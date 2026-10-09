#!/usr/bin/env python3
"""Follow the managed FTP suite in its isolated VM: explicit disk replacement.
Uses the existing test disks and data; all writes are fixture-only.
"""
import ftplib
import json
import os
from pathlib import Path
import subprocess
import time

work = Path('/tmp/ftp-managed')
assert (work / '.fixture').read_text().strip() == 'isolated-remote-share-qemu'
assert 'root=/dev/vda' in Path('/proc/cmdline').read_text()
root = Path('/mnt/ftp-managed-disk')
password = 'Ftp-rebind-fixture-1005'
proc = subprocess.Popen(['/tmp/ftp-share-driver'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def call(op, args=None, id=None, success=True):
    proc.stdin.write(json.dumps(dict(op=op, args=args or {}, id=id, service='ftp')) + '\n')
    proc.stdin.flush()
    response = json.loads(proc.stdout.readline())
    assert (response['code'] == 2000) == success, response
    return response['data']


def action(name):
    return call('action', dict(confirm=True, expected_revision=call('get')['control_revision'], action=name))


def record():
    return next(s for s in call('get')['shares'] if s['id'] == shared['id'])


def contents(name):
    with ftplib.FTP(timeout=30) as ftp:
        ftp.connect('10.0.2.15', 2121)
        ftp.login(account['login'], password)
        data = bytearray()
        ftp.retrbinary('RETR rebound/' + name, data.extend)
        return data


empty_before = os.stat('/var/empty')
source_before = os.stat(root / 'alpha')
assert not call('get')['shares'], 'run after the primary suite cleans up'
account = call('account-POST', dict(confirm=True, username='ftpmrebind', password=password))
shared = None
try:
    assert account['login'] == 'dwshare_ftpmrebind'
    import pwd
    identity = pwd.getpwnam(account['login'])
    assert identity.pw_uid > 0 and identity.pw_shell == '/bin/false' and identity.pw_dir == '/var/empty'
    shadow = next(line.split(':')[1] for line in Path('/etc/shadow').read_text().splitlines() if line.startswith(account['login'] + ':'))
    assert shadow.startswith('!') or shadow.startswith('*')
    private = root / 'ftp-private-fixture'
    private.mkdir(mode=0o700, exist_ok=True)
    denied = call('ftp-POST', dict(confirm=True, name='forbidden', path=str(private), read_only=True,
        users=[dict(account_id=account['id'], read_only=True)]), success=False)
    assert denied['error'] == 'directory_permission_denied'
    assert os.stat(private).st_mode & 0o777 == 0o700
    shared = call('ftp-POST', dict(confirm=True, name='rebound', path=str(root / 'alpha'), read_only=True,
        users=[dict(account_id=account['id'], read_only=True)]))
    assert action('start')['running']
    assert contents('readme.txt') == b'alpha fixture\n'
    action('stop')
    subprocess.run(['umount', str(root)], check=True)
    subprocess.run(['mount', '/dev/vdc', str(root)], check=True)
    (root / 'alpha/replacement.txt').write_text('replacement fixture\n')
    assert not record()['path_available']
    error = call('ftp-PUT', dict(confirm=True, expected_revision=record()['revision'], note='not a rebind'), shared['id'], False)
    assert error['error'] == 'directory_binding_changed'
    call('ftp-PUT', dict(confirm=True, expected_revision=record()['revision'], rebind=True), shared['id'])
    assert record()['path_available'] and not call('get')['running']
    action('start')
    assert contents('replacement.txt') == b'replacement fixture\n'
    action('stop')
    subprocess.run(['umount', str(root)], check=True)
    subprocess.run(['mount', '/dev/vdb', str(root)], check=True)
    watcher = subprocess.Popen(['/tmp/ftp-share-driver', '--file-share-bindings'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(4)
        assert not call('get')['running'] and not call('get')['requested_running'] and not record()['path_available']
    finally:
        watcher.terminate(); watcher.wait(timeout=10)
    call('ftp-DELETE', dict(confirm=True, expected_revision=record()['revision']), shared['id'])
    shared = None
    assert (root / 'alpha/readme.txt').read_text() == 'alpha fixture\n'
    empty_after, source_after = os.stat('/var/empty'), os.stat(root / 'alpha')
    assert (empty_before.st_mode, empty_before.st_uid, empty_before.st_gid) == (empty_after.st_mode, empty_after.st_uid, empty_after.st_gid)
    assert (source_before.st_mode, source_before.st_uid, source_before.st_gid) == (source_after.st_mode, source_after.st_uid, source_after.st_gid)
    print(json.dumps({'result': 'PASS', 'scope': 'explicit rebind serves replacement only after confirmation; stopped intent survives disk changes; offline deletion retains source data; locked identity and source/home permissions verified'}), flush=True)
finally:
    if shared is None:
        current = next(a for a in call('account-GET')['items'] if a['id'] == account['id'])
        call('account-DELETE', dict(confirm=True, expected_revision=current['revision']), account['id'])
    proc.stdin.close(); proc.wait(timeout=10)
