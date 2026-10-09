#!/usr/bin/env python3
"""Managed FTP/FTPS integration on the existing isolated OpenWrt QEMU VM.

Requires /tmp/ftp-managed/.fixture, a freshly compiled /tmp/ftp-share-driver,
the private runtime, production init/PAM and the two existing fixture disks.
Never point this at a router: it creates fixture accounts, shares and mounts.
"""
import ftplib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import time

WORK = Path('/tmp/ftp-managed')
assert (WORK / '.fixture').read_text().strip() == 'isolated-remote-share-qemu'
assert 'root=/dev/vda' in Path('/proc/cmdline').read_text()
HOST = '10.0.2.15'
MOUNT = Path('/mnt/ftp-managed-disk')
DRIVER = '/tmp/ftp-share-driver'
INIT = Path('/etc/init.d/dreamingwrt-ftp')
PASSWORD = 'Ftp-managed-fixture-1005'
ROTATED = 'Ftp-rotated-fixture-1005'
proc = subprocess.Popen([DRIVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
watcher = None
accounts = []
shares = []
original_init = INIT.read_text()


def passed(name):
    print(json.dumps({'passed': name}), flush=True)


def call(op, args=None, id=None, success=True, service='ftp'):
    proc.stdin.write(json.dumps(dict(op=op, args=args or {}, id=id, service=service)) + '\n')
    proc.stdin.flush()
    line = proc.stdout.readline()
    assert line, 'test driver terminated'
    value = json.loads(line)
    assert (value['code'] == 2000) == success, value
    return value['data']


def action(name):
    return call('action', {'confirm': True, 'expected_revision': call('get')['control_revision'], 'action': name})


def settings(success=True, **fields):
    return call('settings', {'confirm': True, 'expected_revision': call('get')['revision'], **fields}, success=success)


def share(id):
    return next(s for s in call('get')['shares'] if s['id'] == id)


def update(id, success=True, **fields):
    return call('ftp-PUT', {'confirm': True, 'expected_revision': share(id)['revision'], **fields}, id, success)


def account(id):
    return next(a for a in call('account-GET')['items'] if a['id'] == id)


def account_update(id, success=True, **fields):
    return call('account-PUT', {'confirm': True, 'expected_revision': account(id)['revision'], **fields}, id, success)


class ReusingTLS(ftplib.FTP_TLS):
    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
            assert conn.session_reused
        return conn, size


def connect(login, password=PASSWORD, tls=False, context=None):
    ftp = ReusingTLS(context=context, timeout=30) if tls else ftplib.FTP(timeout=30)
    ftp.connect(HOST, 2121)
    try:
        ftp.login(login, password)
        if tls:
            ftp.prot_p()
        return ftp
    except Exception:
        ftp.close()
        raise


def denied(fn):
    try:
        fn()
    except ftplib.error_perm as e:
        assert str(e).startswith(('500', '530', '550', '553', '522')), e
    else:
        raise AssertionError('forbidden FTP operation succeeded')


def revoked(ftp):
    try:
        ftp.voidcmd('NOOP')
    except (OSError, EOFError, ftplib.Error):
        pass
    else:
        raise AssertionError('old session survived revocation')
    finally:
        ftp.close()


def roundtrip(ftp, directory):
    content = b'\x00\xffmanaged-ftp\r\n' * 4096
    ftp.storbinary(f'STOR {directory}/payload.bin', io.BytesIO(content))
    got = bytearray()
    ftp.retrbinary(f'RETR {directory}/payload.bin', got.extend)
    assert got == content
    ftp.rename(f'{directory}/payload.bin', f'{directory}/renamed.bin')
    ftp.delete(f'{directory}/renamed.bin')


def wait_for(check, label, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise AssertionError('timeout: ' + label)


def fail_next_restart():
    # Inject a single failure in the task VM only, retaining the same procd name.
    INIT.write_text(original_init.replace('start_service() {', 'start_service() {\n    if [ -f /tmp/ftp-managed/fail-once ]; then rm /tmp/ftp-managed/fail-once; return 1; fi', 1))
    (WORK / 'fail-once').touch()


try:
    if '--resume-tls' not in sys.argv:
        state = call('get')
        assert state['installed'] and not state['running'] and state['settings'] is None
        assert state['source'] == 'unconfigured'
        settings(listen_address=HOST, listen_port=2121, passive_min_port=21000, passive_max_port=21004)
        assert not call('get')['running']
        stale = call('settings', {'confirm': True, 'expected_revision': 0, 'listen_port': 2122}, success=False)
        assert stale['error'] == 'revision_conflict'
        passed('unconfigured_state_settings_revision_and_save_does_not_start')

        for username in ['ftpma', 'ftpmb']:
            a = call('account-POST', {'confirm': True, 'username': username, 'password': PASSWORD})
            accounts.append(a['id'])
        alice, bob = accounts
        login_a, login_b = account(alice)['login'], account(bob)['login']
        for name, users in [('alpha', [{'account_id': alice, 'read_only': False}, {'account_id': bob, 'read_only': True}]),
                            ('beta', [{'account_id': bob, 'read_only': False}])]:
            s = call('ftp-POST', {'confirm': True, 'name': name, 'path': str(MOUNT / name), 'read_only': False, 'users': users})
            shares.append(s['id'])
        alpha, beta = shares
        assert len(account(alice)['references']) == 1 and len(account(bob)['references']) == 2
        e = call('account-DELETE', {'confirm': True, 'expected_revision': account(alice)['revision']}, alice, False)
        assert e['error'] == 'account_in_use'
        assert not action('enable')['running']
        assert action('disable')['enabled'] is False
        assert action('start')['running']
        passed('dedicated_accounts_references_and_independent_autostart')

        with connect(login_a) as ftp:
            assert ftp.pwd() == '/' and ftp.nlst() == ['alpha']
            roundtrip(ftp, 'alpha')
            denied(lambda: ftp.sendcmd('PORT 10,0,2,15,80,1'))
            denied(lambda: ftp.sendcmd('EPRT |1|10.0.2.15|20481|'))
            denied(lambda: ftp.retrbinary('RETR /etc/passwd', lambda _: None))
            denied(lambda: ftp.retrbinary('RETR alpha/outside', lambda _: None))
            ftp.cwd('../../../')
            assert ftp.pwd() == '/'
        with connect(login_b) as ftp:
            assert set(ftp.nlst()) == {'alpha', 'beta'}
            denied(lambda: ftp.storbinary('STOR alpha/forbidden', io.BytesIO(b'x')))
            denied(lambda: ftp.delete('alpha/readme.txt'))
            roundtrip(ftp, 'beta')
        for user, password in [(login_a, 'wrong-fixture-password'), ('root', PASSWORD), ('anonymous', 'fixture@example.invalid')]:
            denied(lambda: connect(user, password))
        passed('real_passive_transfer_per_user_chroot_readonly_and_rejections')

        update(beta, read_only=True)
        with connect(login_b) as ftp:
            denied(lambda: ftp.storbinary('STOR beta/forbidden', io.BytesIO(b'x')))
        update(beta, read_only=False)
        before = call('get')
        for port in [2122, 21004]:
            with socket.socket() as occupied:
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                occupied.bind((HOST, port)); occupied.listen()
                error = settings(success=False, **({'listen_port': port} if port == 2122 else {'passive_max_port': 21004}))
                assert error['reason'] == 'port_in_use' and error['rolled_back']
            assert call('get')['revision'] == before['revision'] and call('get')['running']
        with connect(login_a) as ftp:
            roundtrip(ftp, 'alpha')
        passed('share_readonly_precedence_control_and_passive_port_conflict_rollback')

        old = connect(login_a)
        account_update(alice, password=ROTATED)
        revoked(old)
        denied(lambda: connect(login_a))
        with connect(login_a, ROTATED) as ftp:
            assert ftp.nlst() == ['alpha']
        old = connect(login_b)
        account_update(bob, enabled=False)
        revoked(old)
        denied(lambda: connect(login_b))
        account_update(bob, enabled=True)
        fail_next_restart()
        old_revision = account(alice)['revision']
        error = account_update(alice, success=False, password=PASSWORD)
        assert error['rolled_back'] and not error['rollback_failed'] and account(alice)['revision'] == old_revision
        INIT.write_text(original_init)
        denied(lambda: connect(login_a))
        with connect(login_a, ROTATED) as ftp:
            roundtrip(ftp, 'alpha')
        passed('password_rotation_disable_session_revocation_and_failed_apply_restores_credentials')

    else:
        saved_accounts = {a['username']: a for a in call('account-GET')['items']}
        alice, bob = saved_accounts['ftpma']['id'], saved_accounts['ftpmb']['id']
        login_a, login_b = saved_accounts['ftpma']['login'], saved_accounts['ftpmb']['login']
        accounts[:] = [alice, bob]
        saved_shares = {s['name']: s['id'] for s in call('get')['shares']}
        alpha, beta = saved_shares['alpha'], saved_shares['beta']
        shares[:] = [alpha, beta]
        passed('resuming_tls_after_preserved_plain_ftp_and_credential_results')

    cert, key = str(WORK / 'server.crt'), str(WORK / 'server.key')
    settings(tls=True, cert_file=cert, key_file=key)
    ctx = ssl.create_default_context(cafile=cert)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    denied(lambda: connect(login_a, ROTATED))
    with connect(login_a, ROTATED, True, ctx) as ftp:
        assert ftp.sock.version() == 'TLSv1.2'
        roundtrip(ftp, 'alpha')
        ftp.prot_c()
        denied(lambda: ftp.nlst())
        ftp.prot_p()
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    with connect(login_b, tls=True, context=ctx) as ftp:
        assert ftp.sock.version() == 'TLSv1.3'
    prior = call('get')['revision']
    error = settings(success=False, cert_file=str(WORK / 'invalid.crt'))
    assert error['error'] == 'invalid_certificate' and call('get')['revision'] == prior
    passed('verified_tls12_binary_data_session_reuse_tls13_and_invalid_certificate')
    settings(tls=False)

    # A protocol receipt remains successful if a later item fails and is retried.
    operation = call('operation-POST', {'confirm': True, 'request_id': 'ftp-managed-1005-operation', 'items': [
        {'protocol': 'ftp', 'action': 'create', 'body': {'name': 'receipt', 'path': str(MOUNT / 'alpha'), 'read_only': True, 'users': [{'account_id': alice, 'read_only': True}]}},
        {'protocol': 'ftp', 'action': 'create', 'body': {'name': 'receipt-later', 'path': str(MOUNT / 'later'), 'read_only': True, 'users': [{'account_id': alice, 'read_only': True}]}}
    ]})
    assert operation['state'] == 'partial'
    first_id = operation['results'][0]['result']['id']
    shares.append(first_id)
    (MOUNT / 'later').mkdir(mode=0o755)
    operation = call('operation-RETRY', {'confirm': True}, operation['operation_id'])
    assert operation['state'] == 'success' and operation['results'][0]['result']['id'] == first_id
    shares.append(operation['results'][1]['result']['id'])
    passed('operation_partial_success_retry_without_duplicate_creation')

    with sqlite3.connect(WORK / 'config.db') as db:
        db.execute('BEGIN IMMEDIATE')
        assert call('get')['running']
        conflict = update(alpha, success=False, note='competing writer')
        assert conflict['error'] == 'storage_busy'
        db.rollback()
    watcher = subprocess.Popen([DRIVER, '--file-share-bindings'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    old = connect(login_a, ROTATED)
    subprocess.run(['umount', '-l', str(MOUNT)], check=True)
    wait_for(lambda: not share(alpha)['path_available'] and not call('get')['running'], 'disk withdrawal')
    revoked(old)
    subprocess.run(['mount', '/dev/vdc', str(MOUNT)], check=True)
    wait_for(lambda: not call('get')['running'], 'replacement stays unpublished')
    assert not share(alpha)['path_available']
    assert update(alpha, success=False, note='replacement disk')['error'] == 'directory_binding_changed'
    subprocess.run(['umount', str(MOUNT)], check=True)
    subprocess.run(['mount', '/dev/vdb', str(MOUNT)], check=True)
    wait_for(lambda: share(alpha)['running'] and call('get')['running'], 'original disk resumes')
    with connect(login_a, ROTATED) as ftp:
        roundtrip(ftp, 'alpha')
    passed('writer_contention_disk_loss_revocation_replacement_rejection_original_uuid_restore')

    action('stop')
    settings(passive_max_port=21004)
    assert not call('get')['running'] and not call('get')['requested_running']
    watcher.terminate(); watcher.wait(timeout=10); watcher = None
    action('start')
    for id in list(shares):
        call('ftp-DELETE', {'confirm': True, 'expected_revision': share(id)['revision']}, id)
        shares.remove(id)
    assert not call('get')['running'] and (MOUNT / 'alpha/readme.txt').read_text() == 'alpha fixture\n'
    assert not account(alice)['references'] and not account(bob)['references']
    passed('manual_stop_preserved_last_share_closes_listener_data_and_accounts_retained')
    print(json.dumps({'result': 'PASS', 'scope': 'managed FTP/FTPS actual runtime, production procd/PAM and C/SQLite backend'}), flush=True)
finally:
    INIT.write_text(original_init)
    if watcher:
        watcher.terminate(); watcher.wait(timeout=10)
    # Leave failed fixtures for diagnosis; only the successful path releases identities.
    if not shares:
        action('stop'); action('disable')
        for id in accounts:
            call('account-DELETE', {'confirm': True, 'expected_revision': account(id)['revision']}, id)
    proc.stdin.close(); proc.wait(timeout=10)
