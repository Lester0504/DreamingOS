#!/usr/bin/env python3
"""Real libuci/SQLite and isolated Docker daemon settings/rollback regression.

Only the test container's daemon is restarted. The host engine is used solely
for the test container lifecycle; config paths and socket live under /tmp.
OpenWrt procd enablement is represented by a private flag in the init adapter.
"""
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time
import uuid

from test_container_service_runtime import compile_fixture


INIT = r'''#!/usr/bin/env python3
import json,os,shlex,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent
container=(root/'container-name').read_text().strip()
action=sys.argv[1]
def outer(*args):
 return subprocess.run(['docker','--host','unix:///var/run/docker.sock','exec',container,*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode
if action=='enabled':sys.exit(0 if (root/'enabled').exists() else 1)
if action in ('enable','disable'):
 if action=='enable':(root/'enabled').touch()
 else:(root/'enabled').unlink(missing_ok=True)
 sys.exit(0)
if action=='running':sys.exit(outer('sh','-c','test -s /tmp/test-dockerd.pid && kill -0 $(cat /tmp/test-dockerd.pid)'))
if action=='restart':
 with (root/'restarts').open('a') as f:f.write('restart\n')
 if (root/'hold-restart').exists():
  (root/'restart-held').touch()
  while (root/'hold-restart').exists():time.sleep(.1)
 if (root/'fail-once').exists():
  (root/'fail-once').unlink();sys.exit(1)
 mirrors=[]
 for line in (root/'uci/dockerd').read_text().splitlines():
  words=shlex.split(line)
  if len(words)==3 and words[:2]==['list','registry_mirrors']:mirrors.append(words[2])
 (root/'daemon.json').write_text(json.dumps({'registry-mirrors':mirrors}))
 sys.exit(outer('sh','/work/engine-control','restart'))
if action=='stop':sys.exit(outer('sh','/work/engine-control','stop'))
sys.exit(2)
'''

CONTROL = r'''#!/bin/sh
stop() {
 if [ -s /tmp/test-dockerd.pid ]; then
  kill "$(cat /tmp/test-dockerd.pid)" 2>/dev/null || true
  n=0
  while [ -s /tmp/test-dockerd.pid ] && [ "$n" -lt 100 ]; do sleep .1; n=$((n+1)); done
 fi
}
stop
[ "$1" = stop ] && exit 0
mkdir -p /tmp/bin
for tool in containerd runc; do
 printf '#!/bin/sh\nexec /host-libs/ld-linux-x86-64.so.2 --library-path /host-libs /host-bin/%s "$@"\n' "$tool" > "/tmp/bin/$tool"
 chmod +x "/tmp/bin/$tool"
done
PATH=/tmp/bin:$PATH nohup /host-libs/ld-linux-x86-64.so.2 --library-path /host-libs /host-bin/dockerd \
 --host=unix:///work/engine.sock --config-file=/work/daemon.json \
 --data-root=/tmp/docker-data --exec-root=/tmp/docker-exec --pidfile=/tmp/test-dockerd.pid \
 --iptables=false --ip6tables=false --bridge=none --ip-forward=false --ip-masq=false \
 --storage-driver=vfs --userland-proxy=false >> /work/daemon.log 2>&1 < /dev/null &
n=0
while [ ! -S /work/engine.sock ] && [ "$n" -lt 100 ]; do sleep .1; n=$((n+1)); done
[ -S /work/engine.sock ] || exit 1
chmod 666 /work/engine.sock
'''


def main():
    if os.environ.get('DOCKER_SETTINGS_REAL') != '1':
        raise SystemExit('Set DOCKER_SETTINGS_REAL=1 to run a test-owned privileged daemon container')
    container = 'dwrt-settings-' + uuid.uuid4().hex[:12]
    outer = ['docker', '--host', 'unix:///var/run/docker.sock']
    with tempfile.TemporaryDirectory(prefix='docker-settings-') as directory:
        root = Path(directory)
        binary = compile_fixture(root, root / 'core.db', settings=True)
        (root / 'uci').mkdir()
        uci = root / 'uci/dockerd'
        original = "config globals 'globals'\n option data_root '/opt/docker/'\n list registry_mirrors 'https://old.example'\n option unknown_kept 'yes'\nconfig proxies 'proxies'\n option http_proxy 'http://test-private-value'\n"
        uci.write_text(original)
        with sqlite3.connect(root / 'config.db'):
            pass
        (root / 'enabled').touch()
        (root / 'container-name').write_text(container)
        (root / 'daemon.json').write_text('{"registry-mirrors":["https://old.example"]}')
        (root / 'engine-control').write_text(CONTROL)
        init = root / 'init-dockerd'
        init.write_text(INIT)
        init.chmod(0o755)
        env = dict(os.environ, DOCKER_HOST='unix://' + str(root / 'engine.sock'))
        mounted = ['--mount', 'type=bind,src=/usr/lib/x86_64-linux-gnu,dst=/host-libs,readonly',
                   '--mount', f'type=bind,src={root},dst=/work']
        for tool in ('dockerd', 'containerd', 'runc'):
            mounted += ['--mount', f'type=bind,src=/usr/bin/{tool},dst=/host-bin/{tool},readonly']
        jobs = []

        def invoke(mode, payload=None):
            args = [str(binary), mode]
            if payload is not None:
                args.append(json.dumps(payload))
            proc = subprocess.run(args, env=env, text=True, stdout=subprocess.PIPE, timeout=45)
            result = json.loads(proc.stdout)
            return result.get('data', result)

        def get():
            return invoke('config-get')

        def save(mirrors, autostart=True, revision=None):
            return invoke('config-set', {'confirm': True, 'revision': revision or get()['revision'],
                                        'config': {'registry_mirrors': mirrors, 'autostart': autostart}})

        def submit(op='config_apply', **kw):
            result = invoke('workflow-write', {'confirm': True, 'operation': op,
                                               'revision': get()['revision'], **kw})
            assert result.get('job_id'), result
            jobs.append(result['job_id'])
            return result['job_id']

        def wait(job):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                with sqlite3.connect(root / 'core.db') as db:
                    row = db.execute('SELECT state,rc,error,result_json,worker_pid FROM container_job WHERE id=?', (job,)).fetchone()
                if row[0] not in ('running', 'queued'):
                    return row[0], json.loads(row[3] or '{}')
                time.sleep(.1)
            raise AssertionError(('job timeout', row))

        try:
            subprocess.run([*outer, 'run', '-d', '--init', '--name', container, '--privileged', '--network', 'none',
                            *mounted, '--entrypoint', 'sh', 'node:22-slim', '-c', 'while :; do sleep 60; done'],
                           check=True, stdout=subprocess.DEVNULL)
            subprocess.run([*outer, 'exec', container, 'sh', '/work/engine-control', 'restart'], check=True)
            for _ in range(100):
                p = subprocess.run(['docker', 'info', '--format', '{{json .}}'], env=env,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                info = json.loads(p.stdout or '{}')
                if info.get('ServerVersion'):
                    break
                time.sleep(.1)
            assert info.get('ServerVersion'), (root / 'daemon.log').read_text()[-2000:]
            initial = get()
            assert initial['config_write'] and initial['config']['registry_mirrors'] == ['https://old.example'], initial
            rev = initial['revision']
            assert save(['https://new.example'], False)['persisted']
            assert uci.read_text() == original and (root / 'enabled').exists()
            assert not (root / 'restarts').exists()
            assert save([], revision=rev)['error'] == 'revision_conflict'
            assert save(['https://user:secret@mirror.example'])['error'] == 'invalid_docker_settings'
            assert save(['file:///tmp/image'])['error'] == 'invalid_docker_settings'
            assert invoke('config-set', {'revision': get()['revision'], 'config': initial['config']})['error'] == 'confirmation_required'
            state, result = wait(submit())
            assert state == 'failed' and result['error'] == 'docker_restart_confirmation_required', (state, result)
            state, result = wait(submit(allow_restart=True))
            assert state == 'success' and result['applied'], (state, result)
            assert Path(result['backup']).read_text() == original
            assert not (root / 'enabled').exists()
            assert 'unknown_kept' in uci.read_text() and 'test-private-value' in uci.read_text()
            assert not get()['pending_apply'] and get()['state'] == 'idle'
            assert 'test-private-value' not in json.dumps(result)
            print('ok: real daemon mirror restart/readback; DB-only save; CAS/auth/URL validation; backup and unrelated UCI retained', flush=True)

            restarts = (root / 'restarts').read_text()
            assert save(['https://new.example'], True)['persisted']
            state, result = wait(submit())
            assert state == 'success' and (root / 'restarts').read_text() == restarts, (state, result)
            assert (root / 'enabled').exists()
            assert save(['https://failed.example'])['persisted']
            (root / 'fail-once').touch()
            state, result = wait(submit(allow_restart=True))
            assert state == 'failed' and result['rollback'] == 'restored', (state, result)
            assert get()['pending_apply'] and get()['applied_config']['registry_mirrors'] == ['https://new.example']
            print('ok: autostart-only apply never restarts; failed restart restores old UCI/autostart and real daemon mirrors', flush=True)

            (root / 'hold-restart').touch()
            job = submit(allow_restart=True)
            for _ in range(100):
                if (root / 'restart-held').exists():
                    break
                time.sleep(.1)
            assert (root / 'restart-held').exists()
            with sqlite3.connect(root / 'core.db') as db:
                pid = db.execute('SELECT worker_pid FROM container_job WHERE id=?', (job,)).fetchone()[0]
            os.killpg(pid, signal.SIGKILL)
            subprocess.run([str(binary), 'reconcile'], env=env, check=True)
            unchanged = uci.read_bytes()
            assert get()['state'] == 'applying' and uci.read_bytes() == unchanged
            assert save([])['error'] == 'docker_settings_recovery_or_apply_pending'
            (root / 'hold-restart').unlink()
            state, result = wait(submit('config_recover'))
            assert state == 'success' and result['rollback'] == 'restored', (state, result)
            assert get()['state'] == 'idle'
            print('ok: killed worker leaves durable recovery; GET does not restore; explicit recovery restores real engine', flush=True)

            uci.write_text(uci.read_text() + '\n# external-change\n')
            assert get()['external_change']
            state, result = wait(submit(allow_restart=True))
            assert state == 'failed' and result['error'] == 'docker_settings_external_change', (state, result)
            assert '# external-change' in uci.read_text()
            print('ok: external UCI edit is detected and never overwritten', flush=True)
        finally:
            if (root / 'core.db').exists():
                with sqlite3.connect(root / 'core.db') as db:
                    try:
                        for pid, in db.execute("SELECT worker_pid FROM container_job WHERE worker_pid>0"):
                            try:
                                os.killpg(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    except sqlite3.OperationalError:
                        pass
            subprocess.run([*outer, 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
