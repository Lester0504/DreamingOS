#!/usr/bin/env python3
"""Exercise the production DB/config/job flow, including failed apply recovery."""
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from test_container_service_runtime import compile_fixture


def main():
    if sys.platform != 'linux':
        print('SKIP: LXC job process identity requires Linux /proc')
        return
    with tempfile.TemporaryDirectory(prefix='lxc-config-') as directory:
        t = Path(directory).resolve()
        root = t / 'containers'
        container = root / 'sample'
        container.mkdir(parents=True)
        b = t / 'bin'
        b.mkdir()
        original = '# keep this comment\nlxc.include = /etc/lxc/default.conf\nlxc.net.0.type = empty\nlxc.mount.entry = /data/archive archive none bind,ro 0 0\nlxc.cgroup2.memory.max = 33554432\n'
        config = container / 'config'
        config.write_text(original)
        (t / 'state').write_text('STOPPED')
        db = t / 'jobs.db'
        exe = compile_fixture(t, db)
        script = '''#!/usr/bin/env python3
import os,sys,time
from pathlib import Path
t=Path(os.environ['LXC_TEST_ROOT']);cmd=Path(sys.argv[0]).name
if cmd=='lxc-config': print(t/'containers')
elif cmd=='lxc-info': print((t/'state').read_text())
elif cmd=='lxc-stop':
 if (t/'stop-fails').exists(): sys.exit(1)
 (t/'state').write_text('STOPPED')
elif cmd=='lxc-start':
 text=(t/'containers/sample/config').read_text()
 if (t/'slow').exists(): time.sleep(30)
 if (t/'start-fails').exists() and '67108864' in text: sys.exit(1)
 (t/'state').write_text('RUNNING')
'''
        for command in ('lxc-config', 'lxc-info', 'lxc-start', 'lxc-stop'):
            (b / command).write_text(script)
            (b / command).chmod(0o755)
        env = dict(os.environ, LXC_TEST_ROOT=str(t), DOCKER_WORKFLOW_TEST_ROOT=str(t), PATH=str(b)+':'+os.environ['PATH'])

        def call(*args):
            p = subprocess.run([str(exe), *args], env=env, text=True, capture_output=True, timeout=15)
            assert p.stdout, p.stderr
            return json.loads(p.stdout)

        def read():
            return call('lxc-config', 'sample')['data']

        def action(kind, document=None, **extra):
            d = document or read()
            payload = {k: d[k] for k in ('identity', 'revision', 'fingerprint')}
            payload.update(confirm=True, **extra)
            return call('lxc-action', 'sample', kind, json.dumps(payload))

        def wait(job):
            assert 'job_id' in job, job
            for _ in range(160):
                result = call('lxc-get', job['job_id'])['data']
                if result['state'] not in ('queued', 'running'):
                    return result
                time.sleep(.05)
            raise AssertionError(result)

        d = read()
        assert d['state'] == 'external' and d['revision'] == 0
        with sqlite3.connect(t / 'config.db') as conn:
            assert not conn.execute("SELECT name FROM sqlite_master WHERE name='lxc_config_document'").fetchall()
        assert action('config_set', fields={'memory_bytes': 67108864})['error'] == 'lxc_config_takeover_required'
        assert action('config_set', fields={'memory_bytes': '67108864'})['error'] == 'invalid_config_value'
        saved = action('config_set', takeover=True, fields={'memory_bytes': 67108864})
        assert saved['persisted'] and not saved['applied'] and config.read_text() == original, saved
        assert action('config_set', d, takeover=True, fields={'cpu_weight': 120})['error'] == 'lxc_config_revision_conflict'
        applied = wait(action('config_apply'))
        assert applied['state'] == 'success' and applied['result']['state'] == 'STOPPED', applied
        assert read()['state'] == 'idle' and read()['applied']
        text = config.read_text()
        assert text.replace('67108864', '33554432') == original

        before = read()
        config.write_text(text + '# external change\n')
        conflict = action('config_set', before, fields={'cpu_weight': 120})
        assert conflict['error'] == 'lxc_config_external_conflict' and '# external change' in config.read_text()
        config.write_text(text)
        action('config_set', fields={'memory_bytes': 33554432})
        assert wait(action('config_apply'))['state'] == 'success'
        (t / 'state').write_text('RUNNING')
        action('config_set', fields={'memory_bytes': 67108864})
        assert action('config_apply')['error'] == 'restart_confirmation_required'
        (t / 'start-fails').touch()
        failure = wait(action('config_apply', restart_confirm=True))
        assert failure['state'] == 'failed' and failure['result']['recovered'], failure
        assert '33554432' in config.read_text() and (t / 'state').read_text() == 'RUNNING'
        assert read()['fields']['memory_bytes'] == 67108864 and read()['state'] == 'pending'
        (t / 'start-fails').unlink()
        (t / 'stop-fails').touch()
        stop = wait(action('config_apply', restart_confirm=True))
        assert stop['state'] == 'failed' and '33554432' in config.read_text(), stop
        (t / 'stop-fails').unlink()

        (t / 'slow').touch()
        job = action('config_apply', restart_confirm=True)
        for _ in range(100):
            if '67108864' in config.read_text():
                break
            time.sleep(.03)
        assert '67108864' in config.read_text()
        with sqlite3.connect(db) as conn:
            pid = conn.execute('SELECT worker_pid FROM container_job WHERE id=?', (job['job_id'],)).fetchone()[0]
        os.killpg(pid, signal.SIGKILL)
        (t / 'slow').unlink()
        assert wait(job)['state'] == 'failed'
        assert read()['state'] == 'applying' and not read()['applied']
        recovery = wait(action('config_recover', restart_confirm=True))
        assert recovery['state'] == 'success' and recovery['result']['recovered'], recovery
        assert '33554432' in config.read_text() and read()['state'] == 'pending'
        assert wait(action('config_apply', restart_confirm=True))['state'] == 'success'
        assert read()['applied'] and (t / 'state').read_text() == 'RUNNING'
        new_root=t/'new-containers';new_root.mkdir()
        external=root/'external';external.mkdir();(external/'config').write_text('lxc.net.0.type = empty\n')
        settings=call('lxc-settings')['data']
        payload={'confirm':True,'revision':settings['revision'],'storage_ref':{'path':str(new_root)},'default_template':'alpine/3.22/amd64/default'}
        saved=call('lxc-settings-save',json.dumps(payload))
        assert saved['ok'] and saved['new_containers_only'] and saved['migrated'] is False,saved
        assert call('lxc-settings')['data']['config']['lxcpath']==str(new_root)
        assert read()['lxcpath']==str(root) and config.exists()
        assert call('lxc-config','external')['data']['config_path']==str(external/'config')
        assert call('lxc-settings-save',json.dumps(payload))['error']=='lxc_config_revision_conflict'
        duplicate=new_root/'sample';duplicate.mkdir();(duplicate/'config').write_text('lxc.net.0.type = empty\n')
        assert read()['error']=='lxc_name_ambiguous'
        (duplicate/'config').unlink();duplicate.rmdir();new_root.rename(t/'missing-mount')
        assert read()['lxcpath']==str(root)
        print('PASS: query-only ownership, explicit takeover, CAS and external conflict, stopped apply, restart confirmation, failed start/stop rollback, interrupted apply recovery, retained draft')
        print('PASS: new default root preserves managed and external containers, settings CAS, duplicate-name rejection, missing default root does not hide old objects')


if __name__ == '__main__':
    main()
