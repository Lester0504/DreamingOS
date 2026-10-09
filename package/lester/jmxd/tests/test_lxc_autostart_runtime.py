#!/usr/bin/env python3
"""Boot scheduler, real task workers and config persistence with explicit CLI fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from test_container_service_runtime import compile_fixture


def main():
    if sys.platform != 'linux':
        print('SKIP: persistent worker identity requires Linux /proc')
        return
    with tempfile.TemporaryDirectory(prefix='lxc-autostart-') as temporary:
        t=Path(temporary).resolve();root=t/'containers';root.mkdir();b=t/'bin';b.mkdir()
        exe=compile_fixture(t,t/'jobs.db',lxc_boot=True)
        for name in ['alpha','beta','failed','disabled','external','changed']:
            p=root/name;p.mkdir();(p/'config').write_text('lxc.net.0.type = empty\nlxc.start.auto = 1\n')
            (p/'state').write_text('STOPPED')
        script='''#!/usr/bin/env python3
import os,sys,time,json
from pathlib import Path
t=Path(os.environ['LXC_TEST_ROOT']);cmd=Path(sys.argv[0]).name
if cmd=='lxc-config':print(t/'containers');sys.exit(0)
name=sys.argv[sys.argv.index('-n')+1];p=t/'containers'/name
if cmd=='lxc-info':print((p/'state').read_text());sys.exit(0)
with (t/'calls').open('a') as f:f.write(json.dumps([cmd,name,time.monotonic()])+'\\n')
if cmd=='lxc-start' and name=='failed':sys.exit(1)
(p/'state').write_text('RUNNING' if cmd=='lxc-start' else 'STOPPED')
'''
        for command in ['lxc-config','lxc-info','lxc-start','lxc-stop']:
            (b/command).write_text(script);(b/command).chmod(0o755)
        env=dict(os.environ,PATH=str(b)+':'+os.environ['PATH'],LXC_TEST_ROOT=str(t),DOCKER_WORKFLOW_TEST_ROOT=str(t))

        def call(*args):
            p=subprocess.run([str(exe),*args],env=env,text=True,capture_output=True,timeout=70)
            assert p.stdout,(p.returncode,p.stderr)
            return json.loads(p.stdout)

        def document(name):
            return call('lxc-config',name)['data']

        def action(name,kind,**extra):
            d=document(name)
            return call('lxc-action',name,kind,json.dumps({k:d[k] for k in ['identity','revision','fingerprint']}|{'confirm':True}|extra))

        def wait(job):
            assert 'job_id' in job,job
            for _ in range(100):
                d=call('lxc-get',job['job_id'])['data']
                if d['state'] not in ['queued','running']:
                    assert d['state']=='success',d
                    return d
                time.sleep(.05)
            raise AssertionError(d)

        for name,order in [('alpha',2),('beta',1),('failed',3),('changed',4),('disabled',0)]:
            saved=action(name,'config_set',takeover=True,fields={'autostart':name!='disabled','start_order':order,'start_delay':1 if name=='beta' else 0})
            assert saved['persisted'] and not saved['applied'] and not saved['restart_required'],saved
            wait(action(name,'config_apply'))
            assert (root/name/'state').read_text()=='STOPPED'
        assert action('alpha','config_set',fields={'autostart':'true'})['error']=='invalid_autostart'
        assert action('alpha','config_set',fields={'start_delay':301})['error']=='invalid_autostart_value'
        (root/'changed/config').write_text((root/'changed/config').read_text()+'# external edit\n')
        candidates=call('lxc-boot-candidates')
        assert [v['name'] for v in candidates]==['beta','alpha','failed','changed'],candidates
        assert call('lxc-boot')['ok']
        calls=[json.loads(line) for line in (t/'calls').read_text().splitlines()]
        assert [(c[0],c[1]) for c in calls]==[('lxc-start','beta'),('lxc-start','alpha'),('lxc-start','failed')],calls
        assert calls[1][2]-calls[0][2]>=1,calls
        assert (root/'alpha/state').read_text()=='RUNNING' and (root/'beta/state').read_text()=='RUNNING'
        for name in ['external','changed','disabled','failed']:
            assert (root/name/'state').read_text()=='STOPPED',name
        jobs=call('lxc-list')['data']['items']
        assert any(j['state']=='failed' and j['kind']=='lxc_start' for j in jobs),jobs
        before=(t/'calls').read_text()
        saved=action('alpha','config_set',fields={'autostart':False,'start_order':7})
        assert not saved['restart_required'],saved
        wait(action('alpha','config_apply'))
        assert (root/'alpha/state').read_text()=='RUNNING' and (t/'calls').read_text()==before
        (root/'beta/state').write_text('STOPPED')
        assert call('lxc-boot')['ok']
        assert (root/'beta/state').read_text()=='STOPPED' and (t/'calls').read_text()==before
        print('PASS: managed applied-only autostart, order/delay, external config rejection, persistent failed start, boot-only marker, disabling autostart leaves running container unchanged')


if __name__=='__main__':
    main()
