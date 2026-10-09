#!/usr/bin/env python3
"""Production creation validation/worker, with explicit network/CLI fault fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from test_container_service_runtime import compile_fixture


def main():
    if sys.platform!='linux':
        print('SKIP: job process identity requires Linux /proc')
        return
    with tempfile.TemporaryDirectory(prefix='lxc-create-') as directory:
        t=Path(directory).resolve();root=t/'containers';root.mkdir();b=t/'bin';b.mkdir()
        (t/'templates').mkdir();(t/'templates/lxc-local').write_text('#!/bin/sh\n');(t/'templates/lxc-local').chmod(0o755)
        (t/'net/br-test/bridge').mkdir(parents=True);(t/'default.conf').write_text('# preserved default\n')
        for name in ['subuid','subgid']:(t/name).write_text('root:100000:65536\n')
        shared=t/'shared';shared.mkdir();(shared/'sentinel').write_text('external data')
        exe=compile_fixture(t,t/'jobs.db',lxc_fixture=True)
        script='''#!/usr/bin/env python3
import json,os,sys,shutil,time
from pathlib import Path
t=Path(os.environ['LXC_TEST_ROOT']);cmd=Path(sys.argv[0]).name
with (t/'calls').open('a') as f:f.write(json.dumps([cmd,*sys.argv[1:]])+'\\n')
if cmd=='lxc-config':print(t/'containers');sys.exit(0)
root=Path(sys.argv[sys.argv.index('-P')+1]);name=sys.argv[sys.argv.index('-n')+1];d=root/name
if cmd=='lxc-info':
 if not (d/'config').exists():sys.exit(1)
 print((d/'state').read_text() if (d/'state').exists() else 'STOPPED')
elif cmd=='lxc-create':
 d.mkdir();(d/'rootfs').mkdir();config=Path(sys.argv[sys.argv.index('-f')+1]).read_text()
 (d/'config').write_text(config);(d/'rootfs/marker').write_text(name)
 if os.environ.get('LXC_TEST_CREATE_DELAY'):time.sleep(20)
 if os.environ.get('LXC_TEST_PARTIAL_FAIL'):sys.exit(1)
elif cmd=='lxc-start':
 if os.environ.get('LXC_TEST_START_FAIL'):sys.exit(1)
 (d/'state').write_text('RUNNING')
elif cmd=='lxc-stop':(d/'state').write_text('STOPPED')
elif cmd=='lxc-destroy':shutil.rmtree(d)
'''
        for command in ['lxc-config','lxc-info','lxc-create','lxc-start','lxc-stop','lxc-destroy']:
            (b/command).write_text(script);(b/command).chmod(0o755)
        index='alpine;3.22;amd64;default;20261005_13:00;/images/alpine/3.22/amd64/default/20261005_13:00/\n'
        index+='alpine;3.22;arm64;default;20261005_13:00;/images/alpine/3.22/arm64/default/20261005_13:00/\n'
        env=dict(os.environ,LXC_TEST_ROOT=str(t),DOCKER_WORKFLOW_TEST_ROOT=str(t),LXC_TEST_INDEX=index,PATH=str(b)+':'+os.environ['PATH'])
        body={'template_id':'alpine/3.22/amd64/default','build':'20261005_13:00','storage_ref':{'path':str(root)},'bridge':'br-test','privilege':'unprivileged','mounts':[{'source':{'path':str(shared)},'target':'/mnt/data','read_only':True}]}

        def call(*args):
            p=subprocess.run([str(exe),*args],text=True,capture_output=True,env=env,timeout=15)
            assert p.stdout,p.stderr
            return json.loads(p.stdout)

        def create(name,action='create',**patch):
            return call('lxc-action',name,action,json.dumps({**body,'confirm':True,**patch}))

        def wait(job):
            assert 'job_id' in job,job
            for _ in range(100):
                d=call('lxc-get',job['job_id'])['data']
                if d['state'] not in ['running','queued']:return d
                time.sleep(.05)
            raise AssertionError(d)

        assert create('../bad')['error']=='invalid_create_request'
        assert create('test',arbitrary_url='https://example.org/rootfs')['error']=='invalid_create_request'
        assert create('test',bridge='missing')['error']=='lxc_bridge_unavailable'
        assert create('test',network_mode='static')['error']=='lxc_guest_static_address_unsupported'
        assert create('test',template_id='alpine/3.22/arm64/default')['error']=='template_architecture_mismatch'
        assert create('test',privilege='privileged')['error']=='privileged_confirmation_required'
        assert create('test',storage_ref={'path':str(root),'inode':1})['error']=='lxc_storage_changed'
        preview=create('test','create_preflight');assert preview['ok'] and not (root/'test').exists(),preview
        assert preview['plan']['uid_base']==100000 and preview['plan']['mounts'][0]['read_only']
        stopped=wait(create('test'));assert stopped['state']=='success' and stopped['result']['created'] and stopped['result']['state']=='STOPPED',stopped
        assert create('test')['error']=='lxc_name_exists'
        config=call('lxc-config','test')['data'];assert config['ownership']=='managed' and config['applied'],config
        assert 'lxc.idmap = u 0 100000 65536' in config['config'] and 'bind,ro,create=dir' in config['config']
        # Edit only the managed network/mount layout, then revalidate the directory at apply time.
        (t/'net/br-next/bridge').mkdir(parents=True)
        replacement=t/'replacement';replacement.mkdir();(replacement/'sentinel').write_text('replacement data')
        def config_action(kind,**extra):
            d=call('lxc-config','test')['data']
            return call('lxc-action','test',kind,json.dumps({k:d[k] for k in ['identity','revision','fingerprint']}|{'confirm':True}|extra))
        assert config_action('config_set',fields={'bridge':42})['error']=='invalid_bridge'
        assert config_action('config_set',fields={'mounts':[{'source':{'path':str(shared)},'target':'/mnt/../escape','read_only':True}]})['error']=='invalid_mount'
        advanced={'bridge':'br-next','mounts':[{'source':{'path':str(replacement)},'target':'/mnt/replaced','read_only':True}]}
        old_config=(root/'test/config').read_text()
        saved=config_action('config_set',fields=advanced);assert saved['persisted'] and not saved['applied'],saved
        assert (root/'test/config').read_text()==old_config
        replacement.rename(t/'replacement-original');replacement.mkdir()
        failed_apply=wait(config_action('config_apply'))
        assert failed_apply['state']=='failed' and failed_apply['result']['error']=='lxc_storage_changed',failed_apply
        assert (root/'test/config').read_text()==old_config
        replacement.rmdir();(t/'replacement-original').rename(replacement)
        applied=wait(config_action('config_apply'));assert applied['state']=='success',applied
        changed=call('lxc-config','test')['data']
        assert changed['fields']['bridge']=='br-next' and changed['fields']['mounts'][0]['source']['path']==str(replacement),changed
        assert 'lxc.net.0.link = br-next' in changed['config'] and 'mnt/replaced none bind,ro' in changed['config']
        assert (shared/'sentinel').read_text()=='external data' and (replacement/'sentinel').read_text()=='replacement data'
        print('PASS: managed network/mount draft, invalid fields, apply-time mount identity, actual config readback, external data retained')
        running=wait(create('started',start_after_create=True));assert running['state']=='success' and running['result']['started'],running
        env['LXC_TEST_START_FAIL']='1';failed=wait(create('kept',start_after_create=True));env.pop('LXC_TEST_START_FAIL')
        assert failed['state']=='failed' and failed['result']['created'] and failed['result']['remaining_object'] and (root/'kept/config').exists(),failed
        env['LXC_TEST_PARTIAL_FAIL']='1';partial=wait(create('partial'));env.pop('LXC_TEST_PARTIAL_FAIL')
        assert partial['state']=='failed' and partial['result']['remaining_object'] and partial['result']['remaining_path']==str(root/'partial'),partial
        env['LXC_TEST_DOWNLOAD_FAIL']='1';download=wait(create('download'));env.pop('LXC_TEST_DOWNLOAD_FAIL')
        assert download['state']=='failed' and not (root/'download').exists(),download
        env['LXC_TEST_CREATE_DELAY']='1';delayed=create('cancelled');env.pop('LXC_TEST_CREATE_DELAY')
        for _ in range(100):
            if (root/'cancelled/config').exists():break
            time.sleep(.05)
        assert (root/'cancelled/config').exists()
        cancelled=call('lxc-cancel',delayed['job_id']);assert cancelled['ok'],cancelled
        terminal=wait(delayed)
        assert terminal['state']=='cancelled' and terminal['result']['remaining_object'] and terminal['result']['observed_identity'],terminal
        assert terminal['result']['remaining_path']==str(root/'cancelled') and not terminal['result']['ownership_verified'],terminal
        assert Path(terminal['result']['staging_path']).is_dir(),terminal
        assert (shared/'sentinel').read_text()=='external data'
        print('PASS: preflight without creation, fixed template/source, namespace mode, bridge, storage identity, RO bind, managed config, create-only/start, duplicate name, partial failure and retained objects, download failure')


if __name__=='__main__':main()
