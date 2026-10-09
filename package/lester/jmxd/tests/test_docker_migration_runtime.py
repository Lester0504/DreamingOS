#!/usr/bin/env python3
"""Offline migration against a private Engine; no host daemon restarts.

Real Engine, rsync, metadata, libuci and SQLite. The provider discovery seam
supplies a test mount; fstab admission is real but boot persistence is not a
claim this isolated test can make. All writable paths are under the test root.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time
import uuid

from test_container_service_runtime import compile_fixture
import apd_test_deps

PROVIDER = r'''
int jmx_storage_provider_discover(struct jmx_storage_provider *p,size_t capacity){
 if(!capacity)return 0;
 memset(p,0,sizeof(*p));
 snprintf(p->mountpoint,sizeof(p->mountpoint),"%s",getenv("MIGRATION_TEST_MOUNT"));
 snprintf(p->uuid,sizeof(p->uuid),"migration-test-uuid");
 snprintf(p->filesystem,sizeof(p->filesystem),"ext4");
 p->mounted=1;p->writable=1;return 1;
}
'''
INIT = r'''#!/usr/bin/python3
import json,os,shlex,signal,subprocess,sys,time
from pathlib import Path
root=Path(__file__).parent
pidfile=root/'dockerd.pid'
action=sys.argv[1]
def running():
 try:
  os.kill(int(pidfile.read_text()),0);return True
 except (FileNotFoundError,ProcessLookupError,ValueError):return False
if action=='enabled':sys.exit(0 if (root/'enabled').exists() else 1)
if action in ('enable','disable'):
 if action=='enable':(root/'enabled').touch()
 else:(root/'enabled').unlink(missing_ok=True)
 sys.exit(0)
if action=='running':sys.exit(0 if running() else 1)
if action in ('stop','restart'):
 if running():
  os.kill(int(pidfile.read_text()),signal.SIGTERM)
  for _ in range(300):
   if not running():break
   time.sleep(.1)
 if running():sys.exit(1)
 if (root/'containerd.pid').exists():
  try:
   cd=int((root/'containerd.pid').read_text());os.kill(cd,signal.SIGTERM)
   for _ in range(100):
    try:os.kill(cd,0)
    except ProcessLookupError:break
    time.sleep(.1)
  except ProcessLookupError:pass
 if action=='stop':sys.exit(0)
if action in ('start','restart'):
 if running():sys.exit(0)
 if (root/'fail-start-once').exists():
  (root/'fail-start-once').unlink();sys.exit(1)
 if (root/'hold-start').exists():
  (root/'start-held').touch()
  while (root/'hold-start').exists():time.sleep(.1)
 driver=os.environ.get('MIGRATION_TEST_DRIVER','overlayfs')
 config={'registry-mirrors':[],'features':{'containerd-snapshotter':driver=='overlayfs'}}
 for line in (root/'uci/dockerd').read_text().splitlines():
  words=shlex.split(line)
  if len(words)==3 and words[:2]==['list','registry_mirrors']:config['registry-mirrors'].append(words[2])
  if len(words)==3 and words[:2]==['option','data_root']:config['data-root']=words[2]
 (root/'daemon.json').write_text(json.dumps(config))
 (root/'exec').mkdir(exist_ok=True)
 cd_socket=str(root/'exec/containerd.sock')
 cd_config=root/'exec/containerd.toml'
 cd_config.write_text("version = 2\nroot = '"+config['data-root']+"/containerd/daemon'\nstate = '"+str(root/'exec/state')+"'\n[grpc]\naddress = '"+cd_socket+"'\n")
 with (root/'containerd.log').open('ab') as cdlog:
  cd=subprocess.Popen(['containerd','--config',str(cd_config)],stdout=cdlog,stderr=cdlog,stdin=subprocess.DEVNULL,start_new_session=True)
 (root/'containerd.pid').write_text(str(cd.pid))
 for _ in range(100):
  if Path(cd_socket).exists():break
  time.sleep(.1)
 with (root/'daemon.log').open('ab') as log:
  subprocess.Popen(['dockerd','--host=unix://'+str(root/'engine.sock'),'--config-file='+str(root/'daemon.json'),
   '--containerd='+cd_socket,'--exec-root='+str(root/'exec/docker'),'--pidfile='+str(pidfile),'--iptables=false','--ip6tables=false',
   '--bridge=none','--ip-forward=false','--ip-masq=false','--storage-driver='+driver,'--userland-proxy=false'],
   stdout=log,stderr=log,stdin=subprocess.DEVNULL,start_new_session=True)
 for _ in range(200):
  if (root/'engine.sock').exists():
   try:(root/'engine.sock').chmod(0o666)
   except FileNotFoundError:pass
   if running():sys.exit(0)
  time.sleep(.1)
 sys.exit(1)
sys.exit(2)
'''


def main():
    if os.environ.get('DOCKER_MIGRATION_REAL') != '1':
        raise SystemExit('Set DOCKER_MIGRATION_REAL=1 for a test-owned daemon under /tmp (sudo only outside the source tree)')
    outer=['docker','--host','unix:///var/run/docker.sock']
    with tempfile.TemporaryDirectory(prefix='docker-migration-') as directory:
        root=Path(directory)
        (root/'docker_migration_provider_fixture.inc').write_text(PROVIDER)
        binary=compile_fixture(root,root/'core.db',settings=True,engine_socket=root/'engine.sock',migration=True)
        libs=root/'libs';libs.mkdir()
        prefix,_=apd_test_deps.resolve_prefix('uci','uci.h')
        for lib in ('libuci.so','libubox.so'):
            candidates=list((prefix/'lib').glob(lib+'*'))
            if not candidates:
                candidates=list((prefix.parent/'lib').glob(lib+'*'))
            for path in candidates:
                if path.is_file():shutil.copyfile(path,libs/path.name)
        (root/'uci').mkdir();(root/'mount').mkdir();(root/'mount/target').mkdir()
        source=root/'source';target=root/'mount/target'
        uci=root/'uci/dockerd'
        original=f"config globals 'globals'\n option data_root '{source}'\n option unknown_kept 'yes'\n"
        uci.write_text(original)
        (root/'uci/fstab').write_text(f"config mount\n option uuid 'migration-test-uuid'\n option target '{root/'mount'}'\n option enabled '1'\n")
        (root/'enabled').touch()
        (root/'config.db').touch()
        (root/'init-dockerd').write_text(INIT);(root/'init-dockerd').chmod(0o755)
        env=dict(os.environ,DOCKER_HOST='unix://'+str(root/'engine.sock'))
        (root/'bin').mkdir()
        (root/'bin/rsync').write_text('#!/bin/sh\nif [ "$1" = "-aHAXS" ]; then\n if [ -f '+str(root/'fail-copy')+' ]; then rm '+str(root/'fail-copy')+'; exit 23; fi\n if [ -f '+str(root/'hold-copy')+' ]; then touch '+str(root/'copy-held')+'; while [ -f '+str(root/'hold-copy')+' ]; do sleep .1; done; fi\nfi\nexec /usr/bin/rsync "$@"\n')
        (root/'bin/rsync').chmod(0o755)
        exec_prefix=['sudo' ,'-n','env','PATH='+str(root/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH='+str(libs),'DOCKER_HOST='+env['DOCKER_HOST'],
                     'DOCKER_WORKFLOW_TEST_ROOT='+str(root),'MIGRATION_TEST_MOUNT='+str(root/'mount'),'MIGRATION_TEST_DRIVER='+os.environ.get('DOCKER_MIGRATION_DRIVER','overlayfs')]
        def inside(*args,check=True):
            return subprocess.run([*exec_prefix,*map(str,args)],cwd=root,text=True,capture_output=True,check=check,timeout=120)
        def docker(*args,check=True):
            return subprocess.run(['docker',*args],env=env,text=True,capture_output=True,check=check,timeout=120)
        def invoke(mode,payload=None):
            args=[str(binary),mode]
            if payload is not None:args.append(json.dumps(payload))
            p=inside(*args,check=False)
            if not p.stdout.strip():raise AssertionError((mode,p.returncode,p.stderr))
            result=json.loads(p.stdout)
            return result.get('data',result)
        def config():return invoke('config-get')
        def preview(path=target):return invoke('workflow-read',{'operation':'storage_preview','directory_ref':{'root_id':'primary','path':str(path)}})
        def submit(plan=None,op='storage_migrate',**extra):
            payload={'confirm':True,'operation':op,**extra}
            if plan:payload.update(revision=plan['revision'],directory_ref={'root_id':'primary','path':plan['target']},allow_stop=True)
            result=invoke('workflow-write',payload)
            assert result.get('job_id'),result
            return result['job_id']
        def wait(job):
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                data=inside('python3','-c',"import sqlite3,json;d=sqlite3.connect("+repr(str(root/'core.db'))+");print(json.dumps(d.execute('SELECT state,result_json,worker_pid FROM container_job WHERE id=?',("+repr(job)+",)).fetchone()))")
                row=json.loads(data.stdout)
                if row[0] not in ('running','queued'):return row[0],json.loads(row[1] or '{}')
                time.sleep(.15)
            raise AssertionError(('job_timeout',row))
        try:
            p=inside(root/'init-dockerd','start',check=False)
            assert p.returncode==0,p.stderr
            for _ in range(150):
                info=docker('info','--format','{{json .}}',check=False)
                if info.returncode==0:break
                time.sleep(.1)
            assert info.returncode==0,inside('tail','-25',root/'daemon.log').stdout
            # Import a small real image from the outer engine without a registry.
            image=root/'image.tar'
            with image.open('wb') as stream:subprocess.run([*outer,'image','save','redis:8.4-alpine'],stdout=stream,check=True)
            docker('load','-i',str(image))
            docker('volume','create','migration-volume')
            created=docker('create','--name','migration-stopped','--restart','always','--network','none','-v','migration-volume:/data','redis:8.4-alpine').stdout.strip()
            running=docker('run','-d','--name','migration-running','--network','none','--restart','unless-stopped','-v','migration-volume:/data','redis:8.4-alpine',check=False)
            assert running.returncode==0, running.stderr
            running_id=running.stdout.strip()
            docker('exec',running_id,'sh','-c','printf volume-preserved > /data/migration-check')
            inside('python3','-c',f"from pathlib import Path;import os;p=Path({str(source)!r})/'migration-metadata';p.mkdir();(p/'data').write_bytes(b'actual-data');os.link(p/'data',p/'hardlink');os.symlink('data',p/'symlink');os.chmod(p/'data',0o640);os.setxattr(p/'data','user.migration',b'preserved');os.chown(p/'data',123,456)")
            initial=config();assert initial['config']['data_root']==str(source),initial
            assert invoke('config-set',{'confirm':True,'revision':initial['revision'],'config':initial['config']})['error']=='docker_data_root_requires_migration'
            plan=preview()
            if not plan.get('ok'):
                print('info',docker('info','--format','{{json .Containerd}} {{json .DockerRootDir}}').stdout,flush=True)
                print(inside('python3','-c',"from pathlib import Path;p=Path("+repr(str(root/'exec'))+");print('\\n'.join(str(x)+'\\n'+x.read_text() for x in p.rglob('containerd.toml')))").stdout,flush=True)
                print(inside('python3','-c',"from pathlib import Path;print([p.read_bytes().replace(bytes([0]),b' ') for p in Path('/proc').glob('[0-9]*/cmdline') if b'containerd' in p.read_bytes() and b'--config' in p.read_bytes()])").stdout,flush=True)
            assert plan['ok'],plan
            assert len(plan['inventory']['containers'])==2 and plan['containerd']['root'].startswith(str(source)+'/' ),plan
            (root/'uci/fstab').write_text((root/'uci/fstab').read_text().replace("'1'","'0'"))
            assert preview()['error']=='docker_migration_target_not_persistent'
            (root/'uci/fstab').write_text((root/'uci/fstab').read_text().replace("'0'","'1'"))
            (target/'unexpected').touch();assert preview()['error']=='docker_migration_target_not_empty';(target/'unexpected').unlink()
            assert preview(source)['error']=='docker_migration_paths_overlap'
            print('ok: real Docker/containerd roots, inventory, empty/persistent/overlap and ordinary-save gates',flush=True)
            state,result=wait(submit(plan));assert state=='success',(state,result)
            assert result['phase']=='complete' and result['source_retained'] and result['applied'] and result['copied_bytes']>0 and result['copied_files']>0,result
            assert json.loads(docker('info','--format','{{json .}}').stdout)['DockerRootDir']==str(target)
            assert json.loads(docker('inspect',running_id).stdout)[0]['State']['Running']
            assert not json.loads(docker('inspect',created).stdout)[0]['State']['Running']
            volume=json.loads(docker('volume','inspect','migration-volume').stdout)[0]
            assert volume['Mountpoint'].startswith(str(target)+'/'),volume
            mounts=json.loads(docker('inspect',running_id).stdout)[0]['Mounts']
            assert all(x['Source'].startswith(str(target)+'/') for x in mounts if x['Type']=='volume'),mounts
            assert docker('exec',running_id,'cat','/data/migration-check').stdout=='volume-preserved'
            assert not config()['pending_apply'] and config()['config']['data_root']==str(target),config()
            inside('python3','-c',f"from pathlib import Path;import os;p=Path({str(target)!r})/'migration-metadata';assert (p/'data').read_bytes()==b'actual-data';assert (p/'data').stat().st_ino==(p/'hardlink').stat().st_ino;assert os.readlink(p/'symlink')=='data';assert (p/'data').stat().st_uid==123;assert (p/'data').stat().st_gid==456;assert os.getxattr(p/'data','user.migration')==b'preserved';assert (Path({str(source)!r})/'migration-metadata/data').exists()")
            print('ok: offline copy+checksum, both roots switched, running/stopped identities, volume, owner/mode/link/xattr and retained source',flush=True)
            inside('rm','-rf',source)  # only this now-inactive test copy, after retention assertion
            next_target=root/'mount/next';next_target.mkdir();plan=preview(next_target);assert plan['ok'],plan
            (root/'fail-start-once').touch()
            state,result=wait(submit(plan));assert state=='failed' and result['rollback']=='restored',(state,result)
            assert config()['state']=='idle' and config()['data_root']==str(target),config()
            print('ok: failed new-root start automatically restores UCI, source engine and running container',flush=True)
            inside('rm','-rf',next_target)
            # Leave an interrupted switching/start journal and recover explicitly.
            recover_target=root/'mount/recover';recover_target.mkdir();plan=preview(recover_target);assert plan['ok'],plan
            (root/'hold-start').touch();job=submit(plan)
            for _ in range(200):
                if (root/'start-held').exists():break
                time.sleep(.1)
            assert (root/'start-held').exists()
            pid=json.loads(inside('python3','-c',"import sqlite3;print(sqlite3.connect("+repr(str(root/'core.db'))+").execute('SELECT worker_pid FROM container_job WHERE id=?',("+repr(job)+",)).fetchone()[0])").stdout)
            inside('kill','-KILL','--','-'+str(pid))
            inside(binary,'reconcile');before=inside('cat',uci).stdout
            assert config()['state'].startswith('migration_') and inside('cat',uci).stdout==before
            assert invoke('pull',{'image':'busy:1','confirm':True})['error']=='docker_migration_recovery_required'
            (root/'hold-start').unlink()
            state,result=wait(submit(op='storage_recover'));assert state=='success' and result['rollback']=='restored',(state,result)
            assert config()['state']=='idle' and config()['data_root']==str(target)
            print('ok: killed worker leaves durable journal; reads do not restore; other writes blocked; explicit recovery restores service',flush=True)
            inside('rm','-rf',recover_target)
            fail_target=root/'mount/copy-failure';fail_target.mkdir();plan=preview(fail_target);assert plan['ok'],plan
            (root/'fail-copy').touch()
            state,result=wait(submit(plan));assert state=='failed' and result['copy_rc']==23 and result['rollback']=='restored',(state,result)
            cancel_target=root/'mount/cancel';cancel_target.mkdir();plan=preview(cancel_target);assert plan['ok'],plan
            (root/'hold-copy').touch();job=submit(plan)
            for _ in range(200):
                if (root/'copy-held').exists():break
                time.sleep(.1)
            assert (root/'copy-held').exists()
            cancelled=json.loads(inside(binary,'cancel',job).stdout);assert cancelled['ok'],cancelled
            state,result=wait(job);assert state=='cancelled',(state,result)
            assert config()['state']=='migration_copying'
            (root/'hold-copy').unlink()
            # An external UCI edit is not overwritten even by recovery.
            inside('sh','-c','printf "\\n# external-edit\\n" >> '+shlex.quote(str(uci)))
            state,result=wait(submit(op='storage_recover'));assert state=='failed' and result['error']=='docker_settings_external_change',(state,result)
            inside('python3','-c',"from pathlib import Path;p=Path("+repr(str(uci))+");p.write_text(p.read_text().replace('\\n# external-edit\\n',''))")
            state,result=wait(submit(op='storage_recover'));assert state=='success' and result['rollback']=='restored',(state,result)
            print('ok: copy failure restores; cancellation keeps source and requires recovery; external UCI edits preserved',flush=True)
        finally:
            docker('rm','-f','-v','migration-running','migration-stopped',check=False)
            inside(root/'init-dockerd','stop',check=False)
            inside('rm','-rf',source,root/'mount',root/'exec',check=False)
            inside('chmod','-R','a+rwX',root,check=False)

if __name__=='__main__':main()
