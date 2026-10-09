#!/usr/bin/env python3
"""Exercise the real LXC job/DB logic with explicit copy/snapshot CLI faults."""
import json,os,sqlite3,subprocess,sys,tempfile,time
from pathlib import Path
from test_container_service_runtime import compile_fixture

def main():
 if sys.platform!='linux':print('SKIP: job process identity needs Linux /proc');return
 with tempfile.TemporaryDirectory(prefix='lxc-maintenance-') as directory:
  t=Path(directory).resolve();root=t/'containers';root.mkdir();b=t/'bin';b.mkdir();source=root/'source';(source/'rootfs').mkdir(parents=True)
  external=t/'shared';external.mkdir();(external/'marker').write_text('external')
  config=f'lxc.rootfs.path = dir:{source}/rootfs\nlxc.net.0.type = veth\nlxc.net.0.link = br-test\nlxc.start.auto = 0\nlxc.mount.entry = {external} mnt/shared none bind,rw,create=dir 0 0\n'
  (source/'config').write_text(config);(source/'rootfs/marker').write_text('before')
  exe=compile_fixture(t,t/'jobs.db');script='''#!/usr/bin/env python3
import os,sys,time,shutil,json
from pathlib import Path
t=Path(os.environ['LXC_TEST_ROOT']);cmd=Path(sys.argv[0]).name
if cmd=='lxc-config':print(t/'containers');sys.exit(0)
root=Path(sys.argv[sys.argv.index('-P')+1]);name=sys.argv[sys.argv.index('-n')+1];d=root/name
if cmd=='lxc-info':
 if not (d/'config').exists():sys.exit(1)
 print('RUNNING' if (t/'running').exists() else 'STOPPED');sys.exit(0)
if cmd=='lxc-copy':
 if (t/'copy-before').exists():(t/'copy-waiting').touch();time.sleep(20)
 if (t/'copy-fail').exists():sys.exit(1)
 dest=root/sys.argv[sys.argv.index('-N')+1];dest.mkdir();shutil.copytree(d/'rootfs',dest/'rootfs')
 (dest/'config').write_text((d/'config').read_text().replace(str(d/'rootfs'),str(dest/'rootfs')))
 if (t/'slow').exists():time.sleep(20)
elif cmd=='lxc-snapshot':
 snaps=d/'snaps';snaps.mkdir(exist_ok=True)
 if '-r' in sys.argv:
  snap=snaps/sys.argv[sys.argv.index('-r')+1]
  if (t/'restore-fail').exists():(d/'rootfs/marker').write_text('partial');sys.exit(1)
  shutil.rmtree(d/'rootfs');shutil.copytree(snap/'rootfs',d/'rootfs')
 elif '-d' in sys.argv:
  snap=snaps/sys.argv[sys.argv.index('-d')+1];shutil.rmtree(snap)
 else:
  i=0
  while (snaps/('snap'+str(i))).exists():i+=1
  snap=snaps/('snap'+str(i));snap.mkdir();shutil.copytree(d/'rootfs',snap/'rootfs');(snap/'config').write_text((d/'config').read_text());(snap/'ts').write_text('2026:10:07 20:00:00')
'''
  for name in ['lxc-config','lxc-info','lxc-copy','lxc-snapshot','lxc-start','lxc-stop']:(b/name).write_text(script);(b/name).chmod(0o755)
  env=dict(os.environ,LXC_TEST_ROOT=str(t),DOCKER_WORKFLOW_TEST_ROOT=str(t),PATH=str(b)+':'+os.environ['PATH'])
  def call(*args):
   p=subprocess.run([str(exe),*args],text=True,capture_output=True,env=env,timeout=20);assert p.stdout,p.stderr;return json.loads(p.stdout)
  def doc(name='source'):return call('lxc-config',name)['data']
  baseline=doc();saved=call('lxc-action','source','config_set',json.dumps({'confirm':True,'takeover':True,'identity':baseline['identity'],'fingerprint':baseline['fingerprint'],'revision':0,'fields':{'cpu_weight':100}}));assert saved['persisted'],saved
  origin={'name':'source','lxcpath':str(root),'mounts':[{'source':{'path':str(external)},'target':'/mnt/shared','read_only':False}]}
  with sqlite3.connect(t/'config.db') as db:
   db.execute("UPDATE lxc_config_document SET desired=applied,state='idle'")
   db.execute('CREATE TABLE lxc_origin(path TEXT PRIMARY KEY,source_json TEXT NOT NULL)');db.execute('INSERT INTO lxc_origin VALUES(?,?)',(str(source/'config'),json.dumps(origin)))
  def action(kind,**patch):
   d=doc();return call('lxc-action','source',kind,json.dumps({'confirm':True,'identity':d['identity'],'fingerprint':d['fingerprint'],**patch}))
  def wait(job):
   assert 'job_id' in job,job
   for _ in range(120):
    item=call('lxc-get',job['job_id'])['data']
    if item['state'] not in ['queued','running']:return item
    time.sleep(.05)
   raise AssertionError(item)
  assert action('clone',new_name='../bad')['error']=='invalid_clone_name'
  assert action('clone',new_name='copy',mount_policy='share')['error']=='shared_mount_confirmation_required'
  assert action('clone',new_name='copy',identity='changed')['error']=='container_identity_changed'
  assert action('clone',new_name='copy',fingerprint='changed')['error']=='lxc_config_external_conflict'
  (t/'running').touch();assert action('snapshot')['error']=='container_must_be_stopped';(t/'running').unlink()
  preview=action('maintenance_preflight',operation='clone',new_name='copy');assert preview['ok'] and not (root/'copy').exists(),preview
  copied=wait(action('clone',new_name='copy'));assert copied['state']=='success',copied
  assert doc('copy')['config'].rstrip().endswith('lxc.mount.entry =') and (root/'copy/rootfs/marker').read_text()=='before'
  assert action('clone',new_name='copy')['error']=='lxc_name_exists'
  (t/'copy-before').touch();pending=action('clone',new_name='reserved')
  for _ in range(100):
   if (t/'copy-waiting').exists():break
   time.sleep(.03)
  other=doc('copy')
  collision=call('lxc-action','copy','clone',json.dumps({'confirm':True,'identity':other['identity'],'fingerprint':other['fingerprint'],'new_name':'reserved'}))
  assert collision['error']=='container_operation_busy',collision
  assert call('lxc-cancel',pending['job_id'])['ok'];assert wait(pending)['state']=='cancelled'
  (t/'copy-before').unlink();(t/'copy-waiting').unlink()
  (t/'slow').touch();pending=action('clone',new_name='partial-copy')
  for _ in range(100):
   if (root/'partial-copy/config').exists():break
   time.sleep(.03)
  assert (root/'partial-copy/config').exists()
  assert call('lxc-cancel',pending['job_id'])['ok'];partial=wait(pending);(t/'slow').unlink()
  assert partial['state']=='cancelled' and partial['result']['remaining_copy'],partial
  assert partial['result']['remaining_copy_path']==str(root/'partial-copy') and partial['result']['observed_copy_identity'],partial
  assert partial['result']['copy_ownership_verified'] is False,partial

  snap=wait(action('snapshot'));assert snap['state']=='success',snap
  items=call('lxc-action','source','snapshot_list','{}')['items'];selected=next(i for i in items if i['id']==snap['result']['snapshot'])
  request={'snapshot':selected['id'],'snapshot_identity':selected['identity']}
  assert action('snapshot_delete',snapshot='../bad')['error']=='invalid_snapshot_name'
  assert action('snapshot_delete',**{**request,'snapshot_identity':'bad'})['error']=='lxc_snapshot_changed'
  assert action('snapshot_restore',**request)['error']=='restore_confirmation_required'
  (source/'rootfs/marker').write_text('after')
  (t/'copy-fail').touch();failed=wait(action('snapshot_restore',restore_confirm=True,**request));(t/'copy-fail').unlink()
  assert failed['state']=='failed' and (source/'rootfs/marker').read_text()=='after',failed
  (t/'restore-fail').touch();failed=wait(action('snapshot_restore',restore_confirm=True,**request));(t/'restore-fail').unlink()
  assert failed['state']=='failed' and failed['result']['rollback_ready'],failed
  assert (root/failed['result']['rollback_container']/'rootfs/marker').read_text()=='after'
  restored=wait(action('snapshot_restore',restore_confirm=True,**request));assert restored['state']=='success' and (source/'rootfs/marker').read_text()=='before',restored
  deleted=wait(action('snapshot_delete',**request));assert deleted['state']=='success',deleted
  assert call('lxc-action','source','snapshot_list','{}')['items']==[]
  assert (external/'marker').read_text()=='external'
  print('PASS: stopped/identity/config guards, copy with detached mounts, precise snapshot identity/delete, restore confirmation, backup failure preserves source, restore failure preserves rollback data, restored marker and external data')

if __name__=='__main__':main()
