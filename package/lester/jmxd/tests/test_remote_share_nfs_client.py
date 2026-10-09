#!/usr/bin/env python3
"""Real NFS client test. Run only inside the task's disposable OpenWrt VM.
Uses /tmp/remote-share-nfs-live and /tmp/remote-share-nfs-client; never production.
The C driver owns configuration writes. No system account changes are needed.
"""
from pathlib import Path
import errno,json,os,subprocess,urllib.request
base=Path('/tmp/remote-share-nfs-live');client=Path('/tmp/remote-share-nfs-client')
base.mkdir(exist_ok=True);client.mkdir(exist_ok=True);os.chown(base,0,65534);os.chmod(base,0o770)
(base/'keep.txt').write_text('NFS fixture');os.chmod(base/'keep.txt',0o644)
def call(op,args=None,id=None,success=True):
 request=urllib.request.Request('http://127.0.0.1:18086',json.dumps(dict(op=op,service='nfs',args=args or {},id=id)).encode())
 value=json.load(urllib.request.urlopen(request,timeout=180));assert (value['code']==2000)==success,value;return value['data']
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30)
def mount():run('/sbin/mount.nfs','127.0.0.1:/remote-share/'+share['id'],str(client),'-o','vers=3,proto=tcp,nolock,timeo=20,retrans=1')
def control(action):return call('action',{'confirm':True,'expected_revision':call('get')['control_revision'],'action':action})
def passed(step):print(json.dumps({'passed':step}),flush=True)
original=call('get');rpc_was_running=subprocess.run(['/etc/init.d/rpcbind','status'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
share=None;mounted=False
try:
 if not rpc_was_running:run('/etc/init.d/rpcbind','start')
 for item in original['exports']:
  if item['path']==str(base):call('nfs-delete',{'confirm':True,'expected_revision':item['revision']},item['id'])
 share=call('nfs',{'confirm':True,'path':str(base),'clients':'127.0.0.1','options':'rw,sync,root_squash,no_subtree_check'})
 mount();mounted=True
 assert (client/'keep.txt').read_text()=='NFS fixture'
 fd=os.open(client/'client.txt',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o660)
 os.write(fd,b'root is squashed');os.fsync(fd);os.close(fd)
 assert (base/'client.txt').stat().st_uid==65534
 passed('real_nfs_read_write_and_root_squash')
 current=call('get');export_projection=Path('/etc/exports').read_bytes();control_revision=current['control_revision']
 result=call('settings',{'confirm':True,'expected_revision':current['revision'],'default_clients':'198.51.100.0/24','default_options':'ro,sync,root_squash,fsid=8'})
 assert result['persisted'] and not result['applied'] and result['affected_existing_exports']==0
 updated=call('get');assert updated['default_clients']=='198.51.100.0/24' and updated['control_revision']==control_revision
 assert Path('/etc/exports').read_bytes()==export_projection and updated['exports']==current['exports']
 assert (client/'keep.txt').read_text()=='NFS fixture'
 (client/'after-default-change.txt').write_text('existing export still writable')
 passed('new_export_defaults_leave_live_export_unchanged')

 run('/bin/umount',str(client));mounted=False
 share=call('nfs',{'confirm':True,'expected_revision':share['revision'],'options':'ro,sync,root_squash,no_subtree_check'},share['id'])
 mount();mounted=True
 try:
  fd=os.open(client/'forbidden.txt',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o660)
  try:os.write(fd,b'must fail');os.fsync(fd)
  finally:os.close(fd)
  raise AssertionError('read-only NFS allowed write')
 except OSError as error:assert error.errno in [errno.EROFS,errno.EACCES,errno.EPERM],error
 passed('read_only_export_rejects_client_write')
 run('/bin/umount',str(client));mounted=False
 deleted_path='/remote-share/'+share['id']
 call('nfs-delete',{'confirm':True,'expected_revision':share['revision']},share['id']);share=None
 assert (base/'keep.txt').read_text()=='NFS fixture'
 assert all(x['path']!=str(base) for x in call('get')['exports'])
 result=subprocess.run(['/sbin/mount.nfs','127.0.0.1:'+deleted_path,str(client),'-o','vers=3,proto=tcp,nolock,timeo=20,retrans=1,retry=0'],capture_output=True,timeout=30)
 if result.returncode==0:mounted=True
 assert result.returncode!=0,'deleted export still mounts'
 passed('delete_revokes_export_and_preserves_data')
 print(json.dumps({'result':'PASS','scope':'isolated VM real kernel NFS server and client; no production device'}),flush=True)
finally:
 if mounted:subprocess.run(['/bin/umount',str(client)],capture_output=True,timeout=30)
 if share:call('nfs-delete',{'confirm':True,'expected_revision':share['revision']},share['id'])
 current=call('get')
 call('settings',{'confirm':True,'expected_revision':current['revision'],**{key:original[key] for key in ['default_clients','default_options']}})
 if not original['running']:control('stop')
 if not rpc_was_running:subprocess.run(['/etc/init.d/rpcbind','stop'],capture_output=True,timeout=30)
