#!/usr/bin/env python3
"""Run ONLY in the task-owned disposable VM, never on a production router.
Exercises the real nginx/ujail, account tools, C transaction driver and HTTP DAV.
Creates only davalice/davbob and /tmp/remote-share-dav-live fixtures.
"""
from pathlib import Path
import base64,http.client,json,os,ssl,subprocess,urllib.request,shutil,time,socket,uuid
BASE=Path('/tmp/remote-share-dav-live');BASE.mkdir(exist_ok=True)
secret='DAV-fixture-only-123';rotated='DAV-rotated-only-456'
def call(op,args=None,id=None,success=True):
 data=json.dumps(dict(op=op,args=args or {},id=id,service='webdav')).encode()
 value=json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18086',data),timeout=300))
 assert (value['code']==2000)==success,value
 return value['data']
def request(method,path='/',user='dwshare_davalice',password=secret,body=None,headers=None,port=15091,tls=False):
 conn=http.client.HTTPSConnection('127.0.0.1',port,context=ssl._create_unverified_context(),timeout=20) if tls else http.client.HTTPConnection('127.0.0.1',port,timeout=20)
 h={'Authorization':'Basic '+base64.b64encode((user+':'+password).encode()).decode(),**(headers or {})}
 conn.request(method,path,body,h);resp=conn.getresponse();data=resp.read();status=resp.status;conn.close();return status,data
def ok(step):print(json.dumps({'passed':step}),flush=True)
for name in ['alpha','beta','outside']:
 p=BASE/name;p.mkdir(exist_ok=True);os.chown(p,0,65534);os.chmod(p,0o770)
 for extra in ['new.txt','copied.txt','moved.txt','dir']:
  q=p/extra
  if q.is_dir():shutil.rmtree(q)
  elif q.exists():q.unlink()
 (p/'readme.txt').write_text(name);os.chown(p/'readme.txt',0,65534);os.chmod(p/'readme.txt',0o660)
link=BASE/'alpha/link'
if not link.exists():link.symlink_to(BASE/'outside')
for s in call('get')['shares']:
 if s['path'].startswith(str(BASE)+'/') or (os.environ.get('REMOTE_SHARE_BINDING_DISKS')=='1' and s['path']=='/mnt/remote-share-dav-binding/data'):
  call('webdav-DELETE',{'confirm':True,'expected_revision':s['revision']},s['id'])
for a in call('account-GET')['items']:
 if a['username'] in ['davalice','davbob']:call('account-DELETE',{'confirm':True,'expected_revision':a['revision']},a['id'])
a=call('account-POST',{'confirm':True,'username':'davalice','password':secret})
b=call('account-POST',{'confirm':True,'username':'davbob','password':secret})
alpha=call('webdav-POST',{'confirm':True,'name':'DAV Alpha','path':str(BASE/'alpha'),'read_only':False,'listen_address':'127.0.0.1','listen_port':15091,'users':[{'account_id':a['id'],'read_only':False},{'account_id':b['id'],'read_only':True}]})
beta_request={'confirm':True,'request_id':'dav-client-'+str(uuid.uuid4()),'items':[{'protocol':'webdav','action':'create','body':{'name':'DAV Beta','path':str(BASE/'beta'),'read_only':False,'listen_address':'127.0.0.1','listen_port':15092,'users':[{'account_id':a['id'],'read_only':False}]}}]}
op=call('operation-POST',beta_request);assert op['state']=='success',op
beta=op['results'][0]['result']
assert call('operation-POST',beta_request)['results'][0]['result']['id']==beta['id']
assert len(call('get')['shares'])==2
ok('webdav_operation_receipt_and_duplicate_request')
call('action',{'confirm':True,'expected_revision':call('get')['control_revision'],'action':'start'})
ok('two_real_sandboxes_started')
initial=call('get')
call('action',{'confirm':True,'expected_revision':initial['control_revision'],'action':'enable'})
assert call('get')['running']
call('action',{'confirm':True,'expected_revision':initial['control_revision'],'action':'stop'},success=False)
current=call('get');call('action',{'confirm':True,'expected_revision':current['control_revision'],'action':'stop'})
assert call('get')['enabled'] and not call('get')['running']
current=call('get');call('action',{'confirm':True,'expected_revision':current['control_revision'],'action':'disable'})
assert not call('get')['running']
current=call('get');call('action',{'confirm':True,'expected_revision':current['control_revision'],'action':'start'})
assert not call('get')['enabled'] and call('get')['running']
ok('actions_revision_and_independent_autostart')
# A competing writer must be reported as busy, without applying either request.
import sqlite3
control=call('get')['control_revision']
with sqlite3.connect('/tmp/remote-share-live.db',timeout=30) as writer:
 writer.execute('BEGIN IMMEDIATE')
 busy=call('webdav-PUT',{'confirm':True,'expected_revision':alpha['revision'],'note':'must not commit'},alpha['id'],False)
 assert busy['error']=='storage_busy',busy
 busy=call('action',{'confirm':True,'expected_revision':control,'action':'stop'},success=False)
 assert busy['error']=='storage_busy',busy
 writer.rollback()
assert call('get')['running'] and call('get')['control_revision']==control
ok('competing_writer_reported_busy_without_changes')
assert request('OPTIONS')[0]==200
assert request('PROPFIND',headers={'Depth':'1'})[0]==207
assert request('GET','/readme.txt')==(200,b'alpha')
assert request('HEAD','/readme.txt')[0]==200
assert request('PUT','/new.txt',body='dav client') [0] in [201,204]
assert request('MKCOL','/dir/')[0]==201
assert request('COPY','/new.txt',headers={'Destination':'http://127.0.0.1:15092/cross.txt'})[0]==400
assert request('COPY','/new.txt',headers={'Destination':'http://127.0.0.1:15091/copied.txt'})[0] in [201,204]
assert request('MOVE','/copied.txt',headers={'Destination':'http://127.0.0.1:15091/moved.txt'})[0] in [201,204]
assert request('DELETE','/moved.txt')[0]==204
ok('options_propfind_get_head_put_mkcol_copy_move_delete')
assert request('GET','/readme.txt',user=b['login'])==(200,b'alpha')
assert request('PUT','/denied.txt',user=b['login'],body='must fail')[0] in [401,403]
assert request('GET','/readme.txt',user=b['login'],port=15092)[0] in [401,403]
assert request('PUT','/link/escaped.txt',body='must not escape')[0]>=400
assert not (BASE/'outside/escaped.txt').exists()
assert request('GET','/link/readme.txt')[0]>=400
# Credential projection and TLS keys must not be mounted in the data worker.
generation=Path('/etc/dreamingwrt/webdav/current').read_text().strip()
for name,target in [('credentials',Path(generation)/alpha['id']/'users'),('other-share',BASE/'beta')]:
 link=BASE/'alpha'/name
 if link.is_symlink():link.unlink()
 link.symlink_to(target)
 source='/'+name+('/readme.txt' if name=='other-share' else '')
 assert request('COPY',source,headers={'Destination':'http://127.0.0.1:15091/leaked.txt'})[0]>=400
 assert not (BASE/'alpha/leaked.txt').exists()

ok('per_user_acl_cross_share_denial_and_symlink_isolation')
alpha=call('webdav-PUT',{'confirm':True,'expected_revision':alpha['revision'],'read_only':True},alpha['id'])
assert request('PUT','/denied.txt',body='readonly')[0] in [401,403]
ok('share_readonly_overrides_user_write')
a=call('account-PUT',{'confirm':True,'expected_revision':a['revision'],'password':rotated},a['id'])
assert request('GET','/readme.txt',port=15092)[0]==401
assert request('GET','/readme.txt',password=rotated,port=15092)==(200,b'beta')
b=call('account-PUT',{'confirm':True,'expected_revision':b['revision'],'enabled':False},b['id'])
assert request('GET','/readme.txt',user=b['login'])[0]==401
ok('credential_rotation_and_disable_applied')
cert=BASE/'cert.pem';key=BASE/'key.pem'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
os.chown(key,0,65534);os.chmod(key,0o640)
beta=call('webdav-PUT',{'confirm':True,'expected_revision':beta['revision'],'tls':True,'cert_file':str(cert),'key_file':str(key)},beta['id'])
assert request('GET','/readme.txt',port=15092,tls=True,password=rotated)==(200,b'beta')
failed=call('webdav-PUT',{'confirm':True,'expected_revision':beta['revision'],'cert_file':str(BASE/'beta/readme.txt')},beta['id'],False)
assert failed['rolled_back'],failed
assert request('GET','/readme.txt',port=15092,tls=True,password=rotated)[0]==200
assert request('PUT','/tls.txt',port=15092,tls=True,password=rotated,body='tls')[0] in [201,204]
assert request('COPY','/tls.txt',port=15092,tls=True,password=rotated,headers={'Destination':'https://127.0.0.1:15092/tls-copy.txt'})[0] in [201,204]
assert request('DELETE','/tls-copy.txt',port=15092,tls=True,password=rotated)[0]==204
assert call('get')['last_error']=='webdav_preflight_failed'
# A real other listener prevents applying a conflicting share and leaves TLS live.
with socket.socket() as occupied:
 occupied.bind(('127.0.0.1',15093));occupied.listen()
 failed=call('webdav-POST',{'confirm':True,'name':'Conflict','path':str(BASE/'beta'),'listen_address':'127.0.0.1','listen_port':15093,'users':[{'account_id':a['id'],'read_only':True}]},success=False)
 assert failed['reason']=='port_in_use' and failed['rolled_back'],failed
assert request('GET','/readme.txt',port=15092,tls=True,password=rotated)[0]==200
ok('tls_invalid_certificate_and_port_conflict_rollback')
assert call('account-DELETE',{'confirm':True,'expected_revision':a['revision']},a['id'],False)['error']=='account_in_use'
# Mount-loss coverage is opt-in for the task VM with its two known scratch disks.
if os.environ.get('REMOTE_SHARE_BINDING_DISKS')=='1':
 assert Path('/tmp/hw-remote-share-resume-1003-vm').exists()
 for dev in ['vdb','vdc']:assert Path('/sys/block/'+dev+'/size').read_text().strip()=='65536'
 mountroot=Path('/mnt/remote-share-dav-binding');mountroot.mkdir(exist_ok=True)
 fallback=mountroot/'data';fallback.mkdir(exist_ok=True);(fallback/'marker.txt').write_text('SYSTEM_FALLBACK')
 def disk_run(*args):subprocess.run(args,check=True,capture_output=True,timeout=30)
 def disk_mount(dev):disk_run('/bin/mount',dev,str(mountroot))
 def disk_unmount():disk_run('/bin/umount',str(mountroot))
 def wait_disk(available,running):
  until=time.monotonic()+90
  while time.monotonic()<until:
   view=call('get');row=next(x for x in view['shares'] if x['id']==disk_share['id'])
   others_ready=all(not view['requested_running'] or not x['enabled'] or not x['path_available'] or x['running'] for x in view['shares'] if x['id']!=disk_share['id'])
   if row['path_available']==available and row['running']==running and others_ready:return row
   time.sleep(.5)
  raise AssertionError(('DAV binding did not settle',available,running,row))
 def not_listening():
  try:conn=socket.create_connection(('127.0.0.1',15094),timeout=2)
  except ConnectionRefusedError:return
  conn.close();raise AssertionError('withdrawn DAV still listens')
 disk_mount('/dev/vdb')
 disk_share=call('webdav-POST',{'confirm':True,'name':'DAV Disk','path':str(mountroot/'data'),'read_only':False,'listen_address':'127.0.0.1','listen_port':15094,'users':[{'account_id':a['id'],'read_only':False}]})
 assert request('GET','/marker.txt',port=15094,password=rotated)==(200,b'ORIGINAL_DISK')
 disk_unmount();wait_disk(False,False);not_listening()
 assert (fallback/'marker.txt').read_text()=='SYSTEM_FALLBACK'
 disk_mount('/dev/vdc');wait_disk(False,False);not_listening()
 denied=call('webdav-PUT',{'confirm':True,'expected_revision':disk_share['revision'],'note':'ordinary save'},disk_share['id'],False)
 assert denied['error']=='directory_binding_changed',denied
 disk_unmount();disk_mount('/dev/vdb');row=wait_disk(True,True)
 assert row['revision']==disk_share['revision']
 assert request('GET','/marker.txt',port=15094,password=rotated)==(200,b'ORIGINAL_DISK')
 ok('dav_unmount_withdrawal_replacement_denial_and_original_uuid_recovery')
 call('action',{'confirm':True,'expected_revision':call('get')['control_revision'],'action':'stop'})
 disk_unmount();disk_mount('/dev/vdb');time.sleep(3)
 assert not call('get')['requested_running'] and not call('get')['running'];not_listening()
 call('action',{'confirm':True,'expected_revision':call('get')['control_revision'],'action':'start'})
 assert request('GET','/marker.txt',port=15094,password=rotated)==(200,b'ORIGINAL_DISK')
 call('webdav-DELETE',{'confirm':True,'expected_revision':disk_share['revision']},disk_share['id']);disk_unmount()
 ok('dav_explicit_stop_survives_storage_recovery')
for s in [alpha,beta]:call('webdav-DELETE',{'confirm':True,'expected_revision':s['revision']},s['id'])
for port in [15091,15092]:
 try:
  sock=socket.create_connection(('127.0.0.1',port),timeout=2);sock.close()
  raise AssertionError('deleted share still listens')
 except ConnectionRefusedError:pass
for x in [a,b]:call('account-DELETE',{'confirm':True,'expected_revision':x['revision']},x['id'])
assert (BASE/'alpha/readme.txt').read_text()=='alpha'
ok('delete_preserves_data_and_releases_accounts')
print(json.dumps({'result':'PASS','scope':'isolated VM real nginx+ujail+C/SQLite/account tools, no production device'}),flush=True)
