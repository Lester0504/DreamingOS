#!/usr/bin/env python3
"""Disposable VM only: two 32 MiB virtio test disks + real NFS client.
Paired with test_remote_share_binding_smb_client.py on the host. The temporary
HTTP test transport exchanges phase/ack files; no product endpoint is added.
"""
from pathlib import Path
import json,os,subprocess,time,urllib.request,uuid

assert Path('/tmp/hw-remote-share-resume-1003-vm').exists(), 'disposable VM marker required'
root=Path('/mnt/remote-share-binding-test');client=Path('/tmp/remote-share-binding-client')
root.mkdir(exist_ok=True);client.mkdir(exist_ok=True)
phase_file=Path('/tmp/remote-share-binding-phase.json');ack_file=Path('/tmp/remote-share-binding-ack.json')
session=str(uuid.uuid4());shares={};mounted=False;disk_mounted=False
def run(*args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True,timeout=40)
def call(op,service='nfs',args=None,id=None,success=True):
    body=json.dumps(dict(op=op,service=service,args=args or {},id=id)).encode()
    value=json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18086',body),timeout=180))
    assert (value['code']==2000)==success,value
    return value['data']
def items(service):return call('get',service)[ 'shares' if service=='samba' else 'exports']
def fixture(label):
    d=root/'data';d.mkdir(exist_ok=True);os.chown(d,0,65534);os.chmod(d,0o770)
    (d/'marker.txt').write_text(label);os.chown(d/'marker.txt',0,65534);os.chmod(d/'marker.txt',0o660)
def disk(device):
    global disk_mounted
    run('/bin/mount',device,str(root));disk_mounted=True
def unmount_disk():
    global disk_mounted
    run('/bin/umount',str(root));disk_mounted=False
def wait_state(available,published):
    until=time.monotonic()+90
    while time.monotonic()<until:
        try:
            rows=[next(r for r in items(service) if r['id']==s['id']) for service,s in shares.items()]
            if all(r['path_available']==available and r['published']==published for r in rows):
                # The watcher may be between mounting the pin and applying the daemon.
                configs=Path('/etc/exports').read_text()+Path('/var/etc/smb.conf').read_text()
                if all((('/remote-share/'+s['id']) in configs)==published for s in shares.values()):return rows
        except (AssertionError,StopIteration):pass
        time.sleep(1)
    raise AssertionError(('binding state did not settle',available,published))
def phase(name,value=None):
    token=session+':'+name
    phase_file.write_text(json.dumps(dict(token=token,name=name,value=value,share='BindingGuest')))
    until=time.monotonic()+60
    while time.monotonic()<until:
        try:
            ack=json.loads(ack_file.read_text())
            if ack.get('token')==token:
                assert ack.get('ok'),ack
                print(json.dumps({'passed':name,'smb':ack}),flush=True);return
        except (FileNotFoundError,json.JSONDecodeError):pass
        time.sleep(.3)
    raise AssertionError('SMB observer did not acknowledge '+name)
def mount_client(success=True):
    global mounted
    share=shares['nfs'];target='/remote-share/'+share['id']
    result=run('/sbin/mount.nfs','127.0.0.1:'+target,str(client),'-o','vers=3,proto=tcp,nolock,soft,timeo=10,retrans=1,retry=0,actimeo=0,lookupcache=none',check=False)
    mounted=result.returncode==0
    assert mounted==success,(result.returncode,result.stderr)
def unmount_client():
    global mounted
    if mounted:run('/bin/umount',str(client));mounted=False
def verify_client(value):
    mount_client();assert (client/'marker.txt').read_text()==value
    (client/'from-nfs.txt').write_text('client-write')
    assert (root/'data/from-nfs.txt').stat().st_uid==65534
    unmount_client()

try:
    for device in ['vdb','vdc']:
        assert Path('/sys/block/'+device+'/size').read_text().strip()=='65536'
        run('/usr/sbin/mkfs.ext4','-F','/dev/'+device)
    fixture('UNDERLYING_SYSTEM_DIRECTORY')
    disk('/dev/vdb');fixture('ORIGINAL_DISK');unmount_disk()
    disk('/dev/vdc');fixture('REPLACEMENT_DISK');unmount_disk()
    disk('/dev/vdb')
    run('/etc/init.d/rpcbind','start')
    current=call('get','samba')
    call('settings','samba',{'confirm':True,'expected_revision':current['revision'],'guest_access':True})
    shares['samba']=call('samba','samba',{'confirm':True,'name':'BindingGuest','path':str(root/'data'),'guest_access':True,'read_only':True})
    shares['nfs']=call('nfs',args={'confirm':True,'path':str(root/'data'),'clients':'127.0.0.1','options':'rw,sync,root_squash,no_subtree_check'})
    original_revisions={k:v['revision'] for k,v in shares.items()}
    # Simulate pre-binding persisted rows: seed migrates the identity in place,
    # without replacing IDs or consuming either protocol's edit revision.
    import sqlite3
    with sqlite3.connect('/tmp/remote-share-live.db',timeout=30) as db:
        db.execute('DELETE FROM file_share_binding')
    wait_state(True,True)
    for service,s in shares.items():assert next(r for r in items(service) if r['id']==s['id'])['revision']==original_revisions[service]
    verify_client('ORIGINAL_DISK');phase('original_disk_published','ORIGINAL_DISK')
    unmount_disk();wait_state(False,False)
    assert (root/'data/marker.txt').read_text()=='UNDERLYING_SYSTEM_DIRECTORY'
    mount_client(False);phase('unmount_revokes_without_exposing_underlying')
    disk('/dev/vdc');wait_state(False,False)
    mount_client(False);phase('replacement_disk_is_not_trusted')
    denied=call('nfs',args={'confirm':True,'expected_revision':shares['nfs']['revision'],'note':'ordinary save'},id=shares['nfs']['id'],success=False)
    assert denied['error']=='directory_binding_changed'
    unmount_disk();disk('/dev/vdb');wait_state(True,True)
    verify_client('ORIGINAL_DISK');phase('original_identity_restores_automatically','ORIGINAL_DISK')
    for service,s in shares.items():assert next(r for r in items(service) if r['id']==s['id'])['revision']==original_revisions[service]
    unmount_disk();disk('/dev/vdc');wait_state(False,False)
    for service,s in list(shares.items()):
        shares[service]=call('samba' if service=='samba' else 'nfs',service,{'confirm':True,'expected_revision':s['revision'],'rebind':True},s['id'])
    wait_state(True,True);verify_client('REPLACEMENT_DISK');phase('explicit_rebind_trusts_selected_disk','REPLACEMENT_DISK')
    stale=call('nfs',args={'confirm':True,'expected_revision':original_revisions['nfs'],'rebind':True},id=shares['nfs']['id'],success=False)
    assert stale['error']=='revision_conflict'
    unmount_disk();wait_state(False,False)
    for service,s in list(shares.items()):
        shares[service]=call('samba' if service=='samba' else 'nfs',service,{'confirm':True,'expected_revision':s['revision'],'enabled':False},s['id'])
        call('samba-delete' if service=='samba' else 'nfs-delete',service,{'confirm':True,'expected_revision':shares[service]['revision']},s['id'])
    shares.clear();phase('offline_disable_and_delete_revoke')
    for device,label in [('/dev/vdb','ORIGINAL_DISK'),('/dev/vdc','REPLACEMENT_DISK')]:
        disk(device);assert (root/'data/marker.txt').read_text()==label
        assert (root/'data').stat().st_uid==0 and (root/'data').stat().st_gid==65534
        assert (root/'data').stat().st_mode&0o777==0o770
        unmount_disk()
    print(json.dumps({'result':'PASS','scope':'real ext4 UUID/mount replacement, NFS root_squash, SMB observer, rollback/revision and offline removal'}),flush=True)
finally:
    unmount_client()
    for service,s in shares.items():
        try:call('samba-delete' if service=='samba' else 'nfs-delete',service,{'confirm':True,'expected_revision':s['revision']},s['id'])
        except Exception as e:print('cleanup error',str(e),flush=True)
    if disk_mounted:unmount_disk()
