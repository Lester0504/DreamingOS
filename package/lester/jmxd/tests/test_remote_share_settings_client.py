#!/usr/bin/env python3
"""Real SMB settings test against the task-owned QEMU VM only.
Run on 31.6 in the smbprotocol test environment. Loopback forwards 18886/18845
belong to hw-remote-share-resume-1003; no production device is contacted.
"""
import json, uuid, urllib.request
from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, ImpersonationLevel, FilePipePrinterAccessMask, FileAttributes, ShareAccess, CreateDisposition, CreateOptions
from smbprotocol.exceptions import SMBResponseException
URL='http://127.0.0.1:18886';PORT=18845

def call(op,args=None,id=None,success=True):
    value=json.load(urllib.request.urlopen(urllib.request.Request(URL,json.dumps(dict(op=op,service='samba',args=args or {},id=id)).encode()),timeout=120))
    assert (value['code']==2000)==success,value
    return value['data']
def setting(**fields):
    current=call('get')
    return call('settings',{'confirm':True,'expected_revision':current['revision'],**fields})
def passed(name):print(json.dumps({'passed':name}),flush=True)
def connection(dialect):
    c=Connection(uuid.uuid4(),'127.0.0.1',port=PORT,require_signing=False)
    try:c.connect(dialect=dialect,timeout=15)
    except Exception:
        c.disconnect();raise
    return c

def guest_allowed():
    c=connection(Dialects.SMB_3_1_1)
    try:
        s=Session(c,'remote_share_unknown_user','fixture-invalid-password',require_encryption=False,auth_protocol='ntlm');s.connect()
        t=TreeConnect(s,r'\\127.0.0.1\PolicyGuest');t.connect(require_secure_negotiate=False)
        f=Open(t,'readme.txt');f.create(ImpersonationLevel.Impersonation,FilePipePrinterAccessMask.GENERIC_READ,FileAttributes.FILE_ATTRIBUTE_NORMAL,ShareAccess.FILE_SHARE_READ,CreateDisposition.FILE_OPEN,CreateOptions.FILE_NON_DIRECTORY_FILE)
        assert f.read(0,128)==b'alpha fixture';f.close()
        t.disconnect();s.disconnect()
    finally:c.disconnect()

before=call('get');share=None
assert 'min_protocol' in before['settings_fields']
assert all(s['name']!='PolicyGuest' for s in before['shares'])
try:
    setting(min_protocol='SMB2_10',max_protocol='SMB3_11',guest_access=True)
    share=call('samba',{'confirm':True,'name':'PolicyGuest','path':'/tmp/remote-share-live/alpha','guest_access':True,'read_only':True})
    c=connection(Dialects.SMB_2_1_0);assert c.dialect==Dialects.SMB_2_1_0;c.disconnect()
    c=connection(Dialects.SMB_3_1_1);assert c.dialect==Dialects.SMB_3_1_1;c.disconnect()
    passed('allowed_smb21_and_smb311_negotiate')
    try:connection(Dialects.SMB_2_0_2)
    except SMBResponseException as e:assert e.status==0xc00000bb,e
    else:raise AssertionError('SMB2_02 accepted below minimum')
    setting(min_protocol='SMB2_10',max_protocol='SMB2_10')
    try:connection(Dialects.SMB_3_1_1)
    except SMBResponseException as e:assert e.status==0xc00000bb,e
    else:raise AssertionError('SMB3_11 accepted above maximum')
    passed('minimum_and_maximum_reject_outside_dialects')
    setting(max_protocol='SMB3_11')
    guest_allowed();passed('guest_share_access_enabled')
    setting(guest_access=False)
    assert call('get')['shares'][-1]['guest_access'] is True,'global gate must not rewrite share intent'
    try:guest_allowed()
    except SMBResponseException as e:assert e.status in [0xc000006d,0xc0000022],e
    else:raise AssertionError('global guest disable still permits access')
    setting(guest_access=True);guest_allowed()
    passed('global_guest_gate_denies_and_restores_real_access')
    current=call('get')
    error=call('settings',{'confirm':True,'expected_revision':before['revision'],'guest_access':False},success=False)
    assert error['error']=='revision_conflict' and call('get')['revision']==current['revision']
    passed('stale_settings_revision_does_not_change_service')
    print(json.dumps({'result':'PASS','scope':'isolated VM real Samba dialect negotiation and guest share access'}),flush=True)
finally:
    if share:call('samba-delete',{'confirm':True,'expected_revision':share['revision']},share['id'])
    setting(**{k:before[k] for k in ['workgroup','server_description','interfaces','min_protocol','max_protocol','guest_access']})
