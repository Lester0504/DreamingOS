#!/usr/bin/env python3
"""Host observer for the disposable VM's disk binding test; loopback only."""
import json,time,urllib.request,uuid
from smbprotocol.connection import Connection,Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open,ImpersonationLevel,FilePipePrinterAccessMask,FileAttributes,ShareAccess,CreateDisposition,CreateOptions

URL='http://127.0.0.1:18886';seen=set();held=None
def connect():
    c=Connection(uuid.uuid4(),'127.0.0.1',port=18845,require_signing=False)
    try:
        c.connect(dialect=Dialects.SMB_3_1_1,timeout=10)
        s=Session(c,'binding_unknown_user','fixture-invalid-password',require_encryption=False,auth_protocol='ntlm');s.connect()
        t=TreeConnect(s,r'\\127.0.0.1\BindingGuest');t.connect(require_secure_negotiate=False)
        return c,t
    except Exception:c.disconnect();raise
def read(t):
    f=Open(t,'marker.txt');f.create(ImpersonationLevel.Impersonation,FilePipePrinterAccessMask.GENERIC_READ,FileAttributes.FILE_ATTRIBUTE_NORMAL,ShareAccess.FILE_SHARE_READ,CreateDisposition.FILE_OPEN,CreateOptions.FILE_NON_DIRECTORY_FILE)
    try:return f.read(0,128).decode()
    finally:f.close()
until=time.monotonic()+600
while time.monotonic()<until:
    try:p=json.load(urllib.request.urlopen(URL+'/binding-phase',timeout=5))
    except Exception:time.sleep(.5);continue
    if not p or p['token'] in seen:time.sleep(.3);continue
    error='';c=None
    try:
        if p['name']=='unmount_revokes_without_exposing_underlying' and held:
            try:value=read(held[1])
            except Exception:pass
            else:raise AssertionError('existing SMB session still reads '+value)
            held[0].disconnect();held=None
        if p['value'] is not None:
            c,t=connect();assert read(t)==p['value']
            if p['name']=='original_disk_published':held=(c,t);c=None
        else:
            try:c,t=connect();value=read(t)
            except Exception:pass
            else:raise AssertionError('withdrawn share reads '+value)
    except Exception as e:error=str(e)
    finally:
        if c:c.disconnect()
    ack={'token':p['token'],'ok':not error,'error':error}
    urllib.request.urlopen(urllib.request.Request(URL+'/binding-ack',json.dumps(ack).encode()),timeout=10).read()
    print(json.dumps({'phase':p['name'],**ack}),flush=True)
    assert not error,error
    seen.add(p['token'])
    if p['name']=='offline_disable_and_delete_revoke':break
else:raise AssertionError('binding client test timed out')
print(json.dumps({'result':'PASS','phases':len(seen)}),flush=True)
