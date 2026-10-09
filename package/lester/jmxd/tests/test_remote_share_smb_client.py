#!/usr/bin/env python3
"""SMB protocol integration against the task-owned 31.6 isolated VM.
Requires the explicit VM fixture transport on loopback:18086 and SMB:11445.
Uses only hwalice/hwbob and Alpha/Beta beneath /tmp/remote-share-live.
Run with the task's smbprotocol environment; never point at a production device.
"""
import json,urllib.request,smbclient
from smbprotocol.exceptions import SMBOSError,SMBResponseException,SMBAuthenticationError
URL='http://127.0.0.1:18086';server='127.0.0.1';PORT=11445
secret='Live-SMB-test-123';rotated='Live-SMB-rotated-456';steps=[]
def record(step):
 steps.append(step);print(json.dumps({'passed':step}),flush=True)
def call(op,args=None,id=None):
 body=json.dumps(dict(op=op,service='samba',args=args or {},id=id)).encode()
 value=json.load(urllib.request.urlopen(urllib.request.Request(URL,body),timeout=100))
 assert value['code']==2000,value
 return value['data']
def login(name,password=secret):
 smbclient.reset_connection_cache()
 smbclient.register_session(server,username=name,password=password,port=PORT,auth_protocol='ntlm',connection_timeout=10)
def read(share):
 with smbclient.open_file('\\\\'+server+'\\'+share+'\\readme.txt',mode='r',port=PORT) as f:return f.read()
def write(share):
 with smbclient.open_file('\\\\'+server+'\\'+share+'\\client.txt',mode='w',port=PORT) as f:f.write('SMB client data')
def deny(fn):
 try:fn()
 except (SMBOSError,SMBResponseException) as e:
  status=getattr(e,'ntstatus',getattr(e,'status',None));assert status in [0xc0000022,0xc000006d,0xc0000072],repr(e)
  return
 raise AssertionError('operation unexpectedly permitted')
for item in call('get')['shares']:
 if item['name'] in ['Alpha','Beta'] and item['path'].startswith('/tmp/remote-share-live/'):
  call('samba-delete',{'confirm':True,'expected_revision':item['revision']},item['id'])
for item in call('account-GET')['items']:
 if item['username'] in ['hwalice','hwbob']:
  call('account-DELETE',{'confirm':True,'expected_revision':item['revision']},item['id'])
a=call('account-POST',{'confirm':True,'username':'hwalice','password':secret})
b=call('account-POST',{'confirm':True,'username':'hwbob','password':secret})
alpha=call('samba',{'confirm':True,'name':'Alpha','path':'/tmp/remote-share-live/alpha','allowed_users':[a['login'],b['login']],'read_only_users':[b['login']],'read_only':False})
beta=call('samba',{'confirm':True,'name':'Beta','path':'/tmp/remote-share-live/beta','allowed_users':[a['login']],'read_only':False})
record('accounts_and_shares_applied')
login(a['login']);assert read('Alpha')=='alpha fixture';write('Alpha');assert read('Beta')=='beta fixture';write('Beta');record('alice_read_write_both_shares')
login(b['login']);assert read('Alpha')=='alpha fixture';deny(lambda:write('Alpha'));deny(lambda:read('Beta'));record('bob_readonly_alpha_denied_beta')
alpha=call('samba',{'confirm':True,'expected_revision':alpha['revision'],'read_only':True},alpha['id'])
login(a['login']);assert read('Alpha')=='alpha fixture';deny(lambda:write('Alpha'));record('share_readonly_overrides_user_write')
a=call('account-PUT',{'confirm':True,'expected_revision':a['revision'],'password':rotated},a['id'])
try:login(a['login'])
except (SMBAuthenticationError, SMBResponseException) as error:
 if isinstance(error, SMBResponseException):assert error.status in [0xc000006d,0xc0000072]
else:raise AssertionError('old password accepted')
login(a['login'],rotated);assert read('Beta')=='beta fixture';record('password_rotation_real_login')
b=call('account-PUT',{'confirm':True,'expected_revision':b['revision'],'enabled':False},b['id'])
try:login(b['login'])
except (SMBAuthenticationError, SMBResponseException) as error:
 if isinstance(error, SMBResponseException):assert error.status in [0xc000006d,0xc0000072]
else:raise AssertionError('disabled account accepted')
record('disabled_account_denied')
call('samba-delete',{'confirm':True,'expected_revision':alpha['revision']},alpha['id'])
call('samba-delete',{'confirm':True,'expected_revision':beta['revision']},beta['id'])
call('account-DELETE',{'confirm':True,'expected_revision':a['revision']},a['id'])
call('account-DELETE',{'confirm':True,'expected_revision':b['revision']},b['id'])
assert not call('account-GET')['items'];record('references_and_accounts_removed')
smbclient.reset_connection_cache()
print(json.dumps({'result':'PASS','environment':'isolated QEMU overlay on 31.6','steps':steps}))
