#!/usr/bin/env python3
"""Exercise write-only upstream credentials with a generated loopback source.
Requires the IPTV_TESTING daemon and the integration HTTP fixture. The secret
key and all media are temporary test material under --directory.
"""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import threading
import time

p=argparse.ArgumentParser()
p.add_argument('--directory',required=True)
p.add_argument('--http-port',type=int,default=19751)
a=p.parse_args();root=Path(a.directory).resolve()
assert str(root).startswith('/tmp/') and (root/'synthetic.ts').exists()
checks=[]
def check(value,label):
    assert value,label
    checks.append(label)
def recv(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data));assert part;data+=part
    return data
def call(method,resource='',body=None):
    q=json.dumps(dict(method=method,resource=resource,body=body,actor='isolated-access-test')).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10);s.connect(str(root/'iptv.sock'));s.sendall(struct.pack('!I',len(q))+q)
        return json.loads(recv(s,struct.unpack('!I',recv(s,4))[0]))
def request(method,resource='',body=None):
    result=call(method,resource,body);assert not result['status'],result;return result['data']
def wait(channel,state):
    for _ in range(100):
        result=request('GET','channels/'+channel)['runtime']
        if result['state']==state:return result
        assert result['state']!='error',result
        time.sleep(.2)
    raise AssertionError(result)

secret='generated-iptv-fixture-secret'
auth='Basic '+base64.b64encode(('fixture:'+secret).encode()).decode()
media=(root/'synthetic.ts').read_bytes();authorized=[]
class Source(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        if self.path!='/source.ts?access='+secret or self.headers.get('Authorization')!=auth:
            self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="fixture"');self.end_headers();return
        authorized.append(True);self.send_response(200);self.send_header('Content-Type','video/mp2t');self.end_headers()
        try:
            while True:
                for off in range(0,len(media),188*150):
                    self.wfile.write(media[off:off+188*150]);self.wfile.flush();time.sleep(20*188*150/len(media))
        except (BrokenPipeError,ConnectionResetError):pass

server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Source)
threading.Thread(target=server.serve_forever,daemon=True).start()
base='http://127.0.0.1:'+str(server.server_port)+'/source.ts'
access='http://fixture:'+secret+'@127.0.0.1:'+str(server.server_port)+'/source.ts?access='+secret
key=root/'access.key'
if not key.exists():
    fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(os.urandom(32))
channel=None
try:
    check(request('GET','capabilities')['source_credentials'],'existing test key enables the credential capability')
    channel=request('POST','channels',dict(name='带鉴权的自生成源',source_url=base,access_url=access))['record']
    check(channel['has_access_url'] and 'access_url' not in channel and secret not in json.dumps(channel),'saved catalogue returns only credential presence')
    with sqlite3.connect(root/'config.db') as db:
        stored=db.execute("SELECT body FROM iptv_record WHERE kind='channels' AND id=?",(channel['id'],)).fetchone()[0]
    check(secret not in stored and secret.encode() not in (root/'config.db').read_bytes(),'plaintext credentials never enter the catalogue or SQLite file')
    bad=call('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],access_url=access.replace('/source.ts','/different.ts')))
    check(bad['code']=='source_access_address_mismatch','secret access URL cannot silently change the public source location')
    request('POST','channels/'+channel['id']+'/probe',{})
    probe=wait(channel['id'],'probe_complete')
    check(authorized and secret not in json.dumps(probe),'ffprobe authenticates while its response omits the access URL')
    check(all(secret not in p.read_text() for p in (root/'.dreamingwrt-iptv').glob('*/probe.json')),'probe cache omits credential filenames')
    ticket=request('POST','channels/'+channel['id']+'/preview',{})
    wait(channel['id'],'media_ready')
    result=subprocess.run(['ffmpeg','-nostdin','-v','error','-xerror','-i',
        'http://127.0.0.1:'+str(a.http_port)+ticket['url'],'-t','2','-f','null','-'],capture_output=True,timeout=25)
    check(result.returncode==0,'encrypted Basic-auth and query URL produces independently decodable HLS')
    check(all(secret not in p.read_text() for p in (root/'.dreamingwrt-iptv').glob('*/error.log')),'media errors never persist plaintext credentials')
    request('POST','channels/'+channel['id']+'/stop',{'confirm':True})
    request('DELETE','sessions/'+ticket['session_id'],{})
    channel=request('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],name='改名后保留凭据',access_url=''))['record']
    check(channel['has_access_url'],'blank write-only field and unrelated edits preserve the saved secret')
    check(call('GET','exports/xlsx')['code']=='source_access_export_unsupported','unsupported credential migration is rejected rather than silently exporting an incomplete channel')
    channel=request('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],mode='external'))['record']
    direct=request('POST','channels/'+channel['id']+'/preview',{})
    check(direct['url']==access,'explicit external playback receives the resolved access URL')
    exported=request('GET','exports/m3u')
    check(secret not in exported['text'] and exported['omitted_credential_sources']>=1,'management export omits credential sources with an explicit count')
    missing=root/'access.key.offline';key.rename(missing)
    try:
        result=call('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],access_url=access))
        check(result['code']=='source_secret_store_unavailable' and request('GET','channels/'+channel['id'])['revision']==channel['revision'],'missing key rejects a credential update without persisting changes')
    finally:missing.rename(key)
    channel=request('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],clear_access_url=True))['record']
    check(not channel['has_access_url'] and request('POST','channels/'+channel['id']+'/preview',{})['url']==base,'explicit clear removes saved credentials and restores the public URL')
    request('DELETE','channels/'+channel['id'],{'if_revision':channel['revision']});channel=None
    result=dict(passed=len(checks),checks=checks,environment='31.6 lester; generated temporary key; loopback Basic-auth/query source; no production key creation')
    (root/'access-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2));print(json.dumps(result,ensure_ascii=False))
finally:
    if channel:call('POST','channels/'+channel['id']+'/stop',{'confirm':True})
    server.shutdown()
