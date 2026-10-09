#!/usr/bin/env python3
"""Exercise the actual api_iptv.c RAW_FD route against an isolated IPC daemon.
Only the /tmp fixture's recorded MP4 is extended temporarily; it is restored.
"""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess

p=argparse.ArgumentParser();p.add_argument('--directory',required=True);a=p.parse_args()
root=Path(a.directory).resolve();assert str(root).startswith('/tmp/')
def recv(s,n):
    b=b''
    while len(b)<n:
        part=s.recv(n-len(b));assert part;b+=part
    return b
def call(method,resource='',body=None):
    q=json.dumps(dict(method=method,resource=resource,body=body,actor='http-transport-test')).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5);s.connect(str(root/'iptv.sock'));s.sendall(struct.pack('!I',len(q))+q)
        result=json.loads(recv(s,struct.unpack('!I',recv(s,4))[0]));assert not result['status'],result;return result['data']
records=call('GET','recordings')['items'];record=next(r for r in records if r['state']=='ready')
session=call('POST','recordings/'+record['id']+'/preview',{})
path=root/'.dreamingwrt-recordings'/record['id']/'archive.mp4';original=path.stat().st_size
checks=[]
def request(method,range_value=''):
    args=[str(root/'http-fixture'),method,session['url']]
    if range_value:args.append(range_value)
    raw=subprocess.run(args,check=True,capture_output=True,timeout=15).stdout
    head,body=raw.split(b'\r\n\r\n',1);return head.decode(),body
try:
    # A >16 MiB resource proves the route streams bounded chunks rather than
    # treating the existing live-segment IPC cap as a whole-recording limit.
    size=max(original,17*1024*1024)
    with path.open('ab') as f:f.truncate(size)
    head,data=request('HEAD');assert '200 OK' in head and f'Content-Length: {size}' in head and not data;checks.append('HEAD returns full length without a body')
    head,data=request('GET','bytes=0-31');assert '206 Partial Content' in head and len(data)==32 and b'ftyp' in data;checks.append('bounded first-byte range')
    head,data=request('GET','bytes=-16');assert f'Content-Range: bytes {size-16}-{size-1}/{size}' in head and len(data)==16;checks.append('suffix byte range')
    head,data=request('GET',f'bytes={size-16}-');assert len(data)==16 and '206 Partial Content' in head;checks.append('open-ended byte range')
    head,data=request('GET',f'bytes={size}-');assert '416 Range Not Satisfiable' in head and f'Content-Range: bytes */{size}' in head;checks.append('unsatisfiable range reports complete length')
    head,data=request('GET');assert len(data)==size;checks.append('whole file larger than IPC segment limit is streamed')
    call('DELETE','sessions/'+session['session_id'],{})
    head,data=request('HEAD');assert '401 Error' in head;checks.append('HEAD authorization checked after ticket release')
finally:
    with path.open('ab') as f:f.truncate(original)
result={'passed':len(checks),'checks':checks,'environment':'actual api_iptv.c raw route + gateway + isolated daemon; outer webd dispatcher not exercised'}
(root/'http-transport-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
