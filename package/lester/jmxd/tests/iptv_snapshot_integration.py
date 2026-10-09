#!/usr/bin/env python3
"""Actual JPEG capture, resource limits and provider authorization in /tmp."""
import argparse
import base64
import json
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import time

p=argparse.ArgumentParser();p.add_argument('--directory',required=True);p.add_argument('--http-port',type=int,default=19751)
a=p.parse_args();root=Path(a.directory).resolve();assert str(root).startswith('/tmp/')
checks=[]
def check(value,label):
    assert value,label
    checks.append(label)
def recv(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data));assert part;data+=part
    return data
def call(method,path,body=None,actor='snapshot-test'):
    q=json.dumps(dict(method=method,resource=path,body=body,actor=actor)).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10);s.connect(str(root/'iptv.sock'));s.sendall(struct.pack('!I',len(q))+q)
        return json.loads(recv(s,struct.unpack('!I',recv(s,4))[0]))
def req(method,path,body=None,**kw):
    r=call(method,path,body,**kw);assert not r['status'],r;return r['data']
def wait(job):
    for _ in range(100):
        state=req('GET','jobs/'+job['id'])
        if state['state'] not in ['queued','running']:return state
        time.sleep(.2)
    raise AssertionError(state)

saved=req('GET','settings');channels=[];viewer=None
try:
    req('PUT','settings',dict(if_revision=saved['revision'],enabled=True,cache_path=str(root),max_streams=1))
    channel=req('POST','channels',dict(name='截图自生成频道',source_url=f'http://127.0.0.1:{a.http_port}/source.ts'))['record'];channels.append(channel['id'])
    absent=req('GET','snapshots/'+channel['id'])
    check(absent['state']=='absent' and not req('GET','channels/'+channel['id'])['runtime']['process_running'],'reading absent snapshot never starts source capture')
    job=req('POST','snapshots/'+channel['id'],{});done=wait(job)
    check(done['state']=='complete','explicit snapshot job completes against real FFmpeg input')
    shot=req('GET','snapshots/'+channel['id']);image=base64.b64decode(shot['base64']);path=root/'snapshot-test.jpg';path.write_bytes(image)
    decoded=subprocess.run(['ffprobe','-v','error','-show_entries','stream=codec_name,width,height','-of','json',str(path)],capture_output=True,check=True)
    track=json.loads(decoded.stdout)['streams'][0]
    check(track['codec_name']=='mjpeg' and 0<track['width']<=640 and 0<track['height']<=360,'snapshot is an independently decoded JPEG bounded to 640 by 360')
    check(abs(shot['captured_at']-time.time())<10 and 'path' not in shot,'snapshot reports real capture time without exposing storage path')
    channel=req('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],source_url='http://127.0.0.1:1/offline.ts'))['record']
    done=wait(req('POST','snapshots/'+channel['id'],{}));old=req('GET','snapshots/'+channel['id'])
    check(done['state']=='failed' and old['base64']==shot['base64'] and old['captured_at']==shot['captured_at'],'failed recapture preserves previous image and its original timestamp')
    channel=req('PUT','channels/'+channel['id'],dict(if_revision=channel['revision'],source_url=f'http://127.0.0.1:{a.http_port}/source.ts'))['record']
    req('POST','channels/'+channel['id']+'/start',{})
    done=wait(req('POST','snapshots/'+channel['id'],{}))
    check(done['state']=='failed' and done['error']=='media_budget_exhausted','snapshot and live reception share the total media budget')
    req('POST','channels/'+channel['id']+'/stop',{'confirm':True})
    external=req('POST','channels',dict(name='直连截图禁止',source_url='http://127.0.0.1/direct.ts',mode='external'))['record'];channels.append(external['id'])
    check(call('POST','snapshots/'+external['id'],{})['code']=='external_source_not_hosted','external channel capture cannot silently turn into server hosting')
    with sqlite3.connect(root/'config.db') as db:
        db.executescript("CREATE TABLE IF NOT EXISTS web_users(username TEXT PRIMARY KEY,status TEXT);CREATE TABLE IF NOT EXISTS web_sessions(token TEXT PRIMARY KEY,username TEXT,revoked INTEGER,type TEXT,expires_at INTEGER)")
        db.execute("INSERT INTO web_users VALUES('snapshot-fixture','enabled')")
        db.execute("INSERT INTO web_sessions VALUES('snapshot-fixture-token','snapshot-fixture',0,'access',?)",(int(time.time())+600,))
    check(call('WEB_VIEW','snapshot/'+channel['id'],actor='snapshot-fixture-token')['status']==403,'a logged-in identity without an IPTV grant cannot read snapshots')
    viewer=req('POST','viewers',dict(name='截图授权',principal_id='web:snapshot-fixture',all_categories=True,category_ids=[],expires_at=0))['record']
    view=req('WEB_VIEW','snapshot/'+channel['id'],actor='snapshot-fixture-token')
    check(view['base64']==shot['base64'] and 'last_attempt' not in view,'authorized provider returns the same cached image without administration job details')
    viewer=req('PUT','viewers/'+viewer['id'],dict(if_revision=viewer['revision'],enabled=False))['record']
    check(call('WEB_VIEW','snapshot/'+channel['id'],actor='snapshot-fixture-token')['status']==403,'revoking a grant rejects subsequent snapshot requests')
    with sqlite3.connect(root/'config.db') as db:stored=Path(db.execute('SELECT path FROM iptv_snapshot WHERE channel=?',(channel['id'],)).fetchone()[0])
    current=req('GET','channels/'+channel['id']);req('DELETE','channels/'+channel['id'],{'if_revision':current['revision']});channels.remove(channel['id'])
    check(not stored.exists(),'channel deletion removes only its registered snapshot file')
    (root/'snapshot-result.json').write_text(json.dumps({'passed':len(checks),'checks':checks,'environment':'temporary DB and loopback generated media'},ensure_ascii=False,indent=2));print(json.dumps({'passed':len(checks)}))
finally:
    for channel in channels:
        call('POST','channels/'+channel+'/stop',{'confirm':True});current=req('GET','channels/'+channel);call('DELETE','channels/'+channel,{'if_revision':current['revision']})
    if viewer:call('DELETE','viewers/'+viewer['id'],{'if_revision':viewer['revision']})
    with sqlite3.connect(root/'config.db') as db:
        for table,key,val in [('web_sessions','token','snapshot-fixture-token'),('web_users','username','snapshot-fixture')]:
            if db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone():db.execute('DELETE FROM '+table+' WHERE '+key+'=?',(val,))
    current=req('GET','settings');req('PUT','settings',dict(if_revision=current['revision'],max_streams=saved['max_streams']))
