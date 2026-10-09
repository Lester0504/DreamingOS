#!/usr/bin/env python3
"""Actual encoder smoke and MPEG-2/MP2 -> HLS transcode in a /tmp fixture."""
import argparse
import base64
import http.server
import json
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import io
import zipfile
import xml.etree.ElementTree as ET

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
def call(method,path,body=None):
    q=json.dumps(dict(method=method,resource=path,body=body,actor='encoder-test')).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10);s.connect(str(root/'iptv.sock'));s.sendall(struct.pack('!I',len(q))+q)
        return json.loads(recv(s,struct.unpack('!I',recv(s,4))[0]))
def req(method,path,body=None):
    r=call(method,path,body);assert not r['status'],r;return r['data']
def wait(channel,state):
    for _ in range(150):
        r=req('GET','channels/'+channel)['runtime']
        if r['state']==state:return r
        assert r['state']!='error',r
        time.sleep(.2)
    raise AssertionError(r)

media=root/'mpeg2-source.ts'
subprocess.run(['ffmpeg','-v','error','-f','lavfi','-i','testsrc2=size=320x180:rate=25','-f','lavfi','-i','sine=frequency=660:sample_rate=48000','-t','12','-c:v','mpeg2video','-g','25','-c:a','mp2','-f','mpegts','-y',str(media)],check=True)
data=media.read_bytes()
class Source(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Type','video/mp2t');self.end_headers()
        try:
            while True:
                for n in range(0,len(data),188*100):
                    self.wfile.write(data[n:n+188*100]);self.wfile.flush();time.sleep(12*188*100/len(data))
        except (BrokenPipeError,ConnectionResetError):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Source);threading.Thread(target=server.serve_forever,daemon=True).start()
saved=req('GET','settings');channels=[];tickets=[]
try:
    cfg=req('PUT','settings',dict(if_revision=saved['revision'],enabled=True,cache_path=str(root),max_streams=4,max_transcodes=1))['record']
    codecs=req('GET','encoders')['items']
    check(all(c['runtime_available'] is None and c['state']=='untested' for c in codecs),'reading encoder capabilities does not run any smoke tests')
    ch=req('POST','channels',dict(name='MPEG2转H264',source_url=f'http://127.0.0.1:{server.server_port}/source.ts',video_encoder='libx264',audio_encoder='aac'))['record'];channels.append(ch)
    check(call('POST','channels/'+ch['id']+'/preview',{})['code']=='encoder_smoke_required','unverified encoder cannot start even when it is compiled')
    check(call('POST','channels',dict(name='bad',source_url=ch['source_url'],video_encoder='auto'))['code']=='encoder_unknown','unspecified auto fallback is not accepted')
    check(call('POST','channels',dict(name='bad',source_url=ch['source_url'],video_encoder='libx265'))['code']=='hevc_requires_fmp4','HEVC output requires an explicit fMP4 container')
    workbook=req('GET','exports/xlsx')
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(workbook['base64']))) as archive:
        text=archive.read('xl/worksheets/sheet1.xml').decode()
    check('libx264' in text and 'aac' in text,'XLSX export preserves configured encoders')
    preview=req('POST','imports/preview',dict(format='xlsx',base64=workbook['base64'],duplicates='update'))
    row=next(r for r in preview['rows'] if r['source_url']==ch['source_url'])
    req('POST','imports/commit',dict(format='xlsx',base64=workbook['base64'],duplicates='update',if_revision=preview['base_revision']))
    ch=req('GET','channels/'+ch['id'])
    check(row['action']=='update' and ch['video_encoder']=='libx264' and ch['audio_encoder']=='aac','XLSX import commits and reads back video and audio encoding configuration')
    results=[]
    for codec in codecs:
        if not codec['compiled']:continue
        req('POST','encoders/'+codec['id']+'/probe',{})
        for _ in range(170):
            current=next(c for c in req('GET','encoders')['items'] if c['id']==codec['id'])
            if current['state']!='testing':break
            time.sleep(.2)
        assert current['state']!='testing',current
        results.append(current)
    for name in ['libx264','libx265','aac','ac3','eac3','mp2','libopus']:
        row=next((r for r in results if r['id']==name),None)
        if row:check(row['runtime_available'],name+' actually encodes a bounded synthetic sample')
    failed=[r for r in results if not r['runtime_available']]
    check(bool(failed) and all(r['reason']=='encoder_smoke_failed' for r in failed),'compiled hardware encoders without usable hardware fail without software fallback')
    ticket=req('POST','channels/'+ch['id']+'/preview',{});tickets.append(ticket)
    state=wait(ch['id'],'media_ready')
    check(state['transcoding'] and state['video_encoder']=='libx264' and state['audio_encoder']=='aac','runtime exposes the actual selected video and audio encoders')
    url=f'http://127.0.0.1:{a.http_port}'+ticket['url']
    result=subprocess.run(['ffprobe','-v','error','-show_entries','stream=codec_name','-of','json',url],capture_output=True,timeout=25)
    tracks={s['codec_name'] for s in json.loads(result.stdout)['streams']}
    check(result.returncode==0 and tracks=={'h264','aac'},'MPEG2 and MP2 source becomes actual H264 and AAC HLS')
    subprocess.run(['ffmpeg','-v','error','-xerror','-i',url,'-t','2','-f','null','-'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True,timeout=25)
    check(True,'independent FFmpeg client decodes transcoded HLS')
    other=req('POST','channels',dict(name='转码预算第二路',source_url=ch['source_url'],video_encoder='libx264'))['record'];channels.append(other)
    check(call('POST','channels/'+other['id']+'/preview',{})['code']=='transcode_budget_exhausted','transcode limit applies before the total stream budget is exhausted')
    for item in tickets:req('DELETE','sessions/'+item['session_id'])
    req('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    hevc=req('PUT','channels/'+other['id'],dict(if_revision=other['revision'],video_encoder='libx265',audio_encoder='aac',hls_container='fmp4'))['record']
    req('POST','channels/'+hevc['id']+'/probe',{});wait(hevc['id'],'probe_complete')
    ticket=req('POST','channels/'+hevc['id']+'/preview',{});tickets.append(ticket);wait(hevc['id'],'media_ready')
    result=subprocess.run(['ffmpeg','-v','error','-xerror','-i',f'http://127.0.0.1:{a.http_port}'+ticket['url'],'-t','2','-f','null','-'],capture_output=True,timeout=30)
    check(result.returncode==0,'software HEVC and AAC fMP4 HLS independently decodes')
    out={'passed':len(checks),'checks':checks,'encoders':results,'environment':'31.6 lester temporary DB, loopback MPEG2/MP2 generated source; not target hardware'}
    (root/'encoder-result.json').write_text(json.dumps(out,ensure_ascii=False,indent=2));print(json.dumps({'passed':len(checks),'encoders':len(results)}))
finally:
    for item in tickets:call('DELETE','sessions/'+item['session_id'])
    for ch in channels:
        call('POST','channels/'+ch['id']+'/stop',{'confirm':True})
        current=req('GET','channels/'+ch['id']);call('DELETE','channels/'+ch['id'],{'if_revision':current['revision']})
    current=req('GET','settings');req('PUT','settings',dict(if_revision=current['revision'],max_streams=saved['max_streams'],max_transcodes=saved.get('max_transcodes',1)))
    server.shutdown()
