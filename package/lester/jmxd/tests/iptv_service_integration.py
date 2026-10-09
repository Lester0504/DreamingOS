#!/usr/bin/env python3
"""Isolated IPTV process/socket/media integration. Never touches router state.
Build the daemon with IPTV_TESTING, a /tmp DB and a /tmp socket first.
Requires ffmpeg with the lavfi testsrc2 and libx264 encoder on the test host.
"""
import argparse
import base64
import csv
import hashlib
import io
import zipfile
import xml.etree.ElementTree as ET
import datetime
import gzip
import concurrent.futures
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
import urllib.request

p=argparse.ArgumentParser()
p.add_argument('--directory',required=True)
p.add_argument('--daemon',required=True)
p.add_argument('--serve',action='store_true')
p.add_argument('--serve-only',action='store_true')
p.add_argument('--port',type=int,default=0)
a=p.parse_args()
root=Path(a.directory);root.mkdir(parents=True,exist_ok=True)
assert str(root).startswith('/tmp/')
sock=str(root/'iptv.sock')
checks=[]
def check(value,label):
    assert value,label
    checks.append(label)
def recvall(s,n):
    chunks=[]
    while n:
        data=s.recv(n)
        if not data:raise RuntimeError('short IPC response')
        chunks.append(data);n-=len(data)
    return b''.join(chunks)
def call(method,resource='',body=None,actor='isolation-admin',**extra):
    request={'method':method,'resource':resource,'body':body,'actor':actor,**extra}
    data=json.dumps(request).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5);s.connect(sock);s.sendall(struct.pack('!I',len(data))+data)
        n=struct.unpack('!I',recvall(s,4))[0]
        result=json.loads(recvall(s,n))
        if result.get('length'):result['bytes']=recvall(s,result['length'])
        return result

def request(method,path,body=None,**kw):
    result=call(method,path,body,**kw)
    assert not result['status'],result
    return result['data']

media=root/'synthetic.ts'
if not media.exists():
    subprocess.run(['ffmpeg','-v','error','-f','lavfi','-i','testsrc2=size=320x180:rate=25','-f','lavfi','-i','sine=frequency=440:sample_rate=48000','-t','20','-c:v','libx264','-preset','ultrafast','-g','50','-c:a','aac','-f','mpegts','-y',str(media)],check=True)
source_bytes=media.read_bytes()
source_enabled=True
source_agents=[]
epg_start=int(time.time())-3600
epg_end=epg_start+10800
def epg_stamp(t):
    return datetime.datetime.fromtimestamp(t,datetime.timezone(datetime.timedelta(hours=8))).strftime("%Y%m%d%H%M%S %z")
epg_xml=f'<tv><programme channel="synthetic" start="{epg_stamp(epg_start)}" stop="{epg_stamp(epg_end)}"><title>自生成节目表</title><desc>非录像</desc></programme></tv>'.encode()
class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def api(self,method):
        size=int(self.headers.get('Content-Length','0'))
        body=json.loads(self.rfile.read(size)) if size else None
        result=call(method,self.path.split('?',1)[0][len('/api/v1/iptv/'):],body)
        if result['status']:
            status=result['status'];payload={'ok':False,'error':{'code':result['code'],'message':result['code']}}
        else:
            status=200;payload={'ok':True,'data':{**result['data'],'can_manage':True}}
        data=json.dumps(payload).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):self.api('POST')
    def do_PUT(self):self.api('PUT')
    def do_DELETE(self):self.api('DELETE')
    def do_HEAD(self):self.do_GET()
    def do_GET(self):
        if self.path in ['/epg.xml.gz','/bad-epg.xml']:
            data=gzip.compress(epg_xml) if self.path.endswith('.gz') else b'<tv>invalid'
            self.send_response(200);self.send_header('Content-Type','application/octet-stream');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
        if self.path=='/list.m3u':
            data=f'#EXTM3U\n#EXTINF:-1,URL 导入频道\n{base}/external.m3u8\n'.encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
        if self.path=='/source.ts':
            source_agents.append(self.headers.get('User-Agent',''))
            self.send_response(200);self.send_header('Content-Type','video/mp2t');self.send_header('Connection','close');self.end_headers()
            chunk=188*150
            try:
                while source_enabled:
                    for off in range(0,len(source_bytes),chunk):
                        if not source_enabled:return
                        self.wfile.write(source_bytes[off:off+chunk]);self.wfile.flush()
                        time.sleep(20*chunk/len(source_bytes))
            except (BrokenPipeError,ConnectionResetError):pass
            self.close_connection=True
            return
        if self.path.startswith('/api/v1/iptv/media/'):
            _,token,channel,name=self.path.rsplit('/',3)
            if name.startswith('record-'):
                result=call('MEDIA_RECORD_INFO',token=token,channel=channel,name=name)
                if result['status']:self.send_error(result['status'],result['code']);return
                size=result['data']['size'];first=0;last=size-1
                if self.headers.get('Range'):
                    a,b=self.headers['Range'][6:].split('-');first=int(a or 0);last=min(int(b),last) if b else last
                self.send_response(206 if self.headers.get('Range') else 200);self.send_header('Content-Type','video/mp4');self.send_header('Accept-Ranges','bytes');self.send_header('Content-Length',str(last-first+1))
                if self.headers.get('Range'):self.send_header('Content-Range',f'bytes {first}-{last}/{size}')
                self.end_headers()
                if self.command=='HEAD':return
                try:
                    while first<=last:
                        part=call('MEDIA_RECORD_READ',token=token,channel=channel,name=name,offset=first,maximum=min(1024*1024,last-first+1))
                        if part['status']:return
                        self.wfile.write(part['bytes']);first+=part['length']
                except (BrokenPipeError,ConnectionResetError):pass
                return
            result=call('MEDIA',token=token,channel=channel,name=name)
            if result['status']:
                self.send_error(result['status'],result['code']);return
            self.send_response(200);self.send_header('Content-Type',result['type']);self.send_header('Content-Length',str(result['length']));self.end_headers()
            try:self.wfile.write(result['bytes'])
            except BrokenPipeError:pass
            return
        if self.path.startswith('/api/v1/iptv/'):
            self.api('GET');return
        self.send_error(404)
server=http.server.ThreadingHTTPServer(('127.0.0.1',a.port),HTTP)
threading.Thread(target=server.serve_forever,daemon=True).start()
base=f'http://127.0.0.1:{server.server_port}'
log=(root/'daemon-test.log').open('wb')
process=subprocess.Popen([a.daemon],stdout=log,stderr=log)
try:
    for _ in range(50):
        if Path(sock).exists():break
        if process.poll() is not None:raise RuntimeError('daemon exited')
        time.sleep(.1)
    if a.serve_only:
        for row in request('GET','channels')['items']:
            if row['mode']=='managed':request('PUT','channels/'+row['id'],{'if_revision':row['revision'],'source_url':base+'/source.ts','hls_container':'mpegts'})
        print('BROWSER_TEST_SERVER',base,flush=True)
        while True:time.sleep(1)
    overview=request('GET','overview');check(overview['capabilities']['ffmpeg_installed'],'real tool availability')
    matrix=overview['capabilities']['input_capabilities']
    check(all(row['compiled']==(row['name'] in overview['capabilities']['input_protocols']) and row['runtime_available'] is None for row in matrix),
          'protocol capabilities come from both installed tools and distinguish unprobed runtime support')
    cfg=request('GET','settings')
    result=request('PUT','settings',{'if_revision':cfg['revision'],'enabled':True,'cache_path':str(root),'idle_seconds':10})
    check(result['record']['enabled'],'settings canonical save')
    dry_root=root/'preflight-only';dry_root.mkdir(exist_ok=True)
    current=request('GET','settings')
    preflight=request('POST','settings/preflight',{'if_revision':current['revision'],'cache_path':str(dry_root)})
    check(preflight['valid'] and not list(dry_root.iterdir()) and request('GET','settings')['revision']==current['revision'],
          'storage preflight reports capacity and active impact without creating files or saving settings')
    invalid=call('PUT','settings',{'if_revision':current['revision'],'cache_path':str(root/'absent-volume')})
    check(invalid['code']=='storage_path_unavailable' and request('GET','settings')['revision']==current['revision'],
          'unavailable storage directory is rejected before configuration is persisted')

    check(call('PUT','settings',{'if_revision':cfg['revision'],'enabled':False})['code']=='revision_conflict','stale settings cannot overwrite')
    offline_root=root/'temporary-recording-mount';offline_root.mkdir(exist_ok=True)
    current=request('GET','settings')
    request('PUT','settings',{'if_revision':current['revision'],'recording_path':str(offline_root)})
    offline_root.rename(root/'temporary-recording-offline')
    current=request('GET','settings')
    stopped=request('PUT','settings',{'if_revision':current['revision'],'enabled':False})
    check(stopped['record']['enabled'] is False,'offline storage does not prevent disabling the IPTV module')
    (root/'temporary-recording-offline').rename(offline_root)
    request('PUT','settings',{'if_revision':stopped['record']['revision'],'enabled':True,'recording_path':''})

    cat=request('POST','categories',{'name':'隔离测试','enabled':True})['record']
    ch=request('POST','channels',{'name':'自生成测试画面','source_url':base+'/source.ts','category_id':cat['id'],'program_id':1,'user_agent':'DreamingWrt-iptv-test'})['record']
    check(request('GET','channels/'+ch['id'])['id']==ch['id'],'stable catalogue id')
    check(call('DELETE','categories/'+cat['id'],{'if_revision':cat['revision']})['code']=='category_in_use','category reference protected')
    check(call('PUT','channels/'+ch['id'],{'if_revision':1,'unknown':True})['code']=='unknown_field','field allowlist')
    check(call('POST','channels',{'name':'invalid','source_url':'file:///etc/passwd'})['code']=='input_protocol_unsupported','input protocol gate')
    pair=request('POST','channels/batch',{'operation':'create','rows':[{'name':'批量甲','source_url':base+'/a.ts','mode':'external'},{'name':'批量乙','source_url':base+'/b.ts','mode':'external'}]})
    pair_ids=[row['id'] for row in pair['items']]
    partial=request('POST','channels/batch',{'operation':'update','rows':[{'id':pair_ids[0],'if_revision':1},{'id':pair_ids[1],'if_revision':0}],'patch':{'enabled':False}})
    check(partial['saved']==1 and partial['items'][1]['error']=='revision_conflict' and request('GET','channels/'+pair_ids[1])['enabled'],
          'batch channel updates preserve conflicting rows and return per-row outcomes')
    request('POST','channels/batch',{'operation':'delete','rows':[{'id':pair_ids[0],'if_revision':2},{'id':pair_ids[1],'if_revision':1}]})

    check(call('POST','channels',{'name':'invalid','source_url':'http://example.invalid/?token=secret'})['code']=='source_credentials_not_supported','unsupported secrets are not persisted')
    revision=request('GET','channels')['revision']
    probe_draft={k:ch[k] for k in ['name','enabled','position','number','mode','source_url','category_id','program_id','user_agent']}
    draft_result=request('POST','probes',probe_draft)
    for _ in range(40):
        state=request('GET','probes/'+draft_result['operation_id'])
        if state['state'] in ['probe_complete','error']:break
        time.sleep(.25)
    check(state['state']=='probe_complete' and state['probe']['streams'][0]['codec_name']=='h264',
          'unsaved draft probe returns actual media tracks')
    check(request('GET','channels')['revision']==revision and not draft_result['persisted'],
          'draft probe never saves a channel or changes the catalogue revision')
    check('DreamingWrt-iptv-test' in source_agents,'HTTP User-Agent reaches the actual source')
    request('DELETE','probes/'+draft_result['operation_id'])
    check(not request('GET','probes/'+draft_result['operation_id'])['process_running'],'draft probe can release its process and temporary resources')
    check(call('POST','probes',{**probe_draft,'shell':'touch /tmp/forbidden'})['code']=='unknown_field',
          'draft probe accepts only channel fields, never arbitrary tool arguments')
    one=request('POST','channels/'+ch['id']+'/preview',{})
    two=request('POST','channels/'+ch['id']+'/preview',{},actor='second-admin')
    check(one['session_id']!=two['session_id'],'independent preview credentials')
    for _ in range(40):
        state=next(x for x in request('GET','channels')['items'] if x['id']==ch['id'])['runtime']
        if state['state']=='media_ready':break
        assert state['state']!='error',state
        time.sleep(.5)
    check(state['media_ready'],'first real HLS segment with selected MPEG-TS programme 1')
    def decode(session):
        return subprocess.run(['ffmpeg','-v','error','-i',base+session['url'],'-t','3','-f','null','-'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        results=list(pool.map(decode,[one,two]))
    check(all(r.returncode==0 for r in results),'two actual FFmpeg clients decode HLS')
    request('DELETE','sessions/'+one['session_id'],{})
    check(call('MEDIA',token=one['session_id'],channel=ch['id'],name='index.m3u8')['status']==401,'closed preview ticket rejected')
    check(call('MEDIA',token=two['session_id'],channel=ch['id'],name='index.m3u8')['status']==0,'closing one viewer preserves the other')
    check(call('MEDIA',token=two['session_id'],channel=ch['id'],name='../config.db')['status']==404,'media path traversal rejected')
    request('POST','sessions/'+two['session_id']+'/renew',{},actor='second-admin')
    check(call('POST','sessions/'+two['session_id']+'/renew',{},actor='wrong-admin')['status']==401,'lease renewal owner checked')
    request('PUT','categories/'+cat['id'],{'if_revision':cat['revision'],'enabled':False})
    check(call('MEDIA',token=two['session_id'],channel=ch['id'],name='index.m3u8')['status']==403,'category withdrawal applies to existing media token')
    request('DELETE','sessions/'+two['session_id'],{},actor='second-admin')
    for _ in range(25):
        state=next(x for x in request('GET','channels')['items'] if x['id']==ch['id'])['runtime']
        if state['state']=='stopped':break
        time.sleep(.5)
    check(state['state']=='stopped' and not state['process_running'],'last viewer releases source process')
    # The resumed implementation: imports, atomic order, actual fMP4 and retry.
    playlist=f'#EXTM3U\n#EXTINF:-1 group-title="导入分类",测试直连\n{base}/direct.m3u8\n#EXTINF:-1,重复行\n{base}/direct.m3u8\n#EXTINF:-1,非法源\nfile:///etc/passwd\n'
    rev=request('GET','channels')['revision']
    draft=request('POST','imports/preview',{'format':'m3u','text':playlist})
    check([r['action'] for r in draft['rows']]==['create','skip','error'],'import preview classifies duplicates and errors')
    check(request('GET','channels')['revision']==rev,'import preview does not write catalogue')
    committed=request('POST','imports/commit',{'format':'m3u','text':playlist,'if_revision':rev})
    check(committed['saved']==1 and committed['rows'][2]['action']=='error','partial import reports each row')
    retry=request('POST','imports/commit',{'format':'m3u','text':playlist,'if_revision':committed['revision']})
    check(retry['saved']==0,'retry does not duplicate imported channels')
    check(call('POST','imports/commit',{'format':'m3u','text':playlist,'if_revision':rev})['code']=='revision_conflict','import stale revision rejected')
    # XLSX reads a real ZIP workbook; independent XML reader checks its export.
    exported=request('GET','exports/xlsx')
    binary=base64.b64decode(exported['base64'])
    (root/'channels.xlsx').write_bytes(binary)
    with zipfile.ZipFile(io.BytesIO(binary)) as z:
        ns={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        sheet=ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
        values=[[ ''.join(c.itertext()) for c in row] for row in sheet.find('s:sheetData',ns)]
    check(values[0][0]=='频道名称' and any('自生成测试画面' in row for row in values[1:]),'XLSX export is a real independently parsed workbook')
    book=request('POST','imports/preview',{'format':'xlsx','base64':exported['base64'],'duplicates':'update'})
    check(all(r['action']=='update' for r in book['rows']),'XLSX roundtrip maps existing rows without duplicates')
    check({r['mode'] for r in book['rows']}=={'managed','external'},'XLSX preserves managed and external semantics')
    check(request('GET','channels')['revision']==retry['revision'],'XLSX preview leaves catalogue revision unchanged')
    template=request('GET','exports/template')
    check(request('POST','imports/preview',{'format':'xlsx','base64':template['base64']})['rows']==[],'XLSX template has no artificial channel')
    def custom_book(sheet_xml, shared=None):
        output=io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(binary)) as original,zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
            for name in original.namelist():z.writestr(name,sheet_xml.encode() if name=='xl/worksheets/sheet1.xml' else original.read(name))
            if shared:z.writestr('xl/sharedStrings.xml',shared.encode())
        return base64.b64encode(output.getvalue()).decode()
    xml=f'<worksheet xmlns="{ns["s"]}"><sheetData><row><c r="A1" t="s"><v>0</v></c><c r="D1" t="s"><v>1</v></c></row><row><c r="A2" t="s"><v>2</v></c><c r="D2" t="inlineStr"><is><t>{base}/workbook.ts</t></is></c></row></sheetData></worksheet>'
    shared=f'<sst xmlns="{ns["s"]}"><si><t>频道名称</t></si><si><t>输入地址</t></si><si><t>共享字符串频道</t></si></sst>'
    sparse=request('POST','imports/preview',{'format':'xlsx','base64':custom_book(xml,shared)})
    check(sparse['rows'][0]['name']=='共享字符串频道' and sparse['rows'][0]['action']=='create','XLSX shared strings and sparse cell coordinates')
    formula=xml.replace('<c r="D2" t="inlineStr">','<c r="D2" t="inlineStr"><f>HYPERLINK("x")</f>')
    check(request('POST','imports/preview',{'format':'xlsx','base64':custom_book(formula,shared)})['rows'][0]['error']=='workbook_formula_not_supported','XLSX formulas rejected explicitly')
    committed_book=request('POST','imports/commit',{'format':'xlsx','base64':custom_book(xml,shared),'if_revision':request('GET','channels')['revision']})
    check(committed_book['saved']==1,'XLSX commit saves validated channel')
    listed=request('GET','channels');ids=[c['id'] for c in listed['items']]
    order=request('PUT','playlist/reorder',{'kind':'channels','ids':ids[::-1],'if_revision':listed['revision']})
    check([c['id'] for c in request('GET','channels')['items']]==ids[::-1],'reorder commits complete set atomically')
    check(call('PUT','playlist/reorder',{'kind':'channels','ids':[ids[0]]*len(ids),'if_revision':order['revision']})['code']=='duplicate_id','duplicate reorder ids rejected')
    check('direct.m3u8' in request('GET','exports/m3u')['text'] and '/source.ts' not in request('GET','exports/m3u')['text'],'direct export never leaks managed upstream')
    category=request('GET','categories/'+cat['id'])
    request('PUT','categories/'+cat['id'],{'if_revision':category['revision'],'enabled':True})
    channel=request('GET','channels/'+ch['id'])
    request('PUT','channels/'+ch['id'],{'if_revision':channel['revision'],'hls_container':'fmp4'})
    request('POST','channels/'+ch['id']+'/probe',{})
    for _ in range(40):
        probe=next(c for c in request('GET','channels')['items'] if c['id']==ch['id'])['runtime']
        if probe['state']=='probe_complete':break
        time.sleep(.5)
    check(probe['state']=='probe_complete','fMP4 audio codec uses actual probe')
    three=request('POST','channels/'+ch['id']+'/preview',{})
    def runtime():
        return next(x for x in request('GET','channels')['items'] if x['id']==ch['id'])['runtime']
    for _ in range(40):
        state=runtime()
        if state['media_ready']:break
        time.sleep(.5)
    check(state['media_ready'],'fMP4 actual first segment')
    check(call('MEDIA',token=three['session_id'],channel=ch['id'],name='init.mp4')['type']=='video/mp4','fMP4 init authorized with correct content type')
    check(decode(three).returncode==0,'actual FFmpeg client decodes fMP4 HLS')
    cfg=request('GET','settings')
    change=request('PUT','settings',{'if_revision':cfg['revision'],'window_segments':5})
    check(not change['applied'] and ch['id'] in change['pending_channels'],'saved settings expose pending active channel')
    source_enabled=False
    for _ in range(40):
        state=runtime()
        if state['state']=='retrying':break
        time.sleep(.25)
    check(state['state']=='retrying' and not state['process_running'],'source disconnect enters bounded retry')
    source_enabled=True
    for _ in range(50):
        state=runtime()
        if state['media_ready']:break
        time.sleep(.5)
    check(state['media_ready'] and state['retries']==1,'same lease recovers after HTTP source returns')
    check(decode(three).returncode==0,'recovered stream is decodable')
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    check(runtime()['state']=='stopped','explicit global stop does not auto-restart')
    request('DELETE','sessions/'+three['session_id'],{})
    epg=request('POST','epg-sources',{'name':'隔离 XMLTV','url':base+'/epg.xml.gz','interval_hours':24})['record']
    def job():
        return next((x for x in request('GET','epg/jobs')['items'] if x['source_id']==epg['id']),{})
    for _ in range(50):
        state=job()
        if state.get('state') in ['complete','failed']:break
        time.sleep(.2)
    check(state.get('state')=='complete' and state['programmes']==1,'XMLTV gzip scheduled fetch and atomic index')
    channel=request('GET','channels/'+ch['id'])
    request('PUT','channels/'+ch['id'],{'if_revision':channel['revision'],'epg_source_id':epg['id'],'epg_id':'synthetic'})
    guide=request('GET','epg/'+ch['id'])['items']
    check(guide[0]['start']==epg_start and guide[0]['end']==epg_end,'XMLTV timezone converts to UTC exactly')
    check(guide[0]['recording_available'] is False,'EPG programme does not pretend recording exists')
    request('PUT','epg-sources/'+epg['id'],{'if_revision':epg['revision'],'url':base+'/bad-epg.xml'})
    request('POST','epg-sources/'+epg['id']+'/refresh',{})
    for _ in range(50):
        state=job()
        if state.get('state')=='failed':break
        time.sleep(.2)
    check(state.get('state')=='failed' and state['last_success']>0,'EPG failed refresh reports last success')
    check(request('GET','epg/'+ch['id'])['items']==guide,'EPG bad refresh preserves last successful programmes')
    # Existing web identities and TV activations are test fixtures only in this
    # temporary DB; IPTV never creates or mutates those authorities in production.
    with sqlite3.connect(root/'config.db') as db:
        db.executescript("CREATE TABLE IF NOT EXISTS web_users(username TEXT PRIMARY KEY,status TEXT);CREATE TABLE IF NOT EXISTS web_sessions(token TEXT PRIMARY KEY,username TEXT,type TEXT,revoked INTEGER,expires_at INTEGER);CREATE TABLE IF NOT EXISTS tvhome_settings(id INTEGER PRIMARY KEY,media_principal_id TEXT,pin_required INTEGER,modules_json TEXT);CREATE TABLE IF NOT EXISTS tvhome_terminal(id TEXT PRIMARY KEY,media_principal_id TEXT);CREATE TABLE IF NOT EXISTS tvhome_principal(id TEXT PRIMARY KEY,terminal_id TEXT,revoked INTEGER);CREATE TABLE IF NOT EXISTS tvhome_session(token TEXT PRIMARY KEY,terminal_id TEXT,principal_id TEXT,revoked INTEGER,expires_at_ms INTEGER);")
        db.execute("INSERT INTO web_users VALUES('isolated-viewer','enabled')")
        for token in ['phone-a','phone-b']:
            db.execute("INSERT INTO web_sessions VALUES(?, 'isolated-viewer','access',0,?)",(token,int(time.time())+900))
        db.execute("INSERT INTO tvhome_settings VALUES(1,'web:isolated-viewer',0,?)",(json.dumps({'live':True}),))
        db.execute("INSERT INTO tvhome_terminal VALUES('tv-terminal','')")
        db.execute("INSERT INTO tvhome_principal VALUES('tv-principal','tv-terminal',0)")
        db.execute("INSERT INTO tvhome_session VALUES('tv-token','tv-terminal','tv-principal',0,?)",(int(time.time()*1000)+900000,))
    check(call('WEB_VIEW','channels',actor='invalid')['status']==401,'viewer requires an existing valid identity')
    check(request('WEB_VIEW','channels',actor='phone-a')['items']==[],'identity alone grants no IPTV channels')
    grant=request('POST','viewers',{'name':'测试观看者','principal_id':'web:isolated-viewer','all_categories':True,'category_ids':[],'expires_at':0})['record']
    check(len(request('WEB_VIEW','channels',actor='phone-a')['items'])==len(request('WEB_VIEW','channels',actor='phone-b')['items'])>0,'same principal can watch from two phone sessions')
    channel=request('GET','channels/'+ch['id'])
    request('PUT','channels/'+ch['id'],{'if_revision':channel['revision'],'hls_container':'mpegts'})
    check(any(g['id']==cat['id'] for g in request('WEB_VIEW','categories',actor='phone-a')['items']),
          'provider categories are filtered through granted enabled channels')
    now=request('WEB_VIEW','epg/'+ch['id']+'/now',actor='phone-a')
    day=datetime.datetime.fromtimestamp(epg_start,datetime.timezone.utc).strftime('%Y-%m-%d')
    daily=request('WEB_VIEW','epg/'+ch['id']+'/'+day,actor='phone-a')
    check(len(now['items'])==1 and len(daily['items'])==1 and daily['date_timezone']=='UTC',
          'provider now and explicit UTC day return actual programme intervals')
    xml=ET.fromstring(request('WEB_VIEW','xmltv',actor='phone-a')['text'])
    check(any(n.get('id')==ch['id'] for n in xml.findall('channel')) and any(n.get('channel')==ch['id'] for n in xml.findall('programme')),
          'XMLTV export uses stable provider channel IDs')
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    exported=request('WEB_VIEW','playlist',{'origin_url':base},actor='phone-a')
    check(not runtime()['process_running'] and 'phone-a' not in exported['text'] and exported['expires_at']>time.time(),
          'viewer M3U export issues short-lived tickets without starting any media source')
    lines=exported['text'].splitlines();entry=next(lines[i+1] for i,line in enumerate(lines[:-1]) if ('tvg-id="'+ch['id']+'"') in line)
    ticket_from_list=entry.split('/media/')[1].split('/')[0]
    first=call('MEDIA',token=ticket_from_list,channel=ch['id'],name='index.m3u8')
    check(first['code']=='first_segment_pending' and runtime()['process_running'],
          'first M3U media request starts only the selected channel through the shared budget')
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    call('MEDIA',token=ticket_from_list,channel=ch['id'],name='index.m3u8')
    check(not runtime()['process_running'],'an already-used M3U ticket cannot undo an explicit global stop')
    request('WEB_VIEW','release/'+ticket_from_list,{'confirmed':True},actor='phone-a')
    view=request('WEB_VIEW','stream/'+ch['id'],actor='phone-a')
    tv=request('TV_VIEW','stream/'+ch['id'],actor='tv-token')
    check(tv['resource_id']==view['resource_id'] and tv['session_id']!=view['session_id'],'TV and mobile reuse one channel with separate media tickets')
    extra_view=request('WEB_VIEW','stream/'+ch['id'],actor='phone-b')
    sessions=request('GET','sessions')
    opaque=hashlib.sha256(extra_view['session_id'].encode()).hexdigest()
    check(any(r['id']==opaque for r in sessions['items']) and extra_view['session_id'] not in json.dumps(sessions) and 'phone-b' not in json.dumps(sessions),
          'management session list exposes opaque identifiers without playable or parent credentials')
    request('POST','sessions/'+opaque+'/revoke',{'confirm':True})
    check(call('MEDIA',token=extra_view['session_id'],channel=ch['id'],name='index.m3u8')['status']==401,
          'management revokes only the selected IPTV media lease')
    exported_viewers=list(csv.DictReader(io.StringIO(request('GET','exports/viewers.csv')['text'])))
    check(exported_viewers[0]['principal_id']=='web:isolated-viewer' and 'phone-a' not in str(exported_viewers),
          'viewer CSV exports existing principal grants without session credentials')

    check(call('WEB_VIEW','renew/'+view['session_id'],{'confirmed':True},actor='phone-b')['status']==401,'other phone session cannot renew a media ticket')
    request('WEB_VIEW','renew/'+view['session_id'],{'confirmed':True},actor='phone-a')
    for _ in range(40):
        if runtime()['media_ready']:break
        time.sleep(.5)
    check(call('MEDIA',token=view['session_id'],channel=ch['id'],name='index.m3u8')['status']==0,'viewer ticket reads actual HLS')
    request('WEB_VIEW','release/'+view['session_id'],{'confirmed':True},actor='phone-a')
    check(call('MEDIA',token=view['session_id'],channel=ch['id'],name='index.m3u8')['status']==401,'viewer explicitly releases only its own lease')
    check(call('MEDIA',token=tv['session_id'],channel=ch['id'],name='index.m3u8')['status']==0,'TV lease survives mobile close')
    with sqlite3.connect(root/'config.db') as db:db.execute("UPDATE tvhome_settings SET pin_required=1")
    check(call('MEDIA',token=tv['session_id'],channel=ch['id'],name='index.m3u8')['status']==403,'TV PIN gate cannot be bypassed with an old media URL')
    with sqlite3.connect(root/'config.db') as db:db.execute("UPDATE tvhome_settings SET pin_required=0,modules_json='{}'")
    check(call('TV_VIEW','channels',actor='tv-token')['status']==401,'TV module disabled denies direct provider access')
    request('PUT','viewers/'+grant['id'],{'if_revision':grant['revision'],'enabled':False})
    check(request('WEB_VIEW','channels',actor='phone-b')['items']==[],'grant withdrawal removes authorized directory')
    check(call('MEDIA',token=tv['session_id'],channel=ch['id'],name='index.m3u8')['status']==403,'grant withdrawal rejects old media ticket')
    check(call('DELETE','epg-sources/'+epg['id'],{'if_revision':2})['code']=='epg_source_in_use','referenced EPG source cannot be deleted')
    check(call('POST','channels',{'name':'bad\nplaylist','source_url':base+'/source.ts'})['status']==400,'playlist name cannot inject extra directives')
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    def wait_job(id):
        for _ in range(160):
            job=request('GET','jobs/'+id)
            if job['state'] in ['complete','failed','cancelled','interrupted']:return job
            time.sleep(.2)
        raise AssertionError(job)
    revision=request('GET','channels')['revision']
    fetch=request('POST','imports/fetch',{'url':base+'/list.m3u','format':'m3u','confirm':True})
    fetched=wait_job(fetch['id'])
    check(fetched['state']=='complete' and fetched['result']['rows'][0]['action']=='create','URL playlist fetch is an asynchronous preview')
    check(request('GET','channels')['revision']==revision,'URL fetch does not import or periodically subscribe')
    check(request('POST','scans/preview',{'template':base+'/[1-2]/[3-4].ts'})['count']==4,'scan expands only the explicit Cartesian range')
    check(call('POST','scans/preview',{'template':base+'/[1-129].ts'})['code']=='scan_template_invalid_or_limit','scan rejects oversized range before network activity')
    check(call('POST','scans',{'template':base+'/source.ts'})['code']=='requires_confirmation','scan start requires explicit confirmation')
    scan=request('POST','scans',{'template':base+'/source.ts','timeout_seconds':10,'confirm':True})
    scanned=wait_job(scan['id'])
    check(scanned['state']=='complete' and scanned['result']['rows'][0]['state']=='found','scan validates a real video stream using shared ffprobe budget')
    choice={'rows':[{'index':0,'name':'已存在的扫描频道'}]}
    preview_scan=request('POST','scans/'+scan['id']+'/import-preview',choice)
    check(preview_scan['rows'][0]['action']=='skip','scan import detects existing source')
    scan=request('POST','scans',{'template':base+'/source.ts','timeout_seconds':30,'confirm':True})
    request('POST','scans/'+scan['id']+'/stop',{})
    stopped=wait_job(scan['id'])
    check(stopped['state']=='cancelled','scan stop cancels queued or active probe')
    request('DELETE','scans/'+scan['id'],{})
    check(call('GET','scans/'+scan['id'])['status']==404,'finished scan history can be deleted without deleting channels')
    channel=request('GET','channels/'+ch['id'])
    request('PUT','channels/'+ch['id'],{'if_revision':channel['revision'],'timeshift_minutes':1})
    settings=request('GET','settings')
    request('PUT','settings',{'if_revision':settings['revision'],'window_segments':3})
    request('POST','channels/'+ch['id']+'/start',{})
    for _ in range(70):
        window_result=call('GET','channels/'+ch['id']+'/timeshift')
        if not window_result['status'] and len(window_result['data']['segments'])>=6:break
        time.sleep(.4)
    window=window_result['data']
    check(window and len(window['segments'])>=6 and window['end']-window['start']<60,
          'timeshift reports actual retained segments instead of configured minutes')
    start=int(window['segments'][1]['start'])+1
    shifted=request('POST','channels/'+ch['id']+'/timeshift',{'start':start})
    playlist=call('MEDIA',token=shifted['session_id'],channel=ch['id'],name=f'at{start}.m3u8')
    check(playlist['status']==0 and b'#EXT-X-START:' in playlist['bytes'],
          'timeshift playlist selects actual time and exposes precise offset')
    check(decode(shifted).returncode==0,'actual FFmpeg client decodes retained timeshift')
    check(call('POST','channels/'+ch['id']+'/timeshift',{'start':int(window['start'])-5})['code']=='timeshift_window_expired',
          'timeshift rejects expired interval')
    window=request('GET','channels/'+ch['id']+'/timeshift')
    absent=window['segments'][2]
    segment=root/'.dreamingwrt-iptv'/window['generation']/absent['name']
    saved_segment=segment.read_bytes();segment.unlink()
    try:
        check(request('GET','channels/'+ch['id']+'/timeshift')['missing_segments']==1,
              'timeshift reports a missing retained segment')
        check(call('POST','channels/'+ch['id']+'/timeshift',{'start':int(absent['start'])+1})['code']=='timeshift_gap',
              'timeshift does not silently seek across a gap')
    finally:segment.write_bytes(saved_segment)
    grant=request('GET','viewers/'+grant['id'])
    request('PUT','viewers/'+grant['id'],{'if_revision':grant['revision'],'enabled':True})
    viewer_window=request('WEB_VIEW','timeshift/'+ch['id']+'/info',actor='phone-a')
    viewer_start=int(viewer_window['segments'][-2]['start'])+1
    viewer_shift=request('WEB_VIEW',f'timeshift/{ch["id"]}/{viewer_start}',actor='phone-a')
    check(call('MEDIA',token=viewer_shift['session_id'],channel=ch['id'],name=f'at{viewer_start}.m3u8')['status']==0,
          'viewer timeshift uses the same authorized provider and bounded media lease')
    request('WEB_VIEW','release/'+viewer_shift['session_id'],{'confirmed':True},actor='phone-a')
    request('DELETE','sessions/'+shifted['session_id'],{})
    check(runtime()['manual_hold'] and runtime()['process_running'],
          'closing preview retains explicitly started stream')
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    check(call('GET','channels/'+ch['id']+'/timeshift')['status']!=0,
          'stopped stream does not advertise old timeshift history')
    cfg=request('GET','settings')
    request('PUT','settings',{'if_revision':cfg['revision'],'recording_path':str(root),'recording_segment_seconds':10,'recording_limit_mb':128,'max_streams':2})
    channel=request('GET','channels/'+ch['id'])
    check(call('POST','captures/'+ch['id']+'/start',{'if_revision':channel['revision']})['code']=='requires_confirmation',
          'continuous recording requires an explicit resource confirmation')
    request('POST','captures/'+ch['id']+'/start',{'if_revision':channel['revision'],'confirm':True})
    preview=request('POST','channels/'+ch['id']+'/preview',{})
    request('DELETE','sessions/'+preview['session_id'],{})
    check(runtime()['recording_hold'],'closing preview retains continuous recording holder')
    def wait_record(predicate,timeout=65):
        until=time.time()+timeout
        while time.time()<until:
            listing=request('GET','recordings')
            for r in listing['items']:
                if predicate(r):return r
            time.sleep(.5)
        raise AssertionError(listing)
    recorded=wait_record(lambda r:r['state']=='ready')
    check(recorded['end']>recorded['start'] and recorded['bytes']>0 and recorded['archive_bytes']>0,
          'shared live segments become an indexed archive after actual decode verification')
    guide_with_recording=request('WEB_VIEW','epg/'+ch['id']+'/now',actor='phone-a')
    check(any(p['recording_available'] and any(r['recording_id']==recorded['id'] and r['offset_seconds']>=0 for r in p['recordings']) for p in guide_with_recording['items']),
          'programme replay availability comes from real ready recording intervals and offsets')
    request('POST','captures/'+ch['id']+'/stop',{})
    for _ in range(20):
        capture=next(c for c in request('GET','recordings')['captures'] if c['id']==ch['id'])
        if capture['state']=='stopped':break
        time.sleep(.2)
    check(capture['state']=='stopped' and not runtime()['recording_hold'],'recording stop finalizes independently of other viewers')
    ticket=request('POST','recordings/'+recorded['id']+'/preview',{})
    name='record-'+recorded['id']+'.mp4'
    info=call('MEDIA_RECORD_INFO',token=ticket['session_id'],channel=ch['id'],name=name)
    part=call('MEDIA_RECORD_READ',token=ticket['session_id'],channel=ch['id'],name=name,offset=0,maximum=32)
    check(info['data']['size']==recorded['archive_bytes'] and b'ftyp' in part['bytes'],
          'recording media transport exposes authorized metadata and bounded byte slices')
    check(decode(ticket).returncode==0,'actual FFmpeg client decodes archived MP4 over HTTP')
    other_name='record-'+('0'*48)+'.mp4'
    check(call('MEDIA_RECORD_INFO',token=ticket['session_id'],channel=ch['id'],name=other_name)['status']==403,
          'recording ticket cannot access another recording of the channel')
    check(call('MEDIA',token=ticket['session_id'],channel=ch['id'],name='index.m3u8')['code']=='recording_ticket_scope',
          'recording ticket cannot be reused for live HLS')
    with sqlite3.connect(root/'config.db') as db:db.execute("UPDATE tvhome_settings SET pin_required=0,modules_json=?",(json.dumps({'live':True}),))
    mobile_record=request('WEB_VIEW','recording/'+recorded['id'],actor='phone-a')
    tv_record=request('TV_VIEW','recording/'+recorded['id'],actor='tv-token')
    check(mobile_record['resource_id']==tv_record['resource_id']==recorded['id'] and mobile_record['session_id']!=tv_record['session_id'],
          'TV and mobile use the same recording resource with independent tickets')
    check(any(r['id']==recorded['id'] for r in request('WEB_VIEW','recordings/'+ch['id'],actor='phone-a')['items']) and
          any(r['id']==recorded['id'] for r in request('TV_VIEW','recordings/'+ch['id'],actor='tv-token')['items']),
          'authorized TV and mobile recording lists expose the same indexed files')
    current_grant=request('GET','viewers/'+grant['id'])
    disabled=request('PUT','viewers/'+grant['id'],{'if_revision':current_grant['revision'],'enabled':False})['record']
    check(call('MEDIA_RECORD_READ',token=mobile_record['session_id'],channel=ch['id'],name=name,offset=0,maximum=32)['status']==403 and
          call('MEDIA_RECORD_INFO',token=tv_record['session_id'],channel=ch['id'],name=name)['status']==403,
          'grant withdrawal rejects existing TV and mobile recording byte requests')
    request('PUT','viewers/'+grant['id'],{'if_revision':disabled['revision'],'enabled':True})
    request('WEB_VIEW','release/'+mobile_record['session_id'],{'confirmed':True},actor='phone-a')
    request('TV_VIEW','release/'+tv_record['session_id'],{'confirmed':True},actor='tv-token')
    check(call('DELETE','recordings/'+recorded['id'],{'if_revision':recorded['revision'],'confirm':True})['code']=='recording_in_use',
          'playing recordings cannot be deleted')
    request('DELETE','sessions/'+ticket['session_id'],{})
    check(call('MEDIA_RECORD_INFO',token=ticket['session_id'],channel=ch['id'],name=name)['status']==401,
          'released recording ticket is revoked on the next media request')
    locked=request('PUT','recordings/'+recorded['id'],{'if_revision':recorded['revision'],'locked':True})
    check(call('DELETE','recordings/'+recorded['id'],{'if_revision':locked['revision'],'confirm':True})['code']=='recording_locked',
          'locked recording requires its own force confirmation')
    # Simulate an unwritable archive destination only inside the isolated volume.
    record_dir=root/'.dreamingwrt-recordings'/recorded['id']
    mp4=record_dir/'archive.mp4';mp4.unlink();mp4.mkdir()
    request('POST','recordings/'+recorded['id']+'/archive',{'if_revision':locked['revision']})
    failed=wait_record(lambda r:r['id']==recorded['id'] and r['state']=='archive_failed')
    check((record_dir/'source.ts').stat().st_size>0 and failed.get('error'),
          'failed archive preserves original TS and explicit failure')
    mp4.rmdir()
    request('POST','recordings/'+recorded['id']+'/archive',{'if_revision':failed['revision']})
    restored=wait_record(lambda r:r['id']==recorded['id'] and r['state']=='ready')
    check(restored['locked'],'successful archive retry preserves the lock')
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    # Replace the configured module directory to model a mount disappearing and
    # an empty directory remaining at the same path. No live mounts are touched.
    request('POST','captures/'+ch['id']+'/start',{'if_revision':channel['revision'],'confirm':True})
    storage=root/'.dreamingwrt-recordings';offline=root/'recordings-offline';storage.rename(offline);storage.mkdir()
    try:
        for _ in range(20):
            capture=next(c for c in request('GET','recordings')['captures'] if c['id']==ch['id'])
            if capture['state']=='error':break
            time.sleep(.2)
        check(capture['error']=='recording_storage_unavailable' and not list(storage.iterdir()),
              'recording stops after storage identity changes and never writes into the replacement directory')
    finally:storage.rmdir();offline.rename(storage)
    request('POST','channels/'+ch['id']+'/stop',{'confirm':True})
    # Interrupt an active capture. Restart preserves the partial source and
    # requires a visible archive retry instead of claiming that it stayed live.
    request('POST','captures/'+ch['id']+'/start',{'if_revision':channel['revision'],'confirm':True})
    interrupted=wait_record(lambda r:r['state']=='writing' and r['bytes']>0)
    process.terminate();process.wait(timeout=15)
    process=subprocess.Popen([a.daemon],stdout=log,stderr=log)
    for _ in range(100):
        if Path(sock).exists():break
        time.sleep(.1)
    recovered=request('GET','recordings/'+interrupted['id'])
    partial=root/'.dreamingwrt-recordings'/interrupted['id']/'source.ts'
    check(recovered['state']=='interrupted' and partial.stat().st_size>0,
          'service restart preserves partial TS and explicitly marks recording interrupted')
    request('POST','recordings/'+interrupted['id']+'/archive',{'if_revision':recovered['revision']})
    recovered=wait_record(lambda r:r['id']==interrupted['id'] and r['state']=='ready')
    check(recovered['media_ready'],'interrupted recording can be re-archived and decoded after restart')
    history_view=request('WEB_VIEW','recording/'+recovered['id'],actor='phone-a')
    channel=request('GET','channels/'+ch['id'])
    request('DELETE','channels/'+ch['id'],{'if_revision':channel['revision']})
    history=request('POST','recordings/'+recovered['id']+'/preview',{})
    history_name='record-'+recovered['id']+'.mp4'
    check(partial.exists() and call('MEDIA_RECORD_INFO',token=history['session_id'],channel=ch['id'],name=history_name)['status']==0,
          'channel deletion preserves historical files and management playback')
    check(call('MEDIA_RECORD_INFO',token=history_view['session_id'],channel=ch['id'],name=history_name)['status']==403,
          'deleted channel does not retain viewer access to old recording tickets')
    request('DELETE','sessions/'+history['session_id'],{})
    request('WEB_VIEW','release/'+history_view['session_id'],{'confirmed':True},actor='phone-a')
    # Expire an isolated record to test preview/revision/locked cleanup semantics.
    with sqlite3.connect(root/'config.db') as db:
        db.execute("UPDATE iptv_record SET body=json_set(body,'$.end',unixepoch()-86400*30,'$.start',unixepoch()-86400*30-10) WHERE kind='recordings' AND id=?",(recorded['id'],))
    check(all(r['id']!=recorded['id'] for r in request('POST','recordings/cleanup-preview',{})['items']),
          'retention cleanup preview excludes locked recordings')
    current=request('GET','recordings/'+recorded['id'])
    unlocked=request('PUT','recordings/'+recorded['id'],{'if_revision':current['revision'],'locked':False})
    clean=request('POST','recordings/cleanup-preview',{})
    check(any(r['id']==recorded['id'] for r in clean['items']) and record_dir.exists(),
          'cleanup preview reports expired scope without deleting files')
    result=request('POST','recordings/cleanup',{'confirm':True,'items':[{'id':recorded['id'],'revision':unlocked['revision']}]})
    check(result['items'][0]['deleted'] and not record_dir.exists(),'cleanup deletes only the explicitly previewed registered record')
    # Automatic expiry is opt-in, protects playing/locked files, and only
    # removes registered files. These are synthetic files in this /tmp volume.
    cfg=request('GET','settings')
    request('PUT','settings',{'if_revision':cfg['revision'],'recording_auto_cleanup':True})
    recovered=request('GET','recordings/'+interrupted['id'])
    lock=request('PUT','recordings/'+interrupted['id'],{'if_revision':recovered['revision'],'locked':True})
    with sqlite3.connect(root/'config.db') as db:
        db.execute("UPDATE iptv_record SET body=json_set(body,'$.end',unixepoch()-86400*30) WHERE kind='recordings' AND id=?",(interrupted['id'],))
    time.sleep(2)
    check(partial.exists(),'automatic expiry preserves locked recordings')
    request('PUT','recordings/'+interrupted['id'],{'if_revision':lock['revision'],'locked':False})
    for _ in range(20):
        if not partial.exists():break
        time.sleep(.2)
    check(not partial.exists() and call('GET','recordings/'+interrupted['id'])['status']==404,
          'automatic expiry removes the registered unlocked recording and its index')
    result={'passed':len(checks),'checks':checks,'environment':'31.6; lester; isolated /tmp DB/socket; synthetic H.264/AAC HTTP source; FFmpeg HLS clients','unverified':['browser decode','real ISP input','target router dependencies','TV/mobile provider']}
    (root/'integration-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print(json.dumps(result,ensure_ascii=False),flush=True)
    if a.serve:
        category=request('GET','categories/'+cat['id'])
        request('PUT','categories/'+cat['id'],{'if_revision':category['revision'],'enabled':True})
        print('BROWSER_TEST_SERVER',base,flush=True)
        while True:time.sleep(1)
finally:
    for error_file in (root/'.dreamingwrt-iptv').glob('*/error.log'):
        if error_file.stat().st_size:
            print('MEDIA_TOOL_ERROR',error_file.read_text()[-2000:])
    source_enabled=False
    process.terminate()
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:process.kill();process.wait()
    server.shutdown();log.close()
