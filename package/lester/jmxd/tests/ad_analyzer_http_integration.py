from pathlib import Path
import http.client,json,subprocess as sp,time,os,uuid
assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net')
out=Path('/tmp/hw-ad-analyzer-1004');prefix='/api/v1/diagnostics/ad-analyzer/'
checks=[]
def check(name,ok):
 assert ok,name;checks.append(name)
def call(method,path,body=None,role='admin',status=200):
 c=http.client.HTTPConnection('127.0.0.1',19489,timeout=8);h={'Content-Type':'application/json','Sec-Fetch-Site':'same-origin'}
 if role:h['Authorization']='Bearer isolated-ad-'+role
 c.request(method,path if path.startswith('/api/') else prefix+path,json.dumps(body) if body else None,h);r=c.getresponse();b=json.loads(r.read());c.close();assert r.status==status,(method,path,r.status,b);return b.get('data',b)
parent=int((out/'netns.pid').read_text());pids=Path(f'/proc/{parent}/task/{parent}/children').read_text().split();devices=[p for p in pids if Path('/proc/'+p+'/cmdline').read_bytes().startswith(b'sleep\x003600')]
assert len(devices)==2,devices
client='''import socket,struct,sys
n=sys.argv[1];s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);q=struct.pack('!6H',1234,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in n.split('.'))+b'\\0'+struct.pack('!HH',1,1);s.sendto(q,('10.205.0.1',53));a=s.recv(4096);print(socket.inet_ntoa(a[-4:]))'''
def query(device,domain):return sp.run(['nsenter','-t',devices[device],'-n','python3','-c',client,domain],text=True,capture_output=True,check=True).stdout.strip()
def body(**kw):return {'request_id':str(uuid.uuid4()),**kw}
def state(sid):return call('GET','sessions/'+sid)
def rules(domain,action='block'):return [{'domain':domain,'action':action,'match':'exact'}]
scope={'type':'device','device_id':'02:00:00:00:00:16'}
def change(sid,suffix,rs=None,**kw):
 b=body(expected_revision=state(sid)['revision'],scope=scope,**kw)
 if rs is not None:
  pv=call('POST','sessions/'+sid+'/conclusions/preview',body(expected_revision=state(sid)['revision'],scope=scope,rules=rs));b.update(rules=rs,provider_revision=pv['provider_revision'])
 return call('POST','sessions/'+sid+'/'+suffix,b)
cap=call('GET','capabilities');check('HTTP ubus provider ready',cap['actions']['can_trial_block'] and cap['actions']['can_trial_allow'])
viewer=call('GET','capabilities',role='viewer');check('viewer permissions projected',viewer['permissions']['operate'] is False)
call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=1800),role='viewer',status=403);checks.append('viewer HTTP write forbidden')
call('GET','capabilities',role=None,status=401);checks.append('anonymous HTTP unauthorized')
for previous in call('GET','sessions')['sessions']:
 if previous['can_operate']:change(previous['session_id'],'end')
a=call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=1800),status=201);sid=a['session_id']
query(0,'http-ads.test');query(0,'http-normal.test');time.sleep(5.3)
obs=call('GET','sessions/'+sid+'/observations');check('HTTP timer captured real DNS',obs['total']>=2)
r=change(sid,'trial',rules('http-ads.test'),ttl_seconds=120);check('HTTP ubus block applied',r['trial']['apply_state']=='applied' and query(0,'http-ads.test')=='0.0.0.0');check('HTTP block other device isolated',query(1,'http-ads.test')=='198.51.100.42');check('HTTP block shared IP normal domain',query(0,'http-normal.test')=='198.51.100.42')
r=change(sid,'stop');check('HTTP stop persists report keeps trial',r['report_saved'] and query(0,'http-ads.test')=='0.0.0.0')
change(sid,'end');check('HTTP end withdraws trial',query(0,'http-ads.test')=='198.51.100.42')
a=call('POST','sessions',body(device_ip='10.205.0.16',mode='false_positive',observe_ttl=1800),status=201);sid=a['session_id']
rs=rules('http-login.parent.test','allow');change(sid,'trial',rs,ttl_seconds=120);check('HTTP allow overrides parent for A',query(0,'http-login.parent.test')=='198.51.100.42');check('HTTP parent still blocks B and sibling',query(1,'http-login.parent.test')=='0.0.0.0' and query(0,'http-ads.parent.test')=='0.0.0.0')
saved=change(sid,'conclusions/commit',rs);check('HTTP allow saved and applied',saved['saved'])
canonical=call('GET','/api/v1/aegis/domain-overrides');raw=json.dumps(canonical);check('canonical Aegis GET has exact allow',any(r.get('domain')=='http-login.parent.test' and r.get('action')=='allow' and r.get('match')=='exact' and r.get('apply_state')=='applied' for r in canonical['items']))
change(sid,'end');check('permanent survives HTTP end',query(0,'http-login.parent.test')=='198.51.100.42')
reports=call('GET','reports');check('reports from real HTTP sessions',reports['total']>=2)
a=call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=1800),status=201)
for name in ['ads.test','normal.test','login.parent.test','metrics.example.co.uk']:query(0,name)
time.sleep(5.3)
(out/'http-evidence.json').write_text(json.dumps({'checks':checks,'count':len(checks),'canonical':canonical},ensure_ascii=False,indent=2));print('PASS',len(checks),'full HTTP/webd/ubus/AegisX/DNS checks')
