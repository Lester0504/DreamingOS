#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
from pathlib import Path
import subprocess as sp,socket,struct,time,os,threading,json,sys
if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
 raise SystemExit('Run this harness inside an isolated network namespace (unshare -n); never on the host network.')
out=Path('/tmp/hw-ad-analyzer-1004');runtime=out/'policy-runtime';runtime.mkdir(exist_ok=True)
# This script runs in an otherwise empty outer network namespace.
def run(*args):return sp.run(args,check=True,stdout=sp.PIPE,stderr=sp.PIPE,text=True).stdout
run('ip','link','set','lo','up');run('ip','link','add','lan','type','bridge');run('ip','addr','add','10.205.0.1/24','dev','lan');run('ip','link','set','lan','up')
children=[];proc=None
try:
 for idx,ip in [('a','16'),('b','160')]:
  child=sp.Popen(['unshare','-n','sleep','3600']);children.append(child);time.sleep(.05)
  run('ip','link','add','v'+idx,'type','veth','peer','name','c'+idx);run('ip','link','set','v'+idx,'master','lan');run('ip','link','set','v'+idx,'up');run('ip','link','set','c'+idx,'netns',str(child.pid))
  ns=['nsenter','-t',str(child.pid),'-n'];run(*ns,'ip','link','set','lo','up');run(*ns,'ip','link','set','c'+idx,'address','02:00:00:00:00:'+('16' if idx=='a' else '60'));run(*ns,'ip','addr','add','10.205.0.'+ip+'/24','dev','c'+idx);run(*ns,'ip','link','set','c'+idx,'up');run(*ns,'ping','-c','1','-W','1','10.205.0.1')
 def answer(q):
  end=12
  while q[end]:end+=1+q[end]
  end+=5;t=struct.unpack('!H',q[end-4:end-2])[0];data=socket.inet_pton(socket.AF_INET if t==1 else socket.AF_INET6,'198.51.100.42' if t==1 else '2001:db8::42');return q[:2]+struct.pack('!5H',0x8180,1,1,0,0)+q[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',t,1,300,len(data))+data
 def udp():
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',15484))
  while True:
   q,a=s.recvfrom(4096);s.sendto(answer(q),a)
 def tcp():
  s=socket.socket();s.bind(('127.0.0.1',15484));s.listen()
  while True:
   c,_=s.accept()
   def serve(c):
    with c:
     while True:
      p=c.recv(2)
      if not p:return
      q=c.recv(struct.unpack('!H',p)[0]);a=answer(q);c.sendall(struct.pack('!H',len(a))+a)
   threading.Thread(target=serve,args=(c,),daemon=True).start()
 threading.Thread(target=udp,daemon=True).start();threading.Thread(target=tcp,daemon=True).start()
 (runtime/'queries.log').write_text('');os.chown(runtime/'queries.log',65534,0);os.chmod(runtime/'queries.log',0o640);rev=0
 def policy(rows):
  global rev
  rev+=1;tmp=runtime/'policy.new';tmp.write_text('DWAD1 '+str(rev)+'\n'+'\n'.join(rows)+'\n');tmp.replace(runtime/'policy')
 observer='O capture 02:00:00:00:00:16 10.205.0.16 '+str(int(time.time())+120)+' - - *'
 def rule(domain,act='B',ttl=120,mac='02:00:00:00:00:16',ip='10.205.0.16',match='E'):
  return f'R trial {mac} {ip} {int(time.time())+ttl if ttl else 0} {act} {match} {domain}'
 policy([observer]);env=os.environ.copy();env['LD_LIBRARY_PATH']=str(out/'dnsmasq-objects/lib')
 log=(out/'dns-policy-isolation.log').open('w')
 command=[str(out/'dnsmasq-objects/dnsmasq-test'),'--keep-in-foreground','--user=nobody','--group=nogroup','--conf-file=/dev/null','--port=53','--listen-address=10.205.0.1,127.0.0.1','--bind-interfaces','--no-hosts','--no-resolv','--server=127.0.0.1#15484','--address=/parent.test/0.0.0.0','--cache-size=100','--pid-file='+str(runtime/'pid')];proc=sp.Popen(command,env=env,stdout=log,stderr=log);time.sleep(.2)
 client='''import socket,struct,json,sys,time
name=sys.argv[1];tcp=sys.argv[2]=='tcp';typ=int(sys.argv[3]);s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM);s.settimeout(2);s.connect(('10.205.0.1',53))
def q():
 w=struct.pack('!6H',1234,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\\0'+struct.pack('!HH',typ,1)
 s.sendall(struct.pack('!H',len(w))+w if tcp else w)
 a=s.recv(2) if tcp else s.recv(4096)
 if tcp:a=s.recv(struct.unpack('!H',a)[0])
 end=12
 while a[end]:end+=1+a[end]
 end+=5
 return {'rcode':a[3]&15,'ip':socket.inet_ntop(socket.AF_INET if typ==1 else socket.AF_INET6,a[-(4 if typ==1 else 16):]),'ttl':struct.unpack('!I',a[end+6:end+10])[0]}
r=[q()]
if len(sys.argv)>4:time.sleep(float(sys.argv[4]));r.append(q())
print(json.dumps(r))'''
 def query(device,name,transport='udp',typ=1,delay=None):
  cmd=['nsenter','-t',str(children[device].pid),'-n','python3','-c',client,name,transport,str(typ)]+([str(delay)] if delay else [])
  return json.loads(run(*cmd))
 checks=[]
 def check(label,got,expected):
  assert got==expected,(label,got,expected);checks.append(label)
 check('baseline cache A',query(0,'ads.test')[0]['ip'],'198.51.100.42')
 policy([observer,rule('ads.test')]);check('cached A blocked',query(0,'ads.test')[0]['ip'],'0.0.0.0');check('B same domain unchanged',query(1,'ads.test')[0]['ip'],'198.51.100.42');check('A sibling same IP unchanged',query(0,'normal.test')[0]['ip'],'198.51.100.42');check('TCP block',query(0,'ads.test','tcp')[0]['ip'],'0.0.0.0');check('AAAA block',query(0,'ads.test','udp',28)[0]['ip'],'::')
 policy([observer,rule('login.parent.test','A')]);check('exact allow',query(0,'login.parent.test')[0]['ip'],'198.51.100.42');check('allow has TTL zero',query(0,'login.parent.test')[0]['ttl'],0);check('sibling parent stays blocked',query(0,'ads.parent.test')[0]['ip'],'0.0.0.0');check('other device stays blocked',query(1,'login.parent.test')[0]['ip'],'0.0.0.0');check('TCP exact allow',query(0,'login.parent.test','tcp')[0]['ip'],'198.51.100.42')
 policy([observer,rule('login.parent.test','A',2)]);result=query(0,'login.parent.test','tcp',1,3);check('same TCP lease expires',[r['ip'] for r in result],['198.51.100.42','0.0.0.0'])
 policy([observer,rule('ads.test',mac='02:00:00:00:00:60')]);check('wrong MAC never transfers',query(0,'ads.test')[0]['ip'],'198.51.100.42')
 policy([observer]);check('explicit revoke',query(0,'ads.test')[0]['ip'],'198.51.100.42')
 text=(runtime/'queries.log').read_text();check('observer only device A','from 10.205.0.160' in text,False);check('observer captures responses','reply ads.test is 0.0.0.0' in text,True)
 # Same real resolver and real source identities, through analyzer + provider + SQLite.
 (runtime/'leases').write_text('0 02:00:00:00:00:16 10.205.0.16 TestA *\n0 02:00:00:00:00:60 10.205.0.160 TestB *\n')
 for f in ['config.db','sessions.db']:
  (runtime/f).unlink(missing_ok=True)
 cli=str(out/'control-cli');counter=0
 def call(method,path='',body=None,status=200):
  args=[cli,str(runtime/'config.db'),str(runtime),str(runtime/'leases'),method,path,json.dumps(body or {})]
  r=json.loads(run(*args));assert r['http_status']==status,(method,path,r);return r
 call('INIT')
 def cap():return call('PROVIDER','capabilities')['provider_revision']
 scope={'type':'device','device_id':'02:00:00:00:00:16'}
 def body(**kw):
  global counter
  counter+=1;return {'request_id':'request-'+str(counter),**kw}
 def state(sid):return call('GET','sessions/'+sid)
 def change(sid,suffix,**kw):
  return call('POST','sessions/'+sid+'/'+suffix,body(expected_revision=state(sid)['revision'],scope=scope,provider_revision=cap(),**kw))
 def rules(*names,action='block'):return [{'domain':d,'action':action,'match':'exact'} for d in names]
 a=call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=120),201);sid=a['session_id']
 query(0,'ads.test');query(0,'normal.test');call('CAPTURE',status=0);obs=call('GET','sessions/'+sid+'/observations');check('native observer feeds real session',obs['total'],2)
 tr=change(sid,'trial',rules=rules('ads.test'),ttl_seconds=120);check('analyzer real block',query(0,'ads.test')[0]['ip'],'0.0.0.0');check('analyzer normal shared IP',query(0,'normal.test')[0]['ip'],'198.51.100.42')
 stopped=change(sid,'stop');check('stop saves report',stopped['report_saved'],True);check('stop keeps trial',query(0,'ads.test')[0]['ip'],'0.0.0.0')
 ended=change(sid,'end');check('end reverts trial',query(0,'ads.test')[0]['ip'],'198.51.100.42')
 a=call('POST','sessions',body(device_ip='10.205.0.16',mode='false_positive',observe_ttl=120),201);sid=a['session_id']
 tr=change(sid,'trial',rules=rules('login.parent.test',action='allow'),ttl_seconds=120);check('analyzer exact allow',query(0,'login.parent.test')[0]['ip'],'198.51.100.42');check('analyzer allow B unaffected',query(1,'login.parent.test')[0]['ip'],'0.0.0.0')
 pv=change(sid,'conclusions/preview',rules=rules('login.parent.test',action='allow'));saved=change(sid,'conclusions/commit',rules=rules('login.parent.test',action='allow'));check('permanent saved',saved['saved'],True)
 change(sid,'end');check('permanent survives trial revoke',query(0,'login.parent.test')[0]['ip'],'198.51.100.42');call('RESTART');check('permanent survives provider restart',query(0,'login.parent.test')[0]['ip'],'198.51.100.42')
 a=call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=120),201);sid=a['session_id']
 x=change(sid,'bisect',rules=rules('ads.test','normal.test'),ttl_seconds=120,baseline_confirmed=True)
 check('first half actually blocked',query(0,'ads.test')[0]['ip'],'0.0.0.0');check('holdout remains normal',query(0,'normal.test')[0]['ip'],'198.51.100.42')
 def feedback(x,value):return change(sid,'bisect/feedback',trial_id=x['trial']['id'],round_id=x['bisect']['round_id'],feedback=value,ttl_seconds=120)
 x=feedback(x,'uncertain');check('uncertain retains candidates',len(x['bisect']['candidates']),2)
 x=feedback(x,'effective');check('one candidate still needs retest',x['bisect']['state'],'awaiting_feedback');check('one candidate final retest flag',x['bisect']['final_retest'],True)
 x=change(sid,'bisect/undo',trial_id=x['trial']['id'],round_id=x['bisect']['round_id'],ttl_seconds=120);check('undo restores both candidates',len(x['bisect']['candidates']),2)
 x=feedback(x,'effective');x=feedback(x,'effective');check('single effective retest recorded',x['bisect']['state'],'verified_candidate');check('final feedback removes trial',query(0,'ads.test')[0]['ip'],'198.51.100.42')
 change(sid,'end')
 # Durable retry after analyzer storage fails: provider effect must be recovered,
 # not duplicated or misreported as an untouched data plane.
 import sqlite3
 a=call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=120),201);sid=a['session_id']
 request=body(expected_revision=state(sid)['revision'],scope=scope,provider_revision=cap(),rules=rules('retry.test'),ttl_seconds=120)
 with sqlite3.connect(runtime/'sessions.db') as db:db.execute("CREATE TRIGGER fail_save BEFORE UPDATE ON analyzer_sessions BEGIN SELECT RAISE(ABORT,'test disk full'); END")
 failed=call('POST','sessions/'+sid+'/trial',request,503);check('provider applied despite session save failure',query(0,'retry.test')[0]['ip'],'0.0.0.0')
 with sqlite3.connect(runtime/'sessions.db') as db:db.execute('DROP TRIGGER fail_save')
 retry=call('POST','sessions/'+sid+'/trial',request);repeat=call('POST','sessions/'+sid+'/trial',request);check('durable trial retry stable id',repeat['trial']['id'],retry['trial']['id'])
 # Version and scope conflicts cannot mutate the applied set.
 bad=body(expected_revision=1,scope=scope,provider_revision=cap(),rules=rules('changed.test'),ttl_seconds=120)
 call('POST','sessions/'+sid+'/trial',bad,409);check('stale revision keeps old trial',query(0,'retry.test')[0]['ip'],'0.0.0.0')
 bad=body(expected_revision=state(sid)['revision'],scope={'type':'device','device_id':'02:00:00:00:00:60'},provider_revision=cap(),rules=rules('changed.test'),ttl_seconds=120)
 call('POST','sessions/'+sid+'/trial',bad,409);check('scope conflict keeps old trial',query(0,'changed.test')[0]['ip'],'198.51.100.42')
 # A failed resolver acknowledgement rolls configuration and snapshot back.
 oldrev=cap();proc.terminate();proc.wait(timeout=5)
 bad=body(expected_revision=state(sid)['revision'],scope=scope,provider_revision=oldrev,rules=rules('changed.test'),ttl_seconds=120)
 failed=call('POST','sessions/'+sid+'/trial',bad,503);check('failed resolver apply reports rollback',failed['rollback_ok'],True)
 proc=sp.Popen(command,env=env,stdout=log,stderr=log);time.sleep(.2)
 check('rollback restored previous trial',query(0,'retry.test')[0]['ip'],'0.0.0.0');check('failed candidate absent',query(0,'changed.test')[0]['ip'],'198.51.100.42')
 call('RESTART');check('provider restart clears temporary block',query(0,'retry.test')[0]['ip'],'198.51.100.42');call('RECOVER',status=0)
 # Wrong candidate set cannot be labelled as a verified culprit.
 a=call('POST','sessions',body(device_ip='10.205.0.16',mode='find_ads',observe_ttl=120),201);sid=a['session_id']
 x=change(sid,'bisect',rules=rules('normal.test'),ttl_seconds=120,baseline_confirmed=True);x=feedback(x,'ineffective');check('wrong singleton is unlocated',x['bisect']['state'],'unlocated')
 x=change(sid,'bisect/undo',trial_id=x['trial']['id'],round_id=x['bisect']['round_id'],ttl_seconds=120);check('undo from final result restores trial',x['bisect']['state'],'awaiting_feedback')
 change(sid,'end')
 (out/'dns-policy-evidence.json').write_text(json.dumps({'checks':checks,'queries_log':str(runtime/'queries.log')},indent=2));print('PASS',len(checks),'real DNS isolation checks',flush=True)
 if '--serve' in sys.argv:
  (out/'netns.pid').write_text(str(os.getpid()))
  while True:time.sleep(1)
finally:
 if proc:proc.terminate();proc.wait(timeout=5)
 for c in children:c.terminate();c.wait(timeout=5)
