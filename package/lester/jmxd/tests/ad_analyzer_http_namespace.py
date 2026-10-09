from pathlib import Path
import subprocess as sp,os,time,json,sqlite3,http.client,sys
out=Path('/tmp/hw-ad-analyzer-1004')
assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net')
assert os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt')
def run(*a):return sp.run(a,check=True,capture_output=True,text=True).stdout
run('mount','--make-rprivate','/')
run('mount','--bind',str(out),'/opt')
run('mount','-t','tmpfs','tmpfs','/tmp');out.mkdir();run('mount','--bind','/opt',str(out))
run('mount','-t','tmpfs','tmpfs','/run')
etc=out/'http-etc';etc.mkdir(exist_ok=True)
for name in ['passwd','group','nsswitch.conf','ld.so.cache','localtime']:
 p=Path('/etc')/name
 if p.exists(): (etc/name).write_bytes(p.read_bytes())
(etc/'passwd').write_text('\n'.join(x for x in (etc/'passwd').read_text().splitlines() if not x.startswith('dnsmasq:'))+'\n')
with (etc/'passwd').open('a') as f:f.write('dnsmasq:x:65534:65534:DNS test:/nonexistent:/usr/sbin/nologin\n')
(etc/'dreamingwrt').mkdir(exist_ok=True);(etc/'config').mkdir(exist_ok=True)
run('mount','--bind',str(etc),'/etc')
Path('/tmp/dhcp.leases').write_text('0 02:00:00:00:00:16 10.205.0.16 TestA *\n0 02:00:00:00:00:60 10.205.0.160 TestB *\n')
Path('/run/ubus').mkdir();Path('/run/dreamingwrt/ad-dns').mkdir(parents=True)
run('mount','--bind',str(out/'policy-runtime'),'/run/dreamingwrt/ad-dns')
env=os.environ.copy();env['LD_LIBRARY_PATH']=str(out/'http-libs')
procs=[]
def start(binary,*args):
 log=(out/(Path(binary).name+'-http.log')).open('w');p=sp.Popen([str(out/binary),*args],env=env,stdout=log,stderr=sp.STDOUT);procs.append(p);return p
try:
 start('ubusd');time.sleep(.3)
 start('build-x86/dreamingwrt-webd','19489','127.0.0.1');time.sleep(1)
 start('aegis-build-x86/dreamingwrt-aegisxd');time.sleep(1)
 now=int(time.time())
 with sqlite3.connect('/etc/dreamingwrt/apid.db') as db:
  for role in ['admin','viewer']:
   db.execute("INSERT OR REPLACE INTO app_devices(id,name,role,paired_at,approval_state) VALUES(?,?,?,?,?)",('ad-test-'+role,role,role,now,'approved'))
   db.execute("INSERT OR REPLACE INTO auth_tokens(token,device_id,type,created_at,expires_at) VALUES(?,?,?,?,?)",('isolated-ad-'+role,'ad-test-'+role,'access',now,now+7200))
 (out/'http-netns.pid').write_text(str(os.getpid()))
 print('HTTP_READY',flush=True)
 while True:
  if any(p.poll() is not None for p in procs):raise RuntimeError('service exited: '+str([p.poll() for p in procs]))
  time.sleep(1)
finally:
 for p in reversed(procs):
  p.terminate()
 for p in reversed(procs):
  try:p.wait(timeout=3)
  except sp.TimeoutExpired:p.kill();p.wait()
