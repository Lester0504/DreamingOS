#!/usr/bin/env python3
"""Run as lester on 31.6. Real Netboot C + SQLite + loopback HTTP; external
DHCP/exec/storage acquisition are test boundaries. No real mounts or LAN writes.
"""
import json,os,re,socket,sqlite3,subprocess,tempfile
from http.client import HTTPConnection
from pathlib import Path
SRC=Path(__file__).resolve().parents[1]/'src'
ROOT=SRC.parents[3]
TC=ROOT/'staging_dir/toolchain-x86_64_gcc-16.1.0_glibc'
ST=ROOT/'staging_dir/target-x86_64_glibc/usr'
WORK=Path(tempfile.mkdtemp(prefix='netboot-test-',dir='/tmp'))
boot=WORK/'boot';boot.mkdir()
for name in ['undionly.kpxe','snponly.efi']:(boot/name).write_bytes(b'0123456789abcdef')
(boot/'manifest.json').write_text(json.dumps({name:{'version':'fixture','source':'test-only','license':'test'} for name in ['undionly.kpxe','snponly.efi']}))
db=sqlite3.connect(WORK/'config.db')
db.executescript('''CREATE TABLE lan(id TEXT,name TEXT,device TEXT,enabled INT,updated_at INT);
CREATE TABLE lan_address(lan_id TEXT,ip TEXT,prefix INT,is_primary INT);
CREATE TABLE dhcp_scope(id TEXT,lan_id TEXT,enabled INT,pool_start TEXT,pool_end TEXT);
CREATE TABLE dhcp_option(scope_id TEXT,code TEXT);
INSERT INTO lan VALUES('testlan','Loopback fixture','lo',1,1);
INSERT INTO lan_address VALUES('testlan','127.0.0.1',8,1);
INSERT INTO dhcp_scope VALUES('scope','testlan',1,'100','200');''');db.commit();db.close()
args=[str(TC/'bin/x86_64-openwrt-linux-gnu-gcc'),'-O1','-g','-I'+str(SRC),'-I'+str(ST/'include'),f'-DNB_DB_PATH="{WORK}/config.db"',f'-DNB_BOOT_DIR="{boot}"',f'-DNB_RUN_DIR="{WORK}/run"']
args += [str(p) for p in (SRC/'netboot').glob('*.c')]+[str(Path(__file__).with_name('netboot_runtime_driver.c')),'-L'+str(ST/'lib'),'-Wl,-rpath-link,'+str(ST/'lib'),'-ljson-c','-lsqlite3','-luci','-lubox','-lcrypto','-lpthread','-o',str(WORK/'driver')]
with (WORK/'compile.log').open('w') as log:subprocess.run(args,check=True,stdout=log,stderr=log)
p=subprocess.Popen([str(TC/'lib/ld-linux-x86-64.so.2'),'--library-path',f'{ST}/lib:{TC}/lib',str(WORK/'driver')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
count=0

def raw(**kw):
 global count
 p.stdin.write(json.dumps(kw)+'\n');p.stdin.flush();line=p.stdout.readline();assert line,'driver exited';count+=1;return json.loads(line)
def call(resource,method='GET',body=None,id='',action='',status=200):
 r=raw(method=method,resource=resource,body=body or {},id=id,action=action);assert r['http_status']==status,r;return r['data']
def write(resource,body=None,method='POST',**kw):
 return call(resource,method,{'confirm':True,'expected_revision':call('settings')['revision'],**(body or {})},**kw)
def http(path,method='GET',body=None,headers=None):
 global count
 c=HTTPConnection('127.0.0.1',port,timeout=4);c.request(method,path,body,headers or {});r=c.getresponse();data=r.read();code=r.status;h=dict(r.getheaders());c.close();count+=1;return code,data,h
try:
 s=call('settings');assert s['revision']==0 and not s['enabled'] and s['interface_ids']==[] and not s['allow_unknown']
 db=sqlite3.connect(WORK/'config.db');assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='netboot_config'").fetchone();db.close()
 st=call('status');assert st['runtime_state']=='stopped' and not st['boot_verified']
 pr=call('preflight','POST',{'expected_revision':0,'enabled':True});assert not pr['ok'] and any(e['code']=='no_interface_selected' for e in pr['errors'])
 assert call('settings','PUT',{'expected_revision':0},status=400)['error']=='confirmation_required'
 raw(op='observe',body={'mac':'02:11:22:33:44:55'});c=call('clients')['items'][0];assert c['source']=='observed' and c['allowed'] is False
 c=write('clients',{'mac':'02-11-22-33-44-55','allowed':True,'name':'Test','default_image_id':''})['client'];assert c['mac']=='02:11:22:33:44:55'
 assert call('clients','PUT',{'confirm':True,'expected_revision':0,'allowed':False},id=c['id'],status=409)['error']=='revision_conflict'
 write('clients',{'mac':c['mac']},status=409)
 images=[]
 for i in range(2):images.append(write('images',{'name':'ISO '+str(i),'path':'/fixture/missing '+str(i)+'.iso','enabled':False})['image'])
 assert all(i['image_status']=='missing' and not i['enabled'] for i in images)
 ids=[i['id'] for i in images]
 write('images',{'ids':ids[::-1]},method='PUT',id='order');assert [i['id'] for i in call('images')['items']]==ids[::-1]
 write('images',{'ids':[ids[0],ids[0]]},method='PUT',id='order',status=400)
 rev=call('settings')['revision'];pr=call('preflight','POST',{'expected_revision':rev,'menu_timeout':20})
 r=call('settings','PUT',{'expected_revision':rev,'confirm':True,'apply':True,'preflight_token':pr['fingerprint'],'menu_timeout':20});assert r['persisted'] and r['applied']
 assert call('settings')['menu_timeout']==20
 for password in ['fixture-password','']:
  rev=call('settings')['revision'];pr=call('preflight','POST',{'expected_revision':rev,'menu_password':password})
  call('settings','PUT',{'expected_revision':rev,'confirm':True,'apply':True,'preflight_token':pr['fingerprint'],'menu_password':password})
  public=call('settings');assert public['has_menu_password']==bool(password) and 'password_hash' not in public and 'password_salt' not in public
 # A DHCP-side write must use the SAME connection, then roll back with a failed apply.
 rev=call('settings')['revision'];pr=call('preflight','POST',{'expected_revision':rev,'interface_ids':['testlan']})
 failure=call('settings','PUT',{'expected_revision':rev,'confirm':True,'apply':True,'preflight_token':pr['fingerprint'],'interface_ids':['testlan']},status=503)
 assert failure['error']=='apply_failed' and failure['result']['rollback_failed']
 authority=raw(op='authority-result')['data'];assert authority=={'rc':0,'in_transaction':True},authority
 assert call('settings')['revision']==rev and call('settings')['interface_ids']==[]
 db=sqlite3.connect(WORK/'config.db');assert db.execute("SELECT pool_start FROM dhcp_scope WHERE id='scope'").fetchone()[0]=='100';db.close()
 fixture=WORK/'iso';(fixture/'images/pxeboot').mkdir(parents=True)
 (fixture/'.treeinfo').write_text('[general]\nfamily = Rocky Linux\nversion = 9.6\narch = x86_64\n')
 for name in ['images/pxeboot/vmlinuz','images/pxeboot/initrd.img','images/install.img']:(fixture/name).write_bytes(b'fixture')
 im=raw(op='detect',path=str(fixture))['data'];assert im['image_status']=='ready' and im['boot_verified'] is False
 (fixture/'.treeinfo').write_text('[general]\nfamily=Rocky Linux\nversion=9.6\narch=i386\n');assert raw(op='detect',path=str(fixture))['data']['image_status']=='unsupported'
 (fixture/'.treeinfo').write_text('[general]\nfamily=Rocky Linux\nversion=9.6\narch=x86_64\n');(fixture/'images/pxeboot/vmlinuz').unlink();(fixture/'images/pxeboot/vmlinuz').symlink_to('/etc/passwd');assert raw(op='detect',path=str(fixture))['data']['error']=='template_file_missing'
 # An active listener is a conflict; its closed TCP connections are not.
 guard=socket.socket();guard.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 guard.bind(('127.0.0.1',0));guard.listen(1);probe_port=guard.getsockname()[1]
 probe={'expected_revision':rev,'enabled':True,'interface_ids':['testlan'],'http_port':probe_port}
 assert any(e['code']=='port_in_use' for e in call('preflight','POST',probe)['errors'])
 peer=socket.create_connection(('127.0.0.1',probe_port));accepted,_=guard.accept()
 accepted.shutdown(socket.SHUT_WR);assert peer.recv(1)==b'';peer.close();accepted.close();guard.close()
 assert not any(e['code']=='port_in_use' for e in call('preflight','POST',probe)['errors'])
 sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
 cfg={'revision':1,'settings':{'enabled':True,'interface_ids':['testlan'],'http_port':port,'menu_timeout':0,'allow_unknown':False},'clients':[],'images':[]}
 lan={'id':'testlan','ipv4':'127.0.0.1','device':'lo','prefix':8}
 block=raw(op='render',body=cfg,interface=lan)['data']['block'];(WORK/'dnsmasq.conf').write_text(block)
 subprocess.run(['/usr/sbin/dnsmasq','--test','--conf-file='+str(WORK/'dnsmasq.conf')],check=True,capture_output=True)
 assert 'tag:lo,tag:!dw-nb-ipxe' in block and 'option:client-arch,7' in block
 r=raw(op='http',body=cfg,interface=lan)['data'];assert r['rc']==0,r
 code,script,_=http('/boot.ipxe');assert code==200 and b'param mac ${netX/mac}' in script and b'param platform ${platform}' in script
 assert http('/menu.ipxe','POST','mac=02%3A11%3A22%3A33%3A44%3A55&arch=x86_64')[0]==403
 cfg['clients']=[{'id':c['mac'],'allowed':True}];raw(op='publish',body=cfg)
 code,body,_=http('/menu.ipxe','POST','mac=02%3A11%3A22%3A33%3A44%3A55&arch=x86_64&platform=efi');assert code==200
 assert call('clients')['items'][0]['platform']=='efi'
 token=re.search(rb'/s/([0-9a-f]{64})/',body)[1].decode()
 assert http('/s/'+token+'/menu.ipxe')[0]==200
 assert http('/s/'+('0'*64)+'/menu.ipxe')[0]==403
 assert http('/image/anything/images/install.img')[0]==403
 for value,expected in [('bytes=2-5',b'2345'),('bytes=-4',b'cdef'),('bytes=10-',b'abcdef')]:
  code,body,headers=http('/bin/undionly.kpxe',headers={'Range':value});assert code==206 and body==expected,(code,body)
 assert http('/bin/undionly.kpxe','HEAD')[1]==b''
 assert http('/bin/undionly.kpxe',headers={'Range':'bytes=30-50'})[0]==416
 assert http('/bin/../manifest.json')[0]==403
 cfg['clients'][0]['allowed']=False;raw(op='publish',body=cfg);assert http('/s/'+token+'/menu.ipxe')[0]==403
 db=sqlite3.connect(WORK/'config.db');db.execute('UPDATE dhcp_scope SET enabled=0');db.commit();db.close()
 assert http('/boot.ipxe')[0]==503
 raw(op='stop');assert call('logs')['total']>0
 result={'result':'PASS','checks_and_calls':count,'work':str(WORK),'scope':'real C/SQLite/loopback HTTP and dnsmasq syntax; fixture source acquisition, no real ISO mount, DHCP apply or client boot'}
 print(json.dumps(result));(WORK/'result.json').write_text(json.dumps(result,indent=2))
finally:
 p.stdin.close();p.wait(timeout=10)
