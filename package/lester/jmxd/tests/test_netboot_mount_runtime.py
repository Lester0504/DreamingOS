#!/usr/bin/env python3
"""Compile as lester; exercise disposable ISO mounts in a private mount namespace.

The privileged runner and its loader/libraries live only in /tmp. No root process
reads the OpenWrt tree. Storage acquisition is a fixture; loop/mount/source identity,
HTTP streaming and client policy run through the real Netboot C implementation.
The ISO contains test bytes, not a bootable installer. No DHCP or production writes.
"""
import json, os, re, shutil, sqlite3, subprocess, tempfile
from pathlib import Path

RUNNER = r'''
import json,os,re,socket,sqlite3,subprocess,sys
from pathlib import Path
from http.client import HTTPConnection
w=Path(sys.argv[1]); subprocess.run(['mount','-t','tmpfs','tmpfs','/run'],check=True)
p=subprocess.Popen([str(w/'libs/ld-linux-x86-64.so.2'),'--library-path',str(w/'libs'),str(w/'driver')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
count=0
def raw(**data):
 global count
 p.stdin.write(json.dumps(data)+'\n');p.stdin.flush();line=p.stdout.readline();assert line,'driver exited';count+=1;return json.loads(line)
def call(resource,method='GET',body=None,id='',action=''):
 r=raw(method=method,resource=resource,body=body or {},id=id,action=action);assert r['http_status']==200,r;return r['data']
def write(resource,body=None,method='POST',**kw):
 return call(resource,method,{'confirm':True,'expected_revision':call('settings')['revision'],**(body or {})},**kw)
def request(path,method='GET',body=None,headers=None):
 global count
 c=HTTPConnection('127.0.0.1',port,timeout=5);c.request(method,path,body,headers or {});r=c.getresponse();data=r.read();h=dict(r.getheaders());c.close();count+=1;return r.status,data,h
ids=[]
try:
 image=write('images',{'name':'Real loop fixture','path':str(w/'source with spaces.iso')})['image'];ids.append(image['id'])
 assert image['image_status']=='ready' and image['boot_verified'] is False,image
 mount=w/'run/images'/image['id'];assert mount.is_mount()
 assert (mount/'images/pxeboot/vmlinuz').read_bytes()==b'kernel-fixture'
 try:(mount/'write-test').write_bytes(b'no');raise AssertionError('mount writable')
 except OSError as e:assert e.errno==30,e
 print('PASS real readonly ISO mount and space-containing source path',flush=True)
 sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
 cfg={'revision':1,'settings':{'enabled':True,'interface_ids':['testlan'],'http_port':port,'menu_timeout':0,'allow_unknown':False},'clients':[],'images':[image]}
 lan={'id':'testlan','ipv4':'127.0.0.1','device':'lo','prefix':8}
 assert raw(op='http',body=cfg,interface=lan)['data']['rc']==0
 payload='mac=02%3A00%3A00%3A00%3A00%3A01&arch=x86_64'
 assert request('/menu.ipxe','POST',payload)[0]==403
 cfg['clients']=[{'id':'02:00:00:00:00:01','allowed':True}];raw(op='publish',body=cfg)
 code,menu,_=request('/menu.ipxe','POST',payload);assert code==200
 token=re.search(rb'/s/([0-9a-f]{64})/',menu)[1].decode()
 base='/s/'+token+'/image/'+image['id']
 assert request('/s/'+token+'/boot/'+image['id']+'.ipxe')[0]==200
 assert request(base+'/.treeinfo')[0]==200
 code,data,h=request(base+'/images/pxeboot/vmlinuz',headers={'Range':'bytes=0-5'});assert code==206 and data==b'kernel'
 assert request(base+'/images/install.img','HEAD')[2]['Content-Length']=='1048576'
 assert request(base+'/%2e%2e/config.db')[0]==404
 cfg['images'][0]['enabled']=False;raw(op='publish',body=cfg);assert request(base+'/.treeinfo')[0]==403
 cfg['images'][0]['enabled']=True;cfg['clients'][0]['allowed']=False;raw(op='publish',body=cfg);assert request(base+'/.treeinfo')[0]==403
 cfg['clients'][0]['allowed']=True;raw(op='publish',body=cfg)
 print('PASS menu, boot script, protected ISO GET/HEAD/Range, disabled-image and client revocation',flush=True)
 os.replace(w/'replacement.iso',w/'source with spaces.iso')
 assert call('images')['items'][0]['error']=='source_changed'
 assert request(base+'/.treeinfo')[0]==403
 image=write('images',id=image['id'],action='remount')['image'];assert image['image_status']=='ready',image
 print('PASS replaced source invalidates serving; explicit remount establishes new identity',flush=True)
 # Stop transfers, then delete only registration and the owned mount.
 raw(op='stop');write('images',method='DELETE',id=image['id']);ids.clear()
 assert (w/'source with spaces.iso').exists() and not mount.exists()
 print('PASS delete unmounts owned image and preserves original ISO',flush=True)
 (w/'result.json').write_text(json.dumps({'result':'PASS','checks_and_calls':count,'work':str(w),'scope':'real readonly loop/ISO + protected HTTP; fixture storage and ISO bytes; no DHCP/client installer'},indent=2))
finally:
 raw(op='stop')
 for id in ids:
  try:write('images',method='DELETE',id=id)
  except Exception as e:print('cleanup:',e,file=sys.stderr)
 p.stdin.close();p.wait(timeout=10)
'''

def main():
    assert os.geteuid()!=0, 'Compile as lester, never root in the source tree'
    src=Path(__file__).resolve().parents[1]/'src';root=src.parents[3]
    tc=root/'staging_dir/toolchain-x86_64_gcc-16.1.0_glibc';st=root/'staging_dir/target-x86_64_glibc/usr'
    work=Path(tempfile.mkdtemp(prefix='netboot-mount-',dir='/tmp'));boot=work/'boot';boot.mkdir()
    for name in ['undionly.kpxe','snponly.efi']:(boot/name).write_bytes(b'fixture-not-boot-firmware')
    (boot/'manifest.json').write_text(json.dumps({n:{'version':'fixture','source':'test','license':'test'} for n in ['undionly.kpxe','snponly.efi']}))
    iso=work/'contents';(iso/'images/pxeboot').mkdir(parents=True)
    (iso/'.treeinfo').write_text('[general]\nfamily=Rocky Linux\nversion=9.6\narch=x86_64\n')
    (iso/'images/pxeboot/vmlinuz').write_bytes(b'kernel-fixture');(iso/'images/pxeboot/initrd.img').write_bytes(b'initrd-fixture')
    (iso/'images/install.img').write_bytes(b'x'*1048576)
    with (work/'iso.log').open('w') as log:subprocess.run(['xorriso','-as','mkisofs','-R','-J','-o',str(work/'source with spaces.iso'),str(iso)],check=True,stdout=log,stderr=log)
    shutil.copy2(work/'source with spaces.iso',work/'replacement.iso')
    with sqlite3.connect(work/'config.db') as db:
        db.executescript("CREATE TABLE lan(id TEXT,name TEXT,device TEXT,enabled INT,updated_at INT); CREATE TABLE lan_address(lan_id TEXT,ip TEXT,prefix INT,is_primary INT); CREATE TABLE dhcp_scope(id TEXT,lan_id TEXT,enabled INT,pool_start TEXT,pool_end TEXT); CREATE TABLE dhcp_option(scope_id TEXT,code TEXT); INSERT INTO lan VALUES('testlan','Loopback','lo',1,1); INSERT INTO lan_address VALUES('testlan','127.0.0.1',8,1); INSERT INTO dhcp_scope VALUES('scope','testlan',1,'100','200');")
    args=[str(tc/'bin/x86_64-openwrt-linux-gnu-gcc'),'-O1','-I'+str(src),'-I'+str(st/'include')]
    for key,value in {'NB_DB_PATH':work/'config.db','NB_RUN_DIR':work/'run','NB_BOOT_DIR':boot,'NB_TEST_SOURCE_ROOT':work}.items():args.append(f'-D{key}="{value}"')
    args += [str(p) for p in (src/'netboot').glob('*.c')]+[str(Path(__file__).with_name('netboot_runtime_driver.c')),'-L'+str(st/'lib'),'-Wl,-rpath-link,'+str(st/'lib'),'-ljson-c','-lsqlite3','-luci','-lubox','-lcrypto','-lpthread','-o',str(work/'driver')]
    with (work/'compile.log').open('w') as log:subprocess.run(args,check=True,stdout=log,stderr=log)
    libs=work/'libs';libs.mkdir();queue=[work/'driver'];copied=set()
    while queue:
        obj=queue.pop();dynamic=subprocess.check_output(['readelf','-d',str(obj)],text=True)
        for name in re.findall(r'\(NEEDED\).*\[(.*?)\]',dynamic):
            if name in copied:continue
            source=next((d/name for d in [st/'lib',tc/'lib',tc/'usr/lib'] if (d/name).exists()),None)
            if source is None:raise RuntimeError('dependency missing '+name)
            shutil.copy2(source.resolve(),libs/name);copied.add(name);queue.append(libs/name)
    shutil.copy2((tc/'lib/ld-linux-x86-64.so.2').resolve(),libs/'ld-linux-x86-64.so.2')
    (work/'runner.py').write_text(RUNNER)
    print('WORK',work,flush=True)
    subprocess.run(['sudo','-n','unshare','--mount','--propagation','private','python3',str(work/'runner.py'),str(work)],cwd=work,check=True)
    print((work/'result.json').read_text())

if __name__=='__main__':main()
