#!/usr/bin/env python3
"""Real webd HTTP storage gates in a caller-created private mount namespace.

Stage this script plus bin/{webd,fixture,ubusd}, runtime libraries, etc/run/tmp/logs
under one /tmp bundle. Run after binding its etc, run, tmp over the corresponding
runtime directories; this script refuses a non-isolated config directory.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

PORT=19129

def main():
    assert os.stat('etc').st_ino == os.stat('/etc/dreamingwrt').st_ino, 'private config mount required'
    assert os.stat('run').st_ino == os.stat('/run').st_ino, 'private run mount required'
    assert os.stat('tmp').st_ino == os.stat('/tmp').st_ino, 'private tmp mount required'
    env=dict(os.environ, LD_LIBRARY_PATH='./lib', WEBD_SETUP_TEST_FIXTURE_READY='/tmp/fixture.ready')
    procs=[]; checks=[]
    def start(name,args=()):
        p=subprocess.Popen(['./lib/ld-linux-x86-64.so.2','--library-path','./lib',f'./bin/{name}',*args],env=env,stdout=open(f'logs/{name}.log','w'),stderr=subprocess.STDOUT)
        procs.append(p);return p
    def request(method,path,cookie='',body=None,site='same-origin',forwarded='192.0.2.10',token=''):
        c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=10)
        h={'Content-Type':'application/json','Sec-Fetch-Site':site,'X-Forwarded-For':forwarded}
        if cookie:h['Cookie']=cookie
        if token:h['Authorization']='Bearer '+token
        c.request(method,path,body=json.dumps(body) if body is not None else None,headers=h)
        r=c.getresponse();v=r.read();result=(r.status,dict(r.getheaders()),json.loads(v));c.close();return result
    def check(name,status,actual):
        assert actual[0]==status,(name,actual)
        checks.append(name)
        return actual[2]
    try:
        start('ubusd')
        for _ in range(100):
            if Path('/run/ubus/ubus.sock').exists():break
            time.sleep(.05)
        start('fixture')
        for _ in range(100):
            if Path('/tmp/fixture.ready').exists():break
            time.sleep(.05)
        start('webd',(str(PORT),'127.0.0.1'))
        for _ in range(100):
            try:request('GET','/api/v1/health');break
            except OSError:time.sleep(.1)
        check('anonymous storage GET needs setup session',401,request('GET','/api/setup/storage'))
        check('anonymous storage POST needs setup session',401,request('POST','/api/setup/storage',body={}))
        init=request('POST','/api/setup/start',body={});check('start creates setup cookie',200,init)
        cookie=init[1]['Set-Cookie'].split(';')[0]
        data=check('setup cookie reads storage',200,request('GET','/api/setup/storage',cookie))['data']
        assert data['contract_version']=='data-storage.v1' and not data['default']['configured']
        check('setup invalid selection reaches validation',400,request('POST','/api/setup/storage',cookie,{}))
        check('cross-site setup POST is refused',403,request('POST','/api/setup/storage',cookie,{},site='cross-site'))
        check('different IP cannot reuse setup session',401,request('GET','/api/setup/storage',cookie,forwarded='192.0.2.11'))
        salt=bytes(range(16));password='StorageFixtureOnly26';encoded='pbkdf2-sha256$100000$'+salt.hex()+'$'+hashlib.pbkdf2_hmac('sha256',password.encode(),salt,100000,32).hex()
        with sqlite3.connect('/etc/dreamingwrt/config.db') as db:
            for name,role in [('storage-admin','admin'),('storage-viewer','viewer')]:
                db.execute('INSERT INTO web_users(username,password_hash,status,role,permissions_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(name,encoded,'enabled',role,'[]',int(time.time()),int(time.time())))
        check('setup cookie remains valid after account creation',200,request('GET','/api/setup/storage',cookie))
        check('setup POST still reaches validation after account creation',400,request('POST','/api/setup/storage',cookie,{}))
        check('anonymous storage closed after account exists',409,request('GET','/api/setup/storage'))
        tokens={}
        for name in ['storage-admin','storage-viewer']:
            login=check(name+' login',200,request('POST','/api/v1/session/login',body={'username':name,'password':password}))
            tokens[name]=login.get('access_token') or login['data']['access_token']
        viewer=tokens['storage-viewer'];admin=tokens['storage-admin']
        check('authenticated viewer GET',200,request('GET','/api/v1/setup/storage',token=viewer))
        check('authenticated viewer POST refused',403,request('POST','/api/v1/setup/storage',body={},token=viewer))
        check('compatibility alias viewer POST refused',403,request('POST','/api/setup/storage',body={},token=viewer))
        check('admin POST reaches input validation',400,request('POST','/api/v1/setup/storage',body={},token=admin))
        check('invalid bearer does not fall back to setup cookie',401,request('POST','/api/setup/storage',cookie,{},token='forged'))
        check('finish in isolated fixture',200,request('POST','/api/setup/finish',cookie,{}))
        check('finished setup closes public GET',409,request('GET','/api/setup/storage',cookie))
        check('finished setup closes public POST',409,request('POST','/api/setup/storage',cookie,{}))
        check('initialized device authenticated GET remains available',200,request('GET','/api/v1/setup/storage',token=viewer))
        check('initialized device admin POST remains validated',400,request('POST','/api/v1/setup/storage',body={},token=admin))
        assert not Path('/etc/dreamingwrt/data-storage.json').exists()
        print(json.dumps({'result':'PASS','count':len(checks),'checks':checks},indent=2))
    finally:
        for p in reversed(procs):p.terminate()
        for p in reversed(procs):
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
if __name__=='__main__':main()
