#!/usr/bin/env python3
"""Real SQLite + iptvd IPC + API adapter. Only the supplied /tmp fixture is mutated."""
import argparse,concurrent.futures,json,sqlite3,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--directory',required=True);p.add_argument('--daemon',required=True);p.add_argument('--http-fixture',required=True);a=p.parse_args()
root=Path(a.directory);assert str(root).startswith('/tmp/');root.mkdir(parents=True,exist_ok=True)
db=root/'config.db';checks=[];daemon=None

def sql(query,args=()):
    with sqlite3.connect(db) as c:return c.execute(query,args).fetchall()
def start():
    global daemon
    (root/'iptv.sock').unlink(missing_ok=True)
    daemon=subprocess.Popen([a.daemon],stdout=open(root/'daemon.log','a'),stderr=subprocess.STDOUT)
    for _ in range(100):
        if (root/'iptv.sock').exists():return
        assert daemon.poll() is None,'daemon exited';time.sleep(.05)
    raise AssertionError('socket unavailable')
def req(path,body=None,who='web-a',prefix='view',method=None):
    call=[a.http_fixture,method or ('POST' if body is not None else 'GET'),'/api/v1/iptv/'+prefix+'/'+path,who,json.dumps(body or {})]
    return json.loads(subprocess.check_output(call,text=True))
def ok(r,label,status=200):
    assert r['status']==status,(label,r);checks.append(label);return r['body'].get('data',{})
def fav(value,rev,key):return {'favorite':value,'if_revision':rev,'idempotency_key':key}
def watch(pos,rev,key,action='watch'):return {'position_seconds':pos,'if_revision':rev,'idempotency_key':key,'action':action}
def record(kind,id,body):sql('INSERT OR REPLACE INTO iptv_record VALUES(?,?,1,?)',(kind,id,json.dumps({'id':id,**body})))
for suffix in ['','-wal','-shm']:Path(str(db)+suffix).unlink(missing_ok=True)
try:
    start()
    with sqlite3.connect(db) as c:
        c.executescript("""CREATE TABLE web_users(username,status);INSERT INTO web_users VALUES('alice','enabled'),('bob','enabled');
        CREATE TABLE web_sessions(token,username,revoked,type,expires_at);INSERT INTO web_sessions VALUES('web-a','alice',0,'access',9999999999),('web-b','bob',0,'access',9999999999);
        CREATE TABLE tvhome_settings(id,pin_required,modules_json,media_principal_id);INSERT INTO tvhome_settings VALUES(1,0,'{"live":true}','web:alice');
        CREATE TABLE tvhome_terminal(id,media_principal_id);INSERT INTO tvhome_terminal VALUES('tv-a','');
        CREATE TABLE tvhome_principal(id,revoked,terminal_id);INSERT INTO tvhome_principal VALUES('principal-a',0,'tv-a');
        CREATE TABLE tvhome_session(token,revoked,principal_id,terminal_id,expires_at_ms);INSERT INTO tvhome_session VALUES('tv-a-token',0,'principal-a','tv-a',9999999999000);""")
    record('settings','main',{'enabled':True})
    for name in ['alice','bob']:record('viewers',name,{'principal_id':'web:'+name,'enabled':True,'all_categories':True})
    for id in ['ch-a','ch-b']:record('channels',id,{'enabled':True,'name':id,'mode':'external','source_url':'http://127.0.0.1/unused','category_id':''})
    for id,duration in [('rec-short',240),('rec-long',7200),('rec-next',240)]:record('recordings',id,{'state':'ready','channel_id':'ch-a','start':100,'end':100+duration})
    assert ok(req('favorites'),'empty favorites')['channel_ids']==[]
    first=ok(req('favorites/ch-a',fav(True,0,'add-a')),'web favorite')
    shared=ok(req('favorites',who='tv-a-token',prefix='client'),'TV shares subject');assert shared==first
    assert ok(req('favorites',who='web-b'),'other subject isolated')['channel_ids']==[]
    repeated=ok(req('favorites/ch-a',fav(True,0,'add-a'),who='tv-a-token',prefix='client'),'cross-session idempotency');assert repeated==first
    ok(req('favorites/ch-a',fav(False,0,'add-a')),'key reuse rejected',409)
    conflict=ok(req('favorites/ch-b',fav(True,0,'stale')),'canonical survives IPC/API 409',409);assert conflict['canonical']==first
    with concurrent.futures.ThreadPoolExecutor() as pool:
        results=list(pool.map(lambda x:req('favorites/'+x,fav(True,1,'race-'+x)),['ch-a','ch-b']))
    assert sorted(x['status'] for x in results)==[200,409];checks.append('concurrent writes only one wins')
    current=ok(req('favorites'),'winner canonical');assert current['revision']==2
    ok(req('favorites/ch-a',{**fav(True,2,'fake'),'principal':'web:bob'}),'caller cannot choose subject',400)
    ok(req('favorites/ch-a',fav(True,2,'get-write'),method='GET'),'GET cannot mutate',405)
    zero=ok(req('progress/rec-short'),'initial recording progress');assert zero['duration_seconds']==240 and zero['episode_id']=='rec-short'
    short=ok(req('progress/rec-short',watch(160,0,'short-160')),'short film not finished');assert not short['finished'] and short['position_seconds']==160
    assert ok(req('progress/rec-short',who='tv-a-token',prefix='client'),'TV resumes phone recording')==short
    long=ok(req('progress/rec-long',watch(7020,0,'long-7020')),'long film finished server rule');assert long['finished'] and long['duration_seconds']==7200
    assert ok(req('progress/rec-next'),'next recording fresh')['position_seconds']==0
    restart=ok(req('progress/rec-long',watch(0,1,'restart','restart')),'manual restart distinct');assert not restart['finished'] and restart['last_action']=='restart'
    ok(req('progress/rec-long',watch(10,1,'late')),'late progress cannot overwrite restart',409)
    assert ok(req('progress/rec-long'),'restart preserved')['position_seconds']==0
    ok(req('progress/ch-a',watch(20,0,'live')),'live cannot be marked finished',404)
    ok(req('progress/rec-long',{**watch(10,2,'duration'),'duration_seconds':1}),'client duration rejected',400)
    ok(req('progress/rec-long',watch(-1,2,'negative')),'negative progress rejected',400)
    sql("UPDATE web_sessions SET revoked=1 WHERE token='web-a'");ok(req('favorites'),'revoked parent rejected',401);sql("UPDATE web_sessions SET revoked=0 WHERE token='web-a'")
    sql('UPDATE tvhome_settings SET pin_required=1');ok(req('favorites',who='tv-a-token',prefix='client'),'PIN still denies',401);sql('UPDATE tvhome_settings SET pin_required=0')
    record('channels','ch-a',{'enabled':False,'name':'ch-a'})
    assert 'ch-a' not in ok(req('favorites'),'revoked channel absent')['channel_ids']
    ok(req('favorites/ch-a',fav(True,2,'denied')),'revoked favorite denied',403)
    ok(req('progress/rec-short'),'revoked channel progress denied',403)
    record('channels','ch-a',{'enabled':True,'name':'ch-a','mode':'external','source_url':'http://127.0.0.1/unused'})
    daemon.terminate();daemon.wait(timeout=10);start()
    assert ok(req('progress/rec-short'),'progress survives restart')['position_seconds']==160
    assert ok(req('favorites'),'favorite version survives restart')['revision']==2
    assert sql('SELECT count(*) FROM iptv_subject_request WHERE idempotency_key=?',('add-a',))[0][0]==1;checks.append('exactly one durable idempotency receipt')
    print(json.dumps({'passed':len(checks),'checks':checks},ensure_ascii=False,indent=2))
finally:
    if daemon and daemon.poll() is None:daemon.terminate();daemon.wait(timeout=10)
