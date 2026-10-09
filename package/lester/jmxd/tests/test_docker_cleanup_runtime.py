#!/usr/bin/env python3
"""Cleanup preview/revalidation using only explicitly selected test-owned objects."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import uuid
from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_WORKFLOW_REAL')!='1':
        raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 for isolated Docker integration')
    prefix='dwrt-cleanup-'+uuid.uuid4().hex[:12]
    ids=set();network=prefix+'-net';volume=prefix+'-volume'
    def docker(*args):return subprocess.check_output(['docker',*args],text=True).strip()
    with tempfile.TemporaryDirectory(prefix='docker-cleanup-') as directory:
        temp=Path(directory);db=temp/'core.db';binary=compile_fixture(temp,db)
        def invoke(mode,op,**kw):
            return json.loads(subprocess.run([str(binary),mode,json.dumps({'operation':op,**kw})],stdout=subprocess.PIPE,text=True).stdout)
        def preview():return invoke('workflow-read','cleanup_preview')['data']
        def write(**kw):return invoke('workflow-write','cleanup_execute',confirm=True,**kw)
        try:
            docker('network','create',network);docker('volume','create',volume)
            initial=preview();assert initial['ok'],initial
            item=next(x for x in initial['items'] if x['kind']=='volume' and x['id']==volume)
            assert not item['selected']
            attached=docker('create','--network','none','--name',prefix+'-attached','--mount','type=volume,source='+volume+',target=/data','redis:8.4-alpine');ids.add(attached)
            conflict=write(items=[item]);assert conflict['error']=='cleanup_conflict',conflict
            assert docker('volume','inspect',volume)
            docker('rm',attached);ids.remove(attached)
            stopped=docker('create','--network','none','--name',prefix+'-stopped','--mount','type=volume,source='+volume+',target=/data','redis:8.4-alpine');ids.add(stopped)
            current=preview();target=next(x for x in current['items'] if x['kind']=='container' and x['id']==stopped)
            assert not any(x['kind']=='volume' and x['id']==volume for x in current['items'])
            docker('start',stopped)
            conflict=write(items=[target]);assert conflict['error']=='cleanup_conflict',conflict
            docker('stop',stopped)
            current=preview();target=next(x for x in current['items'] if x['kind']=='container' and x['id']==stopped)
            net=next(x for x in current['items'] if x['kind']=='network' and x['name']==network)
            # Docker's human-readable Status advances while a stopped object
            # remains unchanged; taking time to confirm must not invalidate it.
            time.sleep(2)
            accepted=write(items=[target,net]);assert accepted.get('job_id'),accepted
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                with sqlite3.connect(db) as conn:
                    row=conn.execute('SELECT state,error,result_json FROM container_job WHERE id=?',(accepted['job_id'],)).fetchone()
                if row[0] not in ('queued','running'):break
                time.sleep(.1)
            assert row[0]=='success',row
            result=json.loads(row[2]);assert len(result['items'])==2 and all(x['ok'] for x in result['items']),result
            assert result['reclaimed_bytes'] is None
            assert subprocess.run(['docker','inspect',stopped],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
            ids.remove(stopped)
            assert docker('volume','inspect',volume)
            print('ok: no volume preselection; new volume reference and restarted container reject stale cleanup; exact selected container/network deleted; unselected data volume retained; unknown reclaimed bytes remain null')
        finally:
            for cid in ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
