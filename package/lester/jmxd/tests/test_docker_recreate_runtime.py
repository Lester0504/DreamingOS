#!/usr/bin/env python3
"""Opt-in real clone/recreate and failed-switch recovery, isolated objects only."""
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid
from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_WORKFLOW_REAL')!='1':raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 for isolated Docker integration')
    name='dwrt-recreate-'+uuid.uuid4().hex[:12]
    subprocess.run(['docker','image','inspect','redis:8.4-alpine'],check=True,stdout=subprocess.DEVNULL)
    ids=set();volumes=set()
    with tempfile.TemporaryDirectory(prefix='docker-recreate-') as directory:
        temp=Path(directory);db=temp/'core.db';binary=compile_fixture(temp,db)
        def inspect(id):return json.loads(subprocess.check_output(['docker','inspect',id],text=True))[0]
        def read(id):
            return json.loads(subprocess.check_output([str(binary),'workflow-read',json.dumps({'operation':'container_template','id':id})],text=True))['data']
        def run(op,template,config,success=True):
            accepted=json.loads(subprocess.check_output([str(binary),'workflow-write',json.dumps({'confirm':True,'operation':op,'id':template['id'],'revision':template['revision'],'config':config})],text=True))
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                with sqlite3.connect(db) as conn:
                    conn.row_factory=sqlite3.Row
                    row=dict(conn.execute('SELECT * FROM container_job WHERE id=?',(accepted['job_id'],)).fetchone())
                result=json.loads(row['result_json'])
                if result.get('container_id'):ids.add(result['container_id'])
                if row['state'] not in ('queued','running'):
                    assert row['state']==('success' if success else 'failed'),row
                    assert 'recreate-test-secret' not in row['output']
                    return result
                time.sleep(.1)
            raise AssertionError('recreate job timeout')
        try:
            original=subprocess.check_output(['docker','create','--name',name,'-e','RECREATE_TEST=recreate-test-secret','redis:8.4-alpine'],text=True).strip();ids.add(original)
            volumes.update(m['Name'] for m in inspect(original)['Mounts'] if m['Type']=='volume')
            subprocess.run(['docker','start',original],check=True,stdout=subprocess.DEVNULL)
            template=read(original);assert template['config']['env']['RECREATE_TEST']=='recreate-test-secret'
            clone=json.loads(json.dumps(template['config']));clone['name']=name+'-clone';clone['start_after_create']=False
            result=run('container_clone',template,clone)
            assert not inspect(result['container_id'])['State']['Running'] and inspect(original)['State']['Running']
            # Force replacement start to fail after the original is stopped.
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen()
                changed=json.loads(json.dumps(template['config']))
                changed['ports']=[{'host_ip':'127.0.0.1','host_port':listener.getsockname()[1],'container_port':6379,'protocol':'tcp'}]
                failed=run('container_recreate',template,changed,False)
                assert failed['rollback_succeeded'] and failed['phase']=='original_restored',failed
                restored=inspect(original);assert restored['State']['Running'] and restored['Name']=='/'+name
            template=read(original);changed=template['config'];changed['env']['RECREATE_TEST']='changed-private-value'
            result=run('container_recreate',template,changed)
            replacement=inspect(result['container_id']);retained=inspect(original)
            assert replacement['State']['Running'] and replacement['Name']=='/'+name
            assert not retained['State']['Running'] and retained['Name'].startswith('/'+name+'-backup-')
            assert 'RECREATE_TEST=changed-private-value' in replacement['Config']['Env']
            with sqlite3.connect(db) as conn:
                assert 'recreate-test-secret' not in '\n'.join(conn.iterdump())
            print('ok: real clone keeps source/data, stopped clone, failed start restores original name/running state, verified replacement retains backup, encrypted requests')
        finally:
            for id in ids:
                if subprocess.run(['docker','inspect',id],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                    volumes.update(m['Name'] for m in inspect(id)['Mounts'] if m['Type']=='volume')
                    subprocess.run(['docker','rm','-f',id],check=True,stdout=subprocess.DEVNULL)
            for volume in volumes:subprocess.run(['docker','volume','rm',volume],check=True,stdout=subprocess.DEVNULL)

if __name__=='__main__':main()
