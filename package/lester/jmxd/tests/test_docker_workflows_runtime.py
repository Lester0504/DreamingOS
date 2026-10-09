#!/usr/bin/env python3
"""Opt-in Docker integration in a temporary DB, using only a generated project.

DOCKER_WORKFLOW_REAL=1 python3 tests/test_docker_workflows_runtime.py
Requires an existing redis:8.4-alpine image; never pulls, publishes ports or
restarts the host engine. Project teardown preserves named volumes; the test
then explicitly removes only its own generated volume after asserting this.
"""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time

from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_WORKFLOW_REAL') != '1':
        raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 to authorize the isolated Docker integration test')
    subprocess.run(['docker','image','inspect','redis:8.4-alpine'],check=True,stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix='docker-workflows-') as directory:
        temp=Path(directory);db=temp/'core.db';binary=compile_fixture(temp,db)
        project=None;volume=None
        def invoke(mode,payload,success=True):
            result=subprocess.run([str(binary),mode,json.dumps(payload)],capture_output=True,text=True)
            data=json.loads(result.stdout)
            if success: assert result.returncode==0 and data.get('ok',True),data
            return data
        def write(op,**kwargs):return invoke('workflow-write',{'operation':op,'confirm':True,**kwargs})
        def read(op,**kwargs):return invoke('workflow-read',{'operation':op,**kwargs})['data']
        def job(accepted):
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                with sqlite3.connect(db) as conn:
                    conn.row_factory=sqlite3.Row
                    row=dict(conn.execute('SELECT * FROM container_job WHERE id=?',(accepted['job_id'],)).fetchone())
                if row['state'] not in ('queued','running'):
                    assert row['state']=='success',row
                    return row
                time.sleep(.15)
            raise AssertionError('job timed out')
        yaml='''x-preserved: {marker: untouched}
services:
  first:
    image: redis:8.4-alpine
    environment:
      WORKFLOW_SECRET: fixture-secret-keep-private
    volumes: ["data:/data"]
  second:
    image: redis:8.4-alpine
volumes:
  data: {}
'''
        try:
            saved=write('compose_save',name='workflow-test',yaml=yaml)
            project=saved['project']['id'];volume=project+'_data'
            assert saved['persisted'] and not saved['applied']
            assert read('compose_config',id=project)['yaml']==yaml
            assert subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).strip()==''
            bad=invoke('workflow-write',{'operation':'compose_save','confirm':True,'id':project,'revision':99,'name':'workflow-test','yaml':yaml},False)
            assert bad['error']=='revision_conflict',bad
            bad=invoke('workflow-write',{'operation':'compose_save','confirm':True,'name':'bad-yaml','yaml':'services: ['},False)
            assert bad['error']=='invalid_compose_yaml',bad
            with sqlite3.connect(db) as conn:
                assert conn.execute('SELECT COUNT(*) FROM docker_compose_project').fetchone()[0]==1
                dump='\n'.join(conn.iterdump());assert 'fixture-secret-keep-private' not in dump
            job(write('up',id=project,revision=1))
            ids=subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project='+project],text=True).split()
            assert len(ids)==2,ids
            listing=read('compose_list');item=next(p for p in listing['projects'] if p['id']==project)
            assert len(item['services'])==2 and item['managed'],item
            assert read('compose_logs',id=project)['ok']
            yaml2=yaml.replace('untouched','still-preserved')
            saved=write('compose_save',id=project,revision=1,name='workflow-test',yaml=yaml2)
            assert saved['project']['revision']==2 and read('compose_config',id=project)['yaml']==yaml2
            job(write('recreate',id=project,revision=2))
            job(write('stop',id=project,revision=2))
            assert subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project='+project],text=True).strip()==''
            job(write('delete',id=project,revision=2))
            subprocess.run(['docker','volume','inspect',volume],check=True,stdout=subprocess.DEVNULL)
            assert subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).strip()==''
            assert not any(p['id']==project for p in read('compose_list')['projects'])
            with sqlite3.connect(db) as conn:
                assert all('fixture-secret-keep-private' not in row[0] for row in conn.execute('SELECT output FROM container_job'))
            print('ok: real two-service save/no-start, encrypted YAML preservation, revision conflict, invalid YAML, up, logs, edit/recreate, stop, delete preserving data')
        finally:
            if project:
                ids=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).split()
                if ids:subprocess.run(['docker','rm','-f',*ids],check=True,stdout=subprocess.DEVNULL)
                networks=subprocess.check_output(['docker','network','ls','-q','--filter','label=com.docker.compose.project='+project],text=True).split()
                if networks:subprocess.run(['docker','network','rm',*networks],check=True,stdout=subprocess.DEVNULL)
            if volume and subprocess.run(['docker','volume','inspect',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                subprocess.run(['docker','volume','rm',volume],check=True,stdout=subprocess.DEVNULL)

if __name__=='__main__':main()
