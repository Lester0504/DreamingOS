#!/usr/bin/env python3
"""Real local Compose build/file references; touches only a unique temporary project."""
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
    if os.environ.get('DOCKER_WORKFLOW_REAL') != '1':
        raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 for isolated Docker integration')
    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True).strip()
    docker('image', 'inspect', 'redis:8.4-alpine')
    image = 'dwrt-directory-' + uuid.uuid4().hex[:12] + ':local'
    project = None
    volumes = set()
    with tempfile.TemporaryDirectory(prefix='docker-directory-') as directory:
        temp = Path(directory)
        os.environ['DOCKER_WORKFLOW_TEST_ROOT'] = str(temp)
        work = temp / 'project'
        work.mkdir()
        (work / 'data').mkdir()
        (work / 'data/keep.txt').write_text('persistent-data')
        (work / 'Dockerfile').write_text('FROM redis:8.4-alpine\nCOPY marker.txt /directory-marker.txt\n')
        (work / 'marker.txt').write_text('built-from-project-directory')
        (work / 'runtime.env').write_text('DIRECTORY_ENV=directory-env-private\n')
        (work / 'app.conf').write_text('config-from-project-directory')
        (work / 'secret.txt').write_text('directory-file-private')
        db = temp / 'core.db'
        binary = compile_fixture(temp, db)
        def invoke(mode, payload):
            return json.loads(subprocess.run([str(binary), mode, json.dumps(payload)], stdout=subprocess.PIPE, text=True).stdout)
        def write(op, **kwargs):
            return invoke('workflow-write', {'operation':op, 'confirm':True, **kwargs})
        def read(op, **kwargs):
            return invoke('workflow-read', {'operation':op, **kwargs})['data']
        def job(accepted):
            assert accepted.get('job_id'), accepted
            until = time.monotonic() + 90
            while time.monotonic() < until:
                with sqlite3.connect(db) as c:
                    row = c.execute('SELECT state,error,result_json,output FROM container_job WHERE id=?', (accepted['job_id'],)).fetchone()
                if row[0] not in ('queued','running'):
                    assert row[0] == 'success', row
                    assert 'directory-env-private' not in row[3] and 'directory-file-private' not in row[3]
                    return row
                time.sleep(.1)
            raise AssertionError('compose directory job timed out')
        yaml = f'''x-preserved: keep-original
services:
  app:
    image: {image}
    build: .
    env_file: [./runtime.env]
    environment:
      LITERAL_VALUE: "cost$$value"
    volumes: ["./data:/data"]
    configs: [appconfig]
    secrets: [appsecret]
  peer:
    image: redis:8.4-alpine
configs:
  appconfig:
    file: ./app.conf
secrets:
  appsecret:
    file: ./secret.txt
'''
        try:
            saved = write('compose_save', name='directory-project', yaml=yaml, directory_ref={'root_id':'', 'path':str(work)})
            assert saved.get('persisted') and not saved['applied'], saved
            project = saved['project']['id']
            assert read('compose_config', id=project)['yaml'] == yaml
            assert saved['project']['directory_ref']['inode'] == work.stat().st_ino
            assert not docker('ps', '-aq', '--filter', 'label=com.docker.compose.project='+project)
            job(write('build', id=project, revision=1))
            assert not docker('ps', '-aq', '--filter', 'label=com.docker.compose.project='+project)
            job(write('up', id=project, revision=1))
            ids = docker('ps', '-q', '--filter', 'label=com.docker.compose.project='+project).split()
            assert len(ids) == 2, ids
            for cid in ids:
                volumes.update(m['Name'] for m in json.loads(docker('inspect',cid))[0]['Mounts'] if m['Type']=='volume')
            app = docker('ps', '-q', '--filter', 'label=com.docker.compose.project='+project, '--filter', 'label=com.docker.compose.service=app')
            assert docker('exec', app, 'cat', '/directory-marker.txt') == 'built-from-project-directory'
            assert docker('exec', app, 'printenv', 'DIRECTORY_ENV') == 'directory-env-private'
            assert docker('exec', app, 'printenv', 'LITERAL_VALUE') == 'cost$value'
            assert docker('exec', app, 'cat', '/appconfig') == 'config-from-project-directory'
            assert docker('exec', app, 'cat', '/run/secrets/appsecret') == 'directory-file-private'
            assert docker('exec', app, 'cat', '/data/keep.txt') == 'persistent-data'
            saved2 = write('compose_save', id=project, revision=1, name='directory-project', yaml=yaml+'\n')
            assert saved2['project']['directory_ref'] == saved['project']['directory_ref']
            job(write('delete', id=project, revision=2))
            assert (work / 'data/keep.txt').read_text() == 'persistent-data'
            bad = write('compose_validate', yaml=yaml, directory_ref={'root_id':'','path':str(work),'inode':work.stat().st_ino+1})
            assert bad['error'] == 'project_directory_changed', bad
            print('ok: project directory identity, raw YAML preservation, local Dockerfile build without start, two-service apply with env/config/secret/bind files, edit retains directory, delete retains data, stale directory rejected')
        finally:
            if project:
                ids = docker('ps','-aq','--filter','label=com.docker.compose.project='+project).split()
                if ids: docker('rm','-f',*ids)
                networks = docker('network','ls','-q','--filter','label=com.docker.compose.project='+project).split()
                if networks: docker('network','rm',*networks)
            for volume in volumes:
                subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    main()
