#!/usr/bin/env python3
"""Interrupt only isolated Docker replacement workers and recover through production jobs."""
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time
import uuid
from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_WORKFLOW_REAL') != '1':
        raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 for isolated Docker integration')
    ids=set();volumes=set()
    with tempfile.TemporaryDirectory(prefix='docker-recovery-') as directory:
        temp=Path(directory);db=temp/'core.db';binary=compile_fixture(temp,db)
        def invoke(mode,arg):
            return json.loads(subprocess.check_output([str(binary),mode,json.dumps(arg) if isinstance(arg,dict) else arg],text=True))
        def row(job):
            with sqlite3.connect(db) as c:
                c.row_factory=sqlite3.Row
                value=dict(c.execute('SELECT * FROM container_job WHERE id=?',(job,)).fetchone())
            value['result']=json.loads(value['result_json'])
            if value['result'].get('container_id'):ids.add(value['result']['container_id'])
            return value
        def inspect(id):return json.loads(subprocess.check_output(['docker','inspect',id],text=True))[0]
        def wait(job,predicate,seconds=50):
            until=time.monotonic()+seconds
            while time.monotonic()<until:
                value=row(job)
                if predicate(value):return value
                time.sleep(.025)
            raise AssertionError(row(job))
        try:
            for mode in ('cancel','interrupt'):
                name='dwrt-recovery-'+uuid.uuid4().hex[:12]
                original=subprocess.check_output(['docker','create','--name',name,'--stop-signal','SIGSTOP','redis:8.4-alpine'],text=True).strip()
                ids.add(original)
                subprocess.run(['docker','start',original],check=True,stdout=subprocess.DEVNULL)
                t=invoke('workflow-read',{'operation':'container_template','id':original})['data']
                accepted=invoke('workflow-write',{'confirm':True,'operation':'container_recreate','id':original,'revision':t['revision'],'config':t['config']})
                job=accepted['job_id']
                at=wait(job,lambda r:r['result'].get('phase')=='stopping_original')
                assert at['worker_pid']>1
                time.sleep(.5)
                if mode=='cancel':
                    assert invoke('cancel',job)['state']=='cancelled'
                else:
                    os.kill(at['worker_pid'],signal.SIGKILL)
                # The Engine owns an already accepted stop request; allow its
                # fixed 10-second timeout to settle before testing recovery.
                time.sleep(11)
                if mode=='interrupt':
                    subprocess.run([str(binary),'reconcile'],check=True,stdout=subprocess.DEVNULL)
                failed=row(job)
                assert failed['state']==('cancelled' if mode=='cancel' else 'failed'),failed
                assert failed['result']['recoverable'] and not inspect(original)['State']['Running']
                recovery=invoke('workflow-write',{'operation':'container_recover','confirm':True,'id':job})
                restored=wait(recovery['job_id'],lambda r:r['state'] not in ('queued','running'))
                assert restored['state']=='success',restored
                assert restored['result']['rollback_succeeded'] and not row(job)['result']['recoverable']
                live=inspect(original)
                assert live['Name']=='/'+name and live['State']['Running'],live['State']
                if failed['result'].get('container_id'):
                    candidate=inspect(failed['result']['container_id'])
                    assert not candidate['State']['Running']
            print('ok: cancellation and killed-worker interruption retain source/candidate, reconcile reports failure, explicit recovery restores original name/running state and retains data')
        finally:
            for id in ids:
                if subprocess.run(['docker','inspect',id],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                    volumes.update(m['Name'] for m in inspect(id)['Mounts'] if m['Type']=='volume')
                    subprocess.run(['docker','rm','-f',id],check=True,stdout=subprocess.DEVNULL)
            for volume in volumes:subprocess.run(['docker','volume','rm',volume],check=True,stdout=subprocess.DEVNULL)

if __name__=='__main__':main()
