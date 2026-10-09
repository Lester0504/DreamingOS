#!/usr/bin/env python3
"""Real multi-network/static address preservation and rollback on isolated networks."""
import ipaddress
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
    name='dwrt-netcopy-'+uuid.uuid4().hex[:10];ids=set();networks=[];volumes=set()
    def docker(*args):return subprocess.check_output(['docker',*args],text=True).strip()
    def inspect(id):return json.loads(docker('inspect',id))[0]
    with tempfile.TemporaryDirectory(prefix='docker-netcopy-') as directory:
        temp=Path(directory);db=temp/'core.db';binary=compile_fixture(temp,db)
        def invoke(op,**kwargs):
            return json.loads(subprocess.check_output([str(binary),'workflow-write',json.dumps({'operation':op,'confirm':True,**kwargs})],text=True))
        def template(id):return json.loads(subprocess.check_output([str(binary),'workflow-read',json.dumps({'operation':'container_template','id':id})],text=True))['data']
        def run(op,t,cfg,success=True):
            job=invoke(op,id=t['id'],revision=t['revision'],config=cfg)['job_id'];deadline=time.monotonic()+50
            while time.monotonic()<deadline:
                with sqlite3.connect(db) as c:
                    row=c.execute('SELECT state,error,result_json FROM container_job WHERE id=?',(job,)).fetchone()
                result=json.loads(row[2])
                if result.get('container_id'):ids.add(result['container_id'])
                if row[0] not in ('queued','running'):
                    assert row[0]==('success' if success else 'failed'),row
                    return result
                time.sleep(.05)
            raise AssertionError('network replacement timeout')
        try:
            addresses=[]
            for i in range(2):
                net=name+'-'+str(i);docker('network','create',net);networks.append(net)
                subnet=json.loads(docker('network','inspect',net))[0]['IPAM']['Config'][0]['Subnet']
                addresses.append(str(ipaddress.ip_network(subnet).network_address+20))
            original=docker('create','--name',name,'--restart','unless-stopped','--network',networks[0],'--ip',addresses[0],'--network-alias','first-service','redis:8.4-alpine');ids.add(original)
            docker('network','connect','--ip',addresses[1],'--alias','second-service',networks[1],original)
            docker('start',original)
            t=template(original);cfg=json.loads(json.dumps(t['config']));cfg['name']=name+'-clone'
            cloned=run('container_clone',t,cfg)
            clone=inspect(cloned['container_id'])
            assert set(clone['NetworkSettings']['Networks'])==set(networks)
            for net in networks:assert not clone['NetworkSettings']['Networks'][net].get('IPAMConfig'),clone['NetworkSettings']['Networks'][net]
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen()
                cfg=json.loads(json.dumps(t['config']));cfg['ports']=[{'host_ip':'127.0.0.1','host_port':listener.getsockname()[1],'container_port':6379,'protocol':'tcp'}]
                failed=run('container_recreate',t,cfg,False)
                assert failed['rollback_succeeded'],failed
                old=inspect(original)
                assert old['State']['Running'] and old['HostConfig']['RestartPolicy']['Name']=='unless-stopped'
                for net,addr in zip(networks,addresses):assert old['NetworkSettings']['Networks'][net]['IPAddress']==addr
            t=template(original);cfg=t['config'];cfg['env']['NETCOPY_TEST']='retained'
            result=run('container_recreate',t,cfg)
            new=inspect(result['container_id']);old=inspect(original)
            assert new['State']['Running'] and new['Name']=='/'+name
            assert old['HostConfig']['RestartPolicy']['Name']=='no' and not old['State']['Running']
            for net,addr in zip(networks,addresses):assert new['NetworkSettings']['Networks'][net]['IPAddress']==addr
            assert 'second-service' in new['NetworkSettings']['Networks'][networks[1]]['Aliases']
            print('ok: two-network clone gets new addresses; failed replacement restores static addresses, aliases and restart policy; successful replacement keeps endpoints and disables backup auto-start')
        finally:
            for id in ids:
                if subprocess.run(['docker','inspect',id],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                    volumes.update(m['Name'] for m in inspect(id)['Mounts'] if m['Type']=='volume');docker('rm','-f',id)
            for net in networks:docker('network','rm',net)
            for volume in volumes:docker('volume','rm',volume)

if __name__=='__main__':main()
