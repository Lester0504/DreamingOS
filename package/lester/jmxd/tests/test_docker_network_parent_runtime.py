#!/usr/bin/env python3
"""Real macvlan/ipvlan on a disposable, unnumbered internal Docker bridge.

The test parent is created by Docker with gateway_mode_ipv4=isolated, has no external
ports or host routes, and is removed after its test containers and networks.
No physical parent, existing network, host address or daemon config is changed.
"""
import json
import os
from pathlib import Path
import sqlite3
import time
import subprocess
import tempfile
import uuid

from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_NETWORK_PARENT_REAL') != '1':
        raise SystemExit('Set DOCKER_NETWORK_PARENT_REAL=1 for the isolated network test')
    suffix = uuid.uuid4().hex[:10]
    prefix, parent = 'dwrt-parent-' + suffix, 'dwp' + suffix
    owned, containers, helper = [], [], None

    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True).strip()

    with tempfile.TemporaryDirectory(prefix='docker-parent-') as directory:
        root = Path(directory)
        binary = compile_fixture(root, root / 'core.db')

        def invoke(mode, payload, env=None):
            raw = subprocess.run([str(binary), mode, json.dumps(payload)], env=env,
                                 text=True, stdout=subprocess.PIPE, timeout=45).stdout
            obj = json.loads(raw)
            return obj.get('data', obj)

        def plan(payload, env=None):
            return invoke('workflow-read', dict(payload, operation='network_validate'), env)

        try:
            owned.append(docker('network', 'create', '--internal', '--opt', 'com.docker.network.bridge.gateway_mode_ipv4=isolated',
                                '--opt', 'com.docker.network.bridge.name=' + parent, prefix))
            helper = docker('run', '-d', '--network', prefix, '--mount', 'type=tmpfs,destination=/data', 'redis:8.4-alpine')
            options = invoke('workflow-read', {'operation': 'network_options'})
            assert options['ok'] and {'macvlan', 'ipvlan'} <= set(options['drivers']), options
            assert parent in {x['name'] for x in options['parents']}, options
            assert 'lo' not in {x['name'] for x in options['parents']}
            routed = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all'], text=True))
            assert not [x for x in routed if x.get('dev') == parent], routed
            for second in range(240, 254):
                payload = {'name': prefix + '-macvlan', 'driver': 'macvlan', 'parent': parent,
                           'ipam': {'subnet': f'10.{second}.64.0/24', 'gateway': f'10.{second}.64.2',
                                    'ip_range': f'10.{second}.64.128/25'}}
                if plan(payload).get('ok'):
                    break
            else:
                raise AssertionError('No conflict-free isolated test subnet')
            for driver in ('macvlan', 'ipvlan'):
                payload.update(name=prefix + '-' + driver, driver=driver)
                preview = plan(payload)
                assert preview['ok'] and preview['dhcp_check'] == 'manual_required', preview
                assert preview['mode'] == ('bridge' if driver == 'macvlan' else 'l2'), preview
                assert subprocess.run(['docker', 'network', 'inspect', payload['name']],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
                missing = invoke('network-create', dict(payload, confirm=True))
                assert missing['error'] == 'network_acknowledgement_required', missing
                assert plan(dict(payload, parent='lo'))['reason'] == 'existing_ethernet_parent_required'
                assert plan(dict(payload, acknowledge_dhcp='yes'))['reason'] == 'boolean_required'
                route = next(x for x in routed if x.get('dst', '').startswith('192.168.') and '/' in x['dst'] and not x['dst'].endswith('/32'))
                import ipaddress
                subnet = ipaddress.ip_network(route['dst'])
                conflict = plan(dict(payload, ipam={'subnet': str(subnet), 'gateway': str(subnet.network_address + 1),
                                                    'ip_range': str(subnet)}))
                assert conflict['error'] == 'network_conflict', conflict
                assert any(x['source'] == 'host_route' for x in conflict['conflicts']), conflict
                created = invoke('network-create', dict(payload, confirm=True, acknowledge_dhcp=True))
                assert created['ok'], created
                owned.append(payload['name'])
                raw = json.loads(docker('network', 'inspect', created['network_id']))[0]
                assert raw['Options']['parent'] == parent and raw['Driver'] == driver, raw
                assert raw['Options'][driver + '_mode'] == preview['mode'], raw
                assert raw['IPAM']['Config'][0]['IPRange'] == payload['ipam']['ip_range'], raw
                assert plan(dict(payload, name=prefix + '-stale'))['error'] == 'network_conflict'
                for index in range(2):
                    containers.append(docker('run', '-d', '--name', prefix + '-' + driver + '-' + str(index),
                                             '--network', payload['name'], '--mount', 'type=tmpfs,destination=/data', 'redis:8.4-alpine'))
                endpoints = [json.loads(docker('inspect', c))[0]['NetworkSettings']['Networks'][payload['name']] for c in containers]
                for endpoint in endpoints:
                    assert endpoint['IPAddress'].startswith(f'10.{second}.64.') and int(endpoint['IPAddress'].split('.')[-1]) >= 128, endpoint
                    assert endpoint['Gateway'] == f'10.{second}.64.2', endpoint
                assert docker('exec', containers[0], 'redis-cli', '-h', endpoints[1]['IPAddress'], 'ping') == 'PONG'
                edit = invoke('workflow-read', {'operation': 'network_edit', 'id': payload['name']})
                assert edit['ok'], edit
                edit['config']['ipam']['ip_range'] = f'10.{second}.64.192/26'
                edit['config']['acknowledge_dhcp'] = True
                job = invoke('workflow-write', {'operation': 'network_recreate', 'id': edit['id'], 'revision': edit['revision'],
                                               'config': edit['config'], 'confirm': True, 'allow_disconnect': True})
                assert job.get('job_id'), job
                for _ in range(400):
                    with sqlite3.connect(root / 'core.db') as db:
                        row = db.execute('SELECT state,result_json,error FROM container_job WHERE id=?', (job['job_id'],)).fetchone()
                    if row[0] not in ('queued', 'running'):
                        break
                    time.sleep(.05)
                assert row[0] == 'success', row
                endpoints = [json.loads(docker('inspect', c))[0]['NetworkSettings']['Networks'][payload['name']] for c in containers]
                assert all(int(e['IPAddress'].split('.')[-1]) >= 192 for e in endpoints), endpoints
                assert docker('exec', containers[0], 'redis-cli', '-h', endpoints[1]['IPAddress'], 'ping') == 'PONG'

                for c in containers:
                    docker('rm', '-fv', c)
                containers.clear()
                docker('network', 'rm', owned.pop())
            print('ok: real macvlan bridge/ipvlan L2 create and rebuild, IP/gateway and peer Redis PING; '
                  'parent/route/Docker subnet checks; DHCP acknowledgement; preview zero writes; '
                  'test parent unnumbered and isolated from physical interfaces')
        finally:
            for c in containers:
                subprocess.run(['docker', 'rm', '-fv', c], stdout=subprocess.DEVNULL)
            if helper:
                subprocess.run(['docker', 'rm', '-fv', helper], stdout=subprocess.DEVNULL)
            for network in reversed(owned):
                subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
