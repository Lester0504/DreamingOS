#!/usr/bin/env python3
"""Validate bridge IPAM against real host routes and test-owned Docker networks."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_WORKFLOW_REAL') != '1':
        raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 for isolated Docker integration')
    prefix = 'dwrt-ipam-' + uuid.uuid4().hex[:12]
    owned = []
    container = None

    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True).strip()

    with tempfile.TemporaryDirectory(prefix='docker-ipam-') as directory:
        temp = Path(directory)
        binary = compile_fixture(temp, temp / 'core.db')

        def invoke(mode, payload, env=None):
            proc = subprocess.run([str(binary), mode, json.dumps(payload)],
                                  stdout=subprocess.PIPE, text=True, env=env)
            result = json.loads(proc.stdout)
            return result.get('data', result)

        def preview(payload, env=None):
            return invoke('workflow-read', dict(payload, operation='network_validate'), env)

        try:
            for second in range(240, 254):
                subnet = f'10.{second}.64.0/24'
                request = {'name': prefix, 'driver': 'bridge', 'internal': True,
                           'ipam': {'subnet': subnet, 'gateway': f'10.{second}.64.1',
                                    'ip_range': f'10.{second}.64.128/25'}}
                checked = preview(request)
                if checked.get('ok'):
                    break
            assert checked.get('ok'), checked
            assert not checked['automatic_subnet']
            assert subprocess.run(['docker', 'network', 'inspect', prefix], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
            missing_confirm = invoke('network-create', request)
            assert missing_confirm['error'] == 'confirmation_required', missing_confirm
            for changes in ({'subnet': f'10.{second}.64.7/24'},
                            {'gateway': f'10.{second}.65.1'},
                            {'gateway': f'10.{second}.64.255'},
                            {'ip_range': f'10.{second}.65.0/24'},
                            {'subnet': '::/64'}):
                invalid = preview(dict(request, ipam=dict(request['ipam'], **changes)))
                assert invalid['error'] == 'invalid_network_request', invalid
            invalid = preview(dict(request, typo=True))
            assert invalid['error'] == 'invalid_network_request', invalid

            routes = json.loads(subprocess.check_output(
                ['ip', '-j', '-4', 'route', 'show', 'table', 'all'], text=True))
            routed = next(x['dst'] for x in routes if x.get('dst', '').startswith('192.168.')
                          and '/' in x['dst'] and not x['dst'].endswith('/32'))
            conflict = preview(dict(request, ipam={'subnet': routed}))
            assert conflict['error'] == 'network_conflict', conflict
            assert any(x['source'] == 'host_route' for x in conflict['conflicts'])

            fake_bin = temp / 'bin'
            fake_bin.mkdir()
            fake_ip = fake_bin / 'ip'
            fake_ip.write_text('#!/bin/sh\nexit 1\n')
            fake_ip.chmod(0o755)
            unavailable = preview(request, dict(os.environ, PATH=str(fake_bin) + ':' + os.environ['PATH']))
            assert unavailable['error'] == 'network_validation_unavailable', unavailable

            created = invoke('network-create', dict(request, confirm=True))
            assert created.get('ok') and created.get('network_id'), created
            owned.append(created['network_id'])
            raw = json.loads(docker('network', 'inspect', owned[-1]))[0]
            assert raw['Internal'] is True and raw['Driver'] == 'bridge', raw
            pool = raw['IPAM']['Config'][0]
            assert (pool['Subnet'], pool['Gateway'], pool['IPRange']) == (
                subnet, request['ipam']['gateway'], request['ipam']['ip_range']), pool
            stale = invoke('network-create', dict(request, name=prefix + '-stale', confirm=True))
            assert stale['error'] == 'network_conflict', stale
            assert any(x['source'] == 'docker_network' for x in stale['conflicts'])
            duplicate = preview(request)
            assert duplicate['field'] == 'name', duplicate

            container = docker('create', '--name', prefix + '-container', '--network', prefix,
                               'redis:8.4-alpine')
            docker('start', container)
            attached = json.loads(docker('inspect', container))[0]['NetworkSettings']['Networks'][prefix]
            assert attached['IPAddress'].startswith(f'10.{second}.64.'), attached
            assert int(attached['IPAddress'].split('.')[-1]) >= 128, attached
            # Internal bridges deliberately omit the endpoint default gateway.
            assert attached['Gateway'] == '', attached
            print('ok: invalid CIDR/gateway/range rejected; host routes and Docker subnets conflict; '
                  'route read failure rejects; preview creates nothing; confirmation required; '
                  'real bridge IPAM readback and allocated container IP match; stale preview rejected')
        finally:
            if container:
                subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL)
            for network in owned:
                subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
