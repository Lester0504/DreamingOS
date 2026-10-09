#!/usr/bin/env python3
"""Replace test-owned networks, inject Engine failure and recover killed jobs."""
import http.client
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid

from test_container_service_runtime import compile_fixture


def main():
    if os.environ.get('DOCKER_WORKFLOW_REAL') != '1':
        raise SystemExit('Set DOCKER_WORKFLOW_REAL=1 for test-owned Docker resources')
    name = 'dwrt-netedit-' + uuid.uuid4().hex[:12]
    containers = []
    with tempfile.TemporaryDirectory(prefix='docker-netedit-') as directory:
        root = Path(directory)
        state = {'fail_create': False, 'hold_delete': False, 'writes': [], 'errors': []}
        held, release = threading.Event(), threading.Event()

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def serve(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if self.command != 'GET':
                    state['writes'].append((self.command, self.path))
                if state['fail_create'] and self.command == 'POST' and self.path == '/networks/create':
                    state['fail_create'] = False
                    code, output = 500, b'{"message":"test injected network create failure"}'
                else:
                    connection = http.client.HTTPConnection('localhost', timeout=25)
                    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.sock.connect('/var/run/docker.sock')
                    connection.request(self.command, self.path, body, {'Content-Type': 'application/json'})
                    response = connection.getresponse()
                    code, output = response.status, response.read()
                    connection.close()
                    if code >= 400:state['errors'].append((self.path, code, output.decode()[:600]))
                if state['hold_delete'] and self.command == 'DELETE' and self.path.startswith('/networks/'):
                    state['hold_delete'] = False
                    held.set()
                    release.wait(35)
                try:
                    self.send_response(code)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(output)))
                    self.end_headers()
                    self.wfile.write(output)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            do_GET = do_POST = do_DELETE = serve

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True

        server = Server(str(root / 'proxy.sock'), Proxy)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        db = root / 'core.db'
        binary = compile_fixture(root, db, engine_socket=root / 'proxy.sock')

        def docker(*args):
            return subprocess.check_output(['docker', *args], text=True).strip()

        def invoke(mode, payload=None):
            args = [str(binary), mode]
            if payload is not None:
                args.append(json.dumps(payload) if isinstance(payload, dict) else payload)
            proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, timeout=60)
            if mode == 'reconcile' and proc.returncode == 0:
                return {}
            data = json.loads(proc.stdout)
            return data.get('data', data)

        def row(job):
            with sqlite3.connect(db) as conn:
                conn.row_factory = sqlite3.Row
                record = dict(conn.execute('SELECT * FROM container_job WHERE id=?', (job,)).fetchone())
            record['result'] = json.loads(record['result_json'])
            return record

        def wait(job):
            for _ in range(600):
                record = row(job)
                if record['state'] not in ('queued', 'running'):
                    return record
                time.sleep(.05)
            raise AssertionError(row(job))

        def template():
            result = invoke('workflow-read', {'operation': 'network_edit', 'id': name})
            assert result['ok'], result
            return result

        def request(t=None):
            t = t or template()
            cfg = t['config']
            cfg['ipam']['ip_range'] = subnet.rsplit('.', 1)[0] + '.128/25'
            return {'operation': 'network_recreate', 'id': t['id'], 'revision': t['revision'],
                    'config': cfg, 'confirm': True, 'allow_disconnect': True}

        try:
            for second in range(240, 254):
                subnet = f'10.{second}.88.0/24'
                cfg = {'name': name, 'driver': 'bridge', 'internal': True,
                       'ipam': {'subnet': subnet, 'gateway': f'10.{second}.88.1'}}
                if invoke('workflow-read', dict(cfg, operation='network_validate')).get('ok'):
                    break
            created = invoke('network-create', dict(cfg, confirm=True))
            assert created['ok'], created
            bound = docker('create', '--network', created['network_id'], '--mount', 'type=tmpfs,destination=/data', 'redis:8.4-alpine')
            containers.append(bound)
            before = len(state['writes'])
            blocked = invoke('workflow-read', {'operation': 'network_edit', 'id': name})
            assert blocked['error'] == 'network_id_bound_container' and len(state['writes']) == before, blocked
            docker('rm', bound)
            containers.clear()
            containers.append(docker('run', '-d', '--name', name + '-static', '--network', name,
                                     '--ip', f'10.{second}.88.40', '--network-alias', 'stable-peer',
                                     '--mount', 'type=tmpfs,destination=/data', 'redis:8.4-alpine'))
            containers.append(docker('run', '-d', '--name', name + '-dynamic', '--network', name,
                                     '--mount', 'type=tmpfs,destination=/data', 'redis:8.4-alpine'))
            containers.append(docker('create', '--name', name + '-unstarted', '--network', name, '--mount', 'type=tmpfs,destination=/data', 'redis:8.4-alpine'))
            t = template()
            assert len(t['endpoints']) == 3 and t['disconnect_required'], t
            before = len(state['writes'])
            preview = invoke('workflow-read', dict(request(t), operation='network_edit'))
            assert preview['ok'] and len(state['writes']) == before, preview
            assert invoke('workflow-write', dict(request(t), allow_disconnect=False))['error'] == 'network_disconnect_confirmation_required'
            invalid = request(t)
            invalid['config'] = dict(invalid['config'], ipam={'subnet': f'10.{second}.89.0/24', 'gateway': f'10.{second}.89.1'})
            assert invoke('workflow-read', dict(invalid, operation='network_edit'))['error'] == 'static_endpoint_outside_subnet'
            success = wait(invoke('workflow-write', request())['job_id'])
            assert success['state'] == 'success', (success,state['errors'])
            assert invoke('workflow-write', request(t))['error'] in ('network_not_found', 'revision_conflict')
            raw = json.loads(docker('network', 'inspect', name))[0]
            assert raw['Id'] != created['network_id'] and raw['IPAM']['Config'][0]['IPRange'].endswith('.128/25'), raw
            assert docker('exec', containers[1], 'redis-cli', '-h', f'10.{second}.88.40', 'ping') == 'PONG'

            docker('restart', containers[0])
            assert docker('exec', containers[1], 'redis-cli', '-h', f'10.{second}.88.40', 'ping') == 'PONG'

            docker('start', containers[2])
            assert docker('exec', containers[2], 'redis-cli', '-h', 'stable-peer', 'ping') == 'PONG'
            docker('stop', containers[1])
            stopped = wait(invoke('workflow-write', request())['job_id'])
            assert stopped['state'] == 'success', (stopped,state['errors'])
            assert not json.loads(docker('inspect', containers[1]))[0]['State']['Running']
            docker('start', containers[1])
            assert docker('exec', containers[1], 'redis-cli', '-h', 'stable-peer', 'ping') == 'PONG'
            state['fail_create'] = True
            failed = wait(invoke('workflow-write', request())['job_id'])
            assert failed['state'] == 'failed' and failed['result']['rollback_succeeded'], failed
            assert not failed['result']['recoverable'], failed
            assert docker('exec', containers[1], 'redis-cli', '-h', 'stable-peer', 'ping') == 'PONG'

            for interrupt in ('kill', 'cancel'):
                held.clear()
                release.clear()
                state['hold_delete'] = True
                job = invoke('workflow-write', request())['job_id']
                assert held.wait(20), row(job)
                if interrupt == 'kill':
                    os.kill(row(job)['worker_pid'], signal.SIGKILL)
                else:
                    assert invoke('cancel', job)['state'] == 'cancelled'
                release.set()
                time.sleep(.3)
                invoke('reconcile')
                interrupted = row(job)
                assert interrupted['state'] == ('failed' if interrupt == 'kill' else 'cancelled') and interrupted['result']['recoverable'], interrupted
                before = len(state['writes'])
                invoke('reconcile')
                assert len(state['writes']) == before
                recovered = wait(invoke('workflow-write', {'operation': 'container_recover', 'id': job, 'confirm': True})['job_id'])
                assert recovered['state'] == 'success' and recovered['result']['rollback_succeeded'], recovered
                assert not row(job)['result']['recoverable']
                assert docker('exec', containers[1], 'redis-cli', '-h', 'stable-peer', 'ping') == 'PONG'
            print('ok: preview zero writes, conditional version/disconnect/static-subnet checks; real network replacement; '
                  'static IP, aliases and peer traffic preserved; injected failure rollback; killed/cancelled worker explicit recovery')
        finally:
            release.set()
            for container in containers:
                subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL)
            subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    main()
