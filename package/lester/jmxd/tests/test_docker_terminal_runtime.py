#!/usr/bin/env python3
"""Real container exec + existing terminal Unix/WS protocol, test-owned containers.

Run as the Docker-authorized non-root source owner. TM_BINARY uses a four-second
TM_LEASE_SECONDS override to exercise expiry. No service or existing container is changed.
"""
import base64
import http.client
import json
import os
import socket
import subprocess
import time
import unittest
from test_terminal_manager_runtime import Runtime, WS


class DockerSocket(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost', timeout=8)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect('/var/run/docker.sock')


def engine(path):
    c = DockerSocket()
    c.request('GET', path)
    response = c.getresponse()
    result = json.loads(response.read())
    c.close()
    return result


class Docker(Runtime):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.container = subprocess.check_output([
            'docker', 'run', '-d', '--pull', 'never', '--network', 'none', '--read-only',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/data',
            '--label', 'dwrt.test=docker-terminal', '--entrypoint', '/bin/sh',
            os.environ.get('TM_DOCKER_TEST_IMAGE', 'redis:8.4-alpine'), '-c', 'exec sleep 600'], text=True).strip()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        subprocess.run(['docker', 'rm', '-fv', cls.container], check=True, stdout=subprocess.DEVNULL)

    def start_docker(self, shell='/bin/sh', container=None):
        response = self.rpc('docker/sessions', 'POST', dict(
            container_id=container or self.container, shell=shell, workspace_id='docker-test'))
        self.assertEqual(response['status'], 202, response)
        session = response['data']
        a, b = socket.socketpair()
        result = self.rpc(f"docker/sessions/{session['id']}/ws", body={
            'websocket_key': base64.b64encode(os.urandom(16)).decode()}, passed=a)
        a.close()
        self.assertTrue(result['data']['fd_owned'], result)
        ws = WS(b)
        self.addCleanup(ws.peer.close)
        self.addCleanup(lambda: self.rpc(f"docker/sessions/{session['id']}/disconnect", 'POST'))
        return session, ws

    def assert_exec_stopped(self, exec_id):
        for _ in range(80):
            if not engine(f'/exec/{exec_id}/json')['Running']:
                return
            time.sleep(.05)
        self.fail('container exec process still running after session ended')

    def test_docker_01_real_tty_resize_scope_and_close(self):
        caps = self.rpc('docker/capabilities')['data']
        self.assertTrue(caps['terminal'], caps)
        session, ws = self.start_docker()
        ready = ws.until_state('ready')
        self.assertTrue(ready['exec_id'])
        ws.send({'type': 'resize', 'cols': 91, 'rows': 27})
        ws.send({'type': 'input', 'data': "stty size; printf '\\344\\270\\255\\346\\226\\207-TTY-OK\\n'\n"})
        output = b''
        for _ in range(40):
            opcode, data = ws.event()
            if opcode == 2:
                output += data
                if b'27 91' in output and '中文-TTY-OK'.encode() in output:
                    break
        self.assertIn(b'27 91', output)
        self.assertIn('中文-TTY-OK'.encode(), output)
        path = f"docker/sessions/{session['id']}"
        self.assertEqual(self.rpc(path, owner='other')['status'], 404)
        self.assertEqual(self.rpc(path, manage=False)['status'], 403)
        self.assertEqual(self.rpc(f"sessions/{session['id']}")['status'], 404)
        self.assertNotIn(session['id'], [v['id'] for v in self.rpc('sessions')['data']['items']])
        self.assertEqual(self.rpc(path + '/system-info')['status'], 422)
        self.assertEqual(self.rpc(path + '/files')['status'], 422)
        self.assertEqual(self.rpc(path + '/lease', 'POST')['status'], 200)
        ws.peer.close()
        self.assert_exec_stopped(ready['exec_id'])
        self.assertTrue(engine(f'/containers/{self.container}/json')['State']['Running'])

    def test_docker_02_lease_expiration_kills_exec(self):
        session, ws = self.start_docker()
        ready = ws.until_state('ready')
        ended = ws.until_state('disconnected')
        self.assertEqual(ended['reason'], 'authorization_lease_expired')
        self.assert_exec_stopped(ready['exec_id'])

    def test_docker_03_disconnect_and_shell_error(self):
        session, ws = self.start_docker()
        ready = ws.until_state('ready')
        self.rpc(f"docker/sessions/{session['id']}/disconnect", 'POST')
        ws.until_state('closed')
        self.assert_exec_stopped(ready['exec_id'])
        session, ws = self.start_docker('/bin/bash')
        failed = ws.until_state('failed')
        self.assertEqual(failed['reason'], 'docker_shell_unavailable')

    def test_docker_04_reject_host_and_unknown_fields(self):
        body = dict(container_id=self.container, workspace_id='test')
        for extra in [dict(host={'type': 'local'}), dict(shell='/bin/sh -c id'), dict(command='id'), dict(user='root'), dict(container_id='../version')]:
            self.assertEqual(self.rpc('docker/sessions', 'POST', {**body, **extra})['status'], 422)
        self.assertEqual(self.rpc('sessions', 'POST', {'host': {'type': 'docker', 'name': 'x', 'container_id': self.container}, 'workspace_id': 'test'})['status'], 422)
        self.assertEqual(self.rpc('docker/sessions', 'POST', body, manage=False)['status'], 403)

    def test_docker_05_container_stop_closes_session(self):
        session, ws = self.start_docker()
        ready = ws.until_state('ready')
        subprocess.run(['docker', 'stop', '-t', '1', self.container], check=True, stdout=subprocess.DEVNULL)
        try:
            ended = ws.until_state('disconnected')
            self.assertEqual(ended['reason'], 'remote_closed')
            self.assert_exec_stopped(ready['exec_id'])
            _, ws2 = self.start_docker()
            self.assertEqual(ws2.until_state('failed')['reason'], 'docker_container_not_running')
        finally:
            subprocess.run(['docker', 'start', self.container], check=True, stdout=subprocess.DEVNULL)

    def test_docker_06_migration_blocks_new_exec(self):
        import fcntl
        import sqlite3
        from pathlib import Path
        lock=os.environ.get('TM_MIGRATION_TEST_LOCK')
        database=os.environ.get('TM_MIGRATION_TEST_DB')
        if not lock or not database:self.skipTest('isolated migration lock/DB not configured')
        with open(lock,'a+') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX)
            _,ws=self.start_docker()
            self.assertEqual(ws.until_state('failed')['reason'],'docker_migration_busy_or_recovery_required')
        try:
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE docker_engine_settings(id INTEGER PRIMARY KEY,state TEXT)')
                db.execute("INSERT INTO docker_engine_settings VALUES(1,'migration_copying')")
            _,ws=self.start_docker()
            self.assertEqual(ws.until_state('failed')['reason'],'docker_migration_busy_or_recovery_required')
            self.assertTrue(engine(f'/containers/{self.container}/json')['State']['Running'])
        finally:Path(database).unlink(missing_ok=True)


if __name__ == '__main__':
    suite = unittest.TestSuite(Docker(name) for name in unittest.defaultTestLoader.getTestCaseNames(Docker) if name.startswith('test_docker_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
