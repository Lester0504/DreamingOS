#!/usr/bin/env python3
"""Real Engine pull from a test-owned loopback registry; never uses external registries.

Requires DOCKER_PULL_REAL=1. Generates two unique scratch images, observes byte
progress, validates completion/cache/error/cancel, removes only its own image.
"""
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from test_container_service_runtime import compile_fixture


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def artifact():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        item = tarfile.TarInfo('pull-fixture.bin')
        payload = os.urandom(8 * 1024 * 1024)
        item.size = len(payload)
        archive.addfile(item, io.BytesIO(payload))
    raw = stream.getvalue()
    layer = gzip.compress(raw, mtime=0)
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {},
                         'rootfs': {'type': 'layers', 'diff_ids': [digest(raw)]}}).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
                          'config': {'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': len(config), 'digest': digest(config)},
                          'layers': [{'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip', 'size': len(layer), 'digest': digest(layer)}]}).encode()
    return manifest, {digest(layer): layer, digest(config): config}, digest(config)


def main():
    if os.environ.get('DOCKER_PULL_REAL') != '1':
        raise SystemExit('Set DOCKER_PULL_REAL=1 for the test-owned local registry')
    items = {name: artifact() for name in ['success', 'cancel']}
    prefix = 'dwrt-pull-' + uuid.uuid4().hex[:12]
    stop = threading.Event()

    class Registry(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if self.path.rstrip('/') == '/v2':
                content, mime = b'{}', 'application/json'
            else:
                parts = self.path.split('/')
                name = parts[2].removeprefix(prefix + '-') if len(parts) > 4 else ''
                if name not in items:
                    self.send_error(404)
                    return
                manifest, blobs, _ = items[name]
                content = manifest if parts[3] == 'manifests' else blobs.get(parts[4])
                if content is None:
                    self.send_error(404)
                    return
                mime = 'application/vnd.docker.distribution.manifest.v2+json' if parts[3] == 'manifests' else 'application/octet-stream'
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
            self.send_header('Docker-Content-Digest', digest(content))
            self.end_headers()
            if self.command == 'HEAD':
                return
            try:
                for offset in range(0, len(content), 65536):
                    if stop.is_set():
                        return
                    self.wfile.write(content[offset:offset + 65536])
                    self.wfile.flush()
                    if len(content) > 100000:
                        time.sleep(.04)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Registry)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    registry = f'127.0.0.1:{server.server_port}'
    images = [f'{registry}/{prefix}-{name}:latest' for name in items]
    try:
        with tempfile.TemporaryDirectory(prefix='docker-pull-') as directory:
            root = Path(directory)
            db = root / 'core.db'
            binary = compile_fixture(root, db)

            def call(mode, data):
                r = subprocess.run([str(binary), mode, json.dumps(data)], capture_output=True, text=True)
                assert r.returncode == 0, r.stdout + r.stderr
                return json.loads(r.stdout)

            def row(job):
                with sqlite3.connect(db) as conn:
                    conn.row_factory = sqlite3.Row
                    return dict(conn.execute('SELECT * FROM container_job WHERE id=?', (job,)).fetchone())

            def wait(job, state=None):
                deadline = time.monotonic() + 45
                seen = []
                while time.monotonic() < deadline:
                    r = row(job)
                    transfer = json.loads(r['result_json']).get('transfer', {})
                    if transfer:
                        seen.append(transfer)
                    if r['state'] not in ('queued', 'running'):
                        if state:
                            assert r['state'] == state, r
                        return r, seen
                    time.sleep(.12)
                raise AssertionError('pull job timeout')

            job = call('pull', {'image': images[0], 'confirm': True})['job_id']
            finished, seen = wait(job, 'success')
            result = json.loads(finished['result_json'])
            assert result['image_id'] == items['success'][2], result
            assert result['transfer']['phase'] == 'complete', result
            assert any(0 < layer.get('downloaded_bytes', 0) < layer.get('download_total_bytes', 0)
                       for snap in seen for layer in snap.get('layers', [])
                       if layer.get('downloaded_bytes') and layer.get('download_total_bytes')), seen
            actual = json.loads(subprocess.check_output(['docker', 'image', 'inspect', images[0]], text=True))[0]
            assert actual['Id'] == result['image_id']
            print('real pull: intermediate bytes, terminal state and image identity verified')
            wait(call('pull', {'image': images[0], 'confirm': True})['job_id'], 'success')
            print('cached image: verified success')
            failed, _ = wait(call('pull', {'image': f'{registry}/{prefix}-missing:latest', 'confirm': True})['job_id'], 'failed')
            assert json.loads(failed['result_json'])['transfer']['error'], failed
            print('missing manifest: Engine HTTP 200 error stream remains failed')
            job = call('pull', {'image': images[1], 'confirm': True})['job_id']
            for _ in range(150):
                r = row(job)
                layers = json.loads(r['result_json']).get('transfer', {}).get('layers', [])
                if any(x.get('downloaded_bytes') for x in layers):
                    break
                time.sleep(.05)
            else:
                raise AssertionError('cancel test never started downloading')
            subprocess.run([str(binary), 'cancel', job], check=True, stdout=subprocess.DEVNULL)
            time.sleep(.8)
            cancelled = row(job)
            assert cancelled['state'] == 'cancelled', cancelled
            assert json.loads(cancelled['result_json'])['transfer']['phase'] != 'complete', cancelled
            print('cancel: keeps last measured bytes, no false success')
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        for image in images:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
