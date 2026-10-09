#!/usr/bin/env python3
"""Real RTSP recording, restart, storage loss and export; no camera required.

Run on Linux with ffmpeg, ffprobe, a C compiler and MEDIAMTX_BIN pointing to
an upstream MediaMTX binary. All generated files and processes are temporary.
"""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def main():
    mediamtx = os.environ['MEDIAMTX_BIN']
    with tempfile.TemporaryDirectory(prefix='nvr-runtime-') as directory:
        base = Path(directory)
        disk = base/'disk'
        disk.mkdir()
        mountinfo = base/'mountinfo'
        dev = disk.stat().st_dev
        mounted = f'91 1 {os.major(dev)}:{os.minor(dev)} / {disk} rw - ext4 /dev/test rw\n'
        mountinfo.write_text(mounted)
        flags = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-DNAS_STDIN',
                 '-DNVR_SEGMENT_SECONDS="2"', '-DSTORAGE_FILES_TEST_ALLOW_PROTECTED_DEVICE=1',
                 '-DSTORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT=1',f'-DDATA_STORAGE_CONFIG="{base}/default.json"',f'-DDATA_STORAGE_TEST_UUIDS="{base}/uuids.json"',
                 f'-DSTORAGE_FILES_MOUNTINFO="{mountinfo}"', '-I', str(ROOT/'src')]
        subprocess.run(flags+[str(ROOT/'src/storage/data_storage.c'),str(ROOT/'src/nas/nvr.c'), str(ROOT/'src/nas/nvr_main.c'),
                             str(ROOT/'src/storage/storage_files.c'), '-ljson-c', '-lsqlite3',
                             '-o', str(base/'nvrd')], check=True)
        subprocess.run(flags+[str(ROOT/'src/storage/storage_files.c'),
                             str(ROOT/'tests/test_storage_files_fixture.c'), '-ljson-c',
                             '-o', str(base/'files')], check=True)
        rid = json.loads(subprocess.check_output([str(base/'files')], text=True))['data']['root_id']
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        url = f'rtsp://127.0.0.1:{port}/camera'
        (base/'mediamtx.yml').write_text(f'logLevel: warn\nrtspAddress: 127.0.0.1:{port}\nrtmp: no\nhls: no\nwebrtc: no\nsrt: no\npaths:\n  camera:\n    source: publisher\n')
        children = []
        process = None
        checks = []
        def start_child(argv, name):
            with (base/name).open('a') as log:
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            children.append(child)
            return child
        def publisher():
            return start_child(['/usr/bin/ffmpeg', '-nostdin', '-v', 'error', '-re', '-f', 'lavfi', '-i',
                                'testsrc2=size=320x240:rate=25', '-f', 'lavfi', '-i',
                                'sine=frequency=880:sample_rate=48000', '-c:v', 'libx264', '-threads', '1',
                                '-g', '25', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', '-c:a', 'aac',
                                '-f', 'rtsp', '-rtsp_transport', 'tcp', url], 'publisher.log')
        def start():
            return subprocess.Popen([str(base/'nvrd'), str(base/'nvr.json')], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def call(method, route, params=None, status=200):
            process.stdin.write(json.dumps({'method': method, 'route': route, 'params': params or {}})+'\n')
            process.stdin.flush()
            assert select.select([process.stdout], [], [], 8)[0], f'timed out: {route}'
            line = process.stdout.readline()
            assert line, 'service exited: '+process.stderr.read()
            response = json.loads(line)
            assert response['http_status'] == status, response
            return response['data']
        def until(read, predicate, timeout=25):
            end = time.monotonic()+timeout
            while time.monotonic() < end:
                value = read()
                if predicate(value): return value
                time.sleep(.25)
            raise AssertionError(('condition not reached', value))
        def clips(): return call('GET', '/recordings')['items']
        def cameras(): return call('GET', '/cameras')['items']
        def probe(path):
            return json.loads(subprocess.check_output(['/usr/bin/ffprobe', '-v', 'error', '-show_streams',
                              '-show_format', '-of', 'json', str(path)], text=True))
        def close():
            process.stdin.close()
            assert process.wait(timeout=10) == 0
            process.stdout.close()
            process.stderr.close()
        try:
            server = start_child([mediamtx, str(base/'mediamtx.yml')], 'mediamtx.log')
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.1', port), .1): break
                except OSError: time.sleep(.1)
            assert server.poll() is None
            source = publisher()
            process = start()
            assert call('GET', '/status')['storage']['state'] == 'storage_unavailable'
            assert not (disk/'.dreamingos-nvr').exists()
            call('POST', '/settings', {'root_id': rid}, 400)
            call('POST', '/settings', {'root_id': 'invalid', 'path': str(disk)}, 409)
            call('POST', '/settings', {'root_id': rid, 'path': str(disk)})
            call('POST', '/cameras', {'name': 'bad', 'url': 'file:///etc/passwd'}, 400)
            camera = call('POST', '/cameras', {'name': 'Test camera', 'url': url}, 201)['id']
            call('POST', '/cameras/action', {'id': camera, 'action': 'stop'}, 202)
            assert cameras()[0]['state'] == 'stopped'
            call('POST', '/cameras/action', {'id': camera, 'action': 'start'}, 202)
            initial = until(clips, lambda rows: len(rows) >= 2)
            current = cameras()[0]
            assert current['state'] == 'recording' and current['preview']
            assert 'url' not in current
            clip = initial[0]
            manifest = Path(clip['playback']['path']).read_text()
            assert '#EXT-X-ENDLIST' in manifest and '/api/v1/storage/files/raw?' in manifest
            media = probe(clip['file']['path'])
            assert any(s['codec_name'] == 'h264' for s in media['streams'])
            subprocess.run(['/usr/bin/ffmpeg', '-v', 'error', '-i', clip['file']['path'],
                            '-frames:v', '1', '-f', 'null', '-'], check=True)
            checks.append('RTSP -> H.264 recording + authenticated HLS manifest + decoded frame')
            # No HTTP/client polling or open window is necessary for recording.
            before = len(list(disk.rglob('rec-*.ts')))
            time.sleep(5)
            assert len(list(disk.rglob('rec-*.ts'))) > before
            checks.append('recording continues without client requests')
            call('POST', '/settings', {'root_id': rid, 'path': str(disk)}, 409)
            call('POST', '/exports', {'recording_id': clip['id'], 'start_seconds': -1}, 400)
            call('POST', '/exports', {'recording_id': clip['id'], 'start_seconds': .2, 'end_seconds': 1.2}, 202)
            jobs = until(lambda: call('GET', '/exports')['items'], lambda rows: rows[0]['state'] != 'running')
            assert jobs[0]['state'] == 'succeeded', jobs
            export = probe(jobs[0]['file']['path'])
            assert .8 <= float(export['format']['duration']) <= 1.5, export['format']
            checks.append('trim export completes and MP4 duration is verified')
            source.terminate(); source.wait(timeout=5)
            until(cameras, lambda rows: rows[0]['state'] == 'reconnecting', 20)
            count = len(clips())
            source = publisher()
            until(clips, lambda rows: len(rows) > count, 30)
            checks.append('stream loss becomes reconnecting and recovery produces new clips')
            known = {c['id'] for c in clips()}
            process.kill(); process.wait(timeout=5)
            process.stdin.close(); process.stdout.close(); process.stderr.close()
            process = start()
            assert known <= {c['id'] for c in clips()}
            until(clips, lambda rows: len(rows) > len(known), 25)
            checks.append('crash restart retains clip IDs and resumes enabled camera')
            mountinfo.write_text('')
            assert call('GET', '/status')['storage']['state'] == 'storage_unavailable'
            call('GET', '/recordings', status=409)
            time.sleep(2)
            close(); process = None
            process = start()
            assert call('GET', '/status')['storage']['state'] == 'storage_unavailable'
            mountinfo.write_text(mounted)
            until(lambda: call('GET', '/status'), lambda state: state['storage']['state'] == 'ready', 10)
            assert known <= {c['id'] for c in clips()}
            count = len(clips())
            until(clips, lambda rows: len(rows) > count, 25)
            checks.append('disk loss blocks reads; startup before mount recovers without data loss')
            call('POST', '/cameras/action', {'id': camera, 'action': 'stop'}, 202)
            until(cameras, lambda rows: rows[0]['state'] == 'stopped')
            count = len(clips()); time.sleep(3)
            assert len(clips()) == count
            call('POST', '/cameras/action', {'id': camera, 'action': 'remove'}, 202)
            assert cameras() == [] and len(clips()) == count
            assert Path(clip['file']['path']).is_file()
            checks.append('explicit stop ends recording; removing camera retains footage')
            report = {'result': 'passed', 'checks': checks, 'recordings': count, 'export_seconds': export['format']['duration']}
            if os.environ.get('NVR_TEST_REPORT'):
                Path(os.environ['NVR_TEST_REPORT']).write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2))
        finally:
            if process and process.poll() is None: close()
            for child in reversed(children):
                if child.poll() is None: child.terminate()
            for child in children:
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: child.kill(); child.wait()

if __name__ == '__main__': main()
