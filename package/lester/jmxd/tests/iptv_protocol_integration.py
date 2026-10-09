#!/usr/bin/env python3
"""Loopback-only protocol validation against the IPTV_TESTING service.

Run iptv_service_integration.py --serve-only first. MediaMTX is a test input
server, not a runtime dependency. No interfaces, routes or UCI are modified.
"""
import argparse
import json
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--directory', required=True)
p.add_argument('--mediamtx', required=True)
p.add_argument('--http-port', type=int, default=19751)
p.add_argument('--case', choices=['udp', 'rtp', 'rtsp-tcp', 'rtsp-udp', 'rtmp'])
a = p.parse_args()
root = Path(a.directory).resolve()
assert str(root).startswith('/tmp/') and (root / 'synthetic.ts').is_file()
checks, children, logs = [], [], []


def recv(s, n):
    data = b''
    while len(data) < n:
        part = s.recv(n - len(data))
        assert part, 'short IPC response'
        data += part
    return data


def call(method, resource='', body=None):
    q = json.dumps(dict(method=method, resource=resource, body=body,
                        actor='isolated-protocol-test')).encode()
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10)
        s.connect(str(root / 'iptv.sock'))
        s.sendall(struct.pack('!I', len(q)) + q)
        return json.loads(recv(s, struct.unpack('!I', recv(s, 4))[0]))


def request(method, resource='', body=None):
    result = call(method, resource, body)
    assert not result['status'], result
    return result['data']


def spawn(name, argv):
    log = (root / (name + '.log')).open('wb')
    logs.append(log)
    process = subprocess.Popen(argv, stdout=log, stderr=log)
    children.append(process)
    return process


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def wait_state(channel, expected, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = request('GET', 'channels/' + channel)['runtime']
        if state['state'] == expected:
            return state
        assert state['state'] != 'error', state
        time.sleep(.2)
    raise AssertionError(state)


def receiver_pids():
    found = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            cmd = (proc / 'cmdline').read_bytes()
            if b'ffmpeg\0' in cmd and bytes(str(root / '.dreamingwrt-iptv'), 'utf-8') in cmd:
                found.append(int(proc.name))
        except (FileNotFoundError, PermissionError):
            pass
    return found


config = root / 'protocol-mediamtx.yml'
config.write_text('''logLevel: warn
api: false
metrics: false
pprof: false
playback: false
hls: false
webrtc: false
srt: false
rtsp: true
rtspTransports: [tcp, udp]
rtspAddress: 127.0.0.1:19760
rtpAddress: 127.0.0.1:19762
rtcpAddress: 127.0.0.1:19763
rtmp: true
rtmpAddress: 127.0.0.1:19761
paths:
  all_others:
''')
active_channel = None
try:
    # Only the isolated test database receives a network-authority fixture.
    with sqlite3.connect(root / 'config.db') as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS wan(id TEXT PRIMARY KEY,name TEXT,device TEXT,
            access_mode TEXT,enabled INTEGER,vlan_id TEXT);
        CREATE TABLE IF NOT EXISTS wan_advanced(wan_id TEXT PRIMARY KEY,
            default_route INTEGER,dhcp_vendor_class TEXT);
        INSERT OR REPLACE INTO wan(id,name,device,access_mode,enabled,vlan_id) VALUES('protocol-loopback','隔离回环','lo','static',1,'');
        INSERT OR REPLACE INTO wan_advanced VALUES('protocol-loopback',0,'');
        ''')
        if 'role' not in {row[1] for row in db.execute('PRAGMA table_info(wan)')}:
            db.execute("ALTER TABLE wan ADD COLUMN role TEXT DEFAULT 'iptv'")
    inputs = request('GET', 'inputs')['items']
    assert next(i for i in inputs if i['id'] == 'protocol-loopback')['local_address'] == '127.0.0.1'
    checks.append('multicast binds the explicit loopback network-authority address')
    server = spawn('mediamtx', [a.mediamtx, str(config)])
    time.sleep(1)
    assert server.poll() is None, 'MediaMTX failed; see mediamtx.log'
    # MP4 provides AAC AudioSpecificConfig required by the RTSP publisher.
    # The generated programme remains the same H.264/AAC test source.
    source = root / 'protocol-source.mp4'
    subprocess.run(['ffmpeg', '-nostdin', '-v', 'error', '-i', str(root / 'synthetic.ts'),
        '-c', 'copy', '-bsf:a', 'aac_adtstoasc', '-movflags', '+faststart', '-y', str(source)], check=True)
    common = ['ffmpeg', '-nostdin', '-v', 'error', '-stream_loop', '-1', '-re',
              '-i', str(source), '-map', '0:v:0', '-map', '0:a:0', '-c', 'copy']
    cases = [
        ('udp', 'udp://239.255.19.1:19764', 'mpegts', {}, 'protocol-loopback'),
        ('rtp', 'rtp://239.255.19.2:19766', 'rtp_mpegts', {}, 'protocol-loopback'),
        ('rtsp-tcp', 'rtsp://127.0.0.1:19760/synthetic', 'rtsp', {'rtsp_transport': 'tcp'}, ''),
        ('rtsp-udp', 'rtsp://127.0.0.1:19760/synthetic', 'rtsp', {'rtsp_transport': 'udp'}, ''),
        ('rtmp', 'rtmp://127.0.0.1:19761/synthetic', 'flv', {}, ''),
    ]
    for name, url, muxer, options, binding in cases:
        if a.case and a.case != name:
            continue
        output = url + '?localaddr=127.0.0.1&ttl=0&pkt_size=1316' if binding else url
        flags = ['-rtsp_transport', 'tcp'] if muxer == 'rtsp' else []
        if muxer == 'flv':
            flags += ['-bsf:a', 'aac_adtstoasc']
        sender = spawn('sender-' + name, common + flags + ['-f', muxer, output])
        time.sleep(2)
        assert sender.poll() is None, 'input publisher failed: ' + name
        channel = request('POST', 'channels', dict(name='自生成 ' + name,
            source_url=url, mode='managed', input_id=binding, **options))['record']
        active_channel = channel['id']
        assert call('POST', 'channels/' + active_channel + '/preview', {})['code'] == 'source_probe_required'
        request('POST', 'channels/' + active_channel + '/probe', {})
        probe = wait_state(active_channel, 'probe_complete')
        assert any(s.get('codec_name') == 'h264' for s in probe['probe']['streams'])
        checks.append(name + ' actual ffprobe receives H.264 media')
        ticket = request('POST', 'channels/' + active_channel + '/preview', {})
        wait_state(active_channel, 'media_ready')
        if options:
            commands = [Path('/proc', str(pid), 'cmdline').read_bytes() for pid in receiver_pids()]
            expected = b'-rtsp_transport\0' + options['rtsp_transport'].encode() + b'\0'
            assert any(expected in cmd for cmd in commands)
            checks.append(name + ' requested transport reaches the FFmpeg process')
        result = subprocess.run(['ffmpeg', '-nostdin', '-v', 'error', '-xerror',
            '-i', 'http://127.0.0.1:' + str(a.http_port) + ticket['url'],
            '-t', '2', '-f', 'null', '-'], capture_output=True, timeout=25)
        assert result.returncode == 0, (name, result.stderr.decode()[-1500:])
        checks.append(name + ' generated HLS actually decodes in an independent client')
        receiver = receiver_pids()
        assert receiver, 'no supervised receiver found'
        request('POST', 'channels/' + active_channel + '/stop', {'confirm': True})
        assert all(not Path('/proc', str(pid)).exists() for pid in receiver)
        checks.append(name + ' explicit stop reaps the actual media receiver')
        request('DELETE', 'sessions/' + ticket['session_id'], {})
        request('DELETE', 'channels/' + active_channel, {'if_revision': channel['revision']})
        active_channel = None
        stop(sender)
        print('PASS', name, flush=True)
    result = dict(passed=len(checks), checks=checks,
        environment='31.6 lester; self-generated H.264/AAC; multicast TTL 0 and localaddr 127.0.0.1; MediaMTX loopback only',
        unverified=['physical NIC', 'DHCP/PPPoE/VLAN application', 'ISP input', 'target router'])
    (root / 'protocol-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps(result, ensure_ascii=False))
except Exception as error:
    (root / 'protocol-failure.json').write_text(json.dumps(dict(checks=checks, error=str(error)), ensure_ascii=False, indent=2))
    for log in (root / '.dreamingwrt-iptv').glob('*/error.log'):
        if log.stat().st_size:
            print('MEDIA_ERROR', log.read_text()[-2500:], flush=True)
    raise
finally:
    if active_channel:
        call('POST', 'channels/' + active_channel + '/stop', {'confirm': True})
    for child in reversed(children):
        stop(child)
    for log in logs:
        log.close()
