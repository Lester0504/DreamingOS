"""Real isolated Nginx: migration, HTTP/TLS/LuCI routing and error preservation.

Run on a host with nginx and openssl. Never touches its active configuration.
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import os
import socket
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PREFIX = '/luci-static/dreamingwrt/fingerprint/images/'
PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jH1sAAAAASUVORK5CYII=')


class Upstream(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('denied.png'):
            status, body = 403, b'{"ok":false,"error":"license_denied"}'
        elif self.path.endswith('unavailable.png'):
            status, body = 503, b'{"ok":false,"error":"resource_unavailable"}'
        else:
            status, body = 200, PNG
        self.send_response(status)
        self.send_header('Content-Type', 'image/png' if status == 200 else 'application/json')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def test_proxy():
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='device-images-nginx-') as tmp:
        tmp = Path(tmp)
        snippet = tmp/'usr/share/dreamingwrt/nginx/device-images.inc'
        snippet.parent.mkdir(parents=True)
        snippet.write_text((ROOT/'files/usr/share/dreamingwrt/nginx/device-images.inc').read_text()
                           .replace('127.0.0.1:12518', f'127.0.0.1:{upstream.server_port}'))
        migration = (ROOT/'files/etc/uci-defaults/92-dreamingwrt-device-images').read_text()
        for prefix in ('/etc/', '/usr/'):
            migration = migration.replace(prefix, str(tmp)+prefix)
        script = tmp/'migration.sh'
        script.write_text(migration)
        for tree in ('nginx', 'dreamingos/nginx'):
            conf = tmp/f'etc/{tree}/conf.d'
            conf.mkdir(parents=True)
            (conf/'dreamingwrt-webd.locations').write_text('# existing parallel-task route\nlocation = /preserved { return 200 "preserved"; }\n')
            luci = (ROOT/'files/etc/nginx/conf.d/luci-12517.conf.disabled').read_text()
            luci = '\n'.join(line for line in luci.splitlines() if 'device-images.inc' not in line)+'\n'
            (conf/'luci-12517.conf').write_text(luci)
            (conf/'luci-12517.conf.disabled').write_text(luci)
        subprocess.run(['sh', str(script)], check=True)
        contents = {p: p.read_bytes() for p in tmp.glob('etc/**/conf.d/*') if p.is_file()}
        subprocess.run(['sh', str(script)], check=True)
        assert all(p.read_bytes() == value for p, value in contents.items())
        for p in tmp.glob('etc/**/conf.d/*.locations'):
            assert p.read_text().count('device-images.inc') == 1
            assert 'existing parallel-task route' in p.read_text()
            assert Path(str(p)+'.before-device-images').is_file()
        print('PASS migration: legacy/private paths, active/disabled LuCI, backup and idempotence')

        # Validate the shipped full location set and both full server templates.
        conf = tmp/'etc/dreamingos/nginx/conf.d'
        text = (ROOT/'files/etc/nginx/conf.d/dreamingwrt-webd.locations').read_text()
        (conf/'dreamingwrt-webd.locations').write_text(text.replace('/usr/share/', str(tmp)+'/usr/share/'))
        (tmp/'restrict_locally').write_text('allow 127.0.0.1; deny all;\n')
        (conf/'luci.locations').write_text('location /luci-static/ { return 200 "legacy-static"; }\nlocation ~ \\.png$ { return 404 "legacy-regex"; }\n')
        http, https, luci = free_port(), free_port(), free_port()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', str(tmp/'key'), '-out', str(tmp/'cert')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = (ROOT/'files/etc/nginx/conf.d/dreamingwrt-console-ssl.conf.disabled').read_text()
        tls = tls.replace('listen 443 ssl;', f'listen 127.0.0.1:{https} ssl;')
        tls = tls.replace('listen [::]:443 ssl;', '')
        tls = tls.replace('/etc/dreamingwrt/tls/console.crt', str(tmp/'cert')).replace('/etc/dreamingwrt/tls/console.key', str(tmp/'key'))
        lc = (conf/'luci-12517.conf').read_text().replace('listen 12517;', f'listen 127.0.0.1:{luci};').replace('listen [::]:12517;', '')
        for name, text in [('tls.conf', tls), ('luci.conf', lc)]:
            (tmp/name).write_text(text.replace('include conf.d/', 'include '+str(conf)+'/'))
        config = tmp/'nginx.conf'
        # The build host's Nginx includes Lua; preserve its module search path
        # when changing -p for this isolated instance.
        lua = Path(shutil.which('nginx')).resolve().parents[1]/'lib/lua'
        lua_path = f'lua_package_path "{lua}/?.lua;;";' if (lua/'resty/core.lua').exists() else ''
        (tmp/'logs').mkdir()
        config.write_text(f'''pid {tmp}/nginx.pid;
error_log {tmp}/error.log;
events {{}}
http {{
 {lua_path}
 access_log off;
 client_body_temp_path {tmp}/body;
 proxy_temp_path {tmp}/proxy;
 fastcgi_temp_path {tmp}/fastcgi;
 uwsgi_temp_path {tmp}/uwsgi;
 scgi_temp_path {tmp}/scgi;
 server {{ listen 127.0.0.1:{http}; include {conf}/*.locations; }}
 include {tmp}/tls.conf;
 include {tmp}/luci.conf;
}}
''')
        command = ['nginx', '-p', str(tmp)+'/', '-c', str(config)]
        checked = subprocess.run([*command, '-t'], capture_output=True, text=True)
        assert checked.returncode == 0, checked.stderr
        stderr = (tmp/'stderr.log').open('w')
        process = subprocess.Popen([*command, '-g', 'daemon off;'], stdout=subprocess.DEVNULL, stderr=stderr)
        try:
            context = ssl._create_unverified_context()
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.1', http), timeout=.1): break
                except OSError: time.sleep(.05)
            for scheme, port in [('http', http), ('https', https), ('http', luci)]:
                for name, expected in [('known.png', 200), ('denied.png', 403), ('unavailable.png', 503)]:
                    request = urllib.request.Request(f'{scheme}://127.0.0.1:{port}{PREFIX}{name}')
                    try: response = urllib.request.urlopen(request, context=context)
                    except urllib.error.HTTPError as error: response = error
                    with response:
                        body = response.read()
                        assert response.status == expected, (port, response.status, body)
                        assert body == PNG if expected == 200 else (b'license_denied' if expected == 403 else b'resource_unavailable') in body
            for port in (http, luci):
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/luci-static/other.css') as response:
                    assert response.read() == b'legacy-static'
            print('PASS real Nginx: HTTP/HTTPS/LuCI exact-prefix precedence, PNG bytes, 403/503 bodies, unrelated LuCI static')
        except Exception:
            print((tmp/'error.log').read_text())
            print((tmp/'stderr.log').read_text())
            raise
        finally:
            process.terminate()
            process.wait(timeout=10)
            stderr.close()
            upstream.shutdown()


if __name__ == '__main__':
    test_proxy()
