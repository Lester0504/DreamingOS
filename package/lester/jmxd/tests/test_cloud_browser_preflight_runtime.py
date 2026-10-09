#!/usr/bin/env python3
"""Real TLS and resolver preflight; only the cloud binding lookup is substituted."""
import http.server
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            pass

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        body = b'{"ok":true,"rp_id":"localhost"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

with tempfile.TemporaryDirectory(prefix="cloud-preflight-") as tmp:
    p = Path(tmp)
    cert, key = p / "tls.crt", p / "tls.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "libcurl", "openssl", "json-c"], text=True))
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                        *shlex.split(os.environ.get("CFLAGS", "")),
                        f"-DCLOUD_BROWSER_HTTPS_PORT={port}",
                        str(ROOT / "tests/cloud_browser_preflight_fixture.c"),
                        str(ROOT / "src/cloud/cloud_browser_preflight.c"),
                        "-o", str(p / "test"), *flags], check=True)
        subprocess.run([str(p / "test"), str(cert), str(port)], check=True, timeout=30)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
