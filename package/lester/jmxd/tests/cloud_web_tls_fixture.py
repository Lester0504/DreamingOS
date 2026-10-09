#!/usr/bin/env python3
"""Run the C client tests against a real, temporary HTTPS upstream."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import hashlib
import json


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    publication_mode = -1

    def publication(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.endswith("/challenge"):
            data = {"nonce": "0" * 32, "router_id": "router-" + "a" * 32}
        else:
            request = request["request"]
            if request["operation"] == "read":
                Handler.publication_mode += 1
            mode = Handler.publication_mode
            data = {"cloud_id": "a" * 32, "canonical_host": "test.dev.dreamingnet.com",
                    "generation": 1, "revision": 1}
            if mode > 0:
                data.update(features_v1=3 if mode != 2 else 0, negotiated_v1=0,
                            account_service_limit=4, account_services=1, device_services=1,
                            account_connection_limit=2, account_bandwidth_bps=8000000)
            if request["operation"] == "replace":
                if mode == 0:
                    assert "features_v1" not in request
                else:
                    assert request["features_v1"] == (0 if mode == 2 else 3)
                    data["negotiated_v1"] = request["features_v1"]
                data.update(generation=2, revision=2)
            if mode == 3:
                data["negotiated_v1"] = 4  # impossible subset: reject, never publish
            if mode == 4:
                data["account_services"] = "1"  # typed quota contract
        body = json.dumps({"ok": True, "data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass  # The negative certificate cases intentionally abort TLS.

    def do_POST(self):
        if self.path.startswith("/api/v1/cloud/web-access/agent/"):
            self.publication()
            return
        if self.path == "/reject-upload":
            self.send_response(413)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.close_connection = True
            return
        chunked = self.headers.get("Transfer-Encoding") == "chunked"
        assert not (chunked and self.headers.get("Content-Length"))
        remaining = 0 if chunked else int(self.headers["Content-Length"])
        total = 0
        digest = hashlib.sha256()
        while True:
            if chunked and not remaining:
                line = self.rfile.readline(128)
                if not line:
                    return
                remaining = int(line.strip(), 16)
                if not remaining:
                    assert self.rfile.read(2) == b"\r\n"
                    break
            elif not remaining:
                break
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                return
            digest.update(chunk)
            total += len(chunk)
            remaining -= len(chunk)
            if chunked and not remaining:
                assert self.rfile.read(2) == b"\r\n"
        body = json.dumps({"bytes": total, "sha256": digest.hexdigest()}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(8):
                if i:
                    time.sleep(10 if os.environ.get("CWC_TEST_LONG_SSE") else .05)
                body = f"data: {i}\n\n".encode()
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        body = b"cloud-https-upstream"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


with tempfile.TemporaryDirectory(prefix="cwc-https-") as directory:
    root = Path(directory)
    with (root / "openssl.log").open("w") as log:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "key"), "-out", str(root / "ca"),
                        "-days", "1", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, stdout=log, stderr=log)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "ca", root / "key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ, CWC_TEST_TLS_PORT=str(server.server_port),
                   CWC_TEST_TLS_CA=str(root / "ca"))
        result = subprocess.run([sys.argv[1]], env=env)
    finally:
        server.shutdown()
        server.server_close()
    sys.exit(result.returncode)
