#!/usr/bin/env python3
"""Linux loopback-only probe integration. No router access or privileged commands."""
import http.server
import socket
import struct
import subprocess
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status = 503 if self.path == "/bad" else 302 if self.path == "/redirect" else 200
        self.send_response(status)
        self.send_header("Location", "http://192.0.2.1/")
        self.end_headers()
        self.wfile.write(b"expected-marker")

    def log_message(self, *_):
        pass


def main():
    binary = sys.argv[1]
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("127.0.0.1", 0))
    dns.settimeout(0.1)
    stop = threading.Event()

    def answer():
        while not stop.is_set():
            try:
                data, peer = dns.recvfrom(4096)
            except socket.timeout:
                continue
            end = 12
            while data[end]:
                end += data[end] + 1
            end += 1
            qtype = struct.unpack("!H", data[end:end+2])[0]
            question = data[12:end+4]
            count = 1 if qtype == 1 else 0
            header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0)
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
            dns.sendto(header + question + (rr if count else b""), peer)

    dns_thread = threading.Thread(target=answer, daemon=True)
    dns_thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    cases = [
        ("icmp", "127.0.0.1", "success"),
        ("tcp", f"tcp://127.0.0.1:{server.server_port}", "success"),
        ("dns", f"dns://127.0.0.1:{dns.getsockname()[1]}/probe.example", "success"),
        ("http", base + "/", "success"),
        ("http", base + "/", "body"),
        ("http", base + "/", "body-mismatch"),
        ("http", base + "/bad", "expect-503"),
        ("http", base + "/bad", "status"),
        ("http", base + "/redirect", "status"),
        ("http", base + "/", "device"),
        ("icmp", "-bad", "invalid"),
    ]
    try:
        for args in cases:
            subprocess.run([binary, *args], check=True, timeout=5)
    finally:
        stop.set()
        dns_thread.join()
        dns.close()
        server.shutdown()
        thread.join()
        server.server_close()
    print(f"ok: {len(cases)} bound probe integration cases")


if __name__ == "__main__":
    main()
