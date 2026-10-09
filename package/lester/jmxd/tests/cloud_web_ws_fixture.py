#!/usr/bin/env python3
"""Opt-in interop fixture; requires websockets 15.0.1 in the test environment."""
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading

from websockets.client import ClientProtocol
from websockets.frames import Frame, OP_BINARY, OP_TEXT, OP_CONT, OP_PING, OP_PONG, OP_CLOSE, Close
from websockets.http11 import Response
from websockets.datastructures import Headers
from websockets.sync.server import serve
from websockets.uri import parse_uri


def run(binary):
    with tempfile.TemporaryDirectory(prefix="cwc-ws-") as directory:
        root = Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "key"), "-out", str(root / "ca"),
                        "-days", "1", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "ca", root / "key")
        protocol = ClientProtocol(parse_uri("wss://nas.apps.dreamingnet.com/ws"),
                                  origin="https://nas.apps.dreamingnet.com",
                                  subprotocols=["cloud-test"], max_size=16 * 1024 * 1024)
        protocol.send_request(protocol.connect())
        protocol.data_to_send()
        payload = bytes(range(256)) * (32768 + 1)
        frames = [Frame(OP_TEXT, b"frag-", fin=False), Frame(OP_PING, b"probe"),
                  Frame(OP_CONT, "\u6d4b\u8bd5".encode()), Frame(OP_BINARY, payload)]
        (root / "input").write_bytes(b"".join(f.serialize(mask=True) for f in frames))
        (root / "close").write_bytes(Frame(OP_CLOSE, Close(1000, "done").serialize()).serialize(mask=True))

        def handler(ws):
            assert ws.request.headers["Host"] == "nas.apps.dreamingnet.com"
            assert ws.request.headers["Origin"] == "https://nas.apps.dreamingnet.com"
            assert ws.subprotocol == "cloud-test"
            try:
                ws.send("ready")
                for message in ws:
                    ws.send(message)
            except Exception as error:
                # Revocation deliberately tears down without a close handshake.
                if type(error).__name__ != "ConnectionClosedError":
                    raise

        def process_request(connection, request):
            if request.path == "/reject":
                return Response(401, "Unauthorized", Headers([
                    ("Transfer-Encoding", "chunked"), ("Connection", "close"),
                    ("WWW-Authenticate", "Bearer")]), b"3\r\nden\r\n3\r\nied\r\n0\r\n\r\n")

        def process_response(connection, request, response):
            if request.path == "/bad-accept":
                del response.headers["Sec-WebSocket-Accept"]
                response.headers["Sec-WebSocket-Accept"] = "invalid"
            return response

        with serve(handler, "127.0.0.1", 0, ssl=context, compression=None,
                   subprotocols=["cloud-test"], process_request=process_request,
                   process_response=process_response, max_size=16 * 1024 * 1024,
                   close_timeout=2) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = dict(os.environ, CWC_TEST_WS_PORT=str(server.socket.getsockname()[1]),
                       CWC_TEST_WS_DIR=str(root), CWC_TEST_WS_CA=str(root / "ca"),
                       CWC_TEST_WS_KEY=protocol.key)
            result = subprocess.run([binary], env=env)
            if result.returncode:
                raise RuntimeError(f"C WebSocket tests failed: {result.returncode}")
        protocol.receive_data((root / "output-0").read_bytes())
        events = protocol.events_received()
        assert protocol.handshake_exc is None, protocol.handshake_exc
        assert any(isinstance(e, Response) and e.status_code == 101 for e in events)
        data = [e for e in events if isinstance(e, Frame)]
        assert any(e.opcode == OP_TEXT and e.data == b"ready" for e in data)
        assert any(e.opcode == OP_TEXT and e.data == "frag-\u6d4b\u8bd5".encode() for e in data)
        assert any(e.opcode == OP_PONG and e.data == b"probe" for e in data)
        assert any(e.opcode == OP_BINARY and e.data == payload for e in data)
        assert any(e.opcode == OP_CLOSE and Close.parse(e.data).code == 1000 for e in data)
        assert (root / "output-2").read_bytes().endswith(b"denied")
        print("PASS WebSocket TLS interop: fragmented UTF-8, ping/pong, 8 MiB binary, close, rejection, bad accept, CA/name, revocation")


if __name__ == "__main__":
    run(sys.argv[1])
