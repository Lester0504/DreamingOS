#!/usr/bin/env python3
"""Exercise the real APD TLS session against an authenticated unbind response."""
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading

import test_apd_transport_contract as transport


def run_case(root, binary, paths, fail=False, malformed=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(paths["server.pem"], paths["server.key"])
    context.load_verify_locations(paths["ca.pem"])
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["dreamingwrt-ap/2"])
    request_id = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    received, errors = [], []

    def serve():
        try:
            sock, _ = listener.accept()
            with context.wrap_socket(sock, server_side=True) as tls:
                hello = transport.receive(tls, "session_hello")
                ready = dict(hello, kind="session_ready", session_epoch="a" * 64,
                             unbind_required=True,
                             unbind_request_id="invalid" if malformed else request_id)
                payload = json.dumps(ready).encode("ascii")
                tls.sendall(struct.pack("!I", len(payload)) + payload)
                if malformed:
                    try:
                        assert tls.recv(1) == b""
                    except ssl.SSLError:
                        pass
                    return
                length = struct.unpack("!I", transport.read_exact(tls, 4))[0]
                ack = json.loads(transport.read_exact(tls, length))
                assert ack == dict(protocol=transport.PROTOCOL_V2, kind="unbind_ack",
                                   ap_id=transport.AP_ID, session_epoch="a" * 64,
                                   request_id=request_id, unpaired=not fail,
                                   error_code="credentials_unpair_failed" if fail else "")
                received.append(ack)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    pki = root / ("failed" if fail else "malformed" if malformed else "success")
    pki.mkdir()
    env = dict(os.environ, APD_TEST_UNBIND="1",
               APD_TEST_CLIENT_CERT=str(paths["client.pem"]))
    if fail:
        env["APD_TEST_UNBIND_FAIL"] = "1"
    result = subprocess.run(
        [str(binary), str(pki), str(paths["ca.pem"]), str(paths["client.key"]),
         str(paths["client.csr"]), str(listener.getsockname()[1])],
        env=env, capture_output=True, text=True, timeout=15)
    worker.join(10)
    listener.close()
    assert not worker.is_alive() and not errors, (errors, result.returncode, result.stderr)
    assert result.returncode == (14 if malformed else 0), result.stderr
    assert len(received) == (0 if malformed else 1)


def main():
    with tempfile.TemporaryDirectory(prefix="apd-unbind-") as directory:
        root = Path(directory)
        paths = transport.generate_pki(root)
        binary = root / "fixture"
        transport.compile_fixture(binary)
        run_case(root, binary, paths)
        run_case(root, binary, paths, fail=True)
        run_case(root, binary, paths, malformed=True)
    print("PASS: APD mTLS unbind success, cleanup failure ACK, malformed request rejection")


if __name__ == "__main__":
    main()
