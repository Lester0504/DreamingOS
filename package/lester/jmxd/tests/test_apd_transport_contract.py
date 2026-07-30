#!/usr/bin/env python3
"""Static and live TLS contract for the APD control transport."""

from __future__ import annotations

import hashlib
import json
import re
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import shlex
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/apd/apd_transport.c"
FIXTURE = ROOT / "tests/apd_transport_fixture.c"
WIRE = ROOT / "src/ap_control_wire.c"
_ENV_PREFIX = os.environ.get("APD_TEST_PREFIX", "")
_ENV_OPENSSL = os.environ.get("APD_TEST_OPENSSL_PREFIX", "")
JSON_PREFIX = (Path(_ENV_PREFIX) if _ENV_PREFIX else
               Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19"))
OPENSSL_PREFIX = (Path(_ENV_OPENSSL) if _ENV_OPENSSL else
                  (JSON_PREFIX if _ENV_PREFIX else
                   Path("/opt/homebrew/var/homebrew/tmp/.cellar/openssl@3/3.6.3")))
TOKEN = "A" * 43
PROTOCOL = "ap-control.v1"
PROTOCOL_V2 = "ap-control.v2"
CONTROLLER = "bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb"
CHALLENGE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
CERTIFICATE = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
RECOVERED_ENROLLMENT = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
AP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


FIELDS = {
    "enrollment_hello": {"protocol", "kind", "ap_id", "key_id", "public_key", "model", "board_name", "model_source", "model_available", "model_reason"},
    "enrollment_challenge": {"protocol", "kind", "controller_id", "challenge_id", "server_nonce", "expires_at"},
    "enrollment_claim": {"protocol", "kind", "challenge_id", "server_nonce", "client_nonce", "enrollment_id", "token_id", "token", "ap_id", "key_id", "public_key", "site_id", "hardware_digest", "csr_der", "csr_sha256", "challenge_expires_at", "signature"},
    "enrollment_certificate": {"protocol", "kind", "controller_id", "enrollment_id", "certificate_id", "certificate_der", "certificate_fingerprint", "ca_fingerprint"},
    "activation_hello": {"protocol", "kind", "controller_id", "enrollment_id", "certificate_id", "ap_id"},
    "activation_challenge": {"protocol", "kind", "enrollment_id", "certificate_id", "challenge"},
    "activation_response": {"protocol", "kind", "enrollment_id", "certificate_id", "challenge"},
    "activation_complete": {"protocol", "kind", "controller_id", "enrollment_id", "certificate_id", "certificate_fingerprint", "adopted"},
    "session_hello": {"protocol", "kind", "controller_id", "certificate_id", "ap_id"},
    "session_ready": {"protocol", "kind", "controller_id", "certificate_id", "ap_id", "session_epoch"},
    "heartbeat": {"protocol", "kind", "ap_id", "session_epoch", "sequence", "timestamp"},
    "heartbeat_ack": {"protocol", "kind", "ap_id", "session_epoch", "sequence"},
    "telemetry_snapshot": {"protocol", "kind", "schema", "version", "ap_id", "session_epoch", "sequence", "observed_at", "snapshot"},
    "telemetry_ack": {"protocol", "kind", "ap_id", "session_epoch", "sequence", "accepted"},
    "radio_job_reconcile": {"protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id", "attempt_id", "dispatch_generation", "request_digest", "radio_id", "mode", "state", "finish_id", "outcome", "error_code", "observed_at", "result_complete", "result"},
    "radio_job_reconcile_ack": {"protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id", "attempt_id", "dispatch_generation", "request_digest", "controller_state", "cancel_requested", "result_complete", "error_code"},
    "radio_job_poll": {"protocol", "kind", "ap_id", "session_epoch", "sequence"},
    "radio_job_idle": {"protocol", "kind", "ap_id", "session_epoch", "reply_to"},
    "radio_job_offer": {"protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id", "attempt_id", "dispatch_generation", "request_digest", "radio_id", "mode", "expected_impact", "controller_state", "cancel_requested"},
    "radio_job_accept": {"protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id", "attempt_id", "dispatch_generation", "request_digest"},
    "radio_job_accept_ack": {"protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id", "attempt_id", "dispatch_generation", "request_digest", "controller_state", "cancel_requested"},
    "radio_job_start": {"protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id", "attempt_id", "dispatch_generation", "request_digest"},
    "radio_job_start_ack": {"protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id", "attempt_id", "dispatch_generation", "request_digest", "controller_state", "cancel_requested"},
    "radio_job_finish": {"protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id", "attempt_id", "dispatch_generation", "request_digest", "finish_id", "outcome", "error_code", "result_complete", "result"},
    "radio_job_finish_ack": {"protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id", "attempt_id", "dispatch_generation", "request_digest", "finish_id", "controller_state", "cancel_requested", "result_complete", "error_code"},
    "error": {"protocol", "kind", "error", "reason"},
}


def command(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def generate_pki(root: Path) -> dict[str, Path]:
    paths = {name: root / name for name in (
        "ca.key", "ca.pem", "ca.der", "server.key", "server.csr", "server.pem",
        "client.key", "client.csr", "client.pem", "client.der")}
    command("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(paths["ca.key"]))
    command("openssl", "req", "-x509", "-new", "-key", str(paths["ca.key"]),
            "-out", str(paths["ca.pem"]), "-days", "2", "-subj", "/CN=APD Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    command("openssl", "x509", "-in", str(paths["ca.pem"]), "-outform", "DER",
            "-out", str(paths["ca.der"]))
    command("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(paths["server.key"]))
    command("openssl", "req", "-new", "-key", str(paths["server.key"]),
            "-out", str(paths["server.csr"]), "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1")
    extension = root / "server.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n", encoding="ascii")
    command("openssl", "x509", "-req", "-in", str(paths["server.csr"]),
            "-CA", str(paths["ca.pem"]), "-CAkey", str(paths["ca.key"]),
            "-CAcreateserial", "-out", str(paths["server.pem"]), "-days", "2",
            "-extfile", str(extension))
    command("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(paths["client.key"]))
    command("openssl", "req", "-new", "-key", str(paths["client.key"]),
            "-out", str(paths["client.csr"]), "-subj", "/CN=DreamingWrt AP",
            "-addext", f"subjectAltName=URI:urn:dreamingwrt:ap:{AP_ID}")
    extension = root / "client.ext"
    extension.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:dreamingwrt:ap:{AP_ID}\n", encoding="ascii")
    command("openssl", "x509", "-req", "-in", str(paths["client.csr"]),
            "-CA", str(paths["ca.pem"]), "-CAkey", str(paths["ca.key"]),
            "-CAcreateserial", "-out", str(paths["client.pem"]), "-days", "2",
            "-extfile", str(extension))
    command("openssl", "x509", "-in", str(paths["client.pem"]), "-outform", "DER",
            "-out", str(paths["client.der"]))
    for path in paths.values():
        path.chmod(0o600)
    return paths


def read_exact(stream: ssl.SSLSocket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        data = stream.recv(length - len(output))
        if not data:
            raise EOFError("short AP control frame")
        output.extend(data)
    return bytes(output)


def receive_any(stream: ssl.SSLSocket) -> dict[str, object]:
    length = struct.unpack("!I", read_exact(stream, 4))[0]
    assert 0 < length <= 65536
    message = json.loads(read_exact(stream, length).decode("utf-8"))
    assert isinstance(message, dict), message
    kind = str(message.get("kind"))
    assert kind in FIELDS, kind
    assert set(message) == FIELDS[kind], (kind, message.get("kind"), set(message))
    expected_protocol = (PROTOCOL_V2 if stream.selected_alpn_protocol() ==
                         "dreamingwrt-ap/2" else PROTOCOL)
    assert message["protocol"] == expected_protocol and message["kind"] == kind
    return message


def receive(stream: ssl.SSLSocket, kind: str) -> dict[str, object]:
    message = receive_any(stream)
    assert message["kind"] == kind, (kind, message["kind"])
    return message


def send(stream: ssl.SSLSocket, message: dict[str, object]) -> None:
    assert set(message) == FIELDS[str(message["kind"])]
    expected_protocol = (PROTOCOL_V2 if stream.selected_alpn_protocol() ==
                         "dreamingwrt-ap/2" else PROTOCOL)
    assert message["protocol"] == expected_protocol
    payload = json.dumps(message, separators=(",", ":")).encode("ascii")
    stream.sendall(struct.pack("!I", len(payload)) + payload)


def receive_after_optional_telemetry(stream: ssl.SSLSocket,
                                     session_epoch: str) -> dict[str, object]:
    message = receive_any(stream)
    if message["kind"] != "telemetry_snapshot":
        return message
    send(stream, {"protocol": PROTOCOL_V2, "kind": "telemetry_ack",
                  "ap_id": AP_ID, "session_epoch": session_epoch,
                  "sequence": message["sequence"], "accepted": True})
    return receive_any(stream)


def lowercase_hex(value: object, length: int | None = None) -> bool:
    if not isinstance(value, str) or not value or value != value.lower():
        return False
    if any(character not in "0123456789abcdef" for character in value):
        return False
    return length is None or len(value) == length * 2


def server(listener: socket.socket, context: ssl.SSLContext, paths: dict[str, Path],
           errors: list[BaseException]) -> None:
    try:
        client_der = paths["client.der"].read_bytes()
        client_digest = hashlib.sha256(client_der).hexdigest()
        ca_digest = hashlib.sha256(paths["ca.der"].read_bytes()).hexdigest()
        enrollment_id = RECOVERED_ENROLLMENT
        enrollment_attempts = 0
        activation_attempts = 0
        session_attempts = 0
        first_finish_id: str | None = None
        while True:
            with context.wrap_socket(listener.accept()[0], server_side=True) as tls:
                assert tls.version() == "TLSv1.3"
                selected_alpn = tls.selected_alpn_protocol()
                assert selected_alpn in ("dreamingwrt-ap/1", "dreamingwrt-ap/2")
                peer_der = tls.getpeercert(binary_form=True)
                if peer_der is None:
                    # Certificate delivery and the TLS close can race. A retry is
                    # a valid idempotent enrollment recovery, but it must still
                    # present the complete token-bound enrollment exchange.
                    enrollment_attempts += 1
                    assert enrollment_attempts <= 5
                    challenge_id = (
                        CHALLENGE if enrollment_attempts == 1 else
                        f"cccccccc-cccc-4ccc-8ccc-{enrollment_attempts:012x}"
                    )
                    hello = receive(tls, "enrollment_hello")
                    assert hello["ap_id"] == AP_ID
                    assert lowercase_hex(hello["public_key"], 32)
                    send(tls, {
                        "protocol": PROTOCOL,
                        "kind": "enrollment_challenge",
                        "controller_id": CONTROLLER,
                        "challenge_id": challenge_id,
                        "server_nonce": "11" * 32,
                        "expires_at": int(time.time()) + 120,
                    })
                    claim = receive(tls, "enrollment_claim")
                    assert str(claim["enrollment_id"]) != enrollment_id
                    assert claim["token"] == TOKEN
                    assert claim["challenge_id"] == challenge_id
                    for key, size in (("server_nonce", 32), ("client_nonce", 32),
                                      ("public_key", 32), ("csr_sha256", 32),
                                      ("signature", 64)):
                        assert lowercase_hex(claim[key], size), key
                    assert lowercase_hex(claim["csr_der"])
                    send(tls, {
                        "protocol": PROTOCOL,
                        "kind": "enrollment_certificate",
                        "controller_id": CONTROLLER,
                        "enrollment_id": enrollment_id,
                        "certificate_id": CERTIFICATE,
                        "certificate_der": client_der.hex(),
                        "certificate_fingerprint": client_digest,
                        "ca_fingerprint": ca_digest,
                    })
                    continue
                assert peer_der == client_der, (
                    activation_attempts,
                    hashlib.sha256(peer_der).hexdigest(),
                    hashlib.sha256(client_der).hexdigest())
                hello = receive_any(tls)
                if hello["kind"] == "session_hello":
                    assert selected_alpn == "dreamingwrt-ap/2"
                    session_attempts += 1
                    wire_protocol = PROTOCOL_V2
                    session_epoch = (("33" if session_attempts == 1 else "55") * 32)
                    controller_sequence = 1000
                    send(tls, {"protocol": wire_protocol, "kind": "session_ready",
                               "controller_id": CONTROLLER,
                               "certificate_id": CERTIFICATE,
                               "ap_id": AP_ID,
                               "session_epoch": session_epoch})
                    first_job_frame = receive_any(tls)
                    if first_job_frame["kind"] == "telemetry_snapshot":
                        telemetry = first_job_frame
                        assert telemetry["schema"] == "apd-backend.snapshot"
                        assert telemetry["version"] == 1
                        assert telemetry["ap_id"] == AP_ID
                        assert telemetry["session_epoch"] == session_epoch
                        snapshot = telemetry["snapshot"]
                        assert isinstance(snapshot, dict)
                        assert snapshot["snapshot_version"] == "wireless-snapshot.v1"
                        assert snapshot["model"] == "Fixture AP 1"
                        assert snapshot["model_available"] is True
                        assert len(snapshot["radios"]) == 1
                        survey = snapshot["radios"][0]["survey"]
                        assert survey["source"] == "iw_survey"
                        assert survey["channel_active_time_ms"] == 1000
                        assert survey["channel_busy_time_ms"] == 200
                        assert len(snapshot["ssids"]) == 1
                        assert snapshot["stations"] == []
                        send(tls, {"protocol": wire_protocol,
                                   "kind": "telemetry_ack", "ap_id": AP_ID,
                                   "session_epoch": session_epoch,
                                   "sequence": telemetry["sequence"],
                                   "accepted": True})
                        first_job_frame = receive_any(tls)
                    job = {
                        "job_id": "11111111-1111-4111-8111-111111111111",
                        "attempt_id": "22222222-2222-4222-8222-222222222222",
                        "dispatch_generation": 1,
                        "request_digest": "sha256:" + "44" * 32,
                    }
                    if first_job_frame["kind"] == "radio_job_reconcile":
                        reconcile = first_job_frame
                        assert reconcile["session_epoch"] == session_epoch
                        assert reconcile["state"] == "completed"
                        assert reconcile["finish_id"] == first_finish_id
                        assert reconcile["outcome"] == "completed"
                        assert reconcile["error_code"] == ""
                        assert reconcile["result_complete"] is True
                        assert len(reconcile["result"]) == 1
                        assert all(reconcile[key] == value
                                   for key, value in job.items())
                        send(tls, {"protocol": wire_protocol,
                                   "kind": "radio_job_finish_ack",
                                   "ap_id": AP_ID,
                                   "session_epoch": session_epoch,
                                   "reply_to": reconcile["sequence"], **job,
                                   "finish_id": reconcile["finish_id"],
                                   "controller_state": "completed",
                                   "cancel_requested": False,
                                   "result_complete": True,
                                   "error_code": ""})
                        poll = receive(tls, "radio_job_poll")
                        send(tls, {"protocol": wire_protocol,
                                   "kind": "radio_job_idle", "ap_id": AP_ID,
                                   "session_epoch": session_epoch,
                                   "reply_to": poll["sequence"]})
                        for _ in range(2):
                            heartbeat = receive(tls, "heartbeat")
                            send(tls, {"protocol": wire_protocol,
                                       "kind": "heartbeat_ack", "ap_id": AP_ID,
                                       "session_epoch": session_epoch,
                                       "sequence": heartbeat["sequence"]})
                            poll = receive_after_optional_telemetry(
                                tls, session_epoch)
                            assert poll["kind"] == "radio_job_poll"
                            send(tls, {"protocol": wire_protocol,
                                       "kind": "radio_job_idle", "ap_id": AP_ID,
                                       "session_epoch": session_epoch,
                                       "reply_to": poll["sequence"]})
                        time.sleep(2)
                        break
                    poll = first_job_frame
                    assert poll["kind"] == "radio_job_poll"
                    controller_sequence += 1
                    send(tls, {"protocol": wire_protocol,
                               "kind": "radio_job_offer", "ap_id": AP_ID,
                               "session_epoch": session_epoch,
                               "reply_to": poll["sequence"], **job,
                               "radio_id": "phy0", "mode": "neighbor",
                               "expected_impact": "brief_radio_scan",
                               "controller_state": "leased",
                               "cancel_requested": False})
                    accept = receive(tls, "radio_job_accept")
                    assert all(accept[key] == value for key, value in job.items())
                    controller_sequence += 1
                    send(tls, {"protocol": wire_protocol,
                               "kind": "radio_job_accept_ack", "ap_id": AP_ID,
                               "session_epoch": session_epoch,
                               "reply_to": accept["sequence"], **job,
                               "controller_state": "leased",
                               "cancel_requested": False})
                    start = receive(tls, "radio_job_start")
                    assert all(start[key] == value for key, value in job.items())
                    controller_sequence += 1
                    send(tls, {"protocol": wire_protocol,
                               "kind": "radio_job_start_ack", "ap_id": AP_ID,
                               "session_epoch": session_epoch,
                               "reply_to": start["sequence"], **job,
                               "controller_state": "running",
                               "cancel_requested": False})
                    finish = receive(tls, "radio_job_finish")
                    assert all(finish[key] == value for key, value in job.items())
                    assert finish["outcome"] == "completed"
                    assert finish["result_complete"] is True
                    assert len(finish["result"]) == 1
                    assert finish["result"][0]["ssid"] == "Neighbor"
                    first_finish_id = str(finish["finish_id"])
                    # Simulate AC commit with a lost finish ACK.
                    continue
                assert hello["kind"] == "activation_hello", hello
                assert hello["enrollment_id"] == enrollment_id
                activation_attempts += 1
                if activation_attempts == 1:
                    challenge = "22" * 32
                    send(tls, {"protocol": PROTOCOL, "kind": "activation_challenge",
                               "enrollment_id": enrollment_id,
                               "certificate_id": CERTIFICATE,
                               "challenge": challenge})
                    response = receive(tls, "activation_response")
                    assert response["challenge"] == challenge
                # The first complete is committed by AC but deliberately fails
                # the fixture's local APD commit. A retry must accept AC's
                # immediate idempotent complete without waiting for a challenge.
                send(tls, {"protocol": PROTOCOL, "kind": "activation_complete",
                           "controller_id": CONTROLLER,
                           "enrollment_id": enrollment_id,
                           "certificate_id": CERTIFICATE,
                           "certificate_fingerprint": client_digest,
                           "adopted": True})
                assert activation_attempts <= 5
    except BaseException as error:
        errors.append(error)


def static_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert '#define APD_TRANSPORT_PROTOCOL_V1 "ap-control.v1"' in source
    assert '#define APD_TRANSPORT_PROTOCOL_V2 "ap-control.v2"' in source
    assert 'AP_CONTROL_ALPN_V2 "\\x10" AP_CONTROL_ALPN_V1' in source
    assert "TLS1_3_VERSION" in source and "SSL_set1_host" in source
    assert "X509_VERIFY_PARAM_set1_ip_asc" in source
    assert "SSL_set_alpn_protos" in source and "ap_control_ssl_selected_alpn" in source
    assert "AP_CONTROL_IO_TIMEOUT_MS" in source and "AP_CONTROL_FRAME_MAX" in source
    assert "APD_TRANSPORT_BACKOFF_MAX_SECONDS 60" in source
    assert "apd_transport_adopted" in source and "apd_transport_reason" in source
    assert "connection.protocol_version == 2" in source
    poll_block = source[source.index("static int apd_v2_poll("):
                        source.index("static int apd_session_run(")]
    execute_start = source.index("static int apd_v2_execute(\n    SSL")
    execute_end = source.index("static int apd_v2_poll(SSL", execute_start)
    execute_block = source[execute_start:execute_end]
    assert poll_block.index("apd_radio_job_offer_store(&job") < poll_block.index(
        '"radio_job_accept"')
    assert poll_block.index("apd_radio_job_mark_running(&job") < poll_block.index(
        '"radio_job_start"')
    assert execute_block.index("apd_v2_finish_store(job") < execute_block.index(
        "apd_v2_finish_send(ssl")
    assert "apd_radio_job_pending_finish_get" in source
    assert "apd_radio_job_pending_reconcile_get" in source
    assert "apd_radio_job_session_rebind" in source
    # Phase W2c dormancy: the config job wire is compiled but the gate is a
    # hard compile-time 0 in production, and the wire step only runs when
    # the gate is set.
    assert "#ifdef APD_CONFIG_JOBS_TEST_ENABLE" in source
    jobs_step = source[source.index("static int apd_v2_jobs_step("):
                       source.index("static int apd_v2_accept_or_start(")]
    assert "apd_config_executor_enabled()" in jobs_step
    assert jobs_step.index("apd_config_executor_enabled()") < jobs_step.index(
        "apd_config_wire_step(ssl")
    config_start = source.index("static int apd_config_execute(")
    # Skip the forward declaration that precedes apd_config_execute.
    config_end = source.index("static int apd_config_wire_step(",
                              config_start)
    config_block = source[config_start:config_end]
    # Executor ordering: stage -> capture rollback reference -> persist the
    # applying state -> mutate live config -> persist applied -> readback.
    # The rollback reference must be durable before the first live mutation.
    assert config_block.index("apd_config_stage(") < config_block.index(
        "apd_config_capture_previous(")
    assert config_block.index("apd_config_capture_previous(") < \
        config_block.index("apd_config_job_mark_applying(")
    assert config_block.index("apd_config_job_mark_applying(") < \
        config_block.index("apd_config_apply_prepared(")
    assert config_block.index("apd_config_apply_prepared(") < \
        config_block.index("apd_config_job_mark_applied(")
    assert config_block.index("apd_config_job_mark_applied(") < \
        config_block.index("apd_config_readback(")
    assert config_block.index("apd_config_job_finish_store(") < \
        config_block.index("apd_config_finish_send(")
    assert 'error_code = "readback_mismatch"' in config_block
    wire_step = source[config_end:source.index("static int apd_session_run(")]
    assert wire_step.index("apd_config_job_offer_store(") < wire_step.index(
        "apd_config_accept(")
    assert wire_step.index("apd_config_accept(") < wire_step.index(
        "apd_config_execute(")
    assert 'strcmp(pending.entry.state, "completed")' in source
    assert 'strcmp(pending.entry.state, "failed")' in source
    assert "apd_backend_neighbor_scan(job->radio_id" in source
    assert "apd_backend_survey_scan(job->radio_id" in source
    assert '!strcmp(name, "survey")' in source
    assert '"radio_job_mode_unsupported"' in source
    production = source.split("#else", 1)[1]
    assert "struct apd_bootstrap_config {" not in production.split("#endif", 1)[0]
    for kind, fields in FIELDS.items():
        marker = f"apd_fields_{kind}[]"
        assert marker in source, marker
        block = source[source.index(marker):source.index("};", source.index(marker))]
        for field in fields:
            assert f'"{field}"' in block, (kind, field)
    log_calls = [line for line in source.splitlines() if "apd_transport_log(" in line]
    assert all("token" not in line and "body" not in line and "csr" not in line
               for line in log_calls)


def compile_fixture(binary: Path) -> None:
    compiler = shlex.split(os.environ.get("CC", "cc"))
    json_archive = JSON_PREFIX / "lib/libjson-c.a"
    assert json_archive.is_file()
    command(*compiler, "-std=c11",
            "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Werror", f"-I{ROOT / 'src'}",
            f"-I{JSON_PREFIX / 'include'}", f"-I{OPENSSL_PREFIX / 'include'}",
            str(FIXTURE), str(WIRE), str(json_archive),
            f"-L{OPENSSL_PREFIX / 'lib'}",
            f"-Wl,-rpath,{OPENSSL_PREFIX / 'lib'}", "-lssl",
            "-lcrypto", "-lpthread", "-o", str(binary))


def live_contract(root: Path) -> None:
    paths = generate_pki(root)
    pki = root / "pki"
    pki.mkdir(mode=0o700)
    binary = root / "fixture"
    compile_fixture(binary)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(paths["server.pem"], paths["server.key"])
    context.load_verify_locations(paths["ca.pem"])
    context.verify_mode = ssl.CERT_OPTIONAL
    context.set_alpn_protocols(["dreamingwrt-ap/2", "dreamingwrt-ap/1"])
    errors: list[BaseException] = []
    worker = threading.Thread(target=server,
                              args=(listener, context, paths, errors), daemon=True)
    worker.start()
    runtime_env = os.environ.copy()
    runtime_env["DYLD_LIBRARY_PATH"] = str(OPENSSL_PREFIX / "lib")
    runtime_env["LD_LIBRARY_PATH"] = str(OPENSSL_PREFIX / "lib")
    result = subprocess.run(
        [str(binary), str(pki), str(paths["ca.pem"]), str(paths["client.key"]),
         str(paths["client.csr"]), str(listener.getsockname()[1])],
        env=runtime_env, check=False, capture_output=True, text=True,
        timeout=int(os.environ.get("APD_TRANSPORT_TEST_TIMEOUT", "40")))
    worker.join(timeout=5)
    listener.close()
    if errors:
        raise AssertionError(
            f"server failed: {errors[0]!r}\n"
            f"fixture rc={result.returncode}\nstdout={result.stdout}\n"
            f"stderr={result.stderr}"
        ) from errors[0]
    assert not worker.is_alive()
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "telemetry_gate=3 survey_30s_suppressed=12 forced_refresh_s=300" in result.stdout
    snapshot_match = re.search(r"snapshot_calls=(\d+)", result.stdout)
    assert snapshot_match and int(snapshot_match.group(1)) >= 3, result.stdout
    assert result.stdout.strip().startswith(
        "ok: APD TLS enrollment, activation, v2 radio job, heartbeat, telemetry, and state")
    assert TOKEN not in result.stdout + result.stderr


def main() -> None:
    static_contract()
    with tempfile.TemporaryDirectory(prefix="apd-transport-") as raw:
        live_contract(Path(raw))
    print("ok: APD transport v1 enrollment/activation, v2 radio job, strict reply binding, Survey-only 30s suppression, 300s forced refresh, and heartbeat continuity")


if __name__ == "__main__":
    main()
