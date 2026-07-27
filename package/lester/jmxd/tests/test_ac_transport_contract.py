#!/usr/bin/env python3
"""Contract and live TLS tests for the DreamingWrt AC node listener."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_transport.c"
WIRE = ROOT / "src/ap_control_wire.c"
FIXTURE = ROOT / "tests/ac_transport_runtime_fixture.c"
TELEMETRY_FIXTURE = ROOT / "tests/ac_transport_telemetry_fixture.c"
HEADER = ROOT / "tests/ac_enrollment_fixture.h"
TRANSPORT_HEADER = ROOT / "tests/ac_transport_fixture.h"
OPENSSL = Path("/opt/homebrew/opt/openssl@3")
JSON_C = Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
PROTOCOL = "ap-control.v1"
ALPN = "dreamingwrt-ap/1"
PROTOCOL_V2 = "ap-control.v2"
ALPN_V2 = "dreamingwrt-ap/2"
CONTROLLER_ID = "11111111-1111-5111-8111-111111111111"
AP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def lowercase_hex(value: object, length: int | None = None) -> bool:
    if not isinstance(value, str) or not value or value != value.lower():
        return False
    if any(character not in "0123456789abcdef" for character in value):
        return False
    return length is None or len(value) == length * 2


def compile_fixture(output: Path) -> None:
    prefix = Path(os.environ.get("AC_TRANSPORT_TEST_PREFIX", OPENSSL))
    json_prefix = Path(os.environ.get("AC_TRANSPORT_JSON_PREFIX", JSON_C))
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_TRANSPORT_TEST_STANDALONE", "-Wall", "-Wextra", "-Werror",
        f"-include{TRANSPORT_HEADER}",
        f"-I{prefix / 'include'}", f"-I{json_prefix / 'include'}",
        f"-L{prefix / 'lib'}", f"-Wl,-rpath,{prefix / 'lib'}",
        str(FIXTURE), str(TELEMETRY_FIXTURE), str(SOURCE), str(WIRE),
        "-lssl", "-lcrypto", str(json_prefix / "lib/libjson-c.a"),
        "-lpthread", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def protocol_version_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    wire_header = (ROOT / "src/ap_control_wire.h").read_text(encoding="utf-8")
    assert '#define AC_TRANSPORT_PROTOCOL_V1 "ap-control.v1"' in source
    assert '#define AC_TRANSPORT_PROTOCOL_V2 "ap-control.v2"' in source
    assert "AP_CONTROL_ALPN_V2" in source and "AP_CONTROL_ALPN_V1" in source
    assert '#define AP_CONTROL_ALPN_V2 "dreamingwrt-ap/2"' in wire_header
    assert "ap_control_ssl_selected_alpn_version" in source


def read_line(process: subprocess.Popen[str], timeout: float = 10) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert process.poll() is None, process.stderr.read() if process.stderr else ""
        assert process.stdout is not None
        line = process.stdout.readline()
        if line:
            return line.strip()
    raise AssertionError("fixture did not report listener state")


def frame_send(connection: ssl.SSLSocket, value: object) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def frame_receive(connection: ssl.SSLSocket) -> dict[str, object]:
    header = connection.recv(4)
    assert len(header) == 4
    length = struct.unpack("!I", header)[0]
    assert 0 < length <= 64 * 1024
    payload = bytearray()
    while len(payload) < length:
        chunk = connection.recv(length - len(payload))
        assert chunk
        payload.extend(chunk)
    value = json.loads(payload)
    assert isinstance(value, dict)
    return value


def wait_for_file(path: Path, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.01)
    raise AssertionError(f"fixture did not create {path.name}")


def client_context(directory: Path, mtls: bool = False,
                   alpn: str = ALPN,
                   minimum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
                   maximum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = minimum
    context.maximum_version = maximum
    context.check_hostname = False
    context.load_verify_locations(directory / "ca.pem")
    context.set_alpn_protocols([alpn])
    if mtls:
        context.load_cert_chain(directory / "client.pem", directory / "client.key")
    return context


def connect(directory: Path, port: int, mtls: bool = False,
            alpn: str = ALPN) -> ssl.SSLSocket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    return client_context(directory, mtls=mtls, alpn=alpn).wrap_socket(
        raw, server_hostname="127.0.0.1"
    )


def enrollment_challenge(directory: Path, port: int) -> None:
    hello = {
        "protocol": PROTOCOL,
        "kind": "enrollment_hello",
        "ap_id": AP_ID,
        "key_id": "sha256:" + "a" * 64,
        "public_key": "11" * 32,
        "model": "Fixture AP 1",
        "board_name": "fixture,ap1",
        "model_source": "ubus_system_board",
        "model_available": True,
        "model_reason": "",
    }
    with connect(directory, port) as connection:
        assert connection.version() == "TLSv1.3"
        assert connection.selected_alpn_protocol() == ALPN
        frame_send(connection, hello)
        response = frame_receive(connection)
        assert set(response) == {
            "protocol", "kind", "controller_id", "challenge_id",
            "server_nonce", "expires_at",
        }
        assert response["protocol"] == PROTOCOL
        assert response["kind"] == "enrollment_challenge"
        assert response["controller_id"] == CONTROLLER_ID
        assert len(str(response["server_nonce"])) == 64
        assert int(response["expires_at"]) > int(time.time())


def invalid_request_is_secret_free(directory: Path, port: int) -> None:
    token = "S" * 43
    with connect(directory, port) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "enrollment_hello",
            "ap_id": AP_ID,
            "key_id": "sha256:" + "a" * 64,
            "public_key": "11" * 32,
            "model": "Fixture AP 1",
            "board_name": "fixture,ap1",
            "model_source": "ubus_system_board",
            "model_available": True,
            "model_reason": "",
            "token": token,
        })
        response = frame_receive(connection)
        encoded = json.dumps(response, separators=(",", ":"))
        assert response == {
            "protocol": PROTOCOL,
            "kind": "error",
            "error": "invalid_request",
            "reason": "enrollment_request_rejected",
        }
        assert token not in encoded and "public_key" not in encoded


def enrollment_claim(directory: Path, port: int) -> tuple[str, str]:
    token = "S" * 43
    enrollment_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    token_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    with connect(directory, port) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "enrollment_hello",
            "ap_id": AP_ID,
            "key_id": "sha256:" + "a" * 64,
            "public_key": "11" * 32,
            "model": "Fixture AP 1",
            "board_name": "fixture,ap1",
            "model_source": "ubus_system_board",
            "model_available": True,
            "model_reason": "",
        })
        challenge = frame_receive(connection)
        csr = bytes.fromhex("3003020101")
        import hashlib
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "enrollment_claim",
            "challenge_id": challenge["challenge_id"],
            "server_nonce": challenge["server_nonce"],
            "client_nonce": "33" * 32,
            "enrollment_id": enrollment_id,
            "token_id": token_id,
            "token": token,
            "ap_id": AP_ID,
            "key_id": "sha256:" + "a" * 64,
            "public_key": "11" * 32,
            "site_id": "default",
            "hardware_digest": "",
            "csr_der": csr.hex(),
            "csr_sha256": hashlib.sha256(csr).hexdigest(),
            "challenge_expires_at": challenge["expires_at"],
            "signature": "44" * 64,
        })
        response = frame_receive(connection)
        assert set(response) == {
            "protocol", "kind", "controller_id", "enrollment_id",
            "certificate_id", "certificate_der", "certificate_fingerprint",
            "ca_fingerprint",
        }
        assert response["kind"] == "enrollment_certificate"
        assert response["enrollment_id"] == enrollment_id
        assert len(str(response["certificate_fingerprint"])) == 64
        assert token not in json.dumps(response)
        return enrollment_id, str(response["certificate_id"])


def activation(directory: Path, port: int, enrollment_id: str,
               certificate_id: str) -> None:
    hello = {
        "protocol": PROTOCOL,
        "kind": "activation_hello",
        "controller_id": CONTROLLER_ID,
        "enrollment_id": enrollment_id,
        "certificate_id": certificate_id,
        "ap_id": AP_ID,
    }
    with connect(directory, port, mtls=True) as connection:
        frame_send(connection, hello)
        challenge = frame_receive(connection)
        assert challenge["kind"] == "activation_challenge"
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "activation_response",
            "enrollment_id": enrollment_id,
            "certificate_id": certificate_id,
            "challenge": challenge["challenge"],
        })
        # Wait for the fixture DB commit without reading activation_complete,
        # then drop the connection. This deterministically models response
        # loss after activation has become durable.
        wait_for_file(directory / "activation.committed")

    # The same now-active certificate gets the idempotent terminal response
    # without creating another activation challenge.
    with connect(directory, port, mtls=True) as connection:
        frame_send(connection, hello)
        complete = frame_receive(connection)
        assert complete["kind"] == "activation_complete", complete
        assert complete["certificate_id"] == certificate_id


def adopted_session(directory: Path, port: int, certificate_id: str) -> None:
    with connect(directory, port, mtls=True) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "session_hello",
            "controller_id": CONTROLLER_ID,
            "certificate_id": certificate_id,
            "ap_id": AP_ID,
        })
        telemetry_ack = frame_receive(connection)
        session_epoch = telemetry_ack["session_epoch"]
        assert lowercase_hex(session_epoch, 32)
        assert telemetry_ack == {
            "protocol": PROTOCOL,
            "kind": "session_ready",
            "controller_id": CONTROLLER_ID,
            "certificate_id": certificate_id,
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
        }, telemetry_ack
        observed_at = int(time.time())
        snapshot = {
            "ok": True,
            "contract_version": PROTOCOL,
            "snapshot_version": "wireless-snapshot.v1",
            "source": "dreamingwrt-apd",
            "backend": "fixture",
            "observed_at": observed_at,
            "complete": True,
            "stale": False,
            "reason": None,
            "wireless_present": True,
            "phy_count": 1,
            "radio_count": 1,
            "ssid_count": 1,
            "station_count": 1,
            "model": "Fixture AP 1",
            "board_name": "fixture,ap1",
            "model_source": "ubus_system_board",
            "model_available": True,
            "model_reason": "",
            "radios": [{"id": "phy0", "band": "5GHz"}],
            "ssids": [{"id": "wlan0", "radio_id": "phy0", "interface": "wlan0", "broadcast_name": "Fixture"}],
            "stations": [{"mac": "02:00:00:00:00:01", "interface": "wlan0"}],
            "desired": {},
            "sources": {},
        }
        telemetry = {
            "protocol": PROTOCOL,
            "kind": "telemetry_snapshot",
            "schema": "apd-backend.snapshot",
            "version": 1,
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
            "sequence": 1,
            "observed_at": observed_at,
            "snapshot": snapshot,
        }
        frame_send(connection, telemetry)
        telemetry_ack = frame_receive(connection)
        assert telemetry_ack == {
            "protocol": PROTOCOL,
            "kind": "telemetry_ack",
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
            "sequence": 1,
            "accepted": True,
        }, telemetry_ack
        frame_send(connection, telemetry)
        assert frame_receive(connection) == telemetry_ack
        # Optional AP system facts (2026-07-26 APD): must be accepted.
        observed_at_system = int(time.time())
        snapshot_system = dict(snapshot)
        snapshot_system["observed_at"] = observed_at_system
        snapshot_system["system"] = {
            "uptime_seconds": 1234,
            "firmware_version": "QWRT fixture 1.0",
            "ip": "192.0.2.10",
            "mac": "02:00:00:00:00:aa",
        }
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "telemetry_snapshot",
            "schema": "apd-backend.snapshot",
            "version": 1,
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
            "sequence": 2,
            "observed_at": observed_at_system,
            "snapshot": snapshot_system,
        })
        assert frame_receive(connection) == {
            "protocol": PROTOCOL,
            "kind": "telemetry_ack",
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
            "sequence": 2,
            "accepted": True,
        }
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "heartbeat",
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
            "sequence": 3,
            "timestamp": int(time.time()) - 3600,
        })
        assert frame_receive(connection) == {
            "protocol": PROTOCOL,
            "kind": "heartbeat_ack",
            "ap_id": AP_ID,
            "session_epoch": session_epoch,
            "sequence": 3,
        }


def radio_identity(offer: dict[str, object], sequence: int,
                   kind: str) -> dict[str, object]:
    return {
        "protocol": PROTOCOL_V2,
        "kind": kind,
        "ap_id": AP_ID,
        "session_epoch": offer["session_epoch"],
        "sequence": sequence,
        "job_id": offer["job_id"],
        "attempt_id": offer["attempt_id"],
        "dispatch_generation": offer["dispatch_generation"],
        "request_digest": offer["request_digest"],
    }


def radio_reconcile(offer: dict[str, object], sequence: int, state: str,
                    *, finish_id: str = "", outcome: str = "",
                    error_code: str = "", result_complete: bool = False,
                    result: list[dict[str, object]] | None = None
                    ) -> dict[str, object]:
    message = radio_identity(offer, sequence, "radio_job_reconcile")
    message.update({
        "radio_id": offer["radio_id"], "mode": offer["mode"],
        "state": state, "finish_id": finish_id, "outcome": outcome,
        "error_code": error_code,
        "observed_at": int(time.time()) if finish_id else 0,
        "result_complete": result_complete,
        "result": [] if result is None else result,
    })
    return message


def assert_radio_binding(response: dict[str, object],
                         request: dict[str, object]) -> None:
    assert response["protocol"] == PROTOCOL_V2
    assert response["ap_id"] == AP_ID
    assert response["session_epoch"] == request["session_epoch"]
    assert response["reply_to"] == request["sequence"]
    for field in ("job_id", "attempt_id", "dispatch_generation",
                  "request_digest"):
        assert response[field] == request[field]


def radio_job_v2_session(directory: Path, port: int,
                         certificate_id: str) -> None:
    with connect(directory, port, mtls=True, alpn=ALPN_V2) as connection:
        assert connection.selected_alpn_protocol() == ALPN_V2
        frame_send(connection, {
            "protocol": PROTOCOL_V2,
            "kind": "session_hello",
            "controller_id": CONTROLLER_ID,
            "certificate_id": certificate_id,
            "ap_id": AP_ID,
        })
        ready = frame_receive(connection)
        assert ready["protocol"] == PROTOCOL_V2
        assert ready["kind"] == "session_ready"
        epoch = ready["session_epoch"]

        poll = {
            "protocol": PROTOCOL_V2, "kind": "radio_job_poll",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 1,
        }
        frame_send(connection, poll)
        offer = frame_receive(connection)
        assert set(offer) == {
            "protocol", "kind", "ap_id", "session_epoch", "reply_to",
            "job_id", "attempt_id", "dispatch_generation",
            "request_digest", "radio_id", "mode", "expected_impact",
            "controller_state", "cancel_requested",
        }
        assert offer["kind"] == "radio_job_offer"
        assert offer["reply_to"] == 1 and offer["controller_state"] == "leased"
        assert offer["cancel_requested"] is False
        frame_send(connection, poll)
        assert frame_receive(connection) == offer

        accept = radio_identity(offer, 2, "radio_job_accept")
        frame_send(connection, accept)
        accept_ack = frame_receive(connection)
        assert accept_ack["kind"] == "radio_job_accept_ack"
        assert accept_ack["controller_state"] == "leased"
        assert accept_ack["cancel_requested"] is False
        assert_radio_binding(accept_ack, accept)
        frame_send(connection, accept)
        assert frame_receive(connection) == accept_ack

        start = radio_identity(offer, 3, "radio_job_start")
        frame_send(connection, start)
        start_ack = frame_receive(connection)
        assert start_ack["kind"] == "radio_job_start_ack"
        assert start_ack["controller_state"] == "running"
        assert_radio_binding(start_ack, start)
        frame_send(connection, start)
        assert frame_receive(connection) == start_ack

        reconcile = radio_reconcile(offer, 4, "running")
        frame_send(connection, reconcile)
        reconcile_ack = frame_receive(connection)
        assert reconcile_ack["kind"] == "radio_job_reconcile_ack"
        assert reconcile_ack["controller_state"] == "running"
        assert reconcile_ack["cancel_requested"] is False
        assert reconcile_ack["result_complete"] is False
        assert_radio_binding(reconcile_ack, reconcile)

        finish = radio_identity(offer, 5, "radio_job_finish")
        finish.update({
            "finish_id": "30000000-0000-4000-8000-000000000001",
            "outcome": "completed", "error_code": "",
            "result_complete": True,
            "result": [{"bssid": "02:00:00:00:00:01", "rssi": -52}],
        })
        frame_send(connection, finish)
        finish_ack = frame_receive(connection)
        assert finish_ack["kind"] == "radio_job_finish_ack"
        assert finish_ack["controller_state"] == "completed"
        assert finish_ack["result_complete"] is True
        assert finish_ack["finish_id"] == finish["finish_id"]
        assert_radio_binding(finish_ack, finish)
        frame_send(connection, finish)
        assert frame_receive(connection) == finish_ack

        poll["sequence"] = 6
        frame_send(connection, poll)
        cancelled_offer = frame_receive(connection)
        assert cancelled_offer["kind"] == "radio_job_offer"
        cancelled_accept = radio_identity(
            cancelled_offer, 7, "radio_job_accept"
        )
        frame_send(connection, cancelled_accept)
        cancelled_ack = frame_receive(connection)
        assert cancelled_ack["kind"] == "radio_job_accept_ack"
        assert cancelled_ack["controller_state"] == "cancel_requested"
        assert cancelled_ack["cancel_requested"] is True
        cancelled = radio_reconcile(
            cancelled_offer, 8, "cancelled",
            finish_id="30000000-0000-4000-8000-000000000002",
            outcome="cancelled", error_code="controller_cancelled",
            result_complete=True,
        )
        frame_send(connection, cancelled)
        cancelled_done = frame_receive(connection)
        assert cancelled_done["kind"] == "radio_job_finish_ack"
        assert cancelled_done["controller_state"] == "cancelled"
        assert cancelled_done["error_code"] == "controller_cancelled"
        assert cancelled_done["finish_id"] == cancelled["finish_id"]
        frame_send(connection, cancelled)
        assert frame_receive(connection) == cancelled_done

        poll["sequence"] = 9
        frame_send(connection, poll)
        interrupted_offer = frame_receive(connection)
        interrupted_accept = radio_identity(
            interrupted_offer, 10, "radio_job_accept"
        )
        frame_send(connection, interrupted_accept)
        assert frame_receive(connection)["controller_state"] == "leased"
        interrupted_start = radio_identity(
            interrupted_offer, 11, "radio_job_start"
        )
        frame_send(connection, interrupted_start)
        assert frame_receive(connection)["controller_state"] == "running"
        interrupted = radio_reconcile(
            interrupted_offer, 12, "interrupted",
            finish_id="30000000-0000-4000-8000-000000000003",
            outcome="failed",
            error_code="apd_restarted_during_execution",
        )
        frame_send(connection, interrupted)
        interrupted_ack = frame_receive(connection)
        assert interrupted_ack["kind"] == "radio_job_finish_ack"
        assert interrupted_ack["controller_state"] == "failed"
        assert interrupted_ack["error_code"] == \
            "apd_restarted_during_execution"
        assert interrupted_ack["cancel_requested"] is False

        poll["sequence"] = 13
        frame_send(connection, poll)
        completed_offer = frame_receive(connection)
        completed_accept = radio_identity(
            completed_offer, 14, "radio_job_accept"
        )
        frame_send(connection, completed_accept)
        assert frame_receive(connection)["controller_state"] == "leased"
        completed_start = radio_identity(
            completed_offer, 15, "radio_job_start"
        )
        frame_send(connection, completed_start)
        assert frame_receive(connection)["controller_state"] == "running"
        completed = radio_reconcile(
            completed_offer, 16, "completed",
            finish_id="30000000-0000-4000-8000-000000000004",
            outcome="completed", result_complete=True,
            result=[{"bssid": "02:00:00:00:00:04", "rssi": -44}],
        )
        frame_send(connection, completed)
        completed_ack = frame_receive(connection)
        assert completed_ack["kind"] == "radio_job_finish_ack"
        assert completed_ack["controller_state"] == "completed"
        assert completed_ack["result_complete"] is True

        poll["sequence"] = 17
        frame_send(connection, poll)
        failed_offer = frame_receive(connection)
        failed_accept = radio_identity(failed_offer, 18, "radio_job_accept")
        frame_send(connection, failed_accept)
        assert frame_receive(connection)["controller_state"] == "leased"
        failed_start = radio_identity(failed_offer, 19, "radio_job_start")
        frame_send(connection, failed_start)
        assert frame_receive(connection)["controller_state"] == "running"
        failed = radio_reconcile(
            failed_offer, 20, "failed",
            finish_id="30000000-0000-4000-8000-000000000005",
            outcome="failed", error_code="scan_command_failed",
        )
        frame_send(connection, failed)
        failed_ack = frame_receive(connection)
        assert failed_ack["kind"] == "radio_job_finish_ack"
        assert failed_ack["controller_state"] == "failed"
        assert failed_ack["error_code"] == "scan_command_failed"

        poll["sequence"] = 21
        frame_send(connection, poll)
        direct_cancel_offer = frame_receive(connection)
        direct_cancel_accept = radio_identity(
            direct_cancel_offer, 22, "radio_job_accept"
        )
        frame_send(connection, direct_cancel_accept)
        direct_cancel_accept_ack = frame_receive(connection)
        assert direct_cancel_accept_ack["cancel_requested"] is True
        direct_cancel = radio_identity(
            direct_cancel_offer, 23, "radio_job_finish"
        )
        direct_cancel.update({
            "finish_id": "30000000-0000-4000-8000-000000000006",
            "outcome": "cancelled", "error_code": "controller_cancelled",
            "result_complete": True, "result": [],
        })
        frame_send(connection, direct_cancel)
        direct_cancel_ack = frame_receive(connection)
        assert direct_cancel_ack["kind"] == "radio_job_finish_ack"
        assert direct_cancel_ack["controller_state"] == "cancelled"
        assert direct_cancel_ack["result_complete"] is True
        frame_send(connection, direct_cancel)
        assert frame_receive(connection) == direct_cancel_ack

        poll["sequence"] = 24
        frame_send(connection, poll)
        idle = frame_receive(connection)
        assert idle == {
            "protocol": PROTOCOL_V2, "kind": "radio_job_idle",
            "ap_id": AP_ID, "session_epoch": epoch, "reply_to": 24,
        }


def radio_job_v2_telemetry_heartbeat_poll(directory: Path, port: int,
                                          certificate_id: str) -> None:
    with connect(directory, port, mtls=True, alpn=ALPN_V2) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "session_hello",
            "controller_id": CONTROLLER_ID, "certificate_id": certificate_id,
            "ap_id": AP_ID,
        })
        ready = frame_receive(connection)
        assert ready["protocol"] == PROTOCOL_V2
        epoch = ready["session_epoch"]
        observed_at = int(time.time())
        snapshot = {
            "ok": True, "contract_version": PROTOCOL,
            "snapshot_version": "wireless-snapshot.v1",
            "source": "dreamingwrt-apd", "backend": "fixture",
            "observed_at": observed_at, "complete": True, "stale": False,
            "reason": None, "wireless_present": True,
            "phy_count": 1, "radio_count": 1, "ssid_count": 1,
            "station_count": 1, "model": "Fixture AP 1",
            "board_name": "fixture,ap1", "model_source": "ubus_system_board",
            "model_available": True, "model_reason": "",
            "radios": [{"id": "phy0", "band": "5GHz"}],
            "ssids": [{"id": "wlan0", "radio_id": "phy0",
                       "interface": "wlan0", "broadcast_name": "Fixture"}],
            "stations": [{"mac": "02:00:00:00:00:02",
                          "interface": "wlan0"}],
            "desired": {}, "sources": {},
        }
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "telemetry_snapshot",
            "schema": "apd-backend.snapshot", "version": 1,
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 1,
            "observed_at": observed_at, "snapshot": snapshot,
        })
        telemetry_ack = frame_receive(connection)
        assert telemetry_ack == {
            "protocol": PROTOCOL_V2, "kind": "telemetry_ack",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 1,
            "accepted": True,
        }
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "heartbeat", "ap_id": AP_ID,
            "session_epoch": epoch, "sequence": 2,
            "timestamp": observed_at,
        })
        heartbeat_ack = frame_receive(connection)
        assert heartbeat_ack == {
            "protocol": PROTOCOL_V2, "kind": "heartbeat_ack",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 2,
        }
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "radio_job_poll",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 3,
        })
        offer = frame_receive(connection)
        assert offer["protocol"] == PROTOCOL_V2
        assert offer["kind"] == "radio_job_offer"
        assert offer["reply_to"] == 3


def radio_job_v2_old_epoch_rejected(directory: Path, port: int,
                                    certificate_id: str) -> None:
    with connect(directory, port, mtls=True, alpn=ALPN_V2) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "session_hello",
            "controller_id": CONTROLLER_ID, "certificate_id": certificate_id,
            "ap_id": AP_ID,
        })
        ready = frame_receive(connection)
        assert ready["kind"] == "session_ready"
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "radio_job_poll",
            "ap_id": AP_ID, "session_epoch": "0" * 64, "sequence": 1,
        })
        denied = frame_receive(connection)
        assert denied["kind"] == "radio_job_error"
        assert denied["error"] == "invalid_session"
        assert denied["reason"] == "session_not_current"
        assert denied["reply_to"] == 1


def config_job_v2_session(directory: Path, port: int,
                          certificate_id: str) -> None:
    """W2c config job wire: offer/accept/finish with idempotent finish
    replay and idle after the terminal state."""
    with connect(directory, port, mtls=True, alpn=ALPN_V2) as connection:
        assert connection.selected_alpn_protocol() == ALPN_V2
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "session_hello",
            "controller_id": CONTROLLER_ID,
            "certificate_id": certificate_id, "ap_id": AP_ID,
        })
        ready = frame_receive(connection)
        assert ready["kind"] == "session_ready"
        epoch = ready["session_epoch"]
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "config_job_poll",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 1,
        })
        offer = frame_receive(connection)
        assert offer["kind"] == "config_job_offer", offer
        assert offer["reply_to"] == 1
        assert offer["controller_state"] == "leased"
        assert offer["candidate_digest"].startswith("sha256:")
        assert "uci-wireless-candidate.v1" in offer["candidate"]
        identity = {
            "job_id": offer["job_id"], "attempt_id": offer["attempt_id"],
            "dispatch_generation": offer["dispatch_generation"],
            "request_digest": offer["request_digest"],
        }
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "config_job_accept",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 2,
            **identity,
        })
        ack = frame_receive(connection)
        assert ack["kind"] == "config_job_accept_ack", ack
        assert ack["controller_state"] == "running"
        finish = {
            "protocol": PROTOCOL_V2, "kind": "config_job_finish",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 3,
            **identity,
            "finish_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "outcome": "applied", "error_code": "",
            "readback": "{\"match\":true}",
        }
        frame_send(connection, finish)
        finish_ack = frame_receive(connection)
        assert finish_ack["kind"] == "config_job_finish_ack", finish_ack
        assert finish_ack["controller_state"] == "applied"
        assert finish_ack["finish_id"] == finish["finish_id"]
        replay = dict(finish)
        replay["sequence"] = 4
        frame_send(connection, replay)
        replay_ack = frame_receive(connection)
        assert replay_ack["kind"] == "config_job_finish_ack", replay_ack
        assert replay_ack["controller_state"] == "applied"
        frame_send(connection, {
            "protocol": PROTOCOL_V2, "kind": "config_job_poll",
            "ap_id": AP_ID, "session_epoch": epoch, "sequence": 5,
        })
        idle = frame_receive(connection)
        assert idle["kind"] == "config_job_idle", idle


def telemetry_rejected(directory: Path, port: int, certificate_id: str,
                       mutate: str) -> None:
    with connect(directory, port, mtls=True) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL,
            "kind": "session_hello",
            "controller_id": CONTROLLER_ID,
            "certificate_id": certificate_id,
            "ap_id": AP_ID,
        })
        ready = frame_receive(connection)
        assert ready["kind"] == "session_ready"
        session_epoch = ready["session_epoch"]
        observed_at = int(time.time())
        snapshot = {
            "ok": True, "contract_version": PROTOCOL,
            "snapshot_version": "wireless-snapshot.v1",
            "source": "dreamingwrt-apd", "backend": "fixture",
            "observed_at": observed_at, "complete": True, "stale": False,
            "reason": None, "wireless_present": True,
            "phy_count": 1, "radio_count": 1, "ssid_count": 1,
            "station_count": 0, "model": "Fixture AP 1",
            "board_name": "fixture,ap1", "model_source": "ubus_system_board",
            "model_available": True, "model_reason": "",
            "radios": [{"id": "phy0"}],
            "ssids": [{"id": "wlan0", "radio_id": "phy0", "interface": "wlan0"}],
            "stations": [], "desired": {}, "sources": {},
        }
        message: dict[str, object] = {
            "protocol": PROTOCOL, "kind": "telemetry_snapshot",
            "schema": "apd-backend.snapshot", "version": 1,
            "ap_id": AP_ID, "session_epoch": session_epoch,
            "sequence": 2, "observed_at": observed_at,
            "snapshot": snapshot,
        }
        if mutate == "ap_id":
            message["ap_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        elif mutate == "missing_snapshot":
            del message["snapshot"]
        elif mutate == "sequence_rollback":
            frame_send(connection, {
                "protocol": PROTOCOL, "kind": "heartbeat", "ap_id": AP_ID,
                "session_epoch": session_epoch, "sequence": 3,
                "timestamp": observed_at,
            })
            assert frame_receive(connection)["kind"] == "heartbeat_ack"
            message["sequence"] = 2
        elif mutate == "system_not_object":
            snapshot["system"] = "bogus"
        else:
            raise AssertionError(mutate)
        frame_send(connection, message)
        denied = frame_receive(connection)
        assert denied["kind"] == "error", denied
        assert denied["error"] == "session_denied"


def oversized_telemetry_rejected(directory: Path, port: int,
                                 certificate_id: str) -> None:
    with connect(directory, port, mtls=True) as connection:
        frame_send(connection, {
            "protocol": PROTOCOL, "kind": "session_hello",
            "controller_id": CONTROLLER_ID, "certificate_id": certificate_id,
            "ap_id": AP_ID,
        })
        assert frame_receive(connection)["kind"] == "session_ready"
        connection.sendall(struct.pack("!I", 64 * 1024 + 1))
        connection.settimeout(3)
        assert connection.recv(1) == b""


def tls_gates(directory: Path, port: int) -> None:
    try:
        with connect(directory, port, alpn="http/1.1"):
            raise AssertionError("wrong ALPN accepted")
    except (ssl.SSLError, ConnectionError, OSError):
        pass

    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    context = client_context(
        directory, minimum=ssl.TLSVersion.TLSv1_2,
        maximum=ssl.TLSVersion.TLSv1_2,
    )
    try:
        with context.wrap_socket(raw, server_hostname="127.0.0.1"):
            raise AssertionError("TLS 1.2 accepted")
    except (ssl.SSLError, ConnectionError, OSError):
        raw.close()

    with connect(directory, port) as connection:
        connection.sendall(struct.pack("!I", 64 * 1024 + 1))
        connection.settimeout(3)
        assert connection.recv(1) == b""


def live_contract(binary: Path, root: Path) -> None:
    env = os.environ.copy()
    env.update({
        "DREAMINGWRT_AC_LISTEN_ADDR": "127.0.0.1",
        "DREAMINGWRT_AC_LISTEN_PORT": "0",
        "AC_TRANSPORT_TEST_OUTPUT": str(root),
    })
    process = subprocess.Popen(
        [str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        fields: dict[str, str] = {}
        for _ in range(3):
            line = read_line(process)
            key, value = line.split("=", 1)
            fields[key] = value
        port = int(fields["port"])
        assert 0 < port <= 65535
        assert fields["reason"] == "listening"
        assert fields["controller_id"] == CONTROLLER_ID
        enrollment_challenge(root, port)
        invalid_request_is_secret_free(root, port)
        enrollment_id, certificate_id = enrollment_claim(root, port)
        activation(root, port, enrollment_id, certificate_id)
        adopted_session(root, port, certificate_id)
        radio_job_v2_telemetry_heartbeat_poll(root, port, certificate_id)
        radio_job_v2_session(root, port, certificate_id)
        radio_job_v2_old_epoch_rejected(root, port, certificate_id)
        config_job_v2_session(root, port, certificate_id)
        telemetry_rejected(root, port, certificate_id, "ap_id")
        telemetry_rejected(root, port, certificate_id, "sequence_rollback")
        telemetry_rejected(root, port, certificate_id, "missing_snapshot")
        telemetry_rejected(root, port, certificate_id, "system_not_object")
        oversized_telemetry_rejected(root, port, certificate_id)
        tls_gates(root, port)
    finally:
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=12)
    assert process.returncode == 0, (stdout, stderr)
    assert "stopped=1" in stdout and "reason=stopped" in stdout
    assert "heartbeats=3" in stdout
    assert (root / "telemetry-store-count").read_text().strip() == "3"
    assert (root / "identity-report-count").read_text().strip() == "1"
    assert (root / "radio-lease-count").read_text().strip() == "6"
    assert (root / "radio-start-count").read_text().strip() == "4"
    assert (root / "radio-finish-count").read_text().strip() == "6"
    assert (root / "config-lease-count").read_text().strip() == "1"
    assert (root / "config-start-count").read_text().strip() == "1"
    assert (root / "config-finish-count").read_text().strip() == "1"
    assert "controller_after_stop=" in stdout
    assert "SSSSSS" not in stdout + stderr


def static_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    required = (
        "TLS1_3_VERSION", "AP_CONTROL_ALPN", "AP_CONTROL_FRAME_MAX",
        "AP_CONTROL_IO_TIMEOUT_MS", "AC_TRANSPORT_DEFAULT_PORT",
        "DREAMINGWRT_AC_LISTEN_ADDR", "DREAMINGWRT_AC_LISTEN_PORT",
        "AC_TRANSPORT_WORKERS_MAX", "AC_TRANSPORT_ACCEPT_BURST",
        "ac_peer_identity", "NID_client_auth", "BASIC_CONSTRAINTS",
        "ac_db_certificate_peer_authorize", "ac_db_enrollment_activate",
        "ac_db_ap_heartbeat",
        "ac_db_ap_telemetry_store", "ac_db_ap_identity_report",
        "ac_db_ap_session_is_current", "ac_db_radio_job_lease_next",
        "ac_db_radio_job_mark_running", "ac_db_radio_job_reconcile",
        "ac_db_radio_job_finish", "radio_job_poll", "radio_job_offer",
        "radio_job_accept", "radio_job_start", "radio_job_finish",
        "radio_job_reconcile", "reply_to", "cancel_requested",
        "ac_pki_issue_ap_certificate", "ac_transport_reason",
        "ac_transport_port", "ac_transport_controller_id",
        "pthread_join", "shutdown(g_ac_transport.worker_fd",
    )
    for item in required:
        assert item in source, item
    for fields in (
        "ac_fields_enrollment_hello", "ac_fields_enrollment_challenge",
        "ac_fields_enrollment_claim", "ac_fields_enrollment_certificate",
        "ac_fields_activation_hello", "ac_fields_activation_challenge",
        "ac_fields_activation_response", "ac_fields_activation_complete",
        "ac_fields_session_hello", "ac_fields_session_ready",
        "ac_fields_heartbeat", "ac_fields_heartbeat_ack", "ac_fields_error",
        "ac_fields_telemetry_snapshot", "ac_fields_telemetry_ack",
        "ac_fields_radio_job_poll", "ac_fields_radio_job_identity",
        "ac_fields_radio_job_reconcile", "ac_fields_radio_job_finish",
        "ac_fields_radio_job_idle", "ac_fields_radio_job_offer",
        "ac_fields_radio_job_ack", "ac_fields_radio_job_reconcile_ack",
        "ac_fields_radio_job_finish_ack", "ac_fields_radio_job_error",
    ):
        assert source.count(fields) >= 2, fields
    assert '"token"' not in source[source.index("static int ac_send_error"):
                                    source.index("static int ac_json_get_hex_exact")]
    controller_getter = source[source.index("const char *ac_transport_controller_id") :]
    assert "return g_ac_transport_controller_id_copy;" in controller_getter
    assert "return NULL" not in controller_getter


def main() -> None:
    protocol_version_contract()
    static_contract()
    with tempfile.TemporaryDirectory(prefix="ac-transport-") as raw:
        root = Path(raw)
        binary = root / "fixture"
        compile_fixture(binary)
        live_contract(binary, root)
    print("ok: AC v1 telemetry and v2 radio job lease/accept/start/reconcile/finish transport")


if __name__ == "__main__":
    main()
