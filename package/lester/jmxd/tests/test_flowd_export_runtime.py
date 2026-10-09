#!/usr/bin/env python3
"""NetFlow v9 and IPFIX export: encode for real, then decode with a foreign parser.

The acceptance bar the handoff set is explicit: a real collector must parse the
records, and "UDP packets were sent" does not pass. So this compiles the
production encoders, emits real datagrams, and hands them to scapy's
NetFlow/IPFIX dissector -- a decoder that knows nothing about our code, so a
field-order or length mistake shows up as a wrong value instead of agreeing with
our own bug.

Both protocols and both address families are covered, because a v4-only export
would leave our own IPv6 multi-WAN traffic invisible.

Scapy lives on the authoritative tree (31.6). Where it is missing the datagrams
are still encoded and their structure checked, and the test says plainly that
the independent decode was skipped rather than reporting a pass it did not earn.
"""

from __future__ import annotations

from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
EXPORT_C = ROOT / "src/flowd/flowd_export.c"
EXPORT_H = ROOT / "src/flowd/flowd_export.h"
FIXTURE = ROOT / "tests/flowd_export_runtime_fixture.c"
DECODER = ROOT / "tests/flowd_export_decode_check.py"


def build(directory: Path) -> Path:
    binary = directory / "flowd-export-fixture"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", f"-I{ROOT / 'src/flowd'}",
         str(FIXTURE), str(EXPORT_C), "-o", str(binary)],
        check=True, capture_output=True, text=True)
    return binary


def emit(binary: Path, protocol: str, family: str, directory: Path) -> Path:
    path = directory / f"{protocol}_{family}.bin"
    result = subprocess.run([str(binary), protocol, str(path), family],
                            check=True, capture_output=True, text=True)
    assert path.exists() and path.stat().st_size > 0, result.stdout
    return path


def have_scapy() -> bool:
    return subprocess.run(
        [sys.executable, "-c",
         "from scapy.layers.netflow import NetflowHeaderV10"],
        capture_output=True).returncode == 0


def test_headers_match_the_two_specifications() -> None:
    """Structural checks that hold regardless of whether scapy is installed."""
    with tempfile.TemporaryDirectory(prefix="flowd-export-") as raw:
        directory = Path(raw)
        binary = build(directory)

        ipfix = emit(binary, "ipfix", "v4", directory).read_bytes()
        version, length = struct.unpack("!HH", ipfix[:4])
        assert version == 10, f"IPFIX version field is {version}"
        # IPFIX carries a byte length; a mismatch is the classic reason a
        # collector drops the datagram without a word.
        assert length == len(ipfix), f"IPFIX length {length} != {len(ipfix)} bytes"
        domain = struct.unpack("!I", ipfix[12:16])[0]
        assert domain == 42, f"observation domain {domain}"

        v9 = emit(binary, "netflow9", "v4", directory).read_bytes()
        version, count = struct.unpack("!HH", v9[:4])
        assert version == 9, f"NetFlow version field is {version}"
        # v9 carries a record count instead of a length: 2 data records plus the
        # template flowset.
        assert count == 3, f"v9 record count {count}, expected 3"


def test_template_and_data_travel_together() -> None:
    """A collector must be able to decode the first datagram it ever sees."""
    with tempfile.TemporaryDirectory(prefix="flowd-export-") as raw:
        directory = Path(raw)
        binary = build(directory)
        for protocol, template_set in (("ipfix", 2), ("netflow9", 0)):
            data = emit(binary, protocol, "v4", directory).read_bytes()
            offset = 16 if protocol == "ipfix" else 20
            set_id = struct.unpack("!H", data[offset:offset + 2])[0]
            assert set_id == template_set, (
                f"{protocol}: first set id {set_id}, expected {template_set}")


def test_mixed_family_batch_is_refused() -> None:
    """One datagram carries one template, so a mixed batch must not encode."""
    with tempfile.TemporaryDirectory(prefix="flowd-export-") as raw:
        directory = Path(raw)
        binary = build(directory)
        result = subprocess.run(
            [str(binary), "ipfix", str(directory / "mixed.bin"), "mixed"],
            check=True, capture_output=True, text=True)
        assert "mixed-family batch rejected" in result.stdout, result.stdout


def test_sequence_semantics_differ_per_protocol() -> None:
    """v9 counts packets, IPFIX counts records. Conflating them misleads a collector."""
    with tempfile.TemporaryDirectory(prefix="flowd-export-") as raw:
        directory = Path(raw)
        binary = build(directory)
        ipfix = subprocess.run([str(binary), "ipfix",
                                str(directory / "a.bin"), "v4"],
                               check=True, capture_output=True, text=True).stdout
        v9 = subprocess.run([str(binary), "netflow9",
                             str(directory / "b.bin"), "v4"],
                            check=True, capture_output=True, text=True).stdout
        assert "sequence_after=2" in ipfix, f"IPFIX must count 2 records: {ipfix}"
        assert "sequence_after=1" in v9, f"v9 must count 1 packet: {v9}"


def test_records_decode_in_a_foreign_parser() -> bool:
    if not have_scapy():
        print("SKIP: scapy is not installed here, so the independent decode did "
              "not run; encoding and header structure were still checked")
        return False
    with tempfile.TemporaryDirectory(prefix="flowd-export-") as raw:
        directory = Path(raw)
        binary = build(directory)
        for protocol in ("ipfix", "netflow9"):
            for family in ("v4", "v6"):
                path = emit(binary, protocol, family, directory)
                result = subprocess.run(
                    [sys.executable, str(DECODER), protocol, str(path), family],
                    capture_output=True, text=True)
                assert result.returncode == 0, (
                    f"{protocol}/{family} failed to decode:\n"
                    f"{result.stdout}\n{result.stderr}")
                assert "ok:" in result.stdout, result.stdout
    return True


def test_datagrams_arrive_over_real_udp() -> None:
    """The send path, not just the encoder: bind a socket and receive.

    A collector reads bytes off a socket, so the transport is part of what has
    to work: resolution, a connected socket, and a datagram whose declared
    length matches what actually arrived.
    """
    with tempfile.TemporaryDirectory(prefix="flowd-export-") as raw:
        binary = build(Path(raw))
        for protocol, version in (("ipfix", 10), ("netflow9", 9)):
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(5)
            port = listener.getsockname()[1]
            try:
                result = subprocess.run(
                    [str(binary), protocol, "--udp", str(port), "v4"],
                    check=True, capture_output=True, text=True)
                assert "datagrams=1" in result.stdout, result.stdout
                assert "errors=0" in result.stdout, result.stdout
                data, _ = listener.recvfrom(65535)
            finally:
                listener.close()
            assert struct.unpack("!H", data[:2])[0] == version, (
                f"{protocol}: wrong version on the wire")
            if protocol == "ipfix":
                declared = struct.unpack("!H", data[2:4])[0]
                assert declared == len(data), (
                    f"IPFIX declared {declared} but {len(data)} bytes arrived; "
                    f"a collector would drop this without a word")


if __name__ == "__main__":
    test_headers_match_the_two_specifications()
    test_template_and_data_travel_together()
    test_mixed_family_batch_is_refused()
    test_sequence_semantics_differ_per_protocol()
    test_datagrams_arrive_over_real_udp()
    decoded = test_records_decode_in_a_foreign_parser()
    if decoded:
        print("ok: both exporters encode valid datagrams and decode in a "
              "foreign parser (ipfix/netflow9 x v4/v6)")
    else:
        print("ok (partial): both exporters encode valid datagrams with correct "
              "headers; the foreign-parser decode was skipped, run this on 31.6 "
              "for the full gate")
