#!/usr/bin/env python3
"""Collector-side proof for a *collected* flow, not a hand-typed one.

The existing collector check feeds the encoders values written by the fixture.
This one starts from a real /proc/net/nf_conntrack line, runs it through the
production parser and delta bookkeeping, and only then encodes and sends. So the
numbers a collector reads here are the ones collection actually produced --
which is what the handoff's acceptance criterion is about.

The line is a TCP/IPv4 conversation from 192.168.30.1 carrying 9+10 packets and
1280+4553 bytes across both directions, so the record must show 19 packets and
5833 bytes.

usage: flowd_collect_collector_check.py <fixture-binary> <ipfix|netflow9>
"""

from __future__ import annotations

import socket
import subprocess
import sys

from scapy.layers.netflow import NetflowHeader, netflowv9_defragment


EXPECTED = {
    "src": "1.28.111.142",
    "dst": "162.159.8.38",
    "sport": 57776,
    "dport": 443,
    "protocol": 6,
    "bytes": 5833,
    "packets": 19,
}


def as_int(value):
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, "big")
    return value


def main() -> int:
    fixture, protocol = sys.argv[1], sys.argv[2]

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(5)
    port = listener.getsockname()[1]
    try:
        run = subprocess.run([fixture, "--emit-udp", protocol, str(port)],
                             capture_output=True, text=True)
        if run.returncode != 0:
            print(f"FAIL exporter: {run.stdout}{run.stderr}")
            return 1
        payload, sender = listener.recvfrom(65535)
    except socket.timeout:
        print("FAIL nothing arrived on the collector socket")
        return 1
    finally:
        listener.close()

    records = []
    seen = set()
    for pkt in netflowv9_defragment([NetflowHeader(payload)]):
        layer = pkt
        while layer:
            for record in getattr(layer, "records", None) or []:
                # Dedupe by identity: collecting per layer would count one
                # record several times and turn a mismatch into a count error.
                if id(record) not in seen:
                    seen.add(id(record))
                    records.append(record)
            layer = layer.payload if layer.payload else None

    if len(records) != 1:
        print(f"FAIL decoded {len(records)} records, expected 1")
        return 1

    record = records[0]
    got = {
        "src": str(getattr(record, "IPV4_SRC_ADDR", None)),
        "dst": str(getattr(record, "IPV4_DST_ADDR", None)),
        "sport": as_int(getattr(record, "L4_SRC_PORT", None)),
        "dport": as_int(getattr(record, "L4_DST_PORT", None)),
        "protocol": as_int(getattr(record, "PROTOCOL", None)),
        "bytes": as_int(getattr(record, "IN_BYTES", None)),
        "packets": as_int(getattr(record, "IN_PKTS", None)),
    }
    if got != EXPECTED:
        print(f"FAIL collected flow decoded as {got}, expected {EXPECTED}")
        return 1

    print(f"ok: {protocol} {len(payload)} bytes received from "
          f"{sender[0]}:{sender[1]}; the flow collected from a real conntrack "
          f"line decoded as {got['src']}:{got['sport']} -> "
          f"{got['dst']}:{got['dport']} proto {got['protocol']}, "
          f"{got['bytes']} bytes / {got['packets']} packets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
