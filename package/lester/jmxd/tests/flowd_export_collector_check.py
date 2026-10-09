#!/usr/bin/env python3
"""Collector-side proof: receive datagrams on a socket and decode what arrived.

This is the strongest form of the acceptance gate the handoff set. The bytes are
not read back from a buffer the exporter filled; they are received from a UDP
socket, exactly as nfcapd or Elastiflow would see them, and then parsed by
scapy's dissector, which knows nothing about our encoder.

usage: flowd_export_collector_check.py <fixture-binary> <ipfix|netflow9> <v4|v6>
"""

from __future__ import annotations

import socket
import subprocess
import sys

from scapy.layers.netflow import NetflowHeader, netflowv9_defragment


EXPECTED = {
    "v4": [("192.168.30.10", 51000, 443, 15000, 20),
           ("192.168.30.11", 51001, 53, 300, 3)],
    "v6": [("2001:db8::1", 5353, 443, 8192, 12),
           ("fd00::a", 1234, 53, 512, 4)],
}


def as_int(value):
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, "big")
    return value


def main() -> int:
    fixture, protocol, family = sys.argv[1], sys.argv[2], sys.argv[3]

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(5)
    port = listener.getsockname()[1]
    try:
        run = subprocess.run([fixture, protocol, "--udp", str(port), family],
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

    packet = NetflowHeader(payload)
    resolved = netflowv9_defragment([packet])
    records = []
    seen = set()
    for pkt in resolved:
        layer = pkt
        while layer:
            for record in getattr(layer, "records", None) or []:
                if id(record) not in seen:
                    seen.add(id(record))
                    records.append(record)
            layer = layer.payload if layer.payload else None

    want = EXPECTED[family]
    if len(records) != len(want):
        print(f"FAIL decoded {len(records)} records from the wire, expected "
              f"{len(want)}")
        return 1

    failures = 0
    for index, (src, sport, dport, octets, packets) in enumerate(want):
        record = records[index]
        got_src = getattr(record, "IPV4_SRC_ADDR", None) or \
            getattr(record, "IPV6_SRC_ADDR", None)
        got = (str(got_src),
               as_int(getattr(record, "L4_SRC_PORT", None)),
               as_int(getattr(record, "L4_DST_PORT", None)),
               as_int(getattr(record, "IN_BYTES", None)),
               as_int(getattr(record, "IN_PKTS", None)))
        if got != (src, sport, dport, octets, packets):
            print(f"FAIL record {index} from the wire: {got} != "
                  f"{(src, sport, dport, octets, packets)}")
            failures += 1

    if failures:
        return 1
    print(f"ok: {protocol}/{family} {len(payload)} bytes received from "
          f"{sender[0]}:{sender[1]}, {len(records)} records decoded with "
          f"matching five-tuple and counters")
    return 0


if __name__ == "__main__":
    sys.exit(main())
