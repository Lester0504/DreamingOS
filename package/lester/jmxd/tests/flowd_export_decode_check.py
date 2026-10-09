#!/usr/bin/env python3
"""Decode datagrams produced by the flowd exporters with an independent parser.

Run as: flowd_export_decode_check.py <protocol> <datagram-file> <family>

This is the collector half of the acceptance gate. Scapy's NetFlow/IPFIX
dissector is used deliberately: it knows nothing about our encoder, so a field
order or length mistake surfaces as a parse failure or a wrong value rather than
agreeing with our own bug. "UDP packets were sent" does not pass; the record
fields must come back with the values that went in.
"""

from __future__ import annotations

import sys

from scapy.layers.netflow import (NetflowHeader, NetflowHeaderV9,
                                  NetflowHeaderV10, netflowv9_defragment)


EXPECTED_V4 = [
    {"src": "192.168.30.10", "dst": "1.1.1.1", "sport": 51000, "dport": 443,
     "proto": 6, "bytes": 15000, "packets": 20},
    {"src": "192.168.30.11", "dst": "8.8.8.8", "sport": 51001, "dport": 53,
     "proto": 6, "bytes": 300, "packets": 3},
]
EXPECTED_V6 = [
    {"src": "2001:db8::1", "dst": "2001:db8::2", "sport": 5353, "dport": 443,
     "proto": 17, "bytes": 8192, "packets": 12},
    {"src": "fd00::a", "dst": "fd00::b", "sport": 1234, "dport": 53,
     "proto": 17, "bytes": 512, "packets": 4},
]


def field(record, *names):
    for name in names:
        if hasattr(record, name):
            value = getattr(record, name)
            if value is not None:
                return value
    return None


def as_int(value):
    """Scapy hands back 8-octet counters as raw bytes rather than integers.

    That is a property of its dissector, not of our encoding, so normalise here
    instead of narrowing the wire fields: 4-byte counters would wrap inside a
    single long-lived flow on a gigabit WAN.
    """
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, "big")
    return value


def main() -> int:
    protocol, path, family = sys.argv[1], sys.argv[2], sys.argv[3]
    raw = open(path, "rb").read()

    packet = NetflowHeader(raw)
    version = packet.version
    want_version = 10 if protocol == "ipfix" else 9
    if version != want_version:
        print(f"FAIL version {version} != {want_version}")
        return 1
    header_layer = NetflowHeaderV10 if want_version == 10 else NetflowHeaderV9
    if header_layer not in packet:
        print(f"FAIL {header_layer.__name__} not recognised by the decoder")
        return 1

    # Template + data arrive in the same datagram, which is what a collector
    # needs in order to decode the very first packet it ever receives.
    resolved = netflowv9_defragment([packet])
    if not resolved:
        print("FAIL defragment produced nothing")
        return 1

    # After defragmentation the decoded rows live in the data flowset's
    # `records` list, not as payload layers of the packet.
    #
    # Collected by identity: `records` is reachable from several layers in the
    # chain, so appending on every hit counted each row four times and turned 2
    # flows into "8 records" -- a count that looked like a pass while hiding how
    # many rows really decoded.
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

    if len(records) != len(EXPECTED_V6 if family == "v6" else EXPECTED_V4):
        print(f"FAIL decoded {len(records)} records, expected "
              f"{len(EXPECTED_V6 if family == 'v6' else EXPECTED_V4)}")
        return 1

    if not records:
        print("FAIL no data records decoded; the template was not applied")
        print(packet.show(dump=True)[:3000])
        return 1

    expected = EXPECTED_V6 if family == "v6" else EXPECTED_V4
    if len(records) < len(expected):
        print(f"FAIL decoded {len(records)} records, expected {len(expected)}")
        return 1

    failures = 0
    for index, want in enumerate(expected):
        got = records[index]
        src = field(got, "sourceIPv4Address", "sourceIPv6Address",
                    "IPV4_SRC_ADDR", "IPV6_SRC_ADDR")
        dst = field(got, "destinationIPv4Address", "destinationIPv6Address",
                    "IPV4_DST_ADDR", "IPV6_DST_ADDR")
        sport = as_int(field(got, "sourceTransportPort", "L4_SRC_PORT"))
        dport = as_int(field(got, "destinationTransportPort", "L4_DST_PORT"))
        proto = as_int(field(got, "protocolIdentifier", "PROTOCOL"))
        octets = as_int(field(got, "octetDeltaCount", "IN_BYTES"))
        packets = as_int(field(got, "packetDeltaCount", "IN_PKTS"))

        def check(name, actual, wanted):
            nonlocal failures
            if str(actual) != str(wanted):
                print(f"FAIL record {index} {name}: got {actual!r}, "
                      f"expected {wanted!r}")
                failures += 1

        check("src", src, want["src"])
        check("dst", dst, want["dst"])
        check("sport", sport, want["sport"])
        check("dport", dport, want["dport"])
        check("proto", proto, want["proto"])
        check("bytes", octets, want["bytes"])
        check("packets", packets, want["packets"])

        # Timestamps are the one field pair the two protocols disagree on:
        # IPFIX carries absolute milliseconds, v9 carries an offset from
        # sysUpTime. Both must survive the round trip in their own terms.
        if protocol == "ipfix":
            start = as_int(field(got, "flowStartMilliseconds"))
            end = as_int(field(got, "flowEndMilliseconds"))
            if start is None or end is None:
                print(f"FAIL record {index}: IPFIX absolute ms timestamps absent")
                failures += 1
            elif not (start >= 1_600_000_000_000 and end >= start):
                print(f"FAIL record {index}: implausible IPFIX timestamps "
                      f"{start} .. {end}")
                failures += 1
        else:
            start = as_int(field(got, "FIRST_SWITCHED", "flowStartSysUpTime"))
            end = as_int(field(got, "LAST_SWITCHED", "flowEndSysUpTime"))
            if start is None or end is None:
                print(f"FAIL record {index}: v9 sysUpTime timestamps absent")
                failures += 1
            elif end < start:
                print(f"FAIL record {index}: v9 end before start {start} .. {end}")
                failures += 1

    if failures:
        return 1
    print(f"ok: {protocol} {family} decoded {len(records)} records with matching "
          f"five-tuple and counters")
    return 0


if __name__ == "__main__":
    sys.exit(main())
