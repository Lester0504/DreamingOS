#!/usr/bin/env python3
"""Host-side regression tests for the DreamingWrt DPI v3 wire contract."""

from __future__ import annotations

import hashlib
import pathlib
import struct
import subprocess
import tempfile
import unittest
import zlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
JMX_HEADER = ROOT / "jmx" / "src" / "jmx_nl_rule_v3.h"
JMXD_HEADER = ROOT / "jmxd" / "src" / "jmx_nl_rule_v3.h"

ABI_VERSION = 3
ACTION_BEGIN = 50
ACTION_RULE_BATCH = 51
ACTION_STEP_BATCH = 52
ACTION_PORT_BATCH = 53
ACTION_COMMIT = 54
ACTION_ABORT = 55
ACTION_STATUS = 56
ACTION_CAPABILITY = 57

REASON_NONE = 0
REASON_BAD_ABI = 1
REASON_BAD_HEADER = 2
REASON_BAD_SIZE = 3
REASON_BAD_CRC = 4
REASON_BAD_GENERATION = 5
REASON_UNSUPPORTED_ACTION = 16

CAP_RAW_LITERAL_CHAIN = 0x00000001
CAP_NOCASE = 0x00000002
CAP_POSITION_ABSOLUTE = 0x00000004
CAP_POSITION_RELATIVE = 0x00000008
CAP_NORMALIZED_URI = 0x00000010
CAP_NEGATIVE = 0x00000020
CAP_BYTE_TEST = 0x00000040
CAP_BYTE_JUMP = 0x00000080
CAP_TCP_STREAM = 0x00000100
CAP_CROSS_DIRECTION_STATE = 0x00000200
CAP_PROTOCOL_MAPPING = 0x00000400

MODE_OFF = 0
MODE_SHADOW = 1
MODE_ACTIVE = 2
PROTO_TCP = 1
DIR_ORIGINAL = 1
MATCH_LITERAL_EXACT_1 = 0x01
CONDITION_POSITIVE = 1
CASE_EXACT = 2
VIEW_RAW = 0
POS_DEPTH = 0x01
PORT_DESTINATION = 2

HEADER = struct.Struct("<IHHIIIIII")
BEGIN = struct.Struct("<IIII32s")
RULE = struct.Struct("<IIIIHBBB3s")
STEP = struct.Struct("<IH7B3xiiiiHH4BIII64s")
PORT = struct.Struct("<IB3xHH")
STATUS = struct.Struct("<10I32s2I")


def build_request(
    action: int,
    generation: int,
    record_size: int,
    count: int,
    payload: bytes,
    flags: int = 0,
) -> bytes:
    return HEADER.pack(
        action,
        ABI_VERSION,
        HEADER.size,
        record_size,
        generation,
        count,
        len(payload),
        flags,
        zlib.crc32(payload) & 0xFFFFFFFF,
    ) + payload


def expected_record_size(action: int) -> int:
    return {
        ACTION_BEGIN: BEGIN.size,
        ACTION_RULE_BATCH: RULE.size,
        ACTION_STEP_BATCH: STEP.size,
        ACTION_PORT_BATCH: PORT.size,
    }.get(action, 0)


def validate_fixture(
    message: bytes,
    *,
    generation_required: bool = True,
    expected_generation: int | None = None,
) -> int:
    """Mirror invariant ordering used by jmx_v3_nl_handle for wire fixtures."""
    if len(message) < HEADER.size:
        return REASON_BAD_HEADER
    fields = HEADER.unpack_from(message)
    (
        action,
        abi_version,
        header_size,
        record_size,
        generation,
        count,
        payload_bytes,
        _flags,
        crc32,
    ) = fields
    if abi_version != ABI_VERSION:
        return REASON_BAD_ABI
    if header_size != HEADER.size:
        return REASON_BAD_HEADER
    if HEADER.size + payload_bytes != len(message):
        return REASON_BAD_SIZE
    payload = message[HEADER.size:]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc32:
        return REASON_BAD_CRC
    if action in (ACTION_CAPABILITY, ACTION_STATUS, ACTION_COMMIT, ACTION_ABORT):
        if (
            record_size
            or count
            or payload_bytes
            or (action in (ACTION_COMMIT, ACTION_ABORT) and generation == 0)
            or (action == ACTION_CAPABILITY and generation != 0)
        ):
            return REASON_BAD_SIZE
        return REASON_NONE
    if generation_required and generation == 0:
        return REASON_BAD_SIZE
    if record_size != expected_record_size(action) or count == 0:
        return REASON_BAD_SIZE
    if count * record_size != payload_bytes:
        return REASON_BAD_SIZE
    if action == ACTION_BEGIN and count != 1:
        return REASON_BAD_SIZE
    if expected_generation is not None and generation != expected_generation:
        return REASON_BAD_GENERATION
    return REASON_NONE


class V3WireContractTest(unittest.TestCase):
    def test_package_headers_are_byte_identical(self) -> None:
        self.assertEqual(JMX_HEADER.read_bytes(), JMXD_HEADER.read_bytes())

    def test_c_compiler_observes_fixed_wire_sizes_and_values(self) -> None:
        source = r'''
#include <stdio.h>
#include "jmx_nl_rule_v3.h"

_Static_assert(sizeof(struct jmx_nl_v3_hdr) == 32, "header ABI drift");
_Static_assert(sizeof(struct jmx_nl_begin_v3) == 48, "begin ABI drift");
_Static_assert(sizeof(struct jmx_nl_rule_v3) == 24, "rule ABI drift");
_Static_assert(sizeof(struct jmx_nl_step_v3) == 116, "step ABI drift");
_Static_assert(sizeof(struct jmx_nl_port_v3) == 12, "port ABI drift");
_Static_assert(sizeof(struct jmx_nl_status_v3) == 80, "status ABI drift");

int main(void) {
    printf("%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
        JMX_RULE_ABI_V3,
        JMX_NL_ACT_RULESET_BEGIN_V3,
        JMX_NL_ACT_RULE_V3_BATCH,
        JMX_NL_ACT_STEP_V3_BATCH,
        JMX_NL_ACT_PORT_V3_BATCH,
        JMX_NL_ACT_RULESET_COMMIT_V3,
        JMX_NL_ACT_RULESET_ABORT_V3,
        JMX_NL_ACT_RULESET_STATUS_V3,
        JMX_NL_ACT_CAPABILITY_V3,
        JMX_V3_CAP_RAW_LITERAL_CHAIN,
        JMX_V3_CAP_NOCASE,
        JMX_V3_CAP_POSITION_ABSOLUTE,
        JMX_V3_CAP_POSITION_RELATIVE,
        JMX_V3_CAP_NORMALIZED_URI,
        JMX_V3_CAP_NEGATIVE,
        JMX_V3_CAP_BYTE_TEST,
        JMX_V3_CAP_BYTE_JUMP,
        JMX_V3_CAP_TCP_STREAM,
        JMX_V3_CAP_CROSS_DIRECTION_STATE,
        JMX_V3_CAP_PROTOCOL_MAPPING,
        JMX_V3_CAP_KNOWN_MASK,
        JMX_V3_MODE_OFF,
        JMX_V3_MODE_SHADOW,
        JMX_V3_MODE_ACTIVE,
        JMX_V3_PROTO_TCP,
        JMX_V3_DIR_ORIGINAL,
        JMX_V3_MATCH_LITERAL_EXACT_1,
        JMX_V3_CONDITION_POSITIVE,
        JMX_V3_CASE_EXACT,
        JMX_V3_VIEW_RAW,
        JMX_V3_PORT_DESTINATION,
        JMX_V3_REASON_UNSUPPORTED_ACTION);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            source_path = pathlib.Path(tmp) / "wire_sizes.c"
            binary_path = pathlib.Path(tmp) / "wire_sizes"
            source_path.write_text(source, encoding="ascii")
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(JMX_HEADER.parent),
                    str(source_path),
                    "-o",
                    str(binary_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [str(binary_path)], check=True, capture_output=True, text=True
            )
        expected = [
            ABI_VERSION,
            ACTION_BEGIN,
            ACTION_RULE_BATCH,
            ACTION_STEP_BATCH,
            ACTION_PORT_BATCH,
            ACTION_COMMIT,
            ACTION_ABORT,
            ACTION_STATUS,
            ACTION_CAPABILITY,
            CAP_RAW_LITERAL_CHAIN,
            CAP_NOCASE,
            CAP_POSITION_ABSOLUTE,
            CAP_POSITION_RELATIVE,
            CAP_NORMALIZED_URI,
            CAP_NEGATIVE,
            CAP_BYTE_TEST,
            CAP_BYTE_JUMP,
            CAP_TCP_STREAM,
            CAP_CROSS_DIRECTION_STATE,
            CAP_PROTOCOL_MAPPING,
            0x000007FF,
            MODE_OFF,
            MODE_SHADOW,
            MODE_ACTIVE,
            PROTO_TCP,
            DIR_ORIGINAL,
            MATCH_LITERAL_EXACT_1,
            CONDITION_POSITIVE,
            CASE_EXACT,
            VIEW_RAW,
            PORT_DESTINATION,
            REASON_UNSUPPORTED_ACTION,
        ]
        self.assertEqual([int(value) for value in result.stdout.split()], expected)

    def test_python_layout_matches_c_contract(self) -> None:
        self.assertEqual(
            (HEADER.size, BEGIN.size, RULE.size, STEP.size, PORT.size, STATUS.size),
            (32, 48, 24, 116, 12, 80),
        )

    def test_ieee_crc32_over_payload_only_and_empty_catalog_digest(self) -> None:
        self.assertEqual(zlib.crc32(b"123456789") & 0xFFFFFFFF, 0xCBF43926)
        digest = hashlib.sha256(b"dreamingwrt-v3-empty-catalog").digest()
        self.assertEqual(
            digest.hex(),
            "95e4809a4ab2d91cc23757aeb0109aac65e7192496dab5b3466d5e8c932264dc",
        )
        payload = BEGIN.pack(0, 0, 0, 0, digest)
        message = build_request(ACTION_BEGIN, 7, BEGIN.size, 1, payload, flags=MODE_OFF)
        self.assertEqual(
            HEADER.unpack_from(message)[8], zlib.crc32(payload) & 0xFFFFFFFF
        )
        self.assertNotEqual(
            HEADER.unpack_from(message)[8], zlib.crc32(message) & 0xFFFFFFFF
        )
        self.assertEqual(validate_fixture(message), REASON_NONE)

    def test_wire_structs_are_little_endian(self) -> None:
        message = build_request(ACTION_BEGIN, 0x11223344, BEGIN.size, 1, b"x" * BEGIN.size)
        self.assertEqual(message[0:4], b"\x32\x00\x00\x00")
        self.assertEqual(message[4:8], b"\x03\x00\x20\x00")
        self.assertEqual(message[12:16], b"\x44\x33\x22\x11")

        rule = RULE.pack(
            0x01020304,
            0x11223344,
            0x55667788,
            0x00000403,
            0x1234,
            PROTO_TCP,
            DIR_ORIGINAL,
            0xA5,
            b"\x00\x00\x00",
        )
        self.assertEqual(rule.hex(), "0403020144332211887766550304000034120101a5000000")

        port = PORT.pack(0x01020304, PORT_DESTINATION, 443, 8443)
        self.assertEqual(port.hex(), "0403020102000000bb01fb20")

    def test_valid_begin_fixture(self) -> None:
        digest = hashlib.sha256(b"fixture-catalog").digest()
        payload = BEGIN.pack(1, 2, 0, 0x407, digest)
        message = build_request(ACTION_BEGIN, 7, BEGIN.size, 1, payload, flags=1)
        self.assertEqual(validate_fixture(message), REASON_NONE)

    def test_malformed_size_count_crc_and_generation_fixtures(self) -> None:
        payload = BEGIN.pack(1, 1, 0, 1, hashlib.sha256(b"fixture").digest())
        valid = build_request(ACTION_BEGIN, 9, BEGIN.size, 1, payload)

        self.assertEqual(validate_fixture(valid[:-1]), REASON_BAD_SIZE)

        bad_count = bytearray(valid)
        struct.pack_into("<I", bad_count, 16, 2)
        self.assertEqual(validate_fixture(bytes(bad_count)), REASON_BAD_SIZE)

        bad_crc = bytearray(valid)
        bad_crc[-1] ^= 0x80
        self.assertEqual(validate_fixture(bytes(bad_crc)), REASON_BAD_CRC)

        zero_generation = bytearray(valid)
        struct.pack_into("<I", zero_generation, 12, 0)
        self.assertEqual(validate_fixture(bytes(zero_generation)), REASON_BAD_SIZE)

        rule_payload = RULE.pack(
            1001,
            42,
            100,
            CAP_RAW_LITERAL_CHAIN,
            1,
            PROTO_TCP,
            DIR_ORIGINAL,
            0,
            b"\x00\x00\x00",
        )
        wrong_generation = build_request(ACTION_RULE_BATCH, 10, RULE.size, 1, rule_payload)
        self.assertEqual(
            validate_fixture(wrong_generation, expected_generation=9),
            REASON_BAD_GENERATION,
        )

    def test_capability_empty_request_allows_generation_zero(self) -> None:
        message = build_request(ACTION_CAPABILITY, 0, 0, 0, b"")
        self.assertEqual(
            validate_fixture(message, generation_required=False), REASON_NONE
        )

    def test_status_empty_request_accepts_snapshot_or_target_generation(self) -> None:
        current = build_request(ACTION_STATUS, 0, 0, 0, b"")
        target = build_request(ACTION_STATUS, 0x11223344, 0, 0, b"")
        self.assertEqual(validate_fixture(current), REASON_NONE)
        self.assertEqual(validate_fixture(target), REASON_NONE)


if __name__ == "__main__":
    unittest.main()
