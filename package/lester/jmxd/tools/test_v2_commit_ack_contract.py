#!/usr/bin/env python3
"""Host-side regression tests for the DreamingWrt legacy v2 VERSION ACK contract."""

from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
JMXD_HEADER = ROOT / "jmxd" / "src" / "jmx_nl_rule.h"
JMXD_PUSH = ROOT / "jmxd" / "src" / "jmx_nl_push.c"
JMX_HANDLER = ROOT / "jmx" / "src" / "jmx_v2_nl_handler.c"
JMX_RULES_H = ROOT / "jmx" / "src" / "jmx_v2_rules.h"

JMX_NL_MAGIC = 0xA0B0C0D0
ACTION_VERSION = 13
NLMSG_HDRLEN = 16
OUTER = struct.Struct("=II")
VERSION_REQ = struct.Struct("=iI")
VERSION_ACK = struct.Struct("=iIi")
# Real ACK has four fields.  Keep a separate Struct expression to make the
# expected order explicit: action/version/active_count/status.
VERSION_ACK_FULL = struct.Struct("=iIIi")


def nlmsg(seq: int, payload: bytes, *, pid: int = 0, magic: int = JMX_NL_MAGIC) -> bytes:
    outer = OUTER.pack(magic, len(payload))
    length = NLMSG_HDRLEN + len(outer) + len(payload)
    return struct.pack("=IHHII", length, 29, 0, seq, pid) + outer + payload


def decode_commit_ack(packet: bytes, *, seq: int, version: int, expected_count: int) -> str:
    if len(packet) < NLMSG_HDRLEN:
        return "unknown"
    nl_len, _typ, _flags, nl_seq, nl_pid = struct.unpack_from("=IHHII", packet)
    if nl_len < NLMSG_HDRLEN or nl_len > len(packet):
        return "unknown"
    if nl_seq != seq or nl_pid != 0:
        return "unknown"
    nl_payload = nl_len - NLMSG_HDRLEN
    if nl_payload != OUTER.size + VERSION_ACK_FULL.size:
        return "nack:wire-size"
    magic, inner_len = OUTER.unpack_from(packet, NLMSG_HDRLEN)
    if magic != JMX_NL_MAGIC or inner_len != VERSION_ACK_FULL.size:
        return "nack:outer"
    action, ack_version, active_count, status = VERSION_ACK_FULL.unpack_from(
        packet, NLMSG_HDRLEN + OUTER.size
    )
    if action != ACTION_VERSION:
        return "nack:action"
    if status != 0:
        return f"nack:status:{status}"
    if ack_version != version or active_count != expected_count:
        return "nack:snapshot"
    return "ok"


class V2CommitAckContractTest(unittest.TestCase):
    def test_c_header_exports_fixed_version_ack_wire_size(self) -> None:
        source = r'''
#include <stdio.h>
#include "jmx_nl_rule.h"

_Static_assert(sizeof(struct jmx_nl_rule_version_msg) == 8, "v2 VERSION request ABI drift");
_Static_assert(sizeof(struct jmx_nl_rule_version_ack) == 16, "v2 VERSION ACK ABI drift");
_Static_assert(JMX_NL_ACT_RULE_VERSION == 13, "v2 VERSION action drift");

int main(void) {
    printf("%u %zu %zu %u\n", JMX_NL_ACT_RULE_VERSION,
           sizeof(struct jmx_nl_rule_version_msg),
           sizeof(struct jmx_nl_rule_version_ack), JMX_NL_MAGIC);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "v2_ack_sizes.c"
            bin_path = pathlib.Path(tmp) / "v2_ack_sizes"
            src.write_text(source, encoding="ascii")
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(JMXD_HEADER.parent),
                    str(src),
                    "-o",
                    str(bin_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run([str(bin_path)], check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.split(), ["13", "8", "16", str(JMX_NL_MAGIC)])

    def test_python_layout_documents_request_and_ack_order(self) -> None:
        self.assertEqual(VERSION_REQ.size, 8)
        self.assertEqual(VERSION_ACK_FULL.size, 16)
        request = VERSION_REQ.pack(ACTION_VERSION, 0x11223344)
        ack = VERSION_ACK_FULL.pack(ACTION_VERSION, 0x11223344, 7, -22)
        self.assertEqual(request.hex(), "0d00000044332211")
        self.assertEqual(ack.hex(), "0d0000004433221107000000eaffffff")

    def test_ack_decoder_requires_kernel_peer_seq_size_action_status_and_snapshot(self) -> None:
        good = nlmsg(99, VERSION_ACK_FULL.pack(ACTION_VERSION, 1234, 42, 0))
        self.assertEqual(decode_commit_ack(good, seq=99, version=1234, expected_count=42), "ok")
        self.assertEqual(
            decode_commit_ack(nlmsg(98, VERSION_ACK_FULL.pack(ACTION_VERSION, 1234, 42, 0)), seq=99, version=1234, expected_count=42),
            "unknown",
        )
        self.assertEqual(
            decode_commit_ack(nlmsg(99, VERSION_ACK_FULL.pack(ACTION_VERSION, 1234, 42, 0), pid=77), seq=99, version=1234, expected_count=42),
            "unknown",
        )
        self.assertEqual(
            decode_commit_ack(nlmsg(99, VERSION_ACK_FULL.pack(12, 1234, 42, 0)), seq=99, version=1234, expected_count=42),
            "nack:action",
        )
        self.assertEqual(
            decode_commit_ack(nlmsg(99, VERSION_ACK_FULL.pack(ACTION_VERSION, 1234, 41, 0)), seq=99, version=1234, expected_count=42),
            "nack:snapshot",
        )
        self.assertEqual(
            decode_commit_ack(nlmsg(99, VERSION_ACK_FULL.pack(ACTION_VERSION, 1234, 42, -5)), seq=99, version=1234, expected_count=42),
            "nack:status:-5",
        )
        short_payload = VERSION_ACK.pack(ACTION_VERSION, 1234, 0)
        self.assertEqual(
            decode_commit_ack(nlmsg(99, short_payload), seq=99, version=1234, expected_count=42),
            "nack:wire-size",
        )

    def test_userspace_commit_uses_nonzero_seq_and_send_wait_under_same_mutex(self) -> None:
        src = JMXD_PUSH.read_text(encoding="utf-8")
        self.assertIn("nl_send_seq(fd, &vmsg, sizeof(vmsg), seq)", src)
        self.assertIn("v2_wait_commit_ack_locked(fd, seq, version, expected_count)", src)
        self.assertRegex(src, re.compile(r"static uint32_t v2_next_seq_locked\(void\).*?if \(!g_v2_next_seq\).*?g_v2_next_seq = 1;", re.S))
        self.assertRegex(src, re.compile(r"v2_lock\(\);.*?nl_flush_rules_locked\(nl_fd\).*?nl_commit_version_locked\(nl_fd, version, pushed\).*?v2_unlock_preserve_errno\(\);", re.S))
        self.assertIn("ack->version != version || ack->active_count != expected_count", src)
        self.assertIn("nlh->nlmsg_seq != seq || nlh->nlmsg_pid != 0", src)
        self.assertIn("static pthread_mutex_t g_nl_lock", src)
        self.assertNotIn("g_v2_nl_lock", src)
        self.assertNotIn("g_v3_nl_lock", src)
        self.assertIn("nl_payload != sizeof(*outer) + sizeof(*ack)", src)
        self.assertIn("ack->action != JMX_NL_ACT_RULE_VERSION", src)
        self.assertIn("ack->status != 0", src)

    def test_kernel_version_handler_replies_with_active_snapshot_and_errno_status(self) -> None:
        handler = JMX_HANDLER.read_text(encoding="utf-8")
        rules_h = JMX_RULES_H.read_text(encoding="utf-8")
        self.assertIn("void jmx_v2_rules_active_snapshot(uint32_t *version, uint32_t *count);", rules_h)
        self.assertIn("struct v2_version_ack_msg", handler)
        self.assertLess(handler.index("case JMX_NL_ACT_RULE_VERSION"), handler.index("if (jmx_v3_nl_handle"))
        self.assertIn("jmx_v2_rules_active_snapshot(&active_version, &active_count)", handler)
        self.assertIn("ack.status = status;", handler)
        self.assertIn("len != (int)sizeof(struct v2_version_msg)", handler)
        self.assertIn("v2_send_version_ack(reply, portid, nlmsg_seq, -EMSGSIZE)", handler)
        self.assertIn("rc = jmx_v2_rules_commit(vm->version);", handler)
        self.assertIn("v2_send_version_ack(reply, portid, nlmsg_seq, rc)", handler)


if __name__ == "__main__":
    unittest.main()
