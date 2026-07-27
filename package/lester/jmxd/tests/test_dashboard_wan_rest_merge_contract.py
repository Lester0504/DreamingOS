#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "webd" / "jmx_app_api.c"


def function_body(source, name):
    match = re.search(
        rf"(?:static\s+)?[^;{{]*?\b{re.escape(name)}\s*\([^;{{]*\)\s*\{{",
        source,
    )
    if not match:
        raise AssertionError(f"function not found: {name}")
    start = match.end()
    depth = 1
    for offset, char in enumerate(source[start:], start=start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:offset]
    raise AssertionError(f"unterminated function: {name}")


class DashboardWanRestMergeContractTest(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding="utf-8")

    def test_line_load_merge_preserves_runtime_device(self):
        body = function_body(self.source, "webd_merge_wan_load_item")

        self.assertIn(
            'runtime_device = app_nc_json_str(load, "runtime_device", device);',
            body,
        )
        self.assertIn('webd_put_string(wan, "runtime_device", runtime_device);', body)

    def test_line_load_merge_preserves_conntrack_evidence(self):
        body = function_body(self.source, "webd_merge_wan_load_item")

        for field in (
            "connections_source",
            "conntrack_state",
            "conntrack_total",
            "conntrack_mapped_total",
            "conntrack_unmapped",
            "conntrack_source",
            "observed_at",
        ):
            self.assertIn(f'"{field}"', body)
        self.assertIn('webd_put_int(wan, "connections", connections);', body)
        self.assertIn("webd_put_i64(rt, field", body)
        self.assertIn("webd_put_i64(wan, field", body)
        self.assertIn("webd_put_string(rt, field", body)
        self.assertIn("webd_put_string(wan, field", body)

    def test_network_wans_prefers_line_load_runtime(self):
        body = function_body(self.source, "webd_merge_network_wans_runtime")

        line_load = "webd_merge_wans_from_runtime(wans, items, 0);"
        line_health = "webd_merge_wans_from_runtime(wans, items, 1);"
        self.assertIn(line_load, body)
        self.assertIn(line_health, body)
        self.assertLess(body.index(line_load), body.index(line_health))


if __name__ == "__main__":
    unittest.main()
