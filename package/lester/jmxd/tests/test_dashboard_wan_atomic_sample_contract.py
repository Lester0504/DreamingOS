#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "jmx_dreamingwrt_api.c"


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


class DashboardWanAtomicSampleContractTest(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding="utf-8")

    def test_fast_cached_read_does_not_advance_counter_baseline(self):
        body = function_body(self.source, "dw_realtime_dashboard_throughput_topic")
        update_block = re.search(
            r"if \(slot && update_baseline\) \{(?P<body>.*?)\n\s*\}",
            body,
            re.S,
        )

        self.assertIsNotNone(update_block)
        self.assertIn("slot->last_ms = now_ms;", update_block.group("body"))
        cached_branch = re.search(
            r"else if \(slot->valid\) \{(?P<body>.*?)\n\s*\} else \{",
            body,
            re.S,
        )
        self.assertIsNotNone(cached_branch)
        self.assertNotIn("update_baseline", cached_branch.group("body"))
        self.assertNotIn("slot->last_ms", cached_branch.group("body"))

    def test_unreadable_live_counter_is_not_published_as_idle(self):
        body = function_body(self.source, "dw_realtime_dashboard_throughput_topic")

        self.assertIn('zero_reason = "counter_source_unavailable";', body)
        self.assertRegex(
            body,
            r"else \{\s*sample_valid = 0;\s*up_rate = 0;\s*down_rate = 0;\s*"
            r'zero_reason = "counter_source_unavailable";',
        )

    def test_summary_uses_one_throughput_object_for_traffic_and_wans(self):
        body = function_body(self.source, "dw_handle_summary")

        self.assertEqual(
            body.count("dw_realtime_dashboard_throughput_topic(NULL)"), 1
        )
        self.assertIn("dw_overlay_traffic_from_throughput(traffic, throughput);", body)
        self.assertIn("dw_overlay_wans_from_throughput(wans, throughput);", body)

    def test_realtime_topics_share_one_atomic_sample(self):
        body = function_body(self.source, "jmx_dreamingwrt_realtime_snapshot_get")

        self.assertEqual(
            body.count("throughput = dw_realtime_dashboard_throughput_topic(req);"), 1
        )
        self.assertIn("dw_realtime_common_topics(throughput)", body)
        self.assertIn("json_object_get(throughput)", body)
        self.assertIn("dw_overlay_wans_from_throughput(wans, throughput);", body)

    def test_global_validity_requires_every_wan_sample(self):
        body = function_body(self.source, "dw_realtime_dashboard_throughput_topic")

        self.assertIn("wan_count > 0 && valid_count == wan_count", body)
        self.assertIn('"incomplete_wan_sample"', body)
        self.assertIn("LEFT JOIN net_interface_state", body)
        self.assertNotIn("s.ts>=?1", body)

    def test_runtime_inventory_is_scoped_to_current_uci_wans(self):
        body = function_body(self.source, "dw_realtime_dashboard_throughput_topic")

        self.assertIn("dw_configured_wan_names", body)
        self.assertIn("dw_configured_wan_index", body)
        self.assertIn("if (configured_index < 0)\n            continue;", body)
        self.assertIn('"runtime_inventory_missing"', body)

    def test_throughput_wans_do_not_publish_global_connections(self):
        body = function_body(self.source, "dw_realtime_dashboard_throughput_topic")

        # The topic-level value is the system conntrack total. It must never be
        # attached to one WAN merely because that WAN is first in the array.
        self.assertIn(
            'json_object_object_add(out, "connections", '
            'json_object_new_int(global_connections));',
            body,
        )
        self.assertNotRegex(
            body,
            r'json_object_object_add\s*\(\s*w\s*,\s*"connections"',
        )

    def test_throughput_overlay_cannot_replace_wan_conntrack_attribution(self):
        body = function_body(self.source, "dw_overlay_wan_sample")

        for field in (
            "connections",
            "connections_source",
            "conntrack_state",
            "conntrack_mapped_total",
            "conntrack_unmapped",
            "observed_at",
        ):
            self.assertNotIn(f'"{field}"', body)

    def test_dashboard_and_wan_models_share_conntrack_attribution(self):
        for name in (
            "dw_handle_summary",
            "dw_realtime_common_topics",
            "jmx_dreamingwrt_realtime_snapshot_get",
            "dw_handle_line_load",
        ):
            body = function_body(self.source, name)
            self.assertIn("dw_apply_wan_conntrack_contract", body, name)

    def test_shared_conntrack_contract_publishes_quality_and_observation(self):
        body = function_body(self.source, "dw_apply_wan_conntrack_contract")

        for field in (
            "connections",
            "connections_source",
            "conntrack_state",
            "conntrack_mapped_total",
            "conntrack_unmapped",
            "observed_at",
        ):
            self.assertIn(f'"{field}"', body)
        self.assertIn('"per_wan_conntrack_attribution"', body)
        self.assertIn('"global_conntrack_single_wan"', body)

    def test_atomic_realtime_reuses_dashboard_conntrack_snapshot(self):
        body = function_body(self.source, "jmx_dreamingwrt_realtime_snapshot_get")

        self.assertIn("dashboard_conntrack_wans", body)
        self.assertIn(
            "dw_copy_wan_conntrack_contract(wans, dashboard_conntrack_wans)",
            body,
        )
        self.assertRegex(
            body.replace("\n", " "),
            r"if \(dashboard_conntrack_wans\).*?dw_copy_wan_conntrack_contract"
            r".*?else\s+dw_apply_wan_conntrack_contract",
        )


if __name__ == "__main__":
    unittest.main()
