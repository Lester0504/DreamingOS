#!/usr/bin/env python3
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUTE = (ROOT / "src" / "jmx_route.c").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "jmx_main.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src" / "jmx_conntrack.h").read_text(encoding="utf-8")


def ipv6_rule_is_family_neutral(rule):
    return not (
        rule["carrier_id"]
        or rule["src_addr"]
        or rule["src_mask"]
        or rule["dst_addr"]
        or rule["dst_mask"]
    )


def select_weighted_slot(members, slot):
    healthy = [member for member in members if member["health"]]
    if not healthy:
        return None
    point = slot % sum(member["weight"] for member in healthy)
    for member in healthy:
        if point < member["weight"]:
            return member["wan_id"]
        point -= member["weight"]
    raise AssertionError("unreachable weighted slot")


class IPv6MultiWanContractTest(unittest.TestCase):
    def test_ipv6_rule_gate_fixture(self):
        fixtures = [
            ({"carrier_id": 0, "src_addr": 0, "src_mask": 0,
              "dst_addr": 0, "dst_mask": 0}, True),
            ({"carrier_id": 2, "src_addr": 0, "src_mask": 0,
              "dst_addr": 0, "dst_mask": 0}, False),
            ({"carrier_id": 0, "src_addr": 0x0A000000,
              "src_mask": 0xFF000000, "dst_addr": 0,
              "dst_mask": 0}, False),
            ({"carrier_id": 0, "src_addr": 0, "src_mask": 0,
              "dst_addr": 0x08080808, "dst_mask": 0xFFFFFFFF}, False),
            ({"carrier_id": 0, "src_addr": 0, "src_mask": 0xFFFFFFFF,
              "dst_addr": 0, "dst_mask": 0}, False),
            ({"carrier_id": 0, "src_addr": 0, "src_mask": 0,
              "dst_addr": 0x08080808, "dst_mask": 0}, False),
        ]
        for rule, expected in fixtures:
            self.assertEqual(ipv6_rule_is_family_neutral(rule), expected)

    def test_health_weight_and_failover_fixtures(self):
        members = [
            {"wan_id": 1, "weight": 1, "health": True},
            {"wan_id": 2, "weight": 2, "health": True},
        ]
        self.assertEqual(
            [select_weighted_slot(members, slot) for slot in range(6)],
            [1, 2, 2, 1, 2, 2],
        )

        members[0]["health"] = False
        self.assertEqual(
            [select_weighted_slot(members, slot) for slot in range(3)],
            [2, 2, 2],
        )

        members[1]["health"] = False
        self.assertIsNone(select_weighted_slot(members, 0))

    def test_selector_reuses_wan_health_weight_and_metrics(self):
        self.assertIn("const struct jmx_route_flow_key *key", ROUTE)
        self.assertIn("if (!wan || !wan->health || !wan->fwmark)", ROUTE)
        self.assertIn("jmx_weighted_slot_select(candidates, n", ROUTE)
        self.assertIn("jmx_select_min_metric_nolock(candidates, n, false", ROUTE)
        self.assertIn("jmx_select_min_metric_nolock(candidates, n, true", ROUTE)
        self.assertIn("jmx_route_select_wan_internal(&key", ROUTE)

    def test_ipv6_hash_uses_full_source_and_destination(self):
        hash6 = re.search(
            r"static u32 jmx_route_hash6\(.*?\n\}", ROUTE, re.S
        )
        self.assertIsNotNone(hash6)
        body = hash6.group(0)
        self.assertIn("memcpy(words, key->addr.v6.src", body)
        self.assertIn("memcpy(words + 4, key->addr.v6.dst", body)
        self.assertIn("jhash2(words, 10", body)

    def test_ipv4_only_rules_do_not_leak_into_ipv6(self):
        self.assertIn("key->family != AF_INET6", ROUTE)
        self.assertIn(
            "r->carrier_id || r->src_addr || r->src_mask ||", ROUTE
        )
        self.assertIn("r->dst_addr || r->dst_mask", ROUTE)

    def test_ipv6_hook_binds_and_restores_conntrack_mark(self):
        self.assertIn("jmx_route_select_wan6_acquire", HEADER)
        self.assertIn("if (flow->src6 && flow->dst6)", MAIN)
        self.assertIn("ct->jmx_data.route_mark = fwmark", MAIN)
        self.assertGreaterEqual(
            MAIN.count("skb->mark = ct->jmx_data.route_mark"), 3
        )
        self.assertRegex(
            MAIN,
            r"\.pf = NFPROTO_(?:INET|IPV6),\s*\n"
            r"\s*\.hooknum = NF_INET_PRE_ROUTING",
        )

    def test_ipv6_reuses_generation_rx_and_destroy_lifecycle(self):
        self.assertIn("ct->jmx_data.route_wan_generation = wan_generation", MAIN)
        self.assertIn("jmx_wan_flow_account_rx(wan_id, generation, bytes)", MAIN)
        self.assertIn("jmx_wan_flow_release(wan_id, generation)", MAIN)
        self.assertIn("CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY", MAIN)
        self.assertIn("jmx_route_prepare_lifecycle(ct)", MAIN)

    def test_all_down_keeps_main_route_fallback(self):
        self.assertIn("if (n == 0)\n\t\treturn NULL;", ROUTE)
        self.assertIn("int ret = -ENOENT;", ROUTE)
        self.assertIn("*out_fwmark = 0;", ROUTE)


if __name__ == "__main__":
    unittest.main()
