#!/usr/bin/env python3
from pathlib import Path


HERE = Path(__file__).resolve().parent
LESTER = HERE.parent.parent
if not (LESTER / "jmx" / "src" / "jmx_conntrack.h").exists():
    raise RuntimeError(f"cannot locate package root from {HERE}")
TREE = LESTER.parents[1] if LESTER.name == "lester" else LESTER


def read(path: str) -> str:
    base = TREE if path.startswith("target/") else LESTER
    return (base / path).read_text(encoding="utf-8")


def read_optional(path: str) -> str:
    base = TREE if path.startswith("target/") else LESTER
    candidate = base / path
    return candidate.read_text(encoding="utf-8") if candidate.exists() else ""


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def test_kernel_route_engine() -> None:
    header = read("jmx/src/jmx_conntrack.h")
    route = read("jmx/src/jmx_route.c")

    assert "JMX_STICKY_DOWNLOAD    = 7" in header
    assert "JMX_STICKY_CONN_CNT    = 8" in header
    for field in ("u32  weight", "atomic64_t rx_bytes", "atomic64_t active_conn", "u32  generation"):
        assert field in header

    match = section(route, "static int jmx_rule_match", "static u32 jmx_route_hash")
    assert "jmx_carrier_lookup_nolock(key->addr.v4.dst)" in match
    assert "jmx_carrier_lookup(dst_ip)" not in match
    assert "key->family == AF_INET" in match
    assert "key->family != AF_INET6" in match
    assert "only family-neutral rules may" in match
    assert "jmx_weighted_metric_cmp" in route
    assert "div64_u64" in route
    assert "jmx_weighted_slot_select" in route
    assert "g_new_flow_seq[rule_idx]++" in route
    assert "return candidates[jmx_route_hash" not in route
    assert "JMX_STICKY_DOWNLOAD" in route
    assert "JMX_STICKY_CONN_CNT" in route
    assert "jmx_route_select_wan_acquire" in route
    assert "jmx_route_select_wan6" in route
    assert "jmx_route_select_wan6_acquire" in route
    assert "atomic64_inc(&wan->active_conn)" in route
    assert "wan->generation == generation" in route
    assert "weight active_conn rx_bytes generation" in route


def test_wire_and_userspace() -> None:
    header = read("jmxd/src/routed/jmx_route.h")
    routed = read("jmxd/src/routed/jmx_route.c")
    handler = read("jmx/src/jmx_v2_nl_handler.c")

    assert "struct jmx_wan_register_wire" in header
    assert "sizeof(struct jmx_wan_register_wire) == 37" in header
    assert "sizeof(struct jmx_nl_wan_register_v1) == 33" in handler
    assert "sizeof(struct jmx_nl_wan_register_v2) == 37" in handler
    assert "u32 weight = 1" in handler
    assert "len >= (int)sizeof(struct jmx_nl_wan_register_v2)" in handler
    assert 'json_get_weight(req_obj, "weight", 1, &weight)' in routed
    assert 'json_get_u32(wan, "weight", 1)' in routed
    assert "jmx_route_db_replace_begin" in routed
    assert '!strcmp(s, "download") || !strcmp(s, "least_rx_load_normalized")' in routed
    assert 'if (!strcmp(s, "conn_cnt")' in routed
    for algorithm in (
        "hash_src_dst_dport", "hash_src_dst", "weighted_new_flow_rr",
        "least_rx_load_normalized", "least_active_conn_normalized",
        "hash_src", "hash_src_sport",
    ):
        assert algorithm in routed
    assert 'json_get_str(\n        rule, "algorithm"' in routed
    assert 'json_object_new_string(route_mode_algorithm(mode_id)' in read("jmxd/src/routed/jmx_route_db.c")
    assert 'return UINT8_MAX' in routed
    assert '"all_down_actions", json_object_new_string("main_route")' in routed
    assert 'strcmp(all_down_action, "main_route")' in read("jmxd/src/routed/jmx_route_db.c")
    assert '"id name fwmark table gateway health weight active_conn rx_bytes generation' in read("jmx/src/jmx_route.c")
    assert 'json_object_object_add(o, "active_conn"' in routed
    assert 'json_object_object_add(o, "rx_bytes"' in routed
    sender = section(routed, "static int jmx_route_nl_send", "int jmx_route_nl_carrier_flush")
    assert "nlh->nlmsg_len = NLMSG_LENGTH(total)" in sender
    assert "nlh->nlmsg_len = NLMSG_SPACE(total)" not in sender


def test_conntrack_lifecycle() -> None:
    main = read("jmx/src/jmx_main.c")
    patches = (
        read_optional("target/linux/generic/hack-7.2/980-nf-contrack-support-jmx-data.patch"),
        read_optional("target/linux/generic/hack-7.1/980-nf-contrack-support-jmx-data.patch"),
    )
    patch = next((candidate for candidate in patches
                  if "route_wan_generation" in candidate and
                  "route_counted" in candidate), "")
    events = read_optional("target/linux/generic/hack-7.2/952-net-conntrack-events-support-multiple-registrant.patch")
    if not events:
        events = read_optional("target/linux/generic/hack-7.1/952-net-conntrack-events-support-multiple-registrant.patch")
    package = read("jmx/Makefile")

    if patch:
        assert "route_wan_generation" in patch
        assert "route_counted" in patch
    assert "jmx_route_select_wan_acquire" in main
    assert "nf_ct_ecache_ext_add(ct, BIT(IPCT_DESTROY)" in main
    assert "nf_ct_ext_add(ct, NF_CT_EXT_ECACHE, GFP_ATOMIC)" in main
    assert "ecache->ctmask |= BIT(IPCT_DESTROY)" in main
    assert "events & (1UL << IPCT_DESTROY)" in main
    assert "xchg(&ct->jmx_data.route_counted, 0)" in main
    assert "jmx_wan_flow_release(wan_id, generation)" in main
    assert "CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY" in main
    assert "jmx_wan_flow_account_rx(wan_id, generation, bytes)" in main
    if events:
        assert "net->ct.nf_conntrack_chain" in events
        assert "atomic_notifier_call_chain(&net->ct.nf_conntrack_chain" in events
    assert "CONFIG_NF_CONNTRACK_CHAIN_EVENTS=y" in package


def test_main_nondefault_lookup_guard() -> None:
    routed = read("jmxd/src/routed/jmx_route.c")
    install = section(routed, "static int route_main_nondefault_rule_install", "static const char *route_json_string")
    cleanup = section(routed, "static void jmx_route_cleanup_old_system_routes", "static void jmx_route_state_add")
    sync = section(routed, "static int jmx_route_sync_json(struct json_object *config)\n{",
                   "int jmx_route_sync_config(void)")
    readback = section(routed, "static int route_main_nondefault_rule_count", "static int route_main_nondefault_rule_install")

    required = ('"priority", priority', '"lookup", "main"', '"suppress_prefixlength", "0"')
    for token in required:
        assert token in install
    assert "route_main_nondefault_rule_delete();" not in cleanup
    assert 'strstr(p, "lookup main")' in readback
    assert 'strstr(p, "suppress_prefixlength 0")' in readback
    assert "while (count > 1)" in install
    assert '"rule", "del", "priority", priority' in install
    assert "JMX_ROUTE_MAIN_NONDEFAULT_PRIO 1000" in routed
    assert "JMX_ROUTE_RULE_PRIO_BASE 10000" in routed
    assert "JMX_ROUTE_MAIN_NONDEFAULT_PRIO < JMX_ROUTE_RULE_PRIO_BASE" in routed
    assert "route_main_nondefault_rule_install()" in sync
    assert sync.index("route_main_nondefault_rule_install()") < sync.index("jmx_route_nl_rule_flush(fd)")
    assert sync.index("route_main_nondefault_rule_install()") < sync.index("jmx_route_apply_system_route(")
    assert "route_main_nondefault_rule_count()" in sync
    assert "route_kernel_state_counts" in sync
    assert "route_main_nondefault_rule_count" in sync
    assert "route_sync_network_wans" in sync
    direct_add = section(routed, "struct json_object *jmx_api_route_rule_add", "struct json_object *jmx_api_route_rule_del")
    assert direct_add.index("route_main_nondefault_rule_install()") < direct_add.index("jmx_route_nl_rule_add")
    direct_flush = section(routed, "struct json_object *jmx_api_route_rule_flush", "static struct json_object *route_json_ok")
    assert "route_main_nondefault_rule_delete();" not in direct_flush
    assert '"main_nondefault_rule_ready"' in routed
    assert '"main_nondefault_rule_count"' in routed


def test_explicit_wan_prefers_runtime_ppp_state() -> None:
    routed = read("jmxd/src/routed/jmx_route.c")
    sync = section(routed, "static int jmx_route_sync_json(struct json_object *config)\n{",
                   "int jmx_route_sync_config(void)")
    explicit = section(sync, 'json_object_object_get_ex(config, "wans", &wans)', "if (wan_count == 0)")

    assert "route_ifstatus_runtime(name, l3_ifname" in explicit
    assert "runtime_gateway, sizeof(runtime_gateway)" in explicit
    assert 'snprintf(logical_name, sizeof(logical_name), "wan%u", id)' in explicit
    assert "if (runtime_gateway[0])" in explicit
    assert "gw_str = runtime_gateway" in explicit
    assert "gateway = route_ipv4_from_string(gw_str, 0)" in explicit
    assert "if (runtime_ok)" in explicit
    assert "health = runtime_online ? 1 : 0" in explicit
    assert 'strncmp(route_ifname, "ppp", 3)' in explicit
    assert "system_gateway = NULL" in explicit
    assert "jmx_route_apply_system_route(route_ifname, fwmark, table_id," in explicit
    assert "system_gateway)" in explicit


def main() -> None:
    test_kernel_route_engine()
    test_wire_and_userspace()
    test_conntrack_lifecycle()
    test_main_nondefault_lookup_guard()
    test_explicit_wan_prefers_runtime_ppp_state()
    print("ok: multi-WAN route, lifecycle, wire, persistence, and LAN return guard contracts")


if __name__ == "__main__":
    main()
