#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MAIN = (SRC / "jmx_main.c").read_text(encoding="utf-8")
V2 = (SRC / "jmx_v2_nl_handler.c").read_text(encoding="utf-8")
V3 = (SRC / "jmx_v3_nl_handler.c").read_text(encoding="utf-8")
RULES = (SRC / "jmx_v3_rules.c").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def test_single_inbound_dispatch_is_fail_closed_on_sender_capability() -> None:
    receive = function_body(MAIN, "static void jmx_netlink_msg_rcv")
    guard = "netlink_net_capable(skb, CAP_NET_ADMIN)"
    assert guard in receive
    assert "capable(CAP_NET_ADMIN)" not in receive
    assert receive.index(guard) < receive.index("nlmsg_hdr(skb)")
    assert receive.index(guard) < receive.index("jmx_user_msg_handle(")
    assert "return;" in receive[receive.index(guard) : receive.index("nlmsg_hdr(skb)")]


def test_legacy_v2_v3_share_the_guarded_dispatch_path() -> None:
    dispatch = function_body(MAIN, "static void jmx_user_msg_handle")
    for action in (
        "JMX_NL_MSG_INIT",
        "JMX_NL_MSG_ADD_FEATURE",
        "JMX_NL_MSG_CLEAN_FEATURE",
    ):
        assert action in dispatch
    assert "jmx_v2_nl_handle(" in dispatch
    assert "jmx_v3_nl_handle(" in V2
    assert "nl_cfg.input = jmx_netlink_msg_rcv" in MAIN


def test_v3_owner_portid_and_generation_checks_remain_enforced() -> None:
    owner = function_body(RULES, "static int check_owner_locked")
    handler = function_body(V3, "int jmx_v3_nl_handle")
    assert "v3_tx.owner_portid != owner_portid" in owner
    assert "v3_tx.generation != generation" in owner
    assert "v3_tx.set->generation != generation" in owner
    assert "jmx_v3_tx_commit(portid, generation" in handler
    assert "jmx_v3_tx_abort(portid, generation" in handler
    assert "jmx_v3_tx_add_rules(portid, generation" in handler
    assert "jmx_v3_tx_add_steps(portid, generation" in handler
    assert "jmx_v3_tx_add_ports(portid, generation" in handler


if __name__ == "__main__":
    test_single_inbound_dispatch_is_fail_closed_on_sender_capability()
    test_legacy_v2_v3_share_the_guarded_dispatch_path()
    test_v3_owner_portid_and_generation_checks_remain_enforced()
    print("ok: netlink capability defensive contract passed")
