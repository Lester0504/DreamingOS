#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src/jmx_v2_nl_handler.c").read_text()
RULES = (ROOT / "src/jmx_v2_rules.c").read_text()
HEADER = (ROOT / "src/jmx_v2_rules.h").read_text()
MAIN = (ROOT / "src/jmx_main.c").read_text()


def body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


def test_owner_aware_rule_api() -> None:
    assert "int jmx_v2_rules_begin(uint32_t owner_portid);" in HEADER
    assert "int jmx_v2_rule_add(uint32_t owner_portid," in HEADER
    assert "int jmx_v2_rules_commit(uint32_t owner_portid," in HEADER
    assert "jmx_v2_rules_flush" not in HEADER

    assert "jmx_v2_rules_begin(portid)" in HANDLER
    assert "jmx_v2_rule_add(portid, NULL)" in HANDLER
    assert "jmx_v2_rule_add(portid, &kr)" in HANDLER
    assert "jmx_v2_rules_commit(portid, vm->version)" in HANDLER


def test_begin_and_mutations_are_serialized() -> None:
    begin = body(RULES, "int jmx_v2_rules_begin(", "static int jmx_v2_rule_add_locked")
    add = body(RULES, "int jmx_v2_rule_add(", "/* ── Commit")
    commit = body(RULES, "int jmx_v2_rules_commit(", "uint32_t jmx_v2_rules_count")

    assert begin.index("mutex_lock(&rules_update_lock)") < begin.index(
        "staging_owner_portid != owner_portid"
    ) < begin.index("jmx_v2_rule_set_clear(STAGING_SET())")
    assert begin.index("staging_owner_portid = owner_portid") < begin.index(
        "jmx_v2_tx_refresh_locked()"
    )
    assert add.index("mutex_lock(&rules_update_lock)") < add.index(
        "jmx_v2_tx_check_owner_locked(owner_portid)"
    ) < add.index("jmx_v2_rule_add_locked(in)")
    assert commit.index("mutex_lock(&rules_update_lock)") < commit.index(
        "jmx_v2_tx_check_owner_locked(owner_portid)"
    )


def test_timeout_is_wrap_safe_and_clears_staging() -> None:
    assert "#define JMX_V2_TX_TIMEOUT (30U * HZ)" in RULES
    assert "time_after_eq(jiffies, staging_deadline)" in RULES
    assert "struct delayed_work rules_tx_expire_work" in RULES
    assert "INIT_DELAYED_WORK(&rules_tx_expire_work" in RULES
    assert "mod_delayed_work(system_wq, &rules_tx_expire_work" in RULES
    assert "cancel_delayed_work_sync(&rules_tx_expire_work)" in RULES

    expire = body(RULES, "static bool jmx_v2_tx_expire_locked", "static void jmx_v2_tx_expire_workfn")
    reset = body(RULES, "static void jmx_v2_tx_reset_locked", "static bool jmx_v2_tx_expire_locked")
    assert "jmx_v2_tx_reset_locked(true)" in expire
    assert "jmx_v2_rule_set_clear(STAGING_SET())" in reset
    assert "staging_owner_portid = 0" in reset
    assert "staging_deadline = 0" in reset


def test_commit_releases_only_the_accepted_owner() -> None:
    commit = body(RULES, "int jmx_v2_rules_commit(", "uint32_t jmx_v2_rules_count")
    owner_check = commit.index("jmx_v2_tx_check_owner_locked(owner_portid)")
    rejected = commit.index("owner_rejected:")
    assert "jmx_v2_tx_reset_locked(false)" in commit[owner_check:rejected]
    assert "jmx_v2_tx_reset_locked(true)" in commit[owner_check:rejected]
    assert "jmx_v2_tx_reset_locked" not in commit[rejected:]


def test_unrelated_actions_are_not_owner_gated() -> None:
    for marker in (
        "case JMX_NL_ACT_REGEX_RESULT:",
        "case JMX_NL_ACT_CARRIER_FLUSH:",
        "case JMX_NL_ACT_CARRIER_ADD:",
        "case JMX_NL_ACT_WAN_REGISTER:",
        "case JMX_NL_ACT_WAN_UNREGISTER:",
        "case JMX_NL_ACT_WAN_HEALTH:",
        "case JMX_NL_ACT_ROUTE_ADD:",
        "case JMX_NL_ACT_ROUTE_DEL:",
        "case JMX_NL_ACT_ROUTE_FLUSH:",
    ):
        start = HANDLER.index(marker)
        next_case = HANDLER.find("\n\tcase ", start + len(marker))
        section = HANDLER[start : next_case if next_case != -1 else len(HANDLER)]
        assert "jmx_v2_tx_" not in section
        assert "jmx_v2_rules_begin" not in section
        assert "jmx_v2_rule_add(" not in section
        assert "jmx_v2_rules_commit(" not in section

    assert "netlink_net_capable(skb, CAP_NET_ADMIN)" in MAIN


if __name__ == "__main__":
    test_owner_aware_rule_api()
    test_begin_and_mutations_are_serialized()
    test_timeout_is_wrap_safe_and_clears_staging()
    test_commit_releases_only_the_accepted_owner()
    test_unrelated_actions_are_not_owner_gated()
    print("ok: K-08 v2 rule transactions are owner-bound and expire safely")
