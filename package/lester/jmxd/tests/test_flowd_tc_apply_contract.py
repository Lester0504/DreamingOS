#!/usr/bin/env python3
"""Static contract for flowd's owned tc apply/readback boundary."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLOWD = ROOT / "src" / "flowd"
TC = (FLOWD / "flowd_tc_apply.c").read_text(encoding="utf-8")
HEADER = (FLOWD / "flowd_tc_apply.h").read_text(encoding="utf-8")
DB = (FLOWD / "flowd_db.c").read_text(encoding="utf-8")


FORBIDDEN_SHELL_FORMS = ("system(", "popen(", "sh -c", "/bin/sh")


def _assert_shell_free(source: str) -> None:
    for forbidden in FORBIDDEN_SHELL_FORMS:
        assert forbidden not in source, forbidden


def _assert_controlled_argv_executor(source: str, header: str = "") -> None:
    combined = source + "\n" + header
    for required in (
        "flowd_tc_run",
        "execv(argv[0], argv)",
        '"/usr/sbin/nft"',
        '"-j", "-d", "qdisc", "show"',
        '"/sbin/tc"',
        '"/sbin/ip"',
    ):
        assert required in combined, required


def test_executor_is_owned_and_shell_free() -> None:
    assert '"dreamingwrt-flowd"' in HEADER
    assert '"/sbin/tc"' in HEADER
    assert '"/sbin/ip"' in HEADER
    _assert_shell_free(TC)
    _assert_controlled_argv_executor(TC, HEADER)
    for required in (
        "flowd_tc_apply_executor_available",
        "flowd_tc_runtime_state_read",
        '"flowd_tc_apply_state"',
        "flowd_tc_write_state",
        "flowd_tc_readback_plan",
        "flowd_tc_ingress_attach",
        "flowd_tc_clear_plan",
        "flowd_wan_resolve_ifname",
        "flowd_tc_qdisc_state",
        'json_object_new_string("unchanged")',
        "cake_diffserv_tins",
        "legacy_nft_table_conflict",
        "tc_readback_failed",
        "rollback_ok",
        "flowd_apply_mode_disabled",
        "flowd_tc_resources",
    ):
        assert required in TC, required
    assert "flowd_apply_mode_plan_only" not in TC
    assert "plan-only" not in TC


def test_shell_free_contract_rejects_real_shell_mutations() -> None:
    """Keep the negative guard narrow: shell calls fail, argv nft remains valid."""
    for mutation in (
        'int injected(void) { return system("nft list ruleset"); }',
        'int injected(void) { return popen("tc qdisc show", "r") != 0; }',
        'char *injected[] = { "/bin/sh", "-c", "nft list ruleset", 0 };',
    ):
        mutated = TC + "\n" + mutation
        try:
            _assert_shell_free(mutated)
        except AssertionError:
            pass
        else:
            raise AssertionError("shell mutation was not rejected")
    _assert_controlled_argv_executor(TC, HEADER)


def test_compile_contract_exposes_tc_executor_without_claiming_nft() -> None:
    for required in (
        "flowd_tc_compile_artifacts",
        '"tc_executor_ready"',
        '"dreamingwrt-flowd.tc"',
        '"flowd_wan_capacity+flowd_qos_settings+flowd_qos_classes"',
        '"apply_requested"',
        '"runtime_applied"',
        '"runtime_reason"',
    ):
        assert required in DB, required


if __name__ == "__main__":
    test_executor_is_owned_and_shell_free()
    test_shell_free_contract_rejects_real_shell_mutations()
    test_compile_contract_exposes_tc_executor_without_claiming_nft()
    print("ok: flowd tc apply/readback contract")
