#!/usr/bin/env python3
"""U-15 source contract for kernel-default restoration.

The handler changes live kernel state, persistent UCI state, and SQLite state.
This contract deliberately requires a fail-closed, reversible implementation
rather than accepting best-effort shell commands followed by an unconditional
success response.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    """Return one C function definition, including nested blocks."""
    match = re.search(rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{", SOURCE, re.S)
    if not match:
        raise AssertionError(f"missing function: {name}")
    brace = SOURCE.index("{", match.start())
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():index + 1]
    raise AssertionError(f"unterminated function: {name}")


def helper_names() -> set[str]:
    """Find the private helpers owned by the kernel-restore command family."""
    return {
        match.group(1)
        for match in re.finditer(
            r"\b(nc_kernel_restore_[A-Za-z0-9_]+)\s*\([^;]*?\)\s*\{",
            SOURCE,
            re.S,
        )
    }


def named_helper(*needles: str) -> tuple[str, str]:
    matches = sorted(
        name for name in HELPERS
        if all(needle in name.lower() for needle in needles)
    )
    if not matches:
        raise AssertionError(
            "missing dedicated nc_kernel_restore helper containing: "
            + ", ".join(needles)
        )
    name = matches[0]
    return name, function(name)


HANDLER = function("jmx_system_kernel_restore_defaults")
HELPERS = helper_names()
FAMILY = HANDLER + "\n" + "\n".join(function(name) for name in sorted(HELPERS))


def test_family_has_no_shell_command_boundary() -> None:
    forbidden_literals = (
        "nc_run_quiet(",
        "system(",
        "popen(",
        "pclose(",
        '"/bin/sh"',
        '"-c"',
        "/bin/sh -c",
    )
    for token in forbidden_literals:
        assert token not in FAMILY, \
            f"kernel-restore family still uses a shell command boundary: {token}"


def test_sysctl_uses_absolute_path_fixed_argv_and_shared_exec() -> None:
    assert '"/sbin/sysctl"' in FAMILY, "sysctl path must be absolute"
    assert re.search(r"(?:char|const\s+char)\s*\*\s*(?:const\s+)?[A-Za-z0-9_]*argv\s*\[", FAMILY), \
        "sysctl execution needs explicit argv vectors"
    for token in ('"-n"', '"-w"'):
        assert token in FAMILY, f"missing fixed sysctl argv token: {token}"
    assert '"--system"' not in FAMILY, \
        "BusyBox sysctl on DreamingWrt does not support --system"
    assert "jmx_exec_capture(" in FAMILY, \
        "sysctl readback must use bounded jmx_exec_capture"
    assert "jmx_exec_wait(" in FAMILY, \
        "sysctl mutations must use bounded jmx_exec_wait"
    assert not re.search(r'"sysctl(?:\s|$)', FAMILY), \
        "bare sysctl command strings are forbidden"


def test_every_exec_result_is_rejected_on_all_abnormal_states() -> None:
    _, guard = named_helper("exec", "ok")
    for state in ("timed_out", "truncated", "term_signal", "exit_code"):
        assert re.search(rf"(?:->|\.){state}\b", guard), \
            f"exec guard does not inspect {state}"
    assert re.search(r"timed_out\s*\|\||\|\|\s*[^;]*timed_out", guard)
    assert re.search(r"truncated\s*\|\||\|\|\s*[^;]*truncated", guard)
    assert re.search(r"term_signal\s*!=\s*0|term_signal\b[^;]*\|\|", guard)
    assert re.search(r"exit_code\s*!=\s*0", guard), \
        "non-zero sysctl exit status must fail closed"
    assert re.search(r"return\s+0\s*;", guard) and re.search(r"return\s+(?:-1|1)\s*;", guard), \
        "exec guard must have distinct accepted and rejected returns"


def test_sysctl_old_values_are_captured_before_write_and_reversed_on_failure() -> None:
    read_name, read_helper = named_helper("sysctl", "read")
    write_name, write_helper = named_helper("sysctl", "write")
    rollback_name, rollback_helper = named_helper("sysctl", "rollback")

    assert "jmx_exec_capture(" in read_helper and '"-n"' in read_helper
    assert "jmx_exec_wait(" in write_helper and '"-w"' in write_helper
    for token in ("old_value", "applied"):
        assert token in FAMILY, f"sysctl rollback snapshot lacks {token}"

    read_call = HANDLER.find(f"{read_name}(")
    write_call = HANDLER.find(f"{write_name}(")
    assert 0 <= read_call < write_call, \
        "each original sysctl value must be captured before the first mutation"
    assert f"{rollback_name}(" in HANDLER, \
        "the public handler must invoke sysctl rollback on failure"

    reverse_loop = re.search(
        r"for\s*\([^;]*-\s*1\s*;[^;]*(?:>=\s*0|>\s*0)[^;]*;[^)]*(?:--|-\s*=\s*1)",
        rollback_helper,
        re.S,
    )
    while_loop = re.search(
        r"while\s*\([^)]*(?:>\s*0|!=\s*0)[^)]*\)\s*\{[^{}]*(?:--|-\s*=\s*1)",
        rollback_helper,
        re.S,
    )
    assert reverse_loop or while_loop, \
        "applied sysctls must be rolled back in reverse order"
    assert write_name in rollback_helper or "jmx_exec_wait(" in rollback_helper, \
        "rollback must restore saved values through the fixed-argv writer"


def test_tuning_file_is_removed_with_unlink_not_rm() -> None:
    path = "/etc/sysctl.d/99-dreamingwrt-tuning.conf"
    assert path in FAMILY, "kernel tuning file path is missing"
    assert "unlink(" in FAMILY, "kernel tuning file must be removed with unlink(2)"
    assert not re.search(rf'"[^"\n]*\brm\b[^"\n]*{re.escape(path)}', FAMILY), \
        "kernel tuning cleanup must not spawn rm"
    publish_name, publish = named_helper("tuning", "publish")
    verify_name, verify = named_helper("tuning", "verify")
    assert "openat(" in FAMILY and "O_NOFOLLOW" in FAMILY and "O_EXCL" in FAMILY
    assert "fsync(" in FAMILY and "renameat(" in FAMILY
    assert "Managed by DreamingWrt kernel restore-defaults" in publish
    assert "nc_kernel_restore_tuning_write(" in publish
    assert "memcmp(" in verify and "lstat(" in verify
    assert f"{publish_name}(" in HANDLER and f"{verify_name}(" in publish


def test_system_uci_uses_libuci_snapshot_commit_and_rollback() -> None:
    snapshot_name, snapshot = named_helper("uci", "snapshot")
    apply_name, apply = named_helper("uci", "apply")
    rollback_name, rollback = named_helper("uci", "rollback")

    assert '"system"' in FAMILY and '"packet_steering"' in FAMILY
    assert "uci_alloc_context(" in FAMILY and "uci_load(" in FAMILY
    assert "uci_foreach_element(" in FAMILY, \
        "system @system[0] must be resolved as a real type=system section"
    assert "uci_lookup_option_string(" in snapshot, \
        "UCI rollback snapshot must preserve the old option value"
    assert re.search(r"(?:existed|was_set|had_value|present)", snapshot), \
        "UCI snapshot must distinguish an absent option from an empty value"
    assert "uci_set(" in apply or "nc_uci_set_pkg(" in apply
    assert "jmx_uci_commit(" in apply or "uci_commit(" in apply
    assert ("uci_set(" in rollback or "nc_uci_set_pkg(" in rollback or
            "uci_delete(" in rollback or "nc_uci_delete_pkg(" in rollback)
    assert "jmx_uci_commit(" in rollback or "uci_commit(" in rollback
    assert '"/sbin/uci"' not in FAMILY and not re.search(r'"uci\s', FAMILY)

    for name in (snapshot_name, apply_name, rollback_name):
        assert f"{name}(" in HANDLER, f"handler does not use UCI helper {name}"
    assert HANDLER.find(f"{snapshot_name}(") < HANDLER.find(f"{apply_name}(")


def test_sqlite_commit_is_transactional_and_follows_runtime_uci_verification() -> None:
    db_names = sorted(
        name for name in HELPERS
        if "sqlite" in name.lower() or "_db_" in name.lower()
    )
    assert db_names, "kernel restore needs a dedicated SQLite transaction helper"
    db_name = db_names[0]
    db_helper = function(db_name)
    for statement in ('"BEGIN IMMEDIATE"', '"COMMIT"', '"ROLLBACK"'):
        assert statement in db_helper, f"SQLite transaction lacks {statement}"
    assert "sqlite3_exec(" in db_helper
    assert "sqlite3_step(" in db_helper or "nc_step_done(" in db_helper

    db_call = HANDLER.find(f"{db_name}(")
    assert db_call >= 0, "public handler does not invoke SQLite transaction helper"
    pre_db = HANDLER[:db_call]
    assert re.search(r"readback_verified\s*=\s*1", pre_db), \
        "SQLite must not begin before runtime sysctl readback succeeds"
    assert re.search(r"uci_(?:committed|applied|verified)\s*=\s*1", pre_db), \
        "SQLite must not begin before UCI apply/commit succeeds"
    assert re.search(
        r"if\s*\([^)]*!\s*readback_verified[^)]*\)\s*(?:\{|goto|return)",
        pre_db,
        re.S,
    ), "handler must gate SQLite on readback_verified"


def test_response_exposes_transaction_and_rollback_truth() -> None:
    fields = (
        "failed_stage",
        "actions_attempted",
        "actions_applied",
        "readback_verified",
        "rollback_attempted",
        "rollback_succeeded",
        "reason",
    )
    for field in fields:
        assert f'"{field}"' in FAMILY, f"response omits {field}"
    assert "API_CODE_ERROR" in FAMILY, \
        "runtime/UCI/SQLite failures must not return success"
    assert "API_CODE_SUCCESS" in FAMILY
    assert re.search(r'"ok"[^;]*json_object_new_boolean\(0\)', FAMILY), \
        "failure response must report ok=false"
    assert re.search(r'"ok"[^;]*json_object_new_boolean\(1\)', FAMILY), \
        "verified commit response must report ok=true"
    assert not re.search(
        r"\n\s*rollback_ok\s*=\s*0\s*;\s*\n\s*rollback_ok\s*=\s*0\s*;",
        HANDLER,
    ), "rollback state must not be forced false outside a failed compensation"


if __name__ == "__main__":
    test_family_has_no_shell_command_boundary()
    test_sysctl_uses_absolute_path_fixed_argv_and_shared_exec()
    test_every_exec_result_is_rejected_on_all_abnormal_states()
    test_sysctl_old_values_are_captured_before_write_and_reversed_on_failure()
    test_tuning_file_is_removed_with_unlink_not_rm()
    test_system_uci_uses_libuci_snapshot_commit_and_rollback()
    test_sqlite_commit_is_transactional_and_follows_runtime_uci_verification()
    test_response_exposes_transaction_and_rollback_truth()
    print("ok: U-15 kernel restore is fixed-argv, verified, transactional, and reversible")
