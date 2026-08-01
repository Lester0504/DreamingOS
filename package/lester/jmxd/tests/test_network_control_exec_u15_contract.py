#!/usr/bin/env python3
"""U-15 source contract for network-control nft/tc runtime apply.

The generated rules are privileged input.  Applying them must never cross a
shell command boundary, must be bounded, and must fail closed unless the
resulting nft table/qdisc state is read back and verified.  This test is
intentionally source based so a regression cannot be hidden behind a mocked
successful command runner.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
EXEC_SOURCE = (ROOT / "src/jmx_exec.c").read_text(encoding="utf-8")


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


def reachable_family(root: str) -> dict[str, str]:
    """Collect local nc_* helpers transitively called by a guarded apply."""
    found: dict[str, str] = {}
    pending = [root]
    while pending:
        name = pending.pop()
        if name in found:
            continue
        body = function(name)
        found[name] = body
        for callee in re.findall(r"\b(nc_[A-Za-z0-9_]+)\s*\(", body):
            if callee in found or callee in pending:
                continue
            try:
                function(callee)
            except AssertionError:
                continue
            pending.append(callee)
    return found


def family_text(family: dict[str, str]) -> str:
    return "\n".join(family[name] for name in sorted(family))


def literals(text: str) -> list[str]:
    return re.findall(r'"(?:\\.|[^"\\])*"', text, re.S)


NFT_FUNCTIONS = reachable_family("nc_nft_guarded_apply")
TC_FUNCTIONS = reachable_family("nc_tc_guarded_apply")
NFT = family_text(NFT_FUNCTIONS)
TC = family_text(TC_FUNCTIONS)
CALLER = function("jmx_network_control_apply")
STATUS_PERSIST = function("nc_netctl_persist_apply_status")
NFT_GENERATOR = "\n".join(
    function(name)
    for name in (
        "nc_nft_gen_mac_rules",
        "nc_nft_app_emit_ports",
        "nc_nft_for_each_app_rule",
        "nc_nft_gen_connection_limit_rules",
        "nc_nft_write_ruleset",
    )
)


def assert_no_shell_boundary(scope: str, label: str) -> None:
    for token in ("nc_run_quiet(", "system(", "popen(", "pclose("):
        assert token not in scope, f"{label} still uses forbidden command boundary: {token}"
    assert not re.search(r'\bexec(?:l|v|ve|vp)?\s*\(\s*"/bin/(?:ba)?sh"', scope), \
        f"{label} must not exec a shell command"
    assert '"-c"' not in scope, f"{label} must not execute shell -c"
    for literal in literals(scope):
        assert not re.search(r"(?:&&|\|\||[<>])", literal), \
            f"{label} embeds a shell operator in {literal}"


def assert_bounded_process_primitive(scope: str, label: str) -> None:
    shared = "jmx_exec_capture(" in scope or "jmx_exec_wait(" in scope
    if shared:
        for token in (
            "clock_gettime(CLOCK_MONOTONIC",
            "setpgid(0, 0)",
            "setpgid(pid, pid)",
            "kill(-pid, SIGTERM)",
            "kill(-pid, SIGKILL)",
            "waitpid(pid, &status",
            "clean_env",
            "jmx_exec_close_extra_fds()",
            "WIFEXITED(status)",
            "WIFSIGNALED(status)",
        ):
            assert token in EXEC_SOURCE, \
                f"shared executor used by {label} lacks required safeguard: {token}"
    else:
        for token in (
            "clock_gettime(CLOCK_MONOTONIC",
            "setpgid(",
            "SIGTERM",
            "SIGKILL",
            "waitpid(",
            "execve(",
            "WIFEXITED",
            "WIFSIGNALED",
        ):
            assert token in scope, \
                f"{label} lacks bounded process-tree execution safeguard: {token}"
        assert "clean_env" in scope or "envp" in scope, \
            f"{label} must use a small explicit environment"
        assert "_SC_OPEN_MAX" in scope or "close_range(" in scope, \
            f"{label} must close inherited descriptors"


def assert_exec_result_fails_closed(scope: str, label: str) -> None:
    for state in ("timed_out", "truncated", "term_signal", "exit_code"):
        assert state in scope, \
            f"{label} does not inspect executor result state: {state}"
    assert re.search(r"exit_code\s*!=\s*0|exit_code\s*==\s*0", scope), \
        f"{label} does not reject a non-zero exit status"
    assert re.search(r"return\s+-[1-9][0-9]*", scope), \
        f"{label} has no fail-closed error return"


def test_guarded_apply_families_exist() -> None:
    assert "nc_nft_guarded_apply" in NFT_FUNCTIONS
    assert "nc_tc_guarded_apply" in TC_FUNCTIONS


def test_no_legacy_shell_execution_boundary() -> None:
    assert_no_shell_boundary(NFT, "nc_nft_guarded_apply")
    assert_no_shell_boundary(TC, "nc_tc_guarded_apply")


def test_nft_uses_absolute_fixed_argv_with_capture_and_deadline() -> None:
    assert '"/usr/sbin/nft"' in NFT or '"/sbin/nft"' in NFT, \
        "nft must be invoked through a trusted absolute path"
    assert re.search(
        r"(?:char|const\s+char)\s*\*\s*(?:const\s+)?[A-Za-z0-9_]*argv\s*\[",
        NFT,
    ), "nft operations need explicit argv vectors"
    assert not re.search(r'\{\s*"nft"\s*,', NFT), \
        "nft argv[0] must not depend on PATH lookup"
    assert "jmx_exec_capture(" in NFT or (
        "poll(" in NFT and "clock_gettime(CLOCK_MONOTONIC" in NFT
    ), "nft list/check/readback output must use a bounded capture executor"
    assert re.search(r"(?:TIMEOUT|DEADLINE)[A-Za-z0-9_]*", NFT), \
        "nft execution needs an explicit finite deadline"
    assert re.search(r"(?:CAPTURE|OUTPUT|STDERR)[A-Za-z0-9_]*(?:MAX|LIMIT)", NFT), \
        "nft capture needs an explicit byte budget"
    assert_bounded_process_primitive(NFT, "nc_nft_guarded_apply")
    assert_exec_result_fails_closed(NFT, "nc_nft_guarded_apply")


def test_nft_check_backup_delete_apply_readback_and_rollback_are_verified() -> None:
    assert re.search(r'"-c"\s*,\s*"-f"|"--check"\s*,\s*"--file"', NFT), \
        "nft ruleset must be syntax-checked with fixed argv -c -f before mutation"
    for token in ('"list"', '"table"', '"delete"', '"-f"'):
        assert token in NFT, f"nft transaction omits operation token {token}"
    for stage in ("check", "backup", "delete", "apply", "readback", "rollback"):
        assert stage in NFT.lower(), \
            f"nft transaction does not expose or handle its {stage} stage"
    assert NFT.lower().count("rollback") >= 2, \
        "nft failures must enter an explicit rollback path and report its result"
    assert re.search(r"rollback[^\n;]*(?:!=\s*0|==\s*0)|(?:!=\s*0|==\s*0)[^\n;]*rollback", NFT, re.I), \
        "nft rollback exit status must be checked, not merely attempted"
    assert re.search(r"readback|health", NFT, re.I) and re.search(
        r"readback|strstr\s*\(|strcmp\s*\(|output", NFT, re.I
    ), "nft success requires parsed runtime readback"


def test_nft_backup_is_in_memory_or_unpredictable_root_only_storage() -> None:
    assert "/tmp/dw-netctl-nft-" not in NFT, \
        "predictable PID-derived /tmp nft backups are forbidden"
    memory_backup = (
        re.search(r"backup[^\n;]*(?:\.output|output_len|capture)", NFT, re.I)
        and re.search(r"rollback[^\n;]*(?:stdin|input|buffer|memfd|\.output)", NFT, re.I)
    )
    secure_storage = (
        "O_EXCL" in NFT
        and "O_NOFOLLOW" in NFT
        and re.search(r"0600|S_IRUSR\s*\|\s*S_IWUSR", NFT)
        and ("mkstemp(" in NFT or "getrandom(" in NFT or "O_TMPFILE" in NFT)
    )
    assert memory_backup or secure_storage, \
        "nft rollback state must stay in bounded memory or a root-only unpredictable file"


def test_nft_ruleset_is_validated_and_published_atomically() -> None:
    for token in ("O_EXCL", "O_NOFOLLOW", "O_CLOEXEC", "0600"):
        assert token in NFT_GENERATOR, \
            f"nft generated artifact lacks protected temporary-file flag {token}"
    for token in ("fflush(fp)", "fsync(fileno(fp))", "renameat(", "fsync(dirfd)"):
        assert token in NFT_GENERATOR, \
            f"nft generated artifact is not durably/atomically published: {token}"
    assert 'fopen(path, "w")' not in NFT_GENERATOR, \
        "nft ruleset must not truncate its live artifact before generation succeeds"
    for token in (
        "nc_netctl_mac_ok(",
        "nc_netctl_comment_ok(",
        "json_tokener_parse(app_ids)",
        "SQLITE_DONE",
        "ferror(fp)",
    ):
        assert token in NFT_GENERATOR, \
            f"nft generator does not fail closed for persisted input/DB/write errors: {token}"
    assert "app_ids=%s" not in NFT_GENERATOR, \
        "raw persisted JSON must never be emitted into nft comments"


def test_tc_never_executes_a_persistent_shell_file() -> None:
    scope = TC + "\n" + CALLER
    assert "network_control_tc.sh" not in scope, \
        "tc apply must not execute or hand off a persistent generated shell file"
    assert not re.search(r'"/(?:bin|usr/bin)/(?:ba)?sh"\s*,[^}]*\.sh', scope, re.S), \
        "tc apply must not invoke a persistent script through sh"
    anonymous_fd = (
        ("memfd_create(" in TC or "O_TMPFILE" in TC)
        and ("fexecve(" in TC or "execveat(" in TC or "/proc/self/fd/" in TC)
        and ("F_ADD_SEALS" in TC or "F_SEAL_WRITE" in TC or "fchmod(" in TC)
    )
    structured_argv = (
        ('"/sbin/tc"' in TC or '"/usr/sbin/tc"' in TC)
        and re.search(
            r"(?:char|const\s+char)\s*\*\s*(?:const\s+)?[A-Za-z0-9_]*argv\s*\[",
            TC,
        )
        and ("jmx_exec_capture(" in TC or "jmx_exec_wait(" in TC or "execve(" in TC)
    )
    assert anonymous_fd or structured_argv, \
        "tc must execute from a protected anonymous fd or structured fixed argv"


def test_tc_is_bounded_process_tree_safe_and_checks_full_status() -> None:
    assert re.search(r"(?:TIMEOUT|DEADLINE)[A-Za-z0-9_]*", TC), \
        "tc apply needs an explicit finite deadline"
    assert_bounded_process_primitive(TC, "nc_tc_guarded_apply")
    assert_exec_result_fails_closed(TC, "nc_tc_guarded_apply")


def test_tc_qdisc_readback_is_captured_parsed_and_required() -> None:
    for token in ('"qdisc"', '"show"', '"dev"'):
        assert token in TC, f"tc readback argv omits {token}"
    assert "jmx_exec_capture(" in TC or "poll(" in TC, \
        "tc qdisc readback must capture bounded output"
    assert re.search(r"(?:\.output|output_len)", TC), \
        "tc qdisc success must inspect captured runtime output"
    assert re.search(r"strstr\s*\(|strcmp\s*\(|qdisc[^\n;]*parse|readback[^\n;]*verify", TC, re.I), \
        "tc qdisc readback must be parsed, not accepted from exit status alone"
    assert re.search(r"readback|health", TC, re.I)
    assert re.search(r"(?:readback|health)[^\n;]*(?:return\s+-|failed)|(?:return\s+-|failed)[^\n;]*(?:readback|health)", TC, re.I), \
        "missing or mismatched qdisc readback must fail closed"


def test_tc_filter_readback_verifies_full_rule_and_clsact_ownership() -> None:
    for token in (
        '"protocol"',
        '"kind"',
        '"keys"',
        '"ip_proto"',
        '"src_port"',
        '"dst_port"',
        '"actions"',
        '"police"',
        '"control_action"',
        '" rate "',
        '"Kbit"',
    ):
        assert token in TC, f"tc readback omits exact rule field {token}"
    assert "json_tokener_parse(result.output)" in TC, \
        "tc filter readback must parse structured JSON matching keys"
    assert "rate != (unsigned long)rule->rate_kbit" in TC, \
        "tc filter readback must reject a mismatched police rate"
    for unit in ('"Kbit"', '"Mbit"', '"Gbit"', '"bit"'):
        assert unit in TC, f"tc rate readback does not normalize {unit}"
    assert "ULONG_MAX / multiplier" in TC, \
        "tc rate unit conversion must reject integer overflow"
    for token in ("clsact_owned", "nc_tc_remove_owned_clsact(", '"qdisc"', '"delete"'):
        assert token in TC or token in SOURCE, \
            f"tc clsact ownership/cleanup contract is missing {token}"
    assert re.search(r"if\s*\(\s*!owned\s*\)\s*return\s+0", TC), \
        "tc must never delete a clsact qdisc it did not create"


def test_timeout_truncation_signal_nonzero_and_readback_never_report_success() -> None:
    for scope, label in ((NFT, "nft"), (TC, "tc")):
        assert_exec_result_fails_closed(scope, label)
        success_returns = [
            match.start() for match in re.finditer(r"return\s+0\s*;", scope)
        ]
        assert success_returns, f"{label} guarded apply has no explicit success return"
        last_failure_check = max(
            scope.rfind("timed_out"),
            scope.rfind("truncated"),
            scope.rfind("term_signal"),
            scope.rfind("exit_code"),
            scope.lower().rfind("readback"),
            scope.lower().rfind("health"),
        )
        assert max(success_returns) > last_failure_check, \
            f"{label} can return success before all executor/readback failures are checked"


def test_apply_response_only_advertises_real_runtime_artifacts() -> None:
    assert "network_control.json" not in CALLER, \
        "apply response must not advertise a JSON export that is never generated"
    assert "NC_NETCTL_NFT_RULESET" in CALLER, \
        "apply response must retain the real generated nft artifact path"


def test_status_persistence_is_atomic_and_runtime_is_compensated_on_failure() -> None:
    for token in (
        'nc_exec("BEGIN IMMEDIATE")',
        'nc_exec("COMMIT")',
        'nc_exec("ROLLBACK")',
        "network_control_status",
        "network_control_global",
        "sqlite3_changes(g_netconfig_db) != 1",
    ):
        assert token in STATUS_PERSIST, \
            f"network-control status persistence is not a checked transaction: {token}"
    for token in (
        "nc_nft_transaction_restore(&nft_transaction)",
        "nc_tc_restore_previous(&tc_previous)",
        "nft_compensation_after_status_failure_failed",
        "tc_compensation_after_status_failure_failed",
        "status_persisted",
    ):
        assert token in CALLER, \
            f"status failure does not compensate or report runtime state: {token}"
    assert re.search(
        r"if\s*\(\s*!nft_transaction\.applied\s*\|\|\s*runtime_ok\s*\)\s*"
        r"nc_nft_transaction_finish",
        CALLER,
    ), "failed nft compensation must retain its root-only recovery snapshot"


if __name__ == "__main__":
    test_guarded_apply_families_exist()
    test_no_legacy_shell_execution_boundary()
    test_nft_uses_absolute_fixed_argv_with_capture_and_deadline()
    test_nft_check_backup_delete_apply_readback_and_rollback_are_verified()
    test_nft_backup_is_in_memory_or_unpredictable_root_only_storage()
    test_nft_ruleset_is_validated_and_published_atomically()
    test_tc_never_executes_a_persistent_shell_file()
    test_tc_is_bounded_process_tree_safe_and_checks_full_status()
    test_tc_qdisc_readback_is_captured_parsed_and_required()
    test_tc_filter_readback_verifies_full_rule_and_clsact_ownership()
    test_timeout_truncation_signal_nonzero_and_readback_never_report_success()
    test_apply_response_only_advertises_real_runtime_artifacts()
    test_status_persistence_is_atomic_and_runtime_is_compensated_on_failure()
    print("ok: U-15 network-control nft/tc apply is bounded, verified, and reversible")
