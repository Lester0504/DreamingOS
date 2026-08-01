#!/usr/bin/env python3
"""U-15 contract for the system startup-service command family.

This test is intentionally source-level: jmx_netconfig_db.c depends on the
OpenWrt UCI/ubus headers, while the security properties under test are the
command boundary, trusted init-script lookup, and honest runtime readback.
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


def service_family() -> str:
    """Include the public handler and every nc_sys_service_* private helper."""
    names = {
        match.group(1)
        for match in re.finditer(
            r"\b(nc_sys_service_[A-Za-z0-9_]+|nc_sys_services_json)\s*\(", SOURCE
        )
    }
    names.add("jmx_system_startup_service_action")
    return "\n".join(function(name) for name in sorted(names))


NAME_OK = function("nc_sys_service_name_ok")
TOKEN_OK = function("nc_sys_service_token_ok")
ACTION_OK = function("nc_sys_service_action_ok")
SERVICE_OPEN = function("nc_sys_service_open")
SERVICES_JSON = function("nc_sys_services_json")
ACTION = function("jmx_system_startup_service_action")
FAMILY = service_family()


def test_family_has_no_shell_interpreter_boundary() -> None:
    for token in (
        "system(",
        "popen(",
        "pclose(",
        '"/bin/sh"',
        '"-c"',
        "/bin/sh -c",
    ):
        assert token not in FAMILY, f"startup-service family still uses shell token: {token}"


def test_service_and_action_are_strict_allowlists() -> None:
    # Service names are one init.d basename, never a path or an option.
    for token in ("strlen(name)", "isalnum(*p)", "*p != '_'", "*p != '-'"):
        assert token in TOKEN_OK, f"service-name allowlist missing: {token}"
    assert re.search(r"len\s*>\s*[A-Za-z0-9_]+", TOKEN_OK), \
        "service names need an explicit length ceiling"
    for forbidden_character in ("*p == '/'", "*p == '.'", "*p == ' '", "*p == '@'"):
        assert forbidden_character not in TOKEN_OK, \
            f"service-name allowlist admits path/shell syntax: {forbidden_character}"
    assert "nc_sys_service_open(name, &handle)" in NAME_OK
    assert "nc_sys_service_token_ok(name)" in SERVICE_OPEN

    expected_actions = {"enable", "disable", "start", "stop", "restart", "reload", "status"}
    compared_actions = set(re.findall(r'strcmp\(action,\s*"([^"]+)"\)', ACTION_OK))
    assert compared_actions == expected_actions, \
        f"service action allowlist differs: {sorted(compared_actions)}"
    assert "nc_sys_service_action_ok(action)" in ACTION
    assert "unsupported_action" in ACTION


def test_init_scripts_are_opened_from_a_trusted_directory() -> None:
    required = (
        'open("/etc/init.d"',
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "openat(",
        "fstat(",
        "S_ISREG(",
        "st_uid",
        "S_IWGRP",
        "S_IWOTH",
        "S_IX",
    )
    for token in required:
        assert token in FAMILY, f"trusted init-script lookup missing: {token}"
    assert re.search(r"st_uid\s*!=\s*0|st_uid\s*==\s*0", FAMILY), \
        "init script ownership must be checked against root"


def test_actions_use_fixed_argv_and_fail_closed_exec() -> None:
    assert "jmx_exec_wait(" in FAMILY or "jmx_exec_capture(" in FAMILY, \
        "service actions must use the shared argv exec primitive"
    assert re.search(r"\bargv\s*\[", FAMILY), \
        "service execution needs an explicit argv vector"
    for state in ("timed_out", "term_signal", "exit_code"):
        assert state in FAMILY, f"service execution ignores process state: {state}"


def test_enabled_and_running_are_runtime_readbacks() -> None:
    for field in ('"enabled"', '"running"'):
        assert field in SERVICES_JSON, f"service inventory omits readback field: {field}"
    for readback_action in ('"running"', '"enabled"'):
        assert readback_action in FAMILY, \
            f"service inventory lacks {readback_action} runtime readback"
    assert "jmx_exec_" in FAMILY or '"/etc/rc.d"' in FAMILY, \
        "service state must come from native rc.d or bounded fixed-argv readback"
    assert "nc_sys_services_json(" in ACTION, \
        "action response must refresh service state instead of echoing requested intent"


def test_enumeration_is_bounded_and_stably_sorted() -> None:
    limit_names = set(re.findall(
        r"#define\s+(NC_SYS_[A-Z0-9_]*SERVICE[A-Z0-9_]*(?:MAX|LIMIT)[A-Z0-9_]*)\s+\(?\s*[1-9][0-9]*",
        SOURCE,
    ))
    enforced_limits = sorted(name for name in limit_names if name in SERVICES_JSON)
    assert enforced_limits, "service enumeration needs an enforced named positive count budget"
    assert "qsort(" in FAMILY, "service inventory must be sorted before JSON emission"
    assert "strcmp(" in FAMILY, "service sort comparator must use a stable lexical key"
    assert "readdir(" in FAMILY, "service inventory must enumerate init.d without a shell pipeline"


if __name__ == "__main__":
    test_family_has_no_shell_interpreter_boundary()
    test_service_and_action_are_strict_allowlists()
    test_init_scripts_are_opened_from_a_trusted_directory()
    test_actions_use_fixed_argv_and_fail_closed_exec()
    test_enabled_and_running_are_runtime_readbacks()
    test_enumeration_is_bounded_and_stably_sorted()
    print("ok: U-15 system startup services use trusted fixed-argv execution and readback")
