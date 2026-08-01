#!/usr/bin/env python3
"""U-15 setup command paths must not pass setup data through a root shell."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    match = re.search(rf"static\s+[^\n]+\s+{name}\([^)]*\)\s*\{{", SOURCE)
    assert match, f"missing {name}"
    start = match.end()
    depth = 1
    pos = start
    while pos < len(SOURCE) and depth:
        if SOURCE[pos] == "{":
            depth += 1
        elif SOURCE[pos] == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"unterminated {name}"
    return SOURCE[start : pos - 1]


def assert_complete_status_check(body: str) -> None:
    for token in (
        "jmx_exec_capture(",
        "result.timed_out",
        "result.term_signal != 0",
        "result.truncated",
        "result.exit_code != 0",
        "jmx_exec_result_free(&result)",
    ):
        assert token in body, f"missing exec-result check: {token}"


def test_setup_has_no_popen_data_channel() -> None:
    for forbidden in ("popen(", "pclose(", "nc_setup_cmd_first_line"):
        assert forbidden not in SOURCE


def test_ssh_port_uses_fixed_uci_argv() -> None:
    body = function_body("nc_setup_ssh_port")
    assert 'NC_SETUP_UCI_PATH           "/sbin/uci"' in SOURCE
    assert 'NC_SETUP_UCI_PATH, "-q", "get", "dropbear.@dropbear[0].Port", NULL' in body
    assert_complete_status_check(body)
    for forbidden in ("2>/dev/null", "/bin/sh", " -c", "system("):
        assert forbidden not in body


def test_pppoe_discovery_uses_fixed_bounded_argv() -> None:
    body = function_body("nc_setup_probe_pppoe")
    assert 'NC_SETUP_PPPOE_DISCOVERY_PATH "/usr/sbin/pppoe-discovery"' in SOURCE
    assert 'NC_SETUP_PPPOE_DISCOVERY_PATH, "-I", (char *)ifname, "-t", "2", NULL' in body
    assert "NC_SETUP_COMMAND_OUTPUT_MAX" in body
    assert "NC_SETUP_COMMAND_TIMEOUT_MS" in body
    assert "nc_iface_name_ok(ifname)" in body
    assert_complete_status_check(body)
    for forbidden in ("nc_cmd_exists(", "2>/dev/null", "/bin/sh", " -c", "system("):
        assert forbidden not in body


if __name__ == "__main__":
    test_setup_has_no_popen_data_channel()
    test_ssh_port_uses_fixed_uci_argv()
    test_pppoe_discovery_uses_fixed_bounded_argv()
    print("ok: U-15 setup command data paths use bounded fixed argv exec")
