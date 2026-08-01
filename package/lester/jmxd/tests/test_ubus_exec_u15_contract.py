#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_ubus.c").read_text()


def function_body(name: str) -> str:
    match = re.search(
        rf"(?m)^(?!\s*(?:if|while|for|switch|return)\b)[^\n;{{}}]*\b{name}\s*\([^;]*?\)\s*\{{",
        SOURCE,
        re.S,
    )
    assert match, f"missing function {name}"
    start = match.end()
    depth = 1
    offset = start
    while depth and offset < len(SOURCE):
        if SOURCE[offset] == "{":
            depth += 1
        elif SOURCE[offset] == "}":
            depth -= 1
        offset += 1
    assert depth == 0, f"unterminated function {name}"
    return SOURCE[start : offset - 1]


def test_shell_inventory_is_empty() -> None:
    for forbidden in (
        "exec_with_result_line",
        "system(",
        "popen(",
        "pclose(",
        '"/bin/sh"',
        '"/bin/ash"',
        "free |",
        "df -k",
        "grep Mem",
        "awk '{",
    ):
        assert forbidden not in SOURCE, f"shell execution remains: {forbidden}"


def test_exec_result_is_fail_closed() -> None:
    helper = function_body("jmx_ubus_exec_succeeded")
    for check in (
        "!result->timed_out",
        "!result->truncated",
        "result->term_signal == 0",
        "result->exit_code == 0",
    ):
        assert check in helper

    capture = function_body("jmx_ubus_exec_capture")
    assert "JMX_UBUS_EXEC_TIMEOUT_MS" in capture
    assert "jmx_exec_capture(path, argv, output_limit" in capture
    assert "jmx_ubus_exec_succeeded(&result)" in capture
    assert "result.output_len < output_len" in capture
    assert "jmx_exec_result_free(&result)" in capture


def test_only_fixed_absolute_programs_are_spawned() -> None:
    reload_body = function_body("reload_oaf_rule")
    assert '{ "/usr/bin/oaf_rule", "reload", NULL }' in reload_body
    assert "jmx_exec_wait(argv[0], argv, JMX_UBUS_EXEC_TIMEOUT_MS" in reload_body
    assert "jmx_ubus_exec_succeeded(&result)" in reload_body
    assert "jmx_exec_result_free(&result)" in reload_body

    temperature = function_body("get_tempinfo_values")
    assert '{ "/sbin/tempinfo", NULL }' in temperature
    assert "JMX_UBUS_TEMPINFO_MAX_OUTPUT" in temperature
    assert "jmx_ubus_exec_capture(argv[0], argv" in temperature

    board = function_body("get_cpu_model_name_from_ubus")
    assert '{ "/bin/ubus", "call", "system", "board", NULL }' in board
    assert "JMX_UBUS_BOARD_MAX_OUTPUT" in board
    assert "jmx_ubus_exec_capture(argv[0], argv" in board


def test_proc_sysfs_and_dashboard_metrics_are_structured() -> None:
    oaf = function_body("jmx_api_get_oaf_status")
    assert 'read_unsigned_file("/proc/sys/oaf/enable"' in oaf
    assert 'read_file_buf("/proc/sys/oaf/version"' in oaf
    assert "uname(&uts)" in oaf

    model = function_body("get_model")
    assert 'read_file_buf("/proc/device-tree/model"' in model
    assert 'read_file_buf("/tmp/sysinfo/board_name"' in model

    memory = function_body("read_memory_kb")
    assert 'fopen("/proc/meminfo", "r")' in memory
    for field in (
        '"MemTotal:"',
        '"MemAvailable:"',
        '"MemFree:"',
        '"Buffers:"',
        '"Cached:"',
        '"SReclaimable:"',
        '"Shmem:"',
    ):
        assert field in memory

    dashboard = function_body("get_dashboard_system_status")
    assert "read_kernel_release(buf, sizeof(buf))" in dashboard
    assert "read_memory_kb(&total_mem_kb, &used_mem_kb)" in dashboard
    assert 'read_unsigned_file("/proc/sys/net/netfilter/nf_conntrack_count"' in dashboard
    for call in (
        'add_storage_stat(storage_obj, "tmp", "/tmp")',
        'add_storage_stat(storage_obj, "root", "/")',
        'add_storage_stat(storage_obj, "boot", "/boot")',
    ):
        assert call in dashboard

    storage = function_body("add_storage_stat")
    assert "statvfs(path, &vfs)" in storage


if __name__ == "__main__":
    test_shell_inventory_is_empty()
    test_exec_result_is_fail_closed()
    test_only_fixed_absolute_programs_are_spawned()
    test_proc_sysfs_and_dashboard_metrics_are_structured()
    print("ok: U-15 jmx_ubus shell calls use bounded fixed argv or structured reads")
