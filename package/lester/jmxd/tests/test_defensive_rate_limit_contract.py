#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def body(start: str, end: str) -> str:
    begin = CORE.index(start)
    finish = CORE.index(end, begin)
    return CORE[begin:finish]


def test_rate_limit_script_is_unlinked_and_never_executed_by_path() -> None:
    opened = body("static FILE *nc_rate_limit_open_script", "static int nc_rate_limit_run_script")
    run = body("static int nc_rate_limit_run_script", "static int nc_rate_limit_mac_ok")
    apply = body("static int nc_rate_limit_apply_all", "int nc_client_rate_limit_set_ex")

    for token in ("O_EXCL", "O_NOFOLLOW", "O_CLOEXEC", "unlinkat"):
        assert token in opened
    assert '"/tmp/dw-client-rate-limits.sh"' not in CORE
    assert "nc_run_quiet" not in apply
    assert 'execl("/bin/sh", "sh", "-s"' in run
    assert "dup2(fd, STDIN_FILENO)" in run
    assert "NC_RATE_LIMIT_APPLY_TIMEOUT_MS" in run


def test_rate_limit_config_rejects_multiline_remark_and_negative_rates() -> None:
    setter = body("int nc_client_rate_limit_set_ex", "int nc_client_rate_limit_set(")
    assert "upload_kbps < 0" in setter
    assert "download_kbps < 0" in setter
    assert "strchr(remark, '\\r')" in setter
    assert "strchr(remark, '\\n')" in setter


def test_wan_runtime_uses_single_bounded_oom_safe_append() -> None:
    helper = body("static int nc_buffer_append", "static char *nc_network_status_read")
    first = body("static struct json_object *nc_network_status_json", "static void nc_wan_merge_ipv6_runtime")
    second = body("static void nc_wan_merge_runtime", "static char *nc_csv_escape")

    assert "grown = realloc(*buf, next)" in helper
    assert "if (!grown)" in helper
    reader = body("static char *nc_network_status_read", "static struct json_object *nc_network_status_json")
    assert "NC_NETWORK_STATUS_MAX" in reader
    assert "nc_network_status_read(fp)" in first
    assert "nc_network_status_read(fp)" in second
    assert "buf = realloc(buf" not in first
    assert "buf = realloc(buf" not in second
