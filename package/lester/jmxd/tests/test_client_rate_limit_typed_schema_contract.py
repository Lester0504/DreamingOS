#!/usr/bin/env python3
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/jmx_netconfig_db.h").read_text(encoding="utf-8")


def body(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_ubus_set_and_delete_publish_typed_policies() -> None:
    set_policy = body(
        API,
        "static const struct blobmsg_policy dw_client_rate_limit_set_policy[]",
        "static const struct blobmsg_policy dw_client_rate_limit_delete_policy[]",
    )
    delete_policy = body(
        API,
        "static const struct blobmsg_policy dw_client_rate_limit_delete_policy[]",
        "static int dw_handle_client_rate_limit_set",
    )
    for token in (
        '{ .name = "data", .type = BLOBMSG_TYPE_TABLE }',
        '{ .name = "mac", .type = BLOBMSG_TYPE_STRING }',
        '{ .name = "ip", .type = BLOBMSG_TYPE_STRING }',
        '{ .name = "upload_kbps", .type = BLOBMSG_TYPE_INT32 }',
        '{ .name = "download_kbps", .type = BLOBMSG_TYPE_INT32 }',
        '{ .name = "remark", .type = BLOBMSG_TYPE_STRING }',
    ):
        assert token in set_policy
    assert '{ .name = "data", .type = BLOBMSG_TYPE_TABLE }' in delete_policy
    assert '{ .name = "mac", .type = BLOBMSG_TYPE_STRING }' in delete_policy
    assert 'UBUS_METHOD("client_rate_limit_set", dw_handle_client_rate_limit_set, dw_client_rate_limit_set_policy)' in API
    assert 'UBUS_METHOD("client_rate_limit_delete", dw_handle_client_rate_limit_delete, dw_client_rate_limit_delete_policy)' in API


def test_handlers_use_strict_core_sinks_without_coercing_getters() -> None:
    setter = body(API, "static int dw_handle_client_rate_limit_set", "static int dw_handle_client_rate_limit_delete")
    deleter = body(API, "static int dw_handle_client_rate_limit_delete", "static int dw_handle_flow_control_set")
    assert "nc_client_rate_limit_set_json(payload, &reason, &field)" in setter
    assert "nc_client_rate_limit_delete_json(payload, &reason, &field)" in deleter
    for handler in (setter, deleter):
        assert "dw_json_get_string" not in handler
        assert "dw_json_get_int" not in handler
        assert 'json_object_object_add(data, "reason"' in handler
        assert 'json_object_object_add(data, "field"' in handler


def test_core_sink_checks_types_lengths_and_ranges_before_mutation() -> None:
    helpers = body(CORE, "static int nc_rate_limit_ip_ok", "static void nc_rate_limit_emit_filter")
    setter = body(CORE, "int nc_client_rate_limit_set_json", "int nc_client_rate_limit_delete_json")
    deleter = body(CORE, "int nc_client_rate_limit_delete_json", "/* ═══ Client Control Rule Schedule Runtime")
    for token in (
        "json_object_is_type(cfg, json_type_object)",
        "json_object_is_type(item, json_type_string)",
        "json_object_is_type(item, json_type_int)",
        "json_object_get_string_len(item)",
        "strlen(text) != text_len",
        '"missing_required_field"',
        '"invalid_field_type"',
        '"field_too_long"',
        '"field_out_of_range"',
        "NC_RATE_LIMIT_KBPS_MAX",
    ):
        assert token in helpers
    assert setter.index("nc_rate_limit_json_object") < setter.index("nc_client_rate_limit_set(mac")
    assert setter.index("nc_rate_limit_json_kbps") < setter.index("nc_client_rate_limit_set(mac")
    assert deleter.index("nc_rate_limit_json_object") < deleter.index("nc_client_rate_limit_delete(mac)")
    assert "nc_client_rate_limit_set_json" in HEADER
    assert "nc_client_rate_limit_delete_json" in HEADER


def test_internal_sink_has_matching_defensive_bounds() -> None:
    setter = body(CORE, "int nc_client_rate_limit_set_ex", "int nc_client_rate_limit_set(")
    for token in (
        "nc_rate_limit_ip_ok(ip)",
        "NC_RATE_LIMIT_IP_MAX",
        "NC_RATE_LIMIT_PROTOCOL_MAX",
        "NC_RATE_LIMIT_REMARK_MAX",
        "upload_kbps > NC_RATE_LIMIT_KBPS_MAX",
        "download_kbps > NC_RATE_LIMIT_KBPS_MAX",
    ):
        assert token in setter


def test_runtime_failure_has_stable_reason_and_field() -> None:
    setter = body(CORE, "int nc_client_rate_limit_set_json", "int nc_client_rate_limit_delete_json")
    deleter = body(CORE, "int nc_client_rate_limit_delete_json", "/* ═══ Client Control Rule Schedule Runtime")
    for sink in (setter, deleter):
        assert '*reason = "runtime_apply_failed"' in sink
        assert '*field = "runtime"' in sink


def test_json_type_rejection_precedes_mutation_in_host_fixture() -> None:
    cc = shutil.which("cc") or shutil.which("clang")
    pkg_config = shutil.which("pkg-config")
    if not cc or not pkg_config:
        return
    flags = subprocess.run(
        [pkg_config, "--cflags", "--libs", "json-c"],
        check=False,
        capture_output=True,
        text=True,
    )
    if flags.returncode != 0:
        return

    helpers = body(CORE, "static int nc_rate_limit_json_string", "static void nc_rate_limit_emit_filter")
    setters = body(CORE, "int nc_client_rate_limit_set_json", "/* ═══ Client Control Rule Schedule Runtime")
    source = f'''\
#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#define NC_RATE_LIMIT_IP_MAX 63
#define NC_RATE_LIMIT_REMARK_MAX 127
#define NC_RATE_LIMIT_KBPS_MAX 10000000
static int mutations;
static int nc_rate_limit_mac_ok(const char *mac) {{
    int i;
    if (!mac || strlen(mac) != 17) return 0;
    for (i = 0; i < 17; i++) {{
        if ((i + 1) % 3 == 0) {{ if (mac[i] != ':') return 0; }}
        else if (!isxdigit((unsigned char)mac[i])) return 0;
    }}
    return 1;
}}
static int nc_rate_limit_ip_ok(const char *ip) {{
    struct in_addr v4; struct in6_addr v6;
    return !ip || !ip[0] || inet_pton(AF_INET, ip, &v4) == 1 || inet_pton(AF_INET6, ip, &v6) == 1;
}}
static int nc_client_rate_limit_set(const char *mac, const char *ip, int up, int down, const char *remark) {{
    (void)mac; (void)ip; (void)up; (void)down; (void)remark; mutations++; return 0;
}}
static int nc_client_rate_limit_delete(const char *mac) {{ (void)mac; mutations++; return 0; }}
{helpers}
{setters}
static int run(const char *json, int is_delete, int expected_rc, int expected_mutations,
               const char *expected_reason, const char *expected_field) {{
    struct json_object *cfg = json_tokener_parse(json);
    const char *reason = NULL, *field = NULL;
    int rc;
    mutations = 0;
    rc = is_delete ? nc_client_rate_limit_delete_json(cfg, &reason, &field)
                   : nc_client_rate_limit_set_json(cfg, &reason, &field);
    json_object_put(cfg);
    if (rc != expected_rc || mutations != expected_mutations ||
        strcmp(reason, expected_reason) || strcmp(field, expected_field)) {{
        fprintf(stderr, "rc=%d mutations=%d reason=%s field=%s\\n", rc, mutations, reason, field);
        return 1;
    }}
    return 0;
}}
int main(void) {{
    if (run("{{\\\"mac\\\":\\\"02:11:22:33:44:55\\\",\\\"upload_kbps\\\":\\\"1000\\\"}}", 0, -1, 0,
            "invalid_field_type", "upload_kbps")) return 1;
    if (run("{{\\\"mac\\\":\\\"02:11:22:33:44:55\\\",\\\"download_kbps\\\":10000001}}", 0, -1, 0,
            "field_out_of_range", "download_kbps")) return 1;
    if (run("{{\\\"mac\\\":\\\"02:11:22:33:44:55\\\",\\\"remark\\\":\\\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\\"}}",
            0, -1, 0, "field_too_long", "remark")) return 1;
    if (run("{{\\\"mac\\\":\\\"02:11:22:33:44:55\\\",\\\"remark\\\":\\\"ok" "\\\\" "u0000hidden\\\"}}",
            0, -1, 0, "invalid_field_value", "remark")) return 1;
    if (run("[]", 0, -1, 0, "invalid_field_type", "data")) return 1;
    if (run("{{\\\"mac\\\":17}}", 1, -1, 0, "invalid_field_type", "mac")) return 1;
    if (run("{{\\\"mac\\\":\\\"02:11:22:33:44:55\\\",\\\"ip\\\":\\\"192.0.2.10\\\",\\\"upload_kbps\\\":1000}}",
            0, 0, 1, "", "")) return 1;
    if (run("{{\\\"mac\\\":\\\"02:11:22:33:44:55\\\"}}", 1, 0, 1, "", "")) return 1;
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "rate_limit_schema_fixture.c"
        binary = Path(tmp) / "rate_limit_schema_fixture"
        src.write_text(source, encoding="utf-8")
        subprocess.run(
            [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(src), "-o", str(binary), *flags.stdout.split()],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
