#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "src" / "jmx_main.c").read_text()
HEADER = (ROOT / "src" / "jmx.h").read_text()
CLIENT_HEADER = (ROOT / "src" / "jmx_client.h").read_text()


def require(pattern: str, text: str, message: str) -> None:
    if not re.search(pattern, text, re.MULTILINE):
        raise AssertionError(message)


def reject(pattern: str, text: str, message: str) -> None:
    if re.search(pattern, text, re.MULTILINE):
        raise AssertionError(message)


for symbol in (
    "ipv6_to_str",
    "af_send_msg_to_user",
    "jmx_v2_update_active_app",
    "jmx_v2_update_active_app_ex",
    "jmx_v2_update_active_app6_ex",
):
    require(
        rf"^[^\n;]*\b{symbol}\s*\([^;]*;",
        HEADER,
        f"cross-TU symbol {symbol} must have a declaration in jmx.h",
    )

external_definitions = set(
    re.findall(
        r"^(?!static\b|extern\b|if\b|for\b|while\b|switch\b)"
        r"(?:[A-Za-z_]\w*\s+)+(?:\*\s*)?([A-Za-z_]\w*)\s*"
        r"\([^;{}]*?\)\s*\{",
        MAIN,
        re.MULTILINE,
    )
)
expected_external_definitions = {
    "ipv6_to_str",
    "af_send_msg_to_user",
    "af_update_client_app_info",
    "jmx_v2_update_active_app",
    "jmx_v2_update_active_app_ex",
    "jmx_v2_update_active_app6_ex",
}
if external_definitions != expected_external_definitions:
    raise AssertionError(
        "jmx_main external definitions changed without an explicit cross-TU contract: "
        f"{sorted(external_definitions ^ expected_external_definitions)}"
    )

for symbol in external_definitions:
    require(
        rf"\b{symbol}\s*\([^;]*;",
        HEADER + CLIENT_HEADER,
        f"external definition {symbol} must be declared in an existing header",
    )

for symbol in (
    "parse_flow_proto",
    "match_feature",
    "match_app_filter_rule",
    "match_mac_filter_rule",
    "dpi_main",
    "jmx_hook_bypass_handle",
    "jmx_hook_gateway_handle",
    "netlink_jmx_init",
    "af_update_active_app_list",
    "af_update_active_host_list",
):
    require(
        rf"^static\s+[^\n]*\b{symbol}\s*\(",
        MAIN,
        f"TU-local symbol {symbol} must remain static",
    )

for dead_symbol in (
    "jmx_del_timer_sync_compat",
    "load_feature_config",
    "load_feature_buf_from_file",
    "af_match_bcast_packet",
    "af_match_by_url",
    "af_match_one",
    "af_find_active_host",
):
    reject(
        rf"\b{dead_symbol}\s*\(",
        MAIN,
        f"unused helper {dead_symbol} must not return",
    )

reject(r"\bu_int8_t\s+drop\s*=\s*0\s*;", MAIN, "unused drop locals must not return")
reject(r"\breport_flag\b", MAIN, "write-only report_flag state must not return")
reject(
    r"#\s*pragma\s+GCC\s+diagnostic|__diag_ignore|Wno-(?:missing-prototypes|unused)",
    MAIN + HEADER,
    "warning cleanup must not add warning suppression",
)
reject(
    r"char\s+feature\s*\[\s*MAX_FEATURE_LINE_LEN\s*\]",
    MAIN,
    "feature netlink payload must not consume an 8 KiB kernel stack frame",
)
require(
    r"feature\s*=\s*kmemdup_nul\s*\(\s*data\s*,\s*len\s*,\s*GFP_KERNEL\s*\)",
    MAIN,
    "feature netlink payload must use a length-bounded heap copy",
)
require(
    r"struct\s+feature_parse_workspace\s*\{[\s\S]*?\}\s*\*workspace\s*;",
    MAIN,
    "feature parser scratch buffers must live in a heap workspace",
)
require(
    r"workspace\s*=\s*kzalloc\s*\(\s*sizeof\s*\(\s*\*workspace\s*\)\s*,\s*GFP_KERNEL\s*\)",
    MAIN,
    "feature parser workspace must be zero-initialized and bounded",
)

print("ok: K-12 jmx_main missing-prototype/unused warning cleanup contract passed")
