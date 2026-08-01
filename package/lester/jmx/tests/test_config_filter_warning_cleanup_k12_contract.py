#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CONFIG = (ROOT / "src" / "jmx_config.c").read_text()
CONFIG_HEADER = (ROOT / "src" / "jmx_config.h").read_text()
MAC_FILTER = (ROOT / "src" / "jmx_mac_filter.c").read_text()
MAC_FILTER_HEADER = (ROOT / "src" / "jmx_mac_filter.h").read_text()
APP_FILTER = (ROOT / "src" / "jmx_app_filter.c").read_text()
APP_FILTER_HEADER = (ROOT / "src" / "jmx_app_filter.h").read_text()


def require(pattern: str, text: str, message: str) -> None:
    if not re.search(pattern, text, re.MULTILINE):
        raise AssertionError(message)


def reject(pattern: str, text: str, message: str) -> None:
    if re.search(pattern, text, re.MULTILINE):
        raise AssertionError(message)


def external_definitions(text: str) -> set[str]:
    return set(
        re.findall(
            r"^(?!static\b|extern\b|if\b|for\b|while\b|switch\b)"
            r"(?:[A-Za-z_]\w*[\s*]+)+([A-Za-z_]\w*)\s*"
            r"\([^;{}]*?\)\s*\{",
            text,
            re.MULTILINE,
        )
    )


def function_body(text: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^)]*\)\s*\{{", text)
    if not match:
        raise AssertionError(f"missing function: {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index]
    raise AssertionError(f"unterminated function: {name}")


expected_external = {
    "jmx_config": {"jmx_register_dev", "jmx_unregister_dev"},
    "jmx_mac_filter": {
        "jmx_mac_filter_init",
        "jmx_mac_filter_exit",
        "jmx_match_mac_filter_rule",
        "jmx_match_mac_filter_whitelist",
        "jmx_api_add_mac_filter_rule",
        "jmx_api_del_mac_filter_rule",
        "jmx_api_mod_mac_filter_rule",
        "jmx_api_dump_mac_filter_rule",
        "jmx_api_flush_mac_filter_rule",
        "jmx_api_add_mac_filter_whitelist",
        "jmx_api_del_mac_filter_whitelist",
        "jmx_api_flush_mac_filter_whitelist",
    },
    "jmx_app_filter": {
        "jmx_app_filter_init",
        "jmx_app_filter_exit",
        "jmx_match_app_filter_rule_record",
        "jmx_match_app_filter_whitelist",
        "jmx_api_add_app_filter_rule",
        "jmx_api_del_app_filter_rule",
        "jmx_api_mod_app_filter_rule",
        "jmx_api_dump_app_filter_rule",
        "jmx_api_flush_app_filter_rule",
        "jmx_api_add_app_filter_whitelist",
        "jmx_api_flush_app_filter_whitelist",
    },
}

for source, header, label in (
    (CONFIG, CONFIG_HEADER, "jmx_config"),
    (MAC_FILTER, MAC_FILTER_HEADER, "jmx_mac_filter"),
    (APP_FILTER, APP_FILTER_HEADER, "jmx_app_filter"),
):
    actual = external_definitions(source)
    if actual != expected_external[label]:
        raise AssertionError(
            f"{label} external API changed without an explicit header contract: "
            f"{sorted(actual ^ expected_external[label])}"
        )
    for symbol in actual:
        require(
            rf"\b{symbol}\s*\([^;]*;",
            header,
            f"{label} external definition {symbol} must be declared in its header",
        )


for symbol in (
    "jmx_config_handle",
    "jmx_find_mac_filter_rule",
    "jmx_add_mac_filter_rule",
    "jmx_del_mac_filter_rule",
    "jmx_del_mac_from_rule",
    "jmx_update_appfilter_jiffies",
    "jmx_add_app_filter_rule",
    "jmx_del_app_filter_rule",
    "jmx_del_app_id_from_rule",
):
    source = CONFIG if symbol == "jmx_config_handle" else (
        MAC_FILTER if "mac" in symbol else APP_FILTER
    )
    require(
        rf"^static\s+[^\n]*\b{symbol}\s*\(",
        source,
        f"TU-local helper {symbol} must remain static",
    )

for dead_symbol in ("jmx_add_mac_to_rule", "jmx_add_app_id_to_rule"):
    reject(
        rf"\b{dead_symbol}\s*\(",
        MAC_FILTER + MAC_FILTER_HEADER + APP_FILTER + APP_FILTER_HEADER,
        f"unused helper {dead_symbol} must not return",
    )

reject(r"\bint\s+i\s*;", function_body(MAC_FILTER, "jmx_api_add_mac_filter_rule"),
       "unused add-rule loop index must not return")
reject(r"\bcJSON\s*\*mac_array\s*;",
       function_body(MAC_FILTER, "jmx_api_add_mac_filter_rule"),
       "unused add-rule mac_array local must not return")
reject(r"\bint\s+mac_type\b", MAC_FILTER,
       "unused mac_type local must not return")
reject(
    r"#\s*pragma\s+GCC\s+diagnostic|__diag_ignore|Wno-(?:missing-prototypes|unused)",
    CONFIG + CONFIG_HEADER + MAC_FILTER + MAC_FILTER_HEADER + APP_FILTER + APP_FILTER_HEADER,
    "warning cleanup must not add warning suppression",
)

print("ok: K-12 config/mac-filter/app-filter warning cleanup contract passed")
