#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CLIENT = (ROOT / "src" / "jmx_client.c").read_text()
CLIENT_HEADER = (ROOT / "src" / "jmx_client.h").read_text()
CLIENT_FS = (ROOT / "src" / "jmx_client_fs.c").read_text()
CLIENT_FS_HEADER = (ROOT / "src" / "jmx_client_fs.h").read_text()
CONNTRACK = (ROOT / "src" / "jmx_conntrack.c").read_text()
CONNTRACK_HEADER = (ROOT / "src" / "jmx_conntrack.h").read_text()


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


for source, header, label in (
    (CLIENT, CLIENT_HEADER, "jmx_client"),
    (CLIENT_FS, CLIENT_FS_HEADER, "jmx_client_fs"),
    (CONNTRACK, CONNTRACK_HEADER, "jmx_conntrack"),
):
    for symbol in external_definitions(source):
        require(
            rf"\b{symbol}\s*\([^;]*;",
            header,
            f"{label} external definition {symbol} must be declared in its header",
        )

expected_external = {
    "jmx_client": {
        "af_client_put",
        "af_client_get_if_live",
        "af_client_list_reset_report_num",
        "find_and_add_af_client",
        "find_af_client_by_ip",
        "find_af_client_by_ipv6",
        "af_client_get_by_ip",
        "af_client_get_by_ipv6",
        "check_client_expire",
        "get_or_create_visit_info",
        "af_account_client_app_packet",
        "af_client_counter_generation",
        "af_client_init",
        "af_client_exit",
    },
    "jmx_client_fs": {
        "init_af_client_procfs",
        "finit_af_client_procfs",
        "create_client_proc_dir",
        "remove_client_proc_dir",
    },
    "jmx_conntrack": {
        "af_conn_find_and_add",
        "af_conn_record_match",
        "af_conn_clean_timeout",
        "af_conn_init",
        "af_conn_exit",
    },
}

for source, label in (
    (CLIENT, "jmx_client"),
    (CLIENT_FS, "jmx_client_fs"),
    (CONNTRACK, "jmx_conntrack"),
):
    actual = external_definitions(source)
    if actual != expected_external[label]:
        raise AssertionError(
            f"{label} external API changed without an explicit header contract: "
            f"{sorted(actual ^ expected_external[label])}"
        )

for symbol in (
    "get_mac_hash_code",
    "find_af_client",
    "nf_client_add",
    "check_expired_visit_info",
    "__af_visit_info_report",
    "af_update_client_status",
):
    require(
        rf"^static\s+[^\n]*\b{symbol}\s*\(",
        CLIENT,
        f"TU-local client helper {symbol} must remain static",
    )

for symbol in (
    "af_conn_cleanup",
    "af_conn_add",
    "af_conn_find",
    "af_conn_init_procfs",
    "af_conn_remove_procfs",
):
    require(
        rf"^static\s+[^\n]*\b{symbol}\s*\(",
        CONNTRACK,
        f"TU-local conntrack helper {symbol} must remain static",
    )

require(
    r"extern\s+struct\s+list_head\s+af_client_list_table\s*\[",
    CLIENT_HEADER,
    "the client table shared with procfs must be owned by jmx_client.h",
)
require(
    r'#include\s+"jmx_client_fs\.h"',
    CLIENT_FS,
    "jmx_client_fs.c must include its own public contract",
)

for dead_symbol in ("flush_expired_visit_info", "af_conn_update"):
    reject(
        rf"\b{dead_symbol}\s*\(",
        CLIENT + CLIENT_HEADER + CONNTRACK + CONNTRACK_HEADER,
        f"unused helper {dead_symbol} must not return",
    )

reject(
    r"struct\s+net\s*\*\s*net\s*=\s*&init_net",
    CLIENT_FS + CONNTRACK,
    "unused procfs net locals must not return",
)
reject(
    r"af_client_visit_seq_next\s*\([^)]*\)\s*\{\s*"
    r"struct\s+af_client_visit_iter_state\s*\*\s*st\s*=\s*s->private",
    CLIENT_FS,
    "unused client visit iterator state must not return",
)
reject(
    r"static\s+int\s+af_visiting_seq_show\s*\([^)]*\)\s*\{"
    r"(?:(?!\n\}).)*static\s+int\s+index\s*=\s*0\s*;",
    CLIENT_FS,
    "write-only procfs iterator state must not return",
)
reject(
    r"#\s*pragma\s+GCC\s+diagnostic|__diag_ignore|Wno-(?:missing-prototypes|unused)",
    CLIENT + CLIENT_HEADER + CLIENT_FS + CLIENT_FS_HEADER + CONNTRACK + CONNTRACK_HEADER,
    "warning cleanup must not add warning suppression",
)

print("ok: K-12 client/procfs/conntrack warning cleanup contract passed")
