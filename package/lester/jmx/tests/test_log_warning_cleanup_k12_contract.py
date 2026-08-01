#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_log.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src" / "jmx_log.h").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "jmx_main.c").read_text(encoding="utf-8")


def require(pattern: str, text: str, message: str) -> None:
    if not re.search(pattern, text, re.MULTILINE | re.DOTALL):
        raise AssertionError(message)


def reject(pattern: str, text: str, message: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL):
        raise AssertionError(message)


for symbol in ("jmx_debug_level", "jmx_debug_at_least", "af_log_init", "af_log_exit"):
    require(
        rf"^[^\n;]*\b{symbol}\s*\([^;]*;",
        HEADER,
        f"cross-TU log symbol {symbol} must have a typed header declaration",
    )

external_definitions = set(
    re.findall(
        r"^(?!static\b|extern\b|if\b|for\b|while\b|switch\b)"
        r"(?:[A-Za-z_]\w*\s+)+(?:\*\s*)?([A-Za-z_]\w*)\s*"
        r"\([^;{}]*?\)\s*\{",
        SOURCE,
        re.MULTILINE,
    )
)
expected_external_definitions = {
    "jmx_debug_level",
    "jmx_debug_at_least",
    "af_log_init",
    "af_log_exit",
}
if external_definitions != expected_external_definitions:
    raise AssertionError(
        "jmx_log external definitions changed without an explicit contract: "
        f"{sorted(external_definitions ^ expected_external_definitions)}"
    )

for helper in (
    "debug_show",
    "debug_store",
    "af_init_log_sysfs",
    "af_fini_log_sysfs",
    "af_init_log_sysctl",
    "af_fini_log_sysctl",
):
    require(
        rf"^static\s+[^\n]*\b{helper}\s*\(",
        SOURCE,
        f"TU-local log helper {helper} must remain static",
    )

require(
    r'^static char\s+g_jmx_version\s*\[\s*64\s*\]\s*=\s*JMX_VERSION\s*;',
    SOURCE,
    "the sysctl-only version buffer must not expose unnecessary external linkage",
)
require(
    r"#if\s*\(LINUX_VERSION_CODE\s*<\s*KERNEL_VERSION\(6,\s*4,\s*0\)\)"
    r"\s*static struct ctl_table jmx_drt_table\[\] = \{.*?"
    r"static struct ctl_table jmx_root_table\[\] = \{.*?#endif",
    SOURCE,
    "legacy sysctl hierarchy tables must not be compiled unused on Linux 6.4+",
)
require(
    r"#if\s*\(LINUX_VERSION_CODE\s*<\s*KERNEL_VERSION\(6,\s*4,\s*0\)\)"
    r"\s*jmx_table_header\s*=\s*register_sysctl_table\(jmx_root_table\);"
    r"\s*#else\s*jmx_table_header\s*=\s*register_sysctl\("
    r"\"dreamingwrt/jmx\",\s*jmx_table\);",
    SOURCE,
    "old and new kernel sysctl registration paths must preserve their semantics",
)

require(
    r"#define\s+JMX_DEBUG_RATELIMITED\(level,\s*fmt,\s*\.\.\.\)\s+do\s*\{\s*\\"
    r"\s*if\s*\(jmx_debug_at_least\(level\)\)\s*\\"
    r"\s*pr_info_ratelimited\(fmt,\s*##__VA_ARGS__\);\s*\\",
    HEADER,
    "warning cleanup must preserve rate-limited logging and format checking",
)
require(
    r"return\s+level\s*>\s*0\s*&&\s*jmx_debug_level\(\)\s*>=\s*level\s*;",
    SOURCE,
    "debug level zero must keep debug logging disabled",
)
require(
    r"level\s*<\s*0\s*\|\|\s*level\s*>\s*jmx_debug_max",
    SOURCE,
    "sysfs debug writes must remain range checked",
)
require(
    r"\.proc_handler\s*=\s*proc_dointvec_minmax,\s*"
    r"\.extra1\s*=\s*SYSCTL_ZERO,\s*\.extra2\s*=\s*&jmx_debug_max",
    SOURCE,
    "sysctl debug writes must remain range checked",
)
require(
    r'^#include\s+"jmx_log\.h"$',
    MAIN,
    "the cross-TU caller must consume the public log header",
)
reject(
    r"#\s*pragma\s+GCC\s+diagnostic|__diag_ignore|Wno-(?:unused|missing-prototypes|missing-declarations|format)",
    SOURCE + HEADER,
    "K-12 log cleanup must not suppress compiler diagnostics",
)

print("ok: K-12 jmx_log warning cleanup and logging-semantics contract passed")
