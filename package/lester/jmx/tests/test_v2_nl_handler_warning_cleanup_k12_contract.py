#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_v2_nl_handler.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src" / "jmx_v2_nl_handler.h").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "jmx_main.c").read_text(encoding="utf-8")


def require(pattern: str, text: str, message: str) -> None:
    if not re.search(pattern, text, re.MULTILINE):
        raise AssertionError(message)


def reject(pattern: str, text: str, message: str) -> None:
    if re.search(pattern, text, re.MULTILINE):
        raise AssertionError(message)


require(
    r'^#include\s+"jmx_v2_nl_handler\.h"$',
    SOURCE,
    "the v2 handler definition must see its public prototype",
)
require(
    r"^int\s+jmx_v2_nl_handle\s*\(\s*const char \*data,\s*int len,\s*"
    r"u32 portid,\s*u32 nlmsg_seq,\s*jmx_v3_nl_reply_fn reply\s*\)\s*;",
    HEADER,
    "the cross-TU v2 handler needs one typed header declaration",
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
if external_definitions != {"jmx_v2_nl_handle"}:
    raise AssertionError(
        "v2 netlink external definitions changed without an explicit contract: "
        f"{sorted(external_definitions)}"
    )

for helper in ("v2_send_version_ack", "v2_copy_rule"):
    require(
        rf"^static\s+[^\n]*\b{helper}\s*\(",
        SOURCE,
        f"TU-local helper {helper} must remain static",
    )

reject(
    r"^extern\s+[^;]+;",
    SOURCE,
    "cross-TU declarations must come from headers, not local extern statements",
)
require(
    r'^#include\s+"jmx_v2_nl_handler\.h"$',
    MAIN,
    "the v2 dispatch caller must consume the typed public header",
)
reject(
    r"^extern\s+int\s+jmx_v2_nl_handle\s*\(",
    MAIN,
    "the v2 dispatch caller must not duplicate the public declaration",
)
reject(
    r"#\s*pragma\s+GCC\s+diagnostic|__diag_ignore|Wno-(?:missing-prototypes|missing-declarations|unused)",
    SOURCE + HEADER,
    "K-12 cleanup must not suppress compiler diagnostics",
)

print("ok: K-12 jmx_v2_nl_handler warning cleanup contract passed")
