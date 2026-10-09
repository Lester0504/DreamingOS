"""
Centralized source file access for webd dispatch tests.

All tests that assert on the text of jmx_app_api.c (and, after the split,
on the concatenated text of webd/api/*.c) should read through this module
so that the file list is maintained in one place.
"""

import os
from pathlib import Path
import re

# Works both in the repository (DreamingOS/jmxd/tests) and in a frozen
# standalone jmxd tree under /tmp.
_JMXD = Path(__file__).resolve().parent.parent


def _webd_base() -> Path:
    override = os.environ.get("WEBD_SOURCE_DIR")
    return Path(override) if override else _JMXD / "src" / "webd"


def webd_source_files() -> list[Path]:
    """Return the list of source files that participate in dispatch routing."""
    base = _webd_base()
    entry = base / "jmx_app_api.c"
    # Headers are included as well as .c files: the split moves declarations
    # (struct http_req, the route table macros) into api/*.h, and a text
    # assertion about a declaration must keep finding it after the move.
    modules = sorted((base / "api").glob("*.c")) + sorted((base / "api").glob("*.h"))
    return [entry, *modules]


def webd_dispatch_text() -> str:
    """Concatenated text of all dispatch source files. For text assertions."""
    parts = []
    for p in webd_source_files():
        parts.append(p.read_text(encoding="utf-8"))
    return "\n".join(parts)


def webd_module_path(name: str) -> Path:
    """Path of one dispatch source file, by bare file name.

    ``name`` is either ``jmx_app_api.c`` or a file under ``webd/api/``, e.g.
    ``api_ubus.c``.
    """
    base = _webd_base()
    if name == "jmx_app_api.c":
        return base / name
    return base / "api" / name


def webd_module_text(name: str) -> str:
    """Text of a single dispatch source file.

    Slicing between two anchors only holds inside one translation unit. A
    ``between()`` over ``webd_dispatch_text()`` whose anchors landed in
    different files used to work by accident of concatenation order; use this
    instead so the assertion states which file it is really about.
    """
    return webd_module_path(name).read_text(encoding="utf-8")


def webd_function_text(module: str, name: str) -> str:
    """Read a definition, not its forward declaration or an adjacent module."""
    text = webd_module_text(module)
    pattern = (
        rf"(?m)^(?:static\s+)?[A-Za-z_][\w \t*]*\b{re.escape(name)}"
        rf"\s*\([^;{{}}]*\)\s*\{{"
    )
    matches = list(re.finditer(pattern, text))
    assert len(matches) == 1, (module, name, len(matches))

    start = matches[0].start()
    pos = matches[0].end() - 1
    depth = 0
    state = "code"
    while pos < len(text):
        ch = text[pos]
        nxt = text[pos + 1] if pos + 1 < len(text) else ""

        if state == "code":
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "/" and nxt == "/":
                state = "line_comment"
                pos += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                pos += 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    if end < len(text) and text[end] == "\n":
                        end += 1
                    return text[start:end]
        elif state in ("string", "char"):
            if ch == "\\":
                pos += 1
            elif (state == "string" and ch == '"') or (
                state == "char" and ch == "'"
            ):
                state = "code"
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment" and ch == "*" and nxt == "/":
            state = "code"
            pos += 1
        pos += 1

    raise AssertionError((module, name, "unterminated definition"))
