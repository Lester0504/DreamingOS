#!/usr/bin/env python3
"""Static contract for the jmx release/debug and build-hygiene guardrails."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
GITIGNORE = (ROOT / ".gitignore").read_text(encoding="utf-8")


def make_block(name: str) -> str:
    match = re.search(
        rf"^define {re.escape(name)}\n(?P<body>.*?)^endef$",
        MAKEFILE,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"missing make block: {name}"
    return match.group("body")


def test_release_is_default_and_debug_is_explicit() -> None:
    assert re.search(r"^JMX_DEBUG\s*\?=\s*0$", MAKEFILE, re.MULTILINE)
    branch = MAKEFILE.split("ifeq ($(JMX_DEBUG),1)", 1)[1].split("endif", 1)[0]
    debug_flags, release_flags = branch.split("else", 1)
    assert "-Og" in debug_flags
    assert "-g3" in debug_flags
    assert "-fno-inline" in debug_flags
    assert "-O2" not in debug_flags
    assert "-O2" in release_flags
    assert "-Og" not in release_flags


def test_format_security_and_general_warnings_are_enabled() -> None:
    for flag in ("-Wall", "-Wextra", "-Wformat=2", "-Werror=format-security"):
        assert flag in MAKEFILE

    forbidden = (
        "-Wno-format",
        "-Wno-misleading-indentation",
        "-Wno-missing-prototypes",
        "-Wno-missing-declarations",
        "-Wno-unused-variable",
        "-Wno-implicit-fallthrough",
        "-Wno-parentheses",
    )
    for flag in forbidden:
        assert flag not in MAKEFILE, f"global suppression restored: {flag}"


def test_openwrt_kbuild_contract_is_preserved() -> None:
    compile_block = make_block("Build/Compile")
    assert '$(MAKE) -C "$(LINUX_DIR)"' in compile_block
    assert "$(MAKE_OPTS)" in compile_block
    assert "modules" in compile_block
    assert 'M="$(PKG_BUILD_DIR)"' in MAKEFILE
    assert 'EXTRA_CFLAGS="$(EXTRA_CFLAGS)"' in MAKEFILE


def test_clean_is_scoped_and_covers_generated_files() -> None:
    clean = make_block("Build/Clean")
    assert "$(call Build/Clean/Default)" in clean
    assert clean.count('find "$(JMX_PACKAGE_DIR)"') == 2
    for pattern in (
        "*.o",
        "*.ko",
        "*.cmd",
        "Module.symvers",
        "modules.order",
        "__pycache__",
    ):
        assert pattern in clean
    assert "-delete" in clean
    assert "-exec rm -rf '{}' +" in clean
    assert "src/*.c" not in clean
    assert "*.bak" not in clean


def test_generated_files_are_ignored() -> None:
    entries = {
        line.strip()
        for line in GITIGNORE.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for pattern in (
        "*.o",
        "*.ko",
        "*.cmd",
        "Module.symvers",
        "modules.order",
        "__pycache__/",
    ):
        assert pattern in entries


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok: K-12 jmx build guardrails contract passed")
