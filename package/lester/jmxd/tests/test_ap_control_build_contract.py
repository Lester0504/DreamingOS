#!/usr/bin/env python3
"""Build and packaging contract for DreamingWrt AP control Phase 0."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def read_required(path: Path) -> str:
    assert path.is_file(), f"required production file is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def package_block(makefile: str, package: str, suffix: str = "") -> str:
    name = f"Package/{package}{suffix}"
    match = re.search(
        rf"^define {re.escape(name)}\s*$\n(.*?)^endef\s*$",
        makefile,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"OpenWrt package block is missing: {name}"
    return match.group(1)


def component_entry(supervisor: str, name: str) -> str:
    match = re.search(
        rf"\{{\s*\.name\s*=\s*\"{re.escape(name)}\"",
        supervisor,
    )
    assert match, f"dreamingwrt-init component is missing: {name}"
    start = match.start()
    depth = 0
    for pos in range(start, len(supervisor)):
        if supervisor[pos] == "{":
            depth += 1
        elif supervisor[pos] == "}":
            depth -= 1
            if depth == 0:
                return supervisor[start:pos + 1]
    raise AssertionError(f"could not delimit dreamingwrt-init component: {name}")


def function_body(text: str, symbol: str) -> str:
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert match, f"production function body is missing: {symbol}"
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text) and depth:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"could not delimit production function: {symbol}"
    return text[start:pos - 1]


def test_phase0_has_the_two_formal_source_components_and_objects() -> None:
    expected_sources = (
        "ac/ac_main.c",
        "ac/ac_internal.h",
        "ac/ac_db.c",
        "ac/ac_enrollment.c",
        "ac/ac_protocol.c",
        "ac/ac_transport.c",
        "ac/ac_ubus.c",
        "apd/apd_main.c",
        "apd/apd_internal.h",
        "apd/apd_db.c",
        "apd/apd_enrollment.c",
        "apd/apd_protocol.c",
        "apd/apd_transport.c",
        "apd/apd_backend.c",
        "apd/apd_backend_openwrt.c",
        "apd/apd_readonly_command.c",
        "apd/apd_readonly_command.h",
        "apd/apd_ubus.c",
    )
    missing = [path for path in expected_sources if not (SRC / path).is_file()]
    assert not missing, f"AP control Phase 0 production sources are missing: {missing}"

    makefile = read_required(SRC / "Makefile")
    required_make_tokens = (
        "AC_OBJS := ac/ac_main.o ac/ac_db.o ac/ac_enrollment.o ac/ac_pki.o ac/ac_protocol.o ac/ac_transport.o ac/ac_ubus.o ap_control_wire.o",
        "APD_OBJS := apd/apd_main.o apd/apd_db.o apd/apd_enrollment.o apd/apd_credentials.o apd/apd_protocol.o apd/apd_transport.o apd/apd_backend.o apd/apd_backend_openwrt.o apd/apd_readonly_command.o apd/apd_ubus.o ap_control_wire.o",
        "AC_EXEC := dreamingwrt-ac",
        "APD_EXEC := dreamingwrt-apd",
        "$(AC_EXEC): $(AC_OBJS)",
        "$(APD_EXEC): $(APD_OBJS)",
    )
    missing_tokens = [token for token in required_make_tokens if token not in makefile]
    assert not missing_tokens, f"src/Makefile is missing AP control targets: {missing_tokens}"
    for assignment in ("AC_LIBS ?=", "APD_LIBS ?="):
        line = next(value for value in makefile.splitlines()
                    if value.startswith(assignment))
        assert "-lnghttp2" not in line, (
            "AP node transport is TLS 1.3 length-prefixed JSON, not HTTP/2"
        )
    all_line = next((line for line in makefile.splitlines() if line.startswith("all:")), "")
    assert "$(AC_EXEC)" in all_line and "$(APD_EXEC)" in all_line


def test_openwrt_packages_install_only_the_formal_binaries() -> None:
    makefile = read_required(ROOT / "Makefile")
    for package in ("dreamingwrt-ac", "dreamingwrt-apd"):
        definition = package_block(makefile, package)
        install = package_block(makefile, package, "/install")
        assert "Optional" in definition or "optional" in definition
        assert f"$(INSTALL_BIN) $(PKG_BUILD_DIR)/{package} $(1)/usr/bin" in install
        assert f"$(eval $(call BuildPackage,{package}))" in makefile
        assert f"define Package/{package}/postinst" not in makefile, (
            f"{package} must not auto-enable itself after installation"
        )

        if package == "dreamingwrt-ac":
            assert "/etc/init.d" not in install, (
                "controller AC must use dreamingwrt-init"
            )
        else:
            assert "dreamingwrt-apd.init" in install
            assert "$(1)/etc/init.d/dreamingwrt-apd" in install

    meta = package_block(makefile, "jmxd")
    assert "+dreamingwrt-ac" not in meta and "+dreamingwrt-apd" not in meta, (
        "Phase 0 AP components are optional and must not be selected by the generic meta package"
    )


def test_unified_init_registers_optional_noncritical_disabled_components() -> None:
    supervisor = read_required(SRC / "init/dreamingwrt_init.c")
    for name, short in (("dreamingwrt-ac", "ac"), ("dreamingwrt-apd", "apd")):
        entry = component_entry(supervisor, name)
        assert f'.path = "/usr/bin/{name}"' in entry
        assert re.search(r"\.enabled\s*=\s*0\b", entry), f"{name} must default disabled"
        assert re.search(r"\.critical\s*=\s*0\b", entry), f"{name} must be non-critical"
        assert ".alias_name" not in entry and ".alias_path" not in entry
        assert f'"{short}"' not in entry, (
            "ac/apd are canonical short names derived by short_name(), not compatibility aliases"
        )

    short_name = function_body(supervisor, "short_name")
    assert '"dreamingwrt-"' in short_name
    assert "return c->name + strlen(prefix);" in short_name
    matcher = function_body(supervisor, "component_name_matches")
    assert "strcmp(name, short_name(c)) == 0" in matcher, (
        "dreamingwrt-init must accept the derived ac/apd short names"
    )


def test_retired_binary_and_package_names_do_not_exist() -> None:
    production_paths = [ROOT / "Makefile", SRC / "Makefile"]
    production_paths.extend(
        path for path in SRC.rglob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    )
    production = "\n".join(read_required(path) for path in production_paths)
    retired = (
        "dreamingwrt-apd-server",
        "dreamingwrt-apd-client",
        "APD_SERVER_EXEC",
        "APD_CLIENT_EXEC",
    )
    found = [name for name in retired if name in production]
    assert not found, f"retired AP control names remain in production build files: {found}"


if __name__ == "__main__":
    test_phase0_has_the_two_formal_source_components_and_objects()
    test_openwrt_packages_install_only_the_formal_binaries()
    test_unified_init_registers_optional_noncritical_disabled_components()
    test_retired_binary_and_package_names_do_not_exist()
    print("ok: AP control build, packages, formal names, and optional supervisor registration")
