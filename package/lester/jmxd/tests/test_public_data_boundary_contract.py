#!/usr/bin/env python3
"""Keep private datasets optional in the public DreamingOS source tree."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
MAIN = (ROOT / "src/main.c").read_text(encoding="utf-8")
SIGNATURES = (ROOT / "src/jmx_signature_update.c").read_text(encoding="utf-8")


def config_block(name: str, next_name: str) -> str:
    start = MAKEFILE.index(f"config {name}")
    return MAKEFILE[start:MAKEFILE.index(f"config {next_name}", start)]


def test_private_datasets_are_not_shipped() -> None:
    for relative in (
        "files/signatures/dreamingwrt_signatures.db",
        "files/fingerprint.db",
        "files/fingerprint",
        "files/logo",
    ):
        assert not (ROOT / relative).exists(), relative


def test_private_bundle_options_default_off_and_validate_inputs() -> None:
    signature = config_block(
        "DREAMINGWRT_BUNDLE_SIGNATURE_DB", "DREAMINGWRT_BUNDLE_FINGERPRINT_DB"
    )
    fingerprint = config_block(
        "DREAMINGWRT_BUNDLE_FINGERPRINT_DB", "DREAMINGWRT_GATEWAY_SHADOW"
    )
    images = config_block("DREAMINGWRT_FULL_CLIENT_IMAGES", "DREAMINGWRT_LOGOS")
    logos = config_block("DREAMINGWRT_LOGOS", "DREAMINGWRT_AEGISXD_WITH_SURICATA")
    for block in (signature, fingerprint, images, logos):
        assert "default n" in block
    for marker in (
        "DREAMINGWRT_BUNDLE_SIGNATURE_DB=y but",
        "DREAMINGWRT_BUNDLE_FINGERPRINT_DB=y but",
        "DREAMINGWRT_FULL_CLIENT_IMAGES=y but",
        "DREAMINGWRT_LOGOS=y but",
    ):
        assert marker in MAKEFILE


def test_package_install_is_conditionally_guarded() -> None:
    assert "ifeq ($(CONFIG_DREAMINGWRT_BUNDLE_SIGNATURE_DB),y)" in MAKEFILE
    assert "ifeq ($(CONFIG_DREAMINGWRT_BUNDLE_FINGERPRINT_DB),y)" in MAKEFILE
    assert "ifeq ($(CONFIG_DREAMINGWRT_FULL_CLIENT_IMAGES),y)" in MAKEFILE
    assert "ifeq ($(CONFIG_DREAMINGWRT_LOGOS),y)" in MAKEFILE


def test_missing_signature_database_is_ready_but_degraded() -> None:
    for marker in (
        "JMX_SIGNATURE_UNAVAILABLE",
        "jmx_core_note_signature_unavailable",
        '"signature_database_unavailable"',
        "g_core_runtime.stage = JMX_CORE_STAGE_READY",
        "g_core_runtime.ready = 1",
        "g_core_runtime.degraded = 1",
    ):
        assert marker in MAIN
    assert '"signature_state"' in MAIN
    assert '"fingerprint_catalog_state"' in MAIN


def test_explicit_missing_signature_database_is_an_error() -> None:
    for marker in (
        "int explicit_path = path && path[0]",
        "if (!candidate_exists && !explicit_path &&",
        '"signature: requested database does not exist: %s\\n"',
        "explicit_path && !candidate_exists ? -ENOENT : -1",
    ):
        assert marker in MAIN


def test_invalid_installed_signature_database_remains_an_error() -> None:
    for marker in (
        '"PRAGMA quick_check"',
        '"app", "dpi_rule", "meta"',
        'exists ? "invalid" : "unavailable"',
        'exists ? "invalid_signature_database" : "signature_database_unavailable"',
        "ok || !exists ? API_CODE_SUCCESS : API_CODE_ERROR",
    ):
        assert marker in SIGNATURES


if __name__ == "__main__":
    test_private_datasets_are_not_shipped()
    test_private_bundle_options_default_off_and_validate_inputs()
    test_package_install_is_conditionally_guarded()
    test_missing_signature_database_is_ready_but_degraded()
    test_explicit_missing_signature_database_is_an_error()
    test_invalid_installed_signature_database_remains_an_error()
    print("ok: public tree excludes private datasets and degrades explicitly")
