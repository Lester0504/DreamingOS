#!/usr/bin/env python3
"""Keep removed static authorities from returning to the firmware package."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_removed_static_authorities_are_absent() -> None:
    for relative in (
        "files/config.db",
        "files/dreamingwrt_signatures.db",
        "files/feature.cfg",
        "files/gen_class.sh",
        "files/appfilter.config",
        "files/appfilter_whitelist.config",
        "files/macfilter.config",
        "files/macfilter_whitelist.config",
        "files/jmx_route.config",
        "files/jmx.config",
        "files/user_info.config",
        "files/jmx_cli.sh",
        "files/uci-defaults/100_jmx",
        "files/fingerprint-rules/fingerprint-image-index.csv",
        "files/fingerprint-rules/fingerprint-image-index.json",
        "files/fingerprint-rules/unifi-fingerprint-rules.json",
    ):
        assert not (ROOT / relative).exists(), relative


def test_runtime_sources_use_sqlite_authorities() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    sources = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "src/jmx_config.c",
            "src/jmx_ubus.c",
            "src/main.c",
            "src/init/dreamingwrt_init.c",
            "src/jmx_db.c",
            "src/webd/jmx_app_api.c",
            "src/jmx_system_data_path.c",
        )
    )
    assert "config DREAMINGWRT_BUNDLE_FINGERPRINT_DB" in makefile
    assert "config DREAMINGWRT_BUNDLE_SIGNATURE_DB" in makefile
    assert "ifeq ($(CONFIG_DREAMINGWRT_BUNDLE_FINGERPRINT_DB),y)" in makefile
    assert "ifeq ($(CONFIG_DREAMINGWRT_BUNDLE_SIGNATURE_DB),y)" in makefile
    assert "fingerprint-image-index" not in makefile
    assert "unifi-fingerprint-rules" not in makefile
    assert "/tmp/feature.cfg" not in sources
    assert "fingerprint-image-index.csv" not in sources
    assert 'JMX_SYSTEM_FINGERPRINT_RUNTIME_PATH "/etc/dreamingwrt/fingerprint/fingerprint.db"' in sources
    assert 'JMX_SYSTEM_FINGERPRINT_NEW_PATH "/usr/share/dreamingos/system-db/fingerprint.db"' in sources
    assert 'JMX_SYSTEM_FINGERPRINT_LEGACY_PATH "/usr/share/dreamingwrt/system-db/fingerprint.db"' in sources
    all_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "src").rglob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    )
    assert "/usr/share/jmxd/dreamingwrt_signatures.db" not in all_sources
    assert "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db" in all_sources


if __name__ == "__main__":
    test_removed_static_authorities_are_absent()
    test_runtime_sources_use_sqlite_authorities()
    print("ok: static authority consolidation contract")
