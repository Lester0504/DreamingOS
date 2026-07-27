#!/usr/bin/env python3
"""Contract for persistent DreamingWrt AC listener defaults under unified init."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "src/init/dreamingwrt_init.c"
PKI = ROOT / "src/ac/ac_pki.c"
RESTORE = ROOT / "src/init/config_restore.h"


def test_unified_init_injects_ac_listener_defaults_without_overriding_operator_env() -> None:
    source = INIT.read_text(encoding="utf-8")
    entry_start = source.index('{ .name = "dreamingwrt-ac"')
    entry_end = source.index('{ .name = "dreamingwrt-apd"', entry_start)
    entry = source[entry_start:entry_end]

    assert '.enabled = 0' in entry and '.critical = 0' in entry
    assert 'DREAMINGWRT_AC_LISTEN_ADDR=0.0.0.0' in entry
    assert 'DREAMINGWRT_AC_LISTEN_PORT=18443' in entry
    assert 'DREAMINGWRT_AC_LISTEN_NAMES=' not in entry
    assert 'apply_component_env_defaults(c);' in source
    assert 'if (!getenv(key) || !getenv(key)[0])' in source, (
        "non-empty operator supplied DREAMINGWRT_AC_LISTEN_* env must remain an override"
    )
    assert source.index('apply_component_env_defaults(c);') < source.index('execv(path, argv);')


def test_ac_pki_rotates_only_server_certificate_when_listen_names_change() -> None:
    source = PKI.read_text(encoding="utf-8")

    assert 'ac_pki_server_without_san_valid' in source
    assert 'getifaddrs(&interfaces)' in source
    assert 'IFF_UP' in source and 'IFF_LOOPBACK' in source
    assert 'X509_free(pki->server_cert);' in source
    assert 'pki->server_cert = ac_pki_server_create' in source
    assert 'ac_pki_certificate_store(dirfd, AC_PKI_SERVER_CERT_FILE' in source
    assert 'ac_pki_key_store(dirfd, AC_PKI_CA_KEY_FILE' in source
    assert 'ac_pki_key_store(dirfd, AC_PKI_SERVER_KEY_FILE' in source
    ca_validation_pos = source.index('if (!ac_pki_ca_valid(pki->ca_cert, pki->ca_key)')
    server_rotation_pos = source.index('X509_free(pki->server_cert);')
    assert ca_validation_pos < server_rotation_pos, (
        "CA validity must be checked before any server certificate SAN rotation"
    )
    assert 'ac_pki_server_without_san_valid(pki->server_cert,' in source


def test_init_runtime_buffers_follow_their_source_contracts() -> None:
    source = INIT.read_text(encoding="utf-8")
    restore = RESTORE.read_text(encoding="utf-8")

    assert '#define DWRT_STORAGE_SCAN_PATH_SIZE 512' in source
    assert 'char largest_path[DWRT_STORAGE_SCAN_PATH_SIZE];' in source
    assert 'char path[DWRT_STORAGE_SCAN_PATH_SIZE];' in source
    assert 'char operation_id[96];' in restore
    assert 'sizeof(((struct dwrt_config_restore_info *)0)->operation_id)' in source
    assert '_Static_assert(sizeof(g_config_restore_attempted_operation)' in source


if __name__ == "__main__":
    test_unified_init_injects_ac_listener_defaults_without_overriding_operator_env()
    test_ac_pki_rotates_only_server_certificate_when_listen_names_change()
    test_init_runtime_buffers_follow_their_source_contracts()
    print("ok: AC init persistent listener defaults and safe server SAN rotation contract")
