#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/jmx_netconfig_db.h").read_text(encoding="utf-8")
WORK_MODE = (ROOT / "src/jmx_dreamingwrt_work_mode.c").read_text(encoding="utf-8")
NETWORK = (ROOT / "src/jmx_network.c").read_text(encoding="utf-8")
MAIN = (ROOT / "src/main.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")


def test_work_mode_is_owned_by_config_db_after_one_time_import():
    for required in (
        "CREATE TABLE IF NOT EXISTS work_mode_settings",
        "CREATE TABLE IF NOT EXISTS work_mode_snapshot",
        'NC_WORK_MODE_UCI_MIGRATION "work_mode_uci_v1"',
        "uci:/etc/config/jmx",
        '"legacy_uci_imported"',
        '"preserved_existing_config_db_value"',
        'nc_exec("BEGIN IMMEDIATE")',
        'nc_exec("ROLLBACK")',
    ):
        assert required in DB
    for helper in (
        "jmx_work_mode_config_get",
        "jmx_work_mode_config_set_legacy",
        "jmx_work_mode_config_begin_apply",
        "jmx_work_mode_config_finish_apply",
        "jmx_work_mode_config_begin_rollback",
        "jmx_work_mode_config_finish_rollback",
    ):
        assert helper in HEADER
        assert helper in DB


def test_all_runtime_consumers_stop_reading_first_party_work_mode_uci():
    assert 'jmx_uci_get_int_value(ctx, "jmx.network.work_mode")' not in WORK_MODE
    assert 'WM_JMX_PKG' not in WORK_MODE
    assert 'WM_DREAMINGWRT_PKG' not in WORK_MODE
    assert 'wm_backup_config(rollback_id, "jmx")' not in WORK_MODE
    assert 'wm_rollback_config(rollback_id, "jmx")' not in WORK_MODE
    assert 'jmx_uci_commit(ctx, "jmx")' not in WORK_MODE
    assert 'jmx_work_mode_config_get(&work_mode' in NETWORK
    assert 'jmx_work_mode_config_set_legacy(work_mode)' in NETWORK
    assert 'jmx_work_mode_config_get(&work_mode' in MAIN
    assert 'jmx_work_mode_config_get(&work_mode' in UBUS
    assert not (ROOT / "files/jmx_cli.sh").exists()


def test_apply_and_rollback_are_db_transaction_plus_native_projection():
    for required in (
        "jmx_work_mode_config_begin_apply(target_mode, rollback_id",
        "jmx_work_mode_config_finish_apply(0, \"runtime_projection_failed\")",
        "jmx_work_mode_config_finish_apply(1, \"\")",
        "jmx_work_mode_config_begin_rollback(rollback_id, &mode)",
        "jmx_work_mode_config_finish_rollback(1, rollback_id, \"\")",
        "wm_uci_readback(target_mode, lan_ip, auto_nm, gateway",
        'wm_backup_config(rollback_id, "network") != 0',
        'wm_backup_config(rollback_id, "dhcp") != 0',
        'wm_backup_config(rollback_id, "firewall") != 0',
    ):
        assert required in WORK_MODE
    assert "__sync_add_and_fetch(&wm_rollback_sequence, 1)" in WORK_MODE
    assert "if (nc_schema() != 0) goto fail;" in DB
    assert "sqlite3_close(g_netconfig_db);" in DB


if __name__ == "__main__":
    test_work_mode_is_owned_by_config_db_after_one_time_import()
    test_all_runtime_consumers_stop_reading_first_party_work_mode_uci()
    test_apply_and_rollback_are_db_transaction_plus_native_projection()
    print("ok: work mode uses config.db authority and native UCI projection only")
