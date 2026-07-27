from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_line_health_filters_runtime_history_by_configured_wans():
    source = (ROOT / "src" / "jmx_db.c").read_text()

    assert "jmx_netconfig_wan_configured(name, name)" in source
    assert "bucket_start<=?3" in source


def test_wan_session_contract_is_bounded_by_current_boot():
    source = (ROOT / "src" / "jmx_db.c").read_text()

    assert '"connection_time_source"' in source
    assert '"connection_time_valid"' in source
    assert '"connection_time_reason"' in source
    assert '"session_predates_current_boot"' in source
    assert '"future_session_timestamp"' in source
    assert '"previous_boot_pruned"' in source
    assert '"future_timestamp_pruned"' in source


def test_configured_wan_lookup_uses_config_db_wan_table():
    source = (ROOT / "src" / "jmx_netconfig_db.c").read_text()
    header = (ROOT / "src" / "jmx_netconfig_db.h").read_text()

    assert "jmx_netconfig_wan_configured" in header
    assert "SELECT 1 FROM wan WHERE id=?1 OR ifname=?2 LIMIT 1" in source
