from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDITD = ROOT / "src" / "audit" / "jmx_auditd.c"


def test_audit_worker_exposes_its_own_runtime_status():
    source = AUDITD.read_text()

    assert 'UBUS_METHOD_NOARG("status", handle_status)' in source
    for field in (
        '"last_aggregation_at"',
        '"last_url_sample_at"',
        '"db_ready"',
        '"sources"',
        '"current_hour"',
        '"app_name_source"',
    ):
        assert field in source
    assert 'SELECT app_id,name FROM app WHERE enabled=1 ORDER BY app_id' in source
    assert "APPID_NAMES" not in source
