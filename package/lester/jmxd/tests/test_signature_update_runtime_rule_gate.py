from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_signature_update_rejects_empty_fixed_runtime_rules():
    source = (ROOT / "src" / "jmx_signature_update.c").read_text()

    assert "nc_signature_runtime_invalid_rule_count" in source
    assert "lower(match_type) IN ('exact','fixed','bm')" in source
    assert '"empty_fixed_payload_rules"' in source
    assert '"runtime_empty_fixed_payload"' in source
    assert "invalid_runtime_rules > 0" in source
