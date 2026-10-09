"""Contract checks for canonical authority diagnostics."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/authority/authority_diagnostics.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/authority/authority_diagnostics.h").read_text(encoding="utf-8")


def test_authority_contract_exposes_required_readback_fields():
    assert 'JMX_AUTHORITY_DIAGNOSTICS_CONTRACT "authority-diagnostics.v1"' in HEADER
    for field in (
        "canonical_path", "format", "schema_version", "sha256",
        "duplicate_paths", "writer_count", "last_update", "migration_state",
        "path_observations", "format_conflict", "active_path", "active_role",
        "canonical_present", "canonical_writable", "canonical_read_only",
        "present_duplicate_paths", "present_duplicate_count",
        "content_mismatch_paths", "content_mismatch_count",
        "writable_duplicate_paths", "writable_duplicate_count",
    ):
        assert f'"{field}"' in SOURCE
    assert '"degraded"' in SOURCE
    assert '"authority_duplicate_or_invalid"' in SOURCE


def test_authority_paths_and_format_guards_are_explicit():
    for path in (
        "/etc/dreamingwrt/dreamingwrt_signatures.db",
        "/usr/share/dreamingos/system-db/dreamingwrt_signatures.db",
        "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db",
        "/etc/dreamingwrt/dreamingwrt_signatures.dwsig",
        "/etc/dreamingwrt/fingerprint/fingerprint.db",
        "/usr/share/dreamingos/system-db/fingerprint.db",
        "/usr/share/dreamingwrt/system-db/fingerprint.db",
        "/etc/dreamingwrt/dreamingwrt.db",
    ):
        assert path in SOURCE
    assert '"SQLite format 3\\0"' in SOURCE
    assert '"DWSIG001"' in SOURCE
    assert '"degraded_format_or_integrity"' in SOURCE
    assert '"degraded_format_conflict"' in SOURCE
    assert '"degraded_duplicate_content_mismatch"' in SOURCE
    assert '"degraded_writable_duplicate"' in SOURCE
    assert '"runtime_canonical"' in SOURCE
    assert '"firmware_seed"' in SOURCE
    assert '"firmware_fallback"' in SOURCE


def test_dreamingwrt_db_is_not_treated_as_signature_authority():
    assert '"control_runtime_identity_network_aegis_foreign_keys"' in SOURCE
    assert '"control_runtime_local_rescue_only"' in SOURCE
    assert '"core_config_identity_and_runtime_foreign_keys"' in SOURCE
    assert 'migration_allowed' in SOURCE
    assert 'json_object_new_boolean(desc->allow_migration)' in SOURCE


def test_authority_duplicate_metadata_is_explicitly_read_only_inventory():
    assert 'json_object_new_boolean(path_present && !path_writable)' in SOURCE
    assert 'json_object_new_boolean(canonical_present &&' in SOURCE
    assert 'json_object_new_boolean(exists &&' in SOURCE
    assert '!present_duplicate_count' in SOURCE


if __name__ == "__main__":
    test_authority_contract_exposes_required_readback_fields()
    test_authority_paths_and_format_guards_are_explicit()
    test_dreamingwrt_db_is_not_treated_as_signature_authority()
    print("ok: authority diagnostics contract")
