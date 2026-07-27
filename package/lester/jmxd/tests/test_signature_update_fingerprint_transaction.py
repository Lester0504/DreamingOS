#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_signature_update.c").read_text(encoding="utf-8")
DB = (ROOT / "src" / "jmx_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src" / "jmx_db.h").read_text(encoding="utf-8")


assert 'JMX_FINGERPRINT_DB_TARGET "/etc/dreamingwrt/fingerprint/fingerprint.db"' in SOURCE
assert 'strcmp(rel, "fingerprint/fingerprint.db")' in SOURCE
assert '"fingerprint_application_id_mismatch"' in SOURCE
assert '"fingerprint_schema_mismatch"' in SOURCE
assert '"fingerprint_device_count_mismatch"' in SOURCE
assert '"fingerprint_requires_v2"' in SOURCE

apply_start = SOURCE.index("struct json_object *jmx_signature_update_apply")
apply_end = SOURCE.index("struct json_object *jmx_signature_update_status", apply_start)
apply = SOURCE[apply_start:apply_end]

reload_pos = apply.index("jmx_runtime_reload_signature_db(JMX_SIGNATURE_DB_DEFAULT)")
fingerprint_rename_pos = apply.index("rename(tmp_fingerprint, JMX_FINGERPRINT_DB_TARGET)")
assert reload_pos < fingerprint_rename_pos
assert "goto rollback;" in apply
assert "rollback_db_file_failed" in apply
assert "rollback_fingerprint_file_failed" in apply
assert "rollback_runtime_reload_failed" in apply
assert "rollback_fingerprint_import_failed" in apply
assert '"fingerprint_installed"' in apply
assert '"fingerprint_target"' in apply
assert '"fingerprint_device_count"' in apply
assert '"fingerprint_sha256"' in apply

assert "int db_try_import_fingerprint_catalog(void)" in DB
assert "int db_try_import_fingerprint_catalog(void);" in HEADER

print("ok: signature apply keeps DPI and fingerprint database state transactional")
