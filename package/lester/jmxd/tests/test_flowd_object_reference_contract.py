#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FLOWD = (ROOT / "src/flowd/flowd_db.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


for table, fields in {
    "flowd_split_rules": ("src_object", "dst_object", "app_object", "service_object", "time_object"),
    "flowd_domain_rules": ("domain_object", "src_object", "time_object"),
    "flowd_qos_rules": ("src_object", "dst_object", "app_object", "service_object", "time_object"),
    "flowd_quota_rules": ("target_object",),
    "flowd_conn_limit_rules": ("src_object", "dst_object", "service_object", "time_object"),
    "flowd_app_rules": ("src_object", "app_object", "time_object"),
}.items():
    for field in fields:
        assert f"FROM {table} WHERE {field}=?1" in FLOWD, (table, field)

assert 'flowd_exec(g_flowd_config_db, "BEGIN IMMEDIATE")' in FLOWD
assert 'flowd_error("reference_conflict"' in FLOWD
assert '"reference_count"' in FLOWD
assert '"referenced_by"' in FLOWD
assert '"delete_locked"' in FLOWD
assert 'json_object_new_int(409)' in FLOWD
assert 'status = app_routed_http_status(resp, status);' in WEBD

print("ok: flowd objects expose all rule references and refuse atomic delete on conflict")
