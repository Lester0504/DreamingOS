#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


schema = between(WEB, '"CREATE TABLE IF NOT EXISTS app_devices ("',
                 '"CREATE TABLE IF NOT EXISTS auth_tokens ("')
for column in ("approval_state", "approved_at", "approved_by", "status_token_hash"):
    assert column in schema
assert "paired_at>0 AND approval_state<>'approved'" in schema
assert "approval_state='expired'" in schema

pair_init = between(WEB, "static struct json_object *jmx_app_pair_init_ex",
                    "static struct json_object *jmx_app_pair_error")
assert "webd_token_sha256(status_token, status_token_hash)" in pair_init
assert "'pending',0,'',?9" in pair_init
assert "device_count == 0 && pending == 0" in pair_init
assert "web_owner_count == 0" in pair_init
assert 'json_object_object_add(resp, "status_token"' in pair_init
assert 'json_object_object_add(resp, "state", json_object_new_string("pending_approval"))' in pair_init

confirm = between(WEB, "static struct json_object *jmx_app_pair_confirm_ex",
                  "struct json_object *jmx_app_pair_cancel")
assert "pair_approval_required" in confirm
assert "webd_password_verify(code, stored_hash)" in confirm
assert confirm.index("webd_password_verify(code, stored_hash)") < confirm.index(
    'strcmp(approval_state, "approved")'
)
assert "approval_state='approved' AND approved_at>0" in confirm
assert "status_token_hash=''" in confirm

status = between(WEB, "static struct json_object *jmx_app_pair_status",
                 "static struct json_object *jmx_app_pair_approve")
assert "pair_status_token_required" in status
assert "webd_token_sha256(status_token, supplied_status_hash)" in status
assert "ct_str_equal(supplied_status_hash, stored_status_hash)" in status
assert 'state = "pending_approval"' in status
assert 'state = "approved"' in status
assert 'state = "canceled"' in status
assert 'state = "expired"' in status
assert 'state = "rejected"' in status
assert "if (!found && !owner_authenticated)" in status

approval = between(WEB, "static struct json_object *jmx_app_pair_approve",
                   "static int jmx_app_owner_count_except")
assert "approval_state='pending'" in approval
assert 'const char *state = approve ? "approved" : "rejected"' in approval
assert "approved_by=?3" in approval

public_routes = between(WEB, "/* ── Pair init (no auth) ── */",
                        "/* ── Pair cancel")
assert '"/api/v1/auth/pair/status"' in public_routes
assert "jmx_app_pair_status(pair_id, status_token, 0)" in public_routes
assert "pair status requires the one-time status token" in public_routes

approve_dispatch = between(WEB, 'else if (!strcmp(req.path, "/api/v1/auth/pair/approve")',
                           "/* ── Session ── */")
assert "!webd_identity_is_user(device_id) || role != JMX_ROLE_OWNER" in approve_dispatch
assert "jmx_app_pair_approve(pair_id, device_id, approve" in approve_dispatch

device_admin = between(WEB, "/* ── Set device role / enabled state",
                       "/* ── System status")
assert "jmx_app_device_patch_atomic(" in device_admin
assert "jmx_app_device_delete_atomic(" in device_admin

device_patch = between(WEB, "static int jmx_app_device_patch_atomic",
                       "static int jmx_app_device_delete_atomic")
assert 'sqlite3_exec(g_app_db, "BEGIN IMMEDIATE"' in device_patch
assert 'sqlite3_exec(g_app_db, "COMMIT"' in device_patch
assert 'sqlite3_exec(g_app_db, "ROLLBACK"' in device_patch
assert "UPDATE app_devices SET role=?1,enabled=?2" in device_patch
assert "UPDATE auth_tokens SET revoked=1" in device_patch
assert "webd_identity_is_user(actor_identity)" in device_patch

device_delete = between(WEB, "static int jmx_app_device_delete_atomic",
                        "/* ══════════════════════════════════════════════════════════════════════\n * Config Transaction")
assert 'sqlite3_exec(g_app_db, "BEGIN IMMEDIATE"' in device_delete
assert "jmx_app_owner_count_except(device_id)" in device_delete
assert 'sqlite3_exec(g_app_db, "ROLLBACK"' in device_delete

csrf = between(WEB, "if ((!strncmp(req.path, \"/api/v1/uploads\"",
               "const char *required_permission")
assert '"/api/v1/auth/pair/approve"' in csrf
assert '{ "/api/v1/auth/pair/approve",     "POST", JMX_RISK_HIGH }' in PERMS

cancel = between(WEB, "struct json_object *jmx_app_pair_cancel",
                 "static struct json_object *jmx_app_login_ex")
assert "approval_state='canceled'" in cancel
assert "DELETE FROM app_devices" not in cancel
assert '!strcmp((const char *)sqlite3_column_text(st, 8), "pending")' in WEB

print("ok: app pairing requires Web-owner approval and token-scoped public status")
