#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


password_db = between(
    DB,
    "static int nc_web_user_password_set",
    "static int nc_chpasswd_stdin",
)
assert "int create_if_missing" in password_db
assert '"web_user_not_found"' in password_db
assert "else if (create_if_missing)" in password_db

password_api = between(
    DB,
    "int jmx_admin_password_set_ex",
    "struct json_object *jmx_system_settings_get",
)
assert "jmx_admin_password_set_ex(req, out, 0)" in password_api
assert "nc_web_user_password_set(safe_user, pw, create_if_missing" in password_api
assert "jmx_admin_password_set_ex(admin, out, 1)" in SETUP

rename = between(
    WEB,
    "static int webd_web_user_rename_local",
    "static int webd_system_settings_apply_admin_ops",
)
assert 'UPDATE web_sessions SET username' not in rename
assert 'UPDATE web_user_group_members SET username' in rename
assert "webd_directory_revoke_sessions(old_username)" in rename

admin_ops = between(
    WEB,
    "static int webd_system_settings_apply_admin_ops",
    "static int webd_system_settings_has_admin_write",
)
assert "if (admin && new_password[0] && all_ok)" in admin_ops
assert "if (admin && avatar_data[0] && all_ok)" in admin_ops
assert '"reauth_required"' in admin_ops
assert "webd_directory_revoke_sessions" in admin_ops

save = between(
    WEB,
    "static struct json_object *webd_system_settings_save_response",
    "static struct json_object *webd_system_health_history_response",
)
assert "webd_system_settings_admin_preflight(body, current_username, status)" in save
assert save.index("webd_system_settings_admin_preflight(body, current_username, status)") < save.index(
    'webd_system_settings_core_payload(body)'
)
assert 'app_ubus_invoke_timeout("dreamingwrt_system_settings_apply"' not in save
assert '"jmxd.dreamingwrt_system_settings_transaction"' in save

preflight = between(
    WEB,
    "static struct json_object *webd_system_settings_admin_preflight",
    "static struct json_object *webd_system_settings_save_response",
)
assert "!webd_system_settings_has_admin_write(body)" in preflight
assert "webd_directory_username_exists(current_username)" in preflight
assert '"current_user_not_found"' in preflight
assert "webd_web_user_name_ok(new_username)" in preflight
assert '"username_exists"' in preflight
assert "password_len < 8 || password_len > 256" in preflight
assert '"password_confirmation_mismatch"' in preflight
assert '"conflicting_avatar_sources"' in preflight
assert '"/luci-static/"' in preflight
assert 'strstr(avatar_url, "..")' in preflight
assert "stat(path, &st) != 0 || !S_ISREG(st.st_mode)" in preflight

avatar_preflight = between(
    WEB,
    "static int webd_admin_avatar_data_url_preflight",
    "static struct json_object *webd_system_settings_admin_preflight",
)
assert 'strcmp(mime, "image/png")' in avatar_preflight
assert 'strcmp(mime, "image/jpeg")' in avatar_preflight
assert 'strcmp(mime, "image/webp")' in avatar_preflight
assert "WEBD_ADMIN_AVATAR_MAX_BYTES" in avatar_preflight

dispatch = between(
    WEB,
    'else if ((!strcmp(req.path, "/api/v1/system/settings")',
    "/* ── Network overview",
)
assert "webd_system_settings_has_admin_write(body_json)" in dispatch
assert "!webd_identity_is_user(device_id) || role != JMX_ROLE_OWNER" in dispatch
assert "webd_system_settings_admin_targets_current" in dispatch
assert '"owner_web_session_required"' in dispatch

has_admin_write = between(
    WEB,
    "static int webd_system_settings_has_admin_write",
    "static int webd_system_settings_admin_targets_current",
)
assert 'app_nc_json_has(admin, "password_confirm")' in has_admin_write
scrub = between(
    WEB,
    "static void webd_system_settings_scrub_sensitive",
    "static int webd_web_user_name_ok",
)
assert '"password_confirm"' in scrub

csrf = between(
    WEB,
    "if ((!strncmp(req.path, \"/api/v1/uploads\"",
    "const char *required_permission",
)
assert '"/api/v1/system/settings"' in csrf
assert '"/api/v1/save_system_settings"' in csrf
assert '"/api/v1/system/admin/"' in csrf

assert '{ "/api/v1/system/admin/avatar",   "POST,PUT", JMX_RISK_HIGH }' in PERMS
assert '{ "/api/v1/system/admin/avatar",       "POST,PUT", JMX_RISK_MEDIUM }' not in PERMS

dedicated_password = between(
    WEB,
    'else if (!strcmp(req.path, "/api/v1/system/admin/password")',
    "/* ── Startup service action",
)
assert "webd_identity_is_user(device_id)" in dedicated_password
assert "webd_identity_username(device_id)" in dedicated_password
assert "webd_directory_revoke_sessions(username)" in dedicated_password

print("ok: administrator writes require the current Web owner, update-only users, CSRF, and truthful partial failure")
