#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


avatar = between(CORE, "int jmx_admin_avatar_set", "int jmx_admin_rename")
assert "nc_web_user_avatar_persist(username, url)" in avatar
assert "nc_web_user_avatar_persist(username, avatar_url)" in avatar
assert '"avatar_file_not_found"' in avatar
assert "unlink(path)" in avatar

settings = between(CORE, "struct json_object *jmx_system_settings_get", "int jmx_system_settings_set")
assert "SELECT username,role,avatar_url FROM web_users" in settings
assert 'snprintf(av,sizeof(av),"/luci-static/dreamingwrt/avatar/%s.png"' not in settings

schema = between(WEB, 'CREATE TABLE IF NOT EXISTS web_users', 'CREATE TABLE IF NOT EXISTS web_user_groups')
assert 'config_db_add_column_if_missing("web_users", "avatar_url"' in schema

auth_state = between(WEB, "static void webd_system_basic_attach_auth_state",
                     "static void webd_system_settings_scrub_sensitive")
assert "SELECT avatar_url FROM web_users" in auth_state
assert 'static const char *exts[] = { "png", "jpg", "jpeg", "webp", NULL }' in auth_state
assert "webd_twofa_qr_available()" in auth_state

avatar_bff = between(WEB, "static int webd_admin_avatar_persist_from_response",
                     "static int webd_system_settings_apply_admin_ops")
assert "UPDATE web_users SET avatar_url=?1" in avatar_bff
assert 'snprintf(path, sizeof(path), "/www%s", url)' in avatar_bff
assert "sqlite3_changes(g_config_db) > 0" in avatar_bff

admin_ops = between(WEB, "static int webd_system_settings_apply_admin_ops",
                    "static int webd_system_settings_has_admin_write")
assert admin_ops.count("webd_admin_avatar_persist_from_response(") == 2
assert admin_ops.count('"admin_avatar_persisted"') == 2

bootstrap = between(WEB, "static int webd_pairing_origin",
                    "static struct json_object *webd_upload_meta_json")
assert '"dreamingwrt-app-pairing"' in bootstrap
assert '"qr_payload_version"' in bootstrap
assert '"base_url"' in bootstrap
assert "req->host" in bootstrap
assert 'jmx_cache_put("webd_bootstrap:guest", resp, 10)' in bootstrap
assert "webd_json_clone(cached)" in bootstrap
assert "webd_bootstrap_attach_pairing(resp, req)" in bootstrap

parser = between(WEB, "static int parse_http_request", "static int http_content_length_from_raw")
assert 'find_header_value(raw, hdr_end, "Host"' in parser
assert 'find_header_value(raw, hdr_end, "X-Forwarded-Host"' not in parser
assert 'find_header_value(raw, hdr_end, "X-Forwarded-Proto"' in parser

assert "+qrencode" in MAKEFILE
print("ok: avatars persist their real URL, QR capability is runtime-backed, and pairing discovery is versioned")
