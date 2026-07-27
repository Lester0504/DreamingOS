#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


db_init = between(WEB, "static int app_db_init", "static sqlite3_stmt *app_prepare")
assert "webd_session_idle_migrate(g_config_db, g_app_db)" in db_init
assert db_init.index("webd_session_idle_migrate") < db_init.rindex("return 0;")
assert "goto fail" in db_init[db_init.index("webd_session_idle_migrate"):]

login = between(WEB, "static struct json_object *jmx_web_login_ex",
                "static void gen_pair_code")
assert "gen_random_hex(session_id, TOKEN_LEN)" in login
assert "webd_session_idle_login_insert(" in login
assert "app_insert_web_session(" not in login

refresh = between(WEB, "static struct json_object *jmx_app_refresh_ex",
                  "\nstruct json_object *jmx_app_refresh(")
assert "FROM auth_tokens t" in refresh
assert "webd_session_idle_refresh_issue(" in refresh
assert "webd_session_idle_error(idle_rc)" in refresh

validation = between(WEB, "static char *jmx_app_validate_token_mode",
                     "struct json_object *jmx_app_devices_list")
assert "auth_tokens" in validation
assert "webd_session_idle_access_check(" in validation
assert "record_activity" in validation
assert "WEBD_AUTH_DB_IDLE_TIMEOUT" in validation

auth_gate = between(WEB, "/* ── All remaining routes require Bearer token",
                    "/* ── Permission check")
assert "WEBD_AUTH_DB_IDLE_TIMEOUT" in auth_gate
assert "WEBD_SESSION_IDLE_ERROR" in auth_gate
assert "http_send_json(fd, 401" in auth_gate

ws = between(WEB, "static void webd_realtime_ws_session",
             "static int webd_safe_token")
assert "jmx_app_validate_token_mode(req->auth_token" in ws
assert "&token_state, 0" in ws
assert "WEBD_SESSION_IDLE_ERROR" in ws

sse = between(WEB, "#define MAX_SSE_CLIENTS", "/* ═════════",)
assert "g_sse_tokens" in sse
assert "webd_sse_auth_timer_cb" in sse
assert "jmx_app_validate_token_mode(" in sse
assert "g_sse_tokens[i], &token_state, 0" in sse
assert "web_session_idle_timeout" in sse

basic = between(WEB, "static void webd_system_basic_attach_auth_state",
                "static void webd_system_settings_scrub_sensitive")
assert "webd_session_idle_timeout_get(" in basic
assert '"web_login_timeout_min"' in basic
assert '"web_login_timeout"' in basic

preflight = between(WEB, "static struct json_object *webd_system_settings_admin_preflight",
                    "#define WEBD_ADMIN_AVATAR_SNAPSHOT_FILES")
assert '"web_login_timeout_min"' in preflight
assert "WEBD_SESSION_IDLE_MIN_MIN" in preflight
assert "WEBD_SESSION_IDLE_MAX_MIN" in preflight
assert '"invalid_web_login_timeout"' in preflight

transaction = between(WEB, "static struct json_object *webd_system_settings_transaction_response",
                      "static struct json_object *webd_system_settings_save_response")
assert '"system_settings"' in transaction
assert '"admin_avatar"' in transaction
assert '"web_login_timeout"' in transaction
assert '"admin_identity"' in transaction
assert "WEBD_ADMIN_TXN_IRREVERSIBLE" in transaction
assert "webd_admin_txn_execute(" in transaction
assert "identity_ctx.compensation_failed" in transaction
assert "WEBD_ADMIN_TXN_ROLLBACK_FAILED" in transaction

identity = between(WEB, "static int webd_admin_identity_apply_cb",
                   "static struct json_object *webd_admin_transaction_error_response")
assert 'sqlite3_exec(g_config_db, "BEGIN IMMEDIATE"' in identity
assert 'PRAGMA defer_foreign_keys=ON' in identity
assert 'sqlite3_exec(g_app_db, "BEGIN IMMEDIATE"' in identity
assert "UPDATE web_sessions SET revoked=1" in identity
assert "webd_admin_identity_config_restore(ctx)" in identity
assert "ctx->compensation_failed = 1" in identity

save = between(WEB, "static struct json_object *webd_system_settings_save_response",
               "static struct json_object *webd_capabilities_data")
assert save.index("webd_system_settings_admin_preflight(") < save.index(
    "webd_system_settings_transaction_response("
)
assert save.index("webd_system_settings_transaction_response(") < save.index(
    'webd_system_settings_core_payload(body)'
)

print("ok: Web idle sessions and administrator compensation transaction are wired end to end")
