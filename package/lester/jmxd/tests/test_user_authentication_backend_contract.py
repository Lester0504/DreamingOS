#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DB = (SRC / "authd/authd_db.c").read_text(encoding="utf-8")
WRITE = (SRC / "authd/authd_write.c").read_text(encoding="utf-8")
UBUS = (SRC / "authd/authd_ubus.c").read_text(encoding="utf-8")
WEBD = (SRC / "webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (SRC / "webd/jmx_app_perms.c").read_text(encoding="utf-8")
INIT = (SRC / "init/dreamingwrt_init.c").read_text(encoding="utf-8")
STATUS = (SRC / "jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
SRC_MAKE = (SRC / "Makefile").read_text(encoding="utf-8")
PKG_MAKE = (ROOT / "Makefile").read_text(encoding="utf-8")


TABLES = (
    "authentication_settings",
    "authentication_portal",
    "authentication_access_rules",
    "authentication_packages",
    "authentication_accounts",
    "authentication_account_sources",
    "authentication_ledger",
    "authentication_vouchers",
    "authentication_sessions",
    "authentication_delegated_services",
    "authentication_notifications",
    "authentication_notification_schedules",
)

ROUTES = {
    "/api/v1/authentication": "aggregate_get",
    "/api/v1/authentication/web": "web_get",
    "/api/v1/authentication/online-users": "online_users_get",
    "/api/v1/authentication/accounts": "accounts_get",
    "/api/v1/authentication/ledger": "ledger_get",
    "/api/v1/authentication/packages": "packages_get",
    "/api/v1/authentication/vouchers": "vouchers_get",
    "/api/v1/authentication/delegated-services": "delegated_get",
    "/api/v1/authentication/notifications": "notifications_get",
}


def test_real_daemon_package_and_supervisor_integration() -> None:
    for name in ("authd_main.c", "authd_common.c", "authd_db.c", "authd_write.c", "authd_html.c", "authd_ubus.c", "authd_internal.h"):
        assert (SRC / "authd" / name).is_file()
    assert "AUTHD_EXEC := dreamingwrt-authd" in SRC_MAKE
    assert "$(AUTHD_EXEC): $(AUTHD_OBJS)" in SRC_MAKE
    assert "AUTHD_LIBS ?=" in SRC_MAKE and "-lm" in SRC_MAKE.split("AUTHD_LIBS ?=", 1)[1].splitlines()[0]
    assert "-lxml2" in SRC_MAKE and "AUTHD_CFLAGS" in SRC_MAKE
    assert "+libxml2" in PKG_MAKE and "+libiconv-full" in PKG_MAKE
    assert "-L$(STAGING_DIR)/usr/lib/libiconv-full/lib" in PKG_MAKE
    assert "-liconv" in PKG_MAKE and "-liconv" in SRC_MAKE
    assert "JMXD_AUTHD_LIBS" in PKG_MAKE
    assert "define Package/dreamingwrt-authd" in PKG_MAKE
    assert "$(eval $(call BuildPackage,dreamingwrt-authd))" in PKG_MAKE
    assert 'name = "dreamingwrt-authd"' in INIT
    assert 'path = "/usr/bin/dreamingwrt-authd"' in INIT
    assert '{ "authd", "dreamingwrt.authd" }' in STATUS
    assert (ROOT / "tests/authd_html_sanitize_harness.c").is_file()
    assert (ROOT / "tests/test_authd_html_sanitizer.sh").is_file()


def test_schema_is_owned_by_config_db_without_global_user_version_collision() -> None:
    assert '#define AUTHD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"' in (
        SRC / "authd/authd_internal.h"
    ).read_text(encoding="utf-8")
    for table in TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {table}" in DB
    assert "authentication_schema_meta" in DB
    assert "PRAGMA user_version=" not in DB
    assert "SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX" in DB
    assert "sqlite3_busy_timeout(g_authd_db, 5000)" in DB


def test_phase_one_capabilities_are_honest() -> None:
    common = (SRC / "authd/authd_common.c").read_text(encoding="utf-8")
    assert '"read", json_object_new_boolean(1)' in common
    for capability in (
        "extend_session",
        "disconnect",
        "portal_runtime",
        "radius_accounting",
        "radius_disconnect",
        "websocket_sessions",
    ):
        assert f'"{capability}", json_object_new_boolean(0)' in common
    # The account-management group is no longer hardcoded: every underlying
    # write is implemented and reachable, so these follow whether the account
    # store is actually writable. Pinning them to a literal made the honest
    # dynamic form fail the "honesty" test, which is backwards. Assert the
    # binding instead, plus the reason published when it is false.
    for capability in ("write_accounts", "account_crud", "package_crud",
                       "voucher_crud", "account_bulk", "account_import"):
        assert f'"{capability}", json_object_new_boolean(accounts_writable)' in common, (
            f"{capability} must follow account-store writability, not a literal"
        )
    assert '"write_accounts_reason"' in common
    assert '"account_store_not_writable"' in common
    assert "static int authd_accounts_writable(void)" in common
    for capability in ("voucher_one_time_reveal", "password_policy_write", "ledger_write",
                       "update_web", "web_config_write", "portal_config_write", "access_rule_crud",
                       "write_delegated", "delegated_crud", "delegated_import",
                       "write_notifications", "notification_config_write",
                       "notification_periodic_crud", "notification_rich_text_sanitization"):
        assert f'"{capability}", json_object_new_boolean(1)' in common
    for capability in ("portal_runtime", "portal_publish", "portal_asset_upload",
                       "notification_delivery"):
        assert f'"{capability}", json_object_new_boolean(0)' in common
    assert '"notification_preview", json_object_new_boolean(1)' in common


def test_ubus_and_authenticated_read_routes_are_complete() -> None:
    assert 'UBUS_OBJECT_TYPE("dreamingwrt.authd"' in UBUS
    for path, method in ROUTES.items():
        assert f'!strcmp(req.path, "{path}")' in WEBD
        assert f'app_ubus_object_or_error("dreamingwrt.authd", "{method}"' in WEBD
        assert f'{{ "{path}"' in PERMS
    assert 'webd_query_get(req.query, "limit"' in WEBD
    assert 'webd_query_get(req.query, "offset"' in WEBD
    assert "AUTHD_MAX_LIMIT 500" in (SRC / "authd/authd_internal.h").read_text(encoding="utf-8")


def test_read_models_never_serialize_secret_material() -> None:
    assert '"has_password"' in DB
    assert '"has_code"' in DB
    assert 'SELECT id,username,display_name' in DB
    assert 'SELECT id,batch_id,display_hint' in DB
    assert 'SELECT id,line_name,username,interface' in DB
    forbidden_output_keys = (
        'json_object_object_add(item, "password_hash"',
        'json_object_object_add(item, "password_cipher"',
        'json_object_object_add(item, "code_digest"',
        'json_object_object_add(item, "code_cipher"',
        'json_object_object_add(item, "secret_cipher"',
        'json_object_object_add(portal, "secret_config_cipher"',
    )
    for needle in forbidden_output_keys:
        assert needle not in DB


def test_aggregate_shape_and_empty_state_are_stable() -> None:
    for key in (
        "web",
        "online_users",
        "account_management",
        "delegated",
        "notifications",
        "aggregate_limit",
        "aggregate_truncated",
    ):
        assert f'"{key}"' in DB
    assert '"packages"' in DB
    assert '"accounts"' in DB
    assert '"password_policy"' in DB
    assert '"ledger"' in DB
    assert '"vouchers"' in DB
    assert '"services"' in DB
    assert '"online"' in DB
    assert '"realtime"' in DB
    assert '"periodic"' in DB
    assert '"expiry"' in DB
    assert '"expired"' in DB


def test_account_package_and_voucher_writes_keep_secret_boundaries() -> None:
    for method in (
        "package_upsert", "package_delete", "account_upsert", "account_delete",
        "voucher_create", "voucher_update", "voucher_delete", "vouchers_expired_delete",
    ):
        assert f'UBUS_METHOD_NOARG("{method}"' in UBUS
    assert "PKCS5_PBKDF2_HMAC" in WRITE
    assert "AUTHD_PASSWORD_ITERATIONS 210000" in WRITE
    assert "RAND_bytes" in WRITE
    assert "RAND_priv_bytes" in WRITE
    assert "HMAC(EVP_sha256()" in WRITE
    assert 'AUTHD_SECRET_KEY_PATH "/etc/dreamingwrt/authd.key"' in (
        SRC / "authd/authd_internal.h"
    ).read_text(encoding="utf-8")
    assert "O_NOFOLLOW" in WRITE
    assert "O_DIRECTORY" in WRITE
    assert "0600" in WRITE
    assert "idx_auth_voucher_digest" in DB
    assert "code_cipher,''," not in WRITE
    assert 'json_object_object_add(item, "code"' in WRITE
    assert 'json_object_object_add(item, "code"' not in DB
    for forbidden in (
        'json_object_object_add(item, "password_hash"',
        'json_object_object_add(item, "code_digest"',
        'json_object_object_add(item, "code_cipher"',
    ):
        assert forbidden not in DB
    assert "package_in_use" in WRITE
    assert "account_has_active_sessions" in WRITE
    assert "BEGIN IMMEDIATE" in WRITE and "ROLLBACK" in WRITE and "COMMIT" in WRITE
    assert "authd_accounts_bulk" in WRITE
    assert "authd_accounts_import" in WRITE
    assert "authd_password_policy_set" in WRITE
    assert "authd_ledger_upsert" in WRITE
    assert "authd_ledger_delete" in WRITE
    assert "account_username" in DB and "account_display_name" in DB
    assert "amount_minor" in WRITE and "llround(value * 100.0)" in WRITE
    assert 'json_object_object_add(item, "amount", json_object_new_string(amount))' in DB
    assert "authd_web_set" in WRITE and "authd_portal_set" in WRITE
    assert "authd_access_rule_upsert" in WRITE and "authd_access_rule_delete" in WRITE
    assert "EVP_aes_256_gcm" in WRITE and '"v1:%s:%s:%s"' in WRITE
    assert "config_json" in DB and "secret_config_cipher" in DB
    assert 'json_object_object_add(web, "has_guest_password"' in DB
    assert 'json_object_object_add(web, "guest_password"' not in DB
    assert WRITE.count('"reset_to_defaults"') >= 3
    assert 'default_minutes *= 60' in WRITE and 'default_minutes *= 1440' in WRITE
    assert 'expiration_value /= 60' in DB and 'expiration_value /= 1440' in DB
    assert "authd_delegated_upsert" in WRITE and "authd_delegated_delete" in WRITE
    assert "authd_delegated_import" in WRITE
    delegated_import = WRITE[WRITE.index("struct json_object *authd_delegated_import"):WRITE.index(
        "static int authd_ledger_account_snapshot"
    )]
    assert '"BEGIN IMMEDIATE"' in delegated_import
    assert '"ROLLBACK"' in delegated_import and '"COMMIT"' in delegated_import
    assert 'json_object_object_add(data, "dry_run"' in delegated_import
    assert '"pending_runtime"' in WRITE
    assert '"delegated_runtime_apply", json_object_new_boolean(0)' in (
        SRC / "authd/authd_common.c"
    ).read_text(encoding="utf-8")
    assert "SELECT id FROM wan WHERE enabled=1" in WRITE
    assert 'json_object_object_add(item, "password_cipher"' not in DB
    for method in ("delegated_upsert", "delegated_delete", "delegated_import"):
        assert f'UBUS_METHOD_NOARG("{method}"' in UBUS
    assert '/api/v1/authentication/delegated-services/import' in WEBD
    assert WEBD.index('/api/v1/authentication/delegated-services/import') < WEBD.index(
        '!strncmp(req.path, "/api/v1/authentication/delegated-services/"'
    )
    html = (SRC / "authd/authd_html.c").read_text(encoding="utf-8")
    assert "htmlReadMemory" in html and "HTML_PARSE_NONET" in html
    assert '"script"' in html and '"style"' in html
    assert '"javascript:"' not in html
    assert "authd_html_href_ok" in html and '"https://"' in html and '"http://"' in html
    assert "authd_notification_set" in WRITE
    assert "authd_notification_preview" in WRITE
    assert "authd_notification_schedule_upsert" in WRITE
    assert "authd_notification_schedule_delete" in WRITE
    assert "authd_public_address_ok" in WRITE
    assert "authd_html_sanitize" in WRITE
    assert "json_object_object_foreach(audience, key, value)" in DB
    assert "json_object_object_foreach(schedule, key, value)" in DB
    assert "json_object_object_foreach(content, key, value)" in DB
    for method in ("notification_set", "notification_preview", "notification_schedule_upsert", "notification_schedule_delete"):
        assert f'UBUS_METHOD_NOARG("{method}"' in UBUS
    for route in (
        "/api/v1/authentication/notifications/realtime",
        "/api/v1/authentication/notifications/expiry",
        "/api/v1/authentication/notifications/expired",
        "/api/v1/authentication/notifications/periodic",
        "/api/v1/authentication/notifications/preview",
    ):
        assert route in WEBD and route in PERMS
    assert '"authentication-notification-preview.v1"' in WRITE
    assert '"delivery_attempted", json_object_new_boolean(0)' in WRITE
    assert '"captive_portal_session_delivery_pending"' in WRITE
    assert 'app_ubus_object_or_error("dreamingwrt.authd", "notification_preview"' in WEBD
    assert '{ "/api/v1/authentication/notifications/preview", "POST", JMX_RISK_LOW }' in PERMS
    assert '!strcmp(code_s, "notification_not_found")' in WEBD
    for method in ("portal_get", "web_set", "portal_set", "access_rule_upsert", "access_rule_delete"):
        assert f'UBUS_METHOD_NOARG("{method}"' in UBUS
    for route in (
        "/api/v1/authentication/web/portal",
        "/api/v1/authentication/web/access-rules",
    ):
        assert route in WEBD and route in PERMS
    assert '"reset_to_defaults"' in WRITE
    assert "password_policy_json='{}'" in WRITE
    assert '"invalid_account_batch"' in WRITE
    assert '"invalid_import_rows"' in WRITE
    assert 'count > 500' in WRITE
    assert 'if (confirm && json_object_object_get_ex(response, "data"' in WRITE
    for path, method in (
        ("packages", "package_upsert"),
        ("accounts", "account_upsert"),
        ("vouchers", "voucher_create"),
    ):
        assert f'/api/v1/authentication/{path}' in WEBD
        assert f'"{method}"' in WEBD
    assert 'json_object_object_add(owned_params, "_update", json_object_new_boolean(1))' in WEBD
    assert '"package_in_use"' in WEBD
    assert '"account_has_active_sessions"' in WEBD
    assert '"password"' not in WEBD[WEBD.index("static struct json_object *app_authentication_write"):WEBD.index("static struct json_object *app_client_rate_limit_payload")]
    for route, method in (
        ("/api/v1/authentication/accounts/bulk", "accounts_bulk"),
        ("/api/v1/authentication/accounts/import", "accounts_import"),
        ("/api/v1/authentication/accounts/password-policy", "password_policy_set"),
        ("/api/v1/authentication/ledger", "ledger_upsert"),
    ):
        assert route in WEBD and f'"{method}"' in WEBD
        assert route in PERMS
    assert WEBD.index('/api/v1/authentication/accounts/bulk') < WEBD.index(
        '!strncmp(req.path, "/api/v1/authentication/accounts/"'
    )
    assert 'UBUS_METHOD_NOARG("ledger_get"' in UBUS
    assert 'UBUS_METHOD_NOARG("ledger_upsert"' in UBUS
    assert 'UBUS_METHOD_NOARG("ledger_delete"' in UBUS
    assert '/api/v1/authentication/ledger/' in WEBD


if __name__ == "__main__":
    test_real_daemon_package_and_supervisor_integration()
    test_schema_is_owned_by_config_db_without_global_user_version_collision()
    test_phase_one_capabilities_are_honest()
    test_ubus_and_authenticated_read_routes_are_complete()
    test_read_models_never_serialize_secret_material()
    test_aggregate_shape_and_empty_state_are_stable()
    test_account_package_and_voucher_writes_keep_secret_boundaries()
    print("ok: authd schema, package, supervisor, ubus, REST, capability, and secret boundaries")
