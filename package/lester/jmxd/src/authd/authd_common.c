// SPDX-License-Identifier: GPL-2.0-or-later
#include "authd_internal.h"

sqlite3 *g_authd_db;
struct ubus_context *g_authd_ubus;
struct blob_buf g_authd_blob;
int64_t g_authd_started_at;

int64_t authd_now_s(void)
{
    return (int64_t)time(NULL);
}

const char *authd_sqlite_text(sqlite3_stmt *st, int col, const char *def)
{
    const unsigned char *value;

    if (!st)
        return def;
    value = sqlite3_column_text(st, col);
    return value ? (const char *)value : def;
}

struct json_object *authd_json_from_blob(struct blob_attr *msg)
{
    struct json_object *obj = NULL;
    char *text;

    if (!msg)
        return json_object_new_object();
    text = blobmsg_format_json(msg, true);
    if (text) {
        obj = json_tokener_parse(text);
        free(text);
    }
    if (!obj || !json_object_is_type(obj, json_type_object)) {
        if (obj)
            json_object_put(obj);
        obj = json_object_new_object();
    }
    return obj;
}

/*
 * Is the account store actually writable right now?
 *
 * account_upsert / account_delete / accounts_bulk / accounts_import are all
 * implemented, so the only thing that can make the write path fail is the DB
 * itself being absent or read-only (open failed, or the filesystem holding
 * config.db went read-only). Probe that instead of hardcoding the capability,
 * so the flag cannot claim a write channel that would actually error out.
 */
static int authd_accounts_writable(void)
{
    int readonly;

    if (!g_authd_db)
        return 0;
    readonly = sqlite3_db_readonly(g_authd_db, "main");
    /* -1 = no such database; treat anything but an explicit 0 as not writable */
    return readonly == 0 ? 1 : 0;
}

struct json_object *authd_capabilities_json(void)
{
    struct json_object *cap = json_object_new_object();
    int accounts_writable = authd_accounts_writable();

    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "update_web", json_object_new_boolean(1));
    json_object_object_add(cap, "web_config_write", json_object_new_boolean(1));
    json_object_object_add(cap, "portal_config_write", json_object_new_boolean(1));
    json_object_object_add(cap, "access_rule_crud", json_object_new_boolean(1));
    json_object_object_add(cap, "portal_publish", json_object_new_boolean(0));
    json_object_object_add(cap, "portal_asset_upload", json_object_new_boolean(0));
    json_object_object_add(cap, "extend_session", json_object_new_boolean(0));
    json_object_object_add(cap, "disconnect", json_object_new_boolean(0));
    /*
     * write_accounts is the umbrella flag the UI uses to enable the whole
     * account management surface. It was hardcoded 0 while every underlying
     * write (upsert/delete/bulk/import) was already implemented and reachable,
     * which made the frontend grey out a working feature.
     */
    json_object_object_add(cap, "write_accounts", json_object_new_boolean(accounts_writable));
    json_object_object_add(cap, "account_crud", json_object_new_boolean(accounts_writable));
    json_object_object_add(cap, "package_crud", json_object_new_boolean(accounts_writable));
    json_object_object_add(cap, "voucher_crud", json_object_new_boolean(accounts_writable));
    json_object_object_add(cap, "account_bulk", json_object_new_boolean(accounts_writable));
    json_object_object_add(cap, "account_import", json_object_new_boolean(accounts_writable));
    if (!accounts_writable)
        json_object_object_add(cap, "write_accounts_reason",
                               json_object_new_string("account_store_not_writable"));
    json_object_object_add(cap, "ledger_write", json_object_new_boolean(1));
    json_object_object_add(cap, "password_policy_write", json_object_new_boolean(1));
    json_object_object_add(cap, "voucher_one_time_reveal", json_object_new_boolean(1));
    json_object_object_add(cap, "accounts_runtime_auth", json_object_new_boolean(0));
    json_object_object_add(cap, "write_delegated", json_object_new_boolean(1));
    json_object_object_add(cap, "delegated_crud", json_object_new_boolean(1));
    json_object_object_add(cap, "delegated_import", json_object_new_boolean(1));
    json_object_object_add(cap, "delegated_runtime_apply", json_object_new_boolean(0));
    /*
     * The delegated interface is enumerable and optional. Without these two
     * flags the UI cannot tell "old build, keep the free-text box" from "new
     * build, render a picker", and an empty submit used to fail outright with
     * delegated_interface_not_found.
     */
    json_object_object_add(cap, "delegated_interface_options", json_object_new_boolean(1));
    json_object_object_add(cap, "delegated_interface_optional", json_object_new_boolean(1));
    json_object_object_add(cap, "write_notifications", json_object_new_boolean(1));
    json_object_object_add(cap, "notification_config_write", json_object_new_boolean(1));
    json_object_object_add(cap, "notification_periodic_crud", json_object_new_boolean(1));
    json_object_object_add(cap, "notification_rich_text_sanitization", json_object_new_boolean(1));
    json_object_object_add(cap, "notification_delivery", json_object_new_boolean(0));
    json_object_object_add(cap, "notification_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "portal_runtime", json_object_new_boolean(0));
    json_object_object_add(cap, "radius_accounting", json_object_new_boolean(0));
    json_object_object_add(cap, "radius_disconnect", json_object_new_boolean(0));
    json_object_object_add(cap, "websocket_sessions", json_object_new_boolean(0));
    return cap;
}

struct json_object *authd_envelope(struct json_object *data)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    return root;
}

struct json_object *authd_error(const char *error, const char *message)
{
    struct json_object *root = json_object_new_object();
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(error ? error : "internal_error"));
    json_object_object_add(data, "message", json_object_new_string(message ? message : "request failed"));
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "code", json_object_new_int(4000));
    json_object_object_add(root, "data", data);
    return root;
}
