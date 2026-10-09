// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * API-Key management subsystem (Phase 6W).
 *
 * The whole webd_api_key_* / webd_api_keys_* handler-definition subsystem — the
 * api_keys table row serialiser (digest withheld), the management capabilities
 * probe, the list/create/revoke/delete/audit response builders, the name/id
 * validators, and the /api/v1/auth/api-keys/<id>/<suffix> path-id extractor.
 * Lifted verbatim out of jmx_app_api.c.
 *
 * handle_client reaches this subsystem only via response builders it DISPATCHES
 * (list, create, revoke, delete, audit) plus the path-id helper used in the
 * route match — none are jmx_api_route table rows — so no route moved. They are
 * declared in api_keys_internal.h.
 *
 * app_prepare (borrowed, def stays in main) and g_app_db (the app-db handle,
 * owned by main) come from api_keys_internal.h, as do the four non-static
 * identity/parse/config helpers. jmx_role_t (jmx_app_perms.h) and the sqlite3
 * types (<sqlite3.h>) are included below, before api_keys_internal.h, so its
 * declarations resolve under the same include-order discipline main uses.
 *
 * This file is a pure extraction: no behaviour changed, no route moved.
 */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <openssl/crypto.h>

#include "webd_http_req.h"
#include "../jmx_app_perms.h"
#include "../webd_api_keys.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_keys_internal.h"

/* ── API-Key management (session administrators only) ── */

/*
 * One row of the api_keys table, without the digest.
 *
 * key_hash never leaves the database: it is not needed by any UI, and shipping
 * it would turn a read-only management call into an offline attack target.
 */
static struct json_object *webd_api_key_row_json(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *c;
    int64_t revoked_at = sqlite3_column_int64(st, 6);
    int64_t expires_at = sqlite3_column_int64(st, 5);
    int64_t now = (int64_t)time(NULL);

    c = (const char *)sqlite3_column_text(st, 0);
    webd_obj_add_str(o, "key_id", c ? c : "");
    c = (const char *)sqlite3_column_text(st, 1);
    webd_obj_add_str(o, "name", c ? c : "");
    c = (const char *)sqlite3_column_text(st, 2);
    webd_obj_add_str(o, "tier", c ? c : "read_only");
    c = (const char *)sqlite3_column_text(st, 3);
    webd_obj_add_str(o, "scope_json", c ? c : "");
    c = (const char *)sqlite3_column_text(st, 4);
    webd_obj_add_str(o, "allow_ips", c ? c : "");
    json_object_object_add(o, "expires_at", json_object_new_int64(expires_at));
    json_object_object_add(o, "revoked_at", json_object_new_int64(revoked_at));
    json_object_object_add(o, "created_at",
                           json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_object_add(o, "last_used_at",
                           json_object_new_int64(sqlite3_column_int64(st, 8)));
    c = (const char *)sqlite3_column_text(st, 9);
    webd_obj_add_str(o, "last_used_ip", c ? c : "");
    json_object_object_add(o, "use_count",
                           json_object_new_int64(sqlite3_column_int64(st, 10)));
    c = (const char *)sqlite3_column_text(st, 11);
    webd_obj_add_str(o, "created_by", c ? c : "");
    json_object_object_add(o, "revoked", json_object_new_boolean(revoked_at > 0));
    json_object_object_add(o, "expired",
                           json_object_new_boolean(expires_at > 0 && now >= expires_at));
    /* Derived so the UI does not have to reimplement the same three-way test
     * and drift from the server's view of the same row. */
    webd_obj_add_str(o, "state", revoked_at > 0 ? "revoked" :
                     (expires_at > 0 && now >= expires_at) ? "expired" : "active");
    return o;
}

/*
 * Capabilities for the API-Key manager, resolved against the CALLER's role
 * rather than written as constant true.
 *
 * The route table classifies the subtree as GET=medium, write=high
 * (jmx_app_perms.c:73-75), so admin can read the list but only owner can mint,
 * revoke or delete. Reporting create=true to an admin would light the button up
 * for a request the router then answers 403: the same "capability lies about
 * the backend" failure as reporting false while the POST route exists.
 */
static void webd_api_keys_add_capabilities(struct json_object *data,
                                           jmx_role_t role)
{
    struct json_object *cap = json_object_new_object();
    int can_read  = jmx_perm_check(role, JMX_RISK_MEDIUM);
    int can_write = jmx_perm_check(role, JMX_RISK_HIGH);

    json_object_object_add(cap, "read", json_object_new_boolean(can_read));
    json_object_object_add(cap, "create", json_object_new_boolean(can_write));
    json_object_object_add(cap, "revoke", json_object_new_boolean(can_write));
    json_object_object_add(cap, "delete", json_object_new_boolean(can_write));
    /* Audit is a GET on the same subtree, so it follows the read risk. */
    json_object_object_add(cap, "audit", json_object_new_boolean(can_read));
    /*
     * Tiers the create route actually accepts. webd_api_key_tier_parse()
     * refuses anything else, "admin" included, so the UI must build its
     * options from this list instead of a hand-kept table that can drift.
     */
    struct json_object *tiers = json_object_new_array();
    json_object_array_add(tiers, json_object_new_string("read_only"));
    json_object_array_add(tiers, json_object_new_string("control"));
    json_object_object_add(cap, "tiers", tiers);
    json_object_object_add(cap, "plaintext_shown_once", json_object_new_boolean(1));
    json_object_object_add(cap, "create_endpoint",
                           json_object_new_string("/api/v1/auth/api-keys"));
    json_object_object_add(cap, "revoke_endpoint",
                           json_object_new_string("/api/v1/auth/api-keys/{key_id}/revoke"));
    json_object_object_add(cap, "audit_endpoint",
                           json_object_new_string("/api/v1/auth/api-keys/{key_id}/audit"));
    /* So the UI can say WHY the button is disabled instead of guessing. */
    json_object_object_add(cap, "write_min_role", json_object_new_string("owner"));
    if (!can_write)
        webd_obj_add_str(cap, "create_reason",
                         "api key create/revoke/delete is a high risk action and "
                         "is limited to the owner role");
    json_object_object_add(data, "capabilities", cap);
}

struct json_object *webd_api_keys_list_response(jmx_role_t role,
                                                       int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = app_prepare(
        "SELECT key_id,name,tier,scope_json,allow_ips,expires_at,revoked_at,"
        "created_at,last_used_at,last_used_ip,use_count,created_by "
        "FROM api_keys ORDER BY created_at DESC");

    if (!st) {
        json_object_put(data);
        json_object_put(items);
        if (http_status) *http_status = 500;
        return webd_error("api_key_store_unavailable", "api key store is unavailable",
                          "apid.db:api_keys", "webd.api_key");
    }
    while (sqlite3_step(st) == SQLITE_ROW)
        json_object_array_add(items, webd_api_key_row_json(st));
    sqlite3_finalize(st);
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "total",
                           json_object_new_int((int)json_object_array_length(items)));
    webd_obj_add_str(data, "source", "apid.db:api_keys");
    webd_api_keys_add_capabilities(data, role);
    if (http_status) *http_status = 200;
    return webd_envelope(data, "webd.api_key");
}

/* Name is used in the UI and in audit context, so it is restricted to a plain
 * label rather than escaped later at every render site. */
static int webd_api_key_name_ok(const char *name)
{
    size_t i;

    if (!name || !name[0] || strlen(name) > WEBD_API_KEY_NAME_MAX)
        return 0;
    for (i = 0; name[i]; i++) {
        unsigned char c = (unsigned char)name[i];

        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != ' ')
            return 0;
    }
    return 1;
}

struct json_object *webd_api_keys_create_response(struct json_object *body,
                                                         const char *created_by,
                                                         char *key_id_out,
                                                         size_t key_id_out_len,
                                                         int *http_status)
{
    const char *name = app_nc_json_str(body, "name", "");
    const char *tier_s = app_nc_json_str(body, "tier", "read_only");
    const char *scope_json = app_nc_json_str(body, "scope_json", "");
    const char *allow_ips = app_nc_json_str(body, "allow_ips", "");
    int64_t expires_at = app_nc_json_int64(body, "expires_at", 0);
    webd_api_key_tier_t tier;
    char plain[WEBD_API_KEY_PLAIN_MAX];
    char reason[64] = "";
    struct json_object *data;
    int api_key_create_denied = 0;

    if (webd_identity_is_user(created_by)) {
        sqlite3_stmt *policy = config_prepare(
            "SELECT api_key_create_denied FROM web_users WHERE username=?1");
        int policy_rc;

        if (!policy) {
            if (http_status) *http_status = 500;
            return webd_error("api_key_create_policy_unavailable",
                              "api key creation policy is unavailable",
                              "config.db:web_users", "webd.api_key");
        }
        sqlite3_bind_text(policy, 1, webd_identity_username(created_by),
                          -1, SQLITE_TRANSIENT);
        policy_rc = sqlite3_step(policy);
        if (policy_rc == SQLITE_ROW)
            api_key_create_denied = sqlite3_column_int(policy, 0) != 0;
        sqlite3_finalize(policy);
        if (policy_rc != SQLITE_ROW) {
            if (http_status) *http_status = 500;
            return webd_error("api_key_create_policy_unavailable",
                              "api key creation policy is unavailable",
                              "config.db:web_users", "webd.api_key");
        }
        if (api_key_create_denied) {
            if (http_status) *http_status = 403;
            return webd_error("api_key_create_denied_for_user",
                              "this user is not allowed to create API keys",
                              webd_identity_username(created_by), "webd.api_key");
        }
    }

    if (!webd_api_key_name_ok(name)) {
        if (http_status) *http_status = 400;
        return webd_error("invalid_name",
                          "name is required and may contain letters, digits, space, - _ .",
                          "name", "webd.api_key");
    }
    if (webd_api_key_tier_parse(tier_s, &tier) != 0) {
        if (http_status) *http_status = 400;
        return webd_error("invalid_tier", "tier must be read_only or control",
                          "tier", "webd.api_key");
    }
    if (webd_api_key_scope_valid(scope_json, reason, sizeof(reason)) != 0) {
        if (http_status) *http_status = 400;
        return webd_error(reason[0] ? reason : "invalid_scope",
                          "scope_json is not a usable scope document",
                          "scope_json", "webd.api_key");
    }
    if (webd_api_key_allow_ips_valid(allow_ips, reason, sizeof(reason)) != 0) {
        if (http_status) *http_status = 400;
        return webd_error(reason[0] ? reason : "invalid_allow_ips",
                          "allow_ips must be a comma separated list of addresses or CIDRs",
                          "allow_ips", "webd.api_key");
    }
    /* A past expiry would store a key that can never authenticate, which reads
     * in the UI as "created but broken". */
    if (expires_at > 0 && expires_at <= (int64_t)time(NULL)) {
        if (http_status) *http_status = 400;
        return webd_error("expires_at_in_past", "expires_at must be in the future",
                          "expires_at", "webd.api_key");
    }
    if (webd_api_key_create(g_app_db, name, tier, scope_json, allow_ips,
                            expires_at, created_by, plain, sizeof(plain),
                            key_id_out, key_id_out_len) != 0) {
        OPENSSL_cleanse(plain, sizeof(plain));
        if (http_status) *http_status = 500;
        return webd_error("api_key_create_failed", "the api key could not be created",
                          "apid.db:api_keys", "webd.api_key");
    }
    data = json_object_new_object();
    webd_obj_add_str(data, "key_id", key_id_out);
    webd_obj_add_str(data, "name", name);
    webd_obj_add_str(data, "tier", webd_api_key_tier_str(tier));
    json_object_object_add(data, "expires_at", json_object_new_int64(expires_at));
    /*
     * The only time the plaintext is ever returned. It is not stored, not
     * logged, and cannot be re-read, so the UI must tell the user to copy it now.
     */
    webd_obj_add_str(data, "api_key", plain);
    json_object_object_add(data, "plaintext_shown_once", json_object_new_boolean(1));
    OPENSSL_cleanse(plain, sizeof(plain));
    if (http_status) *http_status = 200;
    return webd_envelope(data, "webd.api_key");
}

/* Key ids are generated hex; validating the shape keeps a malformed path
 * segment out of the store lookups entirely. */
static int webd_api_key_id_ok(const char *key_id)
{
    size_t i;

    if (!key_id || strlen(key_id) != WEBD_API_KEY_ID_LEN)
        return 0;
    for (i = 0; key_id[i]; i++) {
        if (!isxdigit((unsigned char)key_id[i]))
            return 0;
    }
    return 1;
}

struct json_object *webd_api_keys_revoke_response(const char *key_id,
                                                         int *http_status)
{
    struct json_object *data;
    int rc;

    if (!webd_api_key_id_ok(key_id)) {
        if (http_status) *http_status = 400;
        return webd_error("invalid_key_id", "key_id is invalid", "key_id",
                          "webd.api_key");
    }
    if (!webd_api_key_exists(g_app_db, key_id)) {
        if (http_status) *http_status = 404;
        return webd_error("api_key_not_found", "the api key was not found",
                          "key_id", "webd.api_key");
    }
    rc = webd_api_key_revoke(g_app_db, key_id, (int64_t)time(NULL));
    if (rc < 0) {
        if (http_status) *http_status = 500;
        return webd_error("api_key_revoke_failed", "the api key could not be revoked",
                          "apid.db:api_keys", "webd.api_key");
    }
    data = json_object_new_object();
    webd_obj_add_str(data, "key_id", key_id);
    webd_obj_add_str(data, "state", "revoked");
    /* Distinguishes "revoked now" from "already revoked" so a repeated click
     * does not read as a fresh action in the UI. */
    json_object_object_add(data, "already_revoked", json_object_new_boolean(rc == 1));
    if (http_status) *http_status = 200;
    return webd_envelope(data, "webd.api_key");
}

struct json_object *webd_api_keys_delete_response(const char *key_id,
                                                         int *http_status)
{
    struct json_object *data;

    if (!webd_api_key_id_ok(key_id)) {
        if (http_status) *http_status = 400;
        return webd_error("invalid_key_id", "key_id is invalid", "key_id",
                          "webd.api_key");
    }
    if (webd_api_key_delete(g_app_db, key_id) != 0) {
        if (http_status) *http_status = 404;
        return webd_error("api_key_not_found", "the api key was not found",
                          "key_id", "webd.api_key");
    }
    data = json_object_new_object();
    webd_obj_add_str(data, "key_id", key_id);
    webd_obj_add_str(data, "state", "deleted");
    if (http_status) *http_status = 200;
    return webd_envelope(data, "webd.api_key");
}

/*
 * Audit history for one key.
 *
 * Deleting a key does not delete its trail, so this reads api_audit_log by
 * api_key_id and works for ids that no longer have a row in api_keys.
 */
struct json_object *webd_api_keys_audit_response(const char *key_id,
                                                        const struct http_req *req,
                                                        int *http_status)
{
    struct json_object *data, *items;
    sqlite3_stmt *st;
    char limit_s[16] = "";
    char offset_s[16] = "";
    int limit = 100, offset = 0;

    if (!webd_api_key_id_ok(key_id)) {
        if (http_status) *http_status = 400;
        return webd_error("invalid_key_id", "key_id is invalid", "key_id",
                          "webd.api_key");
    }
    if (req && webd_query_get(req->query, "limit", limit_s, sizeof(limit_s)))
        app_parse_positive_int_segment(limit_s, &limit);
    if (req && webd_query_get(req->query, "offset", offset_s, sizeof(offset_s)))
        app_parse_positive_int_segment(offset_s, &offset);
    if (limit <= 0 || limit > 500)
        limit = 100;
    if (offset < 0)
        offset = 0;
    st = app_prepare(
        "SELECT ts,action,target,result,failure_reason,risk,source_ip,peer_ip,"
        "ip_source,user_agent FROM api_audit_log WHERE api_key_id=?1 "
        "ORDER BY ts DESC, id DESC LIMIT ?2 OFFSET ?3");
    if (!st) {
        if (http_status) *http_status = 500;
        return webd_error("audit_query_failed", "the audit trail is unavailable",
                          "apid.db:api_audit_log", "webd.api_key");
    }
    sqlite3_bind_text(st, 1, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, limit);
    sqlite3_bind_int(st, 3, offset);
    data = json_object_new_object();
    items = json_object_new_array();
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        const char *c;

        json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(st, 0)));
        c = (const char *)sqlite3_column_text(st, 1);
        webd_obj_add_str(o, "action", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 2);
        webd_obj_add_str(o, "target", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 3);
        webd_obj_add_str(o, "result", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 4);
        webd_obj_add_str(o, "failure_reason", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 5);
        webd_obj_add_str(o, "risk", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 6);
        webd_obj_add_str(o, "source_ip", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 7);
        webd_obj_add_str(o, "peer_ip", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 8);
        webd_obj_add_str(o, "ip_source", c ? c : "");
        /*
         * Returned raw and JSON-encoded. The client must treat it as text, not
         * markup: it is caller-supplied and rendering it as HTML would turn the
         * audit view into a stored XSS sink aimed at an administrator.
         */
        c = (const char *)sqlite3_column_text(st, 9);
        webd_obj_add_str(o, "user_agent", c ? c : "");
        json_object_array_add(items, o);
    }
    sqlite3_finalize(st);
    json_object_object_add(data, "items", items);
    webd_obj_add_str(data, "key_id", key_id);
    json_object_object_add(data, "limit", json_object_new_int(limit));
    json_object_object_add(data, "offset", json_object_new_int(offset));
    json_object_object_add(data, "count",
                          json_object_new_int((int)json_object_array_length(items)));
    webd_obj_add_str(data, "source", "apid.db:api_audit_log");
    if (http_status) *http_status = 200;
    return webd_envelope(data, "webd.api_key");
}

/*
 * Extracts the id from /api/v1/auth/api-keys/<id>/<suffix>.
 *
 * Written as a helper rather than pointer arithmetic at each call site because
 * the lengths are easy to get subtly wrong, and an underflowed length here
 * would be a memcpy over the request buffer.
 */
int webd_api_key_path_id(const char *path, const char *suffix,
                                char *out, size_t out_len)
{
    const char *base = "/api/v1/auth/api-keys/";
    size_t base_len = strlen(base);
    size_t path_len, suffix_len, id_len;

    if (!path || !suffix || !out || !out_len)
        return -1;
    path_len = strlen(path);
    suffix_len = strlen(suffix);
    if (path_len <= base_len + suffix_len)
        return -1;
    if (strncmp(path, base, base_len) != 0)
        return -1;
    if (strcmp(path + path_len - suffix_len, suffix) != 0)
        return -1;
    id_len = path_len - base_len - suffix_len;
    if (id_len >= out_len)
        return -1;
    /* One path segment only: an embedded '/' means this is a deeper route. */
    if (memchr(path + base_len, '/', id_len))
        return -1;
    memcpy(out, path + base_len, id_len);
    out[id_len] = '\0';
    return 0;
}

