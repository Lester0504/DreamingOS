// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Mobile App HTTP API (/api/v1/...)
 * Runs on uloop alongside ubus. Uses raw POSIX sockets.
 *
 * Database tables (auto-created):
 *   app_devices   — paired devices
 *   auth_tokens   — access + refresh tokens
 *   config_apply_tasks — config transaction log
 *   api_audit_log — all app operations
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jmx.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "jmx_app_api.h"
#include "jmx_app_perms.h"
#include "jmx_app_cache.h"
#include "jmx_app_cache.h"
#include "jmx_utils.h"
#include "jmx_netconfig_db.h"
#include "jmx_db.h"
#include "jmx_system.h"

/* Forward declarations for functions in jmx_netconfig_db.c */
extern int nc_dns_valid_protocol(const char *p);
extern int nc_dns_valid_rule_type(const char *t);

/* Local JSON helpers (nc_json_* are static in netconfig_db.c) */
static const char *app_nc_json_str(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    const char *s = json_object_get_string(v);
    return s ? s : def;
}
static int app_nc_json_int(struct json_object *o, const char *k, int def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int(v);
}
static int app_nc_json_bool(struct json_object *o, const char *k, int def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_boolean(v);
}

/* ═══ AI Response Envelope Helper ═══ */
static struct json_object *ai_envelope(struct json_object *resp, int default_code)
{
    if (!resp) {
        struct json_object *e = json_object_new_object();
        json_object_object_add(e, "ok", json_object_new_boolean(0));
        json_object_object_add(e, "code", json_object_new_int(default_code));
        json_object_object_add(e, "message", json_object_new_string("internal_error"));
        json_object_object_add(e, "ts", json_object_new_int64(time(NULL)));
        return e;
    }
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;
    int code = default_code;
    if (json_object_object_get_ex(resp, "code", &code_obj) && code_obj)
        code = json_object_get_int(code_obj);
    json_object_object_get_ex(resp, "data", &data_obj);
    int is_ok = 1;
    const char *msg = "";
    if (data_obj) {
        struct json_object *ok_obj = NULL;
        struct json_object *err_obj = NULL;
        if (json_object_object_get_ex(data_obj, "ok", &ok_obj) && ok_obj)
            is_ok = json_object_get_boolean(ok_obj);
        if (json_object_object_get_ex(data_obj, "error", &err_obj) && err_obj)
            msg = json_object_get_string(err_obj);
        if (!is_ok && !msg[0]) {
            struct json_object *msg_obj = NULL;
            if (json_object_object_get_ex(data_obj, "message", &msg_obj) && msg_obj)
                msg = json_object_get_string(msg_obj);
        }
    }
    struct json_object *env = json_object_new_object();
    json_object_object_add(env, "ok", json_object_new_boolean(is_ok));
    json_object_object_add(env, "code", json_object_new_int(code));
    if (msg && msg[0]) json_object_object_add(env, "message", json_object_new_string(msg));
    if (data_obj) json_object_object_add(env, "data", json_object_get(data_obj));
    json_object_object_add(env, "ts", json_object_new_int64(time(NULL)));
    json_object_put(resp);
    return env;
}

/* ══════════════════════════════════════════════════════════════════════
 * Constants
 * ══════════════════════════════════════════════════════════════════════ */

#define APP_API_DEFAULT_PORT  9898
#define APP_API_BACKLOG       8
#define APP_API_MAX_CLIENTS   16
#define APP_API_READ_BUF      16384
#define APP_API_WRITE_BUF     32768
#define TOKEN_LEN             64
#define PAIR_CODE_LEN         6
#define ACCESS_TTL_S          900     /* 15 min */
#define REFRESH_TTL_S         2592000 /* 30 days */
#define PAIR_TTL_S            300

/* ══════════════════════════════════════════════════════════════════════
 * DB helpers — reuse the same SQLite path as netconfig_db
 * ══════════════════════════════════════════════════════════════════════ */

static sqlite3 *g_app_db = NULL;

static int app_db_init(void)
{
    if (g_app_db) return 0;
    int rc = sqlite3_open("/etc/dreamingwrt/jmxd.db", &g_app_db);
    if (rc != 0) { g_app_db = NULL; return -1; }
    sqlite3_exec(g_app_db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(g_app_db, "PRAGMA foreign_keys=ON", NULL, NULL, NULL);

    /* Tables */
    sqlite3_exec(g_app_db,
        "CREATE TABLE IF NOT EXISTS app_devices ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " platform TEXT DEFAULT '',"
        " public_key TEXT DEFAULT '',"
        " paired_at INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " role TEXT NOT NULL DEFAULT 'operator',"
        " enabled INTEGER NOT NULL DEFAULT 1)",
        NULL, NULL, NULL);

    sqlite3_exec(g_app_db,
        "CREATE TABLE IF NOT EXISTS auth_tokens ("
        " token TEXT PRIMARY KEY,"
        " device_id TEXT NOT NULL,"
        " type TEXT NOT NULL DEFAULT 'access',"
        " created_at INTEGER NOT NULL,"
        " expires_at INTEGER NOT NULL,"
        " revoked INTEGER NOT NULL DEFAULT 0,"
        " FOREIGN KEY(device_id) REFERENCES app_devices(id) ON DELETE CASCADE)",
        NULL, NULL, NULL);

    sqlite3_exec(g_app_db,
        "CREATE TABLE IF NOT EXISTS config_apply_tasks ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " scope TEXT NOT NULL DEFAULT 'network',"
        " changes_json TEXT DEFAULT '{}',"
        " state TEXT NOT NULL DEFAULT 'pending',"
        " rollback_timeout INTEGER NOT NULL DEFAULT 90,"
        " started_at INTEGER NOT NULL,"
        " confirmed_at INTEGER DEFAULT 0,"
        " finished_at INTEGER DEFAULT 0,"
        " error TEXT DEFAULT '',"
        " app_device_id TEXT DEFAULT '')",
        NULL, NULL, NULL);

    sqlite3_exec(g_app_db,
        "CREATE TABLE IF NOT EXISTS api_audit_log ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ts INTEGER NOT NULL,"
        " actor TEXT DEFAULT '',"
        " app_device_id TEXT DEFAULT '',"
        " action TEXT NOT NULL,"
        " risk TEXT DEFAULT 'low',"
        " target TEXT DEFAULT '',"
        " before_hash TEXT DEFAULT '',"
        " after_hash TEXT DEFAULT '')",
        NULL, NULL, NULL);

    return 0;
}

static sqlite3_stmt *app_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (!g_app_db || sqlite3_prepare_v2(g_app_db, sql, -1, &st, NULL) != SQLITE_OK)
        return NULL;
    return st;
}

static int64_t now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

/* ══════════════════════════════════════════════════════════════════════
 * Crypto helpers
 * ══════════════════════════════════════════════════════════════════════ */

static void gen_random_hex(char *out, int len)
{
    static const char hex[] = "0123456789abcdef";
    FILE *fp = fopen("/dev/urandom", "r");
    int i;
    if (fp) {
        for (i = 0; i < len; i++) { int c = fgetc(fp); out[i] = hex[c & 0xf]; }
        fclose(fp);
    } else {
        srand((unsigned)time(NULL));
        for (i = 0; i < len; i++) out[i] = hex[rand() & 0xf];
    }
    out[len] = '\0';
}

static void gen_pair_code(char *out)
{
    FILE *fp = fopen("/dev/urandom", "r");
    int i;
    for (i = 0; i < PAIR_CODE_LEN; i++) {
        int c = fp ? fgetc(fp) : (rand() % 10);
        out[i] = '0' + (c % 10);
    }
    if (fp) fclose(fp);
    out[PAIR_CODE_LEN] = '\0';
}

/* ══════════════════════════════════════════════════════════════════════
 * Auth / Pairing
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *jmx_app_pair_init(struct json_object *req)
{
    const char *device_id = app_nc_json_str(req, "app_device_id", "");
    const char *device_name = app_nc_json_str(req, "app_device_name", "");
    const char *platform = app_nc_json_str(req, "platform", "");
    const char *pubkey = app_nc_json_str(req, "public_key", "");
    if (!device_id[0]) return NULL;

    int64_t ts = now_s();
    /* Determine role: first device becomes owner, rest are operator */
    const char *default_role = "operator";
    {
        sqlite3_stmt *cnt = app_prepare("SELECT COUNT(*) FROM app_devices");
        if (cnt) {
            if (sqlite3_step(cnt) == SQLITE_ROW && sqlite3_column_int(cnt, 0) == 0)
                default_role = "owner";
            sqlite3_finalize(cnt);
        }
    }

    sqlite3_stmt *st = app_prepare(
        "INSERT INTO app_devices(id,name,platform,public_key,paired_at,last_seen,role) "
        "VALUES(?1,?2,?3,?4,?5,?5,?6) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,platform=excluded.platform,"
        "public_key=excluded.public_key,last_seen=excluded.last_seen");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, device_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, platform, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, pubkey, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, ts);
    sqlite3_bind_text(st, 6, default_role, -1, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);

    char code[PAIR_CODE_LEN + 1];
    gen_pair_code(code);

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "pair_id", json_object_new_string(device_id));
    json_object_object_add(resp, "code", json_object_new_string(code));
    json_object_object_add(resp, "expires_in", json_object_new_int(PAIR_TTL_S));
    json_object_object_add(resp, "requires_local_confirm", json_object_new_boolean(1));
    return resp;
}

struct json_object *jmx_app_pair_confirm(struct json_object *req)
{
    const char *device_id = app_nc_json_str(req, "app_device_id", "");
    const char *code = app_nc_json_str(req, "code", "");
    (void)code; /* In v1 we accept any code; local confirm is the gate */
    if (!device_id[0]) return NULL;

    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "UPDATE app_devices SET paired_at=?1,last_seen=?1 WHERE id=?2");
    if (!st) return NULL;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);

    /* Generate tokens */
    char access_tok[TOKEN_LEN + 1], refresh_tok[TOKEN_LEN + 1];
    gen_random_hex(access_tok, TOKEN_LEN);
    gen_random_hex(refresh_tok, TOKEN_LEN);

    st = app_prepare(
        "INSERT INTO auth_tokens(token,device_id,type,created_at,expires_at) "
        "VALUES(?1,?2,'access',?3,?4)");
    if (st) {
        sqlite3_bind_text(st, 1, access_tok, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, ts);
        sqlite3_bind_int64(st, 4, ts + ACCESS_TTL_S);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    st = app_prepare(
        "INSERT INTO auth_tokens(token,device_id,type,created_at,expires_at) "
        "VALUES(?1,?2,'refresh',?3,?4)");
    if (st) {
        sqlite3_bind_text(st, 1, refresh_tok, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, ts);
        sqlite3_bind_int64(st, 4, ts + REFRESH_TTL_S);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "access_token", json_object_new_string(access_tok));
    json_object_object_add(resp, "refresh_token", json_object_new_string(refresh_tok));
    json_object_object_add(resp, "expires_in", json_object_new_int(ACCESS_TTL_S));
    json_object_object_add(resp, "device_id", json_object_new_string(device_id));
    return resp;
}

struct json_object *jmx_app_pair_cancel(struct json_object *req)
{
    const char *device_id = app_nc_json_str(req, "app_device_id", "");
    if (!device_id[0]) return NULL;
    sqlite3_stmt *st = app_prepare("DELETE FROM app_devices WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, device_id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    return resp;
}

struct json_object *jmx_app_login(struct json_object *req)
{
    const char *device_id = app_nc_json_str(req, "app_device_id", "");
    if (!device_id[0]) return NULL;

    /* Check device exists and is paired */
    sqlite3_stmt *st = app_prepare("SELECT 1 FROM app_devices WHERE id=?1 AND enabled=1");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, device_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return NULL; }
    sqlite3_finalize(st);

    int64_t ts = now_s();
    char access_tok[TOKEN_LEN + 1], refresh_tok[TOKEN_LEN + 1];
    gen_random_hex(access_tok, TOKEN_LEN);
    gen_random_hex(refresh_tok, TOKEN_LEN);

    /* Revoke old tokens for this device */
    st = app_prepare("UPDATE auth_tokens SET revoked=1 WHERE device_id=?1");
    if (st) { sqlite3_bind_text(st, 1, device_id, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st); }

    st = app_prepare("INSERT INTO auth_tokens(token,device_id,type,created_at,expires_at) VALUES(?1,?2,'access',?3,?4)");
    if (st) {
        sqlite3_bind_text(st, 1, access_tok, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, ts);
        sqlite3_bind_int64(st, 4, ts + ACCESS_TTL_S);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    st = app_prepare("INSERT INTO auth_tokens(token,device_id,type,created_at,expires_at) VALUES(?1,?2,'refresh',?3,?4)");
    if (st) {
        sqlite3_bind_text(st, 1, refresh_tok, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, ts);
        sqlite3_bind_int64(st, 4, ts + REFRESH_TTL_S);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    st = app_prepare("UPDATE app_devices SET last_seen=?1 WHERE id=?2");
    if (st) { sqlite3_bind_int64(st, 1, ts); sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st); }

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "access_token", json_object_new_string(access_tok));
    json_object_object_add(resp, "refresh_token", json_object_new_string(refresh_tok));
    json_object_object_add(resp, "expires_in", json_object_new_int(ACCESS_TTL_S));
    json_object_object_add(resp, "device_id", json_object_new_string(device_id));
    return resp;
}

struct json_object *jmx_app_refresh(struct json_object *req)
{
    const char *refresh_token = app_nc_json_str(req, "refresh_token", "");
    if (!refresh_token[0]) return NULL;

    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "SELECT device_id FROM auth_tokens WHERE token=?1 AND type='refresh' "
        "AND revoked=0 AND expires_at>?2");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, refresh_token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return NULL; }
    const char *device_id = strdup((const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);

    char access_tok[TOKEN_LEN + 1];
    gen_random_hex(access_tok, TOKEN_LEN);

    st = app_prepare("INSERT INTO auth_tokens(token,device_id,type,created_at,expires_at) VALUES(?1,?2,'access',?3,?4)");
    if (st) {
        sqlite3_bind_text(st, 1, access_tok, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, ts);
        sqlite3_bind_int64(st, 4, ts + ACCESS_TTL_S);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "access_token", json_object_new_string(access_tok));
    json_object_object_add(resp, "expires_in", json_object_new_int(ACCESS_TTL_S));
    free((void *)device_id);
    return resp;
}

struct json_object *jmx_app_logout(struct json_object *req)
{
    const char *token = app_nc_json_str(req, "access_token", "");
    if (!token[0]) return NULL;
    sqlite3_stmt *st = app_prepare("UPDATE auth_tokens SET revoked=1 WHERE token=?1");
    if (st) { sqlite3_bind_text(st, 1, token, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st); }
    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    return resp;
}

struct json_object *jmx_app_session(const char *token)
{
    if (!token || !token[0]) return NULL;
    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "SELECT t.device_id,d.name,d.platform,d.role FROM auth_tokens t "
        "JOIN app_devices d ON d.id=t.device_id "
        "WHERE t.token=?1 AND t.type='access' AND t.revoked=0 AND t.expires_at>?2");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return NULL; }

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "device_id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    json_object_object_add(resp, "device_name", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
    json_object_object_add(resp, "platform", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
    json_object_object_add(resp, "role", json_object_new_string((const char *)sqlite3_column_text(st, 3)));
    json_object_object_add(resp, "valid", json_object_new_boolean(1));
    sqlite3_finalize(st);
    return resp;
}

char *jmx_app_validate_token(const char *token)
{
    if (!token || !token[0]) return NULL;
    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "SELECT device_id FROM auth_tokens WHERE token=?1 AND type='access' "
        "AND revoked=0 AND expires_at>?2");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts);
    char *dev = NULL;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *s = (const char *)sqlite3_column_text(st, 0);
        if (s) dev = strdup(s);
    }
    sqlite3_finalize(st);
    return dev;
}

struct json_object *jmx_app_devices_list(void)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = app_prepare(
        "SELECT id,name,platform,paired_at,last_seen,role,enabled FROM app_devices ORDER BY last_seen DESC");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
            json_object_object_add(o, "name", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(o, "platform", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
            json_object_object_add(o, "paired_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
            json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 4)));
            json_object_object_add(o, "role", json_object_new_string((const char *)sqlite3_column_text(st, 5)));
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    return arr;
}

int jmx_app_device_delete(const char *id)
{
    if (!id || !id[0]) return -1;
    sqlite3_stmt *st = app_prepare("DELETE FROM app_devices WHERE id=?1");
    if (!st) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    int rc = (sqlite3_step(st) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

int jmx_app_device_set_role(const char *device_id, const char *role)
{
    if (!device_id || !device_id[0] || !role || !role[0]) return -1;
    /* Validate role */
    if (strcmp(role, "owner") && strcmp(role, "admin") &&
        strcmp(role, "operator") && strcmp(role, "viewer") && strcmp(role, "ai-agent"))
        return -2;
    sqlite3_stmt *st = app_prepare("UPDATE app_devices SET role=?1 WHERE id=?2");
    if (!st) return -1;
    sqlite3_bind_text(st, 1, role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
    int rc = (sqlite3_step(st) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * Config Transaction
 * ══════════════════════════════════════════════════════════════════════ */

static struct uloop_timeout g_rollback_timer;
static int g_pending_apply_id = 0;

static void rollback_timeout_cb(struct uloop_timeout *t)
{
    if (g_pending_apply_id <= 0) return;
    fprintf(stderr, "[app-api] auto-rollback apply task #%d\n", g_pending_apply_id);
    sqlite3_stmt *st = app_prepare(
        "UPDATE config_apply_tasks SET state='rolled_back',finished_at=?1 WHERE id=?2 AND state='pending'");
    if (st) {
        int64_t ts = now_s();
        sqlite3_bind_int64(st, 1, ts);
        sqlite3_bind_int(st, 2, g_pending_apply_id);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    /* TODO: actual rollback — for now mark as rolled back */
    g_pending_apply_id = 0;
}

struct json_object *jmx_config_apply(struct json_object *req)
{
    const char *scope = app_nc_json_str(req, "scope", "network");
    int rollback_timeout = app_nc_json_int(req, "rollback_timeout", 90);
    struct json_object *changes = NULL;
    json_object_object_get_ex(req, "changes", &changes);

    int64_t ts = now_s();
    const char *changes_str = changes ? json_object_to_json_string(changes) : "{}";

    sqlite3_stmt *st = app_prepare(
        "INSERT INTO config_apply_tasks(scope,changes_json,state,rollback_timeout,started_at) "
        "VALUES(?1,?2,'pending',?3,?4)");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, changes_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, rollback_timeout);
    sqlite3_bind_int64(st, 4, ts);
    sqlite3_step(st);
    int task_id = (int)sqlite3_last_insert_rowid(g_app_db);
    sqlite3_finalize(st);

    /* Start rollback timer */
    g_pending_apply_id = task_id;
    g_rollback_timer.cb = rollback_timeout_cb;
    uloop_timeout_set(&g_rollback_timer, rollback_timeout * 1000);

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "task_id", json_object_new_int(task_id));
    json_object_object_add(resp, "state", json_object_new_string("pending"));
    json_object_object_add(resp, "rollback_timeout", json_object_new_int(rollback_timeout));
    json_object_object_add(resp, "require_confirm", json_object_new_boolean(1));
    return resp;
}

struct json_object *jmx_config_confirm(struct json_object *req)
{
    int task_id = app_nc_json_int(req, "task_id", 0);
    if (task_id <= 0) return NULL;

    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "UPDATE config_apply_tasks SET state='confirmed',confirmed_at=?1,finished_at=?1 WHERE id=?2 AND state='pending'");
    if (!st) return NULL;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_int(st, 2, task_id);
    sqlite3_step(st);
    sqlite3_finalize(st);

    if (g_pending_apply_id == task_id) {
        uloop_timeout_cancel(&g_rollback_timer);
        g_pending_apply_id = 0;
    }

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "task_id", json_object_new_int(task_id));
    json_object_object_add(resp, "state", json_object_new_string("confirmed"));
    return resp;
}

struct json_object *jmx_config_rollback(struct json_object *req)
{
    int task_id = app_nc_json_int(req, "task_id", 0);
    if (task_id <= 0) return NULL;

    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "UPDATE config_apply_tasks SET state='rolled_back',finished_at=?1 WHERE id=?2 AND state='pending'");
    if (!st) return NULL;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_int(st, 2, task_id);
    sqlite3_step(st);
    sqlite3_finalize(st);

    if (g_pending_apply_id == task_id) {
        uloop_timeout_cancel(&g_rollback_timer);
        g_pending_apply_id = 0;
    }

    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "task_id", json_object_new_int(task_id));
    json_object_object_add(resp, "state", json_object_new_string("rolled_back"));
    return resp;
}

struct json_object *jmx_config_snapshot(struct json_object *req)
{
    (void)req;
    struct json_object *resp = json_object_new_object();
    struct json_object *snapshot = json_object_new_object();

    /* Capture current config state */
    struct json_object *wans = jmx_netconfig_wan_list();
    struct json_object *wan_data = NULL;
    if (wans && json_object_object_get_ex(wans, "data", &wan_data)) {
        struct json_object *wan_arr = NULL;
        if (json_object_object_get_ex(wan_data, "wans", &wan_arr))
            json_object_object_add(snapshot, "wans", json_object_get(wan_arr));
    }
    if (wans) json_object_put(wans);

    struct json_object *lans = jmx_netconfig_lan_list();
    struct json_object *lan_data = NULL;
    if (lans && json_object_object_get_ex(lans, "data", &lan_data)) {
        struct json_object *lan_arr = NULL;
        if (json_object_object_get_ex(lan_data, "lans", &lan_arr))
            json_object_object_add(snapshot, "lans", json_object_get(lan_arr));
    }
    if (lans) json_object_put(lans);

    struct json_object *global = jmx_netconfig_global_get();
    struct json_object *g_data = NULL;
    if (global && json_object_object_get_ex(global, "data", &g_data)) {
        struct json_object *g_obj = NULL;
        if (json_object_object_get_ex(g_data, "global", &g_obj))
            json_object_object_add(snapshot, "global", json_object_get(g_obj));
    }
    if (global) json_object_put(global);

    struct json_object *dns = jmx_dns_service_get();
    if (dns) {
        struct json_object *dns_data = NULL;
        if (json_object_object_get_ex(dns, "data", &dns_data))
            json_object_object_add(snapshot, "dns", json_object_get(dns_data));
        json_object_put(dns);
    }

    json_object_object_add(resp, "snapshot", snapshot);
    json_object_object_add(resp, "ts", json_object_new_int64(now_s()));
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    return resp;
}

struct json_object *jmx_config_validate(struct json_object *req)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *errors = json_object_new_array();
    struct json_object *changes = NULL;
    json_object_object_get_ex(req, "changes", &changes);
    int valid = 1;

    if (changes) {
        /* Validate WAN changes */
        struct json_object *wan_arr = NULL;
        if (json_object_object_get_ex(changes, "wan", &wan_arr) && json_object_is_type(wan_arr, json_type_array)) {
            int i, n = (int)json_object_array_length(wan_arr);
            for (i = 0; i < n; i++) {
                struct json_object *w = json_object_array_get_idx(wan_arr, i);
                const char *id = app_nc_json_str(w, "id", "");
                const char *device = app_nc_json_str(w, "device", "");
                if (!id[0]) {
                    struct json_object *e = json_object_new_object();
                    json_object_object_add(e, "field", json_object_new_string("wan.id"));
                    json_object_object_add(e, "reason", json_object_new_string("missing"));
                    json_object_object_add(e, "message", json_object_new_string("WAN id is required"));
                    json_object_array_add(errors, e);
                    valid = 0;
                }
                if (!device[0]) {
                    struct json_object *e = json_object_new_object();
                    json_object_object_add(e, "field", json_object_new_string("wan.device"));
                    json_object_object_add(e, "reason", json_object_new_string("missing"));
                    json_object_object_add(e, "message", json_object_new_string("WAN device is required"));
                    json_object_array_add(errors, e);
                    valid = 0;
                }
            }
        }

        /* Validate LAN changes */
        struct json_object *lan_arr = NULL;
        if (json_object_object_get_ex(changes, "lan", &lan_arr) && json_object_is_type(lan_arr, json_type_array)) {
            int i, n = (int)json_object_array_length(lan_arr);
            for (i = 0; i < n; i++) {
                struct json_object *l = json_object_array_get_idx(lan_arr, i);
                const char *id = app_nc_json_str(l, "id", "");
                if (!id[0]) {
                    struct json_object *e = json_object_new_object();
                    json_object_object_add(e, "field", json_object_new_string("lan.id"));
                    json_object_object_add(e, "reason", json_object_new_string("missing"));
                    json_object_object_add(e, "message", json_object_new_string("LAN id is required"));
                    json_object_array_add(errors, e);
                    valid = 0;
                }
            }
        }
    }

    json_object_object_add(resp, "valid", json_object_new_boolean(valid));
    json_object_object_add(resp, "errors", errors);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    return resp;
}

struct json_object *jmx_config_last_apply(void)
{
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st = app_prepare(
        "SELECT id,scope,state,rollback_timeout,started_at,confirmed_at,finished_at,error "
        "FROM config_apply_tasks ORDER BY id DESC LIMIT 1");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(resp, "task_id", json_object_new_int(sqlite3_column_int(st, 0)));
        json_object_object_add(resp, "scope", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(resp, "state", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(resp, "rollback_timeout", json_object_new_int(sqlite3_column_int(st, 3)));
        json_object_object_add(resp, "started_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(resp, "confirmed_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(resp, "finished_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(resp, "error", json_object_new_string((const char *)sqlite3_column_text(st, 7)));
    }
    if (st) sqlite3_finalize(st);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    return resp;
}

/* ══════════════════════════════════════════════════════════════════════
 * Tasks
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *jmx_tasks_list(void)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = app_prepare(
        "SELECT id,scope,state,started_at,finished_at,error FROM config_apply_tasks ORDER BY id DESC LIMIT 50");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(o, "scope", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(o, "state", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
            json_object_object_add(o, "started_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
            json_object_object_add(o, "finished_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
            json_object_object_add(o, "error", json_object_new_string((const char *)sqlite3_column_text(st, 5)));
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    return arr;
}

struct json_object *jmx_tasks_get(int task_id)
{
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st = app_prepare(
        "SELECT id,scope,state,changes_json,rollback_timeout,started_at,confirmed_at,finished_at,error "
        "FROM config_apply_tasks WHERE id=?1");
    if (st) {
        sqlite3_bind_int(st, 1, task_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(resp, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(resp, "scope", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(resp, "state", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
            const char *cj = (const char *)sqlite3_column_text(st, 3);
            struct json_object *changes = cj ? json_tokener_parse(cj) : json_object_new_object();
            json_object_object_add(resp, "changes", changes ? changes : json_object_new_object());
            json_object_object_add(resp, "rollback_timeout", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(resp, "started_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(resp, "confirmed_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
            json_object_object_add(resp, "finished_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_object_add(resp, "error", json_object_new_string((const char *)sqlite3_column_text(st, 8)));
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    return resp;
}

int jmx_tasks_delete(int task_id)
{
    (void)task_id;
    /* Legacy listener ABI: task journals are never ordinary deletable rows. */
    return -2;
}

/* ══════════════════════════════════════════════════════════════════════
 * Events (SSE)
 * ══════════════════════════════════════════════════════════════════════ */

#define MAX_SSE_CLIENTS 8
static int g_sse_fds[MAX_SSE_CLIENTS];
static int g_sse_count = 0;

int jmx_events_fd_add(int fd)
{
    if (g_sse_count >= MAX_SSE_CLIENTS) return -1;
    g_sse_fds[g_sse_count++] = fd;
    return 0;
}

void jmx_events_fd_remove(int fd)
{
    int i;
    for (i = 0; i < g_sse_count; i++) {
        if (g_sse_fds[i] == fd) {
            g_sse_fds[i] = g_sse_fds[--g_sse_count];
            return;
        }
    }
}

void jmx_events_emit(const char *topic, const char *type, struct json_object *data)
{
    static int64_t evt_seq = 0;
    int64_t ts = now_s();
    char buf[4096];
    struct json_object *evt = json_object_new_object();
    json_object_object_add(evt, "id", json_object_new_int64(++evt_seq));
    json_object_object_add(evt, "ts", json_object_new_int64(ts));
    json_object_object_add(evt, "topic", json_object_new_string(topic ? topic : ""));
    json_object_object_add(evt, "type", json_object_new_string(type ? type : "updated"));
    if (data) json_object_object_add(evt, "data", json_object_get(data));
    const char *s = json_object_to_json_string(evt);
    int len = snprintf(buf, sizeof(buf), "id: %lld\nevent: %s\ndata: %s\n\n",
                       (long long)evt_seq, topic ? topic : "message", s);
    json_object_put(evt);

    int i;
    for (i = 0; i < g_sse_count; i++) {
        if (write(g_sse_fds[i], buf, (size_t)len) <= 0) {
            close(g_sse_fds[i]);
            g_sse_fds[i] = g_sse_fds[--g_sse_count];
            i--;
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Audit
 * ══════════════════════════════════════════════════════════════════════ */

void jmx_app_audit_log(const char *actor, const char *app_device_id,
                   const char *action, const char *risk,
                   const char *target, const char *before_hash,
                   const char *after_hash)
{
    int64_t ts = now_s();
    sqlite3_stmt *st = app_prepare(
        "INSERT INTO api_audit_log(ts,actor,app_device_id,action,risk,target,before_hash,after_hash) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8)");
    if (!st) return;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_text(st, 2, actor ? actor : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, app_device_id ? app_device_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, action ? action : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, risk ? risk : "low", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, target ? target : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, before_hash ? before_hash : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, after_hash ? after_hash : "", -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* ══════════════════════════════════════════════════════════════════════
 * HTTP Router
 * ══════════════════════════════════════════════════════════════════════ */

static struct uloop_fd g_listen_fd;

/* Minimal HTTP response builder */
static int http_send(int fd, int status, const char *status_text,
                     const char *content_type, const char *body, int body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type\r\n"
        "Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n",
        status, status_text, content_type, body_len);
    write(fd, header, (size_t)hlen);
    if (body && body_len > 0) write(fd, body, (size_t)body_len);
    return 0;
}

static int http_send_json(int fd, int status, struct json_object *resp)
{
    const char *s = resp ? json_object_to_json_string(resp) : "{}";
    int slen = (int)strlen(s);

    /* Generate ETag from content hash */
    unsigned int hash = 5381;
    int i;
    for (i = 0; i < slen; i++) hash = ((hash << 5) + hash) + (unsigned char)s[i];
    char etag[32];
    snprintf(etag, sizeof(etag), "\"%08x\"", hash);

    /* Build response with ETag */
    char header[768];
    const char *status_text =
        status == 200 ? "OK" :
        status == 401 ? "Unauthorized" :
        status == 403 ? "Forbidden" :
        status == 404 ? "Not Found" :
        "Bad Request";
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match\r\n"
        "Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: max-age=0\r\n"
        "ETag: %s\r\n"
        "\r\n",
        status, status_text, slen, etag);
    write(fd, header, (size_t)hlen);
    if (slen > 0) write(fd, s, (size_t)slen);
    return 0;
}

static int http_send_sse_header(int fd)
{
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n";
    return write(fd, hdr, strlen(hdr));
}

/* Extract Bearer token from Authorization header */
static const char *extract_bearer(const char *headers, char *tok_out, int tok_out_sz)
{
    const char *p = strstr(headers, "Authorization:");
    if (!p) p = strstr(headers, "authorization:");
    if (!p) return NULL;
    p = strchr(p, ':');
    if (!p) return NULL;
    p++;
    while (*p == ' ') p++;
    if (strncmp(p, "Bearer ", 7) != 0) return NULL;
    p += 7;
    int i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < tok_out_sz - 1) tok_out[i++] = *p++;
    tok_out[i] = '\0';
    return tok_out;
}

/* Parse request path and body */
struct http_req {
    char method[8];
    char path[512];
    const char *body;
    int body_len;
    char auth_token[TOKEN_LEN + 1];
    char if_none_match[64]; /* ETag for conditional requests */
};

static int parse_http_request(const char *raw, int raw_len, struct http_req *out)
{
    memset(out, 0, sizeof(*out));
    /* Method */
    const char *sp = strchr(raw, ' ');
    if (!sp || sp - raw >= (int)sizeof(out->method)) return -1;
    memcpy(out->method, raw, (size_t)(sp - raw));
    out->method[sp - raw] = '\0';
    /* Path */
    const char *path_start = sp + 1;
    const char *path_end = strchr(path_start, ' ');
    if (!path_end || path_end - path_start >= (int)sizeof(out->path)) return -1;
    memcpy(out->path, path_start, (size_t)(path_end - path_start));
    out->path[path_end - path_start] = '\0';
    /* Headers → auth + If-None-Match */
    const char *hdr_end = strstr(raw, "\r\n\r\n");
    if (hdr_end) {
        extract_bearer(raw, out->auth_token, sizeof(out->auth_token));
        /* Extract If-None-Match */
        const char *inm = strstr(raw, "If-None-Match:");
        if (!inm) inm = strstr(raw, "if-none-match:");
        if (inm && inm < hdr_end) {
            const char *v = strchr(inm, ':');
            if (v) {
                v++;
                while (*v == ' ') v++;
                int i = 0;
                while (*v && *v != '\r' && *v != '\n' && i < (int)sizeof(out->if_none_match) - 1)
                    out->if_none_match[i++] = *v++;
                out->if_none_match[i] = '\0';
            }
        }
        out->body = hdr_end + 4;
        out->body_len = raw_len - (int)(out->body - raw);
    }
    return 0;
}

/* ── ubus invoke helper for HTTP API ── */
struct ubus_invoke_resp {
    struct json_object *json;
    int rc;
};

static void ubus_invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct ubus_invoke_resp *r = req->priv;
    if (!msg) return;
    char *s = blobmsg_format_json(msg, true);
    if (s) {
        r->json = json_tokener_parse(s);
        free(s);
    }
}

static struct json_object *app_ubus_invoke(const char *method, struct json_object *params)
{
    struct ubus_context *uctx = ubus_connect(NULL);
    if (!uctx) return NULL;
    uint32_t id;
    if (ubus_lookup_id(uctx, "dreamingwrt", &id) != UBUS_STATUS_OK) {
        ubus_free(uctx);
        return NULL;
    }
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    if (params) {
        /* Convert JSON to blob */
        const char *s = json_object_to_json_string(params);
        if (s && s[0]) {
            blobmsg_add_json_from_string(&b, s);
        }
    }
    struct ubus_invoke_resp resp = { .json = NULL, .rc = -1 };
    int rc = ubus_invoke(uctx, id, method, b.head, ubus_invoke_cb, &resp, 2000);
    blob_buf_free(&b);
    ubus_free(uctx);
    if (rc != UBUS_STATUS_OK) {
        if (resp.json) json_object_put(resp.json);
        return NULL;
    }
    return resp.json;
}

/* Route dispatcher */
static void handle_client(int fd)
{
    char buf[APP_API_READ_BUF];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(fd); return; }
    buf[n] = '\0';

    struct http_req req;
    if (parse_http_request(buf, n, &req) != 0) {
        http_send(fd, 400, "Bad Request", "text/plain", "bad request", 11);
        close(fd);
        return;
    }

    /* OPTIONS (CORS preflight) */
    if (!strcmp(req.method, "OPTIONS")) {
        http_send(fd, 200, "OK", "text/plain", "", 0);
        close(fd);
        return;
    }

    /* Parse body JSON */
    struct json_object *body_json = NULL;
    if (req.body && req.body_len > 0) {
        body_json = json_tokener_parse(req.body);
        if (!body_json) body_json = json_object_new_object();
    } else {
        body_json = json_object_new_object();
    }

    /* ── Bootstrap (no auth) ── */
    if (!strcmp(req.path, "/api/v1/bootstrap")) {
        struct json_object *resp = json_object_new_object();
        struct json_object *dev = json_object_new_object();
        char hostname[128] = {0};
        FILE *fp = fopen("/proc/sys/kernel/hostname", "r");
        if (fp) { fgets(hostname, sizeof(hostname), fp); fclose(fp); }
        size_t hl = strlen(hostname);
        while (hl > 0 && (hostname[hl-1] == '\n' || hostname[hl-1] == '\r')) hostname[--hl] = '\0';
        json_object_object_add(dev, "hostname", json_object_new_string(hostname));
        json_object_object_add(dev, "model", json_object_new_string("DreamingWrt"));
        json_object_object_add(dev, "api_version", json_object_new_string("1.0"));
        json_object_object_add(resp, "device", dev);
        struct json_object *auth = json_object_new_object();
        json_object_object_add(auth, "pairing_available", json_object_new_boolean(1));
        json_object_object_add(resp, "auth", auth);
        struct json_object *feat = json_object_new_object();
        json_object_object_add(feat, "events", json_object_new_boolean(1));
        json_object_object_add(feat, "tasks", json_object_new_boolean(1));
        json_object_object_add(feat, "config_transactions", json_object_new_boolean(1));
        json_object_object_add(resp, "features", feat);
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        http_send_json(fd, 200, resp);
        json_object_put(resp);
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── Pair init (no auth) ── */
    if (!strcmp(req.path, "/api/v1/auth/pair/init") && !strcmp(req.method, "POST")) {
        struct json_object *resp = jmx_app_pair_init(body_json);
        if (resp) {
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            http_send_json(fd, 200, resp);
            json_object_put(resp);
        } else {
            http_send_json(fd, 400, NULL);
        }
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── Pair confirm (no auth) ── */
    if (!strcmp(req.path, "/api/v1/auth/pair/confirm") && !strcmp(req.method, "POST")) {
        struct json_object *resp = jmx_app_pair_confirm(body_json);
        if (resp) {
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            http_send_json(fd, 200, resp);
            json_object_put(resp);
        } else {
            http_send_json(fd, 400, NULL);
        }
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── Login (no auth) ── */
    if (!strcmp(req.path, "/api/v1/auth/login") && !strcmp(req.method, "POST")) {
        struct json_object *resp = jmx_app_login(body_json);
        if (resp) {
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            http_send_json(fd, 200, resp);
            json_object_put(resp);
        } else {
            http_send_json(fd, 401, NULL);
        }
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── Refresh (no auth) ── */
    if (!strcmp(req.path, "/api/v1/auth/refresh") && !strcmp(req.method, "POST")) {
        struct json_object *resp = jmx_app_refresh(body_json);
        if (resp) {
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            http_send_json(fd, 200, resp);
            json_object_put(resp);
        } else {
            http_send_json(fd, 401, NULL);
        }
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── Capabilities (no auth) ── */
    if (!strcmp(req.path, "/api/v1/capabilities")) {
        struct json_object *resp = jmx_cache_get("capabilities");
        if (!resp) {
            resp = jmx_netconfig_capabilities();
            if (resp) jmx_cache_put("capabilities", resp, 60);
        }
        http_send_json(fd, 200, resp);
        json_object_put(resp);
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── All remaining routes require Bearer token ── */
    char *device_id = jmx_app_validate_token(req.auth_token);
    if (!device_id) {
        struct json_object *err = json_object_new_object();
        json_object_object_add(err, "ok", json_object_new_boolean(0));
        json_object_object_add(err, "code", json_object_new_int(401));
        json_object_object_add(err, "message", json_object_new_string("unauthorized"));
        http_send_json(fd, 401, err);
        json_object_put(err);
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* ── Permission check ── */
    jmx_risk_t risk = jmx_perm_route_risk(req.method, req.path);
    if (risk == JMX_RISK_BLOCKED) {
        jmx_app_audit_log("app", device_id, req.path, "blocked", req.path, NULL, NULL);
        struct json_object *err = json_object_new_object();
        json_object_object_add(err, "ok", json_object_new_boolean(0));
        json_object_object_add(err, "code", json_object_new_int(403));
        json_object_object_add(err, "message", json_object_new_string("blocked: this operation is not allowed from app"));
        http_send_json(fd, 403, err);
        json_object_put(err);
        free(device_id);
        close(fd);
        json_object_put(body_json);
        return;
    }

    /* Look up role from app_devices */
    jmx_role_t role = JMX_ROLE_OPERATOR;
    {
        sqlite3_stmt *rst = app_prepare("SELECT role FROM app_devices WHERE id=?1");
        if (rst) {
            sqlite3_bind_text(rst, 1, device_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(rst) == SQLITE_ROW)
                role = jmx_perm_parse_role((const char *)sqlite3_column_text(rst, 0));
            sqlite3_finalize(rst);
        }
    }

    if (!jmx_perm_check(role, risk)) {
        jmx_app_audit_log("app", device_id, req.path, jmx_perm_risk_str(risk), req.path, NULL, NULL);
        struct json_object *err = json_object_new_object();
        json_object_object_add(err, "ok", json_object_new_boolean(0));
        json_object_object_add(err, "code", json_object_new_int(403));
        char msg[256];
        snprintf(msg, sizeof(msg), "forbidden: role '%s' cannot perform '%s' risk action", 
                 /* role name */
                 role == JMX_ROLE_OWNER ? "owner" : role == JMX_ROLE_ADMIN ? "admin" :
                 role == JMX_ROLE_VIEWER ? "viewer" : role == JMX_ROLE_AI_AGENT ? "ai-agent" : "operator",
                 jmx_perm_risk_str(risk));
        json_object_object_add(err, "message", json_object_new_string(msg));
        json_object_object_add(err, "required_risk", json_object_new_string(jmx_perm_risk_str(risk)));
        http_send_json(fd, 403, err);
        json_object_put(err);
        free(device_id);
        close(fd);
        json_object_put(body_json);
        return;
    }

    jmx_app_audit_log("app", device_id, req.path, jmx_perm_risk_str(risk), req.path, NULL, NULL);

    struct json_object *resp = NULL;
    int status = 200;

    /* ── Session ── */
    if (!strcmp(req.path, "/api/v1/auth/session")) {
        resp = jmx_app_session(req.auth_token);
    }
    /* ── Logout ── */
    else if (!strcmp(req.path, "/api/v1/auth/logout") && !strcmp(req.method, "POST")) {
        resp = jmx_app_logout(body_json);
    }
    /* ── Devices ── */
    else if (!strcmp(req.path, "/api/v1/auth/devices") && !strcmp(req.method, "GET")) {
        struct json_object *arr = jmx_app_devices_list();
        resp = json_object_new_object();
        json_object_object_add(resp, "devices", arr);
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
    }
    /* ── Set device role (PATCH /api/v1/auth/devices/:id) ── */
    else if (!strncmp(req.path, "/api/v1/auth/devices/", 21) && !strcmp(req.method, "PATCH")) {
        const char *dev_id = req.path + 21;
        const char *new_role = app_nc_json_str(body_json, "role", "");
        if (!dev_id[0] || !new_role[0]) {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "code", json_object_new_int(400));
            json_object_object_add(resp, "message", json_object_new_string("missing device_id or role"));
        } else {
            /* Only owner/admin can change roles */
            int rc = jmx_app_device_set_role(dev_id, new_role);
            if (rc == -2) {
                resp = json_object_new_object();
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "code", json_object_new_int(400));
                json_object_object_add(resp, "message", json_object_new_string("invalid role"));
            } else if (rc != 0) {
                resp = json_object_new_object();
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "code", json_object_new_int(404));
                json_object_object_add(resp, "message", json_object_new_string("device not found"));
            } else {
                resp = json_object_new_object();
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                jmx_cache_invalidate("auth_devices");
            }
        }
    }
    /* ── Delete device ── */
    else if (!strncmp(req.path, "/api/v1/auth/devices/", 21) && !strcmp(req.method, "DELETE")) {
        const char *dev_id = req.path + 21;
        if (jmx_app_device_delete(dev_id) == 0) {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
        } else {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "code", json_object_new_int(404));
            json_object_object_add(resp, "message", json_object_new_string("device not found"));
        }
    }
    /* ── System status (cached 5s) ── */
    else if (!strcmp(req.path, "/api/v1/system/status")) {
        resp = jmx_cache_get("system_status");
        if (!resp) {
            resp = get_system_status();
            if (resp) jmx_cache_put("system_status", resp, 5);
        }
    }
    /* ── Network overview (cached 3s) ── */
    else if (!strcmp(req.path, "/api/v1/network/overview")) {
        resp = jmx_cache_get("network_overview");
        if (!resp) {
            resp = jmx_netconfig_network_overview();
            if (resp) jmx_cache_put("network_overview", resp, 3);
        }
    }
    /* ── Global config ── */
    else if (!strcmp(req.path, "/api/v1/network/global")) {
        resp = jmx_netconfig_global_get();
    }
    else if (!strcmp(req.path, "/api/v1/network/global") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_netconfig_global_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        json_object_object_add(resp, "apply_state", json_object_new_string(rc == 0 ? "saved" : "error"));
        if (rc == 0) jmx_cache_invalidate("network_overview");
    }
    else if (!strcmp(req.path, "/api/v1/network/global/apply") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_netconfig_global_apply();
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        json_object_object_add(resp, "apply_state", json_object_new_string(rc == 0 ? "applied" : "error"));
        if (rc == 0) jmx_cache_invalidate("network_overview");
    }
    /* ── Ports ── */
    else if (!strcmp(req.path, "/api/v1/network/ports")) {
        resp = jmx_netconfig_physical_port_list();
    }
    /* ── WAN list ── */
    else if (!strcmp(req.path, "/api/v1/network/wans")) {
        resp = jmx_netconfig_wan_list();
    }
    /* ── WAN single ── */
    else if (!strncmp(req.path, "/api/v1/network/wans/", 21) && !strchr(req.path + 21, '/')) {
        resp = jmx_netconfig_wan_get(req.path + 21);
    }
    /* ── WAN create/update ── */
    else if (!strcmp(req.path, "/api/v1/network/wans") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *verr = jmx_netconfig_wan_validate(body_json);
        if (verr) {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "code", json_object_new_int(400));
            json_object_object_add(resp, "message", json_object_new_string("validation failed"));
            json_object_object_add(resp, "errors", verr);
            status = 400;
        } else {
            int rc = jmx_netconfig_wan_set(body_json);
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
            if (rc == 0) {
                const char *wid = app_nc_json_str(body_json, "id", "");
                if (wid[0]) json_object_object_add(resp, "id", json_object_new_string(wid));
                jmx_cache_invalidate("network_overview");
            }
        }
    }
    /* ── WAN delete ── */
    else if (!strncmp(req.path, "/api/v1/network/wans/", 21) && !strcmp(req.method, "DELETE")) {
        const char *id = req.path + 21;
        int rc = jmx_netconfig_wan_delete(id);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── LAN list ── */
    else if (!strcmp(req.path, "/api/v1/network/lans")) {
        resp = jmx_netconfig_lan_list();
    }
    /* ── LAN single ── */
    else if (!strncmp(req.path, "/api/v1/network/lans/", 21) && !strchr(req.path + 21, '/')) {
        resp = jmx_netconfig_lan_get(req.path + 21);
    }
    /* ── LAN create/update ── */
    else if (!strcmp(req.path, "/api/v1/network/lans") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *verr = jmx_netconfig_lan_validate(body_json);
        if (verr) {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "code", json_object_new_int(400));
            json_object_object_add(resp, "message", json_object_new_string("validation failed"));
            json_object_object_add(resp, "errors", verr);
            status = 400;
        } else {
            int rc = jmx_netconfig_lan_set(body_json);
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
            if (rc == 0) jmx_cache_invalidate("network_overview");
        }
    }
    /* ── DNS service ── */
    else if (!strcmp(req.path, "/api/v1/services/dns") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("dns_service");
        if (!resp) {
            resp = jmx_dns_service_get();
            if (resp) jmx_cache_put("dns_service", resp, 3);
        }
    }
    else if (!strcmp(req.path, "/api/v1/services/dns") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int lp = nc_json_int_def(body_json, "listen_port", 53);
        int cs = nc_json_int_def(body_json, "cache_size", 4096);
        {
            int bad_upstream = 0, bad_rule = 0, idx_up = -1, idx_ru = -1;
            struct json_object *uparr = NULL;
            struct json_object *ruarr = NULL;
            if (json_object_object_get_ex(body_json, "upstreams", &uparr) && uparr && json_object_is_type(uparr, json_type_array)) {
                int i, n = json_object_array_length(uparr);
                for (i = 0; i < n; i++) {
                    struct json_object *u = json_object_array_get_idx(uparr, i);
                    const char *proto = nc_json_str_def(u, "protocol", "udp");
                    const char *addr = nc_json_str_def(u, "address", "");
                    if (!nc_dns_valid_protocol(proto) || !addr[0]) { bad_upstream = 1; idx_up = i; break; }
                }
            }
            if (json_object_object_get_ex(body_json, "rules", &ruarr) && ruarr && json_object_is_type(ruarr, json_type_array)) {
                int i, n = json_object_array_length(ruarr);
                for (i = 0; i < n; i++) {
                    struct json_object *r = json_object_array_get_idx(ruarr, i);
                    const char *domain = nc_json_str_def(r, "domain", "");
                    const char *type = nc_json_str_def(r, "type", "");
                    if (!domain[0] || !nc_dns_valid_rule_type(type)) { bad_rule = 1; idx_ru = i; break; }
                }
            }
            if (lp < 1 || lp > 65535 || cs < 0 || cs > 1000000 || bad_upstream || bad_rule) {
            resp = json_object_new_object();
            struct json_object *verr = json_object_new_array();
            if (lp < 1 || lp > 65535) {
                struct json_object *e = json_object_new_object();
                json_object_object_add(e, "field", json_object_new_string("dns.listen_port"));
                json_object_object_add(e, "reason", json_object_new_string("out_of_range"));
                json_object_object_add(e, "message", json_object_new_string("listen_port must be 1-65535"));
                json_object_array_add(verr, e);
            }
            if (cs < 0 || cs > 1000000) {
                struct json_object *e = json_object_new_object();
                json_object_object_add(e, "field", json_object_new_string("dns.cache_size"));
                json_object_object_add(e, "reason", json_object_new_string("out_of_range"));
                json_object_object_add(e, "message", json_object_new_string("cache_size must be 0-1000000"));
                json_object_array_add(verr, e);
            }
            if (bad_upstream) {
                struct json_object *e = json_object_new_object();
                json_object_object_add(e, "field", json_object_new_string("dns.upstreams"));
                json_object_object_add(e, "index", json_object_new_int(idx_up));
                json_object_object_add(e, "reason", json_object_new_string("invalid_upstream"));
                json_object_object_add(e, "message", json_object_new_string("upstream must have valid protocol and address"));
                json_object_array_add(verr, e);
            }
            if (bad_rule) {
                struct json_object *e = json_object_new_object();
                json_object_object_add(e, "field", json_object_new_string("dns.rules"));
                json_object_object_add(e, "index", json_object_new_int(idx_ru));
                json_object_object_add(e, "reason", json_object_new_string("invalid_rule"));
                json_object_object_add(e, "message", json_object_new_string("rule must have valid domain and type"));
                json_object_array_add(verr, e);
            }
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "code", json_object_new_int(400));
            json_object_object_add(resp, "message", json_object_new_string("validation failed"));
            json_object_object_add(resp, "errors", verr);
            status = 400;
        } else {
            int apply = app_nc_json_bool(body_json, "apply", 1);
            resp = jmx_dns_service_save_apply_result(body_json, apply);
            jmx_cache_invalidate("dns_service");
        }
        }
    }
    else if (!strcmp(req.path, "/api/v1/services/dns/rules") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_dns_rule_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("dns_service");
    }
    else if (!strncmp(req.path, "/api/v1/services/dns/rules/", 26) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_dns_rule_delete(req.path + 26);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("dns_service");
    }
    else if (!strcmp(req.path, "/api/v1/services/dns/wan-policy") && !strcmp(req.method, "GET")) {
        resp = jmx_wan_dns_policy_get("");
    }
    else if (!strcmp(req.path, "/api/v1/services/dns/wan-policy") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        const char *wid = app_nc_json_str(body_json, "wan_id", "");
        int rc = jmx_wan_dns_policy_set(wid, body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("dns_service");
    }
    else if (!strncmp(req.path, "/api/v1/services/dns/wan-policy/", 32) && !strcmp(req.method, "DELETE")) {
        int pid = atoi(req.path + 32);
        int rc = jmx_wan_dns_policy_delete(pid);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("dns_service");
    }
    /* ── AI Config & Tools ── */
    else if (!strcmp(req.path, "/api/v1/ai/config") && !strcmp(req.method, "GET")) {
        resp = ai_envelope(jmx_ai_config_get(), 200);
    }
    else if (!strcmp(req.path, "/api/v1/ai/config") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        { int rc = jmx_ai_config_set(body_json);
          struct json_object *d = json_object_new_object();
          json_object_object_add(d, "ok", json_object_new_boolean(rc == 0));
          resp = jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, d);
          resp = ai_envelope(resp, rc == 0 ? 200 : 400); }
    }
    else if (!strcmp(req.path, "/api/v1/ai/models") && !strcmp(req.method, "GET")) {
        resp = ai_envelope(jmx_ai_models_get(), 200);
    }
    else if (!strcmp(req.path, "/api/v1/ai/tools") && !strcmp(req.method, "GET")) {
        resp = ai_envelope(jmx_ai_tools_get(), 200);
    }
    else if (!strcmp(req.path, "/api/v1/ai/chat") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = ai_envelope(jmx_ai_chat(body_json), 200);
    }
    else if (!strcmp(req.path, "/api/v1/ai/tool-authorize") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int aid = nc_json_int_def(body_json, "id", 0);
        int approve = nc_json_bool_def(body_json, "approve", 0);
        const char *role = app_nc_json_str(body_json, "role", "admin");
        int rc = jmx_ai_tool_authorize(aid, approve, role);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── AI Tool-Call execution ── */
    else if (!strcmp(req.path, "/api/v1/ai/tool-call") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = ai_envelope(jmx_ai_tool_call(body_json), 200);
    }
    /* ── AI Tool Authorizations list ── */
    else if (!strcmp(req.path, "/api/v1/ai/tool-authorizations") && !strcmp(req.method, "GET")) {
        resp = ai_envelope(jmx_ai_tool_authorizations_list(), 200);
    }
    /* ── AI Tool Authorizations approve/deny ── */
    else if (!strncmp(req.path, "/api/v1/ai/tool-authorizations/", 31) && !strcmp(req.method, "POST")) {
        const char *tail = req.path + 31;
        char id_buf[32] = "";
        const char *action = "";
        /* Parse: {id}/approve or {id}/deny */
        const char *slash = strchr(tail, '/');
        if (slash) {
            size_t id_len = slash - tail;
            if (id_len < sizeof(id_buf)) { strncpy(id_buf, tail, id_len); id_buf[id_len] = 0; }
            action = slash + 1;
        } else {
            snprintf(id_buf, sizeof(id_buf), "%s", tail);
        }
        int auth_id = atoi(id_buf);
        int approve = (!strcmp(action, "approve")) ? 1 : 0;
        const char *role = app_nc_json_str(body_json, "role", "admin");
        int rc = jmx_ai_tool_authorize(auth_id, approve, role);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) {
            json_object_object_add(resp, "auth_id", json_object_new_int(auth_id));
            json_object_object_add(resp, "action", json_object_new_string(action));
        }
    }
    /* ── AI Conversations (legacy) ── */
    else if (!strcmp(req.path, "/api/v1/ai/conversations") && !strcmp(req.method, "GET")) {
        resp = jmx_ai_conversations_list();
    }
    else if (!strncmp(req.path, "/api/v1/ai/conversations/", 24) && !strcmp(req.method, "GET")) {
        resp = jmx_ai_conversation_get(req.path + 24);
    }
    else if (!strcmp(req.path, "/api/v1/ai/conversations") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_ai_conversation_save(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strncmp(req.path, "/api/v1/ai/conversations/", 24) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_ai_conversation_delete(req.path + 24);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── AI history ── */
    else if (!strcmp(req.path, "/api/v1/ai/history") && !strcmp(req.method, "GET")) {
        int limit = nc_json_int_def(body_json, "limit", 50);
        int off = nc_json_int_def(body_json, "offset", 0);
        resp = ai_envelope(jmx_ai_history_list(limit, off), 200);
    }
    else if (!strncmp(req.path, "/api/v1/ai/history/", 19) && !strcmp(req.method, "GET")) {
        resp = ai_envelope(jmx_ai_history_get(req.path + 19), 200);
    }
    else if (!strcmp(req.path, "/api/v1/ai/history") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_ai_history_save(body_json);
        if (!resp) { status = 500; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("internal_error")); }
        else {
            struct json_object *okv = NULL;
            if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        }
    }
    else if (!strncmp(req.path, "/api/v1/ai/history/", 19) && !strcmp(req.method, "DELETE")) {
        int ok = jmx_ai_history_delete(req.path + 19) == 0;
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    }
    else if (!strcmp(req.path, "/api/v1/ai/history") && !strcmp(req.method, "DELETE")) {
        int ok = jmx_ai_history_clear() == 0;
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    }
    /* ── UPnP service ── */
    else if (!strcmp(req.path, "/api/v1/services/upnp") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("upnp_service");
        if (!resp) {
            resp = jmx_upnp_service_get();
            if (resp) jmx_cache_put("upnp_service", resp, 3);
        }
    }
    /* ── Flow control ── */
    else if (!strcmp(req.path, "/api/v1/flow-control") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("flow_control");
        if (!resp) {
            resp = jmx_flow_control_get();
            if (resp) jmx_cache_put("flow_control", resp, 2);
        }
    }
    else if (!strcmp(req.path, "/api/v1/flow-control") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_flow_control_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("flow_control");
    }
    else if (!strcmp(req.path, "/api/v1/flow-control/apply") && !strcmp(req.method, "POST")) {
        resp = jmx_flow_control_apply(body_json);
        jmx_cache_invalidate("flow_control");
    }
    else if (!strcmp(req.path, "/api/v1/flow-control/smart") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_flow_control_smart_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("flow_control");
    }
    else if (!strcmp(req.path, "/api/v1/flow-control/smart/priorities") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_flow_control_priority_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("flow_control");
    }
    else if (!strcmp(req.path, "/api/v1/flow-control/group-carrier") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_flow_control_group_carrier_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("flow_control");
    }
    /* CSV export endpoints temporarily disabled - need client/cleanup context */
    /* else if (!strcmp(req.path, "/api/v1/wan-config/export.csv") && !strcmp(req.method, "GET")) { ... } */
    /* else if (!strcmp(req.path, "/api/v1/lan-config/export.csv") && !strcmp(req.method, "GET")) { ... } */
    /* ── Advanced Routing ── */
    else if (!strcmp(req.path, "/api/v1/routing")) {
        resp = jmx_cache_get("advanced_routing");
        if (!resp) {
            resp = jmx_advanced_routing_get();
            if (resp) jmx_cache_put("advanced_routing", resp, 5);
        }
    }
    else if (!strcmp(req.path, "/api/v1/routing") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_advanced_routing_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("advanced_routing");
    }
    else if (!strcmp(req.path, "/api/v1/routing/apply") && !strcmp(req.method, "POST")) {
        resp = jmx_advanced_routing_apply(body_json);
        jmx_cache_invalidate("advanced_routing");
    }
    /* ── UPnP static mapping ── */
    /* ── UPnP mappings CRUD ── */
    else if (!strcmp(req.path, "/api/v1/services/upnp/mappings") && !strcmp(req.method, "GET")) {
        resp = jmx_upnp_mappings_list();
    }
    else if (!strcmp(req.path, "/api/v1/services/upnp/mappings") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_upnp_mapping_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("upnp_service");
    }
    else if (!strncmp(req.path, "/api/v1/services/upnp/mappings/", 31) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_upnp_mapping_delete(req.path + 31);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("upnp_service");
    }

    /* ── Advanced Routing sub-resources ── */
    else if (!strcmp(req.path, "/api/v1/routing/static-routes") && !strcmp(req.method, "GET")) {
        struct json_object *sr = jmx_routing_static_routes_list();
        resp = json_object_new_object();
        json_object_object_add(resp, "static_routes", sr);
        json_object_object_add(resp, "ts", json_object_new_int64(nc_now_s()));
    }
    else if (!strcmp(req.path, "/api/v1/routing/static-routes") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_routing_static_route_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strncmp(req.path, "/api/v1/routing/static-routes/", 30) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_routing_static_route_delete(req.path + 30);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strcmp(req.path, "/api/v1/routing/policy-rules") && !strcmp(req.method, "GET")) {
        struct json_object *pr = jmx_routing_policy_rules_list();
        resp = json_object_new_object();
        json_object_object_add(resp, "policy_rules", pr);
        json_object_object_add(resp, "ts", json_object_new_int64(nc_now_s()));
    }
    else if (!strcmp(req.path, "/api/v1/routing/policy-rules") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_routing_policy_rule_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strncmp(req.path, "/api/v1/routing/policy-rules/", 29) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_routing_policy_rule_delete(req.path + 29);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strcmp(req.path, "/api/v1/routing/tables") && !strcmp(req.method, "GET")) {
        struct json_object *tbl = jmx_routing_tables_list();
        resp = json_object_new_object();
        json_object_object_add(resp, "tables", tbl);
        json_object_object_add(resp, "ts", json_object_new_int64(nc_now_s()));
    }
    else if (!strcmp(req.path, "/api/v1/routing/tables") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_routing_table_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strncmp(req.path, "/api/v1/routing/tables/", 23) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_routing_table_delete(req.path + 23);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }

    /* ── Flow Control rules CRUD ── */
    else if (!strcmp(req.path, "/api/v1/flow-control/rules") && !strcmp(req.method, "GET")) {
        struct json_object *fr = jmx_flow_rules_list();
        resp = json_object_new_object();
        json_object_object_add(resp, "rules", fr);
        json_object_object_add(resp, "ts", json_object_new_int64(nc_now_s()));
    }
    else if (!strcmp(req.path, "/api/v1/flow-control/rules") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_flow_rule_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strncmp(req.path, "/api/v1/flow-control/rules/", 27) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_flow_rule_delete(req.path + 27);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }

    /* ── Bulk IP Management ── */
    else if (!strcmp(req.path, "/api/v1/bulk-ip") && !strcmp(req.method, "GET")) {
        resp = jmx_bulk_ip_get()  ;
    }
    else if (!strcmp(req.path, "/api/v1/bulk-ip/reserve") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_bulk_ip_reserve(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strcmp(req.path, "/api/v1/bulk-ip/delete") && !strcmp(req.method, "POST")) {
        const char *id = nc_json_str_def(body_json, "id", "");
        int rc = jmx_bulk_ip_delete(id);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── Firewall service ── */
    else if (!strcmp(req.path, "/api/v1/services/firewall") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("firewall_service");
        if (!resp) {
            resp = jmx_firewall_service_get();
            if (resp) jmx_cache_put("firewall_service", resp, 5);
        }
    }
    else if (!strcmp(req.path, "/api/v1/services/firewall") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_firewall_service_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("firewall_service");
    }
    else if (!strcmp(req.path, "/api/v1/services/firewall/apply") && !strcmp(req.method, "POST")) {
        resp = jmx_firewall_service_apply(body_json);
        jmx_cache_invalidate("firewall_service");
    }
    /* ── Geo-Block ── */
    else if (!strcmp(req.path, "/api/v1/firewall/geo-block") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("geo_block");
        if (!resp) {
            resp = jmx_geo_block_get();
            if (resp) jmx_cache_put("geo_block", resp, 30);
        }
    }
    else if (!strcmp(req.path, "/api/v1/firewall/geo-block") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_geo_block_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) { jmx_cache_invalidate("firewall_service"); jmx_cache_invalidate("geo_block"); }
    }
    /* ── Plugins ── */
    else if (!strcmp(req.path, "/api/v1/plugins") && !strcmp(req.method, "GET")) {
        resp = jmx_plugins_list();
    }
    else if (!strncmp(req.path, "/api/v1/plugins/", 16) && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        /* /api/v1/plugins/{id}/{action} */
        const char *rest = req.path + 16;
        const char *slash = strchr(rest, '/');
        if (slash) {
            char pid[128] = {0};
            snprintf(pid, sizeof(pid), "%.*s", (int)(slash - rest), rest);
            const char *action = slash + 1;
            int rc = jmx_plugin_action(pid, action);
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        } else {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("missing action"));
        }
    }
    /* ── VPN config ── */
    else if (!strcmp(req.path, "/api/v1/services/vpn") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("vpn_config");
        if (!resp) {
            resp = jmx_vpn_config_get();
            if (resp) jmx_cache_put("vpn_config", resp, 5);
        }
    }
    else if (!strcmp(req.path, "/api/v1/services/vpn") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_vpn_config_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("vpn_config");
    }
    else if (!strcmp(req.path, "/api/v1/services/vpn/apply") && !strcmp(req.method, "POST")) {
        resp = jmx_vpn_config_apply(body_json);
        jmx_cache_invalidate("vpn_config");
    }
    /* ── VPN status ── */
    else if (!strcmp(req.path, "/api/v1/services/vpn/status") && !strcmp(req.method, "GET")) {
        /* Reuse the ubus vpn_status logic — build from DB */
        resp = jmx_vpn_config_get(); /* config includes status data */
    }
    /* ── WAN DNS policy ── */
    else if (!strncmp(req.path, "/api/v1/network/wans/", 21)) {
        /* /api/v1/network/wans/{id}/dns-policy */
        const char *rest = req.path + 21;
        const char *slash = strchr(rest, '/');
        if (slash && !strcmp(slash, "/dns-policy")) {
            char wan_id[128];
            int wlen = (int)(slash - rest);
            if (wlen >= (int)sizeof(wan_id)) wlen = (int)sizeof(wan_id) - 1;
            memcpy(wan_id, rest, (size_t)wlen);
            wan_id[wlen] = '\0';
            if (!strcmp(req.method, "GET")) {
                resp = jmx_wan_dns_policy_get(wan_id);
            } else if (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT")) {
                json_object_object_add(body_json, "wan_id", json_object_new_string(wan_id));
                int rc = jmx_wan_dns_policy_set(wan_id, body_json);
                resp = json_object_new_object();
                json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
            }
        }
    }
    /* ── Config snapshot ── */
    else if (!strcmp(req.path, "/api/v1/config/snapshot")) {
        resp = jmx_config_snapshot(body_json);
    }
    /* ── Config validate ── */
    else if (!strcmp(req.path, "/api/v1/config/validate") && !strcmp(req.method, "POST")) {
        resp = jmx_config_validate(body_json);
    }
    /* ── Config apply ── */
    else if (!strcmp(req.path, "/api/v1/config/apply") && !strcmp(req.method, "POST")) {
        resp = jmx_config_apply(body_json);
    }
    /* ── Config confirm ── */
    else if (!strcmp(req.path, "/api/v1/config/confirm") && !strcmp(req.method, "POST")) {
        resp = jmx_config_confirm(body_json);
    }
    /* ── Config rollback ── */
    else if (!strcmp(req.path, "/api/v1/config/rollback") && !strcmp(req.method, "POST")) {
        resp = jmx_config_rollback(body_json);
    }
    /* ── Config last-apply ── */
    else if (!strcmp(req.path, "/api/v1/config/last-apply")) {
        resp = jmx_config_last_apply();
    }
    /* ── Tasks ── */
    else if (!strcmp(req.path, "/api/v1/tasks")) {
        struct json_object *arr = jmx_tasks_list();
        resp = json_object_new_object();
        json_object_object_add(resp, "tasks", arr);
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
    }
    /* ── Task single / delete ── */
    else if (!strncmp(req.path, "/api/v1/tasks/", 14)) {
        int tid = atoi(req.path + 14);
        if (tid > 0 && !strcmp(req.method, "DELETE")) {
            int rc = jmx_tasks_delete(tid);
            resp = json_object_new_object();
            status = 409;
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error",
                json_object_new_string(rc == -2 ? "task_purge_not_supported" :
                                                  "task_delete_failed"));
            json_object_object_add(resp, "deleted", json_object_new_boolean(0));
        } else if (tid > 0) {
            resp = jmx_tasks_get(tid);
        } else {
            status = 400;
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
        }
    }
    /* ── RADIUS servers ── */
    else if (!strcmp(req.path, "/api/v1/services/radius")) {
        resp = jmx_netconfig_radius_list();
    }
    else if (!strcmp(req.path, "/api/v1/services/radius") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_netconfig_radius_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strncmp(req.path, "/api/v1/services/radius/", 24) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_netconfig_radius_delete(req.path + 24);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── Cellular / Modem ── */
    else if (!strcmp(req.path, "/api/v1/services/cellular")) {
        resp = jmx_cache_get("cellular_service");
        if (!resp) {
            resp = jmx_cellular_service_get();
            if (resp) jmx_cache_put("cellular_service", resp, 3);
        }
    }
    else if (!strcmp(req.path, "/api/v1/services/cellular") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_cellular_service_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("cellular_service");
    }
    else if (!strcmp(req.path, "/api/v1/services/cellular/apply") && !strcmp(req.method, "POST")) {
        int dry = app_nc_json_bool(body_json, "dry_run", 0);
        int rc = jmx_cellular_service_apply(dry);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        jmx_cache_invalidate("cellular_service");
    }
    else if (!strcmp(req.path, "/api/v1/services/cellular/slots") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_cellular_slot_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("cellular_service");
    }
    else if (!strncmp(req.path, "/api/v1/services/cellular/slots/", 32) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_cellular_slot_delete(req.path + 32);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("cellular_service");
    }
    else if (!strcmp(req.path, "/api/v1/services/cellular/apn-profiles") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_cellular_apn_profile_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("cellular_service");
    }
    else if (!strncmp(req.path, "/api/v1/services/cellular/apn-profiles/", 39) && !strcmp(req.method, "DELETE")) {
        int rc = jmx_cellular_apn_profile_delete(req.path + 39);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
        if (rc == 0) jmx_cache_invalidate("cellular_service");
    }
    else if (!strcmp(req.path, "/api/v1/services/cellular/status")) {
        resp = jmx_cellular_runtime_status(body_json);
    }
    /* ── System services ── */
    else if (!strcmp(req.path, "/api/v1/system/services")) {
        resp = jmx_cache_get("system_services");
        if (!resp) {
            resp = jmx_system_services_status(body_json);
            if (resp) jmx_cache_put("system_services", resp, 10);
        }
    }
    /* ── System mounts ── */
    else if (!strcmp(req.path, "/api/v1/system/mounts")) {
        resp = jmx_cache_get("system_mounts");
        if (!resp) {
            resp = jmx_system_mounts_status(body_json);
            if (resp) jmx_cache_put("system_mounts", resp, 30);
        }
    }
    /* ── Audit log ── */
    else if (!strcmp(req.path, "/api/v1/audit/events")) {
        resp = json_object_new_object();
        struct json_object *arr = json_object_new_array();
        sqlite3_stmt *ast = app_prepare(
            "SELECT id,ts,actor,app_device_id,action,risk,target FROM api_audit_log ORDER BY id DESC LIMIT 100");
        if (ast) {
            while (sqlite3_step(ast) == SQLITE_ROW) {
                struct json_object *o = json_object_new_object();
                json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(ast, 0)));
                json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(ast, 1)));
                json_object_object_add(o, "actor", json_object_new_string((const char *)sqlite3_column_text(ast, 2)));
                json_object_object_add(o, "device_id", json_object_new_string((const char *)sqlite3_column_text(ast, 3)));
                json_object_object_add(o, "action", json_object_new_string((const char *)sqlite3_column_text(ast, 4)));
                json_object_object_add(o, "risk", json_object_new_string((const char *)sqlite3_column_text(ast, 5)));
                json_object_object_add(o, "target", json_object_new_string((const char *)sqlite3_column_text(ast, 6)));
                json_object_array_add(arr, o);
            }
            sqlite3_finalize(ast);
        }
        json_object_object_add(resp, "events", arr);
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
    }
    /* ── System Health ── */
    else if (!strcmp(req.path, "/api/v1/system/health")) {
        resp = jmx_cache_get("system_health");
        if (!resp) {
            resp = app_ubus_invoke("system_health", NULL);
            if (resp) jmx_cache_put("system_health", resp, 5);
        }
    }
    /* ── Clients ── */
    else if (!strcmp(req.path, "/api/v1/clients")) {
        resp = jmx_cache_get("clients");
        if (!resp) {
            resp = app_ubus_invoke("clients", NULL);
            if (resp) jmx_cache_put("clients", resp, 3);
        }
    }
    /* ── Client Detail (single device) ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strlen(req.path) > 16 && !strcmp(req.method, "GET")) {
        /* /api/v1/clients/{mac} */
        const char *mac = req.path + 16;
        struct json_object *params = json_object_new_object();
        json_object_object_add(params, "mac", json_object_new_string(mac));
        resp = jmx_db_api_client_get(params);
        json_object_put(params);
        if (resp) {
            struct json_object *data_obj = NULL;
            json_object_object_get_ex(resp, "data", &data_obj);
            struct json_object *err_obj = NULL;
            if (data_obj && json_object_object_get_ex(data_obj, "error", &err_obj) && err_obj) {
                const char *err = json_object_get_string(err_obj);
                if (!strcmp(err, "not_found")) status = 404;
            }
        }
    }
    /* ── Client Identity Override (PATCH) ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strlen(req.path) > 16 && !strcmp(req.method, "PATCH")) {
        /* /api/v1/clients/{mac}/identity or /api/v1/clients/{mac} */
        const char *mac_part = req.path + 16;
        /* Strip /identity suffix if present */
        char mac_buf[32] = {0};
        const char *slash = strchr(mac_part, '/');
        if (slash) {
            size_t len = slash - mac_part;
            if (len < sizeof(mac_buf)) strncpy(mac_buf, mac_part, len);
        } else {
            snprintf(mac_buf, sizeof(mac_buf), "%s", mac_part);
        }
        /* Merge mac into body */
        struct json_object *override_req = body_json ? json_object_get(body_json) : json_object_new_object();
        json_object_object_add(override_req, "mac", json_object_new_string(mac_buf));
        resp = jmx_db_api_client_override(override_req);
        json_object_put(override_req);
    }
    /* ── Client Actions (POST) ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/actions") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        /* /api/v1/clients/{mac}/actions */
        const char *mac_part = req.path + 16;
        char mac_buf[32] = {0};
        const char *slash = strchr(mac_part, '/');
        if (slash) {
            size_t len = slash - mac_part;
            if (len < sizeof(mac_buf)) strncpy(mac_buf, mac_part, len);
        }
        const char *action = nc_json_str_def(body_json, "action", "");
        int dry_run = nc_json_bool_def(body_json, "dry_run", 0);
        resp = json_object_new_object();
        if (!mac_buf[0] || !action[0]) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("missing_mac_or_action"));
            status = 400;
        } else if (!strcmp(action, "block")) {
            /* Add MAC deny rule via network control */
            struct json_object *mac_rule = json_object_new_object();
            json_object_object_add(mac_rule, "mac", json_object_new_string(mac_buf));
            json_object_object_add(mac_rule, "mode", json_object_new_string("deny"));
            json_object_object_add(mac_rule, "id", json_object_new_string("app_block"));
            struct json_object *arr = json_object_new_array();
            json_object_array_add(arr, mac_rule);
            struct json_object *netctl_cfg = json_object_new_object();
            json_object_object_add(netctl_cfg, "mac_rules", arr);
            if (!dry_run) {
                jmx_network_control_save(netctl_cfg);
                jmx_network_control_apply(NULL);
            }
            json_object_put(netctl_cfg);
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
            json_object_object_add(resp, "action", json_object_new_string("block"));
            json_object_object_add(resp, "status", json_object_new_string(dry_run ? "dry_run" : "applied"));
            jmx_app_audit_log("app", "", "client.block", "high", mac_buf, "", "");
        } else if (!strcmp(action, "unblock")) {
            struct json_object *mac_rule = json_object_new_object();
            json_object_object_add(mac_rule, "mac", json_object_new_string(mac_buf));
            json_object_object_add(mac_rule, "mode", json_object_new_string("accept"));
            json_object_object_add(mac_rule, "id", json_object_new_string("app_unblock"));
            struct json_object *arr = json_object_new_array();
            json_object_array_add(arr, mac_rule);
            struct json_object *netctl_cfg = json_object_new_object();
            json_object_object_add(netctl_cfg, "mac_rules", arr);
            if (!dry_run) {
                jmx_network_control_save(netctl_cfg);
                jmx_network_control_apply(NULL);
            }
            json_object_put(netctl_cfg);
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
            json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
            json_object_object_add(resp, "action", json_object_new_string("unblock"));
            json_object_object_add(resp, "status", json_object_new_string(dry_run ? "dry_run" : "applied"));
            jmx_app_audit_log("app", "", "client.unblock", "high", mac_buf, "", "");
        } else if (!strcmp(action, "rate_limit")) {
            struct json_object *args = NULL;
            json_object_object_get_ex(body_json, "args", &args);
            int up_kbps = nc_json_int_def(args, "upload_kbps", 0);
            int down_kbps = nc_json_int_def(args, "download_kbps", 0);
            const char *remark = nc_json_str_def(args, "remark", "app rate limit");
            if (up_kbps <= 0 && down_kbps <= 0) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("missing_rate"));
                status = 400;
            } else if (dry_run) {
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
                json_object_object_add(resp, "action", json_object_new_string("rate_limit"));
                json_object_object_add(resp, "status", json_object_new_string("dry_run"));
            } else {
                char ip_buf[64] = {0};
                struct json_object *cp = json_object_new_object();
                json_object_object_add(cp, "mac", json_object_new_string(mac_buf));
                struct json_object *cr = jmx_db_api_client_get(cp);
                json_object_put(cp);
                if (cr) {
                    struct json_object *cd = NULL;
                    json_object_object_get_ex(cr, "data", &cd);
                    struct json_object *co = NULL;
                    if (cd) json_object_object_get_ex(cd, "client", &co);
                    if (co) { const char *ip = nc_json_str_def(co, "ip", ""); if (ip[0]) snprintf(ip_buf, sizeof(ip_buf), "%s", ip); }
                    json_object_put(cr);
                }
                int rc = nc_client_rate_limit_set(mac_buf, ip_buf, up_kbps, down_kbps, remark);
                if (rc == 0) { struct json_object *ar = jmx_flow_control_apply(NULL); if (ar) json_object_put(ar); }
                json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
                json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
                json_object_object_add(resp, "action", json_object_new_string("rate_limit"));
                json_object_object_add(resp, "status", json_object_new_string(rc == 0 ? "applied" : "failed"));
                jmx_app_audit_log("app", "", "client.rate_limit", "medium", mac_buf, "", "");
            }
        } else if (!strcmp(action, "rate_limit_remove")) {
            if (!dry_run) {
                int rc = nc_client_rate_limit_delete(mac_buf);
                if (rc == 0) { struct json_object *ar = jmx_flow_control_apply(NULL); if (ar) json_object_put(ar); }
                json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
                json_object_object_add(resp, "status", json_object_new_string(rc == 0 ? "applied" : "failed"));
            } else {
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "status", json_object_new_string("dry_run"));
            }
            json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
            json_object_object_add(resp, "action", json_object_new_string("rate_limit_remove"));
            jmx_app_audit_log("app", "", "client.rate_limit_remove", "medium", mac_buf, "", "");
        } else if (!strcmp(action, "dhcp_reserve")) {
            struct json_object *args = NULL;
            json_object_object_get_ex(body_json, "args", &args);
            const char *rip = nc_json_str_def(args, "ip", "");
            const char *rname = nc_json_str_def(args, "name", "");
            if (!rip[0]) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("missing_ip"));
                status = 400;
            } else {
                struct json_object *dcfg = json_object_new_object();
                struct json_object *rarr = json_object_new_array();
                struct json_object *res = json_object_new_object();
                char rid[64]; snprintf(rid, sizeof(rid), "app_%s", mac_buf);
                for (char *p = rid; *p; p++) if (*p == ':') *p = '_';
                json_object_object_add(res, "id", json_object_new_string(rid));
                json_object_object_add(res, "mac", json_object_new_string(mac_buf));
                json_object_object_add(res, "ip", json_object_new_string(rip));
                json_object_object_add(res, "name", json_object_new_string(rname[0] ? rname : rid));
                json_object_object_add(res, "enabled", json_object_new_boolean(1));
                json_object_array_add(rarr, res);
                json_object_object_add(dcfg, "reservations", rarr);
                if (!dry_run) {
                    int rc = jmx_dhcp_service_set(dcfg);
                    json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
                    json_object_object_add(resp, "status", json_object_new_string(rc == 0 ? "applied" : "failed"));
                } else {
                    json_object_object_add(resp, "ok", json_object_new_boolean(1));
                    json_object_object_add(resp, "status", json_object_new_string("dry_run"));
                }
                json_object_put(dcfg);
                json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
                json_object_object_add(resp, "action", json_object_new_string("dhcp_reserve"));
                jmx_app_audit_log("app", "", "client.dhcp_reserve", "medium", mac_buf, "", "");
            }
        } else if (!strcmp(action, "dhcp_release")) {
            char rid[64]; snprintf(rid, sizeof(rid), "app_%s", mac_buf);
            for (char *p = rid; *p; p++) if (*p == ':') *p = '_';
            if (!dry_run) {
                int rc = jmx_dhcp_reservation_delete(rid);
                json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
                json_object_object_add(resp, "status", json_object_new_string(rc == 0 ? "applied" : "failed"));
            } else {
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "status", json_object_new_string("dry_run"));
            }
            json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
            json_object_object_add(resp, "action", json_object_new_string("dhcp_release"));
            jmx_app_audit_log("app", "", "client.dhcp_release", "medium", mac_buf, "", "");
        } else if (!strcmp(action, "kick")) {
            char ip_buf[64] = {0};
            struct json_object *cp = json_object_new_object();
            json_object_object_add(cp, "mac", json_object_new_string(mac_buf));
            struct json_object *cr = jmx_db_api_client_get(cp);
            json_object_put(cp);
            if (cr) {
                struct json_object *cd = NULL;
                json_object_object_get_ex(cr, "data", &cd);
                struct json_object *co = NULL;
                if (cd) json_object_object_get_ex(cd, "client", &co);
                if (co) { const char *ip = nc_json_str_def(co, "ip", ""); if (ip[0]) snprintf(ip_buf, sizeof(ip_buf), "%s", ip); }
                json_object_put(cr);
            }
            if (!ip_buf[0]) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("client_not_online"));
                status = 400;
            } else if (dry_run) {
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
                json_object_object_add(resp, "action", json_object_new_string("kick"));
                json_object_object_add(resp, "status", json_object_new_string("dry_run"));
            } else {
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "conntrack -D -s %s 2>/dev/null; conntrack -D -d %s 2>/dev/null", ip_buf, ip_buf);
                system(cmd);
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "mac", json_object_new_string(mac_buf));
                json_object_object_add(resp, "action", json_object_new_string("kick"));
                json_object_object_add(resp, "status", json_object_new_string("applied"));
                json_object_object_add(resp, "note", json_object_new_string("conntrack flushed"));
                jmx_app_audit_log("app", "", "client.kick", "medium", mac_buf, "", "");
            }
        } else {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("unsupported_action"));
            json_object_object_add(resp, "message", json_object_new_string("Supported: block, unblock, kick, rate_limit, rate_limit_remove, dhcp_reserve, dhcp_release"));
            status = 501;
        }
    } else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/connections") && !strcmp(req.method, "GET")) {
        /* /api/v1/clients/{mac}/connections */
        const char *mac_part = req.path + 16;
        char mac_buf[32] = {0};
        const char *slash = strchr(mac_part, '/');
        if (slash) { size_t len = slash - mac_part; if (len < sizeof(mac_buf)) strncpy(mac_buf, mac_part, len); }
        struct json_object *params = json_object_new_object();
        json_object_object_add(params, "mac", json_object_new_string(mac_buf));
        resp = app_ubus_invoke("client_connections", params);
        json_object_put(params);
    }
    /* ── Client Traffic History ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/traffic-history") && !strcmp(req.method, "GET")) {
        const char *mac_part = req.path + 16;
        char mac_buf[32] = {0};
        const char *slash = strchr(mac_part, '/');
        if (slash) { size_t len = slash - mac_part; if (len < sizeof(mac_buf)) strncpy(mac_buf, mac_part, len); }
        struct json_object *params = json_object_new_object();
        json_object_object_add(params, "mac", json_object_new_string(mac_buf));
        resp = app_ubus_invoke("client_traffic_history", params);
        json_object_put(params);
    }
    /* ── Client Online History ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/online-history") && !strcmp(req.method, "GET")) {
        const char *mac_part = req.path + 16;
        char mac_buf[32] = {0};
        const char *slash = strchr(mac_part, '/');
        if (slash) { size_t len = slash - mac_part; if (len < sizeof(mac_buf)) strncpy(mac_buf, mac_part, len); }
        struct json_object *params = json_object_new_object();
        json_object_object_add(params, "mac", json_object_new_string(mac_buf));
        resp = app_ubus_invoke("client_online_history", params);
        json_object_put(params);
    }
    /* ── Client Apps (per-device active apps) ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/apps") && !strcmp(req.method, "GET")) {
        /* /api/v1/clients/{mac}/apps — forward to ubus apps with mac filter */
        resp = app_ubus_invoke("apps", NULL);
    }
    /* ── App Search (signature DB) ── */
    else if (!strcmp(req.path, "/api/v1/signatures/apps") && !strcmp(req.method, "GET")) {
        resp = app_ubus_invoke("signature_db_apps", NULL);
    }
    /* ── App Icon ── */
    else if (!strncmp(req.path, "/api/v1/signatures/apps/", 24) && strstr(req.path, "/icon") && !strcmp(req.method, "GET")) {
        /* /api/v1/signatures/apps/{app_id}/icon — placeholder */
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("not_implemented"));
        json_object_object_add(resp, "message", json_object_new_string("App icon serving not yet implemented"));
        status = 501;
    }
    /* ── Client Policies (CRUD) ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/policies") && !strcmp(req.method, "GET")) {
        /* /api/v1/clients/{mac}/policies — list network control rules for this client */
        resp = jmx_network_control_get();
    }
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/policies") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        /* /api/v1/clients/{mac}/policies — create policy via network control */
        if (body_json) {
            struct json_object *policy_type = NULL;
            json_object_object_get_ex(body_json, "type", &policy_type);
            const char *type_str = policy_type ? json_object_get_string(policy_type) : "";
            int dry_run = nc_json_bool_def(body_json, "dry_run", 0);
            resp = json_object_new_object();
            if (!type_str[0]) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("missing_type"));
                status = 400;
            } else if (!strcmp(type_str, "app_block") || !strcmp(type_str, "category_block")) {
                /* Map to network_control app_rules */
                struct json_object *target = NULL;
                json_object_object_get_ex(body_json, "target", &target);
                const char *app_id = nc_json_str_def(target, "app_id", "");
                const char *app_name = nc_json_str_def(target, "app_name", "");
                struct json_object *app_rule = json_object_new_object();
                char rule_id[128];
                snprintf(rule_id, sizeof(rule_id), "policy_app_%s", app_id[0] ? app_id : "unknown");
                json_object_object_add(app_rule, "id", json_object_new_string(rule_id));
                json_object_object_add(app_rule, "name", json_object_new_string(app_name[0] ? app_name : rule_id));
                json_object_object_add(app_rule, "action", json_object_new_string("block"));
                struct json_object *ids_arr = json_object_new_array();
                if (app_id[0]) json_object_array_add(ids_arr, json_object_new_string(app_id));
                json_object_object_add(app_rule, "app_ids", ids_arr);
                struct json_object *rules_arr = json_object_new_array();
                json_object_array_add(rules_arr, app_rule);
                struct json_object *netctl_cfg = json_object_new_object();
                json_object_object_add(netctl_cfg, "app_rules", rules_arr);
                if (!dry_run) {
                    jmx_network_control_save(netctl_cfg);
                    jmx_network_control_apply(NULL);
                }
                json_object_put(netctl_cfg);
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "policy_id", json_object_new_string(rule_id));
                json_object_object_add(resp, "status", json_object_new_string(dry_run ? "dry_run" : "applied"));
                jmx_app_audit_log("app", "", "client.policy.create", "medium", rule_id, "", "");
            } else if (!strcmp(type_str, "rate_limit")) {
                struct json_object *limit = NULL;
                json_object_object_get_ex(body_json, "limit", &limit);
                int down = nc_json_int_def(limit, "down_kbps", 0);
                int up = nc_json_int_def(limit, "up_kbps", 0);
                if (!dry_run) {
                    const char *mac_part = req.path + 16;
                    char mac_buf[32] = {0};
                    const char *slash = strchr(mac_part, '/');
                    if (slash) { size_t len = slash - mac_part; if (len < sizeof(mac_buf)) strncpy(mac_buf, mac_part, len); }
                    nc_client_rate_limit_set(mac_buf, "", up, down, "policy rate limit");
                    jmx_flow_control_apply(NULL);
                }
                json_object_object_add(resp, "ok", json_object_new_boolean(1));
                json_object_object_add(resp, "status", json_object_new_string(dry_run ? "dry_run" : "applied"));
            } else {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("unsupported_policy_type"));
                json_object_object_add(resp, "message", json_object_new_string("Supported: app_block, category_block, rate_limit"));
                status = 501;
            }
            json_object_object_add(resp, "ts", json_object_new_int64(time(NULL)));
        } else {
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("empty_body"));
            status = 400;
        }
    }
    /* ── Client WAN Policy ── */
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/wan-policy") && !strcmp(req.method, "GET")) {
        resp = jmx_netconfig_wan_list();
    }
    else if (!strncmp(req.path, "/api/v1/clients/", 16) && strstr(req.path, "/wan-policy") && (!strcmp(req.method, "PATCH") || !strcmp(req.method, "PUT"))) {
        /* Placeholder — WAN per-client policy needs route subsystem integration */
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("not_implemented"));
        json_object_object_add(resp, "message", json_object_new_string("Per-client WAN policy requires route subsystem integration"));
        status = 501;
    }
    /* ── Network Diagnostics ── */
    else if (!strcmp(req.path, "/api/v1/diagnostics/ping") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("ping", body_json);
    }
    else if (!strcmp(req.path, "/api/v1/diagnostics/traceroute") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("traceroute", body_json);
    }
    else if (!strcmp(req.path, "/api/v1/diagnostics/nslookup") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("nslookup", body_json);
    }
    else if (!strcmp(req.path, "/api/v1/diagnostics/speedtest") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("speedtest", body_json);
    }
    /* ── WiFi ── */
    else if (!strcmp(req.path, "/api/v1/wifi/config") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("wifi_config");
        if (!resp) {
            resp = app_ubus_invoke("wifi_config", NULL);
            if (resp) jmx_cache_put("wifi_config", resp, 10);
        }
    }
    else if (!strcmp(req.path, "/api/v1/wifi/config") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("wifi_config_save", body_json);
        jmx_cache_invalidate("wifi_config");
    }
    else if (!strcmp(req.path, "/api/v1/wifi/config/apply") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("wifi_config_apply", body_json);
        jmx_cache_invalidate("wifi_config");
    }
    else if (!strcmp(req.path, "/api/v1/wifi/status") && !strcmp(req.method, "GET")) {
        resp = jmx_cache_get("wifi_status");
        if (!resp) {
            resp = app_ubus_invoke("wifi_status", NULL);
            if (resp) jmx_cache_put("wifi_status", resp, 5);
        }
    }
    else if (!strcmp(req.path, "/api/v1/wifi/scan") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("wifi_config_scan", body_json);
    }
    /* ── Multicast ── */
    else if (!strcmp(req.path, "/api/v1/services/multicast") && !strcmp(req.method, "GET")) {
        resp = jmx_multicast_service_get();
    }
    else if (!strcmp(req.path, "/api/v1/services/multicast") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_multicast_service_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strcmp(req.path, "/api/v1/services/multicast/apply") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int dry = nc_json_bool_def(body_json, "dry_run", 0);
        int rc = jmx_multicast_service_apply(dry);
        struct json_object *d = json_object_new_object();
        json_object_object_add(d, "ok", json_object_new_boolean(rc == 0));
        resp = jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, d);
    }
    /* ── Work Mode ── */
    else if (!strcmp(req.path, "/api/v1/system/work-mode") && !strcmp(req.method, "GET")) {
        resp = app_ubus_invoke("work_mode_get", NULL);
    }
    else if (!strcmp(req.path, "/api/v1/system/work-mode/preview") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("work_mode_preview", body_json);
    }
    else if (!strcmp(req.path, "/api/v1/system/work-mode/apply") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("work_mode_apply", body_json);
    }
    else if (!strcmp(req.path, "/api/v1/system/work-mode/rollback") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = app_ubus_invoke("work_mode_rollback", body_json);
    }
    /* ── Log Center (advanced) ── */
    else if (!strcmp(req.path, "/api/v1/logs/query") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_log_center_query(body_json);
    }
    else if (!strcmp(req.path, "/api/v1/logs/export") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_log_center_export(body_json);
    }
    else if (!strcmp(req.path, "/api/v1/logs/clear") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_log_center_clear(body_json);
    }
    else if (!strcmp(req.path, "/api/v1/logs/events/search") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_log_center_event_search(body_json);
    }
    else if (!strcmp(req.path, "/api/v1/logs/events") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_log_center_event_add(body_json);
    }
    else if (!strcmp(req.path, "/api/v1/logs/alarms") && !strcmp(req.method, "GET")) {
        resp = jmx_log_center_alarm_get(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/logs/alarms/summary") && !strcmp(req.method, "GET")) {
        resp = jmx_log_center_alarm_summary(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/logs/warning-rules") && !strcmp(req.method, "GET")) {
        resp = jmx_log_center_warning_rules_get();
    }
    else if (!strcmp(req.path, "/api/v1/logs/warning-rules") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_log_center_warning_rules_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strcmp(req.path, "/api/v1/logs/channels") && !strcmp(req.method, "GET")) {
        resp = jmx_log_center_channels_get();
    }
    else if (!strcmp(req.path, "/api/v1/logs/channels") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_log_center_channels_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    else if (!strcmp(req.path, "/api/v1/logs/delivery/stats") && !strcmp(req.method, "GET")) {
        resp = jmx_log_center_delivery_stats();
    }
    else if (!strcmp(req.path, "/api/v1/logs/settings") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_log_center_settings_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── Services Status ── */
    else if (!strcmp(req.path, "/api/v1/system/services") && !strcmp(req.method, "GET")) {
        resp = jmx_system_services_status(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/system/mounts") && !strcmp(req.method, "GET")) {
        resp = jmx_system_mounts_status(NULL);
    }
    /* ── Signature DB (advanced) ── */
    else if (!strcmp(req.path, "/api/v1/signatures/rules") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_rules(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/signatures/carriers") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_carriers(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/signatures/domain-groups") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_domain_groups(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/signatures/domains") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_domains(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/signatures/vendors") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_device_vendors(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/signatures/device-types") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_device_types(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/signatures/fingerprints") && !strcmp(req.method, "GET")) {
        resp = jmx_signature_db_fingerprint_rules(NULL);
    }
    /* ── Disabled Functions ── */
    else if (!strcmp(req.path, "/api/v1/system/disabled-functions") && !strcmp(req.method, "GET")) {
        resp = jmx_system_disabled_functions_get();
    }
    else if (!strcmp(req.path, "/api/v1/system/disabled-functions") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_system_disabled_functions_set(body_json);
    }
    /* ── Cron ── */
    else if (!strcmp(req.path, "/api/v1/system/cron") && !strcmp(req.method, "GET")) {
        resp = jmx_system_cron_get(NULL);
    }
    /* ── Hybrid Lines ── */
    else if (!strcmp(req.path, "/api/v1/network/hybrid-lines") && !strcmp(req.method, "GET")) {
        resp = jmx_netconfig_hybrid_line_list(NULL);
    }
    else if (!strcmp(req.path, "/api/v1/network/hybrid-lines") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int rc = jmx_netconfig_hybrid_line_set(body_json);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    }
    /* ── Tasks (async) ── */
    else if (!strcmp(req.path, "/api/v1/tasks") && !strcmp(req.method, "GET")) {
        resp = app_ubus_invoke("tasks_list", NULL);
    }
    /* ── Logs ── */
    else if (!strcmp(req.path, "/api/v1/logs")) {
        resp = jmx_cache_get("logs");
        if (!resp) {
            resp = app_ubus_invoke("log_center_get", NULL);
            if (resp) jmx_cache_put("logs", resp, 5);
        }
    }
    /* ── Events SSE ── */
    else if (!strcmp(req.path, "/api/v1/events/stream")) {
        http_send_sse_header(fd);
        jmx_events_fd_add(fd);
        free(device_id);
        json_object_put(body_json);
        /* Don't close fd — keep alive for SSE */
        return;
    }
    /* ── Admin avatar ── */
    else if (!strcmp(req.path, "/api/v1/system/admin/avatar") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *out = json_object_new_object();
        int ok = jmx_admin_avatar_set(body_json, out) == 0;
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        if (!ok) {
            struct json_object *err = NULL;
            if (json_object_object_get_ex(out, "error", &err) && err) json_object_object_add(resp, "error", json_object_get(err));
            struct json_object *msg = NULL;
            if (json_object_object_get_ex(out, "message", &msg) && msg) json_object_object_add(resp, "message", json_object_get(msg));
            status = 400;
        } else {
            struct json_object *u = NULL, *av = NULL;
            if (json_object_object_get_ex(out, "username", &u) && u) json_object_object_add(resp, "username", json_object_get(u));
            if (json_object_object_get_ex(out, "avatar_url", &av) && av) json_object_object_add(resp, "avatar_url", json_object_get(av));
        }
        const char *uname = app_nc_json_str(body_json, "username", "");
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.admin.avatar", ok ? "low" : "medium",
            uname[0] ? uname : "", "", "");
        json_object_put(out);
    }
    /* ── Admin rename ── */
    else if (!strcmp(req.path, "/api/v1/system/admin/rename") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *out = json_object_new_object();
        int ok = jmx_admin_rename(body_json, out) == 0;
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        if (!ok) {
            struct json_object *err = NULL;
            if (json_object_object_get_ex(out, "error", &err) && err) json_object_object_add(resp, "error", json_object_get(err));
            struct json_object *msg = NULL;
            if (json_object_object_get_ex(out, "message", &msg) && msg) json_object_object_add(resp, "message", json_object_get(msg));
            status = 400;
        } else {
            struct json_object *newu = NULL;
            if (json_object_object_get_ex(out, "new_username", &newu) && newu) json_object_object_add(resp, "username", json_object_get(newu));
            json_object_object_add(resp, "rpcd_reloaded", json_object_new_boolean(1));
            json_object_object_add(resp, "session_invalidated", json_object_new_boolean(1));
        }
        const char *old_user = app_nc_json_str(body_json, "old_username", "");
        const char *new_user = app_nc_json_str(body_json, "new_username", "");
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.admin.rename", ok ? "high" : "medium",
            old_user[0] ? old_user : "", new_user[0] ? new_user : "", "");
        json_object_put(out);
    }
    /* ── Admin password ── */
    else if (!strcmp(req.path, "/api/v1/system/admin/password") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *out = json_object_new_object();
        int ok = jmx_admin_password_set(body_json, out) == 0;
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        if (!ok) {
            struct json_object *err = NULL;
            if (json_object_object_get_ex(out, "error", &err) && err) json_object_object_add(resp, "error", json_object_get(err));
            struct json_object *msg = NULL;
            if (json_object_object_get_ex(out, "message", &msg) && msg) json_object_object_add(resp, "message", json_object_get(msg));
            status = 400;
        }
        const char *username = app_nc_json_str(body_json, "username", "");
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.admin.password", ok ? "high" : "medium",
            username[0] ? username : "", "", "");
        json_object_put(out);
    }
    /* ── Startup service action ── */
    /* ── Kernel restore defaults ── */
    else if (!strcmp(req.path, "/api/v1/system/kernel/restore-defaults") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_system_kernel_restore_defaults(body_json);
        if (!resp) { status = 500; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("internal_error")); }
        else {
            struct json_object *okv = NULL;
            if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.kernel.restore_defaults", "high", "", "", "");
    }
    /* ── CPU Interrupt Affinity ── */
    else if (!strcmp(req.path, "/api/v1/system/advanced/cpu-interrupt") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *d = json_object_new_object();
        int rc = jmx_system_cpu_interrupt_set(body_json, d);
        resp = jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, d);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.cpu_interrupt.set", "high", nc_json_str_def(body_json, "irq", ""), "", "");
    }
    /* ── SSH Idle Timeout ── */
    else if (!strcmp(req.path, "/api/v1/system/ssh/idle-timeout") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *d = json_object_new_object();
        int rc = jmx_system_ssh_idle_timeout_set(body_json, d);
        resp = jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, d);
    }
    /* ═══ Container Service ═══ */
    else if (!strcmp(req.path, "/api/v1/container_service") && !strcmp(req.method, "GET")) {
        resp = jmx_container_service_get();
    }
    else if (!strcmp(req.path, "/api/v1/container_service/docker") && !strcmp(req.method, "GET")) {
        resp = jmx_container_docker_get();
    }
    else if (!strcmp(req.path, "/api/v1/container_service/lxc") && !strcmp(req.method, "GET")) {
        resp = jmx_container_lxc_get();
    }
    /* ── Docker container actions ── */
    else if (!strncmp(req.path, "/api/v1/container_service/docker/container/", 44)) {
        const char *rest = req.path + 44;
        char id_buf[128] = {0};
        const char *slash = strchr(rest, '/');
        const char *action = NULL;
        if (slash) {
            size_t len = slash - rest;
            if (len < sizeof(id_buf)) strncpy(id_buf, rest, len);
            action = slash + 1;
        } else {
            snprintf(id_buf, sizeof(id_buf), "%s", rest);
        }
        if (!id_buf[0]) {
            status = 400; resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("missing_container_id"));
        } else if (!action && !strcmp(req.method, "DELETE")) {
            /* DELETE container */
            struct json_object *d = json_object_new_object();
            jmx_docker_container_remove(id_buf, body_json, d);
            resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.container.remove", "high", id_buf, "", "");
        } else if (!action && !strcmp(req.method, "POST")) {
            /* POST container create */
            struct json_object *d = json_object_new_object();
            jmx_docker_container_create(body_json, d);
            resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.container.create", "medium", "", "", "");
        } else if (action && !strcmp(action, "start") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_start(id_buf, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "stop") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_stop(id_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.container.stop", "medium", id_buf, "", "");
        } else if (action && !strcmp(action, "restart") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_restart(id_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.container.restart", "medium", id_buf, "", "");
        } else if (action && !strcmp(action, "pause") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_pause(id_buf, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "unpause") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_unpause(id_buf, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "rename") && !strcmp(req.method, "PUT")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_rename(id_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "restart-policy") && !strcmp(req.method, "PUT")) {
            struct json_object *d = json_object_new_object(); jmx_docker_container_restart_policy(id_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "logs") && !strcmp(req.method, "GET")) {
            resp = jmx_docker_container_logs(id_buf, body_json);
        } else if (action && !strcmp(action, "stats") && !strcmp(req.method, "GET")) {
            resp = jmx_docker_container_stats(id_buf);
        } else {
            status = 404; resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("not_found"));
        }
    }
    /* ── Docker image actions ── */
    else if (!strncmp(req.path, "/api/v1/container_service/docker/image/", 39)) {
        const char *rest = req.path + 39;
        if (!strcmp(rest, "pull") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_image_pull(body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.image.pull", "medium", nc_json_str_def(body_json, "image", ""), "", "");
        } else if (!strcmp(rest, "prune") && !strcmp(req.method, "POST")) {
            resp = jmx_docker_image_prune(body_json);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.image.prune", "high", "", "", "");
        } else {
            /* DELETE /image/{id} */
            char img_id[128]; snprintf(img_id, sizeof(img_id), "%s", rest);
            if (img_id[0] && !strcmp(req.method, "DELETE")) {
                struct json_object *d = json_object_new_object(); jmx_docker_image_remove(img_id, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
                jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.image.remove", "medium", img_id, "", "");
            } else { status = 404; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("not_found")); }
        }
    }
    /* ── Docker network actions ── */
    else if (!strncmp(req.path, "/api/v1/container_service/docker/network/", 41)) {
        const char *rest = req.path + 41;
        if (!strcmp(rest, "create") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_network_create(body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (!strcmp(rest, "prune") && !strcmp(req.method, "POST")) {
            resp = jmx_docker_network_prune();
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.network.prune", "high", "", "", "");
        } else {
            char net_id[128]; snprintf(net_id, sizeof(net_id), "%s", rest);
            if (net_id[0] && !strcmp(req.method, "DELETE")) {
                struct json_object *d = json_object_new_object(); jmx_docker_network_remove(net_id, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
                jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.network.remove", "high", net_id, "", "");
            } else { status = 404; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("not_found")); }
        }
    }
    /* ── Docker volume actions ── */
    else if (!strncmp(req.path, "/api/v1/container_service/docker/volume/", 40)) {
        const char *rest = req.path + 40;
        if (!strcmp(rest, "create") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_docker_volume_create(body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (!strcmp(rest, "prune") && !strcmp(req.method, "POST")) {
            resp = jmx_docker_volume_prune();
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.volume.prune", "high", "", "", "");
        } else {
            char vol_name[256]; snprintf(vol_name, sizeof(vol_name), "%s", rest);
            if (vol_name[0] && !strcmp(req.method, "DELETE")) {
                struct json_object *d = json_object_new_object(); jmx_docker_volume_remove(vol_name, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
                jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.volume.remove", "high", vol_name, "", "");
            } else { status = 404; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("not_found")); }
        }
    }
    /* ── Docker service actions ── */
    else if (!strncmp(req.path, "/api/v1/container_service/docker/service/", 41)) {
        const char *action = req.path + 41;
        if (!strcmp(action, "status") && !strcmp(req.method, "GET")) {
            resp = jmx_docker_service_status();
        } else if (!strcmp(req.method, "POST") && (!strcmp(action, "start") || !strcmp(action, "stop") || !strcmp(action, "restart") || !strcmp(action, "reload"))) {
            struct json_object *d = json_object_new_object();
            jmx_docker_service_action(action, d);
            resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.service", strcmp(action, "stop") == 0 ? "high" : "medium", action, "", "");
        } else { status = 404; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("not_found")); }
    }
    /* ── Docker config ── */
    else if (!strcmp(req.path, "/api/v1/container_service/docker/config") && !strcmp(req.method, "GET")) {
        resp = jmx_docker_config_get();
    }
    else if (!strcmp(req.path, "/api/v1/container_service/docker/config") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *d = json_object_new_object();
        jmx_docker_config_set(body_json, d);
        resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "docker.config.set", "high", "", "", "");
    }
    /* ── LXC container actions ── */
    else if (!strncmp(req.path, "/api/v1/container_service/lxc/container/", 40)) {
        const char *rest = req.path + 40;
        char name_buf[128] = {0};
        const char *slash = strchr(rest, '/');
        const char *action = NULL;
        if (slash) {
            size_t len = slash - rest;
            if (len < sizeof(name_buf)) strncpy(name_buf, rest, len);
            action = slash + 1;
        } else {
            snprintf(name_buf, sizeof(name_buf), "%s", rest);
        }
        if (!name_buf[0]) {
            status = 400; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("missing_container_name"));
        } else if (!action && !strcmp(req.method, "DELETE")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_destroy(name_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "lxc.container.destroy", "high", name_buf, "", "");
        } else if (!action && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_create(body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "lxc.container.create", "high", "", "", "");
        } else if (action && !strcmp(action, "start") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_start(name_buf, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "stop") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_stop(name_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "lxc.container.stop", "medium", name_buf, "", "");
        } else if (action && !strcmp(action, "restart") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_restart(name_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "lxc.container.restart", "medium", name_buf, "", "");
        } else if (action && !strcmp(action, "clone") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_clone(name_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strcmp(action, "snapshot") && !strcmp(req.method, "POST")) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_snapshot(name_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
        } else if (action && !strncmp(action, "snapshot/", 9)) {
            const char *snap = action + 9;
            const char *restore_slash = strstr(snap, "/restore");
            if (restore_slash && !strcmp(req.method, "POST")) {
                char snap_buf[128]; size_t slen = restore_slash - snap;
                if (slen < sizeof(snap_buf)) { strncpy(snap_buf, snap, slen); snap_buf[slen] = 0; }
                struct json_object *d = json_object_new_object(); jmx_lxc_container_snapshot_restore(name_buf, snap_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
                jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "lxc.snapshot.restore", "high", name_buf, snap_buf, "");
            } else { status = 404; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("not_found")); }
        } else if (action && !strcmp(action, "config") && !strcmp(req.method, "GET")) {
            resp = jmx_lxc_container_config_get(name_buf);
        } else if (action && !strcmp(action, "config") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
            struct json_object *d = json_object_new_object(); jmx_lxc_container_config_set(name_buf, body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id, "lxc.container.config.set", "high", name_buf, "", "");
        } else if (action && !strcmp(action, "stats") && !strcmp(req.method, "GET")) {
            resp = jmx_lxc_container_stats(name_buf);
        } else if (action && !strcmp(action, "processes") && !strcmp(req.method, "GET")) {
            resp = jmx_lxc_container_processes(name_buf);
        } else if (action && !strcmp(action, "logs") && !strcmp(req.method, "GET")) {
            resp = jmx_lxc_container_logs(name_buf, body_json);
        } else {
            status = 404; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("not_found"));
        }
    }
    /* ── LXC global config ── */
    else if (!strcmp(req.path, "/api/v1/container_service/lxc/config") && !strcmp(req.method, "GET")) {
        resp = jmx_lxc_config_get();
    }
    else if (!strcmp(req.path, "/api/v1/container_service/lxc/config") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        struct json_object *d = json_object_new_object(); jmx_lxc_config_set(body_json, d); resp = jmx_gen_api_response_data(API_CODE_SUCCESS, d);
    }
    /* ── LXC templates ── */
    else if (!strcmp(req.path, "/api/v1/container_service/lxc/templates") && !strcmp(req.method, "GET")) {
        resp = jmx_lxc_templates_get();
    }
    /* ── System startup service action ── */
    else if (!strcmp(req.path, "/api/v1/system/startup/service-action") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_system_startup_service_action(body_json);
        if (!resp) { status = 500; resp = json_object_new_object(); json_object_object_add(resp, "ok", json_object_new_boolean(0)); json_object_object_add(resp, "error", json_object_new_string("internal_error")); }
        else {
            struct json_object *okv = NULL;
            if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        }
        if (resp) {
            int ok = 0;
            struct json_object *okv2 = NULL;
            if (json_object_object_get_ex(resp, "ok", &okv2) && okv2) ok = json_object_get_boolean(okv2);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                "system.startup.service-action", ok ? "medium" : "low",
                app_nc_json_str(body_json, "service", ""), "", app_nc_json_str(body_json, "action", ""));
        }
    }
    else if (!strcmp(req.path, "/api/v1/system/startup/rc-local") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        const char *content = app_nc_json_str(body_json, "content", "");
        int confirm = app_nc_json_bool(body_json, "confirm_no_exit0", 0);
        resp = json_object_new_object();
        struct json_object *data = json_object_new_object();
        int ok = jmx_system_rc_local_apply(content, confirm, data) == 0;
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        json_object_object_add(resp, "data", data);
        if (!ok) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.startup.rc-local", ok ? "medium" : "low",
            "/etc/rc.local", "", confirm ? "confirm_no_exit0" : "strict");
    }
    /* ── Crontab apply ── */
    else if (!strcmp(req.path, "/api/v1/system/crontab/apply") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        const char *text = app_nc_json_str(body_json, "text", "");
        int bad = 0, bad_line = 0;
        {
            const char *p = text;
            int line = 1, fields = 0, in_field = 0;
            for (; *p; p++) {
                if (*p == '\n') {
                    if (fields > 0 && fields < 6) { bad = 1; bad_line = line; break; }
                    line++;
                    fields = 0; in_field = 0;
                } else if (*p == '#') {
                    while (*p && *p != '\n') p++;
                    if (*p) { line++; fields = 0; in_field = 0; }
                    if (!*p) break;
                } else if (*p == ' ' || *p == '\t') {
                    in_field = 0;
                } else {
                    if (!in_field) { fields++; in_field = 1; }
                }
            }
            if (!bad && fields > 0 && fields < 6) { bad = 1; bad_line = line; }
        }
        if (bad) {
            status = 400;
            resp = json_object_new_object();
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_cron_syntax"));
            struct json_object *data = json_object_new_object();
            json_object_object_add(data, "line", json_object_new_int(bad_line));
            json_object_object_add(data, "message", json_object_new_string("need 5 cron fields and command"));
            json_object_object_add(resp, "data", data);
        } else {
            resp = json_object_new_object();
            struct json_object *data = json_object_new_object();
            int ok = jmx_crontab_apply_text(text, data) == 0;
            json_object_object_add(resp, "ok", json_object_new_boolean(ok));
            if (ok) json_object_object_add(resp, "data", data);
            else { json_object_put(data); status = 500; }
        }
    }
    /* ── System time sync ── */
    else if (!strcmp(req.path, "/api/v1/system/time-sync/browser") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        int64_t ts = (int64_t)app_nc_json_int(body_json, "client_ts", 0);
        resp = json_object_new_object();
        struct json_object *data = json_object_new_object();
        int ok = jmx_system_time_sync_browser(ts, data) == 0;
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        json_object_object_add(resp, "data", data);
        if (!ok) status = 400;
    }
    else if (!strcmp(req.path, "/api/v1/system/time-sync/ntp") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = json_object_new_object();
        struct json_object *data = json_object_new_object();
        int ok = jmx_system_time_sync_ntp(data) == 0;
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        json_object_object_add(resp, "data", data);
        if (!ok) status = 500;
    }
    /* ── Flash: create backup ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/create_backup") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_flash_create_backup(body_json);
        struct json_object *okv = NULL;
        if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.flash.create_backup", "medium", "", "", "");
    }
    /* ── Flash: restore backup ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/restore_backup") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_flash_restore_backup(body_json);
        struct json_object *okv = NULL;
        if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.flash.restore_backup", "high", app_nc_json_str(body_json, "path", ""), "", "confirm");
    }
    /* ── Flash: upload firmware ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/upload_firmware") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_flash_upload_firmware(body_json);
        struct json_object *okv = NULL;
        if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.flash.upload_firmware", "medium", "", "", "");
    }
    /* ── Flash: sysupgrade ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/sysupgrade") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_flash_sysupgrade(body_json);
        struct json_object *okv = NULL;
        if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.flash.sysupgrade", "high", app_nc_json_str(body_json, "image_id", ""), "", "confirm");
    }
    /* ── Flash: factory reset ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/factory_reset") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_flash_factory_reset(body_json);
        struct json_object *okv = NULL;
        if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.flash.factory_reset", "high", "", "", "confirm");
    }
    /* ── Flash: preserve config (GET) ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/preserve_config") && !strcmp(req.method, "GET")) {
        resp = jmx_flash_preserve_config_get(body_json);
    }
    /* ── Flash: preserve config (POST) ── */
    else if (!strcmp(req.path, "/api/v1/system/flash/preserve_config") && (!strcmp(req.method, "POST") || !strcmp(req.method, "PUT"))) {
        resp = jmx_flash_preserve_config_set(body_json);
        struct json_object *okv = NULL;
        if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv)) status = 400;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "system.flash.preserve_config", "medium", "", "", "");
    }
    /* ── 404 ── */
    else {
        status = 404;
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "code", json_object_new_int(404));
        json_object_object_add(resp, "message", json_object_new_string("not found"));
    }

    if (resp) {
        http_send_json(fd, status, resp);
        json_object_put(resp);
    } else {
        http_send(fd, 500, "Internal Server Error", "text/plain", "error", 5);
    }

    free(device_id);
    close(fd);
    json_object_put(body_json);
}

static void client_fd_cb(struct uloop_fd *ufd, unsigned int events)
{
    (void)events;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    int cfd = accept(ufd->fd, (struct sockaddr *)&client_addr, &addrlen);
    if (cfd < 0) return;
    handle_client(cfd);
}

/* ══════════════════════════════════════════════════════════════════════
 * Lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

/* Periodic cache GC callback */
static void cache_gc_timer_cb(struct uloop_timeout *t)
{
    jmx_cache_gc();
    uloop_timeout_set(t, 30000);
}

int jmx_app_api_init(int port)
{
    if (port <= 0) port = APP_API_DEFAULT_PORT;
    if (app_db_init() != 0) {
        fprintf(stderr, "[app-api] failed to init db\n");
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        fprintf(stderr, "[app-api] bind port %d failed\n", port);
        return -1;
    }
    listen(fd, APP_API_BACKLOG);

    memset(g_sse_fds, 0, sizeof(g_sse_fds));
    g_sse_count = 0;

    g_listen_fd.fd = fd;
    g_listen_fd.cb = client_fd_cb;
    uloop_fd_add(&g_listen_fd, ULOOP_READ);

    /* Periodic cache GC every 30 seconds */
    static struct uloop_timeout cache_gc_timer;
    cache_gc_timer.cb = cache_gc_timer_cb;
    uloop_timeout_set(&cache_gc_timer, 30000);

    fprintf(stderr, "[app-api] listening on :%d\n", port);
    return 0;
}

void jmx_app_api_done(void)
{
    int i;
    for (i = 0; i < g_sse_count; i++) close(g_sse_fds[i]);
    g_sse_count = 0;
    if (g_listen_fd.fd >= 0) {
        uloop_fd_delete(&g_listen_fd);
        close(g_listen_fd.fd);
        g_listen_fd.fd = -1;
    }
    jmx_cache_done();
    if (g_app_db) { sqlite3_close(g_app_db); g_app_db = NULL; }
}
