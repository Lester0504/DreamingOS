// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * TVHome persistent control store (Package A) -- implementation.
 *
 * Pattern-B webd-resident module (see tvhome_store.h). Owns its tvhome_* tables
 * in the shared config DB and is called directly from api_tvhome.c. Theme spec
 * validation / canonicalization / display inheritance is delegated to the pure
 * tvhome_theme.c translation unit; this file adds persistence, the four version
 * numbers, the D1 session stub, and the frozen bootstrap/heartbeat/overview
 * shapes (PM-tvhome-package-a-contract.md §4-§7).
 */
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "tvhome_ws.h"
#include <sqlite3.h>
#include <json-c/json.h>

#include "tvhome_store.h"
#include "tvhome_theme.h"
#include "tvhome_ops.h"
#include "tvhome_assets.h"

#ifndef TVH_DB_PATH
#define TVH_DB_PATH            "/etc/dreamingwrt/config.db"
#endif
#define TVH_WS_URL             "/api/v1/tv/client/ws"
#define TVH_SESSION_TTL_SEC    3600           /* short-lived TV session (D1 stub) */
#define TVH_HEARTBEAT_SECONDS  60
#define TVH_ONLINE_WINDOW_SEC  180
#define TVH_MAX_ID             96
#define TVH_MAX_NAME           128

static const char *tvh_schema_sql =
    "CREATE TABLE IF NOT EXISTS tvhome_settings ("
    " id INTEGER PRIMARY KEY CHECK(id=1),"
    " config_version INTEGER NOT NULL DEFAULT 1,"
    " default_theme_id TEXT NOT NULL DEFAULT '',"
    " media_principal_id TEXT NOT NULL DEFAULT '',"
    " heartbeat_seconds INTEGER NOT NULL DEFAULT 60,"
    " online_window_seconds INTEGER NOT NULL DEFAULT 180,"
    " allow_local_edit INTEGER NOT NULL DEFAULT 0,"
    " allow_local_background INTEGER NOT NULL DEFAULT 0,"
    " exit_to_system INTEGER NOT NULL DEFAULT 1,"
    " pin_required INTEGER NOT NULL DEFAULT 0,"
    " pin_hash TEXT NOT NULL DEFAULT '',"
    " discovery_enabled INTEGER NOT NULL DEFAULT 1,"
    " modules_json TEXT NOT NULL DEFAULT '{}',"
    " updated_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS tvhome_theme ("
    " id TEXT PRIMARY KEY,"
    " name TEXT NOT NULL DEFAULT '',"
    " spec_json TEXT NOT NULL,"
    " revision INTEGER NOT NULL DEFAULT 1,"
    " schema_version INTEGER NOT NULL DEFAULT 1,"
    " is_default INTEGER NOT NULL DEFAULT 0,"
    " builtin INTEGER NOT NULL DEFAULT 0,"
    " created_at INTEGER NOT NULL DEFAULT 0,"
    " updated_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS tvhome_group ("
    " id TEXT PRIMARY KEY,"
    " name TEXT NOT NULL DEFAULT '',"
    " theme_id TEXT NOT NULL DEFAULT '',"
    " display_json TEXT NOT NULL DEFAULT '{}',"
    " created_at INTEGER NOT NULL DEFAULT 0,"
    " updated_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS tvhome_terminal ("
    " id TEXT PRIMARY KEY,"
    " name TEXT NOT NULL DEFAULT '',"
    " group_id TEXT NOT NULL DEFAULT '',"
    " theme_id TEXT NOT NULL DEFAULT '',"
    " media_principal_id TEXT NOT NULL DEFAULT '',"
    " display_json TEXT NOT NULL DEFAULT '{}',"
    " device_id TEXT NOT NULL DEFAULT '',"
    " model TEXT NOT NULL DEFAULT '',"
    " last_seen_ms INTEGER NOT NULL DEFAULT 0,"
    " reported_version TEXT NOT NULL DEFAULT '',"
    " applied_config_version INTEGER NOT NULL DEFAULT 0,"
    " foreground_module TEXT NOT NULL DEFAULT '',"
    " created_at INTEGER NOT NULL DEFAULT 0,"
    " updated_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS tvhome_principal ("
    " id TEXT PRIMARY KEY,"
    " terminal_id TEXT NOT NULL DEFAULT '',"
    " device_fingerprint TEXT NOT NULL DEFAULT '',"
    " revoked INTEGER NOT NULL DEFAULT 0,"
    " created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS tvhome_session ("
    " token TEXT PRIMARY KEY,"
    " terminal_id TEXT NOT NULL DEFAULT '',"
    " principal_id TEXT NOT NULL DEFAULT '',"
    " device_id TEXT NOT NULL DEFAULT '',"
    " expires_at_ms INTEGER NOT NULL DEFAULT 0,"
    " revoked INTEGER NOT NULL DEFAULT 0,"
    " created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS tvhome_activation ("
    " id TEXT PRIMARY KEY, device_id TEXT NOT NULL, device_json TEXT NOT NULL, poll_hash TEXT NOT NULL,"
    " code_hash TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', expires_at_ms INTEGER NOT NULL,"
    " created_at_ms INTEGER NOT NULL, terminal_id TEXT NOT NULL DEFAULT '', principal_id TEXT NOT NULL DEFAULT '');"
    "CREATE INDEX IF NOT EXISTS tvhome_activation_code ON tvhome_activation(code_hash);"
    "CREATE TABLE IF NOT EXISTS tvhome_device_profile (terminal_id TEXT PRIMARY KEY,profile_json TEXT NOT NULL);";

/* ---- error / success setters ---- */
static void tvh_reset(struct tvhome_err *err)
{
    if (err)
        err->http_status = 0;
}

static struct json_object *tvh_fail(struct tvhome_err *err, int status,
                                    const char *code, const char *field,
                                    const char *message)
{
    if (err) {
        err->http_status = status;
        snprintf(err->code, sizeof(err->code), "%s", code ? code : "internal_error");
        snprintf(err->field, sizeof(err->field), "%s", field ? field : "");
        snprintf(err->message, sizeof(err->message), "%s", message ? message : "");
    }
    return NULL;
}

/* ---- json field readers (borrowed refs) ---- */
static const char *jstr(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v) &&
        json_object_is_type(v, json_type_string))
        return json_object_get_string(v);
    return NULL;
}

static int jhas(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, k, &v);
}

static int64_t jint64(struct json_object *o, const char *k, int64_t dflt)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v) &&
        (json_object_is_type(v, json_type_int) ||
         json_object_is_type(v, json_type_double)))
        return (int64_t)json_object_get_int64(v);
    return dflt;
}

static int jbool(struct json_object *o, const char *k, int dflt)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v) &&
        json_object_is_type(v, json_type_boolean))
        return json_object_get_boolean(v) ? 1 : 0;
    return dflt;
}

static struct json_object *jobj(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v))
        return v;
    return NULL;
}

/* ---- sqlite column readers ---- */
static const char *col_text(sqlite3_stmt *st, int i)
{
    const unsigned char *t = sqlite3_column_text(st, i);
    return t ? (const char *)t : "";
}

static int64_t col_i64(sqlite3_stmt *st, int i)
{
    return (int64_t)sqlite3_column_int64(st, i);
}

/* ---- time / id / token ---- */
static int64_t now_ms(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        return (int64_t)time(NULL) * 1000;
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Fill buf with n hex chars of entropy (+NUL). Falls back to rand() if the
 * kernel RNG is unavailable; the token still lives only inside the config DB. */
static void hex_entropy(char *buf, size_t hexchars)
{
    size_t need = hexchars / 2;
    unsigned char raw[64];
    size_t got = 0;
    int fd;

    if (need > sizeof(raw))
        need = sizeof(raw);
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, raw, need);
        if (r > 0)
            got = (size_t)r;
        close(fd);
    }
    while (got < need)
        raw[got++] = (unsigned char)(rand() & 0xff);
    for (size_t i = 0; i < need; i++)
        snprintf(buf + i * 2, 3, "%02x", raw[i]);
    buf[need * 2] = '\0';
}

static void gen_id(const char *prefix, char *out, size_t outsz)
{
    char hex[25];
    hex_entropy(hex, 24);
    snprintf(out, outsz, "%s-%s", prefix, hex);
}

static void gen_token(char *out, size_t outsz)
{
    char hex[41];
    hex_entropy(hex, 40);
    snprintf(out, outsz, "tv_sess_%s", hex);
}

/* ---- schema / open / seed ---- */
static int tvh_exec(sqlite3 *db, const char *sql)
{
    char *errmsg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        if (errmsg)
            sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

static int tvh_theme_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int n = 0;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM tvhome_theme", -1, &st,
                           NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return n;
}

/* Build the built-in flow theme spec (schema-valid; canonicalized on seed). */
static struct json_object *tvh_builtin_spec(void)
{
    struct json_object *spec = json_object_new_object();
    struct json_object *bg = json_object_new_object();
    struct json_object *ss = json_object_new_object();
    struct json_object *home = json_object_new_object();
    struct json_object *nav = json_object_new_array();
    struct json_object *n0 = json_object_new_object();

    json_object_object_add(spec, "version", json_object_new_int(1));
    json_object_object_add(spec, "style", json_object_new_string("flow"));
    json_object_object_add(spec, "tokens", json_object_new_object());
    json_object_object_add(spec, "header", json_object_new_object());
    json_object_object_add(spec, "parental", json_object_new_object());

    json_object_object_add(bg, "mode", json_object_new_string("color"));
    json_object_object_add(bg, "color", json_object_new_string("#202326"));
    json_object_object_add(spec, "background", bg);

    json_object_object_add(ss, "enabled", json_object_new_boolean(1));
    json_object_object_add(ss, "mode", json_object_new_string("clock"));
    json_object_object_add(ss, "idleMinutes", json_object_new_int(10));
    json_object_object_add(spec, "screensaver", ss);

    json_object_object_add(home, "sections", json_object_new_array());
    json_object_object_add(spec, "home", home);

    json_object_object_add(n0, "id", json_object_new_string("home"));
    json_object_object_add(n0, "type", json_object_new_string("module"));
    json_object_object_add(n0, "module", json_object_new_string("home"));
    json_object_object_add(n0, "label", json_object_new_string("\xe9\xa6\x96\xe9\xa1\xb5"));
    json_object_array_add(nav, n0);
    json_object_object_add(spec, "nav", nav);
    return spec;
}

static void tvh_seed(sqlite3 *db)
{
    int64_t now = (int64_t)time(NULL);
    char sql[256];

    snprintf(sql, sizeof(sql),
             "INSERT OR IGNORE INTO tvhome_settings(id,config_version,updated_at)"
             " VALUES(1,1,%lld);", (long long)now);
    tvh_exec(db, sql);

    if (tvh_theme_count(db) == 0) {
        struct json_object *spec = tvh_builtin_spec();
        struct tvhome_theme_result r;
        struct json_object *canon = tvhome_theme_canonicalize(spec, &r);
        json_object_put(spec);
        if (canon) {
            const char *cs = json_object_to_json_string_ext(
                canon, JSON_C_TO_STRING_PLAIN);
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(db,
                    "INSERT INTO tvhome_theme(id,name,spec_json,revision,"
                    "schema_version,is_default,builtin,created_at,updated_at)"
                    " VALUES('theme-default',?,?,1,1,1,1,?,?);",
                    -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_text(st, 1, "\xe9\xbb\x98\xe8\xae\xa4\xe4\xb8\xbb\xe9\xa2\x98",
                                  -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, cs, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 3, now);
                sqlite3_bind_int64(st, 4, now);
                sqlite3_step(st);
                sqlite3_finalize(st);
            }
            tvh_exec(db, "UPDATE tvhome_settings SET default_theme_id="
                         "'theme-default' WHERE id=1;");
            json_object_put(canon);
        }
    }
}

static int tvh_open(sqlite3 **out, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    if (out)
        *out = NULL;
    if (!out) {
        tvh_fail(err, 500, "internal_error", "", "null db handle");
        return -1;
    }
    if (sqlite3_open(TVH_DB_PATH, &db) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        tvh_fail(err, 503, "service_not_ready", "", "config store unavailable");
        return -1;
    }
    sqlite3_busy_timeout(db, 3000);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON", NULL, NULL, NULL);
    if (tvh_exec(db, tvh_schema_sql) != 0 || tvhome_ops_schema(db) != 0) {
        sqlite3_close(db);
        tvh_fail(err, 503, "service_not_ready", "", "config schema unavailable");
        return -1;
    }
    tvh_seed(db);
    *out = db;
    return 0;
}

static int64_t tvh_config_version(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int64_t v = 1;
    if (sqlite3_prepare_v2(db, "SELECT config_version FROM tvhome_settings"
                               " WHERE id=1", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            v = col_i64(st, 0);
        sqlite3_finalize(st);
    }
    return v;
}

/* Monotonic, persisted config version. Bumped by every A mutation that can
 * change a terminal's effective config. Never derived from process time. */
static int64_t tvh_bump_config(sqlite3 *db)
{
    tvh_exec(db, "UPDATE tvhome_settings SET config_version=config_version+1"
                 " WHERE id=1;");
    return tvh_config_version(db);
}

/* Empty string -> JSON null (ungrouped / inherit), else a string node. */
static struct json_object *str_or_null(const char *s)
{
    if (!s || !*s)
        return NULL; /* json_object_object_add(..., NULL) stores a JSON null */
    return json_object_new_string(s);
}

/* forward decl: defined with the T client nodes, used earlier by bootstrap */
static struct json_object *theme_client_node(sqlite3 *db, const char *id);

/* THEME_COLS: id,name,spec_json,revision,schema_version,is_default */
#define THEME_COLS "id,name,spec_json,revision,schema_version,is_default,builtin,COALESCE((SELECT enabled FROM tvhome_theme_flags WHERE theme_id=tvhome_theme.id),1)"
static struct json_object *theme_obj_from_stmt(sqlite3_stmt *st, int with_spec)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(col_text(st, 0)));
    json_object_object_add(o, "name", json_object_new_string(col_text(st, 1)));
    json_object_object_add(o, "revision", json_object_new_int64(col_i64(st, 3)));
    json_object_object_add(o, "schema_version",
                           json_object_new_int64(col_i64(st, 4)));
    json_object_object_add(o, "is_default",
                           json_object_new_boolean(col_i64(st, 5) ? 1 : 0));
    json_object_object_add(o, "builtin", json_object_new_boolean(col_i64(st, 6)));
    json_object_object_add(o, "enabled", json_object_new_boolean(col_i64(st, 7)));
    if (with_spec) {
        struct json_object *spec = json_tokener_parse(col_text(st, 2));
        json_object_object_add(o, "spec", spec ? spec : json_object_new_object());
    }
    return o;
}

/* Load a theme row (with spec) by id. Returns NULL if absent. */
static struct json_object *theme_full_by_id(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;
    if (sqlite3_prepare_v2(db, "SELECT " THEME_COLS " FROM tvhome_theme"
                               " WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        o = theme_obj_from_stmt(st, 1);
    sqlite3_finalize(st);
    return o;
}

/* Return owned canonical spec object of theme id, or NULL if absent. */
static struct json_object *theme_spec_by_id(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *spec = NULL;
    if (!id || !*id)
        return NULL;
    if (sqlite3_prepare_v2(db, "SELECT spec_json FROM tvhome_theme WHERE id=?",
                           -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        spec = json_tokener_parse(col_text(st, 0));
    sqlite3_finalize(st);
    return spec;
}

static const char *scalar_text(sqlite3 *db, const char *sql, const char *arg,
                               char *buf, size_t bufsz)
{
    sqlite3_stmt *st = NULL;
    buf[0] = '\0';
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (arg)
            sqlite3_bind_text(st, 1, arg, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(buf, bufsz, "%s", col_text(st, 0));
        sqlite3_finalize(st);
    }
    return buf;
}

static int row_exists(sqlite3 *db, const char *sql, const char *arg)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (arg)
            sqlite3_bind_text(st, 1, arg, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            found = 1;
        sqlite3_finalize(st);
    }
    return found;
}

static int count_query(sqlite3 *db, const char *sql, const char *arg)
{
    sqlite3_stmt *st = NULL;
    int n = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (arg)
            sqlite3_bind_text(st, 1, arg, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return n;
}

/* Effective theme id for a terminal: terminal > group > global default. */
static void resolve_theme_id(sqlite3 *db, const char *term_theme,
                             const char *group_id, char *out, size_t outsz)
{
    out[0] = '\0';
    if (term_theme && *term_theme) {
        snprintf(out, outsz, "%s", term_theme);
        return;
    }
    if (group_id && *group_id) {
        char gt[TVH_MAX_ID] = "";
        scalar_text(db, "SELECT theme_id FROM tvhome_group WHERE id=?",
                    group_id, gt, sizeof(gt));
        if (*gt) {
            snprintf(out, outsz, "%s", gt);
            return;
        }
    }
    scalar_text(db, "SELECT default_theme_id FROM tvhome_settings WHERE id=1",
                NULL, out, outsz);
}

static struct json_object *group_display_layer(sqlite3 *db, const char *group_id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;
    if (!group_id || !*group_id)
        return NULL;
    if (sqlite3_prepare_v2(db, "SELECT display_json FROM tvhome_group WHERE id=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            o = json_tokener_parse(col_text(st, 0));
        sqlite3_finalize(st);
    }
    return o;
}

/* Resolve final {background,screensaver,source} for the given layers (§8). */
static struct json_object *resolve_display(sqlite3 *db, const char *eff_theme_id,
                                           const char *group_id,
                                           const char *term_disp_text)
{
    struct json_object *theme_spec = theme_spec_by_id(db, eff_theme_id);
    struct json_object *group_layer = group_display_layer(db, group_id);
    struct json_object *term_layer = NULL;
    struct json_object *res;

    if (term_disp_text && *term_disp_text)
        term_layer = json_tokener_parse(term_disp_text);
    res = tvhome_display_resolve(theme_spec, group_layer, term_layer);
    json_object_put(theme_spec);
    json_object_put(group_layer);
    json_object_put(term_layer);
    return res;
}

/* Live uses the same persisted provider, identity mapping and grant as
 * iptv_view.c. This read does not start a stream or claim media readiness. */
static struct json_object *tvh_live_capability(sqlite3 *db, const char *terminal)
{
    sqlite3_stmt *st=NULL;
    struct json_object *cfg=NULL,*modules=NULL,*live=NULL,*grant=NULL,*out=json_object_new_object();
    char principal[128]="";
    int pin=0,live_on=0,configured=0,provider_on=0,identity=0,permitted=0;
    if (sqlite3_prepare_v2(db,"SELECT g.pin_required,g.modules_json,COALESCE(NULLIF(t.media_principal_id,''),NULLIF(g.media_principal_id,''),'') FROM tvhome_settings g LEFT JOIN tvhome_terminal t ON t.id=?1 WHERE g.id=1",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,terminal?terminal:"",-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW){
            pin=sqlite3_column_int(st,0);
            modules=json_tokener_parse(col_text(st,1));
            snprintf(principal,sizeof(principal),"%s",col_text(st,2));
        }
    }
    sqlite3_finalize(st); st=NULL;
    if(modules)json_object_object_get_ex(modules,"live",&live);
    struct json_object *live_value=live;
    if(json_object_is_type(live,json_type_object))json_object_object_get_ex(live,"enabled",&live_value);
    live_on=(json_object_is_type(live_value,json_type_boolean)||json_object_is_type(live_value,json_type_int))&&json_object_get_int(live_value)==1;
    const char *provider=json_object_is_type(live,json_type_object)?jstr(live,"provider_id"):NULL;
    int local=!provider||!provider[0]||!strcmp(provider,"iptv.local");
    if(sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind='settings' AND id='main'",-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW)
        cfg=json_tokener_parse(col_text(st,0));
    sqlite3_finalize(st);st=NULL;
    configured=local&&json_object_is_type(cfg,json_type_object);
    provider_on=cfg&&jbool(cfg,"enabled",0);
    if(!strncmp(principal,"web:",4)&&principal[4])
        identity=row_exists(db,"SELECT 1 FROM web_users WHERE username=? AND status='enabled'",principal+4);
    if(identity&&sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind='viewers' AND json_extract(body,'$.principal_id')=?1",-1,&st,NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,principal,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW)grant=json_tokener_parse(col_text(st,0));
    }
    sqlite3_finalize(st);
    int64_t until=grant?jint64(grant,"expires_at",0):0;
    permitted=identity&&grant&&jbool(grant,"enabled",0)&&(!until||until>time(NULL))&&!pin;
    const char *reason=!configured?"provider_not_configured":!live_on?"live_disabled":!provider_on?"module_disabled":pin?"pin_required":!identity?"media_identity_unavailable":!permitted?"channel_not_authorized":"available";
    json_object_object_add(out,"available",json_object_new_boolean(configured));
    json_object_object_add(out,"enabled",json_object_new_boolean(configured&&provider_on&&live_on));
    json_object_object_add(out,"permitted",json_object_new_boolean(permitted));
    json_object_object_add(out,"reason",json_object_new_string(reason));
    json_object_object_add(out,"provider_id",configured?json_object_new_string("iptv.local"):NULL);
    json_object_object_add(out,"api_base",configured?json_object_new_string("/api/v1/iptv/client/"):NULL);
    json_object_object_add(out,"media_principal_id",identity?json_object_new_string(principal):NULL);
    json_object_put(cfg);json_object_put(modules);json_object_put(grant);
    return out;
}

/* home/settings/search are shell modules and never appear here. */
static struct json_object *tvh_capabilities(sqlite3 *db, const char *terminal)
{
    static const char *mods[] = { "live", "vod", "music", "photos", "files", "nvr", "apps" };
    struct json_object *caps = json_object_new_object();
    for (size_t i=0;i<sizeof(mods)/sizeof(mods[0]);i++) {
        if(!strcmp(mods[i],"live")) {json_object_object_add(caps,"live",tvh_live_capability(db,terminal));continue;}
        struct json_object *m=json_object_new_object();
        int available=!strcmp(mods[i],"apps");
        json_object_object_add(m,"available",json_object_new_boolean(available));
        json_object_object_add(m,"enabled",json_object_new_boolean(available));
        json_object_object_add(m,"permitted",json_object_new_boolean(available));
        json_object_object_add(m,"reason",json_object_new_string(available?"available":"provider_not_configured"));
        json_object_object_add(caps,mods[i],m);
    }
    return caps;
}

/* ===================== A settings + overview ===================== */
static struct json_object *settings_build(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = json_object_new_object();
    if (sqlite3_prepare_v2(db,
            "SELECT config_version,default_theme_id,media_principal_id,"
            "heartbeat_seconds,online_window_seconds,allow_local_edit,"
            "allow_local_background,exit_to_system,pin_required,"
            "discovery_enabled,modules_json FROM tvhome_settings WHERE id=1",
            -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *mods;
        json_object_object_add(o, "config_version",
                               json_object_new_int64(col_i64(st, 0)));
        json_object_object_add(o, "default_theme_id", str_or_null(col_text(st, 1)));
        json_object_object_add(o, "media_principal_id",
                               str_or_null(col_text(st, 2)));
        json_object_object_add(o, "heartbeat_seconds",
                               json_object_new_int64(col_i64(st, 3)));
        json_object_object_add(o, "online_window_seconds",
                               json_object_new_int64(col_i64(st, 4)));
        json_object_object_add(o, "allow_local_edit",
                               json_object_new_boolean(col_i64(st, 5) ? 1 : 0));
        json_object_object_add(o, "allow_local_background",
                               json_object_new_boolean(col_i64(st, 6) ? 1 : 0));
        json_object_object_add(o, "exit_to_system",
                               json_object_new_boolean(col_i64(st, 7) ? 1 : 0));
        json_object_object_add(o, "pin_required",
                               json_object_new_boolean(col_i64(st, 8) ? 1 : 0));
        json_object_object_add(o, "discovery_enabled",
                               json_object_new_boolean(col_i64(st, 9) ? 1 : 0));
        mods = json_tokener_parse(col_text(st, 10));
        json_object_object_add(o, "modules",
                               mods ? mods : json_object_new_object());
    }
    if (st)
        sqlite3_finalize(st);
    return o;
}

struct json_object *tvhome_settings_get(struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o;
    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    o = settings_build(db);
    sqlite3_close(db);
    return o;
}

static void set_int(sqlite3 *db, const char *col, int64_t v)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    snprintf(sql, sizeof(sql),
             "UPDATE tvhome_settings SET %s=? WHERE id=1", col);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, v);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

static void set_text(sqlite3 *db, const char *col, const char *v)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    snprintf(sql, sizeof(sql),
             "UPDATE tvhome_settings SET %s=? WHERE id=1", col);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, v ? v : "", -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

struct json_object *tvhome_settings_put(struct json_object *body, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    tvh_reset(err);
    if (!json_object_is_type(body, json_type_object))
        return tvh_fail(err, 400, "invalid_parameter", "settings", "Settings object required");
    if (tvh_open(&db, err) != 0) return NULL;
    if (tv_run(db, "BEGIN IMMEDIATE", 0)) return tv_db_error(db, err);
    if (jhas(body, "config_version") && jint64(body, "config_version", -1) != tvh_config_version(db)) {
        tv_run(db, "ROLLBACK", 0); sqlite3_close(db);
        return tvh_fail(err, 409, "revision_conflict", "config_version", "Settings changed; reload before saving");
    }
    if (jhas(body, "default_theme_id")) {
        const char *id = jstr(body, "default_theme_id");
        if (!id || !*id || !row_exists(db, "SELECT 1 FROM tvhome_theme WHERE id=? AND COALESCE((SELECT enabled FROM tvhome_theme_flags WHERE theme_id=tvhome_theme.id),1)=1", id)) {
            tv_run(db, "ROLLBACK", 0); sqlite3_close(db);
            return tvh_fail(err, 400, "invalid_parameter", "default_theme_id", "An enabled theme is required");
        }
        if (tv_run(db, "UPDATE tvhome_settings SET default_theme_id=? WHERE id=1", 1, id) ||
            tv_run(db, "UPDATE tvhome_theme SET is_default=(id=?)", 1, id)) return tv_db_error(db, err);
    }
    const char *ints[] = {"heartbeat_seconds", "online_window_seconds", "allow_local_edit", "allow_local_background", "exit_to_system", "pin_required", "discovery_enabled", NULL};
    for (int i=0; ints[i]; i++) if (jhas(body, ints[i])) {
        int64_t value = i < 2 ? jint64(body, ints[i], 0) : jbool(body, ints[i], 0);
        if (i < 2 && (value < (i ? 10 : 5) || value > 86400)) {
            tv_run(db, "ROLLBACK", 0); sqlite3_close(db);
            return tvh_fail(err, 400, "invalid_parameter", ints[i], "Interval outside supported range");
        }
        char sql[160], number[32];
        snprintf(sql, sizeof(sql), "UPDATE tvhome_settings SET %s=? WHERE id=1", ints[i]);
        snprintf(number, sizeof(number), "%lld", (long long)value);
        if (tv_run(db, sql, 1, number)) return tv_db_error(db, err);
    }
    if (jhas(body, "media_principal_id") && tv_run(db, "UPDATE tvhome_settings SET media_principal_id=? WHERE id=1", 1, jstr(body,"media_principal_id"))) return tv_db_error(db,err);
    if (jhas(body, "modules")) {
        struct json_object *modules = jobj(body,"modules");
        if (!json_object_is_type(modules,json_type_object)) {
            tv_run(db,"ROLLBACK",0);sqlite3_close(db);
            return tvh_fail(err,400,"invalid_parameter","modules","Module settings object required");
        }
        if (tv_run(db,"UPDATE tvhome_settings SET modules_json=? WHERE id=1",1,tv_json(modules))) return tv_db_error(db,err);
    }
    if (tv_run(db,"UPDATE tvhome_settings SET updated_at=strftime('%s','now') WHERE id=1",0) || tv_changed(db) || tv_run(db,"COMMIT",0)) return tv_db_error(db,err);
    struct json_object *result = settings_build(db);
    sqlite3_close(db);return result;
}

struct json_object *tvhome_overview(struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o, *terms, *th, *gr, *ws;
    int64_t now = now_ms();
    int64_t window;
    int total, online = 0, connected, themes, groups;
    sqlite3_stmt *st = NULL;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;

    window = 0;
    {
        char wb[32];
        scalar_text(db, "SELECT online_window_seconds FROM tvhome_settings"
                        " WHERE id=1", NULL, wb, sizeof(wb));
        window = strtoll(wb, NULL, 10);
        if (window <= 0)
            window = TVH_ONLINE_WINDOW_SEC;
    }
    total = count_query(db, "SELECT COUNT(*) FROM tvhome_terminal", NULL);
    themes = count_query(db, "SELECT COUNT(*) FROM tvhome_theme", NULL);
    groups = count_query(db, "SELECT COUNT(*) FROM tvhome_group", NULL);
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM tvhome_terminal"
                               " WHERE last_seen_ms>0 AND (?-last_seen_ms)<=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_int64(st, 2, window * 1000);
        if (sqlite3_step(st) == SQLITE_ROW)
            online = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
    }
    connected = 0;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(DISTINCT terminal_id) FROM"
                               " tvhome_session WHERE revoked=0 AND expires_at_ms>?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, now);
        if (sqlite3_step(st) == SQLITE_ROW)
            connected = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    o = json_object_new_object();
    json_object_object_add(o, "config_version",
                           json_object_new_int64(tvh_config_version(db)));
    terms = json_object_new_object();
    json_object_object_add(terms, "total", json_object_new_int(total));
    json_object_object_add(terms, "online", json_object_new_int(online));
    json_object_object_add(terms, "connected", json_object_new_int(connected)); /* legacy alias */
    json_object_object_add(terms, "session_active", json_object_new_int(connected));
    json_object_object_add(o, "terminals", terms);
    th = json_object_new_object();
    json_object_object_add(th, "total", json_object_new_int(themes));
    json_object_object_add(o, "themes", th);
    gr = json_object_new_object();
    json_object_object_add(gr, "total", json_object_new_int(groups));
    json_object_object_add(o, "groups", gr);
    ws = json_object_new_object();
    json_object_object_add(ws, "connected", json_object_new_int(tvhome_ws_count(NULL)));
    json_object_object_add(ws, "supported", json_object_new_boolean(1));
    json_object_object_add(o, "ws", ws);
    json_object_object_add(o, "capabilities", tvh_capabilities(db, NULL));
    json_object_object_add(o, "server_time_ms", json_object_new_int64(now));
    sqlite3_close(db);
    return o;
}

/* ===================== A themes ===================== */
static struct json_object *fail_theme_result(struct tvhome_err *err,
                                             struct tvhome_theme_result *r)
{
    return tvh_fail(err, 400, r->code[0] ? r->code : "invalid_theme",
                    r->field,
                    r->message[0] ? r->message : "theme validation failed");
}

struct json_object *tvhome_themes_list(struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o, *arr;
    char dv[TVH_MAX_ID];
    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    arr = json_object_new_array();
    if (sqlite3_prepare_v2(db, "SELECT " THEME_COLS " FROM tvhome_theme"
                               " ORDER BY is_default DESC, name",
                           -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_array_add(arr, theme_obj_from_stmt(st, 0));
        sqlite3_finalize(st);
    }
    o = json_object_new_object();
    json_object_object_add(o, "themes", arr);
    json_object_object_add(o, "capabilities", tvh_capabilities(db, NULL));
    json_object_object_add(o, "count",
                           json_object_new_int(json_object_array_length(arr)));
    scalar_text(db, "SELECT default_theme_id FROM tvhome_settings WHERE id=1",
                NULL, dv, sizeof(dv));
    json_object_object_add(o, "default_theme_id", str_or_null(dv));
    sqlite3_close(db);
    return o;
}

struct json_object *tvhome_theme_get(const char *id, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o;
    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    o = theme_full_by_id(db, id);
    sqlite3_close(db);
    if (!o)
        return tvh_fail(err, 404, "resource_not_found", "id", "theme not found");
    return o;
}

struct json_object *tvhome_theme_check(struct json_object *body, int preview,
                                       struct tvhome_err *err)
{
    struct json_object *spec = jobj(body, "spec");
    struct tvhome_theme_result r;
    struct json_object *canon, *o;

    tvh_reset(err);
    if (!spec || !json_object_is_type(spec, json_type_object))
        return tvh_fail(err, 400, "invalid_parameter", "spec",
                        "spec object required");
    canon = tvhome_theme_canonicalize(spec, &r);
    if (!canon)
        return fail_theme_result(err, &r);
    o = json_object_new_object();
    json_object_object_add(o, "valid", json_object_new_boolean(1));
    json_object_object_add(o, "notes", json_object_new_int(r.notes));
    json_object_object_add(o, "spec", canon); /* transfers ownership */
    if (preview) {
        struct json_object *disp =
            tvhome_display_resolve(canon, NULL, NULL);
        json_object_object_add(o, "display", disp);
    }
    return o;
}

struct json_object *tvhome_theme_create(struct json_object *body,
                                        struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *spec = jobj(body, "spec");
    const char *name = jstr(body, "name");
    struct tvhome_theme_result r;
    struct json_object *canon, *o;
    sqlite3_stmt *st = NULL;
    char id[TVH_MAX_ID];
    int is_default;
    int64_t now = (int64_t)time(NULL);

    tvh_reset(err);
    if (!spec || !json_object_is_type(spec, json_type_object))
        return tvh_fail(err, 400, "invalid_parameter", "spec",
                        "spec object required");
    canon = tvhome_theme_canonicalize(spec, &r);
    if (!canon)
        return fail_theme_result(err, &r);
    if (tvh_open(&db, err) != 0) {
        json_object_put(canon);
        return NULL;
    }
    if(tv_run(db,"BEGIN IMMEDIATE",0)){json_object_put(canon);return tv_db_error(db,err);}
    if(tvhome_assets_validate(db,canon,err)){json_object_put(canon);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
    is_default = (tvh_theme_count(db) == 0) ? 1 : 0;
    gen_id("theme", id, sizeof(id));
    if (sqlite3_prepare_v2(db,
            "INSERT INTO tvhome_theme(id,name,spec_json,revision,schema_version,"
            "is_default,builtin,created_at,updated_at)"
            " VALUES(?,?,?,1,1,?,0,?,?)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name ? name : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3,
            json_object_to_json_string_ext(canon, JSON_C_TO_STRING_PLAIN),
            -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, is_default);
        sqlite3_bind_int64(st, 5, now);
        sqlite3_bind_int64(st, 6, now);
        int inserted=sqlite3_step(st)==SQLITE_DONE;
        sqlite3_finalize(st);
        if(!inserted){json_object_put(canon);return tv_db_error(db,err);}
    }
    json_object_put(canon);
    if (is_default)
        set_text(db, "default_theme_id", id);
    if(tv_changed(db)||tv_run(db,"COMMIT",0))return tv_db_error(db,err);
    o = theme_full_by_id(db, id);
    sqlite3_close(db);
    if (!o)
        return tvh_fail(err, 500, "internal_error", "", "theme create failed");
    return o;
}

struct json_object *tvhome_theme_update(const char *id, struct json_object *body, struct tvhome_err *err)
{
    sqlite3 *db=NULL;struct json_object *old,*canon=NULL,*spec=jobj(body,"spec"),*o;
    tvh_reset(err);if(tvh_open(&db,err))return NULL;
    if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,err);
    old=theme_full_by_id(db,id);
    if(!old){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvh_fail(err,404,"resource_not_found","id","Theme not found");}
    if(!jhas(body,"expected_revision")||jint64(body,"expected_revision",-1)!=jint64(old,"revision",0)){
        json_object_put(old);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvh_fail(err,409,"revision_conflict","expected_revision","Theme changed; compare the current revision before saving");
    }
    if(spec){struct tvhome_theme_result result;canon=tvhome_theme_canonicalize(spec,&result);
        if(!canon){json_object_put(old);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return fail_theme_result(err,&result);}}
    else canon=json_object_get(jobj(old,"spec"));
    if(tvhome_assets_validate(db,canon,err)){json_object_put(canon);json_object_put(old);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
    int enabled=jbool(body,"enabled",jbool(old,"enabled",1));
    if(!enabled&&(jbool(old,"is_default",0)||row_exists(db,"SELECT 1 FROM tvhome_terminal WHERE theme_id=?",id)||row_exists(db,"SELECT 1 FROM tvhome_group WHERE theme_id=?",id))){
        json_object_put(old);json_object_put(canon);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvh_fail(err,409,"theme_in_use","enabled","Default or assigned themes cannot be disabled");
    }
    const char *name=jstr(body,"name");if(!name)name=jstr(old,"name");char now[32];snprintf(now,sizeof(now),"%lld",(long long)time(NULL));
    int rc=tv_run(db,"UPDATE tvhome_theme SET spec_json=?,name=?,revision=revision+1,updated_at=? WHERE id=?",4,tv_json(canon),name,now,id)||
        tv_run(db,"INSERT OR REPLACE INTO tvhome_theme_flags VALUES(?,?)",2,id,enabled?"1":"0");
    json_object_put(old);json_object_put(canon);
    if(rc||tv_changed(db)||tv_run(db,"COMMIT",0))return tv_db_error(db,err);
    o=theme_full_by_id(db,id);sqlite3_close(db);return o;
}

struct json_object *tvhome_theme_delete(const char *id, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    int is_default = 0;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_theme WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id", "theme not found");
    }
    {
        char db2[8];
        scalar_text(db, "SELECT is_default FROM tvhome_theme WHERE id=?", id,
                    db2, sizeof(db2));
        is_default = atoi(db2);
    }
    if (is_default) {
        sqlite3_close(db);
        return tvh_fail(err, 409, "default_theme_in_use", "id",
                        "cannot delete the default theme");
    }
    if (row_exists(db, "SELECT 1 FROM tvhome_terminal WHERE theme_id=?", id) ||
        row_exists(db, "SELECT 1 FROM tvhome_group WHERE theme_id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 409, "asset_in_use", "id",
                        "theme is referenced by a terminal or group");
    }
    if (sqlite3_prepare_v2(db, "DELETE FROM tvhome_theme WHERE id=?", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    tvh_bump_config(db);
    sqlite3_close(db);
    o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "deleted", json_object_new_boolean(1));
    return o;
}

struct json_object *tvhome_theme_set_default(const char *id,
                                             struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_theme WHERE id=? AND COALESCE((SELECT enabled FROM tvhome_theme_flags WHERE theme_id=tvhome_theme.id),1)=1", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id", "theme not found");
    }
    tvh_exec(db, "UPDATE tvhome_theme SET is_default=0;");
    if (sqlite3_prepare_v2(db, "UPDATE tvhome_theme SET is_default=1 WHERE id=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    set_text(db, "default_theme_id", id);
    tvh_bump_config(db);
    sqlite3_close(db);
    o = json_object_new_object();
    json_object_object_add(o, "default_theme_id", json_object_new_string(id));
    return o;
}

struct json_object *tvhome_theme_duplicate(const char *id,
                                           struct json_object *body,
                                           struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    char *spec_copy = NULL;
    char src_name[TVH_MAX_NAME] = "";
    char new_id[TVH_MAX_ID];
    const char *new_name;
    char name_buf[TVH_MAX_NAME + 16];
    int64_t now = (int64_t)time(NULL);

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (sqlite3_prepare_v2(db, "SELECT name,spec_json FROM tvhome_theme WHERE id=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(src_name, sizeof(src_name), "%s", col_text(st, 0));
            spec_copy = strdup(col_text(st, 1));
        }
        sqlite3_finalize(st);
    }
    if (!spec_copy) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id", "theme not found");
    }
    new_name = jstr(body, "name");
    if (!new_name || !*new_name) {
        snprintf(name_buf, sizeof(name_buf), "%s \xe5\x89\xaf\xe6\x9c\xac",
                 src_name); /* "<name> 副本" */
        new_name = name_buf;
    }
    gen_id("theme", new_id, sizeof(new_id));
    if (sqlite3_prepare_v2(db,
            "INSERT INTO tvhome_theme(id,name,spec_json,revision,schema_version,"
            "is_default,builtin,created_at,updated_at)"
            " VALUES(?,?,?,1,1,0,0,?,?)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, new_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, new_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, spec_copy, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, now);
        sqlite3_bind_int64(st, 5, now);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    free(spec_copy);
    tvh_bump_config(db);
    o = theme_full_by_id(db, new_id);
    sqlite3_close(db);
    if (!o)
        return tvh_fail(err, 500, "internal_error", "", "duplicate failed");
    return o;
}

/* ===================== A terminals ===================== */
#define TERM_COLS "id,name,group_id,theme_id,media_principal_id,device_id,model,"\
                  "last_seen_ms,reported_version,applied_config_version,"\
                  "foreground_module"

static int terminal_connected(sqlite3 *db, const char *id, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int n = 0;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM tvhome_session WHERE"
                               " terminal_id=? AND revoked=0 AND expires_at_ms>?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return n > 0;
}

static struct json_object *terminal_obj(sqlite3 *db, sqlite3_stmt *st,
                                        int64_t now, int64_t window_ms)
{
    struct json_object *o = json_object_new_object();
    const char *id = col_text(st, 0);
    int64_t last = col_i64(st, 7);
    int online = (last > 0 && (now - last) <= window_ms) ? 1 : 0;

    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "name", json_object_new_string(col_text(st, 1)));
    json_object_object_add(o, "group_id", str_or_null(col_text(st, 2)));
    json_object_object_add(o, "theme_id", str_or_null(col_text(st, 3)));
    json_object_object_add(o, "media_principal_id", str_or_null(col_text(st, 4)));
    json_object_object_add(o, "device_id", str_or_null(col_text(st, 5)));
    json_object_object_add(o, "model", str_or_null(col_text(st, 6)));
    json_object_object_add(o, "last_seen_ms", json_object_new_int64(last));
    json_object_object_add(o, "reported_version", str_or_null(col_text(st, 8)));
    json_object_object_add(o, "applied_config_version",
                           json_object_new_int64(col_i64(st, 9)));
    json_object_object_add(o, "foreground_module", str_or_null(col_text(st, 10)));
    json_object_object_add(o, "online", json_object_new_boolean(online));
    json_object_object_add(o, "connected",
                           json_object_new_boolean(terminal_connected(db, id, now)));
    json_object_object_add(o, "session_active", json_object_new_boolean(terminal_connected(db,id,now)));
    json_object_object_add(o, "enabled", json_object_new_boolean(!count_query(db,"SELECT COUNT(*) FROM tvhome_principal WHERE terminal_id=? AND revoked=1",id)));
    json_object_object_add(o, "desired_config_version", json_object_new_int64(tvh_config_version(db)));
    struct json_object *ws=json_object_new_object();
    json_object_object_add(ws,"supported",json_object_new_boolean(1));
    json_object_object_add(ws,"connected",json_object_new_boolean(tvhome_ws_count(id)>0));
    json_object_object_add(o,"ws",ws);
    char profile[4097];
    scalar_text(db,"SELECT profile_json FROM tvhome_device_profile WHERE terminal_id=?",id,profile,sizeof(profile));
    json_object_object_add(o,"device",*profile?json_tokener_parse(profile):NULL);
    return o;
}

static struct json_object *terminal_full_by_id(sqlite3 *db, const char *id,
                                               int64_t now, int64_t window_ms)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;
    if (sqlite3_prepare_v2(db, "SELECT " TERM_COLS " FROM tvhome_terminal"
                               " WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        o = terminal_obj(db, st, now, window_ms);
    sqlite3_finalize(st);
    return o;
}

static int64_t settings_window_ms(sqlite3 *db)
{
    char wb[32];
    int64_t w;
    scalar_text(db, "SELECT online_window_seconds FROM tvhome_settings WHERE id=1",
                NULL, wb, sizeof(wb));
    w = strtoll(wb, NULL, 10);
    return (w > 0 ? w : TVH_ONLINE_WINDOW_SEC) * 1000;
}

struct json_object *tvhome_terminals_list(struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o, *arr;
    int64_t now = now_ms();
    int64_t window_ms;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    window_ms = settings_window_ms(db);
    arr = json_object_new_array();
    if (sqlite3_prepare_v2(db, "SELECT " TERM_COLS " FROM tvhome_terminal"
                               " ORDER BY name, id", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_array_add(arr, terminal_obj(db, st, now, window_ms));
        sqlite3_finalize(st);
    }
    o = json_object_new_object();
    json_object_object_add(o, "terminals", arr);
    json_object_object_add(o, "count",
                           json_object_new_int(json_object_array_length(arr)));
    sqlite3_close(db);
    return o;
}

static void term_set_text(sqlite3 *db, const char *col, const char *id,
                          const char *v)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    snprintf(sql, sizeof(sql), "UPDATE tvhome_terminal SET %s=?,updated_at=?"
                               " WHERE id=?", col);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, v ? v : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (int64_t)time(NULL));
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

struct json_object *tvhome_terminal_update(const char *id,
                                           struct json_object *body,
                                           struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_terminal WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id",
                        "terminal not found");
    }
    if (jhas(body, "group_id")) {
        const char *g = jstr(body, "group_id");
        if (g && *g &&
            !row_exists(db, "SELECT 1 FROM tvhome_group WHERE id=?", g)) {
            sqlite3_close(db);
            return tvh_fail(err, 400, "invalid_parameter", "group_id",
                            "group_id must reference an existing group");
        }
        term_set_text(db, "group_id", id, g ? g : "");
    }
    if (jhas(body, "theme_id")) {
        const char *t = jstr(body, "theme_id");
        if (t && *t &&
            !row_exists(db, "SELECT 1 FROM tvhome_theme WHERE id=? AND COALESCE((SELECT enabled FROM tvhome_theme_flags WHERE theme_id=tvhome_theme.id),1)=1", t)) {
            sqlite3_close(db);
            return tvh_fail(err, 400, "invalid_parameter", "theme_id",
                            "theme_id must reference an existing theme");
        }
        term_set_text(db, "theme_id", id, t ? t : "");
    }
    if (jhas(body, "media_principal_id"))
        term_set_text(db, "media_principal_id", id,
                      jstr(body, "media_principal_id"));
    if (jhas(body, "name"))
        term_set_text(db, "name", id, jstr(body, "name"));
    tvh_bump_config(db);
    o = terminal_full_by_id(db, id, now_ms(), settings_window_ms(db));
    sqlite3_close(db);
    return o;
}

struct json_object *tvhome_terminal_delete(const char *id, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_terminal WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id",
                        "terminal not found");
    }
    if (terminal_connected(db,id,now_ms())) {
        sqlite3_close(db);
        return tvh_fail(err,409,"terminal_session_active","id","revoke the active session before deleting its profile");
    }
    /* Deleting the profile is not deactivating the identity: the principal row
     * and any bound device fingerprint are retained (contract D1). */
    if (sqlite3_prepare_v2(db, "DELETE FROM tvhome_terminal WHERE id=?", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    tvh_bump_config(db);
    sqlite3_close(db);
    o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "deleted", json_object_new_boolean(1));
    json_object_object_add(o, "identity_retained", json_object_new_boolean(1));
    return o;
}

/* Build only the {background?,screensaver?} override layer from a request body,
 * preserving explicit null (= inherit upper). Caller owns the result. */
static struct json_object *extract_display_layer(struct json_object *body)
{
    struct json_object *layer = json_object_new_object();
    struct json_object *v;
    if (body && json_object_object_get_ex(body, "background", &v))
        json_object_object_add(layer, "background", v ? json_object_get(v) : NULL);
    if (body && json_object_object_get_ex(body, "screensaver", &v))
        json_object_object_add(layer, "screensaver", v ? json_object_get(v) : NULL);
    return layer;
}

static struct json_object *terminal_display_resolved(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *res = NULL;
    char theme_id[TVH_MAX_ID] = "", group_id[TVH_MAX_ID] = "", eff[TVH_MAX_ID];
    char *disp = NULL;

    if (sqlite3_prepare_v2(db, "SELECT theme_id,group_id,display_json FROM"
                               " tvhome_terminal WHERE id=?", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(theme_id, sizeof(theme_id), "%s", col_text(st, 0));
            snprintf(group_id, sizeof(group_id), "%s", col_text(st, 1));
            disp = strdup(col_text(st, 2));
        }
        sqlite3_finalize(st);
    }
    if (!disp)
        return NULL;
    resolve_theme_id(db, theme_id, group_id, eff, sizeof(eff));
    res = resolve_display(db, eff, group_id, disp);
    if (res) json_object_object_add(res,"override",json_tokener_parse(disp));
    free(disp);
    return res;
}

struct json_object *tvhome_terminal_display_get(const char *id,
                                                struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o;
    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    o = terminal_display_resolved(db, id);
    sqlite3_close(db);
    if (!o)
        return tvh_fail(err, 404, "resource_not_found", "id",
                        "terminal not found");
    return o;
}

struct json_object *tvhome_terminal_display_put(const char *id,
                                                struct json_object *body,
                                                struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o, *layer;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_terminal WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id",
                        "terminal not found");
    }
    if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,err);
    layer=extract_display_layer(body);
    if(tvhome_assets_validate(db,layer,err)){json_object_put(layer);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
    int rc=tv_run(db,"UPDATE tvhome_terminal SET display_json=? WHERE id=?",2,tv_json(layer),id);
    json_object_put(layer);
    if(rc||tv_changed(db)||tv_run(db,"COMMIT",0))return tv_db_error(db,err);
    o = terminal_display_resolved(db, id);
    sqlite3_close(db);
    if (!o)
        return tvh_fail(err, 500, "internal_error", "", "display resolve failed");
    return o;
}

/* ===================== A groups ===================== */
#define GROUP_COLS "id,name,theme_id"
static struct json_object *group_obj(sqlite3 *db, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *id = col_text(st, 0);
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "name", json_object_new_string(col_text(st, 1)));
    json_object_object_add(o, "theme_id", str_or_null(col_text(st, 2)));
    json_object_object_add(o, "member_count",
        json_object_new_int(count_query(db, "SELECT COUNT(*) FROM"
            " tvhome_terminal WHERE group_id=?", id)));
    return o;
}

static struct json_object *group_by_id(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;
    if (sqlite3_prepare_v2(db, "SELECT " GROUP_COLS " FROM tvhome_group"
                               " WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        o = group_obj(db, st);
    sqlite3_finalize(st);
    return o;
}

struct json_object *tvhome_groups_list(struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o, *arr;
    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    arr = json_object_new_array();
    if (sqlite3_prepare_v2(db, "SELECT " GROUP_COLS " FROM tvhome_group"
                               " ORDER BY name, id", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_array_add(arr, group_obj(db, st));
        sqlite3_finalize(st);
    }
    o = json_object_new_object();
    json_object_object_add(o, "groups", arr);
    json_object_object_add(o, "count",
                           json_object_new_int(json_object_array_length(arr)));
    sqlite3_close(db);
    return o;
}

struct json_object *tvhome_group_create(struct json_object *body,
                                        struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    const char *name = jstr(body, "name");
    const char *theme_id = jstr(body, "theme_id");
    char id[TVH_MAX_ID];
    int64_t now = (int64_t)time(NULL);

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (theme_id && *theme_id &&
        !row_exists(db, "SELECT 1 FROM tvhome_theme WHERE id=? AND COALESCE((SELECT enabled FROM tvhome_theme_flags WHERE theme_id=tvhome_theme.id),1)=1", theme_id)) {
        sqlite3_close(db);
        return tvh_fail(err, 400, "invalid_parameter", "theme_id",
                        "theme_id must reference an existing theme");
    }
    gen_id("grp", id, sizeof(id));
    if (sqlite3_prepare_v2(db, "INSERT INTO tvhome_group(id,name,theme_id,"
            "display_json,created_at,updated_at) VALUES(?,?,?,'{}',?,?)",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name ? name : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, theme_id ? theme_id : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, now);
        sqlite3_bind_int64(st, 5, now);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    tvh_bump_config(db);
    o = group_by_id(db, id);
    sqlite3_close(db);
    return o;
}

static void group_set_text(sqlite3 *db, const char *col, const char *id,
                           const char *v)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    snprintf(sql, sizeof(sql), "UPDATE tvhome_group SET %s=?,updated_at=?"
                               " WHERE id=?", col);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, v ? v : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (int64_t)time(NULL));
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

struct json_object *tvhome_group_update(const char *id, struct json_object *body,
                                        struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_group WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id", "group not found");
    }
    if (jhas(body, "theme_id")) {
        const char *t = jstr(body, "theme_id");
        if (t && *t &&
            !row_exists(db, "SELECT 1 FROM tvhome_theme WHERE id=? AND COALESCE((SELECT enabled FROM tvhome_theme_flags WHERE theme_id=tvhome_theme.id),1)=1", t)) {
            sqlite3_close(db);
            return tvh_fail(err, 400, "invalid_parameter", "theme_id",
                            "theme_id must reference an existing theme");
        }
        group_set_text(db, "theme_id", id, t ? t : "");
    }
    if (jhas(body, "name"))
        group_set_text(db, "name", id, jstr(body, "name"));
    tvh_bump_config(db);
    o = group_by_id(db, id);
    sqlite3_close(db);
    return o;
}

struct json_object *tvhome_group_delete(const char *id, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    int reassigned;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_group WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id", "group not found");
    }
    reassigned = count_query(db, "SELECT COUNT(*) FROM tvhome_terminal"
                                 " WHERE group_id=?", id);
    /* members fall back to ungrouped (empty group_id), not deleted */
    if (sqlite3_prepare_v2(db, "UPDATE tvhome_terminal SET group_id='' WHERE"
                               " group_id=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
        st = NULL;
    }
    if (sqlite3_prepare_v2(db, "DELETE FROM tvhome_group WHERE id=?", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    tvh_bump_config(db);
    sqlite3_close(db);
    o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "deleted", json_object_new_boolean(1));
    json_object_object_add(o, "reassigned_terminals",
                           json_object_new_int(reassigned));
    return o;
}

struct json_object *tvhome_group_display_put(const char *id,
                                             struct json_object *body,
                                             struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o, *layer;
    char eff[TVH_MAX_ID];

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (!row_exists(db, "SELECT 1 FROM tvhome_group WHERE id=?", id)) {
        sqlite3_close(db);
        return tvh_fail(err, 404, "resource_not_found", "id", "group not found");
    }
    if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,err);
    layer=extract_display_layer(body);
    if(tvhome_assets_validate(db,layer,err)){json_object_put(layer);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
    int rc=tv_run(db,"UPDATE tvhome_group SET display_json=? WHERE id=?",2,tv_json(layer),id);
    json_object_put(layer);
    if(rc||tv_changed(db)||tv_run(db,"COMMIT",0))return tv_db_error(db,err);
    /* group-level resolution: group override over the group's (or default)
     * theme, with no terminal layer. */
    resolve_theme_id(db, "", id, eff, sizeof(eff));
    o = resolve_display(db, eff, id, NULL);
    sqlite3_close(db);
    return o;
}

/* ===================== T terminal surface (D1 stub) ===================== */
static int tvh_session_terminal(sqlite3 *db, const char *token, char *out,
                                size_t outsz, struct tvhome_err *err)
{
    sqlite3_stmt *st = NULL;
    int revoked = -1, found = 0;
    int64_t exp = 0;
    char term[TVH_MAX_ID] = "";

    if (!token || !*token) {
        tvh_fail(err, 401, "tv_session_expired", "", "missing session token");
        return -1;
    }
    if (sqlite3_prepare_v2(db, "SELECT terminal_id,expires_at_ms,revoked FROM"
                               " tvhome_session WHERE token=?", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, token, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(term, sizeof(term), "%s", col_text(st, 0));
            exp = col_i64(st, 1);
            revoked = (int)col_i64(st, 2);
            found = 1;
        }
        sqlite3_finalize(st);
    }
    if (!found) {
        tvh_fail(err, 401, "tv_session_expired", "", "unknown session");
        return -1;
    }
    if (revoked || count_query(db, "SELECT COUNT(*) FROM tvhome_principal WHERE terminal_id=? AND revoked=1", term)) {
        tvh_fail(err, 401, "tv_session_revoked", "", "session revoked");
        return -1;
    }
    if (exp <= now_ms()) {
        tvh_fail(err, 401, "tv_session_expired", "", "session expired");
        return -1;
    }
    if (!row_exists(db,"SELECT 1 FROM tvhome_terminal WHERE id=?",term)) {
        tvh_fail(err,401,"tv_session_revoked","","terminal profile removed");return -1;
    }
    snprintf(out, outsz, "%s", term);
    return 0;
}

struct json_object *tvhome_ping(struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o, *ident, *modes;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    o = json_object_new_object();
    json_object_object_add(o, "product", json_object_new_string("dreamingos-tvhome"));
    json_object_object_add(o, "api_version", json_object_new_int(1));
    json_object_object_add(o, "protocol_version", json_object_new_int(1));
    ident = json_object_new_object();
    json_object_object_add(ident, "confirmed", json_object_new_boolean(1));
    json_object_object_add(ident, "name", json_object_new_string("DreamingOS"));
    json_object_object_add(o, "server_identity", ident);
    modes = json_object_new_array();
    json_object_array_add(modes, json_object_new_string("admin_approval"));
    json_object_object_add(o, "activation_modes", modes);
    json_object_object_add(o, "config_version",
                           json_object_new_int64(tvh_config_version(db)));
    json_object_object_add(o, "server_time_ms", json_object_new_int64(now_ms()));
    sqlite3_close(db);
    return o;
}

struct json_object *tvhome_session_delete(const char *token,
                                          struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;

    tvh_reset(err);
    if (!token || !*token)
        return tvh_fail(err, 400, "invalid_parameter", "token",
                        "session token required");
    if (tvh_open(&db, err) != 0)
        return NULL;
    /* idempotent logout: revoke if present, always report revoked */
    if (sqlite3_prepare_v2(db, "UPDATE tvhome_session SET revoked=1 WHERE token=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, token, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    o = json_object_new_object();
    json_object_object_add(o, "revoked", json_object_new_boolean(1));
    return o;
}

static struct json_object *bootstrap_settings(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = json_object_new_object();
    if (sqlite3_prepare_v2(db, "SELECT heartbeat_seconds,online_window_seconds,"
            "allow_local_edit,allow_local_background,exit_to_system,pin_required"
            " FROM tvhome_settings WHERE id=1", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(o, "heartbeat_seconds",
                               json_object_new_int64(col_i64(st, 0)));
        json_object_object_add(o, "online_window_seconds",
                               json_object_new_int64(col_i64(st, 1)));
        json_object_object_add(o, "allow_local_edit",
                               json_object_new_boolean(col_i64(st, 2) ? 1 : 0));
        json_object_object_add(o, "allow_local_background",
                               json_object_new_boolean(col_i64(st, 3) ? 1 : 0));
        json_object_object_add(o, "exit_to_system",
                               json_object_new_boolean(col_i64(st, 4) ? 1 : 0));
        json_object_object_add(o, "pin_required",
                               json_object_new_boolean(col_i64(st, 5) ? 1 : 0));
    }
    if (st)
        sqlite3_finalize(st);
    return o;
}

struct json_object *tvhome_bootstrap(const char *token, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o, *term_obj, *theme_obj;
    char term[TVH_MAX_ID] = "";
    char theme_id[TVH_MAX_ID] = "", group_id[TVH_MAX_ID] = "";
    char media_pid[TVH_MAX_ID] = "", eff[TVH_MAX_ID];
    char *disp = NULL;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (tvh_session_terminal(db, token, term, sizeof(term), err) != 0) {
        sqlite3_close(db);
        return NULL;
    }
    if (sqlite3_prepare_v2(db, "SELECT theme_id,group_id,media_principal_id,"
            "display_json FROM tvhome_terminal WHERE id=?", -1, &st,
            NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, term, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(theme_id, sizeof(theme_id), "%s", col_text(st, 0));
            snprintf(group_id, sizeof(group_id), "%s", col_text(st, 1));
            snprintf(media_pid, sizeof(media_pid), "%s", col_text(st, 2));
            disp = strdup(col_text(st, 3));
        }
        sqlite3_finalize(st);
    }
    resolve_theme_id(db, theme_id, group_id, eff, sizeof(eff));

    o = json_object_new_object();
    json_object_object_add(o, "api_version", json_object_new_int(1));
    json_object_object_add(o, "config_version",
                           json_object_new_int64(tvh_config_version(db)));
    json_object_object_add(o, "server_time_ms", json_object_new_int64(now_ms()));
    term_obj = json_object_new_object();
    json_object_object_add(term_obj, "id", json_object_new_string(term));
    json_object_object_add(term_obj, "group_id", str_or_null(group_id));
    json_object_object_add(term_obj, "media_principal_id", str_or_null(media_pid));
    json_object_object_add(o, "terminal", term_obj);
    json_object_object_add(o, "capabilities", tvh_capabilities(db, term));
    theme_obj = theme_client_node(db, eff);
    json_object_object_add(o, "theme", theme_obj ? theme_obj : NULL);
    json_object_object_add(o, "display",
                           resolve_display(db, eff, group_id, disp));
    json_object_object_add(o, "settings", bootstrap_settings(db));
    json_object_object_add(o, "notice", tvhome_notice_for_terminal(db, term));
    json_object_object_add(o, "commands", tvhome_commands_for_terminal(db, term));
    free(disp);
    sqlite3_close(db);
    return o;
}

/* Client-facing theme node: exactly {id,revision,schema_version,spec} (§4). */
static struct json_object *theme_client_node(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id,revision,schema_version,spec_json"
            " FROM tvhome_theme WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *spec = json_tokener_parse(col_text(st, 3));
        o = json_object_new_object();
        json_object_object_add(o, "id", json_object_new_string(col_text(st, 0)));
        json_object_object_add(o, "revision", json_object_new_int64(col_i64(st, 1)));
        json_object_object_add(o, "schema_version",
                               json_object_new_int64(col_i64(st, 2)));
        json_object_object_add(o, "spec", spec ? spec : json_object_new_object());
    }
    sqlite3_finalize(st);
    return o;
}

struct json_object *tvhome_theme_resolved(const char *token,
                                          struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *o;
    char term[TVH_MAX_ID] = "", theme_id[TVH_MAX_ID] = "";
    char group_id[TVH_MAX_ID] = "", eff[TVH_MAX_ID];

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (tvh_session_terminal(db, token, term, sizeof(term), err) != 0) {
        sqlite3_close(db);
        return NULL;
    }
    scalar_text(db, "SELECT theme_id FROM tvhome_terminal WHERE id=?", term,
                theme_id, sizeof(theme_id));
    scalar_text(db, "SELECT group_id FROM tvhome_terminal WHERE id=?", term,
                group_id, sizeof(group_id));
    resolve_theme_id(db, theme_id, group_id, eff, sizeof(eff));
    o = theme_client_node(db, eff);
    sqlite3_close(db);
    if (!o)
        return tvh_fail(err, 404, "resource_not_found", "theme",
                        "no theme resolved for terminal");
    return o;
}

struct json_object *tvhome_heartbeat(const char *token, struct json_object *body,
                                     struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    char term[TVH_MAX_ID] = "";
    const char *rv = jstr(body, "reported_version");
    const char *fg = jstr(body, "foreground_module");
    int64_t applied = jint64(body, "applied_config_version", 0);
    int64_t expected, hb;

    tvh_reset(err);
    if (tvh_open(&db, err) != 0)
        return NULL;
    if (tvh_session_terminal(db, token, term, sizeof(term), err) != 0) {
        sqlite3_close(db);
        return NULL;
    }
    if (sqlite3_prepare_v2(db, "UPDATE tvhome_terminal SET last_seen_ms=?,"
            "reported_version=?,applied_config_version=?,foreground_module=?"
            " WHERE id=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, now_ms());
        sqlite3_bind_text(st, 2, rv ? rv : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, applied);
        sqlite3_bind_text(st, 4, fg ? fg : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, term, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    expected = tvh_config_version(db);
    {
        char hbb[32];
        scalar_text(db, "SELECT heartbeat_seconds FROM tvhome_settings WHERE id=1",
                    NULL, hbb, sizeof(hbb));
        hb = strtoll(hbb, NULL, 10);
        if (hb <= 0)
            hb = TVH_HEARTBEAT_SECONDS;
    }
    sqlite3_close(db);
    o = json_object_new_object();
    json_object_object_add(o, "expected_config_version",
                           json_object_new_int64(expected));
    json_object_object_add(o, "heartbeat_seconds", json_object_new_int64(hb));
    json_object_object_add(o, "authorized", json_object_new_boolean(1));
    json_object_object_add(o, "config_stale",
                           json_object_new_boolean(applied < expected ? 1 : 0));
    return o;
}


/* N1: approval and independent device sessions. All writes below are transactional. */
static int tvh_run(sqlite3 *db, const char *sql, int n, const char **args)
{
    sqlite3_stmt *st = NULL;
    int rc;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    for (int i = 0; i < n; i++) sqlite3_bind_text(st, i + 1, args[i] ? args[i] : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int tvh_secret(char *out, size_t size, const char *prefix)
{
    unsigned char bytes[20];
    size_t len = strlen(prefix);
    if (size < len + sizeof(bytes) * 2 + 1 || RAND_bytes(bytes, sizeof(bytes)) != 1) return -1;
    memcpy(out, prefix, len);
    for (size_t i = 0; i < sizeof(bytes); i++) snprintf(out + len + i * 2, 3, "%02x", bytes[i]);
    return 0;
}

static int tvh_hash(const char *secret, char hash[65])
{
    unsigned char bytes[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (!secret || !EVP_Digest(secret, strlen(secret), bytes, &size, EVP_sha256(), NULL) || size != 32) return -1;
    for (unsigned int i = 0; i < size; i++) snprintf(hash + i * 2, 3, "%02x", bytes[i]);
    return 0;
}

static struct json_object *tvh_tx_error(sqlite3 *db, struct tvhome_err *err)
{
    tvh_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return tvh_fail(err, 503, "service_not_ready", "", "TV control transaction failed; no change committed");
}

static struct json_object *activation_row(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *status = col_text(st, 2);
    if ((!strcmp(status,"pending") || !strcmp(status,"approved")) && col_i64(st,3) <= now_ms()) status = "expired";
    json_object_object_add(o,"id",json_object_new_string(col_text(st,0)));
    json_object_object_add(o,"device",json_tokener_parse(col_text(st,1)));
    json_object_object_add(o,"status",json_object_new_string(status));
    json_object_object_add(o,"expires_at_ms",json_object_new_int64(col_i64(st,3)));
    json_object_object_add(o,"created_at_ms",json_object_new_int64(col_i64(st,4)));
    json_object_object_add(o,"terminal_id",str_or_null(col_text(st,5)));
    return o;
}

struct json_object *tvhome_activation_request(struct json_object *body, struct tvhome_err *err)
{
    sqlite3 *db = NULL;
    struct json_object *device = jobj(body,"device"), *o;
    const char *did = jstr(device,"device_id");
    char id[64], token[64], hash[65], expires[32], created[32];
    tvh_reset(err);
    if (!did || !*did || strlen(did) > 128 || !device || strlen(json_object_to_json_string(device)) > 4096)
        return tvh_fail(err,400,"invalid_parameter","device","device_id and bounded device profile required");
    if (tvh_secret(id,sizeof(id),"req_") || tvh_secret(token,sizeof(token),"tv_req_") || tvh_hash(token,hash))
        return tvh_fail(err,503,"service_not_ready","","secure randomness unavailable");
    if (tvh_open(&db,err)) return NULL;
    if (tvh_exec(db,"BEGIN IMMEDIATE")) return tvh_tx_error(db,err);
    if (count_query(db,"SELECT COUNT(*) FROM tvhome_activation WHERE expires_at_ms>CAST(strftime('%s','now') AS INTEGER)*1000 AND status='pending'",NULL) >= 128 ||
        count_query(db,"SELECT COUNT(*) FROM tvhome_activation WHERE device_id=? AND expires_at_ms>CAST(strftime('%s','now') AS INTEGER)*1000 AND status='pending'",did) >= 3) {
        tvh_exec(db,"ROLLBACK"); sqlite3_close(db);
        return tvh_fail(err,429,"rate_limited","device","pending activation limit reached");
    }
    snprintf(created,sizeof(created),"%lld",(long long)now_ms());
    snprintf(expires,sizeof(expires),"%lld",(long long)(now_ms()+900000));
    const char *args[]={id,did,json_object_to_json_string_ext(device,JSON_C_TO_STRING_PLAIN),hash,expires,created};
    if (tvh_run(db,"INSERT INTO tvhome_activation(id,device_id,device_json,poll_hash,expires_at_ms,created_at_ms) VALUES(?,?,?,?,?,?)",6,args) || tvh_exec(db,"COMMIT")) return tvh_tx_error(db,err);
    sqlite3_close(db);
    o=json_object_new_object();
    json_object_object_add(o,"id",json_object_new_string(id));
    json_object_object_add(o,"poll_token",json_object_new_string(token));
    json_object_object_add(o,"status",json_object_new_string("pending"));
    json_object_object_add(o,"expires_at_ms",json_object_new_int64(strtoll(expires,NULL,10)));
    return o;
}

struct json_object *tvhome_activations(const char *id, const char *poll_token, struct tvhome_err *err)
{
    sqlite3 *db=NULL; sqlite3_stmt *st=NULL;
    struct json_object *list=json_object_new_array(), *o=NULL;
    char hash[65]="";
    tvh_reset(err);
    if (id && (!poll_token || tvh_hash(poll_token,hash))) { json_object_put(list); return tvh_fail(err,401,"invalid_activation","","request credential required"); }
    if (tvh_open(&db,err)) { json_object_put(list); return NULL; }
    const char *sql=id ? "SELECT id,device_json,status,expires_at_ms,created_at_ms,terminal_id FROM tvhome_activation WHERE id=? AND poll_hash=?" :
        "SELECT id,device_json,status,expires_at_ms,created_at_ms,terminal_id FROM tvhome_activation ORDER BY created_at_ms DESC LIMIT 200";
    if (sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK) { json_object_put(list); sqlite3_close(db); return tvh_fail(err,503,"service_not_ready","","activation list unavailable"); }
    if (id) { sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,hash,-1,SQLITE_TRANSIENT); }
    while (sqlite3_step(st)==SQLITE_ROW) json_object_array_add(list,activation_row(st));
    sqlite3_finalize(st); sqlite3_close(db);
    if (id) {
        if (json_object_array_length(list)) o=json_object_get(json_object_array_get_idx(list,0));
        else tvh_fail(err,404,"resource_not_found","id","activation request not found");
        json_object_put(list); return o;
    }
    o=json_object_new_object(); json_object_object_add(o,"activations",list); return o;
}

struct json_object *tvhome_activation_decide(const char *id, int approve, struct json_object *body, struct tvhome_err *err)
{
    sqlite3 *db=NULL; sqlite3_stmt *st=NULL;
    char did[129]="", state[24]="", term[TVH_MAX_ID]="", principal[TVH_MAX_ID]="";
    char code[64], hash[65], expires[32], created[32];
    int64_t exp=0,ttl=jint64(body,"ttl_seconds",600);
    tvh_reset(err);
    if (ttl<60 || ttl>900) return tvh_fail(err,400,"invalid_parameter","ttl_seconds","activation lifetime must be 60–900 seconds");
    if (tvh_open(&db,err)) return NULL;
    if (tvh_exec(db,"BEGIN IMMEDIATE")) return tvh_tx_error(db,err);
    if (sqlite3_prepare_v2(db,"SELECT device_id,status,expires_at_ms FROM tvhome_activation WHERE id=?",-1,&st,NULL)!=SQLITE_OK) return tvh_tx_error(db,err);
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if (sqlite3_step(st)==SQLITE_ROW) { snprintf(did,sizeof(did),"%s",col_text(st,0)); snprintf(state,sizeof(state),"%s",col_text(st,1)); exp=col_i64(st,2); }
    sqlite3_finalize(st);
    if (!*did || (approve && (strcmp(state,"pending") || exp<=now_ms()))) {
        tvh_exec(db,"ROLLBACK"); sqlite3_close(db);
        return tvh_fail(err,*did?409:404,*did?"activation_not_pending":"resource_not_found","id","activation request is missing or no longer pending");
    }
    if (!approve) {
        const char *args[]={id};
        if (tvh_run(db,"UPDATE tvhome_activation SET status='revoked' WHERE id=? AND status!='consumed'",1,args) || tvh_exec(db,"COMMIT")) return tvh_tx_error(db,err);
        sqlite3_close(db);
        struct json_object *o=json_object_new_object(); json_object_object_add(o,"status",json_object_new_string(!strcmp(state,"consumed")?"consumed":"revoked")); return o;
    }
    if (count_query(db,"SELECT COUNT(*) FROM tvhome_principal WHERE device_fingerprint=? AND revoked=1",did)) {
        tvh_exec(db,"ROLLBACK"); sqlite3_close(db);
        return tvh_fail(err,403,"tv_forbidden","device","terminal identity disabled; enable explicitly before approval");
    }
    scalar_text(db,"SELECT id FROM tvhome_principal WHERE device_fingerprint=?",did,principal,sizeof(principal));
    scalar_text(db,"SELECT terminal_id FROM tvhome_principal WHERE device_fingerprint=?",did,term,sizeof(term));
    if (!*term && (tvh_secret(term,sizeof(term),"tv_") || tvh_secret(principal,sizeof(principal),"principal_"))) return tvh_tx_error(db,err);
    if (tvh_secret(code,sizeof(code),"act_") || tvh_hash(code,hash)) return tvh_tx_error(db,err);
    snprintf(expires,sizeof(expires),"%lld",(long long)(now_ms()+ttl*1000));
    snprintf(created,sizeof(created),"%lld",(long long)time(NULL));
    const char *pa[]={principal,term,did,created};
    const char *ta[]={term,jstr(body,"name")?jstr(body,"name"):did,did,created,created};
    const char *aa[]={hash,expires,term,principal,id};
    if (tvh_run(db,"INSERT OR IGNORE INTO tvhome_principal(id,terminal_id,device_fingerprint,created_at) VALUES(?,?,?,?)",4,pa) ||
        tvh_run(db,"INSERT OR IGNORE INTO tvhome_terminal(id,name,device_id,created_at,updated_at) VALUES(?,?,?,?,?)",5,ta) ||
        tvh_run(db,"UPDATE tvhome_activation SET status='approved',code_hash=?,expires_at_ms=?,terminal_id=?,principal_id=? WHERE id=?",5,aa) || tvh_exec(db,"COMMIT")) return tvh_tx_error(db,err);
    sqlite3_close(db);
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"id",json_object_new_string(id));
    json_object_object_add(o,"status",json_object_new_string("approved"));
    json_object_object_add(o,"activation_code",json_object_new_string(code));
    json_object_object_add(o,"terminal_id",json_object_new_string(term));
    json_object_object_add(o,"expires_at_ms",json_object_new_int64(strtoll(expires,NULL,10)));
    return o;
}

static struct json_object *tvh_issue_session(sqlite3 *db,const char *term,const char *principal,const char *did,struct tvhome_err *err)
{
    char token[64],expires[32],created[32],hb[32];
    if (tvh_secret(token,sizeof(token),"tv_sess_")) return tvh_tx_error(db,err);
    snprintf(expires,sizeof(expires),"%lld",(long long)(now_ms()+TVH_SESSION_TTL_SEC*1000LL));
    snprintf(created,sizeof(created),"%lld",(long long)time(NULL));
    const char *old[]={term}, *args[]={token,term,principal,did,expires,created};
    if (tvh_run(db,"UPDATE tvhome_session SET revoked=1 WHERE terminal_id=?",1,old) ||
        tvh_run(db,"INSERT INTO tvhome_session(token,terminal_id,principal_id,device_id,expires_at_ms,created_at) VALUES(?,?,?,?,?,?)",6,args) || tvh_exec(db,"COMMIT")) return tvh_tx_error(db,err);
    struct json_object *o=json_object_new_object();
    scalar_text(db,"SELECT heartbeat_seconds FROM tvhome_settings WHERE id=1",NULL,hb,sizeof(hb));
    json_object_object_add(o,"token",json_object_new_string(token));
    json_object_object_add(o,"terminal_id",json_object_new_string(term));
    json_object_object_add(o,"expires_at_ms",json_object_new_int64(strtoll(expires,NULL,10)));
    json_object_object_add(o,"heartbeat_seconds",json_object_new_int(atoi(hb)));
    json_object_object_add(o,"config_version",json_object_new_int64(tvh_config_version(db)));
    json_object_object_add(o,"ws_url",json_object_new_string(TVH_WS_URL));
    sqlite3_close(db); return o;
}

struct json_object *tvhome_session_create(struct json_object *body,struct tvhome_err *err)
{
    sqlite3 *db=NULL; sqlite3_stmt *st=NULL;
    struct json_object *device=jobj(body,"device");
    const char *did=jstr(device,"device_id"),*code=jstr(jobj(body,"activation"),"code");
    char hash[65],term[TVH_MAX_ID]="",principal[TVH_MAX_ID]="",bound[129]="",state[24]="",id[64]="";
    int64_t exp=0;
    tvh_reset(err);
    if (!did || !*did || strlen(did)>128) return tvh_fail(err,400,"invalid_parameter","device.device_id","device id required");
    if (!code || tvh_hash(code,hash)) return tvh_fail(err,401,"invalid_activation","activation.code","activation code required");
    if (tvh_open(&db,err)) return NULL;
    if (tvh_exec(db,"BEGIN IMMEDIATE")) return tvh_tx_error(db,err);
    if (sqlite3_prepare_v2(db,"SELECT id,terminal_id,principal_id,device_id,status,expires_at_ms FROM tvhome_activation WHERE code_hash=?",-1,&st,NULL)!=SQLITE_OK) return tvh_tx_error(db,err);
    sqlite3_bind_text(st,1,hash,-1,SQLITE_TRANSIENT);
    if (sqlite3_step(st)==SQLITE_ROW) {
        snprintf(id,sizeof(id),"%s",col_text(st,0)); snprintf(term,sizeof(term),"%s",col_text(st,1)); snprintf(principal,sizeof(principal),"%s",col_text(st,2));
        snprintf(bound,sizeof(bound),"%s",col_text(st,3)); snprintf(state,sizeof(state),"%s",col_text(st,4)); exp=col_i64(st,5);
    }
    sqlite3_finalize(st);
    const char *failure=!*id?"invalid_activation":!strcmp(state,"consumed")?"activation_consumed":!strcmp(state,"revoked")?"activation_revoked":exp<=now_ms()?"activation_expired":strcmp(state,"approved")?"invalid_activation":NULL;
    if (failure || strcmp(bound,did) || count_query(db,"SELECT COUNT(*) FROM tvhome_principal WHERE id=? AND revoked=1",principal)) {
        tvh_exec(db,"ROLLBACK"); sqlite3_close(db);
        return tvh_fail(err,failure?401:403,failure?failure:strcmp(bound,did)?"device_bound":"tv_forbidden","activation.code","activation not usable for this device");
    }
    const char *aa[]={id}, *pa[]={term,json_object_to_json_string_ext(device,JSON_C_TO_STRING_PLAIN)};
    if (tvh_run(db,"UPDATE tvhome_activation SET status='consumed' WHERE id=?",1,aa) ||
        tvh_run(db,"INSERT OR REPLACE INTO tvhome_device_profile(terminal_id,profile_json) VALUES(?,?)",2,pa)) return tvh_tx_error(db,err);
    term_set_text(db,"model",term,jstr(device,"model"));
    return tvh_issue_session(db,term,principal,did,err);
}

struct json_object *tvhome_session_refresh(const char *token,struct tvhome_err *err)
{
    sqlite3 *db=NULL; char term[TVH_MAX_ID],principal[TVH_MAX_ID],did[129];
    tvh_reset(err);
    if (tvh_open(&db,err)) return NULL;
    if (tvh_exec(db,"BEGIN IMMEDIATE")) return tvh_tx_error(db,err);
    if (tvh_session_terminal(db,token,term,sizeof(term),err)) { tvh_exec(db,"ROLLBACK"); sqlite3_close(db); return NULL; }
    scalar_text(db,"SELECT principal_id FROM tvhome_session WHERE token=?",token,principal,sizeof(principal));
    scalar_text(db,"SELECT device_id FROM tvhome_session WHERE token=?",token,did,sizeof(did));
    return tvh_issue_session(db,term,principal,did,err);
}

struct json_object *tvhome_terminal_action(const char *id,const char *action,struct tvhome_err *err)
{
    sqlite3 *db=NULL; const char *args[]={id};
    tvh_reset(err);
    if (strcmp(action,"kick") && strcmp(action,"disable") && strcmp(action,"enable") && strcmp(action,"refresh")) return tvh_fail(err,404,"resource_not_found","action","unknown terminal command");
    if (tvh_open(&db,err)) return NULL;
    if (!row_exists(db,"SELECT 1 FROM tvhome_terminal WHERE id=?",id)) { sqlite3_close(db); return tvh_fail(err,404,"resource_not_found","id","terminal not found"); }
    if (tvh_exec(db,"BEGIN IMMEDIATE")) return tvh_tx_error(db,err);
    if (!strcmp(action,"refresh")) { if (tvh_exec(db,"UPDATE tvhome_settings SET config_version=config_version+1 WHERE id=1")) return tvh_tx_error(db,err); }
    else {
        if (strcmp(action,"enable") && tvh_run(db,"UPDATE tvhome_session SET revoked=1 WHERE terminal_id=?",1,args)) return tvh_tx_error(db,err);
        if (!strcmp(action,"disable") && tvh_run(db,"UPDATE tvhome_principal SET revoked=1 WHERE terminal_id=?",1,args)) return tvh_tx_error(db,err);
        if (!strcmp(action,"enable") && tvh_run(db,"UPDATE tvhome_principal SET revoked=0 WHERE terminal_id=?",1,args)) return tvh_tx_error(db,err);
    }
    if (tvh_exec(db,"COMMIT")) return tvh_tx_error(db,err);
    struct json_object *o=terminal_full_by_id(db,id,now_ms(),settings_window_ms(db));
    json_object_object_add(o,"action",json_object_new_string(action));
    sqlite3_close(db); return o;
}

struct json_object *tvhome_group_display_get(const char *id,struct tvhome_err *err)
{
    sqlite3 *db=NULL;char eff[TVH_MAX_ID];struct json_object *o;
    tvh_reset(err);if(tvh_open(&db,err))return NULL;
    if(!row_exists(db,"SELECT 1 FROM tvhome_group WHERE id=?",id)){sqlite3_close(db);return tvh_fail(err,404,"resource_not_found","id","group not found");}
    resolve_theme_id(db,"",id,eff,sizeof(eff));o=resolve_display(db,eff,id,NULL);
    json_object_object_add(o,"override",group_display_layer(db,id));sqlite3_close(db);return o;
}

/* Shared by the TVHome operations/data modules, never by other identities. */
int tvhome_db_open(sqlite3 **db,struct tvhome_err *e) {tvh_reset(e);return tvh_open(db,e);}
int tvhome_authorize(sqlite3 *db,const char *token,char *term,size_t size,struct tvhome_err *e) {return tvh_session_terminal(db,token,term,size,e);}
struct json_object *tvhome_error(struct tvhome_err *e,int status,const char *code,const char *field,const char *message) {return tvh_fail(e,status,code,field,message);}

struct json_object *tvhome_theme_export(const char *id,struct tvhome_err *e)
{
    struct json_object *o=tvhome_theme_get(id,e);if(!o)return NULL;
    struct json_object *library=tvhome_assets_get(NULL,e);if(!library){json_object_put(o);return NULL;}
    struct json_object *refs=json_object_new_array(),*assets=tv_get(library,"assets");
    for(size_t i=0;i<json_object_array_length(assets);i++){
        struct json_object *a=json_object_array_get_idx(assets,i),*uses=tv_get(a,"references");
        for(size_t j=0;j<json_object_array_length(uses);j++){struct json_object *r=json_object_array_get_idx(uses,j);
            if(!strcmp(tv_str(r,"type"),"theme")&&!strcmp(tv_str(r,"id"),id)){
                struct json_object *ref=json_object_new_object();json_object_object_add(ref,"id",json_object_new_string(tv_str(a,"id")));json_object_object_add(ref,"sha256",json_object_new_string(tv_str(a,"sha256")));json_object_array_add(refs,ref);break;
            }
        }
    }
    json_object_put(library);json_object_object_add(o,"format",json_object_new_string("dreamingos-tvhome-theme-v1"));
    json_object_object_add(o,"assets_included",json_object_new_boolean(0));json_object_object_add(o,"asset_refs",refs);return o;
}
struct json_object *tvhome_theme_import(struct json_object *body,struct tvhome_err *e)
{
    sqlite3 *db=NULL;if(tvh_open(&db,e))return NULL;
    if(strcmp(tv_str(body,"format"),"dreamingos-tvhome-theme-v1")||!json_object_is_type(tv_get(body,"asset_refs"),json_type_array)){
        sqlite3_close(db);return tvh_fail(e,400,"invalid_theme_import","format","Import a DreamingOS theme export with its asset dependency manifest");
    }
    if(tvhome_assets_validate(db,tv_get(body,"spec"),e)){sqlite3_close(db);return NULL;}
    sqlite3_close(db);struct json_object *assets=tvhome_assets_get(NULL,e);if(!assets)return NULL;
    struct json_object *list=tv_get(assets,"assets"),*manifest=tv_get(body,"asset_refs");
    for(size_t i=0;i<json_object_array_length(list);i++){
        struct json_object *a=json_object_array_get_idx(list,i);const char *id=tv_str(a,"id");
        /* Serialize a quoted ID: generated IDs contain no escapes, so a substring
         * match here exactly identifies a JSON string value, not a prefix. */
        char quoted[64];snprintf(quoted,sizeof(quoted),"\"%s\"",id);if(!strstr(tv_json(tv_get(body,"spec")),quoted))continue;
        int match=0;for(size_t j=0;j<json_object_array_length(manifest);j++){struct json_object *r=json_object_array_get_idx(manifest,j);if(!strcmp(tv_str(r,"id"),id)&&!strcmp(tv_str(r,"sha256"),tv_str(a,"sha256")))match=1;}
        if(!match){json_object_put(assets);return tvh_fail(e,400,"asset_identity_mismatch","asset_refs","Asset checksum is missing or differs; reselect the local asset explicitly");}
    }
    json_object_put(assets);return tvhome_theme_create(body,e);
}
struct json_object *tvhome_theme_reset(const char *id,struct json_object *body,struct tvhome_err *e)
{
    struct json_object *o=tvhome_theme_get(id,e);if(!o)return NULL;
    if(!jbool(o,"builtin",0)){json_object_put(o);return tvh_fail(e,400,"not_builtin_theme","id","Only the built-in theme can be restored");}
    json_object_put(o);struct json_object *update=json_object_new_object();json_object_object_add(update,"expected_revision",json_object_new_int64(tv_num(body,"expected_revision")));json_object_object_add(update,"spec",tvh_builtin_spec());
    o=tvhome_theme_update(id,update,e);json_object_put(update);return o;
}
