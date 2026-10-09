/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * terminal_policy.c - Unified IP terminal policy engine for DreamingWrt
 *
 * Implements per-IP/CIDR/rate/quota/lifetime/protocol deny policies with
 * atomic CRUD through a single database-backed API surface.
 */
#include "terminal_policy.h"

#include <sqlite3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>
#include <sys/stat.h>
#include <libgen.h>

/* -----------------------------------------------------------------------
 * Database layer
 * ----------------------------------------------------------------------- */
static sqlite3 *g_tp_db = NULL;
static pthread_mutex_t g_tp_db_mtx = PTHREAD_MUTEX_INITIALIZER;

static int tp_sql_exec(sqlite3 *db, const char *sql, char **errmsg)
{
    int rc = sqlite3_exec(db, sql, NULL, NULL, errmsg);
    if (rc != SQLITE_OK && errmsg) {
        fprintf(stderr, "[tp] sql error: %s\n", *errmsg);
        sqlite3_free(*errmsg);
    }
    return rc;
}

int tp_db_init(void)
{
    int rc;
    char *err = NULL;
    char *db_dir = NULL;
    struct stat st;

    /* Ensure directory exists */
    db_dir = strdup(TP_DB_PATH);
    if (!db_dir) return -ENOMEM;
    {
        char *dir = dirname(db_dir);
        if (stat(dir, &st) != 0) {
            mkdir(dir, 0755);
        }
    }
    free(db_dir);

    rc = sqlite3_open_v2(TP_DB_PATH, &g_tp_db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[tp] open failed: %s\n", sqlite3_errmsg(g_tp_db));
        g_tp_db = NULL;
        return -1;
    }

    /* WAL mode + busy timeout */
    tp_sql_exec(g_tp_db, "PRAGMA journal_mode=WAL", NULL);
    tp_sql_exec(g_tp_db, "PRAGMA busy_timeout=5000", NULL);

    /* Create tables */
    const char *stmts[] = {
        "CREATE TABLE IF NOT EXISTS policies ("
        "  id TEXT PRIMARY KEY,"
        "  name TEXT NOT NULL DEFAULT '',"
        "  remark TEXT NOT NULL DEFAULT '',"
        "  enabled INTEGER NOT NULL DEFAULT 1,"
        "  rate_upload_kbps INTEGER NOT NULL DEFAULT 0,"
        "  rate_download_kbps INTEGER NOT NULL DEFAULT 0,"
        "  rate_mode TEXT NOT NULL DEFAULT 'per_ip',"
        "  started_at INTEGER NOT NULL DEFAULT 0,"
        "  duration_count INTEGER NOT NULL DEFAULT 0,"
        "  duration_unit TEXT NOT NULL DEFAULT 'days',"
        "  deadline_at INTEGER NOT NULL DEFAULT 0,"
        "  quota_bytes INTEGER NOT NULL DEFAULT 0,"
        "  quota_accounting TEXT NOT NULL DEFAULT 'bidirectional',"
        "  quota_mode TEXT NOT NULL DEFAULT 'shared',"
        "  deny_protocols TEXT NOT NULL DEFAULT '',"
        "  status TEXT NOT NULL DEFAULT 'active',"
        "  last_transition_at INTEGER NOT NULL DEFAULT 0,"
        "  generation INTEGER NOT NULL DEFAULT 1,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL,"
        "  CHECK (rate_upload_kbps >= 0),"
        "  CHECK (rate_download_kbps >= 0),"
        "  CHECK (duration_count >= 0),"
        "  CHECK (quota_bytes >= 0)"
        ")",
        "CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled)",
        "CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status)",
        "CREATE INDEX IF NOT EXISTS idx_policies_deadline ON policies(deadline_at)",

        "CREATE TABLE IF NOT EXISTS targets ("
        "  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
        "  family INTEGER NOT NULL,"
        "  kind TEXT NOT NULL,"
        "  prefix TEXT NOT NULL,"
        "  prefix_len INTEGER NOT NULL,"
        "  PRIMARY KEY (policy_id, family, prefix)"
        ")",

        "CREATE TABLE IF NOT EXISTS quota_usage ("
        "  policy_id TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,"
        "  used_bytes INTEGER NOT NULL DEFAULT 0,"
        "  checkpoint_at INTEGER NOT NULL DEFAULT 0"
        ")",
    };

    for (size_t i = 0; i < sizeof(stmts)/sizeof(stmts[0]); i++) {
        if ((rc = tp_sql_exec(g_tp_db, stmts[i], &err)) != SQLITE_OK) {
            fprintf(stderr, "[tp] schema[%zu] failed: %s\n", i, err ? err : "unknown");
            sqlite3_free(err);
            tp_db_close();
            return -1;
        }
    }

    return 0;
}

void tp_db_close(void)
{
    if (g_tp_db) {
        sqlite3_close(g_tp_db);
        g_tp_db = NULL;
    }
}

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */
static inline time_t tp_now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (time_t)ts.tv_sec;
}

static const char *json_str_def(struct json_object *obj, const char *key,
                                 const char *def)
{
    struct json_object *v;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return json_object_get_string(v);
}

static int json_bool_def(struct json_object *obj, const char *key, int def)
{
    struct json_object *v;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return json_object_get_boolean(v);
}

static long long json_int_def(struct json_object *obj, const char *key, long long def)
{
    struct json_object *v;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return (long long)json_object_get_int64(v);
}

/* Check valid IPv4 CIDR notation like "192.168.1.0/24" */
static int tp_is_cidr(const char *addr)
{
    return strchr(addr, '/') != NULL;
}

/* Validate and parse host address or CIDR into struct in_addr. Returns 1 on success. */
static int tp_parse_ipv4(const char *addr, struct in_addr *out, int *prefix_len)
{
    char buf[64];
    char *slash;

    snprintf(buf, sizeof(buf), "%s", addr);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        *prefix_len = atoi(slash + 1);
        if (*prefix_len < 0 || *prefix_len > 32) return 0;
    } else {
        *prefix_len = 32;
    }

    if (inet_pton(AF_INET, buf, out) != 1) return 0;
    return 1;
}

/* Validate and parse IPv6 address or CIDR. Returns 1 on success. */
static int tp_parse_ipv6(const char *addr, struct in6_addr *out, int *prefix_len)
{
    char buf[128];
    char *slash;

    snprintf(buf, sizeof(buf), "%s", addr);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        *prefix_len = atoi(slash + 1);
        if (*prefix_len < 0 || *prefix_len > 128) return 0;
    } else {
        *prefix_len = 128;
    }

    if (inet_pton(AF_INET6, buf, out) != 1) return 0;
    return 1;
}

