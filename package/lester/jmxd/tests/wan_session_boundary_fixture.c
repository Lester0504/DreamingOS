// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Runtime harness for WAN connection-time session boundaries.
 *
 * Acceptance found a recreated WAN reporting 8h16m of uptime: the new session
 * adopted the deleted line's still-open wan_session row because the row was
 * matched by wan_id string alone and deletion never ended it. A PPPoE redial
 * with a new IP had the same problem in the other direction, and additionally
 * inserted a duplicate row on every poll.
 *
 * The session tracker, its helpers and the response-shaping helper are
 * extracted verbatim from src/jmx_db.c and compiled against real SQLite, so
 * this exercises shipped code rather than a restatement of it.
 *
 * Driven as a script on stdin, one command per line:
 *   tick <n>                                 advance the virtual clock
 *   boot <n>                                 set reported system uptime
 *   poll <wan> <ifname> <ip> <gw> <online>   feed one sample ("-" means empty)
 *   delete <wan>                             the WAN-delete hook
 *   read <wan>                               emit the published contract
 *   rows <wan>                               emit row counts for that wan
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <sqlite3.h>

#define MAX_WAN_SESSIONS 16

static sqlite3 *g_db;
static int64_t  g_fake_now = 1000000;
static int64_t  g_fake_uptime = 0;   /* 0 => "unknown", disables the boot guard */

/* Production reads the wall clock and /proc/uptime; the fixture drives both so
 * session boundaries are deterministic. */
static int64_t now_s(void)
{
    return g_fake_now;
}

static int64_t db_read_system_uptime_sec(void)
{
    return g_fake_uptime;
}

static int jmx_db_init(void)
{
    return g_db ? 0 : -1;
}

static int db_prepare(sqlite3_stmt **st, const char *sql)
{
    if (sqlite3_prepare_v2(g_db, sql, -1, st, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s (%s)\n", sqlite3_errmsg(g_db), sql);
        return -1;
    }
    return 0;
}

static int db_step_done(sqlite3_stmt *st)
{
    int rc = sqlite3_step(st);

    return (rc == SQLITE_DONE || rc == SQLITE_ROW) ? 0 : -1;
}

static void bind_text_or_null(sqlite3_stmt *st, int idx, const char *v)
{
    if (v && v[0])
        sqlite3_bind_text(st, idx, v, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, idx);
}

/* Defined inside the extracted block, but used before its definition there
 * (production sees it via jmx_db.h). */
int64_t jmx_db_wan_session_started_at(const char *wan_id);

#include "wan_session_extracted.h"

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS wan_session ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " wan_id TEXT NOT NULL,"
    " ifname TEXT NOT NULL,"
    " ip TEXT,"
    " gateway TEXT,"
    " access_mode TEXT,"
    " started_at INTEGER NOT NULL,"
    " ended_at INTEGER,"
    " end_reason TEXT);";

static const char *arg_or_empty(const char *v)
{
    return (v && strcmp(v, "-") == 0) ? "" : v;
}

static void emit_rows(const char *wan)
{
    sqlite3_stmt *st = NULL;
    int open_rows = 0, total_rows = 0;
    char last_reason[64] = "";

    if (db_prepare(&st,
        "SELECT COUNT(*), SUM(ended_at IS NULL) FROM wan_session WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            total_rows = sqlite3_column_int(st, 0);
            open_rows = sqlite3_column_int(st, 1);
        }
        sqlite3_finalize(st);
    }
    st = NULL;
    if (db_prepare(&st,
        "SELECT COALESCE(end_reason,'') FROM wan_session "
        "WHERE wan_id=?1 AND ended_at IS NOT NULL ORDER BY id DESC LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, wan, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(last_reason, sizeof(last_reason), "%s",
                     (const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }
    printf("{\"wan\":\"%s\",\"rows\":%d,\"open_rows\":%d,\"last_end_reason\":\"%s\"}\n",
           wan, total_rows, open_rows, last_reason);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    char line[512];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <db path>\n", argv[0]);
        return 2;
    }
    if (sqlite3_open(argv[1], &g_db) != SQLITE_OK) {
        fprintf(stderr, "cannot open db: %s\n", argv[1]);
        return 2;
    }
    if (sqlite3_exec(g_db, SCHEMA, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "schema failed: %s\n", sqlite3_errmsg(g_db));
        return 2;
    }

    while (fgets(line, sizeof(line), stdin)) {
        char verb[32] = "", wan[64] = "", ifname[64] = "", ip[64] = "", gw[64] = "";
        long long n = 0;
        int online = 1;

        line[strcspn(line, "\n")] = '\0';
        if (!line[0] || line[0] == '#')
            continue;
        if (sscanf(line, "%31s", verb) != 1)
            continue;

        if (!strcmp(verb, "tick")) {
            if (sscanf(line, "%31s %lld", verb, &n) != 2)
                return 2;
            g_fake_now += (int64_t)n;
            if (g_fake_uptime > 0)
                g_fake_uptime += (int64_t)n;
        } else if (!strcmp(verb, "boot")) {
            if (sscanf(line, "%31s %lld", verb, &n) != 2)
                return 2;
            g_fake_uptime = (int64_t)n;
        } else if (!strcmp(verb, "poll")) {
            if (sscanf(line, "%31s %63s %63s %63s %63s %d",
                       verb, wan, ifname, ip, gw, &online) != 6) {
                fprintf(stderr, "bad poll line: %s\n", line);
                return 2;
            }
            jmx_db_update_wan_session(wan, arg_or_empty(ifname),
                                      arg_or_empty(ip), arg_or_empty(gw),
                                      "pppoe", online);
        } else if (!strcmp(verb, "delete")) {
            if (sscanf(line, "%31s %63s", verb, wan) != 2)
                return 2;
            jmx_db_close_wan_session(wan, "wan_deleted");
        } else if (!strcmp(verb, "read")) {
            struct json_object *out;

            if (sscanf(line, "%31s %63s", verb, wan) != 2)
                return 2;
            out = json_object_new_object();
            json_object_object_add(out, "wan", json_object_new_string(wan));
            jmx_db_add_wan_session_contract(out, wan, 0);
            printf("%s\n", json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
            fflush(stdout);
            json_object_put(out);
        } else if (!strcmp(verb, "rows")) {
            if (sscanf(line, "%31s %63s", verb, wan) != 2)
                return 2;
            emit_rows(wan);
        } else {
            fprintf(stderr, "unknown verb: %s\n", verb);
            return 2;
        }
    }

    sqlite3_close(g_db);
    return 0;
}
