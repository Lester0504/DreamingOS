/* Fixture for the persisted lifetime WAN byte counters.
 *
 * jmx_db_update_wan_lifetime_usage() and jmx_db_read_wan_lifetime_usage() are
 * extracted from src/jmx_db.c, so this exercises shipped code against a real
 * SQLite file. The scenario under test is the one acceptance found on the live
 * router: PPPoE recreates its virtual interface on reconnect, the kernel byte
 * counter restarts at zero, and the reported cumulative usage collapses to
 * "since last connect" while still being labelled a total.
 *
 * The harness drives it as a script on stdin, one command per line:
 *   sample <wan> <rx> <tx> <online>   feed one poll
 *   read <wan>                        emit the reported totals as JSON
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <sqlite3.h>

static sqlite3 *g_db;

static int64_t g_fake_now = 1000;

/* Production uses now_s(); the fixture advances a virtual clock so reset
 * timestamps are deterministic. */
static int64_t now_s(void)
{
    return g_fake_now;
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

#include "wan_lifetime_extracted.h"

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS wan_lifetime_usage ("
    " wan_id TEXT PRIMARY KEY,"
    " first_seen_ts INTEGER NOT NULL DEFAULT 0,"
    " last_ts INTEGER NOT NULL DEFAULT 0,"
    " last_rx_bytes INTEGER NOT NULL DEFAULT 0,"
    " last_tx_bytes INTEGER NOT NULL DEFAULT 0,"
    " base_rx_bytes INTEGER NOT NULL DEFAULT 0,"
    " base_tx_bytes INTEGER NOT NULL DEFAULT 0,"
    " reset_count INTEGER NOT NULL DEFAULT 0,"
    " last_reset_ts INTEGER NOT NULL DEFAULT 0,"
    " sample_count INTEGER NOT NULL DEFAULT 0,"
    " updated_at INTEGER NOT NULL DEFAULT 0);";

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
        char verb[32] = "", wan[64] = "";
        unsigned long long rx = 0, tx = 0;
        int online = 1;

        line[strcspn(line, "\n")] = '\0';
        if (!line[0])
            continue;
        if (sscanf(line, "%31s", verb) != 1)
            continue;

        if (!strcmp(verb, "sample")) {
            if (sscanf(line, "%31s %63s %llu %llu %d", verb, wan, &rx, &tx, &online) != 5) {
                fprintf(stderr, "bad sample line: %s\n", line);
                return 2;
            }
            g_fake_now++;
            if (jmx_db_update_wan_lifetime_usage(wan, rx, tx, online) != 0) {
                fprintf(stderr, "update failed for %s\n", wan);
                return 2;
            }
        } else if (!strcmp(verb, "read")) {
            struct jmx_wan_lifetime_usage lt;
            int rc;

            if (sscanf(line, "%31s %63s", verb, wan) != 2) {
                fprintf(stderr, "bad read line: %s\n", line);
                return 2;
            }
            rc = jmx_db_read_wan_lifetime_usage(wan, &lt);
            if (rc != 0) {
                printf("{\"wan\":\"%s\",\"found\":false}\n", wan);
            } else {
                printf("{\"wan\":\"%s\",\"found\":true,"
                       "\"rx_bytes\":%" PRId64 ",\"tx_bytes\":%" PRId64 ","
                       "\"reset_count\":%d,\"last_reset_ts\":%" PRId64 ","
                       "\"first_seen_ts\":%" PRId64 ",\"sample_count\":%d}\n",
                       wan, lt.rx_bytes, lt.tx_bytes, lt.reset_count,
                       lt.last_reset_ts, lt.first_seen_ts, lt.sample_count);
            }
            fflush(stdout);
        } else if (!strcmp(verb, "publish")) {
            /* Exercise the response-shaping helper the API layers call, so the
             * published field names and source labels are covered too. */
            struct json_object *out;
            long long dev_rx = 0, dev_tx = 0;

            if (sscanf(line, "%31s %63s %lld %lld", verb, wan, &dev_rx, &dev_tx) != 4) {
                fprintf(stderr, "bad publish line: %s\n", line);
                return 2;
            }
            out = json_object_new_object();
            jmx_db_add_wan_cumulative_bytes(out, wan, (int64_t)dev_rx, (int64_t)dev_tx);
            printf("%s\n", json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
            fflush(stdout);
            json_object_put(out);
        } else {
            fprintf(stderr, "unknown verb: %s\n", verb);
            return 2;
        }
    }

    sqlite3_close(g_db);
    return 0;
}
