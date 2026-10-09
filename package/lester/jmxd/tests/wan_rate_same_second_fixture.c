// SPDX-License-Identifier: GPL-2.0-or-later
/* Regression contract for the intermittent all-WAN rate zeroing reported from
 * the app (Front-to-Backend-wan-status-rates-intermittently-zero-25pct).
 *
 * dw_calc_interface_rates() differentiates byte counters against the previous
 * net_interface_state row, and dw_now() has one-second resolution. Three
 * writers reach it (the metricsd interface_traffic step, the wan_health step of
 * the same tick, and dw_refresh_wan_state() ahead of every line_load request),
 * so two samples inside one second are routine. When that happened the old code
 * left the rate at 0 and the following jmx_db_write_interface_state() persisted
 * that 0 over an already-correct value, so the rate for that second was
 * destroyed rather than merely unavailable. Both WANs share one clock, hence
 * both lines went to zero together.
 *
 * dw_calc_interface_rates() is static in jmx_dreamingwrt_api.c, and that
 * translation unit needs ubus/uci/libjmx to link, so this fixture reproduces
 * the differentiation step against a real sqlite3 database with the same schema
 * and the same query, and asserts the behaviour the fix must hold:
 *
 *   1. two samples in one second keep the previous rate instead of writing 0
 *   2. a genuinely idle line still reports 0
 *   3. a stale previous row is not carried forward
 *   4. normal differentiation is unchanged
 *   5. the persisted row after a same-second refresh is not zeroed
 *
 * If dw_calc_interface_rates() changes, mirror it here. The point of the copy
 * is to pin the arithmetic and the carry-forward rule, which is where the
 * defect lived.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#define DW_WAN_RATE_STALE_SEC 15

static int failures;

static void check(int cond, const char *what)
{
    printf("%s: %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void check_i64(int64_t got, int64_t want, const char *what)
{
    if (got == want) {
        printf("ok: %s (%lld)\n", what, (long long)got);
        return;
    }
    printf("FAIL: %s: got %lld want %lld\n", what, (long long)got,
           (long long)want);
    failures++;
}

static sqlite3 *db;

static void db_must(int rc, const char *what)
{
    if (rc == SQLITE_OK || rc == SQLITE_DONE || rc == SQLITE_ROW)
        return;
    fprintf(stderr, "sqlite failure in %s: %s\n", what, sqlite3_errmsg(db));
    exit(2);
}

static void db_exec(const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sqlite exec failed: %s\n", err ? err : "?");
        exit(2);
    }
}

/* Same schema shape the daemon uses: one state row per interface, UNIQUE on
 * iface_id so the write is an upsert. */
static void schema_init(void)
{
    db_exec("CREATE TABLE net_interfaces("
            "iface_id INTEGER PRIMARY KEY, name TEXT UNIQUE, kind TEXT);");
    db_exec("CREATE TABLE net_interface_state("
            "iface_id INTEGER UNIQUE, ts INTEGER, online INTEGER,"
            "rx_bytes INTEGER, tx_bytes INTEGER,"
            "rx_rate INTEGER, tx_rate INTEGER,"
            "latency_ms INTEGER, loss_pct INTEGER);");
    db_exec("INSERT INTO net_interfaces(iface_id,name,kind) VALUES(1,'wan','wan');");
    db_exec("INSERT INTO net_interfaces(iface_id,name,kind) VALUES(2,'wan2','wan');");
}

static void state_write(const char *name, int64_t ts,
                        unsigned long long rx_bytes,
                        unsigned long long tx_bytes,
                        int64_t rx_rate, int64_t tx_rate)
{
    sqlite3_stmt *st = NULL;

    db_must(sqlite3_prepare_v2(db,
        "INSERT INTO net_interface_state"
        "(iface_id,ts,online,rx_bytes,tx_bytes,rx_rate,tx_rate,latency_ms,loss_pct) "
        "SELECT iface_id,?2,1,?3,?4,?5,?6,-1,-1 FROM net_interfaces WHERE name=?1 "
        "ON CONFLICT(iface_id) DO UPDATE SET ts=excluded.ts,"
        "rx_bytes=excluded.rx_bytes,tx_bytes=excluded.tx_bytes,"
        "rx_rate=excluded.rx_rate,tx_rate=excluded.tx_rate", -1, &st, NULL),
        "prepare state_write");
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)rx_bytes);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)tx_bytes);
    sqlite3_bind_int64(st, 5, rx_rate);
    sqlite3_bind_int64(st, 6, tx_rate);
    db_must(sqlite3_step(st), "step state_write");
    sqlite3_finalize(st);
}

static void state_read_rates(const char *name, int64_t *rx_rate, int64_t *tx_rate)
{
    sqlite3_stmt *st = NULL;

    *rx_rate = -1;
    *tx_rate = -1;
    db_must(sqlite3_prepare_v2(db,
        "SELECT s.rx_rate,s.tx_rate FROM net_interface_state s "
        "JOIN net_interfaces i ON s.iface_id=i.iface_id WHERE i.name=?1",
        -1, &st, NULL), "prepare state_read_rates");
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *rx_rate = sqlite3_column_int64(st, 0);
        *tx_rate = sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
}

/* Mirror of dw_calc_interface_rates() after the fix, with `now` injected so a
 * same-second sample can be expressed without sleeping. */
static void calc_rates(const char *name, unsigned long long rx_bytes,
                       unsigned long long tx_bytes, int64_t now,
                       int64_t *rx_rate, int64_t *tx_rate, int *carried_forward)
{
    sqlite3_stmt *st = NULL;
    unsigned long long prev_rx = 0, prev_tx = 0;
    int64_t prev_rx_rate = 0, prev_tx_rate = 0;
    int64_t prev_ts = 0;
    int64_t elapsed;
    int rc;

    if (rx_rate)
        *rx_rate = 0;
    if (tx_rate)
        *tx_rate = 0;
    if (carried_forward)
        *carried_forward = 0;
    if (!db || !name || !name[0])
        return;
    rc = sqlite3_prepare_v2(db,
        "SELECT s.rx_bytes,s.tx_bytes,s.ts,s.rx_rate,s.tx_rate "
        "FROM net_interface_state s JOIN net_interfaces i ON s.iface_id=i.iface_id "
        "WHERE i.name=?1 LIMIT 1", -1, &st, NULL);
    if (rc != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        prev_rx = (unsigned long long)sqlite3_column_int64(st, 0);
        prev_tx = (unsigned long long)sqlite3_column_int64(st, 1);
        prev_ts = sqlite3_column_int64(st, 2);
        prev_rx_rate = sqlite3_column_int64(st, 3);
        prev_tx_rate = sqlite3_column_int64(st, 4);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || prev_ts <= 0)
        return;
    elapsed = now - prev_ts;
    if (elapsed > 3600)
        return;
    if (elapsed <= 0) {
        if (prev_ts - now <= DW_WAN_RATE_STALE_SEC) {
            if (rx_rate)
                *rx_rate = prev_rx_rate;
            if (tx_rate)
                *tx_rate = prev_tx_rate;
            if (carried_forward && (prev_rx_rate > 0 || prev_tx_rate > 0))
                *carried_forward = 1;
        }
        return;
    }
    if (rx_rate && rx_bytes >= prev_rx)
        *rx_rate = (int64_t)((rx_bytes - prev_rx) / (unsigned long long)elapsed);
    if (tx_rate && tx_bytes >= prev_tx)
        *tx_rate = (int64_t)((tx_bytes - prev_tx) / (unsigned long long)elapsed);
}

/* The reported defect: a tick and a query land in the same second on both
 * lines. The previous rate must survive rather than being replaced by 0. */
static void test_same_second_keeps_previous_rate(void)
{
    int64_t rx_rate, tx_rate;
    int carried;

    state_write("wan", 1000, 5000000, 1000000, 150323, 52692);
    state_write("wan2", 1000, 2000000, 400000, 17794, 26595);

    /* Same second, counters have barely moved. */
    calc_rates("wan", 5000400, 1000100, 1000, &rx_rate, &tx_rate, &carried);
    check_i64(rx_rate, 150323, "same-second wan rx_rate carried forward");
    check_i64(tx_rate, 52692, "same-second wan tx_rate carried forward");
    check(carried == 1, "same-second wan reports rate_carried_forward");

    calc_rates("wan2", 2000300, 400050, 1000, &rx_rate, &tx_rate, &carried);
    check_i64(rx_rate, 17794, "same-second wan2 rx_rate carried forward");
    check_i64(tx_rate, 26595, "same-second wan2 tx_rate carried forward");
    check(carried == 1, "same-second wan2 reports rate_carried_forward");
}

/* The carry-forward must not invent traffic: an idle line differentiates to 0
 * and must report 0, which is what keeps a dead line from looking busy. */
static void test_idle_line_still_reports_zero(void)
{
    int64_t rx_rate, tx_rate;
    int carried;

    state_write("wan", 2000, 9000000, 3000000, 150323, 52692);
    /* One second later, not a single byte moved. */
    calc_rates("wan", 9000000, 3000000, 2002, &rx_rate, &tx_rate, &carried);
    check_i64(rx_rate, 0, "idle line rx_rate is 0");
    check_i64(tx_rate, 0, "idle line tx_rate is 0");
    check(carried == 0, "idle line does not claim carry-forward");
}

/* Past the staleness window there is nothing trustworthy to carry, so 0 is the
 * honest answer even for a same-second read. */
static void test_stale_previous_row_not_carried(void)
{
    int64_t rx_rate, tx_rate;
    int carried;

    state_write("wan", 3000, 9000000, 3000000, 150323, 52692);
    /* now == prev_ts is impossible past the window, so use a backwards clock,
     * the other way elapsed <= 0 is reached. */
    calc_rates("wan", 9000400, 3000100, 3000 - (DW_WAN_RATE_STALE_SEC + 5),
               &rx_rate, &tx_rate, &carried);
    check_i64(rx_rate, 0, "stale row rx_rate not carried");
    check_i64(tx_rate, 0, "stale row tx_rate not carried");
    check(carried == 0, "stale row does not claim carry-forward");
}

/* Ordinary differentiation must be untouched by the fix. */
static void test_normal_differentiation_unchanged(void)
{
    int64_t rx_rate, tx_rate;
    int carried;

    state_write("wan", 4000, 1000000, 500000, 0, 0);
    /* 2 s later: +400000 rx, +100000 tx. */
    calc_rates("wan", 1400000, 600000, 4002, &rx_rate, &tx_rate, &carried);
    check_i64(rx_rate, 200000, "two-second window rx_rate");
    check_i64(tx_rate, 50000, "two-second window tx_rate");
    check(carried == 0, "measured sample does not claim carry-forward");
}

/* End to end over the persisted row, which is where the damage actually
 * happened: the same-second refresh used to store 0 and the next reader saw
 * it. */
static void test_persisted_row_not_zeroed_by_same_second_refresh(void)
{
    int64_t rx_rate, tx_rate, stored_rx, stored_tx;
    int carried;

    /* A good sample lands at t=5000. */
    state_write("wan", 5000, 20000000, 8000000, 0, 0);
    calc_rates("wan", 20800000, 8200000, 5002, &rx_rate, &tx_rate, &carried);
    state_write("wan", 5002, 20800000, 8200000, rx_rate, tx_rate);
    state_read_rates("wan", &stored_rx, &stored_tx);
    check_i64(stored_rx, 400000, "measured rx_rate persisted");
    check_i64(stored_tx, 100000, "measured tx_rate persisted");

    /* A second writer runs inside the same second and rewrites the row. */
    calc_rates("wan", 20800300, 8200100, 5002, &rx_rate, &tx_rate, &carried);
    state_write("wan", 5002, 20800300, 8200100, rx_rate, tx_rate);
    state_read_rates("wan", &stored_rx, &stored_tx);
    check_i64(stored_rx, 400000, "same-second refresh keeps stored rx_rate");
    check_i64(stored_tx, 100000, "same-second refresh keeps stored tx_rate");
    check(carried == 1, "same-second refresh flags carry-forward");
}

int main(void)
{
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        fprintf(stderr, "cannot open in-memory db\n");
        return 2;
    }
    schema_init();

    test_same_second_keeps_previous_rate();
    test_idle_line_still_reports_zero();
    test_stale_previous_row_not_carried();
    test_normal_differentiation_unchanged();
    test_persisted_row_not_zeroed_by_same_second_refresh();

    sqlite3_close(db);
    if (failures) {
        printf("\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
