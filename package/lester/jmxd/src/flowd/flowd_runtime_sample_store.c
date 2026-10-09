// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_runtime_sample_store.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

struct flowd_runtime_counter_row {
    const char *wan;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
};

static int flowd_runtime_counter_read(const char *sysfs_root,
                                      const char *ifname,
                                      const char *counter, uint64_t *out)
{
    char path[512];
    char text[64];
    char *end = NULL;
    unsigned long long value;
    FILE *fp;

    if (!sysfs_root || !ifname || !ifname[0] || !counter || !out ||
        snprintf(path, sizeof(path), "%s/%s/statistics/%s", sysfs_root,
                 ifname, counter) >= (int)sizeof(path))
        return -1;
    fp = fopen(path, "r");
    if (!fp || !fgets(text, sizeof(text), fp)) {
        if (fp)
            fclose(fp);
        return -1;
    }
    fclose(fp);
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno || end == text)
        return -1;
    while (*end && isspace((unsigned char)*end))
        end++;
    if (*end)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

int flowd_runtime_sample_store(const char *sysfs_root, const char *db_path,
                               const struct flowd_runtime_wan_source *sources,
                               size_t source_count, int64_t sample_ts,
                               size_t *written)
{
    struct flowd_runtime_counter_row *rows = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    size_t row_count = 0;
    size_t i;
    int rc = -1;

    if (written)
        *written = 0;
    if (!sysfs_root || !db_path || !sources || source_count == 0 || sample_ts <= 0)
        return -1;
    rows = calloc(source_count, sizeof(*rows));
    if (!rows)
        return -1;
    for (i = 0; i < source_count; i++) {
        struct flowd_runtime_counter_row *row = &rows[row_count];

        if (!sources[i].wan || !sources[i].wan[0] || !sources[i].ifname ||
            flowd_runtime_counter_read(sysfs_root, sources[i].ifname,
                                       "rx_bytes", &row->rx_bytes) != 0 ||
            flowd_runtime_counter_read(sysfs_root, sources[i].ifname,
                                       "tx_bytes", &row->tx_bytes) != 0 ||
            flowd_runtime_counter_read(sysfs_root, sources[i].ifname,
                                       "rx_packets", &row->rx_packets) != 0 ||
            flowd_runtime_counter_read(sysfs_root, sources[i].ifname,
                                       "tx_packets", &row->tx_packets) != 0)
            continue;
        row->wan = sources[i].wan;
        row_count++;
    }
    if (row_count == 0)
        goto done;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 1000);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS flowd_wan_counters ("
            "wan TEXT PRIMARY KEY,rx_bytes INTEGER NOT NULL,tx_bytes INTEGER NOT NULL,"
            "rx_packets INTEGER NOT NULL,tx_packets INTEGER NOT NULL,sample_ts INTEGER NOT NULL)",
            NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(db, "DELETE FROM flowd_wan_counters", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "INSERT INTO flowd_wan_counters(wan,rx_bytes,tx_bytes,rx_packets,tx_packets,sample_ts) "
            "VALUES(?1,?2,?3,?4,?5,?6)", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    for (i = 0; i < row_count; i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_text(st, 1, rows[i].wan, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)rows[i].rx_bytes);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)rows[i].tx_bytes);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)rows[i].rx_packets);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)rows[i].tx_packets);
        sqlite3_bind_int64(st, 6, sample_ts);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    if (written)
        *written = row_count;
    rc = 0;
    goto done;

rollback:
    if (st)
        sqlite3_finalize(st);
    st = NULL;
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
done:
    if (st)
        sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    free(rows);
    return rc;
}
