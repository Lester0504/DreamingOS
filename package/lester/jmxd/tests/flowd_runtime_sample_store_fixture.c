// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd/flowd_runtime_sample_store.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

static int mkdir_p(const char *path)
{
    char copy[512];
    char *p;

    if (!path || strlen(path) >= sizeof(copy))
        return -1;
    snprintf(copy, sizeof(copy), "%s", path);
    for (p = copy + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(copy, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return mkdir(copy, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static int write_counter(const char *root, const char *ifname,
                         const char *counter, uint64_t value)
{
    char directory[512];
    char path[640];
    FILE *fp;

    snprintf(directory, sizeof(directory), "%s/%s/statistics", root, ifname);
    if (mkdir_p(directory) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/%s", directory, counter);
    fp = fopen(path, "w");
    if (!fp)
        return -1;
    fprintf(fp, "%llu\n", (unsigned long long)value);
    return fclose(fp);
}

static int seed_interface(const char *root, const char *ifname, uint64_t base)
{
    return write_counter(root, ifname, "rx_bytes", base + 1) == 0 &&
           write_counter(root, ifname, "tx_bytes", base + 2) == 0 &&
           write_counter(root, ifname, "rx_packets", base + 3) == 0 &&
           write_counter(root, ifname, "tx_packets", base + 4) == 0 ? 0 : -1;
}

static int assert_row(sqlite3 *db, const char *wan, uint64_t base,
                      int64_t sample_ts)
{
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (sqlite3_prepare_v2(db,
        "SELECT rx_bytes,tx_bytes,rx_packets,tx_packets,sample_ts "
        "FROM flowd_wan_counters WHERE wan=?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, wan, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW &&
        (uint64_t)sqlite3_column_int64(st, 0) == base + 1 &&
        (uint64_t)sqlite3_column_int64(st, 1) == base + 2 &&
        (uint64_t)sqlite3_column_int64(st, 2) == base + 3 &&
        (uint64_t)sqlite3_column_int64(st, 3) == base + 4 &&
        sqlite3_column_int64(st, 4) == sample_ts)
        ok = 1;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

int main(void)
{
    char directory[] = "/tmp/flowd-runtime-store-XXXXXX";
    char sysfs[512];
    char db_path[512];
    struct flowd_runtime_wan_source sources[] = {
        { "wan", "pppoe-wan" },
        { "wan2", "pppoe-wan2" },
        { "missing", "does-not-exist" },
    };
    sqlite3 *db = NULL;
    size_t written = 0;
    int rc = 1;

    if (!mkdtemp(directory))
        return 1;
    snprintf(sysfs, sizeof(sysfs), "%s/sys", directory);
    snprintf(db_path, sizeof(db_path), "%s/flow.db", directory);
    if (seed_interface(sysfs, "pppoe-wan", 1000) != 0 ||
        seed_interface(sysfs, "pppoe-wan2", 2000) != 0 ||
        flowd_runtime_sample_store(sysfs, db_path, sources, 3, 12345,
                                   &written) != 0 || written != 2 ||
        sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK ||
        assert_row(db, "wan", 1000, 12345) != 0 ||
        assert_row(db, "wan2", 2000, 12345) != 0)
        goto done;
    sqlite3_close(db);
    db = NULL;
    if (seed_interface(sysfs, "pppoe-wan", 3000) != 0 ||
        flowd_runtime_sample_store(sysfs, db_path, sources, 1, 12375,
                                   &written) != 0 || written != 1 ||
        sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK ||
        assert_row(db, "wan", 3000, 12375) != 0)
        goto done;
    {
        sqlite3_stmt *st = NULL;
        int count = -1;

        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM flowd_wan_counters",
                              -1, &st, NULL) != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_ROW)
            goto done;
        count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        if (count != 1)
            goto done;
    }
    rc = 0;

done:
    if (db)
        sqlite3_close(db);
    if (rc == 0)
        puts("ok: flowd runtime sampler stores real counters and refreshes rows");
    return rc;
}
