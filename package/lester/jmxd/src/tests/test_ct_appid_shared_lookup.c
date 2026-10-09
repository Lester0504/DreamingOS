/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The realtime rich-flow producer and the compact snapshot must resolve the
 * kernel's per-connection appid through one parser and one match rule. This
 * fixture exercises the shared accessors against a temporary ct_appid file,
 * including the cases that previously produced silent misses: a non-default
 * conntrack zone, an IPv6 tuple, an unreliable (ignored) classification, and a
 * tuple that is absent from the export.
 */
#include "client_connections_snapshot.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *get_app_name_by_id(int id)
{
    (void)id;
    return "";
}

static void write_table(const char *path)
{
    FILE *fp = fopen(path, "w");

    assert(fp);
    fputs("# ct_appid_version 1\n", fp);
    fputs("# scanned 2121 appid_bearing 42 exported 42 capacity 8192 truncated 0\n", fp);
    fputs("family zone proto src src_port dst dst_port app_id match_status wan_id ct_mark route_mark\n", fp);
    /* reliable classification, wan 3 */
    fputs("4 0 6 192.168.30.2 45876 147.79.20.16 443 100000301 0x80000004 3 0x03e80003 0x00010003\n", fp);
    /* reliable classification in a non-default zone */
    fputs("4 7 6 192.168.30.9 51000 1.1.1.1 443 100000470 0x80000004 1 0x03e80001 0x00010001\n", fp);
    /* ignore bit set: evidence exists but must not be trusted for the app */
    fputs("4 0 17 192.168.30.2 61785 8.8.8.8 443 100000999 0x80000005 2 0x03e80002 0x00010002\n", fp);
    /* IPv6, non-canonical spelling on purpose */
    fputs("6 0 17 fd00:0030:0001:0000:be24:11ff:fe1c:9fec 61785 "
          "2408:8710:0020:3f27:002d:0000:0000:0000 443 100000249 0x80000004 3 "
          "0x03e80003 0x00010003\n", fp);
    fclose(fp);
}

int main(void)
{
    struct dw_ct_appid_stats stats;
    struct dw_ct_appid_evidence ev;
    struct dw_ct_appid_table *table;
    const char *path = "ct_appid_fixture.txt";

    write_table(path);
    table = dw_ct_appid_table_load_path(path, &stats);
    assert(table);
    assert(stats.available && stats.version == 1 && stats.version_supported);
    assert(stats.rows == 4 && dw_ct_appid_table_rows(table) == 4);
    assert(stats.scanned == 2121 && stats.appid_bearing == 42 &&
           stats.capacity == 8192 && stats.truncated == 0);

    /* exact IPv4 hit in zone 0 carries both the app and the egress WAN */
    assert(dw_ct_appid_table_lookup(table, 4, 0, 6, "192.168.30.2", 45876,
                                    "147.79.20.16", 443, &ev) == 1);
    assert(ev.app_id == 100000301 && ev.reliable && ev.wan_id == 3);

    /* zone is part of the key: the same tuple in zone 7 must not match zone 0 */
    assert(dw_ct_appid_table_lookup(table, 4, 0, 6, "192.168.30.9", 51000,
                                    "1.1.1.1", 443, &ev) == 0);
    assert(dw_ct_appid_table_lookup(table, 4, 7, 6, "192.168.30.9", 51000,
                                    "1.1.1.1", 443, &ev) == 1);
    assert(ev.app_id == 100000470 && ev.reliable && ev.wan_id == 1);

    /* ignore bit: evidence present, app not trustworthy, WAN still usable */
    assert(dw_ct_appid_table_lookup(table, 4, 0, 17, "192.168.30.2", 61785,
                                    "8.8.8.8", 443, &ev) == 1);
    assert(ev.app_id == 100000999 && !ev.reliable && ev.wan_id == 2);

    /* IPv6 matches regardless of how the caller spells the address */
    assert(dw_ct_appid_table_lookup(table, 6, 0, 17,
                                    "fd00:30:1:0:be24:11ff:fe1c:9fec", 61785,
                                    "2408:8710:20:3f27:2d::", 443, &ev) == 1);
    assert(ev.app_id == 100000249 && ev.reliable && ev.wan_id == 3);

    /* a tuple the kernel never classified stays a miss, not a nearby match */
    assert(dw_ct_appid_table_lookup(table, 4, 0, 6, "192.168.30.2", 45877,
                                    "147.79.20.16", 443, &ev) == 0);
    assert(ev.app_id == 0 && !ev.reliable && ev.wan_id == 0);

    /* protocol is part of the key too */
    assert(dw_ct_appid_table_lookup(table, 4, 0, 17, "192.168.30.2", 45876,
                                    "147.79.20.16", 443, &ev) == 0);

    dw_ct_appid_table_free(table);
    remove(path);
    puts("ct_appid shared lookup tests: ok");
    return 0;
}
