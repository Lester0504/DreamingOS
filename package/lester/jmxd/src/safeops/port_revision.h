/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef JMX_SAFEOPS_PORT_REVISION_H
#define JMX_SAFEOPS_PORT_REVISION_H

#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* Read the configuration DB, not the separate task DB. Runtime counters are
 * excluded; callers can use this while holding the task transaction lock. */
static inline int safeops_port_revision(sqlite3 *db, const char *network_path,
                                       const char *ifname, char out[72])
{
    static const char sql[] =
        "SELECT p.owner_type,p.owner_id,c.ifname,c.configured_speed_mbps,"
        "c.configured_duplex,c.configured_autoneg,c.profile_id,c.native_vlan,"
        "c.tagged_vlans_json,c.poe_enabled,c.poe_mode,c.display_name,c.sort_order,"
        "v.id,v.native_vlan,v.tagged_vlans_json "
        "FROM physical_port p LEFT JOIN physical_port_config c ON c.ifname=p.name "
        "LEFT JOIN physical_port_profile v ON v.id=c.profile_id WHERE p.name=?1";
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    sqlite3_stmt *st = NULL;
    FILE *fp = NULL;
    unsigned char data[4096], digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    size_t n;
    int i, rc = -1;

    out[0] = '\0';
    if (!ctx || !db || !ifname || !ifname[0] ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    if (EVP_DigestUpdate(ctx, ifname, strlen(ifname) + 1) != 1 ||
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    for (i = 0; i < sqlite3_column_count(st); i++) {
        char prefix[48];
        const unsigned char *value = sqlite3_column_text(st, i);
        int size = sqlite3_column_bytes(st, i);
        int plen = snprintf(prefix, sizeof(prefix), "%d:%d:",
                            sqlite3_column_type(st, i), size);
        if (EVP_DigestUpdate(ctx, prefix, (size_t)plen) != 1 ||
            (size && EVP_DigestUpdate(ctx, value, (size_t)size) != 1))
            goto done;
    }
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    fp = fopen(network_path, "rb");
    if (!fp)
        goto done;
    while ((n = fread(data, 1, sizeof(data), fp)) > 0)
        if (EVP_DigestUpdate(ctx, data, n) != 1)
            goto done;
    if (ferror(fp) || EVP_DigestFinal_ex(ctx, digest, &len) != 1 || len != 32)
        goto done;
    memcpy(out, "sha256:", 7);
    for (i = 0; i < 32; i++)
        snprintf(out + 7 + i * 2, 3, "%02x", digest[i]);
    rc = 0;
done:
    if (fp) fclose(fp);
    sqlite3_finalize(st);
    EVP_MD_CTX_free(ctx);
    return rc;
}

#endif
