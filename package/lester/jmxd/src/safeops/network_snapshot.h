// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_SAFEOPS_NETWORK_SNAPSHOT_H
#define DWRT_SAFEOPS_NETWORK_SNAPSHOT_H

#include <sqlite3.h>
#include <json-c/json.h>
#include <string.h>

struct safeops_network_table {
    const char *name;
    const char *key;
    const char *value;
};

static const struct safeops_network_table safeops_wan_tables[] = {
    {"wan", "id", NULL}, {"wan_address", "wan_id", NULL}, {"wan_advanced", "wan_id", NULL},
    {"wan_bond", "wan_id", NULL}, {"wan_dns_policy", "wan_id", NULL},
    {"hybrid_line", "parent_wan_id", NULL}, {NULL, NULL, NULL}
};
static const struct safeops_network_table safeops_lan_tables[] = {
    {"lan", "id", NULL}, {"lan_port", "lan_id", NULL}, {"lan_address", "lan_id", NULL},
    {"lan_dhcp", "lan_id", NULL}, {"lan_ipv6", "lan_id", NULL}, {NULL, NULL, NULL}
};
static const struct safeops_network_table safeops_dns_tables[] = {
    {"dns_service", "id", "1"}, {"dns_listen_interface", "service_id", "1"},
    {"dns_upstream", NULL, NULL}, {"dns_rule", NULL, NULL},
    {"network_meta", "key", "dns_service.apply_state"}, {NULL, NULL, NULL}
};
static const struct safeops_network_table safeops_dhcp_tables[] = {
    {"lan", "id", NULL}, {"lan_address", "lan_id", NULL},
    {"dhcp_scope", "lan_id", NULL}, {"lan_dhcp", "lan_id", NULL}, {NULL, NULL, NULL}
};

static inline const struct safeops_network_table *safeops_network_tables(const char *domain)
{
    if (domain && (!strcmp(domain, "wan") || !strcmp(domain, "iptv"))) return safeops_wan_tables;
    if (domain && !strcmp(domain, "lan")) return safeops_lan_tables;
    if (domain && !strcmp(domain, "dns")) return safeops_dns_tables;
    if (domain && !strcmp(domain, "dhcp")) return safeops_dhcp_tables;
    return NULL;
}

/* Raw database rows are for the encrypted rollback vault, never API responses. */
static inline struct json_object *safeops_network_rows(sqlite3 *db,
                                                       const char *domain,
                                                       const char *id)
{
    const struct safeops_network_table *tables = safeops_network_tables(domain);
    struct json_object *out = json_object_new_object();
    sqlite3_stmt *st = NULL;
    int i, rc;

    if (!tables || !id || !id[0] || (!strcmp(domain, "dns") && strcmp(id, "1"))) goto fail;
    for (i = 0; tables[i].name; i++) {
        char *sql = tables[i].key ?
            sqlite3_mprintf("SELECT * FROM \"%w\" WHERE \"%w\"=?1 ORDER BY rowid",
                            tables[i].name, tables[i].key) :
            sqlite3_mprintf("SELECT * FROM \"%w\" ORDER BY rowid", tables[i].name);
        struct json_object *rows = json_object_new_array();
        rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
        sqlite3_free(sql);
        json_object_object_add(out, tables[i].name, rows);
        if (rc != SQLITE_OK) goto fail;
        if (tables[i].key)
            sqlite3_bind_text(st, 1, tables[i].value ? tables[i].value : id, -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            struct json_object *row = json_object_new_object();
            int col;
            for (col = 0; col < sqlite3_column_count(st); col++) {
                struct json_object *v = NULL;
                switch (sqlite3_column_type(st, col)) {
                case SQLITE_INTEGER:
                    v = json_object_new_int64(sqlite3_column_int64(st, col)); break;
                case SQLITE_FLOAT:
                    v = json_object_new_double(sqlite3_column_double(st, col)); break;
                case SQLITE_TEXT:
                    v = json_object_new_string_len((const char *)sqlite3_column_text(st, col),
                                                    sqlite3_column_bytes(st, col)); break;
                case SQLITE_NULL: break;
                default: json_object_put(row); goto fail;
                }
                json_object_object_add(row, sqlite3_column_name(st, col), v);
            }
            json_object_array_add(rows, row);
        }
        sqlite3_finalize(st); st = NULL;
        if (rc != SQLITE_DONE || (i == 0 &&
            (json_object_array_length(rows) > 1 ||
             (strcmp(domain, "iptv") && json_object_array_length(rows) != 1))))
            goto fail;
    }
    return out;
fail:
    if (st) sqlite3_finalize(st);
    json_object_put(out);
    return NULL;
}

/* Caller owns BEGIN/COMMIT. Only fixed tables and the original entity may change. */
static inline int safeops_network_restore_rows(sqlite3 *db, const char *domain,
                                                const char *id,
                                                struct json_object *snapshot)
{
    const struct safeops_network_table *tables = safeops_network_tables(domain);
    sqlite3_stmt *st = NULL;
    int i, count = 0;

    if (!tables || !id || !snapshot || (!strcmp(domain, "dns") && strcmp(id, "1"))) return -1;
    while (tables[count].name) count++;
    for (i = 0; i < count; i++) {
        struct json_object *rows = NULL;
        size_t r;
        if (!json_object_object_get_ex(snapshot, tables[i].name, &rows) ||
            !json_object_is_type(rows, json_type_array) ||
            (i == 0 && (json_object_array_length(rows) > 1 ||
             (strcmp(domain, "iptv") && json_object_array_length(rows) != 1))))
            return -1;
        for (r = 0; r < json_object_array_length(rows); r++) {
            struct json_object *row = json_object_array_get_idx(rows, r), *key = NULL;
            if (!json_object_is_type(row, json_type_object))
                return -1;
            if (tables[i].key &&
                (!json_object_object_get_ex(row, tables[i].key, &key) || !key ||
                 (!json_object_is_type(key, json_type_string) && !json_object_is_type(key, json_type_int)) ||
                 strcmp(json_object_get_string(key), tables[i].value ? tables[i].value : id)))
                return -1;
        }
    }
    /* Keep the parent row: DELETE would cascade into unrelated policy tables. */
    for (i = count - 1; i > 0; i--) {
        char *sql = tables[i].key ?
            sqlite3_mprintf("DELETE FROM \"%w\" WHERE \"%w\"=?1", tables[i].name, tables[i].key) :
            sqlite3_mprintf("DELETE FROM \"%w\"", tables[i].name);
        int rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
        sqlite3_free(sql);
        if (rc != SQLITE_OK) goto fail;
        if (tables[i].key)
            sqlite3_bind_text(st, 1, tables[i].value ? tables[i].value : id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st); st = NULL;
        if (rc != SQLITE_DONE) goto fail;
    }
    /* An IPTV create has no parent in its before image; a delete has none in
     * its after image. The transaction checks dependencies before restoration. */
    if (!strcmp(domain, "iptv") &&
        !json_object_array_length(json_object_object_get(snapshot, "wan"))) {
        if (sqlite3_prepare_v2(db, "DELETE FROM wan WHERE id=?1", -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st); st = NULL;
        if (rc != SQLITE_DONE) goto fail;
    }
    for (i = 0; i < count; i++) {
        struct json_object *rows = NULL;
        size_t r;
        json_object_object_get_ex(snapshot, tables[i].name, &rows);
        for (r = 0; r < json_object_array_length(rows); r++) {
            struct json_object *row = json_object_array_get_idx(rows, r);
            sqlite3_str *query = sqlite3_str_new(db);
            char *sql;
            int col = 0, rc;
            sqlite3_str_appendf(query, "INSERT INTO \"%w\" (", tables[i].name);
            json_object_object_foreach(row, name, value) {
                (void)value;
                sqlite3_str_appendf(query, "%s\"%w\"", col++ ? "," : "", name);
            }
            sqlite3_str_appendall(query, ") VALUES (");
            for (int n = 0; n < col; n++)
                sqlite3_str_appendf(query, "%s?", n ? "," : "");
            sqlite3_str_appendall(query, ")");
            if (i == 0) {
                int n = 0;
                sqlite3_str_appendf(query, " ON CONFLICT(\"%w\") DO UPDATE SET ", tables[i].key);
                json_object_object_foreach(row, column, ignored) {
                    (void)ignored;
                    if (!strcmp(column, tables[i].key)) continue;
                    sqlite3_str_appendf(query, "%s\"%w\"=excluded.\"%w\"",
                                        n++ ? "," : "", column, column);
                }
            }
            sql = sqlite3_str_finish(query);
            if (!sql) goto fail;
            rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
            sqlite3_free(sql);
            if (rc != SQLITE_OK) goto fail;
            col = 1;
            json_object_object_foreach(row, key, v) {
                (void)key;
                switch (json_object_get_type(v)) {
                case json_type_null: rc = sqlite3_bind_null(st, col); break;
                case json_type_int: rc = sqlite3_bind_int64(st, col, json_object_get_int64(v)); break;
                case json_type_double: rc = sqlite3_bind_double(st, col, json_object_get_double(v)); break;
                case json_type_string:
                    rc = sqlite3_bind_text(st, col, json_object_get_string(v),
                                           json_object_get_string_len(v), SQLITE_TRANSIENT); break;
                default: goto fail;
                }
                if (rc != SQLITE_OK) goto fail;
                col++;
            }
            rc = sqlite3_step(st);
            sqlite3_finalize(st); st = NULL;
            if (rc != SQLITE_DONE) goto fail;
        }
    }
    return 0;
fail:
    if (st) sqlite3_finalize(st);
    return -1;
}
#endif
