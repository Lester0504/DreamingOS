// SPDX-License-Identifier: GPL-2.0-or-later
/* Policy Table: services executors. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <libubox/utils.h>

#include "api_policy_write.h"
#include "api_policy_write_internal.h"
#include "api_policy_paths.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"
#include "../webd_admin_transaction.h"

static int webd_policy_pbr_db_init(sqlite3 *db, char *err, size_t err_len);
static void webd_policy_pbr_sqlite_text(sqlite3_stmt *st, int col,
                                        char *out, size_t out_len);
static int webd_policy_find_pbr_rule(sqlite3 *db, const char *id,
                                     char *rule_id, size_t rule_id_len,
                                     char *legacy_id, size_t legacy_id_len);
static int webd_policy_dhcp_section_name_exists(struct uci_package *pkg, const char *name);
static void webd_policy_dns_generated_section_name(struct uci_package *pkg,
                                                   const char *record_type,
                                                   char *out, size_t out_len);
static struct uci_section *webd_policy_find_dhcp_section(struct uci_package *pkg,
                                                         const char *id,
                                                         int *section_no_out);
static int webd_policy_dns_name_exists_any(struct uci_package *pkg,
                                           struct uci_section *exclude,
                                           const char *name,
                                           char *conflict, size_t conflict_len);
static int webd_policy_dns_set_enabled(struct uci_context *ctx,
                                       struct uci_section *s,
                                       int enable,
                                       char *err, size_t err_len,
                                       struct json_object *diff);
static int webd_policy_dns_name_valid(const char *name);
static int webd_policy_dhcp_backup(char *backup, size_t backup_len,
                                   char *err, size_t err_len);
static const char *webd_policy_dns_record_type_from_body(struct json_object *body);
static int webd_policy_dns_apply_fields(struct uci_context *ctx,
                                        struct uci_package *pkg,
                                        struct uci_section *s,
                                        struct json_object *body,
                                        int create,
                                        char *err, size_t err_len,
                                        struct json_object *diff);
static struct uci_section *webd_policy_find_network_route_section(struct uci_package *pkg,
                                                                  const char *id,
                                                                  int *section_no_out);
static const char *webd_policy_route_section_type_from_body(struct json_object *body);
static int webd_policy_static_route_apply_fields(struct uci_context *ctx,
                                                 struct uci_section *s,
                                                 struct json_object *body,
                                                 int create,
                                                 const char *operation,
                                                 char *err, size_t err_len,
                                                 struct json_object *diff);
static int webd_policy_pbr_backup(char *backup, size_t backup_len,
                                  char *err, size_t err_len);
static int webd_policy_pbr_runtime_reload(struct json_object *steps,
                                          struct json_object *warnings);
static int webd_policy_pbr_normalize_proto(const char *in, char *out, size_t out_len);
static void webd_policy_pbr_target_from_body(struct json_object *body,
                                             char *target, size_t target_len,
                                             char *route_table, size_t route_table_len);
static int webd_policy_pbr_apply_fields(sqlite3 *db,
                                        const char *rule_id,
                                        struct json_object *body,
                                        int create,
                                        const char *operation,
                                        char *err, size_t err_len,
                                        struct json_object *diff);

int webd_policy_sqm_queue_id_match(struct uci_section *s,
                                          const char *id,
                                          int section_no)
{
    char generated[256];

    if (!s || !id || !id[0] || !s->type)
        return 0;
    snprintf(generated, sizeof(generated), "uci-sqm-queue-%s-%d",
             s->e.name ? s->e.name : "anon", section_no);
    if (!strcmp(id, generated))
        return 1;
    if (s->e.name && !strcmp(id, s->e.name))
        return 1;
    return 0;
}

struct uci_section *webd_policy_find_sqm_queue_section(struct uci_package *pkg,
                                                              const char *id,
                                                              int *section_no_out)
{
    struct uci_element *e;
    int section_no = 0;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type || strcmp(s->type, "queue"))
            continue;
        section_no++;
        if (webd_policy_sqm_queue_id_match(s, id, section_no)) {
            if (section_no_out)
                *section_no_out = section_no;
            return s;
        }
    }
    return NULL;
}

int webd_policy_sqm_queue_exists(const char *id)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    int ok = 0;

    if (!id || !id[0])
        return 0;
    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "sqm", &pkg) != UCI_OK || !pkg)
        goto out;
    s = webd_policy_find_sqm_queue_section(pkg, id, NULL);
    ok = s != NULL;
out:
    if (pkg)
        uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return ok;
}

static int webd_policy_pbr_db_init(sqlite3 *db, char *err, size_t err_len)
{
    static const char *schema =
        "CREATE TABLE IF NOT EXISTS advanced_routing_global ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "engine TEXT NOT NULL DEFAULT 'sqlite -> jmx_route kernel marks + ip rule',"
        "apply_state TEXT NOT NULL DEFAULT 'draft',"
        "last_apply_at INTEGER NOT NULL DEFAULT 0,"
        "default_table TEXT NOT NULL DEFAULT 'main',"
        "object_revision INTEGER NOT NULL DEFAULT 0,"
        "health_aware INTEGER NOT NULL DEFAULT 1,"
        "log_policy_hits INTEGER NOT NULL DEFAULT 1,"
        "updated_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS route_table ("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "table_id INTEGER NOT NULL UNIQUE,"
        "role TEXT NOT NULL DEFAULT '',"
        "gateway TEXT NOT NULL DEFAULT '',"
        "metric INTEGER NOT NULL DEFAULT 0,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "updated_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS route_object ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "name TEXT NOT NULL UNIQUE,"
        "object_type TEXT NOT NULL,"
        "family TEXT NOT NULL DEFAULT 'mixed',"
        "value TEXT NOT NULL DEFAULT '',"
        "comment TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS route_object_member ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "object_id TEXT NOT NULL,"
        "value TEXT NOT NULL,"
        "label TEXT NOT NULL DEFAULT '',"
        "sort_order INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS policy_route_rule ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "priority INTEGER NOT NULL,"
        "name TEXT NOT NULL,"
        "source_kind TEXT NOT NULL DEFAULT 'object',"
        "source_ref TEXT NOT NULL DEFAULT '',"
        "pin_wan INTEGER NOT NULL DEFAULT 0,"
        "source_object TEXT NOT NULL DEFAULT '',"
        "dest_object TEXT NOT NULL DEFAULT '',"
        "proto TEXT NOT NULL DEFAULT 'all',"
        "ports TEXT NOT NULL DEFAULT 'any',"
        "action TEXT NOT NULL DEFAULT 'route_table',"
        "target TEXT NOT NULL DEFAULT '',"
        "route_table TEXT NOT NULL DEFAULT '',"
        "schedule TEXT NOT NULL DEFAULT 'always',"
        "sticky INTEGER NOT NULL DEFAULT 1,"
        "comment TEXT NOT NULL DEFAULT '',"
        "hit_count INTEGER NOT NULL DEFAULT 0,"
        "last_hit INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS policy_route_hit_sample ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ts INTEGER NOT NULL,"
        "rule_id TEXT NOT NULL,"
        "client TEXT NOT NULL DEFAULT '',"
        "source TEXT NOT NULL DEFAULT '',"
        "destination TEXT NOT NULL DEFAULT '',"
        "app TEXT NOT NULL DEFAULT '',"
        "route_table TEXT NOT NULL DEFAULT '',"
        "action TEXT NOT NULL DEFAULT '',"
        "reason TEXT NOT NULL DEFAULT '',"
        "bytes INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS policy_composite_object ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "name TEXT NOT NULL UNIQUE,"
        "object_type TEXT NOT NULL DEFAULT 'composite',"
        "family TEXT NOT NULL DEFAULT 'mixed',"
        "value TEXT NOT NULL DEFAULT '',"
        "components_json TEXT NOT NULL DEFAULT '[]',"
        "comment TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "INSERT OR IGNORE INTO advanced_routing_global(id) VALUES(1);";
    /*
     * The CREATE above only shapes a fresh database. Deployed routers already
     * have policy_route_rule without these columns, so migrate explicitly --
     * otherwise every insert naming source_kind fails with "no such column"
     * on exactly the devices that matter.
     */
    static const char *const migrations[] = {
        "ALTER TABLE policy_route_rule ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'object'",
        "ALTER TABLE policy_route_rule ADD COLUMN source_ref TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE policy_route_rule ADD COLUMN pin_wan INTEGER NOT NULL DEFAULT 0",
        NULL
    };
    int i;

    if (webd_policy_db_exec(db, schema, err, err_len) != 0)
        return -1;
    /* A duplicate-column error means the migration already ran; ignore it and
     * let a real failure surface on first use instead of refusing to start. */
    for (i = 0; migrations[i]; i++)
        (void)sqlite3_exec(db, migrations[i], NULL, NULL, NULL);
    return 0;
}

int webd_policy_pbr_id_ok(const char *s)
{
    size_t i;

    if (!s || !s[0] || strlen(s) > 96)
        return 0;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (isalnum(c) || c == '_' || c == '-' || c == '.')
            continue;
        return 0;
    }
    return 1;
}

void webd_policy_pbr_sanitize_id(const char *in, char *out, size_t out_len)
{
    size_t i, j = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in)
        in = "";
    for (i = 0; in[i] && j + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];

        if (isalnum(c) || c == '_' || c == '-' || c == '.')
            out[j++] = (char)c;
        else if ((c == ' ' || c == '/' || c == ':') && j > 0 && out[j - 1] != '-')
            out[j++] = '-';
    }
    while (j > 0 && out[j - 1] == '-')
        j--;
    out[j] = '\0';
    if (!out[0])
        snprintf(out, out_len, "pbr-%lld", (long long)now_s());
}

static void webd_policy_pbr_sqlite_text(sqlite3_stmt *st, int col,
                                        char *out, size_t out_len)
{
    const char *s;

    if (!out || out_len == 0)
        return;
    s = (const char *)sqlite3_column_text(st, col);
    snprintf(out, out_len, "%s", s ? s : "");
}

static int webd_policy_find_pbr_rule(sqlite3 *db, const char *id,
                                     char *rule_id, size_t rule_id_len,
                                     char *legacy_id, size_t legacy_id_len)
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT id,'' FROM policy_route_rule WHERE id=?1 "
        "UNION ALL "
        "SELECT '','adv:'||id FROM adv_policy_rule WHERE id=?2 "
        "LIMIT 1";
    char key[160] = "";
    char legacy_key[160] = "";
    int found = 0;

    if (rule_id && rule_id_len)
        rule_id[0] = '\0';
    if (legacy_id && legacy_id_len)
        legacy_id[0] = '\0';
    if (!db || !id || !id[0])
        return 0;
    snprintf(key, sizeof(key), "%s", id);
    if (!strncmp(key, "policy_route_rule.", 18))
        memmove(key, key + 18, strlen(key + 18) + 1);
    if (!strncmp(key, "pbr.", 4))
        memmove(key, key + 4, strlen(key + 4) + 1);
    if (!strncmp(key, "uci-pbr-policy-", 15))
        memmove(key, key + 15, strlen(key + 15) + 1);
    snprintf(legacy_key, sizeof(legacy_key), "%s", key);
    if (!strncmp(legacy_key, "adv:", 4))
        memmove(legacy_key, legacy_key + 4, strlen(legacy_key + 4) + 1);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, legacy_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        webd_policy_pbr_sqlite_text(st, 0, rule_id, rule_id_len);
        webd_policy_pbr_sqlite_text(st, 1, legacy_id, legacy_id_len);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

int webd_policy_pbr_rule_exists(const char *id)
{
    sqlite3 *db = NULL;
    char rule_id[128];
    char legacy_id[128];
    int ok = 0;

    if (!id || !id[0])
        return 0;
    if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK || !db)
        return 0;
    sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
    ok = webd_policy_find_pbr_rule(db, id, rule_id, sizeof(rule_id),
                                   legacy_id, sizeof(legacy_id));
    sqlite3_close(db);
    return ok;
}

int webd_policy_dhcp_section_id_match(struct uci_section *s,
                                             const char *id,
                                             int section_no)
{
    char generated[256];

    if (!s || !id || !id[0] || !s->type)
        return 0;
    snprintf(generated, sizeof(generated), "uci-dhcp-%s-%s-%d",
             s->type,
             s->e.name ? s->e.name : "anon",
             section_no);
    if (!strcmp(id, generated))
        return 1;
    if (s->e.name && !strcmp(id, s->e.name))
        return 1;
    return 0;
}

static int webd_policy_dhcp_section_name_exists(struct uci_package *pkg, const char *name)
{
    struct uci_element *e;

    if (!pkg || !name || !name[0])
        return 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (s && s->e.name && !strcmp(s->e.name, name))
            return 1;
    }
    return 0;
}

static void webd_policy_dns_generated_section_name(struct uci_package *pkg,
                                                   const char *record_type,
                                                   char *out, size_t out_len)
{
    struct timespec ts;
    unsigned int seq;
    int i;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!record_type || !record_type[0])
        record_type = "domain";
    clock_gettime(CLOCK_REALTIME, &ts);
    seq = (unsigned int)(random() & 0xffffu);
    for (i = 0; i < 64; i++, seq++) {
        snprintf(out, out_len, "dwrt_%s_%lld_%09ld_%ld_%04x",
                 record_type, (long long)ts.tv_sec, ts.tv_nsec,
                 (long)getpid(), seq & 0xffffu);
        if (!webd_policy_dhcp_section_name_exists(pkg, out))
            return;
    }
    out[0] = '\0';
}

static struct uci_section *webd_policy_find_dhcp_section(struct uci_package *pkg,
                                                         const char *id,
                                                         int *section_no_out)
{
    struct uci_element *e;
    int section_no = 0;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type)
            continue;
        if (!webd_policy_dhcp_supported_type(s->type))
            continue;
        section_no++;
        if (webd_policy_dhcp_section_id_match(s, id, section_no)) {
            if (section_no_out)
                *section_no_out = section_no;
            return s;
        }
    }
    return NULL;
}

static int webd_policy_dns_name_exists_any(struct uci_package *pkg,
                                           struct uci_section *exclude,
                                           const char *name,
                                           char *conflict, size_t conflict_len)
{
    struct uci_element *e;
    int section_no = 0;

    if (conflict && conflict_len)
        conflict[0] = '\0';
    if (!pkg || !name || !name[0])
        return 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        char cur[512] = "";
        char inst[128] = "";
        char dns[32] = "";
        const char *key = NULL;
        char generated[256];

        if (!s || s == exclude || !s->type)
            continue;
        if (!webd_policy_dhcp_supported_type(s->type))
            continue;
        section_no++;
        webd_policy_uci_option(s, "instance", inst, sizeof(inst));
        (void)inst;
        if (!strcmp(s->type, "domain"))
            key = "name";
        else if (!strcmp(s->type, "cname"))
            key = "cname";
        else if (!strcmp(s->type, "host")) {
            webd_policy_uci_option(s, "dns", dns, sizeof(dns));
            if (!webd_policy_str_true(dns))
                continue;
            key = "name";
        } else {
            continue;
        }
        if (!webd_policy_uci_option(s, key, cur, sizeof(cur)) || !cur[0])
            continue;
        if (strcasecmp(cur, name))
            continue;
        snprintf(generated, sizeof(generated), "uci-dhcp-%s-%s-%d",
                 s->type,
                 s->e.name ? s->e.name : "anon",
                 section_no);
        if (conflict && conflict_len)
            snprintf(conflict, conflict_len, "%s", s->e.name ? s->e.name : generated);
        return 1;
    }
    return 0;
}

static int webd_policy_dns_set_enabled(struct uci_context *ctx,
                                       struct uci_section *s,
                                       int enable,
                                       char *err, size_t err_len,
                                       struct json_object *diff)
{
    char section[128];
    char instance[128] = "";
    char saved[128] = "";

    if (!ctx || !s || !s->e.name)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);
    webd_policy_uci_option(s, "instance", instance, sizeof(instance));
    webd_policy_uci_option(s, WEBD_POLICY_DNS_SAVED_INSTANCE, saved, sizeof(saved));
    if (enable) {
        const char *restore = saved[0] ? saved : "";
        if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "instance",
                                           restore, 1, err, err_len) != 0)
            return -1;
        if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section,
                                           WEBD_POLICY_DNS_SAVED_INSTANCE,
                                           "", 1, err, err_len) != 0)
            return -1;
        if (diff)
            json_object_array_add(diff, json_object_new_string("+ enable dns record"));
    } else {
        if (!webd_policy_str_eq(instance, WEBD_POLICY_DNS_DISABLED_INSTANCE) && instance[0]) {
            if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section,
                                               WEBD_POLICY_DNS_SAVED_INSTANCE,
                                               instance, 0, err, err_len) != 0)
                return -1;
        }
        if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "instance",
                                           WEBD_POLICY_DNS_DISABLED_INSTANCE,
                                           0, err, err_len) != 0)
            return -1;
        if (diff)
            json_object_array_add(diff, json_object_new_string("- disable dns record"));
    }
    return 0;
}

static int webd_policy_dns_name_valid(const char *name)
{
    size_t i, len;

    if (!name || !name[0])
        return 0;
    len = strlen(name);
    if (len > 253)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == '*'))
            return 0;
    }
    return 1;
}

static int webd_policy_dhcp_backup(char *backup, size_t backup_len,
                                   char *err, size_t err_len)
{
    time_t now = now_s();

    if (!backup || backup_len == 0)
        return -1;
    backup[0] = '\0';
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir("/tmp/dreamingwrt/policy-backups", 0755);
    snprintf(backup, backup_len, "/tmp/dreamingwrt/policy-backups/dhcp.%lld.%ld.bak",
             (long long)now, (long)getpid());
    return webd_policy_copy_file(WEBD_POLICY_CONFIG_DHCP, backup, err, err_len);
}

int webd_policy_dnsmasq_reload(struct json_object *steps,
                                      struct json_object *warnings)
{
    int rc;

    json_object_array_add(steps, json_object_new_string("reload dnsmasq runtime"));
    rc = webd_policy_run_cmd("(/etc/init.d/dnsmasq reload || /etc/init.d/dnsmasq restart) >/tmp/dreamingwrt-policy-dnsmasq-reload.log 2>&1");
    if (rc != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "dnsmasq_reload_failed_rc_%d", rc);
        json_object_array_add(warnings, json_object_new_string(msg));
        return -1;
    }
    return 0;
}

static const char *webd_policy_dns_record_type_from_body(struct json_object *body)
{
    const char *t = app_nc_json_str(body, "record_type",
                    app_nc_json_str(body, "dns_record_type",
                    app_nc_json_str(body, "section_type",
                    app_nc_json_str(body, "kind", ""))));

    if (!strcasecmp(t, "cname") || !strcasecmp(t, "alias"))
        return "cname";
    if (!strcasecmp(t, "host") || !strcasecmp(t, "static_host") ||
        !strcasecmp(t, "dhcp_host"))
        return "host";
    if (!strcasecmp(t, "domain") || !strcasecmp(t, "a") ||
        !strcasecmp(t, "aaaa") || !strcasecmp(t, "dns"))
        return "domain";
    if (app_nc_json_has(body, "cname") || app_nc_json_has(body, "target") ||
        app_nc_json_has(body, "canonical"))
        return "cname";
    if (app_nc_json_has(body, "mac") || app_nc_json_has(body, "macaddr"))
        return "host";
    return "domain";
}

static int webd_policy_dns_apply_fields(struct uci_context *ctx,
                                        struct uci_package *pkg,
                                        struct uci_section *s,
                                        struct json_object *body,
                                        int create,
                                        char *err, size_t err_len,
                                        struct json_object *diff)
{
    static const char *name_keys[] = { "name", "domain", "hostname", "host", "record", NULL };
    static const char *ip_keys[] = { "ip", "address", "addr", "value", "target_ip", NULL };
    static const char *cname_keys[] = { "cname", "alias", "name", "domain", NULL };
    static const char *target_keys[] = { "target", "canonical", "canonical_name", "value", NULL };
    static const char *mac_keys[] = { "mac", "macaddr", "mac_address", NULL };
    char section[128];
    char value[512];
    char ip[256];

    if (!ctx || !pkg || !s || !s->e.name || !s->type || !body)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);

    if (!strcmp(s->type, "cname")) {
        value[0] = '\0';
        if (webd_policy_body_string_any(body, cname_keys, value, sizeof(value)) || create) {
            char conflict[256] = "";

            if (!webd_policy_dns_name_valid(value)) {
                if (err && err_len)
                    snprintf(err, err_len, "invalid cname: %s", value);
                return -1;
            }
            if (webd_policy_dns_name_exists_any(pkg, s, value,
                                                conflict, sizeof(conflict))) {
                if (err && err_len)
                    snprintf(err, err_len, "dns cname already exists: %s conflicts with %s",
                             value, conflict);
                return -1;
            }
            if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "cname", value, 0, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ dns cname"));
        }
        value[0] = '\0';
        if (webd_policy_body_string_any(body, target_keys, value, sizeof(value)) || create) {
            if (!webd_policy_dns_name_valid(value)) {
                if (err && err_len)
                    snprintf(err, err_len, "invalid cname target: %s", value);
                return -1;
            }
            if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "target", value, 0, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ dns cname target"));
        }
        return 0;
    }

    if (!strcmp(s->type, "host")) {
        value[0] = '\0';
        if (webd_policy_body_string_any(body, name_keys, value, sizeof(value)) || create) {
            if (value[0] && !webd_policy_dns_name_valid(value)) {
                if (err && err_len)
                    (void)snprintf(err, err_len, "invalid host name: %.400s", value);
                return -1;
            }
            if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "name", value, 1, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ dhcp host name"));
        }
        value[0] = '\0';
        if (webd_policy_body_string_any(body, mac_keys, value, sizeof(value)) || create) {
            if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "mac", value, 1, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ dhcp host mac"));
        }
        ip[0] = '\0';
        if (webd_policy_body_string_any(body, ip_keys, ip, sizeof(ip)) || create) {
            if (ip[0] && !webd_policy_ip_addr_valid(ip)) {
                if (err && err_len)
                    snprintf(err, err_len, "invalid host ip: %s", ip);
                return -1;
            }
            if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "ip", ip, 1, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ dhcp host ip"));
        }
        return 0;
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, name_keys, value, sizeof(value)) || create) {
        char conflict[256] = "";

        if (!webd_policy_dns_name_valid(value)) {
            if (err && err_len)
                snprintf(err, err_len, "invalid domain: %s", value);
            return -1;
        }
        if (webd_policy_dns_name_exists_any(pkg, s, value,
                                            conflict, sizeof(conflict))) {
            if (err && err_len)
                snprintf(err, err_len, "dns domain already exists: %s conflicts with %s",
                         value, conflict);
            return -1;
        }
        if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "name", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ dns domain name"));
    }
    ip[0] = '\0';
    if (webd_policy_body_string_any(body, ip_keys, ip, sizeof(ip)) || create) {
        if (!webd_policy_ip_addr_valid(ip)) {
            if (err && err_len)
                snprintf(err, err_len, "invalid domain ip: %s", ip);
            return -1;
        }
        if (webd_policy_uci_set_pkg_option(ctx, "dhcp", section, "ip", ip, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ dns domain ip"));
    }
    return 0;
}

struct json_object *webd_policy_dns_apply_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *operation,
                                                          const char *id,
                                                          int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char section_name[128] = "";
    const char *record_type = webd_policy_dns_record_type_from_body(body);
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_dnsmasq;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/config/dhcp"));
    if (webd_policy_dhcp_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_alloc_context failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (uci_load(ctx, "dhcp", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load dhcp failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        char generated_name[128];

        if (uci_add_section(ctx, pkg, record_type, &s) != UCI_OK || !s) {
            snprintf(err, sizeof(err), "uci_add_section dhcp %s failed", record_type);
            if (http_status) *http_status = 500;
            goto fail;
        }
        webd_policy_dns_generated_section_name(pkg, record_type,
                                               generated_name, sizeof(generated_name));
        if (!generated_name[0]) {
            snprintf(err, sizeof(err), "generate dns section name failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        if (webd_policy_uci_rename_section(ctx, "dhcp", record_type, generated_name,
                                           err, sizeof(err)) != 0) {
            if (!err[0])
                snprintf(err, sizeof(err), "rename dhcp dns section failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("rename dhcp dns section"));
        s = uci_lookup_section(ctx, pkg, generated_name);
        if (!s) {
            snprintf(err, sizeof(err), "renamed dhcp section lookup failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("create dhcp dns section"));
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail;
        }
        s = webd_policy_find_dhcp_section(pkg, id, NULL);
        if (!s) {
            snprintf(err, sizeof(err), "dns record not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("load dhcp dns section"));
    }
    snprintf(section_name, sizeof(section_name), "%s", s && s->e.name ? s->e.name : "");
    webd_obj_add_str(tx, "section", section_name);
    webd_obj_add_str(tx, "section_type", s && s->type ? s->type : record_type);

    if (app_nc_json_has(body, "enabled") &&
        strcmp(operation, "delete") && strcmp(operation, "enable") &&
        strcmp(operation, "disable")) {
        if (webd_policy_dns_set_enabled(ctx, s, app_nc_json_bool(body, "enabled", 1),
                                        err, sizeof(err), diff) != 0) {
            if (http_status) *http_status = 400;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("apply dns enabled state"));
    }

    if (!strcmp(operation, "delete")) {
        struct uci_ptr ptr;
        char lookup[256];

        snprintf(lookup, sizeof(lookup), "dhcp.%s", section_name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            snprintf(err, sizeof(err), "uci_delete dns record failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(diff, json_object_new_string("- dns record section"));
        json_object_array_add(steps, json_object_new_string("delete dhcp dns section"));
    } else if (!strcmp(operation, "enable") || !strcmp(operation, "disable")) {
        int enable = !strcmp(operation, "enable");

        if (webd_policy_dns_set_enabled(ctx, s, enable, err, sizeof(err), diff) != 0)
            goto fail;
        json_object_array_add(steps, json_object_new_string("toggle dhcp dns section via dnsmasq instance quarantine"));
    } else if (webd_policy_dns_apply_fields(ctx, pkg, s, body, create,
                                            err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail;
    }

    json_object_array_add(steps, json_object_new_string("uci commit dhcp"));
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit dhcp failed");
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    reload_dnsmasq = webd_policy_query_or_body_bool(req, body, "reload_dnsmasq", 1);
    if (reload_dnsmasq) {
        if (webd_policy_dnsmasq_reload(steps, warnings) != 0) {
            snprintf(err, sizeof(err), "dnsmasq reload failed");
            if (http_status) *http_status = 409;
            goto fail_restore;
        }
    } else {
        json_object_array_add(warnings, json_object_new_string("dnsmasq_reload_skipped"));
    }

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.dns_apply");

fail_restore:
    json_object_array_add(steps, json_object_new_string("restore dhcp backup after failed commit/reload"));
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_DHCP, NULL, 0) == 0)
        json_object_array_add(warnings, json_object_new_string("dhcp_config_restored_from_backup"));
    else
        json_object_array_add(warnings, json_object_new_string("dhcp_config_restore_failed"));
fail:
    if (rc != 0) {
        json_object_object_add(tx, "ok", json_object_new_boolean(0));
        json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
        json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
        json_object_object_add(tx, "applied", json_object_new_boolean(0));
        json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "dns transaction failed"));
        json_object_object_add(tx, "steps", steps);
        json_object_object_add(tx, "warnings", warnings);
        json_object_object_add(tx, "diff", diff);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("policy_dns_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "dns transaction failed"));
        json_object_object_add(data, "transaction", tx);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.dns_apply");
}

int webd_policy_network_route_id_match(struct uci_section *s,
                                              const char *id,
                                              int section_no)
{
    char generated[256];

    if (!s || !id || !id[0] || !s->type)
        return 0;
    snprintf(generated, sizeof(generated), "uci-network-%s-%s-%d",
             s->type,
             s->e.name ? s->e.name : "anon",
             section_no);
    if (!strcmp(id, generated))
        return 1;
    if (s->e.name && !strcmp(id, s->e.name))
        return 1;
    return 0;
}

static struct uci_section *webd_policy_find_network_route_section(struct uci_package *pkg,
                                                                  const char *id,
                                                                  int *section_no_out)
{
    struct uci_element *e;
    int section_no = 0;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type || (strcmp(s->type, "route") && strcmp(s->type, "route6")))
            continue;
        section_no++;
        if (webd_policy_network_route_id_match(s, id, section_no)) {
            if (section_no_out)
                *section_no_out = section_no;
            return s;
        }
    }
    return NULL;
}

int webd_policy_network_route_exists(const char *id)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    int ok = 0;

    if (!id || !id[0])
        return 0;
    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "network", &pkg) != UCI_OK || !pkg)
        goto out;
    s = webd_policy_find_network_route_section(pkg, id, NULL);
    ok = s != NULL;
out:
    if (pkg)
        uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return ok;
}

static const char *webd_policy_route_section_type_from_body(struct json_object *body)
{
    static const char *target_keys[] = { "target", "destination", "dest_addr", "network", "prefix", NULL };
    static const char *gateway_keys[] = { "gateway", "gw", "next_hop", "nexthop", NULL };
    const char *t = app_nc_json_str(body, "section_type",
                    app_nc_json_str(body, "route_type",
                    app_nc_json_str(body, "family",
                    app_nc_json_str(body, "ip_version",
                    app_nc_json_str(body, "ipVersion", "")))));
    char value[512];

    if (!strcasecmp(t, "route6") || !strcasecmp(t, "ipv6") ||
        !strcasecmp(t, "ip6") || !strcmp(t, "IPv6"))
        return "route6";
    if (!strcasecmp(t, "route") || !strcasecmp(t, "ipv4") ||
        !strcasecmp(t, "ip4") || !strcmp(t, "IPv4"))
        return "route";
    if (webd_policy_body_string_any(body, target_keys, value, sizeof(value)) && strchr(value, ':'))
        return "route6";
    if (webd_policy_body_string_any(body, gateway_keys, value, sizeof(value)) && strchr(value, ':'))
        return "route6";
    return "route";
}

int webd_policy_sqm_backup(char *backup, size_t backup_len,
                                  char *err, size_t err_len)
{
    time_t now = now_s();

    if (!backup || backup_len == 0)
        return -1;
    backup[0] = '\0';
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir("/tmp/dreamingwrt/policy-backups", 0755);
    snprintf(backup, backup_len, "/tmp/dreamingwrt/policy-backups/sqm.%lld.%ld.bak",
             (long long)now, (long)getpid());
    return webd_policy_copy_file(WEBD_POLICY_CONFIG_SQM, backup, err, err_len);
}

int webd_policy_sqm_reload(struct json_object *steps,
                                  struct json_object *warnings)
{
    int rc;

    json_object_array_add(steps, json_object_new_string("reload sqm runtime"));
    rc = webd_policy_run_cmd("(/etc/init.d/sqm reload || /etc/init.d/sqm restart) >/tmp/dreamingwrt-policy-sqm-reload.log 2>&1");
    if (rc != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "sqm_reload_failed_rc_%d", rc);
        json_object_array_add(warnings, json_object_new_string(msg));
        return -1;
    }
    return 0;
}

int webd_policy_sqm_apply_fields(struct uci_context *ctx,
                                        struct uci_section *s,
                                        struct json_object *body,
                                        int create,
                                        const char *operation,
                                        char *err, size_t err_len,
                                        struct json_object *diff)
{
    static const char *name_keys[] = { "name", "label", "description", "rule_name", NULL };
    static const char *iface_keys[] = { "interface", "iface", "ifname", "wan", NULL };
    static const char *download_keys[] = { "download", "download_kbps", "down_kbps", "downlink", "downlink_kbps", NULL };
    static const char *upload_keys[] = { "upload", "upload_kbps", "up_kbps", "uplink", "uplink_kbps", NULL };
    static const char *qdisc_keys[] = { "qdisc", "qdisc_advanced", NULL };
    static const char *script_keys[] = { "script", "script_name", NULL };
    static const char *linklayer_keys[] = { "linklayer", "link_layer", NULL };
    static const char *overhead_keys[] = { "overhead", NULL };
    static const char *debug_keys[] = { "debug_logging", "debug", NULL };
    static const char *verbosity_keys[] = { "verbosity", NULL };
    static const char *enabled_keys[] = { "enabled", NULL };
    char section[128];
    char value[512];
    int present;

    if (!ctx || !s || !s->e.name || !body)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);

    if (create && !webd_policy_body_string_any(body, iface_keys, value, sizeof(value))) {
        if (err && err_len)
            snprintf(err, err_len, "interface is required for SQM/QoS create");
        return -1;
    }

#define WEBD_POLICY_SET_SQM_OPTION(keys, option_name, required_on_create) do { \
        value[0] = '\0'; \
        if (webd_policy_body_string_any(body, keys, value, sizeof(value)) || (create && (required_on_create))) { \
            if (webd_policy_value_is_any(value)) value[0] = '\0'; \
            if ((required_on_create) && create && !value[0]) { \
                if (err && err_len) snprintf(err, err_len, option_name " is required for SQM/QoS create"); \
                return -1; \
            } \
            if (webd_policy_uci_set_pkg_option(ctx, "sqm", section, option_name, value, 1, err, err_len) != 0) \
                return -1; \
            json_object_array_add(diff, json_object_new_string("+ sqm " option_name)); \
        } \
    } while (0)

    WEBD_POLICY_SET_SQM_OPTION(iface_keys, "interface", 1);
    WEBD_POLICY_SET_SQM_OPTION(download_keys, "download", 0);
    WEBD_POLICY_SET_SQM_OPTION(upload_keys, "upload", 0);
    WEBD_POLICY_SET_SQM_OPTION(qdisc_keys, "qdisc", 0);
    WEBD_POLICY_SET_SQM_OPTION(script_keys, "script", 0);
    WEBD_POLICY_SET_SQM_OPTION(linklayer_keys, "linklayer", 0);
    WEBD_POLICY_SET_SQM_OPTION(overhead_keys, "overhead", 0);
    WEBD_POLICY_SET_SQM_OPTION(debug_keys, "debug_logging", 0);
    WEBD_POLICY_SET_SQM_OPTION(verbosity_keys, "verbosity", 0);
#undef WEBD_POLICY_SET_SQM_OPTION

    value[0] = '\0';
    if (webd_policy_body_string_any(body, name_keys, value, sizeof(value)) && value[0]) {
        if (webd_policy_uci_set_pkg_option(ctx, "sqm", section, "name", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ sqm name"));
    }

    present = 0;
    {
        int enabled = webd_policy_body_bool_any(body, enabled_keys, 1, &present);
        if (present || create || !strcmp(operation, "enable") || !strcmp(operation, "disable")) {
            if (!strcmp(operation, "disable"))
                enabled = 0;
            else if (!strcmp(operation, "enable"))
                enabled = 1;
            if (webd_policy_uci_set_pkg_option(ctx, "sqm", section, "enabled",
                                               enabled ? "1" : "0", 0, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ sqm enabled"));
        }
    }
    return 0;
}

struct json_object *webd_policy_sqm_apply_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *operation,
                                                          const char *id,
                                                          int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char section_name[128] = "";
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_sqm;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/config/sqm"));
    if (webd_policy_sqm_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_alloc_context failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (uci_load(ctx, "sqm", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load sqm failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        if (uci_add_section(ctx, pkg, "queue", &s) != UCI_OK || !s) {
            snprintf(err, sizeof(err), "uci_add_section sqm queue failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("create sqm queue section"));
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail;
        }
        s = webd_policy_find_sqm_queue_section(pkg, id, NULL);
        if (!s) {
            snprintf(err, sizeof(err), "sqm queue not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("load sqm queue section"));
    }
    snprintf(section_name, sizeof(section_name), "%s", s && s->e.name ? s->e.name : "");
    webd_obj_add_str(tx, "section", section_name);
    webd_obj_add_str(tx, "section_type", s && s->type ? s->type : "queue");

    if (!strcmp(operation, "delete")) {
        struct uci_ptr ptr;
        char lookup[256];

        snprintf(lookup, sizeof(lookup), "sqm.%s", section_name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            snprintf(err, sizeof(err), "uci_delete sqm queue failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(diff, json_object_new_string("- sqm queue section"));
        json_object_array_add(steps, json_object_new_string("delete sqm queue section"));
    } else if (webd_policy_sqm_apply_fields(ctx, s, body, create, operation,
                                            err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail;
    }

    json_object_array_add(steps, json_object_new_string("uci commit sqm"));
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit sqm failed");
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    reload_sqm = webd_policy_query_or_body_bool(req, body, "reload_sqm", 0);
    if (reload_sqm) {
        if (webd_policy_sqm_reload(steps, warnings) != 0) {
            snprintf(err, sizeof(err), "sqm reload failed");
            if (http_status) *http_status = 409;
            goto fail_restore;
        }
    } else {
        json_object_array_add(warnings, json_object_new_string("sqm_reload_skipped"));
    }

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.sqm_apply");

fail_restore:
    json_object_array_add(steps, json_object_new_string("restore sqm backup after failed commit/reload"));
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_SQM, NULL, 0) == 0)
        json_object_array_add(warnings, json_object_new_string("sqm_config_restored_from_backup"));
    else
        json_object_array_add(warnings, json_object_new_string("sqm_config_restore_failed"));
fail:
    if (rc != 0) {
        json_object_object_add(tx, "ok", json_object_new_boolean(0));
        json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
        json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
        json_object_object_add(tx, "applied", json_object_new_boolean(0));
        json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "sqm transaction failed"));
        json_object_object_add(tx, "steps", steps);
        json_object_object_add(tx, "warnings", warnings);
        json_object_object_add(tx, "diff", diff);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("policy_sqm_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "sqm transaction failed"));
        json_object_object_add(data, "transaction", tx);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.sqm_apply");
}

static int webd_policy_static_route_apply_fields(struct uci_context *ctx,
                                                 struct uci_section *s,
                                                 struct json_object *body,
                                                 int create,
                                                 const char *operation,
                                                 char *err, size_t err_len,
                                                 struct json_object *diff)
{
    static const char *iface_keys[] = { "interface", "iface", "network", "source_zone", "src", NULL };
    static const char *target_keys[] = { "target", "destination", "dest_addr", "network_prefix", "prefix", NULL };
    static const char *netmask_keys[] = { "netmask", "mask", NULL };
    static const char *gateway_keys[] = { "gateway", "gw", "next_hop", "nexthop", NULL };
    static const char *metric_keys[] = { "metric", "priority", NULL };
    static const char *mtu_keys[] = { "mtu", NULL };
    static const char *table_keys[] = { "table", "routing_table", NULL };
    static const char *source_keys[] = { "source", "src_ip", "source_ip", "source_prefix", NULL };
    static const char *type_keys[] = { "route_kind", "route_kind_type", NULL };
    static const char *name_keys[] = { "name", "label", "display_name", NULL };
    static const char *comment_keys[] = { "comment", "remark", "note", "description", NULL };
    static const char *enabled_keys[] = { "enabled", NULL };
    char section[128];
    char value[512];
    int present;

    if (!ctx || !s || !s->e.name || !body)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);

    value[0] = '\0';
    if (webd_policy_body_string_any(body, target_keys, value, sizeof(value)) || create) {
        if (webd_policy_value_is_any(value)) {
            if (err && err_len)
                snprintf(err, err_len, "target/destination is required for static route");
            return -1;
        }
        if (webd_policy_uci_set_pkg_option(ctx, "network", section, "target", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ static route target"));
    }

#define WEBD_POLICY_SET_ROUTE_OPTION(keys, option_name) do { \
        value[0] = '\0'; \
        if (webd_policy_body_string_any(body, keys, value, sizeof(value))) { \
            if (webd_policy_value_is_any(value)) value[0] = '\0'; \
            if (webd_policy_uci_set_pkg_option(ctx, "network", section, option_name, value, 1, err, err_len) != 0) \
                return -1; \
            json_object_array_add(diff, json_object_new_string("+ static route " option_name)); \
        } \
    } while (0)

    WEBD_POLICY_SET_ROUTE_OPTION(iface_keys, "interface");
    WEBD_POLICY_SET_ROUTE_OPTION(netmask_keys, "netmask");
    WEBD_POLICY_SET_ROUTE_OPTION(gateway_keys, "gateway");
    WEBD_POLICY_SET_ROUTE_OPTION(metric_keys, "metric");
    WEBD_POLICY_SET_ROUTE_OPTION(mtu_keys, "mtu");
    WEBD_POLICY_SET_ROUTE_OPTION(table_keys, "table");
    WEBD_POLICY_SET_ROUTE_OPTION(source_keys, "source");
    WEBD_POLICY_SET_ROUTE_OPTION(type_keys, "type");
    /* User-readable name and comment persist as schemaless UCI options on
     * the route section; netifd ignores them at reload but routed reads
     * them back (routed_static_projection). Fixes routing-table gap:
     * static routes now keep a real name + remark instead of a generated
     * "Static route <target>" label. */
    WEBD_POLICY_SET_ROUTE_OPTION(name_keys, "name");
    WEBD_POLICY_SET_ROUTE_OPTION(comment_keys, "comment");
#undef WEBD_POLICY_SET_ROUTE_OPTION

    if (create) {
        char iface[256] = "";
        char gateway[256] = "";

        webd_policy_body_string_any(body, iface_keys, iface, sizeof(iface));
        webd_policy_body_string_any(body, gateway_keys, gateway, sizeof(gateway));
        if (webd_policy_value_is_any(iface) && webd_policy_value_is_any(gateway)) {
            if (err && err_len)
                snprintf(err, err_len, "interface or gateway is required for static route create");
            return -1;
        }
    }

    present = 0;
    {
        int enabled = webd_policy_body_bool_any(body, enabled_keys, 1, &present);
        if (present || create || !strcmp(operation, "enable") || !strcmp(operation, "disable")) {
            if (!strcmp(operation, "disable"))
                enabled = 0;
            else if (!strcmp(operation, "enable"))
                enabled = 1;
            if (webd_policy_uci_set_pkg_option(ctx, "network", section, "disabled",
                                               enabled ? "" : "1", 1, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ static route enabled/disabled"));
        }
    }
    return 0;
}

struct json_object *webd_policy_static_route_apply_response(const struct http_req *req,
                                                                   struct json_object *body,
                                                                   const char *operation,
                                                                   const char *id,
                                                                   int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char section_name[128] = "";
    const char *section_type = webd_policy_route_section_type_from_body(body);
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_network;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/config/network"));
    if (webd_policy_network_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_alloc_context failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (uci_load(ctx, "network", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load network failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        if (uci_add_section(ctx, pkg, section_type, &s) != UCI_OK || !s) {
            snprintf(err, sizeof(err), "uci_add_section network %s failed", section_type);
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("create network route section"));
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail;
        }
        s = webd_policy_find_network_route_section(pkg, id, NULL);
        if (!s) {
            snprintf(err, sizeof(err), "static route not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("load network route section"));
    }
    snprintf(section_name, sizeof(section_name), "%s", s && s->e.name ? s->e.name : "");
    webd_obj_add_str(tx, "section", section_name);
    webd_obj_add_str(tx, "section_type", s && s->type ? s->type : section_type);

    if (!strcmp(operation, "delete")) {
        struct uci_ptr ptr;
        char lookup[256];

        snprintf(lookup, sizeof(lookup), "network.%s", section_name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            snprintf(err, sizeof(err), "uci_delete static route failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(diff, json_object_new_string("- static route section"));
        json_object_array_add(steps, json_object_new_string("delete network route section"));
    } else if (webd_policy_static_route_apply_fields(ctx, s, body, create, operation,
                                                      err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail;
    }

    json_object_array_add(steps, json_object_new_string("uci commit network"));
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit network failed");
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    reload_network = webd_policy_query_or_body_bool(req, body, "reload_network", 0);
    if (reload_network) {
        if (webd_policy_network_reload(steps, warnings) != 0) {
            snprintf(err, sizeof(err), "network reload failed");
            if (http_status) *http_status = 409;
            goto fail_restore;
        }
    } else {
        json_object_array_add(warnings, json_object_new_string("network_reload_skipped"));
    }

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.static_route_apply");

fail_restore:
    json_object_array_add(steps, json_object_new_string("restore network backup after failed commit/reload"));
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_NETWORK, NULL, 0) == 0)
        json_object_array_add(warnings, json_object_new_string("network_config_restored_from_backup"));
    else
        json_object_array_add(warnings, json_object_new_string("network_config_restore_failed"));
fail:
    if (rc != 0) {
        json_object_object_add(tx, "ok", json_object_new_boolean(0));
        json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
        json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
        json_object_object_add(tx, "applied", json_object_new_boolean(0));
        json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "static route transaction failed"));
        json_object_object_add(tx, "steps", steps);
        json_object_object_add(tx, "warnings", warnings);
        json_object_object_add(tx, "diff", diff);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("policy_static_route_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "static route transaction failed"));
        json_object_object_add(data, "transaction", tx);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.static_route_apply");
}

static int webd_policy_pbr_backup(char *backup, size_t backup_len,
                                  char *err, size_t err_len)
{
    time_t now = now_s();

    if (!backup || backup_len == 0)
        return -1;
    backup[0] = '\0';
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir("/tmp/dreamingwrt/policy-backups", 0755);
    snprintf(backup, backup_len, "/tmp/dreamingwrt/policy-backups/config-db-pbr.%lld.%ld.bak",
             (long long)now, (long)getpid());
    return webd_policy_copy_file(WEBD_POLICY_CONFIG_DB, backup, err, err_len);
}

static int webd_policy_pbr_runtime_reload(struct json_object *steps,
                                          struct json_object *warnings)
{
    struct json_object *resp;
    int ok;

    json_object_array_add(steps, json_object_new_string("sync policy_route_rule into jmx_route runtime"));
    resp = app_ubus_invoke_timeout("route_reload", NULL, 5000);
    ok = app_ubus_response_ok(resp);
    if (!ok) {
        json_object_array_add(warnings, json_object_new_string("dreamingwrt_route_reload_failed"));
        if (resp)
            json_object_put(resp);
        return -1;
    }
    if (resp)
        json_object_put(resp);

    /*
     * route_reload only syncs the kernel jmx_route selector table and publishes
     * the per-WAN fwmark rules. It does NOT generate the advanced-routing
     * artifacts (rt_tables.d entry, the PBR nft ruleset, the apply script, the
     * UCI draft), and it does not install the "iif <dev> table <n>" rule that
     * actually implements pinning.
     *
     * Without this second call a PBR rule was accepted, stored, visible in the
     * kernel rule list and reported as applied, while the dataplane never got
     * the pin: on 30.1 all four artifacts were absent and
     * advanced_routing_global.last_apply_at was still 0, meaning this path had
     * never published once.
     *
     * Failure here is reported as a warning rather than failing the request. The
     * config.db write and the kernel sync above have already succeeded, so the
     * rule is live for mark-based steering; turning that into a 409 would roll
     * back work that did take effect. The warning names the gap so the caller can
     * tell "stored and steering" from "stored, steering and pinned".
     */
    json_object_array_add(steps,
        json_object_new_string("publish advanced routing runtime artifacts"));
    resp = app_ubus_invoke_timeout("advanced_routing_apply", NULL, 20000);
    if (!app_ubus_response_ok(resp)) {
        json_object_array_add(warnings,
            json_object_new_string("advanced_routing_apply_failed_pin_rules_not_published"));
        if (resp)
            json_object_put(resp);
        return 0;
    }
    if (resp)
        json_object_put(resp);
    return 0;
}

static int webd_policy_pbr_normalize_proto(const char *in, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return -1;
    if (webd_policy_value_is_any(in)) {
        snprintf(out, out_len, "all");
        return 0;
    }
    if (!strcasecmp(in, "tcp_udp") || !strcasecmp(in, "tcp/udp")) {
        snprintf(out, out_len, "all");
        return 0;
    }
    if (!strcasecmp(in, "tcp") || !strcasecmp(in, "udp") ||
        !strcasecmp(in, "icmp") || !strcasecmp(in, "all")) {
        snprintf(out, out_len, "%s", in);
        for (char *p = out; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        return 0;
    }
    if (atoi(in) >= 0 && atoi(in) <= 255) {
        snprintf(out, out_len, "%s", in);
        return 0;
    }
    return -1;
}

static void webd_policy_pbr_target_from_body(struct json_object *body,
                                             char *target, size_t target_len,
                                             char *route_table, size_t route_table_len)
{
    static const char *target_keys[] = {
        "target", "wan", "interface", "out_interface", "destination_network_id",
        "route_group", "target_group", "next_hop", NULL
    };
    static const char *table_keys[] = {
        "route_table", "table", "routing_table", "policy", NULL
    };

    if (target && target_len)
        target[0] = '\0';
    if (route_table && route_table_len)
        route_table[0] = '\0';
    webd_policy_body_string_any(body, target_keys, target, target_len);
    webd_policy_body_string_any(body, table_keys, route_table, route_table_len);
    if (route_table && route_table[0] && target && !target[0])
        snprintf(target, target_len, "%s", route_table);
    if (target && target[0] && route_table && !route_table[0])
        snprintf(route_table, route_table_len, "%s", target);
}

static int webd_policy_pbr_apply_fields(sqlite3 *db,
                                        const char *rule_id,
                                        struct json_object *body,
                                        int create,
                                        const char *operation,
                                        char *err, size_t err_len,
                                        struct json_object *diff)
{
    static const char *name_keys[] = { "name", "label", "description", "rule_name", NULL };
    static const char *priority_keys[] = { "priority", "prio", "index", NULL };
    static const char *src_keys[] = { "source_object", "src", "src_ip", "source", "source_ip", "source_address", "src_addr", NULL };
    static const char *src_kind_keys[] = { "source_kind", "src_kind", NULL };
    static const char *src_ref_keys[] = {
        "source_ref", "src_ref", "in_interface", "source_interface",
        "source_zone", "source_network", "in_network", NULL
    };
    static const char *pin_keys[] = { "pin_wan", "pin", "exclude_from_balance", NULL };
    static const char *dst_keys[] = { "dest_object", "dst", "destination", "destination_ip", "dest_ip", "destination_address", "dest_addr", NULL };
    static const char *proto_keys[] = { "proto", "protocol", "ip_protocol", NULL };
    static const char *ports_keys[] = { "ports", "dest_port", "destination_port", "dst_port", "port", NULL };
    static const char *action_keys[] = { "action", "action_key", NULL };
    static const char *schedule_keys[] = { "schedule", "time_object", NULL };
    static const char *comment_keys[] = { "comment", "remark", "note", "description", NULL };
    static const char *enabled_keys[] = { "enabled", NULL };
    sqlite3_stmt *st = NULL;
    char name[256] = "";
    char priority_s[64] = "";
    char src[256] = "";
    char dst[256] = "";
    char proto_raw[64] = "";
    char proto[64] = "all";
    char ports[128] = "any";
    char action_raw[64] = "";
    char action[64] = "route_table";
    char target[128] = "";
    char route_table[128] = "";
    char schedule[128] = "always";
    char comment[512] = "";
    char src_kind[32] = "";
    char src_ref[128] = "";
    int pin_wan = 0;
    int pin_present = 0;
    int priority;
    int enabled = 1;
    int present = 0;

    if (!db || !rule_id || !rule_id[0])
        return -1;
    if (!create && (!strcmp(operation, "enable") || !strcmp(operation, "disable"))) {
        sqlite3_stmt *est = NULL;
        int want_enabled = !strcmp(operation, "enable") ? 1 : 0;

        if (sqlite3_prepare_v2(db,
            "UPDATE policy_route_rule SET enabled=?1,updated_at=?2 WHERE id=?3",
            -1, &est, NULL) != SQLITE_OK) {
            if (err && err_len)
                snprintf(err, err_len, "prepare policy_route_rule enable/disable failed: %s", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_int(est, 1, want_enabled);
        sqlite3_bind_int64(est, 2, now_s());
        sqlite3_bind_text(est, 3, rule_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(est) != SQLITE_DONE) {
            if (err && err_len)
                snprintf(err, err_len, "enable/disable policy_route_rule failed: %s", sqlite3_errmsg(db));
            sqlite3_finalize(est);
            return -1;
        }
        sqlite3_finalize(est);
        json_object_array_add(diff, json_object_new_string("+ pbr enabled/disabled"));
        return 0;
    }
    webd_policy_body_string_any(body, name_keys, name, sizeof(name));
    webd_policy_body_string_any(body, priority_keys, priority_s, sizeof(priority_s));
    webd_policy_body_string_any(body, src_keys, src, sizeof(src));
    webd_policy_body_string_any(body, dst_keys, dst, sizeof(dst));
    webd_policy_body_string_any(body, proto_keys, proto_raw, sizeof(proto_raw));
    webd_policy_body_string_any(body, ports_keys, ports, sizeof(ports));
    webd_policy_body_string_any(body, action_keys, action_raw, sizeof(action_raw));
    webd_policy_body_string_any(body, schedule_keys, schedule, sizeof(schedule));
    webd_policy_body_string_any(body, comment_keys, comment, sizeof(comment));
    webd_policy_body_string_any(body, src_kind_keys, src_kind, sizeof(src_kind));
    webd_policy_body_string_any(body, src_ref_keys, src_ref, sizeof(src_ref));
    pin_wan = webd_policy_body_bool_any(body, pin_keys, 0, &pin_present);
    webd_policy_pbr_target_from_body(body, target, sizeof(target), route_table, sizeof(route_table));
    enabled = webd_policy_body_bool_any(body, enabled_keys, 1, &present);
    if (!strcmp(operation, "disable"))
        enabled = 0;
    else if (!strcmp(operation, "enable"))
        enabled = 1;
    if (!name[0])
        snprintf(name, sizeof(name), "%s", rule_id);
    priority = priority_s[0] ? atoi(priority_s) : (int)(1000 + (now_s() % 8000));
    if (priority <= 0 || priority > 65535) {
        if (err && err_len)
            snprintf(err, err_len, "priority must be 1..65535");
        return -1;
    }
    /*
     * Source dimension. Default stays "object" so existing callers that only
     * send source_object behave exactly as before. An interface/zone/network
     * source needs a ref, and must not be silently accepted without one --
     * a kind with no ref would match every inbound interface.
     */
    if (!src_kind[0]) {
        snprintf(src_kind, sizeof(src_kind), "%s", src_ref[0] ? "interface" : "object");
    } else {
        for (char *p = src_kind; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        if (!strcmp(src_kind, "iface") || !strcmp(src_kind, "in_interface"))
            snprintf(src_kind, sizeof(src_kind), "interface");
    }
    if (strcmp(src_kind, "object") && strcmp(src_kind, "interface") &&
        strcmp(src_kind, "zone") && strcmp(src_kind, "network")) {
        if (err && err_len)
            snprintf(err, err_len,
                     "source_kind must be object, interface, zone or network");
        return -1;
    }
    if (strcmp(src_kind, "object")) {
        if (!src_ref[0]) {
            if (err && err_len)
                snprintf(err, err_len,
                         "source_ref is required when source_kind is %s", src_kind);
            return -1;
        }
        if (!webd_policy_pbr_id_ok(src_ref)) {
            if (err && err_len)
                snprintf(err, err_len, "source_ref contains unsupported characters");
            return -1;
        }
    } else if (src_ref[0]) {
        if (err && err_len)
            snprintf(err, err_len,
                     "source_ref requires source_kind interface, zone or network");
        return -1;
    }
    /*
     * pin_wan is only meaningful for a whole-interface source: it is enforced by
     * an `ip rule iif` entry, and an IP-group rule has no inbound device to key
     * on. Refusing it here is better than accepting a flag that silently does
     * nothing at runtime.
     */
    if (pin_wan && !strcmp(src_kind, "object")) {
        if (err && err_len)
            snprintf(err, err_len,
                     "pin_wan requires source_kind interface, zone or network");
        return -1;
    }
    if (!src[0] || webd_policy_value_is_any(src))
        snprintf(src, sizeof(src), "any");
    if (!dst[0] || webd_policy_value_is_any(dst))
        snprintf(dst, sizeof(dst), "any");
    if (!ports[0] || webd_policy_value_is_any(ports))
        snprintf(ports, sizeof(ports), "any");
    if (webd_policy_pbr_normalize_proto(proto_raw[0] ? proto_raw : "all", proto, sizeof(proto)) != 0) {
        if (err && err_len)
            snprintf(err, err_len, "unsupported PBR protocol");
        return -1;
    }
    if (!action_raw[0] || !strcasecmp(action_raw, "convert") ||
        !strcasecmp(action_raw, "route") || !strcasecmp(action_raw, "lookup"))
        snprintf(action, sizeof(action), "route_table");
    else if (!strcasecmp(action_raw, "route_table") || !strcasecmp(action_raw, "route_group") ||
             !strcasecmp(action_raw, "main") || !strcasecmp(action_raw, "drop") ||
             !strcasecmp(action_raw, "mark"))
        snprintf(action, sizeof(action), "%s", action_raw);
    if (!target[0] && strcmp(action, "main")) {
        if (err && err_len)
            snprintf(err, err_len, "target/wan/interface/route_table is required for PBR create/update");
        return -1;
    }
    if (!schedule[0])
        snprintf(schedule, sizeof(schedule), "always");

    if (sqlite3_prepare_v2(db,
        "INSERT INTO policy_route_rule("
        "id,enabled,priority,name,source_object,dest_object,proto,ports,action,target,"
        "route_table,schedule,sticky,comment,updated_at,source_kind,source_ref,pin_wan"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) "
        "ON CONFLICT(id) DO UPDATE SET "
        "enabled=excluded.enabled,"
        "priority=excluded.priority,"
        "name=excluded.name,"
        "source_object=excluded.source_object,"
        "dest_object=excluded.dest_object,"
        "proto=excluded.proto,"
        "ports=excluded.ports,"
        "action=excluded.action,"
        "target=excluded.target,"
        "route_table=excluded.route_table,"
        "schedule=excluded.schedule,"
        "sticky=excluded.sticky,"
        "comment=excluded.comment,"
        "updated_at=excluded.updated_at,"
        "source_kind=excluded.source_kind,"
        "source_ref=excluded.source_ref,"
        "pin_wan=excluded.pin_wan",
        -1, &st, NULL) != SQLITE_OK) {
        if (err && err_len)
            snprintf(err, err_len, "prepare policy_route_rule upsert failed: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(st, 1, rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, enabled);
    sqlite3_bind_int(st, 3, priority);
    sqlite3_bind_text(st, 4, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, src, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, dst, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, ports, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, target, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, route_table, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, schedule, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, app_nc_json_bool(body, "sticky", 1));
    sqlite3_bind_text(st, 14, comment, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 15, now_s());
    sqlite3_bind_text(st, 16, src_kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, src_ref, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 18, pin_wan ? 1 : 0);
    if (sqlite3_step(st) != SQLITE_DONE) {
        if (err && err_len)
            snprintf(err, err_len, "write policy_route_rule failed: %s", sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    json_object_array_add(diff, json_object_new_string("+ config.db policy_route_rule"));
    if (create)
        json_object_array_add(diff, json_object_new_string("+ pbr rule create"));
    else
        json_object_array_add(diff, json_object_new_string("+ pbr rule update"));
    return 0;
}

struct json_object *webd_policy_pbr_apply_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *operation,
                                                          const char *id,
                                                          int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    sqlite3 *db = NULL;
    char backup[256] = "";
    char err[512] = "";
    char rule_id[128] = "";
    char legacy_id[128] = "";
    char sanitized[128] = "";
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_route;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/dreamingwrt/config.db"));
    if (webd_policy_pbr_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK || !db) {
        snprintf(err, sizeof(err), "open config.db failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
    if (webd_policy_pbr_db_init(db, err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (webd_policy_db_exec(db, "BEGIN IMMEDIATE", err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        const char *body_id = app_nc_json_str(body, "id", "");
        if (!body_id[0])
            body_id = app_nc_json_str(body, "name", "");
        webd_policy_pbr_sanitize_id(body_id, sanitized, sizeof(sanitized));
        snprintf(rule_id, sizeof(rule_id), "%s", sanitized);
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail_rollback;
        }
        if (!webd_policy_find_pbr_rule(db, id, rule_id, sizeof(rule_id),
                                       legacy_id, sizeof(legacy_id))) {
            snprintf(err, sizeof(err), "PBR policy not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail_rollback;
        }
        if (!rule_id[0] && legacy_id[0]) {
            snprintf(err, sizeof(err), "legacy adv_policy_rule is read-only in policy table; create/update as policy_route_rule");
            if (http_status) *http_status = 409;
            goto fail_rollback;
        }
    }
    if (!webd_policy_pbr_id_ok(rule_id)) {
        snprintf(err, sizeof(err), "invalid PBR policy id");
        if (http_status) *http_status = 400;
        goto fail_rollback;
    }

    webd_obj_add_str(tx, "rule_id", rule_id);
    if (!strcmp(operation, "delete")) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, "DELETE FROM policy_route_rule WHERE id=?1",
                               -1, &st, NULL) != SQLITE_OK) {
            snprintf(err, sizeof(err), "prepare delete policy_route_rule failed");
            if (http_status) *http_status = 500;
            goto fail_rollback;
        }
        sqlite3_bind_text(st, 1, rule_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
            snprintf(err, sizeof(err), "delete policy_route_rule failed: %s", sqlite3_errmsg(db));
            sqlite3_finalize(st);
            if (http_status) *http_status = 500;
            goto fail_rollback;
        }
        sqlite3_finalize(st);
        json_object_array_add(diff, json_object_new_string("- config.db policy_route_rule"));
    } else if (webd_policy_pbr_apply_fields(db, rule_id, body, create, operation,
                                            err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail_rollback;
    }

    if (webd_policy_db_exec(db,
        "UPDATE advanced_routing_global SET object_revision=object_revision+1,"
        "apply_state='draft',updated_at=strftime('%s','now') WHERE id=1",
        err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail_rollback;
    }
    if (webd_policy_db_exec(db, "COMMIT", err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    json_object_array_add(steps, json_object_new_string("commit config.db policy route rule"));

    reload_route = webd_policy_query_or_body_bool(req, body, "reload_route", 1);
    if (reload_route) {
        if (webd_policy_pbr_runtime_reload(steps, warnings) != 0) {
            snprintf(err, sizeof(err), "route reload failed");
            if (http_status) *http_status = 409;
            goto fail_restore;
        }
    } else {
        json_object_array_add(warnings, json_object_new_string("route_runtime_reload_skipped"));
    }

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "runtime_reload", json_object_new_boolean(reload_route));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (db)
        sqlite3_close(db);
    return webd_envelope(data, "webd.policy_engine.pbr_apply");

fail_rollback:
    if (db)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
fail_restore:
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
    if (rc != 0) {
        json_object_array_add(steps, json_object_new_string("restore config.db backup after failed PBR transaction"));
        if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_DB, NULL, 0) == 0)
            json_object_array_add(warnings, json_object_new_string("config_db_restored_from_backup"));
        else
            json_object_array_add(warnings, json_object_new_string("config_db_restore_failed"));
    }
fail:
    if (db)
        sqlite3_close(db);
    json_object_object_add(tx, "ok", json_object_new_boolean(0));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(0));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "PBR transaction failed"));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("policy_pbr_apply_failed"));
    json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "PBR transaction failed"));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    return webd_envelope(data, "webd.policy_engine.pbr_apply");
}

int webd_policy_dhcp_section_exists(const char *id)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    int ok = 0;

    if (!id || !id[0])
        return 0;
    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "dhcp", &pkg) != UCI_OK || !pkg)
        goto out;
    s = webd_policy_find_dhcp_section(pkg, id, NULL);
    ok = s != NULL;
out:
    if (pkg)
        uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return ok;
}

struct json_object *webd_policy_pbr_reorder_response(struct json_object *body,
                                                             int apply_requested,
                                                             int *http_status)
{
    struct json_object *input = NULL;
    struct json_object *ids = json_object_new_array();
    struct json_object *params = json_object_new_object();
    struct json_object *data = json_object_new_object();
    struct json_object *preview = json_object_new_object();
    struct json_object *upstream = NULL;
    const char *policy_type = app_nc_json_str(body, "policy_type",
                              app_nc_json_str(body, "type", "pbr"));
    int i, n;

    if (!body || !json_object_is_type(body, json_type_object)) {
        if (http_status) *http_status = 400;
        json_object_put(ids); json_object_put(params); json_object_put(preview);
        webd_obj_add_str(data, "error", "invalid_request");
        webd_obj_add_str(data, "message", "reorder body must be an object");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        return webd_envelope(data, "webd.policy_engine.pbr_reorder");
    }
    if (strcasecmp(policy_type, "pbr") && strcasecmp(policy_type, "policy_route") &&
        strcasecmp(policy_type, "policy-route")) {
        if (http_status) *http_status = 409;
        json_object_put(ids); json_object_put(params); json_object_put(preview);
        webd_obj_add_str(data, "error", "reorder_scope_conflict");
        webd_obj_add_str(data, "message", "only config.db PBR policy rows support Policy Table reorder");
        webd_obj_add_str(data, "supported_scope", "config.db:policy_route_rule");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        return webd_envelope(data, "webd.policy_engine.pbr_reorder");
    }
    if (!json_object_object_get_ex(body, "ids", &input) &&
        !json_object_object_get_ex(body, "order", &input) &&
        !json_object_object_get_ex(body, "policy_ids", &input) &&
        !json_object_object_get_ex(body, "items", &input))
        input = NULL;
    if (!input || !json_object_is_type(input, json_type_array) ||
        (n = json_object_array_length(input)) <= 0 || n > 4096) {
        if (http_status) *http_status = 400;
        json_object_put(ids); json_object_put(params); json_object_put(preview);
        webd_obj_add_str(data, "error", "invalid_request");
        webd_obj_add_str(data, "message", "ids/order/items must be a non-empty array");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        return webd_envelope(data, "webd.policy_engine.pbr_reorder");
    }
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(input, i);
        const char *id = json_object_is_type(item, json_type_string) ?
                         json_object_get_string(item) : app_nc_json_str(item, "id", "");
        const char *raw_id;

        if (strncmp(id ? id : "", "policy_route_rule.", 18)) {
            if (http_status) *http_status = 409;
            json_object_put(ids); json_object_put(params); json_object_put(preview);
            webd_obj_add_str(data, "error", "reorder_scope_conflict");
            webd_obj_add_str(data, "message", "all reordered rows must come from config.db:policy_route_rule");
            webd_obj_add_str(data, "unsupported_id", id ? id : "");
            webd_obj_add_str(data, "supported_scope", "config.db:policy_route_rule");
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            return webd_envelope(data, "webd.policy_engine.pbr_reorder");
        }
        raw_id = id + 18;
        if (!webd_policy_pbr_id_ok(raw_id)) {
            if (http_status) *http_status = 400;
            json_object_put(ids); json_object_put(params); json_object_put(preview);
            webd_obj_add_str(data, "error", "invalid_policy_id");
            webd_obj_add_str(data, "message", "PBR policy id is invalid");
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            return webd_envelope(data, "webd.policy_engine.pbr_reorder");
        }
        json_object_array_add(ids, json_object_new_string(raw_id));
    }
    json_object_object_add(params, "ids", ids);
    json_object_object_add(params, "base_priority",
        json_object_new_int(app_nc_json_int(body, "base_priority", 1000)));
    json_object_object_add(params, "step",
        json_object_new_int(app_nc_json_int(body, "step", 10)));
    if (!apply_requested) {
        if (http_status) *http_status = 409;
        json_object_object_add(preview, "can_apply", json_object_new_boolean(1));
        json_object_object_add(preview, "applies_changes", json_object_new_boolean(0));
        json_object_object_add(preview, "apply_requires_explicit_apply_true", json_object_new_boolean(1));
        webd_obj_add_str(preview, "policy_type", "pbr");
        webd_obj_add_str(preview, "scope", "config.db:policy_route_rule");
        json_object_object_add(preview, "ordered_ids", json_object_get(ids));
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        webd_obj_add_str(data, "error", "policy_write_preview_only");
        webd_obj_add_str(data, "message", "add apply=true to execute transactional PBR reorder");
        json_object_object_add(data, "preview", preview);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
        json_object_put(params);
        return webd_envelope(data, "webd.policy_engine.pbr_reorder_preview");
    }
    json_object_put(preview);
    upstream = app_routed_call("policy_rules_reorder", params);
    json_object_put(params);
    if (http_status)
        *http_status = app_routed_http_status(upstream, 200);
    json_object_object_add(data, "ok",
        json_object_new_boolean(upstream && app_nc_json_bool(upstream, "ok", 0)));
    json_object_object_add(data, "applied",
        json_object_new_boolean(upstream && app_nc_json_bool(upstream, "ok", 0)));
    webd_obj_add_str(data, "policy_type", "pbr");
    webd_obj_add_str(data, "scope", "config.db:policy_route_rule");
    json_object_object_add(data, "transaction", upstream ? upstream :
                           webd_error("source_unavailable", "dreamingwrt-routed is not available",
                                      "policy_rules_reorder", "webd.policy_engine.pbr_reorder"));
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    return webd_envelope(data, "webd.policy_engine.pbr_reorder");
}

