/* SPDX-License-Identifier: GPL-2.0-or-later */
/* config.db authority and one-time UCI import for jmx_route. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <uci.h>

#include "jmx_route.h"
#include "jmx_route_db.h"

#define JMX_ROUTE_LEGACY_PATH "/etc/config/jmx_route"
#define ROUTE_HEALTH_FAIL_DEFAULT 2
#define ROUTE_HEALTH_RECOVER_DEFAULT 6
#define ROUTE_HEALTH_THRESHOLD_MAX 60

struct jmx_route_db_tx {
    sqlite3 *db;
};

static const char route_schema_sql[] =
    "PRAGMA foreign_keys=ON;"
    "CREATE TABLE IF NOT EXISTS config_migration("
    " name TEXT PRIMARY KEY,status TEXT NOT NULL,source TEXT NOT NULL DEFAULT '',"
    " imported_rows INTEGER NOT NULL DEFAULT 0,imported_at INTEGER NOT NULL DEFAULT 0,"
    " detail TEXT NOT NULL DEFAULT '');"
    "CREATE TABLE IF NOT EXISTS route_global("
    " id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
    " all_down_action TEXT NOT NULL DEFAULT 'main_route',"
    " dangling_wan_policy TEXT NOT NULL DEFAULT 'reinstate_registered');"
    "CREATE TABLE IF NOT EXISTS route_wan("
    " id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 255),position INTEGER NOT NULL UNIQUE,"
    " name TEXT NOT NULL,ifname TEXT NOT NULL DEFAULT '',fwmark INTEGER NOT NULL,"
    " table_id INTEGER NOT NULL,gateway TEXT NOT NULL DEFAULT '',"
    " health INTEGER NOT NULL DEFAULT 1 CHECK(health IN(0,1)),"
    " weight INTEGER NOT NULL DEFAULT 1 CHECK(weight>0),"
    " check_enable INTEGER NOT NULL DEFAULT 0 CHECK(check_enable IN(0,1)),"
    " failover INTEGER NOT NULL DEFAULT 1 CHECK(failover IN(0,1)),"
    " failback INTEGER NOT NULL DEFAULT 1 CHECK(failback IN(0,1)),"
    " fail_threshold INTEGER NOT NULL DEFAULT 2 CHECK(fail_threshold BETWEEN 1 AND 60),"
    " recover_threshold INTEGER NOT NULL DEFAULT 6 CHECK(recover_threshold BETWEEN 1 AND 60),"
    " health_mode TEXT NOT NULL DEFAULT '',check_host TEXT NOT NULL DEFAULT '',"
    " check_url TEXT NOT NULL DEFAULT '');"
    "CREATE TABLE IF NOT EXISTS route_rule("
    " rule_id INTEGER PRIMARY KEY,position INTEGER NOT NULL UNIQUE,name TEXT NOT NULL DEFAULT '',"
    " enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
    " prio INTEGER NOT NULL CHECK(prio BETWEEN 0 AND 65535),appid INTEGER NOT NULL DEFAULT 0,"
    " carrier TEXT NOT NULL DEFAULT '',proto TEXT NOT NULL DEFAULT 'any',"
    " src_addr TEXT NOT NULL DEFAULT '',src_mask TEXT NOT NULL DEFAULT '',"
    " dst_addr TEXT NOT NULL DEFAULT '',dst_mask TEXT NOT NULL DEFAULT '',"
    " dst_port INTEGER NOT NULL DEFAULT 0 CHECK(dst_port BETWEEN 0 AND 65535),"
    " sticky_mode TEXT NOT NULL DEFAULT 'hash_src',"
    " reinstate_dangling INTEGER NOT NULL DEFAULT 1 CHECK(reinstate_dangling IN(0,1)),"
    " policy_id TEXT NOT NULL DEFAULT '',fallback_policy_id TEXT NOT NULL DEFAULT '',"
    " member_weights_explicit INTEGER NOT NULL DEFAULT 0 CHECK(member_weights_explicit IN(0,1)),"
    " created_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0,"
    " smart_path_mode TEXT NOT NULL DEFAULT 'inherit',"
    " adaptive_penalty_sticky INTEGER NOT NULL DEFAULT 0 CHECK(adaptive_penalty_sticky IN(0,1)),"
    " legacy_mode TEXT NOT NULL DEFAULT '',migration_required INTEGER NOT NULL DEFAULT 0"
    " CHECK(migration_required IN(0,1)));"
    "CREATE TABLE IF NOT EXISTS route_rule_wan("
    " rule_id INTEGER NOT NULL REFERENCES route_rule(rule_id) ON DELETE CASCADE,"
    " position INTEGER NOT NULL,wan_id INTEGER NOT NULL CHECK(wan_id BETWEEN 1 AND 255),"
    " weight INTEGER NOT NULL DEFAULT 1 CHECK(weight>0),"
    " PRIMARY KEY(rule_id,position));"
    "CREATE TABLE IF NOT EXISTS route_carrier_prefix("
    " position INTEGER PRIMARY KEY,carrier TEXT NOT NULL,cidr TEXT NOT NULL);";

static void route_error(char *out, size_t out_len, const char *message)
{
    if (out && out_len)
        snprintf(out, out_len, "%s", message ? message : "route config error");
}

/*
 * How a rule member that the export reported as dangling is treated when the
 * sync pass turns out to have registered that WAN after all.
 *
 * route_wan is a user ledger, but jmx_route_sync_json() also tops up from UCI,
 * so a line dialled up in /etc/config/network is live in the kernel while absent
 * from the ledger -- and its rule members get split into dangling_wan_ids. Which
 * way that should resolve is a legitimate disagreement between users, not a bug
 * with one right answer, so it is configuration:
 *
 *   reinstate_registered  reinstate the member when this pass registered the WAN
 *                         (the default, and the behaviour that shipped before
 *                         this switch existed)
 *   keep_excluded         never reinstate; log a warning and leave it out
 *   per_rule              each rule decides through its reinstate_dangling flag
 *
 * The default is deliberately the pre-existing behaviour: upgrading in place must
 * not silently move anybody's traffic.
 */
static int route_dangling_policy_ok(const char *policy)
{
    return policy && (!strcmp(policy, "reinstate_registered") ||
                      !strcmp(policy, "keep_excluded") ||
                      !strcmp(policy, "per_rule"));
}

static int route_exec(sqlite3 *db, const char *sql)
{
    char *message = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &message);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "jmx_route_db: %s failed: %s\n", sql,
                message ? message : sqlite3_errmsg(db));
        sqlite3_free(message);
        errno = rc == SQLITE_BUSY || rc == SQLITE_LOCKED ? EBUSY : EIO;
        return -1;
    }
    return 0;
}

static int route_prepare(sqlite3 *db, sqlite3_stmt **stmt, const char *sql)
{
    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "jmx_route_db: prepare failed: %s: %s\n", sql,
                sqlite3_errmsg(db));
        errno = EIO;
        return -1;
    }
    return 0;
}

/*
 * Additive column migration for config.db files created before a column existed.
 *
 * CREATE TABLE IF NOT EXISTS in route_schema_sql is a no-op once the table is
 * there, so a new column never reaches an existing device without this. A
 * duplicate-column error is the expected outcome on an already-migrated file and
 * is not reported: this runs on every open.
 */
static void route_add_column_if_missing(sqlite3 *db, const char *table,
                                        const char *column, const char *decl)
{
    sqlite3_stmt *stmt = NULL;
    char sql[256];
    int found = 0;

    if (!db || !table || !column || !decl)
        return;
    snprintf(sql, sizeof(sql), "SELECT 1 FROM pragma_table_info('%s') WHERE name=?1",
             table);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(stmt, 1, column, -1, SQLITE_STATIC);
    found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    if (found)
        return;
    snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s", table, column, decl);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}

/* Whether a WAN id still names a configured line.  route_rule_wan has no
 * foreign key into route_wan, so members can reference lines that were removed. */
static int route_wan_id_exists(sqlite3 *db, int wan_id)
{
    sqlite3_stmt *stmt = NULL;
    int found = 0;

    if (route_prepare(db, &stmt, "SELECT 1 FROM route_wan WHERE id=?1") != 0)
        return 0;
    sqlite3_bind_int(stmt, 1, wan_id);
    found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}

static const char *route_json_string(struct json_object *object, const char *key,
                                     const char *def)
{
    struct json_object *value = NULL;

    if (!object || !json_object_object_get_ex(object, key, &value) ||
        !json_object_is_type(value, json_type_string))
        return def;
    return json_object_get_string(value);
}

static int route_json_u32(struct json_object *object, const char *key,
                          uint32_t def, uint32_t *out)
{
    struct json_object *value = NULL;
    int64_t number;

    if (!out)
        return -1;
    if (!object || !json_object_object_get_ex(object, key, &value)) {
        *out = def;
        return 0;
    }
    if (!json_object_is_type(value, json_type_int))
        return -1;
    number = json_object_get_int64(value);
    if (number < 0 || (uint64_t)number > UINT32_MAX)
        return -1;
    *out = (uint32_t)number;
    return 0;
}

static int route_json_bool(struct json_object *object, const char *key,
                           int def, int *out)
{
    struct json_object *value = NULL;

    if (!out)
        return -1;
    if (!object || !json_object_object_get_ex(object, key, &value)) {
        *out = def;
        return 0;
    }
    if (!json_object_is_type(value, json_type_boolean))
        return -1;
    *out = json_object_get_boolean(value) ? 1 : 0;
    return 0;
}

/*
 * `enabled` is a 0/1 flag in config.db and this validator has always read it
 * with route_json_u32(), i.e. json_type_int only.  But the field is a boolean
 * everywhere above routed: webd's REST contract types it as one and its merge
 * writes json_object_new_boolean(), so every WAN-policy create and edit arrived
 * as `true` and was rejected with "invalid route rule numeric field" -- a
 * message that names no field and reads, through webd's 400, as
 * "配置校验未通过，配置未改动".  The read path emits the int form, so a client
 * that reads, edits one field and writes back could not tell which of the
 * rule's three semantic booleans wanted int (`enabled`) and which wanted bool
 * (`adaptive_penalty_sticky`).
 *
 * Accept either spelling for such flags.  This only widens what validates; the
 * canonical output stays int, so config.db and every reader are unchanged.
 */
static int route_json_flag(struct json_object *object, const char *key,
                           uint32_t def, uint32_t *out)
{
    struct json_object *value = NULL;

    if (!out)
        return -1;
    if (!object || !json_object_object_get_ex(object, key, &value)) {
        *out = def;
        return 0;
    }
    if (json_object_is_type(value, json_type_boolean)) {
        *out = json_object_get_boolean(value) ? 1 : 0;
        return 0;
    }
    return route_json_u32(object, key, def, out);
}

static int route_json_mark(struct json_object *object, const char *key,
                           uint32_t def, uint32_t *out)
{
    struct json_object *value = NULL;
    const char *text;
    char *end = NULL;
    unsigned long long number;

    if (!object || !json_object_object_get_ex(object, key, &value)) {
        *out = def;
        return 0;
    }
    if (json_object_is_type(value, json_type_int))
        return route_json_u32(object, key, def, out);
    if (!json_object_is_type(value, json_type_string))
        return -1;
    text = json_object_get_string(value);
    if (!text || !text[0] || text[0] == '-')
        return -1;
    errno = 0;
    number = strtoull(text, &end, 0);
    if (errno || end == text || *end || number > UINT32_MAX)
        return -1;
    *out = (uint32_t)number;
    return 0;
}

static uint32_t route_gcd_u32(uint32_t a, uint32_t b)
{
    while (b) {
        uint32_t r = a % b;
        a = b;
        b = r;
    }
    return a ? a : 1;
}

static int route_string_ok(const char *value, size_t max_len)
{
    return value && strlen(value) < max_len;
}

/*
 * Length-only validation is not enough for the fields that end up as shell
 * words. A WAN name stored here is later interpolated into a popen() command
 * ("ubus -S call network.interface.<name> status") in
 * jmx_netconfig_db.c:nc_dns_route_wan_runtime(), so a name containing ; | ` or
 * $() would run as a command. Restrict the identifier-like fields to the same
 * character class jmx_netconfig_db.c:nc_valid_name() already enforces on the
 * netconfig side.
 *
 * Deliberately scoped to identifiers only: this must keep accepting the names
 * real deployments already use (verified on a live box: "wan", "wan2", plus UCI
 * interfaces such as "wan6", "vpn0", "client1", and dotted VLAN forms like
 * "eth0.100"), and must NOT be applied to free-text fields like a rule's
 * display name, where spaces and punctuation are legitimate.
 */
static int route_identifier_ok(const char *value, size_t max_len)
{
    size_t i;

    if (!route_string_ok(value, max_len))
        return 0;
    for (i = 0; value[i]; i++) {
        char c = value[i];

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')
            continue;
        return 0;
    }
    return 1;
}

static int route_policy_id_ok(const char *value)
{
    return route_identifier_ok(value, 64) && value[0];
}

static int route_policy_graph_validate(struct json_object *rules,
                                       char *error, size_t error_len)
{
    int count, i, j;

    if (!rules || !json_object_is_type(rules, json_type_array))
        return 0;
    count = json_object_array_length(rules);
    if (count > JMX_ROUTE_MAX_RULES) {
        route_error(error, error_len, "too many route rules");
        errno = E2BIG;
        return -1;
    }

    for (i = 0; i < count; i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        const char *policy_id = route_json_string(rule, "policy_id", "");
        const char *fallback = route_json_string(rule, "fallback_policy_id", "");
        uint32_t prio = 0;

        (void)route_json_u32(rule, "prio", 0, &prio);
        if (fallback[0] && !strcmp(policy_id, fallback)) {
            route_error(error, error_len, "fallback policy cannot reference itself");
            errno = EINVAL;
            return -1;
        }
        for (j = 0; j < i; j++) {
            struct json_object *other = json_object_array_get_idx(rules, j);
            const char *other_id = route_json_string(other, "policy_id", "");
            uint32_t other_prio = 0;

            (void)route_json_u32(other, "prio", 0, &other_prio);
            if (!strcmp(policy_id, other_id)) {
                route_error(error, error_len, "duplicate policy_id");
                errno = EEXIST;
                return -1;
            }
            if (prio == other_prio) {
                route_error(error, error_len, "duplicate route rule priority");
                errno = EEXIST;
                return -1;
            }
        }
    }

    for (i = 0; i < count; i++) {
        uint8_t visited[JMX_ROUTE_MAX_RULES] = {0};
        int current = i;

        while (current >= 0) {
            struct json_object *rule;
            const char *fallback;
            int next = -1;

            if (visited[current]) {
                route_error(error, error_len, "fallback policy cycle detected");
                errno = ELOOP;
                return -1;
            }
            visited[current] = 1;
            rule = json_object_array_get_idx(rules, current);
            fallback = route_json_string(rule, "fallback_policy_id", "");
            if (!fallback[0])
                break;
            for (j = 0; j < count; j++) {
                struct json_object *candidate = json_object_array_get_idx(rules, j);

                if (!strcmp(fallback,
                            route_json_string(candidate, "policy_id", ""))) {
                    next = j;
                    break;
                }
            }
            if (next < 0) {
                route_error(error, error_len, "fallback policy does not exist");
                errno = ENOENT;
                return -1;
            }
            {
                struct json_object *target = json_object_array_get_idx(rules, next);
                uint32_t source_prio = 0, target_prio = 0;
                uint32_t source_appid = 0, target_appid = 0;
                uint32_t source_dport = 0, target_dport = 0;
                static const char *const match_keys[] = {
                    "carrier", "proto", "src_addr", "src_mask",
                    "dst_addr", "dst_mask"
                };
                size_t key_index;

                (void)route_json_u32(rule, "prio", 0, &source_prio);
                (void)route_json_u32(target, "prio", 0, &target_prio);
                (void)route_json_u32(rule, "appid", 0, &source_appid);
                (void)route_json_u32(target, "appid", 0, &target_appid);
                (void)route_json_u32(rule, "dst_port", 0, &source_dport);
                (void)route_json_u32(target, "dst_port", 0, &target_dport);
                if (target_prio <= source_prio) {
                    route_error(error, error_len,
                                "fallback policy must have lower routing precedence");
                    errno = EINVAL;
                    return -1;
                }
                if (source_appid != target_appid || source_dport != target_dport) {
                    route_error(error, error_len,
                                "fallback policy match conditions must match primary policy");
                    errno = EINVAL;
                    return -1;
                }
                for (key_index = 0;
                     key_index < sizeof(match_keys) / sizeof(match_keys[0]);
                     key_index++) {
                    if (strcmp(route_json_string(rule, match_keys[key_index], ""),
                               route_json_string(target, match_keys[key_index], ""))) {
                        route_error(error, error_len,
                                    "fallback policy match conditions must match primary policy");
                        errno = EINVAL;
                        return -1;
                    }
                }
            }
            current = next;
        }
    }
    return 0;
}

static int route_ipv4_ok(const char *value)
{
    struct in_addr address;

    return !value || !value[0] || inet_pton(AF_INET, value, &address) == 1;
}

static int route_cidr_ok(const char *value)
{
    char buffer[64];
    char *slash;
    char *end = NULL;
    long prefix = 32;

    if (!value || !value[0] || strlen(value) >= sizeof(buffer))
        return 0;
    snprintf(buffer, sizeof(buffer), "%s", value);
    slash = strchr(buffer, '/');
    if (slash) {
        *slash++ = '\0';
        prefix = strtol(slash, &end, 10);
        if (end == slash || *end || prefix < 0 || prefix > 32)
            return 0;
    }
    return route_ipv4_ok(buffer) && buffer[0];
}

static int route_mode_id(const char *mode)
{
    char *end = NULL;
    unsigned long number;

    if (!mode || !mode[0] || !strcmp(mode, "sip") || !strcmp(mode, "hash_src"))
        return JMX_STICKY_SIP;
    if (!strcmp(mode, "new_conn") || !strcmp(mode, "weighted_new_flow_rr"))
        return JMX_STICKY_NEW_CONN;
    if (!strcmp(mode, "sip_sport") || !strcmp(mode, "sip+sport") ||
        !strcmp(mode, "hash_src_sport"))
        return JMX_STICKY_SIP_SPORT;
    if (!strcmp(mode, "sip_dip") || !strcmp(mode, "sip+dip") ||
        !strcmp(mode, "hash_src_dst"))
        return JMX_STICKY_SIP_DIP;
    if (!strcmp(mode, "sip_dip_dport") || !strcmp(mode, "sip+dip+dport") ||
        !strcmp(mode, "hash_src_dst_dport"))
        return JMX_STICKY_SIP_DIP_DPORT;
    if (!strcmp(mode, "5tuple") || !strcmp(mode, "five_tuple"))
        return JMX_STICKY_5TUPLE;
    if (!strcmp(mode, "primary_backup") || !strcmp(mode, "primary-backup"))
        return JMX_STICKY_PRIMARY_BACKUP;
    if (!strcmp(mode, "download") || !strcmp(mode, "least_rx_load_normalized"))
        return JMX_STICKY_DOWNLOAD;
    if (!strcmp(mode, "conn_cnt") || !strcmp(mode, "conn-count") ||
        !strcmp(mode, "connection_count") ||
        !strcmp(mode, "least_active_conn_normalized"))
        return JMX_STICKY_CONN_CNT;
    if (!strcmp(mode, "adaptive_penalty_sticky") ||
        !strcmp(mode, "adaptive-penalty-sticky"))
        return JMX_STICKY_ADAPTIVE_PENALTY;
    errno = 0;
    number = strtoul(mode, &end, 0);
    if (errno || end == mode || *end || number > JMX_STICKY_MAX)
        return -1;
    return (int)number;
}

static const char *route_mode_algorithm(int mode)
{
    static const char *const names[] = {
        "weighted_new_flow_rr", "hash_src", "hash_src_sport", "hash_src_dst",
        "hash_src_dst_dport", "five_tuple", "primary_backup",
        "least_rx_load_normalized", "least_active_conn_normalized",
        "adaptive_penalty_sticky"
    };

    return mode >= 0 && mode <= JMX_STICKY_MAX ? names[mode] : NULL;
}

static int route_proto_ok(const char *proto)
{
    char *end = NULL;
    unsigned long number;

    if (!proto || !proto[0] || !strcasecmp(proto, "any") ||
        !strcasecmp(proto, "tcp") || !strcasecmp(proto, "udp"))
        return 1;
    errno = 0;
    number = strtoul(proto, &end, 0);
    return !errno && end != proto && !*end && number <= UINT8_MAX;
}

static int route_carrier_id(const char *carrier)
{
    char *end = NULL;
    unsigned long number;

    if (!carrier || !carrier[0] || !strcasecmp(carrier, "any"))
        return JMX_CARRIER_ANY;
    if (!strcasecmp(carrier, "telecom") || !strcasecmp(carrier, "ctcc"))
        return JMX_CARRIER_TELECOM;
    if (!strcasecmp(carrier, "unicom") || !strcasecmp(carrier, "cucc"))
        return JMX_CARRIER_UNICOM;
    if (!strcasecmp(carrier, "mobile") || !strcasecmp(carrier, "cmcc"))
        return JMX_CARRIER_MOBILE;
    if (!strcasecmp(carrier, "edu") || !strcasecmp(carrier, "cernet"))
        return JMX_CARRIER_EDU;
    if (!strcasecmp(carrier, "other"))
        return JMX_CARRIER_OTHER;
    errno = 0;
    number = strtoul(carrier, &end, 0);
    return !errno && end != carrier && !*end && number <= UINT8_MAX ? (int)number : -1;
}

static void route_add_counts(struct json_object *config)
{
    struct json_object *array = NULL;
    int count;

    json_object_object_get_ex(config, "wans", &array);
    count = array ? json_object_array_length(array) : 0;
    json_object_object_add(config, "wan_count", json_object_new_int(count));
    json_object_object_get_ex(config, "rules", &array);
    count = array ? json_object_array_length(array) : 0;
    json_object_object_add(config, "rule_count", json_object_new_int(count));
    json_object_object_get_ex(config, "carrier_prefixes", &array);
    count = array ? json_object_array_length(array) : 0;
    json_object_object_add(config, "carrier_prefix_count", json_object_new_int(count));
}

/*
 * Range-check the caller's stale member list before any rule-level verdict is
 * reached, so a malformed id reports itself instead of surfacing later as the
 * unrelated "must match a carrier" complaint.
 */
static int route_rule_stale_ids_ok(struct json_object *rule)
{
    struct json_object *stale = NULL;
    int i;

    if (!json_object_object_get_ex(rule, "dangling_wan_ids", &stale))
        return 1;
    if (!json_object_is_type(stale, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(stale); i++) {
        struct json_object *value = json_object_array_get_idx(stale, i);
        int64_t wan_id;

        if (!value || !json_object_is_type(value, json_type_int))
            return 0;
        wan_id = json_object_get_int64(value);
        if (wan_id <= 0 || wan_id > UINT8_MAX)
            return 0;
    }
    return 1;
}

/*
 * Whether a rule still records at least one member whose line is absent from
 * this payload.  Such a rule pinned specific lines, so it must not be judged as
 * if it had named none: the members come either from wan_ids entries that did
 * not resolve (already split into reclassified) or from a dangling_wan_ids field
 * the caller round-tripped, and an id there that the payload does restore counts
 * as live rather than stale.
 */
static int route_rule_has_stale_member(struct json_object *rule,
                                       struct json_object *reclassified,
                                       const uint8_t *wan_ids_seen)
{
    struct json_object *stale = NULL;
    int i;

    if (reclassified && json_object_array_length(reclassified) > 0)
        return 1;
    if (!json_object_object_get_ex(rule, "dangling_wan_ids", &stale) ||
        !json_object_is_type(stale, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(stale); i++) {
        struct json_object *value = json_object_array_get_idx(stale, i);
        int64_t wan_id;

        if (!value || !json_object_is_type(value, json_type_int))
            continue;
        wan_id = json_object_get_int64(value);
        if (wan_id > 0 && wan_id <= UINT8_MAX && !wan_ids_seen[wan_id])
            return 1;
    }
    return 0;
}

static int route_validate_payload(struct json_object *request,
                                  struct json_object **canonical,
                                  char *error, size_t error_len)
{
    struct json_object *result = NULL;
    struct json_object *wans = NULL, *rules = NULL, *prefixes = NULL, *failover = NULL;
    struct json_object *out_wans = NULL, *out_rules = NULL, *out_prefixes = NULL;
    const char *all_down_action = "main_route";
    const char *dangling_policy = "reinstate_registered";
    uint8_t wan_ids_seen[256] = {0};
    uint32_t wan_weights_by_id[256] = {0};
    int i;

    if (!canonical || !request || !json_object_is_type(request, json_type_object)) {
        route_error(error, error_len, "request must be an object");
        errno = EINVAL;
        return -1;
    }
    if (json_object_object_get_ex(request, "all_down_action", &failover)) {
        if (!json_object_is_type(failover, json_type_string))
            goto invalid_all_down;
        all_down_action = json_object_get_string(failover);
    }
    if (json_object_object_get_ex(request, "failover", &failover)) {
        struct json_object *value = NULL;
        if (!json_object_is_type(failover, json_type_object)) {
            route_error(error, error_len, "failover must be an object");
            goto invalid;
        }
        if (json_object_object_get_ex(failover, "all_down_action", &value)) {
            if (!json_object_is_type(value, json_type_string))
                goto invalid_all_down;
            all_down_action = json_object_get_string(value);
        }
    }
    if (strcmp(all_down_action, "main_route")) {
invalid_all_down:
        route_error(error, error_len, "all_down_action must be main_route");
        errno = EOPNOTSUPP;
        return -1;
    }
    /* Absent means "keep the current value" is *not* the contract here: this
     * validator rebuilds the canonical config from a fixed field list and the
     * writer replaces route_global wholesale, so an omitted key resolves to the
     * default, exactly like all_down_action. A caller that reads, edits one field
     * and writes back therefore preserves it, which is how the UI works. */
    {
        struct json_object *policy = NULL;

        if (json_object_object_get_ex(request, "dangling_wan_policy", &policy)) {
            if (!json_object_is_type(policy, json_type_string) ||
                !route_dangling_policy_ok(json_object_get_string(policy))) {
                route_error(error, error_len,
                            "dangling_wan_policy must be reinstate_registered, keep_excluded, or per_rule");
                errno = EINVAL;
                return -1;
            }
            dangling_policy = json_object_get_string(policy);
        }
    }
    if (json_object_object_get_ex(request, "wans", &wans) &&
        !json_object_is_type(wans, json_type_array)) {
        route_error(error, error_len, "wans must be an array");
        goto invalid;
    }
    if (json_object_object_get_ex(request, "rules", &rules) &&
        !json_object_is_type(rules, json_type_array)) {
        route_error(error, error_len, "rules must be an array");
        goto invalid;
    }
    if (json_object_object_get_ex(request, "carrier_prefixes", &prefixes) &&
        !json_object_is_type(prefixes, json_type_array)) {
        route_error(error, error_len, "carrier_prefixes must be an array");
        goto invalid;
    }
    if (wans && json_object_array_length(wans) > JMX_ROUTE_MAX_WAN_IFACES) {
        route_error(error, error_len, "too many WANs");
        goto invalid;
    }
    if (rules && json_object_array_length(rules) > JMX_ROUTE_MAX_RULES) {
        route_error(error, error_len, "too many route rules");
        errno = E2BIG;
        return -1;
    }

    result = json_object_new_object();
    out_wans = json_object_new_array();
    out_rules = json_object_new_array();
    out_prefixes = json_object_new_array();
    if (!result || !out_wans || !out_rules || !out_prefixes)
        goto nomem;
    json_object_object_add(result, "wans", out_wans);
    json_object_object_add(result, "rules", out_rules);
    json_object_object_add(result, "carrier_prefixes", out_prefixes);
    json_object_object_add(result, "all_down_action", json_object_new_string("main_route"));
    json_object_object_add(result, "dangling_wan_policy",
                           json_object_new_string(dangling_policy));

    for (i = 0; wans && i < json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);
        struct json_object *out = json_object_new_object();
        uint32_t id, fwmark, table_id, health, weight, check_enable;
        uint32_t failover_value, failback, fail_threshold, recover_threshold;
        const char *name, *ifname, *gateway, *health_mode, *check_host, *check_url;

        if (!wan || !json_object_is_type(wan, json_type_object) || !out ||
            route_json_u32(wan, "id", 0, &id) || !id || id > UINT8_MAX || wan_ids_seen[id] ||
            route_json_mark(wan, "fwmark", 0x10000U + id, &fwmark) ||
            route_json_u32(wan, "table", 100U + id, &table_id) || !table_id ||
            route_json_u32(wan, "health", 1, &health) || health > 1 ||
            route_json_u32(wan, "weight", 1, &weight) || !weight ||
            route_json_u32(wan, "check_enable", 0, &check_enable) || check_enable > 1 ||
            route_json_u32(wan, "failover", 1, &failover_value) || failover_value > 1 ||
            route_json_u32(wan, "failback", 1, &failback) || failback > 1 ||
            route_json_u32(wan, "fail_threshold", ROUTE_HEALTH_FAIL_DEFAULT, &fail_threshold) ||
            !fail_threshold || fail_threshold > ROUTE_HEALTH_THRESHOLD_MAX ||
            route_json_u32(wan, "recover_threshold", ROUTE_HEALTH_RECOVER_DEFAULT,
                           &recover_threshold) || !recover_threshold ||
            recover_threshold > ROUTE_HEALTH_THRESHOLD_MAX) {
            if (out) json_object_put(out);
            route_error(error, error_len, "invalid WAN numeric field or duplicate id");
            goto invalid_result;
        }
        wan_ids_seen[id] = 1;
        wan_weights_by_id[id] = weight;
        name = route_json_string(wan, "name", "wan");
        ifname = route_json_string(wan, "ifname", "");
        gateway = route_json_string(wan, "gateway", "");
        health_mode = route_json_string(wan, "health_mode", "");
        check_host = route_json_string(wan, "check_host", "");
        check_url = route_json_string(wan, "check_url", "");
        /* name and ifname are identifiers that reach a shell command; check for
         * character content, not just length. check_host/check_url stay
         * length-checked here because they are validated where they are used. */
        if (!route_identifier_ok(name, 64) || !name[0] ||
            !route_identifier_ok(ifname, 64) ||
            !route_string_ok(gateway, 64) || !route_ipv4_ok(gateway) ||
            !route_string_ok(health_mode, 32) || !route_string_ok(check_host, 128) ||
            !route_string_ok(check_url, 128)) {
            json_object_put(out);
            route_error(error, error_len, "invalid WAN string or gateway");
            goto invalid_result;
        }
        json_object_object_add(out, "id", json_object_new_int64(id));
        json_object_object_add(out, "name", json_object_new_string(name));
        if (ifname[0]) json_object_object_add(out, "ifname", json_object_new_string(ifname));
        {
            char mark[16];
            snprintf(mark, sizeof(mark), "0x%x", fwmark);
            json_object_object_add(out, "fwmark", json_object_new_string(mark));
        }
        json_object_object_add(out, "table", json_object_new_int64(table_id));
        if (gateway[0]) json_object_object_add(out, "gateway", json_object_new_string(gateway));
        json_object_object_add(out, "health", json_object_new_int64(health));
        json_object_object_add(out, "weight", json_object_new_int64(weight));
        json_object_object_add(out, "check_enable", json_object_new_int64(check_enable));
        json_object_object_add(out, "failover", json_object_new_int64(failover_value));
        json_object_object_add(out, "failback", json_object_new_int64(failback));
        json_object_object_add(out, "fail_threshold", json_object_new_int64(fail_threshold));
        json_object_object_add(out, "recover_threshold", json_object_new_int64(recover_threshold));
        if (health_mode[0]) json_object_object_add(out, "health_mode", json_object_new_string(health_mode));
        if (check_host[0]) json_object_object_add(out, "check_host", json_object_new_string(check_host));
        if (check_url[0]) json_object_object_add(out, "check_url", json_object_new_string(check_url));
        json_object_array_add(out_wans, out);
    }

    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        int adaptive_penalty = 0;
        struct json_object *wan_ids = NULL, *out_ids = json_object_new_array();
        struct json_object *members = NULL, *out_members = json_object_new_array();
        struct json_object *out_stale_ids = NULL;
        struct json_object *out = json_object_new_object();
        uint8_t rule_member_seen[256] = {0};
        uint32_t enabled, prio, appid, dst_port, reinstate_dangling;
        uint32_t member_weights_explicit;
        uint32_t created_at, updated_at;
        const char *name, *carrier, *proto, *src_addr, *src_mask, *dst_addr, *dst_mask;
        const char *policy_id, *fallback_policy_id;
        const char *smart_path_mode = "inherit";
        int adaptive_penalty_sticky = 0;
        struct json_object *smart_path = NULL;
        char policy_id_buf[64];
        const char *mode_name;
        const char *base_mode = NULL;
        const char *algorithm_mode = NULL;
        const char *sticky_mode = NULL;
        const char *legacy_mode = "";
        int migration_required = 0;
        int explicit_base_mode = 0;
        int mode;
        int j;

        if (!rule || !json_object_is_type(rule, json_type_object) || !out || !out_ids || !out_members ||
            route_json_flag(rule, "enabled", 1, &enabled) || enabled > 1 ||
            route_json_u32(rule, "prio", 1000U + (uint32_t)i, &prio) || prio > UINT16_MAX ||
            route_json_u32(rule, "appid", 0, &appid) ||
            route_json_u32(rule, "dst_port", 0, &dst_port) || dst_port > UINT16_MAX ||
            route_json_u32(rule, "created_at", 0, &created_at) ||
            route_json_u32(rule, "updated_at", created_at, &updated_at)) {
            if (out) json_object_put(out);
            if (out_ids) json_object_put(out_ids);
            if (out_members) json_object_put(out_members);
            route_error(error, error_len, "invalid route rule numeric field");
            goto invalid_result;
        }
        /* Only consulted when dangling_wan_policy is per_rule; stored regardless
         * so switching the global policy does not lose per-rule intent. Defaults
         * to 1 to match the global default. */
        if (route_json_u32(rule, "reinstate_dangling", 1, &reinstate_dangling) ||
            reinstate_dangling > 1) {
            if (out) json_object_put(out);
            if (out_ids) json_object_put(out_ids);
            if (out_members) json_object_put(out_members);
            route_error(error, error_len, "reinstate_dangling must be 0 or 1");
            goto invalid_result;
        }
        if (json_object_object_get_ex(rule, "smart_path", &smart_path)) {
            struct json_object *enabled_value = NULL;

            if (!smart_path || json_object_is_type(smart_path, json_type_null)) {
                smart_path_mode = "inherit";
            } else if (json_object_is_type(smart_path, json_type_object) &&
                       json_object_object_get_ex(smart_path, "enabled", &enabled_value) &&
                       enabled_value && json_object_is_type(enabled_value, json_type_boolean)) {
                smart_path_mode = json_object_get_boolean(enabled_value) ?
                    "enabled" : "disabled";
            } else {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len,
                            "smart_path must be null or {enabled:boolean}");
                goto invalid_result;
            }
        }
        if (json_object_object_get_ex(rule, "smart_path_mode", &smart_path)) {
            if (!smart_path || !json_object_is_type(smart_path, json_type_string) ||
                (strcmp(json_object_get_string(smart_path), "inherit") &&
                 strcmp(json_object_get_string(smart_path), "enabled") &&
                 strcmp(json_object_get_string(smart_path), "disabled"))) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len,
                            "smart_path_mode must be inherit, enabled, or disabled");
                goto invalid_result;
            }
            smart_path_mode = json_object_get_string(smart_path);
        }
        name = route_json_string(rule, "name", "");
        policy_id = route_json_string(rule, "policy_id", "");
        fallback_policy_id = route_json_string(rule, "fallback_policy_id", "");
        if (!policy_id[0]) {
            snprintf(policy_id_buf, sizeof(policy_id_buf), "route-policy-%u", prio);
            policy_id = policy_id_buf;
        }
        carrier = route_json_string(rule, "carrier", "");
        if (!carrier[0]) {
            uint32_t carrier_id = 0;
            if (route_json_u32(rule, "carrier_id", 0, &carrier_id) || carrier_id > UINT8_MAX) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len, "invalid carrier_id");
                goto invalid_result;
            }
            if (carrier_id) {
                static char carrier_buffer[16];
                snprintf(carrier_buffer, sizeof(carrier_buffer), "%u", carrier_id);
                carrier = carrier_buffer;
            }
        }
        proto = route_json_string(rule, "proto", "any");
        src_addr = route_json_string(rule, "src_addr", "");
        src_mask = route_json_string(rule, "src_mask", "");
        dst_addr = route_json_string(rule, "dst_addr", "");
        dst_mask = route_json_string(rule, "dst_mask", "");
        if (json_object_object_get_ex(rule, "base_mode", &smart_path)) {
            if (!smart_path || !json_object_is_type(smart_path, json_type_string)) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len, "base_mode must be a string");
                goto invalid_result;
            }
            base_mode = json_object_get_string(smart_path);
            explicit_base_mode = 1;
        }
        if (json_object_object_get_ex(rule, "algorithm", &smart_path)) {
            if (!smart_path || !json_object_is_type(smart_path, json_type_string)) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len, "algorithm must be a string");
                goto invalid_result;
            }
            algorithm_mode = json_object_get_string(smart_path);
        }
        if (json_object_object_get_ex(rule, "sticky_mode", &smart_path)) {
            if (!smart_path || !json_object_is_type(smart_path, json_type_string)) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len, "sticky_mode must be a string");
                goto invalid_result;
            }
            sticky_mode = json_object_get_string(smart_path);
        }
        mode_name = base_mode ? base_mode :
            (algorithm_mode ? algorithm_mode : (sticky_mode ? sticky_mode : "sip"));
        if (explicit_base_mode && !strcmp(mode_name, "adaptive_penalty_sticky")) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            route_error(error, error_len,
                        "base_mode_conflict: adaptive_penalty_sticky is an enhancement, not a base_mode");
            goto invalid_result;
        }
        if ((algorithm_mode && route_mode_id(algorithm_mode) != route_mode_id(mode_name)) ||
            (sticky_mode && route_mode_id(sticky_mode) != route_mode_id(mode_name))) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            route_error(error, error_len,
                        "base_mode_conflict: base_mode, algorithm, and sticky_mode must agree");
            goto invalid_result;
        }
        if (!explicit_base_mode && !strcmp(mode_name, "adaptive_penalty_sticky")) {
            /* The legacy mode fixed its selector to weighted new-flow RR.  Keep
             * that exact behaviour until an explicit canonical write replaces it. */
            mode_name = "weighted_new_flow_rr";
            adaptive_penalty_sticky = 1;
            legacy_mode = "adaptive_penalty_sticky";
            migration_required = 1;
        }
        /* Checked against either spelling, for the same reason as the read
         * below: keyed on json_type_boolean alone, an explicit `0` slipped past
         * this guard and silently became 1 via the legacy branch above. */
        if (migration_required &&
            json_object_object_get_ex(rule, "adaptive_penalty_sticky", &smart_path) &&
            smart_path) {
            uint32_t requested;

            if (route_json_flag(rule, "adaptive_penalty_sticky", 1,
                                &requested) == 0 && !requested) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len,
                            "base_mode_conflict: legacy adaptive mode conflicts with disabled enhancement");
                goto invalid_result;
            }
        }
        /* The mirror image of the `enabled` trap above: this one accepted only
         * json_type_boolean, so a client that spelled the same flag as 1 was
         * rejected.  Take either spelling here too. */
        {
            uint32_t adaptive_flag;

            if (route_json_flag(rule, "adaptive_penalty_sticky",
                                adaptive_penalty_sticky ? 1 : 0,
                                &adaptive_flag) != 0 || adaptive_flag > 1) {
                json_object_put(out); json_object_put(out_ids);
                json_object_put(out_members);
                route_error(error, error_len,
                            "adaptive_penalty_sticky must be boolean");
                goto invalid_result;
            }
            adaptive_penalty_sticky = (int)adaptive_flag;
        }
        mode = route_mode_id(mode_name);
        if (!route_string_ok(name, 128) || !route_policy_id_ok(policy_id) ||
            (fallback_policy_id[0] && !route_string_ok(fallback_policy_id, 64)) ||
            (fallback_policy_id[0] && !route_policy_id_ok(fallback_policy_id)) ||
            !route_string_ok(carrier, 32) ||
            route_carrier_id(carrier) < 0 || !route_string_ok(proto, 16) ||
            !route_proto_ok(proto) || !route_string_ok(src_addr, 64) ||
            !route_string_ok(src_mask, 64) || !route_string_ok(dst_addr, 64) ||
            !route_string_ok(dst_mask, 64) || !route_ipv4_ok(src_addr) ||
            !route_ipv4_ok(src_mask) || !route_ipv4_ok(dst_addr) ||
            !route_ipv4_ok(dst_mask) || mode < 0) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            route_error(error, error_len, "invalid route rule string, IPv4, protocol, carrier, or algorithm");
            goto invalid_result;
        }
        if (json_object_object_get_ex(rule, "wan_ids", &wan_ids) &&
            !json_object_is_type(wan_ids, json_type_array)) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            route_error(error, error_len, "wan_ids must be an array");
            goto invalid_result;
        }
        if (wan_ids && json_object_array_length(wan_ids) > JMX_ROUTE_MAX_WAN_IFACES) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            route_error(error, error_len, "too many WAN targets in route rule");
            goto invalid_result;
        }
        /*
         * Split members the same way route_read_config() does, against the WAN
         * set in this very payload: whatever does not resolve becomes a stale
         * member instead of a live target.  The canonical copy has to match what
         * the export will report, because jmx_route_db_replace_begin() commits
         * only when canonical and readback compare equal.  Classifying here also
         * covers the ordinary case the export cannot see in advance -- deleting a
         * WAN that a rule still references, where the member turns stale as a
         * direct result of this same request.
         */
        if (!route_rule_stale_ids_ok(rule)) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            route_error(error, error_len, "invalid stale WAN target id");
            goto invalid_result;
        }
        if (json_object_object_get_ex(rule, "members", &members) &&
            !json_object_is_type(members, json_type_array)) {
            json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
            route_error(error, error_len, "members must be an array");
            goto invalid_result;
        }
        if (members && json_object_array_length(members) > JMX_ROUTE_MAX_WAN_IFACES) {
            json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
            route_error(error, error_len, "too many route rule members");
            goto invalid_result;
        }
        if (route_json_u32(rule, "member_weights_explicit", members ? 1 : 0,
                           &member_weights_explicit) ||
            member_weights_explicit > 1) {
            json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
            route_error(error, error_len, "member_weights_explicit must be 0 or 1");
            goto invalid_result;
        }
        {
            int wan_count = wan_ids ? json_object_array_length(wan_ids) : 0;
            int member_count = members ? json_object_array_length(members) : 0;
            int count = members ? member_count : wan_count;

            if (members && wan_ids && member_count != wan_count) {
                json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                route_error(error, error_len, "members must contain one entry for every wan_id");
                goto invalid_result;
            }
            for (j = 0; j < count; j++) {
                struct json_object *value = wan_ids ? json_object_array_get_idx(wan_ids, j) : NULL;
                struct json_object *member = members ? json_object_array_get_idx(members, j) : NULL;
                struct json_object *member_wan = NULL;
                int64_t wan_id;
                uint32_t weight = 1;

                if (member) {
                    if (!json_object_is_type(member, json_type_object) ||
                        !json_object_object_get_ex(member, "wan_id", &member_wan) ||
                        !json_object_is_type(member_wan, json_type_int) ||
                        route_json_u32(member, "weight", 1, &weight) || !weight) {
                        json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                        route_error(error, error_len,
                                    "members must contain positive integer weights");
                        goto invalid_result;
                    }
                }
                if (value && (!json_object_is_type(value, json_type_int) ||
                              (member && (!member_wan ||
                               json_object_get_int64(value) !=
                               json_object_get_int64(member_wan))))) {
                    json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                    route_error(error, error_len, "members must match wan_ids in order");
                    goto invalid_result;
                }
                if (!value)
                    value = member_wan;
                if (!value || !json_object_is_type(value, json_type_int) ||
                    (wan_id = json_object_get_int64(value)) <= 0 || wan_id > UINT8_MAX) {
                    json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                    route_error(error, error_len, "invalid WAN target id");
                    goto invalid_result;
                }
                if (!member_weights_explicit)
                    weight = wan_weights_by_id[wan_id] ? wan_weights_by_id[wan_id] : 1;
                if (rule_member_seen[wan_id]) {
                    json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                    route_error(error, error_len, "duplicate WAN target id");
                    goto invalid_result;
                }
                rule_member_seen[wan_id] = 1;
                if (wan_ids_seen[wan_id]) {
                    json_object_array_add(out_ids, json_object_new_int64(wan_id));
                    {
                        struct json_object *canonical_member = json_object_new_object();
                        if (!canonical_member) {
                            json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                            if (out_stale_ids) json_object_put(out_stale_ids);
                            goto nomem;
                        }
                        json_object_object_add(canonical_member, "wan_id", json_object_new_int64(wan_id));
                        json_object_object_add(canonical_member, "weight", json_object_new_int64(weight));
                        json_object_array_add(out_members, canonical_member);
                    }
                } else {
                    if (!out_stale_ids && !(out_stale_ids = json_object_new_array())) {
                        json_object_put(out); json_object_put(out_ids); json_object_put(out_members);
                        goto nomem;
                    }
                    json_object_array_add(out_stale_ids, json_object_new_int64(wan_id));
                }
            }
        }
        {
            uint32_t gcd = 0;
            int k;
            for (k = 0; k < json_object_array_length(out_members); k++) {
                struct json_object *member = json_object_array_get_idx(out_members, k);
                uint32_t weight = (uint32_t)json_object_get_int64(
                    json_object_object_get(member, "weight"));
                gcd = gcd ? route_gcd_u32(gcd, weight) : weight;
            }
            if (!gcd) gcd = 1;
            for (k = 0; k < json_object_array_length(out_members); k++) {
                struct json_object *member = json_object_array_get_idx(out_members, k);
                uint32_t weight = (uint32_t)json_object_get_int64(
                    json_object_object_get(member, "weight"));
                json_object_object_del(member, "weight");
                json_object_object_add(member, "weight", json_object_new_int64(weight / gcd));
            }
            /* Canonical storage keeps only the simplest integer ratio. */
            json_object_object_add(out, "weight_ratio_gcd", json_object_new_int64(1));
            {
                char ratio[128] = "";
                size_t off = 0;
                for (k = 0; k < json_object_array_length(out_members); k++) {
                    struct json_object *member = json_object_array_get_idx(out_members, k);
                    uint32_t weight = (uint32_t)json_object_get_int64(
                        json_object_object_get(member, "weight"));
                    off += snprintf(ratio + off, sizeof(ratio) - off, "%s%u",
                                    k ? ":" : "", weight);
                }
                json_object_object_add(out, "weight_ratio", json_object_new_string(ratio));
            }
        }
        /*
         * A rule that named lines explicitly is not carrier-matched just because
         * every line it named is gone: rejecting it would block the write, and
         * the members are still recorded.  It applies no route until a line comes
         * back, which is what the kernel already does with a missing WAN.
         */
        if (enabled && json_object_array_length(out_ids) == 0 &&
            !route_rule_has_stale_member(rule, out_stale_ids, wan_ids_seen) &&
            route_carrier_id(carrier) <= JMX_CARRIER_ANY) {
            json_object_put(out); json_object_put(out_ids);
            json_object_put(out_members);
            if (out_stale_ids) json_object_put(out_stale_ids);
            route_error(error, error_len,
                        "enabled rule without WAN targets must match a carrier");
            goto invalid_result;
        }
        json_object_object_add(out, "name", json_object_new_string(name));
        json_object_object_add(out, "policy_id", json_object_new_string(policy_id));
        if (fallback_policy_id[0])
            json_object_object_add(out, "fallback_policy_id", json_object_new_string(fallback_policy_id));
        json_object_object_add(out, "enabled", json_object_new_int64(enabled));
        json_object_object_add(out, "prio", json_object_new_int64(prio));
        json_object_object_add(out, "appid", json_object_new_int64(appid));
        if (carrier[0]) json_object_object_add(out, "carrier", json_object_new_string(carrier));
        json_object_object_add(out, "proto", json_object_new_string(proto));
        if (src_addr[0]) json_object_object_add(out, "src_addr", json_object_new_string(src_addr));
        if (src_mask[0]) json_object_object_add(out, "src_mask", json_object_new_string(src_mask));
        if (dst_addr[0]) json_object_object_add(out, "dst_addr", json_object_new_string(dst_addr));
        if (dst_mask[0]) json_object_object_add(out, "dst_mask", json_object_new_string(dst_mask));
        json_object_object_add(out, "dst_port", json_object_new_int64(dst_port));
        json_object_object_add(out, "created_at", json_object_new_int64(created_at));
        json_object_object_add(out, "updated_at", json_object_new_int64(updated_at));
        json_object_object_add(out, "smart_path_mode",
                               json_object_new_string(smart_path_mode));
        json_object_object_add(out, "adaptive_penalty_sticky",
                               json_object_new_boolean(adaptive_penalty_sticky));
        json_object_object_add(out, "base_mode",
                               json_object_new_string(route_mode_algorithm(mode)));
        if (json_object_object_get_ex(rule, "legacy_mode", &smart_path) &&
            smart_path && json_object_is_type(smart_path, json_type_string) &&
            json_object_get_string(smart_path)[0]) {
            legacy_mode = json_object_get_string(smart_path);
            migration_required = 1;
        }
        if (json_object_object_get_ex(rule, "migration_required", &smart_path) &&
            smart_path && json_object_is_type(smart_path, json_type_boolean) &&
            json_object_get_boolean(smart_path))
            migration_required = 1;
        if (legacy_mode[0])
            json_object_object_add(out, "legacy_mode",
                                   json_object_new_string(legacy_mode));
        json_object_object_add(out, "migration_required",
                               json_object_new_boolean(migration_required));
        json_object_object_add(out, "reinstate_dangling",
                               json_object_new_int64(reinstate_dangling));
        json_object_object_add(out, "sticky_mode", json_object_new_string(route_mode_algorithm(mode)));
        json_object_object_add(out, "algorithm", json_object_new_string(route_mode_algorithm(mode)));
        json_object_object_add(out, "wan_ids", out_ids);
        json_object_object_add(out, "members", out_members);
        json_object_object_add(out, "member_weights_explicit",
                               json_object_new_int64(member_weights_explicit));
        json_object_object_add(out, "weight_source", json_object_new_string(
            member_weights_explicit ? "policy_member" : "global_wan"));
        /*
         * Carry stale members through the canonical copy so a read-modify-write
         * cycle preserves them.  This validator rebuilds each rule from a fixed
         * field list, so anything not copied here is dropped -- and because the
         * writer replaces the whole table, dropping them would quietly delete
         * rows during an unrelated edit.  They are still validated as ids.
         */
        {
            struct json_object *stale = NULL;

            if (json_object_object_get_ex(rule, "dangling_wan_ids", &stale) &&
                json_object_is_type(stale, json_type_array) &&
                json_object_array_length(stale) > 0) {
                for (j = 0; j < (int)json_object_array_length(stale); j++) {
                    struct json_object *value = json_object_array_get_idx(stale, j);
                    int64_t wan_id;

                    if (!value || !json_object_is_type(value, json_type_int) ||
                        (wan_id = json_object_get_int64(value)) <= 0 ||
                        wan_id > UINT8_MAX) {
                        json_object_put(out);
                        if (out_stale_ids) json_object_put(out_stale_ids);
                        route_error(error, error_len, "invalid stale WAN target id");
                        goto invalid_result;
                    }
                    if (rule_member_seen[wan_id])
                        continue;
                    rule_member_seen[wan_id] = 1;
                    /*
                     * A stale id that names a line present in this payload has
                     * been restored, and the export will report it as live; keep
                     * it out of the stale list so canonical matches readback.
                     */
                    if (wan_ids_seen[wan_id]) {
                        struct json_object *canonical_member = json_object_new_object();

                        if (!canonical_member) {
                            json_object_put(out);
                            if (out_stale_ids) json_object_put(out_stale_ids);
                            goto nomem;
                        }
                        json_object_object_add(canonical_member, "wan_id",
                                               json_object_new_int64(wan_id));
                        json_object_object_add(canonical_member, "weight",
                            json_object_new_int64(wan_weights_by_id[wan_id] ?
                                                  wan_weights_by_id[wan_id] : 1));
                        json_object_array_add(out_ids, json_object_new_int64(wan_id));
                        json_object_array_add(out_members, canonical_member);
                        continue;
                    }
                    if (!out_stale_ids && !(out_stale_ids = json_object_new_array())) {
                        json_object_put(out);
                        goto nomem;
                    }
                    json_object_array_add(out_stale_ids, json_object_new_int64(wan_id));
                }
            }
            if (out_stale_ids && json_object_array_length(out_stale_ids) > 0)
                json_object_object_add(out, "dangling_wan_ids", out_stale_ids);
            else if (out_stale_ids)
                json_object_put(out_stale_ids);
            out_stale_ids = NULL;
        }
        {
            char ratio[128] = "";
            size_t off = 0;

            for (j = 0; j < (int)json_object_array_length(out_members); j++) {
                struct json_object *member = json_object_array_get_idx(out_members, j);
                uint32_t weight = (uint32_t)json_object_get_int64(
                    json_object_object_get(member, "weight"));

                off += snprintf(ratio + off, sizeof(ratio) - off, "%s%u",
                                j ? ":" : "", weight);
            }
            json_object_object_del(out, "weight_ratio_gcd");
            json_object_object_add(out, "weight_ratio_gcd", json_object_new_int64(1));
            json_object_object_del(out, "weight_ratio");
            json_object_object_add(out, "weight_ratio", json_object_new_string(ratio));
        }
        /*
         * Mirror route_read_config() exactly: an explicit member set that lost
         * every line it named reports explicit_unresolved, not auto_carrier.
         */
        json_object_object_add(out, "wan_selection", json_object_new_string(
            json_object_array_length(out_ids) > 0 ? "explicit" :
            (json_object_object_get(out, "dangling_wan_ids") ? "explicit_unresolved"
                                                            : "auto_carrier")));
        json_object_array_add(out_rules, out);
    }

    if (route_policy_graph_validate(out_rules, error, error_len) != 0)
        goto invalid_result;

    for (i = 0; prefixes && i < json_object_array_length(prefixes); i++) {
        struct json_object *prefix = json_object_array_get_idx(prefixes, i);
        struct json_object *out = json_object_new_object();
        const char *carrier = route_json_string(prefix, "carrier", "");
        const char *cidr = route_json_string(prefix, "cidr", "");

        if (!prefix || !json_object_is_type(prefix, json_type_object) || !out ||
            !route_string_ok(carrier, 32) || route_carrier_id(carrier) <= 0 ||
            !route_string_ok(cidr, 64) || !route_cidr_ok(cidr)) {
            if (out) json_object_put(out);
            route_error(error, error_len, "invalid carrier prefix");
            goto invalid_result;
        }
        json_object_object_add(out, "carrier", json_object_new_string(carrier));
        json_object_object_add(out, "cidr", json_object_new_string(cidr));
        json_object_array_add(out_prefixes, out);
    }
    route_add_counts(result);
    *canonical = result;
    return 0;

nomem:
    route_error(error, error_len, "out of memory");
    errno = ENOMEM;
invalid_result:
    if (result) json_object_put(result);
    return -1;
invalid:
    errno = EINVAL;
    return -1;
}

static int route_replace_tables(sqlite3 *db, struct json_object *config)
{
    struct json_object *wans = NULL, *rules = NULL, *prefixes = NULL;
    sqlite3_stmt *stmt = NULL;
    int i, rc = -1;

    if (route_exec(db, "DELETE FROM route_rule_wan;DELETE FROM route_rule;"
                       "DELETE FROM route_wan;DELETE FROM route_carrier_prefix;"
                       "DELETE FROM route_global;") != 0)
        return -1;
    if (route_prepare(db, &stmt,
        "INSERT INTO route_global(id,enabled,all_down_action,dangling_wan_policy)"
        " VALUES(1,1,?1,?2)") != 0)
        return -1;
    sqlite3_bind_text(stmt, 1, route_json_string(config, "all_down_action", "main_route"),
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, route_json_string(config, "dangling_wan_policy",
                                                 "reinstate_registered"),
                      -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt = NULL;

    json_object_object_get_ex(config, "wans", &wans);
    if (route_prepare(db, &stmt,
        "INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id,gateway,health,weight,"
        "check_enable,failover,failback,fail_threshold,recover_threshold,health_mode,check_host,check_url)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)") != 0)
        goto done;
    for (i = 0; wans && i < json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);
        uint32_t id = (uint32_t)json_object_get_int64(json_object_object_get(wan, "id"));
        uint32_t mark = 0;
        route_json_mark(wan, "fwmark", 0x10000U + id, &mark);
        sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
        sqlite3_bind_int64(stmt, 1, id); sqlite3_bind_int(stmt, 2, i);
        sqlite3_bind_text(stmt, 3, route_json_string(wan, "name", "wan"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, route_json_string(wan, "ifname", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, mark);
        sqlite3_bind_int64(stmt, 6, json_object_get_int64(json_object_object_get(wan, "table")));
        sqlite3_bind_text(stmt, 7, route_json_string(wan, "gateway", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 8, json_object_get_int(json_object_object_get(wan, "health")));
        sqlite3_bind_int64(stmt, 9, json_object_get_int64(json_object_object_get(wan, "weight")));
        sqlite3_bind_int(stmt, 10, json_object_get_int(json_object_object_get(wan, "check_enable")));
        sqlite3_bind_int(stmt, 11, json_object_get_int(json_object_object_get(wan, "failover")));
        sqlite3_bind_int(stmt, 12, json_object_get_int(json_object_object_get(wan, "failback")));
        sqlite3_bind_int(stmt, 13, json_object_get_int(json_object_object_get(wan, "fail_threshold")));
        sqlite3_bind_int(stmt, 14, json_object_get_int(json_object_object_get(wan, "recover_threshold")));
        sqlite3_bind_text(stmt, 15, route_json_string(wan, "health_mode", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 16, route_json_string(wan, "check_host", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 17, route_json_string(wan, "check_url", ""), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
    }
    sqlite3_finalize(stmt); stmt = NULL;

    json_object_object_get_ex(config, "rules", &rules);
    if (route_prepare(db, &stmt,
        "INSERT INTO route_rule(rule_id,position,name,enabled,prio,appid,carrier,proto,src_addr,"
        "src_mask,dst_addr,dst_mask,dst_port,sticky_mode,reinstate_dangling,policy_id,fallback_policy_id,"
        "member_weights_explicit,created_at,updated_at,smart_path_mode,adaptive_penalty_sticky,"
        "legacy_mode,migration_required)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)") != 0)
        goto done;
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        int adaptive_penalty = 0;
        int migration_required = 0;
        sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
        sqlite3_bind_int(stmt, 1, i + 1); sqlite3_bind_int(stmt, 2, i);
        sqlite3_bind_text(stmt, 3, route_json_string(rule, "name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, json_object_get_int(json_object_object_get(rule, "enabled")));
        sqlite3_bind_int(stmt, 5, json_object_get_int(json_object_object_get(rule, "prio")));
        sqlite3_bind_int64(stmt, 6, json_object_get_int64(json_object_object_get(rule, "appid")));
        sqlite3_bind_text(stmt, 7, route_json_string(rule, "carrier", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, route_json_string(rule, "proto", "any"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, route_json_string(rule, "src_addr", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, route_json_string(rule, "src_mask", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, route_json_string(rule, "dst_addr", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 12, route_json_string(rule, "dst_mask", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 13, json_object_get_int(json_object_object_get(rule, "dst_port")));
        sqlite3_bind_text(stmt, 14, route_json_string(rule, "sticky_mode", "hash_src"), -1, SQLITE_TRANSIENT);
        {
            struct json_object *flag = NULL;
            int reinstate = 1;

            if (json_object_object_get_ex(rule, "reinstate_dangling", &flag))
                reinstate = json_object_get_int(flag) ? 1 : 0;
            sqlite3_bind_int(stmt, 15, reinstate);
        }
        sqlite3_bind_text(stmt, 16, route_json_string(rule, "policy_id", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 17, route_json_string(rule, "fallback_policy_id", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 18, json_object_get_boolean(
            json_object_object_get(rule, "member_weights_explicit")) ? 1 : 0);
        sqlite3_bind_int64(stmt, 19, json_object_get_int64(
            json_object_object_get(rule, "created_at")));
        sqlite3_bind_int64(stmt, 20, json_object_get_int64(
            json_object_object_get(rule, "updated_at")));
        sqlite3_bind_text(stmt, 21, route_json_string(rule, "smart_path_mode", "inherit"),
                          -1, SQLITE_TRANSIENT);
        if (route_json_bool(rule, "adaptive_penalty_sticky", 0,
                            &adaptive_penalty) != 0 ||
            route_json_bool(rule, "migration_required", 0,
                            &migration_required) != 0)
            goto done;
        sqlite3_bind_int(stmt, 22, adaptive_penalty ? 1 : 0);
        sqlite3_bind_text(stmt, 23, route_json_string(rule, "legacy_mode", ""),
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 24, migration_required ? 1 : 0);
        if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
    }
    sqlite3_finalize(stmt); stmt = NULL;

    if (route_prepare(db, &stmt,
        "INSERT INTO route_rule_wan(rule_id,position,wan_id,weight) VALUES(?1,?2,?3,?4)") != 0)
        goto done;
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i), *ids = NULL, *members = NULL;
        struct json_object *stale = NULL;
        uint8_t member_seen[256] = {0};
        int j, position = 0;
        json_object_object_get_ex(rule, "wan_ids", &ids);
        json_object_object_get_ex(rule, "members", &members);
        for (j = 0; ids && j < json_object_array_length(ids); j++) {
            int member = json_object_get_int(json_object_array_get_idx(ids, j));

            if (member <= 0 || member > UINT8_MAX || member_seen[member])
                continue;
            member_seen[member] = 1;
            sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
            sqlite3_bind_int(stmt, 1, i + 1); sqlite3_bind_int(stmt, 2, position++);
            sqlite3_bind_int(stmt, 3, member);
            if (members && j < json_object_array_length(members)) {
                struct json_object *member_obj = json_object_array_get_idx(members, j);
                sqlite3_bind_int64(stmt, 4, json_object_get_int64(
                    json_object_object_get(member_obj, "weight")));
            } else {
                sqlite3_bind_int(stmt, 4, 1);
            }
            if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
        }
        /*
         * Members whose line no longer exists are carried through a
         * read-modify-write cycle rather than dropped.  route_read_config()
         * reports them in dangling_wan_ids instead of wan_ids, and this function
         * replaces the whole table, so a caller that reads the config, edits one
         * field and writes it back would otherwise delete them as a side effect
         * of an unrelated edit.  Cleaning them up has to be a deliberate
         * decision, not a by-product of changing the load-balance algorithm.
         */
        if (json_object_object_get_ex(rule, "dangling_wan_ids", &stale) &&
            json_object_is_type(stale, json_type_array)) {
            for (j = 0; j < (int)json_object_array_length(stale); j++) {
                int member = json_object_get_int(json_object_array_get_idx(stale, j));

                if (member <= 0 || member > UINT8_MAX || member_seen[member])
                    continue;
                member_seen[member] = 1;
                sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
                sqlite3_bind_int(stmt, 1, i + 1); sqlite3_bind_int(stmt, 2, position++);
                sqlite3_bind_int(stmt, 3, member);
                sqlite3_bind_int(stmt, 4, 1);
                if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
            }
        }
    }
    sqlite3_finalize(stmt); stmt = NULL;

    json_object_object_get_ex(config, "carrier_prefixes", &prefixes);
    if (route_prepare(db, &stmt,
        "INSERT INTO route_carrier_prefix(position,carrier,cidr) VALUES(?1,?2,?3)") != 0)
        goto done;
    for (i = 0; prefixes && i < json_object_array_length(prefixes); i++) {
        struct json_object *prefix = json_object_array_get_idx(prefixes, i);
        sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
        sqlite3_bind_int(stmt, 1, i);
        sqlite3_bind_text(stmt, 2, route_json_string(prefix, "carrier", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, route_json_string(prefix, "cidr", ""), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
    }
    rc = 0;
done:
    if (rc != 0) {
        fprintf(stderr, "jmx_route_db: replace failed: %s\n", sqlite3_errmsg(db));
        errno = EIO;
    }
    sqlite3_finalize(stmt);
    return rc;
}

static void route_add_sql_text(struct json_object *object, const char *key,
                               sqlite3_stmt *stmt, int column)
{
    const char *value = (const char *)sqlite3_column_text(stmt, column);
    if (value && value[0])
        json_object_object_add(object, key, json_object_new_string(value));
}

static int route_read_config(sqlite3 *db, struct json_object **out)
{
    struct json_object *config = json_object_new_object();
    struct json_object *wans = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    struct json_object *prefixes = json_object_new_array();
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (!out || !config || !wans || !rules || !prefixes)
        goto fail;
    json_object_object_add(config, "wans", wans);
    json_object_object_add(config, "rules", rules);
    json_object_object_add(config, "carrier_prefixes", prefixes);
    json_object_object_add(config, "all_down_action", json_object_new_string("main_route"));
    json_object_object_add(config, "dangling_wan_policy",
                           json_object_new_string("reinstate_registered"));

    if (route_prepare(db, &stmt,
        "SELECT all_down_action,dangling_wan_policy FROM route_global WHERE id=1") != 0)
        goto fail;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *action = (const char *)sqlite3_column_text(stmt, 0);
        const char *policy = (const char *)sqlite3_column_text(stmt, 1);

        json_object_object_del(config, "all_down_action");
        json_object_object_add(config, "all_down_action",
                               json_object_new_string(action ? action : "main_route"));
        json_object_object_del(config, "dangling_wan_policy");
        json_object_object_add(config, "dangling_wan_policy",
            json_object_new_string(route_dangling_policy_ok(policy) ? policy
                                                                   : "reinstate_registered"));
    }
    sqlite3_finalize(stmt); stmt = NULL;

    if (route_prepare(db, &stmt,
        "SELECT id,name,ifname,fwmark,table_id,gateway,health,weight,check_enable,failover,failback,"
        "fail_threshold,recover_threshold,health_mode,check_host,check_url FROM route_wan ORDER BY position") != 0)
        goto fail;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        struct json_object *wan = json_object_new_object();
        char mark[16];
        json_object_object_add(wan, "id", json_object_new_int64(sqlite3_column_int64(stmt, 0)));
        json_object_object_add(wan, "name", json_object_new_string((const char *)sqlite3_column_text(stmt, 1)));
        route_add_sql_text(wan, "ifname", stmt, 2);
        snprintf(mark, sizeof(mark), "0x%x", (uint32_t)sqlite3_column_int64(stmt, 3));
        json_object_object_add(wan, "fwmark", json_object_new_string(mark));
        json_object_object_add(wan, "table", json_object_new_int64(sqlite3_column_int64(stmt, 4)));
        route_add_sql_text(wan, "gateway", stmt, 5);
        json_object_object_add(wan, "health", json_object_new_int(sqlite3_column_int(stmt, 6)));
        json_object_object_add(wan, "weight", json_object_new_int64(sqlite3_column_int64(stmt, 7)));
        json_object_object_add(wan, "check_enable", json_object_new_int(sqlite3_column_int(stmt, 8)));
        json_object_object_add(wan, "failover", json_object_new_int(sqlite3_column_int(stmt, 9)));
        json_object_object_add(wan, "failback", json_object_new_int(sqlite3_column_int(stmt, 10)));
        json_object_object_add(wan, "fail_threshold", json_object_new_int(sqlite3_column_int(stmt, 11)));
        json_object_object_add(wan, "recover_threshold", json_object_new_int(sqlite3_column_int(stmt, 12)));
        route_add_sql_text(wan, "health_mode", stmt, 13);
        route_add_sql_text(wan, "check_host", stmt, 14);
        route_add_sql_text(wan, "check_url", stmt, 15);
        json_object_array_add(wans, wan);
    }
    if (rc != SQLITE_DONE) goto fail;
    sqlite3_finalize(stmt); stmt = NULL;

    if (route_prepare(db, &stmt,
        "SELECT rule_id,name,enabled,prio,appid,carrier,proto,src_addr,src_mask,dst_addr,dst_mask,"
        "dst_port,sticky_mode,reinstate_dangling,policy_id,fallback_policy_id,member_weights_explicit,"
        "created_at,updated_at,smart_path_mode,adaptive_penalty_sticky,legacy_mode,migration_required "
        "FROM route_rule ORDER BY position") != 0)
        goto fail;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        struct json_object *rule = json_object_new_object(), *ids = json_object_new_array();
        struct json_object *members = json_object_new_array();
        struct json_object *dangling = json_object_new_array();
        sqlite3_stmt *wan_stmt = NULL;
        uint8_t member_seen[256] = {0};
        const char *mode = (const char *)sqlite3_column_text(stmt, 12);
        int mode_id = route_mode_id(mode);
        int rule_id = sqlite3_column_int(stmt, 0);
        const char *policy_id = (const char *)sqlite3_column_text(stmt, 14);
        const char *fallback_policy_id = (const char *)sqlite3_column_text(stmt, 15);
        int member_weights_explicit = sqlite3_column_int(stmt, 16) ? 1 : 0;
        char generated_policy_id[64];
        uint32_t gcd = 0;
        char ratio[128] = "";
        size_t ratio_off = 0;
        if (!rule || !ids || !members || !dangling) {
            if (rule) json_object_put(rule);
            if (ids) json_object_put(ids);
            if (members) json_object_put(members);
            if (dangling) json_object_put(dangling);
            goto fail;
        }
        json_object_object_add(rule, "name", json_object_new_string((const char *)sqlite3_column_text(stmt, 1)));
        if (!policy_id || !policy_id[0]) {
            snprintf(generated_policy_id, sizeof(generated_policy_id), "route-policy-%u",
                     (unsigned)sqlite3_column_int(stmt, 3));
            policy_id = generated_policy_id;
        }
        json_object_object_add(rule, "policy_id", json_object_new_string(policy_id));
        if (fallback_policy_id && fallback_policy_id[0])
            json_object_object_add(rule, "fallback_policy_id",
                                   json_object_new_string(fallback_policy_id));
        json_object_object_add(rule, "enabled", json_object_new_int(sqlite3_column_int(stmt, 2)));
        json_object_object_add(rule, "prio", json_object_new_int(sqlite3_column_int(stmt, 3)));
        json_object_object_add(rule, "appid", json_object_new_int64(sqlite3_column_int64(stmt, 4)));
        route_add_sql_text(rule, "carrier", stmt, 5);
        json_object_object_add(rule, "proto", json_object_new_string((const char *)sqlite3_column_text(stmt, 6)));
        route_add_sql_text(rule, "src_addr", stmt, 7); route_add_sql_text(rule, "src_mask", stmt, 8);
        route_add_sql_text(rule, "dst_addr", stmt, 9); route_add_sql_text(rule, "dst_mask", stmt, 10);
        json_object_object_add(rule, "dst_port", json_object_new_int(sqlite3_column_int(stmt, 11)));
        json_object_object_add(rule, "member_weights_explicit",
                               json_object_new_int(member_weights_explicit));
        json_object_object_add(rule, "weight_source", json_object_new_string(
            member_weights_explicit ? "policy_member" : "global_wan"));
        json_object_object_add(rule, "created_at",
                               json_object_new_int64(sqlite3_column_int64(stmt, 17)));
        json_object_object_add(rule, "updated_at",
                               json_object_new_int64(sqlite3_column_int64(stmt, 18)));
        json_object_object_add(rule, "smart_path_mode", json_object_new_string(
            sqlite3_column_text(stmt, 19) && ((const char *)sqlite3_column_text(stmt, 19))[0] ?
            (const char *)sqlite3_column_text(stmt, 19) : "inherit"));
        json_object_object_add(rule, "adaptive_penalty_sticky",
                               json_object_new_boolean(sqlite3_column_int(stmt, 20) ? 1 : 0));
        json_object_object_add(rule, "base_mode", json_object_new_string(
            route_mode_algorithm(mode_id) ? route_mode_algorithm(mode_id) : "hash_src"));
        if (sqlite3_column_text(stmt, 21) &&
            ((const char *)sqlite3_column_text(stmt, 21))[0])
            json_object_object_add(rule, "legacy_mode", json_object_new_string(
                (const char *)sqlite3_column_text(stmt, 21)));
        json_object_object_add(rule, "migration_required", json_object_new_boolean(
            sqlite3_column_int(stmt, 22) ? 1 : 0));
        json_object_object_add(rule, "reinstate_dangling",
                               json_object_new_int(sqlite3_column_int(stmt, 13) ? 1 : 0));
        json_object_object_add(rule, "sticky_mode", json_object_new_string(mode ? mode : "hash_src"));
        json_object_object_add(rule, "algorithm",
                               json_object_new_string(route_mode_algorithm(mode_id) ?
                                                      route_mode_algorithm(mode_id) : "hash_src"));
        if (route_prepare(db, &wan_stmt,
            "SELECT rw.wan_id,rw.weight,w.weight FROM route_rule_wan rw "
            "LEFT JOIN route_wan w ON w.id=rw.wan_id "
            "WHERE rw.rule_id=?1 ORDER BY rw.position") != 0) {
            json_object_put(rule); json_object_put(ids); json_object_put(members);
            json_object_put(dangling);
            goto fail;
        }
        sqlite3_bind_int(wan_stmt, 1, rule_id);
        /*
         * route_rule_wan.wan_id carries only a range CHECK, no foreign key into
         * route_wan(id), so a member can outlive the line it names: dropping a
         * WAN leaves the reference behind. Kernel selection ignores a WAN that
         * does not exist, so routing is unaffected, but exporting the raw list
         * makes the UI draw lines that are not there -- and if a future WAN
         * reuses that id, the stale member would suddenly take effect.
         *
         * Members are therefore split rather than silently dropped:
         * wan_ids holds the ones that resolve, dangling_wan_ids reports the
         * rest. "The API says they are gone while the database still has them"
         * would just be a different inconsistency.
         */
        while ((rc = sqlite3_step(wan_stmt)) == SQLITE_ROW) {
            int member = sqlite3_column_int(wan_stmt, 0);
            int live_member = sqlite3_column_type(wan_stmt, 2) != SQLITE_NULL;
            uint32_t weight = (uint32_t)sqlite3_column_int64(
                wan_stmt, member_weights_explicit || !live_member ? 1 : 2);
            struct json_object *member_obj;

            if (!weight) weight = 1;
            member_obj = json_object_new_object();
            if (!member_obj) {
                sqlite3_finalize(wan_stmt);
                json_object_put(rule); json_object_put(ids); json_object_put(members);
                json_object_put(dangling);
                goto fail;
            }
            json_object_object_add(member_obj, "wan_id", json_object_new_int(member));
            json_object_object_add(member_obj, "weight", json_object_new_int64(weight));

            if (member <= 0 || member > UINT8_MAX || member_seen[member]) {
                json_object_put(member_obj);
                continue;
            }
            member_seen[member] = 1;
            if (live_member) {
                json_object_array_add(ids, json_object_new_int(member));
                json_object_array_add(members, member_obj);
                gcd = gcd ? route_gcd_u32(gcd, weight) : weight;
            } else {
                json_object_array_add(dangling, json_object_new_int(member));
                json_object_put(member_obj);
            }
        }
        sqlite3_finalize(wan_stmt);
        if (rc != SQLITE_DONE) {
            json_object_put(rule); json_object_put(ids); json_object_put(members);
            json_object_put(dangling);
            goto fail;
        }
        json_object_object_add(rule, "wan_ids", ids);
        json_object_object_add(rule, "members", members);
        if (!gcd) gcd = 1;
        for (int k = 0; k < json_object_array_length(members); k++) {
            struct json_object *member_obj = json_object_array_get_idx(members, k);
            uint32_t weight = (uint32_t)json_object_get_int64(
                json_object_object_get(member_obj, "weight"));
            json_object_object_del(member_obj, "weight");
            json_object_object_add(member_obj, "weight", json_object_new_int64(weight / gcd));
            ratio_off += snprintf(ratio + ratio_off, sizeof(ratio) - ratio_off, "%s%u",
                                  k ? ":" : "", weight / gcd);
        }
        json_object_object_add(rule, "weight_ratio_gcd", json_object_new_int64(1));
        json_object_object_add(rule, "weight_ratio", json_object_new_string(ratio));
        if (json_object_array_length(dangling) > 0)
            json_object_object_add(rule, "dangling_wan_ids", dangling);
        else
            json_object_put(dangling);
        /*
         * An explicit member set that has lost every line it named must not be
         * reclassified as auto_carrier: that would report operator-based
         * selection for a rule the user pinned to specific lines.
         */
        json_object_object_add(rule, "wan_selection", json_object_new_string(
            json_object_array_length(ids) > 0 ? "explicit" :
            (json_object_object_get(rule, "dangling_wan_ids") ? "explicit_unresolved"
                                                             : "auto_carrier")));
        json_object_array_add(rules, rule);
    }
    if (rc != SQLITE_DONE) goto fail;
    sqlite3_finalize(stmt); stmt = NULL;

    if (route_prepare(db, &stmt,
        "SELECT carrier,cidr FROM route_carrier_prefix ORDER BY position") != 0)
        goto fail;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        struct json_object *prefix = json_object_new_object();
        json_object_object_add(prefix, "carrier", json_object_new_string((const char *)sqlite3_column_text(stmt, 0)));
        json_object_object_add(prefix, "cidr", json_object_new_string((const char *)sqlite3_column_text(stmt, 1)));
        json_object_array_add(prefixes, prefix);
    }
    if (rc != SQLITE_DONE) goto fail;
    sqlite3_finalize(stmt);
    route_add_counts(config);
    *out = config;
    return 0;
fail:
    sqlite3_finalize(stmt);
    if (config) json_object_put(config);
    else { if (wans) json_object_put(wans); if (rules) json_object_put(rules); if (prefixes) json_object_put(prefixes); }
    errno = errno ? errno : EIO;
    return -1;
}

static const char *route_uci_opt(struct uci_section *section, const char *name)
{
    struct uci_option *option;
    if (!section) return NULL;
    option = uci_lookup_option(section->package->ctx, section, name);
    return option && option->type == UCI_TYPE_STRING ? option->v.string : NULL;
}

static uint32_t route_uci_u32(struct uci_section *section, const char *name, uint32_t def)
{
    const char *value = route_uci_opt(section, name);
    char *end = NULL;
    unsigned long long number;
    if (!value || !value[0] || value[0] == '-') return def;
    errno = 0; number = strtoull(value, &end, 0);
    return errno || end == value || *end || number > UINT32_MAX ? def : (uint32_t)number;
}

static struct json_object *route_uci_wan_ids(struct uci_section *section)
{
    struct json_object *ids = json_object_new_array();
    struct uci_option *option = uci_lookup_option(section->package->ctx, section, "wan_ids");
    struct uci_element *element;
    if (!option) option = uci_lookup_option(section->package->ctx, section, "wans");
    if (!option) return ids;
    if (option->type == UCI_TYPE_LIST) {
        uci_foreach_element(&option->v.list, element)
            json_object_array_add(ids, json_object_new_int((int)strtoul(element->name, NULL, 0)));
    } else if (option->type == UCI_TYPE_STRING && option->v.string) {
        const char *p = option->v.string;
        while (*p) {
            char *end = NULL; unsigned long number;
            while (*p == ' ' || *p == ',' || *p == '\t') p++;
            if (!*p) break;
            number = strtoul(p, &end, 0); if (end == p) break;
            json_object_array_add(ids, json_object_new_int((int)number)); p = end;
        }
    }
    return ids;
}

static void route_uci_add_string(struct json_object *object, const char *key,
                                 struct uci_section *section, const char *option)
{
    const char *value = route_uci_opt(section, option);
    if (value && value[0]) json_object_object_add(object, key, json_object_new_string(value));
}

static struct json_object *route_legacy_payload(int *source_rows)
{
    struct uci_context *context = uci_alloc_context();
    struct uci_package *package = NULL;
    struct uci_element *element;
    struct json_object *payload = json_object_new_object();
    struct json_object *wans = json_object_new_array(), *rules = json_object_new_array();
    struct json_object *prefixes = json_object_new_array();
    int rows = 0;

    if (!payload || !wans || !rules || !prefixes || !context) goto fail;
    json_object_object_add(payload, "wans", wans); json_object_object_add(payload, "rules", rules);
    json_object_object_add(payload, "carrier_prefixes", prefixes);
    json_object_object_add(payload, "all_down_action", json_object_new_string("main_route"));
    /* Legacy /etc/config/jmx_route predates the switch, so the import lands on
     * the default. route_validate_payload() would supply the same value; stating
     * it here keeps the legacy payload readable next to the canonical one. */
    json_object_object_add(payload, "dangling_wan_policy",
                           json_object_new_string("reinstate_registered"));
    if (uci_load(context, "jmx_route", &package) != UCI_OK)
        goto done;
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (!strcmp(section->type, "global")) {
            const char *action = route_uci_opt(section, "all_down_action");
            if (action && action[0]) {
                json_object_object_del(payload, "all_down_action");
                json_object_object_add(payload, "all_down_action", json_object_new_string(action));
            }
            rows++;
        } else if (!strcmp(section->type, "wan")) {
            struct json_object *wan = json_object_new_object();
            uint32_t id = route_uci_u32(section, "id", 0);
            const char *name = route_uci_opt(section, "name");
            json_object_object_add(wan, "id", json_object_new_int64(id));
            json_object_object_add(wan, "name", json_object_new_string(name && name[0] ? name : section->e.name));
            route_uci_add_string(wan, "ifname", section, "ifname");
            route_uci_add_string(wan, "fwmark", section, "fwmark");
            json_object_object_add(wan, "table", json_object_new_int64(route_uci_u32(section, "table", 100 + id)));
            route_uci_add_string(wan, "gateway", section, "gateway");
            json_object_object_add(wan, "health", json_object_new_int64(route_uci_u32(section, "health", 1)));
            json_object_object_add(wan, "weight", json_object_new_int64(route_uci_u32(section, "weight", 1)));
            json_object_object_add(wan, "check_enable", json_object_new_int64(route_uci_u32(section, "check_enable", 0)));
            json_object_object_add(wan, "failover", json_object_new_int64(route_uci_u32(section, "failover", 1)));
            json_object_object_add(wan, "failback", json_object_new_int64(route_uci_u32(section, "failback", 1)));
            json_object_object_add(wan, "fail_threshold", json_object_new_int64(route_uci_u32(section, "fail_threshold", ROUTE_HEALTH_FAIL_DEFAULT)));
            json_object_object_add(wan, "recover_threshold", json_object_new_int64(route_uci_u32(section, "recover_threshold", ROUTE_HEALTH_RECOVER_DEFAULT)));
            route_uci_add_string(wan, "health_mode", section, "health_mode");
            route_uci_add_string(wan, "check_host", section, "check_host");
            route_uci_add_string(wan, "check_url", section, "check_url");
            json_object_array_add(wans, wan); rows++;
        } else if (!strcmp(section->type, "rule")) {
            struct json_object *rule = json_object_new_object();
            route_uci_add_string(rule, "name", section, "name");
            json_object_object_add(rule, "enabled", json_object_new_int64(route_uci_u32(section, "enabled", 1)));
            json_object_object_add(rule, "prio", json_object_new_int64(route_uci_u32(section, "prio", 1000 + json_object_array_length(rules))));
            json_object_object_add(rule, "appid", json_object_new_int64(route_uci_u32(section, "appid", 0)));
            route_uci_add_string(rule, "carrier", section, "carrier"); route_uci_add_string(rule, "proto", section, "proto");
            route_uci_add_string(rule, "src_addr", section, "src_addr"); route_uci_add_string(rule, "src_mask", section, "src_mask");
            route_uci_add_string(rule, "dst_addr", section, "dst_addr"); route_uci_add_string(rule, "dst_mask", section, "dst_mask");
            json_object_object_add(rule, "dst_port", json_object_new_int64(route_uci_u32(section, "dst_port", 0)));
            route_uci_add_string(rule, "sticky_mode", section, "sticky_mode");
            json_object_object_add(rule, "wan_ids", route_uci_wan_ids(section));
            json_object_array_add(rules, rule); rows++;
        } else if (!strcmp(section->type, "carrier_prefix")) {
            struct json_object *prefix = json_object_new_object();
            route_uci_add_string(prefix, "carrier", section, "carrier"); route_uci_add_string(prefix, "cidr", section, "cidr");
            json_object_array_add(prefixes, prefix); rows++;
        }
    }
done:
    if (package) uci_unload(context, package);
    uci_free_context(context);
    if (source_rows) *source_rows = rows;
    return payload;
fail:
    if (package) uci_unload(context, package);
    if (context) uci_free_context(context);
    if (payload) json_object_put(payload); else { if (wans) json_object_put(wans); if (rules) json_object_put(rules); if (prefixes) json_object_put(prefixes); }
    return NULL;
}

static int route_migrate_once(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    struct json_object *legacy = NULL, *canonical = NULL, *readback = NULL;
    const char *detail;
    int existing = 0, source_rows = 0, imported_rows = 0;
    int rc = -1;
    char error[160] = "";

    if (route_exec(db, "BEGIN IMMEDIATE") != 0) return -1;
    if (route_prepare(db, &stmt,
        "SELECT 1 FROM config_migration WHERE name=?1 AND status='done'") != 0) goto done;
    sqlite3_bind_text(stmt, 1, JMX_ROUTE_UCI_MIGRATION, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) { sqlite3_finalize(stmt); stmt = NULL; rc = 0; goto done; }
    sqlite3_finalize(stmt); stmt = NULL;
    if (route_prepare(db, &stmt,
        "SELECT (SELECT count(*) FROM route_global)+(SELECT count(*) FROM route_wan)+"
        "(SELECT count(*) FROM route_rule)+(SELECT count(*) FROM route_carrier_prefix)") != 0) goto done;
    if (sqlite3_step(stmt) == SQLITE_ROW) existing = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt); stmt = NULL;
    if (existing) {
        detail = "preserved_existing_config_db_config";
    } else {
        legacy = route_legacy_payload(&source_rows);
        if (!legacy || route_validate_payload(legacy, &canonical, error, sizeof(error)) != 0 ||
            route_replace_tables(db, canonical) != 0 || route_read_config(db, &readback) != 0 ||
            !json_object_equal(canonical, readback)) {
            fprintf(stderr, "jmx_route_db: legacy import failed: %s\n", error[0] ? error : "readback mismatch");
            goto done;
        }
        imported_rows = source_rows;
        detail = access(JMX_ROUTE_LEGACY_PATH, R_OK) == 0 ? "legacy_uci_imported" : "legacy_uci_missing";
    }
    if (route_prepare(db, &stmt,
        "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail)"
        " VALUES(?1,'done','uci:/etc/config/jmx_route',?2,?3,?4)") != 0) goto done;
    sqlite3_bind_text(stmt, 1, JMX_ROUTE_UCI_MIGRATION, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, imported_rows); sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 4, detail, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt = NULL; rc = 0;
done:
    sqlite3_finalize(stmt);
    if (legacy) json_object_put(legacy); if (canonical) json_object_put(canonical); if (readback) json_object_put(readback);
    if (route_exec(db, rc == 0 ? "COMMIT" : "ROLLBACK") != 0) rc = -1;
    return rc;
}

static int route_open_ready(sqlite3 **out)
{
    sqlite3 *db = NULL;
    if (!out) { errno = EINVAL; return -1; }
    if (sqlite3_open_v2(JMX_ROUTE_DB_PATH, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db); errno = EIO; return -1;
    }
    sqlite3_busy_timeout(db, 3000);
    if (route_exec(db, route_schema_sql) != 0) {
        sqlite3_close(db); return -1;
    }
    /* Devices that created config.db before these columns shipped. Both defaults
     * reproduce the behaviour those devices already have, so an in-place upgrade
     * changes nothing observable. */
    route_add_column_if_missing(db, "route_global", "dangling_wan_policy",
                                "TEXT NOT NULL DEFAULT 'reinstate_registered'");
    route_add_column_if_missing(db, "route_rule", "reinstate_dangling",
                                "INTEGER NOT NULL DEFAULT 1");
    route_add_column_if_missing(db, "route_rule", "policy_id",
                                "TEXT NOT NULL DEFAULT ''");
    route_add_column_if_missing(db, "route_rule", "fallback_policy_id",
                                "TEXT NOT NULL DEFAULT ''");
    route_add_column_if_missing(db, "route_rule", "member_weights_explicit",
                                "INTEGER NOT NULL DEFAULT 0");
    route_add_column_if_missing(db, "route_rule", "created_at",
                                "INTEGER NOT NULL DEFAULT 0");
    route_add_column_if_missing(db, "route_rule", "updated_at",
                                "INTEGER NOT NULL DEFAULT 0");
    route_add_column_if_missing(db, "route_rule", "smart_path_mode",
                                "TEXT NOT NULL DEFAULT 'inherit'");
    route_add_column_if_missing(db, "route_rule", "adaptive_penalty_sticky",
                                "INTEGER NOT NULL DEFAULT 0");
    route_add_column_if_missing(db, "route_rule", "legacy_mode",
                                "TEXT NOT NULL DEFAULT ''");
    route_add_column_if_missing(db, "route_rule", "migration_required",
                                "INTEGER NOT NULL DEFAULT 0");
    /* Mode 9 had no separate base-selector field. Preserve its weighted
     * new-flow behaviour, expose migration state, and never guess another base. */
    if (route_exec(db,
        "UPDATE route_rule SET sticky_mode='weighted_new_flow_rr',"
        " adaptive_penalty_sticky=1,legacy_mode='adaptive_penalty_sticky',"
        " migration_required=1 WHERE sticky_mode='adaptive_penalty_sticky'") != 0) {
        sqlite3_close(db);
        return -1;
    }
    route_add_column_if_missing(db, "route_rule_wan", "weight",
                                "INTEGER NOT NULL DEFAULT 1");
    if (route_exec(db,
        "UPDATE route_rule SET policy_id='route-policy-' || prio WHERE policy_id=''") != 0) {
        sqlite3_close(db);
        return -1;
    }
    if (route_migrate_once(db) != 0) {
        sqlite3_close(db); return -1;
    }
    *out = db;
    return 0;
}

int jmx_route_db_config_get(struct json_object **config)
{
    sqlite3 *db = NULL;
    int rc;
    if (route_open_ready(&db) != 0) return -1;
    rc = route_read_config(db, config);
    sqlite3_close(db);
    return rc;
}

int jmx_route_db_config_get_readonly(struct json_object **config)
{
    sqlite3 *db = NULL;
    int rc;

    if (!config) {
        errno = EINVAL;
        return -1;
    }
    *config = NULL;
    if (sqlite3_open_v2(JMX_ROUTE_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL) !=
        SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        errno = EIO;
        return -1;
    }
    /* _route_tick runs on core's uloop thread; never wait on config writers. */
    sqlite3_busy_timeout(db, 50);
    rc = route_read_config(db, config);
    sqlite3_close(db);
    return rc;
}

int jmx_route_db_replace_begin(struct json_object *request,
                               struct jmx_route_db_tx **tx,
                               struct json_object **previous,
                               struct json_object **readback,
                               char *error, size_t error_len)
{
    struct json_object *canonical = NULL;
    struct jmx_route_db_tx *transaction = NULL;
    sqlite3 *db = NULL;

    if (!tx || !previous || !readback) { errno = EINVAL; return -1; }
    *tx = NULL; *previous = NULL; *readback = NULL;
    if (route_validate_payload(request, &canonical, error, error_len) != 0) return -1;
    if (route_open_ready(&db) != 0) goto fail;
    if (route_exec(db, "BEGIN IMMEDIATE") != 0 || route_read_config(db, previous) != 0 ||
        route_replace_tables(db, canonical) != 0 || route_read_config(db, readback) != 0 ||
        !json_object_equal(canonical, *readback)) {
        route_error(error, error_len, "config.db transactional readback mismatch");
        goto rollback;
    }
    transaction = calloc(1, sizeof(*transaction));
    if (!transaction) { errno = ENOMEM; goto rollback; }
    transaction->db = db; *tx = transaction;
    json_object_put(canonical);
    return 0;
rollback:
    route_exec(db, "ROLLBACK");
fail:
    if (db) sqlite3_close(db);
    if (*previous) { json_object_put(*previous); *previous = NULL; }
    if (*readback) { json_object_put(*readback); *readback = NULL; }
    if (canonical) json_object_put(canonical);
    return -1;
}

int jmx_route_db_replace_commit(struct jmx_route_db_tx *tx)
{
    int rc;
    if (!tx || !tx->db) { errno = EINVAL; return -1; }
    rc = route_exec(tx->db, "COMMIT");
    if (rc != 0) route_exec(tx->db, "ROLLBACK");
    sqlite3_close(tx->db); free(tx);
    return rc;
}

void jmx_route_db_replace_rollback(struct jmx_route_db_tx *tx)
{
    if (!tx) return;
    if (tx->db) { route_exec(tx->db, "ROLLBACK"); sqlite3_close(tx->db); }
    free(tx);
}
