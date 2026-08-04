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
    " all_down_action TEXT NOT NULL DEFAULT 'main_route');"
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
    " sticky_mode TEXT NOT NULL DEFAULT 'hash_src');"
    "CREATE TABLE IF NOT EXISTS route_rule_wan("
    " rule_id INTEGER NOT NULL REFERENCES route_rule(rule_id) ON DELETE CASCADE,"
    " position INTEGER NOT NULL,wan_id INTEGER NOT NULL CHECK(wan_id BETWEEN 1 AND 255),"
    " PRIMARY KEY(rule_id,position));"
    "CREATE TABLE IF NOT EXISTS route_carrier_prefix("
    " position INTEGER PRIMARY KEY,carrier TEXT NOT NULL,cidr TEXT NOT NULL);";

static void route_error(char *out, size_t out_len, const char *message)
{
    if (out && out_len)
        snprintf(out, out_len, "%s", message ? message : "route config error");
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
    errno = 0;
    number = strtoul(mode, &end, 0);
    if (errno || end == mode || *end || number > JMX_STICKY_CONN_CNT)
        return -1;
    return (int)number;
}

static const char *route_mode_algorithm(int mode)
{
    static const char *const names[] = {
        "weighted_new_flow_rr", "hash_src", "hash_src_sport", "hash_src_dst",
        "hash_src_dst_dport", "five_tuple", "primary_backup",
        "least_rx_load_normalized", "least_active_conn_normalized"
    };

    return mode >= 0 && mode <= JMX_STICKY_CONN_CNT ? names[mode] : NULL;
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

static int route_validate_payload(struct json_object *request,
                                  struct json_object **canonical,
                                  char *error, size_t error_len)
{
    struct json_object *result = NULL;
    struct json_object *wans = NULL, *rules = NULL, *prefixes = NULL, *failover = NULL;
    struct json_object *out_wans = NULL, *out_rules = NULL, *out_prefixes = NULL;
    const char *all_down_action = "main_route";
    uint8_t wan_ids_seen[256] = {0};
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
        struct json_object *wan_ids = NULL, *out_ids = json_object_new_array();
        struct json_object *out = json_object_new_object();
        uint32_t enabled, prio, appid, dst_port;
        const char *name, *carrier, *proto, *src_addr, *src_mask, *dst_addr, *dst_mask;
        const char *mode_name;
        int mode;
        int j;

        if (!rule || !json_object_is_type(rule, json_type_object) || !out || !out_ids ||
            route_json_u32(rule, "enabled", 1, &enabled) || enabled > 1 ||
            route_json_u32(rule, "prio", 1000U + (uint32_t)i, &prio) || prio > UINT16_MAX ||
            route_json_u32(rule, "appid", 0, &appid) ||
            route_json_u32(rule, "dst_port", 0, &dst_port) || dst_port > UINT16_MAX) {
            if (out) json_object_put(out);
            if (out_ids) json_object_put(out_ids);
            route_error(error, error_len, "invalid route rule numeric field");
            goto invalid_result;
        }
        name = route_json_string(rule, "name", "");
        carrier = route_json_string(rule, "carrier", "");
        if (!carrier[0]) {
            uint32_t carrier_id = 0;
            if (route_json_u32(rule, "carrier_id", 0, &carrier_id) || carrier_id > UINT8_MAX) {
                json_object_put(out); json_object_put(out_ids);
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
        mode_name = route_json_string(rule, "algorithm",
                                      route_json_string(rule, "sticky_mode", "sip"));
        mode = route_mode_id(mode_name);
        if (!route_string_ok(name, 128) || !route_string_ok(carrier, 32) ||
            route_carrier_id(carrier) < 0 || !route_string_ok(proto, 16) ||
            !route_proto_ok(proto) || !route_string_ok(src_addr, 64) ||
            !route_string_ok(src_mask, 64) || !route_string_ok(dst_addr, 64) ||
            !route_string_ok(dst_mask, 64) || !route_ipv4_ok(src_addr) ||
            !route_ipv4_ok(src_mask) || !route_ipv4_ok(dst_addr) ||
            !route_ipv4_ok(dst_mask) || mode < 0) {
            json_object_put(out); json_object_put(out_ids);
            route_error(error, error_len, "invalid route rule string, IPv4, protocol, carrier, or algorithm");
            goto invalid_result;
        }
        if (json_object_object_get_ex(rule, "wan_ids", &wan_ids) &&
            !json_object_is_type(wan_ids, json_type_array)) {
            json_object_put(out); json_object_put(out_ids);
            route_error(error, error_len, "wan_ids must be an array");
            goto invalid_result;
        }
        if (wan_ids && json_object_array_length(wan_ids) > JMX_ROUTE_MAX_WAN_IFACES) {
            json_object_put(out); json_object_put(out_ids);
            route_error(error, error_len, "too many WAN targets in route rule");
            goto invalid_result;
        }
        for (j = 0; wan_ids && j < json_object_array_length(wan_ids); j++) {
            struct json_object *value = json_object_array_get_idx(wan_ids, j);
            int64_t wan_id;
            if (!value || !json_object_is_type(value, json_type_int) ||
                (wan_id = json_object_get_int64(value)) <= 0 || wan_id > UINT8_MAX) {
                json_object_put(out); json_object_put(out_ids);
                route_error(error, error_len, "invalid WAN target id");
                goto invalid_result;
            }
            json_object_array_add(out_ids, json_object_new_int64(wan_id));
        }
        if (enabled && json_object_array_length(out_ids) == 0 &&
            route_carrier_id(carrier) <= JMX_CARRIER_ANY) {
            json_object_put(out); json_object_put(out_ids);
            route_error(error, error_len,
                        "enabled rule without WAN targets must match a carrier");
            goto invalid_result;
        }
        json_object_object_add(out, "name", json_object_new_string(name));
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
        json_object_object_add(out, "sticky_mode", json_object_new_string(route_mode_algorithm(mode)));
        json_object_object_add(out, "algorithm", json_object_new_string(route_mode_algorithm(mode)));
        json_object_object_add(out, "wan_ids", out_ids);
        json_object_object_add(out, "wan_selection", json_object_new_string(
            json_object_array_length(out_ids) > 0 ? "explicit" : "auto_carrier"));
        json_object_array_add(out_rules, out);
    }

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
        "INSERT INTO route_global(id,enabled,all_down_action) VALUES(1,1,?1)") != 0)
        return -1;
    sqlite3_bind_text(stmt, 1, route_json_string(config, "all_down_action", "main_route"),
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
        "src_mask,dst_addr,dst_mask,dst_port,sticky_mode)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)") != 0)
        goto done;
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
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
        if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
    }
    sqlite3_finalize(stmt); stmt = NULL;

    if (route_prepare(db, &stmt,
        "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(?1,?2,?3)") != 0)
        goto done;
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i), *ids = NULL;
        int j;
        json_object_object_get_ex(rule, "wan_ids", &ids);
        for (j = 0; ids && j < json_object_array_length(ids); j++) {
            sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
            sqlite3_bind_int(stmt, 1, i + 1); sqlite3_bind_int(stmt, 2, j);
            sqlite3_bind_int(stmt, 3, json_object_get_int(json_object_array_get_idx(ids, j)));
            if (sqlite3_step(stmt) != SQLITE_DONE) goto done;
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

    if (route_prepare(db, &stmt, "SELECT all_down_action FROM route_global WHERE id=1") != 0)
        goto fail;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *action = (const char *)sqlite3_column_text(stmt, 0);
        json_object_object_del(config, "all_down_action");
        json_object_object_add(config, "all_down_action",
                               json_object_new_string(action ? action : "main_route"));
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
        "dst_port,sticky_mode FROM route_rule ORDER BY position") != 0)
        goto fail;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        struct json_object *rule = json_object_new_object(), *ids = json_object_new_array();
        sqlite3_stmt *wan_stmt = NULL;
        const char *mode = (const char *)sqlite3_column_text(stmt, 12);
        int mode_id = route_mode_id(mode);
        int rule_id = sqlite3_column_int(stmt, 0);
        json_object_object_add(rule, "name", json_object_new_string((const char *)sqlite3_column_text(stmt, 1)));
        json_object_object_add(rule, "enabled", json_object_new_int(sqlite3_column_int(stmt, 2)));
        json_object_object_add(rule, "prio", json_object_new_int(sqlite3_column_int(stmt, 3)));
        json_object_object_add(rule, "appid", json_object_new_int64(sqlite3_column_int64(stmt, 4)));
        route_add_sql_text(rule, "carrier", stmt, 5);
        json_object_object_add(rule, "proto", json_object_new_string((const char *)sqlite3_column_text(stmt, 6)));
        route_add_sql_text(rule, "src_addr", stmt, 7); route_add_sql_text(rule, "src_mask", stmt, 8);
        route_add_sql_text(rule, "dst_addr", stmt, 9); route_add_sql_text(rule, "dst_mask", stmt, 10);
        json_object_object_add(rule, "dst_port", json_object_new_int(sqlite3_column_int(stmt, 11)));
        json_object_object_add(rule, "sticky_mode", json_object_new_string(mode ? mode : "hash_src"));
        json_object_object_add(rule, "algorithm",
                               json_object_new_string(route_mode_algorithm(mode_id) ?
                                                      route_mode_algorithm(mode_id) : "hash_src"));
        if (route_prepare(db, &wan_stmt,
            "SELECT wan_id FROM route_rule_wan WHERE rule_id=?1 ORDER BY position") != 0) {
            json_object_put(rule); json_object_put(ids); goto fail;
        }
        sqlite3_bind_int(wan_stmt, 1, rule_id);
        while ((rc = sqlite3_step(wan_stmt)) == SQLITE_ROW)
            json_object_array_add(ids, json_object_new_int(sqlite3_column_int(wan_stmt, 0)));
        sqlite3_finalize(wan_stmt);
        if (rc != SQLITE_DONE) { json_object_put(rule); json_object_put(ids); goto fail; }
        json_object_object_add(rule, "wan_ids", ids);
        json_object_object_add(rule, "wan_selection", json_object_new_string(
            json_object_array_length(ids) > 0 ? "explicit" : "auto_carrier"));
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
    if (route_exec(db, route_schema_sql) != 0 || route_migrate_once(db) != 0) {
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
