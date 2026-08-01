// SPDX-License-Identifier: GPL-2.0-or-later
/* ISP/carrier detection by public IPv4 and signature DB CIDR matching. */
#include "jmx_isp.h"
#include "jmx_exec.h"
#include "jmx_signature_db.h"
#include "jmx_system_data_path.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define JMX_ISP_CACHE_TTL_OK_S 300
#define JMX_ISP_CACHE_TTL_FAIL_S 60
#define JMX_ISP_EXEC_TIMEOUT_MS 5000
#define JMX_ISP_IFSTATUS_OUTPUT_MAX (64U * 1024U)

struct jmx_isp_cache_entry {
    char key[32];
    time_t ts;
    int status;
    jmx_isp_entry_t entry;
};

static struct jmx_isp_cache_entry g_isp_cache[JMX_ISP_MAX_WANS];

static int jmx_isp_ifname_ok(const char *s);

static int jmx_isp_cache_find(const char *key, int create)
{
    int free_slot = -1;
    int i;

    if (!jmx_isp_ifname_ok(key))
        return -1;
    for (i = 0; i < JMX_ISP_MAX_WANS; i++) {
        if (g_isp_cache[i].key[0] && !strcmp(g_isp_cache[i].key, key))
            return i;
        if (!g_isp_cache[i].key[0] && free_slot < 0)
            free_slot = i;
    }
    if (!create)
        return -1;
    if (free_slot < 0)
        free_slot = 0;
    memset(&g_isp_cache[free_slot], 0, sizeof(g_isp_cache[free_slot]));
    snprintf(g_isp_cache[free_slot].key, sizeof(g_isp_cache[free_slot].key), "%s", key);
    return free_slot;
}

static int jmx_isp_signature_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                              &source, error, sizeof(error)) == 0)
        return 0;
    fprintf(stderr, "[dreamingwrt-core] ISP signature DB resolve failed: %s\n",
            error);
    return -1;
}

static int jmx_isp_ifname_ok(const char *s)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) >= 32)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == '@'))
            return 0;
    }
    return 1;
}

static int jmx_isp_public_ipv4_ok(const char *ip, uint32_t *host_order)
{
    struct in_addr a;
    uint32_t h;

    if (!ip || inet_pton(AF_INET, ip, &a) != 1)
        return 0;
    h = ntohl(a.s_addr);
    if ((h >> 24) == 0 || (h >> 24) == 10 || (h >> 24) == 127)
        return 0;
    if ((h & 0xfff00000U) == 0xac100000U) /* 172.16.0.0/12 */
        return 0;
    if ((h & 0xffff0000U) == 0xc0a80000U) /* 192.168.0.0/16 */
        return 0;
    if ((h & 0xffff0000U) == 0xa9fe0000U) /* 169.254.0.0/16 */
        return 0;
    if ((h & 0xffc00000U) == 0x64400000U) /* 100.64.0.0/10 */
        return 0;
    if (h >= 0xe0000000U)
        return 0;
    if (host_order)
        *host_order = h;
    return 1;
}

static void jmx_isp_trim(char *s)
{
    char *e;

    if (!s)
        return;
    while (*s && isspace((unsigned char)*s))
        memmove(s, s + 1, strlen(s));
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
}

static int jmx_isp_exec_ok(const struct jmx_exec_result *result)
{
    return result && !result->timed_out && !result->truncated &&
           result->term_signal == 0 && result->exit_code == 0 &&
           result->output;
}

static int jmx_isp_l3_device_from_ifstatus(const char *wan_id, char *out, size_t out_len)
{
    char object[64];
    char *argv[] = { "/bin/ubus", "call", object, "status", NULL };
    struct jmx_exec_result result;
    struct json_tokener *tokener = NULL;
    struct json_object *root = NULL;
    struct json_object *value = NULL;
    size_t parsed;
    size_t len;
    int rc = -1;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (!jmx_isp_ifname_ok(wan_id))
        return -1;
    if (snprintf(object, sizeof(object), "network.interface.%s", wan_id) >=
        (int)sizeof(object))
        return -1;
    if (jmx_exec_capture(argv[0], argv, JMX_ISP_IFSTATUS_OUTPUT_MAX,
                         JMX_ISP_EXEC_TIMEOUT_MS, &result) != 0)
        return -1;
    if (!jmx_isp_exec_ok(&result) || result.output_len == 0 ||
        result.output_len > INT_MAX)
        goto done;
    tokener = json_tokener_new_ex(16);
    if (!tokener)
        goto done;
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT);
    root = json_tokener_parse_ex(tokener, result.output,
                                 (int)result.output_len);
    if (!root || json_tokener_get_error(tokener) != json_tokener_success ||
        !json_object_is_type(root, json_type_object))
        goto done;
    parsed = json_tokener_get_parse_end(tokener);
    while (parsed < result.output_len &&
           isspace((unsigned char)result.output[parsed]))
        parsed++;
    if (parsed != result.output_len ||
        !json_object_object_get_ex(root, "l3_device", &value) ||
        !json_object_is_type(value, json_type_string))
        goto done;
    len = json_object_get_string_len(value);
    if (len == 0 || len >= out_len ||
        !jmx_isp_ifname_ok(json_object_get_string(value)))
        goto done;
    memcpy(out, json_object_get_string(value), len + 1);
    rc = 0;

done:
    if (root)
        json_object_put(root);
    if (tokener)
        json_tokener_free(tokener);
    jmx_exec_result_free(&result);
    return rc;
}

static int jmx_isp_fetch_public_ip_one(const char *iface, const char *url,
                                       char *ip, size_t ip_len)
{
    char *argv_with_iface[] = {
        "/usr/bin/curl", "-4", "-fsS", "--interface", (char *)iface,
        "--connect-timeout", "1", "--max-time", "3", (char *)url, NULL
    };
    char *argv_default[] = {
        "/usr/bin/curl", "-4", "-fsS", "--connect-timeout", "1",
        "--max-time", "3", (char *)url, NULL
    };
    char **argv = iface && iface[0] ? argv_with_iface : argv_default;
    struct jmx_exec_result result;
    size_t len;

    if (!url || !ip || ip_len < 2)
        return -1;
    ip[0] = '\0';
    if (iface && iface[0] && !jmx_isp_ifname_ok(iface))
        return -1;
    if (jmx_exec_capture(argv[0], argv, ip_len - 1,
                         JMX_ISP_EXEC_TIMEOUT_MS, &result) != 0)
        return -1;
    if (!jmx_isp_exec_ok(&result) || result.output_len == 0) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_isp_trim(result.output);
    len = strlen(result.output);
    if (len == 0 || len >= ip_len) {
        jmx_exec_result_free(&result);
        return -1;
    }
    memcpy(ip, result.output, len + 1);
    jmx_exec_result_free(&result);
    return jmx_isp_public_ipv4_ok(ip, NULL) ? 0 : -1;
}

static int jmx_isp_fetch_public_ip(const char *iface, char *ip, size_t ip_len,
                                   char *source, size_t source_len)
{
    static const char *urls[] = {
        "https://ip.sb",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://api.ipify.org"
    };
    size_t i;

    if (source && source_len)
        source[0] = '\0';
    for (i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
        if (jmx_isp_fetch_public_ip_one(iface, urls[i], ip, ip_len) == 0) {
            if (source && source_len)
                snprintf(source, source_len, "%s", urls[i]);
            return 0;
        }
    }
    return -1;
}

static const char *jmx_isp_normalize_carrier(const char *carrier)
{
    if (!carrier || !carrier[0]) return "unknown";
    if (!strcmp(carrier, "edu")) return "cernet";
    if (!strcmp(carrier, "telecom") || !strcmp(carrier, "unicom") ||
        !strcmp(carrier, "mobile") || !strcmp(carrier, "cernet")) return carrier;
    return "unknown";
}

static int jmx_isp_match_carrier(uint32_t public_ip_host_order, jmx_isp_entry_t *out)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    char path[512];
    int best_prefix = -1;
    int ok = -1;

    if (jmx_isp_signature_db_path(path, sizeof(path)) != 0 ||
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(db,
        "SELECT carrier,carrier_id,carrier_name,network,prefix_len "
        "FROM carrier_prefix WHERE enabled=1 ORDER BY prefix_len DESC",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *carrier = (const char *)sqlite3_column_text(st, 0);
        int carrier_id = sqlite3_column_int(st, 1);
        const char *name = (const char *)sqlite3_column_text(st, 2);
        uint32_t network = (uint32_t)sqlite3_column_int64(st, 3);
        int prefix = sqlite3_column_int(st, 4);
        uint32_t mask;

        if (prefix < 0 || prefix > 32)
            continue;
        mask = prefix == 0 ? 0 : (uint32_t)(0xffffffffU << (32 - prefix));
        if ((public_ip_host_order & mask) != (network & mask))
            continue;
        if (prefix <= best_prefix)
            continue;
        best_prefix = prefix;
        out->isp = carrier_id;
        snprintf(out->carrier_key, sizeof(out->carrier_key), "%s", jmx_isp_normalize_carrier(carrier));
        snprintf(out->carrier_name, sizeof(out->carrier_name), "%s", name && name[0] ? name : "Unknown");
        out->confidence = 92;
        ok = 0;
    }

done:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return ok;
}

int jmx_isp_detect_public_ip(const char *public_ip, const char *source,
                             jmx_isp_entry_t *out)
{
    uint32_t ip_h = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    snprintf(out->carrier_key, sizeof(out->carrier_key), "%s", "unknown");
    snprintf(out->carrier_name, sizeof(out->carrier_name), "%s", "Unknown");
    snprintf(out->error, sizeof(out->error), "%s", "invalid_public_ip");

    if (!jmx_isp_public_ipv4_ok(public_ip, &ip_h))
        return -1;

    snprintf(out->public_ip, sizeof(out->public_ip), "%s", public_ip);
    snprintf(out->source, sizeof(out->source), "%s",
             source && source[0] ? source : "runtime_public_ip");
    out->error[0] = '\0';
    if (jmx_isp_match_carrier(ip_h, out) != 0) {
        snprintf(out->error, sizeof(out->error), "%s", "carrier_prefix_not_matched");
        out->confidence = 20;
        return -1;
    }
    return 0;
}

int jmx_isp_detect_sync(const char *wan_id, const char *l3_ifname,
                        jmx_isp_entry_t *out)
{
    char l3[32] = "";
    char source[64] = "";
    char source_iface[32] = "default-route";
    uint32_t ip_h = 0;
    int have_ip = 0;
    int specific_lookup = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    snprintf(out->ifname, sizeof(out->ifname), "%s", wan_id && wan_id[0] ? wan_id : (l3_ifname ? l3_ifname : ""));
    snprintf(out->carrier_key, sizeof(out->carrier_key), "%s", "unknown");
    snprintf(out->carrier_name, sizeof(out->carrier_name), "%s", "Unknown");
    snprintf(out->error, sizeof(out->error), "%s", "public_ip_unavailable");
    specific_lookup = (wan_id && wan_id[0]) || (l3_ifname && l3_ifname[0]);

    if (wan_id && wan_id[0])
        (void)jmx_isp_l3_device_from_ifstatus(wan_id, l3, sizeof(l3));
    if (!l3[0] && l3_ifname && l3_ifname[0] && jmx_isp_ifname_ok(l3_ifname))
        snprintf(l3, sizeof(l3), "%s", l3_ifname);

    if (l3[0] && jmx_isp_fetch_public_ip(l3, out->public_ip, sizeof(out->public_ip), source, sizeof(source)) == 0) {
        have_ip = 1;
        snprintf(source_iface, sizeof(source_iface), "%s", l3);
    }
    if (!have_ip && !specific_lookup &&
        jmx_isp_fetch_public_ip(NULL, out->public_ip, sizeof(out->public_ip), source, sizeof(source)) == 0) {
        have_ip = 1;
        snprintf(source_iface, sizeof(source_iface), "%s", "default-route");
    }
    if (!have_ip || !jmx_isp_public_ipv4_ok(out->public_ip, &ip_h))
        return -1;

    snprintf(out->source, sizeof(out->source), "%.31s@%.31s",
             source[0] ? source : "unknown", source_iface);
    out->error[0] = '\0';
    if (jmx_isp_match_carrier(ip_h, out) != 0) {
        snprintf(out->error, sizeof(out->error), "%s", "carrier_prefix_not_matched");
        out->confidence = 20;
        return -1;
    }
    return 0;
}

int jmx_isp_init(void)
{
    return 0;
}

void jmx_isp_exit(void)
{
}

int jmx_isp_get(const char *ifname, jmx_isp_entry_t *out)
{
    jmx_isp_entry_t detected;
    time_t now = time(NULL);
    int idx;
    int ttl;
    int rc;

    if (!ifname || !out || !jmx_isp_ifname_ok(ifname))
        return -1;
    idx = jmx_isp_cache_find(ifname, 1);
    if (idx < 0)
        return jmx_isp_detect_sync(ifname, ifname, out);
    ttl = g_isp_cache[idx].status == 0 ? JMX_ISP_CACHE_TTL_OK_S : JMX_ISP_CACHE_TTL_FAIL_S;
    if (g_isp_cache[idx].ts > 0 && now - g_isp_cache[idx].ts < ttl) {
        *out = g_isp_cache[idx].entry;
        return g_isp_cache[idx].status;
    }
    rc = jmx_isp_detect_sync(ifname, ifname, &detected);
    g_isp_cache[idx].ts = now;
    g_isp_cache[idx].status = rc;
    g_isp_cache[idx].entry = detected;
    *out = detected;
    return rc;
}

void jmx_isp_refresh(const char *ifname)
{
    jmx_isp_entry_t tmp;
    int idx;
    int rc;

    if (!ifname || !jmx_isp_ifname_ok(ifname))
        return;
    rc = jmx_isp_detect_sync(ifname, ifname, &tmp);
    idx = jmx_isp_cache_find(ifname, 1);
    if (idx >= 0) {
        g_isp_cache[idx].ts = time(NULL);
        g_isp_cache[idx].status = rc;
        g_isp_cache[idx].entry = tmp;
    }
}
