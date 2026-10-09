// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_dreamingwrt_work_mode.c - Work mode management (gateway / bypass)
 *
 * Provides dreamingwrt_work_mode_get / preview / apply / rollback
 * config.db authority with transactional OpenWrt runtime projection.
 */
#include "jmx_dreamingwrt_api.h"
#include "jmx_network.h"
#include "jmx_uci.h"
#include "jmx.h"
#include "jmx_netconfig_db.h"
#include "jmx_exec.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <uci.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

#define WM_ROLLBACK_DIR "/tmp/dreamingwrt-network-rollback"
#define WM_COMMAND_TIMEOUT_MS 2500
#define WM_COMMAND_OUTPUT_MAX (64U * 1024U)

/* ── helpers ── */

static int64_t wm_now(void) { return (int64_t)time(NULL); }
static unsigned long wm_rollback_sequence;

static int wm_token_ok(const char *value, size_t max_len)
{
    size_t i;
    if (!value || !value[0])
        return 0;
    for (i = 0; value[i]; i++) {
        unsigned char c = (unsigned char)value[i];
        if (i >= max_len || (!isalnum(c) && c != '_' && c != '-'))
            return 0;
    }
    return i > 0;
}

static const char *wm_executable(const char *const paths[])
{
    size_t i;
    for (i = 0; paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

static int wm_capture(const char *path, char *const argv[],
                      struct jmx_exec_result *result)
{
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    if (!path || jmx_exec_capture(path, argv, WM_COMMAND_OUTPUT_MAX,
                                  WM_COMMAND_TIMEOUT_MS, result) != 0)
        return -1;
    return result->exit_code == 0 && !result->timed_out && !result->truncated ? 0 : -1;
}

static const char *wm_mode_str(int m)
{
    return m == 1 ? "side-router" : "gateway";
}

static int wm_mode_int(const char *s)
{
    if (s && (strcmp(s, "side-router") == 0 || strcmp(s, "bypass") == 0))
        return 1;
    if (s && strcmp(s, "gateway") == 0)
        return 0;
    return -1;
}

static int wm_find_dhcp_section(struct uci_context *ctx, char *out, size_t out_len);
static int wm_find_dnsmasq_section(struct uci_context *ctx, char *out, size_t out_len);
static int wm_find_lan_zone_section(struct uci_context *ctx, char *out, size_t out_len);
static int wm_find_nat_zone_section(struct uci_context *ctx, char *out, size_t out_len);
static int wm_rollback_config(const char *rollback_id, const char *config_name);

static void wm_add_side_router_contract(struct json_object *out, int current_mode)
{
    struct json_object *modes = json_object_new_array();
    struct json_object *gateway = json_object_new_object();
    struct json_object *side_router = json_object_new_object();

    struct json_object *details = json_object_new_object();
    json_object_array_add(modes, json_object_new_string("gateway"));
    json_object_array_add(modes, json_object_new_string("side-router"));

    json_object_object_add(gateway, "label", json_object_new_string("主路由网关模式"));
    json_object_object_add(gateway, "description",
                           json_object_new_string("设备持有 WAN，LAN 提供 DHCP 与 NAT。"));
    json_object_object_add(details, "gateway", gateway);

    json_object_object_add(side_router, "label", json_object_new_string("旁路由模式"));
    json_object_object_add(side_router, "description",
                           json_object_new_string("LAN 静态地址与上游同段，网关和 DNS 指向上游；默认关闭本机 DHCP 与 NAT。客户端把网关改指本设备时，由本设备执行策略路由等出口控制。"));
    json_object_object_add(details, "side-router", side_router);

    json_object_object_add(out, "available_modes", modes);
    json_object_object_add(out, "mode_details", details);
    json_object_object_add(out, "canonical_mode", json_object_new_string(wm_mode_str(current_mode)));
    json_object_object_add(out, "aliases", json_object_new_string("bypass"));
    json_object_object_add(out, "capability", json_object_new_string("stable"));
    json_object_object_add(out, "risk_level", json_object_new_string("medium"));
    json_object_object_add(out, "required_role", json_object_new_string("admin_or_owner_with_confirmation"));
}

static const char *wm_json_str(struct json_object *obj, const char *key, const char *def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v) return def;
    const char *s = json_object_get_string(v);
    return (s && s[0]) ? s : def;
}

static int wm_json_bool(struct json_object *obj, const char *key, int def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v) return def;
    return json_object_get_boolean(v);
}

static int wm_uci_option_has_value(struct uci_context *ctx,
                                   struct uci_section *section,
                                   const char *option_name,
                                   const char *wanted)
{
    struct uci_option *option;
    struct uci_element *element;

    if (!ctx || !section || !option_name || !wanted)
        return 0;
    option = uci_lookup_option(ctx, section, option_name);
    if (!option)
        return 0;
    if (option->type == UCI_TYPE_STRING)
        return !strcmp(option->v.string, wanted);
    if (option->type != UCI_TYPE_LIST)
        return 0;
    uci_foreach_element(&option->v.list, element) {
        if (!strcmp(element->name, wanted))
            return 1;
    }
    return 0;
}

static int wm_copy_section_name(struct uci_section *section, char *out, size_t out_len)
{
    int written;

    if (!section || !out || out_len == 0 || !section->e.name)
        return -1;
    written = snprintf(out, out_len, "%s", section->e.name);
    return written >= 0 && (size_t)written < out_len ? 0 : -1;
}

/* Resolve native sections by semantic identity, never by UCI list index. */
static int wm_find_dhcp_section(struct uci_context *ctx, char *out, size_t out_len)
{
    struct uci_package *pkg = NULL;
    struct uci_element *element;
    int rc = -1;

    if (!ctx || !out || out_len == 0 || uci_load(ctx, "dhcp", &pkg) != UCI_OK || !pkg)
        return -1;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (!section->type || strcmp(section->type, "dhcp"))
            continue;
        if (!strcmp(section->e.name, "lan") ||
            wm_uci_option_has_value(ctx, section, "interface", "lan") ||
            wm_uci_option_has_value(ctx, section, "network", "lan")) {
            rc = wm_copy_section_name(section, out, out_len);
            break;
        }
    }
    uci_unload(ctx, pkg);
    return rc;
}

static int wm_find_dnsmasq_section(struct uci_context *ctx, char *out, size_t out_len)
{
    struct uci_package *pkg = NULL;
    struct uci_element *element;
    int rc = -1;

    if (!ctx || !out || out_len == 0 || uci_load(ctx, "dhcp", &pkg) != UCI_OK || !pkg)
        return -1;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (section->type && !strcmp(section->type, "dnsmasq")) {
            rc = wm_copy_section_name(section, out, out_len);
            break;
        }
    }
    uci_unload(ctx, pkg);
    return rc;
}

static int wm_find_zone_section(struct uci_context *ctx, const char *wanted,
                                char *out, size_t out_len)
{
    struct uci_package *pkg = NULL;
    struct uci_element *element;
    int rc = -1;

    if (!ctx || !wanted || !out || out_len == 0 ||
        uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg)
        return -1;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *name;
        if (!section->type || strcmp(section->type, "zone"))
            continue;
        name = uci_lookup_option_string(ctx, section, "name");
        if ((name && !strcmp(name, wanted)) || !strcmp(section->e.name, wanted)) {
            rc = wm_copy_section_name(section, out, out_len);
            break;
        }
        if (wm_uci_option_has_value(ctx, section, "network", wanted)) {
            rc = wm_copy_section_name(section, out, out_len);
            break;
        }
    }
    uci_unload(ctx, pkg);
    return rc;
}

static int wm_find_lan_zone_section(struct uci_context *ctx, char *out, size_t out_len)
{
    return wm_find_zone_section(ctx, "lan", out, out_len);
}

static int wm_find_nat_zone_section(struct uci_context *ctx, char *out, size_t out_len)
{
    return wm_find_zone_section(ctx, "wan", out, out_len);
}

static int wm_read_authority(int *mode, char *last_apply_id, size_t last_apply_id_len,
                             char *apply_state, size_t apply_state_len)
{
    if (!mode)
        return -1;
    if (jmx_work_mode_config_get(mode, last_apply_id, last_apply_id_len,
                                 apply_state, apply_state_len) != 0)
        return -1;
    return (*mode == 0 || *mode == 1) ? 0 : -1;
}

static const char *wm_json_array_str(struct json_object *obj, const char *key, int idx)
{
    struct json_object *arr = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &arr) || !arr) return "";
    struct json_object *item = json_object_array_get_idx(arr, idx);
    if (!item) return "";
    return json_object_get_string(item);
}

static int wm_read_mode(void)
{
    int m = 0;

    if (wm_read_authority(&m, NULL, 0, NULL, 0) != 0)
        m = 0;
    return m;
}

/* Detect current LAN config */
static void wm_detect_lan(struct json_object *out)
{
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return;
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "network", &pkg) != UCI_OK) { uci_free_context(ctx); return; }
    struct uci_section *s = uci_lookup_section(ctx, pkg, "lan");
    if (s) {
        const char *ip = uci_lookup_option_string(ctx, s, "ipaddr");
        const char *nm = uci_lookup_option_string(ctx, s, "netmask");
        const char *gw = uci_lookup_option_string(ctx, s, "gateway");
        const char *dns = uci_lookup_option_string(ctx, s, "dns");
        const char *proto = uci_lookup_option_string(ctx, s, "proto");
        if (ip) json_object_object_add(out, "lan_ip", json_object_new_string(ip));
        if (nm) json_object_object_add(out, "lan_netmask", json_object_new_string(nm));
        if (gw) json_object_object_add(out, "lan_gateway", json_object_new_string(gw));
        if (dns) json_object_object_add(out, "lan_dns", json_object_new_string(dns));
        if (proto) json_object_object_add(out, "lan_proto", json_object_new_string(proto));
    }
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
}

/* Detect default route (upstream gateway) */
static void wm_detect_upstream(struct json_object *out)
{
    static const char *const paths[] = { "/sbin/ip", "/usr/sbin/ip", NULL };
    const char *path = wm_executable(paths);
    struct jmx_exec_result result;
    char *argv[] = { (char *)path, "route", "show", "default", NULL };

    if (wm_capture(path, argv, &result) == 0 && result.output) {
        /* parse "default via X.X.X.X dev eth1 ..." */
        char gw[64] = "", dev[32] = "";
        char *p;
        p = strstr(result.output, " via ");
        if (p) { p += 5; sscanf(p, "%63s", gw); }
        p = strstr(result.output, " dev ");
        if (p) { p += 5; sscanf(p, "%31s", dev); }
        if (gw[0]) json_object_object_add(out, "upstream_gateway", json_object_new_string(gw));
        if (dev[0]) json_object_object_add(out, "upstream_iface", json_object_new_string(dev));
    }
    jmx_exec_result_free(&result);
}

static int wm_configured_upstream_gateway(char *out, size_t out_len)
{
    struct uci_context *ctx = uci_alloc_context();
    char value[128] = "";
    char *separator;
    struct in_addr addr;
    int rc = -1;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (!ctx)
        return -1;
    if (jmx_uci_get_value(ctx, "network.lan.gateway", value, sizeof(value)) != 0 ||
        !value[0])
        (void)jmx_uci_get_value(ctx, "network.lan.dns", value, sizeof(value));
    uci_free_context(ctx);
    separator = strpbrk(value, " ,;\t\r\n");
    if (separator)
        *separator = '\0';
    if (inet_pton(AF_INET, value, &addr) == 1 &&
        snprintf(out, out_len, "%s", value) < (int)out_len)
        rc = 0;
    return rc;
}

static int wm_process_running(const char *name)
{
    DIR *dir;
    struct dirent *entry;
    int found = 0;

    if (!name || !name[0])
        return -1;
    dir = opendir("/proc");
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char path[64], comm[32];
        FILE *fp;
        size_t i;
        for (i = 0; entry->d_name[i] && isdigit((unsigned char)entry->d_name[i]); i++) {}
        if (!entry->d_name[0] || entry->d_name[i])
            continue;
        if (snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name) >= (int)sizeof(path))
            continue;
        fp = fopen(path, "re");
        if (!fp)
            continue;
        if (fgets(comm, sizeof(comm), fp)) {
            comm[strcspn(comm, "\r\n")] = '\0';
            if (!strcmp(comm, name))
                found = 1;
        }
        fclose(fp);
        if (found)
            break;
    }
    closedir(dir);
    return found ? 1 : 0;
}

static int wm_udp_port_bound_in(const char *path, unsigned int port)
{
    FILE *fp;
    char line[512];
    int readable = 0;

    fp = fopen(path, "re");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char local[96] = "";
        char *separator;
        unsigned long parsed;

        readable = 1;
        if (sscanf(line, "%*u: %95s", local) != 1)
            continue;
        separator = strrchr(local, ':');
        if (!separator || !separator[1])
            continue;
        parsed = strtoul(separator + 1, NULL, 16);
        if (parsed == port) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return readable ? 0 : -1;
}

static int wm_udp_port_bound(unsigned int port)
{
    int v4 = wm_udp_port_bound_in("/proc/net/udp", port);
    int v6 = wm_udp_port_bound_in("/proc/net/udp6", port);

    if (v4 > 0 || v6 > 0)
        return 1;
    if (v4 < 0 && v6 < 0)
        return -1;
    return 0;
}

/* Detect the actual LAN DHCP listener, while retaining UCI as intent evidence. */
static int wm_dhcp_active(void)
{
    struct uci_context *ctx = uci_alloc_context();
    char section[64] = "", key[128], value[32] = "";
    int listener;

    if (!ctx || wm_find_dhcp_section(ctx, section, sizeof(section)) != 0) {
        if (ctx)
            uci_free_context(ctx);
        return -1;
    }
    snprintf(key, sizeof(key), "dhcp.%s.ignore", section);
    if (jmx_uci_get_value(ctx, key, value, sizeof(value)) != 0 ||
        (strcmp(value, "0") && strcmp(value, "1"))) {
        uci_free_context(ctx);
        return -1;
    }
    uci_free_context(ctx);
    listener = wm_udp_port_bound(67);
    if (listener < 0)
        return -1;
    return listener > 0 ? 1 : 0;
}

static int wm_dns_proxy_active(void)
{
    struct uci_context *ctx = uci_alloc_context();
    char section[64] = "", key[128], value[32] = "";
    int process, listener;

    if (!ctx || wm_find_dnsmasq_section(ctx, section, sizeof(section)) != 0) {
        if (ctx)
            uci_free_context(ctx);
        return -1;
    }
    snprintf(key, sizeof(key), "dhcp.%s.port", section);
    if (jmx_uci_get_value(ctx, key, value, sizeof(value)) == 0 && !strcmp(value, "0")) {
        uci_free_context(ctx);
        return 0;
    }
    uci_free_context(ctx);
    process = wm_process_running("dnsmasq");
    listener = wm_udp_port_bound(53);
    if (process < 0 || listener < 0)
        return -1;
    return process > 0 && listener > 0 ? 1 : 0;
}

static int wm_nft_chain_has_masquerade(const char *ruleset, const char *chain)
{
    char marker[96];
    const char *start, *end, *masquerade;

    if (!ruleset || !chain ||
        snprintf(marker, sizeof(marker), "chain %s {", chain) >= (int)sizeof(marker))
        return 0;
    start = strstr(ruleset, marker);
    if (!start)
        return 0;
    end = strchr(start + strlen(marker), '}');
    masquerade = strstr(start, "masquerade");
    return masquerade && (!end || masquerade < end);
}

static int wm_nat_runtime_state(int *lan_active, int *wan_active)
{
    static const char *const paths[] = { "/usr/sbin/nft", "/sbin/nft", NULL };
    const char *path = wm_executable(paths);
    struct jmx_exec_result result;
    char *argv[] = { (char *)path, "list", "table", "inet", "fw4", NULL };
    int rc = -1;

    if (!lan_active || !wan_active)
        return -1;
    *lan_active = 0;
    *wan_active = 0;
    if (wm_capture(path, argv, &result) != 0 || !result.output ||
        !strstr(result.output, "table inet fw4"))
        goto done;
    *lan_active = wm_nft_chain_has_masquerade(result.output, "srcnat_lan");
    *wan_active = wm_nft_chain_has_masquerade(result.output, "srcnat_wan");
    rc = 0;
done:
    jmx_exec_result_free(&result);
    return rc;
}

/* Detect whether any managed zone currently masquerades traffic. */
static int wm_nat_active(void)
{
    int lan_active, wan_active;

    if (wm_nat_runtime_state(&lan_active, &wan_active) != 0)
        return -1;
    return lan_active || wan_active;
}

/* Ping check (returns latency in ms, or -1 on failure) */
static double wm_ping_check(const char *host)
{
    static const char *const paths[] = { "/bin/ping", "/usr/bin/ping", NULL };
    const char *path = wm_executable(paths);
    struct jmx_exec_result result;
    struct in_addr addr4;
    struct in6_addr addr6;
    double ms = -1;
    char *time_value;
    char *argv[] = { (char *)path, "-c", "1", "-W", "1", (char *)host, NULL };

    if (!host || (!inet_pton(AF_INET, host, &addr4) &&
                  !inet_pton(AF_INET6, host, &addr6)))
        return -1;
    if (wm_capture(path, argv, &result) == 0 && result.output &&
        (time_value = strstr(result.output, "time=")) != NULL &&
        sscanf(time_value + 5, "%lf", &ms) != 1)
        ms = -1;
    jmx_exec_result_free(&result);
    return ms;
}

static int wm_service_action(const char *service, const char *action)
{
    struct jmx_exec_result result;
    char path[128];
    char *argv[] = { path, (char *)action, NULL };
    int rc;

    if (!service || !action || snprintf(path, sizeof(path), "/etc/init.d/%s", service) >=
        (int)sizeof(path) || access(path, X_OK) != 0)
        return -1;
    rc = jmx_exec_wait(path, argv, 15000, &result);
    if (rc == 0)
        rc = result.exit_code == 0 && !result.timed_out ? 0 : -1;
    jmx_exec_result_free(&result);
    return rc;
}

static int wm_reload_services(void)
{
    int rc = 0;

    if (wm_service_action("network", "reload") != 0 &&
        wm_service_action("network", "restart") != 0)
        rc = -1;
    if (wm_service_action("dnsmasq", "reload") != 0 &&
        wm_service_action("dnsmasq", "restart") != 0)
        rc = -1;
    if (wm_service_action("firewall", "reload") != 0 &&
        wm_service_action("firewall", "restart") != 0)
        rc = -1;
    return rc;
}

/* Check if two IPs are in same /24 subnet */
static int wm_same_subnet(const char *ip1, const char *ip2, const char *mask)
{
    if (!ip1 || !ip2 || !mask) return 0;
    struct in_addr a1, a2, m;
    if (!inet_aton(ip1, &a1) || !inet_aton(ip2, &a2) || !inet_aton(mask, &m)) return 0;
    return (a1.s_addr & m.s_addr) == (a2.s_addr & m.s_addr);
}

/* ── UCI transaction helpers ── */

static int wm_uci_set(struct uci_context *ctx, const char *pkg,
                       const char *section, const char *option, const char *value)
{
    char key[256];
    snprintf(key, sizeof(key), "%s.%s.%s", pkg, section, option);
    return jmx_uci_set_value(ctx, key, (char *)value);
}

static int wm_uci_readback(int target_mode, const char *lan_ip,
                           const char *netmask, const char *gateway,
                           int disable_dhcp, int disable_nat,
                           struct json_object *failures)
{
    struct uci_context *ctx = uci_alloc_context();
    char value[128] = "";
    char dhcp_section[64] = "", lan_zone[64] = "", nat_zone[64] = "";
    char key[128];
    int ok = 1;

    if (!ctx)
        return -1;
#define WM_EXPECT(_key, _expected) do { \
    value[0] = '\0'; \
    if (jmx_uci_get_value(ctx, (_key), value, sizeof(value)) != 0 || \
        strcmp(value, (_expected))) { \
        ok = 0; \
        if (failures) json_object_array_add(failures, json_object_new_string(_key)); \
    } \
} while (0)
    WM_EXPECT("network.lan.proto", "static");
    if (lan_ip && lan_ip[0])
        WM_EXPECT("network.lan.ipaddr", lan_ip);
    if (netmask && netmask[0])
        WM_EXPECT("network.lan.netmask", netmask);
    if (target_mode == 1 && gateway && gateway[0])
        WM_EXPECT("network.lan.gateway", gateway);
    if (target_mode == 0) {
        value[0] = '\0';
        if (jmx_uci_get_value(ctx, "network.lan.gateway", value, sizeof(value)) == 0 &&
            value[0]) {
            ok = 0;
            if (failures) json_object_array_add(failures, json_object_new_string("network.lan.gateway"));
        }
    }
    if (wm_find_dhcp_section(ctx, dhcp_section, sizeof(dhcp_section)) != 0) {
        ok = 0;
        if (failures) json_object_array_add(failures, json_object_new_string("dhcp.section"));
    } else {
        snprintf(key, sizeof(key), "dhcp.%s.ignore", dhcp_section);
        WM_EXPECT(key, disable_dhcp ? "1" : "0");
    }
    if (wm_find_lan_zone_section(ctx, lan_zone, sizeof(lan_zone)) != 0) {
        ok = 0;
        if (failures) json_object_array_add(failures, json_object_new_string("firewall.lan_zone"));
    } else {
        snprintf(key, sizeof(key), "firewall.%s.masq", lan_zone);
        WM_EXPECT(key, "0");
    }
    if (wm_find_nat_zone_section(ctx, nat_zone, sizeof(nat_zone)) != 0) {
        ok = 0;
        if (failures) json_object_array_add(failures, json_object_new_string("firewall.wan_zone"));
    } else {
        snprintf(key, sizeof(key), "firewall.%s.masq", nat_zone);
        WM_EXPECT(key, disable_nat ? "0" : "1");
    }
#undef WM_EXPECT
    uci_free_context(ctx);
    return ok ? 0 : -1;
}

static int wm_projection_record(struct json_object *projection,
                                struct json_object *failures,
                                const char *key, int rc)
{
    if (!projection || !key)
        return rc;
    json_object_object_add(projection, key,
                           json_object_new_string(rc == 0 ? "ok" : "failed"));
    if (rc != 0 && failures)
        json_object_array_add(failures, json_object_new_string(key));
    return rc;
}

static int wm_lan_device(char *out, size_t out_len)
{
    struct uci_context *ctx = uci_alloc_context();
    int rc = -1;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (ctx) {
        rc = jmx_uci_get_value(ctx, "network.lan.device", out, out_len);
        uci_free_context(ctx);
    }
    if (rc != 0 || !out[0])
        rc = snprintf(out, out_len, "br-lan") < (int)out_len ? 0 : -1;
    return rc;
}

static int wm_lan_default_route_get(const char *device, char *gateway, size_t gateway_len)
{
    static const char *const paths[] = { "/sbin/ip", "/usr/sbin/ip", NULL };
    const char *path = wm_executable(paths);
    struct jmx_exec_result result;
    char *argv[] = { (char *)path, "-4", "route", "show", "default", NULL };
    char *saveptr = NULL, *line;
    int matched = 0;

    if (!device || !device[0] || !gateway || gateway_len == 0)
        return -1;
    if (wm_capture(path, argv, &result) != 0 || !result.output) {
        jmx_exec_result_free(&result);
        return -1;
    }
    gateway[0] = '\0';
    for (line = strtok_r(result.output, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char route_gateway[64] = "", route_device[64] = "";
        char *via, *dev;

        if (strncmp(line, "default", 7))
            continue;
        via = strstr(line, " via ");
        dev = strstr(line, " dev ");
        if (via)
            sscanf(via + 5, "%63s", route_gateway);
        if (dev)
            sscanf(dev + 5, "%63s", route_device);
        if (!strcmp(route_device, device)) {
            if (!route_gateway[0] ||
                snprintf(gateway, gateway_len, "%s", route_gateway) >= (int)gateway_len)
                matched = -1;
            else
                matched = 1;
            break;
        }
    }
    jmx_exec_result_free(&result);
    return matched;
}

static int wm_default_route_state(const char *gateway, const char *device)
{
    char actual_gateway[64] = "";
    int state = wm_lan_default_route_get(device, actual_gateway, sizeof(actual_gateway));

    if (state <= 0 || !gateway || !gateway[0])
        return state;
    return !strcmp(actual_gateway, gateway) ? 1 : 0;
}

static int wm_ensure_side_router_route(const char *gateway, const char *device)
{
    static const char *const paths[] = { "/sbin/ip", "/usr/sbin/ip", NULL };
    const char *path = wm_executable(paths);
    struct jmx_exec_result result;
    char *argv[] = { (char *)path, "-4", "route", "replace", "default",
                     "via", (char *)gateway, "dev", (char *)device, NULL };
    int rc;

    if (!gateway || !gateway[0] || !device || !device[0] || !path)
        return -1;
    rc = jmx_exec_wait(path, argv, 5000, &result);
    if (rc == 0)
        rc = result.exit_code == 0 && !result.timed_out ? 0 : -1;
    jmx_exec_result_free(&result);
    return rc;
}

static int wm_remove_lan_default_route(const char *device)
{
    static const char *const paths[] = { "/sbin/ip", "/usr/sbin/ip", NULL };
    const char *path = wm_executable(paths);
    struct jmx_exec_result result;
    char *argv[] = { (char *)path, "-4", "route", "del", "default",
                     "dev", (char *)device, NULL };
    int state, rc;

    if (!device || !device[0] || !path)
        return -1;
    state = wm_default_route_state(NULL, device);
    if (state == 0)
        return 0;
    if (state < 0)
        return -1;
    rc = jmx_exec_wait(path, argv, 5000, &result);
    if (rc == 0)
        rc = result.exit_code == 0 && !result.timed_out ? 0 : -1;
    jmx_exec_result_free(&result);
    return rc;
}

static int wm_restore_route_for_mode(int mode)
{
    char device[64] = "", gateway[64] = "";

    if (wm_lan_device(device, sizeof(device)) != 0)
        return -1;
    if (mode == 0)
        return wm_remove_lan_default_route(device);
    if (mode != 1 || wm_configured_upstream_gateway(gateway, sizeof(gateway)) != 0)
        return -1;
    return wm_ensure_side_router_route(gateway, device);
}

static int wm_snapshot_lan_default_route(const char *rollback_id)
{
    char device[64] = "", gateway[64] = "", path[PATH_MAX];
    FILE *fp;
    int state, rc = -1;

    if (!wm_token_ok(rollback_id, 63) || wm_lan_device(device, sizeof(device)) != 0 ||
        snprintf(path, sizeof(path), "%s/%s/lan_default_route", WM_ROLLBACK_DIR,
                 rollback_id) >= (int)sizeof(path))
        return -1;
    state = wm_lan_default_route_get(device, gateway, sizeof(gateway));
    if (state < 0)
        return -1;
    fp = fopen(path, "w");
    if (!fp)
        return -1;
    if ((state > 0 ? fprintf(fp, "via %s\n", gateway) : fprintf(fp, "absent\n")) >= 0 &&
        fflush(fp) == 0 && fsync(fileno(fp)) == 0)
        rc = 0;
    if (fclose(fp) != 0)
        rc = -1;
    if (rc != 0)
        unlink(path);
    return rc;
}

static int wm_restore_lan_default_route(const char *rollback_id, int fallback_mode)
{
    char device[64] = "", gateway[64] = "", path[PATH_MAX], line[96] = "";
    struct in_addr addr;
    FILE *fp;

    if (!wm_token_ok(rollback_id, 63) || wm_lan_device(device, sizeof(device)) != 0 ||
        snprintf(path, sizeof(path), "%s/%s/lan_default_route", WM_ROLLBACK_DIR,
                 rollback_id) >= (int)sizeof(path))
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return errno == ENOENT ? wm_restore_route_for_mode(fallback_mode) : -1;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    line[strcspn(line, "\r\n")] = '\0';
    if (!strcmp(line, "absent"))
        return wm_remove_lan_default_route(device);
    if (sscanf(line, "via %63s", gateway) != 1 ||
        inet_pton(AF_INET, gateway, &addr) != 1)
        return -1;
    return wm_ensure_side_router_route(gateway, device);
}

static int wm_runtime_readback(int target_mode, const char *gateway,
                               int disable_dhcp, int disable_nat,
                               struct json_object *projection,
                               struct json_object *failures)
{
    char device[64] = "";
    int route_ok = 0, dhcp_ok = 0, nat_ok = 0, dns_ok = 0;
    int attempt;

    if (wm_lan_device(device, sizeof(device)) != 0)
        goto record;
    for (attempt = 0; attempt < 5; attempt++) {
        int route = wm_default_route_state(target_mode == 1 ? gateway : NULL, device);
        int dhcp = wm_dhcp_active();
        int lan_nat = 0, wan_nat = 0;
        int nat = wm_nat_runtime_state(&lan_nat, &wan_nat);
        int dns = wm_dns_proxy_active();

        route_ok = target_mode == 1 ? route == 1 : route == 0;
        dhcp_ok = dhcp == (disable_dhcp ? 0 : 1);
        nat_ok = nat == 0 && !lan_nat && wan_nat == (disable_nat ? 0 : 1);
        dns_ok = dns == 1;
        if (route_ok && dhcp_ok && nat_ok && dns_ok)
            break;
        if (attempt < 4)
            sleep(1);
    }

record:
    wm_projection_record(projection, failures, "runtime.default_route", route_ok ? 0 : -1);
    wm_projection_record(projection, failures, "runtime.dhcp_server", dhcp_ok ? 0 : -1);
    wm_projection_record(projection, failures, "runtime.nat", nat_ok ? 0 : -1);
    wm_projection_record(projection, failures, "runtime.dns_proxy", dns_ok ? 0 : -1);
    return route_ok && dhcp_ok && nat_ok && dns_ok ? 0 : -1;
}

static int wm_restore_runtime_configs(const char *rollback_id)
{
    struct uci_context *ctx;
    int restored;

    if (!rollback_id || !rollback_id[0])
        return -1;
    restored = (wm_rollback_config(rollback_id, "network") == 0) ? 1 : 0;
    restored += (wm_rollback_config(rollback_id, "dhcp") == 0) ? 1 : 0;
    restored += (wm_rollback_config(rollback_id, "firewall") == 0) ? 1 : 0;
    if (restored != 3)
        return -1;
    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    if (jmx_uci_commit(ctx, "network") != UCI_OK ||
        jmx_uci_commit(ctx, "dhcp") != UCI_OK ||
        jmx_uci_commit(ctx, "firewall") != UCI_OK) {
        uci_free_context(ctx);
        return -1;
    }
    uci_free_context(ctx);
    return 0;
}

static void wm_projection_mark_readback_failures(struct json_object *projection,
                                                 struct json_object *failures)
{
    size_t i;

    if (!projection || !failures)
        return;
    for (i = 0; i < json_object_array_length(failures); i++) {
        struct json_object *item = json_object_array_get_idx(failures, i);
        if (item)
            json_object_object_add(projection, json_object_get_string(item),
                                   json_object_new_string("readback_failed"));
    }
}

/* Backup a UCI config file to rollback dir */
static int wm_backup_config(const char *rollback_id, const char *config_name)
{
    char dir[PATH_MAX], src[PATH_MAX], dst[PATH_MAX];
    int path_len;
    if (!wm_token_ok(rollback_id, 63) || !wm_token_ok(config_name, 31))
        return -1;
    path_len = snprintf(dir, sizeof(dir), "%s/%s", WM_ROLLBACK_DIR, rollback_id);
    if (path_len < 0 || path_len >= (int)sizeof(dir))
        return -1;
    mkdir(WM_ROLLBACK_DIR, 0755);
    mkdir(dir, 0755);
    path_len = snprintf(src, sizeof(src), "/etc/config/%s", config_name);
    if (path_len < 0 || path_len >= (int)sizeof(src))
        return -1;
    path_len = snprintf(dst, sizeof(dst), "%s/%s", dir, config_name);
    if (path_len < 0 || path_len >= (int)sizeof(dst))
        return -1;
    /* simple file copy */
    FILE *fi = fopen(src, "r");
    FILE *fo = fopen(dst, "w");
    int rc = -1;
    if (fi && fo) {
        char buf[4096];
        size_t n;
        rc = 0;
        while ((n = fread(buf, 1, sizeof(buf), fi)) > 0) {
            if (fwrite(buf, 1, n, fo) != n) {
                rc = -1;
                break;
            }
        }
        if (ferror(fi) || fflush(fo) != 0 || fsync(fileno(fo)) != 0)
            rc = -1;
    }
    if (fi) fclose(fi);
    if (fo) fclose(fo);
    if (rc != 0)
        unlink(dst);
    return rc;
}

/* Restore a UCI config from rollback dir */
static int wm_rollback_config(const char *rollback_id, const char *config_name)
{
    char src[PATH_MAX], dst[PATH_MAX];
    int path_len;
    if (!wm_token_ok(rollback_id, 63) || !wm_token_ok(config_name, 31))
        return -1;
    path_len = snprintf(src, sizeof(src), "%s/%s/%s", WM_ROLLBACK_DIR,
                        rollback_id, config_name);
    if (path_len < 0 || path_len >= (int)sizeof(src))
        return -1;
    path_len = snprintf(dst, sizeof(dst), "/etc/config/%s", config_name);
    if (path_len < 0 || path_len >= (int)sizeof(dst))
        return -1;
    FILE *fi = fopen(src, "r");
    if (!fi) return -1;
    FILE *fo = fopen(dst, "w");
    if (!fo) { fclose(fi); return -1; }
    char buf[4096];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), fi)) > 0) {
        if (fwrite(buf, 1, n, fo) != n) {
            rc = -1;
            break;
        }
    }
    if (ferror(fi) || fflush(fo) != 0 || fsync(fileno(fo)) != 0)
        rc = -1;
    if (fclose(fi) != 0)
        rc = -1;
    if (fclose(fo) != 0)
        rc = -1;
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * dreamingwrt_work_mode_get
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *dw_work_mode_get(struct json_object *req)
{
    (void)req;
    struct json_object *data = json_object_new_object();
    int mode = 0;
    char last_apply_id[64] = "", apply_state[32] = "";
    if (wm_read_authority(&mode, last_apply_id, sizeof(last_apply_id),
                          apply_state, sizeof(apply_state)) != 0)
        mode = 0;

    json_object_object_add(data, "work_mode", json_object_new_string(wm_mode_str(mode)));
    json_object_object_add(data, "canonical_mode", json_object_new_string(wm_mode_str(mode)));
    json_object_object_add(data, "apply_state", json_object_new_string(apply_state[0] ? apply_state : "ready"));
    json_object_object_add(data, "rollback_id", json_object_new_string(last_apply_id));
    json_object_object_add(data, "wan_required", json_object_new_boolean(mode == 0));

    /* LAN info */
    struct json_object *mgmt = json_object_new_object();
    wm_detect_lan(mgmt);
    /* construct management URL */
    char mgmt_url[256] = "";
    struct json_object *lip = json_object_object_get(mgmt, "lan_ip");
    if (lip)
        snprintf(mgmt_url, sizeof(mgmt_url), "http://%s/cgi-bin/luci/", json_object_get_string(lip));
    json_object_object_add(mgmt, "url", json_object_new_string(mgmt_url));
    json_object_object_add(data, "management", mgmt);

    /* upstream */
    struct json_object *upstream = json_object_new_object();
    wm_detect_upstream(upstream);
    const char *gw = "";
    struct json_object *gw_obj = json_object_object_get(upstream, "upstream_gateway");
    if (gw_obj) gw = json_object_get_string(gw_obj);
    double lat = wm_ping_check(gw);
    json_object_object_add(upstream, "reachable", json_object_new_boolean(lat >= 0));
    json_object_object_add(upstream, "latency_ms", lat >= 0 ? json_object_new_double(lat) : json_object_new_null());
    json_object_object_add(data, "upstream", upstream);

    /* services */
    struct json_object *svc = json_object_new_object();
    int dhcp_active = wm_dhcp_active();
    json_object_object_add(svc, "dhcp_server", json_object_new_string(
        dhcp_active > 0 ? "enabled" : dhcp_active == 0 ? "disabled" : "unknown"));
    int nat_active = wm_nat_active();
    json_object_object_add(svc, "nat", json_object_new_string(
        nat_active > 0 ? "enabled" : nat_active == 0 ? "disabled" : "unknown"));
    int dns_active = wm_dns_proxy_active();
    json_object_object_add(svc, "dns_proxy", json_object_new_string(
        dns_active > 0 ? "enabled" : dns_active == 0 ? "disabled" : "unknown"));
    json_object_object_add(data, "services", svc);

    wm_add_side_router_contract(data, mode);

    /* warnings */
    struct json_object *warnings = json_object_new_array();
    if (mode == 1 && wm_dhcp_active() > 0) {
        struct json_object *w = json_object_new_object();
        json_object_object_add(w, "level", json_object_new_string("medium"));
        json_object_object_add(w, "code", json_object_new_string("dhcp_active_in_bypass"));
        json_object_object_add(w, "message", json_object_new_string("旁路由模式下 DHCP 服务器仍在运行，可能导致与上游 DHCP 冲突。"));
        json_object_array_add(warnings, w);
    }
    json_object_object_add(data, "warnings", warnings);

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ══════════════════════════════════════════════════════════════════════
 * dreamingwrt_work_mode_preview
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *dw_work_mode_preview(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    const char *target = wm_json_str(req, "target_mode", "gateway");
    int target_mode = wm_mode_int(target);
    int current_mode = wm_read_mode();
    int same_mode;

    if (target_mode < 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_target_mode"));
        json_object_object_add(data, "requested_mode", json_object_new_string(target));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    same_mode = target_mode == current_mode;

    json_object_object_add(data, "target_mode", json_object_new_string(target_mode ? "side-router" : "gateway"));
    json_object_object_add(data, "requested_mode", json_object_new_string(target));
    wm_add_side_router_contract(data, current_mode);
    json_object_object_add(data, "current_mode", json_object_new_string(wm_mode_str(current_mode)));

    /* What will change */
    struct json_object *changes = json_object_new_array();
    json_object_array_add(changes, json_object_new_string("config.db:work_mode_settings"));
    if (target_mode == 1) {
        /* bypass: will modify network.lan, dhcp, firewall */
        json_object_array_add(changes, json_object_new_string("network.lan"));
        json_object_array_add(changes, json_object_new_string("dhcp.lan"));
        json_object_array_add(changes, json_object_new_string("firewall.zone(name=wan)"));
        json_object_array_add(changes, json_object_new_string("dreamingwrt.runtime"));
    } else {
        /* gateway: restore */
        json_object_array_add(changes, json_object_new_string("network.lan"));
        json_object_array_add(changes, json_object_new_string("dhcp.lan"));
        json_object_array_add(changes, json_object_new_string("firewall.zone(name=wan)"));
        json_object_array_add(changes, json_object_new_string("dreamingwrt.runtime"));
    }
    json_object_object_add(data, "will_change", changes);

    /* Get target params */
    const char *lan_ip = wm_json_str(req, "lan_ip", "");
    const char *gateway = wm_json_str(req, "gateway", "");
    int disable_dhcp = wm_json_bool(req, "disable_dhcp", target_mode == 1);

    /* Auto-detect if not provided */
    char auto_ip[64] = "", auto_gw[64] = "";
    if (!lan_ip[0]) {
        struct json_object *mgmt = json_object_new_object();
        wm_detect_lan(mgmt);
        struct json_object *v = json_object_object_get(mgmt, "lan_ip");
        if (v) snprintf(auto_ip, sizeof(auto_ip), "%s", json_object_get_string(v));
        json_object_put(mgmt);
        lan_ip = auto_ip;
    }
    if (!gateway[0]) {
        struct json_object *up = json_object_new_object();
        wm_detect_upstream(up);
        struct json_object *v = json_object_object_get(up, "upstream_gateway");
        if (v) snprintf(auto_gw, sizeof(auto_gw), "%s", json_object_get_string(v));
        json_object_put(up);
        if (!auto_gw[0])
            (void)wm_configured_upstream_gateway(auto_gw, sizeof(auto_gw));
        gateway = auto_gw;
    }

    /* Build management URL */
    char mgmt_url[256] = "";
    if (lan_ip[0])
        snprintf(mgmt_url, sizeof(mgmt_url), "http://%s/cgi-bin/luci/", lan_ip);
    json_object_object_add(data, "new_management_url", json_object_new_string(mgmt_url));

    /* Warnings */
    struct json_object *warnings = json_object_new_array();
    int ok = 1;

    if (same_mode) {
        struct json_object *w = json_object_new_object();
        json_object_object_add(w, "level", json_object_new_string("info"));
        json_object_object_add(w, "code", json_object_new_string("reconcile_current_mode"));
        json_object_object_add(w, "message", json_object_new_string("当前 authority 已是目标模式；应用将重新投影 UCI、路由和服务运行态。"));
        json_object_array_add(warnings, w);
    }

    if (target_mode == 1) {
        /* bypass checks */
        if (!lan_ip[0]) {
            ok = 0;
            struct json_object *w = json_object_new_object();
            json_object_object_add(w, "level", json_object_new_string("error"));
            json_object_object_add(w, "code", json_object_new_string("no_lan_ip"));
            json_object_object_add(w, "message", json_object_new_string("无法检测 LAN IP，旁路由模式必须有管理地址。"));
            json_object_array_add(warnings, w);
        }
        if (!gateway[0]) {
            ok = 0;
            struct json_object *w = json_object_new_object();
            json_object_object_add(w, "level", json_object_new_string("error"));
            json_object_object_add(w, "code", json_object_new_string("no_upstream_gateway"));
            json_object_object_add(w, "message", json_object_new_string("未检测到上游网关，旁路由模式需要上游网关才能正常工作。"));
            json_object_array_add(warnings, w);
        }
        if (lan_ip[0] && gateway[0]) {
            /* Check upstream reachability */
            double lat = wm_ping_check(gateway);
            if (lat < 0) {
                struct json_object *w = json_object_new_object();
                json_object_object_add(w, "level", json_object_new_string("warning"));
                json_object_object_add(w, "code", json_object_new_string("upstream_unreachable"));
                json_object_object_add(w, "message", json_object_new_string("上游网关不可达，切换后可能丢失管理入口。"));
                json_object_array_add(warnings, w);
            }
        }
        if (wm_dhcp_active() > 0) {
            struct json_object *w = json_object_new_object();
            json_object_object_add(w, "level", json_object_new_string("medium"));
            json_object_object_add(w, "code", json_object_new_string("dhcp_conflict_possible"));
            json_object_object_add(w, "message", json_object_new_string("检测到本机 DHCP 服务正在运行，旁路由模式建议关闭本机 DHCP 以避免冲突。"));
            json_object_array_add(warnings, w);
        }
        if (!disable_dhcp) {
            struct json_object *w = json_object_new_object();
            json_object_object_add(w, "level", json_object_new_string("info"));
            json_object_object_add(w, "code", json_object_new_string("dhcp_kept_enabled"));
            json_object_object_add(w, "message", json_object_new_string("旁路由模式下 DHCP 保持开启，请确保上游没有其他 DHCP 服务器。"));
            json_object_array_add(warnings, w);
        }
    }

    json_object_object_add(data, "ok", json_object_new_boolean(ok));
    json_object_object_add(data, "warnings", warnings);

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ══════════════════════════════════════════════════════════════════════
 * dreamingwrt_work_mode_apply
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *dw_work_mode_apply(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    const char *target = wm_json_str(req, "target_mode", "gateway");
    int target_mode = wm_mode_int(target);
    int current_mode = wm_read_mode();
    int reconcile;

    if (target_mode < 0) {
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_target_mode"));
        json_object_object_add(data, "requested_mode", json_object_new_string(target));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    reconcile = target_mode == current_mode;

    /* Generate rollback ID */
    char rollback_id[64];
    snprintf(rollback_id, sizeof(rollback_id), "wm_%lld_%ld_%lu",
             (long long)wm_now(), (long)getpid(),
             __sync_add_and_fetch(&wm_rollback_sequence, 1));

    /* Step 1: Backup configs */
    if (wm_backup_config(rollback_id, "network") != 0 ||
        wm_backup_config(rollback_id, "dhcp") != 0 ||
        wm_backup_config(rollback_id, "firewall") != 0 ||
        wm_snapshot_lan_default_route(rollback_id) != 0) {
        json_object_object_add(data, "error", json_object_new_string("runtime_backup_failed"));
        json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Get params */
    const char *lan_ip = wm_json_str(req, "lan_ip", "");
    const char *gateway = wm_json_str(req, "gateway", "");
    const char *dns1 = wm_json_array_str(req, "dns", 0);
    const char *dns2 = wm_json_array_str(req, "dns", 1);
    int disable_dhcp = target_mode == 0 ? 0 :
        wm_json_bool(req, "disable_dhcp", 1);
    int disable_nat = target_mode == 1;
    int previous_mode = current_mode;

    /* Auto-detect LAN IP if not provided */
    char auto_ip[64] = "", auto_gw[64] = "", auto_nm[64] = "255.255.255.0";
    if (!lan_ip[0]) {
        struct json_object *mgmt = json_object_new_object();
        wm_detect_lan(mgmt);
        struct json_object *v = json_object_object_get(mgmt, "lan_ip");
        if (v) snprintf(auto_ip, sizeof(auto_ip), "%s", json_object_get_string(v));
        v = json_object_object_get(mgmt, "lan_netmask");
        if (v) snprintf(auto_nm, sizeof(auto_nm), "%s", json_object_get_string(v));
        json_object_put(mgmt);
        lan_ip = auto_ip;
    }
    if (!gateway[0]) {
        struct json_object *up = json_object_new_object();
        wm_detect_upstream(up);
        struct json_object *v = json_object_object_get(up, "upstream_gateway");
        if (v) snprintf(auto_gw, sizeof(auto_gw), "%s", json_object_get_string(v));
        json_object_put(up);
        if (!auto_gw[0])
            (void)wm_configured_upstream_gateway(auto_gw, sizeof(auto_gw));
        gateway = auto_gw;
    }

    if (target_mode == 1 && (!lan_ip[0] || !gateway[0])) {
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string(
            !lan_ip[0] ? "management_ip_required" : "upstream_gateway_required"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Step 2: Validate - management IP must be reachable */
    if (target_mode == 1 && lan_ip[0] && gateway[0]) {
        if (!wm_same_subnet(lan_ip, gateway, auto_nm)) {
            /* Not same subnet - might lose access */
            json_object_object_add(data, "changed", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string("management_ip_not_in_upstream_subnet"));
            json_object_object_add(data, "message", json_object_new_string("管理 IP 与上游网关不在同一网段，切换后将丢失管理入口。"));
            json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
            return jmx_gen_api_response_data(API_CODE_ERROR, data);
        }
    }

    if (jmx_work_mode_config_begin_apply(target_mode, rollback_id,
                                         disable_dhcp, disable_nat,
                                         &previous_mode) != 0) {
        json_object_object_add(data, "error", json_object_new_string("config_db_transaction_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Step 3: project authority into native OpenWrt runtime configs. */
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        jmx_work_mode_config_finish_apply(0, "uci_alloc_failed");
        json_object_object_add(data, "error", json_object_new_string("uci_alloc_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    int rc = 0;

    char key_buf[256];
    char dhcp_section[64] = "", lan_zone[64] = "", nat_zone[64] = "";
    struct json_object *projection = json_object_new_object();
    struct json_object *failures = json_object_new_array();

    if (wm_find_dhcp_section(ctx, dhcp_section, sizeof(dhcp_section)) != 0) {
        json_object_array_add(failures, json_object_new_string("dhcp.section"));
        rc = -1;
    }
    if (wm_find_nat_zone_section(ctx, nat_zone, sizeof(nat_zone)) != 0) {
        json_object_array_add(failures, json_object_new_string("firewall.wan_zone"));
        rc = -1;
    }
    if (wm_find_lan_zone_section(ctx, lan_zone, sizeof(lan_zone)) != 0) {
        json_object_array_add(failures, json_object_new_string("firewall.lan_zone"));
        rc = -1;
    }

    if (target_mode == 1) {
        /* ── Bypass mode ── */
        /* 3c. LAN: set static IP with gateway pointing upstream */
        if (lan_ip[0]) {
            if (wm_projection_record(projection, failures, "network.lan.proto",
                                     wm_uci_set(ctx, "network", "lan", "proto", "static")) != 0)
                rc = -1;
            if (wm_projection_record(projection, failures, "network.lan.ipaddr",
                                     wm_uci_set(ctx, "network", "lan", "ipaddr", lan_ip)) != 0)
                rc = -1;
            if (wm_projection_record(projection, failures, "network.lan.netmask",
                                     wm_uci_set(ctx, "network", "lan", "netmask", auto_nm)) != 0)
                rc = -1;
            if (gateway[0]) {
                if (wm_projection_record(projection, failures, "network.lan.gateway",
                                         wm_uci_set(ctx, "network", "lan", "gateway", gateway)) != 0)
                    rc = -1;
            }
            if (dns1 && dns1[0]) {
                char dns_buf[128];
                if (dns2 && dns2[0])
                    snprintf(dns_buf, sizeof(dns_buf), "%s %s", dns1, dns2);
                else
                    snprintf(dns_buf, sizeof(dns_buf), "%s", dns1);
                if (wm_projection_record(projection, failures, "network.lan.dns",
                                         wm_uci_set(ctx, "network", "lan", "dns", dns_buf)) != 0)
                    rc = -1;
            } else if (gateway[0]) {
                if (wm_projection_record(projection, failures, "network.lan.dns",
                                         wm_uci_set(ctx, "network", "lan", "dns", gateway)) != 0)
                    rc = -1;
            }
        }

        /* 3d. DHCP: optionally disable */
        if (dhcp_section[0]) {
            snprintf(key_buf, sizeof(key_buf), "dhcp.%s.ignore", dhcp_section);
            if (wm_projection_record(projection, failures, "dhcp.ignore",
                                     jmx_uci_set_value(ctx, key_buf, disable_dhcp ? "1" : "0")) != 0)
                rc = -1;
        }

        /* 3e. Side-router never masquerades LAN or WAN traffic. */
        if (lan_zone[0]) {
            snprintf(key_buf, sizeof(key_buf), "firewall.%s.masq", lan_zone);
            if (wm_projection_record(projection, failures, "firewall.lan.masq",
                                     jmx_uci_set_value(ctx, key_buf, "0")) != 0)
                rc = -1;
        }
        if (nat_zone[0]) {
            snprintf(key_buf, sizeof(key_buf), "firewall.%s.masq", nat_zone);
            if (wm_projection_record(projection, failures, "firewall.wan.masq",
                                     jmx_uci_set_value(ctx, key_buf, "0")) != 0)
                rc = -1;
        }
    } else {
        /* ── Gateway mode ── */
        /* Restore LAN to default gateway config */
        if (lan_ip[0]) {
            if (wm_projection_record(projection, failures, "network.lan.proto",
                                     wm_uci_set(ctx, "network", "lan", "proto", "static")) != 0)
                rc = -1;
            if (wm_projection_record(projection, failures, "network.lan.ipaddr",
                                     wm_uci_set(ctx, "network", "lan", "ipaddr", lan_ip)) != 0)
                rc = -1;
            if (wm_projection_record(projection, failures, "network.lan.netmask",
                                     wm_uci_set(ctx, "network", "lan", "netmask", auto_nm)) != 0)
                rc = -1;
            /* Remove gateway from LAN in gateway mode */
            snprintf(key_buf, sizeof(key_buf), "network.lan.gateway");
            if (wm_projection_record(projection, failures, "network.lan.gateway",
                                     jmx_uci_delete(ctx, key_buf)) != 0)
                rc = -1;
        }

        /* Re-enable DHCP */
        if (dhcp_section[0]) {
            snprintf(key_buf, sizeof(key_buf), "dhcp.%s.ignore", dhcp_section);
            if (wm_projection_record(projection, failures, "dhcp.ignore",
                                     jmx_uci_set_value(ctx, key_buf, "0")) != 0)
                rc = -1;
        }

        /* Re-enable NAT */
        if (lan_zone[0]) {
            snprintf(key_buf, sizeof(key_buf), "firewall.%s.masq", lan_zone);
            if (wm_projection_record(projection, failures, "firewall.lan.masq",
                                     jmx_uci_set_value(ctx, key_buf, "0")) != 0)
                rc = -1;
        }
        if (nat_zone[0]) {
            snprintf(key_buf, sizeof(key_buf), "firewall.%s.masq", nat_zone);
            if (wm_projection_record(projection, failures, "firewall.wan.masq",
                                     jmx_uci_set_value(ctx, key_buf, "1")) != 0)
                rc = -1;
        }
    }

    /* Step 4: Commit all */
    if (rc == 0 && wm_projection_record(projection, failures, "network.commit",
                                        jmx_uci_commit(ctx, "network")) != UCI_OK)
        rc = -1;
    if (rc == 0 && wm_projection_record(projection, failures, "dhcp.commit",
                                        jmx_uci_commit(ctx, "dhcp")) != UCI_OK)
        rc = -1;
    if (rc == 0 && wm_projection_record(projection, failures, "firewall.commit",
                                        jmx_uci_commit(ctx, "firewall")) != UCI_OK)
        rc = -1;
    uci_free_context(ctx);
    if (rc == 0 && wm_uci_readback(target_mode, lan_ip, auto_nm, gateway,
                                   disable_dhcp, disable_nat, failures) != 0) {
        wm_projection_mark_readback_failures(projection, failures);
        rc = -1;
    }

    if (rc == 0 && wm_projection_record(projection, failures, "runtime.reload",
                                        wm_reload_services()) != 0)
        rc = -1;
    if (rc == 0) {
        char lan_device[64] = "";
        int route_rc = wm_lan_device(lan_device, sizeof(lan_device));
        if (route_rc == 0)
            route_rc = target_mode == 1 ?
                wm_ensure_side_router_route(gateway, lan_device) :
                wm_remove_lan_default_route(lan_device);
        if (wm_projection_record(projection, failures, "runtime.route_apply", route_rc) != 0)
            rc = -1;
    }
    if (rc == 0 && wm_runtime_readback(target_mode, gateway, disable_dhcp, disable_nat,
                                       projection, failures) != 0)
        rc = -1;

    if (rc != 0) {
        int restore_rc = wm_restore_runtime_configs(rollback_id);
        if (restore_rc == 0 && wm_reload_services() != 0)
            restore_rc = -1;
        if (restore_rc == 0 &&
            wm_restore_lan_default_route(rollback_id, previous_mode) != 0)
            restore_rc = -1;
        const char *error = restore_rc == 0 ? "runtime_projection_failed" : "runtime_restore_failed";
        jmx_work_mode_config_finish_apply(0, error);
        json_object_object_add(data, "error", json_object_new_string(error));
        json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
        json_object_object_add(data, "projection", projection);
        json_object_object_add(data, "failed_fields", failures);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_work_mode_config_finish_apply(1, "") != 0) {
        int restore_rc = wm_restore_runtime_configs(rollback_id);
        if (restore_rc == 0)
            restore_rc = wm_reload_services();
        if (restore_rc == 0)
            restore_rc = wm_restore_lan_default_route(rollback_id, previous_mode);
        (void)restore_rc;
        jmx_work_mode_config_finish_apply(0, "config_db_finalize_failed");
        json_object_object_add(data, "error", json_object_new_string("config_db_finalize_failed"));
        json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
        json_object_object_add(data, "projection", projection);
        json_object_object_add(data, "failed_fields", failures);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Update kernel proc */
    extern void update_jmx_proc_u32_value(char *key, u_int32_t val);
    update_jmx_proc_u32_value("work_mode", target_mode);

    /* Build response */
    char mgmt_url[256] = "";
    if (lan_ip[0])
        snprintf(mgmt_url, sizeof(mgmt_url), "http://%s/cgi-bin/luci/", lan_ip);

    json_object_object_add(data, "changed", json_object_new_boolean(!reconcile));
    json_object_object_add(data, "reconciled", json_object_new_boolean(reconcile));
    json_object_object_add(data, "work_mode", json_object_new_string(wm_mode_str(target_mode)));
    json_object_object_add(data, "canonical_mode", json_object_new_string(wm_mode_str(target_mode)));
    json_object_object_add(data, "apply_state", json_object_new_string("ready"));
    json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
    json_object_object_add(data, "projection", projection);
    json_object_object_add(data, "failed_fields", failures);
    json_object_object_add(data, "new_management_url", json_object_new_string(mgmt_url));
    json_object_object_add(data, "message", json_object_new_string(reconcile ?
        "目标模式未变化；UCI、路由和服务运行态已重新对齐。" : target_mode == 1 ?
        "已切换到旁路由模式，并完成 UCI、路由和服务运行态回读。" :
        "已切换到网关模式，并完成 UCI、路由和服务运行态回读。"));

    /* Warnings */
    struct json_object *warnings = json_object_new_array();
    struct json_object *w = json_object_new_object();
    json_object_object_add(w, "level", json_object_new_string("info"));
    json_object_object_add(w, "code", json_object_new_string("runtime_verified"));
    json_object_object_add(w, "message", json_object_new_string("network、dnsmasq、firewall 与默认路由均已回读。"));
    json_object_array_add(warnings, w);
    json_object_object_add(data, "warnings", warnings);

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ══════════════════════════════════════════════════════════════════════
 * dreamingwrt_work_mode_rollback
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *dw_work_mode_rollback(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    const char *rollback_id = wm_json_str(req, "rollback_id", "");

    /* If no ID given, try last apply */
    char auto_id[64] = "";
    if (!rollback_id[0]) {
        int ignored_mode = 0;
        jmx_work_mode_config_get(&ignored_mode, auto_id, sizeof(auto_id), NULL, 0);
        rollback_id = auto_id;
    }

    if (!rollback_id[0]) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "message", json_object_new_string("没有可用的回滚快照。"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Check rollback dir exists */
    char dir[PATH_MAX];
    if (!wm_token_ok(rollback_id, 63) ||
        snprintf(dir, sizeof(dir), "%s/%s", WM_ROLLBACK_DIR, rollback_id) >=
            (int)sizeof(dir)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "message", json_object_new_string("回滚快照标识无效。"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "message", json_object_new_string("回滚快照不存在或已过期。"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    int mode = 0;
    if (jmx_work_mode_config_begin_rollback(rollback_id, &mode) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "message", json_object_new_string("回滚元数据不存在或已过期。"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Restore native runtime configs. */
    int restored = 0;
    restored += (wm_rollback_config(rollback_id, "network") == 0) ? 1 : 0;
    restored += (wm_rollback_config(rollback_id, "dhcp") == 0) ? 1 : 0;
    restored += (wm_rollback_config(rollback_id, "firewall") == 0) ? 1 : 0;

    /* Commit and reload */
    struct uci_context *ctx = uci_alloc_context();
    if (ctx) {
        int commit_rc = 0;
        if (jmx_uci_commit(ctx, "network") != UCI_OK) commit_rc = -1;
        if (jmx_uci_commit(ctx, "dhcp") != UCI_OK) commit_rc = -1;
        if (jmx_uci_commit(ctx, "firewall") != UCI_OK) commit_rc = -1;
        if (commit_rc != 0)
            restored = -1;
        uci_free_context(ctx);
    } else restored = -1;
    if (restored != 3) {
        jmx_work_mode_config_finish_rollback(0, rollback_id, "runtime_restore_failed");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("runtime_restore_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (wm_reload_services() != 0 ||
        wm_restore_lan_default_route(rollback_id, mode) != 0) {
        jmx_work_mode_config_finish_rollback(0, rollback_id, "runtime_reload_failed");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("runtime_reload_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_work_mode_config_finish_rollback(1, rollback_id, "") != 0) {
        jmx_work_mode_config_finish_rollback(0, rollback_id, "config_db_finalize_failed");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("config_db_finalize_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Update kernel proc with restored mode */
    extern void update_jmx_proc_u32_value(char *key, u_int32_t val);
    update_jmx_proc_u32_value("work_mode", mode);

    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "restored_configs", json_object_new_int(restored));
    json_object_object_add(data, "work_mode", json_object_new_string(wm_mode_str(mode)));
    json_object_object_add(data, "message", json_object_new_string("已回滚到切换前的配置，并完成网络服务与默认路由恢复。"));

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}
