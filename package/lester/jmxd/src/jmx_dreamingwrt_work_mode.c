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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <uci.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

#define WM_ROLLBACK_DIR "/tmp/dreamingwrt-network-rollback"

/* ── helpers ── */

static int64_t wm_now(void) { return (int64_t)time(NULL); }
static unsigned long wm_rollback_sequence;

static const char *wm_mode_str(int m)
{
    return m == 1 ? "bypass" : "gateway";
}

static int wm_mode_int(const char *s)
{
    if (s && strcmp(s, "bypass") == 0) return 1;
    return 0;
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

    if (jmx_work_mode_config_get(&m, NULL, 0, NULL, 0) != 0)
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
    FILE *fp = popen("ip route show default 2>/dev/null", "r");
    if (!fp) return;
    char line[512];
    if (fgets(line, sizeof(line), fp)) {
        /* parse "default via X.X.X.X dev eth1 ..." */
        char gw[64] = "", dev[32] = "";
        char *p;
        p = strstr(line, " via ");
        if (p) { p += 5; sscanf(p, "%63s", gw); }
        p = strstr(line, " dev ");
        if (p) { p += 5; sscanf(p, "%31s", dev); }
        if (gw[0]) json_object_object_add(out, "upstream_gateway", json_object_new_string(gw));
        if (dev[0]) json_object_object_add(out, "upstream_iface", json_object_new_string(dev));
    }
    pclose(fp);
}

/* Detect DHCP server status on LAN */
static int wm_dhcp_active(void)
{
    FILE *fp = popen("pgrep -f 'dnsmasq' >/dev/null 2>&1 && echo 1 || echo 0", "r");
    if (!fp) return 0;
    char c = '0';
    fscanf(fp, "%c", &c);
    pclose(fp);
    return c == '1';
}

/* Detect NAT/masquerade status */
static int wm_nat_active(void)
{
    FILE *fp = popen("nft list chain inet nat postrouting 2>/dev/null | grep -q masquerade && echo 1 || echo 0", "r");
    if (!fp) return 0;
    char c = '0';
    fscanf(fp, "%c", &c);
    pclose(fp);
    return c == '1';
}

/* Ping check (returns latency in ms, or -1 on failure) */
static double wm_ping_check(const char *host)
{
    if (!host || !host[0]) return -1;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s 2>/dev/null | grep 'time=' | sed 's/.*time=//;s/ .*//'", host);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    double ms = -1;
    if (fscanf(fp, "%lf", &ms) != 1) ms = -1;
    pclose(fp);
    return ms;
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
                           int disable_dhcp, int disable_nat)
{
    struct uci_context *ctx = uci_alloc_context();
    char value[128] = "";
    int ok = 1;

    if (!ctx)
        return -1;
#define WM_EXPECT(_key, _expected) do { \
    value[0] = '\0'; \
    if (jmx_uci_get_value(ctx, (_key), value, sizeof(value)) != 0 || \
        strcmp(value, (_expected))) ok = 0; \
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
            value[0])
            ok = 0;
    }
    WM_EXPECT("dhcp.@dnsmasq[0].ignore", disable_dhcp ? "1" : "0");
    WM_EXPECT("firewall.@zone[1].masq", disable_nat ? "0" : "1");
#undef WM_EXPECT
    uci_free_context(ctx);
    return ok ? 0 : -1;
}

/* Backup a UCI config file to rollback dir */
static int wm_backup_config(const char *rollback_id, const char *config_name)
{
    char dir[256], src[256], dst[256];
    snprintf(dir, sizeof(dir), "%s/%s", WM_ROLLBACK_DIR, rollback_id);
    mkdir(WM_ROLLBACK_DIR, 0755);
    mkdir(dir, 0755);
    snprintf(src, sizeof(src), "/etc/config/%s", config_name);
    snprintf(dst, sizeof(dst), "%s/%s", dir, config_name);
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
    char src[256], dst[256];
    snprintf(src, sizeof(src), "%s/%s/%s", WM_ROLLBACK_DIR, rollback_id, config_name);
    snprintf(dst, sizeof(dst), "/etc/config/%s", config_name);
    FILE *fi = fopen(src, "r");
    if (!fi) return -1;
    FILE *fo = fopen(dst, "w");
    if (!fo) { fclose(fi); return -1; }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fi)) > 0)
        fwrite(buf, 1, n, fo);
    fclose(fi);
    fclose(fo);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * dreamingwrt_work_mode_get
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *dw_work_mode_get(struct json_object *req)
{
    (void)req;
    struct json_object *data = json_object_new_object();
    int mode = wm_read_mode();

    json_object_object_add(data, "work_mode", json_object_new_string(wm_mode_str(mode)));
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
    json_object_object_add(svc, "dhcp_server", json_object_new_string(wm_dhcp_active() ? "enabled" : "disabled"));
    json_object_object_add(svc, "nat", json_object_new_string(wm_nat_active() ? "enabled" : "disabled"));
    json_object_object_add(svc, "dns_proxy", json_object_new_string("enabled")); /* dnsmasq always runs */
    json_object_object_add(data, "services", svc);

    /* available modes */
    struct json_object *modes = json_object_new_array();
    json_object_array_add(modes, json_object_new_string("gateway"));
    json_object_array_add(modes, json_object_new_string("bypass"));
    json_object_object_add(data, "available_modes", modes);

    /* warnings */
    struct json_object *warnings = json_object_new_array();
    if (mode == 1 && wm_dhcp_active()) {
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

    json_object_object_add(data, "target_mode", json_object_new_string(target));
    json_object_object_add(data, "current_mode", json_object_new_string(wm_mode_str(current_mode)));

    if (target_mode == current_mode) {
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "will_change", json_object_new_array());
        struct json_object *warnings = json_object_new_array();
        struct json_object *w = json_object_new_object();
        json_object_object_add(w, "level", json_object_new_string("info"));
        json_object_object_add(w, "code", json_object_new_string("already_in_mode"));
        json_object_object_add(w, "message", json_object_new_string("当前已是目标模式，无需切换。"));
        json_object_array_add(warnings, w);
        json_object_object_add(data, "warnings", warnings);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }

    /* What will change */
    struct json_object *changes = json_object_new_array();
    json_object_array_add(changes, json_object_new_string("config.db:work_mode_settings"));
    if (target_mode == 1) {
        /* bypass: will modify network.lan, dhcp, firewall */
        json_object_array_add(changes, json_object_new_string("network.lan"));
        json_object_array_add(changes, json_object_new_string("dhcp.@dnsmasq[0]"));
        json_object_array_add(changes, json_object_new_string("firewall.@zone[1]"));
        json_object_array_add(changes, json_object_new_string("dreamingwrt.runtime"));
    } else {
        /* gateway: restore */
        json_object_array_add(changes, json_object_new_string("network.lan"));
        json_object_array_add(changes, json_object_new_string("dhcp.@dnsmasq[0]"));
        json_object_array_add(changes, json_object_new_string("firewall.@zone[1]"));
        json_object_array_add(changes, json_object_new_string("dreamingwrt.runtime"));
    }
    json_object_object_add(data, "will_change", changes);

    /* Get target params */
    const char *lan_ip = wm_json_str(req, "lan_ip", "");
    const char *gateway = wm_json_str(req, "gateway", "");
    int disable_dhcp = wm_json_bool(req, "disable_dhcp", target_mode == 1);
    int disable_nat = wm_json_bool(req, "disable_nat", target_mode == 1);

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
            struct json_object *w = json_object_new_object();
            json_object_object_add(w, "level", json_object_new_string("warning"));
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
        if (wm_dhcp_active()) {
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

    if (target_mode == current_mode) {
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        json_object_object_add(data, "message", json_object_new_string("已经是目标模式"));
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }

    /* Generate rollback ID */
    char rollback_id[64];
    snprintf(rollback_id, sizeof(rollback_id), "wm_%lld_%ld_%lu",
             (long long)wm_now(), (long)getpid(),
             __sync_add_and_fetch(&wm_rollback_sequence, 1));

    /* Step 1: Backup configs */
    if (wm_backup_config(rollback_id, "network") != 0 ||
        wm_backup_config(rollback_id, "dhcp") != 0 ||
        wm_backup_config(rollback_id, "firewall") != 0) {
        json_object_object_add(data, "error", json_object_new_string("runtime_backup_failed"));
        json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Get params */
    const char *lan_ip = wm_json_str(req, "lan_ip", "");
    const char *gateway = wm_json_str(req, "gateway", "");
    const char *dns1 = wm_json_array_str(req, "dns", 0);
    const char *dns2 = wm_json_array_str(req, "dns", 1);
    int disable_dhcp = wm_json_bool(req, "disable_dhcp", target_mode == 1);
    int disable_nat = wm_json_bool(req, "disable_nat", target_mode == 1);

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
        gateway = auto_gw;
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
                                         disable_dhcp, disable_nat, NULL) != 0) {
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

    if (target_mode == 1) {
        /* ── Bypass mode ── */
        /* 3c. LAN: set static IP with gateway pointing upstream */
        if (lan_ip[0]) {
            rc |= wm_uci_set(ctx, "network", "lan", "proto", "static");
            rc |= wm_uci_set(ctx, "network", "lan", "ipaddr", lan_ip);
            rc |= wm_uci_set(ctx, "network", "lan", "netmask", auto_nm);
            if (gateway[0]) {
                rc |= wm_uci_set(ctx, "network", "lan", "gateway", gateway);
            }
            if (dns1 && dns1[0]) {
                char dns_buf[128];
                if (dns2 && dns2[0])
                    snprintf(dns_buf, sizeof(dns_buf), "%s %s", dns1, dns2);
                else
                    snprintf(dns_buf, sizeof(dns_buf), "%s", dns1);
                rc |= wm_uci_set(ctx, "network", "lan", "dns", dns_buf);
            } else if (gateway[0]) {
                rc |= wm_uci_set(ctx, "network", "lan", "dns", gateway);
            }
        }

        /* 3d. DHCP: optionally disable */
        snprintf(key_buf, sizeof(key_buf), "dhcp.@dnsmasq[0].ignore");
        rc |= jmx_uci_set_value(ctx, key_buf, disable_dhcp ? "1" : "0");

        /* 3e. Firewall: disable NAT/masquerade on LAN */
        /* Set forwarding from lan to lan (bypass, no NAT) when requested. */
        snprintf(key_buf, sizeof(key_buf), "firewall.@zone[1].masq");
        rc |= jmx_uci_set_value(ctx, key_buf, disable_nat ? "0" : "1");
    } else {
        /* ── Gateway mode ── */
        /* Restore LAN to default gateway config */
        if (lan_ip[0]) {
            rc |= wm_uci_set(ctx, "network", "lan", "proto", "static");
            rc |= wm_uci_set(ctx, "network", "lan", "ipaddr", lan_ip);
            rc |= wm_uci_set(ctx, "network", "lan", "netmask", auto_nm);
            /* Remove gateway from LAN in gateway mode */
            snprintf(key_buf, sizeof(key_buf), "network.lan.gateway");
            rc |= jmx_uci_delete(ctx, key_buf);
        }

        /* Re-enable DHCP */
        snprintf(key_buf, sizeof(key_buf), "dhcp.@dnsmasq[0].ignore");
        rc |= jmx_uci_set_value(ctx, key_buf, "0");

        /* Re-enable NAT */
        snprintf(key_buf, sizeof(key_buf), "firewall.@zone[1].masq");
        rc |= jmx_uci_set_value(ctx, key_buf, "1");
    }

    /* Step 4: Commit all */
    if (rc == 0 && jmx_uci_commit(ctx, "network") != UCI_OK) rc = -1;
    if (rc == 0 && jmx_uci_commit(ctx, "dhcp") != UCI_OK) rc = -1;
    if (rc == 0 && jmx_uci_commit(ctx, "firewall") != UCI_OK) rc = -1;
    uci_free_context(ctx);
    if (rc == 0 && wm_uci_readback(target_mode, lan_ip, auto_nm, gateway,
                                   disable_dhcp, disable_nat) != 0)
        rc = -1;

    if (rc != 0) {
        wm_rollback_config(rollback_id, "network");
        wm_rollback_config(rollback_id, "dhcp");
        wm_rollback_config(rollback_id, "firewall");
        jmx_work_mode_config_finish_apply(0, "runtime_projection_failed");
        json_object_object_add(data, "error", json_object_new_string("runtime_projection_failed"));
        json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_work_mode_config_finish_apply(1, "") != 0) {
        wm_rollback_config(rollback_id, "network");
        wm_rollback_config(rollback_id, "dhcp");
        wm_rollback_config(rollback_id, "firewall");
        jmx_work_mode_config_finish_apply(0, "config_db_finalize_failed");
        json_object_object_add(data, "error", json_object_new_string("config_db_finalize_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* Step 5: Reload services (async, don't block) */
    system("(sleep 1; /etc/init.d/network reload; /etc/init.d/dnsmasq restart; /etc/init.d/firewall reload) &");

    /* Update kernel proc */
    extern void update_jmx_proc_u32_value(char *key, u_int32_t val);
    update_jmx_proc_u32_value("work_mode", target_mode);

    /* Build response */
    char mgmt_url[256] = "";
    if (lan_ip[0])
        snprintf(mgmt_url, sizeof(mgmt_url), "http://%s/cgi-bin/luci/", lan_ip);

    json_object_object_add(data, "changed", json_object_new_boolean(1));
    json_object_object_add(data, "work_mode", json_object_new_string(wm_mode_str(target_mode)));
    json_object_object_add(data, "rollback_id", json_object_new_string(rollback_id));
    json_object_object_add(data, "new_management_url", json_object_new_string(mgmt_url));
    json_object_object_add(data, "message", json_object_new_string(target_mode == 1 ?
        "已切换到旁路由模式。网络服务正在重载，页面可能需要刷新。" :
        "已切换到网关模式。网络服务正在重载，页面可能需要刷新。"));

    /* Warnings */
    struct json_object *warnings = json_object_new_array();
    struct json_object *w = json_object_new_object();
    json_object_object_add(w, "level", json_object_new_string("info"));
    json_object_object_add(w, "code", json_object_new_string("reload_pending"));
    json_object_object_add(w, "message", json_object_new_string("网络/DHCP/防火墙正在重载，如果页面无法访问请等待 10 秒后刷新。"));
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
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/%s", WM_ROLLBACK_DIR, rollback_id);
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
    if (restored != 3 ||
        jmx_work_mode_config_finish_rollback(1, rollback_id, "") != 0) {
        jmx_work_mode_config_finish_rollback(0, rollback_id, "runtime_restore_failed");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("runtime_restore_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    system("(sleep 1; /etc/init.d/network reload; /etc/init.d/dnsmasq restart; /etc/init.d/firewall reload) &");

    /* Update kernel proc with restored mode */
    extern void update_jmx_proc_u32_value(char *key, u_int32_t val);
    update_jmx_proc_u32_value("work_mode", mode);

    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "restored_configs", json_object_new_int(restored));
    json_object_object_add(data, "work_mode", json_object_new_string(wm_mode_str(mode)));
    json_object_object_add(data, "message", json_object_new_string("已回滚到切换前的配置。网络服务正在重载。"));

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}
