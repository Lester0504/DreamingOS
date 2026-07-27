// SPDX-License-Identifier: GPL-2.0-or-later
#include "toolkit_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *toolkit_bin(const char *name, char *path, size_t path_len)
{
    static const char *dirs[] = { "/usr/sbin", "/usr/bin", "/sbin", "/bin", NULL };
    for (int i = 0; dirs[i]; i++) {
        snprintf(path, path_len, "%s/%s", dirs[i], name);
        if (access(path, X_OK) == 0) return path;
    }
    path[0] = 0;
    return NULL;
}

static int toolkit_hostname_ok(const char *hostname)
{
    size_t len = hostname ? strlen(hostname) : 0;
    if (!len || len > 253 || hostname[0] == '.' || hostname[len - 1] == '.') return 0;
    for (size_t i = 0; i < len; i++)
        if (!isalnum((unsigned char)hostname[i]) && hostname[i] != '.' && hostname[i] != '-') return 0;
    return 1;
}

static int toolkit_https_base_ok(const char *url)
{
    size_t len = url ? strlen(url) : 0;
    if (len < 9 || len > 700 || strncmp(url, "https://", 8) ||
        strchr(url + 8, '@') || strchr(url, '#')) return 0;
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)url[i] < 0x20 || (unsigned char)url[i] == 0x7f) return 0;
    return 1;
}

static int toolkit_lan_ifname_ok(const char *ifname)
{
    char path[256], raw[32] = "";
    FILE *fp;
    if (!toolkit_ifname_ok(ifname)) return 0;
    if (!strncmp(ifname, "br-", 3) || !strncmp(ifname, "lan", 3)) return 1;
    snprintf(path, sizeof(path), "/sys/class/net/%s/master/uevent", ifname);
    fp = fopen(path, "r");
    if (fp) { fread(raw, 1, sizeof(raw) - 1, fp); fclose(fp); }
    return strstr(raw, "INTERFACE=br-") != NULL;
}

static struct json_object *toolkit_capabilities(void)
{
    char path[128];
    struct json_object *o = json_object_new_object();
    int tc = toolkit_bin("tc", path, sizeof(path)) != NULL;
    int iperf3 = toolkit_bin("iperf3", path, sizeof(path)) != NULL;
    json_object_object_add(o, "router_check", json_object_new_boolean(1));
    json_object_object_add(o, "wake_on_lan", json_object_new_boolean(1));
    json_object_object_add(o, "port_mirror", json_object_new_boolean(tc));
    json_object_object_add(o, "port_mirror_backend", json_object_new_string(tc ? "tc_clsact_matchall_mirred" : "unavailable"));
    json_object_object_add(o, "tc_available", json_object_new_boolean(tc));
    json_object_object_add(o, "sched_core_loaded", json_object_new_boolean(
        access("/sys/module/act_mirred", F_OK) == 0 && access("/sys/module/cls_matchall", F_OK) == 0));
    json_object_object_add(o, "throughput", json_object_new_boolean(iperf3));
    json_object_object_add(o, "throughput_backend", json_object_new_string(iperf3 ? "iperf3" : "unavailable"));
    json_object_object_add(o, "ddns", json_object_new_boolean(1));
    json_object_object_add(o, "ddns_secret_encryption", json_object_new_string("aes-256-gcm"));
    return o;
}

struct json_object *toolkit_status(void)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "worker", json_object_new_string("dreamingwrt-toolkit"));
    json_object_object_add(data, "execution_model", json_object_new_string("on_demand_one_shot"));
    json_object_object_add(data, "resident", json_object_new_boolean(0));
    json_object_object_add(data, "capabilities", toolkit_capabilities());
    return toolkit_success(data, "dreamingwrt-toolkit.status");
}

static void toolkit_check_add(struct json_object *checks, const char *id, const char *label,
                              const char *status, const char *summary,
                              const char *evidence, const char *remediation)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "label", json_object_new_string(label));
    json_object_object_add(o, "status", json_object_new_string(status));
    json_object_object_add(o, "summary", json_object_new_string(summary));
    json_object_object_add(o, "evidence", json_object_new_string(evidence ? evidence : ""));
    json_object_object_add(o, "remediation", json_object_new_string(remediation ? remediation : ""));
    json_object_array_add(checks, o);
}

static int toolkit_proc_running(const char *name)
{
    DIR *dir = opendir("/proc");
    struct dirent *e;
    char path[128], comm[128];
    if (!dir) return 0;
    while ((e = readdir(dir))) {
        FILE *fp;
        if (e->d_type != DT_DIR || e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
        fp = fopen(path, "r");
        if (fp && fgets(comm, sizeof(comm), fp)) {
            comm[strcspn(comm, "\r\n")] = 0;
            fclose(fp);
            if (!strcmp(comm, name) ||
                (strlen(name) > 15 && strlen(comm) == 15 && !strncmp(comm, name, 15))) {
                closedir(dir);
                return 1;
            }
        } else if (fp) fclose(fp);
    }
    closedir(dir);
    return 0;
}

struct json_object *toolkit_router_check(void)
{
    struct json_object *data = json_object_new_object(), *checks = json_object_new_array();
    struct statvfs fs;
    FILE *fp;
    long mem_total = 0, mem_avail = 0;
    char line[256], evidence[256];
    int errors = 0, warnings = 0;
    if (statvfs("/", &fs) == 0) {
        unsigned long long total = (unsigned long long)fs.f_blocks * fs.f_frsize;
        unsigned long long avail = (unsigned long long)fs.f_bavail * fs.f_frsize;
        int free_pct = total ? (int)(avail * 100 / total) : 0;
        snprintf(evidence, sizeof(evidence), "free=%llu total=%llu free_pct=%d", avail, total, free_pct);
        toolkit_check_add(checks, "storage", "存储状态", free_pct < 5 ? "error" : free_pct < 15 ? "warning" : "ok",
                          free_pct < 15 ? "根文件系统可用空间偏低" : "根文件系统空间正常", evidence,
                          free_pct < 15 ? "清理临时文件、日志或扩展 DATA 分区" : "");
        errors += free_pct < 5; warnings += free_pct >= 5 && free_pct < 15;
    } else toolkit_check_add(checks, "storage", "存储状态", "unavailable", "无法读取文件系统", strerror(errno), "检查挂载状态");
    fp = fopen("/proc/meminfo", "r");
    while (fp && fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %ld kB", &mem_total) == 1) continue;
        sscanf(line, "MemAvailable: %ld kB", &mem_avail);
    }
    if (fp) fclose(fp);
    if (mem_total > 0) {
        int avail_pct = (int)(mem_avail * 100 / mem_total);
        snprintf(evidence, sizeof(evidence), "available_kb=%ld total_kb=%ld available_pct=%d", mem_avail, mem_total, avail_pct);
        toolkit_check_add(checks, "memory", "内存状态", avail_pct < 5 ? "error" : avail_pct < 15 ? "warning" : "ok",
                          avail_pct < 15 ? "可用内存偏低" : "内存余量正常", evidence, avail_pct < 15 ? "检查高内存进程与 OOM 日志" : "");
        errors += avail_pct < 5; warnings += avail_pct >= 5 && avail_pct < 15;
    } else toolkit_check_add(checks, "memory", "内存状态", "unavailable", "无法读取内存数据", "/proc/meminfo unavailable", "检查 procfs");
    {
        char ip[128], out[1024]; int ec = 0;
        char *argv[] = { "/sbin/ip", "route", "show", "default", NULL };
        if (access(argv[0], X_OK) != 0) argv[0] = "/usr/sbin/ip";
        int rc = toolkit_exec_wait(argv, 1500, out, sizeof(out), &ec);
        snprintf(ip, sizeof(ip), "exit=%d route=%.90s", ec, out);
        toolkit_check_add(checks, "wan", "线路连通", rc == 0 && out[0] ? "ok" : "error",
                          rc == 0 && out[0] ? "检测到默认路由；未执行外网主动探测" : "未发现可用默认路由",
                          ip, "检查 WAN 状态与策略路由");
        errors += !(rc == 0 && out[0]);
    }
    toolkit_check_add(checks, "dhcp", "DHCP 服务", toolkit_proc_running("dnsmasq") ? "ok" : "error",
                      toolkit_proc_running("dnsmasq") ? "dnsmasq 正在运行" : "dnsmasq 未运行",
                      "process=dnsmasq", "检查 DHCP/DNS 配置并重启 dnsmasq");
    errors += !toolkit_proc_running("dnsmasq");
    {
        int ppp = access("/sys/class/net/pppoe-wan", F_OK) == 0 || toolkit_proc_running("pppd");
        toolkit_check_add(checks, "pppoe", "PPPoE 服务", ppp ? "ok" : "unavailable",
                          ppp ? "检测到 PPPoE 运行态" : "当前未检测到 PPPoE，可能使用 DHCP/静态 WAN",
                          ppp ? "pppd_or_pppoe_interface_present" : "no_pppoe_runtime", "");
    }
    toolkit_check_add(checks, "gateway_conflict", "网关冲突", "unavailable",
                      "未发现可证明的网关地址冲突", "active_arp_probe_not_run", "发现断续掉线时执行专项 ARP 冲突探测");
    {
        int core = toolkit_proc_running("dreamingwrt-core"), webd = toolkit_proc_running("dreamingwrt-webd");
        snprintf(evidence, sizeof(evidence), "core=%d webd=%d", core, webd);
        toolkit_check_add(checks, "core_services", "核心服务", core && webd ? "ok" : "error",
                          core && webd ? "核心服务正在运行" : "核心服务缺失", evidence, "运行 dreamingwrt-init status 并重启异常组件");
        errors += !(core && webd);
    }
    json_object_object_add(data, "checks", checks);
    json_object_object_add(data, "status", json_object_new_string(errors ? "error" : warnings ? "warning" : "ok"));
    json_object_object_add(data, "error_count", json_object_new_int(errors));
    json_object_object_add(data, "warning_count", json_object_new_int(warnings));
    json_object_object_add(data, "degraded", json_object_new_boolean(0));
    return toolkit_success(data, "dreamingwrt-toolkit.router_check");
}

struct json_object *toolkit_wake_on_lan(struct json_object *payload)
{
    const char *mac_text = toolkit_json_str(payload, "mac", "");
    const char *broadcast = toolkit_json_str(payload, "broadcast", "255.255.255.255");
    const char *ifname = toolkit_json_str(payload, "ifname", "br-lan");
    unsigned char mac[6], packet[102];
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(9) };
    int fd, yes = 1;
    if (toolkit_mac_parse(mac_text, mac) != 0 || inet_pton(AF_INET, broadcast, &dst.sin_addr) != 1 ||
        !toolkit_lan_ifname_ok(ifname)) return toolkit_error("invalid_wol_request", "MAC, broadcast, or LAN interface is invalid");
    memset(packet, 0xff, 6);
    for (int i = 0; i < 16; i++) memcpy(packet + 6 + i * 6, mac, 6);
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1) != 0 ||
        sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst)) != sizeof(packet)) {
        if (fd >= 0) close(fd);
        return toolkit_error("wol_send_failed", strerror(errno));
    }
    close(fd);
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "mac", json_object_new_string(mac_text));
    json_object_object_add(data, "broadcast", json_object_new_string(broadcast));
    json_object_object_add(data, "ifname", json_object_new_string(ifname));
    json_object_object_add(data, "bytes_sent", json_object_new_int(sizeof(packet)));
    json_object_object_add(data, "sent_at", json_object_new_int64(toolkit_now_s()));
    return toolkit_success(data, "dreamingwrt-toolkit.wol");
}

static int toolkit_tc_filter(const char *operation, const char *source, const char *target,
                             const char *hook, int add, char *evidence, size_t evidence_len)
{
    char tc[128], pref[16], out[2048]; int ec = 0;
    char *qdisc[] = { tc, "qdisc", "replace", "dev", (char *)source, "clsact", NULL };
    char *filter_add[] = { tc, "filter", "replace", "dev", (char *)source, (char *)hook,
        "pref", pref, "matchall", "action", "mirred", "egress", "mirror", "dev", (char *)target, NULL };
    char *filter_del[] = { tc, "filter", "del", "dev", (char *)source, (char *)hook, "pref", pref, NULL };
    (void)operation;
    if (!toolkit_bin("tc", tc, sizeof(tc))) return -2;
    snprintf(pref, sizeof(pref), "%d", !strcmp(hook, "ingress") ? TOOLKIT_TC_PREF : TOOLKIT_TC_PREF + 1);
    if (add && toolkit_exec_wait(qdisc, 2500, out, sizeof(out), &ec) != 0) {
        snprintf(evidence, evidence_len, "qdisc exit=%d %.300s", ec, out); return -1;
    }
    if (toolkit_exec_wait(add ? filter_add : filter_del, 2500, out, sizeof(out), &ec) != 0 && add) {
        snprintf(evidence, evidence_len, "filter exit=%d %.300s", ec, out); return -1;
    }
    snprintf(evidence, evidence_len, "tc dev=%s hook=%s pref=%s target=%s exit=%d", source, hook, pref, target, ec);
    return 0;
}

static int toolkit_mirror_apply(const char *source, const char *target, const char *direction,
                                int add, char *evidence, size_t evidence_len)
{
    char first[512] = "", second[512] = "";
    int rc = 0;
    if (!strcmp(direction, "ingress") || !strcmp(direction, "both"))
        rc = toolkit_tc_filter(add ? "add" : "delete", source, target, "ingress", add, first, sizeof(first));
    if (rc == 0 && (!strcmp(direction, "egress") || !strcmp(direction, "both")))
        rc = toolkit_tc_filter(add ? "add" : "delete", source, target, "egress", add, second, sizeof(second));
    snprintf(evidence, evidence_len, "%s%s%s", first, first[0] && second[0] ? "; " : "", second);
    return rc;
}

struct json_object *toolkit_port_mirror_list(void)
{
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object(), *items = json_object_new_array();
    if (sqlite3_prepare_v2(g_toolkit_db, "SELECT id,source_ifname,target_ifname,direction,enabled,updated_at FROM toolkit_port_mirror ORDER BY id", -1, &st, NULL) == SQLITE_OK)
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
            json_object_object_add(o, "source_ifname", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(o, "target_ifname", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
            json_object_object_add(o, "direction", json_object_new_string((const char *)sqlite3_column_text(st, 3)));
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_array_add(items, o);
        }
    if (st) sqlite3_finalize(st);
    json_object_object_add(data, "items", items); json_object_object_add(data, "capabilities", toolkit_capabilities());
    return toolkit_success(data, "dreamingwrt-toolkit.port_mirror");
}

struct json_object *toolkit_port_mirror_set(struct json_object *payload)
{
    const char *source = toolkit_json_str(payload, "source_ifname", "");
    const char *target = toolkit_json_str(payload, "target_ifname", "");
    const char *direction = toolkit_json_str(payload, "direction", "both");
    const char *id = toolkit_json_str(payload, "id", "");
    char generated[80], evidence[1024], old_source[16] = "", old_target[16] = "", old_direction[16] = "";
    sqlite3_stmt *st = NULL;
    if (!id[0]) { snprintf(generated, sizeof(generated), "mirror-%s-%s", source, target); id = generated; }
    if (!toolkit_token_ok(id, 64) || !toolkit_ifname_ok(source) || !toolkit_ifname_ok(target) || !strcmp(source, target) ||
        (strcmp(direction, "ingress") && strcmp(direction, "egress") && strcmp(direction, "both")))
        return toolkit_error("invalid_port_mirror", "interfaces, id, or direction is invalid");
    if (sqlite3_prepare_v2(g_toolkit_db,
        "SELECT source_ifname,target_ifname,direction FROM toolkit_port_mirror WHERE id=?1",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(old_source, sizeof(old_source), "%s", sqlite3_column_text(st, 0));
            snprintf(old_target, sizeof(old_target), "%s", sqlite3_column_text(st, 1));
            snprintf(old_direction, sizeof(old_direction), "%s", sqlite3_column_text(st, 2));
        }
        sqlite3_finalize(st); st = NULL;
    }
    if (old_source[0] && (strcmp(old_source, source) || strcmp(old_target, target) ||
                          strcmp(old_direction, direction)))
        toolkit_mirror_apply(old_source, old_target, old_direction, 0, evidence, sizeof(evidence));
    int rc = toolkit_mirror_apply(source, target, direction, 1, evidence, sizeof(evidence));
    if (rc == -2) return toolkit_error("capability_unavailable", "tc is unavailable");
    if (rc != 0) return toolkit_error("port_mirror_apply_failed", evidence);
    if (sqlite3_prepare_v2(g_toolkit_db, "INSERT OR REPLACE INTO toolkit_port_mirror(id,source_ifname,target_ifname,direction,enabled,updated_at) VALUES(?1,?2,?3,?4,1,?5)", -1, &st, NULL) != SQLITE_OK)
        return toolkit_error("storage_error", "port mirror state could not be saved");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, target, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, direction, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, toolkit_now_s());
    int ok = sqlite3_step(st) == SQLITE_DONE; sqlite3_finalize(st);
    if (!ok) { toolkit_mirror_apply(source, target, direction, 0, evidence, sizeof(evidence)); return toolkit_error("storage_error", "port mirror state could not be committed"); }
    struct json_object *data = json_object_new_object(); json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "source_ifname", json_object_new_string(source)); json_object_object_add(data, "target_ifname", json_object_new_string(target));
    json_object_object_add(data, "direction", json_object_new_string(direction)); json_object_object_add(data, "evidence", json_object_new_string(evidence));
    return toolkit_success(data, "dreamingwrt-toolkit.port_mirror");
}

struct json_object *toolkit_port_mirror_delete(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", ""); sqlite3_stmt *st = NULL;
    char source[16] = "", target[16] = "", direction[16] = "", evidence[1024];
    if (!toolkit_token_ok(id, 64) || sqlite3_prepare_v2(g_toolkit_db, "SELECT source_ifname,target_ifname,direction FROM toolkit_port_mirror WHERE id=?1", -1, &st, NULL) != SQLITE_OK)
        return toolkit_error("invalid_port_mirror_id", "port mirror id is invalid");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) { snprintf(source, sizeof(source), "%s", sqlite3_column_text(st, 0)); snprintf(target, sizeof(target), "%s", sqlite3_column_text(st, 1)); snprintf(direction, sizeof(direction), "%s", sqlite3_column_text(st, 2)); }
    sqlite3_finalize(st);
    if (!source[0]) return toolkit_error("port_mirror_not_found", "port mirror was not found");
    toolkit_mirror_apply(source, target, direction, 0, evidence, sizeof(evidence));
    if (sqlite3_prepare_v2(g_toolkit_db, "DELETE FROM toolkit_port_mirror WHERE id=?1", -1, &st, NULL) == SQLITE_OK) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st); }
    struct json_object *data = json_object_new_object(); json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1)); json_object_object_add(data, "evidence", json_object_new_string(evidence));
    return toolkit_success(data, "dreamingwrt-toolkit.port_mirror");
}

void toolkit_port_mirror_restore(void) { }

struct toolkit_curl_buffer { char *data; size_t len; size_t cap; };

static size_t toolkit_curl_write(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct toolkit_curl_buffer *b = opaque;
    size_t bytes = size * nmemb;
    char *next;
    if (!b || bytes > 1024 * 1024 || b->len > 1024 * 1024 - bytes) return 0;
    if (b->len + bytes + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + bytes + 1) cap *= 2;
        next = realloc(b->data, cap);
        if (!next) return 0;
        b->data = next; b->cap = cap;
    }
    memcpy(b->data + b->len, ptr, bytes); b->len += bytes; b->data[b->len] = 0;
    return bytes;
}

static int toolkit_public_ipv4(const char *ifname, char out[INET_ADDRSTRLEN])
{
    struct ifaddrs *list = NULL, *it;
    out[0] = 0;
    if (getifaddrs(&list) != 0) return -1;
    for (it = list; it; it = it->ifa_next) {
        struct sockaddr_in *sin;
        uint32_t ip;
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET ||
            (ifname && ifname[0] && strcmp(ifname, it->ifa_name))) continue;
        sin = (struct sockaddr_in *)it->ifa_addr; ip = ntohl(sin->sin_addr.s_addr);
        if ((ip >> 24) == 127 || (ip >> 24) == 10 || (ip >> 20) == 0xac1 ||
            (ip >> 16) == 0xc0a8 || (ip >> 16) == 0xa9fe) continue;
        inet_ntop(AF_INET, &sin->sin_addr, out, INET_ADDRSTRLEN); break;
    }
    freeifaddrs(list);
    return out[0] ? 0 : -1;
}

struct json_object *toolkit_ddns_update(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", "");
    char resolved_id[80] = "";
    char *provider = NULL, *hostname = NULL, *ifname = NULL, *config_raw = NULL, *secret_raw = NULL;
    struct json_object *config = NULL, *secret = NULL, *response = NULL;
    char address[INET_ADDRSTRLEN], url[1024], auth[1200], body[1024], error[CURL_ERROR_SIZE] = "";
    const char *token, *zone_id, *record_id, *custom_url;
    struct toolkit_curl_buffer buffer = {};
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    long status = 0;
    int ok = 0;
    if (!id[0]) {
        const char *request_provider = toolkit_json_str(payload, "provider", "");
        const char *request_hostname = toolkit_json_str(payload, "hostname", "");
        sqlite3_stmt *lookup = NULL;
        if (request_provider[0] && request_hostname[0] &&
            sqlite3_prepare_v2(g_toolkit_db,
                "SELECT id FROM toolkit_ddns WHERE provider=?1 AND hostname=?2 AND enabled=1 ORDER BY updated_at DESC LIMIT 1",
                -1, &lookup, NULL) == SQLITE_OK) {
            sqlite3_bind_text(lookup, 1, request_provider, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(lookup, 2, request_hostname, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(lookup) == SQLITE_ROW)
                snprintf(resolved_id, sizeof(resolved_id), "%s", sqlite3_column_text(lookup, 0));
            sqlite3_finalize(lookup);
        }
        id = resolved_id;
    }
    if (!toolkit_token_ok(id, 64)) return toolkit_error("ddns_not_found", "No saved DDNS configuration matches this request");
    secret_raw = toolkit_ddns_secret_for_id(id, &provider, &hostname, &ifname, &config_raw);
    if (!provider || !toolkit_hostname_ok(hostname) || !config_raw) goto unavailable;
    config = json_tokener_parse(config_raw); secret = secret_raw ? json_tokener_parse(secret_raw) : NULL;
    if (!config || !json_object_is_type(config, json_type_object) || !secret || !json_object_is_type(secret, json_type_object)) goto unavailable;
    if (toolkit_public_ipv4(ifname, address) != 0) {
        toolkit_ddns_record_result(id, 0, NULL, "no_public_ipv4_on_interface");
        response = toolkit_error("public_address_unavailable", "No public IPv4 address was found on the selected interface");
        goto done;
    }
    curl = curl_easy_init();
    if (!curl) goto unavailable;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, toolkit_curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    if (!strcmp(provider, "cloudflare")) {
        token = toolkit_json_str(secret, "api_token", toolkit_json_str(secret, "token", ""));
        zone_id = toolkit_json_str(config, "zone_id", ""); record_id = toolkit_json_str(config, "record_id", "");
        if (!token[0] || !toolkit_token_ok(zone_id, 80) || !toolkit_token_ok(record_id, 80)) goto unavailable;
        snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zone_id, record_id);
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
        snprintf(body, sizeof(body), "{\"type\":\"A\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":1,\"proxied\":false}", hostname, address);
        headers = curl_slist_append(headers, auth); headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT"); curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    } else if (!strcmp(provider, "custom")) {
        custom_url = toolkit_json_str(config, "update_url", "");
        token = toolkit_json_str(secret, "token", "");
        if (!toolkit_https_base_ok(custom_url)) goto unavailable;
        if (snprintf(url, sizeof(url), "%s%chostname=%s&ip=%s", custom_url,
                     strchr(custom_url, '?') ? '&' : '?', hostname, address) >= (int)sizeof(url))
            goto unavailable;
        if (token[0]) { snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token); headers = curl_slist_append(headers, auth); }
    } else {
        response = toolkit_error("provider_not_implemented", "This DDNS provider is not implemented by the current toolkit build");
        toolkit_ddns_record_result(id, 0, NULL, "provider_not_implemented");
        goto done;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url); if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (curl_easy_perform(curl) == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    ok = status >= 200 && status < 300;
    toolkit_ddns_record_result(id, ok, address, ok ? NULL : (error[0] ? error : "provider_rejected_update"));
    if (!ok) { response = toolkit_error("ddns_update_failed", error[0] ? error : "DDNS provider rejected update"); goto done; }
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "id", json_object_new_string(id)); json_object_object_add(data, "provider", json_object_new_string(provider));
        json_object_object_add(data, "hostname", json_object_new_string(hostname)); json_object_object_add(data, "address", json_object_new_string(address));
        json_object_object_add(data, "http_status", json_object_new_int64(status)); json_object_object_add(data, "updated_at", json_object_new_int64(toolkit_now_s()));
        response = toolkit_success(data, "dreamingwrt-toolkit.ddns_update");
    }
    goto done;
unavailable:
    response = toolkit_error("ddns_credentials_unavailable", "DDNS configuration or encrypted credentials are incomplete");
    if (id[0] && g_toolkit_db) toolkit_ddns_record_result(id, 0, NULL, "ddns_credentials_unavailable");
done:
    if (curl) curl_easy_cleanup(curl); if (headers) curl_slist_free_all(headers);
    free(buffer.data); free(provider); free(hostname); free(ifname); free(config_raw); free(secret_raw);
    if (config) json_object_put(config); if (secret) json_object_put(secret);
    return response;
}

static int toolkit_job_id_ok(const char *id)
{
    return id && !strncmp(id, "iperf-", 6) && toolkit_token_ok(id, 80) && !strchr(id, '/');
}

static int toolkit_iperf_pid_running(pid_t pid)
{
    char path[64], comm[64] = "";
    FILE *fp;
    if (pid <= 1 || kill(pid, 0) != 0) return 0;
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    fp = fopen(path, "r");
    if (!fp) return 0;
    fgets(comm, sizeof(comm), fp); fclose(fp);
    comm[strcspn(comm, "\r\n")] = 0;
    return !strcmp(comm, "iperf3");
}

static void toolkit_job_paths(const char *id, char *meta, size_t meta_len, char *result, size_t result_len)
{
    snprintf(meta, meta_len, "%s/%s.json", TOOLKIT_RUNTIME_DIR, id);
    snprintf(result, result_len, "%s/%s.result.json", TOOLKIT_RUNTIME_DIR, id);
}

static int toolkit_json_file_write(const char *path, struct json_object *o)
{
    char tmp[512]; const char *raw; int fd;
    snprintf(tmp, sizeof(tmp), "%s.tmp-%ld", path, (long)getpid());
    raw = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || !raw || write(fd, raw, strlen(raw)) != (ssize_t)strlen(raw) || fsync(fd) != 0) {
        if (fd >= 0) close(fd); unlink(tmp); return -1;
    }
    if (close(fd) != 0 || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static struct json_object *toolkit_json_file_read(const char *path)
{
    struct stat st; char *raw; struct json_object *o; int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > 2 * 1024 * 1024) { if (fd >= 0) close(fd); return NULL; }
    raw = malloc((size_t)st.st_size + 1); if (!raw) { close(fd); return NULL; }
    ssize_t got = read(fd, raw, (size_t)st.st_size); close(fd); if (got != st.st_size) { free(raw); return NULL; }
    raw[got] = 0; o = json_tokener_parse(raw); free(raw); return o;
}

struct json_object *toolkit_throughput_start(struct json_object *payload)
{
    const char *mode = toolkit_json_str(payload, "mode", "client"), *host = toolkit_json_str(payload, "host", "");
    const char *ifname = toolkit_json_str(payload, "ifname", ""), *actor = toolkit_json_str(payload, "actor", "");
    int port = toolkit_json_int(payload, "port", 5201), duration = toolkit_json_int(payload, "duration_s", 10);
    int parallel = toolkit_json_int(payload, "parallel", 1), reverse = toolkit_json_bool(payload, "reverse", 0);
    char iperf[128], id[96], meta_path[512], result_path[512], port_s[16], duration_s[16], parallel_s[16];
    char *argv[20]; int argc = 0, out_fd; pid_t pid; struct json_object *meta;
    if (!toolkit_bin("iperf3", iperf, sizeof(iperf))) return toolkit_error("capability_unavailable", "iperf3 is unavailable");
    if (strcmp(mode, "client") && strcmp(mode, "server")) return toolkit_error("invalid_throughput_mode", "mode must be client or server");
    if ((!strcmp(mode, "client") && !toolkit_token_ok(host, 253)) ||
        port < 1 || port > 65535 || duration < 1 || duration > 300 || parallel < 1 || parallel > 16 ||
        (ifname[0] && !toolkit_ifname_ok(ifname))) return toolkit_error("invalid_throughput_request", "throughput parameters are invalid");
    if (toolkit_runtime_dir_ready() != 0) return toolkit_error("runtime_storage_unavailable", "toolkit runtime directory is unavailable");
    snprintf(id, sizeof(id), "iperf-%lld-%ld", (long long)toolkit_now_s(), (long)getpid()); toolkit_job_paths(id, meta_path, sizeof(meta_path), result_path, sizeof(result_path));
    snprintf(port_s, sizeof(port_s), "%d", port); snprintf(duration_s, sizeof(duration_s), "%d", duration); snprintf(parallel_s, sizeof(parallel_s), "%d", parallel);
    argv[argc++] = iperf; argv[argc++] = "--json"; argv[argc++] = "--port"; argv[argc++] = port_s;
    if (!strcmp(mode, "client")) { argv[argc++] = "--client"; argv[argc++] = (char *)host; argv[argc++] = "--time"; argv[argc++] = duration_s; argv[argc++] = "--parallel"; argv[argc++] = parallel_s; if (reverse) argv[argc++] = "--reverse"; if (ifname[0]) { argv[argc++] = "--bind-dev"; argv[argc++] = (char *)ifname; } }
    else { argv[argc++] = "--server"; argv[argc++] = "--one-off"; }
    argv[argc] = NULL;
    out_fd = open(result_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600); if (out_fd < 0) return toolkit_error("throughput_start_failed", strerror(errno));
    pid = fork();
    if (pid < 0) { close(out_fd); unlink(result_path); return toolkit_error("throughput_start_failed", strerror(errno)); }
    if (pid == 0) { int nullfd = open("/dev/null", O_RDONLY); setsid(); if (nullfd >= 0) { dup2(nullfd, STDIN_FILENO); close(nullfd); } dup2(out_fd, STDOUT_FILENO); dup2(out_fd, STDERR_FILENO); close(out_fd); execv(iperf, argv); _exit(127); }
    close(out_fd);
    meta = json_object_new_object(); json_object_object_add(meta, "id", json_object_new_string(id)); json_object_object_add(meta, "pid", json_object_new_int(pid));
    json_object_object_add(meta, "actor", json_object_new_string(actor)); json_object_object_add(meta, "mode", json_object_new_string(mode)); json_object_object_add(meta, "host", json_object_new_string(host));
    json_object_object_add(meta, "port", json_object_new_int(port)); json_object_object_add(meta, "duration_s", json_object_new_int(duration)); json_object_object_add(meta, "started_at", json_object_new_int64(toolkit_now_s()));
    if (toolkit_json_file_write(meta_path, meta) != 0) { kill(pid, SIGTERM); json_object_put(meta); unlink(result_path); return toolkit_error("throughput_start_failed", "could not persist task metadata"); }
    json_object_object_add(meta, "state", json_object_new_string("running")); return toolkit_success(meta, "dreamingwrt-toolkit.throughput");
}

static int toolkit_job_owned(struct json_object *meta, struct json_object *payload)
{
    const char *owner = toolkit_json_str(meta, "actor", ""), *actor = toolkit_json_str(payload, "actor", "");
    return !owner[0] || (actor[0] && !strcmp(owner, actor));
}

struct json_object *toolkit_throughput_status(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", ""); char meta_path[512], result_path[512]; struct json_object *meta, *result = NULL;
    pid_t pid; int running;
    if (!toolkit_job_id_ok(id)) return toolkit_error("invalid_throughput_id", "throughput id is invalid");
    toolkit_job_paths(id, meta_path, sizeof(meta_path), result_path, sizeof(result_path)); meta = toolkit_json_file_read(meta_path);
    if (!meta || !toolkit_job_owned(meta, payload)) { if (meta) json_object_put(meta); return toolkit_error("throughput_not_found", "throughput task was not found"); }
    pid = (pid_t)toolkit_json_int(meta, "pid", 0); running = toolkit_iperf_pid_running(pid);
    json_object_object_add(meta, "state", json_object_new_string(running ? "running" : "completed"));
    if (!running) { result = toolkit_json_file_read(result_path); if (result) json_object_object_add(meta, "result", result); else json_object_object_add(meta, "reason", json_object_new_string("iperf3_result_unavailable")); }
    return toolkit_success(meta, "dreamingwrt-toolkit.throughput");
}

struct json_object *toolkit_throughput_stop(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", ""); char meta_path[512], result_path[512]; struct json_object *meta;
    pid_t pid;
    if (!toolkit_job_id_ok(id)) return toolkit_error("invalid_throughput_id", "throughput id is invalid");
    toolkit_job_paths(id, meta_path, sizeof(meta_path), result_path, sizeof(result_path)); meta = toolkit_json_file_read(meta_path);
    if (!meta || !toolkit_job_owned(meta, payload)) { if (meta) json_object_put(meta); return toolkit_error("throughput_not_found", "throughput task was not found"); }
    pid = (pid_t)toolkit_json_int(meta, "pid", 0); if (toolkit_iperf_pid_running(pid)) kill(-pid, SIGTERM);
    json_object_object_add(meta, "state", json_object_new_string("stopped")); json_object_object_add(meta, "stopped_at", json_object_new_int64(toolkit_now_s()));
    toolkit_json_file_write(meta_path, meta); return toolkit_success(meta, "dreamingwrt-toolkit.throughput");
}
