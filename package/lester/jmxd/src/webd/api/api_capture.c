// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Packet-capture subsystem (Phase 6V).
 *
 * The whole webd_capture_* / webd_topology_capture_* handler-definition
 * subsystem — the tcpdump child spawn (fork/execv under a timeout wrapper),
 * capture-meta load/write/refresh, the pcap-file pair store under
 * /tmp/dreamingwrt/captures with prune and byte/file quota, the safe
 * id/host/mac/ifname/protocol sanitisers, the tcpdump/timeout binary probe,
 * and the six webd_topology_capture_* response builders (start, stop, status,
 * list, delete, download). Lifted verbatim out of jmx_app_api.c.
 *
 * handle_client reaches this subsystem only via two response builders
 * (webd_topology_capture_response and webd_topology_capture_download_response),
 * which it DISPATCHES — they are not jmx_api_route table rows — so no route
 * moved. Both are declared in api_capture_internal.h.
 *
 * The WEBD_CAPTURE_* limit/path macros below lived in jmx_app_api.c's preamble
 * (above the moved region, so they did not travel with the bodies); they are
 * capture-only and move here with their values. app_read_first_line /
 * webd_path_ends_with (borrowed, defs stay in main) and the four non-static
 * identity/parse helpers come from api_capture_internal.h.
 *
 * This file is a pure extraction: no behaviour changed, no route moved.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <uci.h>

#include "../webd_http.h"
#include "webd_http_req.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "api_util.h"
#include "api_capture_internal.h"

/* Capture limit/path constants (moved verbatim from jmx_app_api.c's preamble). */
#define WEBD_CAPTURE_DIR "/tmp/dreamingwrt/captures"
#define WEBD_CAPTURE_DEFAULT_DURATION_S 30
#define WEBD_CAPTURE_MAX_DURATION_S 120
#define WEBD_CAPTURE_DEFAULT_PACKET_COUNT 2000
#define WEBD_CAPTURE_MAX_PACKET_COUNT 20000
#define WEBD_CAPTURE_DEFAULT_SNAPLEN 262144
#define WEBD_CAPTURE_MAX_SNAPLEN 262144
#define WEBD_CAPTURE_MAX_FILES 8
#define WEBD_CAPTURE_MAX_BYTES (128ULL * 1024ULL * 1024ULL)

static int webd_capture_mkdir(void)
{
    mkdir("/tmp/dreamingwrt", 0755);
    if (mkdir(WEBD_CAPTURE_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static const char *webd_capture_find_bin(const char *name, char *buf, size_t len)
{
    static const char *dirs[] = { "/usr/bin", "/usr/sbin", "/bin", "/sbin", NULL };
    int i;

    if (!name || !buf || len == 0)
        return "";
    for (i = 0; dirs[i]; i++) {
        if (snprintf(buf, len, "%s/%s", dirs[i], name) >= (int)len)
            continue;
        if (access(buf, X_OK) == 0)
            return buf;
    }
    buf[0] = '\0';
    return "";
}

static int webd_capture_available(void)
{
    char tcpdump[64];
    char timeout_bin[64];

    return webd_capture_find_bin("tcpdump", tcpdump, sizeof(tcpdump))[0] &&
           webd_capture_find_bin("timeout", timeout_bin, sizeof(timeout_bin))[0];
}

static struct json_object *webd_capture_capabilities(void)
{
    char tcpdump[64];
    char timeout_bin[64];
    const char *tcpdump_path = webd_capture_find_bin("tcpdump", tcpdump, sizeof(tcpdump));
    const char *timeout_path = webd_capture_find_bin("timeout", timeout_bin, sizeof(timeout_bin));
    struct json_object *cap = json_object_new_object();

    json_object_object_add(cap, "available", json_object_new_boolean(tcpdump_path[0] && timeout_path[0]));
    json_object_object_add(cap, "tcpdump", json_object_new_boolean(tcpdump_path[0] != '\0'));
    json_object_object_add(cap, "timeout", json_object_new_boolean(timeout_path[0] != '\0'));
    webd_obj_add_str(cap, "tcpdump_path", tcpdump_path);
    webd_obj_add_str(cap, "timeout_path", timeout_path);
    json_object_object_add(cap, "duration_default_s", json_object_new_int(WEBD_CAPTURE_DEFAULT_DURATION_S));
    json_object_object_add(cap, "duration_max_s", json_object_new_int(WEBD_CAPTURE_MAX_DURATION_S));
    json_object_object_add(cap, "packet_count_default", json_object_new_int(WEBD_CAPTURE_DEFAULT_PACKET_COUNT));
    json_object_object_add(cap, "packet_count_max", json_object_new_int(WEBD_CAPTURE_MAX_PACKET_COUNT));
    json_object_object_add(cap, "snaplen_default", json_object_new_int(WEBD_CAPTURE_DEFAULT_SNAPLEN));
    json_object_object_add(cap, "snaplen_max", json_object_new_int(WEBD_CAPTURE_MAX_SNAPLEN));
    json_object_object_add(cap, "max_files", json_object_new_int(WEBD_CAPTURE_MAX_FILES));
    json_object_object_add(cap, "max_bytes", json_object_new_int64((int64_t)WEBD_CAPTURE_MAX_BYTES));
    webd_obj_add_str(cap, "storage", WEBD_CAPTURE_DIR);
    json_object_object_add(cap, "write", json_object_new_boolean(0));
    webd_obj_add_str(cap, "reason", (tcpdump_path[0] && timeout_path[0]) ? "" : "tcpdump_or_timeout_missing");
    return cap;
}

static int webd_capture_safe_id(const char *id)
{
    return id && id[0] && webd_safe_token(id) && !strstr(id, "..") && !strchr(id, '/');
}

static int webd_capture_safe_ifname(const char *ifname)
{
    char path[320];

    if (!ifname || !ifname[0] || !webd_safe_token(ifname) || strchr(ifname, '/'))
        return 0;
    if (!strcmp(ifname, "any"))
        return 1;
    if (snprintf(path, sizeof(path), "/sys/class/net/%s", ifname) >= (int)sizeof(path))
        return 0;
    return access(path, F_OK) == 0;
}

static int webd_capture_safe_mac(const char *mac)
{
    int i;

    if (!mac || !mac[0])
        return 1;
    if (strlen(mac) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':')
                return 0;
        } else if (!isxdigit((unsigned char)mac[i])) {
            return 0;
        }
    }
    return 1;
}

static int webd_capture_safe_host(const char *host)
{
    size_t i;

    if (!host || !host[0])
        return 1;
    if (strlen(host) > 253 || host[0] == '-' || strchr(host, '/'))
        return 0;
    for (i = 0; host[i]; i++) {
        unsigned char c = (unsigned char)host[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == ':'))
            return 0;
    }
    return 1;
}

static int webd_capture_safe_protocol(const char *proto)
{
    if (!proto || !proto[0])
        return 1;
    return !strcmp(proto, "tcp") || !strcmp(proto, "udp") ||
           !strcmp(proto, "icmp") || !strcmp(proto, "icmp6") ||
           !strcmp(proto, "ip") || !strcmp(proto, "ip6") ||
           !strcmp(proto, "arp");
}

static int webd_capture_log_event(const char *event_name, const char *title,
                                  struct json_object *meta,
                                  const char *actor_identity)
{
    struct json_object *event = NULL;
    struct json_object *detail = NULL;
    struct json_object *resp = NULL;
    const char *id = app_nc_json_str(meta, "id", "");
    const char *ifname = app_nc_json_str(meta, "ifname", "");
    const char *mac = app_nc_json_str(meta, "mac", "");
    const char *host = app_nc_json_str(meta, "host", "");
    const char *proto = app_nc_json_str(meta, "protocol", "");
    const char *state = app_nc_json_str(meta, "state", "");
    const char *capture_location = app_nc_json_str(meta, "capture_location", "local_gateway");
    const char *capture_host = app_nc_json_str(meta, "capture_host", "");
    const char *target_role = app_nc_json_str(meta, "target_device_role", "");
    const char *actor = actor_identity && actor_identity[0] ? actor_identity : "";
    const char *username;
    char dedupe[240];
    int ok = 0;

    if (!event_name || !event_name[0] || !meta)
        return -1;

    event = json_object_new_object();
    detail = json_object_new_object();
    if (!event || !detail)
        goto out;

    json_object_object_add(detail, "id", json_object_new_string(id));
    json_object_object_add(detail, "capture_id", json_object_new_string(id));
    json_object_object_add(detail, "state", json_object_new_string(state));
    json_object_object_add(detail, "ifname", json_object_new_string(ifname));
    json_object_object_add(detail, "interface", json_object_new_string(ifname));
    json_object_object_add(detail, "executor",
                           json_object_new_string(app_nc_json_str(meta, "executor", "dreamingwrt-webd")));
    json_object_object_add(detail, "execution_model",
                           json_object_new_string(app_nc_json_str(meta, "execution_model", "local_tcpdump")));
    json_object_object_add(detail, "capture_location", json_object_new_string(capture_location));
    json_object_object_add(detail, "capture_host", json_object_new_string(capture_host));
    json_object_object_add(detail, "capture_namespace",
                           json_object_new_string(app_nc_json_str(meta, "capture_namespace", "dreamingwrt")));
    json_object_object_add(detail, "target_device_role", json_object_new_string(target_role));
    json_object_object_add(detail, "remote_endpoint",
                           json_object_new_string(app_nc_json_str(meta, "remote_endpoint", "")));
    json_object_object_add(detail, "remote_capture",
                           json_object_new_boolean(app_nc_json_bool(meta, "remote_capture", 0)));
    json_object_object_add(detail, "depends_on_remote_device",
                           json_object_new_boolean(app_nc_json_bool(meta, "depends_on_remote_device", 0)));
    json_object_object_add(detail, "requires_remote_credentials",
                           json_object_new_boolean(app_nc_json_bool(meta, "requires_remote_credentials", 0)));
    json_object_object_add(detail, "uses_remote_api",
                           json_object_new_boolean(app_nc_json_bool(meta, "uses_remote_api", 0)));
    json_object_object_add(detail, "mac", json_object_new_string(mac));
    json_object_object_add(detail, "host", json_object_new_string(host));
    json_object_object_add(detail, "protocol", json_object_new_string(proto));
    json_object_object_add(detail, "port", json_object_new_int(app_nc_json_int(meta, "port", 0)));
    json_object_object_add(detail, "duration_s", json_object_new_int(app_nc_json_int(meta, "duration_s", 0)));
    json_object_object_add(detail, "packet_count", json_object_new_int(app_nc_json_int(meta, "packet_count", 0)));
    json_object_object_add(detail, "snaplen", json_object_new_int(app_nc_json_int(meta, "snaplen", 0)));
    json_object_object_add(detail, "pid", json_object_new_int(app_nc_json_int(meta, "pid", 0)));
    json_object_object_add(detail, "size_bytes",
                           json_object_new_int64(app_nc_json_int64(meta, "size_bytes", 0)));
    json_object_object_add(detail, "started_at",
                           json_object_new_int64(app_nc_json_int64(meta, "started_at", 0)));
    json_object_object_add(detail, "stopped_at",
                           json_object_new_int64(app_nc_json_int64(meta, "stopped_at", 0)));
    json_object_object_add(detail, "finished_at",
                           json_object_new_int64(app_nc_json_int64(meta, "finished_at", 0)));
    if (!actor[0])
        actor = app_nc_json_str(meta, "actor_identity", "");
    username = webd_identity_is_user(actor) ? webd_identity_username(actor) : "";
    json_object_object_add(detail, "download_url",
                           json_object_new_string(app_nc_json_str(meta, "download_url", "")));
    json_object_object_add(detail, "actor_identity", json_object_new_string(actor));
    /* Packet capture is an administrator operation, so mark it for the ledger
     * explicitly rather than relying on category='audit' alone. */
    json_object_object_add(detail, "source_id", json_object_new_string("audit"));
    json_object_object_add(detail, "web_audit", json_object_new_boolean(1));

    json_object_object_add(event, "severity", json_object_new_string("info"));
    json_object_object_add(event, "category", json_object_new_string("audit"));
    json_object_object_add(event, "event", json_object_new_string(event_name));
    json_object_object_add(event, "source", json_object_new_string("dreamingwrt-webd"));
    json_object_object_add(event, "iface", json_object_new_string(ifname));
    json_object_object_add(event, "mac", json_object_new_string(mac));
    if (username[0])
        json_object_object_add(event, "username", json_object_new_string(username));
    json_object_object_add(event, "actor", json_object_new_string(actor));
    json_object_object_add(event, "title", json_object_new_string(title && title[0] ? title : event_name));
    snprintf(dedupe, sizeof(dedupe), "topology_capture:%s:%s",
             event_name, id && id[0] ? id : "unknown");
    json_object_object_add(event, "dedupe_key", json_object_new_string(dedupe));
    json_object_object_add(event, "detail_json", detail);
    detail = NULL;

    resp = app_ubus_invoke_object_timeout("dreamingwrt.logd", "event_add", event, 500);
    ok = resp && app_nc_json_bool(resp, "ok", 0);

out:
    if (resp)
        json_object_put(resp);
    if (detail)
        json_object_put(detail);
    if (event)
        json_object_put(event);
    return ok ? 0 : -1;
}

static void webd_capture_path(char *out, size_t len, const char *id, const char *ext)
{
    if (!out || len == 0)
        return;
    snprintf(out, len, "%s/%s.%s", WEBD_CAPTURE_DIR, id ? id : "", ext ? ext : "pcap");
}

static int webd_capture_write_meta(struct json_object *meta)
{
    const char *id = app_nc_json_str(meta, "id", "");
    char path[320];
    char tmp[352];
    const char *s;
    int fd;

    if (!webd_capture_safe_id(id) || webd_capture_mkdir() != 0)
        return -1;
    webd_capture_path(path, sizeof(path), id, "json");
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp))
        return -1;
    s = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (webd_write_all(fd, s, strlen(s)) != 0 || webd_write_all(fd, "\n", 1) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    fsync(fd);
    close(fd);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static struct json_object *webd_capture_load_meta(const char *id)
{
    char path[320];

    if (!webd_capture_safe_id(id))
        return NULL;
    webd_capture_path(path, sizeof(path), id, "json");
    return json_object_from_file(path);
}

static int webd_capture_pid_alive(pid_t pid)
{
    if (pid <= 0)
        return 0;
    if (kill(pid, 0) == 0)
        return 1;
    return errno == EPERM;
}

static void webd_capture_add_download_fields(struct json_object *meta, const char *id)
{
    char url[256];

    snprintf(url, sizeof(url), "/api/v1/topology/capture/download?id=%s", id ? id : "");
    webd_obj_add_str(meta, "download_url", url);
    webd_obj_add_str(meta, "status_url", "/api/v1/topology/capture/status");
}

static const char *webd_capture_target_role(const char *ifname,
                                            const char *mac,
                                            const char *host)
{
    if ((mac && mac[0]) || (host && host[0]))
        return "downstream_client";
    if (ifname && !strncmp(ifname, "eth", 3))
        return "gateway_port";
    if (ifname && !strcmp(ifname, "any"))
        return "local_gateway";
    return "local_gateway";
}

static void webd_capture_local_host(char *out, size_t out_len, char *source, size_t source_len)
{
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr;
    char hostname[128] = "";

    if (out && out_len)
        out[0] = '\0';
    if (source && source_len)
        source[0] = '\0';
    if (!out || out_len == 0)
        return;

    ctx = uci_alloc_context();
    if (ctx) {
        char lookup[] = "network.lan.ipaddr";

        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) == UCI_OK &&
            ptr.o && ptr.o->v.string && ptr.o->v.string[0]) {
            snprintf(out, out_len, "%s", ptr.o->v.string);
            if (source && source_len)
                snprintf(source, source_len, "%s", "uci:network.lan.ipaddr");
        }
        uci_free_context(ctx);
    }
    if (out[0])
        return;

    app_read_first_line("/proc/sys/kernel/hostname", hostname, sizeof(hostname));
    snprintf(out, out_len, "%s", hostname[0] ? hostname : "DreamingWrt");
    if (source && source_len)
        snprintf(source, source_len, "%s", hostname[0] ? "hostname" : "fallback");
}

static void webd_capture_add_local_execution_fields(struct json_object *meta,
                                                    const struct http_req *req,
                                                    const char *ifname,
                                                    const char *mac,
                                                    const char *host)
{
    char capture_host[128] = "";
    char capture_host_source[64] = "";

    if (!meta)
        return;
    webd_capture_local_host(capture_host, sizeof(capture_host),
                            capture_host_source, sizeof(capture_host_source));
    webd_obj_add_str(meta, "executor", "dreamingwrt-webd");
    webd_obj_add_str(meta, "execution_model", "local_tcpdump");
    webd_obj_add_str(meta, "capture_location", "local_gateway");
    webd_obj_add_str(meta, "capture_namespace", "dreamingwrt");
    webd_obj_add_str(meta, "capture_host", capture_host);
    webd_obj_add_str(meta, "capture_host_source", capture_host_source);
    webd_obj_add_str(meta, "capture_peer", req && req->client_ip[0] ? req->client_ip : "");
    webd_obj_add_str(meta, "target_device_role", webd_capture_target_role(ifname, mac, host));
    webd_obj_add_str(meta, "remote_endpoint", "");
    json_object_object_add(meta, "remote_capture", json_object_new_boolean(0));
    json_object_object_add(meta, "depends_on_remote_device", json_object_new_boolean(0));
    json_object_object_add(meta, "requires_remote_credentials", json_object_new_boolean(0));
    json_object_object_add(meta, "uses_remote_api", json_object_new_boolean(0));
}

static void webd_capture_refresh_meta(struct json_object *meta, int persist)
{
    const char *id = app_nc_json_str(meta, "id", "");
    const char *state = app_nc_json_str(meta, "state", "");
    const char *pcap_path = app_nc_json_str(meta, "pcap_path", "");
    pid_t pid = (pid_t)app_nc_json_int(meta, "pid", 0);
    struct stat st;
    int alive = webd_capture_pid_alive(pid);
    int changed = 0;

    if (pcap_path[0] && stat(pcap_path, &st) == 0 && S_ISREG(st.st_mode))
        json_object_object_add(meta, "size_bytes", json_object_new_int64((int64_t)st.st_size));
    else
        json_object_object_add(meta, "size_bytes", json_object_new_int64(0));

    if (!strcmp(state, "running") || !strcmp(state, "stopping")) {
        if (!alive) {
            json_object_object_add(meta, "state", json_object_new_string("finished"));
            json_object_object_add(meta, "finished_at", json_object_new_int64(now_s()));
            if (!app_nc_json_bool(meta, "finished_logged", 0) &&
                webd_capture_log_event("packet_capture_finished",
                                       "Packet capture finished", meta, "") == 0)
                json_object_object_add(meta, "finished_logged", json_object_new_boolean(1));
            changed = 1;
        }
    }
    json_object_object_add(meta, "running", json_object_new_boolean(alive));
    json_object_object_add(meta, "download_available",
                           json_object_new_boolean(app_nc_json_int64(meta, "size_bytes", 0) > 0));
    json_object_object_add(meta, "updated_at", json_object_new_int64(now_s()));
    webd_capture_add_download_fields(meta, id);
    if (persist && changed)
        webd_capture_write_meta(meta);
}

static void webd_capture_remove_pair(const char *id)
{
    char path[320];

    if (!webd_capture_safe_id(id))
        return;
    webd_capture_path(path, sizeof(path), id, "pcap");
    unlink(path);
    webd_capture_path(path, sizeof(path), id, "json");
    unlink(path);
}

static int webd_capture_pair_exists(const char *id)
{
    char path[320];

    if (!webd_capture_safe_id(id))
        return 0;
    webd_capture_path(path, sizeof(path), id, "pcap");
    if (access(path, F_OK) == 0)
        return 1;
    webd_capture_path(path, sizeof(path), id, "json");
    return access(path, F_OK) == 0;
}

static void webd_capture_prune(void)
{
    DIR *d;
    struct dirent *de;
    int count = 0;
    unsigned long long total = 0;
    char oldest_id[192] = "";
    time_t oldest_mtime = 0;
    time_t now = (time_t)now_s();

    if (webd_capture_mkdir() != 0)
        return;
    d = opendir(WEBD_CAPTURE_DIR);
    if (!d)
        return;
    while ((de = readdir(d)) != NULL) {
        char full[384];
        char id[192];
        char *dot;
        struct stat st;

        if (!webd_path_ends_with(de->d_name, ".pcap"))
            continue;
        if (strlen(de->d_name) >= sizeof(id))
            continue;
        memcpy(id, de->d_name, strlen(de->d_name) + 1);
        dot = strrchr(id, '.');
        if (dot)
            *dot = '\0';
        if (!webd_capture_safe_id(id))
            continue;
        snprintf(full, sizeof(full), "%s/%s", WEBD_CAPTURE_DIR, de->d_name);
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (now > st.st_mtime && now - st.st_mtime > 3600) {
            webd_capture_remove_pair(id);
            continue;
        }
        count++;
        total += (unsigned long long)st.st_size;
        if (!oldest_id[0] || st.st_mtime < oldest_mtime) {
            snprintf(oldest_id, sizeof(oldest_id), "%s", id);
            oldest_mtime = st.st_mtime;
        }
    }
    closedir(d);
    while ((count > WEBD_CAPTURE_MAX_FILES || total > WEBD_CAPTURE_MAX_BYTES) && oldest_id[0]) {
        webd_capture_remove_pair(oldest_id);
        count--;
        break;
    }
}

static struct json_object *webd_topology_capture_status_response(const char *id,
                                                                 int *http_status)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *active = json_object_new_array();
    int total = 0;
    int running = 0;

    if (http_status)
        *http_status = 200;
    webd_capture_mkdir();
    if (id && id[0]) {
        struct json_object *meta = webd_capture_load_meta(id);

        if (!meta) {
            if (http_status)
                *http_status = 404;
            json_object_put(root);
            json_object_put(items);
            json_object_put(active);
            return webd_error("capture_not_found", "capture id was not found",
                              "id", "webd.topology_capture");
        }
        webd_capture_refresh_meta(meta, 1);
        json_object_array_add(items, meta);
        if (app_nc_json_bool(meta, "running", 0))
            json_object_array_add(active, json_object_get(meta));
        total = 1;
        running = app_nc_json_bool(meta, "running", 0) ? 1 : 0;
    } else {
        DIR *d = opendir(WEBD_CAPTURE_DIR);
        struct dirent *de;

        if (d) {
            while ((de = readdir(d)) != NULL) {
                char cap_id[192];
                char *dot;
                struct json_object *meta;

                if (!webd_path_ends_with(de->d_name, ".json"))
                    continue;
                if (strlen(de->d_name) >= sizeof(cap_id))
                    continue;
                memcpy(cap_id, de->d_name, strlen(de->d_name) + 1);
                dot = strrchr(cap_id, '.');
                if (dot)
                    *dot = '\0';
                if (!webd_capture_safe_id(cap_id))
                    continue;
                meta = webd_capture_load_meta(cap_id);
                if (!meta)
                    continue;
                webd_capture_refresh_meta(meta, 1);
                total++;
                if (app_nc_json_bool(meta, "running", 0)) {
                    running++;
                    json_object_array_add(active, json_object_get(meta));
                }
                json_object_array_add(items, meta);
            }
            closedir(d);
        }
    }
    json_object_object_add(root, "items", items);
    json_object_object_add(root, "captures", json_object_get(items));
    json_object_object_add(root, "active", active);
    json_object_object_add(root, "total", json_object_new_int(total));
    json_object_object_add(root, "running_count", json_object_new_int(running));
    json_object_object_add(root, "capabilities", webd_capture_capabilities());
    webd_obj_add_str(root, "storage", WEBD_CAPTURE_DIR);
    return webd_envelope(root, "webd.topology_capture");
}

static int webd_capture_list_active_count(void)
{
    struct json_object *status = webd_topology_capture_status_response("", NULL);
    struct json_object *data = NULL;
    int count = 0;

    if (status && json_object_object_get_ex(status, "data", &data) && data)
        count = app_nc_json_int(data, "running_count", 0);
    if (status)
        json_object_put(status);
    return count;
}

static void webd_capture_query_or_body(const struct http_req *req, struct json_object *body,
                                       const char *key, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (req && webd_query_get(req->query, key, out, out_len))
        return;
    snprintf(out, out_len, "%s", app_nc_json_str(body, key, ""));
}

static int webd_capture_query_or_body_int(const struct http_req *req, struct json_object *body,
                                          const char *key, int def)
{
    char buf[64];
    int v;

    if (req && webd_query_get(req->query, key, buf, sizeof(buf)) &&
        app_parse_positive_int_segment(buf, &v))
        return v;
    return app_nc_json_int(body, key, def);
}

static struct json_object *webd_topology_capture_start_response(const struct http_req *req,
                                                                struct json_object *body,
                                                                const char *actor_identity,
                                                                int *http_status)
{
    char tcpdump_path[64];
    char timeout_path[64];
    char ifname[128] = "any";
    char mac[64] = "";
    char host[256] = "";
    char proto[32] = "";
    char port_s[32] = "";
    char id[160];
    char pcap_path[320];
    char duration_arg[32];
    char count_arg[32];
    char snaplen_arg[32];
    char *argv[48];
    int argc = 0;
    int duration;
    int packet_count;
    int snaplen;
    int port = 0;
    int need_and = 0;
    pid_t pid;
    struct json_object *meta;

    if (http_status)
        *http_status = 200;
    if (!webd_capture_available()) {
        if (http_status)
            *http_status = 503;
        meta = json_object_new_object();
        json_object_object_add(meta, "capabilities", webd_capture_capabilities());
        json_object_object_add(meta, "reason", json_object_new_string("tcpdump_or_timeout_missing"));
        return webd_envelope(meta, "webd.topology_capture");
    }
    webd_capture_query_or_body(req, body, "ifname", ifname, sizeof(ifname));
    if (!ifname[0])
        webd_capture_query_or_body(req, body, "interface", ifname, sizeof(ifname));
    if (!ifname[0])
        webd_capture_query_or_body(req, body, "device", ifname, sizeof(ifname));
    if (!ifname[0])
        snprintf(ifname, sizeof(ifname), "any");
    webd_capture_query_or_body(req, body, "mac", mac, sizeof(mac));
    webd_capture_query_or_body(req, body, "host", host, sizeof(host));
    webd_capture_query_or_body(req, body, "protocol", proto, sizeof(proto));
    if (!proto[0])
        webd_capture_query_or_body(req, body, "proto", proto, sizeof(proto));
    webd_capture_query_or_body(req, body, "port", port_s, sizeof(port_s));
    if (port_s[0] && !app_parse_positive_int_segment(port_s, &port))
        port = -1;
    duration = webd_capture_query_or_body_int(req, body, "duration_s", WEBD_CAPTURE_DEFAULT_DURATION_S);
    packet_count = webd_capture_query_or_body_int(req, body, "packet_count", WEBD_CAPTURE_DEFAULT_PACKET_COUNT);
    snaplen = webd_capture_query_or_body_int(req, body, "snaplen", WEBD_CAPTURE_DEFAULT_SNAPLEN);

    if (!webd_capture_safe_ifname(ifname) || !webd_capture_safe_mac(mac) ||
        !webd_capture_safe_host(host) || !webd_capture_safe_protocol(proto) ||
        port < 0 || port > 65535) {
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_capture_filter",
                          "capture target contains invalid ifname/mac/host/protocol/port",
                          "ifname/mac/host/protocol/port", "webd.topology_capture");
    }
    if (duration <= 0 || duration > WEBD_CAPTURE_MAX_DURATION_S ||
        packet_count <= 0 || packet_count > WEBD_CAPTURE_MAX_PACKET_COUNT ||
        snaplen <= 0 || snaplen > WEBD_CAPTURE_MAX_SNAPLEN) {
        if (http_status)
            *http_status = 400;
        return webd_error("capture_limit_exceeded",
                          "capture duration, packet_count or snaplen exceeds webd limits",
                          "duration_s/packet_count/snaplen", "webd.topology_capture");
    }
    if (webd_capture_list_active_count() > 0) {
        if (http_status)
            *http_status = 400;
        return webd_error("capture_already_running",
                          "another topology packet capture is already running",
                          "active capture", "webd.topology_capture");
    }
    if (webd_capture_mkdir() != 0) {
        if (http_status)
            *http_status = 500;
        return webd_error("capture_storage_unavailable",
                          "capture storage directory is not writable",
                          WEBD_CAPTURE_DIR, "webd.topology_capture");
    }
    webd_capture_prune();
    snprintf(id, sizeof(id), "cap-%lld-%ld", (long long)now_s(), random());
    webd_capture_path(pcap_path, sizeof(pcap_path), id, "pcap");
    snprintf(duration_arg, sizeof(duration_arg), "%d", duration);
    snprintf(count_arg, sizeof(count_arg), "%d", packet_count);
    snprintf(snaplen_arg, sizeof(snaplen_arg), "%d", snaplen);

    argv[argc++] = (char *)webd_capture_find_bin("timeout", timeout_path, sizeof(timeout_path));
    argv[argc++] = duration_arg;
    argv[argc++] = (char *)webd_capture_find_bin("tcpdump", tcpdump_path, sizeof(tcpdump_path));
    argv[argc++] = "-i";
    argv[argc++] = ifname;
    argv[argc++] = "-s";
    argv[argc++] = snaplen_arg;
    argv[argc++] = "-c";
    argv[argc++] = count_arg;
    argv[argc++] = "-w";
    argv[argc++] = pcap_path;
    if (proto[0]) {
        argv[argc++] = proto;
        need_and = 1;
    }
    if (mac[0]) {
        if (need_and) argv[argc++] = "and";
        argv[argc++] = "ether";
        argv[argc++] = "host";
        argv[argc++] = mac;
        need_and = 1;
    }
    if (host[0]) {
        if (need_and) argv[argc++] = "and";
        argv[argc++] = "host";
        argv[argc++] = host;
        need_and = 1;
    }
    if (port > 0) {
        if (need_and) argv[argc++] = "and";
        argv[argc++] = "port";
        argv[argc++] = port_s;
    }
    argv[argc] = NULL;

    pid = fork();
    if (pid < 0) {
        if (http_status)
            *http_status = 500;
        return webd_error("capture_start_failed", "failed to fork capture process",
                          "fork", "webd.topology_capture");
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);

        setsid();
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }
        execv(argv[0], argv);
        _exit(127);
    }

    meta = json_object_new_object();
    json_object_object_add(meta, "id", json_object_new_string(id));
    json_object_object_add(meta, "state", json_object_new_string("running"));
    json_object_object_add(meta, "pid", json_object_new_int((int)pid));
    json_object_object_add(meta, "ifname", json_object_new_string(ifname));
    webd_capture_add_local_execution_fields(meta, req, ifname, mac, host);
    webd_obj_add_str(meta, "mac", mac);
    webd_obj_add_str(meta, "host", host);
    webd_obj_add_str(meta, "protocol", proto);
    json_object_object_add(meta, "port", json_object_new_int(port > 0 ? port : 0));
    json_object_object_add(meta, "duration_s", json_object_new_int(duration));
    json_object_object_add(meta, "packet_count", json_object_new_int(packet_count));
    json_object_object_add(meta, "snaplen", json_object_new_int(snaplen));
    json_object_object_add(meta, "started_at", json_object_new_int64(now_s()));
    json_object_object_add(meta, "pcap_path", json_object_new_string(pcap_path));
    json_object_object_add(meta, "size_bytes", json_object_new_int64(0));
    json_object_object_add(meta, "running", json_object_new_boolean(1));
    webd_obj_add_str(meta, "actor_identity", actor_identity);
    json_object_object_add(meta, "capabilities", webd_capture_capabilities());
    webd_capture_add_download_fields(meta, id);
    webd_capture_write_meta(meta);
    webd_capture_log_event("packet_capture_started", "Packet capture started",
                           meta, actor_identity);
    return webd_envelope(meta, "webd.topology_capture");
}

static struct json_object *webd_topology_capture_stop_response(const struct http_req *req,
                                                               struct json_object *body,
                                                               const char *actor_identity,
                                                               int *http_status)
{
    char id[160] = "";
    struct json_object *meta;
    pid_t pid;

    if (http_status)
        *http_status = 200;
    webd_capture_query_or_body(req, body, "id", id, sizeof(id));
    if (!webd_capture_safe_id(id)) {
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_capture_id", "capture id is required",
                          "id", "webd.topology_capture");
    }
    meta = webd_capture_load_meta(id);
    if (!meta) {
        if (http_status)
            *http_status = 404;
        return webd_error("capture_not_found", "capture id was not found",
                          "id", "webd.topology_capture");
    }
    webd_capture_refresh_meta(meta, 0);
    pid = (pid_t)app_nc_json_int(meta, "pid", 0);
    if (app_nc_json_bool(meta, "running", 0) && pid > 0) {
        kill(-pid, SIGTERM);
        usleep(200 * 1000);
        if (webd_capture_pid_alive(pid))
            kill(-pid, SIGKILL);
        json_object_object_add(meta, "state", json_object_new_string("stopped"));
        json_object_object_add(meta, "stopped_at", json_object_new_int64(now_s()));
    }
    webd_capture_refresh_meta(meta, 0);
    webd_capture_write_meta(meta);
    webd_capture_log_event("packet_capture_stopped", "Packet capture stopped",
                           meta, actor_identity);
    return webd_envelope(meta, "webd.topology_capture");
}

static struct json_object *webd_topology_capture_delete_response(const struct http_req *req,
                                                                 struct json_object *body,
                                                                 const char *actor_identity,
                                                                 int *http_status)
{
    char id[160] = "";
    struct json_object *meta;
    struct json_object *root;
    int existed;

    if (http_status)
        *http_status = 200;
    webd_capture_query_or_body(req, body, "id", id, sizeof(id));
    if (!webd_capture_safe_id(id)) {
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_capture_id", "capture id is required",
                          "id", "webd.topology_capture");
    }

    meta = webd_capture_load_meta(id);
    if (meta) {
        webd_capture_refresh_meta(meta, 0);
        if (app_nc_json_bool(meta, "running", 0)) {
            if (http_status)
                *http_status = 400;
            json_object_put(meta);
            return webd_error("capture_running", "running capture must be stopped before delete",
                              "id", "webd.topology_capture");
        }
    }
    existed = webd_capture_pair_exists(id);
    if (!existed) {
        if (http_status)
            *http_status = 404;
        if (meta)
            json_object_put(meta);
        return webd_error("capture_not_found", "capture id was not found",
                          "id", "webd.topology_capture");
    }
    if (!meta) {
        meta = json_object_new_object();
        json_object_object_add(meta, "id", json_object_new_string(id));
        json_object_object_add(meta, "state", json_object_new_string("deleted"));
    } else {
        json_object_object_add(meta, "state", json_object_new_string("deleted"));
    }
    webd_capture_log_event("packet_capture_deleted", "Packet capture deleted",
                           meta, actor_identity);
    webd_capture_remove_pair(id);

    root = json_object_new_object();
    json_object_object_add(root, "id", json_object_new_string(id));
    json_object_object_add(root, "deleted", json_object_new_boolean(1));
    json_object_object_add(root, "deleted_at", json_object_new_int64(now_s()));
    json_object_object_add(root, "capture", meta);
    return webd_envelope(root, "webd.topology_capture");
}

struct json_object *webd_topology_capture_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *actor_identity,
                                                          int *http_status)
{
    char id[160] = "";
    char action[32] = "";

    if (http_status)
        *http_status = 200;
    if (req && webd_query_get(req->query, "id", id, sizeof(id)) && id[0] && !webd_capture_safe_id(id)) {
        if (http_status)
            *http_status = 400;
        return webd_error("invalid_capture_id", "capture id contains invalid characters",
                          "id", "webd.topology_capture");
    }
    if (req && webd_path_ends_with(req->path, "/status"))
        return webd_topology_capture_status_response(id, http_status);
    if (req && (!strcmp(req->method, "GET") || !strcmp(req->method, "HEAD"))) {
        if (!strcmp(req->path, "/api/v1/topology/capture"))
            return webd_topology_capture_status_response(id, http_status);
        if (http_status)
            *http_status = 405;
        return webd_error("method_not_allowed", "capture action requires POST or PUT",
                          "method", "webd.topology_capture");
    }
    if (req)
        webd_query_get(req->query, "action", action, sizeof(action));
    if (!action[0])
        snprintf(action, sizeof(action), "%s", app_nc_json_str(body, "action", ""));
    if (req && !strcmp(req->method, "DELETE"))
        return webd_topology_capture_delete_response(req, body, actor_identity, http_status);
    if (webd_path_ends_with(req ? req->path : "", "/delete") || !strcmp(action, "delete"))
        return webd_topology_capture_delete_response(req, body, actor_identity, http_status);
    if (webd_path_ends_with(req ? req->path : "", "/stop") || !strcmp(action, "stop"))
        return webd_topology_capture_stop_response(req, body, actor_identity, http_status);
    if (webd_path_ends_with(req ? req->path : "", "/start") || !strcmp(action, "start") ||
        (!action[0] && req && !strcmp(req->path, "/api/v1/topology/capture")))
        return webd_topology_capture_start_response(req, body, actor_identity, http_status);
    if (!strcmp(action, "status"))
        return webd_topology_capture_status_response(id, http_status);
    if (http_status)
        *http_status = 400;
    return webd_error("invalid_capture_action", "unknown capture action",
                      "action", "webd.topology_capture");
}

int webd_topology_capture_download_response(int fd, const struct http_req *req)
{
    char id[160];
    char path[320];
    char filename[224];
    char header[768];
    char buf[8192];
    struct json_object *meta;
    struct stat st;
    int f;
    int hlen;

    if (!req)
        return -1;
    if (strcmp(req->method, "GET") && strcmp(req->method, "HEAD")) {
        http_send(fd, 405, "Method Not Allowed", "text/plain", "method not allowed", 18);
        return 0;
    }
    if (!webd_query_get(req->query, "id", id, sizeof(id)) || !webd_capture_safe_id(id)) {
        http_send(fd, 400, "Bad Request", "text/plain", "invalid capture id", 18);
        return 0;
    }
    meta = webd_capture_load_meta(id);
    if (!meta) {
        http_send(fd, 404, "Not Found", "text/plain", "capture not found", 17);
        return 0;
    }
    webd_capture_refresh_meta(meta, 1);
    if (app_nc_json_bool(meta, "running", 0)) {
        json_object_put(meta);
        http_send(fd, 400, "Bad Request", "text/plain", "capture still running", 21);
        return 0;
    }
    webd_capture_path(path, sizeof(path), id, "pcap");
    json_object_put(meta);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        http_send(fd, 404, "Not Found", "text/plain", "pcap not found", 14);
        return 0;
    }
    f = open(path, O_RDONLY | O_CLOEXEC);
    if (f < 0) {
        http_send(fd, 404, "Not Found", "text/plain", "pcap not found", 14);
        return 0;
    }
    snprintf(filename, sizeof(filename), "dreamingwrt-capture-%s.pcap", id);
    hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/vnd.tcpdump.pcap\r\n"
        "Content-Length: %lld\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match,Accept\r\n"
        "Access-Control-Allow-Methods: GET,HEAD,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n",
        (long long)st.st_size, filename);
    if (hlen <= 0 || hlen >= (int)sizeof(header) ||
        webd_write_all(fd, header, (size_t)hlen) != 0) {
        close(f);
        return 0;
    }
    if (!strcmp(req->method, "HEAD")) {
        close(f);
        return 0;
    }
    for (;;) {
        ssize_t n = read(f, buf, sizeof(buf));

        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        if (webd_write_all(fd, buf, (size_t)n) != 0)
            break;
    }
    close(f);
    return 0;
}

