/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_route.c - userspace netlink + ubus helpers for JMX multi-WAN routing
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <json-c/json.h>
#include <uci.h>
#include <sqlite3.h>
#include <libubox/list.h>

#include "jmx.h"
#include "jmx_route.h"
#include "jmx_nl_push.h"
#include "jmx_nl_rule.h"
#include "jmx_config.h"
#include "jmx_user.h"
#include "proc_path.h"
#include "jmx_system_data_path.h"

extern struct list_head client_list;

struct af_msg_hdr_local {
    uint32_t magic;
    uint32_t len;
};

static int jmx_route_nl_send(int fd, const void *data, int len)
{
    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg;
    struct af_msg_hdr_local *hdr;
    int total = len + (int)sizeof(*hdr);
    int ret;

    nlh = calloc(1, NLMSG_SPACE(total));
    if (!nlh)
        return -1;

    /* nlmsg_len is the unpadded wire length; padding is allocation-only. */
    nlh->nlmsg_len = NLMSG_LENGTH(total);
    hdr = (struct af_msg_hdr_local *)NLMSG_DATA(nlh);
    hdr->magic = JMX_NL_MAGIC;
    hdr->len = len;
    memcpy((char *)NLMSG_DATA(nlh) + sizeof(*hdr), data, len);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(fd, &msg, 0);
    if (ret < 0)
        LOG_ERROR("route nl send failed: %s", strerror(errno));

    free(nlh);
    return ret < 0 ? -1 : 0;
}


int jmx_route_nl_carrier_flush(int nl_fd)
{
    struct { int32_t action; } __packed msg = { .action = JMX_NL_ACT_CARRIER_FLUSH };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_carrier_add(int nl_fd, uint32_t network, uint32_t mask, uint8_t carrier_id)
{
    struct { int32_t action; uint32_t network; uint32_t mask; uint8_t carrier_id; } __packed msg;
    memset(&msg, 0, sizeof(msg));
    msg.action = JMX_NL_ACT_CARRIER_ADD;
    msg.network = network;
    msg.mask = mask;
    msg.carrier_id = carrier_id;
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_wan_register(int nl_fd, uint8_t wan_id, const char *name,
                              uint32_t fwmark, uint32_t table_id, uint32_t gateway)
{
    struct {
        int32_t action;
        uint8_t wan_id;
        char name[16];
        uint32_t fwmark;
        uint32_t table_id;
        uint32_t gateway;
    } __packed msg;

    memset(&msg, 0, sizeof(msg));
    msg.action = JMX_NL_ACT_WAN_REGISTER;
    msg.wan_id = wan_id;
    snprintf(msg.name, sizeof(msg.name), "%s", name ? name : "");
    msg.fwmark = fwmark;
    msg.table_id = table_id;
    msg.gateway = gateway;
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_wan_unregister(int nl_fd, uint8_t wan_id)
{
    struct { int32_t action; uint8_t wan_id; } __packed msg = {
        .action = JMX_NL_ACT_WAN_UNREGISTER,
        .wan_id = wan_id,
    };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_wan_health(int nl_fd, uint8_t wan_id, uint8_t health)
{
    struct { int32_t action; uint8_t wan_id; uint8_t health; } __packed msg = {
        .action = JMX_NL_ACT_WAN_HEALTH,
        .wan_id = wan_id,
        .health = health ? 1 : 0,
    };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_rule_add(int nl_fd, const struct jmx_route_rule_wire *rule)
{
    struct { int32_t action; struct jmx_route_rule_wire rule; } __packed msg;
    if (!rule)
        return -1;
    memset(&msg, 0, sizeof(msg));
    msg.action = JMX_NL_ACT_ROUTE_ADD;
    msg.rule = *rule;
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_rule_del(int nl_fd, uint16_t prio)
{
    struct { int32_t action; uint16_t prio; } __packed msg = {
        .action = JMX_NL_ACT_ROUTE_DEL,
        .prio = prio,
    };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}


int jmx_route_nl_rule_clear_hits(int nl_fd, uint16_t prio)
{
    struct { int32_t action; uint16_t prio; } __packed msg = {
        .action = JMX_NL_ACT_ROUTE_CLEAR_HITS,
        .prio = prio,
    };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_rule_flush(int nl_fd)
{
    struct { int32_t action; } __packed msg = { .action = JMX_NL_ACT_ROUTE_FLUSH };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

static uint32_t json_get_u32(struct json_object *obj, const char *key, uint32_t def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v))
        return def;
    return (uint32_t)json_object_get_int64(v);
}

static int json_has_key(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;

    return obj && key && json_object_object_get_ex(obj, key, &v);
}

static uint8_t carrier_from_string(const char *s);
static const char *uci_opt(struct uci_section *s, const char *name);
static uint32_t parse_u32_opt(struct uci_section *s, const char *name, uint32_t def);

static const char *json_get_str(struct json_object *obj, const char *key, const char *def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v))
        return def;
    return json_object_get_string(v);
}

static uint32_t json_get_ipv4(struct json_object *obj, const char *key, uint32_t def)
{
    const char *s = json_get_str(obj, key, NULL);
    struct in_addr a;
    if (!s || !s[0])
        return def;
    if (inet_pton(AF_INET, s, &a) != 1)
        return def;
    return a.s_addr;
}

static int route_exec_quiet(char *const argv[])
{
    pid_t pid;
    int status = -1;

    if (!argv || !argv[0])
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);

        if (devnull >= 0) {
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    do {
        if (waitpid(pid, &status, 0) >= 0)
            break;
    } while (errno == EINTR);

    if (status < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static struct json_object *route_result(int rc)
{
    struct json_object *data = json_object_new_object();
    const char *err = errno ? strerror(errno) : "execution failed";
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "rc", json_object_new_int(rc));
    if (rc != 0)
        json_object_object_add(data, "error", json_object_new_string(err));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static int route_open_nl(void)
{
    int fd = jmx_nl_socket_create();
    if (fd < 0)
        LOG_ERROR("failed to open jmx netlink socket");
    return fd;
}

struct json_object *jmx_api_route_wan_register(struct json_object *req_obj)
{
    int fd, rc;
    uint8_t wan_id = (uint8_t)json_get_u32(req_obj, "wan_id", 0);
    const char *name = json_get_str(req_obj, "name", "");
    uint32_t fwmark = json_get_u32(req_obj, "fwmark", 0);
    uint32_t table_id = json_get_u32(req_obj, "table_id", 0);
    uint32_t gateway = json_get_ipv4(req_obj, "gateway", 0);

    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_wan_register(fd, wan_id, name, fwmark, table_id, gateway);
    close(fd);
    return route_result(rc);
}

struct json_object *jmx_api_route_wan_unregister(struct json_object *req_obj)
{
    int fd, rc;
    uint8_t wan_id = (uint8_t)json_get_u32(req_obj, "wan_id", 0);
    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_wan_unregister(fd, wan_id);
    close(fd);
    return route_result(rc);
}

struct json_object *jmx_api_route_wan_health(struct json_object *req_obj)
{
    int fd, rc;
    uint8_t wan_id = (uint8_t)json_get_u32(req_obj, "wan_id", 0);
    uint8_t health = (uint8_t)json_get_u32(req_obj, "health", 1);
    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_wan_health(fd, wan_id, health);
    close(fd);
    return route_result(rc);
}

struct json_object *jmx_api_route_rule_add(struct json_object *req_obj)
{
    int fd, rc, i;
    struct json_object *wan_arr = NULL;
    struct jmx_route_rule_wire r;

    memset(&r, 0, sizeof(r));
    r.enabled = (uint8_t)json_get_u32(req_obj, "enabled", 1);
    r.prio = (uint16_t)json_get_u32(req_obj, "prio", 100);
    r.src_addr = json_get_ipv4(req_obj, "src_addr", 0);
    r.src_mask = json_get_ipv4(req_obj, "src_mask", 0);
    r.dst_addr = json_get_ipv4(req_obj, "dst_addr", 0);
    r.dst_mask = json_get_ipv4(req_obj, "dst_mask", 0);
    r.dst_port = (uint16_t)json_get_u32(req_obj, "dst_port", 0);
    r.proto = (uint8_t)json_get_u32(req_obj, "proto", 0);
    r.appid = json_get_u32(req_obj, "appid", 0);
    r.carrier_id = (uint8_t)json_get_u32(req_obj, "carrier_id", carrier_from_string(json_get_str(req_obj, "carrier", "any")));
    r.sticky_mode = (uint8_t)json_get_u32(req_obj, "sticky_mode", JMX_STICKY_SIP);

    if (json_object_object_get_ex(req_obj, "wan_ids", &wan_arr) && json_object_is_type(wan_arr, json_type_array)) {
        int n = json_object_array_length(wan_arr);
        if (n > JMX_ROUTE_MAX_WAN_IFACES)
            n = JMX_ROUTE_MAX_WAN_IFACES;
        for (i = 0; i < n; i++)
            r.wan_ids[i] = (uint8_t)json_object_get_int(json_object_array_get_idx(wan_arr, i));
        r.wan_count = (uint8_t)n;
    }

    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_rule_add(fd, &r);
    close(fd);
    return route_result(rc);
}

struct json_object *jmx_api_route_rule_del(struct json_object *req_obj)
{
    int fd, rc;
    uint16_t prio = (uint16_t)json_get_u32(req_obj, "prio", 0);
    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_rule_del(fd, prio);
    close(fd);
    return route_result(rc);
}

struct json_object *jmx_api_route_rule_flush(struct json_object *req_obj)
{
    int fd, rc;
    (void)req_obj;
    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_rule_flush(fd);
    close(fd);
    return route_result(rc);
}


static struct json_object *route_json_ok(struct json_object *data)
{
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data ? data : json_object_new_object());
}

static const char *route_app_name(int appid)
{
    char *name;
    if (appid <= 0) return "";
    name = get_app_name_by_id(appid);
    return name ? name : "";
}

static void route_state_db_init(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open("/var/lib/dreamingwrt/network_state.db", &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return;
    }
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS route_rule_counter (rule_id TEXT PRIMARY KEY,prio INTEGER NOT NULL,name TEXT DEFAULT '',action TEXT NOT NULL,target TEXT DEFAULT '',hit_count INTEGER DEFAULT 0,active_flows INTEGER DEFAULT 0,up_rate INTEGER DEFAULT 0,down_rate INTEGER DEFAULT 0,last_hit INTEGER DEFAULT 0,updated_at INTEGER NOT NULL)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS route_decision_sample (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,client_id TEXT DEFAULT '',client_name TEXT DEFAULT '',ip TEXT DEFAULT '',app TEXT DEFAULT '',destination TEXT DEFAULT '',rule_id TEXT DEFAULT '',rule_name TEXT DEFAULT '',action TEXT DEFAULT '',path TEXT DEFAULT '',wan TEXT DEFAULT '',reason TEXT DEFAULT '',up_bytes INTEGER DEFAULT 0,down_bytes INTEGER DEFAULT 0,latency INTEGER DEFAULT 0)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_route_decision_ts ON route_decision_sample(ts)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_route_decision_client ON route_decision_sample(client_id, ts)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_route_decision_rule ON route_decision_sample(rule_id, ts)", NULL, NULL, NULL);
    sqlite3_close(db);
}

static int route_obj_int(struct json_object *o, const char *k, int def)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v) && v) return json_object_get_int(v);
    return def;
}

static int64_t route_obj_i64(struct json_object *o, const char *k, int64_t def)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v) && v) return json_object_get_int64(v);
    return def;
}

static const char *route_obj_str(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v = NULL;
    if (o && json_object_object_get_ex(o, k, &v) && v) return json_object_get_string(v);
    return def;
}

static void route_enrich_wans(struct json_object *data)
{
    struct json_object *wans = NULL;
    int i;
    if (!json_object_object_get_ex(data, "wans", &wans) || !json_object_is_type(wans, json_type_array)) return;
    for (i = 0; i < json_object_array_length(wans); i++) {
        struct json_object *w = json_object_array_get_idx(wans, i);
        const char *name = route_obj_str(w, "name", "wan");
        int64_t down = route_obj_i64(w, "down_rate", route_obj_i64(w, "rate_down", 0));
        int64_t up = route_obj_i64(w, "up_rate", route_obj_i64(w, "rate_up", 0));
        int health = route_obj_int(w, "health", 1);
        if (!json_has_key(w, "ifname")) json_object_object_add(w, "ifname", json_object_new_string(name));
        if (!json_has_key(w, "carrier")) json_object_object_add(w, "carrier", json_object_new_string(""));
        if (!json_has_key(w, "rate_down")) json_object_object_add(w, "rate_down", json_object_new_int64(down));
        if (!json_has_key(w, "rate_up")) json_object_object_add(w, "rate_up", json_object_new_int64(up));
        if (!json_has_key(w, "down_rate")) json_object_object_add(w, "down_rate", json_object_new_int64(down));
        if (!json_has_key(w, "up_rate")) json_object_object_add(w, "up_rate", json_object_new_int64(up));
        if (!json_has_key(w, "up_bytes")) json_object_object_add(w, "up_bytes", json_object_new_int64(0));
        if (!json_has_key(w, "down_bytes")) json_object_object_add(w, "down_bytes", json_object_new_int64(0));
        if (!json_has_key(w, "connections")) json_object_object_add(w, "connections", json_object_new_int(0));
        if (!json_has_key(w, "load")) json_object_object_add(w, "load", json_object_new_int(health ? 0 : 100));
        if (!json_has_key(w, "status")) json_object_object_add(w, "status", json_object_new_string(health ? "ok" : "bad"));
    }
}

static const char *route_first_wan_name(struct json_object *data)
{
    struct json_object *wans = NULL;
    if (json_object_object_get_ex(data, "wans", &wans) && json_object_is_type(wans, json_type_array) && json_object_array_length(wans) > 0)
        return route_obj_str(json_object_array_get_idx(wans, 0), "name", "wan");
    return "wan";
}

static void route_enrich_rules(struct json_object *data)
{
    struct json_object *rules = NULL;
    int i;
    if (!json_object_object_get_ex(data, "rules", &rules) || !json_object_is_type(rules, json_type_array)) return;
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *r = json_object_array_get_idx(rules, i);
        int prio = route_obj_int(r, "prio", 1000 + i);
        int appid = route_obj_int(r, "appid", 0);
        char id[64], name[128], match[256], target[128];
        snprintf(id, sizeof(id), "rule-%d", prio);
        snprintf(name, sizeof(name), "%s%s%d", appid > 0 ? route_app_name(appid) : "规则 ", appid > 0 ? " " : "", prio);
        snprintf(match, sizeof(match), "%s%s", appid > 0 ? route_app_name(appid) : "any", appid > 0 ? "" : " / default");
        snprintf(target, sizeof(target), "%s", route_obj_str(r, "wan_ids", route_first_wan_name(data)));
        if (!json_has_key(r, "id")) json_object_object_add(r, "id", json_object_new_string(id));
        if (!json_has_key(r, "name")) json_object_object_add(r, "name", json_object_new_string(name));
        if (!json_has_key(r, "type")) json_object_object_add(r, "type", json_object_new_string(appid > 0 ? "app" : "route"));
        if (!json_has_key(r, "match")) json_object_object_add(r, "match", json_object_new_string(match));
        if (!json_has_key(r, "action")) json_object_object_add(r, "action", json_object_new_string(strchr(target, ',') ? "balance" : "route"));
        if (!json_has_key(r, "group")) json_object_object_add(r, "group", json_object_new_string(strchr(target, ',') ? "auto-balance" : ""));
        if (!json_has_key(r, "target")) json_object_object_add(r, "target", json_object_new_string(target));
        if (!json_has_key(r, "active_flows")) json_object_object_add(r, "active_flows", json_object_new_int(0));
        if (!json_has_key(r, "down_rate")) json_object_object_add(r, "down_rate", json_object_new_int64(0));
        if (!json_has_key(r, "up_rate")) json_object_object_add(r, "up_rate", json_object_new_int64(0));
        if (!json_has_key(r, "last_hit")) json_object_object_add(r, "last_hit", json_object_new_int64(0));
        if (!json_has_key(r, "remark")) json_object_object_add(r, "remark", json_object_new_string("待接 nft/ipset/fwmark 真实命中计数"));
    }
}

static struct json_object *route_build_policy_groups(struct json_object *data)
{
    struct json_object *groups = json_object_new_array();
    struct json_object *wans = NULL;
    struct json_object *g = json_object_new_object();
    struct json_object *members = json_object_new_array();
    int i, n = 0;
    if (json_object_object_get_ex(data, "wans", &wans) && json_object_is_type(wans, json_type_array)) n = json_object_array_length(wans);
    for (i = 0; i < n; i++) {
        struct json_object *w = json_object_array_get_idx(wans, i), *m = json_object_new_object();
        const char *name = route_obj_str(w, "name", "wan");
        json_object_object_add(m, "id", json_object_new_string(name));
        json_object_object_add(m, "name", json_object_new_string(name));
        json_object_object_add(m, "weight", json_object_new_int(n > 0 ? 100 / n : 100));
        json_object_object_add(m, "health", json_object_new_string(route_obj_int(w, "health", 1) ? "ok" : "bad"));
        json_object_array_add(members, m);
    }
    json_object_object_add(g, "id", json_object_new_string("auto-balance"));
    json_object_object_add(g, "name", json_object_new_string("自动负载组"));
    json_object_object_add(g, "mode", json_object_new_string("weighted"));
    json_object_object_add(g, "members", members);
    json_object_object_add(g, "active_flows", json_object_new_int(0));
    json_object_object_add(g, "hit_count", json_object_new_int64(0));
    json_object_object_add(g, "down_rate", json_object_new_int64(0));
    json_object_object_add(g, "up_rate", json_object_new_int64(0));
    json_object_array_add(groups, g);
    return groups;
}

static struct json_object *route_build_decisions(struct json_object *data)
{
    struct json_object *arr = json_object_new_array();
    const char *wan = route_first_wan_name(data);
    client_node_t *c = NULL;
    int count = 0;
    list_for_each_entry(c, &client_list, client) {
        struct json_object *d;
        if (!c->online || count >= 100) continue;
        d = json_object_new_object();
        json_object_object_add(d, "id", json_object_new_string("runtime-sample"));
        json_object_object_add(d, "ts", json_object_new_int64((int64_t)time(NULL)));
        json_object_object_add(d, "client", json_object_new_string(c->nickname[0] ? c->nickname : (c->hostname[0] ? c->hostname : c->mac)));
        json_object_object_add(d, "ip", json_object_new_string(c->ip));
        json_object_object_add(d, "app", json_object_new_string(c->visiting_app > 0 ? route_app_name(c->visiting_app) : ""));
        json_object_object_add(d, "destination", json_object_new_string(c->visiting_url));
        json_object_object_add(d, "rule", json_object_new_string(c->visiting_app > 0 ? "应用规则候选" : "默认规则候选"));
        json_object_object_add(d, "action", json_object_new_string("route"));
        json_object_object_add(d, "path", json_object_new_string(wan));
        json_object_object_add(d, "wan", json_object_new_string(wan));
        json_object_object_add(d, "reason", json_object_new_string("运行态样本，待接 conntrack mark/oif 真实决策"));
        json_object_object_add(d, "up_bytes", json_object_new_int64(0));
        json_object_object_add(d, "down_bytes", json_object_new_int64(0));
        json_object_object_add(d, "latency", json_object_new_int(0));
        json_object_array_add(arr, d); count++;
    }
    return arr;
}

static void route_enrich_status(struct json_object *data)
{
    struct json_object *policy = json_object_new_object();
    struct json_object *rules = NULL;
    int rc = 0, wc = 0;
    if (!data) return;
    route_state_db_init();
    route_enrich_wans(data);
    route_enrich_rules(data);
    wc = route_obj_int(data, "wan_count", 0);
    rc = route_obj_int(data, "rule_count", 0);
    if (json_object_object_get_ex(data, "rules", &rules) && json_object_is_type(rules, json_type_array)) rc = json_object_array_length(rules);
    json_object_object_add(policy, "enabled", json_object_new_boolean(1));
    json_object_object_add(policy, "mode", json_object_new_string("health-aware"));
    json_object_object_add(policy, "engine", json_object_new_string("nft marks + ip rule"));
    json_object_object_add(policy, "active_rules", json_object_new_int(rc));
    json_object_object_add(policy, "policy_groups", json_object_new_int(wc > 0 ? 1 : 0));
    json_object_object_add(policy, "active_flows", json_object_new_int(0));
    json_object_object_add(policy, "steered_flows", json_object_new_int(0));
    json_object_object_add(policy, "bypass_flows", json_object_new_int(0));
    json_object_object_add(policy, "fallback_flows", json_object_new_int(0));
    json_object_object_add(policy, "hit_total", json_object_new_int64(0));
    json_object_object_add(policy, "last_apply_at", json_object_new_int64(0));
    json_object_object_add(policy, "last_decision_at", json_object_new_int64((int64_t)time(NULL)));
    if (!json_has_key(data, "ts")) json_object_object_add(data, "ts", json_object_new_int64((int64_t)time(NULL)));
    if (!json_has_key(data, "wan_count")) json_object_object_add(data, "wan_count", json_object_new_int(wc));
    if (!json_has_key(data, "rule_count")) json_object_object_add(data, "rule_count", json_object_new_int(rc));
    json_object_object_add(data, "policy_status", policy);
    json_object_object_add(data, "policy_groups", route_build_policy_groups(data));
    json_object_object_add(data, "route_decisions", route_build_decisions(data));
}

static struct json_object *route_parse_proc_status(FILE *fp)
{
    struct json_object *data = json_object_new_object();
    struct json_object *wans = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    char line[512];
    int section = 0;

    json_object_object_add(data, "available", json_object_new_boolean(1));
    json_object_object_add(data, "wans", wans);
    json_object_object_add(data, "rules", rules);

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        p[strcspn(p, "\n")] = 0;
        if (!strncmp(p, "CarrierPrefixes:", 16)) {
            unsigned carrier_prefix_count = 0;
            if (sscanf(p, "CarrierPrefixes: %u", &carrier_prefix_count) == 1)
                json_object_object_add(data, "carrier_prefix_count", json_object_new_int((int)carrier_prefix_count));
            continue;
        }
        if (strcmp(p, "WANs:") == 0) { section = 1; continue; }
        if (strcmp(p, "Rules:") == 0) { section = 2; continue; }
        if (p[0] == '\0' || !strncmp(p, "id ", 3) || !strncmp(p, "prio ", 5))
            continue;

        if (section == 1) {
            unsigned id, table, health;
            char name[32], fwmark[32], gateway[64];
            if (sscanf(p, "%u %31s %31s %u %63s %u", &id, name, fwmark, &table, gateway, &health) == 6) {
                struct json_object *o = json_object_new_object();
                json_object_object_add(o, "id", json_object_new_int((int)id));
                json_object_object_add(o, "name", json_object_new_string(name));
                json_object_object_add(o, "fwmark", json_object_new_string(fwmark));
                json_object_object_add(o, "table", json_object_new_int((int)table));
                json_object_object_add(o, "gateway", json_object_new_string(gateway));
                json_object_object_add(o, "health", json_object_new_boolean(health != 0));
                json_object_array_add(wans, o);
            }
        } else if (section == 2) {
            unsigned prio, en, proto, appid, carrier, dport, mode;
            unsigned long long hits = 0;
            unsigned long last_hit_s = 0;
            char src[64], dst[64], wans_buf[128] = {0};
            int n = sscanf(p, "%u %u %u %u %u %63s %63s %u %u %llu %lu %127s",
                           &prio, &en, &proto, &appid, &carrier, src, dst, &dport, &mode,
                           &hits, &last_hit_s, wans_buf);
            if (n >= 9) {
                struct json_object *o = json_object_new_object();
                json_object_object_add(o, "prio", json_object_new_int((int)prio));
                json_object_object_add(o, "enabled", json_object_new_boolean(en != 0));
                json_object_object_add(o, "proto", json_object_new_int((int)proto));
                json_object_object_add(o, "appid", json_object_new_int((int)appid));
                json_object_object_add(o, "carrier_id", json_object_new_int((int)carrier));
                json_object_object_add(o, "src", json_object_new_string(src));
                json_object_object_add(o, "dst", json_object_new_string(dst));
                json_object_object_add(o, "dst_port", json_object_new_int((int)dport));
                json_object_object_add(o, "sticky_mode", json_object_new_int((int)mode));
                json_object_object_add(o, "hit_count", json_object_new_int64((int64_t)hits));
                json_object_object_add(o, "last_hit_seconds_ago", json_object_new_int64((int64_t)last_hit_s));
                if (n >= 12)
                    json_object_object_add(o, "wan_ids", json_object_new_string(wans_buf));
                json_object_array_add(rules, o);
            }
        }
    }

    if (!json_has_key(data, "carrier_prefix_count"))
        json_object_object_add(data, "carrier_prefix_count", json_object_new_int(0));
    json_object_object_add(data, "wan_count", json_object_new_int(json_object_array_length(wans)));
    json_object_object_add(data, "rule_count", json_object_new_int(json_object_array_length(rules)));
    return data;
}


struct json_object *jmx_api_route_rule_clear_hits(struct json_object *req_obj)
{
    int fd, rc;
    uint16_t prio = (uint16_t)json_get_u32(req_obj, "prio", 0);
    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_rule_clear_hits(fd, prio);
    close(fd);
    return route_result(rc);
}

struct json_object *jmx_api_route_reload(struct json_object *req_obj)
{
    (void)req_obj;
    return route_result(jmx_route_sync_config());
}


static void json_add_uci_string(struct json_object *o, const char *json_key,
                                struct uci_section *s, const char *uci_key)
{
    const char *v = uci_opt(s, uci_key);
    if (v && v[0])
        json_object_object_add(o, json_key, json_object_new_string(v));
}

static void json_add_uci_u32(struct json_object *o, const char *json_key,
                             struct uci_section *s, const char *uci_key, uint32_t def)
{
    json_object_object_add(o, json_key, json_object_new_int64((int64_t)parse_u32_opt(s, uci_key, def)));
}

static struct json_object *uci_list_to_json(struct uci_section *s, const char *name)
{
    struct json_object *arr = json_object_new_array();
    struct uci_option *o;
    struct uci_element *e;

    o = uci_lookup_option(s->package->ctx, s, name);
    if (!o)
        return arr;
    if (o->type == UCI_TYPE_LIST) {
        uci_foreach_element(&o->v.list, e)
            json_object_array_add(arr, json_object_new_int(atoi(e->name)));
    } else if (o->type == UCI_TYPE_STRING && o->v.string) {
        const char *p = o->v.string;
        while (*p) {
            char *end = NULL;
            long n;
            while (*p == ' ' || *p == ',' || *p == '\t') p++;
            if (!*p) break;
            n = strtol(p, &end, 0);
            if (end == p) break;
            json_object_array_add(arr, json_object_new_int((int)n));
            p = end;
        }
    }
    return arr;
}


struct json_object *jmx_api_route_config_get(struct json_object *req_obj)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    struct json_object *data = json_object_new_object();
    struct json_object *wans = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    struct json_object *carrier_prefixes = json_object_new_array();

    (void)req_obj;
    json_object_object_add(data, "wans", wans);
    json_object_object_add(data, "rules", rules);
    json_object_object_add(data, "carrier_prefixes", carrier_prefixes);

    ctx = uci_alloc_context();
    if (!ctx)
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (uci_load(ctx, "jmx_route", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return route_json_ok(data);
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!strcmp(sec->type, "wan")) {
            struct json_object *o = json_object_new_object();
            json_add_uci_u32(o, "id", sec, "id", 0);
            json_add_uci_string(o, "name", sec, "name");
            json_add_uci_string(o, "ifname", sec, "ifname");
            json_add_uci_string(o, "fwmark", sec, "fwmark");
            json_add_uci_u32(o, "table", sec, "table", 0);
            json_add_uci_string(o, "gateway", sec, "gateway");
            json_add_uci_u32(o, "health", sec, "health", 1);
            json_add_uci_u32(o, "check_enable", sec, "check_enable", 0);
            json_add_uci_string(o, "check_host", sec, "check_host");
            json_object_array_add(wans, o);
        } else if (!strcmp(sec->type, "rule")) {
            struct json_object *o = json_object_new_object();
            json_add_uci_string(o, "name", sec, "name");
            json_add_uci_u32(o, "enabled", sec, "enabled", 1);
            json_add_uci_u32(o, "prio", sec, "prio", 0);
            json_add_uci_u32(o, "appid", sec, "appid", 0);
            json_add_uci_string(o, "carrier", sec, "carrier");
            json_add_uci_string(o, "proto", sec, "proto");
            json_add_uci_string(o, "src_addr", sec, "src_addr");
            json_add_uci_string(o, "src_mask", sec, "src_mask");
            json_add_uci_string(o, "dst_addr", sec, "dst_addr");
            json_add_uci_string(o, "dst_mask", sec, "dst_mask");
            json_add_uci_u32(o, "dst_port", sec, "dst_port", 0);
            json_add_uci_string(o, "sticky_mode", sec, "sticky_mode");
            json_object_object_add(o, "wan_ids", uci_list_to_json(sec, "wan_ids"));
            json_object_array_add(rules, o);
        } else if (!strcmp(sec->type, "carrier_prefix")) {
            struct json_object *o = json_object_new_object();
            json_add_uci_string(o, "carrier", sec, "carrier");
            json_add_uci_string(o, "cidr", sec, "cidr");
            json_object_array_add(carrier_prefixes, o);
        }
    }

    json_object_object_add(data, "wan_count", json_object_new_int(json_object_array_length(wans)));
    json_object_object_add(data, "rule_count", json_object_new_int(json_object_array_length(rules)));
    json_object_object_add(data, "carrier_prefix_count", json_object_new_int(json_object_array_length(carrier_prefixes)));
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return route_json_ok(data);
}

struct json_object *jmx_api_route_config_set(struct json_object *req_obj)
{
    struct json_object *wans = NULL, *rules = NULL;
    FILE *fp;
    int i;

    fp = fopen("/etc/config/jmx_route", "w");
    if (!fp)
        return route_result(-1);

    fprintf(fp, "config global 'global'\n\toption enabled '1'\n\n");

    if (json_object_object_get_ex(req_obj, "wans", &wans) && json_object_is_type(wans, json_type_array)) {
        for (i = 0; i < json_object_array_length(wans); i++) {
            struct json_object *w = json_object_array_get_idx(wans, i);
            uint32_t id = json_get_u32(w, "id", 0);
            const char *name = json_get_str(w, "name", "wan");
            const char *ifname = json_get_str(w, "ifname", "");
            const char *gateway = json_get_str(w, "gateway", "");
            fprintf(fp, "config wan 'wan%u'\n", id);
            fprintf(fp, "\toption id '%u'\n", id);
            fprintf(fp, "\toption name '%s'\n", name);
            if (ifname && ifname[0]) fprintf(fp, "\toption ifname '%s'\n", ifname);
            fprintf(fp, "\toption fwmark '0x%x'\n", json_get_u32(w, "fwmark", id ? 0x10000 + id : 0));
            fprintf(fp, "\toption table '%u'\n", json_get_u32(w, "table", 100 + id));
            if (gateway && gateway[0]) fprintf(fp, "\toption gateway '%s'\n", gateway);
            fprintf(fp, "\toption health '%u'\n", json_get_u32(w, "health", 1));
            fprintf(fp, "\toption check_enable '%u'\n", json_get_u32(w, "check_enable", 0));
            if (json_get_str(w, "check_host", "")[0])
                fprintf(fp, "\toption check_host '%s'\n", json_get_str(w, "check_host", ""));
            fprintf(fp, "\n");
        }
    }

    if (json_object_object_get_ex(req_obj, "rules", &rules) && json_object_is_type(rules, json_type_array)) {
        for (i = 0; i < json_object_array_length(rules); i++) {
            struct json_object *r = json_object_array_get_idx(rules, i);
            struct json_object *wan_ids = NULL;
            int j;
            fprintf(fp, "config rule 'rule%d'\n", i + 1);
            if (json_get_str(r, "name", "")[0]) fprintf(fp, "\toption name '%s'\n", json_get_str(r, "name", ""));
            fprintf(fp, "\toption enabled '%u'\n", json_get_u32(r, "enabled", 1));
            fprintf(fp, "\toption prio '%u'\n", json_get_u32(r, "prio", 1000 + i));
            fprintf(fp, "\toption appid '%u'\n", json_get_u32(r, "appid", 0));
            if (json_get_str(r, "carrier", "")[0]) fprintf(fp, "\toption carrier '%s'\n", json_get_str(r, "carrier", ""));
            else if (json_get_u32(r, "carrier_id", 0)) fprintf(fp, "\toption carrier '%u'\n", json_get_u32(r, "carrier_id", 0));
            fprintf(fp, "\toption proto '%s'\n", json_get_str(r, "proto", "any"));
            if (json_get_str(r, "src_addr", "")[0]) fprintf(fp, "\toption src_addr '%s'\n", json_get_str(r, "src_addr", ""));
            if (json_get_str(r, "src_mask", "")[0]) fprintf(fp, "\toption src_mask '%s'\n", json_get_str(r, "src_mask", ""));
            if (json_get_str(r, "dst_addr", "")[0]) fprintf(fp, "\toption dst_addr '%s'\n", json_get_str(r, "dst_addr", ""));
            if (json_get_str(r, "dst_mask", "")[0]) fprintf(fp, "\toption dst_mask '%s'\n", json_get_str(r, "dst_mask", ""));
            if (json_get_u32(r, "dst_port", 0)) fprintf(fp, "\toption dst_port '%u'\n", json_get_u32(r, "dst_port", 0));
            fprintf(fp, "\toption sticky_mode '%s'\n", json_get_str(r, "sticky_mode", "sip"));
            if (json_object_object_get_ex(r, "wan_ids", &wan_ids) && json_object_is_type(wan_ids, json_type_array)) {
                for (j = 0; j < json_object_array_length(wan_ids); j++)
                    fprintf(fp, "\tlist wan_ids '%d'\n", json_object_get_int(json_object_array_get_idx(wan_ids, j)));
            }
            fprintf(fp, "\n");
        }
    }

    fclose(fp);
    return route_result(jmx_route_sync_config());
}

struct json_object *jmx_api_route_status(struct json_object *req_obj)
{
    (void)req_obj;
    FILE *fp = jmx_fopen_af("jmx_route", "r");

    if (!fp) {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "wans", json_object_new_array());
        json_object_object_add(data, "rules", json_object_new_array());
        route_enrich_status(data);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }

    struct json_object *data = route_parse_proc_status(fp);
    fclose(fp);
    return route_json_ok(data);
}

/* ── UCI config sync ── */

static const char *uci_opt(struct uci_section *s, const char *name)
{
    struct uci_option *o;
    if (!s || !name)
        return NULL;
    o = uci_lookup_option(s->package->ctx, s, name);
    if (!o || o->type != UCI_TYPE_STRING)
        return NULL;
    return o->v.string;
}

static uint32_t parse_u32_opt(struct uci_section *s, const char *name, uint32_t def)
{
    const char *v = uci_opt(s, name);
    char *end = NULL;
    unsigned long n;
    if (!v || !v[0])
        return def;
    n = strtoul(v, &end, 0);
    if (end == v)
        return def;
    return (uint32_t)n;
}

static uint32_t parse_ipv4_opt(struct uci_section *s, const char *name, uint32_t def)
{
    const char *v = uci_opt(s, name);
    struct in_addr a;
    if (!v || !v[0])
        return def;
    if (inet_pton(AF_INET, v, &a) != 1)
        return def;
    return a.s_addr;
}

static uint8_t sticky_mode_from_string(const char *s)
{
    if (!s || !s[0]) return JMX_STICKY_SIP;
    if (!strcmp(s, "new_conn")) return JMX_STICKY_NEW_CONN;
    if (!strcmp(s, "sip")) return JMX_STICKY_SIP;
    if (!strcmp(s, "sip_sport") || !strcmp(s, "sip+sport")) return JMX_STICKY_SIP_SPORT;
    if (!strcmp(s, "sip_dip") || !strcmp(s, "sip+dip")) return JMX_STICKY_SIP_DIP;
    if (!strcmp(s, "sip_dip_dport") || !strcmp(s, "sip+dip+dport")) return JMX_STICKY_SIP_DIP_DPORT;
    if (!strcmp(s, "5tuple") || !strcmp(s, "five_tuple")) return JMX_STICKY_5TUPLE;
    if (!strcmp(s, "primary_backup") || !strcmp(s, "primary-backup")) return JMX_STICKY_PRIMARY_BACKUP;
    return (uint8_t)strtoul(s, NULL, 0);
}

static uint8_t proto_from_string(const char *s)
{
    if (!s || !s[0] || !strcmp(s, "any")) return 0;
    if (!strcasecmp(s, "tcp")) return 6;
    if (!strcasecmp(s, "udp")) return 17;
    return (uint8_t)strtoul(s, NULL, 0);
}


static uint8_t carrier_from_string(const char *s)
{
    if (!s || !s[0] || !strcmp(s, "any")) return JMX_CARRIER_ANY;
    if (!strcasecmp(s, "telecom") || !strcasecmp(s, "ctcc") || !strcmp(s, "电信")) return JMX_CARRIER_TELECOM;
    if (!strcasecmp(s, "unicom") || !strcasecmp(s, "cucc") || !strcmp(s, "联通")) return JMX_CARRIER_UNICOM;
    if (!strcasecmp(s, "mobile") || !strcasecmp(s, "cmcc") || !strcmp(s, "移动")) return JMX_CARRIER_MOBILE;
    if (!strcasecmp(s, "edu") || !strcasecmp(s, "cernet") || !strcmp(s, "教育网")) return JMX_CARRIER_EDU;
    if (!strcasecmp(s, "other")) return JMX_CARRIER_OTHER;
    return (uint8_t)strtoul(s, NULL, 0);
}

static int parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask)
{
    char buf[64];
    char *slash;
    struct in_addr a;
    int prefix = 32;

    if (!cidr || !network || !mask)
        return -1;
    snprintf(buf, sizeof(buf), "%s", cidr);
    slash = strchr(buf, '/');
    if (slash) {
        *slash++ = '\0';
        prefix = atoi(slash);
    }
    if (prefix < 0 || prefix > 32)
        return -1;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;
    *mask = prefix == 0 ? 0 : htonl(0xffffffffUL << (32 - prefix));
    *network = a.s_addr & *mask;
    return 0;
}


static int jmx_route_signature_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                              &source, error, sizeof(error)) == 0)
        return 0;
    LOG_WARN("jmx_route: signature DB resolve failed: %s", error);
    return -1;
}

static uint32_t mask_from_prefix_len(int prefix)
{
    if (prefix <= 0) return 0;
    if (prefix >= 32) return htonl(0xffffffffUL);
    return htonl(0xffffffffUL << (32 - prefix));
}

static int jmx_route_load_builtin_carriers(int fd)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    char path[512];
    int count = 0;

    if (jmx_route_signature_db_path(path, sizeof(path)) != 0)
        return 0;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        LOG_WARN("jmx_route: cannot open signature db for carrier prefixes: %s", path);
        if (db) sqlite3_close(db);
        return 0;
    }

    if (sqlite3_prepare_v2(db,
        "SELECT carrier_id,cidr,prefix_len FROM carrier_prefix WHERE enabled=1 ORDER BY sort_key",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("jmx_route: carrier_prefix table missing in signature db: %s", path);
        sqlite3_close(db);
        return 0;
    }

    while (sqlite3_step(st) == SQLITE_ROW) {
        uint8_t carrier_id = (uint8_t)sqlite3_column_int(st, 0);
        const char *cidr = (const char *)sqlite3_column_text(st, 1);
        int prefix = sqlite3_column_int(st, 2);
        uint32_t network = 0, mask = 0;

        if (!carrier_id || !cidr || parse_cidr(cidr, &network, &mask) != 0)
            continue;
        if (!mask)
            mask = mask_from_prefix_len(prefix);
        if (jmx_route_nl_carrier_add(fd, network, mask, carrier_id) == 0)
            count++;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    LOG_WARN("jmx_route: loaded %d carrier prefixes from %s", count, path);
    return count;
}

static void parse_wan_ids(struct uci_section *s, struct jmx_route_rule_wire *r)
{
    struct uci_option *o;
    struct uci_element *e;
    const char *one;

    o = uci_lookup_option(s->package->ctx, s, "wan_ids");
    if (!o)
        o = uci_lookup_option(s->package->ctx, s, "wans");
    if (!o)
        return;

    if (o->type == UCI_TYPE_LIST) {
        uci_foreach_element(&o->v.list, e) {
            if (r->wan_count >= JMX_ROUTE_MAX_WAN_IFACES)
                break;
            r->wan_ids[r->wan_count++] = (uint8_t)strtoul(e->name, NULL, 0);
        }
        return;
    }

    if (o->type != UCI_TYPE_STRING || !o->v.string)
        return;

    one = o->v.string;
    while (*one && r->wan_count < JMX_ROUTE_MAX_WAN_IFACES) {
        char *end = NULL;
        unsigned long n;
        while (*one == ' ' || *one == ',' || *one == '\t') one++;
        if (!*one) break;
        n = strtoul(one, &end, 0);
        if (end == one) break;
        r->wan_ids[r->wan_count++] = (uint8_t)n;
        one = end;
    }
}


#define JMX_ROUTE_STATE_FILE "/tmp/jmx_route.state"
#define JMX_ROUTE_RULE_PRIO_BASE 10000

static unsigned route_rule_priority(uint32_t table_id)
{
    return JMX_ROUTE_RULE_PRIO_BASE + (table_id % 1000);
}

static void jmx_route_cleanup_old_system_routes(void)
{
    FILE *fp = fopen(JMX_ROUTE_STATE_FILE, "r");
    unsigned prio, table_id;

    if (!fp)
        return;

    while (fscanf(fp, "%u %u", &prio, &table_id) == 2) {
        if (prio >= JMX_ROUTE_RULE_PRIO_BASE && prio < JMX_ROUTE_RULE_PRIO_BASE + 1000) {
            char prio_buf[16];
            char *argv[] = { "ip", "rule", "del", "priority", prio_buf, NULL };

            snprintf(prio_buf, sizeof(prio_buf), "%u", prio);
            (void)route_exec_quiet(argv);
        }
        if (table_id >= 1 && table_id <= 65535) {
            char table_buf[16];
            char *argv[] = { "ip", "route", "flush", "table", table_buf, NULL };

            snprintf(table_buf, sizeof(table_buf), "%u", table_id);
            (void)route_exec_quiet(argv);
        }
    }
    fclose(fp);
    unlink(JMX_ROUTE_STATE_FILE);
}

static void jmx_route_state_add(uint32_t table_id)
{
    FILE *fp = fopen(JMX_ROUTE_STATE_FILE, "a");
    if (!fp)
        return;
    fprintf(fp, "%u %u\n", route_rule_priority(table_id), table_id);
    fclose(fp);
}

static int jmx_route_apply_system_route(const char *ifname, uint32_t fwmark,
                                        uint32_t table_id, const char *gateway)
{
    char fwmark_buf[32];
    char table_buf[16];
    char prio_buf[16];
    int rc = 0;

    if (!fwmark || !table_id)
        return 0;

    snprintf(fwmark_buf, sizeof(fwmark_buf), "0x%x/0xffffffff", fwmark);
    snprintf(table_buf, sizeof(table_buf), "%u", table_id);
    snprintf(prio_buf, sizeof(prio_buf), "%u", route_rule_priority(table_id));
    {
        char *argv[] = { "ip", "rule", "replace", "fwmark", fwmark_buf, "table", table_buf, "priority", prio_buf, NULL };
        rc |= route_exec_quiet(argv);
    }

    if (gateway && gateway[0]) {
        if (ifname && ifname[0]) {
            char *argv[] = { "ip", "route", "replace", "default", "via", (char *)gateway, "dev", (char *)ifname, "table", table_buf, NULL };
            rc |= route_exec_quiet(argv);
        } else {
            char *argv[] = { "ip", "route", "replace", "default", "via", (char *)gateway, "table", table_buf, NULL };
            rc |= route_exec_quiet(argv);
        }
    } else if (ifname && ifname[0]) {
        char *argv[] = { "ip", "route", "replace", "default", "dev", (char *)ifname, "table", table_buf, NULL };
        rc |= route_exec_quiet(argv);
    }

    if (rc == 0)
        jmx_route_state_add(table_id);
    return rc == 0 ? 0 : -1;
}

int jmx_route_sync_config(void)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int fd;
    int wan_count = 0, rule_count = 0, carrier_count = 0;

    fd = route_open_nl();
    if (fd < 0)
        return -1;

    jmx_route_nl_rule_flush(fd);
    jmx_route_nl_carrier_flush(fd);
    jmx_route_cleanup_old_system_routes();

    ctx = uci_alloc_context();
    if (!ctx) {
        close(fd);
        return -1;
    }

    if (uci_load(ctx, "jmx_route", &pkg) != UCI_OK) {
        LOG_WARN("jmx_route: /etc/config/jmx_route not found, route policy disabled");
        uci_free_context(ctx);
        close(fd);
        return 0;
    }


    carrier_count += jmx_route_load_builtin_carriers(fd);

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "carrier_prefix")) {
            const char *cidr = uci_opt(s, "cidr");
            uint8_t carrier = carrier_from_string(uci_opt(s, "carrier"));
            uint32_t network = 0, mask = 0;
            if (cidr && carrier && parse_cidr(cidr, &network, &mask) == 0 &&
                jmx_route_nl_carrier_add(fd, network, mask, carrier) == 0)
                carrier_count++;
        }
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "wan")) {
            uint8_t id = (uint8_t)parse_u32_opt(s, "id", 0);
            const char *name = uci_opt(s, "name");
            const char *ifname = uci_opt(s, "ifname");
            const char *gw_str = uci_opt(s, "gateway");
            uint32_t fwmark = parse_u32_opt(s, "fwmark", id ? (0x10000 + id) : 0);
            uint32_t table_id = parse_u32_opt(s, "table", 100 + id);
            uint32_t gateway = parse_ipv4_opt(s, "gateway", 0);
            uint8_t health = (uint8_t)parse_u32_opt(s, "health", 1);

            if (!id)
                continue;
            if (!name || !name[0])
                name = ifname ? ifname : s->e.name;
            if (jmx_route_nl_wan_register(fd, id, name, fwmark, table_id, gateway) == 0) {
                jmx_route_nl_wan_health(fd, id, health);
                jmx_route_apply_system_route(ifname, fwmark, table_id, gw_str);
                wan_count++;
            }
        }
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "rule")) {
            struct jmx_route_rule_wire r;
            memset(&r, 0, sizeof(r));
            r.enabled = (uint8_t)parse_u32_opt(s, "enabled", 1);
            r.prio = (uint16_t)parse_u32_opt(s, "prio", 1000 + rule_count);
            r.src_addr = parse_ipv4_opt(s, "src_addr", 0);
            r.src_mask = parse_ipv4_opt(s, "src_mask", 0);
            r.dst_addr = parse_ipv4_opt(s, "dst_addr", 0);
            r.dst_mask = parse_ipv4_opt(s, "dst_mask", 0);
            r.dst_port = (uint16_t)parse_u32_opt(s, "dst_port", 0);
            r.proto = proto_from_string(uci_opt(s, "proto"));
            r.appid = parse_u32_opt(s, "appid", 0);
            r.carrier_id = carrier_from_string(uci_opt(s, "carrier"));
            r.sticky_mode = sticky_mode_from_string(uci_opt(s, "sticky_mode"));
            parse_wan_ids(s, &r);
            if (r.enabled && r.wan_count > 0 && jmx_route_nl_rule_add(fd, &r) == 0)
                rule_count++;
        }
    }

    LOG_WARN("jmx_route: synced config carriers=%d wans=%d rules=%d", carrier_count, wan_count, rule_count);
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    close(fd);
    return 0;
}


void jmx_route_health_tick(void)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int fd;

    ctx = uci_alloc_context();
    if (!ctx)
        return;
    if (uci_load(ctx, "jmx_route", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return;
    }

    fd = route_open_nl();
    if (fd < 0) {
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        return;
    }


    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "wan")) {
            uint8_t id = (uint8_t)parse_u32_opt(s, "id", 0);
            uint8_t enabled = (uint8_t)parse_u32_opt(s, "check_enable", 0);
            const char *ifname = uci_opt(s, "ifname");
            const char *target = uci_opt(s, "check_host");
            int rc;

            if (!id || !enabled)
                continue;
            if (!target || !target[0])
                target = uci_opt(s, "gateway");
            if (!target || !target[0])
                target = "223.5.5.5";

            if (ifname && ifname[0]) {
                char *argv[] = { "ping", "-I", (char *)ifname, "-c", "1", "-W", "1", (char *)target, NULL };
                rc = route_exec_quiet(argv);
            } else {
                char *argv[] = { "ping", "-c", "1", "-W", "1", (char *)target, NULL };
                rc = route_exec_quiet(argv);
            }
            jmx_route_nl_wan_health(fd, id, rc == 0 ? 1 : 0);
        }
    }

    close(fd);
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
}
