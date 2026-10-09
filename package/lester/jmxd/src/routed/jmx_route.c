/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_route.c - userspace netlink + ubus helpers for JMX multi-WAN routing
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <json-c/json.h>
#include <uci.h>
#include <sqlite3.h>
#include <libubox/list.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "jmx.h"
#include "jmx_route.h"
#include "dw_config_event.h"
#include "jmx_strbuf.h"
#include "jmx_route_db.h"
#include "jmx_route_mark_runtime.h"
#include "jmx_direction_nl.h"
#include "jmx_direction_snapshot.h"
#include "jmx_nl_push.h"
#include "jmx_nl_rule.h"
#include "jmx_config.h"
#include "jmx_isp.h"
#include "jmx_user.h"
#include "jmx_db.h"
#include "jmx_netconfig_db.h"
#include "proc_path.h"
#include "jmx_signature_db.h"
#include "jmx_system_data_path.h"
#include "wan_sla_route_guard.h"
#include "../flowd/wan_sla_config.h"

extern struct list_head client_list;

#define JMX_ROUTE_CMD_TIMEOUT_SEC 10
/*
 * Poll interval for reaping a forked helper.  This was a flat 100 ms, which put
 * a 100 ms floor under every `ip` invocation: a real call costs ~1.1 ms, but the
 * first waitpid() almost always races the exec, so each command slept one whole
 * tick before its second try.  A policy sync forks ~50 commands, so the floor
 * alone accounted for ~5 s of a ~5.2 s apply -- long enough that webd's ubus
 * client gave up first (2 s budget) and reported a validation failure for a
 * transaction that then committed anyway, seconds after the user was told
 * nothing had changed.
 *
 * Back off geometrically instead: 200 us doubling up to the same 100 ms ceiling.
 * A fast command now returns after ~600 us of sleeping; a genuinely slow one
 * still settles at one wakeup per 100 ms, so the worst case is unchanged.  The
 * ceiling keeps the old name because the two SIGTERM-escalation sleeps below
 * want a full grace tick, not a backed-off one.
 */
#define JMX_ROUTE_CMD_POLL_MIN_US 200
#define JMX_ROUTE_CMD_POLL_US 100000
#define JMX_ROUTE_HEALTH_MAX_STATES 32
#define JMX_ROUTE_HEALTH_IFNAME_LEN 32
#define JMX_ROUTE_HEALTH_TARGET_LEN 128
#define JMX_ROUTE_HEALTH_STATUS_PATH "/tmp/dreamingwrt-wan-health.status"
#define JMX_ROUTE_SNAPSHOT_CACHE_SEC 5
#define JMX_ROUTE_HEALTH_STALE_SEC 20
#define JMX_ROUTE_HEALTH_RECOVERY_SEC 20
#define JMX_ROUTE_HEALTH_RECOVERY_SAMPLES 2
#define JMX_ROUTE_HEALTH_FINANCE_CATEGORY 14
#define JMX_ROUTE_REBIND_SELECTIVE 2
#define JMX_ROUTE_REBIND_ALL 3
#define JMX_ROUTE_STATE_DB_PATH "/var/lib/dreamingwrt/network_state.db"
#define JMX_ROUTE_ADV_SYNC_STATE "/tmp/jmx_route_advanced_sync.json"
#define JMX_ROUTE_RUNTIME_STALE_SEC 15
#define JMX_ROUTE_MAIN_NONDEFAULT_PRIO 1000
#define JMX_ROUTE_RULE_PRIO_BASE 10000

_Static_assert(JMX_ROUTE_MAIN_NONDEFAULT_PRIO < JMX_ROUTE_RULE_PRIO_BASE,
               "main non-default lookup must precede fwmark rules");

struct af_msg_hdr_local {
    uint32_t magic;
    uint32_t len;
};

struct route_health_state {
    uint8_t id;
    uint8_t known;
    uint8_t healthy;
    uint32_t generation;
    uint32_t fail_count;
    uint32_t ok_count;
    uint8_t initialized;
    uint8_t quality_level;
    uint8_t raw_level;
    uint8_t penalty_peak_level;
    uint8_t adaptive_weight;
    uint8_t recovery_observing;
    uint8_t recovery_target_level;
    uint8_t recovery_samples;
    uint8_t last_rebind_mode;
    uint32_t transition_count;
    time_t last_probe;
    time_t last_change;
    time_t recovery_since;
    int checked;
    int online;
    int latency_ms;
    int probe_loss_pct;
    int jitter_ms;
    int jitter_samples;
    int jitter_over_80_pct;
    int counters_valid;
    double up_loss_pct;
    double down_loss_pct;
    char name[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char ifname[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char target[JMX_ROUTE_HEALTH_TARGET_LEN];
    char reason[64];
    char health_mode[32];
};

struct route_health_snapshot {
    time_t updated_at;
    int checked;
    int online;
    int latency_ms;
    int probe_loss_pct;
    int jitter_ms;
    int jitter_samples;
    int jitter_over_80_pct;
    int counters_valid;
    double up_loss_pct;
    double down_loss_pct;
    char name[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char device[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char target[JMX_ROUTE_HEALTH_TARGET_LEN];
    char reason[64];
    char health_mode[32];
};

struct route_health_snapshot_set {
    time_t updated_at;
    size_t count;
    struct route_health_snapshot rows[JMX_ROUTE_MAX_WAN_IFACES];
};

struct route_sync_wan_map {
    uint8_t id;
    uint8_t carrier_id;
	uint32_t fwmark;
    uint32_t table_id;
    char name[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char ifname[JMX_ROUTE_HEALTH_IFNAME_LEN];
};

struct route_network_wan_runtime {
    char name[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char proto[16];
    char configured_ifname[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char l3_ifname[JMX_ROUTE_HEALTH_IFNAME_LEN];
    char gateway[64];
    uint32_t weight;
    uint8_t online;
};

struct route_network_wan_snapshot {
    size_t count;
    struct route_network_wan_runtime wans[JMX_ROUTE_MAX_WAN_IFACES];
};

struct route_adv_sync_stats {
    int checked;
    int synced;
    int skipped;
    int errors;
    int db_policy_rules;
    int legacy_policy_rules;
};

static struct route_health_state g_route_health[JMX_ROUTE_HEALTH_MAX_STATES];
static uint32_t g_route_health_generation;
static uint8_t g_route_auto_carriers[JMX_ROUTE_MAX_WAN_IFACES + 1];
static struct route_network_wan_snapshot g_route_network_wans;
static int g_route_network_wans_ready;

static struct {
    time_t updated_at;
    int valid;
    int count;
} g_route_main_nondefault_cache;

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

    /* nlmsg_len is the unpadded wire length.  Advertising NLMSG_SPACE here
     * makes the kernel include alignment bytes in af_hdr->len validation, so
     * only naturally aligned route messages (such as FLUSH) are accepted. */
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

int jmx_route_nl_appcat_flush(int nl_fd)
{
    struct { int32_t action; uint32_t count; } __packed msg = {
        .action = JMX_NL_ACT_APPCAT_FLUSH,
        .count = 0,
    };
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_appcat_batch(int nl_fd, const struct jmx_appcat_rec *recs,
                              uint32_t count)
{
    struct jmx_appcat_batch msg;
    int wire_len;

    if (!recs || !count || count > JMX_APPCAT_BATCH_MAX) {
        errno = EINVAL;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.action = JMX_NL_ACT_APPCAT_ADD;
    msg.count = count;
    memcpy(msg.recs, recs, count * sizeof(*recs));

    /* Send only the populated prefix so the kernel's payload-derived record
     * cap matches the advertised count exactly. */
    wire_len = (int)(offsetof(struct jmx_appcat_batch, recs) +
                     count * sizeof(*recs));
    return jmx_route_nl_send(nl_fd, &msg, wire_len);
}

int jmx_route_nl_wan_register(int nl_fd, uint8_t wan_id, const char *name,
                              uint32_t fwmark, uint32_t table_id, uint32_t gateway,
                              uint32_t weight)
{
    struct jmx_wan_register_wire msg;

    if (!weight) {
        errno = EINVAL;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.action = JMX_NL_ACT_WAN_REGISTER;
    msg.wan_id = wan_id;
    snprintf(msg.name, sizeof(msg.name), "%s", name ? name : "");
    msg.fwmark = fwmark;
    msg.table_id = table_id;
    msg.gateway = gateway;
    msg.weight = weight;
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

int jmx_route_nl_wan_weight(int nl_fd, uint8_t wan_id, uint32_t weight)
{
    struct { int32_t action; uint8_t wan_id; uint32_t weight; } __packed msg = {
        .action = JMX_NL_ACT_WAN_WEIGHT,
        .wan_id = wan_id,
        .weight = weight,
    };

    if (weight < 1 || weight > 100) {
        errno = EINVAL;
        return -1;
    }
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_wan_adaptive_weight(int nl_fd, uint8_t wan_id, uint32_t weight)
{
    struct { int32_t action; uint8_t wan_id; uint32_t weight; } __packed msg = {
        .action = JMX_NL_ACT_WAN_ADAPTIVE_WEIGHT,
        .wan_id = wan_id,
        .weight = weight,
    };

    if (weight < 1 || weight > 100) {
        errno = EINVAL;
        return -1;
    }
    return jmx_route_nl_send(nl_fd, &msg, sizeof(msg));
}

int jmx_route_nl_wan_rebind(int nl_fd, uint8_t wan_id, uint8_t mode)
{
    struct { int32_t action; uint8_t wan_id; uint8_t mode; } __packed msg = {
        .action = JMX_NL_ACT_WAN_REBIND,
        .wan_id = wan_id,
        .mode = mode,
    };

    if (!wan_id || (mode != JMX_ROUTE_REBIND_SELECTIVE &&
                    mode != JMX_ROUTE_REBIND_ALL)) {
        errno = EINVAL;
        return -1;
    }
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

int jmx_route_nl_rule_add_v2(int nl_fd, const struct jmx_route_rule_wire *rule,
                             uint32_t enhancements)
{
    struct jmx_route_rule_wire_v2 msg;

    if (!rule || (enhancements & ~JMX_ROUTE_ENHANCEMENT_KNOWN)) {
        errno = EINVAL;
        return -1;
    }
    memset(&msg, 0, sizeof(msg));
    msg.action = JMX_NL_ACT_ROUTE_ADD_V2;
    msg.rule = *rule;
    msg.enhancements = enhancements;
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
    const char *text;
    char *end = NULL;
    unsigned long long value;

    if (!obj || !json_object_object_get_ex(obj, key, &v))
        return def;
    if (json_object_is_type(v, json_type_int)) {
        int64_t number = json_object_get_int64(v);

        return number >= 0 && (uint64_t)number <= UINT32_MAX ?
               (uint32_t)number : def;
    }
    /* webd stores adaptive_penalty_sticky and migration_required as JSON
     * booleans, while enabled/prio arrive as ints. Without this branch a
     * boolean falls through to the string test and returns def, so
     * adaptive_penalty_sticky:true read as 0, the enhancement bit was never
     * set, and the rule silently went out over the v1 netlink ABI. */
    if (json_object_is_type(v, json_type_boolean))
        return json_object_get_boolean(v) ? 1U : 0U;
    if (!json_object_is_type(v, json_type_string))
        return def;
    text = json_object_get_string(v);
    if (!text || !text[0] || text[0] == '-')
        return def;
    errno = 0;
    value = strtoull(text, &end, 0);
    return !errno && end != text && !*end && value <= UINT32_MAX ?
           (uint32_t)value : def;
}

static int json_get_weight(struct json_object *obj, const char *key,
                           uint32_t def, uint32_t *weight)
{
    struct json_object *v = NULL;
    int64_t n;

    if (!weight)
        return -1;
    if (!obj || !json_object_object_get_ex(obj, key, &v)) {
        *weight = def;
        return def ? 0 : -1;
    }
    if (!json_object_is_type(v, json_type_int))
        return -1;
    n = json_object_get_int64(v);
    if (n <= 0 || (uint64_t)n > UINT32_MAX)
        return -1;
    *weight = (uint32_t)n;
    return 0;
}

static int json_has_key(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;

    return obj && key && json_object_object_get_ex(obj, key, &v);
}

static uint8_t carrier_from_string(const char *s);
static uint8_t sticky_mode_from_string(const char *s);
static const char *sticky_mode_algorithm(uint8_t mode);
static int route_main_nondefault_rule_install(void);
static const char *uci_opt(struct uci_section *s, const char *name);
static uint32_t parse_u32_opt(struct uci_section *s, const char *name, uint32_t def);
static uint32_t parse_weight_opt(struct uci_section *s, uint32_t def);
static uint32_t route_ipv4_from_string(const char *s, uint32_t def);
static struct json_object *route_parse_proc_status(FILE *fp);
static int jmx_route_apply_system_route(const char *ifname, uint32_t fwmark,
                                        uint32_t table_id, const char *gateway);
static void jmx_route_cleanup_system_route(uint32_t table_id);
static int jmx_route_sync_json(struct json_object *config);
static void route_rule_from_json(struct json_object *rule,
                                 struct jmx_route_rule_wire *out,
                                 int default_prio, uint32_t *enhancements,
                                 int legacy_adaptive_fallback);
static int route_kernel_rule_v2_supported(uint32_t *enhancements_out);
static int route_config_requires_rule_v2(struct json_object *config);
static int route_policy_kernel_readback_matches(struct json_object *config,
                                                int carrier_neutral,
                                                int verify_all_rules,
                                                int *weights_enforced,
                                                char *error, size_t error_len);

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
    uint32_t weight;

    if (json_get_weight(req_obj, "weight", 1, &weight) != 0) {
        errno = EINVAL;
        return route_result(-1);
    }

    fd = route_open_nl();
    if (fd < 0)
        return route_result(-1);
    rc = jmx_route_nl_wan_register(fd, wan_id, name, fwmark, table_id,
                                   gateway, weight);
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
    struct json_object *wan_arr = NULL, *members = NULL;
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
    {
        struct json_object *mode_obj = NULL;

        if (json_object_object_get_ex(req_obj, "algorithm", &mode_obj) &&
            json_object_is_type(mode_obj, json_type_string))
            r.sticky_mode = sticky_mode_from_string(json_object_get_string(mode_obj));
        else if (json_object_object_get_ex(req_obj, "sticky_mode", &mode_obj) &&
            json_object_is_type(mode_obj, json_type_string))
            r.sticky_mode = sticky_mode_from_string(json_object_get_string(mode_obj));
        else
            r.sticky_mode = (uint8_t)json_get_u32(req_obj, "sticky_mode", JMX_STICKY_SIP);
    }
    if (r.sticky_mode > JMX_STICKY_MAX) {
        errno = EINVAL;
        return route_result(-1);
    }

    if (json_object_object_get_ex(req_obj, "members", &members) &&
        json_object_is_type(members, json_type_array)) {
        int n = json_object_array_length(members);

        if (n > JMX_ROUTE_MAX_WAN_IFACES)
            n = JMX_ROUTE_MAX_WAN_IFACES;
        for (i = 0; i < n; i++) {
            struct json_object *member = json_object_array_get_idx(members, i);
            uint32_t weight = 0;

            if (!member || !json_object_is_type(member, json_type_object) ||
                json_get_weight(member, "weight", 1, &weight) != 0) {
                errno = EINVAL;
                return route_result(-1);
            }
            r.wan_ids[i] = (uint8_t)json_get_u32(member, "wan_id", 0);
            r.wan_weights[i] = weight;
            if (!r.wan_ids[i]) {
                errno = EINVAL;
                return route_result(-1);
            }
        }
        r.wan_count = (uint8_t)n;
    } else if (json_object_object_get_ex(req_obj, "wan_ids", &wan_arr) &&
               json_object_is_type(wan_arr, json_type_array)) {
        int n = json_object_array_length(wan_arr);
        if (n > JMX_ROUTE_MAX_WAN_IFACES)
            n = JMX_ROUTE_MAX_WAN_IFACES;
        for (i = 0; i < n; i++)
            r.wan_ids[i] = (uint8_t)json_object_get_int(json_object_array_get_idx(wan_arr, i));
        r.wan_count = (uint8_t)n;
    }

    if (route_main_nondefault_rule_install() != 0) {
        errno = EIO;
        return route_result(-1);
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

static int route_wait_cmd(pid_t pid, int *status)
{
    time_t deadline = time(NULL) + JMX_ROUTE_CMD_TIMEOUT_SEC;
    unsigned int poll_us = JMX_ROUTE_CMD_POLL_MIN_US;

    for (;;) {
        pid_t r = waitpid(pid, status, WNOHANG);

        if (r == pid)
            return 0;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (time(NULL) >= deadline) {
            int i;

            kill(pid, SIGTERM);
            for (i = 0; i < 10; i++) {
                r = waitpid(pid, status, WNOHANG);
                if (r == pid)
                    return -1;
                if (r < 0 && errno != EINTR)
                    return -1;
                usleep(JMX_ROUTE_CMD_POLL_US);
            }
            kill(pid, SIGKILL);
            while (waitpid(pid, status, 0) < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            return -1;
        }
        usleep(poll_us);
        if (poll_us < JMX_ROUTE_CMD_POLL_US) {
            poll_us *= 2;
            if (poll_us > JMX_ROUTE_CMD_POLL_US)
                poll_us = JMX_ROUTE_CMD_POLL_US;
        }
    }
}

static int route_run_cmd(char *const argv[])
{
    void (*old_sigchld)(int);
    pid_t pid;
    int status = -1;

    if (!argv || !argv[0])
        return -1;

    old_sigchld = signal(SIGCHLD, SIG_DFL);
    pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (pid < 0) {
        signal(SIGCHLD, old_sigchld);
        return -1;
    }
    if (route_wait_cmd(pid, &status) != 0) {
        signal(SIGCHLD, old_sigchld);
        return -1;
    }
    signal(SIGCHLD, old_sigchld);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static int route_safe_token(const char *s, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)s;

    if (!s || !s[0] || strlen(s) >= max_len)
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.' ||
            *p == ':' || *p == '/' || *p == '@' || *p == '+')
            continue;
        return 0;
    }
    return 1;
}

static int route_ifname_ok(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    if (!s || !s[0] || strlen(s) >= JMX_ROUTE_HEALTH_IFNAME_LEN)
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == '@')
            continue;
        return 0;
    }
    return 1;
}

static void route_trim(char *s)
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

static int route_read_cmd_output(char *const argv[], char *out, size_t out_len)
{
    void (*old_sigchld)(int);
    int pipefd[2];
    pid_t pid;
    int status = -1;
    int exited = 0;
    size_t used = 0;
    time_t deadline;
    unsigned int poll_us = JMX_ROUTE_CMD_POLL_MIN_US;

    if (!argv || !argv[0] || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (pipe(pipefd) != 0)
        return -1;

    old_sigchld = signal(SIGCHLD, SIG_DFL);
    pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);

        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        if (fd >= 0) {
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    if (pid < 0) {
        close(pipefd[0]);
        signal(SIGCHLD, old_sigchld);
        return -1;
    }

    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    deadline = time(NULL) + JMX_ROUTE_CMD_TIMEOUT_SEC;
    while (!exited) {
        char buf[1024];
        ssize_t n;

        for (;;) {
            n = read(pipefd[0], buf, sizeof(buf));
            if (n > 0) {
                if (used + 1 < out_len) {
                    size_t copy = (size_t)n;

                    if (copy > out_len - used - 1)
                        copy = out_len - used - 1;
                    memcpy(out + used, buf, copy);
                    used += copy;
                    out[used] = '\0';
                }
                continue;
            }
            if (n == 0)
                break;
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            break;
        }
        if (waitpid(pid, &status, WNOHANG) == pid) {
            exited = 1;
            continue;
        }
        if (time(NULL) >= deadline) {
            kill(pid, SIGTERM);
            usleep(JMX_ROUTE_CMD_POLL_US);
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            close(pipefd[0]);
            signal(SIGCHLD, old_sigchld);
            return -1;
        }
        usleep(poll_us);
        if (poll_us < JMX_ROUTE_CMD_POLL_US) {
            poll_us *= 2;
            if (poll_us > JMX_ROUTE_CMD_POLL_US)
                poll_us = JMX_ROUTE_CMD_POLL_US;
        }
    }
    for (;;) {
        char buf[1024];
        ssize_t n = read(pipefd[0], buf, sizeof(buf));

        if (n > 0) {
            if (used + 1 < out_len) {
                size_t copy = (size_t)n;

                if (copy > out_len - used - 1)
                    copy = out_len - used - 1;
                memcpy(out + used, buf, copy);
                used += copy;
                out[used] = '\0';
            }
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    close(pipefd[0]);
    signal(SIGCHLD, old_sigchld);
    route_trim(out);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || !out[0])
        return -1;
    return 0;
}

static int route_main_nondefault_rule_count_raw(void)
{
    char output[8192];
    char *line;
    char *saveptr = NULL;
    char *argv[] = { "ip", "-4", "rule", "show", NULL };
    char priority_prefix[24];
    int count = 0;

    if (route_read_cmd_output(argv, output, sizeof(output)) != 0)
        return -1;

    snprintf(priority_prefix, sizeof(priority_prefix), "%u:",
             JMX_ROUTE_MAIN_NONDEFAULT_PRIO);
    for (line = strtok_r(output, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *p = line;

        while (*p && isspace((unsigned char)*p))
            p++;
        if (strncmp(p, priority_prefix, strlen(priority_prefix)) != 0)
            continue;
        if ((!strstr(p, "lookup main") && !strstr(p, "table main")) ||
            !strstr(p, "suppress_prefixlength 0"))
            continue;
        count++;
    }
    return count;
}

static int route_main_nondefault_rule_count(void)
{
    time_t now = time(NULL);

    if (g_route_main_nondefault_cache.valid &&
        now - g_route_main_nondefault_cache.updated_at < JMX_ROUTE_SNAPSHOT_CACHE_SEC)
        return g_route_main_nondefault_cache.count;
    g_route_main_nondefault_cache.count = route_main_nondefault_rule_count_raw();
    if (g_route_main_nondefault_cache.count >= 0) {
        g_route_main_nondefault_cache.updated_at = now;
        g_route_main_nondefault_cache.valid = 1;
    } else {
        g_route_main_nondefault_cache.valid = 0;
    }
    return g_route_main_nondefault_cache.count;
}

static int route_main_nondefault_rule_install(void)
{
    char priority[16];
    char *argv[] = { "ip", "-4", "rule", "add", "priority", priority,
                     "lookup", "main", "suppress_prefixlength", "0", NULL };
    char *del_argv[] = { "ip", "-4", "rule", "del", "priority", priority,
                         "lookup", "main", "suppress_prefixlength", "0", NULL };
    int count = route_main_nondefault_rule_count_raw();

    snprintf(priority, sizeof(priority), "%u", JMX_ROUTE_MAIN_NONDEFAULT_PRIO);
    if (count < 0)
        return -1;
    while (count > 1) {
        if (route_run_cmd(del_argv) != 0)
            return -1;
        count--;
    }
    if (count == 0 && route_run_cmd(argv) != 0)
        return -1;
    return route_main_nondefault_rule_count_raw() == 1 ? 0 : -1;
}

static const char *route_json_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return NULL;
    return json_object_get_string(v);
}

static int route_json_bool_def(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

static int route_json_int_def(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

struct route_ubus_json_result {
    struct json_object *json;
};

static void route_ubus_json_cb(struct ubus_request *req, int type,
                               struct blob_attr *msg)
{
    struct route_ubus_json_result *result = req ? req->priv : NULL;
    char *text;

    (void)type;
    if (!result || !msg)
        return;
    text = blobmsg_format_json(msg, true);
    if (!text)
        return;
    if (result->json)
        json_object_put(result->json);
    result->json = json_tokener_parse(text);
    free(text);
}

static struct json_object *route_ubus_call_json(const char *object,
                                                const char *method,
                                                int timeout_ms)
{
    struct route_ubus_json_result result = { .json = NULL };
    struct blob_buf request = {};
    struct ubus_context *ctx = NULL;
    uint32_t id = 0;
    int rc;

    if (!object || !method)
        return NULL;
    ctx = ubus_connect(NULL);
    if (!ctx)
        return NULL;
    rc = ubus_lookup_id(ctx, object, &id);
    if (rc == UBUS_STATUS_OK) {
        blob_buf_init(&request, 0);
        rc = ubus_invoke(ctx, id, method, request.head,
                         route_ubus_json_cb, &result,
                         timeout_ms > 0 ? timeout_ms : 3000);
        blob_buf_free(&request);
    }
    ubus_free(ctx);
    if (rc != UBUS_STATUS_OK) {
        if (result.json)
            json_object_put(result.json);
        return NULL;
    }
    return result.json;
}

static int route_ifstatus_runtime(const char *wan_name, char *l3_out, size_t l3_len,
                                  char *gateway_out, size_t gateway_len, int *online_out)
{
    char json[65536];
    char *const argv[] = { "ifstatus", (char *)wan_name, NULL };
    struct json_object *root;
    struct json_object *routes = NULL;
    char object[64];
    const char *l3;
    int online;
    size_t i, n;

    if (l3_out && l3_len > 0)
        l3_out[0] = '\0';
    if (gateway_out && gateway_len > 0)
        gateway_out[0] = '\0';
    if (online_out)
        *online_out = 0;
    if ((!l3_out || l3_len == 0) && (!gateway_out || gateway_len == 0) && !online_out)
        return -1;
    if (!route_ifname_ok(wan_name))
        return -1;
    snprintf(object, sizeof(object), "network.interface.%s", wan_name);
    root = route_ubus_call_json(object, "status", 3000);
    if (!root && route_read_cmd_output(argv, json, sizeof(json)) == 0)
        root = json_tokener_parse(json);
    if (!root)
        return -1;
    l3 = route_json_string(root, "l3_device");
    if (l3_out && l3_len > 0 && l3 && route_ifname_ok(l3))
        snprintf(l3_out, l3_len, "%s", l3);
    online = route_json_bool_def(root, "up", 0) &&
             route_json_bool_def(root, "available", 0);
    if (online_out)
        *online_out = online;
    if (gateway_out && gateway_len > 0 &&
        json_object_object_get_ex(root, "route", &routes) &&
        routes && json_object_is_type(routes, json_type_array)) {
        n = json_object_array_length(routes);
        for (i = 0; i < n; i++) {
            struct json_object *r = json_object_array_get_idx(routes, i);
            const char *target = route_json_string(r, "target");
            const char *nexthop = route_json_string(r, "nexthop");
            int mask = route_json_int_def(r, "mask", -1);

            if ((!target || !strcmp(target, "0.0.0.0")) && mask == 0 &&
                nexthop && nexthop[0]) {
                snprintf(gateway_out, gateway_len, "%s", nexthop);
                break;
            }
        }
    }
    json_object_put(root);
    return 0;
}

static int route_l3_device_from_ifstatus(const char *wan_name, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (route_ifstatus_runtime(wan_name, out, out_len, NULL, 0, NULL) != 0)
        return -1;
    return route_ifname_ok(out) ? 0 : -1;
}

static int route_l3_device_from_device(const char *device, char *out, size_t out_len)
{
    struct json_object *root;
    struct json_object *interfaces = NULL;
    size_t i, n;
    int found = 0;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (!route_ifname_ok(device))
        return -1;
    root = route_ubus_call_json("network.interface", "dump", 3000);
    if (!root)
        return -1;
    if (!json_object_object_get_ex(root, "interface", &interfaces) ||
        !interfaces || !json_object_is_type(interfaces, json_type_array)) {
        json_object_put(root);
        return -1;
    }
    n = json_object_array_length(interfaces);
    for (i = 0; i < n; i++) {
        struct json_object *iface = json_object_array_get_idx(interfaces, i);
        const char *dev = route_json_string(iface, "device");
        const char *l3;

        if (!dev || strcmp(dev, device) != 0)
            continue;
        l3 = route_json_string(iface, "l3_device");
        if (!l3)
            continue;
        snprintf(out, out_len, "%s", l3);
        found = route_ifname_ok(out);
        break;
    }
    json_object_put(root);
    return found ? 0 : -1;
}

static const char *route_wan_ifname_option(struct uci_section *s)
{
    const char *ifname = uci_opt(s, "ifname");

    if (!ifname || !ifname[0])
        ifname = uci_opt(s, "device");
    return ifname;
}

static void route_health_probe_ifname(struct uci_section *s, char *out, size_t out_len)
{
    const char *name = uci_opt(s, "name");
    const char *ifname = route_wan_ifname_option(s);

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (name && name[0] && route_l3_device_from_ifstatus(name, out, out_len) == 0)
        return;
    if (s && s->e.name && route_l3_device_from_ifstatus(s->e.name, out, out_len) == 0)
        return;
    if (ifname && ifname[0] && route_l3_device_from_device(ifname, out, out_len) == 0)
        return;
    if (ifname && route_ifname_ok(ifname))
        snprintf(out, out_len, "%s", ifname);
}

static int route_proto_is_wan(const char *proto)
{
    if (!proto || !proto[0])
        return 1;
    if (!strcmp(proto, "dhcpv6") || !strcmp(proto, "none"))
        return 0;
    return !strcmp(proto, "dhcp") || !strcmp(proto, "static") ||
           !strcmp(proto, "pppoe") || !strcmp(proto, "pptp") ||
           !strcmp(proto, "l2tp") || !strcmp(proto, "qmi") ||
           !strcmp(proto, "mbim") || !strcmp(proto, "ncm");
}

static int route_network_iface_is_wan(const char *name, const char *proto)
{
    if (!name || !name[0])
        return 0;
    if (!route_proto_is_wan(proto))
        return 0;
    if (!strncmp(name, "wan", 3))
        return 1;
    return 0;
}

static int route_section_disabled(struct uci_section *s)
{
    const char *disabled = uci_opt(s, "disabled");
    const char *enabled = uci_opt(s, "enabled");

    if (disabled && disabled[0] && strcmp(disabled, "0") &&
        strcasecmp(disabled, "false") && strcasecmp(disabled, "no") &&
        strcasecmp(disabled, "off"))
        return 1;
    if (enabled && enabled[0] &&
        (!strcmp(enabled, "0") || !strcasecmp(enabled, "false") ||
         !strcasecmp(enabled, "no") || !strcasecmp(enabled, "off")))
        return 1;
    return 0;
}

static int route_network_dump_fill(struct json_object *interfaces,
                                   const char *name,
                                   char *l3_out, size_t l3_len,
                                   char *gateway_out, size_t gateway_len,
                                   int *online_out)
{
    size_t i, n;

    if (!interfaces || !name || !name[0])
        return -1;
    n = json_object_array_length(interfaces);
    for (i = 0; i < n; i++) {
        struct json_object *iface = json_object_array_get_idx(interfaces, i);
        struct json_object *routes = NULL;
        const char *ifname = route_json_string(iface, "interface");
        const char *l3;
        int up;
        int available;

        if (!ifname || strcmp(ifname, name) != 0)
            continue;
        l3 = route_json_string(iface, "l3_device");
        if (l3_out && l3_len > 0 && l3 && route_ifname_ok(l3))
            snprintf(l3_out, l3_len, "%s", l3);
        up = route_json_bool_def(iface, "up", 0);
        available = route_json_bool_def(iface, "available", up);
        if (online_out)
            *online_out = up && available;
        if (gateway_out && gateway_len > 0 &&
            json_object_object_get_ex(iface, "route", &routes) &&
            routes && json_object_is_type(routes, json_type_array)) {
            size_t j, m = json_object_array_length(routes);

            for (j = 0; j < m; j++) {
                struct json_object *r = json_object_array_get_idx(routes, j);
                const char *target = route_json_string(r, "target");
                const char *nexthop = route_json_string(r, "nexthop");
                int mask = route_json_int_def(r, "mask", -1);

                if ((!target || !strcmp(target, "0.0.0.0")) && mask == 0 &&
                    nexthop && nexthop[0]) {
                    snprintf(gateway_out, gateway_len, "%s", nexthop);
                    break;
                }
            }
        }
        return 0;
    }
    return -1;
}

static const struct route_network_wan_runtime *
route_network_wan_snapshot_find_name(const struct route_network_wan_snapshot *snapshot,
                                     const char *name)
{
    size_t i;

    if (!snapshot || !name || !name[0])
        return NULL;
    for (i = 0; i < snapshot->count; i++)
        if (!strcmp(snapshot->wans[i].name, name))
            return &snapshot->wans[i];
    return NULL;
}

static int route_network_wan_snapshot_get(struct route_network_wan_snapshot *snapshot)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    struct json_object *root = NULL;
    struct json_object *interfaces = NULL;
    int dump_ok = 0;
    int rc = 0;

    if (!snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    root = route_ubus_call_json("network.interface", "dump", 3000);
    if (root &&
        json_object_object_get_ex(root, "interface", &interfaces) &&
        interfaces && json_object_is_type(interfaces, json_type_array))
        dump_ok = 1;

    ctx = uci_alloc_context();
    if (!ctx) {
        if (root)
            json_object_put(root);
        return -1;
    }
    if (uci_load(ctx, "network", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        if (root)
            json_object_put(root);
        return -1;
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        struct route_network_wan_runtime *wan;
        const char *name;
        const char *proto;
        const char *configured_ifname;
        int online = 0;

        if (!s || strcmp(s->type, "interface") != 0)
            continue;
        name = s->e.name;
        proto = uci_opt(s, "proto");
        if (!route_network_iface_is_wan(name, proto) || route_section_disabled(s))
            continue;
        if (snapshot->count >= JMX_ROUTE_MAX_WAN_IFACES) {
            rc = -1;
            break;
        }
        wan = &snapshot->wans[snapshot->count];
        if (dump_ok) {
            if (route_network_dump_fill(interfaces, name, wan->l3_ifname,
                                        sizeof(wan->l3_ifname), wan->gateway,
                                        sizeof(wan->gateway), &online) != 0) {
                rc = -1;
                break;
            }
        } else if (route_ifstatus_runtime(name, wan->l3_ifname,
                                          sizeof(wan->l3_ifname), wan->gateway,
                                          sizeof(wan->gateway), &online) != 0) {
            rc = -1;
            break;
        }
        configured_ifname = route_wan_ifname_option(s);
        snprintf(wan->name, sizeof(wan->name), "%s", name);
        snprintf(wan->proto, sizeof(wan->proto), "%s", proto ? proto : "");
        snprintf(wan->configured_ifname, sizeof(wan->configured_ifname), "%s",
                 configured_ifname ? configured_ifname : "");
        wan->weight = parse_weight_opt(s, 1);
        wan->online = online ? 1 : 0;
        snapshot->count++;
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    if (root)
        json_object_put(root);
    return rc;
}

static int route_network_wan_runtime_changed(
    struct route_network_wan_snapshot *current, int loaded)
{
    size_t i;

    if (!current)
        return -1;
    if (!loaded && route_network_wan_snapshot_get(current) != 0)
        return -1;
    if (!g_route_network_wans_ready)
        return 1;

    /*
     * This predicate decides whether routed tears down and rebuilds the entire
     * WAN/rule graph.  Liveness is deliberately excluded: a PPP reconnect can
     * briefly clear online, l3_ifname, or gateway, and treating that as a
     * topology edit creates a much larger outage by flushing every WAN and
     * every route rule.  Health changes use JMX_NL_ACT_WAN_HEALTH instead.
     */
    if (current->count != g_route_network_wans.count)
        return 1;
    for (i = 0; i < current->count; i++) {
        const struct route_network_wan_runtime *now = &current->wans[i];
        const struct route_network_wan_runtime *old = &g_route_network_wans.wans[i];

        if (strcmp(now->name, old->name) ||
            strcmp(now->proto, old->proto) ||
            strcmp(now->configured_ifname, old->configured_ifname) ||
            now->weight != old->weight)
            return 1;
    }
    return 0;
}

static void route_sync_wan_map_add(struct route_sync_wan_map *map, size_t map_len,
                                   int *map_count, uint8_t id, const char *name,
                                   const char *ifname, uint32_t fwmark,
				   uint32_t table_id)
{
    int i;

    if (!map || !map_count || !id)
        return;
    for (i = 0; i < *map_count && (size_t)i < map_len; i++) {
        if (map[i].id == id || (name && name[0] && !strcmp(map[i].name, name))) {
            map[i].id = id;
			map[i].fwmark = fwmark;
            map[i].table_id = table_id;
            if (name && name[0])
                snprintf(map[i].name, sizeof(map[i].name), "%s", name);
            if (ifname && ifname[0])
                snprintf(map[i].ifname, sizeof(map[i].ifname), "%s", ifname);
            return;
        }
    }
    if ((size_t)*map_count >= map_len)
        return;
    memset(&map[*map_count], 0, sizeof(map[*map_count]));
    map[*map_count].id = id;
	map[*map_count].fwmark = fwmark;
    map[*map_count].table_id = table_id;
    snprintf(map[*map_count].name, sizeof(map[*map_count].name), "%s", name ? name : "");
    snprintf(map[*map_count].ifname, sizeof(map[*map_count].ifname), "%s", ifname ? ifname : "");
    (*map_count)++;
}

/* True when a WAN with this UCI section name was already registered in this
 * sync pass, so the UCI top-up path can skip it and stay idempotent. */
static int route_sync_wan_registered_by_name(const struct route_sync_wan_map *map,
                                             int map_count, const char *name)
{
    int i;

    if (!map || !name || !name[0])
        return 0;
    for (i = 0; i < map_count; i++)
        if (map[i].id && !strcmp(map[i].name, name))
            return 1;
    return 0;
}

static int route_direction_gateway_mode(void)
{
    int mode = 0;

    if (jmx_work_mode_config_get(&mode, NULL, 0, NULL, 0) != 0)
        return 0;
    return mode == 0;
}

static void route_direction_store_be16(void *dst, uint16_t value)
{
    uint8_t bytes[2] = {
        (uint8_t)(value >> 8),
        (uint8_t)value,
    };

    memcpy(dst, bytes, sizeof(bytes));
}

static void route_direction_store_be32(void *dst, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)(value >> 24),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 8),
        (uint8_t)value,
    };

    memcpy(dst, bytes, sizeof(bytes));
}

static void route_direction_store_be64(void *dst, uint64_t value)
{
    uint8_t bytes[8] = {
        (uint8_t)(value >> 56),
        (uint8_t)(value >> 48),
        (uint8_t)(value >> 40),
        (uint8_t)(value >> 32),
        (uint8_t)(value >> 24),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 8),
        (uint8_t)value,
    };

    memcpy(dst, bytes, sizeof(bytes));
}

static int route_direction_snapshot_wire(
    const struct jmx_direction_snapshot *snapshot,
    uint8_t **out_wire, size_t *out_len)
{
    struct jmx_direction_nl_header *header;
    uint8_t *wire, *cursor;
    size_t wire_len;
    uint16_t lan_count;
    uint16_t local_count;
    uint16_t wan_count;
    uint16_t i;

    if (!snapshot || !out_wire || !out_len ||
        snapshot->version != JMX_DIRECTION_SNAPSHOT_VERSION ||
        !snapshot->generation || snapshot->ready > 1 ||
        snapshot->gateway_mode > 1 ||
        snapshot->lan_prefix_count > JMX_DIRECTION_MAX_LAN_PREFIXES ||
        snapshot->local_address_count > JMX_DIRECTION_MAX_LOCAL_ADDRS ||
        snapshot->wan_count > JMX_DIRECTION_MAX_WANS ||
        (snapshot->ready && jmx_direction_snapshot_validate(snapshot) != 0))
        return -1;
    /* An unready publication is intentionally header-only.  A partially
     * built local snapshot must never cross the ABI as if it were usable. */
    lan_count = snapshot->ready ? snapshot->lan_prefix_count : 0;
    local_count = snapshot->ready ? snapshot->local_address_count : 0;
    wan_count = snapshot->ready ? snapshot->wan_count : 0;
    wire_len = sizeof(*header) +
               (size_t)lan_count *
                   sizeof(struct jmx_direction_nl_prefix) +
               (size_t)local_count *
                   sizeof(struct jmx_direction_nl_local_address) +
               (size_t)wan_count * sizeof(struct jmx_direction_nl_wan);
    wire = calloc(1, wire_len);
    if (!wire)
        return -1;
    header = (struct jmx_direction_nl_header *)wire;
    route_direction_store_be32(&header->action,
                               JMX_NL_ACT_DIRECTION_SNAPSHOT);
    route_direction_store_be16(&header->abi_version,
                               JMX_DIRECTION_NL_ABI_VERSION);
    route_direction_store_be16(&header->header_size, sizeof(*header));
    route_direction_store_be32(&header->message_size, (uint32_t)wire_len);
    route_direction_store_be64(&header->generation, snapshot->generation);
    header->ready = snapshot->ready ? 1 : 0;
    header->gateway_mode = snapshot->gateway_mode ? 1 : 0;
    route_direction_store_be16(&header->lan_prefix_count,
                               lan_count);
    route_direction_store_be16(&header->local_address_count,
                               local_count);
    route_direction_store_be16(&header->wan_count, wan_count);

    cursor = wire + sizeof(*header);
    for (i = 0; i < lan_count; i++) {
        struct jmx_direction_nl_prefix *entry =
            (struct jmx_direction_nl_prefix *)cursor;
        const struct jmx_direction_prefix *source =
            &snapshot->lan_prefixes[i];

        route_direction_store_be32(&entry->ifindex, source->ifindex);
        entry->family = source->family;
        entry->prefix_len = source->prefix_len;
        memcpy(entry->address, source->address, sizeof(entry->address));
        cursor += sizeof(*entry);
    }
    for (i = 0; i < local_count; i++) {
        struct jmx_direction_nl_local_address *entry =
            (struct jmx_direction_nl_local_address *)cursor;
        const struct jmx_direction_local_address *source =
            &snapshot->local_addresses[i];

        entry->family = source->family;
        memcpy(entry->address, source->address, sizeof(entry->address));
        cursor += sizeof(*entry);
    }
    for (i = 0; i < wan_count; i++) {
        struct jmx_direction_nl_wan *entry =
            (struct jmx_direction_nl_wan *)cursor;
        const struct jmx_direction_wan *source = &snapshot->wans[i];

        entry->wan_id = source->wan_id;
        entry->family_mask = source->family_mask;
        entry->registered = source->registered ? 1 : 0;
        route_direction_store_be32(&entry->ifindex, source->ifindex);
        route_direction_store_be32(&entry->route_identity,
                                   source->route_identity);
        route_direction_store_be32(&entry->table_id, source->table_id);
        route_direction_store_be32(&entry->reserved3, 0);
        cursor += sizeof(*entry);
    }
    *out_wire = wire;
    *out_len = wire_len;
    return 0;
}

static int route_direction_snapshot_send(int fd,
                                         const struct jmx_direction_snapshot *snapshot)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int rc;

    if (route_direction_snapshot_wire(snapshot, &wire, &wire_len) != 0)
        return -1;
    rc = jmx_route_nl_send(fd, wire, (int)wire_len);
    free(wire);
    return rc;
}

static int route_direction_snapshot_send_current(int fd)
{
    struct jmx_direction_snapshot snapshot;

    if (jmx_direction_snapshot_read_current(&snapshot) != 0)
        return -1;
    return route_direction_snapshot_send(fd, &snapshot);
}

static int route_direction_snapshot_publish(
    int fd, const struct route_sync_wan_map *map, int map_count)
{
    struct json_object *lan_response = NULL;
    struct json_object *lan_data = NULL;
    struct json_object *registered_wans = NULL;
    int gateway_mode = route_direction_gateway_mode();
    int rc = -1;
    int i;

    registered_wans = json_object_new_array();
    if (!registered_wans)
        return -1;
    for (i = 0; map && i < map_count; i++) {
        struct json_object *wan = json_object_new_object();

        if (!wan)
            goto done;
        json_object_object_add(wan, "id", json_object_new_int(map[i].id));
        json_object_object_add(wan, "ifname",
                               json_object_new_string(map[i].ifname));
        json_object_object_add(wan, "route_identity",
                               json_object_new_int64(map[i].fwmark));
        json_object_object_add(wan, "table",
                               json_object_new_int64(map[i].table_id));
        json_object_array_add(registered_wans, wan);
    }

    lan_response = jmx_netconfig_lan_list();
    if (!lan_response ||
        !json_object_object_get_ex(lan_response, "data", &lan_data) ||
        !lan_data) {
        goto done;
    }
    rc = jmx_direction_snapshot_refresh_json(lan_data, registered_wans,
                                              gateway_mode);
    if (rc == 0)
        rc = route_direction_snapshot_send_current(fd);
done:
    if (lan_response)
        json_object_put(lan_response);
    json_object_put(registered_wans);
    return rc;
}

/* Same question keyed by id: did this WAN get registered in this sync pass,
 * whether it came from the route_wan ledger or the UCI top-up below. */
static int route_sync_wan_registered_by_id(const struct route_sync_wan_map *map,
                                           int map_count, uint8_t id)
{
    int i;

    if (!map || !id)
        return 0;
    for (i = 0; i < map_count; i++)
        if (map[i].id == id)
            return 1;
    return 0;
}

/* Guards against listing the same WAN twice when a member appears in both
 * wan_ids and dangling_wan_ids. */
static int route_rule_wire_has_wan(const struct jmx_route_rule_wire *rule, uint8_t id)
{
    int i;

    if (!rule)
        return 0;
    for (i = 0; i < rule->wan_count && i < JMX_ROUTE_MAX_WAN_IFACES; i++)
        if (rule->wan_ids[i] == id)
            return 1;
    return 0;
}

/*
 * Reinstate rule members the export classified as dangling but which this sync
 * pass did register.
 *
 * route_wan is a user-facing ledger written only by route_config_set, while the
 * kernel also learns WANs from the UCI top-up in jmx_route_sync_json(). A line
 * dialled up in /etc/config/network therefore exists and forwards traffic while
 * being absent from the ledger, and jmx_route_db export splits any rule member
 * naming it into dangling_wan_ids because route_wan has no such row. The rule
 * then reaches the kernel naming only the ledger lines.
 *
 * On 30.1 that left the default rule at wans=1,2 while wan3 -- the current
 * default route carrying the most traffic of the four -- was registered,
 * healthy, and completely outside policy selection: no active_conn, no
 * proto_stats, and no rule constraining it. The fix belongs here rather than in
 * the export, which is right to distrust a member whose line it cannot see: by
 * the time rules are pushed, wan_map is the authoritative set of live WANs, so
 * a "dangling" id present there is not dangling at all.
 *
 * Members still absent from wan_map stay out, which is the case the export's
 * split exists for (a deleted line whose id could later be reused).
 *
 * Whether to reinstate at all is user configuration, because both answers are
 * legitimate: a user who wants every dialled line in the policy wants this, while
 * a user who deliberately left the later lines to the default route does not, and
 * reinstating would move their traffic without them asking. `policy` carries
 * route_global.dangling_wan_policy:
 *
 *   reinstate_registered  reinstate (default; the behaviour before the switch)
 *   keep_excluded         never reinstate, log once per skipped member
 *   per_rule              defer to the rule's own reinstate_dangling flag
 */
static void route_restore_dangling_wan_members(struct json_object *rule_json,
                                               struct jmx_route_rule_wire *rule,
                                               const struct route_sync_wan_map *map,
                                               int map_count,
                                               const char *policy)
{
    struct json_object *stale = NULL;
    int i;
    int reinstate;

    if (!rule_json || !rule || !map)
        return;
    if (!policy || !*policy)
        policy = "reinstate_registered";
    if (!strcmp(policy, "keep_excluded"))
        reinstate = 0;
    else if (!strcmp(policy, "per_rule"))
        reinstate = json_get_u32(rule_json, "reinstate_dangling", 1) ? 1 : 0;
    else
        reinstate = 1;
    if (!json_object_object_get_ex(rule_json, "dangling_wan_ids", &stale) ||
        !json_object_is_type(stale, json_type_array))
        return;
    for (i = 0; i < (int)json_object_array_length(stale) &&
                rule->wan_count < JMX_ROUTE_MAX_WAN_IFACES; i++) {
        struct json_object *value = json_object_array_get_idx(stale, i);
        int64_t raw;
        uint8_t id;

        if (!value || !json_object_is_type(value, json_type_int))
            continue;
        raw = json_object_get_int64(value);
        if (raw <= 0 || raw > JMX_ROUTE_MAX_WAN_IFACES)
            continue;
        id = (uint8_t)raw;
        if (!route_sync_wan_registered_by_id(map, map_count, id))
            continue;
        if (route_rule_wire_has_wan(rule, id))
            continue;
        if (!reinstate) {
            /* The member is live and could have been reinstated; the user asked
             * for it to stay out. Say so, otherwise this looks like the dangling
             * case the export split exists for. */
            LOG_WARN("jmx_route: rule '%s' member wan id=%u is registered but dangling_wan_policy=%s keeps it excluded",
                     json_get_str(rule_json, "name", ""), id, policy);
            continue;
        }
        rule->wan_ids[rule->wan_count++] = id;
        LOG_WARN("jmx_route: rule '%s' member wan id=%u was reported dangling but is registered; reinstating",
                 json_get_str(rule_json, "name", ""), id);
    }
}

static void route_sync_wan_map_set_carrier(struct route_sync_wan_map *map,
                                           int map_count, uint8_t id,
                                           uint8_t carrier_id)
{
    int i;

    for (i = 0; map && i < map_count; i++) {
        if (map[i].id == id) {
            map[i].carrier_id = carrier_id;
            return;
        }
    }
}

#define JMX_ROUTE_DNS_NFT_PATH "/etc/dreamingwrt/dns_domain_route.nft"
#define JMX_ROUTE_DNS_NFT_TABLE "dreamingwrt_dns_route"

#define JMX_ROUTE_IPV6_MW_TABLE "dreamingwrt_npt"

/*
 * IPv6 multi-WAN is only real when the SNAT66 table is actually loaded.
 * Four carrier /60s advertised as SLAAC prefixes let clients choose their own
 * source address, and therefore their own egress, which bypasses scheduling
 * entirely. The ULA + SNAT66 path is what hands that decision back to us, so
 * report live dataplane state rather than a compile-time constant: the UI must
 * not claim a capability the dataplane does not have.
 */
static int route_ipv6_multiwan_active(void)
{
	return nc_run_quiet("nft list table ip6 " JMX_ROUTE_IPV6_MW_TABLE
			    " >/dev/null 2>&1") == 0;
}

static int route_dns_domain_nft_table_exists(void)
{
	return nc_run_quiet("nft list table inet " JMX_ROUTE_DNS_NFT_TABLE
			    " >/dev/null 2>&1") == 0;
}

static int route_dns_domain_nft_chain_exists(void)
{
	return nc_run_quiet("nft list chain inet " JMX_ROUTE_DNS_NFT_TABLE
			    " prerouting >/dev/null 2>&1") == 0;
}

static int route_dns_domain_nft_set_exists(uint8_t wan_id)
{
	char command[256];

	snprintf(command, sizeof(command),
		 "nft list set inet %s wan_%u_v4 >/dev/null 2>&1",
		 JMX_ROUTE_DNS_NFT_TABLE, wan_id);
	return nc_run_quiet(command) == 0;
}

static int route_dns_domain_nft_write(const struct route_sync_wan_map *map,
				      int map_count, int *rule_count)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *st = NULL;
	FILE *fp = NULL;
	const struct route_sync_wan_map *desired[JMX_ROUTE_MAX_WAN_IFACES + 1] = {0};
	int table_exists, chain_exists = 0;
	int i, count = 0, rc = -1;

	if (rule_count)
		*rule_count = 0;
	if (sqlite3_open_v2(JMX_ROUTE_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		goto done;
	if (sqlite3_prepare_v2(db,
		"SELECT DISTINCT wan_id FROM wan_dns_policy WHERE enabled=1 "
		"AND domains NOT IN ('','[]') ORDER BY wan_id", -1, &st, NULL) != SQLITE_OK)
		goto done;
	while (sqlite3_step(st) == SQLITE_ROW) {
		const char *wan_id = (const char *)sqlite3_column_text(st, 0);
		const struct route_sync_wan_map *wan = NULL;

		for (i = 0; i < map_count; i++)
			if (wan_id && !strcmp(map[i].name, wan_id)) {
				wan = &map[i];
				break;
			}
		if (!wan || !wan->fwmark || !wan->table_id) {
			LOG_ERROR("jmx_route: DNS domain policy WAN is not registered: %s",
				  wan_id ? wan_id : "");
			goto done;
		}
		if (!wan->id || wan->id > JMX_ROUTE_MAX_WAN_IFACES)
			goto done;
		desired[wan->id] = wan;
		count++;
	}
	sqlite3_finalize(st);
	st = NULL;

	table_exists = route_dns_domain_nft_table_exists();
	if (table_exists)
		chain_exists = route_dns_domain_nft_chain_exists();
	fp = fopen(JMX_ROUTE_DNS_NFT_PATH ".new", "w");
	if (!fp)
		goto done;
	fprintf(fp, "# DreamingWrt DNS domain route rules - generated by dreamingwrt-core\n");
	if (count == 0) {
		if (table_exists)
			fprintf(fp, "delete table inet %s\n", JMX_ROUTE_DNS_NFT_TABLE);
	} else if (!table_exists) {
		fprintf(fp, "table inet %s {\n", JMX_ROUTE_DNS_NFT_TABLE);
		for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES; i++)
			if (desired[i]) {
				fprintf(fp, "\tset wan_%u_v4 {\n", desired[i]->id);
				fprintf(fp, "\t\ttype ipv4_addr\n");
				fprintf(fp, "\t\tflags timeout\n");
				fprintf(fp, "\t\ttimeout 1h\n\t}\n");
			}
		fprintf(fp, "\tchain prerouting {\n");
		fprintf(fp, "\t\ttype filter hook prerouting priority mangle + 2; policy accept;\n");
		for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES; i++)
			if (desired[i])
				fprintf(fp, "\t\tip daddr @wan_%u_v4 meta mark set 0x%x counter\n",
					desired[i]->id, desired[i]->fwmark);
		fprintf(fp, "\t}\n}\n");
	} else {
		if (chain_exists)
			fprintf(fp, "flush chain inet %s prerouting\n", JMX_ROUTE_DNS_NFT_TABLE);
		else
			fprintf(fp, "add chain inet %s prerouting { type filter hook prerouting priority mangle + 2; policy accept; }\n",
				JMX_ROUTE_DNS_NFT_TABLE);
		for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES; i++) {
			int set_exists = route_dns_domain_nft_set_exists((uint8_t)i);

			if (desired[i] && !set_exists)
				fprintf(fp, "add set inet %s wan_%u_v4 { type ipv4_addr; flags timeout; timeout 1h; }\n",
					JMX_ROUTE_DNS_NFT_TABLE, i);
			else if (!desired[i] && set_exists)
				fprintf(fp, "delete set inet %s wan_%u_v4\n",
					JMX_ROUTE_DNS_NFT_TABLE, i);
		}
		for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES; i++)
			if (desired[i])
				fprintf(fp, "add rule inet %s prerouting ip daddr @wan_%u_v4 meta mark set 0x%x counter\n",
					JMX_ROUTE_DNS_NFT_TABLE, desired[i]->id,
					desired[i]->fwmark);
	}
	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
		fp = NULL;
		goto done;
	}
	fp = NULL;
	if (rename(JMX_ROUTE_DNS_NFT_PATH ".new", JMX_ROUTE_DNS_NFT_PATH) != 0)
		goto done;
	rc = 0;
done:
	if (fp)
		fclose(fp);
	if (st)
		sqlite3_finalize(st);
	if (db)
		sqlite3_close(db);
	if (rc != 0)
		unlink(JMX_ROUTE_DNS_NFT_PATH ".new");
	if (rule_count)
		*rule_count = count;
	return rc;
}

static int route_dns_domain_nft_apply(const struct route_sync_wan_map *map,
				      int map_count)
{
	char command[512];
	int count = 0;

	if (route_dns_domain_nft_write(map, map_count, &count) != 0)
		return -1;
	if (nc_run_quiet("nft -c -f " JMX_ROUTE_DNS_NFT_PATH
			 " >/tmp/dw-dns-route-nft-check.log 2>&1") != 0)
		return -1;
	if (nc_run_quiet("nft -f " JMX_ROUTE_DNS_NFT_PATH
			 " >/tmp/dw-dns-route-nft-apply.log 2>&1") != 0)
		return -1;
	if (count == 0)
		return 0;
	snprintf(command, sizeof(command),
		 "nft list table inet %s >/tmp/dw-dns-route-nft-health.log 2>&1",
		 JMX_ROUTE_DNS_NFT_TABLE);
	return nc_run_quiet(command);
}

static uint8_t route_stored_wan_carrier(const char *name, const char *ifname)
{
    sqlite3 *db = jmx_db_handle();
    sqlite3_stmt *stmt = NULL;
    uint8_t carrier = JMX_CARRIER_ANY;

    if (!db || ((!name || !name[0]) && (!ifname || !ifname[0])) ||
        sqlite3_prepare_v2(db,
        "SELECT carrier FROM net_interfaces "
        "WHERE name=?1 OR name=?2 OR device=?1 OR device=?2 "
        "ORDER BY CASE WHEN name=?1 THEN 0 WHEN name=?2 THEN 1 "
        "WHEN device=?1 THEN 2 ELSE 3 END, updated_at DESC LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK)
        return JMX_CARRIER_ANY;

    sqlite3_bind_text(stmt, 1, name ? name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ifname ? ifname : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *stored = (const char *)sqlite3_column_text(stmt, 0);

        carrier = carrier_from_string(stored);
        if (carrier > JMX_CARRIER_OTHER)
            carrier = JMX_CARRIER_ANY;
    }
    sqlite3_finalize(stmt);
    return carrier;
}

static uint8_t route_detect_wan_carrier(const char *name, const char *ifname)
{
    jmx_isp_entry_t isp;
    uint8_t carrier = route_stored_wan_carrier(name, ifname);

    if (carrier != JMX_CARRIER_ANY)
        return carrier;

    memset(&isp, 0, sizeof(isp));
    if (name && name[0] && jmx_isp_get(name, &isp) == 0 &&
        isp.confidence >= 50 && isp.isp > JMX_CARRIER_ANY &&
        isp.isp <= JMX_CARRIER_OTHER) {
        (void)jmx_db_upsert_interface(name, "wan", ifname, NULL,
                                      isp.carrier_key);
        return (uint8_t)isp.isp;
    }

    memset(&isp, 0, sizeof(isp));
    if (ifname && ifname[0] && (!name || strcmp(name, ifname)) &&
        jmx_isp_get(ifname, &isp) == 0 && isp.confidence >= 50 &&
        isp.isp > JMX_CARRIER_ANY && isp.isp <= JMX_CARRIER_OTHER) {
        if (name && name[0])
            (void)jmx_db_upsert_interface(name, "wan", ifname, NULL,
                                          isp.carrier_key);
        return (uint8_t)isp.isp;
    }

    return JMX_CARRIER_ANY;
}

static int route_config_has_auto_carrier_rules(struct json_object *config)
{
    struct json_object *rules = NULL;
    int i;

    if (!config || !json_object_object_get_ex(config, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array))
        return 0;
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *wan_ids = NULL;

        /* Disabled rules do not participate in runtime carrier mapping.  Do
         * not let their unresolved auto-selection state force a full route
         * graph rebuild on every health tick. */
        if (!json_get_u32(rule, "enabled", 0))
            continue;
        if (carrier_from_string(json_get_str(rule, "carrier", "any")) ==
            JMX_CARRIER_ANY)
            continue;
        if (!json_object_object_get_ex(rule, "wan_ids", &wan_ids) ||
            (json_object_is_type(wan_ids, json_type_array) &&
             json_object_array_length(wan_ids) == 0))
            return 1;
    }
    return 0;
}

static int route_auto_carrier_mapping_changed(struct json_object *config)
{
    struct json_object *wans = NULL;
    int i;

    if (!route_config_has_auto_carrier_rules(config) ||
        !json_object_object_get_ex(config, "wans", &wans) ||
        !json_object_is_type(wans, json_type_array))
        return 0;

    for (i = 0; i < json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);
        uint8_t id = (uint8_t)json_get_u32(wan, "id", 0);
        uint8_t stored;

        if (!id || id > JMX_ROUTE_MAX_WAN_IFACES)
            continue;
        stored = route_stored_wan_carrier(json_get_str(wan, "name", ""),
                                          json_get_str(wan, "ifname", ""));
        if (stored != g_route_auto_carriers[id])
            return 1;
    }
    return 0;
}

static void route_resolve_auto_carrier_wans(struct jmx_route_rule_wire *rule,
                                            const struct route_sync_wan_map *map,
                                            int map_count)
{
    int i;

    if (!rule || !map || rule->wan_count > 0 ||
        rule->carrier_id == JMX_CARRIER_ANY)
        return;

    for (i = 0; i < map_count && rule->wan_count < JMX_ROUTE_MAX_WAN_IFACES; i++) {
        if (map[i].carrier_id == rule->carrier_id)
            rule->wan_ids[rule->wan_count++] = map[i].id;
    }
}

static uint8_t route_sync_wan_id_by_name(const struct route_sync_wan_map *map, int map_count,
                                         const char *name)
{
    int i;

    if (!map || !name || !name[0])
        return 0;
    for (i = 0; i < map_count; i++) {
        char id_buf[16];

        if (!strcmp(map[i].name, name) || !strcmp(map[i].ifname, name))
            return map[i].id;
        snprintf(id_buf, sizeof(id_buf), "%u", map[i].id);
        if (!strcmp(id_buf, name))
            return map[i].id;
        snprintf(id_buf, sizeof(id_buf), "wan%u", map[i].id);
        if (!strcmp(id_buf, name))
            return map[i].id;
    }
    return 0;
}

static uint8_t route_sync_wan_id_by_table(const struct route_sync_wan_map *map, int map_count,
                                          uint32_t table_id)
{
    int i;

    if (!map || !table_id)
        return 0;
    for (i = 0; i < map_count; i++) {
        if (map[i].table_id == table_id)
            return map[i].id;
    }
    return 0;
}

static uint32_t route_ipv4_from_string(const char *s, uint32_t def)
{
    struct in_addr a;

    if (!s || !s[0])
        return def;
    if (inet_pton(AF_INET, s, &a) != 1)
        return def;
    return a.s_addr;
}

static uint8_t route_wan_id_from_name(const char *name, uint8_t used[256], uint8_t fallback)
{
    unsigned long n = 0;
    const char *p;
    uint8_t id;

    if (name && !strncmp(name, "wan", 3)) {
        p = name + 3;
        if (!*p)
            n = 1;
        else if (isdigit((unsigned char)*p))
            n = strtoul(p, NULL, 10);
    }
    if (n > 0 && n <= JMX_ROUTE_MAX_WAN_IFACES && !used[n]) {
        used[n] = 1;
        return (uint8_t)n;
    }
    for (id = fallback; id <= JMX_ROUTE_MAX_WAN_IFACES; id++) {
        if (!used[id]) {
            used[id] = 1;
            return id;
        }
    }
    for (id = 1; id <= JMX_ROUTE_MAX_WAN_IFACES; id++) {
        if (!used[id]) {
            used[id] = 1;
            return id;
        }
    }
    return 0;
}

static int route_sync_network_wans(int fd, int *errors,
                                   struct route_sync_wan_map *map,
                                   size_t map_len, int *map_count)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    uint8_t used[256] = {0};
    uint8_t next_id = 1;
    int count = 0;

    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "network", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return 0;
    }

    /* WANs already registered from config.db keep their id; mark them used so a
     * UCI-only WAN cannot be handed an id that is taken, and so we can skip it
     * below instead of re-registering it. */
    if (map && map_count) {
        int m;

        for (m = 0; m < *map_count && (size_t)m < map_len; m++)
            if (map[m].id)
                used[map[m].id] = 1;
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *name, *proto, *ifname, *gw_cfg;
        char l3_ifname[JMX_ROUTE_HEALTH_IFNAME_LEN] = "";
        char gateway_buf[64] = "";
        const char *route_ifname;
        uint32_t gateway;
        uint8_t id;
        uint32_t fwmark, table_id, weight;
        int online = 0;

        if (!s || strcmp(s->type, "interface") != 0)
            continue;
        name = s->e.name;
        proto = uci_opt(s, "proto");
        if (!route_network_iface_is_wan(name, proto) || route_section_disabled(s))
            continue;
        /* Already registered from config.db (matched by section name): the
         * explicit ledger wins, do not register a second time. */
        if (route_sync_wan_registered_by_name(map, map_count ? *map_count : 0, name))
            continue;
        id = route_wan_id_from_name(name, used, next_id);
        if (!id)
            continue;
        next_id = id + 1;
        ifname = route_wan_ifname_option(s);
        route_ifstatus_runtime(name, l3_ifname, sizeof(l3_ifname),
                               gateway_buf, sizeof(gateway_buf), &online);
        if (!l3_ifname[0])
            route_health_probe_ifname(s, l3_ifname, sizeof(l3_ifname));
        route_ifname = l3_ifname[0] ? l3_ifname : ifname;
        gw_cfg = gateway_buf[0] ? gateway_buf : uci_opt(s, "gateway");
        gateway = route_ipv4_from_string(gw_cfg, 0);
        fwmark = 0x10000 + id;
        table_id = 100 + id;
        weight = parse_weight_opt(s, 1);
        if (!weight) {
            if (errors)
                (*errors)++;
            continue;
        }

        if (jmx_route_nl_wan_register(fd, id, name, fwmark, table_id,
                                      gateway, weight) == 0) {
            const char *system_gateway = gw_cfg;

            route_sync_wan_map_add(map, map_len, map_count, id, name,
					   route_ifname, fwmark, table_id);
            route_sync_wan_map_set_carrier(
                map, *map_count, id,
                route_detect_wan_carrier(name, route_ifname));
            if ((proto && (!strcmp(proto, "pppoe") || !strcmp(proto, "pptp") ||
                           !strcmp(proto, "l2tp"))) ||
                (route_ifname && !strncmp(route_ifname, "ppp", 3)))
                system_gateway = NULL;
            if (jmx_route_nl_wan_health(fd, id, online ? 1 : 0) != 0 && errors)
                (*errors)++;
            if (online) {
                if (jmx_route_apply_system_route(route_ifname, fwmark, table_id,
                                                 system_gateway) != 0 && errors)
                    (*errors)++;
            } else {
                jmx_route_cleanup_system_route(table_id);
            }
            count++;
            LOG_WARN("jmx_route: fallback registered network WAN id=%u name=%s ifname=%s gateway=%s health=%d",
                     id, name ? name : "", route_ifname ? route_ifname : "",
                     gw_cfg ? gw_cfg : "", online ? 1 : 0);
        } else if (errors) {
            (*errors)++;
        }
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return count;
}

static struct route_health_state *route_health_state_get(uint8_t id)
{
    int free_slot = -1;
    int i;

    if (!id)
        return NULL;
    for (i = 0; i < JMX_ROUTE_HEALTH_MAX_STATES; i++) {
        if (g_route_health[i].known && g_route_health[i].id == id)
            return &g_route_health[i];
        if (!g_route_health[i].known && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        free_slot = 0;
    memset(&g_route_health[free_slot], 0, sizeof(g_route_health[free_slot]));
    g_route_health[free_slot].id = id;
    g_route_health[free_slot].known = 1;
    g_route_health[free_slot].healthy = 1;
    return &g_route_health[free_slot];
}

static const struct route_health_state *
route_health_state_find(uint8_t id, const char *name)
{
    int i;

    for (i = 0; i < JMX_ROUTE_HEALTH_MAX_STATES; i++) {
        const struct route_health_state *st = &g_route_health[i];

        if (!st->known)
            continue;
        if ((id && st->id == id) ||
            (name && name[0] && st->name[0] && !strcmp(st->name, name)))
            return st;
    }
    return NULL;
}

static void route_health_prune_states(void)
{
    int i;

    for (i = 0; i < JMX_ROUTE_HEALTH_MAX_STATES; i++) {
        if (g_route_health[i].known &&
            g_route_health[i].generation != g_route_health_generation)
            memset(&g_route_health[i], 0, sizeof(g_route_health[i]));
    }
}

static int route_health_token(const char *line, const char *key,
                              char *out, size_t out_len)
{
    const char *p = line;
    size_t key_len;
    size_t len = 0;

    if (!line || !key || !out || out_len == 0)
        return -1;
    key_len = strlen(key);
    while ((p = strstr(p, key)) != NULL) {
        if ((p == line || isspace((unsigned char)p[-1])) && p[key_len] == '=')
            break;
        p += key_len;
    }
    if (!p)
        return -1;
    p += key_len + 1;
    while (p[len] && !isspace((unsigned char)p[len]))
        len++;
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static int route_health_snapshot_load(struct route_health_snapshot_set *set)
{
    FILE *fp;
    char line[1024];
    time_t now = time(NULL);

    if (!set)
        return -1;
    memset(set, 0, sizeof(*set));
    fp = fopen(JMX_ROUTE_HEALTH_STATUS_PATH, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        struct route_health_snapshot *row;
        char value[160];

        if (route_health_token(line, "updated_at", value, sizeof(value)) == 0 &&
            strncmp(line, "wan=", 4) != 0) {
            set->updated_at = (time_t)atoll(value);
            continue;
        }
        if (strncmp(line, "wan=", 4) != 0 ||
            set->count >= JMX_ROUTE_MAX_WAN_IFACES)
            continue;
        row = &set->rows[set->count];
        memset(row, 0, sizeof(*row));
        row->updated_at = set->updated_at;
        row->latency_ms = -1;
        row->probe_loss_pct = -1;
        row->up_loss_pct = -1;
        row->down_loss_pct = -1;
#define ROUTE_HEALTH_TEXT(k, field) \
        do { if (route_health_token(line, k, value, sizeof(value)) == 0 && \
                 strcmp(value, "-")) JMX_STRBUF_COPY(row->field, value); } while (0)
#define ROUTE_HEALTH_INT(k, field) \
        do { if (route_health_token(line, k, value, sizeof(value)) == 0) row->field = atoi(value); } while (0)
        ROUTE_HEALTH_TEXT("wan", name);
        ROUTE_HEALTH_TEXT("device", device);
        ROUTE_HEALTH_TEXT("target", target);
        ROUTE_HEALTH_TEXT("reason", reason);
        ROUTE_HEALTH_TEXT("health_mode", health_mode);
        ROUTE_HEALTH_INT("checked", checked);
        ROUTE_HEALTH_INT("online", online);
        ROUTE_HEALTH_INT("latency", latency_ms);
        if (route_health_token(line, "probe_loss", value, sizeof(value)) == 0)
            row->probe_loss_pct = atoi(value);
        else
            ROUTE_HEALTH_INT("loss", probe_loss_pct);
        ROUTE_HEALTH_INT("jitter_ms", jitter_ms);
        ROUTE_HEALTH_INT("jitter_samples", jitter_samples);
        ROUTE_HEALTH_INT("jitter_over_80_pct", jitter_over_80_pct);
        ROUTE_HEALTH_INT("counters_valid", counters_valid);
        if (route_health_token(line, "up_loss_pct", value, sizeof(value)) == 0 ||
            route_health_token(line, "up_loss", value, sizeof(value)) == 0)
            row->up_loss_pct = atof(value);
        if (route_health_token(line, "down_loss_pct", value, sizeof(value)) == 0 ||
            route_health_token(line, "down_loss", value, sizeof(value)) == 0)
            row->down_loss_pct = atof(value);
#undef ROUTE_HEALTH_INT
#undef ROUTE_HEALTH_TEXT
        if (row->name[0])
            set->count++;
    }
    fclose(fp);
    if (set->updated_at <= 0 || now < set->updated_at ||
        now - set->updated_at > JMX_ROUTE_HEALTH_STALE_SEC)
        return -1;
    return set->count > 0 ? 0 : -1;
}

static const struct route_health_snapshot *
route_health_snapshot_find(const struct route_health_snapshot_set *set,
                           const char *name, const char *ifname)
{
    size_t i;

    if (!set)
        return NULL;
    for (i = 0; i < set->count; i++)
        if ((name && name[0] && !strcmp(set->rows[i].name, name)) ||
            (ifname && ifname[0] && !strcmp(set->rows[i].device, ifname)))
            return &set->rows[i];
    return NULL;
}

static uint8_t route_health_level_for(const struct route_health_snapshot *s)
{
    double real_loss = -1;

    if (!s)
        return 0;
    if (!s->online || !strcmp(s->reason, "link_down") ||
        !strcmp(s->reason, "no_device") ||
        !strcmp(s->reason, "all_probes_failed"))
        return 3;
    if (s->counters_valid) {
        if (s->up_loss_pct >= 0)
            real_loss = s->up_loss_pct;
        if (s->down_loss_pct > real_loss)
            real_loss = s->down_loss_pct;
    }
    /*
     * probe_loss_pct is a three-packet reachability sample (0/33/67/100),
     * not the WAN's forwarding loss.  Treating one or two missed replies as
     * 33%/67% line loss escalates a healthy WAN to L1/L2 and can trigger
     * selective conntrack rebinds.  Reachability still has a hard-down path
     * above when every configured probe fails; quality levels below that use
     * only independent forwarding counters, RTT and jitter.
     */
    if (real_loss >= 40.0 || s->latency_ms >= 800)
        return 3;
    if (real_loss > 15.0 || s->jitter_over_80_pct > 30 ||
        s->latency_ms >= 400)
        return 2;
    /* A disagreement between independent probes is useful telemetry, but it
     * is not by itself evidence that forwarding quality degraded. One target
     * may reject HTTP or a PPP peer may not answer ICMP while real traffic,
     * RTT, jitter and the other probes remain healthy. Penalize only measured
     * quality thresholds; keep partial_probe_fail visible in status. */
    if (real_loss > 2.0 || s->latency_ms >= 180 ||
        s->jitter_over_80_pct > 0)
        return 1;
    return 0;
}

static uint8_t route_health_weight_for(uint8_t level)
{
    static const uint8_t weights[] = { 100, 70, 25, 1 };

    return level < sizeof(weights) ? weights[level] : 1;
}

static void route_health_snapshot_copy(struct route_health_state *st,
                                       const struct route_health_snapshot *s)
{
    st->checked = s->checked;
    st->online = s->online;
    st->latency_ms = s->latency_ms;
    st->probe_loss_pct = s->probe_loss_pct;
    st->jitter_ms = s->jitter_ms;
    st->jitter_samples = s->jitter_samples;
    st->jitter_over_80_pct = s->jitter_over_80_pct;
    st->counters_valid = s->counters_valid;
    st->up_loss_pct = s->up_loss_pct;
    st->down_loss_pct = s->down_loss_pct;
    snprintf(st->target, sizeof(st->target), "%s", s->target);
    snprintf(st->reason, sizeof(st->reason), "%s", s->reason);
    snprintf(st->health_mode, sizeof(st->health_mode), "%s", s->health_mode);
}

static int route_health_event_emit(const struct route_health_state *st,
                                   const char *level, const char *event,
                                   const char *title, const char *state)
{
    struct json_object *o;
    struct json_object *detail;
    struct json_object *resp;
    char id[96];
    char dedupe[96];

    if (!st || !event)
        return -1;
    snprintf(id, sizeof(id), "route-wan-%u-%u-%lld", st->id,
             st->transition_count, (long long)st->last_change);
    snprintf(dedupe, sizeof(dedupe), "wan_quality:%s",
             st->name[0] ? st->name : "unknown");
    o = json_object_new_object();
    detail = json_object_new_object();
    if (!o || !detail) {
        if (o) json_object_put(o);
        if (detail) json_object_put(detail);
        return -1;
    }
    json_object_object_add(detail, "wan_id", json_object_new_string(st->name));
    json_object_object_add(detail, "wan_numeric_id", json_object_new_int(st->id));
    json_object_object_add(detail, "ifname", json_object_new_string(st->ifname));
    json_object_object_add(detail, "quality_level", json_object_new_int(st->quality_level));
    json_object_object_add(detail, "raw_level", json_object_new_int(st->raw_level));
    json_object_object_add(detail, "penalty_peak_level",
                           json_object_new_int(st->penalty_peak_level));
    json_object_object_add(detail, "adaptive_weight", json_object_new_int(st->adaptive_weight));
    json_object_object_add(detail, "reason", json_object_new_string(st->reason));
    json_object_object_add(detail, "latency_ms", json_object_new_int(st->latency_ms));
    json_object_object_add(detail, "probe_loss_pct", json_object_new_int(st->probe_loss_pct));
    json_object_object_add(detail, "up_loss_pct", st->counters_valid ?
                           json_object_new_double(st->up_loss_pct) : json_object_new_null());
    json_object_object_add(detail, "down_loss_pct", st->counters_valid ?
                           json_object_new_double(st->down_loss_pct) : json_object_new_null());
    json_object_object_add(detail, "jitter_ms", json_object_new_int(st->jitter_ms));
    json_object_object_add(detail, "jitter_over_80_pct",
                           json_object_new_int(st->jitter_over_80_pct));
    json_object_object_add(detail, "recovery_observing",
                           json_object_new_boolean(st->recovery_observing));
    json_object_object_add(detail, "recovery_target_level",
                           json_object_new_int(st->recovery_target_level));
    json_object_object_add(detail, "recovery_since",
                           json_object_new_int64((int64_t)st->recovery_since));
    json_object_object_add(detail, "rebind_mode", json_object_new_int(st->last_rebind_mode));

    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "type", json_object_new_string("system"));
    json_object_object_add(o, "level", json_object_new_string(level ? level : "info"));
    json_object_object_add(o, "category", json_object_new_string("network.wan"));
    json_object_object_add(o, "module", json_object_new_string("dreamingwrt-routed"));
    json_object_object_add(o, "source", json_object_new_string("routed.health"));
    json_object_object_add(o, "iface", json_object_new_string(st->ifname));
    json_object_object_add(o, "wan_id", json_object_new_string(st->name));
    json_object_object_add(o, "title", json_object_new_string(title ? title : event));
    json_object_object_add(o, "event", json_object_new_string(event));
    json_object_object_add(o, "detail_json", detail);
    json_object_object_add(o, "dedupe_key", json_object_new_string(dedupe));
    json_object_object_add(o, "state", json_object_new_string(state ? state : ""));
    json_object_object_add(o, "target", json_object_new_string(st->name));
    json_object_object_add(o, "ts", json_object_new_int64((int64_t)st->last_change));
    resp = jmx_log_center_event_add(o);
    if (resp)
        json_object_put(resp);
    json_object_put(o);
    return 0;
}

static void route_health_emit_transition(const struct route_health_state *st)
{
    if (st->recovery_observing) {
        route_health_event_emit(st, "notice", "wan.penalty.recovering",
                                "WAN quality recovery observation started", "observing");
    } else if (st->quality_level == 0) {
        if (st->penalty_peak_level >= 2)
            route_health_event_emit(st, "notice",
                                    "wan.quality.critical_recovered",
                                    "WAN critical quality penalty recovered",
                                    "completed");
        route_health_event_emit(st, "notice", "wan.quality.recovered",
                                "WAN quality recovered", "completed");
    } else if (st->quality_level == 1) {
        route_health_event_emit(st, "warning", "wan.quality.degraded",
                                "WAN quality degraded", "active");
    } else {
        route_health_event_emit(st, st->quality_level >= 3 ? "critical" : "warning",
                                "wan.quality.critical",
                                st->quality_level >= 3 ?
                                    "WAN removed from route group" :
                                    "WAN quality critically degraded",
                                "active");
    }
}

static int route_health_apply_level(int fd, struct route_health_state *st,
                                    uint8_t level, int emit)
{
    uint8_t old_level = st->quality_level;
    uint8_t weight = route_health_weight_for(level);
    uint8_t rebind = 0;

    if (jmx_route_nl_wan_adaptive_weight(fd, st->id, weight) != 0)
        return -1;
    if (jmx_route_nl_wan_health(fd, st->id, level < 3 ? 1 : 0) != 0)
        return -1;
    if (level > old_level) {
        if (level > st->penalty_peak_level)
            st->penalty_peak_level = level;
        if (level >= 3)
            rebind = JMX_ROUTE_REBIND_ALL;
        else if (level >= 2)
            rebind = JMX_ROUTE_REBIND_SELECTIVE;
        if (rebind) {
            if (jmx_route_nl_wan_rebind(fd, st->id, rebind) != 0)
                return -1;
            st->last_rebind_mode = rebind;
        }
    }
    st->quality_level = level;
    st->adaptive_weight = weight;
    st->healthy = level < 3;
    st->last_change = st->last_probe;
    st->transition_count++;
    if (emit)
        route_health_emit_transition(st);
    if (level == 0)
        st->penalty_peak_level = 0;
    LOG_WARN("jmx_route: WAN %s quality L%u->L%u weight=%u reason=%s",
             st->name, old_level, level, weight, st->reason);
    return 0;
}

static int route_health_tick_one(int fd, uint8_t id, uint8_t enabled,
                                 uint8_t failover, uint8_t failback,
                                 uint8_t config_health, const char *name,
                                 const char *ifname,
                                 const struct route_health_snapshot *snap)
{
    struct route_health_state *st;
    uint8_t raw;
    int hard_down;

    (void)config_health;
    if (!id || !enabled || !failover)
        return 0;
    st = route_health_state_get(id);
    if (!st)
        return -1;
    st->generation = g_route_health_generation;
    snprintf(st->name, sizeof(st->name), "%s", name && name[0] ? name : "wan");
    snprintf(st->ifname, sizeof(st->ifname), "%s", ifname && ifname[0] ? ifname : "");
    if (!snap || snap->updated_at <= st->last_probe)
        return 0;

    st->last_probe = snap->updated_at;
    route_health_snapshot_copy(st, snap);
    raw = route_health_level_for(snap);
    hard_down = !strcmp(snap->reason, "link_down") ||
                !strcmp(snap->reason, "no_device");
    if (raw == 3) {
        st->fail_count++;
        st->ok_count = 0;
        if (!hard_down && st->fail_count < 2)
            raw = 2;
    } else {
        st->fail_count = 0;
        st->ok_count++;
    }
    st->raw_level = raw;

    if (!st->initialized) {
        st->initialized = 1;
        st->last_change = st->last_probe;
        return route_health_apply_level(fd, st, raw, raw > 0);
    }

    if (raw > st->quality_level) {
        st->recovery_observing = 0;
        st->recovery_samples = 0;
        return route_health_apply_level(fd, st, raw, 1);
    }
    if (raw == st->quality_level) {
        st->recovery_observing = 0;
        st->recovery_samples = 0;
        return 0;
    }
    if (!failback && st->quality_level >= 3)
        return 0;

    if (!st->recovery_observing) {
        st->recovery_observing = 1;
        st->recovery_target_level = st->quality_level - 1;
        st->recovery_since = st->last_probe;
        st->recovery_samples = 1;
        st->transition_count++;
        route_health_emit_transition(st);
        return 0;
    }
    if (raw > st->recovery_target_level) {
        st->recovery_since = st->last_probe;
        st->recovery_samples = 0;
        return 0;
    }
    if (st->recovery_samples < UINT8_MAX)
        st->recovery_samples++;
    if (st->recovery_samples < JMX_ROUTE_HEALTH_RECOVERY_SAMPLES ||
        st->last_probe - st->recovery_since < JMX_ROUTE_HEALTH_RECOVERY_SEC)
        return 0;

    st->recovery_observing = 0;
    st->recovery_samples = 0;
    return route_health_apply_level(fd, st, st->recovery_target_level, 1);
}

static const char *route_app_name(int appid)
{
    char *name;
    if (appid <= 0) return "";
    name = get_app_name_by_id(appid);
    return name ? name : "";
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

struct route_runtime_identity {
    char runtime_id[160];
    char source[64];
    char reason[96];
    int stable;
};

static uint64_t route_runtime_hash(const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    uint64_t hash = UINT64_C(1469598103934665603);

    while (*p) {
        hash ^= (uint64_t)*p++;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t route_runtime_hash_alt(const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    uint64_t hash = UINT64_C(5381);

    while (*p)
        hash = ((hash << 5) + hash) ^ (uint64_t)*p++;
    return hash;
}

static int route_runtime_semantic_key(struct json_object *rule,
                                      char *out, size_t out_len)
{
    unsigned wan_ids[JMX_ROUTE_MAX_WAN_IFACES];
    char wan_key[64] = "";
    char wan_input[128];
    char *save = NULL;
    char *token;
    size_t wan_count = 0;
    size_t i;
    int written;

    if (!rule || !out || out_len == 0)
        return -1;
    snprintf(wan_input, sizeof(wan_input), "%s",
             route_obj_str(rule, "wan_ids", ""));
    for (token = strtok_r(wan_input, ",", &save); token &&
         wan_count < JMX_ROUTE_MAX_WAN_IFACES;
         token = strtok_r(NULL, ",", &save)) {
        char *end = NULL;
        unsigned long value;

        while (*token == ' ' || *token == '\t')
            token++;
        errno = 0;
        value = strtoul(token, &end, 10);
        while (end && (*end == ' ' || *end == '\t'))
            end++;
        if (errno || end == token || (end && *end) || value > UINT8_MAX)
            return -1;
        wan_ids[wan_count++] = (unsigned)value;
    }
    if (token)
        return -1;
    for (i = 0; i < wan_count; i++) {
        size_t used = strlen(wan_key);
        int n = snprintf(wan_key + used, sizeof(wan_key) - used,
                         "%s%u", i ? "," : "", wan_ids[i]);

        if (n < 0 || (size_t)n >= sizeof(wan_key) - used)
            return -1;
    }
    written = snprintf(out, out_len,
        "en=%d|proto=%d|appid=%d|carrier=%d|src=%s|dst=%s|dport=%d|mode=%d|wans=%s",
        route_obj_int(rule, "enabled", 0),
        route_obj_int(rule, "proto", 0),
        route_obj_int(rule, "appid", 0),
        route_obj_int(rule, "carrier_id", 0),
        route_obj_str(rule, "src", ""),
        route_obj_str(rule, "dst", ""),
        route_obj_int(rule, "dst_port", 0),
        route_obj_int(rule, "sticky_mode", 0),
        wan_key);
    return written >= 0 && (size_t)written < out_len ? 0 : -1;
}

static int route_runtime_semantic_duplicates(struct json_object *rules,
                                             size_t current,
                                             const char *semantic_key)
{
    size_t i;
    int matches = 0;

    if (!rules || !json_object_is_type(rules, json_type_array) ||
        !semantic_key || !semantic_key[0])
        return 0;
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *candidate = json_object_array_get_idx(rules, i);
        char candidate_key[512];

        if (i == current)
            continue;
        if (route_runtime_semantic_key(candidate, candidate_key,
                                       sizeof(candidate_key)) == 0 &&
            !strcmp(candidate_key, semantic_key))
            matches++;
    }
    return matches;
}

static void route_runtime_identity_resolve(struct json_object *rules,
                                           size_t index,
                                           struct json_object *rule,
                                           struct route_runtime_identity *identity)
{
    char semantic_key[512];
    uint64_t semantic_hash;
    uint64_t semantic_hash_alt;

    if (!identity)
        return;
    memset(identity, 0, sizeof(*identity));
    snprintf(identity->source, sizeof(identity->source), "%s", "unavailable");
    snprintf(identity->reason, sizeof(identity->reason), "%s", "identity_unavailable");
    if (!rule || route_runtime_semantic_key(rule, semantic_key,
                                            sizeof(semantic_key)) != 0) {
        snprintf(identity->reason, sizeof(identity->reason), "%s",
                 "runtime_semantics_invalid");
        return;
    }
    if (route_runtime_semantic_duplicates(rules, index, semantic_key) > 0) {
        snprintf(identity->reason, sizeof(identity->reason), "%s",
                 "duplicate_runtime_semantics");
        return;
    }
    semantic_hash = route_runtime_hash(semantic_key);
    semantic_hash_alt = route_runtime_hash_alt(semantic_key);
    snprintf(identity->runtime_id, sizeof(identity->runtime_id),
             "runtime-route:%016llx%016llx",
             (unsigned long long)semantic_hash,
             (unsigned long long)semantic_hash_alt);
    snprintf(identity->source, sizeof(identity->source), "%s",
             "runtime_semantic_fingerprint_v1");
    snprintf(identity->reason, sizeof(identity->reason), "%s", "ok");
    identity->stable = 1;
}

static int route_state_db_init(sqlite3 **out_db)
{
    sqlite3 *db = NULL;
    char *err = NULL;
    int rc;

    if (out_db)
        *out_db = NULL;
    if (mkdir("/var/lib", 0755) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/var/lib/dreamingwrt", 0755) != 0 && errno != EEXIST)
        return -1;
    rc = sqlite3_open_v2(JMX_ROUTE_STATE_DB_PATH, &db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 500);
    rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS route_rule_counter ("
        "rule_id TEXT PRIMARY KEY,"
        "prio INTEGER NOT NULL,"
        "name TEXT DEFAULT '',"
        "action TEXT NOT NULL,"
        "target TEXT DEFAULT '',"
        "hit_count INTEGER DEFAULT 0,"
        "active_flows INTEGER DEFAULT 0,"
        "up_rate INTEGER DEFAULT 0,"
        "down_rate INTEGER DEFAULT 0,"
        "last_hit INTEGER DEFAULT 0,"
        "updated_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS route_rule_counter_v2 ("
        "runtime_id TEXT PRIMARY KEY,"
        "configured_id TEXT DEFAULT '',"
        "configured_type TEXT DEFAULT '',"
        "kernel_prio INTEGER NOT NULL,"
        "name TEXT DEFAULT '',"
        "action TEXT NOT NULL,"
        "target TEXT DEFAULT '',"
        "hit_count INTEGER NOT NULL DEFAULT 0,"
        "byte_count INTEGER,"
        "byte_counter_supported INTEGER NOT NULL DEFAULT 0,"
        "last_hit INTEGER DEFAULT 0,"
        "observed_at INTEGER NOT NULL,"
        "reset_generation INTEGER NOT NULL DEFAULT 0,"
        "counter_source TEXT NOT NULL DEFAULT 'jmx_route_kernel',"
        "identity_source TEXT NOT NULL,"
        "updated_at INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_route_rule_counter_v2_configured "
        "ON route_rule_counter_v2(configured_id, updated_at);"
        "CREATE TABLE IF NOT EXISTS route_decision_sample ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ts INTEGER NOT NULL,"
        "client_id TEXT DEFAULT '',"
        "client_name TEXT DEFAULT '',"
        "ip TEXT DEFAULT '',"
        "app TEXT DEFAULT '',"
        "destination TEXT DEFAULT '',"
        "rule_id TEXT DEFAULT '',"
        "rule_name TEXT DEFAULT '',"
        "action TEXT DEFAULT '',"
        "path TEXT DEFAULT '',"
        "wan TEXT DEFAULT '',"
        "reason TEXT DEFAULT '',"
        "up_bytes INTEGER DEFAULT 0,"
        "down_bytes INTEGER DEFAULT 0,"
        "latency INTEGER DEFAULT 0"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_route_decision_ts ON route_decision_sample(ts);"
        "CREATE INDEX IF NOT EXISTS idx_route_decision_client ON route_decision_sample(client_id, ts);"
        "CREATE INDEX IF NOT EXISTS idx_route_decision_rule ON route_decision_sample(rule_id, ts);",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN("jmx_route: state db init failed: %s", err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }
    if (out_db)
        *out_db = db;
    else
        sqlite3_close(db);
    return 0;
}

static int route_rule_counter_upsert(sqlite3 *db, struct json_object *rule, time_t now)
{
    sqlite3_stmt *st = NULL;
    char rule_id[64];
    const char *runtime_id;
    const char *configured_id;
    const char *configured_type;
    const char *identity_source;
    const char *name;
    const char *action;
    const char *target;
    int prio;
    int64_t hits;
    int64_t last_hit;
    int64_t previous_hits = 0;
    int reset_generation = 0;
    int reset_detected = 0;
    int rc = -1;

    if (!db || !rule)
        return -1;
    prio = route_obj_int(rule, "prio", 0);
    if (prio <= 0)
        return -1;
    snprintf(rule_id, sizeof(rule_id), "rule-%d", prio);
    name = route_obj_str(rule, "name", rule_id);
    action = route_obj_str(rule, "action", "route");
    target = route_obj_str(rule, "target", route_obj_str(rule, "wan_ids", ""));
    hits = route_obj_i64(rule, "hit_count", 0);
    last_hit = route_obj_i64(rule, "last_hit", 0);
    if (last_hit <= 0) {
        int64_t seconds_ago = route_obj_i64(rule, "last_hit_seconds_ago", -1);

        if (hits > 0 && seconds_ago >= 0)
            last_hit = (int64_t)now - seconds_ago;
    }

    st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO route_rule_counter("
        "rule_id,prio,name,action,target,hit_count,active_flows,up_rate,down_rate,last_hit,updated_at"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) "
        "ON CONFLICT(rule_id) DO UPDATE SET "
        "prio=excluded.prio,"
        "name=excluded.name,"
        "action=excluded.action,"
        "target=excluded.target,"
        "hit_count=excluded.hit_count,"
        "active_flows=excluded.active_flows,"
        "up_rate=excluded.up_rate,"
        "down_rate=excluded.down_rate,"
        "last_hit=excluded.last_hit,"
        "updated_at=excluded.updated_at",
        -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, prio);
    sqlite3_bind_text(st, 3, name ? name : rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, action ? action : "route", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, target ? target : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, hits);
    sqlite3_bind_int64(st, 7, route_obj_i64(rule, "active_flows", 0));
    sqlite3_bind_int64(st, 8, route_obj_i64(rule, "up_rate", 0));
    sqlite3_bind_int64(st, 9, route_obj_i64(rule, "down_rate", 0));
    sqlite3_bind_int64(st, 10, last_hit);
    sqlite3_bind_int64(st, 11, (int64_t)now);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    if (rc != 0)
        return rc;

    runtime_id = route_obj_str(rule, "runtime_id", NULL);
    configured_id = route_obj_str(rule, "configured_id", "");
    configured_type = route_obj_str(rule, "configured_type", "");
    identity_source = route_obj_str(rule, "runtime_identity_source", "unavailable");
    if (!runtime_id || !runtime_id[0] ||
        !route_obj_int(rule, "runtime_identity_stable", 0))
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT hit_count,reset_generation FROM route_rule_counter_v2 "
        "WHERE runtime_id=?1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, runtime_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            previous_hits = sqlite3_column_int64(st, 0);
            reset_generation = sqlite3_column_int(st, 1);
            if (hits < previous_hits) {
                reset_generation++;
                reset_detected = 1;
            }
        }
        sqlite3_finalize(st);
        st = NULL;
    } else {
        return -1;
    }
    if (sqlite3_prepare_v2(db,
        "INSERT INTO route_rule_counter_v2("
        "runtime_id,configured_id,configured_type,kernel_prio,name,action,target,hit_count,byte_count,"
        "byte_counter_supported,last_hit,observed_at,reset_generation,counter_source,"
        "identity_source,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,0,?9,?10,?11,'jmx_route_kernel',?12,?13) "
        "ON CONFLICT(runtime_id) DO UPDATE SET "
        "configured_id=excluded.configured_id,configured_type=excluded.configured_type,"
        "kernel_prio=excluded.kernel_prio,"
        "name=excluded.name,action=excluded.action,target=excluded.target,"
        "hit_count=excluded.hit_count,byte_count=NULL,byte_counter_supported=0,"
        "last_hit=excluded.last_hit,observed_at=excluded.observed_at,"
        "reset_generation=excluded.reset_generation,counter_source=excluded.counter_source,"
        "identity_source=excluded.identity_source,updated_at=excluded.updated_at",
        -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, runtime_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, configured_id ? configured_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, configured_type ? configured_type : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, prio);
    sqlite3_bind_text(st, 5, name ? name : rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, action ? action : "route", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, target ? target : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, hits);
    sqlite3_bind_int64(st, 9, last_hit);
    sqlite3_bind_int64(st, 10, (int64_t)now);
    sqlite3_bind_int(st, 11, reset_generation);
    sqlite3_bind_text(st, 12, identity_source ? identity_source : "unavailable",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 13, (int64_t)now);
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    if (rc != 0)
        return rc;
    json_object_object_add(rule, "counter_reset_generation",
                           json_object_new_int(reset_generation));
    json_object_object_add(rule, "counter_reset_detected",
                           json_object_new_boolean(reset_detected));
    json_object_object_add(rule, "observed_at",
                           json_object_new_int64((int64_t)now));
    return rc;
}

static int route_state_persist_rule_counters(struct json_object *data)
{
    sqlite3 *db = NULL;
    struct json_object *rules = NULL;
    time_t now = time(NULL);
    int persisted = 0;
    size_t i;
    static time_t g_route_counter_persist_last = 0;
    static int g_route_counter_persist_last_ok = 0;
    static int g_route_counter_persist_last_count = 0;

#define ROUTE_COUNTER_STATE_CLEAR() do { \
    for (i = 0; i < json_object_array_length(rules); i++) { \
        struct json_object *state_rule = json_object_array_get_idx(rules, i); \
        json_object_object_del(state_rule, "counter_reset_generation"); \
        json_object_object_del(state_rule, "counter_reset_detected"); \
    } \
} while (0)

    if (!data || !json_object_object_get_ex(data, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array))
        return 0;
    if (g_route_counter_persist_last &&
        now - g_route_counter_persist_last < 15) {
        json_object_object_add(data, "route_rule_counter_persisted",
            json_object_new_int(g_route_counter_persist_last_ok ?
                                g_route_counter_persist_last_count : 0));
        json_object_object_add(data, "route_rule_counter_persist_skipped",
                               json_object_new_boolean(1));
        json_object_object_add(data, "route_rule_counter_persist_reason",
                               json_object_new_string("throttled_15s"));
        json_object_object_add(data, "route_rule_counter_db",
                               json_object_new_string(JMX_ROUTE_STATE_DB_PATH));
        return g_route_counter_persist_last_ok ?
               g_route_counter_persist_last_count : -1;
    }
    if (route_state_db_init(&db) != 0 || !db)
        return -1;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        g_route_counter_persist_last = now;
        g_route_counter_persist_last_ok = 0;
        return -1;
    }
    for (i = 0; i < json_object_array_length(rules); i++) {
        if (route_rule_counter_upsert(db, json_object_array_get_idx(rules, i), now) != 0) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            sqlite3_close(db);
            ROUTE_COUNTER_STATE_CLEAR();
            g_route_counter_persist_last = now;
            g_route_counter_persist_last_ok = 0;
            json_object_object_add(data, "route_rule_counter_persisted",
                                   json_object_new_int(0));
            json_object_object_add(data, "route_rule_counter_persist_error",
                                   json_object_new_string("counter_state_transaction_failed"));
            return -1;
        }
        persisted++;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        ROUTE_COUNTER_STATE_CLEAR();
        g_route_counter_persist_last = now;
        g_route_counter_persist_last_ok = 0;
        json_object_object_add(data, "route_rule_counter_persisted",
                               json_object_new_int(0));
        json_object_object_add(data, "route_rule_counter_persist_error",
                               json_object_new_string("counter_state_commit_failed"));
        return -1;
    }
    sqlite3_close(db);
    json_object_object_add(data, "route_rule_counter_persisted", json_object_new_int(persisted));
    json_object_object_add(data, "route_rule_counter_db", json_object_new_string(JMX_ROUTE_STATE_DB_PATH));
    g_route_counter_persist_last = now;
    g_route_counter_persist_last_ok = 1;
    g_route_counter_persist_last_count = persisted;
#undef ROUTE_COUNTER_STATE_CLEAR
    return persisted;
}

/* Route status enrichment is polled by the UI and must never block the uloop
 * thread for the main DB's 5s busy timeout while webd/healthd hold a write
 * lock.  A dedicated read-only connection with a short timeout turns a
 * contended read into a degraded sample instead of a seconds-long stall. */
static sqlite3 *route_open_readonly_db(void)
{
    sqlite3 *db = NULL;

    if (sqlite3_open_v2(JMX_DB_PATH_DEFAULT, &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 100);
    return db;
}


static int route_read_wan_runtime(const char *name, char *device, size_t device_len,
                                  char *proto, size_t proto_len,
                                  char *carrier, size_t carrier_len,
                                  int64_t *state_ts, int *online,
                                  unsigned long long *rx_bytes,
                                  unsigned long long *tx_bytes,
                                  int64_t *rx_rate, int64_t *tx_rate,
                                  int *latency_ms, int *loss_pct)
{
    sqlite3 *db = route_open_readonly_db();
    sqlite3_stmt *st = NULL;
    int rc;

    if (device && device_len > 0)
        device[0] = '\0';
    if (proto && proto_len > 0)
        proto[0] = '\0';
    if (carrier && carrier_len > 0)
        carrier[0] = '\0';
    if (state_ts)
        *state_ts = 0;
    if (online)
        *online = 0;
    if (rx_bytes)
        *rx_bytes = 0;
    if (tx_bytes)
        *tx_bytes = 0;
    if (rx_rate)
        *rx_rate = 0;
    if (tx_rate)
        *tx_rate = 0;
    if (latency_ms)
        *latency_ms = -1;
    if (loss_pct)
        *loss_pct = -1;
    if (!db || !name || !name[0]) {
        if (db)
            sqlite3_close(db);
        return -1;
    }

    rc = sqlite3_prepare_v2(db,
        "SELECT COALESCE(i.device,''),COALESCE(i.proto,''),COALESCE(i.carrier,''),"
        "s.ts,s.online,s.rx_bytes,s.tx_bytes,s.rx_rate,s.tx_rate,s.latency_ms,s.loss_pct "
        "FROM net_interfaces i LEFT JOIN net_interface_state s ON s.iface_id=i.iface_id "
        "WHERE i.name=?1 LIMIT 1",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const char *sdev = (const char *)sqlite3_column_text(st, 0);
        const char *sproto = (const char *)sqlite3_column_text(st, 1);
        const char *scarrier = (const char *)sqlite3_column_text(st, 2);

        if (device && device_len > 0 && sdev)
            snprintf(device, device_len, "%s", sdev);
        if (proto && proto_len > 0 && sproto)
            snprintf(proto, proto_len, "%s", sproto);
        if (carrier && carrier_len > 0 && scarrier)
            snprintf(carrier, carrier_len, "%s", scarrier);
        if (state_ts)
            *state_ts = sqlite3_column_int64(st, 3);
        if (online)
            *online = sqlite3_column_int(st, 4);
        if (rx_bytes)
            *rx_bytes = (unsigned long long)sqlite3_column_int64(st, 5);
        if (tx_bytes)
            *tx_bytes = (unsigned long long)sqlite3_column_int64(st, 6);
        if (rx_rate)
            *rx_rate = sqlite3_column_int64(st, 7);
        if (tx_rate)
            *tx_rate = sqlite3_column_int64(st, 8);
        if (latency_ms)
            *latency_ms = sqlite3_column_int(st, 9);
        if (loss_pct)
            *loss_pct = sqlite3_column_int(st, 10);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* The nexthop the kernel is actually using for a device.
 *
 * route_status reported only the gateway registered into the jmx_route module
 * and route_config_get only the configured value; acceptance found all three
 * disagreeing with `ip route` (A-013).  /proc/net/route answers this without a
 * subprocess, which matters because route_status is polled.
 *
 * Two passes, because a multi-WAN box does not keep every default route in the
 * main table.  First a real default route on that device.  Failing that, the
 * device's /32 on-link route, which on a PPPoE link is the peer address and is
 * exactly what a p2p nexthop means.  `via_peer` reports which pass matched so
 * the caller is not told a peer address is a default gateway.
 */
static int route_proc_device_nexthop(const char *device, char *out, size_t out_len,
                                     int *via_peer)
{
    FILE *fp;
    char line[256];
    char peer[64] = "";
    int found = 0;

    if (via_peer)
        *via_peer = 0;
    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (!device || !device[0])
        return -1;
    fp = fopen("/proc/net/route", "r");
    if (!fp)
        return -1;
    /* Skip the header row. */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        char iface[64] = "";
        unsigned long dest = 0, gw = 0, mask = 0;
        unsigned flags = 0;
        int refcnt = 0, use = 0, metric = 0;
        struct in_addr addr;

        if (sscanf(line, "%63s %lx %lx %x %d %d %d %lx",
                   iface, &dest, &gw, &flags, &refcnt, &use, &metric, &mask) != 8)
            continue;
        if (strcmp(iface, device))
            continue;
        /* /proc/net/route prints addresses as the in_addr in host byte order,
         * so the value assigns straight into s_addr. */
        if (dest == 0 && mask == 0 && gw != 0) {
            addr.s_addr = (in_addr_t)gw;
            if (inet_ntop(AF_INET, &addr, out, (socklen_t)out_len)) {
                found = 1;
                break;
            }
        }
        if (!peer[0] && mask == 0xFFFFFFFFUL && gw == 0 && dest != 0) {
            addr.s_addr = (in_addr_t)dest;
            if (!inet_ntop(AF_INET, &addr, peer, sizeof(peer)))
                peer[0] = '\0';
        }
    }
    fclose(fp);
    if (!found && peer[0]) {
        snprintf(out, out_len, "%s", peer);
        if (via_peer)
            *via_peer = 1;
        found = 1;
    }
    return found ? 0 : -1;
}

static void route_enrich_wan_runtime(struct json_object *w, const char *name)
{
    char device[64] = "";
    char proto[32] = "";
    char carrier[32] = "";
    int64_t state_ts = 0;
    int64_t rx_rate = 0, tx_rate = 0;
    unsigned long long rx_bytes = 0, tx_bytes = 0;
    int online = 0, latency = -1, loss = -1;
    int64_t now = (int64_t)time(NULL);
    int fresh = 0;

    if (!w || !name || !name[0])
        return;
    if (route_read_wan_runtime(name, device, sizeof(device), proto, sizeof(proto),
                               carrier, sizeof(carrier), &state_ts, &online,
                               &rx_bytes, &tx_bytes, &rx_rate, &tx_rate,
                               &latency, &loss) != 0) {
        if (!json_has_key(w, "rate_source"))
            json_object_object_add(w, "rate_source", json_object_new_string("route_proc_only"));
        if (!json_has_key(w, "sample_valid"))
            json_object_object_add(w, "sample_valid", json_object_new_boolean(0));
        if (!json_has_key(w, "degraded"))
            json_object_object_add(w, "degraded", json_object_new_boolean(1));
        if (!json_has_key(w, "zero_reason"))
            json_object_object_add(w, "zero_reason", json_object_new_string("runtime_sample_unavailable"));
        return;
    }

    fresh = state_ts > 0 && state_ts >= now - JMX_ROUTE_RUNTIME_STALE_SEC;
    json_object_object_add(w, "runtime_updated_at", json_object_new_int64(state_ts));
    json_object_object_add(w, "updated_at", json_object_new_int64(state_ts));
    json_object_object_add(w, "sample_age_ms",
                           json_object_new_int64(state_ts > 0 ? (now - state_ts) * 1000 : -1));
    json_object_object_add(w, "sample_valid", json_object_new_boolean(fresh));
    json_object_object_add(w, "degraded", json_object_new_boolean(!fresh));
    json_object_object_add(w, "rate_source", json_object_new_string("wan_state"));
    json_object_object_add(w, "zero_reason",
                           json_object_new_string((rx_rate > 0 || tx_rate > 0) ? "" :
                                                  (fresh ? "idle" : "no_sample")));
    json_object_object_add(w, "online", json_object_new_boolean(online != 0));
    if (device[0] && !json_has_key(w, "device"))
        json_object_object_add(w, "device", json_object_new_string(device));
    if (device[0])
        json_object_object_add(w, "runtime_device", json_object_new_string(device));
    if (proto[0])
        json_object_object_add(w, "proto", json_object_new_string(proto));
    if (carrier[0])
        json_object_object_add(w, "carrier", json_object_new_string(carrier));
    json_object_object_add(w, "down_rate", json_object_new_int64(fresh ? rx_rate : 0));
    json_object_object_add(w, "up_rate", json_object_new_int64(fresh ? tx_rate : 0));
    json_object_object_add(w, "rate_down", json_object_new_int64(fresh ? rx_rate : 0));
    json_object_object_add(w, "rate_up", json_object_new_int64(fresh ? tx_rate : 0));
    /* Cumulative bytes go through the shared publisher: the sampled counter is
     * the runtime device's, and for PPPoE that device is recreated on every
     * reconnect, so the raw value means "since last connect" (Acceptance
     * A-013). */
    jmx_db_add_wan_cumulative_bytes(w, name, (int64_t)rx_bytes, (int64_t)tx_bytes);
    /* Gateway provenance.  Keep whatever the module reported as
     * `module_gateway`, and expose the kernel's live nexthop separately so a
     * caller can tell a stale registration from the route actually in force. */
    {
        char live_gw[64] = "";
        const char *dev = device[0] ? device : NULL;
        const char *module_gw = route_obj_str(w, "gateway", "");
        int via_peer = 0;

        if (dev && route_proc_device_nexthop(dev, live_gw, sizeof(live_gw), &via_peer) == 0) {
            json_object_object_add(w, "module_gateway", json_object_new_string(module_gw));
            json_object_object_add(w, "kernel_gateway", json_object_new_string(live_gw));
            json_object_object_add(w, "gateway_source",
                                   json_object_new_string(via_peer ? "proc_net_route_p2p_peer"
                                                                  : "proc_net_route_default"));
            json_object_object_add(w, "gateway_matches_kernel",
                                   json_object_new_boolean(module_gw && !strcmp(module_gw, live_gw)));
            /* `gateway` is what callers already read, so make it the value that
             * is actually routing traffic. */
            json_object_object_add(w, "gateway", json_object_new_string(live_gw));
        } else {
            json_object_object_add(w, "gateway_source",
                                   json_object_new_string(dev ? "module_registration" : "unknown_device"));
            json_object_object_add(w, "gateway_matches_kernel", json_object_new_boolean(0));
        }
    }
    json_object_object_add(w, "latency", json_object_new_int(latency));
    json_object_object_add(w, "loss", json_object_new_int(loss));
    json_object_object_add(w, "health_measured", json_object_new_boolean(latency >= 0 || loss >= 0));
}

static void route_enrich_wan_health(struct json_object *w, uint8_t id,
                                    const char *name)
{
    const struct route_health_state *st = route_health_state_find(id, name);
    time_t now = time(NULL);
    int64_t remaining = 0;

    if (!w || !st || !st->initialized)
        return;
    if (st->recovery_observing) {
        remaining = JMX_ROUTE_HEALTH_RECOVERY_SEC - (now - st->recovery_since);
        if (remaining < 0)
            remaining = 0;
    }
    json_object_object_add(w, "quality_level", json_object_new_int(st->quality_level));
    json_object_object_add(w, "quality_raw_level", json_object_new_int(st->raw_level));
    json_object_object_add(w, "penalty_peak_level",
                           json_object_new_int(st->penalty_peak_level));
    json_object_object_add(w, "adaptive_weight_runtime",
                           json_object_new_int(st->adaptive_weight));
    json_object_object_add(w, "penalty_active",
                           json_object_new_boolean(st->quality_level > 0));
    json_object_object_add(w, "recovery_observing",
                           json_object_new_boolean(st->recovery_observing));
    json_object_object_add(w, "recovery_target_level",
                           st->recovery_observing ?
                               json_object_new_int(st->recovery_target_level) :
                               json_object_new_null());
    json_object_object_add(w, "recovery_remaining_sec",
                           json_object_new_int64(remaining));
    json_object_object_add(w, "health_sample_at",
                           json_object_new_int64((int64_t)st->last_probe));
    json_object_object_add(w, "health_transition_at",
                           json_object_new_int64((int64_t)st->last_change));
    json_object_object_add(w, "health_reason", json_object_new_string(st->reason));
    json_object_object_add(w, "health_mode", json_object_new_string(st->health_mode));
    json_object_object_add(w, "latency_ms", json_object_new_int(st->latency_ms));
    json_object_object_add(w, "probe_loss_pct",
                           st->probe_loss_pct >= 0 ?
                               json_object_new_int(st->probe_loss_pct) :
                               json_object_new_null());
    json_object_object_add(w, "up_loss_pct",
                           st->counters_valid && st->up_loss_pct >= 0 ?
                               json_object_new_double(st->up_loss_pct) :
                               json_object_new_null());
    json_object_object_add(w, "down_loss_pct",
                           st->counters_valid && st->down_loss_pct >= 0 ?
                               json_object_new_double(st->down_loss_pct) :
                               json_object_new_null());
    json_object_object_add(w, "jitter_ms", json_object_new_int(st->jitter_ms));
    json_object_object_add(w, "jitter_samples", json_object_new_int(st->jitter_samples));
    json_object_object_add(w, "jitter_over_80_pct",
                           json_object_new_int(st->jitter_over_80_pct));
    json_object_object_add(w, "last_rebind_mode",
                           json_object_new_int(st->last_rebind_mode));
}

static void route_enrich_wans(struct json_object *data)
{
    struct json_object *wans = NULL;
    size_t i;
    if (!json_object_object_get_ex(data, "wans", &wans) || !json_object_is_type(wans, json_type_array)) return;
    for (i = 0; i < json_object_array_length(wans); i++) {
        struct json_object *w = json_object_array_get_idx(wans, i);
        const char *name = route_obj_str(w, "name", "wan");
        int64_t down = route_obj_i64(w, "down_rate", route_obj_i64(w, "rate_down", 0));
        int64_t up = route_obj_i64(w, "up_rate", route_obj_i64(w, "rate_up", 0));
        int health = route_obj_int(w, "health", 1);
        uint8_t id = (uint8_t)route_obj_int(w, "id", 0);
        route_enrich_wan_runtime(w, name);
        route_enrich_wan_health(w, id, name);
        down = route_obj_i64(w, "down_rate", route_obj_i64(w, "rate_down", down));
        up = route_obj_i64(w, "up_rate", route_obj_i64(w, "rate_up", up));
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
        int64_t hits = route_obj_i64(r, "hit_count", 0);
        int64_t last_hit_s = route_obj_i64(r, "last_hit_seconds_ago", -1);
        struct route_runtime_identity identity;
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
        route_runtime_identity_resolve(rules, i, r, &identity);
        json_object_object_add(r, "kernel_priority", json_object_new_int(prio));
        json_object_object_add(r, "runtime_identity_stable",
                               json_object_new_boolean(identity.stable));
        json_object_object_add(r, "runtime_identity_source",
                               json_object_new_string(identity.source));
        json_object_object_add(r, "runtime_identity_reason",
                               json_object_new_string(identity.reason));
        json_object_object_add(r, "runtime_id",
                               identity.stable ? json_object_new_string(identity.runtime_id) :
                               json_object_new_null());
        json_object_object_add(r, "configured_id", json_object_new_null());
        json_object_object_add(r, "configured_id_source",
                               json_object_new_string("not_carried_by_kernel_route_rule_v1"));
        json_object_object_add(r, "byte_count", json_object_new_null());
        json_object_object_add(r, "byte_counter_supported",
                               json_object_new_boolean(0));
        json_object_object_add(r, "byte_counter_reason",
                               json_object_new_string("jmx_route_kernel_exposes_packet_hits_only"));
        json_object_object_add(r, "observed_at",
                               json_object_new_int64((int64_t)time(NULL)));
        if (!json_has_key(r, "last_hit")) {
            if (hits > 0 && last_hit_s >= 0)
                json_object_object_add(r, "last_hit", json_object_new_int64((int64_t)time(NULL) - last_hit_s));
            else
                json_object_object_add(r, "last_hit", json_object_new_int64(0));
        }
        if (!json_has_key(r, "counter_source"))
            json_object_object_add(r, "counter_source", json_object_new_string("jmx_route_kernel"));
        if (!json_has_key(r, "counter_ready"))
            json_object_object_add(r, "counter_ready", json_object_new_boolean(1));
        if (!json_has_key(r, "counter_precision"))
            json_object_object_add(r, "counter_precision", json_object_new_string("aggregate_rule_counter"));
        if (!json_has_key(r, "verified"))
            json_object_object_add(r, "verified", json_object_new_boolean(1));
        if (!json_has_key(r, "policy_hit"))
            json_object_object_add(r, "policy_hit", json_object_new_boolean(hits > 0));
        if (!json_has_key(r, "security_event_source"))
            json_object_object_add(r, "security_event_source", json_object_new_string("route_rule_counter_delta"));
        if (!json_has_key(r, "sample_source"))
            json_object_object_add(r, "sample_source", json_object_new_string("route_rule_counter"));
        if (!json_has_key(r, "remark"))
            json_object_object_add(r, "remark", json_object_new_string("内核 jmx_route 聚合命中计数；Aegis 只在 hit_count 增量时生成 verified policy_route 事件"));
    }
}

static struct json_object *route_rule_counters_batch(struct json_object *rules,
                                                     int state_ready)
{
    struct json_object *items = json_object_new_array();
    int i;

    if (!items)
        return NULL;
    if (!rules || !json_object_is_type(rules, json_type_array))
        return items;
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *item = json_object_new_object();
        struct json_object *runtime_id = NULL;
        struct json_object *configured_id = NULL;

        if (!item) {
            json_object_put(items);
            return NULL;
        }
        json_object_object_get_ex(rule, "runtime_id", &runtime_id);
        json_object_object_get_ex(rule, "configured_id", &configured_id);
        json_object_object_add(item, "runtime_id",
            runtime_id ? json_object_get(runtime_id) : json_object_new_null());
        json_object_object_add(item, "configured_id",
            configured_id ? json_object_get(configured_id) : json_object_new_null());
        json_object_object_add(item, "kernel_priority",
                               json_object_new_int(route_obj_int(rule, "prio", 0)));
        json_object_object_add(item, "hit_count",
                               json_object_new_int64(route_obj_i64(rule, "hit_count", 0)));
        json_object_object_add(item, "byte_count", json_object_new_null());
        json_object_object_add(item, "last_hit",
            route_obj_i64(rule, "last_hit", 0) > 0 ?
            json_object_new_int64(route_obj_i64(rule, "last_hit", 0)) :
            json_object_new_null());
        json_object_object_add(item, "counter_source",
                               json_object_new_string("jmx_route_kernel"));
        json_object_object_add(item, "counter_precision",
                               json_object_new_string("aggregate_rule_packet_counter"));
        json_object_object_add(item, "counter_ready", json_object_new_boolean(1));
        json_object_object_add(item, "byte_counter_supported",
                               json_object_new_boolean(0));
        json_object_object_add(item, "byte_counter_reason",
                               json_object_new_string("jmx_route_kernel_exposes_packet_hits_only"));
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(route_obj_i64(rule, "observed_at", 0)));
        if (!route_obj_int(rule, "runtime_identity_stable", 0)) {
            json_object_object_add(item, "reset_generation", json_object_new_null());
            json_object_object_add(item, "reset_detected", json_object_new_null());
            json_object_object_add(item, "state_ready", json_object_new_boolean(0));
            json_object_object_add(item, "state_reason",
                                   json_object_new_string(route_obj_str(
                                       rule, "runtime_identity_reason",
                                       "runtime_identity_unavailable")));
        } else if (state_ready) {
            json_object_object_add(item, "reset_generation",
                json_object_new_int(route_obj_int(rule, "counter_reset_generation", 0)));
            json_object_object_add(item, "reset_detected",
                json_object_new_boolean(route_obj_int(rule, "counter_reset_detected", 0)));
            json_object_object_add(item, "state_ready", json_object_new_boolean(1));
        } else {
            json_object_object_add(item, "reset_generation", json_object_new_null());
            json_object_object_add(item, "reset_detected", json_object_new_null());
            json_object_object_add(item, "state_ready", json_object_new_boolean(0));
            json_object_object_add(item, "state_reason",
                                   json_object_new_string("counter_state_persistence_failed"));
        }
        json_object_array_add(items, item);
    }
    return items;
}

static struct json_object *route_build_policy_groups(struct json_object *data)
{
    struct json_object *groups = json_object_new_array();
    struct json_object *wans = NULL;
    struct json_object *g = json_object_new_object();
    struct json_object *members = json_object_new_array();
    int i, n = 0;
    int valid_members = 0;
    int bad_members = 0;
    int64_t total_down = 0;
    int64_t total_up = 0;
    int64_t active_flows = 0;
    int64_t group_hits = 0;
    int64_t balance_rules = 0;
    struct json_object *rules = NULL;
    if (json_object_object_get_ex(data, "wans", &wans) && json_object_is_type(wans, json_type_array)) n = json_object_array_length(wans);
    for (i = 0; i < n; i++) {
        struct json_object *w = json_object_array_get_idx(wans, i), *m = json_object_new_object();
        const char *name = route_obj_str(w, "name", "wan");
        int health = route_obj_int(w, "health", 1);
        int sample_valid = route_obj_int(w, "sample_valid", 0);
        int64_t down = route_obj_i64(w, "down_rate", route_obj_i64(w, "rate_down", 0));
        int64_t up = route_obj_i64(w, "up_rate", route_obj_i64(w, "rate_up", 0));
        int64_t active = route_obj_i64(w, "active_conn", 0);
        json_object_object_add(m, "id", json_object_new_string(name));
        json_object_object_add(m, "name", json_object_new_string(name));
        json_object_object_add(m, "weight",
                               json_object_new_int(route_obj_int(w, "weight", 1)));
        json_object_object_add(m, "health", json_object_new_string(health ? "ok" : "bad"));
        json_object_object_add(m, "sample_valid", json_object_new_boolean(sample_valid != 0));
        json_object_object_add(m, "down_rate", json_object_new_int64(sample_valid ? down : 0));
        json_object_object_add(m, "up_rate", json_object_new_int64(sample_valid ? up : 0));
        json_object_object_add(m, "active_flows", json_object_new_int64(active));
        /* Same cumulative kernel counter as the WAN table, not a live count.
         * It restarts from zero whenever core re-pushes the rule set, which
         * jmx_route_sync_config() does on every core startup. */
        json_object_object_add(m, "active_flows_semantics",
            json_object_new_string("cumulative_per_wan_connection_count_since_rule_push"));
        active_flows += active;
        if (sample_valid) {
            valid_members++;
            total_down += down;
            total_up += up;
        }
        if (!health)
            bad_members++;
        json_object_array_add(members, m);
    }
    json_object_object_add(g, "id", json_object_new_string("auto-balance"));
    json_object_object_add(g, "name", json_object_new_string("自动负载组"));
    json_object_object_add(g, "mode", json_object_new_string("weighted"));
    json_object_object_add(g, "members", members);
    json_object_object_add(g, "active_flows", json_object_new_int64(active_flows));
    /* Was hardcoded 0 while the load-balance rule behind this group reported
     * six-figure hit_count, which read as "the group never matched anything".
     * Sum the hits of the rules that actually target this group instead. */
    if (json_object_object_get_ex(data, "rules", &rules) &&
        json_object_is_type(rules, json_type_array)) {
        int ri;
        int rn = json_object_array_length(rules);

        for (ri = 0; ri < rn; ri++) {
            struct json_object *r = json_object_array_get_idx(rules, ri);
            const char *wan_ids = route_obj_str(r, "wan_ids", "");

            /* A rule spanning several WANs is a load-balance rule, i.e. this group. */
            if (!wan_ids || !strchr(wan_ids, ','))
                continue;
            group_hits += route_obj_i64(r, "hit_count", 0);
            balance_rules++;
        }
    }
    json_object_object_add(g, "hit_count", json_object_new_int64(group_hits));
    json_object_object_add(g, "hit_count_semantics",
        json_object_new_string("cumulative_packet_hits_of_load_balance_rules_since_rule_push"));
    json_object_object_add(g, "hit_count_rule_count", json_object_new_int64(balance_rules));
    json_object_object_add(g, "active_flows_semantics",
        json_object_new_string("cumulative_per_wan_connection_count_since_rule_push"));
    json_object_object_add(g, "down_rate", json_object_new_int64(total_down));
    json_object_object_add(g, "up_rate", json_object_new_int64(total_up));
    json_object_object_add(g, "sample_valid", json_object_new_boolean(valid_members > 0));
    json_object_object_add(g, "degraded", json_object_new_boolean(n > 0 && valid_members == 0));
    json_object_object_add(g, "health", json_object_new_string(bad_members == 0 ? "ok" : (bad_members < n ? "warn" : "bad")));
    json_object_object_add(g, "rate_source", json_object_new_string(valid_members > 0 ? "wan_state_sum" : "unavailable"));
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
        json_object_object_add(d, "verified", json_object_new_boolean(0));
        json_object_object_add(d, "policy_hit", json_object_new_boolean(0));
        json_object_object_add(d, "candidate", json_object_new_boolean(1));
        json_object_object_add(d, "security_event", json_object_new_boolean(0));
        json_object_object_add(d, "persisted", json_object_new_boolean(0));
        json_object_object_add(d, "sample_source", json_object_new_string("runtime_candidate"));
        json_object_object_add(d, "client", json_object_new_string(c->nickname[0] ? c->nickname : (c->hostname[0] ? c->hostname : c->mac)));
        json_object_object_add(d, "ip", json_object_new_string(c->ip));
        json_object_object_add(d, "app", json_object_new_string(c->visiting_app > 0 ? route_app_name(c->visiting_app) : ""));
        json_object_object_add(d, "destination", json_object_new_string(c->visiting_url));
        json_object_object_add(d, "rule", json_object_new_string(c->visiting_app > 0 ? "应用规则候选" : "默认规则候选"));
        json_object_object_add(d, "action", json_object_new_string("route"));
        json_object_object_add(d, "path", json_object_new_string(wan));
        json_object_object_add(d, "wan", json_object_new_string(wan));
        json_object_object_add(d, "reason", json_object_new_string("运行态候选样本，未验证 conntrack mark/oif，不写入 policy_route 安全事件"));
        json_object_object_add(d, "reason_code", json_object_new_string("runtime_candidate_unverified"));
        json_object_object_add(d, "up_bytes", json_object_new_int64(0));
        json_object_object_add(d, "down_bytes", json_object_new_int64(0));
        json_object_object_add(d, "latency", json_object_new_int(0));
        json_object_array_add(arr, d); count++;
    }
    return arr;
}

/* Instantaneous steering counts, read from conntrack fwmarks.
 *
 * The kernel's per-WAN "active_conn" in /proc/dreamingwrt/jmx/jmx_route is a
 * cumulative counter, not a live one: on 30.1 it only ever grows (1860 -> 1868
 * over five seconds) and the two WAN values sum to 2722 while the whole
 * conntrack table holds 864 entries. Publishing it as "active_flows" is what
 * made the UI show a policy ratio of 0.0% against a six-figure denominator.
 *
 * conntrack marks do carry the live picture. jmx_route writes
 * mark = (rule_prio << 16) | wan_id, verified on 30.1: every one of the 905
 * marked/unmarked entries decoded to a known rule priority and WAN id with zero
 * leftovers (marks 6553601 -> prio 100/wan 1, 7208962 -> prio 110/wan 2,
 * 65536001/65536002 -> prio 1000 load-balance, 0 -> unsteered).
 *
 * A rule with a non-zero carrier_id is an explicit policy (operator steering);
 * carrier_id 0 is the default load-balance rule. Counting them separately is
 * what lets the UI say "policy steered" without lying.
 *
 * The fast path is the ctnetlink mark runtime (dedicated thread, no procfs
 * walk on the uloop thread); procfs remains as the fallback when the runtime
 * is not yet seeded, unsupported, or recovering from event loss. */

static struct {
    time_t updated_at;
    int valid;
    struct jmx_route_mark_counts counts;
} g_route_marks_cache;

static int route_count_conntrack_marks(struct json_object *data,
                                       struct jmx_route_mark_counts *out)
{
    struct json_object *rules = NULL;
    struct json_object *wans = NULL;
    /* prio -> carrier_id, small linear table (rule counts are single digits). */
    struct { int prio; int carrier; } rule_map[64];
    int rule_map_n = 0;
    int wan_ids[32];
    int wan_n = 0;
    int rule_prios[64];
    int rule_carriers[64];
    FILE *fp;
    char line[2048];
    int i;
    time_t now = time(NULL);

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!data)
        return -1;

    if (g_route_marks_cache.valid &&
        now - g_route_marks_cache.updated_at < JMX_ROUTE_SNAPSHOT_CACHE_SEC) {
        *out = g_route_marks_cache.counts;
        return 0;
    }

    if (json_object_object_get_ex(data, "rules", &rules) &&
        json_object_is_type(rules, json_type_array)) {
        int n = json_object_array_length(rules);

        for (i = 0; i < n && rule_map_n < (int)(sizeof(rule_map) / sizeof(rule_map[0])); i++) {
            struct json_object *r = json_object_array_get_idx(rules, i);

            if (!route_obj_int(r, "enabled", 0))
                continue;
            rule_map[rule_map_n].prio = route_obj_int(r, "prio", 0);
            rule_map[rule_map_n].carrier = route_obj_int(r, "carrier_id", 0);
            rule_prios[rule_map_n] = rule_map[rule_map_n].prio;
            rule_carriers[rule_map_n] = rule_map[rule_map_n].carrier;
            rule_map_n++;
        }
    }
    if (json_object_object_get_ex(data, "wans", &wans) &&
        json_object_is_type(wans, json_type_array)) {
        int n = json_object_array_length(wans);

        for (i = 0; i < n && wan_n < (int)(sizeof(wan_ids) / sizeof(wan_ids[0])); i++)
            wan_ids[wan_n++] = route_obj_int(json_object_array_get_idx(wans, i), "id", 0);
    }
    if (rule_map_n == 0 || wan_n == 0)
        return -1;
    out->prio_n = rule_map_n;
    for (i = 0; i < rule_map_n; i++) {
        out->prio[i] = rule_map[i].prio;
        out->per_prio[i] = 0;
    }

    if (jmx_route_mark_runtime_sample(rule_prios, rule_carriers, rule_map_n,
                                      wan_ids, wan_n, out) == 0) {
        g_route_marks_cache.counts = *out;
        g_route_marks_cache.updated_at = now;
        g_route_marks_cache.valid = 1;
        return 0;
    }

    fp = fopen("/proc/net/nf_conntrack", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        const char *m = strstr(line, "mark=");
        unsigned long mark;
        int prio;
        int wan;
        int carrier = -1;
        int wan_known = 0;

        out->total++;
        if (!m) {
            out->unsteered++;
            continue;
        }
        mark = strtoul(m + 5, NULL, 10);
        if (mark == 0) {
            out->unsteered++;
            continue;
        }
        prio = (int)(mark >> 16);
        wan = (int)(mark & 0xFFFF);
        {
            int slot = -1;

            for (i = 0; i < rule_map_n; i++) {
                if (rule_map[i].prio == prio) {
                    slot = i;
                    break;
                }
            }
            if (slot >= 0)
                out->per_prio[slot]++;
        }
        for (i = 0; i < rule_map_n; i++) {
            if (rule_map[i].prio == prio) {
                carrier = rule_map[i].carrier;
                break;
            }
        }
        for (i = 0; i < wan_n; i++) {
            if (wan_ids[i] == wan) {
                wan_known = 1;
                break;
            }
        }
        if (carrier < 0 || !wan_known)
            out->unknown++;
        else if (carrier > 0)
            out->explicit_steer++;
        else
            out->load_balance++;
    }
    fclose(fp);
    g_route_marks_cache.counts = *out;
    g_route_marks_cache.updated_at = now;
    g_route_marks_cache.valid = 1;
    return 0;
}

static void route_enrich_status(struct json_object *data)
{
    struct json_object *policy = json_object_new_object();
    struct json_object *rules = NULL;
    struct json_object *adv_sync = NULL;
    FILE *adv_fp;
    int rc = 0, wc = 0;
    int available;
    int64_t hit_total = 0;
    int64_t last_hit_at = 0;
    int64_t active_flows = 0;
    int64_t cumulative_conn = 0;
    struct jmx_route_mark_counts marks;
    int marks_ok;
    const char *counter_reason;
    int main_nondefault_count;
    int main_nondefault_ready;
    int counter_state_ready = 0;
    int i;
    if (!data) return;
    (void)route_state_db_init(NULL);
    route_enrich_wans(data);
    route_enrich_rules(data);
    wc = route_obj_int(data, "wan_count", 0);
    rc = route_obj_int(data, "rule_count", 0);
    {
        struct json_object *wans = NULL;

        if (json_object_object_get_ex(data, "wans", &wans) &&
            json_object_is_type(wans, json_type_array)) {
            for (i = 0; i < json_object_array_length(wans); i++)
                cumulative_conn += route_obj_i64(json_object_array_get_idx(wans, i),
                                                 "active_conn", 0);
        }
    }
    if (json_object_object_get_ex(data, "rules", &rules) && json_object_is_type(rules, json_type_array)) {
        rc = json_object_array_length(rules);
        for (i = 0; i < rc; i++) {
            struct json_object *r = json_object_array_get_idx(rules, i);
            int64_t hits = route_obj_i64(r, "hit_count", 0);
            int64_t last = route_obj_i64(r, "last_hit", 0);
            hit_total += hits;
            if (last > last_hit_at)
                last_hit_at = last;
        }
    }
    available = route_obj_int(data, "available", 0);
    /* Needs the enriched rules/wans arrays, so it runs after route_enrich_rules(). */
    marks_ok = route_count_conntrack_marks(data, &marks) == 0;
    /* active_flows must be a live count to serve as the denominator of a
     * percentage. When marks are readable that is the conntrack table size;
     * otherwise fall back to the kernel's cumulative figure and label it. */
    active_flows = marks_ok ? marks.total : cumulative_conn;
    /* Fill the per-rule live counts, which route_enrich_rules() could only
     * default to 0. A rule showing hit_count=104561 next to active_flows=0 was
     * the specific contradiction acceptance reported. */
    if (marks_ok && json_object_object_get_ex(data, "rules", &rules) &&
        json_object_is_type(rules, json_type_array)) {
        int n = json_object_array_length(rules);

        for (i = 0; i < n; i++) {
            struct json_object *r = json_object_array_get_idx(rules, i);
            int prio = route_obj_int(r, "prio", 0);
            int j;

            for (j = 0; j < marks.prio_n; j++) {
                if (marks.prio[j] != prio)
                    continue;
                json_object_object_del(r, "active_flows");
                json_object_object_add(r, "active_flows",
                                       json_object_new_int64(marks.per_prio[j]));
                json_object_object_add(r, "active_flows_source",
                                       json_object_new_string("nf_conntrack_fwmark"));
                json_object_object_add(r, "active_flows_semantics",
                    json_object_new_string("instantaneous_conntrack_entries_marked_by_this_rule"));
                json_object_object_add(r, "hit_count_semantics",
                    json_object_new_string("cumulative_packet_hits_since_rule_push"));
                break;
            }
        }
    }
    main_nondefault_count = route_main_nondefault_rule_count();
    main_nondefault_ready = main_nondefault_count == 1;
    json_object_object_add(data, "main_nondefault_rule_ready",
                           json_object_new_boolean(main_nondefault_ready));
    json_object_object_add(data, "main_nondefault_rule_priority",
                           json_object_new_int(JMX_ROUTE_MAIN_NONDEFAULT_PRIO));
    json_object_object_add(data, "main_nondefault_rule_count",
                           json_object_new_int(main_nondefault_count));
    counter_reason = available ? (rc > 0 ? "ok" : "no_route_rules") : "jmx_route_proc_missing";
    if (!json_has_key(data, "counter_source"))
        json_object_object_add(data, "counter_source", json_object_new_string(available ? "jmx_route_kernel" : "unavailable"));
    if (!json_has_key(data, "counter_ready"))
        json_object_object_add(data, "counter_ready", json_object_new_boolean(available != 0));
    if (!json_has_key(data, "counter_supported"))
        json_object_object_add(data, "counter_supported", json_object_new_boolean(available != 0));
    if (!json_has_key(data, "counter_precision"))
        json_object_object_add(data, "counter_precision", json_object_new_string("aggregate_rule_counter"));
    if (!json_has_key(data, "counter_reason"))
        json_object_object_add(data, "counter_reason", json_object_new_string(counter_reason));
    if (!json_has_key(data, "route_rule_counter_supported"))
        json_object_object_add(data, "route_rule_counter_supported", json_object_new_boolean(available != 0));
    if (!json_has_key(data, "policy_route_verified_counter_supported"))
        json_object_object_add(data, "policy_route_verified_counter_supported", json_object_new_boolean(available != 0));
    if (!json_has_key(data, "route_rule_counter_db"))
        json_object_object_add(data, "route_rule_counter_db", json_object_new_string(JMX_ROUTE_STATE_DB_PATH));
    if (!json_has_key(data, "hit_total"))
        json_object_object_add(data, "hit_total", json_object_new_int64(hit_total));
    if (!json_has_key(data, "last_hit_at"))
        json_object_object_add(data, "last_hit_at", last_hit_at > 0 ? json_object_new_int64(last_hit_at) : json_object_new_null());
    json_object_object_add(policy, "enabled", json_object_new_boolean(1));
    json_object_object_add(policy, "mode", json_object_new_string("health-aware"));
    json_object_object_add(policy, "engine", json_object_new_string("jmx_route kernel marks + ip rule"));
    json_object_object_add(policy, "main_nondefault_rule_ready",
                           json_object_new_boolean(main_nondefault_ready));
    json_object_object_add(policy, "active_rules", json_object_new_int(rc));
    json_object_object_add(policy, "policy_groups", json_object_new_int(wc > 0 ? 1 : 0));
    json_object_object_add(policy, "active_flows", json_object_new_int64(active_flows));
    /* Instantaneous counts from conntrack fwmarks. steered_flows used to be a
     * hardcoded 0, which made the UI compute steered/active = 0.0% while the
     * rules were demonstrably matching (hit_count in the six figures, last hit
     * seconds ago). When marks cannot be read the fields are null with an
     * explicit *_supported=false rather than a misleading 0. */
    if (marks_ok) {
        json_object_object_add(policy, "steered_flows",
                               json_object_new_int64(marks.explicit_steer));
        json_object_object_add(policy, "load_balance_flows",
                               json_object_new_int64(marks.load_balance));
        json_object_object_add(policy, "bypass_flows",
                               json_object_new_int64(marks.unsteered));
        json_object_object_add(policy, "unattributed_flows",
                               json_object_new_int64(marks.unknown));
        json_object_object_add(policy, "fallback_flows",
                               json_object_new_int64(marks.unknown));
        json_object_object_add(policy, "steered_flows_supported",
                               json_object_new_boolean(1));
        json_object_object_add(policy, "flow_counter_source",
                               json_object_new_string("nf_conntrack_fwmark"));
    } else {
        json_object_object_add(policy, "steered_flows", NULL);
        json_object_object_add(policy, "load_balance_flows", NULL);
        json_object_object_add(policy, "bypass_flows", NULL);
        json_object_object_add(policy, "unattributed_flows", NULL);
        json_object_object_add(policy, "fallback_flows", NULL);
        json_object_object_add(policy, "steered_flows_supported",
                               json_object_new_boolean(0));
        json_object_object_add(policy, "steered_flows_reason",
                               json_object_new_string("nf_conntrack_marks_unreadable"));
        json_object_object_add(policy, "flow_counter_source",
                               json_object_new_string("unavailable"));
    }
    json_object_object_add(policy, "hit_total", json_object_new_int64(hit_total));
    /* Explicit semantics so the UI can word its labels correctly and acceptance
     * can recompute independently. The three counters answer different
     * questions and were previously indistinguishable in the payload. */
    json_object_object_add(policy, "hit_total_semantics",
        json_object_new_string("cumulative_rule_packet_hits_since_rule_push"));
    json_object_object_add(policy, "active_flows_semantics",
        json_object_new_string(marks_ok ? "instantaneous_conntrack_entries"
                                       : "cumulative_kernel_wan_connections"));
    json_object_object_add(policy, "steered_flows_semantics",
        json_object_new_string("instantaneous_conntrack_entries_matching_explicit_carrier_rules"));
    json_object_object_add(policy, "kernel_cumulative_connections",
                           json_object_new_int64(cumulative_conn));
    json_object_object_add(policy, "kernel_cumulative_connections_semantics",
        json_object_new_string("cumulative_per_wan_connection_count_since_rule_push"));
    /* Both cumulative counters restart at zero when core re-pushes rules on
     * startup, so a drop across samples is a restart, not a counter bug. This
     * is also why the two are numerically equal in steady state: the kernel
     * increments per-WAN active_conn and per-rule hits on the same event. */
    json_object_object_add(policy, "cumulative_counter_epoch",
        json_object_new_string("reset_on_core_rule_push"));
    json_object_object_add(policy, "last_hit_at", last_hit_at > 0 ? json_object_new_int64(last_hit_at) : json_object_new_null());
    json_object_object_add(policy, "counter_source", json_object_new_string(available ? "jmx_route_kernel" : "unavailable"));
    json_object_object_add(policy, "counter_ready", json_object_new_boolean(available != 0));
    json_object_object_add(policy, "counter_supported", json_object_new_boolean(available != 0));
    json_object_object_add(policy, "counter_precision", json_object_new_string("aggregate_rule_counter"));
    json_object_object_add(policy, "counter_reason", json_object_new_string(counter_reason));
    json_object_object_add(policy, "route_rule_counter_supported", json_object_new_boolean(available != 0));
    json_object_object_add(policy, "verified_counter_supported", json_object_new_boolean(available != 0));
    json_object_object_add(policy, "last_apply_at", json_object_new_int64(0));
    json_object_object_add(policy, "last_decision_at", json_object_new_int64((int64_t)time(NULL)));
    if (!json_has_key(data, "ts")) json_object_object_add(data, "ts", json_object_new_int64((int64_t)time(NULL)));
    if (!json_has_key(data, "wan_count")) json_object_object_add(data, "wan_count", json_object_new_int(wc));
    if (!json_has_key(data, "rule_count")) json_object_object_add(data, "rule_count", json_object_new_int(rc));
    if (available)
        counter_state_ready = route_state_persist_rule_counters(data) >= 0;
    json_object_object_add(data, "rule_counter_batch_supported",
                           json_object_new_boolean(available != 0));
    json_object_object_add(data, "rule_counter_batch_source",
                           json_object_new_string(available ? "jmx_route_kernel_snapshot" :
                                                  "unavailable"));
    json_object_object_add(data, "rule_counter_identity_version",
                           json_object_new_string("runtime_semantic_fingerprint_v1"));
    json_object_object_add(data, "configured_id_supported",
                           json_object_new_boolean(0));
    json_object_object_add(data, "configured_id_reason",
                           json_object_new_string("kernel_route_rule_v1_does_not_carry_configured_id"));
    json_object_object_add(data, "rule_counters",
                           route_rule_counters_batch(rules, counter_state_ready));
    json_object_object_add(policy, "rule_counter_batch_supported",
                           json_object_new_boolean(available != 0));
    json_object_object_add(policy, "runtime_identity_supported",
                           json_object_new_boolean(available != 0));
    json_object_object_add(policy, "configured_id_supported",
                           json_object_new_boolean(0));
    adv_fp = fopen(JMX_ROUTE_ADV_SYNC_STATE, "r");
    if (adv_fp) {
        char buf[2048];
        size_t n = fread(buf, 1, sizeof(buf) - 1, adv_fp);

        fclose(adv_fp);
        buf[n] = '\0';
        adv_sync = json_tokener_parse(buf);
        if (adv_sync && json_object_is_type(adv_sync, json_type_object)) {
            json_object_object_add(data, "advanced_sync", adv_sync);
        } else {
            if (adv_sync)
                json_object_put(adv_sync);
        }
    }
    json_object_object_add(data, "policy_status", policy);
    json_object_object_add(data, "policy_groups", route_build_policy_groups(data));
    json_object_object_add(data, "route_decisions", route_build_decisions(data));
    {
        struct jmx_route_mark_runtime_status mrs;

        if (jmx_route_mark_runtime_status(&mrs) == 0) {
            struct json_object *mr = json_object_new_object();

            json_object_object_add(mr, "active",
                                   json_object_new_boolean(mrs.active != 0));
            json_object_object_add(mr, "supported",
                                   json_object_new_boolean(mrs.supported != 0));
            json_object_object_add(mr, "dumping",
                                   json_object_new_boolean(mrs.dumping != 0));
            json_object_object_add(mr, "resync_needed",
                                   json_object_new_boolean(mrs.resync_needed != 0));
            json_object_object_add(mr, "overflow",
                                   json_object_new_boolean(mrs.overflow != 0));
            json_object_object_add(mr, "missing_id",
                                   json_object_new_int(mrs.missing_id));
            json_object_object_add(mr, "events_upsert",
                json_object_new_int64((int64_t)mrs.events_upsert));
            json_object_object_add(mr, "events_destroy",
                json_object_new_int64((int64_t)mrs.events_destroy));
            json_object_object_add(mr, "events_error",
                json_object_new_int64((int64_t)mrs.events_error));
            json_object_object_add(mr, "enobufs",
                json_object_new_int64((int64_t)mrs.enobufs));
            json_object_object_add(mr, "dumps",
                json_object_new_int64((int64_t)mrs.dumps));
            json_object_object_add(mr, "dump_entries",
                json_object_new_int64((int64_t)mrs.dump_entries));
            json_object_object_add(mr, "last_full_sync",
                mrs.last_full_sync > 0 ?
                json_object_new_int64((int64_t)mrs.last_full_sync) :
                json_object_new_null());
            json_object_object_add(mr, "updated_at",
                json_object_new_int64((int64_t)mrs.updated_at));
            json_object_object_add(data, "mark_runtime", mr);
        }
    }
}

static struct json_object *route_parse_proc_status(FILE *fp)
{
    struct json_object *data = json_object_new_object();
    struct json_object *wans = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    char line[512];
    int section = 0;
    int rule_enhancements_column = 0;

    json_object_object_add(data, "available", json_object_new_boolean(1));
    json_object_object_add(data, "wans", wans);
    json_object_object_add(data, "rules", rules);

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        p[strcspn(p, "\n")] = 0;
        if (!strncmp(p, "RouteRuleAbi:", 13)) {
            unsigned abi = 0, enhancements = 0;

            if (sscanf(p, "RouteRuleAbi: %u enhancements: %x", &abi,
                       &enhancements) >= 1) {
                json_object_object_add(data, "route_rule_abi",
                                       json_object_new_int((int)abi));
                json_object_object_add(data, "route_rule_enhancements",
                                       json_object_new_int64((int64_t)enhancements));
            }
            continue;
        }
        if (!strncmp(p, "CarrierPrefixes:", 16)) {
            unsigned carrier_prefix_count = 0;
            if (sscanf(p, "CarrierPrefixes: %u", &carrier_prefix_count) == 1)
                json_object_object_add(data, "carrier_prefix_count", json_object_new_int((int)carrier_prefix_count));
            continue;
        }
        if (strcmp(p, "WANs:") == 0) { section = 1; continue; }
        if (strcmp(p, "Rules:") == 0) { section = 2; continue; }
        if (!strncmp(p, "prio ", 5)) {
            rule_enhancements_column = strstr(p, "enhancements") != NULL;
            continue;
        }
        if (p[0] == '\0' || !strncmp(p, "id ", 3))
            continue;

        if (section == 1) {
            unsigned id, table, health, weight = 1, adaptive_weight = 100;
            unsigned generation = 0, rebind_mode = 0, rebind_pending = 0;
            unsigned long long active_conn = 0, rx_bytes = 0;
            unsigned long long rebind_requested = 0, rebind_killed = 0;
            unsigned long long rebind_sensitive = 0, rebind_at = 0;
            char name[32], fwmark[32], gateway[64];
            int n = sscanf(p,
                           "%u %31s %31s %u %63s %u %u %u %llu %llu %u "
                           "%llu %llu %llu %u %llu %u",
                           &id, name, fwmark, &table, gateway, &health, &weight,
                           &adaptive_weight, &active_conn, &rx_bytes, &generation,
                           &rebind_requested, &rebind_killed, &rebind_sensitive,
                           &rebind_mode, &rebind_at, &rebind_pending);

            if (n != 17) {
                rebind_requested = rebind_killed = rebind_sensitive = rebind_at = 0;
                rebind_mode = rebind_pending = 0;
                n = sscanf(p, "%u %31s %31s %u %63s %u %u %u %llu %llu %u",
                           &id, name, fwmark, &table, gateway, &health, &weight,
                           &adaptive_weight, &active_conn, &rx_bytes, &generation);
            }
            if (n != 17 && n != 11) {
                adaptive_weight = 100;
                n = sscanf(p, "%u %31s %31s %u %63s %u %u %llu %llu %u",
                           &id, name, fwmark, &table, gateway, &health, &weight,
                           &active_conn, &rx_bytes, &generation);
            }
            if (n == 17 || n == 11 || n == 10 || n == 6) {
                struct json_object *o = json_object_new_object();
                json_object_object_add(o, "id", json_object_new_int((int)id));
                json_object_object_add(o, "name", json_object_new_string(name));
                json_object_object_add(o, "fwmark", json_object_new_string(fwmark));
                json_object_object_add(o, "table", json_object_new_int((int)table));
                json_object_object_add(o, "gateway", json_object_new_string(gateway));
                json_object_object_add(o, "health", json_object_new_boolean(health != 0));
                json_object_object_add(o, "weight", json_object_new_int64((int64_t)weight));
                json_object_object_add(o, "adaptive_weight",
                                       json_object_new_int64((int64_t)adaptive_weight));
                json_object_object_add(o, "active_conn", json_object_new_int64((int64_t)active_conn));
                json_object_object_add(o, "rx_bytes", json_object_new_int64((int64_t)rx_bytes));
                json_object_object_add(o, "generation", json_object_new_int64((int64_t)generation));
                json_object_object_add(o, "rebind_requested",
                                       json_object_new_int64((int64_t)rebind_requested));
                json_object_object_add(o, "rebind_killed",
                                       json_object_new_int64((int64_t)rebind_killed));
                json_object_object_add(o, "rebind_sensitive_skipped",
                                       json_object_new_int64((int64_t)rebind_sensitive));
                json_object_object_add(o, "rebind_last_mode",
                                       json_object_new_int((int)rebind_mode));
                json_object_object_add(o, "rebind_last_at",
                                       json_object_new_int64((int64_t)rebind_at));
                json_object_object_add(o, "rebind_pending_mode",
                                       json_object_new_int((int)rebind_pending));
                json_object_array_add(wans, o);
            }
        } else if (section == 2) {
            unsigned prio, en, proto, appid, carrier, dport, mode;
            unsigned long long hits = 0;
            unsigned long last_hit_s = 0;
            unsigned enhancements = 0;
            char src[64], dst[64], members_buf[192] = {0};
            int n;

            if (rule_enhancements_column)
                n = sscanf(p, "%u %u %u %u %u %63s %63s %u %u %llu %lu %x %127s",
                           &prio, &en, &proto, &appid, &carrier, src, dst, &dport, &mode,
                           &hits, &last_hit_s, &enhancements, members_buf);
            else
                n = sscanf(p, "%u %u %u %u %u %63s %63s %u %u %llu %lu %127s",
                           &prio, &en, &proto, &appid, &carrier, src, dst, &dport, &mode,
                           &hits, &last_hit_s, members_buf);
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
                json_object_object_add(o, "enhancements",
                                       json_object_new_int64((int64_t)enhancements));
                json_object_object_add(o, "hit_count", json_object_new_int64((int64_t)hits));
                json_object_object_add(o, "last_hit_seconds_ago", json_object_new_int64((int64_t)last_hit_s));
                if (n >= 12) {
                    char ids_buf[128] = "";
                    char weights_buf[128] = "";
                    char parse_buf[192];
                    char *save = NULL;
                    char *token;
                    size_t ids_off = 0, weights_off = 0;
                    int first = 1;

                    snprintf(parse_buf, sizeof(parse_buf), "%s", members_buf);
                    for (token = strtok_r(parse_buf, ",", &save); token;
                         token = strtok_r(NULL, ",", &save)) {
                        char *colon = strchr(token, ':');
                        unsigned id;
                        unsigned weight = 0;

                        if (colon) {
                            *colon++ = '\0';
                            weight = (unsigned)strtoul(colon, NULL, 10);
                        }
                        id = (unsigned)strtoul(token, NULL, 10);
                        ids_off += snprintf(ids_buf + ids_off,
                                            sizeof(ids_buf) - ids_off,
                                            "%s%u", first ? "" : ",", id);
                        weights_off += snprintf(weights_buf + weights_off,
                                                sizeof(weights_buf) - weights_off,
                                                "%s%u", first ? "" : ",", weight);
                        first = 0;
                    }
                    json_object_object_add(o, "wan_ids", json_object_new_string(ids_buf));
                    json_object_object_add(o, "wan_weights",
                                           json_object_new_string(weights_buf));
                }
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

static int route_kernel_state_counts(int *carrier_count, int *wan_count, int *rule_count)
{
    struct json_object *data = NULL;
    struct json_object *value = NULL;
    FILE *fp;

    if (!carrier_count || !wan_count || !rule_count)
        return -1;
    fp = jmx_fopen_af("jmx_route", "r");
    if (!fp)
        return -1;
    data = route_parse_proc_status(fp);
    fclose(fp);
    if (!data)
        return -1;

    if (!json_object_object_get_ex(data, "carrier_prefix_count", &value))
        goto fail;
    *carrier_count = json_object_get_int(value);
    if (!json_object_object_get_ex(data, "wan_count", &value))
        goto fail;
    *wan_count = json_object_get_int(value);
    if (!json_object_object_get_ex(data, "rule_count", &value))
        goto fail;
    *rule_count = json_object_get_int(value);
    json_object_put(data);
    return 0;

fail:
    json_object_put(data);
    return -1;
}

/* ROUTE_ADD_V2 has no request/response netlink acknowledgement.  The module
 * advertises the versioned ABI in procfs, so verify it before a config sync
 * changes any live route state.  An older module must never receive the 96-byte
 * payload: it has no action 44 and would silently leave the enhancement absent. */
static int route_kernel_rule_v2_supported(uint32_t *enhancements_out)
{
    struct json_object *data = NULL;
    struct json_object *value = NULL;
    FILE *fp;
    int supported = 0;
    uint32_t enhancements = 0;

    if (enhancements_out)
        *enhancements_out = 0;
    fp = jmx_fopen_af("jmx_route", "r");
    if (!fp)
        return 0;
    data = route_parse_proc_status(fp);
    fclose(fp);
    if (!data)
        return 0;
    if (json_object_object_get_ex(data, "route_rule_enhancements", &value))
        enhancements = (uint32_t)json_object_get_int64(value);
    if (enhancements_out)
        *enhancements_out = enhancements;
    if (json_object_object_get_ex(data, "route_rule_abi", &value) &&
        json_object_get_int(value) >= 2 &&
        (enhancements & JMX_ROUTE_ENHANCEMENT_ADAPTIVE_PENALTY))
        supported = 1;
    json_object_put(data);
    return supported;
}

static int route_config_requires_rule_v2(struct json_object *config)
{
    struct json_object *rules = NULL;
    int i;

    if (!config || !json_object_object_get_ex(config, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);

        if (!json_get_u32(rule, "enabled", 1) ||
            !json_get_u32(rule, "adaptive_penalty_sticky", 0))
            continue;
        /* Legacy mode 9 retains its exact historic dataplane behaviour when the
         * device has not installed an ABI-v2 kernel yet.  Every canonical
         * base-mode + enhancement combination requires v2. */
        if (!json_get_u32(rule, "migration_required", 0))
            return 1;
    }
    return 0;
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


struct json_object *jmx_api_route_config_get(struct json_object *req_obj)
{
    struct json_object *data = NULL;
    struct json_object *capabilities = json_object_new_object();

    (void)req_obj;
    if (jmx_route_db_config_get(&data) != 0 || !data) {
        if (data)
            json_object_put(data);
        if (capabilities)
            json_object_put(capabilities);
        return route_result(-1);
    }
    json_object_object_add(capabilities, "algorithms", json_object_new_string(
        "hash_src_dst_dport,hash_src_dst,weighted_new_flow_rr,least_rx_load_normalized,least_active_conn_normalized,hash_src,hash_src_sport"));
    json_object_object_add(capabilities, "weighted_members", json_object_new_boolean(1));
    json_object_object_add(capabilities, "all_down_actions", json_object_new_string("main_route"));
    /* The switch is discoverable, so the UI does not have to hardcode the value
     * set. per_rule reads each rule's reinstate_dangling flag, which is why that
     * field is exported on every rule regardless of the active policy. */
    json_object_object_add(capabilities, "dangling_wan_policies",
                           json_object_new_string(
                               "reinstate_registered,keep_excluded,per_rule"));
    json_object_object_add(capabilities, "dangling_wan_policy_default",
                           json_object_new_string("reinstate_registered"));
    json_object_object_add(capabilities, "dangling_wan_policy_scope",
                           json_object_new_string("global+per_rule"));
    json_object_object_add(capabilities, "ipv6_multiwan",
                           json_object_new_boolean(route_ipv6_multiwan_active()));
    json_object_object_add(capabilities, "config_authority",
                           json_object_new_string("config.db"));
    json_object_object_add(capabilities, "transactional_apply",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "auto_carrier_wan_selection",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "explicit_wan_selection",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "unresolved_auto_carrier_rejected",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "wan_carrier_source",
                           json_object_new_string(
                               "dreamingwrt.db:net_interfaces.carrier+jmx_isp"));
    /* `carrier_prefixes` is the operator's *override* list, not the whole
     * carrier prefix table.  The bulk of the prefixes are loaded straight from
     * the signature DB (`carrier_prefix`, see jmx_route_load_builtin_carriers)
     * and never appear here, so an empty array means "no overrides configured",
     * not "carrier routing unconfigured".  Reading it as the latter caused a
     * false diagnosis during acceptance (A-013), hence these explicit fields. */
    json_object_object_add(capabilities, "carrier_prefixes_semantics",
                           json_object_new_string("user_override_only"));
    json_object_object_add(capabilities, "carrier_prefix_builtin_source",
                           json_object_new_string("signature_db:carrier_prefix(enabled=1)"));
    {
        int builtin = 0, kwan = 0, krule = 0;

        if (route_kernel_state_counts(&builtin, &kwan, &krule) == 0)
            json_object_object_add(data, "carrier_prefix_kernel_count",
                                   json_object_new_int(builtin));
    }
    json_object_object_add(data, "capabilities", capabilities);
    return route_json_ok(data);
}

struct json_object *jmx_api_route_config_set(struct json_object *req_obj)
{
    struct jmx_route_db_tx *tx = NULL;
    struct json_object *previous = NULL;
    struct json_object *readback = NULL;
    struct json_object *data = NULL;
    char error[160] = "";
    const char *failure_stage = "config_validation";
    int rollback_attempted = 0;
    int route_rollback_ok = 1;
    int weights_enforced = 1;
    int saved_errno;

    if (jmx_route_db_replace_begin(req_obj, &tx, &previous, &readback,
                                   error, sizeof(error)) != 0)
        goto fail;
    if (jmx_route_sync_json(readback) != 0) {
        saved_errno = errno ? errno : EIO;
        failure_stage = "runtime_apply";
        jmx_route_db_replace_rollback(tx);
        tx = NULL;
        rollback_attempted = 1;
        route_rollback_ok = previous && jmx_route_sync_json(previous) == 0;
        if (!route_rollback_ok)
            LOG_ERROR("jmx_route: failed to restore runtime after DB apply failure");
        errno = saved_errno;
        snprintf(error, sizeof(error), "%s", "runtime apply/readback failed");
        goto fail;
    }
    if (route_policy_kernel_readback_matches(readback, 0, 1,
                                             &weights_enforced,
                                             error, sizeof(error)) != 0) {
        saved_errno = errno ? errno : EIO;
        failure_stage = "kernel_readback";
        jmx_route_db_replace_rollback(tx);
        tx = NULL;
        rollback_attempted = 1;
        route_rollback_ok = previous && jmx_route_sync_json(previous) == 0;
        if (!route_rollback_ok)
            LOG_ERROR("jmx_route: failed to restore runtime after rule readback mismatch");
        errno = saved_errno;
        goto fail;
    }
    if (jmx_route_db_replace_commit(tx) != 0) {
        tx = NULL;
        failure_stage = "persistence_commit";
        rollback_attempted = 1;
        route_rollback_ok = previous && jmx_route_sync_json(previous) == 0;
        if (!route_rollback_ok)
            LOG_ERROR("jmx_route: failed to restore runtime after DB commit failure");
        snprintf(error, sizeof(error), "%s", "config.db commit failed");
        goto fail;
    }
    tx = NULL;
    data = readback;
    readback = NULL;
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "config_authority",
                           json_object_new_string("config.db"));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(1));
    /*
     * The persisted ratio (weight_ratio) is always authoritative; whether the
     * kernel enforces it per-flow depends on the loaded jmx.ko.  Surface both
     * so the UI never claims data-plane weighting that the module cannot do.
     */
    json_object_object_add(data, "weight_runtime_enforced",
                           json_object_new_boolean(weights_enforced));
    json_object_object_add(data, "weight_runtime_reason",
                           json_object_new_string(weights_enforced ?
                               "kernel_reports_per_member_weights" :
                               "kernel_module_ids_only_weight_ratio_configured_not_enforced"));
    if (previous)
        json_object_put(previous);
    return route_json_ok(data);

fail:
    saved_errno = errno ? errno : EIO;
    if (tx)
        jmx_route_db_replace_rollback(tx);
    if (previous)
        json_object_put(previous);
    if (readback)
        json_object_put(readback);
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "rc", json_object_new_int(-1));
    json_object_object_add(data, "error", json_object_new_string(
        error[0] ? error : strerror(saved_errno)));
    json_object_object_add(data, "config_authority",
                           json_object_new_string("config.db"));
    json_object_object_add(data, "failure_stage",
                           json_object_new_string(failure_stage));
    json_object_object_add(data, "rollback_attempted",
                           json_object_new_boolean(rollback_attempted));
    json_object_object_add(data, "route_rollback_ok",
                           json_object_new_boolean(route_rollback_ok));
    json_object_object_add(data, "runtime_reason", json_object_new_string(
        route_rollback_ok ?
        (rollback_attempted ? "previous_config_restored" :
                              "request_rejected_before_apply") :
        "previous_config_restore_failed"));
    if (rollback_attempted)
        dw_report_config_commit_failed("route_config", "", failure_stage,
                                       route_rollback_ok);
    errno = saved_errno;
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

/*
 * Change the load-balance selector without rebuilding the whole route graph.
 * route_config_set is intentionally a full transactional replace and its
 * runtime sync flushes all kernel rules and WAN registrations.  That is the
 * right primitive for structural edits, but it is unnecessarily disruptive
 * for a selector change: the kernel replaces a rule with the same priority in
 * place and keeps its counters/conntrack marks.  Persist the complete config
 * in the same DB transaction, then replace only the generic default rule.
 *
 * WAN-policy modes are intentionally carrier-neutral.  Legacy auto-carrier
 * rules are disabled when this contract is applied so a higher-priority
 * operator match cannot silently bypass the selected all-uplink policy.
 */
static int route_policy_rule_eligible(struct json_object *rule)
{
    struct json_object *wan_ids = NULL;
    uint32_t prio;

    if (!rule || !json_object_is_type(rule, json_type_object))
        return 0;
    prio = json_get_u32(rule, "prio", 0);
    if (prio < 1000)
        return 0;
    if (!json_object_object_get_ex(rule, "wan_ids", &wan_ids) ||
        !json_object_is_type(wan_ids, json_type_array))
        return 0;
    return json_object_array_length(wan_ids) > 1;
}

static int route_policy_auto_carrier_rule(struct json_object *rule)
{
    const char *selection;

    if (!rule || !json_object_is_type(rule, json_type_object))
        return 0;
    selection = json_get_str(rule, "wan_selection", "");
    return !strcmp(selection, "auto_carrier");
}

static int route_policy_apply_rule(int fd, struct json_object *rule);

static int route_policy_reconcile_rule(int fd, struct json_object *rule)
{
    if (route_policy_auto_carrier_rule(rule)) {
        uint16_t prio = (uint16_t)json_get_u32(rule, "prio", 0);

        if (!prio)
            return -1;
        if (!json_get_u32(rule, "enabled", 1))
            return jmx_route_nl_rule_del(fd, prio);
    }
    return route_policy_apply_rule(fd, rule);
}

static int route_policy_apply_rule(int fd, struct json_object *rule)
{
    struct jmx_route_rule_wire wire;
    int i;

    uint32_t enhancements = 0;
    int v2_supported = route_kernel_rule_v2_supported(NULL);

    route_rule_from_json(rule, &wire, (int)json_get_u32(rule, "prio", 1000),
                         &enhancements, !v2_supported);
    if (wire.carrier_id != JMX_CARRIER_ANY && wire.wan_count == 0) {
        for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES &&
                    wire.wan_count < JMX_ROUTE_MAX_WAN_IFACES; i++) {
            if (g_route_auto_carriers[i] == wire.carrier_id)
                wire.wan_ids[wire.wan_count++] = (uint8_t)i;
        }
    }
    if (!wire.enabled || wire.wan_count == 0 ||
        wire.sticky_mode > JMX_STICKY_MAX)
        return -1;
    if (enhancements) {
        if (!v2_supported) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return jmx_route_nl_rule_add_v2(fd, &wire, enhancements);
    }
    return jmx_route_nl_rule_add(fd, &wire);
}

static struct json_object *route_policy_find_wan(struct json_object *wans,
                                                 uint8_t id)
{
    int i;

    if (!wans || !json_object_is_type(wans, json_type_array) || !id)
        return NULL;
    for (i = 0; i < json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);

        if ((uint8_t)json_get_u32(wan, "id", 0) == id)
            return wan;
    }
    return NULL;
}

static struct uci_section *route_policy_find_network_wan(struct uci_package *pkg,
                                                         const char *name)
{
    struct uci_element *e;

    if (!pkg || !name || !name[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (s && !strcmp(s->type, "interface") && !strcmp(s->e.name, name))
            return s;
    }
    return NULL;
}

/*
 * route_wan is the configuration authority, but older installations can have
 * live UCI WANs which were registered into the kernel by the runtime top-up and
 * never written into that ledger.  A policy request naming one of those lines
 * used to be accepted and then canonicalized back out as dangling.  Admit only
 * WAN ids the kernel already knows, and materialize the same line into the
 * transaction so database and runtime membership can converge atomically.
 */
static int route_policy_materialize_requested_wans(struct json_object *config,
                                                   struct json_object *requested_ids,
                                                   char *error, size_t error_len)
{
    struct json_object *configured_wans = NULL;
    struct json_object *runtime = NULL;
    struct json_object *runtime_wans = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    FILE *fp = NULL;
    int i;
    int rc = -1;

    if (!config || !requested_ids ||
        !json_object_object_get_ex(config, "wans", &configured_wans) ||
        !json_object_is_type(configured_wans, json_type_array)) {
        snprintf(error, error_len, "%s", "route WAN authority is unavailable");
        errno = EIO;
        return -1;
    }
    fp = jmx_fopen_af("jmx_route", "r");
    if (!fp) {
        snprintf(error, error_len, "%s", "kernel WAN readback is unavailable");
        errno = EIO;
        return -1;
    }
    runtime = route_parse_proc_status(fp);
    fclose(fp);
    fp = NULL;
    if (!runtime ||
        !json_object_object_get_ex(runtime, "wans", &runtime_wans) ||
        !json_object_is_type(runtime_wans, json_type_array)) {
        snprintf(error, error_len, "%s", "kernel WAN inventory is unavailable");
        errno = EIO;
        goto out;
    }
    ctx = uci_alloc_context();
    if (ctx && uci_load(ctx, "network", &pkg) != UCI_OK)
        pkg = NULL;

    for (i = 0; i < json_object_array_length(requested_ids); i++) {
        uint8_t id = (uint8_t)json_object_get_int(
            json_object_array_get_idx(requested_ids, i));
        struct json_object *live;
        struct json_object *wan;
        struct uci_section *section;
        const char *name;
        const char *value;
        const char *gateway;
        char ifname[JMX_ROUTE_HEALTH_IFNAME_LEN] = "";

        if (route_policy_find_wan(configured_wans, id))
            continue;
        live = route_policy_find_wan(runtime_wans, id);
        if (!live) {
            snprintf(error, error_len,
                     "requested WAN id %u is not registered in the kernel", id);
            errno = ENODEV;
            goto out;
        }
        name = json_get_str(live, "name", "");
        if (!name[0]) {
            snprintf(error, error_len,
                     "requested WAN id %u has no runtime identity", id);
            errno = EIO;
            goto out;
        }
        section = route_policy_find_network_wan(pkg, name);
        if (route_l3_device_from_ifstatus(name, ifname, sizeof(ifname)) != 0 &&
            section)
            route_health_probe_ifname(section, ifname, sizeof(ifname));

        wan = json_object_new_object();
        if (!wan) {
            errno = ENOMEM;
            goto out;
        }
        json_object_object_add(wan, "id", json_object_new_int(id));
        json_object_object_add(wan, "name", json_object_new_string(name));
        if (ifname[0])
            json_object_object_add(wan, "ifname", json_object_new_string(ifname));
        json_object_object_add(wan, "fwmark", json_object_new_string(
            json_get_str(live, "fwmark", "")));
        json_object_object_add(wan, "table", json_object_new_int(
            (int)json_get_u32(live, "table", 100U + id)));
        gateway = json_get_str(live, "gateway", "");
        if (route_ipv4_from_string(gateway, UINT32_MAX) != UINT32_MAX)
            json_object_object_add(wan, "gateway", json_object_new_string(gateway));
        json_object_object_add(wan, "health", json_object_new_int(
            json_get_u32(live, "health", 1) ? 1 : 0));
        json_object_object_add(wan, "weight", json_object_new_int64(
            (int64_t)json_get_u32(live, "weight", 1)));
        json_object_object_add(wan, "check_enable", json_object_new_int(
            section ? (int)parse_u32_opt(section, "check_enable", 1) : 1));
        json_object_object_add(wan, "failover", json_object_new_int(
            section ? (int)parse_u32_opt(section, "failover", 1) : 1));
        json_object_object_add(wan, "failback", json_object_new_int(
            section ? (int)parse_u32_opt(section, "failback", 1) : 1));
        json_object_object_add(wan, "fail_threshold", json_object_new_int(
            section ? (int)parse_u32_opt(section, "fail_threshold", 2) : 2));
        json_object_object_add(wan, "recover_threshold", json_object_new_int(
            section ? (int)parse_u32_opt(section, "recover_threshold", 6) : 6));
        value = section ? uci_opt(section, "health_mode") : NULL;
        if (value && value[0])
            json_object_object_add(wan, "health_mode", json_object_new_string(value));
        value = section ? uci_opt(section, "check_host") : NULL;
        if (value && value[0])
            json_object_object_add(wan, "check_host", json_object_new_string(value));
        value = section ? uci_opt(section, "check_url") : NULL;
        if (value && value[0])
            json_object_object_add(wan, "check_url", json_object_new_string(value));
        json_object_array_add(configured_wans, wan);
    }
    rc = 0;
out:
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    if (runtime)
        json_object_put(runtime);
    return rc;
}

static int route_policy_runtime_members(const char *ids_text,
                                        const char *weights_text,
                                        uint8_t seen[256],
                                        uint32_t weights[256],
                                        int *count,
                                        int *weights_reported)
{
    char ids_buffer[128];
    char weights_buffer[128];
    char *id_token;
    char *weight_token;
    char *id_save = NULL;
    char *weight_save = NULL;

    if (weights_reported)
        *weights_reported = 0;
    if (!ids_text || !weights_text || !seen || !weights || !count ||
        strlen(ids_text) >= sizeof(ids_buffer) ||
        strlen(weights_text) >= sizeof(weights_buffer))
        return -1;
    memset(seen, 0, 256);
    memset(weights, 0, 256 * sizeof(weights[0]));
    *count = 0;
    snprintf(ids_buffer, sizeof(ids_buffer), "%s", ids_text);
    snprintf(weights_buffer, sizeof(weights_buffer), "%s", weights_text);
    id_token = strtok_r(ids_buffer, ",", &id_save);
    weight_token = strtok_r(weights_buffer, ",", &weight_save);
    while (id_token && weight_token) {
        char *id_end = NULL;
        char *weight_end = NULL;
        unsigned long id;
        unsigned long weight;

        errno = 0;
        id = strtoul(id_token, &id_end, 10);
        if (errno || id_end == id_token || *id_end || id == 0 ||
            id > UINT8_MAX || seen[id])
            return -1;
        errno = 0;
        weight = strtoul(weight_token, &weight_end, 10);
        /*
         * A weight of 0 is how an older kernel that predates per-member
         * weights reports this line: jmx_route's /proc printed only ids, so
         * route_parse_proc_status() fills the parallel weights column with 0.
         * Treat that as "member present, weight not runtime-enforced" instead
         * of a malformed line, and let the caller decide whether the weight
         * ratio can be verified.  A weight-aware kernel always prints >= 1.
         */
        if (errno || weight_end == weight_token || *weight_end ||
            weight > UINT32_MAX)
            return -1;
        if (weight > 0 && weights_reported)
            *weights_reported = 1;
        seen[id] = 1;
        weights[id] = (uint32_t)weight;
        (*count)++;
        id_token = strtok_r(NULL, ",", &id_save);
        weight_token = strtok_r(NULL, ",", &weight_save);
    }
    return *count > 0 && !id_token && !weight_token ? 0 : -1;
}

static uint32_t route_policy_weight_gcd(const uint8_t seen[256],
                                        const uint32_t weights[256])
{
    uint32_t gcd = 0;
    int id;

    for (id = 1; id <= UINT8_MAX; id++) {
        uint32_t a, b;

        if (!seen[id] || !weights[id])
            continue;
        a = gcd;
        b = weights[id];
        while (b) {
            uint32_t remainder = a % b;
            a = b;
            b = remainder;
        }
        gcd = a;
    }
    return gcd ? gcd : 1;
}

static void route_policy_weights_normalize(const uint8_t seen[256],
                                           uint32_t weights[256])
{
    uint32_t gcd = route_policy_weight_gcd(seen, weights);
    int id;

    for (id = 1; id <= UINT8_MAX; id++)
        if (seen[id] && weights[id])
            weights[id] /= gcd;
}

static int route_policy_kernel_readback_matches(struct json_object *config,
                                                int carrier_neutral,
                                                int verify_all_rules,
                                                int *weights_enforced,
                                                char *error, size_t error_len)
{
    struct json_object *rules = NULL;
    struct json_object *runtime = NULL;
    struct json_object *runtime_rules = NULL;
    FILE *fp;
    int i;
    int rc = -1;

    if (weights_enforced)
        *weights_enforced = 1;
    fp = jmx_fopen_af("jmx_route", "r");
    if (!fp) {
        snprintf(error, error_len, "%s", "kernel policy readback is unavailable");
        errno = EIO;
        return -1;
    }
    runtime = route_parse_proc_status(fp);
    fclose(fp);
    if (!runtime || !json_object_object_get_ex(runtime, "rules", &runtime_rules) ||
        !json_object_is_type(runtime_rules, json_type_array) ||
        !json_object_object_get_ex(config, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array)) {
        snprintf(error, error_len, "%s", "kernel policy readback is malformed");
        errno = EIO;
        goto out;
    }
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *actual = NULL;
        struct json_object *ids = NULL;
        struct json_object *members = NULL;
        uint8_t expected_seen[256] = {0};
        uint8_t actual_seen[256] = {0};
        uint32_t expected_weights[256] = {0};
        uint32_t actual_weights[256] = {0};
        int expected_count = 0;
        int actual_count = 0;
        int expected_present;
        uint16_t prio;
        int j;

        if (!verify_all_rules && !route_policy_rule_eligible(rule) &&
            !(carrier_neutral && route_policy_auto_carrier_rule(rule)))
            continue;
        prio = (uint16_t)json_get_u32(rule, "prio", 0);
        expected_present = json_get_u32(rule, "enabled", 1) &&
                           (verify_all_rules || route_policy_rule_eligible(rule));
        for (j = 0; j < json_object_array_length(runtime_rules); j++) {
            struct json_object *candidate = json_object_array_get_idx(runtime_rules, j);

            if ((uint16_t)json_get_u32(candidate, "prio", 0) == prio) {
                actual = candidate;
                break;
            }
        }
        if (!expected_present) {
            if (actual) {
                snprintf(error, error_len,
                         "kernel policy readback retained disabled rule prio=%u", prio);
                errno = EIO;
                goto out;
            }
            continue;
        }
        if (!actual) {
            snprintf(error, error_len,
                     "kernel policy readback missing rule prio=%u", prio);
            errno = EIO;
            goto out;
        }
        {
            uint8_t expected_mode = sticky_mode_from_string(json_get_str(
                rule, "base_mode", json_get_str(
                    rule, "algorithm", json_get_str(rule, "sticky_mode", "hash_src"))));
            int v2_supported = route_kernel_rule_v2_supported(NULL);
            uint32_t expected_enhancements = json_get_u32(
                rule, "adaptive_penalty_sticky", 0) && v2_supported ?
                JMX_ROUTE_ENHANCEMENT_ADAPTIVE_PENALTY : 0;

            if (!v2_supported && json_get_u32(rule, "migration_required", 0) &&
                json_get_u32(rule, "adaptive_penalty_sticky", 0))
                expected_mode = JMX_STICKY_ADAPTIVE_PENALTY;
            if ((uint8_t)json_get_u32(actual, "sticky_mode", UINT8_MAX) !=
                expected_mode) {
                snprintf(error, error_len,
                         "kernel policy mode mismatch at prio=%u", prio);
                errno = EIO;
                goto out;
            }
            if ((uint32_t)json_get_u32(actual, "enhancements", 0) !=
                expected_enhancements) {
                snprintf(error, error_len,
                         "kernel policy enhancement mismatch at prio=%u", prio);
                errno = EIO;
                goto out;
            }
        }
        if ((uint8_t)json_get_u32(actual, "carrier_id", UINT8_MAX) !=
            carrier_from_string(json_get_str(rule, "carrier", "any"))) {
            snprintf(error, error_len,
                     "kernel policy carrier mismatch at prio=%u", prio);
            errno = EIO;
            goto out;
        }
        if (!json_object_object_get_ex(rule, "wan_ids", &ids) ||
            !json_object_is_type(ids, json_type_array)) {
            snprintf(error, error_len,
                     "configured policy members missing at prio=%u", prio);
            errno = EIO;
            goto out;
        }
        for (j = 0; j < json_object_array_length(ids); j++) {
            int id = json_object_get_int(json_object_array_get_idx(ids, j));

            if (id <= 0 || id > UINT8_MAX || expected_seen[id]) {
                snprintf(error, error_len,
                         "configured policy members invalid at prio=%u", prio);
                errno = EIO;
                goto out;
            }
            expected_seen[id] = 1;
            expected_count++;
        }
        if (expected_count == 0 && verify_all_rules &&
            carrier_from_string(json_get_str(rule, "carrier", "any")) !=
                JMX_CARRIER_ANY) {
            if (route_policy_runtime_members(json_get_str(actual, "wan_ids", ""),
                                             json_get_str(actual, "wan_weights", ""),
                                             actual_seen, actual_weights,
                                             &actual_count, NULL) != 0) {
                snprintf(error, error_len,
                         "kernel auto-carrier policy resolved no members at prio=%u",
                         prio);
                errno = EIO;
                goto out;
            }
            continue;
        }
        if (!json_object_object_get_ex(rule, "members", &members) ||
            !json_object_is_type(members, json_type_array) ||
            json_object_array_length(members) != expected_count) {
            snprintf(error, error_len,
                     "configured policy weights missing at prio=%u", prio);
            errno = EIO;
            goto out;
        }
        for (j = 0; j < json_object_array_length(members); j++) {
            struct json_object *member = json_object_array_get_idx(members, j);
            int id = (int)json_get_u32(member, "wan_id", 0);
            uint32_t weight = json_get_u32(member, "weight", 0);

            if (id <= 0 || id > UINT8_MAX || !expected_seen[id] || !weight) {
                snprintf(error, error_len,
                         "configured policy weights invalid at prio=%u", prio);
                errno = EIO;
                goto out;
            }
            expected_weights[id] = weight;
        }
        {
            int rule_weights_reported = 0;

            if (route_policy_runtime_members(json_get_str(actual, "wan_ids", ""),
                                             json_get_str(actual, "wan_weights", ""),
                                             actual_seen, actual_weights,
                                             &actual_count,
                                             &rule_weights_reported) != 0 ||
                actual_count != expected_count ||
                memcmp(actual_seen, expected_seen, sizeof(actual_seen)) != 0) {
                snprintf(error, error_len,
                         "kernel policy member weight mismatch at prio=%u", prio);
                errno = EIO;
                goto out;
            }
            /*
             * The kernel membership (ids) must always agree.  Whether the
             * *ratio* is enforced in the data plane depends on the loaded
             * jmx.ko: a weight-aware module prints per-member weights and we
             * compare the reduced ratio; an older module prints ids only, so
             * weights read back as 0.  In that case the ids are enforced but
             * the ratio is not, and we report weights_enforced=0 to the caller
             * rather than failing an otherwise-correct policy.
             */
            if (rule_weights_reported) {
                route_policy_weights_normalize(expected_seen, expected_weights);
                route_policy_weights_normalize(actual_seen, actual_weights);
                if (memcmp(actual_weights, expected_weights, sizeof(actual_weights)) != 0) {
                    snprintf(error, error_len,
                             "kernel policy member weight mismatch at prio=%u",
                             prio);
                    errno = EIO;
                    goto out;
                }
            } else if (weights_enforced) {
                *weights_enforced = 0;
            }
        }
    }
    rc = 0;
out:
    if (runtime)
        json_object_put(runtime);
    return rc;
}

struct json_object *jmx_api_route_policy_set(struct json_object *req_obj)
{
    struct json_object *config = NULL;
    struct json_object *rules = NULL;
    struct json_object *previous = NULL;
    struct json_object *readback = NULL;
    struct jmx_route_db_tx *tx = NULL;
    struct json_object *mode_obj = NULL;
    struct json_object *base_mode_obj = NULL;
    struct json_object *legacy_mode_obj = NULL;
    struct json_object *requested_ids = NULL;
    struct json_object *requested_members = NULL;
    const char *mode_name = NULL;
    const char *algorithm;
    int enable_adaptive = -1;
    int legacy_adaptive_request = 0;
    char error[160] = "";
    int mode;
    int fd = -1;
    int i;
    int changed = 0;
    int disabled_carrier_rules = 0;
    int carrier_neutral = 0;
    int weights_enforced = 1;

    if (!req_obj || !json_object_is_type(req_obj, json_type_object)) {
        snprintf(error, sizeof(error), "%s", "request must be an object");
        errno = EINVAL;
        goto fail;
    }
    if (json_object_object_get_ex(req_obj, "base_mode", &base_mode_obj)) {
        if (!base_mode_obj || !json_object_is_type(base_mode_obj, json_type_string)) {
            snprintf(error, sizeof(error), "%s", "base_mode must be a string");
            errno = EINVAL;
            goto fail;
        }
        mode_name = json_object_get_string(base_mode_obj);
    }
    if (json_object_object_get_ex(req_obj, "mode", &mode_obj)) {
        int base_id;
        int alias_id;

        legacy_mode_obj = mode_obj;
        if (!mode_obj || !json_object_is_type(mode_obj, json_type_string)) {
            snprintf(error, sizeof(error), "%s", "mode and algorithm must be strings");
            errno = EINVAL;
            goto fail;
        }
        if (!mode_name) {
            mode_name = json_object_get_string(mode_obj);
        } else {
            base_id = sticky_mode_from_string(mode_name);
            alias_id = sticky_mode_from_string(json_object_get_string(mode_obj));
            if (base_id != alias_id) {
                snprintf(error, sizeof(error), "%s",
                         "base_mode_conflict: base_mode, mode, and algorithm must agree");
                errno = EINVAL;
                goto fail;
            }
        }
    }
    if (json_object_object_get_ex(req_obj, "algorithm", &mode_obj)) {
        int base_id;
        int alias_id;

        if (!mode_obj || !json_object_is_type(mode_obj, json_type_string)) {
            snprintf(error, sizeof(error), "%s", "mode and algorithm must be strings");
            errno = EINVAL;
            goto fail;
        }
        if (!mode_name) {
            mode_name = json_object_get_string(mode_obj);
            legacy_mode_obj = mode_obj;
        } else {
            base_id = sticky_mode_from_string(mode_name);
            alias_id = sticky_mode_from_string(json_object_get_string(mode_obj));
            if (base_id != alias_id) {
                snprintf(error, sizeof(error), "%s",
                         "base_mode_conflict: base_mode, mode, and algorithm must agree");
                errno = EINVAL;
                goto fail;
            }
        }
    }
    if (!mode_name || !mode_name[0]) {
        snprintf(error, sizeof(error), "%s", "base_mode is required");
        errno = EINVAL;
        goto fail;
    }
    if (json_object_object_get_ex(req_obj, "enable_adaptive_penalty_sticky", &mode_obj)) {
        if (!mode_obj || !json_object_is_type(mode_obj, json_type_boolean)) {
            snprintf(error, sizeof(error), "%s",
                     "enable_adaptive_penalty_sticky must be boolean");
            errno = EINVAL;
            goto fail;
        }
        enable_adaptive = json_object_get_boolean(mode_obj) ? 1 : 0;
    }
    if (json_object_object_get_ex(req_obj, "carrier_neutral", &mode_obj) && mode_obj &&
        (json_object_is_type(mode_obj, json_type_boolean) ||
         json_object_is_type(mode_obj, json_type_int)))
        carrier_neutral = json_object_get_boolean(mode_obj) ? 1 : 0;
    if (!strcmp(mode_name, "load_balance"))
        mode_name = "new_conn";
    if (!strcmp(mode_name, "adaptive_penalty_sticky")) {
        if (json_has_key(req_obj, "base_mode")) {
            snprintf(error, sizeof(error), "%s",
                     "base_mode_conflict: adaptive_penalty_sticky is an enhancement");
            errno = EINVAL;
            goto fail;
        }
        mode_name = "weighted_new_flow_rr";
        if (enable_adaptive >= 0 && !enable_adaptive) {
            snprintf(error, sizeof(error), "%s",
                     "base_mode_conflict: legacy adaptive mode conflicts with disabled enhancement");
            errno = EINVAL;
            goto fail;
        }
        enable_adaptive = 1;
        legacy_adaptive_request = 1;
    }
    if (base_mode_obj && legacy_mode_obj &&
        sticky_mode_from_string(json_object_get_string(legacy_mode_obj)) ==
            JMX_STICKY_ADAPTIVE_PENALTY) {
        snprintf(error, sizeof(error), "%s",
                 "base_mode_conflict: legacy adaptive mode cannot accompany base_mode");
        errno = EINVAL;
        goto fail;
    }
    mode = sticky_mode_from_string(mode_name);
    if (mode < 0 || mode > JMX_STICKY_MAX || mode == JMX_STICKY_5TUPLE) {
        snprintf(error, sizeof(error), "%s", "unsupported WAN policy mode");
        errno = EOPNOTSUPP;
        goto fail;
    }
    algorithm = sticky_mode_algorithm((uint8_t)mode);
    if (!algorithm) {
        snprintf(error, sizeof(error), "%s", "unsupported WAN policy mode");
        errno = EOPNOTSUPP;
        goto fail;
    }
    if (json_object_object_get_ex(req_obj, "members", &requested_members)) {
        uint8_t seen[JMX_ROUTE_MAX_WAN_IFACES + 1] = {0};
        int count;

        if (!json_object_is_type(requested_members, json_type_array) ||
            (count = json_object_array_length(requested_members)) < 2 ||
            count > JMX_ROUTE_MAX_WAN_IFACES) {
            snprintf(error, sizeof(error), "%s",
                     "members must contain 2 to 8 WAN members");
            errno = EINVAL;
            goto fail;
        }
        requested_ids = json_object_new_array();
        if (!requested_ids) {
            errno = ENOMEM;
            goto fail;
        }
        for (i = 0; i < count; i++) {
            struct json_object *member = json_object_array_get_idx(requested_members, i);
            int id;
            uint32_t weight;

            if (!member || !json_object_is_type(member, json_type_object) ||
                (id = (int)json_get_u32(member, "wan_id", 0)) <= 0 ||
                id > JMX_ROUTE_MAX_WAN_IFACES || seen[id] ||
                json_get_weight(member, "weight", 0, &weight) != 0) {
                snprintf(error, sizeof(error), "%s",
                         "members contains an invalid, duplicate, or unweighted WAN");
                errno = EINVAL;
                goto fail;
            }
            seen[id] = 1;
            json_object_array_add(requested_ids, json_object_new_int(id));
        }
    } else if (json_object_object_get_ex(req_obj, "wan_ids", &requested_ids)) {
        uint8_t seen[JMX_ROUTE_MAX_WAN_IFACES + 1] = {0};
        int count;

        if (!json_object_is_type(requested_ids, json_type_array) ||
            (count = json_object_array_length(requested_ids)) < 2 ||
            count > JMX_ROUTE_MAX_WAN_IFACES) {
            snprintf(error, sizeof(error), "%s", "wan_ids must contain 2 to 8 WAN ids");
            errno = EINVAL;
            goto fail;
        }
        for (i = 0; i < count; i++) {
            struct json_object *value = json_object_array_get_idx(requested_ids, i);
            int id;

            if (!value || !json_object_is_type(value, json_type_int) ||
                (id = json_object_get_int(value)) <= 0 ||
                id > JMX_ROUTE_MAX_WAN_IFACES || seen[id]) {
                snprintf(error, sizeof(error), "%s", "wan_ids contains an invalid or duplicate id");
                errno = EINVAL;
                goto fail;
            }
            seen[id] = 1;
        }
    }
    if (jmx_route_db_config_get(&config) != 0 || !config ||
        !json_object_object_get_ex(config, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array)) {
        snprintf(error, sizeof(error), "%s", "route config is unavailable");
        errno = EIO;
        goto fail;
    }
    if (requested_ids &&
        route_policy_materialize_requested_wans(config, requested_ids,
                                                error, sizeof(error)) != 0)
        goto fail;
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);

        if (carrier_neutral && route_policy_auto_carrier_rule(rule)) {
            if (json_get_u32(rule, "enabled", 1)) {
                json_object_object_del(rule, "enabled");
                json_object_object_add(rule, "enabled", json_object_new_int(0));
                disabled_carrier_rules++;
            }
            continue;
        }
        if (!route_policy_rule_eligible(rule))
            continue;
        if (requested_ids) {
            json_object_object_del(rule, "wan_ids");
            json_object_object_add(rule, "wan_ids", json_object_get(requested_ids));
            json_object_object_del(rule, "members");
            if (requested_members) {
                json_object_object_add(rule, "members",
                                       json_object_get(requested_members));
                json_object_object_del(rule, "member_weights_explicit");
                json_object_object_add(rule, "member_weights_explicit",
                                       json_object_new_int(1));
            } else {
                struct json_object *equal_members = json_object_new_array();
                int member_index;

                if (!equal_members) {
                    errno = ENOMEM;
                    goto fail;
                }
                for (member_index = 0;
                     member_index < json_object_array_length(requested_ids);
                     member_index++) {
                    struct json_object *member = json_object_new_object();
                    int id = json_object_get_int(
                        json_object_array_get_idx(requested_ids, member_index));

                    if (!member) {
                        json_object_put(equal_members);
                        errno = ENOMEM;
                        goto fail;
                    }
                    json_object_object_add(member, "wan_id", json_object_new_int(id));
                    json_object_object_add(member, "weight", json_object_new_int(1));
                    json_object_array_add(equal_members, member);
                }
                json_object_object_add(rule, "members", equal_members);
                json_object_object_del(rule, "member_weights_explicit");
                json_object_object_add(rule, "member_weights_explicit",
                                       json_object_new_int(0));
            }
            json_object_object_del(rule, "wan_selection");
            json_object_object_add(rule, "wan_selection",
                                   json_object_new_string("explicit"));
        }
        json_object_object_del(rule, "sticky_mode");
        json_object_object_del(rule, "algorithm");
        json_object_object_del(rule, "base_mode");
        json_object_object_del(rule, "updated_at");
        json_object_object_add(rule, "sticky_mode", json_object_new_string(algorithm));
        json_object_object_add(rule, "algorithm", json_object_new_string(algorithm));
        json_object_object_add(rule, "base_mode", json_object_new_string(algorithm));
        if (enable_adaptive >= 0) {
            json_object_object_del(rule, "adaptive_penalty_sticky");
            json_object_object_add(rule, "adaptive_penalty_sticky",
                                   json_object_new_boolean(enable_adaptive));
            json_object_object_del(rule, "legacy_mode");
            json_object_object_del(rule, "migration_required");
            if (legacy_adaptive_request) {
                json_object_object_add(rule, "legacy_mode",
                                       json_object_new_string("adaptive_penalty_sticky"));
                json_object_object_add(rule, "migration_required",
                                       json_object_new_boolean(1));
            } else {
                json_object_object_add(rule, "migration_required",
                                       json_object_new_boolean(0));
            }
        } else if (!legacy_adaptive_request) {
            json_object_object_del(rule, "legacy_mode");
            json_object_object_del(rule, "migration_required");
            json_object_object_add(rule, "migration_required",
                                   json_object_new_boolean(0));
        }
        json_object_object_add(rule, "updated_at",
                               json_object_new_int64((int64_t)time(NULL)));
        changed++;
    }
    if (!changed) {
        snprintf(error, sizeof(error), "%s", "no eligible multi-WAN rules found");
        errno = ENOENT;
        goto fail;
    }

    if (jmx_route_db_replace_begin(config, &tx, &previous, &readback,
                                   error, sizeof(error)) != 0)
        goto fail;
    fd = route_open_nl();
    if (fd < 0) {
        snprintf(error, sizeof(error), "%s", "route netlink is unavailable");
        errno = EIO;
        goto rollback;
    }
    rules = NULL;
    json_object_object_get_ex(readback, "rules", &rules);
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        if (!route_policy_rule_eligible(rule) &&
            !(carrier_neutral && route_policy_auto_carrier_rule(rule)))
            continue;
        if (route_policy_reconcile_rule(fd, rule) != 0) {
            snprintf(error, sizeof(error), "%s", "runtime policy apply failed");
            errno = EIO;
            goto rollback;
        }
    }
    close(fd);
    fd = -1;
    if (route_policy_kernel_readback_matches(readback, carrier_neutral, 0,
                                             &weights_enforced,
                                             error, sizeof(error)) != 0)
        goto rollback;
    if (jmx_route_db_replace_commit(tx) != 0) {
        tx = NULL;
        snprintf(error, sizeof(error), "%s", "config.db commit failed");
        errno = EIO;
        if (previous) {
            struct json_object *old_rules = NULL;
            fd = route_open_nl();
            if (fd >= 0 && json_object_object_get_ex(previous, "rules", &old_rules)) {
                for (i = 0; i < json_object_array_length(old_rules); i++) {
                    struct json_object *rule = json_object_array_get_idx(old_rules, i);
                    if (route_policy_rule_eligible(rule) ||
                        (carrier_neutral && route_policy_auto_carrier_rule(rule)))
                        (void)route_policy_reconcile_rule(fd, rule);
                }
            }
            if (fd >= 0) close(fd);
            fd = -1;
        }
        goto fail;
    }
    tx = NULL;
    json_object_object_add(readback, "ok", json_object_new_boolean(1));
    json_object_object_add(readback, "runtime_applied", json_object_new_boolean(1));
    json_object_object_add(readback, "apply_disruption",
                           json_object_new_string("new_connections_only"));
    json_object_object_add(readback, "selected_mode",
                           json_object_new_string(algorithm));
    json_object_object_add(readback, "updated_rule_count",
                           json_object_new_int(changed));
    json_object_object_add(readback, "disabled_carrier_rule_count",
                           json_object_new_int(disabled_carrier_rules));
    json_object_object_add(readback, "carrier_neutral",
                           json_object_new_boolean(carrier_neutral));
    json_object_object_add(readback, "weight_runtime_enforced",
                           json_object_new_boolean(weights_enforced));
    json_object_object_add(readback, "weight_runtime_reason",
                           json_object_new_string(weights_enforced ?
                               "kernel_reports_per_member_weights" :
                               "kernel_module_ids_only_weight_ratio_configured_not_enforced"));
    if (config) json_object_put(config);
    if (previous) json_object_put(previous);
    if (requested_members && requested_ids)
        json_object_put(requested_ids);
    return route_json_ok(readback);

rollback:
    if (fd >= 0) close(fd);
    if (tx) {
        jmx_route_db_replace_rollback(tx);
        tx = NULL;
    }
    /* Restore only the rules touched by this operation. */
    if (previous) {
        struct json_object *old_rules = NULL;
        fd = route_open_nl();
        if (fd >= 0 && json_object_object_get_ex(previous, "rules", &old_rules)) {
            for (i = 0; i < json_object_array_length(old_rules); i++) {
                struct json_object *rule = json_object_array_get_idx(old_rules, i);
                if (route_policy_rule_eligible(rule) ||
                    (carrier_neutral && route_policy_auto_carrier_rule(rule)))
                    (void)route_policy_reconcile_rule(fd, rule);
            }
        }
        if (fd >= 0) close(fd);
    }
fail:
    if (fd >= 0) close(fd);
    if (tx) jmx_route_db_replace_rollback(tx);
    if (config) json_object_put(config);
    if (previous) json_object_put(previous);
    if (readback) json_object_put(readback);
    if (requested_members && requested_ids)
        json_object_put(requested_ids);
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string(
            error[0] ? error : strerror(errno ? errno : EIO)));
        json_object_object_add(data, "runtime_applied", json_object_new_boolean(0));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
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
        json_object_object_add(data, "counter_source", json_object_new_string("unavailable"));
        json_object_object_add(data, "counter_reason", json_object_new_string("jmx_route_proc_missing"));
        route_enrich_status(data);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }

    struct json_object *data = route_parse_proc_status(fp);
    fclose(fp);
    route_enrich_status(data);
    return route_json_ok(data);
}

static struct json_object *route_sla_response(struct json_object *data, int ok)
{
    json_object_object_add(data, "ok", json_object_new_boolean(ok));
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *route_sla_field(struct json_object *obj,
                                            const char *key)
{
    struct json_object *value = NULL;

    if (obj)
        json_object_object_get_ex(obj, key, &value);
    return value;
}

static struct json_object *route_sla_status_snapshot(void)
{
    FILE *fp = jmx_fopen_af("jmx_route", "r");
    struct json_object *status;

    if (!fp)
        return NULL;
    status = route_parse_proc_status(fp);
    fclose(fp);
    return status;
}

static struct json_object *route_sla_wan(struct json_object *status,
                                         const char *name)
{
    struct json_object *wans = NULL;
    int i;

    if (!status || !json_object_object_get_ex(status, "wans", &wans) ||
        !json_object_is_type(wans, json_type_array))
        return NULL;
    for (i = 0; i < (int)json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);

        if (!strcmp(json_get_str(wan, "name", ""), name))
            return wan;
    }
    return NULL;
}

static int route_sla_alternatives(struct json_object *status, int target_id)
{
    struct json_object *wans = NULL;
    int i, count = 0;

    if (!status || !json_object_object_get_ex(status, "wans", &wans) ||
        !json_object_is_type(wans, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);

        if ((int)json_get_u32(wan, "id", 0) != target_id &&
            json_get_u32(wan, "health", 0))
            count++;
    }
    return count;
}

static int route_sla_level_for_weight(int weight, int health)
{
    if (!health || weight <= 1)
        return 3;
    if (weight <= 25)
        return 2;
    if (weight <= 70)
        return 1;
    return 0;
}

static int route_sla_rule_has_wan(const char *members, int target_id)
{
    const char *p = members;

    while (p && *p) {
        char *end = NULL;
        long id = strtol(p, &end, 10);

        if (end == p)
            return 0;
        if (id == target_id)
            return 1;
        p = *end == ',' ? end + 1 : NULL;
    }
    return 0;
}

static struct json_object *route_sla_affected_groups(struct json_object *status,
                                                      int target_id)
{
    struct json_object *out = json_object_new_array();
    struct json_object *rules = NULL;
    int i;

    if (!status || !json_object_object_get_ex(status, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array))
        return out;
    for (i = 0; i < (int)json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        const char *members = json_get_str(rule, "wan_ids", "");

        if (route_sla_rule_has_wan(members, target_id)) {
            struct json_object *item = json_object_new_object();

            json_object_object_add(item, "prio",
                                   json_object_new_int((int)json_get_u32(rule, "prio", 0)));
            json_object_array_add(out, item);
        }
    }
    return out;
}

static const char *route_sla_transition_event(struct json_object *request)
{
    const char *state = json_get_str(request, "stable_state", "unknown");

    if (!strcmp(json_get_str(request, "state", state), "recovering"))
        return "wan.sla.recovering";
    if (!strcmp(state, "healthy"))
        return "wan.sla.recovered";
    if (!strcmp(state, "degraded"))
        return "wan.sla.degraded";
    if (!strcmp(state, "critical"))
        return "wan.sla.critical";
    if (!strcmp(state, "down"))
        return "wan.sla.down";
    return NULL;
}

static void route_sla_event_emit(struct json_object *request,
                                 struct json_object *action,
                                 const char *event)
{
    struct json_object *body, *detail, *resp;
    const char *sla_id = json_get_str(request, "sla_id", "unknown");
    const char *decision = json_get_str(request, "decision_id", "unknown");
    const char *wan = json_get_str(request, "wan_id", "");
    char id[256], dedupe[160];

    if (!event)
        return;
    body = json_object_new_object();
    detail = json_object_new_object();
    if (!body || !detail) {
        if (body) json_object_put(body);
        if (detail) json_object_put(detail);
        return;
    }
    snprintf(id, sizeof(id), "%s:%s", event, decision);
    snprintf(dedupe, sizeof(dedupe), "wan_sla:%s", sla_id);
    json_object_object_add(detail, "sla_id", json_object_new_string(sla_id));
    json_object_object_add(detail, "sla_revision",
                           json_object_new_int64(route_obj_i64(request, "sla_revision", 0)));
    json_object_object_add(detail, "wan_id", json_object_new_string(wan));
    json_object_object_add(detail, "decision_id", json_object_new_string(decision));
    json_object_object_add(detail, "stable_state",
                           json_object_new_string(json_get_str(request, "stable_state", "unknown")));
    json_object_object_add(detail, "requested_level",
                           json_object_new_int((int)json_get_u32(request, "requested_level", 0)));
    json_object_object_add(detail, "reasons",
                           json_object_get(route_sla_field(request, "reasons")));
    json_object_object_add(detail, "evidence_window",
                           json_object_get(route_sla_field(request, "evidence_window")));
    json_object_object_add(detail, "route_action", json_object_get(action));
    json_object_object_add(body, "id", json_object_new_string(id));
    json_object_object_add(body, "type", json_object_new_string("system"));
    json_object_object_add(body, "level", json_object_new_string(
        strstr(event, "failed") || strstr(event, "down") ? "critical" : "warning"));
    json_object_object_add(body, "category", json_object_new_string("network.wan"));
    json_object_object_add(body, "module", json_object_new_string("dreamingwrt-routed"));
    json_object_object_add(body, "source", json_object_new_string("routed.wan_sla"));
    json_object_object_add(body, "wan_id", json_object_new_string(wan));
    json_object_object_add(body, "event", json_object_new_string(event));
    json_object_object_add(body, "title", json_object_new_string(event));
    json_object_object_add(body, "detail_json", detail);
    json_object_object_add(body, "dedupe_key", json_object_new_string(dedupe));
    json_object_object_add(body, "state",
                           json_object_new_string(json_get_str(request, "stable_state", "unknown")));
    json_object_object_add(body, "target", json_object_new_string(sla_id));
    json_object_object_add(body, "ts",
                           json_object_new_int64(route_obj_i64(request, "evaluated_at", time(NULL))));
    resp = jmx_log_center_event_add(body);
    if (resp)
        json_object_put(resp);
    json_object_put(body);
}

struct json_object *jmx_api_route_sla_apply(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    struct json_object *config = NULL, *before = NULL, *after = NULL;
    struct json_object *before_wan, *after_wan, *affected;
    struct route_health_state *state;
    sqlite3 *db = NULL;
    const char *sla_id = json_get_str(req_obj, "sla_id", "");
    const char *wan_name = json_get_str(req_obj, "wan_id", "");
    const char *decision = json_get_str(req_obj, "decision_id", "");
    const char *event;
    char reason[96] = "";
    int target_id, alternatives, verdict, level, previous_level;
    int previous_weight, new_weight, health, rebind_mode, expected_rebind;
    int fd, rc, readback_ok;

    json_object_object_add(data, "decision_id", json_object_new_string(decision));
    json_object_object_add(data, "sla_id", json_object_new_string(sla_id));
    json_object_object_add(data, "wan_id", json_object_new_string(wan_name));
    if (!sla_id[0] || sqlite3_open_v2(JMX_ROUTE_DB_PATH, &db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        json_object_object_add(data, "error", json_object_new_string("config_unavailable"));
        if (db) sqlite3_close(db);
        return route_sla_response(data, 0);
    }
    sqlite3_busy_timeout(db, 100);
    config = wan_sla_config_load(db, sla_id);
    sqlite3_close(db);
    if (!config) {
        json_object_object_add(data, "error", json_object_new_string("sla_not_found"));
        return route_sla_response(data, 0);
    }
    before = route_sla_status_snapshot();
    before_wan = route_sla_wan(before, wan_name);
    if (!before_wan) {
        json_object_put(config);
        if (before) json_object_put(before);
        json_object_object_add(data, "error", json_object_new_string("wan_not_registered"));
        return route_sla_response(data, 0);
    }
    target_id = (int)json_get_u32(before_wan, "id", 0);
    alternatives = route_sla_alternatives(before, target_id);
    affected = route_sla_affected_groups(before, target_id);
    verdict = wan_sla_route_guard_validate(req_obj, config, time(NULL), alternatives,
                                           reason, sizeof(reason));
    json_object_put(config);
    previous_weight = (int)json_get_u32(before_wan, "adaptive_weight", 100);
    health = (int)json_get_u32(before_wan, "health", 1);
    previous_level = route_sla_level_for_weight(previous_weight, health);
    json_object_object_add(data, "previous_weight", json_object_new_int(previous_weight));
    json_object_object_add(data, "eligible_alternatives", json_object_new_int(alternatives));
    if (verdict == WAN_SLA_ROUTE_REJECT) {
        json_object_put(before);
        json_object_object_add(data, "error", json_object_new_string(reason));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "affected_policy_groups", affected);
        return route_sla_response(data, 0);
    }
    if (verdict == WAN_SLA_ROUTE_SUPPRESS) {
        json_object_put(before);
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "suppressed_reason", json_object_new_string(reason));
        json_object_object_add(data, "new_weight", json_object_new_int(previous_weight));
        json_object_object_add(data, "health", json_object_new_boolean(health));
        json_object_object_add(data, "applied_level", json_object_new_int(previous_level));
        json_object_object_add(data, "rebind_mode", json_object_new_int(0));
        json_object_object_add(data, "readback_ok", json_object_new_boolean(1));
        json_object_object_add(data, "affected_policy_groups", affected);
        route_sla_event_emit(req_obj, data, "wan.sla.action_suppressed");
        return route_sla_response(data, 1);
    }

    level = (int)json_get_u32(req_obj, "requested_level", 0);
    expected_rebind = level > previous_level ?
        (level >= 3 ? JMX_ROUTE_REBIND_ALL : level >= 2 ? JMX_ROUTE_REBIND_SELECTIVE : 0) : 0;
    state = route_health_state_get((uint8_t)target_id);
    if (!state) {
        json_object_put(before);
        json_object_object_add(data, "error", json_object_new_string("route_state_unavailable"));
        json_object_object_add(data, "affected_policy_groups", affected);
        return route_sla_response(data, 0);
    }
    snprintf(state->name, sizeof(state->name), "%s", wan_name);
    snprintf(state->reason, sizeof(state->reason), "wan_sla:%s", sla_id);
    state->initialized = 1;
    state->quality_level = (uint8_t)previous_level;
    state->adaptive_weight = (uint8_t)previous_weight;
    state->healthy = health != 0;
    state->last_probe = (time_t)route_obj_i64(req_obj, "evaluated_at", time(NULL));
    state->last_rebind_mode = 0;
    fd = route_open_nl();
    rc = fd < 0 ? -1 : route_health_apply_level(fd, state, (uint8_t)level, 0);
    if (fd >= 0)
        close(fd);
    after = route_sla_status_snapshot();
    after_wan = route_sla_wan(after, wan_name);
    new_weight = after_wan ? (int)json_get_u32(after_wan, "adaptive_weight", 0) : 0;
    health = after_wan ? (int)json_get_u32(after_wan, "health", 0) : 0;
    rebind_mode = after_wan ? (int)json_get_u32(after_wan, "rebind_last_mode", 0) : 0;
    readback_ok = rc == 0 && after_wan &&
        new_weight == route_health_weight_for((uint8_t)level) && health == (level < 3) &&
        (!expected_rebind || rebind_mode == expected_rebind);
    json_object_put(before);
    if (after) json_object_put(after);
    json_object_object_add(data, "applied", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "new_weight", json_object_new_int(new_weight));
    json_object_object_add(data, "health", json_object_new_boolean(health));
    json_object_object_add(data, "rebind_mode", json_object_new_int(rebind_mode));
    json_object_object_add(data, "applied_level",
                           json_object_new_int(route_sla_level_for_weight(new_weight, health)));
    json_object_object_add(data, "readback_ok", json_object_new_boolean(readback_ok));
    json_object_object_add(data, "affected_policy_groups", affected);
    if (!readback_ok) {
        json_object_object_add(data, "error", json_object_new_string(
            rc ? "route_action_failed" : "route_readback_mismatch"));
        route_sla_event_emit(req_obj, data, "wan.sla.route_action_failed");
        return route_sla_response(data, 0);
    }
    if (json_get_u32(req_obj, "transition", 0)) {
        event = route_sla_transition_event(req_obj);
        route_sla_event_emit(req_obj, data, event);
    }
    return route_sla_response(data, 1);
}

int jmx_route_counter_tick(void)
{
    FILE *fp = jmx_fopen_af("jmx_route", "r");
    struct json_object *data;
    int rc = -1;

    if (!fp) {
        (void)route_state_db_init(NULL);
        return -1;
    }
    data = route_parse_proc_status(fp);
    fclose(fp);
    if (data) {
        /* Periodic tick must stay off the shared SQLite read path: the WAN
         * runtime enrichment below queries the main DB once per WAN and can
         * block for the whole busy timeout when healthd/webd hold a write
         * lock.  route_status (the actual API) still does the full enrich;
         * the 3-second tick only needs the CPU-only rule identity so the
         * counter state table can be persisted. */
        route_enrich_rules(data);
        rc = route_state_persist_rule_counters(data) >= 0 ? 0 : -1;
        json_object_put(data);
    }
    return rc;
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

static uint32_t parse_weight_opt(struct uci_section *s, uint32_t def)
{
    const char *v = uci_opt(s, "weight");
    char *end = NULL;
    unsigned long long n;

    if (!v || !v[0])
        return def;
    if (*v == '-')
        return 0;
    errno = 0;
    n = strtoull(v, &end, 0);
    if (errno || end == v || *end != '\0' || !n || n > UINT32_MAX)
        return 0;
    return (uint32_t)n;
}

static uint8_t sticky_mode_from_string(const char *s)
{
    char *end = NULL;
    unsigned long n;

    if (!s || !s[0]) return JMX_STICKY_SIP;
    if (!strcmp(s, "new_conn") || !strcmp(s, "weighted_new_flow_rr")) return JMX_STICKY_NEW_CONN;
    if (!strcmp(s, "sip") || !strcmp(s, "hash_src")) return JMX_STICKY_SIP;
    if (!strcmp(s, "sip_sport") || !strcmp(s, "sip+sport") || !strcmp(s, "hash_src_sport")) return JMX_STICKY_SIP_SPORT;
    if (!strcmp(s, "sip_dip") || !strcmp(s, "sip+dip") || !strcmp(s, "hash_src_dst")) return JMX_STICKY_SIP_DIP;
    if (!strcmp(s, "sip_dip_dport") || !strcmp(s, "sip+dip+dport") || !strcmp(s, "hash_src_dst_dport")) return JMX_STICKY_SIP_DIP_DPORT;
    if (!strcmp(s, "5tuple") || !strcmp(s, "five_tuple")) return JMX_STICKY_5TUPLE;
    if (!strcmp(s, "primary_backup") || !strcmp(s, "primary-backup")) return JMX_STICKY_PRIMARY_BACKUP;
    if (!strcmp(s, "download") || !strcmp(s, "least_rx_load_normalized")) return JMX_STICKY_DOWNLOAD;
    if (!strcmp(s, "conn_cnt") || !strcmp(s, "conn-count") ||
        !strcmp(s, "connection_count") || !strcmp(s, "least_active_conn_normalized"))
        return JMX_STICKY_CONN_CNT;
    if (!strcmp(s, "adaptive_penalty_sticky") ||
        !strcmp(s, "adaptive-penalty-sticky"))
        return JMX_STICKY_ADAPTIVE_PENALTY;
    errno = 0;
    n = strtoul(s, &end, 0);
    if (errno || end == s || *end || n > JMX_STICKY_MAX)
        return UINT8_MAX;
    return (uint8_t)n;
}

static const char *sticky_mode_algorithm(uint8_t mode)
{
    switch (mode) {
    case JMX_STICKY_NEW_CONN: return "weighted_new_flow_rr";
    case JMX_STICKY_SIP: return "hash_src";
    case JMX_STICKY_SIP_SPORT: return "hash_src_sport";
    case JMX_STICKY_SIP_DIP: return "hash_src_dst";
    case JMX_STICKY_SIP_DIP_DPORT: return "hash_src_dst_dport";
    case JMX_STICKY_5TUPLE: return "five_tuple";
    case JMX_STICKY_PRIMARY_BACKUP: return "primary_backup";
    case JMX_STICKY_DOWNLOAD: return "least_rx_load_normalized";
    case JMX_STICKY_CONN_CNT: return "least_active_conn_normalized";
    case JMX_STICKY_ADAPTIVE_PENALTY: return "adaptive_penalty_sticky";
    default: return "unsupported";
    }
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

static void route_adv_trim_copy(char *out, size_t out_len, const char *in)
{
    const char *start = in;
    const char *end;
    size_t len;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    while (*start && isspace((unsigned char)*start))
        start++;
    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
        end--;
    len = (size_t)(end - start);
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, start, len);
    out[len] = '\0';
}

static int route_adv_is_any(const char *s)
{
    char buf[64];

    route_adv_trim_copy(buf, sizeof(buf), s);
    return !buf[0] || !strcasecmp(buf, "any") || !strcasecmp(buf, "all") ||
           !strcmp(buf, "*") || !strcmp(buf, "0");
}

static int route_adv_parse_single_port(const char *s, uint16_t *port)
{
    char buf[64];
    char *p = buf;
    char *end = NULL;
    unsigned long n;

    if (!port)
        return -1;
    *port = 0;
    if (route_adv_is_any(s))
        return 0;
    route_adv_trim_copy(buf, sizeof(buf), s);
    if (!strcasecmp(buf, "http"))
        snprintf(buf, sizeof(buf), "%s", "80");
    else if (!strcasecmp(buf, "https") || !strcasecmp(buf, "quic"))
        snprintf(buf, sizeof(buf), "%s", "443");
    else if (!strcasecmp(buf, "dns"))
        snprintf(buf, sizeof(buf), "%s", "53");
    if (buf[0] == '{') {
        size_t len = strlen(buf);

        if (len < 2 || buf[len - 1] != '}')
            return -1;
        buf[len - 1] = '\0';
        p = buf + 1;
        while (*p && isspace((unsigned char)*p))
            p++;
    }
    n = strtoul(p, &end, 10);
    if (end == p || n == 0 || n > 65535)
        return -1;
    while (*end && isspace((unsigned char)*end))
        end++;
    if (*end && *end != '}')
        return -1;
    *port = (uint16_t)n;
    return 0;
}

static int route_adv_parse_proto(const char *s, uint8_t *proto)
{
    char buf[32];
    char *end = NULL;
    unsigned long n;

    if (!proto)
        return -1;
    *proto = 0;
    route_adv_trim_copy(buf, sizeof(buf), s);
    if (!buf[0] || !strcasecmp(buf, "any") || !strcasecmp(buf, "all") ||
        !strcmp(buf, "*"))
        return 0;
    if (!strcasecmp(buf, "tcp_udp") || !strcasecmp(buf, "tcp/udp") ||
        !strcasecmp(buf, "tcp,udp"))
        return 0;
    if (!strcasecmp(buf, "tcp")) {
        *proto = 6;
        return 0;
    }
    if (!strcasecmp(buf, "udp")) {
        *proto = 17;
        return 0;
    }
    if (!strcasecmp(buf, "icmp")) {
        *proto = 1;
        return 0;
    }
    n = strtoul(buf, &end, 10);
    if (end == buf || *end || n > 255)
        return -1;
    *proto = (uint8_t)n;
    return 0;
}

static int route_adv_direct_cidr(const char *s, uint32_t *addr, uint32_t *mask)
{
    char buf[128];

    if (route_adv_is_any(s)) {
        if (addr)
            *addr = 0;
        if (mask)
            *mask = 0;
        return 0;
    }
    route_adv_trim_copy(buf, sizeof(buf), s);
    if (!strncasecmp(buf, "IP:", 3))
        memmove(buf, buf + 3, strlen(buf + 3) + 1);
    if (!strncasecmp(buf, "CIDR:", 5))
        memmove(buf, buf + 5, strlen(buf + 5) + 1);
    if (!strncasecmp(buf, "NET:", 4))
        memmove(buf, buf + 4, strlen(buf + 4) + 1);
    if (!strncasecmp(buf, "地址:", 7))
        memmove(buf, buf + 7, strlen(buf + 7) + 1);
    {
        char trimmed[128];

        route_adv_trim_copy(trimmed, sizeof(trimmed), buf);
        snprintf(buf, sizeof(buf), "%s", trimmed);
    }
    if (!strcasecmp(buf, "lan") || !strcasecmp(buf, "br-lan") ||
        !strcasecmp(buf, "local") || !strcasecmp(buf, "internal")) {
        snprintf(buf, sizeof(buf), "%s", "192.168.0.0/16");
    }
    if (strchr(buf, ',') || strchr(buf, ';') || strchr(buf, '-') ||
        strchr(buf, ':') || strchr(buf, ' '))
        return -1;
    return parse_cidr(buf, addr, mask);
}

static int route_adv_db_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!db || !name || !name[0])
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?1 LIMIT 1",
        -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

static int route_adv_resolve_object_cidr(sqlite3 *db, const char *ref,
                                         uint32_t *addr, uint32_t *mask)
{
    sqlite3_stmt *st = NULL;
    char key[128];
    int rows = 0;
    int parsed = 0;
    int bad = 0;
    uint32_t one_addr = 0, one_mask = 0;

    if (!addr || !mask)
        return -1;
    *addr = 0;
    *mask = 0;
    route_adv_trim_copy(key, sizeof(key), ref);
    if (!key[0])
        return 0;
    if (route_adv_direct_cidr(key, addr, mask) == 0)
        return 0;
    if (!db || !route_adv_db_table_exists(db, "route_object") ||
        !route_adv_db_table_exists(db, "route_object_member"))
        return -1;
    if (sqlite3_prepare_v2(db,
        "SELECT value FROM route_object WHERE id=?1 AND enabled=1 AND value<>'' "
        "UNION ALL "
        "SELECT m.value FROM route_object_member m "
        "JOIN route_object o ON o.id=m.object_id "
        "WHERE o.id=?1 AND o.enabled=1 AND m.value<>'' "
        "ORDER BY value",
        -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *v = (const char *)sqlite3_column_text(st, 0);
        uint32_t a = 0, m = 0;

        rows++;
        if (!v || route_adv_direct_cidr(v, &a, &m) != 0) {
            bad++;
            continue;
        }
        one_addr = a;
        one_mask = m;
        parsed++;
    }
    sqlite3_finalize(st);
    if (rows <= 0 || bad || parsed != 1)
        return -1;
    *addr = one_addr;
    *mask = one_mask;
    return 0;
}

static int route_adv_lookup_table(sqlite3 *db, const char *token, uint32_t *table_id,
                                  char *id, size_t id_len, char *name, size_t name_len,
                                  char *role, size_t role_len)
{
    sqlite3_stmt *st = NULL;
    char key[128];
    char *end = NULL;
    long numeric = -1;
    int rows = 0;
    int rc;

    if (table_id)
        *table_id = 0;
    if (id && id_len > 0)
        id[0] = '\0';
    if (name && name_len > 0)
        name[0] = '\0';
    if (role && role_len > 0)
        role[0] = '\0';
    if (!db || !token || !token[0] || !route_adv_db_table_exists(db, "route_table"))
        return 0;
    route_adv_trim_copy(key, sizeof(key), token);
    if (!key[0] || !strcasecmp(key, "main") || !strcasecmp(key, "default") ||
        !strcasecmp(key, "local"))
        return 0;
    numeric = strtol(key, &end, 10);
    if (end == key || *end)
        numeric = -1;
    rc = sqlite3_prepare_v2(db,
        "SELECT id,name,table_id,role FROM route_table "
        "WHERE enabled=1 AND (id=?1 OR name=?1 OR role=?1 OR table_id=?2) "
        "ORDER BY table_id LIMIT 2",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, numeric >= 0 ? (int)numeric : -1);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *sid = (const char *)sqlite3_column_text(st, 0);
        const char *sname = (const char *)sqlite3_column_text(st, 1);
        const char *srole = (const char *)sqlite3_column_text(st, 3);

        rows++;
        if (rows == 1) {
            if (id && id_len > 0)
                snprintf(id, id_len, "%s", sid ? sid : "");
            if (name && name_len > 0)
                snprintf(name, name_len, "%s", sname ? sname : "");
            if (role && role_len > 0)
                snprintf(role, role_len, "%s", srole ? srole : "");
            if (table_id)
                *table_id = (uint32_t)sqlite3_column_int(st, 2);
        }
    }
    sqlite3_finalize(st);
    if (rows > 1)
        return -1;
    return rows == 1 ? 1 : 0;
}

static uint8_t route_adv_target_one_wan(sqlite3 *db, const struct route_sync_wan_map *map,
                                        int map_count, const char *target)
{
    char key[128];
    uint32_t table_id = 0;
    char table_id_name[64] = "";
    char table_name[64] = "";
    char table_role[64] = "";
    uint8_t id;
    int rc;
    char *end = NULL;
    unsigned long numeric;

    route_adv_trim_copy(key, sizeof(key), target);
    if (!key[0] || !strcasecmp(key, "main") || !strcasecmp(key, "default") ||
        !strcasecmp(key, "local"))
        return 0;
    if (!strncmp(key, "dwrt_", 5))
        memmove(key, key + 5, strlen(key + 5) + 1);
    id = route_sync_wan_id_by_name(map, map_count, key);
    if (id)
        return id;
    numeric = strtoul(key, &end, 10);
    if (end != key && !*end) {
        id = route_sync_wan_id_by_table(map, map_count, (uint32_t)numeric);
        if (id)
            return id;
    }
    rc = route_adv_lookup_table(db, key, &table_id, table_id_name, sizeof(table_id_name),
                                table_name, sizeof(table_name), table_role, sizeof(table_role));
    if (rc <= 0)
        return 0;
    id = route_sync_wan_id_by_table(map, map_count, table_id);
    if (id)
        return id;
    id = route_sync_wan_id_by_name(map, map_count, table_id_name);
    if (id)
        return id;
    id = route_sync_wan_id_by_name(map, map_count, table_name);
    if (id)
        return id;
    return route_sync_wan_id_by_name(map, map_count, table_role);
}

static int route_adv_add_wan_target(sqlite3 *db, const struct route_sync_wan_map *map,
                                    int map_count, const char *target,
                                    struct jmx_route_rule_wire *r)
{
    char buf[256];
    char *save = NULL;
    char *tok;
    int added = 0;

    if (!r)
        return -1;
    route_adv_trim_copy(buf, sizeof(buf), target);
    if (!buf[0])
        return -1;
    for (tok = strtok_r(buf, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        uint8_t id = route_adv_target_one_wan(db, map, map_count, tok);
        int exists = 0;
        int i;

        if (!id)
            continue;
        for (i = 0; i < r->wan_count; i++) {
            if (r->wan_ids[i] == id) {
                exists = 1;
                break;
            }
        }
        if (exists)
            continue;
        if (r->wan_count >= JMX_ROUTE_MAX_WAN_IFACES)
            return -1;
        r->wan_ids[r->wan_count++] = id;
        added++;
    }
    return added > 0 ? 0 : -1;
}

static void route_adv_sync_state_write(const struct route_adv_sync_stats *st,
                                       int wan_map_count)
{
    struct json_object *o = json_object_new_object();
    FILE *fp;

    if (!o)
        return;
    json_object_object_add(o, "ts", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(o, "source", json_object_new_string("config.db"));
    json_object_object_add(o, "mode", json_object_new_string("conservative_safe_subset"));
    json_object_object_add(o, "wan_map_count", json_object_new_int(wan_map_count));
    json_object_object_add(o, "checked", json_object_new_int(st ? st->checked : 0));
    json_object_object_add(o, "synced", json_object_new_int(st ? st->synced : 0));
    json_object_object_add(o, "skipped", json_object_new_int(st ? st->skipped : 0));
    json_object_object_add(o, "errors", json_object_new_int(st ? st->errors : 0));
    json_object_object_add(o, "db_policy_rules", json_object_new_int(st ? st->db_policy_rules : 0));
    json_object_object_add(o, "legacy_policy_rules", json_object_new_int(st ? st->legacy_policy_rules : 0));
    json_object_object_add(o, "supports", json_object_new_string(
        "single IPv4/CIDR source/destination, single dst port, tcp/udp/icmp/all, target mapped to registered WAN"));
    fp = fopen(JMX_ROUTE_ADV_SYNC_STATE, "w");
    if (fp) {
        fputs(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN), fp);
        fputc('\n', fp);
        fclose(fp);
    }
    json_object_put(o);
}

static int route_adv_sync_policy_rows(sqlite3 *db, int fd,
                                      const struct route_sync_wan_map *map,
                                      int map_count,
                                      struct route_adv_sync_stats *stats,
                                      int *sync_errors)
{
    sqlite3_stmt *st = NULL;
    int synced = 0;

    if (!db || !map || map_count <= 0 ||
        !route_adv_db_table_exists(db, "policy_route_rule"))
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT id,priority,source_object,dest_object,proto,ports,action,target,route_table,sticky "
        "FROM policy_route_rule WHERE enabled=1 ORDER BY priority,id",
        -1, &st, NULL) != SQLITE_OK) {
        if (stats)
            stats->errors++;
        if (sync_errors)
            (*sync_errors)++;
        return 0;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        int priority = sqlite3_column_int(st, 1);
        const char *src = (const char *)sqlite3_column_text(st, 2);
        const char *dst = (const char *)sqlite3_column_text(st, 3);
        const char *proto = (const char *)sqlite3_column_text(st, 4);
        const char *ports = (const char *)sqlite3_column_text(st, 5);
        const char *action = (const char *)sqlite3_column_text(st, 6);
        const char *target = (const char *)sqlite3_column_text(st, 7);
        const char *route_table = (const char *)sqlite3_column_text(st, 8);
        int sticky = sqlite3_column_int(st, 9);
        const char *target_token = (route_table && route_table[0]) ? route_table : target;
        struct jmx_route_rule_wire r;
        uint16_t dst_port = 0;
        uint8_t proto_id = 0;

        if (stats) {
            stats->checked++;
            stats->db_policy_rules++;
        }
        if (!action || (!strcasecmp(action, "drop") || !strcasecmp(action, "main") ||
                        !strcasecmp(action, "mark"))) {
            if (stats) stats->skipped++;
            continue;
        }
        if (strcasecmp(action, "route_table") && strcasecmp(action, "route_group") &&
            strcasecmp(action, "lookup") && strcasecmp(action, "route")) {
            if (stats) stats->skipped++;
            continue;
        }
        if (priority <= 0 || priority > 65535) {
            if (stats) stats->skipped++;
            continue;
        }
        memset(&r, 0, sizeof(r));
        r.enabled = 1;
        r.prio = (uint16_t)priority;
        r.sticky_mode = sticky ? JMX_STICKY_SIP : JMX_STICKY_NEW_CONN;
        {
            uint32_t src_addr = 0, src_mask = 0, dst_addr = 0, dst_mask = 0;

            if (route_adv_resolve_object_cidr(db, src, &src_addr, &src_mask) != 0 ||
                route_adv_resolve_object_cidr(db, dst, &dst_addr, &dst_mask) != 0 ||
                route_adv_parse_proto(proto, &proto_id) != 0 ||
                route_adv_parse_single_port(ports, &dst_port) != 0 ||
                route_adv_add_wan_target(db, map, map_count, target_token, &r) != 0) {
                if (stats) stats->skipped++;
                continue;
            }
            r.src_addr = src_addr;
            r.src_mask = src_mask;
            r.dst_addr = dst_addr;
            r.dst_mask = dst_mask;
        }
        r.proto = proto_id;
        r.dst_port = dst_port;
        if (jmx_route_nl_rule_add(fd, &r) == 0) {
            synced++;
            if (stats) stats->synced++;
            LOG_WARN("jmx_route: synced advanced policy rule id=%s prio=%u target=%s wans=%u",
                     id ? id : "", r.prio, target_token ? target_token : "", r.wan_count);
        } else {
            if (stats) stats->errors++;
            if (sync_errors)
                (*sync_errors)++;
        }
    }
    sqlite3_finalize(st);
    return synced;
}

static int route_adv_sync_legacy_policy_rows(sqlite3 *db, int fd,
                                             const struct route_sync_wan_map *map,
                                             int map_count,
                                             struct route_adv_sync_stats *stats,
                                             int *sync_errors)
{
    sqlite3_stmt *st = NULL;
    int synced = 0;
    int idx = 0;

    if (!db || !map || map_count <= 0 ||
        !route_adv_db_table_exists(db, "adv_policy_rule"))
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT id,src,dst,sport,dport,protocol,action,target "
        "FROM adv_policy_rule WHERE enabled=1 ORDER BY src,id",
        -1, &st, NULL) != SQLITE_OK) {
        if (stats)
            stats->errors++;
        if (sync_errors)
            (*sync_errors)++;
        return 0;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *src = (const char *)sqlite3_column_text(st, 1);
        const char *dst = (const char *)sqlite3_column_text(st, 2);
        const char *sport = (const char *)sqlite3_column_text(st, 3);
        const char *dport = (const char *)sqlite3_column_text(st, 4);
        const char *proto = (const char *)sqlite3_column_text(st, 5);
        const char *action = (const char *)sqlite3_column_text(st, 6);
        const char *target = (const char *)sqlite3_column_text(st, 7);
        struct jmx_route_rule_wire r;
        uint16_t dst_port = 0;
        uint8_t proto_id = 0;

        if (stats) {
            stats->checked++;
            stats->legacy_policy_rules++;
        }
        idx++;
        if (sport && sport[0] && !route_adv_is_any(sport)) {
            if (stats) stats->skipped++;
            continue;
        }
        if (action && action[0] && strcasecmp(action, "lookup") &&
            strcasecmp(action, "route") && strcasecmp(action, "route_table")) {
            if (stats) stats->skipped++;
            continue;
        }
        memset(&r, 0, sizeof(r));
        r.enabled = 1;
        r.prio = (uint16_t)(20000 + (idx % 10000));
        r.sticky_mode = JMX_STICKY_SIP;
        {
            uint32_t src_addr = 0, src_mask = 0, dst_addr = 0, dst_mask = 0;

            if (route_adv_resolve_object_cidr(db, src, &src_addr, &src_mask) != 0 ||
                route_adv_resolve_object_cidr(db, dst, &dst_addr, &dst_mask) != 0 ||
                route_adv_parse_proto(proto, &proto_id) != 0 ||
                route_adv_parse_single_port(dport, &dst_port) != 0 ||
                route_adv_add_wan_target(db, map, map_count, target, &r) != 0) {
                if (stats) stats->skipped++;
                continue;
            }
            r.src_addr = src_addr;
            r.src_mask = src_mask;
            r.dst_addr = dst_addr;
            r.dst_mask = dst_mask;
        }
        r.proto = proto_id;
        r.dst_port = dst_port;
        if (jmx_route_nl_rule_add(fd, &r) == 0) {
            synced++;
            if (stats) stats->synced++;
            LOG_WARN("jmx_route: synced legacy policy rule id=%s prio=%u target=%s wans=%u",
                     id ? id : "", r.prio, target ? target : "", r.wan_count);
        } else {
            if (stats) stats->errors++;
            if (sync_errors)
                (*sync_errors)++;
        }
    }
    sqlite3_finalize(st);
    return synced;
}

static int route_adv_sync_config_db(int fd, const struct route_sync_wan_map *map,
                                    int map_count, int *sync_errors)
{
    sqlite3 *db = NULL;
    struct route_adv_sync_stats stats;
    int synced = 0;

    memset(&stats, 0, sizeof(stats));
    if (sqlite3_open_v2(JMX_NETCONFIG_DB_PATH_DEFAULT, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        route_adv_sync_state_write(&stats, map_count);
        return 0;
    }
    sqlite3_busy_timeout(db, 500);
    synced += route_adv_sync_policy_rows(db, fd, map, map_count, &stats, sync_errors);
    synced += route_adv_sync_legacy_policy_rows(db, fd, map, map_count, &stats, sync_errors);
    sqlite3_close(db);
    route_adv_sync_state_write(&stats, map_count);
    if (stats.checked > 0 || stats.synced > 0 || stats.skipped > 0)
        LOG_WARN("jmx_route: advanced DB sync checked=%d synced=%d skipped=%d errors=%d",
                 stats.checked, stats.synced, stats.skipped, stats.errors);
    return synced;
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

static int jmx_route_load_builtin_carriers(int fd, int *errors)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    char path[512];
    int count = 0;
    int rc;

    if (jmx_route_signature_db_path(path, sizeof(path)) != 0) {
        if (errors)
            (*errors)++;
        return 0;
    }
    if (jmx_signature_db_acquire_path(path, &db) != SQLITE_OK) {
        LOG_WARN("jmx_route: cannot open signature db for carrier prefixes: %s (%s)",
                 path, jmx_signature_db_last_error());
        if (db) jmx_signature_db_release_path(db);
        return 0;
    }

    if (sqlite3_prepare_v2(db,
        "SELECT carrier_id,cidr,prefix_len FROM carrier_prefix WHERE enabled=1 ORDER BY sort_key",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("jmx_route: carrier_prefix table missing in signature db: %s", path);
        jmx_signature_db_release_path(db);
        return 0;
    }

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
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
        else if (errors)
            (*errors)++;
    }

    if (rc != SQLITE_DONE) {
        LOG_WARN("jmx_route: carrier_prefix scan failed in signature db: %s", path);
        if (errors)
            (*errors)++;
    }

    sqlite3_finalize(st);
    jmx_signature_db_release_path(db);
    LOG_WARN("jmx_route: loaded %d carrier prefixes from %s", count, path);
    return count;
}

/*
 * Push the appid -> category mapping into the kernel.
 *
 * The kernel counts forwarded bytes per WAN per category, but the category
 * only exists in the signature database, so without this the whole table
 * collapses into Unknown.  Rows are sent in batches to keep the number of
 * netlink round trips proportional to the app count / JMX_APPCAT_BATCH_MAX
 * rather than to the app count itself.
 */
static int jmx_route_load_app_categories(int fd, int *errors)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct jmx_appcat_rec batch[JMX_APPCAT_BATCH_MAX];
    char path[512];
    uint32_t pending = 0;
    int count = 0;
    int rc;

    if (jmx_route_signature_db_path(path, sizeof(path)) != 0) {
        if (errors)
            (*errors)++;
        return 0;
    }
    /* The appid -> category map is byte-accounting enrichment, not a routing
     * input: without it the per-WAN category counters collapse into Unknown,
     * but WAN registration, marks and rules are unaffected.  A signature DB
     * that is absent or invalid must therefore NOT fail a full route sync -- otherwise a
     * WAN-policy write on a device without the signature runtime rolls back at
     * runtime_apply.  Match jmx_route_load_builtin_carriers(): log and return 0
     * WITHOUT incrementing *errors so the enrichment is best-effort. */
    if (jmx_signature_db_acquire_path(path, &db) != SQLITE_OK) {
        LOG_WARN("jmx_route: cannot open signature db for app categories: %s (%s)",
                 path, jmx_signature_db_last_error());
        if (db)
            jmx_signature_db_release_path(db);
        return 0;
    }

    if (sqlite3_prepare_v2(db,
        "SELECT app_id,COALESCE(category_id,0) FROM app WHERE enabled=1",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("jmx_route: app table missing in signature db: %s", path);
        jmx_signature_db_release_path(db);
        return 0;
    }

    if (jmx_route_nl_appcat_flush(fd) != 0 && errors)
        (*errors)++;

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint32_t appid = (uint32_t)sqlite3_column_int64(st, 0);
        int category_id = sqlite3_column_int(st, 1);

        if (!appid)
            continue;
        batch[pending].appid = appid;
        batch[pending].category_id = (uint16_t)category_id;
        pending++;
        if (pending == JMX_APPCAT_BATCH_MAX) {
            if (jmx_route_nl_appcat_batch(fd, batch, pending) == 0)
                count += (int)pending;
            else if (errors)
                (*errors)++;
            pending = 0;
        }
    }
    if (pending) {
        if (jmx_route_nl_appcat_batch(fd, batch, pending) == 0)
            count += (int)pending;
        else if (errors)
            (*errors)++;
    }

    if (rc != SQLITE_DONE) {
        LOG_WARN("jmx_route: app category scan failed in signature db: %s", path);
        if (errors)
            (*errors)++;
    }

    sqlite3_finalize(st);
    jmx_signature_db_release_path(db);
    LOG_WARN("jmx_route: pushed %d app categories from %s", count, path);
    return count;
}

#define JMX_ROUTE_STATE_FILE "/tmp/jmx_route.state"
static unsigned route_rule_priority(uint32_t table_id)
{
    return JMX_ROUTE_RULE_PRIO_BASE + (table_id % 1000);
}

static void jmx_route_cleanup_system_route(uint32_t table_id)
{
    char prio_buf[16];
    char table_buf[16];
    char *del_argv[] = { "ip", "rule", "del", "priority", prio_buf, NULL };
    char *flush_argv[] = { "ip", "route", "flush", "table", table_buf, NULL };
    int i;

    if (!table_id || table_id > 65535)
        return;
    snprintf(prio_buf, sizeof(prio_buf), "%u", route_rule_priority(table_id));
    snprintf(table_buf, sizeof(table_buf), "%u", table_id);
    for (i = 0; i < 4; i++)
        route_run_cmd(del_argv);
    route_run_cmd(flush_argv);
}

static void jmx_route_cleanup_old_system_routes(void)
{
    FILE *fp = fopen(JMX_ROUTE_STATE_FILE, "r");
    unsigned prio, table_id;

    if (fp) {
        while (fscanf(fp, "%u %u", &prio, &table_id) == 2) {
            if (prio >= JMX_ROUTE_RULE_PRIO_BASE &&
                prio < JMX_ROUTE_RULE_PRIO_BASE + 1000 &&
                table_id >= 1 && table_id <= 65535)
                jmx_route_cleanup_system_route(table_id);
        }
        fclose(fp);
    }
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
    /*
     * BusyBox/iproute2 on OpenWrt supports "ip route replace", but not every
     * shipped ip rule binary supports "ip rule replace".  30.1 currently
     * returns "Command \"replace\" is unknown" for ip rule, which made
     * dreamingwrt route_reload report a hard failure even though the kernel
     * jmx_route rule set had already been synced.  Keep this path portable by
     * deleting any old rule with our deterministic priority first, then adding
     * the fresh fwmark rule.
     */
    {
        int i;
        char *del_argv[] = { "ip", "rule", "del", "priority", prio_buf, NULL };
        char *add_argv[] = { "ip", "rule", "add", "fwmark", fwmark_buf,
                             "table", table_buf, "priority", prio_buf, NULL };

        for (i = 0; i < 4; i++)
            route_run_cmd(del_argv);
        rc |= route_run_cmd(add_argv);
    }

    if (gateway && gateway[0]) {
        if (ifname && ifname[0]) {
            char *argv[] = { "ip", "route", "replace", "default", "via", (char *)gateway,
                             "dev", (char *)ifname, "table", table_buf, NULL };
            rc |= route_run_cmd(argv);
        } else {
            char *argv[] = { "ip", "route", "replace", "default", "via", (char *)gateway,
                             "table", table_buf, NULL };
            rc |= route_run_cmd(argv);
        }
    } else if (ifname && ifname[0]) {
        char *argv[] = { "ip", "route", "replace", "default", "dev", (char *)ifname,
                         "table", table_buf, NULL };
        rc |= route_run_cmd(argv);
    }

    if (rc == 0)
        jmx_route_state_add(table_id);
    else
        jmx_route_cleanup_system_route(table_id);
    return rc == 0 ? 0 : -1;
}

static void route_health_probe_ifname_json(struct json_object *wan,
                                           char *out, size_t out_len,
                                           const struct route_network_wan_snapshot *runtime)
{
    const char *name = json_get_str(wan, "name", "");
    const char *ifname = json_get_str(wan, "ifname", "");
    char logical_name[16];
    const struct route_network_wan_runtime *rt;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (name[0] && (rt = route_network_wan_snapshot_find_name(runtime, name)) &&
        rt->l3_ifname[0] && route_ifname_ok(rt->l3_ifname)) {
        snprintf(out, out_len, "%s", rt->l3_ifname);
        return;
    }
    snprintf(logical_name, sizeof(logical_name), "wan%u",
             json_get_u32(wan, "id", 0));
    if ((rt = route_network_wan_snapshot_find_name(runtime, logical_name)) &&
        rt->l3_ifname[0] && route_ifname_ok(rt->l3_ifname)) {
        snprintf(out, out_len, "%s", rt->l3_ifname);
        return;
    }
    if (name[0] && route_l3_device_from_ifstatus(name, out, out_len) == 0)
        return;
    if (route_l3_device_from_ifstatus(logical_name, out, out_len) == 0)
        return;
    if (ifname[0] && route_l3_device_from_device(ifname, out, out_len) == 0)
        return;
    if (route_ifname_ok(ifname))
        snprintf(out, out_len, "%s", ifname);
}

static void route_rule_from_json(struct json_object *rule,
                                 struct jmx_route_rule_wire *out,
                                 int default_prio, uint32_t *enhancements,
                                 int legacy_adaptive_fallback)
{
    struct json_object *wan_ids = NULL, *members = NULL;
    const char *base_mode;
    int i;

    memset(out, 0, sizeof(*out));
    if (enhancements)
        *enhancements = 0;
    out->enabled = (uint8_t)json_get_u32(rule, "enabled", 1);
    out->prio = (uint16_t)json_get_u32(rule, "prio", (uint32_t)default_prio);
    out->src_addr = json_get_ipv4(rule, "src_addr", 0);
    out->src_mask = json_get_ipv4(rule, "src_mask", 0);
    out->dst_addr = json_get_ipv4(rule, "dst_addr", 0);
    out->dst_mask = json_get_ipv4(rule, "dst_mask", 0);
    out->dst_port = (uint16_t)json_get_u32(rule, "dst_port", 0);
    out->proto = proto_from_string(json_get_str(rule, "proto", "any"));
    out->appid = json_get_u32(rule, "appid", 0);
    out->carrier_id = carrier_from_string(json_get_str(rule, "carrier", "any"));
    base_mode = json_get_str(rule, "base_mode", json_get_str(
        rule, "algorithm", json_get_str(rule, "sticky_mode", "hash_src")));
    out->sticky_mode = sticky_mode_from_string(base_mode);
    if (json_get_u32(rule, "adaptive_penalty_sticky", 0)) {
        if (legacy_adaptive_fallback &&
            json_get_u32(rule, "migration_required", 0))
            out->sticky_mode = JMX_STICKY_ADAPTIVE_PENALTY;
        else if (enhancements)
            *enhancements |= JMX_ROUTE_ENHANCEMENT_ADAPTIVE_PENALTY;
    }
    if (json_object_object_get_ex(rule, "members", &members) &&
        json_object_is_type(members, json_type_array)) {
        int explicit_weights = json_get_u32(
            rule, "member_weights_explicit", 1) ? 1 : 0;

        for (i = 0; i < json_object_array_length(members) &&
                    out->wan_count < JMX_ROUTE_MAX_WAN_IFACES; i++) {
            struct json_object *member = json_object_array_get_idx(members, i);
            uint32_t weight = 0;

            if (!member || !json_object_is_type(member, json_type_object) ||
                json_get_weight(member, "weight", 1, &weight) != 0)
                continue;
            out->wan_ids[out->wan_count] =
                (uint8_t)json_get_u32(member, "wan_id", 0);
            out->wan_weights[out->wan_count] = explicit_weights ? weight : 0;
            if (out->wan_ids[out->wan_count])
                out->wan_count++;
        }
    } else if (json_object_object_get_ex(rule, "wan_ids", &wan_ids) &&
               json_object_is_type(wan_ids, json_type_array)) {
        for (i = 0; i < json_object_array_length(wan_ids) &&
                    out->wan_count < JMX_ROUTE_MAX_WAN_IFACES; i++)
            out->wan_ids[out->wan_count++] = (uint8_t)json_object_get_int(
                json_object_array_get_idx(wan_ids, i));
    }

    /*
     * Global WAN mode override for the default multi-WAN rule.
     *
     * The kernel already implements both semantics per rule: PRIMARY_BACKUP
     * always takes the first healthy WAN (failover), while the weighted
     * selectors spread new flows across every healthy WAN (load balance). What
     * was missing was anything driving that choice from user configuration --
     * network_global.wan_mode now does.
     *
     * Scope is deliberately narrow: only the default rule, meaning carrier_id 0
     * (no operator steering) spanning more than one WAN, and only when the rule
     * did not state an algorithm of its own. An explicit policy rule carries a
     * deliberate algorithm, and a global toggle must not silently rewrite the
     * operator's per-rule steering.
     */
    if (out->carrier_id == 0 && out->wan_count > 1 &&
        !json_has_key(rule, "base_mode") && !json_has_key(rule, "algorithm") &&
        !json_has_key(rule, "sticky_mode")) {
        char wan_mode[32];

        if (jmx_netconfig_wan_mode_get(wan_mode, sizeof(wan_mode)) == 0 &&
            !strcmp(wan_mode, "failover"))
            out->sticky_mode = JMX_STICKY_PRIMARY_BACKUP;
    }
}

static int jmx_route_sync_json(struct json_object *config)
{
    struct json_object *prefixes = NULL, *wans = NULL, *rules = NULL;
    const char *dangling_policy;
    int fd;
    int wan_count = 0, rule_count = 0, carrier_count = 0;
    int sync_errors = 0;
    int configured_rules_expected = 0;
    int configured_rules_added = 0;
    struct route_sync_wan_map wan_map[JMX_ROUTE_MAX_WAN_IFACES];
    struct route_network_wan_snapshot runtime_snapshot;
    int wan_map_count = 0;
    int runtime_snapshot_valid;
    int v2_supported;
    int i;

    if (!config || !json_object_is_type(config, json_type_object)) {
        errno = EINVAL;
        return -1;
    }
    /* Do this before the first flush/unregister. A canonical adaptive overlay
     * needs action 44; applying it to an old module would otherwise replace a
     * working policy with one that has silently lost its enhancement. */
    v2_supported = route_kernel_rule_v2_supported(NULL);
    if (route_config_requires_rule_v2(config) && !v2_supported) {
        LOG_ERROR("jmx_route: canonical adaptive policy requires RouteRuleAbi=2 enhancements=0x%x",
                  JMX_ROUTE_ENHANCEMENT_ADAPTIVE_PENALTY);
        errno = EOPNOTSUPP;
        return -1;
    }
    /* Invalidate locally before opening the transport as well: if netlink is
     * unavailable, the userspace consumer must not keep advertising the old
     * WAN identity as ready. */
    (void)jmx_direction_snapshot_publish_unready(route_direction_gateway_mode());
    /* Rule/WAN topology is about to change; drop cached snapshots so status
     * enrichment cannot attribute marks or rule counts to the old topology. */
    g_route_marks_cache.valid = 0;
    g_route_main_nondefault_cache.valid = 0;
    memset(wan_map, 0, sizeof(wan_map));
    runtime_snapshot_valid = route_network_wan_snapshot_get(&runtime_snapshot) == 0;

    fd = route_open_nl();
    if (fd < 0)
        return -1;

    /* Publish the unready generation to the kernel before replacing any
     * route/WAN identity.  A send failure keeps the dataplane fail-open by
     * treating this sync as failed; the local snapshot is still unready. */
    if (route_direction_snapshot_send_current(fd) != 0) {
        LOG_ERROR("jmx_route: failed to send direction snapshot unready state");
        close(fd);
        errno = EIO;
        return -1;
    }

    if (route_main_nondefault_rule_install() != 0) {
        LOG_ERROR("jmx_route: failed to install main non-default lookup priority=%u",
                  JMX_ROUTE_MAIN_NONDEFAULT_PRIO);
        sync_errors++;
    }
    if (jmx_route_nl_rule_flush(fd) != 0)
        sync_errors++;
    if (jmx_route_nl_carrier_flush(fd) != 0)
        sync_errors++;
    for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES; i++) {
        if (jmx_route_nl_wan_unregister(fd, (uint8_t)i) != 0)
            sync_errors++;
    }
    jmx_route_cleanup_old_system_routes();
    carrier_count += jmx_route_load_builtin_carriers(fd, &sync_errors);
    /* Refresh the kernel's appid -> category map on the same trigger as the
     * carrier prefixes; both come from the signature database. */
    jmx_route_load_app_categories(fd, &sync_errors);

    json_object_object_get_ex(config, "carrier_prefixes", &prefixes);
    for (i = 0; prefixes && i < json_object_array_length(prefixes); i++) {
        struct json_object *prefix = json_object_array_get_idx(prefixes, i);
        const char *cidr = json_get_str(prefix, "cidr", "");
        uint8_t carrier = carrier_from_string(json_get_str(prefix, "carrier", "any"));
        uint32_t network = 0, mask = 0;

        if (!carrier || parse_cidr(cidr, &network, &mask) != 0)
            continue;
        if (jmx_route_nl_carrier_add(fd, network, mask, carrier) == 0)
            carrier_count++;
        else
            sync_errors++;
    }

    json_object_object_get_ex(config, "wans", &wans);
    for (i = 0; wans && i < json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);
        uint8_t id = (uint8_t)json_get_u32(wan, "id", 0);
        const char *name = json_get_str(wan, "name", "");
        const char *ifname = json_get_str(wan, "ifname", "");
        const char *route_ifname = ifname;
        const char *configured_gateway = json_get_str(wan, "gateway", "");
        const char *gw_str = configured_gateway;
        const char *system_gateway;
        uint32_t fwmark = json_get_u32(wan, "fwmark", id ? 0x10000U + id : 0);
        uint32_t table_id = json_get_u32(wan, "table", 100U + id);
        uint32_t gateway;
        uint8_t health = (uint8_t)json_get_u32(wan, "health", 1);
        uint32_t weight = json_get_u32(wan, "weight", 1);
        char l3_ifname[JMX_ROUTE_HEALTH_IFNAME_LEN] = "";
        char runtime_gateway[64] = "";
        char logical_name[16];
        int runtime_online = 0;
        int runtime_ok;

        if (!id || !weight) {
            sync_errors++;
            continue;
        }
        if (!name[0])
            name = ifname[0] ? ifname : "wan";
        runtime_ok = route_ifstatus_runtime(name, l3_ifname, sizeof(l3_ifname),
                                            runtime_gateway, sizeof(runtime_gateway),
                                            &runtime_online) == 0;
        if (!runtime_ok) {
            snprintf(logical_name, sizeof(logical_name), "wan%u", id);
            runtime_ok = route_ifstatus_runtime(logical_name, l3_ifname,
                                                sizeof(l3_ifname), runtime_gateway,
                                                sizeof(runtime_gateway),
                                                &runtime_online) == 0;
        }
        if (!l3_ifname[0])
            route_health_probe_ifname_json(wan, l3_ifname, sizeof(l3_ifname),
                                           runtime_snapshot_valid ? &runtime_snapshot : NULL);
        if (l3_ifname[0])
            route_ifname = l3_ifname;
        if (runtime_gateway[0])
            gw_str = runtime_gateway;
        gateway = route_ipv4_from_string(gw_str, 0);
        if (runtime_ok)
            health = runtime_online ? 1 : 0;
        system_gateway = gw_str;
        if (route_ifname && !strncmp(route_ifname, "ppp", 3))
            system_gateway = NULL;
        if (jmx_route_nl_wan_register(fd, id, name, fwmark, table_id,
                                      gateway, weight) == 0) {
            route_sync_wan_map_add(wan_map, JMX_ROUTE_MAX_WAN_IFACES,
                                   &wan_map_count, id, name, route_ifname,
				   fwmark, table_id);
            route_sync_wan_map_set_carrier(
                wan_map, wan_map_count, id,
                route_detect_wan_carrier(name, route_ifname));
            if (jmx_route_nl_wan_health(fd, id, health) != 0)
                sync_errors++;
            if (runtime_ok && !runtime_online) {
                jmx_route_cleanup_system_route(table_id);
            } else if (jmx_route_apply_system_route(route_ifname, fwmark, table_id,
                                                    system_gateway) != 0) {
                sync_errors++;
            }
            wan_count++;
        } else {
            sync_errors++;
        }
    }

    /* Top up from UCI unconditionally, not only when config.db has no WANs.
     * A WAN added through the web UI lands in /etc/config/network but is not
     * written into route_wan, so gating this on wan_count == 0 left every WAN
     * beyond the ones already in the ledger unregistered: dialled up with a
     * real address, yet invisible to the scheduler (no fwmark rule, empty
     * table). route_sync_network_wans() skips names already registered above
     * and reserves their ids, so repeating this is idempotent. */
    {
        int uci_wans = route_sync_network_wans(fd, &sync_errors,
                                              wan_map, JMX_ROUTE_MAX_WAN_IFACES,
                                              &wan_map_count);

        if (uci_wans > 0) {
            wan_count += uci_wans;
            LOG_WARN("jmx_route: registered %d WAN(s) present in uci network but missing from route_wan",
                     uci_wans);
        }
    }

    json_object_object_get_ex(config, "rules", &rules);
    /* Read once per sync pass: route_global is a single row, and re-reading it
     * per rule would only invite the two halves of one push to disagree. */
    dangling_policy = json_get_str(config, "dangling_wan_policy", "reinstate_registered");
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct jmx_route_rule_wire rule;
        struct json_object *rule_json = json_object_array_get_idx(rules, i);
        uint32_t enhancements = 0;

        route_rule_from_json(rule_json, &rule,
                             1000 + rule_count, &enhancements,
                             !v2_supported);
        if (!rule.enabled)
            continue;
        configured_rules_expected++;
        route_resolve_auto_carrier_wans(&rule, wan_map, wan_map_count);
        /* Runs after the UCI top-up above, so wan_map already holds every WAN
         * this pass registered -- including lines absent from the route_wan
         * ledger, whose members the export had to report as dangling. */
        route_restore_dangling_wan_members(rule_json, &rule, wan_map, wan_map_count,
                                           dangling_policy);
        if (rule.wan_count == 0) {
            LOG_ERROR("jmx_route: enabled rule '%s' carrier=%s resolved no WAN targets",
                      json_get_str(rule_json, "name", ""),
                      json_get_str(rule_json, "carrier", "any"));
            sync_errors++;
            continue;
        }
        if (rule.sticky_mode <= JMX_STICKY_MAX &&
            ((!enhancements && jmx_route_nl_rule_add(fd, &rule) == 0) ||
             (enhancements && v2_supported &&
              jmx_route_nl_rule_add_v2(fd, &rule, enhancements) == 0))) {
            rule_count++;
            configured_rules_added++;
        } else {
            sync_errors++;
        }
    }
    if (configured_rules_added != configured_rules_expected) {
        LOG_ERROR("jmx_route: configured rule apply mismatch expected=%d added=%d",
                  configured_rules_expected, configured_rules_added);
        if (!sync_errors)
            sync_errors++;
    }

    rule_count += route_adv_sync_config_db(fd, wan_map, wan_map_count, &sync_errors);
	if (route_dns_domain_nft_apply(wan_map, wan_map_count) != 0) {
		LOG_ERROR("jmx_route: DNS domain route nft apply failed");
		sync_errors++;
	}

    {
        int actual_carriers = -1, actual_wans = -1, actual_rules = -1;
        int main_nondefault_ready = route_main_nondefault_rule_count_raw() == 1;

        if (route_kernel_state_counts(&actual_carriers, &actual_wans, &actual_rules) != 0 ||
            actual_carriers != carrier_count || actual_wans != wan_count ||
            actual_rules != rule_count || !main_nondefault_ready) {
            LOG_ERROR("jmx_route: kernel readback mismatch expected carriers=%d wans=%d rules=%d main_nondefault=1 actual carriers=%d wans=%d rules=%d main_nondefault=%d",
                      carrier_count, wan_count, rule_count,
                      actual_carriers, actual_wans, actual_rules,
                      main_nondefault_ready);
            sync_errors++;
        }
    }
    LOG_WARN("jmx_route: synced config carriers=%d wans=%d rules=%d errors=%d",
             carrier_count, wan_count, rule_count, sync_errors);
    if (!sync_errors) {
        memset(g_route_auto_carriers, 0, sizeof(g_route_auto_carriers));
        for (i = 0; i < wan_map_count; i++) {
            if (wan_map[i].id <= JMX_ROUTE_MAX_WAN_IFACES)
                g_route_auto_carriers[wan_map[i].id] = wan_map[i].carrier_id;
        }
        if (route_direction_snapshot_publish(fd, wan_map, wan_map_count) != 0) {
            LOG_ERROR("jmx_route: direction snapshot publish failed; leaving gate fail-open");
            (void)jmx_direction_snapshot_publish_unready(route_direction_gateway_mode());
            if (route_direction_snapshot_send_current(fd) != 0)
                LOG_ERROR("jmx_route: failed to send direction unready state");
            sync_errors++;
        }
    }
    if (runtime_snapshot_valid) {
        /* Consume this edge even when another route component failed. Retrying
         * a full flush every 30 seconds is more disruptive than surfacing the
         * error and leaving an explicit route_reload available for recovery. */
        g_route_network_wans = runtime_snapshot;
        g_route_network_wans_ready = 1;
    }
    close(fd);
    if (sync_errors)
        errno = EIO;
    return sync_errors ? -1 : 0;
}

int jmx_route_sync_config(void)
{
    struct json_object *config = NULL;
    int rc;

    if (jmx_route_db_config_get(&config) != 0)
        return -1;
    rc = jmx_route_sync_json(config);
    json_object_put(config);
    return rc;
}

static int route_health_enabled_opt(struct uci_section *s, int def)
{
    const char *v = uci_opt(s, "check_enable");

    if (!v || !v[0])
        v = uci_opt(s, "dreamingwrt_check_enable");
    if (!v || !v[0])
        v = uci_opt(s, "health_enabled");
    if (!v || !v[0])
        return def;
    if (!strcmp(v, "1") || !strcasecmp(v, "true") ||
        !strcasecmp(v, "yes") || !strcasecmp(v, "on"))
        return 1;
    return 0;
}

static int route_health_network_wans(int fd,
                                     const struct route_health_snapshot_set *snapshots,
                                     const struct route_network_wan_snapshot *runtime)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    uint8_t used[256] = {0};
    uint8_t next_id = 1;
    int count = 0;

    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "network", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return 0;
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *name, *proto, *ifname;
        const struct route_health_snapshot *snap;
        char l3_ifname[JMX_ROUTE_HEALTH_IFNAME_LEN] = "";
        uint8_t id;
        uint8_t enabled;
        uint8_t failover;
        uint8_t failback;
        uint8_t config_health = 1;

        if (!s || strcmp(s->type, "interface") != 0)
            continue;
        name = s->e.name;
        proto = uci_opt(s, "proto");
        if (!route_network_iface_is_wan(name, proto) || route_section_disabled(s))
            continue;
        id = route_wan_id_from_name(name, used, next_id);
        if (!id)
            continue;
        next_id = id + 1;
        /* UCI is the authoritative runtime WAN inventory.  A line omitted
         * from route_wan still needs health tracking; otherwise wan3/wan4 are
         * pruned whenever config.db contains only wan1/wan2. */
        enabled = (uint8_t)route_health_enabled_opt(s, 1);
        if (!enabled)
            continue;
        if (route_health_state_get(id)->generation == g_route_health_generation)
            continue;
        failover = (uint8_t)parse_u32_opt(s, "failover", 1);
        failback = (uint8_t)parse_u32_opt(s, "failback", 1);
        ifname = route_wan_ifname_option(s);
        {
            const struct route_network_wan_runtime *rt =
                route_network_wan_snapshot_find_name(runtime, name);

            if (rt && rt->l3_ifname[0] && route_ifname_ok(rt->l3_ifname))
                snprintf(l3_ifname, sizeof(l3_ifname), "%s", rt->l3_ifname);
        }
        if (!l3_ifname[0])
            route_l3_device_from_ifstatus(name, l3_ifname, sizeof(l3_ifname));
        if (!l3_ifname[0])
            route_health_probe_ifname(s, l3_ifname, sizeof(l3_ifname));
        if (!l3_ifname[0] && ifname && route_ifname_ok(ifname))
            snprintf(l3_ifname, sizeof(l3_ifname), "%s", ifname);
        snap = route_health_snapshot_find(snapshots, name, l3_ifname);
        route_health_tick_one(fd, id, enabled, failover, failback,
                              config_health, name, l3_ifname, snap);
        count++;
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return count;
}


void jmx_route_health_tick(void)
{
    struct json_object *config = NULL;
    struct json_object *wans = NULL;
    struct route_network_wan_snapshot runtime_snapshot;
    struct route_health_snapshot_set health_snapshots;
    int health_snapshot_ok;
    int runtime_snapshot_valid;
    int fd;
    int i;
    int runtime_changed = -1;

    g_route_health_generation++;
    if (g_route_health_generation == 0)
        g_route_health_generation = 1;

    runtime_snapshot_valid = route_network_wan_snapshot_get(&runtime_snapshot) == 0;
    if (!runtime_snapshot_valid)
        memset(&runtime_snapshot, 0, sizeof(runtime_snapshot));

    fd = route_open_nl();
    if (fd < 0)
        return;
    health_snapshot_ok = route_health_snapshot_load(&health_snapshots) == 0;
    if (!health_snapshot_ok)
        memset(&health_snapshots, 0, sizeof(health_snapshots));
    if (jmx_route_db_config_get_readonly(&config) != 0 || !config) {
        route_health_network_wans(fd, &health_snapshots,
                                  runtime_snapshot_valid ? &runtime_snapshot : NULL);
        route_health_prune_states();
        close(fd);
        return;
    }

    json_object_object_get_ex(config, "wans", &wans);
    for (i = 0; wans && i < json_object_array_length(wans); i++) {
        struct json_object *wan = json_object_array_get_idx(wans, i);
        uint8_t id = (uint8_t)json_get_u32(wan, "id", 0);
        uint8_t enabled = (uint8_t)json_get_u32(
            wan, "check_enable", json_get_u32(wan, "health_enabled", 1));
        uint8_t failover = (uint8_t)json_get_u32(wan, "failover", 1);
        uint8_t failback = (uint8_t)json_get_u32(wan, "failback", 1);
        uint8_t config_health = (uint8_t)json_get_u32(wan, "health", 1);
        const char *name = json_get_str(wan, "name", "wan");
        const struct route_health_snapshot *snap;
        char l3_ifname[JMX_ROUTE_HEALTH_IFNAME_LEN] = "";

        if (!id)
            continue;
        route_health_probe_ifname_json(wan, l3_ifname, sizeof(l3_ifname),
                                       runtime_snapshot_valid ? &runtime_snapshot : NULL);
        snap = route_health_snapshot_find(&health_snapshots, name, l3_ifname);
        route_health_tick_one(fd, id, enabled, failover, failback,
                              config_health, name, l3_ifname, snap);
    }
    /* Always top up from the live network inventory.  The generation guard in
     * route_health_network_wans() skips ids already handled from config.db and
     * admits runtime-only lines such as wan3/wan4. */
    route_health_network_wans(fd, &health_snapshots,
                              runtime_snapshot_valid ? &runtime_snapshot : NULL);

    route_health_prune_states();
    close(fd);
    if (runtime_snapshot_valid)
        runtime_changed = route_network_wan_runtime_changed(&runtime_snapshot, 1);
    if (runtime_changed > 0)
        LOG_WARN("jmx_route: WAN runtime topology changed; resyncing route configuration");
    if (runtime_changed > 0 || route_auto_carrier_mapping_changed(config))
        (void)jmx_route_sync_json(config);
    json_object_put(config);
}
