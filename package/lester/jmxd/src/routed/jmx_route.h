/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_ROUTE_H__
#define __JMX_ROUTE_H__

#include <stdint.h>
#include <json-c/json.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define JMX_ROUTE_MAX_WAN_IFACES  8

enum jmx_carrier_id {
    JMX_CARRIER_ANY = 0,
    JMX_CARRIER_TELECOM = 1,
    JMX_CARRIER_UNICOM = 2,
    JMX_CARRIER_MOBILE = 3,
    JMX_CARRIER_EDU = 4,
    JMX_CARRIER_OTHER = 255,
};

#define JMX_NL_ACT_WAN_REGISTER    30
#define JMX_NL_ACT_WAN_UNREGISTER  31
#define JMX_NL_ACT_WAN_HEALTH      32
#define JMX_NL_ACT_ROUTE_ADD       33
#define JMX_NL_ACT_ROUTE_DEL       34
#define JMX_NL_ACT_ROUTE_FLUSH     35
#define JMX_NL_ACT_ROUTE_CLEAR_HITS 36
#define JMX_NL_ACT_CARRIER_FLUSH    40
#define JMX_NL_ACT_CARRIER_ADD      41
#define JMX_NL_ACT_APPCAT_FLUSH     42
#define JMX_NL_ACT_APPCAT_ADD       43

/*
 * appid -> category push.  The kernel needs the mapping to keep the per-WAN
 * per-category counters in /proc/dreamingwrt/jmx/wan<N>/proto_stats; the
 * category itself only exists in the signature database.
 */
#define JMX_APPCAT_BATCH_MAX 512

struct jmx_appcat_rec {
    uint32_t appid;
    uint16_t category_id;
} __packed;

struct jmx_appcat_batch {
    int32_t  action;
    uint32_t count;
    struct jmx_appcat_rec recs[JMX_APPCAT_BATCH_MAX];
} __packed;

enum jmx_route_sticky_mode {
    JMX_STICKY_NEW_CONN = 0,
    JMX_STICKY_SIP = 1,
    JMX_STICKY_SIP_SPORT = 2,
    JMX_STICKY_SIP_DIP = 3,
    JMX_STICKY_SIP_DIP_DPORT = 4,
	JMX_STICKY_5TUPLE = 5,
	JMX_STICKY_PRIMARY_BACKUP = 6,
	JMX_STICKY_DOWNLOAD = 7,
	JMX_STICKY_CONN_CNT = 8,
};

struct jmx_wan_register_wire {
    int32_t  action;
    uint8_t  wan_id;
    char     name[16];
    uint32_t fwmark;
    uint32_t table_id;
    uint32_t gateway;
    uint32_t weight;
} __packed;

_Static_assert(sizeof(struct jmx_wan_register_wire) == 37,
               "jmx WAN register wire layout changed");

struct jmx_route_rule_wire {
    uint8_t  enabled;
    uint16_t prio;
    uint32_t src_addr;
    uint32_t src_mask;
    uint32_t dst_addr;
    uint32_t dst_mask;
    uint16_t dst_port;
    uint8_t  proto;
    uint32_t appid;
    uint8_t  carrier_id;
    uint8_t  sticky_mode;
    uint8_t  wan_count;
    uint8_t  wan_ids[JMX_ROUTE_MAX_WAN_IFACES];
    /*
     * Kernel jmx_route handler receives this payload as jmx_route_rule_t, not
     * as a shorter userspace-only struct.  Keep the wire size/layout equal to
     * jmx/src/jmx_conntrack.h:jmx_route_rule_t so JMX_NL_ACT_ROUTE_ADD passes
     * the kernel len check and policy/PBR rules actually appear under
     * /proc/dreamingwrt/jmx/jmx_route Rules.
     */
    uint64_t hit_count;
    uint64_t last_hit_jiffies;
};

int jmx_route_nl_wan_register(int nl_fd, uint8_t wan_id, const char *name,
                              uint32_t fwmark, uint32_t table_id, uint32_t gateway,
                              uint32_t weight);
int jmx_route_nl_wan_unregister(int nl_fd, uint8_t wan_id);
int jmx_route_nl_wan_health(int nl_fd, uint8_t wan_id, uint8_t health);
int jmx_route_nl_rule_add(int nl_fd, const struct jmx_route_rule_wire *rule);
int jmx_route_nl_rule_del(int nl_fd, uint16_t prio);
int jmx_route_nl_rule_flush(int nl_fd);
int jmx_route_nl_rule_clear_hits(int nl_fd, uint16_t prio);
int jmx_route_nl_carrier_flush(int nl_fd);
int jmx_route_nl_carrier_add(int nl_fd, uint32_t network, uint32_t mask, uint8_t carrier_id);
int jmx_route_nl_appcat_flush(int nl_fd);
int jmx_route_nl_appcat_batch(int nl_fd, const struct jmx_appcat_rec *recs,
                              uint32_t count);

struct json_object *jmx_api_route_wan_register(struct json_object *req_obj);
struct json_object *jmx_api_route_wan_unregister(struct json_object *req_obj);
struct json_object *jmx_api_route_wan_health(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_add(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_del(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_flush(struct json_object *req_obj);
struct json_object *jmx_api_route_rule_clear_hits(struct json_object *req_obj);
struct json_object *jmx_api_route_status(struct json_object *req_obj);
struct json_object *jmx_api_route_reload(struct json_object *req_obj);
struct json_object *jmx_api_route_config_get(struct json_object *req_obj);
struct json_object *jmx_api_route_config_set(struct json_object *req_obj);
struct json_object *jmx_api_route_policy_set(struct json_object *req_obj);
int jmx_route_sync_config(void);
void jmx_route_health_tick(void);
int jmx_route_counter_tick(void);

#endif
