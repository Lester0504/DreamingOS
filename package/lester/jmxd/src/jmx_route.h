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

enum jmx_route_sticky_mode {
    JMX_STICKY_NEW_CONN = 0,
    JMX_STICKY_SIP = 1,
    JMX_STICKY_SIP_SPORT = 2,
    JMX_STICKY_SIP_DIP = 3,
    JMX_STICKY_SIP_DIP_DPORT = 4,
    JMX_STICKY_5TUPLE = 5,
    JMX_STICKY_PRIMARY_BACKUP = 6,
};

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
     * Must match kernel jmx_route_rule_t wire size/layout
     * (jmx/src/jmx_conntrack.h).  The kernel netlink handler casts
     * JMX_NL_ACT_ROUTE_ADD payload to jmx_route_rule_t and rejects shorter
     * messages by len, so keep the counter tail even though userspace sends 0.
     */
    uint64_t hit_count;
    uint64_t last_hit_jiffies;
};

int jmx_route_nl_wan_register(int nl_fd, uint8_t wan_id, const char *name,
                              uint32_t fwmark, uint32_t table_id, uint32_t gateway);
int jmx_route_nl_wan_unregister(int nl_fd, uint8_t wan_id);
int jmx_route_nl_wan_health(int nl_fd, uint8_t wan_id, uint8_t health);
int jmx_route_nl_rule_add(int nl_fd, const struct jmx_route_rule_wire *rule);
int jmx_route_nl_rule_del(int nl_fd, uint16_t prio);
int jmx_route_nl_rule_flush(int nl_fd);
int jmx_route_nl_rule_clear_hits(int nl_fd, uint16_t prio);
int jmx_route_nl_carrier_flush(int nl_fd);
int jmx_route_nl_carrier_add(int nl_fd, uint32_t network, uint32_t mask, uint8_t carrier_id);

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
int jmx_route_sync_config(void);
void jmx_route_health_tick(void);
int jmx_route_counter_tick(void);

#endif
