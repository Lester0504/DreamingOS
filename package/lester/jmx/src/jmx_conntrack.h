
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __AF_SIMPLE_CONNTRACK_H__
#define __AF_SIMPLE_CONNTRACK_H__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/in6.h>
#define AF_CONN_TIMEOUT 30  
#define AF_CONN_HASH_SIZE 256

extern spinlock_t af_conn_lock;
typedef enum {
    AF_CONN_NEW = 0,
    AF_CONN_ESTABLISHED,
    AF_CONN_DPI_FINISHED,
} af_conn_state_t;

typedef struct {
    struct hlist_node node;     
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;
    u32 total_pkts;
    u32 app_id;
	u8 client_hello;
    u8  drop;
    u8 ignore;
    af_conn_state_t state;      
    unsigned long last_jiffies;
} af_conn_t;

int af_conn_init(void);

af_conn_t* af_conn_find_and_add(u32 src_ip, u32 dst_ip, 
                       u16 src_port, u16 dst_port, 
                       u8 protocol);

void af_conn_record_match(u32 src_ip, u32 dst_ip, u16 src_port,
                          u16 dst_port, u8 protocol, u32 app_id, u8 drop);

void af_conn_clean_timeout(void);


void af_conn_exit(void);

/* ===== Phase 5: Multi-WAN route policy ===== */

enum jmx_route_source {
	JMX_ROUTE_SRC_DEFAULT  = 0,
	JMX_ROUTE_SRC_APP      = 1,
	JMX_ROUTE_SRC_DOMAIN   = 2,
	JMX_ROUTE_SRC_TUPLE    = 3,
	JMX_ROUTE_SRC_MANUAL   = 4,
};

enum jmx_sticky_mode {
	JMX_STICKY_NEW_CONN    = 0,
	JMX_STICKY_SIP         = 1,
	JMX_STICKY_SIP_SPORT   = 2,
	JMX_STICKY_SIP_DIP     = 3,
	JMX_STICKY_SIP_DIP_DPORT = 4,
	JMX_STICKY_5TUPLE      = 5,
	JMX_STICKY_PRIMARY_BACKUP = 6,
	JMX_STICKY_DOWNLOAD    = 7,
	JMX_STICKY_CONN_CNT    = 8,
};

#define JMX_MAX_WAN_IFACES   8
#define JMX_MAX_ROUTE_RULES  256
#define JMX_ROUTE_TABLE_BASE 100
#define JMX_MAX_CARRIER_PREFIXES 8192

enum jmx_carrier_id {
	JMX_CARRIER_ANY = 0,
	JMX_CARRIER_TELECOM = 1,
	JMX_CARRIER_UNICOM = 2,
	JMX_CARRIER_MOBILE = 3,
	JMX_CARRIER_EDU = 4,
	JMX_CARRIER_OTHER = 255,
};

#define JMX_NL_ACT_CARRIER_FLUSH 40
#define JMX_NL_ACT_CARRIER_ADD   41

#define JMX_NL_ACT_APPCAT_FLUSH  42
#define JMX_NL_ACT_APPCAT_ADD    43

/*
 * Per-WAN x per-category forwarding statistics.
 *
 * Category ids mirror the userspace signature database `app_category` table.
 * That table is sparse (1..17 plus 99 for "unknown"), so the kernel keeps a
 * dense slot array and maps id 99 onto JMX_APP_CAT_UNKNOWN.  Any appid the
 * kernel has no mapping for is also counted as unknown; traffic is never
 * redistributed across categories to make the table look complete.
 */
#define JMX_APP_CAT_UNKNOWN     0
#define JMX_APP_CAT_SLOTS       18
#define JMX_APP_CAT_DB_UNKNOWN  99

typedef struct jmx_wan_cat_stat {
	atomic64_t active_conn;
	atomic64_t tx_packets;
	atomic64_t rx_packets;
	atomic64_t tx_bytes;
	atomic64_t rx_bytes;
} jmx_wan_cat_stat_t;

typedef struct jmx_wan_iface {
	u8   wan_id;
	char name[16];
	u32  fwmark;
	u32  table_id;
	u32  gateway;
	u8   health;
	u32  weight;
	atomic64_t rx_bytes;
	atomic64_t active_conn;
	u32  generation;
	/* Fixed-size table: no per-flow allocation on the forwarding path. */
	jmx_wan_cat_stat_t cats[JMX_APP_CAT_SLOTS];
} jmx_wan_iface_t;

typedef struct jmx_route_rule {
	u8   enabled;
	u16  prio;
	u32  src_addr;
	u32  src_mask;
	u32  dst_addr;
	u32  dst_mask;
	u16  dst_port;
	u8   proto;
	u32  appid;
	u8   carrier_id;
	u8   sticky_mode;
	u8   wan_count;
	u8   wan_ids[JMX_MAX_WAN_IFACES];
	u64  hit_count;
	u64  last_hit_jiffies;
} jmx_route_rule_t;

int  jmx_wan_register(u8 wan_id, const char *name, u32 fwmark, u32 table_id,
		      u32 gateway, u32 weight);
void jmx_wan_unregister(u8 wan_id);
void jmx_wan_set_health(u8 wan_id, u8 health);
jmx_wan_iface_t *jmx_wan_find(u8 wan_id);
int  jmx_wan_get_count(void);
void jmx_wan_flow_account_rx(u8 wan_id, u32 generation, u64 bytes);
void jmx_wan_flow_release(u8 wan_id, u32 generation);

/* Direction-aware accounting.  is_reply selects the download column. */
void jmx_wan_flow_account(u8 wan_id, u32 generation, u8 cat_slot,
			  u64 bytes, bool is_reply);
void jmx_wan_flow_cat_acquire(u8 wan_id, u32 generation, u8 cat_slot);
void jmx_wan_flow_cat_release(u8 wan_id, u32 generation, u8 cat_slot);

/*
 * active_conn reconciliation.  The incremental gauge drifts upward because the
 * increment is unconditional while the decrement is gated on a generation
 * match, so a periodic walk of the conntrack table re-measures it instead.
 * Snapshot the generations first, walk without holding jmx_route_lock, then
 * assign; see the comments on both functions in jmx_route.c.
 */
void jmx_wan_active_conn_reconcile(const u64 *counts, const u64 *cat_counts,
				   const u32 *generations, u8 count);
u8   jmx_wan_generation_snapshot(u32 *generations, u8 count);

/* appid -> category slot map, pushed down from jmxd. */
int  jmx_app_cat_add(u32 appid, u16 db_category_id);
void jmx_app_cat_flush(void);
u8   jmx_app_cat_slot(u32 appid);
const char *jmx_app_cat_name(u8 cat_slot);
int  jmx_app_cat_map_count(void);

int  jmx_route_rule_add(const jmx_route_rule_t *rule);
void jmx_route_rule_del(u16 prio);
void jmx_route_rule_flush(void);
void jmx_route_rule_clear_hits(u16 prio);
int  jmx_carrier_prefix_add(u32 network, u32 mask, u8 carrier_id);
void jmx_carrier_prefix_flush(void);
u8   jmx_carrier_lookup(u32 ip);
int  jmx_route_select_wan(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port,
                          u8 proto, u32 appid, u32 *out_fwmark, u8 *out_wan_id,
                          u8 *out_route_source, u16 *out_rule_prio);
int  jmx_route_select_wan_acquire(u32 src_ip, u32 dst_ip, u16 src_port,
				  u16 dst_port, u8 proto, u32 appid,
				  u32 *out_fwmark, u8 *out_wan_id,
				  u8 *out_route_source, u16 *out_rule_prio,
				  u32 *out_wan_generation);
int  jmx_route_select_wan6(const struct in6_addr *src_ip,
			   const struct in6_addr *dst_ip, u16 src_port,
			   u16 dst_port, u8 proto, u32 appid,
			   u32 *out_fwmark, u8 *out_wan_id,
			   u8 *out_route_source, u16 *out_rule_prio);
int  jmx_route_select_wan6_acquire(const struct in6_addr *src_ip,
				   const struct in6_addr *dst_ip, u16 src_port,
				   u16 dst_port, u8 proto, u32 appid,
				   u32 *out_fwmark, u8 *out_wan_id,
				   u8 *out_route_source, u16 *out_rule_prio,
				   u32 *out_wan_generation);
int  jmx_route_init(void);
void jmx_route_exit(void);
int  jmx_route_init_procfs(void);
void jmx_route_exit_procfs(void);
#endif 
