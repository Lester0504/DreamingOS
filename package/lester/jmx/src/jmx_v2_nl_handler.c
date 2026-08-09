// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_v2_nl_handler.c - Netlink message handler for v2 binary rules + regex results
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/netfilter.h>
#include <linux/in6.h>
#include <net/netfilter/nf_conntrack.h>

#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "jmx_v2_rules.h"
#include "jmx_v2_nl_handler.h"
#include "jmx_conntrack.h"
#include "jmx_log.h"
#include "jmx_client.h"

#define JMX_NL_ACT_RULE_FLUSH      10
#define JMX_NL_ACT_RULE_ADD        11
#define JMX_NL_ACT_RULE_ADD_BATCH  12
#define JMX_NL_ACT_RULE_VERSION    13
#define JMX_NL_ACT_RULE_STATUS     14
#define JMX_NL_ACT_REGEX_RESULT    20
#define JMX_MATCH_STATUS_RELIABLE   0x4
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

struct jmx_nl_wan_register_v1 {
	int32_t action;
	u8 wan_id;
	char name[16];
	u32 fwmark;
	u32 table_id;
	u32 gateway;
} __packed;

struct jmx_nl_wan_register_v2 {
	int32_t action;
	u8 wan_id;
	char name[16];
	u32 fwmark;
	u32 table_id;
	u32 gateway;
	u32 weight;
} __packed;

static_assert(sizeof(struct jmx_nl_wan_register_v1) == 33);
static_assert(sizeof(struct jmx_nl_wan_register_v2) == 37);

/* Binary rule structure */
struct v2_nl_rule {
	uint32_t appid;
	uint32_t rule_id;
	uint32_t priority;
	uint8_t  method;
	uint8_t  proto;
	uint8_t  dir;
	uint8_t  port_count;
	uint8_t  len_count;
	uint8_t  _pad[3];
	uint32_t pkt_seq;
	int32_t  offset;
	uint16_t match_len;
	char     match_str[256];
	struct {
		uint16_t min_port;
		uint16_t max_port;
	} ports[8];
	struct {
		uint16_t min_len;
		uint16_t max_len;
	} len_range[4];
} __packed;

struct v2_batch_msg {
	int32_t  action;
	uint32_t count;
	uint32_t version;
	/* rules follow */
};

struct v2_version_msg {
	int32_t  action;
	uint32_t version;
};

struct v2_status_msg {
	int32_t  action;
	uint32_t request_action;
	uint32_t version;
	int32_t  status;
	uint32_t active_version;
	uint32_t active_rules;
} __packed;

static_assert(sizeof(struct v2_version_msg) == 8);
static_assert(sizeof(struct v2_status_msg) == 24);

/* Regex result from userspace */
struct v2_regex_result_msg {
	int32_t  action;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
	uint8_t  app_proto;
	uint8_t  af;
	uint8_t  _pad;
	uint32_t appid;
	uint8_t  host_len;
	uint8_t  _pad2[3];
	uint8_t  src_ip6[16];
	uint8_t  dst_ip6[16];
	char     host[128];
} __packed;

static int v2_send_version_ack(jmx_v3_nl_reply_fn reply, uint32_t portid,
					       uint32_t nlmsg_seq, uint32_t version,
					       int status)
{
	struct v2_status_msg ack;
	uint32_t active_version = 0, active_count = 0;

	if (!reply || !portid || !nlmsg_seq)
		return -EINVAL;
	jmx_v2_rules_get_status(&active_version, &active_count);
	memset(&ack, 0, sizeof(ack));
	ack.action = JMX_NL_ACT_RULE_STATUS;
	ack.request_action = JMX_NL_ACT_RULE_VERSION;
	ack.version = version;
	ack.status = status;
	ack.active_version = active_version;
	ack.active_rules = active_count;
	return reply(portid, nlmsg_seq, &ack, sizeof(ack));
}

static int v2_copy_rule(const struct v2_nl_rule *nr, jmx_v2_rule_t *kr)
{
	if (!nr || !kr)
		return -EINVAL;

	if (nr->match_len > sizeof(nr->match_str) ||
	    nr->port_count > ARRAY_SIZE(nr->ports) ||
	    nr->len_count > ARRAY_SIZE(nr->len_range))
		return -EINVAL;

	memset(kr, 0, sizeof(*kr));
	kr->appid = nr->appid;
	kr->rule_id = nr->rule_id;
	kr->priority = nr->priority;
	kr->method = nr->method;
	kr->proto = nr->proto;
	kr->dir = nr->dir;
	kr->port_count = nr->port_count;
	kr->len_count = nr->len_count;
	kr->pkt_seq = nr->pkt_seq;
	kr->offset = nr->offset;
	kr->match_len = nr->match_len;
	memcpy(kr->match_str, nr->match_str, kr->match_len);
	memcpy(kr->ports, nr->ports, sizeof(kr->ports[0]) * kr->port_count);
	memcpy(kr->len_range, nr->len_range, sizeof(kr->len_range[0]) * kr->len_count);

	return 0;
}

/*
 * Handle a v2 netlink message.
 * Returns 1 if handled, 0 if not.
 */
int jmx_v2_nl_handle(const char *data, int len, u32 portid,
		     u32 nlmsg_seq,
		     jmx_v3_nl_reply_fn reply)
{
	int32_t action;

	if (len < (int)sizeof(int32_t))
		return 0;

	memcpy(&action, data, sizeof(action));

	/* Decode legacy VERSION before the v3 fallback so the v2 commit path
	 * always produces the explicit generation/count ACK contract. */
	switch (action) {
	case JMX_NL_ACT_RULE_VERSION: {
		const struct v2_version_msg *vm = (const struct v2_version_msg *)data;
		int rc;
		if (len != (int)sizeof(struct v2_version_msg)) {
			v2_send_version_ack(reply, portid, nlmsg_seq, 0, -EMSGSIZE);
			return 1;
		}
		if (!portid || !nlmsg_seq) {
			pr_warn_ratelimited("jmx_v2: reject VERSION with sender portid=%u seq=%u\n",
				portid, nlmsg_seq);
			return 1;
		}
		rc = jmx_v2_rules_commit(portid, vm->version);
		if (rc != 0)
			pr_err("jmx_v2: generation %u commit rejected; previous generation remains active\n",
			       vm->version);
		if (v2_send_version_ack(reply, portid, nlmsg_seq, vm->version, rc) < 0)
			pr_warn_ratelimited("jmx_v2: VERSION ACK send failed portid=%u seq=%u status=%d\n",
				portid, nlmsg_seq, rc);
		return 1;
	}
	}

	if (jmx_v3_nl_handle(data, (uint32_t)len, portid, nlmsg_seq, reply))
		return 1;

	switch (action) {
	case JMX_NL_ACT_RULE_FLUSH: {
		int rc = jmx_v2_rules_begin(portid);

		if (rc)
			pr_warn_ratelimited("jmx_v2: FLUSH rejected owner=%u rc=%d\n",
					    portid, rc);
		else
			JMX_DEBUG_RATELIMITED(1,
				"jmx_v2: staging transaction started owner=%u\n",
				portid);
		return 1;
	}

	case JMX_NL_ACT_RULE_ADD: {
		const struct v2_nl_rule *nr;
		jmx_v2_rule_t kr;
		if (len < (int)(sizeof(int32_t) + sizeof(struct v2_nl_rule)))
			return 1;
		nr = (const struct v2_nl_rule *)(data + sizeof(int32_t));
		if (v2_copy_rule(nr, &kr) != 0) {
			jmx_v2_rule_add(portid, NULL);
			pr_warn_ratelimited("jmx_v2: invalid rule ignored\n");
			return 1;
		}
		if (jmx_v2_rule_add(portid, &kr) != 0)
			pr_warn_ratelimited("jmx_v2: rule add rejected\n");
		return 1;
	}

	case JMX_NL_ACT_RULE_ADD_BATCH: {
		const struct v2_batch_msg *bm = (const struct v2_batch_msg *)data;
		const struct v2_nl_rule *rules;
		uint32_t i, count;
		size_t expected;
		if (len < (int)sizeof(struct v2_batch_msg))
			return 1;
		count = bm->count;
		if (count > 1024) {
			jmx_v2_rule_add(portid, NULL);
			pr_err("jmx_v2: batch too large (%u)\n", count);
			return 1;
		}
		expected = sizeof(struct v2_batch_msg) + sizeof(struct v2_nl_rule) * count;
		if (len < (int)expected) {
			jmx_v2_rule_add(portid, NULL);
			pr_warn_ratelimited("jmx_v2: short batch len=%d count=%u\n", len, count);
			return 1;
		}
		rules = (const struct v2_nl_rule *)(data + sizeof(struct v2_batch_msg));
		for (i = 0; i < count; i++) {
			jmx_v2_rule_t kr;
			const struct v2_nl_rule *nr = &rules[i];
			if (v2_copy_rule(nr, &kr) != 0) {
				jmx_v2_rule_add(portid, NULL);
				pr_warn_ratelimited("jmx_v2: invalid batch rule ignored\n");
				continue;
			}
			if (jmx_v2_rule_add(portid, &kr) != 0)
				pr_warn_ratelimited("jmx_v2: batch rule add rejected\n");
		}
		JMX_DEBUG_RATELIMITED(1, "jmx_v2: batch added %u rules\n", count);
		return 1;
	}

	case JMX_NL_ACT_REGEX_RESULT: {
		/*
		 * Userspace regex/domain/DNS-cache engine found a match.
		 * IPv4 results refresh conntrack + af_conn + active_app; IPv6 results
		 * currently refresh active_app directly because af_conn is IPv4-only. */
		const struct v2_regex_result_msg *rm;
		uint8_t host_len;

		if (len < (int)sizeof(struct v2_regex_result_msg))
			return 1;

		rm = (const struct v2_regex_result_msg *)data;
		host_len = min_t(uint8_t, rm->host_len, sizeof(rm->host));

		if (rm->af == AF_INET6) {
			jmx_v2_update_active_app6_ex(rm->appid, rm->src_ip6, rm->dst_ip6,
							  rm->src_port, rm->dst_port, rm->proto,
							  rm->app_proto, rm->host, host_len);
			JMX_DEBUG_RATELIMITED(2, "jmx_v2: regex result appid=%u for [%pI6]:%u->[%pI6]:%u proto=%u\n",
				rm->appid, rm->src_ip6, rm->src_port, rm->dst_ip6, rm->dst_port, rm->proto);
			return 1;
		}

		{
			struct nf_conntrack_tuple tuple;
			struct nf_conntrack_tuple_hash *h;
			struct nf_conn *ct;
			struct net *net = &init_net;
			int ct_found;

			memset(&tuple, 0, sizeof(tuple));
			tuple.src.l3num = AF_INET;
			tuple.src.u3.ip = rm->src_ip;
			tuple.dst.u3.ip = rm->dst_ip;

			if (rm->proto == 6) { /* TCP */
				tuple.dst.protonum = IPPROTO_TCP;
				tuple.src.u.tcp.port = htons(rm->src_port);
				tuple.dst.u.tcp.port = htons(rm->dst_port);
			} else { /* UDP */
				tuple.dst.protonum = IPPROTO_UDP;
				tuple.src.u.udp.port = htons(rm->src_port);
				tuple.dst.u.udp.port = htons(rm->dst_port);
			}

			h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
			ct = h ? nf_ct_tuplehash_to_ctrack(h) : NULL;
			ct_found = ct ? 1 : 0;

			spin_lock(&af_conn_lock);
			{
				af_conn_t *afc = af_conn_find_and_add(rm->src_ip, rm->dst_ip,
								  rm->src_port, rm->dst_port, rm->proto);
				if (afc) {
					afc->app_id = rm->appid;
					afc->drop = 0;
					afc->last_jiffies = jiffies;
					afc->total_pkts++;
					afc->state = AF_CONN_DPI_FINISHED;
				}
			}
			spin_unlock(&af_conn_lock);

			jmx_v2_update_active_app_ex(rm->appid, rm->src_ip, rm->dst_ip,
						    rm->src_port, rm->dst_port, rm->proto,
						    rm->app_proto, rm->host,
						    host_len);

			/* Also update visiting_app for the LAN client.  A conntrack lookup
			 * can fail after NAT or when userspace reports a tuple direction that
			 * no longer matches, but the UI/audit view should still reflect the
			 * successful regex/DNS-cache classification. */
			if (g_record_enable) {
					af_client_info_t *cli = af_client_get_by_ip(rm->src_ip);
						if (!cli)
							cli = af_client_get_by_ip(rm->dst_ip);
						if (cli) {
							af_update_client_app_info(cli, rm->appid, 0, 0, 0);
							af_client_put(cli);
						}
					}

			if (ct) {
				ct->jmx_data.app_id = rm->appid;
				ct->jmx_data.match_status |= JMX_MATCH_STATUS_RELIABLE;
				nf_ct_put(ct);
			}
			JMX_DEBUG_RATELIMITED(2, "jmx_v2: regex result appid=%u for %pI4:%u->%pI4:%u proto=%u ct=%u\n",
				rm->appid,
				&rm->src_ip, rm->src_port,
				&rm->dst_ip, rm->dst_port,
				rm->proto, ct_found);
		}
		return 1;
	}



	case JMX_NL_ACT_CARRIER_FLUSH:
		jmx_carrier_prefix_flush();
		JMX_DEBUG_RATELIMITED(1, "jmx_route: carrier prefixes flushed\n");
		return 1;

	case JMX_NL_ACT_CARRIER_ADD: {
		struct { int32_t action; u32 network; u32 mask; u8 carrier_id; } __packed *m;
		if (len < (int)sizeof(*m)) return 1;
		m = (void *)data;
		jmx_carrier_prefix_add(m->network, m->mask, m->carrier_id);
		return 1;
	}

	case JMX_NL_ACT_APPCAT_FLUSH:
		jmx_app_cat_flush();
		JMX_DEBUG_RATELIMITED(1, "jmx_route: app category map flushed\n");
		return 1;

	case JMX_NL_ACT_APPCAT_ADD: {
		/* Batch payload: header then count x {appid, category_id}. */
		struct appcat_hdr { int32_t action; u32 count; } __packed;
		struct appcat_rec { u32 appid; u16 category_id; } __packed;
		const struct appcat_hdr *h;
		const struct appcat_rec *recs;
		u32 i, count, max_recs;
		int added = 0, rejected = 0;

		if (len < (int)sizeof(*h))
			return 1;
		h = (const void *)data;
		count = h->count;
		max_recs = (u32)((len - sizeof(*h)) / sizeof(*recs));
		if (count > max_recs) {
			pr_warn("jmx_route: appcat batch truncated count=%u payload=%u\n",
				count, max_recs);
			count = max_recs;
		}
		recs = (const void *)(data + sizeof(*h));
		for (i = 0; i < count; i++) {
			if (jmx_app_cat_add(recs[i].appid, recs[i].category_id))
				rejected++;
			else
				added++;
		}
		JMX_DEBUG_RATELIMITED(1,
			"jmx_route: appcat batch added=%d rejected=%d total=%d\n",
			added, rejected, jmx_app_cat_map_count());
		return 1;
	}

	case JMX_NL_ACT_WAN_REGISTER: {
		const struct jmx_nl_wan_register_v1 *m;
		u32 weight = 1;
		char name[17];
		int rc;

		if (len < (int)sizeof(*m))
			return 1;
		if (len > (int)sizeof(*m) &&
		    len < (int)sizeof(struct jmx_nl_wan_register_v2)) {
			pr_warn("jmx_route: malformed wan register len=%d\n", len);
			return 1;
		}
		m = (void *)data;
		memcpy(name, m->name, sizeof(m->name));
		name[sizeof(m->name)] = '\0';
		if (len >= (int)sizeof(struct jmx_nl_wan_register_v2))
			weight = ((const struct jmx_nl_wan_register_v2 *)data)->weight;
		rc = jmx_wan_register(m->wan_id, name, m->fwmark, m->table_id,
				      m->gateway, weight);
		if (rc)
			pr_warn("jmx_route: wan register rejected id=%u weight=%u rc=%d\n",
				m->wan_id, weight, rc);
		else
			JMX_DEBUG_RATELIMITED(1, "jmx_route: wan register id=%u name=%s fwmark=0x%x table=%u gw=%pI4 weight=%u\n",
				m->wan_id, name, m->fwmark, m->table_id, &m->gateway, weight);
		return 1;
	}

	case JMX_NL_ACT_WAN_UNREGISTER: {
		struct { int32_t action; u8 wan_id; } __packed *m;
		if (len < (int)sizeof(*m)) return 1;
		m = (void *)data;
		jmx_wan_unregister(m->wan_id);
		return 1;
	}

	case JMX_NL_ACT_WAN_HEALTH: {
		struct { int32_t action; u8 wan_id; u8 health; } __packed *m;
		if (len < (int)sizeof(*m)) return 1;
		m = (void *)data;
		jmx_wan_set_health(m->wan_id, m->health);
		return 1;
	}

	case JMX_NL_ACT_ROUTE_ADD: {
		struct { int32_t action; jmx_route_rule_t rule; } __packed *m;
		int rc;
		if (len < (int)sizeof(*m)) return 1;
		m = (void *)data;
		rc = jmx_route_rule_add(&m->rule);
		if (rc)
			pr_warn("jmx_route: rule rejected prio=%u mode=%u wans=%u rc=%d\n",
				m->rule.prio, m->rule.sticky_mode, m->rule.wan_count, rc);
		else
			JMX_DEBUG_RATELIMITED(1, "jmx_route: rule added prio=%u appid=%u mode=%u wans=%u\n",
				m->rule.prio, m->rule.appid, m->rule.sticky_mode, m->rule.wan_count);
		return 1;
	}

	case JMX_NL_ACT_ROUTE_DEL: {
		struct { int32_t action; u16 prio; } __packed *m;
		if (len < (int)sizeof(*m)) return 1;
		m = (void *)data;
		jmx_route_rule_del(m->prio);
		return 1;
	}


	case JMX_NL_ACT_ROUTE_CLEAR_HITS: {
		struct { int32_t action; u16 prio; } __packed *m;
		if (len < (int)sizeof(*m)) return 1;
		m = (void *)data;
		jmx_route_rule_clear_hits(m->prio);
		return 1;
	}

	case JMX_NL_ACT_ROUTE_FLUSH:
		jmx_route_rule_flush();
		JMX_DEBUG_RATELIMITED(1, "jmx_route: all rules flushed\n");
		return 1;

	default:
		return 0;
	}
}
