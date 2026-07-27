/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_V3_RULES_H__
#define __JMX_V3_RULES_H__

#include <linux/types.h>
#include "jmx_nl_rule_v3.h"

struct jmx_v3_snapshot {
	u32 capabilities;
	u32 active_generation;
	u32 active_rules;
	u32 active_steps;
	u32 active_ports;
	u32 active_mode;
	u8 active_catalog_digest[JMX_V3_CATALOG_DIGEST_LEN];
	u32 staging_generation;
	u32 staging_state;
};

int jmx_v3_rules_init(void);
void jmx_v3_rules_exit(void);
u32 jmx_v3_capabilities(void);
void jmx_v3_get_snapshot(struct jmx_v3_snapshot *snapshot);

int jmx_v3_tx_begin(u32 owner_portid, u32 generation,
			const struct jmx_nl_begin_v3 *begin, u32 flags,
			u32 *reason, u32 *detail);
int jmx_v3_tx_add_rules(u32 owner_portid, u32 generation,
			const struct jmx_nl_rule_v3 *records, u32 count,
			u32 *reason, u32 *detail);
int jmx_v3_tx_add_steps(u32 owner_portid, u32 generation,
			const struct jmx_nl_step_v3 *records, u32 count,
			u32 *reason, u32 *detail);
int jmx_v3_tx_add_ports(u32 owner_portid, u32 generation,
			const struct jmx_nl_port_v3 *records, u32 count,
			u32 *reason, u32 *detail);
int jmx_v3_tx_commit(u32 owner_portid, u32 generation,
			 u32 *reason, u32 *detail);
int jmx_v3_tx_abort(u32 owner_portid, u32 generation,
			u32 *reason, u32 *detail);
void jmx_v3_tx_fail(u32 owner_portid, u32 generation,
		    u32 reason, u32 detail);

u32 jmx_v3_match_payload(const u8 *payload, u32 len,
			 u8 proto, u8 dir, u16 sport, u16 dport,
			 u32 *out_priority, u8 *out_mode);
u32 jmx_v3_appid_for_commit(u32 appid, u8 mode);

#endif /* __JMX_V3_RULES_H__ */
