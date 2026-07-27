/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_V3_AC_H__
#define __JMX_V3_AC_H__

#include <linux/types.h>
#include "jmx_nl_rule_v3.h"

struct jmx_v3_ac;

struct jmx_v3_ac_pattern {
	u32 rule_index;
	u16 step_index;
	u16 len;
	u8 bytes[JMX_V3_PAYLOAD_MAX];
};

struct jmx_v3_ac_stats {
	u32 patterns;
	u32 nodes;
	u32 edges;
	u32 outputs;
	u32 duplicate_payloads;
};

typedef int (*jmx_v3_ac_emit_fn)(void *context, u32 rule_index,
					 u16 step_index, u32 start, u32 end,
					 u32 *work_budget);

int jmx_v3_ac_build(const struct jmx_v3_ac_pattern *patterns, u32 count,
			    struct jmx_v3_ac **out,
			    struct jmx_v3_ac_stats *stats);
void jmx_v3_ac_free(struct jmx_v3_ac *ac);
int jmx_v3_ac_scan(const struct jmx_v3_ac *ac, const u8 *payload, u32 len,
			   jmx_v3_ac_emit_fn emit, void *context,
			   u32 *work_budget);

#endif /* __JMX_V3_AC_H__ */
