/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_v2_ac.h - Compact Aho-Corasick automaton for kernel DPI
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_V2_AC_H__
#define __JMX_V2_AC_H__

#include <linux/types.h>

typedef struct jmx_v2_ac jmx_v2_ac_t;

typedef struct {
	u32 appid;
	u32 priority;
	u8 proto;
	u8 dir;
	u8 method;
	u8 port_count;
	u8 len_count;
	u16 ports_min[8];
	u16 ports_max[8];
	u16 lens_min[4];
	u16 lens_max[4];
	u32 pkt_seq;
	s32 offset;
	u16 match_len;
	char match_str[256];
} jmx_v2_ac_pattern_t;

struct jmx_v2_ac_stats {
	u32 patterns;
	u32 nodes;
	u32 edges;
	u32 outputs;
	u32 duplicate_payloads;
};

int jmx_v2_ac_build(const jmx_v2_ac_pattern_t *pats, u32 count,
		    jmx_v2_ac_t **out_ac, struct jmx_v2_ac_stats *stats);
void jmx_v2_ac_free(jmx_v2_ac_t *ac);

u32 jmx_v2_ac_scan(const jmx_v2_ac_t *ac, const u8 *payload, u16 len,
		   u8 proto, u8 dir, u16 dport, u32 pkt_seq,
		   u32 *out_priority);
u32 jmx_v2_ac_count(const jmx_v2_ac_t *ac);

#endif
