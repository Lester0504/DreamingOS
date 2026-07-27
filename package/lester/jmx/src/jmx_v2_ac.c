// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_v2_ac.c - Compact Aho-Corasick automaton for kernel DPI
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include "jmx_v2_ac.h"

#define AC_NONE U32_MAX

struct ac_node {
	u32 fail;
	u32 dict_suffix;
	u32 edge_begin;
	u32 output_begin;
	u16 edge_count;
	u16 output_count;
};

struct ac_edge {
	u32 target;
	u8 byte;
};

struct ac_output {
	u32 pattern_index;
};

struct ac_build_node {
	u32 first_edge;
	u32 first_output;
	u32 fail;
	u32 dict_suffix;
	u32 edge_count;
	u32 output_count;
};

struct ac_build_edge {
	u32 next;
	u32 target;
	u8 byte;
};

struct ac_build_output {
	u32 next;
	u32 pattern_index;
};

struct jmx_v2_ac {
	struct ac_node *nodes;
	struct ac_edge *edges;
	struct ac_output *outputs;
	jmx_v2_ac_pattern_t *pats;
	u32 node_count;
	u32 edge_count;
	u32 output_count;
	u32 pat_count;
};

static u32 build_find_child(const struct ac_build_node *nodes,
			    const struct ac_build_edge *edges,
			    u32 node, u8 byte)
{
	u32 edge = nodes[node].first_edge;

	while (edge != AC_NONE) {
		if (edges[edge].byte == byte)
			return edges[edge].target;
		edge = edges[edge].next;
	}
	return AC_NONE;
}

static u32 find_child(const jmx_v2_ac_t *ac, u32 node, u8 byte)
{
	const struct ac_node *n = &ac->nodes[node];
	int lo = 0, hi = (int)n->edge_count - 1;

	while (lo <= hi) {
		int mid = (lo + hi) >> 1;
		const struct ac_edge *edge = &ac->edges[n->edge_begin + mid];

		if (edge->byte == byte)
			return edge->target;
		if (edge->byte < byte)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return AC_NONE;
}

static void sort_edges(struct ac_edge *edges, u32 count)
{
	u32 i;

	/* A trie node has at most 256 byte-labelled edges. */
	for (i = 1; i < count; i++) {
		struct ac_edge value = edges[i];
		u32 j = i;

		while (j > 0 && edges[j - 1].byte > value.byte) {
			edges[j] = edges[j - 1];
			j--;
		}
		edges[j] = value;
	}
}

static void emit_node(const jmx_v2_ac_t *ac, u32 node, u32 pos, u16 len,
		      u8 proto, u8 dir, u16 dport, u32 pkt_seq,
		      u32 *best, u32 *best_pri)
{
	const struct ac_node *n = &ac->nodes[node];
	u32 i;

	for (i = 0; i < n->output_count; i++) {
		const struct ac_output *out = &ac->outputs[n->output_begin + i];
		const jmx_v2_ac_pattern_t *p = &ac->pats[out->pattern_index];
		u32 start;
		int m, matched;

		if (pos + 1 < p->match_len)
			continue;
		start = pos + 1 - p->match_len;

		if (p->proto != 0 && !(p->proto & proto))
			continue;
		if (p->dir != 0 && p->dir != dir)
			continue;
		/* Legacy EXACT means the literal is the complete packet payload. */
		if (p->method == 0 && p->match_len != len)
			continue;
		if (p->offset >= 0 && start != (u32)p->offset)
			continue;
		if (p->pkt_seq && (pkt_seq == 0 || pkt_seq > 32 ||
				   !(p->pkt_seq & (1U << (pkt_seq - 1)))))
			continue;

		if (p->port_count > 0) {
			matched = 0;
			for (m = 0; m < p->port_count; m++) {
				if (dport >= p->ports_min[m] &&
				    dport <= p->ports_max[m]) {
					matched = 1;
					break;
				}
			}
			if (!matched)
				continue;
		}

		if (p->len_count > 0) {
			matched = 0;
			for (m = 0; m < p->len_count; m++) {
				if (len >= p->lens_min[m] &&
				    len <= p->lens_max[m]) {
					matched = 1;
					break;
				}
			}
			if (!matched)
				continue;
		}

		if (p->priority < *best_pri) {
			*best_pri = p->priority;
			*best = p->appid;
		}
	}
}

int jmx_v2_ac_build(const jmx_v2_ac_pattern_t *pats, u32 count,
		    jmx_v2_ac_t **out_ac, struct jmx_v2_ac_stats *stats)
{
	struct ac_build_node *bnodes = NULL;
	struct ac_build_edge *bedges = NULL;
	struct ac_build_output *boutputs = NULL;
	jmx_v2_ac_t *ac = NULL;
	u32 *queue = NULL;
	u32 max_nodes = 1, node_count = 1, edge_count = 0, output_count = 0;
	u32 qh = 0, qt = 0, duplicate_payloads = 0;
	u32 i, j;
	int rc = -ENOMEM;

	if (!out_ac || !pats || count == 0)
		return -EINVAL;
	*out_ac = NULL;
	if (stats)
		memset(stats, 0, sizeof(*stats));

	for (i = 0; i < count; i++) {
		if (pats[i].match_len == 0)
			return -EINVAL;
		if (check_add_overflow(max_nodes, (u32)pats[i].match_len,
				       &max_nodes))
			return -EOVERFLOW;
	}

	bnodes = kvmalloc_array(max_nodes, sizeof(*bnodes), GFP_KERNEL | __GFP_ZERO);
	bedges = kvmalloc_array(max_nodes - 1, sizeof(*bedges), GFP_KERNEL);
	boutputs = kvmalloc_array(count, sizeof(*boutputs), GFP_KERNEL);
	if (!bnodes || !bedges || !boutputs)
		goto out;

	for (i = 0; i < max_nodes; i++) {
		bnodes[i].first_edge = AC_NONE;
		bnodes[i].first_output = AC_NONE;
		bnodes[i].dict_suffix = AC_NONE;
	}

	for (i = 0; i < count; i++) {
		u32 node = 0;

		for (j = 0; j < pats[i].match_len; j++) {
			u8 byte = (u8)pats[i].match_str[j];
			u32 child = build_find_child(bnodes, bedges, node, byte);

			if (child == AC_NONE) {
				if (node_count >= max_nodes || edge_count >= max_nodes - 1) {
					rc = -EOVERFLOW;
					goto out;
				}
				child = node_count++;
				bedges[edge_count].byte = byte;
				bedges[edge_count].target = child;
				bedges[edge_count].next = bnodes[node].first_edge;
				bnodes[node].first_edge = edge_count++;
				bnodes[node].edge_count++;
			}
			node = child;
		}

		if (bnodes[node].output_count > 0)
			duplicate_payloads++;
		if (bnodes[node].output_count == U16_MAX) {
			rc = -EOVERFLOW;
			goto out;
		}
		boutputs[output_count].pattern_index = i;
		boutputs[output_count].next = bnodes[node].first_output;
		bnodes[node].first_output = output_count++;
		bnodes[node].output_count++;
	}

	queue = kvmalloc_array(node_count, sizeof(*queue), GFP_KERNEL);
	if (!queue)
		goto out;

	for (i = bnodes[0].first_edge; i != AC_NONE; i = bedges[i].next) {
		u32 child = bedges[i].target;

		bnodes[child].fail = 0;
		bnodes[child].dict_suffix = AC_NONE;
		queue[qt++] = child;
	}

	while (qh < qt) {
		u32 node_index = queue[qh++];
		u32 edge;

		for (edge = bnodes[node_index].first_edge; edge != AC_NONE;
		     edge = bedges[edge].next) {
			u8 byte = bedges[edge].byte;
			u32 child = bedges[edge].target;
			u32 failure = bnodes[node_index].fail;
			u32 transition = AC_NONE;

			while (failure != 0) {
				transition = build_find_child(bnodes, bedges, failure, byte);
				if (transition != AC_NONE)
					break;
				failure = bnodes[failure].fail;
			}
			if (transition == AC_NONE)
				transition = build_find_child(bnodes, bedges, 0, byte);
			if (transition == AC_NONE || transition == child)
				transition = 0;

			bnodes[child].fail = transition;
			if (bnodes[transition].output_count > 0)
				bnodes[child].dict_suffix = transition;
			else
				bnodes[child].dict_suffix = bnodes[transition].dict_suffix;
			queue[qt++] = child;
		}
	}

	ac = kzalloc(sizeof(*ac), GFP_KERNEL);
	if (!ac)
		goto out;
	ac->nodes = kvcalloc(node_count, sizeof(*ac->nodes), GFP_KERNEL);
	ac->edges = kvmalloc_array(edge_count, sizeof(*ac->edges), GFP_KERNEL);
	ac->outputs = kvmalloc_array(output_count, sizeof(*ac->outputs), GFP_KERNEL);
	ac->pats = kvmalloc_array(count, sizeof(*ac->pats), GFP_KERNEL);
	if (!ac->nodes || !ac->edges || !ac->outputs || !ac->pats)
		goto out;

	ac->node_count = node_count;
	ac->edge_count = edge_count;
	ac->output_count = output_count;
	ac->pat_count = count;
	memcpy(ac->pats, pats, sizeof(*pats) * count);

	edge_count = 0;
	output_count = 0;
	for (i = 0; i < node_count; i++) {
		u32 item;

		ac->nodes[i].fail = bnodes[i].fail;
		ac->nodes[i].dict_suffix = bnodes[i].dict_suffix;
		ac->nodes[i].edge_begin = edge_count;
		ac->nodes[i].output_begin = output_count;
		ac->nodes[i].edge_count = bnodes[i].edge_count;
		ac->nodes[i].output_count = bnodes[i].output_count;

		for (item = bnodes[i].first_edge; item != AC_NONE;
		     item = bedges[item].next) {
			ac->edges[edge_count].byte = bedges[item].byte;
			ac->edges[edge_count].target = bedges[item].target;
			edge_count++;
		}
		sort_edges(&ac->edges[ac->nodes[i].edge_begin],
			   ac->nodes[i].edge_count);

		for (item = bnodes[i].first_output; item != AC_NONE;
		     item = boutputs[item].next) {
			ac->outputs[output_count].pattern_index =
				boutputs[item].pattern_index;
			output_count++;
		}
	}

	if (stats) {
		stats->patterns = count;
		stats->nodes = node_count;
		stats->edges = edge_count;
		stats->outputs = output_count;
		stats->duplicate_payloads = duplicate_payloads;
	}
	*out_ac = ac;
	ac = NULL;
	rc = 0;

	pr_info("jmx_ac: patterns=%u nodes=%u edges=%u outputs=%u duplicate_payloads=%u\n",
		count, node_count, edge_count, output_count, duplicate_payloads);

out:
	if (ac)
		jmx_v2_ac_free(ac);
	kvfree(queue);
	kvfree(boutputs);
	kvfree(bedges);
	kvfree(bnodes);
	return rc;
}

void jmx_v2_ac_free(jmx_v2_ac_t *ac)
{
	if (!ac)
		return;
	kvfree(ac->nodes);
	kvfree(ac->edges);
	kvfree(ac->outputs);
	kvfree(ac->pats);
	kfree(ac);
}

u32 jmx_v2_ac_scan(const jmx_v2_ac_t *ac, const u8 *payload, u16 len,
		   u8 proto, u8 dir, u16 dport, u32 pkt_seq,
		   u32 *out_priority)
{
	u32 state = 0, best = 0, best_pri = U32_MAX;
	u32 pos;

	if (!ac || ac->pat_count == 0 || !payload)
		return 0;

	for (pos = 0; pos < len; pos++) {
		u32 next;
		u32 output_node;

		while (state != 0) {
			next = find_child(ac, state, payload[pos]);
			if (next != AC_NONE)
				goto transition_found;
			state = ac->nodes[state].fail;
		}
		next = find_child(ac, 0, payload[pos]);
		state = next == AC_NONE ? 0 : next;
		goto emit;

transition_found:
		state = next;
emit:
		output_node = state;
		while (output_node != AC_NONE) {
			emit_node(ac, output_node, pos, len, proto, dir, dport,
				  pkt_seq, &best, &best_pri);
			output_node = ac->nodes[output_node].dict_suffix;
		}
	}

	if (out_priority)
		*out_priority = best_pri;
	return best;
}

u32 jmx_v2_ac_count(const jmx_v2_ac_t *ac)
{
	return ac ? ac->pat_count : 0;
}
