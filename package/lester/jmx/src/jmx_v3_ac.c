// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include "jmx_v3_ac.h"

#define V3_AC_NONE U32_MAX

struct v3_ac_node {
	u32 fail;
	u32 dict_suffix;
	u32 edge_begin;
	u32 output_begin;
	u16 edge_count;
	u16 output_count;
};

struct v3_ac_edge {
	u32 target;
	u8 byte;
};

struct v3_ac_output {
	u32 rule_index;
	u16 step_index;
	u16 pattern_len;
};

struct v3_build_node {
	u32 first_edge;
	u32 first_output;
	u32 fail;
	u32 dict_suffix;
	u32 edge_count;
	u32 output_count;
};

struct v3_build_edge {
	u32 next;
	u32 target;
	u8 byte;
};

struct v3_build_output {
	u32 next;
	u32 rule_index;
	u16 step_index;
	u16 pattern_len;
};

struct jmx_v3_ac {
	struct v3_ac_node *nodes;
	struct v3_ac_edge *edges;
	struct v3_ac_output *outputs;
	u32 root_next[256];
	u32 node_count;
	u32 edge_count;
	u32 output_count;
};

static u8 v3_fold(u8 byte)
{
	return byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte;
}

static u32 build_find_child(const struct v3_build_node *nodes,
			    const struct v3_build_edge *edges,
			    u32 node, u8 byte)
{
	u32 edge = nodes[node].first_edge;

	while (edge != V3_AC_NONE) {
		if (edges[edge].byte == byte)
			return edges[edge].target;
		edge = edges[edge].next;
	}
	return V3_AC_NONE;
}

static int find_child(const struct jmx_v3_ac *ac, u32 node, u8 byte,
		      u32 *target, u32 *work_budget)
{
	const struct v3_ac_node *n = &ac->nodes[node];
	int lo = 0, hi = (int)n->edge_count - 1;

	while (lo <= hi) {
		int mid = (lo + hi) >> 1;
		const struct v3_ac_edge *edge = &ac->edges[n->edge_begin + mid];

		if (!*work_budget)
			return -E2BIG;
		(*work_budget)--;
		if (edge->byte == byte) {
			*target = edge->target;
			return 1;
		}
		if (edge->byte < byte)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	*target = V3_AC_NONE;
	return 0;
}

static void sort_edges(struct v3_ac_edge *edges, u32 count)
{
	u32 i;

	for (i = 1; i < count; i++) {
		struct v3_ac_edge value = edges[i];
		u32 j = i;

		while (j > 0 && edges[j - 1].byte > value.byte) {
			edges[j] = edges[j - 1];
			j--;
		}
		edges[j] = value;
	}
}

int jmx_v3_ac_build(const struct jmx_v3_ac_pattern *patterns, u32 count,
			    struct jmx_v3_ac **out,
			    struct jmx_v3_ac_stats *stats)
{
	struct v3_build_node *bnodes = NULL;
	struct v3_build_edge *bedges = NULL;
	struct v3_build_output *boutputs = NULL;
	struct jmx_v3_ac *ac = NULL;
	u32 *queue = NULL;
	u32 max_nodes = 1, nodes = 1, edges = 0, outputs = 0;
	u32 qh = 0, qt = 0, duplicates = 0;
	u32 i, j;
	int rc = -ENOMEM;

	if (!out || !patterns || !count)
		return -EINVAL;
	*out = NULL;
	if (stats)
		memset(stats, 0, sizeof(*stats));
	for (i = 0; i < count; i++) {
		if (!patterns[i].len || patterns[i].len > JMX_V3_PAYLOAD_MAX)
			return -EINVAL;
		if (check_add_overflow(max_nodes, (u32)patterns[i].len, &max_nodes))
			return -EOVERFLOW;
	}

	bnodes = kvmalloc_array(max_nodes, sizeof(*bnodes), GFP_KERNEL | __GFP_ZERO);
	bedges = kvmalloc_array(max_nodes - 1, sizeof(*bedges), GFP_KERNEL);
	boutputs = kvmalloc_array(count, sizeof(*boutputs), GFP_KERNEL);
	if (!bnodes || !bedges || !boutputs)
		goto out;
	for (i = 0; i < max_nodes; i++) {
		bnodes[i].first_edge = V3_AC_NONE;
		bnodes[i].first_output = V3_AC_NONE;
		bnodes[i].dict_suffix = V3_AC_NONE;
	}

	for (i = 0; i < count; i++) {
		u32 node = 0;

		for (j = 0; j < patterns[i].len; j++) {
			u8 byte = v3_fold(patterns[i].bytes[j]);
			u32 child = build_find_child(bnodes, bedges, node, byte);

			if (child == V3_AC_NONE) {
				if (nodes >= max_nodes || edges >= max_nodes - 1) {
					rc = -EOVERFLOW;
					goto out;
				}
				child = nodes++;
				bedges[edges].byte = byte;
				bedges[edges].target = child;
				bedges[edges].next = bnodes[node].first_edge;
				bnodes[node].first_edge = edges++;
				bnodes[node].edge_count++;
			}
			node = child;
		}
		if (bnodes[node].output_count)
			duplicates++;
		if (bnodes[node].output_count == U16_MAX) {
			rc = -EOVERFLOW;
			goto out;
		}
		boutputs[outputs].rule_index = patterns[i].rule_index;
		boutputs[outputs].step_index = patterns[i].step_index;
		boutputs[outputs].pattern_len = patterns[i].len;
		boutputs[outputs].next = bnodes[node].first_output;
		bnodes[node].first_output = outputs++;
		bnodes[node].output_count++;
	}

	queue = kvmalloc_array(nodes, sizeof(*queue), GFP_KERNEL);
	if (!queue)
		goto out;
	for (i = bnodes[0].first_edge; i != V3_AC_NONE; i = bedges[i].next) {
		u32 child = bedges[i].target;
		bnodes[child].fail = 0;
		queue[qt++] = child;
	}
	while (qh < qt) {
		u32 node = queue[qh++];
		u32 edge;

		for (edge = bnodes[node].first_edge; edge != V3_AC_NONE;
		     edge = bedges[edge].next) {
			u8 byte = bedges[edge].byte;
			u32 child = bedges[edge].target;
			u32 failure = bnodes[node].fail;
			u32 transition = V3_AC_NONE;

			while (failure) {
				transition = build_find_child(bnodes, bedges, failure, byte);
				if (transition != V3_AC_NONE)
					break;
				failure = bnodes[failure].fail;
			}
			if (transition == V3_AC_NONE)
				transition = build_find_child(bnodes, bedges, 0, byte);
			if (transition == V3_AC_NONE || transition == child)
				transition = 0;
			bnodes[child].fail = transition;
			bnodes[child].dict_suffix = bnodes[transition].output_count ?
				transition : bnodes[transition].dict_suffix;
			queue[qt++] = child;
		}
	}

	ac = kzalloc(sizeof(*ac), GFP_KERNEL);
	if (!ac)
		goto out;
	ac->nodes = kvcalloc(nodes, sizeof(*ac->nodes), GFP_KERNEL);
	ac->edges = kvmalloc_array(edges, sizeof(*ac->edges), GFP_KERNEL);
	ac->outputs = kvmalloc_array(outputs, sizeof(*ac->outputs), GFP_KERNEL);
	if (!ac->nodes || !ac->edges || !ac->outputs)
		goto out;
	ac->node_count = nodes;
	ac->edge_count = edges;
	ac->output_count = outputs;

	edges = 0;
	outputs = 0;
	for (i = 0; i < nodes; i++) {
		u32 item;
		ac->nodes[i].fail = bnodes[i].fail;
		ac->nodes[i].dict_suffix = bnodes[i].dict_suffix;
		ac->nodes[i].edge_begin = edges;
		ac->nodes[i].output_begin = outputs;
		ac->nodes[i].edge_count = bnodes[i].edge_count;
		ac->nodes[i].output_count = bnodes[i].output_count;
		for (item = bnodes[i].first_edge; item != V3_AC_NONE;
		     item = bedges[item].next) {
			ac->edges[edges].byte = bedges[item].byte;
			ac->edges[edges].target = bedges[item].target;
			edges++;
		}
		sort_edges(&ac->edges[ac->nodes[i].edge_begin],
		   ac->nodes[i].edge_count);
		if (!i) {
			for (j = 0; j < ac->nodes[i].edge_count; j++) {
				const struct v3_ac_edge *edge =
					&ac->edges[ac->nodes[i].edge_begin + j];

				ac->root_next[edge->byte] = edge->target;
			}
		}
		for (item = bnodes[i].first_output; item != V3_AC_NONE;
		     item = boutputs[item].next) {
			ac->outputs[outputs].rule_index = boutputs[item].rule_index;
			ac->outputs[outputs].step_index = boutputs[item].step_index;
			ac->outputs[outputs].pattern_len = boutputs[item].pattern_len;
			outputs++;
		}
	}
	if (stats) {
		stats->patterns = count;
		stats->nodes = nodes;
		stats->edges = edges;
		stats->outputs = outputs;
		stats->duplicate_payloads = duplicates;
	}
	*out = ac;
	ac = NULL;
	rc = 0;
out:
	if (ac)
		jmx_v3_ac_free(ac);
	kvfree(queue);
	kvfree(boutputs);
	kvfree(bedges);
	kvfree(bnodes);
	return rc;
}

void jmx_v3_ac_free(struct jmx_v3_ac *ac)
{
	if (!ac)
		return;
	kvfree(ac->nodes);
	kvfree(ac->edges);
	kvfree(ac->outputs);
	kfree(ac);
}

static int emit_node(const struct jmx_v3_ac *ac, u32 node, u32 end,
		     jmx_v3_ac_emit_fn emit, void *context, u32 *work_budget)
{
	const struct v3_ac_node *n = &ac->nodes[node];
	u32 i;

	for (i = 0; i < n->output_count; i++) {
		const struct v3_ac_output *out = &ac->outputs[n->output_begin + i];
		int rc;

		if (end < out->pattern_len)
			continue;
		if (!*work_budget)
			return -E2BIG;
		(*work_budget)--;
		rc = emit(context, out->rule_index, out->step_index,
			  end - out->pattern_len, end, work_budget);
		if (rc)
			return rc;
	}
	return 0;
}

int jmx_v3_ac_scan(const struct jmx_v3_ac *ac, const u8 *payload, u32 len,
			   jmx_v3_ac_emit_fn emit, void *context,
			   u32 *work_budget)
{
	u32 state = 0, pos;

	if (!ac || !payload || !len || !emit || !work_budget)
		return -EINVAL;
	for (pos = 0; pos < len; pos++) {
		u32 next, output_node;
		u8 byte = v3_fold(payload[pos]);
		int found, rc;

		if (!*work_budget)
			return -E2BIG;
		(*work_budget)--;

		while (state) {
			found = find_child(ac, state, byte, &next, work_budget);
			if (found < 0)
				return found;
			if (found)
				goto found;
			if (!*work_budget)
				return -E2BIG;
			(*work_budget)--;
			state = ac->nodes[state].fail;
		}
		state = ac->root_next[byte];
		goto emit;
found:
		state = next;
emit:
		output_node = state;
		while (output_node != V3_AC_NONE) {
			rc = emit_node(ac, output_node, pos + 1, emit, context,
				       work_budget);
			if (rc)
				return rc;
			output_node = ac->nodes[output_node].dict_suffix;
		}
	}
	return 0;
}
