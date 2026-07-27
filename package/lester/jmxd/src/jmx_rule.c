/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_rule.c - Rule set management
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "jmx_rule.h"

static inline uint32_t hash_appid(uint32_t appid)
{
	return appid % JMX_HASH_BUCKETS;
}

void jmx_rule_set_init(jmx_rule_set_t *rs)
{
	if (!rs) return;
	memset(rs, 0, sizeof(*rs));
}

void jmx_rule_set_free(jmx_rule_set_t *rs)
{
	uint32_t i;
	jmx_match_rule_t *m, *mn;
	jmx_nr_rule_t *n, *nn;

	if (!rs) return;

	for (i = 0; i < JMX_HASH_BUCKETS; i++) {
		for (m = rs->match_buckets[i]; m; m = mn) {
			mn = m->next;
			free(m);
		}
		rs->match_buckets[i] = NULL;

		for (n = rs->nr_buckets[i]; n; n = nn) {
			nn = n->next;
			free(n);
		}
		rs->nr_buckets[i] = NULL;
	}

	rs->match_count = 0;
	rs->nr_count = 0;
	rs->app_info_count = 0;
	rs->fast_rules = 0;
	rs->slow_rules = 0;
	rs->total_rules = 0;
}


/*
 * Detect overly broad "catch-all" regex patterns that would match almost any
 * non-empty payload, e.g. "^[^\x00].*[^\x00]$" or similar.
 * These patterns are meant as fallbacks but steal matches from specific rules
 * due to higher priority. Return 1 if the pattern is a catch-all.
 */
static int is_catchall_pattern(const char *str, int len)
{
    if (!str || len == 0) return 0;

    /* Single dot, dot-star, three dots */
    if (len == 1 && str[0] == '.') return 1;
    if (len == 2 && str[0] == '.' && str[1] == '*') return 1;
    if (len == 3 && str[0] == '.' && str[1] == '.' && str[2] == '.') return 1;

    /* [^\x00].*[^\x00] style catch-all */
    if (len >= 8) {
        int has_neg_null = 0, has_dot_star = 0, i;
        for (i = 0; i < len - 4; i++) {
            if (str[i] == '[' && str[i+1] == '^' && str[i+2] == '\\' &&
                str[i+3] == 'x' && str[i+4] == '0')
                has_neg_null = 1;
            if (i+1 < len && str[i] == '.' && str[i+1] == '*')
                has_dot_star = 1;
        }
        if (has_neg_null && has_dot_star) return 1;
    }

    /* Short alternation like (H|@) or (a|b) — too generic */
    if (len >= 3 && len <= 12 && str[0] == '(' && str[len-1] == ')') {
        int alt_count = 1, max_alt_len = 0, cur_len = 0, i;
        for (i = 1; i < len - 1; i++) {
            if (str[i] == '|') {
                alt_count++;
                if (cur_len > max_alt_len) max_alt_len = cur_len;
                cur_len = 0;
            } else {
                cur_len++;
            }
        }
        if (cur_len > max_alt_len) max_alt_len = cur_len;
        if (alt_count >= 2 && max_alt_len <= 2) return 1;
    }

    /* Count non-special literal chars — too few = too generic */
    {
        int lit = 0, i;
        for (i = 0; i < len; i++) {
            char c = str[i];
            if (c == '\\' && i + 1 < len) { i++; continue; }
            if (c == '.' || c == '*' || c == '+' || c == '?' || c == '[' ||
                c == ']' || c == '(' || c == ')' || c == '{' || c == '}' ||
                c == '|' || c == '^' || c == '$') continue;
            lit++;
        }
        if (lit < 3) return 1;
    }

    return 0;
}

static int is_unsafe_nofix_rule(const jmx_match_rule_t *rule)
{
    int i;
    if (!rule || rule->method != JMX_MATCH_NO_FIXED) return 0;

    /* NO_FIXED has no payload signature. Without both port and length, it is
     * just a metadata guess and causes massive false positives. */
    if (rule->port_count == 0 || rule->len_count == 0)
        return 1;

    for (i = 0; i < rule->port_count; i++) {
        uint16_t min = rule->ports[i].min_port;
        uint16_t max = rule->ports[i].max_port;
        if (min == 0 && max == 0) return 1;
        if (max > min && (uint32_t)max - min > 16) return 1;
        if (min == 80 || min == 443 || max == 80 || max == 443) return 1;
    }
    return 0;
}

int jmx_rule_set_add_match(jmx_rule_set_t *rs, const jmx_match_rule_t *rule)
{
	jmx_match_rule_t *copy;
	uint32_t bucket;

	if (!rs || !rule) return -1;
	if (rs->match_count >= JMX_MAX_RULES) return -2;

	/* Fixed matchers without a payload are invalid regardless of which loader
	 * produced them; silently accepting one can poison the whole generation. */
	if ((rule->method == JMX_MATCH_EXACT ||
	     rule->method == JMX_MATCH_BM_STR) && rule->match_len == 0)
		return 0;

	/* Skip unsafe NO_FIXED metadata-only guesses. Keep payload signatures as main signal. */
	if (is_unsafe_nofix_rule(rule))
		return 0;

	/* Skip overly broad patterns */
	if (rule->method == JMX_MATCH_REGEX && rule->match_len > 0) {
		if (is_catchall_pattern(rule->match_str, rule->match_len)) {
			return 0;
		}
	}

	copy = malloc(sizeof(jmx_match_rule_t));
	if (!copy) return -3;

	memcpy(copy, rule, sizeof(jmx_match_rule_t));
	copy->next = NULL;

	bucket = hash_appid(rule->appid);
	copy->next = rs->match_buckets[bucket];
	rs->match_buckets[bucket] = copy;
	rs->match_count++;
	rs->total_rules++;

	if (jmx_rule_is_fast_path(rule))
		rs->fast_rules++;
	else
		rs->slow_rules++;

	return 0;
}

int jmx_rule_set_add_nr(jmx_rule_set_t *rs, const jmx_nr_rule_t *rule)
{
	jmx_nr_rule_t *copy;
	uint32_t bucket;

	if (!rs || !rule) return -1;
	if (rs->nr_count >= JMX_MAX_NR_RULES) return -2;

	copy = malloc(sizeof(jmx_nr_rule_t));
	if (!copy) return -3;

	memcpy(copy, rule, sizeof(jmx_nr_rule_t));
	copy->next = NULL;

	bucket = hash_appid(rule->appid);
	copy->next = rs->nr_buckets[bucket];
	rs->nr_buckets[bucket] = copy;
	rs->nr_count++;

	return 0;
}

int jmx_rule_set_add_app_info(jmx_rule_set_t *rs, uint32_t appid, const char *name)
{
	if (!rs || !name) return -1;
	if (rs->app_info_count >= JMX_MAX_APP_INFOS) return -2;

	rs->app_info[rs->app_info_count].appid = appid;
	strncpy(rs->app_info[rs->app_info_count].name, name,
		JMX_MAX_APP_NAME_LEN - 1);
	rs->app_info[rs->app_info_count].name[JMX_MAX_APP_NAME_LEN - 1] = '\0';
	rs->app_info_count++;

	return 0;
}

const char *jmx_rule_set_app_name(const jmx_rule_set_t *rs, uint32_t appid)
{
	uint32_t i;
	if (!rs) return "unknown";

	for (i = 0; i < rs->app_info_count; i++) {
		if (rs->app_info[i].appid == appid)
			return rs->app_info[i].name;
	}
	return "unknown";
}

int jmx_rule_is_fast_path(const jmx_match_rule_t *rule)
{
	if (!rule) return 0;

	switch (rule->method) {
	case JMX_MATCH_EXACT:
	case JMX_MATCH_BM_STR:
	case JMX_MATCH_NO_FIXED:
		return 1;  /* kernel fast path */
	case JMX_MATCH_REGEX:
	default:
		return 0;  /* NFQUEUE slow path */
	}
}

void jmx_chain_rule_set_init(jmx_chain_rule_set_t *rs, uint32_t engine_caps)
{
	if (!rs)
		return;
	memset(rs, 0, sizeof(*rs));
	rs->engine_capabilities = engine_caps;
}

void jmx_chain_rule_set_free(jmx_chain_rule_set_t *rs)
{
	uint32_t engine_caps;

	if (!rs)
		return;
	engine_caps = rs->engine_capabilities;
	free(rs->rules);
	free(rs->steps);
	free(rs->ports);
	memset(rs, 0, sizeof(*rs));
	rs->engine_capabilities = engine_caps;
}

static int chain_reserve(void **items, size_t item_size, size_t *capacity,
			 size_t needed)
{
	size_t next;
	void *new_items;

	if (needed <= *capacity)
		return 0;
	next = *capacity ? *capacity : 32;
	while (next < needed) {
		if (next > SIZE_MAX / 2)
			return -1;
		next *= 2;
	}
	if (next > SIZE_MAX / item_size)
		return -1;
	new_items = realloc(*items, next * item_size);
	if (!new_items)
		return -1;
	*items = new_items;
	*capacity = next;
	return 0;
}

int jmx_chain_rule_set_add_rule(jmx_chain_rule_set_t *rs,
				const jmx_chain_rule_t *rule)
{
	if (!rs || !rule || !rule->signature_rule_id)
		return -1;
	if (chain_reserve((void **)&rs->rules, sizeof(*rs->rules),
			  &rs->rule_capacity, rs->rule_count + 1) != 0)
		return -1;
	rs->rules[rs->rule_count++] = *rule;
	return 0;
}

int jmx_chain_rule_set_add_step(jmx_chain_rule_set_t *rs,
				const jmx_chain_step_t *step)
{
	if (!rs || !step || !step->signature_rule_id)
		return -1;
	if (chain_reserve((void **)&rs->steps, sizeof(*rs->steps),
			  &rs->step_capacity, rs->step_count + 1) != 0)
		return -1;
	rs->steps[rs->step_count++] = *step;
	return 0;
}

int jmx_chain_rule_set_add_port(jmx_chain_rule_set_t *rs,
				const jmx_chain_port_t *port)
{
	if (!rs || !port || !port->signature_rule_id)
		return -1;
	if (chain_reserve((void **)&rs->ports, sizeof(*rs->ports),
			  &rs->port_capacity, rs->port_count + 1) != 0)
		return -1;
	rs->ports[rs->port_count++] = *port;
	return 0;
}

jmx_chain_rule_t *jmx_chain_rule_find(jmx_chain_rule_set_t *rs,
				      uint32_t signature_rule_id)
{
	size_t lo = 0, hi;

	if (!rs)
		return NULL;
	hi = rs->rule_count;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (rs->rules[mid].signature_rule_id == signature_rule_id)
			return &rs->rules[mid];
		if (rs->rules[mid].signature_rule_id < signature_rule_id)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

const jmx_chain_rule_t *jmx_chain_rule_find_const(const jmx_chain_rule_set_t *rs,
						 uint32_t signature_rule_id)
{
	return jmx_chain_rule_find((jmx_chain_rule_set_t *)rs, signature_rule_id);
}
