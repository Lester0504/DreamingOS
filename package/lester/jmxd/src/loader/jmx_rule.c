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

int jmx_rule_set_add_match(jmx_rule_set_t *rs, const jmx_match_rule_t *rule)
{
	jmx_match_rule_t *copy;
	uint32_t bucket;

	if (!rs || !rule) return -1;
	if (rs->match_count >= JMX_MAX_RULES) return -2;

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
	if (rs->app_info_count >= 2048) return -2;

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
