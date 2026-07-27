// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_domain.c - Domain group classification for DPI
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Loads iKuai domaingroup txt files and provides O(1) domain lookup.
 * Supports reverse matching: "sub.example.com" matches entry "example.com"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include "jmx_domain.h"

/* ── Hash table ── */

static jmx_domain_entry_t *g_buckets[JMX_DOMAIN_HASH_BUCKETS];
static uint32_t g_entry_count;

/* Groups */
static jmx_domain_group_t g_groups[JMX_DOMAIN_MAX_GROUPS];
static uint32_t g_group_count;
static uint16_t g_next_group_id = 1;

/* ── Hash function (djb2) ── */

static uint32_t domain_hash(const char *s, int len)
{
	uint32_t h = 5381;
	int i;
	for (i = 0; i < len; i++)
		h = ((h << 5) + h) + (uint8_t)tolower(s[i]);
	return h % JMX_DOMAIN_HASH_BUCKETS;
}

/* ── Group management ── */

static uint16_t get_or_create_group(const char *name)
{
	uint32_t i;
	for (i = 0; i < g_group_count; i++) {
		if (strncmp(g_groups[i].name, name, JMX_DOMAIN_MAX_NAME - 1) == 0)
			return g_groups[i].id;
	}
	if (g_group_count >= JMX_DOMAIN_MAX_GROUPS)
		return 0;
	g_groups[g_group_count].id = g_next_group_id;
	strncpy(g_groups[g_group_count].name, name, JMX_DOMAIN_MAX_NAME - 1);
	g_groups[g_group_count].name[JMX_DOMAIN_MAX_NAME - 1] = '\0';
	g_group_count++;
	return g_next_group_id++;
}

/* ── Init / Exit ── */

int jmx_domain_init(void)
{
	memset(g_buckets, 0, sizeof(g_buckets));
	g_entry_count = 0;
	g_group_count = 0;
	g_next_group_id = 1;
	return 0;
}

void jmx_domain_exit(void)
{
	uint32_t i;
	jmx_domain_entry_t *e, *tmp;
	for (i = 0; i < JMX_DOMAIN_HASH_BUCKETS; i++) {
		for (e = g_buckets[i]; e; e = tmp) {
			tmp = e->next;
			free(e);
		}
		g_buckets[i] = NULL;
	}
	g_entry_count = 0;
	g_group_count = 0;
}

/* ── Add domain ── */

static int add_domain(const char *domain, int domain_len, uint16_t group_id)
{
	jmx_domain_entry_t *e;
	uint32_t h;

	if (domain_len <= 0 || domain_len >= JMX_DOMAIN_MAX_NAME)
		return -1;
	if (g_entry_count >= JMX_DOMAIN_MAX_ENTRIES)
		return -2;

	e = malloc(sizeof(jmx_domain_entry_t));
	if (!e) return -3;

	/* Store lowercase */
	int i;
	for (i = 0; i < domain_len; i++)
		e->domain[i] = tolower(domain[i]);
	e->domain[domain_len] = '\0';
	e->group_id = group_id;

	h = domain_hash(domain, domain_len);
	e->next = g_buckets[h];
	g_buckets[h] = e;
	g_entry_count++;
	return 0;
}

/* ── Load a single domaingroup txt file ── */

static int load_group_file(const char *path, const char *group_name)
{
	FILE *f;
	char line[256];
	uint16_t gid;
	int count = 0;

	gid = get_or_create_group(group_name);
	if (gid == 0) return -1;

	f = fopen(path, "r");
	if (!f) return -1;

	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		char *space;
		int dlen;

		/* Skip comments and empty lines */
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\0' || *p == '\n') continue;

		/* domain is first token (before space) */
		space = strchr(p, ' ');
		if (space)
			dlen = space - p;
		else {
			dlen = strlen(p);
			while (dlen > 0 && (p[dlen-1] == '\n' || p[dlen-1] == '\r'))
				dlen--;
		}

		if (dlen > 0 && add_domain(p, dlen, gid) == 0)
			count++;
	}

	fclose(f);
	return count;
}

/* ── Load directory ── */

int jmx_domain_load_dir(const char *dir_path)
{
	DIR *d;
	struct dirent *ent;
	char path[512];
	char group_name[128];
	int total = 0;

	d = opendir(dir_path);
	if (!d) {
		fprintf(stderr, "domain: cannot open dir %s\n", dir_path);
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		int nlen = strlen(ent->d_name);
		if (nlen < 5) continue;
		if (strcmp(ent->d_name + nlen - 4, ".txt") != 0) continue;

		/* Extract group name from filename: "Category-Subcategory.txt" */
		snprintf(path, sizeof(path), "%s/%s", dir_path, ent->d_name);
		strncpy(group_name, ent->d_name, sizeof(group_name) - 1);
		group_name[sizeof(group_name) - 1] = '\0';
		/* Remove .txt extension */
		group_name[nlen - 4] = '\0';

		int ret = load_group_file(path, group_name);
		if (ret > 0) {
			total += ret;
			fprintf(stderr, "domain: loaded %s (%d domains)\n",
				group_name, ret);
		}
	}

	closedir(d);
	fprintf(stderr, "domain: total %u domains in %u groups\n",
		g_entry_count, g_group_count);
	return total;
}

/* ── Match ── */

uint16_t jmx_domain_match(const char *hostname, int hostname_len)
{
	char lower[JMX_DOMAIN_MAX_NAME];
	int i, len;
	uint32_t h;
	jmx_domain_entry_t *e;

	if (!hostname || hostname_len <= 0 || hostname_len >= JMX_DOMAIN_MAX_NAME)
		return 0;

	/* Lowercase the hostname */
	for (i = 0; i < hostname_len; i++)
		lower[i] = tolower(hostname[i]);
	lower[hostname_len] = '\0';
	len = hostname_len;

	/* Try full match first, then progressively strip leftmost labels */
	while (len > 0) {
		h = domain_hash(lower, len);
		for (e = g_buckets[h]; e; e = e->next) {
			if ((int)strlen(e->domain) == len &&
			    memcmp(e->domain, lower, len) == 0)
				return e->group_id;
		}

		/* Strip leftmost label: "sub.example.com" → "example.com" */
		const char *dot = memchr(lower, '.', len);
		if (!dot) break;
		int skip = dot - lower + 1;
		len -= skip;
		memmove(lower, lower + skip, len);
		lower[len] = '\0';
	}

	return 0;
}

const char *jmx_domain_group_name(uint16_t group_id)
{
	uint32_t i;
	for (i = 0; i < g_group_count; i++)
		if (g_groups[i].id == group_id)
			return g_groups[i].name;
	return "unknown";
}

uint32_t jmx_domain_count(void) { return g_entry_count; }
uint32_t jmx_domain_group_count(void) { return g_group_count; }
