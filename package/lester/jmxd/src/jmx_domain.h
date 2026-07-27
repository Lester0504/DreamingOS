/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_domain.h - Domain group classification for DPI
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_DOMAIN_H__
#define __JMX_DOMAIN_H__

#include <stdint.h>

#define JMX_DOMAIN_MAX_NAME    128
#define JMX_DOMAIN_MAX_ENTRIES 24576
#define JMX_DOMAIN_MAX_GROUPS  64
#define JMX_DOMAIN_HASH_BUCKETS 1024

/* Domain group (category) */
typedef struct {
	uint16_t id;
	char     name[JMX_DOMAIN_MAX_NAME];
} jmx_domain_group_t;

/* Single domain entry */
typedef struct jmx_domain_entry {
	char     domain[JMX_DOMAIN_MAX_NAME];
	uint16_t group_id;
	struct jmx_domain_entry *next;
} jmx_domain_entry_t;

/* Initialize domain matcher */
int jmx_domain_init(void);

/* Free domain matcher */
void jmx_domain_exit(void);

/* Load domaingroup directory (reads all .txt files) */
int jmx_domain_load_dir(const char *dir_path);

/* Match a hostname against domain database.
 * Returns group_id (0 = no match).
 * Supports reverse matching: "sub.example.com" matches "example.com" */
uint16_t jmx_domain_match(const char *hostname, int hostname_len);

/* Get group name by id */
const char *jmx_domain_group_name(uint16_t group_id);

/* Stats */
uint32_t jmx_domain_count(void);
uint32_t jmx_domain_group_count(void);

#endif /* __JMX_DOMAIN_H__ */
