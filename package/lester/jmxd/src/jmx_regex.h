/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_regex.h - NFQUEUE regex matching engine for jmxd
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_REGEX_H__
#define __JMX_REGEX_H__

#include "jmx_rule.h"

/*
 * Initialize the regex engine from a rule set.
 * Pre-compiles all REGEX rules with PCRE2.
 * Returns 0 on success.
 */
int jmx_regex_init(const jmx_rule_set_t *rs);

/*
 * Cleanup.
 */
void jmx_regex_exit(void);

/*
 * Start the NFQUEUE listener thread.
 * Spawns a background thread that processes packets.
 * Returns 0 on success.
 */
int jmx_regex_start(void);

/*
 * Stop the NFQUEUE listener.
 */
void jmx_regex_stop(void);

/*
 * Get count of compiled regex rules.
 */
int jmx_regex_count(void);
uint64_t jmx_regex_stat_packets(void);
uint64_t jmx_regex_stat_matched(void);
uint64_t jmx_regex_stat_miss(void);

/* Set netlink fd for sending results back to kernel */
void jmx_regex_set_netlink_fd(int fd);

/* Set rule set pointer for NR account extraction */
void jmx_regex_set_rule_set(const jmx_rule_set_t *rs);

#endif
