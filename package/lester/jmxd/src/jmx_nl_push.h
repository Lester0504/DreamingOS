/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_nl_push.h - Push rules to kernel via netlink
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_NL_PUSH_H__
#define __JMX_NL_PUSH_H__

#include "jmx_rule.h"

typedef struct {
	uint32_t engine_capabilities;
	uint32_t active_generation;
	uint32_t active_rules;
	uint32_t active_steps;
	uint32_t active_ports;
	uint32_t active_mode;
	uint8_t active_catalog_digest[JMX_V3_CATALOG_DIGEST_LEN];
	uint32_t staging_generation;
	uint32_t staging_state;
	uint32_t reason;
	uint32_t detail;
} jmx_v3_kernel_status_t;

/*
 * Push all rules from a rule_set to the kernel module via netlink.
 * Uses batch mode: sends rules in chunks, then signals version commit.
 *
 * nl_fd: netlink socket fd (already bound)
 * rs:    populated rule set
 * version: rule set version number (for atomic swap)
 *
 * Returns 0 on success, <0 on error.
 */
int jmx_nl_push_rules(int nl_fd, const jmx_rule_set_t *rs, uint32_t version);

/*
 * Flush all v2 rules in the kernel.
 */
int jmx_nl_flush_rules(int nl_fd);

/*
 * Create and bind a netlink socket for jmx protocol.
 * Returns fd or <0 on error.
 */
int jmx_nl_socket_create(void);

/* Probe is ACK-based and bounded by a finite timeout. */
int jmx_nl_v3_probe(int nl_fd, jmx_v3_kernel_status_t *status);

/* Query current v3 ruleset status with an empty STATUS payload. */
int jmx_nl_v3_status(int nl_fd, uint32_t generation,
			  jmx_v3_kernel_status_t *status);

/* Returns success only after a validated COMMIT/STATUS active snapshot. */
int jmx_nl_push_chain_rules(int nl_fd, const jmx_chain_rule_set_t *rs,
			    uint32_t generation, uint8_t mode,
			    jmx_v3_kernel_status_t *status);

#endif
