/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_nl_push.h - Push rules to kernel via netlink
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_NL_PUSH_H__
#define __JMX_NL_PUSH_H__

#include "jmx_rule.h"

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

#endif
