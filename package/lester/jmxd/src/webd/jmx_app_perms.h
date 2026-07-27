// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Permission layer for Mobile App API.
 * Risk levels: low / medium / high / blocked
 * Roles: owner / admin / operator / viewer / ai-agent
 */
#ifndef __JMX_APP_PERMS_H__
#define __JMX_APP_PERMS_H__

/* Risk levels — ordered by severity */
typedef enum {
    JMX_RISK_LOW     = 0,
    JMX_RISK_MEDIUM  = 1,
    JMX_RISK_HIGH    = 2,
    JMX_RISK_BLOCKED = 3
} jmx_risk_t;

/* Roles — ordered by privilege */
typedef enum {
    JMX_ROLE_VIEWER   = 0,
    JMX_ROLE_OPERATOR = 1,
    JMX_ROLE_ADMIN    = 2,
    JMX_ROLE_OWNER    = 3,
    JMX_ROLE_AI_AGENT = 4
} jmx_role_t;

/*
 * Classify a route + method into a risk level.
 * Returns JMX_RISK_BLOCKED for routes that must never be called from App/AI.
 */
jmx_risk_t jmx_perm_route_risk(const char *method, const char *path);

/*
 * Check if a role is allowed to perform an action at the given risk level.
 * Returns 1 = allowed, 0 = denied.
 *
 * Rules:
 *   blocked   → nobody
 *   high      → owner only (+ local confirm)
 *   medium    → admin + owner
 *   low       → operator + admin + owner
 *   viewer    → read-only (GET on safe paths)
 *   ai-agent  → low only (medium+ blocked)
 */
int jmx_perm_check(jmx_role_t role, jmx_risk_t risk);

/*
 * Parse role string to enum. Default: JMX_ROLE_OPERATOR.
 */
jmx_role_t jmx_perm_parse_role(const char *s);

/*
 * Human-readable risk string.
 */
const char *jmx_perm_risk_str(jmx_risk_t r);

#endif
