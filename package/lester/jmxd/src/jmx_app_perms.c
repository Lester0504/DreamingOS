// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Permission layer for Mobile App API.
 */
#include <string.h>
#include "jmx_app_perms.h"

/* ── Route risk classification ── */

struct route_risk {
    const char *prefix;
    const char *methods;  /* comma-separated, "" = all */
    jmx_risk_t  risk;
};

static const struct route_risk g_route_risks[] = {
    /* Blocked — never from App/AI */
    { "/api/v1/system/upgrade",   "POST", JMX_RISK_BLOCKED },
    { "/api/v1/system/restore",   "POST", JMX_RISK_BLOCKED },

    /* High — owner only, requires local confirm */
    { "/api/v1/system/reboot",    "POST", JMX_RISK_HIGH },
    { "/api/v1/system/shutdown",  "POST", JMX_RISK_HIGH },
    { "/api/v1/system/power/schedules", "POST,PUT,DELETE", JMX_RISK_HIGH },
    { "/api/v1/system/power/schedules/", "POST,PUT,DELETE", JMX_RISK_HIGH },
    { "/api/v1/system/backup",    "POST", JMX_RISK_HIGH },
    { "/api/v1/network/lans",     "POST,PUT,PATCH,DELETE", JMX_RISK_HIGH },
    { "/api/v1/network/lans/",    "DELETE", JMX_RISK_HIGH },

    /* Medium — affects network but auto-rollbackable */
    { "/api/v1/network/wans",     "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/network/wans/",    "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/network/wans/",    "PATCH",  JMX_RISK_MEDIUM },
    { "/api/v1/network/wans/",    "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/network/work-mode","PUT",    JMX_RISK_MEDIUM },
    { "/api/v1/services/dns",     "PATCH,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/services/dns/",    "POST,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/upnp",    "PATCH,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/services/upnp/",   "POST,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/flow-control",     "PATCH,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flow-control/",    "POST",   JMX_RISK_MEDIUM },

    /* Firewall — medium risk (auto-rollbackable) */
    { "/api/v1/services/firewall",     "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/services/firewall/apply","POST", JMX_RISK_MEDIUM },

    /* VPN — high risk (persistent side-effects) */
    { "/api/v1/services/vpn",     "POST,PUT,PATCH", JMX_RISK_HIGH },
    { "/api/v1/services/vpn/apply","POST", JMX_RISK_HIGH },

    /* RADIUS — medium */
    { "/api/v1/services/radius",  "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },

    /* Cellular — medium (slot/apn changes) */
    { "/api/v1/services/cellular",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/apply",  "POST", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/slots",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/slots/", "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/apn-profiles",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/apn-profiles/", "DELETE", JMX_RISK_MEDIUM },

    /* Advanced Routing — medium */
    { "/api/v1/routing",         "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/routing/apply",   "POST", JMX_RISK_MEDIUM },

    /* DNS rules — medium */
    { "/api/v1/services/dns/rules",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/dns/rules/", "DELETE", JMX_RISK_MEDIUM },

    /* DNS WAN policy — medium */
    { "/api/v1/services/dns/wan-policy",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/dns/wan-policy/", "DELETE", JMX_RISK_MEDIUM },

    /* UPnP static mappings — medium */
    { "/api/v1/services/upnp/mappings",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/upnp/mappings/", "DELETE", JMX_RISK_MEDIUM },

    /* AI conversations — low (no network impact) */
    { "/api/v1/ai/conversations",  "POST,PUT,DELETE", JMX_RISK_LOW },
    { "/api/v1/ai/conversations/", "DELETE", JMX_RISK_LOW },

    { "/api/v1/config/apply",     "POST",   JMX_RISK_MEDIUM },
    { "/api/v1/config/rollback",  "POST",   JMX_RISK_MEDIUM },

    /* Auth operations — low risk (no network impact) */
    { "/api/v1/auth/",            "",       JMX_RISK_LOW },

    /* Everything else — low (read or safe write) */
    { NULL, NULL, JMX_RISK_LOW }
};

jmx_risk_t jmx_perm_route_risk(const char *method, const char *path)
{
    const struct route_risk *r;
    for (r = g_route_risks; r->prefix; r++) {
        if (strncmp(path, r->prefix, strlen(r->prefix)) != 0) continue;
        /* If methods specified, check match */
        if (r->methods[0]) {
            const char *p = r->methods;
            int match = 0;
            while (*p) {
                const char *end = strchr(p, ',');
                int len = end ? (int)(end - p) : (int)strlen(p);
                if ((int)strlen(method) == len && !strncmp(method, p, (size_t)len)) { match = 1; break; }
                p += len;
                if (*p == ',') p++;
            }
            if (!match) continue;
        }
        return r->risk;
    }
    return JMX_RISK_LOW;
}

/* ── Permission check ── */

int jmx_perm_check(jmx_role_t role, jmx_risk_t risk)
{
    if (risk == JMX_RISK_BLOCKED) return 0;

    if (role == JMX_ROLE_AI_AGENT)
        return (risk == JMX_RISK_LOW) ? 1 : 0;

    if (role == JMX_ROLE_VIEWER)
        return (risk == JMX_RISK_LOW) ? 1 : 0;

    if (risk == JMX_RISK_HIGH)
        return (role == JMX_ROLE_OWNER) ? 1 : 0;

    if (risk == JMX_RISK_MEDIUM)
        return (role == JMX_ROLE_ADMIN || role == JMX_ROLE_OWNER) ? 1 : 0;

    /* low — everyone except viewer/ai-agent checked above */
    return 1;
}

/* ── Role parsing ── */

jmx_role_t jmx_perm_parse_role(const char *s)
{
    if (!s) return JMX_ROLE_OPERATOR;
    if (!strcmp(s, "owner"))    return JMX_ROLE_OWNER;
    if (!strcmp(s, "admin"))    return JMX_ROLE_ADMIN;
    if (!strcmp(s, "operator")) return JMX_ROLE_OPERATOR;
    if (!strcmp(s, "viewer"))   return JMX_ROLE_VIEWER;
    if (!strcmp(s, "ai-agent")) return JMX_ROLE_AI_AGENT;
    return JMX_ROLE_OPERATOR;
}

const char *jmx_perm_risk_str(jmx_risk_t r)
{
    switch (r) {
    case JMX_RISK_LOW:     return "low";
    case JMX_RISK_MEDIUM:  return "medium";
    case JMX_RISK_HIGH:    return "high";
    case JMX_RISK_BLOCKED: return "blocked";
    }
    return "low";
}
