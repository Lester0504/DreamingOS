// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Route-risk contract for the per-user notification mute preference
 * (Handoff: Front-to-Backend-notification-user-mute-preference).
 *
 * The handoff asks Backend to state, rather than inherit by accident, who may
 * change their own preference. This asserts the answer against the real
 * permission table: reading is viewer-visible, writing is operator and above,
 * and neither tier is the admin-grade one the global settings write uses.
 */
#include <stdio.h>
#include <string.h>

#include "../webd/jmx_app_perms.h"

static int g_fail;

static void expect_risk(const char *method, const char *path, jmx_risk_t want)
{
    jmx_risk_t got = jmx_perm_route_risk(method, path);

    if (got != want) {
        fprintf(stderr, "FAIL %s %s: risk %s, expected %s\n", method, path,
                jmx_perm_risk_str(got), jmx_perm_risk_str(want));
        g_fail = 1;
    }
}

static void expect_allowed(const char *role_s, const char *method,
                           const char *path, int want)
{
    jmx_role_t role = jmx_perm_parse_role(role_s);
    int got = jmx_perm_check(role, jmx_perm_route_risk(method, path));

    if (got != want) {
        fprintf(stderr, "FAIL %s %s %s: allowed=%d, expected %d\n", role_s,
                method, path, got, want);
        g_fail = 1;
    }
}

int main(void)
{
    const char *me = "/api/v1/notifyd/preferences/me";

    expect_risk("GET", me, JMX_RISK_LOW);
    expect_risk("PUT", me, JMX_RISK_LOW_WRITE);
    expect_risk("POST", me, JMX_RISK_LOW_WRITE);
    expect_risk("PATCH", me, JMX_RISK_LOW_WRITE);

    /* Personal scope must not become an admin-grade write, and must not stay at
     * the fail-closed MEDIUM default an unregistered write route would get. */
    expect_risk("PUT", "/api/v1/notifyd/settings", JMX_RISK_MEDIUM);

    expect_allowed("viewer", "GET", me, 1);
    expect_allowed("viewer", "PUT", me, 0);
    expect_allowed("ai-agent", "PUT", me, 0);
    expect_allowed("operator", "GET", me, 1);
    expect_allowed("operator", "PUT", me, 1);
    expect_allowed("admin", "PUT", me, 1);
    expect_allowed("owner", "PUT", me, 1);
    /* An unrecognised role must not gain the write by falling back. */
    expect_allowed("not-a-role", "PUT", me, 0);

    /* A personal preference write is real state change and belongs in the
     * audit ledger, unlike the viewer-readable GET. */
    if (jmx_perm_route_audit_policy("PUT", me) != JMX_AUDIT_STATE_CHANGE) {
        fprintf(stderr, "FAIL audit policy for PUT %s\n", me);
        g_fail = 1;
    }
    if (jmx_perm_route_audit_policy("GET", me) != JMX_AUDIT_NONE) {
        fprintf(stderr, "FAIL audit policy for GET %s\n", me);
        g_fail = 1;
    }

    if (g_fail)
        return 1;
    printf("ok: notifyd preference route perms\n");
    return 0;
}
