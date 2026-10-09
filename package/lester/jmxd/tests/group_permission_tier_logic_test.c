// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit test for the group permission tier decision logic.
 *
 * The production functions in jmx_app_api.c are static and talk to sqlite, so
 * the decision core is reproduced here verbatim and exercised against real
 * inputs. This is a behaviour test rather than a text assertion: it catches the
 * "custom tier holding only write.high accidentally grants write.low" class of
 * bug, which a grep-style contract test cannot see.
 *
 * Build and run:
 *   cc -std=c11 -Wall -Wextra -o /tmp/gptl tests/group_permission_tier_logic_test.c && /tmp/gptl
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    JMX_RISK_LOW       = 0,
    JMX_RISK_LOW_WRITE = 1,
    JMX_RISK_MEDIUM    = 2,
    JMX_RISK_HIGH      = 3,
    JMX_RISK_BLOCKED   = 4
} jmx_risk_t;

/* Mirrors webd_group_permission_for_risk(). */
static const char *permission_for_risk(jmx_risk_t risk)
{
    switch (risk) {
    case JMX_RISK_LOW:       return "read";
    case JMX_RISK_LOW_WRITE: return "write.low";
    case JMX_RISK_MEDIUM:    return "write.medium";
    case JMX_RISK_HIGH:      return "write.high";
    default:                 return NULL;
    }
}

static int array_has(const char *const *permissions, const char *required)
{
    int i;

    if (!permissions || !required)
        return 0;
    for (i = 0; permissions[i]; i++) {
        if (!strcmp(permissions[i], required))
            return 1;
    }
    return 0;
}

struct group_row {
    const char *tier;
    const char *const *permissions;
};

/*
 * Mirrors the loop in webd_group_permission_allows(): every group carrying a
 * tier must allow the operation, an empty tier does not constrain, and a native
 * plugin action may be satisfied by either its exact permission or the generic
 * one for its risk.
 */
static int group_allows(const struct group_row *rows, int n, jmx_risk_t risk,
                        const char *native_permission)
{
    const char *generic = permission_for_risk(risk);
    int i;

    if (!generic)
        return 0;
    for (i = 0; i < n; i++) {
        int allowed;

        if (!rows[i].tier || !rows[i].tier[0])
            continue;
        allowed = array_has(rows[i].permissions, generic) ||
                  (native_permission &&
                   array_has(rows[i].permissions, native_permission));
        if (!allowed)
            return 0;
    }
    return 1;
}

static const char *const readonly_perms[]  = { "read", NULL };
static const char *const operator_perms[]  = { "read", "write.low", NULL };
static const char *const admin_perms[]     = { "read", "write.low", "write.medium", NULL };
static const char *const full_perms[]      = { "read", "write.low", "write.medium", "write.high", NULL };
static const char *const high_only_perms[] = { "write.high", NULL };
static const char *const proxy_read_perms[] = { "read", "dreamingproxy.read", NULL };

static int failures;

static void check(const char *name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
}

int main(void)
{
    /* No groups at all: the tier feature must not constrain anyone by default. */
    check("no_groups_allows_high", group_allows(NULL, 0, JMX_RISK_HIGH, NULL), 1);

    /* An untiered group predates the feature and must not demote its members. */
    {
        const struct group_row rows[] = { { "", NULL } };
        check("untiered_group_allows_high",
              group_allows(rows, 1, JMX_RISK_HIGH, NULL), 1);
    }

    /* readonly caps at reads. */
    {
        const struct group_row rows[] = { { "readonly", readonly_perms } };
        check("readonly_allows_read", group_allows(rows, 1, JMX_RISK_LOW, NULL), 1);
        check("readonly_denies_low_write",
              group_allows(rows, 1, JMX_RISK_LOW_WRITE, NULL), 0);
        check("readonly_denies_high", group_allows(rows, 1, JMX_RISK_HIGH, NULL), 0);
    }

    /* operator and admin allow up to their own level and no further. */
    {
        const struct group_row rows[] = { { "operator", operator_perms } };
        check("operator_allows_low_write",
              group_allows(rows, 1, JMX_RISK_LOW_WRITE, NULL), 1);
        check("operator_denies_medium",
              group_allows(rows, 1, JMX_RISK_MEDIUM, NULL), 0);
    }
    {
        const struct group_row rows[] = { { "admin", admin_perms } };
        check("admin_allows_medium", group_allows(rows, 1, JMX_RISK_MEDIUM, NULL), 1);
        check("admin_denies_high", group_allows(rows, 1, JMX_RISK_HIGH, NULL), 0);
    }
    {
        const struct group_row rows[] = { { "full", full_perms } };
        check("full_allows_high", group_allows(rows, 1, JMX_RISK_HIGH, NULL), 1);
    }

    /*
     * The reason this file exists: a custom tier listing only write.high must
     * not imply the lower grants. An ordered "maximum risk" implementation
     * answers 1 for all three of these.
     */
    {
        const struct group_row rows[] = { { "custom", high_only_perms } };
        check("custom_high_only_allows_high",
              group_allows(rows, 1, JMX_RISK_HIGH, NULL), 1);
        check("custom_high_only_denies_read",
              group_allows(rows, 1, JMX_RISK_LOW, NULL), 0);
        check("custom_high_only_denies_medium",
              group_allows(rows, 1, JMX_RISK_MEDIUM, NULL), 0);
    }

    /* Several tiered groups: the strictest wins, membership never adds power. */
    {
        const struct group_row rows[] = {
            { "full", full_perms },
            { "readonly", readonly_perms },
        };
        check("strictest_group_wins",
              group_allows(rows, 2, JMX_RISK_MEDIUM, NULL), 0);
        check("strictest_group_still_allows_read",
              group_allows(rows, 2, JMX_RISK_LOW, NULL), 1);
    }

    /* A plugin action passes on either its exact permission or the generic one. */
    {
        const struct group_row rows[] = { { "custom", proxy_read_perms } };
        check("plugin_exact_permission_allows",
              group_allows(rows, 1, JMX_RISK_LOW, "dreamingproxy.read"), 1);
        check("plugin_action_without_grant_denied",
              group_allows(rows, 1, JMX_RISK_MEDIUM, "dreamingproxy.configure"), 0);
    }
    {
        const struct group_row rows[] = { { "admin", admin_perms } };
        check("preset_tier_covers_plugin_configure",
              group_allows(rows, 1, JMX_RISK_MEDIUM, "dreamingproxy.configure"), 1);
    }

    /* BLOCKED has no permission that can satisfy it. */
    {
        const struct group_row rows[] = { { "full", full_perms } };
        check("blocked_is_never_allowed",
              group_allows(rows, 1, JMX_RISK_BLOCKED, NULL), 0);
    }

    printf("\n%s\n", failures ? "FAILURES PRESENT" : "all group tier logic checks passed");
    return failures ? 1 : 0;
}
