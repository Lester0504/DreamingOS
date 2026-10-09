// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Contract: every write shape that revokes an AP adoption must be classified
 * JMX_RISK_HIGH, so only `owner` can reach it.
 *
 * Why this exists as a fixture rather than a live API test: the REST routes do
 * not exist yet. The risk table is being populated ahead of them because the
 * fallback for an unregistered write is JMX_RISK_MEDIUM, which admits `admin`.
 * Losing controller management of an AP is as destructive as a factory reset,
 * so it belongs with reboot at owner-only. This fixture fails the moment
 * somebody adds an unpair route in a shape the classifier does not recognise.
 *
 * Build:
 *   cc -O0 -Wall -Wextra -I../src/webd -o /tmp/ap_unpair_risk \
 *      ap_unpair_risk_tier_fixture.c ../src/webd/jmx_app_perms.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "jmx_app_perms.h"

#define AP_ID "3f2a1b4c-0000-4000-8000-000000000001"

static void expect_risk(const char *method, const char *path, jmx_risk_t want)
{
    jmx_risk_t got = jmx_perm_route_risk(method, path);

    if (got != want) {
        fprintf(stderr, "FAIL %s %s: want risk %d, got %d\n",
                method, path, (int)want, (int)got);
        assert(got == want);
    }
}

/* Only owner may pass; every other role, including admin, must be refused. */
static void expect_owner_only(const char *method, const char *path)
{
    jmx_risk_t risk = jmx_perm_route_risk(method, path);

    assert(risk == JMX_RISK_HIGH);
    assert(jmx_perm_check(JMX_ROLE_OWNER, risk) == 1);
    assert(jmx_perm_check(JMX_ROLE_ADMIN, risk) == 0);
    assert(jmx_perm_check(JMX_ROLE_OPERATOR, risk) == 0);
    assert(jmx_perm_check(JMX_ROLE_VIEWER, risk) == 0);
    assert(jmx_perm_check(JMX_ROLE_AI_AGENT, risk) == 0);
}

static void test_unpair_shapes_are_high(void)
{
    expect_owner_only("POST",   "/api/v1/ac/aps/unpair");
    /*
     * Caught in live testing on 30.1: the table row for this literal path
     * lists POST,PUT,DELETE only, so PATCH fell through to the rename
     * id-subtree row and answered MEDIUM (admin-reachable). Any write verb on
     * an unpair path must be HIGH.
     */
    expect_owner_only("PUT",    "/api/v1/ac/aps/unpair");
    expect_owner_only("PATCH",  "/api/v1/ac/aps/unpair");
    expect_owner_only("DELETE", "/api/v1/ac/aps/unpair");
    expect_owner_only("POST",   "/api/v1/ac/aps/" AP_ID "/unpair");
    expect_owner_only("PUT",    "/api/v1/ac/aps/" AP_ID "/unpair");
    expect_owner_only("DELETE", "/api/v1/ac/aps/" AP_ID "/unpair");

    /*
     * The interesting one. "/api/v1/ac/aps/" is registered as a PATCH id
     * subtree for rename at MEDIUM, so if the unpair classifier ran after the
     * table a PATCH-shaped unpair would inherit MEDIUM and become reachable by
     * admin. Asserting HIGH here pins the ordering.
     */
    expect_owner_only("PATCH",  "/api/v1/ac/aps/" AP_ID "/unpair");

    /* Forgetting an AP by id is an unpair by another name. */
    expect_owner_only("DELETE", "/api/v1/ac/aps/" AP_ID);

    /* AP-local unpair, no id segment. */
    expect_owner_only("POST",   "/api/v1/apd/unpair");
    expect_owner_only("DELETE", "/api/v1/apd/unpair");
}

static void test_neighbours_unchanged(void)
{
    /* Rename / model override stays admin-grade; this must not be dragged up. */
    expect_risk("PATCH",  "/api/v1/ac/aps/" AP_ID, JMX_RISK_MEDIUM);
    assert(jmx_perm_check(JMX_ROLE_ADMIN,
                          jmx_perm_route_risk("PATCH", "/api/v1/ac/aps/" AP_ID)) == 1);

    expect_risk("GET",    "/api/v1/ac/aps",            JMX_RISK_LOW);
    expect_risk("GET",    "/api/v1/ac/status",         JMX_RISK_LOW);
    expect_risk("GET",    "/api/v1/ac/capabilities",   JMX_RISK_LOW);
    expect_risk("GET",    "/api/v1/ac/pairing-tokens", JMX_RISK_LOW);
    expect_risk("POST",   "/api/v1/ac/pairing-tokens", JMX_RISK_MEDIUM);
    expect_risk("POST",   "/api/v1/system/reboot",     JMX_RISK_HIGH);
    expect_risk("PATCH",  "/api/v1/clients/aa:bb:cc:dd:ee:ff", JMX_RISK_LOW_WRITE);
}

static void test_lookalikes_not_swallowed(void)
{
    /* A read that merely contains the word is still a read. */
    expect_risk("GET",  "/api/v1/ac/aps/" AP_ID "/unpair", JMX_RISK_LOW);
    expect_risk("HEAD", "/api/v1/ac/aps/" AP_ID "/unpair", JMX_RISK_LOW);

    /* Empty id segment is malformed, not an unpair. */
    expect_risk("POST", "/api/v1/ac/aps//unpair", JMX_RISK_MEDIUM);

    /* Sibling subresources under the id keep their own default. */
    expect_risk("POST", "/api/v1/ac/aps/" AP_ID "/radio-job", JMX_RISK_MEDIUM);

    /* Not the unpair route: substring match must not be enough. */
    expect_risk("POST", "/api/v1/ac/aps/" AP_ID "/unpair-history", JMX_RISK_MEDIUM);
    expect_risk("POST", "/api/v1/apd/unpair-status", JMX_RISK_MEDIUM);
}

int main(void)
{
    test_unpair_shapes_are_high();
    test_neighbours_unchanged();
    test_lookalikes_not_swallowed();

    printf("ap_unpair_risk_tier_fixture: all assertions passed\n");
    return 0;
}
