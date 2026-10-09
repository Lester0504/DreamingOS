// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exercise the traffic-log scope gate with the production decision logic.
 *
 * The gate is the part that was missing when the setting was merely stored, and
 * it is not visible in a schema check: what matters is which events survive it.
 * The two decision functions are lifted from aegisxd_hits.c by textual
 * extraction (see the Python harness) so this compiles without dragging in
 * ubus, curl and sqlite -- and so a change to the real logic reaches this test
 * instead of a copy drifting quietly.
 *
 * Cases mirror what each producer actually records:
 *   dns_filter monitor -> "monitor"    observed, resolved
 *   dns_filter block   -> "block"      enforced
 *   nft counter        -> "drop"       enforced by the ruleset
 *   reputation flow    -> "alert"      observed over conntrack
 *   suricata           -> "alert"/"drop"
 *   policy route       -> block/drop/allow/route/limit
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Scope state the extracted gate consults, normally filled from the settings
 * row; set directly here so each case is explicit. */
static struct {
    int64_t loaded_at;
    int blocked_only;
    int gateway_dns;
    int aegisx_service;
    int device_admin;
} g_scope_cache;

enum aegisxd_hit_source {
    AEGISXD_HIT_SOURCE_GATEWAY_DNS = 0,
    AEGISXD_HIT_SOURCE_AEGISX_SERVICE,
    AEGISXD_HIT_SOURCE_DEVICE_ADMIN,
};

static void aegisxd_scope_refresh(int64_t now) { (void)now; }

#include "aegis_scope_gate_extracted.h"

static int failures;

static void expect(const char *label, int got, int want)
{
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %s, expected %s\n", label,
                got ? "kept" : "dropped", want ? "kept" : "dropped");
        failures++;
    }
}

static void set_scope(int blocked_only, int dns, int service, int admin)
{
    g_scope_cache.loaded_at = 1;
    g_scope_cache.blocked_only = blocked_only;
    g_scope_cache.gateway_dns = dns;
    g_scope_cache.aegisx_service = service;
    g_scope_cache.device_admin = admin;
}

#define KEEP 1
#define DROP 0

int main(void)
{
    /* scope=all: every source on, nothing filtered by verdict. */
    set_scope(0, 1, 1, 1);
    expect("all/dns monitor",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "monitor", 1), KEEP);
    expect("all/dns block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "block", 1), KEEP);
    expect("all/reputation alert",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "alert", 1), KEEP);
    expect("all/policy route",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_DEVICE_ADMIN, "route", 1), KEEP);

    /* scope=blocked: only enforced verdicts survive. This is the behaviour the
     * acceptance criterion asks for and the part that did not exist before. */
    set_scope(1, 1, 1, 1);
    expect("blocked/dns monitor",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "monitor", 1), DROP);
    expect("blocked/dns block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "block", 1), KEEP);
    expect("blocked/nft drop",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "drop", 1), KEEP);
    expect("blocked/reputation alert",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "alert", 1), DROP);
    expect("blocked/suricata drop",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "drop", 1), KEEP);
    expect("blocked/policy allow",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_DEVICE_ADMIN, "allow", 1), DROP);
    expect("blocked/policy route",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_DEVICE_ADMIN, "route", 1), DROP);
    expect("blocked/policy limit",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_DEVICE_ADMIN, "limit", 1), DROP);
    expect("blocked/policy block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_DEVICE_ADMIN, "block", 1), KEEP);

    /* Source toggles are independent of scope and of each other. */
    set_scope(0, 0, 1, 1);
    expect("dns off/dns block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "block", 1), DROP);
    expect("dns off/nft drop",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "drop", 1), KEEP);
    set_scope(0, 1, 0, 1);
    expect("service off/nft drop",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "drop", 1), DROP);
    expect("service off/dns block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "block", 1), KEEP);
    set_scope(0, 1, 1, 0);
    expect("admin off/policy block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_DEVICE_ADMIN, "block", 1), DROP);

    /* A source toggle off must win even for an enforced verdict: the operator
     * asked not to log that class at all. */
    set_scope(1, 0, 1, 1);
    expect("blocked + dns off/dns block",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_GATEWAY_DNS, "block", 1), DROP);

    /*
     * An unknown action counts as blocked. Under-reporting an enforcement action
     * is the worse error: the operator would conclude nothing was stopped.
     */
    set_scope(1, 1, 1, 1);
    expect("blocked/unknown action",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "quarantine", 1), KEEP);
    expect("blocked/empty action",
           aegisxd_hits_scope_admits(AEGISXD_HIT_SOURCE_AEGISX_SERVICE, "", 1), KEEP);

    if (failures) {
        fprintf(stderr, "%d scope-gate assertion(s) failed\n", failures);
        return 1;
    }
    printf("ok: scope gate keeps enforced verdicts under 'blocked', keeps "
           "everything under 'all', and honours the three source toggles\n");
    return 0;
}
