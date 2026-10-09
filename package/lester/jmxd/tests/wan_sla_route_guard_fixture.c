// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "flowd/wan_sla_config.h"
#include "routed/wan_sla_route_guard.h"

static struct json_object *config(void)
{
    return json_tokener_parse(
        "{\"id\":\"sla-a\",\"name\":\"A\",\"enabled\":true,\"wan\":\"wan2\","
        "\"method\":\"icmp\",\"targets\":[\"1.1.1.1\",\"8.8.8.8\"],"
        "\"interval_s\":5,\"timeout_ms\":1000,\"loss_threshold_pct\":50,"
        "\"latency_threshold_ms\":300,\"fail_count\":3,\"recover_count\":2,"
        "\"remark\":\"\",\"revision\":7,\"reliability\":2,\"window_s\":60,"
        "\"failure_interval_s\":2,\"recovery_interval_s\":10,\"cooldown_s\":60,"
        "\"profile_version\":1,\"profile\":\"system-default\",\"action_mode\":\"failover\","
        "\"aggregation\":\"worst\",\"degraded\":{\"loss_pct\":3,\"latency_p95_ms\":180,\"jitter_ms\":80},"
        "\"critical\":{\"loss_pct\":15,\"latency_p95_ms\":400,\"jitter_ms\":150},"
        "\"down\":{\"loss_pct\":100},\"expected_status\":[200],\"body_marker\":\"\"}");
}

static struct json_object *request(struct json_object *cfg, int level, int64_t now)
{
    static const char *states[] = {"healthy", "degraded", "critical", "down"};
    struct json_object *out = json_object_new_object();
    char digest[17];

    wan_sla_config_digest(cfg, digest);
    json_object_object_add(out, "sla_id", json_object_new_string("sla-a"));
    json_object_object_add(out, "sla_revision", json_object_new_int64(7));
    json_object_object_add(out, "wan_id", json_object_new_string("wan2"));
    json_object_object_add(out, "evaluated_at", json_object_new_int64(now - 1));
    json_object_object_add(out, "expires_at", json_object_new_int64(now + 20));
    json_object_object_add(out, "stable_state", json_object_new_string(states[level]));
    json_object_object_add(out, "requested_level", json_object_new_int(level));
    json_object_object_add(out, "reasons", json_object_new_array());
    json_object_object_add(out, "evidence_window", json_object_new_object());
    json_object_object_add(out, "decision_id", json_object_new_string("decision-1"));
    json_object_object_add(out, "config_digest", json_object_new_string(digest));
    return out;
}

static void expect(const char *name, int actual, int expected, const char *reason,
                   const char *expected_reason)
{
    if (actual != expected || strcmp(reason, expected_reason)) {
        fprintf(stderr, "%s: verdict=%d reason=%s\n", name, actual, reason);
        exit(1);
    }
}

int main(void)
{
    struct json_object *cfg = config();
    struct json_object *req;
    int64_t now = 2000000000;
    char reason[64];
    int level;

    for (level = 0; level <= 3; level++) {
        req = request(cfg, level, now);
        expect("valid", wan_sla_route_guard_validate(req, cfg, now, 1,
               reason, sizeof(reason)), WAN_SLA_ROUTE_ALLOW, reason, "");
        json_object_put(req);
    }

    req = request(cfg, 3, now);
    expect("last WAN", wan_sla_route_guard_validate(req, cfg, now, 0,
           reason, sizeof(reason)), WAN_SLA_ROUTE_SUPPRESS, reason, "last_available_wan");
    json_object_object_add(req, "sla_revision", json_object_new_int64(6));
    expect("revision", wan_sla_route_guard_validate(req, cfg, now, 1,
           reason, sizeof(reason)), WAN_SLA_ROUTE_REJECT, reason, "stale_revision");
    json_object_object_add(req, "sla_revision", json_object_new_int64(7));
    json_object_object_add(req, "evaluated_at", json_object_new_int64(now - 10));
    json_object_object_add(req, "expires_at", json_object_new_int64(now - 2));
    expect("expiry", wan_sla_route_guard_validate(req, cfg, now, 1,
           reason, sizeof(reason)), WAN_SLA_ROUTE_REJECT, reason, "decision_expired");
    json_object_object_add(req, "expires_at", json_object_new_int64(now + 20));
    json_object_object_add(req, "wan_id", json_object_new_string("wan3"));
    expect("WAN", wan_sla_route_guard_validate(req, cfg, now, 1,
           reason, sizeof(reason)), WAN_SLA_ROUTE_REJECT, reason, "wan_identity_mismatch");
    json_object_object_add(req, "wan_id", json_object_new_string("wan2"));
    json_object_object_add(req, "config_digest", json_object_new_string("0000000000000000"));
    expect("digest", wan_sla_route_guard_validate(req, cfg, now, 1,
           reason, sizeof(reason)), WAN_SLA_ROUTE_REJECT, reason, "config_digest_mismatch");
    json_object_put(req);
    json_object_put(cfg);
    puts("ok: WAN SLA routed guard validates identity, freshness, digest and last-WAN suppression");
    return 0;
}
