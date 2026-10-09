// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef FLOWD_WAN_SLA_EVAL_H
#define FLOWD_WAN_SLA_EVAL_H

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>

#define WAN_SLA_MAX_TARGETS 16
#define WAN_SLA_MAX_ROUNDS 3600

struct wan_sla_threshold {
    double loss_pct, latency_p95_ms, jitter_ms;
};

struct wan_sla_profile {
    int reliability, window_s, failure_interval_s, recovery_interval_s;
    int cooldown_s, fail_count, recover_count, interval_s;
    struct wan_sla_threshold degraded, critical;
    double down_loss_pct;
};

/* One complete round, never a partially collected target set. */
struct wan_sla_round {
    int64_t at;
    unsigned count, ok_mask;
    double latency_ms[WAN_SLA_MAX_TARGETS];
    double forwarding_loss_pct; /* -1 means unavailable, not zero. */
};

struct wan_sla_evaluator {
    struct wan_sla_round rounds[WAN_SLA_MAX_ROUNDS];
    size_t head, count;
    int level, candidate_level, failure_streak, success_streak;
    int recovering;
    int64_t revision, state_since, last_transition_at, last_sample_at;
    int64_t recovery_since, cooldown_until;
};

/* Returns a canonical, versioned profile or NULL for invalid input. */
struct json_object *wan_sla_profile_normalize(struct json_object *body,
                                             struct json_object *existing,
                                             int target_count);
int wan_sla_profile_read(struct json_object *rule, struct wan_sla_profile *out);
void wan_sla_evaluator_reset(struct wan_sla_evaluator *e, int64_t revision);
int wan_sla_evaluator_add(struct wan_sla_evaluator *e, int64_t revision,
                          const struct wan_sla_round *round);
struct json_object *wan_sla_evaluate(struct wan_sla_evaluator *e,
                                    const struct wan_sla_profile *profile,
                                    int64_t now);

#endif
