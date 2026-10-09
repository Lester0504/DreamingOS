// SPDX-License-Identifier: GPL-2.0-or-later
#include "wan_sla_eval.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

static struct json_object *get(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (o) json_object_object_get_ex(o, key, &v);
    return v;
}

static int integer(struct json_object *o, const char *key, int fallback,
                   int min, int max, int *ok)
{
    struct json_object *v = get(o, key);
    int64_t n;
    if (!v) return fallback;
    n = json_object_get_int64(v);
    if (!json_object_is_type(v, json_type_int) || n < min || n > max) {
        *ok = 0;
        return fallback;
    }
    return (int)n;
}

static void number_add(struct json_object *o, const char *key, double value)
{
    json_object_object_add(o, key, json_object_new_double(value));
}

static int threshold(struct json_object *source, struct json_object *fallback,
                      const char *name, struct json_object *out,
                      const double defaults[3])
{
    static const char *keys[] = {"loss_pct", "latency_p95_ms", "jitter_ms"};
    static const double maxima[] = {100, 600000, 600000};
    struct json_object *src = get(source, name), *prev = get(fallback, name);
    struct json_object *result = json_object_new_object();
    size_t i;
    if (src && !json_object_is_type(src, json_type_object)) goto invalid;
    for (i = 0; i < 3; i++) {
        struct json_object *v = get(src, keys[i]);
        double n;
        if (!v) v = get(prev, keys[i]);
        n = v ? json_object_get_double(v) : defaults[i];
        if ((v && !json_object_is_type(v, json_type_int) &&
                  !json_object_is_type(v, json_type_double)) ||
            !isfinite(n) || n <= 0 || n > maxima[i]) goto invalid;
        number_add(result, keys[i], n);
    }
    json_object_object_add(out, name, result);
    return 0;
invalid:
    json_object_put(result);
    return -1;
}

struct json_object *wan_sla_profile_normalize(struct json_object *body,
                                             struct json_object *existing,
                                             int target_count)
{
    static const struct { const char *key; int def, min, max; } fields[] = {
        {"window_s", 60, 2, WAN_SLA_MAX_ROUNDS},
        {"failure_interval_s", 2, 1, 3600},
        {"recovery_interval_s", 10, 1, 3600},
        {"cooldown_s", 60, 0, 86400}
    };
    static const double degraded[] = {3, 180, 80}, critical[] = {15, 400, 150};
    static const char *dimensions[] = {"loss_pct", "latency_p95_ms", "jitter_ms"};
    struct json_object *out = json_object_new_object(), *v, *down;
    const char *text;
    size_t i;
    int ok = 1, value;
    if (target_count < 1 || target_count > WAN_SLA_MAX_TARGETS) goto invalid;
    value = integer(existing, "reliability", (target_count + 1) / 2,
                    1, WAN_SLA_MAX_TARGETS, &ok);
    value = integer(body, "reliability", value, 1, target_count, &ok);
    if (value > target_count) goto invalid;
    json_object_object_add(out, "reliability", json_object_new_int(value));
    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        value = integer(existing, fields[i].key, fields[i].def,
                        fields[i].min, fields[i].max, &ok);
        value = integer(body, fields[i].key, value, fields[i].min, fields[i].max, &ok);
        json_object_object_add(out, fields[i].key, json_object_new_int(value));
    }
    value = integer(body, "profile_version", 1, 1, 1, &ok);
    json_object_object_add(out, "profile_version", json_object_new_int(value));
    v = get(body, "profile");
    if (!v) v = get(existing, "profile");
    text = v ? json_object_get_string(v) : "system-default";
    if (!text || (v && !json_object_is_type(v, json_type_string)) ||
        strcmp(text, "system-default")) goto invalid;
    json_object_object_add(out, "profile", json_object_new_string(text));
    v = get(body, "action_mode");
    if (!v) v = get(existing, "action_mode");
    text = v ? json_object_get_string(v) : "observe";
    if (!text || (v && !json_object_is_type(v, json_type_string)) ||
        (strcmp(text, "observe") && strcmp(text, "degrade") &&
         strcmp(text, "failover"))) goto invalid;
    json_object_object_add(out, "action_mode", json_object_new_string(text));
    v = get(body, "aggregation");
    if (!v) v = get(existing, "aggregation");
    text = v ? json_object_get_string(v) : "worst";
    if (!text || (v && !json_object_is_type(v, json_type_string)) ||
        strcmp(text, "worst")) goto invalid;
    json_object_object_add(out, "aggregation", json_object_new_string(text));
    if (threshold(body, existing, "degraded", out, degraded) ||
        threshold(body, existing, "critical", out, critical)) goto invalid;
    for (i = 0; i < 3; i++)
        if (json_object_get_double(get(get(out, "degraded"), dimensions[i])) >=
            json_object_get_double(get(get(out, "critical"), dimensions[i]))) goto invalid;
    down = get(body, "down");
    if (!down) down = get(existing, "down");
    if (down && !json_object_is_type(down, json_type_object)) goto invalid;
    value = integer(down, "loss_pct", 100, 100, 100, &ok);
    down = json_object_new_object();
    json_object_object_add(down, "loss_pct", json_object_new_int(value));
    json_object_object_add(out, "down", down);
    v = get(body, "expected_status");
    if (!v) v = get(existing, "expected_status");
    {
        struct json_object *codes = json_object_new_array();
        int seen[600] = {0};
        if (v && (!json_object_is_type(v,json_type_array) ||
                  json_object_array_length(v)>16)) { json_object_put(codes); goto invalid; }
        for (i=0;v && i<json_object_array_length(v);i++) {
            struct json_object *code=json_object_array_get_idx(v,i);
            int n=json_object_get_int(code);
            if (!code || !json_object_is_type(code,json_type_int) || n<100 || n>599 || seen[n]) {
                json_object_put(codes); goto invalid;
            }
            seen[n]=1;
        }
        for (i=100;i<600;i++) if(seen[i])json_object_array_add(codes,json_object_new_int((int)i));
        json_object_object_add(out,"expected_status",codes);
    }
    v = get(body, "body_marker");
    if (!v) v = get(existing, "body_marker");
    if (v && (!json_object_is_type(v,json_type_string) || json_object_get_string_len(v)>256 ||
              strlen(json_object_get_string(v))!=(size_t)json_object_get_string_len(v))) goto invalid;
    json_object_object_add(out,"body_marker",json_object_new_string(v?json_object_get_string(v):""));
    v = get(body, "dns_servers");
    if (!v) v = get(existing, "dns_servers");
    {
        /*
         * Optional comma-separated resolver list for http/https targets. The
         * bound probe socket cannot reach the box's own 127.0.0.1 resolver, so
         * name resolution for a web target needs an explicit public resolver
         * (e.g. the same 223.5.5.5 an operator already trusts). dns method
         * ignores this — its target string already carries the server. Empty
         * means "no override". c-ares validates the addresses at probe time;
         * here we only bound the shape (comma-separated IPv4/IPv6 literals).
         */
        const char *s = v ? json_object_get_string(v) : "";
        size_t len, i, tok = 0;
        if (v && !json_object_is_type(v, json_type_string)) goto invalid;
        if (!s) s = "";
        len = strlen(s);
        if (len > 128 || (v && (size_t)json_object_get_string_len(v) != len)) goto invalid;
        for (i = 0; i < len; i++) {
            char ch = s[i];
            if (ch == ',') { if (tok == 0) goto invalid; tok = 0; }
            else if ((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f')||(ch>='A'&&ch<='F')||ch=='.'||ch==':') {
                if (++tok > 45) goto invalid;
            } else goto invalid;
        }
        if (len && tok == 0) goto invalid;
        json_object_object_add(out,"dns_servers",json_object_new_string(s));
    }
    if (ok) return out;
invalid:
    json_object_put(out);
    return NULL;
}

int wan_sla_profile_read(struct json_object *rule, struct wan_sla_profile *out)
{
    struct json_object *targets = get(rule, "targets"), *p;
    int ok = 1;
    if (!targets || !out || !json_object_is_type(targets, json_type_array)) return -1;
    p = wan_sla_profile_normalize(rule, NULL, (int)json_object_array_length(targets));
    if (!p) return -1;
    memset(out, 0, sizeof(*out));
#define INT_FIELD(f) out->f = json_object_get_int(get(p, #f))
    INT_FIELD(reliability); INT_FIELD(window_s); INT_FIELD(failure_interval_s);
    INT_FIELD(recovery_interval_s); INT_FIELD(cooldown_s);
#undef INT_FIELD
    out->interval_s = integer(rule, "interval_s", 5, 1, 3600, &ok);
    out->fail_count = integer(rule, "fail_count", 3, 1, 100, &ok);
    out->recover_count = integer(rule, "recover_count", 2, 1, 100, &ok);
#define THRESHOLD_FIELD(level, f) out->level.f = json_object_get_double(get(get(p, #level), #f))
    THRESHOLD_FIELD(degraded, loss_pct); THRESHOLD_FIELD(degraded, latency_p95_ms);
    THRESHOLD_FIELD(degraded, jitter_ms); THRESHOLD_FIELD(critical, loss_pct);
    THRESHOLD_FIELD(critical, latency_p95_ms); THRESHOLD_FIELD(critical, jitter_ms);
#undef THRESHOLD_FIELD
    out->down_loss_pct = json_object_get_double(get(get(p, "down"), "loss_pct"));
    json_object_put(p);
    return ok ? 0 : -1;
}

void wan_sla_evaluator_reset(struct wan_sla_evaluator *e, int64_t revision)
{
    memset(e, 0, sizeof(*e));
    e->revision = revision;
    e->level = -1;
    e->candidate_level = -1;
}

int wan_sla_evaluator_add(struct wan_sla_evaluator *e, int64_t revision,
                          const struct wan_sla_round *round)
{
    unsigned i;
    if (!e || !round || revision != e->revision || round->at <= 0 ||
        round->count < 1 || round->count > WAN_SLA_MAX_TARGETS ||
        round->ok_mask >= (1U << round->count) ||
        !isfinite(round->forwarding_loss_pct) || round->forwarding_loss_pct < -1 ||
        round->forwarding_loss_pct > 100) return -1;
    for (i = 0; i < round->count; i++)
        if ((round->ok_mask & (1U << i)) &&
            (!isfinite(round->latency_ms[i]) || round->latency_ms[i] < 0)) return -1;
    if (e->count && round->at <= e->rounds[(e->head + WAN_SLA_MAX_ROUNDS - 1) %
                                          WAN_SLA_MAX_ROUNDS].at) return -1;
    e->rounds[e->head] = *round;
    e->head = (e->head + 1) % WAN_SLA_MAX_ROUNDS;
    if (e->count < WAN_SLA_MAX_ROUNDS) e->count++;
    return 0;
}

static int compare_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static const char *state_name(int level)
{
    static const char *names[] = {"healthy", "degraded", "critical", "down"};
    return level >= 0 && level <= 3 ? names[level] : "unknown";
}

static unsigned successes(unsigned mask)
{
    unsigned count = 0;
    while (mask) { count += mask & 1U; mask >>= 1; }
    return count;
}

struct json_object *wan_sla_evaluate(struct wan_sla_evaluator *e,
                                    const struct wan_sla_profile *p, int64_t now)
{
    struct json_object *out = json_object_new_object(), *window = json_object_new_object();
    struct json_object *breaches = json_object_new_array(), *targets = json_object_new_array();
    double *rtts = NULL, previous[WAN_SLA_MAX_TARGETS] = {0}, delta_sum = 0;
    unsigned have_previous = 0, target_total[WAN_SLA_MAX_TARGETS] = {0};
    unsigned target_ok[WAN_SLA_MAX_TARGETS] = {0}, total = 0, good = 0, deltas = 0;
    unsigned rounds = 0, round_ok = 0, latest_ok = 0, count = 0;
    size_t n = 0, i;
    double p50 = 0, p95 = 0, jitter = 0, loss = 0, forwarding = -1;
    int raw = 0, fresh = 0, transition = 0, max_interval;
    const char *suppressed = "insufficient_samples";
    int64_t latest = 0, oldest = 0;

    if (!e || !p || !e->count) goto output;
    latest = e->rounds[(e->head + WAN_SLA_MAX_ROUNDS - 1) % WAN_SLA_MAX_ROUNDS].at;
    max_interval = p->interval_s;
    if (p->failure_interval_s > max_interval) max_interval = p->failure_interval_s;
    if (p->recovery_interval_s > max_interval) max_interval = p->recovery_interval_s;
    fresh = now >= latest && now - latest <= max_interval * 3;
    if (!fresh) { suppressed = "evidence_stale"; goto output; }
    rtts = malloc(e->count * WAN_SLA_MAX_TARGETS * sizeof(*rtts));
    if (!rtts) { suppressed = "evaluation_unavailable"; goto output; }
    for (i = 0; i < e->count; i++) {
        const struct wan_sla_round *r = &e->rounds[(e->head + WAN_SLA_MAX_ROUNDS -
                                                    e->count + i) % WAN_SLA_MAX_ROUNDS];
        unsigned j, voted;
        if (r->at <= now - p->window_s || r->at > now) continue;
        if (!oldest) oldest = r->at;
        count = r->count;
        voted = successes(r->ok_mask);
        rounds++;
        if (voted >= (unsigned)p->reliability) round_ok++;
        latest_ok = voted;
        total += r->count;
        good += voted;
        for (j = 0; j < r->count; j++) {
            target_total[j]++;
            if (r->ok_mask & (1U << j)) {
                double latency = r->latency_ms[j];
                rtts[n++] = latency;
                target_ok[j]++;
                if (have_previous & (1U << j)) {
                    delta_sum += fabs(latency - previous[j]);
                    deltas++;
                }
                previous[j] = latency;
                have_previous |= 1U << j;
            }
        }
        if (r->at == latest) forwarding = r->forwarding_loss_pct;
    }
    if (total) loss = 100.0 * (total - good) / total;
    if (n) {
        qsort(rtts, n, sizeof(*rtts), compare_double);
        p50 = rtts[(n * 50 + 99) / 100 - 1];
        p95 = rtts[(n * 95 + 99) / 100 - 1];
    }
    if (deltas) jitter = delta_sum / deltas;
    for (i = 0; i < count; i++) {
        struct json_object *t = json_object_new_object();
        json_object_object_add(t, "index", json_object_new_int((int)i));
        json_object_object_add(t, "samples", json_object_new_int(target_total[i]));
        json_object_object_add(t, "successes", json_object_new_int(target_ok[i]));
        json_object_object_add(t, "degraded", json_object_new_boolean(target_ok[i] < target_total[i]));
        json_object_array_add(targets, t);
    }
    if (rounds < 2) goto output;
    /* Target failures remain visible, but quorum-successful rounds must not
     * turn a single broken target into a WAN loss penalty. */
#define BREACH(key, observed, d, c) do { \
    if ((observed) >= (d)) { \
        int level = (observed) >= (c) ? 2 : 1; \
        if (level > raw) raw = level; \
        json_object_array_add(breaches, json_object_new_string(key)); \
    } \
} while (0)
    if (latest_ok < (unsigned)p->reliability) {
        BREACH("active_loss_pct", loss, p->degraded.loss_pct, p->critical.loss_pct);
        if (raw < 1) raw = 1;
        json_object_array_add(breaches, json_object_new_string("target_quorum"));
        if (loss >= p->down_loss_pct) raw = 3;
    }
    if (n) BREACH("latency_p95_ms", p95, p->degraded.latency_p95_ms, p->critical.latency_p95_ms);
    if (deltas) BREACH("jitter_ms", jitter, p->degraded.jitter_ms, p->critical.jitter_ms);
    if (forwarding >= 0) BREACH("forwarding_loss_pct", forwarding, p->degraded.loss_pct, p->critical.loss_pct);
#undef BREACH
    suppressed = "";
    if (latest > e->last_sample_at) {
        if (e->last_sample_at && latest-e->last_sample_at>max_interval*3) {
            e->failure_streak=e->success_streak=0;
            e->recovering=0;e->recovery_since=0;e->candidate_level=-1;
        }
        e->last_sample_at = latest;
        if (raw > (e->level < 0 ? 0 : e->level)) {
            e->success_streak = 0;
            e->recovering = 0;
            e->recovery_since = 0;
            if (e->candidate_level != raw) e->failure_streak = 0;
            e->candidate_level = raw;
            if (e->failure_streak < 100) e->failure_streak++;
            if (e->failure_streak >= p->fail_count) {
                e->level = raw;
                e->cooldown_until = latest + p->cooldown_s;
                transition = 1;
            }
        } else if (raw < e->level || e->level < 0) {
            e->failure_streak = 0;
            if (e->success_streak < 100) e->success_streak++;
            if (e->level < 0) {
                if (raw == 0 && e->success_streak >= p->recover_count) {
                    e->level = 0;
                    transition = 1;
                }
            } else {
                if (!e->recovering) {
                    e->recovering = 1;
                    e->recovery_since = latest;
                    transition = 1;
                }
                if (e->success_streak >= p->recover_count &&
                    e->success_streak >= 2 && latest - e->recovery_since >= 20 &&
                    latest >= e->cooldown_until) {
                    e->level--;
                    e->recovering = 0;
                    e->success_streak = 0;
                    e->recovery_since = 0;
                    e->cooldown_until = latest + p->cooldown_s;
                    transition = 1;
                }
            }
        } else {
            if (e->recovering) transition = 1;
            e->recovering = 0;
            e->recovery_since = 0;
            e->failure_streak = e->success_streak = 0;
            e->candidate_level = raw;
        }
        if (transition) e->state_since = e->last_transition_at = latest;
    }
    if (e->level < 0) suppressed = "initial_hysteresis";
    else if (raw > e->level) suppressed = "failure_hysteresis";
    else if (e->recovering) suppressed = now < e->cooldown_until ? "cooldown" : "recovery_observation";

output:
    if (suppressed[0] && (!strcmp(suppressed, "evidence_stale") ||
                          !strcmp(suppressed, "insufficient_samples"))) {
        if (e) {
            e->failure_streak = e->success_streak = 0;
            e->recovering = 0;
            e->recovery_since = 0;
        }
    }
    free(rtts);
    json_object_object_add(out, "state", json_object_new_string(e && e->recovering ? "recovering" : state_name(e ? e->level : -1)));
    json_object_object_add(out, "stable_state", json_object_new_string(state_name(e ? e->level : -1)));
    json_object_object_add(out, "sample_fresh", json_object_new_boolean(fresh));
    json_object_object_add(out, "transition", json_object_new_boolean(transition));
    json_object_object_add(out, "requested_level", e && e->level >= 0 ? json_object_new_int(e->level) : NULL);
    json_object_object_add(out, "decision_suppressed_reason", json_object_new_string(suppressed));
#define TIME_FIELD(f) json_object_object_add(out, #f, json_object_new_int64(e ? e->f : 0))
    TIME_FIELD(state_since); TIME_FIELD(last_transition_at); TIME_FIELD(cooldown_until);
    TIME_FIELD(success_streak); TIME_FIELD(failure_streak);
#undef TIME_FIELD
    json_object_object_add(out, "last_sample_at", json_object_new_int64(latest));
    json_object_object_add(window, "samples", json_object_new_int(total));
    json_object_object_add(window, "rounds", json_object_new_int(rounds));
    json_object_object_add(window, "quorum_successes", json_object_new_int(round_ok));
    json_object_object_add(window, "availability_pct", rounds ? json_object_new_double(100.0*round_ok/rounds) : NULL);
    json_object_object_add(window, "started_at", json_object_new_int64(oldest));
    json_object_object_add(window, "finished_at", json_object_new_int64(latest));
    json_object_object_add(window, "active_loss_pct", total ? json_object_new_double(loss) : NULL);
    json_object_object_add(window, "forwarding_loss_pct", forwarding >= 0 ? json_object_new_double(forwarding) : NULL);
    json_object_object_add(window, "latency_p50_ms", n ? json_object_new_double(p50) : NULL);
    json_object_object_add(window, "latency_p95_ms", n ? json_object_new_double(p95) : NULL);
    json_object_object_add(window, "jitter_ms", deltas ? json_object_new_double(jitter) : NULL);
    json_object_object_add(window, "jitter_algorithm", json_object_new_string("per_target_mean_absolute_adjacent_rtt_delta"));
    json_object_object_add(out, "window", window);
    json_object_object_add(out, "targets", targets);
    json_object_object_add(out, "breached_dimensions", breaches);
    return out;
}
