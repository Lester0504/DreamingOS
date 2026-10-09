// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd/wan_sla_eval.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct json_object *field(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    assert(json_object_object_get_ex(o, key, &v));
    return v;
}

static struct json_object *sample(struct wan_sla_evaluator *e,
                                  struct wan_sla_profile *p,
                                  int64_t at, unsigned mask, double rtt,
                                  double forwarding)
{
    struct wan_sla_round r = {.at=at, .count=3, .ok_mask=mask,
                              .forwarding_loss_pct=forwarding};
    unsigned i;
    for (i = 0; i < r.count; i++) r.latency_ms[i] = rtt;
    assert(wan_sla_evaluator_add(e, 1, &r) == 0);
    return wan_sla_evaluate(e, p, at);
}

static void expect_state(struct json_object *o, const char *state)
{
    assert(!strcmp(json_object_get_string(field(o, "stable_state")), state));
}

int main(void)
{
    struct wan_sla_evaluator *e = calloc(1, sizeof(*e));
    struct wan_sla_profile p;
    struct json_object *rule = json_tokener_parse("{\"targets\":[\"a\",\"b\",\"c\"],\"window_s\":10}");
    struct json_object *o, *canonical, *invalid;
    int i;
    assert(e && wan_sla_profile_read(rule, &p) == 0 && p.reliability == 2);
    canonical = wan_sla_profile_normalize(rule, NULL, 3);
    assert(canonical && json_object_get_int(field(canonical,"profile_version")) == 1);
    invalid = json_tokener_parse("{\"reliability\":4}");
    assert(!wan_sla_profile_normalize(invalid,NULL,3));
    json_object_put(invalid);
    invalid = json_tokener_parse("{\"critical\":{\"latency_p95_ms\":100}}");
    assert(!wan_sla_profile_normalize(invalid,NULL,3));
    json_object_put(invalid);
    invalid = json_tokener_parse("{\"aggregation\":\"quorum\"}");
    assert(!wan_sla_profile_normalize(invalid,NULL,3));
    json_object_put(invalid);
    /* dns_servers: valid CSV of resolver IPs is accepted and echoed. */
    {
        struct json_object *dns = json_tokener_parse("{\"dns_servers\":\"223.5.5.5,2400:3200::1\"}");
        struct json_object *norm = wan_sla_profile_normalize(dns, NULL, 3);
        assert(norm && !strcmp(json_object_get_string(field(norm,"dns_servers")),"223.5.5.5,2400:3200::1"));
        json_object_put(norm); json_object_put(dns);
    }
    /* dns_servers: empty is a valid "no override"; malformed shapes are rejected. */
    {
        struct json_object *ok0 = json_tokener_parse("{\"dns_servers\":\"\"}");
        struct json_object *n0 = wan_sla_profile_normalize(ok0, NULL, 3);
        assert(n0 && !strcmp(json_object_get_string(field(n0,"dns_servers")),""));
        json_object_put(n0); json_object_put(ok0);
    }
    invalid = json_tokener_parse("{\"dns_servers\":\"223.5.5.5,\"}");   /* trailing comma */
    assert(!wan_sla_profile_normalize(invalid,NULL,3));
    json_object_put(invalid);
    invalid = json_tokener_parse("{\"dns_servers\":\"1.1.1.1,,2.2.2.2\"}"); /* empty token */
    assert(!wan_sla_profile_normalize(invalid,NULL,3));
    json_object_put(invalid);
    invalid = json_tokener_parse("{\"dns_servers\":\"has space\"}");    /* bad char */
    assert(!wan_sla_profile_normalize(invalid,NULL,3));
    json_object_put(invalid);
    wan_sla_evaluator_reset(e,1);
    for (i = 100; i <= 110; i += 2) {
        o = sample(e,&p,i,3,30,-1);
        if (i >= 104) expect_state(o,"healthy");
        json_object_put(o);
    }
    o = wan_sla_evaluate(e,&p,110);
    assert(json_object_get_double(field(field(o,"window"),"active_loss_pct")) > 33);
    assert(!field(field(o,"window"),"forwarding_loss_pct"));
    assert(json_object_array_length(field(o,"breached_dimensions")) == 0);
    assert(json_object_get_boolean(field(json_object_array_get_idx(field(o,"targets"),2),"degraded")));
    json_object_put(o);
    for (i = 112; i <= 116; i += 2) {
        o = sample(e,&p,i,7,450,-1);
        expect_state(o, i < 116 ? "healthy" : "critical");
        if (i == 116) assert(json_object_get_boolean(field(o,"transition")));
        json_object_put(o);
    }
    o = wan_sla_evaluate(e,&p,116);
    assert(!json_object_get_boolean(field(o,"transition")));
    json_object_put(o);
    for (i = 118; i <= 160; i += 2) {
        o = sample(e,&p,i,7,30,-1);
        expect_state(o,"critical");
        json_object_put(o);
    }
    for (; i <= 176; i += 2) {
        o = sample(e,&p,i,7,30,-1);
        if (i == 176) expect_state(o,"degraded");
        json_object_put(o);
    }
    o = wan_sla_evaluate(e,&p,300);
    expect_state(o,"degraded");
    assert(!json_object_get_boolean(field(o,"sample_fresh")));
    assert(!strcmp(json_object_get_string(field(o,"decision_suppressed_reason")),"evidence_stale"));
    json_object_put(o);
    wan_sla_evaluator_reset(e,1);
    for (i=400;i<=410;i+=2) {
        o=sample(e,&p,i,0,0,-1);
        if(i==410)expect_state(o,"down");
        json_object_put(o);
    }
    {
        struct wan_sla_round r = {.at=411,.count=3,.ok_mask=7,.forwarding_loss_pct=-1};
        assert(wan_sla_evaluator_add(e,2,&r) == -1);
        r.latency_ms[0] = NAN;
        assert(wan_sla_evaluator_add(e,1,&r) == -1);
        r.latency_ms[0] = 2; r.at=410;
        assert(wan_sla_evaluator_add(e,1,&r) == -1);
    }
    json_object_put(rule); json_object_put(canonical); free(e);
    puts("ok: SLA profile, quorum, p95, hysteresis, cooldown, stale and revision cases");
    return 0;
}
