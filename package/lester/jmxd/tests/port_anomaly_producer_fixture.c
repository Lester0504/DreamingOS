/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Contract fixture for the autonomous port-anomaly producer.
 *
 * Exercises the sysfs-backed detectors and the fail-closed / no-fake-zero
 * honesty rules directly against jmx_observability.c, driving samples through
 * jmx_obs_port_sample_append() and scoring through
 * jmx_obs_port_anomaly_producer_score() on an in-memory database.
 */
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <json-c/json.h>

#include "../src/jmx_observability.h"

#define CHECK(name, condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL %s\n", name); return 1; } \
} while (0)

static int object_int(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &value))
        return -1;
    return json_object_get_int(value);
}

static double object_double(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &value))
        return -1;
    return json_object_get_double(value);
}

static const char *object_string(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &value) || !value ||
        json_object_is_type(value, json_type_null))
        return NULL;
    return json_object_get_string(value);
}

static struct json_object *object_object(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !key || !json_object_object_get_ex(obj, key, &value) || !value)
        return NULL;
    return value;
}

static int object_is_null(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &value))
        return 0;
    return value == NULL || json_object_is_type(value, json_type_null);
}

static int status_is(struct json_object *obj, const char *want)
{
    const char *s = object_string(obj, "status");
    return s && !strcmp(s, want);
}

static int array_has_string(struct json_object *arr, const char *want)
{
    size_t i;
    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    for (i = 0; i < json_object_array_length(arr); i++) {
        const char *s = json_object_get_string(json_object_array_get_idx(arr, i));
        if (s && !strcmp(s, want))
            return 1;
    }
    return 0;
}

/* Finds a detector item (top-level items[]) by its event_code. */
static struct json_object *find_item(struct json_object *result, const char *code)
{
    struct json_object *items = object_object(result, "items");
    size_t i;
    if (!items || !json_object_is_type(items, json_type_array))
        return NULL;
    for (i = 0; i < json_object_array_length(items); i++) {
        struct json_object *it = json_object_array_get_idx(items, i);
        const char *c = object_string(it, "event_code");
        if (c && !strcmp(c, code))
            return it;
    }
    return NULL;
}

static int append_sample(sqlite3 *db, const char *port_key, const char *ifname,
                         const char *phys_id, int64_t rx_err, int64_t tx_err,
                         int64_t rx_drop, int64_t tx_drop, int64_t rx_pkt,
                         int64_t tx_pkt, int64_t rx_mcast, int speed, int carrier,
                         int64_t at_ms)
{
    struct jmx_obs_port_reading r;
    memset(&r, 0, sizeof(r));
    r.port_key = port_key;
    r.ifname = ifname;
    r.phys_port_id = phys_id;
    r.rx_errors = rx_err;
    r.tx_errors = tx_err;
    r.rx_dropped = rx_drop;
    r.tx_dropped = tx_drop;
    r.rx_packets = rx_pkt;
    r.tx_packets = tx_pkt;
    r.rx_multicast = rx_mcast;
    r.speed_mbps = speed;
    r.carrier = carrier;
    return jmx_obs_port_sample_append(db, &r, at_ms);
}

int main(void)
{
    sqlite3 *db = NULL;
    struct json_object *result;
    struct json_object *categories;
    struct json_object *caps;
    const int64_t base = 1000000000000LL;      /* fixed epoch ms */
    const int64_t now = base + 30LL * 60000LL;  /* 30 min later, inside window */

    CHECK("sqlite", sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK("store init", jmx_obs_port_sample_store_init(db) == 0);

    /* (a1) cold start: a single sample -> producer_complete false -> UNKNOWN. */
    CHECK("cold append", append_sample(db, "physid:0xA1", "eth1", "0xA1",
          0, 0, 0, 0, 1000000, 1000000, 0, 1000, 1, base) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth1", now);
    CHECK("cold status unknown", status_is(result, "UNKNOWN"));
    CHECK("cold score null", object_is_null(result, "score"));
    CHECK("cold sample count", object_int(result, "sample_count") == 1);
    caps = object_object(result, "capabilities");
    CHECK("cold missing producer",
          array_has_string(object_object(caps, "missing"), "structured_port_producer"));
    json_object_put(result);

    /* (a2) no stable-tier port_key (if:) -> not stable -> UNKNOWN even with two
     * good samples. An uplink/CPU port with no switch-port label lands here. */
    CHECK("iftier s1", append_sample(db, "if:eth2", "eth2", "",
          0, 0, 0, 0, 1000000, 1000000, 0, 1000, 1, base) == 0);
    CHECK("iftier s2", append_sample(db, "if:eth2", "eth2", "",
          0, 0, 0, 0, 1100000, 1100000, 0, 1000, 1, base + 60000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth2", now);
    CHECK("iftier status unknown", status_is(result, "UNKNOWN"));
    CHECK("iftier score null", object_is_null(result, "score"));
    CHECK("iftier missing identity",
          array_has_string(object_object(object_object(result, "capabilities"),
                           "missing"), "stable_port_identity"));
    CHECK("iftier reason", object_string(result, "reason") &&
          !strcmp(object_string(result, "reason"),
                  "port_stable_identity_absent_or_unstable"));
    json_object_put(result);

    /* (a3) mac:-only tier (no phys_port_id, no phys_port_name) also stays
     * UNKNOWN: a MAC is not a hardware-position identity. */
    CHECK("mactier s1", append_sample(db, "mac:aa:bb:cc:00:00:01", "eth9", "",
          0, 0, 0, 0, 1000000, 1000000, 0, 1000, 1, base) == 0);
    CHECK("mactier s2", append_sample(db, "mac:aa:bb:cc:00:00:01", "eth9", "",
          0, 0, 0, 0, 1100000, 1100000, 0, 1000, 1, base + 60000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth9", now);
    CHECK("mactier status unknown", status_is(result, "UNKNOWN"));
    json_object_put(result);

    /* (a4) DSA phys_port_name tier (physname:p0), NO phys_port_id at all --
     * exactly the BPI-R4 lab hardware shape -- IS stable enough to score, at
     * "inferred" confidence. This is the refinement: gating on phys_port_id
     * alone left the producer inert on real hardware. */
    CHECK("physname s1", append_sample(db, "physname:p2:aa:bb:cc:00:00:10", "eth7", "",
          0, 0, 0, 0, 1000000, 500000, 0, 1000, 1, base) == 0);
    CHECK("physname s2", append_sample(db, "physname:p2:aa:bb:cc:00:00:10", "eth7", "",
          3000, 0, 0, 0, 1100000, 550000, 0, 1000, 1, base + 300000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth7", now);
    categories = object_object(result, "categories");
    CHECK("physname complete", object_int(object_object(result, "capabilities"),
          "complete") == 1);
    CHECK("physname not unknown", !status_is(result, "UNKNOWN"));
    CHECK("physname traffic scored",
          object_double(object_object(categories, "TRAFFIC_PATH_HEALTH"), "score") > 0);
    CHECK("physname confidence inferred",
          object_string(object_object(result, "port"), "identity_confidence") &&
          !strcmp(object_string(object_object(result, "port"), "identity_confidence"),
                  "inferred"));
    CHECK("physname tier label",
          object_string(object_object(result, "port"), "identity_tier") &&
          !strcmp(object_string(object_object(result, "port"), "identity_tier"),
                  "phys_port_name"));
    json_object_put(result);

    /* (b) TRAFFIC_PATH_HEALTH fires on a real rx-error delta. */
    CHECK("traffic s1", append_sample(db, "physid:0xB2", "eth3", "0xB2",
          0, 0, 0, 0, 1000000, 500000, 0, 1000, 1, base) == 0);
    CHECK("traffic s2", append_sample(db, "physid:0xB2", "eth3", "0xB2",
          3000, 0, 0, 0, 1100000, 550000, 0, 1000, 1, base + 300000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth3", now);
    categories = object_object(result, "categories");
    CHECK("traffic complete", object_int(object_object(result, "capabilities"),
          "complete") == 1);
    CHECK("traffic path scored",
          object_double(object_object(categories, "TRAFFIC_PATH_HEALTH"), "score") > 0);
    CHECK("traffic rx detector present", find_item(result, "PORT_RX_ERRORS") != NULL);
    CHECK("traffic top not unknown", !status_is(result, "UNKNOWN"));
    /* (d) unsupported families are marked, never a healthy zero. */
    caps = object_object(result, "capabilities");
    CHECK("d cable_power missing", array_has_string(object_object(caps, "missing"), "CABLE_POWER"));
    CHECK("d broadcast_storm missing", array_has_string(object_object(caps, "missing"), "BROADCAST_STORM"));
    CHECK("d multicast missing", array_has_string(object_object(caps, "missing"), "MULTICAST_DISCOVERY"));
    CHECK("d cable_power unsupported",
          status_is(object_object(categories, "CABLE_POWER"), "UNSUPPORTED"));
    CHECK("d cable_power score null",
          object_is_null(object_object(categories, "CABLE_POWER"), "score"));
    CHECK("d multicast unsupported",
          status_is(object_object(categories, "MULTICAST_DISCOVERY"), "UNSUPPORTED"));
    CHECK("d multicast score null",
          object_is_null(object_object(categories, "MULTICAST_DISCOVERY"), "score"));
    json_object_put(result);

    /* (c) LINK_FLAP fires on carrier transitions with hysteresis; a rapid burst
     * saturates recurrence but the category score stays within the [0,100] cap.
     * An unknown (-1) carrier reading must not manufacture a phantom transition. */
    {
        int i;
        int64_t rxp = 2000000, txp = 1000000;
        int carrier = 1;
        int64_t t = base;
        /* 20 alternating readings -> 19 transitions, plus one unknown that is
         * ignored (no phantom flap across it). */
        for (i = 0; i < 20; i++) {
            CHECK("flap append", append_sample(db, "physid:0xC3", "eth4", "0xC3",
                  0, 0, 0, 0, rxp, txp, 0, 1000, carrier, t) == 0);
            rxp += 10000; txp += 5000; t += 30000;
            carrier = carrier ? 0 : 1;
        }
        /* unknown carrier reading in-window; last real carrier was preserved */
        CHECK("flap unknown append", append_sample(db, "physid:0xC3", "eth4", "0xC3",
              0, 0, 0, 0, rxp, txp, 0, 1000, -1, t) == 0);
    }
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth4",
                                                 base + 60LL * 60000LL);
    categories = object_object(result, "categories");
    {
        struct json_object *flood = object_object(categories, "LOOP_BROADCAST_FLOOD");
        struct json_object *item = find_item(result, "PORT_LINK_FLAP");
        struct json_object *evidence = object_object(item, "evidence");
        double score = object_double(flood, "score");
        CHECK("flap fired", item != NULL);
        CHECK("flap score positive", score > 0);
        CHECK("flap score within cap", score <= 100.0);
        /* 20 alternating real readings -> 19 transitions, unknown ignored. */
        CHECK("flap hysteresis count", object_int(evidence, "flap_count") == 19);
        /* traffic path saw no error/drop deltas -> checked healthy, not unknown. */
        CHECK("flap traffic none",
              status_is(object_object(categories, "TRAFFIC_PATH_HEALTH"), "NONE"));
    }
    json_object_put(result);

    /* (e) counter reset: rx_errors rolls back while drops rise. The reset
     * detector is unknown (absent), NOT a healthy zero and NOT a false anomaly;
     * the still-valid drop counter fires on its own real delta. */
    CHECK("reset s1", append_sample(db, "physid:0xE5", "eth6", "0xE5",
          10000, 0, 0, 0, 2000000, 1000000, 0, 1000, 1, base) == 0);
    CHECK("reset s2", append_sample(db, "physid:0xE5", "eth6", "0xE5",
          5, 0, 40000, 0, 2100000, 1050000, 0, 1000, 1, base + 300000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth6", now);
    categories = object_object(result, "categories");
    CHECK("reset complete", object_int(object_object(result, "capabilities"),
          "complete") == 1);
    CHECK("reset rx detector absent", find_item(result, "PORT_RX_ERRORS") == NULL);
    CHECK("reset drop detector present", find_item(result, "PORT_DROPPED_TRAFFIC") != NULL);
    CHECK("reset traffic scored from drops",
          object_double(object_object(categories, "TRAFFIC_PATH_HEALTH"), "score") > 0);
    json_object_put(result);

    /* (f) small-denominator guard: a DOWN port (carrier 0) with ~0 forwarded
     * packets but a handful of drops must NOT go CRITICAL. This reproduces the
     * live false positive (99 drops, packet_delta 0 -> rate 1.0 -> score 100).
     * With the min-packets floor the drop detector is not assessable (absent),
     * TRAFFIC_PATH_HEALTH is NONE, and the port is not red. */
    CHECK("idle s1", append_sample(db, "physname:p4:aa:bb:cc:00:00:20", "eth10", "",
          0, 0, 0, 0, 1000000, 500000, 0, 1000, 0, base) == 0);
    CHECK("idle s2", append_sample(db, "physname:p4:aa:bb:cc:00:00:20", "eth10", "",
          0, 0, 99, 0, 1000000, 500000, 0, 1000, 0, base + 550000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth10", now);
    categories = object_object(result, "categories");
    CHECK("idle complete", object_int(object_object(result, "capabilities"),
          "complete") == 1);
    CHECK("idle drop detector absent", find_item(result, "PORT_DROPPED_TRAFFIC") == NULL);
    CHECK("idle traffic none",
          status_is(object_object(categories, "TRAFFIC_PATH_HEALTH"), "NONE"));
    CHECK("idle not critical", !status_is(result, "CRITICAL"));
    CHECK("idle score not 100",
          object_is_null(result, "score") || object_double(result, "score") < 100.0);
    json_object_put(result);

    /* (g) a genuinely busy port with a high drop ratio over real volume still
     * fires CRITICAL: the guard does not neuter the real detector. */
    CHECK("busy s1", append_sample(db, "physname:p5:aa:bb:cc:00:00:21", "eth11", "",
          0, 0, 0, 0, 2000000, 1000000, 0, 1000, 1, base) == 0);
    CHECK("busy s2", append_sample(db, "physname:p5:aa:bb:cc:00:00:21", "eth11", "",
          0, 0, 100000, 0, 2900000, 1000000, 0, 1000, 1, base + 300000) == 0);
    result = jmx_obs_port_anomaly_producer_score(db, "sw-1", "eth11", now);
    categories = object_object(result, "categories");
    {
        struct json_object *item = find_item(result, "PORT_DROPPED_TRAFFIC");
        CHECK("busy drop detector present", item != NULL);
        CHECK("busy traffic critical",
              status_is(object_object(categories, "TRAFFIC_PATH_HEALTH"), "CRITICAL"));
        /* 100000 drops over 900000 forwarded packets = 11% >> 2% critical. */
        CHECK("busy denominator forwarded packets",
              object_int(object_object(item, "evidence"), "packet_delta") == 900000);
    }
    json_object_put(result);

    /* Bridge: DEGRADED/CRITICAL categories reach the structured-event timeline. */
    {
        struct jmx_obs_retention_profile profile;
        struct json_object *timeline, *events;
        jmx_obs_retention_profile_default(&profile);
        timeline = jmx_obs_event_timeline(db, base - 60000, now + 60000,
                                          "port", "eth6", &profile);
        events = object_object(timeline, "events");
        CHECK("bridge event present", events &&
              json_object_array_length(events) >= 1);
        json_object_put(timeline);
    }

    sqlite3_close(db);
    puts("ok: port anomaly producer fail-closed, real detectors, no-fake-zero");
    return 0;
}
