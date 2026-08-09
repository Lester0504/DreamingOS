#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "client_protocol_history.h"

static struct json_object *field(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    assert(json_object_object_get_ex(object, name, &value));
    return value;
}

static struct json_object *last_point(struct json_object *result)
{
    struct json_object *points = field(result, "points");
    size_t count = json_object_array_length(points);

    assert(count > 0);
    return json_object_array_get_idx(points, count - 1);
}

static struct json_object *find_item(struct json_object *point, const char *series_id)
{
    struct json_object *items = field(point, "items");
    size_t i;

    for (i = 0; i < json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);

        if (!strcmp(json_object_get_string(field(item, "series_id")), series_id))
            return item;
    }
    return NULL;
}

static void make_snapshot(char *output, size_t output_size,
                          unsigned long long app1_in,
                          unsigned long long app1_out,
                          int include_app2,
                          unsigned long long app2_in,
                          unsigned long long app2_out,
                          unsigned long long generation)
{
    size_t used = (size_t)snprintf(output, output_size,
             "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
             "OfflineTime InBytes OutBytes TotalBytes counter_generation byte_semantics\n"
             "aa:bb:cc:dd:ee:ff 101 1 0 1 0 1 0 0 %llu %llu %llu %llu client_direction_skb_len_v1\n",
             app1_in, app1_out, app1_in + app1_out, generation);
    assert(used < output_size);
    if (include_app2) {
        snprintf(output + used, output_size - used,
                 "aa:bb:cc:dd:ee:ff 202 1 0 1 0 1 0 0 %llu %llu %llu %llu client_direction_skb_len_v1\n",
                 app2_in, app2_out, app2_in + app2_out, generation);
    }
}

/*
 * Build a snapshot whose header is caller-supplied but whose single row is a
 * fully valid modern row. That isolates the header contract: if the snapshot is
 * rejected, only the header check at protocol_history_sample() can be the cause,
 * because the row itself parses cleanly.
 */
static void make_snapshot_with_header(char *output, size_t output_size,
                                      const char *header,
                                      unsigned long long generation)
{
    size_t used = (size_t)snprintf(output, output_size, "%s\n", header);

    assert(used < output_size);
    used += (size_t)snprintf(output + used, output_size - used,
             "aa:bb:cc:dd:ee:ff 101 1 0 1 0 1 0 0 100 100 200 %llu client_direction_skb_len_v1\n",
             generation);
    assert(used < output_size);
}

static void test_monotonic_delta_and_reset(void)
{
    char snapshot[2048];
    struct json_object *result;
    struct json_object *item;

    jmx_client_protocol_history_reset();
    make_snapshot(snapshot, sizeof(snapshot), 1000, 500, 1, 2000, 1000, 11);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 11, 1000, 100000) == 2);
    result = jmx_client_protocol_history_query(NULL, "AA:BB:CC:DD:EE:FF", 1000, 300);
    assert(!json_object_get_boolean(field(result, "available")));
    assert(json_object_array_length(field(result, "points")) == 0);
    json_object_put(result);

    make_snapshot(snapshot, sizeof(snapshot), 1400, 700, 1, 2600, 1300, 11);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 11, 1004, 104000) == 2);
    result = jmx_client_protocol_history_query(NULL, "aa:bb:cc:dd:ee:ff", 1004, 300);
    assert(json_object_get_boolean(field(result, "producer_supported")));
    assert(json_object_get_boolean(field(result, "available")));
    assert(json_object_get_boolean(field(result, "per_app_supported")));
    assert(json_object_get_boolean(field(result, "per_protocol_supported")));
    assert(!json_object_get_boolean(field(result, "complete")));
    item = find_item(last_point(result), "app:101");
    assert(item);
    assert(json_object_get_int64(field(item, "down_bytes_delta")) == 400);
    assert(json_object_get_int64(field(item, "up_bytes_delta")) == 200);
    assert(json_object_get_int64(field(item, "down_rate")) == 100);
    assert(json_object_get_int64(field(item, "up_rate")) == 50);
    json_object_put(result);

    make_snapshot(snapshot, sizeof(snapshot), 10, 5, 1, 3000, 1500, 11);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 11, 1008, 108000) == 2);
    result = jmx_client_protocol_history_query(NULL, "aa:bb:cc:dd:ee:ff", 1008, 300);
    assert(json_object_get_int64(field(result, "reset_count")) == 1);
    assert(find_item(last_point(result), "app:101") == NULL);
    assert(find_item(last_point(result), "app:202") != NULL);
    json_object_put(result);

    make_snapshot(snapshot, sizeof(snapshot), 20, 10, 1, 3200, 1600, 12);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 12, 1012, 112000) == 2);
    result = jmx_client_protocol_history_query(NULL, "aa:bb:cc:dd:ee:ff", 1012, 300);
    assert(json_object_get_int64(field(result, "producer_generation")) == 2);
    assert(json_object_get_int64(field(result, "reset_count")) >= 2);
    assert(json_object_array_length(field(last_point(result), "items")) == 0);
    json_object_put(result);
}

static void test_missing_series_rebuilds_baseline(void)
{
    char snapshot[2048];
    struct json_object *result;

    jmx_client_protocol_history_reset();
    make_snapshot(snapshot, sizeof(snapshot), 100, 100, 1, 100, 100, 21);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 21, 2000, 200000) == 2);
    make_snapshot(snapshot, sizeof(snapshot), 200, 200, 0, 0, 0, 21);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 21, 2004, 204000) == 1);
    make_snapshot(snapshot, sizeof(snapshot), 300, 300, 0, 0, 0, 21);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 21, 2024, 224000) == 1);
    make_snapshot(snapshot, sizeof(snapshot), 400, 400, 1, 5000, 5000, 21);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 21, 2028, 228000) == 2);
    result = jmx_client_protocol_history_query(NULL, "aa:bb:cc:dd:ee:ff", 2028, 300);
    assert(json_object_get_int64(field(result, "gap_count")) >= 2);
    assert(find_item(last_point(result), "app:202") == NULL);
    json_object_put(result);
}

static void test_series_cap_aggregates_real_other(void)
{
    char first[16384];
    char second[16384];
    size_t first_used = 0;
    size_t second_used = 0;
    struct json_object *result;
    struct json_object *point;
    struct json_object *other;
    int i;

    jmx_client_protocol_history_reset();
    first_used += (size_t)snprintf(first + first_used, sizeof(first) - first_used,
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes counter_generation byte_semantics\n");
    second_used += (size_t)snprintf(second + second_used, sizeof(second) - second_used,
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes counter_generation byte_semantics\n");
    for (i = 1; i <= 40; i++) {
        first_used += (size_t)snprintf(first + first_used, sizeof(first) - first_used,
            "11:22:33:44:55:66 %d 1 0 1 0 1 0 0 100 100 200 31 client_direction_skb_len_v1\n", i);
        second_used += (size_t)snprintf(second + second_used, sizeof(second) - second_used,
            "11:22:33:44:55:66 %d 1 0 1 0 1 0 0 %d %d %d 31 client_direction_skb_len_v1\n",
            i, 100 + i, 100 + i * 2, 200 + i * 3);
    }
    assert(jmx_client_protocol_history_sample_snapshot(first, 31, 3000, 300000) == 40);
    assert(jmx_client_protocol_history_sample_snapshot(second, 31, 3004, 304000) == 40);
    result = jmx_client_protocol_history_query(NULL, "11:22:33:44:55:66", 3004, 300);
    point = last_point(result);
    assert(json_object_array_length(field(point, "items")) == 33);
    other = find_item(point, "other");
    assert(other);
    assert(json_object_get_int64(field(other, "down_bytes_delta")) == 292);
    assert(json_object_get_int64(field(other, "up_bytes_delta")) == 584);
    json_object_put(result);
}

static void test_ring_bound_and_fallback_capability(void)
{
    char snapshot[1024];
    struct json_object *result;
    int i;

    jmx_client_protocol_history_reset();
    make_snapshot(snapshot, sizeof(snapshot), 1, 1, 0, 0, 0, 41);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 41, 4000, 400000) == 1);
    for (i = 1; i <= 80; i++) {
        make_snapshot(snapshot, sizeof(snapshot), 1 + (unsigned long long)i * 10,
                      1 + (unsigned long long)i * 20, 0, 0, 0, 41);
        assert(jmx_client_protocol_history_sample_snapshot(snapshot, 41,
            4000 + i * 4, 400000 + i * 4000) == 1);
    }
    result = jmx_client_protocol_history_query(NULL, "aa:bb:cc:dd:ee:ff", 4320, 300);
    assert(json_object_array_length(field(result, "points")) ==
           JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS);
    assert(json_object_get_int64(field(result, "revision")) >= 80);
    assert(json_object_get_double(field(result, "coverage_ratio")) > 0.9);
    assert(json_object_get_boolean(field(result, "complete")));
    json_object_put(result);
}

static void test_kernel_generation_and_semantics_are_authoritative(void)
{
    char snapshot[2048];
    char *row;

    jmx_client_protocol_history_reset();
    make_snapshot(snapshot, sizeof(snapshot), 100, 100, 1, 2000, 1000, 51);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 52, 5000, 500000) < 0);

    make_snapshot(snapshot, sizeof(snapshot), 100, 100, 1, 2000, 1000, 51);
    row = strstr(snapshot, "aa:bb:cc:dd:ee:ff 202");
    assert(row);
    {
        char *generation = strstr(row, " 3000 51 client_direction_skb_len_v1");
        assert(generation);
        memcpy(generation, " 3000 52", 8);
    }
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 0, 5000, 500000) < 0);

    make_snapshot(snapshot, sizeof(snapshot), 100, 100, 0, 0, 0, 51);
    row = strstr(snapshot, "client_direction_skb_len_v1");
    assert(row);
    memcpy(row, "unknown_direction_semantics_v1",
           strlen("client_direction_skb_len_v1"));
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 0, 5000, 500000) < 0);
}

/*
 * The header must declare all four columns the consumer depends on. A producer
 * that still emits the pre-generation/pre-semantics header is exactly the source
 * this code must refuse: without counter_generation it cannot tell a counter
 * reset from a delta, and without byte_semantics it cannot know what the byte
 * columns mean. Each column gets its own case on purpose -- one merged case
 * would stay green if only one of the two strstr() checks were dropped.
 */
static void test_incomplete_header_is_rejected(void)
{
    static const char *const invalid_headers[] = {
        /* Legacy header: both new columns absent. */
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes",
        /* byte_semantics alone missing. */
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes counter_generation",
        /* counter_generation alone missing. */
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes byte_semantics",
        /* AppID missing: not a per-app source at all. */
        "MAC TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes counter_generation byte_semantics",
        /* Unrelated header from some other producer entirely. */
        "device app_name rx tx",
    };
    char snapshot[2048];
    size_t i;

    for (i = 0; i < sizeof(invalid_headers) / sizeof(invalid_headers[0]); i++) {
        jmx_client_protocol_history_reset();
        make_snapshot_with_header(snapshot, sizeof(snapshot), invalid_headers[i], 61);
        assert(jmx_client_protocol_history_sample_snapshot(snapshot, 61, 6000, 600000) < 0);
    }

    /*
     * A wholly legacy snapshot -- old header plus old 13-field rows -- is the
     * real-world shape of this regression, and must also be refused.
     */
    jmx_client_protocol_history_reset();
    snprintf(snapshot, sizeof(snapshot),
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes\n"
        "aa:bb:cc:dd:ee:ff 101 1 0 1 0 1 0 0 100 100 200\n");
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 0, 6000, 600000) < 0);

    /* The complete header on the same row still samples, so the rejections
     * above are attributable to the header and not to the row or the clock. */
    jmx_client_protocol_history_reset();
    make_snapshot_with_header(snapshot, sizeof(snapshot),
        "MAC AppID TotalNum DropNum Conn IsHttp LatestTime LatestAction "
        "OfflineTime InBytes OutBytes TotalBytes counter_generation byte_semantics",
        61);
    assert(jmx_client_protocol_history_sample_snapshot(snapshot, 61, 6000, 600000) == 1);
}

int main(void)
{
    test_monotonic_delta_and_reset();
    test_missing_series_rebuilds_baseline();
    test_series_cap_aggregates_real_other();
    test_ring_bound_and_fallback_capability();
    test_kernel_generation_and_semantics_are_authoritative();
    test_incomplete_header_is_rejected();
    puts("ok: client protocol hot history producer fixture");
    return 0;
}
