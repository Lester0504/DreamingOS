#include "client_protocol_history.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define PROTOCOL_HISTORY_PROC_PRIMARY "/proc/dreamingwrt/jmx/af_client_visit_list"
#define PROTOCOL_HISTORY_PROC_LEGACY "/proc/net/af_client_visit_list"
#define PROTOCOL_HISTORY_MAX_CLIENTS 256
#define PROTOCOL_HISTORY_COUNTER_SLOTS 16384
#define PROTOCOL_HISTORY_MAX_ROWS 8192
/*
 * Hard ceiling on total lines consumed from the producer per sample, including
 * duplicates and rejected rows. row_count below only counts unique rows, so it
 * cannot bound a source that emits endlessly repeating rows; this does.
 */
#define PROTOCOL_HISTORY_MAX_LINES (PROTOCOL_HISTORY_MAX_ROWS * 4)
#define PROTOCOL_HISTORY_MAX_GAP_SEC 15
#define PROTOCOL_HISTORY_COMPLETE_RATIO 0.95
#define PROTOCOL_HISTORY_BYTE_SEMANTICS "client_direction_skb_len_v1"

struct protocol_history_item {
    int app_id;
    uint64_t up_bytes_delta;
    uint64_t down_bytes_delta;
};

struct protocol_history_point {
    int64_t ts;
    int interval_sec;
    uint64_t producer_generation;
    int item_count;
    uint64_t other_up_bytes_delta;
    uint64_t other_down_bytes_delta;
    struct protocol_history_item *items;
};

struct protocol_history_client {
    int used;
    char mac[18];
    int head;
    int count;
    int64_t first_observed_at;
    int64_t last_observed_at;
    int64_t last_gap_at;
    int64_t last_reset_at;
    uint64_t reset_count;
    uint64_t gap_count;
    uint64_t revision;
    int counters_nonzero;
    struct {
        int app_id;
        int64_t last_active_at;
    } series[JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES];
    struct protocol_history_point points[JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS];
};

struct protocol_history_counter {
    int used;
    char mac[18];
    int app_id;
    uint64_t in_bytes;
    uint64_t out_bytes;
    int64_t last_seen_at;
    int64_t last_seen_mono_ms;
    uint64_t seen_epoch;
};

struct protocol_history_row {
    char mac[18];
    int app_id;
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint64_t previous_seen_epoch;
};

struct protocol_history_tick_client {
    struct protocol_history_client *client;
    int item_count;
    uint64_t other_up_bytes_delta;
    uint64_t other_down_bytes_delta;
    struct protocol_history_item items[JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES];
};

static struct protocol_history_client protocol_history_clients[PROTOCOL_HISTORY_MAX_CLIENTS];
static struct protocol_history_counter protocol_history_counters[PROTOCOL_HISTORY_COUNTER_SLOTS];
static uint64_t protocol_history_source_identity;
static uint64_t protocol_history_producer_generation;
static uint64_t protocol_history_snapshot_epoch;
static uint64_t protocol_history_revision;
static int64_t protocol_history_last_sample_at;
static int64_t protocol_history_last_sample_mono_ms;
static int64_t protocol_history_last_gap_at;
static int protocol_history_source_readable;

static int protocol_history_mac_normalize(const char *input, char *output, size_t output_len)
{
    size_t i;

    if (!input || !output || output_len < 18 || strlen(input) != 17)
        return -1;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (input[i] != ':')
                return -1;
            output[i] = ':';
        } else {
            if (!isxdigit((unsigned char)input[i]))
                return -1;
            output[i] = (char)tolower((unsigned char)input[i]);
        }
    }
    output[17] = '\0';
    return 0;
}

static uint64_t protocol_history_hash(const char *mac, int app_id)
{
    uint64_t hash = 1469598103934665603ULL;
    const unsigned char *p = (const unsigned char *)mac;

    while (*p) {
        hash ^= *p++;
        hash *= 1099511628211ULL;
    }
    hash ^= (uint32_t)app_id;
    hash *= 1099511628211ULL;
    return hash;
}

static struct protocol_history_client *protocol_history_client_get(const char *mac,
                                                                    int create,
                                                                    int64_t now)
{
    int i;
    int free_index = -1;
    int oldest_index = -1;
    int64_t oldest_seen = 0;

    for (i = 0; i < PROTOCOL_HISTORY_MAX_CLIENTS; i++) {
        if (protocol_history_clients[i].used &&
            !strcmp(protocol_history_clients[i].mac, mac))
            return &protocol_history_clients[i];
        if (!protocol_history_clients[i].used && free_index < 0)
            free_index = i;
        if (protocol_history_clients[i].used &&
            (oldest_index < 0 ||
             protocol_history_clients[i].last_observed_at < oldest_seen)) {
            oldest_index = i;
            oldest_seen = protocol_history_clients[i].last_observed_at;
        }
    }
    if (!create)
        return NULL;
    if (free_index < 0)
        free_index = oldest_index;
    if (free_index < 0)
        return NULL;
    if (protocol_history_clients[free_index].used) {
        char evicted_mac[18];

        snprintf(evicted_mac, sizeof(evicted_mac), "%s",
                 protocol_history_clients[free_index].mac);
        for (i = 0; i < JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS; i++)
            free(protocol_history_clients[free_index].points[i].items);
        for (i = 0; i < PROTOCOL_HISTORY_COUNTER_SLOTS; i++) {
            if (protocol_history_counters[i].used &&
                !strcmp(protocol_history_counters[i].mac, evicted_mac))
                memset(&protocol_history_counters[i], 0,
                       sizeof(protocol_history_counters[i]));
        }
    }
    memset(&protocol_history_clients[free_index], 0,
           sizeof(protocol_history_clients[free_index]));
    protocol_history_clients[free_index].used = 1;
    protocol_history_clients[free_index].first_observed_at = now;
    snprintf(protocol_history_clients[free_index].mac,
             sizeof(protocol_history_clients[free_index].mac), "%s", mac);
    return &protocol_history_clients[free_index];
}

static struct protocol_history_counter *protocol_history_counter_get(const char *mac,
                                                                      int app_id,
                                                                      int create)
{
    uint64_t hash = protocol_history_hash(mac, app_id);
    size_t start = (size_t)(hash % PROTOCOL_HISTORY_COUNTER_SLOTS);
    size_t i;
    struct protocol_history_counter *oldest = NULL;

    for (i = 0; i < PROTOCOL_HISTORY_COUNTER_SLOTS; i++) {
        struct protocol_history_counter *counter =
            &protocol_history_counters[(start + i) % PROTOCOL_HISTORY_COUNTER_SLOTS];

        if (!counter->used) {
            if (!create)
                return NULL;
            memset(counter, 0, sizeof(*counter));
            counter->used = 1;
            counter->app_id = app_id;
            snprintf(counter->mac, sizeof(counter->mac), "%s", mac);
            return counter;
        }
        if (counter->app_id == app_id && !strcmp(counter->mac, mac))
            return counter;
        if (!oldest || counter->last_seen_at < oldest->last_seen_at)
            oldest = counter;
    }
    if (!create || !oldest)
        return NULL;
    memset(oldest, 0, sizeof(*oldest));
    oldest->used = 1;
    oldest->app_id = app_id;
    snprintf(oldest->mac, sizeof(oldest->mac), "%s", mac);
    return oldest;
}

static struct protocol_history_tick_client *protocol_history_tick_client_get(
    struct protocol_history_tick_client *clients, int *count,
    struct protocol_history_client *client)
{
    int i;

    for (i = 0; i < *count; i++) {
        if (clients[i].client == client)
            return &clients[i];
    }
    if (*count >= PROTOCOL_HISTORY_MAX_CLIENTS)
        return NULL;
    memset(&clients[*count], 0, sizeof(clients[*count]));
    clients[*count].client = client;
    (*count)++;
    return &clients[*count - 1];
}

static uint64_t protocol_history_item_bytes(const struct protocol_history_item *item)
{
    return item->up_bytes_delta + item->down_bytes_delta;
}

static int protocol_history_client_series_slot(struct protocol_history_client *client,
                                               int app_id,
                                               int64_t now)
{
    int i;
    int free_index = -1;
    int stale_index = -1;
    int64_t stale_time = 0;

    if (!client || app_id <= 0)
        return -1;
    for (i = 0; i < JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES; i++) {
        if (client->series[i].app_id == app_id) {
            client->series[i].last_active_at = now;
            return i;
        }
        if (client->series[i].app_id <= 0 && free_index < 0)
            free_index = i;
        if (client->series[i].app_id > 0 &&
            client->series[i].last_active_at <=
                now - JMX_CLIENT_PROTOCOL_HISTORY_WINDOW_SEC &&
            (stale_index < 0 || client->series[i].last_active_at < stale_time)) {
            stale_index = i;
            stale_time = client->series[i].last_active_at;
        }
    }
    if (free_index < 0)
        free_index = stale_index;
    if (free_index < 0)
        return -1;
    client->series[free_index].app_id = app_id;
    client->series[free_index].last_active_at = now;
    return free_index;
}

static void protocol_history_tick_add(struct protocol_history_tick_client *tick,
                                      int app_id,
                                      uint64_t up_bytes_delta,
                                      uint64_t down_bytes_delta,
                                      int64_t now)
{
    struct protocol_history_item item;
    int slot;

    if (!tick || (up_bytes_delta == 0 && down_bytes_delta == 0))
        return;
    if (app_id <= 0) {
        tick->other_up_bytes_delta += up_bytes_delta;
        tick->other_down_bytes_delta += down_bytes_delta;
        return;
    }
    slot = protocol_history_client_series_slot(tick->client, app_id, now);
    if (slot < 0) {
        tick->other_up_bytes_delta += up_bytes_delta;
        tick->other_down_bytes_delta += down_bytes_delta;
        return;
    }
    item.app_id = app_id;
    item.up_bytes_delta = up_bytes_delta;
    item.down_bytes_delta = down_bytes_delta;
    if (tick->item_count < JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES)
        tick->items[tick->item_count++] = item;
}

static int protocol_history_item_compare(const void *left, const void *right)
{
    const struct protocol_history_item *a = left;
    const struct protocol_history_item *b = right;
    uint64_t a_bytes = protocol_history_item_bytes(a);
    uint64_t b_bytes = protocol_history_item_bytes(b);

    if (a_bytes < b_bytes)
        return 1;
    if (a_bytes > b_bytes)
        return -1;
    return a->app_id - b->app_id;
}

static void protocol_history_point_append(struct protocol_history_tick_client *tick,
                                          int64_t now,
                                          int interval_sec)
{
    struct protocol_history_client *client;
    struct protocol_history_point *point;

    if (!tick || !tick->client)
        return;
    client = tick->client;
    point = &client->points[client->head];
    free(point->items);
    memset(point, 0, sizeof(*point));
    point->ts = now;
    point->interval_sec = interval_sec;
    point->producer_generation = protocol_history_producer_generation;
    point->other_up_bytes_delta = tick->other_up_bytes_delta;
    point->other_down_bytes_delta = tick->other_down_bytes_delta;
    if (tick->item_count > 0) {
        point->items = calloc((size_t)tick->item_count, sizeof(point->items[0]));
        if (point->items) {
            point->item_count = tick->item_count;
            memcpy(point->items, tick->items,
                   (size_t)tick->item_count * sizeof(tick->items[0]));
            qsort(point->items, (size_t)point->item_count, sizeof(point->items[0]),
                  protocol_history_item_compare);
        } else {
            int i;

            for (i = 0; i < tick->item_count; i++) {
                point->other_up_bytes_delta += tick->items[i].up_bytes_delta;
                point->other_down_bytes_delta += tick->items[i].down_bytes_delta;
            }
        }
    }
    client->last_observed_at = now;
    client->revision = ++protocol_history_revision;
    client->head = (client->head + 1) % JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS;
    if (client->count < JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS)
        client->count++;
}

static int protocol_history_parse_row(const char *line,
                                      char mac[18], int *app_id,
                                      uint64_t *in_bytes, uint64_t *out_bytes,
                                      uint64_t *source_generation)
{
    char raw_mac[32];
    unsigned long long parsed_in = 0;
    unsigned long long parsed_out = 0;
    unsigned long long total_bytes = 0;
    unsigned long long parsed_generation = 0;
    unsigned long long total_num = 0;
    unsigned long long drop_num = 0;
    unsigned long long connections = 0;
    unsigned long long is_http = 0;
    long long latest_time = 0;
    long long latest_action = 0;
    long long offline_time = 0;
    int parsed_app_id = 0;
    char byte_semantics[64] = "";
    int fields;

    fields = sscanf(line,
                    "%31s %d %llu %llu %llu %llu %lld %lld %lld %llu %llu %llu %llu %63s",
                    raw_mac, &parsed_app_id, &total_num, &drop_num, &connections,
                    &is_http, &latest_time, &latest_action, &offline_time,
                    &parsed_in, &parsed_out, &total_bytes, &parsed_generation,
                    byte_semantics);
    if (fields != 14 || parsed_generation == 0 ||
        strcmp(byte_semantics, PROTOCOL_HISTORY_BYTE_SEMANTICS) ||
        protocol_history_mac_normalize(raw_mac, mac, 18) != 0)
        return -1;
    *app_id = parsed_app_id;
    *in_bytes = (uint64_t)parsed_in;
    *out_bytes = (uint64_t)parsed_out;
    *source_generation = (uint64_t)parsed_generation;
    return 0;
}

static int protocol_history_next_line(const char **snapshot_cursor,
                                      FILE *stream,
                                      char *line,
                                      size_t line_size)
{
    if (stream)
        return fgets(line, (int)line_size, stream) != NULL;
    if (snapshot_cursor && *snapshot_cursor && **snapshot_cursor) {
        const char *start = *snapshot_cursor;
        const char *end = strchr(start, '\n');
        size_t length = end ? (size_t)(end - start) : strlen(start);

        if (length >= line_size)
            length = line_size - 1;
        memcpy(line, start, length);
        line[length] = '\0';
        *snapshot_cursor = end ? end + 1 : start + strlen(start);
        return 1;
    }
    return 0;
}

static void protocol_history_mark_gap(int64_t now)
{
    int i;

    protocol_history_last_gap_at = now;
    for (i = 0; i < PROTOCOL_HISTORY_MAX_CLIENTS; i++) {
        if (!protocol_history_clients[i].used)
            continue;
        protocol_history_clients[i].gap_count++;
        protocol_history_clients[i].last_gap_at = now;
    }
}

static void protocol_history_generation_changed(int64_t now)
{
    int i;

    memset(protocol_history_counters, 0, sizeof(protocol_history_counters));
    protocol_history_producer_generation++;
    if (protocol_history_producer_generation == 0)
        protocol_history_producer_generation = 1;
    for (i = 0; i < PROTOCOL_HISTORY_MAX_CLIENTS; i++) {
        if (!protocol_history_clients[i].used)
            continue;
        protocol_history_clients[i].reset_count++;
        protocol_history_clients[i].last_reset_at = now;
    }
}

static int protocol_history_sample(FILE *stream, const char *snapshot,
                                   uint64_t expected_generation,
                                   int64_t now, int64_t monotonic_ms)
{
    static struct protocol_history_row rows[PROTOCOL_HISTORY_MAX_ROWS];
    static struct protocol_history_tick_client tick_clients[PROTOCOL_HISTORY_MAX_CLIENTS];
    const char *cursor = snapshot;
    char line[512];
    int row_count = 0;
    int tick_client_count = 0;
    int first_line = 1;
    int header_valid = 0;
    int interval_sec = 0;
    int valid_interval = 0;
    uint64_t source_generation = 0;
    int i;
    int lines_read = 0;

    if (now <= 0 || monotonic_ms <= 0)
        return -EINVAL;

    while (protocol_history_next_line(&cursor, stream, line, sizeof(line))) {
        char mac[18];
        int app_id;
        uint64_t in_bytes;
        uint64_t out_bytes;
        uint64_t row_generation;

        /*
         * A malformed or looping producer (e.g. a /proc source whose seq_file
         * emits endlessly repeating rows) would otherwise spin this loop
         * forever: duplicate rows take the `continue` path below without
         * advancing row_count, so the row_count >= MAX_ROWS break never fires.
         * Since this runs on the core's single ubus/uloop thread, that wedges
         * the entire control plane. Bail out once the line budget is exhausted.
         */
        if (++lines_read > PROTOCOL_HISTORY_MAX_LINES)
            return -EPROTO;

        if (first_line) {
            first_line = 0;
            if (strstr(line, "MAC") && strstr(line, "AppID") &&
                strstr(line, "counter_generation") &&
                strstr(line, "byte_semantics")) {
                header_valid = 1;
                continue;
            }
            return -EPROTO;
        }
        if (row_count >= PROTOCOL_HISTORY_MAX_ROWS)
            break;
        if (protocol_history_parse_row(line, mac, &app_id, &in_bytes,
                                       &out_bytes, &row_generation) != 0)
            return -EPROTO;
        if (source_generation == 0)
            source_generation = row_generation;
        if (row_generation != source_generation ||
            (expected_generation != 0 && row_generation != expected_generation))
            return -EPROTO;
        for (int duplicate = row_count - 1; duplicate >= 0; duplicate--) {
            if (rows[duplicate].app_id == app_id &&
                !strcmp(rows[duplicate].mac, mac)) {
                rows[duplicate].in_bytes = in_bytes;
                rows[duplicate].out_bytes = out_bytes;
                row_generation = 0;
                break;
            }
        }
        if (row_generation == 0)
            continue;
        snprintf(rows[row_count].mac, sizeof(rows[row_count].mac), "%s", mac);
        rows[row_count].app_id = app_id;
        rows[row_count].in_bytes = in_bytes;
        rows[row_count].out_bytes = out_bytes;
        row_count++;
    }

    if (!header_valid)
        return -EPROTO;
    if (source_generation == 0) {
        protocol_history_snapshot_epoch++;
        if (protocol_history_snapshot_epoch == 0)
            protocol_history_snapshot_epoch = 1;
        protocol_history_source_readable = 1;
        protocol_history_last_sample_at = now;
        protocol_history_last_sample_mono_ms = monotonic_ms;
        return 0;
    }
    if (protocol_history_source_identity == 0) {
        protocol_history_source_identity = source_generation;
        protocol_history_producer_generation = 1;
    } else if (protocol_history_source_identity != source_generation) {
        protocol_history_source_identity = source_generation;
        protocol_history_generation_changed(now);
    }
    protocol_history_snapshot_epoch++;
    if (protocol_history_snapshot_epoch == 0)
        protocol_history_snapshot_epoch = 1;
    memset(tick_clients, 0, sizeof(tick_clients));

    for (i = 0; i < row_count; i++) {
        struct protocol_history_counter *counter =
            protocol_history_counter_get(rows[i].mac, rows[i].app_id, 1);
        struct protocol_history_client *client =
            protocol_history_client_get(rows[i].mac, 1, now);

        if (!counter || !client)
            continue;
        rows[i].previous_seen_epoch = counter->seen_epoch;
        counter->seen_epoch = protocol_history_snapshot_epoch;
        client->last_observed_at = now;
        if (rows[i].in_bytes > 0 || rows[i].out_bytes > 0)
            client->counters_nonzero = 1;
        protocol_history_tick_client_get(tick_clients, &tick_client_count, client);
    }

    if (protocol_history_last_sample_mono_ms > 0 &&
        monotonic_ms > protocol_history_last_sample_mono_ms) {
        int64_t delta_ms = monotonic_ms - protocol_history_last_sample_mono_ms;

        interval_sec = (int)((delta_ms + 500) / 1000);
        valid_interval = interval_sec >= 1 &&
                         interval_sec <= PROTOCOL_HISTORY_MAX_GAP_SEC;
    }
    if (protocol_history_last_sample_mono_ms > 0 && !valid_interval)
        protocol_history_mark_gap(now);

    for (i = 0; i < row_count; i++) {
        struct protocol_history_counter *counter =
            protocol_history_counter_get(rows[i].mac, rows[i].app_id, 0);
        struct protocol_history_client *client =
            protocol_history_client_get(rows[i].mac, 0, now);
        struct protocol_history_tick_client *tick;
        int baseline;
        int64_t counter_delta_ms;

        if (!counter || !client)
            continue;
        tick = protocol_history_tick_client_get(tick_clients, &tick_client_count, client);
        baseline = counter->last_seen_mono_ms <= 0;
        counter_delta_ms = counter->last_seen_mono_ms > 0 ?
            monotonic_ms - counter->last_seen_mono_ms : 0;
        if (!baseline && rows[i].previous_seen_epoch + 1 !=
                         protocol_history_snapshot_epoch) {
            client->gap_count++;
            client->last_gap_at = now;
            baseline = 1;
        }
        if (!baseline && valid_interval &&
            (counter_delta_ms < 1000 ||
             counter_delta_ms > PROTOCOL_HISTORY_MAX_GAP_SEC * 1000LL)) {
            client->gap_count++;
            client->last_gap_at = now;
            baseline = 1;
        }

        if (!baseline &&
            (rows[i].in_bytes < counter->in_bytes ||
             rows[i].out_bytes < counter->out_bytes)) {
            client->reset_count++;
            client->last_reset_at = now;
            baseline = 1;
        }
        if (!baseline && valid_interval && tick) {
            uint64_t down_delta = rows[i].in_bytes - counter->in_bytes;
            uint64_t up_delta = rows[i].out_bytes - counter->out_bytes;

            protocol_history_tick_add(tick, rows[i].app_id,
                                      up_delta, down_delta, now);
        }
        counter->in_bytes = rows[i].in_bytes;
        counter->out_bytes = rows[i].out_bytes;
        counter->last_seen_at = now;
        counter->last_seen_mono_ms = monotonic_ms;
    }

    if (valid_interval) {
        for (i = 0; i < tick_client_count; i++)
            protocol_history_point_append(&tick_clients[i], now, interval_sec);
    }
    protocol_history_source_readable = 1;
    protocol_history_last_sample_at = now;
    protocol_history_last_sample_mono_ms = monotonic_ms;
    return row_count;
}

int jmx_client_protocol_history_sample_snapshot(const char *snapshot,
                                                uint64_t source_generation,
                                                int64_t now,
                                                int64_t monotonic_ms)
{
    if (!snapshot)
        return -EINVAL;
    return protocol_history_sample(NULL, snapshot, source_generation,
                                   now, monotonic_ms);
}

int jmx_client_protocol_history_sample_tick(int64_t now, int64_t monotonic_ms)
{
    const char *paths[] = {
        PROTOCOL_HISTORY_PROC_PRIMARY,
        PROTOCOL_HISTORY_PROC_LEGACY,
    };
    FILE *stream = NULL;
    size_t i;
    int rc;

    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        stream = fopen(paths[i], "r");
        if (!stream)
            continue;
        break;
    }
    if (!stream) {
        if (protocol_history_source_readable)
            protocol_history_mark_gap(now);
        protocol_history_source_readable = 0;
        return -errno;
    }
    rc = protocol_history_sample(stream, NULL, 0, now, monotonic_ms);
    fclose(stream);
    if (rc < 0) {
        if (protocol_history_source_readable)
            protocol_history_mark_gap(now);
        protocol_history_source_readable = 0;
    }
    return rc;
}

void jmx_client_protocol_history_reset(void)
{
    int i;
    int j;

    for (i = 0; i < PROTOCOL_HISTORY_MAX_CLIENTS; i++) {
        for (j = 0; j < JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS; j++)
            free(protocol_history_clients[i].points[j].items);
    }
    memset(protocol_history_clients, 0, sizeof(protocol_history_clients));
    memset(protocol_history_counters, 0, sizeof(protocol_history_counters));
    protocol_history_source_identity = 0;
    protocol_history_producer_generation = 0;
    protocol_history_snapshot_epoch = 0;
    protocol_history_revision = 0;
    protocol_history_last_sample_at = 0;
    protocol_history_last_sample_mono_ms = 0;
    protocol_history_last_gap_at = 0;
    protocol_history_source_readable = 0;
}

static const char *protocol_history_text(sqlite3_stmt *statement, int column)
{
    const unsigned char *value = sqlite3_column_text(statement, column);

    return value ? (const char *)value : "";
}

static void protocol_history_add_capabilities(struct json_object *result,
                                              int producer_available,
                                              int complete,
                                              double coverage_ratio,
                                              uint64_t reset_count,
                                              uint64_t gap_count,
                                              uint64_t revision,
                                              int64_t observed_at)
{
    json_object_object_add(result, "producer_supported", json_object_new_boolean(1));
    json_object_object_add(result, "available",
                           json_object_new_boolean(producer_available));
    json_object_object_add(result, "complete", json_object_new_boolean(complete));
    json_object_object_add(result, "per_app_supported",
                           json_object_new_boolean(producer_available));
    json_object_object_add(result, "per_protocol_supported",
                           json_object_new_boolean(producer_available));
    json_object_object_add(result, "supported",
                           json_object_new_boolean(producer_available));
    json_object_object_add(result, "coverage_ratio", json_object_new_double(coverage_ratio));
    json_object_object_add(result, "reset_count", json_object_new_int64((int64_t)reset_count));
    json_object_object_add(result, "gap_count", json_object_new_int64((int64_t)gap_count));
    json_object_object_add(result, "producer_generation",
                           json_object_new_int64((int64_t)protocol_history_producer_generation));
    json_object_object_add(result, "revision", json_object_new_int64((int64_t)revision));
    json_object_object_add(result, "observed_at", json_object_new_int64(observed_at));
}

static struct json_object *protocol_history_hot_query(const char *mac,
                                                      int64_t now,
                                                      int window_sec)
{
    struct json_object *result = json_object_new_object();
    struct json_object *points = json_object_new_array();
    struct protocol_history_client *client = protocol_history_client_get(mac, 0, now);
    int series_count = 0;
    int covered_seconds = 0;
    int point_count = 0;
    int complete = 0;
    int producer_available = 0;
    double coverage_ratio = 0.0;
    int i;

    json_object_object_add(result, "mac", json_object_new_string(mac));
    json_object_object_add(result, "window_sec", json_object_new_int(window_sec));
    json_object_object_add(result, "lookback_sec",
                           json_object_new_int(JMX_CLIENT_PROTOCOL_HISTORY_LOOKBACK_SEC));
    json_object_object_add(result, "max_interval_sec",
                           json_object_new_int(PROTOCOL_HISTORY_MAX_GAP_SEC));
    json_object_object_add(result, "source",
                           json_object_new_string("af_client_visit_list_counter_delta"));
    json_object_object_add(result, "byte_semantics",
                           json_object_new_string("monotonic_client_app_counter_delta"));
    json_object_object_add(result, "first_sample_counted", json_object_new_boolean(0));
    json_object_object_add(result, "counter_reset_counted", json_object_new_boolean(0));

    if (client) {
        for (i = 0; i < client->count; i++) {
            int index = client->head - client->count + i;
            struct protocol_history_point *sample;
            struct json_object *point;
            struct json_object *items;
            int j;

            while (index < 0)
                index += JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS;
            index %= JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS;
            sample = &client->points[index];
            if (sample->ts <= 0 || sample->ts <= now - window_sec || sample->ts > now)
                continue;
            point = json_object_new_object();
            items = json_object_new_array();
            json_object_object_add(point, "ts", json_object_new_int64(sample->ts));
            json_object_object_add(point, "timestamp", json_object_new_int64(sample->ts));
            json_object_object_add(point, "interval_seconds",
                                   json_object_new_int(sample->interval_sec));
            json_object_object_add(point, "producer_generation",
                                   json_object_new_int64((int64_t)sample->producer_generation));
            json_object_object_add(point, "source",
                                   json_object_new_string("af_client_visit_list_counter_delta"));
            for (j = 0; j < sample->item_count; j++) {
                struct json_object *item = json_object_new_object();
                char series_id[32];

                snprintf(series_id, sizeof(series_id), "app:%d", sample->items[j].app_id);
                json_object_object_add(item, "series_id", json_object_new_string(series_id));
                json_object_object_add(item, "app_id",
                                       json_object_new_int(sample->items[j].app_id));
                json_object_object_add(item, "app", json_object_new_string(""));
                json_object_object_add(item, "app_name", json_object_new_string(""));
                json_object_object_add(item, "protocol", json_object_new_string(""));
                json_object_object_add(item, "proto", json_object_new_string(""));
                json_object_object_add(item, "service", json_object_new_string(""));
                json_object_object_add(item, "domain", json_object_new_string(""));
                json_object_object_add(item, "host", json_object_new_string(""));
                json_object_object_add(item, "up_bytes_delta",
                                       json_object_new_int64((int64_t)sample->items[j].up_bytes_delta));
                json_object_object_add(item, "down_bytes_delta",
                                       json_object_new_int64((int64_t)sample->items[j].down_bytes_delta));
                json_object_object_add(item, "up_rate", json_object_new_int64(
                    (int64_t)(sample->items[j].up_bytes_delta / (uint64_t)sample->interval_sec)));
                json_object_object_add(item, "down_rate", json_object_new_int64(
                    (int64_t)(sample->items[j].down_bytes_delta / (uint64_t)sample->interval_sec)));
                json_object_object_add(item, "flow_count", json_object_new_int(0));
                json_object_object_add(item, "interval_seconds",
                                       json_object_new_int(sample->interval_sec));
                json_object_object_add(item, "source",
                                       json_object_new_string("af_client_visit_list_counter_delta"));
                json_object_array_add(items, item);
                series_count++;
            }
            if (sample->other_up_bytes_delta > 0 || sample->other_down_bytes_delta > 0) {
                struct json_object *item = json_object_new_object();

                json_object_object_add(item, "series_id", json_object_new_string("other"));
                json_object_object_add(item, "app_id", json_object_new_int(0));
                json_object_object_add(item, "app", json_object_new_string("Other"));
                json_object_object_add(item, "app_name", json_object_new_string("Other"));
                json_object_object_add(item, "protocol", json_object_new_string(""));
                json_object_object_add(item, "proto", json_object_new_string(""));
                json_object_object_add(item, "service", json_object_new_string(""));
                json_object_object_add(item, "domain", json_object_new_string(""));
                json_object_object_add(item, "host", json_object_new_string(""));
                json_object_object_add(item, "up_bytes_delta",
                                       json_object_new_int64((int64_t)sample->other_up_bytes_delta));
                json_object_object_add(item, "down_bytes_delta",
                                       json_object_new_int64((int64_t)sample->other_down_bytes_delta));
                json_object_object_add(item, "up_rate", json_object_new_int64(
                    (int64_t)(sample->other_up_bytes_delta / (uint64_t)sample->interval_sec)));
                json_object_object_add(item, "down_rate", json_object_new_int64(
                    (int64_t)(sample->other_down_bytes_delta / (uint64_t)sample->interval_sec)));
                json_object_object_add(item, "flow_count", json_object_new_int(0));
                json_object_object_add(item, "interval_seconds",
                                       json_object_new_int(sample->interval_sec));
                json_object_object_add(item, "source",
                                       json_object_new_string("af_client_visit_list_counter_delta"));
                json_object_array_add(items, item);
                series_count++;
            }
            json_object_object_add(point, "items", items);
            json_object_array_add(points, point);
            covered_seconds += sample->interval_sec;
            point_count++;
        }
        if (window_sec > 0) {
            coverage_ratio = (double)covered_seconds / (double)window_sec;
            if (coverage_ratio > 1.0)
                coverage_ratio = 1.0;
        }
        producer_available = protocol_history_source_readable &&
                             client->counters_nonzero && series_count > 0;
        complete = producer_available && coverage_ratio >= PROTOCOL_HISTORY_COMPLETE_RATIO &&
                   (client->last_gap_at <= 0 ||
                    client->last_gap_at <= now - window_sec) &&
                   (client->last_reset_at <= 0 ||
                    client->last_reset_at <= now - window_sec);
        protocol_history_add_capabilities(result, producer_available, complete,
                                          coverage_ratio, client->reset_count,
                                          client->gap_count, client->revision,
                                          client->last_observed_at);
    } else {
        protocol_history_add_capabilities(result, 0, 0, 0.0, 0, 0,
                                          protocol_history_revision,
                                          protocol_history_last_sample_at);
    }
    json_object_object_add(result, "point_count", json_object_new_int(point_count));
    json_object_object_add(result, "series_sample_count", json_object_new_int(series_count));
    json_object_object_add(result, "points", points);
    if (producer_available)
        json_object_object_add(result, "reason", json_object_new_string(
            complete ? "" : "partial_hot_window_after_producer_start"));
    else if (!protocol_history_source_readable)
        json_object_object_add(result, "reason",
                               json_object_new_string("app_counter_source_unavailable"));
    else if (!client)
        json_object_object_add(result, "reason",
                               json_object_new_string("client_app_counters_not_observed"));
    else
        json_object_object_add(result, "reason",
                               json_object_new_string("app_byte_counters_zero_or_no_delta"));
    return result;
}

static struct json_object *protocol_history_audit_fallback(const char *db_path,
                                                           const char *mac,
                                                           int64_t now,
                                                           int window_sec)
{
    static const char sql[] =
        "WITH ordered AS ("
        " SELECT ts,flow_id,COALESCE(protocol,proto,'') AS protocol,"
        " COALESCE(service,'') AS service,"
        " COALESCE(destination_app_id,0) AS destination_app_id,"
        " COALESCE(destination_app_name,'') AS destination_app_name,"
        " COALESCE(destination_host,host,'') AS destination_host,"
        " COALESCE(tx_bytes,0) AS tx_bytes,COALESCE(rx_bytes,0) AS rx_bytes,"
        " LAG(ts) OVER (PARTITION BY flow_id ORDER BY ts) AS prev_ts,"
        " LAG(COALESCE(tx_bytes,0)) OVER (PARTITION BY flow_id ORDER BY ts) AS prev_tx,"
        " LAG(COALESCE(rx_bytes,0)) OVER (PARTITION BY flow_id ORDER BY ts) AS prev_rx"
        " FROM audit_flow_sample WHERE lower(client_mac)=?1 AND ts>=?2 AND ts<=?3"
        "), deltas AS ("
        " SELECT ts,flow_id,protocol,service,destination_app_id,destination_app_name,"
        " destination_host,tx_bytes-prev_tx AS delta_tx,rx_bytes-prev_rx AS delta_rx,"
        " ts-prev_ts AS interval_sec"
        " FROM ordered WHERE prev_ts IS NOT NULL AND ts>?4 AND ts-prev_ts BETWEEN 1 AND ?5"
        " AND tx_bytes>=prev_tx AND rx_bytes>=prev_rx"
        "), grouped AS ("
        " SELECT ts,protocol,service,destination_app_id,destination_app_name,destination_host,"
        " SUM(delta_tx) AS delta_tx,SUM(delta_rx) AS delta_rx,"
        " MAX(interval_sec) AS interval_sec,COUNT(DISTINCT flow_id) AS flow_count"
        " FROM deltas WHERE delta_tx>0 OR delta_rx>0"
        " GROUP BY ts,protocol,service,destination_app_id,destination_app_name,destination_host"
        "), ranked AS ("
        " SELECT *,DENSE_RANK() OVER (ORDER BY ts DESC) AS point_rank,"
        " ROW_NUMBER() OVER (PARTITION BY ts ORDER BY (delta_tx+delta_rx) DESC,"
        " destination_app_id ASC,protocol ASC,service ASC,destination_host ASC) AS series_rank"
        " FROM grouped"
        ")"
        " SELECT ts,protocol,service,destination_app_id,destination_app_name,destination_host,"
        " delta_tx,delta_rx,interval_sec,flow_count"
        " FROM ranked WHERE point_rank<=?6 AND series_rank<=?7"
        " ORDER BY ts ASC,(delta_tx+delta_rx) DESC,destination_app_id ASC,"
        " protocol ASC,service ASC,destination_host ASC";
    struct json_object *points = json_object_new_array();
    struct json_object *current_point = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    int64_t current_ts = -1;
    int point_count = 0;
    int series_count = 0;
    int rc = SQLITE_ERROR;

    if (!db_path || !db_path[0] || now <= 0 ||
        sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 100);
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, now - JMX_CLIENT_PROTOCOL_HISTORY_LOOKBACK_SEC);
    sqlite3_bind_int64(statement, 3, now);
    sqlite3_bind_int64(statement, 4, now - window_sec);
    sqlite3_bind_int(statement, 5, JMX_CLIENT_PROTOCOL_HISTORY_MAX_INTERVAL_SEC);
    sqlite3_bind_int(statement, 6, JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS);
    sqlite3_bind_int(statement, 7, JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES_PER_POINT);

    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
        int64_t ts = sqlite3_column_int64(statement, 0);
        int64_t delta_tx = sqlite3_column_int64(statement, 6);
        int64_t delta_rx = sqlite3_column_int64(statement, 7);
        int interval_sec = sqlite3_column_int(statement, 8);
        struct json_object *items;
        struct json_object *item;
        char series_id[96];
        int app_id = sqlite3_column_int(statement, 3);

        if (ts <= 0 || interval_sec <= 0 || delta_tx < 0 || delta_rx < 0)
            continue;
        if (!current_point || ts != current_ts) {
            current_point = json_object_new_object();
            json_object_object_add(current_point, "ts", json_object_new_int64(ts));
            json_object_object_add(current_point, "timestamp", json_object_new_int64(ts));
            json_object_object_add(current_point, "interval_seconds",
                                   json_object_new_int(interval_sec));
            items = json_object_new_array();
            json_object_object_add(current_point, "items", items);
            json_object_object_add(current_point, "source",
                                   json_object_new_string("audit_flow_sample_counter_delta"));
            json_object_array_add(points, current_point);
            current_ts = ts;
            point_count++;
        } else {
            json_object_object_get_ex(current_point, "items", &items);
        }
        if (!items || json_object_array_length(items) >=
                      JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES_PER_POINT)
            continue;
        if (app_id > 0)
            snprintf(series_id, sizeof(series_id), "app:%d", app_id);
        else
            snprintf(series_id, sizeof(series_id), "proto:%s:%s",
                     protocol_history_text(statement, 1),
                     protocol_history_text(statement, 2));
        item = json_object_new_object();
        json_object_object_add(item, "series_id", json_object_new_string(series_id));
        json_object_object_add(item, "app_id", json_object_new_int(app_id));
        json_object_object_add(item, "app", json_object_new_string(
            protocol_history_text(statement, 4)));
        json_object_object_add(item, "app_name", json_object_new_string(
            protocol_history_text(statement, 4)));
        json_object_object_add(item, "protocol", json_object_new_string(
            protocol_history_text(statement, 1)));
        json_object_object_add(item, "proto", json_object_new_string(
            protocol_history_text(statement, 1)));
        json_object_object_add(item, "service", json_object_new_string(
            protocol_history_text(statement, 2)));
        json_object_object_add(item, "domain", json_object_new_string(
            protocol_history_text(statement, 5)));
        json_object_object_add(item, "host", json_object_new_string(
            protocol_history_text(statement, 5)));
        json_object_object_add(item, "up_bytes_delta", json_object_new_int64(delta_tx));
        json_object_object_add(item, "down_bytes_delta", json_object_new_int64(delta_rx));
        json_object_object_add(item, "up_rate", json_object_new_int64(delta_tx / interval_sec));
        json_object_object_add(item, "down_rate", json_object_new_int64(delta_rx / interval_sec));
        json_object_object_add(item, "flow_count",
                               json_object_new_int(sqlite3_column_int(statement, 9)));
        json_object_object_add(item, "interval_seconds", json_object_new_int(interval_sec));
        json_object_object_add(item, "source",
                               json_object_new_string("audit_flow_sample_counter_delta"));
        json_object_array_add(items, item);
        series_count++;
    }

done:
    if (statement)
        sqlite3_finalize(statement);
    if (db)
        sqlite3_close(db);
    {
        struct json_object *fallback = json_object_new_object();

        json_object_object_add(fallback, "available",
                               json_object_new_boolean(rc == SQLITE_DONE && series_count > 0));
        json_object_object_add(fallback, "complete", json_object_new_boolean(0));
        json_object_object_add(fallback, "supported", json_object_new_boolean(0));
        json_object_object_add(fallback, "per_app_supported", json_object_new_boolean(0));
        json_object_object_add(fallback, "per_protocol_supported", json_object_new_boolean(0));
        json_object_object_add(fallback, "point_count", json_object_new_int(point_count));
        json_object_object_add(fallback, "series_sample_count", json_object_new_int(series_count));
        json_object_object_add(fallback, "source",
                               json_object_new_string("audit_flow_sample_counter_delta"));
        json_object_object_add(fallback, "byte_semantics",
                               json_object_new_string("same_flow_adjacent_counter_delta"));
        json_object_object_add(fallback, "points", points);
        return fallback;
    }
}

struct json_object *jmx_client_protocol_history_query(const char *db_path,
                                                      const char *mac,
                                                      int64_t now,
                                                      int window_sec)
{
    struct json_object *result;
    struct json_object *available = NULL;
    char normalized_mac[18];

    if (window_sec <= 0 || window_sec > JMX_CLIENT_PROTOCOL_HISTORY_LOOKBACK_SEC)
        window_sec = JMX_CLIENT_PROTOCOL_HISTORY_WINDOW_SEC;
    if (protocol_history_mac_normalize(mac, normalized_mac, sizeof(normalized_mac)) != 0) {
        result = json_object_new_object();
        json_object_object_add(result, "mac", json_object_new_string(""));
        protocol_history_add_capabilities(result, 0, 0, 0.0, 0, 0,
                                          protocol_history_revision,
                                          protocol_history_last_sample_at);
        json_object_object_add(result, "window_sec", json_object_new_int(window_sec));
        json_object_object_add(result, "point_count", json_object_new_int(0));
        json_object_object_add(result, "series_sample_count", json_object_new_int(0));
        json_object_object_add(result, "reason", json_object_new_string("invalid_client_mac"));
        json_object_object_add(result, "points", json_object_new_array());
        return result;
    }
    result = protocol_history_hot_query(normalized_mac, now, window_sec);
    if (!json_object_object_get_ex(result, "available", &available) ||
        !json_object_get_boolean(available)) {
        struct json_object *fallback = protocol_history_audit_fallback(
            db_path, normalized_mac, now, window_sec);
        struct json_object *fallback_available = NULL;

        json_object_object_add(result, "fallback", fallback);
        if (json_object_object_get_ex(fallback, "available", &fallback_available) &&
            json_object_get_boolean(fallback_available))
            json_object_object_add(result, "reason", json_object_new_string(
                "minute_flow_sample_fallback_not_full_hot_window"));
    }
    return result;
}
