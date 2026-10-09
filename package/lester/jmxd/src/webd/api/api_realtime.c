// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Realtime / WebSocket subsystem (Phase 6U).
 *
 * The whole webd_ws_* handler-definition subsystem — the RFC6455 accept-key
 * and handshake, frame read/send, close, the per-connection client-connection
 * subscription table, notification dedupe, and the snapshot/topic builders —
 * plus webd_realtime_ws_session, the /api/v1/realtime/ws upgrade loop. Lifted
 * verbatim out of jmx_app_api.c. handle_client calls webd_realtime_ws_session
 * inline on the WebSocket upgrade (an fd hijack, not a jmx_api_route entry), so
 * no route moved; webd_dashboard_live_response reaches webd_ws_snapshot_data
 * directly. Both entry points are declared in api_realtime_internal.h.
 *
 * The WEBD_WS_* cadence/limit macros below lived in jmx_app_api.c's preamble
 * (above the moved region, so they did not travel with the bodies); they are
 * WS-only and move here with their design commentary. ACCESS_TTL_S,
 * WEBD_WS_MAX_CHILDREN and enum webd_auth_db_state are shared with main and
 * come from jmx_app_api.h / api_realtime_internal.h.
 *
 * This file is a pure extraction: no behaviour changed, no route moved.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <openssl/evp.h>

#include "../../jmx_strbuf.h"
#include "../jmx_app_api.h"
#include "../jmx_app_cache.h"
#include "../webd_session_idle.h"
#include "../webd_http.h"
#include "webd_http_req.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"
#include "api_runtime_cache.h"
#include "api_client_control_internal.h"
#include "api_client_profile.h"
#include "api_insights_internal.h"
#include "api_realtime_internal.h"

/* WS cadence/limit constants (moved verbatim from jmx_app_api.c's preamble). */
#define WEBD_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WEBD_WS_MAX_PAYLOAD 8192
#define WEBD_WS_AUTH_CHECK_S 30
#define WEBD_WS_MAX_LIFETIME_S ACCESS_TTL_S
#define WEBD_WS_THROUGHPUT_INTERVAL_MS 250
/*
 * Cadence for the fast topics other than dashboard.throughput -- topology.flow,
 * wan.metrics, clients.metrics and their siblings.
 *
 * These used to be gated on `now == last_push` with time_t, i.e. one push per
 * wall-clock second, which is why the monitoring pages felt a step behind the
 * dashboard even though the socket was idle. 500ms rather than throughput's
 * 250ms: these topics carry considerably more per push, and the data feeding
 * them is now live-counter derived with its own sub-second floor, so a second
 * doubling would mostly re-send equal objects.
 */
#define WEBD_WS_FAST_INTERVAL_MS 500
#define WEBD_WS_THROUGHPUT_CACHE_MAX_AGE_MS 200
#define WEBD_WS_THROUGHPUT_CACHE_PATH "/tmp/dreamingwrt/ws-throughput.json"
#define WEBD_WS_THROUGHPUT_LOCK_PATH "/tmp/dreamingwrt/ws-throughput.lock"
/*
 * Cross-process reuse window for one realtime_snapshot call, shared by every WS
 * child so N concurrent sessions cost core one build rather than N. It has to
 * stay just under the push cadence: at 900ms against a 500ms cadence every
 * second push would return the previous object, which is the paired-duplicate
 * behaviour this change exists to remove. 400ms keeps the fan-in protection --
 * concurrent sessions still share a build -- while letting consecutive pushes
 * differ.
 */
#define WEBD_WS_FAST_CACHE_MAX_AGE_MS 400
#define WEBD_WS_FAST_CACHE_PATH "/tmp/dreamingwrt/ws-fast.json"
#define WEBD_WS_FAST_LOCK_PATH "/tmp/dreamingwrt/ws-fast.lock"

static int webd_read_exact(int fd, void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static void webd_base64_encode(const unsigned char *in, size_t in_len,
                               char *out, size_t out_len)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, j = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    while (i < in_len && j + 4 < out_len) {
        size_t rem = in_len - i;
        unsigned int a = in[i++];
        unsigned int b = rem > 1 ? in[i++] : 0;
        unsigned int c = rem > 2 ? in[i++] : 0;

        out[j++] = tbl[(a >> 2) & 0x3f];
        out[j++] = tbl[((a & 0x3) << 4) | ((b >> 4) & 0xf)];
        out[j++] = rem > 1 ? tbl[((b & 0xf) << 2) | ((c >> 6) & 0x3)] : '=';
        out[j++] = rem > 2 ? tbl[c & 0x3f] : '=';
    }
    out[j] = '\0';
}

int webd_ws_accept_key(const char *client_key, char *out, size_t out_len)
{
    char src[256];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!client_key || !client_key[0] || !out || out_len == 0)
        return -1;
    if (snprintf(src, sizeof(src), "%s%s", client_key, WEBD_WS_GUID) >= (int)sizeof(src))
        return -1;
    if (!EVP_Digest(src, strlen(src), digest, &digest_len, EVP_sha1(), NULL))
        return -1;
    webd_base64_encode(digest, digest_len, out, out_len);
    return out[0] ? 0 : -1;
}

int webd_ws_send_frame(int fd, int opcode, const char *payload)
{
    unsigned char hdr[10];
    size_t len = payload ? strlen(payload) : 0;
    int hlen = 0;

    hdr[hlen++] = (unsigned char)(0x80 | (opcode & 0x0f));
    if (len < 126) {
        hdr[hlen++] = (unsigned char)len;
    } else if (len <= 65535) {
        hdr[hlen++] = 126;
        hdr[hlen++] = (unsigned char)((len >> 8) & 0xff);
        hdr[hlen++] = (unsigned char)(len & 0xff);
    } else {
        int i;

        hdr[hlen++] = 127;
        for (i = 7; i >= 0; i--)
            hdr[hlen++] = (unsigned char)(((uint64_t)len >> (i * 8)) & 0xff);
    }
    if (webd_write_all(fd, hdr, (size_t)hlen) != 0)
        return -1;
    if (len > 0 && webd_write_all(fd, payload, len) != 0)
        return -1;
    return 0;
}

/*
 * Close with an explicit status code and reason.
 *
 * A close frame with an empty payload gives the client no status at all: the
 * WebSocket API surfaces it as 1005 (no status received), which cannot be told
 * apart from an abnormal drop. The app needs that distinction to decide between
 * "refresh the token and reconnect silently" and "the network is gone, tell the
 * user", so the code is now always sent.
 *
 * Payload layout per RFC 6455 section 5.5.1: two bytes of big-endian status
 * followed by an optional UTF-8 reason, capped at 123 bytes so the whole frame
 * stays within the 125-byte control frame limit.
 */
int webd_ws_send_close(int fd, int code, const char *reason)
{
    unsigned char frame[2 + 2 + 123];
    size_t reason_len = reason ? strlen(reason) : 0;
    size_t payload_len;

    if (reason_len > 123)
        reason_len = 123;
    payload_len = 2 + reason_len;
    frame[0] = 0x88;                                  /* FIN + opcode 8 */
    frame[1] = (unsigned char)payload_len;            /* always < 126 */
    frame[2] = (unsigned char)((code >> 8) & 0xff);
    frame[3] = (unsigned char)(code & 0xff);
    if (reason_len)
        memcpy(frame + 4, reason, reason_len);
    return webd_write_all(fd, frame, 2 + payload_len);
}

int webd_ws_send_json(int fd, struct json_object *obj)
{
    const char *s = obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "{}";
    return webd_ws_send_frame(fd, 1, s ? s : "{}");
}

int webd_ws_read_frame(int fd, char *out, size_t out_len, int *opcode)
{
    unsigned char hdr[2];
    unsigned char mask[4];
    unsigned char payload[WEBD_WS_MAX_PAYLOAD + 1];
    uint64_t len;
    size_t i;

    if (!out || out_len == 0 || !opcode)
        return -1;
    out[0] = '\0';
    if (webd_read_exact(fd, hdr, 2) != 0)
        return -1;
    *opcode = hdr[0] & 0x0f;
    len = hdr[1] & 0x7f;
    if (len == 126) {
        unsigned char ext[2];
        if (webd_read_exact(fd, ext, 2) != 0)
            return -1;
        len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127) {
        unsigned char ext[8];
        if (webd_read_exact(fd, ext, 8) != 0)
            return -1;
        len = 0;
        for (i = 0; i < 8; i++)
            len = (len << 8) | ext[i];
    }
    if (!(hdr[1] & 0x80) || len > WEBD_WS_MAX_PAYLOAD || len >= out_len)
        return -1;
    if (webd_read_exact(fd, mask, 4) != 0)
        return -1;
    if (len > 0 && webd_read_exact(fd, payload, (size_t)len) != 0)
        return -1;
    for (i = 0; i < (size_t)len; i++)
        out[i] = (char)(payload[i] ^ mask[i % 4]);
    out[len] = '\0';
    return (int)len;
}


static int webd_ws_topics_any(const webd_ws_topics_t *topics)
{
    return topics &&
           (topics->dashboard_metrics || topics->dashboard_throughput ||
            topics->topology_flow || topics->wan_metrics ||
            topics->route_status ||
            topics->clients_metrics || topics->apps_metrics ||
            topics->client_detail || topics->client_overview ||
            topics->client_protocols ||
            topics->client_connections || topics->client_conntrack ||
            topics->notifications ||
            topics->logs_events ||
            topics->web_appearance ||
            topics->insights_flows_summary || topics->insights_flows_geo ||
            topics->insights_activity_rate || topics->insights_activity_traffic ||
            topics->insights_status);
}

static int webd_ws_topics_need_core_snapshot(const webd_ws_topics_t *topics)
{
    if (!topics)
        return 1;
    return topics->dashboard_metrics || topics->dashboard_throughput ||
           topics->topology_flow || topics->wan_metrics ||
           topics->clients_metrics || topics->apps_metrics || topics->insights_flows_summary ||
           topics->insights_flows_geo || topics->insights_activity_rate ||
           topics->insights_activity_traffic || topics->insights_status;
}

static int webd_ws_topics_only_throughput(const webd_ws_topics_t *topics)
{
    webd_ws_topics_t only;

    if (!topics || !topics->dashboard_throughput)
        return 0;
    memset(&only, 0, sizeof(only));
    only.dashboard_throughput = 1;
    return memcmp(topics, &only, sizeof(only)) == 0;
}

static int webd_ws_topics_have_fast_core(const webd_ws_topics_t *topics)
{
    return !topics || topics->dashboard_metrics || topics->topology_flow ||
           topics->wan_metrics || topics->clients_metrics ||
           topics->apps_metrics;
}

static webd_ws_topics_t webd_ws_all_fast_core_topics(void)
{
    webd_ws_topics_t topics;

    memset(&topics, 0, sizeof(topics));
    topics.dashboard_metrics = 1;
    topics.topology_flow = 1;
    topics.wan_metrics = 1;
    topics.clients_metrics = 1;
    topics.apps_metrics = 1;
    return topics;
}

static webd_ws_topics_t webd_ws_fast_topics(const webd_ws_topics_t *topics)
{
    webd_ws_topics_t out;

    memset(&out, 0, sizeof(out));
    if (!topics) {
        out.dashboard_metrics = 1;
        return out;
    }
    out.dashboard_metrics = topics->dashboard_metrics;
    out.dashboard_throughput = topics->dashboard_throughput;
    out.topology_flow = topics->topology_flow;
    out.wan_metrics = topics->wan_metrics;
    out.route_status = topics->route_status;
    out.clients_metrics = topics->clients_metrics;
    out.apps_metrics = topics->apps_metrics;
    out.client_detail = topics->client_detail;
    out.client_overview = topics->client_overview;
    out.client_protocols = topics->client_protocols;
    out.client_connections = topics->client_connections;
    out.client_conntrack = topics->client_conntrack;
    out.notifications = topics->notifications;
    out.logs_events = topics->logs_events;
    out.web_appearance = topics->web_appearance;
    return out;
}

static webd_ws_topics_t webd_ws_insights_topics(const webd_ws_topics_t *topics)
{
    webd_ws_topics_t out;

    memset(&out, 0, sizeof(out));
    if (!topics)
        return out;
    out.insights_flows_summary = topics->insights_flows_summary;
    out.insights_flows_geo = topics->insights_flows_geo;
    out.insights_activity_rate = topics->insights_activity_rate;
    out.insights_activity_traffic = topics->insights_activity_traffic;
    out.insights_status = topics->insights_status;
    return out;
}

static void webd_ws_topics_set(webd_ws_topics_t *topics, const char *topic, int enabled)
{
    if (!topics || !topic)
        return;
    if (!strcmp(topic, "dashboard.metrics"))
        topics->dashboard_metrics = enabled;
    else if (!strcmp(topic, "dashboard.throughput"))
        topics->dashboard_throughput = enabled;
    else if (!strcmp(topic, "topology.flow"))
        topics->topology_flow = enabled;
    else if (!strcmp(topic, "wan.metrics"))
        topics->wan_metrics = enabled;
    else if (!strcmp(topic, "route.status"))
        topics->route_status = enabled;
    else if (!strcmp(topic, "clients.metrics"))
        topics->clients_metrics = enabled;
    else if (!strcmp(topic, "apps.metrics"))
        topics->apps_metrics = enabled;
    else if (!strcmp(topic, "client.detail"))
        topics->client_detail = enabled;
    else if (!strcmp(topic, "client.overview"))
        topics->client_overview = enabled;
    else if (!strcmp(topic, "client.protocols") || !strcmp(topic, "client.protocol"))
        topics->client_protocols = enabled;
    else if (!strcmp(topic, "client.connections"))
        topics->client_connections = enabled;
    else if (!strcmp(topic, "client.conntrack"))
        topics->client_conntrack = enabled;
    else if (!strcmp(topic, "notifications") || !strcmp(topic, "notify.events"))
        topics->notifications = enabled;
    else if (!strcmp(topic, "logs.events") || !strcmp(topic, "logs.realtime") ||
             !strcmp(topic, "log.events") || !strcmp(topic, "system.logs"))
        topics->logs_events = enabled;
    else if (!strcmp(topic, "web.appearance"))
        topics->web_appearance = enabled;
    else if (!strcmp(topic, "insights.flows.summary"))
        topics->insights_flows_summary = enabled;
    else if (!strcmp(topic, "insights.flows.geo"))
        topics->insights_flows_geo = enabled;
    else if (!strcmp(topic, "insights.activity.rate"))
        topics->insights_activity_rate = enabled;
    else if (!strcmp(topic, "insights.activity.traffic"))
        topics->insights_activity_traffic = enabled;
    else if (!strcmp(topic, "insights.status"))
        topics->insights_status = enabled;
}

static void webd_ws_params_del_filter_keys(struct json_object *params)
{
    int i;

    if (!params)
        return;
    for (i = 0; i < (int)(sizeof(webd_insights_filter_fields) / sizeof(webd_insights_filter_fields[0])); i++) {
        const char *field = webd_insights_filter_fields[i];
        char exclude_key[96];

        json_object_object_del(params, field);
        snprintf(exclude_key, sizeof(exclude_key), "exclude_%s", field);
        json_object_object_del(params, exclude_key);
    }
    json_object_object_del(params, "exclude");
}

static void webd_ws_params_set_ref(struct json_object *params,
                                   const char *key,
                                   struct json_object *value)
{
    if (!params || !key || !key[0] || !value)
        return;
    json_object_object_add(params, key, json_object_get(value));
}

static void webd_ws_params_copy_known_scalars(struct json_object *params,
                                              struct json_object *src)
{
    static const char *keys[] = {
        "period", "top", "pageNumber", "page_number", "pageSize", "page_size",
        "timestampFrom", "timestampTo", "ts_from", "ts_to", "start", "end",
        "mac", "client_mac",
        "search_text", "searchText", "query", "q", "mode", "anchor", "matrix_offset", "matrix_limit", "includeUnidentified",
        "cursor_seq", "since_seq", "after_seq", "last_seq",
        "cursor_rowid", "since_rowid", "after_rowid", "last_rowid",
        "cursor_ts", "since_ts", "after_ts", "last_ts",
        "cursor_id", "since_id", "after_id", "last_id",
        "incremental", "delta"
    };
    int i;

    if (!params || !src || !json_object_is_type(src, json_type_object))
        return;
    for (i = 0; i < (int)(sizeof(keys) / sizeof(keys[0])); i++) {
        struct json_object *v = NULL;

        if (json_object_object_get_ex(src, keys[i], &v) && v)
            webd_ws_params_set_ref(params, keys[i], v);
    }
    {
        static const char *array_keys[] = {
            "categories", "events", "deviceMacs", "clientDeviceMacs",
            "adminIds", "severities", "programs"
        };

        for (i = 0; i < (int)(sizeof(array_keys) / sizeof(array_keys[0])); i++) {
            struct json_object *v = NULL;

            if (json_object_object_get_ex(src, array_keys[i], &v) && v &&
                json_object_is_type(v, json_type_array))
                webd_ws_params_set_ref(params, array_keys[i], v);
        }
    }
}

static void webd_ws_params_apply_filter_obj(struct json_object *params,
                                            struct json_object *src,
                                            int replace_filters)
{
    struct json_object *include = NULL;
    struct json_object *exclude = NULL;
    struct json_object *exclude_out = NULL;
    int i;

    if (!params || !src || !json_object_is_type(src, json_type_object))
        return;
    if (replace_filters)
        webd_ws_params_del_filter_keys(params);

    json_object_object_get_ex(src, "include", &include);
    json_object_object_get_ex(src, "exclude", &exclude);
    if (exclude && json_object_is_type(exclude, json_type_object))
        exclude_out = json_object_new_object();

    for (i = 0; i < (int)(sizeof(webd_insights_filter_fields) / sizeof(webd_insights_filter_fields[0])); i++) {
        const char *field = webd_insights_filter_fields[i];
        struct json_object *v = NULL;
        char exclude_key[96];

        if (include && json_object_is_type(include, json_type_object) &&
            json_object_object_get_ex(include, field, &v) && v)
            webd_ws_params_set_ref(params, field, v);
        else if (json_object_object_get_ex(src, field, &v) && v)
            webd_ws_params_set_ref(params, field, v);

        snprintf(exclude_key, sizeof(exclude_key), "exclude_%s", field);
        v = NULL;
        if (exclude && json_object_is_type(exclude, json_type_object) &&
            json_object_object_get_ex(exclude, field, &v) && v) {
            webd_ws_params_set_ref(params, exclude_key, v);
            if (exclude_out)
                webd_ws_params_set_ref(exclude_out, field, v);
        } else if (json_object_object_get_ex(src, exclude_key, &v) && v) {
            webd_ws_params_set_ref(params, exclude_key, v);
        }
    }
    if (exclude_out)
        json_object_object_add(params, "exclude", exclude_out);
}

static int webd_ws_params_object_has_filters(struct json_object *src)
{
    struct json_object *dummy = NULL;
    int i;

    if (!src || !json_object_is_type(src, json_type_object))
        return 0;
    if (json_object_object_get_ex(src, "include", &dummy) ||
        json_object_object_get_ex(src, "exclude", &dummy))
        return 1;
    for (i = 0; i < (int)(sizeof(webd_insights_filter_fields) / sizeof(webd_insights_filter_fields[0])); i++) {
        const char *field = webd_insights_filter_fields[i];
        char exclude_key[96];

        if (json_object_object_get_ex(src, field, &dummy))
            return 1;
        snprintf(exclude_key, sizeof(exclude_key), "exclude_%s", field);
        if (json_object_object_get_ex(src, exclude_key, &dummy))
            return 1;
    }
    return 0;
}

static void webd_ws_params_apply_object(struct json_object **params_ref,
                                        struct json_object *src,
                                        int replace_filters)
{
    struct json_object *filters = NULL;

    if (!params_ref || !src || !json_object_is_type(src, json_type_object))
        return;
    if (!*params_ref)
        *params_ref = json_object_new_object();
    webd_ws_params_copy_known_scalars(*params_ref, src);
    if (webd_ws_params_object_has_filters(src))
        webd_ws_params_apply_filter_obj(*params_ref, src, replace_filters);
    if (json_object_object_get_ex(src, "filters", &filters) && filters)
        webd_ws_params_apply_filter_obj(*params_ref, filters, replace_filters);
}

static void webd_ws_apply_client_msg(webd_ws_topics_t *topics,
                                     struct json_object **params_ref,
                                     const char *payload)
{
    struct json_object *msg = payload ? json_tokener_parse(payload) : NULL;
    struct json_object *arr = NULL;
    struct json_object *params = NULL;
    const char *type;
    int enabled;
    int i;

    if (!msg)
        return;
    type = app_nc_json_str(msg, "type", "");
    enabled = strcmp(type, "unsubscribe") != 0;
    if ((!strcmp(type, "subscribe") || !strcmp(type, "unsubscribe") || !strcmp(type, "update")) &&
        json_object_object_get_ex(msg, "topics", &arr) && arr &&
        json_object_is_type(arr, json_type_array)) {
        for (i = 0; i < (int)json_object_array_length(arr); i++)
            webd_ws_topics_set(topics, json_object_get_string(json_object_array_get_idx(arr, i)), enabled);
    }
    if (!strcmp(type, "subscribe") || !strcmp(type, "update")) {
        webd_ws_params_apply_object(params_ref, msg, 1);
        if (json_object_object_get_ex(msg, "params", &params) && params)
            webd_ws_params_apply_object(params_ref, params, 1);
    } else if (!strcmp(type, "ack")) {
        webd_ws_params_apply_object(params_ref, msg, 0);
        if (json_object_object_get_ex(msg, "params", &params) && params)
            webd_ws_params_apply_object(params_ref, params, 0);
    }
    json_object_put(msg);
}

#define WEBD_WS_MAX_CLIENT_CONNECTION_SUBS 8

struct webd_ws_client_connection_sub {
    int active;
    char subscription_id[48];
    char mac[32];
    char snapshot_id[96];
    uint64_t revision;
};

struct webd_ws_client_connection_subs {
    struct webd_ws_client_connection_sub items[
        WEBD_WS_MAX_CLIENT_CONNECTION_SUBS];
};

static struct webd_ws_client_connection_sub *
webd_ws_client_connection_sub_find(
    struct webd_ws_client_connection_subs *subs, const char *subscription_id)
{
    size_t i;

    if (!subs || !subscription_id || !subscription_id[0])
        return NULL;
    for (i = 0; i < WEBD_WS_MAX_CLIENT_CONNECTION_SUBS; i++)
        if (subs->items[i].active &&
            !strcmp(subs->items[i].subscription_id, subscription_id))
            return &subs->items[i];
    return NULL;
}

static struct webd_ws_client_connection_sub *
webd_ws_client_connection_sub_alloc(
    struct webd_ws_client_connection_subs *subs)
{
    size_t i;

    if (!subs)
        return NULL;
    for (i = 0; i < WEBD_WS_MAX_CLIENT_CONNECTION_SUBS; i++)
        if (!subs->items[i].active)
            return &subs->items[i];
    return NULL;
}

static struct webd_ws_client_connection_sub *
webd_ws_client_connection_sub_find_mac(
    struct webd_ws_client_connection_subs *subs, const char *mac)
{
    size_t i;

    if (!subs || !mac || !mac[0])
        return NULL;
    for (i = 0; i < WEBD_WS_MAX_CLIENT_CONNECTION_SUBS; i++)
        if (subs->items[i].active && !strcmp(subs->items[i].mac, mac))
            return &subs->items[i];
    return NULL;
}

static int webd_ws_client_connections_cursor(char *snapshot_id,
                                              size_t snapshot_id_len,
                                              uint64_t *revision)
{
    struct json_object *response;
    struct json_object *data;
    struct json_object *resources = NULL;
    size_t i;
    int found = 0;

    if (!snapshot_id || snapshot_id_len == 0 || !revision)
        return -1;
    snapshot_id[0] = '\0';
    *revision = 0;
    response = app_ubus_invoke_timeout("read_models_status", NULL, 1500);
    data = webd_data_from_jmx_response(response);
    if (data && json_object_object_get_ex(data, "resources", &resources) &&
        resources && json_object_is_type(resources, json_type_array)) {
        for (i = 0; i < json_object_array_length(resources); i++) {
            struct json_object *resource =
                json_object_array_get_idx(resources, i);
            const char *name = app_nc_json_str(resource, "name", "");
            const char *current_snapshot =
                app_nc_json_str(resource, "snapshot_id", "");
            int64_t current_revision =
                app_nc_json_int64(resource, "revision", 0);
            int64_t observed_at =
                app_nc_json_int64(resource, "observed_at", 0);

            if (strcmp(name, "client_connections"))
                continue;
            if (current_snapshot[0] && current_revision > 0 &&
                observed_at > 0 &&
                snprintf(snapshot_id, snapshot_id_len, "%s",
                         current_snapshot) < (int)snapshot_id_len) {
                *revision = (uint64_t)current_revision;
                found = 1;
            }
            break;
        }
    }
    if (data)
        json_object_put(data);
    if (response)
        json_object_put(response);
    return found ? 0 : -1;
}

static void webd_ws_client_connection_reject(struct json_object *rejected,
                                             const char *topic,
                                             const char *code,
                                             const char *message)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "topic",
                           json_object_new_string(topic ? topic : ""));
    json_object_object_add(item, "code",
                           json_object_new_string(code ? code : "rejected"));
    json_object_object_add(item, "message",
                           json_object_new_string(message ? message : ""));
    json_object_array_add(rejected, item);
}

static void webd_ws_client_connection_accept(struct json_object *accepted,
                                             const char *state,
                                             const struct webd_ws_client_connection_sub *sub)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "topic",
                           json_object_new_string("client.connections.v2"));
    json_object_object_add(item, "subscription_id",
                           json_object_new_string(sub->subscription_id));
    json_object_object_add(item, "entity_id",
                           json_object_new_string(sub->mac));
    json_object_object_add(item, "snapshot_id",
                           json_object_new_string(sub->snapshot_id));
    json_object_object_add(item, "revision",
                           json_object_new_int64((int64_t)sub->revision));
    if (state && state[0])
        json_object_object_add(item, "state", json_object_new_string(state));
    json_object_array_add(accepted, item);
}

static int webd_ws_client_connections_send_ack(int fd, const char *request_id,
                                                struct json_object *accepted,
                                                struct json_object *rejected)
{
    struct json_object *ack = json_object_new_object();
    int rc;

    json_object_object_add(ack, "type",
                           json_object_new_string("subscription_ack"));
    json_object_object_add(ack, "request_id",
                           json_object_new_string(request_id ? request_id : ""));
    json_object_object_add(ack, "accepted", accepted);
    json_object_object_add(ack, "rejected", rejected);
    json_object_object_add(ack, "ts", json_object_new_int64(now_s()));
    rc = webd_ws_send_json(fd, ack);
    json_object_put(ack);
    return rc;
}

static void webd_ws_client_connection_unsubscribe_one(
    struct webd_ws_client_connection_subs *subs, const char *subscription_id,
    struct json_object *accepted, struct json_object *rejected)
{
    struct webd_ws_client_connection_sub *sub =
        webd_ws_client_connection_sub_find(subs, subscription_id);

    if (!sub) {
        webd_ws_client_connection_reject(
            rejected, "client.connections.v2", "subscription_not_found",
            "subscription_id is not active on this connection");
        return;
    }
    webd_ws_client_connection_accept(accepted, "unsubscribed", sub);
    memset(sub, 0, sizeof(*sub));
}

static int webd_ws_client_connections_apply_message(
    int fd, struct webd_ws_client_connection_subs *subs, const char *payload)
{
    struct json_object *msg = payload ? json_tokener_parse(payload) : NULL;
    struct json_object *subscriptions = NULL;
    struct json_object *accepted;
    struct json_object *rejected;
    const char *type;
    const char *request_id;
    int handled = 0;
    size_t i;

    if (!msg || !json_object_is_type(msg, json_type_object)) {
        if (msg)
            json_object_put(msg);
        return 0;
    }
    type = app_nc_json_str(msg, "type", "");
    request_id = app_nc_json_str(msg, "request_id", "");
    if (!strcmp(type, "unsubscribe")) {
        struct json_object *ids = NULL;
        const char *subscription_id =
            app_nc_json_str(msg, "subscription_id", "");
        int has_v2_id = subscription_id[0] != '\0';

        if (!has_v2_id &&
            !json_object_object_get_ex(msg, "subscription_ids", &ids))
            json_object_object_get_ex(msg, "subscriptions", &ids);
        if (!has_v2_id && ids && json_object_is_type(ids, json_type_array)) {
            for (i = 0; i < json_object_array_length(ids); i++) {
                struct json_object *value = json_object_array_get_idx(ids, i);
                const char *id = json_object_is_type(value, json_type_object) ?
                    app_nc_json_str(value, "subscription_id", "") :
                    (json_object_is_type(value, json_type_string) ?
                     json_object_get_string(value) : "");

                if (id && id[0]) {
                    has_v2_id = 1;
                    break;
                }
            }
        }
        if (!has_v2_id) {
            json_object_put(msg);
            return 0;
        }
        handled = 1;
        accepted = json_object_new_array();
        rejected = json_object_new_array();
        if (subscription_id[0])
            webd_ws_client_connection_unsubscribe_one(
                subs, subscription_id, accepted, rejected);
        if (ids && json_object_is_type(ids, json_type_array)) {
            for (i = 0; i < json_object_array_length(ids); i++) {
                struct json_object *value = json_object_array_get_idx(ids, i);
                const char *id = json_object_is_type(value, json_type_object) ?
                    app_nc_json_str(value, "subscription_id", "") :
                    (json_object_is_type(value, json_type_string) ?
                     json_object_get_string(value) : "");

                if (id && id[0])
                    webd_ws_client_connection_unsubscribe_one(
                        subs, id, accepted, rejected);
            }
        }
        if (webd_ws_client_connections_send_ack(
                fd, request_id, accepted, rejected) != 0) {
            json_object_put(msg);
            return -1;
        }
        json_object_put(msg);
        return handled;
    }
    if (strcmp(type, "subscribe") ||
        !json_object_object_get_ex(msg, "subscriptions", &subscriptions) ||
        !subscriptions || !json_object_is_type(subscriptions, json_type_array)) {
        json_object_put(msg);
        return 0;
    }
    handled = 1;
    accepted = json_object_new_array();
    rejected = json_object_new_array();
    for (i = 0; i < json_object_array_length(subscriptions); i++) {
        struct json_object *request =
            json_object_array_get_idx(subscriptions, i);
        struct json_object *params = NULL;
        struct json_object *since_value = NULL;
        struct json_object *snapshot_value = NULL;
        struct webd_ws_client_connection_sub *sub;
        const char *topic = app_nc_json_str(request, "topic", "");
        const char *mac_raw;
        const char *requested_snapshot = "";
        int has_since;
        int has_snapshot;
        int64_t requested_revision = -1;
        char random_id[25];

        if (strcmp(topic, "client.connections.v2")) {
            webd_ws_client_connection_reject(
                rejected, topic, "unsupported_topic",
                "only client.connections.v2 is accepted in subscriptions[]");
            continue;
        }
        if (!request || !json_object_is_type(request, json_type_object) ||
            !json_object_object_get_ex(request, "params", &params) ||
            !params || !json_object_is_type(params, json_type_object)) {
            webd_ws_client_connection_reject(
                rejected, topic, "params_required",
                "params.mac is required");
            continue;
        }
        mac_raw = app_nc_json_str(params, "mac", "");
        has_since = json_object_object_get_ex(params, "since_revision",
                                              &since_value) && since_value;
        has_snapshot = json_object_object_get_ex(params, "snapshot_id",
                                                 &snapshot_value) &&
                       snapshot_value;
        if (has_since && json_object_is_type(since_value, json_type_int))
            requested_revision = json_object_get_int64(since_value);
        if (has_snapshot &&
            json_object_is_type(snapshot_value, json_type_string))
            requested_snapshot = json_object_get_string(snapshot_value);
        if (!mac_raw[0]) {
            webd_ws_client_connection_reject(
                rejected, topic, "mac_required", "params.mac is required");
            continue;
        }
        if (has_since != has_snapshot ||
            (has_since && (requested_revision < 0 ||
                           !requested_snapshot || !requested_snapshot[0]))) {
            webd_ws_client_connection_reject(
                rejected, topic, "invalid_resume_cursor",
                "snapshot_id and since_revision must be supplied together");
            continue;
        }
        sub = webd_ws_client_connection_sub_alloc(subs);
        if (!sub) {
            webd_ws_client_connection_reject(
                rejected, topic, "subscription_limit_reached",
                "this WebSocket already has the maximum active subscriptions");
            continue;
        }
        memset(sub, 0, sizeof(*sub));
        if (webd_normalize_mac_text(mac_raw, sub->mac,
                                    sizeof(sub->mac)) != 0) {
            webd_ws_client_connection_reject(
                rejected, topic, "invalid_mac", "params.mac is invalid");
            continue;
        }
        if (webd_ws_client_connection_sub_find_mac(subs, sub->mac)) {
            webd_ws_client_connection_reject(
                rejected, topic, "duplicate_entity_subscription",
                "this WebSocket already subscribes to this client");
            memset(sub, 0, sizeof(*sub));
            continue;
        }
        if (has_since) {
            if (strlen(requested_snapshot) >= sizeof(sub->snapshot_id)) {
                webd_ws_client_connection_reject(
                    rejected, topic, "invalid_resume_cursor",
                    "snapshot_id exceeds the supported length");
                memset(sub, 0, sizeof(*sub));
                continue;
            }
            memcpy(sub->snapshot_id, requested_snapshot,
                   strlen(requested_snapshot) + 1);
            sub->revision = (uint64_t)requested_revision;
        } else if (webd_ws_client_connections_cursor(
                       sub->snapshot_id, sizeof(sub->snapshot_id),
                       &sub->revision) != 0) {
            webd_ws_client_connection_reject(
                rejected, topic, "source_building",
                "client connection read model has no complete generation yet");
            memset(sub, 0, sizeof(*sub));
            continue;
        }
        if (gen_random_hex_checked(random_id, 24) != 0) {
            webd_ws_client_connection_reject(
                rejected, topic, "subscription_id_unavailable",
                "strong randomness is unavailable");
            memset(sub, 0, sizeof(*sub));
            continue;
        }
        snprintf(sub->subscription_id, sizeof(sub->subscription_id),
                 "sub-%s", random_id);
        sub->active = 1;
        webd_ws_client_connection_accept(accepted, "subscribed", sub);
    }
    if (webd_ws_client_connections_send_ack(
            fd, request_id, accepted, rejected) != 0) {
        json_object_put(msg);
        return -1;
    }
    json_object_put(msg);
    return handled;
}

static void webd_ws_copy_field(struct json_object *dst,
                               struct json_object *src, const char *key)
{
    struct json_object *value = NULL;

    if (dst && src && key &&
        json_object_object_get_ex(src, key, &value) && value)
        json_object_object_add(dst, key, json_object_get(value));
}

static struct json_object *webd_ws_client_connection_event(
    const struct webd_ws_client_connection_sub *sub,
    struct json_object *data, int resync)
{
    static const char *delta_fields[] = {
        "contract", "snapshot_id", "base_revision", "revision",
        "observed_at", "stale", "columns", "upserts", "removed",
        "complete", "reason"
    };
    struct json_object *event = json_object_new_object();
    size_t i;

    json_object_object_add(event, "type", json_object_new_string(
        resync ? "resync_required" : "event"));
    json_object_object_add(event, "topic",
                           json_object_new_string("client.connections.v2"));
    json_object_object_add(event, "subscription_id",
                           json_object_new_string(sub->subscription_id));
    json_object_object_add(event, "entity_id",
                           json_object_new_string(sub->mac));
    json_object_object_add(event, "ts", json_object_new_int64(now_s()));
    for (i = 0; i < sizeof(delta_fields) / sizeof(delta_fields[0]); i++)
        webd_ws_copy_field(event, data, delta_fields[i]);
    return event;
}

static int webd_ws_client_connections_push(
    int fd, struct webd_ws_client_connection_subs *subs)
{
    size_t i;

    if (!subs)
        return 0;
    for (i = 0; i < WEBD_WS_MAX_CLIENT_CONNECTION_SUBS; i++) {
        struct webd_ws_client_connection_sub *sub = &subs->items[i];
        struct json_object *params;
        struct json_object *response;
        struct json_object *data;
        struct json_object *event;
        const char *type;
        const char *snapshot_id;
        int64_t base_revision;
        int64_t revision;

        if (!sub->active)
            continue;
        params = json_object_new_object();
        json_object_object_add(params, "mac", json_object_new_string(sub->mac));
        json_object_object_add(params, "snapshot_id",
                               json_object_new_string(sub->snapshot_id));
        json_object_object_add(params, "since_revision",
                               json_object_new_int64((int64_t)sub->revision));
        response = app_ubus_invoke_timeout(
            "client_connections_delta", params, 1500);
        json_object_put(params);
        data = webd_data_from_jmx_response(response);
        if (!data) {
            if (response)
                json_object_put(response);
            continue;
        }
        type = app_nc_json_str(data, "type", "");
        if (!strcmp(type, "resync_required")) {
            event = webd_ws_client_connection_event(sub, data, 1);
            if (webd_ws_send_json(fd, event) != 0) {
                json_object_put(event);
                json_object_put(data);
                if (response)
                    json_object_put(response);
                return -1;
            }
            json_object_put(event);
            memset(sub, 0, sizeof(*sub));
            json_object_put(data);
            if (response)
                json_object_put(response);
            continue;
        }
        snapshot_id = app_nc_json_str(data, "snapshot_id", "");
        base_revision = app_nc_json_int64(data, "base_revision", -1);
        revision = app_nc_json_int64(data, "revision", -1);
        if (!snapshot_id[0] || strcmp(snapshot_id, sub->snapshot_id) ||
            base_revision != (int64_t)sub->revision ||
            revision < base_revision) {
            struct json_object *resync = json_object_new_object();

            json_object_object_add(resync, "contract",
                                   json_object_new_string(
                                       "client-connections.v2"));
            json_object_object_add(resync, "snapshot_id",
                                   json_object_new_string(snapshot_id));
            json_object_object_add(resync, "revision",
                                   json_object_new_int64(revision));
            json_object_object_add(resync, "reason",
                                   json_object_new_string(
                                       "source_rebuilt"));
            event = webd_ws_client_connection_event(sub, resync, 1);
            json_object_put(resync);
            if (webd_ws_send_json(fd, event) != 0) {
                json_object_put(event);
                json_object_put(data);
                if (response)
                    json_object_put(response);
                return -1;
            }
            json_object_put(event);
            memset(sub, 0, sizeof(*sub));
        } else if ((uint64_t)revision > sub->revision) {
            event = webd_ws_client_connection_event(sub, data, 0);
            if (webd_ws_send_json(fd, event) != 0) {
                json_object_put(event);
                json_object_put(data);
                if (response)
                    json_object_put(response);
                return -1;
            }
            json_object_put(event);
            sub->revision = (uint64_t)revision;
        }
        json_object_put(data);
        if (response)
            json_object_put(response);
    }
    return 0;
}


static struct json_object *webd_ws_event(const char *kind, const char *topic, struct json_object *data)
{
    static uint64_t sequence;
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "type", json_object_new_string(kind ? kind : "event"));
    if (topic && topic[0])
        json_object_object_add(root, "topic", json_object_new_string(topic));
    json_object_object_add(root, "seq",
                           json_object_new_int64((int64_t)__sync_add_and_fetch(&sequence, 1)));
    json_object_object_add(root, "ts", json_object_new_int64(now_s()));
    if (data)
        json_object_object_add(root, "data", data);
    else
        json_object_object_add(root, "data", json_object_new_object());
    return root;
}

static struct json_object *webd_ws_error_msg(const char *code, const char *message)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "type", json_object_new_string("error"));
    json_object_object_add(root, "code", json_object_new_string(code ? code : "error"));
    json_object_object_add(root, "message", json_object_new_string(message ? message : ""));
    json_object_object_add(root, "ts", json_object_new_int64(now_s()));
    return root;
}

static struct json_object *webd_ws_topics_request(const webd_ws_topics_t *topics)
{
    struct json_object *req = json_object_new_object();
    struct json_object *arr = json_object_new_array();

    if (!req || !arr) {
        if (req)
            json_object_put(req);
        if (arr)
            json_object_put(arr);
        return NULL;
    }
    if (!topics || topics->dashboard_metrics) {
        json_object_array_add(arr, json_object_new_string("dashboard.metrics"));
        json_object_object_add(req, "dashboard_metrics", json_object_new_boolean(1));
    }
    if (topics && topics->dashboard_throughput) {
        json_object_array_add(arr, json_object_new_string("dashboard.throughput"));
        json_object_object_add(req, "dashboard_throughput", json_object_new_boolean(1));
        json_object_object_add(req, "throughput_interval_ms",
                               json_object_new_int(WEBD_WS_THROUGHPUT_INTERVAL_MS));
    }
    if (topics && topics->topology_flow) {
        json_object_array_add(arr, json_object_new_string("topology.flow"));
        json_object_object_add(req, "topology_flow", json_object_new_boolean(1));
    }
    if (topics && topics->wan_metrics) {
        json_object_array_add(arr, json_object_new_string("wan.metrics"));
        json_object_object_add(req, "wan_metrics", json_object_new_boolean(1));
    }
    if (topics && topics->clients_metrics) {
        json_object_array_add(arr, json_object_new_string("clients.metrics"));
        json_object_object_add(req, "clients_metrics", json_object_new_boolean(1));
    }
    if (topics && topics->apps_metrics) {
        json_object_array_add(arr, json_object_new_string("apps.metrics"));
        json_object_object_add(req, "apps_metrics", json_object_new_boolean(1));
    }
    if (topics && topics->insights_flows_summary) {
        json_object_array_add(arr, json_object_new_string("insights.flows.summary"));
        json_object_object_add(req, "insights_flows_summary", json_object_new_boolean(1));
    }
    if (topics && topics->insights_flows_geo) {
        json_object_array_add(arr, json_object_new_string("insights.flows.geo"));
        json_object_object_add(req, "insights_flows_geo", json_object_new_boolean(1));
    }
    if (topics && topics->insights_activity_rate) {
        json_object_array_add(arr, json_object_new_string("insights.activity.rate"));
        json_object_object_add(req, "insights_activity_rate", json_object_new_boolean(1));
    }
    if (topics && topics->insights_activity_traffic) {
        json_object_array_add(arr, json_object_new_string("insights.activity.traffic"));
        json_object_object_add(req, "insights_activity_traffic", json_object_new_boolean(1));
    }
    if (topics && topics->insights_status) {
        json_object_array_add(arr, json_object_new_string("insights.status"));
        json_object_object_add(req, "insights_status", json_object_new_boolean(1));
    }
    json_object_object_add(req, "topics", arr);
    return req;
}

static void webd_ws_insights_query_from_params(struct json_object *params,
                                               struct webd_insights_query *q)
{
    webd_insights_read_query(NULL, params, q);
}

static struct json_object *webd_ws_insights_summary_data(struct json_object *params)
{
    struct webd_insights_query q;
    struct json_object *data;

    webd_ws_insights_query_from_params(params, &q);
    data = webd_insights_build_dataset(&q, 1000, 0, 1, 1, WEBD_INSIGHTS_PART_ALL);
    json_object_object_add(data, "transport", json_object_new_string("webd.realtime_ws_bff"));
    json_object_object_add(data, "topic", json_object_new_string("insights.flows.summary"));
    json_object_object_add(data, "ws_filters_supported", json_object_new_boolean(1));
    json_object_object_add(data, "ws_update_supported", json_object_new_boolean(1));
    return data;
}

static struct json_object *webd_ws_insights_geo_data(struct json_object *params)
{
    struct webd_insights_query q;
    struct json_object *data;

    webd_ws_insights_query_from_params(params, &q);
    data = webd_insights_geo_from_flows(&q, NULL);
    json_object_object_add(data, "period", json_object_new_string(q.period));
    json_object_object_add(data, "timestampFrom", json_object_new_int64(q.ts_from));
    json_object_object_add(data, "timestampTo", json_object_new_int64(q.ts_to));
    json_object_object_add(data, "transport", json_object_new_string("webd.realtime_ws_bff"));
    json_object_object_add(data, "topic", json_object_new_string("insights.flows.geo"));
    json_object_object_add(data, "ws_filters_supported", json_object_new_boolean(1));
    json_object_object_add(data, "ws_update_supported", json_object_new_boolean(1));
    return data;
}

static struct json_object *webd_ws_activity_body_from_params(struct json_object *params)
{
    struct webd_insights_query q;
    struct json_object *body = json_object_new_object();

    webd_ws_insights_query_from_params(params, &q);
    json_object_object_add(body, "period", json_object_new_string(q.period));
    json_object_object_add(body, "timestampFrom", json_object_new_int64(q.ts_from));
    json_object_object_add(body, "timestampTo", json_object_new_int64(q.ts_to));
    json_object_object_add(body, "start", json_object_new_int64(q.ts_from));
    json_object_object_add(body, "end", json_object_new_int64(q.ts_to));
    json_object_object_add(body, "top", json_object_new_int(q.top));
    if (q.search[0])
        json_object_object_add(body, "search_text", json_object_new_string(q.search));
    if (params)
        webd_ws_params_apply_object(&body, params, 0);
    return body;
}

static struct json_object *webd_ws_enveloped_data(struct json_object *envelope)
{
    struct json_object *data = NULL;

    if (!envelope)
        return NULL;
    if (json_object_object_get_ex(envelope, "data", &data) && data) {
        data = json_object_get(data);
        json_object_put(envelope);
        return data;
    }
    json_object_put(envelope);
    return NULL;
}

static struct json_object *webd_ws_insights_activity_rate_data(struct json_object *params)
{
    struct json_object *body = webd_ws_activity_body_from_params(params);
    struct json_object *data = webd_ws_enveloped_data(
        webd_insights_activity_rate_response(NULL, body, NULL));

    json_object_put(body);
    if (!data)
        data = json_object_new_object();
    json_object_object_add(data, "transport", json_object_new_string("webd.realtime_ws_bff"));
    json_object_object_add(data, "topic", json_object_new_string("insights.activity.rate"));
    json_object_object_add(data, "ws_update_supported", json_object_new_boolean(1));
    return data;
}

static struct json_object *webd_ws_insights_activity_traffic_data(struct json_object *params)
{
    struct json_object *body = webd_ws_activity_body_from_params(params);
    struct json_object *data = webd_ws_enveloped_data(
        webd_insights_activity_traffic_response(NULL, body, NULL));

    json_object_put(body);
    if (!data)
        data = json_object_new_object();
    json_object_object_add(data, "transport", json_object_new_string("webd.realtime_ws_bff"));
    json_object_object_add(data, "topic", json_object_new_string("insights.activity.traffic"));
    json_object_object_add(data, "ws_filters_supported", json_object_new_boolean(1));
    json_object_object_add(data, "ws_update_supported", json_object_new_boolean(1));
    return data;
}

static struct json_object *webd_ws_insights_status_data(void)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "available", json_object_new_boolean(1));
    json_object_object_add(data, "flows_summary_ws", json_object_new_boolean(1));
    json_object_object_add(data, "flows_geo_ws", json_object_new_boolean(1));
    json_object_object_add(data, "activity_rate_ws", json_object_new_boolean(1));
    json_object_object_add(data, "activity_traffic_ws", json_object_new_boolean(1));
    json_object_object_add(data, "geo_ws", json_object_new_boolean(1));
    json_object_object_add(data, "risk_ws", json_object_new_boolean(0));
    json_object_object_add(data, "ws_filters_supported", json_object_new_boolean(1));
    json_object_object_add(data, "ws_update_supported", json_object_new_boolean(1));
    json_object_object_add(data, "source", json_object_new_string("webd.realtime_ws_bff"));
    return data;
}

#define WEBD_WS_NOTIFICATION_DEDUPE_SIZE 64
#define WEBD_WS_NOTIFICATION_ID_LEN 128

static char g_webd_ws_notification_ids[WEBD_WS_NOTIFICATION_DEDUPE_SIZE]
                                      [WEBD_WS_NOTIFICATION_ID_LEN];
static unsigned int g_webd_ws_notification_id_count;
static unsigned int g_webd_ws_notification_id_next;

static void webd_ws_notifications_reset(void)
{
    memset(g_webd_ws_notification_ids, 0, sizeof(g_webd_ws_notification_ids));
    g_webd_ws_notification_id_count = 0;
    g_webd_ws_notification_id_next = 0;
}

static int webd_ws_notification_seen(const char *id)
{
    unsigned int i;

    if (!id || !id[0])
        return 0;
    for (i = 0; i < g_webd_ws_notification_id_count; i++)
        if (!strcmp(g_webd_ws_notification_ids[i], id))
            return 1;
    return 0;
}

static void webd_ws_notification_remember(const char *id)
{
    if (!id || !id[0] || webd_ws_notification_seen(id))
        return;
    snprintf(g_webd_ws_notification_ids[g_webd_ws_notification_id_next],
             WEBD_WS_NOTIFICATION_ID_LEN, "%s", id);
    g_webd_ws_notification_id_next =
        (g_webd_ws_notification_id_next + 1) % WEBD_WS_NOTIFICATION_DEDUPE_SIZE;
    if (g_webd_ws_notification_id_count < WEBD_WS_NOTIFICATION_DEDUPE_SIZE)
        g_webd_ws_notification_id_count++;
}

static void webd_ws_notifications_filter_sent(struct json_object *data)
{
    struct json_object *items = NULL;
    struct json_object *fresh;
    int suppressed = 0;
    int i;

    if (!data || !json_object_is_type(data, json_type_object) ||
        !json_object_object_get_ex(data, "items", &items) || !items ||
        !json_object_is_type(items, json_type_array))
        return;
    fresh = json_object_new_array();
    if (!fresh)
        return;
    for (i = 0; i < (int)json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);
        const char *id = app_nc_json_str(item, "id", "");

        if (!id[0] || webd_ws_notification_seen(id)) {
            suppressed++;
            continue;
        }
        webd_ws_notification_remember(id);
        json_object_array_add(fresh, json_object_get(item));
    }
    json_object_object_add(data, "items", fresh);
    json_object_object_add(data, "total",
                           json_object_new_int((int)json_object_array_length(fresh)));
    json_object_object_add(data, "has_more", json_object_new_boolean(0));
    json_object_object_add(data, "next_cursor", json_object_new_string(""));
    json_object_object_add(data, "new_count",
                           json_object_new_int((int)json_object_array_length(fresh)));
    json_object_object_add(data, "connection_duplicates_suppressed",
                           json_object_new_int(suppressed));
    json_object_object_add(data, "dedupe_scope",
                           json_object_new_string("websocket_connection"));
}

static struct json_object *webd_ws_notifications_data(void)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp;
    struct json_object *data;

    if (!req)
        return NULL;
    json_object_object_add(req, "limit", json_object_new_int(20));
    json_object_object_add(req, "state", json_object_new_string(""));
    json_object_object_add(req, "interrupt_only", json_object_new_boolean(1));
    json_object_object_add(req, "since", json_object_new_int64(now_s() - 3));
    resp = app_ubus_object_or_error("dreamingwrt.notifyd", "outbox_list", req);
    json_object_put(req);
    data = webd_data_or_self_from_jmx_response(resp);
    if (resp)
        json_object_put(resp);
    if (!data)
        return NULL;
    webd_ws_notifications_filter_sent(data);
    json_object_object_add(data, "transport", json_object_new_string("webd.realtime_ws_bff"));
    json_object_object_add(data, "topic", json_object_new_string("notifications"));
    json_object_object_add(data, "source", json_object_new_string("notifyd.outbox"));
    json_object_object_add(data, "surface", json_object_new_string("browser_interrupt"));
    json_object_object_add(data, "history_replayed", json_object_new_boolean(0));
    json_object_object_add(data, "delivery_semantics", json_object_new_string("recent_edge_events_only"));
    return data;
}

static struct json_object *webd_ws_logs_data(struct json_object *params, const char *topic)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp;
    struct json_object *data;
    struct json_object *code_obj = NULL;

    if (!req)
        return NULL;
    json_object_object_add(req, "pageNumber", json_object_new_int(0));
    json_object_object_add(req, "pageSize", json_object_new_int(20));
    if (params && json_object_is_type(params, json_type_object))
        webd_ws_params_apply_object(&req, params, 0);
    resp = app_ubus_invoke_object_timeout("dreamingwrt.logd", "unifi_search", req, 1500);
    json_object_put(req);
    if (!resp)
        return NULL;
    if (json_object_object_get_ex(resp, "code", &code_obj) && code_obj)
        data = webd_data_or_self_from_jmx_response(resp);
    else
        data = json_object_get(resp);
    json_object_put(resp);
    if (!data)
        return NULL;
    if (!json_object_is_type(data, json_type_object)) {
        struct json_object *wrapped = json_object_new_object();
        json_object_object_add(wrapped, "data", data);
        data = wrapped;
    }
    json_object_object_add(data, "transport", json_object_new_string("webd.realtime_ws_bff"));
    json_object_object_add(data, "topic", json_object_new_string(topic && topic[0] ? topic : "logs.events"));
    json_object_object_add(data, "source", json_object_new_string("dreamingwrt.logd.unifi_search"));
    json_object_object_add(data, "realtime", json_object_new_boolean(1));
    json_object_object_add(data, "ws_update_supported", json_object_new_boolean(1));
    json_object_object_add(data, "cursor_supported", json_object_new_boolean(1));
    json_object_object_add(data, "cursor_field", json_object_new_string("seq"));
    json_object_object_add(data, "ack_supported", json_object_new_boolean(1));
    return data;
}

static int webd_ws_client_mac_from_params(struct json_object *params,
                                          char *out, size_t out_len)
{
    const char *raw;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    raw = app_nc_json_str(params, "mac", "");
    if (!raw[0])
        raw = app_nc_json_str(params, "client_mac", "");
    if (!raw[0])
        return -1;
    return webd_normalize_mac_text(raw, out, out_len);
}

static struct json_object *webd_ws_client_profile_for_mac(const char *mac)
{
    struct http_req req;

    if (!mac || !mac[0])
        return NULL;
    memset(&req, 0, sizeof(req));
    snprintf(req.method, sizeof(req.method), "GET");
    snprintf(req.path, sizeof(req.path), "/api/v1/client_profile");
    snprintf(req.query, sizeof(req.query), "mac=%s", mac);
    return webd_client_profile_response(&req);
}

static struct json_object *webd_ws_client_topic_base(const char *topic,
                                                     const char *mac,
                                                     struct json_object *profile)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(
        profile ? app_nc_json_bool(profile, "ok", 0) : 0));
    webd_obj_add_str(data, "topic", topic);
    webd_obj_add_str(data, "mac", mac ? mac : "");
    webd_obj_add_str(data, "client_mac", mac ? mac : "");
    json_object_object_add(data, "ts", json_object_new_int64(now_s()));
    webd_obj_add_str(data, "transport", "webd.realtime_ws_bff");
    webd_obj_add_str(data, "source", "webd.client_profile");
    if (!mac || !mac[0])
        webd_obj_add_str(data, "error", "mac_required");
    else if (!profile || !app_nc_json_bool(profile, "ok", 0))
        webd_obj_add_str(data, "error", app_nc_json_str(profile, "error", "client_profile_unavailable"));
    return data;
}

static void webd_ws_client_add_current_flat(struct json_object *data,
                                            struct json_object *current)
{
    if (!data || !current)
        return;
    json_object_object_add(data, "online", json_object_new_boolean(app_nc_json_bool(current, "online", 0)));
    json_object_object_add(data, "up_rate", json_object_new_int64(app_nc_json_int64(current, "up_rate", 0)));
    json_object_object_add(data, "down_rate", json_object_new_int64(app_nc_json_int64(current, "down_rate", 0)));
    json_object_object_add(data, "tx_rate", json_object_new_int64(app_nc_json_int64(current, "tx_rate",
        app_nc_json_int64(current, "up_rate", 0))));
    json_object_object_add(data, "rx_rate", json_object_new_int64(app_nc_json_int64(current, "rx_rate",
        app_nc_json_int64(current, "down_rate", 0))));
    json_object_object_add(data, "connections", json_object_new_int64(app_nc_json_int64(current, "connections", 0)));
    json_object_object_add(data, "sample_valid", json_object_new_boolean(app_nc_json_bool(current, "sample_valid", 0)));
    json_object_object_add(data, "sample_age_ms", json_object_new_int64(app_nc_json_int64(current, "sample_age_ms", -1)));
    webd_obj_add_str(data, "rate_source", app_nc_json_str(current, "rate_source", ""));
    webd_obj_add_str(data, "online_source", app_nc_json_str(current, "online_source", ""));
    webd_obj_add_str(data, "neigh_state", app_nc_json_str(current, "neigh_state", ""));
    webd_obj_add_str(data, "zero_reason", app_nc_json_str(current, "zero_reason", ""));
}

static struct json_object *webd_ws_client_overview_data(const char *mac,
                                                        struct json_object *profile)
{
    struct json_object *data = webd_ws_client_topic_base("client.overview", mac, profile);
    struct json_object *current = webd_obj_child_obj(profile, "current");
    struct json_object *basic = webd_obj_child_obj(profile, "basic");
    struct json_object *overview = webd_obj_child_array(profile, "overview_history");
    struct json_object *traffic = webd_obj_child_array(profile, "traffic_history");
    struct json_object *cap = webd_obj_child_obj(profile, "capabilities");

    if (current) {
        json_object_object_add(data, "current", json_object_get(current));
        webd_ws_client_add_current_flat(data, current);
    }
    if (basic)
        json_object_object_add(data, "basic", json_object_get(basic));
    json_object_object_add(data, "overview_history", overview ? json_object_get(overview) : json_object_new_array());
    json_object_object_add(data, "traffic_history", traffic ? json_object_get(traffic) : json_object_new_array());
    json_object_object_add(data, "overview_window_sec", json_object_new_int(
        app_nc_json_int(cap, "overview_history_window_sec", 300)));
    json_object_object_add(data, "overview_step_sec", json_object_new_int(
        app_nc_json_int(cap, "overview_history_step_sec", 4)));
    webd_obj_add_str(data, "overview_source",
        app_nc_json_str(cap, "overview_history_source", "client_runtime_ring"));
    json_object_object_add(data, "degraded", json_object_new_boolean(
        !overview || json_object_array_length(overview) == 0));
    webd_obj_add_str(data, "reason", overview && json_object_array_length(overview) > 0 ? "" :
        app_nc_json_str(cap, "overview_history_reason", "no_runtime_samples_yet"));
    return data;
}

static struct json_object *webd_ws_client_detail_data(const char *mac,
                                                      struct json_object *profile)
{
    static const char *const fields[] = {
        "current", "basic", "detected_identity", "effective_identity",
        "override_fields", "traffic_history", "overview_history",
        "today_metrics", "protocol_summary", "connections", "sessions",
        "lines", "capabilities", "diagnostics", "source", NULL
    };
    struct json_object *data = webd_ws_client_topic_base("client.detail", mac,
                                                         profile);
    struct json_object *authorities = json_object_new_array();
    int i;

    for (i = 0; profile && fields[i]; i++) {
        struct json_object *value = NULL;

        if (json_object_object_get_ex(profile, fields[i], &value) && value)
            json_object_object_add(data, fields[i], json_object_get(value));
    }
    json_object_array_add(authorities, json_object_new_string("client.overview"));
    json_object_array_add(authorities, json_object_new_string("client.protocols"));
    json_object_array_add(authorities, json_object_new_string("client.connections"));
    json_object_array_add(authorities, json_object_new_string("client.connections.v2"));
    json_object_object_add(data, "authority_topics", authorities);
    json_object_object_add(data, "requires_mac",
                           json_object_new_boolean(1));
    webd_obj_add_str(data, "payload_contract", "client-detail.v1");
    webd_obj_add_str(data, "composition",
                     "client_profile_projection_of_authoritative_topics");
    return data;
}

static struct json_object *webd_ws_client_protocols_data(const char *mac,
                                                         struct json_object *profile)
{
    struct json_object *data = webd_ws_client_topic_base("client.protocols", mac, profile);
    struct json_object *summary = webd_obj_child_obj(profile, "protocol_summary");
    struct json_object *current = webd_obj_child_obj(profile, "current");

    if (current) {
        json_object_object_add(data, "current", json_object_get(current));
        webd_ws_client_add_current_flat(data, current);
    }
    if (summary) {
        struct json_object *protocols = webd_obj_child_array(summary, "protocols");
        struct json_object *items = webd_obj_child_array(summary, "items");
        struct json_object *categories = webd_obj_child_array(summary, "categories");
        struct json_object *history = webd_obj_child_array(summary, "rate_history");
        struct json_object *total_history = webd_obj_child_array(summary, "total_rate_history");

        json_object_object_add(data, "protocol_summary", json_object_get(summary));
        json_object_object_add(data, "protocols", protocols ? json_object_get(protocols) : json_object_new_array());
        json_object_object_add(data, "items", items ? json_object_get(items) : json_object_new_array());
        json_object_object_add(data, "categories", categories ? json_object_get(categories) : json_object_new_array());
        json_object_object_add(data, "rate_history", history ? json_object_get(history) : json_object_new_array());
        json_object_object_add(data, "history", history ? json_object_get(history) : json_object_new_array());
        json_object_object_add(data, "total_rate_history",
                               total_history ? json_object_get(total_history) : json_object_new_array());
        json_object_object_add(data, "rate_history_supported", json_object_new_boolean(
            app_nc_json_bool(summary, "rate_history_supported", 0)));
        json_object_object_add(data, "per_protocol_rate_history_supported", json_object_new_boolean(
            app_nc_json_bool(summary, "per_protocol_rate_history_supported", 0)));
        json_object_object_add(data, "total_rate_history_supported", json_object_new_boolean(
            app_nc_json_bool(summary, "total_rate_history_supported", 0)));
        json_object_object_add(data, "rate_history_revision", json_object_new_int64(
            app_nc_json_int64(summary, "rate_history_revision", 0)));
        json_object_object_add(data, "rate_history_observed_at", json_object_new_int64(
            app_nc_json_int64(summary, "rate_history_observed_at", 0)));
        json_object_object_add(data, "rate_history_producer_supported", json_object_new_boolean(
            app_nc_json_bool(summary, "rate_history_producer_supported", 0)));
        json_object_object_add(data, "rate_history_complete", json_object_new_boolean(
            app_nc_json_bool(summary, "rate_history_complete", 0)));
        json_object_object_add(data, "protocol_count", json_object_new_int(app_nc_json_int(summary, "protocol_count", 0)));
        json_object_object_add(data, "category_count", json_object_new_int(app_nc_json_int(summary, "category_count", 0)));
        json_object_object_add(data, "degraded", json_object_new_boolean(app_nc_json_bool(summary, "degraded", 0)));
        webd_obj_add_str(data, "rate_source", app_nc_json_str(summary, "rate_source", "unavailable"));
        webd_obj_add_str(data, "reason", app_nc_json_str(summary, "reason", ""));
    } else {
        json_object_object_add(data, "protocols", json_object_new_array());
        json_object_object_add(data, "items", json_object_new_array());
        json_object_object_add(data, "categories", json_object_new_array());
        json_object_object_add(data, "rate_history", json_object_new_array());
        json_object_object_add(data, "history", json_object_new_array());
        json_object_object_add(data, "total_rate_history", json_object_new_array());
        json_object_object_add(data, "rate_history_supported", json_object_new_boolean(0));
        json_object_object_add(data, "per_protocol_rate_history_supported", json_object_new_boolean(0));
        json_object_object_add(data, "total_rate_history_supported", json_object_new_boolean(0));
        json_object_object_add(data, "rate_history_revision", json_object_new_int64(0));
        json_object_object_add(data, "rate_history_observed_at", json_object_new_int64(0));
        json_object_object_add(data, "rate_history_producer_supported", json_object_new_boolean(0));
        json_object_object_add(data, "rate_history_complete", json_object_new_boolean(0));
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        webd_obj_add_str(data, "reason", "protocol_summary_unavailable");
    }
    return data;
}

static struct json_object *webd_ws_client_connections_data(const char *topic,
                                                           const char *mac,
                                                           struct json_object *profile)
{
    struct json_object *data = webd_ws_client_topic_base(topic, mac, profile);
    struct json_object *connections = webd_obj_child_array(profile, "connections");
    struct json_object *sessions = webd_obj_child_array(profile, "sessions");
    struct json_object *lines = webd_obj_child_array(profile, "lines");
    struct json_object *current = webd_obj_child_obj(profile, "current");
    struct json_object *cap = webd_obj_child_obj(profile, "capabilities");
    int current_connections = current ? app_nc_json_int(current, "connections", 0) : 0;
    int connection_samples = connections ? (int)json_object_array_length(connections) : 0;
    int session_samples = sessions ? (int)json_object_array_length(sessions) : 0;

    if (current) {
        json_object_object_add(data, "current", json_object_get(current));
        webd_ws_client_add_current_flat(data, current);
    }
    json_object_object_add(data, "connections", connections ? json_object_get(connections) : json_object_new_array());
    json_object_object_add(data, "sessions", sessions ? json_object_get(sessions) : json_object_new_array());
    json_object_object_add(data, "conntrack", connections ? json_object_get(connections) : json_object_new_array());
    json_object_object_add(data, "lines", lines ? json_object_get(lines) : json_object_new_array());
    json_object_object_add(data, "current_connections", json_object_new_int(current_connections));
    json_object_object_add(data, "active_connections", json_object_new_int(current_connections));
    json_object_object_add(data, "connection_count", json_object_new_int(current_connections));
    json_object_object_add(data, "total", json_object_new_int(connection_samples));
    json_object_object_add(data, "sample_count", json_object_new_int(connection_samples));
    json_object_object_add(data, "connection_sample_count", json_object_new_int(connection_samples));
    json_object_object_add(data, "session_sample_count", json_object_new_int(session_samples));
    json_object_object_add(data, "degraded", json_object_new_boolean(!connections || connection_samples == 0));
    webd_obj_add_str(data, "connection_source", app_nc_json_str(cap, "connection_source", ""));
    json_object_object_add(data, "connection_app_domain", json_object_new_boolean(
        app_nc_json_bool(cap, "connection_app_domain", 0)));
    if (!strcmp(topic, "client.conntrack"))
        webd_obj_add_str(data, "alias_of", "client.connections");
    if (!connections || connection_samples == 0)
        webd_obj_add_str(data, "reason", app_nc_json_str(cap, "sessions_reason", "no_connection_samples"));
    return data;
}

static void webd_ws_snapshot_overlay_client_detail(struct json_object *snapshot,
                                                   const webd_ws_topics_t *topics,
                                                   struct json_object *params)
{
    struct json_object *data = NULL;
    struct json_object *profile = NULL;
    char mac[32] = {0};
    int want;

    if (!snapshot || !topics)
        return;
    want = topics->client_detail || topics->client_overview ||
           topics->client_protocols ||
           topics->client_connections || topics->client_conntrack;
    if (!want)
        return;
    if (!json_object_object_get_ex(snapshot, "data", &data) ||
        !data || !json_object_is_type(data, json_type_object)) {
        data = json_object_new_object();
        json_object_object_add(snapshot, "data", data);
    }
    if (webd_ws_client_mac_from_params(params, mac, sizeof(mac)) == 0)
        profile = webd_ws_client_profile_for_mac(mac);

    if (topics->client_detail)
        json_object_object_add(data, "client.detail",
                               webd_ws_client_detail_data(mac, profile));
    if (topics->client_overview)
        json_object_object_add(data, "client.overview",
                               webd_ws_client_overview_data(mac, profile));
    if (topics->client_protocols)
        json_object_object_add(data, "client.protocols",
                               webd_ws_client_protocols_data(mac, profile));
    if (topics->client_connections)
        json_object_object_add(data, "client.connections",
                               webd_ws_client_connections_data("client.connections", mac, profile));
    if (topics->client_conntrack)
        json_object_object_add(data, "client.conntrack",
                               webd_ws_client_connections_data("client.conntrack", mac, profile));
    if (profile)
        json_object_put(profile);
}

static int webd_ws_logs_params_uncached(struct json_object *params)
{
    static const char *keys[] = {
        "cursor_seq", "since_seq", "after_seq", "last_seq",
        "cursor_rowid", "since_rowid", "after_rowid", "last_rowid",
        "cursor_ts", "since_ts", "after_ts", "last_ts",
        "cursor_id", "since_id", "after_id", "last_id",
        "incremental", "delta", "search_text", "searchText", "query",
        "timestampFrom", "timestampTo", "ts_from", "ts_to",
        "categories", "events", "deviceMacs", "clientDeviceMacs", "adminIds",
        "severities", "programs",
        NULL
    };
    int i;

    if (!params || !json_object_is_type(params, json_type_object))
        return 0;
    for (i = 0; keys[i]; i++) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(params, keys[i], &v) && v)
            return 1;
    }
    return 0;
}

static void webd_ws_snapshot_overlay_insights(struct json_object *snapshot,
                                              const webd_ws_topics_t *topics,
                                              struct json_object *params)
{
    struct json_object *data = NULL;

    if (!snapshot || !topics)
        return;
    if (!json_object_object_get_ex(snapshot, "data", &data) ||
        !data || !json_object_is_type(data, json_type_object)) {
        data = json_object_new_object();
        json_object_object_add(snapshot, "data", data);
    }
    if (topics->insights_flows_summary)
        json_object_object_add(data, "insights.flows.summary", webd_ws_insights_summary_data(params));
    if (topics->insights_flows_geo)
        json_object_object_add(data, "insights.flows.geo", webd_ws_insights_geo_data(params));
    if (topics->insights_activity_rate)
        json_object_object_add(data, "insights.activity.rate", webd_ws_insights_activity_rate_data(params));
    if (topics->insights_activity_traffic)
        json_object_object_add(data, "insights.activity.traffic", webd_ws_insights_activity_traffic_data(params));
    if (topics->insights_status)
        json_object_object_add(data, "insights.status", webd_ws_insights_status_data());
}

static struct json_object *webd_ws_route_status_data(void)
{
    struct json_object *response;
    struct json_object *route_data;
    int status = 200;

    response = webd_route_status_response(NULL, &status);
    route_data = webd_data_from_jmx_response(response);
    if (!route_data) {
        route_data = json_object_new_object();
        json_object_object_add(route_data, "available", json_object_new_boolean(0));
        json_object_object_add(route_data, "reason", json_object_new_string(
            status == 401 ? "unauthorized" : "route_status_source_unavailable"));
        json_object_object_add(route_data, "status", json_object_new_int(status));
    }
    if (response)
        json_object_put(response);
    return route_data;
}

static void webd_ws_snapshot_overlay_route_status(struct json_object *snapshot,
                                                   const webd_ws_topics_t *topics)
{
    struct json_object *data = NULL;

    if (!snapshot || !topics || !topics->route_status)
        return;
    if (!json_object_object_get_ex(snapshot, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object)) {
        data = json_object_new_object();
        json_object_object_add(snapshot, "data", data);
    }
    json_object_object_add(data, "route.status", webd_ws_route_status_data());
}

static void webd_ws_snapshot_overlay_notifications(struct json_object *snapshot,
                                                   const webd_ws_topics_t *topics)
{
    struct json_object *data = NULL;

    if (!snapshot || !topics || !topics->notifications)
        return;
    if (!json_object_object_get_ex(snapshot, "data", &data) ||
        !data || !json_object_is_type(data, json_type_object)) {
        data = json_object_new_object();
        json_object_object_add(snapshot, "data", data);
    }
    json_object_object_add(data, "notifications", webd_ws_notifications_data());
}

static void webd_ws_snapshot_overlay_logs(struct json_object *snapshot,
                                          const webd_ws_topics_t *topics,
                                          struct json_object *params)
{
    struct json_object *data = NULL;
    struct json_object *logs;

    if (!snapshot || !topics || !topics->logs_events)
        return;
    if (!json_object_object_get_ex(snapshot, "data", &data) ||
        !data || !json_object_is_type(data, json_type_object)) {
        data = json_object_new_object();
        json_object_object_add(snapshot, "data", data);
    }
    if (webd_ws_logs_params_uncached(params)) {
        logs = webd_ws_logs_data(params, "logs.events");
    } else {
        logs = jmx_cache_get("ws_logs_events");
        if (!logs) {
            logs = webd_ws_logs_data(params, "logs.events");
            if (logs)
                jmx_cache_put("ws_logs_events", logs, 2);
        }
    }
    if (logs) {
        json_object_object_add(data, "logs.events", json_object_get(logs));
        json_object_object_add(data, "logs.realtime", json_object_get(logs));
        json_object_object_add(data, "log.events", json_object_get(logs));
        json_object_put(logs);
    }
}

static void webd_ws_snapshot_overlay_appearance(struct json_object *snapshot,
                                                const webd_ws_topics_t *topics)
{
    struct json_object *data = NULL;

    if (!snapshot || !topics || !topics->web_appearance)
        return;
    if (!json_object_object_get_ex(snapshot, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object)) {
        data = json_object_new_object();
        json_object_object_add(snapshot, "data", data);
    }
    json_object_object_add(data, "web.appearance", webd_public_appearance_data());
}

static int webd_ws_throughput_snapshot_valid(struct json_object *snapshot)
{
    struct json_object *data = NULL;
    struct json_object *throughput = NULL;

    return snapshot && json_object_is_type(snapshot, json_type_object) &&
           json_object_object_get_ex(snapshot, "data", &data) && data &&
           json_object_is_type(data, json_type_object) &&
           json_object_object_get_ex(data, "dashboard.throughput", &throughput) &&
           throughput && json_object_is_type(throughput, json_type_object);
}

static struct json_object *webd_ws_throughput_cache_read_fresh(void)
{
    struct stat st;
    int64_t age_ms;
    struct json_object *snapshot;

    if (stat(WEBD_WS_THROUGHPUT_CACHE_PATH, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 65536)
        return NULL;
    age_ms = webd_now_ms() - webd_ws_file_mtime_ms(&st);
    if (age_ms < 0 || age_ms >= WEBD_WS_THROUGHPUT_CACHE_MAX_AGE_MS)
        return NULL;
    snapshot = json_object_from_file(WEBD_WS_THROUGHPUT_CACHE_PATH);
    if (!webd_ws_throughput_snapshot_valid(snapshot)) {
        if (snapshot)
            json_object_put(snapshot);
        return NULL;
    }
    return snapshot;
}

static void webd_ws_throughput_cache_write(struct json_object *snapshot)
{
    char tmp[192];
    const char *json;
    int fd;

    if (!webd_ws_throughput_snapshot_valid(snapshot))
        return;
    if (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST)
        return;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld",
                 WEBD_WS_THROUGHPUT_CACHE_PATH, (long)getpid()) >=
        (int)sizeof(tmp))
        return;
    json = json_object_to_json_string_ext(snapshot, JSON_C_TO_STRING_PLAIN);
    if (!json)
        return;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (webd_write_all(fd, json, strlen(json)) != 0 || close(fd) != 0) {
        unlink(tmp);
        return;
    }
    if (rename(tmp, WEBD_WS_THROUGHPUT_CACHE_PATH) != 0)
        unlink(tmp);
}

static struct json_object *webd_ws_shared_throughput_snapshot(struct json_object *req)
{
    struct json_object *snapshot;
    int lock_fd;

    snapshot = webd_ws_throughput_cache_read_fresh();
    if (snapshot)
        return snapshot;
    if (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST)
        return app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
    lock_fd = open(WEBD_WS_THROUGHPUT_LOCK_PATH,
                   O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0)
            close(lock_fd);
        return app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
    }
    snapshot = webd_ws_throughput_cache_read_fresh();
    if (!snapshot) {
        snapshot = app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
        if (snapshot)
            webd_ws_throughput_cache_write(snapshot);
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return snapshot;
}

static int webd_ws_fast_snapshot_valid(struct json_object *snapshot)
{
    struct json_object *data = NULL;
    struct json_object *dashboard = NULL;
    struct json_object *topology = NULL;

    return snapshot && json_object_is_type(snapshot, json_type_object) &&
           json_object_object_get_ex(snapshot, "data", &data) && data &&
           json_object_is_type(data, json_type_object) &&
           json_object_object_get_ex(data, "dashboard.metrics", &dashboard) &&
           dashboard && json_object_is_type(dashboard, json_type_object) &&
           json_object_object_get_ex(data, "topology.flow", &topology) &&
           topology && json_object_is_type(topology, json_type_object);
}

static struct json_object *webd_ws_fast_cache_read_fresh(void)
{
    struct stat st;
    int64_t age_ms;
    struct json_object *snapshot;

    if (stat(WEBD_WS_FAST_CACHE_PATH, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > 524288)
        return NULL;
    age_ms = webd_now_ms() - webd_ws_file_mtime_ms(&st);
    if (age_ms < 0 || age_ms >= WEBD_WS_FAST_CACHE_MAX_AGE_MS)
        return NULL;
    snapshot = json_object_from_file(WEBD_WS_FAST_CACHE_PATH);
    if (!webd_ws_fast_snapshot_valid(snapshot)) {
        if (snapshot)
            json_object_put(snapshot);
        return NULL;
    }
    return snapshot;
}

static void webd_ws_fast_cache_write(struct json_object *snapshot)
{
    char tmp[192];
    const char *json;
    int fd;

    if (!webd_ws_fast_snapshot_valid(snapshot))
        return;
    if (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST)
        return;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", WEBD_WS_FAST_CACHE_PATH,
                 (long)getpid()) >= (int)sizeof(tmp))
        return;
    json = json_object_to_json_string_ext(snapshot, JSON_C_TO_STRING_PLAIN);
    if (!json)
        return;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (webd_write_all(fd, json, strlen(json)) != 0 || close(fd) != 0) {
        unlink(tmp);
        return;
    }
    if (rename(tmp, WEBD_WS_FAST_CACHE_PATH) != 0)
        unlink(tmp);
}

static struct json_object *webd_ws_shared_fast_snapshot(struct json_object *req)
{
    struct json_object *snapshot;
    int lock_fd;

    snapshot = webd_ws_fast_cache_read_fresh();
    if (snapshot)
        return snapshot;
    if (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST)
        return app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
    lock_fd = open(WEBD_WS_FAST_LOCK_PATH,
                   O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0)
            close(lock_fd);
        return app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
    }
    snapshot = webd_ws_fast_cache_read_fresh();
    if (!snapshot) {
        snapshot = app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
        if (snapshot)
            webd_ws_fast_cache_write(snapshot);
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return snapshot;
}

static void webd_ws_merge_throughput_snapshot(struct json_object *fast_snapshot,
                                              struct json_object *throughput_snapshot)
{
    struct json_object *fast_data = NULL;
    struct json_object *throughput_data = NULL;
    struct json_object *throughput = NULL;

    if (!fast_snapshot || !throughput_snapshot ||
        !json_object_object_get_ex(fast_snapshot, "data", &fast_data) ||
        !fast_data || !json_object_is_type(fast_data, json_type_object) ||
        !json_object_object_get_ex(throughput_snapshot, "data",
                                   &throughput_data) ||
        !throughput_data ||
        !json_object_is_type(throughput_data, json_type_object) ||
        !json_object_object_get_ex(throughput_data, "dashboard.throughput",
                                   &throughput) || !throughput)
        return;
    json_object_object_add(fast_data, "dashboard.throughput",
                           json_object_get(throughput));
}

struct json_object *webd_ws_snapshot_data(const webd_ws_topics_t *topics,
                                                 struct json_object *params)
{
    struct json_object *req = NULL;
    struct json_object *resp = NULL;

    if (webd_ws_topics_need_core_snapshot(topics)) {
        if (!webd_ws_topics_only_throughput(topics) &&
            webd_ws_topics_have_fast_core(topics)) {
            webd_ws_topics_t shared_topics = webd_ws_all_fast_core_topics();

            req = webd_ws_topics_request(&shared_topics);
        } else {
            req = webd_ws_topics_request(topics);
        }
        if (!req)
            return NULL;
        if (webd_ws_topics_only_throughput(topics))
            resp = webd_ws_shared_throughput_snapshot(req);
        else if (webd_ws_topics_have_fast_core(topics))
            resp = webd_ws_shared_fast_snapshot(req);
        else
            resp = app_ubus_invoke_timeout("realtime_snapshot", req, 1500);
        json_object_put(req);
        if (resp && topics && topics->dashboard_throughput &&
            webd_ws_topics_have_fast_core(topics)) {
            webd_ws_topics_t throughput_topics;
            struct json_object *throughput_req;
            struct json_object *throughput_snapshot;

            memset(&throughput_topics, 0, sizeof(throughput_topics));
            throughput_topics.dashboard_throughput = 1;
            throughput_req = webd_ws_topics_request(&throughput_topics);
            throughput_snapshot = throughput_req ?
                webd_ws_shared_throughput_snapshot(throughput_req) : NULL;
            if (throughput_req)
                json_object_put(throughput_req);
            if (throughput_snapshot) {
                webd_ws_merge_throughput_snapshot(resp, throughput_snapshot);
                json_object_put(throughput_snapshot);
            }
        }
    }
    if (!resp) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ts", json_object_new_int64(now_s()));
        json_object_object_add(resp, "window_sec", json_object_new_int(1));
        json_object_object_add(resp, "topics", json_object_new_array());
        json_object_object_add(resp, "data", json_object_new_object());
    }
    webd_ws_snapshot_overlay_insights(resp, topics, params);
    webd_ws_snapshot_overlay_route_status(resp, topics);
    webd_ws_snapshot_overlay_client_detail(resp, topics, params);
    webd_ws_snapshot_overlay_notifications(resp, topics);
    webd_ws_snapshot_overlay_logs(resp, topics, params);
    webd_ws_snapshot_overlay_appearance(resp, topics);
    return resp;
}

static int webd_ws_send_topic_data(int fd, const char *kind, const char *topic,
                                   struct json_object *data)
{
    struct json_object *msg;
    int rc;

    if (!data)
        msg = webd_ws_error_msg("source_unavailable", topic ? topic : "topic unavailable");
    else
        msg = webd_ws_event(kind, topic, data);
    rc = webd_ws_send_json(fd, msg);
    json_object_put(msg);
    return rc;
}

uint64_t webd_ws_semantic_hash(uint64_t hash, struct json_object *value)
{
    const char *text;

    if (!value)
        return (hash ^ 0xffU) * 1099511628211ULL;
    if (json_object_is_type(value, json_type_object)) {
        json_object_object_foreach(value, key, child) {
            const unsigned char *p;

            if (!strcmp(key, "ts") || !strcmp(key, "sample_age_ms") ||
                !strcmp(key, "runtime_updated_at") || !strcmp(key, "updated_at") ||
                !strcmp(key, "last_decision_at"))
                continue;
            for (p = (const unsigned char *)key; *p; p++)
                hash = (hash ^ *p) * 1099511628211ULL;
            hash = webd_ws_semantic_hash(hash, child);
        }
        return hash;
    }
    if (json_object_is_type(value, json_type_array)) {
        int i;
        for (i = 0; i < (int)json_object_array_length(value); i++)
            hash = webd_ws_semantic_hash(hash, json_object_array_get_idx(value, i));
        return hash;
    }
    text = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    if (text) {
        const unsigned char *p;
        for (p = (const unsigned char *)text; *p; p++)
            hash = (hash ^ *p) * 1099511628211ULL;
    }
    return hash;
}

static int webd_ws_send_route_status_if_changed(int fd, const char *kind,
                                                 int force, uint64_t *last_hash)
{
    struct json_object *data = webd_ws_route_status_data();
    uint64_t hash;
    int rc = 0;

    if (!data)
        return -1;
    hash = webd_ws_semantic_hash(1469598103934665603ULL, data);
    if (force || !last_hash || !*last_hash || *last_hash != hash) {
        rc = webd_ws_send_topic_data(fd, kind, "route.status", data);
        if (rc == 0 && last_hash)
            *last_hash = hash;
    } else {
        json_object_put(data);
    }
    return rc;
}

static uint64_t webd_ws_appearance_row_hash(void)
{
    sqlite3_stmt *st = NULL;
    uint64_t hash = 1469598103934665603ULL;
    int i;

    if (!g_config_db || sqlite3_prepare_v2(g_config_db,
        "SELECT * FROM appearance_settings WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return 1;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return 1;
    }
    for (i = 0; i < sqlite3_column_count(st); i++) {
        const unsigned char *text = sqlite3_column_text(st, i);
        int len = sqlite3_column_bytes(st, i);
        int j;

        hash = (hash ^ (unsigned char)sqlite3_column_type(st, i)) * 1099511628211ULL;
        hash = (hash ^ (unsigned char)i) * 1099511628211ULL;
        for (j = 0; text && j < len; j++)
            hash = (hash ^ text[j]) * 1099511628211ULL;
    }
    sqlite3_finalize(st);
    return hash ? hash : 1;
}

static int webd_ws_send_appearance_if_changed(int fd, const char *kind,
                                              int force, uint64_t *last_hash)
{
    uint64_t hash = webd_ws_appearance_row_hash();
    int rc = 0;

    if (force || !last_hash || !*last_hash || *last_hash != hash) {
        struct json_object *data = webd_public_appearance_data();

        if (!data)
            return -1;
        rc = webd_ws_send_topic_data(fd, kind, "web.appearance", data);
        if (rc == 0 && last_hash)
            *last_hash = hash;
    }
    return rc;
}

static int webd_ws_send_snapshot_topics(int fd, const char *kind,
                                        const webd_ws_topics_t *topics,
                                        struct json_object *params)
{
    struct json_object *snapshot = webd_ws_snapshot_data(topics, params);
    struct json_object *topic_data = NULL;
    int rc = 0;

    if (!snapshot ||
        !json_object_object_get_ex(snapshot, "data", &topic_data) ||
        !topic_data || !json_object_is_type(topic_data, json_type_object)) {
        struct json_object *err = webd_ws_error_msg("source_unavailable", "realtime snapshot source unavailable");
        rc = webd_ws_send_json(fd, err);
        json_object_put(err);
        if (snapshot)
            json_object_put(snapshot);
        return rc;
    }

#define WEBD_WS_EMIT_TOPIC(flag, name) do { \
        struct json_object *v = NULL; \
        if ((flag) && json_object_object_get_ex(topic_data, (name), &v) && v) { \
            rc = webd_ws_send_topic_data(fd, kind, (name), json_object_get(v)); \
            if (rc != 0) { json_object_put(snapshot); return rc; } \
        } \
    } while (0)

    WEBD_WS_EMIT_TOPIC(!topics || topics->dashboard_metrics, "dashboard.metrics");
    WEBD_WS_EMIT_TOPIC(topics && topics->dashboard_throughput, "dashboard.throughput");
    WEBD_WS_EMIT_TOPIC(topics && topics->topology_flow, "topology.flow");
    WEBD_WS_EMIT_TOPIC(topics && topics->wan_metrics, "wan.metrics");
    WEBD_WS_EMIT_TOPIC(topics && topics->route_status, "route.status");
    WEBD_WS_EMIT_TOPIC(topics && topics->clients_metrics, "clients.metrics");
    WEBD_WS_EMIT_TOPIC(topics && topics->apps_metrics, "apps.metrics");
    WEBD_WS_EMIT_TOPIC(topics && topics->client_detail, "client.detail");
    WEBD_WS_EMIT_TOPIC(topics && topics->client_overview, "client.overview");
    WEBD_WS_EMIT_TOPIC(topics && topics->client_protocols, "client.protocols");
    WEBD_WS_EMIT_TOPIC(topics && topics->client_connections, "client.connections");
    WEBD_WS_EMIT_TOPIC(topics && topics->client_conntrack, "client.conntrack");
    WEBD_WS_EMIT_TOPIC(topics && topics->notifications, "notifications");
    WEBD_WS_EMIT_TOPIC(topics && topics->logs_events, "logs.events");
    WEBD_WS_EMIT_TOPIC(topics && topics->logs_events, "logs.realtime");
    WEBD_WS_EMIT_TOPIC(topics && topics->logs_events, "log.events");
    WEBD_WS_EMIT_TOPIC(topics && topics->web_appearance, "web.appearance");
    WEBD_WS_EMIT_TOPIC(topics && topics->insights_flows_summary, "insights.flows.summary");
    WEBD_WS_EMIT_TOPIC(topics && topics->insights_flows_geo, "insights.flows.geo");
    WEBD_WS_EMIT_TOPIC(topics && topics->insights_activity_rate, "insights.activity.rate");
    WEBD_WS_EMIT_TOPIC(topics && topics->insights_activity_traffic, "insights.activity.traffic");
    WEBD_WS_EMIT_TOPIC(topics && topics->insights_status, "insights.status");

#undef WEBD_WS_EMIT_TOPIC

    json_object_put(snapshot);
    return 0;
}

void webd_realtime_ws_session(int fd, const struct http_req *req, const char *device_id)
{
    char accept_key[128];
    char hdr[512];
    int hlen;
    webd_ws_topics_t topics = {0};
    time_t started = now_s();
    time_t last_push = 0;
    int64_t last_push_ms = 0;
    time_t last_insights_push = started;
    time_t last_auth = started;
    int64_t last_throughput_push_ms = 0;
    /*
     * Why the session ends, reported to the client as a close code so it can
     * choose between a silent token refresh and telling the user. Defaults to the
     * lifetime cap because that is the outcome when the loop simply runs out.
     */
    int close_code = 1001;
    const char *close_reason = "access_token_lifetime_reached";
    uint64_t last_route_status_hash = 0;
    uint64_t last_appearance_hash = 0;
    int push_now = 0;
    struct json_object *insights_params = NULL;
    struct webd_ws_client_connection_subs connection_subs = {{0}};

    if (!req || !req->websocket || webd_ws_accept_key(req->ws_key, accept_key, sizeof(accept_key)) != 0) {
        struct json_object *err = webd_error("bad_websocket_handshake", "invalid websocket handshake", "Sec-WebSocket-Key", "webd.realtime");
        http_send_json(fd, 400, err);
        json_object_put(err);
        return;
    }

    hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n",
        accept_key);
    if (hlen <= 0 || hlen >= (int)sizeof(hdr) ||
        webd_write_all(fd, hdr, (size_t)hlen) != 0)
        return;

    topics.dashboard_metrics = 1;
    webd_ws_notifications_reset();
    insights_params = json_object_new_object();
    /*
     * Tell the client the session's own rules up front. Without this the app can
     * only discover the lifetime cap by being disconnected, and it has no way to
     * know that the server never sends ping frames, so it cannot size its own
     * keepalive or refresh timer. Sent before the first snapshot so it is
     * available immediately after the handshake.
     */
    {
        struct json_object *hello = json_object_new_object();

        json_object_object_add(hello, "type", json_object_new_string("session"));
        json_object_object_add(hello, "ts", json_object_new_int64(started));
        json_object_object_add(hello, "max_lifetime_s",
                               json_object_new_int(WEBD_WS_MAX_LIFETIME_S));
        json_object_object_add(hello, "expires_at",
                               json_object_new_int64((int64_t)started +
                                                     WEBD_WS_MAX_LIFETIME_S));
        json_object_object_add(hello, "auth_check_interval_s",
                               json_object_new_int(WEBD_WS_AUTH_CHECK_S));
        json_object_object_add(hello, "throughput_interval_ms",
                               json_object_new_int(WEBD_WS_THROUGHPUT_INTERVAL_MS));
        /* The other fast topics run on their own, slower cadence. Advertising it
         * lets the client size its render loop instead of inferring the rate from
         * arrival times. */
        json_object_object_add(hello, "fast_interval_ms",
                               json_object_new_int(WEBD_WS_FAST_INTERVAL_MS));
        json_object_object_add(hello, "insights_interval_ms",
                               json_object_new_int(5000));
        json_object_object_add(hello, "max_payload_bytes",
                               json_object_new_int(WEBD_WS_MAX_PAYLOAD));
        json_object_object_add(hello, "max_concurrent_sessions",
                               json_object_new_int(WEBD_WS_MAX_CHILDREN));
        /* The server answers pings but never initiates them, so keepalive is the
         * client's responsibility. Saying so avoids a client that waits forever
         * for a ping that will not come. */
        json_object_object_add(hello, "server_ping", json_object_new_boolean(0));
        json_object_object_add(hello, "client_ping_expected",
                               json_object_new_boolean(1));
        json_object_object_add(hello, "unknown_topics_ignored",
                               json_object_new_boolean(1));
        json_object_object_add(hello, "parameterized_subscriptions",
                               json_object_new_boolean(1));
        json_object_object_add(hello, "client_connections_v2",
                               json_object_new_boolean(1));
        json_object_object_add(hello, "client_detail_topic",
                               json_object_new_boolean(1));
        json_object_object_add(hello, "client_detail_requires_mac",
                               json_object_new_boolean(1));
        json_object_object_add(hello, "max_client_connection_subscriptions",
                               json_object_new_int(
                                   WEBD_WS_MAX_CLIENT_CONNECTION_SUBS));
        webd_ws_send_json(fd, hello);
        json_object_put(hello);
    }
    webd_ws_send_snapshot_topics(fd, "snapshot", &topics, insights_params);

    while (now_s() - started < WEBD_WS_MAX_LIFETIME_S) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLERR | POLLHUP };
        /*
         * The loop can only push as often as it wakes, so the timeout has to
         * track the shortest cadence actually subscribed. Leaving it at 1000ms
         * would hold the fast topics at 1Hz no matter what the gate below says,
         * which is how the old second-granularity cap survived being "fixed"
         * anywhere else.
         */
        int poll_timeout_ms = topics.dashboard_throughput ?
                              WEBD_WS_THROUGHPUT_INTERVAL_MS :
                              WEBD_WS_FAST_INTERVAL_MS;
        int rc = poll(&pfd, 1, poll_timeout_ms);
        time_t now = now_s();
        int64_t now_ms = webd_now_ms();

        if (rc < 0) {
            if (errno == EINTR)
                continue;
            close_code = 1011;
            close_reason = "poll_failed";
            break;
        }
        if (rc > 0) {
            if (pfd.revents & (POLLERR | POLLHUP)) {
                close_code = 1001;
                close_reason = "peer_hangup";
                break;
            }
            if (pfd.revents & POLLIN) {
                char payload[WEBD_WS_MAX_PAYLOAD + 1];
                int opcode = 0;
                int n = webd_ws_read_frame(fd, payload, sizeof(payload), &opcode);

                if (n < 0) {
                    close_code = 1002;
                    close_reason = "malformed_frame";
                    break;
                }
                if (opcode == 8) {
                    /* Client initiated the close; echo 1000 rather than invent a
                     * reason of our own. */
                    close_code = 1000;
                    close_reason = "client_closed";
                    break;
                }
                if (opcode == 9) {
                    webd_ws_send_frame(fd, 10, "");
                } else if (opcode == 1) {
                    int handled = webd_ws_client_connections_apply_message(
                        fd, &connection_subs, payload);

                    if (handled < 0) {
                        close_code = 1011;
                        close_reason = "subscription_ack_write_failed";
                        break;
                    }
                    if (!handled) {
                        webd_ws_apply_client_msg(&topics, &insights_params,
                                                 payload);
                        push_now = 1;
                    }
                }
            }
        }
        if (now - last_auth >= WEBD_WS_AUTH_CHECK_S) {
            int token_state = WEBD_AUTH_DB_INVALID;
            char *check = jmx_app_validate_token_mode(req->auth_token,
                                                       &token_state, 0);

            if (!check) {
                const char *code = token_state == WEBD_AUTH_DB_IDLE_TIMEOUT ?
                                   WEBD_SESSION_IDLE_ERROR : "auth.expired";
                struct json_object *expired = webd_ws_error_msg(
                    code, token_state == WEBD_AUTH_DB_IDLE_TIMEOUT ?
                          "web session idle timeout" : "session expired");
                webd_ws_send_json(fd, expired);
                json_object_put(expired);
                /*
                 * 4001 is a private-use code meaning "the credential expired,
                 * refresh and reconnect". It is deliberately distinct from the
                 * idle-timeout case (4002), where reconnecting without user
                 * activity would just be logged out again.
                 */
                close_code = token_state == WEBD_AUTH_DB_IDLE_TIMEOUT ? 4002 : 4001;
                close_reason = token_state == WEBD_AUTH_DB_IDLE_TIMEOUT ?
                               "session_idle_timeout" : "access_token_expired";
                break;
            }
            free(check);
            last_auth = now;
        }
        if (webd_ws_client_connections_push(fd, &connection_subs) != 0) {
            close_code = 1011;
            close_reason = "client_connections_delta_write_failed";
            break;
        }
        {
            webd_ws_topics_t fast = webd_ws_fast_topics(&topics);
            webd_ws_topics_t insights = webd_ws_insights_topics(&topics);
            webd_ws_topics_t throughput = {0};

            /* Every break below is a failed write, i.e. the socket is already
             * gone. The close frame will not arrive, but the code is set anyway
             * so the intent is recorded and the final send stays uniform. */
            if (!topics.route_status)
                last_route_status_hash = 0;
            else if (webd_ws_send_route_status_if_changed(
                         fd, push_now ? "snapshot" : "event", push_now,
                         &last_route_status_hash) != 0) {
                close_code = 1011;
                close_reason = "push_write_failed";
                break;
            }

            if (!topics.web_appearance)
                last_appearance_hash = 0;
            else if (webd_ws_send_appearance_if_changed(
                         fd, push_now ? "snapshot" : "event", push_now,
                         &last_appearance_hash) != 0) {
                close_code = 1011;
                close_reason = "push_write_failed";
                break;
            }

            if (topics.dashboard_throughput &&
                (push_now || last_throughput_push_ms <= 0 ||
                 now_ms - last_throughput_push_ms >=
                     WEBD_WS_THROUGHPUT_INTERVAL_MS)) {
                throughput.dashboard_throughput = 1;
                last_throughput_push_ms = now_ms;
                if (webd_ws_send_snapshot_topics(fd, push_now ? "snapshot" : "event",
                                                 &throughput, insights_params) != 0) {
                    close_code = 1011;
                    close_reason = "push_write_failed";
                    break;
                }
            }

            fast.dashboard_throughput = 0;
            fast.route_status = 0;
            fast.web_appearance = 0;

            /*
             * Millisecond gate. The previous `now == last_push` comparison was
             * time_t, so these topics could not exceed 1Hz however short the
             * poll timeout was -- the cap was the clock's resolution, not a
             * decision about cost.
             *
             * insights.* keeps its 5s cadence: those are aggregate queries, an
             * order of magnitude more expensive than the fast topics, and the
             * second condition below is what lets an insights push through in a
             * window where the fast topics are not yet due.
             */
            if (!push_now && last_push_ms > 0 &&
                now_ms - last_push_ms < WEBD_WS_FAST_INTERVAL_MS &&
                !webd_ws_topics_any(&insights))
                continue;
            if (!push_now && last_push_ms > 0 &&
                now_ms - last_push_ms < WEBD_WS_FAST_INTERVAL_MS &&
                webd_ws_topics_any(&insights) &&
                now - last_insights_push < 5)
                continue;
            last_push = now;
            last_push_ms = now_ms;

            if (webd_ws_topics_any(&fast) &&
                webd_ws_send_snapshot_topics(fd, push_now ? "snapshot" : "event",
                                             &fast, insights_params) != 0) {
                close_code = 1011;
                close_reason = "push_write_failed";
                break;
            }
            if (webd_ws_topics_any(&insights) && (push_now || now - last_insights_push >= 5)) {
                last_insights_push = now;
                if (webd_ws_send_snapshot_topics(fd, "event", &insights, insights_params) != 0) {
                    close_code = 1011;
                    close_reason = "push_write_failed";
                    break;
                }
            }
        }
        push_now = 0;
    }
    (void)device_id;
    if (insights_params)
        json_object_put(insights_params);
    webd_ws_send_close(fd, close_code, close_reason);
}

/* -- Dashboard snapshot/live + topology node detail (Phase 8B) --------------
 * Lifted verbatim out of jmx_app_api.c together with the three dashboard
 * timing knobs only they use. handle_client dispatches the three builders,
 * declared in api_realtime_internal.h; none is a jmx_api_route table row.
 * The live builder shares webd_ws_snapshot_data() with the WS session above.
 */
#define WEBD_DASHBOARD_SNAPSHOT_TTL_SEC 2
#define WEBD_DASHBOARD_SNAPSHOT_STALE_SEC 60
#define WEBD_DASHBOARD_SUMMARY_TIMEOUT_MS 3000

static void webd_mark_dashboard_snapshot_stale(struct json_object *resp, int age_ms)
{
    webd_mark_cached_response_stale(resp, age_ms, "summary_timeout_stale_cache");
}

struct json_object *webd_dashboard_snapshot_response(int *status)
{
    int cache_age_ms = 0;
    int cache_stale = 0;
    struct json_object *cached;
    struct json_object *data;
    struct json_object *resp;

    cached = jmx_cache_get_allow_stale("dashboard_snapshot",
                                       WEBD_DASHBOARD_SNAPSHOT_STALE_SEC,
                                       &cache_age_ms, &cache_stale);
    if (cached && !cache_stale)
        return cached;

    data = app_ubus_invoke_timeout("summary", NULL, WEBD_DASHBOARD_SUMMARY_TIMEOUT_MS);
    if (data) {
        resp = webd_envelope(data, "jmxd.summary");
        if (resp)
            jmx_cache_put_with_stale("dashboard_snapshot", resp,
                                     WEBD_DASHBOARD_SNAPSHOT_TTL_SEC,
                                     WEBD_DASHBOARD_SNAPSHOT_STALE_SEC);
        if (cached)
            json_object_put(cached);
        return resp;
    }

    if (cached) {
        resp = webd_json_clone(cached);
        json_object_put(cached);
        if (resp) {
            webd_mark_dashboard_snapshot_stale(resp, cache_age_ms);
            return resp;
        }
    }

    /* Keep the legacy route usable when the full summary is cold or blocked.
     * The realtime model is a bounded, explicitly degraded fallback; callers
     * can inspect the metadata instead of mistaking it for historical summary
     * data. */
    resp = webd_dashboard_live_response(status);
    if (resp && app_nc_json_bool(resp, "ok", 0)) {
        struct json_object *meta = NULL;

        if (json_object_object_get_ex(resp, "meta", &meta) && meta &&
            json_object_is_type(meta, json_type_object)) {
            json_object_object_add(meta, "fallback", json_object_new_boolean(1));
            webd_obj_add_str(meta, "fallback_source", "jmxd.realtime_snapshot");
            webd_obj_add_str(meta, "summary_source_error", "summary_timeout_or_unavailable");
        }
        return resp;
    }
    if (resp)
        json_object_put(resp);

    if (status)
        *status = 503;
    return webd_error("source_unavailable", "dashboard snapshot source is not available", "dreamingwrt summary", "webd");
}

struct json_object *webd_dashboard_live_response(int *status)
{
    webd_ws_topics_t topics = {0};
    struct json_object *snapshot;
    struct json_object *shared;
    struct json_object *data;
    struct json_object *resp;
    struct json_object *meta;
    int shared_age_ms = 0;
    int lock_fd = -1;

    topics.dashboard_metrics = 1;
    topics.dashboard_throughput = 1;
    topics.topology_flow = 1;
    topics.wan_metrics = 1;
    topics.clients_metrics = 1;
    topics.apps_metrics = 1;

    /*
     * A cold dashboard is opened by several browser requests at once.  The
     * old path only consulted the cross-worker snapshot after realtime_snapshot
     * had already failed, so every worker could enter the same slow core read.
     * Treat the shared snapshot as a short read-through cache and make the
     * refresh single-flight across workers.
     */
    shared = webd_shared_json_read(WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH,
                                   WEBD_DASHBOARD_LIVE_SHARED_FRESH_MS,
                                   WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES,
                                   &shared_age_ms);
    if (shared)
        return shared;
    lock_fd = webd_shared_lock_open(WEBD_DASHBOARD_LIVE_SHARED_LOCK_PATH);
    if (lock_fd >= 0) {
        shared = webd_shared_json_read(WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH,
                                       WEBD_DASHBOARD_LIVE_SHARED_FRESH_MS,
                                       WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES,
                                       &shared_age_ms);
        if (shared) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
            return shared;
        }
    }
    snapshot = webd_ws_snapshot_data(&topics, NULL);
    data = webd_data_or_self_from_jmx_response(snapshot);
    if (!data) {
        shared = webd_shared_json_read(WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH,
                                       WEBD_DASHBOARD_LIVE_SHARED_STALE_MS,
                                       WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES,
                                       &shared_age_ms);
        if (shared) {
            webd_mark_cached_response_stale(shared, shared_age_ms,
                                            "realtime_snapshot_timeout_shared_cache");
            if (snapshot)
                json_object_put(snapshot);
            if (lock_fd >= 0) {
                flock(lock_fd, LOCK_UN);
                close(lock_fd);
            }
            return shared;
        }
        if (snapshot)
            json_object_put(snapshot);
        if (lock_fd >= 0) {
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
        }
        if (status)
            *status = 503;
        return webd_error("source_unavailable", "dashboard realtime snapshot source is not available",
                          "dreamingwrt realtime_snapshot", "webd.dashboard_live");
    }

    resp = webd_envelope(data, "jmxd.realtime_snapshot");
    meta = NULL;
    if (resp && json_object_object_get_ex(resp, "meta", &meta) && meta) {
        json_object_object_add(meta, "transport", json_object_new_string("http_snapshot"));
        json_object_object_add(meta, "ws_path", json_object_new_string("/api/v1/realtime/ws"));
        json_object_object_add(meta, "fallback_for", json_object_new_string("/api/v1/dashboard/live"));
    }
    if (resp)
        (lock_fd >= 0) ?
            webd_shared_json_write_locked(WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH,
                                          WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES,
                                          resp, lock_fd) :
            webd_shared_json_write(WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH,
                                   WEBD_DASHBOARD_LIVE_SHARED_LOCK_PATH,
                                   WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES, resp);
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    if (snapshot)
        json_object_put(snapshot);
    return resp;
}

struct json_object *webd_topology_node_detail_response(const struct http_req *req,
                                                       struct json_object *body,
                                                       int *http_status)
{
    char id[256] = "";
    char node_id[256] = "";
    char mac[64] = "";
    char type[64] = "";
    char wan_id[128] = "";
    struct json_object *params;
    struct json_object *upstream;
    struct json_object *data;
    struct json_object *resp;

    if (http_status)
        *http_status = 200;
    if (!webd_query_get(req->query, "id", id, sizeof(id)))
        snprintf(id, sizeof(id), "%s", app_nc_json_str(body, "id", ""));
    if (!webd_query_get(req->query, "node_id", node_id, sizeof(node_id)))
        snprintf(node_id, sizeof(node_id), "%s", app_nc_json_str(body, "node_id", ""));
    if (!webd_query_get(req->query, "mac", mac, sizeof(mac)))
        snprintf(mac, sizeof(mac), "%s", app_nc_json_str(body, "mac", ""));
    if (!webd_query_get(req->query, "type", type, sizeof(type)))
        snprintf(type, sizeof(type), "%s", app_nc_json_str(body, "type", ""));
    if (!webd_query_get(req->query, "wan_id", wan_id, sizeof(wan_id)))
        snprintf(wan_id, sizeof(wan_id), "%s", app_nc_json_str(body, "wan_id", ""));

    if (!id[0] && node_id[0])
        snprintf(id, sizeof(id), "%s", node_id);
    if (!id[0] && mac[0])
        snprintf(id, sizeof(id), "%s", mac);
    if (!id[0] && wan_id[0])
        snprintf(id, sizeof(id), "%s", wan_id);
    if (!id[0]) {
        if (http_status) *http_status = 400;
        return webd_error("missing_topology_node_id", "topology node id/mac/wan_id is required",
                          "id", "webd.topology_node_detail");
    }
    if (!webd_safe_token(id) ||
        (node_id[0] && !webd_safe_token(node_id)) ||
        (mac[0] && !webd_safe_token(mac)) ||
        (type[0] && !webd_safe_token(type)) ||
        (wan_id[0] && !webd_safe_token(wan_id))) {
        if (http_status) *http_status = 400;
        return webd_error("invalid_topology_node_id", "topology node query contains invalid characters",
                          "id", "webd.topology_node_detail");
    }

    params = json_object_new_object();
    json_object_object_add(params, "id", json_object_new_string(id));
    if (node_id[0])
        json_object_object_add(params, "node_id", json_object_new_string(node_id));
    if (mac[0])
        json_object_object_add(params, "mac", json_object_new_string(mac));
    if (type[0])
        json_object_object_add(params, "type", json_object_new_string(type));
    if (wan_id[0])
        json_object_object_add(params, "wan_id", json_object_new_string(wan_id));

    upstream = app_ubus_invoke_timeout("topology_node_detail", params, 2000);
    json_object_put(params);
    data = webd_data_or_self_from_jmx_response(upstream);
    if (!data) {
        if (upstream)
            json_object_put(upstream);
        if (http_status) *http_status = 503;
        return webd_error("source_unavailable", "topology node detail source is not available",
                          "dreamingwrt topology_node_detail", "webd.topology_node_detail");
    }
    resp = webd_envelope(data, "jmxd.topology_node_detail");
    if (upstream)
        json_object_put(upstream);
    return resp;
}
