// SPDX-License-Identifier: GPL-2.0-or-later
#include "logd_internal.h"

static void logd_event_id(char *out, size_t out_len, int64_t ts)
{
    struct timespec tv;

    if (!out || out_len == 0)
        return;
    clock_gettime(CLOCK_REALTIME, &tv);
    snprintf(out, out_len, "evt-%lld-%ld-%llu-%u",
             (long long)ts, tv.tv_nsec,
             (unsigned long long)++g_event_seq, (unsigned)getpid());
}

static int64_t logd_event_next_seq(void)
{
    sqlite3_stmt *st;
    int64_t seq = 0;
    int rc;

    st = logd_prepare("SELECT CAST(value AS INTEGER) FROM log_meta WHERE key='event_seq_next'");
    if (st) {
        if (sqlite3_step(st) == SQLITE_ROW)
            seq = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    if (seq <= 0) {
        st = logd_prepare("SELECT COALESCE(MAX(seq),0)+1 FROM log_events");
        if (st) {
            if (sqlite3_step(st) == SQLITE_ROW)
                seq = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
        }
    }
    if (seq <= 0)
        seq = 1;
    st = logd_prepare(
        "INSERT INTO log_meta(key,value) VALUES('event_seq_next',CAST(?1 AS TEXT)) "
        "ON CONFLICT(key) DO UPDATE SET value=CAST(?1 AS TEXT)");
    if (!st)
        return seq;
    sqlite3_bind_int64(st, 1, seq + 1);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? seq : seq;
}

static void logd_detail_json(struct json_object *body, char *out, size_t out_len)
{
    struct json_object *detail = NULL;

    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%s", "{}");
    if (!body)
        return;
    if (json_object_object_get_ex(body, "detail_json", &detail) && detail) {
        const char *s = json_object_to_json_string(detail);
        if (s && strlen(s) < out_len)
            snprintf(out, out_len, "%s", s);
        return;
    }
    if (json_object_object_get_ex(body, "detail", &detail) && detail) {
        struct json_object *o = json_object_new_object();
        const char *s;

        if (!o)
            return;
        json_object_object_add(o, "text", json_object_new_string(json_object_get_string(detail) ? json_object_get_string(detail) : ""));
        s = json_object_to_json_string(o);
        if (s && strlen(s) < out_len)
            snprintf(out, out_len, "%s", s);
        json_object_put(o);
    }
}

static const char *logd_detail_str(struct json_object *o, const char *key);

static int logd_json_array_has_string(struct json_object *arr, const char *value)
{
    int i;

    if (!arr || !json_object_is_type(arr, json_type_array) || !value || !value[0])
        return 0;
    for (i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *s = v ? json_object_get_string(v) : "";

        if (s && !strcmp(s, value))
            return 1;
    }
    return 0;
}

static void logd_json_array_add_unique(struct json_object *arr, const char *value)
{
    if (arr && value && value[0] && !logd_json_array_has_string(arr, value))
        json_object_array_add(arr, json_object_new_string(value));
}

static void logd_collectors_union(struct json_object *out, struct json_object *detail)
{
    struct json_object *arr = NULL;
    const char *collector;
    int i;

    if (!out || !detail || !json_object_is_type(detail, json_type_object))
        return;
    collector = logd_detail_str(detail, "collector");
    logd_json_array_add_unique(out, collector);
    if (!json_object_object_get_ex(detail, "collectors", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array))
        return;
    for (i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *s = v ? json_object_get_string(v) : "";

        logd_json_array_add_unique(out, s);
    }
}

static void logd_merge_dedupe_detail(const char *dedupe_key, const char *category,
                                     const char *event, char *detail_json,
                                     size_t detail_json_len)
{
    sqlite3_stmt *st;
    struct json_object *old_detail = NULL;
    struct json_object *new_detail = NULL;
    struct json_object *collectors = NULL;
    const char *old_s = NULL;
    const char *merged_s;

    if (!dedupe_key || !dedupe_key[0] || !detail_json || detail_json_len == 0)
        return;
    st = logd_prepare(
        "SELECT detail_json FROM log_events WHERE dedupe_key=?1 AND category=?2 AND event=?3 AND state!='cleared' "
        "ORDER BY last_seen DESC LIMIT 1");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, dedupe_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, category ? category : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, event ? event : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        old_s = (const char *)sqlite3_column_text(st, 0);
    if (old_s && old_s[0])
        old_detail = json_tokener_parse(old_s);
    sqlite3_finalize(st);
    if (!old_detail || !json_object_is_type(old_detail, json_type_object)) {
        if (old_detail)
            json_object_put(old_detail);
        return;
    }
    new_detail = json_tokener_parse(detail_json);
    if (!new_detail || !json_object_is_type(new_detail, json_type_object)) {
        if (new_detail)
            json_object_put(new_detail);
        json_object_put(old_detail);
        return;
    }
    collectors = json_object_new_array();
    logd_collectors_union(collectors, old_detail);
    logd_collectors_union(collectors, new_detail);
    json_object_object_foreach(new_detail, key, value) {
        if (strcmp(key, "collectors"))
            json_object_object_add(old_detail, key, json_object_get(value));
    }
    json_object_object_add(old_detail, "collectors", collectors);
    merged_s = json_object_to_json_string_ext(old_detail, JSON_C_TO_STRING_PLAIN);
    if (merged_s && strlen(merged_s) < detail_json_len)
        snprintf(detail_json, detail_json_len, "%s", merged_s);
    json_object_put(new_detail);
    json_object_put(old_detail);
}

static const char *logd_detail_str(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return "";
    if (!json_object_is_type(v, json_type_string))
        return "";
    return json_object_get_string(v) ? json_object_get_string(v) : "";
}

static void logd_copy_if_empty_from_detail(char *dst, size_t dst_len,
                                           struct json_object *detail,
                                           const char *k1, const char *k2,
                                           const char *k3, const char *k4)
{
    const char *s = "";

    if (!dst || dst_len == 0 || dst[0] || !detail)
        return;
    if (k1) s = logd_detail_str(detail, k1);
    if ((!s || !s[0]) && k2) s = logd_detail_str(detail, k2);
    if ((!s || !s[0]) && k3) s = logd_detail_str(detail, k3);
    if ((!s || !s[0]) && k4) s = logd_detail_str(detail, k4);
    if (s && s[0])
        snprintf(dst, dst_len, "%s", s);
}

static void logd_promote_field_if_missing(struct json_object *body,
                                          const char *key, const char *value)
{
    struct json_object *old = NULL;

    if (!body || !key || !value || !value[0])
        return;
    if (json_object_object_get_ex(body, key, &old) && old &&
        json_object_get_string(old) && json_object_get_string(old)[0])
        return;
    json_object_object_add(body, key, json_object_new_string(value));
}

static void logd_event_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    const char *detail_s = logd_sqlite_text(st, 13, "{}");
    struct json_object *detail = detail_s && detail_s[0] ? json_tokener_parse(detail_s) : NULL;

    json_object_object_add(o, "id", json_object_new_string(logd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
    json_object_object_add(o, "severity", json_object_new_string(logd_sqlite_text(st, 2, "info")));
    json_object_object_add(o, "category", json_object_new_string(logd_sqlite_text(st, 3, "system")));
    json_object_object_add(o, "event", json_object_new_string(logd_sqlite_text(st, 4, "event")));
    json_object_object_add(o, "source", json_object_new_string(logd_sqlite_text(st, 5, "")));
    json_object_object_add(o, "iface", json_object_new_string(logd_sqlite_text(st, 6, "")));
    json_object_object_add(o, "wan_id", json_object_new_string(logd_sqlite_text(st, 7, "")));
    json_object_object_add(o, "ip", json_object_new_string(logd_sqlite_text(st, 8, "")));
    json_object_object_add(o, "mac", json_object_new_string(logd_sqlite_text(st, 9, "")));
    json_object_object_add(o, "username", json_object_new_string(logd_sqlite_text(st, 10, "")));
    json_object_object_add(o, "actor", json_object_new_string(logd_sqlite_text(st, 11, "")));
    json_object_object_add(o, "title", json_object_new_string(logd_sqlite_text(st, 12, "")));
    if (detail)
        json_object_object_add(o, "detail_json", detail);
    else
        json_object_object_add(o, "detail_json", json_object_new_string(detail_s ? detail_s : "{}"));
    json_object_object_add(o, "dedupe_key", json_object_new_string(logd_sqlite_text(st, 14, "")));
    json_object_object_add(o, "state", json_object_new_string(logd_sqlite_text(st, 15, "active")));
    json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 16)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 17)));
    json_object_object_add(o, "count", json_object_new_int(sqlite3_column_int(st, 18)));
    json_object_array_add(arr, o);
}

static void logd_lookup_dedupe_id(const char *dedupe_key, const char *category,
                                  const char *event, char *out, size_t out_len)
{
    sqlite3_stmt *st;
    const char *id;

    if (!out || out_len == 0 || !dedupe_key || !dedupe_key[0])
        return;
    st = logd_prepare(
        "SELECT id FROM log_events WHERE dedupe_key=?1 AND category=?2 AND event=?3 AND state!='cleared' "
        "ORDER BY last_seen DESC LIMIT 1");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, dedupe_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, category ? category : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, event ? event : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        id = (const char *)sqlite3_column_text(st, 0);
        if (id && id[0])
            snprintf(out, out_len, "%s", id);
    }
    sqlite3_finalize(st);
}

struct logd_notifyd_reply {
    struct json_object *json;
    int seen;
};

static void logd_notifyd_enqueue_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct logd_notifyd_reply *reply = req ? req->priv : NULL;

    (void)type;
    if (!reply)
        return;
    if (reply->json)
        json_object_put(reply->json);
    reply->json = logd_json_from_blob(msg);
    reply->seen = 1;
}

static int logd_notifyd_enqueue(struct json_object *body)
{
    struct blob_buf b = {};
    struct logd_notifyd_reply reply = {};
    struct json_object *enqueued_o = NULL;
    const char *s;
    uint32_t id;
    int rc;
    int notified = 0;

    if (!g_logd_ubus || !body)
        return 0;
    if (ubus_lookup_id(g_logd_ubus, "dreamingwrt.notifyd", &id) != UBUS_STATUS_OK)
        return 0;
    s = json_object_to_json_string(body);
    blob_buf_init(&b, 0);
    if (s && s[0])
        blobmsg_add_json_from_string(&b, s);
    rc = ubus_invoke(g_logd_ubus, id, "enqueue", b.head,
                     logd_notifyd_enqueue_cb, &reply, LOGD_NOTIFYD_TIMEOUT_MS);
    blob_buf_free(&b);
    if (rc == UBUS_STATUS_OK && reply.seen && reply.json && logd_json_bool(reply.json, "ok", 0)) {
        if (json_object_object_get_ex(reply.json, "enqueued", &enqueued_o) && enqueued_o)
            notified = json_object_get_int(enqueued_o) > 0;
        else
            notified = 1;
    }
    if (reply.json)
        json_object_put(reply.json);
    return notified;
}

static int logd_event_severity_rank(const char *severity)
{
    severity = logd_severity(severity);
    if (!strcmp(severity, "critical")) return 5;
    if (!strcmp(severity, "error")) return 4;
    if (!strcmp(severity, "warning")) return 3;
    if (!strcmp(severity, "notice")) return 2;
    if (!strcmp(severity, "info")) return 1;
    return 0;
}

static int logd_event_severity_escalated(const char *dedupe_key,
                                         const char *category,
                                         const char *event,
                                         const char *new_severity)
{
    sqlite3_stmt *st;
    const char *old_severity = "info";
    int escalated = 0;

    if (!dedupe_key || !dedupe_key[0])
        return 0;
    st = logd_prepare(
        "SELECT severity FROM log_events WHERE dedupe_key=?1 AND category=?2 "
        "AND event=?3 AND state!='cleared' ORDER BY last_seen DESC LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, dedupe_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, category ? category : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, event ? event : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        old_severity = logd_sqlite_text(st, 0, "info");
        escalated = logd_event_severity_rank(new_severity) >
                    logd_event_severity_rank(old_severity);
    }
    sqlite3_finalize(st);
    return escalated;
}

static int logd_event_should_notify(const char *severity, const char *title,
                                    const char *dedupe_key,
                                    const char *detail_json)
{
    int raw_log = dedupe_key && !strncmp(dedupe_key, "log:", 4);

    if (!raw_log)
        return 1;
    if (logd_event_severity_rank(severity) <
        logd_event_severity_rank("critical"))
        return 0;
    return logd_contains_ci(title, "out of memory") ||
           logd_contains_ci(title, "oom-killer") ||
           logd_contains_ci(title, "kernel panic") ||
           logd_contains_ci(title, "thermal shutdown") ||
           logd_contains_ci(detail_json, "out of memory") ||
           logd_contains_ci(detail_json, "oom-killer") ||
           logd_contains_ci(detail_json, "kernel panic") ||
           logd_contains_ci(detail_json, "thermal shutdown");
}


struct logd_notify_event_contract {
    const char *source_category;
    const char *source_event;
    const char *event_code;
    const char *notify_category;
    const char *producer;
    const char *default_severity;
    const char *recovery_event;
    const char *recovers_event;
};

static const struct logd_notify_event_contract logd_notify_event_contracts[] = {
    { "resource", "threshold_exceeded", "SYSTEM_RESOURCE_THRESHOLD", "SYSTEM",
      "dreamingwrt.logd.collector.resource", "warning", "", "" },
    { "port", "link_down", "PORT_LINK_DOWN", "INTERNET_AND_WAN",
      "dreamingwrt.logd.collector.port", "warning", "PORT_LINK_UP", "" },
    { "port", "link_up", "PORT_LINK_UP", "INTERNET_AND_WAN",
      "dreamingwrt.logd.collector.port", "notice", "PORT_LINK_DOWN", "PORT_LINK_DOWN" },
    { "dhcp", "lease_assigned", "CLIENT_CONNECTED_WIRED", "CLIENT_DEVICES",
      "dreamingwrt.logd.collector.dhcp_lease", "notice", "CLIENT_DISCONNECTED", "" },
    { "dhcp", "lease_released", "CLIENT_DISCONNECTED", "CLIENT_DEVICES",
      "dreamingwrt.logd.collector.dhcp_lease", "notice", "CLIENT_CONNECTED_WIRED", "CLIENT_CONNECTED_WIRED" },
    { "dhcp", "dhcp_log", "DHCP_EVENT", "CLIENT_DEVICES",
      "dreamingwrt.logd.collector.dhcp_lease", "notice", "", "" },
    { "wan", "wan_log", "WAN_EVENT", "INTERNET_AND_WAN",
      "dreamingwrt.logd.collector.system_log", "notice", "", "" },
    { "pppoe", "pppoe_log", "PPPOE_EVENT", "INTERNET_AND_WAN",
      "dreamingwrt.logd.collector.system_log", "notice", "", "" },
    { "audit", "auth_log", "ADMIN_AUTH_EVENT", "ADMIN",
      "dreamingwrt.logd.collector.system_log", "warning", "", "" },
    { "network.wan", "wan.failover.down", "WAN_FAILOVER_ACTIVE", "INTERNET_AND_WAN",
      "dreamingwrt.routed.health", "warning", "WAN_FAILBACK", "" },
    { "network.wan", "wan.failover.recovered", "WAN_FAILBACK", "INTERNET_AND_WAN",
      "dreamingwrt.routed.health", "notice", "WAN_FAILOVER_ACTIVE", "WAN_FAILOVER_ACTIVE" },
};

static const struct logd_notify_event_contract *
logd_notify_contract_find(const char *category, const char *event,
                          const char *event_code)
{
    size_t i;

    if (!category)
        category = "";
    if (!event)
        event = "";
    if (!event_code)
        event_code = "";
    for (i = 0; i < sizeof(logd_notify_event_contracts) / sizeof(logd_notify_event_contracts[0]); i++) {
        const struct logd_notify_event_contract *c = &logd_notify_event_contracts[i];

        if (event_code[0] && !strcmp(event_code, c->event_code))
            return c;
        if (!strcmp(category, c->source_category) && !strcmp(event, c->source_event))
            return c;
        if (!strcmp(category, c->notify_category) && !strcmp(event, c->event_code))
            return c;
    }
    return NULL;
}

static void logd_json_replace_string(struct json_object *o, const char *key,
                                     const char *value)
{
    struct json_object *replacement;

    if (!o || !key)
        return;
    replacement = json_object_new_string(value ? value : "");
    if (!replacement)
        return;
    json_object_object_del(o, key);
    json_object_object_add(o, key, replacement);
}

static void logd_notify_dedupe_from_contract(const struct logd_notify_event_contract *c,
                                             struct json_object *detail,
                                             const char *iface,
                                             const char *wan_id,
                                             const char *ip,
                                             const char *mac,
                                             char *out, size_t out_len)
{
    const char *value = "";

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (!c)
        return;
    if (!strcmp(c->event_code, "WAN_FAILOVER_ACTIVE") ||
        !strcmp(c->event_code, "WAN_FAILBACK")) {
        value = wan_id && wan_id[0] ? wan_id : "";
        if (!value[0]) value = logd_detail_str(detail, "wan_id");
        if (!value[0]) value = logd_detail_str(detail, "wan");
        if (!value[0]) value = logd_detail_str(detail, "wan_name");
        if (!value[0]) value = iface && iface[0] ? iface : "";
        if (!value[0]) value = logd_detail_str(detail, "iface");
        if (!value[0]) value = logd_detail_str(detail, "ifname");
        if (!value[0]) value = logd_detail_str(detail, "target");
        snprintf(out, out_len, "wan_failover:%s", value[0] ? value : "unknown");
    } else if (!strcmp(c->event_code, "PORT_LINK_DOWN") ||
               !strcmp(c->event_code, "PORT_LINK_UP")) {
        value = iface && iface[0] ? iface : "";
        if (!value[0]) value = logd_detail_str(detail, "iface");
        if (!value[0]) value = logd_detail_str(detail, "interface");
        if (!value[0]) value = logd_detail_str(detail, "ifname");
        snprintf(out, out_len, "port:%s:carrier", value[0] ? value : "unknown");
    } else if (!strcmp(c->event_code, "CLIENT_CONNECTED_WIRED") ||
               !strcmp(c->event_code, "CLIENT_DISCONNECTED")) {
        value = mac && mac[0] ? mac : "";
        if (!value[0]) value = logd_detail_str(detail, "mac");
        if (!value[0]) value = logd_detail_str(detail, "client_mac");
        if (!value[0]) value = ip && ip[0] ? ip : "";
        snprintf(out, out_len, "client:%s:presence", value[0] ? value : "unknown");
    }
}

static void logd_notify_add_metadata(struct json_object *detail,
                                     const struct logd_notify_event_contract *c,
                                     const char *raw_category,
                                     const char *raw_event,
                                     const char *source,
                                     const char *iface,
                                     const char *wan_id,
                                     const char *ip,
                                     const char *mac)
{
    struct json_object *meta = NULL;

    if (!detail || !c)
        return;
    logd_json_replace_string(detail, "event_code", c->event_code);
    logd_json_replace_string(detail, "producer", c->producer);
    logd_json_replace_string(detail, "source_category", raw_category ? raw_category : "");
    logd_json_replace_string(detail, "source_event", raw_event ? raw_event : "");
    if (c->recovery_event && c->recovery_event[0])
        logd_json_replace_string(detail, "recovery_event", c->recovery_event);
    if (c->recovers_event && c->recovers_event[0])
        logd_json_replace_string(detail, "recovers_event", c->recovers_event);

    if (!json_object_object_get_ex(detail, "source_metadata", &meta) || !meta ||
        !json_object_is_type(meta, json_type_object)) {
        meta = json_object_new_object();
        if (!meta)
            return;
        json_object_object_add(detail, "source_metadata", meta);
    }
    json_object_object_add(meta, "source", json_object_new_string(source ? source : ""));
    json_object_object_add(meta, "iface", json_object_new_string(iface ? iface : ""));
    json_object_object_add(meta, "wan_id", json_object_new_string(wan_id ? wan_id : ""));
    json_object_object_add(meta, "ip", json_object_new_string(ip ? ip : ""));
    json_object_object_add(meta, "mac", json_object_new_string(mac ? mac : ""));
}

static struct json_object *logd_notify_body_for_enqueue(struct json_object *body,
                                                        const struct logd_notify_event_contract *c,
                                                        const char *raw_category,
                                                        const char *raw_event,
                                                        const char *source,
                                                        const char *iface,
                                                        const char *wan_id,
                                                        const char *ip,
                                                        const char *mac,
                                                        const char *dedupe_key,
                                                        const char *severity)
{
    struct json_object *out;
    struct json_object *detail = NULL;
    struct json_object *parsed = NULL;
    const char *s;

    if (!body)
        return NULL;
    if (!c)
        return json_object_get(body);
    s = json_object_to_json_string(body);
    out = s ? json_tokener_parse(s) : NULL;
    if (!out || !json_object_is_type(out, json_type_object)) {
        if (out)
            json_object_put(out);
        out = json_object_new_object();
    }
    logd_json_replace_string(out, "category", c->notify_category);
    logd_json_replace_string(out, "event", c->event_code);
    logd_json_replace_string(out, "event_code", c->event_code);
    logd_json_replace_string(out, "producer", c->producer);
    logd_json_replace_string(out, "severity", severity ? severity : c->default_severity);
    logd_json_replace_string(out, "dedupe_key", dedupe_key ? dedupe_key : "");
    logd_json_replace_string(out, "source_category", raw_category ? raw_category : "");
    logd_json_replace_string(out, "source_event", raw_event ? raw_event : "");
    if (c->recovery_event && c->recovery_event[0])
        logd_json_replace_string(out, "recovery_event", c->recovery_event);
    if (c->recovers_event && c->recovers_event[0])
        logd_json_replace_string(out, "recovers_event", c->recovers_event);

    if (json_object_object_get_ex(out, "detail_json", &detail) && detail &&
        json_object_is_type(detail, json_type_object)) {
        logd_notify_add_metadata(detail, c, raw_category, raw_event, source, iface, wan_id, ip, mac);
        return out;
    }
    if (detail && json_object_is_type(detail, json_type_string))
        parsed = json_tokener_parse(json_object_get_string(detail));
    if (!parsed || !json_object_is_type(parsed, json_type_object)) {
        if (parsed)
            json_object_put(parsed);
        parsed = json_object_new_object();
    }
    logd_notify_add_metadata(parsed, c, raw_category, raw_event, source, iface, wan_id, ip, mac);
    json_object_object_del(out, "detail_json");
    json_object_object_add(out, "detail_json", parsed);
    return out;
}

static int logd_clear_recovered_events(const char *dedupe_key, const char *current_id,
                                       const struct logd_notify_event_contract *c)
{
    sqlite3_stmt *st;
    int rc;
    int changed;

    if (!c || !c->recovers_event || !c->recovers_event[0] ||
        !dedupe_key || !dedupe_key[0])
        return 0;
    st = logd_prepare(
        "UPDATE log_events SET state='cleared',last_seen=?1 "
        "WHERE dedupe_key=?2 AND state!='cleared' AND id!=?3 AND event=?4");
    if (!st)
        return 0;
    sqlite3_bind_int64(st, 1, logd_now_s());
    sqlite3_bind_text(st, 2, dedupe_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, current_id ? current_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, c->recovers_event, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    changed = rc == SQLITE_DONE ? sqlite3_changes(g_logd_db) : 0;
    sqlite3_finalize(st);
    return changed;
}

struct json_object *logd_add_event(struct json_object *body)
{
    const char *severity = logd_severity(logd_json_str(body, "severity", logd_json_str(body, "level", "info")));
    const char *category = logd_json_str(body, "category", "system");
    const char *event = logd_json_str(body, "event", "");
    const char *raw_category = category;
    const char *raw_event = event;
    const char *event_code = logd_json_str(body, "event_code", "");
    const struct logd_notify_event_contract *notify_contract = NULL;
    const char *source = logd_json_str(body, "source", "");
    const char *iface = logd_json_str(body, "iface", "");
    const char *wan_id = logd_json_str(body, "wan_id", "");
    const char *ip = logd_json_str(body, "ip", "");
    const char *mac = logd_json_str(body, "mac", "");
    const char *username = logd_json_str(body, "username", "");
    const char *actor = logd_json_str(body, "actor", "");
    const char *title = logd_json_str(body, "title", "");
    const char *dedupe_key = logd_json_str(body, "dedupe_key", "");
    const char *state = logd_json_str(body, "state", "active");
    int64_t ts = logd_json_i64(body, "ts", logd_now_s());
    char iface_eff[64];
    char wan_id_eff[64];
    char ip_eff[96];
    char mac_eff[64];
    char username_eff[128];
    char actor_eff[128];
    char raw_category_eff[64];
    char raw_event_eff[128];
    char id[96];
    char detail_json[LOGD_MAX_DETAIL_JSON];
    struct json_object *detail_obj = NULL;
    sqlite3_stmt *st;
    int deduped = 0;
    int severity_escalated = 0;
    int notified = 0;
    int recovered_count = 0;
    int64_t seq = 0;
    char notify_dedupe_key[256] = "";
    int rc;
    struct json_object *resp = json_object_new_object();
    enum jmx_storage_write_priority write_priority;

    write_priority = (!strcmp(severity, "critical") || !strcmp(severity, "error")) ?
                     JMX_STORAGE_WRITE_EMERGENCY :
                     (!strcmp(severity, "warning") ? JMX_STORAGE_WRITE_IMPORTANT :
                      JMX_STORAGE_WRITE_BULK);
    if (!jmx_storage_guard_allow("/", write_priority, NULL)) {
        g_logd_storage_suppressed++;
        g_logd_storage_last_suppressed_at = logd_now_s();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("storage_pressure_write_suppressed"));
        json_object_object_add(resp, "persisted", json_object_new_boolean(0));
        json_object_object_add(resp, "storage_pressure", json_object_new_string(
            write_priority == JMX_STORAGE_WRITE_BULK ? "warning_or_critical" : "critical"));
        return resp;
    }

    snprintf(iface_eff, sizeof(iface_eff), "%s", iface ? iface : "");
    snprintf(wan_id_eff, sizeof(wan_id_eff), "%s", wan_id ? wan_id : "");
    snprintf(ip_eff, sizeof(ip_eff), "%s", ip ? ip : "");
    snprintf(mac_eff, sizeof(mac_eff), "%s", mac ? mac : "");
    snprintf(username_eff, sizeof(username_eff), "%s", username ? username : "");
    snprintf(actor_eff, sizeof(actor_eff), "%s", actor ? actor : "");
    snprintf(raw_category_eff, sizeof(raw_category_eff), "%s", raw_category ? raw_category : "");
    snprintf(raw_event_eff, sizeof(raw_event_eff), "%s", raw_event ? raw_event : "");
    raw_category = raw_category_eff;
    raw_event = raw_event_eff;
    logd_detail_json(body, detail_json, sizeof(detail_json));
    detail_obj = detail_json[0] ? json_tokener_parse(detail_json) : NULL;
    if (detail_obj && json_object_is_type(detail_obj, json_type_object)) {
        logd_copy_if_empty_from_detail(iface_eff, sizeof(iface_eff), detail_obj,
                                       "iface", "interface", "ifname", "device");
        logd_copy_if_empty_from_detail(wan_id_eff, sizeof(wan_id_eff), detail_obj,
                                       "wan_id", "wan", "wan_name", NULL);
        logd_copy_if_empty_from_detail(ip_eff, sizeof(ip_eff), detail_obj,
                                       "ip", "client_ip", "src_ip", "source_ip");
        logd_copy_if_empty_from_detail(mac_eff, sizeof(mac_eff), detail_obj,
                                       "mac", "client_mac", "src_mac", "source_mac");
        logd_copy_if_empty_from_detail(username_eff, sizeof(username_eff), detail_obj,
                                       "username", "user", "admin", "admin_id");
        logd_copy_if_empty_from_detail(actor_eff, sizeof(actor_eff), detail_obj,
                                       "actor", NULL, NULL, NULL);
    }
    notify_contract = logd_notify_contract_find(raw_category, raw_event, event_code);
    if (notify_contract) {
        category = notify_contract->notify_category;
        event = notify_contract->event_code;
        if (logd_event_severity_rank(severity) <
            logd_event_severity_rank(notify_contract->default_severity))
            severity = notify_contract->default_severity;
        logd_notify_dedupe_from_contract(notify_contract, detail_obj, iface_eff,
                                        wan_id_eff, ip_eff, mac_eff,
                                        notify_dedupe_key, sizeof(notify_dedupe_key));
        if (notify_dedupe_key[0])
            dedupe_key = notify_dedupe_key;
        if (detail_obj && json_object_is_type(detail_obj, json_type_object)) {
            const char *detail_s;

            logd_notify_add_metadata(detail_obj, notify_contract, raw_category,
                                     raw_event, source, iface_eff, wan_id_eff,
                                     ip_eff, mac_eff);
            detail_s = json_object_to_json_string_ext(detail_obj,
                                                      JSON_C_TO_STRING_PLAIN);
            if (detail_s && strlen(detail_s) < sizeof(detail_json))
                snprintf(detail_json, sizeof(detail_json), "%s", detail_s);
        }
    }
    if (detail_obj)
        json_object_put(detail_obj);

    if (!logd_token_ok(category, 64) || !logd_token_ok(event, 128) ||
        !logd_text_ok(source, 128) || !logd_text_ok(iface_eff, sizeof(iface_eff)) ||
        !logd_text_ok(wan_id_eff, sizeof(wan_id_eff)) || !logd_text_ok(ip_eff, sizeof(ip_eff)) ||
        !logd_text_ok(mac_eff, sizeof(mac_eff)) || !logd_text_ok(username_eff, sizeof(username_eff)) ||
        !logd_text_ok(actor_eff, sizeof(actor_eff)) || !logd_text_ok(title, LOGD_MAX_TEXT) ||
        !logd_text_ok(dedupe_key, 256) || !logd_token_ok(state, 32)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_event_fields"));
        return resp;
    }
    if (ts <= 0)
        ts = logd_now_s();
    logd_event_id(id, sizeof(id), ts);
    logd_promote_field_if_missing(body, "iface", iface_eff);
    logd_promote_field_if_missing(body, "wan_id", wan_id_eff);
    logd_promote_field_if_missing(body, "ip", ip_eff);
    logd_promote_field_if_missing(body, "mac", mac_eff);
    logd_promote_field_if_missing(body, "username", username_eff);
    logd_promote_field_if_missing(body, "actor", actor_eff);

    if (dedupe_key[0]) {
        int count_increment = strncmp(dedupe_key, "log:", 4) ? 1 : 0;

        severity_escalated = logd_event_severity_escalated(
            dedupe_key, category, event, severity);
        logd_merge_dedupe_detail(dedupe_key, category, event,
                                 detail_json, sizeof(detail_json));
        st = logd_prepare(
            "UPDATE log_events SET ts=?1,severity=(CASE "
            "WHEN severity='critical' OR ?2='critical' THEN 'critical' "
            "WHEN severity='error' OR ?2='error' THEN 'error' "
            "WHEN severity='warning' OR ?2='warning' THEN 'warning' "
            "WHEN severity='notice' OR ?2='notice' THEN 'notice' ELSE 'info' END),"
            "title=?3,detail_json=?4,last_seen=?1,count=count+?15,state='active',"
            "source=COALESCE(NULLIF(source,''),?5),iface=COALESCE(NULLIF(iface,''),?6),wan_id=COALESCE(NULLIF(wan_id,''),?7),"
            "ip=COALESCE(NULLIF(ip,''),?8),mac=COALESCE(NULLIF(mac,''),?9),username=COALESCE(NULLIF(username,''),?10),actor=COALESCE(NULLIF(actor,''),?11) "
            "WHERE dedupe_key=?12 AND category=?13 AND event=?14 AND state!='cleared'");
        if (!st) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("dedupe_update_prepare_failed"));
            return resp;
        }
        sqlite3_bind_int64(st, 1, ts);
        sqlite3_bind_text(st, 2, severity, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, title, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, detail_json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, iface_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, wan_id_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, ip_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, mac_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, username_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, actor_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, dedupe_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, category, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, event, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 15, count_increment);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("dedupe_update_failed"));
            return resp;
        }
        deduped = sqlite3_changes(g_logd_db) > 0;
        if (deduped)
            logd_lookup_dedupe_id(dedupe_key, category, event, id, sizeof(id));
    }

    if (!deduped) {
        seq = logd_event_next_seq();
        st = logd_prepare(
            "INSERT INTO log_events(id,seq,ts,severity,category,event,source,iface,wan_id,ip,mac,username,actor,title,detail_json,dedupe_key,state,first_seen,last_seen,count,created_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?3,?3,1,?3)");
        if (!st) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("insert_prepare_failed"));
            return resp;
        }
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, seq);
        sqlite3_bind_int64(st, 3, ts);
        sqlite3_bind_text(st, 4, severity, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, category, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, event, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, iface_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, wan_id_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, ip_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, mac_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, username_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, actor_eff, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, title, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, detail_json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 16, dedupe_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 17, state, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("insert_failed"));
            return resp;
        }
        sqlite3_finalize(st);
    }
    logd_prune_if_needed();
    recovered_count = logd_clear_recovered_events(dedupe_key, id, notify_contract);
    json_object_object_add(body, "id", json_object_new_string(id));
    json_object_object_add(body, "ts", json_object_new_int64(ts));
    json_object_object_add(body, "deduplicated", json_object_new_boolean(deduped));
    if (notify_contract) {
        logd_json_replace_string(body, "category", notify_contract->notify_category);
        logd_json_replace_string(body, "event", notify_contract->event_code);
        logd_json_replace_string(body, "event_code", notify_contract->event_code);
        logd_json_replace_string(body, "producer", notify_contract->producer);
        logd_json_replace_string(body, "severity", severity);
        logd_json_replace_string(body, "dedupe_key", dedupe_key);
        logd_json_replace_string(body, "source_category", raw_category);
        logd_json_replace_string(body, "source_event", raw_event);
        if (notify_contract->recovery_event && notify_contract->recovery_event[0])
            logd_json_replace_string(body, "recovery_event", notify_contract->recovery_event);
        if (notify_contract->recovers_event && notify_contract->recovers_event[0])
            logd_json_replace_string(body, "recovers_event", notify_contract->recovers_event);
    }
    if ((!deduped || severity_escalated || recovered_count > 0) &&
        logd_event_should_notify(severity, title, dedupe_key, detail_json)) {
        struct json_object *notify_body = logd_notify_body_for_enqueue(
            body, notify_contract, raw_category, raw_event, source, iface_eff,
            wan_id_eff, ip_eff, mac_eff, dedupe_key, severity);

        notified = logd_notifyd_enqueue(notify_body ? notify_body : body);
        if (notify_body)
            json_object_put(notify_body);
    }
    if (!deduped || severity_escalated || recovered_count > 0)
        logd_syslog_enqueue_event(body);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (seq > 0)
        json_object_object_add(resp, "seq", json_object_new_int64(seq));
    json_object_object_add(resp, "deduplicated", json_object_new_boolean(deduped));
    json_object_object_add(resp, "severity_escalated", json_object_new_boolean(severity_escalated));
    json_object_object_add(resp, "recovered_count", json_object_new_int(recovered_count));
    if (notify_contract) {
        json_object_object_add(resp, "event_code", json_object_new_string(notify_contract->event_code));
        json_object_object_add(resp, "producer", json_object_new_string(notify_contract->producer));
    }
    json_object_object_add(resp, "notified", json_object_new_boolean(notified));
    json_object_object_add(resp, "ts", json_object_new_int64(ts));
    return resp;
}

int logd_publish_event(const char *severity, const char *category, const char *event,
                       const char *source, const char *iface, const char *title,
                       const char *dedupe_key, struct json_object *detail)
{
    struct json_object *body = json_object_new_object();
    struct json_object *resp;
    int ok = 0;

    if (!body)
        return -1;
    json_object_object_add(body, "severity", json_object_new_string(severity ? severity : "info"));
    json_object_object_add(body, "category", json_object_new_string(category ? category : "system"));
    json_object_object_add(body, "event", json_object_new_string(event ? event : "event"));
    json_object_object_add(body, "source", json_object_new_string(source ? source : "dreamingwrt-logd"));
    json_object_object_add(body, "iface", json_object_new_string(iface ? iface : ""));
    json_object_object_add(body, "title", json_object_new_string(title ? title : ""));
    json_object_object_add(body, "dedupe_key", json_object_new_string(dedupe_key ? dedupe_key : ""));
    if (detail)
        json_object_object_add(body, "detail_json", json_object_get(detail));
    resp = logd_add_event(body);
    if (resp)
        ok = logd_json_bool(resp, "ok", 0);
    if (resp)
        json_object_put(resp);
    json_object_put(body);
    return ok ? 0 : -1;
}

struct json_object *logd_list_events(struct json_object *body)
{
    const char *category = logd_json_str(body, "category", "");
    const char *severity = logd_json_str(body, "severity", logd_json_str(body, "level", ""));
    const char *event = logd_json_str(body, "event", "");
    const char *source = logd_json_str(body, "source", "");
    const char *iface = logd_json_str(body, "iface", "");
    int64_t since = logd_json_i64(body, "since", 0);
    int64_t until = logd_json_i64(body, "until", 0);
    int limit = logd_json_int(body, "limit", LOGD_DEFAULT_LIMIT);
    int offset = logd_json_int(body, "offset", 0);
    char sql[1024];
    sqlite3_stmt *st;
    int b = 1;
    int rc;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();

    if (limit <= 0 || limit > LOGD_MAX_LIMIT) limit = LOGD_DEFAULT_LIMIT;
    if (offset < 0) offset = 0;
    snprintf(sql, sizeof(sql),
        "SELECT id,ts,severity,category,event,source,iface,wan_id,ip,mac,username,actor,title,detail_json,dedupe_key,state,first_seen,last_seen,count "
        "FROM log_events WHERE 1=1 %s %s %s %s %s %s %s ORDER BY ts DESC LIMIT ? OFFSET ?",
        category[0] ? "AND category=?" : "",
        severity[0] ? "AND severity=?" : "",
        event[0] ? "AND event=?" : "",
        source[0] ? "AND source=?" : "",
        iface[0] ? "AND iface=?" : "",
        since > 0 ? "AND ts>=?" : "",
        until > 0 ? "AND ts<=?" : "");
    st = logd_prepare(sql);
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("query_prepare_failed"));
        json_object_put(arr);
        return resp;
    }
    if (category[0]) sqlite3_bind_text(st, b++, category, -1, SQLITE_TRANSIENT);
    if (severity[0]) sqlite3_bind_text(st, b++, severity, -1, SQLITE_TRANSIENT);
    if (event[0]) sqlite3_bind_text(st, b++, event, -1, SQLITE_TRANSIENT);
    if (source[0]) sqlite3_bind_text(st, b++, source, -1, SQLITE_TRANSIENT);
    if (iface[0]) sqlite3_bind_text(st, b++, iface, -1, SQLITE_TRANSIENT);
    if (since > 0) sqlite3_bind_int64(st, b++, since);
    if (until > 0) sqlite3_bind_int64(st, b++, until);
    sqlite3_bind_int(st, b++, limit);
    sqlite3_bind_int(st, b++, offset);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW)
        logd_event_row_json(arr, st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("query_failed"));
        json_object_object_add(resp, "events", arr);
        json_object_object_add(resp, "limit", json_object_new_int(limit));
        json_object_object_add(resp, "offset", json_object_new_int(offset));
        return resp;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "events", arr);
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    json_object_object_add(resp, "offset", json_object_new_int(offset));
    return resp;
}

struct logd_unifi_query {
    const char *search;
    const char *cursor_id;
    const char *actor;
    int64_t ts_from;
    int64_t ts_to;
    int64_t cursor_ts;
    int64_t cursor_rowid;
    int64_t cursor_seq;
    int page;
    int page_size;
    int incremental;
};

static int logd_unifi_ts_s(int64_t ts)
{
    if (ts > 100000000000LL)
        ts /= 1000;
    if (ts < 0)
        ts = 0;
    return (int)ts;
}

static int64_t logd_json_i64_any(struct json_object *o, const char **keys, int64_t def)
{
    int i;

    if (!keys)
        return def;
    for (i = 0; keys[i]; i++) {
        struct json_object *v = NULL;

        if (o && json_object_object_get_ex(o, keys[i], &v) && v)
            return json_object_get_int64(v);
    }
    return def;
}

static const char *logd_json_str_any(struct json_object *o, const char **keys, const char *def)
{
    int i;

    if (!keys)
        return def;
    for (i = 0; keys[i]; i++) {
        struct json_object *v = NULL;
        const char *s;

        if (!o || !json_object_object_get_ex(o, keys[i], &v) || !v ||
            !json_object_is_type(v, json_type_string))
            continue;
        s = json_object_get_string(v);
        if (s && s[0])
            return s;
    }
    return def;
}

static void logd_csv_escape(FILE *fp, const char *s)
{
    int quote = 0;
    const char *p;

    if (!fp)
        return;
    if (!s)
        s = "";
    for (p = s; *p; p++) {
        if (*p == '"' || *p == ',' || *p == '\n' || *p == '\r') {
            quote = 1;
            break;
        }
    }
    if (!quote) {
        fputs(s, fp);
        return;
    }
    fputc('"', fp);
    for (p = s; *p; p++) {
        if (*p == '"')
            fputc('"', fp);
        fputc(*p, fp);
    }
    fputc('"', fp);
}

static const char *logd_unifi_category(const char *category, const char *event)
{
    if (!category)
        category = "";
    if (!event)
        event = "";
    if (!strcmp(category, "SYSTEM") || !strcmp(category, "INTERNET_AND_WAN") ||
        !strcmp(category, "CLIENT_DEVICES") || !strcmp(category, "DEVICES") ||
        !strcmp(category, "ADMIN") || !strcmp(category, "SECURITY") ||
        !strcmp(category, "VPN"))
        return category;
    if (!strcmp(category, "dhcp") || !strcmp(category, "client") ||
        !strncmp(event, "lease_", 6))
        return "CLIENT_DEVICES";
    if (!strcmp(category, "wan") || !strcmp(category, "pppoe") ||
        !strcmp(category, "port") || !strcmp(event, "link_up") ||
        !strcmp(event, "link_down"))
        return "INTERNET_AND_WAN";
    if (!strcmp(category, "audit") || !strcmp(category, "auth"))
        return "ADMIN";
    if (!strcmp(category, "security"))
        return "SECURITY";
    if (!strcmp(category, "vpn"))
        return "VPN";
    return "SYSTEM";
}

static const char *logd_unifi_subcategory(const char *category, const char *event)
{
    if (!category)
        category = "";
    if (!event)
        event = "";
    if (!strcmp(category, "dhcp") || !strcmp(category, "CLIENT_DEVICES"))
        return "CLIENT";
    if (!strcmp(category, "port"))
        return "WIRED";
    if (!strcmp(category, "wan") || !strcmp(category, "pppoe") ||
        !strcmp(category, "INTERNET_AND_WAN"))
        return "WAN";
    if (!strcmp(category, "audit") || !strcmp(category, "ADMIN"))
        return "AUTH";
    if (!strcmp(category, "kernel"))
        return "KERNEL";
    if (!strcmp(category, "resource"))
        return "RESOURCE";
    return "GENERAL";
}

static const char *logd_unifi_event_key(const char *category, const char *event)
{
    if (!event || !event[0])
        return "SYSTEM_LOG";
    if (!strcmp(event, "lease_assigned"))
        return "CLIENT_CONNECTED_WIRED";
    if (!strcmp(event, "lease_released"))
        return "CLIENT_DISCONNECTED";
    if (!strcmp(event, "link_up"))
        return "PORT_LINK_UP";
    if (!strcmp(event, "link_down"))
        return "PORT_LINK_DOWN";
    if (!strcmp(event, "port_log"))
        return "PORT_EVENT";
    if (!strcmp(event, "wan_log") || (category && !strcmp(category, "wan")))
        return "WAN_EVENT";
    if (!strcmp(event, "pppoe_log") || (category && !strcmp(category, "pppoe")))
        return "PPPOE_EVENT";
    if (!strcmp(event, "auth_log"))
        return "ADMIN_AUTH_EVENT";
    if (!strcmp(event, "packet_capture_started"))
        return "PACKET_CAPTURE_STARTED";
    if (!strcmp(event, "packet_capture_stopped"))
        return "PACKET_CAPTURE_STOPPED";
    if (!strcmp(event, "packet_capture_finished"))
        return "PACKET_CAPTURE_FINISHED";
    if (!strcmp(event, "packet_capture_deleted"))
        return "PACKET_CAPTURE_DELETED";
    if (!strcmp(event, "threshold_exceeded"))
        return "SYSTEM_RESOURCE_THRESHOLD";
    if (!strcmp(event, "dhcp_log"))
        return "DHCP_EVENT";
    if (!strcmp(event, "callbacks_suppressed"))
        return "CALLBACKS_SUPPRESSED";
    if (!strcmp(event, "log_line"))
        return "SYSTEM_LOG";
    return event;
}

static const char *logd_unifi_severity(const char *severity)
{
    if (!severity)
        return "LOW";
    if (!strcmp(severity, "critical"))
        return "VERY_HIGH";
    if (!strcmp(severity, "error"))
        return "HIGH";
    if (!strcmp(severity, "warning"))
        return "MEDIUM";
    return "LOW";
}

static int logd_unifi_cef_severity(const char *severity)
{
    if (!severity)
        return 1;
    if (!strcmp(severity, "critical"))
        return 10;
    if (!strcmp(severity, "error"))
        return 7;
    if (!strcmp(severity, "warning"))
        return 5;
    if (!strcmp(severity, "notice"))
        return 3;
    return 1;
}

static const char *logd_json_obj_str(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return "";
    if (!json_object_is_type(v, json_type_string))
        return "";
    return json_object_get_string(v) ? json_object_get_string(v) : "";
}

static int64_t logd_json_obj_i64(struct json_object *o, const char *key, int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

static void logd_program_id_normalize(const char *raw, char *out, size_t out_len)
{
    const char *p = raw ? raw : "";
    const char *base;
    size_t n = 0;

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    base = strrchr(p, '/');
    if (base)
        p = base + 1;
    while (*p && n + 1 < out_len) {
        unsigned char c = (unsigned char)*p++;

        if (c == '[' || c == '(' || c == ':' || isspace(c))
            break;
        if (isalnum(c) || c == '_' || c == '-' || c == '.')
            out[n++] = (char)tolower(c);
    }
    out[n] = 0;
}

static const char *logd_canonical_source_id(const char *detail_source,
                                            const char *source,
                                            const char *category)
{
    if (detail_source && detail_source[0])
        return detail_source;
    if ((category && !strcmp(category, "kernel")) ||
        (source && (!strcmp(source, "kernel") || !strcmp(source, "kernel_log"))))
        return "kernel";
    if ((category && (!strcmp(category, "audit") || !strcmp(category, "auth"))) ||
        (source && !strcmp(source, "audit")))
        return "audit";
    if (source && (!strcmp(source, "notification") || !strcmp(source, "notifyd")))
        return "notification";
    if (source && !strcmp(source, "alarm"))
        return "alarm";
    if (source && !strcmp(source, "syslog"))
        return "syslog";
    return "general";
}

static const char *logd_canonical_source_label(const char *source_id)
{
    if (!strcmp(source_id, "kernel")) return "Kernel logs";
    if (!strcmp(source_id, "audit")) return "Audit logs";
    if (!strcmp(source_id, "notification")) return "Notifications";
    if (!strcmp(source_id, "alarm")) return "Alarms";
    if (!strcmp(source_id, "syslog")) return "Remote syslog";
    return "General logs";
}

static void logd_cef_escape(const char *s, char *out, size_t out_len, int header)
{
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    while (*p && n + 1 < out_len) {
        char c = (char)*p++;
        int esc = 0;

        if (c == '\\' || c == '\r' || c == '\n')
            esc = 1;
        else if (header && c == '|')
            esc = 1;
        else if (!header && c == '=')
            esc = 1;
        if (esc) {
            if (n + 2 >= out_len)
                break;
            out[n++] = '\\';
            if (c == '\r' || c == '\n')
                c = ' ';
        }
        out[n++] = c;
    }
    out[n] = 0;
}

static void logd_unifi_build_cef(char *out, size_t out_len,
                                 const char *key, const char *title,
                                 const char *severity, const char *uni_category,
                                 const char *ip, const char *mac,
                                 const char *user, const char *source,
                                 const char *iface, const char *message,
                                 const char *module, const char *facility)
{
    char key_e[128];
    char title_e[256];
    char category_e[96];
    char ip_e[96];
    char mac_e[96];
    char user_e[160];
    char source_e[160];
    char iface_e[96];
    char message_e[512];
    char module_e[160];
    char facility_e[64];

    if (!out || out_len == 0)
        return;
    logd_cef_escape(key, key_e, sizeof(key_e), 1);
    logd_cef_escape(title, title_e, sizeof(title_e), 1);
    logd_cef_escape(uni_category, category_e, sizeof(category_e), 0);
    logd_cef_escape(ip, ip_e, sizeof(ip_e), 0);
    logd_cef_escape(mac, mac_e, sizeof(mac_e), 0);
    logd_cef_escape(user, user_e, sizeof(user_e), 0);
    logd_cef_escape(source, source_e, sizeof(source_e), 0);
    logd_cef_escape(iface, iface_e, sizeof(iface_e), 0);
    logd_cef_escape(message && message[0] ? message : title, message_e, sizeof(message_e), 0);
    logd_cef_escape(module, module_e, sizeof(module_e), 0);
    logd_cef_escape(facility, facility_e, sizeof(facility_e), 0);
    snprintf(out, out_len,
             "CEF:0|DreamingWrt|Network|31.6|%s|%s|%d|cs1=%s cs1Label=category src=%s smac=%s duser=%s deviceExternalId=%s deviceInboundInterface=%s sproc=%s cs2=%s cs2Label=facility msg=%s",
             key_e, title_e, logd_unifi_cef_severity(severity), category_e,
             ip_e, mac_e, user_e, source_e, iface_e, module_e, facility_e, message_e);
}

static const char *logd_unifi_target(const char *category)
{
    if (!category)
        return "SYSTEM";
    if (!strcmp(category, "dhcp") || !strcmp(category, "client") ||
        !strcmp(category, "CLIENT_DEVICES"))
        return "CLIENT";
    if (!strcmp(category, "wan") || !strcmp(category, "pppoe") ||
        !strcmp(category, "port") || !strcmp(category, "INTERNET_AND_WAN") ||
        !strcmp(category, "DEVICES"))
        return "DEVICE";
    if (!strcmp(category, "audit") || !strcmp(category, "ADMIN"))
        return "ADMIN";
    return "SYSTEM";
}

static void logd_unifi_title_case(const char *key, char *out, size_t out_len)
{
    size_t i;
    int cap = 1;

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (!key)
        return;
    for (i = 0; i + 1 < out_len && key[i]; i++) {
        char c = key[i];
        if (c == '_' || c == '-' || c == '.') {
            out[i] = ' ';
            cap = 1;
            continue;
        }
        out[i] = cap ? (char)toupper((unsigned char)c) : (char)tolower((unsigned char)c);
        cap = 0;
    }
    out[i] = 0;
}

static int logd_unifi_arr_nonempty(struct json_object *body, const char *key)
{
    struct json_object *arr = NULL;

    return body && key && json_object_object_get_ex(body, key, &arr) && arr &&
           json_object_is_type(arr, json_type_array) &&
           json_object_array_length(arr) > 0;
}

static int logd_unifi_array_has(struct json_object *arr, const char *needle)
{
    int i, n;

    if (!arr || !needle || !json_object_is_type(arr, json_type_array))
        return 0;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *s = v ? json_object_get_string(v) : NULL;
        if (s && !strcmp(s, needle))
            return 1;
    }
    return 0;
}

static int logd_unifi_severity_bind_count(struct json_object *arr)
{
    int i, n, count = 0;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *s = v ? json_object_get_string(v) : NULL;
        if (!s || !s[0] || !strcmp(s, "LOW"))
            continue;
        count++;
    }
    return count;
}

static void logd_unifi_parse_query(struct json_object *body, struct logd_unifi_query *q)
{
    static const char *rowid_keys[] = { "cursor_rowid", "since_rowid", "after_rowid", "last_rowid", NULL };
    static const char *seq_keys[] = { "cursor_seq", "since_seq", "after_seq", "last_seq", NULL };
    static const char *ts_keys[] = { "cursor_ts", "since_ts", "after_ts", "last_ts", NULL };
    static const char *id_keys[] = { "cursor_id", "since_id", "after_id", "last_id", NULL };

    if (!q)
        return;
    memset(q, 0, sizeof(*q));
    q->search = logd_json_str(body, "searchText", logd_json_str(body, "search_text",
                             logd_json_str(body, "query", logd_json_str(body, "q", ""))));
    q->ts_from = logd_unifi_ts_s(logd_json_i64(body, "timestampFrom",
                             logd_json_i64(body, "ts_from", 0)));
    q->ts_to = logd_unifi_ts_s(logd_json_i64(body, "timestampTo",
                           logd_json_i64(body, "ts_to", 0)));
    q->cursor_rowid = logd_json_i64_any(body, rowid_keys, 0);
    q->cursor_seq = logd_json_i64_any(body, seq_keys, 0);
    q->cursor_ts = logd_unifi_ts_s(logd_json_i64_any(body, ts_keys, 0));
    q->cursor_id = logd_json_str_any(body, id_keys, "");
    q->actor = logd_json_str(body, "actor", logd_json_str(body, "viewer", "default"));
    q->incremental = q->cursor_seq > 0 || q->cursor_rowid > 0 || q->cursor_ts > 0 ||
                     (q->cursor_id && q->cursor_id[0]);
    q->page = logd_json_int(body, "pageNumber", logd_json_int(body, "page_number", 0));
    q->page_size = logd_json_int(body, "pageSize", logd_json_int(body, "page_size", 25));
    if (q->page < 0)
        q->page = 0;
    if (q->page_size <= 0)
        q->page_size = 25;
    if (q->page_size > 200)
        q->page_size = 200;
    if (!q->actor || !q->actor[0] || !logd_text_ok(q->actor, 128))
        q->actor = "default";
}

static void logd_unifi_bind_array(sqlite3_stmt *st, int *b, struct json_object *arr,
                                  const char *kind)
{
    int i, n;

    if (!st || !b || !arr || !json_object_is_type(arr, json_type_array))
        return;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *s = v ? json_object_get_string(v) : "";

        if (!s)
            s = "";
        if (!strcmp(kind, "like")) {
            char pat[256];

            snprintf(pat, sizeof(pat), "%%%s%%", s);
            sqlite3_bind_text(st, (*b)++, pat, -1, SQLITE_TRANSIENT);
            continue;
        }
        if (!strcmp(kind, "severity")) {
            if (!strcmp(s, "VERY_HIGH"))
                s = "critical";
            else if (!strcmp(s, "HIGH"))
                s = "error";
            else if (!strcmp(s, "MEDIUM"))
                s = "warning";
            else if (!strcmp(s, "LOW"))
                continue;
        }
        sqlite3_bind_text(st, (*b)++, s, -1, SQLITE_TRANSIENT);
    }
}

static void logd_unifi_append_in_clause(char *sql, size_t sql_len, const char *column,
                                        int count)
{
    int i;

    if (!sql || !column || count <= 0)
        return;
    strncat(sql, " AND ", sql_len - strlen(sql) - 1);
    strncat(sql, column, sql_len - strlen(sql) - 1);
    strncat(sql, " IN (", sql_len - strlen(sql) - 1);
    for (i = 0; i < count; i++)
        strncat(sql, i ? ",?" : "?", sql_len - strlen(sql) - 1);
    strncat(sql, ")", sql_len - strlen(sql) - 1);
}

static void logd_unifi_append_like_clause(char *sql, size_t sql_len,
                                          const char *column, int count)
{
    int i;

    if (!sql || !column || count <= 0)
        return;
    strncat(sql, " OR ", sql_len - strlen(sql) - 1);
    strncat(sql, column, sql_len - strlen(sql) - 1);
    strncat(sql, " LIKE ?", sql_len - strlen(sql) - 1);
    for (i = 1; i < count; i++) {
        strncat(sql, " OR ", sql_len - strlen(sql) - 1);
        strncat(sql, column, sql_len - strlen(sql) - 1);
        strncat(sql, " LIKE ?", sql_len - strlen(sql) - 1);
    }
}

static void logd_unifi_append_client_filter_clause(char *sql, size_t sql_len,
                                                   int count)
{
    if (!sql || count <= 0)
        return;
    strncat(sql, " AND (", sql_len - strlen(sql) - 1);
    strncat(sql, "mac IN (", sql_len - strlen(sql) - 1);
    for (int i = 0; i < count; i++)
        strncat(sql, i ? ",?" : "?", sql_len - strlen(sql) - 1);
    strncat(sql, ")", sql_len - strlen(sql) - 1);
    logd_unifi_append_like_clause(sql, sql_len, "detail_json", count);
    strncat(sql, ")", sql_len - strlen(sql) - 1);
}

static void logd_unifi_append_device_filter_clause(char *sql, size_t sql_len,
                                                   int count)
{
    static const char *exprs[] = {
        "('iface:'||iface)",
        "('wan:'||wan_id)",
        "('source:'||source)",
        "iface",
        "wan_id",
        "source",
    };

    if (!sql || count <= 0)
        return;
    strncat(sql, " AND (", sql_len - strlen(sql) - 1);
    for (size_t e = 0; e < sizeof(exprs) / sizeof(exprs[0]); e++) {
        if (e)
            strncat(sql, " OR ", sql_len - strlen(sql) - 1);
        strncat(sql, exprs[e], sql_len - strlen(sql) - 1);
        strncat(sql, " IN (", sql_len - strlen(sql) - 1);
        for (int i = 0; i < count; i++)
            strncat(sql, i ? ",?" : "?", sql_len - strlen(sql) - 1);
        strncat(sql, ")", sql_len - strlen(sql) - 1);
    }
    logd_unifi_append_like_clause(sql, sql_len, "detail_json", count);
    strncat(sql, ")", sql_len - strlen(sql) - 1);
}

static int logd_unifi_build_where(struct json_object *body, char *sql, size_t sql_len,
                                  struct json_object **sev_arr, struct json_object **cat_arr,
                                  struct json_object **evt_arr, struct json_object **mac_arr,
                                  struct json_object **device_arr,
                                  struct json_object **admin_arr,
                                  struct json_object **program_arr)
{
    int n;

    if (!sql || sql_len == 0)
        return -1;
    snprintf(sql, sql_len, " FROM log_events WHERE 1=1");
    if (body && logd_unifi_arr_nonempty(body, "severities")) {
        int sev_bind_count;
        int low_selected;

        json_object_object_get_ex(body, "severities", sev_arr);
        sev_bind_count = logd_unifi_severity_bind_count(*sev_arr);
        low_selected = logd_unifi_array_has(*sev_arr, "LOW");
        strncat(sql, " AND (", sql_len - strlen(sql) - 1);
        if (sev_bind_count > 0) {
            strncat(sql, "severity IN (", sql_len - strlen(sql) - 1);
            for (int i = 0; i < sev_bind_count; i++)
                strncat(sql, i ? ",?" : "?", sql_len - strlen(sql) - 1);
            strncat(sql, ")", sql_len - strlen(sql) - 1);
        }
        if (low_selected) {
            if (sev_bind_count > 0)
                strncat(sql, " OR ", sql_len - strlen(sql) - 1);
            strncat(sql, "severity IN ('info','notice')", sql_len - strlen(sql) - 1);
        }
        if (sev_bind_count <= 0 && !low_selected)
            strncat(sql, "1=1", sql_len - strlen(sql) - 1);
        strncat(sql, ")", sql_len - strlen(sql) - 1);
    }
    if (body && logd_unifi_arr_nonempty(body, "categories")) {
        json_object_object_get_ex(body, "categories", cat_arr);
        logd_unifi_append_in_clause(sql, sql_len,
            "(CASE "
            "WHEN category IN ('SYSTEM','INTERNET_AND_WAN','CLIENT_DEVICES','DEVICES','ADMIN','SECURITY','VPN') THEN category "
            "WHEN category IN ('dhcp','client') THEN 'CLIENT_DEVICES' "
            "WHEN category IN ('wan','pppoe','port') THEN 'INTERNET_AND_WAN' "
            "WHEN category IN ('audit','auth') THEN 'ADMIN' "
            "WHEN category='security' THEN 'SECURITY' "
            "WHEN category='vpn' THEN 'VPN' "
            "ELSE 'SYSTEM' END)",
            json_object_array_length(*cat_arr));
    }
    if (body && logd_unifi_arr_nonempty(body, "events")) {
        json_object_object_get_ex(body, "events", evt_arr);
        logd_unifi_append_in_clause(sql, sql_len,
            "(CASE "
            "WHEN event='lease_assigned' THEN 'CLIENT_CONNECTED_WIRED' "
            "WHEN event='lease_released' THEN 'CLIENT_DISCONNECTED' "
            "WHEN event='link_up' THEN 'PORT_LINK_UP' "
            "WHEN event='link_down' THEN 'PORT_LINK_DOWN' "
            "WHEN event='port_log' THEN 'PORT_EVENT' "
            "WHEN event='wan_log' THEN 'WAN_EVENT' "
            "WHEN event='pppoe_log' THEN 'PPPOE_EVENT' "
            "WHEN event='auth_log' THEN 'ADMIN_AUTH_EVENT' "
            "WHEN event='packet_capture_started' THEN 'PACKET_CAPTURE_STARTED' "
            "WHEN event='packet_capture_stopped' THEN 'PACKET_CAPTURE_STOPPED' "
            "WHEN event='packet_capture_finished' THEN 'PACKET_CAPTURE_FINISHED' "
            "WHEN event='packet_capture_deleted' THEN 'PACKET_CAPTURE_DELETED' "
            "WHEN event='threshold_exceeded' THEN 'SYSTEM_RESOURCE_THRESHOLD' "
            "WHEN event='dhcp_log' THEN 'DHCP_EVENT' "
            "WHEN event='log_line' THEN 'SYSTEM_LOG' "
            "ELSE event END)",
            json_object_array_length(*evt_arr));
    }
    if (body && logd_unifi_arr_nonempty(body, "clientDeviceMacs")) {
        json_object_object_get_ex(body, "clientDeviceMacs", mac_arr);
        logd_unifi_append_client_filter_clause(sql, sql_len, json_object_array_length(*mac_arr));
    }
    if (body && logd_unifi_arr_nonempty(body, "deviceMacs")) {
        json_object_object_get_ex(body, "deviceMacs", device_arr);
        logd_unifi_append_device_filter_clause(sql, sql_len, json_object_array_length(*device_arr));
    }
    if (body && logd_unifi_arr_nonempty(body, "adminIds")) {
        json_object_object_get_ex(body, "adminIds", admin_arr);
        strncat(sql, " AND (username IN (", sql_len - strlen(sql) - 1);
        n = json_object_array_length(*admin_arr);
        for (int i = 0; i < n; i++)
            strncat(sql, i ? ",?" : "?", sql_len - strlen(sql) - 1);
        strncat(sql, ") OR actor IN (", sql_len - strlen(sql) - 1);
        for (int i = 0; i < n; i++)
            strncat(sql, i ? ",?" : "?", sql_len - strlen(sql) - 1);
        strncat(sql, ")", sql_len - strlen(sql) - 1);
        logd_unifi_append_like_clause(sql, sql_len, "detail_json", n);
        strncat(sql, ")", sql_len - strlen(sql) - 1);
    }
    if (body && logd_unifi_arr_nonempty(body, "programs")) {
        json_object_object_get_ex(body, "programs", program_arr);
        logd_unifi_append_in_clause(sql, sql_len,
            "(CASE lower(rtrim(COALESCE(NULLIF(json_extract(detail_json,'$.program'),''),"
            "NULLIF(json_extract(detail_json,'$.module'),''),source),'[0123456789]()')) "
            "WHEN 'kernel_log' THEN 'kernel' WHEN 'system_log' THEN 'system' "
            "ELSE lower(rtrim(COALESCE(NULLIF(json_extract(detail_json,'$.program'),''),"
            "NULLIF(json_extract(detail_json,'$.module'),''),source),'[0123456789]()')) END)",
            json_object_array_length(*program_arr));
    }
    return 0;
}

static void logd_unifi_bind_common(sqlite3_stmt *st, int *b,
                                   const struct logd_unifi_query *q,
                                   struct json_object *sev_arr,
                                   struct json_object *cat_arr,
                                   struct json_object *evt_arr,
                                   struct json_object *mac_arr,
                                   struct json_object *device_arr,
                                   struct json_object *admin_arr,
                                   struct json_object *program_arr)
{
    char pat[320];

    if (!st || !b || !q)
        return;
    if (sev_arr)
        logd_unifi_bind_array(st, b, sev_arr, "severity");
    if (cat_arr)
        logd_unifi_bind_array(st, b, cat_arr, "category");
    if (evt_arr)
        logd_unifi_bind_array(st, b, evt_arr, "event");
    if (mac_arr) {
        logd_unifi_bind_array(st, b, mac_arr, "mac");
        logd_unifi_bind_array(st, b, mac_arr, "like");
    }
    if (device_arr) {
        for (int i = 0; i < 6; i++)
            logd_unifi_bind_array(st, b, device_arr, "mac");
        logd_unifi_bind_array(st, b, device_arr, "like");
    }
    if (admin_arr) {
        logd_unifi_bind_array(st, b, admin_arr, "admin");
        logd_unifi_bind_array(st, b, admin_arr, "admin");
        logd_unifi_bind_array(st, b, admin_arr, "like");
    }
    if (program_arr)
        logd_unifi_bind_array(st, b, program_arr, "program");
    if (q->ts_from > 0)
        sqlite3_bind_int64(st, (*b)++, q->ts_from);
    if (q->ts_to > 0)
        sqlite3_bind_int64(st, (*b)++, q->ts_to);
    if (q->cursor_seq > 0)
        sqlite3_bind_int64(st, (*b)++, q->cursor_seq);
    else if (q->cursor_rowid > 0)
        sqlite3_bind_int64(st, (*b)++, q->cursor_rowid);
    else if (q->cursor_ts > 0) {
        sqlite3_bind_int64(st, (*b)++, q->cursor_ts);
        sqlite3_bind_int64(st, (*b)++, q->cursor_ts);
        sqlite3_bind_text(st, (*b)++, q->cursor_id ? q->cursor_id : "", -1, SQLITE_TRANSIENT);
    }
    if (q->search && q->search[0]) {
        snprintf(pat, sizeof(pat), "%%%s%%", q->search);
        for (int i = 0; i < 11; i++)
            sqlite3_bind_text(st, (*b)++, pat, -1, SQLITE_TRANSIENT);
    }
}

static void logd_unifi_add_time_search_where(char *sql, size_t sql_len,
                                             const struct logd_unifi_query *q)
{
    if (!sql || !q)
        return;
    if (q->ts_from > 0)
        strncat(sql, " AND ts>=?", sql_len - strlen(sql) - 1);
    if (q->ts_to > 0)
        strncat(sql, " AND ts<=?", sql_len - strlen(sql) - 1);
    if (q->cursor_seq > 0)
        strncat(sql, " AND seq>?", sql_len - strlen(sql) - 1);
    else if (q->cursor_rowid > 0)
        strncat(sql, " AND rowid>?", sql_len - strlen(sql) - 1);
    else if (q->cursor_ts > 0)
        strncat(sql, " AND (ts>? OR (ts=? AND id>?))", sql_len - strlen(sql) - 1);
    if (q->search && q->search[0])
        strncat(sql, " AND (title LIKE ? OR detail_json LIKE ? OR category LIKE ? OR event LIKE ? OR source LIKE ? OR iface LIKE ? OR wan_id LIKE ? OR ip LIKE ? OR mac LIKE ? OR username LIKE ? OR actor LIKE ?)",
                sql_len - strlen(sql) - 1);
}

static void logd_unifi_actor_state(const char *actor,
                                   sqlite3_int64 rowid,
                                   sqlite3_int64 seq,
                                   const char *id,
                                   int64_t *read_at,
                                   int64_t *acked_at)
{
    sqlite3_stmt *st;

    if (read_at)
        *read_at = 0;
    if (acked_at)
        *acked_at = 0;
    if (!actor || !actor[0] || !id || !id[0])
        return;
    st = logd_prepare(
        "SELECT CASE WHEN COALESCE(c.cursor_seq,0)>=?3 OR COALESCE(c.cursor_rowid,0)>=?2 THEN COALESCE(c.updated_at,0) "
        "ELSE COALESCE(r.read_at,0) END AS read_at, COALESCE(a.acked_at,0) "
        "FROM (SELECT ?1 AS actor, ?4 AS event_id) x "
        "LEFT JOIN log_read_cursors c ON c.actor=x.actor "
        "LEFT JOIN log_read_events r ON r.actor=x.actor AND r.event_id=x.event_id "
        "LEFT JOIN log_event_ack a ON a.actor=x.actor AND a.event_id=x.event_id");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, rowid);
    sqlite3_bind_int64(st, 3, seq);
    sqlite3_bind_text(st, 4, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (read_at)
            *read_at = sqlite3_column_int64(st, 0);
        if (acked_at)
            *acked_at = sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
    if (read_at && *read_at <= 0 && acked_at && *acked_at > 0)
        *read_at = *acked_at;
}

static void logd_unifi_item_from_stmt_for_actor(struct json_object *arr, sqlite3_stmt *st,
                                                const char *viewer)
{
    sqlite3_int64 rowid = sqlite3_column_int64(st, 0);
    sqlite3_int64 seq = sqlite3_column_int64(st, 1);
    const char *id = logd_sqlite_text(st, 2, "");
    int64_t ts = sqlite3_column_int64(st, 3);
    const char *severity = logd_sqlite_text(st, 4, "info");
    const char *category = logd_sqlite_text(st, 5, "system");
    const char *event = logd_sqlite_text(st, 6, "log_line");
    const char *source = logd_sqlite_text(st, 7, "");
    const char *iface = logd_sqlite_text(st, 8, "");
    const char *wan_id = logd_sqlite_text(st, 9, "");
    const char *ip = logd_sqlite_text(st, 10, "");
    const char *mac = logd_sqlite_text(st, 11, "");
    const char *username = logd_sqlite_text(st, 12, "");
    const char *actor = logd_sqlite_text(st, 13, "");
    const char *title = logd_sqlite_text(st, 14, "");
    const char *detail_s = logd_sqlite_text(st, 15, "{}");
    const char *state = logd_sqlite_text(st, 17, "active");
    int count = sqlite3_column_int(st, 20);
    int64_t read_at = 0;
    int64_t acked_at = 0;
    const char *key = logd_unifi_event_key(category, event);
    const char *uni_category = logd_unifi_category(category, event);
    char fallback_title[160];
    char cef[1024];
    struct json_object *o = json_object_new_object();
    struct json_object *params = json_object_new_object();
    struct json_object *device = json_object_new_object();
    struct json_object *client = json_object_new_object();
    struct json_object *admin = json_object_new_object();
    struct json_object *raw = json_object_new_object();
    struct json_object *detail = detail_s && detail_s[0] ? json_tokener_parse(detail_s) : NULL;
    const char *parsed_facility = logd_json_obj_str(detail, "facility");
    const char *facility_level = logd_json_obj_str(detail, "facility_level");
    const char *parsed_module = logd_json_obj_str(detail, "module");
    const char *parsed_message = logd_json_obj_str(detail, "message");
    const char *source_id = logd_json_obj_str(detail, "source_id");
    const char *source_label = logd_json_obj_str(detail, "source_label");
    const char *program = logd_json_obj_str(detail, "program");
    const char *program_label = logd_json_obj_str(detail, "program_label");
    const char *package = logd_json_obj_str(detail, "package");
    const char *raw_line = logd_json_obj_str(detail, "raw");
    const char *event_fingerprint = logd_json_obj_str(detail, "event_fingerprint");
    struct json_object *collectors = NULL;
    const char *canonical_source_id = logd_canonical_source_id(source_id, source, category);
    char canonical_program[128];
    const char *client_hostname = logd_json_obj_str(detail, "hostname");
    const char *client_id = logd_json_obj_str(detail, "client_id");
    const char *device_name = logd_json_obj_str(detail, "device_name");
    int64_t original_ts_ms = logd_json_obj_i64(detail, "original_timestamp_ms", 0);

    logd_unifi_title_case(key, fallback_title, sizeof(fallback_title));
    logd_program_id_normalize(program[0] ? program : (parsed_module[0] ? parsed_module : source),
                              canonical_program, sizeof(canonical_program));
    if (!canonical_program[0])
        snprintf(canonical_program, sizeof(canonical_program), "%s",
                 !strcmp(canonical_source_id, "kernel") ? "kernel" : "system");
    if (!title || !title[0])
        title = fallback_title[0] ? fallback_title : key;
    if (seq <= 0)
        seq = rowid;
    logd_unifi_actor_state(viewer, rowid, seq, id, &read_at, &acked_at);

    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "seq", json_object_new_int64(seq));
    json_object_object_add(o, "cursor_seq", json_object_new_int64(seq));
    json_object_object_add(o, "rowid", json_object_new_int64(rowid));
    json_object_object_add(o, "cursor_rowid", json_object_new_int64(rowid));
    json_object_object_add(o, "external_id", json_object_new_string(id));
    json_object_object_add(o, "category", json_object_new_string(uni_category));
    json_object_object_add(o, "raw_category", json_object_new_string(category));
    json_object_object_add(o, "subcategory", json_object_new_string(logd_unifi_subcategory(category, event)));
    json_object_object_add(o, "event", json_object_new_string(key));
    json_object_object_add(o, "raw_event", json_object_new_string(event));
    json_object_object_add(o, "key", json_object_new_string(key));
    json_object_object_add(o, "title", json_object_new_string(title));
    json_object_object_add(o, "message", json_object_new_string(parsed_message[0] ? parsed_message : title));
    json_object_object_add(o, "source_id", json_object_new_string(canonical_source_id));
    json_object_object_add(o, "source_label", json_object_new_string(source_label[0] ? source_label : logd_canonical_source_label(canonical_source_id)));
    json_object_object_add(o, "program", json_object_new_string(canonical_program));
    json_object_object_add(o, "program_label", json_object_new_string(program_label[0] ? program_label : canonical_program));
    json_object_object_add(o, "package", json_object_new_string(package));
    json_object_object_add(o, "raw", json_object_new_string(raw_line[0] ? raw_line : title));
    json_object_object_add(o, "event_fingerprint", json_object_new_string(event_fingerprint));
    if (detail && json_object_object_get_ex(detail, "collectors", &collectors) && collectors)
        json_object_object_add(o, "collectors", json_object_get(collectors));
    else {
        struct json_object *fallback_collectors = json_object_new_array();
        const char *collector = logd_json_obj_str(detail, "collector");
        if (collector[0])
            json_object_array_add(fallback_collectors, json_object_new_string(collector));
        json_object_object_add(o, "collectors", fallback_collectors);
    }
    if (parsed_facility[0])
        json_object_object_add(o, "facility", json_object_new_string(parsed_facility));
    if (facility_level[0])
        json_object_object_add(o, "facility_level", json_object_new_string(facility_level));
    if (parsed_module[0])
        json_object_object_add(o, "module", json_object_new_string(parsed_module));
    json_object_object_add(o, "severity", json_object_new_string(logd_unifi_severity(severity)));
    json_object_object_add(o, "raw_severity", json_object_new_string(severity));
    json_object_object_add(o, "status", json_object_new_string(!strcmp(state, "cleared") ? "ARCHIVED" : (acked_at > 0 ? "ACKED" : (read_at > 0 ? "READ" : "NEW"))));
    json_object_object_add(o, "read", json_object_new_boolean(read_at > 0));
    json_object_object_add(o, "read_at", json_object_new_int64(read_at));
    json_object_object_add(o, "acked", json_object_new_boolean(acked_at > 0));
    json_object_object_add(o, "acked_at", json_object_new_int64(acked_at));
    json_object_object_add(o, "target", json_object_new_string(logd_unifi_target(category)));
    json_object_object_add(o, "type", json_object_new_string(!strcmp(uni_category, "ADMIN") ? "AUDIT" : "GENERAL"));
    json_object_object_add(o, "timestamp", json_object_new_int64(ts * 1000));
    json_object_object_add(o, "ts", json_object_new_int64(ts));
    if (original_ts_ms > 0)
        json_object_object_add(o, "original_timestamp", json_object_new_int64(original_ts_ms));
    json_object_object_add(o, "count", json_object_new_int(count));

    json_object_object_add(device, "id", json_object_new_string(iface[0] ? iface : (wan_id[0] ? wan_id : (source[0] ? source : "gateway"))));
    json_object_object_add(device, "name", json_object_new_string(device_name[0] ? device_name : (iface[0] ? iface : (wan_id[0] ? wan_id : "DreamingWrt"))));
    json_object_object_add(device, "model", json_object_new_string("DreamingWrt"));
    if (source[0])
        json_object_object_add(device, "source", json_object_new_string(source));
    if (iface[0])
        json_object_object_add(device, "interface", json_object_new_string(iface));
    if (wan_id[0])
        json_object_object_add(device, "wan_id", json_object_new_string(wan_id));
    json_object_object_add(params, "DEVICE", device);

    if (mac[0] || ip[0]) {
        if (mac[0])
            json_object_object_add(client, "mac", json_object_new_string(mac));
        if (ip[0])
            json_object_object_add(client, "ip", json_object_new_string(ip));
        if (client_hostname[0]) {
            json_object_object_add(client, "name", json_object_new_string(client_hostname));
            json_object_object_add(client, "hostname", json_object_new_string(client_hostname));
        }
        if (client_id[0])
            json_object_object_add(client, "client_id", json_object_new_string(client_id));
        json_object_object_add(params, "CLIENT", client);
    } else {
        json_object_put(client);
    }

    if (username[0] || actor[0]) {
        json_object_object_add(admin, "id", json_object_new_string(username[0] ? username : actor));
        json_object_object_add(admin, "name", json_object_new_string(username[0] ? username : actor));
        if (actor[0])
            json_object_object_add(admin, "actor", json_object_new_string(actor));
        json_object_object_add(params, "ADMIN", admin);
    } else {
        json_object_put(admin);
    }

    json_object_object_add(raw, "source", json_object_new_string(source));
    json_object_object_add(raw, "iface", json_object_new_string(iface));
    json_object_object_add(raw, "wan_id", json_object_new_string(wan_id));
    json_object_object_add(raw, "state", json_object_new_string(state));
    json_object_object_add(raw, "category", json_object_new_string(category));
    json_object_object_add(raw, "event", json_object_new_string(event));
    json_object_object_add(raw, "severity", json_object_new_string(severity));
    if (detail)
        json_object_object_add(raw, "detail_json", detail);
    else
        json_object_object_add(raw, "detail_json", json_object_new_string(detail_s ? detail_s : "{}"));
    json_object_object_add(params, "RAW", raw);
    json_object_object_add(o, "parameters", params);

    logd_unifi_build_cef(cef, sizeof(cef), key, title, severity, uni_category,
                         ip, mac, username[0] ? username : actor, source,
                         iface, parsed_message, parsed_module, parsed_facility);
    json_object_object_add(o, "cef", json_object_new_string(cef));
    json_object_array_add(arr, o);
}

static void logd_unifi_item_from_stmt(struct json_object *arr, sqlite3_stmt *st)
{
    logd_unifi_item_from_stmt_for_actor(arr, st, NULL);
}

static int64_t logd_unifi_count_state(const char *where, const struct logd_unifi_query *q,
                                      struct json_object *sev_arr,
                                      struct json_object *cat_arr,
                                      struct json_object *evt_arr,
                                      struct json_object *mac_arr,
                                      struct json_object *device_arr,
                                      struct json_object *admin_arr,
                                      struct json_object *program_arr,
                                      const char *kind)
{
    sqlite3_stmt *st;
    char sql[4096];
    int b = 1;
    int64_t total = 0;

    if (!where || !q || !kind)
        return 0;
    if (!strcmp(kind, "unread")) {
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*)%s AND NOT EXISTS ("
                 " SELECT 1 FROM log_read_cursors c WHERE c.actor=? AND (c.cursor_seq>=log_events.seq OR c.cursor_rowid>=log_events.rowid))"
                 " AND NOT EXISTS ("
                 " SELECT 1 FROM log_read_events r WHERE r.actor=? AND r.event_id=log_events.id)"
                 " AND NOT EXISTS ("
                 " SELECT 1 FROM log_event_ack a WHERE a.actor=? AND a.event_id=log_events.id)",
                 where);
    } else if (!strcmp(kind, "acked")) {
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*)%s AND EXISTS ("
                 " SELECT 1 FROM log_event_ack a WHERE a.actor=? AND a.event_id=log_events.id)",
                 where);
    } else {
        return 0;
    }
    st = logd_prepare(sql);
    if (!st)
        return 0;
    logd_unifi_bind_common(st, &b, q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr);
    sqlite3_bind_text(st, b++, q->actor ? q->actor : "default", -1, SQLITE_TRANSIENT);
    if (!strcmp(kind, "unread"))
        sqlite3_bind_text(st, b++, q->actor ? q->actor : "default", -1, SQLITE_TRANSIENT);
    if (!strcmp(kind, "unread"))
        sqlite3_bind_text(st, b++, q->actor ? q->actor : "default", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        total = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return total;
}

struct json_object *logd_unifi_capabilities_json(void)
{
    struct json_object *cap = json_object_new_object();

    json_object_object_add(cap, "cef", json_object_new_boolean(1));
    json_object_object_add(cap, "cef_escape", json_object_new_boolean(1));
    json_object_object_add(cap, "structured_logread", json_object_new_boolean(1));
    json_object_object_add(cap, "structured_sources", json_object_new_boolean(1));
    json_object_object_add(cap, "dynamic_programs", json_object_new_boolean(1));
    json_object_object_add(cap, "program_filter", json_object_new_boolean(1));
    json_object_object_add(cap, "cross_collector_dedupe", json_object_new_boolean(1));
    json_object_object_add(cap, "event_fingerprint", json_object_new_boolean(1));
    json_object_object_add(cap, "audit", json_object_new_boolean(1));
    json_object_object_add(cap, "filter_data", json_object_new_boolean(1));
    json_object_object_add(cap, "pagination", json_object_new_boolean(1));
    json_object_object_add(cap, "search", json_object_new_boolean(1));
    json_object_object_add(cap, "log_center_v2", json_object_new_boolean(1));
    json_object_object_add(cap, "unifi_style_logs", json_object_new_boolean(1));
    json_object_object_add(cap, "settings_write", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_test", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_tls", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_tls_custom_ca", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_tls_client_cert", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_mtls", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_tls_verify_controls", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_cert_upload", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_cert_list", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_cert_delete", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_queue", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_queue_status", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_queue_flush", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_queue_clear", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_profiles", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_multi_profile", json_object_new_boolean(1));
    json_object_object_add(cap, "siem_profiles", json_object_new_boolean(1));
    json_object_object_add(cap, "max_syslog_profiles", json_object_new_int(LOGD_SYSLOG_MAX_PROFILES));
    json_object_object_add(cap, "syslog_vendor_presets", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_preset_apply_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_queue_watermark", json_object_new_boolean(1));
    json_object_object_add(cap, "syslog_queue_max_rows", json_object_new_int(LOGD_SYSLOG_QUEUE_MAX_ROWS));
    json_object_object_add(cap, "syslog_queue_sent_retention_sec", json_object_new_int(LOGD_SYSLOG_QUEUE_SENT_RETENTION_SEC));
    json_object_object_add(cap, "syslog_queue_failed_retention_sec", json_object_new_int(LOGD_SYSLOG_QUEUE_FAILED_RETENTION_SEC));
    json_object_object_add(cap, "export", json_object_new_boolean(1));
    json_object_object_add(cap, "download", json_object_new_boolean(1));
    json_object_object_add(cap, "download_url", json_object_new_boolean(1));
    json_object_object_add(cap, "siem_export", json_object_new_boolean(1));
    json_object_object_add(cap, "cursor", json_object_new_boolean(1));
    json_object_object_add(cap, "cursor_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "cursor_field", json_object_new_string("seq"));
    json_object_object_add(cap, "legacy_cursor_field", json_object_new_string("rowid"));
    json_object_object_add(cap, "stable_seq", json_object_new_boolean(1));
    json_object_object_add(cap, "rowid_cursor_compat", json_object_new_boolean(1));
    json_object_object_add(cap, "incremental_search", json_object_new_boolean(1));
    json_object_object_add(cap, "ack_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "persistent_ack", json_object_new_boolean(1));
    json_object_object_add(cap, "mark_read_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "persistent_mark_read", json_object_new_boolean(1));
    json_object_object_add(cap, "read_state_actor_scoped", json_object_new_boolean(1));
    json_object_object_add(cap, "realtime_ws", json_object_new_boolean(0));
    json_object_object_add(cap, "realtime_websocket", json_object_new_boolean(0));
    return cap;
}

static int logd_unifi_bind_event_ids(sqlite3_stmt *st, int *b, struct json_object *ids);

struct json_object *logd_unifi_search(struct json_object *body)
{
    struct logd_unifi_query q;
    struct json_object *sev_arr = NULL, *cat_arr = NULL, *evt_arr = NULL;
    struct json_object *mac_arr = NULL, *device_arr = NULL, *admin_arr = NULL;
    struct json_object *program_arr = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    char where[2048];
    char sql[4096];
    int b = 1;
    int rc;
    int64_t total = 0;
    int64_t max_rowid = 0;
    int64_t max_seq = 0;
    int returned = 0;
    int cursor_idx = -1;

    logd_unifi_parse_query(body, &q);
    if (logd_unifi_build_where(body, where, sizeof(where), &sev_arr, &cat_arr,
                               &evt_arr, &mac_arr, &device_arr, &admin_arr,
                               &program_arr) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("query_build_failed"));
        json_object_put(arr);
        return resp;
    }
    logd_unifi_add_time_search_where(where, sizeof(where), &q);

    snprintf(sql, sizeof(sql), "SELECT COUNT(*)%s", where);
    st = logd_prepare(sql);
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("count_prepare_failed"));
        json_object_put(arr);
        return resp;
    }
    logd_unifi_bind_common(st, &b, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr);
    if (sqlite3_step(st) == SQLITE_ROW)
        total = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);

    snprintf(sql, sizeof(sql),
             "SELECT rowid,seq,id,ts,severity,category,event,source,iface,wan_id,ip,mac,username,actor,title,detail_json,dedupe_key,state,first_seen,last_seen,count"
             "%s %s LIMIT ?%s", where,
             q.incremental ? "ORDER BY seq ASC" : "ORDER BY ts DESC,seq DESC",
             q.incremental ? "" : " OFFSET ?");
    st = logd_prepare(sql);
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("search_prepare_failed"));
        json_object_put(arr);
        return resp;
    }
    b = 1;
    logd_unifi_bind_common(st, &b, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr);
    sqlite3_bind_int(st, b++, q.page_size);
    if (!q.incremental)
        sqlite3_bind_int(st, b++, q.page * q.page_size);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int64_t rowid = sqlite3_column_int64(st, 0);
        int64_t seq = sqlite3_column_int64(st, 1);
        if (rowid > max_rowid)
            max_rowid = rowid;
        if (seq > max_seq)
            max_seq = seq;
        logd_unifi_item_from_stmt_for_actor(arr, st, q.actor);
        returned++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("search_failed"));
        json_object_put(arr);
        return resp;
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "data", arr);
    json_object_object_add(resp, "page_number", json_object_new_int(q.page));
    json_object_object_add(resp, "page_size", json_object_new_int(q.page_size));
    json_object_object_add(resp, "returned", json_object_new_int(returned));
    json_object_object_add(resp, "incremental", json_object_new_boolean(q.incremental));
    json_object_object_add(resp, "cursor_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "cursor_field", json_object_new_string("seq"));
    json_object_object_add(resp, "legacy_cursor_field", json_object_new_string("rowid"));
    json_object_object_add(resp, "cursor_seq", json_object_new_int64(q.cursor_seq));
    json_object_object_add(resp, "cursor_rowid", json_object_new_int64(q.cursor_rowid));
    if (q.cursor_ts > 0)
        json_object_object_add(resp, "cursor_ts", json_object_new_int64(q.cursor_ts));
    if (q.cursor_id && q.cursor_id[0])
        json_object_object_add(resp, "cursor_id", json_object_new_string(q.cursor_id));
    if (returned > 0)
        cursor_idx = q.incremental ? returned - 1 : 0;
    json_object_object_add(resp, "next_cursor_seq", json_object_new_int64(max_seq > 0 ? max_seq : q.cursor_seq));
    json_object_object_add(resp, "next_cursor_rowid", json_object_new_int64(max_rowid > 0 ? max_rowid : q.cursor_rowid));
    json_object_object_add(resp, "next_cursor_ts", json_object_new_int64(cursor_idx >= 0 ? logd_json_i64(json_object_array_get_idx(arr, cursor_idx), "ts", 0) : q.cursor_ts));
    json_object_object_add(resp, "next_cursor_id", json_object_new_string(cursor_idx >= 0 ? logd_json_str(json_object_array_get_idx(arr, cursor_idx), "id", "") : (q.cursor_id ? q.cursor_id : "")));
    json_object_object_add(resp, "ack_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "mark_read_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "read_actor", json_object_new_string(q.actor ? q.actor : "default"));
    json_object_object_add(resp, "unread_total", json_object_new_int64(logd_unifi_count_state(where, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr, "unread")));
    json_object_object_add(resp, "acked_total", json_object_new_int64(logd_unifi_count_state(where, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr, "acked")));
    json_object_object_add(resp, "has_more", json_object_new_boolean(total > returned && q.incremental));
    json_object_object_add(resp, "total_element_count", json_object_new_int64(total));
    json_object_object_add(resp, "total_page_count",
                           json_object_new_int((int)((total + q.page_size - 1) / q.page_size)));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_unifi_get_by_ids(struct json_object *body)
{
    struct json_object *ids = NULL;
    struct json_object *items = json_object_new_array();
    struct json_object *resp = json_object_new_object();
    const char *actor = logd_json_str(body, "actor", logd_json_str(body, "viewer", "default"));
    sqlite3_stmt *st = NULL;
    char sql[4096];
    int n;
    int b = 1;
    int rc = SQLITE_DONE;

    if (!body || (!json_object_object_get_ex(body, "log_ids", &ids) &&
                  !json_object_object_get_ex(body, "ids", &ids)) ||
        !ids || !json_object_is_type(ids, json_type_array)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("missing_log_ids"));
        json_object_put(items);
        return resp;
    }
    n = json_object_array_length(ids);
    if (n <= 0 || n > 50) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string(n > 50 ? "too_many_log_ids" : "missing_log_ids"));
        json_object_object_add(resp, "max_items", json_object_new_int(50));
        json_object_put(items);
        return resp;
    }
    snprintf(sql, sizeof(sql),
             "SELECT rowid,seq,id,ts,severity,category,event,source,iface,wan_id,ip,mac,username,actor,title,detail_json,dedupe_key,state,first_seen,last_seen,count "
             "FROM log_events WHERE id IN (");
    for (int i = 0; i < n; i++)
        strncat(sql, i ? ",?" : "?", sizeof(sql) - strlen(sql) - 1);
    strncat(sql, ") ORDER BY ts DESC,seq DESC", sizeof(sql) - strlen(sql) - 1);
    st = logd_prepare(sql);
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("log_ids_prepare_failed"));
        json_object_put(items);
        return resp;
    }
    logd_unifi_bind_event_ids(st, &b, ids);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW)
        logd_unifi_item_from_stmt_for_actor(items, st, actor);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("log_ids_query_failed"));
        json_object_put(items);
        return resp;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "data", items);
    json_object_object_add(resp, "requested", json_object_new_int(n));
    json_object_object_add(resp, "returned", json_object_new_int(json_object_array_length(items)));
    json_object_object_add(resp, "missing", json_object_new_int(n - json_object_array_length(items)));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_unifi_export(struct json_object *body)
{
    struct logd_unifi_query q;
    struct json_object *sev_arr = NULL, *cat_arr = NULL, *evt_arr = NULL;
    struct json_object *mac_arr = NULL, *device_arr = NULL, *admin_arr = NULL;
    struct json_object *program_arr = NULL;
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st = NULL;
    char where[2048];
    char sql[4096];
    char path[256];
    char id[96];
    char filename[128];
    char download_url[192];
    const char *format = logd_json_str(body, "format", "json");
    const char *body_s = body ? json_object_to_json_string(body) : "{}";
    FILE *fp;
    int b = 1;
    int rc;
    int count = 0;
    int limit;

    if (strcmp(format, "json") && strcmp(format, "csv") && strcmp(format, "cef")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_export_format"));
        return resp;
    }
    logd_unifi_parse_query(body, &q);
    limit = logd_json_int(body, "limit", logd_json_int(body, "pageSize", 1000));
    if (limit <= 0)
        limit = 1000;
    if (limit > LOGD_MAX_EXPORT_LIMIT)
        limit = LOGD_MAX_EXPORT_LIMIT;
    q.page = 0;
    q.page_size = limit;
    if (logd_unifi_build_where(body, where, sizeof(where), &sev_arr, &cat_arr,
                               &evt_arr, &mac_arr, &device_arr, &admin_arr,
                               &program_arr) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("query_build_failed"));
        return resp;
    }
    logd_unifi_add_time_search_where(where, sizeof(where), &q);
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir(LOGD_EXPORT_DIR, 0755);
    snprintf(id, sizeof(id), "logs-%lld-%u-%016" PRIx64 ".%s",
             (long long)logd_now_s(), (unsigned)getpid(),
             logd_hash64(body_s),
             format);
    snprintf(filename, sizeof(filename), "dreamingwrt-%s", id);
    snprintf(path, sizeof(path), "%s/%s", LOGD_EXPORT_DIR, id);
    fp = fopen(path, "w");
    if (!fp) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("export_open_failed"));
        return resp;
    }
    snprintf(sql, sizeof(sql),
             "SELECT rowid,seq,id,ts,severity,category,event,source,iface,wan_id,ip,mac,username,actor,title,detail_json,dedupe_key,state,first_seen,last_seen,count"
             "%s ORDER BY ts DESC,seq DESC LIMIT ?", where);
    st = logd_prepare(sql);
    if (!st) {
        fclose(fp);
        unlink(path);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("export_prepare_failed"));
        return resp;
    }
    b = 1;
    logd_unifi_bind_common(st, &b, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr);
    sqlite3_bind_int(st, b++, limit);
    if (!strcmp(format, "json")) {
        struct json_object *arr = json_object_new_array();

        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            logd_unifi_item_from_stmt(arr, st);
            count++;
        }
        fprintf(fp, "%s\n", json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PRETTY));
        json_object_put(arr);
    } else if (!strcmp(format, "csv")) {
        fprintf(fp, "id,seq,timestamp,severity,category,event,title,source,iface,wan_id,ip,mac,username,actor,count,detail_json\n");
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            fprintf(fp, "%s,%lld,%lld,%s,%s,%s,",
                    logd_sqlite_text(st, 2, ""),
                    (long long)sqlite3_column_int64(st, 1),
                    (long long)sqlite3_column_int64(st, 3),
                    logd_sqlite_text(st, 4, ""),
                    logd_sqlite_text(st, 5, ""),
                    logd_sqlite_text(st, 6, ""));
            logd_csv_escape(fp, logd_sqlite_text(st, 14, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 7, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 8, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 9, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 10, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 11, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 12, ""));
            fputc(',', fp);
            logd_csv_escape(fp, logd_sqlite_text(st, 13, ""));
            fprintf(fp, ",%d,", sqlite3_column_int(st, 20));
            logd_csv_escape(fp, logd_sqlite_text(st, 15, "{}"));
            fputc('\n', fp);
            count++;
        }
    } else {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            struct json_object *arr = json_object_new_array();
            struct json_object *item;
            struct json_object *cef = NULL;

            logd_unifi_item_from_stmt(arr, st);
            item = json_object_array_get_idx(arr, 0);
            if (item && json_object_object_get_ex(item, "cef", &cef) && cef)
                fprintf(fp, "%s\n", json_object_get_string(cef));
            json_object_put(arr);
            count++;
        }
    }
    sqlite3_finalize(st);
    fclose(fp);
    if (rc != SQLITE_DONE) {
        unlink(path);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("export_failed"));
        return resp;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "id", json_object_new_string(id));
    json_object_object_add(resp, "path", json_object_new_string(path));
    json_object_object_add(resp, "filename", json_object_new_string(filename));
    json_object_object_add(resp, "format", json_object_new_string(format));
    json_object_object_add(resp, "count", json_object_new_int(count));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    snprintf(download_url, sizeof(download_url), "/api/v1/logs/download?id=%s", id);
    json_object_object_add(resp, "download_url", json_object_new_string(download_url));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

static int logd_unifi_bind_event_ids(sqlite3_stmt *st, int *b, struct json_object *ids)
{
    int n;

    if (!st || !b || !ids || !json_object_is_type(ids, json_type_array))
        return 0;
    n = json_object_array_length(ids);
    for (int i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(ids, i);
        const char *id = v ? json_object_get_string(v) : "";

        sqlite3_bind_text(st, (*b)++, id ? id : "", -1, SQLITE_TRANSIENT);
    }
    return n;
}

static struct json_object *logd_unifi_state_update(struct json_object *body, int ack)
{
    const char *actor = logd_json_str(body, "actor", logd_json_str(body, "viewer", "default"));
    const char *note = logd_json_str(body, "note", "");
    int64_t until_seq = logd_json_i64(body, "until_seq",
                        logd_json_i64(body, "cursor_seq",
                        logd_json_i64(body, "seq", 0)));
    int64_t until_rowid = logd_json_i64(body, "until_rowid",
                          logd_json_i64(body, "cursor_rowid",
                          logd_json_i64(body, "rowid", 0)));
    int all = logd_json_bool(body, "all", 0) || logd_json_bool(body, "all_read", 0);
    int64_t now = logd_now_s();
    struct json_object *ids = NULL;
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st = NULL;
    char sql[4096];
    int b = 1;
    int n = 0;
    int changed = 0;
    int rc = SQLITE_DONE;

    if (!actor || !actor[0] || !logd_text_ok(actor, 128) ||
        !logd_text_ok(note, 512)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_actor_or_note"));
        return resp;
    }
    if (!json_object_object_get_ex(body, "ids", &ids) || !ids)
        json_object_object_get_ex(body, "event_ids", &ids);
    if (!ids)
        json_object_object_get_ex(body, "events", &ids);
    if (ids && !json_object_is_type(ids, json_type_array))
        ids = NULL;
    n = ids ? json_object_array_length(ids) : 0;
    if (n > LOGD_MAX_LIMIT) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("too_many_event_ids"));
        json_object_object_add(resp, "max_ids", json_object_new_int(LOGD_MAX_LIMIT));
        return resp;
    }

    if (!ack && (all || until_seq > 0 || until_rowid > 0)) {
        if (all && until_seq <= 0 && until_rowid <= 0) {
            sqlite3_stmt *max_st = logd_prepare("SELECT COALESCE(MAX(seq),0),COALESCE(MAX(rowid),0) FROM log_events");

            if (max_st) {
                if (sqlite3_step(max_st) == SQLITE_ROW) {
                    until_seq = sqlite3_column_int64(max_st, 0);
                    until_rowid = sqlite3_column_int64(max_st, 1);
                }
                sqlite3_finalize(max_st);
            }
        }
        st = logd_prepare(
            "INSERT INTO log_read_cursors(actor,cursor_rowid,cursor_seq,cursor_ts,updated_at) "
            "VALUES(?1,?2,?3,(SELECT COALESCE(MAX(ts),0) FROM log_events WHERE (?3>0 AND seq<=?3) OR (?3<=0 AND rowid<=?2)),?4) "
            "ON CONFLICT(actor) DO UPDATE SET "
            "cursor_rowid=MAX(cursor_rowid,excluded.cursor_rowid),"
            "cursor_seq=MAX(cursor_seq,excluded.cursor_seq),"
            "cursor_ts=MAX(cursor_ts,excluded.cursor_ts),"
            "updated_at=excluded.updated_at");
        if (!st) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("mark_read_prepare_failed"));
            return resp;
        }
        sqlite3_bind_text(st, 1, actor, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, until_rowid > 0 ? until_rowid : 0);
        sqlite3_bind_int64(st, 3, until_seq > 0 ? until_seq : 0);
        sqlite3_bind_int64(st, 4, now);
        rc = sqlite3_step(st);
        changed += sqlite3_changes(g_logd_db);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("mark_read_failed"));
            return resp;
        }
    }

    if (n > 0) {
        snprintf(sql, sizeof(sql),
                 ack ?
                 "INSERT OR REPLACE INTO log_event_ack(actor,event_id,rowid,seq,acked_at,note) "
                 "SELECT ?,id,rowid,seq,?,? FROM log_events WHERE id IN (" :
                 "INSERT OR REPLACE INTO log_read_events(actor,event_id,rowid,seq,read_at) "
                 "SELECT ?,id,rowid,seq,? FROM log_events WHERE id IN (");
        for (int i = 0; i < n; i++)
            strncat(sql, i ? ",?" : "?", sizeof(sql) - strlen(sql) - 1);
        strncat(sql, ")", sizeof(sql) - strlen(sql) - 1);
        st = logd_prepare(sql);
        if (!st) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string(ack ? "ack_prepare_failed" : "mark_read_prepare_failed"));
            return resp;
        }
        sqlite3_bind_text(st, b++, actor, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, b++, now);
        if (ack)
            sqlite3_bind_text(st, b++, note ? note : "", -1, SQLITE_TRANSIENT);
        logd_unifi_bind_event_ids(st, &b, ids);
        rc = sqlite3_step(st);
        changed += sqlite3_changes(g_logd_db);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string(ack ? "ack_failed" : "mark_read_failed"));
            return resp;
        }
    }

    if (ack && n <= 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("missing_event_ids"));
        return resp;
    }
    if (!ack && n <= 0 && !all && until_seq <= 0 && until_rowid <= 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("missing_mark_read_target"));
        return resp;
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "actor", json_object_new_string(actor));
    json_object_object_add(resp, ack ? "acked" : "marked_read", json_object_new_int(changed));
    json_object_object_add(resp, "changed", json_object_new_int(changed));
    if (!ack) {
        json_object_object_add(resp, "cursor_seq", json_object_new_int64(until_seq));
        json_object_object_add(resp, "cursor_rowid", json_object_new_int64(until_rowid));
    }
    json_object_object_add(resp, "ts", json_object_new_int64(now));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_unifi_mark_read(struct json_object *body)
{
    return logd_unifi_state_update(body, 0);
}

struct json_object *logd_unifi_ack(struct json_object *body)
{
    return logd_unifi_state_update(body, 1);
}

struct json_object *logd_unifi_count(struct json_object *body)
{
    struct logd_unifi_query q;
    struct json_object *sev_arr = NULL, *cat_arr = NULL, *evt_arr = NULL;
    struct json_object *mac_arr = NULL, *device_arr = NULL, *admin_arr = NULL;
    struct json_object *program_arr = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *by = json_object_new_object();
    sqlite3_stmt *st = NULL;
    char where[2048];
    char sql[4096];
    int b = 1;
    int64_t total = 0;

    logd_unifi_parse_query(body, &q);
    logd_unifi_build_where(body, where, sizeof(where), &sev_arr, &cat_arr,
                           &evt_arr, &mac_arr, &device_arr, &admin_arr,
                           &program_arr);
    logd_unifi_add_time_search_where(where, sizeof(where), &q);
    snprintf(sql, sizeof(sql), "SELECT severity,COUNT(*)%s GROUP BY severity", where);
    st = logd_prepare(sql);
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("count_prepare_failed"));
        json_object_put(by);
        return resp;
    }
    logd_unifi_bind_common(st, &b, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *sev = logd_sqlite_text(st, 0, "info");
        int64_t cnt = sqlite3_column_int64(st, 1);
        const char *uni = logd_unifi_severity(sev);
        struct json_object *old = NULL;
        int64_t prev = 0;

        if (json_object_object_get_ex(by, uni, &old) && old)
            prev = json_object_get_int64(old);
        json_object_object_add(by, uni, json_object_new_int64(prev + cnt));
        total += cnt;
    }
    sqlite3_finalize(st);
    {
        struct json_object *tmp = NULL;
        if (!json_object_object_get_ex(by, "LOW", &tmp))
        json_object_object_add(by, "LOW", json_object_new_int64(0));
        tmp = NULL;
        if (!json_object_object_get_ex(by, "MEDIUM", &tmp))
        json_object_object_add(by, "MEDIUM", json_object_new_int64(0));
        tmp = NULL;
        if (!json_object_object_get_ex(by, "HIGH", &tmp))
        json_object_object_add(by, "HIGH", json_object_new_int64(0));
        tmp = NULL;
        if (!json_object_object_get_ex(by, "VERY_HIGH", &tmp))
        json_object_object_add(by, "VERY_HIGH", json_object_new_int64(0));
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "total", json_object_new_int64(total));
    json_object_object_add(resp, "actor", json_object_new_string(q.actor ? q.actor : "default"));
    json_object_object_add(resp, "unread_total", json_object_new_int64(logd_unifi_count_state(where, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr, "unread")));
    json_object_object_add(resp, "acked_total", json_object_new_int64(logd_unifi_count_state(where, &q, sev_arr, cat_arr, evt_arr, mac_arr, device_arr, admin_arr, program_arr, "acked")));
    json_object_object_add(resp, "bySeverity", by);
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

static void logd_unifi_filter_row(struct json_object *arr, const char *id,
                                  const char *label, int64_t count)
{
    struct json_object *o;
    int i, n;

    if (!arr || !id || !id[0])
        return;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *old = json_object_array_get_idx(arr, i);
        struct json_object *old_id = NULL;
        struct json_object *old_count = NULL;

        if (!old || !json_object_object_get_ex(old, "id", &old_id) || !old_id)
            continue;
        if (strcmp(json_object_get_string(old_id), id))
            continue;
        if (json_object_object_get_ex(old, "count", &old_count) && old_count)
            count += json_object_get_int64(old_count);
        json_object_object_add(old, "count", json_object_new_int64(count));
        return;
    }
    o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "label", json_object_new_string(label && label[0] ? label : id));
    json_object_object_add(o, "count", json_object_new_int64(count));
    json_object_array_add(arr, o);
}

static void logd_unifi_device_filter_row(struct json_object *arr, const char *id,
                                         const char *name, const char *kind,
                                         const char *value, int64_t count)
{
    struct json_object *o;
    int i, n;

    if (!arr || !id || !id[0])
        return;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *old = json_object_array_get_idx(arr, i);
        struct json_object *old_id = NULL;
        struct json_object *old_count = NULL;

        if (!old || !json_object_object_get_ex(old, "id", &old_id) || !old_id)
            continue;
        if (strcmp(json_object_get_string(old_id), id))
            continue;
        if (json_object_object_get_ex(old, "count", &old_count) && old_count)
            count += json_object_get_int64(old_count);
        json_object_object_add(old, "count", json_object_new_int64(count));
        return;
    }
    o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "key", json_object_new_string(id));
    json_object_object_add(o, "mac", json_object_new_string(id));
    json_object_object_add(o, "name", json_object_new_string(name && name[0] ? name : id));
    json_object_object_add(o, "label", json_object_new_string(name && name[0] ? name : id));
    json_object_object_add(o, "model", json_object_new_string("DreamingWrt"));
    json_object_object_add(o, "type", json_object_new_string("device"));
    json_object_object_add(o, "kind", json_object_new_string(kind && kind[0] ? kind : "device"));
    if (value && value[0]) {
        json_object_object_add(o, "value", json_object_new_string(value));
        if (!strcmp(kind ? kind : "", "iface"))
            json_object_object_add(o, "interface", json_object_new_string(value));
        else if (!strcmp(kind ? kind : "", "wan"))
            json_object_object_add(o, "wan_id", json_object_new_string(value));
        else if (!strcmp(kind ? kind : "", "source"))
            json_object_object_add(o, "source", json_object_new_string(value));
    }
    json_object_object_add(o, "count", json_object_new_int64(count));
    json_object_array_add(arr, o);
}

static void logd_unifi_client_filter_row(struct json_object *arr, const char *mac,
                                         const char *ip, const char *hostname,
                                         const char *client_id, int64_t count)
{
    struct json_object *o;
    int i, n;

    if (!arr || !mac || !mac[0])
        return;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *old = json_object_array_get_idx(arr, i);
        struct json_object *old_mac = NULL;
        struct json_object *old_count = NULL;

        if (!old || !json_object_object_get_ex(old, "mac", &old_mac) || !old_mac)
            continue;
        if (strcmp(json_object_get_string(old_mac), mac))
            continue;
        if (json_object_object_get_ex(old, "count", &old_count) && old_count)
            count += json_object_get_int64(old_count);
        json_object_object_add(old, "count", json_object_new_int64(count));
        if (hostname && hostname[0])
            json_object_object_add(old, "name", json_object_new_string(hostname));
        if (ip && ip[0])
            json_object_object_add(old, "ip", json_object_new_string(ip));
        if (client_id && client_id[0])
            json_object_object_add(old, "client_id", json_object_new_string(client_id));
        return;
    }
    o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(mac));
    json_object_object_add(o, "mac", json_object_new_string(mac));
    json_object_object_add(o, "name", json_object_new_string(hostname && hostname[0] ? hostname : (ip && ip[0] ? ip : mac)));
    json_object_object_add(o, "label", json_object_new_string(hostname && hostname[0] ? hostname : (ip && ip[0] ? ip : mac)));
    if (ip && ip[0])
        json_object_object_add(o, "ip", json_object_new_string(ip));
    if (hostname && hostname[0])
        json_object_object_add(o, "hostname", json_object_new_string(hostname));
    if (client_id && client_id[0])
        json_object_object_add(o, "client_id", json_object_new_string(client_id));
    json_object_object_add(o, "count", json_object_new_int64(count));
    json_object_array_add(arr, o);
}

static void logd_unifi_filter_distinct(struct json_object *arr, const char *sql,
                                       int map_category)
{
    sqlite3_stmt *st = logd_prepare(sql);

    if (!st)
        return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *raw = logd_sqlite_text(st, 0, "");
        int64_t cnt = sqlite3_column_int64(st, 1);
        char label[128];
        const char *id = raw;

        if (!raw[0])
            continue;
        if (map_category) {
            id = logd_unifi_category(raw, "");
            logd_unifi_title_case(id, label, sizeof(label));
        } else {
            id = logd_unifi_event_key("", raw);
            logd_unifi_title_case(id, label, sizeof(label));
        }
        logd_unifi_filter_row(arr, id, label, cnt);
    }
    sqlite3_finalize(st);
}

struct json_object *logd_unifi_filter_data(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *categories = json_object_new_array();
    struct json_object *events = json_object_new_array();
    struct json_object *devices = json_object_new_array();
    struct json_object *clients = json_object_new_array();
    struct json_object *admins = json_object_new_array();
    struct json_object *programs = json_object_new_array();
    sqlite3_stmt *st = NULL;

    (void)body;
    logd_unifi_filter_row(categories, "SYSTEM", "System", 0);
    logd_unifi_filter_row(categories, "INTERNET_AND_WAN", "Internet and WAN", 0);
    logd_unifi_filter_row(categories, "CLIENT_DEVICES", "Client Devices", 0);
    logd_unifi_filter_row(categories, "ADMIN", "Admin", 0);
    logd_unifi_filter_row(categories, "SECURITY", "Security", 0);
    logd_unifi_filter_row(categories, "VPN", "VPN", 0);
    logd_unifi_filter_distinct(categories, "SELECT category,COUNT(*) FROM log_events GROUP BY category ORDER BY COUNT(*) DESC LIMIT 64", 1);
    logd_unifi_filter_row(events, "SYSTEM_LOG", "System Log", 0);
    logd_unifi_filter_row(events, "SYSTEM_RESOURCE_THRESHOLD", "System Resource Threshold", 0);
    logd_unifi_filter_row(events, "CLIENT_CONNECTED_WIRED", "Wired Client Connected", 0);
    logd_unifi_filter_row(events, "CLIENT_DISCONNECTED", "Client Disconnected", 0);
    logd_unifi_filter_row(events, "PORT_LINK_UP", "Port Link Up", 0);
    logd_unifi_filter_row(events, "PORT_LINK_DOWN", "Port Link Down", 0);
    logd_unifi_filter_row(events, "PORT_EVENT", "Port Event", 0);
    logd_unifi_filter_row(events, "WAN_EVENT", "WAN Event", 0);
    logd_unifi_filter_row(events, "PPPOE_EVENT", "PPPoE Event", 0);
    logd_unifi_filter_row(events, "ADMIN_AUTH_EVENT", "Admin Auth Event", 0);
    logd_unifi_filter_row(events, "PACKET_CAPTURE_STARTED", "Packet Capture Started", 0);
    logd_unifi_filter_row(events, "PACKET_CAPTURE_STOPPED", "Packet Capture Stopped", 0);
    logd_unifi_filter_row(events, "PACKET_CAPTURE_FINISHED", "Packet Capture Finished", 0);
    logd_unifi_filter_row(events, "PACKET_CAPTURE_DELETED", "Packet Capture Deleted", 0);
    logd_unifi_filter_row(events, "DHCP_EVENT", "DHCP Event", 0);
    logd_unifi_filter_distinct(events, "SELECT event,COUNT(*) FROM log_events GROUP BY event ORDER BY COUNT(*) DESC LIMIT 128", 0);

    st = logd_prepare("SELECT iface,COUNT(*) FROM log_events WHERE iface!='' GROUP BY iface ORDER BY COUNT(*) DESC LIMIT 64");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *iface = logd_sqlite_text(st, 0, "");
            char id[96];
            char name[128];

            snprintf(id, sizeof(id), "iface:%s", iface);
            snprintf(name, sizeof(name), "Interface %s", iface);
            logd_unifi_device_filter_row(devices, id, name, "iface", iface,
                                         sqlite3_column_int64(st, 1));
        }
        sqlite3_finalize(st);
    }

    st = logd_prepare("SELECT wan_id,COUNT(*) FROM log_events WHERE wan_id!='' GROUP BY wan_id ORDER BY COUNT(*) DESC LIMIT 64");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *wan = logd_sqlite_text(st, 0, "");
            char id[96];
            char name[128];

            snprintf(id, sizeof(id), "wan:%s", wan);
            snprintf(name, sizeof(name), "WAN %s", wan);
            logd_unifi_device_filter_row(devices, id, name, "wan", wan,
                                         sqlite3_column_int64(st, 1));
        }
        sqlite3_finalize(st);
    }

    st = logd_prepare("SELECT source,COUNT(*) FROM log_events WHERE source!='' GROUP BY source ORDER BY COUNT(*) DESC LIMIT 64");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *source = logd_sqlite_text(st, 0, "");
            char id[128];
            char name[160];

            snprintf(id, sizeof(id), "source:%s", source);
            snprintf(name, sizeof(name), "Source %s", source);
            logd_unifi_device_filter_row(devices, id, name, "source", source,
                                         sqlite3_column_int64(st, 1));
        }
        sqlite3_finalize(st);
    }

    st = logd_prepare(
        "SELECT mac,MAX(ip),MAX(json_extract(detail_json,'$.hostname')),MAX(json_extract(detail_json,'$.client_id')),COUNT(*) "
        "FROM log_events WHERE mac!='' GROUP BY mac ORDER BY COUNT(*) DESC LIMIT 128");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *mac = logd_sqlite_text(st, 0, "");
            const char *ip = logd_sqlite_text(st, 1, "");
            const char *hostname = logd_sqlite_text(st, 2, "");
            const char *client_id = logd_sqlite_text(st, 3, "");

            logd_unifi_client_filter_row(clients, mac, ip, hostname, client_id,
                                         sqlite3_column_int64(st, 4));
        }
        sqlite3_finalize(st);
    }

    st = logd_prepare(
        "SELECT json_extract(detail_json,'$.mac'),MAX(json_extract(detail_json,'$.ip')),MAX(json_extract(detail_json,'$.hostname')),MAX(json_extract(detail_json,'$.client_id')),COUNT(*) "
        "FROM log_events WHERE mac='' AND json_extract(detail_json,'$.mac') IS NOT NULL AND json_extract(detail_json,'$.mac')!='' "
        "GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 128");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *mac = logd_sqlite_text(st, 0, "");
            const char *ip = logd_sqlite_text(st, 1, "");
            const char *hostname = logd_sqlite_text(st, 2, "");
            const char *client_id = logd_sqlite_text(st, 3, "");

            logd_unifi_client_filter_row(clients, mac, ip, hostname, client_id,
                                         sqlite3_column_int64(st, 4));
        }
        sqlite3_finalize(st);
    }

    st = logd_prepare(
        "SELECT COALESCE(NULLIF(username,''),NULLIF(actor,''),NULLIF(json_extract(detail_json,'$.username'),''),NULLIF(json_extract(detail_json,'$.user'),''),NULLIF(json_extract(detail_json,'$.actor'),'')),COUNT(*) "
        "FROM log_events WHERE username!='' OR actor!='' OR json_extract(detail_json,'$.username')!='' OR json_extract(detail_json,'$.user')!='' OR json_extract(detail_json,'$.actor')!='' "
        "GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 64");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            const char *id = logd_sqlite_text(st, 0, "");
            json_object_object_add(o, "id", json_object_new_string(id));
            json_object_object_add(o, "name", json_object_new_string(id));
            json_object_object_add(o, "count", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_array_add(admins, o);
        }
        sqlite3_finalize(st);
    }

    st = logd_prepare(
        "SELECT CASE lower(rtrim(COALESCE(NULLIF(json_extract(detail_json,'$.program'),''),"
        "NULLIF(json_extract(detail_json,'$.module'),''),source),'[0123456789]()')) "
        "WHEN 'kernel_log' THEN 'kernel' WHEN 'system_log' THEN 'system' "
        "ELSE lower(rtrim(COALESCE(NULLIF(json_extract(detail_json,'$.program'),''),"
        "NULLIF(json_extract(detail_json,'$.module'),''),source),'[0123456789]()')) END," 
        "MAX(json_extract(detail_json,'$.program_label'))," 
        "MAX(json_extract(detail_json,'$.package')),COUNT(*) "
        "FROM log_events WHERE COALESCE(NULLIF(json_extract(detail_json,'$.program'),''),"
        "NULLIF(json_extract(detail_json,'$.module'),''),source)!='' "
        "GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 256");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            const char *id = logd_sqlite_text(st, 0, "");
            const char *label = logd_sqlite_text(st, 1, "");
            const char *package = logd_sqlite_text(st, 2, "");

            if (!id[0]) {
                json_object_put(o);
                continue;
            }
            json_object_object_add(o, "id", json_object_new_string(id));
            json_object_object_add(o, "name", json_object_new_string(label[0] ? label : id));
            json_object_object_add(o, "label", json_object_new_string(label[0] ? label : id));
            json_object_object_add(o, "package", json_object_new_string(package));
            json_object_object_add(o, "count", json_object_new_int64(sqlite3_column_int64(st, 3)));
            json_object_array_add(programs, o);
        }
        sqlite3_finalize(st);
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "categories", categories);
    json_object_object_add(resp, "events", events);
    json_object_object_add(resp, "deviceFilters", devices);
    json_object_object_add(resp, "clientFilters", clients);
    json_object_object_add(resp, "adminFilters", admins);
    json_object_object_add(resp, "programs", programs);
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_clear_events(struct json_object *body)
{
    const char *id = logd_json_str(body, "id", "");
    const char *category = logd_json_str(body, "category", "");
    int64_t before = logd_json_i64(body, "before", 0);
    int confirm = logd_json_bool(body, "confirm", 0);
    sqlite3_stmt *st = NULL;
    int changed = 0;
    int rc;
    struct json_object *resp = json_object_new_object();

    if (id[0]) {
        st = logd_prepare("DELETE FROM log_events WHERE id=?1");
        if (st) sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    } else if (before > 0 && category[0]) {
        st = logd_prepare("DELETE FROM log_events WHERE category=?1 AND ts<?2");
        if (st) {
            sqlite3_bind_text(st, 1, category, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, before);
        }
    } else if (before > 0) {
        st = logd_prepare("DELETE FROM log_events WHERE ts<?1");
        if (st) sqlite3_bind_int64(st, 1, before);
    } else if (confirm) {
        st = logd_prepare("DELETE FROM log_events");
    } else {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("missing_clear_filter"));
        return resp;
    }
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("clear_prepare_failed"));
        return resp;
    }
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("clear_failed"));
        return resp;
    }
    changed = sqlite3_changes(g_logd_db);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "cleared", json_object_new_int(changed));
    return resp;
}
