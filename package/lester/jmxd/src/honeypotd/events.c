// SPDX-License-Identifier: GPL-2.0-or-later
#include "honeypotd_internal.h"

static void hp_sockaddr_text(const struct sockaddr_storage *address, char *host,
                             size_t host_size, uint16_t *port)
{
    const void *raw = NULL;

    host[0] = '\0';
    *port = 0;
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)address;

        raw = &sin->sin_addr;
        *port = ntohs(sin->sin_port);
    } else if (address->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)address;

        raw = &sin6->sin6_addr;
        *port = ntohs(sin6->sin6_port);
    }
    if (raw)
        (void)inet_ntop(address->ss_family, raw, host, host_size);
}

static void hp_event_enqueue(struct hp_event_queue *queue, struct json_object *event)
{
    struct json_object *envelope;
    const char *serialized;
    size_t tail;
    size_t length;

    if (!event)
        return;
    envelope = json_object_new_object();
    if (!envelope) {
        queue->dropped++;
        return;
    }
    json_object_object_add(envelope, "payload", json_object_get(event));
    serialized = json_object_to_json_string_ext(envelope, JSON_C_TO_STRING_PLAIN);
    length = serialized ? strlen(serialized) : 0;
    if (length == 0 || length >= HP_EVENT_JSON_LIMIT || queue->count >= HP_MAX_EVENTS) {
        queue->dropped++;
        json_object_put(envelope);
        return;
    }
    tail = (queue->head + queue->count) % HP_MAX_EVENTS;
    memcpy(queue->items[tail], serialized, length + 1);
    queue->count++;
    json_object_put(envelope);
}

static struct json_object *hp_event_base(const struct hp_runtime *runtime,
                                         const struct hp_listener *listener,
                                         const char *source_ip, uint16_t source_port,
                                         const char *stage, struct json_object *payload)
{
    struct json_object *event = json_object_new_object();

    if (!event)
        return NULL;
    json_object_object_add(event, "schema_version", json_object_new_int(1));
    json_object_object_add(event, "event_type", json_object_new_string("honeypot_hit"));
    json_object_object_add(event, "ingest_token",
                           json_object_new_string(runtime->ingest_token));
    json_object_object_add(event, "timestamp_ms", json_object_new_int64((int64_t)hp_realtime_ms()));
    json_object_object_add(event, "source_ip", json_object_new_string(source_ip ? source_ip : ""));
    json_object_object_add(event, "source_port", json_object_new_int(source_port));
    json_object_object_add(event, "destination_ip", json_object_new_string(listener->address));
    json_object_object_add(event, "destination_port", json_object_new_int(listener->external_port));
    json_object_object_add(event, "listen_port", json_object_new_int(listener->listen_port));
    json_object_object_add(event, "honeypot_id", json_object_new_string(listener->honeypot_id));
    json_object_object_add(event, "transport", json_object_new_string(
        listener->transport == HP_TRANSPORT_UDP ? "udp" : "tcp"));
    json_object_object_add(event, "service", json_object_new_string(hp_service_name(listener->service)));
    json_object_object_add(event, "profile", json_object_new_string(listener->profile));
    json_object_object_add(event, "stage", json_object_new_string(stage ? stage : "connect"));
    json_object_object_add(event, "payload_encoding", json_object_new_string("json"));
    json_object_object_add(event, "payload", payload ? json_object_get(payload) : json_object_new_object());
    if (listener->ifname[0])
        json_object_object_add(event, "interface", json_object_new_string(listener->ifname));
    return event;
}

void hp_emit_session_event(struct hp_state *state, const struct hp_session *session,
                           const char *stage, struct json_object *payload)
{
    const struct hp_listener *listener = &state->runtime.listeners[session->listener_index];
    struct json_object *event = hp_event_base(&state->runtime, listener, session->source_ip,
                                              session->source_port, stage, payload);

    hp_event_enqueue(&state->events, event);
    if (event)
        json_object_put(event);
}

void hp_emit_datagram_event(struct hp_state *state, const struct hp_listener *listener,
                            const struct sockaddr_storage *source, socklen_t source_len,
                            const char *stage, struct json_object *payload)
{
    struct json_object *event;
    char source_ip[INET6_ADDRSTRLEN];
    uint16_t source_port;

    (void)source_len;
    hp_sockaddr_text(source, source_ip, sizeof(source_ip), &source_port);
    event = hp_event_base(&state->runtime, listener, source_ip, source_port, stage, payload);
    hp_event_enqueue(&state->events, event);
    if (event)
        json_object_put(event);
}

int hp_events_init(struct hp_event_queue *queue)
{
    memset(queue, 0, sizeof(*queue));
    queue->ubus = ubus_connect(NULL);
    return queue->ubus ? 0 : -1;
}

void hp_events_close(struct hp_event_queue *queue)
{
    if (queue->ubus)
        ubus_free(queue->ubus);
    memset(queue, 0, sizeof(*queue));
}

static int hp_events_reconnect(struct hp_event_queue *queue)
{
    if (queue->ubus)
        ubus_free(queue->ubus);
    queue->ubus = ubus_connect(NULL);
    return queue->ubus ? 0 : -1;
}

struct hp_event_reply {
    bool received;
    bool accepted;
};

static void hp_event_reply_cb(struct ubus_request *request, int type,
                              struct blob_attr *message)
{
    struct hp_event_reply *reply = request ? request->priv : NULL;
    char *text;
    struct json_object *response;
    struct json_object *ok = NULL, *stored = NULL;

    (void)type;
    if (!reply || !message)
        return;
    text = blobmsg_format_json(message, true);
    response = text ? json_tokener_parse(text) : NULL;
    free(text);
    reply->received = true;
    if (response && json_object_object_get_ex(response, "ok", &ok) &&
        json_object_get_boolean(ok) &&
        json_object_object_get_ex(response, "stored", &stored) &&
        json_object_get_boolean(stored))
        reply->accepted = true;
    if (response)
        json_object_put(response);
}

void hp_events_flush(struct hp_event_queue *queue, uint64_t now_ms)
{
    struct blob_buf blob = { 0 };
    uint32_t object_id;
    struct hp_event_reply reply = { 0 };
    int rc;

    if (queue->count == 0 || now_ms < queue->next_retry_ms)
        return;
    if (!queue->ubus && hp_events_reconnect(queue) != 0) {
        queue->next_retry_ms = now_ms + 1000;
        return;
    }
    rc = ubus_lookup_id(queue->ubus, HP_AEGIS_UBUS_OBJECT, &object_id);
    if (rc != UBUS_STATUS_OK) {
        hp_events_reconnect(queue);
        queue->next_retry_ms = now_ms + 1000;
        return;
    }
    blob_buf_init(&blob, 0);
    if (!blobmsg_add_json_from_string(&blob, queue->items[queue->head])) {
        blob_buf_free(&blob);
        queue->head = (queue->head + 1) % HP_MAX_EVENTS;
        queue->count--;
        queue->dropped++;
        return;
    }
    rc = ubus_invoke(queue->ubus, object_id, HP_AEGIS_UBUS_METHOD, blob.head,
                     hp_event_reply_cb, &reply, HP_UBUS_TIMEOUT_MS);
    blob_buf_free(&blob);
    if (rc == UBUS_STATUS_OK && reply.received && reply.accepted) {
        queue->items[queue->head][0] = '\0';
        queue->head = (queue->head + 1) % HP_MAX_EVENTS;
        queue->count--;
        queue->next_retry_ms = 0;
        return;
    }
    if (rc == UBUS_STATUS_OK && reply.received && !reply.accepted) {
        queue->items[queue->head][0] = '\0';
        queue->head = (queue->head + 1) % HP_MAX_EVENTS;
        queue->count--;
        queue->dropped++;
        queue->next_retry_ms = 0;
        return;
    }
    if (rc == UBUS_STATUS_CONNECTION_FAILED)
        hp_events_reconnect(queue);
    queue->next_retry_ms = now_ms + 1000;
}
