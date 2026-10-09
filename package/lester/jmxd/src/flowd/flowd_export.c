// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NetFlow v9 / IPFIX encoders over one shared flow representation.
 *
 * The two wire formats are close relatives: both describe records with
 * templates and both pack template and data sets into a datagram. What differs:
 *
 *   header        v9 carries sysUpTime + count of records; IPFIX carries a byte
 *                 length and no record count
 *   sequence      v9 counts exported packets; IPFIX counts exported data records
 *   timestamps    v9 uses milliseconds since device boot (sysUpTime base);
 *                 IPFIX uses absolute milliseconds since the epoch
 *   template set  v9 flowset id 0; IPFIX set id 2
 *
 * Everything else -- field identifiers, field order, record layout -- is shared,
 * which is why one field table below serves both.
 */
/*
 * getaddrinfo / addrinfo are POSIX, not ISO C, so under -std=c11 glibc hides
 * them unless a feature macro asks for them. Declared here rather than pushed
 * into every caller's CFLAGS so this file compiles the same way everywhere.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strcasecmp: declared here, not in <string.h>, under glibc */
#include <sys/socket.h>
#include <unistd.h>

#include "flowd_export.h"

/* IANA information element identifiers, common to NetFlow v9 and IPFIX. */
#define IE_OCTET_DELTA_COUNT 1
#define IE_PACKET_DELTA_COUNT 2
#define IE_PROTOCOL_IDENTIFIER 4
#define IE_IP_CLASS_OF_SERVICE 5
#define IE_TCP_CONTROL_BITS 6
#define IE_SOURCE_TRANSPORT_PORT 7
#define IE_SOURCE_IPV4_ADDRESS 8
#define IE_INGRESS_INTERFACE 10
#define IE_DESTINATION_TRANSPORT_PORT 11
#define IE_DESTINATION_IPV4_ADDRESS 12
#define IE_EGRESS_INTERFACE 14
#define IE_FLOW_END_SYS_UP_TIME 21
#define IE_FLOW_START_SYS_UP_TIME 22
#define IE_SOURCE_IPV6_ADDRESS 27
#define IE_DESTINATION_IPV6_ADDRESS 28
#define IE_FLOW_END_MILLISECONDS 153
#define IE_FLOW_START_MILLISECONDS 152

struct flowd_export_field {
    uint16_t id;
    uint16_t length;
};

/*
 * Field layout, in wire order.
 *
 * The counters are 8 octets rather than 4: on a gigabit WAN a 32-bit octet
 * counter wraps inside a single long-lived flow, and a wrapped counter is worse
 * than a missing one because the collector cannot tell.
 *
 * The time fields are the one place the protocols genuinely disagree, so they
 * are chosen per protocol below instead of being hardcoded here.
 */
static const struct flowd_export_field FIELDS_V4[] = {
    { IE_SOURCE_IPV4_ADDRESS, 4 },
    { IE_DESTINATION_IPV4_ADDRESS, 4 },
    { IE_SOURCE_TRANSPORT_PORT, 2 },
    { IE_DESTINATION_TRANSPORT_PORT, 2 },
    { IE_PROTOCOL_IDENTIFIER, 1 },
    { IE_IP_CLASS_OF_SERVICE, 1 },
    { IE_TCP_CONTROL_BITS, 1 },
    { IE_INGRESS_INTERFACE, 4 },
    { IE_EGRESS_INTERFACE, 4 },
    { IE_OCTET_DELTA_COUNT, 8 },
    { IE_PACKET_DELTA_COUNT, 8 },
};

static const struct flowd_export_field FIELDS_V6[] = {
    { IE_SOURCE_IPV6_ADDRESS, 16 },
    { IE_DESTINATION_IPV6_ADDRESS, 16 },
    { IE_SOURCE_TRANSPORT_PORT, 2 },
    { IE_DESTINATION_TRANSPORT_PORT, 2 },
    { IE_PROTOCOL_IDENTIFIER, 1 },
    { IE_IP_CLASS_OF_SERVICE, 1 },
    { IE_TCP_CONTROL_BITS, 1 },
    { IE_INGRESS_INTERFACE, 4 },
    { IE_EGRESS_INTERFACE, 4 },
    { IE_OCTET_DELTA_COUNT, 8 },
    { IE_PACKET_DELTA_COUNT, 8 },
};

#define FIELD_COUNT_V4 (sizeof(FIELDS_V4) / sizeof(FIELDS_V4[0]))
#define FIELD_COUNT_V6 (sizeof(FIELDS_V6) / sizeof(FIELDS_V6[0]))

/* Time field ids and widths, chosen by protocol. IPFIX has absolute
 * millisecond elements; v9 only has the sysUpTime-relative pair. */
static uint16_t time_start_id(int protocol)
{
    return protocol == FLOWD_EXPORT_PROTOCOL_IPFIX ?
        IE_FLOW_START_MILLISECONDS : IE_FLOW_START_SYS_UP_TIME;
}

static uint16_t time_end_id(int protocol)
{
    return protocol == FLOWD_EXPORT_PROTOCOL_IPFIX ?
        IE_FLOW_END_MILLISECONDS : IE_FLOW_END_SYS_UP_TIME;
}

static uint16_t time_field_length(int protocol)
{
    return protocol == FLOWD_EXPORT_PROTOCOL_IPFIX ? 8 : 4;
}

int flowd_export_protocol_from_string(const char *name)
{
    if (!name || !*name)
        return FLOWD_EXPORT_PROTOCOL_IPFIX;
    if (!strcasecmp(name, "ipfix") || !strcasecmp(name, "v10") ||
        !strcasecmp(name, "10"))
        return FLOWD_EXPORT_PROTOCOL_IPFIX;
    if (!strcasecmp(name, "netflow9") || !strcasecmp(name, "netflow_v9") ||
        !strcasecmp(name, "v9") || !strcasecmp(name, "9"))
        return FLOWD_EXPORT_PROTOCOL_NETFLOW9;
    return -1;
}

const char *flowd_export_protocol_name(int protocol)
{
    switch (protocol) {
    case FLOWD_EXPORT_PROTOCOL_IPFIX: return "ipfix";
    case FLOWD_EXPORT_PROTOCOL_NETFLOW9: return "netflow9";
    default: return "unknown";
    }
}

/* ── little serialisation helpers, all big-endian on the wire ── */

struct writer {
    uint8_t *base;
    size_t len;
    size_t offset;
    int overflow;
};

static void put_bytes(struct writer *w, const void *src, size_t n)
{
    if (w->overflow || w->offset + n > w->len) {
        w->overflow = 1;
        return;
    }
    memcpy(w->base + w->offset, src, n);
    w->offset += n;
}

static void put_u8(struct writer *w, uint8_t v)
{
    put_bytes(w, &v, 1);
}

static void put_u16(struct writer *w, uint16_t v)
{
    uint16_t be = htons(v);
    put_bytes(w, &be, 2);
}

static void put_u32(struct writer *w, uint32_t v)
{
    uint32_t be = htonl(v);
    put_bytes(w, &be, 4);
}

static void put_u64(struct writer *w, uint64_t v)
{
    uint8_t be[8];

    for (int i = 7; i >= 0; i--) {
        be[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    put_bytes(w, be, 8);
}

static const struct flowd_export_field *fields_for(int family, size_t *count)
{
    if (family == AF_INET6) {
        *count = FIELD_COUNT_V6;
        return FIELDS_V6;
    }
    *count = FIELD_COUNT_V4;
    return FIELDS_V4;
}

static uint16_t template_id_for(int family)
{
    return family == AF_INET6 ? FLOWD_EXPORT_TEMPLATE_ID_V6 :
                                FLOWD_EXPORT_TEMPLATE_ID_V4;
}

static size_t record_length(int protocol, int family)
{
    const struct flowd_export_field *fields;
    size_t count, total = 0;

    fields = fields_for(family, &count);
    for (size_t i = 0; i < count; i++)
        total += fields[i].length;
    /* start + end time */
    total += 2u * time_field_length(protocol);
    return total;
}

/*
 * Template set.
 *
 * Identical body for both protocols; only the enclosing set id differs (IPFIX
 * set 2, NetFlow v9 flowset 0). That is exactly the "same data model, different
 * envelope" property that makes supporting both cheap.
 */
static int encode_template_set(int protocol, int family, struct writer *w)
{
    const struct flowd_export_field *fields;
    size_t count;
    size_t set_start = w->offset;
    uint16_t set_id = protocol == FLOWD_EXPORT_PROTOCOL_IPFIX ?
        FLOWD_EXPORT_IPFIX_SET_TEMPLATE : FLOWD_EXPORT_NETFLOW9_FLOWSET_TEMPLATE;
    uint16_t field_count;
    size_t set_len;

    fields = fields_for(family, &count);
    field_count = (uint16_t)(count + 2); /* + start/end time */

    put_u16(w, set_id);
    put_u16(w, 0);                       /* length, patched below */
    put_u16(w, template_id_for(family));
    put_u16(w, field_count);
    for (size_t i = 0; i < count; i++) {
        put_u16(w, fields[i].id);
        put_u16(w, fields[i].length);
    }
    put_u16(w, time_start_id(protocol));
    put_u16(w, time_field_length(protocol));
    put_u16(w, time_end_id(protocol));
    put_u16(w, time_field_length(protocol));

    if (w->overflow)
        return -1;
    set_len = w->offset - set_start;
    w->base[set_start + 2] = (uint8_t)((set_len >> 8) & 0xff);
    w->base[set_start + 3] = (uint8_t)(set_len & 0xff);
    return (int)set_len;
}

int flowd_export_encode_template(int protocol, int family, uint8_t *out,
                                 size_t out_len)
{
    struct writer w = { out, out_len, 0, 0 };

    if (!out || (protocol != FLOWD_EXPORT_PROTOCOL_IPFIX &&
                 protocol != FLOWD_EXPORT_PROTOCOL_NETFLOW9))
        return -1;
    if (encode_template_set(protocol, family, &w) < 0)
        return -1;
    return (int)w.offset;
}

static void encode_one_record(int protocol, const struct flowd_export_flow *flow,
                              uint64_t boot_time_ms, struct writer *w)
{
    int v6 = flow->family == AF_INET6;

    put_bytes(w, flow->src_addr, v6 ? 16 : 4);
    put_bytes(w, flow->dst_addr, v6 ? 16 : 4);
    put_u16(w, flow->src_port);
    put_u16(w, flow->dst_port);
    put_u8(w, flow->protocol);
    put_u8(w, flow->tos);
    put_u8(w, flow->tcp_flags);
    put_u32(w, flow->input_if);
    put_u32(w, flow->output_if);
    put_u64(w, flow->bytes);
    put_u64(w, flow->packets);
    if (protocol == FLOWD_EXPORT_PROTOCOL_IPFIX) {
        /* Absolute milliseconds; no dependence on the exporter's uptime. */
        put_u64(w, flow->first_switched_ms);
        put_u64(w, flow->last_switched_ms);
    } else {
        /*
         * v9 timestamps are relative to sysUpTime, so they are only meaningful
         * next to the header's uptime field. Clamp instead of wrapping: a flow
         * that began before the recorded boot time would otherwise encode as a
         * huge positive offset and read as a flow from the future.
         */
        uint64_t start = flow->first_switched_ms > boot_time_ms ?
            flow->first_switched_ms - boot_time_ms : 0;
        uint64_t end = flow->last_switched_ms > boot_time_ms ?
            flow->last_switched_ms - boot_time_ms : 0;
        put_u32(w, (uint32_t)start);
        put_u32(w, (uint32_t)end);
    }
}

size_t flowd_export_flows_per_datagram(int protocol, int family,
                                       int include_template)
{
    size_t header = protocol == FLOWD_EXPORT_PROTOCOL_IPFIX ? 16 : 20;
    size_t budget = FLOWD_EXPORT_MAX_DATAGRAM;
    size_t per_record = record_length(protocol, family);
    size_t set_header = 4;

    if (budget <= header + set_header)
        return 0;
    budget -= header + set_header;
    if (include_template) {
        uint8_t scratch[512];
        int template_len = flowd_export_encode_template(protocol, family,
                                                       scratch, sizeof(scratch));
        if (template_len < 0 || (size_t)template_len >= budget)
            return 0;
        budget -= (size_t)template_len;
    }
    return per_record ? budget / per_record : 0;
}

int flowd_export_encode_datagram(const struct flowd_export_config *config,
                                 struct flowd_export_state *state,
                                 const struct flowd_export_flow *flows,
                                 size_t count, int include_template,
                                 uint64_t now_ms, uint8_t *out, size_t out_len)
{
    struct writer w = { out, out_len, 0, 0 };
    size_t header_start, data_start, data_len;
    int protocol, family;
    uint16_t record_count;

    if (!config || !state || !out || !flows || count == 0)
        return -1;
    protocol = config->protocol;
    if (protocol != FLOWD_EXPORT_PROTOCOL_IPFIX &&
        protocol != FLOWD_EXPORT_PROTOCOL_NETFLOW9)
        return -1;
    family = flows[0].family;
    /* One template per datagram, so mixing families would encode records
     * against the wrong layout. The caller batches by family. */
    for (size_t i = 1; i < count; i++)
        if (flows[i].family != family)
            return -1;

    header_start = w.offset;
    put_u16(&w, (uint16_t)protocol);
    if (protocol == FLOWD_EXPORT_PROTOCOL_IPFIX) {
        put_u16(&w, 0);                        /* total length, patched below */
        put_u32(&w, (uint32_t)(now_ms / 1000));/* export time, seconds */
        put_u32(&w, state->sequence);           /* counts data records */
        put_u32(&w, config->observation_domain);
    } else {
        record_count = (uint16_t)(count + (include_template ? 1 : 0));
        put_u16(&w, record_count);
        put_u32(&w, (uint32_t)(now_ms - state->boot_time_ms)); /* sysUpTime ms */
        put_u32(&w, (uint32_t)(now_ms / 1000));
        put_u32(&w, state->sequence);           /* counts exported packets */
        put_u32(&w, config->observation_domain);
    }

    if (include_template && encode_template_set(protocol, family, &w) < 0)
        return -1;

    data_start = w.offset;
    put_u16(&w, template_id_for(family));
    put_u16(&w, 0);                             /* set length, patched below */
    for (size_t i = 0; i < count; i++)
        encode_one_record(protocol, &flows[i], state->boot_time_ms, &w);
    if (w.overflow)
        return -1;
    data_len = w.offset - data_start;
    out[data_start + 2] = (uint8_t)((data_len >> 8) & 0xff);
    out[data_start + 3] = (uint8_t)(data_len & 0xff);

    if (protocol == FLOWD_EXPORT_PROTOCOL_IPFIX) {
        size_t total = w.offset - header_start;
        out[header_start + 2] = (uint8_t)((total >> 8) & 0xff);
        out[header_start + 3] = (uint8_t)(total & 0xff);
        /* IPFIX sequence counts data records, not datagrams. */
        state->sequence += (uint32_t)count;
    } else {
        /* NetFlow v9 sequence counts exported packets. */
        state->sequence += 1;
    }
    state->records_sent += (uint32_t)count;
    if (include_template)
        state->last_template_ms = now_ms;
    return (int)w.offset;
}

/* ── Transport ──────────────────────────────────────────────────────────── */

int flowd_export_sink_open(struct flowd_export_sink *sink, const char *host,
                           uint16_t port)
{
    struct addrinfo hints, *results = NULL, *entry;
    char service[8];
    int rc;

    if (!sink || !host || !host[0] || port == 0)
        return -1;
    memset(sink, 0, sizeof(*sink));
    sink->fd = -1;
    snprintf(service, sizeof(service), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;   /* a v6 collector is as valid as a v4 one */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    rc = getaddrinfo(host, service, &hints, &results);
    if (rc != 0 || !results) {
        snprintf(sink->last_error, sizeof(sink->last_error),
                 "resolve_failed:%s", gai_strerror(rc));
        return -1;
    }
    for (entry = results; entry; entry = entry->ai_next) {
        /*
         * SOCK_CLOEXEC is a Linux extension and absent on some hosts the test
         * harness builds on, so the flag is applied separately via FD_CLOEXEC.
         */
        int fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (fd < 0)
            continue;
        fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
        if (connect(fd, entry->ai_addr, entry->ai_addrlen) == 0) {
            sink->fd = fd;
            sink->family = entry->ai_family;
            break;
        }
        close(fd);
    }
    freeaddrinfo(results);
    if (sink->fd < 0) {
        snprintf(sink->last_error, sizeof(sink->last_error), "connect_failed:%s",
                 strerror(errno));
        return -1;
    }
    sink->last_error[0] = '\0';
    return 0;
}

void flowd_export_sink_close(struct flowd_export_sink *sink)
{
    if (!sink || sink->fd < 0)
        return;
    close(sink->fd);
    sink->fd = -1;
}

int flowd_export_sink_send(struct flowd_export_sink *sink,
                           const uint8_t *datagram, size_t len)
{
    ssize_t sent;

    if (!sink || sink->fd < 0 || !datagram || len == 0)
        return -1;
    do {
        sent = send(sink->fd, datagram, len, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
        sink->send_errors++;
        snprintf(sink->last_error, sizeof(sink->last_error), "send_failed:%s",
                 strerror(errno));
        return -1;
    }
    sink->datagrams_sent++;
    sink->bytes_sent += (uint64_t)sent;
    sink->last_error[0] = '\0';
    return (int)sent;
}

int flowd_export_emit(const struct flowd_export_config *config,
                      struct flowd_export_state *state,
                      struct flowd_export_sink *sink,
                      const struct flowd_export_flow *flows, size_t count,
                      uint64_t now_ms)
{
    uint8_t datagram[FLOWD_EXPORT_MAX_DATAGRAM];
    size_t offset = 0;
    int datagrams = 0;

    if (!config || !state || !sink || !flows || count == 0)
        return -1;
    if (!config->enabled)
        return 0;

    while (offset < count) {
        /*
         * The template is resent on a timer, and always on the first datagram
         * after start. UDP has no delivery guarantee, so a collector that missed
         * the original template would otherwise discard every record until the
         * exporter restarted.
         */
        int include_template =
            state->last_template_ms == 0 ||
            (config->template_refresh_s &&
             now_ms - state->last_template_ms >=
                 (uint64_t)config->template_refresh_s * 1000u);
        size_t capacity = flowd_export_flows_per_datagram(config->protocol,
                                                         flows[offset].family,
                                                         include_template);
        size_t batch = count - offset;
        int len;

        if (capacity == 0)
            return -1;
        if (batch > capacity)
            batch = capacity;
        /* One template per datagram, so a batch may not cross families. */
        for (size_t i = 1; i < batch; i++)
            if (flows[offset + i].family != flows[offset].family) {
                batch = i;
                break;
            }
        len = flowd_export_encode_datagram(config, state, flows + offset, batch,
                                           include_template, now_ms, datagram,
                                           sizeof(datagram));
        if (len <= 0)
            return -1;
        if (flowd_export_sink_send(sink, datagram, (size_t)len) < 0)
            return -1;
        datagrams++;
        offset += batch;
    }
    return datagrams;
}
