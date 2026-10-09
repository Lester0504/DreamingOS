// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NetFlow v9 / IPFIX export.
 *
 * One internal flow representation, two interchangeable encoders. The two
 * protocols share a data model -- a template describes the field layout, and
 * records are encoded against it -- and differ in the header, the set/flowset
 * identifiers and a few field semantics. So the split here is at the encoder
 * only; collection, aggregation, timeout logic and configuration are common.
 *
 * IPFIX is the default (RFC 7011, the standardised successor); NetFlow v9
 * (RFC 3954) is the compatibility option.
 */
#ifndef DREAMINGWRT_FLOWD_EXPORT_H
#define DREAMINGWRT_FLOWD_EXPORT_H

#include <stddef.h>
#include <stdint.h>

#define FLOWD_EXPORT_PROTOCOL_IPFIX 10
#define FLOWD_EXPORT_PROTOCOL_NETFLOW9 9

/* Template/set identifiers. IPFIX reserves 0-255 for set IDs and requires data
 * set IDs >= 256; NetFlow v9 uses flowset ID 0 for templates and >= 256 for
 * data. Keeping the data template IDs identical across both keeps one field
 * table valid for either encoder. */
#define FLOWD_EXPORT_TEMPLATE_ID_V4 256
#define FLOWD_EXPORT_TEMPLATE_ID_V6 257
#define FLOWD_EXPORT_IPFIX_SET_TEMPLATE 2
#define FLOWD_EXPORT_NETFLOW9_FLOWSET_TEMPLATE 0

/* An exported datagram must fit one UDP packet without IP fragmentation. */
#define FLOWD_EXPORT_MAX_DATAGRAM 1400

/*
 * Internal flow record: protocol-independent, filled from the conntrack/flowd
 * aggregation. IPv6 is carried in the same struct and selected by `family`,
 * because a v6-only export would leave our own multi-WAN v6 traffic invisible.
 */
struct flowd_export_flow {
    int family;                 /* AF_INET or AF_INET6 */
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;           /* IP protocol number */
    uint8_t tos;
    uint8_t tcp_flags;
    uint32_t input_if;
    uint32_t output_if;
    uint64_t bytes;
    uint64_t packets;
    /* Milliseconds since the epoch; both encoders derive their own time base
     * from these rather than each keeping a separate clock. */
    uint64_t first_switched_ms;
    uint64_t last_switched_ms;
};

struct flowd_export_config {
    int enabled;
    int protocol;               /* FLOWD_EXPORT_PROTOCOL_* */
    char collector_host[256];
    uint16_t collector_port;
    uint32_t active_timeout_s;
    uint32_t inactive_timeout_s;
    uint32_t template_refresh_s;
    uint32_t sampling_rate;     /* 1 = every flow */
    uint32_t observation_domain;
};

/*
 * Encoder state. `sequence` counts differently per protocol -- NetFlow v9
 * counts exported packets, IPFIX counts exported data records -- which is a
 * real semantic difference and is handled inside the encoders rather than by
 * the caller.
 */
struct flowd_export_state {
    uint32_t sequence;
    uint32_t records_sent;
    uint64_t boot_time_ms;
    uint64_t last_template_ms;
};

int flowd_export_protocol_from_string(const char *name);
const char *flowd_export_protocol_name(int protocol);

/*
 * Encode a template set for `family` into `out`.
 * Returns the byte count written, or -1 when the buffer is too small.
 */
int flowd_export_encode_template(int protocol, int family, uint8_t *out,
                                 size_t out_len);

/*
 * Encode one datagram carrying `count` flows, all of the same family.
 * Returns bytes written, or -1 on a buffer or argument error.
 */
int flowd_export_encode_datagram(const struct flowd_export_config *config,
                                 struct flowd_export_state *state,
                                 const struct flowd_export_flow *flows,
                                 size_t count, int include_template,
                                 uint64_t now_ms, uint8_t *out, size_t out_len);

/* How many flows of `family` fit in one datagram alongside the header. */
size_t flowd_export_flows_per_datagram(int protocol, int family,
                                       int include_template);

/* ── Transport ────────────────────────────────────────────────────────────
 * A connected UDP socket per collector. Connected rather than sendto() per
 * datagram so the route and source address are resolved once and a dead
 * collector surfaces as ECONNREFUSED on send instead of silent loss.
 */
struct flowd_export_sink {
    int fd;
    int family;                 /* resolved collector family */
    uint64_t datagrams_sent;
    uint64_t bytes_sent;
    uint64_t send_errors;
    char last_error[128];
};

int flowd_export_sink_open(struct flowd_export_sink *sink,
                           const char *host, uint16_t port);
void flowd_export_sink_close(struct flowd_export_sink *sink);
/* Returns bytes sent, or -1 with sink->last_error set. */
int flowd_export_sink_send(struct flowd_export_sink *sink,
                           const uint8_t *datagram, size_t len);

/*
 * Export a batch end to end: template refresh decision, encoding, and send.
 * Flows must share one family. Returns the number of datagrams sent, or -1.
 */
int flowd_export_emit(const struct flowd_export_config *config,
                      struct flowd_export_state *state,
                      struct flowd_export_sink *sink,
                      const struct flowd_export_flow *flows, size_t count,
                      uint64_t now_ms);

#endif
