// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Flow collection logic: conntrack parsing, counter bookkeeping, timeout
 * decisions.
 *
 * Split from flowd_export_runtime.c on purpose. These functions touch no
 * sqlite, ubus or uloop state, which lets them be compiled and driven directly
 * by a test against real /proc/net/nf_conntrack text. They are also where a
 * mistake yields plausible-but-wrong export data rather than a visible failure,
 * so being able to exercise them in isolation is worth the extra file.
 */
/*
 * strtok_r is POSIX, not ISO C: under a strict -std=c11 compile glibc hides it
 * and the call silently degrades to an implicit int-returning declaration.
 * Declared before any header is pulled in, which is where the macro has to be.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "flowd_export.h"
#include "flowd_export_runtime.h"

/*
 * A conntrack line carries two tuples (original and reply) and two counter
 * pairs. Only the original direction is exported as the flow key; the reply
 * direction is the same conversation seen backwards, and emitting both would
 * double-count every connection. Reply bytes are added to the flow's volume
 * because the collector's notion of a flow's traffic includes what came back.
 */
int flowd_export_parse_conntrack_line(const char *line,
                                      struct flowd_export_tracked *out)
{
    char work[FLOWD_EXPORT_CT_LINE_MAX];
    char *save = NULL;
    char *tok;
    const char *family_name;
    const char *proto_name;
    int have_src = 0, have_dst = 0, have_sport = 0, have_dport = 0;
    int packet_fields = 0, byte_fields = 0;
    uint64_t packets = 0, bytes_sent = 0, bytes_received = 0;

    if (!line || !out)
        return 0;
    if (strlen(line) >= sizeof(work))
        return 0;
    memset(out, 0, sizeof(*out));
    snprintf(work, sizeof(work), "%s", line);

    family_name = strtok_r(work, " \t\r\n", &save);
    if (!family_name)
        return 0;
    if (!strcmp(family_name, "ipv4"))
        out->family = AF_INET;
    else if (!strcmp(family_name, "ipv6"))
        out->family = AF_INET6;
    else
        return 0;

    if (!strtok_r(NULL, " \t\r\n", &save))      /* l3 protocol number */
        return 0;
    proto_name = strtok_r(NULL, " \t\r\n", &save);
    if (!proto_name)
        return 0;
    /*
     * The IP protocol number follows the name. Taking the name would mean
     * maintaining a table; the number is what the encoders need anyway.
     */
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (!tok)
        return 0;
    out->protocol = (uint8_t)atoi(tok);

    while ((tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        if (!strncmp(tok, "src=", 4)) {
            if (!have_src) {
                if (inet_pton(out->family, tok + 4, out->src_addr) != 1)
                    return 0;
                have_src = 1;
            }
        } else if (!strncmp(tok, "dst=", 4)) {
            if (!have_dst) {
                if (inet_pton(out->family, tok + 4, out->dst_addr) != 1)
                    return 0;
                have_dst = 1;
            }
        } else if (!strncmp(tok, "sport=", 6)) {
            if (!have_sport) {
                out->src_port = (uint16_t)atoi(tok + 6);
                have_sport = 1;
            }
        } else if (!strncmp(tok, "dport=", 6)) {
            if (!have_dport) {
                out->dst_port = (uint16_t)atoi(tok + 6);
                have_dport = 1;
            }
        } else if (!strncmp(tok, "packets=", 8)) {
            /* Both directions count toward the flow's volume. */
            if (packet_fields < 2) {
                packets += strtoull(tok + 8, NULL, 10);
                packet_fields++;
            }
        } else if (!strncmp(tok, "bytes=", 6)) {
            if (byte_fields < 2) {
                uint64_t bytes = strtoull(tok + 6, NULL, 10);
                if (byte_fields == 0)
                    bytes_sent = bytes;
                else
                    bytes_received = bytes;
                byte_fields++;
            }
        }
    }
    if (!have_src || !have_dst)
        return 0;
    /*
     * ICMP and other portless protocols have no ports; that is a valid flow, and
     * the encoders write zero. Requiring ports here would silently drop all
     * ICMP from the export.
     */
    out->packets_total = packets;
    out->bytes_sent = bytes_sent;
    out->bytes_received = bytes_received;
    out->bytes_total = bytes_sent + bytes_received;
    return 1;
}

/* ── tracked-flow table ─────────────────────────────────────────────────── */

int flowd_export_same_flow(const struct flowd_export_tracked *a,
                                  const struct flowd_export_tracked *b)
{
    size_t addr_len = (a->family == AF_INET6) ? 16 : 4;

    return a->family == b->family && a->protocol == b->protocol &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           !memcmp(a->src_addr, b->src_addr, addr_len) &&
           !memcmp(a->dst_addr, b->dst_addr, addr_len);
}

int flowd_export_flow_due(const struct flowd_export_tracked *flow,
                          const struct flowd_export_config *config,
                          uint64_t now_ms)
{
    uint64_t pending_bytes;

    if (!flow || !config || flow->in_use != FLOWD_EXPORT_SLOT_LIVE)
        return 0;
    pending_bytes = flow->bytes_total - flow->bytes_exported;
    /* Nothing new to say. An empty record would cost a datagram and tell the
     * collector only that the flow still exists. */
    if (!pending_bytes && flow->packets_total == flow->packets_exported)
        return 0;
    /* Active timeout: long-lived flow reported while still running. */
    if (now_ms - flow->last_export_ms >=
        (uint64_t)config->active_timeout_s * 1000ULL)
        return 1;
    /* Inactive timeout: counters stopped moving, so flush what is left. */
    if (now_ms - flow->last_seen_ms >=
        (uint64_t)config->inactive_timeout_s * 1000ULL)
        return 1;
    return 0;
}

int flowd_export_apply_sample(struct flowd_export_tracked *slot,
                             const struct flowd_export_tracked *sample,
                             uint64_t now_ms)
{
    int reset = 0;

    if (!slot || !sample)
        return 0;
    /*
     * Counters below what we already exported mean this is a different
     * connection reusing the tuple. Rebase instead of subtracting, or the
     * unsigned delta wraps to something in the exabytes.
     */
    if (sample->bytes_total < slot->bytes_exported ||
        sample->packets_total < slot->packets_exported) {
        slot->bytes_exported = 0;
        slot->packets_exported = 0;
        slot->first_seen_ms = now_ms;
        slot->last_export_ms = now_ms;
        reset = 1;
    }
    /* "Active" means the counters moved; a flow merely still present in the
     * table is idle, and the inactive timeout should be allowed to retire it. */
    if (sample->bytes_total != slot->bytes_total ||
        sample->packets_total != slot->packets_total)
        slot->last_seen_ms = now_ms;
    slot->bytes_total = sample->bytes_total;
    slot->packets_total = sample->packets_total;
    slot->last_poll_ms = now_ms;
    return reset;
}

void flowd_export_fill_record(const struct flowd_export_tracked *flow,
                              struct flowd_export_flow *out,
                              uint64_t now_ms)
{
    memset(out, 0, sizeof(*out));
    out->family = flow->family;
    memcpy(out->src_addr, flow->src_addr, sizeof(out->src_addr));
    memcpy(out->dst_addr, flow->dst_addr, sizeof(out->dst_addr));
    out->src_port = flow->src_port;
    out->dst_port = flow->dst_port;
    out->protocol = flow->protocol;
    out->bytes = flow->bytes_total - flow->bytes_exported;
    out->packets = flow->packets_total - flow->packets_exported;
    /*
     * The interval this record covers, not the flow's whole life: start at the
     * previous export, end at the last observed activity.
     */
    out->first_switched_ms = flow->last_export_ms;
    out->last_switched_ms = flow->last_seen_ms ? flow->last_seen_ms : now_ms;
    if (out->last_switched_ms < out->first_switched_ms)
        out->last_switched_ms = out->first_switched_ms;
}

/*
 * FNV-1a over the flow key. Cheap, and good enough scatter for a table indexed
 * by conntrack tuples; this is a lookup index, not a security-relevant hash.
 */
uint32_t flowd_export_flow_hash(const struct flowd_export_tracked *flow)
{
    size_t addr_len = (flow->family == AF_INET6) ? 16 : 4;
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < addr_len; i++) {
        h = (h ^ flow->src_addr[i]) * 16777619u;
        h = (h ^ flow->dst_addr[i]) * 16777619u;
    }
    h = (h ^ (uint32_t)(flow->src_port & 0xff)) * 16777619u;
    h = (h ^ (uint32_t)(flow->src_port >> 8)) * 16777619u;
    h = (h ^ (uint32_t)(flow->dst_port & 0xff)) * 16777619u;
    h = (h ^ (uint32_t)(flow->dst_port >> 8)) * 16777619u;
    h = (h ^ flow->protocol) * 16777619u;
    h = (h ^ (uint32_t)flow->family) * 16777619u;
    return h;
}
