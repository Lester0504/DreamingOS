// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Emit real NetFlow v9 / IPFIX datagrams from the production encoders.
 *
 * Writes raw datagram bytes to the file named in argv[2] so an independent
 * decoder can parse them. The acceptance bar for this feature is a real
 * collector reading the records, not "UDP packets were sent", so the fixture
 * deliberately does no validation of its own beyond encoder return values.
 *
 * usage: fixture <ipfix|netflow9> <output-path> [v4|v6|mixed]
 *        fixture <ipfix|netflow9> --udp <port> [v4|v6]
 *
 * In --udp mode the datagrams go over the real transport (a connected UDP
 * socket) to 127.0.0.1:<port>, so the send path is exercised and not just the
 * encoder.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "flowd_export.h"

static void fill_v4(struct flowd_export_flow *flow, const char *src,
                    const char *dst, uint16_t sport, uint16_t dport,
                    uint64_t bytes, uint64_t packets)
{
    memset(flow, 0, sizeof(*flow));
    flow->family = AF_INET;
    inet_pton(AF_INET, src, flow->src_addr);
    inet_pton(AF_INET, dst, flow->dst_addr);
    flow->src_port = sport;
    flow->dst_port = dport;
    flow->protocol = 6;         /* TCP */
    flow->tos = 0;
    flow->tcp_flags = 0x18;     /* PSH|ACK */
    flow->input_if = 2;
    flow->output_if = 3;
    flow->bytes = bytes;
    flow->packets = packets;
    flow->first_switched_ms = 1750000000000ULL;
    flow->last_switched_ms = 1750000004500ULL;
}

static void fill_v6(struct flowd_export_flow *flow, const char *src,
                    const char *dst, uint16_t sport, uint16_t dport,
                    uint64_t bytes, uint64_t packets)
{
    memset(flow, 0, sizeof(*flow));
    flow->family = AF_INET6;
    inet_pton(AF_INET6, src, flow->src_addr);
    inet_pton(AF_INET6, dst, flow->dst_addr);
    flow->src_port = sport;
    flow->dst_port = dport;
    flow->protocol = 17;        /* UDP */
    flow->tcp_flags = 0;
    flow->input_if = 4;
    flow->output_if = 5;
    flow->bytes = bytes;
    flow->packets = packets;
    flow->first_switched_ms = 1750000001000ULL;
    flow->last_switched_ms = 1750000003000ULL;
}

int main(int argc, char **argv)
{
    struct flowd_export_config config;
    struct flowd_export_state state;
    struct flowd_export_flow flows[4];
    uint8_t datagram[FLOWD_EXPORT_MAX_DATAGRAM];
    const char *family_mode = argc > 3 ? argv[3] : "v4";
    FILE *out;
    int protocol, len;
    size_t count;
    uint64_t now_ms = 1750000005000ULL;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <ipfix|netflow9> <output> [v4|v6|mixed]\n",
                argv[0]);
        return 2;
    }
    protocol = flowd_export_protocol_from_string(argv[1]);
    if (protocol < 0) {
        fprintf(stderr, "unknown protocol %s\n", argv[1]);
        return 2;
    }

    memset(&config, 0, sizeof(config));
    config.enabled = 1;
    config.protocol = protocol;
    snprintf(config.collector_host, sizeof(config.collector_host), "127.0.0.1");
    config.collector_port = 2055;
    config.active_timeout_s = 60;
    config.inactive_timeout_s = 15;
    config.template_refresh_s = 600;
    config.sampling_rate = 1;
    config.observation_domain = 42;

    memset(&state, 0, sizeof(state));
    state.boot_time_ms = 1749999000000ULL;

    if (!strcmp(family_mode, "v6")) {
        fill_v6(&flows[0], "2001:db8::1", "2001:db8::2", 5353, 443, 8192, 12);
        fill_v6(&flows[1], "fd00::a", "fd00::b", 1234, 53, 512, 4);
        count = 2;
    } else if (!strcmp(family_mode, "mixed")) {
        /* Must be rejected: one datagram carries one template. */
        fill_v4(&flows[0], "192.168.30.10", "1.1.1.1", 51000, 443, 1000, 5);
        fill_v6(&flows[1], "2001:db8::1", "2001:db8::2", 5353, 443, 8192, 12);
        count = 2;
    } else {
        fill_v4(&flows[0], "192.168.30.10", "1.1.1.1", 51000, 443, 15000, 20);
        fill_v4(&flows[1], "192.168.30.11", "8.8.8.8", 51001, 53, 300, 3);
        count = 2;
    }

    /*
     * --udp exercises the real transport: resolve, connected socket, send.
     * A collector-side decode of what actually arrives on the wire is the
     * acceptance gate, and it cannot be met by encoding into a buffer.
     */
    if (!strcmp(argv[2], "--udp")) {
        struct flowd_export_sink sink;
        int port = argc > 3 ? atoi(argv[3]) : 0;
        int sent;

        family_mode = argc > 4 ? argv[4] : "v4";
        if (!strcmp(family_mode, "v6")) {
            fill_v6(&flows[0], "2001:db8::1", "2001:db8::2", 5353, 443, 8192, 12);
            fill_v6(&flows[1], "fd00::a", "fd00::b", 1234, 53, 512, 4);
        } else {
            fill_v4(&flows[0], "192.168.30.10", "1.1.1.1", 51000, 443, 15000, 20);
            fill_v4(&flows[1], "192.168.30.11", "8.8.8.8", 51001, 53, 300, 3);
        }
        count = 2;
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "invalid port\n");
            return 2;
        }
        config.collector_port = (uint16_t)port;
        if (flowd_export_sink_open(&sink, "127.0.0.1", (uint16_t)port) != 0) {
            fprintf(stderr, "FAIL sink open: %s\n", sink.last_error);
            return 1;
        }
        sent = flowd_export_emit(&config, &state, &sink, flows, count, now_ms);
        if (sent <= 0) {
            fprintf(stderr, "FAIL emit returned %d (%s)\n", sent,
                    sink.last_error);
            flowd_export_sink_close(&sink);
            return 1;
        }
        printf("protocol=%s datagrams=%d bytes=%llu errors=%llu\n",
               flowd_export_protocol_name(protocol), sent,
               (unsigned long long)sink.bytes_sent,
               (unsigned long long)sink.send_errors);
        flowd_export_sink_close(&sink);
        return 0;
    }

    len = flowd_export_encode_datagram(&config, &state, flows, count, 1,
                                       now_ms, datagram, sizeof(datagram));
    if (!strcmp(family_mode, "mixed")) {
        /* A mixed batch must be refused rather than silently mis-encoded. */
        if (len >= 0) {
            fprintf(stderr, "FAIL mixed-family batch was encoded\n");
            return 1;
        }
        printf("ok: mixed-family batch rejected\n");
        return 0;
    }
    if (len <= 0) {
        fprintf(stderr, "FAIL encode returned %d\n", len);
        return 1;
    }

    out = fopen(argv[2], "wb");
    if (!out) {
        fprintf(stderr, "cannot open %s\n", argv[2]);
        return 2;
    }
    fwrite(datagram, 1, (size_t)len, out);
    fclose(out);

    printf("protocol=%s bytes=%d flows=%zu sequence_after=%u records=%u "
           "capacity=%zu\n",
           flowd_export_protocol_name(protocol), len, count, state.sequence,
           state.records_sent,
           flowd_export_flows_per_datagram(protocol, flows[0].family, 1));
    return 0;
}
