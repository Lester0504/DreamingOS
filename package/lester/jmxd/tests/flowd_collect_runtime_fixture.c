// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exercise flow collection: the conntrack parser, the counter-delta bookkeeping
 * and the active/inactive timeout decision.
 *
 * These are the three places where a mistake produces plausible-looking but
 * wrong export data rather than an obvious failure -- a swapped tuple, a
 * cumulative total sent as an interval delta, or a flow that never reaches the
 * collector because it is never considered due. The input lines are copied
 * verbatim from /proc/net/nf_conntrack on the live router (192.168.30.1), so the
 * parser is checked against real kernel output instead of a guessed format.
 *
 * Optionally writes the datagram for a collected flow to a file or UDP port so
 * an independent decoder can confirm the collected values survive encoding:
 *   fixture --emit <ipfix|netflow9> <path>
 *   fixture --emit-udp <ipfix|netflow9> <port>
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "flowd_export.h"
#include "flowd_export_runtime.h"

static int failures;

static void fail(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "FAIL ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    failures++;
}

/* Real lines from 192.168.30.1. Kept exactly as the kernel printed them. */
static const char *LINE_TCP_V4 =
    "ipv4     2 tcp      6 117 TIME_WAIT src=1.28.111.142 dst=162.159.8.38 "
    "sport=57776 dport=443 packets=9 bytes=1280 src=162.159.8.38 "
    "dst=1.28.111.142 sport=443 dport=57776 packets=10 bytes=4553 [ASSURED] "
    "mark=65536001 zone=0 use=2";
static const char *LINE_UDP_V4 =
    "ipv4     2 udp      17 15 src=192.168.30.2 dst=110.43.87.239 sport=50101 "
    "dport=8053 packets=3 bytes=300 src=110.43.87.239 dst=10.132.61.23 "
    "sport=8053 dport=50101 packets=2 bytes=200 mark=65536002 zone=0 use=2";
static const char *LINE_ICMP_V4 =
    "ipv4     2 icmp     1 9 src=192.168.30.2 dst=116.130.221.170 type=8 code=0 "
    "id=49663 packets=4 bytes=400 src=116.130.221.170 dst=1.28.111.142 type=0 "
    "code=0 id=49663 packets=4 bytes=400 mark=0 zone=0 use=2";
static const char *LINE_TCP_V6 =
    "ipv6     10 tcp      6 73 SYN_SENT "
    "src=2409:8a10:0001:c0d9:b1e9:3e86:b54a:2ed8 "
    "dst=2404:6800:400a:1007:0000:0000:0000:0066 sport=34503 dport=80 "
    "packets=1 bytes=60 [UNREPLIED] "
    "src=2404:6800:400a:1007:0000:0000:0000:0066 "
    "dst=2409:8a10:0001:c0d9:b1e9:3e86:b54a:2ed8 sport=80 dport=34503 "
    "packets=0 bytes=0 mark=0 zone=0 use=2";
static const char *LINE_ICMP_V6 =
    "ipv6     10 icmpv6   58 21 src=fd00:0030:0001:0000:e86a:9aff:fe62:3d96 "
    "dst=2408:871a:10d0:5008:0000:0000:0000:00fb type=128 code=0 id=15871 "
    "packets=2 bytes=208 src=2408:871a:10d0:5008:0000:0000:0000:00fb "
    "dst=2409:8a10:001f:f970:0000:0000:0000:0001 type=129 code=0 id=15871 "
    "packets=2 bytes=208 mark=0 zone=0 use=2";

static void expect_addr(const char *label, int family,
                        const unsigned char *got, const char *want)
{
    char text[INET6_ADDRSTRLEN] = {0};

    if (!inet_ntop(family, got, text, sizeof(text))) {
        fail("%s: address could not be formatted", label);
        return;
    }
    if (strcmp(text, want))
        fail("%s: got %s, expected %s", label, text, want);
}

static void test_parses_real_conntrack_lines(void)
{
    struct flowd_export_tracked f;

    if (!flowd_export_parse_conntrack_line(LINE_TCP_V4, &f)) {
        fail("a real TCP/IPv4 conntrack line was rejected");
    } else {
        if (f.family != AF_INET)
            fail("tcp/v4 family %d", f.family);
        if (f.protocol != 6)
            fail("tcp/v4 protocol %u, expected 6", f.protocol);
        expect_addr("tcp/v4 src", AF_INET, f.src_addr, "1.28.111.142");
        expect_addr("tcp/v4 dst", AF_INET, f.dst_addr, "162.159.8.38");
        if (f.src_port != 57776 || f.dst_port != 443)
            fail("tcp/v4 ports %u->%u, expected 57776->443",
                 f.src_port, f.dst_port);
        /* Both directions contribute: 1280 + 4553, 9 + 10. */
        if (f.bytes_total != 5833)
            fail("tcp/v4 bytes %llu, expected 5833 (both directions)",
                 (unsigned long long)f.bytes_total);
        if (f.packets_total != 19)
            fail("tcp/v4 packets %llu, expected 19",
                 (unsigned long long)f.packets_total);
    }

    if (!flowd_export_parse_conntrack_line(LINE_UDP_V4, &f))
        fail("a real UDP/IPv4 line was rejected");
    else if (f.protocol != 17 || f.src_port != 50101 || f.dst_port != 8053)
        fail("udp/v4 parsed as proto=%u %u->%u", f.protocol, f.src_port,
             f.dst_port);

    /*
     * ICMP has no ports. Requiring them would silently drop every ping from the
     * export while looking like the parser simply saw nothing.
     */
    if (!flowd_export_parse_conntrack_line(LINE_ICMP_V4, &f))
        fail("a portless ICMP line was rejected; ICMP would never be exported");
    else {
        if (f.protocol != 1)
            fail("icmp/v4 protocol %u, expected 1", f.protocol);
        if (f.src_port || f.dst_port)
            fail("icmp/v4 invented ports %u->%u", f.src_port, f.dst_port);
        if (f.bytes_total != 800)
            fail("icmp/v4 bytes %llu, expected 800",
                 (unsigned long long)f.bytes_total);
    }

    if (!flowd_export_parse_conntrack_line(LINE_TCP_V6, &f))
        fail("a real TCP/IPv6 line was rejected");
    else {
        if (f.family != AF_INET6)
            fail("tcp/v6 family %d", f.family);
        expect_addr("tcp/v6 src", AF_INET6, f.src_addr,
                    "2409:8a10:1:c0d9:b1e9:3e86:b54a:2ed8");
        if (f.src_port != 34503 || f.dst_port != 80)
            fail("tcp/v6 ports %u->%u", f.src_port, f.dst_port);
    }

    if (!flowd_export_parse_conntrack_line(LINE_ICMP_V6, &f))
        fail("a real ICMPv6 line was rejected");
    else if (f.protocol != 58)
        fail("icmpv6 protocol %u, expected 58", f.protocol);

    /* Garbage and headers must be skipped, not half-parsed. */
    if (flowd_export_parse_conntrack_line("", &f))
        fail("an empty line parsed as a flow");
    if (flowd_export_parse_conntrack_line("ipv4 2 tcp\n", &f))
        fail("a truncated line parsed as a flow");
    if (flowd_export_parse_conntrack_line("unknown 99 tcp 6 1 src=1.1.1.1 "
                                          "dst=2.2.2.2 sport=1 dport=2\n", &f))
        fail("an unknown address family parsed as a flow");
}

static void sample(struct flowd_export_tracked *out, uint64_t bytes,
                   uint64_t packets)
{
    if (!flowd_export_parse_conntrack_line(LINE_TCP_V4, out)) {
        fail("fixture setup: base line did not parse");
        return;
    }
    out->bytes_total = bytes;
    out->packets_total = packets;
}

static void test_exports_deltas_not_totals(void)
{
    struct flowd_export_tracked slot;
    struct flowd_export_tracked next;
    struct flowd_export_flow record;

    sample(&slot, 1000, 10);
    slot.in_use = 1;
    slot.first_seen_ms = 1000;
    slot.last_seen_ms = 1000;
    slot.last_export_ms = 1000;
    slot.last_poll_ms = 1000;

    /* First export covers everything seen so far. */
    flowd_export_fill_record(&slot, &record, 2000);
    if (record.bytes != 1000 || record.packets != 10)
        fail("first record %llu bytes / %llu packets, expected 1000/10",
             (unsigned long long)record.bytes,
             (unsigned long long)record.packets);
    slot.bytes_exported = slot.bytes_total;
    slot.packets_exported = slot.packets_total;
    slot.last_export_ms = 2000;

    /* The flow keeps running; the second record must carry only the increment.
     * Sending 2500 again would double-count the first 1000 at the collector. */
    sample(&next, 2500, 25);
    flowd_export_apply_sample(&slot, &next, 3000);
    flowd_export_fill_record(&slot, &record, 3000);
    if (record.bytes != 1500 || record.packets != 15)
        fail("second record %llu bytes / %llu packets, expected the 1500/15 "
             "delta rather than the cumulative total",
             (unsigned long long)record.bytes,
             (unsigned long long)record.packets);
    /* The interval must start where the previous record ended. */
    if (record.first_switched_ms != 2000)
        fail("record interval starts at %llu, expected the previous export at 2000",
             (unsigned long long)record.first_switched_ms);
    if (record.last_switched_ms < record.first_switched_ms)
        fail("record ends before it starts");

    slot.bytes_exported = slot.bytes_total;
    slot.packets_exported = slot.packets_total;

    /*
     * Tuple reuse: a new connection lands on the same five-tuple and conntrack
     * restarts from a small count. Subtracting would underflow to ~18 exabytes,
     * which a collector cannot distinguish from real traffic.
     */
    sample(&next, 60, 1);
    if (!flowd_export_apply_sample(&slot, &next, 4000))
        fail("a backwards counter was not reported as a reset");
    flowd_export_fill_record(&slot, &record, 4000);
    if (record.bytes != 60 || record.packets != 1)
        fail("after tuple reuse the record is %llu bytes / %llu packets, "
             "expected the new connection's 60/1",
             (unsigned long long)record.bytes,
             (unsigned long long)record.packets);

    /* An idle flow must not keep refreshing last_seen: the inactive timeout is
     * what retires it, and a rolling timestamp would keep it alive forever. */
    slot.bytes_exported = slot.bytes_total;
    slot.packets_exported = slot.packets_total;
    slot.last_seen_ms = 4000;
    sample(&next, 60, 1);
    flowd_export_apply_sample(&slot, &next, 9000);
    if (slot.last_seen_ms != 4000)
        fail("an unchanged counter refreshed last_seen to %llu; the inactive "
             "timeout would never fire",
             (unsigned long long)slot.last_seen_ms);
}

static void test_timeouts_decide_when_to_send(void)
{
    struct flowd_export_config config;
    struct flowd_export_tracked slot;

    memset(&config, 0, sizeof(config));
    config.active_timeout_s = 60;
    config.inactive_timeout_s = 15;

    sample(&slot, 1000, 10);
    slot.in_use = 1;
    slot.last_export_ms = 100000;
    slot.last_seen_ms = 100000;

    /* Fresh, active, nothing overdue. */
    if (flowd_export_flow_due(&slot, &config, 105000))
        fail("a flow exported 5s ago and still active was already due");

    /* Active timeout: a long-lived flow is reported while it runs, so a
     * multi-hour download is visible before it finishes. */
    if (!flowd_export_flow_due(&slot, &config, 161000))
        fail("the active timeout did not fire after 61s");

    /* Inactive timeout: counters stopped, flush the remainder. */
    slot.last_export_ms = 100000;
    slot.last_seen_ms = 100000;
    if (!flowd_export_flow_due(&slot, &config, 116000))
        fail("the inactive timeout did not fire 16s after the last activity");

    /* Nothing new to report: an empty record costs a datagram and tells the
     * collector only that the flow still exists. */
    slot.bytes_exported = slot.bytes_total;
    slot.packets_exported = slot.packets_total;
    if (flowd_export_flow_due(&slot, &config, 900000))
        fail("a fully-exported flow was still due, which would emit empty records");
}

/*
 * The tracked table is a hash table with linear probing, so a retired flow must
 * leave a tombstone rather than an empty slot. An empty slot would cut any probe
 * chain running through it: a flow stored later in that chain would stop being
 * found, get inserted a second time with bytes_exported = 0, and re-export the
 * connection's entire cumulative total as a single delta. This drives the real
 * hash and comparison functions over deliberately colliding keys.
 */
#define SLOTS (FLOWD_EXPORT_MAX_TRACKED * 2)
static struct flowd_export_tracked probe_table[SLOTS];

static struct flowd_export_tracked *probe_lookup(
    const struct flowd_export_tracked *seen, int insert)
{
    struct flowd_export_tracked *freeslot = NULL;
    size_t mask = SLOTS - 1;
    size_t start = flowd_export_flow_hash(seen) & mask;
    size_t probe;

    for (probe = 0; probe < SLOTS; probe++) {
        struct flowd_export_tracked *slot = &probe_table[(start + probe) & mask];

        if (slot->in_use == FLOWD_EXPORT_SLOT_EMPTY) {
            if (!freeslot)
                freeslot = slot;
            break;
        }
        if (slot->in_use == FLOWD_EXPORT_SLOT_TOMBSTONE) {
            if (!freeslot)
                freeslot = slot;
            continue;
        }
        if (flowd_export_same_flow(slot, seen))
            return slot;
    }
    if (!insert || !freeslot)
        return NULL;
    memcpy(freeslot, seen, sizeof(*freeslot));
    freeslot->in_use = FLOWD_EXPORT_SLOT_LIVE;
    return freeslot;
}

static void test_retiring_a_flow_keeps_the_probe_chain_intact(void)
{
    struct flowd_export_tracked a, b, c;
    struct flowd_export_tracked *slot_a, *slot_b, *slot_c;
    size_t mask = SLOTS - 1;
    size_t i, found = 0;

    memset(probe_table, 0, sizeof(probe_table));

    /*
     * Build three flows that hash to the same bucket, so B and C sit behind A in
     * one probe chain. Searching the key space is how we get a genuine collision
     * rather than assuming one.
     */
    if (!flowd_export_parse_conntrack_line(LINE_TCP_V4, &a)) {
        fail("collision setup: base line did not parse");
        return;
    }
    a.src_port = 1000;
    for (i = 1001; i < 65000 && found < 2; i++) {
        struct flowd_export_tracked candidate = a;

        candidate.src_port = (uint16_t)i;
        if ((flowd_export_flow_hash(&candidate) & mask) ==
            (flowd_export_flow_hash(&a) & mask)) {
            if (found == 0)
                b = candidate;
            else
                c = candidate;
            found++;
        }
    }
    if (found < 2) {
        fail("could not construct two colliding flow keys; the chain test did "
             "not run");
        return;
    }

    slot_a = probe_lookup(&a, 1);
    slot_b = probe_lookup(&b, 1);
    slot_c = probe_lookup(&c, 1);
    if (!slot_a || !slot_b || !slot_c) {
        fail("collision setup: a colliding flow could not be inserted");
        return;
    }
    /* Give C a history, so a duplicate insert would be visible as a huge delta. */
    slot_c->bytes_total = 500000;
    slot_c->bytes_exported = 500000;
    slot_c->packets_total = 400;
    slot_c->packets_exported = 400;

    /* Retire the flow in the middle of the chain, the way the poll loop does. */
    memset(slot_b, 0, sizeof(*slot_b));
    slot_b->in_use = FLOWD_EXPORT_SLOT_TOMBSTONE;

    if (probe_lookup(&c, 0) != slot_c)
        fail("after retiring a flow mid-chain, the flow behind it is no longer "
             "found; it would be tracked twice and re-export its whole total");
    if (probe_lookup(&a, 0) != slot_a)
        fail("retiring a flow lost the flow ahead of it in the chain");

    /* A tombstone must be reusable, or the table leaks capacity. */
    if (probe_lookup(&b, 1) != slot_b)
        fail("a tombstoned slot was not reused for the same key");
}

/* Encode a collected flow so an independent decoder can check the values that
 * came out of collection, not just ones a fixture typed in by hand. */
static int emit_collected(const char *protocol_name, const char *target,
                          int over_udp)
{
    struct flowd_export_config config;
    struct flowd_export_state state;
    struct flowd_export_tracked slot;
    struct flowd_export_flow record;
    uint8_t datagram[FLOWD_EXPORT_MAX_DATAGRAM];
    int len;

    memset(&config, 0, sizeof(config));
    memset(&state, 0, sizeof(state));
    config.protocol = flowd_export_protocol_from_string(protocol_name);
    config.observation_domain = 42;
    config.sampling_rate = 1;
    state.boot_time_ms = 1000;

    if (!flowd_export_parse_conntrack_line(LINE_TCP_V4, &slot)) {
        fprintf(stderr, "collection failed on a real conntrack line\n");
        return 1;
    }
    slot.in_use = 1;
    slot.first_seen_ms = 2000;
    slot.last_seen_ms = 5000;
    slot.last_export_ms = 2000;
    flowd_export_fill_record(&slot, &record, 5000);

    len = flowd_export_encode_datagram(&config, &state, &record, 1, 1, 5000,
                                       datagram, sizeof(datagram));
    if (len <= 0) {
        fprintf(stderr, "encoding a collected flow failed\n");
        return 1;
    }
    if (over_udp) {
        struct flowd_export_sink sink;

        if (flowd_export_sink_open(&sink, "127.0.0.1",
                                   (uint16_t)atoi(target)) != 0) {
            fprintf(stderr, "sink open failed: %s\n", sink.last_error);
            return 1;
        }
        if (flowd_export_sink_send(&sink, datagram, (size_t)len) < 0) {
            fprintf(stderr, "sink send failed: %s\n", sink.last_error);
            flowd_export_sink_close(&sink);
            return 1;
        }
        flowd_export_sink_close(&sink);
    } else {
        FILE *fp = fopen(target, "wb");

        if (!fp) {
            fprintf(stderr, "cannot write %s\n", target);
            return 1;
        }
        fwrite(datagram, 1, (size_t)len, fp);
        fclose(fp);
    }
    printf("emitted %d bytes for the collected flow\n", len);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--emit"))
        return emit_collected(argv[2], argv[3], 0);
    if (argc == 4 && !strcmp(argv[1], "--emit-udp"))
        return emit_collected(argv[2], argv[3], 1);

    test_parses_real_conntrack_lines();
    test_exports_deltas_not_totals();
    test_timeouts_decide_when_to_send();
    test_retiring_a_flow_keeps_the_probe_chain_intact();

    if (failures) {
        fprintf(stderr, "%d collection assertion(s) failed\n", failures);
        return 1;
    }
    printf("ok: real conntrack lines parse, exports carry deltas not totals, "
           "and the active/inactive timeouts decide when to send\n");
    return 0;
}
