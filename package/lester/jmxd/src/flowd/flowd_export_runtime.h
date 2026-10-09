// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Flow collection and periodic export scheduling.
 *
 * The encoders in flowd_export.h turn flow records into datagrams; this is the
 * part that produces the records and decides when to send them. Flows come from
 * the kernel conntrack table rather than an independent capture path: the
 * handoff specifies reuse, and on an embedded router a second accounting path
 * would spend CPU on data the kernel already has.
 */
#ifndef DREAMINGWRT_FLOWD_EXPORT_RUNTIME_H
#define DREAMINGWRT_FLOWD_EXPORT_RUNTIME_H

#include <stdint.h>

#include "flowd_export.h"

/* Poll cadence. The inactive timeout is the tightest deadline we must honour,
 * and its floor is 5s, so a 5s tick can always meet it without the timer
 * resolution itself becoming the dominant error. */
#define FLOWD_EXPORT_TICK_MS 5000

/*
 * Tracked-flow ceiling. A busy router can hold tens of thousands of conntrack
 * entries; each tracked flow costs a fixed-size slot here, so the table is
 * bounded rather than growing with whatever the WAN happens to be doing. When
 * full, new flows are counted as dropped instead of evicting an established
 * flow whose counters have not been exported yet -- losing a flow we already
 * promised to report is worse than not starting to track a new one.
 */
#define FLOWD_EXPORT_MAX_TRACKED 8192

/*
 * Slots allocated, as opposed to flows admitted. Twice the flow ceiling keeps
 * the load factor at or below 0.5, which bounds the probe walk: measured on a
 * full 8192-flow table, allowing occupancy to reach 1.0 pushed the average probe
 * count to ~78 and the poll to 8.5ms, while a half-full table settles near 2
 * probes. The extra ~900KB buys predictable per-tick cost on the path that runs
 * every 5 seconds.
 */
#define FLOWD_EXPORT_TABLE_SLOTS (FLOWD_EXPORT_MAX_TRACKED * 2)

/* The probe index is a bitmask, so the slot count must be a power of two. */
_Static_assert((FLOWD_EXPORT_TABLE_SLOTS &
                (FLOWD_EXPORT_TABLE_SLOTS - 1)) == 0,
               "FLOWD_EXPORT_TABLE_SLOTS must be a power of two");

/* A conntrack line longer than this is skipped rather than truncated: a partial
 * parse would silently produce a wrong five-tuple. */
#define FLOWD_EXPORT_CT_LINE_MAX 4096

/*
 * Slot states. A retired flow becomes a tombstone rather than empty so it does
 * not cut the probe chain that runs through it; see flowd_export_track().
 */
#define FLOWD_EXPORT_SLOT_EMPTY 0
#define FLOWD_EXPORT_SLOT_LIVE 1
#define FLOWD_EXPORT_SLOT_TOMBSTONE 2

/*
 * One tracked flow. `bytes`/`packets` are cumulative counters as conntrack
 * reports them; what gets exported is the delta since the last export, because
 * NetFlow/IPFIX records describe an interval, not a running total. Re-exporting
 * the cumulative value would make a collector's own rate maths wrong.
 */
struct flowd_export_tracked {
    int in_use;                 /* FLOWD_EXPORT_SLOT_* */
    int family;
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t bytes_total;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_total;
    uint64_t bytes_exported;
    uint64_t packets_exported;
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;      /* last time the counters moved */
    uint64_t last_export_ms;
    uint64_t last_poll_ms;      /* last tick this flow was present in conntrack */
};

struct flowd_export_runtime_stats {
    uint64_t polls;
    uint64_t poll_errors;
    uint64_t lines_seen;
    uint64_t lines_unparsed;
    uint64_t flows_tracked;
    uint64_t flows_dropped_table_full;
    uint64_t flows_expired;
    uint64_t records_exported;
    uint64_t datagrams_sent;
    uint64_t send_errors;
    uint64_t counter_resets;
    int64_t last_poll_at;
    int64_t last_export_at;
    char last_error[128];
};

/* Load the export configuration from flowd_export_settings. */
int flowd_export_config_load(struct flowd_export_config *out);

/*
 * Parse one /proc/net/nf_conntrack line into a flow key plus counters.
 * Returns 1 on success, 0 when the line is not a usable flow.
 *
 * Split out and given internal linkage in the .c file only for the test seam;
 * the parser is where a format surprise turns into wrong exported data, so it
 * is exercised directly rather than through the whole daemon.
 */
int flowd_export_parse_conntrack_line(const char *line,
                                      struct flowd_export_tracked *out);

/*
 * Decide whether a tracked flow should be exported now.
 * `active`: a long-lived flow is reported periodically so a collector sees it
 * before it ends. `inactive`: a flow whose counters stopped moving is flushed
 * and released. Returns 1 to export.
 */
int flowd_export_flow_due(const struct flowd_export_tracked *flow,
                          const struct flowd_export_config *config,
                          uint64_t now_ms);

/* Whether two samples describe the same flow (family, protocol, five-tuple). */
int flowd_export_same_flow(const struct flowd_export_tracked *a,
                           const struct flowd_export_tracked *b);

/*
 * Hash of the flow key, used to index the tracked table.
 *
 * The table is probed rather than scanned: a linear scan costs O(table) per
 * conntrack line, so a full table turned one poll into ~94ms of uloop time on a
 * measured 8192-flow sample. Since every tick reads every line, that quadratic
 * term is the only part of collection that does not scale.
 */
uint32_t flowd_export_flow_hash(const struct flowd_export_tracked *flow);

/*
 * Fold a fresh conntrack sample into a tracked flow.
 *
 * Returns 1 when the cumulative counters went backwards, which means the slot is
 * being reused by a new connection sharing the five-tuple. The caller counts
 * that; the important part is that the exported delta is never computed from a
 * smaller total than what was already exported, which as unsigned arithmetic
 * would underflow into an astronomical byte count.
 */
int flowd_export_apply_sample(struct flowd_export_tracked *slot,
                             const struct flowd_export_tracked *sample,
                             uint64_t now_ms);

/* Build the record to send for a tracked flow: the delta since the last export
 * over the interval it covers, not the flow's cumulative total. */
void flowd_export_fill_record(const struct flowd_export_tracked *flow,
                              struct flowd_export_flow *out, uint64_t now_ms);

/* Start/stop the collection timer. Stop must leave no timer armed and no socket
 * open, which is the handoff's "no leaked timers or handles" criterion. */
int flowd_export_runtime_start(void);
void flowd_export_runtime_stop(void);

/* Re-read configuration on the next tick, after a settings write. */
void flowd_export_runtime_config_invalidate(void);

const struct flowd_export_runtime_stats *flowd_export_runtime_stats(void);
int flowd_export_runtime_active(void);

#endif
