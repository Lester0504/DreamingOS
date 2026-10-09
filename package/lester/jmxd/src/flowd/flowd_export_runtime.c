// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Flow collection for NetFlow v9 / IPFIX export.
 *
 * Source is /proc/net/nf_conntrack. The kernel already accounts bytes and
 * packets per connection (nf_conntrack_acct), so this reads what exists rather
 * than adding a second accounting path on a device that has to forward traffic
 * at the same time.
 *
 * Text parsing rather than the netlink dump API is a deliberate choice: flowd
 * already keeps a conntrack *event* socket open for QoE, and opening a second
 * netlink handle for periodic full dumps would contend with it. A 5s read of a
 * procfs file is cheap and, unlike an event stream, cannot fall behind and drop
 * ENOBUFS mid-accounting.
 *
 * What is exported is the *delta* since the last export. conntrack counters are
 * cumulative for the life of the connection; a NetFlow record describes an
 * interval. Exporting the cumulative value would make a collector's own rate
 * calculation wrong, and every periodic record for a long-lived flow would
 * re-report bytes already counted.
 */
#include "flowd_internal.h"
#include "flowd_export_runtime.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#define FLOWD_CONNTRACK_PROC "/proc/net/nf_conntrack"
#define FLOWD_CONNTRACK_PROC_LEGACY "/proc/net/ip_conntrack"

/*
 * A flow absent from two consecutive polls is treated as gone. One missing poll
 * is not enough: conntrack entries can disappear between reads for reasons that
 * have nothing to do with the flow ending, and flushing on a single miss would
 * split one flow into several exported records.
 */
#define FLOWD_EXPORT_MISSING_POLLS_GONE 2

static struct {
    int active;
    int config_dirty;
    struct uloop_timeout timer;
    struct flowd_export_config config;
    struct flowd_export_state state;
    struct flowd_export_sink sink;
    int sink_open;
    struct flowd_export_tracked *table;
    size_t table_len;
    size_t table_live;
    struct flowd_export_runtime_stats stats;
} g_export;

static uint64_t flowd_export_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (uint64_t)time(NULL) * 1000ULL;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void flowd_export_error_set(const char *code)
{
    snprintf(g_export.stats.last_error, sizeof(g_export.stats.last_error),
             "%s", code ? code : "");
}

int flowd_export_config_load(struct flowd_export_config *out)
{
    sqlite3_stmt *st;
    int rc;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    /* Defaults mirror the schema, so a missing row behaves like a fresh install
     * (disabled) rather than like an enabled export with empty settings. */
    out->protocol = FLOWD_EXPORT_PROTOCOL_IPFIX;
    out->collector_port = 4739;
    out->active_timeout_s = 60;
    out->inactive_timeout_s = 15;
    out->template_refresh_s = 600;
    out->sampling_rate = 1;
    out->observation_domain = 1;

    st = flowd_config_prepare(
        "SELECT enabled,protocol,collector_host,collector_port,"
        "active_timeout_seconds,inactive_timeout_seconds,"
        "template_refresh_seconds,sampling_rate,observation_domain "
        "FROM flowd_export_settings WHERE id=1");
    if (!st)
        return -1;
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    out->enabled = sqlite3_column_int(st, 0);
    out->protocol = flowd_export_protocol_from_string(
        flowd_sqlite_text(st, 1, "ipfix"));
    snprintf(out->collector_host, sizeof(out->collector_host), "%s",
             flowd_sqlite_text(st, 2, ""));
    out->collector_port = (uint16_t)sqlite3_column_int(st, 3);
    out->active_timeout_s = (uint32_t)sqlite3_column_int(st, 4);
    out->inactive_timeout_s = (uint32_t)sqlite3_column_int(st, 5);
    out->template_refresh_s = (uint32_t)sqlite3_column_int(st, 6);
    out->sampling_rate = (uint32_t)sqlite3_column_int(st, 7);
    out->observation_domain = (uint32_t)sqlite3_column_int(st, 8);
    sqlite3_finalize(st);
    return 0;
}

/* ── conntrack parsing ──────────────────────────────────────────────────── */





static struct flowd_export_tracked *
flowd_export_track(const struct flowd_export_tracked *seen, uint64_t now_ms)
{
    struct flowd_export_tracked *free_slot = NULL;
    size_t mask = g_export.table_len - 1;
    size_t start = flowd_export_flow_hash(seen) & mask;
    size_t probe;

    /*
     * Open addressing with linear probing; the table size is a power of two so
     * the index is a mask rather than a modulo.
     *
     * Expired flows leave a tombstone instead of an empty slot. Clearing to
     * empty would truncate any probe chain running through that slot, so a flow
     * stored later in the chain would stop being found and get inserted a second
     * time -- and the duplicate, starting from bytes_exported = 0, would
     * re-export the connection's whole cumulative total as one delta. The
     * tombstone keeps the chain intact while still being reusable.
     */
    for (probe = 0; probe < g_export.table_len; probe++) {
        struct flowd_export_tracked *slot =
            &g_export.table[(start + probe) & mask];

        if (slot->in_use == FLOWD_EXPORT_SLOT_EMPTY) {
            if (!free_slot)
                free_slot = slot;
            break;
        }
        if (slot->in_use == FLOWD_EXPORT_SLOT_TOMBSTONE) {
            /* Reusable, but keep probing: the flow may be further along. */
            if (!free_slot)
                free_slot = slot;
            continue;
        }
        if (flowd_export_same_flow(slot, seen))
            return slot;
    }
    /*
     * The ceiling is on admitted flows, not on slots, so occupancy stays at or
     * below half and the probe walk stays short. A new flow is refused rather
     * than evicting an established one whose counters have not been exported --
     * losing a flow already promised to the collector is the worse trade.
     */
    if (!free_slot || g_export.table_live >= FLOWD_EXPORT_MAX_TRACKED) {
        g_export.stats.flows_dropped_table_full++;
        flowd_export_error_set("flow_table_full");
        return NULL;
    }
    memcpy(free_slot, seen, sizeof(*free_slot));
    free_slot->in_use = FLOWD_EXPORT_SLOT_LIVE;
    free_slot->bytes_exported = 0;
    free_slot->packets_exported = 0;
    free_slot->first_seen_ms = now_ms;
    free_slot->last_seen_ms = now_ms;
    free_slot->last_export_ms = now_ms;
    free_slot->last_poll_ms = now_ms;
    g_export.table_live++;
    g_export.stats.flows_tracked++;
    return free_slot;
}







/* ── export ─────────────────────────────────────────────────────────────── */

static int flowd_export_ensure_sink(void)
{
    if (g_export.sink_open)
        return 0;
    if (!g_export.config.collector_host[0]) {
        flowd_export_error_set("collector_host_empty");
        return -1;
    }
    if (flowd_export_sink_open(&g_export.sink, g_export.config.collector_host,
                               g_export.config.collector_port) != 0) {
        g_export.stats.send_errors++;
        flowd_export_error_set(g_export.sink.last_error[0] ?
                               g_export.sink.last_error : "collector_unreachable");
        return -1;
    }
    g_export.sink_open = 1;
    flowd_export_error_set("");
    return 0;
}

static void flowd_export_close_sink(void)
{
    if (!g_export.sink_open)
        return;
    flowd_export_sink_close(&g_export.sink);
    g_export.sink_open = 0;
}

/*
 * Send one family's batch. Batches are per family because a datagram carries one
 * template, and the encoder rejects a mixed batch rather than encoding it wrong.
 */
static void flowd_export_send_batch(struct flowd_export_flow *flows,
                                    size_t count, uint64_t now_ms)
{
    int sent;

    if (!count)
        return;
    if (flowd_export_ensure_sink() != 0)
        return;
    sent = flowd_export_emit(&g_export.config, &g_export.state, &g_export.sink,
                             flows, count, now_ms);
    if (sent < 0) {
        g_export.stats.send_errors++;
        flowd_export_error_set(g_export.sink.last_error[0] ?
                               g_export.sink.last_error : "export_send_failed");
        /*
         * Drop the socket so the next tick re-resolves the collector. A
         * collector that moved or restarted otherwise keeps failing against a
         * stale connected socket.
         */
        flowd_export_close_sink();
        return;
    }
    g_export.stats.datagrams_sent += (uint64_t)sent;
    g_export.stats.records_exported += count;
    g_export.stats.last_export_at = flowd_now_s();
}

static void flowd_export_poll(uint64_t now_ms)
{
    struct flowd_export_flow batch_v4[64];
    struct flowd_export_flow batch_v6[64];
    size_t n4 = 0, n6 = 0;
    char line[FLOWD_EXPORT_CT_LINE_MAX];
    FILE *fp;
    size_t i;

    fp = fopen(FLOWD_CONNTRACK_PROC, "r");
    if (!fp)
        fp = fopen(FLOWD_CONNTRACK_PROC_LEGACY, "r");
    if (!fp) {
        g_export.stats.poll_errors++;
        flowd_export_error_set("conntrack_unavailable");
        return;
    }
    g_export.stats.polls++;
    g_export.stats.last_poll_at = flowd_now_s();

    while (fgets(line, sizeof(line), fp)) {
        struct flowd_export_tracked seen;
        struct flowd_export_tracked *slot;

        g_export.stats.lines_seen++;
        if (!flowd_export_parse_conntrack_line(line, &seen)) {
            g_export.stats.lines_unparsed++;
            continue;
        }
        slot = flowd_export_track(&seen, now_ms);
        if (!slot)
            continue;
        if (flowd_export_apply_sample(slot, &seen, now_ms))
            g_export.stats.counter_resets++;
    }
    fclose(fp);

    for (i = 0; i < g_export.table_len; i++) {
        struct flowd_export_tracked *slot = &g_export.table[i];
        int gone;

        if (slot->in_use != FLOWD_EXPORT_SLOT_LIVE)
            continue;
        gone = (now_ms - slot->last_poll_ms) >
               (uint64_t)FLOWD_EXPORT_MISSING_POLLS_GONE * FLOWD_EXPORT_TICK_MS;
        if (!gone && !flowd_export_flow_due(slot, &g_export.config, now_ms))
            continue;
        /* A vanished flow still gets its remaining counters flushed, otherwise
         * the tail of every connection is missing from the export. */
        if (slot->bytes_total > slot->bytes_exported ||
            slot->packets_total > slot->packets_exported) {
            struct flowd_export_flow *dst;

            if (slot->family == AF_INET6)
                dst = (n6 < 64) ? &batch_v6[n6++] : NULL;
            else
                dst = (n4 < 64) ? &batch_v4[n4++] : NULL;
            if (dst) {
                flowd_export_fill_record(slot, dst, now_ms);
                slot->bytes_exported = slot->bytes_total;
                slot->packets_exported = slot->packets_total;
                slot->last_export_ms = now_ms;
            }
        }
        if (gone) {
            memset(slot, 0, sizeof(*slot));
            /* Tombstone, not empty: an empty slot here would break any probe
             * chain passing through it. */
            slot->in_use = FLOWD_EXPORT_SLOT_TOMBSTONE;
            if (g_export.table_live)
                g_export.table_live--;
            g_export.stats.flows_expired++;
        }
    }

    flowd_export_send_batch(batch_v4, n4, now_ms);
    flowd_export_send_batch(batch_v6, n6, now_ms);
}

static void flowd_export_release_table(void)
{
    free(g_export.table);
    g_export.table = NULL;
    g_export.table_len = 0;
    g_export.table_live = 0;
}

static void flowd_export_tick(struct uloop_timeout *t)
{
    uint64_t now_ms = flowd_export_now_ms();

    if (g_export.config_dirty) {
        struct flowd_export_config next;

        if (flowd_export_config_load(&next) == 0) {
            /* A collector change must not keep sending to the old address. */
            if (strcmp(next.collector_host, g_export.config.collector_host) ||
                next.collector_port != g_export.config.collector_port ||
                next.protocol != g_export.config.protocol)
                flowd_export_close_sink();
            g_export.config = next;
            g_export.config_dirty = 0;
        }
    }

    if (!g_export.config.enabled) {
        /*
         * Disabled: stop exporting immediately, release the socket, and forget
         * the tracked flows. Keeping them would make a later re-enable emit one
         * enormous catch-up record covering the disabled window -- traffic the
         * operator had asked not to export.
         */
        flowd_export_close_sink();
        if (g_export.table_len)
            flowd_export_release_table();
    } else {
        if (!g_export.table) {
            g_export.table = calloc(FLOWD_EXPORT_TABLE_SLOTS,
                                    sizeof(*g_export.table));
            if (!g_export.table) {
                flowd_export_error_set("flow_table_alloc_failed");
                uloop_timeout_set(t, FLOWD_EXPORT_TICK_MS);
                return;
            }
            g_export.table_len = FLOWD_EXPORT_TABLE_SLOTS;
            g_export.state.boot_time_ms = now_ms;
        }
        flowd_export_poll(now_ms);
    }
    uloop_timeout_set(t, FLOWD_EXPORT_TICK_MS);
}

void flowd_export_runtime_config_invalidate(void)
{
    g_export.config_dirty = 1;
}

int flowd_export_runtime_start(void)
{
    if (g_export.active)
        return 0;
    memset(&g_export, 0, sizeof(g_export));
    if (flowd_export_config_load(&g_export.config) != 0) {
        /* Without settings, stay off rather than guessing a collector. */
        flowd_export_error_set("export_settings_unavailable");
        return -1;
    }
    g_export.state.boot_time_ms = flowd_export_now_ms();
    g_export.timer.cb = flowd_export_tick;
    uloop_timeout_set(&g_export.timer, FLOWD_EXPORT_TICK_MS);
    g_export.active = 1;
    return 0;
}

void flowd_export_runtime_stop(void)
{
    if (!g_export.active)
        return;
    uloop_timeout_cancel(&g_export.timer);
    flowd_export_close_sink();
    flowd_export_release_table();
    g_export.active = 0;
}

const struct flowd_export_runtime_stats *flowd_export_runtime_stats(void)
{
    return &g_export.stats;
}

int flowd_export_runtime_active(void)
{
    return g_export.active && g_export.config.enabled;
}
