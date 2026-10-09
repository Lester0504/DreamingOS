// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Snapshot cache for slow read-only ubus handlers.
 *
 * Design notes:
 *
 *  - The cache stores one canonical json_object per key. Handlers receive a
 *    deep clone (serialise + parse), so no json-c refcount is ever shared
 *    between the cached snapshot and the reply being built.
 *  - Refresh is driven by a uloop timer on the main thread, never by a
 *    background thread. The heavy builders touch shared UCI/sqlite/client
 *    runtime state that has no lock discipline outside this file, so running
 *    them off-thread would race the rest of jmxd. A request never blocks on a
 *    rebuild: it gets the last snapshot instantly, or an explicit
 *    refreshing/loading envelope on the first miss; the timer refreshes one
 *    entry per tick so a slow build (summary can take ~1.5s) cannot monopolise
 *    the loop back-to-back.
 *  - Entries are LRU-evicted after an idle window so arbitrary audit filters
 *    cannot grow the table without bound.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libubox/uloop.h>
#include <json-c/json.h>

#include "dw_read_cache.h"
#include "dw_memory_diagnostics.h"

#define DW_READ_CACHE_MAX_ENTRIES 24
#define DW_READ_CACHE_REFRESH_INTERVAL_MS 1000
#define DW_READ_CACHE_IDLE_EVICT_MS 60000
#define DW_READ_CACHE_REFRESH_KEEP_MS 5000

struct dw_read_cache_entry {
    char key[DW_READ_CACHE_KEY_MAX];
    int ttl_ms;
    int requested;
    int resident;
    int64_t built_at_ms;
    int64_t last_requested_ms;
    int64_t next_refresh_at_ms;
    struct json_object *obj;
    struct json_object *in;
    dw_read_builder_fn fn;
};

static struct {
    struct uloop_timeout refresh_tm;
    struct dw_read_cache_entry entries[DW_READ_CACHE_MAX_ENTRIES];
    unsigned int next_index;
    int running;
    int initialised;
} g_cache;

static int64_t dw_read_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static struct json_object *dw_read_json_clone(struct json_object *o)
{
    const char *s;
    struct json_object *c;

    if (!o)
        return json_object_new_object();
    s = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    if (!s)
        return json_object_new_object();
    c = json_tokener_parse(s);
    return c ? c : json_object_new_object();
}

void dw_read_cache_key_for(const char *method, struct json_object *in,
                           char *out, size_t out_len)
{
    int n = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!method)
        method = "read";
    n = snprintf(out, out_len, "%s", method);
    if (n < 0 || (size_t)n >= out_len - 1)
        return;
    if (!in || !json_object_is_type(in, json_type_object))
        return;

    json_object_object_foreach(in, key, val) {
        const char *s = NULL;
        char tmp[128];
        int64_t v;

        if ((size_t)n >= out_len - 1)
            break;
        if (json_object_is_type(val, json_type_int)) {
            v = json_object_get_int64(val);
            if (!strcmp(key, "ts_from") || !strcmp(key, "ts_to") ||
                !strcmp(key, "timestampFrom") || !strcmp(key, "timestampTo") ||
                !strcmp(key, "from") || !strcmp(key, "to") ||
                !strcmp(key, "ts"))
                v /= 60000;
            n += snprintf(out + n, out_len - (size_t)n, "|%s=%lld",
                          key, (long long)v);
        } else if (json_object_is_type(val, json_type_string)) {
            s = json_object_get_string(val);
            n += snprintf(out + n, out_len - (size_t)n, "|%s=%s",
                          key, s ? s : "");
        } else if (json_object_is_type(val, json_type_boolean)) {
            n += snprintf(out + n, out_len - (size_t)n, "|%s=%d",
                          key, json_object_get_boolean(val) ? 1 : 0);
        } else if (json_object_is_type(val, json_type_double)) {
            snprintf(tmp, sizeof(tmp), "%.6f", json_object_get_double(val));
            n += snprintf(out + n, out_len - (size_t)n, "|%s=%s",
                          key, tmp);
        } else {
            s = json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN);
            n += snprintf(out + n, out_len - (size_t)n, "|%s=%s",
                          key, s ? s : "");
        }
    }
}

static struct dw_read_cache_entry *dw_read_cache_find(const char *key)
{
    int i;

    for (i = 0; i < DW_READ_CACHE_MAX_ENTRIES; i++) {
        struct dw_read_cache_entry *e = &g_cache.entries[i];

        if (e->key[0] && !strcmp(e->key, key))
            return e;
    }
    return NULL;
}

static struct dw_read_cache_entry *dw_read_cache_slot(const char *key)
{
    struct dw_read_cache_entry *e = dw_read_cache_find(key);
    struct dw_read_cache_entry *idle = NULL;
    struct dw_read_cache_entry *oldest = NULL;
    struct dw_read_cache_entry *oldest_any = NULL;
    int64_t now = dw_read_now_ms();
    int i;

    if (e)
        return e;
    for (i = 0; i < DW_READ_CACHE_MAX_ENTRIES; i++) {
        struct dw_read_cache_entry *c = &g_cache.entries[i];

        if (!c->key[0]) {
            idle = c;
            break;
        }
        if (!oldest_any ||
            c->last_requested_ms < oldest_any->last_requested_ms)
            oldest_any = c;
        if (!c->resident &&
            (!oldest || c->last_requested_ms < oldest->last_requested_ms))
            oldest = c;
    }
    if (idle)
        e = idle;
    else if (oldest)
        e = oldest;
    else
        e = oldest_any;
    if (e->obj) {
        json_object_put(e->obj);
        e->obj = NULL;
    }
    if (e->in) {
        json_object_put(e->in);
        e->in = NULL;
    }
    memset(e, 0, sizeof(*e));
    snprintf(e->key, sizeof(e->key), "%s", key);
    e->last_requested_ms = now;
    e->requested = 1;
    return e;
}

static void dw_read_cache_entry_remember(struct dw_read_cache_entry *e,
                                         struct json_object *in,
                                         dw_read_builder_fn fn)
{
    if (fn)
        e->fn = fn;
    if (in) {
        struct json_object *clone = dw_read_json_clone(in);

        if (e->in)
            json_object_put(e->in);
        e->in = clone;
    }
}

void dw_read_cache_put(const char *key, struct json_object *obj, int ttl_ms,
                       dw_read_builder_fn fn, struct json_object *in)
{
    struct dw_read_cache_entry *e;

    if (!key || !obj)
        return;
    e = dw_read_cache_slot(key);
    dw_read_cache_entry_remember(e, in, fn);
    if (e->obj)
        json_object_put(e->obj);
    e->obj = json_object_get(obj);
    e->ttl_ms = ttl_ms > 0 ? ttl_ms : 1000;
    e->built_at_ms = dw_read_now_ms();
}

int dw_read_cache_get(const char *key, int ttl_ms,
                      struct json_object *in, dw_read_builder_fn fn,
                      struct json_object **out)
{
    struct dw_read_cache_entry *e;
    int64_t now;
    int rc = 0;

    if (out)
        *out = NULL;
    if (!key)
        return 0;
    e = dw_read_cache_slot(key);
    dw_read_cache_entry_remember(e, in, fn);
    e->ttl_ms = ttl_ms > 0 ? ttl_ms : 1000;
    e->last_requested_ms = now = dw_read_now_ms();
    e->requested = 1;
    if (e->obj) {
        if (now >= e->built_at_ms &&
            now - e->built_at_ms < e->ttl_ms) {
            if (out)
                *out = dw_read_json_clone(e->obj);
            rc = 1;
        } else {
            if (out)
                *out = dw_read_json_clone(e->obj);
            rc = 2;
        }
    }
    return rc;
}

void dw_read_cache_prewarm(const char *key, struct json_object *in,
                           dw_read_builder_fn fn, int ttl_ms)
{
    struct dw_read_cache_entry *e;

    if (!key || !fn)
        return;
    e = dw_read_cache_slot(key);
    dw_read_cache_entry_remember(e, in, fn);
    e->ttl_ms = ttl_ms > 0 ? ttl_ms : 1000;
    e->resident = 1;
    e->last_requested_ms = dw_read_now_ms();
    /*
     * A prewarm is an actual one-shot refresh request.  The old implementation
     * only remembered the builder, so the first dashboard request was still a
     * synchronous cache miss on the ubus loop.  Marking it pending lets the
     * existing timer build it without blocking request dispatch; once built,
     * the normal TTL path takes over and it is no longer refreshed until used.
     */
    e->requested = 1;
    e->next_refresh_at_ms = dw_read_now_ms();
}

static void dw_read_cache_refresh_one(struct dw_read_cache_entry *e)
{
    struct json_object *in = e->in ? dw_read_json_clone(e->in)
                                   : json_object_new_object();
    struct json_object *out = NULL;

    if (e->fn)
        out = e->fn(in);
    json_object_put(in);
    if (!out)
        return;
    if (e->obj)
        json_object_put(e->obj);
    e->obj = out;
    e->built_at_ms = dw_read_now_ms();
}

static void dw_read_cache_evict_idle(void)
{
    int64_t now = dw_read_now_ms();
    int i;

    for (i = 0; i < DW_READ_CACHE_MAX_ENTRIES; i++) {
        struct dw_read_cache_entry *e = &g_cache.entries[i];

        if (!e->key[0])
            continue;
        if (e->resident)
            continue;
        if (now - e->last_requested_ms <= DW_READ_CACHE_IDLE_EVICT_MS)
            continue;
        if (e->obj) {
            json_object_put(e->obj);
            e->obj = NULL;
        }
        if (e->in) {
            json_object_put(e->in);
            e->in = NULL;
        }
        memset(e, 0, sizeof(*e));
    }
}

static void dw_read_cache_tick(void)
{
    int i;
    int rebuilt = 0;

    for (i = 0; i < DW_READ_CACHE_MAX_ENTRIES; i++) {
        struct dw_read_cache_entry *e =
            &g_cache.entries[(g_cache.next_index + (unsigned int)i) %
                             DW_READ_CACHE_MAX_ENTRIES];
        int64_t now = dw_read_now_ms();

        if (!e->key[0] || !e->requested || !e->fn)
            continue;
        if (now < e->next_refresh_at_ms)
            continue;
        if (e->obj && e->ttl_ms > 0 && now >= e->built_at_ms &&
            now - e->built_at_ms < e->ttl_ms)
            continue;
        dw_read_cache_refresh_one(e);
        e->requested = 0;
        e->next_refresh_at_ms = now + DW_READ_CACHE_REFRESH_KEEP_MS;
        g_cache.next_index = (g_cache.next_index + (unsigned int)i + 1U) %
                             DW_READ_CACHE_MAX_ENTRIES;
        rebuilt = 1;
        break;
    }
    dw_read_cache_evict_idle();
    if (g_cache.running)
        uloop_timeout_set(&g_cache.refresh_tm,
                          rebuilt ? DW_READ_CACHE_REFRESH_INTERVAL_MS : 1000);
}

static void dw_read_cache_timer_cb(struct uloop_timeout *t)
{
    (void)t;
    dw_read_cache_tick();
}

void dw_read_cache_init(void)
{
    if (!g_cache.initialised) {
        memset(&g_cache, 0, sizeof(g_cache));
        g_cache.initialised = 1;
        g_cache.refresh_tm.cb = dw_read_cache_timer_cb;
    }

    /*
     * ubus reconnect unregisters and registers the object again.  stop()
     * cancels this timer, so an already-initialised cache must explicitly
     * re-arm it here or every prewarm remains a permanent cold miss.
     */
    g_cache.running = 1;
    uloop_timeout_set(&g_cache.refresh_tm, 100);
}

void dw_read_cache_stop(void)
{
    if (!g_cache.initialised)
        return;
    g_cache.running = 0;
    uloop_timeout_cancel(&g_cache.refresh_tm);
}

void dw_read_builder_lock(void)
{
}

void dw_read_builder_unlock(void)
{
}

struct json_object *dw_read_cache_memory_json(void)
{
    struct json_object *o = json_object_new_object();
    uint64_t entries = 0, resident = 0, idle = 0, nodes = 0, strings = 0;
    int64_t now = dw_read_now_ms();
    /* Called by the main ubus loop, which also owns all cache mutations. */
    for (int i = 0; i < DW_READ_CACHE_MAX_ENTRIES; ++i) {
        struct dw_read_cache_entry *e = &g_cache.entries[i];
        if (!e->key[0]) continue;
        ++entries;
        resident += e->resident != 0;
        idle += !e->resident && now - e->last_requested_ms > DW_READ_CACHE_IDLE_EVICT_MS;
        dw_mem_json_content(e->obj, &nodes, &strings);
        dw_mem_json_content(e->in, &nodes, &strings);
    }
    dw_mem_u64(o, "entries", entries);
    dw_mem_u64(o, "resident_entries", resident);
    dw_mem_u64(o, "idle_evictable_entries", idle);
    dw_mem_u64(o, "fixed_table_bytes", sizeof(g_cache));
    dw_mem_u64(o, "json_nodes", nodes);
    dw_mem_u64(o, "json_string_bytes", strings);
    json_object_object_add(o, "json_heap_bytes", NULL);
    json_object_object_add(o, "reason", json_object_new_string("json_c_has_no_object_allocation_size_api"));
    return o;
}
