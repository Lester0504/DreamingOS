// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Snapshot cache for slow read-only ubus handlers.
 *
 * The dashboard/insights methods rebuild JSON from UCI, procfs, conntrack and
 * SQLite. Those builds used to run synchronously on the ubus main loop, so a
 * single slow method stalled every other request. This module keeps one
 * canonical JSON snapshot per request key, refreshes it from a uloop timer on
 * the main thread (the builders touch shared UCI/sqlite/client runtime state
 * with no cross-thread lock discipline), and hands ubus handlers a private
 * clone. Requests are answered from the last snapshot without waiting for a
 * rebuild; first misses return an explicit refreshing envelope and stale
 * entries are rebuilt one per timer tick.
 */
#ifndef DW_READ_CACHE_H
#define DW_READ_CACHE_H

#include <json-c/json.h>

#define DW_READ_CACHE_KEY_MAX 768

/* Builder signature. Takes request JSON, returns response JSON (owned). */
typedef struct json_object *(*dw_read_builder_fn)(struct json_object *in);

/*
 * Initialise the cache and start the background refresher. Safe to call once;
 * later calls are no-ops.
 */
void dw_read_cache_init(void);
void dw_read_cache_stop(void);
struct json_object *dw_read_cache_memory_json(void);

/*
 * Canonical cache key for a method + request. Time bounds are quantised to
 * 60s so near-identical dashboard/insights requests share one entry instead
 * of churning the cache every second.
 */
void dw_read_cache_key_for(const char *method, struct json_object *in,
                           char *out, size_t out_len);

/*
 * Fetch a snapshot.
 * Returns 1 (fresh clone in *out), 2 (stale clone in *out, background refresh
 * requested) or 0 (no snapshot yet; the timer owns the first refresh and the
 * caller must return an explicit refreshing/loading response).
 * The request object and builder are remembered so the refresher can rebuild
 * with the same arguments. The caller keeps ownership of the request object;
 * the cache stores its own clone.
 */
int dw_read_cache_get(const char *key, int ttl_ms,
                      struct json_object *in, dw_read_builder_fn fn,
                      struct json_object **out);

/* Store a snapshot. Caller keeps ownership of obj and in. */
void dw_read_cache_put(const char *key, struct json_object *obj, int ttl_ms,
                       dw_read_builder_fn fn, struct json_object *in);

/* Queue a key for background prewarm (used at startup). */
void dw_read_cache_prewarm(const char *key, struct json_object *in,
                           dw_read_builder_fn fn, int ttl_ms);

/* Recursive lock held around every heavy snapshot build. */
void dw_read_builder_lock(void);
void dw_read_builder_unlock(void);

#endif /* DW_READ_CACHE_H */
