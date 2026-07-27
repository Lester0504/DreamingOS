// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Simple in-memory TTL cache for hot API responses.
 * Thread-safe via simple mutex (single-threaded uloop context, but defensive).
 */
#ifndef __JMX_APP_CACHE_H__
#define __JMX_APP_CACHE_H__

#include <json-c/json.h>

/*
 * Get cached response for a key. Returns NULL if expired or missing.
 * Caller must json_object_put() the returned object.
 */
struct json_object *jmx_cache_get(const char *key);

/*
 * Get cached response even after its normal TTL expired, bounded by total
 * object age. This is for last-known-good responses during short upstream
 * stalls. Caller must json_object_put() the returned object.
 */
struct json_object *jmx_cache_get_allow_stale(const char *key,
                                              int max_age_seconds,
                                              int *age_ms,
                                              int *is_stale);

/*
 * Store a response in cache with TTL in seconds.
 * Holds a json-c reference to the object until expiry or invalidation.
 */
void jmx_cache_put(const char *key, struct json_object *val, int ttl_seconds);

/*
 * Store a response with a short fresh TTL and a longer stale retention window.
 * Normal jmx_cache_get() still treats the item as expired at ttl_seconds.
 */
void jmx_cache_put_with_stale(const char *key, struct json_object *val,
                              int ttl_seconds, int stale_seconds);

/*
 * Invalidate a specific cache entry.
 */
void jmx_cache_invalidate(const char *key);

/*
 * Invalidate all entries matching a prefix.
 */
void jmx_cache_invalidate_prefix(const char *prefix);

/*
 * Cleanup: call periodically to evict expired entries.
 */
void jmx_cache_gc(void);

/*
 * Shutdown: free all cache memory.
 */
void jmx_cache_done(void);

#endif
