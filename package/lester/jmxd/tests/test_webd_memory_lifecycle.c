/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
static int64_t fake_ms;
static int cache_clock_gettime(clockid_t clock_id, struct timespec *ts)
{
    (void)clock_id;
    ts->tv_sec = fake_ms / 1000;
    ts->tv_nsec = (fake_ms % 1000) * 1000000;
    return 0;
}
#define clock_gettime cache_clock_gettime
#include "../src/webd/jmx_app_cache.c"
#undef clock_gettime
static int destroyed;
static void on_destroy(struct json_object *o, void *data)
{
    (void)o; (void)data; ++destroyed;
}
static void store(const char *key)
{
    struct json_object *v = json_object_new_string("payload");
    json_object_set_userdata(v, NULL, on_destroy);
    jmx_cache_put_with_stale(key, v, 2, 10);
    json_object_put(v);
}
int main(void)
{
    struct json_object *v, *stats;
    store("stale");
    fake_ms = 2000;
    assert(jmx_cache_get("stale") == NULL);
    jmx_cache_gc();
    assert(destroyed == 0);
    v = jmx_cache_get_allow_stale("stale", 10, NULL, NULL);
    assert(v); json_object_put(v);
    fake_ms = 4000;
    assert(jmx_cache_get_allow_stale("stale", 3, NULL, NULL) == NULL);
    v = jmx_cache_get_allow_stale("stale", 10, NULL, NULL);
    assert(v); json_object_put(v);
    stats = jmx_cache_status_json();
    assert(json_object_get_int(json_object_object_get(json_object_object_get(stats, "stale"), "entries")) == 1);
    json_object_put(stats);
    fake_ms = 10000;
    jmx_cache_gc();
    assert(destroyed == 1 && g_entry_count == 0);
    /* A replacement at capacity must neither evict another key nor allocate
     * a second entry. Every original key remains readable. */
    char key[40];
    for (int i = 0; i < CACHE_MAX_ENTRIES; ++i) {
        snprintf(key, sizeof(key), "key-%d", i); store(key);
    }
    store("key-128");
    assert(g_entry_count == CACHE_MAX_ENTRIES);
    for (int i = 0; i < CACHE_MAX_ENTRIES; ++i) {
        snprintf(key, sizeof(key), "key-%d", i);
        v = jmx_cache_get(key); assert(v); json_object_put(v);
    }
    jmx_cache_done();
    assert(destroyed == CACHE_MAX_ENTRIES + 2);
    puts("cache lifecycle: fresh/stale/expiry/replacement/ownership PASS");
}
