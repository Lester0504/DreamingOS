// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Simple in-memory TTL cache for hot API responses.
 * Fixed-size hash table with linked-list chaining.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <json-c/json.h>
#include "jmx_app_cache.h"

#define CACHE_BUCKETS 64
#define CACHE_MAX_ENTRIES 256

struct cache_entry {
    char *key;
    struct json_object *val;
    int64_t created_at;
    int64_t expires_at;
    int64_t stale_until;
    struct cache_entry *next;
};

static struct cache_entry *g_buckets[CACHE_BUCKETS];
static int g_entry_count = 0;
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static unsigned int hash_key(const char *key)
{
    unsigned int h = 5381;
    while (*key) h = ((h << 5) + h) + (unsigned char)*key++;
    return h % CACHE_BUCKETS;
}

static struct cache_entry *find_entry(const char *key)
{
    if (!key)
        return NULL;
    unsigned int b = hash_key(key);
    struct cache_entry *e = g_buckets[b];
    while (e) {
        if (!strcmp(e->key, key)) return e;
        e = e->next;
    }
    return NULL;
}

static void free_entry(struct cache_entry *e)
{
    if (!e) return;
    free(e->key);
    if (e->val) json_object_put(e->val);
    free(e);
}

struct json_object *jmx_cache_get(const char *key)
{
    struct json_object *result = NULL;

    if (!key)
        return NULL;
    pthread_mutex_lock(&g_cache_lock);
    struct cache_entry *e = find_entry(key);
    if (!e)
        goto out;
    if (now_ms() >= e->expires_at) {
        /* expired — remove */
        unsigned int b = hash_key(key);
        if (g_buckets[b] == e) {
            g_buckets[b] = e->next;
        } else {
            struct cache_entry *p = g_buckets[b];
            while (p && p->next != e) p = p->next;
            if (p) p->next = e->next;
        }
        g_entry_count--;
        free_entry(e);
        goto out;
    }
    result = json_object_get(e->val);
out:
    pthread_mutex_unlock(&g_cache_lock);
    return result;
}

struct json_object *jmx_cache_get_allow_stale(const char *key,
                                              int max_age_seconds,
                                              int *age_ms,
                                              int *is_stale)
{
    struct cache_entry *e;
    int64_t now;

    if (age_ms)
        *age_ms = 0;
    if (is_stale)
        *is_stale = 0;
    if (!key || max_age_seconds <= 0)
        return NULL;

    pthread_mutex_lock(&g_cache_lock);
    e = find_entry(key);
    if (!e) {
        pthread_mutex_unlock(&g_cache_lock);
        return NULL;
    }

    now = now_ms();
    if (now - e->created_at > (int64_t)max_age_seconds * 1000 ||
        now >= e->stale_until) {
        unsigned int b = hash_key(key);
        struct cache_entry *cur = g_buckets[b];
        struct cache_entry *prev = NULL;

        while (cur && cur != e) {
            prev = cur;
            cur = cur->next;
        }
        if (cur) {
            if (prev)
                prev->next = cur->next;
            else
                g_buckets[b] = cur->next;
            g_entry_count--;
            free_entry(cur);
        }
        pthread_mutex_unlock(&g_cache_lock);
        return NULL;
    }

    if (age_ms)
        *age_ms = (int)(now - e->created_at);
    if (is_stale)
        *is_stale = now >= e->expires_at;
    {
        struct json_object *result = json_object_get(e->val);
        pthread_mutex_unlock(&g_cache_lock);
        return result;
    }
}

void jmx_cache_put(const char *key, struct json_object *val, int ttl_seconds)
{
    jmx_cache_put_with_stale(key, val, ttl_seconds, ttl_seconds);
}

void jmx_cache_put_with_stale(const char *key, struct json_object *val,
                              int ttl_seconds, int stale_seconds)
{
    if (!key || !val || ttl_seconds <= 0) return;
    if (stale_seconds < ttl_seconds)
        stale_seconds = ttl_seconds;
    pthread_mutex_lock(&g_cache_lock);

    /* Evict if at capacity */
    if (g_entry_count >= CACHE_MAX_ENTRIES) {
        /* Simple eviction: remove oldest from first non-empty bucket */
        int i;
        for (i = 0; i < CACHE_BUCKETS; i++) {
            if (g_buckets[i]) {
                struct cache_entry *old = g_buckets[i];
                g_buckets[i] = old->next;
                g_entry_count--;
                free_entry(old);
                break;
            }
        }
    }

    /* Remove existing entry if present */
    struct cache_entry *existing = find_entry(key);
    if (existing) {
        unsigned int b = hash_key(key);
        if (g_buckets[b] == existing) {
            g_buckets[b] = existing->next;
        } else {
            struct cache_entry *p = g_buckets[b];
            while (p && p->next != existing) p = p->next;
            if (p) p->next = existing->next;
        }
        g_entry_count--;
        free_entry(existing);
    }

    struct cache_entry *e = calloc(1, sizeof(*e));
    if (!e) {
        pthread_mutex_unlock(&g_cache_lock);
        return;
    }
    e->key = strdup(key);
    if (!e->key) {
        free(e);
        pthread_mutex_unlock(&g_cache_lock);
        return;
    }
    e->val = json_object_get(val);
    e->created_at = now_ms();
    e->expires_at = e->created_at + (int64_t)ttl_seconds * 1000;
    e->stale_until = e->created_at + (int64_t)stale_seconds * 1000;

    unsigned int b = hash_key(key);
    e->next = g_buckets[b];
    g_buckets[b] = e;
    g_entry_count++;
    pthread_mutex_unlock(&g_cache_lock);
}

void jmx_cache_invalidate(const char *key)
{
    if (!key)
        return;
    pthread_mutex_lock(&g_cache_lock);
    unsigned int b = hash_key(key);
    struct cache_entry *e = g_buckets[b];
    struct cache_entry *prev = NULL;
    while (e) {
        if (!strcmp(e->key, key)) {
            if (prev) prev->next = e->next;
            else g_buckets[b] = e->next;
            g_entry_count--;
            free_entry(e);
            pthread_mutex_unlock(&g_cache_lock);
            return;
        }
        prev = e;
        e = e->next;
    }
    pthread_mutex_unlock(&g_cache_lock);
}

void jmx_cache_invalidate_prefix(const char *prefix)
{
    if (!prefix)
        return;
    pthread_mutex_lock(&g_cache_lock);
    int plen = (int)strlen(prefix);
    int i;
    for (i = 0; i < CACHE_BUCKETS; i++) {
        struct cache_entry *e = g_buckets[i];
        struct cache_entry *prev = NULL;
        while (e) {
            if (!strncmp(e->key, prefix, (size_t)plen)) {
                struct cache_entry *rm = e;
                e = e->next;
                if (prev) prev->next = rm->next;
                else g_buckets[i] = rm->next;
                g_entry_count--;
                free_entry(rm);
                continue;
            }
            prev = e;
            e = e->next;
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
}

void jmx_cache_gc(void)
{
    int64_t now = now_ms();
    int i;
    pthread_mutex_lock(&g_cache_lock);
    for (i = 0; i < CACHE_BUCKETS; i++) {
        struct cache_entry *e = g_buckets[i];
        struct cache_entry *prev = NULL;
        while (e) {
            if (now >= e->stale_until) {
                struct cache_entry *rm = e;
                e = e->next;
                if (prev) prev->next = rm->next;
                else g_buckets[i] = rm->next;
                g_entry_count--;
                free_entry(rm);
                continue;
            }
            prev = e;
            e = e->next;
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
}

void jmx_cache_done(void)
{
    int i;
    pthread_mutex_lock(&g_cache_lock);
    for (i = 0; i < CACHE_BUCKETS; i++) {
        struct cache_entry *e = g_buckets[i];
        while (e) {
            struct cache_entry *next = e->next;
            free_entry(e);
            e = next;
        }
        g_buckets[i] = NULL;
    }
    g_entry_count = 0;
    pthread_mutex_unlock(&g_cache_lock);
}
