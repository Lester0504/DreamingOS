// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_qoe_cache.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int qoe_family_valid(uint8_t family)
{
    return family == AF_INET || family == AF_INET6;
}

static uint64_t qoe_hash(uint64_t key, uint8_t scope, uint8_t family,
                         uint16_t policy_prio)
{
    uint64_t value = key ^ ((uint64_t)scope * 0x9e3779b97f4a7c15ULL) ^
                     ((uint64_t)family * 0xd6e8feb86659fd93ULL) ^
                     ((uint64_t)policy_prio * 0xa0761d6478bd642fULL);

    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

static int qoe_capacity_ok(size_t capacity)
{
    return capacity >= 2 && (capacity & (capacity - 1)) == 0;
}

static size_t qoe_find_slot(struct flowd_qoe_cache *cache, uint8_t scope,
                            uint8_t family, uint64_t key,
                            uint16_t policy_prio, uint64_t now_ms, int *found)
{
    size_t first_expired = SIZE_MAX;
    size_t oldest = SIZE_MAX;
    uint64_t oldest_used = UINT64_MAX;
    size_t start;
    size_t probe;

    *found = 0;
    start = (size_t)(qoe_hash(key, scope, family, policy_prio) &
                     (cache->capacity - 1));
    for (probe = 0; probe < cache->capacity; probe++) {
        size_t slot = (start + probe) & (cache->capacity - 1);
        struct flowd_qoe_entry *entry = &cache->entries[slot];

        if (!entry->generation)
            return first_expired != SIZE_MAX ? first_expired : slot;
        if (entry->scope == scope && entry->family == family &&
            entry->key == key && entry->policy_prio == policy_prio) {
            *found = 1;
            return slot;
        }
        if (entry->valid_until_ms <= now_ms && first_expired == SIZE_MAX)
            first_expired = slot;
        if (entry->last_used_ms < oldest_used) {
            oldest_used = entry->last_used_ms;
            oldest = slot;
        }
    }
    return first_expired != SIZE_MAX ? first_expired : oldest;
}

static int qoe_path_cmp(const void *left, const void *right)
{
    const struct flowd_qoe_path *a = left;
    const struct flowd_qoe_path *b = right;

    if (a->healthy != b->healthy)
        return a->healthy ? -1 : 1;
    if (a->score_us < b->score_us)
        return -1;
    if (a->score_us > b->score_us)
        return 1;
    return (int)a->wan_id - (int)b->wan_id;
}

static uint32_t qoe_equivalent_margin_us(uint32_t best_score_us)
{
    uint64_t relative;

    relative = (uint64_t)best_score_us * FLOWD_QOE_EQUIVALENT_PERCENT / 100U;
    if (relative < FLOWD_QOE_EQUIVALENT_ABS_US)
        relative = FLOWD_QOE_EQUIVALENT_ABS_US;
    return relative > UINT32_MAX ? UINT32_MAX : (uint32_t)relative;
}

static uint8_t qoe_choose_preferred_wan(const struct flowd_qoe_entry *entry,
                                        uint8_t previous_wan)
{
    uint32_t best_score_us = UINT32_MAX;
    uint64_t ceiling;
    uint64_t best_rank = 0;
    uint8_t selected = 0;
    size_t i;

    if (!entry)
        return 0;
    for (i = 0; i < entry->path_count; i++) {
        if (entry->paths[i].healthy && entry->paths[i].score_us < best_score_us)
            best_score_us = entry->paths[i].score_us;
    }
    if (best_score_us == UINT32_MAX)
        return 0;
    ceiling = (uint64_t)best_score_us + qoe_equivalent_margin_us(best_score_us);

    /* Hysteresis: a still-healthy previous choice in the same quality tier is
     * more valuable than chasing a few milliseconds of probe noise. */
    if (previous_wan) {
        for (i = 0; i < entry->path_count; i++) {
            const struct flowd_qoe_path *path = &entry->paths[i];

            if (path->wan_id == previous_wan && path->healthy &&
                (uint64_t)path->score_us <= ceiling)
                return previous_wan;
        }
    }

    /* Rendezvous hashing distributes equivalent destinations across the tier
     * without making a destination jump when RTT ordering jitters. */
    for (i = 0; i < entry->path_count; i++) {
        const struct flowd_qoe_path *path = &entry->paths[i];
        uint64_t rank;

        if (!path->healthy || (uint64_t)path->score_us > ceiling)
            continue;
        rank = qoe_hash(entry->key ^ ((uint64_t)path->wan_id << 56),
                        entry->scope, entry->family, entry->policy_prio);
        if (!selected || rank > best_rank) {
            selected = path->wan_id;
            best_rank = rank;
        }
    }
    return selected;
}

static struct flowd_qoe_entry *qoe_lookup_exact(struct flowd_qoe_cache *cache,
                                                enum flowd_qoe_scope scope,
                                                uint8_t family,
                                                uint64_t key,
                                                uint16_t policy_prio,
                                                uint64_t now_ms)
{
    size_t start;
    size_t probe;

    start = (size_t)(qoe_hash(key, (uint8_t)scope, family, policy_prio) &
                     (cache->capacity - 1));
    for (probe = 0; probe < cache->capacity; probe++) {
        size_t slot = (start + probe) & (cache->capacity - 1);
        struct flowd_qoe_entry *entry = &cache->entries[slot];

        if (!entry->generation)
            return NULL;
        if (entry->scope != (uint8_t)scope || entry->family != family ||
            entry->key != key || entry->policy_prio != policy_prio)
            continue;
        if (entry->valid_until_ms <= now_ms) {
            cache->expirations++;
            return NULL;
        }
        entry->last_used_ms = now_ms;
        return entry;
    }
    return NULL;
}

static struct flowd_qoe_entry *qoe_find_exact(struct flowd_qoe_cache *cache,
                                              enum flowd_qoe_scope scope,
                                              uint8_t family,
                                              uint64_t key,
                                              uint16_t policy_prio)
{
    size_t start;
    size_t probe;

    start = (size_t)(qoe_hash(key, (uint8_t)scope, family, policy_prio) &
                     (cache->capacity - 1));
    for (probe = 0; probe < cache->capacity; probe++) {
        size_t slot = (start + probe) & (cache->capacity - 1);
        struct flowd_qoe_entry *entry = &cache->entries[slot];

        if (!entry->generation)
            return NULL;
        if (entry->scope == (uint8_t)scope && entry->family == family &&
            entry->key == key && entry->policy_prio == policy_prio)
            return entry;
    }
    return NULL;
}

uint64_t flowd_qoe_key(uint32_t asn, uint32_t scope_id)
{
    return ((uint64_t)asn << 32) | (uint64_t)scope_id;
}

uint32_t flowd_qoe_country_code_id(const char iso_code[3])
{
    unsigned char a;
    unsigned char b;

    if (!iso_code || !iso_code[0] || !iso_code[1])
        return 0;
    a = (unsigned char)toupper((unsigned char)iso_code[0]);
    b = (unsigned char)toupper((unsigned char)iso_code[1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z')
        return 0;
    return 0x80000000U | ((uint32_t)a << 8) | b;
}

int flowd_qoe_address_set(struct flowd_qoe_address *address,
                          int family,
                          const void *bytes)
{
    size_t length;

    if (!address || !bytes || !qoe_family_valid((uint8_t)family))
        return -1;
    length = family == AF_INET ? 4U : 16U;
    memset(address, 0, sizeof(*address));
    address->family = (uint8_t)family;
    memcpy(address->bytes, bytes, length);
    return 0;
}

int flowd_qoe_address_equal(const struct flowd_qoe_address *left,
                            const struct flowd_qoe_address *right)
{
    size_t length;

    if (!left || !right || left->family != right->family ||
        !qoe_family_valid(left->family))
        return 0;
    length = left->family == AF_INET ? 4U : 16U;
    return memcmp(left->bytes, right->bytes, length) == 0;
}

size_t flowd_qoe_address_length(const struct flowd_qoe_address *address)
{
    if (!address)
        return 0;
    if (address->family == AF_INET)
        return 4;
    if (address->family == AF_INET6)
        return 16;
    return 0;
}

int flowd_qoe_cache_init(struct flowd_qoe_cache *cache, size_t capacity)
{
    if (!cache || !qoe_capacity_ok(capacity))
        return -1;
    memset(cache, 0, sizeof(*cache));
    cache->entries = calloc(capacity, sizeof(*cache->entries));
    if (!cache->entries)
        return -1;
    cache->capacity = capacity;
    return 0;
}

void flowd_qoe_cache_destroy(struct flowd_qoe_cache *cache)
{
    if (!cache)
        return;
    free(cache->entries);
    memset(cache, 0, sizeof(*cache));
}

void flowd_qoe_cache_clear(struct flowd_qoe_cache *cache)
{
    if (!cache || !cache->entries)
        return;
    memset(cache->entries, 0, cache->capacity * sizeof(*cache->entries));
    cache->count = 0;
}

const struct flowd_qoe_entry *flowd_qoe_cache_lookup(
    struct flowd_qoe_cache *cache,
    const struct flowd_qoe_destination *destination,
    uint16_t policy_prio,
    uint64_t now_ms,
    enum flowd_qoe_scope *matched_scope)
{
    struct flowd_qoe_entry *entry = NULL;
    enum flowd_qoe_scope hit_scope = 0;

    if (matched_scope)
        *matched_scope = 0;
    if (!cache || !cache->entries || !destination || !destination->asn ||
        !policy_prio ||
        !qoe_family_valid(destination->family))
        return NULL;
    cache->lookups++;
    if (destination->city_id) {
        entry = qoe_lookup_exact(cache, FLOWD_QOE_SCOPE_CITY,
                                 destination->family,
                                 flowd_qoe_key(destination->asn, destination->city_id),
                                 policy_prio,
                                 now_ms);
        if (entry)
            hit_scope = FLOWD_QOE_SCOPE_CITY;
    }
    if (!entry && destination->country_id) {
        entry = qoe_lookup_exact(cache, FLOWD_QOE_SCOPE_COUNTRY,
                                 destination->family,
                                 flowd_qoe_key(destination->asn, destination->country_id),
                                 policy_prio,
                                 now_ms);
        if (entry)
            hit_scope = FLOWD_QOE_SCOPE_COUNTRY;
    }
    if (!entry) {
        entry = qoe_lookup_exact(cache, FLOWD_QOE_SCOPE_ASN,
                                 destination->family,
                                 flowd_qoe_key(destination->asn, 0),
                                 policy_prio, now_ms);
        if (entry)
            hit_scope = FLOWD_QOE_SCOPE_ASN;
    }
    if (entry) {
        cache->hits++;
        /*
         * hits == sum(hits_by_scope) is the invariant the runtime response
         * self-checks, so both counters must move together on every hit.
         */
        cache->hits_by_scope[hit_scope]++;
        if (matched_scope)
            *matched_scope = hit_scope;
    } else {
        cache->misses++;
    }
    return entry;
}

int flowd_qoe_cache_record(struct flowd_qoe_cache *cache,
                           enum flowd_qoe_scope scope,
                           uint8_t family,
                           uint64_t key,
                           uint16_t policy_prio,
                           const struct flowd_qoe_path *paths,
                           size_t path_count,
                           uint64_t now_ms,
                           uint64_t ttl_ms)
{
    struct flowd_qoe_entry next;
    uint8_t seen[256] = {0};
    size_t slot;
    size_t i;
    int found;
    uint8_t previous_wan = 0;

    if (!cache || !cache->entries || !key || !policy_prio || !paths || !path_count ||
        path_count > FLOWD_QOE_MAX_WANS ||
        scope < FLOWD_QOE_SCOPE_ASN || scope > FLOWD_QOE_SCOPE_CITY ||
        !qoe_family_valid(family))
        return -1;
    memset(&next, 0, sizeof(next));
    next.key = key;
    next.policy_prio = policy_prio;
    next.scope = (uint8_t)scope;
    next.family = family;
    next.learned_at_ms = now_ms;
    next.last_used_ms = now_ms;
    next.valid_until_ms = now_ms + (ttl_ms ? ttl_ms : FLOWD_QOE_DEFAULT_TTL_MS);
    for (i = 0; i < path_count; i++) {
        struct flowd_qoe_path path = paths[i];

        if (!path.wan_id || seen[path.wan_id])
            continue;
        seen[path.wan_id] = 1;
        if (!path.score_us) {
            uint64_t score = (uint64_t)path.rtt_us + path.penalty_us;
            path.score_us = score > UINT32_MAX ? UINT32_MAX : (uint32_t)score;
        }
        next.paths[next.path_count++] = path;
    }
    if (!next.path_count)
        return -1;
    qsort(next.paths, next.path_count, sizeof(next.paths[0]), qoe_path_cmp);
    slot = qoe_find_slot(cache, next.scope, next.family, key, policy_prio,
                         now_ms, &found);
    if (slot == SIZE_MAX)
        return -1;
    if (found && cache->entries[slot].valid_until_ms > now_ms)
        previous_wan = cache->entries[slot].preferred_wan;
    next.preferred_wan = qoe_choose_preferred_wan(&next, previous_wan);
    if (!found && cache->entries[slot].generation) {
        cache->evictions++;
    } else if (!found) {
        cache->count++;
    }
    cache->generation++;
    if (!cache->generation)
        cache->generation++;
    next.generation = cache->generation;
    cache->entries[slot] = next;
    return 0;
}

int flowd_qoe_cache_invalidate(struct flowd_qoe_cache *cache,
                               enum flowd_qoe_scope scope,
                               uint8_t family,
                               uint64_t key,
                               uint16_t policy_prio,
                               uint64_t now_ms)
{
    struct flowd_qoe_entry *entry;

    if (!cache || !cache->entries)
        return -1;
    entry = qoe_find_exact(cache, scope, family, key, policy_prio);
    if (!entry)
        return -1;
    entry->valid_until_ms = now_ms;
    return 0;
}

size_t flowd_qoe_cache_mark_wan_down(struct flowd_qoe_cache *cache,
                                     uint8_t wan_id,
                                     uint64_t now_ms)
{
    size_t changed = 0;
    size_t i;
    size_t j;

    if (!cache || !cache->entries || !wan_id)
        return 0;
    for (i = 0; i < cache->capacity; i++) {
        struct flowd_qoe_entry *entry = &cache->entries[i];

        if (!entry->generation || entry->valid_until_ms <= now_ms)
            continue;
        for (j = 0; j < entry->path_count; j++) {
            if (entry->paths[j].wan_id != wan_id || !entry->paths[j].healthy)
                continue;
            entry->paths[j].healthy = 0;
            changed++;
        }
        if (entry->preferred_wan == wan_id) {
            qsort(entry->paths, entry->path_count, sizeof(entry->paths[0]), qoe_path_cmp);
            entry->preferred_wan = qoe_choose_preferred_wan(entry, 0);
        }
    }
    return changed;
}

void flowd_qoe_token_bucket_init(struct flowd_qoe_token_bucket *bucket,
                                 uint32_t rate_per_s,
                                 uint32_t burst,
                                 uint64_t now_ms)
{
    if (!bucket)
        return;
    memset(bucket, 0, sizeof(*bucket));
    bucket->rate_per_s = rate_per_s;
    bucket->burst = burst;
    bucket->tokens_milli = (uint64_t)burst * 1000ULL;
    bucket->last_refill_ms = now_ms;
}

static void qoe_token_bucket_refill(struct flowd_qoe_token_bucket *bucket,
                                    uint64_t now_ms)
{
    uint64_t cap;
    uint64_t elapsed;
    uint64_t refill;

    if (!bucket || !bucket->rate_per_s || !bucket->burst ||
        now_ms <= bucket->last_refill_ms)
        return;
    cap = (uint64_t)bucket->burst * 1000ULL;
    elapsed = now_ms - bucket->last_refill_ms;
    refill = elapsed > cap / bucket->rate_per_s
        ? cap : elapsed * bucket->rate_per_s;
    bucket->tokens_milli = refill >= cap - bucket->tokens_milli
        ? cap : bucket->tokens_milli + refill;
    bucket->last_refill_ms = now_ms;
}

int flowd_qoe_token_bucket_take(struct flowd_qoe_token_bucket *bucket,
                                uint64_t now_ms)
{
    if (!bucket || !bucket->rate_per_s || !bucket->burst)
        return 0;
    qoe_token_bucket_refill(bucket, now_ms);
    if (bucket->tokens_milli < 1000ULL) {
        bucket->rejected++;
        return 0;
    }
    bucket->tokens_milli -= 1000ULL;
    bucket->accepted++;
    return 1;
}

uint32_t flowd_qoe_token_bucket_available(struct flowd_qoe_token_bucket *bucket,
                                          uint64_t now_ms)
{
    if (!bucket)
        return 0;
    qoe_token_bucket_refill(bucket, now_ms);
    return (uint32_t)(bucket->tokens_milli / 1000ULL);
}
