// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_QOE_CACHE_H
#define DREAMINGWRT_FLOWD_QOE_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define FLOWD_QOE_MAX_WANS 8
#define FLOWD_QOE_DEFAULT_CAPACITY 4096
#define FLOWD_QOE_DEFAULT_TTL_MS (30ULL * 60ULL * 1000ULL)
#define FLOWD_QOE_DEFAULT_PROBE_RATE 20
#define FLOWD_QOE_DEFAULT_PROBE_BURST 40
#define FLOWD_QOE_EQUIVALENT_ABS_US 5000U
#define FLOWD_QOE_EQUIVALENT_PERCENT 20U

enum flowd_qoe_scope {
    FLOWD_QOE_SCOPE_ASN = 1,
    FLOWD_QOE_SCOPE_COUNTRY = 2,
    FLOWD_QOE_SCOPE_CITY = 3,
};

/*
 * Layered hit accounting. flowd_qoe_cache_lookup() already resolves which of
 * the three scopes answered a lookup; these slots keep that information
 * instead of collapsing it into a single hits counter. Index 0 is unused so a
 * scope enum value can index the array directly.
 */
#define FLOWD_QOE_SCOPE_SLOTS (FLOWD_QOE_SCOPE_CITY + 1)

struct flowd_qoe_address {
    uint8_t family;
    uint8_t bytes[16];
};

struct flowd_qoe_destination {
    uint32_t asn;
    uint32_t city_id;
    uint32_t country_id;
    uint8_t family;
};

struct flowd_qoe_path {
    uint8_t wan_id;
    uint8_t healthy;
    uint16_t confidence;
    uint32_t rtt_us;
    uint32_t penalty_us;
    uint32_t score_us;
};

struct flowd_qoe_entry {
    uint64_t key;
    uint64_t learned_at_ms;
    uint64_t last_used_ms;
    uint64_t valid_until_ms;
    uint32_t generation;
    uint8_t scope;
    uint8_t path_count;
    uint8_t preferred_wan;
    uint8_t family;
    uint16_t policy_prio;
    struct flowd_qoe_path paths[FLOWD_QOE_MAX_WANS];
};

struct flowd_qoe_cache {
    struct flowd_qoe_entry *entries;
    size_t capacity;
    size_t count;
    uint64_t lookups;
    uint64_t hits;
    uint64_t hits_by_scope[FLOWD_QOE_SCOPE_SLOTS];
    uint64_t misses;
    uint64_t evictions;
    uint64_t expirations;
    uint32_t generation;
};

struct flowd_qoe_token_bucket {
    uint32_t rate_per_s;
    uint32_t burst;
    uint64_t tokens_milli;
    uint64_t last_refill_ms;
    uint64_t accepted;
    uint64_t rejected;
};

uint64_t flowd_qoe_key(uint32_t asn, uint32_t scope_id);
uint32_t flowd_qoe_country_code_id(const char iso_code[3]);
int flowd_qoe_address_set(struct flowd_qoe_address *address,
                          int family,
                          const void *bytes);
int flowd_qoe_address_equal(const struct flowd_qoe_address *left,
                            const struct flowd_qoe_address *right);
size_t flowd_qoe_address_length(const struct flowd_qoe_address *address);
int flowd_qoe_cache_init(struct flowd_qoe_cache *cache, size_t capacity);
void flowd_qoe_cache_destroy(struct flowd_qoe_cache *cache);
void flowd_qoe_cache_clear(struct flowd_qoe_cache *cache);
const struct flowd_qoe_entry *flowd_qoe_cache_lookup(
    struct flowd_qoe_cache *cache,
    const struct flowd_qoe_destination *destination,
    uint16_t policy_prio,
    uint64_t now_ms,
    enum flowd_qoe_scope *matched_scope);
int flowd_qoe_cache_record(struct flowd_qoe_cache *cache,
                           enum flowd_qoe_scope scope,
                           uint8_t family,
                           uint64_t key,
                           uint16_t policy_prio,
                           const struct flowd_qoe_path *paths,
                           size_t path_count,
                           uint64_t now_ms,
                           uint64_t ttl_ms);
int flowd_qoe_cache_invalidate(struct flowd_qoe_cache *cache,
                               enum flowd_qoe_scope scope,
                               uint8_t family,
                               uint64_t key,
                               uint16_t policy_prio,
                               uint64_t now_ms);
size_t flowd_qoe_cache_mark_wan_down(struct flowd_qoe_cache *cache,
                                     uint8_t wan_id,
                                     uint64_t now_ms);
void flowd_qoe_token_bucket_init(struct flowd_qoe_token_bucket *bucket,
                                 uint32_t rate_per_s,
                                 uint32_t burst,
                                 uint64_t now_ms);
int flowd_qoe_token_bucket_take(struct flowd_qoe_token_bucket *bucket,
                                uint64_t now_ms);
uint32_t flowd_qoe_token_bucket_available(struct flowd_qoe_token_bucket *bucket,
                                          uint64_t now_ms);

#endif
