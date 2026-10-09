/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "client_connections_snapshot.h"

#include "dw_read_model.h"
#include "dw_memory_diagnostics.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <time.h>

extern char *get_app_name_by_id(int id);

#define DW_CC_CONNTRACK_PATH "/proc/net/nf_conntrack"
#define DW_CC_CONNTRACK_FALLBACK "/proc/net/ip_conntrack"
#define DW_CC_DPI_APP_PATH "/proc/dreamingwrt/jmx/af_active_app"
#define DW_CC_DPI_HOST_PATH "/proc/dreamingwrt/jmx/af_active_host"
#define DW_CC_CT_APPID_PATH "/proc/dreamingwrt/jmx/ct_appid"
#define DW_CC_CT_APPID_VERSION 1
#define DW_CC_PERIOD_MS 750U
#define DW_CC_STALE_AFTER_MS 3000U
#define DW_CC_DELTA_SLOTS 64U
#define DW_CC_DELTA_BYTES_MAX (128U * 1024U * 1024U)

/* These short-lived arrays otherwise raise glibc's dynamic mmap threshold and
 * leave burst-sized arenas resident after the ring has returned to normal. */
#define DW_CC_MMAP_MIN_BYTES (256U * 1024U)
static uint64_t g_dw_cc_mapped_bytes;
static uint64_t g_dw_cc_mapped_peak_bytes;

static void dw_cc_mapped_add(size_t bytes)
{
    uint64_t live = __atomic_add_fetch(&g_dw_cc_mapped_bytes, bytes, __ATOMIC_RELAXED);
    uint64_t peak = __atomic_load_n(&g_dw_cc_mapped_peak_bytes, __ATOMIC_RELAXED);
    while (live > peak && !__atomic_compare_exchange_n(
               &g_dw_cc_mapped_peak_bytes, &peak, live, 0,
               __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}

static void *dw_cc_buffer_alloc(size_t bytes, int clear)
{
    void *p;
    if (!bytes)
        return NULL;
    if (bytes < DW_CC_MMAP_MIN_BYTES)
        return clear ? calloc(1, bytes) : malloc(bytes);
    p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    dw_cc_mapped_add(bytes);
    return p;
}

static void dw_cc_buffer_free(void *p, size_t bytes)
{
    if (!p)
        return;
    if (bytes < DW_CC_MMAP_MIN_BYTES) {
        free(p);
    } else {
        munmap(p, bytes);
        __atomic_sub_fetch(&g_dw_cc_mapped_bytes, bytes, __ATOMIC_RELAXED);
    }
}

static void *dw_cc_buffer_grow(void *p, size_t old_bytes, size_t new_bytes)
{
    void *next;
    if (new_bytes < DW_CC_MMAP_MIN_BYTES)
        return realloc(p, new_bytes);
    if (p && old_bytes >= DW_CC_MMAP_MIN_BYTES) {
        next = mremap(p, old_bytes, new_bytes, MREMAP_MAYMOVE);
        if (next == MAP_FAILED)
            return NULL;
        dw_cc_mapped_add(new_bytes - old_bytes);
        return next;
    }
    next = dw_cc_buffer_alloc(new_bytes, 0);
    if (!next)
        return NULL;
    if (p) {
        memcpy(next, p, old_bytes);
        dw_cc_buffer_free(p, old_bytes);
    }
    return next;
}

struct dw_cc_row {
    char id[DW_CC_ID_LEN];
    int family;
    int l4_number;
    char protocol[16];
    char state[24];
    int timeout;
    int zone;
    uint32_t mark;
    int wan_id;
    char original_src[DW_CC_ADDR_LEN];
    char original_dst[DW_CC_ADDR_LEN];
    int original_sport;
    int original_dport;
    char reply_src[DW_CC_ADDR_LEN];
    char reply_dst[DW_CC_ADDR_LEN];
    int reply_sport;
    int reply_dport;
    int icmp_type;
    int icmp_code;
    int icmp_id;
    uint64_t original_bytes;
    uint64_t reply_bytes;
    int app_id;
    char dpi_mac[DW_CC_MAC_LEN];
    char domain[256];
    char app_source[16];
    char external_ip[DW_CC_ADDR_LEN];
};

struct dw_cc_wan_addresses {
    char ipv4[5][DW_CC_ADDR_LEN];
    char ipv6[5][DW_CC_ADDR_LEN];
};

struct dw_cc_source {
    int available;
    int version;
    size_t rows;
    size_t matched;
    size_t scanned;
    size_t appid_bearing;
    size_t exported;
    size_t capacity;
    size_t truncated;
};

struct dw_cc_generation {
    struct dw_cc_source conntrack;
    struct dw_cc_source dpi_app;
    struct dw_cc_source dpi_host;
    struct dw_cc_source ct_appid;
    size_t wan_matched;
    struct dw_cc_row *rows;
    size_t row_count;
    size_t row_capacity;
};

static int dw_cc_wan_id_from_ifname(const char *ifname)
{
    const char *suffix;
    char *end = NULL;
    long id;

    if (!ifname)
        return 0;
    if (!strcmp(ifname, "pppoe-wan") || !strcmp(ifname, "wan"))
        return 1;
    suffix = NULL;
    if (!strncmp(ifname, "pppoe-wan", 9))
        suffix = ifname + 9;
    else if (!strncmp(ifname, "wan", 3))
        suffix = ifname + 3;
    if (!suffix || !*suffix)
        return 0;
    errno = 0;
    id = strtol(suffix, &end, 10);
    if (errno || end == suffix || *end || id < 1 || id > 4)
        return 0;
    return (int)id;
}

static void dw_cc_collect_wan_addresses(struct dw_cc_wan_addresses *addresses)
{
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa;

    if (!addresses)
        return;
    memset(addresses, 0, sizeof(*addresses));
    if (getifaddrs(&ifaddr) != 0)
        return;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        int wan_id;
        char host[INET6_ADDRSTRLEN];

        if (!ifa->ifa_name || !ifa->ifa_addr)
            continue;
        wan_id = dw_cc_wan_id_from_ifname(ifa->ifa_name);
        if (wan_id < 1 || wan_id > 4)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET &&
            !addresses->ipv4[wan_id][0] &&
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                      host, sizeof(host)))
            snprintf(addresses->ipv4[wan_id], DW_CC_ADDR_LEN, "%s", host);
        else if (ifa->ifa_addr->sa_family == AF_INET6 &&
                 !addresses->ipv6[wan_id][0] &&
                 inet_ntop(AF_INET6,
                           &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
                           host, sizeof(host)) &&
                 strncmp(host, "fe80:", 5) != 0)
            snprintf(addresses->ipv6[wan_id], DW_CC_ADDR_LEN, "%s", host);
    }
    freeifaddrs(ifaddr);
}

static void dw_cc_apply_external_ip(struct dw_cc_row *row,
                                    const struct dw_cc_wan_addresses *addresses)
{
    if (!row || !addresses || row->wan_id < 1 || row->wan_id > 4)
        return;
    if (row->family == 6)
        snprintf(row->external_ip, sizeof(row->external_ip), "%s",
                 addresses->ipv6[row->wan_id]);
    else
        snprintf(row->external_ip, sizeof(row->external_ip), "%s",
                 addresses->ipv4[row->wan_id]);
}

/* A previous/deleted row is only used to determine client membership. Keep
 * every address and the MAC, without a second copy of counters/domain/etc. */
struct dw_cc_membership {
    char dpi_mac[DW_CC_MAC_LEN];
    char original_src[DW_CC_ADDR_LEN];
    char original_dst[DW_CC_ADDR_LEN];
    char reply_src[DW_CC_ADDR_LEN];
    char reply_dst[DW_CC_ADDR_LEN];
};

struct dw_cc_removed {
    char id[DW_CC_ID_LEN];
    struct dw_cc_membership membership;
};

struct dw_cc_change {
    struct dw_cc_row current;
    /* NULL with has_previous means membership is unchanged from current. */
    struct dw_cc_membership *previous;
    int has_previous;
};

struct dw_cc_delta {
    struct dw_cc_change *upserts;
    size_t upsert_count;
    struct dw_cc_removed *removed;
    size_t removed_count;
    struct dw_cc_membership *previous_memberships;
    size_t previous_membership_count;
};

struct dw_cc_dpi {
    int family;
    char protocol[16];
    char src[DW_CC_ADDR_LEN];
    char dst[DW_CC_ADDR_LEN];
    int sport;
    int dport;
    int app_id;
    char mac[DW_CC_MAC_LEN];
    char domain[256];
    int from_app;
    int from_host;
};

struct dw_cc_ct_appid {
    int family;
    int zone;
    int proto;
    char src[DW_CC_ADDR_LEN];
    int sport;
    char dst[DW_CC_ADDR_LEN];
    int dport;
    int app_id;
    unsigned int match_status;
    int wan_id;
};

static struct dw_rm_resource *g_dw_cc_resource;
/* The read model has one producer. Reuse one retired row buffer only at the
 * current row capacity; a smaller following generation releases a burst buffer.
 * Readers never see this spare, and destroy joins the producer before cleanup. */
static struct dw_cc_row *g_dw_cc_spare_rows;
static size_t g_dw_cc_spare_row_bytes;
static size_t g_dw_cc_next_row_bytes;

static void dw_cc_spare_rows_free(void)
{
    dw_cc_buffer_free(g_dw_cc_spare_rows,
        __atomic_load_n(&g_dw_cc_spare_row_bytes, __ATOMIC_RELAXED));
    g_dw_cc_spare_rows = NULL;
    __atomic_store_n(&g_dw_cc_spare_row_bytes, 0, __ATOMIC_RELAXED);
}

static void dw_cc_lower(char *value)
{
    unsigned char *p = (unsigned char *)value;

    while (p && *p) {
        *p = (unsigned char)tolower(*p);
        p++;
    }
}

static void dw_cc_normalize_mac(const char *input, char *out, size_t out_len)
{
    size_t i;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!input)
        return;
    snprintf(out, out_len, "%s", input);
    for (i = 0; out[i]; i++)
        out[i] = (char)tolower((unsigned char)out[i]);
}

static int dw_cc_normalize_ip(const char *input, char *out, size_t out_len,
                              int *family)
{
    unsigned char bytes[16];
    char value[DW_CC_ADDR_LEN];
    size_t len;
    int af;

    if (!input || !input[0] || !out || out_len == 0)
        return -1;
    snprintf(value, sizeof(value), "%s", input);
    len = strlen(value);
    if (len >= 2 && value[0] == '[' && value[len - 1] == ']') {
        memmove(value, value + 1, len - 2);
        value[len - 2] = '\0';
    }
    af = strchr(value, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(af, value, bytes) != 1 ||
        !inet_ntop(af, bytes, out, (socklen_t)out_len))
        return -1;
    if (family)
        *family = af == AF_INET6 ? 6 : 4;
    return 0;
}

static int dw_cc_ip_equal(const char *left, const char *right)
{
    unsigned char a[16], b[16];
    int af;

    if (!left || !right || !left[0] || !right[0])
        return 0;
    af = strchr(left, ':') || strchr(right, ':') ? AF_INET6 : AF_INET;
    return inet_pton(af, left, a) == 1 && inet_pton(af, right, b) == 1 &&
           !memcmp(a, b, af == AF_INET6 ? 16 : 4);
}

void dw_cc_filter_init(struct dw_cc_client_filter *filter, const char *mac)
{
    if (!filter)
        return;
    memset(filter, 0, sizeof(*filter));
    dw_cc_normalize_mac(mac, filter->mac, sizeof(filter->mac));
}

int dw_cc_filter_add_address(struct dw_cc_client_filter *filter,
                             const char *address)
{
    char normalized[DW_CC_ADDR_LEN];
    size_t i;

    if (!filter || filter->address_count >= DW_CC_MAX_CLIENT_ADDRS ||
        dw_cc_normalize_ip(address, normalized, sizeof(normalized), NULL) != 0)
        return -1;
    for (i = 0; i < filter->address_count; i++)
        if (dw_cc_ip_equal(filter->addresses[i], normalized))
            return 0;
    snprintf(filter->addresses[filter->address_count], DW_CC_ADDR_LEN,
             "%s", normalized);
    filter->address_count++;
    return 0;
}

static int dw_cc_filter_has_ip(const struct dw_cc_client_filter *filter,
                               const char *address)
{
    size_t i;

    if (!filter || !address || !address[0])
        return 0;
    for (i = 0; i < filter->address_count; i++)
        if (dw_cc_ip_equal(filter->addresses[i], address))
            return 1;
    return 0;
}

static int dw_cc_addresses_match_filter(const char *mac,
                                        const char *original_src,
                                        const char *original_dst,
                                        const char *reply_src,
                                        const char *reply_dst,
                                        const struct dw_cc_client_filter *filter)
{
    if (!filter)
        return 0;
    if (filter->mac[0] && mac[0] && !strcasecmp(filter->mac, mac))
        return 1;
    return dw_cc_filter_has_ip(filter, original_src) ||
           dw_cc_filter_has_ip(filter, original_dst) ||
           dw_cc_filter_has_ip(filter, reply_src) ||
           dw_cc_filter_has_ip(filter, reply_dst);
}

static int dw_cc_row_matches_filter(const struct dw_cc_row *row,
                                    const struct dw_cc_client_filter *filter)
{
    return row && dw_cc_addresses_match_filter(row->dpi_mac,
        row->original_src, row->original_dst, row->reply_src, row->reply_dst,
        filter);
}

static int dw_cc_membership_matches_filter(const struct dw_cc_membership *member,
                                            const struct dw_cc_client_filter *filter)
{
    return dw_cc_addresses_match_filter(member->dpi_mac,
        member->original_src, member->original_dst, member->reply_src,
        member->reply_dst, filter);
}

static int dw_cc_membership_equal(const struct dw_cc_row *a,
                                   const struct dw_cc_row *b)
{
    return !strcmp(a->dpi_mac, b->dpi_mac) &&
           !strcmp(a->original_src, b->original_src) &&
           !strcmp(a->original_dst, b->original_dst) &&
           !strcmp(a->reply_src, b->reply_src) &&
           !strcmp(a->reply_dst, b->reply_dst);
}

static void dw_cc_membership_set(struct dw_cc_membership *member,
                                  const struct dw_cc_row *row)
{
    memcpy(member->dpi_mac, row->dpi_mac, sizeof(member->dpi_mac));
    memcpy(member->original_src, row->original_src, sizeof(member->original_src));
    memcpy(member->original_dst, row->original_dst, sizeof(member->original_dst));
    memcpy(member->reply_src, row->reply_src, sizeof(member->reply_src));
    memcpy(member->reply_dst, row->reply_dst, sizeof(member->reply_dst));
}

static int dw_cc_token_value(const char *line, const char *key,
                             int occurrence, char *out, size_t out_len)
{
    const char *p = line;
    size_t key_len = strlen(key);
    int seen = 0;

    if (!line || !key || !out || out_len == 0)
        return -1;
    while ((p = strstr(p, key)) != NULL) {
        if ((p == line || isspace((unsigned char)p[-1])) &&
            seen++ == occurrence) {
            const char *value = p + key_len;
            size_t len = strcspn(value, " \t\r\n");

            if (len == 0 || len >= out_len)
                return -1;
            memcpy(out, value, len);
            out[len] = '\0';
            return 0;
        }
        p += key_len;
    }
    return -1;
}

static int dw_cc_token_int(const char *line, const char *key, int occurrence,
                           int *value)
{
    char text[32];
    char *end = NULL;
    long parsed;

    if (dw_cc_token_value(line, key, occurrence, text, sizeof(text)) != 0)
        return -1;
    errno = 0;
    parsed = strtol(text, &end, 0);
    if (errno || end == text || *end)
        return -1;
    *value = (int)parsed;
    return 0;
}

static int dw_cc_token_u64(const char *line, const char *key, int occurrence,
                           uint64_t *value)
{
    char text[32];
    char *end = NULL;
    unsigned long long parsed;

    if (dw_cc_token_value(line, key, occurrence, text, sizeof(text)) != 0)
        return -1;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno || end == text || *end)
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static void dw_cc_make_id(struct dw_cc_row *row)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char canonical[512];
    size_t i;

    snprintf(canonical, sizeof(canonical),
             "family=%d|zone=%d|proto=%d|src=%s|sport=%d|dst=%s|dport=%d|"
             "icmp_type=%d|icmp_code=%d|icmp_id=%d",
             row->family, row->zone, row->l4_number,
             row->original_src, row->original_sport,
             row->original_dst, row->original_dport,
             row->icmp_type, row->icmp_code, row->icmp_id);
    SHA256((const unsigned char *)canonical, strlen(canonical), digest);
    memcpy(row->id, "ct:", 3);
    for (i = 0; i < 16; i++)
        snprintf(row->id + 3 + i * 2, sizeof(row->id) - 3 - i * 2,
                 "%02x", digest[i]);
}

static int dw_cc_parse_conntrack_line(const char *line, struct dw_cc_row *row)
{
    char family[8] = "";
    char protocol[16] = "";
    char token5[32] = "";
    char mark_text[32];
    int fields;

    if (!line || !row)
        return -1;
    memset(row, 0, sizeof(*row));
    fields = sscanf(line, "%7s %*d %15s %d %d %31s",
                    family, protocol, &row->l4_number,
                    &row->timeout, token5);
    if (fields < 4 || (strcmp(family, "ipv4") && strcmp(family, "ipv6")))
        return -1;
    row->family = !strcmp(family, "ipv6") ? 6 : 4;
    snprintf(row->protocol, sizeof(row->protocol), "%s", protocol);
    dw_cc_lower(row->protocol);
    if (fields >= 5 && !strchr(token5, '=')) {
        snprintf(row->state, sizeof(row->state), "%.23s", token5);
        dw_cc_lower(row->state);
    }
    if (dw_cc_token_value(line, "src=", 0, row->original_src,
                          sizeof(row->original_src)) != 0 ||
        dw_cc_token_value(line, "dst=", 0, row->original_dst,
                          sizeof(row->original_dst)) != 0 ||
        dw_cc_token_value(line, "src=", 1, row->reply_src,
                          sizeof(row->reply_src)) != 0 ||
        dw_cc_token_value(line, "dst=", 1, row->reply_dst,
                          sizeof(row->reply_dst)) != 0)
        return -1;
    if (dw_cc_normalize_ip(row->original_src, row->original_src,
                           sizeof(row->original_src), NULL) != 0 ||
        dw_cc_normalize_ip(row->original_dst, row->original_dst,
                           sizeof(row->original_dst), NULL) != 0 ||
        dw_cc_normalize_ip(row->reply_src, row->reply_src,
                           sizeof(row->reply_src), NULL) != 0 ||
        dw_cc_normalize_ip(row->reply_dst, row->reply_dst,
                           sizeof(row->reply_dst), NULL) != 0)
        return -1;
    (void)dw_cc_token_int(line, "sport=", 0, &row->original_sport);
    (void)dw_cc_token_int(line, "dport=", 0, &row->original_dport);
    (void)dw_cc_token_int(line, "sport=", 1, &row->reply_sport);
    (void)dw_cc_token_int(line, "dport=", 1, &row->reply_dport);
    (void)dw_cc_token_int(line, "type=", 0, &row->icmp_type);
    (void)dw_cc_token_int(line, "code=", 0, &row->icmp_code);
    (void)dw_cc_token_int(line, "id=", 0, &row->icmp_id);
    (void)dw_cc_token_int(line, "zone=", 0, &row->zone);
    (void)dw_cc_token_u64(line, "bytes=", 0, &row->original_bytes);
    (void)dw_cc_token_u64(line, "bytes=", 1, &row->reply_bytes);
    if (dw_cc_token_value(line, "mark=", 0, mark_text, sizeof(mark_text)) == 0) {
        char *end = NULL;
        unsigned long mark;

        errno = 0;
        mark = strtoul(mark_text, &end, 0);
        if (!errno && end != mark_text && !*end && mark <= UINT32_MAX) {
            row->mark = (uint32_t)mark;
            if ((row->mark >> 16) && (row->mark & 0xffffU))
                row->wan_id = (int)(row->mark & 0xffffU);
        }
    }
    dw_cc_make_id(row);
    return 0;
}

static int dw_cc_parse_ct_appid_line(const char *line,
                                     struct dw_cc_ct_appid *item)
{
    char src[DW_CC_ADDR_LEN];
    char dst[DW_CC_ADDR_LEN];
    unsigned int ct_mark;
    unsigned int route_mark;
    int parsed;

    if (!line || !item)
        return -1;
    memset(item, 0, sizeof(*item));
    parsed = sscanf(line, "%d %d %d %63s %d %63s %d %d %x %d %x %x",
                    &item->family, &item->zone, &item->proto,
                    src, &item->sport, dst, &item->dport, &item->app_id,
                    &item->match_status, &item->wan_id,
                    &ct_mark, &route_mark);
    if (parsed != 12 || (item->family != 4 && item->family != 6) ||
        item->zone < 0 || item->proto < 0 || item->proto > 255 ||
        item->sport < 0 || item->sport > 65535 ||
        item->dport < 0 || item->dport > 65535 || item->app_id <= 0 ||
        dw_cc_normalize_ip(src, item->src, sizeof(item->src), NULL) != 0 ||
        dw_cc_normalize_ip(dst, item->dst, sizeof(item->dst), NULL) != 0)
        return -1;
    if ((item->family == 4 && strchr(item->src, ':')) ||
        (item->family == 6 && !strchr(item->src, ':')) ||
        (item->family == 4 && strchr(item->dst, ':')) ||
        (item->family == 6 && !strchr(item->dst, ':')))
        return -1;
    return 0;
}

static int dw_cc_ct_appid_compare(const void *left, const void *right)
{
    const struct dw_cc_ct_appid *a = left;
    const struct dw_cc_ct_appid *b = right;
    int order;

    if (a->family != b->family)
        return a->family < b->family ? -1 : 1;
    if (a->zone != b->zone)
        return a->zone < b->zone ? -1 : 1;
    if (a->proto != b->proto)
        return a->proto < b->proto ? -1 : 1;
    order = strcmp(a->src, b->src);
    if (order)
        return order;
    if (a->sport != b->sport)
        return a->sport < b->sport ? -1 : 1;
    order = strcmp(a->dst, b->dst);
    if (order)
        return order;
    if (a->dport != b->dport)
        return a->dport < b->dport ? -1 : 1;
    return 0;
}

static int dw_cc_ct_appid_matches_row(const struct dw_cc_ct_appid *item,
                                      const struct dw_cc_row *row)
{
    return item && row && item->family == row->family &&
           item->zone == row->zone && item->proto == row->l4_number &&
           item->sport == row->original_sport &&
           item->dport == row->original_dport &&
           dw_cc_ip_equal(item->src, row->original_src) &&
           dw_cc_ip_equal(item->dst, row->original_dst);
}

static int dw_cc_ct_appid_append(struct dw_cc_ct_appid **items, size_t *count,
                                 size_t *capacity,
                                 const struct dw_cc_ct_appid *item)
{
    struct dw_cc_ct_appid *next;

    if (*count >= *capacity) {
        size_t new_capacity = *capacity ? *capacity * 2 : 128;

        next = realloc(*items, new_capacity * sizeof(**items));
        if (!next)
            return -1;
        *items = next;
        *capacity = new_capacity;
    }
    (*items)[(*count)++] = *item;
    return 0;
}

static int dw_cc_load_ct_appid_from(const char *path,
                                    struct dw_cc_ct_appid **items, size_t *count,
                                    size_t *capacity, struct dw_cc_source *source);

static int dw_cc_load_ct_appid(struct dw_cc_ct_appid **items, size_t *count,
                               size_t *capacity, struct dw_cc_source *source)
{
    return dw_cc_load_ct_appid_from(DW_CC_CT_APPID_PATH, items, count, capacity,
                                    source);
}

static int dw_cc_load_ct_appid_from(const char *path,
                                    struct dw_cc_ct_appid **items, size_t *count,
                                    size_t *capacity, struct dw_cc_source *source)
{
    FILE *fp = fopen(path ? path : DW_CC_CT_APPID_PATH, "r");
    char line[1024];

    memset(source, 0, sizeof(*source));
    if (!fp)
        return -1;
    source->available = 1;
    while (fgets(line, sizeof(line), fp)) {
        struct dw_cc_ct_appid item;
        size_t truncated;

        if (sscanf(line, "# ct_appid_version %d", &source->version) == 1)
            continue;
        if (sscanf(line,
                   "# scanned %zu appid_bearing %zu exported %zu capacity %zu truncated %zu",
                   &source->scanned, &source->appid_bearing,
                   &source->exported, &source->capacity, &truncated) == 5) {
            source->truncated = truncated;
            continue;
        }
        if (line[0] == '#' || !strncmp(line, "family ", 7))
            continue;
        if (dw_cc_parse_ct_appid_line(line, &item) != 0)
            continue;
        if (dw_cc_ct_appid_append(items, count, capacity, &item) != 0) {
            fclose(fp);
            return -1;
        }
        source->rows++;
    }
    fclose(fp);
    if (!source->exported)
        source->exported = source->rows;
    if (!source->appid_bearing)
        source->appid_bearing = source->rows;
    qsort(*items, *count, sizeof(**items), dw_cc_ct_appid_compare);
    return 0;
}

static const struct dw_cc_ct_appid *dw_cc_find_ct_appid(
    const struct dw_cc_ct_appid *items, size_t count,
    const struct dw_cc_row *row)
{
    size_t low = 0;
    size_t high = count;

    while (low < high) {
        size_t middle = low + (high - low) / 2;
        struct dw_cc_ct_appid key;
        int order;

        memset(&key, 0, sizeof(key));
        key.family = row->family;
        key.zone = row->zone;
        key.proto = row->l4_number;
        snprintf(key.src, sizeof(key.src), "%s", row->original_src);
        key.sport = row->original_sport;
        snprintf(key.dst, sizeof(key.dst), "%s", row->original_dst);
        key.dport = row->original_dport;
        order = dw_cc_ct_appid_compare(&items[middle], &key);
        if (order < 0)
            low = middle + 1;
        else
            high = middle;
    }
    if (low < count && dw_cc_ct_appid_matches_row(&items[low], row))
        return &items[low];
    return NULL;
}

static int dw_cc_apply_ct_appid(struct dw_cc_row *row,
                                const struct dw_cc_ct_appid *item,
                                struct dw_cc_source *source)
{
    if (!dw_cc_ct_appid_matches_row(item, row))
        return 0;
    if (source)
        source->matched++;
    if (item->wan_id > 0)
        row->wan_id = item->wan_id;
    if ((item->match_status & 0x4U) && !(item->match_status & 0x1U)) {
        row->app_id = item->app_id;
        snprintf(row->app_source, sizeof(row->app_source), "ct_appid");
    }
    return 1;
}

/*
 * Shared ct_appid view for consumers outside this file.
 *
 * The realtime rich-flow producer used to ignore the kernel export entirely and
 * reported app_id=0 for tuples the kernel had already classified.  It now reads
 * the same table through these accessors, so the parser, the sort order, the
 * version gate and the "reliable" bit rule cannot drift between the compact
 * snapshot and the rich flow list.
 */
struct dw_ct_appid_table {
    struct dw_cc_ct_appid *items;
    size_t count;
};

struct dw_ct_appid_table *dw_ct_appid_table_load(struct dw_ct_appid_stats *stats)
{
    return dw_ct_appid_table_load_path(NULL, stats);
}

struct dw_ct_appid_table *dw_ct_appid_table_load_path(const char *path,
                                                     struct dw_ct_appid_stats *stats)
{
    struct dw_ct_appid_table *table;
    struct dw_cc_source source;
    size_t capacity = 0;

    if (stats)
        memset(stats, 0, sizeof(*stats));
    table = calloc(1, sizeof(*table));
    if (!table)
        return NULL;
    if (dw_cc_load_ct_appid_from(path ? path : DW_CC_CT_APPID_PATH,
                                 &table->items, &table->count, &capacity,
                                 &source) != 0) {
        free(table->items);
        free(table);
        if (stats)
            stats->available = source.available;
        return NULL;
    }
    if (stats) {
        stats->available = source.available;
        stats->version = source.version;
        stats->version_supported = source.version == DW_CC_CT_APPID_VERSION;
        stats->rows = source.rows;
        stats->scanned = source.scanned;
        stats->appid_bearing = source.appid_bearing;
        stats->exported = source.exported;
        stats->capacity = source.capacity;
        stats->truncated = source.truncated;
    }
    if (source.version != DW_CC_CT_APPID_VERSION) {
        /* Unknown layout: keep the counters, refuse to attribute from it. */
        free(table->items);
        table->items = NULL;
        table->count = 0;
    }
    return table;
}

void dw_ct_appid_table_free(struct dw_ct_appid_table *table)
{
    if (!table)
        return;
    free(table->items);
    free(table);
}

size_t dw_ct_appid_table_rows(const struct dw_ct_appid_table *table)
{
    return table ? table->count : 0;
}

int dw_ct_appid_table_lookup(const struct dw_ct_appid_table *table,
                             int family, int zone, int proto,
                             const char *src, int sport,
                             const char *dst, int dport,
                             struct dw_ct_appid_evidence *out)
{
    struct dw_cc_ct_appid key;
    size_t low = 0;
    size_t high;

    if (out)
        memset(out, 0, sizeof(*out));
    if (!table || !table->count || !src || !dst)
        return 0;
    memset(&key, 0, sizeof(key));
    key.family = family;
    key.zone = zone;
    key.proto = proto;
    key.sport = sport;
    key.dport = dport;
    if (dw_cc_normalize_ip(src, key.src, sizeof(key.src), NULL) != 0 ||
        dw_cc_normalize_ip(dst, key.dst, sizeof(key.dst), NULL) != 0)
        return 0;
    high = table->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;

        if (dw_cc_ct_appid_compare(&table->items[middle], &key) < 0)
            low = middle + 1;
        else
            high = middle;
    }
    if (low >= table->count || dw_cc_ct_appid_compare(&table->items[low], &key) != 0)
        return 0;
    if (out) {
        const struct dw_cc_ct_appid *item = &table->items[low];

        out->app_id = item->app_id;
        out->match_status = item->match_status;
        out->wan_id = item->wan_id;
        out->reliable = (item->match_status & 0x4U) && !(item->match_status & 0x1U);
    }
    return 1;
}

static int dw_cc_dpi_tuple_equal(const struct dw_cc_dpi *dpi,
                                 const struct dw_cc_row *row)
{
    return dpi && row && dpi->family == row->family &&
           !strcasecmp(dpi->protocol, row->protocol) &&
           dpi->sport == row->original_sport &&
           dpi->dport == row->original_dport &&
           dw_cc_ip_equal(dpi->src, row->original_src) &&
           dw_cc_ip_equal(dpi->dst, row->original_dst);
}

static int dw_cc_dpi_append(struct dw_cc_dpi **items, size_t *count,
                            size_t *capacity, const struct dw_cc_dpi *item)
{
    struct dw_cc_dpi *next;

    if (*count >= *capacity) {
        size_t new_capacity = *capacity ? *capacity * 2 : 128;

        next = realloc(*items, new_capacity * sizeof(**items));
        if (!next)
            return -1;
        *items = next;
        *capacity = new_capacity;
    }
    (*items)[(*count)++] = *item;
    return 0;
}

static int dw_cc_load_dpi_file(const char *path, int is_app,
                               struct dw_cc_dpi **items, size_t *count,
                               size_t *capacity, struct dw_cc_source *source)
{
    FILE *fp = fopen(path, "r");
    char line[2048];

    memset(source, 0, sizeof(*source));
    if (!fp)
        return -1;
    source->available = 1;
    while (fgets(line, sizeof(line), fp)) {
        struct dw_cc_dpi dpi;
        char src[DW_CC_ADDR_LEN], dst[DW_CC_ADDR_LEN];
        char protocol[16], domain[256], mac[DW_CC_MAC_LEN];
        int parsed;

        if (strstr(line, is_app ? "AppID" : "Host") && strstr(line, "MAC"))
            continue;
        memset(&dpi, 0, sizeof(dpi));
        if (is_app) {
            parsed = sscanf(line, "%d %31s %63s %d %63s %d %15s %*d %*d %255s",
                            &dpi.app_id, mac, src, &dpi.sport, dst, &dpi.dport,
                            protocol, domain);
            if (parsed < 8)
                continue;
            dpi.from_app = 1;
        } else {
            parsed = sscanf(line, "%255s %31s %63s %d %63s %d %15s",
                            domain, mac, src, &dpi.sport, dst, &dpi.dport,
                            protocol);
            if (parsed < 7)
                continue;
            dpi.from_host = 1;
        }
        if (dw_cc_normalize_ip(src, dpi.src, sizeof(dpi.src), &dpi.family) != 0 ||
            dw_cc_normalize_ip(dst, dpi.dst, sizeof(dpi.dst), NULL) != 0)
            continue;
        snprintf(dpi.protocol, sizeof(dpi.protocol), "%s", protocol);
        dw_cc_lower(dpi.protocol);
        dw_cc_normalize_mac(mac, dpi.mac, sizeof(dpi.mac));
        if (strcmp(domain, "-"))
            snprintf(dpi.domain, sizeof(dpi.domain), "%s", domain);
        if (dw_cc_dpi_append(items, count, capacity, &dpi) != 0) {
            fclose(fp);
            return -1;
        }
        source->rows++;
    }
    fclose(fp);
    return 0;
}

static void dw_cc_enrich_row(struct dw_cc_row *row,
                             const struct dw_cc_dpi *dpi, size_t dpi_count,
                             struct dw_cc_source *app_source,
                             struct dw_cc_source *host_source,
                             const struct dw_cc_ct_appid *ct_appid,
                             size_t ct_appid_count,
                             struct dw_cc_source *ct_source)
{
    size_t i;
    int app_matched = 0;
    int host_matched = 0;
    const struct dw_cc_ct_appid *exact = dw_cc_find_ct_appid(
        ct_appid, ct_appid_count, row);

    if (exact)
        (void)dw_cc_apply_ct_appid(row, exact, ct_source);

    for (i = 0; i < dpi_count; i++) {
        if (!dw_cc_dpi_tuple_equal(&dpi[i], row))
            continue;
        if (!row->dpi_mac[0] && dpi[i].mac[0])
            snprintf(row->dpi_mac, sizeof(row->dpi_mac), "%s", dpi[i].mac);
        if (dpi[i].from_app && !app_matched && !row->app_source[0]) {
            row->app_id = dpi[i].app_id;
            snprintf(row->app_source, sizeof(row->app_source), "af_active_app");
            if (dpi[i].domain[0] && !row->domain[0])
                snprintf(row->domain, sizeof(row->domain), "%s", dpi[i].domain);
            app_source->matched++;
            app_matched = 1;
        }
        if (dpi[i].from_host && !host_matched) {
            if (dpi[i].domain[0])
                snprintf(row->domain, sizeof(row->domain), "%s", dpi[i].domain);
            host_source->matched++;
            host_matched = 1;
        }
    }
}

static int dw_cc_row_compare(const void *left, const void *right)
{
    const struct dw_cc_row *a = left;
    const struct dw_cc_row *b = right;

    return strcmp(a->id, b->id);
}

static int dw_cc_row_equal(const struct dw_cc_row *a,
                           const struct dw_cc_row *b)
{
    if (!a || !b)
        return 0;

    /* Only fields affecting the compact row or client membership belong here. */
    return !strcmp(a->id, b->id) &&
           a->family == b->family &&
           !strcmp(a->protocol, b->protocol) &&
           !strcmp(a->state, b->state) &&
           a->wan_id == b->wan_id &&
           !strcmp(a->original_src, b->original_src) &&
           !strcmp(a->original_dst, b->original_dst) &&
           a->original_sport == b->original_sport &&
           a->original_dport == b->original_dport &&
           !strcmp(a->reply_src, b->reply_src) &&
           !strcmp(a->reply_dst, b->reply_dst) &&
           a->reply_sport == b->reply_sport &&
           a->reply_dport == b->reply_dport &&
           a->original_bytes == b->original_bytes &&
           a->reply_bytes == b->reply_bytes &&
           a->app_id == b->app_id &&
           !strcmp(a->dpi_mac, b->dpi_mac) &&
           !strcmp(a->domain, b->domain) &&
           !strcmp(a->external_ip, b->external_ip);
}

static void dw_cc_generation_free(void *context, void *generation_ptr)
{
    struct dw_cc_generation *generation = generation_ptr;

    (void)context;
    if (!generation)
        return;
    size_t bytes = generation->row_capacity * sizeof(*generation->rows);
    if (g_dw_cc_resource && generation->rows && !g_dw_cc_spare_rows &&
        bytes >= DW_CC_MMAP_MIN_BYTES && bytes == g_dw_cc_next_row_bytes) {
        g_dw_cc_spare_rows = generation->rows;
        __atomic_store_n(&g_dw_cc_spare_row_bytes, bytes, __ATOMIC_RELAXED);
    } else {
        dw_cc_buffer_free(generation->rows, bytes);
    }
    free(generation);
}

static int dw_cc_collect(void *context, struct dw_rm_collect_result *result)
{
    struct dw_cc_generation *generation = calloc(1, sizeof(*generation));
    struct dw_cc_dpi *dpi = NULL;
    struct dw_cc_ct_appid *ct_appid = NULL;
    size_t dpi_count = 0, dpi_capacity = 0, row_capacity = 0;
    size_t ct_appid_count = 0, ct_appid_capacity = 0;
    static size_t previous_row_count;
    size_t initial_capacity = 128;
    struct dw_cc_wan_addresses wan_addresses;
    FILE *fp = NULL;
    char line[4096];

    (void)context;
    while (initial_capacity < previous_row_count) initial_capacity *= 2;
    dw_cc_collect_wan_addresses(&wan_addresses);
    if (!generation || !result) {
        free(generation);
        return -1;
    }
    if (g_dw_cc_spare_rows) {
        size_t bytes = initial_capacity * sizeof(*generation->rows);
        if (__atomic_load_n(&g_dw_cc_spare_row_bytes, __ATOMIC_RELAXED) == bytes) {
            generation->rows = g_dw_cc_spare_rows;
            generation->row_capacity = row_capacity = initial_capacity;
            g_dw_cc_spare_rows = NULL;
            __atomic_store_n(&g_dw_cc_spare_row_bytes, 0, __ATOMIC_RELAXED);
        } else {
            dw_cc_spare_rows_free();
        }
    }
    (void)dw_cc_load_dpi_file(DW_CC_DPI_APP_PATH, 1, &dpi, &dpi_count,
                              &dpi_capacity, &generation->dpi_app);
    (void)dw_cc_load_dpi_file(DW_CC_DPI_HOST_PATH, 0, &dpi, &dpi_count,
                              &dpi_capacity, &generation->dpi_host);
    (void)dw_cc_load_ct_appid(&ct_appid, &ct_appid_count, &ct_appid_capacity,
                              &generation->ct_appid);
    if (generation->ct_appid.version != DW_CC_CT_APPID_VERSION)
        ct_appid_count = 0;
    fp = fopen(DW_CC_CONNTRACK_PATH, "r");
    if (!fp)
        fp = fopen(DW_CC_CONNTRACK_FALLBACK, "r");
    if (fp) {
        generation->conntrack.available = 1;
        while (fgets(line, sizeof(line), fp)) {
            struct dw_cc_row row;

            generation->conntrack.rows++;
            if (dw_cc_parse_conntrack_line(line, &row) != 0)
                continue;
            dw_cc_enrich_row(&row, dpi, dpi_count, &generation->dpi_app,
                             &generation->dpi_host, ct_appid, ct_appid_count,
                             &generation->ct_appid);
            dw_cc_apply_external_ip(&row, &wan_addresses);
            if (row.wan_id > 0)
                generation->wan_matched++;
            if (generation->row_count >= row_capacity) {
                struct dw_cc_row *next;
                size_t new_capacity = row_capacity ? row_capacity * 2 : initial_capacity;

                next = dw_cc_buffer_grow(generation->rows,
                               row_capacity * sizeof(*generation->rows),
                               new_capacity * sizeof(*generation->rows));
                if (!next) {
                    fclose(fp);
                    free(dpi);
                    free(ct_appid);
                    dw_cc_buffer_free(generation->rows,
                        generation->row_capacity * sizeof(*generation->rows));
                    free(generation);
                    return -1;
                }
                generation->rows = next;
                row_capacity = new_capacity;
                generation->row_capacity = row_capacity;
            }
            generation->rows[generation->row_count++] = row;
        }
        fclose(fp);
    }
    free(dpi);
    free(ct_appid);
    if (generation->row_count > 1)
        qsort(generation->rows, generation->row_count, sizeof(*generation->rows),
              dw_cc_row_compare);
    generation->row_capacity = row_capacity;
    previous_row_count = generation->row_count;
    initial_capacity = 128;
    while (initial_capacity < previous_row_count) initial_capacity *= 2;
    g_dw_cc_next_row_bytes = previous_row_count ?
        initial_capacity * sizeof(*generation->rows) : 0;
    if (!previous_row_count) {
        dw_cc_buffer_free(generation->rows,
            generation->row_capacity * sizeof(*generation->rows));
        generation->rows = NULL;
        generation->row_capacity = 0;
    }
    result->generation = generation;
    result->observed_at = (int64_t)time(NULL);
    result->complete = generation->conntrack.available;
    result->scanned_rows = generation->conntrack.rows;
    return 0;
}

static void dw_cc_delta_free(void *context, void *delta_ptr)
{
    struct dw_cc_delta *delta = delta_ptr;

    (void)context;
    if (!delta)
        return;
    dw_cc_buffer_free(delta->upserts,
                       delta->upsert_count * sizeof(*delta->upserts));
    dw_cc_buffer_free(delta->removed,
                       delta->removed_count * sizeof(*delta->removed));
    dw_cc_buffer_free(delta->previous_memberships,
        delta->previous_membership_count * sizeof(*delta->previous_memberships));
    free(delta);
}

static int dw_cc_diff(void *context, const void *previous_ptr,
                      const void *current_ptr, void **delta_out,
                      size_t *delta_bytes)
{
    const struct dw_cc_generation *previous = previous_ptr;
    const struct dw_cc_generation *current = current_ptr;
    struct dw_cc_delta *delta;
    size_t old_index = 0, new_index = 0;

    (void)context;
    if (!previous || !current || !delta_out || !delta_bytes)
        return -1;
    delta = calloc(1, sizeof(*delta));
    if (!delta)
        return -1;
    while (old_index < previous->row_count || new_index < current->row_count) {
        int order;

        if (old_index >= previous->row_count)
            order = 1;
        else if (new_index >= current->row_count)
            order = -1;
        else
            order = strcmp(previous->rows[old_index].id,
                           current->rows[new_index].id);
        if (order < 0) {
            delta->removed_count++;
            old_index++;
        } else if (order > 0) {
            delta->upsert_count++;
            new_index++;
        } else {
            if (!dw_cc_row_equal(&previous->rows[old_index],
                                 &current->rows[new_index])) {
                delta->upsert_count++;
                if (!dw_cc_membership_equal(&previous->rows[old_index],
                                             &current->rows[new_index]))
                    delta->previous_membership_count++;
            }
            old_index++;
            new_index++;
        }
    }
    delta->upserts = dw_cc_buffer_alloc(
        delta->upsert_count * sizeof(*delta->upserts), 1);
    delta->removed = dw_cc_buffer_alloc(
        delta->removed_count * sizeof(*delta->removed), 1);
    delta->previous_memberships = dw_cc_buffer_alloc(
        delta->previous_membership_count * sizeof(*delta->previous_memberships), 0);
    if ((delta->upsert_count && !delta->upserts) ||
        (delta->removed_count && !delta->removed) ||
        (delta->previous_membership_count && !delta->previous_memberships)) {
        dw_cc_delta_free(NULL, delta);
        return -1;
    }
    delta->upsert_count = 0;
    delta->removed_count = 0;
    delta->previous_membership_count = 0;
    old_index = 0;
    new_index = 0;
    while (old_index < previous->row_count || new_index < current->row_count) {
        int order;

        if (old_index >= previous->row_count)
            order = 1;
        else if (new_index >= current->row_count)
            order = -1;
        else
            order = strcmp(previous->rows[old_index].id,
                           current->rows[new_index].id);
        if (order < 0) {
            struct dw_cc_removed *removed =
                &delta->removed[delta->removed_count++];
            const struct dw_cc_row *row = &previous->rows[old_index++];
            memcpy(removed->id, row->id, sizeof(removed->id));
            dw_cc_membership_set(&removed->membership, row);
        } else if (order > 0) {
            delta->upserts[delta->upsert_count++].current =
                current->rows[new_index++];
        } else {
            if (!dw_cc_row_equal(&previous->rows[old_index],
                                 &current->rows[new_index])) {
                struct dw_cc_change *change =
                    &delta->upserts[delta->upsert_count++];

                change->current = current->rows[new_index];
                if (!dw_cc_membership_equal(&previous->rows[old_index],
                                             &current->rows[new_index])) {
                    change->previous = &delta->previous_memberships[
                        delta->previous_membership_count++];
                    dw_cc_membership_set(change->previous,
                                          &previous->rows[old_index]);
                }
                change->has_previous = 1;
            }
            old_index++;
            new_index++;
        }
    }
    *delta_bytes = sizeof(*delta) +
                   delta->upsert_count * sizeof(*delta->upserts) +
                   delta->removed_count * sizeof(*delta->removed) +
                   delta->previous_membership_count * sizeof(*delta->previous_memberships);
    *delta_out = delta;
    return 0;
}

int dw_cc_snapshot_start(void)
{
    struct dw_rm_config config;

    if (g_dw_cc_resource)
        return 0;
    memset(&config, 0, sizeof(config));
    config.name = "client_connections";
    config.contract = "client-connections.v2";
    config.memory_profile = 1;
    config.period_ms = DW_CC_PERIOD_MS;
    config.stale_after_ms = DW_CC_STALE_AFTER_MS;
    config.ring_slots = DW_CC_DELTA_SLOTS;
    config.ring_bytes_max = DW_CC_DELTA_BYTES_MAX;
    config.ops.collect = dw_cc_collect;
    config.ops.free_generation = dw_cc_generation_free;
    config.ops.diff = dw_cc_diff;
    config.ops.free_delta = dw_cc_delta_free;
    if (dw_rm_create(&config, &g_dw_cc_resource) != 0)
        return -1;
    if (dw_rm_start(g_dw_cc_resource) != 0) {
        dw_rm_destroy(g_dw_cc_resource);
        g_dw_cc_resource = NULL;
        return -1;
    }
    return 0;
}

void dw_cc_snapshot_stop(void)
{
    if (!g_dw_cc_resource)
        return;
    dw_rm_destroy(g_dw_cc_resource);
    g_dw_cc_resource = NULL;
    dw_cc_spare_rows_free();
    g_dw_cc_next_row_bytes = 0;
}

static struct json_object *dw_cc_columns_json(void)
{
    static const char *columns[] = {
        "id", "family", "protocol", "state", "source_port",
        "destination_ip", "destination_port", "external_ip", "app_id",
        "app_name", "category_key", "wan_id", "domain", "up_bytes",
        "down_bytes"
    };
    struct json_object *array = json_object_new_array();
    size_t i;

    for (i = 0; i < sizeof(columns) / sizeof(columns[0]); i++)
        json_object_array_add(array, json_object_new_string(columns[i]));
    return array;
}

static int dw_cc_row_client_is_source(const struct dw_cc_row *row,
                                      const struct dw_cc_client_filter *filter)
{
    if (dw_cc_filter_has_ip(filter, row->original_src))
        return 1;
    if (dw_cc_filter_has_ip(filter, row->original_dst))
        return 0;
    if (filter->mac[0] && row->dpi_mac[0] &&
        !strcasecmp(filter->mac, row->dpi_mac))
        return 1;
    return dw_cc_filter_has_ip(filter, row->reply_dst);
}

static void dw_cc_service_category(const char *protocol, int port,
                                   char *app_name, size_t app_name_len,
                                   char *category_key, size_t category_key_len)
{
    const char *name = "";
    const char *key = "unknown_application";

    if (protocol && !strcasecmp(protocol, "icmp")) {
        name = "ICMP 服务";
        key = "service_icmp";
    } else if (protocol && !strcasecmp(protocol, "tcp")) {
        switch (port) {
        case 22: name = "SSH 服务"; key = "service_ssh"; break;
        case 25: case 465: case 587:
            name = "邮件发送服务"; key = "service_smtp"; break;
        case 53: name = "DNS 服务"; key = "service_dns"; break;
        case 80: case 8080:
            name = "HTTP 服务"; key = "service_http"; break;
        case 110: case 995:
            name = "邮件接收服务"; key = "service_pop3"; break;
        case 123: name = "NTP 服务"; key = "service_ntp"; break;
        case 143: case 993:
            name = "邮件接收服务"; key = "service_imap"; break;
        case 443: case 8443:
            name = "TLS/HTTPS 服务"; key = "service_https"; break;
        case 853: name = "加密 DNS 服务"; key = "service_dot"; break;
        case 5228: name = "推送连接服务"; key = "service_push"; break;
        default: break;
        }
    } else if (protocol && !strcasecmp(protocol, "udp")) {
        switch (port) {
        case 53: name = "DNS 服务"; key = "service_dns"; break;
        case 67: case 68:
            name = "DHCP 服务"; key = "service_dhcp"; break;
        case 123: name = "NTP 服务"; key = "service_ntp"; break;
        case 443: case 8443:
            name = "QUIC/HTTP3 服务"; key = "service_quic"; break;
        case 500: case 4500:
            name = "IPsec VPN 服务"; key = "service_ipsec"; break;
        case 853: name = "加密 DNS 服务"; key = "service_doq"; break;
        case 5353: name = "mDNS 服务"; key = "service_mdns"; break;
        default: break;
        }
    }
    if (app_name && app_name_len)
        snprintf(app_name, app_name_len, "%s", name);
    if (category_key && category_key_len)
        snprintf(category_key, category_key_len, "%s", key);
}

static struct json_object *dw_cc_row_json(const struct dw_cc_row *row,
                                          const struct dw_cc_client_filter *filter)
{
    struct json_object *array = json_object_new_array();
    int source = dw_cc_row_client_is_source(row, filter);
    const char *destination_ip = source ? row->original_dst : row->original_src;
    int source_port = source ? row->original_sport : row->original_dport;
    int destination_port = source ? row->original_dport : row->original_sport;
    const char *external_ip = row->external_ip;
    char app_name[64] = "";
    char wan_id[16] = "";
    char category_key[32] = "unknown_application";

    /*
     * external_ip is the local address selected for the connection's WAN,
     * not a value guessed from the reply tuple.  NATed TCP entries often keep
     * only the LAN-side reply tuple, while UDP and IPv6 may expose a different
     * shape; using the per-WAN address cache keeps the column semantically
     * stable across protocols and conntrack phases.
     */
    (void)source;
    if (row->app_id > 0) {
        const char *resolved = get_app_name_by_id(row->app_id);

        if (resolved && resolved[0] && strcasecmp(resolved, "unknown"))
            snprintf(app_name, sizeof(app_name), "%s", resolved);
    }
    if (row->wan_id == 1)
        snprintf(wan_id, sizeof(wan_id), "wan");
    else if (row->wan_id > 1)
        snprintf(wan_id, sizeof(wan_id), "wan%d", row->wan_id);
    if (row->app_id > 0 && app_name[0])
        snprintf(category_key, sizeof(category_key), "app_%d", row->app_id);
    else
        dw_cc_service_category(row->protocol, destination_port,
                               app_name, sizeof(app_name),
                               category_key, sizeof(category_key));
    json_object_array_add(array, json_object_new_string(row->id));
    json_object_array_add(array, json_object_new_int(row->family));
    json_object_array_add(array, json_object_new_string(row->protocol));
    json_object_array_add(array, json_object_new_string(row->state));
    json_object_array_add(array, json_object_new_int(source_port));
    json_object_array_add(array, json_object_new_string(destination_ip));
    json_object_array_add(array, json_object_new_int(destination_port));
    json_object_array_add(array, json_object_new_string(external_ip));
    json_object_array_add(array, json_object_new_int(row->app_id));
    json_object_array_add(array, json_object_new_string(app_name));
    json_object_array_add(array, json_object_new_string(category_key));
    json_object_array_add(array, json_object_new_string(wan_id));
    json_object_array_add(array, json_object_new_string(row->domain));
    json_object_array_add(array, json_object_new_int64((int64_t)(source ?
        row->original_bytes : row->reply_bytes)));
    json_object_array_add(array, json_object_new_int64((int64_t)(source ?
        row->reply_bytes : row->original_bytes)));
    return array;
}

int dw_cc_test_service_category(const char *protocol, int port,
                                char *app_name, size_t app_name_len,
                                char *category_key, size_t category_key_len)
{
    dw_cc_service_category(protocol, port, app_name, app_name_len,
                           category_key, category_key_len);
    return category_key && category_key[0] &&
           strcmp(category_key, "unknown_application") != 0;
}

static const char *dw_cc_source_state(const struct dw_cc_source *source,
                                      int allow_partial)
{
    if (!source->available)
        return "unavailable";
    if (!source->rows)
        return "empty";
    if (allow_partial && source->matched < source->rows)
        return "partial";
    return "ready";
}

static const char *dw_cc_ct_appid_state(const struct dw_cc_source *source)
{
    if (!source->available)
        return "unavailable";
    if (source->version != DW_CC_CT_APPID_VERSION)
        return "unsupported";
    if (!source->rows)
        return "empty";
    if (source->truncated)
        return "partial";
    return "ready";
}

static struct json_object *dw_cc_source_json(const struct dw_cc_source *source,
                                             int allow_partial)
{
    struct json_object *object = json_object_new_object();

    json_object_object_add(object, "state", json_object_new_string(
        dw_cc_source_state(source, allow_partial)));
    json_object_object_add(object, "rows",
                           json_object_new_int64((int64_t)source->rows));
    if (allow_partial)
        json_object_object_add(object, "matched",
                               json_object_new_int64((int64_t)source->matched));
    return object;
}

static struct json_object *dw_cc_ct_appid_source_json(
    const struct dw_cc_source *source)
{
    struct json_object *object = json_object_new_object();

    json_object_object_add(object, "state", json_object_new_string(
        dw_cc_ct_appid_state(source)));
    json_object_object_add(object, "version", json_object_new_int(source->version));
    json_object_object_add(object, "scanned", json_object_new_int64(
        (int64_t)source->scanned));
    json_object_object_add(object, "appid_bearing", json_object_new_int64(
        (int64_t)source->appid_bearing));
    json_object_object_add(object, "exported", json_object_new_int64(
        (int64_t)source->exported));
    json_object_object_add(object, "capacity", json_object_new_int64(
        (int64_t)source->capacity));
    json_object_object_add(object, "truncated", json_object_new_int64(
        (int64_t)source->truncated));
    json_object_object_add(object, "rows", json_object_new_int64(
        (int64_t)source->rows));
    json_object_object_add(object, "matched", json_object_new_int64(
        (int64_t)source->matched));
    return object;
}

static struct json_object *dw_cc_client_json(
    const struct dw_cc_client_filter *filter)
{
    struct json_object *client = json_object_new_object();
    struct json_object *addresses = json_object_new_array();
    size_t i;

    json_object_object_add(client, "mac", json_object_new_string(
        filter && filter->mac[0] ? filter->mac : ""));
    if (filter)
        for (i = 0; i < filter->address_count; i++)
            json_object_array_add(addresses,
                                  json_object_new_string(filter->addresses[i]));
    json_object_object_add(client, "addresses", addresses);
    return client;
}

static void dw_cc_add_common_meta(struct json_object *root,
                                  const struct dw_rm_view *view,
                                  const struct dw_cc_client_filter *filter)
{
    json_object_object_add(root, "contract",
                           json_object_new_string(view->contract));
    json_object_object_add(root, "format", json_object_new_string("columns"));
    json_object_object_add(root, "snapshot_id",
                           json_object_new_string(view->snapshot_id));
    json_object_object_add(root, "revision",
                           json_object_new_int64((int64_t)view->revision));
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(view->observed_at));
    json_object_object_add(root, "stale", json_object_new_boolean(view->stale));
    if (filter)
        json_object_object_add(root, "client", dw_cc_client_json(filter));
}

static struct json_object *dw_cc_building_json(
    const struct dw_rm_view *view, const struct dw_cc_client_filter *filter)
{
    struct json_object *root = json_object_new_object();
    struct json_object *sources = json_object_new_object();
    struct json_object *reasons = json_object_new_array();
    static const char *names[] = {
        "conntrack", "ct_appid", "dpi_app", "dpi_host", "wan_attribution"
    };
    size_t i;

    dw_cc_add_common_meta(root, view, filter);
    json_object_object_add(root, "columns", dw_cc_columns_json());
    json_object_object_add(root, "rows", json_object_new_array());
    json_object_object_add(root, "total", json_object_new_int(0));
    json_object_object_add(root, "complete", json_object_new_boolean(0));
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        struct json_object *source = json_object_new_object();

        json_object_object_add(source, "state", json_object_new_string("building"));
        json_object_object_add(source, "rows", json_object_new_int(0));
        json_object_object_add(sources, names[i], source);
    }
    json_object_object_add(root, "source_state", sources);
    json_object_object_add(root, "degraded", json_object_new_boolean(1));
    json_object_array_add(reasons, json_object_new_string("snapshot_building"));
    json_object_object_add(root, "degraded_reasons", reasons);
    return root;
}

struct json_object *dw_cc_snapshot_json(const struct dw_cc_client_filter *filter,
                                        int *result_code)
{
    struct dw_rm_view view;
    const struct dw_cc_generation *generation;
    struct json_object *root, *rows, *sources, *reasons;
    size_t i, total = 0;
    int degraded;

    if (result_code)
        *result_code = 0;
    if (!g_dw_cc_resource) {
        if (result_code)
            *result_code = -ENODEV;
        return NULL;
    }
    if (dw_rm_view_begin(g_dw_cc_resource, &view) != 0) {
        root = dw_cc_building_json(&view, filter);
        dw_rm_view_end(&view);
        return root;
    }
    generation = view.generation;
    root = json_object_new_object();
    rows = json_object_new_array();
    sources = json_object_new_object();
    reasons = json_object_new_array();
    for (i = 0; i < generation->row_count; i++) {
        if (!dw_cc_row_matches_filter(&generation->rows[i], filter))
            continue;
        json_object_array_add(rows, dw_cc_row_json(&generation->rows[i], filter));
        total++;
    }
    degraded = !generation->conntrack.available ||
               !generation->ct_appid.available ||
               generation->ct_appid.version != DW_CC_CT_APPID_VERSION ||
               generation->ct_appid.truncated > 0 ||
               !generation->dpi_app.available ||
               !generation->dpi_host.available ||
               generation->wan_matched < generation->row_count || view.stale;
    dw_cc_add_common_meta(root, &view, filter);
    json_object_object_add(root, "columns", dw_cc_columns_json());
    json_object_object_add(root, "rows", rows);
    json_object_object_add(root, "total", json_object_new_int64((int64_t)total));
    json_object_object_add(root, "complete", json_object_new_boolean(view.complete));
    {
        struct json_object *conntrack = dw_cc_source_json(&generation->conntrack, 0);
        struct json_object *wan = json_object_new_object();

        json_object_object_add(conntrack, "scan_ms",
                               json_object_new_int64(view.collect_ms));
        json_object_object_add(sources, "conntrack", conntrack);
        json_object_object_add(sources, "ct_appid",
                               dw_cc_ct_appid_source_json(
                                   &generation->ct_appid));
        json_object_object_add(sources, "dpi_app",
                               dw_cc_source_json(&generation->dpi_app, 1));
        json_object_object_add(sources, "dpi_host",
                               dw_cc_source_json(&generation->dpi_host, 1));
        json_object_object_add(wan, "state", json_object_new_string(
            generation->wan_matched == generation->row_count ? "ready" :
            generation->wan_matched ? "partial" : "empty"));
        json_object_object_add(wan, "matched", json_object_new_int64(
            (int64_t)generation->wan_matched));
        json_object_object_add(wan, "total", json_object_new_int64(
            (int64_t)generation->row_count));
        json_object_object_add(sources, "wan_attribution", wan);
    }
    if (!generation->conntrack.available)
        json_object_array_add(reasons,
                              json_object_new_string("conntrack_unavailable"));
    if (!generation->ct_appid.available)
        json_object_array_add(reasons,
                              json_object_new_string("ct_appid_unavailable"));
    else if (generation->ct_appid.version != DW_CC_CT_APPID_VERSION)
        json_object_array_add(reasons,
                              json_object_new_string("ct_appid_unsupported"));
    if (generation->ct_appid.truncated)
        json_object_array_add(reasons,
                              json_object_new_string("ct_appid_truncated"));
    if (!generation->dpi_app.available)
        json_object_array_add(reasons,
                              json_object_new_string("dpi_app_unavailable"));
    if (!generation->dpi_host.available)
        json_object_array_add(reasons,
                              json_object_new_string("dpi_host_unavailable"));
    if (generation->wan_matched < generation->row_count)
        json_object_array_add(reasons,
                              json_object_new_string("wan_attribution_partial"));
    if (view.stale)
        json_object_array_add(reasons, json_object_new_string("snapshot_stale"));
    json_object_object_add(root, "source_state", sources);
    json_object_object_add(root, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(root, "degraded_reasons", reasons);
    dw_rm_view_end(&view);
    return root;
}

struct json_object *dw_cc_delta_json(const struct dw_cc_client_filter *filter,
                                     const char *snapshot_id,
                                     uint64_t since_revision,
                                     int *result_code)
{
    struct dw_rm_view view;
    enum dw_rm_resume_result resume;
    struct json_object *upsert_map, *removed_map, *upserts, *removed, *root;
    size_t i, j;

    if (result_code)
        *result_code = 0;
    if (!g_dw_cc_resource) {
        if (result_code)
            *result_code = -ENODEV;
        return NULL;
    }
    resume = dw_rm_resume_begin(g_dw_cc_resource, snapshot_id,
                                since_revision, &view);
    if (resume != DW_RM_RESUME_OK) {
        dw_rm_view_end(&view);
        if (result_code)
            *result_code = -ESTALE;
        return dw_rm_resync_json(g_dw_cc_resource, resume);
    }
    upsert_map = json_object_new_object();
    removed_map = json_object_new_object();
    for (i = 0; i < view.delta_count; i++) {
        const struct dw_cc_delta *delta = dw_rm_view_delta_at(
            &view, i, NULL, NULL, NULL);

        if (!delta)
            continue;
        for (j = 0; j < delta->upsert_count; j++) {
            const struct dw_cc_change *change = &delta->upserts[j];
            int current_match =
                dw_cc_row_matches_filter(&change->current, filter);
            int previous_match = change->has_previous &&
                (change->previous ?
                 dw_cc_membership_matches_filter(change->previous, filter) :
                 current_match);

            if (current_match) {
                json_object_object_add(upsert_map, change->current.id,
                                       dw_cc_row_json(&change->current, filter));
                json_object_object_del(removed_map, change->current.id);
            } else if (previous_match) {
                json_object_object_del(upsert_map, change->current.id);
                json_object_object_add(removed_map, change->current.id,
                                       json_object_new_boolean(1));
            }
        }
        for (j = 0; j < delta->removed_count; j++) {
            const struct dw_cc_removed *row = &delta->removed[j];

            if (!dw_cc_membership_matches_filter(&row->membership, filter))
                continue;
            json_object_object_del(upsert_map, row->id);
            json_object_object_add(removed_map, row->id,
                                   json_object_new_boolean(1));
        }
    }
    upserts = json_object_new_array();
    removed = json_object_new_array();
    {
        json_object_object_foreach(upsert_map, upsert_key, upsert_value) {
            (void)upsert_key;
            json_object_array_add(upserts, json_object_get(upsert_value));
        }
    }
    {
        json_object_object_foreach(removed_map, removed_key, removed_value) {
            (void)removed_value;
            json_object_array_add(removed, json_object_new_string(removed_key));
        }
    }
    root = json_object_new_object();
    json_object_object_add(root, "contract",
                           json_object_new_string(view.contract));
    json_object_object_add(root, "snapshot_id",
                           json_object_new_string(view.snapshot_id));
    json_object_object_add(root, "base_revision",
                           json_object_new_int64((int64_t)since_revision));
    json_object_object_add(root, "revision",
                           json_object_new_int64((int64_t)view.revision));
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(view.observed_at));
    json_object_object_add(root, "stale", json_object_new_boolean(view.stale));
    json_object_object_add(root, "columns", dw_cc_columns_json());
    json_object_object_add(root, "upserts", upserts);
    json_object_object_add(root, "removed", removed);
    json_object_object_add(root, "complete", json_object_new_boolean(view.complete));
    json_object_put(upsert_map);
    json_object_put(removed_map);
    dw_rm_view_end(&view);
    return root;
}

struct json_object *dw_cc_detail_json(const struct dw_cc_client_filter *filter,
                                      const char *connection_id,
                                      int *result_code)
{
    struct dw_rm_view view;
    const struct dw_cc_generation *generation;
    struct json_object *root = NULL;
    size_t i;

    if (result_code)
        *result_code = 0;
    if (!connection_id || strncmp(connection_id, "ct:", 3)) {
        if (result_code)
            *result_code = -EINVAL;
        return NULL;
    }
    if (!g_dw_cc_resource || dw_rm_view_begin(g_dw_cc_resource, &view) != 0) {
        if (g_dw_cc_resource)
            dw_rm_view_end(&view);
        if (result_code)
            *result_code = -EAGAIN;
        return NULL;
    }
    generation = view.generation;
    for (i = 0; i < generation->row_count; i++) {
        const struct dw_cc_row *row = &generation->rows[i];
        struct json_object *original, *reply, *evidence;

        if (strcmp(row->id, connection_id) ||
            !dw_cc_row_matches_filter(row, filter))
            continue;
        root = json_object_new_object();
        original = json_object_new_object();
        reply = json_object_new_object();
        evidence = json_object_new_object();
        dw_cc_add_common_meta(root, &view, filter);
        json_object_object_add(root, "columns", dw_cc_columns_json());
        json_object_object_add(root, "row", dw_cc_row_json(row, filter));
        json_object_object_add(original, "src",
                               json_object_new_string(row->original_src));
        json_object_object_add(original, "sport",
                               json_object_new_int(row->original_sport));
        json_object_object_add(original, "dst",
                               json_object_new_string(row->original_dst));
        json_object_object_add(original, "dport",
                               json_object_new_int(row->original_dport));
        json_object_object_add(reply, "src",
                               json_object_new_string(row->reply_src));
        json_object_object_add(reply, "sport",
                               json_object_new_int(row->reply_sport));
        json_object_object_add(reply, "dst",
                               json_object_new_string(row->reply_dst));
        json_object_object_add(reply, "dport",
                               json_object_new_int(row->reply_dport));
        json_object_object_add(root, "original_tuple", original);
        json_object_object_add(root, "reply_tuple", reply);
        json_object_object_add(root, "zone", json_object_new_int(row->zone));
        json_object_object_add(root, "mark",
                               json_object_new_int64((int64_t)row->mark));
        json_object_object_add(root, "timeout", json_object_new_int(row->timeout));
        json_object_object_add(evidence, "dpi_mac",
                               json_object_new_string(row->dpi_mac));
        json_object_object_add(evidence, "app_id",
                               json_object_new_int(row->app_id));
        json_object_object_add(evidence, "app_source",
                               json_object_new_string(row->app_source));
        json_object_object_add(evidence, "domain",
                               json_object_new_string(row->domain));
        json_object_object_add(root, "evidence", evidence);
        break;
    }
    dw_rm_view_end(&view);
    if (!root && result_code)
        *result_code = -ENOENT;
    return root;
}

struct json_object *dw_cc_read_model_status_json(void)
{
    return g_dw_cc_resource ? dw_rm_status_json(g_dw_cc_resource) : NULL;
}

int dw_cc_test_parse_conntrack(const char *line, char *id, size_t id_len,
                               int *family, int *wan_id,
                               uint64_t *up_bytes, uint64_t *down_bytes)
{
    struct dw_cc_row row;

    if (dw_cc_parse_conntrack_line(line, &row) != 0)
        return -1;
    if (id && id_len)
        snprintf(id, id_len, "%s", row.id);
    if (family)
        *family = row.family;
    if (wan_id)
        *wan_id = row.wan_id;
    if (up_bytes)
        *up_bytes = row.original_bytes;
    if (down_bytes)
        *down_bytes = row.reply_bytes;
    return 0;
}

int dw_cc_test_parse_ct_appid(const char *line, int *family, int *zone,
                              int *proto, char *src, size_t src_len,
                              int *sport, char *dst, size_t dst_len,
                              int *dport, int *app_id, unsigned int *match_status,
                              int *wan_id)
{
    struct dw_cc_ct_appid item;

    if (dw_cc_parse_ct_appid_line(line, &item) != 0)
        return -1;
    if (family)
        *family = item.family;
    if (zone)
        *zone = item.zone;
    if (proto)
        *proto = item.proto;
    if (src && src_len)
        snprintf(src, src_len, "%s", item.src);
    if (sport)
        *sport = item.sport;
    if (dst && dst_len)
        snprintf(dst, dst_len, "%s", item.dst);
    if (dport)
        *dport = item.dport;
    if (app_id)
        *app_id = item.app_id;
    if (match_status)
        *match_status = item.match_status;
    if (wan_id)
        *wan_id = item.wan_id;
    return 0;
}

int dw_cc_test_ct_tuple_matches(int ct_family, int ct_zone, int ct_proto,
                                const char *ct_src, int ct_sport,
                                const char *ct_dst, int ct_dport,
                                int row_family, int row_zone, int row_proto,
                                const char *row_src, int row_sport,
                                const char *row_dst, int row_dport)
{
    struct dw_cc_ct_appid item;
    struct dw_cc_row row;

    memset(&item, 0, sizeof(item));
    memset(&row, 0, sizeof(row));
    item.family = ct_family;
    item.zone = ct_zone;
    item.proto = ct_proto;
    item.sport = ct_sport;
    item.dport = ct_dport;
    row.family = row_family;
    row.zone = row_zone;
    row.l4_number = row_proto;
    row.original_sport = row_sport;
    row.original_dport = row_dport;
    if (dw_cc_normalize_ip(ct_src, item.src, sizeof(item.src), NULL) != 0 ||
        dw_cc_normalize_ip(ct_dst, item.dst, sizeof(item.dst), NULL) != 0 ||
        dw_cc_normalize_ip(row_src, row.original_src,
                           sizeof(row.original_src), NULL) != 0 ||
        dw_cc_normalize_ip(row_dst, row.original_dst,
                           sizeof(row.original_dst), NULL) != 0)
        return -1;
    return dw_cc_ct_appid_matches_row(&item, &row);
}

int dw_cc_test_resolve_app(const char *conntrack_line,
                           const char *ct_appid_line, int fallback_app_id,
                           int *app_id, int *wan_id)
{
    struct dw_cc_row row;
    struct dw_cc_ct_appid item;
    struct dw_cc_source source;

    memset(&source, 0, sizeof(source));
    if (dw_cc_parse_conntrack_line(conntrack_line, &row) != 0)
        return -1;
    if (fallback_app_id > 0) {
        row.app_id = fallback_app_id;
        snprintf(row.app_source, sizeof(row.app_source), "fallback");
    }
    if (dw_cc_parse_ct_appid_line(ct_appid_line, &item) != 0)
        return -1;
    {
        int matched = dw_cc_apply_ct_appid(&row, &item, &source);

        if (app_id)
            *app_id = row.app_id;
        if (wan_id)
            *wan_id = row.wan_id;
        return matched;
    }
}

int dw_cc_test_compact_row_equal(const char *left, const char *right)
{
    struct dw_cc_row a;
    struct dw_cc_row b;

    if (dw_cc_parse_conntrack_line(left, &a) != 0 ||
        dw_cc_parse_conntrack_line(right, &b) != 0)
        return -1;
    return dw_cc_row_equal(&a, &b);
}

struct json_object *dw_cc_memory_json(void)
{
    struct dw_rm_view view;
    const struct dw_cc_generation *g;
    struct json_object *o;
    if (!g_dw_cc_resource) return dw_mem_unknown("read_model_not_started");
    if (dw_rm_view_begin(g_dw_cc_resource, &view) != 0) {
        dw_rm_view_end(&view);
        return dw_mem_unknown("generation_not_ready");
    }
    g = view.generation;
    o = json_object_new_object();
    dw_mem_u64(o, "rows", g->row_count);
    dw_mem_u64(o, "row_capacity", g->row_capacity);
    dw_mem_u64(o, "row_bytes", g->row_count * sizeof(*g->rows));
    dw_mem_u64(o, "allocated_row_bytes", g->row_capacity * sizeof(*g->rows));
    dw_mem_u64(o, "generation_struct_bytes", sizeof(*g));
    dw_mem_u64(o, "spare_row_buffer_bytes",
               __atomic_load_n(&g_dw_cc_spare_row_bytes, __ATOMIC_RELAXED));
    dw_mem_u64(o, "large_buffer_mapped_bytes",
               __atomic_load_n(&g_dw_cc_mapped_bytes, __ATOMIC_RELAXED));
    dw_mem_u64(o, "large_buffer_mapped_peak_bytes",
               __atomic_load_n(&g_dw_cc_mapped_peak_bytes, __ATOMIC_RELAXED));
    json_object_object_add(o, "large_buffer_note", json_object_new_string(
        "requested_bytes_excluding_page_rounding; outside_malloc_arena; not_PSS"));
    dw_rm_view_end(&view);
    json_object_object_add(o, "delta_ring", dw_rm_status_json(g_dw_cc_resource));
    return o;
}
