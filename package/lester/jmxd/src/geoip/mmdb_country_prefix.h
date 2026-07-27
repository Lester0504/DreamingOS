// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_MMDB_COUNTRY_PREFIX_H
#define DREAMINGWRT_MMDB_COUNTRY_PREFIX_H

#include <stddef.h>
#include <stdint.h>

#define DWRT_GEOIP_DEFAULT_MAX_NODES 5000000ULL
#define DWRT_GEOIP_DEFAULT_MAX_PREFIXES 3000000ULL
#define DWRT_GEOIP_DEFAULT_TIMEOUT_MS 30000ULL

enum dwrt_geoip_status {
    DWRT_GEOIP_OK = 0,
    DWRT_GEOIP_INVALID_ARGUMENT,
    DWRT_GEOIP_SOURCE_MISSING,
    DWRT_GEOIP_SOURCE_NOT_REGULAR,
    DWRT_GEOIP_SOURCE_TOO_LARGE,
    DWRT_GEOIP_OPEN_FAILED,
    DWRT_GEOIP_INVALID_DATABASE,
    DWRT_GEOIP_NODE_LIMIT,
    DWRT_GEOIP_PREFIX_LIMIT,
    DWRT_GEOIP_TIMEOUT,
    DWRT_GEOIP_OUT_OF_MEMORY,
    DWRT_GEOIP_COUNTRY_EMPTY,
    DWRT_GEOIP_IO_ERROR,
};

struct dwrt_geoip_prefix {
    uint8_t address[16];
    uint8_t family;
    uint8_t prefix_len;
    char iso_code[3];
};

struct dwrt_geoip_prefix_list {
    struct dwrt_geoip_prefix *items;
    size_t count;
    size_t capacity;
};

struct dwrt_geoip_options {
    const char (*countries)[3];
    size_t country_count;
    uint64_t max_nodes;
    uint64_t max_prefixes;
    uint64_t timeout_ms;
    uint64_t max_source_bytes;
    int merge;
};

struct dwrt_geoip_stats {
    uint64_t source_bytes;
    uint64_t nodes_visited;
    uint64_t data_leaves;
    uint64_t filtered_leaves;
    uint64_t empty_records;
    uint64_t raw_prefixes;
    uint64_t merged_prefixes;
    size_t ipv4_prefixes;
    size_t ipv6_prefixes;
};

int dwrt_geoip_country_prefix_load(const char *mmdb_path,
                                   const struct dwrt_geoip_options *options,
                                   struct dwrt_geoip_prefix_list *out,
                                   struct dwrt_geoip_stats *stats,
                                   char *detail, size_t detail_len);
void dwrt_geoip_prefix_list_free(struct dwrt_geoip_prefix_list *list);
const char *dwrt_geoip_status_code(int status);
int dwrt_geoip_is_official_country(const char code[3]);
size_t dwrt_geoip_prefix_count(const struct dwrt_geoip_prefix_list *list,
                               const char code[3], int family);
int dwrt_geoip_prefix_write_csv_atomic(const char *output,
                                       const struct dwrt_geoip_prefix_list *list,
                                       char *detail, size_t detail_len);

#endif
