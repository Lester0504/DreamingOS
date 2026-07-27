// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "../src/geoip/mmdb_country_prefix.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SELECTED_COUNTRIES 249

static void usage(FILE *stream, const char *prog)
{
    fprintf(stream,
            "Usage: %s --mmdb FILE --output CSV [options]\n\n"
            "Options:\n"
            "  --country CC       Export only CC; repeat for multiple countries\n"
            "  --max-nodes N      Traversal node limit (default %llu)\n"
            "  --max-prefixes N   Selected-prefix limit (default %llu)\n"
            "  --timeout-ms N     Traversal timeout (default %llu)\n"
            "  --no-merge         Disable same-country buddy prefix merge\n"
            "  -h, --help         Show this help\n",
            prog, (unsigned long long)DWRT_GEOIP_DEFAULT_MAX_NODES,
            (unsigned long long)DWRT_GEOIP_DEFAULT_MAX_PREFIXES,
            (unsigned long long)DWRT_GEOIP_DEFAULT_TIMEOUT_MS);
}

static int parse_u64(const char *raw, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(raw ? raw : "", &end, 10);
    if (errno || !end || end == raw || *end || value == 0)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

static size_t all_countries(char countries[MAX_SELECTED_COUNTRIES][3])
{
    size_t count = 0;
    int a, b;

    for (a = 'A'; a <= 'Z'; a++) {
        for (b = 'A'; b <= 'Z'; b++) {
            char code[3] = { (char)a, (char)b, '\0' };
            if (dwrt_geoip_is_official_country(code)) {
                memcpy(countries[count++], code, 3);
            }
        }
    }
    return count;
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"mmdb", required_argument, NULL, 'm'},
        {"output", required_argument, NULL, 'o'},
        {"country", required_argument, NULL, 'c'},
        {"max-nodes", required_argument, NULL, 'n'},
        {"max-prefixes", required_argument, NULL, 'p'},
        {"timeout-ms", required_argument, NULL, 't'},
        {"no-merge", no_argument, NULL, 'M'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    char countries[MAX_SELECTED_COUNTRIES][3];
    size_t country_count = 0;
    const char *mmdb = NULL, *output = NULL;
    struct dwrt_geoip_prefix_list prefixes;
    struct dwrt_geoip_stats stats;
    struct dwrt_geoip_options config = {
        .max_nodes = DWRT_GEOIP_DEFAULT_MAX_NODES,
        .max_prefixes = DWRT_GEOIP_DEFAULT_MAX_PREFIXES,
        .timeout_ms = DWRT_GEOIP_DEFAULT_TIMEOUT_MS,
        .merge = 1,
    };
    char detail[256] = "";
    int option, rc;

    while ((option = getopt_long(argc, argv, "m:o:c:n:p:t:Mh", options, NULL)) != -1) {
        switch (option) {
        case 'm': mmdb = optarg; break;
        case 'o': output = optarg; break;
        case 'c':
            if (country_count >= MAX_SELECTED_COUNTRIES || strlen(optarg) != 2) {
                fprintf(stderr, "invalid --country: %s\n", optarg);
                return 2;
            }
            countries[country_count][0] = (char)toupper((unsigned char)optarg[0]);
            countries[country_count][1] = (char)toupper((unsigned char)optarg[1]);
            countries[country_count++][2] = '\0';
            break;
        case 'n': if (parse_u64(optarg, &config.max_nodes)) return 2; break;
        case 'p': if (parse_u64(optarg, &config.max_prefixes)) return 2; break;
        case 't': if (parse_u64(optarg, &config.timeout_ms)) return 2; break;
        case 'M': config.merge = 0; break;
        case 'h': usage(stdout, argv[0]); return 0;
        default: usage(stderr, argv[0]); return 2;
        }
    }
    if (!mmdb || !output || optind != argc) {
        usage(stderr, argv[0]);
        return 2;
    }
    if (country_count == 0)
        country_count = all_countries(countries);
    config.countries = (const char (*)[3])countries;
    config.country_count = country_count;
    rc = dwrt_geoip_country_prefix_load(mmdb, &config, &prefixes, &stats,
                                        detail, sizeof(detail));
    if (rc != DWRT_GEOIP_OK) {
        fprintf(stderr, "MMDB export failed: %s: %s\n", dwrt_geoip_status_code(rc), detail);
        return 1;
    }
    rc = dwrt_geoip_prefix_write_csv_atomic(output, &prefixes, detail, sizeof(detail));
    if (rc != DWRT_GEOIP_OK) {
        fprintf(stderr, "CSV export failed: %s: %s\n", dwrt_geoip_status_code(rc), detail);
        dwrt_geoip_prefix_list_free(&prefixes);
        return 1;
    }
    printf("mmdb=%s output=%s selected_countries=%zu source_bytes=%" PRIu64 "\n",
           mmdb, output, country_count, stats.source_bytes);
    printf("nodes_visited=%" PRIu64 " data_leaves=%" PRIu64
           " filtered_leaves=%" PRIu64 " raw_prefixes=%" PRIu64
           " merged=%" PRIu64 "\n", stats.nodes_visited, stats.data_leaves,
           stats.filtered_leaves, stats.raw_prefixes, stats.merged_prefixes);
    printf("prefixes=%zu ipv4=%zu ipv6=%zu\n", prefixes.count,
           stats.ipv4_prefixes, stats.ipv6_prefixes);
    dwrt_geoip_prefix_list_free(&prefixes);
    return 0;
}
