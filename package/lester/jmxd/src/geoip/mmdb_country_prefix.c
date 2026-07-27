// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "mmdb_country_prefix.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <maxminddb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Sorted ISO 3166-1 alpha-2 codes. Private and user-assigned codes are absent. */
static const char official_iso_codes[] =
    "ADAEAFAGAIALAMAOAQARASATAUAWAXAZBABBBDBEBFBGBHBIBJBLBMBNBOBQBRBSBTBVBWBYBZ"
    "CACCCDCFCGCHCICKCLCMCNCOCRCVCUCWCXCYCZDEDJDKDMDODZECEEEGEHERESETFIFJFKFMFOFR"
    "GAGBGDGEGFGGGHGIGLGMGNGPGQGRGSGTGUGWGYHKHMHNHRHTHUIDIEILIMINIOIQIRISITJEJM"
    "JOJPKEKGKHKIKMKNKPKRKWKYKZLALBLCLILKLRLSLTLULVLYMAMCMDMEMFMGMHMKMLMMMNMOMP"
    "MQMRMSMTMUMVMWMXMYMZNANCNENFNGNINLNONPNRNUNZOMPAPEPFPGPHPKPLPMPNPRPSPTPWPY"
    "QARERORSRURWSASBSCSDSESGSHSISJSKSLSMSNSOSRSSSTSVSXSYSZTCTDTFTGTHTJTKTLTMTN"
    "TOTRTTTVTWTZUAUGUMUSUYUZVAVCVEVGVIVNVUWFWSYEYTZAZMZW";

struct load_ctx {
    MMDB_s *mmdb;
    struct dwrt_geoip_prefix_list *prefixes;
    struct dwrt_geoip_stats *stats;
    bool selected[26][26];
    uint64_t max_nodes;
    uint64_t max_prefixes;
    uint64_t timeout_ms;
    uint64_t started_ms;
    uint32_t ipv4_start_node;
    uint16_t ipv4_start_depth;
    bool skip_ipv4_subtree;
    int status;
    char *detail;
    size_t detail_len;
};

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void set_error(struct load_ctx *ctx, int status, const char *detail)
{
    if (!ctx || ctx->status != DWRT_GEOIP_OK)
        return;
    ctx->status = status;
    if (ctx->detail && ctx->detail_len)
        snprintf(ctx->detail, ctx->detail_len, "%s", detail ? detail : "");
}

static void set_detail(char *detail, size_t detail_len, const char *value)
{
    if (detail && detail_len)
        snprintf(detail, detail_len, "%s", value ? value : "");
}

int dwrt_geoip_is_official_country(const char code[3])
{
    size_t i;

    if (!code || code[0] < 'A' || code[0] > 'Z' ||
        code[1] < 'A' || code[1] > 'Z' || code[2] != '\0')
        return 0;
    for (i = 0; official_iso_codes[i] && official_iso_codes[i + 1]; i += 2)
        if (official_iso_codes[i] == code[0] && official_iso_codes[i + 1] == code[1])
            return 1;
    return 0;
}

static bool selected_country(const struct load_ctx *ctx, const char code[3])
{
    return ctx->selected[(unsigned)code[0] - 'A'][(unsigned)code[1] - 'A'];
}

static void set_address_bit(uint8_t address[16], unsigned bit, bool value)
{
    uint8_t mask = (uint8_t)(1U << (7U - (bit % 8U)));

    if (value)
        address[bit / 8U] |= mask;
    else
        address[bit / 8U] &= (uint8_t)~mask;
}

static bool get_address_bit(const uint8_t address[16], unsigned bit)
{
    return (address[bit / 8U] >> (7U - (bit % 8U))) & 1U;
}

static bool address_prefix_is_zero(const uint8_t address[16], unsigned bits)
{
    unsigned full_bytes = bits / 8U;
    unsigned partial_bits = bits % 8U;
    unsigned i;

    for (i = 0; i < full_bytes; i++)
        if (address[i])
            return false;
    if (partial_bits) {
        uint8_t mask = (uint8_t)(0xffU << (8U - partial_bits));
        if (address[full_bytes] & mask)
            return false;
    }
    return true;
}

static bool ipv4_compat_or_mapped(const uint8_t address[16], uint8_t prefix_len)
{
    static const uint8_t zero_ten[10] = {0};
    static const uint8_t zero_twelve[12] = {0};

    if (prefix_len < 96)
        return false;
    if (!memcmp(address, zero_twelve, sizeof(zero_twelve)))
        return true;
    return !memcmp(address, zero_ten, sizeof(zero_ten)) &&
           address[10] == 0xff && address[11] == 0xff;
}

static bool append_prefix(struct load_ctx *ctx, const uint8_t address[16],
                          uint8_t family, uint8_t prefix_len, const char code[3])
{
    struct dwrt_geoip_prefix_list *list = ctx->prefixes;
    struct dwrt_geoip_prefix *item;

    if (!selected_country(ctx, code)) {
        ctx->stats->filtered_leaves++;
        return true;
    }
    if (list->count >= ctx->max_prefixes) {
        set_error(ctx, DWRT_GEOIP_PREFIX_LIMIT, "selected prefix count exceeds configured limit");
        return false;
    }
    if (list->count == list->capacity) {
        size_t next = list->capacity ? list->capacity * 2U : 4096U;
        struct dwrt_geoip_prefix *grown;

        if (next > ctx->max_prefixes)
            next = (size_t)ctx->max_prefixes;
        if (next <= list->capacity || next > SIZE_MAX / sizeof(*grown)) {
            set_error(ctx, DWRT_GEOIP_OUT_OF_MEMORY, "prefix allocation size overflow");
            return false;
        }
        grown = realloc(list->items, next * sizeof(*grown));
        if (!grown) {
            set_error(ctx, DWRT_GEOIP_OUT_OF_MEMORY, "out of memory collecting selected prefixes");
            return false;
        }
        list->items = grown;
        list->capacity = next;
    }
    item = &list->items[list->count++];
    memset(item, 0, sizeof(*item));
    memcpy(item->address, address, family == 4 ? 4U : 16U);
    item->family = family;
    item->prefix_len = prefix_len;
    memcpy(item->iso_code, code, 3);
    return true;
}

static bool add_mmdb_leaf(struct load_ctx *ctx, const uint8_t address[16],
                          uint8_t family, uint8_t prefix_len, MMDB_entry_s *entry)
{
    MMDB_entry_data_s data;
    char code[3];
    int status;

    ctx->stats->data_leaves++;
    if (family == 6 && ipv4_compat_or_mapped(address, prefix_len)) {
        ctx->stats->filtered_leaves++;
        return true;
    }
    memset(&data, 0, sizeof(data));
    status = MMDB_get_value(entry, &data, "country", "iso_code", NULL);
    if (status == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
        ctx->stats->filtered_leaves++;
        return true;
    }
    if (status != MMDB_SUCCESS) {
        set_error(ctx, DWRT_GEOIP_INVALID_DATABASE, MMDB_strerror(status));
        return false;
    }
    if (!data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING || data.data_size != 2) {
        ctx->stats->filtered_leaves++;
        return true;
    }
    code[0] = (char)toupper((unsigned char)data.utf8_string[0]);
    code[1] = (char)toupper((unsigned char)data.utf8_string[1]);
    code[2] = '\0';
    if (!dwrt_geoip_is_official_country(code)) {
        ctx->stats->filtered_leaves++;
        return true;
    }
    return append_prefix(ctx, address, family, prefix_len, code);
}

static bool walk_node(struct load_ctx *ctx, uint32_t node_number,
                      uint8_t address[16], uint8_t family, uint16_t depth);

static bool walk_record(struct load_ctx *ctx, uint8_t record_type, uint64_t record,
                        MMDB_entry_s *entry, uint8_t address[16],
                        uint8_t family, uint16_t depth)
{
    unsigned max_depth = family == 4 ? 32U : 128U;

    if (depth > max_depth) {
        set_error(ctx, DWRT_GEOIP_INVALID_DATABASE, "search tree exceeds address-family depth");
        return false;
    }
    switch (record_type) {
    case MMDB_RECORD_TYPE_SEARCH_NODE:
        if (record > UINT32_MAX) {
            set_error(ctx, DWRT_GEOIP_INVALID_DATABASE, "search node exceeds uint32 range");
            return false;
        }
        return walk_node(ctx, (uint32_t)record, address, family, depth);
    case MMDB_RECORD_TYPE_EMPTY:
        ctx->stats->empty_records++;
        return true;
    case MMDB_RECORD_TYPE_DATA:
        return add_mmdb_leaf(ctx, address, family, (uint8_t)depth, entry);
    default:
        set_error(ctx, DWRT_GEOIP_INVALID_DATABASE, "invalid MMDB search-tree record");
        return false;
    }
}

static bool walk_node(struct load_ctx *ctx, uint32_t node_number,
                      uint8_t address[16], uint8_t family, uint16_t depth)
{
    MMDB_search_node_s node;
    int status;

    if (family == 6 && ctx->skip_ipv4_subtree &&
        node_number == ctx->ipv4_start_node && depth == ctx->ipv4_start_depth &&
        address_prefix_is_zero(address, depth))
        return true;
    if (depth >= (family == 4 ? 32U : 128U)) {
        set_error(ctx, DWRT_GEOIP_INVALID_DATABASE, "search node below maximum address depth");
        return false;
    }
    if (++ctx->stats->nodes_visited > ctx->max_nodes) {
        set_error(ctx, DWRT_GEOIP_NODE_LIMIT, "visited node count exceeds configured limit");
        return false;
    }
    if ((ctx->stats->nodes_visited & 1023ULL) == 0 && ctx->timeout_ms &&
        monotonic_ms() - ctx->started_ms > ctx->timeout_ms) {
        set_error(ctx, DWRT_GEOIP_TIMEOUT, "MMDB traversal exceeded configured timeout");
        return false;
    }
    status = MMDB_read_node(ctx->mmdb, node_number, &node);
    if (status != MMDB_SUCCESS) {
        set_error(ctx, DWRT_GEOIP_INVALID_DATABASE, MMDB_strerror(status));
        return false;
    }
    set_address_bit(address, depth, false);
    if (!walk_record(ctx, node.left_record_type, node.left_record,
                     &node.left_record_entry, address, family, depth + 1U))
        return false;
    set_address_bit(address, depth, true);
    if (!walk_record(ctx, node.right_record_type, node.right_record,
                     &node.right_record_entry, address, family, depth + 1U))
        return false;
    set_address_bit(address, depth, false);
    return true;
}

static int compare_prefix(const void *left, const void *right)
{
    const struct dwrt_geoip_prefix *a = left;
    const struct dwrt_geoip_prefix *b = right;
    size_t bytes;
    int cmp = strcmp(a->iso_code, b->iso_code);

    if (cmp)
        return cmp;
    if (a->family != b->family)
        return (int)a->family - (int)b->family;
    bytes = a->family == 4 ? 4U : 16U;
    cmp = memcmp(a->address, b->address, bytes);
    if (cmp)
        return cmp;
    return (int)a->prefix_len - (int)b->prefix_len;
}

static bool can_merge(const struct dwrt_geoip_prefix *a,
                      const struct dwrt_geoip_prefix *b)
{
    unsigned parent_bits, full_bytes, partial_bits;

    if (a->family != b->family || a->prefix_len == 0 ||
        a->prefix_len != b->prefix_len || strcmp(a->iso_code, b->iso_code))
        return false;
    parent_bits = (unsigned)a->prefix_len - 1U;
    full_bytes = parent_bits / 8U;
    partial_bits = parent_bits % 8U;
    if (full_bytes && memcmp(a->address, b->address, full_bytes))
        return false;
    if (partial_bits) {
        uint8_t mask = (uint8_t)(0xffU << (8U - partial_bits));
        if ((a->address[full_bytes] & mask) != (b->address[full_bytes] & mask))
            return false;
    }
    return !get_address_bit(a->address, parent_bits) &&
           get_address_bit(b->address, parent_bits);
}

static void normalize_prefixes(struct load_ctx *ctx, int merge)
{
    size_t read_index, write_index = 0;

    qsort(ctx->prefixes->items, ctx->prefixes->count,
          sizeof(*ctx->prefixes->items), compare_prefix);
    for (read_index = 0; read_index < ctx->prefixes->count; read_index++) {
        struct dwrt_geoip_prefix current = ctx->prefixes->items[read_index];

        if (write_index && !compare_prefix(&ctx->prefixes->items[write_index - 1U], &current))
            continue;
        ctx->prefixes->items[write_index++] = current;
        while (merge && write_index >= 2U &&
               can_merge(&ctx->prefixes->items[write_index - 2U],
                         &ctx->prefixes->items[write_index - 1U])) {
            struct dwrt_geoip_prefix *parent = &ctx->prefixes->items[write_index - 2U];
            parent->prefix_len--;
            set_address_bit(parent->address, parent->prefix_len, false);
            write_index--;
            ctx->stats->merged_prefixes++;
        }
    }
    ctx->prefixes->count = write_index;
}

static int prepare_selection(struct load_ctx *ctx, const struct dwrt_geoip_options *options)
{
    size_t i;

    if (!options || !options->countries || options->country_count == 0 ||
        options->country_count > 249)
        return DWRT_GEOIP_INVALID_ARGUMENT;
    for (i = 0; i < options->country_count; i++) {
        const char *code = options->countries[i];
        if (!dwrt_geoip_is_official_country(code))
            return DWRT_GEOIP_INVALID_ARGUMENT;
        ctx->selected[(unsigned)code[0] - 'A'][(unsigned)code[1] - 'A'] = true;
    }
    return DWRT_GEOIP_OK;
}

int dwrt_geoip_country_prefix_load(const char *mmdb_path,
                                   const struct dwrt_geoip_options *options,
                                   struct dwrt_geoip_prefix_list *out,
                                   struct dwrt_geoip_stats *stats,
                                   char *detail, size_t detail_len)
{
    struct load_ctx ctx;
    struct stat st;
    MMDB_s mmdb;
    uint8_t address[16] = {0};
    bool country_seen[26][26] = {{false}};
    size_t i;
    int rc;

    if (detail && detail_len)
        detail[0] = '\0';
    if (!mmdb_path || !options || !out || !stats)
        return DWRT_GEOIP_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    memset(stats, 0, sizeof(*stats));
    memset(&ctx, 0, sizeof(ctx));
    ctx.prefixes = out;
    ctx.stats = stats;
    ctx.max_nodes = options->max_nodes ? options->max_nodes : DWRT_GEOIP_DEFAULT_MAX_NODES;
    ctx.max_prefixes = options->max_prefixes ? options->max_prefixes : DWRT_GEOIP_DEFAULT_MAX_PREFIXES;
    ctx.timeout_ms = options->timeout_ms ? options->timeout_ms : DWRT_GEOIP_DEFAULT_TIMEOUT_MS;
    ctx.detail = detail;
    ctx.detail_len = detail_len;
    rc = prepare_selection(&ctx, options);
    if (rc != DWRT_GEOIP_OK) {
        set_detail(detail, detail_len, "country selection is empty or invalid");
        return rc;
    }
    if (lstat(mmdb_path, &st) != 0) {
        set_detail(detail, detail_len, strerror(errno));
        return errno == ENOENT ? DWRT_GEOIP_SOURCE_MISSING : DWRT_GEOIP_OPEN_FAILED;
    }
    if (!S_ISREG(st.st_mode)) {
        set_detail(detail, detail_len, "MMDB source is not a regular file");
        return DWRT_GEOIP_SOURCE_NOT_REGULAR;
    }
    stats->source_bytes = (uint64_t)st.st_size;
    if (options->max_source_bytes && stats->source_bytes > options->max_source_bytes) {
        set_detail(detail, detail_len, "MMDB source exceeds configured size limit");
        return DWRT_GEOIP_SOURCE_TOO_LARGE;
    }
    memset(&mmdb, 0, sizeof(mmdb));
    rc = MMDB_open(mmdb_path, MMDB_MODE_MMAP, &mmdb);
    if (rc != MMDB_SUCCESS) {
        set_detail(detail, detail_len, MMDB_strerror(rc));
        if (rc == MMDB_FILE_OPEN_ERROR || rc == MMDB_IO_ERROR)
            return DWRT_GEOIP_OPEN_FAILED;
        if (rc == MMDB_OUT_OF_MEMORY_ERROR)
            return DWRT_GEOIP_OUT_OF_MEMORY;
        return DWRT_GEOIP_INVALID_DATABASE;
    }
    ctx.mmdb = &mmdb;
    ctx.started_ms = monotonic_ms();
    if ((mmdb.metadata.ip_version != 4 && mmdb.metadata.ip_version != 6) ||
        mmdb.metadata.node_count > ctx.max_nodes) {
        set_error(&ctx, mmdb.metadata.node_count > ctx.max_nodes ? DWRT_GEOIP_NODE_LIMIT :
                  DWRT_GEOIP_INVALID_DATABASE, "invalid MMDB metadata or node limit exceeded");
        goto done;
    }
    if (mmdb.metadata.ip_version == 4) {
        if (!walk_node(&ctx, 0, address, 4, 0))
            goto done;
    } else {
        ctx.ipv4_start_node = mmdb.ipv4_start_node.node_value;
        ctx.ipv4_start_depth = mmdb.ipv4_start_node.netmask;
        ctx.skip_ipv4_subtree = ctx.ipv4_start_depth <= 96 &&
                                ctx.ipv4_start_node < mmdb.metadata.node_count;
        if (!walk_node(&ctx, 0, address, 6, 0))
            goto done;
        memset(address, 0, sizeof(address));
        if (ctx.ipv4_start_node < mmdb.metadata.node_count) {
            if (!walk_node(&ctx, ctx.ipv4_start_node, address, 4, 0))
                goto done;
        } else {
            int gai_error = 0, mmdb_error = MMDB_SUCCESS;
            MMDB_lookup_result_s lookup = MMDB_lookup_string(&mmdb, "0.0.0.0",
                                                              &gai_error, &mmdb_error);
            if (gai_error || mmdb_error != MMDB_SUCCESS) {
                set_error(&ctx, DWRT_GEOIP_INVALID_DATABASE,
                          mmdb_error == MMDB_SUCCESS ? gai_strerror(gai_error) :
                                                      MMDB_strerror(mmdb_error));
                goto done;
            }
            if (lookup.found_entry && !add_mmdb_leaf(&ctx, address, 4, 0, &lookup.entry))
                goto done;
        }
    }
    stats->raw_prefixes = out->count;
    normalize_prefixes(&ctx, options->merge);
    for (i = 0; i < out->count; i++) {
        unsigned a = (unsigned)out->items[i].iso_code[0] - 'A';
        unsigned b = (unsigned)out->items[i].iso_code[1] - 'A';

        country_seen[a][b] = true;
        if (out->items[i].family == 4)
            stats->ipv4_prefixes++;
        else
            stats->ipv6_prefixes++;
    }
    for (i = 0; i < options->country_count; i++) {
        unsigned a = (unsigned)options->countries[i][0] - 'A';
        unsigned b = (unsigned)options->countries[i][1] - 'A';

        if (!country_seen[a][b]) {
            char empty[64];
            snprintf(empty, sizeof(empty), "country=%s has no MMDB prefixes", options->countries[i]);
            set_error(&ctx, DWRT_GEOIP_COUNTRY_EMPTY, empty);
            break;
        }
    }
done:
    MMDB_close(&mmdb);
    if (ctx.status != DWRT_GEOIP_OK) {
        dwrt_geoip_prefix_list_free(out);
        return ctx.status;
    }
    return DWRT_GEOIP_OK;
}

void dwrt_geoip_prefix_list_free(struct dwrt_geoip_prefix_list *list)
{
    if (!list)
        return;
    free(list->items);
    memset(list, 0, sizeof(*list));
}

const char *dwrt_geoip_status_code(int status)
{
    static const char *codes[] = {
        "ok", "invalid_argument", "mmdb_missing", "mmdb_not_regular",
        "mmdb_too_large", "mmdb_open_failed", "mmdb_invalid",
        "mmdb_node_limit", "mmdb_prefix_limit", "mmdb_timeout",
        "mmdb_out_of_memory", "mmdb_country_empty", "mmdb_io_error"
    };

    return status >= 0 && (size_t)status < sizeof(codes) / sizeof(codes[0]) ?
           codes[status] : "mmdb_unknown_error";
}

size_t dwrt_geoip_prefix_count(const struct dwrt_geoip_prefix_list *list,
                               const char code[3], int family)
{
    size_t i, count = 0;

    if (!list || !code || (family != 4 && family != 6))
        return 0;
    for (i = 0; i < list->count; i++)
        if (list->items[i].family == family && !strcmp(list->items[i].iso_code, code))
            count++;
    return count;
}

int dwrt_geoip_prefix_write_csv_atomic(const char *output,
                                       const struct dwrt_geoip_prefix_list *list,
                                       char *detail, size_t detail_len)
{
    char *temporary;
    size_t path_len, i;
    FILE *stream = NULL;
    int fd = -1, rc = DWRT_GEOIP_IO_ERROR;

    if (!output || !list)
        return DWRT_GEOIP_INVALID_ARGUMENT;
    path_len = strlen(output) + sizeof(".tmp.XXXXXX");
    temporary = malloc(path_len);
    if (!temporary)
        return DWRT_GEOIP_OUT_OF_MEMORY;
    snprintf(temporary, path_len, "%s.tmp.XXXXXX", output);
    fd = mkstemp(temporary);
    if (fd < 0 || !(stream = fdopen(fd, "w"))) {
        set_detail(detail, detail_len, strerror(errno));
        goto done;
    }
    fd = -1;
    if (fputs("network,country_iso_code\n", stream) == EOF)
        goto done;
    for (i = 0; i < list->count; i++) {
        char address[INET6_ADDRSTRLEN];
        const struct dwrt_geoip_prefix *item = &list->items[i];
        int af = item->family == 4 ? AF_INET : AF_INET6;

        if (!inet_ntop(af, item->address, address, sizeof(address)) ||
            fprintf(stream, "%s/%u,%s\n", address, (unsigned)item->prefix_len,
                    item->iso_code) < 0)
            goto done;
    }
    if (fflush(stream) || fsync(fileno(stream)) || fclose(stream) || rename(temporary, output)) {
        stream = NULL;
        set_detail(detail, detail_len, strerror(errno));
        goto done;
    }
    stream = NULL;
    rc = DWRT_GEOIP_OK;
done:
    if (stream)
        fclose(stream);
    if (fd >= 0)
        close(fd);
    if (rc != DWRT_GEOIP_OK)
        unlink(temporary);
    free(temporary);
    return rc;
}
