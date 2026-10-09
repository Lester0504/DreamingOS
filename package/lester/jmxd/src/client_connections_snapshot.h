/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DREAMINGWRT_CLIENT_CONNECTIONS_SNAPSHOT_H
#define DREAMINGWRT_CLIENT_CONNECTIONS_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>

#include <json-c/json.h>

#define DW_CC_MAX_CLIENT_ADDRS 24
#define DW_CC_MAC_LEN 32
#define DW_CC_ADDR_LEN 64
#define DW_CC_ID_LEN 36

struct dw_cc_client_filter {
    char mac[DW_CC_MAC_LEN];
    char addresses[DW_CC_MAX_CLIENT_ADDRS][DW_CC_ADDR_LEN];
    size_t address_count;
};

int dw_cc_snapshot_start(void);
void dw_cc_snapshot_stop(void);

void dw_cc_filter_init(struct dw_cc_client_filter *filter, const char *mac);
int dw_cc_filter_add_address(struct dw_cc_client_filter *filter, const char *address);

struct json_object *dw_cc_snapshot_json(const struct dw_cc_client_filter *filter,
                                        int *result_code);
struct json_object *dw_cc_delta_json(const struct dw_cc_client_filter *filter,
                                     const char *snapshot_id,
                                     uint64_t since_revision,
                                     int *result_code);
struct json_object *dw_cc_detail_json(const struct dw_cc_client_filter *filter,
                                      const char *connection_id,
                                      int *result_code);
struct json_object *dw_cc_read_model_status_json(void);
struct json_object *dw_cc_memory_json(void);

/* Pure parser hooks used by the focused host test. */
int dw_cc_test_parse_conntrack(const char *line, char *id, size_t id_len,
                               int *family, int *wan_id,
                               uint64_t *up_bytes, uint64_t *down_bytes);

/*
 * Reusable view of /proc/dreamingwrt/jmx/ct_appid.
 *
 * The compact snapshot path already consumed the kernel's per-connection appid
 * export; the realtime rich-flow path had no access to it because the parser,
 * the sort order and the tuple match all lived in this translation unit as
 * static helpers.  Exporting a tuple-keyed lookup keeps one parser and one
 * match rule for both consumers instead of a second, drifting copy.
 */
struct dw_ct_appid_table;

struct dw_ct_appid_evidence {
    int app_id;
    unsigned int match_status;
    int wan_id;
    int reliable;   /* kernel marked the classification usable for this ct */
};

struct dw_ct_appid_stats {
    int available;
    int version;
    int version_supported;
    size_t rows;
    size_t scanned;
    size_t appid_bearing;
    size_t exported;
    size_t capacity;
    size_t truncated;
};

struct dw_ct_appid_table *dw_ct_appid_table_load(struct dw_ct_appid_stats *stats);
/* Same loader against an explicit path; used by the focused host fixture. */
struct dw_ct_appid_table *dw_ct_appid_table_load_path(const char *path,
                                                     struct dw_ct_appid_stats *stats);
void dw_ct_appid_table_free(struct dw_ct_appid_table *table);
size_t dw_ct_appid_table_rows(const struct dw_ct_appid_table *table);
int dw_ct_appid_table_lookup(const struct dw_ct_appid_table *table,
                             int family, int zone, int proto,
                             const char *src, int sport,
                             const char *dst, int dport,
                             struct dw_ct_appid_evidence *out);

int dw_cc_test_parse_ct_appid(const char *line, int *family, int *zone,
                              int *proto, char *src, size_t src_len,
                              int *sport, char *dst, size_t dst_len,
                              int *dport, int *app_id, unsigned int *match_status,
                              int *wan_id);
int dw_cc_test_ct_tuple_matches(int ct_family, int ct_zone, int ct_proto,
                                const char *ct_src, int ct_sport,
                                const char *ct_dst, int ct_dport,
                                int row_family, int row_zone, int row_proto,
                                const char *row_src, int row_sport,
                                const char *row_dst, int row_dport);
int dw_cc_test_resolve_app(const char *conntrack_line,
                           const char *ct_appid_line, int fallback_app_id,
                           int *app_id, int *wan_id);
int dw_cc_test_compact_row_equal(const char *left, const char *right);
int dw_cc_test_service_category(const char *protocol, int port,
                                char *app_name, size_t app_name_len,
                                char *category_key, size_t category_key_len);

#endif
