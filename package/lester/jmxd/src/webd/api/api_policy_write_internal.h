// SPDX-License-Identifier: GPL-2.0-or-later
/* Private shared policy helpers; one implementation per symbol. */
#ifndef WEBD_API_POLICY_WRITE_INTERNAL_H
#define WEBD_API_POLICY_WRITE_INTERNAL_H

#include <stddef.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <uci.h>

struct http_req;

int webd_normalize_mac_text(const char *in, char *out, size_t out_len);
struct json_object *webd_policy_acl_apply_response(struct json_object *body,
                                                          const char *operation,
                                                          const char *policy_id,
                                                          int *http_status);
int webd_policy_acl_parse_id(const char *policy_id, char *type, size_t type_len,
                                    char *raw_id, size_t raw_id_len);
int webd_policy_acl_type_supported(const char *type);
void webd_policy_action_add(struct json_object *actions,
                                   const char *name, const char *method,
                                   const char *url, int supported,
                                   const char *reason);
const char *webd_policy_action_key_from_target(const char *target);
const char *webd_policy_action_to_target(const char *action);
void webd_policy_append(char *out, size_t out_len, const char *value);
int webd_policy_body_bool_any(struct json_object *body, const char **keys,
                                     int def, int *present);
int webd_policy_body_string_any(struct json_object *body, const char **keys,
                                       char *out, size_t out_len);
struct json_object *webd_policy_capabilities(void);
int webd_policy_copy_file(const char *src, const char *dst, char *err, size_t err_len);
int webd_policy_db_exec(sqlite3 *db, const char *sql, char *err, size_t err_len);
int webd_policy_dhcp_section_exists(const char *id);
int webd_policy_dhcp_section_id_match(struct uci_section *s,
                                             const char *id,
                                             int section_no);
int webd_policy_dhcp_supported_type(const char *type);
struct json_object *webd_policy_dns_apply_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *operation,
                                                          const char *id,
                                                          int *http_status);
int webd_policy_dnsmasq_reload(struct json_object *steps,
                                      struct json_object *warnings);
struct json_object *webd_policy_extract_data_ref(struct json_object *resp);
struct uci_section *webd_policy_find_sqm_queue_section(struct uci_package *pkg,
                                                              const char *id,
                                                              int *section_no_out);
int webd_policy_firewall_backup(char *backup, size_t backup_len,
                                       char *err, size_t err_len);
struct json_object *webd_policy_firewall_nat_apply_response(const struct http_req *req,
                                                                   struct json_object *body,
                                                                   const char *operation,
                                                                   const char *id,
                                                                   int *http_status);
struct json_object *webd_policy_firewall_redirect_apply_response(const struct http_req *req,
                                                                        struct json_object *body,
                                                                        const char *operation,
                                                                        const char *id,
                                                                        int *http_status);
int webd_policy_firewall_reload(struct json_object *steps,
                                       struct json_object *warnings);
int webd_policy_firewall_rule_apply_fields(struct uci_context *ctx,
                                                  struct uci_section *s,
                                                  struct json_object *body,
                                                  int create,
                                                  const char *operation,
                                                  char *err, size_t err_len,
                                                  struct json_object *diff);
struct json_object *webd_policy_firewall_rule_apply_response(const struct http_req *req,
                                                                    struct json_object *body,
                                                                    const char *operation,
                                                                    const char *id,
                                                                    int *http_status);
int webd_policy_firewall_rule_id_match(struct uci_section *s,
                                              const char *id,
                                              int section_no);
int webd_policy_firewall_section_is_type(const char *id, const char *type);
int webd_policy_firewall_validate(struct json_object *steps,
                                         struct json_object *warnings,
                                         char *err, size_t err_len);
int webd_policy_ip_addr_valid(const char *ip);
int webd_policy_network_backup(char *backup, size_t backup_len,
                                      char *err, size_t err_len);
int webd_policy_network_reload(struct json_object *steps,
                                      struct json_object *warnings);
int webd_policy_network_route_exists(const char *id);
int webd_policy_network_route_id_match(struct uci_section *s,
                                              const char *id,
                                              int section_no);
struct json_object *webd_policy_pbr_apply_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *operation,
                                                          const char *id,
                                                          int *http_status);
int webd_policy_pbr_id_ok(const char *s);
struct json_object *webd_policy_pbr_reorder_response(struct json_object *body,
                                                             int apply_requested,
                                                             int *http_status);
int webd_policy_pbr_rule_exists(const char *id);
void webd_policy_pbr_sanitize_id(const char *in, char *out, size_t out_len);
int webd_policy_query_or_body_bool(const struct http_req *req,
                                          struct json_object *body,
                                          const char *key,
                                          int def);
int webd_policy_run_cmd(const char *cmd);
int webd_policy_sqm_apply_fields(struct uci_context *ctx,
                                        struct uci_section *s,
                                        struct json_object *body,
                                        int create,
                                        const char *operation,
                                        char *err, size_t err_len,
                                        struct json_object *diff);
struct json_object *webd_policy_sqm_apply_response(const struct http_req *req,
                                                          struct json_object *body,
                                                          const char *operation,
                                                          const char *id,
                                                          int *http_status);
int webd_policy_sqm_backup(char *backup, size_t backup_len,
                                  char *err, size_t err_len);
int webd_policy_sqm_queue_exists(const char *id);
int webd_policy_sqm_queue_id_match(struct uci_section *s,
                                          const char *id,
                                          int section_no);
int webd_policy_sqm_reload(struct json_object *steps,
                                  struct json_object *warnings);
struct json_object *webd_policy_static_route_apply_response(const struct http_req *req,
                                                                   struct json_object *body,
                                                                   const char *operation,
                                                                   const char *id,
                                                                   int *http_status);
int webd_policy_str_eq(const char *a, const char *b);
int webd_policy_str_false(const char *s);
int webd_policy_str_true(const char *s);
int webd_policy_uci_option(struct uci_section *s, const char *name,
                                  char *out, size_t out_len);
int webd_policy_uci_rename_section(struct uci_context *ctx,
                                          const char *package,
                                          const char *type,
                                          const char *new_name,
                                          char *err, size_t err_len);
int webd_policy_uci_set_option(struct uci_context *ctx,
                                      const char *section,
                                      const char *option,
                                      const char *value,
                                      int delete_if_empty,
                                      char *err, size_t err_len);
int webd_policy_uci_set_pkg_option(struct uci_context *ctx,
                                          const char *package,
                                          const char *section,
                                          const char *option,
                                          const char *value,
                                          int delete_if_empty,
                                          char *err, size_t err_len);
int webd_policy_value_is_any(const char *s);
int webd_policy_value_safe(const char *s);
void webd_policy_zone_to_uci(const char *in, char *out, size_t out_len);

#endif
