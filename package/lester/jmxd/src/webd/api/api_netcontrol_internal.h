// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_NETCONTROL_INTERNAL_H
#define WEBD_API_NETCONTROL_INTERNAL_H

/*
 * Borrowed from jmx_app_api.c. These eighteen network-control helpers are
 * de-static'd there (their definitions stay in main, shared with the callers
 * that remain in other domains); the nc BFF adapters in api_netcontrol.c reuse
 * the single implementations. The nc TU is a separate compilation unit and
 * needs the prototypes. <stddef.h> is for size_t (webd_mac_for_ip); terminal_policy.h
 * supplies tp_error_t (webd_terminal_policy_restore) plus the tp_* prototypes the
 * moved bodies call directly (tp_policy_get/snapshot/delete/renew/reset_usage,
 * tp_valid_unit), and it is self-contained (own guard + <stdint.h>/<stddef.h>/
 * <json-c/json.h>). WEBD_NETCTL_TERMINAL_MAX_RULES moved here from jmx_app_api.c so
 * both the module (rule-build cap) and the one surviving in-main use share a single
 * definition; main includes this header (early, before that use) so it is unchanged
 * there.
 */
#include <stddef.h>

#include "../../terminal_policy/terminal_policy.h"

struct json_object;

#define WEBD_NETCTL_TERMINAL_MAX_RULES 512

int webd_mac_for_ip(const char *ip, char *out_mac, size_t mac_len,
                    char *out_reason, size_t reason_len);
int webd_netctl_rule_id_ok(const char *id);
int webd_netctl_terminal_rule_exists(const char *rule_id);
int webd_terminal_policy_apply_ok(struct json_object *resp);
int webd_terminal_policy_apply_rollback_noop(struct json_object *resp);
int webd_terminal_policy_id_ok(const char *id);
int webd_terminal_policy_init_schema(void);
struct json_object *webd_netctl_get_response(int *status);
struct json_object *webd_netctl_terminal_capabilities(void);
struct json_object *webd_netctl_terminal_rule_build(struct json_object *body,
                                                    const char *rule_id,
                                                    const char **code,
                                                    char *err, size_t err_len);
struct json_object *webd_netctl_terminal_rules(void);
struct json_object *webd_netctl_terminal_write(struct json_object *rule, int *status);
struct json_object *webd_terminal_policy_apply(int *status);
struct json_object *webd_terminal_policy_apply_error(struct json_object *apply,
                                                     int rollback_ok,
                                                     const char *detail);
struct json_object *webd_terminal_policy_flowd(const char *method, int *status);
struct json_object *webd_terminal_policy_response(const char *id, int *status);
struct json_object *webd_terminal_policy_restore(struct json_object *old,
                                                 const char *id, int update,
                                                 tp_error_t *tp_err);
struct json_object *webd_terminal_policy_write(struct json_object *body,
                                               const char *id, int update,
                                               int *status);

#endif /* WEBD_API_NETCONTROL_INTERNAL_H */
