// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_TERMINAL_INTERNAL_H
#define WEBD_API_TERMINAL_INTERNAL_H

/*
 * Terminal-policy subsystem contract (Phase 6Y), extracted from
 * jmx_app_api.c into api_terminal.c. terminal_policy.h supplies tp_error_t
 * (webd_terminal_policy_restore) and struct json_object; it is self-contained
 * (own guard + <stdint.h>/<stddef.h>/<json-c/json.h>).
 *
 * The ten entry points below are dispatched by the network-control BFF
 * adapters in api_netcontrol.c (which declares the same prototypes in
 * api_netcontrol_internal.h). Declaring them here too lets api_terminal.c
 * self-check its definitions, and lets jmx_app_api.c — which includes both
 * headers — force the two prototype sets to agree.
 */
#include "../../terminal_policy/terminal_policy.h"

struct json_object;

/* Entry points reached from api_netcontrol.c (BFF dispatchers). Prototypes
 * are the exact definition signatures. */
int webd_terminal_policy_id_ok(const char *id);
int webd_terminal_policy_init_schema(void);
struct json_object *webd_terminal_policy_flowd(const char *method,
                                                      int *status);
int webd_terminal_policy_apply_ok(struct json_object *resp);
int webd_terminal_policy_apply_rollback_noop(struct json_object *resp);
struct json_object *webd_terminal_policy_apply(int *status);
struct json_object *webd_terminal_policy_apply_error(
    struct json_object *apply, int rollback_ok, const char *detail);
struct json_object *webd_terminal_policy_restore(struct json_object *old,
                                                         const char *id,
                                                         int update,
                                                         tp_error_t *tp_err);
struct json_object *webd_terminal_policy_write(struct json_object *body,
                                                       const char *id,
                                                       int update,
                                                       int *status);
struct json_object *webd_terminal_policy_response(const char *id, int *status);

/*
 * Borrowed from jmx_app_api.c (definition stays there): the tp_db_init
 * lifecycle helper. De-static'd there; its other callers are main-only
 * lifecycle sites. Redeclared here (not cross-including a sibling domain's
 * internal header) so this TU owns its full contract.
 */
int webd_terminal_policy_open(void);

#endif /* WEBD_API_TERMINAL_INTERNAL_H */
