// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_DHCP_INTERNAL_H
#define WEBD_API_DHCP_INTERNAL_H
/* Phase 7K: DHCP scope / reservation / audit subsystem moved out of
 * jmx_app_api.c (behavior-preserving). Routes are unchanged and still
 * dispatched from handle_client() in the main TU; only the function
 * definitions moved here. The audit-operation struct is shared with the
 * route handlers that stay in main (they declare local instances), so it
 * is promoted here verbatim, before the prototypes that reference it. */
struct json_object;

struct webd_dhcp_audit_operation {
    const char *action;
    char target[384];
};

/* Defined in api_dhcp.c, still reached from the main TU. */
struct json_object *app_dhcp_merge_partial_payload(struct json_object *body);
int app_dhcp_reserve_apply(const char *lan_id, struct json_object *reservation);
int webd_dhcp_route_is_write(const char *method, const char *path);
void webd_dhcp_audit_classify_request(const char *method, const char *path, struct json_object *body, struct webd_dhcp_audit_operation *op);
void webd_dhcp_audit_emit(const char *device_id, const struct webd_dhcp_audit_operation *op, struct json_object *response, int denied, const char *denial_reason);

/* Borrowed: definitions stay in jmx_app_api.c (audit context used by other
 * subsystems too); de-static'd so the moved audit path can reach them. */
extern char g_webd_audit_source_ip[];
extern char g_webd_audit_api_key_id[];
void jmx_app_audit_log_full_stage(const char *actor, const char *app_device_id, const char *action, const char *risk, const char *target, const char *before_hash, const char *after_hash, const char *source_ip, const char *result, const char *failure_reason, const char *failure_stage);
/* Non-static identity helper defined in jmx_app_api.c. */
int webd_identity_is_user(const char *identity);

#endif /* WEBD_API_DHCP_INTERNAL_H */
