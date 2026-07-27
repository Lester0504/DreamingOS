// SPDX-License-Identifier: GPL-2.0-or-later
#include "authd_internal.h"

static int authd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                           struct json_object *response)
{
    const char *text = response ? json_object_to_json_string(response) : "{}";

    blob_buf_init(&g_authd_blob, 0);
    if (!blobmsg_add_json_from_string(&g_authd_blob, text)) {
        blob_buf_free(&g_authd_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_authd_blob.head);
    blob_buf_free(&g_authd_blob);
    return UBUS_STATUS_OK;
}

typedef struct json_object *(*authd_read_fn)(void);
typedef struct json_object *(*authd_query_fn)(struct json_object *query);

static int authd_handle_read(struct ubus_context *ctx, struct ubus_request_data *req,
                             authd_read_fn fn)
{
    struct json_object *response = fn();
    int rc = authd_send_json(ctx, req, response);
    json_object_put(response);
    return rc;
}

static int authd_handle_query(struct ubus_context *ctx, struct ubus_request_data *req,
                              struct blob_attr *msg, authd_query_fn fn)
{
    struct json_object *query = authd_json_from_blob(msg);
    struct json_object *response = fn(query);
    int rc = authd_send_json(ctx, req, response);

    json_object_put(response);
    json_object_put(query);
    return rc;
}

#define AUTHD_READ_HANDLER(name, fn) \
    static int name(struct ubus_context *ctx, struct ubus_object *obj, \
                    struct ubus_request_data *req, const char *method, struct blob_attr *msg) \
    { (void)obj; (void)method; (void)msg; return authd_handle_read(ctx, req, fn); }

#define AUTHD_QUERY_HANDLER(name, fn) \
    static int name(struct ubus_context *ctx, struct ubus_object *obj, \
                    struct ubus_request_data *req, const char *method, struct blob_attr *msg) \
    { (void)obj; (void)method; return authd_handle_query(ctx, req, msg, fn); }

AUTHD_READ_HANDLER(authd_handle_status, authd_status_json)
AUTHD_READ_HANDLER(authd_handle_aggregate_get, authd_aggregate_json)
AUTHD_READ_HANDLER(authd_handle_web_get, authd_web_json)
AUTHD_READ_HANDLER(authd_handle_portal_get, authd_portal_json)
AUTHD_QUERY_HANDLER(authd_handle_online_users_get, authd_online_users_json)
AUTHD_QUERY_HANDLER(authd_handle_packages_get, authd_packages_json)
AUTHD_QUERY_HANDLER(authd_handle_accounts_get, authd_accounts_json)
AUTHD_QUERY_HANDLER(authd_handle_ledger_get, authd_ledger_json)
AUTHD_QUERY_HANDLER(authd_handle_account_management_get, authd_account_management_json)
AUTHD_QUERY_HANDLER(authd_handle_vouchers_get, authd_vouchers_json)
AUTHD_QUERY_HANDLER(authd_handle_delegated_get, authd_delegated_json)
AUTHD_READ_HANDLER(authd_handle_notifications_get, authd_notifications_json)
AUTHD_QUERY_HANDLER(authd_handle_package_upsert, authd_package_upsert)
AUTHD_QUERY_HANDLER(authd_handle_package_delete, authd_package_delete)
AUTHD_QUERY_HANDLER(authd_handle_account_upsert, authd_account_upsert)
AUTHD_QUERY_HANDLER(authd_handle_account_delete, authd_account_delete)
AUTHD_QUERY_HANDLER(authd_handle_accounts_bulk, authd_accounts_bulk)
AUTHD_QUERY_HANDLER(authd_handle_accounts_import, authd_accounts_import)
AUTHD_QUERY_HANDLER(authd_handle_password_policy_set, authd_password_policy_set)
AUTHD_QUERY_HANDLER(authd_handle_web_set, authd_web_set)
AUTHD_QUERY_HANDLER(authd_handle_portal_set, authd_portal_set)
AUTHD_QUERY_HANDLER(authd_handle_access_rule_upsert, authd_access_rule_upsert)
AUTHD_QUERY_HANDLER(authd_handle_access_rule_delete, authd_access_rule_delete)
AUTHD_QUERY_HANDLER(authd_handle_delegated_upsert, authd_delegated_upsert)
AUTHD_QUERY_HANDLER(authd_handle_delegated_delete, authd_delegated_delete)
AUTHD_QUERY_HANDLER(authd_handle_delegated_import, authd_delegated_import)
AUTHD_QUERY_HANDLER(authd_handle_notification_set, authd_notification_set)
AUTHD_QUERY_HANDLER(authd_handle_notification_preview, authd_notification_preview)
AUTHD_QUERY_HANDLER(authd_handle_notification_schedule_upsert, authd_notification_schedule_upsert)
AUTHD_QUERY_HANDLER(authd_handle_notification_schedule_delete, authd_notification_schedule_delete)
AUTHD_QUERY_HANDLER(authd_handle_ledger_upsert, authd_ledger_upsert)
AUTHD_QUERY_HANDLER(authd_handle_ledger_delete, authd_ledger_delete)
AUTHD_QUERY_HANDLER(authd_handle_voucher_create, authd_voucher_create)
AUTHD_QUERY_HANDLER(authd_handle_voucher_update, authd_voucher_update)
AUTHD_QUERY_HANDLER(authd_handle_voucher_delete, authd_voucher_delete)
AUTHD_QUERY_HANDLER(authd_handle_vouchers_expired_delete, authd_vouchers_expired_delete)

static const struct ubus_method authd_methods[] = {
    UBUS_METHOD_NOARG("status", authd_handle_status),
    UBUS_METHOD_NOARG("aggregate_get", authd_handle_aggregate_get),
    UBUS_METHOD_NOARG("web_get", authd_handle_web_get),
    UBUS_METHOD_NOARG("portal_get", authd_handle_portal_get),
    UBUS_METHOD_NOARG("online_users_get", authd_handle_online_users_get),
    UBUS_METHOD_NOARG("packages_get", authd_handle_packages_get),
    UBUS_METHOD_NOARG("accounts_get", authd_handle_accounts_get),
    UBUS_METHOD_NOARG("ledger_get", authd_handle_ledger_get),
    UBUS_METHOD_NOARG("account_management_get", authd_handle_account_management_get),
    UBUS_METHOD_NOARG("vouchers_get", authd_handle_vouchers_get),
    UBUS_METHOD_NOARG("delegated_get", authd_handle_delegated_get),
    UBUS_METHOD_NOARG("notifications_get", authd_handle_notifications_get),
    UBUS_METHOD_NOARG("package_upsert", authd_handle_package_upsert),
    UBUS_METHOD_NOARG("package_delete", authd_handle_package_delete),
    UBUS_METHOD_NOARG("account_upsert", authd_handle_account_upsert),
    UBUS_METHOD_NOARG("account_delete", authd_handle_account_delete),
    UBUS_METHOD_NOARG("accounts_bulk", authd_handle_accounts_bulk),
    UBUS_METHOD_NOARG("accounts_import", authd_handle_accounts_import),
    UBUS_METHOD_NOARG("password_policy_set", authd_handle_password_policy_set),
    UBUS_METHOD_NOARG("web_set", authd_handle_web_set),
    UBUS_METHOD_NOARG("portal_set", authd_handle_portal_set),
    UBUS_METHOD_NOARG("access_rule_upsert", authd_handle_access_rule_upsert),
    UBUS_METHOD_NOARG("access_rule_delete", authd_handle_access_rule_delete),
    UBUS_METHOD_NOARG("delegated_upsert", authd_handle_delegated_upsert),
    UBUS_METHOD_NOARG("delegated_delete", authd_handle_delegated_delete),
    UBUS_METHOD_NOARG("delegated_import", authd_handle_delegated_import),
    UBUS_METHOD_NOARG("notification_set", authd_handle_notification_set),
    UBUS_METHOD_NOARG("notification_preview", authd_handle_notification_preview),
    UBUS_METHOD_NOARG("notification_schedule_upsert", authd_handle_notification_schedule_upsert),
    UBUS_METHOD_NOARG("notification_schedule_delete", authd_handle_notification_schedule_delete),
    UBUS_METHOD_NOARG("ledger_upsert", authd_handle_ledger_upsert),
    UBUS_METHOD_NOARG("ledger_delete", authd_handle_ledger_delete),
    UBUS_METHOD_NOARG("voucher_create", authd_handle_voucher_create),
    UBUS_METHOD_NOARG("voucher_update", authd_handle_voucher_update),
    UBUS_METHOD_NOARG("voucher_delete", authd_handle_voucher_delete),
    UBUS_METHOD_NOARG("vouchers_expired_delete", authd_handle_vouchers_expired_delete),
};

static struct ubus_object_type authd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt.authd", authd_methods);

static struct ubus_object authd_object = {
    .name = "dreamingwrt.authd",
    .type = &authd_object_type,
    .methods = authd_methods,
    .n_methods = ARRAY_SIZE(authd_methods),
};

static struct ubus_object authd_alias_object = {
    .name = "dreamingos.authd",
    .type = &authd_object_type,
    .methods = authd_methods,
    .n_methods = ARRAY_SIZE(authd_methods),
};

int authd_ubus_start(void)
{
    int rc;

    g_authd_ubus = ubus_connect(NULL);
    if (!g_authd_ubus) {
        fprintf(stderr, "[dreamingwrt-authd] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_authd_ubus);
    rc = ubus_add_object(g_authd_ubus, &authd_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-authd] ubus object failed: %s\n", ubus_strerror(rc));
        ubus_free(g_authd_ubus);
        g_authd_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_authd_ubus, &authd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-authd] ubus alias failed: %s\n", ubus_strerror(rc));
        ubus_remove_object(g_authd_ubus, &authd_object);
        ubus_free(g_authd_ubus);
        g_authd_ubus = NULL;
        return -1;
    }
    return 0;
}

void authd_ubus_stop(void)
{
    if (!g_authd_ubus)
        return;
    ubus_remove_object(g_authd_ubus, &authd_alias_object);
    ubus_remove_object(g_authd_ubus, &authd_object);
    ubus_free(g_authd_ubus);
    g_authd_ubus = NULL;
}
