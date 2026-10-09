// SPDX-License-Identifier: GPL-2.0-or-later
#include "api_support.h"
#include "api_error.h"
#include "api_request.h"
#include "api_keys_internal.h"
#include "api_client_control_internal.h"
#include "../webd_support.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

static struct json_object *support_dispatch(struct jmx_api_ctx *ctx)
{
    if (strcmp(ctx->req->method, "GET") && ctx->req->auth_via_cookie && strcmp(ctx->req->sec_fetch_site, "same-origin")) {
        ctx->status = 403; return webd_error("same_origin_required", "请从设备页面提交操作", "", "webd.support");
    }
    if (!webd_identity_is_user(ctx->device_id)) {
        ctx->status = 403; return webd_error("personal_session_required", "反馈需要个人 Web 会话", "", "webd.support");
    }
    char subject[65];
    if (support_subject(g_config_db, webd_identity_username(ctx->device_id), subject)) {
        ctx->status = 503; return webd_error("subject_unavailable", "无法解析反馈归属", "", "webd.support");
    }
    if (mkdir(SUPPORT_STATE_DIR, 0700) && errno != EEXIST) {
        ctx->status = 503; return webd_error("storage_unavailable", "反馈存储不可用", "", "webd.support");
    }
    sqlite3 *db = NULL;
    if (support_db_open(SUPPORT_DB_PATH, &db)) {
        ctx->status = 503; return webd_error("storage_unavailable", "反馈存储不可用", "", "webd.support");
    }
    struct support_config config; (void)support_config_load(&config);
    struct json_object *query = json_object_new_object(); char value[256];
    const char *keys[] = {"page", "page_size", "status", NULL};
    for (int i = 0; keys[i]; ++i) if (webd_query_get(ctx->req->query, keys[i], value, sizeof(value))) {
        if (i < 2) {
            char *end = NULL; long n = strtol(value, &end, 10);
            if (!*value || *end || n < 1 || n > 100000) n = 0;
            json_object_object_add(query, keys[i], json_object_new_int64(n));
        } else json_object_object_add(query, keys[i], json_object_new_string(value));
    }
    int writable = ctx->role != JMX_ROLE_VIEWER;
    struct json_object *result = support_handle(db, &config, subject, writable, ctx->req->method,
        ctx->req->path + strlen("/api/v1/support/"), query, ctx->body, &ctx->status);
    json_object_put(query); sqlite3_close(db); return result;
}
const struct jmx_api_route support_api_routes[] = {
    JMX_API_ROUTE(1124, "/api/v1/support/", "GET,POST", JMX_API_PREFIX, support_dispatch),
    JMX_API_ROUTE_END
};
