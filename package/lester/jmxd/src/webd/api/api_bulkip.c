// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Bulk-IP / IPAM management BFF (Phase 6R). The /api/v1/bulk-ip/* surface: the
 * collection GET, transactions, refresh, reserve, delete, static-reservations
 * transactions, and CSV import (preview / commit). The core owns the persistent
 * truth; these handlers are thin BFF adapters. Each branch body moves VERBATIM
 * from jmx_app_api.c behind an alias preamble (req/body_json/device_id as
 * referenced; resp+status always), so no second implementation remains there.
 *
 * 8 single-exact routes (JMX_API_EXACT). No prefix and no multi-exact alias
 * routes.
 *
 * GET /api/v1/bulk-ip/import/jobs/<job_id> STAYS inline in jmx_app_api.c: it is
 * matched by the path helper webd_ipam_job_path_id() (no req.path literal), is
 * absent from the merged route inventory, and is left untouched.
 *
 * Zero borrowed helpers: the moved bodies reach no static-in-main function, so
 * there is no api_bulkip_internal.h. Every symbol they use is already exported
 * (app_ubus_*, jmx_app_audit_log, app_nc_json_*, json-c, libc).
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_bulkip.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── storage alias predicate (raid|raids) ── */


/* ── storage route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *bulk_ip(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("bulk_ip_get", NULL);

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_transactions(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_invoke("bulk_ip_transaction", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_refresh(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_invoke("bulk_ip_refresh", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_reserve(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        struct json_object *request=json_object_new_object(),*items=json_object_new_array(),*snapshot=app_ubus_invoke("bulk_ip_get",NULL),*data=NULL,*rev=NULL;
        json_object_object_add(request,"action",json_object_new_string("reserve"));
        json_object_object_add(request,"network_id",json_object_new_string(app_nc_json_str(body_json,"network_id","lan")));
        json_object_array_add(items,json_object_get(body_json)); json_object_object_add(request,"items",items);
        if(snapshot&&json_object_object_get_ex(snapshot,"data",&data)&&data&&json_object_object_get_ex(data,"revision",&rev))json_object_object_add(request,"expected_revision",json_object_get(rev));
        resp = app_ubus_invoke("bulk_ip_transaction",request); json_object_put(request); if(snapshot)json_object_put(snapshot);
        status = app_response_status(resp,status);

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        const char *id = app_nc_json_str(body_json, "id", "");
        struct json_object *request=json_object_new_object(),*items=json_object_new_array(),*item=app_json_id_param(id),*snapshot=app_ubus_invoke("bulk_ip_get",NULL),*data=NULL,*rev=NULL;
        json_object_object_add(request,"action",json_object_new_string("delete"));
        json_object_object_add(request,"network_id",json_object_new_string(app_nc_json_str(body_json,"network_id","lan")));
        json_object_array_add(items,item); json_object_object_add(request,"items",items);
        if(snapshot&&json_object_object_get_ex(snapshot,"data",&data)&&data&&json_object_object_get_ex(data,"revision",&rev))json_object_object_add(request,"expected_revision",json_object_get(rev));
        resp = app_ubus_invoke("bulk_ip_transaction",request); json_object_put(request); if(snapshot)json_object_put(snapshot);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_static_reservations_transactions(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        char ipam_target[160];
        snprintf(ipam_target, sizeof(ipam_target),
                 "action=%s network=%s mac=%s address=%s",
                 app_nc_json_str(body_json, "action", "set"),
                 app_nc_json_str(body_json, "network_id", "-"),
                 app_nc_json_str(body_json, "mac", "-"),
                 app_nc_json_str(body_json, "address", "-"));
        resp = app_ubus_or_error("ipam_reservation_transaction", body_json);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "ipam.static_reservation.set", "high", ipam_target, "", "");

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_import_preview(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /* Not audited as a write: preview touches neither DHCP nor the address
         * table, and auditing it at the same risk level as commit would bury the
         * one entry that matters under the ones that changed nothing. */
        resp = app_ubus_or_error("ipam_import_preview", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *bulk_ip_import_commit(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        char ipam_target[160];
        snprintf(ipam_target, sizeof(ipam_target), "preview=%s request=%s version=%s",
                 app_nc_json_str(body_json, "preview_id", "-"),
                 app_nc_json_str(body_json, "request_id", "-"),
                 app_nc_json_str(body_json, "expected_version", "-"));
        resp = app_ubus_or_error("ipam_import_commit", body_json);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "ipam.import.commit", "high", ipam_target, "", "");

    ctx->status = status;
    return resp;
}

const struct jmx_api_route bulkip_api_routes[] = {
    JMX_API_ROUTE(526, "/api/v1/bulk-ip", "GET", JMX_API_EXACT, bulk_ip),
    JMX_API_ROUTE(527, "/api/v1/bulk-ip/transactions", "POST", JMX_API_EXACT, bulk_ip_transactions),
    JMX_API_ROUTE(528, "/api/v1/bulk-ip/refresh", "POST", JMX_API_EXACT, bulk_ip_refresh),
    JMX_API_ROUTE(529, "/api/v1/bulk-ip/reserve", "POST,PUT", JMX_API_EXACT, bulk_ip_reserve),
    JMX_API_ROUTE(530, "/api/v1/bulk-ip/delete", "POST", JMX_API_EXACT, bulk_ip_delete),
    JMX_API_ROUTE(531, "/api/v1/bulk-ip/static-reservations/transactions", "POST,PUT", JMX_API_EXACT, bulk_ip_static_reservations_transactions),
    JMX_API_ROUTE(532, "/api/v1/bulk-ip/import/preview", "POST", JMX_API_EXACT, bulk_ip_import_preview),
    JMX_API_ROUTE(533, "/api/v1/bulk-ip/import/commit", "POST", JMX_API_EXACT, bulk_ip_import_commit),
    JMX_API_ROUTE_END,
};
