// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Storage management BFF (Phase 6Q). The /api/v1/storage/* surface: overview,
 * migration, partitions, raid (+ raid/scan), the file browser (files / files
 * content / files mutate), and file-services. The core owns the persistent
 * truth; these handlers are thin BFF adapters. Each branch body moves VERBATIM
 * from jmx_app_api.c behind an alias preamble (req/body_json/device_id as
 * referenced; resp+status always), so no second implementation remains there.
 *
 * 8 single-exact routes (JMX_API_EXACT) + 1 multi-exact alias route (raid|raids
 * GET): the two spellings are one route, emitted as a JMX_API_PREDICATE_ROUTE +
 * JMX_API_PREDICATE_ONLY whose predicate OR's the two exact aliases, reproducing
 * the legacy match byte-for-byte (all_paths=2, match=exact). No prefix routes.
 *
 * GET|HEAD /api/v1/storage/files/raw STAYS inline in jmx_app_api.c: it is a
 * RAW_FD download that writes the socket and close(fd)s, in the early RAW_FD
 * block before the post-auth router dispatch.
 *
 * Zero borrowed helpers: the moved bodies reach no static-in-main function, so
 * there is no api_storage_internal.h. Every symbol they use is already exported
 * (app_ubus_*, webd_query_get, jmx_app_audit_log, app_nc_json_*, json-c, libc).
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <json-c/json.h>

#include "storage/storage_files.h"

#include "api_storage.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── storage alias predicate (raid|raids) ── */

static int storage_raid_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/storage/raid") ||
            !strcmp(path, "/api/v1/storage/raids"));
}

/* ── storage route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *storage_overview(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        char range[16] = "1h";
        struct json_object *params = json_object_new_object();
        webd_query_get(req.query, "range", range, sizeof(range));
        json_object_object_add(params, "range", json_object_new_string(range));
        resp = app_ubus_invoke_timeout("storage_overview", params, 5000);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_migration(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        char audit_target[320];
        const char *use = app_nc_json_str(body_json, "use", "");
        const char *provider_id = app_nc_json_str(body_json, "provider_id", "");

        /* Preserve the versioned migration payload as the single backend
         * authority; WebD only supplies the guarded route and timeout. */
        resp = app_ubus_core_route("storage_migration_apply", body_json,
                                   120000, &status);
        snprintf(audit_target, sizeof(audit_target), "use=%s provider_id=%s",
                 use[0] ? use : "-", provider_id[0] ? provider_id : "-");
        jmx_app_audit_log_ex(device_id && device_id[0] ? device_id : "http", device_id,
                          "storage.migration.apply", "high", audit_target, ctx->req->client_ip,
                          status == 202 ? "accepted" : status < 400 ? "success" : "failed",
                          status < 400 ? "" : app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

static struct json_object *storage_partitions(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke_timeout("storage_partitions", NULL, 5000);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_raid(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke_timeout("storage_raid", NULL, 5000);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_raid_scan(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke_timeout("storage_raid_scan", NULL, 6000);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_files(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        char root_id[64] = "";
        char path[PATH_MAX] = "/";
        char search[129] = "";
        struct json_object *params = json_object_new_object();

        webd_query_get(req.query, "root_id", root_id, sizeof(root_id));
        webd_query_get(req.query, "path", path, sizeof(path));
        if (!webd_query_get(req.query, "search", search, sizeof(search)))
            webd_query_get(req.query, "q", search, sizeof(search));
        json_object_object_add(params, "root_id", json_object_new_string(root_id));
        json_object_object_add(params, "path", json_object_new_string(path));
        json_object_object_add(params, "search", json_object_new_string(search));
        resp = app_ubus_invoke_timeout("storage_files", params, 5000);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_files_content(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        char root_id[64] = "";
        char path[PATH_MAX] = "";
        struct json_object *params = json_object_new_object();

        webd_query_get(req.query, "root_id", root_id, sizeof(root_id));
        webd_query_get(req.query, "path", path, sizeof(path));
        json_object_object_add(params, "root_id", json_object_new_string(root_id));
        json_object_object_add(params, "path", json_object_new_string(path));
        resp = app_ubus_invoke_timeout("storage_file_content", params, 5000);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_files_search(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        char root_id[64] = "";
        char path[PATH_MAX] = "/";
        char query[129] = "";
        char limit[16] = "";
        struct json_object *params = json_object_new_object();

        webd_query_get(req.query, "root_id", root_id, sizeof(root_id));
        webd_query_get(req.query, "path", path, sizeof(path));
        if (!webd_query_get(req.query, "query", query, sizeof(query)))
            webd_query_get(req.query, "q", query, sizeof(query));
        webd_query_get(req.query, "limit", limit, sizeof(limit));
        json_object_object_add(params, "root_id", json_object_new_string(root_id));
        json_object_object_add(params, "path", json_object_new_string(path));
        json_object_object_add(params, "query", json_object_new_string(query));
        if (limit[0])
            json_object_object_add(params, "limit",
                                   json_object_new_int(atoi(limit)));
        resp = app_ubus_invoke_timeout("storage_files_search", params, 10000);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

/* storage-files.v1 error built in webd for transport-level rejects (media type)
 * so the whole /storage/files/* surface speaks one error dialect. */
static struct json_object *storage_files_local_error(const char *code,
                                                     const char *message)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "error", json_object_new_string(code));
    json_object_object_add(data, "message", json_object_new_string(message));
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    return app_jmx_response_data(APP_API_CODE_ERROR, data);
}

static int storage_files_query_flag(const char *v)
{
    return v && (!strcmp(v, "1") || !strcasecmp(v, "true") ||
                 !strcasecmp(v, "yes"));
}

static int storage_files_is_octet_stream(const char *content_type)
{
    return content_type &&
           !strncasecmp(content_type, "application/octet-stream", 24);
}

/* Upload writes reuse storage_files.c's sandbox in-process (storage_files.o is
 * linked into webd), so a multi-megabyte body never traverses ubus. */

/* POST /api/v1/storage/files/upload -- single-shot octet-stream to a path. */
static struct json_object *storage_files_upload(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;
    char root_id[64] = "", path[PATH_MAX] = "/", filename[256] = "";
    char overwrite[8] = "", audit_target[320];

    webd_query_get(req.query, "root_id", root_id, sizeof(root_id));
    webd_query_get(req.query, "path", path, sizeof(path));
    webd_query_get(req.query, "filename", filename, sizeof(filename));
    webd_query_get(req.query, "overwrite", overwrite, sizeof(overwrite));
    if (!storage_files_is_octet_stream(req.content_type))
        resp = storage_files_local_error("unsupported_media_type",
            "upload body must be application/octet-stream");
    else
        resp = jmx_storage_files_store_bytes(root_id, path, filename,
            (const unsigned char *)req.body,
            (size_t)(req.body_len > 0 ? req.body_len : 0),
            storage_files_query_flag(overwrite));
    status = app_response_status(resp, status);
    snprintf(audit_target, sizeof(audit_target), "%s:%s/%s",
             root_id[0] ? root_id : "-", path[0] ? path : "/", filename);
    jmx_app_audit_log_ex(device_id && device_id[0] ? device_id : "http", device_id,
                      "storage.files.upload", "medium", audit_target, ctx->req->client_ip,
                      status < 400 ? "success" : "failed", status < 400 ? "" : app_ubus_response_error_code(resp));
    ctx->status = status;
    return resp;
}

/* POST /api/v1/storage/files/upload/init -- start a chunked session (JSON). */
static struct json_object *storage_files_upload_init_h(struct jmx_api_ctx *ctx)
{
    struct json_object *b = ctx->body;
    struct json_object *resp;

    resp = jmx_storage_files_upload_init(
        app_nc_json_str(b, "root_id", ""),
        app_nc_json_str(b, "dest_path", app_nc_json_str(b, "path", "/")),
        app_nc_json_str(b, "filename", ""),
        app_nc_json_str(b, "upload_id", ""),
        app_nc_json_int64(b, "total_size", 0),
        app_nc_json_int(b, "total_chunks", 0),
        app_nc_json_bool(b, "overwrite", 0));
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

/* POST|PUT /api/v1/storage/files/upload/chunk -- one octet-stream chunk. */
static struct json_object *storage_files_upload_chunk_h(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    char root_id[64] = "", upload_id[80] = "", index[16] = "";

    webd_query_get(req.query, "root_id", root_id, sizeof(root_id));
    webd_query_get(req.query, "upload_id", upload_id, sizeof(upload_id));
    if (!webd_query_get(req.query, "chunk_index", index, sizeof(index)))
        webd_query_get(req.query, "index", index, sizeof(index));
    if (!storage_files_is_octet_stream(req.content_type))
        resp = storage_files_local_error("unsupported_media_type",
            "chunk body must be application/octet-stream");
    else
        resp = jmx_storage_files_upload_chunk(root_id, upload_id, atoi(index),
            (const unsigned char *)req.body,
            (size_t)(req.body_len > 0 ? req.body_len : 0));
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

/* POST /api/v1/storage/files/upload/complete -- merge chunks (JSON). */
static struct json_object *storage_files_upload_complete_h(struct jmx_api_ctx *ctx)
{
    const char *upload_id = app_nc_json_str(ctx->body, "upload_id", "");
    struct json_object *resp;

    resp = jmx_storage_files_upload_complete(
        app_nc_json_str(ctx->body, "root_id", ""), upload_id);
    ctx->status = app_response_status(resp, ctx->status);
    jmx_app_audit_log_task(ctx->device_id, ctx->device_id, "storage.files.upload.complete", "medium",
        app_nc_json_str(ctx->body, "root_id", ""), ctx->req->client_ip,
        ctx->status < 400 ? "success" : "failed", ctx->status < 400 ? "" : app_ubus_response_error_code(resp),
        app_nc_json_str(ctx->body, "upload_id", ""));
    return resp;
}

/* POST /api/v1/storage/files/upload/cancel -- drop a chunked session (JSON). */
static struct json_object *storage_files_upload_cancel_h(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = jmx_storage_files_upload_cancel(
        app_nc_json_str(ctx->body, "root_id", ""),
        app_nc_json_str(ctx->body, "upload_id", ""));

    ctx->status = app_response_status(resp, ctx->status);
    jmx_app_audit_log_task(ctx->device_id, ctx->device_id, "storage.files.upload.cancel", "medium",
        app_nc_json_str(ctx->body, "root_id", ""), ctx->req->client_ip,
        ctx->status < 400 ? "cancelled" : "failed", ctx->status < 400 ? "" : app_ubus_response_error_code(resp),
        app_nc_json_str(ctx->body, "upload_id", ""));
    return resp;
}

static struct json_object *storage_files_mutate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        char audit_action[64];
        char audit_target[256];
        const char *action = app_nc_json_str(body_json, "action", "");
        const char *root_id = app_nc_json_str(body_json, "root_id", "");
        const char *parent = app_nc_json_str(body_json, "path", "");
        const char *leaf = app_nc_json_str(body_json, "name", "");

        if (!leaf[0])
            leaf = app_nc_json_str(body_json, "new_name", "");
        /* Record which action was attempted even when it is rejected: an
         * unsupported_action attempt is exactly what an audit trail wants to
         * keep. The action is validated downstream, so it is bounded here to
         * keep an arbitrary client string out of the audit action column. */
        snprintf(audit_action, sizeof(audit_action), "storage.files.%s",
                 (!strcmp(action, "mkdir") || !strcmp(action, "create") ||
                  !strcmp(action, "write") || !strcmp(action, "rename") ||
                  !strcmp(action, "delete") || !strcmp(action, "move") ||
                  !strcmp(action, "copy")) ?
                     action : "mutate");
        snprintf(audit_target, sizeof(audit_target), "%s:%s%s%s",
                 root_id[0] ? root_id : "-", parent[0] ? parent : "/",
                 leaf[0] ? " -> " : "", leaf);
        resp = app_ubus_invoke_timeout("storage_files_mutate", body_json, 10000);
        status = app_response_status(resp, status);
        jmx_app_audit_log_response(device_id && device_id[0] ? device_id : "http", device_id,
                          audit_action, "medium", audit_target, ctx->req->client_ip, resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *storage_file_services(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("file_services_get", NULL);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

/* Optional NAS control data only; media bytes keep using the raw file route.
 * No scanner, database, archive or download engine is linked into webd. */
static struct json_object *nas_gateway(struct jmx_api_ctx *ctx)
{
    const char *route = ctx->req->path + strlen("/api/v1/nas");
    int nvr = !strncmp(route, "/nvr/", 5);
    const char *object = nvr ? "dreamingwrt.nvr" : "dreamingos.nas";
    if (nvr) route += 4;
    if (!app_ubus_object_available(object)) {
        int installed = access(nvr ? "/usr/sbin/dreamingos-nvrd" : "/usr/sbin/dreamingos-nasd", X_OK) == 0;
        struct json_object *data = json_object_new_object();
        if (!strcmp(route, "/status") && !strcmp(ctx->req->method, "GET")) {
            struct json_object *package = json_object_new_object();
            json_object_object_add(package, "installed", json_object_new_boolean(installed));
            json_object_object_add(package, "state", json_object_new_string(installed ? "stopped" : "not_installed"));
            json_object_object_add(data, "package", package);
            json_object_object_add(data, "features", json_object_new_object());
            ctx->status = 200;
        } else {
            json_object_object_add(data, "error", json_object_new_string(installed ? "service_unavailable" : "package_not_installed"));
            ctx->status = installed ? 503 : 409;
        }
        json_object_object_add(data, "contract_version", json_object_new_string(nvr ? "nvr.v1" : "nas.v1"));
        struct json_object *out = json_object_new_object();
        json_object_object_add(out, "code", json_object_new_int(ctx->status < 400 ? 2000 : 4000));
        json_object_object_add(out, "data", data);
        return out;
    }
    struct json_object *params = ctx->body ? json_object_get(ctx->body) : json_object_new_object();
    if (!strcmp(ctx->req->method, "GET")) {
        const char *keys[] = {"id", "job_id", "library_id", "limit", "offset", "q", "favorite", "trashed", "collection_id", "recent", "engine", "camera_id", "from_unix", "to_unix", NULL};
        for (int i = 0; keys[i]; i++) {
            char value[512] = "";
            webd_query_get(ctx->req->query, keys[i], value, sizeof(value));
            if (value[0]) json_object_object_add(params, keys[i], json_object_new_string(value));
        }
    }
    struct json_object *input = json_object_new_object(), *call = json_object_new_object();
    json_object_object_add(input, "method", json_object_new_string(ctx->req->method));
    json_object_object_add(input, "route", json_object_new_string(route));
    json_object_object_add(input, "params", params);
    json_object_object_add(call, "req", json_object_new_string(json_object_to_json_string_ext(input, JSON_C_TO_STRING_PLAIN)));
    struct json_object *result = app_ubus_invoke_object_timeout(object, "request", call, 7000);
    json_object_put(input); json_object_put(call);
    struct json_object *status = NULL, *body = NULL, *out = NULL;
    if (result && json_object_object_get_ex(result, "http_status", &status) &&
        json_object_object_get_ex(result, "body", &body)) {
        ctx->status = json_object_get_int(status);
        out = json_tokener_parse(json_object_get_string(body));
    }
    if (result) json_object_put(result);
    if (!out) {
        ctx->status = 503;
        out = webd_error("service_unavailable", "NAS service did not return a valid response", "", "webd.nas");
    }
    if (strcmp(ctx->req->method, "GET"))
        jmx_app_audit_log_ex(ctx->device_id, ctx->device_id, nvr ? "nvr.command" : "nas.command", "medium", route, ctx->req->client_ip,
                          ctx->status == 202 ? "accepted" : ctx->status < 400 ? "success" : "failed",
                          ctx->status < 400 ? "" : app_ubus_response_error_code(out));
    return out;
}

const struct jmx_api_route storage_api_routes[] = {
    JMX_API_ROUTE(1101, "/api/v1/nas/", "GET,POST", JMX_API_PREFIX, nas_gateway),
    JMX_API_ROUTE(401, "/api/v1/storage/overview", "GET", JMX_API_EXACT, storage_overview),
    JMX_API_ROUTE(402, "/api/v1/storage/migration", "POST", JMX_API_EXACT, storage_migration),
    JMX_API_ROUTE(403, "/api/v1/storage/partitions", "GET", JMX_API_EXACT, storage_partitions),
    JMX_API_PREDICATE_ROUTE(404, "/api/v1/storage/raid", "GET", JMX_API_PREDICATE_ONLY, storage_raid_path, storage_raid),
    JMX_API_ROUTE(405, "/api/v1/storage/raid/scan", "POST", JMX_API_EXACT, storage_raid_scan),
    JMX_API_ROUTE(406, "/api/v1/storage/files", "GET", JMX_API_EXACT, storage_files),
    JMX_API_ROUTE(407, "/api/v1/storage/files/content", "GET", JMX_API_EXACT, storage_files_content),
    JMX_API_ROUTE(907, "/api/v1/storage/files/search", "GET", JMX_API_EXACT, storage_files_search),
    JMX_API_ROUTE(408, "/api/v1/storage/files/mutate", "POST", JMX_API_EXACT, storage_files_mutate),
    JMX_API_ROUTE(908, "/api/v1/storage/files/upload", "POST", JMX_API_EXACT, storage_files_upload),
    JMX_API_ROUTE(909, "/api/v1/storage/files/upload/init", "POST", JMX_API_EXACT, storage_files_upload_init_h),
    JMX_API_ROUTE(910, "/api/v1/storage/files/upload/chunk", "POST,PUT", JMX_API_EXACT, storage_files_upload_chunk_h),
    JMX_API_ROUTE(911, "/api/v1/storage/files/upload/complete", "POST", JMX_API_EXACT, storage_files_upload_complete_h),
    JMX_API_ROUTE(912, "/api/v1/storage/files/upload/cancel", "POST", JMX_API_EXACT, storage_files_upload_cancel_h),
    JMX_API_ROUTE(409, "/api/v1/storage/file-services", "GET", JMX_API_EXACT, storage_file_services),
    JMX_API_ROUTE_END,
};
