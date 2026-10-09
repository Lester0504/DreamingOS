// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ubus surface for dreamingos-vm.
 *
 * webd's api_vm.c gateway forwards the /api/v1/vm/ subtree here. To keep the frozen vm.v1
 * envelope lossless across the ubus hop, every method takes a single string
 * field `req` (a JSON document) and replies { http_status:int, body:"<json>" },
 * where body is the vm.v1 body serialized as an opaque string. That is on
 * purpose: JSON null (progress/result/error/object_id), int64 timestamps and
 * revisions, and nested objects survive intact, whereas passing them as blobmsg
 * fields would flatten them. The gateway parses `body` back and adds meta.
 *
 * Two objects share one type/method table: the primary `dreamingwrt.vm` and the
 * contract alias `dreamingos.vm` the gateway actually calls (VM_SOURCE).
 */
#include "vm_internal.h"

static struct ubus_context *g_vm_ubus;
static struct blob_buf g_vm_blob;

/* Incoming policy: a single opaque JSON string. See file header. */
static const struct blobmsg_policy vm_req_policy[] = {
    { .name = "req", .type = BLOBMSG_TYPE_STRING },
};

/* Parse the `req` field into a json object; NULL when absent or unparsable.
 * Every field accessor below tolerates a NULL object. */
static struct json_object *vm_ubus_req(struct blob_attr *msg)
{
    struct blob_attr *tb[1];

    blobmsg_parse(vm_req_policy, 1, tb, blob_data(msg), blob_len(msg));
    if (!tb[0])
        return NULL;
    return json_tokener_parse(blobmsg_get_string(tb[0]));
}

static const char *vm_j_str(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v;

    if (o && json_object_object_get_ex(o, k, &v) &&
        json_object_is_type(v, json_type_string))
        return json_object_get_string(v);
    return def;
}
static int vm_j_int(struct json_object *o, const char *k, int def)
{
    struct json_object *v;

    if (o && json_object_object_get_ex(o, k, &v) &&
        !json_object_is_type(v, json_type_null))
        return json_object_get_int(v);
    return def;
}

/* Reply with { http_status, body }. body is serialized to an opaque string; the
 * caller keeps ownership and frees it. */
static int vm_ubus_reply(struct ubus_request_data *req, int http_status,
                         struct json_object *body)
{
    const char *s = body ? json_object_to_json_string(body) : "";

    blob_buf_init(&g_vm_blob, 0);
    blobmsg_add_u32(&g_vm_blob, "http_status", (uint32_t)http_status);
    blobmsg_add_string(&g_vm_blob, "body", s);
    ubus_send_reply(g_vm_ubus, req, g_vm_blob.head);
    blob_buf_free(&g_vm_blob);
    return UBUS_STATUS_OK;
}

/* A data==NULL return from the read helpers is always an error status; shape it
 * into the vm.v1 error body the gateway forwards verbatim. */
static struct json_object *vm_error_from_status(int http_status)
{
    switch (http_status) {
    case 404: return vm_error_obj("not_found", "resource not found", NULL);
    case 400: return vm_error_obj("bad_request", "bad request", NULL);
    default:  return vm_error_obj("service_unavailable",
                                  "virtualization service is unavailable", NULL);
    }
}

/* Category 1: an inner data object (or NULL+status). Wrap data as {ok,data} or
 * synthesize the error body, reply, and free. vm_data_obj adopts data. */
static int vm_reply_data(struct ubus_request_data *req,
                         struct json_object *data, int http_status)
{
    struct json_object *body = data ? vm_data_obj(data)
                                    : vm_error_from_status(http_status);

    vm_ubus_reply(req, http_status, body);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

/* Category 2: the callee already returned a full {ok,...} body. */
static int vm_reply_body(struct ubus_request_data *req,
                         struct json_object *body, int http_status)
{
    vm_ubus_reply(req, http_status, body);
    json_object_put(body);
    return UBUS_STATUS_OK;
}
static int vm_m_status(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
    (void)ctx; (void)obj; (void)method; (void)msg;
    return vm_reply_data(req, vm_status_json(), 200);
}

static int vm_m_capabilities(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    (void)ctx; (void)obj; (void)method; (void)msg;
    return vm_reply_data(req, vm_capabilities_json(), 200);
}

static int vm_m_overview(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
    struct json_object *data;
    (void)ctx; (void)obj; (void)method; (void)msg;

    /* The one live read: a NULL connection is degraded (503), not empty. */
    data = vm_overview_json();
    return vm_reply_data(req, data, data ? 200 : 503);
}
static int vm_m_instance_list(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *data;
    int http = 200;
    (void)ctx; (void)obj; (void)method;

    data = vm_instance_list_json(vm_j_int(rq, "page", 1),
                                 vm_j_int(rq, "page_size", 50),
                                 vm_j_str(rq, "q", NULL),
                                 vm_j_str(rq, "state", NULL), &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_pool_list(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    int http = 200;
    (void)ctx; (void)obj; (void)method;
    struct json_object *data = vm_pool_list_json(vm_j_int(rq, "page", 1),
        vm_j_int(rq, "page_size", 50), vm_j_str(rq, "q", NULL),
        vm_j_str(rq, "state", NULL), &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_network_list(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    int http = 200;
    (void)ctx; (void)obj; (void)method;
    struct json_object *data = vm_network_list_json(vm_j_int(rq, "page", 1),
        vm_j_int(rq, "page_size", 50), vm_j_str(rq, "q", NULL),
        vm_j_str(rq, "state", NULL), &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_instance_get(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *data;
    int http = 200;
    (void)ctx; (void)obj; (void)method;

    data = vm_instance_get_json(vm_j_str(rq, "id", NULL), &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_task_get(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *data;
    int http = 200;
    (void)ctx; (void)obj; (void)method;

    data = vm_task_get_json(vm_j_str(rq, "task_id", NULL), &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}
static int vm_m_task_list(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    struct json_object *data;
    int http = 200;
    (void)ctx; (void)obj; (void)method; (void)msg;

    data = vm_task_list_json(&http);
    return vm_reply_data(req, data, http);
}

static int vm_m_task_cancel(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *data;
    int http = 200;
    (void)ctx; (void)obj; (void)method;

    data = vm_task_cancel(vm_j_str(rq, "task_id", NULL), &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_instance_validate(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *cfg = NULL, *body;
    int http = 200;
    (void)ctx; (void)obj; (void)method;

    /* The gateway sends { config: {...} }; tolerate a bare config too. */
    if (rq)
        json_object_object_get_ex(rq, "config", &cfg);
    body = vm_instance_validate(cfg ? cfg : rq, &http);
    vm_reply_body(req, body, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}
static int vm_m_instance_action(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *body;
    int http = 200;
    (void)ctx; (void)obj; (void)method;

    body = vm_instance_action(vm_j_str(rq, "id", NULL), rq, &http);
    vm_reply_body(req, body, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_instance_create(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *data;
    int http = 202;
    (void)ctx; (void)obj; (void)method;

    /* A write with libvirt unreachable is 503, not a task that will only fail. */
    if (!vm_conn()) {
        vm_reply_body(req, vm_error_obj("service_unavailable",
                          "virtualization service is unavailable", NULL), 503);
        json_object_put(rq);
        return UBUS_STATUS_OK;
    }
    data = vm_task_submit("instance_create", NULL, rq, &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}

static int vm_m_instance_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *rq = vm_ubus_req(msg);
    struct json_object *data;
    int http = 202;
    (void)ctx; (void)obj; (void)method;

    if (!vm_conn()) {
        vm_reply_body(req, vm_error_obj("service_unavailable",
                          "virtualization service is unavailable", NULL), 503);
        json_object_put(rq);
        return UBUS_STATUS_OK;
    }
    data = vm_task_submit("instance_delete", vm_j_str(rq, "id", NULL), rq, &http);
    vm_reply_data(req, data, http);
    json_object_put(rq);
    return UBUS_STATUS_OK;
}
static const struct ubus_method vm_methods[] = {
    UBUS_METHOD("status", vm_m_status, vm_req_policy),
    UBUS_METHOD("capabilities", vm_m_capabilities, vm_req_policy),
    UBUS_METHOD("overview", vm_m_overview, vm_req_policy),
    UBUS_METHOD("pool_list", vm_m_pool_list, vm_req_policy),
    UBUS_METHOD("network_list", vm_m_network_list, vm_req_policy),
    UBUS_METHOD("instance_list", vm_m_instance_list, vm_req_policy),
    UBUS_METHOD("instance_get", vm_m_instance_get, vm_req_policy),
    UBUS_METHOD("instance_validate", vm_m_instance_validate, vm_req_policy),
    UBUS_METHOD("instance_create", vm_m_instance_create, vm_req_policy),
    UBUS_METHOD("instance_action", vm_m_instance_action, vm_req_policy),
    UBUS_METHOD("instance_delete", vm_m_instance_delete, vm_req_policy),
    UBUS_METHOD("task_get", vm_m_task_get, vm_req_policy),
    UBUS_METHOD("task_list", vm_m_task_list, vm_req_policy),
    UBUS_METHOD("task_cancel", vm_m_task_cancel, vm_req_policy),
};

static struct ubus_object_type vm_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_vm", vm_methods);

static struct ubus_object vm_object = {
    .name = "dreamingwrt.vm",
    .type = &vm_object_type,
    .methods = vm_methods,
    .n_methods = ARRAY_SIZE(vm_methods),
};

/* The contract alias the gateway calls (VM_SOURCE == "webd.vm"). */
static struct ubus_object vm_alias_object = {
    .name = "dreamingos.vm",
    .type = &vm_object_type,
    .methods = vm_methods,
    .n_methods = ARRAY_SIZE(vm_methods),
};
int vm_ubus_start(void)
{
    int rc;

    g_vm_ubus = ubus_connect(NULL);
    if (!g_vm_ubus) {
        fprintf(stderr, "[dreamingos-vm] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_vm_ubus);
    rc = ubus_add_object(g_vm_ubus, &vm_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingos-vm] ubus object register failed rc=%d\n", rc);
        ubus_free(g_vm_ubus);
        g_vm_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_vm_ubus, &vm_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingos-vm] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(g_vm_ubus, &vm_object);
        ubus_free(g_vm_ubus);
        g_vm_ubus = NULL;
        return -1;
    }
    return 0;
}

void vm_ubus_stop(void)
{
    if (g_vm_ubus) {
        ubus_remove_object(g_vm_ubus, &vm_alias_object);
        ubus_remove_object(g_vm_ubus, &vm_object);
        ubus_free(g_vm_ubus);
        g_vm_ubus = NULL;
    }
}







