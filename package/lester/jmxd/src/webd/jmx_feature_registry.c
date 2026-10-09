 // SPDX-License-Identifier: GPL-2.0-or-later
 /*
  * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
  *
  * Feature/Resource/Capability registry.
  *
  * Registers dreamingwrt.registry + dreamingos.registry on ubus with two
  * methods:
  *   feature_list   -- all known features with live availability
  *   feature_status -- single feature detail
  *
  * Each feature carries a probe function that runs at query time so the
  * answer is always live.  When probe is NULL, the default probe checks
  * whether the feature's ubus_object is reachable.
  */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 
 #include <json-c/json.h>
 #include <libubox/blobmsg.h>
 #include <libubox/blobmsg_json.h>
 #include <libubox/uloop.h>
 #include <libubox/utils.h>
 #include <libubus.h>
 
 #include "jmx_feature_registry.h"
 
 /* ------------------------------------------------------------------ */
 /*  Internal ubus context                                              */
 /* ------------------------------------------------------------------ */
 
 static struct ubus_context *g_reg_ubus;
 static struct blob_buf      g_reg_blob;
 
 /* ------------------------------------------------------------------ */
 /*  Default probe: ubus object existence                               */
 /* ------------------------------------------------------------------ */
 
 static int ubus_object_reachable(const char *name)
 {
     uint32_t id = 0;
 
     if (!g_reg_ubus || !name || !name[0])
         return 0;
     return ubus_lookup_id(g_reg_ubus, name, &id) == UBUS_STATUS_OK;
 }
 
 /* ------------------------------------------------------------------ */
 /*  Per-feature probe helpers                                          */
 /* ------------------------------------------------------------------ */
 
 /* Wifi: check both local wifi and AC subsystem. */
 static struct json_object *probe_wifi(void)
 {
     struct json_object *result = json_object_new_object();
     int ac_up   = ubus_object_reachable("dreamingwrt.ac");
     int core_up = ubus_object_reachable("dreamingwrt");
     int available = core_up; /* wifi config lives in core */
 
     json_object_object_add(result, "available",
                            json_object_new_boolean(available));
     if (!available)
         json_object_object_add(result, "reason",
                                json_object_new_string("core_unavailable"));
     else
         json_object_object_add(result, "reason", NULL);
 
     /* capabilities */
     struct json_object *caps = json_object_new_object();
     json_object_object_add(caps, "wifi_read",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "wifi_write",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "ac_managed",
                            json_object_new_boolean(ac_up));
     json_object_object_add(result, "capabilities", caps);
 
     /* permissions */
     struct json_object *perms = json_object_new_object();
     json_object_object_add(perms, "wifi:read",
                            json_object_new_boolean(1));
     json_object_object_add(perms, "wifi:write",
                            json_object_new_boolean(1));
     json_object_object_add(result, "permissions", perms);
 
     return result;
 }
 
 /* Auth: check authd subsystem. */
 static struct json_object *probe_auth(void)
 {
     struct json_object *result = json_object_new_object();
     int available = ubus_object_reachable("dreamingwrt.authd");
 
     json_object_object_add(result, "available",
                            json_object_new_boolean(available));
     if (!available)
         json_object_object_add(result, "reason",
                                json_object_new_string("authd_unavailable"));
     else
         json_object_object_add(result, "reason", NULL);
 
     struct json_object *caps = json_object_new_object();
     json_object_object_add(caps, "accounts_read",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "accounts_write",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "portal_config",
                            json_object_new_boolean(available));
     json_object_object_add(result, "capabilities", caps);
 
     struct json_object *perms = json_object_new_object();
     json_object_object_add(perms, "auth:read",
                            json_object_new_boolean(1));
     json_object_object_add(perms, "auth:write",
                            json_object_new_boolean(1));
     json_object_object_add(result, "permissions", perms);
 
     return result;
 }
 
 /* OTA: check otad subsystem. */
 static struct json_object *probe_ota(void)
 {
     struct json_object *result = json_object_new_object();
     int available = ubus_object_reachable("dreamingwrt.otad");
 
     json_object_object_add(result, "available",
                            json_object_new_boolean(available));
     if (!available)
         json_object_object_add(result, "reason",
                                json_object_new_string("otad_unavailable"));
     else
         json_object_object_add(result, "reason", NULL);
 
     struct json_object *caps = json_object_new_object();
     json_object_object_add(caps, "ota_check",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "ota_apply",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "ota_rollback",
                            json_object_new_boolean(available));
     json_object_object_add(result, "capabilities", caps);
 
     struct json_object *perms = json_object_new_object();
     json_object_object_add(perms, "system:read",
                            json_object_new_boolean(1));
     json_object_object_add(perms, "system:write",
                            json_object_new_boolean(1));
     json_object_object_add(result, "permissions", perms);
 
     return result;
 }
 
 /* ------------------------------------------------------------------ */
 /*  Feature table                                                      */
 /* ------------------------------------------------------------------ */
 
 static const struct feature_descriptor g_features[] = {
     {
         .feature_id   = "wifi.management",
         .display_name = "Wi-Fi Management",
         .ubus_object  = "dreamingwrt",
         .permission   = "wifi:write",
         .probe        = probe_wifi,
     },
     {
         .feature_id   = "auth.accounts",
         .display_name = "Authentication & Accounts",
         .ubus_object  = "dreamingwrt.authd",
         .permission   = "auth:write",
         .probe        = probe_auth,
     },
     {
         .feature_id   = "system.ota",
         .display_name = "OTA Firmware Update",
         .ubus_object  = "dreamingwrt.otad",
         .permission   = "system:write",
         .probe        = probe_ota,
     },
 };
 
 #define FEATURE_COUNT (sizeof(g_features) / sizeof(g_features[0]))
 
 /* ------------------------------------------------------------------ */
 /*  Default probe (ubus existence)                                     */
 /* ------------------------------------------------------------------ */
 
 static struct json_object *default_probe(const struct feature_descriptor *f)
 {
     struct json_object *result = json_object_new_object();
     int available = ubus_object_reachable(f->ubus_object);
 
     json_object_object_add(result, "available",
                            json_object_new_boolean(available));
     if (!available)
         json_object_object_add(result, "reason",
                                json_object_new_string("subsystem_unavailable"));
     else
         json_object_object_add(result, "reason", NULL);
 
     struct json_object *caps = json_object_new_object();
     json_object_object_add(caps, "read",
                            json_object_new_boolean(available));
     json_object_object_add(caps, "write",
                            json_object_new_boolean(available));
     json_object_object_add(result, "capabilities", caps);
 
     struct json_object *perms = json_object_new_object();
     if (f->permission)
         json_object_object_add(perms, f->permission,
                                json_object_new_boolean(1));
     json_object_object_add(result, "permissions", perms);
 
     return result;
 }
 
 /* ------------------------------------------------------------------ */
 /*  Envelope builder (product-plane.v1)                                */
 /* ------------------------------------------------------------------ */
 
 static struct json_object *build_feature_envelope(
     const struct feature_descriptor *f, struct json_object *probe_result)
 {
     struct json_object *envelope = json_object_new_object();
     struct json_object *val;
 
     json_object_object_add(envelope, "contract",
                            json_object_new_string("product-plane.v1"));
     json_object_object_add(envelope, "resource",
                            json_object_new_string("registry.feature"));
     json_object_object_add(envelope, "ok",
                            json_object_new_boolean(1));
 
     /* data */
     struct json_object *data = json_object_new_object();
     json_object_object_add(data, "feature_id",
                            json_object_new_string(f->feature_id));
     json_object_object_add(data, "display_name",
                            json_object_new_string(f->display_name));
 
     if (json_object_object_get_ex(probe_result, "available", &val))
         json_object_object_add(data, "available", json_object_get(val));
     else
         json_object_object_add(data, "available",
                                json_object_new_boolean(0));
 
     if (json_object_object_get_ex(probe_result, "reason", &val))
         json_object_object_add(data, "reason", json_object_get(val));
     else
         json_object_object_add(data, "reason", NULL);
 
     json_object_object_add(envelope, "data", data);
 
     /* capabilities */
     if (json_object_object_get_ex(probe_result, "capabilities", &val))
         json_object_object_add(envelope, "capabilities",
                                json_object_get(val));
     else
         json_object_object_add(envelope, "capabilities",
                                json_object_new_object());
 
     /* permissions */
     if (json_object_object_get_ex(probe_result, "permissions", &val))
         json_object_object_add(envelope, "permissions",
                                json_object_get(val));
     else
         json_object_object_add(envelope, "permissions",
                                json_object_new_object());
 
     return envelope;
 }
 
 /* ------------------------------------------------------------------ */
 /*  Public pure-function API                                           */
 /* ------------------------------------------------------------------ */
 
 struct json_object *feature_registry_list(void)
 {
     struct json_object *response = json_object_new_object();
     struct json_object *features = json_object_new_array();
     size_t i;
 
     json_object_object_add(response, "contract",
                            json_object_new_string("product-plane.v1"));
     json_object_object_add(response, "resource",
                            json_object_new_string("registry.feature_list"));
     json_object_object_add(response, "ok",
                            json_object_new_boolean(1));
 
     for (i = 0; i < FEATURE_COUNT; i++) {
         const struct feature_descriptor *f = &g_features[i];
         struct json_object *probe_result;
 
         if (f->probe)
             probe_result = f->probe();
         else
             probe_result = default_probe(f);
 
         struct json_object *entry = build_feature_envelope(f, probe_result);
         json_object_put(probe_result);
         json_object_array_add(features, entry);
     }
 
     json_object_object_add(response, "data", features);
     return response;
 }
 
 struct json_object *feature_registry_status(const char *feature_id)
 {
     size_t i;
 
     if (!feature_id || !feature_id[0])
         return NULL;
 
     for (i = 0; i < FEATURE_COUNT; i++) {
         const struct feature_descriptor *f = &g_features[i];
 
         if (strcmp(f->feature_id, feature_id) != 0)
             continue;
 
         struct json_object *probe_result;
         if (f->probe)
             probe_result = f->probe();
         else
             probe_result = default_probe(f);
 
         struct json_object *envelope = build_feature_envelope(f, probe_result);
         json_object_put(probe_result);
         return envelope;
     }
 
     return NULL;
 }
 
 /* ------------------------------------------------------------------ */
 /*  ubus reply helper                                                  */
 /* ------------------------------------------------------------------ */
 
 static int reg_send_json(struct ubus_context *ctx,
                          struct ubus_request_data *req,
                          struct json_object *obj)
 {
     const char *s = obj ? json_object_to_json_string(obj) : "{}";
 
     blob_buf_init(&g_reg_blob, 0);
     if (!blobmsg_add_json_from_string(&g_reg_blob, s)) {
         blob_buf_free(&g_reg_blob);
         return UBUS_STATUS_UNKNOWN_ERROR;
     }
     ubus_send_reply(ctx, req, g_reg_blob.head);
     blob_buf_free(&g_reg_blob);
     return UBUS_STATUS_OK;
 }
 
 static int reg_send_error(struct ubus_context *ctx,
                           struct ubus_request_data *req,
                           const char *code, const char *message)
 {
     struct json_object *resp = json_object_new_object();
 
     json_object_object_add(resp, "contract",
                            json_object_new_string("product-plane.v1"));
     json_object_object_add(resp, "resource",
                            json_object_new_string("registry.feature"));
     json_object_object_add(resp, "ok",
                            json_object_new_boolean(0));
 
     struct json_object *err = json_object_new_object();
     json_object_object_add(err, "code",
                            json_object_new_string(code));
     json_object_object_add(err, "message",
                            json_object_new_string(message));
     json_object_object_add(resp, "error", err);
 
     int rc = reg_send_json(ctx, req, resp);
     json_object_put(resp);
     return rc;
 }
 
 /* ------------------------------------------------------------------ */
 /*  ubus method handlers                                               */
 /* ------------------------------------------------------------------ */
 
 static int handle_feature_list(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
 {
     struct json_object *resp;
     int rc;
     (void)obj; (void)method; (void)msg;
 
     resp = feature_registry_list();
     rc = reg_send_json(ctx, req, resp);
     json_object_put(resp);
     return rc;
 }
 
 enum {
     REG_STATUS_FEATURE_ID,
     __REG_STATUS_MAX,
 };
 
 static const struct blobmsg_policy reg_status_policy[__REG_STATUS_MAX] = {
     [REG_STATUS_FEATURE_ID] = {
         .name = "feature_id", .type = BLOBMSG_TYPE_STRING
     },
 };
 
 static int handle_feature_status(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
 {
     struct blob_attr *tb[__REG_STATUS_MAX];
     struct json_object *resp;
     const char *fid;
     int rc;
     (void)obj; (void)method;
 
     blobmsg_parse(reg_status_policy, __REG_STATUS_MAX, tb,
                   blob_data(msg), blob_len(msg));
 
     if (!tb[REG_STATUS_FEATURE_ID])
         return reg_send_error(ctx, req, "missing_parameter",
                               "feature_id is required");
 
     fid = blobmsg_get_string(tb[REG_STATUS_FEATURE_ID]);
     resp = feature_registry_status(fid);
     if (!resp)
         return reg_send_error(ctx, req, "feature_not_found",
                               "unknown feature_id");
 
     rc = reg_send_json(ctx, req, resp);
     json_object_put(resp);
     return rc;
 }
 
 /* ------------------------------------------------------------------ */
 /*  ubus object registration                                           */
 /* ------------------------------------------------------------------ */
 
 static const struct ubus_method reg_methods[] = {
     UBUS_METHOD_NOARG("feature_list", handle_feature_list),
     UBUS_METHOD("feature_status", handle_feature_status, reg_status_policy),
 };
 
 static struct ubus_object_type reg_object_type =
     UBUS_OBJECT_TYPE("dreamingwrt_registry", reg_methods);
 
 static struct ubus_object reg_object = {
     .name = "dreamingwrt.registry",
     .type = &reg_object_type,
     .methods = reg_methods,
     .n_methods = ARRAY_SIZE(reg_methods),
 };
 
 static struct ubus_object reg_alias_object = {
     .name = "dreamingos.registry",
     .type = &reg_object_type,
     .methods = reg_methods,
     .n_methods = ARRAY_SIZE(reg_methods),
 };
 
 /* ------------------------------------------------------------------ */
 /*  Lifecycle                                                          */
 /* ------------------------------------------------------------------ */
 
 int feature_registry_ubus_start(void)
 {
     int rc;
 
     g_reg_ubus = ubus_connect(NULL);
     if (!g_reg_ubus) {
         fprintf(stderr,
                 "[dreamingwrt-registry] ubus connect failed\n");
         return -1;
     }
     ubus_add_uloop(g_reg_ubus);
 
     rc = ubus_add_object(g_reg_ubus, &reg_object);
     if (rc != UBUS_STATUS_OK) {
         fprintf(stderr,
                 "[dreamingwrt-registry] ubus object register failed "
                 "rc=%d\n", rc);
         ubus_free(g_reg_ubus);
         g_reg_ubus = NULL;
         return -1;
     }
 
     rc = ubus_add_object(g_reg_ubus, &reg_alias_object);
     if (rc != UBUS_STATUS_OK) {
         fprintf(stderr,
                 "[dreamingwrt-registry] ubus alias register failed "
                 "rc=%d\n", rc);
         ubus_remove_object(g_reg_ubus, &reg_object);
         ubus_free(g_reg_ubus);
         g_reg_ubus = NULL;
         return -1;
     }
 
     fprintf(stderr,
             "[dreamingwrt-registry] started (%zu features)\n",
             FEATURE_COUNT);
     return 0;
 }
 
 void feature_registry_ubus_stop(void)
 {
     if (g_reg_ubus) {
         ubus_remove_object(g_reg_ubus, &reg_alias_object);
         ubus_remove_object(g_reg_ubus, &reg_object);
         ubus_free(g_reg_ubus);
         g_reg_ubus = NULL;
     }
 }
