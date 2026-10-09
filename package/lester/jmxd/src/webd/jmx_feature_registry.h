 /* SPDX-License-Identifier: GPL-2.0-or-later */
 /*
  * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
  *
  * Feature/Resource/Capability registry.
  *
  * Exposes a unified ubus interface (dreamingwrt.registry / dreamingos.registry)
  * so that frontends and the task center can query "which features exist, which
  * are available, and why not".
  *
  * Responses follow product-plane-contract-v1.md (section 3 resource envelope).
  */
 #ifndef DREAMINGWRT_FEATURE_REGISTRY_H
 #define DREAMINGWRT_FEATURE_REGISTRY_H
 
 #include <json-c/json.h>
 
 /* -- Lifecycle (call from webd_main or equivalent) -- */
 
 /*
  * Connect to ubus and register dreamingwrt.registry + dreamingos.registry.
  * Returns 0 on success, -1 on failure.
  */
 int  feature_registry_ubus_start(void);
 void feature_registry_ubus_stop(void);
 
 /* -- Probe interface -- */
 
 /*
  * A feature probe checks whether a subsystem is available at query time.
  * Returns a newly-owned json_object with at least:
  *   { "available": bool, "reason": string|null,
  *     "capabilities": {...}, "permissions": {...} }
  */
 typedef struct json_object *(*feature_probe_fn)(void);
 
 /*
  * Static feature descriptor.  Populated once at compile time; the probe
  * function runs on every query so the answer is always live.
  */
 struct feature_descriptor {
     const char       *feature_id;     /* e.g. "wifi.management"           */
     const char       *display_name;   /* human label, may be i18n key     */
     const char       *ubus_object;    /* subsystem ubus name to probe     */
     const char       *permission;     /* primary permission, e.g. "wifi:write" */
     feature_probe_fn  probe;          /* NULL = ubus-existence-only probe */
 };
 
 /* -- Pure-function helpers (usable without ubus) -- */
 
 /*
  * Build a product-plane.v1 feature_list response from the compiled-in
  * descriptor table.  Caller owns the result.
  */
 struct json_object *feature_registry_list(void);
 
 /*
  * Build a product-plane.v1 feature_status response for one feature_id.
  * Returns NULL if the feature_id is unknown.  Caller owns the result.
  */
 struct json_object *feature_registry_status(const char *feature_id);
 
 #endif
