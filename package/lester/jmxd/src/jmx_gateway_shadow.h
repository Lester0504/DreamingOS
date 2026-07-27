// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_gateway_shadow.h - Gateway Shadow (VRRP HA) control plane
 *
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_GATEWAY_SHADOW_H__
#define __JMX_GATEWAY_SHADOW_H__

#include <json-c/json.h>

/* Ensure schema tables exist (idempotent; called from netconfig init). */
int jmx_gateway_shadow_schema_ensure(void);

/* Full config + capabilities snapshot. */
struct json_object *jmx_gateway_shadow_get(void);

/* Runtime/status only. */
struct json_object *jmx_gateway_shadow_status(void);

/* Local preflight: packages, interfaces, config sanity. Does not mutate peer trust. */
struct json_object *jmx_gateway_shadow_preflight(struct json_object *payload);

/* Persist draft config. Secrets are write-only. */
struct json_object *jmx_gateway_shadow_save(struct json_object *payload);

/*
 * Apply runtime. Fail-closed unless preflight + packages allow activation.
 * Never claims seamless session continuity.
 */
struct json_object *jmx_gateway_shadow_apply(struct json_object *payload);

/* Disable and best-effort stop external daemons managed by this feature. */
struct json_object *jmx_gateway_shadow_disable(struct json_object *payload);

/* Pairing phase-1: honest capability_disabled until mutual auth exists. */
struct json_object *jmx_gateway_shadow_pairing_start(struct json_object *payload);
struct json_object *jmx_gateway_shadow_pairing_approve(struct json_object *payload);

#endif /* __JMX_GATEWAY_SHADOW_H__ */
