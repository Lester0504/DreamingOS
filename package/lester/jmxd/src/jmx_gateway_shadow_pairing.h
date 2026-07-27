// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_gateway_shadow_pairing.h - Gateway Shadow authenticated pairing
 *
 * This module is intentionally independent from the Gateway Shadow runtime
 * controller.  The controller may call these entry points after the protocol
 * has been linked, but this file has no dependency on webd or ubus.
 */
#ifndef __JMX_GATEWAY_SHADOW_PAIRING_H__
#define __JMX_GATEWAY_SHADOW_PAIRING_H__

#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JMX_GATEWAY_SHADOW_PAIRING_PROTOCOL \
    "dreamingwrt-gateway-shadow-pairing"
#define JMX_GATEWAY_SHADOW_PAIRING_VERSION 1

/* Create the pairing-only schema in DREAMINGWRT_CONFIG_DB (idempotent). */
int jmx_gateway_shadow_pairing_schema_ensure(void);

/* Return the public Ed25519 identity.  Private key material is never returned. */
struct json_object *jmx_gateway_shadow_pairing_identity(void);

/*
 * Initial call (action absent or "start"):
 *   returns a signed offer and a local-only plaintext pairing_code.
 * Final call (action="finalize"):
 *   verifies the responder acceptance and returns a signed confirmation.
 */
struct json_object *jmx_gateway_shadow_pairing_protocol_start(
    struct json_object *payload);

/*
 * Initial call (action absent or "approve"):
 *   verifies offer + user-entered pairing_code and returns an acceptance.
 * Final call (action="confirm"):
 *   verifies the initiator confirmation and completes responder trust.
 */
struct json_object *jmx_gateway_shadow_pairing_protocol_approve(
    struct json_object *payload);

#ifdef __cplusplus
}
#endif

#endif /* __JMX_GATEWAY_SHADOW_PAIRING_H__ */
