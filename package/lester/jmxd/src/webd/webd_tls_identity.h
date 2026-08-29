/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DREAMINGWRT_WEBD_TLS_IDENTITY_H
#define DREAMINGWRT_WEBD_TLS_IDENTITY_H

#include <stddef.h>

struct json_object;

/* Build the public TLS identity from an explicit PEM certificate path.
 * The returned object is owned by the caller. NULL means the certificate is
 * unavailable or malformed; use webd_tls_identity_attach() for the wire shape.
 */
struct json_object *webd_tls_identity_from_certificate(const char *cert_path);

/* Add a stable readback shape without ever exposing certificate/private-key
 * material: {tls_identity: {...}} or {tls_identity: null,
 * tls_identity_reason: tls_identity_unavailable|tls_identity_malformed}.
 */
void webd_tls_identity_attach(struct json_object *object);

#endif
