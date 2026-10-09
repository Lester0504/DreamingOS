// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 B2 web-publish schema: the field-level JSON schema of the
// DATA-frame heads OPEN (0x10) / RESP (0x11) framed by wire.h/wire.c, plus the
// SERVICES manifest ELEMENT (the per-service object inside the array whose
// ENVELOPE {revision,services[],sig} is frozen in control.c / wire doc §18).
// wire.c freezes only the 12-byte framing; control.c freezes the five CONTROL
// payloads; this header + webframe.c freeze the B2 data-plane heads + service
// element, with strict validation and byte-stable encoders.
//
// Shared contract between the cloud gateway (dreamingrelay/cloud-web) and the
// device agent (jmxd/src/cloud): the SCHEMA and the golden vectors in
// tests/test_cloud_web_webframe.c are authoritative. This json-c implementation
// is cloud-web's; the device side must reproduce the same schema and golden
// bytes (it may use its own JSON library). Dependency-free apart from wire.h
// (constants) + json-c, so it compiles/fuzzes in isolation like wire.c/control.c.
//
// Destination stays device-local (PRD §6.2): OPEN carries a registered
// `service_id` ONLY, never a URL/host/IP/port; the device maps service_id ->
// its own fixed local record. The SERVICES element therefore carries no
// destination either -- its presence in the signed manifest = the service is
// currently authorized; absence => the device rejects OPEN with CW_ERR_SERVICE.
#ifndef DREAMINGOS_CLOUD_WEB_WEBFRAME_H
#define DREAMINGOS_CLOUD_WEB_WEBFRAME_H

#include <stddef.h>

/* Bounds. Heads are still capped by the wire frame (CW_WIRE_FRAME_MAX=65536);
 * these per-field caps fail closed well inside that. */
#define CW_WEB_SERVICE_ID_MAX 63     /* DNS-label-safe token (s-<id>.apps...) */
#define CW_WEB_METHOD_MAX     16     /* longest allowlisted method + slack */
#define CW_WEB_PATH_MAX       8192   /* origin-form request target */
#define CW_WEB_HDR_NAME_MAX   256    /* one header field-name */
#define CW_WEB_HDR_VALUE_MAX  8192   /* one header field-value */
#define CW_WEB_MAX_HEADERS    128    /* header entries per head */
#define CW_WEB_STATUS_MIN     100
#define CW_WEB_STATUS_MAX     599

struct cw_web_open {                 /* OPEN head: browser request, cloud->device */
    char service_id[CW_WEB_SERVICE_ID_MAX + 1];
    char method[CW_WEB_METHOD_MAX + 1];
    char path[CW_WEB_PATH_MAX + 1];
    int  n_headers;                  /* validated header count */
};

struct cw_web_resp {                 /* RESP head: {status,headers}, device->cloud */
    int status;                      /* CW_WEB_STATUS_MIN .. CW_WEB_STATUS_MAX */
    int n_headers;
};

struct cw_web_service {              /* one SERVICES manifest element (B2) */
    char service_id[CW_WEB_SERVICE_ID_MAX + 1];
};

/* Encoders: write a compact, byte-stable JSON head into out[0..cap) and return
 * the length written (excluding the NUL), or -1 on a schema violation or a cap
 * that is too small. Key order is fixed (see webframe.c) so output matches the
 * golden vectors byte-for-byte.
 *
 * headers_json is a pre-serialized JSON array of [name,value] pairs, e.g.
 * "[[\"host\",\"s-web.apps.dreamingnet.com\"],[\"accept\",\"application/json\"]]";
 * pass "[]" for no headers. Each pair is validated (name = lowercase HTTP token
 * 1..CW_WEB_HDR_NAME_MAX; value 0..CW_WEB_HDR_VALUE_MAX with no CR/LF/NUL/C0
 * except HTAB), then re-emitted deterministically. */
long cw_web_open_encode(const char *service_id, const char *method,
                        const char *path, const char *headers_json,
                        char *out, size_t cap);
long cw_web_resp_encode(int status, const char *headers_json,
                        char *out, size_t cap);
/* SERVICES element {service_id}. presence in the signed manifest = authorized. */
long cw_web_service_encode(const char *service_id, char *out, size_t cap);

/* Decoders: parse json[0..len), enforce the full field-level schema (required
 * keys, exact types, ranges, valid header pairs, and NO unknown keys), fill
 * *out, and return 0; return -1 on malformed JSON or any schema violation. */
int cw_web_open_decode(const char *json, size_t len, struct cw_web_open *out);
int cw_web_resp_decode(const char *json, size_t len, struct cw_web_resp *out);
int cw_web_service_decode(const char *json, size_t len, struct cw_web_service *out);

/* Exposed predicates (for callers/tests). 1 if valid, else 0. */
int cw_web_is_service_id(const char *s);   /* [a-z0-9-] 1..63, alnum ends */
int cw_web_method_ok(const char *m);       /* in the frozen method allowlist */

#endif
