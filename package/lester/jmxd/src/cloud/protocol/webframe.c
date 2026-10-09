// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 B2 web-publish schema codec (see webframe.h). Encoders emit
// compact, key-order-stable JSON matching the golden vectors; decoders enforce
// the full field-level schema (required keys, exact types, ranges, valid header
// pairs, NO unknown keys) and fail closed. Self-contained: json-c + wire.h
// constants only, so it keeps wire.c/control.c's property of compiling/fuzzing
// in isolation and can be shared verbatim with the device agent's schema.
#include "webframe.h"
#include "wire.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdint.h>
#include <string.h>

/* ---- strict parse + field helpers (mirror control.c; no cross-file dep) ---- */

/* Strict parse of json[0..len) requiring the whole input be one value of `want`
 * (object/array) with no trailing garbage. Returns a new ref or NULL. */
static struct json_object *web_parse_typed(const char *json, size_t len,
                                           enum json_type want)
{
    if (!json || !len || len > CW_WIRE_FRAME_MAX)
        return NULL;
    struct json_tokener *tok = json_tokener_new_ex(16);
    if (!tok)
        return NULL;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *o = json_tokener_parse_ex(tok, json, (int)len);
    size_t end = json_tokener_get_parse_end(tok);
    while (end < len && isspace((unsigned char)json[end]))
        end++;
    if (json_tokener_get_error(tok) != json_tokener_success ||
        end != len || !json_object_is_type(o, want)) {
        json_object_put(o);
        o = NULL;
    }
    json_tokener_free(tok);
    return o;
}

static struct json_object *web_parse(const char *json, size_t len)
{
    return web_parse_typed(json, len, json_type_object);
}

/* Reject any top-level key of `o` not present in NULL-terminated `allowed`. */
static int web_only_keys(struct json_object *o, const char *const *allowed)
{
    json_object_object_foreach(o, key, value) {
        (void)value;
        size_t i;
        for (i = 0; allowed[i] && strcmp(key, allowed[i]); i++) {}
        if (!allowed[i])
            return 0;
    }
    return 1;
}

/* Required string field: string type, 1..max bytes, NUL-clean, no control
 * chars. Returns a pointer into `o` (valid until o is freed) or NULL. */
static const char *web_str(struct json_object *o, const char *key, size_t max)
{
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) ||
        !json_object_is_type(v, json_type_string))
        return NULL;
    const char *s = json_object_get_string(v);
    size_t n = (size_t)json_object_get_string_len(v);
    if (!n || n > max || strlen(s) != n)
        return NULL;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 32 || s[i] == 127)
            return NULL;
    return s;
}

/* Required integer field constrained to [lo,hi]; must be a JSON int (rejects
 * floats/strings/bools). Sets *out on success. */
static int web_int(struct json_object *o, const char *key,
                   int64_t lo, int64_t hi, int64_t *out)
{
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) ||
        !json_object_is_type(v, json_type_int))
        return -1;
    int64_t n = json_object_get_int64(v);
    if (n < lo || n > hi)
        return -1;
    *out = n;
    return 0;
}

/* Serialize `root` compactly into out[0..cap); returns length (excl. NUL) or
 * -1 if cap is too small. Always releases the reference to `root`. */
static long web_emit(struct json_object *root, char *out, size_t cap)
{
    if (!root)
        return -1;
    size_t len = 0;
    const char *s = json_object_to_json_string_length(
        root, JSON_C_TO_STRING_PLAIN, &len);
    long rc = -1;
    if (s && out && len + 1 <= cap) {
        memcpy(out, s, len);
        out[len] = '\0';
        rc = (long)len;
    }
    json_object_put(root);
    return rc;
}

/* ---- field validators (service_id / method / headers / path) ---- */

/* service_id = [a-z0-9-], 1..CW_WEB_SERVICE_ID_MAX, alnum at both ends (so
 * "s-<id>" stays a valid DNS label sequence). Lowercase only. */
int cw_web_is_service_id(const char *s)
{
    if (!s)
        return 0;
    size_t n = strlen(s);
    if (n < 1 || n > CW_WEB_SERVICE_ID_MAX)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!alnum && c != '-')
            return 0;
        if (c == '-' && (i == 0 || i == n - 1))
            return 0;
    }
    return 1;
}

/* Frozen method allowlist. CONNECT/TRACE and any custom/lowercase token are
 * rejected (fail closed; CONNECT would ask the device to tunnel arbitrarily,
 * which PRD §6.2 forbids). WebSocket rides GET+Upgrade, so GET covers it. */
int cw_web_method_ok(const char *m)
{
    static const char *const ok[] = {
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", NULL };
    if (!m)
        return 0;
    for (size_t i = 0; ok[i]; i++)
        if (strcmp(m, ok[i]) == 0)
            return 1;
    return 0;
}

/* RFC 7230 token char, lowercase only (canonical, HTTP/2 style). */
static int web_is_tchar_lower(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return 1;
    default:
        return 0;
    }
}

/* Header field-name: 1..NAME_MAX lowercase tchar, NUL-clean. */
static int web_hdr_name_ok(const char *s, size_t n)
{
    if (n < 1 || n > CW_WEB_HDR_NAME_MAX || strlen(s) != n)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!web_is_tchar_lower((unsigned char)s[i]))
            return 0;
    return 1;
}

/* Header field-value: 0..VALUE_MAX, NUL-clean, no CR/LF/other C0 except HTAB,
 * no DEL. Empty is allowed. This is the anti-injection guard (blocks CR/LF). */
static int web_hdr_value_ok(const char *s, size_t n)
{
    if (n > CW_WEB_HDR_VALUE_MAX || strlen(s) != n)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c < 0x20 && c != 0x09) || c == 0x7f)
            return 0;
    }
    return 1;
}

/* Origin-form request target: 1..PATH_MAX, must start '/', NUL-clean, reject
 * any byte <= 0x20 (incl. SP) and DEL (percent-encoding carries the rest). */
static int web_path_ok(const char *s, size_t n)
{
    if (n < 1 || n > CW_WEB_PATH_MAX || strlen(s) != n || s[0] != '/')
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

/* headers = array (<= MAX_HEADERS) of [name,value] 2-element string arrays,
 * order + duplicates preserved. Sets *count. Returns 1 if valid. */
static int web_headers_ok(struct json_object *arr, int *count)
{
    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    size_t n = json_object_array_length(arr);
    if (n > CW_WEB_MAX_HEADERS)
        return 0;
    for (size_t i = 0; i < n; i++) {
        struct json_object *pair = json_object_array_get_idx(arr, i);
        if (!pair || !json_object_is_type(pair, json_type_array) ||
            json_object_array_length(pair) != 2)
            return 0;
        struct json_object *jn = json_object_array_get_idx(pair, 0);
        struct json_object *jv = json_object_array_get_idx(pair, 1);
        if (!json_object_is_type(jn, json_type_string) ||
            !json_object_is_type(jv, json_type_string))
            return 0;
        if (!web_hdr_name_ok(json_object_get_string(jn),
                             (size_t)json_object_get_string_len(jn)) ||
            !web_hdr_value_ok(json_object_get_string(jv),
                              (size_t)json_object_get_string_len(jv)))
            return 0;
    }
    *count = (int)n;
    return 1;
}

/* ---- OPEN head {service_id, method, path, headers}  (cloud -> device) ---- */

long cw_web_open_encode(const char *service_id, const char *method,
                        const char *path, const char *headers_json,
                        char *out, size_t cap)
{
    if (!cw_web_is_service_id(service_id) || !cw_web_method_ok(method) ||
        !path || !web_path_ok(path, strlen(path)) || !headers_json)
        return -1;
    struct json_object *arr = web_parse_typed(headers_json, strlen(headers_json),
                                              json_type_array);
    int hc = 0;
    if (!arr || !web_headers_ok(arr, &hc)) {
        json_object_put(arr);
        return -1;
    }
    struct json_object *o = json_object_new_object();
    if (!o) {
        json_object_put(arr);
        return -1;
    }
    json_object_object_add(o, "service_id", json_object_new_string(service_id));
    json_object_object_add(o, "method", json_object_new_string(method));
    json_object_object_add(o, "path", json_object_new_string(path));
    json_object_object_add(o, "headers", arr);   /* takes ownership of arr */
    return web_emit(o, out, cap);
}

int cw_web_open_decode(const char *json, size_t len, struct cw_web_open *out)
{
    static const char *const keys[] = { "service_id", "method",
                                         "path", "headers", NULL };
    struct json_object *o = web_parse(json, len);
    if (!o)
        return -1;
    int rc = -1, hc = 0;
    struct json_object *arr = NULL;
    const char *sid = web_str(o, "service_id", CW_WEB_SERVICE_ID_MAX);
    const char *m   = web_str(o, "method", CW_WEB_METHOD_MAX);
    const char *p   = web_str(o, "path", CW_WEB_PATH_MAX);
    if (web_only_keys(o, keys) &&
        sid && cw_web_is_service_id(sid) &&
        m && cw_web_method_ok(m) &&
        p && web_path_ok(p, strlen(p)) &&
        json_object_object_get_ex(o, "headers", &arr) &&
        web_headers_ok(arr, &hc)) {
        memcpy(out->service_id, sid, strlen(sid) + 1);
        memcpy(out->method, m, strlen(m) + 1);
        memcpy(out->path, p, strlen(p) + 1);
        out->n_headers = hc;
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- RESP head {status, headers}  (device -> cloud) ---- */

long cw_web_resp_encode(int status, const char *headers_json,
                        char *out, size_t cap)
{
    if (status < CW_WEB_STATUS_MIN || status > CW_WEB_STATUS_MAX || !headers_json)
        return -1;
    struct json_object *arr = web_parse_typed(headers_json, strlen(headers_json),
                                              json_type_array);
    int hc = 0;
    if (!arr || !web_headers_ok(arr, &hc)) {
        json_object_put(arr);
        return -1;
    }
    struct json_object *o = json_object_new_object();
    if (!o) {
        json_object_put(arr);
        return -1;
    }
    json_object_object_add(o, "status", json_object_new_int64(status));
    json_object_object_add(o, "headers", arr);   /* takes ownership of arr */
    return web_emit(o, out, cap);
}

int cw_web_resp_decode(const char *json, size_t len, struct cw_web_resp *out)
{
    static const char *const keys[] = { "status", "headers", NULL };
    struct json_object *o = web_parse(json, len);
    if (!o)
        return -1;
    int rc = -1, hc = 0;
    int64_t st = 0;
    struct json_object *arr = NULL;
    if (web_only_keys(o, keys) &&
        web_int(o, "status", CW_WEB_STATUS_MIN, CW_WEB_STATUS_MAX, &st) == 0 &&
        json_object_object_get_ex(o, "headers", &arr) &&
        web_headers_ok(arr, &hc)) {
        out->status = (int)st;
        out->n_headers = hc;
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- SERVICES manifest element {service_id}  (cloud -> device, B2) ----
 * The ENVELOPE {revision,services[],sig} stays in control.c (elements opaque
 * there). This freezes ONE element: presence in the signed manifest =
 * authorized. Destination (host/port/target) is deliberately absent -- it is
 * device-local by service_id (PRD §6.2); the illustrative {"...","port":80}
 * in wire doc §18 was an opacity example, never a committed field. */

long cw_web_service_encode(const char *service_id, char *out, size_t cap)
{
    if (!cw_web_is_service_id(service_id))
        return -1;
    struct json_object *o = json_object_new_object();
    if (!o)
        return -1;
    json_object_object_add(o, "service_id", json_object_new_string(service_id));
    return web_emit(o, out, cap);
}

int cw_web_service_decode(const char *json, size_t len, struct cw_web_service *out)
{
    static const char *const keys[] = { "service_id", NULL };
    struct json_object *o = web_parse(json, len);
    if (!o)
        return -1;
    int rc = -1;
    const char *sid = web_str(o, "service_id", CW_WEB_SERVICE_ID_MAX);
    if (web_only_keys(o, keys) && sid && cw_web_is_service_id(sid)) {
        memcpy(out->service_id, sid, strlen(sid) + 1);
        rc = 0;
    }
    json_object_put(o);
    return rc;
}
