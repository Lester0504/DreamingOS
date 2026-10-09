// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 CONTROL-frame JSON schema codec (see control.h). Encoders emit
// compact, key-order-stable JSON matching the golden vectors; decoders enforce
// the full field-level schema (required keys, exact types, ranges, and NO
// unknown keys) and fail closed. Self-contained: json-c + wire.h constants
// only, so it keeps wire.c's property of compiling/fuzzing in isolation and can
// be shared verbatim with the device agent's schema (jmxd adopts it at B1).
#include "control.h"
#include "wire.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdint.h>
#include <string.h>

/* ---- strict parse + field helpers (no common.c dependency) ---- */

/* Strict parse of json[0..len) requiring the whole input be one value of `want`
 * (object/array) with no trailing garbage. Returns a new ref or NULL. */
static struct json_object *ctl_parse_typed(const char *json, size_t len,
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

static struct json_object *ctl_parse(const char *json, size_t len)
{
    return ctl_parse_typed(json, len, json_type_object);
}

/* Reject any top-level key of `o` not present in NULL-terminated `allowed`. */
static int ctl_only_keys(struct json_object *o, const char *const *allowed)
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
static const char *ctl_str(struct json_object *o, const char *key, size_t max)
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
static int ctl_int(struct json_object *o, const char *key,
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

static int ctl_is_lower_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* relay_router_id = "router-" + 32 lowercase hex, exactly 39 chars. */
static int ctl_is_router_id(const char *s)
{
    return s && strlen(s) == CW_CTL_ROUTER_ID_LEN &&
           strncmp(s, "router-", 7) == 0 && ctl_is_lower_hex(s + 7, 32);
}

/* base64 alphabet check (charset only; non-emptiness ensured by ctl_str). */
static int ctl_is_base64(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
            return 0;
    }
    return 1;
}

/* Serialize `root` compactly into out[0..cap); returns length (excl. NUL) or
 * -1 if cap is too small. Always releases the reference to `root`. */
static long ctl_emit(struct json_object *root, char *out, size_t cap)
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

/* ---- GENERATION.action enum <-> string ---- */

int cw_ctl_action_from_str(const char *s)
{
    if (!s) return -1;
    if (!strcmp(s, "enable"))    return CW_CTL_GEN_ENABLE;
    if (!strcmp(s, "revoke"))    return CW_CTL_GEN_REVOKE;
    if (!strcmp(s, "supersede")) return CW_CTL_GEN_SUPERSEDE;
    return -1;
}

const char *cw_ctl_action_str(int action)
{
    switch (action) {
    case CW_CTL_GEN_ENABLE:    return "enable";
    case CW_CTL_GEN_REVOKE:    return "revoke";
    case CW_CTL_GEN_SUPERSEDE: return "supersede";
    default:                   return NULL;
    }
}

/* ---- HELLO {proto, relay_router_id, generation}  (device -> cloud) ---- */

long cw_ctl_hello_encode(const struct cw_ctl_hello *h, char *out, size_t cap)
{
    if (!h || h->proto != CW_WIRE_VERSION ||
        !ctl_is_router_id(h->relay_router_id) || h->generation == 0)
        return -1;
    struct json_object *o = json_object_new_object();
    if (!o) return -1;
    json_object_object_add(o, "proto", json_object_new_int64(h->proto));
    json_object_object_add(o, "relay_router_id",
                           json_object_new_string(h->relay_router_id));
    json_object_object_add(o, "generation", json_object_new_int64(h->generation));
    return ctl_emit(o, out, cap);
}

int cw_ctl_hello_decode(const char *json, size_t len, struct cw_ctl_hello *out)
{
    static const char *const keys[] = { "proto", "relay_router_id",
                                         "generation", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1;
    int64_t proto = 0, gen = 0;
    const char *rid = ctl_str(o, "relay_router_id", CW_CTL_ROUTER_ID_LEN);
    if (ctl_only_keys(o, keys) &&
        ctl_int(o, "proto", CW_WIRE_VERSION, CW_WIRE_VERSION, &proto) == 0 &&
        rid && ctl_is_router_id(rid) &&
        ctl_int(o, "generation", 1, 0xffffffffLL, &gen) == 0) {
        out->proto = (uint32_t)proto;
        memcpy(out->relay_router_id, rid, CW_CTL_ROUTER_ID_LEN + 1);
        out->generation = (uint32_t)gen;
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- WELCOME {session_id, generation, heartbeat, limits{...}} ---- */

long cw_ctl_welcome_encode(const struct cw_ctl_welcome *w, char *out, size_t cap)
{
    if (!w || strlen(w->session_id) != CW_CTL_SESSION_ID_LEN ||
        !ctl_is_lower_hex(w->session_id, CW_CTL_SESSION_ID_LEN) ||
        w->generation == 0 ||
        w->heartbeat == 0 || w->heartbeat > (uint32_t)CW_WIRE_PING_TIMEOUT ||
        w->limits.max_streams == 0 || w->limits.max_streams > CW_WIRE_MAX_STREAMS ||
        w->limits.stream_window == 0 ||
        w->limits.stream_window > CW_WIRE_WINDOW_MAX ||
        w->limits.conn_window < w->limits.stream_window ||
        w->limits.conn_window > CW_WIRE_WINDOW_MAX)
        return -1;
    struct json_object *o = json_object_new_object();
    struct json_object *lim = json_object_new_object();
    if (!o || !lim) { json_object_put(o); json_object_put(lim); return -1; }
    json_object_object_add(o, "session_id", json_object_new_string(w->session_id));
    json_object_object_add(o, "generation", json_object_new_int64(w->generation));
    json_object_object_add(o, "heartbeat", json_object_new_int64(w->heartbeat));
    json_object_object_add(lim, "max_streams",
                           json_object_new_int64(w->limits.max_streams));
    json_object_object_add(lim, "stream_window",
                           json_object_new_int64(w->limits.stream_window));
    json_object_object_add(lim, "conn_window",
                           json_object_new_int64(w->limits.conn_window));
    json_object_object_add(o, "limits", lim);
    return ctl_emit(o, out, cap);
}

int cw_ctl_welcome_decode(const char *json, size_t len, struct cw_ctl_welcome *out)
{
    static const char *const keys[]  = { "session_id", "generation",
                                          "heartbeat", "limits", NULL };
    static const char *const lkeys[] = { "max_streams", "stream_window",
                                          "conn_window", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1;
    struct json_object *lim = NULL;
    int64_t gen = 0, hb = 0, ms = 0, sw = 0, cwnd = 0;
    const char *sid = ctl_str(o, "session_id", CW_CTL_SESSION_ID_LEN);
    if (ctl_only_keys(o, keys) &&
        sid && strlen(sid) == CW_CTL_SESSION_ID_LEN &&
        ctl_is_lower_hex(sid, CW_CTL_SESSION_ID_LEN) &&
        ctl_int(o, "generation", 1, 0xffffffffLL, &gen) == 0 &&
        ctl_int(o, "heartbeat", 1, CW_WIRE_PING_TIMEOUT, &hb) == 0 &&
        json_object_object_get_ex(o, "limits", &lim) &&
        json_object_is_type(lim, json_type_object) &&
        ctl_only_keys(lim, lkeys) &&
        ctl_int(lim, "max_streams", 1, CW_WIRE_MAX_STREAMS, &ms) == 0 &&
        ctl_int(lim, "stream_window", 1, CW_WIRE_WINDOW_MAX, &sw) == 0 &&
        ctl_int(lim, "conn_window", sw, CW_WIRE_WINDOW_MAX, &cwnd) == 0) {
        memcpy(out->session_id, sid, CW_CTL_SESSION_ID_LEN + 1);
        out->generation = (uint32_t)gen;
        out->heartbeat = (uint32_t)hb;
        out->limits.max_streams = (uint32_t)ms;
        out->limits.stream_window = (uint32_t)sw;
        out->limits.conn_window = (uint32_t)cwnd;
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- GENERATION {generation, action}  (cloud -> device) ---- */

long cw_ctl_generation_encode(const struct cw_ctl_generation *g,
                              char *out, size_t cap)
{
    const char *a = g ? cw_ctl_action_str(g->action) : NULL;
    if (!g || g->generation == 0 || !a)
        return -1;
    struct json_object *o = json_object_new_object();
    if (!o) return -1;
    json_object_object_add(o, "generation", json_object_new_int64(g->generation));
    json_object_object_add(o, "action", json_object_new_string(a));
    return ctl_emit(o, out, cap);
}

int cw_ctl_generation_decode(const char *json, size_t len,
                             struct cw_ctl_generation *out)
{
    static const char *const keys[] = { "generation", "action", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1, act = -1;
    int64_t gen = 0;
    const char *a = ctl_str(o, "action", 16);
    if (ctl_only_keys(o, keys) &&
        ctl_int(o, "generation", 1, 0xffffffffLL, &gen) == 0 &&
        a && (act = cw_ctl_action_from_str(a)) != -1) {
        out->generation = (uint32_t)gen;
        out->action = act;
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- GOAWAY {code, last_stream_id, reason}  (either direction) ---- */

long cw_ctl_goaway_encode(const struct cw_ctl_goaway *g, char *out, size_t cap)
{
    if (!g || g->code < CW_ERR_NONE || g->code > CW_ERR_INTERNAL)
        return -1;
    size_t rlen = strlen(g->reason);
    if (rlen > CW_CTL_REASON_MAX)
        return -1;
    for (size_t i = 0; i < rlen; i++)
        if ((unsigned char)g->reason[i] < 32 || g->reason[i] == 127)
            return -1;
    struct json_object *o = json_object_new_object();
    if (!o) return -1;
    json_object_object_add(o, "code", json_object_new_int64(g->code));
    json_object_object_add(o, "last_stream_id",
                           json_object_new_int64(g->last_stream_id));
    json_object_object_add(o, "reason", json_object_new_string(g->reason));
    return ctl_emit(o, out, cap);
}

int cw_ctl_goaway_decode(const char *json, size_t len, struct cw_ctl_goaway *out)
{
    static const char *const keys[] = { "code", "last_stream_id",
                                         "reason", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1, reason_ok = 1;
    int64_t code = 0, lsid = 0;
    char reason[CW_CTL_REASON_MAX + 1];
    reason[0] = '\0';
    struct json_object *rv = NULL;
    /* reason is optional; when present it must be a printable string (empty
     * allowed, so encode("")/decode round-trips) of <= CW_CTL_REASON_MAX. */
    if (json_object_object_get_ex(o, "reason", &rv)) {
        reason_ok = 0;
        if (json_object_is_type(rv, json_type_string)) {
            const char *rs = json_object_get_string(rv);
            size_t rn = (size_t)json_object_get_string_len(rv);
            if (rn <= CW_CTL_REASON_MAX && strlen(rs) == rn) {
                reason_ok = 1;
                for (size_t i = 0; i < rn && reason_ok; i++)
                    if ((unsigned char)rs[i] < 32 || rs[i] == 127)
                        reason_ok = 0;
                if (reason_ok) { memcpy(reason, rs, rn); reason[rn] = '\0'; }
            }
        }
    }
    if (ctl_only_keys(o, keys) && reason_ok &&
        ctl_int(o, "code", CW_ERR_NONE, CW_ERR_INTERNAL, &code) == 0 &&
        ctl_int(o, "last_stream_id", 0, 0xffffffffLL, &lsid) == 0) {
        out->code = (int)code;
        out->last_stream_id = (uint32_t)lsid;
        memcpy(out->reason, reason, sizeof reason);
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- SERVICES {revision, services[], sig}  (envelope only; elements B2) ---- */

long cw_ctl_services_encode(int64_t revision, const char *services_array_json,
                            const char *sig, char *out, size_t cap)
{
    if (revision < 1 || !services_array_json || !sig)
        return -1;
    size_t slen = strlen(sig);
    if (!slen || slen > CW_CTL_SIG_MAX || !ctl_is_base64(sig, slen))
        return -1;
    /* The manifest body is opaque here; the envelope only requires it be a
     * JSON array. Parse it strictly and re-emit it inside the envelope so the
     * whole payload is one deterministic compact serialization. */
    struct json_object *arr = ctl_parse_typed(services_array_json,
                                              strlen(services_array_json),
                                              json_type_array);
    if (!arr) return -1;
    struct json_object *o = json_object_new_object();
    if (!o) { json_object_put(arr); return -1; }
    json_object_object_add(o, "revision", json_object_new_int64(revision));
    json_object_object_add(o, "services", arr);   /* takes ownership of arr */
    json_object_object_add(o, "sig", json_object_new_string(sig));
    return ctl_emit(o, out, cap);
}

int cw_ctl_services_decode(const char *json, size_t len,
                           struct cw_ctl_services *out)
{
    static const char *const keys[] = { "revision", "services", "sig", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1;
    int64_t rev = 0;
    struct json_object *arr = NULL;
    const char *sig = ctl_str(o, "sig", CW_CTL_SIG_MAX);
    if (ctl_only_keys(o, keys) &&
        ctl_int(o, "revision", 1, INT64_MAX, &rev) == 0 &&
        json_object_object_get_ex(o, "services", &arr) &&
        json_object_is_type(arr, json_type_array) &&
        sig && ctl_is_base64(sig, strlen(sig))) {
        out->revision = rev;
        out->n_services = (int)json_object_array_length(arr);
        memcpy(out->sig, sig, strlen(sig) + 1);
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- AUTH_CHALLENGE {nonce}  (cloud -> device, §20) ---- */

long cw_ctl_auth_challenge_encode(const struct cw_ctl_auth_challenge *c,
                                  char *out, size_t cap)
{
    if (!c || strlen(c->nonce) != CW_CTL_NONCE_LEN ||
        !ctl_is_lower_hex(c->nonce, CW_CTL_NONCE_LEN))
        return -1;
    struct json_object *o = json_object_new_object();
    if (!o) return -1;
    json_object_object_add(o, "nonce", json_object_new_string(c->nonce));
    return ctl_emit(o, out, cap);
}

int cw_ctl_auth_challenge_decode(const char *json, size_t len,
                                 struct cw_ctl_auth_challenge *out)
{
    static const char *const keys[] = { "nonce", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1;
    const char *nonce = ctl_str(o, "nonce", CW_CTL_NONCE_LEN);
    if (ctl_only_keys(o, keys) &&
        nonce && strlen(nonce) == CW_CTL_NONCE_LEN &&
        ctl_is_lower_hex(nonce, CW_CTL_NONCE_LEN)) {
        memcpy(out->nonce, nonce, CW_CTL_NONCE_LEN + 1);
        rc = 0;
    }
    json_object_put(o);
    return rc;
}

/* ---- AUTH_RESPONSE {sign_pub, kex_pub, signature}  (device -> cloud, §20) ---- */

/* Exact-length base64 field: a JSON string of exactly `n` base64 chars. The
 * actual base64->bytes decode + crypto verification is cloud-internal (device.c
 * / tunnel_server.c); this codec only freezes the JSON shape + charset. */
static const char *ctl_b64_exact(struct json_object *o, const char *key, size_t n)
{
    const char *s = ctl_str(o, key, n);
    if (!s || strlen(s) != n || !ctl_is_base64(s, n))
        return NULL;
    return s;
}

long cw_ctl_auth_response_encode(const struct cw_ctl_auth_response *r,
                                 char *out, size_t cap)
{
    if (!r ||
        strlen(r->sign_pub) != CW_CTL_PUBKEY_B64 ||
        !ctl_is_base64(r->sign_pub, CW_CTL_PUBKEY_B64) ||
        strlen(r->kex_pub) != CW_CTL_PUBKEY_B64 ||
        !ctl_is_base64(r->kex_pub, CW_CTL_PUBKEY_B64) ||
        strlen(r->signature) != CW_CTL_SIG_B64 ||
        !ctl_is_base64(r->signature, CW_CTL_SIG_B64))
        return -1;
    struct json_object *o = json_object_new_object();
    if (!o) return -1;
    json_object_object_add(o, "sign_pub", json_object_new_string(r->sign_pub));
    json_object_object_add(o, "kex_pub", json_object_new_string(r->kex_pub));
    json_object_object_add(o, "signature", json_object_new_string(r->signature));
    return ctl_emit(o, out, cap);
}

int cw_ctl_auth_response_decode(const char *json, size_t len,
                                struct cw_ctl_auth_response *out)
{
    static const char *const keys[] = { "sign_pub", "kex_pub",
                                         "signature", NULL };
    struct json_object *o = ctl_parse(json, len);
    if (!o) return -1;
    int rc = -1;
    const char *sp = ctl_b64_exact(o, "sign_pub", CW_CTL_PUBKEY_B64);
    const char *kp = ctl_b64_exact(o, "kex_pub", CW_CTL_PUBKEY_B64);
    const char *sg = ctl_b64_exact(o, "signature", CW_CTL_SIG_B64);
    if (ctl_only_keys(o, keys) && sp && kp && sg) {
        memcpy(out->sign_pub, sp, CW_CTL_PUBKEY_B64 + 1);
        memcpy(out->kex_pub, kp, CW_CTL_PUBKEY_B64 + 1);
        memcpy(out->signature, sg, CW_CTL_SIG_B64 + 1);
        rc = 0;
    }
    json_object_put(o);
    return rc;
}
