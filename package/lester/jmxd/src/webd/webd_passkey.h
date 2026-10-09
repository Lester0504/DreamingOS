/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * WebAuthn / Passkey backend for DreamingWrt Web Console.
 *
 * Provides credential registration (attestation), authentication (assertion),
 * challenge lifecycle, credential CRUD, and COSE-to-OpenSSL signature
 * verification. Runs as a webd sub-module; routes are registered in
 * jmx_app_api.c alongside the existing /api/v1/session/ endpoints.
 *
 * Storage:
 *   /etc/dreamingwrt/passkeys/config.json
 *   /etc/dreamingwrt/passkeys/credentials/<credential_id_hex>.json
 *
 * Dependencies:
 *   OpenSSL (EVP_PKEY, SHA-256, EC P-256, RSA-256)
 *   json-c
 *   Minimal inline CBOR decoder (no external library)
 */
#ifndef DREAMINGWRT_WEBD_PASSKEY_H
#define DREAMINGWRT_WEBD_PASSKEY_H

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>
#include <sqlite3.h>

/* ── Limits ── */

#define WEBD_PASSKEY_CHALLENGE_LEN       32
#define WEBD_PASSKEY_CHALLENGE_HEX_LEN   (WEBD_PASSKEY_CHALLENGE_LEN * 2)
#define WEBD_PASSKEY_CHALLENGE_TTL_S     60
#define WEBD_PASSKEY_MAX_CREDENTIALS     16
#define WEBD_PASSKEY_CREDENTIAL_ID_MAX   1024
#define WEBD_PASSKEY_FRIENDLY_NAME_MAX   64
#define WEBD_PASSKEY_RP_ID_MAX           253
#define WEBD_PASSKEY_RP_NAME_MAX         64

/* COSE algorithm identifiers we accept. */
#define WEBD_PASSKEY_COSE_ES256   (-7)    /* EC P-256 + SHA-256 */
#define WEBD_PASSKEY_COSE_RS256   (-257)  /* RSASSA-PKCS1-v1_5 + SHA-256 */

/* ── Storage paths ── */

#ifndef WEBD_PASSKEY_DIR
#define WEBD_PASSKEY_DIR          "/etc/dreamingwrt/passkeys"
#endif
#ifndef WEBD_PASSKEY_CRED_DIR
#define WEBD_PASSKEY_CRED_DIR     WEBD_PASSKEY_DIR "/credentials"
#endif
#ifndef WEBD_PASSKEY_CONFIG_PATH
#define WEBD_PASSKEY_CONFIG_PATH  WEBD_PASSKEY_DIR "/config.json"
#endif
#ifndef WEBD_PASSKEY_CHALLENGE_DIR
#define WEBD_PASSKEY_CHALLENGE_DIR "/run/dreamingwrt/passkeys/challenges"
#endif

/* ── Error codes ── */

enum webd_passkey_result {
    WEBD_PASSKEY_OK                     =  0,
    WEBD_PASSKEY_ERR_INVALID_ARGUMENT   = -1,
    WEBD_PASSKEY_ERR_NOT_FOUND          = -2,
    WEBD_PASSKEY_ERR_CHALLENGE_EXPIRED  = -3,
    WEBD_PASSKEY_ERR_CHALLENGE_MISMATCH = -4,
    WEBD_PASSKEY_ERR_ORIGIN_MISMATCH    = -5,
    WEBD_PASSKEY_ERR_RP_ID_MISMATCH     = -6,
    WEBD_PASSKEY_ERR_SIGNATURE_INVALID  = -7,
    WEBD_PASSKEY_ERR_SIGN_COUNT         = -8,
    WEBD_PASSKEY_ERR_MAX_CREDENTIALS    = -9,
    WEBD_PASSKEY_ERR_DUPLICATE          = -10,
    WEBD_PASSKEY_ERR_CBOR_PARSE         = -11,
    WEBD_PASSKEY_ERR_COSE_UNSUPPORTED   = -12,
    WEBD_PASSKEY_ERR_STORAGE            = -13,
    WEBD_PASSKEY_ERR_ENTROPY            = -14,
    WEBD_PASSKEY_ERR_OPENSSL            = -15,
    WEBD_PASSKEY_ERR_PASSWORD           = -16,
    WEBD_PASSKEY_ERR_TYPE_MISMATCH      = -17,
};

/* ── Credential record (persisted as JSON) ── */

struct webd_passkey_credential {
    char     credential_id_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
    int      cose_alg;          /* COSE algorithm id (-7 or -257) */
    uint8_t *public_key_der;    /* DER-encoded SubjectPublicKeyInfo */
    size_t   public_key_der_len;
    uint32_t sign_count;
    int64_t  created_at;
    int64_t  last_used_at;
    char     friendly_name[WEBD_PASSKEY_FRIENDLY_NAME_MAX + 1];
    char     username[65];      /* web console user who registered it */
};

/* ── Challenge record (persisted under /run for multi-worker webd) ── */

struct webd_passkey_challenge {
    uint8_t  challenge[WEBD_PASSKEY_CHALLENGE_LEN];
    char     challenge_hex[WEBD_PASSKEY_CHALLENGE_HEX_LEN + 1];
    int64_t  created_at;
    int      is_registration;   /* 1 = attestation, 0 = login, 2 = reauthentication */
    char     username[65];      /* only for registration */
    char     friendly_name[WEBD_PASSKEY_FRIENDLY_NAME_MAX + 1];
    char     operation_binding[65]; /* SHA256(session + operation + revision) */
};

/* webd owns the existing PBKDF2 verifier in jmx_app_api.c. */
typedef int (*webd_passkey_verify_password_cb)(
    const char *username, const char *password);

/*
 * ── Public API: route handlers ──
 *
 * Each handler returns a json-c object (caller owns it) and sets *http_status.
 * The dispatch in jmx_app_api.c calls these directly.
 *
 * Parameters:
 *   body      - parsed request body (may be NULL for GET)
 *   username  - authenticated user from session token (NULL for unauth routes)
 *   http_status - output HTTP status code
 */

/* GET  /api/v1/passkey/can-authenticate (no auth) */
struct json_object *webd_passkey_can_authenticate(int *http_status);

/* POST /api/v1/passkey/authenticate/begin (no auth) */
struct json_object *webd_passkey_authenticate_begin(
    struct json_object *body, int *http_status);

/* POST /api/v1/passkey/authenticate/finish (no auth)
 * On success, creates session tokens via webd_session_idle_login_insert(). */
struct json_object *webd_passkey_authenticate_finish(
    struct json_object *body, sqlite3 *config_db, sqlite3 *app_db,
    int *http_status);

/* Authenticated operation confirmation; never creates login tokens. Binding
 * is server-computed, not accepted from the browser as an authority. */
struct json_object *webd_passkey_reauthenticate_begin(
    const char *username, const char *binding, int *http_status);
struct json_object *webd_passkey_reauthenticate_finish(
    struct json_object *body, sqlite3 *config_db, const char *username,
    const char *binding, int *http_status);

/* POST /api/v1/passkey/register/begin (auth + password) */
struct json_object *webd_passkey_register_begin(
    struct json_object *body, const char *username,
    const char *client_ip, int *http_status);

/* POST /api/v1/passkey/register/finish (auth) */
struct json_object *webd_passkey_register_finish(
    struct json_object *body, const char *username, int *http_status);

/* GET  /api/v1/passkey/list (auth) */
struct json_object *webd_passkey_list(
    const char *username, int *http_status);

/* POST /api/v1/passkey/delete (auth + password) */
struct json_object *webd_passkey_delete(
    struct json_object *body, const char *username,
    const char *client_ip, int *http_status);

/* POST /api/v1/passkey/rename (auth) */
struct json_object *webd_passkey_rename(
    struct json_object *body, const char *username, int *http_status);

/* ── Lifecycle ── */

/* Initialize passkey subsystem: load config, create directories.
 * Called once from jmx_app_api_init(). */
int webd_passkey_init(void);

/* Periodic GC: expire stale challenges. Called from a timer or on each request. */
void webd_passkey_gc(void);

/* ── Config helpers ── */

/* Read the effective rp_id. Falls back to the system hostname.
 * Writes into out (at most out_len bytes). Returns 0 on success. */
int webd_passkey_rp_id(char *out, size_t out_len);

void webd_passkey_set_password_verifier(webd_passkey_verify_password_cb verify);

/* ── Base64url codec (thin wrapper over OpenSSL base64) ── */

/* Decode base64url to binary. Returns decoded length, or -1 on error.
 * out must be at least (in_len * 3 / 4 + 3) bytes. */
int webd_base64url_decode(const char *in, size_t in_len,
                          uint8_t *out, size_t out_max);

/* Encode binary to base64url (no padding). Returns 0 on success. */
int webd_base64url_encode(const uint8_t *in, size_t in_len,
                          char *out, size_t out_max);

/* ── Minimal CBOR decoder (subset for attestationObject) ── */

enum webd_cbor_type {
    WEBD_CBOR_UINT    = 0,
    WEBD_CBOR_NINT    = 1,  /* negative integer */
    WEBD_CBOR_BSTR    = 2,  /* byte string */
    WEBD_CBOR_TSTR    = 3,  /* text string */
    WEBD_CBOR_ARRAY   = 4,
    WEBD_CBOR_MAP     = 5,
    WEBD_CBOR_SIMPLE  = 7,
    WEBD_CBOR_ERROR   = 0xff,
};

struct webd_cbor_item {
    enum webd_cbor_type type;
    union {
        uint64_t    uint_val;
        int64_t     int_val;
        struct { const uint8_t *data; size_t len; } str;
        size_t      container_count;  /* number of items in array/map */
    } v;
};

/* Decode one CBOR item from buf[*pos]. Advances *pos past the header.
 * For strings, v.str.data points into buf (zero-copy).
 * For containers, only the count is returned; caller iterates children.
 * Returns 0 on success, -1 on parse error. */
int webd_cbor_decode_item(const uint8_t *buf, size_t buf_len,
                          size_t *pos, struct webd_cbor_item *item);

/* Skip one complete CBOR item (including nested containers). */
int webd_cbor_skip_item(const uint8_t *buf, size_t buf_len, size_t *pos);

/* Human-readable error string. */
const char *webd_passkey_strerror(int result);

#endif /* DREAMINGWRT_WEBD_PASSKEY_H */
