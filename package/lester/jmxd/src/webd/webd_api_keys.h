// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Outbound-facing API-Key channel: credentials an external agent presents to
 * call this router's API without holding a web session.
 *
 * Deliberately separate from `auth_tokens`, which stores its token in the
 * clear. Only a keyed digest of an API-Key is ever persisted, so a leaked
 * database, backup, or OTA image does not hand over usable credentials.
 */
#ifndef __WEBD_API_KEYS_H__
#define __WEBD_API_KEYS_H__

#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

/* Plaintext key layout: dwrt_<key_id>_<secret>. The prefix exists so leak
 * scanners and log filters can recognise the credential on sight. */
#define WEBD_API_KEY_PREFIX      "dwrt_"
#define WEBD_API_KEY_ID_LEN      16   /* hex chars */
#define WEBD_API_KEY_SECRET_LEN  64   /* hex chars, from 32 random bytes */
#define WEBD_API_KEY_PLAIN_MAX   128
#define WEBD_API_KEY_NAME_MAX    64
#define WEBD_API_KEY_SCOPE_MAX   2048
#define WEBD_API_KEY_IPS_MAX     512

/* Digest scheme identifier, so a future algorithm change can migrate rows
 * instead of invalidating every key. */
#define WEBD_API_KEY_DIGEST_V1   1

/* Scope tiers, mirroring what the management UI offers. */
typedef enum {
    WEBD_API_KEY_TIER_READ_ONLY = 0,
    WEBD_API_KEY_TIER_CONTROL   = 1
} webd_api_key_tier_t;

/* Outcome of authenticating a presented key. Every value maps to an audit
 * failure_reason so a rejection is always explainable after the fact. */
typedef enum {
    WEBD_API_KEY_OK = 0,
    WEBD_API_KEY_NOT_PRESENTED,
    WEBD_API_KEY_MALFORMED,
    WEBD_API_KEY_UNKNOWN,
    WEBD_API_KEY_REVOKED,
    WEBD_API_KEY_EXPIRED,
    WEBD_API_KEY_IP_NOT_ALLOWED,
    WEBD_API_KEY_SCOPE_DENIED,
    WEBD_API_KEY_FORBIDDEN_ROUTE,
    WEBD_API_KEY_RATE_LIMITED,
    WEBD_API_KEY_DB_ERROR
} webd_api_key_result_t;

struct webd_api_key_identity {
    char key_id[WEBD_API_KEY_ID_LEN + 1];
    char name[WEBD_API_KEY_NAME_MAX + 1];
    webd_api_key_tier_t tier;
    int64_t expires_at;
};

/* Creates the api_keys table. Safe to call repeatedly. */
int webd_api_keys_init(sqlite3 *db);

/*
 * True when the value looks like an API-Key rather than a session token.
 * Used to route an `Authorization: Bearer dwrt_...` value to this channel
 * without a database round trip.
 */
int webd_api_key_looks_like_key(const char *value);

/*
 * Routes an API-Key must never reach, whatever its stored scope says.
 *
 * The user set the shell prohibition as a non-negotiable floor, so it lives
 * in code rather than in configuration: a scope row can be written wrong, a
 * compiled hard gate cannot.
 *
 * Returns 1 when the route is permanently closed to key auth.
 */
int webd_api_key_route_forbidden(const char *method, const char *path);

/*
 * Authenticates a presented key and authorises it for method+path.
 *
 * `peer_ip` must be the TCP peer address, not a header-supplied value: the IP
 * allowlist and the audit trail are both worthless against a forgeable input.
 * On WEBD_API_KEY_OK the identity is filled in for the caller's audit record.
 */
webd_api_key_result_t webd_api_key_authenticate(sqlite3 *db,
                                                const char *presented,
                                                const char *method,
                                                const char *path,
                                                const char *peer_ip,
                                                struct webd_api_key_identity *out);

/* Maps a result to the stable failure_reason string used in audit rows. */
const char *webd_api_key_result_str(webd_api_key_result_t r);

/* Records successful use. Best-effort: a failed bookkeeping write must not
 * turn an authorised call into an error. */
void webd_api_key_mark_used(sqlite3 *db, const char *key_id,
                            const char *peer_ip, int64_t now);

/*
 * Creates a key. `plain_out` receives the only copy of the plaintext that will
 * ever exist; the caller returns it once and must not persist or log it.
 */
int webd_api_key_create(sqlite3 *db, const char *name, webd_api_key_tier_t tier,
                        const char *scope_json, const char *allow_ips,
                        int64_t expires_at, const char *created_by,
                        char *plain_out, size_t plain_out_len,
                        char *key_id_out, size_t key_id_out_len);

int webd_api_key_revoke(sqlite3 *db, const char *key_id, int64_t now);
int webd_api_key_delete(sqlite3 *db, const char *key_id);
int webd_api_key_exists(sqlite3 *db, const char *key_id);

/* Validates a caller-supplied scope document. Returns 0 when usable. */
int webd_api_key_scope_valid(const char *scope_json, char *reason,
                             size_t reason_len);

/* Validates an IP allowlist string (comma separated CIDRs or addresses).
 * An empty value is valid and means "no source restriction". */
int webd_api_key_allow_ips_valid(const char *allow_ips, char *reason,
                                 size_t reason_len);

const char *webd_api_key_tier_str(webd_api_key_tier_t tier);
int webd_api_key_tier_parse(const char *s, webd_api_key_tier_t *out);

#endif /* __WEBD_API_KEYS_H__ */
