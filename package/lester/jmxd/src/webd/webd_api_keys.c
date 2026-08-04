// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * API-Key channel storage and authorisation.
 */
#include "webd_api_keys.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <json-c/json.h>

#define API_KEY_PEPPER_PATH "/etc/dreamingwrt/api-key-pepper"
#define API_KEY_RATE_WINDOW_S 60
#define API_KEY_RATE_MAX      120   /* per key_id, per source IP, per window */
#define API_KEY_RATE_SLOTS    64

/* ── low level helpers ── */

static void api_key_hex(const unsigned char *in, size_t in_len, char *out,
                        size_t out_len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (!out || out_len < in_len * 2 + 1) {
        if (out && out_len)
            out[0] = '\0';
        return;
    }
    for (i = 0; i < in_len; i++) {
        out[i * 2] = digits[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
}

/* Constant time compare. A length-dependent early exit here would leak how
 * much of a guessed digest matched. */
static int api_key_ct_equal(const char *a, const char *b)
{
    size_t alen, blen, n, i;
    unsigned char diff = 0;

    if (!a || !b)
        return 0;
    alen = strlen(a);
    blen = strlen(b);
    n = alen > blen ? alen : blen;
    for (i = 0; i < n; i++) {
        unsigned char ac = i < alen ? (unsigned char)a[i] : 0;
        unsigned char bc = i < blen ? (unsigned char)b[i] : 0;

        diff |= (unsigned char)(ac ^ bc);
    }
    return diff == 0 && alen == blen;
}

/*
 * Per-installation HMAC pepper.
 *
 * A bare SHA256 of a high-entropy key is already hard to reverse, but the
 * digest would then be identical on every router, which makes a stolen
 * database table comparable across devices. The pepper is stored outside the
 * database on purpose: a leaked db backup alone cannot verify guesses.
 */
static int api_key_pepper(unsigned char *out, size_t out_len)
{
    FILE *f;
    unsigned char fresh[32];
    size_t got;

    if (!out || out_len < sizeof(fresh))
        return -1;
    f = fopen(API_KEY_PEPPER_PATH, "rb");
    if (f) {
        got = fread(out, 1, sizeof(fresh), f);
        fclose(f);
        if (got == sizeof(fresh))
            return 0;
    }
    if (RAND_bytes(fresh, sizeof(fresh)) != 1)
        return -1;
    f = fopen(API_KEY_PEPPER_PATH, "wb");
    if (!f) {
        OPENSSL_cleanse(fresh, sizeof(fresh));
        return -1;
    }
    /* 0600 before any content is written: the window between create and
     * chmod is exactly when another local process could read it. */
    (void)fchmod(fileno(f), 0600);
    got = fwrite(fresh, 1, sizeof(fresh), f);
    if (fflush(f) != 0 || got != sizeof(fresh)) {
        fclose(f);
        OPENSSL_cleanse(fresh, sizeof(fresh));
        return -1;
    }
    fclose(f);
    memcpy(out, fresh, sizeof(fresh));
    OPENSSL_cleanse(fresh, sizeof(fresh));
    return 0;
}

/* HMAC-SHA256(pepper, key_id || ':' || secret). key_id is mixed in so a
 * secret cannot be replayed under a different key_id row. */
static int api_key_digest(const char *key_id, const char *secret,
                          char out[65])
{
    unsigned char pepper[32];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    char msg[WEBD_API_KEY_ID_LEN + WEBD_API_KEY_SECRET_LEN + 2];
    int rc = -1;

    if (!key_id || !secret || !out)
        return -1;
    if (snprintf(msg, sizeof(msg), "%s:%s", key_id, secret) >= (int)sizeof(msg))
        return -1;
    if (api_key_pepper(pepper, sizeof(pepper)) != 0)
        goto done;
    if (!HMAC(EVP_sha256(), pepper, (int)sizeof(pepper),
              (const unsigned char *)msg, strlen(msg), mac, &mac_len) ||
        mac_len != 32)
        goto done;
    api_key_hex(mac, mac_len, out, 65);
    rc = out[0] ? 0 : -1;
done:
    OPENSSL_cleanse(pepper, sizeof(pepper));
    OPENSSL_cleanse(msg, sizeof(msg));
    return rc;
}

static int api_key_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;

    if (!db || !sql)
        return -1;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int webd_api_keys_init(sqlite3 *db)
{
    if (!db)
        return -1;
    return api_key_exec(db,
        "CREATE TABLE IF NOT EXISTS api_keys ("
        " key_id TEXT PRIMARY KEY,"
        " key_hash TEXT NOT NULL,"
        " digest_version INTEGER NOT NULL DEFAULT 1,"
        " name TEXT NOT NULL DEFAULT '',"
        " tier TEXT NOT NULL DEFAULT 'read_only',"
        " scope_json TEXT NOT NULL DEFAULT '',"
        " allow_ips TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " expires_at INTEGER NOT NULL DEFAULT 0,"
        " last_used_at INTEGER NOT NULL DEFAULT 0,"
        " last_used_ip TEXT NOT NULL DEFAULT '',"
        " use_count INTEGER NOT NULL DEFAULT 0,"
        " revoked_at INTEGER NOT NULL DEFAULT 0,"
        " created_by TEXT NOT NULL DEFAULT '')");
}

const char *webd_api_key_tier_str(webd_api_key_tier_t tier)
{
    return tier == WEBD_API_KEY_TIER_CONTROL ? "control" : "read_only";
}

int webd_api_key_tier_parse(const char *s, webd_api_key_tier_t *out)
{
    if (!s || !out)
        return -1;
    if (!strcmp(s, "read_only") || !strcmp(s, "readonly")) {
        *out = WEBD_API_KEY_TIER_READ_ONLY;
        return 0;
    }
    if (!strcmp(s, "control")) {
        *out = WEBD_API_KEY_TIER_CONTROL;
        return 0;
    }
    /* `admin` is refused rather than silently downgraded: a caller asking for
     * it must see that this channel does not offer it. */
    return -1;
}

int webd_api_key_looks_like_key(const char *value)
{
    size_t prefix = sizeof(WEBD_API_KEY_PREFIX) - 1;

    if (!value || strncmp(value, WEBD_API_KEY_PREFIX, prefix) != 0)
        return 0;
    /* Length check only; the real decision is made by the digest lookup. */
    return strlen(value) >
           prefix + WEBD_API_KEY_ID_LEN + 1;
}

/* ── path normalisation ── */

static int api_key_hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Canonicalises a request path before any scope or hard-gate comparison.
 *
 * Scope bypass is the realistic attack on this feature, so matching never sees
 * the raw path: percent escapes are decoded, duplicate slashes collapsed, `.`
 * and `..` segments resolved, the trailing slash dropped, and the result
 * lowercased. Comparing a raw path would let `/API/V1/%73ystem//x/../shell`
 * miss a gate that `/api/v1/system/shell` hits.
 *
 * Returns 0 on success, -1 when the input cannot be represented safely.
 */
static int api_key_normalize_path(const char *path, char *out, size_t out_len)
{
    char decoded[1024];
    size_t i = 0, o = 0;
    char *segments[64];
    int depth = 0;
    char work[1024];
    size_t w = 0;

    if (!path || !out || out_len < 2)
        return -1;
    /* percent-decode, rejecting NUL injection and malformed escapes */
    while (path[i] && o < sizeof(decoded) - 1) {
        if (path[i] == '%') {
            int hi = api_key_hexval(path[i + 1]);
            int lo = hi >= 0 ? api_key_hexval(path[i + 2]) : -1;

            if (hi < 0 || lo < 0)
                return -1;
            if ((hi << 4 | lo) == 0)
                return -1;
            decoded[o++] = (char)(hi << 4 | lo);
            i += 3;
            continue;
        }
        decoded[o++] = path[i++];
    }
    if (path[i])
        return -1;
    decoded[o] = '\0';
    if (decoded[0] != '/')
        return -1;

    /* split and resolve . / .. */
    if (strlen(decoded) >= sizeof(work))
        return -1;
    memcpy(work, decoded, strlen(decoded) + 1);
    {
        char *save = NULL;
        char *tok = strtok_r(work, "/", &save);

        while (tok) {
            if (!strcmp(tok, ".")) {
                /* no-op segment */
            } else if (!strcmp(tok, "..")) {
                if (depth > 0)
                    depth--;
            } else if (tok[0]) {
                if (depth >= (int)(sizeof(segments) / sizeof(segments[0])))
                    return -1;
                segments[depth++] = tok;
            }
            tok = strtok_r(NULL, "/", &save);
        }
    }

    for (int s = 0; s < depth; s++) {
        size_t len = strlen(segments[s]);

        if (w + len + 2 > out_len)
            return -1;
        out[w++] = '/';
        for (size_t c = 0; c < len; c++)
            out[w++] = (char)tolower((unsigned char)segments[s][c]);
    }
    if (w == 0) {
        if (out_len < 2)
            return -1;
        out[w++] = '/';
    }
    out[w] = '\0';
    return 0;
}

/* ── hard gates ── */

/*
 * Route prefixes an API-Key may never reach.
 *
 * Ordering note: these are checked against the normalised path with segment
 * aware matching, so "/api/v1/system/ttyd" also covers "/api/v1/system/ttyd/x"
 * but not "/api/v1/system/ttyd-status".
 */
static const char *const g_api_key_forbidden[] = {
    /* shell / command execution — user-declared permanent floor */
    "/terminal",
    "/api/v1/system/ttyd",
    "/api/v1/policy-engine/terminal-groups",
    /*
     * Device-destroying operations: an unattended credential must not be able
     * to reset or reflash the router.
     *
     * Whole subtrees rather than leaf routes. An earlier version of this list
     * enumerated leaves and named several that do not exist — the real routes
     * carry an extra `flash/` segment — so factory_reset, sysupgrade,
     * upload_firmware and restore_backup were all reachable while the list
     * looked complete. A list that reads as covered but denies nothing is worse
     * than a short one, so these are prefixes and every entry below is a route
     * that actually exists in jmx_app_perms.c.
     *
     * This closes the LOW-risk /api/v1/system/flash/capabilities too. That is
     * deliberate: a key has no reason to read flash capability bits, and
     * carving out an exception is how the enumeration mistake comes back.
     */
    "/api/v1/system/flash",
    "/api/v1/system/power",
    "/api/v1/system/ota",
    "/api/v1/system/reboot",
    "/api/v1/system/shutdown",
    "/api/v1/system/backup",
    "/api/v1/system/upgrade",
    "/api/v1/system/restore",
    "/api/v1/system/kernel/restore-defaults",
    "/api/v1/setup",
    /* key self-management: prevents a key from minting or renewing itself */
    "/api/v1/auth/api-keys",
    /* identity and credential surfaces */
    "/api/v1/auth/pair",
    "/api/v1/auth/2fa",
    "/api/v1/system/admin",
    "/api/v1/system/users",
    "/api/v1/system/user-groups",
    NULL
};

/* Segment-aware prefix match on an already normalised path. */
static int api_key_prefix_match(const char *path, const char *prefix)
{
    size_t len = strlen(prefix);

    if (strncmp(path, prefix, len) != 0)
        return 0;
    return path[len] == '\0' || path[len] == '/';
}

static int api_key_method_is_readonly(const char *method)
{
    return method && (!strcasecmp(method, "GET") || !strcasecmp(method, "HEAD") ||
                      !strcasecmp(method, "OPTIONS"));
}

int webd_api_key_route_forbidden(const char *method, const char *path)
{
    char norm[1024];
    int i;

    (void)method;
    if (!path)
        return 1;
    /* A path that cannot be normalised is refused rather than passed through:
     * an unparseable path is exactly what a bypass attempt looks like. */
    if (api_key_normalize_path(path, norm, sizeof(norm)) != 0)
        return 1;
    for (i = 0; g_api_key_forbidden[i]; i++) {
        if (api_key_prefix_match(norm, g_api_key_forbidden[i]))
            return 1;
    }
    /* Writes to the file manager stay closed even under the control tier. */
    if (api_key_prefix_match(norm, "/api/v1/storage/files") &&
        !api_key_method_is_readonly(method))
        return 1;
    return 0;
}

/* ── scope ── */

int webd_api_key_scope_valid(const char *scope_json, char *reason,
                             size_t reason_len)
{
    struct json_object *root, *allow = NULL, *methods = NULL;
    size_t n, i;
    int rc = -1;

    if (!scope_json || !scope_json[0])
        return 0;   /* empty scope means "tier default", which is valid */
    if (strlen(scope_json) > WEBD_API_KEY_SCOPE_MAX) {
        if (reason) snprintf(reason, reason_len, "scope_too_long");
        return -1;
    }
    root = json_tokener_parse(scope_json);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (reason) snprintf(reason, reason_len, "scope_not_object");
        goto done;
    }
    if (json_object_object_get_ex(root, "allow", &allow) && allow) {
        if (!json_object_is_type(allow, json_type_array)) {
            if (reason) snprintf(reason, reason_len, "scope_allow_not_array");
            goto done;
        }
        n = json_object_array_length(allow);
        for (i = 0; i < n; i++) {
            struct json_object *e = json_object_array_get_idx(allow, i);
            const char *s = e && json_object_is_type(e, json_type_string) ?
                            json_object_get_string(e) : NULL;

            if (!s || s[0] != '/') {
                if (reason) snprintf(reason, reason_len, "scope_allow_entry_invalid");
                goto done;
            }
        }
    }
    if (json_object_object_get_ex(root, "methods", &methods) && methods) {
        if (!json_object_is_type(methods, json_type_array)) {
            if (reason) snprintf(reason, reason_len, "scope_methods_not_array");
            goto done;
        }
    }
    rc = 0;
done:
    if (root)
        json_object_put(root);
    return rc;
}

/*
 * Decides whether a stored scope permits method+path.
 *
 * Default deny: an empty or absent `allow` list grants nothing beyond the tier
 * default, and an unlisted path is refused. The inverse ("everything except a
 * blacklist") would silently expose every route added later.
 */
static int api_key_scope_allows(const char *scope_json, const char *method,
                                const char *norm_path)
{
    struct json_object *root, *allow = NULL, *methods = NULL;
    int path_ok = 0, method_ok = 0;
    size_t n, i;

    if (!scope_json || !scope_json[0])
        return 1;   /* no explicit scope: tier rules alone decide */
    root = json_tokener_parse(scope_json);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root)
            json_object_put(root);
        return 0;
    }
    if (!json_object_object_get_ex(root, "allow", &allow) || !allow ||
        !json_object_is_type(allow, json_type_array) ||
        json_object_array_length(allow) == 0) {
        path_ok = 1;   /* nothing narrowed: fall back to tier rules */
    } else {
        n = json_object_array_length(allow);
        for (i = 0; i < n && !path_ok; i++) {
            struct json_object *e = json_object_array_get_idx(allow, i);
            const char *pattern = e && json_object_is_type(e, json_type_string) ?
                                  json_object_get_string(e) : NULL;
            char lowered[512];
            size_t len, c;

            if (!pattern || !pattern[0])
                continue;
            len = strlen(pattern);
            if (len >= sizeof(lowered))
                continue;
            for (c = 0; c < len; c++)
                lowered[c] = (char)tolower((unsigned char)pattern[c]);
            lowered[len] = '\0';
            /* trailing '*' is a subtree wildcard; anything else is exact or
             * segment-prefix */
            if (len && lowered[len - 1] == '*') {
                lowered[len - 1] = '\0';
                while (len > 1 && lowered[len - 2] == '/') {
                    lowered[len - 2] = '\0';
                    len--;
                }
                if (api_key_prefix_match(norm_path, lowered))
                    path_ok = 1;
            } else {
                if (len > 1 && lowered[len - 1] == '/')
                    lowered[len - 1] = '\0';
                if (!strcmp(norm_path, lowered))
                    path_ok = 1;
            }
        }
    }
    if (!json_object_object_get_ex(root, "methods", &methods) || !methods ||
        !json_object_is_type(methods, json_type_array) ||
        json_object_array_length(methods) == 0) {
        method_ok = 1;
    } else {
        n = json_object_array_length(methods);
        for (i = 0; i < n && !method_ok; i++) {
            struct json_object *e = json_object_array_get_idx(methods, i);
            const char *m = e && json_object_is_type(e, json_type_string) ?
                            json_object_get_string(e) : NULL;

            if (m && method && !strcasecmp(m, method))
                method_ok = 1;
        }
    }
    json_object_put(root);
    return path_ok && method_ok;
}

/* ── IP allowlist ── */

static int api_key_parse_cidr(const char *entry, unsigned char *net,
                              int *bits, int *family)
{
    char buf[64];
    char *slash;
    struct in_addr v4;
    struct in6_addr v6;

    if (!entry || !entry[0] || strlen(entry) >= sizeof(buf))
        return -1;
    snprintf(buf, sizeof(buf), "%s", entry);
    slash = strchr(buf, '/');
    if (slash) {
        char *end = NULL;
        long v;

        *slash = '\0';
        v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0)
            return -1;
        *bits = (int)v;
    } else {
        *bits = -1;
    }
    if (inet_pton(AF_INET, buf, &v4) == 1) {
        *family = AF_INET;
        if (*bits < 0)
            *bits = 32;
        if (*bits > 32)
            return -1;
        memcpy(net, &v4, 4);
        return 0;
    }
    if (inet_pton(AF_INET6, buf, &v6) == 1) {
        *family = AF_INET6;
        if (*bits < 0)
            *bits = 128;
        if (*bits > 128)
            return -1;
        memcpy(net, &v6, 16);
        return 0;
    }
    return -1;
}

static int api_key_ip_in_cidr(const char *ip, const char *entry)
{
    unsigned char net[16], addr[16];
    int bits = 0, family = 0, addr_family;
    struct in_addr v4;
    struct in6_addr v6;
    int full_bytes, rest;

    if (api_key_parse_cidr(entry, net, &bits, &family) != 0)
        return 0;
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        addr_family = AF_INET;
        memcpy(addr, &v4, 4);
    } else if (inet_pton(AF_INET6, ip, &v6) == 1) {
        addr_family = AF_INET6;
        memcpy(addr, &v6, 16);
    } else {
        return 0;
    }
    if (addr_family != family)
        return 0;
    full_bytes = bits / 8;
    rest = bits % 8;
    if (full_bytes && memcmp(addr, net, (size_t)full_bytes) != 0)
        return 0;
    if (rest) {
        unsigned char mask = (unsigned char)(0xff << (8 - rest));

        if ((addr[full_bytes] & mask) != (net[full_bytes] & mask))
            return 0;
    }
    return 1;
}

int webd_api_key_allow_ips_valid(const char *allow_ips, char *reason,
                                 size_t reason_len)
{
    char buf[WEBD_API_KEY_IPS_MAX + 1];
    char *save = NULL, *tok;
    unsigned char net[16];
    int bits, family;

    if (!allow_ips || !allow_ips[0])
        return 0;
    if (strlen(allow_ips) > WEBD_API_KEY_IPS_MAX) {
        if (reason) snprintf(reason, reason_len, "allow_ips_too_long");
        return -1;
    }
    snprintf(buf, sizeof(buf), "%s", allow_ips);
    tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok && api_key_parse_cidr(tok, net, &bits, &family) != 0) {
            if (reason) snprintf(reason, reason_len, "allow_ips_entry_invalid");
            return -1;
        }
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static int api_key_ip_allowed(const char *allow_ips, const char *peer_ip)
{
    char buf[WEBD_API_KEY_IPS_MAX + 1];
    char *save = NULL, *tok;

    if (!allow_ips || !allow_ips[0])
        return 1;   /* empty allowlist means unrestricted, per user decision */
    if (!peer_ip || !peer_ip[0])
        return 0;
    snprintf(buf, sizeof(buf), "%s", allow_ips);
    tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok && api_key_ip_in_cidr(peer_ip, tok))
            return 1;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

/* ── rate limiting ── */

struct api_key_rate_slot {
    char key_id[WEBD_API_KEY_ID_LEN + 1];
    char ip[64];
    int64_t window_start;
    int count;
};

static struct api_key_rate_slot g_rate_slots[API_KEY_RATE_SLOTS];

/* Returns 1 when the call is within budget, 0 when it must be refused. */
static int api_key_rate_ok(const char *key_id, const char *ip, int64_t now)
{
    struct api_key_rate_slot *victim = NULL;
    int i;

    if (!key_id || !ip)
        return 1;
    for (i = 0; i < API_KEY_RATE_SLOTS; i++) {
        struct api_key_rate_slot *s = &g_rate_slots[i];

        if (s->key_id[0] && !strcmp(s->key_id, key_id) && !strcmp(s->ip, ip)) {
            if (now - s->window_start >= API_KEY_RATE_WINDOW_S) {
                s->window_start = now;
                s->count = 0;
            }
            if (s->count >= API_KEY_RATE_MAX)
                return 0;
            s->count++;
            return 1;
        }
        if (!s->key_id[0]) {
            victim = victim ? victim : s;
        } else if (now - s->window_start >= API_KEY_RATE_WINDOW_S) {
            /* Reuse the stalest expired slot rather than the first one seen, so
             * a burst of distinct keys cannot evict an active counter. */
            if (!victim || victim->key_id[0])
                victim = s;
        }
    }
    if (!victim)
        victim = &g_rate_slots[0];
    snprintf(victim->key_id, sizeof(victim->key_id), "%s", key_id);
    snprintf(victim->ip, sizeof(victim->ip), "%s", ip);
    victim->window_start = now;
    victim->count = 1;
    return 1;
}

/* ── authentication ── */

const char *webd_api_key_result_str(webd_api_key_result_t r)
{
    switch (r) {
    case WEBD_API_KEY_OK:               return "ok";
    case WEBD_API_KEY_NOT_PRESENTED:    return "not_presented";
    case WEBD_API_KEY_MALFORMED:        return "malformed_key";
    case WEBD_API_KEY_UNKNOWN:          return "unknown_key";
    case WEBD_API_KEY_REVOKED:          return "revoked";
    case WEBD_API_KEY_EXPIRED:          return "expired";
    case WEBD_API_KEY_IP_NOT_ALLOWED:   return "ip_not_allowed";
    case WEBD_API_KEY_SCOPE_DENIED:     return "scope_denied";
    case WEBD_API_KEY_FORBIDDEN_ROUTE:  return "forbidden_route";
    case WEBD_API_KEY_RATE_LIMITED:     return "rate_limited";
    case WEBD_API_KEY_DB_ERROR:         return "key_store_unavailable";
    }
    return "denied";
}

/* Splits dwrt_<key_id>_<secret>. */
static int api_key_split(const char *presented, char *key_id, size_t id_len,
                         char *secret, size_t secret_len)
{
    size_t prefix = sizeof(WEBD_API_KEY_PREFIX) - 1;
    const char *rest, *sep;
    size_t i;

    if (!webd_api_key_looks_like_key(presented))
        return -1;
    if (strlen(presented) > WEBD_API_KEY_PLAIN_MAX)
        return -1;
    rest = presented + prefix;
    sep = strchr(rest, '_');
    if (!sep || (size_t)(sep - rest) != WEBD_API_KEY_ID_LEN)
        return -1;
    if (id_len < WEBD_API_KEY_ID_LEN + 1)
        return -1;
    memcpy(key_id, rest, WEBD_API_KEY_ID_LEN);
    key_id[WEBD_API_KEY_ID_LEN] = '\0';
    if (strlen(sep + 1) != WEBD_API_KEY_SECRET_LEN ||
        secret_len < WEBD_API_KEY_SECRET_LEN + 1)
        return -1;
    memcpy(secret, sep + 1, WEBD_API_KEY_SECRET_LEN + 1);
    /* both halves must be hex: rejects anything that could confuse the digest
     * or the SQL lookup */
    for (i = 0; i < WEBD_API_KEY_ID_LEN; i++) {
        if (api_key_hexval(key_id[i]) < 0)
            return -1;
    }
    for (i = 0; i < WEBD_API_KEY_SECRET_LEN; i++) {
        if (api_key_hexval(secret[i]) < 0)
            return -1;
    }
    return 0;
}

webd_api_key_result_t webd_api_key_authenticate(sqlite3 *db,
                                                const char *presented,
                                                const char *method,
                                                const char *path,
                                                const char *peer_ip,
                                                struct webd_api_key_identity *out)
{
    char key_id[WEBD_API_KEY_ID_LEN + 1] = "";
    char secret[WEBD_API_KEY_SECRET_LEN + 1] = "";
    char digest[65] = "";
    char norm[1024];
    sqlite3_stmt *st = NULL;
    webd_api_key_result_t rc = WEBD_API_KEY_UNKNOWN;
    int64_t now = (int64_t)time(NULL);
    char stored_hash[128] = "";
    char stored_tier[32] = "";
    char stored_scope[WEBD_API_KEY_SCOPE_MAX + 1] = "";
    char stored_ips[WEBD_API_KEY_IPS_MAX + 1] = "";
    char stored_name[WEBD_API_KEY_NAME_MAX + 1] = "";
    int64_t expires_at = 0, revoked_at = 0;
    webd_api_key_tier_t tier = WEBD_API_KEY_TIER_READ_ONLY;

    if (!presented || !presented[0])
        return WEBD_API_KEY_NOT_PRESENTED;
    if (api_key_split(presented, key_id, sizeof(key_id), secret,
                      sizeof(secret)) != 0)
        return WEBD_API_KEY_MALFORMED;
    if (!db)
        return WEBD_API_KEY_DB_ERROR;

    if (sqlite3_prepare_v2(db,
            "SELECT key_hash,tier,scope_json,allow_ips,expires_at,revoked_at,name "
            "FROM api_keys WHERE key_id=?1", -1, &st, NULL) != SQLITE_OK) {
        rc = WEBD_API_KEY_DB_ERROR;
        goto done;
    }
    sqlite3_bind_text(st, 1, key_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        rc = WEBD_API_KEY_UNKNOWN;
        goto done;
    }
    {
        const char *c;

        c = (const char *)sqlite3_column_text(st, 0);
        snprintf(stored_hash, sizeof(stored_hash), "%s", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 1);
        snprintf(stored_tier, sizeof(stored_tier), "%s", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 2);
        snprintf(stored_scope, sizeof(stored_scope), "%s", c ? c : "");
        c = (const char *)sqlite3_column_text(st, 3);
        snprintf(stored_ips, sizeof(stored_ips), "%s", c ? c : "");
        expires_at = sqlite3_column_int64(st, 4);
        revoked_at = sqlite3_column_int64(st, 5);
        c = (const char *)sqlite3_column_text(st, 6);
        snprintf(stored_name, sizeof(stored_name), "%s", c ? c : "");
    }
    sqlite3_finalize(st);
    st = NULL;

    if (api_key_digest(key_id, secret, digest) != 0) {
        rc = WEBD_API_KEY_DB_ERROR;
        goto done;
    }
    if (!api_key_ct_equal(digest, stored_hash)) {
        /* Reported as unknown, not "wrong secret": distinguishing the two would
         * confirm which key_ids exist. */
        rc = WEBD_API_KEY_UNKNOWN;
        goto done;
    }
    /*
     * Identity is published as soon as the secret proves out, before the
     * remaining gates run. A rejection for scope or expiry still has to name
     * the key in the audit trail; that is the record that shows a leaked
     * credential being probed.
     */
    if (out) {
        snprintf(out->key_id, sizeof(out->key_id), "%s", key_id);
        snprintf(out->name, sizeof(out->name), "%s", stored_name);
        out->expires_at = expires_at;
    }
    if (revoked_at > 0) {
        rc = WEBD_API_KEY_REVOKED;
        goto done;
    }
    if (expires_at > 0 && now >= expires_at) {
        rc = WEBD_API_KEY_EXPIRED;
        goto done;
    }
    if (!api_key_ip_allowed(stored_ips, peer_ip)) {
        rc = WEBD_API_KEY_IP_NOT_ALLOWED;
        goto done;
    }
    if (!api_key_rate_ok(key_id, peer_ip ? peer_ip : "", now)) {
        rc = WEBD_API_KEY_RATE_LIMITED;
        goto done;
    }
    /* Hard gates run before scope so a mis-written scope cannot open them. */
    if (webd_api_key_route_forbidden(method, path)) {
        rc = WEBD_API_KEY_FORBIDDEN_ROUTE;
        goto done;
    }
    if (api_key_normalize_path(path, norm, sizeof(norm)) != 0) {
        rc = WEBD_API_KEY_SCOPE_DENIED;
        goto done;
    }
    if (webd_api_key_tier_parse(stored_tier, &tier) != 0)
        tier = WEBD_API_KEY_TIER_READ_ONLY;   /* unreadable tier fails closed */
    if (out)
        out->tier = tier;
    if (tier == WEBD_API_KEY_TIER_READ_ONLY && !api_key_method_is_readonly(method)) {
        rc = WEBD_API_KEY_SCOPE_DENIED;
        goto done;
    }
    if (!api_key_scope_allows(stored_scope, method, norm)) {
        rc = WEBD_API_KEY_SCOPE_DENIED;
        goto done;
    }
    rc = WEBD_API_KEY_OK;
done:
    if (st)
        sqlite3_finalize(st);
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

void webd_api_key_mark_used(sqlite3 *db, const char *key_id,
                            const char *peer_ip, int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!db || !key_id || !key_id[0])
        return;
    if (sqlite3_prepare_v2(db,
            "UPDATE api_keys SET last_used_at=?1,last_used_ip=?2,"
            "use_count=use_count+1 WHERE key_id=?3", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, peer_ip ? peer_ip : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, key_id, -1, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
}

/* ── management ── */

int webd_api_key_create(sqlite3 *db, const char *name, webd_api_key_tier_t tier,
                        const char *scope_json, const char *allow_ips,
                        int64_t expires_at, const char *created_by,
                        char *plain_out, size_t plain_out_len,
                        char *key_id_out, size_t key_id_out_len)
{
    unsigned char id_raw[WEBD_API_KEY_ID_LEN / 2];
    unsigned char secret_raw[WEBD_API_KEY_SECRET_LEN / 2];
    char key_id[WEBD_API_KEY_ID_LEN + 1];
    char secret[WEBD_API_KEY_SECRET_LEN + 1];
    char digest[65];
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || !plain_out || plain_out_len < WEBD_API_KEY_PLAIN_MAX ||
        !key_id_out || key_id_out_len < WEBD_API_KEY_ID_LEN + 1)
        return -1;
    if (RAND_bytes(id_raw, sizeof(id_raw)) != 1 ||
        RAND_bytes(secret_raw, sizeof(secret_raw)) != 1)
        return -1;
    api_key_hex(id_raw, sizeof(id_raw), key_id, sizeof(key_id));
    api_key_hex(secret_raw, sizeof(secret_raw), secret, sizeof(secret));
    OPENSSL_cleanse(secret_raw, sizeof(secret_raw));
    if (!key_id[0] || !secret[0])
        goto done;
    if (api_key_digest(key_id, secret, digest) != 0)
        goto done;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO api_keys(key_id,key_hash,digest_version,name,tier,"
            "scope_json,allow_ips,created_at,expires_at,created_by) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, WEBD_API_KEY_DIGEST_V1);
    sqlite3_bind_text(st, 4, name ? name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, webd_api_key_tier_str(tier), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, scope_json ? scope_json : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, allow_ips ? allow_ips : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, (int64_t)time(NULL));
    sqlite3_bind_int64(st, 9, expires_at > 0 ? expires_at : 0);
    sqlite3_bind_text(st, 10, created_by ? created_by : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    if (snprintf(plain_out, plain_out_len, "%s%s_%s", WEBD_API_KEY_PREFIX,
                 key_id, secret) >= (int)plain_out_len)
        goto done;
    snprintf(key_id_out, key_id_out_len, "%s", key_id);
    rc = 0;
done:
    if (st)
        sqlite3_finalize(st);
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

int webd_api_key_exists(sqlite3 *db, const char *key_id)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!db || !key_id || !key_id[0])
        return 0;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM api_keys WHERE key_id=?1", -1,
                           &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, key_id, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

int webd_api_key_revoke(sqlite3 *db, const char *key_id, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || !key_id || !key_id[0])
        return -1;
    if (sqlite3_prepare_v2(db,
            "UPDATE api_keys SET revoked_at=?1 WHERE key_id=?2 AND revoked_at=0",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now > 0 ? now : (int64_t)time(NULL));
    sqlite3_bind_text(st, 2, key_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = sqlite3_changes(db) > 0 ? 0 : 1;   /* 1 = already revoked */
    sqlite3_finalize(st);
    return rc;
}

int webd_api_key_delete(sqlite3 *db, const char *key_id)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || !key_id || !key_id[0])
        return -1;
    if (sqlite3_prepare_v2(db, "DELETE FROM api_keys WHERE key_id=?1", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = sqlite3_changes(db) > 0 ? 0 : 1;   /* 1 = no such key */
    sqlite3_finalize(st);
    return rc;
}
