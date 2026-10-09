// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * api_appearance.c - Appearance/branding config + public media BFF builders.
 *
 * Extracted verbatim from webd/jmx_app_api.c (Phase 7S) with no behavioral
 * change. Routes are unchanged and still dispatched from handle_client() in
 * the main TU; only the function definitions moved here.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <zlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <uci.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "../jmx_strbuf.h"
#include "../jmx_app_api.h"
#include "../jmx_app_perms.h"
#include "../webd_system_web_access.h"
#include "../jmx_app_cache.h"
#include "../jmx_system_data_path.h"
#include "../../storage/storage_files.h"
#include "../webd_http.h"
#include "../webd_static.h"
#include "../webd_mmdb.h"
#include "../webd_wifi_aggregate.h"
#include "../webd_upload_staging.h"
#include "../webd_backup_store.h"
#include "../webd_init_control.h"
#include "../native_plugins.h"
#include "../terminal_groups.h"
#include "../system_ttyd.h"
#include "../system_ttyd_proxy.h"
#include "../webd_session_idle.h"
#include "../webd_passkey.h"
#include "../webd_admin_transaction.h"
#include "../webd_vpn_aggregate.h"
#include "../webd_api_keys.h"
#include "../webd_ac_secret_rpc.h"
#include "../../ap_control_wire.h"
#include "../../ap_radio_id.h"
#include "../../safeops/port_snapshot.h"
#include "../../safeops/rollback_claim.h"
#include "../../safeops/revision_sequence.h"
#include "../../ac/ac_secrets.h"
#include "../../safeops/config_snapshot_codec.h"
#include "../ai_runtime.h"
#include "../ai_local_rpc.h"
#include "../ai_oauth.h"
#include "../jmx_auth_contract.h"
#include "../jmx_wifi_contract.h"
#include "api_router.h"
#include "api_request.h"
#include "api_toolkit.h"
#include "api_dashboard.h"
#include "api_topology.h"
#include "api_util.h"
#include "api_json.h"
#include "api_error.h"
#include "api_ubus.h"
#include "api_shared_json.h"
#include "api_runtime_cache.h"
#include "api_clients_list.h"
#include "api_client_control.h"
#include "api_client_connections.h"
#include "api_client_profile.h"
#include "api_policy_read.h"
#include "api_policy_objects.h"
#include "api_policy_paths.h"
#include "api_insights_internal.h"  /* struct webd_jmx_features + webd_jmx_features_read() used by webd_kernel_runtime_data */
#include "../../jmx_config_schema.h"
#include "../../proc_path.h"
#include "../../terminal_policy/terminal_policy.h"
#include "../../client_connections_snapshot.h"
#include "api_bootstrap_internal.h"

/* Macros copied verbatim from jmx_app_api.c (ODR-safe; main keeps its copies). */
#define WEBD_PBKDF2_ITER      100000
#define WEBD_PBKDF2_DK_LEN    32
#define WEBD_SALT_HEX_LEN     32
#define WEBD_TOTP_SECRET_BYTES 20
#define WEBD_TOTP_SECRET_MAX   64
#define WEBD_TOTP_STEP_S       30
#define WEBD_TOTP_DIGITS       6
#define WEBD_TOTP_WINDOW       1
#define WEBD_TOTP_STEP_MIN_S   15
#define WEBD_TOTP_STEP_MAX_S   120
#define WEBD_TOTP_DIGITS_MAX   8
#define WEBD_TOTP_WINDOW_MAX   5
#define WEBD_BRUTE_WINDOW_S         300
#define WEBD_BRUTE_MAX_FAILS        5
#define WEBD_BRUTE_LOCK_S           1800
#define WEBD_BRUTE_IP_WINDOW_S      600
#define WEBD_BRUTE_IP_MAX_FAILS     20
#define WEBD_BRUTE_IP_BAN_S         0

#include "api_auth_core_internal.h"

int app_insert_token(const char *token, const char *device_id,
                            const char *type, int64_t created_at,
                            int64_t expires_at)
{
    sqlite3_stmt *st = app_prepare(
        "INSERT INTO auth_tokens(token,device_id,type,created_at,expires_at) "
        "VALUES(?1,?2,?3,?4,?5)");
    int rc;

    if (!st) return -1;
    sqlite3_bind_text(st, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, type, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, created_at);
    sqlite3_bind_int64(st, 5, expires_at);
    rc = app_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * Crypto helpers
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Strong-random hex generator for session tokens, refresh tokens, session ids,
 * setup tokens and password salts.
 *
 * Returns 0 on success, -1 if strong randomness was unavailable. On failure the
 * buffer is zeroed and NOTHING usable is produced: callers must abort the
 * operation rather than issue whatever is in the buffer.
 *
 * This used to fall back to srand(time(NULL)) + rand() whenever
 * fopen("/dev/urandom") failed, which is reachable in practice (fd exhaustion,
 * or /dev not ready during early boot) and silent. time(NULL) has one-second
 * granularity, so a whole day is only 86400 candidate seeds and an attacker who
 * knows roughly when a token was issued can recompute it. A predictable session
 * token is worse than a failed login, so the weak path is gone entirely.
 *
 * The old loop also ignored fgetc() failures: EOF is -1, and -1 & 0xf is 15, so
 * every failed byte silently became 'f'. Short reads are now treated as errors.
 */
int gen_random_hex_checked(char *out, int len)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char buf[128];
    int produced = 0;

    if (!out || len <= 0)
        return -1;
    out[0] = '\0';
    while (produced < len) {
        /* One byte yields two hex digits, so ask for half the remaining run. */
        size_t want = (size_t)(len - produced + 1) / 2;
        ssize_t got;
        size_t i;

        if (want > sizeof(buf))
            want = sizeof(buf);
        got = getrandom(buf, want, 0);
        if (got <= 0) {
            if (got < 0 && errno == EINTR)
                continue;
            memset(out, 0, (size_t)len + 1);
            fprintf(stderr, "[dreamingwrt-webd] gen_random_hex: strong randomness "
                            "unavailable (%s); refusing to emit a predictable token\n",
                    strerror(errno));
            return -1;
        }
        for (i = 0; i < (size_t)got && produced < len; i++) {
            out[produced++] = hex[(buf[i] >> 4) & 0xf];
            if (produced < len)
                out[produced++] = hex[buf[i] & 0xf];
        }
    }
    out[len] = '\0';
    return 0;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    size_t i;

    if (!hex || !out || strlen(hex) != out_len * 2)
        return -1;
    for (i = 0; i < out_len; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

void bytes_to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!out || out_len == 0)
        return;
    if (!in || out_len < in_len * 2 + 1) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i < in_len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[in[i] & 0xf];
    }
    out[in_len * 2] = '\0';
}

int ct_str_equal(const char *a, const char *b)
{
    size_t alen, blen, i, n;
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

int webd_token_sha256(const char *token, char out[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!token || !token[0] || !out ||
        EVP_Digest(token, strlen(token), digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len != 32)
        return -1;
    bytes_to_hex(digest, digest_len, out, 65);
    return out[0] ? 0 : -1;
}

/*
 * Strong randomness only, same contract as gen_random_hex(): there is no
 * pseudo-random fallback, because a credential an attacker can predict is
 * worse than a credential we failed to issue. Returns 0 on success, -1 when
 * the kernel entropy source is unavailable; callers must fail the operation.
 */
static int gen_random_bytes(unsigned char *out, size_t len)
{
    size_t filled = 0;

    if (!out || len == 0)
        return -1;
    while (filled < len) {
        ssize_t got = getrandom(out + filled, len - filled, 0);

        if (got <= 0) {
            if (got < 0 && errno == EINTR)
                continue;
            memset(out, 0, len);
            fprintf(stderr, "[dreamingwrt-webd] gen_random_bytes: strong randomness "
                            "unavailable (%s); refusing to emit a predictable secret\n",
                    strerror(errno));
            return -1;
        }
        filled += (size_t)got;
    }
    return 0;
}

static void base32_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned int buffer = 0;
    int bits_left = 0;
    size_t i, o = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    for (i = 0; i < in_len; i++) {
        buffer = (buffer << 8) | in[i];
        bits_left += 8;
        while (bits_left >= 5) {
            if (o + 1 >= out_len) { out[0] = '\0'; return; }
            out[o++] = alphabet[(buffer >> (bits_left - 5)) & 0x1f];
            bits_left -= 5;
        }
    }
    if (bits_left > 0) {
        if (o + 1 >= out_len) { out[0] = '\0'; return; }
        out[o++] = alphabet[(buffer << (5 - bits_left)) & 0x1f];
    }
    out[o] = '\0';
}

static int base32_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static int base32_decode(const char *in, unsigned char *out, size_t out_len, size_t *written)
{
    unsigned int buffer = 0;
    int bits_left = 0;
    size_t o = 0;
    const char *p;

    if (written) *written = 0;
    if (!in || !out)
        return -1;
    for (p = in; *p; p++) {
        int v;
        if (*p == '=' || *p == ' ' || *p == '-' || *p == '\t' || *p == '\r' || *p == '\n')
            continue;
        v = base32_val(*p);
        if (v < 0)
            return -1;
        buffer = (buffer << 5) | (unsigned int)v;
        bits_left += 5;
        if (bits_left >= 8) {
            bits_left -= 8;
            if (o >= out_len)
                return -1;
            out[o++] = (unsigned char)((buffer >> bits_left) & 0xff);
        }
    }
    if (written) *written = o;
    return o > 0 ? 0 : -1;
}

static int webd_totp_digits_ok(int digits)
{
    return digits >= 6 && digits <= WEBD_TOTP_DIGITS_MAX;
}

static int webd_totp_step_ok(int step_s)
{
    return step_s >= WEBD_TOTP_STEP_MIN_S && step_s <= WEBD_TOTP_STEP_MAX_S;
}

static int webd_totp_window_ok(int window)
{
    return window >= 0 && window <= WEBD_TOTP_WINDOW_MAX;
}

static int webd_totp_code_ok(const char *code, int digits)
{
    int i;

    if (!webd_totp_digits_ok(digits) || !code || strlen(code) != (size_t)digits)
        return 0;
    for (i = 0; code[i]; i++) {
        if (!isdigit((unsigned char)code[i]))
            return 0;
    }
    return 1;
}

static uint32_t webd_totp_truncate(const unsigned char *digest, unsigned int digest_len)
{
    int offset;

    if (!digest || digest_len < 20)
        return 0;
    offset = digest[digest_len - 1] & 0x0f;
    return ((uint32_t)(digest[offset] & 0x7f) << 24) |
           ((uint32_t)(digest[offset + 1] & 0xff) << 16) |
           ((uint32_t)(digest[offset + 2] & 0xff) << 8) |
           (uint32_t)(digest[offset + 3] & 0xff);
}

static int webd_totp_at_counter(const char *secret_b32, int64_t counter,
                                int digits, char *out, size_t out_len)
{
    unsigned char secret[64];
    size_t secret_len = 0;
    unsigned char msg[8];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    uint32_t value;
    int i;

    if (!webd_totp_digits_ok(digits) || !secret_b32 || !out || out_len < (size_t)digits + 1 || counter < 0)
        return -1;
    if (base32_decode(secret_b32, secret, sizeof(secret), &secret_len) != 0)
        return -1;
    for (i = 7; i >= 0; i--) {
        msg[i] = (unsigned char)(counter & 0xff);
        counter >>= 8;
    }
    if (!HMAC(EVP_sha1(), secret, (int)secret_len, msg, sizeof(msg), digest, &digest_len))
        return -1;
    value = webd_totp_truncate(digest, digest_len);
    if (digits == 6)
        value %= 1000000U;
    else if (digits == 7)
        value %= 10000000U;
    else
        value %= 100000000U;
    snprintf(out, out_len, "%0*u", digits, (unsigned int)value);
    return 0;
}

int webd_totp_verify_secret(const char *secret_b32, const char *code,
                                   int step_s, int digits, int window,
                                   int64_t last_counter, int64_t *matched_counter)
{
    int64_t now_counter;
    int drift;

    if (matched_counter)
        *matched_counter = -1;
    if (!webd_totp_step_ok(step_s) || !webd_totp_digits_ok(digits) ||
        !webd_totp_window_ok(window) || !webd_totp_code_ok(code, digits) ||
        !secret_b32 || !secret_b32[0])
        return 0;
    now_counter = now_s() / step_s;
    for (drift = -window; drift <= window; drift++) {
        int64_t counter = now_counter + drift;
        char expected[WEBD_TOTP_DIGITS_MAX + 1];

        if (counter <= last_counter || counter < 0)
            continue;
        if (webd_totp_at_counter(secret_b32, counter, digits, expected, sizeof(expected)) != 0)
            continue;
        if (ct_str_equal(code, expected)) {
            if (matched_counter)
                *matched_counter = counter;
            return 1;
        }
    }
    return 0;
}

/* Returns 0 on success, -1 when no strong entropy is available. */
static int webd_totp_secret_new(char *out, size_t out_len)
{
    unsigned char secret[WEBD_TOTP_SECRET_BYTES];
    int rc;

    if (!out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (gen_random_bytes(secret, sizeof(secret)) != 0)
        return -1;
    base32_encode(secret, sizeof(secret), out, out_len);
    rc = out[0] ? 0 : -1;
    memset(secret, 0, sizeof(secret));
    return rc;
}

int webd_totp_secret_ok(const char *secret)
{
    unsigned char decoded[64];
    size_t decoded_len = 0;

    if (!secret || !secret[0] || strlen(secret) > WEBD_TOTP_SECRET_MAX)
        return 0;
    return base32_decode(secret, decoded, sizeof(decoded), &decoded_len) == 0 && decoded_len >= 10;
}

struct webd_auth_settings {
    int brute_enabled;
    int fail_window_s;
    int max_failures;
    int lock_s;
    int ip_ban_enabled;
    int ip_fail_window_s;
    int ip_max_failures;
    int ip_ban_s;
    char twofa_issuer[64];
    int twofa_step_s;
    int twofa_digits;
    int twofa_window;
};

static void webd_auth_settings_defaults(struct webd_auth_settings *s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->brute_enabled = 1;
    s->fail_window_s = WEBD_BRUTE_WINDOW_S;
    s->max_failures = WEBD_BRUTE_MAX_FAILS;
    s->lock_s = WEBD_BRUTE_LOCK_S;
    s->ip_ban_enabled = 1;
    s->ip_fail_window_s = WEBD_BRUTE_IP_WINDOW_S;
    s->ip_max_failures = WEBD_BRUTE_IP_MAX_FAILS;
    s->ip_ban_s = WEBD_BRUTE_IP_BAN_S;
    snprintf(s->twofa_issuer, sizeof(s->twofa_issuer), "%s", "DreamingWrt");
    s->twofa_step_s = WEBD_TOTP_STEP_S;
    s->twofa_digits = WEBD_TOTP_DIGITS;
    s->twofa_window = WEBD_TOTP_WINDOW;
}

static int webd_auth_settings_load(struct webd_auth_settings *s)
{
    sqlite3_stmt *st;
    const char *issuer;
    int rc;

    if (!s)
        return -1;
    webd_auth_settings_defaults(s);
    st = config_prepare(
        "SELECT brute_enabled,fail_window_s,max_failures,lock_s,ip_ban_enabled,ip_fail_window_s,"
        "ip_max_failures,ip_ban_s,twofa_issuer,twofa_step_s,twofa_digits,twofa_window "
        "FROM web_auth_settings WHERE id=1");
    if (!st)
        return -1;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        s->brute_enabled = sqlite3_column_int(st, 0) ? 1 : 0;
        s->fail_window_s = sqlite3_column_int(st, 1);
        s->max_failures = sqlite3_column_int(st, 2);
        s->lock_s = sqlite3_column_int(st, 3);
        s->ip_ban_enabled = sqlite3_column_int(st, 4) ? 1 : 0;
        s->ip_fail_window_s = sqlite3_column_int(st, 5);
        s->ip_max_failures = sqlite3_column_int(st, 6);
        s->ip_ban_s = sqlite3_column_int(st, 7);
        issuer = (const char *)sqlite3_column_text(st, 8);
        snprintf(s->twofa_issuer, sizeof(s->twofa_issuer), "%s", issuer && issuer[0] ? issuer : "DreamingWrt");
        s->twofa_step_s = sqlite3_column_int(st, 9);
        s->twofa_digits = sqlite3_column_int(st, 10);
        s->twofa_window = sqlite3_column_int(st, 11);
    } else {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    if (s->fail_window_s <= 0) s->fail_window_s = WEBD_BRUTE_WINDOW_S;
    if (s->max_failures <= 0) s->max_failures = WEBD_BRUTE_MAX_FAILS;
    if (s->lock_s <= 0) s->lock_s = WEBD_BRUTE_LOCK_S;
    if (s->ip_fail_window_s <= 0) s->ip_fail_window_s = WEBD_BRUTE_IP_WINDOW_S;
    if (s->ip_max_failures <= 0) s->ip_max_failures = WEBD_BRUTE_IP_MAX_FAILS;
    if (!webd_totp_step_ok(s->twofa_step_s)) s->twofa_step_s = WEBD_TOTP_STEP_S;
    if (!webd_totp_digits_ok(s->twofa_digits)) s->twofa_digits = WEBD_TOTP_DIGITS;
    if (!webd_totp_window_ok(s->twofa_window)) s->twofa_window = WEBD_TOTP_WINDOW;
    return 0;
}

int webd_password_hash(const char *password, char *out, size_t out_len)
{
    char salt_hex[WEBD_SALT_HEX_LEN + 1];
    unsigned char salt[WEBD_SALT_HEX_LEN / 2];
    unsigned char dk[WEBD_PBKDF2_DK_LEN];
    char dk_hex[WEBD_PBKDF2_DK_LEN * 2 + 1];

    if (!password || !password[0] || !out || out_len == 0)
        return -1;
    /* A predictable salt makes the stored hash precomputable, so fail closed. */
    if (gen_random_hex_checked(salt_hex, WEBD_SALT_HEX_LEN) != 0)
        return -1;
    if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0)
        return -1;
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                          WEBD_PBKDF2_ITER, EVP_sha256(), sizeof(dk), dk) != 1)
        return -1;
    bytes_to_hex(dk, sizeof(dk), dk_hex, sizeof(dk_hex));
    if (!dk_hex[0])
        return -1;
    if (snprintf(out, out_len, "pbkdf2-sha256$%d$%s$%s",
                 WEBD_PBKDF2_ITER, salt_hex, dk_hex) >= (int)out_len)
        return -1;
    return 0;
}

int webd_password_verify(const char *password, const char *stored)
{
    char tmp[256];
    char *alg, *iter_s, *salt_hex, *hash_hex;
    unsigned char salt[WEBD_SALT_HEX_LEN / 2];
    unsigned char dk[WEBD_PBKDF2_DK_LEN];
    char dk_hex[WEBD_PBKDF2_DK_LEN * 2 + 1];
    int iter;
    unsigned char diff = 0;
    size_t i;

    if (!password || !stored || !stored[0])
        return 0;
    snprintf(tmp, sizeof(tmp), "%s", stored);
    alg = strtok(tmp, "$");
    iter_s = strtok(NULL, "$");
    salt_hex = strtok(NULL, "$");
    hash_hex = strtok(NULL, "$");
    if (!alg || strcmp(alg, "pbkdf2-sha256") || !iter_s || !salt_hex || !hash_hex)
        return 0;
    iter = atoi(iter_s);
    if (iter < 10000 || iter > 1000000)
        return 0;
    if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0)
        return 0;
    if (strlen(hash_hex) != sizeof(dk) * 2)
        return 0;
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                          iter, EVP_sha256(), sizeof(dk), dk) != 1)
        return 0;
    bytes_to_hex(dk, sizeof(dk), dk_hex, sizeof(dk_hex));
    for (i = 0; i < sizeof(dk_hex) - 1; i++)
        diff |= (unsigned char)(dk_hex[i] ^ hash_hex[i]);
    return diff == 0;
}

int webd_username_ok(const char *username)
{
    int i;

    if (!username || !username[0]) return 0;
    if (strlen(username) > 64) return 0;
    for (i = 0; username[i]; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.')
            return 0;
    }
    return 1;
}

int webd_role_ok(const char *role)
{
    return role && (!strcmp(role, "owner") || !strcmp(role, "admin") ||
                    !strcmp(role, "operator") || !strcmp(role, "viewer") ||
                    !strcmp(role, "user"));
}



int webd_sqlite_step_row(sqlite3_stmt *st, int *state)
{
    int rc;

    if (state)
        *state = WEBD_AUTH_DB_FAILED;
    if (!st)
        return 0;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (state)
            *state = WEBD_AUTH_DB_OK;
        return 1;
    }
    if (rc == SQLITE_DONE) {
        if (state)
            *state = WEBD_AUTH_DB_INVALID;
    }
    return 0;
}

int webd_user_twofa_get_ex(const char *username, struct webd_twofa_state *out,
                                  int *state)
{
    sqlite3_stmt *st;
    const char *secret;
    int ok = 0;
    int row_state = WEBD_AUTH_DB_INVALID;

    if (state)
        *state = WEBD_AUTH_DB_INVALID;
    if (!webd_username_ok(username) || !out)
        return 0;
    memset(out, 0, sizeof(*out));
    out->step_s = WEBD_TOTP_STEP_S;
    out->digits = WEBD_TOTP_DIGITS;
    out->window = WEBD_TOTP_WINDOW;
    out->last_counter = -1;
    st = config_prepare("SELECT twofa_enabled,twofa_secret,twofa_bound_at,twofa_last_counter,status,twofa_step_s,twofa_digits,twofa_window FROM web_users WHERE username=?1");
    if (!st) {
        if (state) *state = WEBD_AUTH_DB_FAILED;
        return 0;
    }
    sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
    if (webd_sqlite_step_row(st, &row_state)) {
        const char *status = (const char *)sqlite3_column_text(st, 4);
        if (status && !strcmp(status, "enabled")) {
            out->enabled = sqlite3_column_int(st, 0) ? 1 : 0;
            secret = (const char *)sqlite3_column_text(st, 1);
            snprintf(out->secret, sizeof(out->secret), "%s", secret ? secret : "");
            out->bound_at = sqlite3_column_int64(st, 2);
            out->last_counter = sqlite3_column_int64(st, 3);
            out->step_s = sqlite3_column_int(st, 5);
            out->digits = sqlite3_column_int(st, 6);
            out->window = sqlite3_column_int(st, 7);
            if (!webd_totp_step_ok(out->step_s)) out->step_s = WEBD_TOTP_STEP_S;
            if (!webd_totp_digits_ok(out->digits)) out->digits = WEBD_TOTP_DIGITS;
            if (!webd_totp_window_ok(out->window)) out->window = WEBD_TOTP_WINDOW;
            ok = 1;
        }
    } else if (row_state == WEBD_AUTH_DB_FAILED) {
        if (state) *state = WEBD_AUTH_DB_FAILED;
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    if (state)
        *state = ok ? WEBD_AUTH_DB_OK : WEBD_AUTH_DB_INVALID;
    return ok;
}

static int webd_user_twofa_set(const char *username, const char *secret, int enabled,
                               int step_s, int digits, int window, int64_t counter)
{
    sqlite3_stmt *st;
    int rc;

    if (!webd_username_ok(username) ||
        (enabled && (!webd_totp_secret_ok(secret) || !webd_totp_step_ok(step_s) ||
                     !webd_totp_digits_ok(digits) || !webd_totp_window_ok(window))))
        return -1;
    st = config_prepare(
        "UPDATE web_users SET twofa_enabled=?1,twofa_secret=?2,twofa_bound_at=?3,"
        "twofa_last_counter=?4,twofa_step_s=?5,twofa_digits=?6,twofa_window=?7,updated_at=?8 WHERE username=?9");
    if (!st) return -1;
    sqlite3_bind_int(st, 1, enabled ? 1 : 0);
    sqlite3_bind_text(st, 2, enabled ? secret : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, enabled ? now_s() : 0);
    sqlite3_bind_int64(st, 4, enabled ? counter : -1);
    sqlite3_bind_int(st, 5, enabled ? step_s : WEBD_TOTP_STEP_S);
    sqlite3_bind_int(st, 6, enabled ? digits : WEBD_TOTP_DIGITS);
    sqlite3_bind_int(st, 7, enabled ? window : WEBD_TOTP_WINDOW);
    sqlite3_bind_int64(st, 8, now_s());
    sqlite3_bind_text(st, 9, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

/*
 * Replay guard: the WHERE clause only advances twofa_last_counter, so two
 * concurrent requests carrying the same code cannot both commit. The loser
 * updates zero rows and the existing sqlite3_changes() check turns that into
 * a failure, which the caller must treat as a rejected code.
 */
int webd_user_twofa_touch_counter(const char *username, int64_t counter)
{
    sqlite3_stmt *st;
    int rc;

    if (!webd_username_ok(username) || counter < 0)
        return -1;
    st = config_prepare("UPDATE web_users SET twofa_last_counter=?1,updated_at=?2 "
                        "WHERE username=?3 AND twofa_enabled=1 AND twofa_last_counter < ?1");
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, counter);
    sqlite3_bind_int64(st, 2, now_s());
    sqlite3_bind_text(st, 3, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_config_db) > 0 ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

/* Defined further down with the session-identity helpers. */
int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);

/*
 * Outcome of the OTP gate that guards irreversible operations.
 */

/*
 * Requires a valid, unused TOTP code before an irreversible operation runs.
 *
 * The identity string is webd's own: "web:<username>" for a browser session,
 * anything else for an app device or API-Key caller. API-Key callers cannot
 * present a TOTP by construction, so they are refused outright rather than
 * granted a bypass; a gate with an exemption for the least interactive channel
 * is not a gate. This mirrors the standing rule that API-Keys never get shell.
 *
 * The matched counter is consumed on success, so a code cannot be replayed to
 * run the same destructive action twice. Consumption is what makes this
 * single-use, so it happens here rather than being left to the caller.
 */
enum webd_otp_gate_result webd_otp_gate_check(const char *identity,
                                                     struct json_object *body,
                                                     char *username_out,
                                                     size_t username_len)
{
    struct webd_twofa_state twofa;
    const char *username;
    const char *code;
    int64_t matched = -1;
    int state = WEBD_AUTH_DB_FAILED;

    if (username_out && username_len)
        username_out[0] = '\0';
    if (!webd_identity_is_user(identity))
        return WEBD_OTP_GATE_CHANNEL_FORBIDDEN;
    username = webd_identity_username(identity);
    if (!webd_username_ok(username))
        return WEBD_OTP_GATE_CHANNEL_FORBIDDEN;
    if (username_out && username_len)
        jmx_strbuf_copy(username_out, username_len, username);

    memset(&twofa, 0, sizeof(twofa));
    if (!webd_user_twofa_get_ex(username, &twofa, &state)) {
        /*
         * A failed lookup must not read as "2FA is off". Distinguishing it from
         * a genuine unbound account keeps a database problem from silently
         * lowering the bar on an irreversible operation.
         */
        return state == WEBD_AUTH_DB_OK ? WEBD_OTP_GATE_NOT_BOUND :
                                          WEBD_OTP_GATE_UNAVAILABLE;
    }
    if (!twofa.enabled || !twofa.secret[0])
        return WEBD_OTP_GATE_NOT_BOUND;

    code = app_nc_json_str(body, "otp", "");
    if (!code[0])
        code = app_nc_json_str(body, "otp_code", "");
    if (!code[0])
        code = app_nc_json_str(body, "totp", "");
    if (!code[0])
        return WEBD_OTP_GATE_CODE_MISSING;

    if (!webd_totp_verify_secret(twofa.secret, code, twofa.step_s, twofa.digits,
                                 twofa.window, twofa.last_counter, &matched))
        return WEBD_OTP_GATE_CODE_INVALID;
    /*
     * Losing this race means another request already consumed the same counter,
     * which is exactly the replay this gate exists to stop, so it is a rejection
     * rather than an internal error.
     */
    if (matched < 0 || webd_user_twofa_touch_counter(username, matched) != 0)
        return WEBD_OTP_GATE_CODE_INVALID;
    return WEBD_OTP_GATE_OK;
}

/* Maps a gate refusal to the response body and HTTP status the frontend keys on. */
struct json_object *webd_otp_gate_error(enum webd_otp_gate_result result,
                                               const char *operation,
                                               int *http_status)
{
    struct json_object *o;

    switch (result) {
    case WEBD_OTP_GATE_CHANNEL_FORBIDDEN:
        o = webd_error("otp_channel_not_supported",
                       "this operation requires an interactive session with TOTP; "
                       "API-Key and app-device callers cannot perform it",
                       "otp", "webd.auth");
        if (http_status) *http_status = 403;
        break;
    case WEBD_OTP_GATE_NOT_BOUND:
        o = webd_error("twofa_required_not_bound",
                       "two-factor authentication must be bound before this operation",
                       "otp", "webd.auth");
        json_object_object_add(o, "twofa_enabled", json_object_new_boolean(0));
        json_object_object_add(o, "bind_endpoint",
                               json_object_new_string("/api/v1/auth/2fa/prepare"));
        if (http_status) *http_status = 403;
        break;
    case WEBD_OTP_GATE_CODE_MISSING:
        o = webd_error("otp_required", "a TOTP code is required for this operation",
                       "otp", "webd.auth");
        json_object_object_add(o, "twofa_enabled", json_object_new_boolean(1));
        if (http_status) *http_status = 401;
        break;
    case WEBD_OTP_GATE_CODE_INVALID:
        o = webd_error("otp_invalid", "the TOTP code is incorrect, expired, or already used",
                       "otp", "webd.auth");
        json_object_object_add(o, "twofa_enabled", json_object_new_boolean(1));
        if (http_status) *http_status = 401;
        break;
    default:
        o = webd_error("otp_verification_unavailable",
                       "two-factor state could not be read, so the operation was refused",
                       "otp", "webd.auth");
        if (http_status) *http_status = 500;
        break;
    }
    json_object_object_add(o, "requires_otp", json_object_new_boolean(1));
    json_object_object_add(o, "changed", json_object_new_boolean(0));
    if (operation && operation[0])
        json_object_object_add(o, "operation", json_object_new_string(operation));
    return o;
}

static void webd_urlencode(const char *in, char *out, size_t out_len)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    const unsigned char *p;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;
    for (p = (const unsigned char *)in; *p && o + 1 < out_len; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            out[o++] = (char)*p;
        } else {
            if (o + 3 >= out_len)
                break;
            out[o++] = '%';
            out[o++] = hex[(*p >> 4) & 0xf];
            out[o++] = hex[*p & 0xf];
        }
    }
    out[o] = '\0';
}


static char *webd_twofa_qr_svg_from_uri(const char *uri)
{
    int fds[2];
    pid_t pid;
    char *out = NULL;
    size_t len = 0, cap = 0;
    const size_t max_len = 262144;
    int status = 0;
    const char *qrencode = NULL;

    if (access("/usr/bin/qrencode", X_OK) == 0)
        qrencode = "/usr/bin/qrencode";
    else if (access("/bin/qrencode", X_OK) == 0)
        qrencode = "/bin/qrencode";
    else if (access("/usr/sbin/qrencode", X_OK) == 0)
        qrencode = "/usr/sbin/qrencode";

    if (!uri || !uri[0] || !qrencode)
        return NULL;
    if (pipe(fds) != 0)
        return NULL;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    if (pid == 0) {
        int devnull;

        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(qrencode, "qrencode", "-t", "SVG", "-o", "-", "-m", "0", "-s", "4", uri, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    cap = 8192;
    out = malloc(cap);
    if (!out) {
        close(fds[0]);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return NULL;
    }
    for (;;) {
        ssize_t n;

        if (len + 4096 + 1 > cap) {
            size_t ncap = cap * 2;
            char *tmp;

            if (ncap > max_len)
                ncap = max_len;
            if (ncap <= cap || len + 4096 + 1 > ncap) {
                free(out);
                out = NULL;
                break;
            }
            tmp = realloc(out, ncap);
            if (!tmp) {
                free(out);
                out = NULL;
                break;
            }
            out = tmp;
            cap = ncap;
        }
        n = read(fds[0], out + len, cap - len - 1);
        if (n > 0) {
            len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    close(fds[0]);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!out)
        return NULL;
    out[len] = '\0';
    if (len == 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || !strstr(out, "<svg")) {
        free(out);
        return NULL;
    }
    return out;
}

int webd_twofa_qr_available(void)
{
    return access("/usr/bin/qrencode", X_OK) == 0 ||
           access("/bin/qrencode", X_OK) == 0 ||
           access("/usr/sbin/qrencode", X_OK) == 0;
}

struct json_object *webd_twofa_public_status(const char *username)
{
    struct webd_twofa_state st;
    struct json_object *data = json_object_new_object();
    int twofa_state = WEBD_AUTH_DB_INVALID;

    if (!webd_user_twofa_get_ex(username, &st, &twofa_state)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string(twofa_state == WEBD_AUTH_DB_FAILED ? "twofa_state_unavailable" : "user_not_found"));
        return data;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "username", json_object_new_string(username ? username : ""));
    json_object_object_add(data, "twofa_enabled", json_object_new_boolean(st.enabled));
    json_object_object_add(data, "bound_at", json_object_new_int64(st.bound_at));
    json_object_object_add(data, "method", json_object_new_string("totp"));
    json_object_object_add(data, "digits", json_object_new_int(st.digits));
    json_object_object_add(data, "period", json_object_new_int(st.step_s));
    json_object_object_add(data, "window", json_object_new_int(st.window));
    return data;
}

struct json_object *webd_twofa_prepare(const char *username)
{
    struct webd_auth_settings settings;
    struct webd_twofa_state current;
    struct json_object *data = json_object_new_object();
    char secret[WEBD_TOTP_SECRET_MAX + 1];
    char issuer_enc[128], label_enc[256];
    char label[160], uri[512];
    int twofa_state = WEBD_AUTH_DB_INVALID;

    if (!webd_user_twofa_get_ex(username, &current, &twofa_state)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string(twofa_state == WEBD_AUTH_DB_FAILED ? "twofa_state_unavailable" : "user_not_found"));
        return data;
    }
    if (webd_auth_settings_load(&settings) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("auth_settings_unavailable"));
        return data;
    }
    if (webd_totp_secret_new(secret, sizeof(secret)) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("secret_entropy_unavailable"));
        json_object_object_add(data, "message", json_object_new_string("strong randomness is unavailable; refusing to issue a predictable TOTP secret"));
        return data;
    }
    snprintf(label, sizeof(label), "%s:%s", settings.twofa_issuer, username ? username : "");
    webd_urlencode(settings.twofa_issuer, issuer_enc, sizeof(issuer_enc));
    webd_urlencode(label, label_enc, sizeof(label_enc));
    snprintf(uri, sizeof(uri), "otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
             label_enc, secret, issuer_enc, settings.twofa_digits, settings.twofa_step_s);

    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "username", json_object_new_string(username ? username : ""));
    json_object_object_add(data, "secret", json_object_new_string(secret));
    json_object_object_add(data, "otpauth_url", json_object_new_string(uri));
    json_object_object_add(data, "issuer", json_object_new_string(settings.twofa_issuer));
    json_object_object_add(data, "account", json_object_new_string(username ? username : ""));
    json_object_object_add(data, "label", json_object_new_string(label));
    json_object_object_add(data, "algorithm", json_object_new_string("SHA1"));
    json_object_object_add(data, "digits", json_object_new_int(settings.twofa_digits));
    json_object_object_add(data, "period", json_object_new_int(settings.twofa_step_s));
    json_object_object_add(data, "window", json_object_new_int(settings.twofa_window));
    {
        char *qr_svg = webd_twofa_qr_svg_from_uri(uri);

        if (qr_svg) {
            json_object_object_add(data, "qr_svg", json_object_new_string(qr_svg));
            json_object_object_add(data, "qr_svg_supported", json_object_new_boolean(1));
            json_object_object_add(data, "qr_format", json_object_new_string("svg"));
            json_object_object_add(data, "qr_source", json_object_new_string("qrencode"));
            free(qr_svg);
        } else {
            json_object_object_add(data, "qr_svg_supported", json_object_new_boolean(0));
            json_object_object_add(data, "qr_source", json_object_new_string("unavailable"));
            json_object_object_add(data, "qr_reason", json_object_new_string("qrencode_unavailable_or_failed"));
        }
    }
    json_object_object_add(data, "already_enabled", json_object_new_boolean(current.enabled));
    return data;
}

struct json_object *webd_twofa_enable(const char *username, struct json_object *body)
{
    const char *secret = app_nc_json_str(body, "secret", "");
    const char *code = app_nc_json_str(body, "code", app_nc_json_str(body, "otp", ""));
    struct webd_auth_settings settings;
    struct json_object *data = json_object_new_object();
    int64_t counter = -1;

    if (!webd_username_ok(username)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_user"));
        return data;
    }
    if (webd_auth_settings_load(&settings) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("auth_settings_unavailable"));
        return data;
    }
    if (!webd_totp_secret_ok(secret) ||
        !webd_totp_verify_secret(secret, code, settings.twofa_step_s, settings.twofa_digits,
                                 settings.twofa_window, -1, &counter)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_2fa_code"));
        return data;
    }
    if (webd_user_twofa_set(username, secret, 1, settings.twofa_step_s, settings.twofa_digits,
                            settings.twofa_window, counter) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("twofa_enable_failed"));
        return data;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "twofa_enabled", json_object_new_boolean(1));
    json_object_object_add(data, "digits", json_object_new_int(settings.twofa_digits));
    json_object_object_add(data, "period", json_object_new_int(settings.twofa_step_s));
    json_object_object_add(data, "window", json_object_new_int(settings.twofa_window));
    json_object_object_add(data, "username", json_object_new_string(username));
    return data;
}

struct json_object *webd_twofa_disable(const char *username, struct json_object *body)
{
    const char *code = app_nc_json_str(body, "code", app_nc_json_str(body, "otp", ""));
    struct webd_twofa_state st;
    struct json_object *data = json_object_new_object();
    int64_t counter = -1;
    int twofa_state = WEBD_AUTH_DB_INVALID;

    if (!webd_user_twofa_get_ex(username, &st, &twofa_state)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string(twofa_state == WEBD_AUTH_DB_FAILED ? "twofa_state_unavailable" : "user_not_found"));
        return data;
    }
    if (st.enabled && !webd_totp_verify_secret(st.secret, code, st.step_s, st.digits,
                                              st.window, st.last_counter, &counter)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_2fa_code"));
        return data;
    }
    if (webd_user_twofa_set(username, "", 0, WEBD_TOTP_STEP_S, WEBD_TOTP_DIGITS,
                            WEBD_TOTP_WINDOW, -1) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("twofa_disable_failed"));
        return data;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "twofa_enabled", json_object_new_boolean(0));
    return data;
}

struct json_object *webd_auth_settings_json(void)
{
    struct webd_auth_settings s;
    struct json_object *data = json_object_new_object();

    if (webd_auth_settings_load(&s) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("auth_settings_unavailable"));
        return data;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "brute_enabled", json_object_new_boolean(s.brute_enabled));
    json_object_object_add(data, "fail_window_s", json_object_new_int(s.fail_window_s));
    json_object_object_add(data, "max_failures", json_object_new_int(s.max_failures));
    json_object_object_add(data, "lock_s", json_object_new_int(s.lock_s));
    json_object_object_add(data, "ip_ban_enabled", json_object_new_boolean(s.ip_ban_enabled));
    json_object_object_add(data, "ip_fail_window_s", json_object_new_int(s.ip_fail_window_s));
    json_object_object_add(data, "ip_max_failures", json_object_new_int(s.ip_max_failures));
    json_object_object_add(data, "ip_ban_s", json_object_new_int(s.ip_ban_s));
    json_object_object_add(data, "twofa_issuer", json_object_new_string(s.twofa_issuer));
    json_object_object_add(data, "twofa_step_s", json_object_new_int(s.twofa_step_s));
    json_object_object_add(data, "twofa_digits", json_object_new_int(s.twofa_digits));
    json_object_object_add(data, "twofa_window", json_object_new_int(s.twofa_window));
    return data;
}

int webd_auth_settings_update(struct json_object *body)
{
    struct webd_auth_settings s;
    const char *issuer;
    sqlite3_stmt *st;
    int rc;

    if (webd_auth_settings_load(&s) != 0)
        return -1;
    if (!body || !json_object_is_type(body, json_type_object))
        return -1;
    s.brute_enabled = app_nc_json_bool(body, "brute_enabled", s.brute_enabled);
    s.fail_window_s = app_nc_json_int(body, "fail_window_s", s.fail_window_s);
    s.max_failures = app_nc_json_int(body, "max_failures", s.max_failures);
    s.lock_s = app_nc_json_int(body, "lock_s", s.lock_s);
    s.ip_ban_enabled = app_nc_json_bool(body, "ip_ban_enabled", s.ip_ban_enabled);
    s.ip_fail_window_s = app_nc_json_int(body, "ip_fail_window_s", s.ip_fail_window_s);
    s.ip_max_failures = app_nc_json_int(body, "ip_max_failures", s.ip_max_failures);
    s.ip_ban_s = app_nc_json_int(body, "ip_ban_s", s.ip_ban_s);
    s.twofa_step_s = app_nc_json_int(body, "twofa_step_s", s.twofa_step_s);
    s.twofa_digits = app_nc_json_int(body, "twofa_digits", s.twofa_digits);
    s.twofa_window = app_nc_json_int(body, "twofa_window", s.twofa_window);
    issuer = app_nc_json_str(body, "twofa_issuer", s.twofa_issuer);
    if (issuer && issuer[0] && strlen(issuer) < sizeof(s.twofa_issuer))
        snprintf(s.twofa_issuer, sizeof(s.twofa_issuer), "%s", issuer);
    if (s.fail_window_s < 60 || s.fail_window_s > 86400) return -1;
    if (s.max_failures < 1 || s.max_failures > 100) return -1;
    if (s.lock_s < 60 || s.lock_s > 86400) return -1;
    if (s.ip_fail_window_s < 60 || s.ip_fail_window_s > 86400) return -1;
    if (s.ip_max_failures < 1 || s.ip_max_failures > 1000) return -1;
    if (s.ip_ban_s < 0 || s.ip_ban_s > 2592000) return -1;
    if (!webd_totp_step_ok(s.twofa_step_s)) return -1;
    if (!webd_totp_digits_ok(s.twofa_digits)) return -1;
    if (!webd_totp_window_ok(s.twofa_window)) return -1;

    st = config_prepare(
        "UPDATE web_auth_settings SET brute_enabled=?1,fail_window_s=?2,max_failures=?3,lock_s=?4,"
        "ip_ban_enabled=?5,ip_fail_window_s=?6,ip_max_failures=?7,ip_ban_s=?8,twofa_issuer=?9,"
        "twofa_step_s=?10,twofa_digits=?11,twofa_window=?12,updated_at=?13 WHERE id=1");
    if (!st) return -1;
    sqlite3_bind_int(st, 1, s.brute_enabled);
    sqlite3_bind_int(st, 2, s.fail_window_s);
    sqlite3_bind_int(st, 3, s.max_failures);
    sqlite3_bind_int(st, 4, s.lock_s);
    sqlite3_bind_int(st, 5, s.ip_ban_enabled);
    sqlite3_bind_int(st, 6, s.ip_fail_window_s);
    sqlite3_bind_int(st, 7, s.ip_max_failures);
    sqlite3_bind_int(st, 8, s.ip_ban_s);
    sqlite3_bind_text(st, 9, s.twofa_issuer, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 10, s.twofa_step_s);
    sqlite3_bind_int(st, 11, s.twofa_digits);
    sqlite3_bind_int(st, 12, s.twofa_window);
    sqlite3_bind_int64(st, 13, now_s());
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

struct json_object *webd_auth_failures_json(void)
{
    sqlite3_stmt *st;
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int rc;

    st = config_prepare("SELECT scope,auth_key,fail_count,first_failed_at,last_failed_at,locked_until,banned,ban_reason FROM web_auth_failures ORDER BY updated_at DESC LIMIT 200");
    if (!st) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("auth_failures_query_failed"));
        json_object_object_add(data, "failures", arr);
        return data;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "scope", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(o, "key", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(o, "fail_count", json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_object_add(o, "first_failed_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(o, "last_failed_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(o, "locked_until", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(o, "banned", json_object_new_boolean(sqlite3_column_int(st, 6)));
        json_object_object_add(o, "ban_reason", json_object_new_string((const char *)sqlite3_column_text(st, 7)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("auth_failures_query_failed"));
        json_object_object_add(data, "failures", arr);
        return data;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "failures", arr);
    return data;
}

struct json_object *webd_auth_failures_clear(struct json_object *body)
{
    const char *scope = app_nc_json_str(body, "scope", "");
    const char *key = app_nc_json_str(body, "key", "");
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st;
    int rc = SQLITE_OK;

    if (scope[0] && key[0]) {
        st = config_prepare("DELETE FROM web_auth_failures WHERE scope=?1 AND auth_key=?2");
        if (!st) {
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string("auth_failures_clear_failed"));
            return data;
        }
        sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
    } else {
        rc = config_db_exec_checked("DELETE FROM web_auth_failures") == 0 ? SQLITE_DONE : SQLITE_ERROR;
    }
    if (rc != SQLITE_DONE && rc != SQLITE_OK) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("auth_failures_clear_failed"));
        return data;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    return data;
}

static void webd_auth_key(const char *prefix, const char *value, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%s:%s", prefix ? prefix : "", value ? value : "");
}

static int webd_auth_failure_state(const char *scope, const char *key,
                                   int64_t *locked_until, int *banned)
{
    sqlite3_stmt *st;
    int found = 0;
    int rc;

    if (locked_until) *locked_until = 0;
    if (banned) *banned = 0;
    if (!scope || !key || !key[0])
        return 0;
    st = config_prepare("SELECT locked_until,banned FROM web_auth_failures WHERE scope=?1 AND auth_key=?2");
    if (!st) return -1;
    sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (locked_until) *locked_until = sqlite3_column_int64(st, 0);
        if (banned) *banned = sqlite3_column_int(st, 1);
        found = 1;
    } else if (rc != SQLITE_DONE) {
        found = -1;
    }
    sqlite3_finalize(st);
    return found;
}

static struct json_object *webd_login_block_response(const char *error, int64_t locked_until, int banned)
{
    struct json_object *data = json_object_new_object();
    int64_t now = now_s();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(error ? error : "login_locked"));
    json_object_object_add(data, "locked_until", json_object_new_int64(locked_until));
    json_object_object_add(data, "retry_after", json_object_new_int64(locked_until > now ? locked_until - now : 0));
    json_object_object_add(data, "banned", json_object_new_boolean(banned));
    return data;
}

int webd_auth_precheck(const char *username, const char *ip, struct json_object **err_out)
{
    struct webd_auth_settings s;
    int64_t now = now_s(), locked = 0;
    int banned = 0;
    char user_key[96];
    char ip_key[96];

    if (err_out) *err_out = NULL;
    if (webd_auth_settings_load(&s) != 0) {
        if (err_out) {
            struct json_object *data = json_object_new_object();
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string("auth_settings_unavailable"));
            *err_out = data;
        }
        return -1;
    }
    if (!s.brute_enabled)
        return 0;
    if (username && username[0]) {
        int state_rc;

        webd_auth_key("user", username, user_key, sizeof(user_key));
        state_rc = webd_auth_failure_state("user", user_key, &locked, &banned);
        if (state_rc < 0) {
            if (err_out) {
                struct json_object *data = json_object_new_object();
                json_object_object_add(data, "ok", json_object_new_boolean(0));
                json_object_object_add(data, "error", json_object_new_string("auth_state_unavailable"));
                *err_out = data;
            }
            return -1;
        }
        if (state_rc && (banned || locked > now)) {
            if (err_out) *err_out = webd_login_block_response(banned ? "user_banned" : "user_locked", locked, banned);
            return -1;
        }
    }
    if (ip && ip[0]) {
        int state_rc;

        webd_auth_key("ip", ip, ip_key, sizeof(ip_key));
        state_rc = webd_auth_failure_state("ip", ip_key, &locked, &banned);
        if (state_rc < 0) {
            if (err_out) {
                struct json_object *data = json_object_new_object();
                json_object_object_add(data, "ok", json_object_new_boolean(0));
                json_object_object_add(data, "error", json_object_new_string("auth_state_unavailable"));
                *err_out = data;
            }
            return -1;
        }
        if (state_rc && (banned || locked > now)) {
            if (err_out) *err_out = webd_login_block_response(banned ? "ip_banned" : "ip_locked", locked, banned);
            return -1;
        }
    }
    return 0;
}

static void webd_auth_clear_failure(const char *scope, const char *key)
{
    sqlite3_stmt *st;

    if (!scope || !key || !key[0])
        return;
    st = config_prepare("DELETE FROM web_auth_failures WHERE scope=?1 AND auth_key=?2");
    if (!st) return;
    sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void webd_auth_clear_success(const char *username, const char *ip)
{
    char key[96];

    if (username && username[0]) {
        webd_auth_key("user", username, key, sizeof(key));
        webd_auth_clear_failure("user", key);
    }
    if (ip && ip[0]) {
        webd_auth_key("ip", ip, key, sizeof(key));
        webd_auth_clear_failure("ip", key);
    }
}

struct json_object *webd_auth_record_unavailable_response(void)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("auth_failure_record_unavailable"));
    json_object_object_add(data, "message", json_object_new_string("authentication failure state could not be updated"));
    return data;
}

static int webd_auth_record_failure_one(const char *scope, const char *key,
                                        int window_s, int max_failures,
                                        int lock_s, int ban_enabled, int ban_s,
                                        const char *reason)
{
    sqlite3_stmt *st;
    int64_t now = now_s(), first = now, locked_until = 0;
    int count = 0, banned = 0;
    int rc;

    if (!scope || !key || !key[0])
        return 0;
    st = config_prepare("SELECT fail_count,first_failed_at,banned FROM web_auth_failures WHERE scope=?1 AND auth_key=?2");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(st, 0);
        first = sqlite3_column_int64(st, 1);
        banned = sqlite3_column_int(st, 2);
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    if (window_s <= 0 || now - first > window_s) {
        first = now;
        count = 0;
    }
    count++;
    if (!banned && max_failures > 0 && count >= max_failures) {
        locked_until = ban_enabled && ban_s == 0 ? 0 : now + (ban_enabled && ban_s > 0 ? ban_s : lock_s);
        if (ban_enabled && ban_s == 0)
            banned = 1;
        else if (lock_s > 0 && locked_until == 0)
            locked_until = now + lock_s;
    }
    st = config_prepare(
        "INSERT INTO web_auth_failures(scope,auth_key,fail_count,first_failed_at,last_failed_at,locked_until,banned,ban_reason,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?5) "
        "ON CONFLICT(scope,auth_key) DO UPDATE SET fail_count=excluded.fail_count,first_failed_at=excluded.first_failed_at,"
        "last_failed_at=excluded.last_failed_at,locked_until=excluded.locked_until,banned=excluded.banned,"
        "ban_reason=excluded.ban_reason,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, count);
    sqlite3_bind_int64(st, 4, first);
    sqlite3_bind_int64(st, 5, now);
    sqlite3_bind_int64(st, 6, locked_until);
    sqlite3_bind_int(st, 7, banned);
    sqlite3_bind_text(st, 8, reason ? reason : "auth_failed", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int webd_auth_record_failure(const char *username, const char *ip, const char *reason)
{
    struct webd_auth_settings s;
    char key[96];
    int rc = 0;

    if (webd_auth_settings_load(&s) != 0)
        return -1;
    if (!s.brute_enabled)
        return 0;
    if (username && username[0]) {
        webd_auth_key("user", username, key, sizeof(key));
        if (webd_auth_record_failure_one("user", key, s.fail_window_s, s.max_failures,
                                         s.lock_s, 0, 0, reason) != 0)
            rc = -1;
    }
    if (ip && ip[0]) {
        webd_auth_key("ip", ip, key, sizeof(key));
        if (webd_auth_record_failure_one("ip", key, s.ip_fail_window_s, s.ip_max_failures,
                                         s.lock_s, s.ip_ban_enabled, s.ip_ban_s, reason) != 0)
            rc = -1;
    }
    return rc;
}

int webd_user_count(void)
{
    sqlite3_stmt *st = config_prepare("SELECT COUNT(*) FROM web_users");
    int n = -1;

    if (!st) return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}
