// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Replay and single-use behaviour of the TOTP gate that guards irreversible
 * operations (factory reset).
 *
 * The gate itself lives inside jmx_app_api.c, which cannot be linked
 * standalone, so the two pieces that decide whether a code is accepted are
 * driven here against real sqlite and real HMAC:
 *
 *   1. the counter-window verifier, including its `counter <= last_counter`
 *      rejection, and
 *   2. the SQL counter advance, whose `twofa_last_counter < ?1` predicate is
 *      what makes two concurrent requests unable to spend the same code.
 *
 * These mirror the implementation deliberately: the point is to prove the
 * algorithm and the SQL predicate behave as claimed. If the implementation
 * changes shape, this fixture must be updated alongside it.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sqlite3.h>

#define TOTP_DIGITS 6
#define TOTP_STEP_S 30
#define TOTP_WINDOW 1

static int64_t g_now_s = 1785820000;

static int64_t now_s(void) { return g_now_s; }

/* RFC 4648 base32 decode, matching base32_decode() in the implementation. */
static int base32_decode(const char *in, unsigned char *out, size_t out_max,
                         size_t *out_len)
{
    uint32_t buffer = 0;
    int bits = 0;
    size_t produced = 0;

    if (!in || !out || !out_len)
        return -1;
    for (; *in; in++) {
        const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const char *found;

        if (*in == '=' || *in == ' ')
            continue;
        found = strchr(alphabet, *in);
        if (!found)
            return -1;
        buffer = (buffer << 5) | (uint32_t)(found - alphabet);
        bits += 5;
        if (bits >= 8) {
            if (produced >= out_max)
                return -1;
            bits -= 8;
            out[produced++] = (unsigned char)((buffer >> bits) & 0xff);
        }
    }
    *out_len = produced;
    return 0;
}

static int ct_str_equal(const char *a, const char *b)
{
    size_t i;
    unsigned char diff = 0;

    if (!a || !b || strlen(a) != strlen(b))
        return 0;
    for (i = 0; a[i]; i++)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static uint32_t totp_truncate(const unsigned char *digest, unsigned int len)
{
    int offset;

    if (!digest || len < 20)
        return 0;
    offset = digest[len - 1] & 0x0f;
    return ((uint32_t)(digest[offset] & 0x7f) << 24) |
           ((uint32_t)(digest[offset + 1] & 0xff) << 16) |
           ((uint32_t)(digest[offset + 2] & 0xff) << 8) |
           (uint32_t)digest[offset + 3];
}

static int totp_at_counter(const char *secret_b32, int64_t counter, int digits,
                           char *out, size_t out_len)
{
    unsigned char secret[64];
    size_t secret_len = 0;
    unsigned char msg[8];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    uint32_t value;
    int i;

    if (counter < 0 ||
        base32_decode(secret_b32, secret, sizeof(secret), &secret_len) != 0)
        return -1;
    for (i = 7; i >= 0; i--) {
        msg[i] = (unsigned char)(counter & 0xff);
        counter >>= 8;
    }
    if (!HMAC(EVP_sha1(), secret, (int)secret_len, msg, sizeof(msg), digest,
              &digest_len))
        return -1;
    value = totp_truncate(digest, digest_len);
    value %= 1000000U;
    snprintf(out, out_len, "%0*u", digits, (unsigned int)value);
    return 0;
}

static int totp_verify(const char *secret_b32, const char *code, int step_s,
                       int digits, int window, int64_t last_counter,
                       int64_t *matched)
{
    int64_t now_counter;
    int drift;

    if (matched)
        *matched = -1;
    if (!code || strlen(code) != (size_t)digits)
        return 0;
    now_counter = now_s() / step_s;
    for (drift = -window; drift <= window; drift++) {
        int64_t counter = now_counter + drift;
        char expected[TOTP_DIGITS + 1];

        if (counter <= last_counter || counter < 0)
            continue;
        if (totp_at_counter(secret_b32, counter, digits, expected,
                            sizeof(expected)) != 0)
            continue;
        if (ct_str_equal(code, expected)) {
            if (matched)
                *matched = counter;
            return 1;
        }
    }
    return 0;
}

static void sql(sqlite3 *db, const char *statement)
{
    char *error = NULL;

    if (sqlite3_exec(db, statement, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "sqlite failed: %s\nstatement: %s\n",
                error ? error : "unknown", statement);
        sqlite3_free(error);
        exit(1);
    }
}

/* Mirrors webd_user_twofa_touch_counter(): success only when the row advances. */
static int touch_counter(sqlite3 *db, const char *username, int64_t counter)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (counter < 0)
        return -1;
    assert(sqlite3_prepare_v2(db,
        "UPDATE web_users SET twofa_last_counter=?1,updated_at=?2 "
        "WHERE username=?3 AND twofa_enabled=1 AND twofa_last_counter < ?1",
        -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_int64(st, 1, counter);
    sqlite3_bind_int64(st, 2, now_s());
    sqlite3_bind_text(st, 3, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) > 0 ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

static int64_t stored_counter(sqlite3 *db, const char *username)
{
    sqlite3_stmt *st = NULL;
    int64_t value = -99;

    assert(sqlite3_prepare_v2(db,
        "SELECT twofa_last_counter FROM web_users WHERE username=?1",
        -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return value;
}

int main(void)
{
    const char *secret = "JBSWY3DPEHPK3PXP";
    const char *user = "otp-gate-user";
    sqlite3 *db = NULL;
    char code[TOTP_DIGITS + 1];
    char stale[TOTP_DIGITS + 1];
    int64_t matched = -1;
    int64_t counter_now;

    assert(sqlite3_open(":memory:", &db) == SQLITE_OK);
    sql(db, "CREATE TABLE web_users(username TEXT PRIMARY KEY, twofa_enabled INTEGER,"
            " twofa_last_counter INTEGER NOT NULL DEFAULT -1, updated_at INTEGER)");
    sql(db, "INSERT INTO web_users VALUES('otp-gate-user',1,-1,0)");

    counter_now = now_s() / TOTP_STEP_S;
    assert(totp_at_counter(secret, counter_now, TOTP_DIGITS, code, sizeof(code)) == 0);

    /* 1. A correct, unused code verifies and reports its counter. */
    assert(totp_verify(secret, code, TOTP_STEP_S, TOTP_DIGITS, TOTP_WINDOW, -1,
                       &matched) == 1);
    assert(matched == counter_now);

    /* 2. Consuming it advances the stored counter. */
    assert(touch_counter(db, user, matched) == 0);
    assert(stored_counter(db, user) == counter_now);

    /*
     * 3. Replay: the same code no longer verifies once the counter is stored.
     * This is the property the factory-reset gate depends on. Without it one
     * code could trigger two irreversible operations.
     */
    assert(totp_verify(secret, code, TOTP_STEP_S, TOTP_DIGITS, TOTP_WINDOW,
                       stored_counter(db, user), &matched) == 0);
    assert(matched == -1);

    /* 4. Even if verification were bypassed, the SQL advance refuses to move
     *    backwards or sideways, so a concurrent duplicate loses. */
    assert(touch_counter(db, user, counter_now) == -1);
    assert(touch_counter(db, user, counter_now - 1) == -1);

    /* 5. Malformed input is rejected rather than parsed loosely. */
    assert(totp_verify(secret, "12345", TOTP_STEP_S, TOTP_DIGITS, TOTP_WINDOW, -1,
                       &matched) == 0);
    assert(totp_verify(secret, "", TOTP_STEP_S, TOTP_DIGITS, TOTP_WINDOW, -1,
                       &matched) == 0);

    /*
     * 6. A code from an old step is refused even though it is a real code,
     *    because the window only ever looks forward of last_counter.
     */
    assert(totp_at_counter(secret, counter_now - 5, TOTP_DIGITS, stale,
                           sizeof(stale)) == 0);
    assert(totp_verify(secret, stale, TOTP_STEP_S, TOTP_DIGITS, TOTP_WINDOW,
                       stored_counter(db, user), &matched) == 0);

    /*
     * 7. Time moves on: the next step yields a fresh, acceptable code, so the
     *    guard blocks reuse without locking the account out.
     */
    g_now_s += TOTP_STEP_S;
    counter_now = now_s() / TOTP_STEP_S;
    assert(totp_at_counter(secret, counter_now, TOTP_DIGITS, code, sizeof(code)) == 0);
    assert(totp_verify(secret, code, TOTP_STEP_S, TOTP_DIGITS, TOTP_WINDOW,
                       stored_counter(db, user), &matched) == 1);
    assert(matched == counter_now);
    assert(touch_counter(db, user, matched) == 0);

    /* 8. Disabling 2FA makes the advance fail, so a disabled account cannot be
     *    silently treated as verified by a stale counter write. */
    sql(db, "UPDATE web_users SET twofa_enabled=0 WHERE username='otp-gate-user'");
    assert(touch_counter(db, user, counter_now + 1) == -1);

    sqlite3_close(db);
    printf("webd_otp_gate_fixture: all checks passed\n");
    return 0;
}
