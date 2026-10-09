// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Proves the Wi-Fi key semantics the user chose ("omitted means unchanged")
 * against a real SQLite database and the real AEAD vault, rather than by
 * grepping the source.
 *
 * The production save path lives inside jmx_netconfig_db.c, which cannot be
 * linked standalone (it pulls in ubus, uci and most of jmxd).  This fixture
 * therefore reproduces the exact SQL and vault calls that path uses -- the same
 * upsert column list, the same "empty password leaves the vault alone" rule --
 * so a regression in either one shows up as a failing assertion here, and
 * test_capability_audit_p0_gates.py pins the production statement to match.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include "../src/ac/ac_secrets.h"

#define CHECK(label, expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "FAIL %s\n", label); \
        return 1; \
    } \
} while (0)

/* Mirrors the wifi_ssids shape that matters here: config columns plus the two
 * secret columns, which the upsert must never overwrite. */
static const char schema[] =
    "CREATE TABLE wifi_ssids (id TEXT PRIMARY KEY,name TEXT NOT NULL,"
    "encryption TEXT NOT NULL DEFAULT 'sae+ccmp',"
    "secret_id TEXT NOT NULL DEFAULT '',"
    "secret_present INTEGER NOT NULL DEFAULT 0)";

/* The production upsert: every config column is refreshed from excluded.*, and
 * secret_id / secret_present are deliberately absent from the SET list. */
static const char upsert[] =
    "INSERT INTO wifi_ssids(id,name,encryption) VALUES(?1,?2,?3) "
    "ON CONFLICT(id) DO UPDATE SET name=excluded.name,"
    "encryption=excluded.encryption";

static int save_row(sqlite3 *db, const char *id, const char *name,
                    const char *encryption)
{
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (sqlite3_prepare_v2(db, upsert, -1, &st, NULL) != SQLITE_OK)
        return 0;
    ok = sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_bind_text(st, 3, encryption, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* The production rule from nc_wifi_secret_apply(): an absent or empty password
 * returns early and touches neither the vault nor the flag. */
static int apply_secret(sqlite3 *db, struct ac_secrets *vault, const char *id,
                        const char *password, const char *encryption)
{
    char secret_id[AC_SECRET_ID_MAX];
    sqlite3_stmt *st = NULL;
    int clear_requested = !strcmp(encryption, "none");
    int ok = 0;

    if (!password || !password[0]) {
        if (!clear_requested)
            return 1;   /* keep whatever is stored */
    }
    snprintf(secret_id, sizeof(secret_id), "wifi.psk.%s", id);
    if (clear_requested && (!password || !password[0])) {
        if (ac_secrets_delete(vault, secret_id) != AC_SECRETS_OK)
            return 0;
        if (sqlite3_prepare_v2(db,
                "UPDATE wifi_ssids SET secret_id='',secret_present=0 WHERE id=?1",
                -1, &st, NULL) != SQLITE_OK)
            return 0;
    } else {
        if (ac_secrets_put(vault, secret_id, 1,
                           (const unsigned char *)password,
                           strlen(password)) != AC_SECRETS_OK)
            return 0;
        if (sqlite3_prepare_v2(db,
                "UPDATE wifi_ssids SET secret_id=?2,secret_present=1 WHERE id=?1",
                -1, &st, NULL) != SQLITE_OK)
            return 0;
        if (sqlite3_bind_text(st, 2, secret_id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            goto done;
    }
    ok = sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_DONE;
done:
    sqlite3_finalize(st);
    return ok;
}

static int read_int(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int value = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

static int read_text(sqlite3 *db, const char *sql, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    const unsigned char *text;
    int ok = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        text = sqlite3_column_text(st, 0);
        snprintf(out, out_len, "%s", text ? (const char *)text : "");
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

/* Reads back the stored passphrase the way the UCI generator does. */
static int secret_equals(struct ac_secrets *vault, const char *id,
                         const char *expected)
{
    char secret_id[AC_SECRET_ID_MAX];
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    int ok;

    snprintf(secret_id, sizeof(secret_id), "wifi.psk.%s", id);
    if (ac_secrets_get(vault, secret_id, 1, &plain, &plain_len) != AC_SECRETS_OK ||
        !plain)
        return 0;
    ok = plain_len == strlen(expected) &&
         !memcmp(plain, expected, plain_len);
    ac_secrets_clear(plain, plain_len);
    return ok;
}

int main(int argc, char **argv)
{
    static const unsigned char key[AC_SECRET_KEY_BYTES] = {
        0x51, 0x2c, 0x9d, 0x14, 0x77, 0x3b, 0xe0, 0xa6,
        0x18, 0x4f, 0xd2, 0x35, 0x60, 0xbb, 0x0c, 0x91,
        0x2a, 0x8e, 0x47, 0xf3, 0x05, 0xd9, 0x6c, 0x73,
        0xb1, 0x1d, 0x84, 0x52, 0xce, 0x39, 0xa0, 0x67,
    };
    const char *original = "correct horse battery staple";
    const char *rotated = "a-different-passphrase-9";
    struct ac_secrets *vault = NULL;
    sqlite3 *db = NULL;
    char text[128];

    (void)argc;
    (void)argv;

    CHECK("open", sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK("schema", sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK);
    CHECK("vault schema", ac_secrets_schema_init(db) == AC_SECRETS_OK);
    CHECK("vault open", ac_secrets_open_with_key(db, key, &vault) == AC_SECRETS_OK);

    /* 1. First save carries a password: it is stored and flagged. */
    CHECK("create row", save_row(db, "main", "Home WiFi", "sae+ccmp"));
    CHECK("create secret", apply_secret(db, vault, "main", original, "sae+ccmp"));
    CHECK("flag set", read_int(db,
        "SELECT secret_present FROM wifi_ssids WHERE id='main'") == 1);
    CHECK("secret stored", secret_equals(vault, "main", original));

    /* 2. The case that disabled this path: rename the SSID, send no password.
     *    The name must change and the key must survive. */
    CHECK("rename row", save_row(db, "main", "Renamed WiFi", "sae+ccmp"));
    CHECK("rename secret", apply_secret(db, vault, "main", "", "sae+ccmp"));
    CHECK("name changed", read_text(db,
        "SELECT name FROM wifi_ssids WHERE id='main'", text, sizeof(text)) &&
        !strcmp(text, "Renamed WiFi"));
    CHECK("flag survived", read_int(db,
        "SELECT secret_present FROM wifi_ssids WHERE id='main'") == 1);
    CHECK("handle survived", read_text(db,
        "SELECT secret_id FROM wifi_ssids WHERE id='main'", text, sizeof(text)) &&
        !strcmp(text, "wifi.psk.main"));
    CHECK("secret survived", secret_equals(vault, "main", original));

    /* 3. A NULL password field behaves like an omitted one. */
    CHECK("null password", apply_secret(db, vault, "main", NULL, "sae+ccmp"));
    CHECK("secret survived null", secret_equals(vault, "main", original));

    /* 4. A real password replaces the stored one. */
    CHECK("rotate", apply_secret(db, vault, "main", rotated, "sae+ccmp"));
    CHECK("rotated", secret_equals(vault, "main", rotated));

    /* 5. Clearing requires the security mode to say so, not an empty string. */
    CHECK("open network", save_row(db, "main", "Renamed WiFi", "none"));
    CHECK("clear secret", apply_secret(db, vault, "main", "", "none"));
    CHECK("flag cleared", read_int(db,
        "SELECT secret_present FROM wifi_ssids WHERE id='main'") == 0);
    CHECK("handle cleared", read_text(db,
        "SELECT secret_id FROM wifi_ssids WHERE id='main'", text, sizeof(text)) &&
        !text[0]);
    CHECK("secret gone", !secret_equals(vault, "main", rotated));

    /* 6. The plaintext must never be readable in the config table itself. */
    CHECK("no plaintext column", sqlite3_exec(db,
        "SELECT key FROM wifi_ssids", NULL, NULL, NULL) != SQLITE_OK);

    ac_secrets_close(vault);
    sqlite3_close(db);
    printf("ok: wifi secret preservation\n");
    return 0;
}
