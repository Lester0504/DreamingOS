// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "../src/ac/ac_secrets.h"

#define CHECK(label, expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "FAIL %s\n", label); \
        return 1; \
    } \
} while (0)

static int blob_contains(const unsigned char *haystack, int haystack_len,
                         const unsigned char *needle, size_t needle_len)
{
    int i;

    if (!haystack || needle_len > (size_t)haystack_len)
        return 0;
    for (i = 0; i <= haystack_len - (int)needle_len; i++) {
        if (!memcmp(haystack + i, needle, needle_len))
            return 1;
    }
    return 0;
}

static int inspect_ciphertext(sqlite3 *db, const unsigned char *secret,
                              size_t secret_len)
{
    sqlite3_stmt *statement = NULL;
    const unsigned char *ciphertext;
    int ciphertext_len, ok = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT ciphertext FROM ac_secrets WHERE secret_id='wifi.psk'",
            -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW)
        goto done;
    ciphertext = sqlite3_column_blob(statement, 0);
    ciphertext_len = sqlite3_column_bytes(statement, 0);
    ok = ciphertext_len == (int)secret_len &&
         !blob_contains(ciphertext, ciphertext_len, secret, secret_len);
done:
    sqlite3_finalize(statement);
    return ok;
}

static int mutate(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static int mutate_tag(sqlite3 *db)
{
    sqlite3_stmt *read_statement = NULL, *write_statement = NULL;
    const unsigned char *stored;
    unsigned char tag[16];
    int length, ok = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT tag FROM ac_secrets WHERE secret_id='wifi.psk'",
            -1, &read_statement, NULL) != SQLITE_OK ||
        sqlite3_step(read_statement) != SQLITE_ROW)
        goto done;
    stored = sqlite3_column_blob(read_statement, 0);
    length = sqlite3_column_bytes(read_statement, 0);
    if (!stored || length != (int)sizeof(tag))
        goto done;
    memcpy(tag, stored, sizeof(tag));
    tag[0] ^= 0x80;
    sqlite3_finalize(read_statement);
    read_statement = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE ac_secrets SET tag=?1 WHERE secret_id='wifi.psk'",
            -1, &write_statement, NULL) != SQLITE_OK ||
        sqlite3_bind_blob(write_statement, 1, tag, sizeof(tag),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(write_statement) != SQLITE_DONE)
        goto done;
    ok = sqlite3_changes(db) == 1;
done:
    memset(tag, 0, sizeof(tag));
    sqlite3_finalize(write_statement);
    sqlite3_finalize(read_statement);
    return ok;
}

int main(int argc, char **argv)
{
    static const unsigned char key_a[AC_SECRET_KEY_BYTES] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    static const unsigned char key_b[AC_SECRET_KEY_BYTES] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    };
    static const unsigned char value[] = "correct horse battery staple";
    struct ac_secrets *primary = NULL, *wrong = NULL, *filebacked = NULL;
    sqlite3 *legacy = NULL;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    sqlite3 *db = NULL;

    CHECK("key path", argc == 2);
    CHECK("open db", sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK("legacy empty schema", sqlite3_exec(db,
          "CREATE TABLE ac_secrets(secret_id TEXT PRIMARY KEY,"
          "version INTEGER NOT NULL,cipher_text BLOB NOT NULL,"
          "nonce BLOB NOT NULL,key_id TEXT NOT NULL,updated_at INTEGER NOT NULL)",
          NULL, NULL, NULL) == SQLITE_OK);
    CHECK("schema", ac_secrets_schema_init(db) == AC_SECRETS_OK);
    CHECK("key create", ac_secrets_open_or_create(db, argv[1],
                                                     &filebacked) ==
                         AC_SECRETS_OK);
    ac_secrets_close(filebacked);
    filebacked = NULL;
    CHECK("key reopen", ac_secrets_open_or_create(db, argv[1],
                                                     &filebacked) ==
                         AC_SECRETS_OK);
    ac_secrets_close(filebacked);
    filebacked = NULL;
    CHECK("open primary", ac_secrets_open_with_key(db, key_a, &primary) ==
                          AC_SECRETS_OK);
    CHECK("open wrong", ac_secrets_open_with_key(db, key_b, &wrong) ==
                        AC_SECRETS_OK);
    CHECK("distinct key ids", strcmp(ac_secrets_key_id(primary),
                                     ac_secrets_key_id(wrong)));

    CHECK("put", ac_secrets_put(primary, "wifi.psk", 7, value,
                                 sizeof(value) - 1) == AC_SECRETS_OK);
    CHECK("ciphertext opaque", inspect_ciphertext(db, value,
                                                   sizeof(value) - 1));
    CHECK("roundtrip", ac_secrets_get(primary, "wifi.psk", 7,
                                       &plaintext, &plaintext_len) ==
                       AC_SECRETS_OK);
    CHECK("roundtrip value", plaintext_len == sizeof(value) - 1 &&
                              !memcmp(plaintext, value, plaintext_len));
    ac_secrets_clear(plaintext, plaintext_len);
    plaintext = NULL;
    plaintext_len = 0;

    CHECK("wrong key rejected", ac_secrets_get(wrong, "wifi.psk", 7,
                                               &plaintext, &plaintext_len) ==
                              AC_SECRETS_AUTH_FAILED);
    CHECK("requested version bound", ac_secrets_get(primary, "wifi.psk", 8,
                                                     &plaintext, &plaintext_len) ==
                                    AC_SECRETS_AUTH_FAILED);
    CHECK("stored version mutate", mutate(db,
          "UPDATE ac_secrets SET version=8 WHERE secret_id='wifi.psk'"));
    CHECK("stored version aad bound", ac_secrets_get(primary, "wifi.psk", 8,
                                                      &plaintext, &plaintext_len) ==
                                     AC_SECRETS_AUTH_FAILED);

    CHECK("restore", ac_secrets_put(primary, "wifi.psk", 7, value,
                                     sizeof(value) - 1) == AC_SECRETS_OK);
    CHECK("secret id mutate", mutate(db,
          "UPDATE ac_secrets SET secret_id='wifi.psk.moved'"
          " WHERE secret_id='wifi.psk'"));
    CHECK("secret id aad bound", ac_secrets_get(primary, "wifi.psk.moved",
                                                7, &plaintext, &plaintext_len) ==
                               AC_SECRETS_AUTH_FAILED);
    CHECK("restore after id mutate", ac_secrets_delete(
              primary, "wifi.psk.moved") == AC_SECRETS_OK &&
          ac_secrets_put(primary, "wifi.psk", 7, value, sizeof(value) - 1) ==
              AC_SECRETS_OK);
    CHECK("key id mutate", mutate(db,
          "UPDATE ac_secrets SET key_id='sha256:00000000000000000000000000000000"
          "00000000000000000000000000000000' WHERE secret_id='wifi.psk'"));
    CHECK("key id aad bound", ac_secrets_get(primary, "wifi.psk", 7,
                                             &plaintext, &plaintext_len) ==
                            AC_SECRETS_AUTH_FAILED);
    CHECK("restore after key id mutate", ac_secrets_put(
              primary, "wifi.psk", 7, value, sizeof(value) - 1) ==
              AC_SECRETS_OK);
    CHECK("tamper tag", mutate_tag(db));
    CHECK("tamper rejected", ac_secrets_get(primary, "wifi.psk", 7,
                                             &plaintext, &plaintext_len) ==
                            AC_SECRETS_AUTH_FAILED);

    CHECK("replace after tamper", ac_secrets_put(primary, "wifi.psk", 9,
                                                  value, sizeof(value) - 1) ==
                                 AC_SECRETS_OK);
    CHECK("delete", ac_secrets_delete(primary, "wifi.psk") ==
                    AC_SECRETS_OK);
    CHECK("deleted", ac_secrets_get(primary, "wifi.psk", 9,
                                     &plaintext, &plaintext_len) ==
                    AC_SECRETS_NOT_FOUND);
    CHECK("delete replay", ac_secrets_delete(primary, "wifi.psk") ==
                           AC_SECRETS_NOT_FOUND);

    CHECK("legacy db", sqlite3_open(":memory:", &legacy) == SQLITE_OK);
    CHECK("legacy nonempty schema", sqlite3_exec(legacy,
          "CREATE TABLE ac_secrets(secret_id TEXT PRIMARY KEY,"
          "version INTEGER NOT NULL,cipher_text BLOB NOT NULL,"
          "nonce BLOB NOT NULL,key_id TEXT NOT NULL,updated_at INTEGER NOT NULL);"
          "INSERT INTO ac_secrets VALUES('keep',1,X'01',X'02','old',1)",
          NULL, NULL, NULL) == SQLITE_OK);
    CHECK("legacy nonempty rejected",
          ac_secrets_schema_init(legacy) == AC_SECRETS_ERROR);
    CHECK("legacy row preserved",
          sqlite3_exec(legacy, "SELECT cipher_text FROM ac_secrets",
                       NULL, NULL, NULL) == SQLITE_OK);

    ac_secrets_close(wrong);
    ac_secrets_close(primary);
    sqlite3_close(legacy);
    sqlite3_close(db);
    puts("ok");
    return 0;
}
