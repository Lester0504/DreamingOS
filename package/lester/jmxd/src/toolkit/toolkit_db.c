// SPDX-License-Identifier: GPL-2.0-or-later
#include "toolkit_internal.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TOOLKIT_KEY_PATH "/etc/dreamingwrt/toolkit.key"

static int toolkit_sql(const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(g_toolkit_db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-toolkit] sqlite: %s\n", error ? error : "error");
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

int toolkit_db_init(void)
{
    if (g_toolkit_db) return 0;
    if (sqlite3_open_v2(TOOLKIT_CONFIG_DB, &g_toolkit_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_busy_timeout(g_toolkit_db, 3000);
    if (toolkit_sql("PRAGMA journal_mode=WAL") != 0 ||
        toolkit_sql("CREATE TABLE IF NOT EXISTS toolkit_port_mirror("
                    "id TEXT PRIMARY KEY,source_ifname TEXT NOT NULL,target_ifname TEXT NOT NULL,"
                    "direction TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL)") != 0 ||
        toolkit_sql("CREATE TABLE IF NOT EXISTS toolkit_ddns("
                    "id TEXT PRIMARY KEY,provider TEXT NOT NULL,hostname TEXT NOT NULL,ifname TEXT NOT NULL DEFAULT '',"
                    "enabled INTEGER NOT NULL DEFAULT 1,config_json TEXT NOT NULL DEFAULT '{}',"
                    "secret_cipher BLOB,secret_nonce BLOB,secret_tag BLOB,last_address TEXT NOT NULL DEFAULT '',"
                    "last_success_at INTEGER NOT NULL DEFAULT 0,last_failure_at INTEGER NOT NULL DEFAULT 0,"
                    "last_error TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL)") != 0)
        goto fail;
    return 0;
fail:
    toolkit_db_close();
    return -1;
}

void toolkit_db_close(void)
{
    if (g_toolkit_db) sqlite3_close(g_toolkit_db);
    g_toolkit_db = NULL;
}

static int toolkit_key_load(unsigned char key[32])
{
    FILE *fp = fopen(TOOLKIT_KEY_PATH, "rb");
    if (fp) {
        size_t got = fread(key, 1, 32, fp);
        fclose(fp);
        return got == 32 ? 0 : -1;
    }
    if (errno != ENOENT || RAND_bytes(key, 32) != 1) return -1;
    fp = fopen(TOOLKIT_KEY_PATH, "wb");
    if (!fp) return -1;
    chmod(TOOLKIT_KEY_PATH, 0600);
    if (fwrite(key, 1, 32, fp) != 32 || fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp); unlink(TOOLKIT_KEY_PATH); return -1;
    }
    return fclose(fp);
}

static int toolkit_secret_encrypt(const char *plain, unsigned char **cipher, int *cipher_len,
                                  unsigned char nonce[12], unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32];
    int len = 0, total = 0, ok = -1;
    size_t plain_len = strlen(plain ? plain : "{}");
    if (plain_len > 65536 || toolkit_key_load(key) != 0 || RAND_bytes(nonce, 12) != 1) return -1;
    *cipher = malloc(plain_len + 16);
    if (!*cipher) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, *cipher, &len, (const unsigned char *)(plain ? plain : "{}"),
                          (int)plain_len) != 1)
        goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, *cipher + total, &len) != 1) goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
    *cipher_len = total;
    ok = 0;
done:
    memset(key, 0, sizeof(key));
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ok != 0) { free(*cipher); *cipher = NULL; }
    return ok;
}

static char *toolkit_secret_decrypt(const void *cipher, int cipher_len,
                                    const void *nonce, int nonce_len,
                                    const void *tag, int tag_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32];
    char *plain = NULL;
    int len = 0, total = 0;
    if (!cipher || cipher_len < 0 || cipher_len > 65552 || nonce_len != 12 || tag_len != 16 ||
        toolkit_key_load(key) != 0) return NULL;
    plain = malloc((size_t)cipher_len + 1);
    ctx = EVP_CIPHER_CTX_new();
    if (!plain || !ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, (unsigned char *)plain, &len, cipher, cipher_len) != 1)
        goto fail;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, (unsigned char *)plain + total, &len) != 1)
        goto fail;
    total += len; plain[total] = 0;
    memset(key, 0, sizeof(key)); EVP_CIPHER_CTX_free(ctx);
    return plain;
fail:
    memset(key, 0, sizeof(key));
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(plain);
    return NULL;
}

static int toolkit_id_ok(const char *id)
{
    return toolkit_token_ok(id, 64) && !strchr(id, '/') && !strchr(id, ':');
}

static struct json_object *toolkit_ddns_row(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    json_object_object_add(o, "provider", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
    json_object_object_add(o, "hostname", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
    json_object_object_add(o, "ifname", json_object_new_string((const char *)sqlite3_column_text(st, 3)));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "credentials_set", json_object_new_boolean(sqlite3_column_bytes(st, 5) > 0));
    json_object_object_add(o, "last_address", json_object_new_string((const char *)sqlite3_column_text(st, 6)));
    json_object_object_add(o, "last_success_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
    json_object_object_add(o, "last_failure_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_object_add(o, "last_error", json_object_new_string((const char *)sqlite3_column_text(st, 9)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    return o;
}

struct json_object *toolkit_ddns_list(void)
{
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object(), *items = json_object_new_array();
    if (sqlite3_prepare_v2(g_toolkit_db,
        "SELECT id,provider,hostname,ifname,enabled,secret_cipher,last_address,last_success_at,last_failure_at,last_error,updated_at FROM toolkit_ddns ORDER BY id",
        -1, &st, NULL) == SQLITE_OK)
        while (sqlite3_step(st) == SQLITE_ROW) json_object_array_add(items, toolkit_ddns_row(st));
    if (st) sqlite3_finalize(st);
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "credentials_redacted", json_object_new_boolean(1));
    return toolkit_success(data, "dreamingwrt-toolkit.ddns");
}

struct json_object *toolkit_ddns_set(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", "");
    const char *provider = toolkit_json_str(payload, "provider", "");
    const char *hostname = toolkit_json_str(payload, "hostname", "");
    const char *ifname = toolkit_json_str(payload, "ifname", "");
    struct json_object *config = NULL, *credentials = NULL;
    const char *config_raw = "{}", *secret_raw = "{}";
    unsigned char *cipher = NULL, nonce[12], tag[16];
    int cipher_len = 0, supplied = 0;
    sqlite3_stmt *st = NULL;
    char generated[80];
    if (!id[0]) { snprintf(generated, sizeof(generated), "ddns-%lld", (long long)toolkit_now_s()); id = generated; }
    if (!toolkit_id_ok(id) || !toolkit_token_ok(provider, 32) || !hostname[0] || strlen(hostname) > 253 ||
        (ifname[0] && !toolkit_ifname_ok(ifname)))
        return toolkit_error("invalid_ddns_config", "id, provider, hostname, or interface is invalid");
    json_object_object_get_ex(payload, "config", &config);
    json_object_object_get_ex(payload, "credentials", &credentials);
    if (config && json_object_is_type(config, json_type_object))
        config_raw = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN);
    supplied = credentials && json_object_is_type(credentials, json_type_object) &&
               json_object_object_length(credentials) > 0;
    if (supplied) {
        secret_raw = json_object_to_json_string_ext(credentials, JSON_C_TO_STRING_PLAIN);
        if (toolkit_secret_encrypt(secret_raw, &cipher, &cipher_len, nonce, tag) != 0)
            return toolkit_error("secret_storage_failed", "DDNS credentials could not be encrypted");
    }
    if (sqlite3_prepare_v2(g_toolkit_db,
        "INSERT INTO toolkit_ddns(id,provider,hostname,ifname,enabled,config_json,secret_cipher,secret_nonce,secret_tag,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,"
        "hostname=excluded.hostname,ifname=excluded.ifname,enabled=excluded.enabled,config_json=excluded.config_json,"
        "secret_cipher=CASE WHEN ?11 THEN excluded.secret_cipher ELSE toolkit_ddns.secret_cipher END,"
        "secret_nonce=CASE WHEN ?11 THEN excluded.secret_nonce ELSE toolkit_ddns.secret_nonce END,"
        "secret_tag=CASE WHEN ?11 THEN excluded.secret_tag ELSE toolkit_ddns.secret_tag END,updated_at=excluded.updated_at",
        -1, &st, NULL) != SQLITE_OK) goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, provider, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, hostname, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, ifname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, toolkit_json_bool(payload, "enabled", 1)); sqlite3_bind_text(st, 6, config_raw, -1, SQLITE_TRANSIENT);
    if (supplied) { sqlite3_bind_blob(st, 7, cipher, cipher_len, SQLITE_TRANSIENT); sqlite3_bind_blob(st, 8, nonce, 12, SQLITE_TRANSIENT); sqlite3_bind_blob(st, 9, tag, 16, SQLITE_TRANSIENT); }
    else { sqlite3_bind_null(st, 7); sqlite3_bind_null(st, 8); sqlite3_bind_null(st, 9); }
    sqlite3_bind_int64(st, 10, toolkit_now_s()); sqlite3_bind_int(st, 11, supplied);
    if (sqlite3_step(st) != SQLITE_DONE) goto fail;
    sqlite3_finalize(st); free(cipher);
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "credentials_set", json_object_new_boolean(supplied));
    return toolkit_success(data, "dreamingwrt-toolkit.ddns");
fail:
    if (st) sqlite3_finalize(st); free(cipher);
    return toolkit_error("storage_error", "DDNS configuration could not be saved");
}

struct json_object *toolkit_ddns_delete(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", "");
    sqlite3_stmt *st = NULL;
    if (!toolkit_id_ok(id) || sqlite3_prepare_v2(g_toolkit_db, "DELETE FROM toolkit_ddns WHERE id=?1", -1, &st, NULL) != SQLITE_OK)
        return toolkit_error("invalid_ddns_id", "DDNS id is invalid");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    int ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_toolkit_db) > 0;
    sqlite3_finalize(st);
    if (!ok) return toolkit_error("ddns_not_found", "DDNS configuration was not found");
    struct json_object *data = json_object_new_object(); json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    return toolkit_success(data, "dreamingwrt-toolkit.ddns");
}

char *toolkit_ddns_secret_for_id(const char *id, char **provider, char **hostname,
                                 char **ifname, char **config_json)
{
    sqlite3_stmt *st = NULL;
    char *secret = NULL;
    if (sqlite3_prepare_v2(g_toolkit_db,
        "SELECT provider,hostname,ifname,config_json,secret_cipher,secret_nonce,secret_tag FROM toolkit_ddns WHERE id=?1 AND enabled=1",
        -1, &st, NULL) != SQLITE_OK) return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *provider = strdup((const char *)sqlite3_column_text(st, 0));
        *hostname = strdup((const char *)sqlite3_column_text(st, 1));
        *ifname = strdup((const char *)sqlite3_column_text(st, 2));
        *config_json = strdup((const char *)sqlite3_column_text(st, 3));
        secret = toolkit_secret_decrypt(sqlite3_column_blob(st, 4), sqlite3_column_bytes(st, 4),
                                        sqlite3_column_blob(st, 5), sqlite3_column_bytes(st, 5),
                                        sqlite3_column_blob(st, 6), sqlite3_column_bytes(st, 6));
    }
    sqlite3_finalize(st);
    return secret;
}

void toolkit_ddns_record_result(const char *id, int ok, const char *address, const char *error)
{
    sqlite3_stmt *st = NULL;
    const char *sql = ok ?
        "UPDATE toolkit_ddns SET last_address=?1,last_success_at=?2,last_error='',updated_at=?2 WHERE id=?3" :
        "UPDATE toolkit_ddns SET last_failure_at=?2,last_error=?1,updated_at=?2 WHERE id=?3";
    if (sqlite3_prepare_v2(g_toolkit_db, sql, -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, ok ? (address ? address : "") : (error ? error : "update_failed"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, toolkit_now_s()); sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
    sqlite3_step(st); sqlite3_finalize(st);
}
