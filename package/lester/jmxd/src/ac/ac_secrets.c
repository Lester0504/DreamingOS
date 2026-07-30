// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_secrets.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#define AC_SECRET_NONCE_BYTES 12U
#define AC_SECRET_TAG_BYTES 16U
#define AC_SECRET_KEY_ID_BYTES (7U + SHA256_DIGEST_LENGTH * 2U + 1U)
#define AC_SECRET_AAD_DOMAIN "dreamingwrt.ac.secret.v1"

struct ac_secrets {
    sqlite3 *db;
    unsigned char key[AC_SECRET_KEY_BYTES];
    char key_id[AC_SECRET_KEY_ID_BYTES];
};

static int ac_secret_owner_secure(uid_t owner)
{
#ifdef AC_SECRETS_TESTING
    return owner == geteuid();
#else
    return geteuid() == 0 && owner == 0;
#endif
}

static void ac_u32be(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void ac_u64be(unsigned char out[8], uint64_t value)
{
    unsigned int i;

    for (i = 0; i < 8; i++)
        out[7U - i] = (unsigned char)(value >> (i * 8U));
}

static int ac_secret_id_valid(const char *secret_id)
{
    size_t i, length;

    if (!secret_id || !(length = strlen(secret_id)) ||
        length > AC_SECRET_ID_MAX)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)secret_id[i];
        if (c < 0x21 || c > 0x7e)
            return 0;
    }
    return 1;
}

static int ac_secret_key_id(const unsigned char key[AC_SECRET_KEY_BYTES],
                            char out[AC_SECRET_KEY_ID_BYTES])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int i;

    if (!SHA256(key, AC_SECRET_KEY_BYTES, digest))
        return -1;
    memcpy(out, "sha256:", 7);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out[7U + i * 2U] = hex[digest[i] >> 4];
        out[8U + i * 2U] = hex[digest[i] & 0x0f];
    }
    out[AC_SECRET_KEY_ID_BYTES - 1U] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int ac_secret_aad(const char *secret_id, uint64_t version,
                         const char *key_id, unsigned char **out,
                         size_t *out_len)
{
    const size_t domain_len = sizeof(AC_SECRET_AAD_DOMAIN) - 1U;
    size_t id_len = strlen(secret_id);
    size_t key_id_len = strlen(key_id);
    size_t length = 4U + domain_len + 4U + id_len + 8U + 4U + key_id_len;
    unsigned char *aad, *cursor;

    if (id_len > UINT32_MAX || key_id_len > UINT32_MAX ||
        !(aad = OPENSSL_malloc(length)))
        return -1;
    cursor = aad;
    ac_u32be(cursor, (uint32_t)domain_len);
    cursor += 4;
    memcpy(cursor, AC_SECRET_AAD_DOMAIN, domain_len);
    cursor += domain_len;
    ac_u32be(cursor, (uint32_t)id_len);
    cursor += 4;
    memcpy(cursor, secret_id, id_len);
    cursor += id_len;
    ac_u64be(cursor, version);
    cursor += 8;
    ac_u32be(cursor, (uint32_t)key_id_len);
    cursor += 4;
    memcpy(cursor, key_id, key_id_len);
    *out = aad;
    *out_len = length;
    return 0;
}

static int ac_secret_key_read(const char *path,
                              unsigned char key[AC_SECRET_KEY_BYTES])
{
    struct stat status;
    size_t offset = 0;
    unsigned char extra;
    int fd = -1, rc = -1;

    if (!path || !*path ||
        (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        !ac_secret_owner_secure(status.st_uid) || status.st_nlink != 1 ||
        (status.st_mode & 0077) != 0)
        goto done;
    while (offset < AC_SECRET_KEY_BYTES) {
        ssize_t count = read(fd, key + offset, AC_SECRET_KEY_BYTES - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        offset += (size_t)count;
    }
    for (;;) {
        ssize_t count = read(fd, &extra, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0)
            break;
        goto done;
    }
    rc = 0;
done:
    if (fd >= 0 && close(fd) != 0)
        rc = -1;
    if (rc != 0)
        OPENSSL_cleanse(key, AC_SECRET_KEY_BYTES);
    return rc;
}

static int ac_secret_write_full(int fd, const unsigned char *data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, data + offset, len - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int ac_secret_key_create(const char *path,
                                unsigned char key[AC_SECRET_KEY_BYTES])
{
    unsigned char suffix[8] = { 0 };
    char parent[PATH_MAX];
    char temporary[96] = { 0 };
    const char *base;
    const char *slash;
    size_t parent_len;
    struct stat parent_status;
    struct stat status;
    int parent_fd = -1;
    int fd = -1;
    int rc = -1;

    slash = path ? strrchr(path, '/') : NULL;
    if (!slash || slash == path || !slash[1] ||
        (parent_len = (size_t)(slash - path)) >= sizeof(parent) ||
        snprintf(parent, sizeof(parent), "%.*s", (int)parent_len, path) >=
            (int)sizeof(parent))
        goto done;
    base = slash + 1;
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0 || fstat(parent_fd, &parent_status) != 0 ||
        !S_ISDIR(parent_status.st_mode) ||
        !ac_secret_owner_secure(parent_status.st_uid) ||
        (parent_status.st_mode & 0022) != 0 ||
        RAND_bytes(key, AC_SECRET_KEY_BYTES) != 1 ||
        RAND_bytes(suffix, sizeof(suffix)) != 1 ||
        snprintf(temporary, sizeof(temporary),
                 ".%s.tmp.%ld.%02x%02x%02x%02x%02x%02x%02x%02x",
                 base, (long)getpid(), suffix[0], suffix[1], suffix[2],
                 suffix[3], suffix[4], suffix[5], suffix[6], suffix[7]) >=
            (int)sizeof(temporary))
        goto done;
    fd = openat(parent_fd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        !ac_secret_owner_secure(status.st_uid) || status.st_nlink != 1 ||
        fchmod(fd, 0600) != 0 ||
        ac_secret_write_full(fd, key, AC_SECRET_KEY_BYTES) != 0 ||
        fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (linkat(parent_fd, temporary, parent_fd, base, 0) == 0) {
        rc = fsync(parent_fd) == 0 ? 0 : -1;
    } else if (errno == EEXIST) {
        rc = ac_secret_key_read(path, key);
    }
done:
    if (fd >= 0 && close(fd) != 0)
        rc = -1;
    if (parent_fd >= 0 && temporary[0])
        unlinkat(parent_fd, temporary, 0);
    if (parent_fd >= 0)
        close(parent_fd);
    if (rc != 0)
        OPENSSL_cleanse(key, AC_SECRET_KEY_BYTES);
    OPENSSL_cleanse(suffix, sizeof(suffix));
    return rc;
}

static int ac_secrets_open_key(sqlite3 *db,
                               const unsigned char key[AC_SECRET_KEY_BYTES],
                               struct ac_secrets **out)
{
    struct ac_secrets *secrets;

    if (!db || !key || !out)
        return AC_SECRETS_INVALID;
    *out = NULL;
    if (!(secrets = OPENSSL_zalloc(sizeof(*secrets))))
        return AC_SECRETS_ERROR;
    secrets->db = db;
    memcpy(secrets->key, key, sizeof(secrets->key));
    if (ac_secret_key_id(secrets->key, secrets->key_id) != 0) {
        ac_secrets_close(secrets);
        return AC_SECRETS_ERROR;
    }
    *out = secrets;
    return AC_SECRETS_OK;
}

int ac_secrets_open(sqlite3 *db, const char *key_path,
                    struct ac_secrets **out)
{
    unsigned char key[AC_SECRET_KEY_BYTES];
    int rc;

    memset(key, 0, sizeof(key));
    if (!out)
        return AC_SECRETS_INVALID;
    *out = NULL;
    if (ac_secret_key_read(key_path, key) != 0)
        return AC_SECRETS_ERROR;
    rc = ac_secrets_open_key(db, key, out);
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}

int ac_secrets_open_or_create(sqlite3 *db, const char *key_path,
                              struct ac_secrets **out)
{
    unsigned char key[AC_SECRET_KEY_BYTES] = { 0 };
    int rc;

    if (!db || !out)
        return AC_SECRETS_INVALID;
    *out = NULL;
    if (ac_secret_key_read(key_path, key) != 0 &&
        ac_secret_key_create(key_path, key) != 0)
        return AC_SECRETS_ERROR;
    rc = ac_secrets_open_key(db, key, out);
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}

#ifdef AC_SECRETS_TESTING
int ac_secrets_open_with_key(sqlite3 *db,
                             const unsigned char key[AC_SECRET_KEY_BYTES],
                             struct ac_secrets **out)
{
    return ac_secrets_open_key(db, key, out);
}
#endif

void ac_secrets_close(struct ac_secrets *secrets)
{
    if (!secrets)
        return;
    OPENSSL_cleanse(secrets, sizeof(*secrets));
    OPENSSL_free(secrets);
}

const char *ac_secrets_key_id(const struct ac_secrets *secrets)
{
    return secrets ? secrets->key_id : NULL;
}

int ac_secrets_schema_init(sqlite3 *db)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS ac_secrets ("
        "secret_id TEXT PRIMARY KEY NOT NULL,"
        "version INTEGER NOT NULL CHECK(version > 0),"
        "key_id TEXT NOT NULL,"
        "nonce BLOB NOT NULL CHECK(length(nonce) = 12),"
        "ciphertext BLOB NOT NULL,"
        "tag BLOB NOT NULL CHECK(length(tag) = 16)"
        ")";

    sqlite3_stmt *statement = NULL;
    int columns = 0, total_columns = 0;

    int old_shape = 0;
    sqlite3_int64 rows = 0;

    if (!db || sqlite3_exec(db, schema, NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, "PRAGMA table_info(ac_secrets)", -1,
                           &statement, NULL) != SQLITE_OK)
        return AC_SECRETS_ERROR;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(statement, 1);

        total_columns++;
        if (name && (!strcmp(name, "secret_id") || !strcmp(name, "version") ||
                     !strcmp(name, "key_id") || !strcmp(name, "nonce") ||
                     !strcmp(name, "ciphertext") || !strcmp(name, "tag")))
            columns++;
        if (name && (!strcmp(name, "cipher_text") ||
                     !strcmp(name, "updated_at")))
            old_shape++;
    }
    sqlite3_finalize(statement);
    if (columns == 6 && total_columns == 6)
        return AC_SECRETS_OK;
    if (old_shape != 2 || total_columns != 6 ||
        sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ac_secrets", -1,
                           &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return AC_SECRETS_ERROR;
    }
    rows = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    if (rows != 0)
        return AC_SECRETS_ERROR;
    return sqlite3_exec(db, "DROP TABLE ac_secrets", NULL, NULL, NULL) ==
               SQLITE_OK &&
           sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK ?
           AC_SECRETS_OK : AC_SECRETS_ERROR;
}

int ac_secrets_put(struct ac_secrets *secrets, const char *secret_id,
                   uint64_t version, const unsigned char *plaintext,
                   size_t plaintext_len)
{
    static const char sql[] =
        "INSERT INTO ac_secrets"
        "(secret_id,version,key_id,nonce,ciphertext,tag)"
        " VALUES(?1,?2,?3,?4,?5,?6)"
        " ON CONFLICT(secret_id) DO UPDATE SET"
        " version=excluded.version,key_id=excluded.key_id,"
        " nonce=excluded.nonce,ciphertext=excluded.ciphertext,"
        " tag=excluded.tag";
    unsigned char nonce[AC_SECRET_NONCE_BYTES];
    unsigned char tag[AC_SECRET_TAG_BYTES];
    unsigned char *aad = NULL, *ciphertext = NULL;
    size_t aad_len = 0;
    EVP_CIPHER_CTX *cipher = NULL;
    sqlite3_stmt *statement = NULL;
    int length = 0, final_len = 0, rc = AC_SECRETS_ERROR;

    memset(nonce, 0, sizeof(nonce));
    memset(tag, 0, sizeof(tag));
    if (!secrets || !ac_secret_id_valid(secret_id) || version == 0 ||
        version > INT64_MAX || (!plaintext && plaintext_len) ||
        plaintext_len > INT_MAX)
        return AC_SECRETS_INVALID;
    if (ac_secret_aad(secret_id, version, secrets->key_id, &aad, &aad_len) ||
        aad_len > INT_MAX || RAND_bytes(nonce, sizeof(nonce)) != 1 ||
        !(ciphertext = OPENSSL_malloc(plaintext_len ? plaintext_len : 1U)) ||
        !(cipher = EVP_CIPHER_CTX_new()) ||
        EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce),
                            NULL) != 1 ||
        EVP_EncryptInit_ex(cipher, NULL, NULL, secrets->key, nonce) != 1 ||
        EVP_EncryptUpdate(cipher, NULL, &length, aad, (int)aad_len) != 1 ||
        (plaintext_len && EVP_EncryptUpdate(cipher, ciphertext, &length,
                                             plaintext,
                                             (int)plaintext_len) != 1) ||
        EVP_EncryptFinal_ex(cipher, ciphertext + length, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, sizeof(tag),
                            tag) != 1)
        goto done;
    length += final_len;
    if (sqlite3_prepare_v2(secrets->db, sql, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_text(statement, 1, secret_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 2, (sqlite3_int64)version) != SQLITE_OK ||
        sqlite3_bind_text(statement, 3, secrets->key_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(statement, 4, nonce, sizeof(nonce), SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(statement, 5, ciphertext, length, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(statement, 6, tag, sizeof(tag), SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_DONE)
        goto done;
    rc = AC_SECRETS_OK;
done:
    sqlite3_finalize(statement);
    EVP_CIPHER_CTX_free(cipher);
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, plaintext_len ? plaintext_len : 1U);
        OPENSSL_free(ciphertext);
    }
    if (aad) {
        OPENSSL_cleanse(aad, aad_len);
        OPENSSL_free(aad);
    }
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
    return rc;
}

int ac_secrets_get(struct ac_secrets *secrets, const char *secret_id,
                   uint64_t version, unsigned char **plaintext,
                   size_t *plaintext_len)
{
    static const char sql[] =
        "SELECT version,key_id,nonce,ciphertext,tag FROM ac_secrets"
        " WHERE secret_id=?1";
    sqlite3_stmt *statement = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    unsigned char *aad = NULL, *cleartext = NULL;
    const unsigned char *nonce, *ciphertext, *tag;
    const char *stored_key_id;
    sqlite3_int64 stored_version;
    size_t aad_len = 0;
    int nonce_len, ciphertext_len, tag_len, length = 0, final_len = 0;
    int step, rc = AC_SECRETS_ERROR;

    if (!secrets || !ac_secret_id_valid(secret_id) || version == 0 ||
        version > INT64_MAX || !plaintext || !plaintext_len)
        return AC_SECRETS_INVALID;
    *plaintext = NULL;
    *plaintext_len = 0;
    if (sqlite3_prepare_v2(secrets->db, sql, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_text(statement, 1, secret_id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
        goto done;
    step = sqlite3_step(statement);
    if (step == SQLITE_DONE) {
        rc = AC_SECRETS_NOT_FOUND;
        goto done;
    }
    if (step != SQLITE_ROW)
        goto done;
    stored_version = sqlite3_column_int64(statement, 0);
    stored_key_id = (const char *)sqlite3_column_text(statement, 1);
    nonce = sqlite3_column_blob(statement, 2);
    nonce_len = sqlite3_column_bytes(statement, 2);
    ciphertext = sqlite3_column_blob(statement, 3);
    ciphertext_len = sqlite3_column_bytes(statement, 3);
    tag = sqlite3_column_blob(statement, 4);
    tag_len = sqlite3_column_bytes(statement, 4);
    if (stored_version <= 0 || (uint64_t)stored_version != version ||
        !stored_key_id || strcmp(stored_key_id, secrets->key_id) ||
        !nonce || nonce_len != AC_SECRET_NONCE_BYTES || ciphertext_len < 0 ||
        (ciphertext_len && !ciphertext) || !tag || tag_len != AC_SECRET_TAG_BYTES) {
        rc = AC_SECRETS_AUTH_FAILED;
        goto done;
    }
    if (ac_secret_aad(secret_id, version, stored_key_id, &aad, &aad_len) != 0 ||
        aad_len > INT_MAX ||
        !(cleartext = OPENSSL_malloc(ciphertext_len ?
                                     (size_t)ciphertext_len : 1U)) ||
        !(cipher = EVP_CIPHER_CTX_new()) ||
        EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1 ||
        EVP_DecryptInit_ex(cipher, NULL, NULL, secrets->key, nonce) != 1 ||
        EVP_DecryptUpdate(cipher, NULL, &length, aad, (int)aad_len) != 1 ||
        (ciphertext_len && EVP_DecryptUpdate(cipher, cleartext, &length,
                                              ciphertext, ciphertext_len) != 1) ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, tag_len,
                            (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(cipher, cleartext + length, &final_len) != 1) {
        rc = AC_SECRETS_AUTH_FAILED;
        goto done;
    }
    length += final_len;
    *plaintext = cleartext;
    *plaintext_len = (size_t)length;
    cleartext = NULL;
    rc = AC_SECRETS_OK;
done:
    if (cleartext) {
        OPENSSL_cleanse(cleartext, ciphertext_len > 0 ?
                        (size_t)ciphertext_len : 1U);
        OPENSSL_free(cleartext);
    }
    if (aad) {
        OPENSSL_cleanse(aad, aad_len);
        OPENSSL_free(aad);
    }
    EVP_CIPHER_CTX_free(cipher);
    sqlite3_finalize(statement);
    return rc;
}

int ac_secrets_delete(struct ac_secrets *secrets, const char *secret_id)
{
    sqlite3_stmt *statement = NULL;
    int changed, rc = AC_SECRETS_ERROR;

    if (!secrets || !ac_secret_id_valid(secret_id))
        return AC_SECRETS_INVALID;
    if (sqlite3_prepare_v2(secrets->db,
            "DELETE FROM ac_secrets WHERE secret_id=?1", -1,
            &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_text(statement, 1, secret_id, -1,
                          SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_DONE)
        goto done;
    changed = sqlite3_changes(secrets->db);
    rc = changed ? AC_SECRETS_OK : AC_SECRETS_NOT_FOUND;
done:
    sqlite3_finalize(statement);
    return rc;
}

void ac_secrets_clear(unsigned char *plaintext, size_t plaintext_len)
{
    if (!plaintext)
        return;
    OPENSSL_cleanse(plaintext, plaintext_len ? plaintext_len : 1U);
    OPENSSL_free(plaintext);
}
