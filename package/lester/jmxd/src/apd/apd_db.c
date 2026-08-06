// SPDX-License-Identifier: GPL-2.0-or-later
#ifdef APD_DB_TEST_STANDALONE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#define APD_DB_PATH "/etc/dreamingwrt/apd.db"
#define APD_IDENTITY_KEY_PATH "/etc/dreamingwrt/apd-pki/identity.ed25519"
#define APD_SCHEMA_VERSION 3
#define APD_SERVICE_NAME "dreamingwrt-apd"
#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
#define APD_KEY_ID_LEN 71
#define APD_PAIRING_VALUE_LEN 128
struct apd_node_identity {
    char ap_id[APD_AP_ID_LEN + 1];
    char key_id[APD_KEY_ID_LEN + 1];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    int64_t created_at;
};
struct apd_pairing_status {
    char state[32];
    char controller_id[APD_PAIRING_VALUE_LEN + 1];
    char request_id[APD_PAIRING_VALUE_LEN + 1];
    int challenge_present;
    int attempts;
    int64_t expires_at;
    int64_t updated_at;
};
void apd_db_close(void);
#else
#include "apd_internal.h"
#endif

#ifndef O_NOFOLLOW
#error "dreamingwrt-apd requires O_NOFOLLOW for identity storage"
#endif

#if !defined(SQLITE_OPEN_NOFOLLOW) && !defined(APD_DB_TEST_STANDALONE)
#error "dreamingwrt-apd requires SQLITE_OPEN_NOFOLLOW for identity storage"
#endif

sqlite3 *g_apd_db;
#ifndef APD_DB_TEST_STANDALONE
struct ubus_context *g_apd_ubus;
struct blob_buf g_apd_blob;
#endif
int64_t g_apd_started_at;

int64_t apd_now_s(void)
{
    return (int64_t)time(NULL);
}

const char *apd_db_path(void)
{
    const char *override = getenv("DREAMINGWRT_APD_DB_PATH");

    return override && override[0] ? override : APD_DB_PATH;
}

const char *apd_identity_key_path(void)
{
    const char *override = getenv("DREAMINGWRT_APD_IDENTITY_KEY_PATH");

    return override && override[0] ? override : APD_IDENTITY_KEY_PATH;
}

static int apd_uuid_valid(const char *value)
{
    static const int hyphen[] = { 8, 13, 18, 23 };
    size_t i;
    int h = 0;

    if (!value || strlen(value) != APD_AP_ID_LEN || value[14] != '4' ||
        (value[19] != '8' && value[19] != '9' && value[19] != 'a' &&
         value[19] != 'b'))
        return 0;
    for (i = 0; i < APD_AP_ID_LEN; i++) {
        if (h < 4 && (int)i == hyphen[h]) {
            if (value[i] != '-')
                return 0;
            h++;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static void apd_hex(char *out, size_t out_size,
                    const unsigned char *data, size_t data_len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (out_size < data_len * 2 + 1)
        return;
    for (i = 0; i < data_len; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 15];
    }
    out[data_len * 2] = '\0';
}

static int apd_generate_uuid(char out[APD_AP_ID_LEN + 1])
{
    unsigned char raw[16];

    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    snprintf(out, APD_AP_ID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    OPENSSL_cleanse(raw, sizeof(raw));
    return 0;
}

static int apd_generate_identity(char ap_id[APD_AP_ID_LEN + 1],
                                 unsigned char private_key[APD_ED25519_KEY_LEN],
                                 unsigned char public_key[APD_ED25519_KEY_LEN],
                                 char key_id[APD_KEY_ID_LEN + 1])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char digest_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    size_t private_len = APD_ED25519_KEY_LEN;
    size_t public_len = APD_ED25519_KEY_LEN;
    int rc = -1;

    if (apd_generate_uuid(ap_id) != 0)
        goto done;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0 ||
        EVP_PKEY_get_raw_private_key(key, private_key, &private_len) <= 0 ||
        EVP_PKEY_get_raw_public_key(key, public_key, &public_len) <= 0 ||
        private_len != APD_ED25519_KEY_LEN || public_len != APD_ED25519_KEY_LEN ||
        !SHA256(public_key, public_len, digest))
        goto done;
    apd_hex(digest_hex, sizeof(digest_hex), digest, sizeof(digest));
    snprintf(key_id, APD_KEY_ID_LEN + 1, "sha256:%s", digest_hex);
    rc = 0;
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(digest_hex, sizeof(digest_hex));
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int apd_path_parent(const char *path, char *out, size_t out_size)
{
    const char *slash = path ? strrchr(path, '/') : NULL;
    size_t len;

    if (!slash || slash == path || !out || out_size == 0)
        return -1;
    len = (size_t)(slash - path);
    if (len >= out_size)
        return -1;
    memcpy(out, path, len);
    out[len] = '\0';
    return 0;
}

static int apd_sync_parent(const char *path);

static int apd_secure_owner(uid_t owner)
{
#ifdef APD_DB_TEST_STANDALONE
    return owner == geteuid();
#else
    return geteuid() == 0 && owner == 0;
#endif
}

static int apd_validate_parent_mode(const char *path, mode_t required_mode,
                                    const char *purpose)
{
    char parent[512];
    struct stat st;

    if (apd_path_parent(path, parent, sizeof(parent)) != 0 ||
        lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) ||
        !apd_secure_owner(st.st_uid) ||
        (required_mode ? (st.st_mode & 0777) != required_mode :
                         (st.st_mode & 0022) != 0)) {
        fprintf(stderr, "[%s] unsafe %s parent for %s\n",
                APD_SERVICE_NAME, purpose, path ? path : "(null)");
        return -1;
    }
    return 0;
}

static int apd_validate_parent(const char *path)
{
    return apd_validate_parent_mode(path, 0, "database");
}

static int apd_validate_key_file(const char *path)
{
    struct stat st;

    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !apd_secure_owner(st.st_uid) ||
        (st.st_mode & 0777) != 0600 || st.st_size != APD_ED25519_KEY_LEN) {
        fprintf(stderr, "[%s] unsafe identity key file %s\n",
                APD_SERVICE_NAME, path ? path : "(null)");
        return -1;
    }
    return 0;
}

static int apd_prepare_key_parent(const char *path)
{
    char parent[512];
    char grandparent[512];
    struct stat st;

    if (apd_path_parent(path, parent, sizeof(parent)) != 0)
        return -1;
    if (lstat(parent, &st) != 0) {
        if (errno != ENOENT ||
            apd_path_parent(parent, grandparent, sizeof(grandparent)) != 0 ||
            lstat(grandparent, &st) != 0 || !S_ISDIR(st.st_mode) ||
            !apd_secure_owner(st.st_uid) || (st.st_mode & 0022) != 0 ||
            mkdir(parent, 0700) != 0 || apd_sync_parent(parent) != 0)
            return -1;
    }
    return apd_validate_parent_mode(path, 0700, "identity key");
}

static int apd_read_full(int fd, unsigned char *data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t count = read(fd, data + offset, len - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int apd_write_full(int fd, const unsigned char *data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t count = write(fd, data + offset, len - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int apd_sync_parent(const char *path)
{
    char parent[512];
    int fd;
    int rc;

    if (apd_path_parent(path, parent, sizeof(parent)) != 0)
        return -1;
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc == 0 ? 0 : -1;
}

static int apd_identity_key_store(const unsigned char key[APD_ED25519_KEY_LEN])
{
    const char *path = apd_identity_key_path();
    char temporary[640] = {0};
    struct stat st;
    unsigned char suffix[8] = {0};
    int fd = -1;
    int rc = -1;

    if (!key || apd_prepare_key_parent(path) != 0 ||
        RAND_bytes(suffix, sizeof(suffix)) != 1 ||
        snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%02x%02x%02x%02x%02x%02x%02x%02x",
                 path, (long)getpid(), suffix[0], suffix[1], suffix[2], suffix[3],
                 suffix[4], suffix[5], suffix[6], suffix[7]) >= (int)sizeof(temporary))
        goto done;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
        goto done;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !apd_secure_owner(st.st_uid) ||
        fchmod(fd, 0600) != 0 || apd_write_full(fd, key, APD_ED25519_KEY_LEN) != 0 ||
        fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if ((lstat(path, &st) == 0 || errno != ENOENT) ||
        rename(temporary, path) != 0 ||
        apd_sync_parent(path) != 0 || apd_validate_key_file(path) != 0)
        goto done;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (temporary[0])
        unlink(temporary);
    OPENSSL_cleanse(suffix, sizeof(suffix));
    return rc;
}

static int apd_identity_private_key_load(unsigned char out[APD_ED25519_KEY_LEN])
{
    const char *path = apd_identity_key_path();
    struct stat before;
    struct stat after;
    unsigned char extra;
    int fd = -1;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, APD_ED25519_KEY_LEN);
    if (apd_validate_parent_mode(path, 0700, "identity key") != 0 ||
        apd_validate_key_file(path) != 0)
        goto done;
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || !apd_secure_owner(before.st_uid) ||
        (before.st_mode & 0777) != 0600 || before.st_size != APD_ED25519_KEY_LEN ||
        apd_read_full(fd, out, APD_ED25519_KEY_LEN) != 0 ||
        read(fd, &extra, 1) != 0 || fstat(fd, &after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid || before.st_nlink != after.st_nlink)
        goto done;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        OPENSSL_cleanse(out, APD_ED25519_KEY_LEN);
    OPENSSL_cleanse(&extra, sizeof(extra));
    return rc;
}

EVP_PKEY *apd_identity_key_open(void)
{
    unsigned char private_key[APD_ED25519_KEY_LEN] = {0};
    EVP_PKEY *key = NULL;

    if (apd_identity_private_key_load(private_key) == 0)
        key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                           private_key, sizeof(private_key));
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return key;
}

static int apd_validate_db_file(const char *path)
{
    struct stat st;

    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !apd_secure_owner(st.st_uid) ||
        (st.st_mode & 0777) != 0600) {
        fprintf(stderr, "[%s] unsafe database file %s\n", APD_SERVICE_NAME, path);
        return -1;
    }
    return 0;
}

static int apd_prepare_db_file(const char *path)
{
    int fd;

    if (apd_validate_parent(path) != 0)
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        if (fchmod(fd, 0600) != 0 || fsync(fd) != 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        close(fd);
    } else if (errno != EEXIST) {
        fprintf(stderr, "[%s] cannot securely create %s: %s\n",
                APD_SERVICE_NAME, path, strerror(errno));
        return -1;
    }
    return apd_validate_db_file(path);
}

static int apd_init_lock_acquire(const char *path)
{
    char lock_path[576];
    struct stat st;
    int fd;

    if (!path || snprintf(lock_path, sizeof(lock_path), "%s.init.lock", path) >=
                     (int)sizeof(lock_path) || apd_validate_parent(path) != 0)
        return -1;
    fd = open(lock_path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !apd_secure_owner(st.st_uid) ||
        (st.st_mode & 0777) != 0600 ||
        flock(fd, LOCK_EX) != 0) {
        fprintf(stderr, "[%s] cannot acquire secure identity lock\n",
                APD_SERVICE_NAME);
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static void apd_init_lock_release(int fd)
{
    if (fd < 0)
        return;
    flock(fd, LOCK_UN);
    close(fd);
}

static int apd_exec(const char *sql)
{
    char *error = NULL;
#ifdef APD_DB_TEST_STANDALONE
    static int injected_commit_failure;

    if (!injected_commit_failure && !strcmp(sql, "COMMIT") &&
        getenv("APD_DB_TEST_FAIL_COMMIT_ONCE")) {
        injected_commit_failure = 1;
        return -1;
    }
#endif
    int rc = sqlite3_exec(g_apd_db, sql, NULL, NULL, &error);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "[%s] sqlite error: %s\n", APD_SERVICE_NAME,
                error ? error : sqlite3_errmsg(g_apd_db));
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int apd_table_exists(const char *name)
{
    sqlite3_stmt *st = NULL;
    int step;
    int exists = -1;

    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    step = sqlite3_step(st);
    if (step == SQLITE_ROW)
        exists = 1;
    else if (step == SQLITE_DONE)
        exists = 0;
    sqlite3_finalize(st);
    return exists;
}

static int apd_private_matches_public(
    const unsigned char private_key[APD_ED25519_KEY_LEN],
    const unsigned char public_key[APD_ED25519_KEY_LEN])
{
    EVP_PKEY *key = NULL;
    unsigned char derived[APD_ED25519_KEY_LEN] = {0};
    size_t derived_len = sizeof(derived);
    int matched = 0;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                       private_key, APD_ED25519_KEY_LEN);
    if (key && EVP_PKEY_get_raw_public_key(key, derived, &derived_len) > 0 &&
        derived_len == APD_ED25519_KEY_LEN &&
        CRYPTO_memcmp(derived, public_key, APD_ED25519_KEY_LEN) == 0)
        matched = 1;
    EVP_PKEY_free(key);
    OPENSSL_cleanse(derived, sizeof(derived));
    return matched;
}

static int apd_identity_from_private(
    const unsigned char private_key[APD_ED25519_KEY_LEN],
    char ap_id[APD_AP_ID_LEN + 1],
    unsigned char public_key[APD_ED25519_KEY_LEN],
    char key_id[APD_KEY_ID_LEN + 1])
{
    EVP_PKEY *key = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    char digest_hex[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    size_t public_len = APD_ED25519_KEY_LEN;
    int rc = -1;

    if (!private_key || !ap_id || !public_key || !key_id ||
        !(key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                             private_key,
                                             APD_ED25519_KEY_LEN)) ||
        EVP_PKEY_get_raw_public_key(key, public_key, &public_len) <= 0 ||
        public_len != APD_ED25519_KEY_LEN ||
        !SHA256(public_key, public_len, digest) ||
        apd_generate_uuid(ap_id) != 0)
        goto done;
    apd_hex(digest_hex, sizeof(digest_hex), digest, sizeof(digest));
    snprintf(key_id, APD_KEY_ID_LEN + 1, "sha256:%s", digest_hex);
    rc = 0;
done:
    EVP_PKEY_free(key);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(digest_hex, sizeof(digest_hex));
    return rc;
}

static int apd_identity_create_v3(void)
{
    sqlite3_stmt *st = NULL;
    char ap_id[APD_AP_ID_LEN + 1] = {0};
    char key_id[APD_KEY_ID_LEN + 1] = {0};
    unsigned char private_key[APD_ED25519_KEY_LEN] = {0};
    unsigned char public_key[APD_ED25519_KEY_LEN] = {0};
    int rc = -1;

    if (lstat(apd_identity_key_path(), &(struct stat){0}) == 0) {
        if (apd_identity_private_key_load(private_key) != 0 ||
            apd_identity_from_private(private_key, ap_id, public_key,
                                      key_id) != 0)
            goto done;
    } else {
        if (errno != ENOENT ||
            apd_generate_identity(ap_id, private_key, public_key, key_id) != 0 ||
            apd_identity_key_store(private_key) != 0)
            goto done;
    }
    if (apd_exec("BEGIN IMMEDIATE") != 0 ||
        apd_exec("CREATE TABLE apd_node_identity_v3 ("
                 "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                 "ap_id TEXT NOT NULL UNIQUE,public_key BLOB NOT NULL,"
                 "key_id TEXT NOT NULL UNIQUE,algorithm TEXT NOT NULL "
                 "CHECK(algorithm='Ed25519'),created_at INTEGER NOT NULL)") != 0 ||
        sqlite3_prepare_v2(g_apd_db,
            "INSERT INTO apd_node_identity_v3(singleton,ap_id,public_key,key_id,algorithm,created_at) "
            "VALUES(1,?1,?2,?3,'Ed25519',?4)", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, public_key, sizeof(public_key), SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, apd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (apd_exec("COMMIT") == 0) {
        rc = 0;
        goto done;
    }
rollback:
    sqlite3_finalize(st);
    st = NULL;
    apd_exec("ROLLBACK");
done:
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(ap_id, sizeof(ap_id));
    OPENSSL_cleanse(key_id, sizeof(key_id));
    return rc;
}

static int apd_schema_migrate(void)
{
    static const char common_schema[] =
        "CREATE TABLE IF NOT EXISTS apd_schema_meta ("
        " singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,"
        " owner TEXT NOT NULL,migrated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS apd_identity ("
        " singleton INTEGER PRIMARY KEY CHECK(singleton=1),ap_id TEXT NOT NULL DEFAULT '',"
        " controller_id TEXT NOT NULL DEFAULT '',hardware_identity_digest TEXT NOT NULL DEFAULT '',"
        " certificate_id TEXT NOT NULL DEFAULT '',key_id TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS apd_pairing_state ("
        " singleton INTEGER PRIMARY KEY CHECK(singleton=1),state TEXT NOT NULL CHECK(state IN "
        " ('unpaired','pending','challenge_pending','challenge_verified','expired','failed')),"
        " controller_id TEXT NOT NULL DEFAULT '',request_id TEXT NOT NULL DEFAULT '',"
        " challenge_hash BLOB,attempts INTEGER NOT NULL DEFAULT 0,expires_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS apd_certificate_meta ("
        " certificate_id TEXT PRIMARY KEY,serial TEXT NOT NULL,key_id TEXT NOT NULL,"
        " not_before INTEGER NOT NULL,not_after INTEGER NOT NULL,state TEXT NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS apd_applied_state ("
        " config_domain TEXT PRIMARY KEY,applied_revision INTEGER NOT NULL DEFAULT 0,"
        " readback_digest TEXT NOT NULL DEFAULT '',last_known_good_ref TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS apd_transaction_journal ("
        " transaction_id TEXT PRIMARY KEY,desired_revision INTEGER NOT NULL,candidate_digest TEXT NOT NULL,"
        " previous_digest TEXT NOT NULL DEFAULT '',state TEXT NOT NULL,applied_revision INTEGER NOT NULL DEFAULT 0,"
        " readback_digest TEXT NOT NULL DEFAULT '',error_code TEXT NOT NULL DEFAULT '',"
        " rollback_ref TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_apd_journal_state ON apd_transaction_journal(state,updated_at);";
    sqlite3_stmt *st = NULL;
    const void *blob;
    char ap_id[APD_AP_ID_LEN + 1] = {0};
    char key_id[APD_KEY_ID_LEN + 1] = {0};
    char algorithm[16] = {0};
    unsigned char private_key[APD_ED25519_KEY_LEN] = {0};
    unsigned char disk_key[APD_ED25519_KEY_LEN] = {0};
    unsigned char public_key[APD_ED25519_KEY_LEN] = {0};
    unsigned char public_digest[SHA256_DIGEST_LENGTH] = {0};
    char expected_key_id[APD_KEY_ID_LEN + 1] = {0};
    int64_t created_at = 0;
    int has_v2;
    int has_v3;
    int rc = -1;

    if (apd_exec("PRAGMA secure_delete=ON") != 0 ||
        apd_exec(common_schema) != 0)
        goto done;
    has_v2 = apd_table_exists("apd_node_identity_v2");
    has_v3 = apd_table_exists("apd_node_identity_v3");
    if (has_v2 < 0 || has_v3 < 0 || (has_v2 && has_v3))
        goto done;
    if (!has_v2 && !has_v3) {
        if (apd_identity_create_v3() != 0)
            goto done;
        has_v3 = 1;
    }
    if (has_v3) {
        if (apd_validate_key_file(apd_identity_key_path()) != 0)
            goto done;
    } else {
        if (sqlite3_prepare_v2(g_apd_db,
                "SELECT ap_id,private_key,public_key,key_id,algorithm,created_at "
                "FROM apd_node_identity_v2 WHERE singleton=1",
                -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW ||
            sqlite3_column_bytes(st, 1) != APD_ED25519_KEY_LEN ||
            sqlite3_column_bytes(st, 2) != APD_ED25519_KEY_LEN)
            goto done;
        snprintf(ap_id, sizeof(ap_id), "%s", sqlite3_column_text(st, 0));
        blob = sqlite3_column_blob(st, 1);
        if (!blob)
            goto done;
        memcpy(private_key, blob, sizeof(private_key));
        blob = sqlite3_column_blob(st, 2);
        if (!blob)
            goto done;
        memcpy(public_key, blob, sizeof(public_key));
        snprintf(key_id, sizeof(key_id), "%s", sqlite3_column_text(st, 3));
        snprintf(algorithm, sizeof(algorithm), "%s", sqlite3_column_text(st, 4));
        created_at = sqlite3_column_int64(st, 5);
        sqlite3_finalize(st);
        st = NULL;
        if (!SHA256(public_key, sizeof(public_key), public_digest))
            goto done;
        memcpy(expected_key_id, "sha256:", 7);
        apd_hex(expected_key_id + 7, sizeof(expected_key_id) - 7,
                public_digest, sizeof(public_digest));
        if (!apd_uuid_valid(ap_id) || strcmp(algorithm, "Ed25519") != 0 ||
            created_at <= 0 || strlen(key_id) != APD_KEY_ID_LEN ||
            CRYPTO_memcmp(key_id, expected_key_id, APD_KEY_ID_LEN) != 0 ||
            !apd_private_matches_public(private_key, public_key))
            goto done;
        if (lstat(apd_identity_key_path(), &(struct stat){0}) == 0) {
            if (apd_identity_private_key_load(disk_key) != 0 ||
                CRYPTO_memcmp(disk_key, private_key, sizeof(disk_key)) != 0)
                goto done;
        } else if (errno != ENOENT || apd_identity_key_store(private_key) != 0) {
            goto done;
        }
        if (apd_exec("BEGIN IMMEDIATE") != 0 ||
            apd_exec("CREATE TABLE apd_node_identity_v3 ("
                     "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                     "ap_id TEXT NOT NULL UNIQUE,public_key BLOB NOT NULL,"
                     "key_id TEXT NOT NULL UNIQUE,algorithm TEXT NOT NULL "
                     "CHECK(algorithm='Ed25519'),created_at INTEGER NOT NULL)") != 0 ||
            sqlite3_prepare_v2(g_apd_db,
                "INSERT INTO apd_node_identity_v3(singleton,ap_id,public_key,key_id,algorithm,created_at) "
                "VALUES(1,?1,?2,?3,'Ed25519',?4)", -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, public_key, sizeof(public_key), SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, key_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, created_at);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto rollback;
        sqlite3_finalize(st);
        st = NULL;
        if (apd_exec("DROP TABLE apd_node_identity_v2") != 0)
            goto rollback;
        if (apd_exec("COMMIT") != 0)
            goto rollback;
    }
    if (apd_exec("BEGIN IMMEDIATE") != 0 ||
        apd_exec("INSERT INTO apd_pairing_state(singleton,state,updated_at) "
                 "VALUES(1,'unpaired',strftime('%s','now')) "
                 "ON CONFLICT(singleton) DO NOTHING") != 0 ||
        sqlite3_prepare_v2(g_apd_db,
            "INSERT INTO apd_schema_meta(singleton,version,owner,migrated_at) VALUES(1,?1,?2,?3) "
            "ON CONFLICT(singleton) DO UPDATE SET version=excluded.version,owner=excluded.owner,"
            "migrated_at=excluded.migrated_at WHERE apd_schema_meta.version<excluded.version "
            "OR apd_schema_meta.owner<>excluded.owner", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int(st, 1, APD_SCHEMA_VERSION);
    sqlite3_bind_text(st, 2, APD_SERVICE_NAME, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, apd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (apd_exec("COMMIT") != 0)
        goto rollback;
    rc = 0;
    goto done;
rollback:
    sqlite3_finalize(st);
    st = NULL;
    apd_exec("ROLLBACK");
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(disk_key, sizeof(disk_key));
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(public_digest, sizeof(public_digest));
    OPENSSL_cleanse(expected_key_id, sizeof(expected_key_id));
    OPENSSL_cleanse(ap_id, sizeof(ap_id));
    OPENSSL_cleanse(key_id, sizeof(key_id));
    OPENSSL_cleanse(algorithm, sizeof(algorithm));
    return rc;
}

static int apd_integrity_check(void)
{
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (sqlite3_prepare_v2(g_apd_db, "PRAGMA quick_check(1)", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_text(st, 0) &&
        strcmp((const char *)sqlite3_column_text(st, 0), "ok") == 0)
        ok = 1;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int apd_identity_validate(void)
{
    sqlite3_stmt *st = NULL;
    unsigned char private_key[APD_ED25519_KEY_LEN];
    unsigned char derived[APD_ED25519_KEY_LEN];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char expected_key_id[APD_KEY_ID_LEN + 1];
    const unsigned char *ap_id;
    const unsigned char *public_key;
    const unsigned char *key_id;
    const unsigned char *algorithm;
    size_t derived_len = sizeof(derived);
    int rc = -1;

    memset(derived, 0, sizeof(derived));
    memset(private_key, 0, sizeof(private_key));
    memset(digest, 0, sizeof(digest));
    memset(expected_key_id, 0, sizeof(expected_key_id));
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT ap_id,public_key,key_id,algorithm FROM apd_node_identity_v3 WHERE singleton=1",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        goto done;
    ap_id = sqlite3_column_text(st, 0);
    public_key = sqlite3_column_blob(st, 1);
    key_id = sqlite3_column_text(st, 2);
    algorithm = sqlite3_column_text(st, 3);
    if (!apd_uuid_valid((const char *)ap_id) || !public_key ||
        !key_id || !algorithm ||
        sqlite3_column_bytes(st, 1) != APD_ED25519_KEY_LEN ||
        strcmp((const char *)algorithm, "Ed25519") != 0)
        goto done;
    {
        EVP_PKEY *key = apd_identity_key_open();

        if (!key) {
            goto done;
        }
        if (EVP_PKEY_get_raw_public_key(key, derived, &derived_len) <= 0) {
            EVP_PKEY_free(key);
            goto done;
        }
        EVP_PKEY_free(key);
    }
    if (
        derived_len != APD_ED25519_KEY_LEN ||
        CRYPTO_memcmp(derived, public_key, APD_ED25519_KEY_LEN) != 0 ||
        !SHA256(public_key, APD_ED25519_KEY_LEN, digest))
        goto done;
    apd_hex(expected_key_id + 7, sizeof(expected_key_id) - 7,
            digest, sizeof(digest));
    memcpy(expected_key_id, "sha256:", 7);
    if (strlen((const char *)key_id) != APD_KEY_ID_LEN ||
        CRYPTO_memcmp(expected_key_id, key_id, APD_KEY_ID_LEN) != 0)
        goto done;
    rc = 0;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(derived, sizeof(derived));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(expected_key_id, sizeof(expected_key_id));
    return rc;
}

static int apd_pairing_validate(void)
{
    sqlite3_stmt *st = NULL;
    const unsigned char *state;
    const unsigned char *controller_id;
    const unsigned char *request_id;
    int challenge_bytes;
    int attempts;
    int rc = -1;

    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT state,controller_id,request_id,challenge_hash,attempts,expires_at "
            "FROM apd_pairing_state WHERE singleton=1", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    state = sqlite3_column_text(st, 0);
    controller_id = sqlite3_column_text(st, 1);
    request_id = sqlite3_column_text(st, 2);
    challenge_bytes = sqlite3_column_bytes(st, 3);
    attempts = sqlite3_column_int(st, 4);
    if (!state || !controller_id || !request_id ||
        strlen((const char *)controller_id) > APD_PAIRING_VALUE_LEN ||
        strlen((const char *)request_id) > APD_PAIRING_VALUE_LEN ||
        attempts < 0 || attempts > 5 ||
        (challenge_bytes != 0 && challenge_bytes != SHA256_DIGEST_LENGTH))
        goto done;
    if (strcmp((const char *)state, "unpaired") != 0 &&
        strcmp((const char *)state, "pending") != 0 &&
        strcmp((const char *)state, "challenge_pending") != 0 &&
        strcmp((const char *)state, "challenge_verified") != 0 &&
        strcmp((const char *)state, "expired") != 0 &&
        strcmp((const char *)state, "failed") != 0)
        goto done;
    if (strcmp((const char *)state, "unpaired") == 0 &&
        (controller_id[0] || request_id[0] || challenge_bytes != 0 || attempts != 0 ||
         sqlite3_column_int64(st, 5) != 0))
        goto done;
    if ((strcmp((const char *)state, "pending") == 0 ||
         strcmp((const char *)state, "challenge_pending") == 0 ||
         strcmp((const char *)state, "challenge_verified") == 0) &&
        (!controller_id[0] || !request_id[0] || sqlite3_column_int64(st, 5) <= 0))
        goto done;
    if (strcmp((const char *)state, "challenge_pending") == 0 &&
        challenge_bytes != SHA256_DIGEST_LENGTH)
        goto done;
    if (strcmp((const char *)state, "challenge_pending") != 0 && challenge_bytes != 0)
        goto done;
    rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

int apd_db_init(void)
{
    mode_t old_umask;
    int open_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                     SQLITE_OPEN_FULLMUTEX;
    int lock_fd;

    lock_fd = apd_init_lock_acquire(apd_db_path());
    if (lock_fd < 0 || apd_prepare_db_file(apd_db_path()) != 0) {
        apd_init_lock_release(lock_fd);
        return -1;
    }
    old_umask = umask(0077);
#if defined(SQLITE_OPEN_NOFOLLOW) && !defined(APD_DB_TEST_STANDALONE)
    open_flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    if (sqlite3_open_v2(apd_db_path(), &g_apd_db,
            open_flags, NULL) != SQLITE_OK) {
        fprintf(stderr, "[%s] cannot open %s: %s\n", APD_SERVICE_NAME,
                apd_db_path(), g_apd_db ? sqlite3_errmsg(g_apd_db) : "open failed");
        apd_db_close();
        umask(old_umask);
        apd_init_lock_release(lock_fd);
        return -1;
    }
    sqlite3_busy_timeout(g_apd_db, 5000);
    if (apd_exec("PRAGMA foreign_keys=ON") != 0 || apd_integrity_check() != 0 ||
        apd_schema_migrate() != 0 || apd_identity_validate() != 0 ||
        apd_pairing_validate() != 0 ||
        apd_validate_db_file(apd_db_path()) != 0) {
        fprintf(stderr, "[%s] identity database validation failed\n", APD_SERVICE_NAME);
        apd_db_close();
        umask(old_umask);
        apd_init_lock_release(lock_fd);
        return -1;
    }
    umask(old_umask);
    apd_init_lock_release(lock_fd);
    return 0;
}

void apd_db_close(void)
{
    if (g_apd_db)
        sqlite3_close(g_apd_db);
    g_apd_db = NULL;
}

int apd_db_identity_get(struct apd_node_identity *out)
{
    sqlite3_stmt *st = NULL;
    const void *public_key;
    int rc = -1;

    if (!g_apd_db || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT ap_id,key_id,public_key,created_at FROM apd_node_identity_v3 WHERE singleton=1",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        goto done;
    public_key = sqlite3_column_blob(st, 2);
    if (!public_key || sqlite3_column_bytes(st, 2) != APD_ED25519_KEY_LEN)
        goto done;
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", sqlite3_column_text(st, 0));
    snprintf(out->key_id, sizeof(out->key_id), "%s", sqlite3_column_text(st, 1));
    memcpy(out->public_key, public_key, APD_ED25519_KEY_LEN);
    out->created_at = sqlite3_column_int64(st, 3);
    rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

int apd_db_pairing_status_get(struct apd_pairing_status *out)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_apd_db || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_pairing_state SET state='expired',challenge_hash=NULL,updated_at=?1 "
            "WHERE singleton=1 AND state IN ('pending','challenge_pending','challenge_verified') "
            "AND expires_at>0 AND expires_at<=?1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, apd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT state,controller_id,request_id,challenge_hash IS NOT NULL,attempts,expires_at,updated_at "
            "FROM apd_pairing_state WHERE singleton=1", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    snprintf(out->state, sizeof(out->state), "%s", sqlite3_column_text(st, 0));
    snprintf(out->controller_id, sizeof(out->controller_id), "%s", sqlite3_column_text(st, 1));
    snprintf(out->request_id, sizeof(out->request_id), "%s", sqlite3_column_text(st, 2));
    out->challenge_present = sqlite3_column_int(st, 3) != 0;
    out->attempts = sqlite3_column_int(st, 4);
    out->expires_at = sqlite3_column_int64(st, 5);
    out->updated_at = sqlite3_column_int64(st, 6);
    rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static int apd_pairing_value_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > APD_PAIRING_VALUE_LEN)
        return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)value[i] < 0x21 || (unsigned char)value[i] > 0x7e)
            return 0;
    return 1;
}

int apd_db_pairing_begin(const char *controller_id, const char *request_id,
                         int64_t expires_at)
{
    sqlite3_stmt *st = NULL;
    struct apd_pairing_status current;
    int rc = -1;

    if (!apd_pairing_value_valid(controller_id) || !apd_pairing_value_valid(request_id) ||
        expires_at <= apd_now_s() || expires_at > apd_now_s() + 600 ||
        apd_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (apd_db_pairing_status_get(&current) != 0 ||
        (strcmp(current.state, "unpaired") != 0 && strcmp(current.state, "expired") != 0))
        goto done;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_pairing_state SET state='pending',controller_id=?1,request_id=?2,"
            "challenge_hash=NULL,attempts=0,expires_at=?3,updated_at=?4 WHERE singleton=1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, controller_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, expires_at);
    sqlite3_bind_int64(st, 4, apd_now_s());
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0 && apd_exec("COMMIT") == 0)
        return 0;
    apd_exec("ROLLBACK");
    return -1;
}

int apd_db_pairing_set_challenge(const char *request_id,
                                 const unsigned char *challenge,
                                 size_t challenge_len)
{
    sqlite3_stmt *st = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int rc = -1;

    if (!apd_pairing_value_valid(request_id) || !challenge || challenge_len < 32 ||
        challenge_len > 256 || !SHA256(challenge, challenge_len, digest) ||
        apd_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_pairing_state SET state='challenge_pending',challenge_hash=?1,updated_at=?2 "
            "WHERE singleton=1 AND state='pending' AND request_id=?3 AND expires_at>?2",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_blob(st, 1, digest, sizeof(digest), SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, apd_now_s());
    sqlite3_bind_text(st, 3, request_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = 0;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (rc == 0 && apd_exec("COMMIT") == 0)
        return 0;
    apd_exec("ROLLBACK");
    return -1;
}

int apd_db_pairing_verify_challenge(const char *request_id,
                                    const unsigned char *challenge,
                                    size_t challenge_len)
{
    sqlite3_stmt *st = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    const void *expected;
    int matched = 0;
    int rc = -1;

    if (!apd_pairing_value_valid(request_id) || !challenge || challenge_len < 32 ||
        challenge_len > 256 || !SHA256(challenge, challenge_len, digest) ||
        apd_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT challenge_hash FROM apd_pairing_state WHERE singleton=1 AND "
            "state='challenge_pending' AND request_id=?1 AND expires_at>?2 AND attempts<5",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, apd_now_s());
    if (sqlite3_step(st) != SQLITE_ROW || sqlite3_column_bytes(st, 0) != SHA256_DIGEST_LENGTH)
        goto done;
    expected = sqlite3_column_blob(st, 0);
    matched = expected && CRYPTO_memcmp(expected, digest, sizeof(digest)) == 0;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_apd_db, matched ?
            "UPDATE apd_pairing_state SET state='challenge_verified',challenge_hash=NULL,updated_at=?1 "
            "WHERE singleton=1 AND state='challenge_pending' AND request_id=?2" :
            "UPDATE apd_pairing_state SET attempts=attempts+1,state=CASE WHEN attempts+1>=5 THEN 'failed' ELSE state END,"
            "challenge_hash=CASE WHEN attempts+1>=5 THEN NULL ELSE challenge_hash END,"
            "updated_at=?1 WHERE singleton=1 AND state='challenge_pending' AND request_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, apd_now_s());
    sqlite3_bind_text(st, 2, request_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = matched ? 0 : 1;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (rc >= 0 && apd_exec("COMMIT") == 0)
        return rc;
    apd_exec("ROLLBACK");
    return -1;
}

int apd_db_pairing_reset(const char *request_id)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!apd_pairing_value_valid(request_id) || apd_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_pairing_state SET state='unpaired',controller_id='',request_id='',"
            "challenge_hash=NULL,attempts=0,expires_at=0,updated_at=?1 "
            "WHERE singleton=1 AND request_id=?2", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, apd_now_s());
        sqlite3_bind_text(st, 2, request_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
            rc = 0;
    }
    sqlite3_finalize(st);
    if (rc == 0 && apd_exec("COMMIT") == 0)
        return 0;
    apd_exec("ROLLBACK");
    return -1;
}

/*
 * Unconditional return to 'unpaired', used by the unpair path.
 *
 * apd_db_pairing_reset() deliberately requires a matching request_id so a
 * stale controller cannot cancel someone else's in-flight pairing. Unpair has
 * no request_id to present -- adoption completed long ago and the row may sit
 * in any state -- so it clears the singleton outright. Unlike the targeted
 * reset this tolerates "no row changed", because a row already reading
 * 'unpaired' is the desired end state, not a failure.
 */
int apd_db_pairing_clear(void)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_apd_db || apd_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_pairing_state SET state='unpaired',controller_id='',request_id='',"
            "challenge_hash=NULL,attempts=0,expires_at=0,updated_at=?1 "
            "WHERE singleton=1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, apd_now_s());
        if (sqlite3_step(st) == SQLITE_DONE)
            rc = 0;
    }
    sqlite3_finalize(st);
    if (rc == 0 && apd_exec("COMMIT") == 0)
        return 0;
    apd_exec("ROLLBACK");
    return -1;
}
