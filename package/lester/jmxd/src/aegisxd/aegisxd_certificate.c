// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

#include <fcntl.h>
#include <sys/file.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define AEGISXD_CA_DEFAULT_DAYS 3650
#define AEGISXD_CA_MIN_DAYS 365
#define AEGISXD_CA_MAX_DAYS 7300
#define AEGISXD_CA_MAX_PEM 16384

struct aegisxd_ca_record {
    int generation;
    char state[24];
    char subject[256];
    char serial[80];
    char fingerprint[96];
    int64_t not_before;
    int64_t not_after;
    int64_t created_at;
    int64_t rotated_at;
    int64_t revoked_at;
};

static int certificate_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] certificate schema failed: %s\n",
                error ? error : sqlite3_errmsg(db));
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

int aegisxd_certificate_schema_init(void)
{
    sqlite3_stmt *statement = NULL;
    const char *schema = NULL;
    int migration_required = 0;

    if (certificate_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_inspection_ca ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " generation INTEGER NOT NULL DEFAULT 0,"
        " state TEXT NOT NULL DEFAULT 'absent' CHECK(state IN ('absent','active','revoked')),"
        " subject TEXT NOT NULL DEFAULT '',"
        " serial TEXT NOT NULL DEFAULT '',"
        " fingerprint_sha256 TEXT NOT NULL DEFAULT '',"
        " not_before INTEGER NOT NULL DEFAULT 0,"
        " not_after INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " rotated_at INTEGER NOT NULL DEFAULT 0,"
        " revoked_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)"
        ";INSERT OR IGNORE INTO aegis_inspection_ca(id) VALUES(1)") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_aegisxd_config_db,
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='aegis_certificate_distributions'", -1,
            &statement, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(statement) == SQLITE_ROW) {
        schema = (const char *)sqlite3_column_text(statement, 0);
        migration_required = !schema || !strstr(schema, "'superseded'") ||
                             !strstr(schema, "'ca_revoked'");
    }
    sqlite3_finalize(statement);

    if (migration_required && certificate_exec(g_aegisxd_config_db,
        "BEGIN IMMEDIATE"
        ";DROP INDEX IF EXISTS idx_aegis_certificate_distributions_target"
        ";ALTER TABLE aegis_certificate_distributions "
        "RENAME TO aegis_certificate_distributions_legacy"
        ";CREATE TABLE aegis_certificate_distributions ("
        " distribution_id TEXT PRIMARY KEY,"
        " ca_generation INTEGER NOT NULL,"
        " target_type TEXT NOT NULL,"
        " target_id TEXT NOT NULL,"
        " method TEXT NOT NULL CHECK(method IN ('manual')),"
        " state TEXT NOT NULL CHECK(state IN "
        "('ready_for_download','downloaded','cancelled','superseded','ca_revoked')),"
        " reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " downloaded_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)"
        ";INSERT INTO aegis_certificate_distributions "
        "SELECT * FROM aegis_certificate_distributions_legacy"
        ";DROP TABLE aegis_certificate_distributions_legacy"
        ";CREATE INDEX idx_aegis_certificate_distributions_target "
        "ON aegis_certificate_distributions(target_type,target_id,created_at DESC)"
        ";COMMIT") != 0) {
        (void)sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return certificate_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_certificate_distributions ("
        " distribution_id TEXT PRIMARY KEY,"
        " ca_generation INTEGER NOT NULL,"
        " target_type TEXT NOT NULL,"
        " target_id TEXT NOT NULL,"
        " method TEXT NOT NULL CHECK(method IN ('manual')),"
        " state TEXT NOT NULL CHECK(state IN "
        "('ready_for_download','downloaded','cancelled','superseded','ca_revoked')),"
        " reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " downloaded_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)"
        ";CREATE INDEX IF NOT EXISTS idx_aegis_certificate_distributions_target "
        "ON aegis_certificate_distributions(target_type,target_id,created_at DESC)");
}

static int certificate_json_int(struct json_object *body, const char *key, int def)
{
    struct json_object *value = NULL;

    if (!body || !json_object_object_get_ex(body, key, &value) || !value ||
        !json_object_is_type(value, json_type_int))
        return def;
    return json_object_get_int(value);
}

static int certificate_text_ok(const char *value, size_t maximum, int allow_empty)
{
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length;

    if (!value || (!(length = strlen(value)) && !allow_empty) || length > maximum)
        return 0;
    for (; *cursor; cursor++)
        if (*cursor < 0x20 || *cursor == 0x7f)
            return 0;
    return 1;
}

static int certificate_id(char out[37])
{
    unsigned char bytes[16];

    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
        return -1;
    bytes[6] = (unsigned char)((bytes[6] & 0x0f) | 0x40);
    bytes[8] = (unsigned char)((bytes[8] & 0x3f) | 0x80);
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
             bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return 0;
}

static int certificate_uuid_ok(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 36)
        return 0;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-')
                return 0;
        } else if (!isxdigit((unsigned char)value[i])) {
            return 0;
        }
    }
    return 1;
}

static int certificate_mac_normalize(const char *input, char output[18])
{
    unsigned int octets[6];
    char tail;

    if (!input || sscanf(input, "%2x:%2x:%2x:%2x:%2x:%2x%c",
                         &octets[0], &octets[1], &octets[2], &octets[3],
                         &octets[4], &octets[5], &tail) != 6)
        return -1;
    snprintf(output, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]);
    return 0;
}

static int certificate_client_known(const char *mac)
{
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;
    int known = 0;

    if (!mac || sqlite3_open_v2(AEGISXD_CLIENT_DB_PATH, &database,
                                SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                                NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(database,
            "SELECT 1 FROM clients WHERE lower(mac)=?1 LIMIT 1", -1,
            &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, mac, -1, SQLITE_TRANSIENT);
    known = sqlite3_step(statement) == SQLITE_ROW;
done:
    sqlite3_finalize(statement);
    if (database)
        sqlite3_close(database);
    return known;
}

static int certificate_prepare_directory(void)
{
    struct stat status;

    if (aegisxd_mkdir_p(AEGISXD_PKI_DIR, 0700) != 0 ||
        lstat(AEGISXD_PKI_DIR, &status) != 0 || !S_ISDIR(status.st_mode) ||
        S_ISLNK(status.st_mode) || chmod(AEGISXD_PKI_DIR, 0700) != 0)
        return -1;
    return 0;
}

static int certificate_lock(void)
{
    char path[AEGISXD_MAX_PATH];
    int fd;

    if (certificate_prepare_directory() != 0 ||
        snprintf(path, sizeof(path), "%s/.lock", AEGISXD_PKI_DIR) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fchmod(fd, 0600) != 0 || flock(fd, LOCK_EX) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static void certificate_unlock(int fd)
{
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
}

static int certificate_paths(int generation, char *key, size_t key_size,
                             char *cert, size_t cert_size)
{
    if (generation <= 0 ||
        snprintf(key, key_size, "%s/inspection-ca-%d.key.pem",
                 AEGISXD_PKI_DIR, generation) >= (int)key_size ||
        snprintf(cert, cert_size, "%s/inspection-ca-%d.pem",
                 AEGISXD_PKI_DIR, generation) >= (int)cert_size)
        return -1;
    return 0;
}

static int certificate_test_fail(const char *stage)
{
#ifdef AEGISXD_CERTIFICATE_TEST_STANDALONE
    const char *configured = getenv("AEGISXD_CERTIFICATE_FAIL_STAGE");

    return configured && stage && !strcmp(configured, stage);
#else
    (void)stage;
    return 0;
#endif
}

static int certificate_sync_directory(void)
{
    int fd;
    int rc;

    if (certificate_test_fail("directory-fsync")) {
        errno = EIO;
        return -1;
    }
    fd = open(AEGISXD_PKI_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc == 0 ? 0 : -1;
}

static int certificate_unlink_durable(const char *path)
{
    if (!path || !path[0])
        return -1;
    if (unlink(path) != 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    return certificate_sync_directory();
}

static int certificate_atomic_write(const char *path, mode_t mode,
                                    int (*writer)(BIO *, void *), void *value)
{
    char temporary[AEGISXD_MAX_PATH] = "";
    unsigned char random[8];
    BIO *bio = NULL;
    int fd = -1;
    int rc = -1;

    if (!path || !writer || RAND_bytes(random, sizeof(random)) != 1 ||
        snprintf(temporary, sizeof(temporary), "%s.tmp.%02x%02x%02x%02x%02x%02x%02x%02x",
                 path, random[0], random[1], random[2], random[3], random[4],
                 random[5], random[6], random[7]) >= (int)sizeof(temporary))
        goto done;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0 || fchmod(fd, mode) != 0 || !(bio = BIO_new_fd(fd, BIO_NOCLOSE)) ||
        writer(bio, value) != 1 || BIO_flush(bio) != 1 || fsync(fd) != 0 ||
        rename(temporary, path) != 0 || certificate_sync_directory() != 0)
        goto done;
    rc = 0;
done:
    BIO_free(bio);
    if (fd >= 0)
        close(fd);
    if (rc != 0) {
        if (temporary[0])
            (void)unlink(temporary);
        if (path)
            (void)unlink(path);
        (void)certificate_sync_directory();
    }
    OPENSSL_cleanse(random, sizeof(random));
    return rc;
}

static int certificate_write_key(BIO *bio, void *value)
{
    return PEM_write_bio_PrivateKey(bio, (EVP_PKEY *)value, NULL, NULL, 0, NULL, NULL);
}

static int certificate_write_x509(BIO *bio, void *value)
{
    return PEM_write_bio_X509(bio, (X509 *)value);
}

static EVP_PKEY *certificate_key_generate(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;

    if (!context || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int certificate_extension(X509 *certificate, int nid, const char *value)
{
    X509V3_CTX context;
    X509_EXTENSION *extension;

    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, certificate, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char *)value);
    if (!extension)
        return -1;
    if (X509_add_ext(certificate, extension, -1) != 1) {
        X509_EXTENSION_free(extension);
        return -1;
    }
    X509_EXTENSION_free(extension);
    return 0;
}

static X509 *certificate_ca_generate(EVP_PKEY *key, const char *common_name,
                                     int validity_days)
{
    X509 *certificate = NULL;
    X509_NAME *name;
    unsigned char serial_bytes[16];
    BIGNUM *serial_number = NULL;
    ASN1_INTEGER *serial = NULL;

    if (!key || !common_name || RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1 ||
        !(serial_number = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL)) ||
        !(serial = BN_to_ASN1_INTEGER(serial_number, NULL)) ||
        !(certificate = X509_new()) || X509_set_version(certificate, 2) != 1 ||
        X509_set_serialNumber(certificate, serial) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate), -300) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate),
                         (long)validity_days * 86400L) ||
        X509_set_pubkey(certificate, key) != 1 ||
        !(name = X509_get_subject_name(certificate)) ||
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   (const unsigned char *)"DreamingOS", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                                   (const unsigned char *)"AegisX Inspection", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                   (const unsigned char *)common_name, -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate, name) != 1 ||
        certificate_extension(certificate, NID_basic_constraints,
                              "critical,CA:TRUE,pathlen:0") != 0 ||
        certificate_extension(certificate, NID_key_usage,
                              "critical,keyCertSign,cRLSign") != 0 ||
        certificate_extension(certificate, NID_subject_key_identifier, "hash") != 0 ||
        certificate_extension(certificate, NID_authority_key_identifier,
                              "keyid:always") != 0 ||
        X509_sign(certificate, key, EVP_sha256()) <= 0) {
        X509_free(certificate);
        certificate = NULL;
    }
    ASN1_INTEGER_free(serial);
    BN_free(serial_number);
    OPENSSL_cleanse(serial_bytes, sizeof(serial_bytes));
    return certificate;
}

static int certificate_time(const ASN1_TIME *value, int64_t *out)
{
    struct tm time_value;

    if (!value || !out || ASN1_TIME_to_tm(value, &time_value) != 1)
        return -1;
#if defined(__APPLE__) || defined(__GLIBC__)
    *out = (int64_t)timegm(&time_value);
#else
    *out = (int64_t)mktime(&time_value);
#endif
    return *out > 0 ? 0 : -1;
}

static int certificate_describe(X509 *certificate, struct aegisxd_ca_record *record)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_length = 0;
    BIGNUM *serial_number = NULL;
    char *serial_hex = NULL;
    char *subject = NULL;
    size_t i;

    if (!certificate || !record || X509_check_ca(certificate) <= 0 ||
        X509_digest(certificate, EVP_sha256(), digest, &digest_length) != 1 ||
        digest_length != sizeof(digest) ||
        !(serial_number = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), NULL)) ||
        !(serial_hex = BN_bn2hex(serial_number)) ||
        !(subject = X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0)) ||
        certificate_time(X509_get0_notBefore(certificate), &record->not_before) != 0 ||
        certificate_time(X509_get0_notAfter(certificate), &record->not_after) != 0)
        goto failed;
    snprintf(record->subject, sizeof(record->subject), "%s", subject);
    snprintf(record->serial, sizeof(record->serial), "%s", serial_hex);
    snprintf(record->fingerprint, sizeof(record->fingerprint), "sha256:");
    for (i = 0; i < sizeof(digest); i++)
        snprintf(record->fingerprint + 7 + i * 2,
                 sizeof(record->fingerprint) - 7 - i * 2, "%02x", digest[i]);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_free(subject);
    OPENSSL_free(serial_hex);
    BN_free(serial_number);
    return 0;
failed:
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_free(subject);
    OPENSSL_free(serial_hex);
    BN_free(serial_number);
    return -1;
}

static int certificate_record_load(struct aegisxd_ca_record *record)
{
    sqlite3_stmt *statement;
    int rc;

    if (!record)
        return -1;
    memset(record, 0, sizeof(*record));
    snprintf(record->state, sizeof(record->state), "absent");
    statement = aegisxd_config_prepare(
        "SELECT generation,state,subject,serial,fingerprint_sha256,not_before,not_after,"
        "created_at,rotated_at,revoked_at FROM aegis_inspection_ca WHERE id=1");
    if (!statement)
        return -1;
    rc = sqlite3_step(statement);
    if (rc == SQLITE_ROW) {
        record->generation = sqlite3_column_int(statement, 0);
        snprintf(record->state, sizeof(record->state), "%s",
                 aegisxd_sqlite_text(statement, 1, "absent"));
        snprintf(record->subject, sizeof(record->subject), "%s",
                 aegisxd_sqlite_text(statement, 2, ""));
        snprintf(record->serial, sizeof(record->serial), "%s",
                 aegisxd_sqlite_text(statement, 3, ""));
        snprintf(record->fingerprint, sizeof(record->fingerprint), "%s",
                 aegisxd_sqlite_text(statement, 4, ""));
        record->not_before = sqlite3_column_int64(statement, 5);
        record->not_after = sqlite3_column_int64(statement, 6);
        record->created_at = sqlite3_column_int64(statement, 7);
        record->rotated_at = sqlite3_column_int64(statement, 8);
        record->revoked_at = sqlite3_column_int64(statement, 9);
    }
    sqlite3_finalize(statement);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int certificate_files_valid(const struct aegisxd_ca_record *record,
                                   int require_key)
{
    char key_path[AEGISXD_MAX_PATH];
    char cert_path[AEGISXD_MAX_PATH];
    BIO *bio = NULL;
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    struct stat status;
    int valid = 0;

    if (!record || record->generation <= 0 ||
        certificate_paths(record->generation, key_path, sizeof(key_path),
                          cert_path, sizeof(cert_path)) != 0 ||
        lstat(cert_path, &status) != 0 || !S_ISREG(status.st_mode) ||
        S_ISLNK(status.st_mode) || !(bio = BIO_new_file(cert_path, "r")) ||
        !(certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL)) ||
        X509_check_ca(certificate) <= 0)
        goto done;
    BIO_free(bio);
    bio = NULL;
    if (!require_key) {
        valid = 1;
        goto done;
    }
    if (lstat(key_path, &status) != 0 || !S_ISREG(status.st_mode) ||
        S_ISLNK(status.st_mode) || (status.st_mode & 077) != 0 ||
        !(bio = BIO_new_file(key_path, "r")) ||
        !(key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) ||
        X509_check_private_key(certificate, key) != 1)
        goto done;
    valid = 1;
done:
    BIO_free(bio);
    EVP_PKEY_free(key);
    X509_free(certificate);
    return valid;
}

static int certificate_key_generation(const char *name)
{
    int generation = 0;
    char tail;

    if (!name || sscanf(name, "inspection-ca-%d.key.pem%c", &generation, &tail) != 1)
        return 0;
    return generation > 0 ? generation : 0;
}

static int certificate_private_key_cleanup_pending(const struct aegisxd_ca_record *record)
{
    DIR *directory;
    struct dirent *entry;
    int pending = 0;

    directory = opendir(AEGISXD_PKI_DIR);
    if (!directory)
        return 0;
    while ((entry = readdir(directory)) != NULL) {
        int generation = certificate_key_generation(entry->d_name);

        if (generation > 0 &&
            (!record || strcmp(record->state, "active") || generation != record->generation)) {
            pending = 1;
            break;
        }
    }
    closedir(directory);
    return pending;
}

static int certificate_cleanup_obsolete_private_keys(const struct aegisxd_ca_record *record)
{
    DIR *directory;
    struct dirent *entry;
    int removed = 0;
    int rc = 0;

    if (certificate_test_fail("after-db-commit-before-key-cleanup")) {
        errno = EIO;
        return -1;
    }
    directory = opendir(AEGISXD_PKI_DIR);
    if (!directory)
        return errno == ENOENT ? 0 : -1;
    while ((entry = readdir(directory)) != NULL) {
        char path[AEGISXD_MAX_PATH];
        int generation = certificate_key_generation(entry->d_name);

        if (generation <= 0 ||
            (record && !strcmp(record->state, "active") && generation == record->generation))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", AEGISXD_PKI_DIR,
                     entry->d_name) >= (int)sizeof(path) || unlink(path) != 0) {
            if (errno != ENOENT)
                rc = -1;
            continue;
        }
        removed = 1;
    }
    closedir(directory);
    if (removed && certificate_sync_directory() != 0)
        rc = -1;
    return rc;
}

static int certificate_reconcile_private_keys(struct aegisxd_ca_record *record)
{
    int lockfd;
    int rc;

    lockfd = certificate_lock();
    if (lockfd < 0)
        return -1;
    if (certificate_record_load(record) != 0) {
        certificate_unlock(lockfd);
        return -1;
    }
    rc = certificate_cleanup_obsolete_private_keys(record);
    certificate_unlock(lockfd);
    return rc;
}

static int certificate_commit(void)
{
    if (certificate_test_fail("before-db-commit")) {
        errno = EIO;
        return -1;
    }
    return sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static int certificate_transition_distributions(int generation, const char *state,
                                                const char *reason, int64_t now)
{
    sqlite3_stmt *statement;
    int rc;

    statement = aegisxd_config_prepare(
        "UPDATE aegis_certificate_distributions SET state=?1,reason=?2,updated_at=?3 "
        "WHERE ca_generation=?4 AND state IN ('ready_for_download','downloaded')");
    if (!statement)
        return -1;
    sqlite3_bind_text(statement, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 3, now);
    sqlite3_bind_int(statement, 4, generation);
    rc = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return rc;
}

static struct json_object *certificate_record_json(const struct aegisxd_ca_record *record)
{
    struct json_object *object = json_object_new_object();
    int active = record && !strcmp(record->state, "active") &&
                 certificate_files_valid(record, 1);

    json_object_object_add(object, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(object, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(object, "certificate_type", "inspection_root_ca");
    aegisxd_json_add_string(object, "trust_domain", "aegisx_ssl_inspection");
    json_object_object_add(object, "present",
                           json_object_new_boolean(record && record->generation > 0));
    json_object_object_add(object, "active", json_object_new_boolean(active));
    json_object_object_add(object, "generation",
                           json_object_new_int(record ? record->generation : 0));
    aegisxd_json_add_string(object, "state", record ? record->state : "absent");
    aegisxd_json_add_string(object, "subject", record ? record->subject : "");
    aegisxd_json_add_string(object, "serial", record ? record->serial : "");
    aegisxd_json_add_string(object, "fingerprint_sha256",
                            record ? record->fingerprint : "");
    json_object_object_add(object, "not_before",
                           json_object_new_int64(record ? record->not_before : 0));
    json_object_object_add(object, "not_after",
                           json_object_new_int64(record ? record->not_after : 0));
    json_object_object_add(object, "created_at",
                           json_object_new_int64(record ? record->created_at : 0));
    json_object_object_add(object, "rotated_at",
                           json_object_new_int64(record ? record->rotated_at : 0));
    json_object_object_add(object, "revoked_at",
                           json_object_new_int64(record ? record->revoked_at : 0));
    json_object_object_add(object, "private_key_exportable", json_object_new_boolean(0));
    json_object_object_add(object, "private_key_cleanup_pending",
                           json_object_new_boolean(
                               certificate_private_key_cleanup_pending(record)));
    json_object_object_add(object, "download_supported", json_object_new_boolean(active));
    json_object_object_add(object, "manual_distribution_supported", json_object_new_boolean(1));
    json_object_object_add(object, "automatic_distribution_supported", json_object_new_boolean(0));
    aegisxd_json_add_string(object, "automatic_distribution_reason",
                            "trusted_terminal_certificate_agent_missing");
    json_object_object_add(object, "ssl_inspection_active", json_object_new_boolean(0));
    aegisxd_json_add_string(object, "ssl_inspection_reason",
                            "inspection_dataplane_not_implemented");
    if (record && !strcmp(record->state, "active") && !active)
        aegisxd_json_add_string(object, "runtime_error", "inspection_ca_material_invalid");
    return object;
}

struct json_object *aegisxd_certificate_status_json(void)
{
    struct aegisxd_ca_record record;

    if (certificate_record_load(&record) != 0)
        return aegisxd_error("certificate_state_unavailable",
                             "inspection CA state could not be read");
    (void)certificate_reconcile_private_keys(&record);
    return certificate_record_json(&record);
}

static struct json_object *certificate_generate(struct json_object *body, int rotate)
{
    struct aegisxd_ca_record current;
    struct aegisxd_ca_record locked;
    struct aegisxd_ca_record next;
    const char *common_name = aegisxd_json_str(body, "common_name",
                                               "DreamingOS AegisX Inspection CA");
    int validity_days = certificate_json_int(body, "validity_days",
                                             AEGISXD_CA_DEFAULT_DAYS);
    int expected_generation = certificate_json_int(body, "expected_generation", -1);
    int generation;
    int lockfd = -1;
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    sqlite3_stmt *statement = NULL;
    char key_path[AEGISXD_MAX_PATH] = "";
    char cert_path[AEGISXD_MAX_PATH] = "";
    int64_t now = aegisxd_now_s();
    int rc = -1;
    int transaction_started = 0;
    int committed = 0;

    if (!aegisxd_json_bool(body, "confirm", 0))
        return aegisxd_error("confirmation_required", "confirm=true is required");
    if (!certificate_text_ok(common_name, 96, 0))
        return aegisxd_error("invalid_common_name", "common_name is invalid");
    if (validity_days < AEGISXD_CA_MIN_DAYS || validity_days > AEGISXD_CA_MAX_DAYS)
        return aegisxd_error("invalid_validity_days", "validity_days must be between 365 and 7300");
    if (certificate_record_load(&current) != 0)
        return aegisxd_error("certificate_state_unavailable", "inspection CA state could not be read");
    if (!rotate && !strcmp(current.state, "active"))
        return aegisxd_error("inspection_ca_already_active", "use rotate for an active inspection CA");
    if (rotate && strcmp(current.state, "active"))
        return aegisxd_error("inspection_ca_not_active", "an active inspection CA is required for rotation");
    if (rotate && expected_generation != current.generation)
        return aegisxd_error("certificate_generation_conflict", "expected_generation does not match active CA");

    lockfd = certificate_lock();
    if (lockfd < 0)
        goto done;
    if (certificate_record_load(&locked) != 0 ||
        locked.generation != current.generation || strcmp(locked.state, current.state)) {
        certificate_unlock(lockfd);
        return aegisxd_error("certificate_generation_conflict",
                             "inspection CA changed while this operation was waiting");
    }
    generation = locked.generation + 1;
    if (certificate_paths(generation, key_path, sizeof(key_path),
                                       cert_path, sizeof(cert_path)) != 0 ||
        !(key = certificate_key_generate()) ||
        !(certificate = certificate_ca_generate(key, common_name, validity_days)))
        goto done;
    memset(&next, 0, sizeof(next));
    next.generation = generation;
    snprintf(next.state, sizeof(next.state), "active");
    next.created_at = rotate ? current.created_at : now;
    next.rotated_at = rotate ? now : 0;
    if (certificate_describe(certificate, &next) != 0 ||
        certificate_atomic_write(key_path, 0600, certificate_write_key, key) != 0 ||
        certificate_atomic_write(cert_path, 0644, certificate_write_x509, certificate) != 0)
        goto done;
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    transaction_started = 1;
    statement = aegisxd_config_prepare(
        "UPDATE aegis_inspection_ca SET generation=?1,state='active',subject=?2,serial=?3,"
        "fingerprint_sha256=?4,not_before=?5,not_after=?6,created_at=?7,rotated_at=?8,"
        "revoked_at=0,updated_at=?9 WHERE id=1 AND generation=?10");
    if (!statement)
        goto done;
    sqlite3_bind_int(statement, 1, next.generation);
    sqlite3_bind_text(statement, 2, next.subject, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, next.serial, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, next.fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 5, next.not_before);
    sqlite3_bind_int64(statement, 6, next.not_after);
    sqlite3_bind_int64(statement, 7, next.created_at);
    sqlite3_bind_int64(statement, 8, next.rotated_at);
    sqlite3_bind_int64(statement, 9, now);
    sqlite3_bind_int(statement, 10, current.generation);
    if (sqlite3_step(statement) != SQLITE_DONE || sqlite3_changes(g_aegisxd_config_db) != 1)
        goto done;
    sqlite3_finalize(statement);
    statement = NULL;
    if (rotate && certificate_transition_distributions(
            current.generation, "superseded", "ca_rotated", now) != 0)
        goto done;
    if (certificate_commit() != 0)
        goto done;
    committed = 1;
    transaction_started = 0;
    rc = 0;
    if (certificate_cleanup_obsolete_private_keys(&next) != 0)
        fprintf(stderr, "[dreamingwrt-aegisxd] obsolete inspection CA key cleanup pending: %s\n",
                strerror(errno));
done:
    sqlite3_finalize(statement);
    if (transaction_started)
        (void)sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    if (rc != 0 && !committed) {
        if (key_path[0])
            (void)certificate_unlink_durable(key_path);
        if (cert_path[0])
            (void)certificate_unlink_durable(cert_path);
    }
    X509_free(certificate);
    EVP_PKEY_free(key);
    certificate_unlock(lockfd);
    if (rc != 0)
        return aegisxd_error("inspection_ca_generation_failed",
                             "inspection CA material could not be committed");
    return certificate_record_json(&next);
}

struct json_object *aegisxd_certificate_generate_json(struct json_object *body)
{
    return certificate_generate(body, 0);
}

struct json_object *aegisxd_certificate_rotate_json(struct json_object *body)
{
    return certificate_generate(body, 1);
}

struct json_object *aegisxd_certificate_revoke_json(struct json_object *body)
{
    struct aegisxd_ca_record record;
    struct aegisxd_ca_record locked;
    sqlite3_stmt *statement = NULL;
    char key_path[AEGISXD_MAX_PATH];
    char cert_path[AEGISXD_MAX_PATH];
    int expected_generation = certificate_json_int(body, "expected_generation", -1);
    int lockfd = -1;
    int64_t now = aegisxd_now_s();
    int transaction_started = 0;

    if (!aegisxd_json_bool(body, "confirm", 0))
        return aegisxd_error("confirmation_required", "confirm=true is required");
    if (certificate_record_load(&record) != 0 || strcmp(record.state, "active"))
        return aegisxd_error("inspection_ca_not_active", "an active inspection CA is required");
    if (expected_generation != record.generation)
        return aegisxd_error("certificate_generation_conflict", "expected_generation does not match active CA");
    if ((lockfd = certificate_lock()) < 0 ||
        certificate_paths(record.generation, key_path, sizeof(key_path),
                          cert_path, sizeof(cert_path)) != 0)
        goto failed;
    if (certificate_record_load(&locked) != 0 ||
        locked.generation != record.generation || strcmp(locked.state, "active"))
        goto conflict;
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        goto failed;
    transaction_started = 1;
    statement = aegisxd_config_prepare(
        "UPDATE aegis_inspection_ca SET state='revoked',revoked_at=?1,updated_at=?1 "
        "WHERE id=1 AND generation=?2 AND state='active'");
    if (!statement)
        goto failed;
    sqlite3_bind_int64(statement, 1, now);
    sqlite3_bind_int(statement, 2, record.generation);
    if (sqlite3_step(statement) != SQLITE_DONE || sqlite3_changes(g_aegisxd_config_db) != 1)
        goto failed;
    sqlite3_finalize(statement);
    statement = NULL;
    if (certificate_transition_distributions(
            record.generation, "ca_revoked", "ca_revoked", now) != 0 ||
        certificate_commit() != 0)
        goto failed;
    transaction_started = 0;
    snprintf(record.state, sizeof(record.state), "revoked");
    record.revoked_at = now;
    if (certificate_cleanup_obsolete_private_keys(&record) != 0)
        fprintf(stderr, "[dreamingwrt-aegisxd] revoked inspection CA key cleanup pending: %s\n",
                strerror(errno));
    sqlite3_finalize(statement);
    certificate_unlock(lockfd);
    return certificate_record_json(&record);
failed:
    if (transaction_started)
        (void)sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_finalize(statement);
    certificate_unlock(lockfd);
    return aegisxd_error("inspection_ca_revoke_failed", "inspection CA could not be revoked");
conflict:
    certificate_unlock(lockfd);
    return aegisxd_error("certificate_generation_conflict",
                         "inspection CA changed while this operation was waiting");
}

static int certificate_read_file(const char *path, unsigned char **out, size_t *out_length)
{
    struct stat status;
    unsigned char *data = NULL;
    size_t offset = 0;
    int fd = -1;

    if (!path || !out || !out_length || lstat(path, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) || status.st_size <= 0 ||
        status.st_size > AEGISXD_CA_MAX_PEM ||
        (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        !(data = malloc((size_t)status.st_size + 1)))
        goto failed;
    while (offset < (size_t)status.st_size) {
        ssize_t count = read(fd, data + offset, (size_t)status.st_size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto failed;
        offset += (size_t)count;
    }
    data[offset] = '\0';
    close(fd);
    *out = data;
    *out_length = offset;
    return 0;
failed:
    if (fd >= 0)
        close(fd);
    free(data);
    return -1;
}

static char *certificate_base64(const unsigned char *data, size_t length)
{
    size_t capacity = 4 * ((length + 2) / 3) + 1;
    unsigned char *encoded;

    if (!data || !length || length > INT_MAX || !(encoded = malloc(capacity)))
        return NULL;
    if (EVP_EncodeBlock(encoded, data, (int)length) <= 0) {
        free(encoded);
        return NULL;
    }
    return (char *)encoded;
}

static struct json_object *certificate_distribution_download_validate(
    const char *distribution_id, int active_generation)
{
    sqlite3_stmt *statement;
    const char *state;
    int generation;

    if (!distribution_id || !distribution_id[0])
        return NULL;
    if (!certificate_uuid_ok(distribution_id))
        return aegisxd_error("invalid_certificate_distribution_id",
                             "distribution_id is invalid");
    statement = aegisxd_config_prepare(
        "SELECT ca_generation,state FROM aegis_certificate_distributions "
        "WHERE distribution_id=?1");
    if (!statement)
        return aegisxd_error("certificate_distribution_state_unavailable",
                             "certificate distribution could not be read");
    sqlite3_bind_text(statement, 1, distribution_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_not_found",
                             "certificate distribution does not exist");
    }
    generation = sqlite3_column_int(statement, 0);
    state = aegisxd_sqlite_text(statement, 1, "");
    if (!strcmp(state, "ca_revoked")) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_ca_revoked",
                             "certificate distribution CA was revoked");
    }
    if (!strcmp(state, "superseded") || generation != active_generation) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_superseded",
                             "certificate distribution belongs to a superseded CA");
    }
    if (strcmp(state, "ready_for_download") && strcmp(state, "downloaded")) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_not_downloadable",
                             "certificate distribution is not downloadable");
    }
    sqlite3_finalize(statement);
    return NULL;
}

struct json_object *aegisxd_certificate_download_json(struct json_object *body)
{
    struct aegisxd_ca_record record;
    const char *format = aegisxd_json_str(body, "format", "pem");
    const char *distribution_id = aegisxd_json_str(body, "distribution_id", "");
    char key_path[AEGISXD_MAX_PATH];
    char cert_path[AEGISXD_MAX_PATH];
    unsigned char *pem = NULL;
    unsigned char *content = NULL;
    size_t pem_length = 0;
    size_t content_length = 0;
    char *encoded = NULL;
    X509 *certificate = NULL;
    BIO *bio = NULL;
    const unsigned char *cursor;
    struct json_object *response;
    struct json_object *distribution_error;

    if (strcmp(format, "pem") && strcmp(format, "der"))
        return aegisxd_error("invalid_certificate_format", "format must be pem or der");
    if (certificate_record_load(&record) != 0)
        return aegisxd_error("certificate_state_unavailable",
                             "inspection CA state could not be read");
    distribution_error = certificate_distribution_download_validate(
        distribution_id, record.generation);
    if (distribution_error)
        return distribution_error;
    if (strcmp(record.state, "active") || !certificate_files_valid(&record, 1))
        return aegisxd_error("inspection_ca_not_active", "an active inspection CA is required");
    if (certificate_paths(record.generation, key_path, sizeof(key_path),
                          cert_path, sizeof(cert_path)) != 0 ||
        certificate_read_file(cert_path, &pem, &pem_length) != 0)
        return aegisxd_error("inspection_ca_material_invalid", "inspection CA certificate is unavailable");
    if (!strcmp(format, "pem")) {
        content = pem;
        content_length = pem_length;
        pem = NULL;
    } else {
        bio = BIO_new_mem_buf(pem, (int)pem_length);
        certificate = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
        if (certificate) {
            int length = i2d_X509(certificate, NULL);
            unsigned char *write_cursor;
            if (length > 0 && (content = malloc((size_t)length))) {
                write_cursor = content;
                if (i2d_X509(certificate, &write_cursor) == length)
                    content_length = (size_t)length;
            }
        }
    }
    cursor = content;
    if (!cursor || !content_length || !(encoded = certificate_base64(content, content_length))) {
        free(pem); free(content); BIO_free(bio); X509_free(certificate);
        return aegisxd_error("inspection_ca_encode_failed", "inspection CA download could not be encoded");
    }
    response = json_object_new_object();
    json_object_object_add(response, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(response, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(response, "format", format);
    aegisxd_json_add_string(response, "content_type",
                            !strcmp(format, "pem") ? "application/x-pem-file" :
                                                     "application/pkix-cert");
    aegisxd_json_add_string(response, "filename",
                            !strcmp(format, "pem") ? "dreamingos-aegisx-inspection-ca.pem" :
                                                     "dreamingos-aegisx-inspection-ca.der");
    aegisxd_json_add_string(response, "fingerprint_sha256", record.fingerprint);
    json_object_object_add(response, "generation", json_object_new_int(record.generation));
    json_object_object_add(response, "content_length", json_object_new_int64(content_length));
    aegisxd_json_add_string(response, "content_base64", encoded);
    json_object_object_add(response, "private_key_included", json_object_new_boolean(0));
    if (distribution_id[0])
        aegisxd_json_add_string(response, "distribution_id", distribution_id);
    free(pem); free(content); free(encoded); BIO_free(bio); X509_free(certificate);
    return response;
}

struct json_object *aegisxd_certificate_distribution_downloaded_json(struct json_object *body)
{
    const char *distribution_id = aegisxd_json_str(body, "distribution_id", "");
    int generation = certificate_json_int(body, "ca_generation", -1);
    sqlite3_stmt *statement;
    struct json_object *response;

    if (!certificate_uuid_ok(distribution_id) || generation <= 0)
        return aegisxd_error("invalid_certificate_distribution_id",
                             "distribution_id and ca_generation are required");
    statement = aegisxd_config_prepare(
        "UPDATE aegis_certificate_distributions SET state='downloaded',downloaded_at=?1,"
        "updated_at=?1 WHERE distribution_id=?2 AND ca_generation=?3 "
        "AND state IN ('ready_for_download','downloaded')");
    if (!statement)
        return aegisxd_error("certificate_distribution_state_unavailable",
                             "certificate distribution could not be updated");
    sqlite3_bind_int64(statement, 1, aegisxd_now_s());
    sqlite3_bind_text(statement, 2, distribution_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, generation);
    if (sqlite3_step(statement) != SQLITE_DONE ||
        sqlite3_changes(g_aegisxd_config_db) != 1) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_not_found",
                             "certificate distribution does not exist for this CA");
    }
    sqlite3_finalize(statement);
    response = aegisxd_certificate_distribution_get_json(body);
    return response;
}

static struct json_object *certificate_distribution_row(sqlite3_stmt *statement)
{
    struct json_object *object = json_object_new_object();

    aegisxd_json_add_string(object, "distribution_id", aegisxd_sqlite_text(statement, 0, ""));
    json_object_object_add(object, "ca_generation", json_object_new_int(sqlite3_column_int(statement, 1)));
    aegisxd_json_add_string(object, "target_type", aegisxd_sqlite_text(statement, 2, ""));
    aegisxd_json_add_string(object, "target_id", aegisxd_sqlite_text(statement, 3, ""));
    aegisxd_json_add_string(object, "method", aegisxd_sqlite_text(statement, 4, "manual"));
    aegisxd_json_add_string(object, "state", aegisxd_sqlite_text(statement, 5, ""));
    aegisxd_json_add_string(object, "reason", aegisxd_sqlite_text(statement, 6, ""));
    json_object_object_add(object, "created_at", json_object_new_int64(sqlite3_column_int64(statement, 7)));
    json_object_object_add(object, "downloaded_at", json_object_new_int64(sqlite3_column_int64(statement, 8)));
    json_object_object_add(object, "installed", json_object_new_boolean(0));
    json_object_object_add(object, "installation_readback_supported", json_object_new_boolean(0));
    return object;
}

struct json_object *aegisxd_certificate_distributions_json(struct json_object *body)
{
    sqlite3_stmt *statement = aegisxd_config_prepare(
        "SELECT distribution_id,ca_generation,target_type,target_id,method,state,reason,"
        "created_at,downloaded_at FROM aegis_certificate_distributions ORDER BY created_at DESC LIMIT 200");
    struct json_object *response;
    struct json_object *items;

    (void)body;
    if (!statement)
        return aegisxd_error("certificate_distribution_state_unavailable",
                             "certificate distributions could not be read");
    response = json_object_new_object();
    items = json_object_new_array();
    while (sqlite3_step(statement) == SQLITE_ROW)
        json_object_array_add(items, certificate_distribution_row(statement));
    sqlite3_finalize(statement);
    json_object_object_add(response, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(response, "service", "dreamingwrt-aegisxd");
    json_object_object_add(response, "items", items);
    json_object_object_add(response, "total", json_object_new_int((int)json_object_array_length(items)));
    json_object_object_add(response, "automatic_distribution_supported", json_object_new_boolean(0));
    aegisxd_json_add_string(response, "automatic_distribution_reason",
                            "trusted_terminal_certificate_agent_missing");
    return response;
}

struct json_object *aegisxd_certificate_distribution_create_json(struct json_object *body)
{
    struct aegisxd_ca_record record;
    const char *target_type = aegisxd_json_str(body, "target_type", "client");
    const char *target_id = aegisxd_json_str(body, "target_id", "");
    const char *method = aegisxd_json_str(body, "method", "manual");
    char distribution_id[37];
    sqlite3_stmt *statement;
    int64_t now = aegisxd_now_s();
    struct json_object *query;
    struct json_object *response;
    char normalized_mac[18];

    if (strcmp(method, "manual"))
        return aegisxd_error("automatic_distribution_unavailable",
                             "a trusted terminal certificate agent is not available");
    if (strcmp(target_type, "client"))
        return aegisxd_error("invalid_distribution_target_type",
                             "only known client terminals are supported");
    if (certificate_mac_normalize(target_id, normalized_mac) != 0)
        return aegisxd_error("invalid_distribution_target",
                             "target_id must be a client MAC address");
    if (!certificate_client_known(normalized_mac))
        return aegisxd_error("certificate_distribution_target_not_found",
                             "target client does not exist in the device database");
    if (certificate_record_load(&record) != 0 || strcmp(record.state, "active") ||
        !certificate_files_valid(&record, 1))
        return aegisxd_error("inspection_ca_not_active", "an active inspection CA is required");
    if (certificate_id(distribution_id) != 0)
        return aegisxd_error("certificate_distribution_create_failed",
                             "distribution identifier could not be generated");
    statement = aegisxd_config_prepare(
        "INSERT INTO aegis_certificate_distributions(distribution_id,ca_generation,target_type,"
        "target_id,method,state,reason,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,'manual','ready_for_download','manual_installation_required',?5,?5)");
    if (!statement)
        return aegisxd_error("certificate_distribution_create_failed",
                             "distribution could not be persisted");
    sqlite3_bind_text(statement, 1, distribution_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, record.generation);
    sqlite3_bind_text(statement, 3, target_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, normalized_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 5, now);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_create_failed",
                             "distribution could not be persisted");
    }
    sqlite3_finalize(statement);
    query = json_object_new_object();
    aegisxd_json_add_string(query, "distribution_id", distribution_id);
    response = aegisxd_certificate_distribution_get_json(query);
    json_object_put(query);
    return response;
}

struct json_object *aegisxd_certificate_distribution_get_json(struct json_object *body)
{
    const char *distribution_id = aegisxd_json_str(body, "distribution_id", "");
    sqlite3_stmt *statement;
    struct json_object *response;

    if (!certificate_uuid_ok(distribution_id))
        return aegisxd_error("invalid_certificate_distribution_id",
                             "distribution_id is invalid");
    statement = aegisxd_config_prepare(
        "SELECT distribution_id,ca_generation,target_type,target_id,method,state,reason,"
        "created_at,downloaded_at FROM aegis_certificate_distributions WHERE distribution_id=?1");
    if (!statement)
        return aegisxd_error("certificate_distribution_state_unavailable",
                             "certificate distribution could not be read");
    sqlite3_bind_text(statement, 1, distribution_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return aegisxd_error("certificate_distribution_not_found",
                             "certificate distribution does not exist");
    }
    response = certificate_distribution_row(statement);
    json_object_object_add(response, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(response, "service", "dreamingwrt-aegisxd");
    sqlite3_finalize(statement);
    return response;
}
