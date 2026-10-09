// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ac_secret_rotation.h"

#include "ac_internal.h"
#include "../ap_control_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AC_SECRET_ROTATION_FRAME_MAX 4096U
#define AC_SECRET_ROTATION_KEY_PATH "/etc/dreamingwrt/ac-secret-rotation.key"
#define AC_SECRET_ROTATION_TTL_SECONDS 60
#define AC_SECRET_ROTATION_IDEMPOTENCY_MAX 128U
#define AC_SECRET_ROTATION_ACTOR_MAX 128U
#define AC_SECRET_ROTATION_SSID_MAX 64U
#define AC_SECRET_ROTATION_SECTION_MAX 32U

struct ac_secret_pending {
    char job_id[37];
    char ap_id[37];
    char ssid_id[AC_SECRET_ROTATION_SSID_MAX + 1];
    char actor_id[AC_SECRET_ROTATION_ACTOR_MAX + 1];
    char idempotency_key[AC_SECRET_ROTATION_IDEMPOTENCY_MAX + 1];
    char request_digest[77];
    int64_t base_revision;
    int64_t secret_version;
    int64_t created_at;
    char sections[AC_SECRET_ROTATION_MAX_SECTIONS]
                 [AC_SECRET_ROTATION_SECTION_MAX + 1];
    size_t section_count;
    unsigned char *secret;
    size_t secret_len;
    int offered;
    int prepared;
    struct ac_secret_pending *next;
};

struct ac_secret_runtime {
    pthread_mutex_t lock;
    pthread_t thread;
    int thread_started;
    int stopping;
    int listen_fd;
    unsigned char hmac_key[32];
    char capable_aps[32][37];
    size_t capable_count;
    struct ac_secret_pending *pending;
};

static struct ac_secret_runtime g_secret_rotation = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .listen_fd = -1,
};

static void ac_secret_db_enter(void)
{
    if (g_ac_db)
        sqlite3_mutex_enter(sqlite3_db_mutex(g_ac_db));
}

static void ac_secret_db_leave(void)
{
    if (g_ac_db)
        sqlite3_mutex_leave(sqlite3_db_mutex(g_ac_db));
}

static int ac_secret_write_full(int fd, const void *data, size_t len)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, bytes + offset, len - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int ac_secret_read_full(int fd, void *data, size_t len)
{
    unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < len) {
        ssize_t got = read(fd, bytes + offset, len - offset);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return -1;
        offset += (size_t)got;
    }
    return 0;
}

static int ac_secret_send_json(int fd, struct json_object *object)
{
    const char *text;
    size_t len;
    unsigned char header[4];

    if (!object || !(text = json_object_to_json_string_ext(
                         object, JSON_C_TO_STRING_PLAIN)) ||
        (len = strlen(text)) == 0 || len > AC_SECRET_ROTATION_FRAME_MAX)
        return -1;
    header[0] = (unsigned char)(len >> 24);
    header[1] = (unsigned char)(len >> 16);
    header[2] = (unsigned char)(len >> 8);
    header[3] = (unsigned char)len;
    return ac_secret_write_full(fd, header, sizeof(header)) == 0 &&
           ac_secret_write_full(fd, text, len) == 0 ? 0 : -1;
}

static int ac_secret_recv_json(int fd, struct json_object **out)
{
    unsigned char header[4];
    unsigned char *payload = NULL;
    size_t len;
    int rc = -1;

    if (!out)
        return -1;
    *out = NULL;
    if (ac_secret_read_full(fd, header, sizeof(header)) != 0)
        return -1;
    len = ((size_t)header[0] << 24) | ((size_t)header[1] << 16) |
          ((size_t)header[2] << 8) | header[3];
    if (len == 0 || len > AC_SECRET_ROTATION_FRAME_MAX ||
        !(payload = OPENSSL_malloc(len)))
        return -1;
    if (ac_secret_read_full(fd, payload, len) == 0 &&
        ap_control_json_parse_strict(payload, len, out) == AP_CONTROL_WIRE_OK)
        rc = 0;
    OPENSSL_cleanse(payload, len);
    OPENSSL_free(payload);
    return rc;
}

static int ac_secret_text_valid(const char *value, size_t minimum,
                                size_t maximum)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len < minimum || len > maximum)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c < 0x21 || c > 0x7e)
            return 0;
    }
    return 1;
}

static int ac_secret_ssid_id_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > AC_SECRET_ROTATION_SSID_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-'))
            return 0;
    }
    return 1;
}

static int ac_secret_value_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;
    int hex = len == AC_SECRET_ROTATION_SECRET_MAX;

    if (!value || len < 8 || len > AC_SECRET_ROTATION_SECRET_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c < 0x20 || c > 0x7e || c == '\'' || c == '"' || c == '\\')
            return 0;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            hex = 0;
    }
    return len < AC_SECRET_ROTATION_SECRET_MAX || hex;
}

static int ac_secret_uuid4_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 36 || value[14] != '4' ||
        !(value[19] == '8' || value[19] == '9' || value[19] == 'a' ||
          value[19] == 'b'))
        return 0;
    for (i = 0; i < 36; i++) {
        unsigned char c = (unsigned char)value[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return 0;
        } else if (!((c >= '0' && c <= '9') ||
                     (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static int ac_secret_digest_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 76 ||
        strncmp(value, "hmac-sha256:", 12))
        return 0;
    for (i = 12; i < 76; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

int ac_secret_rotation_ssid_busy(const char *ssid_id)
{
    sqlite3_stmt *st = NULL;
    int step;

    if (!g_ac_db || !ac_secret_ssid_id_valid(ssid_id) ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_secret_rotation_jobs WHERE ssid_id=?1 "
            "AND state IN ('queued','offered','prepared','running') LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    step = sqlite3_step(st);
    sqlite3_finalize(st);
    if (step == SQLITE_ROW)
        return 1;
    return step == SQLITE_DONE ? 0 : -1;
}

static int ac_secret_key_load(void)
{
    int fd = open(AC_SECRET_ROTATION_KEY_PATH,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    size_t offset = 0;

    if (fd >= 0) {
        if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
            status.st_uid != geteuid() || status.st_nlink != 1 ||
            (status.st_mode & 0077) != 0)
            goto fail;
        while (offset < sizeof(g_secret_rotation.hmac_key)) {
            ssize_t got = read(fd, g_secret_rotation.hmac_key + offset,
                               sizeof(g_secret_rotation.hmac_key) - offset);
            if (got < 0 && errno == EINTR)
                continue;
            if (got <= 0)
                goto fail;
            offset += (size_t)got;
        }
        close(fd);
        return 0;
    }
    if (errno != ENOENT || RAND_bytes(g_secret_rotation.hmac_key,
                                      sizeof(g_secret_rotation.hmac_key)) != 1)
        return -1;
    fd = open(AC_SECRET_ROTATION_KEY_PATH,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || ac_secret_write_full(fd, g_secret_rotation.hmac_key,
                                       sizeof(g_secret_rotation.hmac_key)) != 0 ||
        fsync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0)
            close(fd);
        unlink(AC_SECRET_ROTATION_KEY_PATH);
        OPENSSL_cleanse(g_secret_rotation.hmac_key,
                        sizeof(g_secret_rotation.hmac_key));
        return -1;
    }
    return 0;
fail:
    close(fd);
    OPENSSL_cleanse(g_secret_rotation.hmac_key,
                    sizeof(g_secret_rotation.hmac_key));
    return -1;
}

static int ac_secret_request_digest(const char *ap_id, const char *ssid_id,
                                    int64_t base_revision,
                                    const unsigned char *secret,
                                    size_t secret_len, char out[77])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
        g_secret_rotation.hmac_key, sizeof(g_secret_rotation.hmac_key));
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digest_len = sizeof(digest);
    unsigned char revision[8];
    unsigned int i;

    for (i = 0; i < sizeof(revision); i++)
        revision[sizeof(revision) - i - 1] =
            (unsigned char)((uint64_t)base_revision >> (i * 8U));
    if (!ctx || !key ||
        EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSignUpdate(ctx, ap_id, strlen(ap_id)) != 1 ||
        EVP_DigestSignUpdate(ctx, "\0", 1) != 1 ||
        EVP_DigestSignUpdate(ctx, ssid_id, strlen(ssid_id)) != 1 ||
        EVP_DigestSignUpdate(ctx, revision, sizeof(revision)) != 1 ||
        EVP_DigestSignUpdate(ctx, secret, secret_len) != 1 ||
        EVP_DigestSignFinal(ctx, digest, &digest_len) != 1 || digest_len != 32) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        OPENSSL_cleanse(digest, sizeof(digest));
        return -1;
    }
    memcpy(out, "hmac-sha256:", 12);
    for (i = 0; i < digest_len; i++)
        snprintf(out + 12 + i * 2, 3, "%02x", digest[i]);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int ac_secret_schema_init(void)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS ac_secret_rotation_jobs("
        "job_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL,ssid_id TEXT NOT NULL,"
        "actor_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,"
        "request_digest TEXT NOT NULL,base_revision INTEGER NOT NULL,"
        "secret_version INTEGER NOT NULL,state TEXT NOT NULL,"
        "error_code TEXT NOT NULL DEFAULT '',section_count INTEGER NOT NULL,"
        "secret_configured INTEGER NOT NULL DEFAULT 0,"
        "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_secret_rotation_idempotency "
        "ON ac_secret_rotation_jobs(actor_id,idempotency_key);";
    static const char recover[] =
        "UPDATE ac_secret_rotation_jobs SET state='failed',"
        "error_code='secret_material_lost_on_restart',"
        "updated_at=strftime('%s','now') "
        "WHERE state IN ('queued','offered','prepared','running');";
    static const char active_index[] =
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_secret_rotation_active_target "
        "ON ac_secret_rotation_jobs(ssid_id) "
        "WHERE state IN ('queued','offered','prepared','running');";

    sqlite3_stmt *st = NULL;
    int has_binding_digest = 0;
    int has_binding_present = 0;
    int has_binding_version = 0;
    int has_ssid_secret_version = 0;

    if (!g_ac_db || sqlite3_exec(g_ac_db, schema, NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db, "PRAGMA table_info(ac_ssid_bindings)",
                          -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);

        if (name && !strcmp(name, "secret_digest"))
            has_binding_digest = 1;
        else if (name && !strcmp(name, "secret_present"))
            has_binding_present = 1;
        else if (name && !strcmp(name, "secret_version"))
            has_binding_version = 1;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db, "PRAGMA table_info(ac_ssids)",
                          -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);

        if (name && !strcmp(name, "secret_version"))
            has_ssid_secret_version = 1;
    }
    sqlite3_finalize(st);
    if ((!has_binding_digest && sqlite3_exec(g_ac_db,
             "ALTER TABLE ac_ssid_bindings ADD COLUMN secret_digest "
             "TEXT NOT NULL DEFAULT ''", NULL, NULL, NULL) != SQLITE_OK) ||
        (!has_binding_present && sqlite3_exec(g_ac_db,
             "ALTER TABLE ac_ssid_bindings ADD COLUMN secret_present "
             "INTEGER NOT NULL DEFAULT 0", NULL, NULL, NULL) != SQLITE_OK) ||
        (!has_binding_version && sqlite3_exec(g_ac_db,
             "ALTER TABLE ac_ssid_bindings ADD COLUMN secret_version "
             "INTEGER NOT NULL DEFAULT 0", NULL, NULL, NULL) != SQLITE_OK) ||
        (!has_ssid_secret_version && sqlite3_exec(g_ac_db,
             "ALTER TABLE ac_ssids ADD COLUMN secret_version "
             "INTEGER NOT NULL DEFAULT 0", NULL, NULL, NULL) != SQLITE_OK))
        return -1;
    return sqlite3_exec(g_ac_db, recover, NULL, NULL, NULL) == SQLITE_OK &&
           sqlite3_exec(g_ac_db, active_index, NULL, NULL, NULL) == SQLITE_OK ?
           0 : -1;
}

static struct json_object *ac_secret_error(const char *code,
                                            const char *reason)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string(code));
    json_object_object_add(root, "reason", json_object_new_string(reason));
    return root;
}

static struct json_object *ac_secret_status(const char *job_id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *root;

    if (!job_id)
        return ac_secret_error("database_error", "secret_job_status_failed");
    ac_secret_db_enter();
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,ssid_id,state,error_code,base_revision,secret_version,"
            "section_count,secret_configured,created_at,updated_at "
            "FROM ac_secret_rotation_jobs WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK) {
        ac_secret_db_leave();
        return ac_secret_error("database_error", "secret_job_status_failed");
    }
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        ac_secret_db_leave();
        return ac_secret_error("not_found", "secret_rotation_job_not_found");
    }
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "job_id", json_object_new_string(job_id));
    json_object_object_add(root, "ap_id", json_object_new_string(
        (const char *)sqlite3_column_text(st, 0)));
    json_object_object_add(root, "ssid_id", json_object_new_string(
        (const char *)sqlite3_column_text(st, 1)));
    json_object_object_add(root, "state", json_object_new_string(
        (const char *)sqlite3_column_text(st, 2)));
    json_object_object_add(root, "error_code", json_object_new_string(
        (const char *)sqlite3_column_text(st, 3)));
    json_object_object_add(root, "base_revision",
                           json_object_new_int64(sqlite3_column_int64(st, 4)));
    json_object_object_add(root, "secret_version",
                           json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_object_add(root, "section_count",
                           json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(root, "secret_configured",
                           json_object_new_boolean(sqlite3_column_int(st, 7)));
    json_object_object_add(root, "created_at",
                           json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_object_add(root, "updated_at",
                           json_object_new_int64(sqlite3_column_int64(st, 9)));
    sqlite3_finalize(st);
    ac_secret_db_leave();
    return root;
}

void ac_secret_rotation_scrub_offer(struct json_object *message)
{
    struct json_object *kind = NULL;

    if (!message ||
        !json_object_object_get_ex(message, "kind", &kind) || !kind ||
        !json_object_is_type(kind, json_type_string) ||
        strcmp(json_object_get_string(kind), "secret_job_offer"))
        return;
    ap_control_json_scrub_string(message, "secret");
}

static void ac_secret_pending_free(struct ac_secret_pending *pending)
{
    if (!pending)
        return;
    if (pending->secret) {
        OPENSSL_cleanse(pending->secret, pending->secret_len + 1);
        (void)munlock(pending->secret, pending->secret_len + 1);
        OPENSSL_free(pending->secret);
    }
    OPENSSL_cleanse(pending, sizeof(*pending));
    free(pending);
}

static int ac_secret_sections_resolve(struct ac_secret_pending *pending)
{
    sqlite3_stmt *st = NULL;
    int64_t revision;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT revision,secret_version FROM ac_ssids WHERE ssid_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, pending->ssid_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return 1;
    }
    revision = sqlite3_column_int64(st, 0);
    pending->secret_version = sqlite3_column_int64(st, 1) + 1;
    sqlite3_finalize(st);
    if (revision != pending->base_revision || pending->secret_version <= 0)
        return 2;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT b.section_name FROM ac_ssid_bindings b "
            "JOIN ac_aps a ON a.ap_id=b.ap_id "
            "JOIN ac_ap_runtime r ON r.ap_id=b.ap_id "
            "WHERE b.ssid_id=?1 AND b.ap_id=?2 AND b.section_name<>'' "
            "AND a.adoption_state='adopted' AND r.session_connected=1 "
            "AND r.control_protocol_version=3 AND r.write_capable=1 "
            "ORDER BY b.radio_id",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, pending->ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, pending->ap_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *section = (const char *)sqlite3_column_text(st, 0);

        if (!section || !ac_secret_text_valid(section, 1,
                AC_SECRET_ROTATION_SECTION_MAX) ||
            pending->section_count >= AC_SECRET_ROTATION_MAX_SECTIONS) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(pending->sections[pending->section_count],
                 sizeof(pending->sections[pending->section_count]), "%s",
                 section);
        pending->section_count++;
    }
    sqlite3_finalize(st);
    return pending->section_count > 0 ? 0 : 3;
}

static struct json_object *ac_secret_create(struct json_object *request)
{
    static const char *const fields[] = {
        "operation", "ap_id", "ssid_id", "actor_id", "idempotency_key",
        "base_revision", "confirm", "secret"
    };
    const char *ap_id = NULL, *ssid_id = NULL, *actor_id = NULL;
    const char *idempotency_key = NULL, *secret = NULL;
    struct json_object *confirm = NULL;
    int64_t base_revision = 0;
    struct ac_secret_pending *pending = NULL;
    sqlite3_stmt *st = NULL;
    char digest[77];
    int resolve;
    int64_t now = ac_now_s();

    if (ap_control_json_object_exact(request, fields, 8, fields, 8) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(request, "ap_id", &ap_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || !ac_secret_uuid4_valid(ap_id) ||
        ap_control_json_get_string(request, "ssid_id", &ssid_id, 1,
            AC_SECRET_ROTATION_SSID_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(request, "actor_id", &actor_id, 1,
            AC_SECRET_ROTATION_ACTOR_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(request, "idempotency_key", &idempotency_key,
            1, AC_SECRET_ROTATION_IDEMPOTENCY_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(request, "secret", &secret, 8,
            AC_SECRET_ROTATION_SECRET_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_int64(request, "base_revision", 1, INT64_MAX - 1,
            &base_revision) != AP_CONTROL_WIRE_OK ||
        !json_object_object_get_ex(request, "confirm", &confirm) || !confirm ||
        !json_object_is_type(confirm, json_type_boolean) ||
        !json_object_get_boolean(confirm) ||
        !ac_secret_ssid_id_valid(ssid_id) ||
        !ac_secret_text_valid(actor_id, 1, AC_SECRET_ROTATION_ACTOR_MAX) ||
        !ac_secret_text_valid(idempotency_key, 1,
                              AC_SECRET_ROTATION_IDEMPOTENCY_MAX) ||
        !ac_secret_value_valid(secret) ||
        ac_secret_request_digest(ap_id, ssid_id, base_revision,
            (const unsigned char *)secret, strlen(secret), digest) != 0)
        return ac_secret_error("invalid_request", "secret_rotation_request_invalid");
    pending = calloc(1, sizeof(*pending));
    if (!pending || ap_control_uuid4(pending->job_id) != AP_CONTROL_WIRE_OK)
        goto memory_fail;
    snprintf(pending->ap_id, sizeof(pending->ap_id), "%s", ap_id);
    snprintf(pending->ssid_id, sizeof(pending->ssid_id), "%s", ssid_id);
    snprintf(pending->actor_id, sizeof(pending->actor_id), "%s", actor_id);
    snprintf(pending->idempotency_key, sizeof(pending->idempotency_key), "%s",
             idempotency_key);
    snprintf(pending->request_digest, sizeof(pending->request_digest), "%s",
             digest);
    pending->base_revision = base_revision;
    pending->created_at = now;
    pending->secret_len = strlen(secret);
    pending->secret = OPENSSL_malloc(pending->secret_len + 1);
    if (!pending->secret)
        goto memory_fail;
    memcpy(pending->secret, secret, pending->secret_len + 1);
    (void)mlock(pending->secret, pending->secret_len + 1);
    ac_secret_db_enter();
    if (sqlite3_exec(g_ac_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        ac_secret_db_leave();
        goto database_fail;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT job_id,request_digest FROM ac_secret_rotation_jobs "
            "WHERE actor_id=?1 AND idempotency_key=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto database_rollback;
    sqlite3_bind_text(st, 1, actor_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, idempotency_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *job_id = (const char *)sqlite3_column_text(st, 0);
        const char *stored = (const char *)sqlite3_column_text(st, 1);
        char existing_job[37];
        char existing_digest[77];
        int conflict;

        snprintf(existing_job, sizeof(existing_job), "%s", job_id ? job_id : "");
        snprintf(existing_digest, sizeof(existing_digest), "%s",
                 stored ? stored : "");
        conflict = !existing_digest[0] || strcmp(existing_digest, digest) != 0;
        sqlite3_finalize(st);
        st = NULL;
        sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
        ac_secret_db_leave();
        ac_secret_pending_free(pending);
        if (conflict)
            return ac_secret_error("idempotency_conflict",
                                   "idempotency_key_binding_mismatch");
        return ac_secret_status(existing_job);
    }
    sqlite3_finalize(st);
    st = NULL;
    sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
    ac_secret_db_leave();
    if (!ac_secret_rotation_ap_available(ap_id)) {
        ac_secret_pending_free(pending);
        return ac_secret_error("capability_disabled",
                               "ap_secret_executor_not_online");
    }
    ac_secret_db_enter();
    if (sqlite3_exec(g_ac_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        ac_secret_db_leave();
        goto database_fail;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT job_id,request_digest FROM ac_secret_rotation_jobs "
            "WHERE actor_id=?1 AND idempotency_key=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto database_rollback;
    sqlite3_bind_text(st, 1, actor_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, idempotency_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *job_id = (const char *)sqlite3_column_text(st, 0);
        const char *stored = (const char *)sqlite3_column_text(st, 1);
        char existing_job[37];
        char existing_digest[77];
        int conflict;

        snprintf(existing_job, sizeof(existing_job), "%s", job_id ? job_id : "");
        snprintf(existing_digest, sizeof(existing_digest), "%s",
                 stored ? stored : "");
        conflict = !existing_digest[0] || strcmp(existing_digest, digest) != 0;
        sqlite3_finalize(st);
        st = NULL;
        sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
        ac_secret_db_leave();
        ac_secret_pending_free(pending);
        if (conflict)
            return ac_secret_error("idempotency_conflict",
                                   "idempotency_key_binding_mismatch");
        return ac_secret_status(existing_job);
    }
    sqlite3_finalize(st);
    st = NULL;
    resolve = ac_secret_sections_resolve(pending);
    if (resolve != 0) {
        sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
        ac_secret_db_leave();
        ac_secret_pending_free(pending);
        return ac_secret_error(resolve == 1 ? "not_found" :
            resolve == 2 ? "revision_conflict" : "capability_disabled",
            resolve == 1 ? "ssid_not_found" :
            resolve == 2 ? "base_revision_mismatch" :
            resolve == 3 ? "ssid_has_no_online_managed_binding" :
                           "binding_resolution_failed");
    }
    resolve = ac_secret_rotation_ssid_busy(pending->ssid_id);
    if (resolve != 0) {
        sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
        ac_secret_db_leave();
        ac_secret_pending_free(pending);
        return ac_secret_error(resolve > 0 ? "conflict" : "database_error",
            resolve > 0 ? "secret_rotation_in_progress" :
                          "secret_rotation_state_unavailable");
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_secret_rotation_jobs(job_id,ap_id,ssid_id,actor_id,"
            "idempotency_key,request_digest,base_revision,secret_version,state,"
            "section_count,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'queued',?9,?10,?10)",
            -1, &st, NULL) != SQLITE_OK)
        goto database_rollback;
    sqlite3_bind_text(st, 1, pending->job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, pending->ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, pending->ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, pending->actor_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, pending->idempotency_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, pending->request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, pending->base_revision);
    sqlite3_bind_int64(st, 8, pending->secret_version);
    sqlite3_bind_int(st, 9, (int)pending->section_count);
    sqlite3_bind_int64(st, 10, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto database_rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(g_ac_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto database_rollback;
    ac_secret_db_leave();
    pthread_mutex_lock(&g_secret_rotation.lock);
    pending->next = g_secret_rotation.pending;
    g_secret_rotation.pending = pending;
    pthread_mutex_unlock(&g_secret_rotation.lock);
    return ac_secret_status(pending->job_id);

database_fail:
    sqlite3_finalize(st);
    ac_secret_pending_free(pending);
    return ac_secret_error("database_error", "secret_job_store_failed");
database_rollback:
    sqlite3_finalize(st);
    sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
    ac_secret_db_leave();
    ac_secret_pending_free(pending);
    return ac_secret_error("database_error", "secret_job_store_failed");
memory_fail:
    ac_secret_pending_free(pending);
    return ac_secret_error("internal_error", "memory_unavailable");
}

static void ac_secret_client(int fd)
{
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    const char *operation = NULL;

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
        peer.uid != 0 || ac_secret_recv_json(fd, &request) != 0 ||
        ap_control_json_get_string(request, "operation", &operation, 6, 6) !=
            AP_CONTROL_WIRE_OK) {
        response = ac_secret_error("forbidden", "local_peer_not_authorized");
    } else if (!strcmp(operation, "rotate")) {
        response = ac_secret_create(request);
    } else if (!strcmp(operation, "status")) {
        static const char *const fields[] = { "operation", "job_id" };
        const char *job_id = NULL;

        if (ap_control_json_object_exact(request, fields, 2, fields, 2) !=
                AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(request, "job_id", &job_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || !ac_secret_uuid4_valid(job_id))
            response = ac_secret_error("invalid_request",
                                       "secret_status_request_invalid");
        else
            response = ac_secret_status(job_id);
    } else {
        response = ac_secret_error("invalid_request",
                                   "secret_operation_not_supported");
    }
    (void)ac_secret_send_json(fd, response);
    ap_control_json_scrub_string(request, "secret");
    json_object_put(response);
    json_object_put(request);
}

static void *ac_secret_thread(void *opaque)
{
    (void)opaque;
    while (!g_secret_rotation.stopping) {
        struct pollfd pollfd = { .fd = g_secret_rotation.listen_fd,
                                 .events = POLLIN };
        int ready = poll(&pollfd, 1, 500);

        if (ready > 0 && (pollfd.revents & POLLIN)) {
            int fd = accept4(g_secret_rotation.listen_fd, NULL, NULL,
                             SOCK_CLOEXEC);
            if (fd >= 0) {
                struct timeval timeout = { .tv_sec = 2 };

                (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                                 sizeof(timeout));
                (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                                 sizeof(timeout));
                ac_secret_client(fd);
                close(fd);
            }
        }
    }
    return NULL;
}

int ac_secret_rotation_init(void)
{
    struct sockaddr_un address;

    if (ac_secret_key_load() != 0 || ac_secret_schema_init() != 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s",
             AC_SECRET_ROTATION_SOCKET);
    unlink(AC_SECRET_ROTATION_SOCKET);
    g_secret_rotation.listen_fd = socket(AF_UNIX,
                                         SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_secret_rotation.listen_fd < 0 ||
        bind(g_secret_rotation.listen_fd, (struct sockaddr *)&address,
             sizeof(address)) != 0 || chmod(AC_SECRET_ROTATION_SOCKET, 0600) != 0 ||
        listen(g_secret_rotation.listen_fd, 8) != 0 ||
        pthread_create(&g_secret_rotation.thread, NULL, ac_secret_thread,
                       NULL) != 0) {
        ac_secret_rotation_close();
        return -1;
    }
    g_secret_rotation.thread_started = 1;
    return 0;
}

void ac_secret_rotation_close(void)
{
    struct ac_secret_pending *pending;

    g_secret_rotation.stopping = 1;
    if (g_secret_rotation.listen_fd >= 0)
        shutdown(g_secret_rotation.listen_fd, SHUT_RDWR);
    if (g_secret_rotation.thread_started)
        pthread_join(g_secret_rotation.thread, NULL);
    if (g_secret_rotation.listen_fd >= 0)
        close(g_secret_rotation.listen_fd);
    g_secret_rotation.listen_fd = -1;
    unlink(AC_SECRET_ROTATION_SOCKET);
    pthread_mutex_lock(&g_secret_rotation.lock);
    pending = g_secret_rotation.pending;
    g_secret_rotation.pending = NULL;
    pthread_mutex_unlock(&g_secret_rotation.lock);
    while (pending) {
        struct ac_secret_pending *next = pending->next;
        ac_secret_pending_free(pending);
        pending = next;
    }
    OPENSSL_cleanse(g_secret_rotation.hmac_key,
                    sizeof(g_secret_rotation.hmac_key));
}

void ac_secret_rotation_session_begin(const char *ap_id, int capable)
{
    size_t i;

    pthread_mutex_lock(&g_secret_rotation.lock);
    for (i = 0; i < g_secret_rotation.capable_count; i++)
        if (ap_id && !strcmp(g_secret_rotation.capable_aps[i], ap_id))
            break;
    if (capable && ap_id && i == g_secret_rotation.capable_count &&
        g_secret_rotation.capable_count < 32) {
        snprintf(g_secret_rotation.capable_aps[g_secret_rotation.capable_count],
                 sizeof(g_secret_rotation.capable_aps[0]), "%s", ap_id);
        g_secret_rotation.capable_count++;
    } else if (!capable && i < g_secret_rotation.capable_count) {
        if (i + 1 < g_secret_rotation.capable_count)
            memmove(g_secret_rotation.capable_aps[i],
                    g_secret_rotation.capable_aps[i + 1],
                    (g_secret_rotation.capable_count - i - 1) *
                    sizeof(g_secret_rotation.capable_aps[0]));
        g_secret_rotation.capable_count--;
        memset(g_secret_rotation.capable_aps[g_secret_rotation.capable_count],
               0, sizeof(g_secret_rotation.capable_aps[0]));
    }
    pthread_mutex_unlock(&g_secret_rotation.lock);
}

void ac_secret_rotation_session_end(const char *ap_id)
{
    size_t i;
    struct ac_secret_pending *pending;

    pthread_mutex_lock(&g_secret_rotation.lock);
    for (i = 0; i < g_secret_rotation.capable_count; i++) {
        if (ap_id && strcmp(g_secret_rotation.capable_aps[i], ap_id))
            continue;
        if (i + 1 < g_secret_rotation.capable_count)
            memmove(g_secret_rotation.capable_aps[i],
                    g_secret_rotation.capable_aps[i + 1],
                    (g_secret_rotation.capable_count - i - 1) *
                    sizeof(g_secret_rotation.capable_aps[0]));
        g_secret_rotation.capable_count--;
        memset(g_secret_rotation.capable_aps[g_secret_rotation.capable_count],
               0, sizeof(g_secret_rotation.capable_aps[0]));
        if (ap_id)
            break;
        i--;
    }
    for (pending = g_secret_rotation.pending; pending; pending = pending->next)
        if (!ap_id || !strcmp(pending->ap_id, ap_id))
            pending->offered = 0;
    pthread_mutex_unlock(&g_secret_rotation.lock);
}

int ac_secret_rotation_available_count(void)
{
    int available;

    pthread_mutex_lock(&g_secret_rotation.lock);
    available = (int)g_secret_rotation.capable_count;
    pthread_mutex_unlock(&g_secret_rotation.lock);
    return available;
}

int ac_secret_rotation_ap_available(const char *ap_id)
{
    size_t i;
    int available = 0;

    pthread_mutex_lock(&g_secret_rotation.lock);
    for (i = 0; ap_id && i < g_secret_rotation.capable_count; i++)
        if (!strcmp(g_secret_rotation.capable_aps[i], ap_id)) {
            available = 1;
            break;
        }
    pthread_mutex_unlock(&g_secret_rotation.lock);
    return available;
}

struct json_object *ac_secret_rotation_poll(const char *ap_id,
                                             const char *session_epoch,
                                             int64_t reply_to)
{
    struct ac_secret_pending *pending;
    struct ac_secret_pending **cursor;
    struct ac_secret_pending *expired = NULL;
    struct json_object *root;
    struct json_object *sections;
    size_t i;
    int64_t now = ac_now_s();

    pthread_mutex_lock(&g_secret_rotation.lock);
    for (cursor = &g_secret_rotation.pending; *cursor;) {
        if (!(*cursor)->prepared &&
            now - (*cursor)->created_at > AC_SECRET_ROTATION_TTL_SECONDS) {
            struct ac_secret_pending *item = *cursor;

            *cursor = item->next;
            item->next = expired;
            expired = item;
            continue;
        }
        cursor = &(*cursor)->next;
    }
    for (pending = g_secret_rotation.pending; pending; pending = pending->next)
        if (!pending->offered && !strcmp(pending->ap_id, ap_id))
            break;
    if (pending)
        pending->offered = 1;
    if (pending) {
        sqlite3_stmt *st = NULL;
        int stored = 0;

        ac_secret_db_enter();
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_secret_rotation_jobs SET state='offered',"
                "updated_at=?2 WHERE job_id=?1 "
                "AND state IN ('queued','offered','prepared')",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, pending->job_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, now);
            stored = sqlite3_step(st) == SQLITE_DONE &&
                     sqlite3_changes(g_ac_db) == 1;
        }
        sqlite3_finalize(st);
        ac_secret_db_leave();
        if (!stored) {
            pending->offered = 0;
            pending = NULL;
        }
    }
    while (expired) {
        struct ac_secret_pending *next = expired->next;
        sqlite3_stmt *st = NULL;

        ac_secret_db_enter();
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_secret_rotation_jobs SET state='failed',"
                "error_code='delivery_timeout',updated_at=?2 WHERE job_id=?1",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, expired->job_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, now);
            (void)sqlite3_step(st);
        }
        sqlite3_finalize(st);
        ac_secret_db_leave();
        ac_secret_pending_free(expired);
        expired = next;
    }
    root = json_object_new_object();
    json_object_object_add(root, "protocol",
                           json_object_new_string(AP_CONTROL_PROTOCOL_V3));
    json_object_object_add(root, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(root, "session_epoch",
                           json_object_new_string(session_epoch));
    json_object_object_add(root, "reply_to", json_object_new_int64(reply_to));
    if (!pending) {
        json_object_object_add(root, "kind",
                               json_object_new_string("secret_job_idle"));
        pthread_mutex_unlock(&g_secret_rotation.lock);
        return root;
    }
    sections = json_object_new_array();
    for (i = 0; i < pending->section_count; i++)
        json_object_array_add(sections,
            json_object_new_string(pending->sections[i]));
    json_object_object_add(root, "kind",
                           json_object_new_string("secret_job_offer"));
    json_object_object_add(root, "job_id",
                           json_object_new_string(pending->job_id));
    json_object_object_add(root, "request_digest",
                           json_object_new_string(pending->request_digest));
    json_object_object_add(root, "ssid_id",
                           json_object_new_string(pending->ssid_id));
    json_object_object_add(root, "secret_version",
                           json_object_new_int64(pending->secret_version));
    json_object_object_add(root, "sections", sections);
    json_object_object_add(root, "secret",
        json_object_new_string_len((const char *)pending->secret,
                                   (int)pending->secret_len));
    pthread_mutex_unlock(&g_secret_rotation.lock);
    return root;
}

struct json_object *ac_secret_rotation_prepare(struct json_object *message,
                                                const char *ap_id,
                                                const char *session_epoch,
                                                int64_t reply_to)
{
    static const char *const fields[] = {
        "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
        "request_digest", "outcome", "error_code", "secret_version",
        "secret_configured"
    };
    const char *job_id = NULL, *digest = NULL, *outcome = NULL;
    const char *error_code = NULL;
    struct json_object *configured = NULL;
    int64_t version = 0;
    struct ac_secret_pending **cursor;
    struct ac_secret_pending *pending = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *root;
    int succeeded;
    int stored = 0;
    int revision_state = -1;

    if (ap_control_json_object_exact(message, fields, 11, fields, 11) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "job_id", &job_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || !ac_secret_uuid4_valid(job_id) ||
        ap_control_json_get_string(message, "request_digest", &digest, 12, 76) !=
            AP_CONTROL_WIRE_OK || !ac_secret_digest_valid(digest) ||
        ap_control_json_get_string(message, "outcome", &outcome, 6, 9) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "error_code", &error_code, 0, 127) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_int64(message, "secret_version", 1, INT64_MAX,
                                  &version) != AP_CONTROL_WIRE_OK ||
        !json_object_object_get_ex(message, "secret_configured", &configured) ||
        !configured || !json_object_is_type(configured, json_type_boolean))
        return ac_secret_error("invalid_request", "secret_finish_invalid");
    succeeded = !strcmp(outcome, "completed") &&
                json_object_get_boolean(configured) && !error_code[0];
    if ((!strcmp(outcome, "completed") && !succeeded) ||
        (strcmp(outcome, "completed") && strcmp(outcome, "failed")) ||
        (!strcmp(outcome, "failed") &&
         (!error_code[0] || json_object_get_boolean(configured))))
        return ac_secret_error("invalid_request", "secret_finish_invalid");
    pthread_mutex_lock(&g_secret_rotation.lock);
    for (cursor = &g_secret_rotation.pending; *cursor; cursor = &(*cursor)->next)
        if (!strcmp((*cursor)->job_id, job_id)) {
            pending = *cursor;
            break;
        }
    if (!pending || strcmp(pending->ap_id, ap_id) ||
        strcmp(pending->request_digest, digest) ||
        pending->secret_version != version) {
        pthread_mutex_unlock(&g_secret_rotation.lock);
        return ac_secret_error("conflict", "secret_finish_binding_mismatch");
    }
    ac_secret_db_enter();
    if (succeeded && sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_ssids WHERE ssid_id=?1 AND revision=?2 "
            "AND secret_version<?3",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, pending->ssid_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, pending->base_revision);
        sqlite3_bind_int64(st, 3, pending->secret_version);
        revision_state = sqlite3_step(st) == SQLITE_ROW ? 1 : 0;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (succeeded && revision_state <= 0) {
        sqlite3_stmt *fail = NULL;

        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_secret_rotation_jobs SET state='failed',"
                "error_code=?2,secret_configured=0,updated_at=?3 "
                "WHERE job_id=?1 AND state IN ('queued','offered','prepared')",
                -1, &fail, NULL) == SQLITE_OK) {
            sqlite3_bind_text(fail, 1, job_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(fail, 2, revision_state == 0 ?
                "base_revision_changed_before_prepare" :
                "secret_revision_check_failed", -1, SQLITE_STATIC);
            sqlite3_bind_int64(fail, 3, ac_now_s());
            stored = sqlite3_step(fail) == SQLITE_DONE &&
                     sqlite3_changes(g_ac_db) == 1;
        }
        sqlite3_finalize(fail);
        ac_secret_db_leave();
        if (stored)
            *cursor = pending->next;
        pthread_mutex_unlock(&g_secret_rotation.lock);
        if (stored)
            ac_secret_pending_free(pending);
        if (!stored)
            return ac_secret_error("database_error",
                                   "secret_prepare_store_failed");
        root = json_object_new_object();
        json_object_object_add(root, "protocol",
                               json_object_new_string(AP_CONTROL_PROTOCOL_V3));
        json_object_object_add(root, "kind",
                               json_object_new_string("secret_job_prepare_ack"));
        json_object_object_add(root, "ap_id", json_object_new_string(ap_id));
        json_object_object_add(root, "session_epoch",
                               json_object_new_string(session_epoch));
        json_object_object_add(root, "reply_to", json_object_new_int64(reply_to));
        json_object_object_add(root, "job_id", json_object_new_string(job_id));
        json_object_object_add(root, "accepted", json_object_new_boolean(0));
        json_object_object_add(root, "commit_required", json_object_new_boolean(0));
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_secret_rotation_jobs SET state=?2,error_code=?3,"
            "secret_configured=?4,updated_at=?5 WHERE job_id=?1 "
            "AND state IN ('queued','offered','prepared')",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, succeeded ? "prepared" : "failed", -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(st, 3, error_code, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, succeeded ? 1 : 0);
        sqlite3_bind_int64(st, 5, ac_now_s());
        stored = sqlite3_step(st) == SQLITE_DONE &&
                 sqlite3_changes(g_ac_db) == 1;
    }
    sqlite3_finalize(st);
    ac_secret_db_leave();
    if (!stored) {
        pthread_mutex_unlock(&g_secret_rotation.lock);
        return ac_secret_error("database_error", "secret_prepare_store_failed");
    }
    if (succeeded) {
        pending->prepared = 1;
    } else {
        for (cursor = &g_secret_rotation.pending; *cursor;
             cursor = &(*cursor)->next)
            if (*cursor == pending) {
                *cursor = pending->next;
                break;
            }
    }
    pthread_mutex_unlock(&g_secret_rotation.lock);
    if (!succeeded)
        ac_secret_pending_free(pending);
    root = json_object_new_object();
    json_object_object_add(root, "protocol",
                           json_object_new_string(AP_CONTROL_PROTOCOL_V3));
    json_object_object_add(root, "kind",
                           json_object_new_string("secret_job_prepare_ack"));
    json_object_object_add(root, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(root, "session_epoch",
                           json_object_new_string(session_epoch));
    json_object_object_add(root, "reply_to", json_object_new_int64(reply_to));
    json_object_object_add(root, "job_id", json_object_new_string(job_id));
    json_object_object_add(root, "accepted", json_object_new_boolean(1));
    json_object_object_add(root, "commit_required",
        json_object_new_boolean(succeeded));
    return root;
}

struct json_object *ac_secret_rotation_commit(struct json_object *message,
                                               const char *ap_id,
                                               const char *session_epoch,
                                               int64_t reply_to)
{
    static const char *const fields[] = {
        "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
        "request_digest", "secret_version", "secret_configured"
    };
    const char *job_id = NULL, *digest = NULL;
    struct json_object *configured = NULL;
    int64_t version = 0;
    struct ac_secret_pending **cursor;
    struct ac_secret_pending *pending = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *root;
    int committed = 0;
    int64_t now = ac_now_s();

    if (ap_control_json_object_exact(message, fields, 9, fields, 9) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "job_id", &job_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || !ac_secret_uuid4_valid(job_id) ||
        ap_control_json_get_string(message, "request_digest", &digest, 12, 76) !=
            AP_CONTROL_WIRE_OK || !ac_secret_digest_valid(digest) ||
        ap_control_json_get_int64(message, "secret_version", 1, INT64_MAX,
                                  &version) != AP_CONTROL_WIRE_OK ||
        !json_object_object_get_ex(message, "secret_configured", &configured) ||
        !configured || !json_object_is_type(configured, json_type_boolean) ||
        !json_object_get_boolean(configured))
        return ac_secret_error("invalid_request", "secret_commit_invalid");
    pthread_mutex_lock(&g_secret_rotation.lock);
    for (cursor = &g_secret_rotation.pending; *cursor; cursor = &(*cursor)->next)
        if (!strcmp((*cursor)->job_id, job_id)) {
            pending = *cursor;
            break;
        }
    if (!pending || strcmp(pending->ap_id, ap_id) ||
        strcmp(pending->request_digest, digest) ||
        pending->secret_version != version || !pending->prepared) {
        pthread_mutex_unlock(&g_secret_rotation.lock);
        return ac_secret_error("conflict", "secret_commit_binding_mismatch");
    }
    ac_secret_db_enter();
    if (sqlite3_exec(g_ac_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        goto database_fail;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ssids SET secret_present=1,secret_version=?2,updated_at=?3 "
            "WHERE ssid_id=?1 AND revision=?4 AND secret_version<?2",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, pending->ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, version);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_int64(st, 4, pending->base_revision);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ssid_bindings SET secret_digest=?3,secret_present=1,"
            "secret_version=?4,updated_at=?5 WHERE ssid_id=?1 AND ap_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, pending->ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, pending->ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, pending->request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, version);
    sqlite3_bind_int64(st, 5, now);
    if (sqlite3_step(st) != SQLITE_DONE ||
        sqlite3_changes(g_ac_db) != (int)pending->section_count)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_secret_rotation_jobs SET state='completed',error_code='',"
            "secret_configured=1,updated_at=?2 WHERE job_id=?1 AND state='prepared'",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(g_ac_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback;
    committed = 1;
    ac_secret_db_leave();
    *cursor = pending->next;
    pthread_mutex_unlock(&g_secret_rotation.lock);
    ac_secret_pending_free(pending);
    root = json_object_new_object();
    json_object_object_add(root, "protocol",
                           json_object_new_string(AP_CONTROL_PROTOCOL_V3));
    json_object_object_add(root, "kind",
                           json_object_new_string("secret_job_commit_ack"));
    json_object_object_add(root, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(root, "session_epoch",
                           json_object_new_string(session_epoch));
    json_object_object_add(root, "reply_to", json_object_new_int64(reply_to));
    json_object_object_add(root, "job_id", json_object_new_string(job_id));
    json_object_object_add(root, "accepted", json_object_new_boolean(1));
    return root;

rollback:
    sqlite3_finalize(st);
    sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
database_fail:
    if (!committed)
        ac_secret_db_leave();
    pthread_mutex_unlock(&g_secret_rotation.lock);
    return ac_secret_error("database_error", "secret_commit_store_failed");
}
