// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_secret_executor.h"
#include "apd_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <uci.h>

#define APD_SECRET_SECTION_MAX 32U
#define APD_SECRET_SECTIONS_MAX 16U
#define APD_SECRET_VALUE_MAX 64U
#define APD_SECRET_RELOAD_TIMEOUT_SECONDS 20

struct apd_secret_previous {
    char section[APD_SECRET_SECTION_MAX + 1];
    unsigned char *value;
    size_t value_len;
    int present;
};

struct apd_secret_transaction {
    char job_id[37];
    int64_t secret_version;
    struct apd_secret_previous previous[APD_SECRET_SECTIONS_MAX];
    size_t section_count;
    int applied;
};

static struct json_object *apd_secret_result(const char *operation, int ok,
                                             const char *reason,
                                             int64_t secret_version,
                                             size_t section_count)
{
    struct json_object *root = json_object_new_object();

    if (!root)
        return NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(ok));
    json_object_object_add(root, "operation",
                           json_object_new_string(operation));
    json_object_object_add(root, "secret_version",
                           json_object_new_int64(secret_version));
    json_object_object_add(root, "secret_configured",
                           json_object_new_boolean(ok));
    json_object_object_add(root, "section_count",
                           json_object_new_int64((int64_t)section_count));
    if (!ok)
        json_object_object_add(root, "reason",
            json_object_new_string(reason ? reason : "secret_apply_failed"));
    return root;
}

static int apd_secret_section_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > APD_SECRET_SECTION_MAX)
        return 0;
    for (i = 0; i < len; i++)
        if (!(isalnum((unsigned char)value[i]) || value[i] == '_'))
            return 0;
    return 1;
}

static int apd_secret_value_valid(const unsigned char *secret, size_t len)
{
    size_t i;
    int hex = len == 64;

    if (!secret || len < 8 || len > APD_SECRET_VALUE_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        if (secret[i] < 0x20 || secret[i] > 0x7e || secret[i] == '\'' ||
            secret[i] == '"' || secret[i] == '\\')
            return 0;
        if (!isxdigit(secret[i]))
            hex = 0;
    }
    return len <= 63 || hex;
}

static int apd_secret_ssid_id_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > 64)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-'))
            return 0;
    }
    return 1;
}

static int apd_secret_uuid4_valid(const char *value)
{
    static const int hyphens[] = {8, 13, 18, 23};
    size_t i;
    int h = 0;

    if (!value || strlen(value) != 36 || value[14] != '4' ||
        !(value[19] == '8' || value[19] == '9' || value[19] == 'a' ||
          value[19] == 'b'))
        return 0;
    for (i = 0; i < 36; i++) {
        if (h < 4 && (int)i == hyphens[h]) {
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

static int apd_secret_digest_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 76 || strncmp(value, "hmac-sha256:", 12))
        return 0;
    for (i = 12; i < 76; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static unsigned char *apd_secret_dup_locked(const unsigned char *value,
                                             size_t len)
{
    unsigned char *copy = OPENSSL_malloc(len + 1);

    if (!copy)
        return NULL;
    memcpy(copy, value, len);
    copy[len] = 0;
    (void)mlock(copy, len + 1);
    return copy;
}

static void apd_secret_free_locked(unsigned char *value, size_t len)
{
    if (!value)
        return;
    OPENSSL_cleanse(value, len + 1);
    (void)munlock(value, len + 1);
    OPENSSL_free(value);
}

static int apd_secret_reload(void)
{
    pid_t pid = fork();
    int status = 0;
    unsigned int waited = 0;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        execl("/sbin/wifi", "wifi", "reload", (char *)NULL);
        _exit(127);
    }
    while (waited < APD_SECRET_RELOAD_TIMEOUT_SECONDS * 10U) {
        pid_t result = waitpid(pid, &status, WNOHANG);

        if (result == pid)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
        if (result < 0 && errno != EINTR)
            return -1;
        usleep(100000);
        waited++;
    }
    kill(pid, SIGKILL);
    (void)waitpid(pid, &status, 0);
    return -1;
}

static int apd_secret_set(struct uci_context *ctx, struct uci_package *package,
                          const char *section, const unsigned char *value,
                          size_t value_len, int present)
{
    struct uci_ptr ptr;
    char assignment[APD_SECRET_SECTION_MAX + APD_SECRET_VALUE_MAX + 32];

    memset(&ptr, 0, sizeof(ptr));
    if (present) {
        if (snprintf(assignment, sizeof(assignment), "wireless.%s.key=%.*s",
                     section, (int)value_len, (const char *)value) >=
                (int)sizeof(assignment) ||
            uci_lookup_ptr(ctx, &ptr, assignment, true) != UCI_OK ||
            !ptr.s || strcmp(ptr.s->type, "wifi-iface") ||
            uci_set(ctx, &ptr) != UCI_OK) {
            OPENSSL_cleanse(assignment, sizeof(assignment));
            return -1;
        }
        OPENSSL_cleanse(assignment, sizeof(assignment));
    } else {
        if (snprintf(assignment, sizeof(assignment), "wireless.%s.key",
                     section) >= (int)sizeof(assignment) ||
            uci_lookup_ptr(ctx, &ptr, assignment, true) != UCI_OK ||
            !ptr.s || strcmp(ptr.s->type, "wifi-iface")) {
            OPENSSL_cleanse(assignment, sizeof(assignment));
            return -1;
        }
        if (ptr.o && uci_delete(ctx, &ptr) != UCI_OK) {
            OPENSSL_cleanse(assignment, sizeof(assignment));
            return -1;
        }
        OPENSSL_cleanse(assignment, sizeof(assignment));
    }
    return package ? 0 : -1;
}

static int apd_secret_commit(struct uci_context *ctx,
                             struct uci_package **package)
{
    return uci_save(ctx, *package) == UCI_OK &&
           uci_commit(ctx, package, false) == UCI_OK ? 0 : -1;
}

static int apd_secret_restore(struct apd_secret_transaction *transaction)
{
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    size_t i;
    int rc = -1;

    if (!transaction || !(ctx = uci_alloc_context()))
        return -1;
    uci_set_confdir(ctx, "/etc/config");
    if (uci_load(ctx, "wireless", &package) != UCI_OK || !package)
        goto done;
    for (i = 0; i < transaction->section_count; i++)
        if (apd_secret_set(ctx, package, transaction->previous[i].section,
                           transaction->previous[i].value,
                           transaction->previous[i].value_len,
                           transaction->previous[i].present) != 0)
            goto done;
    if (apd_secret_commit(ctx, &package) != 0 || apd_secret_reload() != 0)
        goto done;
    rc = 0;
done:
    if (package)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

int apd_secret_executor_available(void)
{
    return access("/sbin/wifi", X_OK) == 0 &&
           access("/etc/config/wireless", R_OK | W_OK) == 0;
}

int apd_secret_executor_init(void)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS apd_secret_rotation_jobs("
        "job_id TEXT PRIMARY KEY,request_digest TEXT NOT NULL,"
        "secret_version INTEGER NOT NULL,state TEXT NOT NULL,"
        "committed_at INTEGER NOT NULL);";

    return g_apd_db &&
           sqlite3_exec(g_apd_db, schema, NULL, NULL, NULL) == SQLITE_OK ?
           0 : -1;
}

int apd_secret_job_committed(const char *job_id, const char *request_digest,
                             int64_t secret_version)
{
    sqlite3_stmt *st = NULL;
    int result = 0;

    if (!g_apd_db || !apd_secret_uuid4_valid(job_id) ||
        !apd_secret_digest_valid(request_digest) || secret_version <= 0 ||
        sqlite3_prepare_v2(g_apd_db,
            "SELECT request_digest,secret_version,state "
            "FROM apd_secret_rotation_jobs WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *stored_digest =
            (const char *)sqlite3_column_text(st, 0);
        const char *stored_state =
            (const char *)sqlite3_column_text(st, 2);

        result = stored_digest && stored_state &&
                 !strcmp(stored_digest, request_digest) &&
                 sqlite3_column_int64(st, 1) == secret_version &&
                 !strcmp(stored_state, "completed") ? 1 : -1;
    }
    sqlite3_finalize(st);
    return result;
}

int apd_secret_job_record_commit(const char *job_id,
                                 const char *request_digest,
                                 int64_t secret_version)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_apd_db || !apd_secret_uuid4_valid(job_id) ||
        !apd_secret_digest_valid(request_digest) || secret_version <= 0 ||
        sqlite3_prepare_v2(g_apd_db,
            "INSERT INTO apd_secret_rotation_jobs(job_id,request_digest,"
            "secret_version,state,committed_at) VALUES(?1,?2,?3,'completed',?4) "
            "ON CONFLICT(job_id) DO NOTHING",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, secret_version);
    sqlite3_bind_int64(st, 4, apd_now_s());
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = sqlite3_changes(g_apd_db) == 1 ? 0 : 1;
    sqlite3_finalize(st);
    if (rc == 1)
        rc = apd_secret_job_committed(job_id, request_digest,
                                      secret_version) == 1 ? 0 : -1;
    return rc;
}

int apd_secret_transaction_begin(const char *job_id,
                                 const char *request_digest,
                                 const char *ssid_id,
                                 int64_t secret_version,
                                 struct json_object *sections,
                                 const unsigned char *secret,
                                 size_t secret_len,
                                 struct apd_secret_transaction **out,
                                 struct json_object **result)
{
    struct apd_secret_transaction *transaction = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    size_t i;
    const char *reason = "secret_apply_failed";

    if (!out || !result)
        return -1;
    *out = NULL;
    *result = NULL;
    if (!apd_secret_uuid4_valid(job_id) ||
        !apd_secret_digest_valid(request_digest) ||
        !apd_secret_ssid_id_valid(ssid_id) || secret_version <= 0 ||
        !sections || !json_object_is_type(sections, json_type_array) ||
        json_object_array_length(sections) == 0 ||
        json_object_array_length(sections) > APD_SECRET_SECTIONS_MAX ||
        !apd_secret_value_valid(secret, secret_len)) {
        *result = apd_secret_result("rotate", 0, "invalid_secret_job",
                                    secret_version, 0);
        return -1;
    }
    {
        int committed = apd_secret_job_committed(job_id, request_digest,
                                                 secret_version);

        if (committed < 0) {
            *result = apd_secret_result("rotate", 0, "idempotency_conflict",
                                        secret_version, 0);
            return -1;
        }
        if (committed == 1) {
            *result = apd_secret_result("rotate", 1, NULL, secret_version,
                                        json_object_array_length(sections));
            if (*result)
                json_object_object_add(*result, "idempotent",
                                       json_object_new_boolean(1));
            return 0;
        }
    }
    transaction = OPENSSL_zalloc(sizeof(*transaction));
    if (!transaction || !(ctx = uci_alloc_context())) {
        reason = "memory_unavailable";
        goto fail;
    }
    (void)mlock(transaction, sizeof(*transaction));
    snprintf(transaction->job_id, sizeof(transaction->job_id), "%s", job_id);
    transaction->secret_version = secret_version;
    transaction->section_count = json_object_array_length(sections);
    uci_set_confdir(ctx, "/etc/config");
    if (uci_load(ctx, "wireless", &package) != UCI_OK || !package) {
        reason = "wireless_config_unavailable";
        goto fail;
    }
    for (i = 0; i < transaction->section_count; i++) {
        struct json_object *entry = json_object_array_get_idx(sections, i);
        const char *section;
        struct uci_ptr ptr;
        char lookup[APD_SECRET_SECTION_MAX + 32];
        const char *old_value;

        if (!entry || !json_object_is_type(entry, json_type_string) ||
            !(section = json_object_get_string(entry)) ||
            !apd_secret_section_valid(section)) {
            reason = "invalid_section";
            goto fail;
        }
        snprintf(transaction->previous[i].section,
                 sizeof(transaction->previous[i].section), "%s", section);
        memset(&ptr, 0, sizeof(ptr));
        snprintf(lookup, sizeof(lookup), "wireless.%s", section);
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            strcmp(ptr.s->type, "wifi-iface")) {
            reason = "ssid_section_not_found";
            goto fail;
        }
        old_value = uci_lookup_option_string(ctx, ptr.s, "key");
        if (old_value) {
            transaction->previous[i].value_len = strlen(old_value);
            if (transaction->previous[i].value_len > APD_SECRET_VALUE_MAX) {
                reason = "existing_secret_too_long";
                goto fail;
            }
            transaction->previous[i].value = apd_secret_dup_locked(
                (const unsigned char *)old_value,
                transaction->previous[i].value_len);
            if (!transaction->previous[i].value) {
                reason = "memory_unavailable";
                goto fail;
            }
            transaction->previous[i].present = 1;
        }
    }
    transaction->applied = 1;
    for (i = 0; i < transaction->section_count; i++)
        if (apd_secret_set(ctx, package, transaction->previous[i].section,
                           secret, secret_len, 1) != 0) {
            reason = "uci_set_failed";
            goto rollback_fail;
        }
    if (apd_secret_commit(ctx, &package) != 0) {
        reason = "uci_commit_failed";
        goto rollback_fail;
    }
    if (apd_secret_reload() != 0) {
        reason = "wifi_reload_failed";
        goto rollback_fail;
    }
    uci_unload(ctx, package);
    package = NULL;
    if (uci_load(ctx, "wireless", &package) != UCI_OK || !package) {
        reason = "readback_unavailable";
        goto rollback_fail;
    }
    for (i = 0; i < transaction->section_count; i++) {
        struct uci_ptr ptr;
        char lookup[APD_SECRET_SECTION_MAX + 32];
        const char *actual;

        memset(&ptr, 0, sizeof(ptr));
        snprintf(lookup, sizeof(lookup), "wireless.%s",
                 transaction->previous[i].section);
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            !(actual = uci_lookup_option_string(ctx, ptr.s, "key")) ||
            strlen(actual) != secret_len ||
            CRYPTO_memcmp(actual, secret, secret_len) != 0) {
            reason = "readback_mismatch";
            goto rollback_fail;
        }
    }
    *result = apd_secret_result("rotate", 1, NULL, secret_version,
                                transaction->section_count);
    *out = transaction;
    if (package)
        uci_unload(ctx, package);
    uci_free_context(ctx);
    return 0;

rollback_fail:
    if (package) {
        uci_unload(ctx, package);
        package = NULL;
    }
    uci_free_context(ctx);
    ctx = NULL;
    if (apd_secret_restore(transaction) != 0)
        reason = "rollback_failed";
fail:
    if (package)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    *result = apd_secret_result("rotate", 0, reason, secret_version,
                                transaction ? transaction->section_count : 0);
    apd_secret_transaction_free(transaction);
    return -1;
}

int apd_secret_transaction_commit(struct apd_secret_transaction *transaction)
{
    if (!transaction || !transaction->applied)
        return -1;
    transaction->applied = 0;
    return 0;
}

int apd_secret_transaction_rollback(
    struct apd_secret_transaction *transaction, struct json_object **result)
{
    int rc;

    if (result)
        *result = NULL;
    if (!transaction || !transaction->applied)
        return -1;
    rc = apd_secret_restore(transaction);
    if (rc == 0)
        transaction->applied = 0;
    if (result)
        *result = apd_secret_result("rollback", rc == 0,
            rc == 0 ? NULL : "rollback_failed", transaction->secret_version,
            transaction->section_count);
    return rc;
}

void apd_secret_transaction_free(struct apd_secret_transaction *transaction)
{
    size_t i;

    if (!transaction)
        return;
    for (i = 0; i < transaction->section_count; i++)
        apd_secret_free_locked(transaction->previous[i].value,
                               transaction->previous[i].value_len);
    OPENSSL_cleanse(transaction, sizeof(*transaction));
    (void)munlock(transaction, sizeof(*transaction));
    OPENSSL_free(transaction);
}
