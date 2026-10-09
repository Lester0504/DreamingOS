// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "authority_diagnostics.h"
#include "jmx_dataset_path.h"

#include "../jmx_system_data_path.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define AUTHORITY_SIG_RUNTIME "/etc/dreamingwrt/dreamingwrt_signatures.db"
#define AUTHORITY_SIG_NEW "/usr/share/dreamingos/system-db/dreamingwrt_signatures.db"
#define AUTHORITY_SIG_LEGACY "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db"
#define AUTHORITY_FP_RUNTIME "/etc/dreamingwrt/fingerprint/fingerprint.db"
#define AUTHORITY_FP_NEW "/usr/share/dreamingos/system-db/fingerprint.db"
#define AUTHORITY_FP_LEGACY "/usr/share/dreamingwrt/system-db/fingerprint.db"
#define AUTHORITY_DWSIG_RUNTIME "/etc/dreamingwrt/dreamingwrt_signatures.dwsig"

struct authority_desc {
    const char *name;
    const char *canonical;
    const char *const *duplicates;
    size_t duplicate_count;
    const char *role;
    int allow_migration;
};

static const char *const signature_paths[] = {
    AUTHORITY_SIG_RUNTIME, AUTHORITY_SIG_NEW, AUTHORITY_SIG_LEGACY,
    AUTHORITY_DWSIG_RUNTIME,
};
static const char *const fingerprint_paths[] = {
    AUTHORITY_FP_RUNTIME, AUTHORITY_FP_NEW, AUTHORITY_FP_LEGACY,
};
static const char *db_paths[1]; /* runtime-filled: relocatable core.db */

static void add_str(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

static int file_sha256(const char *path, char out[65])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char buf[65536];
    FILE *fp = NULL;
    size_t n;
    unsigned int i;
    int rc = -1;

    if (!path || !out)
        return -1;
    out[0] = '\0';
    fp = fopen(path, "rb");
    ctx = EVP_MD_CTX_new();
    if (!fp || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        if (EVP_DigestUpdate(ctx, buf, n) != 1)
            goto done;
    if (ferror(fp) || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != 32)
        goto done;
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    rc = 0;
done:
    if (fp)
        fclose(fp);
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int sqlite_schema_version(const char *path, int *version, int *valid)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (version)
        *version = -1;
    if (valid)
        *valid = 0;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    if (version)
        *version = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    if (valid && sqlite3_column_text(st, 0) &&
        !strcmp((const char *)sqlite3_column_text(st, 0), "ok"))
        *valid = 1;
    rc = 0;
done:
    sqlite3_finalize(st);
    sqlite3_close(db);
    return rc;
}

static int sqlite_header(const char *path)
{
    static const unsigned char header[] = "SQLite format 3\0";
    unsigned char got[sizeof(header) - 1];
    FILE *fp = fopen(path, "rb");
    int ok = 0;

    if (!fp)
        return 0;
    ok = fread(got, 1, sizeof(got), fp) == sizeof(got) &&
         !memcmp(got, header, sizeof(got));
    fclose(fp);
    return ok;
}

static int dwsig_header(const char *path)
{
    unsigned char got[8];
    FILE *fp = fopen(path, "rb");
    int ok = 0;

    if (!fp)
        return 0;
    ok = fread(got, 1, sizeof(got), fp) == sizeof(got) &&
         !memcmp(got, "DWSIG001", 8);
    fclose(fp);
    return ok;
}

static int path_open_write_count(const char *path)
{
    DIR *proc = opendir("/proc");
    struct dirent *entry;
    char link_path[PATH_MAX], target[PATH_MAX], fdinfo[PATH_MAX], line[128];
    char resolved[PATH_MAX];
    int count = 0;

    if (!proc || !realpath(path, resolved)) {
        if (proc)
            closedir(proc);
        return 0;
    }
    while ((entry = readdir(proc)) != NULL) {
        DIR *fds;
        struct dirent *fdent;
        char dir_path[PATH_MAX];

        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;
        if (snprintf(dir_path, sizeof(dir_path), "/proc/%s/fd", entry->d_name) >=
            (int)sizeof(dir_path))
            continue;
        fds = opendir(dir_path);
        if (!fds)
            continue;
        while ((fdent = readdir(fds)) != NULL) {
            FILE *fp;
            int flags = 0;

            if (fdent->d_name[0] == '.')
                continue;
            if (snprintf(link_path, sizeof(link_path), "%s/%s", dir_path,
                         fdent->d_name) >= (int)sizeof(link_path))
                continue;
            {
                ssize_t n = readlink(link_path, target, sizeof(target) - 1);
                if (n <= 0)
                    continue;
                target[n] = '\0';
            }
            if (strcmp(target, resolved))
                continue;
            if (snprintf(fdinfo, sizeof(fdinfo), "/proc/%s/fdinfo/%s",
                         entry->d_name, fdent->d_name) >= (int)sizeof(fdinfo))
                continue;
            fp = fopen(fdinfo, "re");
            if (!fp)
                continue;
            while (fgets(line, sizeof(line), fp))
                if (sscanf(line, "flags:\t%o", &flags) == 1)
                    break;
            fclose(fp);
            if ((flags & O_ACCMODE) == O_WRONLY ||
                (flags & O_ACCMODE) == O_RDWR)
                count++;
        }
        closedir(fds);
    }
    closedir(proc);
    return count;
}

static int resolve_canonical(const char *const *paths, size_t count,
                             char *out, size_t out_len)
{
    size_t i;

    out[0] = '\0';
    for (i = 0; i < count; i++)
        if (access(paths[i], R_OK) == 0) {
            snprintf(out, out_len, "%s", paths[i]);
            return 0;
        }
    return -1;
}

static const char *authority_path_role(const struct authority_desc *desc,
                                       const char *path)
{
    if (!desc || !path)
        return "observed_copy";
    if (!strcmp(path, desc->canonical))
        return "runtime_canonical";
    if (strstr(path, ".dwsig"))
        return "sealed_sidecar";
    if (strstr(path, "/usr/share/dreamingos/"))
        return "firmware_seed";
    if (strstr(path, "/usr/share/dreamingwrt/"))
        return "firmware_fallback";
    return "observed_copy";
}

static struct json_object *authority_json(const struct authority_desc *desc)
{
    struct json_object *o = json_object_new_object();
    struct json_object *dups = json_object_new_array();
    struct json_object *present_dups = json_object_new_array();
    struct json_object *mismatch_dups = json_object_new_array();
    struct json_object *writable_dups = json_object_new_array();
    struct json_object *observed = json_object_new_array();
    char sha[65] = {0};
    char active_path[PATH_MAX] = {0};
    struct stat st;
    int exists, canonical_present, schema = -1, sqlite_ok = 0;
    int duplicate_count = 0;
    int present_duplicate_count = 0;
    int content_mismatch_count = 0;
    int writable_duplicate_count = 0;
    int format_conflict = 0;
    size_t i;
    const char *format = "missing";
    const char *state = "missing";
    const char *migration = "none";

    resolve_canonical(desc->duplicates, desc->duplicate_count, active_path,
                      sizeof(active_path));
    canonical_present = access(desc->canonical, R_OK) == 0;
    for (i = 0; i < desc->duplicate_count; i++) {
        struct json_object *path_info = json_object_new_object();
        struct stat path_st;
        char path_sha[65] = {0};
        const char *path_format = "missing";
        int path_present = access(desc->duplicates[i], R_OK) == 0;
        int path_writable = 0;

        if (path_present && stat(desc->duplicates[i], &path_st) == 0 &&
            S_ISREG(path_st.st_mode)) {
            if (dwsig_header(desc->duplicates[i]))
                path_format = "dwsig";
            else if (sqlite_header(desc->duplicates[i]))
                path_format = "sqlite";
            else
                path_format = "unknown";
            (void)file_sha256(desc->duplicates[i], path_sha);
            path_writable = access(desc->duplicates[i], W_OK) == 0;
        } else {
            path_present = 0;
        }
        add_str(path_info, "path", desc->duplicates[i]);
        json_object_object_add(path_info, "present",
                               json_object_new_boolean(path_present));
        json_object_object_add(path_info, "canonical",
                               json_object_new_boolean(
                                   !strcmp(desc->duplicates[i], desc->canonical)));
        json_object_object_add(path_info, "active",
                               json_object_new_boolean(
                                   active_path[0] &&
                                   !strcmp(desc->duplicates[i], active_path)));
        add_str(path_info, "role",
                authority_path_role(desc, desc->duplicates[i]));
        json_object_object_add(path_info, "readable",
                               json_object_new_boolean(path_present));
        json_object_object_add(path_info, "writable",
                               json_object_new_boolean(path_writable));
        json_object_object_add(path_info, "read_only",
                               json_object_new_boolean(path_present && !path_writable));
        add_str(path_info, "format", path_format);
        add_str(path_info, "sha256", path_sha);
        json_object_array_add(observed, path_info);
        if (path_present && strcmp(desc->duplicates[i], desc->canonical)) {
            present_duplicate_count++;
            json_object_array_add(present_dups,
                                  json_object_new_string(desc->duplicates[i]));
            if (path_writable) {
                writable_duplicate_count++;
                json_object_array_add(writable_dups,
                                      json_object_new_string(desc->duplicates[i]));
            }
        }
        if (path_present && !strcmp(desc->name, "signatures") &&
            strstr(desc->duplicates[i], ".dwsig") &&
            !strcmp(path_format, "sqlite"))
            format_conflict = 1;
    }
    exists = active_path[0] && stat(active_path, &st) == 0 && S_ISREG(st.st_mode);
    if (exists) {
        if (dwsig_header(active_path)) {
            format = "dwsig";
            state = "ready";
        } else if (sqlite_header(active_path)) {
            format = "sqlite";
            if (sqlite_schema_version(active_path, &schema, &sqlite_ok) == 0 &&
                sqlite_ok)
                state = "ready";
            else
                state = "degraded";
        } else {
            format = "unknown";
            state = "degraded";
        }
        if (file_sha256(active_path, sha) != 0)
            sha[0] = '\0';
        for (i = 0; i < desc->duplicate_count; i++) {
            char other_sha[65] = {0};
            if (!strcmp(desc->duplicates[i], active_path) ||
                access(desc->duplicates[i], R_OK) != 0 ||
                file_sha256(desc->duplicates[i], other_sha) != 0)
                continue;
            if (sha[0] && !strcmp(sha, other_sha)) {
                json_object_array_add(dups,
                    json_object_new_string(desc->duplicates[i]));
                duplicate_count++;
            } else if (sha[0]) {
                json_object_array_add(mismatch_dups,
                                      json_object_new_string(desc->duplicates[i]));
                content_mismatch_count++;
            }
        }
        if (!canonical_present)
            migration = "degraded_runtime_missing";
        else if (format_conflict)
            migration = "degraded_format_conflict";
        else if (content_mismatch_count)
            migration = "degraded_duplicate_content_mismatch";
        else if (writable_duplicate_count)
            migration = "degraded_writable_duplicate";
        else if (duplicate_count)
            migration = "degraded_duplicate";
        else if (!strcmp(state, "degraded"))
            migration = "degraded_format_or_integrity";
        else
            migration = "stable";
        if (!canonical_present)
            state = "degraded";
    } else if (present_duplicate_count) {
        migration = "degraded_runtime_missing";
    }
    add_str(o, "name", desc->name);
    add_str(o, "role", desc->role);
    add_str(o, "canonical_path", desc->canonical);
    add_str(o, "active_path", active_path);
    add_str(o, "active_role", active_path[0] ?
            authority_path_role(desc, active_path) : "missing");
    json_object_object_add(o, "canonical_present",
                           json_object_new_boolean(canonical_present));
    json_object_object_add(o, "canonical_writable",
                           json_object_new_boolean(canonical_present &&
                                                   access(desc->canonical, W_OK) == 0));
    json_object_object_add(o, "canonical_read_only",
                           json_object_new_boolean(canonical_present &&
                                                   access(desc->canonical, W_OK) != 0));
    add_str(o, "format", format);
    json_object_object_add(o, "schema_version", json_object_new_int(schema));
    add_str(o, "sha256", sha);
    json_object_object_add(o, "duplicate_paths", dups);
    json_object_object_add(o, "duplicate_count", json_object_new_int(duplicate_count));
    json_object_object_add(o, "present_duplicate_paths", present_dups);
    json_object_object_add(o, "present_duplicate_count",
                           json_object_new_int(present_duplicate_count));
    json_object_object_add(o, "content_mismatch_paths", mismatch_dups);
    json_object_object_add(o, "content_mismatch_count",
                           json_object_new_int(content_mismatch_count));
    json_object_object_add(o, "writable_duplicate_paths", writable_dups);
    json_object_object_add(o, "writable_duplicate_count",
                           json_object_new_int(writable_duplicate_count));
    json_object_object_add(o, "path_observations", observed);
    json_object_object_add(o, "format_conflict",
                           json_object_new_boolean(format_conflict));
    json_object_object_add(o, "writer_count",
                           json_object_new_int(active_path[0] ?
                                               path_open_write_count(active_path) : 0));
    json_object_object_add(o, "last_update",
                           json_object_new_int64(exists ? (int64_t)st.st_mtime : 0));
    add_str(o, "migration_state", migration);
    json_object_object_add(o, "migration_allowed",
                           json_object_new_boolean(desc->allow_migration));
    json_object_object_add(o, "ok", json_object_new_boolean(exists &&
                           canonical_present && !strcmp(state, "ready") &&
                           !present_duplicate_count));
    add_str(o, "state", state);
    if (!strcmp(desc->name, "dreamingwrt.db")) {
        add_str(o, "authority_boundary", "control_runtime_local_rescue_only");
        add_str(o, "migration_reason", "core_config_identity_and_runtime_foreign_keys");
    }
    return o;
}

struct json_object *jmx_authority_diagnostics_json(void)
{
    struct authority_desc desc[] = {
        { "signatures", AUTHORITY_SIG_RUNTIME, signature_paths,
          sizeof(signature_paths) / sizeof(signature_paths[0]),
          "dpi_app_carrier_rules", 0 },
        { "fingerprint", AUTHORITY_FP_RUNTIME, fingerprint_paths,
          sizeof(fingerprint_paths) / sizeof(fingerprint_paths[0]),
          "device_fingerprint_catalog", 0 },
        { "dreamingwrt.db", jmx_dataset_path("core"), db_paths,
          sizeof(db_paths) / sizeof(db_paths[0]),
          "control_runtime_identity_network_aegis_foreign_keys", 0 },
    };
    db_paths[0] = jmx_dataset_path("core");
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    int degraded = 0;
    size_t i;

    for (i = 0; i < sizeof(desc) / sizeof(desc[0]); i++) {
        struct json_object *item = authority_json(&desc[i]);
        struct json_object *ok = NULL;
        if (json_object_object_get_ex(item, "ok", &ok) &&
            !json_object_get_boolean(ok))
            degraded = 1;
        if (json_object_object_get_ex(item, "duplicate_count", &ok) &&
            json_object_get_int(ok) > 0)
            degraded = 1;
        if (json_object_object_get_ex(item, "format_conflict", &ok) &&
            json_object_get_boolean(ok))
            degraded = 1;
        json_object_array_add(items, item);
    }
    add_str(root, "contract_version", JMX_AUTHORITY_DIAGNOSTICS_CONTRACT);
    json_object_object_add(root, "degraded", json_object_new_boolean(degraded));
    add_str(root, "reason", degraded ? "authority_duplicate_or_invalid" : "authority_ok");
    json_object_object_add(root, "authorities", items);
    return root;
}
