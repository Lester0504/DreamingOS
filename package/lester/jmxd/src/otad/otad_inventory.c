// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"
#include "otad_inventory_transaction.h"
#include "otad_persist_source.h"

#ifndef OTAD_PERSIST_NEW_DIR
#define OTAD_PERSIST_NEW_DIR "/usr/share/dreamingos/persist.d"
#endif
#ifndef OTAD_PERSIST_LEGACY_DIR
#define OTAD_PERSIST_LEGACY_DIR "/usr/share/dreamingwrt/persist.d"
#endif
#ifndef OTAD_PERSIST_RUNTIME_DIR
#define OTAD_PERSIST_RUNTIME_DIR "/etc/dreamingwrt/persist.d"
#endif

struct scan_stats {
    int files_seen;
    int dirs_seen;
    int package_files;
    int persisted_files;
    int manual_files;
    int unknown_files;
    int errors;
};

static sqlite3_stmt *g_owner_lookup_stmt;

static int path_has_prefix(const char *path, const char *prefix)
{
    size_t n;

    if (!path || !prefix)
        return 0;
    n = strlen(prefix);
    return strncmp(path, prefix, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static int path_excluded(const char *path)
{
    static const char *prefixes[] = {
        "/proc", "/sys", "/dev", "/tmp", "/run", "/mnt", "/overlay",
        "/rom", "/data", NULL
    };
    int i;

    for (i = 0; prefixes[i]; i++) {
        if (path_has_prefix(path, prefixes[i]))
            return 1;
    }
    return 0;
}

static int path_declared_persistent(const struct otad_persist_prefixes *prefixes,
                                    const char *path)
{
    size_t i;

    if (!prefixes || !path)
        return 0;
    for (i = 0; i < prefixes->count; i++)
        if (path_has_prefix(path, prefixes->items[i]))
            return 1;
    return 0;
}

static const char *class_for_path(const struct otad_persist_prefixes *prefixes,
                                  const char *path, const char **policy)
{
    if (policy)
        *policy = "report_only";
    if (path_declared_persistent(prefixes, path) ||
        path_has_prefix(path, "/etc/dreamingwrt") ||
        path_has_prefix(path, "/var/lib/dreamingwrt") ||
        path_has_prefix(path, "/data/dreamingwrt")) {
        if (policy)
            *policy = "preserve";
        return "persisted_data";
    }
    if (path_has_prefix(path, "/usr/local") ||
        path_has_prefix(path, "/opt") ||
        path_has_prefix(path, "/root")) {
        if (policy)
            *policy = "manual_review";
        return "manual_override";
    }
    if (path_has_prefix(path, "/www/dreamingwrt")) {
        if (policy)
            *policy = "slot";
        return "system_owned";
    }
    if (path_has_prefix(path, "/lib/apk") ||
        path_has_prefix(path, "/usr/lib/opkg") ||
        path_has_prefix(path, "/etc/apk") ||
        !strcmp(path, "/etc/board.json") ||
        !strcmp(path, "/etc/dreamingwrt-release.json")) {
        if (policy)
            *policy = "slot";
        return "system_owned";
    }
    return "unknown";
}

static int owner_pkg_for_path(const char *path, char *out, size_t out_len,
                              char *source, size_t source_len)
{
    int rc;
    const char *s;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (source && source_len)
        source[0] = '\0';
    if (!g_owner_lookup_stmt)
        g_owner_lookup_stmt = otad_inventory_prepare(
            "SELECT owner_pkg,source FROM inventory_files "
            "WHERE path=? AND owner_pkg<>'' LIMIT 1");
    if (!g_owner_lookup_stmt)
        return 0;
    sqlite3_reset(g_owner_lookup_stmt);
    sqlite3_clear_bindings(g_owner_lookup_stmt);
    sqlite3_bind_text(g_owner_lookup_stmt, 1, path, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(g_owner_lookup_stmt);
    if (rc == SQLITE_ROW) {
        s = (const char *)sqlite3_column_text(g_owner_lookup_stmt, 0);
        snprintf(out, out_len, "%s", s ? s : "");
        if (source && source_len) {
            s = (const char *)sqlite3_column_text(g_owner_lookup_stmt, 1);
            snprintf(source, source_len, "%s", s ? s : "");
        }
    }
    return out[0] != '\0';
}

static void index_package_file(const char *owner_pkg, const char *path,
                               const char *source,
                               struct scan_stats *stats)
{
    struct stat st;

    if (!owner_pkg || !path || path[0] != '/' || !otad_path_ok(path))
        return;
    if (lstat(path, &st) != 0)
        memset(&st, 0, sizeof(st));
    if (otad_inventory_replace_file(path, owner_pkg, "system_owned", &st,
                                    source, "slot", "") != 0) {
        if (stats)
            stats->errors++;
        return;
    }
    if (stats) {
        stats->files_seen++;
        stats->package_files++;
    }
}

static void scan_package_list_file(const char *pkg, const char *list_path,
                                   const char *source, int relative_paths,
                                   struct scan_stats *stats)
{
    FILE *fp;
    char line[OTAD_MAX_PATH];

    fp = fopen(list_path, "r");
    if (!fp) {
        if (stats)
            stats->errors++;
        return;
    }
    while (fgets(line, sizeof(line), fp)) {
        char absolute[OTAD_MAX_PATH];
        char *start = line;
        char *end;

        while (*start == ' ' || *start == '\t')
            start++;
        end = start + strlen(start);
        while (end > start && (end[-1] == '\r' || end[-1] == '\n' ||
                               end[-1] == ' ' || end[-1] == '\t'))
            *--end = '\0';
        if (!start[0])
            continue;
        if (start[0] == '/') {
            index_package_file(pkg, start, source, stats);
        } else if (relative_paths &&
                   snprintf(absolute, sizeof(absolute), "/%s", start) <
                       (int)sizeof(absolute)) {
            index_package_file(pkg, absolute, source, stats);
        }
    }
    fclose(fp);
}

static void scan_opkg_manifests(struct scan_stats *stats)
{
    DIR *dir;
    struct dirent *de;

    dir = opendir("/usr/lib/opkg/info");
    if (!dir)
        return;
    while ((de = readdir(dir)) != NULL) {
        char path[OTAD_MAX_PATH];
        char pkg[128];
        char *suffix;

        if (de->d_name[0] == '.')
            continue;
        suffix = strstr(de->d_name, ".list");
        if (!suffix || suffix[5] != '\0')
            continue;
        if ((size_t)(suffix - de->d_name) >= sizeof(pkg))
            continue;
        snprintf(pkg, sizeof(pkg), "%.*s", (int)(suffix - de->d_name), de->d_name);
        snprintf(path, sizeof(path), "/usr/lib/opkg/info/%s", de->d_name);
        scan_package_list_file(pkg, path, "opkg_manifest", 0, stats);
    }
    closedir(dir);
}

static void scan_apk_manifests(struct scan_stats *stats)
{
    static const char *manifest_dir = "/lib/apk/packages";
    DIR *dir;
    struct dirent *de;

    dir = opendir(manifest_dir);
    if (!dir)
        return;
    while ((de = readdir(dir)) != NULL) {
        char path[OTAD_MAX_PATH];
        char pkg[128];
        size_t name_len;

        if (de->d_name[0] == '.')
            continue;
        name_len = strlen(de->d_name);
        if (name_len <= 5 || strcmp(de->d_name + name_len - 5, ".list") ||
            name_len - 5 >= sizeof(pkg))
            continue;
        snprintf(pkg, sizeof(pkg), "%.*s", (int)(name_len - 5), de->d_name);
        if (snprintf(path, sizeof(path), "%s/%s", manifest_dir, de->d_name) >=
            (int)sizeof(path))
            continue;
        index_package_file(pkg, path, "apk_manifest", stats);
        scan_package_list_file(pkg, path, "apk_manifest", 1, stats);
    }
    closedir(dir);
}

static void scan_path_recursive(const char *path, int depth, int max_depth,
                                dev_t root_dev,
                                const struct otad_persist_prefixes *prefixes,
                                struct scan_stats *stats)
{
    struct stat st;
    const char *policy;
    const char *class_name;
    char owner[128];
    char owner_source[32];

    if (!path || !otad_path_ok(path) || path_excluded(path))
        return;
    if (lstat(path, &st) != 0) {
        if (stats && !(depth == 0 && errno == ENOENT))
            stats->errors++;
        return;
    }
    if (depth > 0 && root_dev != (dev_t)0 && st.st_dev != root_dev)
        return;

    class_name = class_for_path(prefixes, path, &policy);
    owner_pkg_for_path(path, owner, sizeof(owner), owner_source,
                       sizeof(owner_source));
    if (!owner[0] && S_ISLNK(st.st_mode)) {
        char *resolved = realpath(path, NULL);

        if (resolved && otad_path_ok(resolved) &&
            owner_pkg_for_path(resolved, owner, sizeof(owner), owner_source,
                               sizeof(owner_source)))
            snprintf(owner_source, sizeof(owner_source), "%s", "package_symlink");
        free(resolved);
    }
    if (owner[0])
        class_name = "system_owned";
    if (otad_inventory_replace_file(path, owner, class_name, &st,
                                    owner[0] ? owner_source : "metadata_scan",
                                    policy,
                                    owner[0] ? "" : "no_package_owner") != 0) {
        if (stats)
            stats->errors++;
        return;
    }

    if (stats) {
        if (S_ISDIR(st.st_mode))
            stats->dirs_seen++;
        else
            stats->files_seen++;
        if (owner[0])
            stats->package_files++;
        else if (!strcmp(class_name, "persisted_data"))
            stats->persisted_files++;
        else if (!strcmp(class_name, "manual_override"))
            stats->manual_files++;
        else if (!strcmp(class_name, "unknown"))
            stats->unknown_files++;
    }
    if (!owner[0] && !S_ISDIR(st.st_mode)) {
        if (!strcmp(class_name, "manual_override")) {
            if (otad_inventory_add_unknown(path, "manual_override",
                                           "manual_review", &st, 0) != 0 &&
                stats)
                stats->errors++;
        } else if (!strcmp(class_name, "unknown")) {
            if (otad_inventory_add_unknown(path, "no_package_owner",
                                           "report_only", &st, 0) != 0 &&
                stats)
                stats->errors++;
        }
    }

    if (S_ISDIR(st.st_mode) && (max_depth == 0 || depth < max_depth)) {
        DIR *dir = opendir(path);
        struct dirent *de;

        if (!dir) {
            if (stats)
                stats->errors++;
            return;
        }
        while ((de = readdir(dir)) != NULL) {
            char child[OTAD_MAX_PATH];

            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >= (int)sizeof(child))
                continue;
            scan_path_recursive(child, depth + 1, max_depth, root_dev, prefixes, stats);
        }
        closedir(dir);
    }
}

static void scan_metadata_roots(struct scan_stats *stats, int max_depth,
                                const struct otad_persist_prefixes *prefixes)
{
    static const char *roots[] = {
        "/bin", "/sbin", "/lib", "/usr", "/etc", "/root", "/opt", "/www", NULL
    };
    int i;

    for (i = 0; roots[i]; i++) {
        struct stat st;

        if (lstat(roots[i], &st) != 0) {
            if (errno != ENOENT && stats)
                stats->errors++;
            continue;
        }
        scan_path_recursive(roots[i], 0, max_depth, st.st_dev, prefixes, stats);
    }
}

struct inventory_scan_work {
    struct scan_stats *stats;
    const struct otad_persist_prefixes *prefixes;
    int max_depth;
    int include_apk;
    int include_opkg;
    int include_metadata;
};

static int inventory_scan_transaction_work(void *opaque)
{
    struct inventory_scan_work *work = opaque;

    if (otad_inventory_clear_unknowns() != 0)
        work->stats->errors++;
    if (work->include_apk)
        scan_apk_manifests(work->stats);
    if (work->include_opkg)
        scan_opkg_manifests(work->stats);
    if (work->include_metadata)
        scan_metadata_roots(work->stats, work->max_depth, work->prefixes);
    if (g_owner_lookup_stmt) {
        sqlite3_finalize(g_owner_lookup_stmt);
        g_owner_lookup_stmt = NULL;
    }
    return work->stats->errors ? -1 : 0;
}

struct json_object *otad_inventory_scan(struct json_object *body)
{
    struct scan_stats stats;
    struct otad_persist_prefixes prefixes;
    struct otad_persist_source_status source_status;
    struct inventory_scan_work work;
    struct json_object *resp = json_object_new_object();
    int max_depth = otad_json_int(body, "max_depth", 0);
    int include_apk = otad_json_bool(body, "include_apk", 1);
    int include_opkg = otad_json_bool(body, "include_opkg", 1);
    int include_metadata = otad_json_bool(body, "include_metadata", 1);
    char transaction_error[64];
    int inventory_unchanged = 1;

    if (max_depth < 0)
        max_depth = 0;
    if (max_depth > 64)
        max_depth = 64;
    memset(&stats, 0, sizeof(stats));
    if (otad_persist_sources_load(OTAD_PERSIST_NEW_DIR, OTAD_PERSIST_LEGACY_DIR,
                                  OTAD_PERSIST_RUNTIME_DIR, &prefixes,
                                  &source_status) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error",
                               json_object_new_string("persist_source_preflight_failed"));
        otad_json_add_string(resp, "reason", source_status.error);
        json_object_object_add(resp, "inventory_unchanged", json_object_new_boolean(1));
        json_object_object_add(resp, "transaction_started", json_object_new_boolean(0));
        otad_persist_prefixes_free(&prefixes);
        return resp;
    }
    memset(&work, 0, sizeof(work));
    work.stats = &stats;
    work.prefixes = &prefixes;
    work.max_depth = max_depth;
    work.include_apk = include_apk;
    work.include_opkg = include_opkg;
    work.include_metadata = include_metadata;
    if (otad_inventory_run_transaction(g_otad_inventory_db,
                                       inventory_scan_transaction_work, &work,
                                       &inventory_unchanged, transaction_error,
                                       sizeof(transaction_error)) != 0) {
        if (g_owner_lookup_stmt) {
            sqlite3_finalize(g_owner_lookup_stmt);
            g_owner_lookup_stmt = NULL;
        }
        otad_persist_prefixes_free(&prefixes);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        otad_json_add_string(resp, "error", transaction_error);
        json_object_object_add(resp, "inventory_unchanged",
                               json_object_new_boolean(inventory_unchanged));
        json_object_object_add(resp, "errors", json_object_new_int(stats.errors));
        return resp;
    }
    otad_persist_prefixes_free(&prefixes);

    {
        char ts[32];

        snprintf(ts, sizeof(ts), "%lld", (long long)otad_now_s());
        otad_state_set("last_inventory_scan_at", ts);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "max_depth", json_object_new_int(max_depth));
    json_object_object_add(resp, "full_tree", json_object_new_boolean(max_depth == 0));
    json_object_object_add(resp, "include_apk", json_object_new_boolean(include_apk));
    json_object_object_add(resp, "include_opkg", json_object_new_boolean(include_opkg));
    json_object_object_add(resp, "files_seen", json_object_new_int(stats.files_seen));
    json_object_object_add(resp, "dirs_seen", json_object_new_int(stats.dirs_seen));
    json_object_object_add(resp, "package_files", json_object_new_int(stats.package_files));
    json_object_object_add(resp, "persisted_files", json_object_new_int(stats.persisted_files));
    json_object_object_add(resp, "manual_files", json_object_new_int(stats.manual_files));
    json_object_object_add(resp, "unknown_files", json_object_new_int(stats.unknown_files));
    json_object_object_add(resp, "errors", json_object_new_int(stats.errors));
    json_object_object_add(resp, "unknown_policy", json_object_new_string("report_only"));
    json_object_object_add(resp, "persist_source_new_only",
                           json_object_new_int(source_status.new_only));
    json_object_object_add(resp, "persist_source_legacy_only",
                           json_object_new_int(source_status.legacy_only));
    json_object_object_add(resp, "persist_source_identical_new",
                           json_object_new_int(source_status.identical_new));
    json_object_object_add(resp, "persist_source_runtime_files",
                           json_object_new_int(source_status.runtime_files));
    json_object_object_add(resp, "persist_runtime_authority",
                           json_object_new_string(OTAD_PERSIST_RUNTIME_DIR));
    json_object_object_add(resp, "inventory_unchanged",
                           json_object_new_boolean(inventory_unchanged));
    return resp;
}

struct json_object *otad_unknowns_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st;
    int limit = otad_json_int(body, "limit", 200);
    int total = 0;

    if (limit <= 0)
        limit = 200;
    if (limit > OTAD_MAX_UNKNOWN_RESULTS)
        limit = OTAD_MAX_UNKNOWN_RESULTS;
    st = otad_inventory_prepare("SELECT path,reason,suggested_action,size,mtime,will_preserve FROM inventory_unknowns ORDER BY path LIMIT ?");
    if (!st) {
        json_object_put(arr);
        return otad_error("query_failed", "failed to query inventory_unknowns");
    }
    sqlite3_bind_int(st, 1, limit);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        const char *path = (const char *)sqlite3_column_text(st, 0);
        const char *reason = (const char *)sqlite3_column_text(st, 1);
        const char *action = (const char *)sqlite3_column_text(st, 2);

        otad_json_add_string(o, "path", path);
        otad_json_add_string(o, "reason", reason);
        otad_json_add_string(o, "suggested_action", action);
        json_object_object_add(o, "size", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(o, "mtime", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(o, "will_preserve", json_object_new_boolean(sqlite3_column_int(st, 5) != 0));
        json_object_array_add(arr, o);
        total++;
    }
    sqlite3_finalize(st);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "policy", json_object_new_string("report_only"));
    json_object_object_add(resp, "count", json_object_new_int(total));
    json_object_object_add(resp, "items", arr);
    return resp;
}
