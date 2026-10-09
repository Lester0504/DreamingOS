// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "data_storage.h"
#include "storage_files.h"
#ifndef DATA_STORAGE_TEST_UUIDS
#include <blkid/blkid.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#ifndef DATA_STORAGE_CONFIG
#define DATA_STORAGE_CONFIG "/etc/dreamingwrt/data-storage.json"
#endif
#define APPLY_POLICY "new_service_or_restart"

static const char *str(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) &&
        json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}
static void add(struct json_object *o, const char *k, const char *v)
{ json_object_object_add(o, k, json_object_new_string(v)); }
static void flag(struct json_object *o, const char *k, int v)
{ json_object_object_add(o, k, json_object_new_boolean(v)); }
static int truth(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, k, &v) && json_object_get_boolean(v);
}

/* Probe the actual mounted block device, never a cache keyed by /dev/sdX.
 * The test map is compiled into fixture binaries only. */
static void disk_uuid(const char *source, char *uuid, size_t size)
{
    uuid[0] = '\0';
#ifdef DATA_STORAGE_TEST_UUIDS
    struct json_object *map = json_object_from_file(DATA_STORAGE_TEST_UUIDS);
    snprintf(uuid, size, "%s", str(map, source));
    if (map) json_object_put(map);
#else
    struct stat st;
    if (strncmp(source, "/dev/", 5) || stat(source, &st) || !S_ISBLK(st.st_mode))
        return;
    blkid_probe probe = blkid_new_probe_from_filename(source);
    if (!probe) return;
    const char *value = NULL;
    size_t len = 0;
    if (!blkid_do_safeprobe(probe) &&
        !blkid_probe_lookup_value(probe, "UUID", &value, &len) &&
        value && len > 0 && len < size)
        snprintf(uuid, size, "%s", value);
    blkid_free_probe(probe);
#endif
}

static struct json_object *roots(void)
{
    struct json_object *list = storage_files_roots_json();
    if (!list) return NULL;
    for (size_t i = 0; i < json_object_array_length(list); i++) {
        struct json_object *r = json_object_array_get_idx(list, i);
        char uuid[160], canonical[PATH_MAX];
        const char *reason = "";
        disk_uuid(str(r, "source"), uuid, sizeof(uuid));
        int fd = storage_files_open_dir(str(r, "id"), str(r, "path"), 1,
                                         canonical, sizeof(canonical), &reason);
        if (fd >= 0) {
            struct statvfs fs;
            if (fstatvfs(fd, &fs) || (fs.f_flag & ST_RDONLY))
                reason = "storage_root_read_only";
            close(fd);
        }
        if (!strcmp(str(r, "path"), "/overlay")) reason = "system_storage_root";
        if (!reason[0] && !uuid[0]) reason = "persistent_identity_unavailable";
        add(r, "root_id", str(r, "id"));
        add(r, "uuid", uuid);
        flag(r, "selectable", !reason[0]);
        add(r, "reason", reason);
    }
    return list;
}

static struct json_object *load_default(void)
{
    struct json_object *o = json_object_from_file(DATA_STORAGE_CONFIG);
    if (o && json_object_is_type(o, json_type_object)) return o;
    if (o) json_object_put(o);
    o = json_object_new_object();
    add(o, "reason", access(DATA_STORAGE_CONFIG, F_OK) == 0 ?
        "default_config_invalid" : errno == ENOENT ? "not_configured" :
        "default_config_unavailable");
    return o;
}

static int identity_equal(struct json_object *a, struct json_object *b)
{
    const char *keys[] = {"uuid", "fstype", "mount_root", "relative_path", NULL};
    for (int i = 0; keys[i]; i++)
        if (strcmp(str(a, keys[i]), str(b, keys[i]))) return 0;
    return str(a, "uuid")[0] != '\0';
}

static struct json_object *resolve(struct json_object *saved, struct json_object *list)
{
    struct json_object *o = json_object_new_object(), *match = NULL;
    const char *reason = str(saved, "reason");
    char path[PATH_MAX] = "", canonical[PATH_MAX];
    const char *uuid = str(saved, "uuid");
    int configured = uuid[0] || strcmp(reason, "not_configured");
    add(o, "uuid", uuid);
    add(o, "mount_root", str(saved, "mount_root"));
    add(o, "relative_path", str(saved, "relative_path"));
    add(o, "fstype", str(saved, "fstype"));
    add(o, "root_id", "");
    add(o, "path", str(saved, "path"));
    add(o, "mount_path", str(saved, "mount_path"));
    flag(o, "configured", configured);
    if (!uuid[0]) {
        if (!reason[0]) reason = "default_config_invalid";
        goto done;
    }
    if (!str(saved, "mount_root")[0] || !str(saved, "fstype")[0] ||
        !str(saved, "relative_path")[0]) { reason = "default_config_invalid"; goto done; }
    if (!list) { reason = "storage_inventory_unavailable"; goto done; }
    reason = "storage_identity_unavailable";
    for (size_t i = 0; i < json_object_array_length(list); i++) {
        struct json_object *r = json_object_array_get_idx(list, i);
        if (strcmp(uuid, str(r, "uuid")) ||
            strcmp(str(saved, "fstype"), str(r, "fstype")) ||
            strcmp(str(saved, "mount_root"), str(r, "mount_root"))) continue;
        /* Duplicate mounts/cloned UUIDs are ambiguous; never pick the first. */
        if (match) { reason = "storage_identity_ambiguous"; match = NULL; goto done; }
        match = r;
    }
    if (!match) goto done;
    add(o, "root_id", str(match, "id"));
    add(o, "mount_path", str(match, "path"));
    if (!truth(match, "selectable")) { reason = str(match, "reason"); goto done; }
    const char *relative = str(saved, "relative_path");
    if (relative[0] != '/' || snprintf(path, sizeof(path), "%s%s",
        str(match, "path"), !strcmp(relative, "/") ? "" : relative) >= (int)sizeof(path)) {
        reason = "invalid_relative_path"; goto done;
    }
    int fd = storage_files_open_dir(str(match, "id"), path, 1,
                                     canonical, sizeof(canonical), &reason);
    if (fd < 0) goto done;
    close(fd);
    add(o, "path", canonical);
    reason = "";
done:
    flag(o, "available", !reason[0]);
    add(o, "reason", reason);
    return o;
}

static int persist(struct json_object *o)
{
    char temp[PATH_MAX], parent[PATH_MAX];
    if (snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", DATA_STORAGE_CONFIG) >=
        (int)sizeof(temp)) return -1;
    snprintf(parent, sizeof(parent), "%s", DATA_STORAGE_CONFIG);
    char *slash = strrchr(parent, '/');
    if (!slash) return -1;
    *slash = '\0';
    int dir = open(parent[0] ? parent : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return -1;
    int fd = mkstemp(temp), result = -1;
    if (fd >= 0) {
        if (!json_object_to_fd(fd, o, JSON_C_TO_STRING_PLAIN) && !fsync(fd) &&
            !rename(temp, DATA_STORAGE_CONFIG) && !fsync(dir)) result = 0;
        close(fd);
        unlink(temp);
    }
    close(dir);
    return result;
}

struct json_object *data_storage_response(struct json_object *selection, int *http)
{
    struct json_object *list = roots(), *saved = NULL, *data = json_object_new_object();
    const char *error = "";
    *http = 200;
    if (selection) {
        struct json_object *match = NULL;
        if (!str(selection, "root_id")[0] || !str(selection, "path")[0]) {
            error = "root_id_and_path_required"; *http = 400; goto done;
        }
        if (!list) { error = "storage_inventory_unavailable"; *http = 503; goto done; }
        for (size_t i = 0; i < json_object_array_length(list); i++) {
            struct json_object *r = json_object_array_get_idx(list, i);
            if (!strcmp(str(r, "id"), str(selection, "root_id"))) match = r;
        }
        if (!match || !truth(match, "selectable")) {
            error = match ? str(match, "reason") : "storage_root_not_found";
            *http = 409; goto done;
        }
        char canonical[PATH_MAX];
        int fd = storage_files_open_dir(str(match, "id"), str(selection, "path"), 1,
                                        canonical, sizeof(canonical), &error);
        if (fd < 0) { *http = 409; goto done; }
        close(fd);
        saved = json_object_new_object();
        add(saved, "uuid", str(match, "uuid"));
        add(saved, "fstype", str(match, "fstype"));
        add(saved, "mount_root", str(match, "mount_root"));
        add(saved, "mount_path", str(match, "path"));
        add(saved, "path", canonical);
        const char *relative = canonical + strlen(str(match, "path"));
        add(saved, "relative_path", relative[0] ? relative : "/");
        struct json_object *verified = resolve(saved, list);
        if (!truth(verified, "available")) {
            add(data, "error", str(verified, "reason"));
            json_object_put(verified); *http = 409; goto done;
        }
        json_object_put(verified);
        if (persist(saved)) { error = "default_config_save_failed"; *http = 500; }
    }
done:
    if (error[0]) add(data, "error", error);
    if (saved) json_object_put(saved);
    saved = load_default();
    json_object_object_add(data, "default", resolve(saved, list));
    json_object_put(saved);
    json_object_object_add(data, "roots", list ? list : json_object_new_array());
    add(data, "contract_version", "data-storage.v1");
    add(data, "apply_policy", APPLY_POLICY);
    flag(data, "migration_performed", 0);
    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "code", json_object_new_int(*http < 400 ? 2000 : 4000));
    json_object_object_add(out, "data", data);
    return out;
}

struct json_object *data_storage_app_load(const char *config_file)
{
    struct json_object *app = json_object_from_file(config_file);
    int invalid = !app && access(config_file, F_OK) == 0;
    if (app && (!json_object_is_type(app, json_type_object) ||
                str(app, "root_id")[0] || str(app, "path")[0])) invalid = 1;
    if (invalid) {
        if (!app || !json_object_is_type(app, json_type_object)) {
            if (app) json_object_put(app);
            app = json_object_new_object();
        }
        add(app, "source", "explicit");
        return app;
    }
    if (app) json_object_put(app);
    app = load_default();
    add(app, "source", !strcmp(str(app, "reason"), "not_configured") ?
        "unconfigured" : "default");
    return app;
}

struct json_object *data_storage_app_resolve(struct json_object *snapshot)
{
    const char *source = str(snapshot, "source");
    struct json_object *o;
    int pending = 0;
    if (!strcmp(source, "explicit")) {
        o = json_object_new_object();
        char canonical[PATH_MAX];
        const char *reason = "invalid_explicit_storage";
        int fd = -1;
        if (str(snapshot, "root_id")[0] && str(snapshot, "path")[0])
            fd = storage_files_open_dir(str(snapshot, "root_id"), str(snapshot, "path"),
                                        1, canonical, sizeof(canonical), &reason);
        if (fd >= 0) { close(fd); reason = ""; }
        add(o, "root_id", str(snapshot, "root_id"));
        add(o, "path", fd >= 0 ? canonical : str(snapshot, "path"));
        add(o, "reason", reason);
        flag(o, "available", fd >= 0);
        flag(o, "configured", 1);
    } else {
        struct json_object *list = roots();
        o = resolve(snapshot, list);
        if (list) json_object_put(list);
        struct json_object *current = load_default();
        pending = !strcmp(source, "default") && !identity_equal(snapshot, current);
        json_object_put(current);
    }
    add(o, "source", source[0] ? source : "unconfigured");
    add(o, "apply_policy", APPLY_POLICY);
    flag(o, "pending_default", pending);
    return o;
}
