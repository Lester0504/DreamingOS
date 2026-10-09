// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "storage_provider.h"
#include "storage_supervisor.h"
#include "storage_policy.h"
#include "storage_binding.h"
#include "../jmx_dataset_path.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef STORAGE_PROVIDER_SYSFS
#define STORAGE_PROVIDER_SYSFS "/sys/class/block"
#endif
#ifndef STORAGE_PROVIDER_MOUNTINFO
#define STORAGE_PROVIDER_MOUNTINFO "/proc/self/mountinfo"
#endif
#ifndef STORAGE_PROVIDER_DATA_DIR
#define STORAGE_PROVIDER_DATA_DIR "/etc/dreamingwrt/storage"
#endif
#ifndef STORAGE_PROVIDER_ASSIGNMENTS
#define STORAGE_PROVIDER_ASSIGNMENTS JMX_STORAGE_ASSIGNMENTS_PATH
#endif
#ifndef STORAGE_PROVIDER_PROFILE
#define STORAGE_PROVIDER_PROFILE STORAGE_PROVIDER_DATA_DIR "/profile.json"
#endif

#define STORAGE_PROVIDER_DEFAULT_WARN_BYTES (512ULL * 1024ULL * 1024ULL)
#define STORAGE_PROVIDER_DEFAULT_CRITICAL_BYTES (128ULL * 1024ULL * 1024ULL)
#define STORAGE_PROVIDER_DEFAULT_WARN_PERCENT 85
#define STORAGE_PROVIDER_DEFAULT_CRITICAL_PERCENT 95

struct provider_mount {
    unsigned int major;
    unsigned int minor;
    char source[PATH_MAX];
    char mountpoint[PATH_MAX];
    char fstype[64];
    int read_only;
};

static void copy_text(char *dst, size_t len, const char *src)
{
    size_t n;

    if (!dst || !len)
        return;
    if (!src)
        src = "";
    n = strlen(src);
    if (n >= len)
        n = len - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void prefixed_text(char *dst, size_t len, const char *prefix,
                          const char *value)
{
    size_t prefix_len, value_len, copy_len;

    if (!dst || !len)
        return;
    prefix = prefix ? prefix : "";
    value = value ? value : "";
    prefix_len = strlen(prefix);
    value_len = strlen(value);
    if (prefix_len >= len) {
        memcpy(dst, prefix, len - 1);
        dst[len - 1] = '\0';
        return;
    }
    memcpy(dst, prefix, prefix_len);
    copy_len = value_len < len - prefix_len - 1 ? value_len : len - prefix_len - 1;
    memcpy(dst + prefix_len, value, copy_len);
    dst[prefix_len + copy_len] = '\0';
}

static int read_text(const char *path, char *out, size_t out_len)
{
    FILE *fp;
    size_t n;

    if (!path || !out || out_len < 2)
        return -1;
    out[0] = '\0';
    fp = fopen(path, "re");
    if (!fp)
        return -1;
    n = fread(out, 1, out_len - 1, fp);
    fclose(fp);
    out[n] = '\0';
    while (n && isspace((unsigned char)out[n - 1]))
        out[--n] = '\0';
    return n ? 0 : -1;
}

static int read_u64(const char *path, uint64_t *out)
{
    char value[64];
    char *end = NULL;
    unsigned long long parsed;

    if (!out || read_text(path, value, sizeof(value)) != 0)
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno || end == value || (end && *end))
        return -1;
    *out = (uint64_t)parsed;
    return 0;
}

static int read_dev(const char *path, unsigned int *major_out,
                    unsigned int *minor_out)
{
    char value[64];

    if (!major_out || !minor_out || read_text(path, value, sizeof(value)) != 0)
        return -1;
    return sscanf(value, "%u:%u", major_out, minor_out) == 2 ? 0 : -1;
}

static int is_partition(const char *name)
{
    char path[PATH_MAX];

    if (!name || !name[0] || strchr(name, '/'))
        return 0;
    if (snprintf(path, sizeof(path), STORAGE_PROVIDER_SYSFS "/%s/partition",
                 name) >= (int)sizeof(path))
        return 0;
    return access(path, R_OK) == 0;
}

static int is_protected_mount(const char *mountpoint)
{
    static const char *const protected_paths[] = {
        "/", "/boot", "/data", "/overlay", "/rom", "/tmp", "/run",
        "/etc", "/var", NULL,
    };
    size_t i;

    if (!mountpoint || !mountpoint[0])
        return 0;
    for (i = 0; protected_paths[i]; i++)
        if (!strcmp(mountpoint, protected_paths[i]))
            return 1;
    return 0;
}

static void decode_mountinfo(char *value)
{
    char *src = value;
    char *dst = value;

    if (!value)
        return;
    while (*src) {
        if (src[0] == '\\' && src[1] >= '0' && src[1] <= '7' &&
            src[2] >= '0' && src[2] <= '7' && src[3] >= '0' && src[3] <= '7') {
            *dst++ = (char)(((src[1] - '0') << 6) |
                            ((src[2] - '0') << 3) | (src[3] - '0'));
            src += 4;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static int mount_option_ro(const char *options)
{
    const char *cursor = options;

    if (!options)
        return 0;
    while (*cursor) {
        const char *end = strchr(cursor, ',');
        size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
        if (len == 2 && !strncmp(cursor, "ro", 2))
            return 1;
        if (!end)
            break;
        cursor = end + 1;
    }
    return 0;
}

static int parse_mounts(struct provider_mount *mounts, size_t capacity)
{
    FILE *fp;
    char *line = NULL;
    size_t line_cap = 0;
    int count = 0;

    if (!mounts || !capacity)
        return -1;
    fp = fopen(STORAGE_PROVIDER_MOUNTINFO, "re");
    if (!fp)
        return -1;
    while ((size_t)count < capacity && getline(&line, &line_cap, fp) >= 0) {
        char *fields[192];
        char *save = NULL;
        char *token;
        int n = 0, dash = -1;
        unsigned int major_num, minor_num;

        for (token = strtok_r(line, " ", &save); token && n < 192;
             token = strtok_r(NULL, " ", &save)) {
            token[strcspn(token, "\r\n")] = '\0';
            fields[n++] = token;
            if (!strcmp(token, "-"))
                dash = n - 1;
        }
        if (n < 10 || dash < 6 || dash + 2 >= n ||
            sscanf(fields[2], "%u:%u", &major_num, &minor_num) != 2)
            continue;
        mounts[count].major = major_num;
        mounts[count].minor = minor_num;
        copy_text(mounts[count].mountpoint, sizeof(mounts[count].mountpoint),
                  fields[4]);
        copy_text(mounts[count].fstype, sizeof(mounts[count].fstype),
                  fields[dash + 1]);
        copy_text(mounts[count].source, sizeof(mounts[count].source),
                  fields[dash + 2]);
        decode_mountinfo(mounts[count].mountpoint);
        decode_mountinfo(mounts[count].source);
        mounts[count].read_only = mount_option_ro(fields[5]);
        count++;
    }
    free(line);
    fclose(fp);
    return count;
}

static const struct provider_mount *find_mount(
    const struct provider_mount *mounts, int count,
    unsigned int major_num, unsigned int minor_num)
{
    int i;

    for (i = 0; i < count; i++)
        if (mounts[i].major == major_num && mounts[i].minor == minor_num)
            return &mounts[i];
    return NULL;
}

static int mount_count_for_dev(const struct provider_mount *mounts, int count,
                               unsigned int major_num, unsigned int minor_num)
{
    int i, matches = 0;

    for (i = 0; i < count; i++)
        if (mounts[i].major == major_num && mounts[i].minor == minor_num)
            matches++;
    return matches;
}

static void symlink_value(const char *dir, const char *name, char *out,
                          size_t out_len)
{
    DIR *dp;
    struct dirent *entry;
    char target[PATH_MAX], link_path[PATH_MAX];

    if (!out || !out_len)
        return;
    out[0] = '\0';
    dp = opendir(dir);
    if (!dp)
        return;
    while ((entry = readdir(dp)) != NULL) {
        char *base;

        if (entry->d_name[0] == '.')
            continue;
        if (snprintf(link_path, sizeof(link_path), "%s/%s", dir,
                     entry->d_name) >= (int)sizeof(link_path))
            continue;
        if (!realpath(link_path, target))
            continue;
        base = strrchr(target, '/');
        if (!base || strcmp(base + 1, name))
            continue;
        copy_text(out, out_len, entry->d_name);
        break;
    }
    closedir(dp);
}

static void provider_id(char *out, size_t out_len, const char *device,
                        const char *uuid, const char *label)
{
    if (uuid && uuid[0])
        prefixed_text(out, out_len, "uuid:", uuid);
    else if (label && label[0])
        prefixed_text(out, out_len, "label:", label);
    else
        prefixed_text(out, out_len, "device:", device);
}

int jmx_storage_provider_discover(struct jmx_storage_provider *providers, size_t capacity)
{
    DIR *dir;
    struct dirent *entry;
    struct provider_mount mounts[256];
    int mount_count, count = 0;

    if (!providers || !capacity)
        return -1;
    mount_count = parse_mounts(mounts, sizeof(mounts) / sizeof(mounts[0]));
    if (mount_count < 0)
        mount_count = 0;
    dir = opendir(STORAGE_PROVIDER_SYSFS);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL && (size_t)count < capacity) {
        char path[PATH_MAX];
        unsigned int major_num = 0, minor_num = 0;
        uint64_t sectors = 0;
        const struct provider_mount *mount;
        struct jmx_storage_provider *p;
        const char *name = entry->d_name;

        if (name[0] == '.' || !is_partition(name))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s/size", STORAGE_PROVIDER_SYSFS,
                     name) >= (int)sizeof(path) || read_u64(path, &sectors) != 0 ||
            sectors == 0 || sectors > UINT64_MAX / 512)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s/dev", STORAGE_PROVIDER_SYSFS,
                     name) >= (int)sizeof(path) || read_dev(path, &major_num,
                                                             &minor_num) != 0)
            continue;
        p = &providers[count++];
        memset(p, 0, sizeof(*p));
        snprintf(p->device, sizeof(p->device), "/dev/%s", name);
        p->capacity_bytes = sectors * 512;
        symlink_value("/dev/disk/by-uuid", name, p->uuid, sizeof(p->uuid));
        symlink_value("/dev/disk/by-label", name, p->label, sizeof(p->label));
        provider_id(p->id, sizeof(p->id), p->device, p->uuid, p->label);
        mount = find_mount(mounts, mount_count, major_num, minor_num);
        p->mounted = mount != NULL;
        p->duplicate_mounts = mount_count_for_dev(mounts, mount_count,
                                                  major_num, minor_num);
        p->safe_to_unmount = !mount || (p->duplicate_mounts == 1 &&
                                        !is_protected_mount(mount->mountpoint));
        if (mount) {
            copy_text(p->mountpoint, sizeof(p->mountpoint), mount->mountpoint);
            copy_text(p->filesystem, sizeof(p->filesystem), mount->fstype);
            p->writable = !mount->read_only;
            {
                struct statvfs fs;
                if (statvfs(p->mountpoint, &fs) == 0) {
                    uint64_t block = fs.f_frsize ? fs.f_frsize : fs.f_bsize;
                    p->capacity_bytes = block * (uint64_t)fs.f_blocks;
                    p->available_bytes = block * (uint64_t)fs.f_bavail;
                    p->used_bytes = block *
                        (uint64_t)(fs.f_blocks >= fs.f_bfree ?
                                   fs.f_blocks - fs.f_bfree : 0);
                }
            }
            p->healthy = 1;
            p->eligible = p->safe_to_unmount && p->writable &&
                          p->duplicate_mounts == 1;
            copy_text(p->reason, sizeof(p->reason), p->duplicate_mounts > 1 ?
                      "duplicate_mount" : p->eligible ? "ready" :
                      (mount->read_only ? "read_only" : "system_mount"));
        } else {
            copy_text(p->filesystem, sizeof(p->filesystem), "unknown");
            p->healthy = access(p->device, F_OK) == 0;
            p->writable = 0;
            p->eligible = p->healthy;
            copy_text(p->reason, sizeof(p->reason), p->healthy ? "not_mounted" :
                      "device_unavailable");
        }
    }
    closedir(dir);
    return count;
}

struct storage_pressure {
    uint64_t capacity_bytes;
    uint64_t available_bytes;
    uint64_t used_bytes;
    uint64_t forecast_bytes_per_day;
    int mounted;
    int available_percent;
    int warn_percent;
    int critical_percent;
    uint64_t warn_bytes;
    uint64_t critical_bytes;
    int valid;
};

static uint64_t json_u64(struct json_object *o, const char *key,
                         uint64_t fallback)
{
    struct json_object *value = NULL;
    int64_t parsed;

    if (!o || !json_object_object_get_ex(o, key, &value) || !value)
        return fallback;
    parsed = json_object_get_int64(value);
    return parsed > 0 ? (uint64_t)parsed : fallback;
}

static int json_int(struct json_object *o, const char *key, int fallback)
{
    struct json_object *value = NULL;
    int parsed;

    if (!o || !json_object_object_get_ex(o, key, &value) || !value)
        return fallback;
    parsed = json_object_get_int(value);
    return parsed > 0 && parsed <= 100 ? parsed : fallback;
}

static void storage_profile(struct storage_pressure *profile)
{
    FILE *fp;
    char buf[4096];
    size_t len;
    struct json_object *json;

    memset(profile, 0, sizeof(*profile));
    profile->warn_bytes = STORAGE_PROVIDER_DEFAULT_WARN_BYTES;
    profile->critical_bytes = STORAGE_PROVIDER_DEFAULT_CRITICAL_BYTES;
    profile->warn_percent = STORAGE_PROVIDER_DEFAULT_WARN_PERCENT;
    profile->critical_percent = STORAGE_PROVIDER_DEFAULT_CRITICAL_PERCENT;
    fp = fopen(STORAGE_PROVIDER_PROFILE, "re");
    if (!fp)
        return;
    len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';
    json = json_tokener_parse(buf);
    if (!json)
        return;
    profile->warn_bytes = json_u64(json, "warn_available_bytes", profile->warn_bytes);
    profile->critical_bytes = json_u64(json, "critical_available_bytes", profile->critical_bytes);
    profile->warn_percent = json_int(json, "warn_used_percent", profile->warn_percent);
    profile->critical_percent = json_int(json, "critical_used_percent", profile->critical_percent);
    profile->forecast_bytes_per_day = json_u64(json, "forecast_growth_bytes_per_day", 0);
    if (profile->critical_percent < profile->warn_percent)
        profile->critical_percent = profile->warn_percent;
    if (profile->critical_bytes > profile->warn_bytes)
        profile->critical_bytes = profile->warn_bytes;
    json_object_put(json);
}

static int pressure_read(const char *path, struct storage_pressure *pressure)
{
    struct statvfs fs;
    uint64_t block;

    if (!path || !pressure || statvfs(path, &fs) != 0)
        return -1;
    block = fs.f_frsize ? fs.f_frsize : fs.f_bsize;
    if (!block)
        return -1;
    memset(pressure, 0, sizeof(*pressure));
    pressure->capacity_bytes = block * (uint64_t)fs.f_blocks;
    pressure->available_bytes = block * (uint64_t)fs.f_bavail;
    pressure->used_bytes = block * (uint64_t)(fs.f_blocks >= fs.f_bfree ?
                                               fs.f_blocks - fs.f_bfree : 0);
    pressure->available_percent = pressure->capacity_bytes ?
        (int)((pressure->available_bytes * 100ULL) / pressure->capacity_bytes) : 0;
    pressure->mounted = 1;
    pressure->valid = 1;
    return 0;
}

static void pressure_apply_profile(struct storage_pressure *pressure,
                                   const struct storage_pressure *profile)
{
    if (!pressure || !profile)
        return;
    pressure->forecast_bytes_per_day = profile->forecast_bytes_per_day;
    pressure->warn_percent = profile->warn_percent;
    pressure->critical_percent = profile->critical_percent;
    pressure->warn_bytes = profile->warn_bytes;
    pressure->critical_bytes = profile->critical_bytes;
}

static struct json_object *pressure_json(const struct storage_pressure *p,
                                         const char *path,
                                         const char *profile_name,
                                         const struct storage_pressure *profile)
{
    struct json_object *o = json_object_new_object();
    int used_percent = p->capacity_bytes ?
        (int)((p->used_bytes * 100ULL) / p->capacity_bytes) : 0;
    int critical = p->valid && profile &&
                   (p->available_bytes <= profile->critical_bytes ||
                    used_percent >= profile->critical_percent);
    int warn = p->valid && profile &&
               (p->available_bytes <= profile->warn_bytes ||
                used_percent >= profile->warn_percent);
    json_object_object_add(o, "path", json_object_new_string(path));
    json_object_object_add(o, "profile", json_object_new_string(profile_name));
    json_object_object_add(o, "mounted", json_object_new_boolean(p->mounted));
    json_object_object_add(o, "valid", json_object_new_boolean(p->valid));
    json_object_object_add(o, "capacity_bytes", json_object_new_int64((int64_t)p->capacity_bytes));
    json_object_object_add(o, "available_bytes", json_object_new_int64((int64_t)p->available_bytes));
    json_object_object_add(o, "available_percent", json_object_new_int(p->available_percent));
    json_object_object_add(o, "used_bytes", json_object_new_int64((int64_t)p->used_bytes));
    json_object_object_add(o, "used_percent", json_object_new_int(used_percent));
    json_object_object_add(o, "forecast_growth_bytes_per_day",
                           json_object_new_int64((int64_t)p->forecast_bytes_per_day));
    json_object_object_add(o, "pressure", json_object_new_string(
                           critical ? "critical" : warn ? "warning" : "ok"));
    json_object_object_add(o, "recommend_external_storage",
                           json_object_new_boolean(critical || warn));
    return o;
}

int jmx_storage_provider_has_room(const char *path)
{
    struct storage_pressure p, profile;
    storage_profile(&profile);
    return pressure_read(path, &p) == 0 && p.capacity_bytes &&
           p.available_bytes > profile.critical_bytes &&
           p.used_bytes * 100ULL / p.capacity_bytes < (uint64_t)profile.critical_percent;
}

static struct json_object *load_assignments(void)
{
    struct json_object *empty = json_object_new_object();
    struct json_object *uses = json_object_new_array();
    const char *use;
    FILE *fp;
    char buf[32768];
    size_t len;
    struct json_object *parsed = NULL;
    size_t i;

    fp = fopen(STORAGE_PROVIDER_ASSIGNMENTS, "re");
    if (fp) {
        len = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        buf[len] = '\0';
        parsed = json_tokener_parse(buf);
    }
    for (i = 0; (use = jmx_storage_binding_use(i)) != NULL; i++) {
        struct json_object *item = json_object_new_object();
        struct json_object *src = NULL;
        const char *requested = "";
        char active[128] = "", path[PATH_MAX] = "", state[64] = "", reason[128] = "";
        int valid = jmx_storage_binding_read(use, active, sizeof(active),
            path, sizeof(path), state, sizeof(state), reason, sizeof(reason)) == 0;
        const char *effective = jmx_dataset_path(use);
        if (!valid || !strncmp(effective, "/dev/null/", 10)) {
            copy_text(state, sizeof(state), "unavailable");
            copy_text(reason, sizeof(reason),
                      valid ? "bound_storage_unavailable" : "assignment_invalid");
        }
        if (parsed && json_object_object_get_ex(parsed, use, &src) && src &&
            json_object_is_type(src, json_type_object)) {
            struct json_object *value = NULL;
            if (json_object_object_get_ex(src, "requested_provider", &value) &&
                json_object_is_type(value, json_type_string))
                requested = json_object_get_string(value);
        }
        json_object_object_add(item, "use", json_object_new_string(use));
        json_object_object_add(item, "requested_provider", json_object_new_string(requested ? requested : ""));
        json_object_object_add(item, "active_provider", json_object_new_string(active[0] ? active : "local"));
        json_object_object_add(item, "phase", json_object_new_string("idle"));
        json_object_object_add(item, "state", json_object_new_string(state));
        json_object_object_add(item, "reason", json_object_new_string(reason));
        json_object_object_add(item, "active_path", json_object_new_string(path));
        json_object_object_add(item, "effective_path", json_object_new_string(effective));
        json_object_object_add(item, "migration_state", json_object_new_string(
                               !strcmp(state, "unavailable") ? "unavailable" :
                               path[0] ? "committed" : "not_migrated"));
        json_object_object_add(item, "fallback", json_object_new_boolean(valid && !path[0]));
        json_object_object_add(item, "old_path", json_object_new_string(""));
        json_object_object_add(item, "new_path", json_object_new_string(path));
        json_object_object_add(item, "snapshot_id", json_object_new_string(""));
        json_object_object_add(item, "rollback_available", json_object_new_boolean(0));
        if (valid && src && json_object_is_type(src, json_type_object)) {
            static const char *const metadata[] = {
                "old_path", "new_path", "snapshot_id", "phase", "policy_source"
            };
            struct json_object *value = NULL;
            for (size_t j = 0; j < sizeof(metadata) / sizeof(metadata[0]); j++)
                if (json_object_object_get_ex(src, metadata[j], &value) &&
                    json_object_is_type(value, json_type_string))
                    json_object_object_add(item, metadata[j], json_object_get(value));
            if (json_object_object_get_ex(src, "rollback_available", &value) &&
                json_object_is_type(value, json_type_boolean))
                json_object_object_add(item, "rollback_available", json_object_get(value));
        }
        json_object_array_add(uses, item);
    }
    if (parsed)
        json_object_put(parsed);
    json_object_object_add(empty, "uses", uses);
    return empty;
}

static struct json_object *provider_json(const struct jmx_storage_provider *p)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(p->id));
    json_object_object_add(o, "device", json_object_new_string(p->device));
    json_object_object_add(o, "label", json_object_new_string(p->label));
    json_object_object_add(o, "uuid", json_object_new_string(p->uuid));
    json_object_object_add(o, "filesystem", json_object_new_string(p->filesystem));
    json_object_object_add(o, "mountpoint", json_object_new_string(p->mountpoint));
    json_object_object_add(o, "capacity_bytes", json_object_new_int64((int64_t)p->capacity_bytes));
    json_object_object_add(o, "available_bytes", json_object_new_int64((int64_t)p->available_bytes));
    json_object_object_add(o, "used_bytes", json_object_new_int64((int64_t)p->used_bytes));
    json_object_object_add(o, "mounted", json_object_new_boolean(p->mounted));
    json_object_object_add(o, "writable", json_object_new_boolean(p->writable));
    json_object_object_add(o, "healthy", json_object_new_boolean(p->healthy));
    json_object_object_add(o, "eligible", json_object_new_boolean(p->eligible));
    json_object_object_add(o, "safe_to_unmount", json_object_new_boolean(p->safe_to_unmount));
    json_object_object_add(o, "duplicate_mounts", json_object_new_int(p->duplicate_mounts));
    json_object_object_add(o, "reason", json_object_new_string(p->reason));
    return o;
}

const char *jmx_storage_provider_use_name(enum jmx_storage_provider_use use)
{
    switch (use) {
    case JMX_STORAGE_USE_AUDIT: return "audit";
    case JMX_STORAGE_USE_AEGIS: return "aegis";
    case JMX_STORAGE_USE_LOG: return "log";
    case JMX_STORAGE_USE_SNAPSHOTS: return "snapshots";
    default: return "unknown";
    }
}

struct json_object *jmx_storage_providers_json(void)
{
    struct jmx_storage_provider providers[JMX_STORAGE_PROVIDER_MAX];
    struct json_object *root = json_object_new_object();
    struct json_object *array = json_object_new_array();
    struct storage_pressure profile;
    struct storage_pressure root_pressure, overlay_pressure, data_pressure;
    int count, i, pressure_recommend = 0, ready_provider = 0;
    int recommend = 0;
    const char *recommendation_reason = "storage_ok";

    memset(&root_pressure, 0, sizeof(root_pressure));
    memset(&overlay_pressure, 0, sizeof(overlay_pressure));
    memset(&data_pressure, 0, sizeof(data_pressure));
    storage_profile(&profile);
    (void)pressure_read("/", &root_pressure);
    (void)pressure_read("/overlay", &overlay_pressure);
    (void)pressure_read("/data", &data_pressure);
    pressure_apply_profile(&root_pressure, &profile);
    pressure_apply_profile(&overlay_pressure, &profile);
    pressure_apply_profile(&data_pressure, &profile);

    count = jmx_storage_provider_discover(providers, JMX_STORAGE_PROVIDER_MAX);
    if (count < 0)
        count = 0;
    for (i = 0; i < count; i++) {
        json_object_array_add(array, provider_json(&providers[i]));
        if (providers[i].mounted && providers[i].writable && providers[i].eligible)
            ready_provider++;
    }
    pressure_recommend = (root_pressure.valid &&
                          ((root_pressure.capacity_bytes &&
                            root_pressure.used_bytes * 100ULL /
                            root_pressure.capacity_bytes >=
                            (uint64_t)profile.warn_percent) ||
                           root_pressure.available_bytes <= profile.warn_bytes)) ||
                         (overlay_pressure.valid &&
                          ((overlay_pressure.capacity_bytes &&
                            overlay_pressure.used_bytes * 100ULL /
                            overlay_pressure.capacity_bytes >=
                            (uint64_t)profile.warn_percent) ||
                           overlay_pressure.available_bytes <= profile.warn_bytes)) ||
                         (data_pressure.valid &&
                          ((data_pressure.capacity_bytes &&
                            data_pressure.used_bytes * 100ULL /
                            data_pressure.capacity_bytes >=
                            (uint64_t)profile.warn_percent) ||
                           data_pressure.available_bytes <= profile.warn_bytes));
    if (pressure_recommend) {
        recommend = 1;
        recommendation_reason = "root_overlay_or_data_pressure";
    } else if (!ready_provider) {
        recommend = 1;
        recommendation_reason = count ? "no_ready_external_provider" : "no_external_provider";
    } else {
        recommend = 0;
        recommendation_reason = "storage_ok";
    }
    json_object_object_add(root, "contract_version",
                           json_object_new_string(JMX_STORAGE_PROVIDER_CONTRACT));
    json_object_object_add(root, "providers", array);
    json_object_object_add(root, "recommend_external_storage",
                           json_object_new_boolean(recommend));
    json_object_object_add(root, "recommendation_reason",
                           json_object_new_string(recommendation_reason));
    json_object_object_add(root, "profile", json_object_new_object());
    {
        struct json_object *profile_json = NULL;
        json_object_object_get_ex(root, "profile", &profile_json);
        json_object_object_add(profile_json, "warn_available_bytes",
                               json_object_new_int64((int64_t)profile.warn_bytes));
        json_object_object_add(profile_json, "critical_available_bytes",
                               json_object_new_int64((int64_t)profile.critical_bytes));
        json_object_object_add(profile_json, "warn_used_percent",
                               json_object_new_int(profile.warn_percent));
        json_object_object_add(profile_json, "critical_used_percent",
                               json_object_new_int(profile.critical_percent));
        json_object_object_add(profile_json, "forecast_growth_bytes_per_day",
                               json_object_new_int64((int64_t)profile.forecast_bytes_per_day));
    }
    json_object_object_add(root, "filesystems", json_object_new_array());
    {
        struct json_object *filesystems = NULL;
        json_object_object_get_ex(root, "filesystems", &filesystems);
        json_object_array_add(filesystems, pressure_json(&root_pressure, "/", "rootfs", &profile));
        json_object_array_add(filesystems, pressure_json(&overlay_pressure, "/overlay", "overlay", &profile));
        json_object_array_add(filesystems, pressure_json(&data_pressure, "/data", "data", &profile));
    }
    json_object_object_add(root, "auto_mount_or_format",
                           json_object_new_boolean(0));
    return root;
}

struct json_object *jmx_storage_bindings_json(void)
{
    struct json_object *root = load_assignments();
    json_object_object_add(root, "contract_version",
                           json_object_new_string(JMX_STORAGE_PROVIDER_CONTRACT));
    json_object_object_add(root, "assignment_path",
                           json_object_new_string(STORAGE_PROVIDER_ASSIGNMENTS));
    json_object_object_add(root, "assignment_persistence", json_object_new_string(
                           access(STORAGE_PROVIDER_ASSIGNMENTS, R_OK) == 0 ?
                           "readback" : "default_local"));
    json_object_object_add(root, "sensitive_local_rescue_required",
                           json_object_new_boolean(1));
    return root;
}

struct json_object *jmx_storage_provider_status_json(void)
{
    struct json_object *root = jmx_storage_providers_json();
    struct json_object *bindings = jmx_storage_bindings_json();
    int migration_supported = jmx_storage_supervisor_ready();
    json_object_object_add(root, "bindings", bindings);
    json_object_object_add(root, "migration_supported",
                           json_object_new_boolean(migration_supported));
    json_object_object_add(root, "migration_reason",
                           json_object_new_string(migration_supported ?
                                                   "ready" :
                                                   "supervisor_consumers_unavailable"));
    json_object_object_add(root, "failure_mode", json_object_new_string(
                           "external_storage_unavailable_fail_closed"));
    json_object_object_add(root, "policy", jmx_storage_policy_evaluate(0, NULL, 0, NULL, 0));
    return root;
}
