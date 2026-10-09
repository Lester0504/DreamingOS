// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "storage_policy.h"
#include "storage_provider.h"
#include "../dwrt_features.h"
#include "../jmx_exec.h"

#include <blkid/blkid.h>
#include <uci.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#ifndef STORAGE_POLICY_SYSFS
#define STORAGE_POLICY_SYSFS "/sys"
#endif
#ifndef STORAGE_POLICY_MOUNTINFO
#define STORAGE_POLICY_MOUNTINFO "/proc/self/mountinfo"
#endif

struct disks {
    char names[32][NAME_MAX + 1];
    size_t count;
};

static void text(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

static int read_line(const char *path, char *out, size_t size)
{
    FILE *fp = fopen(path, "re");
    if (!fp)
        return -1;
    int ok = fgets(out, size, fp) != NULL;
    fclose(fp);
    if (ok)
        out[strcspn(out, "\r\n")] = '\0';
    return ok ? 0 : -1;
}

static int disk_add(struct disks *set, const char *name)
{
    for (size_t i = 0; i < set->count; i++)
        if (!strcmp(set->names[i], name))
            return 0;
    if (set->count >= 32 || strlen(name) > NAME_MAX)
        return -1;
    snprintf(set->names[set->count++], NAME_MAX + 1, "%s", name);
    return 0;
}

static int physical_node(const char *node, struct disks *out, unsigned depth)
{
    char real[PATH_MAX], path[PATH_MAX], value[PATH_MAX];
    struct stat st;
    if (depth > 16 || !realpath(node, real))
        return -1;
    if (snprintf(path, sizeof(path), "%s/partition", real) >= (int)sizeof(path))
        return -1;
    if (access(path, F_OK) == 0) {
        char *slash = strrchr(real, '/');
        if (!slash)
            return -1;
        *slash = '\0';
        return physical_node(real, out, depth + 1);
    }
    if (snprintf(path, sizeof(path), "%s/slaves", real) >= (int)sizeof(path))
        return -1;
    DIR *dir = opendir(path);
    struct dirent *entry;
    int children = 0, failed = 0;
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;
            children++;
            if (snprintf(path, sizeof(path), "%s/slaves/%s", real, entry->d_name) >=
                (int)sizeof(path) || physical_node(path, out, depth + 1) != 0)
                failed = 1;
        }
        closedir(dir);
    }
    if (children)
        return failed ? -1 : 0;
    /* OpenWrt fitblk publishes lower_dev on the parent platform device,
     * not in the child disk's slaves directory. */
    const char *fit = strstr(real, "/fitblk/");
    if (fit) {
        size_t prefix = (size_t)(fit - real) + strlen("/fitblk");
        if (snprintf(path, sizeof(path), "%.*s/lower_dev", (int)prefix, real) >=
            (int)sizeof(path))
            return -1;
        return physical_node(path, out, depth + 1);
    }
    if (snprintf(path, sizeof(path), "%s/loop/backing_file", real) >= (int)sizeof(path))
        return -1;
    if (read_line(path, value, sizeof(value)) == 0) {
        if (value[0] != '/' || stat(value, &st) != 0 ||
            snprintf(path, sizeof(path), STORAGE_POLICY_SYSFS "/dev/block/%u:%u",
                     major(st.st_dev), minor(st.st_dev)) >= (int)sizeof(path))
            return -1;
        return physical_node(path, out, depth + 1);
    }
    /* Unresolved virtual devices (including fitrw without slaves) are not
     * guessed to be data disks. The caller records unknown and stops selection. */
    if (strstr(real, "/virtual/") || !strstr(real, "/devices/"))
        return -1;
    const char *base = strrchr(real, '/');
    return base ? disk_add(out, base + 1) : -1;
}

static int system_disks(struct disks *out)
{
    FILE *fp = fopen(STORAGE_POLICY_MOUNTINFO, "re");
    char *line = NULL;
    size_t cap = 0;
    int roots = 0, failed = 0;
    if (!fp)
        return -1;
    while (getline(&line, &cap, fp) >= 0) {
        unsigned a, b;
        char root[PATH_MAX], mountpoint[PATH_MAX], fs[64], source[PATH_MAX];
        char *sep = strstr(line, " - ");
        if (!sep || sscanf(line, "%*u %*u %u:%u %4095s %4095s",
                            &a, &b, root, mountpoint) != 4 ||
            sscanf(sep + 3, "%63s %4095s", fs, source) != 2)
            continue;
        if (strcmp(mountpoint, "/") && strcmp(mountpoint, "/overlay") &&
            strcmp(mountpoint, "/rom") && strcmp(mountpoint, "/boot"))
            continue;
        char path[PATH_MAX];
        if (!strcmp(fs, "overlay")) {
            char *upper = strstr(sep + 3, "upperdir=");
            if (!upper) {
                failed = 1;
                continue;
            }
            upper += 9;
            size_t n = strcspn(upper, ", \n");
            struct stat st;
            if (!n || n >= sizeof(path)) {
                failed = 1;
                continue;
            }
            memcpy(path, upper, n);
            path[n] = '\0';
            if (strchr(path, '\\') || stat(path, &st) != 0) {
                failed = 1;
                continue;
            }
            a = major(st.st_dev);
            b = minor(st.st_dev);
        }
        roots++;
        snprintf(path, sizeof(path), STORAGE_POLICY_SYSFS "/dev/block/%u:%u", a, b);
        if (physical_node(path, out, 0) != 0)
            failed = 1;
    }
    free(line);
    fclose(fp);
    return roots && out->count && !failed ? 0 : -1;
}

static const char *media_class(const struct disks *disk, char *reason, size_t len)
{
    char path[PATH_MAX], real[PATH_MAX], value[128];
    if (disk->count != 1)
        return "unknown";
    const char *name = disk->names[0];
    snprintf(path, sizeof(path), STORAGE_POLICY_SYSFS "/class/block/%s", name);
    if (!realpath(path, real))
        return "unknown";
    snprintf(path, sizeof(path), STORAGE_POLICY_SYSFS "/class/block/%s/device/type", name);
    if (read_line(path, value, sizeof(value)) == 0) {
        if (!strcmp(value, "MMC"))
            return "emmc";
        if (!strcmp(value, "SD"))
            return "sd";
    }
    if (strstr(real, "/nvme/"))
        return "nvme";
    if (strstr(real, "/usb")) {
        snprintf(path, sizeof(path), STORAGE_POLICY_SYSFS "/class/block/%s/queue/rotational", name);
        if (read_line(path, value, sizeof(value)) == 0 && !strcmp(value, "1"))
            return "disk";
        snprintf(reason, len, "usb_ssd_or_flash_unresolved_classified_usb");
        return "usb";
    }
    if (strstr(real, "/ata") || strstr(real, "/host"))
        return "disk";
    return "unknown";
}

static int authorized(const char *uuid, char *target, size_t size, const char **reason)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *entry;
    int matches = 0, allowed = 0;
    *reason = "data_partition_not_authorized";
    if (!ctx)
        return 0;
#ifdef STORAGE_POLICY_UCI_CONFIG_DIR
    uci_set_confdir(ctx, STORAGE_POLICY_UCI_CONFIG_DIR);
#endif
    if (uci_load(ctx, "fstab", &pkg) != UCI_OK)
        goto done;
    uci_foreach_element(&pkg->sections, entry) {
        struct uci_section *section = uci_to_section(entry);
        const char *id = uci_lookup_option_string(ctx, section, "uuid");
        if (strcmp(section->type, "mount") || !id || strcmp(id, uuid))
            continue;
        matches++;
        const char *enabled = uci_lookup_option_string(ctx, section, "enabled");
        const char *data = uci_lookup_option_string(ctx, section, "dreamingos_data");
        const char *path = uci_lookup_option_string(ctx, section, "target");
        if (!enabled || strcmp(enabled, "1")) {
            *reason = "fstab_disabled";
            continue;
        }
        if (!data || strcmp(data, "1"))
            continue;
        if (!path || !dwrt_features_work_dir_ok(path) || strlen(path) >= size) {
            *reason = "fstab_target_invalid";
            continue;
        }
        snprintf(target, size, "%s", path);
        allowed = 1;
    }
    if (matches > 1) {
        *reason = "duplicate_fstab_uuid";
        allowed = 0;
    }
    if (allowed)
        *reason = "eligible";
done:
    uci_free_context(ctx);
    return allowed;
}

static int priority_rank(const char *priority, const char *media)
{
    const char *p = priority;
    int rank = 0;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (strlen(media) == n && !strncmp(p, media, n))
            return rank;
        if (!end)
            break;
        p = end + 1;
        rank++;
    }
    return 99;
}

static int mounted_on(const struct jmx_storage_provider *p, const char *target)
{
    struct stat device, mountpoint;
    return stat(p->device, &device) == 0 && S_ISBLK(device.st_mode) &&
           stat(target, &mountpoint) == 0 && S_ISDIR(mountpoint.st_mode) &&
           device.st_rdev == mountpoint.st_dev &&
           dwrt_features_work_dir_usable(target, NULL, 0);
}

static int empty_mountpoint(const char *target)
{
    struct stat st;
    if ((mkdir(target, 0750) != 0 && errno != EEXIST) ||
        lstat(target, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    DIR *dir = opendir(target);
    struct dirent *entry;
    int empty = 1;
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            empty = 0;
            break;
        }
    closedir(dir);
    return empty;
}

static long long monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

struct json_object *jmx_storage_policy_evaluate(int prepare, char *selected,
                                               size_t selected_len,
                                               char *provider, size_t provider_len)
{
    struct dwrt_features build, user;
    struct jmx_storage_provider *items = calloc(JMX_STORAGE_PROVIDER_MAX, sizeof(*items));
    struct disks system = {0};
    struct json_object *out = json_object_new_object(), *candidates = json_object_new_array();
    if (selected && selected_len) selected[0] = '\0';
    if (provider && provider_len) provider[0] = '\0';
    memset(&build, 0, sizeof(build));
    memset(&user, 0, sizeof(user));
    (void)dwrt_features_load(DWRT_DEVICE_PRESET_PATH, &build, NULL, NULL);
    if (build.preset_version != 1)
        memset(&build, 0, sizeof(build));
    (void)dwrt_features_load(DWRT_FEATURES_PATH, &user, NULL, NULL);
    const char *mode = user.data_storage[0] ? user.data_storage : build.data_storage;
    const char *priority = user.storage_priority[0] ? user.storage_priority :
                           build.storage_priority[0] ? build.storage_priority :
                           "nvme,disk,usb,sd,emmc,system";
    int automount = user.has_automount ? user.storage_automount : build.storage_automount;
    text(out, "policy_source", user.data_storage[0] ? "user_features" : "build_default");
    text(out, "mode", mode[0] ? mode : "legacy");
    text(out, "requested_priority", priority);
    json_object_object_add(out, "candidates", candidates);
    json_object_object_add(out, "automount", json_object_new_boolean(automount));
    text(out, "reason", "legacy_policy");
    if (strcmp(mode, "auto") || !items)
        goto done;
    int system_known = system_disks(&system) == 0;
    int count = jmx_storage_provider_discover(items, JMX_STORAGE_PROVIDER_MAX);
    int eligible[JMX_STORAGE_PROVIDER_MAX] = {0};
    for (int i = 0; i < count; i++) {
        struct jmx_storage_provider *p = &items[i];
        struct disks disks = {0};
        char path[PATH_MAX], detail[128] = "", target[PATH_MAX] = "";
        struct json_object *row = json_object_new_object();
        const char *name = strrchr(p->device, '/');
        const char *reason = "eligible", *media = "unknown";
        int system_backing = 0;
        snprintf(path, sizeof(path), STORAGE_POLICY_SYSFS "/class/block/%s", name ? name + 1 : "");
        int identified = physical_node(path, &disks, 0) == 0;
        if (identified)
            media = media_class(&disks, detail, sizeof(detail));
        for (size_t a = 0; a < disks.count; a++)
            for (size_t b = 0; b < system.count; b++)
                system_backing |= !strcmp(disks.names[a], system.names[b]);
        blkid_probe probe = blkid_new_probe_from_filename(p->device);
        if (probe && blkid_do_safeprobe(probe) == 0) {
            const char *value = NULL;
            if (blkid_probe_lookup_value(probe, "UUID", &value, NULL) == 0)
                snprintf(p->uuid, sizeof(p->uuid), "%s", value);
            if (blkid_probe_lookup_value(probe, "TYPE", &value, NULL) == 0)
                snprintf(p->filesystem, sizeof(p->filesystem), "%s", value);
        }
        if (probe) blkid_free_probe(probe);
        snprintf(p->id, sizeof(p->id), "uuid:%.122s", p->uuid);
        if (!system_known || !identified)
            reason = "system_backing_unknown";
        else if (system_backing)
            reason = "system_disk_excluded";
        else if (!strcmp(media, "unknown"))
            reason = "media_unknown";
        else if (!strcmp(media, "emmc"))
            reason = "emmc_requires_confirmation";
        else if (!p->uuid[0])
            reason = "stable_uuid_unavailable";
        else if (strcmp(p->filesystem, "ext4"))
            reason = "filesystem_unsupported";
        else if (priority_rank(priority, media) == 99)
            reason = "media_not_requested";
        else if (!authorized(p->uuid, target, sizeof(target), &reason)) {
            /* reason supplied by the read-only fstab authorization check. */
        } else if (p->mounted && (strcmp(p->mountpoint, target) || !p->eligible))
            reason = p->writable ? "partition_in_use" : "read_only";
        else if (p->mounted && (!mounted_on(p, target) || !jmx_storage_provider_has_room(target)))
            reason = "mount_backing_or_space_insufficient";
        else if (!p->mounted && !automount)
            reason = "not_mounted";
        else
            eligible[i] = priority_rank(priority, media) + 1;
        text(row, "provider", p->id);
        text(row, "media_class", media);
        text(row, "classification_reason", detail);
        text(row, "reason", reason);
        text(row, "target", target);
        json_object_object_add(row, "system_backing",
                               system_known && identified ? json_object_new_boolean(system_backing) : NULL);
        json_object_array_add(candidates, row);
    }
    text(out, "reason", system_known ? "no_eligible_data_partition" : "system_backing_unknown");
    long long started = monotonic_ms();
    for (;;) {
        int best = -1;
        for (int i = 0; i < count; i++)
            if (eligible[i] && (best < 0 || eligible[i] < eligible[best] ||
                (eligible[i] == eligible[best] && strcmp(items[i].id, items[best].id) < 0)))
                best = i;
        if (best < 0)
            break;
        eligible[best] = 0;
        struct jmx_storage_provider *p = &items[best];
        struct json_object *row = json_object_array_get_idx(candidates, (size_t)best);
        struct json_object *value = NULL;
        json_object_object_get_ex(row, "target", &value);
        const char *best_target = json_object_get_string(value);
        const char *failure = NULL;
        int duplicates = 0;
        for (int i = 0; i < count; i++)
            duplicates += !strcmp(p->uuid, items[i].uuid);
        if (duplicates != 1) {
            failure = "duplicate_uuid";
            goto next_candidate;
        }
        if (!p->mounted && !mounted_on(p, best_target) && prepare) {
            long long elapsed = monotonic_ms() - started;
            if (started < 0 || elapsed < 0 || elapsed >= 8000) {
                text(out, "reason", "mount_wait_budget_exhausted");
                break;
            }
            if (!empty_mountpoint(best_target)) {
                failure = "mountpoint_unavailable_or_occupied";
                goto next_candidate;
            }
            struct jmx_exec_result result = {0};
            /* jmx_exec_wait only passes argv to execve; it never writes the strings. */
            char *argv[] = { "/bin/mount", "-t", "ext4", "-o", "rw,nodev,nosuid",
                             p->device, (char *)best_target, NULL };
            int rc = jmx_exec_wait(argv[0], argv, (int)(8000 - elapsed), &result);
            int ok = rc == 0 && !result.timed_out && result.exit_code == 0;
            jmx_exec_result_free(&result);
            if (!ok) {
                failure = "mount_failed_or_timed_out";
                goto next_candidate;
            }
        }
        if (!mounted_on(p, best_target)) {
            failure = prepare ? "mount_backing_mismatch" : "mount_pending";
            if (!prepare) {
                text(out, "candidate_provider", p->id);
                text(out, "reason", failure);
                break;
            }
            goto next_candidate;
        }
        struct statvfs fs;
        if (statvfs(best_target, &fs) != 0 || (fs.f_flag & ST_RDONLY) ||
            !jmx_storage_provider_has_room(best_target)) {
            failure = "space_or_writability_insufficient";
            goto next_candidate;
        }
        text(out, "active_provider", p->id);
        text(out, "mountpoint", best_target);
        if (selected && selected_len) snprintf(selected, selected_len, "%s", best_target);
        if (provider && provider_len) snprintf(provider, provider_len, "%s", p->id);
        text(out, "reason", "highest_priority_eligible");
        break;
next_candidate:
        text(row, "reason", failure);
        text(out, "reason", failure);
    }
done:
    free(items);
    return out;
}
