/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "memory_profile.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int dw_mp_select(const char *requested, const char *board, uint64_t total,
                 struct dw_memory_profile *p)
{
    memset(p, 0, sizeof(*p));
    p->total_bytes = total;
    if (!requested || (strcmp(requested, "auto") &&
        strcmp(requested, "standard") && strcmp(requested, "compact"))) return -1;
    snprintf(p->requested, sizeof(p->requested), "%s", requested);
    p->supported = 1;
    const char *reason = "manual";
    if (strcmp(requested, "auto")) p->compact = !strcmp(requested, "compact");
    else if (board && (strstr(board, "AX1800Pro") || strstr(board, "ax1800-pro") ||
                       strstr(board, "ax1800pro"))) {
        p->compact = 1; reason = "device_profile";
    } else if (total && total <= 512 * DW_MP_MIB) {
        p->compact = 1; reason = "memory_512m_class";
    } else if (total >= 2048 * DW_MP_MIB) reason = "memory_2g_class";
    else {
        /* Retain standard until Build supplies the intermediate device table. */
        p->supported = 0;
        reason = total ? "device_profile_required" : "memory_total_unavailable";
    }
    snprintf(p->reason, sizeof(p->reason), "%s", reason);
    return 0;
}

void dw_mp_memory(const char *path, struct dw_memory_profile *p)
{
    FILE *f = fopen(path, "r");
    char line[192]; unsigned long long value;
    p->total_bytes = p->available_bytes = 0; p->available_known = 0;
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %llu kB", &value) == 1)
            p->total_bytes = value * 1024;
        else if (sscanf(line, "MemAvailable: %llu kB", &value) == 1) {
            p->available_bytes = value * 1024; p->available_known = 1;
        }
    }
    fclose(f);
}

void dw_mp_load(struct dw_memory_profile *p)
{
    struct dw_memory_profile mem = {0};
    char board[256] = "";
    FILE *f = fopen("/tmp/sysinfo/board_name", "r");
    if (f) { if (!fgets(board, sizeof(board), f)) board[0] = 0; fclose(f); }
    dw_mp_memory("/proc/meminfo", &mem);
    dw_mp_select("auto", board, mem.total_bytes, p);
    struct json_object *o = json_object_from_file(DW_MP_PATH), *v;
    if (o) {
        const char *mode = NULL;
        if (json_object_object_get_ex(o, "requested_mode", &v) &&
            json_object_is_type(v, json_type_string)) mode = json_object_get_string(v);
        struct dw_memory_profile selected;
        if (dw_mp_select(mode, board, mem.total_bytes, &selected) == 0) {
            *p = selected;
            if (json_object_object_get_ex(o, "config_revision", &v))
                p->revision = json_object_get_int64(v);
            if (json_object_object_get_ex(o, "activated_at", &v))
                p->activated_at = json_object_get_int64(v);
        }
        json_object_put(o);
    }
    p->available_bytes = mem.available_bytes; p->available_known = mem.available_known;
}

struct json_object *dw_mp_json(const struct dw_memory_profile *p)
{
    struct json_object *o = json_object_new_object(), *mem = json_object_new_object();
    struct json_object *policy = json_object_new_object();
    json_object_object_add(o, "requested_mode", json_object_new_string(p->requested));
    json_object_object_add(o, "effective_mode", json_object_new_string(p->compact ? "compact" : "standard"));
    json_object_object_add(o, "selection_reason", json_object_new_string(p->reason));
    json_object_object_add(o, "supported", json_object_new_boolean(p->supported));
    json_object_object_add(o, "config_revision", json_object_new_int64(p->revision));
    json_object_object_add(o, "activated_at", json_object_new_int64(p->activated_at));
    json_object_object_add(mem, "total_bytes", p->total_bytes ? json_object_new_int64(p->total_bytes) : NULL);
    json_object_object_add(mem, "available_bytes", p->available_known ? json_object_new_int64(p->available_bytes) : NULL);
    json_object_object_add(mem, "pss_bytes", NULL);
    json_object_object_add(mem, "pss_unavailable_reason", json_object_new_string("not_measured"));
    json_object_object_add(o, "memory", mem);
    json_object_object_add(policy, "web_workers", json_object_new_int(p->compact ? 4 : 16));
    json_object_object_add(policy, "heavy_workers", json_object_new_int(p->compact ? 1 : 2));
    json_object_object_add(policy, "worker_queue", json_object_new_int(p->compact ? 4 : 8));
    json_object_object_add(policy, "dispatch_backlog", json_object_new_int(p->compact ? 16 : 48));
    json_object_object_add(policy, "stats_period_ms", json_object_new_int(p->compact ? 2000 : 750));
    json_object_object_add(policy, "background_period_ms", json_object_new_int(p->compact ? 5000 : 750));
    json_object_object_add(policy, "delta_slots", json_object_new_int(p->compact ? 16 : 64));
    json_object_object_add(policy, "delta_bytes_max", json_object_new_int64((p->compact ? 4 : 128) * DW_MP_MIB));
    json_object_object_add(policy, "optional_task_floor_bytes", json_object_new_int64(64 * DW_MP_MIB));
    json_object_object_add(o, "policy", policy);
    return o;
}

int dw_mp_compact(void)
{
    static _Thread_local time_t checked;
    static _Thread_local int compact;
    time_t now = time(NULL);
    if (!checked || checked != now) {
        struct dw_memory_profile p;
        dw_mp_load(&p); compact = p.compact; checked = now;
    }
    return compact;
}

int dw_mp_publish(const struct dw_memory_profile *p)
{
    char temp[256];
    if (mkdir(DW_MP_RUN_DIR, 0755) != 0 && errno != EEXIST) return -1;
    int lock = open(DW_MP_PATH ".lock", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock < 0) return -1;
    if (flock(lock, LOCK_EX) != 0) { close(lock); return -1; }
    /* A later SQLite transaction may publish before this caller gets here. */
    struct json_object *existing = json_object_from_file(DW_MP_PATH), *revision = NULL;
    int newer = existing && json_object_object_get_ex(existing, "config_revision", &revision) &&
                json_object_get_int64(revision) > p->revision;
    if (existing) json_object_put(existing);
    if (newer) { close(lock); return 0; }
    snprintf(temp, sizeof(temp), "%s.XXXXXX", DW_MP_PATH);
    int fd = mkstemp(temp);
    if (fd < 0) { close(lock); return -1; }
    close(fd);
    struct json_object *o = dw_mp_json(p);
    int rc = json_object_to_file_ext(temp, o, JSON_C_TO_STRING_PLAIN);
    json_object_put(o);
    if (rc == 0) rc = rename(temp, DW_MP_PATH);
    if (rc != 0) unlink(temp);
    close(lock);
    return rc;
}

int dw_mp_reserve(const char *dir, uint64_t available, int available_known,
                  uint64_t peak, int peak_known, int *lease, const char **reason)
{
    char path[512]; int lockfd = -1, fd = -1, rc = -1;
    uint64_t reserved = 0; DIR *d = NULL; struct dirent *entry;
    *lease = -1; *reason = "active_operation_conflict";
    if (!peak_known) { *reason = "resource_peak_unknown"; return -1; }
    if (!available_known) { *reason = "memory_available_unknown"; return -1; }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return -1;
    snprintf(path, sizeof(path), "%s/.lock", dir);
    lockfd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0) goto out;
    if (!strcmp(dir, DW_MP_RESERVATIONS)) {
        struct dw_memory_profile current = {0};
        dw_mp_memory("/proc/meminfo", &current);
        available = current.available_bytes;
        if (!current.available_known) { *reason = "memory_available_unknown"; goto out; }
    }
    d = opendir(dir); if (!d) goto out;
    while ((entry = readdir(d))) {
        if (strncmp(entry->d_name, "lease-", 6)) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) goto out;
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) unlink(path);
        else {
            uint64_t value = 0;
            if (pread(fd, &value, sizeof(value), 0) != sizeof(value) ||
                UINT64_MAX - reserved < value) goto out;
            reserved += value;
        }
        close(fd); fd = -1;
    }
    if (available < 64 * DW_MP_MIB || peak > available - 64 * DW_MP_MIB ||
        reserved > available - 64 * DW_MP_MIB - peak) {
        *reason = "insufficient_memory"; goto out;
    }
    snprintf(path, sizeof(path), "%s/lease-XXXXXX", dir);
    fd = mkstemp(path);
    if (fd < 0) goto out;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (flock(fd, LOCK_EX) != 0 || write(fd, &peak, sizeof(peak)) != sizeof(peak)) {
        unlink(path); goto out;
    }
    *lease = fd; fd = -1; rc = 0; *reason = "admitted";
out:
    if (d) closedir(d);
    if (fd >= 0) close(fd);
    if (lockfd >= 0) close(lockfd);
    return rc;
}

void dw_mp_release(int *lease)
{
    if (*lease >= 0) close(*lease);
    *lease = -1;
}

int dw_mp_admit(uint64_t peak, int known, int *lease, const char **reason)
{
    struct dw_memory_profile p;
    dw_mp_load(&p); *lease = -1;
    if (!p.compact) { *reason = "standard_mode"; return 0; }
    return dw_mp_reserve(DW_MP_RESERVATIONS, p.available_bytes, p.available_known,
                         peak, known, lease, reason);
}
