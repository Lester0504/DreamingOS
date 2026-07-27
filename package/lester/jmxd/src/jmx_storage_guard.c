// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_storage_guard.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/statvfs.h>
#include <time.h>

#define JMX_STORAGE_GUARD_CACHE_SEC 5
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static struct jmx_storage_guard_stats g_storage_guard;
static int64_t g_storage_guard_checked_at;
static char g_storage_guard_path[PATH_MAX];
static atomic_flag g_storage_guard_lock = ATOMIC_FLAG_INIT;

static void storage_guard_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&g_storage_guard_lock,
                                              memory_order_acquire))
        ;
}

static void storage_guard_unlock(void)
{
    atomic_flag_clear_explicit(&g_storage_guard_lock, memory_order_release);
}

const char *jmx_storage_pressure_name(enum jmx_storage_pressure pressure)
{
    switch (pressure) {
    case JMX_STORAGE_PRESSURE_OK: return "ok";
    case JMX_STORAGE_PRESSURE_WARNING: return "warning";
    case JMX_STORAGE_PRESSURE_CRITICAL: return "critical";
    default: return "unknown";
    }
}

enum jmx_storage_pressure jmx_storage_guard_evaluate(
    uint64_t total_bytes, uint64_t available_bytes,
    struct jmx_storage_guard_state *state)
{
    enum jmx_storage_pressure pressure = JMX_STORAGE_PRESSURE_OK;
    unsigned int used_pct = 0;
    const char *reason = "storage_ok";

    if (total_bytes == 0 || available_bytes > total_bytes) {
        pressure = JMX_STORAGE_PRESSURE_UNKNOWN;
        reason = "storage_capacity_invalid";
    } else {
        used_pct = (unsigned int)(((total_bytes - available_bytes) * 100ULL) /
                                  total_bytes);
        if (used_pct >= JMX_STORAGE_CRITICAL_USED_PCT ||
            (total_bytes >= JMX_STORAGE_ABSOLUTE_FLOOR_BYTES &&
             available_bytes <= JMX_STORAGE_CRITICAL_FREE_BYTES)) {
            pressure = JMX_STORAGE_PRESSURE_CRITICAL;
            reason = used_pct >= JMX_STORAGE_CRITICAL_USED_PCT ?
                     "filesystem_usage_critical" : "filesystem_free_critical";
        } else if (used_pct >= JMX_STORAGE_WARN_USED_PCT ||
                   (total_bytes >= JMX_STORAGE_ABSOLUTE_FLOOR_BYTES &&
                    available_bytes <= JMX_STORAGE_WARN_FREE_BYTES)) {
            pressure = JMX_STORAGE_PRESSURE_WARNING;
            reason = used_pct >= JMX_STORAGE_WARN_USED_PCT ?
                     "filesystem_usage_warning" : "filesystem_free_warning";
        }
    }

    if (state) {
        memset(state, 0, sizeof(*state));
        state->pressure = pressure;
        state->total_bytes = total_bytes;
        state->available_bytes = available_bytes;
        state->used_pct = used_pct;
        state->checked_at = (int64_t)time(NULL);
        snprintf(state->reason, sizeof(state->reason), "%s", reason);
    }
    return pressure;
}

int jmx_storage_guard_check(const char *path,
                            struct jmx_storage_guard_state *state)
{
    struct statvfs vfs;
    char probe[PATH_MAX];
    char *slash;
    uint64_t total;
    uint64_t available;

    if (!path || !path[0] || strlen(path) >= sizeof(probe))
        goto failed;
    snprintf(probe, sizeof(probe), "%s", path);
    while (statvfs(probe, &vfs) != 0) {
        if (errno != ENOENT && errno != ENOTDIR)
            goto failed;
        slash = strrchr(probe, '/');
        if (!slash)
            goto failed;
        if (slash == probe)
            probe[1] = '\0';
        else
            *slash = '\0';
        if (!strcmp(probe, "/") && statvfs(probe, &vfs) != 0)
            goto failed;
        if (!strcmp(probe, "/"))
            break;
    }
    total = (uint64_t)vfs.f_blocks * (uint64_t)vfs.f_frsize;
    available = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
    jmx_storage_guard_evaluate(total, available, state);
    return 0;

failed:
    {
        if (state) {
            memset(state, 0, sizeof(*state));
            state->pressure = JMX_STORAGE_PRESSURE_UNKNOWN;
            state->checked_at = (int64_t)time(NULL);
            snprintf(state->reason, sizeof(state->reason), "%s",
                     "statvfs_failed");
        }
        return -1;
    }
}

int jmx_storage_guard_allow(const char *path,
                            enum jmx_storage_write_priority priority,
                            struct jmx_storage_guard_state *state)
{
    int64_t now = (int64_t)time(NULL);
    enum jmx_storage_pressure pressure;
    int allowed;

    storage_guard_lock();
    if (strcmp(g_storage_guard_path, path ? path : "") ||
        g_storage_guard_checked_at <= 0 || now < g_storage_guard_checked_at ||
        now - g_storage_guard_checked_at >= JMX_STORAGE_GUARD_CACHE_SEC) {
        (void)jmx_storage_guard_check(path, &g_storage_guard.state);
        snprintf(g_storage_guard_path, sizeof(g_storage_guard_path), "%s",
                 path ? path : "");
        g_storage_guard_checked_at = now;
        g_storage_guard.checks++;
    }
    pressure = g_storage_guard.state.pressure;
    if (pressure == JMX_STORAGE_PRESSURE_OK)
        allowed = 1;
    else if (pressure == JMX_STORAGE_PRESSURE_CRITICAL)
        allowed = priority >= JMX_STORAGE_WRITE_EMERGENCY;
    else
        allowed = priority >= JMX_STORAGE_WRITE_IMPORTANT;

    if (allowed)
        g_storage_guard.allowed_writes++;
    else {
        g_storage_guard.suppressed_writes++;
        g_storage_guard.last_suppressed_at = now;
    }
    if (state)
        *state = g_storage_guard.state;
    storage_guard_unlock();
    return allowed;
}

void jmx_storage_guard_get_stats(struct jmx_storage_guard_stats *stats)
{
    if (stats) {
        storage_guard_lock();
        *stats = g_storage_guard;
        storage_guard_unlock();
    }
}
