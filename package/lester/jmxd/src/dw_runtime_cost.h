// SPDX-License-Identifier: GPL-2.0-or-later
/* Per-calling-thread accounting for the WAN/settings collection cost audit. */
#ifndef DW_RUNTIME_COST_H
#define DW_RUNTIME_COST_H
#include <stdint.h>
#include <time.h>
#include <sys/resource.h>
#include <json-c/json.h>

struct dw_runtime_cost {
    int64_t wall_us, user_us, system_us, minor_faults;
    int valid;
};

static inline struct dw_runtime_cost dw_runtime_cost_now(void)
{
    struct dw_runtime_cost value = {0};
    struct timespec ts;
    struct rusage ru;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        value.wall_us = (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
#if defined(__linux__)
    /* Linux RUSAGE_THREAD is 1, including when GNU feature macros are absent.
     * RUSAGE_SELF would incorrectly charge concurrent collectors to this call. */
    if (getrusage(1, &ru) == 0) {
        value.user_us = (int64_t)ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec;
        value.system_us = (int64_t)ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
        value.minor_faults = ru.ru_minflt;
        value.valid = 1;
    }
#else
    (void)ru;
#endif
    return value;
}

static inline struct dw_runtime_cost dw_runtime_cost_delta(
    struct dw_runtime_cost start, struct dw_runtime_cost end)
{
    struct dw_runtime_cost value = {
        .wall_us = end.wall_us - start.wall_us,
        .user_us = end.user_us - start.user_us,
        .system_us = end.system_us - start.system_us,
        .minor_faults = end.minor_faults - start.minor_faults,
        .valid = start.valid && end.valid,
    };
    return value;
}

static inline struct json_object *dw_runtime_cost_json(struct dw_runtime_cost value)
{
    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "wall_us", json_object_new_int64(value.wall_us));
    json_object_object_add(out, "user_us", value.valid ? json_object_new_int64(value.user_us) : NULL);
    json_object_object_add(out, "system_us", value.valid ? json_object_new_int64(value.system_us) : NULL);
    json_object_object_add(out, "minor_faults", value.valid ? json_object_new_int64(value.minor_faults) : NULL);
    return out;
}

static inline void dw_runtime_cost_phase(struct json_object *phases, const char *name,
                                          struct dw_runtime_cost *start)
{
    struct dw_runtime_cost end = dw_runtime_cost_now();
    json_object_object_add(phases, name, dw_runtime_cost_json(dw_runtime_cost_delta(*start, end)));
    *start = end;
}
#endif
