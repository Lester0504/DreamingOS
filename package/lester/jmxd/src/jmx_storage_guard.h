// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_GUARD_H
#define DREAMINGWRT_STORAGE_GUARD_H

#include <stdint.h>

#define JMX_STORAGE_WARN_USED_PCT 85
#define JMX_STORAGE_CRITICAL_USED_PCT 95
#define JMX_STORAGE_ABSOLUTE_FLOOR_BYTES (2ULL * 1024ULL * 1024ULL * 1024ULL)
#define JMX_STORAGE_WARN_FREE_BYTES (512ULL * 1024ULL * 1024ULL)
#define JMX_STORAGE_CRITICAL_FREE_BYTES (128ULL * 1024ULL * 1024ULL)

enum jmx_storage_pressure {
    JMX_STORAGE_PRESSURE_OK = 0,
    JMX_STORAGE_PRESSURE_WARNING = 1,
    JMX_STORAGE_PRESSURE_CRITICAL = 2,
    JMX_STORAGE_PRESSURE_UNKNOWN = 3,
};

enum jmx_storage_write_priority {
    JMX_STORAGE_WRITE_BULK = 0,
    JMX_STORAGE_WRITE_IMPORTANT = 1,
    JMX_STORAGE_WRITE_EMERGENCY = 2,
};

struct jmx_storage_guard_state {
    enum jmx_storage_pressure pressure;
    uint64_t total_bytes;
    uint64_t available_bytes;
    unsigned int used_pct;
    int64_t checked_at;
    char reason[64];
};

struct jmx_storage_guard_stats {
    struct jmx_storage_guard_state state;
    uint64_t checks;
    uint64_t allowed_writes;
    uint64_t suppressed_writes;
    int64_t last_suppressed_at;
};

enum jmx_storage_pressure jmx_storage_guard_evaluate(
    uint64_t total_bytes, uint64_t available_bytes,
    struct jmx_storage_guard_state *state);
int jmx_storage_guard_check(const char *path,
                            struct jmx_storage_guard_state *state);
int jmx_storage_guard_allow(const char *path,
                            enum jmx_storage_write_priority priority,
                            struct jmx_storage_guard_state *state);
void jmx_storage_guard_get_stats(struct jmx_storage_guard_stats *stats);
const char *jmx_storage_pressure_name(enum jmx_storage_pressure pressure);

#endif
