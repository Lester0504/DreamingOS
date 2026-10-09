// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_RUNTIME_SAMPLE_STORE_H
#define DREAMINGWRT_FLOWD_RUNTIME_SAMPLE_STORE_H

#include <stddef.h>
#include <stdint.h>

struct flowd_runtime_wan_source {
    const char *wan;
    const char *ifname;
};

int flowd_runtime_sample_store(const char *sysfs_root, const char *db_path,
                               const struct flowd_runtime_wan_source *sources,
                               size_t source_count, int64_t sample_ts,
                               size_t *written);

#endif
