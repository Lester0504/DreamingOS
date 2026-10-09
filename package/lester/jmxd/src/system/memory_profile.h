/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DW_MEMORY_PROFILE_H
#define DW_MEMORY_PROFILE_H
#include <stdint.h>
#include <json-c/json.h>

#ifndef DW_MP_RUN_DIR
#define DW_MP_RUN_DIR "/var/run/dreamingwrt"
#endif
#ifndef DW_MP_PATH
#define DW_MP_PATH DW_MP_RUN_DIR "/memory-profile.json"
#endif
#ifndef DW_MP_RESERVATIONS
#define DW_MP_RESERVATIONS DW_MP_RUN_DIR "/memory-reservations"
#endif
#define DW_MP_MIB (1024ULL * 1024ULL)
struct dw_memory_profile {
    int compact;
    int supported;
    int64_t revision;
    int64_t activated_at;
    uint64_t total_bytes;
    uint64_t available_bytes;
    int available_known;
    char requested[16];
    char reason[64];
};
/* Policy selection uses MemTotal, never transient MemAvailable. */
int dw_mp_select(const char *requested, const char *board, uint64_t total,
                 struct dw_memory_profile *profile);
void dw_mp_memory(const char *path, struct dw_memory_profile *profile);
void dw_mp_load(struct dw_memory_profile *profile);
int dw_mp_compact(void);
int dw_mp_publish(const struct dw_memory_profile *profile);
struct json_object *dw_mp_json(const struct dw_memory_profile *profile);
/* fd holds a kernel lease until release/process exit; -1 means no lease. */
int dw_mp_reserve(const char *directory, uint64_t available, int available_known,
                  uint64_t peak, int peak_known, int *lease,
                  const char **reason);
void dw_mp_release(int *lease);
int dw_mp_admit(uint64_t peak, int peak_known, int *lease, const char **reason);
#endif
