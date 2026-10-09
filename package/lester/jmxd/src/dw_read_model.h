/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DREAMINGWRT_READ_MODEL_H
#define DREAMINGWRT_READ_MODEL_H

#include <stddef.h>
#include <stdint.h>

#include <json-c/json.h>

struct dw_rm_resource;

struct dw_rm_collect_result {
    void *generation;
    int64_t observed_at;
    int complete;
    uint64_t scanned_rows;
};

struct dw_rm_ops {
    int (*collect)(void *context, struct dw_rm_collect_result *result);
    void (*free_generation)(void *context, void *generation);
    int (*diff)(void *context, const void *previous, const void *current,
                void **delta, size_t *delta_bytes);
    void (*free_delta)(void *context, void *delta);
};

struct dw_rm_config {
    const char *name;
    const char *contract;
    unsigned int period_ms;
    unsigned int stale_after_ms;
    size_t ring_slots;
    size_t ring_bytes_max;
    int memory_profile; /* opt in to the connection statistics policy */
    void *context;
    struct dw_rm_ops ops;
};

enum dw_rm_resume_result {
    DW_RM_RESUME_OK = 0,
    DW_RM_RESUME_BUILDING,
    DW_RM_RESUME_SNAPSHOT_CHANGED,
    DW_RM_RESUME_REVISION_TOO_OLD,
    DW_RM_RESUME_REVISION_AHEAD,
    DW_RM_RESUME_SOURCE_REBUILT,
};

struct dw_rm_view {
    struct dw_rm_resource *resource;
    const void *generation;
    const char *name;
    const char *contract;
    const char *snapshot_id;
    uint64_t revision;
    uint64_t base_revision;
    int64_t observed_at;
    int64_t collect_ms;
    uint64_t scanned_rows;
    int complete;
    int stale;
    size_t delta_offset;
    size_t delta_count;
    int locked;
};

int dw_rm_create(const struct dw_rm_config *config,
                 struct dw_rm_resource **resource_out);
int dw_rm_start(struct dw_rm_resource *resource);
void dw_rm_stop(struct dw_rm_resource *resource);
void dw_rm_destroy(struct dw_rm_resource *resource);

int dw_rm_view_begin(struct dw_rm_resource *resource, struct dw_rm_view *view);
enum dw_rm_resume_result dw_rm_resume_begin(struct dw_rm_resource *resource,
                                            const char *snapshot_id,
                                            uint64_t since_revision,
                                            struct dw_rm_view *view);
const void *dw_rm_view_delta_at(const struct dw_rm_view *view, size_t index,
                                uint64_t *revision, int64_t *observed_at,
                                size_t *bytes);
void dw_rm_view_end(struct dw_rm_view *view);

const char *dw_rm_resume_reason(enum dw_rm_resume_result result);
struct json_object *dw_rm_resync_json(struct dw_rm_resource *resource,
                                      enum dw_rm_resume_result result);
struct json_object *dw_rm_status_json(struct dw_rm_resource *resource);
struct json_object *dw_rm_registry_status_json(void);

#endif
