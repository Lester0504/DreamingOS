// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_DIAGNOSTICS_COLLECTOR_H
#define DREAMINGWRT_DIAGNOSTICS_COLLECTOR_H

#include <stddef.h>
#include <stdint.h>

#define DW_DIAG_JOB_ID_LEN 32
#define DW_DIAG_REASON_LEN 64
#define DW_DIAG_STAGE_LEN 64

enum dw_diag_result {
    DW_DIAG_OK = 0,
    DW_DIAG_FORBIDDEN = -1,
    DW_DIAG_INVALID = -2,
    DW_DIAG_NOT_FOUND = -3,
    DW_DIAG_BUSY = -4,
    DW_DIAG_STORAGE = -5,
    DW_DIAG_QUOTA = -6,
    DW_DIAG_IO = -7,
    DW_DIAG_CLEANUP = -8,
};

enum dw_diag_actor {
    DW_DIAG_ACTOR_VIEWER = 0,
    DW_DIAG_ACTOR_ADMIN = 1,
};

enum dw_diag_scope {
    DW_DIAG_SCOPE_SYSTEM = 1U << 0,
    DW_DIAG_SCOPE_NETWORK = 1U << 1,
    DW_DIAG_SCOPE_SERVICES = 1U << 2,
    DW_DIAG_SCOPE_LOGS = 1U << 3,
    DW_DIAG_SCOPE_ALL = (1U << 4) - 1,
};

enum dw_diag_state {
    DW_DIAG_STATE_QUEUED = 0,
    DW_DIAG_STATE_RUNNING,
    DW_DIAG_STATE_STOPPING,
    DW_DIAG_STATE_COMPLETED,
    DW_DIAG_STATE_STOPPED,
    DW_DIAG_STATE_FAILED,
    DW_DIAG_STATE_EXPIRED,
};

struct dw_diag_status {
    char job_id[DW_DIAG_JOB_ID_LEN + 1];
    enum dw_diag_state state;
    uint32_t scope_mask;
    unsigned int progress_percent;
    uint64_t bytes_written;
    int64_t created_at;
    int64_t started_at;
    int64_t finished_at;
    int downloadable;
    int stop_requested;
    char audit_reason[DW_DIAG_REASON_LEN];
    char failure_stage[DW_DIAG_STAGE_LEN];
};

struct dw_diag_writer;
struct dw_diag_manager;

typedef int (*dw_diag_collector_fn)(struct dw_diag_writer *writer,
                                    void *context);

struct dw_diag_collector {
    uint32_t scope_bit;
    const char *name;
    dw_diag_collector_fn collect;
    void *context;
};

typedef int (*dw_diag_storage_allow_fn)(const char *root, void *context);
typedef int64_t (*dw_diag_now_fn)(void *context);
typedef int (*dw_diag_id_fn)(char output[DW_DIAG_JOB_ID_LEN + 1],
                             void *context);

struct dw_diag_config {
    const char *root;
    uint64_t max_job_bytes;
    uint64_t total_quota_bytes;
    unsigned int max_duration_sec;
    unsigned int retention_sec;
    unsigned int max_jobs;
    const struct dw_diag_collector *collectors;
    size_t collector_count;
    dw_diag_storage_allow_fn storage_allow;
    void *storage_context;
    dw_diag_now_fn now;
    void *now_context;
    dw_diag_id_fn id_generate;
    void *id_context;
};

int dw_diag_manager_open(struct dw_diag_manager **manager,
                         const struct dw_diag_config *config,
                         char *reason, size_t reason_len);
void dw_diag_manager_close(struct dw_diag_manager *manager);

int dw_diag_start(struct dw_diag_manager *manager, enum dw_diag_actor actor,
                  uint32_t scope_mask, struct dw_diag_status *status);
int dw_diag_status_get(struct dw_diag_manager *manager,
                       enum dw_diag_actor actor, const char *job_id,
                       struct dw_diag_status *status);
int dw_diag_stop(struct dw_diag_manager *manager, enum dw_diag_actor actor,
                 const char *job_id, struct dw_diag_status *status);
int dw_diag_download_open(struct dw_diag_manager *manager,
                          enum dw_diag_actor actor, const char *job_id,
                          int *fd, uint64_t *size);
int dw_diag_delete(struct dw_diag_manager *manager, enum dw_diag_actor actor,
                   const char *job_id);
int dw_diag_cleanup_expired(struct dw_diag_manager *manager,
                            enum dw_diag_actor actor, int64_t now,
                            unsigned int *cleaned);

int dw_diag_writer_text(struct dw_diag_writer *writer, const char *text);
int dw_diag_writer_key_value(struct dw_diag_writer *writer, const char *key,
                             const char *value);

const char *dw_diag_state_name(enum dw_diag_state state);
const char *dw_diag_result_name(int result);

#endif
