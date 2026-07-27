// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef APD_CONFIG_JOB_JOURNAL_H
#define APD_CONFIG_JOB_JOURNAL_H

/* Phase W2b: durable journal for config jobs.  The core invariant is
 * fail-closed crash recovery: the rollback reference (previous_json)
 * becomes durable in state 'applying' BEFORE the executor mutates the
 * live config, so a power loss at any point resolves to a definite
 * state — never a silent half-applied config:
 *
 *   offered / staged            nothing mutated -> failed(interrupted)
 *   applying                    roll back with previous_json
 *   applied                     readback; mismatch rolls back
 *   completed/failed/rolled_back  terminal, finish replayed until acked
 *
 * Production reachability: none until the config_job wire lands behind
 * apd_config_executor_enabled(); the table is only ever written by that
 * path and by fixtures. */

#include <stdint.h>

#define APD_CONFIG_JOB_UUID_LEN 36
#define APD_CONFIG_JOB_AP_ID_LEN 36
#define APD_CONFIG_JOB_SESSION_EPOCH_LEN 64
#define APD_CONFIG_JOB_DIGEST_LEN 71
#define APD_CONFIG_JOB_ERROR_MAX 127
#define APD_CONFIG_JOB_STATE_MAX 31
#define APD_CONFIG_JOB_OUTCOME_MAX 15
#define APD_CONFIG_JOB_CANDIDATE_MAX_BYTES (16U * 1024U)
#define APD_CONFIG_JOB_PREVIOUS_MAX_BYTES (16U * 1024U)
#define APD_CONFIG_JOB_READBACK_MAX_BYTES (16U * 1024U)
#define APD_CONFIG_JOB_RETENTION_SECONDS 86400
#define APD_CONFIG_JOB_RETENTION_MIN 64

enum apd_config_job_journal_result {
    APD_CONFIG_JOB_JOURNAL_ERROR = -1,
    APD_CONFIG_JOB_JOURNAL_OK = 0,
    APD_CONFIG_JOB_JOURNAL_IDEMPOTENT = 1,
    APD_CONFIG_JOB_JOURNAL_NOT_FOUND = 2,
    APD_CONFIG_JOB_JOURNAL_CONFLICT = 3,
    APD_CONFIG_JOB_JOURNAL_INVALID = 4,
};

struct apd_config_job_assignment {
    char job_id[APD_CONFIG_JOB_UUID_LEN + 1];
    char attempt_id[APD_CONFIG_JOB_UUID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[APD_CONFIG_JOB_DIGEST_LEN + 1];
    char candidate_digest[APD_CONFIG_JOB_DIGEST_LEN + 1];
    char ap_id[APD_CONFIG_JOB_AP_ID_LEN + 1];
    char session_epoch[APD_CONFIG_JOB_SESSION_EPOCH_LEN + 1];
};

struct apd_config_job_finish {
    struct apd_config_job_assignment assignment;
    char finish_id[APD_CONFIG_JOB_UUID_LEN + 1];
    char outcome[APD_CONFIG_JOB_OUTCOME_MAX + 1];
    char error_code[APD_CONFIG_JOB_ERROR_MAX + 1];
    int64_t observed_at;
    const char *readback_json;
};

struct apd_config_job_journal_entry {
    struct apd_config_job_assignment assignment;
    char state[APD_CONFIG_JOB_STATE_MAX + 1];
    char finish_id[APD_CONFIG_JOB_UUID_LEN + 1];
    char outcome[APD_CONFIG_JOB_OUTCOME_MAX + 1];
    char error_code[APD_CONFIG_JOB_ERROR_MAX + 1];
    int64_t observed_at;
    int finish_acked;
    int64_t created_at;
    int64_t updated_at;
};

/* Non-terminal row surfaced at restart; the caller resolves it with the
 * executor (rollback/readback) and records the outcome via
 * apd_config_job_finish_store. */
struct apd_config_job_recovery {
    struct apd_config_job_journal_entry entry;
    char *candidate_json;
    char *previous_json;
};

struct apd_config_job_pending_reconcile {
    struct apd_config_job_journal_entry entry;
    char *readback_json;
};

int apd_config_job_journal_init(void);
int apd_config_job_offer_store(
    const struct apd_config_job_assignment *assignment,
    const char *candidate_json, int64_t now,
    struct apd_config_job_journal_entry *out);
int apd_config_job_mark_staged(
    const struct apd_config_job_assignment *assignment, int64_t now,
    struct apd_config_job_journal_entry *out);
int apd_config_job_mark_applying(
    const struct apd_config_job_assignment *assignment,
    const char *previous_json, int64_t now,
    struct apd_config_job_journal_entry *out);
int apd_config_job_mark_applied(
    const struct apd_config_job_assignment *assignment, int64_t now,
    struct apd_config_job_journal_entry *out);
int apd_config_job_finish_store(const struct apd_config_job_finish *finish,
                                int64_t now,
                                struct apd_config_job_journal_entry *out);
int apd_config_job_finish_ack(
    const struct apd_config_job_assignment *assignment,
    const char *finish_id, int64_t now,
    struct apd_config_job_journal_entry *out);
int apd_config_job_recovery_next(struct apd_config_job_recovery *out);
void apd_config_job_recovery_free(struct apd_config_job_recovery *recovery);
int apd_config_job_pending_reconcile_get(
    const char *ap_id, struct apd_config_job_pending_reconcile *out);
void apd_config_job_pending_reconcile_free(
    struct apd_config_job_pending_reconcile *pending);
int apd_config_job_session_rebind(
    const struct apd_config_job_assignment *assignment,
    const char *new_session_epoch, int64_t now,
    struct apd_config_job_journal_entry *out);
int apd_config_job_journal_get(const char *job_id,
                               struct apd_config_job_journal_entry *out);
int apd_config_job_journal_prune(int64_t now);

#endif
