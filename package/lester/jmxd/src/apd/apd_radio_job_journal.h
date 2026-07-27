// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef APD_RADIO_JOB_JOURNAL_H
#define APD_RADIO_JOB_JOURNAL_H

#include <stdint.h>

#define APD_RADIO_JOB_UUID_LEN 36
#define APD_RADIO_JOB_AP_ID_LEN 36
#define APD_RADIO_JOB_SESSION_EPOCH_LEN 64
#define APD_RADIO_JOB_DIGEST_LEN 71
#define APD_RADIO_JOB_RADIO_ID_MAX 63
#define APD_RADIO_JOB_MODE_MAX 31
#define APD_RADIO_JOB_ERROR_MAX 127
#define APD_RADIO_JOB_STATE_MAX 31
#define APD_RADIO_JOB_OUTCOME_MAX 15
#define APD_RADIO_JOB_RESULT_MAX_ITEMS 128
#define APD_RADIO_JOB_RESULT_MAX_BYTES (48U * 1024U)
#define APD_RADIO_JOB_RETENTION_SECONDS 86400
#define APD_RADIO_JOB_RETENTION_MIN 128

enum apd_radio_job_journal_result {
    APD_RADIO_JOB_JOURNAL_ERROR = -1,
    APD_RADIO_JOB_JOURNAL_OK = 0,
    APD_RADIO_JOB_JOURNAL_IDEMPOTENT = 1,
    APD_RADIO_JOB_JOURNAL_NOT_FOUND = 2,
    APD_RADIO_JOB_JOURNAL_CONFLICT = 3,
    APD_RADIO_JOB_JOURNAL_INVALID = 4,
    APD_RADIO_JOB_JOURNAL_LIMIT = 5,
};

struct apd_radio_job_assignment {
    char job_id[APD_RADIO_JOB_UUID_LEN + 1];
    char attempt_id[APD_RADIO_JOB_UUID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[APD_RADIO_JOB_DIGEST_LEN + 1];
    char ap_id[APD_RADIO_JOB_AP_ID_LEN + 1];
    char session_epoch[APD_RADIO_JOB_SESSION_EPOCH_LEN + 1];
    char radio_id[APD_RADIO_JOB_RADIO_ID_MAX + 1];
    char mode[APD_RADIO_JOB_MODE_MAX + 1];
};

struct apd_radio_job_finish {
    struct apd_radio_job_assignment assignment;
    char finish_id[APD_RADIO_JOB_UUID_LEN + 1];
    char outcome[APD_RADIO_JOB_OUTCOME_MAX + 1];
    char error_code[APD_RADIO_JOB_ERROR_MAX + 1];
    int64_t observed_at;
    const char *result_json;
    int result_complete;
};

struct apd_radio_job_journal_entry {
    struct apd_radio_job_assignment assignment;
    char state[APD_RADIO_JOB_STATE_MAX + 1];
    char finish_id[APD_RADIO_JOB_UUID_LEN + 1];
    char outcome[APD_RADIO_JOB_OUTCOME_MAX + 1];
    char error_code[APD_RADIO_JOB_ERROR_MAX + 1];
    int64_t observed_at;
    int result_count;
    int64_t result_bytes;
    int result_complete;
    int finish_acked;
    int64_t created_at;
    int64_t updated_at;
};

struct apd_radio_job_pending_finish {
    struct apd_radio_job_journal_entry entry;
    char *result_json;
};

struct apd_radio_job_pending_reconcile {
    struct apd_radio_job_journal_entry entry;
    char *result_json;
};

int apd_radio_job_journal_init(void);
int apd_radio_job_offer_store(const struct apd_radio_job_assignment *assignment,
                              int64_t now,
                              struct apd_radio_job_journal_entry *out);
int apd_radio_job_mark_running(const struct apd_radio_job_assignment *assignment,
                               int64_t now,
                               struct apd_radio_job_journal_entry *out);
int apd_radio_job_finish_store(const struct apd_radio_job_finish *finish,
                               int64_t now,
                               struct apd_radio_job_journal_entry *out);
int apd_radio_job_pending_finish_get(const char *ap_id,
                                     struct apd_radio_job_pending_finish *out);
void apd_radio_job_pending_finish_free(
    struct apd_radio_job_pending_finish *pending);
int apd_radio_job_pending_reconcile_get(
    const char *ap_id, struct apd_radio_job_pending_reconcile *out);
void apd_radio_job_pending_reconcile_free(
    struct apd_radio_job_pending_reconcile *pending);
int apd_radio_job_finish_ack(const struct apd_radio_job_assignment *assignment,
                             const char *finish_id,
                             int64_t now,
                             struct apd_radio_job_journal_entry *out);
int apd_radio_job_restart_recover(int64_t now, int *interrupted_count);
int apd_radio_job_journal_prune(int64_t now);
int apd_radio_job_cancel_requested(
    const struct apd_radio_job_assignment *assignment, int64_t now,
    struct apd_radio_job_journal_entry *out);
int apd_radio_job_session_rebind(
    const struct apd_radio_job_assignment *assignment,
    const char *new_session_epoch, int64_t now,
    struct apd_radio_job_journal_entry *out);
int apd_radio_job_journal_get(const char *job_id,
                              struct apd_radio_job_journal_entry *out);

#endif
