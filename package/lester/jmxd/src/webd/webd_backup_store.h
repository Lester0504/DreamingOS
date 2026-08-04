// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Durable config-backup store.
 *
 * Backups used to live in the upload-staging area, which caps every entry at a
 * 24 hour TTL and actively deletes expired ones. Count-based retention is
 * meaningless on top of that: the newest N would quietly evaporate overnight and
 * the "limit reached" path would almost never be observed. This store keeps
 * backups until somebody deletes them, and enforces retention by count only.
 *
 * Retention semantics (decided by the user on 2026-08-04):
 *   - by count, never by age
 *   - the limit is user-configured; there is no built-in eviction default
 *   - at the limit, creation is REFUSED. Nothing is overwritten or dropped.
 */
#ifndef WEBD_BACKUP_STORE_H
#define WEBD_BACKUP_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEBD_BACKUP_ID_LEN 36
#define WEBD_BACKUP_SHA256_HEX_LEN 64
#define WEBD_BACKUP_OWNER_ID_LEN 128
#define WEBD_BACKUP_DEFAULT_ROOT "/data/persist/var/lib/dreamingwrt/backups"

/* Bounds for the user-configured retention count. */
#define WEBD_BACKUP_RETENTION_MIN 1u
#define WEBD_BACKUP_RETENTION_MAX 64u

/*
 * No default retention count is baked in as a contract. Until the user sets one
 * this value is what the store applies, and `retention_configured` stays 0 so
 * the API can tell the UI it is a fallback rather than a decision.
 */
#define WEBD_BACKUP_RETENTION_FALLBACK 5u

/* Single backup: 64 MiB, matching the old staging ceiling for type "backup". */
#define WEBD_BACKUP_MAX_BYTES (64ULL * 1024ULL * 1024ULL)

/* How a backup came to exist. Persisted, so the list can distinguish them. */
#define WEBD_BACKUP_SOURCE_MANUAL    "manual"
#define WEBD_BACKUP_SOURCE_SCHEDULED "scheduled"

/* Schedule frequency. Enumerated rather than a raw cron string: the executor
 * lives in-process, so accepting arbitrary cron would promise more than it
 * keeps. */
#define WEBD_BACKUP_FREQ_DAILY  "daily"
#define WEBD_BACKUP_FREQ_WEEKLY "weekly"

struct webd_backup_meta {
    char backup_id[WEBD_BACKUP_ID_LEN + 1];
    char owner_id[WEBD_BACKUP_OWNER_ID_LEN + 1];
    char source[16];              /* manual | scheduled */
    char original_filename[256];
    uint64_t size_bytes;
    time_t created_at;
    char sha256[WEBD_BACKUP_SHA256_HEX_LEN + 1];
    char source_version[96];
};

struct webd_backup_list {
    struct webd_backup_meta *items;   /* newest first */
    size_t count;
};

struct webd_backup_schedule {
    int enabled;
    char frequency[16];       /* daily | weekly */
    int hour;                 /* 0-23, local time */
    int minute;               /* 0-59 */
    int weekday;              /* 0-6, Sunday=0; only meaningful when weekly */
    char owner_id[WEBD_BACKUP_OWNER_ID_LEN + 1];  /* who configured it */
    /*
     * When this schedule was last written. Acts as a floor on due-time: a window
     * that elapsed before the user configured the schedule is not owed a backup,
     * otherwise enabling a weekly schedule would fire immediately for an
     * occurrence up to a week in the past. Set by schedule_set(), ignored on input.
     */
    time_t configured_at;
};

/*
 * Outcome of the most recent scheduled attempt. This exists because a scheduled
 * backup that silently does not run is indistinguishable from one that works: the
 * user must be able to see that it failed and why.
 */
struct webd_backup_last_run {
    int present;
    time_t at;
    char result[16];          /* ok | failed | skipped */
    char error[96];
    char backup_id[WEBD_BACKUP_ID_LEN + 1];   /* set when result == ok */
};

int webd_backup_store_set_root_for_tests(const char *root);
const char *webd_backup_store_root(void);

int webd_backup_source_valid(const char *source);
int webd_backup_frequency_valid(const char *frequency);

/* Schedule. get() yields a disabled default when nothing is stored. */
void webd_backup_schedule_get(struct webd_backup_schedule *out);
int webd_backup_schedule_set(const struct webd_backup_schedule *in,
                             char *err, size_t err_len);

/*
 * Due-time bookkeeping. `webd_backup_schedule_due()` reports whether the
 * schedule should have fired by `now` given the recorded last attempt, so a
 * missed window (daemon restart, clock jump) is caught on the next tick instead
 * of being skipped silently.
 */
int webd_backup_schedule_due(time_t now);

void webd_backup_last_run_get(struct webd_backup_last_run *out);
int webd_backup_last_run_record(const char *result, const char *error,
                                const char *backup_id, time_t at,
                                char *err, size_t err_len);

/*
 * Retention count. get() never fails: absent or corrupt state yields the
 * fallback with *configured = 0.
 */
unsigned webd_backup_retention_get(int *configured);
int webd_backup_retention_set(unsigned count, char *err, size_t err_len);

/* Number of stored backups. Returns -1 on store failure. */
int webd_backup_count(char *err, size_t err_len);

/*
 * Retention gate, evaluated BEFORE any bytes are written.
 * Returns 0 when a new backup may be created, -1 otherwise with
 * "backup_retention_limit_reached" in err.
 */
int webd_backup_retention_admit(unsigned *count_out, unsigned *limit_out,
                                char *err, size_t err_len);

/*
 * Publish a finished artifact into the store. `artifact_path` is consumed by
 * rename when possible and copied otherwise; the caller still owns unlinking it
 * on failure. Checks the retention gate again under the store lock so two
 * concurrent creates cannot both slip past it.
 */
int webd_backup_publish(const char *owner_id,
                        const char *source,
                        const char *original_filename,
                        const char *source_version,
                        const char *artifact_path,
                        struct webd_backup_meta *out,
                        char *err,
                        size_t err_len);

int webd_backup_get(const char *backup_id,
                    struct webd_backup_meta *out,
                    char *err,
                    size_t err_len);

int webd_backup_list(struct webd_backup_list *out, char *err, size_t err_len);
void webd_backup_list_free(struct webd_backup_list *list);

int webd_backup_delete(const char *backup_id, char *err, size_t err_len);

/* Read-only fd on the stored artifact, re-verifying size and sha256. */
int webd_backup_open_readonly(const char *backup_id, char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif
