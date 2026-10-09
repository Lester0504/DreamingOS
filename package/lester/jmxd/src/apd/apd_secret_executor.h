// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_SECRET_EXECUTOR_H
#define DREAMINGWRT_APD_SECRET_EXECUTOR_H

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>

struct apd_secret_transaction;

int apd_secret_executor_available(void);
int apd_secret_executor_init(void);

/* The result never contains the supplied secret or an old secret. */
int apd_secret_transaction_begin(const char *job_id,
                                 const char *request_digest,
                                 const char *ssid_id,
                                 int64_t secret_version,
                                 struct json_object *sections,
                                 const unsigned char *secret,
                                 size_t secret_len,
                                 struct apd_secret_transaction **out,
                                 struct json_object **result);
int apd_secret_transaction_commit(struct apd_secret_transaction *transaction);
int apd_secret_transaction_rollback(
    struct apd_secret_transaction *transaction, struct json_object **result);
void apd_secret_transaction_free(struct apd_secret_transaction *transaction);
int apd_secret_job_committed(const char *job_id, const char *request_digest,
                             int64_t secret_version);
int apd_secret_job_record_commit(const char *job_id,
                                 const char *request_digest,
                                 int64_t secret_version);

#endif
