// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_CONFIG_RECOVERY_H
#define DREAMINGWRT_APD_CONFIG_RECOVERY_H

#include <stdint.h>

#include "apd_config_executor.h"
#include "apd_config_job_journal.h"

typedef int (*apd_config_finish_id_fn)(
    char out[APD_CONFIG_JOB_UUID_LEN + 1]);

/* Drain every non-terminal row before transport starts. Rows that could
 * have touched live UCI are rolled back; rollback failure is fatal and
 * deliberately leaves the row non-terminal for the next supervisor retry. */
int apd_config_jobs_restart_recover(
    const struct apd_config_paths *paths, int64_t now,
    apd_config_finish_id_fn finish_id, int *recovered);

#endif
