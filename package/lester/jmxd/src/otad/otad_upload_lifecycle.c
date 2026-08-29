// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"
#include "otad_upload_lifecycle.h"
#include "../webd/webd_upload_staging.h"

int otad_consumed_upload_cleanup(const char *operation_id,
                                 int *deleted,
                                 char *error,
                                 size_t error_len)
{
    struct otad_operation_work work;

    if (deleted)
        *deleted = 0;
    if (error && error_len)
        error[0] = '\0';
    if (!otad_operation_id_ok(operation_id) ||
        otad_operation_get_work(operation_id, &work) != 0) {
        if (error && error_len)
            snprintf(error, error_len, "%s", "operation_not_found");
        return -1;
    }
    if (strcmp(work.kind, "firmware") || strcmp(work.action, "apply") ||
        strcmp(work.state, "success"))
        return 1;
    if (!work.upload_id[0])
        return 0;
    if (!otad_upload_id_ok(work.upload_id)) {
        if (error && error_len)
            snprintf(error, error_len, "%s", "operation_upload_id_invalid");
        return -1;
    }
    return webd_upload_delete_privileged(work.upload_id, deleted,
                                         error, error_len);
}
