// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef OTAD_UPLOAD_LIFECYCLE_H
#define OTAD_UPLOAD_LIFECYCLE_H

#include <stddef.h>

int otad_consumed_upload_cleanup(const char *operation_id,
                                 int *deleted,
                                 char *error,
                                 size_t error_len);

#endif
