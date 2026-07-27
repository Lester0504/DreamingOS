// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_internal.h"

const struct apd_backend_ops *apd_backend(void)
{
    return apd_backend_openwrt();
}

struct json_object *apd_backend_disabled(const char *operation,
                                         const char *reason)
{
    return apd_write_disabled_json(operation, reason);
}
