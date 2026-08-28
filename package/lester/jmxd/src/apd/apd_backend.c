// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_internal.h"

const struct apd_backend_ops *apd_backend(void)
{
    static const struct apd_backend_ops *selected;

    if (!selected)
        selected = apd_backend_mac80211_detect() ?
            apd_backend_mac80211() : apd_backend_openwrt();
    return selected;
}

struct json_object *apd_backend_disabled(const char *operation,
                                         const char *reason)
{
    return apd_write_disabled_json(operation, reason);
}
