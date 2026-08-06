// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Forwarding header. The permission layer lives in webd/jmx_app_perms.h.
 *
 * This path used to hold a second, independent copy of the risk and role
 * enums. Nothing included it - both webd/jmx_app_perms.c and
 * webd/jmx_app_api.c resolve "jmx_app_perms.h" to the copy beside them - so it
 * drifted out of sync and became actively dangerous: after JMX_RISK_LOW_WRITE
 * was inserted at 1, this file still called 1 MEDIUM while the live header
 * calls it LOW_WRITE. A new file under src/ that included this path (the more
 * natural-looking one) would have silently mapped MEDIUM onto LOW_WRITE and
 * widened permissions, with no compile error to catch it.
 *
 * Forwarding rather than deleting keeps the path usable while making a second
 * definition impossible.
 */
#ifndef __JMX_APP_PERMS_FORWARD_H__
#define __JMX_APP_PERMS_FORWARD_H__

#include "webd/jmx_app_perms.h"

#endif /* __JMX_APP_PERMS_FORWARD_H__ */
