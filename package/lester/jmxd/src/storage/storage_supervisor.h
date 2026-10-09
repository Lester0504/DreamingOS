// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_SUPERVISOR_H
#define DREAMINGWRT_STORAGE_SUPERVISOR_H

/* Forward-declared on purpose: storage_provider.c only needs
 * jmx_storage_supervisor_ready(), and pulling <libubus.h> in through this
 * header breaks the host-side contract fixtures, which have json-c and sqlite
 * but no ubus.  The implementation includes the real header itself. */
struct ubus_context;

/* Bind the core's live ubus context and install the migration hooks. */
int jmx_storage_supervisor_bind(struct ubus_context *ctx);
void jmx_storage_supervisor_unbind(void);
int jmx_storage_supervisor_ready(void);

#endif
