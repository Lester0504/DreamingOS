// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __JMX_IDENTITY_COLLECTOR_H__
#define __JMX_IDENTITY_COLLECTOR_H__

int jmx_identity_collector_init(void);
int jmx_identity_collector_ready(void);
int jmx_identity_collector_listener_count(void);
void jmx_identity_collector_tick(void);
void jmx_identity_collector_close(void);

#endif
