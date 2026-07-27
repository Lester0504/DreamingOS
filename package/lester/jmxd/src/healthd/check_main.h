// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __CHECK_MAIN_H__
#define __CHECK_MAIN_H__

#include <signal.h>

#define JMX_HEALTH_STATUS_PATH "/tmp/dreamingwrt-health.status"
#define JMX_WAN_HEALTH_STATUS_PATH "/tmp/dreamingwrt-wan-health.status"
#define JMX_HEALTH_STATUS_STALE_SEC 120

int jmx_health_run(volatile sig_atomic_t *stop);

#endif 
