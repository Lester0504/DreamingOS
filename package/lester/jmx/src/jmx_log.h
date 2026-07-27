
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __AF_DEBUG_H__
#define __AF_DEBUG_H__
extern int jmx_test_mode;
extern int af_work_mode;
extern int g_app_filter_enable;
extern int g_record_enable;
extern int g_by_pass_accl;
extern unsigned int jmx_lan_ip;
extern unsigned int jmx_lan_mask;
extern int g_feature_init;
extern int g_user_mode;
extern char g_lan_ifname[64];
extern int g_tcp_rst;
extern int g_feature_count;

#define TEST_MODE() (jmx_test_mode)
int jmx_debug_level(void);
bool jmx_debug_at_least(int level);

#define JMX_DEBUG_RATELIMITED(level, fmt, ...) do { \
	if (jmx_debug_at_least(level)) \
		pr_info_ratelimited(fmt, ##__VA_ARGS__); \
} while (0)

int af_log_init(void);
int af_log_exit(void);
#endif
