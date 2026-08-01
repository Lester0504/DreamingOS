// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __UTILS_H__
#define __UTILS_H__
#include <sys/types.h>

#define MAX_WEEKDAYS 7


typedef struct jmx_time_period {
    char start_time[16];      
    char end_time[16];         
    int weekdays[MAX_WEEKDAYS]; 
    int weekday_count;         
} jmx_time_period_t;

char *str_trim(char *s);
int check_same_network(char *ip1, char *netmask, char *ip2);
int af_read_file_value(const char *file_path, char *value, int value_len);
int af_read_file_int_value(const char *file_path, int *value);
int jmx_send_msg_to_kernel(char *buf);
int jmx_parse_time_str(const char *time_str, jmx_time_period_t *periods, int max_periods);
int jmx_update_proc_value(const char *key, const char *value);
void update_jmx_proc_value(char *key, char *value);
void update_jmx_proc_u32_value(char *key, u_int32_t value);
#endif
