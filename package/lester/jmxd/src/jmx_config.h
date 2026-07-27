// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_CONFIG_H__
#define __JMX_CONFIG_H__

#include <sys/types.h>
#include <uci.h>

/* Legacy default. Do not treat this as a hard ceiling any more. */
#define MAX_SUPPORT_APP_NUM 1024
#define MAX_CLASS_NAME_LEN 32
#define MAX_FEATURE_CFG_LINE_LEN 8192

#include "jmx_user.h"

extern int g_cur_class_num;
extern int g_app_count;
extern int g_app_name_table_capacity;
extern int g_class_name_capacity;
extern char (*CLASS_NAME_TABLE)[MAX_CLASS_NAME_LEN];

typedef struct app_name_info {
    int id;
    char name[64];
} app_name_info_t;

void init_app_name_table(void);
void init_app_class_name_table(void);
void free_app_name_table(void);
void free_app_class_name_table(void);
char *get_app_name_by_id(int id);

int appfilter_config_alloc(void);
int appfilter_config_free(void);
int config_get_appfilter_enable(void);
int config_get_lan_ip(char *lan_ip, int len);
int config_get_lan_mask(char *lan_mask, int len);

#endif
