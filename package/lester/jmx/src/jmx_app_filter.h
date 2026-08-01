
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_APP_FILTER_H__
#define __JMX_APP_FILTER_H__
#include "k_json.h"
#include "jmx_mac.h"
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/types.h>

#define MAX_APP_FILTER_RULE_NUM 64
#define MAX_APP_ID_PER_RULE 1024

extern u_int32_t g_appfilter_update_jiffies;

typedef struct app_id_node {
    int app_id;
    struct hlist_node hlist;
} app_id_node_t;


typedef struct app_id_config {
    struct hlist_head hash_table[256];  // 使用app_id作为hash key
    int count;
} app_id_config_t;


typedef struct app_filter_rule {
    int rule_id;                
    int enable;                 
    mac_config_t mac_list;      
    app_id_config_t app_id_list; 
    atomic64_t hit_count;
    atomic64_t last_hit_s;
    struct list_head list;  
} app_filter_rule_t;

extern int g_appfilter_enable;


int jmx_app_filter_init(void);


void jmx_app_filter_exit(void);


int jmx_match_app_filter_rule_record(int app_id, const unsigned char *mac,
                                     int *rule_id);


int jmx_api_add_app_filter_rule(cJSON *data_obj);


int jmx_api_del_app_filter_rule(cJSON *data_obj);


int jmx_api_dump_app_filter_rule(cJSON *data_obj);


int jmx_api_flush_app_filter_rule(cJSON *data_obj);


int jmx_api_mod_app_filter_rule(cJSON *data_obj);


int jmx_api_add_app_filter_whitelist(cJSON *data_obj);
int jmx_api_flush_app_filter_whitelist(cJSON *data_obj);


int jmx_match_app_filter_whitelist(const unsigned char *mac);

#endif
