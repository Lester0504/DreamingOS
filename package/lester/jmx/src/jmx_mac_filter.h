
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_MAC_FILTER_H__
#define __JMX_MAC_FILTER_H__
#include "k_json.h"
#include "jmx_mac.h"
#include <linux/list.h>

#define MAX_MAC_FILTER_RULE_NUM 64

typedef struct mac_filter_rule {
    int rule_id;                 // 规则ID
    mac_config_t mac_list;      // MAC地址列表
    struct list_head list;      // 链表节点
} mac_filter_rule_t;

extern int g_mac_filter_enable;


int jmx_api_add_mac_filter_whitelist(cJSON *data_obj);
int jmx_api_del_mac_filter_whitelist(cJSON *data_obj);
int jmx_api_flush_mac_filter_whitelist(cJSON *data_obj);


int jmx_match_mac_filter_whitelist(const unsigned char *mac);


int jmx_mac_filter_init(void);


void jmx_mac_filter_exit(void);


mac_filter_rule_t *jmx_match_mac_filter_rule(const unsigned char *mac);


int jmx_api_add_mac_filter_rule(cJSON *data_obj);


int jmx_api_del_mac_filter_rule(cJSON *data_obj);


int jmx_api_dump_mac_filter_rule(cJSON *data_obj);


int jmx_api_flush_mac_filter_rule(cJSON *data_obj);


int jmx_api_mod_mac_filter_rule(cJSON *data_obj);

#endif 
