
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_CONFIG_H__
#define __JMX_CONFIG_H__
#include "k_json.h"
#define JMX_CHAR_DEV "jmx"
typedef int (*k_request_handler)(cJSON *data_obj);
typedef struct k_request_item{
    const char *api;
    k_request_handler handle;
}k_request_item_t;


int jmx_register_dev(void);
void jmx_unregister_dev(void);
#endif
