// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_NETWORK_H__
#define __JMX_NETWORK_H__

#include <json-c/json.h>
#include <netinet/in.h>

#define MAX_INET_ADDR_LEN 32

typedef struct iface_status{
    int proto;
    char ip[MAX_INET_ADDR_LEN];
    char mask[MAX_INET_ADDR_LEN];
    char gateway[MAX_INET_ADDR_LEN];
    char dns1[MAX_INET_ADDR_LEN];
    char dns2[MAX_INET_ADDR_LEN];
    char ipv6[64];
}iface_status_t;

#define JMX_IPV6_CONTRACT_ADDR_MAX 8
#define JMX_IPV6_CONTRACT_TEXT_MAX 96

typedef struct jmx_iface_ipv6_contract {
    char global[JMX_IPV6_CONTRACT_TEXT_MAX];
    char link_local[JMX_IPV6_CONTRACT_TEXT_MAX];
    char delegated_prefix[JMX_IPV6_CONTRACT_TEXT_MAX];
    char addresses[JMX_IPV6_CONTRACT_ADDR_MAX][JMX_IPV6_CONTRACT_TEXT_MAX];
    int address_count;
} jmx_iface_ipv6_contract_t;

int get_iface_status(char *ifname, iface_status_t *status);
int jmx_iface_ipv6_contract_collect(const char *ifname,
                                    jmx_iface_ipv6_contract_t *contract);
void jmx_iface_ipv6_contract_add_json(struct json_object *obj,
                                      const char *ifname);
char *get_interface_status_buf(char *ifname);
char *cidr2str(int cidr);


struct json_object *jmx_api_get_lan_list(struct json_object *req_obj);
struct json_object *jmx_api_add_lan(struct json_object *req_obj);
struct json_object *jmx_api_mod_lan(struct json_object *req_obj);
struct json_object *jmx_api_del_lan(struct json_object *req_obj);
struct json_object *jmx_api_get_wan_list(struct json_object *req_obj);
struct json_object *jmx_api_add_wan(struct json_object *req_obj);
struct json_object *jmx_api_mod_wan(struct json_object *req_obj);
struct json_object *jmx_api_del_wan(struct json_object *req_obj);


struct json_object *jmx_api_get_lan_info(struct json_object *req_obj);
struct json_object *jmx_api_set_lan_info(struct json_object *req_obj);
struct json_object *jmx_api_get_wan_info(struct json_object *req_obj);
struct json_object *jmx_api_set_wan_info(struct json_object *req_obj);


struct json_object *jmx_api_get_work_mode(struct json_object *req_obj);
struct json_object *jmx_api_set_work_mode(struct json_object *req_obj);

#endif
