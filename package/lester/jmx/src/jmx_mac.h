
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_MAC_H__
#define __JMX_MAC_H__
#define MAC_HASH_SIZE 128
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
struct mac_node {
    unsigned char mac[ETH_ALEN];  
    struct hlist_node hlist;  
};

typedef struct mac_config{
	struct hlist_head hash_table[MAC_HASH_SIZE];
}mac_config_t;

void jmx_mac_config_init(mac_config_t *config);
void jmx_add_mac_node(mac_config_t *config, const unsigned char *mac);
void jmx_dump_mac_node(mac_config_t *config);
struct mac_node *jmx_find_mac_node(mac_config_t *config, const unsigned char *mac);
int mac_str_to_bin(const char *mac_str, u8 *mac_bin);
struct mac_node *jmx_flush_mac_list(mac_config_t *config);

#endif
