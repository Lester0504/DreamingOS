
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_NETLINK_H__
#define __JMX_NETLINK_H__
#define DEFAULT_JMX_NL_PID 999
#define JMX_V2_NL_PID 998
#define JMX_NETLINK_ID 29
#define MAX_JMX_NETLINK_MSG_LEN 131072
#define MAX_AF_MSG_DATA_LEN 800
#define MAX_FEATURE_LINE_LEN 8192

struct jmx_nl_msg_hdr
{
    int magic;
    int len;
};

enum E_JMX_NL_MSG_TYPE
{
    JMX_NL_MSG_INIT,
    JMX_NL_MSG_ADD_FEATURE,
    JMX_NL_MSG_CLEAN_FEATURE,
    JMX_NL_MSG_MAX
};

typedef struct jmx_nl_msg
{
    int action;
} jmx_nl_msg_t;

typedef struct jmx_nl_feature_msg{
    jmx_nl_msg_t hdr;
    char feature[MAX_FEATURE_LINE_LEN];
} jmx_nl_feature_msg_t;

int jmx_netlink_init(void);
int jmx_v2_netlink_init(void);
void jmx_netlink_handler(struct uloop_fd *u, unsigned int ev);
int jmx_nl_send_msg_to_kernel(int fd, void *msg, int len);
#endif
int jmx_nl_send_regex_result(int nl_fd, uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t proto, uint32_t appid,
                             uint8_t app_proto, const char *host);
int jmx_nl_send_regex_result_ex(int nl_fd, uint8_t af,
                                uint32_t src_ip, uint32_t dst_ip,
                                const void *src_ip6, const void *dst_ip6,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t proto, uint32_t appid,
                                uint8_t app_proto, const char *host);
