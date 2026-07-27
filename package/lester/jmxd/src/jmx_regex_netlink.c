/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_regex_netlink.c - Send regex match results to kernel
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include "jmx_netlink.h"

#define JMX_NL_ACT_REGEX_RESULT 20

struct regex_result_msg {
	int32_t  action;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
	uint8_t  app_proto;
	uint8_t  af;
	uint8_t  _pad;
	uint32_t appid;
	uint8_t  host_len;
	uint8_t  _pad2[3];
	uint8_t  src_ip6[16];
	uint8_t  dst_ip6[16];
	char     host[128];
} __attribute__((packed));

int jmx_nl_send_regex_result_ex(int nl_fd, uint8_t af,
					 uint32_t src_ip, uint32_t dst_ip,
					 const void *src_ip6, const void *dst_ip6,
					 uint16_t src_port, uint16_t dst_port,
					 uint8_t proto, uint32_t appid,
					 uint8_t app_proto, const char *host)
{
	struct regex_result_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.action = JMX_NL_ACT_REGEX_RESULT;
	msg.af = af ? af : AF_INET;
	msg.src_ip = src_ip;
	msg.dst_ip = dst_ip;
	if (src_ip6)
		memcpy(msg.src_ip6, src_ip6, sizeof(msg.src_ip6));
	if (dst_ip6)
		memcpy(msg.dst_ip6, dst_ip6, sizeof(msg.dst_ip6));
	msg.src_port = src_port;
	msg.dst_port = dst_port;
	msg.proto = proto;
	msg.app_proto = app_proto;
	msg.appid = appid;
	if (host && host[0]) {
		size_t hlen = strlen(host);
		if (hlen > sizeof(msg.host) - 1)
			hlen = sizeof(msg.host) - 1;
		memcpy(msg.host, host, hlen);
		msg.host[hlen] = '\0';
		msg.host_len = (uint8_t)hlen;
	}

	return jmx_nl_send_msg_to_kernel(nl_fd, &msg, sizeof(msg));
}

int jmx_nl_send_regex_result(int nl_fd, uint32_t src_ip, uint32_t dst_ip,
			     uint16_t src_port, uint16_t dst_port,
			     uint8_t proto, uint32_t appid,
			     uint8_t app_proto, const char *host)
{
	return jmx_nl_send_regex_result_ex(nl_fd, AF_INET,
					      src_ip, dst_ip, NULL, NULL,
					      src_port, dst_port, proto, appid,
					      app_proto, host);
}
