#ifndef JMXD_TEST_LINUX_NETLINK_H
#define JMXD_TEST_LINUX_NETLINK_H

#include <stdint.h>
#include <sys/socket.h>

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

struct sockaddr_nl {
	sa_family_t nl_family;
	unsigned short nl_pad;
	uint32_t nl_pid;
	uint32_t nl_groups;
};

struct nlmsghdr {
	uint32_t nlmsg_len;
	uint16_t nlmsg_type;
	uint16_t nlmsg_flags;
	uint32_t nlmsg_seq;
	uint32_t nlmsg_pid;
};

#define NLM_F_REQUEST 0x01U
#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1U) & ~(NLMSG_ALIGNTO - 1U))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(header) ((void *)((char *)(header) + NLMSG_HDRLEN))

#endif
