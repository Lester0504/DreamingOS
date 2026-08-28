#ifndef JMX_TEST_LINUX_IN6_H
#define JMX_TEST_LINUX_IN6_H

#include "types.h"

/* Type only; the license fixture never inspects an address. */
struct in6_addr {
	u8 s6_addr[16];
};

#endif
