#ifndef JMX_TEST_LINUX_RANDOM_H
#define JMX_TEST_LINUX_RANDOM_H

#include <stdlib.h>
#include <time.h>

#include "types.h"

static inline u32 get_random_u32(void)
{
	return (u32)rand();
}

static inline void get_random_bytes(void *buffer, size_t length)
{
	u8 *bytes = buffer;
	size_t i;

	for (i = 0; i < length; i++)
		bytes[i] = (u8)rand();
}

#endif
