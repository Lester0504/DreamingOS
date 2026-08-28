#ifndef JMX_TEST_LINUX_VMALLOC_H
#define JMX_TEST_LINUX_VMALLOC_H

#include <stdint.h>
#include <stdlib.h>

static inline void *kvmalloc_array(size_t count, size_t size,
				   unsigned int flags)
{
	if (size && count > SIZE_MAX / size)
		return NULL;
	return flags & __GFP_ZERO ? calloc(count, size) : malloc(count * size);
}

static inline void *kvcalloc(size_t count, size_t size, unsigned int flags)
{
	(void)flags;
	if (size && count > SIZE_MAX / size)
		return NULL;
	return calloc(count, size);
}

static inline void kvfree(void *memory)
{
	free(memory);
}

#endif
