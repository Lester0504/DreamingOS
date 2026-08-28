#ifndef JMX_TEST_LINUX_SLAB_H
#define JMX_TEST_LINUX_SLAB_H

#include <stdlib.h>
#include <string.h>

#define GFP_KERNEL 0U
#define __GFP_ZERO 1U

static inline void *kzalloc(size_t size, unsigned int flags)
{
	(void)flags;
	return calloc(1, size);
}

static inline void kfree(void *memory)
{
	free(memory);
}

static inline void *kmemdup(const void *source, size_t size, unsigned int flags)
{
	void *copy;

	(void)flags;
	if (!source || size == 0)
		return NULL;
	copy = malloc(size);
	if (!copy)
		return NULL;
	memcpy(copy, source, size);
	return copy;
}

#endif
