#ifndef JMX_TEST_LINUX_KERNEL_H
#define JMX_TEST_LINUX_KERNEL_H

#include <stddef.h>

#include "types.h"

/*
 * Single-threaded fixtures, so the barrier and the one-shot read are plain
 * accesses.  They exist so the module source compiles unchanged.
 */
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))

static inline void smp_wmb(void) {}
static inline void smp_rmb(void) {}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#ifndef container_of
#define container_of(pointer, type, member) \
	((type *)((char *)(pointer) - offsetof(type, member)))
#endif

#endif
