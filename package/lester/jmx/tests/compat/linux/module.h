#ifndef JMX_TEST_LINUX_MODULE_H
#define JMX_TEST_LINUX_MODULE_H

#include <stdbool.h>
#include <stdlib.h>

#include "types.h"

#define module_param(name, type, permissions)
#define MODULE_PARM_DESC(name, description)

enum mod_mem_type {
	MOD_TEXT = 0,
	MOD_DATA,
	MOD_RODATA,
	MOD_RO_AFTER_INIT,
	MOD_INIT_TEXT,
	MOD_INIT_DATA,
	MOD_INIT_RODATA,
	MOD_MEM_NUM_TYPES,
};

struct module_memory {
	unsigned char *base;
	bool is_rox;
	unsigned int size;
};

struct module {
	struct module_memory mem[MOD_MEM_NUM_TYPES];
	void (*exit)(void);
};

extern struct module __this_module;
#define THIS_MODULE (&__this_module)

static inline void panic(const char *reason)
{
	(void)reason;
	abort();
}

#endif
