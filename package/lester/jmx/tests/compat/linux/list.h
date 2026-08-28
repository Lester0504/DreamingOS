#ifndef JMX_TEST_LINUX_LIST_H
#define JMX_TEST_LINUX_LIST_H

/* Only the type is needed: jmx.h embeds it in structs the fixture never walks. */
struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#endif
