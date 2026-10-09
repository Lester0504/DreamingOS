#ifndef DREAMINGWRT_TEST_SYS_RANDOM_H
#define DREAMINGWRT_TEST_SYS_RANDOM_H

#include <stddef.h>
#include <sys/types.h>

ssize_t getrandom(void *buffer, size_t length, unsigned int flags);

#endif
