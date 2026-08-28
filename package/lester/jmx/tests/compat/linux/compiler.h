#ifndef JMX_TEST_LINUX_COMPILER_H
#define JMX_TEST_LINUX_COMPILER_H

/* C11 assert.h provides static_assert, which the ABI header relies on. */
#include <assert.h>

#ifndef __always_inline
#define __always_inline inline
#endif

#endif
