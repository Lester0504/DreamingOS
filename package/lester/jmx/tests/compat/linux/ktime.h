#ifndef JMX_TEST_LINUX_KTIME_H
#define JMX_TEST_LINUX_KTIME_H

#include "types.h"

/*
 * Fixture clock.  The wall clock is injected so expiry and rollback can be
 * exercised deterministically; a fixture that used the real clock would be a
 * different test every day.
 */
extern s64 jmx_test_wall_seconds;

static inline s64 ktime_get_real_seconds(void)
{
	return jmx_test_wall_seconds;
}

#endif
