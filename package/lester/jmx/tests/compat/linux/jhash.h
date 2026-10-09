#ifndef JMX_TEST_LINUX_JHASH_H
#define JMX_TEST_LINUX_JHASH_H

#include "types.h"

/*
 * Deterministic host-side stand-in for the kernel Jenkins hash.  The license
 * fixtures only require stable avalanche and seed participation, not bit-for-
 * bit equality with the target kernel.
 */
static inline u32 jmx_test_jhash_mix(u32 value)
{
	value += value << 10;
	value ^= value >> 6;
	value += value << 3;
	value ^= value >> 11;
	value += value << 15;
	return value;
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return jmx_test_jhash_mix(a ^ jmx_test_jhash_mix(initval));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
	return jmx_test_jhash_mix(jhash_1word(a, b ^ initval));
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	return jmx_test_jhash_mix(jhash_1word(a, jhash_2words(b, c, initval)));
}

static inline u32 jhash2(const u32 *words, u32 length, u32 initval)
{
	u32 hash = initval;
	u32 i;

	for (i = 0; i < length; i++)
		hash = jmx_test_jhash_mix(hash ^ words[i]);
	return hash;
}

#endif
