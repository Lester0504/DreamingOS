#ifndef JMX_TEST_LINUX_TYPES_H
#define JMX_TEST_LINUX_TYPES_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
/* jmx.h uses the BSD u_int*_t spellings. */
#include <sys/types.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t __u8;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

#define __force
#define __rcu
#define __packed __attribute__((packed))
#define U16_MAX UINT16_MAX
#define U32_MAX UINT32_MAX
#define unlikely(value) (value)

static inline void jmx_test_log(const char *format, ...)
{
	(void)format;
}

#define pr_info(...) jmx_test_log(__VA_ARGS__)
#define pr_warn(...) jmx_test_log(__VA_ARGS__)
#define pr_warn_ratelimited(...) jmx_test_log(__VA_ARGS__)
#define pr_info_ratelimited(...) jmx_test_log(__VA_ARGS__)
#define pr_err(...) jmx_test_log(__VA_ARGS__)
#define pr_emerg(...) jmx_test_log(__VA_ARGS__)
#define printk(...) jmx_test_log(__VA_ARGS__)
#define KERN_CONT ""
#define KERN_INFO ""

typedef struct {
	long long counter;
} atomic64_t;

#define ATOMIC64_INIT(value) { (value) }

static inline void atomic64_set(atomic64_t *value, long long next)
{
	value->counter = next;
}

static inline long long atomic64_inc_return(atomic64_t *value)
{
	return ++value->counter;
}

static inline void atomic64_inc(atomic64_t *value)
{
	value->counter++;
}

static inline long long atomic64_read(const atomic64_t *value)
{
	return value->counter;
}

static inline u16 le16_to_cpu(__le16 value)
{
	return value;
}

static inline u32 le32_to_cpu(__le32 value)
{
	return value;
}

static inline __le16 cpu_to_le16(u16 value)
{
	return value;
}

static inline __le32 cpu_to_le32(u32 value)
{
	return value;
}

/*
 * Big-endian helpers.  The host running these fixtures is little-endian, so
 * the conversion is a real byte swap rather than the identity used for the
 * __le* helpers above.  Wire bytes in the license ABI are big-endian, and a
 * fixture that swapped nothing would pass while the module misread the header.
 */
static inline u16 be16_to_cpu(__be16 value)
{
	return __builtin_bswap16(value);
}

static inline u32 be32_to_cpu(__be32 value)
{
	return __builtin_bswap32(value);
}

static inline u64 be64_to_cpu(__be64 value)
{
	return __builtin_bswap64(value);
}

static inline __be16 cpu_to_be16(u16 value)
{
	return __builtin_bswap16(value);
}

static inline __be32 cpu_to_be32(u32 value)
{
	return __builtin_bswap32(value);
}

static inline __be64 cpu_to_be64(u64 value)
{
	return __builtin_bswap64(value);
}

#endif
