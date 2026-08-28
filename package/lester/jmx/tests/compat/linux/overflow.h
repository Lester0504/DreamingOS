#ifndef JMX_TEST_LINUX_OVERFLOW_H
#define JMX_TEST_LINUX_OVERFLOW_H

#define check_add_overflow(a, b, out) __builtin_add_overflow((a), (b), (out))
#define check_mul_overflow(a, b, out) __builtin_mul_overflow((a), (b), (out))

#endif
