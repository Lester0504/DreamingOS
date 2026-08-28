#ifndef JMX_TEST_LINUX_BUILD_BUG_H
#define JMX_TEST_LINUX_BUILD_BUG_H
#define static_assert(condition, ...) _Static_assert(condition, #condition)
#endif
