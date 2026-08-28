#ifndef JMX_TEST_LINUX_PERCPU_H
#define JMX_TEST_LINUX_PERCPU_H

#define DECLARE_PER_CPU(type, name) extern type name
#define this_cpu_inc(value) ((value)++)

#endif
