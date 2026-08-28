#ifndef JMX_TEST_LINUX_JIFFIES_H
#define JMX_TEST_LINUX_JIFFIES_H

extern unsigned long jiffies;

#define HZ 100UL
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)

#endif
