#ifndef JMX_TEST_LINUX_JIFFIES_H
#define JMX_TEST_LINUX_JIFFIES_H

extern unsigned long jiffies;

#define HZ 100UL
#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define msecs_to_jiffies(milliseconds) \
	((unsigned long)(((milliseconds) * HZ + 999UL) / 1000UL))

#endif
