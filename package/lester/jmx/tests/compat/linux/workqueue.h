#ifndef JMX_TEST_LINUX_WORKQUEUE_H
#define JMX_TEST_LINUX_WORKQUEUE_H

#include <stddef.h>
#include <stdbool.h>

struct work_struct {
	void (*fn)(struct work_struct *work);
};

struct delayed_work {
	struct work_struct work;
};

#define INIT_DELAYED_WORK(item, callback) ((item)->work.fn = (callback))
#define INIT_WORK(item, callback) ((item)->fn = (callback))
#define system_wq NULL

#define WQ_UNBOUND 1U
#define WQ_MEM_RECLAIM 2U

struct workqueue_struct {
	int allocated;
};

extern struct workqueue_struct jmx_test_workqueue;
#ifdef JMX_TEST_DEFER_WORK
extern int jmx_test_defer_work;
int jmx_test_queue_work(struct work_struct *work);
#endif

static inline struct workqueue_struct *alloc_workqueue(const char *name,
						       unsigned int flags,
						       int max_active)
{
	(void)name;
	(void)flags;
	(void)max_active;
	return &jmx_test_workqueue;
}

static inline void destroy_workqueue(struct workqueue_struct *queue)
{
	(void)queue;
}

static inline void flush_workqueue(struct workqueue_struct *queue)
{
	(void)queue;
}

/*
 * Run the work inline.  The module offloads Ed25519 verification because it may
 * sleep; in a fixture there is nothing to sleep on, and running it synchronously
 * means a test can assert the resulting state right after the netlink call
 * instead of polling for it.
 */
static inline int queue_work(struct workqueue_struct *queue,
			     struct work_struct *work)
{
	(void)queue;
	if (!work || !work->fn)
		return 0;
#ifdef JMX_TEST_DEFER_WORK
	if (jmx_test_defer_work)
		return jmx_test_queue_work(work);
#endif
	work->fn(work);
	return 1;
}

static inline int mod_delayed_work(void *queue, struct delayed_work *work,
				   unsigned long delay)
{
	(void)queue;
	if (delay == 0 && work && work->work.fn)
		work->work.fn(&work->work);
	return 0;
}

static inline int queue_delayed_work(struct workqueue_struct *queue,
				     struct delayed_work *work,
				     unsigned long delay)
{
	(void)queue;
	if (delay == 0 && work && work->work.fn)
		work->work.fn(&work->work);
	return delay == 0 ? 1 : 0;
}

static inline void cancel_delayed_work_sync(struct delayed_work *work)
{
	(void)work;
}

static inline bool cancel_delayed_work(struct delayed_work *work)
{
	(void)work;
	return false;
}

#endif
