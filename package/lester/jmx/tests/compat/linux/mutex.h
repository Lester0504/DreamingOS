#ifndef JMX_TEST_LINUX_MUTEX_H
#define JMX_TEST_LINUX_MUTEX_H

struct mutex {
	int held;
};

#define DEFINE_MUTEX(name) struct mutex name = { 0 }

static inline void mutex_lock(struct mutex *lock)
{
	lock->held++;
}

static inline void mutex_unlock(struct mutex *lock)
{
	lock->held--;
}

static inline void mutex_init(struct mutex *lock)
{
	lock->held = 0;
}

static inline void mutex_destroy(struct mutex *lock)
{
	lock->held = 0;
}

#define lockdep_is_held(lock) ((lock)->held > 0)
#define lockdep_assert_held(lock) ((void)(lock))

#endif
