#ifndef JMX_TEST_LINUX_RCUPDATE_H
#define JMX_TEST_LINUX_RCUPDATE_H

#define RCU_INIT_POINTER(pointer, value) ((pointer) = (value))
#define rcu_assign_pointer(pointer, value) ((pointer) = (value))
#define rcu_dereference(pointer) (pointer)
#define rcu_dereference_protected(pointer, condition) (pointer)

static inline void rcu_read_lock(void) {}
static inline void rcu_read_unlock(void) {}
static inline void synchronize_rcu(void) {}
static inline void rcu_barrier(void) {}

#endif
