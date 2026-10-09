#ifndef JMX_TEST_LINUX_PROC_FS_H
#define JMX_TEST_LINUX_PROC_FS_H

#include <stddef.h>
#include <sys/types.h>
#ifdef __APPLE__
typedef off_t loff_t;
#endif

struct inode { int unused; };
struct file { void *private_data; };
struct proc_ops {
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	void *proc_write;
};
struct proc_dir_entry {
	const struct proc_ops *ops;
	unsigned int mode;
};
extern struct proc_dir_entry jmx_test_proc_entry;
extern int jmx_test_proc_fail;

static inline struct proc_dir_entry *proc_create(const char *name,
		unsigned int mode, struct proc_dir_entry *parent,
		const struct proc_ops *ops)
{
	if (jmx_test_proc_fail)
		return NULL;
	jmx_test_proc_entry.ops = ops;
	jmx_test_proc_entry.mode = mode;
	return &jmx_test_proc_entry;
}

static inline void proc_remove(struct proc_dir_entry *entry)
{
	if (entry)
		entry->ops = NULL;
}
#endif
