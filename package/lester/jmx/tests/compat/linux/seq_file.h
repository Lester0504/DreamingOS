#ifndef JMX_TEST_LINUX_SEQ_FILE_H
#define JMX_TEST_LINUX_SEQ_FILE_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc_fs.h"

struct seq_file {
	char buffer[2048];
	size_t length;
};

static inline void seq_printf(struct seq_file *seq, const char *format, ...)
{
	va_list args;
	int n;

	va_start(args, format);
	n = vsnprintf(seq->buffer + seq->length,
		      sizeof(seq->buffer) - seq->length, format, args);
	va_end(args);
	if (n < 0 || (size_t)n >= sizeof(seq->buffer) - seq->length)
		abort();
	seq->length += (size_t)n;
}

static inline void seq_puts(struct seq_file *seq, const char *text)
{
	seq_printf(seq, "%s", text);
}

static inline int single_open(struct file *file,
		int (*show)(struct seq_file *, void *), void *data)
{
	struct seq_file *seq = calloc(1, sizeof(*seq));
	int ret;

	if (!seq)
		return -12;
	ret = show(seq, data);
	if (ret) {
		free(seq);
		return ret;
	}
	file->private_data = seq;
	return 0;
}

static inline ssize_t seq_read(struct file *file, char *buffer,
		size_t count, loff_t *offset)
{
	struct seq_file *seq = file->private_data;
	size_t n = *offset >= (loff_t)seq->length ? 0 : seq->length - *offset;
	if (n > count)
		n = count;
	memcpy(buffer, seq->buffer + *offset, n);
	*offset += n;
	return (ssize_t)n;
}

static inline loff_t seq_lseek(struct file *file, loff_t offset, int whence)
{
	return offset;
}

static inline int single_release(struct inode *inode, struct file *file)
{
	free(file->private_data);
	return 0;
}
#endif
