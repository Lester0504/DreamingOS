#ifndef JMX_TEST_LINUX_ERRNO_H
#define JMX_TEST_LINUX_ERRNO_H
#include <errno.h>

/* glibc's bits/errno.h includes <linux/errno.h>.  Under this test shim that
 * resolves back here, so provide the Linux ABI values that the fixture uses. */
#ifndef EPERM
#define EPERM 1
#endif
#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef EACCES
#define EACCES 13
#endif
#ifndef E2BIG
#define E2BIG 7
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EBUSY
#define EBUSY 16
#endif
#ifndef ENODEV
#define ENODEV 19
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ERANGE
#define ERANGE 34
#endif
#ifndef EBADMSG
#define EBADMSG 74
#endif
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif
#ifndef EALREADY
#define EALREADY 114
#endif
#ifndef ECANCELED
#define ECANCELED 125
#endif
#ifndef EKEYREJECTED
#define EKEYREJECTED 129
#endif
#endif
