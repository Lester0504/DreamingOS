/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_V3_NL_HANDLER_H__
#define __JMX_V3_NL_HANDLER_H__

#include <linux/types.h>

typedef int (*jmx_v3_nl_reply_fn)(u32 portid, u32 nlmsg_seq,
				  const void *data, u32 len);

/* Returns 1 for a recognized v3 action (including rejected messages), 0 when
 * the payload belongs to another ABI. */
int jmx_v3_nl_handle(const void *data, u32 len, u32 portid, u32 nlmsg_seq,
			     jmx_v3_nl_reply_fn reply);

#endif /* __JMX_V3_NL_HANDLER_H__ */
