/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_V2_NL_HANDLER_H__
#define __JMX_V2_NL_HANDLER_H__

#include <linux/types.h>

#include "jmx_v3_nl_handler.h"

/* Returns 1 for a recognized v2 action, 0 when the payload is not v2. */
int jmx_v2_nl_handle(const char *data, int len, u32 portid, u32 nlmsg_seq,
		     jmx_v3_nl_reply_fn reply);

#endif /* __JMX_V2_NL_HANDLER_H__ */
