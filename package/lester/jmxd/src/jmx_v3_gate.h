/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_V3_GATE_H__
#define __JMX_V3_GATE_H__

#include <stdint.h>
#include "jmx_nl_rule_v3.h"

/* Keep production closed until the bundled jmx.ko/dreamingwrt-core path has
 * passed loaded-kernel fault injection and packet-level shadow acceptance. */
#define JMX_V3_PRODUCTION_GATE_ENABLED 0

static inline uint8_t jmx_v3_effective_mode(uint8_t requested_mode)
{
	if (!JMX_V3_PRODUCTION_GATE_ENABLED ||
	    requested_mode > JMX_V3_MODE_ACTIVE)
		return JMX_V3_MODE_OFF;
	return requested_mode;
}

#endif /* __JMX_V3_GATE_H__ */
