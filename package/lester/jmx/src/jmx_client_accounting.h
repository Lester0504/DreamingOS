// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __JMX_CLIENT_ACCOUNTING_H__
#define __JMX_CLIENT_ACCOUNTING_H__

#include <linux/types.h>

#define JMX_CLIENT_BYTE_SEMANTICS "client_direction_skb_len_v1"

enum jmx_client_packet_direction {
	JMX_CLIENT_PACKET_DIRECTION_UNKNOWN = 0,
	JMX_CLIENT_PACKET_DIRECTION_DOWNLOAD,
	JMX_CLIENT_PACKET_DIRECTION_UPLOAD,
};

struct jmx_client_byte_counters {
	u64 in_bytes;
	u64 out_bytes;
	u64 total_bytes;
};

static inline bool
jmx_account_client_packet(struct jmx_client_byte_counters *counters,
			  enum jmx_client_packet_direction direction,
			  u32 bytes, bool blocked)
{
	if (!counters || !bytes || blocked)
		return false;

	switch (direction) {
	case JMX_CLIENT_PACKET_DIRECTION_DOWNLOAD:
		counters->in_bytes += bytes;
		break;
	case JMX_CLIENT_PACKET_DIRECTION_UPLOAD:
		counters->out_bytes += bytes;
		break;
	default:
		return false;
	}

	counters->total_bytes += bytes;
	return true;
}

#endif
