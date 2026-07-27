/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_proto_decode.h - legacy account extraction helpers
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_PROTO_DECODE_H__
#define __JMX_PROTO_DECODE_H__

#include <stdint.h>
#include <stddef.h>
#include "jmx_rule.h"

/* Wire types */
#define PB_WIRE_VARINT   0
#define PB_WIRE_64BIT    1
#define PB_WIRE_LEN      2
#define PB_WIRE_32BIT    5

/* Buffer reader */
typedef struct {
	const uint8_t *data;
	size_t         len;
	size_t         pos;
} pb_reader_t;

static inline void pb_reader_init(pb_reader_t *r, const uint8_t *data, size_t len)
{
	r->data = data; r->len = len; r->pos = 0;
}
static inline int pb_reader_eof(const pb_reader_t *r) { return r->pos >= r->len; }

int pb_read_varint(pb_reader_t *r, uint64_t *out);
int pb_read_bytes(pb_reader_t *r, const uint8_t **out, size_t *out_len);
int pb_skip_field(pb_reader_t *r, uint32_t wire_type);
int pb_read_tag(pb_reader_t *r, uint32_t *field_number, uint32_t *wire_type);

/* Extract account ID from payload using NR rules for a given appid */
int jmx_nr_extract_account(const jmx_nr_rule_t *nr,
			   const uint8_t *payload, uint16_t len,
			   uint8_t proto, uint8_t dir,
			   char *account_buf, size_t account_buf_size);

/* Look up NR rules by appid and extract account (first match wins) */
int jmx_nr_match_and_extract(const jmx_rule_set_t *rs, uint32_t appid,
			     const uint8_t *payload, uint16_t len,
			     uint8_t proto, uint8_t dir,
			     char *account_buf, size_t account_buf_size);

#endif
