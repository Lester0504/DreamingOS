/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_proto_decode.c - Protobuf wire-format decoder for iKuai app.dat
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Real field mapping (reverse-engineered):
 *   field 2  (varint) : pkt_seq or match sub-type (values 0,6,17)
 *   field 3  (varint) : direction/type (0,1,2) - not proto
 *   field 4  (varint) : proto? (0=none, 1=TCP?, 2=UDP?)
 *   field 5  (bytes)  : match_str (raw bytes, regex or BM pattern)
 *   field 7  (varint) : appid
 *   field 10 (bytes, repeated) : port_range (sub: f1=min, f2=max)
 *   field 11 (bytes)  : len_range (sub: f1=min, f2=max)
 *   field 19 (varint) : priority
 *   field 20 (varint) : rule_id
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "jmx_proto_decode.h"
#include "jmx_rule.h"

/* ── Wire-format primitives ── */

int pb_read_varint(pb_reader_t *r, uint64_t *out)
{
	uint64_t result = 0;
	int shift = 0;
	while (r->pos < r->len) {
		uint8_t byte = r->data[r->pos++];
		result |= (uint64_t)(byte & 0x7F) << shift;
		if (!(byte & 0x80)) { *out = result; return 0; }
		shift += 7;
		if (shift >= 64) return -1;
	}
	return -1;
}

int pb_read_bytes(pb_reader_t *r, const uint8_t **out, size_t *out_len)
{
	uint64_t len;
	if (pb_read_varint(r, &len) < 0) return -1;
	if (r->pos + len > r->len) return -1;
	*out = r->data + r->pos;
	*out_len = (size_t)len;
	r->pos += (size_t)len;
	return 0;
}

int pb_skip_field(pb_reader_t *r, uint32_t wire_type)
{
	uint64_t val;
	const uint8_t *tmp;
	size_t tmp_len;
	switch (wire_type) {
	case PB_WIRE_VARINT: return pb_read_varint(r, &val);
	case PB_WIRE_64BIT:
		if (r->pos + 8 > r->len) return -1;
		r->pos += 8; return 0;
	case PB_WIRE_LEN: return pb_read_bytes(r, &tmp, &tmp_len);
	case PB_WIRE_32BIT:
		if (r->pos + 4 > r->len) return -1;
		r->pos += 4; return 0;
	default: return -1;
	}
}

int pb_read_tag(pb_reader_t *r, uint32_t *field_number, uint32_t *wire_type)
{
	uint64_t tag;
	if (pb_read_varint(r, &tag) < 0) return -1;
	*field_number = (uint32_t)(tag >> 3);
	*wire_type = (uint32_t)(tag & 0x7);
	return 0;
}

/* ── Parse port_range sub-message ── */
static int parse_port_range(const uint8_t *data, size_t len,
			    jmx_port_range_t *pr)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	pr->min_port = 0;
	pr->max_port = 0;
	pb_reader_init(&r, data, len);
	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn == 1 && wt == PB_WIRE_VARINT) {
			if (pb_read_varint(&r, &v) == 0) pr->min_port = (uint16_t)v;
		} else if (fn == 2 && wt == PB_WIRE_VARINT) {
			if (pb_read_varint(&r, &v) == 0) pr->max_port = (uint16_t)v;
		} else {
			pb_skip_field(&r, wt);
		}
	}
	return 0;
}

/* ── Parse len_range sub-message ── */
static int parse_len_range(const uint8_t *data, size_t len, jmx_len_range_t *lr)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	lr->min_len = 0;
	lr->max_len = 0;
	pb_reader_init(&r, data, len);
	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn == 1 && wt == PB_WIRE_VARINT) {
			if (pb_read_varint(&r, &v) == 0) lr->min_len = (uint16_t)v;
		} else if (fn == 2 && wt == PB_WIRE_VARINT) {
			if (pb_read_varint(&r, &v) == 0) lr->max_len = (uint16_t)v;
		} else {
			pb_skip_field(&r, wt);
		}
	}
	return 0;
}

/* ── Parse AppMatchData (ik_app) ── */
static int parse_ik_app(const uint8_t *data, size_t len, jmx_match_rule_t *rule,
		 uint32_t appid_hint, const char *app_name)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	const uint8_t *b;
	size_t bl;

	memset(rule, 0, sizeof(*rule));
	rule->appid = appid_hint;
	rule->offset = -1;
	rule->dir = JMX_DIR_ANY;
	rule->proto = JMX_PROTO_ANY;

	pb_reader_init(&r, data, len);

	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;

		switch (fn) {
		case 2: /* pkt_seq or sub-type (varint: 0,6,17) */
			if (pb_read_varint(&r, &v) < 0) return -1;
			rule->pkt_seq = (uint32_t)v;
			break;
		case 3: /* direction/type (varint: 0,1,2) */
			if (pb_read_varint(&r, &v) < 0) return -1;
			rule->dir = (v == 0) ? JMX_DIR_ANY :
				    (v == 1) ? JMX_DIR_ORIGINAL :
				    JMX_DIR_REPLY;
			break;
		case 4: /* proto (varint: 1=TCP, 2=UDP, 0=none) */
			if (pb_read_varint(&r, &v) < 0) return -1;
			rule->proto = (v == 1) ? JMX_PROTO_TCP :
				      (v == 2) ? JMX_PROTO_UDP :
				      JMX_PROTO_ANY;
			break;
		case 5: /* match_str (bytes) */
			if (pb_read_bytes(&r, &b, &bl) < 0) return -1;
			if (bl > JMX_MAX_MATCH_STR_LEN - 1)
				bl = JMX_MAX_MATCH_STR_LEN - 1;
			memcpy(rule->match_str, b, bl);
			rule->match_str[bl] = '\0';
			rule->match_len = (uint16_t)bl;
			break;
		case 7: /* appid (varint) */
			if (pb_read_varint(&r, &v) < 0) return -1;
			rule->appid = (uint32_t)v;
			break;
		case 10: /* port_range (repeated, len-delimited) */
			if (pb_read_bytes(&r, &b, &bl) < 0) return -1;
			if (rule->port_count < JMX_MAX_PORT_RANGES) {
				parse_port_range(b, bl, &rule->ports[rule->port_count]);
				rule->port_count++;
			}
			break;
		case 11: /* len_range (len-delimited) */
			if (pb_read_bytes(&r, &b, &bl) < 0) return -1;
			if (rule->len_count < JMX_MAX_LEN_RANGES) {
				parse_len_range(b, bl, &rule->len_range[rule->len_count]);
				rule->len_count++;
			}
			break;
		case 19: /* priority */
			if (pb_read_varint(&r, &v) < 0) return -1;
			rule->priority = (uint32_t)v;
			break;
		case 20: /* rule_id */
			if (pb_read_varint(&r, &v) < 0) return -1;
			rule->rule_id = (uint32_t)v;
			break;
		default:
			if (pb_skip_field(&r, wt) < 0) return -1;
			break;
		}
	}

	/* Infer match_method from match_str */
	if (rule->match_len == 0) {
		rule->method = JMX_MATCH_NO_FIXED;
	} else {
		int has_regex = 0;
		for (size_t i = 0; i < rule->match_len; i++) {
			char c = rule->match_str[i];
			if (c == '^' || c == '$' || c == '*' || c == '+' ||
			    c == '?' || c == '[' || c == '(' || c == '|' ||
			    c == '\\') {
				has_regex = 1;
				break;
			}
		}
		rule->method = has_regex ? JMX_MATCH_REGEX : JMX_MATCH_BM_STR;
	}

	return 0;
}

/* ── Parse slot → repeated ik_app ── */
static int parse_slot(const uint8_t *data, size_t len, jmx_rule_set_t *rs)
{
	pb_reader_t r;
	uint32_t fn, wt;
	const uint8_t *b;
	size_t bl;
	pb_reader_init(&r, data, len);
	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn == 1 && wt == PB_WIRE_LEN) {
			if (pb_read_bytes(&r, &b, &bl) < 0) return -1;
			jmx_match_rule_t rule;
			if (parse_ik_app(b, bl, &rule, 0, NULL) == 0) {
				if (rule.appid > 0)
					jmx_rule_set_add_match(rs, &rule);
			}
		} else {
			if (pb_skip_field(&r, wt) < 0) break;
		}
	}
	return 0;
}

/* ── Parse extend_ik_data → slot[] ── */
static int parse_extend_ik_data(const uint8_t *data, size_t len,
				jmx_rule_set_t *rs)
{
	pb_reader_t r;
	uint32_t fn, wt;
	const uint8_t *b;
	size_t bl;
	pb_reader_init(&r, data, len);
	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn == 1 && wt == PB_WIRE_LEN) {
			if (pb_read_bytes(&r, &b, &bl) < 0) return -1;
			parse_slot(b, bl, rs);
		} else {
			if (pb_skip_field(&r, wt) < 0) break;
		}
	}
	return 0;
}

/* ── Parse top-level APP ── */
static int parse_app_message(const uint8_t *data, size_t len, jmx_rule_set_t *rs)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	const uint8_t *b;
	size_t bl;
	pb_reader_init(&r, data, len);
	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn == 5 && wt == PB_WIRE_LEN) {
			if (pb_read_bytes(&r, &b, &bl) < 0) return -1;
			return parse_extend_ik_data(b, bl, rs);
		} else if (wt == PB_WIRE_VARINT) {
			if (pb_read_varint(&r, &v) < 0) return -1;
		} else {
			if (pb_skip_field(&r, wt) < 0) break;
		}
	}
	return 0;
}

/* ── AES-128-CBC decryption ── */
static int decrypt_ikp(const char *path, const char *key_str,
		       uint8_t **out_data, size_t *out_len)
{
	FILE *f;
	uint8_t *file_data;
	long file_size;
	uint8_t salt[8], key[16], iv[16];
	uint8_t *decrypted;
	int dec_len, final_len;
	EVP_CIPHER_CTX *ctx;

	f = fopen(path, "rb");
	if (!f) return -1;
	fseek(f, 0, SEEK_END); file_size = ftell(f); fseek(f, 0, SEEK_SET);
	if (file_size < 16) { fclose(f); return -1; }
	file_data = malloc(file_size);
	if (!file_data) { fclose(f); return -1; }
	if (fread(file_data, 1, file_size, f) != (size_t)file_size) {
		free(file_data); fclose(f); return -1;
	}
	fclose(f);

	if (memcmp(file_data, "Salted__", 8) != 0) {
		*out_data = file_data; *out_len = file_size; return 0;
	}

	memcpy(salt, file_data + 8, 8);
	if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
			   (const unsigned char *)key_str,
			   strlen(key_str), 1, key, iv) != 16) {
		free(file_data); return -1;
	}
	decrypted = malloc(file_size + AES_BLOCK_SIZE);
	if (!decrypted) { free(file_data); return -1; }
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { free(file_data); free(decrypted); return -1; }
	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
		goto err;
	if (EVP_DecryptUpdate(ctx, decrypted, &dec_len,
			      file_data + 16, file_size - 16) != 1)
		goto err;
	if (EVP_DecryptFinal_ex(ctx, decrypted + dec_len, &final_len) != 1)
		goto err;
	dec_len += final_len;
	EVP_CIPHER_CTX_free(ctx); free(file_data);
	*out_data = decrypted; *out_len = dec_len;
	return 0;
err:
	EVP_CIPHER_CTX_free(ctx); free(file_data); free(decrypted);
	return -1;
}

/* ── Public API ── */
int jmx_load_app_dat(const char *path, const char *aes_key, jmx_rule_set_t *rs)
{
	uint8_t *data = NULL;
	size_t len = 0;
	int ret;
	if (!path || !rs) return -1;
	jmx_rule_set_init(rs);

	if (aes_key && aes_key[0])
		ret = decrypt_ikp(path, aes_key, &data, &len);
	else {
		FILE *f = fopen(path, "rb");
		if (!f) return -1;
		fseek(f, 0, SEEK_END); len = ftell(f); fseek(f, 0, SEEK_SET);
		data = malloc(len);
		if (!data) { fclose(f); return -1; }
		if (fread(data, 1, len, f) != len) {
			free(data); fclose(f); return -1;
		}
		fclose(f); ret = 0;
	}

	if (ret < 0 || !data || len == 0) {
		fprintf(stderr, "Failed to load %s\n", path); return -1;
	}
	fprintf(stderr, "Loaded %s: %zu bytes\n", path, len);

	if (len >= 2 && data[0] == 0x1f && data[1] == 0x8b) {
		uint8_t *decomp = malloc(len * 10);
		if (!decomp) { free(data); return -1; }
		z_stream zs = {0};
		zs.next_in = data; zs.avail_in = len;
		zs.next_out = decomp; zs.avail_out = len * 10;
		if (inflateInit2(&zs, 15 + 16) != Z_OK) {
			free(decomp); free(data); return -1;
		}
		if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
			inflateEnd(&zs); free(decomp); free(data); return -1;
		}
		inflateEnd(&zs); free(data);
		data = decomp; len = zs.total_out;
		fprintf(stderr, "Decompressed to %zu bytes\n", len);
	}

	ret = parse_app_message(data, len, rs);
	free(data);
	if (ret < 0) { fprintf(stderr, "Parse failed\n"); return -1; }

	fprintf(stderr, "Parsed: %u rules (%u fast, %u slow)\n",
		rs->total_rules, rs->fast_rules, rs->slow_rules);
	return 0;
}
