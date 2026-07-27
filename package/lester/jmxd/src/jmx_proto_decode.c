/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_proto_decode.c - legacy protobuf helpers retained only for optional account extraction
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

/* ── Legacy protobuf DB loader: unused by DreamingWrt signature DB runtime. ── */
static int legacy_jmx_load_app_dat(const char *path, const char *aes_key, jmx_rule_set_t *rs)
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

/* ═══════════════════════════════════════════════════════════════════
 * NR (Number Recognition) helper for legacy protobuf rule containers
 * Binary protobuf format:
 *   repeated message {
 *     field 1 (varint): appid
 *     field 2 (bytes):  NR rule container {
 *       field 1 (varint): rule_type
 *       field 2 (bytes):  DPI match rule (ik_app format)
 *       field 3 (bytes, repeated): extraction pattern {
 *         f1 (varint): proto (0=any)
 *         f4 (varint): type (0=body, 7=cookie)
 *         f5 (bytes):  prefix string (e.g. "uin_cookie=")
 *         f8 (varint): is_header flag
 *         f13 (varint): is_reply flag
 *       }
 *       field 4 (bytes, repeated): char range {
 *         f1 (varint): min_char
 *         f2 (varint): max_char
 *       }
 *       field 5 (varint): max_account_len
 *       field 9 (varint): enabled (1)
 *     }
 *     field 3 (bytes): app_name
 *     field 4 (varint): flag
 *   }
 * ═══════════════════════════════════════════════════════════════════ */

/* Parse a single NR extraction pattern (field 3 sub-message) */
static int parse_nr_extract(const uint8_t *data, size_t len, jmx_nr_extract_t *ext)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	const uint8_t *b;
	size_t bl;

	memset(ext, 0, sizeof(*ext));
	pb_reader_init(&r, data, len);

	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		switch (fn) {
		case 1: /* proto */
			if (wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
				ext->proto = (uint8_t)v;
			else pb_skip_field(&r, wt);
			break;
		case 4: /* type */
			if (wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
				ext->type = (uint8_t)v;
			else pb_skip_field(&r, wt);
			break;
		case 5: /* prefix string */
			if (wt == PB_WIRE_LEN && pb_read_bytes(&r, &b, &bl) == 0) {
				if (bl > JMX_MAX_NR_PREFIX_LEN - 1)
					bl = JMX_MAX_NR_PREFIX_LEN - 1;
				memcpy(ext->prefix, b, bl);
				ext->prefix[bl] = '\0';
				ext->prefix_len = (uint16_t)bl;
			} else pb_skip_field(&r, wt);
			break;
		case 8: /* is_header */
			if (wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
				ext->is_header = (uint8_t)v;
			else pb_skip_field(&r, wt);
			break;
		case 13: /* is_reply */
			if (wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
				ext->is_reply = (uint8_t)v;
			else pb_skip_field(&r, wt);
			break;
		default:
			pb_skip_field(&r, wt);
			break;
		}
	}
	return 0;
}

/* Parse char range (field 4 sub-message) */
static int parse_nr_char_range(const uint8_t *data, size_t len, jmx_nr_char_range_t *cr)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;

	cr->min_char = 0;
	cr->max_char = 127;
	pb_reader_init(&r, data, len);

	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn == 1 && wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
			cr->min_char = (uint8_t)v;
		else if (fn == 2 && wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
			cr->max_char = (uint8_t)v;
		else pb_skip_field(&r, wt);
	}
	return 0;
}

/* Parse a single NR rule container (field 2 of top-level message) */
static int parse_nr_rule_container(const uint8_t *data, size_t len,
				   uint32_t appid, const char *app_name,
				   jmx_rule_set_t *rs)
{
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	const uint8_t *b;
	size_t bl;
	jmx_nr_rule_t nr;

	memset(&nr, 0, sizeof(nr));
	nr.appid = appid;
	if (app_name) {
		strncpy(nr.app_name, app_name, JMX_MAX_NR_ID_NAME_LEN - 1);
		nr.app_name[JMX_MAX_NR_ID_NAME_LEN - 1] = '\0';
	}

	pb_reader_init(&r, data, len);

	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;

		switch (fn) {
		case 1: /* rule_type */
			if (wt == PB_WIRE_VARINT)
				pb_read_varint(&r, &v);
			else pb_skip_field(&r, wt);
			break;
		case 2: /* DPI match rule (skip; runtime matching uses DreamingWrt DB) */
			pb_skip_field(&r, wt);
			break;
		case 3: /* extraction pattern (repeated) */
			if (wt == PB_WIRE_LEN && pb_read_bytes(&r, &b, &bl) == 0) {
				if (nr.extract_count < JMX_MAX_NR_EXTRACTS) {
					parse_nr_extract(b, bl,
						&nr.extracts[nr.extract_count]);
					nr.extract_count++;
				}
			} else pb_skip_field(&r, wt);
			break;
		case 4: /* char range (repeated) */
			if (wt == PB_WIRE_LEN && pb_read_bytes(&r, &b, &bl) == 0) {
				if (nr.char_range_count < JMX_MAX_NR_CHAR_RANGES) {
					parse_nr_char_range(b, bl,
						&nr.char_ranges[nr.char_range_count]);
					nr.char_range_count++;
				}
			} else pb_skip_field(&r, wt);
			break;
		case 5: /* max_account_len */
			if (wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
				nr.max_account_len = (uint16_t)v;
			else pb_skip_field(&r, wt);
			break;
		case 9: /* enabled */
			if (wt == PB_WIRE_VARINT && pb_read_varint(&r, &v) == 0)
				nr.enabled = (uint8_t)v;
			else pb_skip_field(&r, wt);
			break;
		default:
			pb_skip_field(&r, wt);
			break;
		}
	}

	/* Only add if enabled and has extraction patterns */
	if (nr.enabled && nr.extract_count > 0) {
		jmx_rule_set_add_nr(rs, &nr);
		fprintf(stderr, "  NR rule: appid=%u name=%s extracts=%u char_ranges=%u max_len=%u\n",
			appid, nr.app_name, nr.extract_count,
			nr.char_range_count, nr.max_account_len);
	}

	return 0;
}

/* Legacy NR file loader: unused by DreamingWrt signature DB runtime. */
static int legacy_jmx_load_audit_json(const char *path, jmx_rule_set_t *rs)
{
	FILE *f;
	uint8_t *data;
	long file_size;
	pb_reader_t r;
	uint32_t fn, wt;
	uint64_t v;
	const uint8_t *b;
	size_t bl;
	uint32_t appid;
	const char *app_name;
	char app_name_buf[JMX_MAX_NR_ID_NAME_LEN];
	int msg_count = 0;

	if (!path || !rs) return -1;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "Cannot open %s\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = malloc(file_size);
	if (!data) { fclose(f); return -1; }
	if (fread(data, 1, file_size, f) != (size_t)file_size) {
		free(data); fclose(f); return -1;
	}
	fclose(f);

	fprintf(stderr, "Loading NR rules from %s (%ld bytes)\n", path, file_size);

	pb_reader_init(&r, data, file_size);

	while (!pb_reader_eof(&r)) {
		if (pb_read_tag(&r, &fn, &wt) < 0) break;
		if (fn != 1 || wt != PB_WIRE_LEN) {
			pb_skip_field(&r, wt);
			continue;
		}
		if (pb_read_bytes(&r, &b, &bl) < 0) break;

		/* Parse top-level message: appid + NR container + app_name */
		appid = 0;
		app_name = NULL;
		const uint8_t *nr_data = NULL;
		size_t nr_len = 0;

		pb_reader_t mr;
		pb_reader_init(&mr, b, bl);
		while (!pb_reader_eof(&mr)) {
			uint32_t mfn, mwt;
			const uint8_t *mb;
			size_t mbl;
			uint64_t mv;
			if (pb_read_tag(&mr, &mfn, &mwt) < 0) break;
			switch (mfn) {
			case 1: /* appid */
				if (mwt == PB_WIRE_VARINT && pb_read_varint(&mr, &mv) == 0)
					appid = (uint32_t)mv;
				else pb_skip_field(&mr, mwt);
				break;
			case 2: /* NR rule container */
				if (mwt == PB_WIRE_LEN && pb_read_bytes(&mr, &mb, &mbl) == 0) {
					nr_data = mb;
					nr_len = mbl;
				} else pb_skip_field(&mr, mwt);
				break;
			case 3: /* app_name */
				if (mwt == PB_WIRE_LEN && pb_read_bytes(&mr, &mb, &mbl) == 0) {
					size_t cplen = mbl < JMX_MAX_NR_ID_NAME_LEN - 1 ?
						       mbl : JMX_MAX_NR_ID_NAME_LEN - 1;
					memcpy(app_name_buf, mb, cplen);
					app_name_buf[cplen] = '\0';
					app_name = app_name_buf;
					jmx_rule_set_add_app_info(rs, appid, app_name);
				} else pb_skip_field(&mr, mwt);
				break;
			default:
				pb_skip_field(&mr, mwt);
				break;
			}
		}

		if (appid > 0 && nr_data && nr_len > 0) {
			parse_nr_rule_container(nr_data, nr_len, appid, app_name, rs);
			msg_count++;
		}
	}

	free(data);
	fprintf(stderr, "Loaded %d NR rules, total NR rules in set: %u\n",
		msg_count, rs->nr_count);
	return 0;
}

/* ── NR account extraction ── */

/* Check if a byte is in any of the allowed char ranges */
static int nr_char_allowed(const jmx_nr_rule_t *nr, uint8_t c)
{
	int i;
	if (nr->char_range_count == 0)
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
		       (c >= 'A' && c <= 'Z');
	for (i = 0; i < nr->char_range_count; i++) {
		if (c >= nr->char_ranges[i].min_char &&
		    c <= nr->char_ranges[i].max_char)
			return 1;
	}
	return 0;
}

/*
 * Try to extract an account ID from payload using an NR rule.
 * For each extraction pattern, search for the prefix in the payload,
 * then extract the following characters that match the char ranges.
 *
 * Returns: length of extracted account (0 = no match)
 * account_buf: filled with the extracted account string (null-terminated)
 */
int jmx_nr_extract_account(const jmx_nr_rule_t *nr,
			   const uint8_t *payload, uint16_t len,
			   uint8_t proto, uint8_t dir,
			   char *account_buf, size_t account_buf_size)
{
	int ei;
	uint16_t pos;
	uint16_t max_len;

	if (!nr || !payload || !account_buf || account_buf_size == 0)
		return 0;

	max_len = nr->max_account_len > 0 ? nr->max_account_len : 64;
	if (max_len >= account_buf_size)
		max_len = account_buf_size - 1;

	for (ei = 0; ei < nr->extract_count; ei++) {
		const jmx_nr_extract_t *ext = &nr->extracts[ei];
		uint16_t plen = ext->prefix_len;

		/* Skip if prefix is empty */
		if (plen == 0) continue;

		/* Direction filter */
		if (ext->is_reply && dir != JMX_DIR_REPLY) continue;

		/* Search for prefix in payload */
		for (pos = 0; pos + plen <= len; pos++) {
			if (memcmp(payload + pos, ext->prefix, plen) != 0)
				continue;

			/* Found prefix at pos+plen, extract account */
			uint16_t start = pos + plen;
			uint16_t alen = 0;

			while (start + alen < len && alen < max_len) {
				uint8_t c = payload[start + alen];
				if (!nr_char_allowed(nr, c))
					break;
				account_buf[alen] = c;
				alen++;
			}

			if (alen > 0) {
				account_buf[alen] = '\0';
				return alen;
			}
		}
	}

	return 0;
}

/*
 * Look up NR rules by appid and try to extract account.
 * Returns number of accounts extracted (0 = no match).
 * First match wins.
 */
int jmx_nr_match_and_extract(const jmx_rule_set_t *rs, uint32_t appid,
			     const uint8_t *payload, uint16_t len,
			     uint8_t proto, uint8_t dir,
			     char *account_buf, size_t account_buf_size)
{
	uint32_t bucket = appid % JMX_HASH_BUCKETS;
	jmx_nr_rule_t *nr;

	if (!rs || !account_buf || account_buf_size == 0)
		return 0;

	for (nr = rs->nr_buckets[bucket]; nr; nr = nr->next) {
		if (nr->appid != appid) continue;
		if (jmx_nr_extract_account(nr, payload, len, proto, dir,
					   account_buf, account_buf_size) > 0)
			return 1;
	}
	return 0;
}
