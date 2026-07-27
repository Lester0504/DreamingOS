/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_signature_db.c - DreamingWrt SQLite signature database loader
 *
 * This is the native replacement for the legacy iKuai app.dat / ik_audit rule
 * inputs. jmxd now consumes dreamingwrt_signatures.db directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include "jmx_signature_db.h"

static int streq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static jmx_proto_t parse_proto(const char *s)
{
    if (streq(s, "tcp")) return JMX_PROTO_TCP;
    if (streq(s, "udp")) return JMX_PROTO_UDP;
    return JMX_PROTO_ANY;
}

static jmx_dir_t parse_dir(const char *s)
{
    if (streq(s, "original") || streq(s, "orig") || streq(s, "request")) return JMX_DIR_ORIGINAL;
    if (streq(s, "reply") || streq(s, "response")) return JMX_DIR_REPLY;
    return JMX_DIR_ANY;
}

static jmx_match_method_t parse_method(const char *s)
{
    if (streq(s, "exact")) return JMX_MATCH_EXACT;
    if (streq(s, "bm") || streq(s, "bm_str") || streq(s, "contains")) return JMX_MATCH_BM_STR;
    if (streq(s, "regex")) return JMX_MATCH_REGEX;
    if (streq(s, "no_fixed") || streq(s, "nofixed")) return JMX_MATCH_NO_FIXED;
    return JMX_MATCH_REGEX;
}

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int copy_pattern(jmx_match_rule_t *r, const char *fmt, const char *text, const char *hex)
{
    size_t n = 0;
    if (fmt && strcmp(fmt, "hex") == 0 && hex && hex[0]) {
        size_t len = strlen(hex);
        size_t i;
        for (i = 0; i + 1 < len && n < JMX_MAX_MATCH_STR_LEN - 1; i += 2) {
            int hi = hex_nibble((unsigned char)hex[i]);
            int lo = hex_nibble((unsigned char)hex[i + 1]);
            if (hi < 0 || lo < 0) break;
            r->match_str[n++] = (char)((hi << 4) | lo);
        }
        r->match_len = (uint16_t)n;
        if (n < JMX_MAX_MATCH_STR_LEN) r->match_str[n] = '\0';
        return 0;
    }
    if (text && text[0]) {
        n = strlen(text);
        if (n > JMX_MAX_MATCH_STR_LEN - 1) n = JMX_MAX_MATCH_STR_LEN - 1;
        memcpy(r->match_str, text, n);
        r->match_str[n] = '\0';
        r->match_len = (uint16_t)n;
    }
    return 0;
}

static int load_apps(sqlite3 *db, jmx_rule_set_t *rs)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT app_id,name FROM app WHERE enabled=1 ORDER BY app_id";
    int rc, count = 0;
    rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint32_t appid = (uint32_t)sqlite3_column_int(st, 0);
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (appid && name) {
            if (jmx_rule_set_add_app_info(rs, appid, (const char *)name) != 0) {
                fprintf(stderr, "signature-db: app capacity or allocation failure at app_id=%u\n",
                        appid);
                sqlite3_finalize(st);
                return -1;
            }
            count++;
        }
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return count;
}

static void load_ports(sqlite3 *db, jmx_match_rule_t *rule)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT min_port,max_port FROM dpi_rule_port WHERE rule_id=?1 ORDER BY id LIMIT 8";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_int(st, 1, (int)rule->rule_id);
    while (sqlite3_step(st) == SQLITE_ROW && rule->port_count < JMX_MAX_PORT_RANGES) {
        rule->ports[rule->port_count].min_port = (uint16_t)sqlite3_column_int(st, 0);
        rule->ports[rule->port_count].max_port = (uint16_t)sqlite3_column_int(st, 1);
        rule->port_count++;
    }
    sqlite3_finalize(st);
}

static int load_rules(sqlite3 *db, jmx_rule_set_t *rs)
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT rule_id,app_id,proto,direction,match_type,pattern_format,"
        "pattern_text,pattern_hex,offset,priority,pkt_seq "
        "FROM dpi_rule WHERE enabled=1 ORDER BY priority ASC, rule_id ASC";
    int rc, seen = 0, added_before;
    rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        jmx_match_rule_t r;
        const char *proto = (const char *)sqlite3_column_text(st, 2);
        const char *dir = (const char *)sqlite3_column_text(st, 3);
        const char *mt = (const char *)sqlite3_column_text(st, 4);
        const char *fmt = (const char *)sqlite3_column_text(st, 5);
        const char *txt = (const char *)sqlite3_column_text(st, 6);
        const char *hex = (const char *)sqlite3_column_text(st, 7);
        memset(&r, 0, sizeof(r));
        r.rule_id = (uint32_t)sqlite3_column_int(st, 0);
        r.appid = (uint32_t)sqlite3_column_int(st, 1);
        r.proto = parse_proto(proto);
        r.dir = parse_dir(dir);
        r.method = parse_method(mt);
        r.offset = sqlite3_column_type(st, 8) == SQLITE_NULL ? -1 : sqlite3_column_int(st, 8);
        r.priority = sqlite3_column_type(st, 9) == SQLITE_NULL ? 50 : (uint32_t)sqlite3_column_int(st, 9);
        r.pkt_seq = sqlite3_column_type(st, 10) == SQLITE_NULL ? 0 : (uint32_t)sqlite3_column_int(st, 10);
        copy_pattern(&r, fmt, txt, hex);
        load_ports(db, &r);
        if ((r.method == JMX_MATCH_EXACT || r.method == JMX_MATCH_BM_STR) &&
            r.match_len == 0) {
            fprintf(stderr,
                    "signature-db: skipped empty fixed payload rule_id=%u method=%s\n",
                    r.rule_id, mt ? mt : "");
            continue;
        }
        added_before = (int)rs->total_rules;
        rc = jmx_rule_set_add_match(rs, &r);
        if (rc < 0) {
            fprintf(stderr,
                    "signature-db: rule capacity or allocation failure at rule_id=%u rc=%d\n",
                    r.rule_id, rc);
            sqlite3_finalize(st);
            return -1;
        }
        if ((int)rs->total_rules > added_before)
            seen++;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return seen;
}

int jmx_load_signature_db(const char *path, jmx_rule_set_t *rs)
{
    sqlite3 *db = NULL;
    int apps, rules;
    if (!path || !rs) return -1;
    jmx_rule_set_init(rs);
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "signature-db: cannot open %s: %s\n", path, db ? sqlite3_errmsg(db) : "oom");
        if (db) sqlite3_close(db);
        return -1;
    }
    apps = load_apps(db, rs);
    rules = load_rules(db, rs);
    sqlite3_close(db);
    if (apps < 0 || rules < 0) {
        fprintf(stderr, "signature-db: invalid schema or read failure: %s\n", path);
        jmx_rule_set_free(rs);
        return -1;
    }
    fprintf(stderr, "signature-db: loaded apps=%d rules=%d fast=%u slow=%u from %s\n",
            apps, rules, rs->fast_rules, rs->slow_rules, path);
    return 0;
}

static int table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)
        found = 1;
    sqlite3_finalize(st);
    return found;
}

static int query_u32(sqlite3 *db, const char *sql, uint32_t *value)
{
    sqlite3_stmt *st = NULL;
    sqlite3_int64 v;
    int rc;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (v < 0 || (uint64_t)v > UINT32_MAX)
        return -1;
    *value = (uint32_t)v;
    return 0;
}

static int column_u32(sqlite3_stmt *st, int col, uint32_t *value)
{
    sqlite3_int64 v;

    if (sqlite3_column_type(st, col) == SQLITE_NULL)
        return -1;
    v = sqlite3_column_int64(st, col);
    if (v < 0 || (uint64_t)v > UINT32_MAX)
        return -1;
    *value = (uint32_t)v;
    return 0;
}

static int column_i32(sqlite3_stmt *st, int col, int32_t *value)
{
    sqlite3_int64 v;

    if (sqlite3_column_type(st, col) == SQLITE_NULL)
        return -1;
    v = sqlite3_column_int64(st, col);
    if (v < INT32_MIN || v > INT32_MAX)
        return -1;
    *value = (int32_t)v;
    return 0;
}

static int parse_chain_proto(const char *s, uint8_t *proto)
{
    if (streq(s, "any")) *proto = JMX_V3_PROTO_ANY;
    else if (streq(s, "tcp")) *proto = JMX_V3_PROTO_TCP;
    else if (streq(s, "udp")) *proto = JMX_V3_PROTO_UDP;
    else return -1;
    return 0;
}

static int parse_chain_dir(const char *s, uint8_t *dir)
{
    if (streq(s, "any")) *dir = JMX_V3_DIR_ANY;
    else if (streq(s, "original")) *dir = JMX_V3_DIR_ORIGINAL;
    else if (streq(s, "reply")) *dir = JMX_V3_DIR_REPLY;
    else if (streq(s, "bidirectional")) *dir = JMX_V3_DIR_BIDIRECTIONAL;
    else return -1;
    return 0;
}

static int parse_condition(const char *s, uint8_t *condition)
{
    if (streq(s, "positive")) *condition = JMX_V3_CONDITION_POSITIVE;
    else if (streq(s, "negative")) *condition = JMX_V3_CONDITION_NEGATIVE;
    else if (streq(s, "numeric")) *condition = JMX_V3_CONDITION_NUMERIC;
    else if (streq(s, "jump")) *condition = JMX_V3_CONDITION_JUMP;
    else return -1;
    return 0;
}

static int parse_case_mode(const char *s, uint8_t *mode)
{
    if (streq(s, "not_applicable")) *mode = JMX_V3_CASE_NOT_APPLICABLE;
    else if (streq(s, "nocase")) *mode = JMX_V3_CASE_NOCASE;
    else if (streq(s, "exact")) *mode = JMX_V3_CASE_EXACT;
    else return -1;
    return 0;
}

static int parse_input_view(const char *s, uint8_t *view)
{
    if (streq(s, "raw")) *view = JMX_V3_VIEW_RAW;
    else if (streq(s, "normalized_uri")) *view = JMX_V3_VIEW_NORMALIZED_URI;
    else return -1;
    return 0;
}

static int parse_endpoint(const char *s, uint8_t *endpoint)
{
    if (streq(s, "source")) *endpoint = JMX_V3_PORT_SOURCE;
    else if (streq(s, "destination")) *endpoint = JMX_V3_PORT_DESTINATION;
    else if (streq(s, "either")) *endpoint = JMX_V3_PORT_EITHER;
    else return -1;
    return 0;
}

static int parse_numeric_encoding(sqlite3_stmt *st, int col, uint8_t *encoding)
{
    const char *s;

    if (sqlite3_column_type(st, col) == SQLITE_NULL) {
        *encoding = 0;
        return 0;
    }
    if (sqlite3_column_type(st, col) == SQLITE_INTEGER) {
        uint32_t v;
        if (column_u32(st, col, &v) != 0 || v > UINT8_MAX)
            return -1;
        *encoding = (uint8_t)v;
        return 0;
    }
    s = (const char *)sqlite3_column_text(st, col);
    if (streq(s, "binary_be") || streq(s, "binary_big_endian")) *encoding = 0x01;
    else if (streq(s, "binary_le") || streq(s, "binary_little_endian")) *encoding = 0x02;
    else if (streq(s, "ascii_hex")) *encoding = 0x04;
    else if (streq(s, "ascii_decimal")) *encoding = 0x08;
    else if (streq(s, "ascii_octal")) *encoding = 0x10;
    else if (streq(s, "ipv4") || streq(s, "dotted_decimal_ipv4")) *encoding = 0x20;
    else return -1;
    return 0;
}

static int parse_comparison(sqlite3_stmt *st, int col, uint8_t *comparison)
{
    const char *s;

    if (sqlite3_column_type(st, col) == SQLITE_NULL) {
        *comparison = 0;
        return 0;
    }
    if (sqlite3_column_type(st, col) == SQLITE_INTEGER) {
        uint32_t v;
        if (column_u32(st, col, &v) != 0 || v > UINT8_MAX)
            return -1;
        *comparison = (uint8_t)v;
        return 0;
    }
    s = (const char *)sqlite3_column_text(st, col);
    if (streq(s, "eq") || streq(s, "==")) *comparison = 0x01;
    else if (streq(s, "ne") || streq(s, "!=")) *comparison = 0x02;
    else if (streq(s, "gt") || streq(s, ">")) *comparison = 0x04;
    else if (streq(s, "lt") || streq(s, "<")) *comparison = 0x08;
    else if (streq(s, "bit_set")) *comparison = 0x10;
    else if (streq(s, "bit_clear")) *comparison = 0x20;
    else return -1;
    return 0;
}

static int validate_foreign_keys(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (sqlite3_exec(db, "PRAGMA foreign_keys=ON", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(db, "PRAGMA foreign_key_check", -1, &st, NULL) != SQLITE_OK)
        return -1;
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int load_catalog_digest(sqlite3 *db,
                               uint8_t digest[JMX_V3_CATALOG_DIGEST_LEN])
{
    sqlite3_stmt *st = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned int digest_len = 0;
    int rc, rows = 0, ret = -1;

    if (sqlite3_prepare_v2(db,
            "SELECT catalog_id,source,source_version,source_sha256 "
            "FROM dpi_source_catalog ORDER BY catalog_id",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto out;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int i;
        sqlite3_int64 catalog_id = sqlite3_column_int64(st, 0);
        if (catalog_id <= 0)
            goto out;
        for (i = 0; i < 4; i++) {
            const void *data;
            int bytes;
            if (i == 0) {
                data = &catalog_id;
                bytes = sizeof(catalog_id);
            } else {
                data = sqlite3_column_text(st, i);
                bytes = sqlite3_column_bytes(st, i);
                if (!data || bytes <= 0)
                    goto out;
            }
            if (EVP_DigestUpdate(ctx, data, (size_t)bytes) != 1)
                goto out;
        }
        rows++;
    }
    if (rc != SQLITE_DONE || rows == 0 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != JMX_V3_CATALOG_DIGEST_LEN)
        goto out;
    ret = 0;
out:
    EVP_MD_CTX_free(ctx);
    sqlite3_finalize(st);
    return ret;
}

static uint32_t step_required_caps(const jmx_chain_step_t *s)
{
    uint32_t caps = 0;

    if (s->matcher_type == JMX_V3_MATCH_LITERAL_NOCASE ||
        s->matcher_type == JMX_V3_MATCH_LITERAL_EXACT_1 ||
        s->matcher_type == JMX_V3_MATCH_LITERAL_EXACT_2)
        caps |= JMX_V3_CAP_RAW_LITERAL_CHAIN;
    if (s->case_mode == JMX_V3_CASE_NOCASE)
        caps |= JMX_V3_CAP_NOCASE;
    if (s->input_view == JMX_V3_VIEW_NORMALIZED_URI ||
        s->matcher_type == JMX_V3_MATCH_NORMALIZED_URI)
        caps |= JMX_V3_CAP_NORMALIZED_URI;
    if (s->condition == JMX_V3_CONDITION_NEGATIVE)
        caps |= JMX_V3_CAP_NEGATIVE;
    if (s->matcher_type == JMX_V3_MATCH_BYTE_TEST)
        caps |= JMX_V3_CAP_BYTE_TEST;
    if (s->matcher_type == JMX_V3_MATCH_BYTE_JUMP)
        caps |= JMX_V3_CAP_BYTE_JUMP;
    if (s->position_flags & (JMX_V3_POS_DEPTH | JMX_V3_POS_OFFSET))
        caps |= JMX_V3_CAP_POSITION_ABSOLUTE;
    if (s->position_flags & (JMX_V3_POS_DISTANCE | JMX_V3_POS_WITHIN))
        caps |= JMX_V3_CAP_POSITION_RELATIVE;
    return caps;
}

static int validate_literal_step(const jmx_chain_step_t *s)
{
    if (s->payload_len == 0 || s->payload_len > JMX_V3_PAYLOAD_MAX)
        return -1;
    if (s->condition != JMX_V3_CONDITION_POSITIVE &&
        s->condition != JMX_V3_CONDITION_NEGATIVE)
        return -1;
    if (!(s->literal_option == 0x00 || s->literal_option == 0x01 ||
          s->literal_option == 0x04))
        return -1;
    switch (s->matcher_type) {
    case JMX_V3_MATCH_LITERAL_NOCASE:
        return s->input_view == JMX_V3_VIEW_RAW &&
               s->case_mode == JMX_V3_CASE_NOCASE ? 0 : -1;
    case JMX_V3_MATCH_LITERAL_EXACT_1:
    case JMX_V3_MATCH_LITERAL_EXACT_2:
        return s->input_view == JMX_V3_VIEW_RAW &&
               s->case_mode == JMX_V3_CASE_EXACT ? 0 : -1;
    case JMX_V3_MATCH_NORMALIZED_URI:
        return s->input_view == JMX_V3_VIEW_NORMALIZED_URI &&
               s->case_mode == JMX_V3_CASE_NOCASE ? 0 : -1;
    default:
        return -1;
    }
}

static int validate_step_semantics(const jmx_chain_step_t *s)
{
    if ((s->position_flags & ~JMX_V3_POS_KNOWN_MASK) != 0)
        return -1;
    if ((s->position_flags & JMX_V3_POS_DEPTH) && s->depth < 0)
        return -1;
    if ((s->position_flags & JMX_V3_POS_OFFSET) && s->offset < 0)
        return -1;

    switch (s->matcher_type) {
    case JMX_V3_MATCH_LITERAL_NOCASE:
    case JMX_V3_MATCH_LITERAL_EXACT_1:
    case JMX_V3_MATCH_LITERAL_EXACT_2:
    case JMX_V3_MATCH_NORMALIZED_URI:
        return validate_literal_step(s);
    case JMX_V3_MATCH_BYTE_TEST:
        if (s->condition != JMX_V3_CONDITION_NUMERIC ||
            s->case_mode != JMX_V3_CASE_NOT_APPLICABLE ||
            s->input_view != JMX_V3_VIEW_RAW || s->payload_len != 12 ||
            s->width == 0 || s->width > 11 || !s->numeric_encoding ||
            !(s->comparison == 0x01 || s->comparison == 0x02 ||
              s->comparison == 0x04 || s->comparison == 0x08 ||
              s->comparison == 0x10 || s->comparison == 0x20) ||
            !(s->numeric_encoding == 0x01 || s->numeric_encoding == 0x02 ||
              s->numeric_encoding == 0x04 || s->numeric_encoding == 0x08 ||
              s->numeric_encoding == 0x10 || s->numeric_encoding == 0x20) ||
            s->payload[0] != (uint8_t)(s->reference_source >> 8) ||
            s->payload[1] != (uint8_t)s->reference_source ||
            s->payload[2] != s->adjust_mode || s->payload[3] != s->width ||
            s->payload[4] != (uint8_t)(s->inline_operand >> 24) ||
            s->payload[5] != (uint8_t)(s->inline_operand >> 16) ||
            s->payload[6] != (uint8_t)(s->inline_operand >> 8) ||
            s->payload[7] != (uint8_t)s->inline_operand ||
            s->payload[8] != (uint8_t)(s->adjustment_operand >> 24) ||
            s->payload[9] != (uint8_t)(s->adjustment_operand >> 16) ||
            s->payload[10] != (uint8_t)(s->adjustment_operand >> 8) ||
            s->payload[11] != (uint8_t)s->adjustment_operand)
            return -1;
        return 0;
    case JMX_V3_MATCH_BYTE_JUMP:
        if (s->condition != JMX_V3_CONDITION_JUMP ||
            s->case_mode != JMX_V3_CASE_NOT_APPLICABLE ||
            s->input_view != JMX_V3_VIEW_RAW || s->payload_len != 4 ||
            s->width == 0 ||
            s->payload[0] != (uint8_t)((uint16_t)s->jump_base >> 8) ||
            s->payload[1] != (uint8_t)s->jump_base ||
            s->payload[2] != s->jump_multiplier || s->payload[3] != s->width)
            return -1;
        return 0;
    default:
        return -1;
    }
}

static int load_chain_stats(sqlite3 *db, jmx_chain_rule_set_t *rs)
{
    if (query_u32(db, "SELECT COUNT(*) FROM dpi_signature_rule",
                  &rs->stats.chain_db_rules) != 0 ||
        query_u32(db,
                  "SELECT COUNT(*) FROM dpi_signature_rule "
                  "WHERE semantic_confidence!='verified'",
                  &rs->stats.chain_unresolved_rules) != 0 ||
        query_u32(db,
                  "SELECT COUNT(*) FROM dpi_signature_rule WHERE step_count=0",
                  &rs->stats.zero_step_rules) != 0 ||
        query_u32(db,
                  "SELECT COUNT(*) FROM (SELECT DISTINCT payload FROM dpi_signature_step "
                  "WHERE input_view='raw' AND length(payload)>0)",
                  &rs->stats.unique_raw_patterns) != 0 ||
        query_u32(db,
                  "SELECT COUNT(*) FROM (SELECT DISTINCT payload FROM dpi_signature_step "
                  "WHERE input_view='normalized_uri' AND length(payload)>0)",
                  &rs->stats.unique_uri_patterns) != 0)
        return -1;
    return 0;
}

static int load_chain_rules(sqlite3 *db, jmx_chain_rule_set_t *rs)
{
    static const char sql[] =
        "SELECT signature_rule_id,app_id,priority,required_capabilities,"
        "step_count,proto,direction "
        "FROM dpi_signature_rule "
        "WHERE enabled=1 AND semantic_confidence='verified' "
        "ORDER BY signature_rule_id";
    sqlite3_stmt *st = NULL;
    int rc;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        jmx_chain_rule_t r;
        uint32_t step_count;
        const char *proto = (const char *)sqlite3_column_text(st, 5);
        const char *dir = (const char *)sqlite3_column_text(st, 6);

        memset(&r, 0, sizeof(r));
        if (column_u32(st, 0, &r.signature_rule_id) != 0 ||
            column_u32(st, 1, &r.appid) != 0 || !r.appid ||
            column_u32(st, 2, &r.priority) != 0 ||
            column_u32(st, 3, &r.required_caps) != 0 ||
            column_u32(st, 4, &step_count) != 0 || step_count == 0 ||
            step_count > JMX_V3_MAX_STEPS_PER_RULE ||
            (r.required_caps & ~JMX_V3_CAP_KNOWN_MASK) != 0 ||
            parse_chain_proto(proto, &r.proto) != 0 ||
            parse_chain_dir(dir, &r.dir) != 0 ||
            (rs->rule_count && rs->rules[rs->rule_count - 1].signature_rule_id >=
                               r.signature_rule_id)) {
            rs->stats.rejected_records++;
            sqlite3_finalize(st);
            return -1;
        }
        r.step_count = (uint16_t)step_count;
        r.first_step = UINT32_MAX;
        r.first_port = UINT32_MAX;
        if (jmx_chain_rule_set_add_rule(rs, &r) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int load_chain_steps(sqlite3 *db, jmx_chain_rule_set_t *rs)
{
    static const char sql[] =
        "SELECT s.signature_rule_id,s.step_index,s.matcher_type,s.condition,"
        "s.case_mode,s.input_view,s.position_flags,s.depth,s.offset,s.distance,"
        "s.within_bytes,s.payload,s.literal_option_code,s.numeric_encoding,"
        "s.comparison,s.reference_source,s.adjust_mode,s.inline_operand,"
        "s.adjustment_operand,s.jump_base,s.jump_multiplier,s.width "
        "FROM dpi_signature_step s JOIN dpi_signature_rule r USING(signature_rule_id) "
        "WHERE r.enabled=1 AND r.semantic_confidence='verified' "
        "ORDER BY s.signature_rule_id,s.step_index";
    sqlite3_stmt *st = NULL;
    jmx_chain_rule_t *current = NULL;
    uint16_t expected_index = 0;
    int rc;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        jmx_chain_step_t s;
        uint32_t v;
        const void *payload;
        int payload_len;

        memset(&s, 0, sizeof(s));
        if (column_u32(st, 0, &s.signature_rule_id) != 0 ||
            column_u32(st, 1, &v) != 0 || v >= JMX_V3_MAX_STEPS_PER_RULE ||
            column_u32(st, 2, &v) != 0 || v > UINT8_MAX) {
            goto bad;
        }
        s.step_index = (uint16_t)sqlite3_column_int(st, 1);
        s.matcher_type = (uint8_t)v;
        if (parse_condition((const char *)sqlite3_column_text(st, 3), &s.condition) != 0 ||
            parse_case_mode((const char *)sqlite3_column_text(st, 4), &s.case_mode) != 0 ||
            parse_input_view((const char *)sqlite3_column_text(st, 5), &s.input_view) != 0 ||
            column_u32(st, 6, &v) != 0 || v > UINT8_MAX)
            goto bad;
        s.position_flags = (uint8_t)v;

        if (s.position_flags & JMX_V3_POS_DEPTH) {
            if (column_i32(st, 7, &s.depth) != 0) goto bad;
        } else if (sqlite3_column_type(st, 7) != SQLITE_NULL) goto bad;
        if (s.position_flags & JMX_V3_POS_OFFSET) {
            if (column_i32(st, 8, &s.offset) != 0) goto bad;
        } else if (sqlite3_column_type(st, 8) != SQLITE_NULL) goto bad;
        if (s.position_flags & JMX_V3_POS_DISTANCE) {
            if (column_i32(st, 9, &s.distance) != 0) goto bad;
        } else if (sqlite3_column_type(st, 9) != SQLITE_NULL) goto bad;
        if (s.position_flags & JMX_V3_POS_WITHIN) {
            if (column_i32(st, 10, &s.within) != 0) goto bad;
        } else if (sqlite3_column_type(st, 10) != SQLITE_NULL) goto bad;

        payload = sqlite3_column_blob(st, 11);
        payload_len = sqlite3_column_bytes(st, 11);
        if (!payload || payload_len <= 0 ||
            payload_len > (int)JMX_V3_PAYLOAD_MAX)
            goto bad;
        s.payload_len = (uint16_t)payload_len;
        memcpy(s.payload, payload, (size_t)payload_len);

#define OPTIONAL_U8(COL, FIELD) do { \
        if (sqlite3_column_type(st, (COL)) != SQLITE_NULL) { \
            if (column_u32(st, (COL), &v) != 0 || v > UINT8_MAX) goto bad; \
            (FIELD) = (uint8_t)v; \
        } \
    } while (0)
#define OPTIONAL_U16(COL, FIELD) do { \
        if (sqlite3_column_type(st, (COL)) != SQLITE_NULL) { \
            if (column_u32(st, (COL), &v) != 0 || v > UINT16_MAX) goto bad; \
            (FIELD) = (uint16_t)v; \
        } \
    } while (0)
#define OPTIONAL_U32(COL, FIELD) do { \
        if (sqlite3_column_type(st, (COL)) != SQLITE_NULL) { \
            if (column_u32(st, (COL), &(FIELD)) != 0) goto bad; \
        } \
    } while (0)
        OPTIONAL_U8(12, s.literal_option);
        if (parse_numeric_encoding(st, 13, &s.numeric_encoding) != 0) goto bad;
        if (parse_comparison(st, 14, &s.comparison) != 0) goto bad;
        OPTIONAL_U16(15, s.reference_source);
        OPTIONAL_U8(16, s.adjust_mode);
        OPTIONAL_U32(17, s.inline_operand);
        OPTIONAL_U32(18, s.adjustment_operand);
        if (sqlite3_column_type(st, 19) != SQLITE_NULL &&
            column_i32(st, 19, &s.jump_base) != 0) goto bad;
        OPTIONAL_U8(20, s.jump_multiplier);
        OPTIONAL_U8(21, s.width);
#undef OPTIONAL_U8
#undef OPTIONAL_U16
#undef OPTIONAL_U32

        if (!current || current->signature_rule_id != s.signature_rule_id) {
            current = jmx_chain_rule_find(rs, s.signature_rule_id);
            expected_index = 0;
            if (current && current->first_step == UINT32_MAX)
                current->first_step = (uint32_t)rs->step_count;
        }
        if (!current || s.step_index != expected_index ||
            s.step_index >= current->step_count ||
            (s.step_index == 0 &&
             (s.position_flags & (JMX_V3_POS_DISTANCE | JMX_V3_POS_WITHIN))) ||
            validate_step_semantics(&s) != 0)
            goto bad;
        if (jmx_chain_rule_set_add_step(rs, &s) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        expected_index++;
        continue;
bad:
        rs->stats.rejected_records++;
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int load_chain_ports(sqlite3 *db, jmx_chain_rule_set_t *rs)
{
    static const char sql[] =
        "SELECT p.signature_rule_id,p.endpoint,p.min_port,p.max_port "
        "FROM dpi_signature_port p JOIN dpi_signature_rule r USING(signature_rule_id) "
        "WHERE r.enabled=1 AND r.semantic_confidence='verified' "
        "ORDER BY p.signature_rule_id,p.id";
    sqlite3_stmt *st = NULL;
    jmx_chain_rule_t *current = NULL;
    int rc;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        jmx_chain_port_t p;
        uint32_t v;

        memset(&p, 0, sizeof(p));
        if (column_u32(st, 0, &p.signature_rule_id) != 0 ||
            parse_endpoint((const char *)sqlite3_column_text(st, 1), &p.endpoint) != 0 ||
            column_u32(st, 2, &v) != 0 || v > UINT16_MAX)
            goto bad;
        p.min_port = (uint16_t)v;
        if (column_u32(st, 3, &v) != 0 || v > UINT16_MAX)
            goto bad;
        p.max_port = (uint16_t)v;
        if (p.min_port > p.max_port)
            goto bad;
        if (!current || current->signature_rule_id != p.signature_rule_id) {
            current = jmx_chain_rule_find(rs, p.signature_rule_id);
            if (!current)
                goto bad;
            current->first_port = (uint32_t)rs->port_count;
        }
        if (current->port_count >= JMX_V3_MAX_PORTS_PER_RULE)
            goto bad;
        if (jmx_chain_rule_set_add_port(rs, &p) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        current->port_count++;
        continue;
bad:
        rs->stats.rejected_records++;
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int finalize_chain_rules(jmx_chain_rule_set_t *rs)
{
    size_t i;

    for (i = 0; i < rs->rule_count; i++) {
        jmx_chain_rule_t *r = &rs->rules[i];
        uint32_t inferred = JMX_V3_CAP_PROTOCOL_MAPPING;
        uint16_t j;

        if (r->first_step == UINT32_MAX ||
            (uint64_t)r->first_step + r->step_count > rs->step_count)
            goto bad;
        if (r->port_count == 0)
            r->first_port = (uint32_t)rs->port_count;
        for (j = 0; j < r->step_count; j++) {
            const jmx_chain_step_t *s = &rs->steps[r->first_step + j];
            if (s->signature_rule_id != r->signature_rule_id || s->step_index != j)
                goto bad;
            inferred |= step_required_caps(s);
        }
        if ((r->required_caps & inferred) != inferred)
            goto bad;
        rs->required_capabilities |= r->required_caps;
        if ((r->required_caps & ~rs->engine_capabilities) == 0) {
            r->active = 1;
            rs->stats.chain_ready_rules++;
            rs->stats.chain_steps += r->step_count;
        } else {
            rs->stats.chain_inactive_by_capability++;
        }
    }
    return 0;
bad:
    rs->stats.rejected_records++;
    return -1;
}

static int load_chain_schema(sqlite3 *db, jmx_chain_rule_set_t *rs)
{
    static const char *tables[] = {
        "dpi_source_catalog", "dpi_signature_rule",
        "dpi_signature_step", "dpi_signature_port"
    };
    size_t i;
    int present = 0;

    for (i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        int rc = table_exists(db, tables[i]);
        if (rc < 0)
            return -1;
        present += rc;
    }
    if (present == 0)
        return 0;
    rs->schema_v2_present = 1;
    if (present != (int)(sizeof(tables) / sizeof(tables[0])) ||
        validate_foreign_keys(db) != 0 || load_chain_stats(db, rs) != 0 ||
        load_catalog_digest(db, rs->catalog_digest) != 0 ||
        load_chain_rules(db, rs) != 0 || load_chain_steps(db, rs) != 0 ||
        load_chain_ports(db, rs) != 0 || finalize_chain_rules(rs) != 0)
        return -1;
    return 0;
}

static void print_chain_stats(const jmx_chain_rule_set_t *rs, int status)
{
    fprintf(stderr,
        "{\"component\":\"signature-loader\",\"schema_v2\":%u,"
        "\"v3_status\":\"%s\",\"legacy_db_rules\":%u,"
        "\"legacy_kernel_rules\":%u,\"legacy_regex_inactive\":%u,"
        "\"chain_db_rules\":%u,\"chain_ready_rules\":%u,"
        "\"chain_inactive_by_capability\":%u,\"chain_unresolved_rules\":%u,"
        "\"chain_steps\":%u,\"unique_raw_patterns\":%u,"
        "\"unique_uri_patterns\":%u,\"zero_step_rules\":%u,"
        "\"rejected_records\":%u}\n",
        rs->schema_v2_present, status == 0 ? "ok" : "rejected",
        rs->stats.legacy_db_rules, rs->stats.legacy_kernel_rules,
        rs->stats.legacy_regex_inactive, rs->stats.chain_db_rules,
        rs->stats.chain_ready_rules, rs->stats.chain_inactive_by_capability,
        rs->stats.chain_unresolved_rules, rs->stats.chain_steps,
        rs->stats.unique_raw_patterns, rs->stats.unique_uri_patterns,
        rs->stats.zero_step_rules, rs->stats.rejected_records);
}

int jmx_load_signature_db_with_chain(const char *path,
                                     jmx_rule_set_t *legacy,
                                     jmx_chain_rule_set_t *chain,
                                     uint32_t engine_capabilities,
                                     int *chain_status)
{
    sqlite3 *db = NULL;
    int apps, rules, v3_status = 0;

    if (!path || !legacy || !chain)
        return -1;
    jmx_rule_set_init(legacy);
    jmx_chain_rule_set_init(chain, engine_capabilities & JMX_V3_CAP_KNOWN_MASK);
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "signature-db: cannot open %s: %s\n", path,
                db ? sqlite3_errmsg(db) : "oom");
        if (db) sqlite3_close(db);
        return -1;
    }
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    apps = load_apps(db, legacy);
    rules = load_rules(db, legacy);
    if (apps >= 0 && rules >= 0) {
        chain->stats.legacy_db_rules = legacy->total_rules;
        chain->stats.legacy_kernel_rules = legacy->fast_rules;
        chain->stats.legacy_regex_inactive = legacy->slow_rules;
        v3_status = load_chain_schema(db, chain);
    }
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(db);
    if (apps < 0 || rules < 0) {
        fprintf(stderr, "signature-db: invalid legacy schema or read failure: %s\n", path);
        jmx_rule_set_free(legacy);
        jmx_chain_rule_set_free(chain);
        return -1;
    }
    if (v3_status != 0) {
        uint32_t rejected = chain->stats.rejected_records;
        uint8_t schema_present = chain->schema_v2_present;
        jmx_chain_rule_set_free(chain);
        chain->schema_v2_present = schema_present;
        chain->stats.legacy_db_rules = legacy->total_rules;
        chain->stats.legacy_kernel_rules = legacy->fast_rules;
        chain->stats.legacy_regex_inactive = legacy->slow_rules;
        chain->stats.rejected_records = rejected ? rejected : 1;
    }
    if (chain_status)
        *chain_status = v3_status;
    print_chain_stats(chain, v3_status);
    return 0;
}
