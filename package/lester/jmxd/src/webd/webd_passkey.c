/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * WebAuthn / Passkey backend for DreamingWrt Web Console.
 *
 * Implements credential registration (attestation), authentication (assertion),
 * challenge lifecycle, credential CRUD, and COSE-to-OpenSSL signature
 * verification.
 *
 * CBOR decoding is inline (no external library dependency).
 * Base64url uses OpenSSL's base64 with url-safe alphabet.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/random.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <json-c/json.h>
#include <sqlite3.h>
#include <uci.h>

#include "webd_passkey.h"
#include "webd_session_idle.h"
#include "api/webd_http_req.h"  /* TOKEN_LEN */

/* ══════════════════════════════════════════════════════════════════════
 * Internal constants
 * ══════════════════════════════════════════════════════════════════════ */

#define PASSKEY_ACCESS_TTL_S   900       /* 15 min — same as session login */
#define PASSKEY_REFRESH_TTL_S  2592000   /* 30 days */
#define PASSKEY_MAX_CHALLENGES 64
#define PASSKEY_MAX_BODY_FIELD 8192
#define PASSKEY_LOG_PREFIX     "[dreamingwrt-webd] passkey: "

/* ══════════════════════════════════════════════════════════════════════
 * Module state
 * ══════════════════════════════════════════════════════════════════════ */

static int g_passkey_initialized = 0;
static webd_passkey_verify_password_cb g_password_verify;

/* Cached config */
static char g_rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];
static char g_rp_name[WEBD_PASSKEY_RP_NAME_MAX + 1];
static int  g_max_credentials = WEBD_PASSKEY_MAX_CREDENTIALS;

/* ══════════════════════════════════════════════════════════════════════
 * Forward declarations
 * ══════════════════════════════════════════════════════════════════════ */

static int64_t passkey_now_s(void);
static int passkey_gen_random(uint8_t *out, size_t len);
static int passkey_gen_random_hex(char *out, int len);
static int passkey_ensure_dir(const char *path);
static int passkey_ensure_dir_tree(const char *path);
static int passkey_load_config(void);
static int passkey_credential_count(void);
static int passkey_credential_load(const char *cred_id_hex,
                                   struct webd_passkey_credential *cred);
static int passkey_credential_save(const struct webd_passkey_credential *cred);
static int passkey_credential_delete_file(const char *cred_id_hex);
static struct webd_passkey_challenge *passkey_challenge_alloc(int is_registration,
                                                              const char *username);
static struct webd_passkey_challenge *passkey_challenge_find(
    const uint8_t *challenge, int is_registration);
static void passkey_challenge_remove(struct webd_passkey_challenge *ch);
static int passkey_challenge_load(const char *path,
                                  struct webd_passkey_challenge *ch);
static int passkey_challenge_take(struct webd_passkey_challenge *ch);
static int passkey_challenge_save(struct webd_passkey_challenge *ch);
static int passkey_origin_allowed(const char *origin, const char *rp_id);
static struct json_object *passkey_body_payload(struct json_object *body);
static int passkey_cose_to_evp_pkey(const uint8_t *cose, size_t cose_len,
                                    int *alg_out, EVP_PKEY **pkey_out,
                                    uint8_t **der_out, size_t *der_len_out);
static int passkey_lookup_role(sqlite3 *config_db, const char *username,
                               char *role, size_t role_len);
static int passkey_decode_credential_id(const char *value, uint8_t *out,
                                        size_t out_max, int *out_len);
static int passkey_string_valid(const char *value, size_t max_len);
static int passkey_parse_attestation_none(const uint8_t *attestation,
                                          size_t attestation_len,
                                          const uint8_t **auth_data,
                                          size_t *auth_data_len);
static int passkey_credential_hex_from_body(struct json_object *body,
                                            char *hex, size_t hex_len);
static int passkey_verify_signature(EVP_PKEY *pkey, int cose_alg,
                                    const uint8_t *auth_data, size_t auth_data_len,
                                    const uint8_t *client_data_hash,
                                    const uint8_t *sig, size_t sig_len);
static const char *passkey_json_str(struct json_object *obj, const char *key);
static struct json_object *passkey_error(const char *code, const char *message,
                                         int status, int *http_status);


/* ══════════════════════════════════════════════════════════════════════
 * Base64url codec
 * ══════════════════════════════════════════════════════════════════════ */

int webd_base64url_decode(const char *in, size_t in_len,
                          uint8_t *out, size_t out_max)
{
    char *padded = NULL;
    size_t padded_len, decoded_max, i;
    int decoded_len;
    EVP_ENCODE_CTX *ctx;
    int outl = 0, outl2 = 0;

    if (!in || !in_len || !out || out_max == 0 || in_len % 4 == 1)
        return -1;

    /* Convert url-safe to standard base64. */
    padded_len = in_len + 4; /* room for padding */
    padded = malloc(padded_len + 1);
    if (!padded)
        return -1;
    for (i = 0; i < in_len; i++) {
        if (in[i] == '-')
            padded[i] = '+';
        else if (in[i] == '_')
            padded[i] = '/';
        else if (isalnum((unsigned char)in[i]))
            padded[i] = in[i];
        else {
            free(padded);
            return -1;
        }
    }
    /* Add padding. */
    while (i % 4 != 0)
        padded[i++] = '=';
    padded[i] = '\0';
    padded_len = i;
    decoded_max = in_len / 4 * 3;
    if (in_len % 4 == 2)
        decoded_max++;
    else if (in_len % 4 == 3)
        decoded_max += 2;
    if (decoded_max > out_max) {
        free(padded);
        return -1;
    }

    /* Add newline that EVP_DecodeUpdate expects at the end. */
    ctx = EVP_ENCODE_CTX_new();
    if (!ctx) {
        free(padded);
        return -1;
    }
    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, out, &outl, (const unsigned char *)padded,
                         (int)padded_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        free(padded);
        return -1;
    }
    if (EVP_DecodeFinal(ctx, out + outl, &outl2) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        free(padded);
        return -1;
    }
    decoded_len = outl + outl2;
    EVP_ENCODE_CTX_free(ctx);
    free(padded);
    return decoded_len >= 0 && (size_t)decoded_len <= out_max ? decoded_len : -1;
}

int webd_base64url_encode(const uint8_t *in, size_t in_len,
                          char *out, size_t out_max)
{
    size_t encoded_len, i;

    if (!in || !out || out_max == 0)
        return -1;

    /* EVP_EncodeBlock writes standard base64 with padding. */
    encoded_len = ((in_len + 2) / 3) * 4;
    if (encoded_len + 1 > out_max)
        return -1;

    EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);

    /* Convert to url-safe and strip padding. */
    for (i = 0; out[i]; i++) {
        if (out[i] == '+')
            out[i] = '-';
        else if (out[i] == '/')
            out[i] = '_';
    }
    /* Strip trailing '=' */
    while (i > 0 && out[i - 1] == '=')
        out[--i] = '\0';
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Minimal CBOR decoder (WebAuthn subset)
 * ══════════════════════════════════════════════════════════════════════ */

static int cbor_read_uint(const uint8_t *buf, size_t buf_len, size_t *pos,
                          int additional, uint64_t *out)
{
    size_t p = *pos;

    if (additional < 24) {
        *out = (uint64_t)additional;
        return 0;
    }
    if (additional == 24) {
        if (p + 1 > buf_len) return -1;
        *out = buf[p];
        *pos = p + 1;
        return 0;
    }
    if (additional == 25) {
        if (p + 2 > buf_len) return -1;
        *out = ((uint64_t)buf[p] << 8) | buf[p + 1];
        *pos = p + 2;
        return 0;
    }
    if (additional == 26) {
        if (p + 4 > buf_len) return -1;
        *out = ((uint64_t)buf[p] << 24) | ((uint64_t)buf[p+1] << 16) |
               ((uint64_t)buf[p+2] << 8) | buf[p+3];
        *pos = p + 4;
        return 0;
    }
    if (additional == 27) {
        if (p + 8 > buf_len) return -1;
        *out = ((uint64_t)buf[p] << 56) | ((uint64_t)buf[p+1] << 48) |
               ((uint64_t)buf[p+2] << 40) | ((uint64_t)buf[p+3] << 32) |
               ((uint64_t)buf[p+4] << 24) | ((uint64_t)buf[p+5] << 16) |
               ((uint64_t)buf[p+6] << 8) | buf[p+7];
        *pos = p + 8;
        return 0;
    }
    return -1; /* indefinite length not supported */
}

int webd_cbor_decode_item(const uint8_t *buf, size_t buf_len,
                          size_t *pos, struct webd_cbor_item *item)
{
    uint8_t initial;
    int major, additional;
    uint64_t val = 0;

    if (!buf || !pos || !item || *pos >= buf_len)
        return -1;

    initial = buf[*pos];
    (*pos)++;
    major = (initial >> 5) & 0x7;
    additional = initial & 0x1f;

    if (cbor_read_uint(buf, buf_len, pos, additional, &val) != 0)
        return -1;

    memset(item, 0, sizeof(*item));

    switch (major) {
    case 0: /* unsigned integer */
        item->type = WEBD_CBOR_UINT;
        item->v.uint_val = val;
        return 0;
    case 1: /* negative integer */
        item->type = WEBD_CBOR_NINT;
        item->v.int_val = -1 - (int64_t)val;
        return 0;
    case 2: /* byte string */
        if (*pos + val > buf_len) return -1;
        item->type = WEBD_CBOR_BSTR;
        item->v.str.data = buf + *pos;
        item->v.str.len = (size_t)val;
        *pos += (size_t)val;
        return 0;
    case 3: /* text string */
        if (*pos + val > buf_len) return -1;
        item->type = WEBD_CBOR_TSTR;
        item->v.str.data = buf + *pos;
        item->v.str.len = (size_t)val;
        *pos += (size_t)val;
        return 0;
    case 4: /* array */
        item->type = WEBD_CBOR_ARRAY;
        item->v.container_count = (size_t)val;
        return 0;
    case 5: /* map */
        item->type = WEBD_CBOR_MAP;
        item->v.container_count = (size_t)val;
        return 0;
    case 7: /* simple / float */
        item->type = WEBD_CBOR_SIMPLE;
        item->v.uint_val = val;
        return 0;
    default:
        return -1;
    }
}

int webd_cbor_skip_item(const uint8_t *buf, size_t buf_len, size_t *pos)
{
    struct webd_cbor_item item;
    size_t i;

    if (webd_cbor_decode_item(buf, buf_len, pos, &item) != 0)
        return -1;

    switch (item.type) {
    case WEBD_CBOR_UINT:
    case WEBD_CBOR_NINT:
    case WEBD_CBOR_BSTR:
    case WEBD_CBOR_TSTR:
    case WEBD_CBOR_SIMPLE:
        return 0; /* already consumed */
    case WEBD_CBOR_ARRAY:
        for (i = 0; i < item.v.container_count; i++)
            if (webd_cbor_skip_item(buf, buf_len, pos) != 0)
                return -1;
        return 0;
    case WEBD_CBOR_MAP:
        for (i = 0; i < item.v.container_count; i++) {
            if (webd_cbor_skip_item(buf, buf_len, pos) != 0) return -1;
            if (webd_cbor_skip_item(buf, buf_len, pos) != 0) return -1;
        }
        return 0;
    default:
        return -1;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Utility helpers
 * ══════════════════════════════════════════════════════════════════════ */

static int64_t passkey_now_s(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (int64_t)time(NULL);
    return (int64_t)ts.tv_sec;
}

static int passkey_gen_random(uint8_t *out, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t got = getrandom(out + done, len - done, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (got == 0) return -1;
        done += (size_t)got;
    }
    return 0;
}

static int passkey_gen_random_hex(char *out, int len)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t buf[128];
    int produced = 0;

    if (!out || len <= 0) return -1;
    out[0] = '\0';
    while (produced < len) {
        size_t want = (size_t)(len - produced + 1) / 2;
        ssize_t got;
        size_t i;
        if (want > sizeof(buf)) want = sizeof(buf);
        got = getrandom(buf, want, 0);
        if (got <= 0) {
            if (got < 0 && errno == EINTR) continue;
            memset(out, 0, (size_t)len + 1);
            return -1;
        }
        for (i = 0; i < (size_t)got && produced < len; i++) {
            out[produced++] = hex[(buf[i] >> 4) & 0xf];
            if (produced < len)
                out[produced++] = hex[buf[i] & 0xf];
        }
    }
    out[len] = '\0';
    return 0;
}

static int passkey_ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
    if (mkdir(path, 0700) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int passkey_ensure_dir_tree(const char *path)
{
    char copy[512];
    char *p;

    if (!path || !path[0] || strlen(path) >= sizeof(copy))
        return -1;
    snprintf(copy, sizeof(copy), "%s", path);
    for (p = copy + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (passkey_ensure_dir(copy) != 0)
            return -1;
        *p = '/';
    }
    return passkey_ensure_dir(copy);
}

static const char *passkey_json_str(struct json_object *obj, const char *key)
{
    struct json_object *val;
    if (!obj || !key) return NULL;
    if (!json_object_object_get_ex(obj, key, &val)) return NULL;
    if (!json_object_is_type(val, json_type_string)) return NULL;
    return json_object_get_string(val);
}

static struct json_object *passkey_error(const char *code, const char *message,
                                         int status, int *http_status)
{
    struct json_object *resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "error", json_object_new_string(code ? code : "internal_error"));
    json_object_object_add(resp, "message", json_object_new_string(message ? message : ""));
    if (http_status) *http_status = status;
    return resp;
}

static struct json_object *passkey_body_payload(struct json_object *body)
{
    struct json_object *data = NULL;

    if (!body || !json_object_is_type(body, json_type_object))
        return body;
    if (json_object_object_get_ex(body, "data", &data) && data &&
        json_object_is_type(data, json_type_object))
        return data;
    return body;
}

static const char *passkey_json_str_any(struct json_object *body,
                                        const char *key)
{
    struct json_object *payload = passkey_body_payload(body);
    struct json_object *response = NULL;
    const char *value;

    value = passkey_json_str(payload, key);
    if (value)
        return value;
    if (!payload || !json_object_object_get_ex(payload, "response", &response) ||
        !response || !json_object_is_type(response, json_type_object))
        return NULL;
    return passkey_json_str(response, key);
}

static int passkey_cbor_skip_children(const uint8_t *buf, size_t buf_len,
                                      const struct webd_cbor_item *item,
                                      size_t *pos)
{
    size_t i;
    size_t count;

    if (!item || !pos)
        return -1;
    if (item->type != WEBD_CBOR_ARRAY && item->type != WEBD_CBOR_MAP)
        return 0;
    count = item->v.container_count;
    if (item->type == WEBD_CBOR_MAP && count > SIZE_MAX / 2)
        return -1;
    if (item->type == WEBD_CBOR_MAP)
        count *= 2;
    for (i = 0; i < count; i++) {
        if (webd_cbor_skip_item(buf, buf_len, pos) != 0)
            return -1;
    }
    return 0;
}

static int passkey_origin_allowed(const char *origin, const char *rp_id)
{
    const char *authority;
    const char *host_begin;
    const char *host_end;
    const char *port = NULL;
    const char *rp_begin;
    const char *rp_end;
    size_t host_len;
    size_t rp_len;

    if (!origin || !rp_id || !rp_id[0] || strncmp(origin, "https://", 8))
        return 0;
    authority = origin + 8;
    if (!authority[0] || strchr(authority, '@') || strchr(authority, '/') ||
        strchr(authority, '?') || strchr(authority, '#'))
        return 0;

    host_begin = authority;
    if (*host_begin == '[') {
        host_begin++;
        host_end = strchr(host_begin, ']');
        if (!host_end || host_end == host_begin)
            return 0;
        if (host_end[1]) {
            if (host_end[1] != ':' || !host_end[2])
                return 0;
            port = host_end + 2;
        }
    } else {
        host_end = strchr(host_begin, ':');
        if (host_end) {
            port = host_end + 1;
            if (!port[0] || strchr(port, ':'))
                return 0;
        } else {
            host_end = host_begin + strlen(host_begin);
        }
    }

    if (port) {
        unsigned long port_number = 0;
        const char *p;

        for (p = port; *p; p++) {
            if (!isdigit((unsigned char)*p))
                return 0;
            port_number = port_number * 10 + (unsigned long)(*p - '0');
            if (port_number > 65535)
                return 0;
        }
        if (port_number == 0)
            return 0;
    }

    rp_begin = rp_id;
    rp_end = rp_id + strlen(rp_id);
    if (rp_begin[0] == '[' && rp_end > rp_begin + 1 && rp_end[-1] == ']') {
        rp_begin++;
        rp_end--;
    }
    host_len = (size_t)(host_end - host_begin);
    rp_len = (size_t)(rp_end - rp_begin);
    return host_len == rp_len && !strncasecmp(host_begin, rp_begin, host_len);
}

static void passkey_bytes_to_hex(const uint8_t *in, size_t in_len,
                                 char *out, size_t out_max)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (!in || !out || out_max < in_len * 2 + 1) {
        if (out && out_max) out[0] = '\0';
        return;
    }
    for (i = 0; i < in_len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[in[i] & 0xf];
    }
    out[in_len * 2] = '\0';
}

static int passkey_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;
    if (!hex || !out || strlen(hex) != out_len * 2) return -1;
    for (i = 0; i < out_len; i++) {
        int hi, lo;
        hi = (hex[i*2] >= '0' && hex[i*2] <= '9') ? hex[i*2] - '0' :
             (hex[i*2] >= 'a' && hex[i*2] <= 'f') ? hex[i*2] - 'a' + 10 :
             (hex[i*2] >= 'A' && hex[i*2] <= 'F') ? hex[i*2] - 'A' + 10 : -1;
        lo = (hex[i*2+1] >= '0' && hex[i*2+1] <= '9') ? hex[i*2+1] - '0' :
             (hex[i*2+1] >= 'a' && hex[i*2+1] <= 'f') ? hex[i*2+1] - 'a' + 10 :
             (hex[i*2+1] >= 'A' && hex[i*2+1] <= 'F') ? hex[i*2+1] - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int passkey_hex_valid(const char *s, size_t max_hex_len)
{
    size_t i;
    if (!s || !s[0]) return 0;
    for (i = 0; s[i]; i++) {
        if (i >= max_hex_len) return 0;
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f') ||
              (s[i] >= 'A' && s[i] <= 'F')))
            return 0;
    }
    return (i > 0 && i % 2 == 0) ? 1 : 0;
}

static int passkey_write_file_atomic(const char *path, const char *data, size_t data_len)
{
    char tmp[512];
    int fd;
    size_t offset = 0;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid()) >= (int)sizeof(tmp))
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    while (offset < data_len) {
        ssize_t written = write(fd, data + offset, data_len - offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmp);
            return -1;
        }
        if (written == 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        offset += (size_t)written;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Config management
 * ══════════════════════════════════════════════════════════════════════ */

static int passkey_load_config(void)
{
    FILE *fp;
    char buf[2048];
    size_t len;
    struct json_object *obj, *val;

    /* Defaults */
    g_rp_id[0] = '\0';
    snprintf(g_rp_name, sizeof(g_rp_name), "DreamingWrt");
    g_max_credentials = WEBD_PASSKEY_MAX_CREDENTIALS;

    fp = fopen(WEBD_PASSKEY_CONFIG_PATH, "r");
    if (!fp) {
        /* No config yet; use defaults. rp_id will be resolved from hostname. */
        return 0;
    }
    len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';

    obj = json_tokener_parse(buf);
    if (!obj) return 0; /* Malformed config, use defaults. */

    if (json_object_object_get_ex(obj, "rp_id", &val) &&
        json_object_is_type(val, json_type_string))
        snprintf(g_rp_id, sizeof(g_rp_id), "%s", json_object_get_string(val));

    if (json_object_object_get_ex(obj, "rp_name", &val) &&
        json_object_is_type(val, json_type_string))
        snprintf(g_rp_name, sizeof(g_rp_name), "%s", json_object_get_string(val));

    if (json_object_object_get_ex(obj, "max_credentials", &val) &&
        json_object_is_type(val, json_type_int)) {
        int n = json_object_get_int(val);
        if (n > 0 && n <= 64) g_max_credentials = n;
    }

    json_object_put(obj);
    return 0;
}

static int passkey_custom_domain(char *out, size_t out_len)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int found = 0;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &pkg) != UCI_OK || !pkg)
        goto done;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *section = uci_to_section(e);
        const char *value;

        if (!section || strcmp(section->type, "system"))
            continue;
        value = uci_lookup_option_string(ctx, section, "console_domain");
        if (value && value[0]) {
            snprintf(out, out_len, "%s", value);
            found = 1;
        }
        break;
    }
done:
    if (ctx)
        uci_free_context(ctx);
    return found;
}

int webd_passkey_rp_id(char *out, size_t out_len)
{
    char hostname[256];
    char custom_domain[WEBD_PASSKEY_RP_ID_MAX + 1];

    if (!out || out_len == 0) return -1;

    if (g_rp_id[0]) {
        snprintf(out, out_len, "%s", g_rp_id);
        return 0;
    }
    if (passkey_custom_domain(custom_domain, sizeof(custom_domain))) {
        snprintf(out, out_len, "%s", custom_domain);
        return 0;
    }

    /* Fallback: system hostname. */
    if (gethostname(hostname, sizeof(hostname)) != 0)
        snprintf(hostname, sizeof(hostname), "dreamingwrt");
    hostname[sizeof(hostname) - 1] = '\0';

    /* If hostname contains a dot, use the full hostname.
     * Otherwise append .local for mDNS. */
    if (strchr(hostname, '.'))
        snprintf(out, out_len, "%s", hostname);
    else
        snprintf(out, out_len, "%s.local", hostname);
    return 0;
}

void webd_passkey_set_password_verifier(webd_passkey_verify_password_cb verify)
{
    g_password_verify = verify;
}

static int passkey_lookup_role(sqlite3 *config_db, const char *username,
                               char *role, size_t role_len)
{
    sqlite3_stmt *st = NULL;
    const char *role_value;
    const char *status;
    int ok = 0;

    if (!config_db || !username || !username[0] || !role || role_len == 0)
        return 0;
    role[0] = '\0';
    if (sqlite3_prepare_v2(config_db,
            "SELECT role,status FROM web_users WHERE username=?1", -1,
            &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        role_value = (const char *)sqlite3_column_text(st, 0);
        status = (const char *)sqlite3_column_text(st, 1);
        if (status && !strcmp(status, "enabled")) {
            snprintf(role, role_len, "%s",
                     role_value && role_value[0] ? role_value : "admin");
            ok = 1;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

static int passkey_decode_credential_id(const char *value, uint8_t *out,
                                        size_t out_max, int *out_len)
{
    int decoded;

    if (!value || !value[0] || !out || !out_len)
        return -1;
    decoded = webd_base64url_decode(value, strlen(value), out, out_max);
    if (decoded <= 0 || (size_t)decoded > out_max)
        return -1;
    *out_len = decoded;
    return 0;
}

static int passkey_string_valid(const char *value, size_t max_len)
{
    size_t i;
    size_t len;

    if (!value || !(len = strlen(value)) || len > max_len)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)value[i];
        if (ch < 0x20 || ch == 0x7f)
            return 0;
    }
    return 1;
}

int webd_passkey_init(void)
{
    static const char default_config[] =
        "{\n  \"rp_id\": \"\",\n  \"rp_name\": \"DreamingWrt\",\n"
        "  \"max_credentials\": 16\n}\n";

    if (g_passkey_initialized)
        return 0;
    if (passkey_ensure_dir_tree(WEBD_PASSKEY_DIR) != 0 ||
        passkey_ensure_dir_tree(WEBD_PASSKEY_CRED_DIR) != 0 ||
        passkey_ensure_dir_tree(WEBD_PASSKEY_CHALLENGE_DIR) != 0)
        return -1;
    chmod(WEBD_PASSKEY_DIR, 0700);
    chmod(WEBD_PASSKEY_CRED_DIR, 0700);
    chmod(WEBD_PASSKEY_CHALLENGE_DIR, 0700);
    if (access(WEBD_PASSKEY_CONFIG_PATH, F_OK) != 0 &&
        passkey_write_file_atomic(WEBD_PASSKEY_CONFIG_PATH, default_config,
                                  sizeof(default_config) - 1) != 0)
        return -1;
    if (passkey_load_config() != 0)
        return -1;
    webd_passkey_gc();
    g_passkey_initialized = 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Credential persistence (JSON files)
 * ══════════════════════════════════════════════════════════════════════ */

static int passkey_credential_count(void)
{
    DIR *d;
    struct dirent *e;
    int count = 0;

    d = opendir(WEBD_PASSKEY_CRED_DIR);
    if (!d) return 0;
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len > 5 && !strcmp(e->d_name + len - 5, ".json"))
            count++;
    }
    closedir(d);
    return count;
}

static int passkey_credential_load(const char *cred_id_hex,
                                   struct webd_passkey_credential *cred)
{
    char path[512];
    FILE *fp;
    char buf[8192];
    size_t len;
    struct json_object *obj, *val;
    const char *pk_hex;

    if (!cred_id_hex || !cred) return -1;
    if (!passkey_hex_valid(cred_id_hex, WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2))
        return -1;

    if (snprintf(path, sizeof(path), "%s/%s.json",
                 WEBD_PASSKEY_CRED_DIR, cred_id_hex) >= (int)sizeof(path))
        return -1;

    fp = fopen(path, "r");
    if (!fp) return -1;
    len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';

    obj = json_tokener_parse(buf);
    if (!obj) return -1;

    memset(cred, 0, sizeof(*cred));
    snprintf(cred->credential_id_hex, sizeof(cred->credential_id_hex),
             "%s", cred_id_hex);

    if (json_object_object_get_ex(obj, "cose_alg", &val))
        cred->cose_alg = json_object_get_int(val);

    pk_hex = passkey_json_str(obj, "public_key_der_hex");
    if (pk_hex && pk_hex[0]) {
        size_t pk_hex_len = strlen(pk_hex);
        cred->public_key_der_len = pk_hex_len / 2;
        cred->public_key_der = malloc(cred->public_key_der_len);
        if (!cred->public_key_der ||
            passkey_hex_to_bytes(pk_hex, cred->public_key_der,
                                cred->public_key_der_len) != 0) {
            free(cred->public_key_der);
            cred->public_key_der = NULL;
            cred->public_key_der_len = 0;
        }
    }

    if (json_object_object_get_ex(obj, "sign_count", &val))
        cred->sign_count = (uint32_t)json_object_get_int64(val);
    if (json_object_object_get_ex(obj, "created_at", &val))
        cred->created_at = json_object_get_int64(val);
    if (json_object_object_get_ex(obj, "last_used_at", &val))
        cred->last_used_at = json_object_get_int64(val);

    {
        const char *name = passkey_json_str(obj, "friendly_name");
        if (name)
            snprintf(cred->friendly_name, sizeof(cred->friendly_name), "%s", name);
    }
    {
        const char *user = passkey_json_str(obj, "username");
        if (user)
            snprintf(cred->username, sizeof(cred->username), "%s", user);
    }

    json_object_put(obj);
    return 0;
}

static int passkey_credential_save(const struct webd_passkey_credential *cred)
{
    char path[512];
    struct json_object *obj;
    const char *json_str;
    char *pk_hex = NULL;

    if (!cred || !cred->credential_id_hex[0]) return -1;

    if (snprintf(path, sizeof(path), "%s/%s.json",
                 WEBD_PASSKEY_CRED_DIR, cred->credential_id_hex) >= (int)sizeof(path))
        return -1;

    obj = json_object_new_object();
    json_object_object_add(obj, "credential_id",
                           json_object_new_string(cred->credential_id_hex));
    json_object_object_add(obj, "cose_alg",
                           json_object_new_int(cred->cose_alg));

    if (cred->public_key_der && cred->public_key_der_len > 0) {
        pk_hex = malloc(cred->public_key_der_len * 2 + 1);
        if (pk_hex) {
            passkey_bytes_to_hex(cred->public_key_der, cred->public_key_der_len,
                                pk_hex, cred->public_key_der_len * 2 + 1);
            json_object_object_add(obj, "public_key_der_hex",
                                   json_object_new_string(pk_hex));
            free(pk_hex);
        }
    }

    json_object_object_add(obj, "sign_count",
                           json_object_new_int64((int64_t)cred->sign_count));
    json_object_object_add(obj, "created_at",
                           json_object_new_int64(cred->created_at));
    json_object_object_add(obj, "last_used_at",
                           json_object_new_int64(cred->last_used_at));
    json_object_object_add(obj, "friendly_name",
                           json_object_new_string(cred->friendly_name));
    json_object_object_add(obj, "username",
                           json_object_new_string(cred->username));

    json_str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    if (!json_str) {
        json_object_put(obj);
        return -1;
    }

    int rc = passkey_write_file_atomic(path, json_str, strlen(json_str));
    json_object_put(obj);
    return rc;
}

static int passkey_credential_delete_file(const char *cred_id_hex)
{
    char path[512];
    if (!cred_id_hex || !passkey_hex_valid(cred_id_hex, WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2))
        return -1;
    if (snprintf(path, sizeof(path), "%s/%s.json",
                 WEBD_PASSKEY_CRED_DIR, cred_id_hex) >= (int)sizeof(path))
        return -1;
    return unlink(path);
}

static void passkey_credential_free(struct webd_passkey_credential *cred)
{
    if (cred && cred->public_key_der) {
        free(cred->public_key_der);
        cred->public_key_der = NULL;
        cred->public_key_der_len = 0;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Challenge store (shared across request workers)
 * ══════════════════════════════════════════════════════════════════════ */

static int passkey_challenge_path(const struct webd_passkey_challenge *ch,
                                  char *path, size_t path_len)
{
    if (!ch || !passkey_hex_valid(ch->challenge_hex,
                                  WEBD_PASSKEY_CHALLENGE_HEX_LEN) ||
        strlen(ch->challenge_hex) != WEBD_PASSKEY_CHALLENGE_HEX_LEN)
        return -1;
    return snprintf(path, path_len, "%s/%s-%s.json",
                    WEBD_PASSKEY_CHALLENGE_DIR,
                    ch->is_registration == 2 ? "reauth" : ch->is_registration ? "reg" : "auth",
                    ch->challenge_hex) < (int)path_len ? 0 : -1;
}

static int passkey_challenge_load(const char *path,
                                  struct webd_passkey_challenge *ch)
{
    char buf[512];
    FILE *fp;
    struct json_object *obj;
    struct json_object *val;
    const char *hex;
    const char *username;
    const char *friendly_name;
    size_t len;

    fp = fopen(path, "r");
    if (!fp)
        return -1;
    len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';
    obj = json_tokener_parse(buf);
    if (!obj)
        return -1;
    memset(ch, 0, sizeof(*ch));
    hex = passkey_json_str(obj, "challenge_hex");
    username = passkey_json_str(obj, "username");
    friendly_name = passkey_json_str(obj, "friendly_name");
    if (!hex || strlen(hex) != WEBD_PASSKEY_CHALLENGE_HEX_LEN ||
        !passkey_hex_valid(hex, WEBD_PASSKEY_CHALLENGE_HEX_LEN) ||
        passkey_hex_to_bytes(hex, ch->challenge, sizeof(ch->challenge)) != 0 ||
        !json_object_object_get_ex(obj, "created_at", &val) ||
        !json_object_is_type(val, json_type_int)) {
        json_object_put(obj);
        return -1;
    }
    ch->created_at = json_object_get_int64(val);
    if (!json_object_object_get_ex(obj, "is_registration", &val) ||
        (!json_object_is_type(val, json_type_boolean) && !json_object_is_type(val, json_type_int))) {
        json_object_put(obj);
        return -1;
    }
    ch->is_registration = json_object_get_int(val);
    if (ch->is_registration < 0 || ch->is_registration > 2) {
        json_object_put(obj);
        return -1;
    }
    const char *binding = passkey_json_str(obj, "operation_binding");
    if (binding) snprintf(ch->operation_binding, sizeof(ch->operation_binding), "%s", binding);
    snprintf(ch->challenge_hex, sizeof(ch->challenge_hex), "%s", hex);
    if (username)
        snprintf(ch->username, sizeof(ch->username), "%s", username);
    if (friendly_name)
        snprintf(ch->friendly_name, sizeof(ch->friendly_name), "%s",
                 friendly_name);
    json_object_put(obj);
    return 0;
}

static int passkey_challenge_save(struct webd_passkey_challenge *ch)
{
    char path[512];
    struct json_object *obj = json_object_new_object();
    const char *data;
    int rc;

    if (!obj || passkey_challenge_path(ch, path, sizeof(path)) != 0) {
        if (obj) json_object_put(obj);
        return -1;
    }
    json_object_object_add(obj, "challenge_hex",
                           json_object_new_string(ch->challenge_hex));
    json_object_object_add(obj, "created_at",
                           json_object_new_int64(ch->created_at));
    json_object_object_add(obj, "is_registration",
                           ch->is_registration == 2 ? json_object_new_int(2) :
                           json_object_new_boolean(ch->is_registration));
    if (ch->is_registration == 2)
        json_object_object_add(obj, "operation_binding", json_object_new_string(ch->operation_binding));
    json_object_object_add(obj, "username", json_object_new_string(ch->username));
    json_object_object_add(obj, "friendly_name",
                           json_object_new_string(ch->friendly_name));
    data = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    rc = data ? passkey_write_file_atomic(path, data, strlen(data)) : -1;
    json_object_put(obj);
    return rc;
}

static int passkey_challenge_take(struct webd_passkey_challenge *ch)
{
    char path[512];

    if (passkey_challenge_path(ch, path, sizeof(path)) != 0)
        return -1;
    return unlink(path);
}

void webd_passkey_gc(void)
{
    DIR *dir = opendir(WEBD_PASSKEY_CHALLENGE_DIR);
    struct dirent *ent;

    if (!dir)
        return;
    while ((ent = readdir(dir)) != NULL) {
        char path[512];
        struct webd_passkey_challenge ch;
        size_t len = strlen(ent->d_name);

        if (len < 10 || strcmp(ent->d_name + len - 5, ".json") ||
            (strncmp(ent->d_name, "auth-", 5) &&
             strncmp(ent->d_name, "reauth-", 7) &&
             strncmp(ent->d_name, "reg-", 4)))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", WEBD_PASSKEY_CHALLENGE_DIR,
                     ent->d_name) >= (int)sizeof(path))
            continue;
        if (passkey_challenge_load(path, &ch) != 0 ||
            ch.created_at > passkey_now_s() ||
            passkey_now_s() - ch.created_at > WEBD_PASSKEY_CHALLENGE_TTL_S)
            unlink(path);
    }
    closedir(dir);
}

static struct webd_passkey_challenge *passkey_challenge_alloc(int is_registration,
                                                              const char *username)
{
    struct webd_passkey_challenge *ch;
    DIR *dir;
    struct dirent *ent;
    int count = 0;

    webd_passkey_gc();
    dir = opendir(WEBD_PASSKEY_CHALLENGE_DIR);
    if (dir) {
        while ((ent = readdir(dir)) != NULL) {
            size_t len = strlen(ent->d_name);

            if (len > 5 && !strcmp(ent->d_name + len - 5, ".json"))
                count++;
        }
        closedir(dir);
    }
    if (count >= PASSKEY_MAX_CHALLENGES)
        return NULL;
    ch = calloc(1, sizeof(*ch));
    if (!ch)
        return NULL;
    if (passkey_gen_random(ch->challenge, WEBD_PASSKEY_CHALLENGE_LEN) != 0) {
        free(ch);
        return NULL;
    }
    passkey_bytes_to_hex(ch->challenge, WEBD_PASSKEY_CHALLENGE_LEN,
                         ch->challenge_hex, sizeof(ch->challenge_hex));
    ch->created_at = passkey_now_s();
    ch->is_registration = is_registration;
    if (username)
        snprintf(ch->username, sizeof(ch->username), "%s", username);
    if (passkey_challenge_save(ch) != 0) {
        free(ch);
        return NULL;
    }
    return ch;
}

static struct webd_passkey_challenge *passkey_challenge_find(
    const uint8_t *challenge, int is_registration)
{
    struct webd_passkey_challenge *ch = calloc(1, sizeof(*ch));
    char path[512];
    int64_t now = passkey_now_s();

    if (!ch)
        return NULL;
    passkey_bytes_to_hex(challenge, WEBD_PASSKEY_CHALLENGE_LEN,
                         ch->challenge_hex, sizeof(ch->challenge_hex));
    ch->is_registration = is_registration;
    if (passkey_challenge_path(ch, path, sizeof(path)) != 0 ||
        passkey_challenge_load(path, ch) != 0 ||
        ch->is_registration != is_registration ||
        memcmp(ch->challenge, challenge, WEBD_PASSKEY_CHALLENGE_LEN) ||
        ch->created_at > now ||
        now - ch->created_at > WEBD_PASSKEY_CHALLENGE_TTL_S ||
        passkey_challenge_take(ch) != 0) {
        free(ch);
        return NULL;
    }
    return ch;
}

static void passkey_challenge_remove(struct webd_passkey_challenge *ch)
{
    free(ch);
}

/* ══════════════════════════════════════════════════════════════════════
 * COSE > OpenSSL EVP_PKEY conversion
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Parse a COSE_Key from the CBOR authData.attestedCredentialData.
 * We support:
 *   alg -7  (ES256): kty=2(EC2), crv=1(P-256), x(32 bytes), y(32 bytes)
 *   alg -257(RS256): kty=3(RSA), n, e
 *
 * Returns 0 on success with:
 *   *alg_out  = COSE alg id
 *   *pkey_out = EVP_PKEY (caller owns)
 *   *der_out  = DER-encoded SPKI (caller must free)
 *   *der_len_out = length of DER
 */
static int passkey_cose_to_evp_pkey(const uint8_t *cose, size_t cose_len,
                                    int *alg_out, EVP_PKEY **pkey_out,
                                    uint8_t **der_out, size_t *der_len_out)
{
    struct webd_cbor_item map_item, key_item, val_item;
    size_t pos = 0;
    size_t i;
    int kty = 0, alg = 0, crv = 0;
    const uint8_t *x = NULL, *y = NULL, *n = NULL, *e_bytes = NULL;
    size_t x_len = 0, y_len = 0, n_len = 0, e_len = 0;
    EVP_PKEY *pkey = NULL;
    uint8_t *spki_der = NULL;
    int spki_der_len = 0;

    if (!cose || cose_len == 0 || !alg_out || !pkey_out || !der_out || !der_len_out)
        return WEBD_PASSKEY_ERR_INVALID_ARGUMENT;

    *alg_out = 0;
    *pkey_out = NULL;
    *der_out = NULL;
    *der_len_out = 0;

    /* Expect a CBOR map at the top level. */
    if (webd_cbor_decode_item(cose, cose_len, &pos, &map_item) != 0 ||
        map_item.type != WEBD_CBOR_MAP)
        return WEBD_PASSKEY_ERR_CBOR_PARSE;

    for (i = 0; i < map_item.v.container_count; i++) {
        int64_t label = 0;

        if (webd_cbor_decode_item(cose, cose_len, &pos, &key_item) != 0)
            return WEBD_PASSKEY_ERR_CBOR_PARSE;

        if (key_item.type == WEBD_CBOR_UINT)
            label = (int64_t)key_item.v.uint_val;
        else if (key_item.type == WEBD_CBOR_NINT)
            label = key_item.v.int_val;
        else {
            if (webd_cbor_skip_item(cose, cose_len, &pos) != 0)
                return WEBD_PASSKEY_ERR_CBOR_PARSE;
            continue;
        }

        if (webd_cbor_decode_item(cose, cose_len, &pos, &val_item) != 0)
            return WEBD_PASSKEY_ERR_CBOR_PARSE;

        switch (label) {
        case 1: /* kty */
            if (val_item.type == WEBD_CBOR_UINT)
                kty = (int)val_item.v.uint_val;
            break;
        case 3: /* alg */
            if (val_item.type == WEBD_CBOR_NINT)
                alg = (int)val_item.v.int_val;
            else if (val_item.type == WEBD_CBOR_UINT)
                alg = (int)val_item.v.uint_val;
            break;
        case -1: /* crv (EC) or n (RSA) */
            if (val_item.type == WEBD_CBOR_UINT)
                crv = (int)val_item.v.uint_val;
            else if (val_item.type == WEBD_CBOR_BSTR) {
                n = val_item.v.str.data;
                n_len = val_item.v.str.len;
            }
            break;
        case -2: /* x (EC) or e (RSA) */
            if (val_item.type == WEBD_CBOR_BSTR) {
                x = val_item.v.str.data;
                x_len = val_item.v.str.len;
                e_bytes = val_item.v.str.data;
                e_len = val_item.v.str.len;
            }
            break;
        case -3: /* y (EC only) */
            if (val_item.type == WEBD_CBOR_BSTR) {
                y = val_item.v.str.data;
                y_len = val_item.v.str.len;
            }
            break;
        default:
            /* Skip value data for containers. */
            if (val_item.type == WEBD_CBOR_ARRAY || val_item.type == WEBD_CBOR_MAP) {
                size_t skip_count = val_item.v.container_count;
                size_t j;
                size_t items = (val_item.type == WEBD_CBOR_MAP) ? skip_count * 2 : skip_count;
                for (j = 0; j < items; j++)
                    if (webd_cbor_skip_item(cose, cose_len, &pos) != 0)
                        return WEBD_PASSKEY_ERR_CBOR_PARSE;
            }
            break;
        }
    }

    if (kty == 2 && alg == WEBD_PASSKEY_COSE_ES256) {
        /* EC P-256. */
        OSSL_PARAM_BLD *bld;
        OSSL_PARAM *params;
        EVP_PKEY_CTX *pctx;
        uint8_t pub_uncompressed[65];

        if (crv != 1 || !x || x_len != 32 || !y || y_len != 32)
            return WEBD_PASSKEY_ERR_COSE_UNSUPPORTED;

        /* Build 0x04 || x || y. */
        pub_uncompressed[0] = 0x04;
        memcpy(pub_uncompressed + 1, x, 32);
        memcpy(pub_uncompressed + 33, y, 32);

        bld = OSSL_PARAM_BLD_new();
        if (!bld) return WEBD_PASSKEY_ERR_OPENSSL;

        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "prime256v1", 0);
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pub_uncompressed, 65);
        params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        if (!params) return WEBD_PASSKEY_ERR_OPENSSL;

        pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!pctx) {
            OSSL_PARAM_free(params);
            return WEBD_PASSKEY_ERR_OPENSSL;
        }
        if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
            EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            OSSL_PARAM_free(params);
            return WEBD_PASSKEY_ERR_OPENSSL;
        }
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
    } else if (kty == 3 && alg == WEBD_PASSKEY_COSE_RS256) {
        /* RSA. */
        OSSL_PARAM_BLD *bld;
        OSSL_PARAM *params;
        EVP_PKEY_CTX *pctx;
        BIGNUM *bn_n = NULL, *bn_e = NULL;

        if (!n || n_len == 0 || !e_bytes || e_len == 0)
            return WEBD_PASSKEY_ERR_COSE_UNSUPPORTED;

        bn_n = BN_bin2bn(n, (int)n_len, NULL);
        bn_e = BN_bin2bn(e_bytes, (int)e_len, NULL);
        if (!bn_n || !bn_e) {
            BN_free(bn_n); BN_free(bn_e);
            return WEBD_PASSKEY_ERR_OPENSSL;
        }

        bld = OSSL_PARAM_BLD_new();
        if (!bld) { BN_free(bn_n); BN_free(bn_e); return WEBD_PASSKEY_ERR_OPENSSL; }
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);
        params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        BN_free(bn_n); BN_free(bn_e);
        if (!params) return WEBD_PASSKEY_ERR_OPENSSL;

        pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pctx) { OSSL_PARAM_free(params); return WEBD_PASSKEY_ERR_OPENSSL; }
        if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
            EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            OSSL_PARAM_free(params);
            return WEBD_PASSKEY_ERR_OPENSSL;
        }
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
    } else {
        return WEBD_PASSKEY_ERR_COSE_UNSUPPORTED;
    }

    /* Serialize public key to DER (SubjectPublicKeyInfo). */
    spki_der_len = i2d_PUBKEY(pkey, NULL);
    if (spki_der_len <= 0) {
        EVP_PKEY_free(pkey);
        return WEBD_PASSKEY_ERR_OPENSSL;
    }
    spki_der = malloc((size_t)spki_der_len);
    if (!spki_der) {
        EVP_PKEY_free(pkey);
        return WEBD_PASSKEY_ERR_OPENSSL;
    }
    {
        unsigned char *cursor = spki_der;

        if (i2d_PUBKEY(pkey, &cursor) != spki_der_len) {
            free(spki_der);
            EVP_PKEY_free(pkey);
            return WEBD_PASSKEY_ERR_OPENSSL;
        }
    }

    *alg_out = alg;
    *pkey_out = pkey;
    *der_out = spki_der;
    *der_len_out = (size_t)spki_der_len;
    return WEBD_PASSKEY_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * Signature verification
 * ══════════════════════════════════════════════════════════════════════ */

static int passkey_verify_signature(EVP_PKEY *pkey, int cose_alg,
                                    const uint8_t *auth_data, size_t auth_data_len,
                                    const uint8_t *client_data_hash,
                                    const uint8_t *sig, size_t sig_len)
{
    EVP_MD_CTX *mdctx;
    int rc;

    if (!pkey || !auth_data || !client_data_hash || !sig || sig_len == 0)
        return WEBD_PASSKEY_ERR_INVALID_ARGUMENT;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) return WEBD_PASSKEY_ERR_OPENSSL;

    if (cose_alg == WEBD_PASSKEY_COSE_ES256) {
        rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    } else if (cose_alg == WEBD_PASSKEY_COSE_RS256) {
        EVP_PKEY_CTX *pctx = NULL;
        rc = EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pkey);
        if (rc == 1 && pctx)
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
    } else {
        EVP_MD_CTX_free(mdctx);
        return WEBD_PASSKEY_ERR_COSE_UNSUPPORTED;
    }

    if (rc != 1) {
        EVP_MD_CTX_free(mdctx);
        return WEBD_PASSKEY_ERR_OPENSSL;
    }

    /* Message = authData || SHA-256(clientDataJSON). */
    if (EVP_DigestVerifyUpdate(mdctx, auth_data, auth_data_len) != 1 ||
        EVP_DigestVerifyUpdate(mdctx, client_data_hash, SHA256_DIGEST_LENGTH) != 1) {
        EVP_MD_CTX_free(mdctx);
        return WEBD_PASSKEY_ERR_OPENSSL;
    }

    rc = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    EVP_MD_CTX_free(mdctx);
    return (rc == 1) ? WEBD_PASSKEY_OK : WEBD_PASSKEY_ERR_SIGNATURE_INVALID;
}

static int passkey_parse_attestation_none(const uint8_t *attestation,
                                          size_t attestation_len,
                                          const uint8_t **auth_data,
                                          size_t *auth_data_len)
{
    struct webd_cbor_item map;
    size_t pos = 0;
    size_t i;
    int fmt_none = 0;
    int empty_att_stmt = 0;

    if (!attestation || !auth_data || !auth_data_len ||
        webd_cbor_decode_item(attestation, attestation_len, &pos, &map) != 0 ||
        map.type != WEBD_CBOR_MAP)
        return -1;
    *auth_data = NULL;
    *auth_data_len = 0;
    for (i = 0; i < map.v.container_count; i++) {
        struct webd_cbor_item key;
        struct webd_cbor_item value;
        int is_fmt;
        int is_auth_data;
        int is_att_stmt;

        if (webd_cbor_decode_item(attestation, attestation_len, &pos, &key) != 0 ||
            webd_cbor_decode_item(attestation, attestation_len, &pos, &value) != 0)
            return -1;
        is_fmt = key.type == WEBD_CBOR_TSTR && key.v.str.len == 3 &&
                 !memcmp(key.v.str.data, "fmt", 3);
        is_auth_data = key.type == WEBD_CBOR_TSTR && key.v.str.len == 8 &&
                       !memcmp(key.v.str.data, "authData", 8);
        is_att_stmt = key.type == WEBD_CBOR_TSTR && key.v.str.len == 7 &&
                      !memcmp(key.v.str.data, "attStmt", 7);
        if (is_fmt) {
            fmt_none = value.type == WEBD_CBOR_TSTR && value.v.str.len == 4 &&
                       !memcmp(value.v.str.data, "none", 4);
        } else if (is_auth_data && value.type == WEBD_CBOR_BSTR) {
            *auth_data = value.v.str.data;
            *auth_data_len = value.v.str.len;
        } else if (is_att_stmt) {
            empty_att_stmt = value.type == WEBD_CBOR_MAP &&
                             value.v.container_count == 0;
        }
        if (passkey_cbor_skip_children(attestation, attestation_len, &value,
                                       &pos) != 0)
            return -1;
    }
    return fmt_none && empty_att_stmt && *auth_data && *auth_data_len ? 0 : -1;
}

static int passkey_credential_hex_from_body(struct json_object *body,
                                            char *hex, size_t hex_len)
{
    const char *value;
    uint8_t decoded[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
    int decoded_len;

    body = passkey_body_payload(body);
    value = passkey_json_str(body, "credential_id_hex");
    if (value && passkey_hex_valid(value, WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2) &&
        strlen(value) + 1 <= hex_len) {
        size_t i;

        for (i = 0; value[i]; i++)
            hex[i] = (char)tolower((unsigned char)value[i]);
        hex[i] = '\0';
        return 0;
    }
    value = passkey_json_str_any(body, "credential_id");
    if (!value) value = passkey_json_str_any(body, "rawId");
    if (!value) value = passkey_json_str_any(body, "id");
    if (passkey_decode_credential_id(value, decoded, sizeof(decoded),
                                     &decoded_len) != 0 ||
        (size_t)decoded_len * 2 + 1 > hex_len)
        return -1;
    passkey_bytes_to_hex(decoded, (size_t)decoded_len, hex, hex_len);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Route handlers
 * ══════════════════════════════════════════════════════════════════════ */

/* GET /api/v1/passkey/can-authenticate */
struct json_object *webd_passkey_can_authenticate(int *http_status)
{
    struct json_object *resp = json_object_new_object();
    int count = passkey_credential_count();
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];

    webd_passkey_rp_id(rp_id, sizeof(rp_id));
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "available", json_object_new_boolean(count > 0));
    json_object_object_add(resp, "passkey_available", json_object_new_boolean(count > 0));
    json_object_object_add(resp, "credential_count", json_object_new_int(count));
    json_object_object_add(resp, "rp_id", json_object_new_string(rp_id));
    if (http_status) *http_status = 200;
    return resp;
}

/* POST /api/v1/passkey/authenticate/begin */
static struct json_object *passkey_authenticate_begin(
    const char *username, const char *binding, int *http_status)
{
    struct webd_passkey_challenge *ch;
    struct json_object *resp, *options, *allow_arr;
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];
    char challenge_b64[128];
    DIR *d;
    struct dirent *ent;

    if (passkey_credential_count() == 0)
        return passkey_error("no_credentials",
                             "no passkey credentials registered", 404, http_status);

    ch = passkey_challenge_alloc(username ? 2 : 0, username);
    if (!ch)
        return passkey_error("challenge_alloc_failed",
                             "could not generate challenge", 500, http_status);

    webd_passkey_rp_id(rp_id, sizeof(rp_id));
    webd_base64url_encode(ch->challenge, WEBD_PASSKEY_CHALLENGE_LEN,
                          challenge_b64, sizeof(challenge_b64));
    if (username) {
        snprintf(ch->operation_binding, sizeof(ch->operation_binding), "%s", binding);
        if (passkey_challenge_save(ch)) {
            passkey_challenge_take(ch); passkey_challenge_remove(ch);
            return passkey_error("challenge_save_failed", "could not persist operation binding", 500, http_status);
        }
    }

    /* Build allowCredentials list from stored credentials. */
    allow_arr = json_object_new_array();
    d = opendir(WEBD_PASSKEY_CRED_DIR);
    if (d) {
        while ((ent = readdir(d)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            char cred_id_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
            uint8_t cred_id_bin[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
            size_t cred_id_bin_len;
            char cred_id_b64[2048];
            struct json_object *entry;

            if (nlen <= 5 || strcmp(ent->d_name + nlen - 5, ".json")) continue;
            snprintf(cred_id_hex, sizeof(cred_id_hex), "%.*s",
                     (int)(nlen - 5), ent->d_name);
            if (!passkey_hex_valid(cred_id_hex, WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2))
                continue;

            if (username) {
                struct webd_passkey_credential credential = {0};
                int match = !passkey_credential_load(cred_id_hex, &credential) &&
                            !strcmp(credential.username, username);
                passkey_credential_free(&credential);
                if (!match) continue;
            }

            cred_id_bin_len = strlen(cred_id_hex) / 2;
            if (passkey_hex_to_bytes(cred_id_hex, cred_id_bin, cred_id_bin_len) != 0)
                continue;
            if (webd_base64url_encode(cred_id_bin, cred_id_bin_len,
                                     cred_id_b64, sizeof(cred_id_b64)) != 0)
                continue;

            entry = json_object_new_object();
            json_object_object_add(entry, "type",
                                   json_object_new_string("public-key"));
            json_object_object_add(entry, "id",
                                   json_object_new_string(cred_id_b64));
            json_object_array_add(allow_arr, entry);
        }
        closedir(d);
    }

    if (username && !json_object_array_length(allow_arr)) {
        json_object_put(allow_arr);
        passkey_challenge_take(ch); passkey_challenge_remove(ch);
        return passkey_error("no_credentials", "current user has no passkey", 404, http_status);
    }
    passkey_challenge_remove(ch);
    options = json_object_new_object();
    json_object_object_add(options, "challenge",
                           json_object_new_string(challenge_b64));
    json_object_object_add(options, "rpId",
                           json_object_new_string(rp_id));
    json_object_object_add(options, "timeout",
                           json_object_new_int(WEBD_PASSKEY_CHALLENGE_TTL_S * 1000));
    json_object_object_add(options, "userVerification",
                           json_object_new_string(username ? "required" : "preferred"));
    json_object_object_add(options, "allowCredentials", allow_arr);

    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "publicKeyCredentialRequestOptions", options);
    if (http_status) *http_status = 200;
    return resp;
}

struct json_object *webd_passkey_authenticate_begin(struct json_object *body, int *status)
{
    (void)body;
    return passkey_authenticate_begin(NULL, NULL, status);
}

struct json_object *webd_passkey_reauthenticate_begin(
    const char *username, const char *binding, int *status)
{
    if (!username || !username[0] || !binding || strlen(binding) != 64 ||
        !passkey_hex_valid(binding, 64))
        return passkey_error("invalid_request", "authenticated operation binding required", 400, status);
    return passkey_authenticate_begin(username, binding, status);
}

/* POST /api/v1/passkey/register/begin */
struct json_object *webd_passkey_register_begin(
    struct json_object *body, const char *username,
    const char *client_ip, int *http_status)
{
    struct json_object *payload;
    struct json_object *resp;
    struct json_object *options;
    struct json_object *rp;
    struct json_object *user;
    struct json_object *params;
    struct json_object *exclude;
    struct webd_passkey_challenge *ch;
    const char *password;
    const char *friendly_name;
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];
    char challenge_b64[128];
    char user_id[128];
    DIR *dir;
    struct dirent *ent;

    (void)client_ip;
    payload = passkey_body_payload(body);
    password = passkey_json_str(payload, "password");
    friendly_name = passkey_json_str(payload, "friendly_name");
    if (!friendly_name)
        friendly_name = passkey_json_str(payload, "display_name");
    if (!username || !username[0] || !passkey_string_valid(username, 64) ||
        !password || !password[0])
        return passkey_error("password_required",
                             "username and password are required", 400, http_status);
    if (!g_password_verify)
        return passkey_error("password_verifier_unavailable",
                             "password verification is unavailable", 503, http_status);
    if (!g_password_verify(username, password))
        return passkey_error("password_invalid", "password verification failed",
                             401, http_status);
    if (passkey_credential_count() >= g_max_credentials)
        return passkey_error("max_credentials", "maximum passkey count reached",
                             409, http_status);

    ch = passkey_challenge_alloc(1, username);
    if (!ch)
        return passkey_error("challenge_alloc_failed",
                             "could not generate challenge", 500, http_status);
    if (friendly_name &&
        passkey_string_valid(friendly_name, WEBD_PASSKEY_FRIENDLY_NAME_MAX)) {
        snprintf(ch->friendly_name, sizeof(ch->friendly_name), "%s",
                 friendly_name);
        if (passkey_challenge_save(ch) != 0) {
            passkey_challenge_take(ch);
            passkey_challenge_remove(ch);
            return passkey_error("challenge_save_failed",
                                 "could not persist registration challenge",
                                 500, http_status);
        }
    }
    webd_passkey_rp_id(rp_id, sizeof(rp_id));
    if (webd_base64url_encode(ch->challenge, WEBD_PASSKEY_CHALLENGE_LEN,
                              challenge_b64, sizeof(challenge_b64)) != 0 ||
        webd_base64url_encode((const uint8_t *)username, strlen(username),
                              user_id, sizeof(user_id)) != 0) {
        passkey_challenge_remove(ch);
        return passkey_error("encoding_failed", "could not build registration options",
                             500, http_status);
    }
    passkey_challenge_remove(ch);

    rp = json_object_new_object();
    json_object_object_add(rp, "id", json_object_new_string(rp_id));
    json_object_object_add(rp, "name", json_object_new_string(g_rp_name));
    user = json_object_new_object();
    json_object_object_add(user, "id", json_object_new_string(user_id));
    json_object_object_add(user, "name", json_object_new_string(username));
    json_object_object_add(user, "displayName", json_object_new_string(username));
    params = json_object_new_array();
    {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "type", json_object_new_string("public-key"));
        json_object_object_add(item, "alg", json_object_new_int(WEBD_PASSKEY_COSE_ES256));
        json_object_array_add(params, item);
        item = json_object_new_object();
        json_object_object_add(item, "type", json_object_new_string("public-key"));
        json_object_object_add(item, "alg", json_object_new_int(WEBD_PASSKEY_COSE_RS256));
        json_object_array_add(params, item);
    }
    exclude = json_object_new_array();
    dir = opendir(WEBD_PASSKEY_CRED_DIR);
    if (dir) {
        while ((ent = readdir(dir)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            char cred_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
            uint8_t cred_bin[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
            char cred_b64[2048];
            struct webd_passkey_credential cred;

            if (nlen <= 5 || strcmp(ent->d_name + nlen - 5, ".json"))
                continue;
            snprintf(cred_hex, sizeof(cred_hex), "%.*s", (int)(nlen - 5),
                     ent->d_name);
            memset(&cred, 0, sizeof(cred));
            if (passkey_credential_load(cred_hex, &cred) != 0 ||
                strcmp(cred.username, username) ||
                strlen(cred_hex) / 2 > sizeof(cred_bin) ||
                passkey_hex_to_bytes(cred_hex, cred_bin, strlen(cred_hex) / 2) != 0 ||
                webd_base64url_encode(cred_bin, strlen(cred_hex) / 2,
                                      cred_b64, sizeof(cred_b64)) != 0) {
                passkey_credential_free(&cred);
                continue;
            }
            {
                struct json_object *item = json_object_new_object();
                json_object_object_add(item, "type",
                                       json_object_new_string("public-key"));
                json_object_object_add(item, "id",
                                       json_object_new_string(cred_b64));
                json_object_array_add(exclude, item);
            }
            passkey_credential_free(&cred);
        }
        closedir(dir);
    }
    options = json_object_new_object();
    json_object_object_add(options, "challenge", json_object_new_string(challenge_b64));
    json_object_object_add(options, "rp", rp);
    json_object_object_add(options, "user", user);
    json_object_object_add(options, "pubKeyCredParams", params);
    json_object_object_add(options, "timeout",
                           json_object_new_int(WEBD_PASSKEY_CHALLENGE_TTL_S * 1000));
    json_object_object_add(options, "attestation", json_object_new_string("none"));
    json_object_object_add(options, "excludeCredentials", exclude);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "publicKeyCredentialCreationOptions", options);
    if (http_status) *http_status = 200;
    return resp;
}

/* POST /api/v1/passkey/register/finish */
struct json_object *webd_passkey_register_finish(
    struct json_object *body, const char *username, int *http_status)
{
    const char *client_data_b64;
    const char *attestation_b64;
    uint8_t client_data_raw[4096];
    uint8_t attestation_raw[PASSKEY_MAX_BODY_FIELD];
    int client_data_len;
    int attestation_len;
    struct json_object *cd_json = NULL;
    const char *cd_type;
    const char *cd_challenge_b64;
    const char *cd_origin;
    uint8_t challenge_decoded[WEBD_PASSKEY_CHALLENGE_LEN + 16];
    int challenge_len;
    struct webd_passkey_challenge *ch = NULL;
    const uint8_t *auth_data;
    size_t auth_data_len;
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    uint32_t sign_count;
    size_t cose_start;
    size_t cose_end;
    int cose_alg;
    EVP_PKEY *pkey = NULL;
    uint8_t *der = NULL;
    size_t der_len = 0;
    uint8_t credential_id[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
    size_t credential_id_len;
    char credential_id_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
    char credential_id_b64[2048];
    const char *friendly_name;
    struct webd_passkey_credential cred;
    struct json_object *resp;
    int rc;

    body = passkey_body_payload(body);
    client_data_b64 = passkey_json_str_any(body, "clientDataJSON");
    attestation_b64 = passkey_json_str_any(body, "attestationObject");
    if (!client_data_b64 || !attestation_b64 || !username || !username[0])
        return passkey_error("missing_fields",
                             "clientDataJSON and attestationObject are required",
                             400, http_status);
    client_data_len = webd_base64url_decode(client_data_b64, strlen(client_data_b64),
                                            client_data_raw, sizeof(client_data_raw));
    attestation_len = webd_base64url_decode(attestation_b64, strlen(attestation_b64),
                                            attestation_raw, sizeof(attestation_raw));
    if (client_data_len <= 0 || attestation_len <= 0)
        return passkey_error("decode_failed", "registration payload is invalid",
                             400, http_status);
    {
        char text[sizeof(client_data_raw)];
        if ((size_t)client_data_len >= sizeof(text))
            return passkey_error("client_data_too_large", "clientDataJSON is too large",
                                 400, http_status);
        memcpy(text, client_data_raw, (size_t)client_data_len);
        text[client_data_len] = '\0';
        cd_json = json_tokener_parse(text);
    }
    if (!cd_json)
        return passkey_error("client_data_invalid", "clientDataJSON is invalid",
                             400, http_status);
    cd_type = passkey_json_str(cd_json, "type");
    cd_challenge_b64 = passkey_json_str(cd_json, "challenge");
    cd_origin = passkey_json_str(cd_json, "origin");
    if (!cd_type || strcmp(cd_type, "webauthn.create") || !cd_challenge_b64) {
        json_object_put(cd_json);
        return passkey_error("client_data_invalid", "registration clientDataJSON is invalid",
                             400, http_status);
    }
    webd_passkey_rp_id(rp_id, sizeof(rp_id));
    if (!cd_origin || !passkey_origin_allowed(cd_origin, rp_id)) {
        json_object_put(cd_json);
        return passkey_error("origin_mismatch", "clientDataJSON origin is not allowed",
                             400, http_status);
    }
    challenge_len = webd_base64url_decode(cd_challenge_b64, strlen(cd_challenge_b64),
                                          challenge_decoded, sizeof(challenge_decoded));
    if (challenge_len != WEBD_PASSKEY_CHALLENGE_LEN ||
        !(ch = passkey_challenge_find(challenge_decoded, 1)) ||
        strcmp(ch->username, username)) {
        if (ch) passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("challenge_mismatch", "registration challenge is invalid",
                             400, http_status);
    }
    if (passkey_parse_attestation_none(attestation_raw, (size_t)attestation_len,
                                       &auth_data, &auth_data_len) != 0 ||
        auth_data_len < 55) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("attestation_invalid", "only none attestation is supported",
                             400, http_status);
    }
    SHA256((const uint8_t *)rp_id, strlen(rp_id), rp_id_hash);
    if (memcmp(auth_data, rp_id_hash, SHA256_DIGEST_LENGTH) != 0 ||
        !(auth_data[32] & 0x01) || !(auth_data[32] & 0x40)) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("authenticator_data_invalid",
                             "rpIdHash, user presence, or credential data is invalid",
                             400, http_status);
    }
    sign_count = ((uint32_t)auth_data[33] << 24) |
                 ((uint32_t)auth_data[34] << 16) |
                 ((uint32_t)auth_data[35] << 8) | auth_data[36];
    credential_id_len = ((size_t)auth_data[53] << 8) | auth_data[54];
    if (!credential_id_len || credential_id_len > sizeof(credential_id) ||
        55 + credential_id_len >= auth_data_len) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_id_invalid", "credential id is invalid",
                             400, http_status);
    }
    memcpy(credential_id, auth_data + 55, credential_id_len);
    passkey_bytes_to_hex(credential_id, credential_id_len, credential_id_hex,
                         sizeof(credential_id_hex));
    if (webd_base64url_encode(credential_id, credential_id_len, credential_id_b64,
                              sizeof(credential_id_b64)) != 0) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_id_invalid", "credential id is too large",
                             400, http_status);
    }
    {
        const char *presented_id = passkey_json_str_any(body, "rawId");
        uint8_t presented[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
        int presented_len;

        if (presented_id &&
            (passkey_decode_credential_id(presented_id, presented,
                                          sizeof(presented), &presented_len) != 0 ||
             (size_t)presented_len != credential_id_len ||
             memcmp(presented, credential_id, credential_id_len))) {
            passkey_challenge_remove(ch);
            json_object_put(cd_json);
            return passkey_error("credential_id_mismatch",
                                 "rawId does not match attested credential id",
                                 400, http_status);
        }
    }
    if (passkey_credential_count() >= g_max_credentials) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("max_credentials", "maximum passkey count reached",
                             409, http_status);
    }
    memset(&cred, 0, sizeof(cred));
    if (passkey_credential_load(credential_id_hex, &cred) == 0) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_exists", "credential is already registered",
                             409, http_status);
    }
    cose_start = 55 + credential_id_len;
    cose_end = cose_start;
    if (webd_cbor_skip_item(auth_data, auth_data_len, &cose_end) != 0 ||
        cose_end <= cose_start ||
        passkey_cose_to_evp_pkey(auth_data + cose_start,
                                 cose_end - cose_start,
                                 &cose_alg, &pkey, &der, &der_len) != WEBD_PASSKEY_OK) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("public_key_invalid", "unsupported COSE public key",
                             400, http_status);
    }
    friendly_name = passkey_json_str_any(body, "friendly_name");
    if (!friendly_name) friendly_name = passkey_json_str_any(body, "name");
    if (!friendly_name) friendly_name = passkey_json_str_any(body, "display_name");
    if (!friendly_name && ch->friendly_name[0]) friendly_name = ch->friendly_name;
    memset(&cred, 0, sizeof(cred));
    snprintf(cred.credential_id_hex, sizeof(cred.credential_id_hex), "%s",
             credential_id_hex);
    cred.cose_alg = cose_alg;
    cred.public_key_der = der;
    cred.public_key_der_len = der_len;
    cred.sign_count = sign_count;
    cred.created_at = passkey_now_s();
    cred.last_used_at = 0;
    snprintf(cred.username, sizeof(cred.username), "%s", username);
    if (friendly_name && passkey_string_valid(friendly_name,
                                               WEBD_PASSKEY_FRIENDLY_NAME_MAX))
        snprintf(cred.friendly_name, sizeof(cred.friendly_name), "%s", friendly_name);
    rc = passkey_credential_save(&cred);
    EVP_PKEY_free(pkey);
    free(der);
    passkey_challenge_remove(ch);
    json_object_put(cd_json);
    if (rc != 0)
        return passkey_error("credential_save_failed", "could not persist credential",
                             500, http_status);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "credential_id",
                           json_object_new_string(credential_id_b64));
    json_object_object_add(resp, "credential_id_hex",
                           json_object_new_string(credential_id_hex));
    json_object_object_add(resp, "friendly_name",
                           json_object_new_string(cred.friendly_name));
    if (http_status) *http_status = 200;
    return resp;
}

/* POST /api/v1/passkey/authenticate/finish */
static struct json_object *passkey_authenticate_finish(
    struct json_object *body, sqlite3 *config_db, sqlite3 *app_db,
    const char *username, const char *binding, int *http_status)
{
    const char *client_data_b64, *auth_data_b64, *sig_b64, *cred_id_b64;
    uint8_t client_data_raw[4096], auth_data_raw[4096], sig_raw[1024];
    uint8_t cred_id_bin[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
    int cd_len, ad_len, sig_len, cred_id_len;
    uint8_t client_data_hash[SHA256_DIGEST_LENGTH];
    struct json_object *cd_json = NULL;
    const char *cd_type, *cd_challenge_b64, *cd_origin;
    uint8_t challenge_decoded[WEBD_PASSKEY_CHALLENGE_LEN + 16];
    int challenge_decoded_len;
    struct webd_passkey_challenge *ch;
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    uint32_t stored_sign_count, reported_sign_count;
    char cred_id_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
    struct webd_passkey_credential cred;
    EVP_PKEY *pkey = NULL;
    const uint8_t *spki_ptr;
    int verify_rc;
    int64_t now;
    char access_tok[TOKEN_LEN + 1], refresh_tok[TOKEN_LEN + 1];
    char session_id[TOKEN_LEN + 1];
    char role[32];
    struct json_object *resp;

    if (!body)
        return passkey_error("invalid_request", "request body required", 400, http_status);
    body = passkey_body_payload(body);

    /* Extract fields. */
    client_data_b64 = passkey_json_str_any(body, "clientDataJSON");
    auth_data_b64 = passkey_json_str_any(body, "authenticatorData");
    sig_b64 = passkey_json_str_any(body, "signature");
    cred_id_b64 = passkey_json_str_any(body, "credential_id");
    if (!cred_id_b64) cred_id_b64 = passkey_json_str_any(body, "rawId");
    if (!cred_id_b64) cred_id_b64 = passkey_json_str_any(body, "id");

    if (!client_data_b64 || !auth_data_b64 || !sig_b64 || !cred_id_b64)
        return passkey_error("missing_fields",
                             "clientDataJSON, authenticatorData, signature, credential_id required",
                             400, http_status);

    /* Decode base64url fields. */
    cd_len = webd_base64url_decode(client_data_b64, strlen(client_data_b64),
                                   client_data_raw, sizeof(client_data_raw));
    ad_len = webd_base64url_decode(auth_data_b64, strlen(auth_data_b64),
                                   auth_data_raw, sizeof(auth_data_raw));
    sig_len = webd_base64url_decode(sig_b64, strlen(sig_b64),
                                    sig_raw, sizeof(sig_raw));
    cred_id_len = webd_base64url_decode(cred_id_b64, strlen(cred_id_b64),
                                         cred_id_bin, sizeof(cred_id_bin));

    if (cd_len <= 0 || ad_len < 37 || sig_len <= 0 || cred_id_len <= 0)
        return passkey_error("decode_failed",
                             "base64url decode failed for one or more fields",
                             400, http_status);

    /* SHA-256(clientDataJSON). */
    SHA256(client_data_raw, (size_t)cd_len, client_data_hash);

    /* Parse clientDataJSON. */
    {
        char cd_str[4096];
        if ((size_t)cd_len >= sizeof(cd_str))
            return passkey_error("client_data_too_large",
                                 "clientDataJSON is too large", 400, http_status);
        memcpy(cd_str, client_data_raw, (size_t)cd_len);
        cd_str[cd_len] = '\0';
        cd_json = json_tokener_parse(cd_str);
    }
    if (!cd_json)
        return passkey_error("client_data_invalid",
                             "clientDataJSON is not valid JSON", 400, http_status);

    cd_type = passkey_json_str(cd_json, "type");
    cd_challenge_b64 = passkey_json_str(cd_json, "challenge");
    cd_origin = passkey_json_str(cd_json, "origin");

    if (!cd_type || strcmp(cd_type, "webauthn.get") != 0) {
        json_object_put(cd_json);
        return passkey_error("type_mismatch",
                             "clientDataJSON type must be webauthn.get", 400, http_status);
    }
    if (!cd_challenge_b64) {
        json_object_put(cd_json);
        return passkey_error("challenge_missing",
                             "challenge missing from clientDataJSON", 400, http_status);
    }

    webd_passkey_rp_id(rp_id, sizeof(rp_id));
    if (!cd_origin || !passkey_origin_allowed(cd_origin, rp_id)) {
        json_object_put(cd_json);
        return passkey_error("origin_mismatch",
                             "clientDataJSON origin is not allowed for this rp_id",
                             400, http_status);
    }

    /* Decode and find challenge. */
    challenge_decoded_len = webd_base64url_decode(
        cd_challenge_b64, strlen(cd_challenge_b64),
        challenge_decoded, sizeof(challenge_decoded));
    if (challenge_decoded_len != WEBD_PASSKEY_CHALLENGE_LEN) {
        json_object_put(cd_json);
        return passkey_error("challenge_invalid",
                             "challenge length mismatch", 400, http_status);
    }

    ch = passkey_challenge_find(challenge_decoded, username ? 2 : 0);
    if (!ch) {
        json_object_put(cd_json);
        return passkey_error("challenge_expired",
                             "challenge not found or expired", 400, http_status);
    }
    if (username && (!binding || strcmp(ch->username, username) ||
                     strcmp(ch->operation_binding, binding))) {
        passkey_challenge_remove(ch); json_object_put(cd_json);
        return passkey_error("operation_mismatch", "confirmation belongs to another session or operation", 403, http_status);
    }

    /* Verify rpIdHash. */
    SHA256((const uint8_t *)rp_id, strlen(rp_id), rp_id_hash);
    if (ad_len < 37 || memcmp(auth_data_raw, rp_id_hash, 32) != 0) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("rp_id_mismatch",
                             "rpIdHash in authenticatorData does not match", 400, http_status);
    }
    if (!(auth_data_raw[32] & 0x01)) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("user_presence_required",
                             "authenticator did not assert user presence", 400,
                             http_status);
    }
    if (username && !(auth_data_raw[32] & 0x04)) {
        passkey_challenge_remove(ch); json_object_put(cd_json);
        return passkey_error("user_verification_required", "verify with the authenticator", 401, http_status);
    }

    /* Credential lookup. */
    passkey_bytes_to_hex(cred_id_bin, (size_t)cred_id_len,
                         cred_id_hex, sizeof(cred_id_hex));
    memset(&cred, 0, sizeof(cred));
    if (passkey_credential_load(cred_id_hex, &cred) != 0) {
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_not_found",
                             "no stored credential matches this id", 404, http_status);
    }
    if (!cred.username[0]) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_corrupt",
                             "stored credential has no owning user", 500,
                             http_status);
    }
    if (username && strcmp(cred.username, username)) {
        passkey_credential_free(&cred); passkey_challenge_remove(ch); json_object_put(cd_json);
        return passkey_error("credential_owner_mismatch", "passkey belongs to another user", 403, http_status);
    }

    /* Reconstruct EVP_PKEY from stored DER. */
    if (!cred.public_key_der || cred.public_key_der_len == 0) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_corrupt",
                             "stored credential has no public key", 500, http_status);
    }
    spki_ptr = cred.public_key_der;
    pkey = d2i_PUBKEY(NULL, &spki_ptr, (long)cred.public_key_der_len);
    if (!pkey) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("key_decode_failed",
                             "could not decode stored public key", 500, http_status);
    }

    /* Verify signature. */
    verify_rc = passkey_verify_signature(pkey, cred.cose_alg,
                                         auth_data_raw, (size_t)ad_len,
                                         client_data_hash,
                                         sig_raw, (size_t)sig_len);
    EVP_PKEY_free(pkey);
    if (verify_rc != WEBD_PASSKEY_OK) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("signature_invalid",
                             "authenticator signature verification failed", 401, http_status);
    }

    /* Check sign count. */
    reported_sign_count = ((uint32_t)auth_data_raw[33] << 24) |
                          ((uint32_t)auth_data_raw[34] << 16) |
                          ((uint32_t)auth_data_raw[35] << 8) |
                          (uint32_t)auth_data_raw[36];
    stored_sign_count = cred.sign_count;

    /* If both are non-zero, reported must be greater. */
    if ((stored_sign_count > 0 || reported_sign_count > 0) &&
        reported_sign_count <= stored_sign_count) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("sign_count_rollback",
                             "authenticator sign count indicates possible cloned credential",
                             401, http_status);
    }

    if (!passkey_lookup_role(config_db, cred.username, role, sizeof(role))) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("user_unavailable",
                             "credential owner is missing or disabled", 401,
                             http_status);
    }

    /* Update credential. */
    now = passkey_now_s();
    cred.sign_count = reported_sign_count;
    cred.last_used_at = now;
    if (passkey_credential_save(&cred) != 0) {
        passkey_credential_free(&cred);
        passkey_challenge_remove(ch);
        json_object_put(cd_json);
        return passkey_error("credential_update_failed",
                             "could not update credential sign count", 500,
                             http_status);
    }

    /* Consume the challenge. */
    passkey_challenge_remove(ch);
    json_object_put(cd_json);

    if (username) {
        passkey_credential_free(&cred);
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "reauthenticated", json_object_new_boolean(1));
        if (http_status) *http_status = 200;
        return resp;
    }

    /* Issue session tokens, same as password login. */
    {
        if (passkey_gen_random_hex(access_tok, TOKEN_LEN) != 0 ||
            passkey_gen_random_hex(refresh_tok, TOKEN_LEN) != 0 ||
            passkey_gen_random_hex(session_id, TOKEN_LEN) != 0) {
            passkey_credential_free(&cred);
            return passkey_error("token_entropy_unavailable",
                                 "strong randomness unavailable", 500, http_status);
        }

        if (webd_session_idle_login_insert(
                app_db, access_tok, now + PASSKEY_ACCESS_TTL_S,
                refresh_tok, now + PASSKEY_REFRESH_TTL_S,
                cred.username, session_id, now) != WEBD_SESSION_IDLE_OK) {
            passkey_credential_free(&cred);
            return passkey_error("session_create_failed",
                                 "could not create session tokens", 500, http_status);
        }

        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "access_token", json_object_new_string(access_tok));
        json_object_object_add(resp, "refresh_token", json_object_new_string(refresh_tok));
        json_object_object_add(resp, "expires_in", json_object_new_int(PASSKEY_ACCESS_TTL_S));
        json_object_object_add(resp, "username", json_object_new_string(cred.username));
        json_object_object_add(resp, "role", json_object_new_string(role));
        json_object_object_add(resp, "auth_type", json_object_new_string("passkey"));
    }
    if (http_status) *http_status = 200;

    passkey_credential_free(&cred);
    return resp;
}

struct json_object *webd_passkey_authenticate_finish(
    struct json_object *body, sqlite3 *config_db, sqlite3 *app_db, int *status)
{
    return passkey_authenticate_finish(body, config_db, app_db, NULL, NULL, status);
}

struct json_object *webd_passkey_reauthenticate_finish(
    struct json_object *body, sqlite3 *config_db, const char *username,
    const char *binding, int *status)
{
    if (!username || !username[0] || !binding || strlen(binding) != 64 ||
        !passkey_hex_valid(binding, 64))
        return passkey_error("invalid_request", "authenticated operation binding required", 400, status);
    return passkey_authenticate_finish(body, config_db, NULL, username, binding, status);
}

/* GET /api/v1/passkey/list */
struct json_object *webd_passkey_list(const char *username, int *http_status)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    DIR *dir;
    struct dirent *ent;

    if (!username || !username[0]) {
        json_object_put(resp);
        json_object_put(items);
        return passkey_error("user_required", "authenticated web user required",
                             401, http_status);
    }
    dir = opendir(WEBD_PASSKEY_CRED_DIR);
    if (dir) {
        while ((ent = readdir(dir)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            char cred_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
            uint8_t cred_id[WEBD_PASSKEY_CREDENTIAL_ID_MAX];
            char cred_b64[2048];
            struct webd_passkey_credential cred;
            struct json_object *item;
            size_t cred_len;

            if (nlen <= 5 || strcmp(ent->d_name + nlen - 5, ".json"))
                continue;
            snprintf(cred_hex, sizeof(cred_hex), "%.*s", (int)(nlen - 5),
                     ent->d_name);
            memset(&cred, 0, sizeof(cred));
            if (passkey_credential_load(cred_hex, &cred) != 0 ||
                strcmp(cred.username, username)) {
                passkey_credential_free(&cred);
                continue;
            }
            cred_len = strlen(cred_hex) / 2;
            if (cred_len > sizeof(cred_id) ||
                passkey_hex_to_bytes(cred_hex, cred_id, cred_len) != 0 ||
                webd_base64url_encode(cred_id, cred_len, cred_b64,
                                      sizeof(cred_b64)) != 0) {
                passkey_credential_free(&cred);
                continue;
            }
            item = json_object_new_object();
            json_object_object_add(item, "id", json_object_new_string(cred_b64));
            json_object_object_add(item, "credential_id",
                                   json_object_new_string(cred_b64));
            json_object_object_add(item, "credential_id_hex",
                                   json_object_new_string(cred_hex));
            json_object_object_add(item, "friendly_name",
                                   json_object_new_string(cred.friendly_name));
            json_object_object_add(item, "algorithm",
                                   json_object_new_int(cred.cose_alg));
            json_object_object_add(item, "sign_count",
                                   json_object_new_int64(cred.sign_count));
            json_object_object_add(item, "created_at",
                                   json_object_new_int64(cred.created_at));
            json_object_object_add(item, "last_used_at",
                                   json_object_new_int64(cred.last_used_at));
            json_object_array_add(items, item);
            passkey_credential_free(&cred);
        }
        closedir(dir);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "credentials", items);
    json_object_object_add(resp, "credential_count",
                           json_object_new_int((int)json_object_array_length(items)));
    if (http_status) *http_status = 200;
    return resp;
}

/* POST /api/v1/passkey/delete */
struct json_object *webd_passkey_delete(
    struct json_object *body, const char *username,
    const char *client_ip, int *http_status)
{
    struct json_object *payload = passkey_body_payload(body);
    const char *password = passkey_json_str(payload, "password");
    char cred_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
    struct webd_passkey_credential cred;
    struct json_object *resp;

    (void)client_ip;
    if (!username || !username[0] || !password || !password[0])
        return passkey_error("password_required", "password is required",
                             400, http_status);
    if (!g_password_verify)
        return passkey_error("password_verifier_unavailable",
                             "password verification is unavailable", 503, http_status);
    if (!g_password_verify(username, password))
        return passkey_error("password_invalid", "password verification failed",
                             401, http_status);
    if (passkey_credential_hex_from_body(payload, cred_hex, sizeof(cred_hex)) != 0)
        return passkey_error("credential_id_invalid", "credential id is required",
                             400, http_status);
    memset(&cred, 0, sizeof(cred));
    if (passkey_credential_load(cred_hex, &cred) != 0 ||
        strcmp(cred.username, username)) {
        passkey_credential_free(&cred);
        return passkey_error("credential_not_found", "credential was not found",
                             404, http_status);
    }
    passkey_credential_free(&cred);
    if (passkey_credential_delete_file(cred_hex) != 0)
        return passkey_error("credential_delete_failed", "could not delete credential",
                             500, http_status);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "deleted", json_object_new_boolean(1));
    if (http_status) *http_status = 200;
    return resp;
}

/* POST /api/v1/passkey/rename */
struct json_object *webd_passkey_rename(
    struct json_object *body, const char *username, int *http_status)
{
    struct json_object *payload = passkey_body_payload(body);
    const char *friendly_name = passkey_json_str(payload, "friendly_name");
    char cred_hex[WEBD_PASSKEY_CREDENTIAL_ID_MAX * 2 + 1];
    struct webd_passkey_credential cred;
    struct json_object *resp;

    if (!friendly_name)
        friendly_name = passkey_json_str(payload, "name");
    if (!friendly_name)
        friendly_name = passkey_json_str(payload, "display_name");
    if (!username || !username[0] ||
        !passkey_string_valid(friendly_name, WEBD_PASSKEY_FRIENDLY_NAME_MAX))
        return passkey_error("friendly_name_invalid",
                             "friendly_name must be 1-64 characters", 400,
                             http_status);
    if (passkey_credential_hex_from_body(payload, cred_hex, sizeof(cred_hex)) != 0)
        return passkey_error("credential_id_invalid", "credential id is required",
                             400, http_status);
    memset(&cred, 0, sizeof(cred));
    if (passkey_credential_load(cred_hex, &cred) != 0 ||
        strcmp(cred.username, username)) {
        passkey_credential_free(&cred);
        return passkey_error("credential_not_found", "credential was not found",
                             404, http_status);
    }
    snprintf(cred.friendly_name, sizeof(cred.friendly_name), "%s", friendly_name);
    if (passkey_credential_save(&cred) != 0) {
        passkey_credential_free(&cred);
        return passkey_error("credential_update_failed", "could not rename credential",
                             500, http_status);
    }
    passkey_credential_free(&cred);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "friendly_name",
                           json_object_new_string(friendly_name));
    if (http_status) *http_status = 200;
    return resp;
}
