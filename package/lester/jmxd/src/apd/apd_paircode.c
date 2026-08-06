// SPDX-License-Identifier: GPL-2.0-or-later
/* Pasteable pairing code encode/decode. See apd_paircode.h for the format. */
#include "apd_paircode.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/*
 * Only OpenSSL's cleanse is needed here. Pulling in apd_internal.h would
 * drag ubus, sqlite and uci into apdctl, which has no business linking the
 * daemon's dependencies just to parse a code.
 */
#include <openssl/crypto.h>

#define APD_PAIRCODE_SCHEMA 1
#define APD_PAIRCODE_PAYLOAD_MAX 320
#define APD_PAIRCODE_CRC_CHARS 7

/* Field tags. Unknown tags are skipped so an older AP can still read a
 * newer code, provided the schema major still matches. */
enum {
    APD_PC_TAG_END = 0,
    APD_PC_TAG_AP_ID = 1,
    APD_PC_TAG_KEY_ID = 2,
    APD_PC_TAG_MAC = 3,
    APD_PC_TAG_MODEL = 4,
    APD_PC_TAG_BOARD = 5,
    APD_PC_TAG_MGMT_IP = 6,
    APD_PC_TAG_MGMT_PORT = 7,
    APD_PC_TAG_CTRL_HOST = 8,
    APD_PC_TAG_CTRL_PORT = 9,
    APD_PC_TAG_CTRL_ID = 10,
    APD_PC_TAG_TOKEN_ID = 11,
    APD_PC_TAG_TOKEN = 12,
    APD_PC_TAG_SITE_ID = 13,
    /*
     * Byte-packed variants. Base32 of an ASCII hex string wastes about half
     * the space, which is the difference between a scannable QR and a
     * text-only code, so identifiers with a known binary form get packed.
     */
    APD_PC_TAG_AP_ID_RAW = 14,     /* 16 raw bytes of the UUID */
    APD_PC_TAG_KEY_ID_RAW = 15,    /* raw sha256 digest bytes */
    APD_PC_TAG_MAC_RAW = 16,       /* 6 raw bytes */
    APD_PC_TAG_IPV4_RAW = 17,      /* 4 raw bytes */
};

static const char apd_pc_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const char *apd_paircode_strerror(int result)
{
    switch (result) {
    case APD_PAIRCODE_OK:            return "ok";
    case APD_PAIRCODE_ERR_ARG:       return "invalid argument";
    case APD_PAIRCODE_ERR_PREFIX:    return "not a DreamingWrt pairing code";
    case APD_PAIRCODE_ERR_FORMAT:    return "malformed pairing code";
    case APD_PAIRCODE_ERR_CHECKSUM:  return "checksum mismatch (incomplete paste?)";
    case APD_PAIRCODE_ERR_SCHEMA:    return "unsupported pairing code version";
    case APD_PAIRCODE_ERR_FIELD:     return "invalid field in pairing code";
    case APD_PAIRCODE_ERR_SPACE:     return "buffer too small";
    default:                         return "unknown error";
    }
}

/* --- CRC-32 (IEEE 802.3, reflected) --- */

static uint32_t apd_pc_crc32(const unsigned char *data, size_t len)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    int k;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}

/* --- base32, RFC 4648 alphabet, no padding --- */

static int apd_pc_b32_encode(const unsigned char *in, size_t in_len,
                             char *out, size_t out_size)
{
    uint32_t buffer = 0;
    int bits = 0;
    size_t i;
    size_t o = 0;

    if (!in || !out || !out_size)
        return APD_PAIRCODE_ERR_ARG;
    for (i = 0; i < in_len; i++) {
        buffer = (buffer << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            if (o + 1 >= out_size)
                return APD_PAIRCODE_ERR_SPACE;
            out[o++] = apd_pc_alphabet[(buffer >> (bits - 5)) & 0x1f];
            bits -= 5;
        }
    }
    if (bits > 0) {
        if (o + 1 >= out_size)
            return APD_PAIRCODE_ERR_SPACE;
        out[o++] = apd_pc_alphabet[(buffer << (5 - bits)) & 0x1f];
    }
    out[o] = '\0';
    return APD_PAIRCODE_OK;
}

static int apd_pc_b32_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= '2' && c <= '7')
        return c - '2' + 26;
    return -1;
}

static int apd_pc_b32_decode(const char *in, unsigned char *out,
                             size_t out_size, size_t *written)
{
    uint32_t buffer = 0;
    int bits = 0;
    size_t o = 0;
    const char *p;

    if (!in || !out || !written)
        return APD_PAIRCODE_ERR_ARG;
    for (p = in; *p; p++) {
        int v = apd_pc_b32_value(*p);

        if (v < 0)
            return APD_PAIRCODE_ERR_FORMAT;
        buffer = (buffer << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            if (o >= out_size)
                return APD_PAIRCODE_ERR_SPACE;
            out[o++] = (unsigned char)((buffer >> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    *written = o;
    return APD_PAIRCODE_OK;
}

/* --- payload writer / reader --- */

struct apd_pc_writer {
    unsigned char data[APD_PAIRCODE_PAYLOAD_MAX];
    size_t length;
    int overflow;
};

static void apd_pc_put_byte(struct apd_pc_writer *w, unsigned char value)
{
    if (w->length >= sizeof(w->data)) {
        w->overflow = 1;
        return;
    }
    w->data[w->length++] = value;
}

static void apd_pc_put_string(struct apd_pc_writer *w, int tag,
                              const char *value)
{
    size_t len;

    if (!value || !value[0])
        return;                       /* absent fields are simply omitted */
    len = strlen(value);
    if (len > 255) {
        w->overflow = 1;
        return;
    }
    apd_pc_put_byte(w, (unsigned char)tag);
    apd_pc_put_byte(w, (unsigned char)len);
    while (*value)
        apd_pc_put_byte(w, (unsigned char)*value++);
}

static void apd_pc_put_u16(struct apd_pc_writer *w, int tag, uint16_t value)
{
    if (!value)
        return;
    apd_pc_put_byte(w, (unsigned char)tag);
    apd_pc_put_byte(w, 2);
    apd_pc_put_byte(w, (unsigned char)(value >> 8));
    apd_pc_put_byte(w, (unsigned char)(value & 0xff));
}

static int apd_pc_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
 * Packs a hex string, ignoring the separators UUIDs and MACs carry. Returns
 * the byte count, or -1 when the input is not pure hex once separators are
 * removed.
 */
static int apd_pc_hex_pack(const char *text, unsigned char *out,
                           size_t out_size)
{
    size_t o = 0;
    int high = -1;

    if (!text)
        return -1;
    for (; *text; text++) {
        int v;

        if (*text == '-' || *text == ':')
            continue;
        v = apd_pc_hex_nibble(*text);
        if (v < 0)
            return -1;
        if (high < 0) {
            high = v;
        } else {
            if (o >= out_size)
                return -1;
            out[o++] = (unsigned char)((high << 4) | v);
            high = -1;
        }
    }
    if (high >= 0)
        return -1;               /* odd number of hex digits */
    return (int)o;
}

static void apd_pc_put_bytes(struct apd_pc_writer *w, int tag,
                             const unsigned char *value, size_t len)
{
    size_t i;

    if (!value || !len || len > 255)
        return;
    apd_pc_put_byte(w, (unsigned char)tag);
    apd_pc_put_byte(w, (unsigned char)len);
    for (i = 0; i < len; i++)
        apd_pc_put_byte(w, value[i]);
}

/* Formats packed UUID bytes back into canonical 8-4-4-4-12 form. */
static int apd_pc_uuid_unpack(const unsigned char *value, size_t value_len,
                              char *out, size_t out_size)
{
    static const int groups[] = {4, 2, 2, 2, 6};
    size_t i;
    size_t o = 0;
    size_t index = 0;
    size_t g;

    if (value_len != 16 || out_size < 37)
        return APD_PAIRCODE_ERR_FIELD;
    for (g = 0; g < sizeof(groups) / sizeof(groups[0]); g++) {
        if (g)
            out[o++] = '-';
        for (i = 0; i < (size_t)groups[g]; i++) {
            static const char hex[] = "0123456789abcdef";

            out[o++] = hex[value[index] >> 4];
            out[o++] = hex[value[index] & 15];
            index++;
        }
    }
    out[o] = '\0';
    return APD_PAIRCODE_OK;
}

static int apd_pc_keyid_unpack(const unsigned char *value, size_t value_len,
                               char *out, size_t out_size)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    size_t o = 0;

    if (!value_len || out_size < 7 + value_len * 2 + 1)
        return APD_PAIRCODE_ERR_FIELD;
    memcpy(out, "sha256:", 7);
    o = 7;
    for (i = 0; i < value_len; i++) {
        out[o++] = hex[value[i] >> 4];
        out[o++] = hex[value[i] & 15];
    }
    out[o] = '\0';
    return APD_PAIRCODE_OK;
}

static int apd_pc_mac_unpack(const unsigned char *value, size_t value_len,
                             char *out, size_t out_size)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t i;
    size_t o = 0;

    if (value_len != 6 || out_size < 18)
        return APD_PAIRCODE_ERR_FIELD;
    for (i = 0; i < 6; i++) {
        if (i)
            out[o++] = ':';
        out[o++] = hex[value[i] >> 4];
        out[o++] = hex[value[i] & 15];
    }
    out[o] = '\0';
    return APD_PAIRCODE_OK;
}

/* Packs a dotted-quad into 4 bytes; returns 0 when the text is not IPv4. */
static int apd_pc_ipv4_pack(const char *text, unsigned char *out)
{
    unsigned int a, b, c, d;
    char extra;

    if (!text || sscanf(text, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    out[0] = (unsigned char)a;
    out[1] = (unsigned char)b;
    out[2] = (unsigned char)c;
    out[3] = (unsigned char)d;
    return 1;
}

static int apd_pc_ipv4_unpack(const unsigned char *value, size_t value_len,
                              char *out, size_t out_size)
{
    if (value_len != 4)
        return APD_PAIRCODE_ERR_FIELD;
    if (snprintf(out, out_size, "%u.%u.%u.%u", value[0], value[1], value[2],
                 value[3]) >= (int)out_size)
        return APD_PAIRCODE_ERR_FIELD;
    return APD_PAIRCODE_OK;
}

struct apd_pc_reader {
    const unsigned char *data;
    size_t length;
    size_t offset;
};

static int apd_pc_next(struct apd_pc_reader *r, int *tag,
                       const unsigned char **value, size_t *value_len)
{
    size_t len;

    if (r->offset >= r->length)
        return 0;                     /* clean end of payload */
    if (r->offset + 2 > r->length)
        return -1;
    *tag = r->data[r->offset];
    len = r->data[r->offset + 1];
    if (r->offset + 2 + len > r->length)
        return -1;
    *value = r->data + r->offset + 2;
    *value_len = len;
    r->offset += 2 + len;
    return 1;
}

static int apd_pc_copy(char *dst, size_t dst_size,
                       const unsigned char *value, size_t value_len)
{
    size_t i;

    if (value_len >= dst_size)
        return APD_PAIRCODE_ERR_FIELD;
    for (i = 0; i < value_len; i++) {
        /* printable ASCII only; keeps a hostile code from smuggling
         * control characters into logs or a browser field */
        if (value[i] < 0x20 || value[i] > 0x7e)
            return APD_PAIRCODE_ERR_FIELD;
        dst[i] = (char)value[i];
    }
    dst[value_len] = '\0';
    return APD_PAIRCODE_OK;
}

static int apd_pc_u16(const unsigned char *value, size_t value_len,
                      uint16_t *out)
{
    if (value_len != 2)
        return APD_PAIRCODE_ERR_FIELD;
    *out = (uint16_t)((value[0] << 8) | value[1]);
    return APD_PAIRCODE_OK;
}

/* --- shared framing --- */

static int apd_pc_finish(const char *prefix, const struct apd_pc_writer *w,
                         char *out, size_t out_size)
{
    char body[APD_PAIRCODE_MAX];
    char crc_text[APD_PAIRCODE_CRC_CHARS + 1];
    unsigned char crc_bytes[4];
    uint32_t crc;
    int rc;
    int n;

    if (w->overflow)
        return APD_PAIRCODE_ERR_SPACE;
    rc = apd_pc_b32_encode(w->data, w->length, body, sizeof(body));
    if (rc != APD_PAIRCODE_OK)
        return rc;

    /* CRC covers the payload bytes, so it validates content rather than
     * the particular base32 rendering. */
    crc = apd_pc_crc32(w->data, w->length);
    crc_bytes[0] = (unsigned char)(crc >> 24);
    crc_bytes[1] = (unsigned char)(crc >> 16);
    crc_bytes[2] = (unsigned char)(crc >> 8);
    crc_bytes[3] = (unsigned char)crc;
    rc = apd_pc_b32_encode(crc_bytes, sizeof(crc_bytes), crc_text,
                           sizeof(crc_text));
    if (rc != APD_PAIRCODE_OK)
        return rc;

    n = snprintf(out, out_size, "%s.%s.%s", prefix, body, crc_text);
    if (n < 0 || (size_t)n >= out_size)
        return APD_PAIRCODE_ERR_SPACE;
    return APD_PAIRCODE_OK;
}

static int apd_pc_open(const char *prefix, const char *text,
                       unsigned char *payload, size_t payload_size,
                       size_t *payload_len)
{
    const char *body;
    const char *dot;
    char body_copy[APD_PAIRCODE_MAX];
    char crc_text[APD_PAIRCODE_CRC_CHARS + 1];
    unsigned char crc_bytes[8];
    size_t prefix_len = strlen(prefix);
    size_t body_len;
    size_t crc_len = 0;
    uint32_t crc;
    int rc;

    if (!text || !payload || !payload_len)
        return APD_PAIRCODE_ERR_ARG;
    if (strncmp(text, prefix, prefix_len) != 0 || text[prefix_len] != '.')
        return APD_PAIRCODE_ERR_PREFIX;
    body = text + prefix_len + 1;
    dot = strrchr(body, '.');
    if (!dot || dot == body)
        return APD_PAIRCODE_ERR_FORMAT;
    body_len = (size_t)(dot - body);
    if (body_len >= sizeof(body_copy))
        return APD_PAIRCODE_ERR_FORMAT;
    memcpy(body_copy, body, body_len);
    body_copy[body_len] = '\0';
    if (snprintf(crc_text, sizeof(crc_text), "%s", dot + 1) < 0 ||
        strlen(dot + 1) != APD_PAIRCODE_CRC_CHARS)
        return APD_PAIRCODE_ERR_CHECKSUM;

    rc = apd_pc_b32_decode(body_copy, payload, payload_size, payload_len);
    if (rc != APD_PAIRCODE_OK)
        return rc;
    rc = apd_pc_b32_decode(crc_text, crc_bytes, sizeof(crc_bytes), &crc_len);
    if (rc != APD_PAIRCODE_OK || crc_len < 4)
        return APD_PAIRCODE_ERR_CHECKSUM;

    crc = apd_pc_crc32(payload, *payload_len);
    if (crc_bytes[0] != (unsigned char)(crc >> 24) ||
        crc_bytes[1] != (unsigned char)(crc >> 16) ||
        crc_bytes[2] != (unsigned char)(crc >> 8) ||
        crc_bytes[3] != (unsigned char)crc)
        return APD_PAIRCODE_ERR_CHECKSUM;
    if (*payload_len < 1)
        return APD_PAIRCODE_ERR_FORMAT;
    if (payload[0] != APD_PAIRCODE_SCHEMA)
        return APD_PAIRCODE_ERR_SCHEMA;
    return APD_PAIRCODE_OK;
}

/* --- AP announcement --- */

int apd_paircode_ap_encode(const struct apd_paircode_ap *in,
                           char *out, size_t out_size)
{
    return apd_paircode_ap_encode_form(in, APD_PAIRCODE_FORM_FULL, out,
                                       out_size);
}

int apd_paircode_ap_encode_form(const struct apd_paircode_ap *in,
                                enum apd_paircode_form form,
                                char *out, size_t out_size)
{
    struct apd_pc_writer w;
    unsigned char packed[64];
    int packed_len;

    if (!in || !out)
        return APD_PAIRCODE_ERR_ARG;
    memset(&w, 0, sizeof(w));
    apd_pc_put_byte(&w, APD_PAIRCODE_SCHEMA);

    /* ap_id: 16 packed bytes instead of 36 ASCII characters. */
    packed_len = apd_pc_hex_pack(in->ap_id, packed, sizeof(packed));
    if (packed_len == 16)
        apd_pc_put_bytes(&w, APD_PC_TAG_AP_ID_RAW, packed, 16);
    else
        apd_pc_put_string(&w, APD_PC_TAG_AP_ID, in->ap_id);

    /* key_id: pack the digest, keeping the "sha256:" prefix implicit. */
    if (in->key_id[0]) {
        const char *hex = strchr(in->key_id, ':');

        packed_len = apd_pc_hex_pack(hex ? hex + 1 : in->key_id, packed,
                                     sizeof(packed));
        if (hex && packed_len > 0 &&
            strncmp(in->key_id, "sha256:", 7) == 0)
            apd_pc_put_bytes(&w, APD_PC_TAG_KEY_ID_RAW, packed,
                             (size_t)packed_len);
        else
            apd_pc_put_string(&w, APD_PC_TAG_KEY_ID, in->key_id);
    }

    packed_len = apd_pc_hex_pack(in->mac, packed, sizeof(packed));
    if (packed_len == 6)
        apd_pc_put_bytes(&w, APD_PC_TAG_MAC_RAW, packed, 6);
    else
        apd_pc_put_string(&w, APD_PC_TAG_MAC, in->mac);

    /*
     * Descriptive strings are what push a code past QR range, and the
     * controller can resolve them from ap_id anyway, so the compact form
     * leaves them out.
     */
    if (form == APD_PAIRCODE_FORM_FULL) {
        apd_pc_put_string(&w, APD_PC_TAG_MODEL, in->model);
        apd_pc_put_string(&w, APD_PC_TAG_BOARD, in->board_name);
    }

    if (in->mgmt_ip[0]) {
        if (apd_pc_ipv4_pack(in->mgmt_ip, packed))
            apd_pc_put_bytes(&w, APD_PC_TAG_IPV4_RAW, packed, 4);
        else
            apd_pc_put_string(&w, APD_PC_TAG_MGMT_IP, in->mgmt_ip);
    }
    apd_pc_put_u16(&w, APD_PC_TAG_MGMT_PORT, in->mgmt_port);
    return apd_pc_finish(APD_PAIRCODE_AP_PREFIX, &w, out, out_size);
}

int apd_paircode_ap_decode(const char *text, struct apd_paircode_ap *out)
{
    unsigned char payload[APD_PAIRCODE_PAYLOAD_MAX];
    struct apd_pc_reader r;
    size_t payload_len = 0;
    const unsigned char *value;
    size_t value_len;
    int tag;
    int rc;
    int step;

    if (!out)
        return APD_PAIRCODE_ERR_ARG;
    memset(out, 0, sizeof(*out));
    rc = apd_pc_open(APD_PAIRCODE_AP_PREFIX, text, payload, sizeof(payload),
                     &payload_len);
    if (rc != APD_PAIRCODE_OK)
        return rc;
    out->schema = payload[0];
    r.data = payload;
    r.length = payload_len;
    r.offset = 1;
    while ((step = apd_pc_next(&r, &tag, &value, &value_len)) == 1) {
        switch (tag) {
        case APD_PC_TAG_AP_ID:
            rc = apd_pc_copy(out->ap_id, sizeof(out->ap_id), value, value_len);
            break;
        case APD_PC_TAG_AP_ID_RAW:
            rc = apd_pc_uuid_unpack(value, value_len, out->ap_id,
                                    sizeof(out->ap_id));
            break;
        case APD_PC_TAG_KEY_ID:
            rc = apd_pc_copy(out->key_id, sizeof(out->key_id), value, value_len);
            break;
        case APD_PC_TAG_KEY_ID_RAW:
            rc = apd_pc_keyid_unpack(value, value_len, out->key_id,
                                     sizeof(out->key_id));
            break;
        case APD_PC_TAG_MAC:
            rc = apd_pc_copy(out->mac, sizeof(out->mac), value, value_len);
            break;
        case APD_PC_TAG_MAC_RAW:
            rc = apd_pc_mac_unpack(value, value_len, out->mac,
                                   sizeof(out->mac));
            break;
        case APD_PC_TAG_MODEL:
            rc = apd_pc_copy(out->model, sizeof(out->model), value, value_len);
            break;
        case APD_PC_TAG_BOARD:
            rc = apd_pc_copy(out->board_name, sizeof(out->board_name), value,
                             value_len);
            break;
        case APD_PC_TAG_MGMT_IP:
            rc = apd_pc_copy(out->mgmt_ip, sizeof(out->mgmt_ip), value,
                             value_len);
            break;
        case APD_PC_TAG_IPV4_RAW:
            rc = apd_pc_ipv4_unpack(value, value_len, out->mgmt_ip,
                                    sizeof(out->mgmt_ip));
            break;
        case APD_PC_TAG_MGMT_PORT:
            rc = apd_pc_u16(value, value_len, &out->mgmt_port);
            break;
        default:
            rc = APD_PAIRCODE_OK;     /* forward compatibility */
            break;
        }
        if (rc != APD_PAIRCODE_OK)
            return rc;
    }
    if (step < 0)
        return APD_PAIRCODE_ERR_FORMAT;
    if (!out->ap_id[0])
        return APD_PAIRCODE_ERR_FIELD;
    return APD_PAIRCODE_OK;
}

/* --- controller bootstrap --- */

int apd_paircode_controller_encode(const struct apd_paircode_controller *in,
                                   char *out, size_t out_size)
{
    struct apd_pc_writer w;
    int rc;

    if (!in || !out)
        return APD_PAIRCODE_ERR_ARG;
    memset(&w, 0, sizeof(w));
    apd_pc_put_byte(&w, APD_PAIRCODE_SCHEMA);
    apd_pc_put_string(&w, APD_PC_TAG_CTRL_HOST, in->controller_host);
    apd_pc_put_u16(&w, APD_PC_TAG_CTRL_PORT, in->controller_port);
    apd_pc_put_string(&w, APD_PC_TAG_CTRL_ID, in->controller_id);
    apd_pc_put_string(&w, APD_PC_TAG_TOKEN_ID, in->token_id);
    apd_pc_put_string(&w, APD_PC_TAG_TOKEN, in->token);
    apd_pc_put_string(&w, APD_PC_TAG_SITE_ID, in->site_id);
    rc = apd_pc_finish(APD_PAIRCODE_CT_PREFIX, &w, out, out_size);
    OPENSSL_cleanse(w.data, sizeof(w.data));
    return rc;
}

int apd_paircode_controller_decode(const char *text,
                                   struct apd_paircode_controller *out)
{
    unsigned char payload[APD_PAIRCODE_PAYLOAD_MAX];
    struct apd_pc_reader r;
    size_t payload_len = 0;
    const unsigned char *value;
    size_t value_len;
    int tag;
    int rc;
    int step;

    if (!out)
        return APD_PAIRCODE_ERR_ARG;
    memset(out, 0, sizeof(*out));
    rc = apd_pc_open(APD_PAIRCODE_CT_PREFIX, text, payload, sizeof(payload),
                     &payload_len);
    if (rc != APD_PAIRCODE_OK)
        goto done;
    out->schema = payload[0];
    r.data = payload;
    r.length = payload_len;
    r.offset = 1;
    while ((step = apd_pc_next(&r, &tag, &value, &value_len)) == 1) {
        switch (tag) {
        case APD_PC_TAG_CTRL_HOST:
            rc = apd_pc_copy(out->controller_host,
                             sizeof(out->controller_host), value, value_len);
            break;
        case APD_PC_TAG_CTRL_PORT:
            rc = apd_pc_u16(value, value_len, &out->controller_port);
            break;
        case APD_PC_TAG_CTRL_ID:
            rc = apd_pc_copy(out->controller_id, sizeof(out->controller_id),
                             value, value_len);
            break;
        case APD_PC_TAG_TOKEN_ID:
            rc = apd_pc_copy(out->token_id, sizeof(out->token_id), value,
                             value_len);
            break;
        case APD_PC_TAG_TOKEN:
            rc = apd_pc_copy(out->token, sizeof(out->token), value, value_len);
            break;
        case APD_PC_TAG_SITE_ID:
            rc = apd_pc_copy(out->site_id, sizeof(out->site_id), value,
                             value_len);
            break;
        default:
            rc = APD_PAIRCODE_OK;
            break;
        }
        if (rc != APD_PAIRCODE_OK)
            goto done;
    }
    if (step < 0) {
        rc = APD_PAIRCODE_ERR_FORMAT;
        goto done;
    }
    /* A bootstrap code without host or token cannot start enrollment. */
    if (!out->controller_host[0] || !out->token[0] || !out->token_id[0])
        rc = APD_PAIRCODE_ERR_FIELD;
done:
    OPENSSL_cleanse(payload, sizeof(payload));
    if (rc != APD_PAIRCODE_OK)
        apd_paircode_controller_cleanse(out);
    return rc;
}

size_t apd_paircode_normalize(char *text)
{
    size_t r = 0;
    size_t w = 0;

    if (!text)
        return 0;
    while (text[r]) {
        unsigned char c = (unsigned char)text[r++];

        /* Terminal copies routinely bring along newlines and stray spaces;
         * dropping them is friendlier than rejecting the paste. */
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        text[w++] = (char)toupper(c);
    }
    text[w] = '\0';
    return w;
}

void apd_paircode_fingerprint_short(const char *key_id, char *out,
                                    size_t out_size)
{
    const char *hex;
    size_t i;
    size_t o = 0;
    int group = 0;

    if (!out || !out_size)
        return;
    out[0] = '\0';
    if (!key_id || !key_id[0])
        return;
    /* key_id is "sha256:<hex>"; show the leading 16 hex digits in groups
     * of four, which is what the web UI displays for comparison. */
    hex = strchr(key_id, ':');
    hex = hex ? hex + 1 : key_id;
    for (i = 0; hex[i] && o + 1 < out_size && i < 16; i++) {
        if (i && group == 4) {
            out[o++] = '-';
            group = 0;
            if (o + 1 >= out_size)
                break;
        }
        out[o++] = (char)toupper((unsigned char)hex[i]);
        group++;
    }
    out[o] = '\0';
}

void apd_paircode_controller_cleanse(struct apd_paircode_controller *value)
{
    if (!value)
        return;
    OPENSSL_cleanse(value, sizeof(*value));
}
