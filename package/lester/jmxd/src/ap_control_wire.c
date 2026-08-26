// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ap_control_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#define AP_JSON_DEPTH_MAX 32U
#define AP_JSON_KEYS_MAX 4096U

struct ap_json_key {
    unsigned int object_id;
    size_t length;
    unsigned char *value;
};

struct ap_json_scan {
    unsigned int depth;
    unsigned int object_depth[AP_JSON_DEPTH_MAX];
    unsigned int object_id[AP_JSON_DEPTH_MAX];
    unsigned int object_count;
    unsigned int next_object_id;
    struct ap_json_key *keys;
    unsigned int key_count;
    unsigned int key_capacity;
};

static int64_t ap_wire_now_ms(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int ap_wire_wait(SSL *ssl, int ssl_error, int64_t deadline)
{
    struct pollfd descriptor;
    int64_t now;
    int timeout;
    int result;

    if (!ssl || (ssl_error != SSL_ERROR_WANT_READ &&
                 ssl_error != SSL_ERROR_WANT_WRITE))
        return AP_CONTROL_WIRE_ERROR;
    descriptor.fd = SSL_get_fd(ssl);
    descriptor.events = ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
    descriptor.revents = 0;
    if (descriptor.fd < 0 || (now = ap_wire_now_ms()) < 0)
        return AP_CONTROL_WIRE_ERROR;
    if (now >= deadline)
        return AP_CONTROL_WIRE_TIMEOUT;
    timeout = deadline - now > INT_MAX ? INT_MAX : (int)(deadline - now);
    do {
        result = poll(&descriptor, 1, timeout);
    } while (result < 0 && errno == EINTR);
    if (result == 0)
        return AP_CONTROL_WIRE_TIMEOUT;
    if (result < 0 || (descriptor.revents & (POLLERR | POLLNVAL)))
        return AP_CONTROL_WIRE_ERROR;
    if (descriptor.revents & POLLHUP)
        return AP_CONTROL_WIRE_CLOSED;
    return AP_CONTROL_WIRE_OK;
}

static int ap_wire_transfer(SSL *ssl, unsigned char *data, size_t length,
                            int writing, int timeout_ms)
{
    int64_t now = ap_wire_now_ms();
    int64_t deadline;
    size_t offset = 0;

    if (!ssl || !data || length == 0 || timeout_ms <= 0 || now < 0 ||
        INT64_MAX - now < timeout_ms)
        return AP_CONTROL_WIRE_ERROR;
    deadline = now + timeout_ms;
    while (offset < length) {
        int chunk = length - offset > INT_MAX ? INT_MAX : (int)(length - offset);
        int count = writing ? SSL_write(ssl, data + offset, chunk) :
                              SSL_read(ssl, data + offset, chunk);

        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        switch (SSL_get_error(ssl, count)) {
        case SSL_ERROR_ZERO_RETURN:
            return AP_CONTROL_WIRE_CLOSED;
        case SSL_ERROR_WANT_READ:
            count = ap_wire_wait(ssl, SSL_ERROR_WANT_READ, deadline);
            break;
        case SSL_ERROR_WANT_WRITE:
            count = ap_wire_wait(ssl, SSL_ERROR_WANT_WRITE, deadline);
            break;
        default:
            return AP_CONTROL_WIRE_ERROR;
        }
        if (count != AP_CONTROL_WIRE_OK)
            return count;
    }
    return AP_CONTROL_WIRE_OK;
}

static int ap_json_hex(unsigned char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

static int ap_json_utf8_append(unsigned char *out, size_t capacity,
                               size_t *length, uint32_t codepoint)
{
    unsigned char encoded[4];
    size_t count;

    if (!out || !length || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff))
        return -1;
    if (codepoint <= 0x7f) {
        encoded[0] = (unsigned char)codepoint;
        count = 1;
    } else if (codepoint <= 0x7ff) {
        encoded[0] = 0xc0 | (unsigned char)(codepoint >> 6);
        encoded[1] = 0x80 | (unsigned char)(codepoint & 0x3f);
        count = 2;
    } else if (codepoint <= 0xffff) {
        encoded[0] = 0xe0 | (unsigned char)(codepoint >> 12);
        encoded[1] = 0x80 | (unsigned char)((codepoint >> 6) & 0x3f);
        encoded[2] = 0x80 | (unsigned char)(codepoint & 0x3f);
        count = 3;
    } else {
        encoded[0] = 0xf0 | (unsigned char)(codepoint >> 18);
        encoded[1] = 0x80 | (unsigned char)((codepoint >> 12) & 0x3f);
        encoded[2] = 0x80 | (unsigned char)((codepoint >> 6) & 0x3f);
        encoded[3] = 0x80 | (unsigned char)(codepoint & 0x3f);
        count = 4;
    }
    if (*length > capacity || count > capacity - *length)
        return -1;
    memcpy(out + *length, encoded, count);
    *length += count;
    return 0;
}

static int ap_json_string_decode(const unsigned char *data, size_t length,
                                 size_t *offset, unsigned char **out,
                                 size_t *out_length)
{
    unsigned char *decoded;
    size_t used = 0;
    size_t i;

    if (!data || !offset || !out || !out_length || *offset >= length ||
        data[*offset] != '"' || !(decoded = malloc(length - *offset + 1)))
        return -1;
    i = *offset + 1;
    while (i < length) {
        unsigned char value = data[i++];

        if (value == '"') {
            decoded[used] = '\0';
            *offset = i;
            *out = decoded;
            *out_length = used;
            return 0;
        }
        if (value < 0x20)
            goto fail;
        if (value != '\\') {
            decoded[used++] = value;
            continue;
        }
        if (i >= length)
            goto fail;
        value = data[i++];
        if (value == '"' || value == '\\' || value == '/')
            decoded[used++] = value;
        else if (value == 'b')
            decoded[used++] = '\b';
        else if (value == 'f')
            decoded[used++] = '\f';
        else if (value == 'n')
            decoded[used++] = '\n';
        else if (value == 'r')
            decoded[used++] = '\r';
        else if (value == 't')
            decoded[used++] = '\t';
        else if (value == 'u') {
            uint32_t codepoint = 0;
            int digit;
            size_t j;

            if (length - i < 4)
                goto fail;
            for (j = 0; j < 4; j++) {
                if ((digit = ap_json_hex(data[i + j])) < 0)
                    goto fail;
                codepoint = (codepoint << 4) | (uint32_t)digit;
            }
            i += 4;
            if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                uint32_t low = 0;

                if (length - i < 6 || data[i] != '\\' || data[i + 1] != 'u')
                    goto fail;
                i += 2;
                for (j = 0; j < 4; j++) {
                    if ((digit = ap_json_hex(data[i + j])) < 0)
                        goto fail;
                    low = (low << 4) | (uint32_t)digit;
                }
                i += 4;
                if (low < 0xdc00 || low > 0xdfff)
                    goto fail;
                codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
                    (low - 0xdc00);
            }
            if (ap_json_utf8_append(decoded, length - *offset, &used,
                                    codepoint) != 0)
                goto fail;
        } else {
            goto fail;
        }
    }
fail:
    OPENSSL_cleanse(decoded, length - *offset + 1);
    free(decoded);
    return -1;
}

static int ap_json_is_object_key(const unsigned char *data, size_t length,
                                 size_t after_string)
{
    size_t i = after_string;

    while (i < length && (data[i] == ' ' || data[i] == '\t' ||
                          data[i] == '\r' || data[i] == '\n'))
        i++;
    return i < length && data[i] == ':';
}

static int ap_json_key_add(struct ap_json_scan *scan, unsigned int object_id,
                           unsigned char *value, size_t length)
{
    unsigned int i;

    if (!scan || !value || scan->key_count >= scan->key_capacity)
        return AP_CONTROL_WIRE_INVALID_JSON;
    for (i = 0; i < scan->key_count; i++)
        if (scan->keys[i].object_id == object_id &&
            scan->keys[i].length == length &&
            CRYPTO_memcmp(scan->keys[i].value, value, length) == 0)
            return AP_CONTROL_WIRE_DUPLICATE_KEY;
    scan->keys[scan->key_count].object_id = object_id;
    scan->keys[scan->key_count].length = length;
    scan->keys[scan->key_count++].value = value;
    return AP_CONTROL_WIRE_OK;
}

static void ap_json_scan_free(struct ap_json_scan *scan)
{
    unsigned int i;

    if (!scan)
        return;
    for (i = 0; i < scan->key_count; i++) {
        OPENSSL_cleanse(scan->keys[i].value, scan->keys[i].length);
        free(scan->keys[i].value);
    }
    free(scan->keys);
    memset(scan, 0, sizeof(*scan));
}

static int ap_json_duplicate_scan(const unsigned char *data, size_t length)
{
    struct ap_json_scan scan;
    size_t i = 0;
    int result = AP_CONTROL_WIRE_OK;

    memset(&scan, 0, sizeof(scan));
    scan.key_capacity = (unsigned int)(length / 4U + 1U);
    if (scan.key_capacity > AP_JSON_KEYS_MAX)
        scan.key_capacity = AP_JSON_KEYS_MAX;
    scan.keys = calloc(scan.key_capacity, sizeof(*scan.keys));
    if (!scan.keys)
        return AP_CONTROL_WIRE_ERROR;
    while (i < length) {
        if (data[i] == '{') {
            if (scan.depth >= AP_JSON_DEPTH_MAX ||
                scan.object_count >= AP_JSON_DEPTH_MAX) {
                result = AP_CONTROL_WIRE_INVALID_JSON;
                break;
            }
            scan.depth++;
            scan.object_depth[scan.object_count++] = scan.depth;
            scan.object_id[scan.object_count - 1] = ++scan.next_object_id;
            i++;
        } else if (data[i] == '[') {
            if (scan.depth >= AP_JSON_DEPTH_MAX) {
                result = AP_CONTROL_WIRE_INVALID_JSON;
                break;
            }
            scan.depth++;
            i++;
        } else if (data[i] == '}' || data[i] == ']') {
            if (scan.depth == 0) {
                result = AP_CONTROL_WIRE_INVALID_JSON;
                break;
            }
            if (data[i] == '}' && scan.object_count > 0 &&
                scan.object_depth[scan.object_count - 1] == scan.depth)
                scan.object_count--;
            scan.depth--;
            i++;
        } else if (data[i] == '"') {
            unsigned char *value = NULL;
            size_t value_length = 0;
            size_t begin = i;

            if (ap_json_string_decode(data, length, &i, &value,
                                      &value_length) != 0) {
                result = AP_CONTROL_WIRE_INVALID_JSON;
                break;
            }
            if (scan.object_count > 0 &&
                scan.object_depth[scan.object_count - 1] == scan.depth &&
                ap_json_is_object_key(data, length, i)) {
                result = ap_json_key_add(
                    &scan, scan.object_id[scan.object_count - 1], value,
                                         value_length);
                if (result != AP_CONTROL_WIRE_OK) {
                    OPENSSL_cleanse(value, value_length);
                    free(value);
                    break;
                }
                value = NULL;
            }
            if (value) {
                OPENSSL_cleanse(value, length - begin + 1);
                free(value);
            }
        } else {
            i++;
        }
    }
    ap_json_scan_free(&scan);
    return result;
}

int ap_control_json_parse_strict(const unsigned char *data, size_t length,
                                 struct json_object **out)
{
    struct json_tokener *tokener = NULL;
    struct json_object *object = NULL;
    enum json_tokener_error error;
    int result;

    if (!data || !out || length == 0 || length > AP_CONTROL_FRAME_MAX ||
        length > INT_MAX || memchr(data, '\0', length))
        return AP_CONTROL_WIRE_INVALID_JSON;
    *out = NULL;
    result = ap_json_duplicate_scan(data, length);
    if (result != AP_CONTROL_WIRE_OK)
        return result;
    tokener = json_tokener_new_ex(AP_JSON_DEPTH_MAX);
    if (!tokener)
        return AP_CONTROL_WIRE_ERROR;
#ifdef JSON_TOKENER_VALIDATE_UTF8
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT |
                           JSON_TOKENER_VALIDATE_UTF8);
#else
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT);
#endif
    object = json_tokener_parse_ex(tokener, (const char *)data, (int)length);
    error = json_tokener_get_error(tokener);
    if (error != json_tokener_success || !object ||
        json_tokener_get_parse_end(tokener) != length) {
        json_object_put(object);
        json_tokener_free(tokener);
        return AP_CONTROL_WIRE_INVALID_JSON;
    }
    json_tokener_free(tokener);
    *out = object;
    return AP_CONTROL_WIRE_OK;
}

static int ap_json_name_in(const char *name, const char *const *items,
                           size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        if (items[i] && strcmp(name, items[i]) == 0)
            return 1;
    return 0;
}

int ap_control_json_object_exact(
    struct json_object *object, const char *const *allowed,
    size_t allowed_count, const char *const *required,
    size_t required_count)
{
    size_t i;

    if (!object || !json_object_is_type(object, json_type_object) ||
        (!allowed && allowed_count) || (!required && required_count))
        return AP_CONTROL_WIRE_INVALID_FIELDS;
    json_object_object_foreach(object, name, value) {
        (void)value;
        if (!ap_json_name_in(name, allowed, allowed_count))
            return AP_CONTROL_WIRE_INVALID_FIELDS;
    }
    for (i = 0; i < required_count; i++) {
        struct json_object *value = NULL;

        if (!required[i] ||
            !json_object_object_get_ex(object, required[i], &value) || !value)
            return AP_CONTROL_WIRE_INVALID_FIELDS;
    }
    return AP_CONTROL_WIRE_OK;
}

int ap_control_frame_encode(struct json_object *object,
                            unsigned char **out, size_t *out_length)
{
    const char *json;
    size_t length;
    unsigned char *frame;

    if (!object || !out || !out_length ||
        !(json = json_object_to_json_string_length(
              object, JSON_C_TO_STRING_PLAIN, &length)) ||
        length == 0 || length > AP_CONTROL_FRAME_MAX ||
        !(frame = malloc(length + 4)))
        return AP_CONTROL_WIRE_ERROR;
    frame[0] = (unsigned char)(length >> 24);
    frame[1] = (unsigned char)(length >> 16);
    frame[2] = (unsigned char)(length >> 8);
    frame[3] = (unsigned char)length;
    memcpy(frame + 4, json, length);
    *out = frame;
    *out_length = length + 4;
    return AP_CONTROL_WIRE_OK;
}

int ap_control_ssl_read_json(SSL *ssl, int timeout_ms,
                             struct json_object **out)
{
    unsigned char header[4];
    unsigned char *payload = NULL;
    uint32_t length;
    int result;

    if (!out)
        return AP_CONTROL_WIRE_ERROR;
    *out = NULL;
    result = ap_wire_transfer(ssl, header, sizeof(header), 0, timeout_ms);
    if (result != AP_CONTROL_WIRE_OK)
        return result;
    length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
             ((uint32_t)header[2] << 8) | header[3];
    if (length == 0 || length > AP_CONTROL_FRAME_MAX)
        return AP_CONTROL_WIRE_OVERSIZED;
    payload = malloc(length);
    if (!payload)
        return AP_CONTROL_WIRE_ERROR;
    result = ap_wire_transfer(ssl, payload, length, 0, timeout_ms);
    if (result == AP_CONTROL_WIRE_OK)
        result = ap_control_json_parse_strict(payload, length, out);
    OPENSSL_cleanse(payload, length);
    free(payload);
    return result;
}

int ap_control_ssl_write_json(SSL *ssl, int timeout_ms,
                              struct json_object *object)
{
    unsigned char *frame = NULL;
    size_t frame_length = 0;
    int result;

    result = ap_control_frame_encode(object, &frame, &frame_length);
    if (result == AP_CONTROL_WIRE_OK)
        result = ap_wire_transfer(ssl, frame, frame_length, 1, timeout_ms);
    if (frame) {
        OPENSSL_cleanse(frame, frame_length);
        free(frame);
    }
    return result;
}

int ap_control_ssl_handshake(SSL *ssl, int server, int timeout_ms)
{
    int64_t now = ap_wire_now_ms();
    int64_t deadline;

    if (!ssl || timeout_ms <= 0 || now < 0 || INT64_MAX - now < timeout_ms)
        return AP_CONTROL_WIRE_ERROR;
    deadline = now + timeout_ms;
    for (;;) {
        int count = server ? SSL_accept(ssl) : SSL_connect(ssl);
        int error;

        if (count == 1)
            return AP_CONTROL_WIRE_OK;
        error = SSL_get_error(ssl, count);
        if (error == SSL_ERROR_ZERO_RETURN)
            return AP_CONTROL_WIRE_CLOSED;
        count = ap_wire_wait(ssl, error, deadline);
        if (count != AP_CONTROL_WIRE_OK)
            return count;
    }
}

int ap_control_ssl_selected_alpn(SSL *ssl)
{
    return ap_control_ssl_selected_alpn_version(ssl) > 0;
}

int ap_control_ssl_selected_alpn_version(SSL *ssl)
{
    const unsigned char *selected = NULL;
    unsigned int length = 0;

    if (!ssl)
        return 0;
    SSL_get0_alpn_selected(ssl, &selected, &length);
    if (selected && length == sizeof(AP_CONTROL_ALPN_V3) - 1 &&
        CRYPTO_memcmp(selected, AP_CONTROL_ALPN_V3, length) == 0)
        return 3;
    if (selected && length == sizeof(AP_CONTROL_ALPN_V2) - 1 &&
        CRYPTO_memcmp(selected, AP_CONTROL_ALPN_V2, length) == 0)
        return 2;
    if (selected && length == sizeof(AP_CONTROL_ALPN_V1) - 1 &&
        CRYPTO_memcmp(selected, AP_CONTROL_ALPN_V1, length) == 0)
        return 1;
    return 0;
}

int ap_control_hex_encode(const unsigned char *data, size_t data_length,
                          char *out, size_t out_size)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if ((!data && data_length) || !out || data_length > (SIZE_MAX - 1) / 2 ||
        out_size < data_length * 2 + 1)
        return AP_CONTROL_WIRE_ERROR;
    for (i = 0; i < data_length; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[data_length * 2] = '\0';
    return AP_CONTROL_WIRE_OK;
}

static int ap_control_hex_value(unsigned char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    return -1;
}

int ap_control_hex_decode(const char *text, unsigned char *out,
                          size_t out_size, size_t *out_length)
{
    size_t length;
    size_t i;

    if (!text || !out || !out_length || (length = strlen(text)) == 0 ||
        (length & 1U) != 0 || length / 2 > out_size)
        return AP_CONTROL_WIRE_INVALID_FIELDS;
    for (i = 0; i < length / 2; i++) {
        int high = ap_control_hex_value((unsigned char)text[i * 2]);
        int low = ap_control_hex_value((unsigned char)text[i * 2 + 1]);

        if (high < 0 || low < 0) {
            OPENSSL_cleanse(out, out_size);
            return AP_CONTROL_WIRE_INVALID_FIELDS;
        }
        out[i] = (unsigned char)((high << 4) | low);
    }
    *out_length = length / 2;
    return AP_CONTROL_WIRE_OK;
}

int ap_control_json_get_string(struct json_object *object, const char *name,
                               const char **out, size_t minimum,
                               size_t maximum)
{
    struct json_object *value = NULL;
    const char *text_value;
    size_t length;

    if (!object || !name || !out || minimum > maximum ||
        !json_object_object_get_ex(object, name, &value) || !value ||
        !json_object_is_type(value, json_type_string) ||
        !(text_value = json_object_get_string(value)) ||
        (length = (size_t)json_object_get_string_len(value)) < minimum ||
        length > maximum || strlen(text_value) != length)
        return AP_CONTROL_WIRE_INVALID_FIELDS;
    *out = text_value;
    return AP_CONTROL_WIRE_OK;
}

int ap_control_json_get_int64(struct json_object *object, const char *name,
                              int64_t minimum, int64_t maximum,
                              int64_t *out)
{
    struct json_object *value = NULL;
    int64_t number;

    if (!object || !name || !out || minimum > maximum ||
        !json_object_object_get_ex(object, name, &value) || !value ||
        !json_object_is_type(value, json_type_int) ||
        (number = json_object_get_int64(value)) < minimum || number > maximum)
        return AP_CONTROL_WIRE_INVALID_FIELDS;
    *out = number;
    return AP_CONTROL_WIRE_OK;
}

int ap_control_uuid4(char out[37])
{
    static const char digits[] = "0123456789abcdef";
    unsigned char raw[16];
    size_t input = 0;
    size_t output = 0;

    if (!out || RAND_bytes(raw, sizeof(raw)) != 1)
        return AP_CONTROL_WIRE_ERROR;
    raw[6] = (unsigned char)((raw[6] & 0x0f) | 0x40);
    raw[8] = (unsigned char)((raw[8] & 0x3f) | 0x80);
    while (input < sizeof(raw)) {
        if (output == 8 || output == 13 || output == 18 || output == 23)
            out[output++] = '-';
        out[output++] = digits[raw[input] >> 4];
        out[output++] = digits[raw[input] & 0x0f];
        input++;
    }
    out[output] = '\0';
    OPENSSL_cleanse(raw, sizeof(raw));
    return AP_CONTROL_WIRE_OK;
}

static const char *const ap_control_capability_names[] = {
    "config_executor", "validate", "stage", "apply", "readback", "rollback"
};

int ap_control_capabilities_add(struct json_object *object,
                                const struct ap_control_capabilities *caps)
{
    const int values[AP_CONTROL_CAPABILITY_COUNT] = {
        caps ? caps->config_executor : 0, caps ? caps->validate : 0,
        caps ? caps->stage : 0, caps ? caps->apply : 0,
        caps ? caps->readback : 0, caps ? caps->rollback : 0
    };
    size_t i;

    struct json_object *nested;

    if (!object || !caps || !(nested = json_object_new_object()))
        return AP_CONTROL_WIRE_INVALID_FIELDS;
    for (i = 0; i < AP_CONTROL_CAPABILITY_COUNT; i++)
        json_object_object_add(nested, ap_control_capability_names[i],
                               json_object_new_boolean(values[i] != 0));
    json_object_object_add(object, "capabilities", nested);
    return AP_CONTROL_WIRE_OK;
}

int ap_control_capabilities_parse(struct json_object *object,
                                  struct ap_control_capabilities *caps)
{
    int *values[AP_CONTROL_CAPABILITY_COUNT];
    size_t i;

    if (!object || !caps ||
        !json_object_is_type(object, json_type_object))
        return AP_CONTROL_WIRE_INVALID_FIELDS;
    values[0] = &caps->config_executor; values[1] = &caps->validate;
    values[2] = &caps->stage; values[3] = &caps->apply;
    values[4] = &caps->readback; values[5] = &caps->rollback;
    memset(caps, 0, sizeof(*caps));
    for (i = 0; i < AP_CONTROL_CAPABILITY_COUNT; i++) {
        struct json_object *value = NULL;

        if (!json_object_object_get_ex(object, ap_control_capability_names[i],
                                       &value) || !value ||
            !json_object_is_type(value, json_type_boolean))
            return AP_CONTROL_WIRE_INVALID_FIELDS;
        *values[i] = json_object_get_boolean(value) ? 1 : 0;
    }
    return ap_control_json_object_exact(object, ap_control_capability_names,
        AP_CONTROL_CAPABILITY_COUNT, ap_control_capability_names,
        AP_CONTROL_CAPABILITY_COUNT);
}

int ap_control_capabilities_all_true(
    const struct ap_control_capabilities *caps)
{
    return caps && caps->config_executor && caps->validate && caps->stage &&
           caps->apply && caps->readback && caps->rollback;
}
