// SPDX-License-Identifier: GPL-2.0-or-later
#include "ap_control_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

static void expect_parse(const char *json, int expected)
{
    struct json_object *object = NULL;
    int result = ap_control_json_parse_strict(
        (const unsigned char *)json, strlen(json), &object);

    assert(result == expected);
    json_object_put(object);
}

int main(void)
{
    static const char *const allowed[] = {"protocol", "kind", "payload"};
    static const char *const required[] = {"protocol", "kind"};
    struct json_object *object = NULL;
    unsigned char *frame = NULL;
    size_t frame_length = 0;
    uint32_t length;
    unsigned char binary[32];
    size_t binary_length = 0;
    char encoded[65];
    char uuid[37];
    const char *protocol = NULL;
    int64_t integer = 0;
    char many_keys[8192];
    size_t many_used = 0;
    unsigned int i;

    expect_parse("{\"protocol\":\"ap-control.v1\",\"kind\":\"hello\",\"payload\":{}}",
                 AP_CONTROL_WIRE_OK);
    expect_parse("{\"kind\":1,\"kind\":2}",
                 AP_CONTROL_WIRE_DUPLICATE_KEY);
    expect_parse("{\"kind\":1,\"payload\":{\"x\":1,\"x\":2}}",
                 AP_CONTROL_WIRE_DUPLICATE_KEY);
    expect_parse("{\"left\":{\"x\":1},\"right\":{\"x\":2}}",
                 AP_CONTROL_WIRE_OK);
    expect_parse("{\"\\u006b\\u0069nd\":1,\"kind\":2}",
                 AP_CONTROL_WIRE_DUPLICATE_KEY);
    expect_parse("{\"kind\":1} trailing", AP_CONTROL_WIRE_INVALID_JSON);
    expect_parse("[1,2,]", AP_CONTROL_WIRE_INVALID_JSON);
    expect_parse("{\"bad\":\"\\ud800\"}", AP_CONTROL_WIRE_INVALID_JSON);
    many_keys[many_used++] = '{';
    for (i = 0; i < 320; i++) {
        int written = snprintf(many_keys + many_used,
                               sizeof(many_keys) - many_used,
                               "%s\"key%u\":%u", i ? "," : "", i, i);

        assert(written > 0 && (size_t)written < sizeof(many_keys) - many_used);
        many_used += (size_t)written;
    }
    many_keys[many_used++] = '}';
    many_keys[many_used] = '\0';
    expect_parse(many_keys, AP_CONTROL_WIRE_OK);
    many_used--;
    assert((size_t)snprintf(many_keys + many_used,
                            sizeof(many_keys) - many_used,
                            ",\"key319\":0}") < sizeof(many_keys) - many_used);
    expect_parse(many_keys, AP_CONTROL_WIRE_DUPLICATE_KEY);
    assert(ap_control_json_parse_strict((const unsigned char *)"{}\0x", 4,
                                        &object) ==
           AP_CONTROL_WIRE_INVALID_JSON);
    assert(ap_control_json_parse_strict(
        (const unsigned char *)"{\"protocol\":\"ap-control.v1\",\"kind\":\"hello\"}",
        strlen("{\"protocol\":\"ap-control.v1\",\"kind\":\"hello\"}"),
        &object) == AP_CONTROL_WIRE_OK);
    assert(ap_control_json_object_exact(
        object, allowed, sizeof(allowed) / sizeof(allowed[0]), required,
        sizeof(required) / sizeof(required[0])) == AP_CONTROL_WIRE_OK);
    json_object_object_add(object, "unknown", json_object_new_int(1));
    assert(ap_control_json_object_exact(
        object, allowed, sizeof(allowed) / sizeof(allowed[0]), required,
        sizeof(required) / sizeof(required[0])) ==
           AP_CONTROL_WIRE_INVALID_FIELDS);
    json_object_object_del(object, "unknown");
    json_object_object_add(object, "number", json_object_new_int64(42));
    assert(ap_control_json_get_string(object, "protocol", &protocol, 1, 32) ==
           AP_CONTROL_WIRE_OK && strcmp(protocol, "ap-control.v1") == 0);
    assert(ap_control_json_get_int64(object, "number", 1, 100, &integer) ==
           AP_CONTROL_WIRE_OK && integer == 42);
    json_object_object_del(object, "number");
    memset(binary, 0xa5, sizeof(binary));
    assert(ap_control_hex_encode(binary, sizeof(binary), encoded,
                                 sizeof(encoded)) == AP_CONTROL_WIRE_OK);
    memset(binary, 0, sizeof(binary));
    assert(ap_control_hex_decode(encoded, binary, sizeof(binary),
                                 &binary_length) == AP_CONTROL_WIRE_OK &&
           binary_length == sizeof(binary) && binary[0] == 0xa5 &&
           binary[31] == 0xa5);
    assert(ap_control_hex_decode("AA", binary, sizeof(binary),
                                 &binary_length) ==
           AP_CONTROL_WIRE_INVALID_FIELDS);
    assert(ap_control_uuid4(uuid) == AP_CONTROL_WIRE_OK && strlen(uuid) == 36 &&
           uuid[14] == '4' && strchr("89ab", uuid[19]) != NULL);
    assert(ap_control_frame_encode(object, &frame, &frame_length) ==
           AP_CONTROL_WIRE_OK);
    length = ((uint32_t)frame[0] << 24) | ((uint32_t)frame[1] << 16) |
             ((uint32_t)frame[2] << 8) | frame[3];
    assert(length == frame_length - 4 && length <= AP_CONTROL_FRAME_MAX);
    OPENSSL_cleanse(frame, frame_length);
    free(frame);
    json_object_put(object);
    puts("ok: AP control framing, strict JSON, duplicate keys, and field gates");
    return 0;
}
