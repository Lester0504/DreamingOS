// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AP_CONTROL_WIRE_H
#define DREAMINGWRT_AP_CONTROL_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include <json-c/json.h>
#include <openssl/ssl.h>

#define AP_CONTROL_ALPN_V1 "dreamingwrt-ap/1"
#define AP_CONTROL_ALPN_V2 "dreamingwrt-ap/2"
#define AP_CONTROL_ALPN_V3 "dreamingwrt-ap/3"
#define AP_CONTROL_PROTOCOL_V3 "ap-control.v3"
#define AP_CONTROL_CAPABILITY_COUNT 6U
/* Enrollment and activation remain on the stable v1 protocol. */
#define AP_CONTROL_ALPN AP_CONTROL_ALPN_V1
#define AP_CONTROL_FRAME_MAX (64U * 1024U)
#define AP_CONTROL_IO_TIMEOUT_MS 10000

enum ap_control_wire_result {
    AP_CONTROL_WIRE_ERROR = -1,
    AP_CONTROL_WIRE_OK = 0,
    AP_CONTROL_WIRE_TIMEOUT = 1,
    AP_CONTROL_WIRE_CLOSED = 2,
    AP_CONTROL_WIRE_OVERSIZED = 3,
    AP_CONTROL_WIRE_INVALID_JSON = 4,
    AP_CONTROL_WIRE_DUPLICATE_KEY = 5,
    AP_CONTROL_WIRE_INVALID_FIELDS = 6,
};

struct ap_control_capabilities {
    int config_executor;
    int validate;
    int stage;
    int apply;
    int readback;
    int rollback;
};

int ap_control_json_parse_strict(const unsigned char *data, size_t length,
                                 struct json_object **out);
int ap_control_json_object_exact(
    struct json_object *object, const char *const *allowed,
    size_t allowed_count, const char *const *required,
    size_t required_count);
int ap_control_frame_encode(struct json_object *object,
                            unsigned char **out, size_t *out_length);
int ap_control_ssl_read_json(SSL *ssl, int timeout_ms,
                             struct json_object **out);
int ap_control_ssl_write_json(SSL *ssl, int timeout_ms,
                              struct json_object *object);
int ap_control_ssl_handshake(SSL *ssl, int server, int timeout_ms);
int ap_control_ssl_selected_alpn(SSL *ssl);
int ap_control_ssl_selected_alpn_version(SSL *ssl);
int ap_control_hex_encode(const unsigned char *data, size_t data_length,
                          char *out, size_t out_size);
int ap_control_hex_decode(const char *text, unsigned char *out,
                          size_t out_size, size_t *out_length);
int ap_control_json_get_string(struct json_object *object, const char *name,
                               const char **out, size_t minimum,
                               size_t maximum);
int ap_control_json_get_int64(struct json_object *object, const char *name,
                              int64_t minimum, int64_t maximum,
                              int64_t *out);
int ap_control_uuid4(char out[37]);
int ap_control_capabilities_add(struct json_object *object,
                                const struct ap_control_capabilities *caps);
int ap_control_capabilities_parse(struct json_object *object,
                                  struct ap_control_capabilities *caps);
int ap_control_capabilities_all_true(
    const struct ap_control_capabilities *caps);

#endif
