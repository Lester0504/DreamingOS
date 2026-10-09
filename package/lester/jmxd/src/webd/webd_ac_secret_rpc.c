// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_ac_secret_rpc.h"

#include "../ac/ac_secret_rotation.h"
#include "../ap_control_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/crypto.h>

#define WEBD_AC_SECRET_FRAME_MAX 4096U
#define WEBD_AC_SECRET_RPC_TIMEOUT_SECONDS 2

static struct json_object *webd_ac_secret_error(const char *code,
                                                 const char *reason,
                                                 int status,
                                                 int *http_status)
{
    struct json_object *root = json_object_new_object();

    if (http_status)
        *http_status = status;
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string(code));
    json_object_object_add(root, "reason", json_object_new_string(reason));
    return root;
}

static int webd_ac_secret_write_full(int fd, const void *data, size_t len)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, bytes + offset, len - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int webd_ac_secret_read_full(int fd, void *data, size_t len)
{
    unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < len) {
        ssize_t got = read(fd, bytes + offset, len - offset);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return -1;
        offset += (size_t)got;
    }
    return 0;
}

static struct json_object *webd_ac_secret_rpc(struct json_object *request)
{
    struct sockaddr_un address;
    unsigned char *frame = NULL;
    size_t frame_len = 0;
    unsigned char header[4];
    unsigned char *payload = NULL;
    size_t payload_len;
    struct json_object *response = NULL;
    struct timeval timeout = { .tv_sec = WEBD_AC_SECRET_RPC_TIMEOUT_SECONDS };
    int fd = -1;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s",
             AC_SECRET_ROTATION_SOCKET);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        ap_control_frame_encode(request, &frame, &frame_len) !=
            AP_CONTROL_WIRE_OK ||
        webd_ac_secret_write_full(fd, frame, frame_len) != 0 ||
        webd_ac_secret_read_full(fd, header, sizeof(header)) != 0)
        goto done;
    payload_len = ((size_t)header[0] << 24) | ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) | header[3];
    if (payload_len == 0 || payload_len > WEBD_AC_SECRET_FRAME_MAX ||
        !(payload = OPENSSL_malloc(payload_len)) ||
        webd_ac_secret_read_full(fd, payload, payload_len) != 0 ||
        ap_control_json_parse_strict(payload, payload_len, &response) !=
            AP_CONTROL_WIRE_OK) {
        json_object_put(response);
        response = NULL;
    }
done:
    if (fd >= 0)
        close(fd);
    if (frame) {
        OPENSSL_cleanse(frame, frame_len);
        free(frame);
    }
    if (payload) {
        OPENSSL_cleanse(payload, payload_len);
        OPENSSL_free(payload);
    }
    return response;
}

static int webd_ac_secret_response_status(struct json_object *response)
{
    struct json_object *ok = NULL;
    struct json_object *error = NULL;
    const char *code = "";

    if (!response)
        return 503;
    if (json_object_object_get_ex(response, "ok", &ok) && ok &&
        json_object_get_boolean(ok))
        return 200;
    if (json_object_object_get_ex(response, "error", &error) && error &&
        json_object_is_type(error, json_type_string))
        code = json_object_get_string(error);
    if (!strcmp(code, "invalid_request"))
        return 400;
    if (!strcmp(code, "not_found"))
        return 404;
    if (!strcmp(code, "revision_conflict") ||
        !strcmp(code, "idempotency_conflict"))
        return 409;
    if (!strcmp(code, "capability_disabled"))
        return 503;
    return 500;
}

static int webd_ac_secret_uuid4_valid(const char *value)
{
    static const int hyphens[] = {8, 13, 18, 23};
    size_t i;
    int h = 0;

    if (!value || strlen(value) != 36 || value[14] != '4' ||
        !(value[19] == '8' || value[19] == '9' || value[19] == 'a' ||
          value[19] == 'b'))
        return 0;
    for (i = 0; i < 36; i++) {
        if (h < 4 && (int)i == hyphens[h]) {
            if (value[i] != '-')
                return 0;
            h++;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

struct json_object *webd_ac_secret_rotate_response(
    const char *ap_id, const char *ssid_id, const char *actor_id,
    struct json_object *body, char *raw_body, size_t raw_body_len,
    int *http_status)
{
    static const char *const body_fields[] = {
        "idempotency_key", "base_revision", "confirm", "secret"
    };
    struct json_object *request = NULL;
    struct json_object *value = NULL;
    struct json_object *response = NULL;
    const char *idempotency_key = NULL;
    const char *secret = NULL;
    int64_t base_revision = 0;
    int confirm = 0;

    if (!webd_ac_secret_uuid4_valid(ap_id) || !ssid_id || !ssid_id[0] ||
        strlen(ssid_id) > 64 || !actor_id || !actor_id[0] ||
        !body || !json_object_is_type(body, json_type_object) ||
        ap_control_json_object_exact(body, body_fields, 4, body_fields, 4) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(body, "idempotency_key", &idempotency_key,
                                   1, 128) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_int64(body, "base_revision", 1, INT64_MAX - 1,
                                  &base_revision) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(body, "secret", &secret, 8, 64) !=
            AP_CONTROL_WIRE_OK ||
        !json_object_object_get_ex(body, "confirm", &value) || !value ||
        !json_object_is_type(value, json_type_boolean) ||
        !(confirm = json_object_get_boolean(value))) {
        ap_control_json_scrub_string(body, "secret");
        if (raw_body && raw_body_len)
            OPENSSL_cleanse(raw_body, raw_body_len);
        return webd_ac_secret_error("invalid_request",
            "idempotency_key, base_revision, confirm=true and secret are required",
            400, http_status);
    }
    request = json_object_new_object();
    if (!request)
        goto unavailable;
    json_object_object_add(request, "operation",
                           json_object_new_string("rotate"));
    json_object_object_add(request, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(request, "ssid_id", json_object_new_string(ssid_id));
    json_object_object_add(request, "actor_id",
                           json_object_new_string(actor_id));
    json_object_object_add(request, "idempotency_key",
                           json_object_new_string(idempotency_key));
    json_object_object_add(request, "base_revision",
                           json_object_new_int64(base_revision));
    json_object_object_add(request, "confirm", json_object_new_boolean(confirm));
    json_object_object_add(request, "secret",
                           json_object_new_string(secret));
    response = webd_ac_secret_rpc(request);
    /* Scrub json-c's child storage and retained parent serialization cache. */
    ap_control_json_scrub_string(request, "secret");
    ap_control_json_scrub_string(body, "secret");
    if (raw_body && raw_body_len)
        OPENSSL_cleanse(raw_body, raw_body_len);
    json_object_put(request);
    if (!response)
        return webd_ac_secret_error("upstream_unavailable",
                                    "ac_secret_rotation_socket_unavailable",
                                    503, http_status);
    if (http_status)
        *http_status = webd_ac_secret_response_status(response);
    return response;

unavailable:
    ap_control_json_scrub_string(request, "secret");
    ap_control_json_scrub_string(body, "secret");
    if (raw_body && raw_body_len)
        OPENSSL_cleanse(raw_body, raw_body_len);
    json_object_put(request);
    return webd_ac_secret_error("internal_error", "memory_unavailable", 500,
                                http_status);
}

struct json_object *webd_ac_secret_status_response(const char *job_id,
                                                   int *http_status)
{
    struct json_object *request;
    struct json_object *response;

    if (!webd_ac_secret_uuid4_valid(job_id))
        return webd_ac_secret_error("invalid_request", "job_id must be a UUID",
                                    400, http_status);
    request = json_object_new_object();
    json_object_object_add(request, "operation",
                           json_object_new_string("status"));
    json_object_object_add(request, "job_id", json_object_new_string(job_id));
    response = webd_ac_secret_rpc(request);
    json_object_put(request);
    if (!response)
        return webd_ac_secret_error("upstream_unavailable",
                                    "ac_secret_rotation_socket_unavailable",
                                    503, http_status);
    if (http_status)
        *http_status = webd_ac_secret_response_status(response);
    return response;
}
