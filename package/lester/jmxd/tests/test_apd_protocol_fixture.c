// SPDX-License-Identifier: GPL-2.0-or-later
#include "test_apd_protocol_fixture.h"

int64_t g_apd_started_at = 1;

int64_t apd_now_s(void)
{
    return 100;
}

const struct apd_backend_ops *apd_backend(void)
{
    static const struct apd_backend_ops backend = {
        .name = "fixture",
        .snapshot_supported = 0,
    };

    return &backend;
}

struct json_object *apd_backend_disabled(const char *operation,
                                         const char *reason)
{
    (void)operation;
    (void)reason;
    return json_object_new_object();
}

int apd_transport_connected(void)
{
    return 0;
}

const char *apd_transport_reason(void)
{
    return "transport_fixture_disconnected";
}

int apd_transport_adopted(void)
{
    const char *value = getenv("APD_TEST_ADOPTED");

    return value && !strcmp(value, "1");
}

int apd_db_identity_get(struct apd_node_identity *out)
{
    size_t i;

    memset(out, 0, sizeof(*out));
    snprintf(out->ap_id, sizeof(out->ap_id),
             "12345678-1234-4123-8123-123456789abc");
    snprintf(out->key_id, sizeof(out->key_id),
             "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    for (i = 0; i < sizeof(out->public_key); i++)
        out->public_key[i] = (unsigned char)i;
    out->created_at = 42;
    return 0;
}

int apd_db_pairing_status_get(struct apd_pairing_status *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->state, sizeof(out->state), "challenge_pending");
    snprintf(out->controller_id, sizeof(out->controller_id), "controller-fixture");
    snprintf(out->request_id, sizeof(out->request_id), "request-fixture");
    out->challenge_present = 1;
    out->attempts = 2;
    out->expires_at = 500;
    out->updated_at = 50;
    return 0;
}

struct json_object *apd_identity_json(void);
struct json_object *apd_pairing_status_json(void);

int main(void)
{
    struct json_object *identity = apd_identity_json();
    struct json_object *pairing = apd_pairing_status_json();

    if (!identity || !pairing)
        return 1;
    printf("%s\n%s\n", json_object_to_json_string_ext(identity,
           JSON_C_TO_STRING_PLAIN), json_object_to_json_string_ext(pairing,
           JSON_C_TO_STRING_PLAIN));
    json_object_put(identity);
    json_object_put(pairing);
    return 0;
}
