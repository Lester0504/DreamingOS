// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_pairing_protocol_fixture.h"

int64_t g_ac_started_at = 1;

int64_t ac_now_s(void) { return 100; }
int ac_transport_listening(void) { return 0; }
const char *ac_transport_reason(void) { return "transport_fixture_disabled"; }
int ac_transport_port(void) { return 0; }
const char *ac_transport_controller_id(void) { return "controller-fixture"; }
int ac_db_managed_ap_counts(int64_t online_after, int *count, int *online)
{
    (void)online_after;
    *count = 0;
    *online = 0;
    return 0;
}
int ac_db_count(const char *table) { (void)table; return 0; }

static void fill_status(struct ac_pairing_token_status *out, const char *state)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->token_id, sizeof(out->token_id),
             "12345678-1234-4123-8123-123456789abc");
    snprintf(out->site_id, sizeof(out->site_id), "site-fixture");
    snprintf(out->state, sizeof(out->state), "%s", state);
    out->hardware_bound = 1;
    out->attempts = 1;
    out->max_attempts = 5;
    out->created_at = 10;
    out->expires_at = 500;
}

int ac_db_pairing_token_create(int64_t ttl_seconds, int max_attempts,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_secret *out)
{
    (void)ttl_seconds; (void)max_attempts; (void)site_id; (void)hardware_digest;
    memset(out, 0, sizeof(*out));
    snprintf(out->token_id, sizeof(out->token_id),
             "12345678-1234-4123-8123-123456789abc");
    snprintf(out->token, sizeof(out->token),
             "secret-sentinel-01234567890123456789012345");
    out->created_at = 10;
    out->expires_at = 500;
    out->max_attempts = 5;
    return 0;
}

int ac_db_pairing_token_status(const char *token_id,
                               struct ac_pairing_token_status *out)
{
    (void)token_id;
    fill_status(out, "active");
    return 0;
}

int ac_db_pairing_token_list(ac_pairing_token_visit_fn visit, void *opaque)
{
    struct ac_pairing_token_status status;
    fill_status(&status, "active");
    return visit(&status, opaque) == 0 ? 1 : -1;
}

int ac_db_pairing_token_revoke(const char *token_id)
{
    (void)token_id;
    return 0;
}

int ac_db_pairing_token_redeem(const char *token_id, const char *token,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_status *out)
{
    (void)token_id; (void)token; (void)site_id; (void)hardware_digest;
    fill_status(out, "consumed");
    out->consumed_at = 100;
    return AC_PAIRING_REDEEM_OK;
}

struct json_object *ac_pairing_token_create_json(int64_t ttl_seconds,
                                                  int max_attempts,
                                                  const char *site_id,
                                                  const char *hardware_digest);
struct json_object *ac_pairing_token_status_json(const char *token_id);
struct json_object *ac_pairing_token_list_json(void);
struct json_object *ac_pairing_token_redeem_json(const char *token_id,
                                                  const char *token,
                                                  const char *site_id,
                                                  const char *hardware_digest);

int main(void)
{
    struct json_object *created = ac_pairing_token_create_json(600, 5,
        "site-fixture", "sha256:feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface");
    struct json_object *status = ac_pairing_token_status_json(
        "12345678-1234-4123-8123-123456789abc");
    struct json_object *list = ac_pairing_token_list_json();
    struct json_object *redeemed = ac_pairing_token_redeem_json(
        "12345678-1234-4123-8123-123456789abc",
        "secret-sentinel-01234567890123456789012345", "site-fixture",
        "sha256:feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface");
    struct json_object *objects[] = {created, status, list, redeemed};
    size_t i;

    for (i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
        if (!objects[i])
            return 1;
        printf("%s\n", json_object_to_json_string_ext(objects[i],
               JSON_C_TO_STRING_PLAIN));
        json_object_put(objects[i]);
    }
    return 0;
}
