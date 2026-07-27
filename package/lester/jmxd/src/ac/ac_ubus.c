// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_internal.h"

static int ac_reply_json(struct ubus_context *ctx,
                         struct ubus_request_data *req,
                         struct json_object *response);

static int ac_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                        struct json_object *response)
{
    const char *text;
    int rc;

    if (!response)
        return UBUS_STATUS_UNKNOWN_ERROR;
    text = json_object_to_json_string(response);
    if (!text)
        return UBUS_STATUS_UNKNOWN_ERROR;

    blob_buf_init(&g_ac_blob, 0);
    if (!blobmsg_add_json_from_string(&g_ac_blob, text)) {
        blob_buf_free(&g_ac_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    rc = ubus_send_reply(ctx, req, g_ac_blob.head);
    blob_buf_free(&g_ac_blob);
    return rc;
}

enum {
    AC_CREATE_TTL_SECONDS,
    AC_CREATE_MAX_ATTEMPTS,
    AC_CREATE_SITE_ID,
    AC_CREATE_HARDWARE_DIGEST,
    __AC_CREATE_MAX,
};

enum {
    AC_RADIO_JOB_AP_ID,
    AC_RADIO_JOB_RADIO_ID,
    AC_RADIO_JOB_MODE,
    AC_RADIO_JOB_IDEMPOTENCY_KEY,
    __AC_RADIO_JOB_CREATE_MAX,
};

static const struct blobmsg_policy ac_radio_job_create_policy[
    __AC_RADIO_JOB_CREATE_MAX] = {
    [AC_RADIO_JOB_AP_ID] = { .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_RADIO_JOB_RADIO_ID] = { .name = "radio_id", .type = BLOBMSG_TYPE_STRING },
    [AC_RADIO_JOB_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
    [AC_RADIO_JOB_IDEMPOTENCY_KEY] = {
        .name = "idempotency_key", .type = BLOBMSG_TYPE_STRING
    },
};

enum {
    AC_RADIO_JOB_ID,
    __AC_RADIO_JOB_ID_MAX,
};

static const struct blobmsg_policy ac_radio_job_id_policy[__AC_RADIO_JOB_ID_MAX] = {
    [AC_RADIO_JOB_ID] = { .name = "job_id", .type = BLOBMSG_TYPE_STRING },
};

enum {
    AC_RADIO_JOB_LIST_AP_ID,
    __AC_RADIO_JOB_LIST_MAX,
};

static const struct blobmsg_policy ac_radio_job_list_policy[
    __AC_RADIO_JOB_LIST_MAX] = {
    [AC_RADIO_JOB_LIST_AP_ID] = {
        .name = "ap_id", .type = BLOBMSG_TYPE_STRING
    },
};

enum {
    AC_SURVEY_AP_ID,
    AC_SURVEY_RADIO_ID,
    AC_SURVEY_START,
    AC_SURVEY_END,
    AC_SURVEY_RESOLUTION,
    AC_SURVEY_LIMIT,
    AC_SURVEY_AFTER_ID,
    __AC_SURVEY_MAX,
};

static const struct blobmsg_policy ac_survey_history_policy[__AC_SURVEY_MAX] = {
    [AC_SURVEY_AP_ID] = { .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_SURVEY_RADIO_ID] = { .name = "radio_id", .type = BLOBMSG_TYPE_STRING },
    [AC_SURVEY_START] = { .name = "start", .type = BLOBMSG_TYPE_INT64 },
    [AC_SURVEY_END] = { .name = "end", .type = BLOBMSG_TYPE_INT64 },
    [AC_SURVEY_RESOLUTION] = { .name = "resolution", .type = BLOBMSG_TYPE_STRING },
    [AC_SURVEY_LIMIT] = { .name = "limit", .type = BLOBMSG_TYPE_INT32 },
    [AC_SURVEY_AFTER_ID] = { .name = "after_id", .type = BLOBMSG_TYPE_INT64 },
};

/* blobmsg_parse() enforces exact attribute types, which would reject the
 * INT32-encoded timestamps that JSON bridges legitimately produce for the
 * INT64 contract fields above.  ac_message_is_strict() already enforced
 * name uniqueness, unknown-field rejection and INT32/INT64-only widening,
 * so this parse-side policy leaves the 64-bit fields untyped and the
 * handler reads them through ac_attr_get_s64(). */
static const struct blobmsg_policy ac_survey_history_parse_policy[
    __AC_SURVEY_MAX] = {
    [AC_SURVEY_AP_ID] = { .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_SURVEY_RADIO_ID] = { .name = "radio_id", .type = BLOBMSG_TYPE_STRING },
    [AC_SURVEY_START] = { .name = "start", .type = BLOBMSG_TYPE_UNSPEC },
    [AC_SURVEY_END] = { .name = "end", .type = BLOBMSG_TYPE_UNSPEC },
    [AC_SURVEY_RESOLUTION] = { .name = "resolution", .type = BLOBMSG_TYPE_STRING },
    [AC_SURVEY_LIMIT] = { .name = "limit", .type = BLOBMSG_TYPE_INT32 },
    [AC_SURVEY_AFTER_ID] = { .name = "after_id", .type = BLOBMSG_TYPE_UNSPEC },
};

enum {
    AC_STATION_EVENTS_AP_ID,
    AC_STATION_EVENTS_EVENT,
    AC_STATION_EVENTS_START,
    AC_STATION_EVENTS_END,
    AC_STATION_EVENTS_LIMIT,
    AC_STATION_EVENTS_AFTER_ID,
    __AC_STATION_EVENTS_MAX,
};

static const struct blobmsg_policy ac_station_events_policy[
    __AC_STATION_EVENTS_MAX] = {
    [AC_STATION_EVENTS_AP_ID] = {
        .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_STATION_EVENTS_EVENT] = {
        .name = "event", .type = BLOBMSG_TYPE_STRING },
    [AC_STATION_EVENTS_START] = {
        .name = "start", .type = BLOBMSG_TYPE_INT64 },
    [AC_STATION_EVENTS_END] = {
        .name = "end", .type = BLOBMSG_TYPE_INT64 },
    [AC_STATION_EVENTS_LIMIT] = {
        .name = "limit", .type = BLOBMSG_TYPE_INT32 },
    [AC_STATION_EVENTS_AFTER_ID] = {
        .name = "after_id", .type = BLOBMSG_TYPE_INT64 },
};

enum {
    AC_WIFI_VALIDATE_AP_ID,
    AC_WIFI_VALIDATE_BASE_REVISION,
    AC_WIFI_VALIDATE_IDEMPOTENCY_KEY,
    AC_WIFI_VALIDATE_CHANGES,
    __AC_WIFI_VALIDATE_MAX,
};

/* The desired changeset travels as a JSON document in a string field:
 * nested blobmsg TABLE payloads have no strict-contract precedent here,
 * while JSON documents already are the config_json/runtime_json idiom.
 * The handler parses and bounds the document in ac_db. */
static const struct blobmsg_policy ac_wifi_validate_policy[
    __AC_WIFI_VALIDATE_MAX] = {
    [AC_WIFI_VALIDATE_AP_ID] = {
        .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_WIFI_VALIDATE_BASE_REVISION] = {
        .name = "base_revision", .type = BLOBMSG_TYPE_INT64 },
    [AC_WIFI_VALIDATE_IDEMPOTENCY_KEY] = {
        .name = "idempotency_key", .type = BLOBMSG_TYPE_STRING },
    [AC_WIFI_VALIDATE_CHANGES] = {
        .name = "changes", .type = BLOBMSG_TYPE_STRING },
};

/* Parse-side companion; see ac_survey_history_parse_policy. */
static const struct blobmsg_policy ac_wifi_validate_parse_policy[
    __AC_WIFI_VALIDATE_MAX] = {
    [AC_WIFI_VALIDATE_AP_ID] = {
        .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_WIFI_VALIDATE_BASE_REVISION] = {
        .name = "base_revision", .type = BLOBMSG_TYPE_UNSPEC },
    [AC_WIFI_VALIDATE_IDEMPOTENCY_KEY] = {
        .name = "idempotency_key", .type = BLOBMSG_TYPE_STRING },
    [AC_WIFI_VALIDATE_CHANGES] = {
        .name = "changes", .type = BLOBMSG_TYPE_STRING },
};

/* Parse-side companion; see ac_survey_history_parse_policy. */
static const struct blobmsg_policy ac_station_events_parse_policy[
    __AC_STATION_EVENTS_MAX] = {
    [AC_STATION_EVENTS_AP_ID] = {
        .name = "ap_id", .type = BLOBMSG_TYPE_STRING },
    [AC_STATION_EVENTS_EVENT] = {
        .name = "event", .type = BLOBMSG_TYPE_STRING },
    [AC_STATION_EVENTS_START] = {
        .name = "start", .type = BLOBMSG_TYPE_UNSPEC },
    [AC_STATION_EVENTS_END] = {
        .name = "end", .type = BLOBMSG_TYPE_UNSPEC },
    [AC_STATION_EVENTS_LIMIT] = {
        .name = "limit", .type = BLOBMSG_TYPE_INT32 },
    [AC_STATION_EVENTS_AFTER_ID] = {
        .name = "after_id", .type = BLOBMSG_TYPE_UNSPEC },
};

static const struct blobmsg_policy ac_create_policy[__AC_CREATE_MAX] = {
    [AC_CREATE_TTL_SECONDS] = { .name = "ttl_seconds", .type = BLOBMSG_TYPE_INT32 },
    [AC_CREATE_MAX_ATTEMPTS] = { .name = "max_attempts", .type = BLOBMSG_TYPE_INT32 },
    [AC_CREATE_SITE_ID] = { .name = "site_id", .type = BLOBMSG_TYPE_STRING },
    [AC_CREATE_HARDWARE_DIGEST] = { .name = "hardware_digest", .type = BLOBMSG_TYPE_STRING },
};

enum {
    AC_TOKEN_ID,
    __AC_TOKEN_MAX,
};

static const struct blobmsg_policy ac_token_policy[__AC_TOKEN_MAX] = {
    [AC_TOKEN_ID] = { .name = "token_id", .type = BLOBMSG_TYPE_STRING },
};

/* JSON-to-blobmsg bridges (webd REST and the ubus CLI both use
 * blobmsg_add_json_from_string) encode every integer with the smallest
 * width that fits, so an INT64 contract field arrives as INT32 whenever
 * the value fits in 32 bits (all current Unix timestamps do).  Accept
 * that lossless widening; every other type mismatch stays rejected. */
static int ac_policy_type_compatible(int policy_type, int attr_type)
{
    if (attr_type == policy_type)
        return 1;
    return policy_type == BLOBMSG_TYPE_INT64 &&
           attr_type == BLOBMSG_TYPE_INT32;
}

/* Read a signed 64-bit contract field from an INT32 or INT64 attribute.
 * Only call after ac_message_is_strict() accepted the message. */
static int64_t ac_attr_get_s64(struct blob_attr *attr)
{
    if (blobmsg_type(attr) == BLOBMSG_TYPE_INT32)
        return (int64_t)(int32_t)blobmsg_get_u32(attr);
    return (int64_t)blobmsg_get_u64(attr);
}

static int ac_message_is_strict(struct blob_attr *msg,
                                const struct blobmsg_policy *policy,
                                size_t policy_len, unsigned int required)
{
    struct blob_attr *attr;
    unsigned int seen = 0;
    size_t rem;
    size_t i;

    if (!msg || policy_len > sizeof(seen) * 8U)
        return 0;
    blobmsg_for_each_attr(attr, msg, rem) {
        const char *name;

        if (!blobmsg_check_attr(attr, true))
            return 0;
        name = blobmsg_name(attr);
        for (i = 0; i < policy_len; i++) {
            unsigned int bit = 1U << i;

            if (strcmp(name, policy[i].name) != 0)
                continue;
            if ((seen & bit) ||
                !ac_policy_type_compatible((int)policy[i].type,
                                           blobmsg_type(attr)))
                return 0;
            seen |= bit;
            break;
        }
        if (i == policy_len)
            return 0;
    }
    return rem == 0 && (seen & required) == required;
}

static int ac_site_id_valid(const char *site_id)
{
    size_t i;
    size_t len = site_id ? strlen(site_id) : 0;

    if (len > AC_PAIRING_SITE_ID_LEN)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)site_id[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '-'))
            return 0;
    }
    return 1;
}

static int ac_hardware_digest_valid(const char *hardware_digest)
{
    const char *hex = hardware_digest;
    size_t len = hardware_digest ? strlen(hardware_digest) : 0;
    size_t i;

    if (len == 0)
        return 1;
    if (len == AC_PAIRING_HARDWARE_DIGEST_LEN &&
        strncmp(hardware_digest, "sha256:", 7) == 0)
        hex += 7;
    else if (len != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)hex[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static int ac_token_id_valid(const char *token_id)
{
    size_t i;

    if (!token_id || strlen(token_id) != AC_PAIRING_TOKEN_ID_LEN)
        return 0;
    for (i = 0; i < AC_PAIRING_TOKEN_ID_LEN; i++) {
        unsigned char c = (unsigned char)token_id[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return 0;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    if (token_id[14] != '4')
        return 0;
    return token_id[19] == '8' || token_id[19] == '9' ||
           token_id[19] == 'a' || token_id[19] == 'b';
}

static int ac_radio_job_ap_id_valid(const char *value)
{
    return ac_token_id_valid(value);
}

static int ac_radio_job_radio_id_valid(const char *value)
{
    size_t i;

    if (!value || strncmp(value, "phy", 3) != 0 || !value[3] || strlen(value) > 31)
        return 0;
    for (i = 3; value[i]; i++)
        if (value[i] < '0' || value[i] > '9')
            return 0;
    return 1;
}

static int ac_radio_job_mode_valid(const char *value)
{
    return value && (!strcmp(value, "neighbor") || !strcmp(value, "survey"));
}

static int ac_radio_job_idempotency_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > AC_RADIO_JOB_IDEMPOTENCY_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '-'))
            return 0;
    }
    return 1;
}

static int ac_parse_radio_job_id(struct blob_attr *msg, const char **job_id)
{
    struct blob_attr *tb[__AC_RADIO_JOB_ID_MAX];

    if (!job_id || !ac_message_is_strict(msg, ac_radio_job_id_policy,
                                         __AC_RADIO_JOB_ID_MAX, 1U << AC_RADIO_JOB_ID) ||
        blobmsg_parse(ac_radio_job_id_policy, __AC_RADIO_JOB_ID_MAX, tb,
                      blob_data(msg), blob_len(msg)) != 0)
        return -1;
    *job_id = blobmsg_get_string(tb[AC_RADIO_JOB_ID]);
    return ac_token_id_valid(*job_id) ? 0 : -1;
}

static int ac_handle_radio_job_create(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__AC_RADIO_JOB_CREATE_MAX];
    struct json_object *response;
    const char *ap_id;
    const char *radio_id;
    const char *mode;
    const char *idempotency_key;
    const unsigned int required = (1U << AC_RADIO_JOB_AP_ID) |
        (1U << AC_RADIO_JOB_RADIO_ID) | (1U << AC_RADIO_JOB_MODE) |
        (1U << AC_RADIO_JOB_IDEMPOTENCY_KEY);

    (void)obj;
    (void)method;
    if (!ac_message_is_strict(msg, ac_radio_job_create_policy,
                              __AC_RADIO_JOB_CREATE_MAX, required) ||
        blobmsg_parse(ac_radio_job_create_policy, __AC_RADIO_JOB_CREATE_MAX, tb,
                      blob_data(msg), blob_len(msg)) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    ap_id = blobmsg_get_string(tb[AC_RADIO_JOB_AP_ID]);
    radio_id = blobmsg_get_string(tb[AC_RADIO_JOB_RADIO_ID]);
    mode = blobmsg_get_string(tb[AC_RADIO_JOB_MODE]);
    idempotency_key = blobmsg_get_string(tb[AC_RADIO_JOB_IDEMPOTENCY_KEY]);
    if (!ac_radio_job_ap_id_valid(ap_id) || !ac_radio_job_radio_id_valid(radio_id) ||
        !ac_radio_job_mode_valid(mode) || !ac_radio_job_idempotency_valid(idempotency_key))
        return UBUS_STATUS_INVALID_ARGUMENT;
    response = ac_radio_job_create_json(ap_id, radio_id, mode, idempotency_key);
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_radio_job_status(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    const char *job_id;
    (void)obj;
    (void)method;
    if (ac_parse_radio_job_id(msg, &job_id) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_radio_job_status_json(job_id));
}

static int ac_handle_radio_job_cancel(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    const char *job_id;
    (void)obj;
    (void)method;
    if (ac_parse_radio_job_id(msg, &job_id) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_radio_job_cancel_json(job_id));
}

static int ac_handle_radio_job_result(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    const char *job_id;
    (void)obj;
    (void)method;
    if (ac_parse_radio_job_id(msg, &job_id) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_radio_job_result_json(job_id));
}

static int ac_handle_radio_job_list(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__AC_RADIO_JOB_LIST_MAX];
    const char *ap_id;

    (void)obj;
    (void)method;
    if (!ac_message_is_strict(msg, ac_radio_job_list_policy,
                              __AC_RADIO_JOB_LIST_MAX,
                              1U << AC_RADIO_JOB_LIST_AP_ID) ||
        blobmsg_parse(ac_radio_job_list_policy, __AC_RADIO_JOB_LIST_MAX, tb,
                      blob_data(msg), blob_len(msg)) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    ap_id = blobmsg_get_string(tb[AC_RADIO_JOB_LIST_AP_ID]);
    if (!ac_radio_job_ap_id_valid(ap_id))
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_radio_job_list_json(ap_id));
}

static int ac_reply_json(struct ubus_context *ctx,
                         struct ubus_request_data *req,
                         struct json_object *response)
{
    int rc = ac_send_json(ctx, req, response);

    if (response)
        json_object_put(response);
    return rc;
}

static int ac_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    struct json_object *response = ac_status_json();
    (void)obj; (void)method; (void)msg;
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_capabilities(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *response = ac_capabilities_json();
    (void)obj; (void)method; (void)msg;
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_aps_list(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    struct json_object *response;
    int64_t observed_at;

    (void)obj;
    (void)method;
    if (msg && blob_len(msg) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    observed_at = ac_now_s();
    response = ac_db_aps_list_json(
        observed_at, observed_at - AC_AP_ONLINE_TIMEOUT_SECONDS);
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_pairing_token_create(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__AC_CREATE_MAX];
    struct json_object *response;
    const char *site_id;
    const char *hardware_digest;
    uint32_t ttl_seconds;
    uint32_t max_attempts;
    const unsigned int required = (1U << AC_CREATE_TTL_SECONDS) |
                                  (1U << AC_CREATE_MAX_ATTEMPTS) |
                                  (1U << AC_CREATE_SITE_ID) |
                                  (1U << AC_CREATE_HARDWARE_DIGEST);

    (void)obj;
    (void)method;
    if (!ac_message_is_strict(msg, ac_create_policy, __AC_CREATE_MAX,
                              required) ||
        blobmsg_parse(ac_create_policy, __AC_CREATE_MAX, tb,
                      blob_data(msg), blob_len(msg)) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    ttl_seconds = blobmsg_get_u32(tb[AC_CREATE_TTL_SECONDS]);
    max_attempts = blobmsg_get_u32(tb[AC_CREATE_MAX_ATTEMPTS]);
    site_id = blobmsg_get_string(tb[AC_CREATE_SITE_ID]);
    hardware_digest = blobmsg_get_string(tb[AC_CREATE_HARDWARE_DIGEST]);
    if (ttl_seconds < AC_PAIRING_TOKEN_TTL_MIN ||
        ttl_seconds > AC_PAIRING_TOKEN_TTL_MAX || max_attempts < 1 ||
        max_attempts > AC_PAIRING_TOKEN_ATTEMPTS_MAX ||
        !ac_site_id_valid(site_id) ||
        !ac_hardware_digest_valid(hardware_digest))
        return UBUS_STATUS_INVALID_ARGUMENT;
    response = ac_pairing_token_create_json((int64_t)ttl_seconds,
                                            (int)max_attempts, site_id,
                                            hardware_digest);
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_pairing_token_list(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct json_object *response;

    (void)obj;
    (void)method;
    if (msg && blob_len(msg) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    response = ac_pairing_token_list_json();
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_radio_job_latest_results(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct json_object *response;

    (void)obj;
    (void)method;
    if (msg && blob_len(msg) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    response = ac_radio_job_latest_results_json();
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_survey_history(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__AC_SURVEY_MAX] = {0};
    const char *ap_id = "";
    const char *radio_id = "";
    const char *resolution = "auto";
    int resolution_seconds = 0;
    int64_t now = ac_now_s();
    int64_t start = now - 12 * 60 * 60;
    int64_t end = now;
    int64_t after_id = 0;
    int limit = 2048;

    (void)obj;
    (void)method;
    if (msg && blob_len(msg) != 0 &&
        (!ac_message_is_strict(msg, ac_survey_history_policy,
                               __AC_SURVEY_MAX, 0) ||
         blobmsg_parse(ac_survey_history_parse_policy, __AC_SURVEY_MAX, tb,
                       blob_data(msg), blob_len(msg)) != 0))
        return UBUS_STATUS_INVALID_ARGUMENT;
    if (tb[AC_SURVEY_AP_ID]) ap_id = blobmsg_get_string(tb[AC_SURVEY_AP_ID]);
    if (tb[AC_SURVEY_RADIO_ID]) radio_id = blobmsg_get_string(tb[AC_SURVEY_RADIO_ID]);
    if (tb[AC_SURVEY_START]) start = ac_attr_get_s64(tb[AC_SURVEY_START]);
    if (tb[AC_SURVEY_END]) end = ac_attr_get_s64(tb[AC_SURVEY_END]);
    if (tb[AC_SURVEY_RESOLUTION])
        resolution = blobmsg_get_string(tb[AC_SURVEY_RESOLUTION]);
    if (tb[AC_SURVEY_LIMIT]) limit = (int)blobmsg_get_u32(tb[AC_SURVEY_LIMIT]);
    if (tb[AC_SURVEY_AFTER_ID])
        after_id = ac_attr_get_s64(tb[AC_SURVEY_AFTER_ID]);
    if (!strcmp(resolution, "300")) resolution_seconds = 300;
    else if (!strcmp(resolution, "3600")) resolution_seconds = 3600;
    else if (strcmp(resolution, "auto")) return UBUS_STATUS_INVALID_ARGUMENT;
    if ((ap_id[0] && !ac_radio_job_ap_id_valid(ap_id)) ||
        (radio_id[0] && (!ap_id[0] || !ac_radio_job_radio_id_valid(radio_id))) ||
        start <= 0 || end < start || limit < 1 ||
        limit > AC_SURVEY_HISTORY_LIMIT_MAX || after_id < 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_db_survey_history_json(
        ap_id, radio_id, start, end, resolution_seconds, limit, after_id));
}

static int ac_handle_station_events(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__AC_STATION_EVENTS_MAX] = {0};
    const char *ap_id = "";
    const char *event = "";
    int64_t now = ac_now_s();
    int64_t start = now - 24 * 60 * 60;
    int64_t end = now;
    int64_t after_id = 0;
    int limit = 256;

    (void)obj;
    (void)method;
    if (msg && blob_len(msg) != 0 &&
        (!ac_message_is_strict(msg, ac_station_events_policy,
                               __AC_STATION_EVENTS_MAX, 0) ||
         blobmsg_parse(ac_station_events_parse_policy,
                       __AC_STATION_EVENTS_MAX, tb,
                       blob_data(msg), blob_len(msg)) != 0))
        return UBUS_STATUS_INVALID_ARGUMENT;
    if (tb[AC_STATION_EVENTS_AP_ID])
        ap_id = blobmsg_get_string(tb[AC_STATION_EVENTS_AP_ID]);
    if (tb[AC_STATION_EVENTS_EVENT])
        event = blobmsg_get_string(tb[AC_STATION_EVENTS_EVENT]);
    if (tb[AC_STATION_EVENTS_START])
        start = ac_attr_get_s64(tb[AC_STATION_EVENTS_START]);
    if (tb[AC_STATION_EVENTS_END])
        end = ac_attr_get_s64(tb[AC_STATION_EVENTS_END]);
    if (tb[AC_STATION_EVENTS_LIMIT])
        limit = (int)blobmsg_get_u32(tb[AC_STATION_EVENTS_LIMIT]);
    if (tb[AC_STATION_EVENTS_AFTER_ID])
        after_id = ac_attr_get_s64(tb[AC_STATION_EVENTS_AFTER_ID]);
    if ((ap_id[0] && !ac_radio_job_ap_id_valid(ap_id)) ||
        (event[0] && strcmp(event, "connect") &&
         strcmp(event, "disconnect") && strcmp(event, "roam")) ||
        start <= 0 || end < start || limit < 1 || limit > 1024 ||
        after_id < 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_db_station_events_json(
        ap_id, event, start, end, limit, after_id));
}

/* Phase W1 read-only static validate; no capability is flipped and the
 * 2026-07-20 write gates stay fail-closed. */
static int ac_handle_wifi_transaction_validate(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__AC_WIFI_VALIDATE_MAX] = {0};
    const char *ap_id;
    const char *idempotency_key;
    const char *changes;
    int64_t base_revision;
    const unsigned int required = (1U << AC_WIFI_VALIDATE_AP_ID) |
                                  (1U << AC_WIFI_VALIDATE_BASE_REVISION) |
                                  (1U << AC_WIFI_VALIDATE_IDEMPOTENCY_KEY) |
                                  (1U << AC_WIFI_VALIDATE_CHANGES);

    (void)obj;
    (void)method;
    if (!ac_message_is_strict(msg, ac_wifi_validate_policy,
                              __AC_WIFI_VALIDATE_MAX, required) ||
        blobmsg_parse(ac_wifi_validate_parse_policy, __AC_WIFI_VALIDATE_MAX,
                      tb, blob_data(msg), blob_len(msg)) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    ap_id = blobmsg_get_string(tb[AC_WIFI_VALIDATE_AP_ID]);
    idempotency_key =
        blobmsg_get_string(tb[AC_WIFI_VALIDATE_IDEMPOTENCY_KEY]);
    changes = blobmsg_get_string(tb[AC_WIFI_VALIDATE_CHANGES]);
    base_revision = ac_attr_get_s64(tb[AC_WIFI_VALIDATE_BASE_REVISION]);
    if (!ac_radio_job_ap_id_valid(ap_id) ||
        !ac_radio_job_idempotency_valid(idempotency_key) ||
        base_revision < 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    return ac_reply_json(ctx, req, ac_db_wifi_transaction_validate_json(
        ap_id, base_revision, idempotency_key, changes, ac_now_s()));
}

static int ac_parse_token_id(struct blob_attr *msg, const char **token_id)
{
    struct blob_attr *tb[__AC_TOKEN_MAX];

    if (!token_id ||
        !ac_message_is_strict(msg, ac_token_policy, __AC_TOKEN_MAX,
                              1U << AC_TOKEN_ID) ||
        blobmsg_parse(ac_token_policy, __AC_TOKEN_MAX, tb,
                      blob_data(msg), blob_len(msg)) != 0)
        return -1;
    *token_id = blobmsg_get_string(tb[AC_TOKEN_ID]);
    return ac_token_id_valid(*token_id) ? 0 : -1;
}

static int ac_handle_pairing_token_status(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct json_object *response;
    const char *token_id;

    (void)obj;
    (void)method;
    if (ac_parse_token_id(msg, &token_id) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    response = ac_pairing_token_status_json(token_id);
    return ac_reply_json(ctx, req, response);
}

static int ac_handle_pairing_token_revoke(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct json_object *response;
    const char *token_id;

    (void)obj;
    (void)method;
    if (ac_parse_token_id(msg, &token_id) != 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    response = ac_pairing_token_revoke_json(token_id);
    return ac_reply_json(ctx, req, response);
}

static const struct ubus_method ac_methods[] = {
    UBUS_METHOD_NOARG("status", ac_handle_status),
    UBUS_METHOD_NOARG("capabilities", ac_handle_capabilities),
    UBUS_METHOD_NOARG("aps_list", ac_handle_aps_list),
    UBUS_METHOD("pairing_token_create", ac_handle_pairing_token_create,
                ac_create_policy),
    UBUS_METHOD_NOARG("pairing_token_list", ac_handle_pairing_token_list),
    UBUS_METHOD("pairing_token_status", ac_handle_pairing_token_status,
                ac_token_policy),
    UBUS_METHOD("pairing_token_revoke", ac_handle_pairing_token_revoke,
                ac_token_policy),
    UBUS_METHOD("radio_job_create", ac_handle_radio_job_create,
                ac_radio_job_create_policy),
    UBUS_METHOD("radio_job_status", ac_handle_radio_job_status,
                ac_radio_job_id_policy),
    UBUS_METHOD("radio_job_cancel", ac_handle_radio_job_cancel,
                ac_radio_job_id_policy),
    UBUS_METHOD("radio_job_result", ac_handle_radio_job_result,
                ac_radio_job_id_policy),
    UBUS_METHOD("radio_job_list", ac_handle_radio_job_list,
                ac_radio_job_list_policy),
    UBUS_METHOD_NOARG("radio_job_latest_results",
                      ac_handle_radio_job_latest_results),
    UBUS_METHOD("survey_history", ac_handle_survey_history,
                ac_survey_history_policy),
    UBUS_METHOD("station_events", ac_handle_station_events,
                ac_station_events_policy),
    UBUS_METHOD("wifi_transaction_validate",
                ac_handle_wifi_transaction_validate,
                ac_wifi_validate_policy),
};

static struct ubus_object_type ac_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt.ac", ac_methods);

static struct ubus_object ac_object = {
    .name = "dreamingwrt.ac",
    .type = &ac_object_type,
    .methods = ac_methods,
    .n_methods = ARRAY_SIZE(ac_methods),
};

static struct ubus_object ac_alias_object = {
    .name = "dreamingos.ac",
    .type = &ac_object_type,
    .methods = ac_methods,
    .n_methods = ARRAY_SIZE(ac_methods),
};

int ac_ubus_start(void)
{
    int rc;

    g_ac_ubus = ubus_connect(NULL);
    if (!g_ac_ubus)
        return -1;
    ubus_add_uloop(g_ac_ubus);
    rc = ubus_add_object(g_ac_ubus, &ac_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(g_ac_ubus);
        g_ac_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_ac_ubus, &ac_alias_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_remove_object(g_ac_ubus, &ac_object);
        ubus_free(g_ac_ubus);
        g_ac_ubus = NULL;
        return -1;
    }
    return 0;
}

void ac_ubus_stop(void)
{
    if (!g_ac_ubus)
        return;
    ubus_remove_object(g_ac_ubus, &ac_alias_object);
    ubus_remove_object(g_ac_ubus, &ac_object);
    ubus_free(g_ac_ubus);
    g_ac_ubus = NULL;
}
