// SPDX-License-Identifier: GPL-2.0-or-later
#define DREAMINGWRT_AC_INTERNAL_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#define AC_PAIRING_TOKEN_ID_LEN 36
#define AC_PAIRING_SITE_ID_LEN 64
#define AC_PAIRING_HARDWARE_DIGEST_LEN 71
#define AC_PAIRING_TOKEN_TTL_MIN 60
#define AC_PAIRING_TOKEN_TTL_MAX 86400
#define AC_PAIRING_TOKEN_ATTEMPTS_MAX 10
#define AC_AP_ONLINE_TIMEOUT_SECONDS 45
#define AC_RADIO_JOB_IDEMPOTENCY_MAX 128
#define AC_SURVEY_HISTORY_LIMIT_MAX 4096

#define BLOBMSG_TYPE_UNSPEC 0
#define BLOBMSG_TYPE_INT32 1
#define BLOBMSG_TYPE_STRING 2
#define BLOBMSG_TYPE_INT64 3
#define UBUS_STATUS_OK 0
#define UBUS_STATUS_INVALID_ARGUMENT 2
#define UBUS_STATUS_UNKNOWN_ERROR 7
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct blob_attr {
    const char *name;
    int type;
    uint32_t u32;
    uint64_t u64;
    const char *string;
    struct blob_attr *children;
    size_t child_count;
    int valid;
};

struct blobmsg_policy {
    const char *name;
    int type;
};

struct blob_buf {
    char *head;
};

struct ubus_context { int unused; };
struct ubus_request_data { int unused; };
struct ubus_object;
typedef int (*ubus_handler_t)(struct ubus_context *, struct ubus_object *,
                              struct ubus_request_data *, const char *,
                              struct blob_attr *);
struct ubus_method {
    const char *name;
    ubus_handler_t handler;
    const struct blobmsg_policy *policy;
};
struct ubus_object_type {
    const char *name;
    const struct ubus_method *methods;
    size_t n_methods;
};
struct ubus_object {
    const char *name;
    struct ubus_object_type *type;
    const struct ubus_method *methods;
    size_t n_methods;
};

#define UBUS_METHOD(name_, handler_, policy_) \
    { .name = (name_), .handler = (handler_), .policy = (policy_) }
#define UBUS_METHOD_NOARG(name_, handler_) \
    { .name = (name_), .handler = (handler_), .policy = NULL }
#define UBUS_OBJECT_TYPE(name_, methods_) \
    { .name = (name_), .methods = (methods_), .n_methods = ARRAY_SIZE(methods_) }
#define blob_data(msg) (msg)
#define blob_len(msg) ((int)(msg)->child_count)
#define blobmsg_for_each_attr(attr, msg, rem) \
    for ((rem) = (msg) ? (int)(msg)->child_count : 0, \
         (attr) = (msg) ? (msg)->children : NULL; \
         (rem) > 0 && (attr); (rem)--, (attr)++)

struct ubus_context *g_ac_ubus;
struct blob_buf g_ac_blob;

static int g_send_rc;
static int g_json_add_ok = 1;
static char *g_last_reply;
static int g_create_calls;
static int64_t g_ttl;
static int g_attempts;
static char g_site[AC_PAIRING_SITE_ID_LEN + 1];
static char g_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
static char g_token_id[AC_PAIRING_TOKEN_ID_LEN + 1];

static int blobmsg_check_attr(struct blob_attr *attr, bool name)
{
    (void)name;
    return attr && attr->valid;
}

static const char *blobmsg_name(struct blob_attr *attr)
{
    return attr->name;
}

static int blobmsg_type(struct blob_attr *attr)
{
    return attr->type;
}

static uint32_t blobmsg_get_u32(struct blob_attr *attr)
{
    return attr->u32;
}

static uint64_t blobmsg_get_u64(struct blob_attr *attr)
{
    return attr->u64;
}

static const char *blobmsg_get_string(struct blob_attr *attr)
{
    return attr->string;
}

static int blobmsg_parse(const struct blobmsg_policy *policy, int policy_len,
                         struct blob_attr **tb, void *data, int len)
{
    struct blob_attr *msg = data;
    int i;
    size_t j;

    (void)len;
    memset(tb, 0, sizeof(*tb) * (size_t)policy_len);
    if (!msg)
        return -1;
    for (j = 0; j < msg->child_count; j++) {
        for (i = 0; i < policy_len; i++) {
            /* Real blobmsg_parse() treats BLOBMSG_TYPE_UNSPEC policy
             * entries as accept-any; type-checked entries must match. */
            if (!strcmp(msg->children[j].name, policy[i].name) &&
                (policy[i].type == BLOBMSG_TYPE_UNSPEC ||
                 msg->children[j].type == policy[i].type) && !tb[i]) {
                tb[i] = &msg->children[j];
                break;
            }
        }
    }
    return 0;
}

static void blob_buf_init(struct blob_buf *buf, int id)
{
    (void)id;
    free(buf->head);
    buf->head = NULL;
}

static int blobmsg_add_json_from_string(struct blob_buf *buf, const char *text)
{
    if (!g_json_add_ok)
        return 0;
    buf->head = strdup(text);
    return buf->head != NULL;
}

static void blob_buf_free(struct blob_buf *buf)
{
    free(buf->head);
    buf->head = NULL;
}

static int ubus_send_reply(struct ubus_context *ctx,
                           struct ubus_request_data *req, void *head)
{
    (void)ctx;
    (void)req;
    free(g_last_reply);
    g_last_reply = head ? strdup((const char *)head) : NULL;
    return g_send_rc;
}

static struct ubus_context *ubus_connect(const char *path)
{
    static struct ubus_context context;
    (void)path;
    return &context;
}

static void ubus_add_uloop(struct ubus_context *ctx) { (void)ctx; }
static int ubus_add_object(struct ubus_context *ctx, struct ubus_object *obj)
{
    (void)ctx; (void)obj; return UBUS_STATUS_OK;
}
static void ubus_remove_object(struct ubus_context *ctx, struct ubus_object *obj)
{
    (void)ctx; (void)obj;
}
static void ubus_free(struct ubus_context *ctx) { (void)ctx; }

static struct json_object *fixture_response(const char *operation)
{
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "operation", json_object_new_string(operation));
    json_object_object_add(root, "mtls_ready", json_object_new_boolean(0));
    json_object_object_add(root, "adopted", json_object_new_boolean(0));
    return root;
}

struct json_object *ac_status_json(void) { return fixture_response("status"); }
struct json_object *ac_capabilities_json(void)
{
    return fixture_response("capabilities");
}
int64_t ac_now_s(void) { return 1000; }
struct json_object *ac_db_aps_list_json(int64_t observed_at,
                                        int64_t online_since)
{
    struct json_object *root = fixture_response("aps_list");
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(root, "online_since",
                           json_object_new_int64(online_since));
    return root;
}
struct json_object *ac_pairing_token_create_json(int64_t ttl_seconds,
                                                  int max_attempts,
                                                  const char *site_id,
                                                  const char *hardware_digest)
{
    struct json_object *root = fixture_response("pairing_token_create");
    g_create_calls++;
    g_ttl = ttl_seconds;
    g_attempts = max_attempts;
    snprintf(g_site, sizeof(g_site), "%s", site_id);
    snprintf(g_hardware, sizeof(g_hardware), "%s", hardware_digest);
    json_object_object_add(root, "token_id", json_object_new_string(
        "12345678-1234-4123-8123-123456789abc"));
    json_object_object_add(root, "token", json_object_new_string(
        "secret-sentinel-01234567890123456789012345"));
    json_object_object_add(root, "display_once", json_object_new_boolean(1));
    return root;
}
struct json_object *ac_pairing_token_list_json(void)
{
    return fixture_response("pairing_token_list");
}
struct json_object *ac_pairing_token_status_json(const char *token_id)
{
    snprintf(g_token_id, sizeof(g_token_id), "%s", token_id);
    return fixture_response("pairing_token_status");
}
struct json_object *ac_pairing_token_revoke_json(const char *token_id)
{
    snprintf(g_token_id, sizeof(g_token_id), "%s", token_id);
    return fixture_response("pairing_token_revoke");
}

static int g_survey_calls;
static int64_t g_survey_start;
static int64_t g_survey_end;
static int64_t g_survey_after_id;
static int g_survey_limit;
static int g_survey_resolution_seconds;
static char g_survey_ap_id[64];
static char g_survey_radio_id[32];

struct json_object *ac_db_survey_history_json(const char *ap_id,
                                              const char *radio_id,
                                              int64_t start, int64_t end,
                                              int resolution_seconds,
                                              int limit, int64_t after_id)
{
    g_survey_calls++;
    g_survey_start = start;
    g_survey_end = end;
    g_survey_after_id = after_id;
    g_survey_limit = limit;
    g_survey_resolution_seconds = resolution_seconds;
    snprintf(g_survey_ap_id, sizeof(g_survey_ap_id), "%s", ap_id ? ap_id : "");
    snprintf(g_survey_radio_id, sizeof(g_survey_radio_id), "%s",
             radio_id ? radio_id : "");
    return fixture_response("survey_history");
}

struct json_object *ac_radio_job_create_json(const char *ap_id,
                                             const char *radio_id,
                                             const char *mode,
                                             const char *idempotency_key)
{
    (void)ap_id; (void)radio_id; (void)mode; (void)idempotency_key;
    return fixture_response("radio_job_create");
}

struct json_object *ac_radio_job_status_json(const char *job_id)
{
    (void)job_id;
    return fixture_response("radio_job_status");
}

struct json_object *ac_radio_job_list_json(const char *ap_id)
{
    (void)ap_id;
    return fixture_response("radio_job_list");
}

struct json_object *ac_radio_job_cancel_json(const char *job_id)
{
    (void)job_id;
    return fixture_response("radio_job_cancel");
}

struct json_object *ac_radio_job_result_json(const char *job_id)
{
    (void)job_id;
    return fixture_response("radio_job_result");
}

struct json_object *ac_radio_job_latest_results_json(void)
{
    return fixture_response("radio_job_latest_results");
}

struct json_object *ac_db_station_events_json(const char *ap_id,
                                              const char *event,
                                              int64_t start, int64_t end,
                                              int limit, int64_t after_id)
{
    (void)ap_id; (void)event; (void)start; (void)end;
    (void)limit; (void)after_id;
    return fixture_response("station_events");
}

struct json_object *ac_db_wifi_transaction_validate_json(
    const char *ap_id, int64_t base_revision, const char *idempotency_key,
    const char *changes_json, int64_t now)
{
    (void)ap_id; (void)base_revision; (void)idempotency_key;
    (void)changes_json; (void)now;
    return fixture_response("wifi_transaction_validate");
}

#include "../src/ac/ac_ubus.c"

static const struct ubus_method *method_named(const char *name)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(ac_methods); i++)
        if (!strcmp(ac_methods[i].name, name))
            return &ac_methods[i];
    return NULL;
}

static int call_method(const char *name, struct blob_attr *msg)
{
    const struct ubus_method *method = method_named(name);
    struct ubus_context context;
    struct ubus_request_data request;

    assert(method != NULL);
    return method->handler(&context, &ac_object, &request, name, msg);
}

static struct blob_attr attr_u32(const char *name, uint32_t value)
{
    struct blob_attr attr = {
        .name = name, .type = BLOBMSG_TYPE_INT32, .u32 = value, .valid = 1
    };
    return attr;
}

static struct blob_attr attr_u64(const char *name, uint64_t value)
{
    struct blob_attr attr = {
        .name = name, .type = BLOBMSG_TYPE_INT64, .u64 = value, .valid = 1
    };
    return attr;
}

static struct blob_attr attr_string(const char *name, const char *value)
{
    struct blob_attr attr = {
        .name = name, .type = BLOBMSG_TYPE_STRING, .string = value, .valid = 1
    };
    return attr;
}

static struct blob_attr message(struct blob_attr *attrs, size_t count)
{
    struct blob_attr msg = {
        .children = attrs, .child_count = count, .valid = 1
    };
    return msg;
}

static void assert_no_secret(const char *reply)
{
    assert(reply != NULL);
    assert(strstr(reply, "secret-sentinel") == NULL);
    assert(strstr(reply, "token_hash") == NULL);
    assert(strstr(reply, "hardware_digest") == NULL);
}

static void test_method_set(void)
{
    const char *required[] = {"status", "capabilities", "aps_list",
                              "pairing_token_create", "pairing_token_list",
                              "pairing_token_status", "pairing_token_revoke",
                              "radio_job_create", "radio_job_status",
                              "radio_job_cancel", "radio_job_result",
                              "radio_job_list", "radio_job_latest_results",
                              "survey_history", "station_events",
                              "wifi_transaction_validate"};
    size_t i;

    assert(ARRAY_SIZE(ac_methods) == ARRAY_SIZE(required));
    for (i = 0; i < ARRAY_SIZE(required); i++)
        assert(method_named(required[i]) != NULL);
    assert(method_named("pairing_token_redeem") == NULL);
}

static void test_survey_history_accepts_int32_encoded_timestamps(void)
{
    /* JSON bridges encode 32-bit-representable integers as INT32, so the
     * INT64 contract fields must accept the widening.  This is exactly
     * the frame webd sends for a browser range request. */
    struct blob_attr widened[] = {
        attr_u32("start", 1784600000u), attr_u32("end", 1784643200u),
        attr_u32("limit", 16), attr_u32("after_id", 5),
        attr_string("resolution", "300"),
    };
    struct blob_attr widened_msg = message(widened, ARRAY_SIZE(widened));
    struct blob_attr native[] = {
        attr_u64("start", 1784600000ull), attr_u64("end", 1784643200ull),
        attr_u64("after_id", 7),
    };
    struct blob_attr native_msg = message(native, ARRAY_SIZE(native));

    g_survey_calls = 0;
    assert(call_method("survey_history", &widened_msg) == UBUS_STATUS_OK);
    assert(g_survey_calls == 1);
    assert(g_survey_start == 1784600000 && g_survey_end == 1784643200);
    assert(g_survey_after_id == 5 && g_survey_limit == 16);
    assert(g_survey_resolution_seconds == 300);
    assert(g_last_reply && strstr(g_last_reply, "survey_history"));

    assert(call_method("survey_history", &native_msg) == UBUS_STATUS_OK);
    assert(g_survey_calls == 2);
    assert(g_survey_start == 1784600000 && g_survey_after_id == 7);
}

static void test_survey_history_still_rejects_real_type_errors(void)
{
    struct blob_attr string_start[] = {
        attr_string("start", "1784600000"), attr_u32("end", 1784643200u),
    };
    struct blob_attr string_start_msg = message(string_start,
                                                ARRAY_SIZE(string_start));
    /* Narrowing INT64 -> INT32 policy stays rejected: limit is INT32. */
    struct blob_attr wide_limit[] = {
        attr_u32("start", 1784600000u), attr_u32("end", 1784643200u),
        attr_u64("limit", 16),
    };
    struct blob_attr wide_limit_msg = message(wide_limit,
                                              ARRAY_SIZE(wide_limit));
    struct blob_attr negative_start[] = {
        attr_u32("start", (uint32_t)-5), attr_u32("end", 1784643200u),
    };
    struct blob_attr negative_msg = message(negative_start,
                                            ARRAY_SIZE(negative_start));
    struct blob_attr inverted[] = {
        attr_u32("start", 1784643200u), attr_u32("end", 1784600000u),
    };
    struct blob_attr inverted_msg = message(inverted, ARRAY_SIZE(inverted));
    struct blob_attr unknown[] = {
        attr_u32("start", 1784600000u), attr_u32("end", 1784643200u),
        attr_u32("extra", 1),
    };
    struct blob_attr unknown_msg = message(unknown, ARRAY_SIZE(unknown));
    int before = g_survey_calls;

    assert(call_method("survey_history", &string_start_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("survey_history", &wide_limit_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("survey_history", &negative_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("survey_history", &inverted_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("survey_history", &unknown_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(g_survey_calls == before);
}

static void test_create(void)
{
    char digest[] = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    struct blob_attr attrs[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", "site-fixture"),
        attr_string("hardware_digest", digest),
    };
    struct blob_attr msg = message(attrs, ARRAY_SIZE(attrs));

    assert(call_method("pairing_token_create", &msg) == UBUS_STATUS_OK);
    assert(g_create_calls == 1 && g_ttl == 600 && g_attempts == 5);
    assert(!strcmp(g_site, "site-fixture") && !strcmp(g_hardware, digest));
    assert(g_last_reply && strstr(g_last_reply, "secret-sentinel"));
    assert(strstr(g_last_reply, "\"display_once\"") &&
           strstr(g_last_reply, "true"));
    assert(strstr(g_last_reply, "\"mtls_ready\"") &&
           strstr(g_last_reply, "false"));
    assert(strstr(g_last_reply, "\"adopted\""));
}

static void assert_bad_create(struct blob_attr *attrs, size_t count)
{
    struct blob_attr msg = message(attrs, count);
    int before = g_create_calls;
    assert(call_method("pairing_token_create", &msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(g_create_calls == before);
}

static void test_create_rejects_invalid_input(void)
{
    char long_site[AC_PAIRING_SITE_ID_LEN + 2];
    struct blob_attr missing[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", "site-fixture"),
    };
    struct blob_attr unknown[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", ""), attr_string("hardware_digest", ""),
        attr_string("extra", "rejected"),
    };
    struct blob_attr duplicate[] = {
        attr_u32("ttl_seconds", 600), attr_u32("ttl_seconds", 601),
        attr_u32("max_attempts", 5), attr_string("site_id", ""),
        attr_string("hardware_digest", ""),
    };
    struct blob_attr wrong_type[] = {
        attr_string("ttl_seconds", "600"), attr_u32("max_attempts", 5),
        attr_string("site_id", ""), attr_string("hardware_digest", ""),
    };
    struct blob_attr ttl_low[] = {
        attr_u32("ttl_seconds", AC_PAIRING_TOKEN_TTL_MIN - 1),
        attr_u32("max_attempts", 5), attr_string("site_id", ""),
        attr_string("hardware_digest", ""),
    };
    struct blob_attr ttl_high[] = {
        attr_u32("ttl_seconds", AC_PAIRING_TOKEN_TTL_MAX + 1),
        attr_u32("max_attempts", 5), attr_string("site_id", ""),
        attr_string("hardware_digest", ""),
    };
    struct blob_attr attempts_zero[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 0),
        attr_string("site_id", ""), attr_string("hardware_digest", ""),
    };
    struct blob_attr attempts_high[] = {
        attr_u32("ttl_seconds", 600),
        attr_u32("max_attempts", AC_PAIRING_TOKEN_ATTEMPTS_MAX + 1),
        attr_string("site_id", ""), attr_string("hardware_digest", ""),
    };
    struct blob_attr bad_site[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", "bad site"), attr_string("hardware_digest", ""),
    };
    struct blob_attr bad_digest[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", ""), attr_string("hardware_digest", "sha256:no"),
    };
    struct blob_attr long_site_attrs[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", long_site), attr_string("hardware_digest", ""),
    };
    struct blob_attr malformed[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", ""), attr_string("hardware_digest", ""),
    };

    memset(long_site, 'a', sizeof(long_site) - 1);
    long_site[sizeof(long_site) - 1] = '\0';
    malformed[2].valid = 0;

    assert_bad_create(missing, ARRAY_SIZE(missing));
    assert_bad_create(unknown, ARRAY_SIZE(unknown));
    assert_bad_create(duplicate, ARRAY_SIZE(duplicate));
    assert_bad_create(wrong_type, ARRAY_SIZE(wrong_type));
    assert_bad_create(ttl_low, ARRAY_SIZE(ttl_low));
    assert_bad_create(ttl_high, ARRAY_SIZE(ttl_high));
    assert_bad_create(attempts_zero, ARRAY_SIZE(attempts_zero));
    assert_bad_create(attempts_high, ARRAY_SIZE(attempts_high));
    assert_bad_create(bad_site, ARRAY_SIZE(bad_site));
    assert_bad_create(bad_digest, ARRAY_SIZE(bad_digest));
    assert_bad_create(long_site_attrs, ARRAY_SIZE(long_site_attrs));
    assert_bad_create(malformed, ARRAY_SIZE(malformed));
}

static void test_create_accepts_range_edges(void)
{
    char site[AC_PAIRING_SITE_ID_LEN + 1];
    struct blob_attr minimum[] = {
        attr_u32("ttl_seconds", AC_PAIRING_TOKEN_TTL_MIN),
        attr_u32("max_attempts", 1), attr_string("site_id", ""),
        attr_string("hardware_digest", ""),
    };
    struct blob_attr maximum[] = {
        attr_u32("ttl_seconds", AC_PAIRING_TOKEN_TTL_MAX),
        attr_u32("max_attempts", AC_PAIRING_TOKEN_ATTEMPTS_MAX),
        attr_string("site_id", site), attr_string("hardware_digest", ""),
    };
    struct blob_attr min_msg = message(minimum, ARRAY_SIZE(minimum));
    struct blob_attr max_msg = message(maximum, ARRAY_SIZE(maximum));

    memset(site, 'a', sizeof(site) - 1);
    site[sizeof(site) - 1] = '\0';
    assert(call_method("pairing_token_create", &min_msg) == UBUS_STATUS_OK);
    assert(g_ttl == AC_PAIRING_TOKEN_TTL_MIN && g_attempts == 1);
    assert(call_method("pairing_token_create", &max_msg) == UBUS_STATUS_OK);
    assert(g_ttl == AC_PAIRING_TOKEN_TTL_MAX &&
           g_attempts == AC_PAIRING_TOKEN_ATTEMPTS_MAX);
    assert(strlen(g_site) == AC_PAIRING_SITE_ID_LEN);
}

static void test_readback_and_revoke(void)
{
    const char *uuid = "12345678-1234-4123-8123-123456789abc";
    struct blob_attr attrs[] = {attr_string("token_id", uuid)};
    struct blob_attr msg = message(attrs, ARRAY_SIZE(attrs));
    struct blob_attr uppercase_attrs[] = {
        attr_string("token_id", "12345678-1234-4123-8123-123456789ABC")
    };
    struct blob_attr uppercase = message(uppercase_attrs,
                                          ARRAY_SIZE(uppercase_attrs));
    struct blob_attr unknown_attrs[] = {
        attr_string("token_id", uuid), attr_string("extra", "rejected")
    };
    struct blob_attr unknown = message(unknown_attrs, ARRAY_SIZE(unknown_attrs));
    struct blob_attr duplicate_attrs[] = {
        attr_string("token_id", uuid), attr_string("token_id", uuid)
    };
    struct blob_attr duplicate = message(duplicate_attrs,
                                          ARRAY_SIZE(duplicate_attrs));
    struct blob_attr wrong_type_attrs[] = {attr_u32("token_id", 1)};
    struct blob_attr wrong_type = message(wrong_type_attrs,
                                          ARRAY_SIZE(wrong_type_attrs));
    struct blob_attr empty = message(NULL, 0);
    struct blob_attr list_arg_attrs[] = {attr_string("token_id", uuid)};
    struct blob_attr list_arg = message(list_arg_attrs,
                                        ARRAY_SIZE(list_arg_attrs));

    assert(call_method("pairing_token_list", NULL) == UBUS_STATUS_OK);
    assert_no_secret(g_last_reply);
    assert(call_method("pairing_token_list", &list_arg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("pairing_token_status", &msg) == UBUS_STATUS_OK);
    assert(!strcmp(g_token_id, uuid));
    assert_no_secret(g_last_reply);
    assert(call_method("pairing_token_revoke", &msg) == UBUS_STATUS_OK);
    assert(!strcmp(g_token_id, uuid));
    assert_no_secret(g_last_reply);
    assert(call_method("pairing_token_status", &uppercase) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("pairing_token_status", &unknown) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("pairing_token_status", &duplicate) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("pairing_token_status", &wrong_type) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("pairing_token_status", &empty) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("pairing_token_revoke", NULL) ==
           UBUS_STATUS_INVALID_ARGUMENT);
}

static void test_send_failures_propagate(void)
{
    const char *uuid = "12345678-1234-4123-8123-123456789abc";
    struct blob_attr token_attrs[] = {attr_string("token_id", uuid)};
    struct blob_attr token_msg = message(token_attrs, ARRAY_SIZE(token_attrs));
    struct blob_attr create_attrs[] = {
        attr_u32("ttl_seconds", 600), attr_u32("max_attempts", 5),
        attr_string("site_id", ""), attr_string("hardware_digest", ""),
    };
    struct blob_attr create_msg = message(create_attrs, ARRAY_SIZE(create_attrs));

    g_send_rc = 19;
    assert(call_method("status", NULL) == 19);
    assert(call_method("capabilities", NULL) == 19);
    assert(call_method("pairing_token_create", &create_msg) == 19);
    assert(call_method("pairing_token_list", NULL) == 19);
    assert(call_method("pairing_token_status", &token_msg) == 19);
    assert(call_method("pairing_token_revoke", &token_msg) == 19);
    g_send_rc = UBUS_STATUS_OK;
    g_json_add_ok = 0;
    assert(call_method("status", NULL) == UBUS_STATUS_UNKNOWN_ERROR);
    g_json_add_ok = 1;
}

static void test_wifi_transaction_validate_contract(void)
{
    const char *ap = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    /* JSON bridges narrow small integers, so base_revision (INT64
     * contract) must accept an INT32 encoding like the other 64-bit
     * fields. */
    struct blob_attr widened[] = {
        attr_string("ap_id", ap), attr_u32("base_revision", 0),
        attr_string("idempotency_key", "web.validate.1"),
        attr_string("changes", "{\"radios\":[]}"),
    };
    struct blob_attr widened_msg = message(widened, ARRAY_SIZE(widened));
    struct blob_attr native[] = {
        attr_string("ap_id", ap), attr_u64("base_revision", 3),
        attr_string("idempotency_key", "web.validate.2"),
        attr_string("changes", "{}"),
    };
    struct blob_attr native_msg = message(native, ARRAY_SIZE(native));
    struct blob_attr missing_changes[] = {
        attr_string("ap_id", ap), attr_u32("base_revision", 0),
        attr_string("idempotency_key", "web.validate.3"),
    };
    struct blob_attr missing_msg = message(missing_changes,
                                           ARRAY_SIZE(missing_changes));
    struct blob_attr unknown[] = {
        attr_string("ap_id", ap), attr_u32("base_revision", 0),
        attr_string("idempotency_key", "web.validate.4"),
        attr_string("changes", "{}"), attr_u32("extra", 1),
    };
    struct blob_attr unknown_msg = message(unknown, ARRAY_SIZE(unknown));
    struct blob_attr bad_ap[] = {
        attr_string("ap_id", "not-a-uuid"), attr_u32("base_revision", 0),
        attr_string("idempotency_key", "web.validate.5"),
        attr_string("changes", "{}"),
    };
    struct blob_attr bad_ap_msg = message(bad_ap, ARRAY_SIZE(bad_ap));

    assert(call_method("wifi_transaction_validate", &widened_msg) ==
           UBUS_STATUS_OK);
    assert(g_last_reply &&
           strstr(g_last_reply, "wifi_transaction_validate"));
    assert(call_method("wifi_transaction_validate", &native_msg) ==
           UBUS_STATUS_OK);
    assert(call_method("wifi_transaction_validate", &missing_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("wifi_transaction_validate", &unknown_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
    assert(call_method("wifi_transaction_validate", &bad_ap_msg) ==
           UBUS_STATUS_INVALID_ARGUMENT);
}

int main(void)
{
    test_method_set();
    test_create();
    test_create_rejects_invalid_input();
    test_create_accepts_range_edges();
    test_readback_and_revoke();
    test_survey_history_accepts_int32_encoded_timestamps();
    test_survey_history_still_rejects_real_type_errors();
    test_wifi_transaction_validate_contract();
    test_send_failures_propagate();
    free(g_last_reply);
    free(g_ac_blob.head);
    puts("ok: AC management pairing ubus is strict, secret-safe, and excludes redeem");
    return 0;
}
