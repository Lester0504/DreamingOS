// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_internal.h"
#include "apd_paircode.h"
#include "apd_audit_forward.h"

static int apd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                         struct json_object *response)
{
    const char *text = response ? json_object_to_json_string(response) : "{}";

    blob_buf_init(&g_apd_blob, 0);
    if (!blobmsg_add_json_from_string(&g_apd_blob, text)) {
        blob_buf_free(&g_apd_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_apd_blob.head);
    blob_buf_free(&g_apd_blob);
    return UBUS_STATUS_OK;
}

static int apd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct json_object *response = apd_status_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_capabilities(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *response = apd_capabilities_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_snapshot(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *response = apd_snapshot_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_identity(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *response = apd_identity_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_pairing_status(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method, struct blob_attr *msg)
{
    struct json_object *response = apd_pairing_status_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

enum {
    APD_BLE_BEGIN_BOOTSTRAP_ID,
    APD_BLE_BEGIN_REQUEST_ID,
    APD_BLE_BEGIN_APP_PUBLIC_KEY,
    APD_BLE_BEGIN_PERIPHERAL_ID,
    __APD_BLE_BEGIN_MAX
};

static const struct blobmsg_policy apd_ble_begin_policy[__APD_BLE_BEGIN_MAX] = {
    [APD_BLE_BEGIN_BOOTSTRAP_ID] = {
        .name = "bootstrap_id", .type = BLOBMSG_TYPE_STRING
    },
    [APD_BLE_BEGIN_REQUEST_ID] = {
        .name = "request_id", .type = BLOBMSG_TYPE_STRING
    },
    [APD_BLE_BEGIN_APP_PUBLIC_KEY] = {
        .name = "app_public_key", .type = BLOBMSG_TYPE_STRING
    },
    [APD_BLE_BEGIN_PERIPHERAL_ID] = {
        .name = "ble_peripheral_id", .type = BLOBMSG_TYPE_STRING
    },
};

static int apd_handle_ble_provision_begin(struct ubus_context *ctx,
                                          struct ubus_object *obj,
                                          struct ubus_request_data *req,
                                          const char *method,
                                          struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_BLE_BEGIN_MAX];
    struct json_object *response;
    const char *bootstrap_id = NULL;
    const char *request_id = NULL;
    const char *app_public_key = NULL;
    const char *ble_peripheral_id = NULL;

    (void)obj; (void)method;
    blobmsg_parse(apd_ble_begin_policy, __APD_BLE_BEGIN_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (tb[APD_BLE_BEGIN_BOOTSTRAP_ID])
        bootstrap_id = blobmsg_get_string(tb[APD_BLE_BEGIN_BOOTSTRAP_ID]);
    if (tb[APD_BLE_BEGIN_REQUEST_ID])
        request_id = blobmsg_get_string(tb[APD_BLE_BEGIN_REQUEST_ID]);
    if (tb[APD_BLE_BEGIN_APP_PUBLIC_KEY])
        app_public_key = blobmsg_get_string(tb[APD_BLE_BEGIN_APP_PUBLIC_KEY]);
    if (tb[APD_BLE_BEGIN_PERIPHERAL_ID])
        ble_peripheral_id = blobmsg_get_string(tb[APD_BLE_BEGIN_PERIPHERAL_ID]);
    response = apd_ble_begin_json_ex(bootstrap_id, request_id,
                                     app_public_key, ble_peripheral_id);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

enum {
    APD_BLE_SESSION_ID,
    APD_BLE_SETUP_CODE,
    __APD_BLE_SESSION_MAX
};

static const struct blobmsg_policy apd_ble_session_policy[__APD_BLE_SESSION_MAX] = {
    [APD_BLE_SESSION_ID] = {
        .name = "session_id", .type = BLOBMSG_TYPE_STRING
    },
    [APD_BLE_SETUP_CODE] = {
        .name = "setup_code", .type = BLOBMSG_TYPE_STRING
    },
};

static int apd_handle_ble_provision_physical_confirm(
    struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_BLE_SESSION_MAX];
    struct json_object *response;
    const char *session_id = NULL;
    const char *setup_code = NULL;

    (void)obj; (void)method;
    blobmsg_parse(apd_ble_session_policy, __APD_BLE_SESSION_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (tb[APD_BLE_SESSION_ID])
        session_id = blobmsg_get_string(tb[APD_BLE_SESSION_ID]);
    if (tb[APD_BLE_SETUP_CODE])
        setup_code = blobmsg_get_string(tb[APD_BLE_SETUP_CODE]);
    response = apd_ble_physical_confirm_json_ex(session_id, setup_code);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

enum {
    APD_BLE_STAGE_SESSION_ID,
    APD_BLE_STAGE_PEER_PUBLIC,
    APD_BLE_STAGE_FRAME,
    __APD_BLE_STAGE_MAX
};

static const struct blobmsg_policy apd_ble_stage_policy[__APD_BLE_STAGE_MAX] = {
    [APD_BLE_STAGE_SESSION_ID] = {
        .name = "session_id", .type = BLOBMSG_TYPE_STRING
    },
    [APD_BLE_STAGE_PEER_PUBLIC] = {
        .name = "peer_public", .type = BLOBMSG_TYPE_STRING
    },
    [APD_BLE_STAGE_FRAME] = {
        .name = "frame", .type = BLOBMSG_TYPE_STRING
    },
};

static int apd_handle_ble_provision_stage(struct ubus_context *ctx,
                                          struct ubus_object *obj,
                                          struct ubus_request_data *req,
                                          const char *method,
                                          struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_BLE_STAGE_MAX];
    struct json_object *response;
    const char *session_id = NULL;
    const char *peer_public = NULL;
    const char *frame = NULL;

    (void)obj; (void)method;
    blobmsg_parse(apd_ble_stage_policy, __APD_BLE_STAGE_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (tb[APD_BLE_STAGE_SESSION_ID])
        session_id = blobmsg_get_string(tb[APD_BLE_STAGE_SESSION_ID]);
    if (tb[APD_BLE_STAGE_PEER_PUBLIC])
        peer_public = blobmsg_get_string(tb[APD_BLE_STAGE_PEER_PUBLIC]);
    if (tb[APD_BLE_STAGE_FRAME])
        frame = blobmsg_get_string(tb[APD_BLE_STAGE_FRAME]);
    response = apd_ble_stage_json(session_id, peer_public, frame);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_ble_provision_commit(struct ubus_context *ctx,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_BLE_SESSION_MAX];
    struct json_object *response;
    const char *session_id = NULL;

    (void)obj; (void)method;
    blobmsg_parse(apd_ble_session_policy, __APD_BLE_SESSION_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (tb[APD_BLE_SESSION_ID])
        session_id = blobmsg_get_string(tb[APD_BLE_SESSION_ID]);
    response = apd_ble_commit_json(session_id);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

enum {
    APD_UNPAIR_CONFIRM,
    __APD_UNPAIR_MAX
};

static const struct blobmsg_policy apd_unpair_policy[__APD_UNPAIR_MAX] = {
    [APD_UNPAIR_CONFIRM] = { .name = "confirm", .type = BLOBMSG_TYPE_BOOL },
};

/*
 * Destructive: drops the certificate and adoption state, after which the
 * controller can no longer manage this AP. The explicit confirm flag exists so
 * a mistyped or replayed call cannot unadopt a live AP; a missing flag is
 * refused by apd_unpair_json() rather than treated as consent.
 */
static int apd_handle_unpair(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_UNPAIR_MAX];
    struct json_object *response;
    int confirmed = 0;

    (void)obj; (void)method;
    blobmsg_parse(apd_unpair_policy, __APD_UNPAIR_MAX, tb, blob_data(msg),
                  blob_len(msg));
    if (tb[APD_UNPAIR_CONFIRM])
        confirmed = blobmsg_get_bool(tb[APD_UNPAIR_CONFIRM]);
    response = apd_unpair_json(confirmed);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

enum {
    APD_TXPOWER_MODE,
    APD_TXPOWER_CONFIRM,
    __APD_TXPOWER_MAX
};

static const struct blobmsg_policy apd_txpower_policy[__APD_TXPOWER_MAX] = {
    [APD_TXPOWER_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
    [APD_TXPOWER_CONFIRM] = { .name = "confirm", .type = BLOBMSG_TYPE_BOOL },
};

static int apd_handle_txpower_mode(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method, struct blob_attr *msg)
{
    struct json_object *response = apd_txpower_mode_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

/*
 * Raises the 6 GHz transmit ceiling above the EEPROM calibration. Only the
 * boards on the apd_txpower_mode allowlist accept this at all; everything
 * else is refused with board_not_standard_power_capable, because driving an
 * unqualified PA past its calibrated target damages it. The confirm flag is
 * required for the raising direction so a replayed call cannot enable it.
 */
static int apd_handle_txpower_mode_set(struct ubus_context *ctx,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_TXPOWER_MAX];
    struct json_object *response;
    const char *mode = NULL;
    int confirmed = 0;

    (void)obj; (void)method;
    blobmsg_parse(apd_txpower_policy, __APD_TXPOWER_MAX, tb, blob_data(msg),
                  blob_len(msg));
    if (tb[APD_TXPOWER_MODE])
        mode = blobmsg_get_string(tb[APD_TXPOWER_MODE]);
    if (tb[APD_TXPOWER_CONFIRM])
        confirmed = blobmsg_get_bool(tb[APD_TXPOWER_CONFIRM]);
    response = apd_txpower_mode_set_json(mode, confirmed);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_ble_status(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method, struct blob_attr *msg)
{
    struct json_object *response = apd_ble_status_json();

    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_ble_cancel(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_BLE_SESSION_MAX];
    struct json_object *response;
    const char *session_id = NULL;

    (void)obj; (void)method;
    blobmsg_parse(apd_ble_session_policy, __APD_BLE_SESSION_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (tb[APD_BLE_SESSION_ID])
        session_id = blobmsg_get_string(tb[APD_BLE_SESSION_ID]);
    response = apd_ble_cancel_json(session_id);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}


static int apd_handle_binding_qr(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
{
    struct apd_node_identity identity;
    struct apd_pairing_status pstatus;
    struct apd_binding_qr bqr;
    char qr_json[APD_BINDING_QR_MAX];
    struct json_object *root;
    int adopted;

    (void)obj; (void)method; (void)msg;
    memset(&identity, 0, sizeof(identity));
    memset(&pstatus, 0, sizeof(pstatus));
    memset(&bqr, 0, sizeof(bqr));

    if (apd_db_identity_get(&identity) != 0) {
        root = json_object_new_object();
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("local_state_unavailable"));
        json_object_object_add(root, "operation",
                               json_object_new_string("binding_qr"));
        json_object_object_add(root, "reason",
                               json_object_new_string("identity_read_failed"));
        apd_send_json(ctx, req, root);
        json_object_put(root);
        return UBUS_STATUS_OK;
    }
    apd_db_pairing_status_get(&pstatus);
    adopted = apd_transport_adopted();

    strncpy(bqr.ap_id, identity.ap_id, sizeof(bqr.ap_id) - 1);
    strncpy(bqr.key_id, identity.key_id, sizeof(bqr.key_id) - 1);
    /* MAC and mgmt_ip are best-effort; read from /proc/net if available. */
    {
        char mac[18] = "";
        FILE *fp = fopen("/sys/class/net/br-lan/address", "r");
        if (!fp) fp = fopen("/sys/class/net/eth0/address", "r");
        if (fp) {
            if (fscanf(fp, "%17s", mac) != 1)
                mac[0] = '\0';
            fclose(fp);
        }
        if (mac[0]) strncpy(bqr.mac, mac, sizeof(bqr.mac) - 1);
    }
    bqr.mgmt_port = 12517;
    bqr.expires_at = time(NULL) + APD_BINDING_TICKET_TTL;

    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "ap_id", json_object_new_string(identity.ap_id));
    json_object_object_add(root, "key_fingerprint",
                           json_object_new_string(identity.key_id));
    json_object_object_add(root, "model", json_object_new_string(bqr.model));
    json_object_object_add(root, "adopted", json_object_new_boolean(adopted));
    json_object_object_add(root, "enrollment_state",
                           json_object_new_string(pstatus.state));
    json_object_object_add(root, "state",
                           json_object_new_string(adopted ? "adopted" :
                               (!strcmp(pstatus.state, "pending") ?
                                "awaiting_confirmation" : "unpaired")));

    if (apd_binding_qr_generate_nonce(bqr.nonce, APD_BINDING_NONCE_LEN) == 0 &&
        apd_binding_qr_encode(&bqr, qr_json, sizeof(qr_json)) == 0) {
        json_object_object_add(root, "qr_payload",
                               json_object_new_string(qr_json));
    }
    json_object_object_add(root, "expires_at",
                           json_object_new_int64(bqr.expires_at));
    json_object_object_add(root, "poll_interval_ms", json_object_new_int(10000));

    apd_send_json(ctx, req, root);
    json_object_put(root);
    OPENSSL_cleanse(&identity, sizeof(identity));
    return UBUS_STATUS_OK;
}

enum {
    APD_AUDIT_EVENT_ID,
    APD_AUDIT_OCCURRED_AT,
    APD_AUDIT_ACTOR,
    APD_AUDIT_ACTOR_SESSION,
    APD_AUDIT_ACTION,
    APD_AUDIT_RISK,
    APD_AUDIT_TARGET,
    APD_AUDIT_SOURCE_IP,
    APD_AUDIT_RESULT,
    APD_AUDIT_FAILURE_REASON,
    APD_AUDIT_REQUEST_ID,
    __APD_AUDIT_MAX
};

static const struct blobmsg_policy apd_audit_policy[__APD_AUDIT_MAX] = {
    [APD_AUDIT_EVENT_ID] = {
        .name = "event_id", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_OCCURRED_AT] = {
        .name = "occurred_at", .type = BLOBMSG_TYPE_INT64 },
    [APD_AUDIT_ACTOR] = {
        .name = "actor", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_ACTOR_SESSION] = {
        .name = "actor_session", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_ACTION] = {
        .name = "action", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_RISK] = {
        .name = "risk", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_TARGET] = {
        .name = "target", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_SOURCE_IP] = {
        .name = "source_ip", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_RESULT] = {
        .name = "result", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_FAILURE_REASON] = {
        .name = "failure_reason", .type = BLOBMSG_TYPE_STRING },
    [APD_AUDIT_REQUEST_ID] = {
        .name = "request_id", .type = BLOBMSG_TYPE_STRING },
};

static int apd_audit_message_strict(struct blob_attr *msg)
{
    struct blob_attr *attr;
    unsigned int seen = 0;
    size_t rem;
    size_t i;

    if (!msg)
        return 0;
    blobmsg_for_each_attr(attr, msg, rem) {
        const char *name;

        if (!blobmsg_check_attr(attr, true))
            return 0;
        name = blobmsg_name(attr);
        for (i = 0; i < __APD_AUDIT_MAX; i++) {
            unsigned int bit = 1U << i;

            if (strcmp(name, apd_audit_policy[i].name) != 0)
                continue;
            if ((i == APD_AUDIT_OCCURRED_AT &&
                 blobmsg_type(attr) != BLOBMSG_TYPE_INT64) ||
                (i != APD_AUDIT_OCCURRED_AT &&
                 blobmsg_type(attr) != BLOBMSG_TYPE_STRING))
                return 0;
            if (seen & bit)
                return 0;
            seen |= bit;
            break;
        }
        if (i == __APD_AUDIT_MAX)
            return 0;
    }
    return rem == 0 &&
        (seen & (1U << APD_AUDIT_OCCURRED_AT)) &&
        (seen & (1U << APD_AUDIT_ACTOR)) &&
        (seen & (1U << APD_AUDIT_ACTOR_SESSION)) &&
        (seen & (1U << APD_AUDIT_ACTION)) &&
        (seen & (1U << APD_AUDIT_RISK)) &&
        (seen & (1U << APD_AUDIT_TARGET)) &&
        (seen & (1U << APD_AUDIT_SOURCE_IP)) &&
        (seen & (1U << APD_AUDIT_RESULT)) &&
        (seen & (1U << APD_AUDIT_FAILURE_REASON)) &&
        (seen & (1U << APD_AUDIT_REQUEST_ID));
}

static int apd_audit_copy(char *out, size_t out_len,
                          struct blob_attr *attr, int required)
{
    const char *value = attr ? blobmsg_get_string(attr) : "";
    size_t length = strlen(value);

    if (!out || out_len == 0 || length >= out_len ||
        (required && length == 0))
        return -1;
    memcpy(out, value, length + 1);
    return 0;
}

static int apd_handle_audit_event(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_AUDIT_MAX];
    struct apd_audit_event event;
    struct json_object *response;
    char reason[APD_AUDIT_REASON_LEN] = "";
    int rc;

    (void)obj;
    (void)method;
    memset(&event, 0, sizeof(event));
    if (!apd_audit_message_strict(msg) ||
        blobmsg_parse(apd_audit_policy, __APD_AUDIT_MAX, tb,
                      blob_data(msg), blob_len(msg)) != 0 ||
        apd_audit_copy(event.event_id, sizeof(event.event_id),
                       tb[APD_AUDIT_EVENT_ID], 0) != 0 ||
        (event.event_id[0] && !apd_audit_event_id_valid(event.event_id)) ||
        (event.occurred_at = (int64_t)blobmsg_get_u64(
            tb[APD_AUDIT_OCCURRED_AT])) <= 0 ||
        apd_audit_copy(event.actor, sizeof(event.actor),
                       tb[APD_AUDIT_ACTOR], 1) != 0 ||
        apd_audit_copy(event.actor_session, sizeof(event.actor_session),
                       tb[APD_AUDIT_ACTOR_SESSION], 0) != 0 ||
        apd_audit_copy(event.action, sizeof(event.action),
                       tb[APD_AUDIT_ACTION], 1) != 0 ||
        apd_audit_copy(event.risk, sizeof(event.risk),
                       tb[APD_AUDIT_RISK], 1) != 0 ||
        apd_audit_copy(event.target, sizeof(event.target),
                       tb[APD_AUDIT_TARGET], 1) != 0 ||
        apd_audit_copy(event.source_ip, sizeof(event.source_ip),
                       tb[APD_AUDIT_SOURCE_IP], 0) != 0 ||
        apd_audit_copy(event.result, sizeof(event.result),
                       tb[APD_AUDIT_RESULT], 1) != 0 ||
        apd_audit_copy(event.failure_reason, sizeof(event.failure_reason),
                       tb[APD_AUDIT_FAILURE_REASON], 0) != 0 ||
        apd_audit_copy(event.request_id, sizeof(event.request_id),
                       tb[APD_AUDIT_REQUEST_ID], 1) != 0) {
        response = json_object_new_object();
        json_object_object_add(response, "ok", json_object_new_boolean(0));
        json_object_object_add(response, "error",
                               json_object_new_string("invalid_audit_event"));
        rc = apd_send_json(ctx, req, response);
        json_object_put(response);
        return rc;
    }
    rc = apd_audit_forward_submit(&event, reason, sizeof(reason));
    response = json_object_new_object();
    json_object_object_add(response, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(response, "persisted",
                           json_object_new_boolean(rc == 0));
    json_object_object_add(response, "source",
                           json_object_new_string("ap_remote"));
    json_object_object_add(response, "event_id",
                           json_object_new_string(event.event_id));
    if (rc != 0) {
        json_object_object_add(response, "error",
            json_object_new_string("controller_audit_unavailable"));
        json_object_object_add(response, "reason",
            json_object_new_string(reason[0] ? reason :
                                   "controller_audit_unavailable"));
    }
    rc = apd_send_json(ctx, req, response);
    json_object_put(response);
    OPENSSL_cleanse(&event, sizeof(event));
    return rc;
}

static int apd_handle_audit_status(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method, struct blob_attr *msg)
{
    struct json_object *response = apd_audit_forward_status_json();
    (void)obj; (void)method; (void)msg;
    int rc = apd_send_json(ctx, req, response);
    json_object_put(response);
    return rc;
}

static int apd_handle_audit_reachable(struct ubus_context *ctx,
                                      struct ubus_object *obj,
                                      struct ubus_request_data *req,
                                      const char *method, struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    (void)obj; (void)method; (void)msg;
    json_object_object_add(resp, "ac_reachable",
                           json_object_new_boolean(apd_audit_forward_ac_reachable()));
    json_object_object_add(resp, "storage",
                           json_object_new_string("memory_only_no_outbox"));
    int rc = apd_send_json(ctx, req, resp);
    json_object_put(resp);
    return rc;
}

static const struct ubus_method apd_methods[] = {
    UBUS_METHOD_NOARG("status", apd_handle_status),
    UBUS_METHOD_NOARG("capabilities", apd_handle_capabilities),
    UBUS_METHOD_NOARG("identity", apd_handle_identity),
    UBUS_METHOD_NOARG("pairing_status", apd_handle_pairing_status),
    {
        .name = "snapshot",
        .handler = apd_handle_snapshot,
    },
    UBUS_METHOD("unpair", apd_handle_unpair, apd_unpair_policy),
    UBUS_METHOD_NOARG("txpower_mode", apd_handle_txpower_mode),
    UBUS_METHOD("txpower_mode_set", apd_handle_txpower_mode_set,
                apd_txpower_policy),
    UBUS_METHOD("ble_provision_begin", apd_handle_ble_provision_begin,
                apd_ble_begin_policy),
    UBUS_METHOD("ble_provision_physical_confirm",
                apd_handle_ble_provision_physical_confirm,
                apd_ble_session_policy),
    UBUS_METHOD("ble_provision_stage", apd_handle_ble_provision_stage,
                apd_ble_stage_policy),
    UBUS_METHOD("ble_provision_commit", apd_handle_ble_provision_commit,
                apd_ble_session_policy),
    UBUS_METHOD_NOARG("ble_provision_status", apd_handle_ble_status),
    UBUS_METHOD_NOARG("binding_qr", apd_handle_binding_qr),
    UBUS_METHOD("audit_event", apd_handle_audit_event, apd_audit_policy),
    UBUS_METHOD_NOARG("audit_status", apd_handle_audit_status),
    UBUS_METHOD_NOARG("audit_reachable", apd_handle_audit_reachable),
    UBUS_METHOD("ble_provision_cancel", apd_handle_ble_cancel,
                apd_ble_session_policy),
};

static struct ubus_object_type apd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt.apd", apd_methods);

static struct ubus_object apd_object = {
    .name = "dreamingwrt.apd",
    .type = &apd_object_type,
    .methods = apd_methods,
    .n_methods = ARRAY_SIZE(apd_methods),
};

static struct ubus_object apd_alias_object = {
    .name = "dreamingos.apd",
    .type = &apd_object_type,
    .methods = apd_methods,
    .n_methods = ARRAY_SIZE(apd_methods),
};

int apd_ubus_start(void)
{
    int rc;

    g_apd_ubus = ubus_connect(APD_UBUS_SOCKET_PATH);
    if (!g_apd_ubus)
        return -1;
    ubus_add_uloop(g_apd_ubus);
    rc = ubus_add_object(g_apd_ubus, &apd_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(g_apd_ubus);
        g_apd_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_apd_ubus, &apd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_remove_object(g_apd_ubus, &apd_object);
        ubus_free(g_apd_ubus);
        g_apd_ubus = NULL;
        return -1;
    }
    /* Item 6: subscribe to hostapd key-mismatch (SAE + PSK auth failures).
     * Best-effort -- a failure here must not stop the AP agent serving. */
    if (apd_hostapd_keymismatch_subscribe_start(g_apd_ubus) != 0)
        fprintf(stderr, "[%s] hostapd key-mismatch subscribe unavailable\n",
                APD_SERVICE_NAME);
    return 0;
}

void apd_ubus_stop(void)
{
    if (!g_apd_ubus)
        return;
    ubus_remove_object(g_apd_ubus, &apd_alias_object);
    ubus_remove_object(g_apd_ubus, &apd_object);
    ubus_free(g_apd_ubus);
    g_apd_ubus = NULL;
}
