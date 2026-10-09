// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_CLOUD_WEB_CLIENT_H
#define DREAMINGOS_CLOUD_WEB_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <json-c/json.h>
#include "protocol/control.h"
#include "protocol/session.h"
#include "protocol/transfer.h"

#define CWC_CONTEXT "dreamingos-cloud-web-v1"
#define CWC_SOCKET "/var/run/dreamingos-cloud-web.sock"
#define CWC_MAX_SERVICES 64
#define CWC_UPLOAD_MAX 262144u /* legacy buffered request / maximum receive window */
#define CWC_STREAM_UPLOAD_MAX (UINT64_C(1024) * 1024 * 1024)

/* Configuration is local authority. No target address comes from a frame. */
struct cwc_service {
    char id[64];
    char public_host[256];
    char target_host[256];
    char server_name[256];
    char ca_path[256];
    char tls_pin[53]; /* libcurl sha256// SPKI pin; requires a service-local trust file. */
    uint16_t port;
    int https;
    int management;
    int container;
};

struct cwc_config {
    char api_host[256];
    uint16_t api_port;
    char tunnel_host[256];
    uint16_t tunnel_port;
    char ca_path[256];
    char state_path[256];
    unsigned char services_key[32];
    char router_id[40];
    unsigned char kex_pub[32];
    EVP_PKEY *sign_key;
    int n_services;
    struct cwc_service services[CWC_MAX_SERVICES];
};

struct cwc_publication {
    uint32_t generation;
    int64_t revision;
    char cloud_id[33];
    char canonical_host[256];
    char error[96];
    int retry_after;
    int features_known, quota_known;
    unsigned features_v1, negotiated_v1;
    int64_t account_service_limit, account_services, device_services;
    int64_t account_connection_limit, account_bandwidth_bps;
};

static inline struct json_object *cwc_transfer_json(const struct cwc_publication *p)
{
    struct json_object *o = json_object_new_object(), *q = json_object_new_object();
    unsigned f = p->negotiated_v1;
    json_object_object_add(o, "capability_state", json_object_new_string(
        !p->features_known ? "unknown" : f ? "negotiated" :
        p->features_v1 ? "available" : "edge_unconfirmed"));
    json_object_object_add(o, "features_v1", json_object_new_int(p->features_v1));
    json_object_object_add(o, "negotiated_v1", json_object_new_int(f));
    json_object_object_add(o, "websocket", json_object_new_boolean(f & CW_FEATURE_WEBSOCKET));
    json_object_object_add(o, "sse", json_object_new_boolean(f & CW_FEATURE_STREAM));
    json_object_object_add(o, "upload_max_bytes", json_object_new_int64(
        f & CW_FEATURE_STREAM ? CW_TRANSFER_MAX : CW_LEGACY_UPLOAD));
    json_object_object_add(o, "response_max_bytes", json_object_new_int64(
        f & CW_FEATURE_STREAM ? CW_TRANSFER_MAX : CW_LEGACY_RESPONSE));
    json_object_object_add(q, "state", json_object_new_string(p->quota_known ? "enforced" : "unknown"));
    const char *names[] = {"service_limit", "services", "connection_limit", "bandwidth_bps"};
    int64_t values[] = {p->account_service_limit, p->account_services,
                       p->account_connection_limit, p->account_bandwidth_bps};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        json_object_object_add(q, names[i], p->quota_known ? json_object_new_int64(values[i]) : NULL);
    json_object_object_add(o, "account_quota", q);
    return o;
}

/* Strict-TLS, body-bound device proof. Reads the current revision, then
 * atomically replaces the published IDs (empty when enabled == 0). */
int cwc_publish(const struct cwc_config *config, int enabled,
                struct cwc_publication *result);
int cwc_publication_read(const struct cwc_config *config,
                         struct cwc_publication *result);

struct cwc_hooks {
    int (*running)(void *user);
    void (*status)(void *user, const char *state, const char *reason,
                   uint32_t generation, int64_t revision, int services);
    void *user;
    void (*publication)(void *user, const struct cwc_publication *result);
};

int cwc_host_valid(const char *host);
int cwc_address_allowed(const char *address, int container);
int cwc_service_valid(const struct cwc_service *service);
struct json_object *cwc_service_probe(const struct cwc_service *service);
int cwc_auth(const struct cwc_config *config, const char *challenge, size_t len,
             char *out, size_t cap);
int cwc_manifest(const struct cwc_config *config, const char *payload, size_t len,
                 int64_t previous_revision, struct cw_session *session,
                 int64_t *revision);
/* Run until stop; reconnect without replaying any request. */
int cwc_run(const struct cwc_config *config, const struct cwc_hooks *hooks);

#endif
