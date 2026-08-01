// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dreamingos-cloud: router-side agent for the zero-knowledge cloud relay.
 *
 * Trust model (design A, see DreamingWrtIOS/Docs/RELAY_REMOTE_ACCESS_GAPS.md):
 * the relay routes frames by router_id and never holds a key that opens them.
 * This daemon owns the router half of that contract:
 *
 *   1. a long-term X25519 identity whose public half is handed to the App
 *      during LAN pairing (webd returns it in pair/confirm and login),
 *   2. an outbound tunnel to the relay so no inbound port has to be opened,
 *   3. per-request unsealing of App traffic and replay of the inner request
 *      against the local webd on 127.0.0.1, then resealing the response.
 *
 * Nothing here terminates App trust: a frame whose Ed25519 signature does not
 * match a key registered in app_devices during pairing is refused outright.
 */
#ifndef DREAMINGOS_CLOUD_INTERNAL_H
#define DREAMINGOS_CLOUD_INTERNAL_H

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sqlite3.h>
#include <uci.h>

#define CLOUD_SERVICE_NAME "dreamingos-cloud"
#define CLOUD_CONTRACT_VERSION "relay-e2ee.v1"

/*
 * Domain separation string. It is shared verbatim with the App
 * (RelaySession.keyDerivationContext) and any change to it is an intentional
 * compatibility break that both sides must make together.
 */
#define CLOUD_E2EE_CONTEXT "dreamingos-relay-e2ee-v1"
#define CLOUD_PROTOCOL "dreamingos-relay"
#define CLOUD_PROTOCOL_VERSION 1

/* Matches the AC<->AP control protocol and the relay's Go implementation. */
#define CLOUD_FRAME_MAX (64U * 1024U)
#define CLOUD_IO_TIMEOUT_MS 10000

#define CLOUD_X25519_KEY_LEN 32
#define CLOUD_ED25519_KEY_LEN 32
#define CLOUD_ED25519_SIG_LEN 64
#define CLOUD_TRAFFIC_KEY_LEN 32
#define CLOUD_CHACHA_NONCE_LEN 12
#define CLOUD_CHACHA_TAG_LEN 16

/* Identity and state live next to the other component state. */
#define CLOUD_STATE_DIR "/etc/dreamingwrt/cloud"
#define CLOUD_IDENTITY_PATH CLOUD_STATE_DIR "/identity.x25519"
#define CLOUD_ROUTER_ID_PATH CLOUD_STATE_DIR "/router_id"
#define CLOUD_APP_DB_PATH "/etc/dreamingwrt/app_api.db"

/* Local webd. The inner request is replayed here as ordinary HTTP. */
#define CLOUD_LOCAL_HOST "127.0.0.1"
#define CLOUD_LOCAL_PORT 12517

/*
 * Inner requests carry an issued_at; anything outside this window is refused so
 * a captured frame cannot be replayed indefinitely. Generous enough to tolerate
 * a phone with a somewhat wrong clock.
 */
#define CLOUD_ISSUED_AT_SKEW_S 300

/* Bounded replay cache of recently served request ids. */
#define CLOUD_REPLAY_CACHE_SIZE 512

#define CLOUD_UUID_LEN 36
#define CLOUD_ROUTER_ID_MAX 128
#define CLOUD_REQUEST_ID_MAX 128

/* ── shared globals ───────────────────────────────────────────────── */

extern struct ubus_context *g_cloud_ubus;
extern struct blob_buf g_cloud_blob;
extern int64_t g_cloud_started_at;

int64_t cloud_now_s(void);
int64_t cloud_monotonic_ms(void);

/* ── identity (cloud_identity.c) ──────────────────────────────────── */

struct cloud_identity {
    unsigned char private_key[CLOUD_X25519_KEY_LEN];
    unsigned char public_key[CLOUD_X25519_KEY_LEN];
    char router_id[CLOUD_ROUTER_ID_MAX + 1];
    /* SHA256 of the public key, first 8 bytes, grouped: A1B2-C3D4-E5F6-0718. */
    char fingerprint[24];
};

/*
 * Loads the identity, generating it on first run. The private key is written
 * 0600 through a temp file plus rename so a crash cannot leave a half-written
 * key that would silently invalidate every paired App.
 */
int cloud_identity_load(struct cloud_identity *out);
const struct cloud_identity *cloud_identity(void);
int cloud_identity_fingerprint(const unsigned char *public_key,
                               char *out, size_t out_size);

/* ── configuration (cloud_config.c) ───────────────────────────────── */

struct cloud_config {
    int enabled;
    char host[256];
    uint16_t port;
    /* Tunnel enrollment secret shared with the relay operator. */
    char auth_token[256];
    int tls_verify;
    char ca_path[256];
};

int cloud_config_load(struct cloud_config *out);
void cloud_config_cleanse(struct cloud_config *config);

/* ── app device registry (cloud_devices.c) ────────────────────────── */

/*
 * Registered App signing keys, read from the app_devices rows webd wrote during
 * pairing. An unknown signing key is refused rather than trusted.
 */
int cloud_devices_signing_key_known(const unsigned char *signing_key,
                                    char *device_id, size_t device_id_size);
int cloud_devices_touch_remote(const char *device_id, int64_t when);
int cloud_devices_count(int *out);

/* ── envelope crypto (cloud_envelope.c) ──────────────────────────── */

struct cloud_inner_request {
    char method[16];
    char *path;
    char request_id[CLOUD_REQUEST_ID_MAX + 1];
    int64_t issued_at;
    char *access_token;
    unsigned char *body;
    size_t body_length;
};

void cloud_inner_request_free(struct cloud_inner_request *request);

/*
 * Derives the per-request traffic key exactly as the App does:
 *   shared  = X25519(router_private, ephemeral_public)
 *   salt    = SHA256(request_id)
 *   info    = CONTEXT || ephemeral_public || router_public
 *   traffic = HKDF-SHA256(shared, salt, info, 32)
 */
int cloud_envelope_derive_key(const unsigned char *ephemeral_public,
                              const char *request_id,
                              unsigned char *out_key);

int cloud_envelope_verify_signature(const char *router_id,
                                    const char *request_id,
                                    const unsigned char *ephemeral_public,
                                    const unsigned char *ciphertext,
                                    size_t ciphertext_length,
                                    const unsigned char *signature,
                                    const unsigned char *signing_key);

int cloud_envelope_open(const unsigned char *key,
                        const unsigned char *ciphertext,
                        size_t ciphertext_length,
                        unsigned char **out, size_t *out_length);

int cloud_envelope_seal(const unsigned char *key,
                        const unsigned char *plaintext,
                        size_t plaintext_length,
                        unsigned char **out, size_t *out_length);

int cloud_envelope_parse_inner(const unsigned char *plaintext,
                               size_t plaintext_length,
                               struct cloud_inner_request *out);

int cloud_envelope_build_response(int status, const char *request_id,
                                  const unsigned char *body,
                                  size_t body_length,
                                  unsigned char **out, size_t *out_length);

/* ── base64 helpers (cloud_envelope.c) ───────────────────────────── */

int cloud_base64_decode(const char *text, unsigned char **out, size_t *out_length);
int cloud_base64_decode_fixed(const char *text, unsigned char *out, size_t expected);
int cloud_base64_encode(const unsigned char *data, size_t length, char **out);

/* ── replay guard (cloud_replay.c) ───────────────────────────────── */

int cloud_replay_seen(const char *request_id, int64_t now);
void cloud_replay_reset(void);

/* ── local HTTP replay (cloud_local.c) ───────────────────────────── */

struct cloud_local_response {
    int status;
    unsigned char *body;
    size_t body_length;
};

void cloud_local_response_free(struct cloud_local_response *response);

/*
 * Replays one unsealed request against the local webd. Only methods and paths
 * that passed validation reach here.
 */
int cloud_local_execute(const struct cloud_inner_request *request,
                        struct cloud_local_response *out);

int cloud_local_method_allowed(const char *method);
int cloud_local_path_allowed(const char *path);

/* ── relay tunnel (cloud_tunnel.c) ──────────────────────────────── */

int cloud_tunnel_start(const struct cloud_config *config);
void cloud_tunnel_stop(void);
int cloud_tunnel_connected(void);
const char *cloud_tunnel_state(void);
const char *cloud_tunnel_reason(void);
int64_t cloud_tunnel_connected_since(void);
void cloud_tunnel_counters(uint64_t *forwarded, uint64_t *rejected);

/* ── ubus surface (cloud_ubus.c) ────────────────────────────────── */

int cloud_ubus_start(void);
void cloud_ubus_stop(void);
struct json_object *cloud_status_json(void);
struct json_object *cloud_identity_json(void);

#endif
