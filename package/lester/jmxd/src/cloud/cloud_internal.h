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
/*
 * Enrollment uses a different context string from E2EE and from the relay's
 * state queries. The separation is deliberate: a signature made for one purpose
 * must not verify for another.
 */
#define CLOUD_ENROLL_CONTEXT "dreamingos-relay-enroll-v1"
#define CLOUD_PROTOCOL "dreamingos-relay"
#define CLOUD_PROTOCOL_VERSION 1

/* Matches the AC<->AP control protocol and the relay's Go implementation. */
#define CLOUD_FRAME_MAX (64U * 1024U)
#define CLOUD_IO_TIMEOUT_MS 10000

/* Mirrors the relay's maxAuthorizedApps: declaring more would be silently
 * truncated on the other side, so the cut is made here where it is visible. */
#define CLOUD_MAX_AUTHORIZED_APPS 64

#define CLOUD_X25519_KEY_LEN 32
#define CLOUD_ED25519_KEY_LEN 32
#define CLOUD_ED25519_SIG_LEN 64
#define CLOUD_TRAFFIC_KEY_LEN 32
#define CLOUD_CHACHA_NONCE_LEN 12
#define CLOUD_CHACHA_TAG_LEN 16

/* Identity and state live next to the other component state. */
/* Overridable at compile time so tests can exercise the real file handling
 * against a temporary directory instead of the live one. */
#ifndef CLOUD_STATE_DIR
#define CLOUD_STATE_DIR "/etc/dreamingwrt/cloud"
#endif
#define CLOUD_IDENTITY_PATH CLOUD_STATE_DIR "/identity.x25519"
#define CLOUD_SIGNING_KEY_PATH CLOUD_STATE_DIR "/identity.ed25519"
#define CLOUD_TUNNEL_TOKEN_PATH CLOUD_STATE_DIR "/tunnel_token"
#define CLOUD_ROUTER_ID_PATH CLOUD_STATE_DIR "/router_id"
/*
 * The id used on the wire with the relay. Always the key fingerprint, which is
 * not necessarily what CLOUD_ROUTER_ID_PATH holds: a legacy router keeps its
 * UUID there because paired Apps pinned it. Persisted separately so other
 * components (notifyd's relay ingest) can address the relay without having to
 * re-derive it from the private key material, which they cannot read.
 */
#define CLOUD_RELAY_ROUTER_ID_PATH CLOUD_STATE_DIR "/relay_router_id"
/* Must stay identical to webd's APP_API_DB_PATH (jmx_app_api.c). webd owns the
 * pairing rows; this daemon only reads them. Verified against 30.1, where the
 * file on disk is apid.db. */
/* Overridable at compile time on the same terms as CLOUD_STATE_DIR, so tests can
 * exercise the real queries against a temporary database. */
#ifndef CLOUD_APP_DB_PATH
#define CLOUD_APP_DB_PATH "/etc/dreamingwrt/apid.db"
#endif

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
    /* Ed25519 is a second, separate key: X25519 cannot sign, and both self
     * enrollment and relay status queries require a signature. */
    unsigned char signing_private_key[CLOUD_ED25519_KEY_LEN];
    unsigned char signing_public_key[CLOUD_ED25519_KEY_LEN];
    char router_id[CLOUD_ROUTER_ID_MAX + 1];
    /* SHA256 of the public key, first 8 bytes, grouped: A1B2-C3D4-E5F6-0718. */
    char fingerprint[24];
    /* 1 when router_id is the contract fingerprint of both public keys, 0 when
     * it is a legacy locally generated UUID that cannot self enroll. */
    int router_id_is_key_derived;
    /*
     * The contract-form id derived from both public keys, always populated even
     * when router_id is a legacy UUID. Enrollment must use this one: the relay
     * verifies the id against the key fingerprint, while router_id stays as the
     * value every paired App has already pinned. Equal to router_id whenever
     * router_id_is_key_derived is set.
     */
    char relay_router_id[CLOUD_ROUTER_ID_MAX + 1];
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

/*
 * router_id per ROUTER_AGENT_CONTRACT.md section 2:
 *   "router-" + hex(SHA256(kex_pub || signing_pub)[:16])
 * 32 lowercase hex characters, both keys as raw bytes, kex first, no separator.
 * Contract test vector: 32x0x01 and 32x0x02 give
 * router-f818afd37a6dc3bc92fb447310112770
 */
int cloud_identity_derive_router_id(const unsigned char *kex_public_key,
                                    const unsigned char *signing_public_key,
                                    char *out, size_t out_size);

/* Ed25519 signature over an arbitrary message, using the persisted signing
 * key. `out` must hold 64 bytes. */
int cloud_identity_sign(const unsigned char *message, size_t message_len,
                        unsigned char *out, size_t out_size);

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

/*
 * Collects the base64 Ed25519 public keys of every paired, enabled App as a
 * JSON array, for the relay's authorized_apps declaration.
 *
 * Only public keys leave the router. The relay needs them to authenticate
 * presence queries without being able to impersonate an App, and without the
 * router having to expose its pairing table.
 *
 * Returns a new json_object array the caller owns, or NULL on failure. An empty
 * array is a valid result meaning "no App may query state yet".
 */
struct json_object *cloud_devices_signing_keys(void);

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

/*
 * One TLS connection to the relay, shared by the tunnel and by enrollment so
 * both honour the same verification settings. A caller that skipped these
 * checks would be the weak link in the whole path.
 */
struct cloud_tls {
    int fd;
    SSL *ssl;
    SSL_CTX *context;
};

int cloud_tls_connect(const struct cloud_config *config, struct cloud_tls *out);
void cloud_tls_close(struct cloud_tls *connection);
int cloud_tls_write_all(SSL *ssl, const unsigned char *data, size_t length);
int cloud_tls_read_some(SSL *ssl, unsigned char *out, size_t length);

int cloud_tunnel_start(const struct cloud_config *config);
void cloud_tunnel_stop(void);
int cloud_tunnel_connected(void);
const char *cloud_tunnel_state(void);
const char *cloud_tunnel_reason(void);
int64_t cloud_tunnel_connected_since(void);
void cloud_tunnel_counters(uint64_t *forwarded, uint64_t *rejected);
/*
 * Why the previous session ended. Reported in status because a tunnel that drops
 * periodically is back to "online" within seconds, so the live state never shows
 * the cause. Any out parameter may be NULL.
 */
void cloud_tunnel_last_disconnect(char *out, size_t size, int64_t *at,
                                  int64_t *session_ms, uint32_t *count);

/* ── self enrollment (cloud_enroll.c) ───────────────────────────── */

/*
 * Result of one enrollment attempt. `code` carries the relay's own error code
 * verbatim (contract section 6.1) because the UI renders different text for
 * `statically_configured` than for a genuine failure, and inventing our own
 * codes here would erase that distinction.
 */
struct cloud_enroll_result {
    int ok;
    int http_status;
    char code[64];
    char message[192];
    char router_id[CLOUD_ROUTER_ID_MAX + 1];
};

/*
 * Runs the two-step challenge/response of POST /v1/router/enroll and, on
 * success, persists the returned tunnel token 0600. The token is returned by
 * the relay exactly once, so persistence failure is treated as overall failure
 * rather than reported as success with a lost secret.
 */
int cloud_enroll_run(const struct cloud_config *config,
                     struct cloud_enroll_result *out);

/*
 * Asynchronous wrapper around cloud_enroll_run().
 *
 * Enrollment does two TLS round trips, which is far too long to hold the uloop
 * thread: ubus would stop answering status queries for the duration, and status
 * is exactly what a caller polls while waiting. So the work runs on a detached
 * thread and the caller polls cloud_enroll_job_json().
 *
 * Returns 0 when a job was started, 1 when one is already running, -1 on
 * failure to start.
 */
int cloud_enroll_job_start(int force);

/* Snapshot of the last or current job: {state, code, message, router_id,
 * relay_status, started_at, finished_at}. Never NULL on success. */
struct json_object *cloud_enroll_job_json(void);

/* Reads the persisted tunnel token. Returns 0 and a NUL-terminated token, or
 * -1 when no usable token is stored. */
int cloud_enroll_token_load(char *out, size_t out_size);
int cloud_enroll_token_present(void);

/* ── ubus surface (cloud_ubus.c) ────────────────────────────────── */

int cloud_ubus_start(void);
void cloud_ubus_stop(void);
struct json_object *cloud_status_json(void);
struct json_object *cloud_identity_json(void);

#endif
