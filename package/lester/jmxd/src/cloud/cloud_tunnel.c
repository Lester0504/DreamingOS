// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Outbound tunnel to the relay.
 *
 * The router dials out and keeps one long-lived connection, so no inbound port
 * has to be opened for remote access. Framing is the length-prefixed JSON the
 * AC<->AP control protocol already uses (4-byte big-endian length, 64 KiB cap),
 * which the relay's Go side mirrors.
 *
 * The tunnel runs on its own thread rather than in uloop because request
 * handling does a blocking local HTTP round trip; putting that in the event
 * loop would stall ubus for the duration. Requests are handled one at a time,
 * which matches the App's usage pattern and keeps this daemon from becoming a
 * way to fan out load into webd.
 *
 * Reconnection backs off exponentially. Without that, a router whose token was
 * revoked would hammer the relay indefinitely.
 */
#include "cloud_internal.h"

#include <pthread.h>

#define CLOUD_TUNNEL_UPGRADE "dreamingos-relay"
#define CLOUD_TUNNEL_BACKOFF_MIN_MS 2000
#define CLOUD_TUNNEL_BACKOFF_MAX_MS 120000
#define CLOUD_TUNNEL_PING_INTERVAL_MS 45000
#define CLOUD_TUNNEL_READ_TIMEOUT_MS 60000

struct cloud_tunnel_connection {
    int fd;
    SSL *ssl;
    SSL_CTX *context;
};

static struct {
    pthread_t thread;
    pthread_mutex_t lock;
    int running;
    int started;
    int connected;
    int64_t connected_since;
    uint64_t forwarded;
    uint64_t rejected;
    char state[32];
    char reason[64];
    struct cloud_config config;
} g_tunnel = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = "stopped",
};

static void cloud_tunnel_set_state(const char *state, const char *reason)
{
    pthread_mutex_lock(&g_tunnel.lock);
    snprintf(g_tunnel.state, sizeof(g_tunnel.state), "%s", state);
    snprintf(g_tunnel.reason, sizeof(g_tunnel.reason), "%s", reason ? reason : "");
    pthread_mutex_unlock(&g_tunnel.lock);
}

static void cloud_tunnel_set_connected(int connected)
{
    pthread_mutex_lock(&g_tunnel.lock);
    g_tunnel.connected = connected ? 1 : 0;
    g_tunnel.connected_since = connected ? cloud_now_s() : 0;
    pthread_mutex_unlock(&g_tunnel.lock);
}

static void cloud_tunnel_count(int forwarded, int rejected)
{
    pthread_mutex_lock(&g_tunnel.lock);
    g_tunnel.forwarded += (uint64_t)(forwarded ? 1 : 0);
    g_tunnel.rejected += (uint64_t)(rejected ? 1 : 0);
    pthread_mutex_unlock(&g_tunnel.lock);
}

static int cloud_tunnel_running(void)
{
    int running;

    pthread_mutex_lock(&g_tunnel.lock);
    running = g_tunnel.running;
    pthread_mutex_unlock(&g_tunnel.lock);
    return running;
}

int cloud_tunnel_connected(void)
{
    int connected;

    pthread_mutex_lock(&g_tunnel.lock);
    connected = g_tunnel.connected;
    pthread_mutex_unlock(&g_tunnel.lock);
    return connected;
}

int64_t cloud_tunnel_connected_since(void)
{
    int64_t since;

    pthread_mutex_lock(&g_tunnel.lock);
    since = g_tunnel.connected_since;
    pthread_mutex_unlock(&g_tunnel.lock);
    return since;
}

void cloud_tunnel_counters(uint64_t *forwarded, uint64_t *rejected)
{
    pthread_mutex_lock(&g_tunnel.lock);
    if (forwarded)
        *forwarded = g_tunnel.forwarded;
    if (rejected)
        *rejected = g_tunnel.rejected;
    pthread_mutex_unlock(&g_tunnel.lock);
}

/* Returned pointers are into thread-shared storage guarded by the lock; the
 * ubus handlers copy them into JSON immediately on the main thread. */
const char *cloud_tunnel_state(void)
{
    static _Thread_local char copy[32];

    pthread_mutex_lock(&g_tunnel.lock);
    snprintf(copy, sizeof(copy), "%s", g_tunnel.state);
    pthread_mutex_unlock(&g_tunnel.lock);
    return copy;
}

const char *cloud_tunnel_reason(void)
{
    static _Thread_local char copy[64];

    pthread_mutex_lock(&g_tunnel.lock);
    snprintf(copy, sizeof(copy), "%s", g_tunnel.reason);
    pthread_mutex_unlock(&g_tunnel.lock);
    return copy;
}

/* ── socket helpers ──────────────────────────────────────────────── */

static int cloud_tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[6];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof(service), "%u", (unsigned int)port);

    if (!host || !host[0] || !port ||
        getaddrinfo(host, service, &hints, &addresses) != 0)
        return -1;

    for (address = addresses; address; address = address->ai_next) {
        struct timeval timeout;
        int flags;

        fd = socket(address->ai_family, address->ai_socktype,
                    address->ai_protocol);
        if (fd < 0)
            continue;
        if ((flags = fcntl(fd, F_GETFD, 0)) >= 0)
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

        /* Blocking socket with SO_RCVTIMEO/SO_SNDTIMEO: the read loop wants a
         * long idle timeout, and a plain timeout is simpler to reason about
         * here than a nonblocking state machine. */
        timeout.tv_sec = CLOUD_IO_TIMEOUT_MS / 1000;
        timeout.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    return fd;
}

static void cloud_tunnel_close(struct cloud_tunnel_connection *connection)
{
    if (!connection)
        return;
    if (connection->ssl) {
        SSL_shutdown(connection->ssl);
        SSL_free(connection->ssl);
    }
    if (connection->context)
        SSL_CTX_free(connection->context);
    if (connection->fd >= 0)
        close(connection->fd);
    memset(connection, 0, sizeof(*connection));
    connection->fd = -1;
}

static int cloud_tunnel_open(const struct cloud_config *config,
                             struct cloud_tunnel_connection *out)
{
    struct cloud_tunnel_connection connection;
    X509_VERIFY_PARAM *parameters;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;

    connection.context = SSL_CTX_new(TLS_client_method());
    if (!connection.context)
        goto fail;
    /* TLS 1.2 floor rather than 1.3: the relay may sit behind a CDN or older
     * termination proxy the operator does not control. */
    if (SSL_CTX_set_min_proto_version(connection.context, TLS1_2_VERSION) != 1)
        goto fail;

    if (config->tls_verify) {
        SSL_CTX_set_verify(connection.context, SSL_VERIFY_PEER, NULL);
        if (config->ca_path[0]) {
            if (SSL_CTX_load_verify_locations(connection.context,
                                              config->ca_path, NULL) != 1)
                goto fail;
        } else if (SSL_CTX_set_default_verify_paths(connection.context) != 1) {
            goto fail;
        }
    } else {
        /* Only reachable when an operator explicitly set tls_verify=0. The
         * status surface reports this so it cannot be forgotten silently. */
        SSL_CTX_set_verify(connection.context, SSL_VERIFY_NONE, NULL);
    }

    connection.fd = cloud_tcp_connect(config->host, config->port);
    if (connection.fd < 0) {
        cloud_tunnel_set_state("connecting", "relay_unreachable");
        goto fail;
    }

    connection.ssl = SSL_new(connection.context);
    if (!connection.ssl || SSL_set_fd(connection.ssl, connection.fd) != 1)
        goto fail;

    if (config->tls_verify) {
        parameters = SSL_get0_param(connection.ssl);
        if (!parameters)
            goto fail;
        X509_VERIFY_PARAM_set_hostflags(parameters,
                                        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(connection.ssl, config->host) != 1)
            goto fail;
    }
    /* SNI is set regardless of verification so the relay can select a cert. */
    if (SSL_set_tlsext_host_name(connection.ssl, config->host) != 1)
        goto fail;

    if (SSL_connect(connection.ssl) != 1) {
        cloud_tunnel_set_state("connecting", "tls_handshake_failed");
        goto fail;
    }
    if (config->tls_verify &&
        SSL_get_verify_result(connection.ssl) != X509_V_OK) {
        cloud_tunnel_set_state("connecting", "tls_verify_failed");
        goto fail;
    }

    *out = connection;
    return 0;
fail:
    cloud_tunnel_close(&connection);
    return -1;
}

/* ── framing ─────────────────────────────────────────────────────── */

static int cloud_ssl_read_exact(SSL *ssl, unsigned char *out, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int got = SSL_read(ssl, out + received, (int)(length - received));

        if (got <= 0) {
            int error = SSL_get_error(ssl, got);

            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        received += (size_t)got;
    }
    return 0;
}

static int cloud_ssl_write_all(SSL *ssl, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int written = SSL_write(ssl, data + sent, (int)(length - sent));

        if (written <= 0) {
            int error = SSL_get_error(ssl, written);

            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        sent += (size_t)written;
    }
    return 0;
}

static int cloud_frame_write(SSL *ssl, struct json_object *frame)
{
    const char *text = json_object_to_json_string_ext(frame,
                                                      JSON_C_TO_STRING_PLAIN);
    size_t length;
    unsigned char header[4];

    if (!text)
        return -1;
    length = strlen(text);
    if (length > CLOUD_FRAME_MAX)
        return -1;
    header[0] = (unsigned char)((length >> 24) & 0xff);
    header[1] = (unsigned char)((length >> 16) & 0xff);
    header[2] = (unsigned char)((length >> 8) & 0xff);
    header[3] = (unsigned char)(length & 0xff);
    if (cloud_ssl_write_all(ssl, header, sizeof(header)) != 0)
        return -1;
    return cloud_ssl_write_all(ssl, (const unsigned char *)text, length);
}

static int cloud_frame_read(SSL *ssl, struct json_object **out)
{
    unsigned char header[4];
    unsigned char *payload;
    uint32_t length;
    struct json_object *parsed;

    if (cloud_ssl_read_exact(ssl, header, sizeof(header)) != 0)
        return -1;
    length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
             ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    /* Validate before allocating so a peer cannot make us reserve 4 GiB. */
    if (!length || length > CLOUD_FRAME_MAX)
        return -1;

    payload = malloc(length + 1);
    if (!payload)
        return -1;
    if (cloud_ssl_read_exact(ssl, payload, length) != 0) {
        free(payload);
        return -1;
    }
    payload[length] = '\0';
    parsed = json_tokener_parse((const char *)payload);
    free(payload);
    if (!parsed || !json_object_is_type(parsed, json_type_object)) {
        if (parsed)
            json_object_put(parsed);
        return -1;
    }
    *out = parsed;
    return 0;
}

static const char *cloud_frame_string(struct json_object *frame, const char *name)
{
    struct json_object *value = NULL;

    if (!json_object_object_get_ex(frame, name, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

/* ── HTTP upgrade ────────────────────────────────────────────────── */

static int cloud_tunnel_upgrade(SSL *ssl, const struct cloud_config *config)
{
    char request[1024];
    char response[1024];
    size_t received = 0;
    int length;

    length = snprintf(request, sizeof(request),
        "GET /v1/router/tunnel HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: %s\r\n"
        "Connection: Upgrade\r\n"
        "User-Agent: %s/%s\r\n"
        "\r\n",
        config->host, CLOUD_TUNNEL_UPGRADE,
        CLOUD_SERVICE_NAME, CLOUD_CONTRACT_VERSION);
    if (length <= 0 || (size_t)length >= sizeof(request))
        return -1;
    if (cloud_ssl_write_all(ssl, (const unsigned char *)request,
                            (size_t)length) != 0)
        return -1;

    /* Read headers one byte at a time up to the blank line. The relay sends no
     * body with 101, so nothing is over-read into the frame stream. */
    while (received < sizeof(response) - 1) {
        if (cloud_ssl_read_exact(ssl, (unsigned char *)response + received, 1) != 0)
            return -1;
        received++;
        response[received] = '\0';
        if (received >= 4 && !memcmp(response + received - 4, "\r\n\r\n", 4))
            break;
    }
    if (strncmp(response, "HTTP/1.1 101", 12)) {
        cloud_tunnel_set_state("connecting", "relay_refused_upgrade");
        return -1;
    }
    return 0;
}

/* ── request handling ────────────────────────────────────────────── */

static struct json_object *cloud_error_frame(const char *request_id,
                                             const char *code,
                                             const char *message)
{
    struct json_object *frame = json_object_new_object();

    if (!frame)
        return NULL;
    json_object_object_add(frame, "protocol",
                           json_object_new_string(CLOUD_PROTOCOL));
    json_object_object_add(frame, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(frame, "kind", json_object_new_string("relay_response"));
    if (request_id)
        json_object_object_add(frame, "request_id",
                               json_object_new_string(request_id));
    json_object_object_add(frame, "code", json_object_new_string(code));
    json_object_object_add(frame, "message",
                           json_object_new_string(message ? message : ""));
    return frame;
}

/*
 * Handles one relay_request frame.
 *
 * Order of checks matters: signature and freshness are verified before the
 * payload is decrypted or acted on, so an unregistered or replayed frame never
 * reaches webd.
 */
static struct json_object *cloud_handle_request(struct json_object *frame)
{
    const struct cloud_identity *identity = cloud_identity();
    const char *request_id = cloud_frame_string(frame, "request_id");
    const char *ephemeral_b64 = cloud_frame_string(frame, "ephemeral_public_key");
    const char *ciphertext_b64 = cloud_frame_string(frame, "ciphertext");
    const char *signature_b64 = cloud_frame_string(frame, "app_signature");
    const char *signing_key_b64 = cloud_frame_string(frame, "app_signing_key");
    unsigned char ephemeral[CLOUD_X25519_KEY_LEN];
    unsigned char signature[CLOUD_ED25519_SIG_LEN];
    unsigned char signing_key[CLOUD_ED25519_KEY_LEN];
    unsigned char traffic_key[CLOUD_TRAFFIC_KEY_LEN];
    unsigned char *ciphertext = NULL, *plaintext = NULL, *sealed = NULL;
    unsigned char *response_payload = NULL;
    size_t ciphertext_length = 0, plaintext_length = 0, sealed_length = 0;
    size_t response_length = 0;
    struct cloud_inner_request inner;
    struct cloud_local_response local;
    struct json_object *result = NULL;
    char device_id[128] = "";
    char *encoded = NULL;
    int64_t now = cloud_now_s();

    memset(&inner, 0, sizeof(inner));
    memset(&local, 0, sizeof(local));

    if (!identity || !request_id || !ephemeral_b64 || !ciphertext_b64 ||
        !signature_b64 || !signing_key_b64 ||
        strlen(request_id) > CLOUD_REQUEST_ID_MAX) {
        cloud_tunnel_count(0, 1);
        return cloud_error_frame(request_id, "invalid_frame",
                                "frame is missing required fields");
    }

    if (cloud_base64_decode_fixed(ephemeral_b64, ephemeral,
                                  sizeof(ephemeral)) != 0 ||
        cloud_base64_decode_fixed(signature_b64, signature,
                                  sizeof(signature)) != 0 ||
        cloud_base64_decode_fixed(signing_key_b64, signing_key,
                                  sizeof(signing_key)) != 0 ||
        cloud_base64_decode(ciphertext_b64, &ciphertext,
                            &ciphertext_length) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "invalid_frame",
                                  "frame fields are not valid base64");
        goto done;
    }

    /* The signing key must belong to a device that completed LAN pairing.
     * This is the check that makes the relay untrusted: it cannot introduce a
     * new App identity. */
    if (!cloud_devices_signing_key_known(signing_key, device_id,
                                         sizeof(device_id))) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "app_not_authorized",
                                  "signing key is not registered on this router");
        goto done;
    }

    if (cloud_envelope_verify_signature(identity->router_id, request_id,
                                        ephemeral, ciphertext,
                                        ciphertext_length, signature,
                                        signing_key) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "app_not_authorized",
                                  "frame signature is invalid");
        goto done;
    }

    if (cloud_replay_seen(request_id, now)) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "request_replayed",
                                  "request_id was already served");
        goto done;
    }

    if (cloud_envelope_derive_key(ephemeral, request_id, traffic_key) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "key_agreement_failed",
                                  "could not derive the traffic key");
        goto done;
    }

    if (cloud_envelope_open(traffic_key, ciphertext, ciphertext_length,
                            &plaintext, &plaintext_length) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "decrypt_failed",
                                  "payload did not authenticate");
        goto done;
    }

    if (cloud_envelope_parse_inner(plaintext, plaintext_length, &inner) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "invalid_request",
                                  "inner request is malformed");
        goto done;
    }

    /* The inner request_id is inside the sealed payload, so a mismatch means
     * the outer frame was stitched together from a different request. */
    if (strcmp(inner.request_id, request_id)) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "invalid_request",
                                  "inner request_id does not match the frame");
        goto done;
    }

    if (inner.issued_at <= 0 ||
        inner.issued_at > now + CLOUD_ISSUED_AT_SKEW_S ||
        inner.issued_at < now - CLOUD_ISSUED_AT_SKEW_S) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "request_expired",
                                  "issued_at is outside the accepted window");
        goto done;
    }

    if (!cloud_local_method_allowed(inner.method) ||
        !cloud_local_path_allowed(inner.path)) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "request_not_allowed",
                                  "only /api/v1/ requests can be relayed");
        goto done;
    }

    if (cloud_local_execute(&inner, &local) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "local_request_failed",
                                  "the local API did not answer");
        goto done;
    }

    if (cloud_envelope_build_response(local.status, request_id, local.body,
                                      local.body_length, &response_payload,
                                      &response_length) != 0 ||
        cloud_envelope_seal(traffic_key, response_payload, response_length,
                            &sealed, &sealed_length) != 0 ||
        cloud_base64_encode(sealed, sealed_length, &encoded) != 0) {
        cloud_tunnel_count(0, 1);
        result = cloud_error_frame(request_id, "seal_failed",
                                  "could not seal the response");
        goto done;
    }

    result = json_object_new_object();
    if (!result)
        goto done;
    json_object_object_add(result, "protocol",
                           json_object_new_string(CLOUD_PROTOCOL));
    json_object_object_add(result, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(result, "kind",
                           json_object_new_string("relay_response"));
    json_object_object_add(result, "request_id",
                           json_object_new_string(request_id));
    json_object_object_add(result, "ciphertext", json_object_new_string(encoded));
    cloud_tunnel_count(1, 0);

    /* Best-effort audit trail; a failure here must not fail the request. */
    if (device_id[0])
        cloud_devices_touch_remote(device_id, now);

done:
    if (encoded) {
        OPENSSL_cleanse(encoded, strlen(encoded));
        free(encoded);
    }
    if (sealed) {
        OPENSSL_cleanse(sealed, sealed_length);
        free(sealed);
    }
    if (response_payload) {
        OPENSSL_cleanse(response_payload, response_length);
        free(response_payload);
    }
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_length);
        free(plaintext);
    }
    free(ciphertext);
    cloud_local_response_free(&local);
    cloud_inner_request_free(&inner);
    OPENSSL_cleanse(traffic_key, sizeof(traffic_key));
    OPENSSL_cleanse(signing_key, sizeof(signing_key));
    return result;
}

/* ── session ─────────────────────────────────────────────────────── */

static int cloud_tunnel_hello(SSL *ssl, const struct cloud_config *config)
{
    const struct cloud_identity *identity = cloud_identity();
    struct json_object *frame;
    struct json_object *reply = NULL;
    struct json_object *accepted = NULL;
    int rc = -1;

    if (!identity)
        return -1;
    frame = json_object_new_object();
    if (!frame)
        return -1;
    json_object_object_add(frame, "protocol",
                           json_object_new_string(CLOUD_PROTOCOL));
    json_object_object_add(frame, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(frame, "kind", json_object_new_string("tunnel_hello"));
    json_object_object_add(frame, "router_id",
                           json_object_new_string(identity->router_id));
    json_object_object_add(frame, "auth_token",
                           json_object_new_string(config->auth_token));
    rc = cloud_frame_write(ssl, frame);
    json_object_put(frame);
    if (rc != 0)
        return -1;

    if (cloud_frame_read(ssl, &reply) != 0)
        return -1;
    rc = -1;
    if (json_object_object_get_ex(reply, "accepted", &accepted) && accepted &&
        json_object_is_type(accepted, json_type_boolean) &&
        json_object_get_boolean(accepted)) {
        rc = 0;
    } else {
        const char *code = cloud_frame_string(reply, "code");

        /* Surfacing the relay's refusal reason verbatim is what makes a wrong
         * token or unenrolled router diagnosable without relay-side access. */
        cloud_tunnel_set_state("rejected", code ? code : "tunnel_rejected");
    }
    json_object_put(reply);
    return rc;
}

static int cloud_tunnel_session(const struct cloud_config *config)
{
    struct cloud_tunnel_connection connection;
    int64_t last_ping;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;

    cloud_tunnel_set_state("connecting", "");
    if (cloud_tunnel_open(config, &connection) != 0)
        return -1;
    if (cloud_tunnel_upgrade(connection.ssl, config) != 0 ||
        cloud_tunnel_hello(connection.ssl, config) != 0) {
        cloud_tunnel_close(&connection);
        return -1;
    }

    cloud_tunnel_set_state("online", "");
    cloud_tunnel_set_connected(1);
    fprintf(stderr, "[%s] tunnel established host=%s port=%u\n",
            CLOUD_SERVICE_NAME, config->host, (unsigned int)config->port);
    last_ping = cloud_monotonic_ms();

    while (cloud_tunnel_running()) {
        struct json_object *frame = NULL;
        const char *kind;
        int64_t now;

        if (cloud_frame_read(connection.ssl, &frame) != 0) {
            /* A read timeout is normal when idle; distinguish it from a real
             * drop by checking whether a ping is due. */
            now = cloud_monotonic_ms();
            if (now >= 0 && now - last_ping < CLOUD_TUNNEL_READ_TIMEOUT_MS &&
                SSL_get_error(connection.ssl, -1) == SSL_ERROR_SYSCALL &&
                (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct json_object *ping = json_object_new_object();

                if (ping) {
                    json_object_object_add(ping, "protocol",
                                           json_object_new_string(CLOUD_PROTOCOL));
                    json_object_object_add(ping, "version",
                                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
                    json_object_object_add(ping, "kind",
                                           json_object_new_string("tunnel_ping"));
                    if (cloud_frame_write(connection.ssl, ping) == 0)
                        last_ping = now;
                    json_object_put(ping);
                    if (last_ping == now)
                        continue;
                }
            }
            break;
        }

        kind = cloud_frame_string(frame, "kind");
        if (!kind) {
            json_object_put(frame);
            continue;
        }

        if (!strcmp(kind, "relay_request")) {
            struct json_object *response = cloud_handle_request(frame);

            if (response) {
                int rc = cloud_frame_write(connection.ssl, response);

                json_object_put(response);
                if (rc != 0) {
                    json_object_put(frame);
                    break;
                }
            }
        } else if (!strcmp(kind, "tunnel_ping")) {
            struct json_object *pong = json_object_new_object();

            if (pong) {
                json_object_object_add(pong, "protocol",
                                       json_object_new_string(CLOUD_PROTOCOL));
                json_object_object_add(pong, "version",
                                       json_object_new_int(CLOUD_PROTOCOL_VERSION));
                json_object_object_add(pong, "kind",
                                       json_object_new_string("tunnel_pong"));
                cloud_frame_write(connection.ssl, pong);
                json_object_put(pong);
            }
        }
        json_object_put(frame);

        now = cloud_monotonic_ms();
        if (now >= 0 && now - last_ping >= CLOUD_TUNNEL_PING_INTERVAL_MS)
            last_ping = now;
    }

    cloud_tunnel_set_connected(0);
    cloud_tunnel_close(&connection);
    return 0;
}

static void *cloud_tunnel_thread(void *argument)
{
    struct cloud_config config;
    int64_t backoff = CLOUD_TUNNEL_BACKOFF_MIN_MS;

    (void)argument;
    pthread_mutex_lock(&g_tunnel.lock);
    config = g_tunnel.config;
    pthread_mutex_unlock(&g_tunnel.lock);

    while (cloud_tunnel_running()) {
        if (cloud_tunnel_session(&config) == 0) {
            /* A clean session end means the relay closed us; retry from the
             * short backoff rather than treating it as a hard failure. */
            backoff = CLOUD_TUNNEL_BACKOFF_MIN_MS;
        }
        if (!cloud_tunnel_running())
            break;

        cloud_tunnel_set_state("backoff", cloud_tunnel_reason());
        /* Sleep in short slices so shutdown does not wait out the backoff. */
        for (int64_t waited = 0; waited < backoff && cloud_tunnel_running();
             waited += 250)
            usleep(250 * 1000);

        backoff *= 2;
        if (backoff > CLOUD_TUNNEL_BACKOFF_MAX_MS)
            backoff = CLOUD_TUNNEL_BACKOFF_MAX_MS;
    }

    cloud_tunnel_set_connected(0);
    cloud_tunnel_set_state("stopped", "");
    OPENSSL_cleanse(&config, sizeof(config));
    return NULL;
}

int cloud_tunnel_start(const struct cloud_config *config)
{
    if (!config)
        return -1;
    if (!config->enabled) {
        cloud_tunnel_set_state("disabled", "relay_disabled");
        return 0;
    }
    if (!config->host[0]) {
        cloud_tunnel_set_state("misconfigured", "relay_host_missing");
        return 0;
    }
    if (!config->auth_token[0]) {
        cloud_tunnel_set_state("misconfigured", "relay_auth_token_missing");
        return 0;
    }

    pthread_mutex_lock(&g_tunnel.lock);
    g_tunnel.config = *config;
    g_tunnel.running = 1;
    pthread_mutex_unlock(&g_tunnel.lock);

    if (pthread_create(&g_tunnel.thread, NULL, cloud_tunnel_thread, NULL) != 0) {
        pthread_mutex_lock(&g_tunnel.lock);
        g_tunnel.running = 0;
        pthread_mutex_unlock(&g_tunnel.lock);
        cloud_tunnel_set_state("failed", "thread_start_failed");
        return -1;
    }
    g_tunnel.started = 1;
    return 0;
}

void cloud_tunnel_stop(void)
{
    pthread_mutex_lock(&g_tunnel.lock);
    g_tunnel.running = 0;
    pthread_mutex_unlock(&g_tunnel.lock);

    if (g_tunnel.started) {
        pthread_join(g_tunnel.thread, NULL);
        g_tunnel.started = 0;
    }
    pthread_mutex_lock(&g_tunnel.lock);
    cloud_config_cleanse(&g_tunnel.config);
    pthread_mutex_unlock(&g_tunnel.lock);
}
