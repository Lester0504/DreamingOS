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
#include <errno.h>
#include <openssl/err.h>

#define CLOUD_TUNNEL_UPGRADE "dreamingos-relay"
#define CLOUD_TUNNEL_BACKOFF_MIN_MS 2000
#define CLOUD_TUNNEL_BACKOFF_MAX_MS 120000
#define CLOUD_TUNNEL_PING_INTERVAL_MS 45000
/*
 * How long a tunnel may go without a readable frame before it is considered
 * dead. Must stay comfortably above the ping interval: the relay answers each
 * ping with a pong, so a live connection produces traffic well inside this.
 *
 * Deliberately below the relay's own 150s read deadline
 * (dreamingrelay internal/server/tunnel.go: tunnelIdleTimeout). When both ends
 * used 150s, whichever noticed first was decided by timing jitter, so a
 * genuinely idle tunnel produced a race instead of one side cleanly reopening
 * it. The router is the side that can reconnect, so it should be the side that
 * gives up first. Two ping intervals still fit inside this with room to spare:
 * a live connection sees a pong at 45s and 90s.
 */
#define CLOUD_TUNNEL_IDLE_LIMIT_MS 105000
/*
 * How often the authorized-App set is re-read and pushed.
 *
 * Pairing and revocation happen in webd, which has no channel into this
 * process, so the set is polled. A newly paired App would otherwise be unable
 * to query presence until the tunnel happened to reconnect, and a revoked one
 * would keep that ability for just as long. Sixty seconds keeps the revocation
 * lag short without querying sqlite in a tight loop.
 */
#define CLOUD_TUNNEL_APPS_REFRESH_MS 60000

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
    /*
     * Why the previous session ended, kept across the reconnect so the cause is
     * still readable after the fact. A tunnel that drops every couple of minutes
     * cannot be diagnosed by catching the log in the act, and the live state is
     * back to "online" seconds later.
     */
    char last_disconnect[160];
    int64_t last_disconnect_at;
    int64_t last_session_ms;
    uint32_t disconnects;
    struct cloud_config config;
} g_tunnel = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = "stopped",
};

/*
 * Records how a session ended.
 *
 * `detail` is expected to already name the loop stage and, where the failure
 * came from OpenSSL, the ssl_error/errno pair. Both the log line and the status
 * field get the same text so a report from the UI and a report from syslog
 * describe the same event.
 */
static void cloud_tunnel_note_disconnect(const char *detail, int64_t session_ms)
{
    pthread_mutex_lock(&g_tunnel.lock);
    snprintf(g_tunnel.last_disconnect, sizeof(g_tunnel.last_disconnect), "%s",
             detail ? detail : "unknown");
    g_tunnel.last_disconnect_at = cloud_now_s();
    g_tunnel.last_session_ms = session_ms;
    g_tunnel.disconnects++;
    pthread_mutex_unlock(&g_tunnel.lock);
    fprintf(stderr, "[%s] tunnel closed after %lldms: %s\n", CLOUD_SERVICE_NAME,
            (long long)session_ms, detail ? detail : "unknown");
}

void cloud_tunnel_last_disconnect(char *out, size_t size, int64_t *at,
                                  int64_t *session_ms, uint32_t *count)
{
    pthread_mutex_lock(&g_tunnel.lock);
    if (out && size)
        snprintf(out, size, "%s", g_tunnel.last_disconnect);
    if (at)
        *at = g_tunnel.last_disconnect_at;
    if (session_ms)
        *session_ms = g_tunnel.last_session_ms;
    if (count)
        *count = g_tunnel.disconnects;
    pthread_mutex_unlock(&g_tunnel.lock);
}

static void cloud_tunnel_set_state(const char *state, const char *reason)
{
    pthread_mutex_lock(&g_tunnel.lock);
    snprintf(g_tunnel.state, sizeof(g_tunnel.state), "%s", state);
    snprintf(g_tunnel.reason, sizeof(g_tunnel.reason), "%s", reason ? reason : "");
    /*
     * "online" is the only state in which the tunnel carries traffic, so any
     * other state must not keep reporting connected. Leaving the flag to the
     * individual teardown paths was wrong: a connect-phase failure such as
     * relay_unreachable returns before the session loop's clear, so a tunnel
     * that had been up once kept reporting connected:true while state said
     * connecting. Callers read that flag to decide whether remote access works,
     * so the two must not be able to disagree.
     */
    if (strcmp(state, "online")) {
        g_tunnel.connected = 0;
        g_tunnel.connected_since = 0;
    }
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

void cloud_tls_close(struct cloud_tls *connection)
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

/*
 * Dials the relay and completes the TLS handshake.
 *
 * Verification failures are fatal here rather than downgraded, and the failure
 * reason is recorded in the tunnel state so a bad CA path or an intercepting
 * middlebox is diagnosable without packet capture.
 */
int cloud_tls_connect(const struct cloud_config *config, struct cloud_tls *out)
{
    struct cloud_tls connection;
    X509_VERIFY_PARAM *parameters;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;
    if (!config || !out)
        return -1;

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
    cloud_tls_close(&connection);
    return -1;
}

/* ── framing ─────────────────────────────────────────────────────── */

static int cloud_tls_read_exact(SSL *ssl, unsigned char *out, size_t length)
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

/*
 * Like cloud_tls_read_exact, but tells an idle timeout apart from a real drop.
 *
 * Returns 0 on success, 1 when nothing arrived before SO_RCVTIMEO expired and
 * no bytes of a frame had been consumed, and -1 on a genuine failure.
 *
 * The distinction has to be made here, at the point where SSL_get_error still
 * describes the operation that just failed. The caller used to re-derive it with
 * SSL_get_error(ssl, -1) after this function had already consumed the error
 * state, passing a return value that was never the real one, and then decide
 * whether to drop the tunnel on the strength of that. That is how a healthy idle
 * connection ended up being torn down on a timer.
 *
 * A timeout partway through a frame is not recoverable: the stream is left
 * mid-message with no way to resynchronise, so it is reported as a failure.
 */
/*
 * Carries the reason a read failed back to the session loop.
 *
 * Without this the loop could only report "the read failed", which is not enough
 * to tell a peer FIN from an RST from a TLS record error, and those have
 * different causes and different fixes.
 */
struct cloud_read_error {
    int ssl_error;
    int sys_errno;
    unsigned long queued;
    size_t partial;
};

static const char *cloud_ssl_error_name(int error)
{
    switch (error) {
    case SSL_ERROR_NONE:
        return "none";
    case SSL_ERROR_ZERO_RETURN:
        return "zero_return";
    case SSL_ERROR_WANT_READ:
        return "want_read";
    case SSL_ERROR_WANT_WRITE:
        return "want_write";
    case SSL_ERROR_SYSCALL:
        return "syscall";
    case SSL_ERROR_SSL:
        return "ssl";
    default:
        return "other";
    }
}

static int cloud_tls_read_exact_idle(SSL *ssl, unsigned char *out, size_t length,
                                    struct cloud_read_error *failure)
{
    size_t received = 0;
    int64_t started = cloud_monotonic_ms();

    while (received < length) {
        int got;

        ERR_clear_error();
        errno = 0;
        got = SSL_read(ssl, out + received, (int)(length - received));
        if (got <= 0) {
            int error = SSL_get_error(ssl, got);

            /*
             * SO_RCVTIMEO expiry does not have one portable spelling. Depending
             * on the OpenSSL build a timed-out read inside SSL_read surfaces as
             * SSL_ERROR_SYSCALL with EAGAIN, or as SSL_ERROR_WANT_READ because
             * the BIO reports "retry" for a socket that is merely not ready.
             *
             * Treating WANT_READ as a bare retry made this loop spin inside
             * SSL_read for the whole session: the idle branch was never reached,
             * so no ping was ever sent and no liveness check ever ran. The
             * observed symptom was a tunnel that died on a fixed timer having
             * carried zero frames. So the elapsed time decides, not the code:
             * once the socket timeout has plainly passed with no byte of a frame
             * in hand, this is an idle timeout regardless of how it was spelled.
             */
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                int64_t now = cloud_monotonic_ms();

                if (received == 0 && now >= 0 && started >= 0 &&
                    now - started >= CLOUD_IO_TIMEOUT_MS)
                    return 1;
                continue;
            }
            if (received == 0 && error == SSL_ERROR_SYSCALL &&
                (errno == EAGAIN || errno == EWOULDBLOCK))
                return 1;
            if (failure) {
                failure->ssl_error = error;
                failure->sys_errno = errno;
                failure->queued = ERR_peek_last_error();
                failure->partial = received;
            }
            return -1;
        }
        received += (size_t)got;
    }
    return 0;
}

int cloud_tls_write_all(SSL *ssl, const unsigned char *data, size_t length)
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

/* Single read, returning the byte count. Used by the HTTP paths, which cannot
 * know the response length up front the way the frame reader can. */
int cloud_tls_read_some(SSL *ssl, unsigned char *out, size_t length)
{
    for (;;) {
        int got = SSL_read(ssl, out, (int)length);
        int error;

        if (got > 0)
            return got;
        error = SSL_get_error(ssl, got);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
            continue;
        if (error == SSL_ERROR_ZERO_RETURN)
            return 0;
        return -1;
    }
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
    if (cloud_tls_write_all(ssl, header, sizeof(header)) != 0)
        return -1;
    return cloud_tls_write_all(ssl, (const unsigned char *)text, length);
}

static int cloud_frame_read_body(SSL *ssl, const unsigned char header[4],
                                 struct json_object **out)
{
    unsigned char *payload;
    uint32_t length;
    struct json_object *parsed;

    length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
             ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    /* Validate before allocating so a peer cannot make us reserve 4 GiB. */
    if (!length || length > CLOUD_FRAME_MAX)
        return -1;

    payload = malloc(length + 1);
    if (!payload)
        return -1;
    if (cloud_tls_read_exact(ssl, payload, length) != 0) {
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

static int cloud_frame_read(SSL *ssl, struct json_object **out)
{
    unsigned char header[4];

    if (cloud_tls_read_exact(ssl, header, sizeof(header)) != 0)
        return -1;
    return cloud_frame_read_body(ssl, header, out);
}

/*
 * Frame read that reports an idle timeout separately. Returns 0 with a frame,
 * 1 when the read timed out with nothing pending, or -1 on failure.
 */
static int cloud_frame_read_idle(SSL *ssl, struct json_object **out,
                                 struct cloud_read_error *failure)
{
    unsigned char header[4];
    int rc = cloud_tls_read_exact_idle(ssl, header, sizeof(header), failure);

    if (rc != 0)
        return rc;
    if (cloud_frame_read_body(ssl, header, out) != 0) {
        if (failure)
            failure->partial = sizeof(header);
        return -1;
    }
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
    if (cloud_tls_write_all(ssl, (const unsigned char *)request,
                            (size_t)length) != 0)
        return -1;

    /* Read headers one byte at a time up to the blank line. The relay sends no
     * body with 101, so nothing is over-read into the frame stream. */
    while (received < sizeof(response) - 1) {
        if (cloud_tls_read_exact(ssl, (unsigned char *)response + received, 1) != 0)
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
 * Verifies an App frame signature against this router's ids.
 *
 * The transcript is CONTEXT || router_id || request_id || eph_pub || ciphertext
 * with no separators, so the router_id string has to match the App's byte for
 * byte. Two ids can name this router: relay_router_id (derived from both public
 * keys, what enrollment registered and what the relay routes on) and router_id
 * (a legacy locally generated UUID on routers that predate the derived scheme).
 *
 * Returns 1 when either id verifies. The derived id is tried first since it is
 * the contract value; the legacy id is a compatibility fallback for Apps that
 * pinned it before migration. When the two are equal only one check runs.
 */
static int cloud_request_signature_valid(const struct cloud_identity *identity,
                                        const char *request_id,
                                        const unsigned char *ephemeral,
                                        const unsigned char *ciphertext,
                                        size_t ciphertext_length,
                                        const unsigned char *signature,
                                        const unsigned char *signing_key)
{
    const char *derived = identity->relay_router_id;
    const char *legacy = identity->router_id;

    if (derived[0] &&
        cloud_envelope_verify_signature(derived, request_id, ephemeral,
                                       ciphertext, ciphertext_length,
                                       signature, signing_key) == 0)
        return 1;

    if (legacy[0] && (!derived[0] || strcmp(derived, legacy)) &&
        cloud_envelope_verify_signature(legacy, request_id, ephemeral,
                                       ciphertext, ciphertext_length,
                                       signature, signing_key) == 0)
        return 1;

    return 0;
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

    /*
     * The App binds its signature transcript to the router_id it talks to, and
     * that is the derived id: the relay indexes sessions by the derived id, so
     * that is the value the App has on the wire and signs over. Verifying
     * against identity->router_id alone rejected every remote request with
     * "frame signature is invalid" whenever the local id was still a legacy
     * UUID, because the two strings differ and the transcript is a bare
     * concatenation with no length prefixes.
     *
     * Both ids are this router's own, so trying the legacy one as a fallback
     * cannot let another router's frame verify here; it only keeps Apps that
     * pinned the pre-migration UUID working. Derived id is tried first because
     * it is what the current contract mandates.
     */
    if (!cloud_request_signature_valid(identity, request_id, ephemeral,
                                       ciphertext, ciphertext_length,
                                       signature, signing_key)) {
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

/*
 * Pushes the current authorized-App set as a standalone frame.
 *
 * Unlike the hello path this sends an empty array too: an empty refresh is how
 * revocation of the last paired App is expressed, and skipping it would leave
 * the relay holding a key the router no longer honours.
 *
 * A NULL ssl records the current set in `digest` without sending anything. That
 * is used right after the handshake, where hello already carried the set and a
 * second identical frame would be noise.
 *
 * Returns 0 when nothing needed sending or the frame went out; -1 only on a
 * write failure, which the caller treats as a dead tunnel.
 */
static int cloud_tunnel_push_authorized_apps(SSL *ssl, char *digest,
                                             size_t digest_size)
{
    struct json_object *authorized = cloud_devices_signing_keys();
    struct json_object *frame;
    const char *serialized;
    int rc = 0;

    if (!authorized)
        return 0;

    /* Only send when the set actually changed, so an idle router does not put a
     * frame on the wire every minute. The serialized array doubles as the
     * comparison key; it is bounded by CLOUD_MAX_AUTHORIZED_APPS entries. */
    serialized = json_object_to_json_string_ext(authorized,
                                                JSON_C_TO_STRING_PLAIN);
    if (!serialized) {
        json_object_put(authorized);
        return 0;
    }
    if (!ssl) {
        if (strlen(serialized) < digest_size)
            snprintf(digest, digest_size, "%s", serialized);
        else
            digest[0] = '\0';
        json_object_put(authorized);
        return 0;
    }
    if (strlen(serialized) < digest_size && !strcmp(digest, serialized)) {
        json_object_put(authorized);
        return 0;
    }

    frame = json_object_new_object();
    if (!frame) {
        json_object_put(authorized);
        return 0;
    }
    json_object_object_add(frame, "protocol",
                           json_object_new_string(CLOUD_PROTOCOL));
    json_object_object_add(frame, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(frame, "kind",
                           json_object_new_string("tunnel_authorized_apps"));
    /* Ownership moves into the frame. */
    json_object_object_add(frame, "authorized_apps", authorized);

    if (cloud_frame_write(ssl, frame) != 0)
        rc = -1;
    else if (strlen(serialized) < digest_size)
        snprintf(digest, digest_size, "%s", serialized);
    else
        digest[0] = '\0';

    json_object_put(frame);
    return rc;
}

static int cloud_tunnel_hello(SSL *ssl, const struct cloud_config *config)
{
    const struct cloud_identity *identity = cloud_identity();
    struct json_object *frame;
    struct json_object *reply = NULL;
    struct json_object *accepted = NULL;
    struct json_object *authorized;
    char token[512];
    int rc = -1;

    if (!identity)
        return -1;
    /*
     * A token obtained through self enrollment wins over a UCI one. Both are
     * valid ways to be registered, but the enrolled token was minted for this
     * exact key pair, whereas a stale UCI value left over from an earlier relay
     * would fail the handshake with no clue as to which credential was used.
     */
    if (cloud_enroll_token_load(token, sizeof(token)) != 0) {
        if (!config->auth_token[0])
            return -1;
        snprintf(token, sizeof(token), "%s", config->auth_token);
    }
    frame = json_object_new_object();
    if (!frame) {
        OPENSSL_cleanse(token, sizeof(token));
        return -1;
    }
    json_object_object_add(frame, "protocol",
                           json_object_new_string(CLOUD_PROTOCOL));
    json_object_object_add(frame, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(frame, "kind", json_object_new_string("tunnel_hello"));
    /*
     * The relay looks up the tunnel token by the router_id in this frame, and
     * enrollment registered it under the derived id, so the two must agree.
     * Sending the legacy UUID here would authenticate against a token that was
     * never stored for it and be rejected as tunnel_unauthorized.
     */
    json_object_object_add(frame, "router_id",
                           json_object_new_string(identity->relay_router_id[0] ?
                                                  identity->relay_router_id :
                                                  identity->router_id));
    json_object_object_add(frame, "auth_token",
                           json_object_new_string(token));
    OPENSSL_cleanse(token, sizeof(token));
    /*
     * Declare which Apps may ask the relay whether this router is online.
     * Without this the relay has no key to verify against and refuses every
     * presence query, so the App would show the router as unreachable even
     * while the tunnel is up.
     *
     * Only public keys are sent. The field is omitted when there is nothing to
     * declare, because the relay treats an absent list as "no opinion" and an
     * empty one as a deliberate statement.
     */
    authorized = cloud_devices_signing_keys();
    if (authorized) {
        if (json_object_array_length(authorized) > 0)
            json_object_object_add(frame, "authorized_apps", authorized);
        else
            json_object_put(authorized);
    }
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
    struct cloud_tls connection;
    int64_t last_ping;
    int64_t last_apps_refresh;
    /* Last time a frame actually arrived, kept separate from ping bookkeeping so
     * a dead peer cannot be masked by our own sends. */
    int64_t last_frame;
    /* Serialized copy of the last pushed set, so an unchanged set costs no
     * frame. Sized for CLOUD_MAX_AUTHORIZED_APPS base64 keys plus separators. */
    char apps_digest[CLOUD_MAX_AUTHORIZED_APPS * 48 + 8];
    /* Why the loop exited, and when it started, so the teardown can say which
     * branch fired instead of leaving every drop indistinguishable. */
    char exit_detail[112];
    int64_t session_start;
    /* Frames received and pings sent during this session. Together with the
     * exit reason these separate an idle timeout from a connection-lifetime cap:
     * a session that received pongs the whole way through and still died was not
     * idle, so a keepalive interval cannot be the cause. */
    unsigned long frames_in;
    unsigned long pings_out;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;
    apps_digest[0] = '\0';
    snprintf(exit_detail, sizeof(exit_detail), "%s", "loop_exit_shutdown");
    frames_in = 0;
    pings_out = 0;

    cloud_tunnel_set_state("connecting", "");
    if (cloud_tls_connect(config, &connection) != 0)
        return -1;
    if (cloud_tunnel_upgrade(connection.ssl, config) != 0 ||
        cloud_tunnel_hello(connection.ssl, config) != 0) {
        cloud_tls_close(&connection);
        return -1;
    }

    cloud_tunnel_set_state("online", "");
    cloud_tunnel_set_connected(1);
    fprintf(stderr, "[%s] tunnel established host=%s port=%u\n",
            CLOUD_SERVICE_NAME, config->host, (unsigned int)config->port);
    last_ping = cloud_monotonic_ms();
    last_apps_refresh = last_ping;
    last_frame = last_ping;
    session_start = last_ping;
    /* The hello already carried the current set, so seed the digest without
     * sending a second copy. */
    cloud_tunnel_push_authorized_apps(NULL, apps_digest, sizeof(apps_digest));

    while (cloud_tunnel_running()) {
        struct json_object *frame = NULL;
        struct cloud_read_error failure;
        const char *kind;
        int64_t now;
        int read_rc;

        memset(&failure, 0, sizeof(failure));
        read_rc = cloud_frame_read_idle(connection.ssl, &frame, &failure);
        if (read_rc < 0) {
            /*
             * The distinction that matters here: zero_return is an orderly TLS
             * close by the relay, syscall with ECONNRESET is the path being cut
             * mid-connection, and syscall with errno 0 is a FIN without a close
             * notify, which is what a middlebox aging out the flow looks like.
             */
            snprintf(exit_detail, sizeof(exit_detail),
                     "read_failed ssl_error=%s(%d) errno=%d(%s) queued=0x%lx partial=%zu",
                     cloud_ssl_error_name(failure.ssl_error), failure.ssl_error,
                     failure.sys_errno,
                     failure.sys_errno ? strerror(failure.sys_errno) : "-",
                     failure.queued, failure.partial);
            break;
        }
        if (read_rc > 0) {
            /*
             * Nothing arrived within SO_RCVTIMEO. That is the normal state of an
             * idle tunnel and must not end it. Send a ping only when one is
             * actually due, then keep waiting.
             *
             * This loop used to tear the tunnel down here whenever its guess
             * about errno did not hold, which produced a reconnect roughly every
             * two minutes on a connection that was perfectly healthy. It also
             * sent a ping on every single timeout, so the ping interval was
             * effectively the socket timeout rather than the configured one.
             */
            now = cloud_monotonic_ms();
            if (now < 0)
                continue;
            /*
             * A peer that has stopped answering must still be noticed. Pings are
             * answered with pongs, so silence for this long means the connection
             * is gone even though the socket has not reported an error yet.
             */
            if (now - last_frame >= CLOUD_TUNNEL_IDLE_LIMIT_MS) {
                snprintf(exit_detail, sizeof(exit_detail),
                         "relay_silent idle_ms=%lld",
                         (long long)(now - last_frame));
                cloud_tunnel_set_state("connecting", "relay_silent");
                break;
            }
            if (now - last_ping >= CLOUD_TUNNEL_PING_INTERVAL_MS) {
                struct json_object *ping = json_object_new_object();

                if (!ping)
                    continue;
                json_object_object_add(ping, "protocol",
                                       json_object_new_string(CLOUD_PROTOCOL));
                json_object_object_add(ping, "version",
                                       json_object_new_int(CLOUD_PROTOCOL_VERSION));
                json_object_object_add(ping, "kind",
                                       json_object_new_string("tunnel_ping"));
                if (cloud_frame_write(connection.ssl, ping) != 0) {
                    json_object_put(ping);
                    snprintf(exit_detail, sizeof(exit_detail),
                             "ping_write_failed errno=%d(%s)", errno,
                             errno ? strerror(errno) : "-");
                    break;
                }
                json_object_put(ping);
                last_ping = now;
                pings_out++;
            }
            /* Refresh here too: an idle tunnel never reaches the bottom of the
             * loop, and revocation must not wait for the next App request. */
            if (now - last_apps_refresh >= CLOUD_TUNNEL_APPS_REFRESH_MS) {
                last_apps_refresh = now;
                if (cloud_tunnel_push_authorized_apps(connection.ssl, apps_digest,
                                                      sizeof(apps_digest)) != 0) {
                    snprintf(exit_detail, sizeof(exit_detail),
                             "apps_push_failed_idle errno=%d(%s)", errno,
                             errno ? strerror(errno) : "-");
                    break;
                }
            }
            continue;
        }

        kind = cloud_frame_string(frame, "kind");
        frames_in++;
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
                    snprintf(exit_detail, sizeof(exit_detail),
                             "response_write_failed errno=%d(%s)", errno,
                             errno ? strerror(errno) : "-");
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
        /*
         * Traffic is proof of life, so it defers the next ping. This used to
         * advance last_ping only once the interval had already elapsed, which
         * meant an active tunnel reported a stale ping age and skewed the idle
         * branch's arithmetic.
         */
        if (now >= 0)
            last_ping = now;
        if (now >= 0)
            last_frame = now;
        if (now >= 0 && now - last_apps_refresh >= CLOUD_TUNNEL_APPS_REFRESH_MS) {
            last_apps_refresh = now;
            if (cloud_tunnel_push_authorized_apps(connection.ssl, apps_digest,
                                                  sizeof(apps_digest)) != 0) {
                snprintf(exit_detail, sizeof(exit_detail),
                         "apps_push_failed_active errno=%d(%s)", errno,
                         errno ? strerror(errno) : "-");
                break;
            }
        }
    }

    {
        char detail[160];

        snprintf(detail, sizeof(detail), "%s in=%lu pings=%lu", exit_detail,
                 frames_in, pings_out);
        cloud_tunnel_note_disconnect(detail,
                                     session_start ?
                                         cloud_monotonic_ms() - session_start : 0);
    }
    cloud_tunnel_set_connected(0);
    cloud_tls_close(&connection);
    return 0;
}

/*
 * Obtains a tunnel credential when none is stored yet.
 *
 * Enrollment runs on the tunnel thread, not at startup, because it needs the
 * network and must not delay the daemon coming up or answering ubus. Failures
 * are recorded in the tunnel state with the relay's own code so a disabled or
 * statically-registered relay reads differently from a broken one.
 *
 * Returns 1 when a credential is available, 0 when it is not.
 */
static int cloud_tunnel_ensure_credential(const struct cloud_config *config)
{
    struct cloud_enroll_result result;

    if (cloud_enroll_token_present() || config->auth_token[0])
        return 1;

    cloud_tunnel_set_state("enrolling", "");
    if (cloud_enroll_run(config, &result) == 0)
        return 1;

    /*
     * statically_configured is not a failure: the operator registered this
     * router in the relay's config.json, so the token belongs in UCI. Saying so
     * plainly keeps the UI from showing a fault for a working setup.
     */
    cloud_tunnel_set_state(!strcmp(result.code, "statically_configured") ?
                               "misconfigured" : "unenrolled",
                           result.code);
    fprintf(stderr, "[%s] enrollment failed code=%s http=%d\n",
            CLOUD_SERVICE_NAME, result.code, result.http_status);
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
        if (!cloud_tunnel_ensure_credential(&config)) {
            /* No credential means every dial would be refused, so back off
             * instead of hammering the relay. */
        } else if (cloud_tunnel_session(&config) == 0) {
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
    /*
     * A missing token is no longer fatal: the thread enrolls to obtain one. It
     * still needs a host, because enrollment dials the same relay.
     */

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
