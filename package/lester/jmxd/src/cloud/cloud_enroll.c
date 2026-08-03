// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Self enrollment against the relay (ROUTER_AGENT_CONTRACT.md section 6.1).
 *
 * Without this the router can only reach a relay whose operator has manually
 * pasted a token into UCI, which is not something a home user can do. Here the
 * router proves possession of its two private keys and receives a tunnel token
 * in exchange.
 *
 * Two properties are load-bearing:
 *
 *   1. The relay's proposed router_id is compared against the locally derived
 *      one before anything is signed. A mismatch means the byte concatenation
 *      or encoding disagrees, and signing anyway would burn a one-shot challenge
 *      while producing a confusing 403 instead of a clear diagnosis.
 *   2. The token is returned exactly once. If persisting it fails, the whole
 *      attempt is reported as failed, because reporting success would leave a
 *      router that believes it is enrolled while holding no usable secret.
 */
#include "cloud_internal.h"

#include <pthread.h>

#define CLOUD_ENROLL_PATH "/v1/router/enroll"
/* The relay caps request bodies at 8 KiB; its responses are far smaller. This
 * bound exists so a hostile or broken peer cannot stream indefinitely. */
#define CLOUD_ENROLL_RESPONSE_MAX 16384
#define CLOUD_ENROLL_CHALLENGE_MAX 256

static void cloud_enroll_fail(struct cloud_enroll_result *out, int http_status,
                              const char *code, const char *message)
{
    if (!out)
        return;
    out->ok = 0;
    out->http_status = http_status;
    snprintf(out->code, sizeof(out->code), "%s", code ? code : "enroll_failed");
    snprintf(out->message, sizeof(out->message), "%s", message ? message : "");
}

int cloud_enroll_token_load(char *out, size_t out_size)
{
    char buffer[512] = {0};
    size_t length;
    FILE *fp;

    if (!out || out_size < 2)
        return -1;
    fp = fopen(CLOUD_TUNNEL_TOKEN_PATH, "r");
    if (!fp)
        return -1;
    if (!fgets(buffer, sizeof(buffer), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    length = strlen(buffer);
    while (length && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r' ||
                      buffer[length - 1] == ' '))
        buffer[--length] = '\0';
    /* Same floor the relay enforces on configured tokens. A shorter value is a
     * truncated file, not a usable secret. */
    if (length < 32 || length >= out_size)
        return -1;
    snprintf(out, out_size, "%s", buffer);
    return 0;
}

int cloud_enroll_token_present(void)
{
    char token[512];
    int present;

    present = cloud_enroll_token_load(token, sizeof(token)) == 0;
    OPENSSL_cleanse(token, sizeof(token));
    return present;
}

/* 0600 through a temp file plus rename: the token cannot be fetched a second
 * time, so a half-written file would mean re-enrolling to recover. */
static int cloud_enroll_token_store(const char *token)
{
    char temp[512];
    size_t length;
    ssize_t written;
    int fd;

    if (!token || !token[0])
        return -1;
    length = strlen(token);
    if (snprintf(temp, sizeof(temp), "%s.tmp", CLOUD_TUNNEL_TOKEN_PATH) >=
        (int)sizeof(temp))
        return -1;
    fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    written = write(fd, token, length);
    if (written < 0 || (size_t)written != length || fsync(fd) != 0) {
        close(fd);
        unlink(temp);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(temp);
        return -1;
    }
    if (rename(temp, CLOUD_TUNNEL_TOKEN_PATH) != 0) {
        unlink(temp);
        return -1;
    }
    return 0;
}

/*
 * Signs CLOUD_ENROLL_CONTEXT || router_id || challenge.
 *
 * The challenge is signed as the base64 string the relay sent, not its decoded
 * bytes. That is easy to get wrong and produces a signature the relay rejects
 * with no hint as to why, so it is spelled out here.
 */
static int cloud_enroll_sign_challenge(const char *router_id,
                                       const char *challenge,
                                       char **out_signature_b64)
{
    unsigned char signature[CLOUD_ED25519_SIG_LEN];
    unsigned char *message;
    size_t context_len = strlen(CLOUD_ENROLL_CONTEXT);
    size_t router_len = strlen(router_id);
    size_t challenge_len = strlen(challenge);
    size_t total = context_len + router_len + challenge_len;
    int rc = -1;

    message = malloc(total);
    if (!message)
        return -1;
    memcpy(message, CLOUD_ENROLL_CONTEXT, context_len);
    memcpy(message + context_len, router_id, router_len);
    memcpy(message + context_len + router_len, challenge, challenge_len);

    if (cloud_identity_sign(message, total, signature, sizeof(signature)) == 0)
        rc = cloud_base64_encode(signature, sizeof(signature),
                                 out_signature_b64);
    free(message);
    OPENSSL_cleanse(signature, sizeof(signature));
    return rc;
}

/*
 * One HTTP POST over an already-verified TLS connection.
 *
 * A fresh connection per step keeps this independent of whether the relay's
 * front end honours keep-alive, at the cost of one extra handshake on a path
 * that runs at most a few times in a router's life.
 */
static int cloud_enroll_post(const struct cloud_config *config,
                             const char *body, int *out_status,
                             struct json_object **out_json)
{
    struct cloud_tls connection;
    char header[512];
    unsigned char *response = NULL;
    size_t capacity = CLOUD_ENROLL_RESPONSE_MAX;
    size_t received = 0;
    char *separator;
    int status = 0;
    int length;
    int rc = -1;

    if (out_status)
        *out_status = 0;
    if (out_json)
        *out_json = NULL;

    if (cloud_tls_connect(config, &connection) != 0)
        return -1;

    length = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s/%s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        CLOUD_ENROLL_PATH, config->host, CLOUD_SERVICE_NAME,
        CLOUD_CONTRACT_VERSION, strlen(body));
    if (length <= 0 || (size_t)length >= sizeof(header))
        goto done;
    if (cloud_tls_write_all(connection.ssl, (const unsigned char *)header,
                            (size_t)length) != 0 ||
        cloud_tls_write_all(connection.ssl, (const unsigned char *)body,
                            strlen(body)) != 0)
        goto done;

    response = malloc(capacity + 1);
    if (!response)
        goto done;
    for (;;) {
        int got;

        if (received >= capacity)
            break;
        got = cloud_tls_read_some(connection.ssl, response + received,
                                  capacity - received);
        if (got <= 0)
            break;
        received += (size_t)got;
    }
    response[received] = '\0';

    if (received < 12 || strncmp((const char *)response, "HTTP/1.", 7))
        goto done;
    status = atoi((const char *)response + 9);
    if (out_status)
        *out_status = status;

    /* The body is JSON in every documented outcome, including the errors, so
     * the code and message survive even on a 4xx. */
    separator = strstr((char *)response, "\r\n\r\n");
    if (separator && out_json) {
        struct json_object *parsed = json_tokener_parse(separator + 4);

        if (parsed && json_object_is_type(parsed, json_type_object))
            *out_json = parsed;
        else if (parsed)
            json_object_put(parsed);
    }
    rc = 0;
done:
    free(response);
    cloud_tls_close(&connection);
    return rc;
}

static const char *cloud_enroll_json_string(struct json_object *root,
                                            const char *name)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, name, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

/* Errors arrive as {"ok":false,"error":{"code":...}}; some front ends flatten
 * that, so both shapes are accepted. */
static void cloud_enroll_capture_error(struct cloud_enroll_result *out,
                                       int status, struct json_object *root,
                                       const char *fallback_code)
{
    struct json_object *error = NULL;
    const char *code = NULL;
    const char *message = NULL;

    if (root && json_object_object_get_ex(root, "error", &error) && error &&
        json_object_is_type(error, json_type_object)) {
        code = cloud_enroll_json_string(error, "code");
        message = cloud_enroll_json_string(error, "message");
    }
    if (!code)
        code = cloud_enroll_json_string(root, "code");
    if (!message)
        message = cloud_enroll_json_string(root, "message");
    cloud_enroll_fail(out, status, code ? code : fallback_code, message);
}

static struct json_object *cloud_enroll_data(struct json_object *root)
{
    struct json_object *ok = NULL;
    struct json_object *data = NULL;

    if (!root)
        return NULL;
    if (!json_object_object_get_ex(root, "ok", &ok) || !ok ||
        !json_object_get_boolean(ok))
        return NULL;
    if (!json_object_object_get_ex(root, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object))
        return NULL;
    return data;
}

int cloud_enroll_run(const struct cloud_config *config,
                     struct cloud_enroll_result *out)
{
    const struct cloud_identity *identity;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    struct json_object *data;
    char *kex_b64 = NULL;
    char *signing_b64 = NULL;
    char *signature_b64 = NULL;
    char challenge[CLOUD_ENROLL_CHALLENGE_MAX];
    char derived[64];
    const char *value;
    int status = 0;
    int rc = -1;

    if (!config || !out)
        return -1;
    memset(out, 0, sizeof(*out));

    if (!config->host[0]) {
        cloud_enroll_fail(out, 0, "relay_host_missing",
                          "relay host is not configured");
        return -1;
    }
    if (cloud_identity_load(NULL) != 0 || !(identity = cloud_identity())) {
        cloud_enroll_fail(out, 0, "identity_unavailable",
                          "router identity could not be loaded");
        return -1;
    }
    /*
     * A legacy UUID router_id cannot self enroll: no signature can make the
     * relay's fingerprint check pass. Refusing here with a specific code is more
     * useful than letting the relay answer router_id_mismatch, and rewriting the
     * id instead would strand every App that already paired with this router.
     */
    if (!identity->router_id_is_key_derived) {
        cloud_enroll_fail(out, 0, "router_id_not_key_derived",
                          "this router uses a legacy router_id and must be "
                          "registered statically on the relay");
        snprintf(out->router_id, sizeof(out->router_id), "%s",
                 identity->router_id);
        return -1;
    }
    snprintf(out->router_id, sizeof(out->router_id), "%s", identity->router_id);

    if (cloud_base64_encode(identity->public_key, CLOUD_X25519_KEY_LEN,
                            &kex_b64) != 0 ||
        cloud_base64_encode(identity->signing_public_key,
                            CLOUD_ED25519_KEY_LEN, &signing_b64) != 0) {
        cloud_enroll_fail(out, 0, "encode_failed",
                          "public keys could not be encoded");
        goto done;
    }

    request = json_object_new_object();
    if (!request) {
        cloud_enroll_fail(out, 0, "enroll_failed", "out of memory");
        goto done;
    }
    json_object_object_add(request, "type",
                           json_object_new_string("dreamingos-relay-enroll"));
    json_object_object_add(request, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(request, "kex_public_key",
                           json_object_new_string(kex_b64));
    json_object_object_add(request, "signing_public_key",
                           json_object_new_string(signing_b64));

    if (cloud_enroll_post(config,
                          json_object_to_json_string_ext(request,
                                                         JSON_C_TO_STRING_PLAIN),
                          &status, &response) != 0) {
        cloud_enroll_fail(out, status, "relay_unreachable",
                          "the relay could not be reached");
        goto done;
    }
    json_object_put(request);
    request = NULL;

    data = cloud_enroll_data(response);
    if (!data) {
        cloud_enroll_capture_error(out, status, response, "challenge_failed");
        goto done;
    }
    value = cloud_enroll_json_string(data, "challenge");
    if (!value || !value[0] || strlen(value) >= sizeof(challenge)) {
        cloud_enroll_fail(out, status, "challenge_failed",
                          "the relay returned no usable challenge");
        goto done;
    }
    snprintf(challenge, sizeof(challenge), "%s", value);

    /*
     * Compare the relay's router_id against the locally derived one before
     * signing. This is the check the contract asks for, and it is what turns a
     * concatenation-order bug into a clear local error rather than a 403 after
     * a wasted challenge.
     */
    if (cloud_identity_derive_router_id(identity->public_key,
                                        identity->signing_public_key,
                                        derived, sizeof(derived)) != 0) {
        cloud_enroll_fail(out, status, "encode_failed",
                          "router_id could not be derived");
        goto done;
    }
    value = cloud_enroll_json_string(data, "router_id");
    if (!value || strcmp(value, derived)) {
        cloud_enroll_fail(out, status, "router_id_mismatch",
                          "the relay derived a different router_id");
        goto done;
    }
    json_object_put(response);
    response = NULL;

    if (cloud_enroll_sign_challenge(derived, challenge, &signature_b64) != 0) {
        cloud_enroll_fail(out, 0, "sign_failed",
                          "the enrollment challenge could not be signed");
        goto done;
    }

    request = json_object_new_object();
    if (!request) {
        cloud_enroll_fail(out, 0, "enroll_failed", "out of memory");
        goto done;
    }
    json_object_object_add(request, "type",
                           json_object_new_string("dreamingos-relay-enroll"));
    json_object_object_add(request, "version",
                           json_object_new_int(CLOUD_PROTOCOL_VERSION));
    json_object_object_add(request, "router_id", json_object_new_string(derived));
    json_object_object_add(request, "kex_public_key",
                           json_object_new_string(kex_b64));
    json_object_object_add(request, "signing_public_key",
                           json_object_new_string(signing_b64));
    json_object_object_add(request, "challenge",
                           json_object_new_string(challenge));
    json_object_object_add(request, "signature",
                           json_object_new_string(signature_b64));

    if (cloud_enroll_post(config,
                          json_object_to_json_string_ext(request,
                                                         JSON_C_TO_STRING_PLAIN),
                          &status, &response) != 0) {
        cloud_enroll_fail(out, status, "relay_unreachable",
                          "the relay could not be reached");
        goto done;
    }

    data = cloud_enroll_data(response);
    if (!data) {
        cloud_enroll_capture_error(out, status, response,
                                   "enroll_signature_invalid");
        goto done;
    }
    value = cloud_enroll_json_string(data, "tunnel_token");
    if (!value || strlen(value) < 32) {
        cloud_enroll_fail(out, status, "enroll_failed",
                          "the relay returned no usable tunnel token");
        goto done;
    }
    if (cloud_enroll_token_store(value) != 0) {
        /* The relay will not hand out this token again, so a storage failure is
         * reported as failure rather than success with a lost secret. */
        cloud_enroll_fail(out, status, "token_persist_failed",
                          "the tunnel token could not be persisted");
        goto done;
    }

    out->ok = 1;
    out->http_status = status;
    snprintf(out->code, sizeof(out->code), "%s", "enrolled");
    snprintf(out->message, sizeof(out->message), "%s",
             "the router enrolled with the relay");
    fprintf(stderr, "[%s] enrolled with relay host=%s router_id=%s\n",
            CLOUD_SERVICE_NAME, config->host, derived);
    rc = 0;
done:
    if (request)
        json_object_put(request);
    if (response)
        json_object_put(response);
    free(kex_b64);
    free(signing_b64);
    free(signature_b64);
    OPENSSL_cleanse(challenge, sizeof(challenge));
    return rc;
}

/* ── asynchronous job ────────────────────────────────────────────── */

/*
 * One enrollment at a time, tracked so a caller can poll instead of blocking.
 *
 * The alternative, running enrollment inline in the ubus handler, would freeze
 * the event loop for two TLS handshakes plus whatever the relay takes to answer.
 * Status queries would time out during exactly the window a UI is polling them.
 */
static struct {
    pthread_mutex_t lock;
    int running;
    int force;
    /* "idle" until the first run, then "running" / "succeeded" / "failed". */
    char state[16];
    char code[64];
    char message[192];
    char router_id[CLOUD_ROUTER_ID_MAX + 1];
    int http_status;
    int64_t started_at;
    int64_t finished_at;
} g_enroll_job = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = "idle",
};

static void *cloud_enroll_job_thread(void *argument)
{
    struct cloud_enroll_result result;
    struct cloud_config config;
    int force;

    (void)argument;
    pthread_mutex_lock(&g_enroll_job.lock);
    force = g_enroll_job.force;
    pthread_mutex_unlock(&g_enroll_job.lock);

    memset(&result, 0, sizeof(result));
    if (cloud_config_load(&config) != 0) {
        cloud_enroll_fail(&result, 0, "config_unavailable",
                          "relay configuration could not be read");
    } else if (!force && cloud_enroll_token_present()) {
        result.ok = 1;
        snprintf(result.code, sizeof(result.code), "%s", "already_enrolled");
        snprintf(result.message, sizeof(result.message), "%s",
                 "a tunnel token is already stored");
        cloud_config_cleanse(&config);
    } else {
        cloud_enroll_run(&config, &result);
        cloud_config_cleanse(&config);
    }

    pthread_mutex_lock(&g_enroll_job.lock);
    snprintf(g_enroll_job.state, sizeof(g_enroll_job.state), "%s",
             result.ok ? "succeeded" : "failed");
    snprintf(g_enroll_job.code, sizeof(g_enroll_job.code), "%s", result.code);
    snprintf(g_enroll_job.message, sizeof(g_enroll_job.message), "%s",
             result.message);
    snprintf(g_enroll_job.router_id, sizeof(g_enroll_job.router_id), "%s",
             result.router_id);
    g_enroll_job.http_status = result.http_status;
    g_enroll_job.finished_at = cloud_now_s();
    g_enroll_job.running = 0;
    pthread_mutex_unlock(&g_enroll_job.lock);
    return NULL;
}

int cloud_enroll_job_start(int force)
{
    pthread_attr_t attributes;
    pthread_t thread;
    int rc;

    pthread_mutex_lock(&g_enroll_job.lock);
    if (g_enroll_job.running) {
        pthread_mutex_unlock(&g_enroll_job.lock);
        return 1;
    }
    g_enroll_job.running = 1;
    g_enroll_job.force = force ? 1 : 0;
    snprintf(g_enroll_job.state, sizeof(g_enroll_job.state), "%s", "running");
    g_enroll_job.code[0] = '\0';
    g_enroll_job.message[0] = '\0';
    g_enroll_job.router_id[0] = '\0';
    g_enroll_job.http_status = 0;
    g_enroll_job.started_at = cloud_now_s();
    g_enroll_job.finished_at = 0;
    pthread_mutex_unlock(&g_enroll_job.lock);

    /* Detached: nothing joins this thread, and the result is published through
     * the guarded snapshot rather than a return value. */
    if (pthread_attr_init(&attributes) != 0)
        goto fail;
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attributes, cloud_enroll_job_thread, NULL);
    pthread_attr_destroy(&attributes);
    if (rc != 0)
        goto fail;
    return 0;
fail:
    pthread_mutex_lock(&g_enroll_job.lock);
    g_enroll_job.running = 0;
    snprintf(g_enroll_job.state, sizeof(g_enroll_job.state), "%s", "failed");
    snprintf(g_enroll_job.code, sizeof(g_enroll_job.code), "%s",
             "thread_start_failed");
    g_enroll_job.finished_at = cloud_now_s();
    pthread_mutex_unlock(&g_enroll_job.lock);
    return -1;
}

struct json_object *cloud_enroll_job_json(void)
{
    struct json_object *job = json_object_new_object();

    if (!job)
        return NULL;
    pthread_mutex_lock(&g_enroll_job.lock);
    json_object_object_add(job, "state",
                           json_object_new_string(g_enroll_job.state));
    /* null rather than empty strings and zeros, so a caller can tell "no value
     * yet" from a real value. */
    json_object_object_add(job, "code",
                           g_enroll_job.code[0] ?
                               json_object_new_string(g_enroll_job.code) : NULL);
    json_object_object_add(job, "message",
                           g_enroll_job.message[0] ?
                               json_object_new_string(g_enroll_job.message) : NULL);
    json_object_object_add(job, "router_id",
                           g_enroll_job.router_id[0] ?
                               json_object_new_string(g_enroll_job.router_id) : NULL);
    json_object_object_add(job, "relay_status",
                           g_enroll_job.http_status > 0 ?
                               json_object_new_int(g_enroll_job.http_status) : NULL);
    json_object_object_add(job, "started_at",
                           g_enroll_job.started_at > 0 ?
                               json_object_new_int64(g_enroll_job.started_at) : NULL);
    json_object_object_add(job, "finished_at",
                           g_enroll_job.finished_at > 0 ?
                               json_object_new_int64(g_enroll_job.finished_at) : NULL);
    pthread_mutex_unlock(&g_enroll_job.lock);
    return job;
}
