// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Device-side account binding by stable code (cloud-web contract §15.4).
 *
 * A user reads a stable binding code off the cloud portal and types it into the
 * device web UI. The device then proves possession of its factory Ed25519 key
 * (challenge/response, cloud-web contract §5) and redeems the code, which
 * records "this router belongs to that account" on the cloud. No account
 * password ever reaches the device, and the redeem only registers the binding
 * relationship: it does NOT open the browser data plane (that tunnel is the
 * separate, locked 09-23 web-access track).
 *
 * Transport uses the browser channel's configured API and trust bundle, falling
 * back to relay 'cert' only when no browser API is configured. Binding never
 * permits disabled TLS verification and does not rewrite the App relay config.
 * The signing transcript is byte-for-byte cw_prove's:
 *   CW_CONTEXT "\n" "binding" "\n" router_id "\n" nonce   (no trailing newline)
 * getting the newlines or the router_id wrong yields a 401 the relay cannot
 * explain, so it is spelled out rather than assembled ad hoc.
 */
#include "cloud_internal.h"
#include "cloud_browser.h"

#include <ctype.h>
#include <curl/curl.h>
#include <pthread.h>

/* Matches cloud-web's CW_CONTEXT. The device is the client the contract in
 * dreamingrelay/cloud-web/docs/cloud-web-v1-http-contract.md §5.2 was written
 * for; this string and the transcript below are that contract. */
#define CLOUD_BIND_CONTEXT "dreamingos-cloud-web-v1"
#define CLOUD_BIND_ACTION "binding"
#define CLOUD_BIND_CHALLENGE_PATH "/api/v1/cloud/web-access/agent/challenge"
#define CLOUD_BIND_CODE_PATH "/api/v1/cloud/web-access/agent/bind-code"
#define CLOUD_BIND_CODE_HEX_LEN 24
#define CLOUD_BIND_NONCE_HEX_LEN 32
#define CLOUD_BIND_DISPLAY_NAME_MAX 64
#define CLOUD_BIND_BODY_MAX 4096U
#define CLOUD_BIND_RESPONSE_MAX (64U * 1024U)

struct cloud_bind_buffer {
    unsigned char *data;
    size_t length;
    size_t capacity;
};

static pthread_once_t g_cloud_bind_curl_once = PTHREAD_ONCE_INIT;

static void cloud_bind_curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static void cloud_bind_fail(struct cloud_bind_result *out, int http_status,
                            const char *code, const char *message)
{
    if (!out)
        return;
    out->ok = 0;
    out->http_status = http_status;
    snprintf(out->code, sizeof(out->code), "%s", code ? code : "bind_failed");
    snprintf(out->message, sizeof(out->message), "%s", message ? message : "");
}

static size_t cloud_bind_write_body(char *data, size_t size, size_t count,
                                    void *argument)
{
    struct cloud_bind_buffer *buffer = argument;
    size_t length = size * count;

    if (!buffer || length > buffer->capacity - buffer->length)
        return 0;
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return length;
}

static const char *cloud_bind_json_string(struct json_object *root,
                                          const char *name)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, name, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int64_t cloud_bind_json_int(struct json_object *root, const char *name)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, name, &value) || !value ||
        !json_object_is_type(value, json_type_int))
        return 0;
    return json_object_get_int64(value);
}

static struct json_object *cloud_bind_response_data(struct json_object *root)
{
    struct json_object *ok = NULL;
    struct json_object *data = NULL;

    if (!root || !json_object_object_get_ex(root, "ok", &ok) || !ok ||
        !json_object_get_boolean(ok) ||
        !json_object_object_get_ex(root, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object))
        return NULL;
    return data;
}

/* Errors arrive as {"error":{"code","message"}} or a flattened {code,message}
 * depending on the front end; both are accepted so the cloud's own code (the
 * one the UI renders differently, e.g. invalid_binding_code vs rate_limited)
 * survives to the caller. */
static void cloud_bind_capture_error(struct cloud_bind_result *out, int status,
                                     struct json_object *root,
                                     const char *fallback)
{
    struct json_object *error = NULL;
    const char *code = NULL;
    const char *message = NULL;

    if (root && json_object_object_get_ex(root, "error", &error) && error &&
        json_object_is_type(error, json_type_object)) {
        code = cloud_bind_json_string(error, "code");
        message = cloud_bind_json_string(error, "message");
    }
    if (!code)
        code = cloud_bind_json_string(root, "code");
    if (!message)
        message = cloud_bind_json_string(root, "message");
    cloud_bind_fail(out, status, code ? code : fallback, message);
}

static int cloud_bind_url(const struct cloud_cert_config *config,
                          const char *path, char *out, size_t out_size)
{
    int written;

    if (!config || !config->api_host[0] || !path || !out)
        return -1;
    written = snprintf(out, out_size, "https://%s:%u%s", config->api_host,
                       (unsigned)config->api_port, path);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

/*
 * One HTTPS POST, modelled on cloud_cert_post: a fresh connection per call,
 * https-only, redirects refused, and TLS verification driven by the shared cert
 * config so binding trusts exactly what certificate issuance already trusts.
 */
static int cloud_bind_post(const struct cloud_cert_config *config,
                           const char *path, const char *body, int *status,
                           struct json_object **response)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    struct cloud_bind_buffer buffer;
    char url[512];
    long http_status = 0;
    CURLcode curl_rc;
    int rc = -1;

    if (status)
        *status = 0;
    if (response)
        *response = NULL;
    if (!config || !body || strlen(body) > CLOUD_BIND_BODY_MAX ||
        cloud_bind_url(config, path, url, sizeof(url)) != 0)
        return -1;

    pthread_once(&g_cloud_bind_curl_once, cloud_bind_curl_init_once);
    buffer.capacity = CLOUD_BIND_RESPONSE_MAX;
    buffer.length = 0;
    buffer.data = calloc(1, buffer.capacity + 1);
    if (!buffer.data)
        return -1;
    curl = curl_easy_init();
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    if (!curl || !headers)
        goto done;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 30000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, config->tls_verify ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, config->tls_verify ? 2L : 0L);
    if (config->ca_path[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, config->ca_path);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cloud_bind_write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
    if (status)
        *status = (int)http_status;
    if (curl_rc != CURLE_OK)
        goto done;
    buffer.data[buffer.length] = '\0';
    if (response) {
        *response = json_tokener_parse((const char *)buffer.data);
        if (!*response || !json_object_is_type(*response, json_type_object)) {
            if (*response)
                json_object_put(*response);
            *response = NULL;
            goto done;
        }
    }
    rc = 0;
done:
    if (curl)
        curl_easy_cleanup(curl);
    if (headers)
        curl_slist_free_all(headers);
    free(buffer.data);
    return rc;
}

/* Normalises a user-typed code in place: strips surrounding whitespace (a
 * pasted code often drags a trailing newline) and lowercases hex, since the
 * cloud stores SHA-256 of the lowercase form it issued. Returns 0 when the
 * result is exactly 24 hex characters. */
static int cloud_bind_normalise_code(char *code)
{
    size_t len, start = 0, i;

    if (!code)
        return -1;
    len = strlen(code);
    while (len && isspace((unsigned char)code[len - 1]))
        code[--len] = '\0';
    while (start < len && isspace((unsigned char)code[start]))
        start++;
    if (start)
        memmove(code, code + start, len - start + 1);
    len -= start;
    if (len != CLOUD_BIND_CODE_HEX_LEN)
        return -1;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)code[i];

        if (!isxdigit(c))
            return -1;
        code[i] = (char)tolower(c);
    }
    return 0;
}

static int cloud_bind_name_valid(const char *name)
{
    size_t len = name ? strlen(name) : 0;
    size_t i;

    if (!len || len > CLOUD_BIND_DISPLAY_NAME_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];

        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int cloud_bind_hex_valid(const char *value, size_t expected)
{
    size_t i;

    if (!value || strlen(value) != expected)
        return 0;
    for (i = 0; i < expected; i++)
        if (!isxdigit((unsigned char)value[i]))
            return 0;
    return 1;
}

/* Signs CW_CONTEXT "\n" "binding" "\n" router_id "\n" nonce with NO trailing
 * newline, identical to cloud-web cw_prove's transcript. */
static int cloud_bind_sign(const char *router_id, const char *nonce,
                           char **out_signature_b64)
{
    unsigned char signature[CLOUD_ED25519_SIG_LEN];
    char message[320];
    int length;
    int rc = -1;

    length = snprintf(message, sizeof(message), "%s\n%s\n%s\n%s",
                      CLOUD_BIND_CONTEXT, CLOUD_BIND_ACTION, router_id, nonce);
    if (length <= 0 || (size_t)length >= sizeof(message))
        return -1;
    if (cloud_identity_sign((const unsigned char *)message, (size_t)length,
                            signature, sizeof(signature)) == 0)
        rc = cloud_base64_encode(signature, sizeof(signature),
                                 out_signature_b64);
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(message, sizeof(message));
    return rc;
}

int cloud_bind_run(const struct cloud_cert_config *config,
                   const char *stable_code, const char *display_name,
                   struct cloud_bind_result *out)
{
    const struct cloud_identity *identity;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    struct json_object *data;
    char *kex_b64 = NULL;
    char *sign_b64 = NULL;
    char *signature_b64 = NULL;
    char code[64];
    char nonce[CLOUD_BIND_NONCE_HEX_LEN + 1];
    const char *value;
    int status = 0;
    int rc = -1;

    if (!config || !out)
        return -1;
    memset(out, 0, sizeof(*out));

    if (!config->api_host[0]) {
        cloud_bind_fail(out, 0, "cloud_host_missing",
                        "the cloud api_host is not configured (relay 'cert')");
        return -1;
    }
    /* Normalise/validate the two user inputs before touching identity or the
     * network, so a blank form or a mistyped code fails locally and fast. */
    if (!stable_code || strlen(stable_code) >= sizeof(code)) {
        cloud_bind_fail(out, 0, "invalid_binding_code",
                        "the binding code is missing or malformed");
        return -1;
    }
    snprintf(code, sizeof(code), "%s", stable_code);
    if (cloud_bind_normalise_code(code) != 0) {
        cloud_bind_fail(out, 0, "invalid_binding_code",
                        "the binding code must be 24 hexadecimal characters");
        OPENSSL_cleanse(code, sizeof(code));
        return -1;
    }
    if (!cloud_bind_name_valid(display_name)) {
        cloud_bind_fail(out, 0, "invalid_display_name",
                        "the display name is required and must be 1-64 "
                        "printable characters");
        OPENSSL_cleanse(code, sizeof(code));
        return -1;
    }
    if (cloud_identity_load(NULL) != 0 || !(identity = cloud_identity())) {
        cloud_bind_fail(out, 0, "identity_unavailable",
                        "the router identity could not be loaded");
        OPENSSL_cleanse(code, sizeof(code));
        return -1;
    }
    if (!identity->relay_router_id[0]) {
        cloud_bind_fail(out, 0, "relay_router_id_unavailable",
                        "the relay router_id could not be derived");
        OPENSSL_cleanse(code, sizeof(code));
        return -1;
    }

    if (cloud_base64_encode(identity->public_key, CLOUD_X25519_KEY_LEN,
                            &kex_b64) != 0 ||
        cloud_base64_encode(identity->signing_public_key,
                            CLOUD_ED25519_KEY_LEN, &sign_b64) != 0) {
        cloud_bind_fail(out, 0, "encode_failed",
                        "the router public keys could not be encoded");
        goto done;
    }

    /* Step 1: challenge. Body allowlist is {kex_pub, sign_pub, action}, action
     * must be "binding" (cloud-web contract §5.1). */
    request = json_object_new_object();
    if (!request) {
        cloud_bind_fail(out, 0, "bind_failed", "out of memory");
        goto done;
    }
    json_object_object_add(request, "kex_pub", json_object_new_string(kex_b64));
    json_object_object_add(request, "sign_pub", json_object_new_string(sign_b64));
    json_object_object_add(request, "action",
                           json_object_new_string(CLOUD_BIND_ACTION));
    if (cloud_bind_post(config, CLOUD_BIND_CHALLENGE_PATH,
                        json_object_to_json_string_ext(request,
                            JSON_C_TO_STRING_PLAIN), &status, &response) != 0) {
        cloud_bind_fail(out, status, "cloud_unreachable",
                        "the cloud challenge endpoint could not be reached");
        goto done;
    }
    json_object_put(request);
    request = NULL;

    data = cloud_bind_response_data(response);
    if (!data) {
        cloud_bind_capture_error(out, status, response, "challenge_failed");
        goto done;
    }
    value = cloud_bind_json_string(data, "nonce");
    if (!value || !cloud_bind_hex_valid(value, CLOUD_BIND_NONCE_HEX_LEN)) {
        cloud_bind_fail(out, status, "challenge_failed",
                        "the cloud returned no usable challenge nonce");
        goto done;
    }
    snprintf(nonce, sizeof(nonce), "%s", value);
    /* The router_id the cloud bound to this nonce must be the one it derives
     * from the keys just sent; a mismatch means an encoding disagreement and
     * signing anyway would burn the one-shot nonce for a 401 with no hint. */
    value = cloud_bind_json_string(data, "router_id");
    if (!value || strcmp(value, identity->relay_router_id)) {
        cloud_bind_fail(out, status, "router_id_mismatch",
                        "the cloud derived a different router_id");
        goto done;
    }
    json_object_put(response);
    response = NULL;

    /* Step 2: sign the transcript, then redeem the code. */
    if (cloud_bind_sign(identity->relay_router_id, nonce, &signature_b64) != 0) {
        cloud_bind_fail(out, 0, "sign_failed",
                        "the binding challenge could not be signed");
        goto done;
    }

    request = json_object_new_object();
    if (!request) {
        cloud_bind_fail(out, 0, "bind_failed", "out of memory");
        goto done;
    }
    json_object_object_add(request, "stable_code", json_object_new_string(code));
    json_object_object_add(request, "nonce", json_object_new_string(nonce));
    json_object_object_add(request, "signature",
                           json_object_new_string(signature_b64));
    json_object_object_add(request, "display_name",
                           json_object_new_string(display_name));
    if (cloud_bind_post(config, CLOUD_BIND_CODE_PATH,
                        json_object_to_json_string_ext(request,
                            JSON_C_TO_STRING_PLAIN), &status, &response) != 0) {
        cloud_bind_fail(out, status, "cloud_unreachable",
                        "the cloud bind-code endpoint could not be reached");
        goto done;
    }

    data = cloud_bind_response_data(response);
    if (!data) {
        cloud_bind_capture_error(out, status, response, "bind_failed");
        goto done;
    }
    value = cloud_bind_json_string(data, "cloud_id");
    if (!value || !value[0]) {
        cloud_bind_fail(out, status, "bind_failed",
                        "the cloud returned no cloud_id");
        goto done;
    }
    snprintf(out->cloud_id, sizeof(out->cloud_id), "%s", value);
    value = cloud_bind_json_string(data, "canonical_host");
    if (value)
        snprintf(out->canonical_host, sizeof(out->canonical_host), "%s", value);
    value = cloud_bind_json_string(data, "entry_url");
    if (value)
        snprintf(out->entry_url, sizeof(out->entry_url), "%s", value);
    value = cloud_bind_json_string(data, "direct_url");
    if (value)
        snprintf(out->direct_url, sizeof(out->direct_url), "%s", value);
    out->generation = cloud_bind_json_int(data, "generation");

    out->ok = 1;
    out->http_status = status;
    snprintf(out->code, sizeof(out->code), "%s", "bound");
    snprintf(out->message, sizeof(out->message), "%s",
             "the router bound to the account");
    fprintf(stderr, "[%s] account-bound cloud_id=%s host=%s generation=%lld\n",
            CLOUD_SERVICE_NAME, out->cloud_id, out->canonical_host,
            (long long)out->generation);
    rc = 0;
done:
    if (request)
        json_object_put(request);
    if (response)
        json_object_put(response);
    free(kex_b64);
    free(sign_b64);
    free(signature_b64);
    OPENSSL_cleanse(code, sizeof(code));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return rc;
}

/* ── asynchronous job ────────────────────────────────────────────── */

/*
 * One binding at a time, polled rather than blocked on. Binding does two TLS
 * round trips; running it inline in the ubus handler would freeze uloop for the
 * whole exchange, and status is exactly what the UI polls meanwhile. The code
 * is a bearer credential, so it is cleansed from the shared slot the moment the
 * worker has copied it.
 */
static struct {
    pthread_mutex_t lock;
    int running;
    char in_code[64];
    char in_name[CLOUD_BIND_DISPLAY_NAME_MAX + 16];
    char state[16];
    char code[64];
    char message[192];
    char cloud_id[64];
    char canonical_host[256];
    char entry_url[512];
    char direct_url[512];
    int64_t generation;
    int http_status;
    int64_t started_at;
    int64_t finished_at;
} g_bind_job = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = "idle",
};

static void *cloud_bind_job_thread(void *argument)
{
    struct cloud_bind_result result;
    struct cloud_cert_config config;
    struct cwc_config browser_config;
    int browser_enabled = 0;
    char code[64];
    char name[CLOUD_BIND_DISPLAY_NAME_MAX + 16];

    (void)argument;
    pthread_mutex_lock(&g_bind_job.lock);
    snprintf(code, sizeof(code), "%s", g_bind_job.in_code);
    snprintf(name, sizeof(name), "%s", g_bind_job.in_name);
    OPENSSL_cleanse(g_bind_job.in_code, sizeof(g_bind_job.in_code));
    pthread_mutex_unlock(&g_bind_job.lock);

    memset(&result, 0, sizeof(result));
    memset(&config, 0, sizeof(config));
    int config_rc = cloud_browser_load(&browser_config, &browser_enabled, 0);
    if (!config_rc && browser_config.api_host[0]) {
        snprintf(config.api_host, sizeof(config.api_host), "%s", browser_config.api_host);
        config.api_port = browser_config.api_port;
        snprintf(config.ca_path, sizeof(config.ca_path), "%s", browser_config.ca_path);
        config.tls_verify = 1;
    } else if (!config_rc) {
        config_rc = cloud_cert_config_load(&config);
    }
    EVP_PKEY_free(browser_config.sign_key);
    if (config_rc != 0 || !config.tls_verify) {
        cloud_bind_fail(&result, 0, "config_unavailable",
                        "verified cloud HTTPS configuration is required");
    } else {
        cloud_bind_run(&config, code, name, &result);
    }
    OPENSSL_cleanse(&config, sizeof(config));
    OPENSSL_cleanse(code, sizeof(code));

    pthread_mutex_lock(&g_bind_job.lock);
    snprintf(g_bind_job.state, sizeof(g_bind_job.state), "%s",
             result.ok ? "succeeded" : "failed");
    snprintf(g_bind_job.code, sizeof(g_bind_job.code), "%s", result.code);
    snprintf(g_bind_job.message, sizeof(g_bind_job.message), "%s",
             result.message);
    snprintf(g_bind_job.cloud_id, sizeof(g_bind_job.cloud_id), "%s",
             result.cloud_id);
    snprintf(g_bind_job.canonical_host, sizeof(g_bind_job.canonical_host), "%s",
             result.canonical_host);
    snprintf(g_bind_job.entry_url, sizeof(g_bind_job.entry_url), "%s",
             result.entry_url);
    snprintf(g_bind_job.direct_url, sizeof(g_bind_job.direct_url), "%s",
             result.direct_url);
    g_bind_job.generation = result.generation;
    g_bind_job.http_status = result.http_status;
    g_bind_job.finished_at = cloud_now_s();
    g_bind_job.running = 0;
    pthread_mutex_unlock(&g_bind_job.lock);
    return NULL;
}

int cloud_bind_job_start(const char *stable_code, const char *display_name)
{
    pthread_attr_t attributes;
    pthread_t thread;
    int rc;

    pthread_mutex_lock(&g_bind_job.lock);
    if (g_bind_job.running) {
        pthread_mutex_unlock(&g_bind_job.lock);
        return 1;
    }
    g_bind_job.running = 1;
    snprintf(g_bind_job.in_code, sizeof(g_bind_job.in_code), "%s",
             stable_code ? stable_code : "");
    snprintf(g_bind_job.in_name, sizeof(g_bind_job.in_name), "%s",
             display_name ? display_name : "");
    snprintf(g_bind_job.state, sizeof(g_bind_job.state), "%s", "running");
    g_bind_job.code[0] = '\0';
    g_bind_job.message[0] = '\0';
    g_bind_job.cloud_id[0] = '\0';
    g_bind_job.canonical_host[0] = '\0';
    g_bind_job.entry_url[0] = '\0';
    g_bind_job.direct_url[0] = '\0';
    g_bind_job.generation = 0;
    g_bind_job.http_status = 0;
    g_bind_job.started_at = cloud_now_s();
    g_bind_job.finished_at = 0;
    pthread_mutex_unlock(&g_bind_job.lock);

    if (pthread_attr_init(&attributes) != 0)
        goto fail;
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attributes, cloud_bind_job_thread, NULL);
    pthread_attr_destroy(&attributes);
    if (rc != 0)
        goto fail;
    return 0;
fail:
    pthread_mutex_lock(&g_bind_job.lock);
    g_bind_job.running = 0;
    OPENSSL_cleanse(g_bind_job.in_code, sizeof(g_bind_job.in_code));
    snprintf(g_bind_job.state, sizeof(g_bind_job.state), "%s", "failed");
    snprintf(g_bind_job.code, sizeof(g_bind_job.code), "%s",
             "thread_start_failed");
    g_bind_job.finished_at = cloud_now_s();
    pthread_mutex_unlock(&g_bind_job.lock);
    return -1;
}

struct json_object *cloud_bind_job_json(void)
{
    struct json_object *job = json_object_new_object();

    if (!job)
        return NULL;
    pthread_mutex_lock(&g_bind_job.lock);
    json_object_object_add(job, "state",
                           json_object_new_string(g_bind_job.state));
    json_object_object_add(job, "code",
                           g_bind_job.code[0] ?
                               json_object_new_string(g_bind_job.code) : NULL);
    json_object_object_add(job, "message",
                           g_bind_job.message[0] ?
                               json_object_new_string(g_bind_job.message) : NULL);
    json_object_object_add(job, "cloud_id",
                           g_bind_job.cloud_id[0] ?
                               json_object_new_string(g_bind_job.cloud_id) : NULL);
    json_object_object_add(job, "canonical_host",
                           g_bind_job.canonical_host[0] ?
                               json_object_new_string(g_bind_job.canonical_host) :
                               NULL);
    json_object_object_add(job, "entry_url",
                           g_bind_job.entry_url[0] ?
                               json_object_new_string(g_bind_job.entry_url) : NULL);
    json_object_object_add(job, "direct_url",
                           g_bind_job.direct_url[0] ?
                               json_object_new_string(g_bind_job.direct_url) : NULL);
    json_object_object_add(job, "generation",
                           g_bind_job.generation > 0 ?
                               json_object_new_int64(g_bind_job.generation) : NULL);
    json_object_object_add(job, "cloud_status",
                           g_bind_job.http_status > 0 ?
                               json_object_new_int(g_bind_job.http_status) : NULL);
    json_object_object_add(job, "started_at",
                           g_bind_job.started_at > 0 ?
                               json_object_new_int64(g_bind_job.started_at) : NULL);
    json_object_object_add(job, "finished_at",
                           g_bind_job.finished_at > 0 ?
                               json_object_new_int64(g_bind_job.finished_at) : NULL);
    pthread_mutex_unlock(&g_bind_job.lock);
    return job;
}
