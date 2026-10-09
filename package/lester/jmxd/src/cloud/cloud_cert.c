// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Device-side CSR relay certificate agent.
 *
 * The device owns the TLS private key and only sends a CSR to the cloud. The
 * factory Ed25519 key authorizes the CSR through the certwire transcript; no
 * Cloudflare credential or TLS private key crosses this process boundary.
 */
#include "cloud_internal.h"

#include <ctype.h>
#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>

#define CLOUD_CERT_UCI_PACKAGE "relay"
#define CLOUD_CERT_UCI_SECTION "cert"
#define CLOUD_CERT_CHALLENGE_PATH "/v1/cert/challenge"
#define CLOUD_CERT_ISSUE_PATH "/v1/cert/issue"
#define CLOUD_CERT_BODY_MAX (128U * 1024U)
#define CLOUD_CERT_RESPONSE_MAX (1024U * 1024U)
#define CLOUD_CERT_TIMER_S (6 * 60 * 60)

struct cloud_cert_buffer {
    unsigned char *data;
    size_t length;
    size_t capacity;
};

struct cloud_cert_result {
    int ok;
    int http_status;
    char code[64];
    char message[192];
    char domain[256];
    int64_t not_before;
    int64_t not_after;
    int64_t renew_after;
};

static pthread_once_t g_cloud_cert_curl_once = PTHREAD_ONCE_INIT;

static void cloud_cert_config_cleanse(struct cloud_cert_config *config)
{
    if (!config)
        return;
    OPENSSL_cleanse(config, sizeof(*config));
}

static void cloud_cert_curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int cloud_cert_bool(const char *value, int fallback)
{
    if (!value || !value[0])
        return fallback;
    if (!strcmp(value, "1") || !strcasecmp(value, "true") ||
        !strcasecmp(value, "yes") || !strcasecmp(value, "on"))
        return 1;
    if (!strcmp(value, "0") || !strcasecmp(value, "false") ||
        !strcasecmp(value, "no") || !strcasecmp(value, "off"))
        return 0;
    return fallback;
}

static int cloud_cert_host_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;
    size_t i;

    if (!length || length > 253 || value[0] == '.' || value[0] == '-')
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':')
            continue;
        return 0;
    }
    return 1;
}

static int cloud_cert_path_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;

    return !length || (length < 256 && value[0] == '/' &&
                       !strstr(value, ".."));
}

static int cloud_cert_label_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;
    size_t i;

    if (length < 3 || length > 63 || value[0] == '-' ||
        value[length - 1] == '-')
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
        if (i && c == '-' && value[i - 1] == '-')
            return 0;
    }
    return 1;
}

static const char *cloud_cert_uci_option(struct uci_context *ctx,
                                         struct uci_package *package,
                                         const char *name)
{
    struct uci_section *section;

    section = uci_lookup_section(ctx, package, CLOUD_CERT_UCI_SECTION);
    return section ? uci_lookup_option_string(ctx, section, name) : NULL;
}

int cloud_cert_config_load(struct cloud_cert_config *out)
{
    struct uci_context *ctx;
    struct uci_package *package = NULL;
    const char *value;
    long port;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->api_port = 443;
    out->tls_verify = 1;

    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    if (uci_load(ctx, CLOUD_CERT_UCI_PACKAGE, &package) != UCI_OK ||
        !package) {
        uci_free_context(ctx);
        return 0;
    }

    out->enabled = cloud_cert_bool(cloud_cert_uci_option(ctx, package,
                                                         "enabled"), 0);
    value = cloud_cert_uci_option(ctx, package, "api_host");
    if (value && cloud_cert_host_valid(value))
        snprintf(out->api_host, sizeof(out->api_host), "%s", value);
    value = cloud_cert_uci_option(ctx, package, "api_port");
    if (value && value[0]) {
        char *end = NULL;

        port = strtol(value, &end, 10);
        if (end && !*end && port > 0 && port <= 65535)
            out->api_port = (uint16_t)port;
    }
    value = cloud_cert_uci_option(ctx, package, "label");
    if (value && value[0]) {
        size_t i;

        snprintf(out->label, sizeof(out->label), "%s", value);
        for (i = 0; out->label[i]; i++)
            out->label[i] = (char)tolower((unsigned char)out->label[i]);
        if (!cloud_cert_label_valid(out->label))
            out->label[0] = '\0';
    }
    value = cloud_cert_uci_option(ctx, package, "lan_ip");
    if (value && value[0] && strlen(value) < sizeof(out->lan_ip))
        snprintf(out->lan_ip, sizeof(out->lan_ip), "%s", value);
    value = cloud_cert_uci_option(ctx, package, "fullchain_path");
    if (value && cloud_cert_path_valid(value))
        snprintf(out->fullchain_path, sizeof(out->fullchain_path), "%s", value);
    value = cloud_cert_uci_option(ctx, package, "key_path");
    if (value && cloud_cert_path_valid(value))
        snprintf(out->key_path, sizeof(out->key_path), "%s", value);
    value = cloud_cert_uci_option(ctx, package, "reload_cmd");
    if (value && strlen(value) < sizeof(out->reload_cmd))
        snprintf(out->reload_cmd, sizeof(out->reload_cmd), "%s", value);
    out->tls_verify = cloud_cert_bool(cloud_cert_uci_option(ctx, package,
                                                            "tls_verify"), 1);
    value = cloud_cert_uci_option(ctx, package, "ca_path");
    if (value && cloud_cert_path_valid(value))
        snprintf(out->ca_path, sizeof(out->ca_path), "%s", value);

    uci_unload(ctx, package);
    uci_free_context(ctx);
    return 0;
}

static void cloud_cert_result_fail(struct cloud_cert_result *out, int status,
                                   const char *code, const char *message)
{
    if (!out)
        return;
    out->ok = 0;
    out->http_status = status;
    snprintf(out->code, sizeof(out->code), "%s",
             code ? code : "cert_failed");
    snprintf(out->message, sizeof(out->message), "%s", message ? message : "");
}

static size_t cloud_cert_write_body(char *data, size_t size, size_t count,
                                    void *argument)
{
    struct cloud_cert_buffer *buffer = argument;
    size_t length = size * count;

    if (!buffer || length > buffer->capacity - buffer->length)
        return 0;
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return length;
}

static const char *cloud_cert_json_string(struct json_object *root,
                                          const char *name)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, name, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int64_t cloud_cert_json_time(struct json_object *root, const char *name)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, name, &value) || !value ||
        !json_object_is_type(value, json_type_int))
        return 0;
    return json_object_get_int64(value);
}

static struct json_object *cloud_cert_response_data(struct json_object *root)
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

static void cloud_cert_capture_error(struct cloud_cert_result *out, int status,
                                     struct json_object *root,
                                     const char *fallback)
{
    struct json_object *error = NULL;
    const char *code = NULL;
    const char *message = NULL;

    if (root && json_object_object_get_ex(root, "error", &error) && error &&
        json_object_is_type(error, json_type_object)) {
        code = cloud_cert_json_string(error, "code");
        message = cloud_cert_json_string(error, "message");
    }
    if (!code)
        code = cloud_cert_json_string(root, "code");
    if (!message)
        message = cloud_cert_json_string(root, "message");
    cloud_cert_result_fail(out, status, code ? code : fallback, message);
}

static int cloud_cert_url(const struct cloud_cert_config *config,
                          const char *path, char *out, size_t out_size)
{
    int written;

    if (!config || !config->api_host[0] || !path || !out)
        return -1;
    written = snprintf(out, out_size, "https://%s:%u%s", config->api_host,
                       (unsigned)config->api_port, path);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

static int cloud_cert_post(const struct cloud_cert_config *config,
                           const char *path, const char *body, int *status,
                           struct json_object **response)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    struct cloud_cert_buffer buffer;
    char url[512];
    long http_status = 0;
    CURLcode curl_rc;
    int rc = -1;

    if (status)
        *status = 0;
    if (response)
        *response = NULL;
    if (!config || !body || strlen(body) > CLOUD_CERT_BODY_MAX ||
        cloud_cert_url(config, path, url, sizeof(url)) != 0)
        return -1;

    pthread_once(&g_cloud_cert_curl_once, cloud_cert_curl_init_once);
    buffer.capacity = CLOUD_CERT_RESPONSE_MAX;
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 180000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, config->tls_verify ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, config->tls_verify ? 2L : 0L);
    if (config->ca_path[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, config->ca_path);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cloud_cert_write_body);
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

static int cloud_cert_generate_csr(const char *domain, EVP_PKEY **out_key,
                                   unsigned char **out_der, size_t *out_der_len,
                                   unsigned char **out_key_pem,
                                   size_t *out_key_pem_len)
{
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *key = NULL;
    X509_REQ *request = NULL;
    X509_NAME *name;
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    X509_EXTENSION *san = NULL;
    BIO *bio = NULL;
    unsigned char *der = NULL;
    unsigned char *key_pem = NULL;
    char san_value[320];
    char *bio_data;
    long bio_len;
    int der_len;
    int san_len;
    int rc = -1;

    if (!domain || !domain[0] || !out_key || !out_der || !out_der_len ||
        !out_key_pem || !out_key_pem_len)
        return -1;
    *out_key = NULL;
    *out_der = NULL;
    *out_der_len = 0;
    *out_key_pem = NULL;
    *out_key_pem_len = 0;

    key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!key_ctx || EVP_PKEY_keygen_init(key_ctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_ctx,
                                               NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(key_ctx, &key) != 1)
        goto done;
    request = X509_REQ_new();
    if (!request || X509_REQ_set_version(request, 0) != 1)
        goto done;
    name = X509_REQ_get_subject_name(request);
    if (!name || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                            (const unsigned char *)domain,
                                            -1, -1, 0) != 1 ||
        X509_REQ_set_pubkey(request, key) != 1)
        goto done;
    san_len = snprintf(san_value, sizeof(san_value), "DNS:%s", domain);
    if (san_len < 0 || (size_t)san_len >= sizeof(san_value))
        goto done;
    san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_value);
    extensions = sk_X509_EXTENSION_new_null();
    if (!san || !extensions || !sk_X509_EXTENSION_push(extensions, san))
        goto done;
    san = NULL;
    if (X509_REQ_add_extensions(request, extensions) != 1 ||
        X509_REQ_sign(request, key, EVP_sha256()) <= 0)
        goto done;
    der_len = i2d_X509_REQ(request, NULL);
    if (der_len <= 0)
        goto done;
    der = malloc((size_t)der_len);
    if (!der)
        goto done;
    {
        unsigned char *cursor = der;

        if (i2d_X509_REQ(request, &cursor) != der_len)
            goto done;
    }
    bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) != 1)
        goto done;
    bio_len = BIO_get_mem_data(bio, &bio_data);
    if (bio_len <= 0)
        goto done;
    key_pem = malloc((size_t)bio_len);
    if (!key_pem)
        goto done;
    memcpy(key_pem, bio_data, (size_t)bio_len);
    *out_key = key;
    *out_der = der;
    *out_der_len = (size_t)der_len;
    *out_key_pem = key_pem;
    *out_key_pem_len = (size_t)bio_len;
    key = NULL;
    der = NULL;
    key_pem = NULL;
    rc = 0;
done:
    if (key_pem) {
        OPENSSL_cleanse(key_pem, (size_t)(bio_len > 0 ? bio_len : 0));
        free(key_pem);
    }
    free(der);
    X509_EXTENSION_free(san);
    if (extensions)
        sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    BIO_free(bio);
    X509_REQ_free(request);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_ctx);
    return rc;
}

static int cloud_cert_write_atomic(const char *path, const unsigned char *data,
                                   size_t length, mode_t mode)
{
    char temp[512];
    int fd;
    size_t written = 0;
    int rc = -1;

    if (!path || !path[0] || strlen(path) >= sizeof(temp) - 8 || !data)
        return -1;
    snprintf(temp, sizeof(temp), "%s.tmp", path);
    fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    if (fchmod(fd, mode) != 0)
        goto done;
    while (written < length) {
        ssize_t n = write(fd, data + written, length - written);

        if (n <= 0)
            goto done;
        written += (size_t)n;
    }
    if (fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto closed;
    }
    fd = -1;
    if (rename(temp, path) != 0)
        goto closed;
    rc = 0;
closed:
    if (rc != 0)
        unlink(temp);
    return rc;
done:
    close(fd);
    unlink(temp);
    return -1;
}

static int cloud_cert_reload(const char *command)
{
    int status;

    if (!command || !command[0])
        return 0;
    status = system(command);
    return status == 0 ? 0 : -1;
}

static int cloud_cert_install(const struct cloud_cert_config *config,
                              const unsigned char *key_pem, size_t key_len,
                              const char *fullchain)
{
    size_t chain_len;

    if (!config || !key_pem || !key_len || !fullchain || !fullchain[0] ||
        !config->key_path[0] || !config->fullchain_path[0])
        return -1;
    chain_len = strlen(fullchain);
    if (!chain_len || cloud_cert_write_atomic(config->key_path, key_pem,
                                              key_len, 0600) != 0 ||
        cloud_cert_write_atomic(config->fullchain_path,
                                (const unsigned char *)fullchain, chain_len,
                                0644) != 0)
        return -1;
    return cloud_cert_reload(config->reload_cmd) == 0 ? 0 : -2;
}

static int cloud_cert_hex_sha256(const unsigned char *data, size_t length,
                                 char *out, size_t out_size)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!data || !out || out_size < SHA256_DIGEST_LENGTH * 2 + 1 ||
        !SHA256(data, length, digest))
        return -1;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[SHA256_DIGEST_LENGTH * 2] = '\0';
    return 0;
}

static int cloud_cert_obtain(const struct cloud_cert_config *config,
                             struct cloud_cert_result *out)
{
    const struct cloud_identity *identity;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    struct json_object *data;
    EVP_PKEY *key = NULL;
    unsigned char *csr_der = NULL;
    unsigned char *key_pem = NULL;
    size_t csr_len = 0;
    size_t key_pem_len = 0;
    char *kex_b64 = NULL;
    char *signing_b64 = NULL;
    char *csr_b64 = NULL;
    char *signature_b64 = NULL;
    char transcript[1024];
    char csr_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char domain[320];
    char challenge_copy[512];
    const char *challenge;
    const char *suffix;
    const char *fullchain;
    const char *reply_router_id;
    const char *reply_domain;
    int status = 0;
    int install_rc;
    int rc = -1;

    if (!config || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!config->api_host[0] || !config->label[0] || !config->lan_ip[0] ||
        !config->key_path[0] || !config->fullchain_path[0]) {
        cloud_cert_result_fail(out, 0, "cert_config_missing",
                               "certificate configuration is incomplete");
        return -1;
    }
    if (cloud_identity_load(NULL) != 0 ||
        !(identity = cloud_identity()) || !identity->relay_router_id[0]) {
        cloud_cert_result_fail(out, 0, "identity_unavailable",
                               "router identity could not be loaded");
        return -1;
    }
    if (cloud_base64_encode(identity->public_key, CLOUD_X25519_KEY_LEN,
                            &kex_b64) != 0 ||
        cloud_base64_encode(identity->signing_public_key,
                            CLOUD_ED25519_KEY_LEN, &signing_b64) != 0) {
        cloud_cert_result_fail(out, 0, "encode_failed",
                               "router public keys could not be encoded");
        goto done;
    }

    request = json_object_new_object();
    if (!request)
        goto memory_fail;
    json_object_object_add(request, "kex_public_key",
                           json_object_new_string(kex_b64));
    json_object_object_add(request, "signing_public_key",
                           json_object_new_string(signing_b64));
    if (cloud_cert_post(config, CLOUD_CERT_CHALLENGE_PATH,
                        json_object_to_json_string_ext(request,
                                                       JSON_C_TO_STRING_PLAIN),
                        &status, &response) != 0) {
        cloud_cert_result_fail(out, status, "challenge_failed",
                               "certificate challenge request failed");
        goto done;
    }
    data = cloud_cert_response_data(response);
    challenge = cloud_cert_json_string(data, "challenge");
    suffix = cloud_cert_json_string(data, "domain_suffix");
    if (!challenge || !challenge[0] || !suffix || !suffix[0] ||
        strlen(suffix) > 255) {
        cloud_cert_capture_error(out, status, response, "challenge_failed");
        goto done;
    }
    reply_router_id = cloud_cert_json_string(data, "router_id");
    if (!reply_router_id || strcmp(reply_router_id, identity->relay_router_id)) {
        cloud_cert_result_fail(out, status, "router_id_mismatch",
                               "the cloud derived a different router_id");
        goto done;
    }
    if (strlen(challenge) >= sizeof(challenge_copy)) {
        cloud_cert_result_fail(out, status, "challenge_failed",
                               "the cloud returned an oversized challenge");
        goto done;
    }
    snprintf(challenge_copy, sizeof(challenge_copy), "%s", challenge);
    snprintf(domain, sizeof(domain), "%s.%s", config->label, suffix);
    json_object_put(response);
    response = NULL;
    json_object_put(request);
    request = NULL;

    if (cloud_cert_generate_csr(domain, &key, &csr_der, &csr_len, &key_pem,
                                &key_pem_len) != 0 ||
        cloud_cert_hex_sha256(csr_der, csr_len, csr_hash_hex,
                              sizeof(csr_hash_hex)) != 0)
        goto crypto_fail;
    if (snprintf(transcript, sizeof(transcript), "%s\n%s\n%s\n%s\n%s\n%s",
                 CLOUD_CERT_CONTEXT, identity->relay_router_id, challenge_copy,
                 domain, config->lan_ip, csr_hash_hex) >=
        (int)sizeof(transcript))
        goto crypto_fail;
    {
        unsigned char signature[CLOUD_ED25519_SIG_LEN];

        if (cloud_identity_sign((const unsigned char *)transcript,
                                strlen(transcript), signature,
                                sizeof(signature)) != 0 ||
            cloud_base64_encode(csr_der, csr_len, &csr_b64) != 0 ||
            cloud_base64_encode(signature, sizeof(signature),
                                &signature_b64) != 0) {
            OPENSSL_cleanse(signature, sizeof(signature));
            goto crypto_fail;
        }
        OPENSSL_cleanse(signature, sizeof(signature));
    }

    request = json_object_new_object();
    if (!request)
        goto memory_fail;
    json_object_object_add(request, "kex_public_key",
                           json_object_new_string(kex_b64));
    json_object_object_add(request, "signing_public_key",
                           json_object_new_string(signing_b64));
    json_object_object_add(request, "challenge",
                           json_object_new_string(challenge_copy));
    json_object_object_add(request, "label",
                           json_object_new_string(config->label));
    json_object_object_add(request, "lan_ip",
                           json_object_new_string(config->lan_ip));
    json_object_object_add(request, "csr", json_object_new_string(csr_b64));
    json_object_object_add(request, "signature",
                           json_object_new_string(signature_b64));
    if (cloud_cert_post(config, CLOUD_CERT_ISSUE_PATH,
                        json_object_to_json_string_ext(request,
                                                       JSON_C_TO_STRING_PLAIN),
                        &status, &response) != 0) {
        cloud_cert_result_fail(out, status, "issue_failed",
                               "certificate issue request failed");
        goto done;
    }
    data = cloud_cert_response_data(response);
    fullchain = cloud_cert_json_string(data, "fullchain_pem");
    if (!fullchain || !fullchain[0]) {
        cloud_cert_capture_error(out, status, response, "issue_failed");
        goto done;
    }
    reply_domain = cloud_cert_json_string(data, "domain");
    {
        int domain_len = snprintf(out->domain, sizeof(out->domain), "%s",
                                  reply_domain ? reply_domain : domain);

        if (domain_len < 0 || (size_t)domain_len >= sizeof(out->domain)) {
            cloud_cert_result_fail(out, status, "issue_failed",
                                   "the cloud returned an oversized domain");
            goto done;
        }
    }
    out->not_before = cloud_cert_json_time(data, "not_before");
    out->not_after = cloud_cert_json_time(data, "not_after");
    out->renew_after = cloud_cert_json_time(data, "renew_after");
    if (!out->renew_after && out->not_after > out->not_before)
        out->renew_after = out->not_before +
                           (out->not_after - out->not_before) * 2 / 3;
    install_rc = cloud_cert_install(config, key_pem, key_pem_len, fullchain);
    if (install_rc != 0) {
        cloud_cert_result_fail(out, status,
                               install_rc == -2 ? "reload_failed" : "install_failed",
                               install_rc == -2 ?
                               "certificate files installed but web server reload failed" :
                               "certificate files were not installed");
        goto done;
    }
    out->ok = 1;
    out->http_status = status;
    snprintf(out->code, sizeof(out->code), "%s", "issued");
    snprintf(out->message, sizeof(out->message), "%s",
             "certificate installed and web server reloaded");
    fprintf(stderr, "[%s] certificate issued domain=%s not_after=%lld\n",
            CLOUD_SERVICE_NAME, out->domain,
            (long long)out->not_after);
    rc = 0;
    goto done;
memory_fail:
    cloud_cert_result_fail(out, status, "cert_failed", "out of memory");
    goto done;
crypto_fail:
    cloud_cert_result_fail(out, status, "crypto_failed",
                           "certificate key or CSR generation failed");
done:
    if (request)
        json_object_put(request);
    if (response)
        json_object_put(response);
    free(kex_b64);
    free(signing_b64);
    free(csr_b64);
    free(signature_b64);
    if (csr_der) {
        OPENSSL_cleanse(csr_der, csr_len);
        free(csr_der);
    }
    if (key_pem) {
        OPENSSL_cleanse(key_pem, key_pem_len);
        free(key_pem);
    }
    EVP_PKEY_free(key);
    OPENSSL_cleanse(transcript, sizeof(transcript));
    OPENSSL_cleanse(csr_hash_hex, sizeof(csr_hash_hex));
    OPENSSL_cleanse(challenge_copy, sizeof(challenge_copy));
    return rc;
}

static struct {
    pthread_mutex_t lock;
    int running;
    int force;
    char state[16];
    char code[64];
    char message[192];
    char domain[256];
    int http_status;
    int64_t not_before;
    int64_t not_after;
    int64_t renew_after;
    int64_t started_at;
    int64_t finished_at;
} g_cloud_cert_job = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = "idle",
};

static void *cloud_cert_job_thread(void *argument)
{
    struct cloud_cert_config config = {0};
    struct cloud_cert_result result;

    (void)argument;
    memset(&result, 0, sizeof(result));
    if (cloud_cert_config_load(&config) != 0) {
        cloud_cert_result_fail(&result, 0, "config_unavailable",
                               "certificate configuration could not be read");
    } else if (cloud_cert_obtain(&config, &result) != 0 && result.code[0] == '\0') {
        cloud_cert_result_fail(&result, 0, "cert_failed", "certificate obtain failed");
    }
    pthread_mutex_lock(&g_cloud_cert_job.lock);
    snprintf(g_cloud_cert_job.state, sizeof(g_cloud_cert_job.state), "%s",
             result.ok ? "succeeded" : "failed");
    snprintf(g_cloud_cert_job.code, sizeof(g_cloud_cert_job.code), "%s",
             result.code);
    snprintf(g_cloud_cert_job.message, sizeof(g_cloud_cert_job.message), "%s",
             result.message);
    snprintf(g_cloud_cert_job.domain, sizeof(g_cloud_cert_job.domain), "%s",
             result.domain);
    g_cloud_cert_job.http_status = result.http_status;
    g_cloud_cert_job.not_before = result.not_before;
    g_cloud_cert_job.not_after = result.not_after;
    g_cloud_cert_job.renew_after = result.renew_after;
    g_cloud_cert_job.finished_at = cloud_now_s();
    g_cloud_cert_job.running = 0;
    pthread_mutex_unlock(&g_cloud_cert_job.lock);
    cloud_cert_config_cleanse(&config);
    return NULL;
}

static int cloud_cert_needs_renewal(const struct cloud_cert_config *config)
{
    FILE *file;
    X509 *certificate = NULL;
    BIO *bio = NULL;
    char *raw = NULL;
    size_t length = 0;
    struct stat st;
    int64_t not_before;
    int64_t not_after;
    int64_t renew_after;
    int rc = 1;

    if (!config || !config->fullchain_path[0])
        return 1;
    file = fopen(config->fullchain_path, "rb");
    if (!file)
        return 1;
    if (fstat(fileno(file), &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > CLOUD_CERT_RESPONSE_MAX)
        goto done;
    raw = malloc((size_t)st.st_size);
    if (!raw || fread(raw, 1, (size_t)st.st_size, file) != (size_t)st.st_size)
        goto done;
    length = (size_t)st.st_size;
    bio = BIO_new_mem_buf(raw, (int)length);
    certificate = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    if (!certificate)
        goto done;
    {
        ASN1_TIME *before = X509_getm_notBefore(certificate);
        ASN1_TIME *after = X509_getm_notAfter(certificate);
        struct tm before_tm;
        struct tm after_tm;

        memset(&before_tm, 0, sizeof(before_tm));
        memset(&after_tm, 0, sizeof(after_tm));
        if (!before || !after || ASN1_TIME_to_tm(before, &before_tm) != 1 ||
            ASN1_TIME_to_tm(after, &after_tm) != 1)
            goto done;
        not_before = (int64_t)timegm(&before_tm);
        not_after = (int64_t)timegm(&after_tm);
    }
    if (not_after <= not_before)
        goto done;
    renew_after = not_before + (not_after - not_before) * 2 / 3;
    rc = time(NULL) >= renew_after ? 1 : 0;
done:
    X509_free(certificate);
    BIO_free(bio);
    free(raw);
    fclose(file);
    return rc;
}

int cloud_cert_job_start(int force)
{
    pthread_attr_t attributes;
    pthread_t thread;
    struct cloud_cert_config config = {0};
    int rc;

    if (cloud_cert_config_load(&config) != 0 || !config.api_host[0] ||
        !config.label[0] || !config.lan_ip[0] || !config.key_path[0] ||
        !config.fullchain_path[0]) {
        cloud_cert_config_cleanse(&config);
        return -1;
    }
    if (!force && !cloud_cert_needs_renewal(&config)) {
        cloud_cert_config_cleanse(&config);
        return 2;
    }
    cloud_cert_config_cleanse(&config);

    pthread_mutex_lock(&g_cloud_cert_job.lock);
    if (g_cloud_cert_job.running) {
        pthread_mutex_unlock(&g_cloud_cert_job.lock);
        return 1;
    }
    g_cloud_cert_job.running = 1;
    g_cloud_cert_job.force = force ? 1 : 0;
    snprintf(g_cloud_cert_job.state, sizeof(g_cloud_cert_job.state), "%s",
             "running");
    g_cloud_cert_job.code[0] = '\0';
    g_cloud_cert_job.message[0] = '\0';
    g_cloud_cert_job.domain[0] = '\0';
    g_cloud_cert_job.http_status = 0;
    g_cloud_cert_job.not_before = 0;
    g_cloud_cert_job.not_after = 0;
    g_cloud_cert_job.renew_after = 0;
    g_cloud_cert_job.started_at = cloud_now_s();
    g_cloud_cert_job.finished_at = 0;
    pthread_mutex_unlock(&g_cloud_cert_job.lock);

    if (pthread_attr_init(&attributes) != 0)
        goto fail;
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attributes, cloud_cert_job_thread, NULL);
    pthread_attr_destroy(&attributes);
    if (rc == 0)
        return 0;
fail:
    pthread_mutex_lock(&g_cloud_cert_job.lock);
    g_cloud_cert_job.running = 0;
    snprintf(g_cloud_cert_job.state, sizeof(g_cloud_cert_job.state), "%s",
             "failed");
    snprintf(g_cloud_cert_job.code, sizeof(g_cloud_cert_job.code), "%s",
             "thread_start_failed");
    g_cloud_cert_job.finished_at = cloud_now_s();
    pthread_mutex_unlock(&g_cloud_cert_job.lock);
    return -1;
}

struct json_object *cloud_cert_job_json(void)
{
    struct json_object *job = json_object_new_object();

    if (!job)
        return NULL;
    pthread_mutex_lock(&g_cloud_cert_job.lock);
    json_object_object_add(job, "state",
                           json_object_new_string(g_cloud_cert_job.state));
    json_object_object_add(job, "code", g_cloud_cert_job.code[0] ?
                           json_object_new_string(g_cloud_cert_job.code) : NULL);
    json_object_object_add(job, "message", g_cloud_cert_job.message[0] ?
                           json_object_new_string(g_cloud_cert_job.message) : NULL);
    json_object_object_add(job, "domain", g_cloud_cert_job.domain[0] ?
                           json_object_new_string(g_cloud_cert_job.domain) : NULL);
    json_object_object_add(job, "relay_status", g_cloud_cert_job.http_status > 0 ?
                           json_object_new_int(g_cloud_cert_job.http_status) : NULL);
    json_object_object_add(job, "not_before", g_cloud_cert_job.not_before > 0 ?
                           json_object_new_int64(g_cloud_cert_job.not_before) : NULL);
    json_object_object_add(job, "not_after", g_cloud_cert_job.not_after > 0 ?
                           json_object_new_int64(g_cloud_cert_job.not_after) : NULL);
    json_object_object_add(job, "renew_after", g_cloud_cert_job.renew_after > 0 ?
                           json_object_new_int64(g_cloud_cert_job.renew_after) : NULL);
    json_object_object_add(job, "started_at", g_cloud_cert_job.started_at > 0 ?
                           json_object_new_int64(g_cloud_cert_job.started_at) : NULL);
    json_object_object_add(job, "finished_at", g_cloud_cert_job.finished_at > 0 ?
                           json_object_new_int64(g_cloud_cert_job.finished_at) : NULL);
    pthread_mutex_unlock(&g_cloud_cert_job.lock);
    return job;
}

struct json_object *cloud_cert_status_json(void)
{
    struct cloud_cert_config config = {0};
    struct json_object *root = json_object_new_object();
    struct json_object *data;
    FILE *file = NULL;
    BIO *bio = NULL;
    X509 *certificate = NULL;
    char *raw = NULL;
    struct stat st;
    int64_t not_before = 0;
    int64_t not_after = 0;
    int64_t renew_after = 0;

    if (!root)
        return NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "source",
                           json_object_new_string(CLOUD_SERVICE_NAME));
    data = json_object_new_object();
    if (cloud_cert_config_load(&config) != 0) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("config_unavailable"));
        json_object_object_add(root, "data", data);
        return root;
    }
    json_object_object_add(data, "enabled",
                           json_object_new_boolean(config.enabled));
    json_object_object_add(data, "configured",
                           json_object_new_boolean(config.api_host[0] &&
                                                   config.label[0] &&
                                                   config.lan_ip[0] &&
                                                   config.key_path[0] &&
                                                   config.fullchain_path[0]));
    json_object_object_add(data, "domain", config.label[0] ?
                           json_object_new_string(config.label) : NULL);
    json_object_object_add(data, "fullchain_path", config.fullchain_path[0] ?
                           json_object_new_string(config.fullchain_path) : NULL);
    json_object_object_add(data, "key_path", config.key_path[0] ?
                           json_object_new_string(config.key_path) : NULL);
    if (config.fullchain_path[0])
        file = fopen(config.fullchain_path, "rb");
    if (file && fstat(fileno(file), &st) == 0 && st.st_size > 0 &&
        (uint64_t)st.st_size <= CLOUD_CERT_RESPONSE_MAX) {
        raw = malloc((size_t)st.st_size);
        if (raw && fread(raw, 1, (size_t)st.st_size, file) == (size_t)st.st_size)
            bio = BIO_new_mem_buf(raw, (int)st.st_size);
        certificate = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    }
    if (certificate) {
        ASN1_TIME *before = X509_getm_notBefore(certificate);
        ASN1_TIME *after = X509_getm_notAfter(certificate);
        struct tm before_tm;
        struct tm after_tm;

        memset(&before_tm, 0, sizeof(before_tm));
        memset(&after_tm, 0, sizeof(after_tm));
        if (before && after && ASN1_TIME_to_tm(before, &before_tm) == 1 &&
            ASN1_TIME_to_tm(after, &after_tm) == 1) {
            not_before = (int64_t)timegm(&before_tm);
            not_after = (int64_t)timegm(&after_tm);
            renew_after = not_before + (not_after - not_before) * 2 / 3;
        }
    }
    json_object_object_add(data, "installed", json_object_new_boolean(
                               certificate && not_after > 0));
    json_object_object_add(data, "not_before", not_before > 0 ?
                           json_object_new_int64(not_before) : NULL);
    json_object_object_add(data, "not_after", not_after > 0 ?
                           json_object_new_int64(not_after) : NULL);
    json_object_object_add(data, "renew_after", renew_after > 0 ?
                           json_object_new_int64(renew_after) : NULL);
    json_object_object_add(data, "renewal_due", json_object_new_boolean(
                               renew_after > 0 && time(NULL) >= renew_after));
    {
        struct json_object *job = cloud_cert_job_json();

        if (job)
            json_object_object_add(data, "job", job);
    }
    json_object_object_add(root, "data", data);
    X509_free(certificate);
    BIO_free(bio);
    free(raw);
    if (file)
        fclose(file);
    cloud_cert_config_cleanse(&config);
    return root;
}

static struct uloop_timeout g_cloud_cert_timer;
static int g_cloud_cert_timer_running;

static void cloud_cert_timer_cb(struct uloop_timeout *timeout)
{
    struct cloud_cert_config config = {0};

    (void)timeout;
    if (cloud_cert_config_load(&config) == 0) {
        if (config.enabled)
            (void)cloud_cert_job_start(0);
        cloud_cert_config_cleanse(&config);
    }
    if (g_cloud_cert_timer_running) {
        g_cloud_cert_timer.cb = cloud_cert_timer_cb;
        uloop_timeout_set(&g_cloud_cert_timer, CLOUD_CERT_TIMER_S * 1000);
    }
}

void cloud_cert_timer_start(void)
{
    struct cloud_cert_config config = {0};

    if (g_cloud_cert_timer_running || cloud_cert_config_load(&config) != 0)
        return;
    if (!config.enabled) {
        cloud_cert_config_cleanse(&config);
        return;
    }
    cloud_cert_config_cleanse(&config);
    memset(&g_cloud_cert_timer, 0, sizeof(g_cloud_cert_timer));
    g_cloud_cert_timer.cb = cloud_cert_timer_cb;
    g_cloud_cert_timer_running = 1;
    uloop_timeout_set(&g_cloud_cert_timer, 1000);
}

void cloud_cert_timer_stop(void)
{
    g_cloud_cert_timer_running = 0;
    uloop_timeout_cancel(&g_cloud_cert_timer);
}
