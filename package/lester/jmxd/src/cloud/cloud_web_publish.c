// SPDX-License-Identifier: GPL-2.0-or-later
#include "cloud_web_client.h"
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PUBLISH_PREFIX "/api/v1/cloud/web-access/agent/"
#define PUBLISH_MAX 16384

struct publish_body {
    char bytes[PUBLISH_MAX + 1];
    size_t length;
};

static size_t publish_write(char *bytes, size_t size, size_t count, void *user)
{
    struct publish_body *body = user;
    if (size && count > (PUBLISH_MAX - body->length) / size)
        return 0;
    size_t n = size * count;
    memcpy(body->bytes + body->length, bytes, n);
    body->length += n;
    return n;
}

static const char *publish_string(struct json_object *o, const char *name)
{
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(o, name, &v) || !json_object_is_type(v, json_type_string))
        return NULL;
    const char *text = json_object_get_string(v);
    return strlen(text) == (size_t)json_object_get_string_len(v) ? text : NULL;
}

static int64_t publish_number(struct json_object *o, const char *name)
{
    struct json_object *v = NULL;
    return json_object_object_get_ex(o, name, &v) && json_object_is_type(v, json_type_int) ?
        json_object_get_int64(v) : 0;
}

static struct json_object *publish_post(const struct cwc_config *config, const char *path,
                                       struct json_object *request, struct cwc_publication *result)
{
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    struct publish_body *body = calloc(1, sizeof(*body));
    struct json_object *root = NULL, *data = NULL, *ok = NULL;
    char url[512];
    long status = 0;
    if (!curl || !headers || !body)
        goto done;
    snprintf(url, sizeof(url), "https://%s:%u%s%s", config->api_host,
             config->api_port, PUBLISH_PREFIX, path);
    const char *json = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);
    if (strlen(json) > PUBLISH_MAX)
        goto done;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (config->ca_path[0]) curl_easy_setopt(curl, CURLOPT_CAINFO, config->ca_path);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, publish_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);
    if (curl_easy_perform(curl) != CURLE_OK)
        goto done;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status == 429) {
        curl_off_t retry = 0;
        curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry);
        result->retry_after = retry > 3600 ? 3600 : retry > 0 ? (int)retry : 60;
    }
    struct json_tokener *tok = json_tokener_new();
    if (!tok)
        goto done;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    root = json_tokener_parse_ex(tok, body->bytes, (int)body->length);
    int valid = json_tokener_get_error(tok) == json_tokener_success &&
                json_tokener_get_parse_end(tok) == body->length &&
                json_object_is_type(root, json_type_object);
    json_tokener_free(tok);
    if (!valid)
        goto done;
    if (status != 200) {
        struct json_object *error = NULL;
        if (json_object_object_get_ex(root, "error", &error)) {
            const char *code = publish_string(error, "code");
            if (code) snprintf(result->error, sizeof(result->error), "%s", code);
        }
        goto done;
    }
    if (json_object_object_get_ex(root, "ok", &ok) &&
        json_object_is_type(ok, json_type_boolean) && json_object_get_boolean(ok) &&
        json_object_object_get_ex(root, "data", &data) &&
        json_object_is_type(data, json_type_object))
        json_object_get(data);
    else
        data = NULL;
done:
    if (root) json_object_put(root);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body);
    return data;
}

static void publish_text(struct json_object *o, const char *key, const char *text)
{
    json_object_object_add(o, key, json_object_new_string(text));
}

static struct json_object *publish_exchange(const struct cwc_config *config,
                                  struct json_object *payload, struct cwc_publication *result)
{
    unsigned char pub[32], digest[32], signature[64];
    size_t pub_len = sizeof(pub), sig_len = sizeof(signature);
    unsigned int digest_len = 0;
    char b64[89], hash[65], message[384];
    struct json_object *challenge = json_object_new_object(), *answer = NULL, *data = NULL;
    EVP_MD_CTX *ctx = NULL;
    if (EVP_PKEY_get_raw_public_key(config->sign_key, pub, &pub_len) != 1 || pub_len != 32)
        goto done;
    EVP_EncodeBlock((unsigned char *)b64, pub, 32);
    publish_text(challenge, "sign_pub", b64);
    EVP_EncodeBlock((unsigned char *)b64, config->kex_pub, 32);
    publish_text(challenge, "kex_pub", b64);
    publish_text(challenge, "action", "services");
    answer = publish_post(config, "challenge", challenge, result);
    if (!answer)
        goto done;
    const char *nonce = publish_string(answer, "nonce");
    const char *rid = publish_string(answer, "router_id");
    if (!nonce || strlen(nonce) != 32 || strspn(nonce, "0123456789abcdef") != 32 ||
        !rid || strcmp(rid, config->router_id))
        goto done;
    const char *json = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);
    if (EVP_Digest(json, strlen(json), digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len != 32)
        goto done;
    for (int i = 0; i < 32; ++i) snprintf(hash + 2 * i, 3, "%02x", digest[i]);
    int len = snprintf(message, sizeof(message), "%s\nservices\n%s\n%s\n%s",
                       CWC_CONTEXT, config->router_id, nonce, hash);
    ctx = EVP_MD_CTX_new();
    if (len < 0 || (size_t)len >= sizeof(message) || !ctx ||
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, config->sign_key) != 1 ||
        EVP_DigestSign(ctx, signature, &sig_len, (unsigned char *)message, len) != 1 || sig_len != 64)
        goto done;
    struct json_object *request = json_object_new_object();
    publish_text(request, "nonce", nonce);
    EVP_EncodeBlock((unsigned char *)b64, signature, 64);
    publish_text(request, "signature", b64);
    json_object_object_add(request, "request", json_object_get(payload));
    data = publish_post(config, "services", request, result);
    json_object_put(request);
done:
    EVP_MD_CTX_free(ctx);
    if (answer) json_object_put(answer);
    json_object_put(challenge);
    return data;
}

static int publish_id_compare(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int publish_result(struct json_object *data, struct cwc_publication *result)
{
    const char *cid = publish_string(data, "cloud_id"), *host = publish_string(data, "canonical_host");
    int64_t generation = publish_number(data, "generation"), revision = publish_number(data, "revision");
    if (!cid || strlen(cid) != 32 || strspn(cid, "0123456789abcdef") != 32 ||
        !cwc_host_valid(host) || generation < 1 || generation > UINT32_MAX || revision < 1)
        return -1;
    struct json_object *f = NULL, *n = NULL;
    result->features_known = json_object_object_get_ex(data, "features_v1", &f);
    result->features_v1 = result->negotiated_v1 = 0;
    if (result->features_known) {
        if (!json_object_is_type(f, json_type_int) || json_object_get_int64(f) < 0 ||
            json_object_get_int64(f) > UINT32_MAX ||
            !json_object_object_get_ex(data, "negotiated_v1", &n) ||
            !json_object_is_type(n, json_type_int) || json_object_get_int64(n) < 0 ||
            json_object_get_int64(n) > UINT32_MAX ||
            ((uint32_t)json_object_get_int64(n) & ~(uint32_t)json_object_get_int64(f)))
            return -1;
        result->features_v1 = (unsigned)json_object_get_int64(f) & CW_FEATURES_V1;
        result->negotiated_v1 = (unsigned)json_object_get_int64(n) & CW_FEATURES_V1;
        if (!(result->features_v1 & CW_FEATURE_STREAM)) result->features_v1 = 0;
        if (!(result->negotiated_v1 & CW_FEATURE_STREAM)) result->negotiated_v1 = 0;
    }
    const char *names[] = {"account_service_limit", "account_services", "device_services",
                          "account_connection_limit", "account_bandwidth_bps"};
    int64_t *values[] = {&result->account_service_limit, &result->account_services,
                        &result->device_services, &result->account_connection_limit,
                        &result->account_bandwidth_bps};
    result->quota_known = json_object_object_get_ex(data, names[0], &f);
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        *values[i] = 0;
        if (!result->quota_known) continue;
        if (!json_object_object_get_ex(data, names[i], &f) ||
            !json_object_is_type(f, json_type_int) || json_object_get_int64(f) < 0)
            return -1;
        *values[i] = json_object_get_int64(f);
    }
    if (result->device_services > CWC_MAX_SERVICES ||
        result->account_services < result->device_services)
        return -1;
    strcpy(result->cloud_id, cid);
    snprintf(result->canonical_host, sizeof(result->canonical_host), "%s", host);
    result->generation = (uint32_t)generation;
    result->revision = revision;
    return 0;
}

int cwc_publication_read(const struct cwc_config *config, struct cwc_publication *result)
{
    if (!result) return -1;
    memset(result, 0, sizeof(*result));
    snprintf(result->error, sizeof(result->error), "publication_failed");
    if (!config || !config->sign_key || !cwc_host_valid(config->api_host) ||
        !config->api_port || config->n_services < 0 || config->n_services > CWC_MAX_SERVICES)
        return -1;
    struct json_object *payload = json_object_new_object();
    publish_text(payload, "operation", "read");
    struct json_object *data = publish_exchange(config, payload, result);
    json_object_put(payload);
    if (!data)
        return -1;
    int rc = publish_result(data, result);
    json_object_put(data);
    if (!rc) result->error[0] = '\0';
    return rc;
}

int cwc_publish(const struct cwc_config *config, int enabled, struct cwc_publication *result)
{
    if (cwc_publication_read(config, result))
        return -1;
    snprintf(result->error, sizeof(result->error), "publication_failed");
    const char *ids[CWC_MAX_SERVICES];
    int count = enabled ? config->n_services : 0;
    for (int i = 0; i < count; ++i) {
        if (!cwc_service_valid(&config->services[i]))
            return -1;
        ids[i] = config->services[i].id;
        if (config->services[i].management &&
            strcmp(config->services[i].public_host, result->canonical_host)) {
            snprintf(result->error, sizeof(result->error), "canonical_host_mismatch");
            return -1;
        }
    }
    qsort(ids, count, sizeof(ids[0]), publish_id_compare);
    for (int i = 1; i < count; ++i)
        if (!strcmp(ids[i - 1], ids[i]))
            return -1;
    snprintf(result->error, sizeof(result->error), "publication_failed");
    struct json_object *payload = json_object_new_object();
    publish_text(payload, "operation", "replace");
    json_object_object_add(payload, "generation", json_object_new_int64(result->generation));
    json_object_object_add(payload, "revision", json_object_new_int64(result->revision));
    struct json_object *services = json_object_new_array();
    for (int i = 0; i < count; ++i) {
        struct json_object *item = json_object_new_object();
        publish_text(item, "service_id", ids[i]);
        json_object_array_add(services, item);
    }
    json_object_object_add(payload, "services", services);
    if (result->features_known)
        json_object_object_add(payload, "features_v1",
            json_object_new_int(enabled ? result->features_v1 : 0));
    struct json_object *data = publish_exchange(config, payload, result);
    json_object_put(payload);
    if (!data)
        return -1;
    int rc = publish_result(data, result);
    json_object_put(data);
    if (!rc) result->error[0] = '\0';
    return rc;
}
