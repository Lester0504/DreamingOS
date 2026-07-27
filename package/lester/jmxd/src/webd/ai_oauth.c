// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "ai_oauth.h"

#include <curl/curl.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define OAUTH_KEY_PATH WEBD_AI_OAUTH_STATE_DIR "/state.key"
#define OAUTH_KEY_LEN 32
#define OAUTH_NONCE_LEN 12
#define OAUTH_TAG_LEN 16
#define OAUTH_MAGIC "DWAO1"
#define OAUTH_MAX_SECRET (256U * 1024U)
#define OAUTH_HTTP_MAX (512U * 1024U)

#define GOOGLE_AUTH_URL "https://accounts.google.com/o/oauth2/v2/auth"
#define GOOGLE_DEVICE_URL "https://oauth2.googleapis.com/device/code"
#define GOOGLE_TOKEN_URL "https://oauth2.googleapis.com/token"
#define GOOGLE_REVOKE_URL "https://oauth2.googleapis.com/revoke"
#define GOOGLE_SCOPE "https://www.googleapis.com/auth/cloud-platform"

#define KIMI_CLIENT_ID "17e5f671-d194-4dfb-9706-5516cb48c098"
#define KIMI_DEVICE_URL "https://auth.kimi.com/api/oauth/device_authorization"
#define KIMI_TOKEN_URL "https://auth.kimi.com/api/oauth/token"
#define ANTHROPIC_TOKEN_URL "https://api.anthropic.com/v1/oauth/token"
#define ANTHROPIC_IDENTITY_DIR "/etc/dreamingwrt/credentials/"
#define ANTHROPIC_IDENTITY_MAX (128U * 1024U)

/* Codex CLI ChatGPT OAuth contract, mirrored from Wei-Shaw/sub2api. */
#define OPENAI_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define OPENAI_AUTH_URL "https://auth.openai.com/oauth/authorize"
#define OPENAI_TOKEN_URL "https://auth.openai.com/oauth/token"
#define OPENAI_REDIRECT_URI "http://localhost:1455/auth/callback"
#define OPENAI_SCOPE "openid profile email offline_access"
#define OPENAI_REFRESH_SCOPE "openid profile email"
#define OPENAI_MODEL_API "https://chatgpt.com/backend-api/codex"
#define OPENAI_OAUTH_USER_AGENT "codex-cli/0.91.0"

struct oauth_provider {
    const char *id;
    int supported;
    const char *mode;
    const char *reason;
    const char *authorization_url;
    const char *device_url;
    const char *token_url;
    const char *revoke_url;
    const char *scope;
    const char *client_id;
    const char *model_api;
};

static const struct oauth_provider providers[] = {
    { "gemini", 1, "authorization_code_pkce_s256", NULL,
      GOOGLE_AUTH_URL, GOOGLE_DEVICE_URL, GOOGLE_TOKEN_URL, GOOGLE_REVOKE_URL,
      GOOGLE_SCOPE, NULL, "https://generativelanguage.googleapis.com/v1" },
    { "kimi", 1, "device_oauth", NULL,
      NULL, KIMI_DEVICE_URL, KIMI_TOKEN_URL, NULL, NULL, KIMI_CLIENT_ID,
      "https://api.kimi.com/coding/v1" },
    { "anthropic", 1, "enterprise_wif",
      "requires_preconfigured_anthropic_workload_identity_federation",
      NULL, NULL, ANTHROPIC_TOKEN_URL, NULL, NULL,
      NULL, "https://api.anthropic.com/v1" },
    { "openai", 1, "chatgpt_authorization_code_pkce_s256", NULL,
      OPENAI_AUTH_URL, NULL, OPENAI_TOKEN_URL, NULL, OPENAI_SCOPE,
      OPENAI_CLIENT_ID, OPENAI_MODEL_API },
    { "grok", 0, "api_key_only",
      "no_public_third_party_oauth_for_xai_model_api",
      NULL, NULL, NULL, NULL, NULL, NULL, "https://api.x.ai/v1" },
    { "antigravity", 0, "not_independent_model_api",
      "antigravity_has_no_independent_public_model_api_oauth_contract_use_gemini",
      NULL, NULL, NULL, NULL, NULL, NULL, NULL },
};

struct http_buffer { char *data; size_t len; };

static long long now_seconds(void) { return (long long)time(NULL); }

static const char *canonical_provider(const char *id)
{
    if (!id) return "";
    if (!strcmp(id, "kimi_code") || !strcmp(id, "kimi-code")) return "kimi";
    if (!strcmp(id, "google-gemini")) return "gemini";
    return id;
}

static const struct oauth_provider *find_provider(const char *id)
{
    size_t i;
    if (!id) return NULL;
    id = canonical_provider(id);
    for (i = 0; i < sizeof(providers) / sizeof(providers[0]); i++)
        if (!strcmp(providers[i].id, id)) return &providers[i];
    return NULL;
}

static struct json_object *result_error(const char *error, const char *message,
                                        int status, int *http_status)
{
    struct json_object *o = json_object_new_object();
    if (http_status) *http_status = status;
    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(error));
    json_object_object_add(o, "message", json_object_new_string(message ? message : error));
    return o;
}

static void add_optional(struct json_object *o, const char *key, const char *value)
{
    if (value) json_object_object_add(o, key, json_object_new_string(value));
}

static struct json_object *provider_json(const struct oauth_provider *p)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "provider", json_object_new_string(p->id));
    json_object_object_add(o, "supported", json_object_new_boolean(p->supported));
    json_object_object_add(o, "mode", json_object_new_string(p->mode));
    add_optional(o, "reason", p->reason);
    add_optional(o, "authorization_url", p->authorization_url);
    add_optional(o, "device_authorization_url", p->device_url);
    add_optional(o, "token_url", p->token_url);
    add_optional(o, "revoke_url", p->revoke_url);
    add_optional(o, "scope", p->scope);
    add_optional(o, "client_id", p->client_id);
    add_optional(o, "model_api_base", p->model_api);
    json_object_object_add(o, "pkce_s256", json_object_new_boolean(
        !strcmp(p->id, "gemini") || !strcmp(p->id, "openai")));
    json_object_object_add(o, "refresh_supported", json_object_new_boolean(p->supported));
    json_object_object_add(o, "device_flow_supported", json_object_new_boolean(
        !strcmp(p->id, "kimi")));
    json_object_object_add(o, "authorization_code_callback_supported",
                           json_object_new_boolean(!strcmp(p->id, "gemini") ||
                                                   !strcmp(p->id, "openai")));
    if (!strcmp(p->id, "openai")) {
        json_object_object_add(o, "account_type",
                               json_object_new_string("chatgpt_oauth"));
        json_object_object_add(o, "api_key_account_type",
                               json_object_new_string("api_key"));
        json_object_object_add(o, "default_redirect_uri",
                               json_object_new_string(OPENAI_REDIRECT_URI));
        json_object_object_add(o, "callback_transport",
                               json_object_new_string("manual_callback_url_to_poll"));
        json_object_object_add(o, "callback_url_parse_required",
                               json_object_new_boolean(1));
        json_object_object_add(o, "custom_redirect_uri_supported",
                               json_object_new_boolean(0));
        json_object_object_add(o, "upstream_revoke_supported",
                               json_object_new_boolean(0));
    }
    if (!strcmp(p->id, "anthropic")) {
        json_object_object_add(o, "identity_token_file_required",
                               json_object_new_boolean(1));
        json_object_object_add(o, "identity_token_file_root",
                               json_object_new_string(ANTHROPIC_IDENTITY_DIR));
        json_object_object_add(o, "browser_login",
                               json_object_new_boolean(0));
    }
    return o;
}

struct json_object *webd_ai_oauth_catalog(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    size_t i;
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract", json_object_new_string("ai-oauth.v1"));
    for (i = 0; i < sizeof(providers) / sizeof(providers[0]); i++)
        json_object_array_add(items, provider_json(&providers[i]));
    json_object_object_add(root, "providers", items);
    return root;
}

static int ensure_state_dir(char *reason, size_t reason_len)
{
    struct stat st;
    if (mkdir("/etc/dreamingwrt", 0755) && errno != EEXIST) goto fail;
    if (mkdir(WEBD_AI_OAUTH_STATE_DIR, 0700) && errno != EEXIST) goto fail;
    if (lstat(WEBD_AI_OAUTH_STATE_DIR, &st) || !S_ISDIR(st.st_mode) ||
        S_ISLNK(st.st_mode) || st.st_uid != 0) {
        errno = EINVAL; goto fail;
    }
    if (chmod(WEBD_AI_OAUTH_STATE_DIR, 0700)) goto fail;
    return 0;
fail:
    if (reason && reason_len) snprintf(reason, reason_len, "state_directory:%s", strerror(errno));
    return -1;
}

static int write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int load_key(unsigned char key[OAUTH_KEY_LEN], char *reason, size_t reason_len)
{
    int fd; ssize_t n; struct stat st;
    if (ensure_state_dir(reason, reason_len)) return -1;
    fd = open(OAUTH_KEY_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
            (st.st_mode & 077) != 0) {
            close(fd); if (reason) snprintf(reason, reason_len, "insecure_key_permissions"); return -1;
        }
        n = read(fd, key, OAUTH_KEY_LEN); close(fd);
        if (n != OAUTH_KEY_LEN) { if (reason) snprintf(reason, reason_len, "invalid_key_file"); return -1; }
        return 0;
    }
    if (errno != ENOENT) goto fail;
    if (RAND_bytes(key, OAUTH_KEY_LEN) != 1) { if (reason) snprintf(reason, reason_len, "random_key_failed"); return -1; }
    fd = open(OAUTH_KEY_PATH, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) goto fail;
    if (fchmod(fd, 0600) || write_all(fd, key, OAUTH_KEY_LEN) || fsync(fd)) {
        int saved = errno; close(fd); unlink(OAUTH_KEY_PATH); errno = saved; goto fail;
    }
    close(fd); return 0;
fail:
    if (reason) snprintf(reason, reason_len, "key_file:%s", strerror(errno));
    return -1;
}

static int state_path(char *out, size_t out_len, const char *provider, const char *kind)
{
    const char *p;
    if (!find_provider(provider)) return -1;
    for (p = kind; *p; p++) if ((*p < 'a' || *p > 'z') && *p != '-') return -1;
    return snprintf(out, out_len, "%s/%s.%s.enc", WEBD_AI_OAUTH_STATE_DIR,
                    provider, kind) >= (int)out_len ? -1 : 0;
}

static int encrypted_save(const char *provider, const char *kind,
                          struct json_object *value, char *reason, size_t reason_len)
{
    unsigned char key[OAUTH_KEY_LEN], nonce[OAUTH_NONCE_LEN], tag[OAUTH_TAG_LEN];
    unsigned char *cipher = NULL, *blob = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const char *plain = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    size_t plain_len = strlen(plain), blob_len;
    int out1 = 0, out2 = 0, aad_len = 0, fd = -1, rc = -1;
    char path[256], tmp[280], aad[192];
    if (plain_len > OAUTH_MAX_SECRET || state_path(path, sizeof(path), provider, kind)) goto done;
    if (load_key(key, reason, reason_len) || RAND_bytes(nonce, sizeof(nonce)) != 1 ||
        snprintf(aad, sizeof(aad), "%s:%s", provider, kind) >= (int)sizeof(aad))
        goto done;
    cipher = malloc(plain_len + 16); ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &aad_len, (const unsigned char *)aad,
                          (int)strlen(aad)) != 1 ||
        EVP_EncryptUpdate(ctx, cipher, &out1, (const unsigned char *)plain, (int)plain_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, cipher + out1, &out2) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        if (reason) snprintf(reason, reason_len, "encrypt_failed");
        goto done;
    }
    blob_len = 5 + sizeof(nonce) + sizeof(tag) + (size_t)(out1 + out2);
    blob = malloc(blob_len); if (!blob) goto done;
    memcpy(blob, OAUTH_MAGIC, 5); memcpy(blob + 5, nonce, sizeof(nonce));
    memcpy(blob + 5 + sizeof(nonce), tag, sizeof(tag));
    memcpy(blob + 5 + sizeof(nonce) + sizeof(tag), cipher, (size_t)(out1 + out2));
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fchmod(fd, 0600) || write_all(fd, blob, blob_len) || fsync(fd)) {
        if (fd >= 0) close(fd);
        unlink(tmp);
        if (reason) snprintf(reason, reason_len, "state_write_failed");
        goto done;
    }
    if (close(fd)) {
        fd = -1;
        unlink(tmp);
        if (reason) snprintf(reason, reason_len, "state_close_failed");
        goto done;
    }
    fd = -1;
    if (rename(tmp, path)) { unlink(tmp); if (reason) snprintf(reason, reason_len, "state_rename_failed"); goto done; }
    rc = 0;
done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(cipher);
    free(blob);
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}

static struct json_object *encrypted_load(const char *provider, const char *kind,
                                          char *reason, size_t reason_len)
{
    unsigned char key[OAUTH_KEY_LEN], *blob = NULL, *plain = NULL;
    EVP_CIPHER_CTX *ctx = NULL; struct json_object *value = NULL;
    struct stat st = {0}; char path[256], aad[192];
    int fd = -1, out1 = 0, out2 = 0, aad_len = 0; ssize_t n;
    size_t cipher_len;
    if (state_path(path, sizeof(path), provider, kind) ||
        snprintf(aad, sizeof(aad), "%s:%s", provider, kind) >= (int)sizeof(aad))
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { if (reason) snprintf(reason, reason_len, "%s", errno == ENOENT ? "not_connected" : "state_open_failed"); return NULL; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 077) ||
        st.st_size < 5 + OAUTH_NONCE_LEN + OAUTH_TAG_LEN || st.st_size > OAUTH_MAX_SECRET) goto done;
    blob = malloc((size_t)st.st_size); plain = malloc((size_t)st.st_size + 1);
    if (!blob || !plain) goto done;
    n = read(fd, blob, (size_t)st.st_size); if (n != st.st_size || memcmp(blob, OAUTH_MAGIC, 5)) goto done;
    if (load_key(key, reason, reason_len)) goto done;
    cipher_len = (size_t)st.st_size - 5 - OAUTH_NONCE_LEN - OAUTH_TAG_LEN;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, OAUTH_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, blob + 5) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &aad_len, (const unsigned char *)aad,
                          (int)strlen(aad)) != 1 ||
        EVP_DecryptUpdate(ctx, plain, &out1, blob + 5 + OAUTH_NONCE_LEN + OAUTH_TAG_LEN, (int)cipher_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, OAUTH_TAG_LEN, blob + 5 + OAUTH_NONCE_LEN) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain + out1, &out2) != 1) {
        if (reason) snprintf(reason, reason_len, "state_authentication_failed");
        goto done;
    }
    plain[out1 + out2] = 0; value = json_tokener_parse((char *)plain);
    if (!value && reason) snprintf(reason, reason_len, "state_json_invalid");
done:
    if (fd >= 0) close(fd);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plain) OPENSSL_cleanse(plain, (size_t)(st.st_size > 0 ? st.st_size : 0));
    free(plain); free(blob); OPENSSL_cleanse(key, sizeof(key)); return value;
}

static const char *json_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_string)
        ? json_object_get_string(v) : NULL;
}

static long long json_i64(struct json_object *o, const char *key, long long fallback)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) ? json_object_get_int64(v) : fallback;
}

static size_t http_write(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct http_buffer *b = opaque; size_t n = size * nmemb; char *next;
    if (n > OAUTH_HTTP_MAX - b->len) return 0;
    next = realloc(b->data, b->len + n + 1); if (!next) return 0;
    b->data = next; memcpy(b->data + b->len, ptr, n); b->len += n; b->data[b->len] = 0; return n;
}

static size_t http_discard(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    (void)ptr; (void)opaque; return size * nmemb;
}

static struct json_object *http_form_user_agent(const char *url,
                                                const char *form,
                                                const char *user_agent,
                                                long *status, char *reason,
                                                size_t reason_len)
{
    CURL *curl = curl_easy_init(); CURLcode cc; struct http_buffer b = {0};
    struct curl_slist *headers = NULL; struct json_object *o = NULL;
    if (!curl) { snprintf(reason, reason_len, "curl_init_failed"); return NULL; }
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url); curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, form); curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(form));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L); curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 30000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     user_agent && user_agent[0] ? user_agent :
                                                   "dreamingwrt-webd/1.0 oauth");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write); curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
    cc = curl_easy_perform(curl); curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    if (cc != CURLE_OK) snprintf(reason, reason_len, "oauth_transport:%s", curl_easy_strerror(cc));
    else if (b.data) o = json_tokener_parse(b.data);
    if (cc == CURLE_OK && !o) snprintf(reason, reason_len, "oauth_invalid_json");
    free(b.data); curl_slist_free_all(headers); curl_easy_cleanup(curl); return o;
}

static struct json_object *http_form(const char *url, const char *form,
                                     long *status, char *reason,
                                     size_t reason_len)
{
    return http_form_user_agent(url, form, NULL, status, reason, reason_len);
}

static struct json_object *http_json(const char *url, struct json_object *body,
                                     long *status, char *reason,
                                     size_t reason_len)
{
    CURL *curl = curl_easy_init();
    CURLcode cc;
    struct http_buffer b = {0};
    struct curl_slist *headers = NULL;
    struct json_object *o = NULL;
    const char *json = body ? json_object_to_json_string_ext(
        body, JSON_C_TO_STRING_PLAIN) : "{}";

    if (!curl) {
        snprintf(reason, reason_len, "curl_init_failed");
        return NULL;
    }
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 30000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-webd/1.0 oauth");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
    cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    if (cc != CURLE_OK)
        snprintf(reason, reason_len, "oauth_transport:%s",
                 curl_easy_strerror(cc));
    else if (b.data)
        o = json_tokener_parse(b.data);
    if (cc == CURLE_OK && !o)
        snprintf(reason, reason_len, "oauth_invalid_json");
    free(b.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return o;
}

static int safe_identifier(const char *value, const char *prefix)
{
    size_t prefix_len = prefix ? strlen(prefix) : 0;
    if (!value || !value[0] || strlen(value) > 160 ||
        (prefix_len && strncmp(value, prefix, prefix_len)))
        return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; p++)
        if (!isalnum(*p) && *p != '-' && *p != '_')
            return 0;
    return 1;
}

static char *anthropic_identity_token_load(const char *path, char *reason,
                                           size_t reason_len)
{
    struct stat st;
    char *token;
    size_t offset = 0;
    int fd;

    if (!path || strncmp(path, ANTHROPIC_IDENTITY_DIR,
                         strlen(ANTHROPIC_IDENTITY_DIR)) || strstr(path, "..") ||
        !path[strlen(ANTHROPIC_IDENTITY_DIR)] ||
        strchr(path + strlen(ANTHROPIC_IDENTITY_DIR), '/')) {
        snprintf(reason, reason_len, "identity_token_path_not_allowed");
        return NULL;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 077) || st.st_size <= 0 ||
        st.st_size > (off_t)ANTHROPIC_IDENTITY_MAX) {
        if (fd >= 0) close(fd);
        snprintf(reason, reason_len, "identity_token_file_invalid");
        return NULL;
    }
    token = malloc((size_t)st.st_size + 1);
    if (!token) { close(fd); return NULL; }
    while (offset < (size_t)st.st_size) {
        ssize_t got = read(fd, token + offset, (size_t)st.st_size - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(token); close(fd); return NULL; }
        offset += (size_t)got;
    }
    close(fd);
    while (offset && (token[offset - 1] == '\n' || token[offset - 1] == '\r'))
        offset--;
    token[offset] = 0;
    if (!offset) { free(token); return NULL; }
    return token;
}

static struct json_object *anthropic_wif_exchange(struct json_object *config,
                                                  long *status, char *reason,
                                                  size_t reason_len)
{
    const char *path = json_string(config, "identity_token_file");
    const char *rule = json_string(config, "federation_rule_id");
    const char *org = json_string(config, "organization_id");
    const char *service = json_string(config, "service_account_id");
    const char *workspace = json_string(config, "workspace_id");
    struct json_object *body;
    struct json_object *response;
    char *assertion;

    if (!safe_identifier(rule, "fdrl_") || !safe_identifier(org, "") ||
        !safe_identifier(service, "svac_") ||
        (workspace && workspace[0] && !safe_identifier(workspace, "wrkspc_"))) {
        snprintf(reason, reason_len, "invalid_anthropic_wif_identifiers");
        return NULL;
    }
    assertion = anthropic_identity_token_load(path, reason, reason_len);
    if (!assertion) return NULL;
    body = json_object_new_object();
    json_object_object_add(body, "grant_type", json_object_new_string(
        "urn:ietf:params:oauth:grant-type:jwt-bearer"));
    json_object_object_add(body, "assertion", json_object_new_string(assertion));
    json_object_object_add(body, "federation_rule_id", json_object_new_string(rule));
    json_object_object_add(body, "organization_id", json_object_new_string(org));
    json_object_object_add(body, "service_account_id", json_object_new_string(service));
    if (workspace && workspace[0])
        json_object_object_add(body, "workspace_id",
                               json_object_new_string(workspace));
    response = http_json(ANTHROPIC_TOKEN_URL, body, status, reason, reason_len);
    OPENSSL_cleanse(assertion, strlen(assertion));
    free(assertion);
    json_object_put(body);
    return response;
}

static int http_form_discard(const char *url, const char *form)
{
    CURL *curl = curl_easy_init(); CURLcode cc; long status = 0;
    struct curl_slist *headers = NULL;
    if (!curl) return -1;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_URL, url); curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, form); curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(form));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L); curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 30000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_discard);
    cc = curl_easy_perform(curl); curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers); curl_easy_cleanup(curl);
    return cc == CURLE_OK && status >= 200 && status < 300 ? 0 : -1;
}

static char *escape(CURL *curl, const char *s) { return curl_easy_escape(curl, s ? s : "", 0); }

static int secure_equal(const char *a, const char *b)
{
    size_t i, alen, blen, n; unsigned char diff;
    if (!a || !b) return 0;
    alen = strlen(a); blen = strlen(b); n = alen > blen ? alen : blen;
    diff = (unsigned char)(alen ^ blen);
    for (i = 0; i < n; i++)
        diff |= (unsigned char)((i < alen ? a[i] : 0) ^ (i < blen ? b[i] : 0));
    return diff == 0;
}

static int redirect_uri_valid(const char *uri)
{
    return uri && (!strncmp(uri, "https://", 8) || !strncmp(uri, "http://", 7)) &&
           !strchr(uri, '\r') && !strchr(uri, '\n') && strlen(uri) <= 2048;
}

static int oauth_query_component_decode(CURL *curl, const char *raw,
                                        size_t raw_len, char **out,
                                        size_t max_len)
{
    char *encoded = NULL, *decoded = NULL;
    int decoded_len = 0;

    if (!curl || !raw || !out || !raw_len || raw_len > 16384)
        return -1;
    for (size_t i = 0; i < raw_len; i++) {
        if (raw[i] != '%')
            continue;
        if (i + 2 >= raw_len || !isxdigit((unsigned char)raw[i + 1]) ||
            !isxdigit((unsigned char)raw[i + 2]))
            return -1;
        i += 2;
    }
    encoded = strndup(raw, raw_len);
    if (!encoded)
        return -1;
    for (size_t i = 0; i < raw_len; i++)
        if (encoded[i] == '+') encoded[i] = ' ';
    decoded = curl_easy_unescape(curl, encoded, (int)raw_len, &decoded_len);
    free(encoded);
    if (!decoded || decoded_len <= 0 || (size_t)decoded_len > max_len ||
        memchr(decoded, '\0', (size_t)decoded_len)) {
        if (decoded) curl_free(decoded);
        return -1;
    }
    *out = decoded;
    return 0;
}

static int openai_callback_url_parse(const char *url, char **code_out,
                                     char **state_out)
{
    CURLU *parsed = NULL;
    CURL *curl = NULL;
    char *scheme = NULL, *host = NULL, *port = NULL, *path = NULL;
    char *query = NULL, *part = NULL;
    char *code = NULL, *state = NULL;
    int rc = -1;

    if (!url || !code_out || !state_out || !url[0] || strlen(url) > 16384 ||
        strchr(url, '\r') || strchr(url, '\n'))
        return -1;
    *code_out = NULL;
    *state_out = NULL;
    parsed = curl_url();
    curl = curl_easy_init();
    if (!parsed || !curl || curl_url_set(parsed, CURLUPART_URL, url, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_PORT, &port, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_PATH, &path, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_QUERY, &query, 0) != CURLUE_OK ||
        strcmp(scheme, "http") || strcasecmp(host, "localhost") ||
        strcmp(port, "1455") || strcmp(path, "/auth/callback"))
        goto done;
    if (curl_url_get(parsed, CURLUPART_USER, &part, 0) == CURLUE_OK && part[0])
        goto done;
    curl_free(part); part = NULL;
    if (curl_url_get(parsed, CURLUPART_PASSWORD, &part, 0) == CURLUE_OK && part[0])
        goto done;
    curl_free(part); part = NULL;
    if (curl_url_get(parsed, CURLUPART_FRAGMENT, &part, 0) == CURLUE_OK && part[0])
        goto done;
    curl_free(part); part = NULL;

    for (const char *cursor = query; cursor && *cursor;) {
        const char *end = strchr(cursor, '&');
        const char *equals;
        size_t segment_len = end ? (size_t)(end - cursor) : strlen(cursor);
        char *key = NULL, *value = NULL;

        equals = memchr(cursor, '=', segment_len);
        if (equals && equals > cursor &&
            oauth_query_component_decode(curl, cursor,
                                         (size_t)(equals - cursor),
                                         &key, 64) == 0 &&
            (!strcmp(key, "code") || !strcmp(key, "state"))) {
            char **target = !strcmp(key, "code") ? &code : &state;

            if (*target || oauth_query_component_decode(
                    curl, equals + 1,
                    segment_len - (size_t)(equals + 1 - cursor),
                    &value, 8192) != 0) {
                curl_free(key);
                goto done;
            }
            *target = value;
            value = NULL;
        }
        if (value) {
            OPENSSL_cleanse(value, strlen(value));
            curl_free(value);
        }
        if (key) curl_free(key);
        if (!end) break;
        cursor = end + 1;
    }
    if (!code || !state)
        goto done;
    *code_out = code;
    *state_out = state;
    code = NULL;
    state = NULL;
    rc = 0;
done:
    if (code) { OPENSSL_cleanse(code, strlen(code)); curl_free(code); }
    if (state) { OPENSSL_cleanse(state, strlen(state)); curl_free(state); }
    curl_free(part);
    curl_free(scheme); curl_free(host); curl_free(port); curl_free(path);
    curl_free(query);
    if (curl) curl_easy_cleanup(curl);
    if (parsed) curl_url_cleanup(parsed);
    return rc;
}

static char *base64url(const unsigned char *data, size_t len)
{
    size_t cap = 4 * ((len + 2) / 3) + 1, i; int n;
    unsigned char *out = malloc(cap);
    if (!out) return NULL;
    n = EVP_EncodeBlock(out, data, (int)len);
    if (n < 0) { free(out); return NULL; }
    while (n > 0 && out[n - 1] == '=') n--;
    for (i = 0; i < (size_t)n; i++) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
    }
    out[n] = 0; return (char *)out;
}

static char *random_base64url(size_t bytes)
{
    unsigned char raw[64];
    if (!bytes || bytes > sizeof(raw) || RAND_bytes(raw, (int)bytes) != 1) return NULL;
    return base64url(raw, bytes);
}

static char *random_hex(size_t bytes)
{
    static const char digits[] = "0123456789abcdef";
    unsigned char raw[64];
    char *out;
    size_t i;

    if (!bytes || bytes > sizeof(raw) || RAND_bytes(raw, (int)bytes) != 1)
        return NULL;
    out = malloc(bytes * 2 + 1);
    if (!out) {
        OPENSSL_cleanse(raw, sizeof(raw));
        return NULL;
    }
    for (i = 0; i < bytes; i++) {
        out[i * 2] = digits[raw[i] >> 4];
        out[i * 2 + 1] = digits[raw[i] & 0x0f];
    }
    out[bytes * 2] = 0;
    OPENSSL_cleanse(raw, sizeof(raw));
    return out;
}

static char *pkce_challenge(const char *verifier)
{
    unsigned char digest[32]; unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); char *out = NULL;
    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, verifier, strlen(verifier)) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &len) == 1 && len == sizeof(digest))
        out = base64url(digest, sizeof(digest));
    EVP_MD_CTX_free(ctx); return out;
}

static struct json_object *oauth_exchange(const struct oauth_provider *p,
                                          const char *grant, const char *code,
                                          const char *client_id, long *status,
                                          char *reason, size_t reason_len)
{
    CURL *curl = curl_easy_init(); char *g = NULL, *c = NULL, *id = NULL;
    char *form = NULL; struct json_object *response = NULL;
    if (!curl) return NULL;
    g = escape(curl, grant); c = escape(curl, code); id = escape(curl, client_id);
    if (g && c && id && asprintf(&form, "grant_type=%s&%s=%s&client_id=%s", g,
                 strstr(grant, "device_code") ? "device_code" : "refresh_token", c, id) < 0) form = NULL;
    if (form) response = http_form(p->token_url, form, status, reason, reason_len);
    curl_free(g); curl_free(c); curl_free(id); free(form); curl_easy_cleanup(curl); return response;
}

static struct json_object *gemini_code_exchange(const struct oauth_provider *p,
                                                const char *code,
                                                const char *client_id,
                                                const char *redirect_uri,
                                                const char *verifier,
                                                long *status, char *reason,
                                                size_t reason_len)
{
    CURL *curl = curl_easy_init(); char *c = NULL, *id = NULL, *redirect = NULL, *v = NULL;
    char *form = NULL; struct json_object *response = NULL;
    if (!curl) return NULL;
    c = escape(curl, code); id = escape(curl, client_id);
    redirect = escape(curl, redirect_uri); v = escape(curl, verifier);
    if (c && id && redirect && v && asprintf(&form,
        "grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s&code_verifier=%s",
        c, id, redirect, v) >= 0)
        response = http_form(p->token_url, form, status, reason, reason_len);
    curl_free(c); curl_free(id); curl_free(redirect); curl_free(v);
    free(form); curl_easy_cleanup(curl); return response;
}

static struct json_object *openai_code_exchange(const struct oauth_provider *p,
                                                const char *code,
                                                const char *redirect_uri,
                                                const char *verifier,
                                                long *status, char *reason,
                                                size_t reason_len)
{
    CURL *curl = curl_easy_init();
    char *c = NULL, *id = NULL, *redirect = NULL, *v = NULL;
    char *form = NULL;
    struct json_object *response = NULL;

    if (!curl) return NULL;
    c = escape(curl, code);
    id = escape(curl, OPENAI_CLIENT_ID);
    redirect = escape(curl, redirect_uri);
    v = escape(curl, verifier);
    if (c && id && redirect && v && asprintf(&form,
        "grant_type=authorization_code&client_id=%s&code=%s&redirect_uri=%s&code_verifier=%s",
        id, c, redirect, v) >= 0)
        response = http_form_user_agent(p->token_url, form,
                                        OPENAI_OAUTH_USER_AGENT, status,
                                        reason, reason_len);
    curl_free(c); curl_free(id); curl_free(redirect); curl_free(v);
    if (form) OPENSSL_cleanse(form, strlen(form));
    free(form);
    curl_easy_cleanup(curl);
    return response;
}

static struct json_object *openai_refresh_exchange(const struct oauth_provider *p,
                                                   const char *refresh_token,
                                                   long *status, char *reason,
                                                   size_t reason_len)
{
    CURL *curl = curl_easy_init();
    char *refresh = NULL, *id = NULL, *scope = NULL, *form = NULL;
    struct json_object *response = NULL;

    if (!curl) return NULL;
    refresh = escape(curl, refresh_token);
    id = escape(curl, OPENAI_CLIENT_ID);
    scope = escape(curl, OPENAI_REFRESH_SCOPE);
    if (refresh && id && scope && asprintf(&form,
        "grant_type=refresh_token&refresh_token=%s&client_id=%s&scope=%s",
        refresh, id, scope) >= 0)
        response = http_form_user_agent(p->token_url, form,
                                        OPENAI_OAUTH_USER_AGENT, status,
                                        reason, reason_len);
    curl_free(refresh); curl_free(id); curl_free(scope);
    if (form) OPENSSL_cleanse(form, strlen(form));
    free(form);
    curl_easy_cleanup(curl);
    return response;
}

static struct json_object *jwt_payload(const char *jwt)
{
    const char *first, *second;
    unsigned char *encoded = NULL, *decoded = NULL;
    struct json_object *payload = NULL;
    size_t len, padded, allocation_len = 0;
    int out_len;

    if (!jwt || !(first = strchr(jwt, '.')) ||
        !(second = strchr(first + 1, '.')) || second == first + 1)
        return NULL;
    len = (size_t)(second - first - 1);
    if (len > OAUTH_MAX_SECRET / 2) return NULL;
    padded = (len + 3U) & ~3U;
    allocation_len = padded + 1;
    encoded = calloc(1, padded + 1);
    decoded = calloc(1, padded + 1);
    if (!encoded || !decoded) goto done;
    memcpy(encoded, first + 1, len);
    for (size_t i = 0; i < len; i++) {
        if (encoded[i] == '-') encoded[i] = '+';
        else if (encoded[i] == '_') encoded[i] = '/';
    }
    for (size_t i = len; i < padded; i++) encoded[i] = '=';
    out_len = EVP_DecodeBlock(decoded, encoded, (int)padded);
    if (out_len < 0) goto done;
    while (padded && encoded[padded - 1] == '=') {
        out_len--;
        padded--;
    }
    decoded[out_len] = 0;
    payload = json_tokener_parse((const char *)decoded);
    if (payload && !json_object_is_type(payload, json_type_object)) {
        json_object_put(payload);
        payload = NULL;
    }
done:
    if (decoded) OPENSSL_cleanse(decoded, allocation_len);
    free(encoded);
    free(decoded);
    return payload;
}

static char *openai_chatgpt_account_id(struct json_object *response)
{
    const char *tokens[2] = {
        json_string(response, "id_token"),
        json_string(response, "access_token")
    };

    for (int i = 0; i < 2; i++) {
        struct json_object *payload = jwt_payload(tokens[i]);
        struct json_object *auth = NULL;
        const char *account = NULL;

        if (!tokens[i]) continue;
        if (payload && json_object_object_get_ex(
                payload, "https://api.openai.com/auth", &auth) && auth &&
            json_object_is_type(auth, json_type_object))
            account = json_string(auth, "chatgpt_account_id");
        if (account && safe_identifier(account, "")) {
            char *copy = strdup(account);
            json_object_put(payload);
            return copy;
        }
        if (payload) json_object_put(payload);
    }
    return NULL;
}

static int persist_token(const char *provider, const char *client_id,
                         const char *project_id,
                         struct json_object *response, const char *old_refresh,
                         char *reason, size_t reason_len)
{
    const char *access = json_string(response, "access_token");
    const char *refresh = json_string(response, "refresh_token");
    const char *type = json_string(response, "token_type");
    struct json_object *state;
    char *chatgpt_account = NULL;
    if (!access || !*access) { snprintf(reason, reason_len, "missing_access_token"); return -1; }
    if (!refresh) refresh = old_refresh;
    state = json_object_new_object();
    json_object_object_add(state, "provider", json_object_new_string(provider));
    json_object_object_add(state, "access_token", json_object_new_string(access));
    if (refresh) json_object_object_add(state, "refresh_token", json_object_new_string(refresh));
    if (client_id) json_object_object_add(state, "client_id", json_object_new_string(client_id));
    if (project_id && strcmp(provider, "openai"))
        json_object_object_add(state, "project_id",
                               json_object_new_string(project_id));
    if (!strcmp(provider, "openai")) {
        chatgpt_account = openai_chatgpt_account_id(response);
        if (!chatgpt_account && project_id)
            chatgpt_account = strdup(project_id);
        if (chatgpt_account)
            json_object_object_add(state, "chatgpt_account_id",
                                   json_object_new_string(chatgpt_account));
        json_object_object_add(state, "account_type",
                               json_object_new_string("chatgpt_oauth"));
    }
    json_object_object_add(state, "token_type", json_object_new_string(type ? type : "Bearer"));
    json_object_object_add(state, "obtained_at", json_object_new_int64(now_seconds()));
    json_object_object_add(state, "expires_at", json_object_new_int64(now_seconds() + json_i64(response, "expires_in", 3600)));
    if (encrypted_save(provider, "token", state, reason, reason_len)) {
        free(chatgpt_account);
        json_object_put(state);
        return -1;
    }
    free(chatgpt_account);
    json_object_put(state);
    return 0;
}

static int persist_anthropic_token(struct json_object *config,
                                   struct json_object *response,
                                   char *reason, size_t reason_len)
{
    const char *access = json_string(response, "access_token");
    struct json_object *state;
    static const char *keys[] = {
        "identity_token_file", "federation_rule_id", "organization_id",
        "service_account_id", "workspace_id", NULL
    };

    if (!access || !access[0]) {
        snprintf(reason, reason_len, "missing_access_token");
        return -1;
    }
    state = json_object_new_object();
    json_object_object_add(state, "provider", json_object_new_string("anthropic"));
    json_object_object_add(state, "access_token", json_object_new_string(access));
    for (int i = 0; keys[i]; i++) {
        const char *value = json_string(config, keys[i]);
        if (value && value[0])
            json_object_object_add(state, keys[i], json_object_new_string(value));
    }
    json_object_object_add(state, "obtained_at",
                           json_object_new_int64(now_seconds()));
    json_object_object_add(state, "expires_at", json_object_new_int64(
        now_seconds() + json_i64(response, "expires_in", 3600)));
    if (encrypted_save("anthropic", "token", state, reason, reason_len)) {
        json_object_put(state);
        return -1;
    }
    json_object_put(state);
    return 0;
}

struct json_object *webd_ai_oauth_status(const char *provider, int *http_status)
{
    const struct oauth_provider *p;
    struct json_object *o, *state, *pending;
    char reason[128] = {0}; long long expiry = 0;
    provider = canonical_provider(provider);
    p = find_provider(provider);
    if (!p) return result_error("unknown_provider", "unknown OAuth provider", 404, http_status);
    if (http_status) *http_status = 200;
    o = provider_json(p);
    json_object_object_add(o, "ok", json_object_new_boolean(1));
    state = encrypted_load(provider, "token", reason, sizeof(reason));
    if (state) { expiry = json_i64(state, "expires_at", 0); json_object_put(state); }
    json_object_object_add(o, "connected", json_object_new_boolean(state != NULL));
    json_object_object_add(o, "expires_at", json_object_new_int64(expiry));
    json_object_object_add(o, "expired", json_object_new_boolean(expiry > 0 && expiry <= now_seconds()));
    if (!state && strcmp(reason, "not_connected")) json_object_object_add(o, "state_reason", json_object_new_string(reason));
    reason[0] = 0;
    pending = encrypted_load(provider, "pending", reason, sizeof(reason));
    json_object_object_add(o, "pending", json_object_new_boolean(pending != NULL));
    if (pending) {
        json_object_object_add(o, "pending_expires_at", json_object_new_int64(
            json_i64(pending, "expires_at", 0)));
        json_object_put(pending);
    }
    return o;
}

struct json_object *webd_ai_oauth_start(struct json_object *request,
                                        const char *actor, int *http_status)
{
    const char *provider = canonical_provider(json_string(request, "provider"));
    const struct oauth_provider *p = find_provider(provider); const char *client_id, *scope;
    CURL *curl; char *id = NULL, *sc = NULL, *form = NULL; long upstream = 0;
    struct json_object *response = NULL, *pending = NULL, *out = NULL; char reason[256] = {0};
    if (!p) return result_error("unknown_provider", "unknown OAuth provider", 404, http_status);
    if (!p->supported) return result_error("oauth_unsupported", p->reason, 409, http_status);
    if (!actor || !*actor) return result_error("actor_required", NULL, 400, http_status);
    if (!strcmp(provider, "anthropic")) {
        struct json_object *token_response;

        token_response = anthropic_wif_exchange(request, &upstream, reason,
                                                sizeof(reason));
        if (!token_response)
            return result_error("wif_exchange_failed", reason, 502, http_status);
        if (upstream < 200 || upstream >= 300 ||
            persist_anthropic_token(request, token_response, reason,
                                    sizeof(reason))) {
            const char *error = json_string(token_response, "error");
            const char *description = json_string(token_response,
                                                  "error_description");
            out = result_error(error ? error : "wif_exchange_failed",
                               description ? description : reason,
                               502, http_status);
            json_object_put(token_response);
            return out;
        }
        out = json_object_new_object();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "provider", json_object_new_string(provider));
        json_object_object_add(out, "connected", json_object_new_boolean(1));
        json_object_object_add(out, "mode", json_object_new_string("enterprise_wif"));
        json_object_object_add(out, "expires_at", json_object_new_int64(
            now_seconds() + json_i64(token_response, "expires_in", 3600)));
        if (http_status) *http_status = 200;
        json_object_put(token_response);
        return out;
    }
    if (!strcmp(provider, "openai")) {
        const char *redirect_uri = json_string(request, "redirect_uri");
        char *verifier = NULL, *challenge = NULL, *state = NULL;
        char *auth = NULL, *eid = NULL, *er = NULL, *es = NULL;
        char *ech = NULL, *estate = NULL;
        char stale[256];

        if (!redirect_uri || !redirect_uri[0]) redirect_uri = OPENAI_REDIRECT_URI;
        if (!secure_equal(redirect_uri, OPENAI_REDIRECT_URI))
            return result_error("invalid_oauth_request",
                                "OpenAI ChatGPT OAuth uses its registered localhost callback; paste the complete callback URL into DreamingWrt after authorization",
                                400, http_status);
        verifier = random_hex(64);
        challenge = verifier ? pkce_challenge(verifier) : NULL;
        state = random_hex(32);
        curl = curl_easy_init();
        if (!verifier || !challenge || !state || !curl)
            goto openai_start_failed;
        eid = escape(curl, OPENAI_CLIENT_ID);
        er = escape(curl, redirect_uri);
        es = escape(curl, OPENAI_SCOPE);
        ech = escape(curl, challenge);
        estate = escape(curl, state);
        if (!eid || !er || !es || !ech || !estate ||
            asprintf(&auth,
                "%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256&id_token_add_organizations=true&codex_cli_simplified_flow=true",
                p->authorization_url, eid, er, es, estate, ech) < 0)
            goto openai_start_failed;
        pending = json_object_new_object();
        if (!pending) goto openai_start_failed;
        json_object_object_add(pending, "provider",
                               json_object_new_string("openai"));
        json_object_object_add(pending, "actor", json_object_new_string(actor));
        json_object_object_add(pending, "client_id",
                               json_object_new_string(OPENAI_CLIENT_ID));
        json_object_object_add(pending, "redirect_uri",
                               json_object_new_string(redirect_uri));
        json_object_object_add(pending, "code_verifier",
                               json_object_new_string(verifier));
        json_object_object_add(pending, "state", json_object_new_string(state));
        json_object_object_add(pending, "started_at",
                               json_object_new_int64(now_seconds()));
        json_object_object_add(pending, "expires_at",
                               json_object_new_int64(now_seconds() + 1800));
        if (!state_path(stale, sizeof(stale), provider, "in-flight"))
            unlink(stale);
        if (encrypted_save(provider, "pending", pending, reason,
                           sizeof(reason)))
            goto openai_start_failed;
        out = json_object_new_object();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "provider",
                               json_object_new_string("openai"));
        json_object_object_add(out, "authorization_url",
                               json_object_new_string(auth));
        json_object_object_add(out, "auth_url", json_object_new_string(auth));
        json_object_object_add(out, "state", json_object_new_string(state));
        json_object_object_add(out, "redirect_uri",
                               json_object_new_string(redirect_uri));
        json_object_object_add(out, "expires_in", json_object_new_int(1800));
        json_object_object_add(out, "callback_transport",
                               json_object_new_string("manual_callback_url_to_poll"));
        json_object_object_add(out, "callback_url_parse_required",
                               json_object_new_boolean(1));
        if (http_status) *http_status = 200;
        goto openai_start_done;
openai_start_failed:
        if (!out)
            out = result_error("oauth_state_failed",
                               reason[0] ? reason :
                                   "OpenAI PKCE initialization failed",
                               500, http_status);
openai_start_done:
        if (pending) json_object_put(pending);
        curl_free(eid); curl_free(er); curl_free(es);
        curl_free(ech); curl_free(estate);
        if (curl) curl_easy_cleanup(curl);
        if (verifier) OPENSSL_cleanse(verifier, strlen(verifier));
        free(verifier); free(challenge); free(state); free(auth);
        return out;
    }
    client_id = !strcmp(provider, "kimi") ? KIMI_CLIENT_ID : json_string(request, "client_id");
    scope = json_string(request, "scope"); if (!scope) scope = p->scope;
    if (!client_id || !*client_id) return result_error("client_id_required", "Gemini OAuth requires a user-owned Google OAuth client_id", 400, http_status);
    if (!strcmp(p->id, "gemini")) {
        const char *redirect_uri = json_string(request, "redirect_uri");
        const char *project_id = json_string(request, "project_id");
        char *verifier = NULL, *challenge = NULL, *state = NULL;
        char *auth = NULL, *eid = NULL, *er = NULL, *es = NULL,
             *ech = NULL, *estate = NULL;
        if (!project_id || !*project_id || !redirect_uri_valid(redirect_uri))
            return result_error("invalid_oauth_request", "Gemini requires project_id and an explicit HTTP(S) callback URI", 400, http_status);
        verifier = random_base64url(48); challenge = verifier ? pkce_challenge(verifier) : NULL;
        state = random_base64url(32); curl = curl_easy_init();
        if (!verifier || !challenge || !state || !curl) goto gemini_start_failed;
        eid = escape(curl, client_id);
        er = escape(curl, redirect_uri); es = escape(curl, scope);
        ech = escape(curl, challenge); estate = escape(curl, state);
        if (!eid || !er || !es || !ech || !estate ||
            asprintf(&auth, "%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s&access_type=offline&prompt=consent",
                     p->authorization_url, eid, er, es, ech, estate) < 0)
            goto gemini_start_failed;
        pending = json_object_new_object();
        json_object_object_add(pending, "provider", json_object_new_string("gemini"));
        json_object_object_add(pending, "actor", json_object_new_string(actor));
        json_object_object_add(pending, "client_id", json_object_new_string(client_id));
        json_object_object_add(pending, "redirect_uri", json_object_new_string(redirect_uri));
        json_object_object_add(pending, "code_verifier", json_object_new_string(verifier));
        json_object_object_add(pending, "state", json_object_new_string(state));
        if (project_id) json_object_object_add(pending, "project_id", json_object_new_string(project_id));
        json_object_object_add(pending, "expires_at", json_object_new_int64(now_seconds() + 600));
        if (encrypted_save(provider, "pending", pending, reason, sizeof(reason)))
            goto gemini_start_failed;
        out = json_object_new_object();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "provider", json_object_new_string("gemini"));
        json_object_object_add(out, "authorization_url", json_object_new_string(auth));
        json_object_object_add(out, "state", json_object_new_string(state));
        json_object_object_add(out, "expires_in", json_object_new_int(600));
        if (http_status) *http_status = 200;
        json_object_put(pending); pending = NULL;
        goto gemini_start_done;
gemini_start_failed:
        if (!out) out = result_error("oauth_state_failed", *reason ? reason : "Gemini PKCE initialization failed", 500, http_status);
        if (pending) json_object_put(pending);
gemini_start_done:
        curl_free(eid); curl_free(er); curl_free(es);
        curl_free(ech); curl_free(estate); if (curl) curl_easy_cleanup(curl);
        if (verifier) OPENSSL_cleanse(verifier, strlen(verifier));
        free(verifier); free(challenge); free(state); free(auth);
        return out;
    }
    curl = curl_easy_init(); if (!curl) return result_error("curl_init_failed", NULL, 500, http_status);
    id = escape(curl, client_id); sc = escape(curl, scope);
    if (id && (!scope || sc)) {
        if (scope) asprintf(&form, "client_id=%s&scope=%s", id, sc);
        else asprintf(&form, "client_id=%s", id);
    }
    if (form) response = http_form(p->device_url, form, &upstream, reason, sizeof(reason));
    curl_free(id); curl_free(sc); free(form); curl_easy_cleanup(curl);
    if (!response) return result_error("oauth_start_failed", reason, 502, http_status);
    if (upstream < 200 || upstream >= 300 || !json_string(response, "device_code")) {
        const char *e = json_string(response, "error"); out = result_error(e ? e : "oauth_start_rejected", json_string(response, "error_description"), 502, http_status); json_object_put(response); return out;
    }
    pending = json_object_new_object();
    json_object_object_add(pending, "provider", json_object_new_string(provider));
    json_object_object_add(pending, "actor", json_object_new_string(actor));
    json_object_object_add(pending, "client_id", json_object_new_string(client_id));
    json_object_object_add(pending, "device_code", json_object_new_string(json_string(response, "device_code")));
    json_object_object_add(pending, "started_at", json_object_new_int64(now_seconds()));
    json_object_object_add(pending, "expires_at", json_object_new_int64(now_seconds() + json_i64(response, "expires_in", 900)));
    json_object_object_add(pending, "interval", json_object_new_int64(json_i64(response, "interval", 5)));
    json_object_object_add(pending, "last_poll_at", json_object_new_int64(0));
    if (encrypted_save(provider, "pending", pending, reason, sizeof(reason))) {
        json_object_put(pending); json_object_put(response); return result_error("oauth_state_failed", reason, 500, http_status);
    }
    json_object_put(pending);
    json_object_object_del(response, "device_code");
    json_object_object_add(response, "ok", json_object_new_boolean(1));
    json_object_object_add(response, "provider", json_object_new_string(provider));
    json_object_object_add(response, "poll_after_seconds", json_object_new_int64(json_i64(response, "interval", 5)));
    if (http_status) *http_status = 200;
    return response;
}

struct json_object *webd_ai_oauth_poll(struct json_object *request,
                                       const char *actor, int *http_status)
{
    const char *provider = canonical_provider(json_string(request, "provider"));
    const struct oauth_provider *p = find_provider(provider); struct json_object *pending, *response, *out;
    const char *device_code, *client_id, *error; long upstream = 0; char reason[256] = {0}, path[256];
    if (!p) return result_error("unknown_provider", NULL, 404, http_status);
    if (!p->supported) return result_error("oauth_unsupported", p->reason, 409, http_status);
    if (!actor || !*actor) return result_error("actor_required", NULL, 400, http_status);
    pending = encrypted_load(provider, "pending", reason, sizeof(reason));
    if (!pending) return result_error("oauth_not_pending", reason, 409, http_status);
    if (!secure_equal(json_string(pending, "actor"), actor)) {
        json_object_put(pending);
        return result_error("oauth_actor_mismatch", NULL, 403, http_status);
    }
    if (json_i64(pending, "expires_at", 0) <= now_seconds()) { json_object_put(pending); return result_error("expired_token", "OAuth authorization expired", 410, http_status); }
    if (!strcmp(p->id, "openai")) {
        const char *code = json_string(request, "code");
        const char *returned_state = json_string(request, "state");
        const char *callback_url = json_string(request, "callback_url");
        const char *expected_state = json_string(pending, "state");
        const char *redirect_uri = json_string(pending, "redirect_uri");
        const char *verifier = json_string(pending, "code_verifier");
        char *parsed_code = NULL, *parsed_state = NULL;
        char pending_path[256], inflight_path[256];

        if (callback_url && callback_url[0]) {
            if (openai_callback_url_parse(callback_url, &parsed_code,
                                          &parsed_state) != 0) {
                json_object_put(pending);
                return result_error("invalid_oauth_callback",
                                    "OpenAI callback URL must match its registered localhost callback and contain one code/state pair",
                                    400, http_status);
            }
            code = parsed_code;
            returned_state = parsed_state;
        }
        if (!code || !code[0] || strlen(code) > 8192 || !returned_state ||
            !secure_equal(returned_state, expected_state)) {
            if (parsed_code) { OPENSSL_cleanse(parsed_code, strlen(parsed_code)); curl_free(parsed_code); }
            if (parsed_state) { OPENSSL_cleanse(parsed_state, strlen(parsed_state)); curl_free(parsed_state); }
            json_object_put(pending);
            return result_error("oauth_state_mismatch",
                                "OpenAI OAuth callback state does not match",
                                400, http_status);
        }
        if (state_path(pending_path, sizeof(pending_path), provider, "pending") ||
            state_path(inflight_path, sizeof(inflight_path), provider, "in-flight") ||
            rename(pending_path, inflight_path)) {
            if (parsed_code) { OPENSSL_cleanse(parsed_code, strlen(parsed_code)); curl_free(parsed_code); }
            if (parsed_state) { OPENSSL_cleanse(parsed_state, strlen(parsed_state)); curl_free(parsed_state); }
            json_object_put(pending);
            return result_error("oauth_callback_already_claimed",
                                "OpenAI OAuth callback was already consumed",
                                409, http_status);
        }
        response = openai_code_exchange(p, code, redirect_uri, verifier,
                                        &upstream, reason, sizeof(reason));
        if (parsed_code) { OPENSSL_cleanse(parsed_code, strlen(parsed_code)); curl_free(parsed_code); }
        if (parsed_state) { OPENSSL_cleanse(parsed_state, strlen(parsed_state)); curl_free(parsed_state); }
        unlink(inflight_path);
        if (!response) {
            json_object_put(pending);
            return result_error("oauth_poll_failed", reason, 502, http_status);
        }
        error = json_string(response, "error");
        if (error || upstream < 200 || upstream >= 300 ||
            persist_token(provider, OPENAI_CLIENT_ID, NULL, response, NULL,
                          reason, sizeof(reason))) {
            out = result_error(error ? error : "oauth_token_failed",
                               error ? json_string(response,
                                                   "error_description") : reason,
                               502, http_status);
            json_object_put(response);
            json_object_put(pending);
            return out;
        }
        out = json_object_new_object();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "provider",
                               json_object_new_string("openai"));
        json_object_object_add(out, "account_type",
                               json_object_new_string("chatgpt_oauth"));
        json_object_object_add(out, "connected", json_object_new_boolean(1));
        json_object_object_add(out, "expires_at", json_object_new_int64(
            now_seconds() + json_i64(response, "expires_in", 3600)));
        if (http_status) *http_status = 200;
        json_object_put(response);
        json_object_put(pending);
        return out;
    }
    if (!strcmp(p->id, "gemini")) {
        const char *code = json_string(request, "code");
        const char *returned_state = json_string(request, "state");
        const char *expected_state = json_string(pending, "state");
        const char *redirect_uri = json_string(pending, "redirect_uri");
        const char *verifier = json_string(pending, "code_verifier");
        const char *project_id = json_string(pending, "project_id");
        if (!code || !returned_state || !secure_equal(returned_state, expected_state)) {
            json_object_put(pending);
            return result_error("oauth_state_mismatch", "Gemini OAuth callback state does not match", 400, http_status);
        }
        client_id = json_string(pending, "client_id");
        response = gemini_code_exchange(p, code, client_id, redirect_uri, verifier,
                                        &upstream, reason, sizeof(reason));
        if (!response) { json_object_put(pending); return result_error("oauth_poll_failed", reason, 502, http_status); }
        error = json_string(response, "error");
        if (error || upstream < 200 || upstream >= 300 ||
            persist_token(provider, client_id, project_id, response, NULL,
                          reason, sizeof(reason))) {
            out = result_error(error ? error : "oauth_token_failed",
                               error ? json_string(response, "error_description") : reason,
                               502, http_status);
            json_object_put(response); json_object_put(pending); return out;
        }
        if (!state_path(path, sizeof(path), provider, "pending")) unlink(path);
        out = json_object_new_object();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "provider", json_object_new_string("gemini"));
        json_object_object_add(out, "connected", json_object_new_boolean(1));
        json_object_object_add(out, "expires_at", json_object_new_int64(now_seconds() + json_i64(response, "expires_in", 3600)));
        if (http_status) *http_status = 200;
        json_object_put(response); json_object_put(pending); return out;
    }
    {
        long long interval = json_i64(pending, "interval", 5);
        long long last_poll = json_i64(pending, "last_poll_at", 0);
        long long now = now_seconds();
        if (last_poll > 0 && now < last_poll + interval) {
            out = result_error("poll_too_fast",
                               "OAuth polling interval has not elapsed",
                               429, http_status);
            json_object_object_add(out, "retry_after_seconds",
                                   json_object_new_int64(last_poll + interval - now));
            json_object_put(pending);
            return out;
        }
        json_object_object_add(pending, "last_poll_at", json_object_new_int64(now));
        if (encrypted_save(provider, "pending", pending, reason, sizeof(reason))) {
            json_object_put(pending);
            return result_error("oauth_state_failed", reason, 500, http_status);
        }
    }
    device_code = json_string(pending, "device_code"); client_id = json_string(pending, "client_id");
    response = oauth_exchange(p, "urn:ietf:params:oauth:grant-type:device_code", device_code, client_id, &upstream, reason, sizeof(reason));
    if (!response) { json_object_put(pending); return result_error("oauth_poll_failed", reason, 502, http_status); }
    error = json_string(response, "error");
    if (error) {
        int status = (!strcmp(error, "authorization_pending") || !strcmp(error, "slow_down")) ? 202 : 400;
        out = result_error(error, json_string(response, "error_description"), status, http_status);
        json_object_object_add(out, "retry_after_seconds", json_object_new_int64(json_i64(pending, "interval", 5) + (!strcmp(error, "slow_down") ? 5 : 0)));
        json_object_put(response); json_object_put(pending); return out;
    }
    if (upstream < 200 || upstream >= 300 || persist_token(provider, client_id, NULL, response, NULL, reason, sizeof(reason))) {
        json_object_put(response); json_object_put(pending); return result_error("oauth_token_failed", reason, 502, http_status);
    }
    if (!state_path(path, sizeof(path), provider, "pending")) unlink(path);
    out = json_object_new_object(); json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "provider", json_object_new_string(provider)); json_object_object_add(out, "connected", json_object_new_boolean(1));
    json_object_object_add(out, "expires_at", json_object_new_int64(now_seconds() + json_i64(response, "expires_in", 3600)));
    if (http_status) *http_status = 200;
    json_object_put(response);
    json_object_put(pending);
    return out;
}

struct json_object *webd_ai_oauth_refresh(const char *provider, int *http_status)
{
    const struct oauth_provider *p;
    struct json_object *state, *response, *out;
    const char *refresh, *client_id, *error; long upstream = 0; char reason[256] = {0};
    provider = canonical_provider(provider);
    p = find_provider(provider);
    if (!p) return result_error("unknown_provider", NULL, 404, http_status);
    if (!p->supported) return result_error("oauth_unsupported", p->reason, 409, http_status);
    state = encrypted_load(provider, "token", reason, sizeof(reason));
    if (!state) return result_error("not_connected", reason, 409, http_status);
    if (!strcmp(provider, "anthropic")) {
        response = anthropic_wif_exchange(state, &upstream, reason,
                                          sizeof(reason));
        if (!response || upstream < 200 || upstream >= 300 ||
            persist_anthropic_token(state, response, reason, sizeof(reason))) {
            if (response) json_object_put(response);
            json_object_put(state);
            return result_error("wif_exchange_failed", reason, 502, http_status);
        }
        out = json_object_new_object();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "provider", json_object_new_string(provider));
        json_object_object_add(out, "connected", json_object_new_boolean(1));
        json_object_object_add(out, "expires_at", json_object_new_int64(
            now_seconds() + json_i64(response, "expires_in", 3600)));
        if (http_status) *http_status = 200;
        json_object_put(response);
        json_object_put(state);
        return out;
    }
    refresh = json_string(state, "refresh_token"); client_id = json_string(state, "client_id");
    if (!refresh) { json_object_put(state); return result_error("refresh_token_unavailable", NULL, 409, http_status); }
    response = !strcmp(provider, "openai") ?
        openai_refresh_exchange(p, refresh, &upstream, reason, sizeof(reason)) :
        oauth_exchange(p, "refresh_token", refresh, client_id, &upstream,
                       reason, sizeof(reason));
    if (!response) { json_object_put(state); return result_error("oauth_refresh_failed", reason, 502, http_status); }
    error = json_string(response, "error");
    if (error || upstream < 200 || upstream >= 300 || persist_token(
            provider, client_id,
            !strcmp(provider, "openai") ?
                json_string(state, "chatgpt_account_id") :
                json_string(state, "project_id"),
            response, refresh, reason, sizeof(reason))) {
        out = result_error(error ? error : "oauth_refresh_failed", error ? json_string(response, "error_description") : reason, 502, http_status);
        json_object_put(response); json_object_put(state); return out;
    }
    out = json_object_new_object(); json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "provider", json_object_new_string(provider)); json_object_object_add(out, "connected", json_object_new_boolean(1));
    json_object_object_add(out, "expires_at", json_object_new_int64(now_seconds() + json_i64(response, "expires_in", 3600)));
    if (http_status) *http_status = 200;
    json_object_put(response);
    json_object_put(state);
    return out;
}

struct json_object *webd_ai_oauth_disconnect(const char *provider,
                                             const char *actor, int *http_status)
{
    const struct oauth_provider *p; char path[256]; int removed = 0;
    struct json_object *o, *state; char reason[128] = {0}; int revoked = 0;
    provider = canonical_provider(provider); p = find_provider(provider);
    if (!p) return result_error("unknown_provider", NULL, 404, http_status);
    if (!actor || !*actor) return result_error("actor_required", NULL, 400, http_status);
    state = encrypted_load(provider, "token", reason, sizeof(reason));
    if (state && p->revoke_url) {
        CURL *curl = curl_easy_init(); char *escaped = NULL, *form = NULL;
        const char *refresh = json_string(state, "refresh_token");
        const char *access = json_string(state, "access_token");
        if (curl && (escaped = escape(curl, refresh ? refresh : access)) != NULL &&
            asprintf(&form, "token=%s", escaped) >= 0)
            revoked = http_form_discard(p->revoke_url, form) == 0;
        free(form); curl_free(escaped); if (curl) curl_easy_cleanup(curl);
    }
    if (state) json_object_put(state);
    if (!state_path(path, sizeof(path), provider, "token") && (!unlink(path) || errno == ENOENT)) removed++;
    if (!state_path(path, sizeof(path), provider, "pending") && (!unlink(path) || errno == ENOENT)) removed++;
    if (!state_path(path, sizeof(path), provider, "in-flight") && (!unlink(path) || errno == ENOENT)) removed++;
    if (removed != 3) return result_error("disconnect_failed", strerror(errno), 500, http_status);
    o = json_object_new_object(); json_object_object_add(o, "ok", json_object_new_boolean(1));
    json_object_object_add(o, "provider", json_object_new_string(provider)); json_object_object_add(o, "connected", json_object_new_boolean(0));
    json_object_object_add(o, "revoked_upstream", json_object_new_boolean(revoked));
    json_object_object_add(o, "upstream_revoke_supported",
                           json_object_new_boolean(p->revoke_url != NULL));
    if (http_status) *http_status = 200;
    return o;
}

int webd_ai_oauth_access_token(const char *provider, char *token, size_t token_len,
                               char *routing_id, size_t routing_id_len,
                               int64_t *expires_at)
{
    struct json_object *state, *refresh_result; const char *access, *routing;
    long long expiry; char reason[128] = {0}; int status = 0;
    provider = canonical_provider(provider);
    if (!find_provider(provider) || !token || !token_len || !routing_id ||
        !routing_id_len)
        return WEBD_AI_OAUTH_INVALID;
    token[0] = 0;
    routing_id[0] = 0;
    state = encrypted_load(provider, "token", reason, sizeof(reason));
    if (!state) return WEBD_AI_OAUTH_UNAVAILABLE;
    access = json_string(state, "access_token"); expiry = json_i64(state, "expires_at", 0);
    if (expiry <= now_seconds() + 300) {
        json_object_put(state);
        refresh_result = webd_ai_oauth_refresh(provider, &status);
        if (!refresh_result || status < 200 || status >= 300) {
            if (refresh_result) json_object_put(refresh_result);
            return WEBD_AI_OAUTH_REFRESH_FAILED;
        }
        json_object_put(refresh_result);
        state = encrypted_load(provider, "token", reason, sizeof(reason));
        if (!state) return WEBD_AI_OAUTH_STORAGE_FAILED;
        access = json_string(state, "access_token"); expiry = json_i64(state, "expires_at", 0);
    }
    routing = !strcmp(provider, "openai") ?
        json_string(state, "chatgpt_account_id") :
        json_string(state, "project_id");
    if (!access || !*access) { json_object_put(state); return WEBD_AI_OAUTH_UNAVAILABLE; }
    if (strlen(access) >= token_len ||
        (routing && strlen(routing) >= routing_id_len)) {
        json_object_put(state); return WEBD_AI_OAUTH_BUFFER_TOO_SMALL;
    }
    memcpy(token, access, strlen(access) + 1);
    if (routing) memcpy(routing_id, routing, strlen(routing) + 1);
    if (expires_at) *expires_at = (int64_t)expiry;
    json_object_put(state); return WEBD_AI_OAUTH_OK;
}
