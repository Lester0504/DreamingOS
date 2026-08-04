// SPDX-License-Identifier: GPL-2.0-or-later
/* Authenticated, fork-safe LLM provider runtime for dreamingwrt-webd. */
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ai_runtime.h"
#include "ai_oauth.h"
#include "jmx_app_api.h"
#include "webd_http.h"

#define AI_CONFIG_DB "/etc/dreamingwrt/config.db"
#define AI_AUDIT_DB "/etc/dreamingwrt/apid.db"
#define AI_MAX_MESSAGES 64
#define AI_MAX_MESSAGE_BYTES (64 * 1024)
#define AI_MAX_PROMPT_BYTES (1280 * 1024)
#define AI_MAX_ATTACHMENTS 8
#define AI_MAX_ATTACHMENT_BYTES (512 * 1024)
#define AI_MAX_ATTACHMENTS_TOTAL (1024 * 1024)
#define AI_MAX_RESPONSE_BYTES (512 * 1024)
#define AI_MAX_REQUESTS_PER_MINUTE 20
#define AI_MAX_CONCURRENT 2
#define AI_MAX_TOOL_ROUNDS 4
#define AI_MAX_TOOL_CALLS_PER_ROUND 8
#define AI_MAX_TOOL_RESULT_BYTES (64 * 1024)
#define AI_MAX_TOOL_RESULTS_TOTAL (512 * 1024)
#define AI_CONVERSATION_TITLE_MAX_BYTES 96
#define AI_CONVERSATION_HISTORY_TITLE_MAX_BYTES 512
#define AI_CONVERSATION_TITLE_CONTEXT_BYTES (16 * 1024)
#define AI_CONVERSATION_TITLE_TOKENS 48
#define AI_CONVERSATION_TITLE_FALLBACK "\xE6\x96\xB0\xE5\xAF\xB9\xE8\xAF\x9D"
#define AI_RESPONSE_DIR "/tmp/dreamingwrt/ai-responses"
#define AI_TOOL_RESUME_DIR "/tmp/dreamingwrt/ai-tool-resume"
#define AI_TOOL_RESUME_TTL 900
#define AI_TOOL_RESUME_MAX_FILES 16
#define AI_TOOL_RESUME_MAX_BYTES (3 * 1024 * 1024)
#define AI_ATTACHMENT_DIR "/opt/dreamingwrt/ai/attachments"
#define AI_ATTACHMENT_TTL (30 * 86400)
#define AI_ATTACHMENT_MAX_META_BYTES 8192
#define AI_ATTACHMENT_SCAN_LIMIT 1024
#define AI_OPENAI_CHATGPT_BASE "https://chatgpt.com/backend-api/codex"
#define AI_OPENAI_CODEX_USER_AGENT \
    "codex_cli_rs/0.144.1 (Ubuntu 22.4.0; x86_64) xterm-256color"
#define AI_OPENAI_CODEX_ORIGINATOR "codex_cli_rs"

struct ai_config {
    int enabled;
    char provider[64];
    char api_base[512];
    char api_key[1024];
    char model[128];
    double temperature;
    int max_tokens;
    char system_prompt[8192];
    char tool_policy[32];
    char reasoning_effort[32];
    char api_shape[32];
    char auth_mode[16];
    char oauth_project[128];
};

struct ai_buffer {
    char *data;
    size_t len;
    size_t cap;
};

struct ai_sse_capture {
    char *pending;
    size_t pending_len;
    struct json_object *completed;
    struct json_object *error;
};

struct ai_result {
    struct json_object *data;
    long provider_status;
    CURLcode curl_code;
    char provider_code[96];
    char provider_message[256];
};

static int64_t ai_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *ai_text(sqlite3_stmt *st, int col)
{
    const unsigned char *s = st ? sqlite3_column_text(st, col) : NULL;
    return s ? (const char *)s : "";
}

static const char *ai_json_string(struct json_object *obj, const char *key,
                                  const char *fallback)
{
    struct json_object *value = NULL;
    if (obj && json_object_object_get_ex(obj, key, &value) && value &&
        json_object_is_type(value, json_type_string))
        return json_object_get_string(value);
    return fallback ? fallback : "";
}

/*
 * Length-independent comparison for secret material.
 *
 * strcmp() returns at the first differing byte, so comparing a resume token with
 * it leaks the token byte by byte through response timing. The resume token
 * names a file an unfinished tool call can be continued from, so treating it as
 * a secret is the right default even though the window is short.
 */
static int ai_ct_str_equal(const char *a, const char *b)
{
    size_t alen, blen, i, n;
    unsigned char diff = 0;

    if (!a || !b)
        return 0;
    alen = strlen(a);
    blen = strlen(b);
    n = alen > blen ? alen : blen;
    for (i = 0; i < n; i++) {
        unsigned char ac = i < alen ? (unsigned char)a[i] : 0;
        unsigned char bc = i < blen ? (unsigned char)b[i] : 0;

        diff |= (unsigned char)(ac ^ bc);
    }
    return diff == 0 && alen == blen;
}

static int ai_contains_i(const char *text, const char *needle)
{
    size_t n = needle ? strlen(needle) : 0;
    if (!text || !needle || !n) return 0;
    for (; *text; text++)
        if (!strncasecmp(text, needle, n)) return 1;
    return 0;
}

static int ai_value_ok(const char *value, size_t max_len)
{
    size_t n = value ? strlen(value) : 0;
    if (!n || n > max_len) return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] == 0x7f)
            return 0;
    return 1;
}

static int ai_attachment_id_ok(const char *id)
{
    if (!id || strlen(id) != 36 || strncmp(id, "att-", 4)) return 0;
    for (size_t i = 4; i < 36; i++)
        if (!isxdigit((unsigned char)id[i])) return 0;
    return 1;
}

static int ai_write_all(int fd, const char *data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t wrote = write(fd, data + offset, len - offset);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return -1;
        offset += (size_t)wrote;
    }
    return 0;
}

static int ai_attachment_dir_ready(void)
{
    if ((mkdir("/opt", 0755) != 0 && errno != EEXIST) ||
        (mkdir("/opt/dreamingwrt", 0700) != 0 && errno != EEXIST) ||
        (mkdir("/opt/dreamingwrt/ai", 0700) != 0 && errno != EEXIST) ||
        (mkdir(AI_ATTACHMENT_DIR, 0700) != 0 && errno != EEXIST))
        return -1;
    return chmod(AI_ATTACHMENT_DIR, 0700);
}

static void ai_attachment_paths(const char *id, char *data, size_t data_len,
                                char *meta, size_t meta_len)
{
    snprintf(data, data_len, "%s/%s.data", AI_ATTACHMENT_DIR, id);
    snprintf(meta, meta_len, "%s/%s.json", AI_ATTACHMENT_DIR, id);
}

static struct json_object *ai_attachment_meta_load(const char *id)
{
    char data_path[512], meta_path[512], raw[AI_ATTACHMENT_MAX_META_BYTES + 1];
    struct stat st;
    struct json_object *meta;
    int fd;
    ssize_t got;

    if (!ai_attachment_id_ok(id)) return NULL;
    ai_attachment_paths(id, data_path, sizeof(data_path), meta_path, sizeof(meta_path));
    fd = open(meta_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > AI_ATTACHMENT_MAX_META_BYTES) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    got = read(fd, raw, (size_t)st.st_size);
    close(fd);
    if (got != st.st_size) return NULL;
    raw[got] = 0;
    meta = json_tokener_parse(raw);
    if (!meta || !json_object_is_type(meta, json_type_object)) {
        if (meta) json_object_put(meta);
        return NULL;
    }
    return meta;
}

static void ai_attachment_remove_files(const char *id)
{
    char data_path[512], meta_path[512];
    if (!ai_attachment_id_ok(id)) return;
    ai_attachment_paths(id, data_path, sizeof(data_path), meta_path, sizeof(meta_path));
    unlink(data_path);
    unlink(meta_path);
}

static void ai_attachment_cleanup_expired(void)
{
    DIR *dir;
    struct dirent *entry;
    int scanned = 0;
    int64_t now = (int64_t)time(NULL);

    if (ai_attachment_dir_ready() != 0 || !(dir = opendir(AI_ATTACHMENT_DIR))) return;
    while (scanned++ < AI_ATTACHMENT_SCAN_LIMIT && (entry = readdir(dir))) {
        size_t len = strlen(entry->d_name);
        char id[37];
        struct json_object *meta;
        int64_t expires;
        if (len != 41 || strcmp(entry->d_name + 36, ".json")) continue;
        memcpy(id, entry->d_name, 36);
        id[36] = 0;
        if (!ai_attachment_id_ok(id)) continue;
        meta = ai_attachment_meta_load(id);
        expires = meta ? (int64_t)json_object_get_int64(
            json_object_object_get(meta, "expires_at")) : 0;
        if (!meta || expires <= now) ai_attachment_remove_files(id);
        if (meta) json_object_put(meta);
    }
    closedir(dir);
}

static int ai_attachment_meta_owned(struct json_object *meta, const char *actor)
{
    return meta && actor && actor[0] &&
           !strcmp(ai_json_string(meta, "actor", ""), actor);
}

static char *ai_attachment_content_load(const char *id, struct json_object *meta,
                                        size_t *out_len)
{
    char data_path[512], meta_path[512];
    struct stat st;
    char *content;
    size_t offset = 0;
    int fd;
    ssize_t got;

    ai_attachment_paths(id, data_path, sizeof(data_path), meta_path, sizeof(meta_path));
    fd = open(data_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > AI_MAX_ATTACHMENT_BYTES ||
        st.st_size != json_object_get_int64(json_object_object_get(meta, "size"))) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    content = malloc((size_t)st.st_size + 1);
    if (!content) { close(fd); return NULL; }
    while (offset < (size_t)st.st_size) {
        got = read(fd, content + offset, (size_t)st.st_size - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(content); close(fd); return NULL; }
        offset += (size_t)got;
    }
    close(fd);
    content[offset] = 0;
    if (out_len) *out_len = offset;
    return content;
}

static struct json_object *ai_meta(const char *source)
{
    struct json_object *meta = json_object_new_object();
    char request_id[80];

    snprintf(request_id, sizeof(request_id), "ai-%lld-%ld",
             (long long)ai_now_ms(), (long)getpid());
    json_object_object_add(meta, "request_id", json_object_new_string(request_id));
    json_object_object_add(meta, "source", json_object_new_string(source));
    json_object_object_add(meta, "generated_at",
                           json_object_new_int64((int64_t)time(NULL)));
    return meta;
}

static struct json_object *ai_success(struct json_object *data, const char *source)
{
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "code", json_object_new_int(2000));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    json_object_object_add(root, "meta", ai_meta(source));
    return root;
}

static struct json_object *ai_error(const char *code, const char *message,
                                    int status, long provider_status,
                                    const char *provider_code,
                                    const char *provider_message)
{
    struct json_object *root = json_object_new_object();
    struct json_object *error = json_object_new_object();
    struct json_object *details = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "code", json_object_new_int(status));
    json_object_object_add(error, "code", json_object_new_string(code));
    json_object_object_add(error, "message", json_object_new_string(message));
    if (provider_status > 0)
        json_object_object_add(details, "provider_status",
                               json_object_new_int64(provider_status));
    if (provider_code && provider_code[0])
        json_object_object_add(details, "provider_code",
                               json_object_new_string(provider_code));
    if (provider_message && provider_message[0])
        json_object_object_add(details, "provider_message",
                               json_object_new_string(provider_message));
    json_object_object_add(error, "details", details);
    json_object_object_add(root, "error", error);
    json_object_object_add(root, "meta", ai_meta("webd.ai.runtime"));
    return root;
}

static int ai_attachment_id_generate(char id[37])
{
    unsigned char random[16];
    size_t offset = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    while (offset < sizeof(random)) {
        ssize_t got = read(fd, random + offset, sizeof(random) - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { close(fd); return -1; }
        offset += (size_t)got;
    }
    close(fd);
    memcpy(id, "att-", 4);
    for (size_t i = 0; i < sizeof(random); i++)
        snprintf(id + 4 + i * 2, 3, "%02x", random[i]);
    id[36] = 0;
    return 0;
}

static struct json_object *ai_attachment_public_meta(struct json_object *meta)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "attachment_id", json_object_new_string(
        ai_json_string(meta, "attachment_id", "")));
    json_object_object_add(data, "name", json_object_new_string(
        ai_json_string(meta, "name", "attachment.txt")));
    json_object_object_add(data, "type", json_object_new_string(
        ai_json_string(meta, "type", "text/plain")));
    json_object_object_add(data, "size", json_object_new_int64(
        json_object_get_int64(json_object_object_get(meta, "size"))));
    json_object_object_add(data, "created_at", json_object_new_int64(
        json_object_get_int64(json_object_object_get(meta, "created_at"))));
    json_object_object_add(data, "expires_at", json_object_new_int64(
        json_object_get_int64(json_object_object_get(meta, "expires_at"))));
    return data;
}

struct json_object *webd_ai_attachment_create(struct json_object *body,
                                              const char *actor,
                                              int *http_status)
{
    const char *name = ai_json_string(body, "name",
                       ai_json_string(body, "filename", ""));
    const char *type = ai_json_string(body, "type", "text/plain");
    const char *content = ai_json_string(body, "content", "");
    size_t size = strlen(content);
    char id[37], data_path[512], meta_path[512], data_tmp[544], meta_tmp[544];
    struct json_object *meta;
    const char *serialized;
    int data_fd = -1, meta_fd = -1;
    int64_t now = (int64_t)time(NULL);

    if (http_status) *http_status = 400;
    if (!body || !actor || !actor[0] || !ai_value_ok(name, 255) ||
        !ai_value_ok(type, 127) ||
        (strncmp(type, "text/", 5) && strcmp(type, "application/json") &&
         strcmp(type, "application/xml") && strcmp(type, "application/yaml") &&
         strcmp(type, "application/x-yaml")))
        return ai_error("invalid_attachment", "Attachment name or MIME type is invalid",
                        400, 0, NULL, NULL);
    if (!size || size > AI_MAX_ATTACHMENT_BYTES) {
        if (http_status) *http_status = 413;
        return ai_error("attachment_too_large", "Attachment must contain 1 to 512 KiB",
                        413, 0, NULL, NULL);
    }
    ai_attachment_cleanup_expired();
    if (ai_attachment_dir_ready() != 0 || ai_attachment_id_generate(id) != 0) {
        if (http_status) *http_status = 500;
        return ai_error("attachment_storage_unavailable", "Attachment storage is unavailable",
                        500, 0, NULL, NULL);
    }
    ai_attachment_paths(id, data_path, sizeof(data_path), meta_path, sizeof(meta_path));
    snprintf(data_tmp, sizeof(data_tmp), "%s.tmp-%ld", data_path, (long)getpid());
    snprintf(meta_tmp, sizeof(meta_tmp), "%s.tmp-%ld", meta_path, (long)getpid());
    data_fd = open(data_tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (data_fd < 0 || ai_write_all(data_fd, content, size) != 0 ||
        fsync(data_fd) != 0 || close(data_fd) != 0) {
        if (data_fd >= 0) close(data_fd);
        unlink(data_tmp);
        if (http_status) *http_status = 500;
        return ai_error("attachment_storage_failed", "Could not store attachment",
                        500, 0, NULL, NULL);
    }
    data_fd = -1;
    meta = json_object_new_object();
    json_object_object_add(meta, "attachment_id", json_object_new_string(id));
    json_object_object_add(meta, "actor", json_object_new_string(actor));
    json_object_object_add(meta, "name", json_object_new_string(name));
    json_object_object_add(meta, "type", json_object_new_string(type));
    json_object_object_add(meta, "size", json_object_new_int64((int64_t)size));
    json_object_object_add(meta, "created_at", json_object_new_int64(now));
    json_object_object_add(meta, "expires_at", json_object_new_int64(now + AI_ATTACHMENT_TTL));
    serialized = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    meta_fd = open(meta_tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (meta_fd < 0 || !serialized || ai_write_all(meta_fd, serialized, strlen(serialized)) != 0 ||
        fsync(meta_fd) != 0) {
        if (meta_fd >= 0) close(meta_fd);
        unlink(data_tmp); unlink(meta_tmp); unlink(data_path); unlink(meta_path);
        json_object_put(meta);
        if (http_status) *http_status = 500;
        return ai_error("attachment_storage_failed", "Could not commit attachment",
                        500, 0, NULL, NULL);
    }
    if (close(meta_fd) != 0 || rename(data_tmp, data_path) != 0 ||
        rename(meta_tmp, meta_path) != 0) {
        meta_fd = -1;
        unlink(data_tmp); unlink(meta_tmp); unlink(data_path); unlink(meta_path);
        json_object_put(meta);
        if (http_status) *http_status = 500;
        return ai_error("attachment_storage_failed", "Could not commit attachment",
                        500, 0, NULL, NULL);
    }
    meta_fd = -1;
    if (http_status) *http_status = 201;
    struct json_object *result = ai_success(ai_attachment_public_meta(meta),
                                            "webd.ai.attachment");
    json_object_put(meta);
    return result;
}

struct json_object *webd_ai_attachment_get(const char *attachment_id,
                                           const char *actor,
                                           int *http_status)
{
    struct json_object *meta;
    int64_t now = (int64_t)time(NULL);
    if (http_status) *http_status = 404;
    if (!ai_attachment_id_ok(attachment_id)) {
        if (http_status) *http_status = 400;
        return ai_error("invalid_attachment_id", "Attachment ID is invalid", 400, 0, NULL, NULL);
    }
    meta = ai_attachment_meta_load(attachment_id);
    if (!meta || !ai_attachment_meta_owned(meta, actor) ||
        json_object_get_int64(json_object_object_get(meta, "expires_at")) <= now) {
        if (meta && json_object_get_int64(json_object_object_get(meta, "expires_at")) <= now)
            ai_attachment_remove_files(attachment_id);
        if (meta) json_object_put(meta);
        return ai_error("attachment_not_found", "Attachment was not found", 404, 0, NULL, NULL);
    }
    if (http_status) *http_status = 200;
    struct json_object *result = ai_success(ai_attachment_public_meta(meta),
                                            "webd.ai.attachment");
    json_object_put(meta);
    return result;
}

struct json_object *webd_ai_attachment_delete(const char *attachment_id,
                                              const char *actor,
                                              int *http_status)
{
    struct json_object *meta;
    if (http_status) *http_status = 404;
    if (!ai_attachment_id_ok(attachment_id)) {
        if (http_status) *http_status = 400;
        return ai_error("invalid_attachment_id", "Attachment ID is invalid", 400, 0, NULL, NULL);
    }
    meta = ai_attachment_meta_load(attachment_id);
    if (!meta || !ai_attachment_meta_owned(meta, actor)) {
        if (meta) json_object_put(meta);
        return ai_error("attachment_not_found", "Attachment was not found", 404, 0, NULL, NULL);
    }
    ai_attachment_remove_files(attachment_id);
    json_object_put(meta);
    if (http_status) *http_status = 200;
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "attachment_id", json_object_new_string(attachment_id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    return ai_success(data, "webd.ai.attachment");
}

static int ai_config_load(struct ai_config *cfg)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!cfg)
        return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->temperature = 0.7;
    cfg->max_tokens = 4096;
    snprintf(cfg->provider, sizeof(cfg->provider), "openai");
    snprintf(cfg->tool_policy, sizeof(cfg->tool_policy), "confirm_medium");
    snprintf(cfg->reasoning_effort, sizeof(cfg->reasoning_effort), "auto");
    snprintf(cfg->api_shape, sizeof(cfg->api_shape), "chat_completions");
    snprintf(cfg->auth_mode, sizeof(cfg->auth_mode), "api_key");
    if (sqlite3_open_v2(AI_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db,
        "SELECT enabled,provider,api_base,api_key,model,temperature,max_tokens,"
        "system_prompt,tool_policy,reasoning_effort,reasoning_api_shape,auth_mode "
        "FROM ai_config WHERE id=1",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_step(st) != SQLITE_ROW) {
        rc = 1;
        goto done;
    }
    cfg->enabled = sqlite3_column_int(st, 0) ? 1 : 0;
    snprintf(cfg->provider, sizeof(cfg->provider), "%s", ai_text(st, 1));
    snprintf(cfg->api_base, sizeof(cfg->api_base), "%s", ai_text(st, 2));
    snprintf(cfg->api_key, sizeof(cfg->api_key), "%s", ai_text(st, 3));
    snprintf(cfg->model, sizeof(cfg->model), "%s", ai_text(st, 4));
    cfg->temperature = sqlite3_column_double(st, 5);
    cfg->max_tokens = sqlite3_column_int(st, 6);
    snprintf(cfg->system_prompt, sizeof(cfg->system_prompt), "%s", ai_text(st, 7));
    snprintf(cfg->tool_policy, sizeof(cfg->tool_policy), "%s", ai_text(st, 8));
    snprintf(cfg->reasoning_effort, sizeof(cfg->reasoning_effort), "%s", ai_text(st, 9));
    snprintf(cfg->api_shape, sizeof(cfg->api_shape), "%s", ai_text(st, 10));
    snprintf(cfg->auth_mode, sizeof(cfg->auth_mode), "%s", ai_text(st, 11));
    rc = 0;
done:
    sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    if (rc == 0 && !strcmp(cfg->auth_mode, "oauth")) {
        int64_t expires_at = 0;

        memset(cfg->api_key, 0, sizeof(cfg->api_key));
        if (webd_ai_oauth_access_token(cfg->provider, cfg->api_key,
                                      sizeof(cfg->api_key), cfg->oauth_project,
                                      sizeof(cfg->oauth_project), &expires_at) != 0)
            cfg->api_key[0] = 0;
    }
    return rc;
}

static int ai_is_gemini(const struct ai_config *cfg)
{
    return cfg && (!strcasecmp(cfg->provider, "gemini") ||
                   !strcasecmp(cfg->provider, "google-gemini"));
}

static int ai_is_kimi(const struct ai_config *cfg)
{
    return cfg && (!strcasecmp(cfg->provider, "kimi") ||
                   !strcasecmp(cfg->provider, "kimi-code") ||
                   !strcasecmp(cfg->provider, "kimi_code"));
}

static int ai_is_openai_chatgpt_oauth(const struct ai_config *cfg)
{
    return cfg && !strcasecmp(cfg->provider, "openai") &&
           !strcmp(cfg->auth_mode, "oauth");
}

static int ai_uses_responses_shape(const struct ai_config *cfg)
{
    return ai_is_openai_chatgpt_oauth(cfg) ||
           (cfg && !strcmp(cfg->api_shape, "responses"));
}

static int ai_config_ready(const struct ai_config *cfg)
{
    return cfg && cfg->enabled && cfg->provider[0] && cfg->api_key[0] &&
           cfg->model[0] && (!strcasecmp(cfg->provider, "openai") ||
           !strcasecmp(cfg->provider, "openai-compatible") ||
           !strcasecmp(cfg->provider, "openai_compatible") ||
           !strcasecmp(cfg->provider, "deepseek") ||
           !strcasecmp(cfg->provider, "qwen") ||
           !strcasecmp(cfg->provider, "custom") ||
           !strcasecmp(cfg->provider, "anthropic") || ai_is_gemini(cfg) ||
           ai_is_kimi(cfg));
}

static int ai_url_ok(const char *url)
{
    return url && (!strncasecmp(url, "https://", 8) ||
                   !strncasecmp(url, "http://", 7));
}

/* ── Multi-provider dispatch ────────────────────────────────────────────────
 * ai_config remains the global default (temperature / max_tokens /
 * system_prompt / tool_policy). Per-provider credentials live in ai_provider,
 * and ai_dispatch_policy decides which of them a request actually uses.
 */
#define AI_DISPATCH_MAX_CANDIDATES 8

struct ai_dispatch_candidate {
    char id[65];
    struct ai_config cfg;
};

struct ai_dispatch_plan {
    char strategy[16];
    int failover_timeout_ms;
    int failover_max_attempts;
    int count;
    struct ai_dispatch_candidate items[AI_DISPATCH_MAX_CANDIDATES];
};

static void ai_dispatch_plan_clear(struct ai_dispatch_plan *plan)
{
    if (!plan)
        return;
    for (int i = 0; i < AI_DISPATCH_MAX_CANDIDATES; i++)
        memset(plan->items[i].cfg.api_key, 0, sizeof(plan->items[i].cfg.api_key));
    memset(plan, 0, sizeof(*plan));
}

/* Session-level defaults still come from ai_config; only the provider identity
 * and its credentials are overridden per candidate. */
static void ai_dispatch_apply_defaults(struct ai_config *cfg,
                                       const struct ai_config *defaults)
{
    cfg->temperature = defaults->temperature;
    cfg->max_tokens = defaults->max_tokens;
    snprintf(cfg->system_prompt, sizeof(cfg->system_prompt), "%s",
             defaults->system_prompt);
    snprintf(cfg->tool_policy, sizeof(cfg->tool_policy), "%s",
             defaults->tool_policy);
}

static void ai_dispatch_resolve_oauth(struct ai_config *cfg)
{
    if (strcmp(cfg->auth_mode, "oauth"))
        return;
    memset(cfg->api_key, 0, sizeof(cfg->api_key));
    if (webd_ai_oauth_access_token(cfg->provider, cfg->api_key,
                                   sizeof(cfg->api_key), cfg->oauth_project,
                                   sizeof(cfg->oauth_project), &(int64_t){0}) != 0)
        cfg->api_key[0] = 0;
}

static int ai_dispatch_weight_pick(sqlite3 *db, int total_weight)
{
    sqlite3_stmt *st = NULL;
    int cursor = 0;

    if (total_weight <= 0)
        return 0;
    if (sqlite3_prepare_v2(db, "SELECT lb_cursor FROM ai_dispatch_policy WHERE id=1",
                           -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        cursor = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    if (cursor < 0)
        cursor = 0;
    return cursor % total_weight;
}

/* The cursor must survive the request: webd forks per request, so an in-memory
 * counter would hand every request to the first provider. */
static void ai_dispatch_cursor_advance(void)
{
    sqlite3 *db = NULL;

    if (sqlite3_open_v2(AI_CONFIG_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return;
    sqlite3_busy_timeout(db, 3000);
    sqlite3_exec(db, "UPDATE ai_dispatch_policy SET lb_cursor=lb_cursor+1 WHERE id=1",
                 NULL, NULL, NULL);
    sqlite3_close(db);
}

/*
 * Build the ordered candidate list for this request.
 * Returns 0 with plan->count > 0 on success, 1 when no ai_provider rows exist
 * (caller falls back to the legacy single ai_config path), -1 on error.
 */
static int ai_dispatch_plan_load(struct ai_dispatch_plan *plan,
                                 const struct ai_config *defaults)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;
    int rows = 0;

    if (!plan || !defaults)
        return -1;
    ai_dispatch_plan_clear(plan);
    snprintf(plan->strategy, sizeof(plan->strategy), "single");
    plan->failover_timeout_ms = 20000;
    plan->failover_max_attempts = 2;

    if (sqlite3_open_v2(AI_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return -1;
    sqlite3_busy_timeout(db, 3000);

    if (sqlite3_prepare_v2(db,
        "SELECT strategy,failover_timeout_ms,failover_max_attempts "
        "FROM ai_dispatch_policy WHERE id=1", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        snprintf(plan->strategy, sizeof(plan->strategy), "%s", ai_text(st, 0));
        if (sqlite3_column_int(st, 1) > 0)
            plan->failover_timeout_ms = sqlite3_column_int(st, 1);
        if (sqlite3_column_int(st, 2) > 0)
            plan->failover_max_attempts = sqlite3_column_int(st, 2);
    }
    if (st) sqlite3_finalize(st);
    st = NULL;

    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ai_provider", -1, &st, NULL)
            == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        rows = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    st = NULL;
    if (rows == 0) {
        sqlite3_close(db);
        return 1;
    }

    if (!strcmp(plan->strategy, "single")) {
        if (sqlite3_prepare_v2(db,
            "SELECT id,provider,api_base,api_key,auth_mode,default_model,"
            "reasoning_effort,reasoning_api_shape FROM ai_provider "
            "WHERE enabled=1 AND role='primary' ORDER BY priority,id LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
            goto done;
    } else if (!strcmp(plan->strategy, "failover")) {
        if (sqlite3_prepare_v2(db,
            "SELECT id,provider,api_base,api_key,auth_mode,default_model,"
            "reasoning_effort,reasoning_api_shape FROM ai_provider "
            "WHERE enabled=1 ORDER BY priority,id LIMIT ?1",
            -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_int(st, 1, plan->failover_max_attempts > AI_DISPATCH_MAX_CANDIDATES ?
                                AI_DISPATCH_MAX_CANDIDATES : plan->failover_max_attempts);
    } else {
        /* load_balance: weighted round-robin over the enabled set, rotated by
         * the persisted cursor so consecutive requests really do spread out. */
        int total_weight = 0, offset = 0, seen = 0;

        if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(SUM(weight),0) FROM ai_provider WHERE enabled=1",
            -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
            total_weight = sqlite3_column_int(st, 0);
        if (st) sqlite3_finalize(st);
        st = NULL;
        if (total_weight <= 0) {
            rc = 0;
            goto done;
        }
        offset = ai_dispatch_weight_pick(db, total_weight);
        if (sqlite3_prepare_v2(db,
            "SELECT id,provider,api_base,api_key,auth_mode,default_model,"
            "reasoning_effort,reasoning_api_shape,weight FROM ai_provider "
            "WHERE enabled=1 ORDER BY priority,id", -1, &st, NULL) != SQLITE_OK)
            goto done;
        while (sqlite3_step(st) == SQLITE_ROW &&
               plan->count < AI_DISPATCH_MAX_CANDIDATES) {
            int weight = sqlite3_column_int(st, 8);
            if (weight < 1) weight = 1;
            /* Pick the bucket the cursor lands in first; remaining providers
             * stay in the list as fallbacks in priority order. */
            if (plan->count == 0 && seen + weight <= offset) {
                seen += weight;
                continue;
            }
            struct ai_dispatch_candidate *c = &plan->items[plan->count];
            memset(c, 0, sizeof(*c));
            snprintf(c->id, sizeof(c->id), "%s", ai_text(st, 0));
            snprintf(c->cfg.provider, sizeof(c->cfg.provider), "%s", ai_text(st, 1));
            snprintf(c->cfg.api_base, sizeof(c->cfg.api_base), "%s", ai_text(st, 2));
            snprintf(c->cfg.api_key, sizeof(c->cfg.api_key), "%s", ai_text(st, 3));
            snprintf(c->cfg.auth_mode, sizeof(c->cfg.auth_mode), "%s", ai_text(st, 4));
            snprintf(c->cfg.model, sizeof(c->cfg.model), "%s", ai_text(st, 5));
            snprintf(c->cfg.reasoning_effort, sizeof(c->cfg.reasoning_effort), "%s",
                     ai_text(st, 6));
            snprintf(c->cfg.api_shape, sizeof(c->cfg.api_shape), "%s", ai_text(st, 7));
            c->cfg.enabled = 1;
            ai_dispatch_apply_defaults(&c->cfg, defaults);
            ai_dispatch_resolve_oauth(&c->cfg);
            plan->count++;
        }
        sqlite3_finalize(st);
        st = NULL;
        ai_dispatch_cursor_advance();
        rc = 0;
        goto done;
    }

    while (sqlite3_step(st) == SQLITE_ROW &&
           plan->count < AI_DISPATCH_MAX_CANDIDATES) {
        struct ai_dispatch_candidate *c = &plan->items[plan->count];
        memset(c, 0, sizeof(*c));
        snprintf(c->id, sizeof(c->id), "%s", ai_text(st, 0));
        snprintf(c->cfg.provider, sizeof(c->cfg.provider), "%s", ai_text(st, 1));
        snprintf(c->cfg.api_base, sizeof(c->cfg.api_base), "%s", ai_text(st, 2));
        snprintf(c->cfg.api_key, sizeof(c->cfg.api_key), "%s", ai_text(st, 3));
        snprintf(c->cfg.auth_mode, sizeof(c->cfg.auth_mode), "%s", ai_text(st, 4));
        snprintf(c->cfg.model, sizeof(c->cfg.model), "%s", ai_text(st, 5));
        snprintf(c->cfg.reasoning_effort, sizeof(c->cfg.reasoning_effort), "%s",
                 ai_text(st, 6));
        snprintf(c->cfg.api_shape, sizeof(c->cfg.api_shape), "%s", ai_text(st, 7));
        c->cfg.enabled = 1;
        ai_dispatch_apply_defaults(&c->cfg, defaults);
        ai_dispatch_resolve_oauth(&c->cfg);
        plan->count++;
    }
    rc = 0;
done:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return rc;
}

/*
 * Which failures justify moving to the next provider.
 * 401/403 are deliberately excluded: a wrong key is a configuration error, and
 * failing over on it just burns the next provider's quota for the same reason.
 */
static int ai_dispatch_should_failover(const struct ai_result *result)
{
    if (!result)
        return 0;
    if (result->curl_code == CURLE_OPERATION_TIMEDOUT ||
        result->curl_code == CURLE_COULDNT_CONNECT ||
        result->curl_code == CURLE_COULDNT_RESOLVE_HOST ||
        result->curl_code == CURLE_SSL_CONNECT_ERROR ||
        result->curl_code == CURLE_PEER_FAILED_VERIFICATION)
        return 1;
    if (result->curl_code != CURLE_OK)
        return 0;
    if (result->provider_status == 401 || result->provider_status == 403)
        return 0;
    return result->provider_status == 429 || result->provider_status >= 500;
}

static const char *ai_dispatch_error_kind(const struct ai_result *result)
{
    if (!result)
        return "invalid_response";
    switch (result->curl_code) {
    case CURLE_OPERATION_TIMEDOUT: return "timeout";
    case CURLE_COULDNT_RESOLVE_HOST: return "dns_failed";
    case CURLE_COULDNT_CONNECT: return "tcp_refused";
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION: return "tls_failed";
    default: break;
    }
    if (result->curl_code != CURLE_OK)
        return "invalid_response";
    if (result->provider_status == 401) return "http_401";
    if (result->provider_status == 403) return "http_403";
    if (result->provider_status == 429) return "http_429";
    if (result->provider_status >= 500) return "http_5xx";
    if (result->provider_status >= 200 && result->provider_status < 300)
        return "invalid_response";
    return "invalid_response";
}

/*
 * Resolve the configuration a request should actually use.
 *
 * Order of precedence:
 *   1. ai_provider rows exist  -> dispatch policy decides (single/failover/lb)
 *   2. no ai_provider rows     -> legacy single ai_config row
 *
 * `plan` is filled so a caller that wants failover can walk the remaining
 * candidates; callers that only need one provider can ignore it.
 * Returns 0 when *cfg is usable, -1 when nothing is configured, and
 * -2 when providers exist but no enabled primary does (single strategy).
 */
static int ai_dispatch_select(struct ai_config *cfg,
                              struct ai_dispatch_plan *plan,
                              char provider_id[65])
{
    struct ai_config defaults;
    int load_rc, plan_rc;

    if (!cfg || !plan)
        return -1;
    if (provider_id) provider_id[0] = '\0';
    load_rc = ai_config_load(&defaults);
    if (load_rc < 0)
        return -1;
    plan_rc = ai_dispatch_plan_load(plan, &defaults);
    if (plan_rc == 1 || plan_rc < 0) {
        /* No provider table content: keep the historical single-config path. */
        ai_dispatch_plan_clear(plan);
        if (load_rc != 0 || !ai_config_ready(&defaults)) {
            memset(defaults.api_key, 0, sizeof(defaults.api_key));
            return -1;
        }
        *cfg = defaults;
        memset(defaults.api_key, 0, sizeof(defaults.api_key));
        return 0;
    }
    memset(defaults.api_key, 0, sizeof(defaults.api_key));
    if (plan->count == 0)
        return !strcmp(plan->strategy, "single") ? -2 : -1;
    /* For single there is exactly one legitimate answer, so an incomplete
     * primary is an error rather than a reason to use someone else. The other
     * strategies may skip a half-configured row and start at the next one. */
    if (!strcmp(plan->strategy, "single")) {
        *cfg = plan->items[0].cfg;
        if (provider_id)
            snprintf(provider_id, 65, "%s", plan->items[0].id);
        return ai_config_ready(cfg) ? 0 : -2;
    }
    for (int i = 0; i < plan->count; i++) {
        if (!ai_config_ready(&plan->items[i].cfg))
            continue;
        *cfg = plan->items[i].cfg;
        if (provider_id)
            snprintf(provider_id, 65, "%s", plan->items[i].id);
        return 0;
    }
    return -1;
}

static struct json_object *ai_dispatch_not_configured(int rc, int *http_status)
{
    if (rc == -2) {
        if (http_status) *http_status = 422;
        return ai_error("primary_required",
                        "dispatch strategy 'single' needs an enabled primary provider",
                        422, 0, NULL, NULL);
    }
    if (http_status) *http_status = 503;
    return ai_error("provider_not_configured",
                    "AI provider is disabled or incomplete", 503, 0, NULL, NULL);
}

/* Load one provider row by id, layered on the ai_config session defaults.
 * Returns 0 on success, -1 when the id does not exist. */

/*
 * webd links only WEBD_OBJS, which does not include jmx_netconfig_db.o, so the
 * jmx_ai_provider_* helpers are not callable from here. These two writes talk
 * to config.db directly, the same way the rest of this file already reads it.
 */
static int ai_provider_record_check(const char *id, int ok, int latency_ms,
                                    const char *error)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!id || !id[0])
        return -1;
    if (sqlite3_open_v2(AI_CONFIG_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return -1;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db,
        "UPDATE ai_provider SET last_check_ts=?2,last_check_ok=?3,"
        "last_check_latency_ms=?4,last_check_error=?5 WHERE id=?1",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
    sqlite3_bind_int(st, 3, ok ? 1 : 0);
    sqlite3_bind_int(st, 4, latency_ms);
    sqlite3_bind_text(st, 5, error ? error : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
done:
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    return rc;
}

static int ai_provider_cache_models(const char *id, struct json_object *models)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;
    sqlite3_int64 now = (sqlite3_int64)time(NULL);

    if (!id || !id[0] || !models || !json_object_is_type(models, json_type_array))
        return -1;
    if (sqlite3_open_v2(AI_CONFIG_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return -1;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        goto close_db;
    if (sqlite3_prepare_v2(db, "DELETE FROM ai_provider_model WHERE provider_id=?1",
                           -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    for (size_t i = 0; i < json_object_array_length(models); i++) {
        struct json_object *item = json_object_array_get_idx(models, i);
        const char *model_id = item && json_object_is_type(item, json_type_string) ?
                               json_object_get_string(item) : NULL;
        if (!model_id || !model_id[0])
            continue;
        if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO ai_provider_model"
            "(provider_id,model_id,display_name,synced_at) VALUES(?1,?2,'',?3)",
            -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, model_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, now);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto rollback;
        sqlite3_finalize(st);
        st = NULL;
    }
    rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    goto close_db;
rollback:
    if (st) sqlite3_finalize(st);
    st = NULL;
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
close_db:
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    return rc;
}

static int ai_provider_config_by_id(const char *id, struct ai_config *cfg)
{
    struct ai_config defaults;
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!id || !id[0] || !cfg)
        return -1;
    memset(cfg, 0, sizeof(*cfg));
    if (ai_config_load(&defaults) < 0)
        return -1;
    if (sqlite3_open_v2(AI_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db,
        "SELECT provider,api_base,api_key,auth_mode,default_model,"
        "reasoning_effort,reasoning_api_shape,enabled FROM ai_provider WHERE id=?1",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    snprintf(cfg->provider, sizeof(cfg->provider), "%s", ai_text(st, 0));
    snprintf(cfg->api_base, sizeof(cfg->api_base), "%s", ai_text(st, 1));
    snprintf(cfg->api_key, sizeof(cfg->api_key), "%s", ai_text(st, 2));
    snprintf(cfg->auth_mode, sizeof(cfg->auth_mode), "%s", ai_text(st, 3));
    snprintf(cfg->model, sizeof(cfg->model), "%s", ai_text(st, 4));
    snprintf(cfg->reasoning_effort, sizeof(cfg->reasoning_effort), "%s", ai_text(st, 5));
    snprintf(cfg->api_shape, sizeof(cfg->api_shape), "%s", ai_text(st, 6));
    /* A disabled provider can still be tested; dispatch is what honors
     * `enabled`. Testing before enabling is the normal setup order. */
    cfg->enabled = 1;
    ai_dispatch_apply_defaults(cfg, &defaults);
    ai_dispatch_resolve_oauth(cfg);
    rc = 0;
done:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    memset(defaults.api_key, 0, sizeof(defaults.api_key));
    return rc;
}

static int ai_ends_with(const char *s, const char *suffix)
{
    size_t n = s ? strlen(s) : 0, m = suffix ? strlen(suffix) : 0;
    return n >= m && !strcmp(s + n - m, suffix);
}

static void ai_default_base(const struct ai_config *cfg, char *out, size_t out_len)
{
    const char *base = cfg->api_base;
    if (ai_is_openai_chatgpt_oauth(cfg)) {
        base = AI_OPENAI_CHATGPT_BASE;
    } else if (!base[0]) {
        if (!strcasecmp(cfg->provider, "anthropic"))
            base = "https://api.anthropic.com/v1";
        else if (ai_is_gemini(cfg))
            base = "https://generativelanguage.googleapis.com/v1beta";
        else if (ai_is_kimi(cfg))
            base = "https://api.kimi.com/coding/v1";
        else if (!strcasecmp(cfg->provider, "deepseek"))
            base = "https://api.deepseek.com/v1";
        else if (!strcasecmp(cfg->provider, "qwen"))
            base = "https://dashscope.aliyuncs.com/compatible-mode/v1";
        else
            base = "https://api.openai.com/v1";
    }
    snprintf(out, out_len, "%s", base);
    while (out[0] && out[strlen(out) - 1] == '/')
        out[strlen(out) - 1] = 0;
}

static int ai_endpoint(const struct ai_config *cfg, const char *kind,
                       char *out, size_t out_len)
{
    char base[640];
    char *p;

    ai_default_base(cfg, base, sizeof(base));
    if (!ai_url_ok(base))
        return -1;
    if (ai_is_gemini(cfg) && (!strcmp(kind, "chat") ||
                              !strcmp(kind, "stream"))) {
        const char *model = cfg->model;
        const char *operation = !strcmp(kind, "stream") ?
                                "streamGenerateContent?alt=sse" :
                                "generateContent";

        if (!strncmp(model, "models/", 7))
            model += 7;
        if (!model[0] || strpbrk(model, "?#\\\r\n") ||
            snprintf(out, out_len, "%s/models/%s:%s", base, model,
                     operation) >= (int)out_len)
            return -1;
        return 0;
    }
    if (!strcmp(kind, "chat") || !strcmp(kind, "stream")) {
        const char *suffix = !strcasecmp(cfg->provider, "anthropic") ?
                             "/messages" :
                             (ai_uses_responses_shape(cfg) ?
                              "/responses" : "/chat/completions");
        const char *known[] = {
            "/chat/completions", "/responses", "/messages", NULL
        };
        for (int i = 0; known[i]; i++) {
            if ((p = strstr(base, known[i])) && p[strlen(known[i])] == 0) {
                if (!strcmp(known[i], suffix))
                    break;
                *p = 0;
                break;
            }
        }
        if (ai_ends_with(base, suffix))
            snprintf(out, out_len, "%s", base);
        else
            snprintf(out, out_len, "%s%s", base, suffix);
        return strlen(out) < out_len ? 0 : -1;
    }
    {
        const char *known[] = {
            "/chat/completions", "/responses", "/messages", "/models", NULL
        };
        for (int i = 0; known[i]; i++) {
            if ((p = strstr(base, known[i])) && p[strlen(known[i])] == 0) {
                *p = 0;
                break;
            }
        }
        if (ai_is_openai_chatgpt_oauth(cfg))
            snprintf(out, out_len, "%s/models?client_version=0.144.1", base);
        else
            snprintf(out, out_len, "%s/models", base);
        return strlen(out) < out_len ? 0 : -1;
    }
}

static int ai_secret_line(const char *line)
{
    static const char *needles[] = {
        "authorization:", "bearer ", "api_key", "apikey", "token=",
        "password", "passwd", "cookie:", "private key", "secret", "otp=", NULL
    };
    for (int i = 0; line && needles[i]; i++) {
        const char *p = line;
        size_t n = strlen(needles[i]);
        while (*p) {
            if (!strncasecmp(p, needles[i], n)) return 1;
            p++;
        }
    }
    return 0;
}

static char *ai_redact_text(const char *src, size_t limit)
{
    size_t len = src ? strnlen(src, limit + 1) : 0;
    char *out;
    size_t start = 0, n = 0;

    if (len > limit)
        return NULL;
    out = calloc(1, len + 64);
    if (!out)
        return NULL;
    if (src && ai_contains_i(src, "-----BEGIN") &&
        ai_contains_i(src, "PRIVATE KEY-----")) {
        snprintf(out, len + 64, "[REDACTED PRIVATE KEY]");
        return out;
    }
    for (size_t i = 0; i <= len; i++) {
        if (i == len || src[i] == '\n') {
            size_t line_len = i - start;
            char *line = strndup(src + start, line_len);
            if (!line) { free(out); return NULL; }
            if (ai_secret_line(line))
                n += (size_t)snprintf(out + n, len + 64 - n,
                                      "%s", "[REDACTED SECRET LINE]");
            else if (line_len) {
                memcpy(out + n, line, line_len);
                n += line_len;
            }
            free(line);
            if (i < len) out[n++] = '\n';
            start = i + 1;
        }
    }
    out[n] = 0;
    return out;
}

static int ai_text_append(char **dst, size_t *len, const char *src, size_t src_len)
{
    char *next;
    if (!dst || !len || !src || src_len > AI_MAX_PROMPT_BYTES ||
        *len > AI_MAX_PROMPT_BYTES - src_len)
        return -1;
    next = realloc(*dst, *len + src_len + 1);
    if (!next) return -1;
    memcpy(next + *len, src, src_len);
    *len += src_len;
    next[*len] = 0;
    *dst = next;
    return 0;
}

static int ai_add_message(struct json_object *messages, const char *role,
                          const char *content, size_t *total,
                          struct json_object **last_user)
{
    struct json_object *message;
    char *redacted;
    size_t len;

    if (strcmp(role, "system") && strcmp(role, "developer") &&
        strcmp(role, "user") && strcmp(role, "assistant"))
        return -1;
    len = content ? strnlen(content, AI_MAX_MESSAGE_BYTES + 1) : 0;
    if (len > AI_MAX_MESSAGE_BYTES || *total > AI_MAX_PROMPT_BYTES - len)
        return -2;
    redacted = ai_redact_text(content ? content : "", AI_MAX_MESSAGE_BYTES);
    if (!redacted) return -2;
    message = json_object_new_object();
    json_object_object_add(message, "role", json_object_new_string(role));
    json_object_object_add(message, "content", json_object_new_string(redacted));
    free(redacted);
    json_object_array_add(messages, message);
    *total += len;
    if (!strcmp(role, "user") && last_user)
        *last_user = message;
    return 0;
}

static int ai_prepare_messages(const struct ai_config *cfg, struct json_object *body,
                               const char *actor,
                               struct json_object **out, size_t *prompt_bytes,
                               char *error, size_t error_len)
{
    struct json_object *input = NULL, *attachments = NULL;
    struct json_object *messages = json_object_new_array();
    struct json_object *last_user = NULL;
    size_t total = 0, attachment_total = 0;
    int count = 0;

    if (!messages) return -1;
    if (cfg->system_prompt[0] &&
        ai_add_message(messages, "system", cfg->system_prompt, &total, NULL) != 0)
        goto too_large;
    if (body && json_object_object_get_ex(body, "messages", &input) && input) {
        if (!json_object_is_type(input, json_type_array)) {
            snprintf(error, error_len, "messages must be an array");
            goto invalid;
        }
        count = json_object_array_length(input);
        if (count <= 0 || count > AI_MAX_MESSAGES) {
            snprintf(error, error_len, "messages must contain 1-%d items", AI_MAX_MESSAGES);
            goto invalid;
        }
        for (int i = 0; i < count; i++) {
            struct json_object *item = json_object_array_get_idx(input, i);
            const char *role = ai_json_string(item, "role", "");
            const char *content = ai_json_string(item, "content", "");
            int rc;
            if (!item || !json_object_is_type(item, json_type_object) || !role[0]) {
                snprintf(error, error_len, "each message requires role and string content");
                goto invalid;
            }
            rc = ai_add_message(messages, role, content, &total, &last_user);
            if (rc == -1) {
                snprintf(error, error_len, "unsupported message role");
                goto invalid;
            }
            if (rc != 0) goto too_large;
        }
    } else {
        const char *message = ai_json_string(body, "message", "");
        if (!message[0]) {
            snprintf(error, error_len, "messages or message is required");
            goto invalid;
        }
        if (ai_add_message(messages, "user", message, &total, &last_user) != 0)
            goto too_large;
    }
    if (body && json_object_object_get_ex(body, "attachments", &attachments) && attachments) {
        char *extra = NULL;
        size_t extra_len = 0;
        if (!json_object_is_type(attachments, json_type_array) ||
            json_object_array_length(attachments) > AI_MAX_ATTACHMENTS) {
            snprintf(error, error_len, "attachments must contain at most %d items",
                     AI_MAX_ATTACHMENTS);
            goto invalid;
        }
        for (int i = 0; i < json_object_array_length(attachments); i++) {
            struct json_object *item = json_object_array_get_idx(attachments, i);
            const char *attachment_id = ai_json_string(item, "attachment_id", "");
            const char *name = ai_json_string(item, "name", "attachment.txt");
            const char *type = ai_json_string(item, "type", "text/plain");
            const char *content = ai_json_string(item, "content", "");
            struct json_object *stored_meta = NULL;
            char *stored_content = NULL;
            size_t len;
            char header[384];
            char *redacted;
            int header_len;
            if (attachment_id[0]) {
                stored_meta = ai_attachment_meta_load(attachment_id);
                if (!stored_meta || !ai_attachment_meta_owned(stored_meta, actor) ||
                    json_object_get_int64(json_object_object_get(stored_meta, "expires_at")) <=
                        (int64_t)time(NULL) ||
                    !(stored_content = ai_attachment_content_load(attachment_id, stored_meta, &len))) {
                    if (stored_meta) json_object_put(stored_meta);
                    free(extra);
                    snprintf(error, error_len, "attachment_id is invalid, expired, or unavailable");
                    goto invalid;
                }
                name = ai_json_string(stored_meta, "name", "attachment.txt");
                type = ai_json_string(stored_meta, "type", "text/plain");
                content = stored_content;
            } else {
                len = strnlen(content, AI_MAX_ATTACHMENT_BYTES + 1);
            }
            if (!item || !json_object_is_type(item, json_type_object) ||
                (strncmp(type, "text/", 5) && strcmp(type, "application/json") &&
                 strcmp(type, "application/xml") && strcmp(type, "application/yaml") &&
                 strcmp(type, "application/x-yaml"))) {
                free(stored_content);
                if (stored_meta) json_object_put(stored_meta);
                free(extra);
                snprintf(error, error_len, "attachment MIME type is not supported");
                goto invalid;
            }
            if (len > AI_MAX_ATTACHMENT_BYTES ||
                len > AI_MAX_ATTACHMENTS_TOTAL ||
                attachment_total > AI_MAX_ATTACHMENTS_TOTAL - len) {
                free(stored_content);
                if (stored_meta) json_object_put(stored_meta);
                free(extra);
                goto too_large;
            }
            redacted = ai_redact_text(content, AI_MAX_ATTACHMENT_BYTES);
            if (!redacted) {
                free(stored_content);
                if (stored_meta) json_object_put(stored_meta);
                free(extra);
                goto too_large;
            }
            header_len = snprintf(header, sizeof(header),
                                  "\n\n[Attachment %d: %s; %s]\n", i + 1, name, type);
            if (header_len < 0 || (size_t)header_len >= sizeof(header) ||
                ai_text_append(&extra, &extra_len, header, (size_t)header_len) != 0 ||
                ai_text_append(&extra, &extra_len, redacted, strlen(redacted)) != 0) {
                free(redacted);
                free(stored_content);
                if (stored_meta) json_object_put(stored_meta);
                free(extra);
                goto too_large;
            }
            free(redacted);
            free(stored_content);
            if (stored_meta) json_object_put(stored_meta);
            attachment_total += len;
        }
        if (extra_len) {
            struct json_object *content_obj = NULL;
            const char *current = "";
            char *combined = NULL;
            size_t combined_len = 0;
            if (!last_user) {
                if (ai_add_message(messages, "user", "Please analyze the attachments.",
                                   &total, &last_user) != 0) {
                    free(extra); goto too_large;
                }
            }
            json_object_object_get_ex(last_user, "content", &content_obj);
            if (content_obj) current = json_object_get_string(content_obj);
            if (ai_text_append(&combined, &combined_len, current, strlen(current)) != 0 ||
                ai_text_append(&combined, &combined_len, extra, extra_len) != 0) {
                free(extra); free(combined); goto too_large;
            }
            json_object_object_add(last_user, "content", json_object_new_string(combined));
            total += attachment_total;
            free(combined);
        }
        free(extra);
    }
    if (total > AI_MAX_PROMPT_BYTES) goto too_large;
    *out = messages;
    if (prompt_bytes) *prompt_bytes = total;
    return 0;
too_large:
    snprintf(error, error_len, "AI prompt or attachment payload exceeds the configured limit");
invalid:
    json_object_put(messages);
    return -1;
}

static size_t ai_http_write(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct ai_buffer *buf = opaque;
    size_t bytes = size * nmemb, need;
    char *next;
    if (!buf || !ptr || !bytes) return bytes;
    if (bytes > AI_MAX_RESPONSE_BYTES || buf->len > AI_MAX_RESPONSE_BYTES - bytes)
        return 0;
    need = buf->len + bytes + 1;
    if (need > buf->cap) {
        size_t cap = buf->cap ? buf->cap : 4096;
        while (cap < need && cap <= AI_MAX_RESPONSE_BYTES / 2) cap *= 2;
        if (cap < need) cap = need;
        next = realloc(buf->data, cap);
        if (!next) return 0;
        buf->data = next;
        buf->cap = cap;
    }
    memcpy(buf->data + buf->len, ptr, bytes);
    buf->len += bytes;
    buf->data[buf->len] = 0;
    return bytes;
}

static int ai_sse_capture_line(struct ai_sse_capture *capture,
                               const char *line, size_t len)
{
    struct json_object *event = NULL;
    const char *type;

    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    if (len < 5 || strncmp(line, "data:", 5)) return 0;
    line += 5;
    len -= 5;
    while (len && (*line == ' ' || *line == '\t')) { line++; len--; }
    if (!len || (len == 6 && !memcmp(line, "[DONE]", 6))) return 0;
    {
        struct json_tokener *tok = json_tokener_new();
        if (!tok) return -1;
        event = json_tokener_parse_ex(tok, line, (int)len);
        if (json_tokener_get_error(tok) != json_tokener_success) {
            if (event) json_object_put(event);
            event = NULL;
        }
        json_tokener_free(tok);
    }
    if (!event) return 0;
    type = ai_json_string(event, "type", "");
    if (!strcmp(type, "response.completed")) {
        struct json_object *response = NULL;
        if (json_object_object_get_ex(event, "response", &response) && response) {
            if (capture->completed) json_object_put(capture->completed);
            capture->completed = json_object_get(response);
        }
    } else if (!strcmp(type, "response.failed") || !strcmp(type, "error")) {
        if (capture->error) json_object_put(capture->error);
        capture->error = json_object_get(event);
    }
    json_object_put(event);
    return 0;
}

static size_t ai_sse_capture_write(char *ptr, size_t size, size_t nmemb,
                                   void *opaque)
{
    struct ai_sse_capture *capture = opaque;
    size_t bytes = size * nmemb, consumed = 0;
    char *next;

    if (!capture || !ptr || !bytes) return bytes;
    if (bytes > AI_MAX_RESPONSE_BYTES ||
        capture->pending_len > AI_MAX_RESPONSE_BYTES - bytes)
        return 0;
    next = realloc(capture->pending, capture->pending_len + bytes + 1);
    if (!next) return 0;
    capture->pending = next;
    memcpy(capture->pending + capture->pending_len, ptr, bytes);
    capture->pending_len += bytes;
    capture->pending[capture->pending_len] = 0;
    while (consumed < capture->pending_len) {
        char *newline = memchr(capture->pending + consumed, '\n',
                               capture->pending_len - consumed);
        size_t line_len;
        if (!newline) break;
        line_len = (size_t)(newline - (capture->pending + consumed));
        if (ai_sse_capture_line(capture, capture->pending + consumed,
                                line_len) != 0)
            return 0;
        consumed += line_len + 1;
    }
    if (consumed) {
        memmove(capture->pending, capture->pending + consumed,
                capture->pending_len - consumed);
        capture->pending_len -= consumed;
        capture->pending[capture->pending_len] = 0;
    }
    return bytes;
}

static void ai_provider_error(struct json_object *response, struct ai_result *result)
{
    struct json_object *error = NULL, *value = NULL;
    if (!response || !result || !json_object_object_get_ex(response, "error", &error) || !error)
        return;
    if (json_object_is_type(error, json_type_string)) {
        snprintf(result->provider_message, sizeof(result->provider_message), "%s",
                 json_object_get_string(error));
        return;
    }
    if (!json_object_is_type(error, json_type_object)) return;
    if (json_object_object_get_ex(error, "code", &value) && value)
        snprintf(result->provider_code, sizeof(result->provider_code), "%s",
                 json_object_get_string(value));
    if (json_object_object_get_ex(error, "type", &value) && value &&
        !result->provider_code[0])
        snprintf(result->provider_code, sizeof(result->provider_code), "%s",
                 json_object_get_string(value));
    if (json_object_object_get_ex(error, "message", &value) && value)
        snprintf(result->provider_message, sizeof(result->provider_message), "%s",
                 json_object_get_string(value));
}

static struct json_object *ai_http_json(const struct ai_config *cfg,
                                        const char *method, const char *url,
                                        const char *body, struct ai_result *result)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    struct ai_buffer buffer = {};
    struct ai_sse_capture sse = {};
    struct json_object *response = NULL;
    char auth[1200];
    int chatgpt_oauth = ai_is_openai_chatgpt_oauth(cfg);
    int chatgpt_sse = chatgpt_oauth && strcmp(method, "GET");

    result->provider_status = 0;
    result->curl_code = CURLE_OK;
    curl = curl_easy_init();
    if (!curl) return NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!strcasecmp(cfg->provider, "anthropic")) {
        snprintf(auth, sizeof(auth), !strcmp(cfg->auth_mode, "oauth") ?
                 "Authorization: Bearer %s" : "x-api-key: %s", cfg->api_key);
        headers = curl_slist_append(headers, auth);
        headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");
    } else if (ai_is_gemini(cfg) && strcmp(cfg->auth_mode, "oauth")) {
        snprintf(auth, sizeof(auth), "x-goog-api-key: %s", cfg->api_key);
        headers = curl_slist_append(headers, auth);
    } else {
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", cfg->api_key);
        headers = curl_slist_append(headers, auth);
        if (ai_is_gemini(cfg) && cfg->oauth_project[0]) {
            char project_header[256];
            snprintf(project_header, sizeof(project_header),
                     "x-goog-user-project: %s", cfg->oauth_project);
            headers = curl_slist_append(headers, project_header);
        }
    }
    if (chatgpt_oauth) {
        char account_header[256];
        headers = curl_slist_append(headers, chatgpt_sse ?
                                    "Accept: text/event-stream" :
                                    "Accept: application/json");
        if (chatgpt_sse)
            headers = curl_slist_append(headers,
                                        "OpenAI-Beta: responses=experimental");
        headers = curl_slist_append(headers,
                                    "Originator: " AI_OPENAI_CODEX_ORIGINATOR);
        if (!chatgpt_sse)
            headers = curl_slist_append(headers, "Version: 0.144.1");
        if (cfg->oauth_project[0]) {
            snprintf(account_header, sizeof(account_header),
                     "chatgpt-account-id: %s", cfg->oauth_project);
            headers = curl_slist_append(headers, account_header);
        }
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 45000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     chatgpt_oauth ?
                         AI_OPENAI_CODEX_USER_AGENT :
                         "dreamingwrt-webd/1.0 ai-runtime");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                     chatgpt_sse ?
                         ai_sse_capture_write : ai_http_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,
                     chatgpt_sse ?
                         (void *)&sse : (void *)&buffer);
    result->curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result->provider_status);
    if (chatgpt_sse) {
        response = sse.completed ? json_object_get(sse.completed) :
                   (sse.error ? json_object_get(sse.error) : NULL);
    } else if (buffer.data)
        response = json_tokener_parse(buffer.data);
    if (response)
        ai_provider_error(response, result);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    memset(auth, 0, sizeof(auth));
    free(buffer.data);
    free(sse.pending);
    if (sse.completed) json_object_put(sse.completed);
    if (sse.error) json_object_put(sse.error);
    return response;
}

static char *ai_content_text(struct json_object *content)
{
    char *out = NULL;
    size_t len = 0;
    if (!content) return NULL;
    if (json_object_is_type(content, json_type_string))
        return strdup(json_object_get_string(content));
    if (!json_object_is_type(content, json_type_array)) return NULL;
    for (int i = 0; i < json_object_array_length(content); i++) {
        struct json_object *item = json_object_array_get_idx(content, i);
        struct json_object *text = NULL, *type = NULL;
        if (!item || !json_object_is_type(item, json_type_object)) continue;
        json_object_object_get_ex(item, "type", &type);
        if (type && strcmp(json_object_get_string(type), "text") &&
            strcmp(json_object_get_string(type), "output_text")) continue;
        if (json_object_object_get_ex(item, "text", &text) && text) {
            const char *s = json_object_get_string(text);
            if (s && ai_text_append(&out, &len, s, strlen(s)) != 0) {
                free(out); return NULL;
            }
        }
    }
    return out;
}

static struct json_object *ai_usage(struct json_object *src, int anthropic)
{
    struct json_object *usage = json_object_new_object();
    struct json_object *v = NULL;
    int64_t prompt = 0, completion = 0, total = 0;
    if (src && json_object_object_get_ex(src,
        anthropic ? "input_tokens" : "prompt_tokens", &v) && v)
        prompt = json_object_get_int64(v);
    if (src && json_object_object_get_ex(src,
        anthropic ? "output_tokens" : "completion_tokens", &v) && v)
        completion = json_object_get_int64(v);
    if (src && json_object_object_get_ex(src, "total_tokens", &v) && v)
        total = json_object_get_int64(v);
    if (!total) total = prompt + completion;
    json_object_object_add(usage, "prompt_tokens", json_object_new_int64(prompt));
    json_object_object_add(usage, "completion_tokens", json_object_new_int64(completion));
    json_object_object_add(usage, "total_tokens", json_object_new_int64(total));
    return usage;
}

static struct json_object *ai_usage_gemini(struct json_object *src)
{
    struct json_object *usage = json_object_new_object();
    int64_t prompt = src ? json_object_get_int64(
        json_object_object_get(src, "promptTokenCount")) : 0;
    int64_t completion = src ? json_object_get_int64(
        json_object_object_get(src, "candidatesTokenCount")) : 0;
    int64_t total = src ? json_object_get_int64(
        json_object_object_get(src, "totalTokenCount")) : 0;

    if (!total) total = prompt + completion;
    json_object_object_add(usage, "prompt_tokens",
                           json_object_new_int64(prompt));
    json_object_object_add(usage, "completion_tokens",
                           json_object_new_int64(completion));
    json_object_object_add(usage, "total_tokens", json_object_new_int64(total));
    return usage;
}

static struct json_object *ai_gemini_contents(struct json_object *messages,
                                              char **system_out)
{
    struct json_object *contents = json_object_new_array();
    char *system = NULL;
    size_t system_len = 0;

    for (int i = 0; messages && i < json_object_array_length(messages); i++) {
        struct json_object *item = json_object_array_get_idx(messages, i);
        struct json_object *parts = NULL, *content = NULL, *dst;
        const char *role = ai_json_string(item, "role", "");

        if (!strcmp(role, "system") || !strcmp(role, "developer")) {
            const char *text = ai_json_string(item, "content", "");
            if (system_len) ai_text_append(&system, &system_len, "\n\n", 2);
            ai_text_append(&system, &system_len, text, strlen(text));
            continue;
        }
        dst = json_object_new_object();
        json_object_object_add(dst, "role", json_object_new_string(
            !strcmp(role, "assistant") || !strcmp(role, "model") ?
            "model" : "user"));
        if (json_object_object_get_ex(item, "parts", &parts) && parts &&
            json_object_is_type(parts, json_type_array)) {
            json_object_object_add(dst, "parts", json_object_get(parts));
        } else {
            struct json_object *out_parts = json_object_new_array();
            struct json_object *part = json_object_new_object();
            const char *text = "";

            if (json_object_object_get_ex(item, "content", &content) && content)
                text = json_object_is_type(content, json_type_string) ?
                       json_object_get_string(content) :
                       json_object_to_json_string_ext(content,
                                                      JSON_C_TO_STRING_PLAIN);
            json_object_object_add(part, "text", json_object_new_string(text));
            json_object_array_add(out_parts, part);
            json_object_object_add(dst, "parts", out_parts);
        }
        json_object_array_add(contents, dst);
    }
    *system_out = system;
    return contents;
}

static struct json_object *ai_anthropic_messages(struct json_object *messages,
                                                 char **system_out)
{
    struct json_object *out = json_object_new_array();
    char *system = NULL;
    size_t system_len = 0;
    for (int i = 0; i < json_object_array_length(messages); i++) {
        struct json_object *item = json_object_array_get_idx(messages, i);
        const char *role = ai_json_string(item, "role", "");
        const char *content = ai_json_string(item, "content", "");
        if (!strcmp(role, "system") || !strcmp(role, "developer")) {
            if (system_len) ai_text_append(&system, &system_len, "\n\n", 2);
            ai_text_append(&system, &system_len, content, strlen(content));
        } else {
            struct json_object *copy = json_object_new_object();
            struct json_object *content_obj = NULL;
            json_object_object_add(copy, "role", json_object_new_string(
                !strcmp(role, "assistant") ? "assistant" : "user"));
            if (json_object_object_get_ex(item, "content", &content_obj) && content_obj &&
                (json_object_is_type(content_obj, json_type_array) ||
                 json_object_is_type(content_obj, json_type_object)))
                json_object_object_add(copy, "content", json_object_get(content_obj));
            else
                json_object_object_add(copy, "content", json_object_new_string(content));
            json_object_array_add(out, copy);
        }
    }
    *system_out = system;
    return out;
}

static struct json_object *ai_openai_codex_input(struct json_object *messages,
                                                 char **instructions_out)
{
    struct json_object *input = json_object_new_array();
    char *instructions = NULL;
    size_t instructions_len = 0;

    if (!input) return NULL;
    for (int i = 0; messages && i < json_object_array_length(messages); i++) {
        struct json_object *item = json_object_array_get_idx(messages, i);
        const char *role = ai_json_string(item, "role", "");
        const char *content = ai_json_string(item, "content", "");

        if (!role[0]) {
            /* Preserve Responses-native function_call/function_call_output
             * items added by the audited tool loop. */
            json_object_array_add(input, json_object_get(item));
            continue;
        }
        if (!strcmp(role, "system") || !strcmp(role, "developer")) {
            if (content[0]) {
                if (instructions_len && ai_text_append(
                        &instructions, &instructions_len, "\n\n", 2) != 0)
                    goto fail;
                if (ai_text_append(&instructions, &instructions_len, content,
                                   strlen(content)) != 0)
                    goto fail;
            }
            continue;
        }
        {
            struct json_object *copy = json_object_new_object();
            if (!copy) goto fail;
            json_object_object_add(copy, "role", json_object_new_string(
                !strcmp(role, "assistant") ? "assistant" : "user"));
            json_object_object_add(copy, "content",
                                   json_object_new_string(content));
            json_object_array_add(input, copy);
        }
    }
    if (!instructions || !instructions[0]) {
        free(instructions);
        instructions = strdup("You are a helpful assistant.");
        if (!instructions) goto fail;
    }
    *instructions_out = instructions;
    return input;
fail:
    free(instructions);
    json_object_put(input);
    return NULL;
}

static struct json_object *ai_core_data(struct json_object *response)
{
    struct json_object *code = NULL, *data = NULL;
    if (!response || !json_object_object_get_ex(response, "code", &code) || !code ||
        json_object_get_int(code) != 2000 ||
        !json_object_object_get_ex(response, "data", &data) || !data)
        return NULL;
    return data;
}

static struct json_object *ai_response_data(struct json_object *response)
{
    struct json_object *data = NULL;
    if (!response || !json_object_object_get_ex(response, "data", &data) || !data ||
        !json_object_is_type(data, json_type_object))
        return NULL;
    return data;
}

static struct json_object *ai_tools_openai(const struct ai_config *cfg,
                                           int responses_shape)
{
    struct json_object *upstream = jmx_app_core_invoke("ai_tools_get", NULL, 2000);
    struct json_object *data = ai_core_data(upstream), *registered = NULL;
    struct json_object *tools = json_object_new_array();
    if (!tools) goto done;
    if (!data || !json_object_object_get_ex(data, "tools", &registered) || !registered ||
        !json_object_is_type(registered, json_type_array)) goto done;
    for (int i = 0; i < json_object_array_length(registered); i++) {
        struct json_object *tool = json_object_array_get_idx(registered, i);
        struct json_object *enabled = NULL, *parameters = NULL;
        const char *name = ai_json_string(tool, "name", "");
        const char *description = ai_json_string(tool, "description", "");
        const char *risk = ai_json_string(tool, "risk_level", "blocked");
        if (json_object_object_get_ex(tool, "enabled", &enabled) && enabled &&
            !json_object_get_boolean(enabled)) continue;
        if (!name[0] || !strcmp(risk, "blocked")) continue;
        if (!strcmp(cfg->tool_policy, "read_only") && strcmp(risk, "low")) continue;
        json_object_object_get_ex(tool, "parameters", &parameters);
        struct json_object *entry = json_object_new_object();
        if (responses_shape) {
            json_object_object_add(entry, "type", json_object_new_string("function"));
            json_object_object_add(entry, "name", json_object_new_string(name));
            json_object_object_add(entry, "description", json_object_new_string(description));
            json_object_object_add(entry, "parameters", parameters ? json_object_get(parameters) :
                                                          json_object_new_object());
            json_object_object_add(entry, "strict", json_object_new_boolean(0));
        } else {
            struct json_object *function = json_object_new_object();
            json_object_object_add(entry, "type", json_object_new_string("function"));
            json_object_object_add(function, "name", json_object_new_string(name));
            json_object_object_add(function, "description", json_object_new_string(description));
            json_object_object_add(function, "parameters", parameters ? json_object_get(parameters) :
                                                             json_object_new_object());
            json_object_object_add(entry, "function", function);
        }
        json_object_array_add(tools, entry);
    }
done:
    if (upstream) json_object_put(upstream);
    return tools;
}

static struct json_object *ai_tools_anthropic(const struct ai_config *cfg)
{
    struct json_object *openai = ai_tools_openai(cfg, 1);
    struct json_object *tools = json_object_new_array();
    if (!tools) { if (openai) json_object_put(openai); return NULL; }
    for (int i = 0; openai && i < json_object_array_length(openai); i++) {
        struct json_object *src = json_object_array_get_idx(openai, i);
        struct json_object *parameters = NULL, *dst = json_object_new_object();
        json_object_object_get_ex(src, "parameters", &parameters);
        json_object_object_add(dst, "name", json_object_new_string(ai_json_string(src, "name", "")));
        json_object_object_add(dst, "description", json_object_new_string(
            ai_json_string(src, "description", "")));
        json_object_object_add(dst, "input_schema", parameters ? json_object_get(parameters) :
                                                    json_object_new_object());
        json_object_array_add(tools, dst);
    }
    if (openai) json_object_put(openai);
    return tools;
}

static struct json_object *ai_tools_gemini(const struct ai_config *cfg)
{
    struct json_object *openai = ai_tools_openai(cfg, 1);
    struct json_object *tools = json_object_new_array();
    struct json_object *wrapper = json_object_new_object();
    struct json_object *declarations = json_object_new_array();

    if (!tools || !wrapper || !declarations) goto fail;
    for (int i = 0; openai && i < json_object_array_length(openai); i++) {
        struct json_object *src = json_object_array_get_idx(openai, i);
        struct json_object *parameters = NULL, *dst = json_object_new_object();

        json_object_object_get_ex(src, "parameters", &parameters);
        json_object_object_add(dst, "name", json_object_new_string(
            ai_json_string(src, "name", "")));
        json_object_object_add(dst, "description", json_object_new_string(
            ai_json_string(src, "description", "")));
        json_object_object_add(dst, "parameters", parameters ?
                               json_object_get(parameters) :
                               json_object_new_object());
        json_object_array_add(declarations, dst);
    }
    if (json_object_array_length(declarations) > 0) {
        json_object_object_add(wrapper, "functionDeclarations", declarations);
        json_object_array_add(tools, wrapper);
    } else {
        json_object_put(declarations);
        json_object_put(wrapper);
    }
    if (openai) json_object_put(openai);
    return tools;

fail:
    if (openai) json_object_put(openai);
    if (tools) json_object_put(tools);
    if (wrapper) json_object_put(wrapper);
    if (declarations) json_object_put(declarations);
    return NULL;
}

static struct json_object *ai_tool_call_normalize(const struct ai_config *cfg,
                                                   struct json_object *tool,
                                                   int index)
{
    struct json_object *normalized = json_object_new_object();
    struct json_object *function = NULL, *args_obj = NULL;
    const char *id = "", *name = "", *args_text = "{}";
    char generated[96];

    if (!tool || !normalized) return normalized;
    if (ai_is_gemini(cfg)) {
        struct json_object *args = NULL;
        id = ai_json_string(tool, "id", "");
        name = ai_json_string(tool, "name", "");
        if (json_object_object_get_ex(tool, "args", &args) && args &&
            json_object_is_type(args, json_type_object))
            args_text = json_object_to_json_string_ext(args,
                                                       JSON_C_TO_STRING_PLAIN);
    } else if (!strcasecmp(cfg->provider, "anthropic")) {
        id = ai_json_string(tool, "id", "");
        name = ai_json_string(tool, "name", "");
        if (json_object_object_get_ex(tool, "input", &args_obj) && args_obj &&
            json_object_is_type(args_obj, json_type_object))
            args_text = json_object_to_json_string_ext(args_obj, JSON_C_TO_STRING_PLAIN);
    } else if (ai_uses_responses_shape(cfg)) {
        id = ai_json_string(tool, "call_id", ai_json_string(tool, "id", ""));
        name = ai_json_string(tool, "name", "");
        args_text = ai_json_string(tool, "arguments", "{}");
    } else {
        id = ai_json_string(tool, "id", "");
        if (json_object_object_get_ex(tool, "function", &function) && function) {
            name = ai_json_string(function, "name", "");
            args_text = ai_json_string(function, "arguments", "{}");
        }
    }
    if (!id[0]) {
        snprintf(generated, sizeof(generated), "tool-%lld-%d", (long long)ai_now_ms(), index);
        id = generated;
    }
    args_obj = args_text && args_text[0] ? json_tokener_parse(args_text) : NULL;
    int arguments_valid = args_obj && json_object_is_type(args_obj, json_type_object);
    if (!args_obj || !json_object_is_type(args_obj, json_type_object)) {
        if (args_obj) json_object_put(args_obj);
        args_obj = json_object_new_object();
    }
    json_object_object_add(normalized, "tool_call_id", json_object_new_string(id));
    json_object_object_add(normalized, "tool", json_object_new_string(name));
    json_object_object_add(normalized, "parameters", args_obj);
    json_object_object_add(normalized, "arguments_valid",
                           json_object_new_boolean(arguments_valid));
    json_object_object_add(normalized, "provider_call", json_object_get(tool));
    return normalized;
}

static struct json_object *ai_execute_tool_call(const struct ai_config *cfg,
                                                struct json_object *tool,
                                                const char *conversation_id,
                                                const char *actor,
                                                int index,
                                                size_t *tool_result_bytes)
{
    struct json_object *normalized = ai_tool_call_normalize(cfg, tool, index);
    struct json_object *request = json_object_new_object();
    struct json_object *params = NULL;
    struct json_object *arguments_valid = NULL;
    const char *tool_name = ai_json_string(normalized, "tool", "");
    const char *call_id = ai_json_string(normalized, "tool_call_id", "");
    json_object_object_get_ex(normalized, "parameters", &params);
    json_object_object_get_ex(normalized, "arguments_valid", &arguments_valid);
    if (!tool_name[0] || !arguments_valid || !json_object_get_boolean(arguments_valid)) {
        json_object_put(request);
        json_object_object_add(normalized, "execution",
                               ai_error("invalid_tool_arguments",
                                        "Provider tool arguments are not a valid JSON object",
                                        400, 0, NULL, NULL));
        return normalized;
    }
    json_object_object_add(request, "tool", json_object_new_string(tool_name));
    json_object_object_add(request, "tool_call_id", json_object_new_string(call_id));
    json_object_object_add(request, "conversation_id", json_object_new_string(
        conversation_id ? conversation_id : ""));
    json_object_object_add(request, "actor", json_object_new_string(actor ? actor : "web"));
    json_object_object_add(request, "parameters", params ? json_object_get(params) :
                                                    json_object_new_object());
    struct json_object *response = jmx_app_core_invoke("ai_tool_call", request, 10000);
    json_object_put(request);
    if (response) {
        const char *serialized = json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN);
        size_t bytes = serialized ? strlen(serialized) : 0;
        if (!serialized || bytes > AI_MAX_TOOL_RESULT_BYTES || !tool_result_bytes ||
            *tool_result_bytes > AI_MAX_TOOL_RESULTS_TOTAL - bytes) {
            json_object_put(response);
            response = ai_error("tool_result_too_large",
                                "Tool result exceeded the model feedback limit",
                                413, 0, NULL, NULL);
        } else {
            *tool_result_bytes += bytes;
        }
    }
    json_object_object_add(normalized, "execution", response ? response :
                           ai_error("tool_source_unavailable", "AI tool source is unavailable",
                                    503, 0, NULL, NULL));
    return normalized;
}

static void ai_tool_execution_collect(struct json_object *execution,
                                      struct json_object *executed,
                                      struct json_object *pending)
{
    struct json_object *response = NULL, *data = NULL;
    const char *status = "execution_failed";
    if (execution) json_object_object_get_ex(execution, "execution", &response);
    data = ai_core_data(response);
    if (data) status = ai_json_string(data, "status", status);
    if (!strcmp(status, "pending_authorization"))
        json_object_array_add(pending, json_object_get(execution));
    else
        json_object_array_add(executed, json_object_get(execution));
}

static void ai_append_tool_feedback(const struct ai_config *cfg,
                                    struct json_object *messages,
                                    struct json_object *provider_calls,
                                    struct json_object *executions)
{
    if (ai_is_gemini(cfg)) {
        struct json_object *model = json_object_new_object();
        struct json_object *model_parts = json_object_new_array();
        struct json_object *user = json_object_new_object();
        struct json_object *user_parts = json_object_new_array();

        for (int i = 0; i < json_object_array_length(provider_calls); i++) {
            struct json_object *part = json_object_new_object();
            json_object_object_add(part, "functionCall", json_object_get(
                json_object_array_get_idx(provider_calls, i)));
            json_object_array_add(model_parts, part);
        }
        for (int i = 0; i < json_object_array_length(executions); i++) {
            struct json_object *execution = json_object_array_get_idx(executions, i);
            struct json_object *response = NULL, *part = json_object_new_object();
            struct json_object *function_response = json_object_new_object();
            struct json_object *payload = json_object_new_object();

            json_object_object_get_ex(execution, "execution", &response);
            json_object_object_add(payload, "result", response ?
                                   json_object_get(response) :
                                   json_object_new_string("tool_source_unavailable"));
            json_object_object_add(function_response, "name", json_object_new_string(
                ai_json_string(execution, "tool", "")));
            json_object_object_add(function_response, "response", payload);
            json_object_object_add(part, "functionResponse", function_response);
            json_object_array_add(user_parts, part);
        }
        json_object_object_add(model, "role", json_object_new_string("model"));
        json_object_object_add(model, "parts", model_parts);
        json_object_object_add(user, "role", json_object_new_string("user"));
        json_object_object_add(user, "parts", user_parts);
        json_object_array_add(messages, model);
        json_object_array_add(messages, user);
    } else if (!strcasecmp(cfg->provider, "anthropic")) {
        struct json_object *assistant = json_object_new_object();
        struct json_object *user = json_object_new_object();
        struct json_object *results = json_object_new_array();
        json_object_object_add(assistant, "role", json_object_new_string("assistant"));
        json_object_object_add(assistant, "content", json_object_get(provider_calls));
        json_object_array_add(messages, assistant);
        for (int i = 0; i < json_object_array_length(executions); i++) {
            struct json_object *execution = json_object_array_get_idx(executions, i);
            struct json_object *response = NULL;
            const char *call_id = ai_json_string(execution, "tool_call_id", "");
            json_object_object_get_ex(execution, "execution", &response);
            struct json_object *block = json_object_new_object();
            json_object_object_add(block, "type", json_object_new_string("tool_result"));
            json_object_object_add(block, "tool_use_id", json_object_new_string(call_id));
            json_object_object_add(block, "content", json_object_new_string(
                response ? json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN) :
                           "{\"error\":\"tool_source_unavailable\"}"));
            json_object_array_add(results, block);
        }
        json_object_object_add(user, "role", json_object_new_string("user"));
        json_object_object_add(user, "content", results);
        json_object_array_add(messages, user);
    } else if (ai_uses_responses_shape(cfg)) {
        for (int i = 0; i < json_object_array_length(provider_calls); i++)
            json_object_array_add(messages, json_object_get(json_object_array_get_idx(provider_calls, i)));
        for (int i = 0; i < json_object_array_length(executions); i++) {
            struct json_object *execution = json_object_array_get_idx(executions, i);
            struct json_object *response = NULL, *output = json_object_new_object();
            json_object_object_get_ex(execution, "execution", &response);
            json_object_object_add(output, "type", json_object_new_string("function_call_output"));
            json_object_object_add(output, "call_id", json_object_new_string(
                ai_json_string(execution, "tool_call_id", "")));
            json_object_object_add(output, "output", json_object_new_string(
                response ? json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN) :
                           "{\"error\":\"tool_source_unavailable\"}"));
            json_object_array_add(messages, output);
        }
    } else {
        struct json_object *assistant = json_object_new_object();
        json_object_object_add(assistant, "role", json_object_new_string("assistant"));
        json_object_object_add(assistant, "content", json_object_new_string(""));
        json_object_object_add(assistant, "tool_calls", json_object_get(provider_calls));
        json_object_array_add(messages, assistant);
        for (int i = 0; i < json_object_array_length(executions); i++) {
            struct json_object *execution = json_object_array_get_idx(executions, i);
            struct json_object *response = NULL, *tool_result = json_object_new_object();
            json_object_object_get_ex(execution, "execution", &response);
            json_object_object_add(tool_result, "role", json_object_new_string("tool"));
            json_object_object_add(tool_result, "tool_call_id", json_object_new_string(
                ai_json_string(execution, "tool_call_id", "")));
            json_object_object_add(tool_result, "content", json_object_new_string(
                response ? json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN) :
                           "{\"error\":\"tool_source_unavailable\"}"));
            json_object_array_add(messages, tool_result);
        }
    }
}

static struct json_object *ai_parse_chat_response(const struct ai_config *cfg,
                                                  struct json_object *response,
                                                  struct ai_result *result)
{
    struct json_object *data = NULL, *usage_src = NULL, *finish = NULL;
    struct json_object *tool_calls = json_object_new_array();
    char *reply = NULL;
    size_t reply_len = 0;

    if (!response || !json_object_is_type(response, json_type_object)) goto fail;
    if (ai_is_gemini(cfg)) {
        struct json_object *candidates = NULL, *candidate = NULL;
        struct json_object *content = NULL, *parts = NULL;

        if (!json_object_object_get_ex(response, "candidates", &candidates) ||
            !candidates || !json_object_is_type(candidates, json_type_array) ||
            !(candidate = json_object_array_get_idx(candidates, 0)) ||
            !json_object_object_get_ex(candidate, "content", &content) ||
            !content || !json_object_object_get_ex(content, "parts", &parts) ||
            !parts || !json_object_is_type(parts, json_type_array))
            goto fail;
        for (int i = 0; i < json_object_array_length(parts); i++) {
            struct json_object *part = json_object_array_get_idx(parts, i);
            struct json_object *text = NULL, *function_call = NULL;

            if (json_object_object_get_ex(part, "text", &text) && text) {
                const char *value = json_object_get_string(text);
                if (value && ai_text_append(&reply, &reply_len, value,
                                            strlen(value)) != 0)
                    goto fail;
            }
            if (json_object_object_get_ex(part, "functionCall", &function_call) &&
                function_call && json_object_is_type(function_call, json_type_object))
                json_object_array_add(tool_calls, json_object_get(function_call));
        }
        json_object_object_get_ex(response, "usageMetadata", &usage_src);
        json_object_object_get_ex(candidate, "finishReason", &finish);
    } else if (!strcasecmp(cfg->provider, "anthropic")) {
        struct json_object *content = NULL;
        if (!json_object_object_get_ex(response, "content", &content)) goto fail;
        reply = ai_content_text(content);
        json_object_object_get_ex(response, "usage", &usage_src);
        json_object_object_get_ex(response, "stop_reason", &finish);
        if (content && json_object_is_type(content, json_type_array)) {
            for (int i = 0; i < json_object_array_length(content); i++) {
                struct json_object *item = json_object_array_get_idx(content, i);
                if (!strcmp(ai_json_string(item, "type", ""), "tool_use"))
                    json_object_array_add(tool_calls, json_object_get(item));
            }
        }
    } else if (ai_uses_responses_shape(cfg)) {
        struct json_object *text = NULL, *output = NULL;
        if (json_object_object_get_ex(response, "output_text", &text) && text)
            reply = strdup(json_object_get_string(text));
        if (json_object_object_get_ex(response, "output", &output) && output &&
            json_object_is_type(output, json_type_array)) {
            for (int i = 0; i < json_object_array_length(output); i++) {
                struct json_object *item = json_object_array_get_idx(output, i), *content = NULL;
                if (!strcmp(ai_json_string(item, "type", ""), "function_call"))
                    json_object_array_add(tool_calls, json_object_get(item));
                if (!reply && json_object_object_get_ex(item, "content", &content))
                    reply = ai_content_text(content);
            }
        }
        json_object_object_get_ex(response, "usage", &usage_src);
        json_object_object_get_ex(response, "status", &finish);
    } else {
        struct json_object *choices = NULL, *choice = NULL, *message = NULL, *content = NULL;
        struct json_object *provider_tools = NULL;
        if (!json_object_object_get_ex(response, "choices", &choices) || !choices ||
            !json_object_is_type(choices, json_type_array) ||
            !(choice = json_object_array_get_idx(choices, 0)) ||
            !json_object_object_get_ex(choice, "message", &message) || !message)
            goto fail;
        if (json_object_object_get_ex(message, "content", &content))
            reply = ai_content_text(content);
        if (json_object_object_get_ex(message, "tool_calls", &provider_tools) &&
            provider_tools && json_object_is_type(provider_tools, json_type_array)) {
            json_object_put(tool_calls);
            tool_calls = json_object_get(provider_tools);
        }
        json_object_object_get_ex(response, "usage", &usage_src);
        json_object_object_get_ex(choice, "finish_reason", &finish);
    }
    if (!reply && json_object_array_length(tool_calls) == 0) goto fail;
    data = json_object_new_object();
    json_object_object_add(data, "reply", json_object_new_string(reply ? reply : ""));
    json_object_object_add(data, "model", json_object_new_string(cfg->model));
    json_object_object_add(data, "provider", json_object_new_string(cfg->provider));
    json_object_object_add(data, "reasoning_effort",
                           json_object_new_string(cfg->reasoning_effort));
    json_object_object_add(data, "finish_reason", json_object_new_string(
        finish ? json_object_get_string(finish) : "stop"));
    json_object_object_add(data, "usage", ai_is_gemini(cfg) ?
                           ai_usage_gemini(usage_src) :
                           ai_usage(usage_src,
                           !strcasecmp(cfg->provider, "anthropic") ||
                           ai_uses_responses_shape(cfg)));
    json_object_object_add(data, "tool_calls", tool_calls);
    json_object_object_add(data, "pending_authorizations", json_object_new_array());
    json_object_object_add(data, "tool_execution_supported", json_object_new_boolean(0));
    free(reply);
    return data;
fail:
    free(reply);
    json_object_put(tool_calls);
    snprintf(result->provider_code, sizeof(result->provider_code),
             "provider_response_invalid");
    return NULL;
}

static struct json_object *ai_call_chat(const struct ai_config *cfg,
                                        struct json_object *messages,
                                        int max_tokens_override,
                                        struct ai_result *result)
{
    struct json_object *request = json_object_new_object();
    struct json_object *response = NULL, *data = NULL;
    char endpoint[768];
    const char *body;
    int max_tokens = max_tokens_override > 0 ? max_tokens_override : cfg->max_tokens;

    if (!request || ai_endpoint(cfg, "chat", endpoint, sizeof(endpoint)) != 0)
        goto done;
    if (ai_is_gemini(cfg)) {
        char *system = NULL;
        struct json_object *contents = ai_gemini_contents(messages, &system);
        struct json_object *generation = json_object_new_object();
        struct json_object *tools = max_tokens_override > 0 ?
                                    json_object_new_array() :
                                    ai_tools_gemini(cfg);

        json_object_object_add(request, "contents", contents);
        if (system && system[0]) {
            struct json_object *instruction = json_object_new_object();
            struct json_object *parts = json_object_new_array();
            struct json_object *part = json_object_new_object();
            json_object_object_add(part, "text", json_object_new_string(system));
            json_object_array_add(parts, part);
            json_object_object_add(instruction, "parts", parts);
            json_object_object_add(request, "systemInstruction", instruction);
        }
        free(system);
        json_object_object_add(generation, "maxOutputTokens",
                               json_object_new_int(max_tokens));
        if (cfg->temperature >= 0 && cfg->temperature <= 2)
            json_object_object_add(generation, "temperature",
                                   json_object_new_double(cfg->temperature));
        json_object_object_add(request, "generationConfig", generation);
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
    } else if (!strcasecmp(cfg->provider, "anthropic")) {
        json_object_object_add(request, "model", json_object_new_string(cfg->model));
        char *system = NULL;
        struct json_object *converted = ai_anthropic_messages(messages, &system);
        struct json_object *tools = max_tokens_override > 0 ? json_object_new_array() :
                                                            ai_tools_anthropic(cfg);
        json_object_object_add(request, "messages", converted);
        json_object_object_add(request, "max_tokens", json_object_new_int(max_tokens));
        if (system && system[0])
            json_object_object_add(request, "system", json_object_new_string(system));
        free(system);
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
        if (cfg->temperature >= 0 && cfg->temperature <= 1)
            json_object_object_add(request, "temperature",
                                   json_object_new_double(cfg->temperature));
    } else if (ai_uses_responses_shape(cfg)) {
        json_object_object_add(request, "model", json_object_new_string(cfg->model));
        struct json_object *tools = max_tokens_override > 0 ? json_object_new_array() :
                                                            ai_tools_openai(cfg, 1);
        if (ai_is_openai_chatgpt_oauth(cfg)) {
            char *instructions = NULL;
            struct json_object *input = ai_openai_codex_input(
                messages, &instructions);
            if (!input || !instructions) {
                if (input) json_object_put(input);
                free(instructions);
                goto done;
            }
            json_object_object_add(request, "input", input);
            json_object_object_add(request, "instructions",
                                   json_object_new_string(instructions));
            json_object_object_add(request, "store",
                                   json_object_new_boolean(0));
            json_object_object_add(request, "stream",
                                   json_object_new_boolean(1));
            free(instructions);
        } else {
            json_object_object_add(request, "input", json_object_get(messages));
            json_object_object_add(request, "max_output_tokens",
                                   json_object_new_int(max_tokens));
        }
        if (cfg->reasoning_effort[0] && strcmp(cfg->reasoning_effort, "auto") &&
            strcmp(cfg->reasoning_effort, "none")) {
            struct json_object *reasoning = json_object_new_object();
            json_object_object_add(reasoning, "effort",
                                   json_object_new_string(cfg->reasoning_effort));
            json_object_object_add(request, "reasoning", reasoning);
        }
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
    } else {
        json_object_object_add(request, "model", json_object_new_string(cfg->model));
        struct json_object *tools = max_tokens_override > 0 ? json_object_new_array() :
                                                            ai_tools_openai(cfg, 0);
        json_object_object_add(request, "messages", json_object_get(messages));
        json_object_object_add(request, "max_tokens", json_object_new_int(max_tokens));
        if (cfg->temperature >= 0 && cfg->temperature <= 2 &&
            strncasecmp(cfg->model, "o1", 2) && strncasecmp(cfg->model, "o3", 2) &&
            strncasecmp(cfg->model, "o4", 2) && strncasecmp(cfg->model, "gpt-5", 5))
            json_object_object_add(request, "temperature",
                                   json_object_new_double(cfg->temperature));
        if ((!strcasecmp(cfg->provider, "openai") ||
             !strcasecmp(cfg->provider, "openai-compatible") ||
             !strcasecmp(cfg->provider, "openai_compatible") ||
             !strcasecmp(cfg->provider, "custom")) &&
            cfg->reasoning_effort[0] && strcmp(cfg->reasoning_effort, "auto") &&
            strcmp(cfg->reasoning_effort, "none"))
            json_object_object_add(request, "reasoning_effort",
                                   json_object_new_string(cfg->reasoning_effort));
        if (tools && json_object_array_length(tools) > 0) {
            json_object_object_add(request, "tools", tools);
            json_object_object_add(request, "tool_choice", json_object_new_string("auto"));
        } else if (tools) {
            json_object_put(tools);
        }
    }
    body = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);
    response = ai_http_json(cfg, "POST", endpoint, body, result);
    if (result->curl_code == CURLE_OK && result->provider_status >= 200 &&
        result->provider_status < 300)
        data = ai_parse_chat_response(cfg, response, result);
done:
    if (response) json_object_put(response);
    if (request) json_object_put(request);
    return data;
}

static void ai_degraded_add(struct json_object *data, const char *reason)
{
    struct json_object *reasons = NULL, *value = NULL;

    if (!data || !reason || !reason[0])
        return;
    json_object_object_del(data, "degraded");
    json_object_object_add(data, "degraded", json_object_new_boolean(1));
    if (!json_object_object_get_ex(data, "degraded_reason", &value) || !value)
        json_object_object_add(data, "degraded_reason",
                               json_object_new_string(reason));
    if (!json_object_object_get_ex(data, "degraded_reasons", &reasons) ||
        !reasons || !json_object_is_type(reasons, json_type_array)) {
        reasons = json_object_new_array();
        json_object_object_add(data, "degraded_reasons", reasons);
    }
    for (size_t i = 0; i < json_object_array_length(reasons); i++) {
        if (!strcmp(json_object_get_string(json_object_array_get_idx(reasons, i)),
                    reason))
            return;
    }
    json_object_array_add(reasons, json_object_new_string(reason));
}

static int ai_title_sensitive(const char *title)
{
    static const char *needles[] = {
        "password", "api_key", "bearer ", "authorization:", "private key",
        "ssh-rsa", "key=",
        "-----begin", "sk-", "ghp_", "github_pat_", "xoxb-", "akia",
        "[redacted", NULL
    };
    int upper = 0, lower = 0, digit = 0, run = 0;

    if (!title || !title[0] || ai_secret_line(title))
        return 1;
    for (int i = 0; needles[i]; i++)
        if (ai_contains_i(title, needles[i]))
            return 1;
    for (const unsigned char *p = (const unsigned char *)title; ; p++) {
        if (isalnum(*p) || *p == '+' || *p == '/' || *p == '_' || *p == '-') {
            run++;
            upper += isupper(*p) ? 1 : 0;
            lower += islower(*p) ? 1 : 0;
            digit += isdigit(*p) ? 1 : 0;
            continue;
        }
        if (run >= 24 && digit > 0 && upper > 0 && lower > 0)
            return 1;
        if (!*p)
            break;
        upper = lower = digit = run = 0;
    }
    return 0;
}

static int ai_title_normalize(const char *raw, char *out, size_t out_len)
{
    struct json_object *parsed = NULL;
    const char *source = raw;
    char *copy = NULL, *start, *end, *readp, *writep;
    size_t len;
    int has_word = 0;

    if (!raw || !out || out_len <= AI_CONVERSATION_TITLE_MAX_BYTES)
        return -1;
    while (*source && isspace((unsigned char)*source))
        source++;
    if (*source == '{') {
        parsed = json_tokener_parse(source);
        if (parsed && json_object_is_type(parsed, json_type_object)) {
            struct json_object *title = NULL;
            if (json_object_object_get_ex(parsed, "title", &title) && title &&
                json_object_is_type(title, json_type_string))
                source = json_object_get_string(title);
        }
    }
    copy = strdup(source ? source : "");
    if (!copy)
        goto invalid;
    start = copy;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (!strncasecmp(start, "title:", 6)) {
        start += 6;
        while (*start && isspace((unsigned char)*start))
            start++;
    }
    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
        *--end = 0;
    while (end > start && (*start == '"' || *start == '\'' || *start == '`' ||
                           *start == '#'))
        start++;
    end = start + strlen(start);
    while (end > start && (end[-1] == '"' || end[-1] == '\'' || end[-1] == '`' ||
                           end[-1] == '#'))
        *--end = 0;
    readp = start;
    writep = start;
    while (*readp) {
        unsigned char ch = (unsigned char)*readp++;
        if (ch < 0x20 || ch == 0x7f) {
            if (writep > start && writep[-1] != ' ')
                *writep++ = ' ';
            continue;
        }
        if (isspace(ch)) {
            if (writep > start && writep[-1] != ' ')
                *writep++ = ' ';
            continue;
        }
        if (isalnum(ch) || ch >= 0x80)
            has_word = 1;
        *writep++ = (char)ch;
    }
    while (writep > start && writep[-1] == ' ')
        writep--;
    *writep = 0;
    len = strlen(start);
    if (!has_word || !len || len > AI_CONVERSATION_TITLE_MAX_BYTES ||
        ai_title_sensitive(start))
        goto invalid;
    snprintf(out, out_len, "%s", start);
    free(copy);
    if (parsed)
        json_object_put(parsed);
    return 0;

invalid:
    free(copy);
    if (parsed)
        json_object_put(parsed);
    if (out && out_len)
        out[0] = 0;
    return -1;
}

static const char *ai_chat_last_user_text(struct json_object *body)
{
    struct json_object *messages = NULL;

    if (body && json_object_object_get_ex(body, "messages", &messages) && messages &&
        json_object_is_type(messages, json_type_array)) {
        for (int i = json_object_array_length(messages) - 1; i >= 0; i--) {
            struct json_object *item = json_object_array_get_idx(messages, i);
            if (!strcmp(ai_json_string(item, "role", ""), "user"))
                return ai_json_string(item, "content", "");
        }
    }
    return ai_json_string(body, "message", "");
}

static char *ai_redact_prefix(const char *text, size_t max_bytes)
{
    size_t len = text ? strnlen(text, max_bytes + 1) : 0;
    char *prefix;

    if (len > max_bytes) {
        len = max_bytes;
        while (len > 0 && ((unsigned char)text[len] & 0xc0) == 0x80)
            len--;
    }
    prefix = strndup(text ? text : "", len);
    if (!prefix)
        return NULL;
    static const char *title_only_secret_labels[] = {
        "\xE5\xAF\x86\xE7\xA0\x81", "\xE5\xAF\x86\xE9\x92\xA5",
        "\xE5\x8F\xA3\xE4\xBB\xA4", "\xE4\xBB\xA4\xE7\x89\x8C",
        "\xE5\x87\xAD\xE6\x8D\xAE", NULL
    };
    char *redacted;

    for (int i = 0; title_only_secret_labels[i]; i++) {
        if (strstr(prefix, title_only_secret_labels[i])) {
            free(prefix);
            return strdup("[SENSITIVE CREDENTIAL MANAGEMENT REQUEST]");
        }
    }
    redacted = ai_redact_text(prefix, max_bytes);
    free(prefix);
    return redacted;
}

static int ai_generate_conversation_title(const struct ai_config *cfg,
                                          struct json_object *body,
                                          const char *reply,
                                          char *title, size_t title_len)
{
    static const char system_prompt[] =
        "Generate one short Simplified Chinese conversation title. Return only the "
        "title, without quotes, markdown, labels, or explanations. Summarize the task; "
        "do not copy or reveal passwords, API keys, tokens, credentials, private keys, "
        "authentication headers, or other secrets. If sensitive data is present, use a "
        "generic description of the task instead. Keep it under 24 Chinese characters.";
    struct ai_config title_cfg;
    struct ai_result title_result = {};
    struct json_object *messages = json_object_new_array(), *data = NULL;
    const char *user = ai_chat_last_user_text(body);
    const char *raw_title;
    char *safe_user = NULL, *safe_reply = NULL, *context = NULL;
    size_t context_len = 0;
    size_t user_len, reply_len;
    int rc = -1;

    if (!cfg || !messages || !title || !title_len)
        goto done;
    safe_user = ai_redact_prefix(user,
        AI_CONVERSATION_TITLE_CONTEXT_BYTES / 2);
    safe_reply = ai_redact_prefix(reply,
        AI_CONVERSATION_TITLE_CONTEXT_BYTES / 2);
    user_len = safe_user ? strlen(safe_user) : 0;
    reply_len = safe_reply ? strlen(safe_reply) : 0;
    if (!safe_user || !safe_reply ||
        ai_text_append(&context, &context_len, "User request:\n", 14) != 0 ||
        ai_text_append(&context, &context_len, safe_user, user_len) != 0 ||
        ai_text_append(&context, &context_len, "\n\nAssistant response:\n", 22) != 0 ||
        ai_text_append(&context, &context_len, safe_reply, reply_len) != 0)
        goto done;
    {
        struct json_object *system = json_object_new_object();
        struct json_object *request = json_object_new_object();
        json_object_object_add(system, "role", json_object_new_string("system"));
        json_object_object_add(system, "content", json_object_new_string(system_prompt));
        json_object_object_add(request, "role", json_object_new_string("user"));
        json_object_object_add(request, "content", json_object_new_string(context));
        json_object_array_add(messages, system);
        json_object_array_add(messages, request);
    }
    title_cfg = *cfg;
    title_cfg.temperature = 0.2;
    snprintf(title_cfg.reasoning_effort, sizeof(title_cfg.reasoning_effort), "none");
    data = ai_call_chat(&title_cfg, messages, AI_CONVERSATION_TITLE_TOKENS,
                        &title_result);
    raw_title = data ? ai_json_string(data, "reply", "") : "";
    if (data && ai_title_normalize(raw_title, title, title_len) == 0)
        rc = 0;

done:
    free(safe_user);
    free(safe_reply);
    free(context);
    if (data)
        json_object_put(data);
    if (messages)
        json_object_put(messages);
    return rc;
}

static int ai_history_lookup(const char *conversation_id,
                             struct json_object **item_out)
{
    struct json_object *request = json_object_new_object(), *response = NULL;
    struct json_object *data = NULL, *item = NULL;
    int rc = -1;

    if (item_out)
        *item_out = NULL;
    if (!request)
        return -1;
    json_object_object_add(request, "id", json_object_new_string(conversation_id));
    response = jmx_app_core_invoke("ai_history_get", request, 3000);
    json_object_put(request);
    data = ai_core_data(response);
    if (data && json_object_object_get_ex(data, "item", &item) && item &&
        json_object_is_type(item, json_type_object)) {
        if (item_out)
            *item_out = json_object_get(item);
        rc = 1;
    } else {
        data = ai_response_data(response);
        if (data && !strcmp(ai_json_string(data, "error", ""), "not_found"))
            rc = 0;
    }
    if (response)
        json_object_put(response);
    return rc;
}

static struct json_object *ai_history_message_copy(struct json_object *source)
{
    struct json_object *copy = json_object_new_object(), *value = NULL;
    const char *role = ai_json_string(source, "role", "");

    if (!copy || (strcmp(role, "system") && strcmp(role, "user") &&
                  strcmp(role, "assistant") && strcmp(role, "tool"))) {
        if (copy)
            json_object_put(copy);
        return NULL;
    }
    json_object_object_add(copy, "role", json_object_new_string(role));
    json_object_object_add(copy, "content", json_object_new_string(
        ai_json_string(source, "content", "")));
    if (json_object_object_get_ex(source, "message_id", &value) && value &&
        json_object_is_type(value, json_type_string))
        json_object_object_add(copy, "message_id", json_object_get(value));
    else if (json_object_object_get_ex(source, "id", &value) && value &&
             json_object_is_type(value, json_type_string))
        json_object_object_add(copy, "message_id", json_object_get(value));
    if (json_object_object_get_ex(source, "created_at", &value) && value)
        json_object_object_add(copy, "created_at", json_object_get(value));
    if (json_object_object_get_ex(source, "attachments", &value) && value &&
        json_object_is_type(value, json_type_array))
        json_object_object_add(copy, "attachments", json_object_get(value));
    return copy;
}

static struct json_object *ai_history_messages(struct json_object *body,
                                               struct json_object *existing_item,
                                               const char *reply)
{
    struct json_object *input = NULL, *messages = json_object_new_array();
    struct json_object *last_user = NULL, *attachments = NULL;
    int body_has_messages = body && json_object_object_get_ex(body, "messages", &input) &&
                            input && json_object_is_type(input, json_type_array);

    if (!messages)
        return NULL;
    if (!body_has_messages && existing_item)
        json_object_object_get_ex(existing_item, "messages", &input);
    if (input && json_object_is_type(input, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(input); i++) {
            struct json_object *copy = ai_history_message_copy(
                json_object_array_get_idx(input, i));
            if (!copy)
                continue;
            if (!strcmp(ai_json_string(copy, "role", ""), "user"))
                last_user = copy;
            json_object_array_add(messages, copy);
        }
    }
    if (!body_has_messages) {
        const char *message = ai_json_string(body, "message", "");
        if (message[0]) {
            last_user = json_object_new_object();
            json_object_object_add(last_user, "role", json_object_new_string("user"));
            json_object_object_add(last_user, "content", json_object_new_string(message));
            json_object_object_add(last_user, "created_at",
                                   json_object_new_int64((int64_t)time(NULL)));
            json_object_array_add(messages, last_user);
        }
    }
    if (last_user && body && json_object_object_get_ex(body, "attachments", &attachments) &&
        attachments && json_object_is_type(attachments, json_type_array)) {
        struct json_object *safe = json_object_new_array();
        for (size_t i = 0; i < json_object_array_length(attachments); i++) {
            struct json_object *source = json_object_array_get_idx(attachments, i);
            struct json_object *meta = json_object_new_object(), *value = NULL;
            const char *name = ai_json_string(source, "name", "");
            if (!source || !json_object_is_type(source, json_type_object) || !name[0]) {
                json_object_put(meta);
                continue;
            }
            json_object_object_add(meta, "name", json_object_new_string(name));
            json_object_object_add(meta, "type", json_object_new_string(
                ai_json_string(source, "type", "text/plain")));
            if (json_object_object_get_ex(source, "size", &value) && value)
                json_object_object_add(meta, "size", json_object_get(value));
            else
                json_object_object_add(meta, "size", json_object_new_int64(0));
            if (json_object_object_get_ex(source, "attachment_id", &value) && value &&
                json_object_is_type(value, json_type_string))
                json_object_object_add(meta, "attachment_id", json_object_get(value));
            json_object_array_add(safe, meta);
        }
        json_object_object_add(last_user, "attachments", safe);
    }
    if (reply && reply[0]) {
        struct json_object *assistant = json_object_new_object();
        json_object_object_add(assistant, "role", json_object_new_string("assistant"));
        json_object_object_add(assistant, "content", json_object_new_string(reply));
        json_object_object_add(assistant, "created_at",
                               json_object_new_int64((int64_t)time(NULL)));
        json_object_array_add(messages, assistant);
    }
    return messages;
}

static int ai_history_save_chat(const struct ai_config *cfg,
                                const char *conversation_id,
                                const char *title,
                                struct json_object *body,
                                struct json_object *existing_item,
                                struct json_object *chat_data)
{
    struct json_object *request = json_object_new_object(), *response = NULL;
    struct json_object *messages = NULL, *usage = NULL, *data = NULL;
    const char *reply = ai_json_string(chat_data, "reply", "");
    int rc = -1;

    if (!request)
        return -1;
    messages = ai_history_messages(body, existing_item, reply);
    if (!messages)
        goto done;
    json_object_object_add(request, "id", json_object_new_string(conversation_id));
    json_object_object_add(request, "title", json_object_new_string(title));
    json_object_object_add(request, "model", json_object_new_string(cfg->model));
    json_object_object_add(request, "reasoning_effort",
                           json_object_new_string(cfg->reasoning_effort));
    if (json_object_object_get_ex(chat_data, "usage", &usage) && usage &&
        json_object_is_type(usage, json_type_object))
        json_object_object_add(request, "usage", json_object_get(usage));
    else
        json_object_object_add(request, "usage", json_object_new_object());
    json_object_object_add(request, "messages", messages);
    messages = NULL;
    response = jmx_app_core_invoke("ai_history_save", request, 5000);
    data = ai_core_data(response);
    if (data && json_object_get_boolean(json_object_object_get(data, "ok")))
        rc = 0;

done:
    if (messages)
        json_object_put(messages);
    if (response)
        json_object_put(response);
    json_object_put(request);
    return rc;
}

static int ai_history_has_assistant(struct json_object *item)
{
    struct json_object *messages = NULL;

    if (!item || !json_object_object_get_ex(item, "messages", &messages) ||
        !messages || !json_object_is_type(messages, json_type_array))
        return 0;
    for (size_t i = 0; i < json_object_array_length(messages); i++)
        if (!strcmp(ai_json_string(json_object_array_get_idx(messages, i),
                                   "role", ""), "assistant"))
            return 1;
    return 0;
}

static int ai_title_is_placeholder(const char *title)
{
    return !title || !title[0] || !strcmp(title, AI_CONVERSATION_TITLE_FALLBACK) ||
           !strcmp(title, "\xE6\x9C\xAA\xE5\x91\xBD\xE5\x90\x8D\xE5\xAF\xB9\xE8\xAF\x9D");
}

static void ai_conversation_lock_path(const char *conversation_id,
                                      char *path, size_t path_len)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    const unsigned char *p = (const unsigned char *)(conversation_id ?
                                                    conversation_id : "");

    for (; *p; p++) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    snprintf(path, path_len, "/tmp/dreamingwrt-ai-title-%02llx.lock",
             (unsigned long long)(hash & UINT64_C(63)));
}

static int ai_conversation_finalize(const struct ai_config *cfg,
                                    struct json_object *body,
                                    struct json_object *chat_data,
                                    const char *conversation_id)
{
    struct json_object *existing_item = NULL, *title_state = json_object_new_object();
    char title[AI_CONVERSATION_HISTORY_TITLE_MAX_BYTES + 1] =
        AI_CONVERSATION_TITLE_FALLBACK;
    char generated[AI_CONVERSATION_TITLE_MAX_BYTES + 1] = "";
    char lock_path[96];
    const char *status = "degraded", *reason = NULL;
    int lock_fd, lookup, save_ok = 0, history_save_failed = 0;

    ai_conversation_lock_path(conversation_id, lock_path, sizeof(lock_path));
    lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0)
            close(lock_fd);
        reason = "conversation_title_lock_failed";
        goto done;
    }
    lookup = ai_history_lookup(conversation_id, &existing_item);
    if (lookup < 0) {
        reason = "conversation_history_lookup_failed";
        goto unlock;
    }
    if (lookup > 0) {
        const char *existing_title = ai_json_string(existing_item, "title", "");
        int continuation = ai_history_has_assistant(existing_item);
        if (!ai_title_is_placeholder(existing_title) && existing_title[0] &&
            strlen(existing_title) <=
            AI_CONVERSATION_HISTORY_TITLE_MAX_BYTES &&
            !ai_title_sensitive(existing_title)) {
            snprintf(title, sizeof(title), "%s", existing_title);
            status = "preserved";
        } else if (ai_title_is_placeholder(existing_title) && continuation) {
            snprintf(title, sizeof(title), "%s",
                     AI_CONVERSATION_TITLE_FALLBACK);
            status = "preserved";
        } else if (ai_title_is_placeholder(existing_title) &&
                   ai_generate_conversation_title(cfg, body,
                       ai_json_string(chat_data, "reply", ""), generated,
                       sizeof(generated)) == 0) {
            snprintf(title, sizeof(title), "%s", generated);
            status = "generated";
        } else {
            snprintf(title, sizeof(title), "%s",
                     AI_CONVERSATION_TITLE_FALLBACK);
            status = "sanitized";
            reason = "conversation_existing_title_sensitive";
        }
    } else if (ai_generate_conversation_title(cfg, body,
               ai_json_string(chat_data, "reply", ""), generated,
               sizeof(generated)) == 0) {
        snprintf(title, sizeof(title), "%s", generated);
        status = "generated";
    } else {
        reason = "conversation_title_generation_failed";
    }
    save_ok = ai_history_save_chat(cfg, conversation_id, title, body,
                                   existing_item, chat_data) == 0;
    if (!save_ok) {
        history_save_failed = 1;
        status = "degraded";
        if (!reason)
            reason = "conversation_history_save_failed";
    }

unlock:
    flock(lock_fd, LOCK_UN);
    close(lock_fd);

done:
    json_object_object_add(chat_data, "conversation_title",
                           json_object_new_string(title));
    json_object_object_add(chat_data, "history_saved",
                           json_object_new_boolean(save_ok));
    if (title_state) {
        json_object_object_add(title_state, "status", json_object_new_string(status));
        json_object_object_add(title_state, "provider",
                               json_object_new_string(cfg->provider));
        json_object_object_add(title_state, "model", json_object_new_string(cfg->model));
        if (reason)
            json_object_object_add(title_state, "reason",
                                   json_object_new_string(reason));
        json_object_object_add(chat_data, "title_generation", title_state);
    }
    if (reason)
        ai_degraded_add(chat_data, reason);
    if (history_save_failed && strcmp(reason ? reason : "",
                                      "conversation_history_save_failed"))
        ai_degraded_add(chat_data, "conversation_history_save_failed");
    if (existing_item)
        json_object_put(existing_item);
    return save_ok ? 0 : -1;
}

static int ai_acquire_slot(void)
{
    char path[96];
    for (int i = 0; i < AI_MAX_CONCURRENT; i++) {
        int fd;
        snprintf(path, sizeof(path), "/tmp/dreamingwrt-ai-runtime.%d.lock", i);
        fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0)
            return fd;
        if (fd >= 0) close(fd);
    }
    return -1;
}

static int ai_rate_limited(const char *actor, const char *action)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int count = 0;
    if (sqlite3_open_v2(AI_AUDIT_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 1000);
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM api_audit_log WHERE ts>=?1 AND actor=?2 AND action=?3",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, (int64_t)time(NULL) - 60);
        sqlite3_bind_text(st, 2, actor ? actor : "web", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, action, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            count = sqlite3_column_int(st, 0);
    }
done:
    sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return count >= AI_MAX_REQUESTS_PER_MINUTE;
}

static void ai_audit(const char *actor, const char *action,
                     const struct ai_config *cfg, const char *target,
                     int64_t elapsed_ms, const char *result)
{
    char after[384];
    snprintf(after, sizeof(after),
             "provider=%s model=%s elapsed_ms=%lld status=%s prompt=redacted",
             cfg && cfg->provider[0] ? cfg->provider : "unavailable",
             cfg && cfg->model[0] ? cfg->model : "unavailable",
             (long long)elapsed_ms, result ? result : "unknown");
    jmx_app_audit_log(actor && actor[0] ? actor : "web", actor,
                      action, !strcmp(action, "ai.chat") ? "low" : "medium",
                      target ? target : "", "", after);
}

static const char *ai_error_code(const struct ai_result *result, int *status)
{
    const char *msg = result->provider_message;
    if (!strcmp(result->provider_code, "resume_storage_failed")) {
        *status = 507;
        return result->provider_code;
    }
    if (!strcmp(result->provider_code, "tool_result_too_large")) {
        *status = 413;
        return result->provider_code;
    }
    if (!strcmp(result->provider_code, "tool_arguments_too_large")) {
        *status = 413;
        return result->provider_code;
    }
    if (!strcmp(result->provider_code, "invalid_tool_arguments") ||
        !strcmp(result->provider_code, "provider_response_invalid")) {
        *status = 502;
        return result->provider_code;
    }
    if (!strcmp(result->provider_code, "tool_round_limit") ||
        !strcmp(result->provider_code, "too_many_tool_calls")) {
        *status = 409;
        return result->provider_code;
    }
    if (result->curl_code == CURLE_OPERATION_TIMEDOUT) {
        *status = 504; return "provider_timeout";
    }
    if (result->curl_code != CURLE_OK) {
        *status = 503; return "provider_unreachable";
    }
    if (result->provider_status == 401 || result->provider_status == 403) {
        *status = 502; return "provider_auth_failed";
    }
    if (result->provider_status == 404) {
        *status = 502; return "model_not_found";
    }
    if (result->provider_status == 429) {
        *status = 429; return "rate_limited";
    }
    if (result->provider_status == 413 ||
        (msg && (ai_contains_i(msg, "context_length") ||
                 ai_contains_i(msg, "context window") ||
                 ai_contains_i(msg, "too many tokens")))) {
        *status = 413; return "context_too_large";
    }
    *status = result->provider_status >= 500 ? 503 : 502;
    return "provider_error";
}

struct ai_stream_state {
    int fd;
    int sequence;
    int disconnected;
    int saw_event;
    int provider_failed;
    int cancelled;
    int gemini;
    char conversation_id[128];
    char response_id[128];
    char finish_reason[64];
    char *pending;
    size_t pending_len;
    char *reply;
    size_t reply_len;
    int64_t prompt_tokens;
    int64_t completion_tokens;
    int64_t total_tokens;
    struct json_object *tool_calls;
    struct json_object *tool_parts;
    struct ai_result *result;
    char active_path[256];
    char cancel_path[256];
};

static int ai_response_id_ok(const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len < 8 || len > 127) return 0;
    for (size_t i = 0; i < len; i++)
        if (!isalnum((unsigned char)value[i]) && value[i] != '-' &&
            value[i] != '_' && value[i] != '.')
            return 0;
    return 1;
}

static int ai_response_paths(const char *response_id,
                             char *active, size_t active_len,
                             char *cancel, size_t cancel_len)
{
    if (!ai_response_id_ok(response_id) ||
        (mkdir("/tmp/dreamingwrt", 0700) != 0 && errno != EEXIST) ||
        (mkdir(AI_RESPONSE_DIR, 0700) != 0 && errno != EEXIST))
        return -1;
    chmod(AI_RESPONSE_DIR, 0700);
    if (snprintf(active, active_len, "%s/%s.active", AI_RESPONSE_DIR,
                 response_id) >= (int)active_len ||
        snprintf(cancel, cancel_len, "%s/%s.cancel", AI_RESPONSE_DIR,
                 response_id) >= (int)cancel_len)
        return -1;
    return 0;
}

static int ai_response_register(struct ai_stream_state *state,
                                const char *actor)
{
    struct json_object *record;
    const char *json;
    int fd, rc = -1;
    if (!state || ai_response_paths(state->response_id,
        state->active_path, sizeof(state->active_path),
        state->cancel_path, sizeof(state->cancel_path)) != 0)
        return -1;
    unlink(state->cancel_path);
    fd = open(state->active_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    record = json_object_new_object();
    json_object_object_add(record, "response_id",
                           json_object_new_string(state->response_id));
    json_object_object_add(record, "conversation_id",
                           json_object_new_string(state->conversation_id));
    json_object_object_add(record, "actor",
                           json_object_new_string(actor ? actor : "web"));
    json_object_object_add(record, "pid", json_object_new_int64((int64_t)getpid()));
    json_object_object_add(record, "created_at",
                           json_object_new_int64((int64_t)time(NULL)));
    json = json_object_to_json_string_ext(record, JSON_C_TO_STRING_PLAIN);
    if (write(fd, json, strlen(json)) == (ssize_t)strlen(json) && fsync(fd) == 0)
        rc = 0;
    json_object_put(record);
    close(fd);
    if (rc != 0) unlink(state->active_path);
    return rc;
}

static void ai_response_unregister(struct ai_stream_state *state)
{
    if (!state) return;
    if (state->active_path[0]) unlink(state->active_path);
    if (state->cancel_path[0]) unlink(state->cancel_path);
}

static int ai_stream_progress(void *opaque, curl_off_t download_total,
                              curl_off_t download_now, curl_off_t upload_total,
                              curl_off_t upload_now)
{
    struct ai_stream_state *state = opaque;
    (void)download_total;
    (void)download_now;
    (void)upload_total;
    (void)upload_now;
    if (!state || state->disconnected) return 1;
    if (state->cancel_path[0] && access(state->cancel_path, F_OK) == 0) {
        state->cancelled = 1;
        return 1;
    }
    return 0;
}

static int ai_stream_write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int ai_stream_emit(struct ai_stream_state *state, const char *event,
                          struct json_object *payload)
{
    struct json_object *data;
    const char *json;
    char header[256];
    int hlen;

    if (!state || state->disconnected) return -1;
    data = payload ? json_object_get(payload) : json_object_new_object();
    json_object_object_add(data, "conversation_id",
                           json_object_new_string(state->conversation_id));
    json_object_object_add(data, "response_id",
                           json_object_new_string(state->response_id));
    json_object_object_add(data, "sequence",
                           json_object_new_int(++state->sequence));
    json_object_object_add(data, "ts", json_object_new_int64(ai_now_ms()));
    json = json_object_to_json_string_ext(data, JSON_C_TO_STRING_PLAIN);
    hlen = snprintf(header, sizeof(header), "id: %s:%d\nevent: %s\ndata: ",
                    state->response_id, state->sequence,
                    event ? event : "message");
    if (hlen <= 0 || hlen >= (int)sizeof(header) ||
        ai_stream_write_all(state->fd, header, (size_t)hlen) != 0 ||
        ai_stream_write_all(state->fd, json, strlen(json)) != 0 ||
        ai_stream_write_all(state->fd, "\n\n", 2) != 0) {
        state->disconnected = 1;
        json_object_put(data);
        return -1;
    }
    json_object_put(data);
    return 0;
}

static void ai_stream_usage(struct ai_stream_state *state,
                            struct json_object *usage, int anthropic)
{
    struct json_object *value = NULL;
    if (!state || !usage || !json_object_is_type(usage, json_type_object)) return;
    if (json_object_object_get_ex(usage,
        anthropic ? "input_tokens" : "prompt_tokens", &value) && value)
        state->prompt_tokens = json_object_get_int64(value);
    if (json_object_object_get_ex(usage,
        anthropic ? "output_tokens" : "completion_tokens", &value) && value)
        state->completion_tokens = json_object_get_int64(value);
    if (json_object_object_get_ex(usage, "total_tokens", &value) && value)
        state->total_tokens = json_object_get_int64(value);
    if (!state->total_tokens)
        state->total_tokens = state->prompt_tokens + state->completion_tokens;
}

static int ai_stream_delta(struct ai_stream_state *state, const char *delta)
{
    struct json_object *data;
    size_t len = delta ? strlen(delta) : 0;
    if (!len) return 0;
    if (len > AI_MAX_RESPONSE_BYTES ||
        state->reply_len > AI_MAX_RESPONSE_BYTES - len ||
        ai_text_append(&state->reply, &state->reply_len, delta, len) != 0) {
        snprintf(state->result->provider_code,
                 sizeof(state->result->provider_code), "provider_response_too_large");
        state->provider_failed = 1;
        return -1;
    }
    data = json_object_new_object();
    json_object_object_add(data, "delta", json_object_new_string(delta));
    if (ai_stream_emit(state, "response.delta", data) != 0) {
        json_object_put(data);
        return -1;
    }
    json_object_put(data);
    return 0;
}

static struct json_object *ai_stream_tool_part(struct ai_stream_state *state,
                                               int index)
{
    struct json_object *part;
    if (!state || !state->tool_parts || index < 0 ||
        index >= 1024)
        return NULL;
    for (int i = 0; i < json_object_array_length(state->tool_parts); i++) {
        part = json_object_array_get_idx(state->tool_parts, i);
        if (json_object_get_int(json_object_object_get(part, "provider_index")) == index)
            return part;
    }
    if (json_object_array_length(state->tool_parts) >= AI_MAX_TOOL_CALLS_PER_ROUND)
        return NULL;
    part = json_object_new_object();
    json_object_object_add(part, "index", json_object_new_int(
        json_object_array_length(state->tool_parts)));
    json_object_object_add(part, "provider_index", json_object_new_int(index));
    json_object_object_add(part, "id", json_object_new_string(""));
    json_object_object_add(part, "name", json_object_new_string(""));
    json_object_object_add(part, "arguments", json_object_new_string(""));
    json_object_object_add(part, "started", json_object_new_boolean(0));
    json_object_array_add(state->tool_parts, part);
    return part;
}

static int ai_stream_part_append(struct json_object *part, const char *key,
                                 const char *delta, size_t limit)
{
    const char *current = ai_json_string(part, key, "");
    size_t current_len = strlen(current), delta_len = delta ? strlen(delta) : 0;
    char *next;
    if (!delta_len) return 0;
    if (delta_len > limit || current_len > limit - delta_len) return -1;
    next = malloc(current_len + delta_len + 1);
    if (!next) return -1;
    memcpy(next, current, current_len);
    memcpy(next + current_len, delta, delta_len + 1);
    json_object_object_add(part, key, json_object_new_string(next));
    free(next);
    return 0;
}

static void ai_stream_tool_started(struct ai_stream_state *state,
                                   struct json_object *part)
{
    struct json_object *started = NULL, *data, *summary;
    if (!state || !part ||
        (json_object_object_get_ex(part, "started", &started) && started &&
         json_object_get_boolean(started)))
        return;
    json_object_object_add(part, "started", json_object_new_boolean(1));
    summary = json_object_new_object();
    json_object_object_add(summary, "index", json_object_get(
        json_object_object_get(part, "index")));
    json_object_object_add(summary, "id", json_object_new_string(
        ai_json_string(part, "id", "")));
    json_object_object_add(summary, "name", json_object_new_string(
        ai_json_string(part, "name", "")));
    data = json_object_new_object();
    json_object_object_add(data, "tool_call", summary);
    ai_stream_emit(state, "tool.call.started", data);
    json_object_put(data);
}

static void ai_stream_tool_merge(struct ai_stream_state *state, int index,
                                 const char *id, const char *name,
                                 const char *arguments, int arguments_are_full)
{
    struct json_object *part = ai_stream_tool_part(state, index);
    if (!part) {
        snprintf(state->result->provider_code,
                 sizeof(state->result->provider_code), "too_many_tool_calls");
        state->provider_failed = 1;
        return;
    }
    if (id && id[0])
        json_object_object_add(part, "id", json_object_new_string(id));
    if (name && name[0])
        json_object_object_add(part, "name", json_object_new_string(name));
    if (arguments && arguments[0]) {
        if (arguments_are_full)
            json_object_object_add(part, "arguments", json_object_new_string(arguments));
        else if (ai_stream_part_append(part, "arguments", arguments,
                                       AI_MAX_TOOL_RESULT_BYTES) != 0) {
            snprintf(state->result->provider_code,
                     sizeof(state->result->provider_code), "tool_arguments_too_large");
            state->provider_failed = 1;
            return;
        }
    }
    if (ai_json_string(part, "id", "")[0] || ai_json_string(part, "name", "")[0])
        ai_stream_tool_started(state, part);
}

static int ai_stream_tools_finalize(struct ai_stream_state *state,
                                    const struct ai_config *cfg)
{
    struct json_object *calls = json_object_new_array();
    if (!calls) return -1;
    for (int i = 0; state && state->tool_parts &&
         i < json_object_array_length(state->tool_parts); i++) {
        struct json_object *part = json_object_array_get_idx(state->tool_parts, i);
        struct json_object *call, *function, *input;
        const char *id = ai_json_string(part, "id", "");
        const char *name = ai_json_string(part, "name", "");
        const char *arguments = ai_json_string(part, "arguments", "");
        char generated[96];
        if (!name[0]) { json_object_put(calls); return -1; }
        if (!id[0]) {
            snprintf(generated, sizeof(generated), "tool-%lld-%d",
                     (long long)ai_now_ms(), i);
            id = generated;
        }
        input = arguments[0] ? json_tokener_parse(arguments) : json_object_new_object();
        if (!input || !json_object_is_type(input, json_type_object)) {
            if (input) json_object_put(input);
            json_object_put(calls);
            return -1;
        }
        call = json_object_new_object();
        if (ai_is_gemini(cfg)) {
            json_object_object_add(call, "id", json_object_new_string(id));
            json_object_object_add(call, "name", json_object_new_string(name));
            json_object_object_add(call, "args", input);
        } else if (!strcasecmp(cfg->provider, "anthropic")) {
            json_object_object_add(call, "type", json_object_new_string("tool_use"));
            json_object_object_add(call, "id", json_object_new_string(id));
            json_object_object_add(call, "name", json_object_new_string(name));
            json_object_object_add(call, "input", input);
        } else if (ai_uses_responses_shape(cfg)) {
            json_object_object_add(call, "type", json_object_new_string("function_call"));
            json_object_object_add(call, "call_id", json_object_new_string(id));
            json_object_object_add(call, "name", json_object_new_string(name));
            json_object_object_add(call, "arguments",
                                   json_object_new_string(arguments[0] ? arguments : "{}"));
            json_object_put(input);
        } else {
            function = json_object_new_object();
            json_object_object_add(call, "id", json_object_new_string(id));
            json_object_object_add(call, "type", json_object_new_string("function"));
            json_object_object_add(function, "name", json_object_new_string(name));
            json_object_object_add(function, "arguments",
                                   json_object_new_string(arguments[0] ? arguments : "{}"));
            json_object_object_add(call, "function", function);
            json_object_put(input);
        }
        json_object_array_add(calls, call);
    }
    json_object_put(state->tool_calls);
    state->tool_calls = calls;
    for (int i = 0; i < json_object_array_length(calls); i++) {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "tool_call", json_object_get(
            json_object_array_get_idx(calls, i)));
        ai_stream_emit(state, "tool.call.completed", data);
        json_object_put(data);
    }
    return 0;
}

static void ai_stream_process_json(struct ai_stream_state *state,
                                   struct json_object *event)
{
    struct json_object *value = NULL, *usage = NULL;
    const char *type;

    if (!state || !event || !json_object_is_type(event, json_type_object)) return;
    if (json_object_object_get_ex(event, "error", &value) && value) {
        ai_provider_error(event, state->result);
        state->provider_failed = 1;
        return;
    }
    if (state->gemini) {
        struct json_object *candidates = NULL, *candidate = NULL;
        struct json_object *content = NULL, *parts = NULL;

        if (json_object_object_get_ex(event, "usageMetadata", &usage) && usage) {
            state->prompt_tokens = json_object_get_int64(
                json_object_object_get(usage, "promptTokenCount"));
            state->completion_tokens = json_object_get_int64(
                json_object_object_get(usage, "candidatesTokenCount"));
            state->total_tokens = json_object_get_int64(
                json_object_object_get(usage, "totalTokenCount"));
        }
        if (!json_object_object_get_ex(event, "candidates", &candidates) ||
            !candidates || !json_object_is_type(candidates, json_type_array) ||
            !(candidate = json_object_array_get_idx(candidates, 0)))
            return;
        snprintf(state->finish_reason, sizeof(state->finish_reason), "%s",
                 ai_json_string(candidate, "finishReason", state->finish_reason));
        if (!json_object_object_get_ex(candidate, "content", &content) ||
            !content || !json_object_object_get_ex(content, "parts", &parts) ||
            !parts || !json_object_is_type(parts, json_type_array))
            return;
        for (int i = 0; i < json_object_array_length(parts); i++) {
            struct json_object *part = json_object_array_get_idx(parts, i);
            struct json_object *text = NULL, *function_call = NULL;

            if (json_object_object_get_ex(part, "text", &text) && text)
                ai_stream_delta(state, json_object_get_string(text));
            if (json_object_object_get_ex(part, "functionCall", &function_call) &&
                function_call) {
                struct json_object *args = NULL;
                const char *args_text = "{}";
                json_object_object_get_ex(function_call, "args", &args);
                if (args) args_text = json_object_to_json_string_ext(
                    args, JSON_C_TO_STRING_PLAIN);
                ai_stream_tool_merge(state, i,
                    ai_json_string(function_call, "id", ""),
                    ai_json_string(function_call, "name", ""), args_text, 1);
            }
        }
        return;
    }
    type = ai_json_string(event, "type", "");
    if (!strcmp(type, "response.output_text.delta")) {
        ai_stream_delta(state, ai_json_string(event, "delta", ""));
    } else if (!strcmp(type, "response.completed")) {
        struct json_object *response = NULL;
        if (json_object_object_get_ex(event, "response", &response) && response) {
            json_object_object_get_ex(response, "usage", &usage);
            snprintf(state->finish_reason, sizeof(state->finish_reason), "%s",
                     ai_json_string(response, "status", "completed"));
        }
        ai_stream_usage(state, usage, 1);
    } else if (!strcmp(type, "response.failed") || !strcmp(type, "error")) {
        ai_provider_error(event, state->result);
        state->provider_failed = 1;
    } else if (!strcmp(type, "response.output_item.added") ||
               !strcmp(type, "response.output_item.done")) {
        struct json_object *item = NULL;
        if (json_object_object_get_ex(event, "item", &item) && item &&
            !strcmp(ai_json_string(item, "type", ""), "function_call"))
            ai_stream_tool_merge(state,
                json_object_get_int(json_object_object_get(event, "output_index")),
                ai_json_string(item, "call_id", ai_json_string(item, "id", "")),
                ai_json_string(item, "name", ""),
                ai_json_string(item, "arguments", ""),
                !strcmp(type, "response.output_item.done"));
    } else if (!strcmp(type, "response.function_call_arguments.delta")) {
        ai_stream_tool_merge(state,
            json_object_get_int(json_object_object_get(event, "output_index")),
            ai_json_string(event, "call_id", ai_json_string(event, "item_id", "")),
            ai_json_string(event, "name", ""), ai_json_string(event, "delta", ""), 0);
    } else if (!strcmp(type, "content_block_delta")) {
        struct json_object *delta = NULL;
        if (json_object_object_get_ex(event, "delta", &delta) && delta) {
            if (!strcmp(ai_json_string(delta, "type", ""), "text_delta"))
                ai_stream_delta(state, ai_json_string(delta, "text", ""));
            else if (!strcmp(ai_json_string(delta, "type", ""), "input_json_delta")) {
                ai_stream_tool_merge(state,
                    json_object_get_int(json_object_object_get(event, "index")),
                    "", "", ai_json_string(delta, "partial_json", ""), 0);
            }
        }
    } else if (!strcmp(type, "content_block_start")) {
        struct json_object *block = NULL;
        if (json_object_object_get_ex(event, "content_block", &block) && block &&
            !strcmp(ai_json_string(block, "type", ""), "tool_use"))
            {
                struct json_object *input = NULL;
                const char *input_text = "";
                if (json_object_object_get_ex(block, "input", &input) && input)
                    input_text = json_object_to_json_string_ext(
                        input, JSON_C_TO_STRING_PLAIN);
                if (!strcmp(input_text, "{}")) input_text = "";
                ai_stream_tool_merge(state,
                    json_object_get_int(json_object_object_get(event, "index")),
                    ai_json_string(block, "id", ""),
                    ai_json_string(block, "name", ""), input_text, 1);
            }
    } else if (!strcmp(type, "message_start")) {
        struct json_object *message = NULL;
        if (json_object_object_get_ex(event, "message", &message) && message)
            json_object_object_get_ex(message, "usage", &usage);
        ai_stream_usage(state, usage, 1);
    } else if (!strcmp(type, "message_delta")) {
        struct json_object *delta = NULL;
        if (json_object_object_get_ex(event, "delta", &delta) && delta)
            snprintf(state->finish_reason, sizeof(state->finish_reason), "%s",
                     ai_json_string(delta, "stop_reason", "end_turn"));
        json_object_object_get_ex(event, "usage", &usage);
        if (usage && json_object_object_get_ex(usage, "output_tokens", &value) && value)
            state->completion_tokens = json_object_get_int64(value);
        state->total_tokens = state->prompt_tokens + state->completion_tokens;
    } else {
        struct json_object *choices = NULL, *choice = NULL, *delta = NULL;
        struct json_object *content = NULL, *tools = NULL, *finish = NULL;
        if (json_object_object_get_ex(event, "usage", &usage))
            ai_stream_usage(state, usage, 0);
        if (!json_object_object_get_ex(event, "choices", &choices) || !choices ||
            !json_object_is_type(choices, json_type_array) ||
            !(choice = json_object_array_get_idx(choices, 0)))
            return;
        if (json_object_object_get_ex(choice, "delta", &delta) && delta) {
            if (json_object_object_get_ex(delta, "content", &content) && content) {
                char *text = ai_content_text(content);
                if (text) { ai_stream_delta(state, text); free(text); }
            }
            if (json_object_object_get_ex(delta, "tool_calls", &tools) && tools &&
                json_object_is_type(tools, json_type_array))
                for (int i = 0; i < json_object_array_length(tools); i++) {
                    struct json_object *tool = json_object_array_get_idx(tools, i);
                    struct json_object *function = NULL;
                    int index = json_object_get_int(json_object_object_get(tool, "index"));
                    json_object_object_get_ex(tool, "function", &function);
                    ai_stream_tool_merge(state, index,
                        ai_json_string(tool, "id", ""),
                        ai_json_string(function, "name", ""),
                        ai_json_string(function, "arguments", ""), 0);
                }
        }
        if (json_object_object_get_ex(choice, "finish_reason", &finish) && finish)
            snprintf(state->finish_reason, sizeof(state->finish_reason), "%s",
                     json_object_get_string(finish));
    }
}

static int ai_stream_process_line(struct ai_stream_state *state,
                                  const char *line, size_t len)
{
    struct json_tokener *tokener;
    struct json_object *event;
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    if (len < 5 || strncmp(line, "data:", 5)) return 0;
    line += 5;
    len -= 5;
    while (len && (*line == ' ' || *line == '\t')) { line++; len--; }
    if (len == 6 && !memcmp(line, "[DONE]", 6)) {
        state->saw_event = 1;
        return 0;
    }
    tokener = json_tokener_new();
    if (!tokener) return -1;
    event = json_tokener_parse_ex(tokener, line, (int)len);
    if (json_tokener_get_error(tokener) != json_tokener_success || !event) {
        if (event) json_object_put(event);
        json_tokener_free(tokener);
        return 0;
    }
    json_tokener_free(tokener);
    state->saw_event = 1;
    ai_stream_process_json(state, event);
    json_object_put(event);
    return state->provider_failed || state->disconnected ? -1 : 0;
}

static size_t ai_stream_http_write(char *ptr, size_t size, size_t nmemb,
                                   void *opaque)
{
    struct ai_stream_state *state = opaque;
    size_t bytes = size * nmemb, consumed = 0;
    char *next;
    if (!state || !ptr || !bytes) return bytes;
    if (bytes > AI_MAX_RESPONSE_BYTES ||
        state->pending_len > AI_MAX_RESPONSE_BYTES - bytes)
        return 0;
    next = realloc(state->pending, state->pending_len + bytes + 1);
    if (!next) return 0;
    state->pending = next;
    memcpy(state->pending + state->pending_len, ptr, bytes);
    state->pending_len += bytes;
    state->pending[state->pending_len] = 0;
    while (consumed < state->pending_len) {
        char *newline = memchr(state->pending + consumed, '\n',
                               state->pending_len - consumed);
        size_t line_len;
        if (!newline) break;
        line_len = (size_t)(newline - (state->pending + consumed));
        if (ai_stream_process_line(state, state->pending + consumed,
                                   line_len) != 0)
            return 0;
        consumed += line_len + 1;
    }
    if (consumed) {
        memmove(state->pending, state->pending + consumed,
                state->pending_len - consumed);
        state->pending_len -= consumed;
        state->pending[state->pending_len] = 0;
    }
    return state->disconnected ? 0 : bytes;
}

static struct json_object *ai_stream_request(const struct ai_config *cfg,
                                             struct json_object *messages,
                                             char *endpoint,
                                             size_t endpoint_len)
{
    struct json_object *request = json_object_new_object();
    if (!request || ai_endpoint(cfg, ai_is_gemini(cfg) ? "stream" : "chat",
                                endpoint, endpoint_len) != 0) {
        if (request) json_object_put(request);
        return NULL;
    }
    if (ai_is_gemini(cfg)) {
        char *system = NULL;
        struct json_object *contents = ai_gemini_contents(messages, &system);
        struct json_object *generation = json_object_new_object();
        struct json_object *tools = ai_tools_gemini(cfg);

        json_object_object_add(request, "contents", contents);
        if (system && system[0]) {
            struct json_object *instruction = json_object_new_object();
            struct json_object *parts = json_object_new_array();
            struct json_object *part = json_object_new_object();
            json_object_object_add(part, "text", json_object_new_string(system));
            json_object_array_add(parts, part);
            json_object_object_add(instruction, "parts", parts);
            json_object_object_add(request, "systemInstruction", instruction);
        }
        free(system);
        json_object_object_add(generation, "maxOutputTokens",
                               json_object_new_int(cfg->max_tokens));
        if (cfg->temperature >= 0 && cfg->temperature <= 2)
            json_object_object_add(generation, "temperature",
                                   json_object_new_double(cfg->temperature));
        json_object_object_add(request, "generationConfig", generation);
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
    } else if (!strcasecmp(cfg->provider, "anthropic")) {
        json_object_object_add(request, "model", json_object_new_string(cfg->model));
        json_object_object_add(request, "stream", json_object_new_boolean(1));
        char *system = NULL;
        struct json_object *converted = ai_anthropic_messages(messages, &system);
        struct json_object *tools = ai_tools_anthropic(cfg);
        json_object_object_add(request, "messages", converted);
        json_object_object_add(request, "max_tokens", json_object_new_int(cfg->max_tokens));
        if (system && system[0])
            json_object_object_add(request, "system", json_object_new_string(system));
        free(system);
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
        if (cfg->temperature >= 0 && cfg->temperature <= 1)
            json_object_object_add(request, "temperature",
                                   json_object_new_double(cfg->temperature));
    } else if (ai_uses_responses_shape(cfg)) {
        json_object_object_add(request, "model", json_object_new_string(cfg->model));
        json_object_object_add(request, "stream", json_object_new_boolean(1));
        struct json_object *tools = ai_tools_openai(cfg, 1);
        if (ai_is_openai_chatgpt_oauth(cfg)) {
            char *instructions = NULL;
            struct json_object *input = ai_openai_codex_input(
                messages, &instructions);
            if (!input || !instructions) {
                if (input) json_object_put(input);
                free(instructions);
                json_object_put(request);
                return NULL;
            }
            json_object_object_add(request, "input", input);
            json_object_object_add(request, "instructions",
                                   json_object_new_string(instructions));
            json_object_object_add(request, "store",
                                   json_object_new_boolean(0));
            free(instructions);
        } else {
            json_object_object_add(request, "input", json_object_get(messages));
            json_object_object_add(request, "max_output_tokens",
                                   json_object_new_int(cfg->max_tokens));
        }
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
        if (cfg->reasoning_effort[0] && strcmp(cfg->reasoning_effort, "auto") &&
            strcmp(cfg->reasoning_effort, "none")) {
            struct json_object *reasoning = json_object_new_object();
            json_object_object_add(reasoning, "effort",
                                   json_object_new_string(cfg->reasoning_effort));
            json_object_object_add(request, "reasoning", reasoning);
        }
    } else {
        json_object_object_add(request, "model", json_object_new_string(cfg->model));
        json_object_object_add(request, "stream", json_object_new_boolean(1));
        struct json_object *options = json_object_new_object();
        struct json_object *tools = ai_tools_openai(cfg, 0);
        json_object_object_add(request, "messages", json_object_get(messages));
        json_object_object_add(request, "max_tokens", json_object_new_int(cfg->max_tokens));
        json_object_object_add(options, "include_usage", json_object_new_boolean(1));
        json_object_object_add(request, "stream_options", options);
        if (tools && json_object_array_length(tools) > 0)
            json_object_object_add(request, "tools", tools);
        else if (tools)
            json_object_put(tools);
        if (cfg->temperature >= 0 && cfg->temperature <= 2 &&
            strncasecmp(cfg->model, "o1", 2) && strncasecmp(cfg->model, "o3", 2) &&
            strncasecmp(cfg->model, "o4", 2) && strncasecmp(cfg->model, "gpt-5", 5))
            json_object_object_add(request, "temperature",
                                   json_object_new_double(cfg->temperature));
        if ((!strcasecmp(cfg->provider, "openai") ||
             !strcasecmp(cfg->provider, "openai-compatible") ||
             !strcasecmp(cfg->provider, "openai_compatible") ||
             !strcasecmp(cfg->provider, "custom")) &&
            cfg->reasoning_effort[0] && strcmp(cfg->reasoning_effort, "auto") &&
            strcmp(cfg->reasoning_effort, "none"))
            json_object_object_add(request, "reasoning_effort",
                                   json_object_new_string(cfg->reasoning_effort));
    }
    return request;
}

static int ai_stream_provider_round(const struct ai_config *cfg,
                                    struct json_object *request,
                                    struct ai_stream_state *state,
                                    struct ai_result *result)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char endpoint[768], auth[1200];
    const char *request_body;

    if (!cfg || !request || !state || !result ||
        ai_endpoint(cfg, ai_is_gemini(cfg) ? "stream" : "chat",
                    endpoint, sizeof(endpoint)) != 0)
        return -1;
    free(state->pending);
    state->pending = NULL;
    state->pending_len = 0;
    state->saw_event = 0;
    state->provider_failed = 0;
    memset(result, 0, sizeof(*result));
    state->gemini = ai_is_gemini(cfg);
    curl = curl_easy_init();
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: text/event-stream");
    if (!strcasecmp(cfg->provider, "anthropic")) {
        snprintf(auth, sizeof(auth), !strcmp(cfg->auth_mode, "oauth") ?
                 "Authorization: Bearer %s" : "x-api-key: %s", cfg->api_key);
        headers = curl_slist_append(headers, auth);
        headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");
    } else if (ai_is_gemini(cfg) && strcmp(cfg->auth_mode, "oauth")) {
        snprintf(auth, sizeof(auth), "x-goog-api-key: %s", cfg->api_key);
        headers = curl_slist_append(headers, auth);
    } else {
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", cfg->api_key);
        headers = curl_slist_append(headers, auth);
        if (ai_is_gemini(cfg) && cfg->oauth_project[0]) {
            char project_header[256];
            snprintf(project_header, sizeof(project_header),
                     "x-goog-user-project: %s", cfg->oauth_project);
            headers = curl_slist_append(headers, project_header);
        }
    }
    if (ai_is_openai_chatgpt_oauth(cfg)) {
        char account_header[256];
        headers = curl_slist_append(headers,
                                    "OpenAI-Beta: responses=experimental");
        headers = curl_slist_append(headers,
                                    "Originator: " AI_OPENAI_CODEX_ORIGINATOR);
        if (cfg->oauth_project[0]) {
            snprintf(account_header, sizeof(account_header),
                     "chatgpt-account-id: %s", cfg->oauth_project);
            headers = curl_slist_append(headers, account_header);
        }
    }
    request_body = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, endpoint);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(request_body));
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 45000L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT,
                         ai_is_openai_chatgpt_oauth(cfg) ?
                             AI_OPENAI_CODEX_USER_AGENT :
                             "dreamingwrt-webd/1.0 ai-runtime");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ai_stream_http_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, state);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, ai_stream_progress);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, state);
        result->curl_code = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result->provider_status);
    } else {
        result->curl_code = CURLE_FAILED_INIT;
    }
    if (state->pending_len && !state->saw_event) {
        struct json_object *response = json_tokener_parse(state->pending);
        if (response) {
            ai_provider_error(response, result);
            json_object_put(response);
        }
    }
    if (curl) curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    memset(auth, 0, sizeof(auth));
    return result->curl_code == CURLE_OK && result->provider_status >= 200 &&
           result->provider_status < 300 && state->saw_event &&
           !state->provider_failed ? 0 : -1;
}

static struct json_object *ai_resume_state_new(const struct ai_config *cfg,
                                                const char *conversation_id,
                                                const char *actor,
                                                struct json_object *history_body,
                                                struct json_object *messages,
                                                struct json_object *provider_calls,
                                                struct json_object *round_executions,
                                                struct json_object *all_executed,
                                                int tool_round,
                                                size_t prompt_bytes,
                                                size_t tool_result_bytes,
                                                char token[65]);
static int ai_resume_state_find(const char *conversation_id, const char *actor,
                                char token[65]);

static int ai_stream_send_error(int fd, struct json_object *error, int status)
{
    int rc = http_send_json(fd, status, error);
    json_object_put(error);
    return rc;
}

int webd_ai_runtime_stream(int fd, struct json_object *body, const char *actor)
{
    struct ai_config cfg;
    struct ai_result result = {};
    struct ai_stream_state state = { .fd = fd, .result = &result };
    struct json_object *messages = NULL, *request = NULL;
    struct json_object *data = NULL, *usage = NULL;
    struct json_object *all_executed = NULL, *all_pending = NULL;
    char endpoint[768], validation[256] = "";
    char conversation_id[128] = "";
    size_t prompt_bytes = 0;
    size_t tool_result_bytes = 0;
    int slot = -1, status = 502;
    int tool_rounds = 0;
    int stream_requires_action = 0;
    int64_t usage_prompt_total = 0, usage_completion_total = 0;
    int64_t started = ai_now_ms();

    if (!body || !json_object_is_type(body, json_type_object))
        return ai_stream_send_error(fd, ai_error("invalid_request",
            "JSON request body is required", 400, 0, NULL, NULL), 400);
    {
        struct ai_dispatch_plan dispatch;
        int select_rc = ai_dispatch_select(&cfg, &dispatch, NULL);
        int status = select_rc == -2 ? 422 : 503;
        struct json_object *err = NULL;

        /* A stream cannot switch providers mid-flight: emitted tokens cannot be
         * taken back, so a retry would duplicate content. Pick one and stay. */
        ai_dispatch_plan_clear(&dispatch);
        if (select_rc != 0) {
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            err = ai_dispatch_not_configured(select_rc, NULL);
            return ai_stream_send_error(fd, err, status);
        }
    }
    {
        const char *model = ai_json_string(body, "model", "");
        const char *effort = ai_json_string(body, "reasoning_effort", "");
        if (model[0]) {
            if (!ai_value_ok(model, sizeof(cfg.model) - 1)) {
                memset(cfg.api_key, 0, sizeof(cfg.api_key));
                return ai_stream_send_error(fd, ai_error("invalid_request",
                    "model is invalid", 400, 0, NULL, NULL), 400);
            }
            snprintf(cfg.model, sizeof(cfg.model), "%s", model);
        }
        if (effort[0]) {
            if (!ai_value_ok(effort, sizeof(cfg.reasoning_effort) - 1) ||
                (strcmp(effort, "auto") && strcmp(effort, "none") &&
                 strcmp(effort, "minimal") && strcmp(effort, "low") &&
                 strcmp(effort, "medium") && strcmp(effort, "high") &&
                 strcmp(effort, "xhigh"))) {
                memset(cfg.api_key, 0, sizeof(cfg.api_key));
                return ai_stream_send_error(fd, ai_error("invalid_request",
                    "reasoning_effort is invalid", 400, 0, NULL, NULL), 400);
            }
            snprintf(cfg.reasoning_effort, sizeof(cfg.reasoning_effort), "%s", effort);
        }
    }
    snprintf(conversation_id, sizeof(conversation_id), "%s",
             ai_json_string(body, "conversation_id", ""));
    if (!ai_value_ok(conversation_id, sizeof(conversation_id) - 1))
        snprintf(conversation_id, sizeof(conversation_id), "ai-%lld-%ld",
                 (long long)time(NULL), (long)getpid());
    {
        char active_resume[65] = "";
        if (ai_resume_state_find(conversation_id, actor, active_resume) == 0) {
            struct json_object *error = ai_error(
                "authorization_pending",
                "This conversation already has a pending tool continuation",
                409, 0, NULL, NULL);
            struct json_object *error_obj = NULL, *details = json_object_new_object();
            json_object_object_add(details, "conversation_id",
                                   json_object_new_string(conversation_id));
            json_object_object_add(details, "resume_token",
                                   json_object_new_string(active_resume));
            json_object_object_add(details, "resume_endpoint",
                                   json_object_new_string("/api/v1/ai/tool-resume"));
            json_object_object_add(details, "resume_stream_endpoint",
                json_object_new_string("/api/v1/ai/tool-resume/stream"));
            if (json_object_object_get_ex(error, "error", &error_obj) && error_obj)
                json_object_object_add(error_obj, "details", details);
            else
                json_object_put(details);
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return ai_stream_send_error(fd, error, 409);
        }
    }
    snprintf(state.conversation_id, sizeof(state.conversation_id), "%s",
             conversation_id);
    snprintf(state.response_id, sizeof(state.response_id), "resp-%lld-%ld",
             (long long)ai_now_ms(), (long)getpid());
    snprintf(state.finish_reason, sizeof(state.finish_reason), "stop");
    state.tool_calls = json_object_new_array();
    state.tool_parts = json_object_new_array();

    if (ai_rate_limited(actor, "ai.chat")) {
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "rate_limited");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        return ai_stream_send_error(fd, ai_error("rate_limited",
            "AI request rate limit exceeded", 429, 0, NULL, NULL), 429);
    }
    slot = ai_acquire_slot();
    if (slot < 0) {
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "concurrency_limited");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        return ai_stream_send_error(fd, ai_error("ai_busy",
            "AI runtime concurrency limit reached", 429, 0, NULL, NULL), 429);
    }
    if (ai_prepare_messages(&cfg, body, actor, &messages, &prompt_bytes,
                            validation, sizeof(validation)) != 0) {
        int http_status = strstr(validation, "exceeds") ? 413 : 400;
        close(slot);
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "validation_failed");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        return ai_stream_send_error(fd, ai_error(
            http_status == 413 ? "context_too_large" : "invalid_request",
            validation, http_status, 0, NULL, NULL), http_status);
    }
    all_executed = json_object_new_array();
    all_pending = json_object_new_array();
    if (!all_executed || !all_pending) {
        if (all_executed) json_object_put(all_executed);
        if (all_pending) json_object_put(all_pending);
        json_object_put(messages);
        close(slot);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        return ai_stream_send_error(fd, ai_error("allocation_failed",
            "AI stream tool loop allocation failed", 500, 0, NULL, NULL), 500);
    }
    request = ai_stream_request(&cfg, messages, endpoint, sizeof(endpoint));
    if (!request || ai_response_register(&state, actor) != 0) {
        if (request) json_object_put(request);
        json_object_put(messages);
        close(slot);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        json_object_put(all_executed);
        json_object_put(all_pending);
        return ai_stream_send_error(fd, ai_error("stream_state_unavailable",
            "AI stream state could not be registered", 500, 0, NULL, NULL), 500);
    }
    if (http_send_sse_header(fd) != 0) {
        ai_response_unregister(&state);
        json_object_put(request);
        json_object_put(messages);
        close(slot);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        json_object_put(all_executed);
        json_object_put(all_pending);
        return -1;
    }
    data = json_object_new_object();
    json_object_object_add(data, "model", json_object_new_string(cfg.model));
    json_object_object_add(data, "provider", json_object_new_string(cfg.provider));
    ai_stream_emit(&state, "conversation.created", data);
    json_object_put(data);
    data = json_object_new_object();
    json_object_object_add(data, "model", json_object_new_string(cfg.model));
    json_object_object_add(data, "reasoning_effort",
                           json_object_new_string(cfg.reasoning_effort));
    ai_stream_emit(&state, "response.started", data);
    json_object_put(data);

    for (tool_rounds = 0; tool_rounds <= AI_MAX_TOOL_ROUNDS; tool_rounds++) {
        struct json_object *round_executions = NULL;
        struct json_object *round_pending = NULL;
        size_t reply_before = state.reply_len;
        int round_ok = ai_stream_provider_round(&cfg, request, &state, &result) == 0;

        usage_prompt_total += state.prompt_tokens;
        usage_completion_total += state.completion_tokens;
        if (state.disconnected || state.cancelled || !round_ok) break;
        if (state.reply_len == reply_before &&
            json_object_array_length(state.tool_parts) == 0) {
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "provider_response_invalid");
            state.provider_failed = 1;
            break;
        }
        if (json_object_array_length(state.tool_parts) == 0) break;
        if (tool_rounds == AI_MAX_TOOL_ROUNDS ||
            ai_stream_tools_finalize(&state, &cfg) != 0) {
            snprintf(result.provider_code, sizeof(result.provider_code), "%s",
                     tool_rounds == AI_MAX_TOOL_ROUNDS ? "tool_round_limit" :
                                                        "invalid_tool_arguments");
            state.provider_failed = 1;
            break;
        }
        round_executions = json_object_new_array();
        round_pending = json_object_new_array();
        for (int i = 0; i < json_object_array_length(state.tool_calls); i++) {
            struct json_object *execution = ai_execute_tool_call(
                &cfg, json_object_array_get_idx(state.tool_calls, i),
                conversation_id, actor, i, &tool_result_bytes);
            struct json_object *response = NULL, *response_data = NULL;
            const char *execution_status = "execution_failed";
            ai_tool_execution_collect(execution, all_executed, round_pending);
            json_object_array_add(round_executions, execution);
            json_object_object_get_ex(execution, "execution", &response);
            response_data = ai_core_data(response);
            if (response_data)
                execution_status = ai_json_string(response_data, "status",
                                                  execution_status);
            data = json_object_new_object();
            json_object_object_add(data, "tool_execution", json_object_get(execution));
            json_object_object_add(data, "status",
                                   json_object_new_string(execution_status));
            ai_stream_emit(&state,
                !strcmp(execution_status, "pending_authorization") ?
                    "tool.call.requires_action" : "tool.call.result", data);
            json_object_put(data);
        }
        if (json_object_array_length(round_pending) > 0) {
            char resume_token[65] = "";
            struct json_object *resume_state = ai_resume_state_new(
                &cfg, conversation_id, actor, body, messages, state.tool_calls,
                round_executions, all_executed, tool_rounds, prompt_bytes,
                tool_result_bytes, resume_token);
            if (!resume_state) {
                snprintf(result.provider_code, sizeof(result.provider_code),
                         "resume_storage_failed");
                state.provider_failed = 1;
            } else {
                for (int i = 0; i < json_object_array_length(round_pending); i++)
                    json_object_array_add(all_pending, json_object_get(
                        json_object_array_get_idx(round_pending, i)));
                data = json_object_new_object();
                json_object_object_add(data, "status",
                                       json_object_new_string("requires_action"));
                json_object_object_add(data, "resume_token",
                                       json_object_new_string(resume_token));
                json_object_object_add(data, "resume_expires_at", json_object_get(
                    json_object_object_get(resume_state, "expires_at")));
                json_object_object_add(data, "resume_endpoint",
                    json_object_new_string("/api/v1/ai/tool-resume"));
                json_object_object_add(data, "resume_stream_endpoint",
                    json_object_new_string("/api/v1/ai/tool-resume/stream"));
                json_object_object_add(data, "pending_authorizations",
                                       json_object_get(round_pending));
                json_object_object_add(data, "tool_executions",
                                       json_object_get(all_executed));
                json_object_object_add(data, "tool_loop_complete",
                                       json_object_new_boolean(0));
                ai_stream_emit(&state, "response.requires_action", data);
                json_object_put(data);
                json_object_put(resume_state);
                stream_requires_action = 1;
            }
            json_object_put(round_pending);
            json_object_put(round_executions);
            break;
        }
        ai_append_tool_feedback(&cfg, messages, state.tool_calls, round_executions);
        json_object_put(round_pending);
        json_object_put(round_executions);
        json_object_put(request);
        request = ai_stream_request(&cfg, messages, endpoint, sizeof(endpoint));
        if (!request) {
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "provider_request_invalid");
            state.provider_failed = 1;
            break;
        }
        json_object_put(state.tool_calls);
        json_object_put(state.tool_parts);
        state.tool_calls = json_object_new_array();
        state.tool_parts = json_object_new_array();
        state.prompt_tokens = 0;
        state.completion_tokens = 0;
        state.total_tokens = 0;
        snprintf(state.finish_reason, sizeof(state.finish_reason), "stop");
    }
    if (!state.disconnected) {
        if (state.cancelled) {
            data = json_object_new_object();
            json_object_object_add(data, "reason",
                                   json_object_new_string("cancelled_by_user"));
            json_object_object_add(data, "partial_reply",
                                   json_object_new_string(state.reply ? state.reply : ""));
            ai_stream_emit(&state, "response.cancelled", data);
            json_object_put(data);
            ai_audit(actor, "ai.chat", &cfg, conversation_id,
                     ai_now_ms() - started, "cancelled");
        } else if (stream_requires_action) {
            ai_audit(actor, "ai.chat", &cfg, conversation_id,
                     ai_now_ms() - started, "requires_action");
        } else if (!state.provider_failed && result.curl_code == CURLE_OK &&
                   result.provider_status >= 200 && result.provider_status < 300) {
            data = json_object_new_object();
            usage = json_object_new_object();
            json_object_object_add(data, "reply",
                                   json_object_new_string(state.reply ? state.reply : ""));
            json_object_object_add(data, "model", json_object_new_string(cfg.model));
            json_object_object_add(data, "provider", json_object_new_string(cfg.provider));
            json_object_object_add(data, "reasoning_effort",
                                   json_object_new_string(cfg.reasoning_effort));
            json_object_object_add(data, "finish_reason",
                                   json_object_new_string(state.finish_reason));
            json_object_object_add(usage, "prompt_tokens",
                                   json_object_new_int64(usage_prompt_total));
            json_object_object_add(usage, "completion_tokens",
                                   json_object_new_int64(usage_completion_total));
            json_object_object_add(usage, "total_tokens", json_object_new_int64(
                usage_prompt_total + usage_completion_total));
            json_object_object_add(data, "usage", usage);
            json_object_object_add(data, "tool_executions",
                                   json_object_get(all_executed));
            json_object_object_add(data, "pending_authorizations",
                                   json_object_new_array());
            json_object_object_add(data, "tool_execution_supported",
                                   json_object_new_boolean(1));
            json_object_object_add(data, "tool_loop_complete", json_object_new_boolean(1));
            json_object_object_add(data, "tool_rounds", json_object_new_int(tool_rounds));
            json_object_object_add(data, "tool_result_bytes",
                                   json_object_new_int64((int64_t)tool_result_bytes));
            json_object_object_add(data, "prompt_bytes",
                                   json_object_new_int64((int64_t)prompt_bytes));
            if (ai_conversation_finalize(&cfg, body, data, conversation_id) == 0) {
                ai_stream_emit(&state, "response.completed", data);
                ai_audit(actor, "ai.chat", &cfg, conversation_id,
                         ai_now_ms() - started, "success");
            } else {
                struct json_object *error = ai_error(
                    "conversation_history_save_failed",
                    "AI response could not be persisted", 500, 0, NULL, NULL);
                ai_stream_emit(&state, "response.failed", error);
                json_object_put(error);
                ai_audit(actor, "ai.chat", &cfg, conversation_id,
                         ai_now_ms() - started,
                         "conversation_history_save_failed");
            }
            json_object_put(data);
        } else {
            const char *code;
            if (state.provider_failed && result.curl_code == CURLE_WRITE_ERROR)
                result.curl_code = CURLE_OK;
            code = ai_error_code(&result, &status);
            data = ai_error(code, "AI provider stream failed", status,
                            result.provider_status, result.provider_code,
                            result.provider_message);
            ai_stream_emit(&state, "response.failed", data);
            json_object_put(data);
            ai_audit(actor, "ai.chat", &cfg, conversation_id,
                     ai_now_ms() - started, code);
        }
    } else {
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "client_disconnected");
    }
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
    json_object_put(request);
    json_object_put(messages);
    json_object_put(state.tool_calls);
    json_object_put(state.tool_parts);
    json_object_put(all_executed);
    json_object_put(all_pending);
    free(state.pending);
    free(state.reply);
    ai_response_unregister(&state);
    close(slot);
    return state.disconnected ? -1 : 0;
}

struct json_object *webd_ai_runtime_cancel(const char *response_id,
                                           const char *actor,
                                           int *http_status)
{
    char active[256], cancel[256], buffer[2048];
    struct json_object *record = NULL, *data;
    struct json_object *pid_obj = NULL;
    const char *owner;
    int64_t worker_pid = 0;
    int fd;
    ssize_t bytes;

    if (http_status) *http_status = 400;
    if (ai_response_paths(response_id, active, sizeof(active),
                          cancel, sizeof(cancel)) != 0)
        return ai_error("invalid_response_id", "response_id is invalid",
                        400, 0, NULL, NULL);
    fd = open(active, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (http_status) *http_status = 404;
        return ai_error("response_not_active", "AI response is not active",
                        404, 0, NULL, NULL);
    }
    bytes = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes <= 0) {
        if (http_status) *http_status = 409;
        return ai_error("response_state_unavailable",
                        "AI response state is unavailable", 409, 0, NULL, NULL);
    }
    buffer[bytes] = 0;
    record = json_tokener_parse(buffer);
    owner = ai_json_string(record, "actor", "");
    if (record && json_object_object_get_ex(record, "pid", &pid_obj) && pid_obj)
        worker_pid = json_object_get_int64(pid_obj);
    if (worker_pid <= 1 || (kill((pid_t)worker_pid, 0) != 0 && errno == ESRCH)) {
        if (record) json_object_put(record);
        unlink(active);
        unlink(cancel);
        if (http_status) *http_status = 404;
        return ai_error("response_not_active", "AI response is not active",
                        404, 0, NULL, NULL);
    }
    if (!record || !owner[0] || !actor || strcmp(owner, actor)) {
        if (record) json_object_put(record);
        if (http_status) *http_status = 403;
        return ai_error("response_owner_mismatch",
                        "Only the response owner can cancel it", 403, 0, NULL, NULL);
    }
    fd = open(cancel, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 && errno != EEXIST) {
        json_object_put(record);
        if (http_status) *http_status = 500;
        return ai_error("cancel_state_write_failed",
                        "Failed to request AI response cancellation",
                        500, 0, NULL, NULL);
    }
    if (fd >= 0) {
        write(fd, actor, strlen(actor));
        fsync(fd);
        close(fd);
    }
    data = json_object_new_object();
    json_object_object_add(data, "response_id", json_object_new_string(response_id));
    json_object_object_add(data, "conversation_id", json_object_new_string(
        ai_json_string(record, "conversation_id", "")));
    json_object_object_add(data, "status", json_object_new_string("cancelling"));
    json_object_put(record);
    jmx_app_audit_log(actor, actor, "ai.response.cancel", "low",
                      response_id, "", "status=cancelling");
    if (http_status) *http_status = 202;
    return ai_success(data, "webd.ai.cancel");
}

struct ai_resume_entry {
    char name[96];
    time_t mtime;
    off_t size;
};

static int ai_resume_token_ok(const char *token)
{
    size_t len = token ? strlen(token) : 0;
    if (len != 64) return 0;
    for (size_t i = 0; i < len; i++)
        if (!isxdigit((unsigned char)token[i])) return 0;
    return 1;
}

static int ai_resume_dir(void)
{
    if ((mkdir("/tmp/dreamingwrt", 0700) != 0 && errno != EEXIST) ||
        (mkdir(AI_TOOL_RESUME_DIR, 0700) != 0 && errno != EEXIST))
        return -1;
    chmod(AI_TOOL_RESUME_DIR, 0700);
    return 0;
}

static int ai_resume_paths(const char *token, char *state, size_t state_len,
                           char *lock, size_t lock_len)
{
    if (!ai_resume_token_ok(token) || ai_resume_dir() != 0 ||
        snprintf(state, state_len, "%s/%s.json", AI_TOOL_RESUME_DIR, token) >=
            (int)state_len ||
        snprintf(lock, lock_len, "%s/%s.lock", AI_TOOL_RESUME_DIR, token) >=
            (int)lock_len)
        return -1;
    return 0;
}

static int ai_resume_entry_cmp(const void *left, const void *right)
{
    const struct ai_resume_entry *a = left;
    const struct ai_resume_entry *b = right;
    return a->mtime < b->mtime ? -1 : a->mtime > b->mtime ? 1 : 0;
}

static void ai_resume_prune(void)
{
    DIR *dir;
    struct dirent *de;
    struct ai_resume_entry entries[64];
    size_t count = 0;
    off_t total = 0;
    time_t now = time(NULL);

    if (ai_resume_dir() != 0 || !(dir = opendir(AI_TOOL_RESUME_DIR))) return;
    while ((de = readdir(dir)) != NULL && count < 64) {
        char path[256];
        struct stat st;
        size_t len = strlen(de->d_name);
        if (len != 69 || strcmp(de->d_name + 64, ".json")) continue;
        if (snprintf(path, sizeof(path), "%s/%s", AI_TOOL_RESUME_DIR, de->d_name) >=
            (int)sizeof(path) || stat(path, &st) != 0)
            continue;
        if (now - st.st_mtime > AI_TOOL_RESUME_TTL) {
            unlink(path);
            continue;
        }
        memcpy(entries[count].name, de->d_name, len + 1);
        entries[count].mtime = st.st_mtime;
        entries[count].size = st.st_size;
        total += st.st_size;
        count++;
    }
    closedir(dir);
    qsort(entries, count, sizeof(entries[0]), ai_resume_entry_cmp);
    for (size_t i = 0; i < count &&
         (count - i > AI_TOOL_RESUME_MAX_FILES || total > 16 * 1024 * 1024); i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%.*s", AI_TOOL_RESUME_DIR, 69,
                 entries[i].name);
        if (unlink(path) == 0) total -= entries[i].size;
    }
    if (!(dir = opendir(AI_TOOL_RESUME_DIR))) return;
    while ((de = readdir(dir)) != NULL) {
        char lock[256], state[256];
        struct stat st;
        int fd;
        size_t len = strlen(de->d_name);
        if (len != 69 || strcmp(de->d_name + 64, ".lock")) continue;
        snprintf(lock, sizeof(lock), "%s/%.*s", AI_TOOL_RESUME_DIR, 69,
                 de->d_name);
        snprintf(state, sizeof(state), "%s/%.*s.json", AI_TOOL_RESUME_DIR, 64,
                 de->d_name);
        if (stat(lock, &st) != 0 || access(state, F_OK) == 0 ||
            now - st.st_mtime <= AI_TOOL_RESUME_TTL)
            continue;
        fd = open(lock, O_RDWR | O_CLOEXEC);
        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0) {
            if (access(state, F_OK) != 0) unlink(lock);
            flock(fd, LOCK_UN);
        }
        if (fd >= 0) close(fd);
    }
    closedir(dir);
}

static int ai_resume_sensitive_key(const char *key)
{
    static const char *keys[] = {
        "password", "passwd", "api_key", "access_token", "refresh_token",
        "authorization", "cookie", "private_key", "secret", "otp", NULL
    };
    for (int i = 0; key && keys[i]; i++)
        if (!strcasecmp(key, keys[i])) return 1;
    return 0;
}

static struct json_object *ai_resume_redacted_clone(struct json_object *value,
                                                     const char *key)
{
    if (!value) return NULL;
    if (ai_resume_sensitive_key(key)) return json_object_new_string("[REDACTED]");
    switch (json_object_get_type(value)) {
    case json_type_object: {
        struct json_object *copy = json_object_new_object();
        json_object_object_foreach(value, child_key, child) {
            struct json_object *redacted = ai_resume_redacted_clone(child, child_key);
            if (redacted) json_object_object_add(copy, child_key, redacted);
        }
        return copy;
    }
    case json_type_array: {
        struct json_object *copy = json_object_new_array();
        for (int i = 0; i < json_object_array_length(value); i++) {
            struct json_object *redacted = ai_resume_redacted_clone(
                json_object_array_get_idx(value, i), NULL);
            if (redacted) json_object_array_add(copy, redacted);
        }
        return copy;
    }
    case json_type_string: {
        const char *text = json_object_get_string(value);
        char *redacted;
        if ((ai_contains_i(text, "-----BEGIN") &&
             ai_contains_i(text, "PRIVATE KEY-----")) ||
            ai_contains_i(text, "Authorization: Bearer ") ||
            ai_contains_i(text, "Cookie:"))
            return json_object_new_string("[REDACTED]");
        redacted = ai_redact_text(text ? text : "", AI_TOOL_RESUME_MAX_BYTES);
        if (!redacted) return json_object_new_string("[REDACTED OVERSIZE STRING]");
        struct json_object *copy = json_object_new_string(redacted);
        free(redacted);
        return copy;
    }
    default:
        return json_object_get(value);
    }
}

static int ai_resume_token_generate(char token[65])
{
    unsigned char random[32];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t offset = 0;
    if (fd < 0) return -1;
    while (offset < sizeof(random)) {
        ssize_t got = read(fd, random + offset, sizeof(random) - offset);
        if (got <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)got;
    }
    close(fd);
    for (size_t i = 0; i < sizeof(random); i++)
        snprintf(token + i * 2, 3, "%02x", random[i]);
    token[64] = 0;
    return 0;
}

static int ai_resume_state_save(struct json_object *state)
{
    const char *token = ai_json_string(state, "resume_token", "");
    const char *serialized;
    char path[256], lock_path[256], tmp[288];
    size_t len;
    int fd, sync_rc, close_rc;
    size_t offset = 0;
    struct json_object *redacted;

    if (ai_resume_paths(token, path, sizeof(path), lock_path, sizeof(lock_path)) != 0)
        return -1;
    redacted = ai_resume_redacted_clone(state, NULL);
    if (!redacted) return -1;
    serialized = json_object_to_json_string_ext(redacted, JSON_C_TO_STRING_PLAIN);
    len = serialized ? strlen(serialized) : 0;
    if (!len || len > AI_TOOL_RESUME_MAX_BYTES) {
        json_object_put(redacted);
        return -1;
    }
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp)) {
        json_object_put(redacted);
        return -1;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        json_object_put(redacted);
        return -1;
    }
    while (offset < len) {
        ssize_t wrote = write(fd, serialized + offset, len - offset);
        if (wrote <= 0) break;
        offset += (size_t)wrote;
    }
    sync_rc = offset == len ? fsync(fd) : -1;
    close_rc = close(fd);
    if (offset != len || sync_rc != 0 || close_rc != 0) {
        unlink(tmp);
        json_object_put(redacted);
        return -1;
    }
    chmod(tmp, 0600);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        json_object_put(redacted);
        return -1;
    }
    json_object_put(redacted);
    return 0;
}

static struct json_object *ai_resume_state_load(const char *token)
{
    struct json_object *state;
    char path[256], lock_path[256];
    struct stat st;
    if (ai_resume_paths(token, path, sizeof(path), lock_path, sizeof(lock_path)) != 0 ||
        stat(path, &st) != 0 || st.st_size <= 0 ||
        st.st_size > AI_TOOL_RESUME_MAX_BYTES ||
        time(NULL) - st.st_mtime > AI_TOOL_RESUME_TTL)
        return NULL;
    state = json_object_from_file(path);
    if (!state || !json_object_is_type(state, json_type_object) ||
        !ai_ct_str_equal(ai_json_string(state, "resume_token", ""), token)) {
        if (state) json_object_put(state);
        return NULL;
    }
    return state;
}

static void ai_resume_state_delete(const char *token)
{
    char path[256], lock_path[256];
    if (ai_resume_paths(token, path, sizeof(path), lock_path, sizeof(lock_path)) != 0)
        return;
    unlink(path);
}

static int ai_resume_state_find(const char *conversation_id, const char *actor,
                                char token[65])
{
    DIR *dir;
    struct dirent *de;
    int found = -1;
    ai_resume_prune();
    if (!(dir = opendir(AI_TOOL_RESUME_DIR))) return -1;
    while ((de = readdir(dir)) != NULL) {
        struct json_object *state;
        size_t len = strlen(de->d_name);
        if (len != 69 || strcmp(de->d_name + 64, ".json")) continue;
        snprintf(token, 65, "%.*s", 64, de->d_name);
        state = ai_resume_state_load(token);
        if (state && !strcmp(ai_json_string(state, "conversation_id", ""),
                             conversation_id ? conversation_id : "") &&
            !strcmp(ai_json_string(state, "actor", ""), actor ? actor : "")) {
            found = 0;
            json_object_put(state);
            break;
        }
        if (state) json_object_put(state);
        token[0] = 0;
    }
    closedir(dir);
    return found;
}

static struct json_object *ai_resume_state_new(const struct ai_config *cfg,
                                                const char *conversation_id,
                                                const char *actor,
                                                struct json_object *history_body,
                                                struct json_object *messages,
                                                struct json_object *provider_calls,
                                                struct json_object *round_executions,
                                                struct json_object *all_executed,
                                                int tool_round,
                                                size_t prompt_bytes,
                                                size_t tool_result_bytes,
                                                char token[65])
{
    struct json_object *state;
    char create_lock_path[256];
    int create_lock = -1;
    time_t now = time(NULL);
    token[0] = 0;
    ai_resume_prune();
    if (snprintf(create_lock_path, sizeof(create_lock_path), "%s/.create.lock",
                 AI_TOOL_RESUME_DIR) >= (int)sizeof(create_lock_path))
        return NULL;
    create_lock = open(create_lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (create_lock < 0 || flock(create_lock, LOCK_EX) != 0) {
        if (create_lock >= 0) close(create_lock);
        return NULL;
    }
    if (ai_resume_state_find(conversation_id, actor, token) == 0) {
        flock(create_lock, LOCK_UN);
        close(create_lock);
        token[0] = 0;
        return NULL;
    }
    if (ai_resume_token_generate(token) != 0) {
        flock(create_lock, LOCK_UN);
        close(create_lock);
        return NULL;
    }
    state = json_object_new_object();
    json_object_object_add(state, "version", json_object_new_int(1));
    json_object_object_add(state, "resume_token", json_object_new_string(token));
    json_object_object_add(state, "conversation_id",
                           json_object_new_string(conversation_id));
    json_object_object_add(state, "actor", json_object_new_string(actor ? actor : "web"));
    json_object_object_add(state, "created_at", json_object_new_int64(now));
    json_object_object_add(state, "expires_at",
                           json_object_new_int64(now + AI_TOOL_RESUME_TTL));
    json_object_object_add(state, "phase",
                           json_object_new_string("awaiting_authorization"));
    json_object_object_add(state, "provider", json_object_new_string(cfg->provider));
    json_object_object_add(state, "model", json_object_new_string(cfg->model));
    json_object_object_add(state, "api_shape", json_object_new_string(cfg->api_shape));
    json_object_object_add(state, "reasoning_effort",
                           json_object_new_string(cfg->reasoning_effort));
    json_object_object_add(state, "tool_policy", json_object_new_string(cfg->tool_policy));
    json_object_object_add(state, "temperature", json_object_new_double(cfg->temperature));
    json_object_object_add(state, "max_tokens", json_object_new_int(cfg->max_tokens));
    json_object_object_add(state, "tool_round", json_object_new_int(tool_round));
    json_object_object_add(state, "prompt_bytes",
                           json_object_new_int64((int64_t)prompt_bytes));
    json_object_object_add(state, "tool_result_bytes",
                           json_object_new_int64((int64_t)tool_result_bytes));
    json_object_object_add(state, "history_body", history_body ?
                           json_object_get(history_body) : json_object_new_object());
    json_object_object_add(state, "messages", json_object_get(messages));
    json_object_object_add(state, "provider_calls", json_object_get(provider_calls));
    json_object_object_add(state, "round_executions", json_object_get(round_executions));
    json_object_object_add(state, "all_executed", json_object_get(all_executed));
    if (ai_resume_state_save(state) != 0) {
        json_object_put(state);
        token[0] = 0;
        state = NULL;
    }
    flock(create_lock, LOCK_UN);
    close(create_lock);
    return state;
}

static struct json_object *ai_resume_authorizations(const char *conversation_id)
{
    struct json_object *request = json_object_new_object();
    struct json_object *response;
    json_object_object_add(request, "conversation_id",
                           json_object_new_string(conversation_id));
    response = jmx_app_core_invoke("ai_tool_authorizations_get", request, 3000);
    json_object_put(request);
    return response;
}

static struct json_object *ai_resume_find_authorization(struct json_object *items,
                                                         const char *call_id)
{
    if (!items || !json_object_is_type(items, json_type_array)) return NULL;
    for (int i = 0; i < json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);
        if (!strcmp(ai_json_string(item, "tool_call_id", ""), call_id)) return item;
    }
    return NULL;
}

static struct json_object *ai_resume_execution_response(struct json_object *authorization)
{
    struct json_object *response = json_object_new_object();
    struct json_object *data = json_object_new_object();
    struct json_object *result = NULL;
    const char *status = ai_json_string(authorization, "status", "execution_failed");
    int ok = !strcmp(status, "executed");
    json_object_object_add(response, "code", json_object_new_int(ok ? 2000 : 5000));
    json_object_object_add(data, "ok", json_object_new_boolean(ok));
    json_object_object_add(data, "status", json_object_new_string(status));
    json_object_object_add(data, "auth_id", json_object_new_int(
        json_object_get_int(json_object_object_get(authorization, "id"))));
    json_object_object_add(data, "tool_call_id", json_object_new_string(
        ai_json_string(authorization, "tool_call_id", "")));
    json_object_object_add(data, "tool", json_object_new_string(
        ai_json_string(authorization, "tool_id", "")));
    if (json_object_object_get_ex(authorization, "result", &result) && result)
        json_object_object_add(data, "result", json_object_get(result));
    if (!ok)
        json_object_object_add(data, "error", json_object_new_string(
            !strcmp(status, "denied") ? "authorization_denied" :
            ai_json_string(authorization, "error", "tool_execution_failed")));
    json_object_object_add(response, "data", data);
    return response;
}

static void ai_resume_merge_executions(struct json_object *all,
                                       struct json_object *round)
{
    if (!all || !round) return;
    for (int i = 0; i < json_object_array_length(round); i++) {
        struct json_object *item = json_object_array_get_idx(round, i);
        const char *call_id = ai_json_string(item, "tool_call_id", "");
        int exists = 0;
        for (int j = 0; j < json_object_array_length(all); j++)
            if (!strcmp(ai_json_string(json_object_array_get_idx(all, j),
                                       "tool_call_id", ""), call_id)) {
                exists = 1;
                break;
            }
        if (!exists) json_object_array_add(all, json_object_get(item));
    }
}

static int ai_resume_result_bytes(struct json_object *executions, size_t *total)
{
    size_t bytes = 0;
    if (!executions || !json_object_is_type(executions, json_type_array) || !total)
        return -1;
    for (int i = 0; i < json_object_array_length(executions); i++) {
        struct json_object *response = NULL;
        const char *serialized;
        size_t len;
        json_object_object_get_ex(json_object_array_get_idx(executions, i),
                                  "execution", &response);
        serialized = response ? json_object_to_json_string_ext(
            response, JSON_C_TO_STRING_PLAIN) : "";
        len = serialized ? strlen(serialized) : 0;
        if (!len || len > AI_MAX_TOOL_RESULT_BYTES ||
            bytes > AI_MAX_TOOL_RESULTS_TOTAL - len)
            return -1;
        bytes += len;
    }
    *total = bytes;
    return 0;
}

static struct json_object *ai_resume_waiting_response(struct json_object *state,
                                                       struct json_object *pending,
                                                       struct json_object *executed)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "conversation_id", json_object_new_string(
        ai_json_string(state, "conversation_id", "")));
    json_object_object_add(data, "resume_token", json_object_new_string(
        ai_json_string(state, "resume_token", "")));
    json_object_object_add(data, "status",
                           json_object_new_string("waiting_authorizations"));
    json_object_object_add(data, "pending_authorizations",
                           pending ? json_object_get(pending) : json_object_new_array());
    json_object_object_add(data, "tool_executions",
                           executed ? json_object_get(executed) : json_object_new_array());
    json_object_object_add(data, "tool_loop_complete", json_object_new_boolean(0));
    return ai_success(data, "webd.ai.tool_resume");
}

static int ai_resume_config_load(struct ai_config *cfg, struct json_object *state)
{
    if (ai_config_load(cfg) != 0 || !ai_config_ready(cfg) ||
        strcmp(cfg->provider, ai_json_string(state, "provider", "")))
        return -1;
    snprintf(cfg->model, sizeof(cfg->model), "%s", ai_json_string(state, "model", ""));
    snprintf(cfg->api_shape, sizeof(cfg->api_shape), "%s",
             ai_json_string(state, "api_shape", "chat_completions"));
    snprintf(cfg->reasoning_effort, sizeof(cfg->reasoning_effort), "%s",
             ai_json_string(state, "reasoning_effort", "auto"));
    snprintf(cfg->tool_policy, sizeof(cfg->tool_policy), "%s",
             ai_json_string(state, "tool_policy", "confirm_medium"));
    cfg->temperature = json_object_get_double(json_object_object_get(state, "temperature"));
    cfg->max_tokens = json_object_get_int(json_object_object_get(state, "max_tokens"));
    return cfg->model[0] ? 0 : -1;
}

static struct json_object *ai_resume_reconcile_authorizations(
    struct json_object *state, const char *actor, struct ai_config *cfg,
    struct json_object *messages, struct json_object *all,
    int *tool_round, size_t *tool_result_bytes, int *http_status)
{
    struct json_object *provider_calls = NULL, *round = NULL;
    struct json_object *auth_response, *auth_data, *items = NULL;
    struct json_object *pending;
    const char *conversation_id = ai_json_string(state, "conversation_id", "");

    if (strcmp(ai_json_string(state, "phase", ""), "awaiting_authorization"))
        return NULL;
    auth_response = ai_resume_authorizations(conversation_id);
    auth_data = ai_core_data(auth_response);
    pending = json_object_new_array();
    json_object_object_get_ex(state, "provider_calls", &provider_calls);
    json_object_object_get_ex(state, "round_executions", &round);
    if (!pending || !auth_data ||
        !json_object_object_get_ex(auth_data, "items", &items) ||
        !provider_calls || !round) {
        if (auth_response) json_object_put(auth_response);
        if (pending) json_object_put(pending);
        if (http_status) *http_status = 503;
        return ai_error("authorization_state_unavailable",
                        "AI authorization state is unavailable", 503,
                        0, NULL, NULL);
    }
    for (int i = 0; i < json_object_array_length(round); i++) {
        struct json_object *execution = json_object_array_get_idx(round, i);
        struct json_object *old_response = NULL, *old_data = NULL;
        const char *old_status = "";
        const char *call_id = ai_json_string(execution, "tool_call_id", "");
        struct json_object *authorization;
        const char *auth_status;

        json_object_object_get_ex(execution, "execution", &old_response);
        old_data = ai_core_data(old_response);
        old_status = old_data ? ai_json_string(old_data, "status", "") : "";
        if (strcmp(old_status, "pending_authorization")) continue;
        authorization = ai_resume_find_authorization(items, call_id);
        if (!authorization ||
            strcmp(ai_json_string(authorization, "actor", ""), actor)) {
            json_object_array_add(pending, json_object_get(execution));
            continue;
        }
        auth_status = ai_json_string(authorization, "status", "pending");
        if (!strcmp(auth_status, "pending") || !strcmp(auth_status, "executing")) {
            json_object_array_add(pending, json_object_get(execution));
            continue;
        }
        json_object_object_add(execution, "execution",
                               ai_resume_execution_response(authorization));
    }
    json_object_put(auth_response);
    if (json_object_array_length(pending) > 0) {
        struct json_object *response = ai_resume_waiting_response(state, pending, all);
        json_object_put(pending);
        if (http_status) *http_status = 202;
        return response;
    }
    json_object_put(pending);
    ai_resume_merge_executions(all, round);
    if (ai_resume_result_bytes(all, tool_result_bytes) != 0) {
        if (http_status) *http_status = 413;
        return ai_error("tool_result_too_large",
                        "Tool results exceeded the model feedback limit",
                        413, 0, NULL, NULL);
    }
    ai_append_tool_feedback(cfg, messages, provider_calls, round);
    (*tool_round)++;
    json_object_object_add(state, "phase", json_object_new_string("provider_pending"));
    json_object_object_add(state, "tool_round", json_object_new_int(*tool_round));
    json_object_object_add(state, "tool_result_bytes",
                           json_object_new_int64((int64_t)*tool_result_bytes));
    json_object_object_add(state, "provider_calls", json_object_new_array());
    json_object_object_add(state, "round_executions", json_object_new_array());
    json_object_object_add(state, "expires_at",
                           json_object_new_int64(time(NULL) + AI_TOOL_RESUME_TTL));
    if (ai_resume_state_save(state) != 0) {
        if (http_status) *http_status = 507;
        return ai_error("resume_storage_failed",
                        "AI continuation checkpoint could not be saved",
                        507, 0, NULL, NULL);
    }
    return NULL;
}

static struct json_object *ai_resume_run_locked(struct json_object *state,
                                                 const char *actor,
                                                 int *http_status)
{
    struct ai_config cfg;
    struct ai_result result = {};
    struct json_object *messages = NULL, *history_body = NULL;
    struct json_object *round = NULL, *all = NULL, *data = NULL;
    const char *token = ai_json_string(state, "resume_token", "");
    const char *conversation_id = ai_json_string(state, "conversation_id", "");
    int tool_round = json_object_get_int(json_object_object_get(state, "tool_round"));
    size_t prompt_bytes = (size_t)json_object_get_int64(
        json_object_object_get(state, "prompt_bytes"));
    size_t tool_result_bytes = (size_t)json_object_get_int64(
        json_object_object_get(state, "tool_result_bytes"));
    int slot = -1, status = 502;
    int64_t started = ai_now_ms();

    if (strcmp(ai_json_string(state, "actor", ""), actor ? actor : "")) {
        if (http_status) *http_status = 403;
        return ai_error("resume_actor_mismatch",
                        "Only the original conversation actor can resume it",
                        403, 0, NULL, NULL);
    }
    if (json_object_get_int64(json_object_object_get(state, "expires_at")) < time(NULL)) {
        ai_resume_state_delete(token);
        if (http_status) *http_status = 410;
        return ai_error("resume_expired", "AI tool continuation expired",
                        410, 0, NULL, NULL);
    }
    if (ai_resume_config_load(&cfg, state) != 0) {
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = 409;
        return ai_error("resume_provider_changed",
                        "The configured provider no longer matches this continuation",
                        409, 0, NULL, NULL);
    }
    json_object_object_get_ex(state, "messages", &messages);
    json_object_object_get_ex(state, "history_body", &history_body);
    json_object_object_get_ex(state, "all_executed", &all);
    if (!messages || !json_object_is_type(messages, json_type_array) ||
        !history_body || !json_object_is_type(history_body, json_type_object) ||
        !all ||
        !json_object_is_type(all, json_type_array)) {
        if (http_status) *http_status = 500;
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_error("resume_state_invalid", "AI tool continuation is invalid",
                        500, 0, NULL, NULL);
    }
    if (ai_rate_limited(actor, "ai.tool.resume")) {
        if (http_status) *http_status = 429;
        ai_audit(actor, "ai.tool.resume", &cfg, conversation_id,
                 ai_now_ms() - started, "rate_limited");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_error("rate_limited", "AI continuation rate limit exceeded",
                        429, 0, NULL, NULL);
    }
    {
        struct json_object *reconcile = ai_resume_reconcile_authorizations(
            state, actor, &cfg, messages, all, &tool_round,
            &tool_result_bytes, http_status);
        if (reconcile) {
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return reconcile;
        }
    }
    slot = ai_acquire_slot();
    if (slot < 0) {
        if (http_status) *http_status = 429;
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_error("ai_busy", "AI runtime concurrency limit reached",
                        429, 0, NULL, NULL);
    }
    for (; tool_round <= AI_MAX_TOOL_ROUNDS; tool_round++) {
        struct json_object *tool_calls = NULL;
        data = ai_call_chat(&cfg, messages, 0, &result);
        if (!data) break;
        if (!json_object_object_get_ex(data, "tool_calls", &tool_calls) || !tool_calls ||
            !json_object_is_type(tool_calls, json_type_array) ||
            json_object_array_length(tool_calls) == 0)
            break;
        if (tool_round == AI_MAX_TOOL_ROUNDS ||
            json_object_array_length(tool_calls) > AI_MAX_TOOL_CALLS_PER_ROUND) {
            json_object_put(data);
            data = NULL;
            snprintf(result.provider_code, sizeof(result.provider_code), "%s",
                     tool_round == AI_MAX_TOOL_ROUNDS ? "tool_round_limit" :
                                                       "too_many_tool_calls");
            break;
        }
        round = json_object_new_array();
        struct json_object *pending = json_object_new_array();
        for (int i = 0; i < json_object_array_length(tool_calls); i++) {
            struct json_object *execution = ai_execute_tool_call(
                &cfg, json_object_array_get_idx(tool_calls, i), conversation_id,
                actor, i, &tool_result_bytes);
            ai_tool_execution_collect(execution, all, pending);
            json_object_array_add(round, execution);
        }
        if (json_object_array_length(pending) > 0) {
            json_object_object_add(state, "phase",
                                   json_object_new_string("awaiting_authorization"));
            json_object_object_add(state, "tool_round", json_object_new_int(tool_round));
            json_object_object_add(state, "tool_result_bytes",
                                   json_object_new_int64((int64_t)tool_result_bytes));
            json_object_object_add(state, "provider_calls", json_object_get(tool_calls));
            json_object_object_add(state, "round_executions", json_object_get(round));
            json_object_object_add(state, "expires_at",
                                   json_object_new_int64(time(NULL) + AI_TOOL_RESUME_TTL));
            if (ai_resume_state_save(state) != 0) {
                json_object_put(pending);
                json_object_put(round);
                json_object_put(data);
                data = NULL;
                snprintf(result.provider_code, sizeof(result.provider_code),
                         "resume_storage_failed");
                break;
            }
            struct json_object *response = ai_resume_waiting_response(state, pending, all);
            json_object_put(pending);
            json_object_put(round);
            json_object_put(data);
            close(slot);
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            if (http_status) *http_status = 202;
            return response;
        }
        json_object_put(pending);
        ai_resume_merge_executions(all, round);
        if (ai_resume_result_bytes(all, &tool_result_bytes) != 0) {
            json_object_put(round);
            json_object_put(data);
            data = NULL;
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "tool_result_too_large");
            break;
        }
        ai_append_tool_feedback(&cfg, messages, tool_calls, round);
        json_object_put(round);
        json_object_put(data);
        data = NULL;
        json_object_object_add(state, "phase", json_object_new_string("provider_pending"));
        json_object_object_add(state, "tool_round", json_object_new_int(tool_round + 1));
        json_object_object_add(state, "tool_result_bytes",
                               json_object_new_int64((int64_t)tool_result_bytes));
        json_object_object_add(state, "provider_calls", json_object_new_array());
        json_object_object_add(state, "round_executions", json_object_new_array());
        json_object_object_add(state, "expires_at",
                               json_object_new_int64(time(NULL) + AI_TOOL_RESUME_TTL));
        if (ai_resume_state_save(state) != 0) {
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "resume_storage_failed");
            break;
        }
        memset(&result, 0, sizeof(result));
    }
    if (!data) {
        const char *code = ai_error_code(&result, &status);
        close(slot);
        ai_audit(actor, "ai.tool.resume", &cfg, conversation_id,
                 ai_now_ms() - started, code);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = status;
        return ai_error(code, "AI provider continuation failed", status,
                        result.provider_status, result.provider_code,
                        result.provider_message);
    }
    json_object_object_add(data, "conversation_id",
                           json_object_new_string(conversation_id));
    json_object_object_add(data, "resume_token", json_object_new_string(token));
    json_object_object_add(data, "status", json_object_new_string("completed"));
    json_object_object_add(data, "prompt_bytes",
                           json_object_new_int64((int64_t)prompt_bytes));
    json_object_object_add(data, "streaming", json_object_new_boolean(0));
    json_object_object_add(data, "tool_executions", json_object_get(all));
    json_object_object_add(data, "pending_authorizations", json_object_new_array());
    json_object_object_del(data, "tool_execution_supported");
    json_object_object_add(data, "tool_execution_supported", json_object_new_boolean(1));
    json_object_object_add(data, "tool_loop_complete", json_object_new_boolean(1));
    json_object_object_add(data, "tool_rounds", json_object_new_int(tool_round));
    json_object_object_add(data, "tool_result_bytes",
                           json_object_new_int64((int64_t)tool_result_bytes));
    if (ai_conversation_finalize(&cfg, history_body, data,
                                 conversation_id) != 0) {
        close(slot);
        json_object_put(data);
        ai_audit(actor, "ai.tool.resume", &cfg, conversation_id,
                 ai_now_ms() - started, "conversation_history_save_failed");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = 500;
        return ai_error("conversation_history_save_failed",
                        "AI response could not be persisted",
                        500, 0, NULL, NULL);
    }
    close(slot);
    ai_resume_state_delete(token);
    ai_audit(actor, "ai.tool.resume", &cfg, conversation_id,
             ai_now_ms() - started, "success");
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
    if (http_status) *http_status = 200;
    return ai_success(data, "webd.ai.tool_resume");
}

struct json_object *webd_ai_runtime_resume(const char *resume_token,
                                           const char *actor,
                                           int *http_status)
{
    char path[256], lock_path[256];
    struct json_object *state, *response;
    int lock_fd;

    if (!ai_resume_token_ok(resume_token) ||
        ai_resume_paths(resume_token, path, sizeof(path), lock_path, sizeof(lock_path)) != 0) {
        if (http_status) *http_status = 400;
        return ai_error("invalid_resume_token", "AI resume token is invalid",
                        400, 0, NULL, NULL);
    }
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        if (http_status) *http_status = 409;
        return ai_error("continuation_busy", "AI continuation is already running",
                        409, 0, NULL, NULL);
    }
    state = ai_resume_state_load(resume_token);
    if (!state) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        if (http_status) *http_status = 404;
        return ai_error("resume_not_found", "AI continuation was not found",
                        404, 0, NULL, NULL);
    }
    response = ai_resume_run_locked(state, actor, http_status);
    json_object_put(state);
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    if (access(path, F_OK) != 0) unlink(lock_path);
    return response;
}

static int ai_resume_stream_run_locked(int fd, struct json_object *resume_state,
                                       const char *actor)
{
    struct ai_config cfg;
    struct ai_result result = {};
    struct ai_stream_state stream = { .fd = fd, .result = &result };
    struct json_object *messages = NULL, *history_body = NULL;
    struct json_object *all = NULL, *request = NULL;
    struct json_object *data = NULL, *usage = NULL;
    const char *token = ai_json_string(resume_state, "resume_token", "");
    const char *conversation_id = ai_json_string(resume_state, "conversation_id", "");
    int tool_round = json_object_get_int(json_object_object_get(resume_state, "tool_round"));
    size_t prompt_bytes = (size_t)json_object_get_int64(
        json_object_object_get(resume_state, "prompt_bytes"));
    size_t tool_result_bytes = (size_t)json_object_get_int64(
        json_object_object_get(resume_state, "tool_result_bytes"));
    int64_t usage_prompt_total = 0, usage_completion_total = 0;
    int64_t started = ai_now_ms();
    int slot = -1, status = 502, requires_action = 0;
    char endpoint[768];

    if (strcmp(ai_json_string(resume_state, "actor", ""), actor ? actor : ""))
        return ai_stream_send_error(fd, ai_error("resume_actor_mismatch",
            "Only the original conversation actor can resume it",
            403, 0, NULL, NULL), 403);
    if (json_object_get_int64(json_object_object_get(resume_state, "expires_at")) <
        time(NULL)) {
        ai_resume_state_delete(token);
        return ai_stream_send_error(fd, ai_error("resume_expired",
            "AI tool continuation expired", 410, 0, NULL, NULL), 410);
    }
    if (ai_resume_config_load(&cfg, resume_state) != 0) {
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_stream_send_error(fd, ai_error("resume_provider_changed",
            "The configured provider no longer matches this continuation",
            409, 0, NULL, NULL), 409);
    }
    json_object_object_get_ex(resume_state, "messages", &messages);
    json_object_object_get_ex(resume_state, "history_body", &history_body);
    json_object_object_get_ex(resume_state, "all_executed", &all);
    if (!messages || !json_object_is_type(messages, json_type_array) ||
        !history_body || !json_object_is_type(history_body, json_type_object) ||
        !all || !json_object_is_type(all, json_type_array)) {
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_stream_send_error(fd, ai_error("resume_state_invalid",
            "AI tool continuation is invalid", 500, 0, NULL, NULL), 500);
    }
    if (ai_rate_limited(actor, "ai.tool.resume")) {
        ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                 ai_now_ms() - started, "rate_limited");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_stream_send_error(fd, ai_error("rate_limited",
            "AI continuation rate limit exceeded", 429, 0, NULL, NULL), 429);
    }
    {
        struct json_object *reconcile = ai_resume_reconcile_authorizations(
            resume_state, actor, &cfg, messages, all, &tool_round,
            &tool_result_bytes, &status);
        if (reconcile) {
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return ai_stream_send_error(fd, reconcile, status);
        }
    }
    slot = ai_acquire_slot();
    if (slot < 0) {
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_stream_send_error(fd, ai_error("ai_busy",
            "AI runtime concurrency limit reached", 429, 0, NULL, NULL), 429);
    }
    snprintf(stream.conversation_id, sizeof(stream.conversation_id), "%s",
             conversation_id);
    snprintf(stream.response_id, sizeof(stream.response_id), "resp-%lld-%ld",
             (long long)ai_now_ms(), (long)getpid());
    snprintf(stream.finish_reason, sizeof(stream.finish_reason), "stop");
    stream.tool_calls = json_object_new_array();
    stream.tool_parts = json_object_new_array();
    request = ai_stream_request(&cfg, messages, endpoint, sizeof(endpoint));
    if (!request || !stream.tool_calls || !stream.tool_parts ||
        ai_response_register(&stream, actor) != 0) {
        if (request) json_object_put(request);
        if (stream.tool_calls) json_object_put(stream.tool_calls);
        if (stream.tool_parts) json_object_put(stream.tool_parts);
        close(slot);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return ai_stream_send_error(fd, ai_error("stream_state_unavailable",
            "AI resume stream state could not be registered",
            500, 0, NULL, NULL), 500);
    }
    if (http_send_sse_header(fd) != 0) {
        ai_response_unregister(&stream);
        json_object_put(request);
        json_object_put(stream.tool_calls);
        json_object_put(stream.tool_parts);
        close(slot);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        return -1;
    }
    data = json_object_new_object();
    json_object_object_add(data, "resume_token", json_object_new_string(token));
    json_object_object_add(data, "model", json_object_new_string(cfg.model));
    json_object_object_add(data, "provider", json_object_new_string(cfg.provider));
    ai_stream_emit(&stream, "conversation.resumed", data);
    json_object_put(data);
    data = json_object_new_object();
    json_object_object_add(data, "resume_token", json_object_new_string(token));
    json_object_object_add(data, "model", json_object_new_string(cfg.model));
    json_object_object_add(data, "reasoning_effort",
                           json_object_new_string(cfg.reasoning_effort));
    ai_stream_emit(&stream, "response.started", data);
    json_object_put(data);

    for (; tool_round <= AI_MAX_TOOL_ROUNDS; tool_round++) {
        struct json_object *round_executions = NULL, *round_pending = NULL;
        size_t reply_before = stream.reply_len;
        int round_ok = ai_stream_provider_round(&cfg, request, &stream, &result) == 0;

        usage_prompt_total += stream.prompt_tokens;
        usage_completion_total += stream.completion_tokens;
        if (stream.disconnected || stream.cancelled || !round_ok) break;
        if (stream.reply_len == reply_before &&
            json_object_array_length(stream.tool_parts) == 0) {
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "provider_response_invalid");
            stream.provider_failed = 1;
            break;
        }
        if (json_object_array_length(stream.tool_parts) == 0) break;
        if (tool_round == AI_MAX_TOOL_ROUNDS ||
            ai_stream_tools_finalize(&stream, &cfg) != 0) {
            snprintf(result.provider_code, sizeof(result.provider_code), "%s",
                     tool_round == AI_MAX_TOOL_ROUNDS ? "tool_round_limit" :
                                                       "invalid_tool_arguments");
            stream.provider_failed = 1;
            break;
        }
        round_executions = json_object_new_array();
        round_pending = json_object_new_array();
        if (!round_executions || !round_pending) {
            if (round_executions) json_object_put(round_executions);
            if (round_pending) json_object_put(round_pending);
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "allocation_failed");
            stream.provider_failed = 1;
            break;
        }
        for (int i = 0; i < json_object_array_length(stream.tool_calls); i++) {
            struct json_object *execution = ai_execute_tool_call(
                &cfg, json_object_array_get_idx(stream.tool_calls, i),
                conversation_id, actor, i, &tool_result_bytes);
            struct json_object *response = NULL, *response_data = NULL;
            const char *execution_status = "execution_failed";
            ai_tool_execution_collect(execution, all, round_pending);
            json_object_array_add(round_executions, execution);
            json_object_object_get_ex(execution, "execution", &response);
            response_data = ai_core_data(response);
            if (response_data)
                execution_status = ai_json_string(response_data, "status",
                                                  execution_status);
            data = json_object_new_object();
            json_object_object_add(data, "tool_execution", json_object_get(execution));
            json_object_object_add(data, "status",
                                   json_object_new_string(execution_status));
            ai_stream_emit(&stream,
                !strcmp(execution_status, "pending_authorization") ?
                    "tool.call.requires_action" : "tool.call.result", data);
            json_object_put(data);
        }
        if (json_object_array_length(round_pending) > 0) {
            json_object_object_add(resume_state, "phase",
                json_object_new_string("awaiting_authorization"));
            json_object_object_add(resume_state, "tool_round",
                                   json_object_new_int(tool_round));
            json_object_object_add(resume_state, "tool_result_bytes",
                json_object_new_int64((int64_t)tool_result_bytes));
            json_object_object_add(resume_state, "provider_calls",
                                   json_object_get(stream.tool_calls));
            json_object_object_add(resume_state, "round_executions",
                                   json_object_get(round_executions));
            json_object_object_add(resume_state, "expires_at",
                json_object_new_int64(time(NULL) + AI_TOOL_RESUME_TTL));
            if (ai_resume_state_save(resume_state) != 0) {
                snprintf(result.provider_code, sizeof(result.provider_code),
                         "resume_storage_failed");
                stream.provider_failed = 1;
            } else {
                data = json_object_new_object();
                json_object_object_add(data, "status",
                                       json_object_new_string("requires_action"));
                json_object_object_add(data, "resume_token",
                                       json_object_new_string(token));
                json_object_object_add(data, "resume_expires_at", json_object_get(
                    json_object_object_get(resume_state, "expires_at")));
                json_object_object_add(data, "resume_endpoint",
                    json_object_new_string("/api/v1/ai/tool-resume"));
                json_object_object_add(data, "resume_stream_endpoint",
                    json_object_new_string("/api/v1/ai/tool-resume/stream"));
                json_object_object_add(data, "pending_authorizations",
                                       json_object_get(round_pending));
                json_object_object_add(data, "tool_executions",
                                       json_object_get(all));
                json_object_object_add(data, "tool_loop_complete",
                                       json_object_new_boolean(0));
                ai_stream_emit(&stream, "response.requires_action", data);
                json_object_put(data);
                requires_action = 1;
            }
            json_object_put(round_pending);
            json_object_put(round_executions);
            break;
        }
        ai_append_tool_feedback(&cfg, messages, stream.tool_calls,
                                round_executions);
        json_object_put(round_pending);
        json_object_put(round_executions);
        json_object_object_add(resume_state, "phase",
                               json_object_new_string("provider_pending"));
        json_object_object_add(resume_state, "tool_round",
                               json_object_new_int(tool_round + 1));
        json_object_object_add(resume_state, "tool_result_bytes",
                               json_object_new_int64((int64_t)tool_result_bytes));
        json_object_object_add(resume_state, "provider_calls",
                               json_object_new_array());
        json_object_object_add(resume_state, "round_executions",
                               json_object_new_array());
        json_object_object_add(resume_state, "expires_at",
                               json_object_new_int64(time(NULL) + AI_TOOL_RESUME_TTL));
        if (ai_resume_state_save(resume_state) != 0) {
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "resume_storage_failed");
            stream.provider_failed = 1;
            break;
        }
        json_object_put(request);
        request = ai_stream_request(&cfg, messages, endpoint, sizeof(endpoint));
        if (!request) {
            snprintf(result.provider_code, sizeof(result.provider_code),
                     "provider_request_invalid");
            stream.provider_failed = 1;
            break;
        }
        json_object_put(stream.tool_calls);
        json_object_put(stream.tool_parts);
        stream.tool_calls = json_object_new_array();
        stream.tool_parts = json_object_new_array();
        stream.prompt_tokens = 0;
        stream.completion_tokens = 0;
        stream.total_tokens = 0;
        snprintf(stream.finish_reason, sizeof(stream.finish_reason), "stop");
    }
    if (!stream.disconnected) {
        if (stream.cancelled) {
            data = json_object_new_object();
            json_object_object_add(data, "resume_token", json_object_new_string(token));
            json_object_object_add(data, "reason",
                                   json_object_new_string("cancelled_by_user"));
            json_object_object_add(data, "partial_reply",
                json_object_new_string(stream.reply ? stream.reply : ""));
            ai_stream_emit(&stream, "response.cancelled", data);
            json_object_put(data);
            ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                     ai_now_ms() - started, "cancelled");
        } else if (requires_action) {
            ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                     ai_now_ms() - started, "requires_action");
        } else if (!stream.provider_failed && result.curl_code == CURLE_OK &&
                   result.provider_status >= 200 && result.provider_status < 300) {
            int emit_ok;
            data = json_object_new_object();
            usage = json_object_new_object();
            json_object_object_add(data, "resume_token", json_object_new_string(token));
            json_object_object_add(data, "reply",
                json_object_new_string(stream.reply ? stream.reply : ""));
            json_object_object_add(data, "model", json_object_new_string(cfg.model));
            json_object_object_add(data, "provider", json_object_new_string(cfg.provider));
            json_object_object_add(data, "reasoning_effort",
                                   json_object_new_string(cfg.reasoning_effort));
            json_object_object_add(data, "finish_reason",
                                   json_object_new_string(stream.finish_reason));
            json_object_object_add(usage, "prompt_tokens",
                                   json_object_new_int64(usage_prompt_total));
            json_object_object_add(usage, "completion_tokens",
                                   json_object_new_int64(usage_completion_total));
            json_object_object_add(usage, "total_tokens", json_object_new_int64(
                usage_prompt_total + usage_completion_total));
            json_object_object_add(data, "usage", usage);
            json_object_object_add(data, "streaming", json_object_new_boolean(1));
            json_object_object_add(data, "tool_executions", json_object_get(all));
            json_object_object_add(data, "pending_authorizations",
                                   json_object_new_array());
            json_object_object_add(data, "tool_execution_supported",
                                   json_object_new_boolean(1));
            json_object_object_add(data, "tool_loop_complete",
                                   json_object_new_boolean(1));
            json_object_object_add(data, "tool_rounds",
                                   json_object_new_int(tool_round));
            json_object_object_add(data, "tool_result_bytes",
                json_object_new_int64((int64_t)tool_result_bytes));
            json_object_object_add(data, "prompt_bytes",
                                   json_object_new_int64((int64_t)prompt_bytes));
            if (ai_conversation_finalize(&cfg, history_body, data,
                                         conversation_id) != 0) {
                struct json_object *error = ai_error(
                    "conversation_history_save_failed",
                    "AI response could not be persisted", 500, 0, NULL, NULL);
                ai_stream_emit(&stream, "response.failed", error);
                json_object_put(error);
                ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                         ai_now_ms() - started,
                         "conversation_history_save_failed");
                emit_ok = -1;
            } else {
                emit_ok = ai_stream_emit(&stream, "response.completed", data);
            }
            json_object_put(data);
            if (emit_ok == 0) {
                ai_resume_state_delete(token);
                ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                         ai_now_ms() - started, "success");
            }
        } else {
            const char *code;
            if (stream.provider_failed && result.curl_code == CURLE_WRITE_ERROR)
                result.curl_code = CURLE_OK;
            code = ai_error_code(&result, &status);
            data = ai_error(code, "AI provider continuation stream failed",
                            status, result.provider_status,
                            result.provider_code, result.provider_message);
            ai_stream_emit(&stream, "response.failed", data);
            json_object_put(data);
            ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                     ai_now_ms() - started, code);
        }
    } else {
        ai_audit(actor, "ai.tool.resume.stream", &cfg, conversation_id,
                 ai_now_ms() - started, "client_disconnected");
    }
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
    json_object_put(request);
    json_object_put(stream.tool_calls);
    json_object_put(stream.tool_parts);
    free(stream.pending);
    free(stream.reply);
    ai_response_unregister(&stream);
    close(slot);
    return stream.disconnected ? -1 : 0;
}

int webd_ai_runtime_resume_stream(int fd, const char *resume_token,
                                  const char *actor)
{
    char path[256], lock_path[256];
    struct json_object *state;
    int lock_fd, rc;

    if (!ai_resume_token_ok(resume_token) ||
        ai_resume_paths(resume_token, path, sizeof(path),
                        lock_path, sizeof(lock_path)) != 0)
        return ai_stream_send_error(fd, ai_error("invalid_resume_token",
            "AI resume token is invalid", 400, 0, NULL, NULL), 400);
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return ai_stream_send_error(fd, ai_error("continuation_busy",
            "AI continuation is already running", 409, 0, NULL, NULL), 409);
    }
    state = ai_resume_state_load(resume_token);
    if (!state) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return ai_stream_send_error(fd, ai_error("resume_not_found",
            "AI continuation was not found", 404, 0, NULL, NULL), 404);
    }
    rc = ai_resume_stream_run_locked(fd, state, actor);
    json_object_put(state);
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    if (access(path, F_OK) != 0) unlink(lock_path);
    return rc;
}

struct json_object *webd_ai_runtime_authorization_resolved(
    struct json_object *authorization_response,
    const char *approver,
    int defer_continuation,
    int *http_status)
{
    struct json_object *authorization = ai_response_data(authorization_response);
    struct json_object *data, *continuation;
    char token[65] = "";
    int continuation_status = 200;
    const char *conversation_id;
    const char *request_actor;

    if (!authorization) {
        if (http_status) *http_status = 500;
        if (authorization_response) json_object_put(authorization_response);
        return ai_error("authorization_response_invalid",
                        "AI authorization response is invalid", 500, 0, NULL, NULL);
    }
    conversation_id = ai_json_string(authorization, "conversation_id", "");
    request_actor = ai_json_string(authorization, "request_actor", "");
    data = json_object_new_object();
    json_object_object_add(data, "authorization", json_object_get(authorization));
    if (!conversation_id[0] || !request_actor[0] ||
        ai_resume_state_find(conversation_id, request_actor, token) != 0) {
        continuation = json_object_new_object();
        json_object_object_add(continuation, "ok", json_object_new_boolean(0));
        json_object_object_add(continuation, "status",
                               json_object_new_string("not_available"));
        json_object_object_add(continuation, "reason",
                               json_object_new_string("resume_state_not_found"));
    } else if (approver && !strcmp(approver, request_actor) && defer_continuation) {
        continuation = json_object_new_object();
        json_object_object_add(continuation, "ok", json_object_new_boolean(1));
        json_object_object_add(continuation, "status",
                               json_object_new_string("ready_to_resume"));
        json_object_object_add(continuation, "resume_token",
                               json_object_new_string(token));
        json_object_object_add(continuation, "resume_endpoint",
                               json_object_new_string("/api/v1/ai/tool-resume"));
        json_object_object_add(continuation, "resume_stream_endpoint",
                               json_object_new_string("/api/v1/ai/tool-resume/stream"));
        continuation_status = 202;
    } else if (approver && !strcmp(approver, request_actor)) {
        continuation = webd_ai_runtime_resume(token, request_actor,
                                              &continuation_status);
    } else {
        continuation = json_object_new_object();
        json_object_object_add(continuation, "ok", json_object_new_boolean(1));
        json_object_object_add(continuation, "status",
                               json_object_new_string("awaiting_original_actor"));
        json_object_object_add(continuation, "reason",
                               json_object_new_string("cross_actor_response_hidden"));
        continuation_status = 202;
    }
    json_object_object_add(data, "continuation", continuation);
    json_object_object_add(data, "continuation_http_status",
                           json_object_new_int(continuation_status));
    json_object_put(authorization_response);
    if (http_status) *http_status = 200;
    return ai_success(data, "webd.ai.authorization");
}

struct json_object *webd_ai_runtime_chat(struct json_object *body,
                                         const char *actor,
                                         int *http_status)
{
    struct ai_config cfg;
    struct ai_result result = {};
    struct json_object *messages = NULL, *data = NULL, *root;
    struct json_object *all_executed = NULL;
    struct json_object *all_pending = NULL;
    struct ai_dispatch_plan dispatch;
    struct json_object *dispatch_attempts = NULL;
    char dispatch_provider_id[65] = "";
    char validation[256] = "";
    char conversation_id[128];
    size_t prompt_bytes = 0;
    size_t tool_result_bytes = 0;
    int slot = -1, status = 400;
    int tool_rounds = 0;
    int64_t started = ai_now_ms();

    if (http_status) *http_status = 400;
    if (!body || !json_object_is_type(body, json_type_object))
        return ai_error("invalid_request", "JSON request body is required", 400, 0, NULL, NULL);
    {
        int select_rc = ai_dispatch_select(&cfg, &dispatch, dispatch_provider_id);
        if (select_rc != 0) {
            ai_dispatch_plan_clear(&dispatch);
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return ai_dispatch_not_configured(select_rc, http_status);
        }
    }
    {
        const char *requested_model = ai_json_string(body, "model", "");
        const char *requested_effort = ai_json_string(body, "reasoning_effort", "");
        if (requested_model[0]) {
            if (!ai_value_ok(requested_model, sizeof(cfg.model) - 1)) {
                memset(cfg.api_key, 0, sizeof(cfg.api_key));
                ai_dispatch_plan_clear(&dispatch);
                return ai_error("invalid_request", "model is invalid", 400, 0, NULL, NULL);
            }
            snprintf(cfg.model, sizeof(cfg.model), "%s", requested_model);
        }
        if (requested_effort[0]) {
            if (!ai_value_ok(requested_effort, sizeof(cfg.reasoning_effort) - 1) ||
                (strcmp(requested_effort, "auto") && strcmp(requested_effort, "none") &&
                 strcmp(requested_effort, "minimal") && strcmp(requested_effort, "low") &&
                 strcmp(requested_effort, "medium") && strcmp(requested_effort, "high") &&
                 strcmp(requested_effort, "xhigh"))) {
                memset(cfg.api_key, 0, sizeof(cfg.api_key));
                ai_dispatch_plan_clear(&dispatch);
                return ai_error("invalid_request", "reasoning_effort is invalid", 400, 0, NULL, NULL);
            }
            snprintf(cfg.reasoning_effort, sizeof(cfg.reasoning_effort), "%s", requested_effort);
        }
    }
    snprintf(conversation_id, sizeof(conversation_id), "%s",
             ai_json_string(body, "conversation_id", ""));
    if (!ai_value_ok(conversation_id, sizeof(conversation_id) - 1))
        snprintf(conversation_id, sizeof(conversation_id), "ai-%lld-%ld",
                 (long long)time(NULL), (long)getpid());
    {
        char active_resume[65] = "";
        if (ai_resume_state_find(conversation_id, actor, active_resume) == 0) {
            struct json_object *details = json_object_new_object();
            struct json_object *error = ai_error(
                "authorization_pending",
                "This conversation already has a pending tool continuation",
                409, 0, NULL, NULL);
            struct json_object *error_obj = NULL;
            json_object_object_add(details, "conversation_id",
                                   json_object_new_string(conversation_id));
            json_object_object_add(details, "resume_token",
                                   json_object_new_string(active_resume));
            json_object_object_add(details, "resume_endpoint",
                                   json_object_new_string("/api/v1/ai/tool-resume"));
            json_object_object_add(details, "resume_stream_endpoint",
                json_object_new_string("/api/v1/ai/tool-resume/stream"));
            if (json_object_object_get_ex(error, "error", &error_obj) && error_obj)
                json_object_object_add(error_obj, "details", details);
            else
                json_object_put(details);
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            ai_dispatch_plan_clear(&dispatch);
            if (http_status) *http_status = 409;
            return error;
        }
    }
    if (ai_rate_limited(actor, "ai.chat")) {
        if (http_status) *http_status = 429;
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "rate_limited");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        ai_dispatch_plan_clear(&dispatch);
        return ai_error("rate_limited", "AI request rate limit exceeded",
                        429, 0, NULL, NULL);
    }
    slot = ai_acquire_slot();
    if (slot < 0) {
        if (http_status) *http_status = 429;
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "concurrency_limited");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        ai_dispatch_plan_clear(&dispatch);
        return ai_error("ai_busy", "AI runtime concurrency limit reached",
                        429, 0, NULL, NULL);
    }
    if (ai_prepare_messages(&cfg, body, actor, &messages, &prompt_bytes,
                            validation, sizeof(validation)) != 0) {
        close(slot);
        if (http_status) *http_status = strstr(validation, "exceeds") ? 413 : 400;
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "validation_failed");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        ai_dispatch_plan_clear(&dispatch);
        return ai_error(strstr(validation, "exceeds") ? "context_too_large" :
                        "invalid_request", validation,
                        http_status ? *http_status : 400, 0, NULL, NULL);
    }
    all_executed = json_object_new_array();
    all_pending = json_object_new_array();
    if (!all_executed || !all_pending) {
        if (all_executed) json_object_put(all_executed);
        if (all_pending) json_object_put(all_pending);
        json_object_put(messages);
        close(slot);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        ai_dispatch_plan_clear(&dispatch);
        if (http_status) *http_status = 500;
        return ai_error("allocation_failed", "AI tool loop allocation failed",
                        500, 0, NULL, NULL);
    }
    for (tool_rounds = 0; tool_rounds <= AI_MAX_TOOL_ROUNDS; tool_rounds++) {
        struct json_object *tool_calls = NULL;
        data = ai_call_chat(&cfg, messages, 0, &result);
        /* Failover only on the first round: once a later round has run, tool
         * results are already bound to the provider that produced them. */
        if (!data && tool_rounds == 0 && !strcmp(dispatch.strategy, "failover")) {
            /* Resume after whichever candidate was actually used, not blindly
             * from index 1: ai_dispatch_select() may have skipped incomplete
             * rows when it picked the first provider. */
            int start = 0;
            while (start < dispatch.count &&
                   strcmp(dispatch.items[start].id, dispatch_provider_id))
                start++;
            for (int next = start + 1; next < dispatch.count && !data; next++) {
                if (!ai_dispatch_should_failover(&result))
                    break;
                if (!dispatch_attempts)
                    dispatch_attempts = json_object_new_array();
                {
                    struct json_object *attempt = json_object_new_object();
                    json_object_object_add(attempt, "provider_id",
                        json_object_new_string(dispatch_provider_id));
                    json_object_object_add(attempt, "provider",
                        json_object_new_string(cfg.provider));
                    json_object_object_add(attempt, "error_kind",
                        json_object_new_string(ai_dispatch_error_kind(&result)));
                    json_object_array_add(dispatch_attempts, attempt);
                }
                memset(cfg.api_key, 0, sizeof(cfg.api_key));
                cfg = dispatch.items[next].cfg;
                snprintf(dispatch_provider_id, sizeof(dispatch_provider_id), "%s",
                         dispatch.items[next].id);
                if (!ai_config_ready(&cfg))
                    continue;
                memset(&result, 0, sizeof(result));
                data = ai_call_chat(&cfg, messages, 0, &result);
            }
        }
        if (!data) break;
        if (!json_object_object_get_ex(data, "tool_calls", &tool_calls) || !tool_calls ||
            !json_object_is_type(tool_calls, json_type_array) ||
            json_object_array_length(tool_calls) == 0)
            break;
        if (tool_rounds == AI_MAX_TOOL_ROUNDS ||
            json_object_array_length(tool_calls) > AI_MAX_TOOL_CALLS_PER_ROUND) {
            json_object_put(data);
            data = NULL;
            snprintf(result.provider_code, sizeof(result.provider_code), "%s",
                     tool_rounds == AI_MAX_TOOL_ROUNDS ? "tool_round_limit" :
                                                        "too_many_tool_calls");
            break;
        }
        struct json_object *round_executions = json_object_new_array();
        for (int i = 0; i < json_object_array_length(tool_calls); i++) {
            struct json_object *execution = ai_execute_tool_call(
                &cfg, json_object_array_get_idx(tool_calls, i), conversation_id,
                actor, i, &tool_result_bytes);
            ai_tool_execution_collect(execution, all_executed, all_pending);
            json_object_array_add(round_executions, execution);
        }
        if (json_object_array_length(all_pending) > 0) {
            char resume_token[65] = "";
            struct json_object *resume_state = ai_resume_state_new(
                &cfg, conversation_id, actor, body, messages, tool_calls,
                round_executions, all_executed, tool_rounds, prompt_bytes,
                tool_result_bytes, resume_token);
            if (!resume_state) {
                json_object_put(round_executions);
                json_object_put(data);
                data = NULL;
                snprintf(result.provider_code, sizeof(result.provider_code),
                         "resume_storage_failed");
                break;
            }
            json_object_object_del(data, "pending_authorizations");
            json_object_object_add(data, "pending_authorizations", json_object_get(all_pending));
            json_object_object_add(data, "tool_executions", json_object_get(all_executed));
            json_object_object_del(data, "tool_execution_supported");
            json_object_object_add(data, "tool_execution_supported", json_object_new_boolean(1));
            json_object_object_add(data, "tool_loop_complete", json_object_new_boolean(0));
            json_object_object_add(data, "resume_token",
                                   json_object_new_string(resume_token));
            json_object_object_add(data, "resume_expires_at", json_object_get(
                json_object_object_get(resume_state, "expires_at")));
            json_object_object_add(data, "resume_endpoint",
                                   json_object_new_string("/api/v1/ai/tool-resume"));
            json_object_object_add(data, "resume_stream_endpoint",
                json_object_new_string("/api/v1/ai/tool-resume/stream"));
            json_object_put(resume_state);
            json_object_put(round_executions);
            break;
        }
        ai_append_tool_feedback(&cfg, messages, tool_calls, round_executions);
        json_object_put(round_executions);
        json_object_put(data);
        data = NULL;
        memset(&result, 0, sizeof(result));
    }
    json_object_put(messages);
    if (!data) {
        const char *code = ai_error_code(&result, &status);
        struct json_object *failed = ai_error(code, "AI provider request failed", status,
                        result.provider_status, result.provider_code,
                        result.provider_message);
        struct json_object *error_obj = NULL;

        close(slot);
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, code);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        ai_dispatch_plan_clear(&dispatch);
        json_object_put(all_executed);
        json_object_put(all_pending);
        if (http_status) *http_status = status;
        /* Report every provider that was tried and why it failed, so a
         * failover run is auditable instead of a single opaque error. */
        if (dispatch_attempts &&
            json_object_object_get_ex(failed, "error", &error_obj) && error_obj) {
            struct json_object *details = NULL;
            if (!json_object_object_get_ex(error_obj, "details", &details) || !details) {
                details = json_object_new_object();
                json_object_object_add(error_obj, "details", details);
            }
            json_object_object_add(details, "attempts", dispatch_attempts);
            json_object_object_add(details, "provider_id",
                                   json_object_new_string(dispatch_provider_id));
        } else if (dispatch_attempts) {
            json_object_put(dispatch_attempts);
        }
        return failed;
    }
    if (dispatch_attempts)
        json_object_object_add(data, "dispatch_attempts", dispatch_attempts);
    if (dispatch_provider_id[0])
        json_object_object_add(data, "provider_id",
                               json_object_new_string(dispatch_provider_id));
    json_object_object_add(data, "dispatch_strategy",
                           json_object_new_string(dispatch.strategy));
    json_object_object_add(data, "conversation_id",
                           json_object_new_string(conversation_id));
    json_object_object_add(data, "prompt_bytes",
                           json_object_new_int64((int64_t)prompt_bytes));
    json_object_object_add(data, "streaming", json_object_new_boolean(0));
    json_object_object_add(data, "attachments_redacted",
                           json_object_new_boolean(1));
    struct json_object *existing_field = NULL;
    if (!json_object_object_get_ex(data, "tool_executions", &existing_field))
        json_object_object_add(data, "tool_executions", json_object_get(all_executed));
    if (!json_object_object_get_ex(data, "pending_authorizations", &existing_field))
        json_object_object_add(data, "pending_authorizations", json_object_get(all_pending));
    json_object_object_del(data, "tool_execution_supported");
    json_object_object_add(data, "tool_execution_supported", json_object_new_boolean(1));
    if (!json_object_object_get_ex(data, "tool_loop_complete", &existing_field))
        json_object_object_add(data, "tool_loop_complete", json_object_new_boolean(1));
    json_object_object_add(data, "tool_rounds", json_object_new_int(tool_rounds));
    json_object_object_add(data, "tool_result_bytes", json_object_new_int64((int64_t)tool_result_bytes));
    if (ai_json_string(data, "reply", "")[0] &&
        ai_conversation_finalize(&cfg, body, data, conversation_id) != 0) {
        close(slot);
        json_object_put(data);
        ai_audit(actor, "ai.chat", &cfg, conversation_id,
                 ai_now_ms() - started, "conversation_history_save_failed");
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        ai_dispatch_plan_clear(&dispatch);
        json_object_put(all_executed);
        json_object_put(all_pending);
        if (http_status) *http_status = 500;
        return ai_error("conversation_history_save_failed",
                        "AI response could not be persisted",
                        500, 0, NULL, NULL);
    }
    close(slot);
    root = ai_success(data, "webd.ai.runtime");
    ai_audit(actor, "ai.chat", &cfg, conversation_id,
             ai_now_ms() - started, "success");
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
    ai_dispatch_plan_clear(&dispatch);
    json_object_put(all_executed);
    json_object_put(all_pending);
    if (http_status) *http_status = 200;
    return root;
}

/*
 * provider_id == NULL tests whatever the dispatch policy would use right now;
 * a non-empty id tests that one row and records the result on it.
 */
struct json_object *webd_ai_runtime_provider_test_id(const char *provider_id,
                                                     const char *actor,
                                                     int *http_status)
{
    struct ai_config cfg;
    struct ai_result result = {};
    struct json_object *messages = json_object_new_array(), *data, *root;
    int slot, status = 400;
    char resolved_id[65] = "";
    int64_t started = ai_now_ms();

    if (http_status) *http_status = 503;
    if (provider_id && provider_id[0]) {
        if (ai_provider_config_by_id(provider_id, &cfg) != 0) {
            json_object_put(messages);
            if (http_status) *http_status = 404;
            return ai_error("provider_not_found", "provider id does not exist",
                            404, 0, NULL, NULL);
        }
        snprintf(resolved_id, sizeof(resolved_id), "%s", provider_id);
        if (!ai_config_ready(&cfg)) {
            json_object_put(messages);
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            ai_provider_record_check(resolved_id, 0, -1, "provider_not_configured");
            return ai_error("provider_not_configured",
                            "provider credentials or model are incomplete",
                            503, 0, NULL, NULL);
        }
    } else {
        struct ai_dispatch_plan dispatch;
        int select_rc = ai_dispatch_select(&cfg, &dispatch, resolved_id);
        ai_dispatch_plan_clear(&dispatch);
        if (select_rc != 0) {
            json_object_put(messages);
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return ai_dispatch_not_configured(select_rc, http_status);
        }
    }
    ai_add_message(messages, "user", "Reply with OK.", &(size_t){0}, NULL);
    slot = ai_acquire_slot();
    if (slot < 0) {
        json_object_put(messages);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = 429;
        return ai_error("ai_busy", "AI runtime concurrency limit reached", 429, 0, NULL, NULL);
    }
    data = ai_call_chat(&cfg, messages, 8, &result);
    json_object_put(messages);
    close(slot);
    if (!data) {
        const char *code = ai_error_code(&result, &status);
        struct json_object *failed;
        const char *kind = ai_dispatch_error_kind(&result);

        ai_audit(actor, "ai.provider.test", &cfg, cfg.model,
                 ai_now_ms() - started, code);
        if (resolved_id[0])
            ai_provider_record_check(resolved_id, 0, -1, kind);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = status;
        failed = ai_error(code, "AI provider connection test failed", status,
                          result.provider_status, result.provider_code,
                          result.provider_message);
        {
            struct json_object *error_obj = NULL, *details = NULL;
            if (json_object_object_get_ex(failed, "error", &error_obj) && error_obj) {
                if (!json_object_object_get_ex(error_obj, "details", &details) || !details) {
                    details = json_object_new_object();
                    json_object_object_add(error_obj, "details", details);
                }
                json_object_object_add(details, "error_kind",
                                       json_object_new_string(kind));
                /* Unmeasurable latency is null, never 0. */
                json_object_object_add(details, "latency_ms", NULL);
                if (resolved_id[0])
                    json_object_object_add(details, "provider_id",
                                           json_object_new_string(resolved_id));
            }
        }
        return failed;
    }
    json_object_put(data);
    data = json_object_new_object();
    json_object_object_add(data, "reachable", json_object_new_boolean(1));
    json_object_object_add(data, "authenticated", json_object_new_boolean(1));
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "provider", json_object_new_string(cfg.provider));
    json_object_object_add(data, "model", json_object_new_string(cfg.model));
    json_object_object_add(data, "model_probed", json_object_new_string(cfg.model));
    json_object_object_add(data, "checked_at", json_object_new_int64(time(NULL)));
    if (resolved_id[0])
        json_object_object_add(data, "provider_id",
                               json_object_new_string(resolved_id));
    json_object_object_add(data, "latency_ms",
                           json_object_new_int64(ai_now_ms() - started));
    root = ai_success(data, "webd.ai.provider_test");
    ai_audit(actor, "ai.provider.test", &cfg, cfg.model,
             ai_now_ms() - started, "success");
    if (resolved_id[0])
        ai_provider_record_check(resolved_id, 1,
                                     (int)(ai_now_ms() - started), "");
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
    if (http_status) *http_status = 200;
    return root;
}

struct json_object *webd_ai_runtime_provider_test(const char *actor,
                                                  int *http_status)
{
    return webd_ai_runtime_provider_test_id(NULL, actor, http_status);
}

static struct json_object *ai_model_explicit_value(struct json_object *item,
                                                   const char *key)
{
    struct json_object *value = NULL;
    struct json_object *caps = NULL;

    if (item && json_object_object_get_ex(item, key, &value) && value)
        return value;
    if (item && json_object_object_get_ex(item, "capabilities", &caps) && caps &&
        json_object_is_type(caps, json_type_object) &&
        json_object_object_get_ex(caps, key, &value) && value)
        return value;
    return NULL;
}

static int ai_model_modalities_has(struct json_object *item, const char *wanted)
{
    static const char *keys[] = { "input_modalities", "modalities", NULL };

    for (int k = 0; keys[k]; k++) {
        struct json_object *arr = NULL;
        if (!item || !json_object_object_get_ex(item, keys[k], &arr) || !arr ||
            !json_object_is_type(arr, json_type_array))
            continue;
        for (int i = 0; i < json_object_array_length(arr); i++) {
            struct json_object *entry = json_object_array_get_idx(arr, i);
            const char *s = entry && json_object_is_type(entry, json_type_string) ?
                            json_object_get_string(entry) : "";
            if (s && !strcasecmp(s, wanted))
                return 1;
        }
    }
    return 0;
}

static void ai_model_add_nullable_bool(struct json_object *out,
                                       struct json_object *item,
                                       const char *out_key,
                                       const char *provider_key,
                                       const char *modality)
{
    struct json_object *value = ai_model_explicit_value(item, provider_key);

    if (value && (json_object_is_type(value, json_type_boolean) ||
                  json_object_is_type(value, json_type_int)))
        json_object_object_add(out, out_key,
                               json_object_new_boolean(json_object_get_boolean(value)));
    else if (modality && ai_model_modalities_has(item, modality))
        json_object_object_add(out, out_key, json_object_new_boolean(1));
    else
        json_object_object_add(out, out_key, json_object_new_null());
}

static struct json_object *ai_model_detail(struct json_object *item, const char *id)
{
    static const char *context_keys[] = {
        "context_window", "context_length", "max_context_length", NULL
    };
    struct json_object *out = json_object_new_object();
    int explicit_metadata = 0;

    json_object_object_add(out, "id", json_object_new_string(id ? id : ""));
    ai_model_add_nullable_bool(out, item, "vision", "vision", "image");
    ai_model_add_nullable_bool(out, item, "file_input", "file_input", "file");
    ai_model_add_nullable_bool(out, item, "tool_calling", "tool_calling", NULL);
    ai_model_add_nullable_bool(out, item, "streaming", "streaming", NULL);
    for (int i = 0; context_keys[i]; i++) {
        struct json_object *value = ai_model_explicit_value(item, context_keys[i]);
        if (value && (json_object_is_type(value, json_type_int) ||
                      json_object_is_type(value, json_type_double))) {
            json_object_object_add(out, "context_window",
                                   json_object_new_int64(json_object_get_int64(value)));
            explicit_metadata = 1;
            break;
        }
    }
    if (!json_object_object_get(out, "context_window"))
        json_object_object_add(out, "context_window", json_object_new_null());
    if (item) {
        struct json_object *v = NULL;
        explicit_metadata = explicit_metadata ||
            json_object_object_get_ex(item, "capabilities", &v) ||
            json_object_object_get_ex(item, "input_modalities", &v) ||
            json_object_object_get_ex(item, "modalities", &v) ||
            json_object_object_get_ex(item, "vision", &v) ||
            json_object_object_get_ex(item, "file_input", &v) ||
            json_object_object_get_ex(item, "tool_calling", &v) ||
            json_object_object_get_ex(item, "streaming", &v);
    }
    json_object_object_add(out, "capability_source",
                           json_object_new_string(explicit_metadata ?
                                                  "provider_metadata" :
                                                  "provider_unspecified"));
    return out;
}

struct json_object *webd_ai_runtime_models_id(const char *provider_id,
                                              const char *actor,
                                              int *http_status)
{
    struct ai_config cfg;
    struct ai_result result = {};
    struct json_object *response = NULL, *provider_models = NULL;
    struct json_object *data, *models, *model_details;
    char endpoint[768];
    char resolved_id[65] = "";
    int status = 400;
    int64_t started = ai_now_ms();

    if (http_status) *http_status = 503;
    if (provider_id && provider_id[0]) {
        if (ai_provider_config_by_id(provider_id, &cfg) != 0) {
            if (http_status) *http_status = 404;
            return ai_error("provider_not_found", "provider id does not exist",
                            404, 0, NULL, NULL);
        }
        snprintf(resolved_id, sizeof(resolved_id), "%s", provider_id);
        if (!ai_config_ready(&cfg)) {
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return ai_error("provider_not_configured",
                            "provider credentials or model are incomplete",
                            503, 0, NULL, NULL);
        }
    } else {
        struct ai_dispatch_plan dispatch;
        int select_rc = ai_dispatch_select(&cfg, &dispatch, resolved_id);
        ai_dispatch_plan_clear(&dispatch);
        if (select_rc != 0) {
            memset(cfg.api_key, 0, sizeof(cfg.api_key));
            return ai_dispatch_not_configured(select_rc, http_status);
        }
    }
    if (ai_endpoint(&cfg, "models", endpoint, sizeof(endpoint)) != 0) {
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = 501;
        return ai_error("models_sync_unsupported",
                        "The configured provider has no supported model-list endpoint",
                        501, 0, NULL, NULL);
    }
    response = ai_http_json(&cfg, "GET", endpoint, NULL, &result);
    if (response)
        json_object_object_get_ex(response,
                                  ai_is_gemini(&cfg) ||
                                  ai_is_openai_chatgpt_oauth(&cfg) ?
                                      "models" : "data",
                                  &provider_models);
    if (result.curl_code != CURLE_OK || result.provider_status < 200 ||
        result.provider_status >= 300 || !response || !provider_models ||
        !json_object_is_type(provider_models, json_type_array)) {
        const char *code = ai_error_code(&result, &status);
        if (response) json_object_put(response);
        ai_audit(actor, "ai.models.sync", &cfg, cfg.provider,
                 ai_now_ms() - started, code);
        memset(cfg.api_key, 0, sizeof(cfg.api_key));
        if (http_status) *http_status = status;
        return ai_error(code, "AI provider model sync failed", status,
                        result.provider_status, result.provider_code,
                        result.provider_message);
    }
    models = json_object_new_array();
    model_details = json_object_new_array();
    for (int i = 0; i < json_object_array_length(provider_models); i++) {
        struct json_object *item = json_object_array_get_idx(provider_models, i);
        const char *id = ai_json_string(item,
            ai_is_gemini(&cfg) ? "name" :
            (ai_is_openai_chatgpt_oauth(&cfg) ? "slug" : "id"), "");
        if (ai_is_gemini(&cfg) && !strncmp(id, "models/", 7)) id += 7;
        if (id[0]) {
            json_object_array_add(models, json_object_new_string(id));
            json_object_array_add(model_details, ai_model_detail(item, id));
        }
    }
    data = json_object_new_object();
    json_object_object_add(data, "models", models);
    json_object_object_add(data, "model_details", model_details);
    json_object_object_add(data, "model_capabilities_normalized",
                           json_object_new_boolean(1));
    json_object_object_add(data, "provider", json_object_new_string(cfg.provider));
    json_object_object_add(data, "configured_model", json_object_new_string(cfg.model));
    json_object_object_add(data, "provider_synced", json_object_new_boolean(1));
    /* Cache the list so model_count / models_synced_at on the provider row
     * reflect a real sync instead of staying at "never synced". */
    if (resolved_id[0]) {
        json_object_object_add(data, "provider_id",
                               json_object_new_string(resolved_id));
        json_object_object_add(data, "models_cached",
            json_object_new_boolean(ai_provider_cache_models(resolved_id,
                                                                   models) == 0));
    }
    json_object_object_add(data, "latency_ms",
                           json_object_new_int64(ai_now_ms() - started));
    json_object_put(response);
    ai_audit(actor, "ai.models.sync", &cfg, cfg.provider,
             ai_now_ms() - started, "success");
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
    if (http_status) *http_status = 200;
    return ai_success(data, "webd.ai.models");
}

struct json_object *webd_ai_runtime_models(const char *actor,
                                           int *http_status)
{
    return webd_ai_runtime_models_id(NULL, actor, http_status);
}

void webd_ai_runtime_attach_capabilities(struct json_object *response)
{
    struct json_object *data = NULL, *caps = NULL, *oauth = NULL;
    struct ai_config cfg;
    int ready = ai_config_load(&cfg) == 0 && ai_config_ready(&cfg);
    if (!response || !json_object_object_get_ex(response, "data", &data) || !data)
        goto done;
    if (!json_object_object_get_ex(data, "capabilities", &caps) || !caps ||
        !json_object_is_type(caps, json_type_object)) {
        caps = json_object_new_object();
        json_object_object_add(data, "capabilities", caps);
    }
    json_object_object_add(caps, "chat_runtime", json_object_new_boolean(ready));
    json_object_object_add(caps, "chat_runtime_endpoint",
                           json_object_new_string("/api/v1/ai/chat"));
    json_object_object_add(caps, "provider_test", json_object_new_boolean(1));
    json_object_object_add(caps, "provider_models_sync",
                           json_object_new_boolean(ready));
    /* The frontend renders the strategy switcher and the provider list only
     * when these are true, so they must not be advertised ahead of the routes. */
    json_object_object_add(caps, "multi_provider", json_object_new_boolean(1));
    json_object_object_add(caps, "ai_multi_provider", json_object_new_boolean(1));
    json_object_object_add(caps, "provider_last_check_persisted",
                           json_object_new_boolean(1));
    json_object_object_add(caps, "providers_endpoint",
                           json_object_new_string("/api/v1/ai/providers"));
    json_object_object_add(caps, "dispatch_policy_endpoint",
                           json_object_new_string("/api/v1/ai/dispatch-policy"));
    {
        struct json_object *strategies = json_object_new_array();
        json_object_array_add(strategies, json_object_new_string("single"));
        json_object_array_add(strategies, json_object_new_string("failover"));
        json_object_array_add(strategies, json_object_new_string("load_balance"));
        json_object_object_add(caps, "dispatch_strategies", strategies);
    }
    {
        struct json_object *strategies = json_object_new_array();
        json_object_array_add(strategies, json_object_new_string("single"));
        json_object_array_add(strategies, json_object_new_string("failover"));
        json_object_array_add(strategies, json_object_new_string("load_balance"));
        json_object_object_add(caps, "ai_dispatch_strategies", strategies);
    }
    json_object_object_add(caps, "streaming", json_object_new_boolean(1));
    json_object_object_add(caps, "streaming_ready", json_object_new_boolean(ready));
    json_object_object_add(caps, "streaming_endpoint",
                           json_object_new_string("/api/v1/ai/chat/stream"));
    json_object_object_add(caps, "stream_replay", json_object_new_boolean(0));
    json_object_object_add(caps, "response_cancel", json_object_new_boolean(1));
    json_object_object_add(caps, "response_cancel_endpoint_template",
                           json_object_new_string("/api/v1/ai/responses/{response_id}"));
    json_object_object_add(caps, "attachments", json_object_new_boolean(1));
    json_object_object_add(caps, "attachment_ids", json_object_new_boolean(1));
    json_object_object_add(caps, "attachment_upload_endpoint",
                           json_object_new_string("/api/v1/ai/attachments"));
    json_object_object_add(caps, "attachment_ttl_sec",
                           json_object_new_int(AI_ATTACHMENT_TTL));
    json_object_object_add(caps, "attachment_redaction", json_object_new_boolean(1));
    json_object_object_add(caps, "max_messages", json_object_new_int(AI_MAX_MESSAGES));
    json_object_object_add(caps, "max_message_bytes",
                           json_object_new_int(AI_MAX_MESSAGE_BYTES));
    json_object_object_add(caps, "max_attachments",
                           json_object_new_int(AI_MAX_ATTACHMENTS));
    json_object_object_add(caps, "max_attachment_bytes",
                           json_object_new_int(AI_MAX_ATTACHMENT_BYTES));
    json_object_object_add(caps, "max_attachments_total_bytes",
                           json_object_new_int(AI_MAX_ATTACHMENTS_TOTAL));
    json_object_object_add(caps, "tool_call_passthrough", json_object_new_boolean(1));
    json_object_object_add(caps, "tool_execution_loop", json_object_new_boolean(1));
    json_object_object_add(caps, "tool_execution_loop_streaming", json_object_new_boolean(1));
    json_object_object_add(caps, "tool_authorization_resume_streaming",
                           json_object_new_boolean(1));
    json_object_object_add(caps, "tool_authorization", json_object_new_boolean(1));
    json_object_object_add(caps, "tool_authorization_resume",
                           json_object_new_boolean(1));
    json_object_object_add(caps, "tool_resume_endpoint",
                           json_object_new_string("/api/v1/ai/tool-resume"));
    json_object_object_add(caps, "tool_resume_stream_endpoint",
                           json_object_new_string("/api/v1/ai/tool-resume/stream"));
    json_object_object_add(caps, "tool_resume_ttl_sec",
                           json_object_new_int(AI_TOOL_RESUME_TTL));
    json_object_object_add(caps, "tool_result_feedback", json_object_new_boolean(1));
    json_object_object_add(caps, "max_tool_rounds", json_object_new_int(AI_MAX_TOOL_ROUNDS));
    json_object_object_add(caps, "max_tool_calls_per_round",
                           json_object_new_int(AI_MAX_TOOL_CALLS_PER_ROUND));
    json_object_object_add(caps, "max_concurrent_requests",
                           json_object_new_int(AI_MAX_CONCURRENT));
    json_object_object_add(caps, "max_requests_per_minute",
                           json_object_new_int(AI_MAX_REQUESTS_PER_MINUTE));
    oauth = webd_ai_oauth_catalog();
    json_object_object_add(oauth, "available", json_object_new_boolean(1));
    json_object_object_add(oauth, "status_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/status"));
    json_object_object_add(oauth, "start_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/start"));
    json_object_object_add(oauth, "poll_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/poll"));
    json_object_object_add(oauth, "refresh_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/refresh"));
    json_object_object_add(oauth, "disconnect_endpoint",
                           json_object_new_string("/api/v1/ai/oauth/disconnect"));
    json_object_object_add(data, "oauth", oauth);
done:
    memset(cfg.api_key, 0, sizeof(cfg.api_key));
}
