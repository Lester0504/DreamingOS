// SPDX-License-Identifier: GPL-2.0-or-later
/* Existing engines only: no second service, credential or daemon configuration. */
#define _GNU_SOURCE
#include "nas_downloads.h"
#include "storage/storage_files.h"
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef NAS_DOWNLOADS_TEST_CONFIG
#include <uci.h>
#endif
struct engine {
    char name[24], endpoint[128], user[512], password[1024], secret[1024];
    const char *reason;
};
struct response {
    char *data;
    size_t length;
    long status;
};
static const char *get(struct json_object *j, const char *key) {
    struct json_object *v = NULL;
    return j && json_object_object_get_ex(j, key, &v) && json_object_is_type(v, json_type_string)
               ? json_object_get_string(v)
               : "";
}
static struct json_object *member(struct json_object *j, const char *key) {
    struct json_object *v = NULL;
    if (j)
        json_object_object_get_ex(j, key, &v);
    return v;
}
static struct json_object *failure(const char *reason, int code, int *status) {
    *status = code;
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "error", json_object_new_string(reason));
    return r;
}
static void load_engine(struct engine *e, const char *name) {
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->reason = "not_configured";
#ifdef NAS_DOWNLOADS_TEST_CONFIG
    struct json_object *j = json_object_from_file(NAS_DOWNLOADS_TEST_CONFIG),
                       *cfg = member(j, name);
    if (cfg) {
        snprintf(e->endpoint, sizeof(e->endpoint), "%s", get(cfg, "endpoint"));
        snprintf(e->secret, sizeof(e->secret), "%s", get(cfg, "secret"));
        snprintf(e->user, sizeof(e->user), "%s", get(cfg, "username"));
        snprintf(e->password, sizeof(e->password), "%s", get(cfg, "password"));
        e->reason = NULL;
    }
    if (j)
        json_object_put(j);
#else
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *package = NULL;
    struct uci_section *section = NULL;
    struct uci_element *element;
    int count = 0;
    if (!ctx)
        return;
    if (uci_load(ctx, name, &package) == UCI_OK) {
        uci_foreach_element(&package->sections, element) {
            struct uci_section *s = uci_to_section(element);
            if ((!strcmp(name, "aria2") && !strcmp(s->type, "aria2")) ||
                (!strcmp(name, "qbittorrent") && !strcmp(s->e.name, "config"))) {
                section = s;
                count++;
            }
        }
    }
    if (count == 1) {
        const char *port = uci_lookup_option_string(
            ctx, section, !strcmp(name, "aria2") ? "rpc_listen_port" : "port");
        const char *enabled = uci_lookup_option_string(ctx, section, "enabled");
        if (enabled && strcmp(enabled, "1")) {
            e->reason = "stopped";
            goto done;
        }
        int p = port ? atoi(port) : !strcmp(name, "aria2") ? 6800 : 8080;
        if (p < 1 || p > 65535)
            goto done;
        snprintf(e->endpoint, sizeof(e->endpoint), "http://127.0.0.1:%d", p);
        e->reason = NULL;
        if (!strcmp(name, "aria2")) {
            const char *secure = uci_lookup_option_string(ctx, section, "rpc_secure");
            if (secure && !strcmp(secure, "true")) {
                e->reason = "rpc_tls_not_supported";
                goto done;
            }
            const char *auth = uci_lookup_option_string(ctx, section, "rpc_auth_method");
            const char *secret = uci_lookup_option_string(ctx, section, "rpc_secret");
            const char *user = uci_lookup_option_string(ctx, section, "rpc_user"),
                       *password = uci_lookup_option_string(ctx, section, "rpc_passwd");
            if (auth && !strcmp(auth, "token")) {
                snprintf(e->secret, sizeof(e->secret), "%s", secret ? secret : "");
                if (!e->secret[0])
                    e->reason = "no_credentials";
            }
            if (auth && !strcmp(auth, "user_pass")) {
                snprintf(e->user, sizeof(e->user), "%s", user ? user : "");
                snprintf(e->password, sizeof(e->password), "%s", password ? password : "");
            }
        } else {
            int fd = open("/etc/qbittorrent-webapi.cred", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            struct stat st;
            char buffer[4097];
            ssize_t n = -1;
            if (fd >= 0) {
                if (!fstat(fd, &st) && S_ISREG(st.st_mode) && !(st.st_mode & 0077))
                    n = read(fd, buffer, sizeof(buffer) - 1);
                close(fd);
            }
            if (n > 0) {
                buffer[n] = 0;
                char *save = NULL;
                for (char *line = strtok_r(buffer, "\n", &save); line;
                     line = strtok_r(NULL, "\n", &save)) {
                    size_t len = strlen(line);
                    if (len && line[len - 1] == '\r')
                        line[len - 1] = 0;
                    if (!strncmp(line, "username=", 9))
                        snprintf(e->user, sizeof(e->user), "%s", line + 9);
                    if (!strncmp(line, "password=", 9))
                        snprintf(e->password, sizeof(e->password), "%s", line + 9);
                }
            }
            if (!e->user[0])
                e->reason = "no_credentials";
        }
    } else if (count > 1)
        e->reason = "multiple_instances";
done:
    uci_free_context(ctx);
#endif
}
static size_t receive(char *bytes, size_t size, size_t count, void *userdata) {
    struct response *r = userdata;
    size_t n = size * count;
    if (n > 4 * 1024 * 1024 - r->length)
        return 0;
    char *next = realloc(r->data, r->length + n + 1);
    if (!next)
        return 0;
    r->data = next;
    memcpy(r->data + r->length, bytes, n);
    r->length += n;
    r->data[r->length] = 0;
    return n;
}
static struct response http_request(CURL *curl, struct engine *e, const char *path, const char *body,
                                    const char *type, curl_mime *mime) {
    struct response r = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s%s", e->endpoint, path);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 800L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1800L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (mime)
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    else if (!body)
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    struct curl_slist *headers = NULL;
    if (type)
        headers = curl_slist_append(headers, type);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
    if (mime)
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, NULL);
    curl_slist_free_all(headers);
    return r;
}
static struct response http(CURL *curl, struct engine *e, const char *path, const char *body,
                            const char *type) {
    return http_request(curl, e, path, body, type, NULL);
}
static struct json_object *rpc(CURL *curl, struct engine *e, const char *method,
                               struct json_object *params, const char **reason) {
    struct json_object *request = json_object_new_object(), *args = json_object_new_array();
    if (e->secret[0]) {
        char token[1100];
        snprintf(token, sizeof(token), "token:%s", e->secret);
        json_object_array_add(args, json_object_new_string(token));
    }
    for (size_t i = 0; params && i < json_object_array_length(params); i++)
        json_object_array_add(args, json_object_get(json_object_array_get_idx(params, i)));
    json_object_object_add(request, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(request, "id", json_object_new_string("nas"));
    json_object_object_add(request, "method", json_object_new_string(method));
    json_object_object_add(request, "params", args);
    if (e->user[0]) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, e->user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, e->password);
    }
    struct response response =
        http(curl, e, "/jsonrpc", json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN),
             "Content-Type: application/json");
    json_object_put(request);
    struct json_object *value = response.data ? json_tokener_parse(response.data) : NULL,
                       *result = NULL;
    if (response.status != 200 || !value || member(value, "error")) {
        *reason = response.status == 401   ? "bad_credentials"
                  : member(value, "error") ? "engine_rejected"
                                           : "engine_unreachable";
    } else {
        result = member(value, "result");
        if (result)
            json_object_get(result);
        else
            *reason = "invalid_engine_response";
    }
    if (value)
        json_object_put(value);
    free(response.data);
    return result;
}
static int login(CURL *curl, struct engine *e, const char **reason) {
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    char *user = curl_easy_escape(curl, e->user, 0),
         *password = curl_easy_escape(curl, e->password, 0);
    char body[5000];
    snprintf(body, sizeof(body), "username=%s&password=%s", user, password);
    curl_free(user);
    curl_free(password);
    struct response r = http(curl, e, "/api/v2/auth/login", body,
                             "Content-Type: application/x-www-form-urlencoded");
    int okay = r.status == 200 && r.data && !strcmp(r.data, "Ok.");
    if (!okay)
        *reason = r.status == 200 || r.status == 403 ? "bad_credentials" : "engine_unreachable";
    free(r.data);
    return okay ? 0 : -1;
}
static struct json_object *actions(const char *state) {
    struct json_object *a = json_object_new_array();
    int paused = !strcmp(state, "paused") || strstr(state, "paused") || strstr(state, "stopped");
    if (!paused && (!strcmp(state, "active") || !strcmp(state, "waiting") || strstr(state, "DL") ||
        strstr(state, "UP") || !strcmp(state, "downloading") || !strcmp(state, "uploading")))
        json_object_array_add(a, json_object_new_string("pause"));
    if (paused)
        json_object_array_add(a, json_object_new_string("resume"));
    json_object_array_add(a, json_object_new_string("remove"));
    return a;
}
static struct json_object *aria_task(struct json_object *value) {
    struct json_object *t = json_object_new_object();
    const char *state = get(value, "status");
    json_object_object_add(t, "id", json_object_new_string(get(value, "gid")));
    json_object_object_add(t, "state", json_object_new_string(state));
    const char *pairs[][2] = {{"totalLength", "total_bytes"},
                              {"completedLength", "completed_bytes"},
                              {"downloadSpeed", "download_speed"},
                              {"uploadSpeed", "upload_speed"}};
    for (int i = 0; i < 4; i++)
        json_object_object_add(t, pairs[i][1],
                               json_object_new_int64(strtoll(get(value, pairs[i][0]), NULL, 10)));
    struct json_object *file = json_object_array_get_idx(member(value, "files"), 0);
    const char *path = get(file, "path"), *name = strrchr(path, '/');
    json_object_object_add(t, "name", json_object_new_string(name ? name + 1 : path));
    json_object_object_add(t, "path", json_object_new_string(path));
    json_object_object_add(t, "error", json_object_new_string(get(value, "errorMessage")));
    json_object_object_add(t, "complete", json_object_new_boolean(!strcmp(state, "complete")));
    json_object_object_add(t, "actions", actions(state));
    return t;
}
static struct json_object *qb_task(struct json_object *value) {
    struct json_object *t = json_object_new_object();
    json_object_object_add(t, "id", json_object_new_string(get(value, "hash")));
    json_object_object_add(t, "name", json_object_new_string(get(value, "name")));
    json_object_object_add(t, "state", json_object_new_string(get(value, "state")));
    /* downloaded is transfer accounting, including discarded/re-downloaded data.
     * size/completed describe the selected files actually present on disk. */
    const char *pairs[][2] = {{"size", "total_bytes"},
                              {"completed", "completed_bytes"},
                              {"dlspeed", "download_speed"},
                              {"upspeed", "upload_speed"}};
    for (int i = 0; i < 4; i++)
        json_object_object_add(
            t, pairs[i][1],
            json_object_new_int64(json_object_get_int64(member(value, pairs[i][0]))));
    json_object_object_add(t, "path", json_object_new_string(get(value, "content_path")));
    json_object_object_add(t, "complete",
                           json_object_new_boolean(json_object_get_double(member(value, "progress")) >= 1.0));
    json_object_object_add(t, "actions", actions(get(value, "state")));
    return t;
}
static struct json_object *engine_settings(CURL *curl, struct engine *e, int aria,
                                           const char **reason) {
    struct json_object *value = NULL;
    if (aria) value = rpc(curl, e, "aria2.getGlobalOption", NULL, reason);
    else {
        struct response r = http(curl, e, "/api/v2/app/preferences", NULL, NULL);
        if (r.status == 200 && r.data) value = json_tokener_parse(r.data);
        if (!value || !json_object_is_type(value, json_type_object)) *reason = "invalid_engine_response";
        free(r.data);
    }
    if (!value) return NULL;
    struct json_object *out = json_object_new_object();
    const char *fields[] = {"download_limit_bps", "upload_limit_bps", "max_active_downloads"};
    const char *keys[] = {aria ? "max-overall-download-limit" : "dl_limit",
                         aria ? "max-overall-upload-limit" : "up_limit",
                         aria ? "max-concurrent-downloads" : "max_active_downloads"};
    for (int i = 0; i < 3; i++) {
        int64_t n = json_object_get_int64(member(value, keys[i]));
        json_object_object_add(out, fields[i], json_object_new_int64(n < 0 ? 0 : n));
    }
    json_object_object_add(out, "queue_enabled", json_object_new_boolean(aria || json_object_get_boolean(member(value, "queueing_enabled"))));
    json_object_object_add(out, "persistence", json_object_new_string(aria ? "engine_runtime" : "engine_config"));
    json_object_put(value);
    return out;
}
static const char *select_engine(struct json_object *input) {
    const char *name = get(input, "engine");
    if (strcmp(name, "auto")) return name;
    const char *url = get(input, "url");
    size_t len = strcspn(url, "?#");
    return member(input, "torrent") || !strncmp(url, "magnet:", 7) ||
           (len >= 8 && !strncasecmp(url + len - 8, ".torrent", 8)) ? "qbittorrent" : "aria2";
}
struct json_object *nas_downloads_request(const char *method, const char *route,
                                          struct json_object *input, int *status) {
    const char *name = !strcmp(route, "/downloads/tasks") && !strcmp(method, "POST")
                           ? select_engine(input) : get(input, "engine");
    if (strcmp(name, "aria2") && strcmp(name, "qbittorrent"))
        return failure("invalid_engine", 400, status);
    struct engine e;
    load_engine(&e, name);
    int aria = !strcmp(name, "aria2");
    const char *reason = e.reason;
    CURL *curl = curl_easy_init();
    if (!curl)
        return failure("engine_unreachable", 503, status);
    struct json_object *out = NULL, *result = NULL;
    *status = 200;
    if (!reason) {
        if (aria) {
            result = rpc(curl, &e, "aria2.getVersion", NULL, &reason);
            if (result)
                json_object_put(result);
            result = NULL;
        } else
            login(curl, &e, &reason);
    }
    if (!strcmp(route, "/downloads/engine") && !strcmp(method, "GET")) {
        out = json_object_new_object();
        json_object_object_add(out, "engine", json_object_new_string(name));
        json_object_object_add(out, "state", json_object_new_string(reason ? reason : "ready"));
        json_object_object_add(
            out, "actions",
            reason ? json_object_new_array()
                   : json_tokener_parse("[\"create\",\"list\",\"pause\",\"resume\",\"remove\",\"settings\"]"));
        json_object_object_add(out, "torrent_file", json_object_new_boolean(!aria && !reason));
        goto done;
    }
    if (reason) {
        out = failure(reason, 409, status);
        goto done;
    }
    if (!strcmp(route, "/downloads/settings") && (!strcmp(method, "GET") || !strcmp(method, "POST"))) {
        if (!strcmp(method, "POST")) {
            const char *fields[] = {"download_limit_bps", "upload_limit_bps", "max_active_downloads"};
            const char *keys[] = {aria ? "max-overall-download-limit" : "dl_limit",
                                 aria ? "max-overall-upload-limit" : "up_limit",
                                 aria ? "max-concurrent-downloads" : "max_active_downloads"};
            struct json_object *options = json_object_new_object();
            for (int i = 0; i < 3; i++) {
                struct json_object *v = member(input, fields[i]);
                int64_t n = json_object_get_int64(v);
                if (!json_object_is_type(v, json_type_int) || n < (i == 2 ? 1 : 0) ||
                    n > (i == 2 ? 1000 : 10000000000LL)) {
                    json_object_put(options); out = failure("invalid_settings", 400, status); goto done;
                }
                char number[32]; snprintf(number, sizeof(number), "%lld", (long long)n);
                json_object_object_add(options, keys[i], aria ? json_object_new_string(number) : json_object_new_int64(n));
            }
            if (aria) {
                struct json_object *params = json_object_new_array();
                json_object_array_add(params, options);
                result = rpc(curl, &e, "aria2.changeGlobalOption", params, &reason);
                json_object_put(params);
                if (result) json_object_put(result);
                result = NULL;
            } else {
                json_object_object_add(options, "queueing_enabled", json_object_new_boolean(1));
                char *escaped = curl_easy_escape(curl, json_object_to_json_string_ext(options, JSON_C_TO_STRING_PLAIN), 0), *body = NULL;
                if (!escaped || asprintf(&body, "json=%s", escaped) < 0) reason = "allocation_failed";
                if (!reason) {
                    struct response r = http(curl, &e, "/api/v2/app/setPreferences", body, "Content-Type: application/x-www-form-urlencoded");
                    if (r.status != 200) reason = "engine_rejected";
                    free(r.data);
                }
                free(body); curl_free(escaped); json_object_put(options);
            }
        }
        if (!reason) out = engine_settings(curl, &e, aria, &reason);
        if (reason) { if (out) json_object_put(out); out = failure(reason, 409, status); }
        goto done;
    }
    if (!strcmp(route, "/downloads/tasks") && !strcmp(method, "GET")) {
        struct json_object *items = json_object_new_array();
        if (aria) {
            const char *methods[] = {"aria2.tellActive", "aria2.tellWaiting", "aria2.tellStopped"};
            for (int i = 0; i < 3 && !reason; i++) {
                struct json_object *params = json_object_new_array();
                if (i) {
                    json_object_array_add(params, json_object_new_int(0));
                    json_object_array_add(params, json_object_new_int(100));
                }
                result = rpc(curl, &e, methods[i], params, &reason);
                json_object_put(params);
                if (result) {
                    for (size_t k = 0; k < json_object_array_length(result); k++)
                        json_object_array_add(items,
                                              aria_task(json_object_array_get_idx(result, k)));
                    json_object_put(result);
                    result = NULL;
                }
            }
        } else {
            struct response r = http(curl, &e, "/api/v2/torrents/info?limit=100", NULL, NULL);
            result = r.data ? json_tokener_parse(r.data) : NULL;
            if (r.status != 200 || !result || !json_object_is_type(result, json_type_array))
                reason = "invalid_engine_response";
            else
                for (size_t i = 0; i < json_object_array_length(result); i++)
                    json_object_array_add(items, qb_task(json_object_array_get_idx(result, i)));
            if (result)
                json_object_put(result);
            result = NULL;
            free(r.data);
        }
        if (reason) {
            json_object_put(items);
            out = failure(reason, 503, status);
        } else {
            out = json_object_new_object();
            json_object_object_add(out, "items", items);
            json_object_object_add(out, "limit", json_object_new_int(100));
        }
        goto done;
    }
    if (!strcmp(route, "/downloads/tasks") && !strcmp(method, "POST")) {
        const char *url = get(input, "url");
        struct json_object *torrent = member(input, "torrent");
        if ((torrent && (aria || url[0] || !json_object_is_type(torrent, json_type_object))) ||
            (!torrent && (strlen(url) > 4096 || strchr(url, '\n') || strchr(url, '\r') ||
            (!aria && strncmp(url, "magnet:", 7) && strncmp(url, "https://", 8) &&
             strncmp(url, "http://", 7)) ||
            (aria && strncmp(url, "http://", 7) && strncmp(url, "https://", 8) &&
             strncmp(url, "ftp://", 6))))) {
            out = failure("unsupported_url", 400, status);
            goto done;
        }
        struct json_object *destination = member(input, "destination");
        char canonical[PATH_MAX];
        int fd = storage_files_open_dir(get(destination, "root_id"), get(destination, "path"), 1,
                                        canonical, sizeof(canonical), &reason);
        if (fd < 0) {
            out = failure("destination_unavailable", 409, status);
            goto done;
        }
        close(fd);
        reason = NULL;
        if (aria) {
            struct json_object *params = json_object_new_array(), *urls = json_object_new_array(),
                               *options = json_object_new_object();
            json_object_array_add(urls, json_object_new_string(url));
            json_object_array_add(params, urls);
            json_object_object_add(options, "dir", json_object_new_string(canonical));
            json_object_object_add(options, "allow-overwrite", json_object_new_string("false"));
            json_object_object_add(options, "auto-file-renaming", json_object_new_string("true"));
            json_object_array_add(params, options);
            result = rpc(curl, &e, "aria2.addUri", params, &reason);
            json_object_put(params);
            if (result) {
                out = json_object_new_object();
                json_object_object_add(out, "id", json_object_get(result));
                json_object_put(result);
                result = NULL;
            }
        } else if (torrent) {
            struct storage_files_stream stream;
            const char *source_path = get(torrent, "path"), *ext = strrchr(source_path, '.');
            if (!ext || strcasecmp(ext, ".torrent") ||
                storage_files_open_stream(get(torrent, "root_id"), source_path, &stream, &reason)) {
                out = failure("torrent_unavailable", 409, status); goto done;
            }
            reason = NULL;
            if (!stream.size_bytes || stream.size_bytes > 2 * 1024 * 1024) {
                close(stream.fd); out = failure("torrent_size_limit", 400, status); goto done;
            }
            size_t length = (size_t)stream.size_bytes, read_bytes = 0;
            char *bytes = malloc(length);
            while (bytes && read_bytes < length) {
                ssize_t n = read(stream.fd, bytes + read_bytes, length - read_bytes);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                read_bytes += n;
            }
            close(stream.fd);
            if (!bytes || read_bytes != length) {
                free(bytes); out = failure("torrent_unavailable", 409, status); goto done;
            }
            curl_mime *mime = curl_mime_init(curl);
            curl_mimepart *part = mime ? curl_mime_addpart(mime) : NULL;
            if (!part) reason = "allocation_failed";
            else {
                curl_mime_name(part, "torrents"); curl_mime_filename(part, stream.basename);
                curl_mime_type(part, "application/x-bittorrent"); curl_mime_data(part, bytes, length);
                part = curl_mime_addpart(mime);
                if (!part) reason = "allocation_failed";
                else { curl_mime_name(part, "savepath"); curl_mime_data(part, canonical, CURL_ZERO_TERMINATED); }
            }
            if (!reason) {
                struct response r = http_request(curl, &e, "/api/v2/torrents/add", NULL, NULL, mime);
                if (r.status != 200 || !r.data || strcmp(r.data, "Ok.")) reason = "engine_rejected";
                else { out = json_object_new_object(); json_object_object_add(out, "accepted", json_object_new_boolean(1)); }
                free(r.data);
            }
            curl_mime_free(mime); free(bytes);
        } else {
            char *escaped = curl_easy_escape(curl, url, 0),
                 *folder = curl_easy_escape(curl, canonical, 0);
            char *body = NULL;
            if (asprintf(&body, "urls=%s&savepath=%s", escaped, folder) < 0)
                body = NULL;
            curl_free(escaped);
            curl_free(folder);
            if (!body)
                reason = "allocation_failed";
            else {
                struct response r = http(curl, &e, "/api/v2/torrents/add", body,
                                         "Content-Type: application/x-www-form-urlencoded");
                free(body);
                if (r.status != 200 || !r.data || strcmp(r.data, "Ok."))
                    reason = "engine_rejected";
                else {
                    out = json_object_new_object();
                    json_object_object_add(out, "accepted", json_object_new_boolean(1));
                }
                free(r.data);
            }
        }
        if (reason)
            out = failure(reason, 409, status);
        else {
            *status = 202;
            json_object_object_add(out, "engine", json_object_new_string(name));
        }
        goto done;
    }
    if (!strcmp(route, "/downloads/action") && !strcmp(method, "POST")) {
        const char *id = get(input, "id"), *action = get(input, "action");
        size_t n = strlen(id);
        if (n != (aria ? 16 : 40) || strspn(id, "0123456789abcdefABCDEF") != n ||
            (strcmp(action, "pause") && strcmp(action, "resume") && strcmp(action, "remove"))) {
            out = failure("invalid_request", 400, status);
            goto done;
        }
        if (aria) {
            struct json_object *params = json_object_new_array();
            json_object_array_add(params, json_object_new_string(id));
            const char *command = !strcmp(action, "pause")    ? "aria2.pause"
                                  : !strcmp(action, "resume") ? "aria2.unpause"
                                                              : "aria2.remove";
            result = rpc(curl, &e, command, params, &reason);
            if (reason && !strcmp(action, "remove")) {
                reason = NULL;
                result = rpc(curl, &e, "aria2.removeDownloadResult", params, &reason);
            }
            json_object_put(params);
            if (result)
                json_object_put(result);
            result = NULL;
        } else {
            char path[128], body[128];
            const char *command = !strcmp(action, "pause")    ? "pause"
                                  : !strcmp(action, "resume") ? "resume"
                                                              : "delete";
            snprintf(path, sizeof(path), "/api/v2/torrents/%s", command);
            snprintf(body, sizeof(body), "hashes=%s&deleteFiles=false", id);
            struct response r =
                http(curl, &e, path, body, "Content-Type: application/x-www-form-urlencoded");
            if (r.status == 404 && strcmp(action, "remove")) {
                free(r.data);
                snprintf(path, sizeof(path), "/api/v2/torrents/%s",
                         !strcmp(action, "pause") ? "stop" : "start");
                r = http(curl, &e, path, body, "Content-Type: application/x-www-form-urlencoded");
            }
            if (r.status != 200)
                reason = "engine_rejected";
            free(r.data);
        }
        out = reason ? failure(reason, 409, status) : json_object_new_object();
        if (!reason)
            json_object_object_add(out, "accepted", json_object_new_boolean(1));
        goto done;
    }
    out = failure("not_found", 404, status);
done:
    curl_easy_cleanup(curl);
    return out;
}
