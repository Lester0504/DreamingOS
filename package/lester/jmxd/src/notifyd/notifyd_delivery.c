// SPDX-License-Identifier: GPL-2.0-or-later
#include "notifyd_internal.h"

#include <curl/curl.h>
#include <stdarg.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

static struct uloop_timeout notifyd_delivery_timer;
static int notifyd_delivery_timer_active;

static void notifyd_error_set(char *error, size_t error_len, const char *value)
{
    if (error && error_len > 0)
        snprintf(error, error_len, "%s", value ? value : "");
}

static int notifyd_load_outbox_item(const char *id, struct notifyd_outbox_item *item,
                                    char *error, size_t error_len)
{
    sqlite3_stmt *st;
    int found = 0;
    int rc;

    if (!item) {
        notifyd_error_set(error, error_len, "invalid_outbox_item");
        return 0;
    }
    if (!notifyd_id_ok(id)) {
        notifyd_error_set(error, error_len, "invalid_id");
        return 0;
    }
    memset(item, 0, sizeof(*item));
    st = notifyd_prepare(
        "SELECT id,channel_id,payload_json,attempts,max_attempts "
        "FROM notify_outbox WHERE id=?1");
    if (!st) {
        notifyd_error_set(error, error_len, "outbox_query_failed");
        return 0;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(item->id, sizeof(item->id), "%s",
                 sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        snprintf(item->channel_id, sizeof(item->channel_id), "%s",
                 sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "");
        snprintf(item->payload_json, sizeof(item->payload_json), "%s",
                 sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "{}");
        item->attempts = sqlite3_column_int(st, 3);
        item->max_attempts = sqlite3_column_int(st, 4);
        if (item->max_attempts < 1)
            item->max_attempts = 1;
        found = 1;
        notifyd_error_set(error, error_len, "");
    } else if (rc == SQLITE_DONE) {
        notifyd_error_set(error, error_len, "outbox_not_found");
    } else {
        notifyd_error_set(error, error_len, "outbox_query_failed");
    }
    sqlite3_finalize(st);
    return found;
}

static void notifyd_delivery_state(const char *id, char *state, size_t state_len)
{
    sqlite3_stmt *st;

    if (!state || state_len == 0)
        return;
    snprintf(state, state_len, "%s", "unknown");
    st = notifyd_prepare("SELECT state FROM notify_outbox WHERE id=?1");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0))
        snprintf(state, state_len, "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
}

static int notifyd_deliver_noop(const struct notifyd_outbox_item *item,
                                const struct notifyd_channel *channel,
                                long *http_status, char *error, size_t error_len)
{
    (void)item;
    (void)channel;
    if (http_status)
        *http_status = 0;
    if (error && error_len > 0)
        error[0] = '\0';
    return 1;
}

static size_t notifyd_discard_write(void *ptr, size_t size, size_t nmemb, void *stream)
{
    (void)ptr;
    (void)stream;
    return size * nmemb;
}

static int notifyd_webhook_headers(struct json_object *options, struct curl_slist **headers,
                                   char *error, size_t error_len)
{
    struct json_object *custom = NULL;
    struct curl_slist *next;

    next = curl_slist_append(*headers, "Content-Type: application/json");
    if (!next) {
        notifyd_error_set(error, error_len, "header_alloc_failed");
        return 0;
    }
    *headers = next;
    next = curl_slist_append(*headers, "Accept: application/json");
    if (!next) {
        notifyd_error_set(error, error_len, "header_alloc_failed");
        return 0;
    }
    *headers = next;
    if (json_object_object_get_ex(options, "headers", &custom) && custom &&
        json_object_is_type(custom, json_type_object)) {
        json_object_object_foreach(custom, key, val) {
            const char *value = json_object_get_string(val);
            char line[640];

            if (!json_object_is_type(val, json_type_string) || !notifyd_text_ok(key, 96) ||
                !notifyd_text_ok(value, 512) || !key[0] || strchr(key, '\n') ||
                strchr(key, '\r') || strchr(key, ':') || (value && strchr(value, '\n')) ||
                (value && strchr(value, '\r'))) {
                notifyd_error_set(error, error_len, "invalid_webhook_header");
                return 0;
            }
            snprintf(line, sizeof(line), "%s: %s", key, value ? value : "");
            next = curl_slist_append(*headers, line);
            if (!next) {
                notifyd_error_set(error, error_len, "header_alloc_failed");
                return 0;
            }
            *headers = next;
        }
    }
    return 1;
}

#define NOTIFYD_ROUTER_ID_PATH "/etc/dreamingwrt/cloud/router_id"
/*
 * The relay authenticates ingest by looking the tunnel token up under the id the
 * router enrolled with, which is always the key fingerprint. On a router whose
 * local router_id is still a legacy UUID the two differ, and posting the UUID is
 * refused with 401 router_unauthorized. So this file is preferred, and
 * NOTIFYD_ROUTER_ID_PATH is only the fallback for a router where the local id is
 * already the derived one.
 */
#define NOTIFYD_RELAY_ROUTER_ID_PATH "/etc/dreamingwrt/cloud/relay_router_id"

/* Read a cloud router id file written by the enrollment flow.  notifyd has no ubus
 * dependency on webd, and this file is the same source webd itself uses, so
 * reading it directly avoids a startup ordering dependency. */
static int notifyd_router_id_load_from(const char *path, char *out, size_t out_len)
{
    FILE *fp;
    size_t n;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    fp = fopen(path, "re");
    if (!fp)
        return 0;
    if (!fgets(out, (int)out_len, fp)) {
        fclose(fp);
        out[0] = '\0';
        return 0;
    }
    fclose(fp);
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
        out[--n] = '\0';
    return out[0] != '\0';
}

/* Prefer the enrolled (key-derived) id; fall back to the local one. */
static int notifyd_router_id_load(char *out, size_t out_len)
{
    if (notifyd_router_id_load_from(NOTIFYD_RELAY_ROUTER_ID_PATH, out, out_len))
        return 1;
    return notifyd_router_id_load_from(NOTIFYD_ROUTER_ID_PATH, out, out_len);
}

/* Map the native notify payload onto the relay ingest contract.  Deliberately a
 * fixed mapping rather than a template engine: the relay defines exactly one
 * shape, and a template language here would be a second configuration surface
 * to validate and get wrong. */
static char *notifyd_relay_ingest_body(const struct notifyd_outbox_item *item,
                                       struct json_object *options,
                                       char *error, size_t error_len)
{
    struct json_object *payload;
    struct json_object *body;
    const char *router_id;
    char router_id_buf[128] = "";
    const char *event;
    const char *detail_body;
    char *out = NULL;
    const char *rendered;

    payload = notifyd_json_parse_or_object(item->payload_json);
    if (!payload) {
        notifyd_error_set(error, error_len, "relay_payload_parse_failed");
        return NULL;
    }
    /* An explicit option wins so a test channel can be pointed at a fixed id,
     * otherwise fall back to the enrolled router id on disk. */
    router_id = notifyd_json_str(options, "router_id", "");
    if (!router_id[0] && notifyd_router_id_load(router_id_buf, sizeof(router_id_buf)))
        router_id = router_id_buf;
    if (!router_id[0]) {
        /* Sending without a router id would be rejected with 400 and would still
         * consume a delivery attempt, so fail before the request. */
        notifyd_error_set(error, error_len, "relay_router_id_unavailable");
        json_object_put(payload);
        return NULL;
    }
    event = notifyd_json_str(payload, "event", "");
    if (!event[0]) {
        notifyd_error_set(error, error_len, "relay_event_id_missing");
        json_object_put(payload);
        return NULL;
    }
    body = json_object_new_object();
    json_object_object_add(body, "router_id", json_object_new_string(router_id));
    /* The relay's event_id is the catalog identifier, which lives in "event"
     * here; the payload's own "id" is a per-occurrence hash and must not be
     * used for subscription matching. */
    json_object_object_add(body, "event_id", json_object_new_string(event));
    json_object_object_add(body, "event", json_object_new_string(event));
    json_object_object_add(body, "occurrence_id",
        json_object_new_string(notifyd_json_str(payload, "id", "")));
    json_object_object_add(body, "severity",
        json_object_new_string(notifyd_json_str(payload, "severity", "info")));
    json_object_object_add(body, "category",
        json_object_new_string(notifyd_json_str(payload, "category", "")));
    json_object_object_add(body, "source",
        json_object_new_string(notifyd_json_str(payload, "source", "")));
    json_object_object_add(body, "title",
        json_object_new_string(notifyd_json_str(payload, "title", "")));
    /* The native payload has no body field; only 6 keys are always present
     * (id, severity, category, event, source, title).  Fall back through the
     * optional text carriers and finally to the title so the relay never gets
     * an empty body, which it would render as a blank notification. */
    detail_body = notifyd_json_str(payload, "body",
                       notifyd_json_str(payload, "message",
                           notifyd_json_str(payload, "detail_json",
                               notifyd_json_str(payload, "title", ""))));
    json_object_object_add(body, "body", json_object_new_string(detail_body));
    json_object_object_add(body, "body_source",
        json_object_new_string(notifyd_json_str(payload, "body", "")[0] ? "body" :
            (notifyd_json_str(payload, "message", "")[0] ? "message" :
                (notifyd_json_str(payload, "detail_json", "")[0] ? "detail_json" : "title"))));
    json_object_object_add(body, "dedupe_key",
        json_object_new_string(notifyd_json_str(payload, "dedupe_key", "")));
    json_object_object_add(body, "ts",
        json_object_new_int64(notifyd_json_i64(payload, "ts", notifyd_now_s())));
    rendered = json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN);
    if (rendered)
        out = strdup(rendered);
    if (!out)
        notifyd_error_set(error, error_len, "relay_body_render_failed");
    json_object_put(body);
    json_object_put(payload);
    return out;
}

static int notifyd_deliver_webhook(const struct notifyd_outbox_item *item,
                                   const struct notifyd_channel *channel,
                                   long *http_status, char *error, size_t error_len)
{
    struct json_object *options = notifyd_json_parse_or_object(channel->options_json);
    const char *url = notifyd_json_str(options, "url", "");
    const char *method = notifyd_json_str(options, "method", "POST");
    int timeout_ms = notifyd_json_int(options, "timeout_ms", 10000);
    struct curl_slist *headers = NULL;
    CURL *curl;
    CURLcode cc;
    long code = 0;
    int ok = 0;
    char *relay_body = NULL;
    const char *post_body;

    if (!notifyd_url_ok(url)) {
        notifyd_error_set(error, error_len, "invalid_webhook_url");
        goto done;
    }
    if (strcmp(method, "POST") && strcmp(method, "PUT") && strcmp(method, "PATCH")) {
        notifyd_error_set(error, error_len, "invalid_webhook_method");
        goto done;
    }
    if (timeout_ms < 1000 || timeout_ms > 60000) {
        notifyd_error_set(error, error_len, "invalid_webhook_timeout");
        goto done;
    }
    curl = curl_easy_init();
    if (!curl) {
        notifyd_error_set(error, error_len, "curl_init_failed");
        goto done;
    }
    if (!notifyd_webhook_headers(options, &headers, error, error_len))
        goto cleanup_curl;
    /* Opt-in relay ingest shape.  The native payload carries the catalog event in
     * "event" and a per-occurrence hash in "id", which is the opposite of what
     * the relay contract calls event_id, so the two cannot be sent as-is. */
    post_body = item->payload_json;
    if (notifyd_json_bool(options, "relay_ingest", 0)) {
        relay_body = notifyd_relay_ingest_body(item, options, error, error_len);
        if (!relay_body)
            goto cleanup_curl;
        post_body = relay_body;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_body));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-notifyd/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, notifyd_discard_write);
    cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_status)
        *http_status = code;
    if (cc != CURLE_OK) {
        snprintf(error, error_len, "curl:%s", curl_easy_strerror(cc));
        goto cleanup_curl;
    }
    if (code < 200 || code >= 300) {
        snprintf(error, error_len, "http_status_%ld", code);
        goto cleanup_curl;
    }
    notifyd_error_set(error, error_len, "");
    ok = 1;
cleanup_curl:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
done:
    free(relay_body);
    json_object_put(options);
    return ok;
}

static int notifyd_mail_address_ok(const char *email)
{
    const char *at;
    const unsigned char *p;

    if (!email || !email[0] || strlen(email) > 254)
        return 0;
    at = strchr(email, '@');
    if (!at || at == email || !at[1] || !strchr(at + 1, '.'))
        return 0;
    for (p = (const unsigned char *)email; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == '<' || *p == '>' || *p == ',' || *p == ';')
            return 0;
    }
    return 1;
}

static void notifyd_mail_header_text(const char *src, char *out, size_t out_len)
{
    size_t i = 0;

    if (!out || out_len == 0)
        return;
    if (!src) src = "";
    while (*src && i + 1 < out_len) {
        unsigned char c = (unsigned char)*src++;
        if (c == '\r' || c == '\n' || c == 0x7f)
            out[i++] = ' ';
        else if (c >= 0x20 || c == '\t')
            out[i++] = (char)c;
    }
    out[i] = '\0';
}

static int notifyd_mail_recipient_add(char recipients[][256], int *count,
                                      const char *email)
{
    int i;

    if (!count || *count >= 64 || !notifyd_mail_address_ok(email))
        return 0;
    for (i = 0; i < *count; i++) {
        if (!strcasecmp(recipients[i], email))
            return 1;
    }
    snprintf(recipients[*count], sizeof(recipients[0]), "%s", email);
    (*count)++;
    return 1;
}

static void notifyd_mail_resolution_warning(char *warning, size_t warning_len,
                                            const char *code, int index)
{
    size_t used;

    if (!warning || warning_len == 0 || !code)
        return;
    used = strlen(warning);
    if (used && used + 1 < warning_len)
        warning[used++] = ',';
    if (used < warning_len)
        snprintf(warning + used, warning_len - used, "%s:%d", code, index);
}

static int notifyd_mail_resolve_recipients(struct json_object *options,
                                           char recipients[][256], int *count,
                                           char *warning, size_t warning_len)
{
    struct json_object *users = NULL, *extra = NULL;
    int i;

    *count = 0;
    if (warning && warning_len) warning[0] = '\0';
    if (json_object_object_get_ex(options, "user_ids", &users) && users &&
        json_object_is_type(users, json_type_array)) {
        for (i = 0; i < (int)json_object_array_length(users) && *count < 64; i++) {
            const char *username = json_object_get_string(json_object_array_get_idx(users, i));
            sqlite3_stmt *st = notifyd_config_prepare(
                "SELECT email FROM web_users WHERE username=?1 AND status='enabled'");
            const char *email = NULL;

            if (!st) {
                notifyd_mail_resolution_warning(warning, warning_len, "directory_error", i);
                continue;
            }
            sqlite3_bind_text(st, 1, username ? username : "", -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW)
                email = notifyd_sqlite_text(st, 0, "");
            if (!email || !email[0])
                notifyd_mail_resolution_warning(warning, warning_len, "user_unresolved", i);
            else if (!notifyd_mail_recipient_add(recipients, count, email))
                notifyd_mail_resolution_warning(warning, warning_len, "user_email_invalid", i);
            sqlite3_finalize(st);
        }
    }
    if (json_object_object_get_ex(options, "recipients", &extra) && extra &&
        json_object_is_type(extra, json_type_array)) {
        for (i = 0; i < (int)json_object_array_length(extra) && *count < 64; i++) {
            const char *email = json_object_get_string(json_object_array_get_idx(extra, i));
            if (!notifyd_mail_recipient_add(recipients, count, email))
                notifyd_mail_resolution_warning(warning, warning_len, "recipient_invalid", i);
        }
    }
    return *count > 0;
}

struct notifyd_smtp_conn {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
};

static int notifyd_smtp_wait(int fd, short events, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = events };
    int rc;

    do { rc = poll(&pfd, 1, timeout_ms); } while (rc < 0 && errno == EINTR);
    return rc > 0 && (pfd.revents & events);
}

static int notifyd_smtp_connect_socket(const char *host, int port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL, *it;
    char service[16];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(service, sizeof(service), "%d", port);
    if (getaddrinfo(host, service, &hints, &res) != 0)
        return -1;
    for (it = res; it; it = it->ai_next) {
        int flags;
        int error = 0;
        socklen_t error_len = sizeof(error);

        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd); fd = -1; continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
            break;
        if (errno != EINPROGRESS || !notifyd_smtp_wait(fd, POLLOUT, timeout_ms) ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) {
            close(fd); fd = -1; continue;
        }
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static int notifyd_smtp_tls_enable(struct notifyd_smtp_conn *conn,
                                   const char *host, int timeout_ms)
{
    int rc;

    conn->ctx = SSL_CTX_new(TLS_client_method());
    if (!conn->ctx)
        return 0;
    SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(conn->ctx) != 1)
        return 0;
    conn->ssl = SSL_new(conn->ctx);
    if (!conn->ssl || SSL_set_fd(conn->ssl, conn->fd) != 1 ||
        SSL_set_tlsext_host_name(conn->ssl, host) != 1 || SSL_set1_host(conn->ssl, host) != 1)
        return 0;
    for (;;) {
        rc = SSL_connect(conn->ssl);
        if (rc == 1)
            break;
        rc = SSL_get_error(conn->ssl, rc);
        if (rc == SSL_ERROR_WANT_READ) {
            if (!notifyd_smtp_wait(conn->fd, POLLIN, timeout_ms)) return 0;
        } else if (rc == SSL_ERROR_WANT_WRITE) {
            if (!notifyd_smtp_wait(conn->fd, POLLOUT, timeout_ms)) return 0;
        } else {
            return 0;
        }
    }
    return SSL_get_verify_result(conn->ssl) == X509_V_OK;
}

static void notifyd_smtp_close(struct notifyd_smtp_conn *conn)
{
    if (!conn) return;
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    if (conn->ctx) SSL_CTX_free(conn->ctx);
    if (conn->fd >= 0) close(conn->fd);
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
}

static int notifyd_smtp_write(struct notifyd_smtp_conn *conn,
                              const void *data, size_t len, int timeout_ms)
{
    const unsigned char *p = data;

    while (len > 0) {
        int rc;

        if (conn->ssl) {
            rc = SSL_write(conn->ssl, p, len > INT_MAX ? INT_MAX : (int)len);
            if (rc <= 0) {
                int ssl_error = SSL_get_error(conn->ssl, rc);
                if (ssl_error == SSL_ERROR_WANT_READ) {
                    if (!notifyd_smtp_wait(conn->fd, POLLIN, timeout_ms)) return 0;
                    continue;
                }
                if (ssl_error == SSL_ERROR_WANT_WRITE) {
                    if (!notifyd_smtp_wait(conn->fd, POLLOUT, timeout_ms)) return 0;
                    continue;
                }
                return 0;
            }
        } else {
            if (!notifyd_smtp_wait(conn->fd, POLLOUT, timeout_ms)) return 0;
            rc = send(conn->fd, p, len, MSG_NOSIGNAL);
            if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                continue;
            if (rc <= 0) return 0;
        }
        p += rc;
        len -= (size_t)rc;
    }
    return 1;
}

static int notifyd_smtp_read_char(struct notifyd_smtp_conn *conn, char *out,
                                  int timeout_ms)
{
    int rc;

    for (;;) {
        if (conn->ssl) {
            rc = SSL_read(conn->ssl, out, 1);
            if (rc == 1) return 1;
            rc = SSL_get_error(conn->ssl, rc);
            if (rc == SSL_ERROR_WANT_READ) {
                if (!notifyd_smtp_wait(conn->fd, POLLIN, timeout_ms)) return 0;
                continue;
            }
            if (rc == SSL_ERROR_WANT_WRITE) {
                if (!notifyd_smtp_wait(conn->fd, POLLOUT, timeout_ms)) return 0;
                continue;
            }
            return 0;
        }
        if (!notifyd_smtp_wait(conn->fd, POLLIN, timeout_ms)) return 0;
        rc = recv(conn->fd, out, 1, 0);
        if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        return rc == 1;
    }
}

static int notifyd_smtp_response(struct notifyd_smtp_conn *conn, char *capture,
                                 size_t capture_len, int timeout_ms)
{
    char line[1024];
    size_t used = 0;
    int code = 0;

    if (capture && capture_len) capture[0] = '\0';
    for (;;) {
        size_t n = 0;
        char c;

        while (n + 1 < sizeof(line)) {
            if (!notifyd_smtp_read_char(conn, &c, timeout_ms)) return -1;
            line[n++] = c;
            if (c == '\n') break;
        }
        line[n] = '\0';
        if (n < 4 || !isdigit((unsigned char)line[0]) || !isdigit((unsigned char)line[1]) ||
            !isdigit((unsigned char)line[2]))
            return -1;
        code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
        if (capture && capture_len > 1 && used + 1 < capture_len) {
            size_t take = n < capture_len - used - 1 ? n : capture_len - used - 1;
            memcpy(capture + used, line, take);
            used += take;
            capture[used] = '\0';
        }
        if (line[3] == ' ') return code;
        if (line[3] != '-') return -1;
    }
}

static int notifyd_smtp_command(struct notifyd_smtp_conn *conn, int timeout_ms,
                                char *capture, size_t capture_len,
                                const char *format, ...)
{
    char command[1024];
    va_list ap;
    int n;

    va_start(ap, format);
    n = vsnprintf(command, sizeof(command), format, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof(command) ||
        !notifyd_smtp_write(conn, command, (size_t)n, timeout_ms))
        return -1;
    return notifyd_smtp_response(conn, capture, capture_len, timeout_ms);
}

static int notifyd_smtp_base64(const char *value, char *out, size_t out_len)
{
    size_t len = value ? strlen(value) : 0;
    int need = 4 * ((int)len + 2) / 3;

    if (need + 1 > (int)out_len || len > INT_MAX)
        return 0;
    EVP_EncodeBlock((unsigned char *)out, (const unsigned char *)(value ? value : ""), (int)len);
    return 1;
}

static char *notifyd_smtp_dot_stuff(const char *mail, size_t *out_len)
{
    size_t len = mail ? strlen(mail) : 0;
    char *out = malloc(len * 2 + 16);
    size_t i = 0, o = 0;
    int line_start = 1;

    if (!out) return NULL;
    while (i < len) {
        char c = mail[i++];
        if (line_start && c == '.') out[o++] = '.';
        if (c == '\r') {
            if (i < len && mail[i] == '\n') i++;
            out[o++] = '\r'; out[o++] = '\n'; line_start = 1;
        } else if (c == '\n') {
            out[o++] = '\r'; out[o++] = '\n'; line_start = 1;
        } else {
            out[o++] = c; line_start = 0;
        }
    }
    if (!line_start) { out[o++] = '\r'; out[o++] = '\n'; }
    out[o] = '\0';
    if (out_len) *out_len = o;
    return out;
}

static int notifyd_smtp_send_native(const struct notifyd_settings *settings,
                                    char recipients[][256], int recipient_count,
                                    const char *mail, char *error, size_t error_len)
{
    struct notifyd_smtp_conn conn = { .fd = -1 };
    char response[4096];
    char user64[512], pass64[1024];
    char *encoded_mail = NULL;
    size_t encoded_len = 0;
    int code;
    int accepted = 0;
    int rejected = 0;
    int i;
    const int timeout_ms = 10000;

    conn.fd = notifyd_smtp_connect_socket(settings->smtp_host, settings->smtp_port, timeout_ms);
    if (conn.fd < 0) { notifyd_error_set(error, error_len, "smtp_connect_failed"); goto fail; }
    if (!strcmp(settings->smtp_security, "ssl") &&
        !notifyd_smtp_tls_enable(&conn, settings->smtp_host, timeout_ms)) {
        notifyd_error_set(error, error_len, "smtp_tls_failed"); goto fail;
    }
    code = notifyd_smtp_response(&conn, response, sizeof(response), timeout_ms);
    if (code != 220) { snprintf(error, error_len, "smtp_greeting_%d", code); goto fail; }
    code = notifyd_smtp_command(&conn, timeout_ms, response, sizeof(response), "EHLO dreamingwrt.local\r\n");
    if (code != 250) { snprintf(error, error_len, "smtp_ehlo_%d", code); goto fail; }
    if (!strcmp(settings->smtp_security, "starttls")) {
        code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "STARTTLS\r\n");
        if (code != 220) { snprintf(error, error_len, "smtp_starttls_%d", code); goto fail; }
        if (!notifyd_smtp_tls_enable(&conn, settings->smtp_host, timeout_ms)) {
            notifyd_error_set(error, error_len, "smtp_tls_failed"); goto fail;
        }
        code = notifyd_smtp_command(&conn, timeout_ms, response, sizeof(response), "EHLO dreamingwrt.local\r\n");
        if (code != 250) { snprintf(error, error_len, "smtp_ehlo_tls_%d", code); goto fail; }
    }
    if (settings->smtp_username[0]) {
        if (!notifyd_smtp_base64(settings->smtp_username, user64, sizeof(user64)) ||
            !notifyd_smtp_base64(settings->smtp_password, pass64, sizeof(pass64))) {
            notifyd_error_set(error, error_len, "smtp_auth_value_too_large"); goto fail;
        }
        code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "AUTH LOGIN\r\n");
        if (code != 334) { snprintf(error, error_len, "smtp_auth_start_%d", code); goto fail; }
        code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "%s\r\n", user64);
        if (code != 334) { snprintf(error, error_len, "smtp_auth_user_%d", code); goto fail; }
        code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "%s\r\n", pass64);
        memset(pass64, 0, sizeof(pass64));
        if (code != 235) { snprintf(error, error_len, "smtp_auth_failed_%d", code); goto fail; }
    }
    code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "MAIL FROM:<%s>\r\n", settings->smtp_from);
    if (code != 250) { snprintf(error, error_len, "smtp_mail_from_%d", code); goto fail; }
    for (i = 0; i < recipient_count; i++) {
        code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "RCPT TO:<%s>\r\n", recipients[i]);
        if (code == 250 || code == 251) accepted++;
        else rejected++;
    }
    if (!accepted) { notifyd_error_set(error, error_len, "smtp_all_recipients_rejected"); goto fail; }
    code = notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "DATA\r\n");
    if (code != 354) { snprintf(error, error_len, "smtp_data_%d", code); goto fail; }
    encoded_mail = notifyd_smtp_dot_stuff(mail, &encoded_len);
    if (!encoded_mail || !notifyd_smtp_write(&conn, encoded_mail, encoded_len, timeout_ms) ||
        !notifyd_smtp_write(&conn, ".\r\n", 3, timeout_ms)) {
        notifyd_error_set(error, error_len, "smtp_body_write_failed"); goto fail;
    }
    code = notifyd_smtp_response(&conn, NULL, 0, timeout_ms);
    if (code != 250) { snprintf(error, error_len, "smtp_body_%d", code); goto fail; }
    notifyd_smtp_command(&conn, timeout_ms, NULL, 0, "QUIT\r\n");
    if (rejected) snprintf(error, error_len, "delivered_with_%d_recipients_rejected", rejected);
    else notifyd_error_set(error, error_len, "");
    free(encoded_mail);
    notifyd_smtp_close(&conn);
    memset(pass64, 0, sizeof(pass64));
    return 1;
fail:
    free(encoded_mail);
    notifyd_smtp_close(&conn);
    memset(pass64, 0, sizeof(pass64));
    return 0;
}

static int notifyd_deliver_email(const struct notifyd_outbox_item *item,
                                 const struct notifyd_channel *channel,
                                 long *http_status, char *error, size_t error_len)
{
    struct notifyd_settings settings;
    struct json_object *options = notifyd_json_parse_or_object(channel->options_json);
    struct json_object *payload = notifyd_json_parse_or_object(item->payload_json);
    const char *prefix = notifyd_json_str(options, "subject_prefix", "[DreamingWrt]");
    const char *reply_to = notifyd_json_str(options, "reply_to", "");
    const char *title = notifyd_json_str(payload, "title", "DreamingWrt notification");
    const char *message = notifyd_json_str(payload, "message", "");
    const char *severity = notifyd_json_str(payload, "severity", "info");
    const char *category = notifyd_json_str(payload, "category", "");
    char recipients[64][256];
    int recipient_count = 0;
    char warning[256] = "";
    char safe_prefix[128], safe_title[256], safe_severity[32], safe_category[128];
    char *mail = NULL;
    size_t mail_len;
    int ok = 0;

    memset(&settings, 0, sizeof(settings));
    if (http_status) *http_status = 0;
    if (notifyd_settings_load(&settings) != 0) {
        notifyd_error_set(error, error_len, "smtp_settings_unavailable");
        goto done;
    }
    if (!settings.smtp_host[0] || !settings.smtp_from[0]) {
        notifyd_error_set(error, error_len, "smtp_not_configured");
        goto done;
    }
    if (!notifyd_mail_address_ok(settings.smtp_from)) {
        notifyd_error_set(error, error_len, "smtp_from_invalid");
        goto done;
    }
    if (reply_to[0] && !notifyd_mail_address_ok(reply_to)) {
        notifyd_error_set(error, error_len, "email_reply_to_invalid");
        goto done;
    }
    if (!notifyd_mail_resolve_recipients(options, recipients, &recipient_count,
                                         warning, sizeof(warning))) {
        notifyd_error_set(error, error_len, warning[0] ? warning : "no_valid_recipients");
        goto done;
    }
    notifyd_mail_header_text(prefix, safe_prefix, sizeof(safe_prefix));
    notifyd_mail_header_text(title, safe_title, sizeof(safe_title));
    notifyd_mail_header_text(severity, safe_severity, sizeof(safe_severity));
    notifyd_mail_header_text(category, safe_category, sizeof(safe_category));
    mail_len = strlen(message) + strlen(safe_prefix) + strlen(safe_title) + 2048;
    if (mail_len > 16384) {
        notifyd_error_set(error, error_len, "email_body_too_large");
        goto done;
    }
    mail = calloc(1, mail_len);
    if (!mail) {
        notifyd_error_set(error, error_len, "email_alloc_failed");
        goto done;
    }
    snprintf(mail, mail_len,
             "From: <%s>\r\nTo: undisclosed-recipients:;\r\nSubject: %s %s\r\n"
             "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n"
             "Content-Transfer-Encoding: 8bit\r\nX-DreamingWrt-Severity: %s\r\n"
             "X-DreamingWrt-Category: %s\r\n%s%s%s\r\n\r\n%s\r\n",
             settings.smtp_from, safe_prefix, safe_title, safe_severity, safe_category,
             reply_to[0] ? "Reply-To: <" : "", reply_to[0] ? reply_to : "", reply_to[0] ? ">\r\n" : "",
             message);
    ok = notifyd_smtp_send_native(&settings, recipients, recipient_count,
                                  mail, error, error_len);
    if (ok && warning[0])
        snprintf(error, error_len, "delivered_with_resolution_warning:%.200s", warning);
done:
    if (settings.smtp_password[0])
        memset(settings.smtp_password, 0, sizeof(settings.smtp_password));
    free(mail);
    json_object_put(options);
    json_object_put(payload);
    return ok;
}

static int notifyd_deliver_channel(const struct notifyd_outbox_item *item,
                                   long *http_status, char *error, size_t error_len)
{
    struct notifyd_channel channel;

    if (!notifyd_channel_get(item->channel_id, &channel)) {
        notifyd_error_set(error, error_len, "channel_not_found");
        return 0;
    }
    if (!channel.enabled) {
        notifyd_error_set(error, error_len, "channel_disabled");
        return 0;
    }
    if (!strcmp(channel.type, "noop"))
        return notifyd_deliver_noop(item, &channel, http_status, error, error_len);
    if (!strcmp(channel.type, "webhook"))
        return notifyd_deliver_webhook(item, &channel, http_status, error, error_len);
    if (!strcmp(channel.type, "email"))
        return notifyd_deliver_email(item, &channel, http_status, error, error_len);
    notifyd_error_set(error, error_len, "unsupported_channel_type");
    return 0;
}

struct json_object *notifyd_deliver_one(const char *id)
{
    struct notifyd_outbox_item item;
    struct json_object *resp = json_object_new_object();
    char error[256] = "";
    char state[32];
    long http_status = 0;
    int ok;
    int state_saved;
    struct timespec started, finished;
    int duration_ms = 0;

    if (!notifyd_load_outbox_item(id, &item, error, sizeof(error))) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string(error[0] ? error : "outbox_not_found"));
        return resp;
    }
    clock_gettime(CLOCK_MONOTONIC, &started);
    ok = notifyd_deliver_channel(&item, &http_status, error, sizeof(error));
    clock_gettime(CLOCK_MONOTONIC, &finished);
    duration_ms = (int)((finished.tv_sec - started.tv_sec) * 1000 +
                        (finished.tv_nsec - started.tv_nsec) / 1000000);
    if (duration_ms < 0) duration_ms = 0;
    state_saved = notifyd_mark_delivery_result(&item, ok, http_status, error, duration_ms);
    notifyd_delivery_state(item.id, state, sizeof(state));
    json_object_object_add(resp, "ok", json_object_new_boolean(ok && state_saved));
    json_object_object_add(resp, "id", json_object_new_string(item.id));
    json_object_object_add(resp, "channel_id", json_object_new_string(item.channel_id));
    json_object_object_add(resp, "delivered", json_object_new_boolean(ok));
    json_object_object_add(resp, "state_saved", json_object_new_boolean(state_saved));
    json_object_object_add(resp, "state", json_object_new_string(state));
    json_object_object_add(resp, "http_status", json_object_new_int((int)http_status));
    json_object_object_add(resp, "duration_ms", json_object_new_int(duration_ms));
    if (!state_saved) {
        json_object_object_add(resp, "error", json_object_new_string("delivery_state_update_failed"));
        if (error[0])
            json_object_object_add(resp, "delivery_error", json_object_new_string(error));
    } else if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    return resp;
}

struct json_object *notifyd_deliver_due(struct json_object *body)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    char ids[NOTIFYD_MAX_DELIVER_PER_TICK][NOTIFYD_MAX_ID];
    int limit = notifyd_json_int(body, "limit", NOTIFYD_MAX_DELIVER_PER_TICK);
    int delivered = 0, failed = 0, queued = 0, backend_failed = 0;
    int64_t now = notifyd_now_s();
    int count = 0;
    int i;
    int rc;

    if (limit <= 0 || limit > NOTIFYD_MAX_DELIVER_PER_TICK)
        limit = NOTIFYD_MAX_DELIVER_PER_TICK;
    memset(ids, 0, sizeof(ids));
    st = notifyd_prepare(
        "SELECT id FROM notify_outbox "
        "WHERE state IN ('pending','retry') AND next_attempt_at<=?1 "
        "ORDER BY next_attempt_at ASC, created_at ASC LIMIT ?2");
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("outbox_query_failed"));
        json_object_object_add(resp, "items", items);
        return resp;
    }
    {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_int(st, 2, limit);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *id = (const char *)sqlite3_column_text(st, 0);
            if (count < limit && id && id[0])
                snprintf(ids[count++], sizeof(ids[0]), "%s", id);
        }
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("outbox_query_failed"));
            json_object_object_add(resp, "items", items);
            return resp;
        }
        sqlite3_finalize(st);
    }
    for (i = 0; i < count; i++) {
        struct json_object *one = notifyd_deliver_one(ids[i]);
        struct json_object *state_o = NULL;
        struct json_object *ok_o = NULL;
        struct json_object *state_saved_o = NULL;
        const char *state = "";

        if (one && json_object_object_get_ex(one, "state", &state_o) && state_o)
            state = json_object_get_string(state_o);
        if (!one || !json_object_object_get_ex(one, "ok", &ok_o) || !json_object_get_boolean(ok_o)) {
            if (one && json_object_object_get_ex(one, "state_saved", &state_saved_o) &&
                state_saved_o && !json_object_get_boolean(state_saved_o))
                backend_failed++;
        }
        if (!strcmp(state, "delivered"))
            delivered++;
        else if (!strcmp(state, "failed"))
            failed++;
        else
            queued++;
        json_object_array_add(items, one ? one : json_object_new_object());
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(backend_failed == 0));
    json_object_object_add(resp, "delivered", json_object_new_int(delivered));
    json_object_object_add(resp, "failed", json_object_new_int(failed));
    json_object_object_add(resp, "queued", json_object_new_int(queued));
    json_object_object_add(resp, "backend_failed", json_object_new_int(backend_failed));
    if (backend_failed > 0)
        json_object_object_add(resp, "error", json_object_new_string("delivery_state_update_failed"));
    json_object_object_add(resp, "items", items);
    return resp;
}

struct json_object *notifyd_test_send(struct json_object *body)
{
    struct json_object *event = json_object_new_object();
    struct json_object *enq;
    struct json_object *id_o = NULL;
    struct json_object *delivery = NULL;
    struct json_object *resp = json_object_new_object();
    const char *channel_id = notifyd_json_str(body, "channel_id", "");
    const char *title = notifyd_json_str(body, "title", "DreamingWrt notification test");
    const char *severity = notifyd_severity(notifyd_json_str(body, "severity", "notice"));
    const char *dedupe_key = notifyd_json_str(body, "dedupe_key", "");

    if (channel_id[0])
        json_object_object_add(event, "channel_id", json_object_new_string(channel_id));
    json_object_object_add(event, "severity", json_object_new_string(severity));
    json_object_object_add(event, "category", json_object_new_string("notify"));
    json_object_object_add(event, "event", json_object_new_string("test_send"));
    json_object_object_add(event, "source", json_object_new_string("dreamingwrt-notifyd"));
    json_object_object_add(event, "title", json_object_new_string(title));
    json_object_object_add(event, "message",
                           json_object_new_string(notifyd_json_str(body, "message", "This is a DreamingWrt notification test.")));
    if (dedupe_key[0] && notifyd_text_ok(dedupe_key, 256))
        json_object_object_add(event, "dedupe_key", json_object_new_string(dedupe_key));
    enq = notifyd_enqueue_direct(event);
    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "enqueue", json_object_get(enq));
    if (json_object_object_get_ex(enq, "id", &id_o) && id_o) {
        struct json_object *ok_o = NULL;
        int delivered = 0;

        delivery = notifyd_deliver_one(json_object_get_string(id_o));
        if (delivery && json_object_object_get_ex(delivery, "ok", &ok_o) && ok_o)
            delivered = json_object_get_boolean(ok_o) ? 1 : 0;
        json_object_object_add(resp, "delivery", delivery);
        json_object_object_del(resp, "ok");
        json_object_object_add(resp, "ok", json_object_new_boolean(delivered));
        if (!delivered)
            json_object_object_add(resp, "error", json_object_new_string("delivery_failed"));
    } else {
        json_object_object_add(resp, "error", json_object_new_string("enqueue_failed"));
    }
    json_object_put(enq);
    json_object_put(event);
    return resp;
}

static void notifyd_delivery_tick(struct uloop_timeout *t)
{
    static int64_t last_prune;
    struct json_object *body = json_object_new_object();
    struct json_object *resp;
    int64_t now = notifyd_now_s();

    (void)t;
    json_object_object_add(body, "limit", json_object_new_int(1));
    resp = notifyd_deliver_due(body);
    json_object_put(resp);
    json_object_put(body);
    if (last_prune <= 0 || now - last_prune >= 3600) {
        if (notifyd_prune_if_needed() == 0)
            last_prune = now;
    }
    if (notifyd_delivery_timer_active)
        uloop_timeout_set(&notifyd_delivery_timer, NOTIFYD_DELIVERY_TICK_MS);
}

void notifyd_delivery_start(void)
{
    notifyd_delivery_timer.cb = notifyd_delivery_tick;
    notifyd_delivery_timer_active = 1;
    uloop_timeout_set(&notifyd_delivery_timer, NOTIFYD_DELIVERY_TICK_MS);
}

void notifyd_delivery_stop(void)
{
    notifyd_delivery_timer_active = 0;
    uloop_timeout_cancel(&notifyd_delivery_timer);
}
