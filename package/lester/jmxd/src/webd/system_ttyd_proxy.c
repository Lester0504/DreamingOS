// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authenticated same-origin reverse proxy for ttyd.
 *
 * This module deliberately contains no route registration, session lookup,
 * audit logger or connection counter.  Those remain parent-worker concerns.
 * It also treats an upgraded WebSocket as opaque bytes: terminal input,
 * output, credentials and frame contents are never parsed or logged here.
 */
#define _GNU_SOURCE
#include "system_ttyd_proxy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <uci.h>

#ifndef SYSTEM_TTYD_PROXY_CONFIG_PATH
#define SYSTEM_TTYD_PROXY_CONFIG_PATH "/etc/config/ttyd"
#endif
#define TTYD_PROXY_PREFIX "/terminal"
#define TTYD_PROXY_WS_SUBPROTOCOL_HEADER "Sec-WebSocket-Protocol"
#define TTYD_PROXY_MAX_HEADER (64U * 1024U)
#define TTYD_PROXY_MAX_HEADERS 128
#define TTYD_PROXY_MAX_TARGET 4096
#define TTYD_PROXY_MAX_HOST 255
#define TTYD_PROXY_MAX_UNIX_PATH (sizeof(((struct sockaddr_un *)0)->sun_path) - 1)
#define TTYD_PROXY_IO_BUFFER (32U * 1024U)
#define TTYD_PROXY_MAX_HTTP_BODY (16U * 1024U * 1024U)
#define TTYD_PROXY_CONNECT_TIMEOUT_MS 3000U
#define TTYD_PROXY_DEFAULT_IDLE_MS (15U * 60U * 1000U)
#define TTYD_PROXY_MIN_IDLE_MS 30000U
#define TTYD_PROXY_MAX_IDLE_MS (60U * 60U * 1000U)

enum proxy_io_result {
    PROXY_IO_WANT_WRITE = -3,
    PROXY_IO_WANT_READ = -2,
    PROXY_IO_ERROR = -1,
    PROXY_IO_EOF = 0,
    PROXY_IO_PROGRESS = 1,
};

struct proxy_slice {
    const char *ptr;
    size_t len;
};

struct proxy_header {
    struct proxy_slice name;
    struct proxy_slice value;
};

struct proxy_http_request {
    struct proxy_slice method;
    struct proxy_slice target;
    struct proxy_slice version;
    struct proxy_header headers[TTYD_PROXY_MAX_HEADERS];
    size_t header_count;
    const unsigned char *body;
    size_t body_len;
    size_t content_length;
    int content_length_present;
    int websocket;
    struct proxy_slice host;
    struct proxy_slice origin;
    struct proxy_slice forwarded_proto;
    struct proxy_slice forwarded_host;
    struct proxy_slice sec_fetch_site;
};

struct proxy_endpoint {
    int unix_socket;
    int family;
    int ssl;
    int port;
    char address[INET6_ADDRSTRLEN];
    char unix_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

struct proxy_upstream {
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};

struct proxy_buffer {
    unsigned char data[TTYD_PROXY_IO_BUFFER];
    size_t offset;
    size_t length;
};

struct proxy_response_head {
    unsigned char data[TTYD_PROXY_MAX_HEADER];
    size_t length;
    size_t header_length;
    size_t content_length;
    int content_length_present;
    int status;
};

static int64_t proxy_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void proxy_result_init(struct system_ttyd_proxy_result *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
}

static void proxy_result_error(struct system_ttyd_proxy_result *result,
                               int status, const char *code)
{
    if (!result)
        return;
    result->http_status = status;
    snprintf(result->error_code, sizeof(result->error_code), "%s",
             code ? code : "ttyd_proxy_error");
}

static const char *proxy_status_text(int status)
{
    switch (status) {
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Content Too Large";
    case 429: return "Too Many Requests";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "Bad Request";
    }
}

static int proxy_wait_fd(int fd, short events, int64_t deadline_ms)
{
    struct pollfd pfd;

    for (;;) {
        int64_t now = proxy_monotonic_ms();
        int timeout;
        int rc;

        if (deadline_ms <= now)
            return 0;
        timeout = (int)(deadline_ms - now);
        pfd.fd = fd;
        pfd.events = events;
        pfd.revents = 0;
        rc = poll(&pfd, 1, timeout);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc <= 0)
            return rc;
        if (pfd.revents & (POLLERR | POLLNVAL))
            return -1;
        if (pfd.revents & (events | POLLHUP))
            return 1;
    }
}

static int proxy_write_plain_all(int fd, const void *data, size_t length,
                                 unsigned int timeout_ms)
{
    const unsigned char *bytes = data;
    size_t offset = 0;
    int64_t deadline = proxy_monotonic_ms() + timeout_ms;

    while (offset < length) {
        ssize_t sent = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);

        if (sent > 0) {
            offset += (size_t)sent;
            deadline = proxy_monotonic_ms() + timeout_ms;
            continue;
        }
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (proxy_wait_fd(fd, POLLOUT, deadline) > 0)
                continue;
        }
        return -1;
    }
    return 0;
}

static int proxy_send_error(int fd, int status, const char *code,
                            struct system_ttyd_proxy_result *result)
{
    char body[256];
    char header[512];
    int body_len;
    int header_len;

    proxy_result_error(result, status, code);
    body_len = snprintf(body, sizeof(body),
                        "{\"ok\":false,\"error\":\"%s\"}\n",
                        code ? code : "ttyd_proxy_error");
    if (body_len <= 0 || body_len >= (int)sizeof(body))
        return -1;
    header_len = snprintf(header, sizeof(header),
                          "HTTP/1.1 %d %s\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: %d\r\n"
                          "Cache-Control: no-store\r\n"
                          "X-Content-Type-Options: nosniff\r\n"
                          "Connection: close\r\n\r\n",
                          status, proxy_status_text(status), body_len);
    if (header_len <= 0 || header_len >= (int)sizeof(header) ||
        proxy_write_plain_all(fd, header, (size_t)header_len, 3000) != 0 ||
        proxy_write_plain_all(fd, body, (size_t)body_len, 3000) != 0)
        return -1;
    return 0;
}

static int proxy_slice_equal_ci(struct proxy_slice slice, const char *value)
{
    size_t length = value ? strlen(value) : 0;

    return slice.len == length && !strncasecmp(slice.ptr, value, length);
}

static int proxy_slice_copy(struct proxy_slice slice, char *out, size_t out_len)
{
    if (!out || slice.len >= out_len)
        return -1;
    memcpy(out, slice.ptr, slice.len);
    out[slice.len] = '\0';
    return 0;
}

static struct proxy_slice proxy_trim(struct proxy_slice value)
{
    while (value.len && (value.ptr[0] == ' ' || value.ptr[0] == '\t')) {
        value.ptr++;
        value.len--;
    }
    while (value.len &&
           (value.ptr[value.len - 1] == ' ' || value.ptr[value.len - 1] == '\t'))
        value.len--;
    return value;
}

static int proxy_token_char(unsigned char c)
{
    return isalnum(c) || c == '!' || c == '#' || c == '$' || c == '%' ||
           c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' ||
           c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
           c == '~';
}

static int proxy_header_name_ok(struct proxy_slice name)
{
    size_t i;

    if (!name.len || name.len > 63)
        return 0;
    for (i = 0; i < name.len; i++)
        if (!proxy_token_char((unsigned char)name.ptr[i]))
            return 0;
    return 1;
}

static int proxy_value_ok(struct proxy_slice value)
{
    size_t i;

    for (i = 0; i < value.len; i++) {
        unsigned char c = (unsigned char)value.ptr[i];
        if ((c < 0x20 && c != '\t') || c == 0x7f)
            return 0;
    }
    return 1;
}

static int proxy_decimal_size(struct proxy_slice value, size_t *out)
{
    size_t result = 0;
    size_t i;

    value = proxy_trim(value);
    if (!value.len)
        return -1;
    for (i = 0; i < value.len; i++) {
        unsigned char c = (unsigned char)value.ptr[i];
        if (!isdigit(c) || result > (SIZE_MAX - (size_t)(c - '0')) / 10)
            return -1;
        result = result * 10 + (size_t)(c - '0');
    }
    *out = result;
    return 0;
}

static int proxy_header_token(struct proxy_slice value, const char *wanted)
{
    size_t wanted_len = strlen(wanted);
    const char *p = value.ptr;
    const char *end = value.ptr + value.len;

    while (p < end) {
        const char *start;
        const char *stop;

        while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
            p++;
        start = p;
        while (p < end && *p != ',')
            p++;
        stop = p;
        while (stop > start && (stop[-1] == ' ' || stop[-1] == '\t'))
            stop--;
        if ((size_t)(stop - start) == wanted_len &&
            !strncasecmp(start, wanted, wanted_len))
            return 1;
    }
    return 0;
}

static int proxy_find_header(const struct proxy_http_request *request,
                             const char *name, struct proxy_slice *value,
                             int *count)
{
    size_t i;
    int matches = 0;

    for (i = 0; i < request->header_count; i++) {
        if (proxy_slice_equal_ci(request->headers[i].name, name)) {
            if (value)
                *value = request->headers[i].value;
            matches++;
        }
    }
    if (count)
        *count = matches;
    return matches > 0;
}

static int proxy_parse_request(const void *raw, size_t raw_len,
                               struct proxy_http_request *request,
                               const char **error)
{
    const char *text = raw;
    const char *headers_end;
    const char *line_end;
    const char *p;
    const char *sp1;
    const char *sp2;
    size_t header_len;
    int count;
    struct proxy_slice value;

    memset(request, 0, sizeof(*request));
    if (!raw || !raw_len) {
        *error = "ttyd_proxy_empty_request";
        return -1;
    }
    if (memchr(raw, '\0', raw_len)) {
        *error = "ttyd_proxy_invalid_request";
        return -1;
    }
    headers_end = memmem(text, raw_len, "\r\n\r\n", 4);
    if (!headers_end) {
        *error = "ttyd_proxy_incomplete_headers";
        return -1;
    }
    header_len = (size_t)(headers_end + 4 - text);
    if (header_len > TTYD_PROXY_MAX_HEADER) {
        *error = "ttyd_proxy_headers_too_large";
        return -2;
    }
    line_end = memmem(text, header_len, "\r\n", 2);
    if (!line_end) {
        *error = "ttyd_proxy_invalid_request_line";
        return -1;
    }
    sp1 = memchr(text, ' ', (size_t)(line_end - text));
    if (!sp1)
        goto bad_line;
    sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - sp1 - 1));
    if (!sp2 || memchr(sp2 + 1, ' ', (size_t)(line_end - sp2 - 1)))
        goto bad_line;
    request->method.ptr = text;
    request->method.len = (size_t)(sp1 - text);
    request->target.ptr = sp1 + 1;
    request->target.len = (size_t)(sp2 - sp1 - 1);
    request->version.ptr = sp2 + 1;
    request->version.len = (size_t)(line_end - sp2 - 1);
    if (!request->method.len || request->method.len > 7 ||
        request->target.len > TTYD_PROXY_MAX_TARGET ||
        (!proxy_slice_equal_ci(request->version, "HTTP/1.1") &&
         !proxy_slice_equal_ci(request->version, "HTTP/1.0")))
        goto bad_line;
    for (p = request->method.ptr; p < request->method.ptr + request->method.len; p++)
        if (!proxy_token_char((unsigned char)*p))
            goto bad_line;

    p = line_end + 2;
    while (p < headers_end) {
        const char *colon;
        struct proxy_header *header;

        /* headers_end points at the CRLF terminating the final header. */
        line_end = memmem(p, (size_t)(headers_end + 2 - p), "\r\n", 2);
        if (!line_end || line_end == p || *p == ' ' || *p == '\t' ||
            request->header_count >= TTYD_PROXY_MAX_HEADERS) {
            *error = "ttyd_proxy_invalid_headers";
            return -1;
        }
        colon = memchr(p, ':', (size_t)(line_end - p));
        if (!colon) {
            *error = "ttyd_proxy_invalid_headers";
            return -1;
        }
        header = &request->headers[request->header_count++];
        header->name.ptr = p;
        header->name.len = (size_t)(colon - p);
        header->value.ptr = colon + 1;
        header->value.len = (size_t)(line_end - colon - 1);
        header->value = proxy_trim(header->value);
        if (!proxy_header_name_ok(header->name) || !proxy_value_ok(header->value)) {
            *error = "ttyd_proxy_invalid_headers";
            return -1;
        }
        p = line_end + 2;
    }

    if (!proxy_find_header(request, "Host", &request->host, &count) || count != 1) {
        *error = "ttyd_proxy_invalid_host";
        return -1;
    }
    proxy_find_header(request, "Origin", &request->origin, &count);
    if (count > 1) {
        *error = "ttyd_proxy_invalid_origin";
        return -1;
    }
    proxy_find_header(request, "X-Forwarded-Proto", &request->forwarded_proto,
                      &count);
    if (count > 1) {
        *error = "ttyd_proxy_invalid_forwarded_proto";
        return -1;
    }
    proxy_find_header(request, "X-Forwarded-Host", &request->forwarded_host,
                      &count);
    if (count > 1) {
        *error = "ttyd_proxy_invalid_forwarded_host";
        return -1;
    }
    proxy_find_header(request, "Sec-Fetch-Site", &request->sec_fetch_site,
                      &count);
    if (count > 1) {
        *error = "ttyd_proxy_invalid_fetch_site";
        return -1;
    }
    if (proxy_find_header(request, "Transfer-Encoding", &value, &count)) {
        *error = "ttyd_proxy_transfer_encoding_unsupported";
        return -1;
    }
    if (proxy_find_header(request, "Content-Length", &value, &count)) {
        if (count != 1 || proxy_decimal_size(value, &request->content_length) != 0) {
            *error = "ttyd_proxy_invalid_content_length";
            return -1;
        }
        request->content_length_present = 1;
    }
    request->body = (const unsigned char *)text + header_len;
    request->body_len = raw_len - header_len;
    if (request->body_len != request->content_length) {
        *error = "ttyd_proxy_incomplete_body";
        return -1;
    }
    if (proxy_find_header(request, "Upgrade", &value, &count)) {
        struct proxy_slice connection = {0};
        int connection_count = 0;

        if (count != 1 || !proxy_slice_equal_ci(value, "websocket") ||
            !proxy_find_header(request, "Connection", &connection,
                               &connection_count) ||
            !proxy_header_token(connection, "upgrade")) {
            *error = "ttyd_proxy_invalid_websocket_upgrade";
            return -1;
        }
        request->websocket = 1;
    }
    return 0;

bad_line:
    *error = "ttyd_proxy_invalid_request_line";
    return -1;
}

static int proxy_host_ok(struct proxy_slice host)
{
    size_t i;
    int bracket = 0;

    host = proxy_trim(host);
    if (!host.len || host.len > TTYD_PROXY_MAX_HOST ||
        host.ptr[0] == '.' || host.ptr[host.len - 1] == '.')
        return 0;
    for (i = 0; i < host.len; i++) {
        unsigned char c = (unsigned char)host.ptr[i];
        if (c == '[') {
            if (i != 0 || bracket)
                return 0;
            bracket = 1;
        } else if (c == ']') {
            if (!bracket)
                return 0;
            bracket = 2;
        } else if (!(isalnum(c) || c == '.' || c == '-' || c == ':' || c == '_')) {
            return 0;
        }
    }
    if (bracket == 1 || memchr(host.ptr, ',', host.len) ||
        memchr(host.ptr, '@', host.len))
        return 0;
    return 1;
}

static int proxy_external_value(struct proxy_slice actual,
                                const char *expected)
{
    size_t expected_len = expected ? strlen(expected) : 0;

    return expected_len && actual.len == expected_len &&
           !strncasecmp(actual.ptr, expected, expected_len);
}

static int proxy_origin_same(const struct proxy_http_request *parsed,
                             const struct system_ttyd_proxy_request *request)
{
    const char *origin = parsed->origin.ptr;
    size_t origin_len = parsed->origin.len;
    size_t proto_len = strlen(request->external_proto);
    size_t host_len = strlen(request->external_host);

    if (!origin_len)
        return !parsed->websocket &&
               (proxy_slice_equal_ci(parsed->method, "GET") ||
                proxy_slice_equal_ci(parsed->method, "HEAD"));
    if (origin_len != proto_len + 3 + host_len ||
        strncasecmp(origin, request->external_proto, proto_len) ||
        memcmp(origin + proto_len, "://", 3) ||
        strncasecmp(origin + proto_len + 3, request->external_host, host_len))
        return 0;
    return 1;
}

static int proxy_request_security(const struct proxy_http_request *parsed,
                                  const struct system_ttyd_proxy_request *request,
                                  const char **error, int *status)
{
    struct proxy_slice expected_host;
    const char *target = parsed->target.ptr;
    size_t target_len = parsed->target.len;
    size_t prefix_len = strlen(TTYD_PROXY_PREFIX);

    if (!request->external_host || !request->external_proto ||
        (strcmp(request->external_proto, "http") &&
         strcmp(request->external_proto, "https"))) {
        *error = "ttyd_proxy_invalid_external_context";
        *status = 400;
        return -1;
    }
    expected_host.ptr = request->external_host;
    expected_host.len = strlen(request->external_host);
    if (!proxy_host_ok(parsed->host) || !proxy_host_ok(expected_host) ||
        !proxy_external_value(parsed->host, request->external_host)) {
        *error = "ttyd_proxy_host_mismatch";
        *status = 400;
        return -1;
    }
    if (parsed->forwarded_proto.len &&
        !proxy_external_value(parsed->forwarded_proto,
                              request->external_proto)) {
        *error = "ttyd_proxy_forwarded_proto_mismatch";
        *status = 400;
        return -1;
    }
    if (parsed->forwarded_host.len &&
        !proxy_external_value(parsed->forwarded_host,
                              request->external_host)) {
        *error = "ttyd_proxy_forwarded_host_mismatch";
        *status = 400;
        return -1;
    }
    if (parsed->sec_fetch_site.len &&
        !proxy_slice_equal_ci(parsed->sec_fetch_site, "same-origin") &&
        !proxy_slice_equal_ci(parsed->sec_fetch_site, "none")) {
        *error = "ttyd_proxy_cross_site_forbidden";
        *status = 403;
        return -1;
    }
    if (!proxy_origin_same(parsed, request)) {
        *error = "ttyd_proxy_origin_forbidden";
        *status = 403;
        return -1;
    }
    if (target_len < prefix_len ||
        memcmp(target, TTYD_PROXY_PREFIX, prefix_len) ||
        (target_len > prefix_len && target[prefix_len] != '/' &&
         target[prefix_len] != '?')) {
        *error = "ttyd_proxy_path_not_found";
        *status = 404;
        return -1;
    }
    if (memchr(target, '#', target_len) || memchr(target, '\\', target_len) ||
        memmem(target, target_len, "/../", 4) ||
        (target_len >= 3 && !memcmp(target + target_len - 3, "/..", 3))) {
        *error = "ttyd_proxy_invalid_path";
        *status = 400;
        return -1;
    }
    if (!proxy_slice_equal_ci(parsed->method, "GET") &&
        !proxy_slice_equal_ci(parsed->method, "HEAD") &&
        !proxy_slice_equal_ci(parsed->method, "POST")) {
        *error = "ttyd_proxy_method_not_allowed";
        *status = 405;
        return -1;
    }
    if (parsed->websocket && !proxy_slice_equal_ci(parsed->method, "GET")) {
        *error = "ttyd_proxy_invalid_websocket_method";
        *status = 400;
        return -1;
    }
    return 0;
}

struct proxy_dynamic {
    unsigned char *data;
    size_t length;
    size_t capacity;
};

static int proxy_dynamic_reserve(struct proxy_dynamic *buffer, size_t extra)
{
    size_t needed;
    size_t capacity;
    unsigned char *next;

    if (extra > SIZE_MAX - buffer->length)
        return -1;
    needed = buffer->length + extra;
    if (needed <= buffer->capacity)
        return 0;
    capacity = buffer->capacity ? buffer->capacity : 1024;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2)
            return -1;
        capacity *= 2;
    }
    next = realloc(buffer->data, capacity);
    if (!next)
        return -1;
    buffer->data = next;
    buffer->capacity = capacity;
    return 0;
}

static int proxy_dynamic_append(struct proxy_dynamic *buffer,
                                const void *data, size_t length)
{
    if (proxy_dynamic_reserve(buffer, length) != 0)
        return -1;
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

static int proxy_dynamic_text(struct proxy_dynamic *buffer, const char *text)
{
    return proxy_dynamic_append(buffer, text, strlen(text));
}

static int proxy_dynamic_slice(struct proxy_dynamic *buffer,
                               struct proxy_slice slice)
{
    return proxy_dynamic_append(buffer, slice.ptr, slice.len);
}

static int proxy_header_is(const struct proxy_header *header, const char *name)
{
    return proxy_slice_equal_ci(header->name, name);
}

static int proxy_connection_named_header(const struct proxy_http_request *request,
                                         const struct proxy_header *candidate)
{
    size_t i;

    for (i = 0; i < request->header_count; i++)
        if (proxy_header_is(&request->headers[i], "Connection")) {
            char name[64];
            if (proxy_slice_copy(candidate->name, name, sizeof(name)) == 0 &&
                proxy_header_token(request->headers[i].value, name))
                return 1;
        }
    return 0;
}

static int proxy_request_header_drop(const struct proxy_http_request *request,
                                     const struct proxy_header *header)
{
    static const char *const names[] = {
        "Host", "Connection", "Keep-Alive", "Upgrade", "Proxy-Connection",
        "Proxy-Authenticate", "Proxy-Authorization", "Authorization", "Cookie",
        "Set-Cookie", "TE", "Trailer", "Transfer-Encoding", "Forwarded",
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Forwarded-Prefix", "X-Real-IP", "Content-Length",
        "Sec-WebSocket-Extensions"
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (proxy_header_is(header, names[i]))
            return 1;
    return proxy_connection_named_header(request, header);
}

static int proxy_append_header(struct proxy_dynamic *buffer,
                               struct proxy_slice name,
                               struct proxy_slice value)
{
    return proxy_dynamic_slice(buffer, name) == 0 &&
           proxy_dynamic_text(buffer, ": ") == 0 &&
           proxy_dynamic_slice(buffer, value) == 0 &&
           proxy_dynamic_text(buffer, "\r\n") == 0 ? 0 : -1;
}

static int proxy_upstream_target(const struct proxy_http_request *request,
                                 struct proxy_slice *path,
                                 struct proxy_slice *query)
{
    const char *target = request->target.ptr;
    size_t target_len = request->target.len;
    size_t prefix_len = strlen(TTYD_PROXY_PREFIX);
    const char *question = memchr(target, '?', target_len);
    size_t path_len = question ? (size_t)(question - target) : target_len;

    query->ptr = question;
    query->len = question ? target_len - path_len : 0;
    path->ptr = target + prefix_len;
    path->len = path_len - prefix_len;
    if (!path->len) {
        path->ptr = "/";
        path->len = 1;
    }
    return 0;
}

static int proxy_build_upstream_request(
    const struct proxy_http_request *request,
    const struct system_ttyd_proxy_request *context,
    struct proxy_dynamic *out)
{
    struct proxy_slice path, query;
    size_t i;
    char content_length[64];

    memset(out, 0, sizeof(*out));
    proxy_upstream_target(request, &path, &query);
    if (proxy_dynamic_slice(out, request->method) != 0 ||
        proxy_dynamic_text(out, " ") != 0 ||
        proxy_dynamic_slice(out, path) != 0 ||
        proxy_dynamic_slice(out, query) != 0 ||
        proxy_dynamic_text(out, " HTTP/1.1\r\nHost: ") != 0 ||
        proxy_dynamic_text(out, context->external_host) != 0 ||
        proxy_dynamic_text(out, "\r\nX-Forwarded-Host: ") != 0 ||
        proxy_dynamic_text(out, context->external_host) != 0 ||
        proxy_dynamic_text(out, "\r\nX-Forwarded-Proto: ") != 0 ||
        proxy_dynamic_text(out, context->external_proto) != 0 ||
        proxy_dynamic_text(out, "\r\nX-Forwarded-Prefix: /terminal\r\n") != 0)
        goto failed;
    for (i = 0; i < request->header_count; i++) {
        const struct proxy_header *header = &request->headers[i];
        /* Preserve the client's requested ttyd subprotocol byte-for-byte. */
        if (request->websocket &&
            proxy_header_is(header, TTYD_PROXY_WS_SUBPROTOCOL_HEADER)) {
            if (proxy_append_header(out, header->name, header->value) != 0)
                goto failed;
            continue;
        }
        if (!proxy_request_header_drop(request, header) &&
            proxy_append_header(out, header->name, header->value) != 0)
            goto failed;
    }
    if (request->content_length_present) {
        snprintf(content_length, sizeof(content_length), "%llu",
                 (unsigned long long)request->content_length);
        if (proxy_dynamic_text(out, "Content-Length: ") != 0 ||
            proxy_dynamic_text(out, content_length) != 0 ||
            proxy_dynamic_text(out, "\r\n") != 0)
            goto failed;
    }
    if (request->websocket) {
        if (proxy_dynamic_text(out,
                               "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n") != 0)
            goto failed;
    } else if (proxy_dynamic_text(out, "Connection: close\r\n\r\n") != 0) {
        goto failed;
    }
    return 0;
failed:
    free(out->data);
    memset(out, 0, sizeof(*out));
    return -1;
}

static int proxy_uci_bool(const char *value, int fallback)
{
    if (!value || !*value)
        return fallback;
    if (!strcasecmp(value, "1") || !strcasecmp(value, "true") ||
        !strcasecmp(value, "yes") || !strcasecmp(value, "on"))
        return 1;
    if (!strcasecmp(value, "0") || !strcasecmp(value, "false") ||
        !strcasecmp(value, "no") || !strcasecmp(value, "off"))
        return 0;
    return fallback;
}

static int proxy_port(const char *value)
{
    char *end = NULL;
    long port;

    if (!value || !*value)
        return 7681;
    errno = 0;
    port = strtol(value, &end, 10);
    if (errno || !end || *end || port < 1 || port > 65535)
        return -1;
    return (int)port;
}

static int proxy_path_has_dotdot(const char *path)
{
    const char *p = path;

    while (p && *p) {
        while (*p == '/')
            p++;
        if (p[0] == '.' && p[1] == '.' && (!p[2] || p[2] == '/'))
            return 1;
        p = strchr(p, '/');
    }
    return 0;
}

static int proxy_unix_path_ok(const char *path)
{
    size_t length = path ? strlen(path) : 0;

    return length > 1 && length <= TTYD_PROXY_MAX_UNIX_PATH &&
           path[0] == '/' && !proxy_path_has_dotdot(path) &&
           (!strncmp(path, "/run/", 5) ||
            !strncmp(path, "/var/run/", 9) ||
            !strncmp(path, "/tmp/ttyd/", 10));
}

static int proxy_address_is_local(int family, const void *address)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *item;
    size_t length = family == AF_INET ? sizeof(struct in_addr) :
                    sizeof(struct in6_addr);
    int found = 0;

    if (getifaddrs(&addresses) != 0)
        return 0;
    for (item = addresses; item; item = item->ifa_next) {
        const void *candidate;
        if (!item->ifa_addr || item->ifa_addr->sa_family != family)
            continue;
        candidate = family == AF_INET ?
            (const void *)&((struct sockaddr_in *)item->ifa_addr)->sin_addr :
            (const void *)&((struct sockaddr_in6 *)item->ifa_addr)->sin6_addr;
        if (!memcmp(candidate, address, length)) {
            found = 1;
            break;
        }
    }
    freeifaddrs(addresses);
    return found;
}

static int proxy_address_from_interface(const char *interface,
                                        int prefer_ipv6,
                                        struct proxy_endpoint *endpoint)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *item;
    int preferred = prefer_ipv6 ? AF_INET6 : AF_INET;
    int pass;

    if (!interface || !*interface || getifaddrs(&addresses) != 0)
        return -1;
    for (pass = 0; pass < 2; pass++) {
        int family = pass ? (preferred == AF_INET ? AF_INET6 : AF_INET) : preferred;
        for (item = addresses; item; item = item->ifa_next) {
            const void *address;
            if (!item->ifa_addr || strcmp(item->ifa_name, interface) ||
                item->ifa_addr->sa_family != family)
                continue;
            address = family == AF_INET ?
                (const void *)&((struct sockaddr_in *)item->ifa_addr)->sin_addr :
                (const void *)&((struct sockaddr_in6 *)item->ifa_addr)->sin6_addr;
            if (inet_ntop(family, address, endpoint->address,
                          sizeof(endpoint->address))) {
                endpoint->family = family;
                freeifaddrs(addresses);
                return 0;
            }
        }
    }
    freeifaddrs(addresses);
    return -1;
}

static int proxy_network_endpoint(struct uci_context *ctx,
                                  const char *network_name,
                                  int prefer_ipv6,
                                  struct proxy_endpoint *endpoint)
{
    struct uci_package *network = NULL;
    struct uci_element *element;
    int rc = -1;

    if (!ctx || !network_name || !*network_name ||
        uci_load(ctx, "network", &network) != UCI_OK || !network)
        return -1;
    uci_foreach_element(&network->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *device;
        const char *address;
        char address_copy[INET6_ADDRSTRLEN + 4];
        char *slash;
        struct in_addr ipv4;
        struct in6_addr ipv6;

        if (strcmp(section->type, "interface") ||
            strcmp(section->e.name, network_name))
            continue;
        address = uci_lookup_option_string(ctx, section,
                    prefer_ipv6 ? "ip6addr" : "ipaddr");
        if (!address)
            address = uci_lookup_option_string(ctx, section,
                        prefer_ipv6 ? "ipaddr" : "ip6addr");
        if (address && strlen(address) < sizeof(address_copy)) {
            snprintf(address_copy, sizeof(address_copy), "%s", address);
            slash = strchr(address_copy, '/');
            if (slash)
                *slash = '\0';
            if (inet_pton(AF_INET, address_copy, &ipv4) == 1 &&
                proxy_address_is_local(AF_INET, &ipv4)) {
                endpoint->family = AF_INET;
                if (inet_ntop(AF_INET, &ipv4, endpoint->address,
                              sizeof(endpoint->address))) {
                    rc = 0;
                    break;
                }
            }
            if (inet_pton(AF_INET6, address_copy, &ipv6) == 1 &&
                proxy_address_is_local(AF_INET6, &ipv6)) {
                endpoint->family = AF_INET6;
                if (inet_ntop(AF_INET6, &ipv6, endpoint->address,
                              sizeof(endpoint->address))) {
                    rc = 0;
                    break;
                }
            }
        }
        device = uci_lookup_option_string(ctx, section, "device");
        if (!device)
            device = uci_lookup_option_string(ctx, section, "ifname");
        if (device && proxy_address_from_interface(device, prefer_ipv6,
                                                    endpoint) == 0)
            rc = 0;
        break;
    }
    uci_unload(ctx, network);
    return rc;
}

static int proxy_tcp_endpoint(struct uci_context *ctx, const char *interface,
                              int prefer_ipv6,
                              struct proxy_endpoint *endpoint)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (!interface || !*interface || !strcmp(interface, "0.0.0.0")) {
        endpoint->family = AF_INET;
        snprintf(endpoint->address, sizeof(endpoint->address), "127.0.0.1");
        return 0;
    }
    if (!strcmp(interface, "::") || !strcmp(interface, "[::]")) {
        endpoint->family = AF_INET6;
        snprintf(endpoint->address, sizeof(endpoint->address), "::1");
        return 0;
    }
    if (inet_pton(AF_INET, interface, &ipv4) == 1) {
        if (!proxy_address_is_local(AF_INET, &ipv4))
            return -1;
        endpoint->family = AF_INET;
        snprintf(endpoint->address, sizeof(endpoint->address), "%s", interface);
        return 0;
    }
    if (inet_pton(AF_INET6, interface, &ipv6) == 1) {
        if (!proxy_address_is_local(AF_INET6, &ipv6))
            return -1;
        endpoint->family = AF_INET6;
        snprintf(endpoint->address, sizeof(endpoint->address), "%s", interface);
        return 0;
    }
    if (interface[0] == '@')
        return proxy_network_endpoint(ctx, interface + 1, prefer_ipv6, endpoint);
    return proxy_address_from_interface(interface, prefer_ipv6, endpoint);
}

/* Select exactly the first enabled ttyd section in UCI order. */
static int proxy_load_first_enabled(struct proxy_endpoint *endpoint,
                                    const char **error)
{
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    struct uci_element *element;
    char directory[PATH_MAX];
    char package_name[64];
    const char *slash;
    int found = 0;
    int rc = -1;

    memset(endpoint, 0, sizeof(*endpoint));
    slash = strrchr(SYSTEM_TTYD_PROXY_CONFIG_PATH, '/');
    if (!slash || slash - SYSTEM_TTYD_PROXY_CONFIG_PATH == 0 ||
        strlen(slash + 1) >= sizeof(package_name) ||
        (size_t)(slash - SYSTEM_TTYD_PROXY_CONFIG_PATH) >= sizeof(directory)) {
        *error = "ttyd_proxy_config_invalid";
        return -1;
    }
    snprintf(directory, sizeof(directory), "%.*s",
             (int)(slash - SYSTEM_TTYD_PROXY_CONFIG_PATH),
             SYSTEM_TTYD_PROXY_CONFIG_PATH);
    snprintf(package_name, sizeof(package_name), "%s", slash + 1);
    ctx = uci_alloc_context();
    if (!ctx || uci_set_confdir(ctx, directory) != UCI_OK ||
        uci_load(ctx, package_name, &package) != UCI_OK || !package) {
        *error = "ttyd_proxy_config_unavailable";
        goto out;
    }
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *interface;
        const char *value;
        int prefer_ipv6;

        if (strcmp(section->type, "ttyd") ||
            !proxy_uci_bool(uci_lookup_option_string(ctx, section, "enable"), 1))
            continue;
        found = 1;
        interface = uci_lookup_option_string(ctx, section, "interface");
        value = uci_lookup_option_string(ctx, section, "unix_sock");
        endpoint->unix_socket = proxy_uci_bool(value, 0) ||
                                (interface && interface[0] == '/');
        endpoint->ssl = proxy_uci_bool(
            uci_lookup_option_string(ctx, section, "ssl"), 0);
        if (endpoint->unix_socket) {
            if (!proxy_unix_path_ok(interface)) {
                *error = "ttyd_proxy_invalid_unix_socket";
                goto out;
            }
            snprintf(endpoint->unix_path, sizeof(endpoint->unix_path), "%s",
                     interface);
        } else {
            endpoint->port = proxy_port(
                uci_lookup_option_string(ctx, section, "port"));
            prefer_ipv6 = proxy_uci_bool(
                uci_lookup_option_string(ctx, section, "ipv6"), 0);
            if (endpoint->port < 0 ||
                proxy_tcp_endpoint(ctx, interface, prefer_ipv6, endpoint) != 0) {
                *error = "ttyd_proxy_local_endpoint_unavailable";
                goto out;
            }
        }
        rc = 0;
        break;
    }
    if (!found)
        *error = "ttyd_proxy_no_enabled_instance";
out:
    if (package)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

static int proxy_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int proxy_connect_socket(const struct proxy_endpoint *endpoint)
{
    int fd;
    int rc;
    int error = 0;
    socklen_t error_len = sizeof(error);
    int64_t deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;

    fd = socket(endpoint->unix_socket ? AF_UNIX : endpoint->family,
                SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || proxy_set_nonblocking(fd) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if (endpoint->unix_socket) {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                 endpoint->unix_path);
        rc = connect(fd, (struct sockaddr *)&address, sizeof(address));
    } else if (endpoint->family == AF_INET6) {
        struct sockaddr_in6 address;
        memset(&address, 0, sizeof(address));
        address.sin6_family = AF_INET6;
        address.sin6_port = htons((uint16_t)endpoint->port);
        if (inet_pton(AF_INET6, endpoint->address, &address.sin6_addr) != 1) {
            close(fd);
            return -1;
        }
        rc = connect(fd, (struct sockaddr *)&address, sizeof(address));
    } else {
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)endpoint->port);
        if (inet_pton(AF_INET, endpoint->address, &address.sin_addr) != 1) {
            close(fd);
            return -1;
        }
        rc = connect(fd, (struct sockaddr *)&address, sizeof(address));
    }
    if (rc == 0)
        return fd;
    if (errno != EINPROGRESS || proxy_wait_fd(fd, POLLOUT, deadline) <= 0 ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error) {
        close(fd);
        return -1;
    }
    return fd;
}

static void proxy_upstream_close(struct proxy_upstream *upstream)
{
    if (!upstream)
        return;
    if (upstream->ssl) {
        SSL_shutdown(upstream->ssl);
        SSL_free(upstream->ssl);
    }
    if (upstream->ssl_ctx)
        SSL_CTX_free(upstream->ssl_ctx);
    if (upstream->fd >= 0)
        close(upstream->fd);
    memset(upstream, 0, sizeof(*upstream));
    upstream->fd = -1;
}

static int proxy_tls_connect(struct proxy_upstream *upstream)
{
    int64_t deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;

    upstream->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!upstream->ssl_ctx)
        return -1;
    SSL_CTX_set_min_proto_version(upstream->ssl_ctx, TLS1_2_VERSION);
    /* The endpoint is constrained to a local address or local UNIX socket. */
    SSL_CTX_set_verify(upstream->ssl_ctx, SSL_VERIFY_NONE, NULL);
    upstream->ssl = SSL_new(upstream->ssl_ctx);
    if (!upstream->ssl || SSL_set_fd(upstream->ssl, upstream->fd) != 1)
        return -1;
    for (;;) {
        int rc = SSL_connect(upstream->ssl);
        int ssl_error;
        short events;

        if (rc == 1)
            return 0;
        ssl_error = SSL_get_error(upstream->ssl, rc);
        if (ssl_error == SSL_ERROR_WANT_READ)
            events = POLLIN;
        else if (ssl_error == SSL_ERROR_WANT_WRITE)
            events = POLLOUT;
        else
            return -1;
        if (proxy_wait_fd(upstream->fd, events, deadline) <= 0)
            return -1;
    }
}

static int proxy_upstream_connect(const struct proxy_endpoint *endpoint,
                                  struct proxy_upstream *upstream)
{
    memset(upstream, 0, sizeof(*upstream));
    upstream->fd = proxy_connect_socket(endpoint);
    if (upstream->fd < 0)
        return -1;
    if (endpoint->ssl && proxy_tls_connect(upstream) != 0) {
        proxy_upstream_close(upstream);
        return -1;
    }
    return 0;
}

static int proxy_upstream_read(struct proxy_upstream *upstream,
                               void *data, size_t length)
{
    ssize_t got;

    if (!upstream->ssl) {
        got = recv(upstream->fd, data, length, 0);
        if (got > 0)
            return (int)got;
        if (got == 0)
            return PROXY_IO_EOF;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return PROXY_IO_WANT_READ;
        return PROXY_IO_ERROR;
    }
    {
        int rc = SSL_read(upstream->ssl, data,
                          length > INT_MAX ? INT_MAX : (int)length);
        int error;
        if (rc > 0)
            return rc;
        error = SSL_get_error(upstream->ssl, rc);
        if (error == SSL_ERROR_ZERO_RETURN)
            return PROXY_IO_EOF;
        if (error == SSL_ERROR_WANT_READ)
            return PROXY_IO_WANT_READ;
        if (error == SSL_ERROR_WANT_WRITE)
            return PROXY_IO_WANT_WRITE;
        return PROXY_IO_ERROR;
    }
}

static int proxy_upstream_write(struct proxy_upstream *upstream,
                                const void *data, size_t length)
{
    ssize_t sent;

    if (!upstream->ssl) {
        sent = send(upstream->fd, data, length, MSG_NOSIGNAL);
        if (sent > 0)
            return (int)sent;
        if (sent < 0 && errno == EINTR)
            return PROXY_IO_WANT_WRITE;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return PROXY_IO_WANT_WRITE;
        return PROXY_IO_ERROR;
    }
    {
        int rc = SSL_write(upstream->ssl, data,
                           length > INT_MAX ? INT_MAX : (int)length);
        int error;
        if (rc > 0)
            return rc;
        error = SSL_get_error(upstream->ssl, rc);
        if (error == SSL_ERROR_WANT_READ)
            return PROXY_IO_WANT_READ;
        if (error == SSL_ERROR_WANT_WRITE)
            return PROXY_IO_WANT_WRITE;
        return PROXY_IO_ERROR;
    }
}

static int proxy_upstream_write_all(struct proxy_upstream *upstream,
                                    const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0;
    int64_t deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;

    while (offset < length) {
        int rc = proxy_upstream_write(upstream, bytes + offset, length - offset);
        short events;

        if (rc > 0) {
            offset += (size_t)rc;
            deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;
            continue;
        }
        if (rc == PROXY_IO_WANT_READ)
            events = POLLIN;
        else if (rc == PROXY_IO_WANT_WRITE)
            events = POLLOUT;
        else
            return -1;
        if (proxy_wait_fd(upstream->fd, events, deadline) <= 0)
            return -1;
    }
    return 0;
}

static int proxy_read_response_head(struct proxy_upstream *upstream,
                                    struct proxy_response_head *head)
{
    int64_t deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;

    memset(head, 0, sizeof(*head));
    while (head->length < sizeof(head->data)) {
        void *end;
        int rc = proxy_upstream_read(upstream, head->data + head->length,
                                     sizeof(head->data) - head->length);
        short events;

        if (rc > 0) {
            head->length += (size_t)rc;
            end = memmem(head->data, head->length, "\r\n\r\n", 4);
            if (end) {
                head->header_length = (size_t)((unsigned char *)end + 4 -
                                               head->data);
                return 0;
            }
            deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;
            continue;
        }
        if (rc == PROXY_IO_WANT_READ)
            events = POLLIN;
        else if (rc == PROXY_IO_WANT_WRITE)
            events = POLLOUT;
        else
            return -1;
        if (proxy_wait_fd(upstream->fd, events, deadline) <= 0)
            return -1;
    }
    return -1;
}

static int proxy_response_parse_status(struct proxy_response_head *head)
{
    const char *text = (const char *)head->data;
    const char *line_end = memmem(text, head->header_length, "\r\n", 2);
    const char *space;
    int status;

    if (!line_end || line_end - text < 12 ||
        (strncmp(text, "HTTP/1.1 ", 9) && strncmp(text, "HTTP/1.0 ", 9)))
        return -1;
    space = text + 9;
    if (!isdigit((unsigned char)space[0]) ||
        !isdigit((unsigned char)space[1]) ||
        !isdigit((unsigned char)space[2]) ||
        (space + 3 < line_end && space[3] != ' '))
        return -1;
    status = (space[0] - '0') * 100 + (space[1] - '0') * 10 +
             (space[2] - '0');
    if (status < 100 || status > 599)
        return -1;
    head->status = status;
    return 0;
}

static int proxy_response_parse_framing(struct proxy_response_head *head)
{
    const char *text = (const char *)head->data;
    const char *headers_end = text + head->header_length - 4;
    const char *line_end = memmem(text, head->header_length, "\r\n", 2);
    const char *p;
    int content_length_count = 0;

    if (!line_end)
        return -1;
    head->content_length = 0;
    head->content_length_present = 0;
    p = line_end + 2;
    while (p < headers_end) {
        const char *colon;
        struct proxy_slice name;
        struct proxy_slice value;

        line_end = memmem(p, (size_t)(headers_end + 2 - p), "\r\n", 2);
        if (!line_end || line_end == p ||
            !(colon = memchr(p, ':', (size_t)(line_end - p))))
            return -1;
        name.ptr = p;
        name.len = (size_t)(colon - p);
        value.ptr = colon + 1;
        value.len = (size_t)(line_end - colon - 1);
        value = proxy_trim(value);
        if (!proxy_header_name_ok(name) || !proxy_value_ok(value))
            return -1;
        if (proxy_slice_equal_ci(name, "Transfer-Encoding"))
            return -1;
        if (proxy_slice_equal_ci(name, "Content-Length")) {
            if (++content_length_count != 1 ||
                proxy_decimal_size(value, &head->content_length) != 0)
                return -1;
            head->content_length_present = 1;
        }
        p = line_end + 2;
    }
    return 0;
}

static int proxy_forward_fixed_body(struct proxy_upstream *upstream,
                                    int client_fd,
                                    const unsigned char *initial,
                                    size_t initial_length,
                                    size_t content_length)
{
    unsigned char buffer[TTYD_PROXY_IO_BUFFER];
    size_t sent = 0;
    int64_t deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;

    if (content_length > TTYD_PROXY_MAX_HTTP_BODY ||
        initial_length > content_length)
        return -1;
    if (initial_length &&
        proxy_write_plain_all(client_fd, initial, initial_length, 3000) != 0)
        return -1;
    sent = initial_length;
    while (sent < content_length) {
        size_t wanted = content_length - sent;
        int rc;
        short events;

        if (wanted > sizeof(buffer))
            wanted = sizeof(buffer);
        rc = proxy_upstream_read(upstream, buffer, wanted);
        if (rc > 0) {
            if (proxy_write_plain_all(client_fd, buffer, (size_t)rc, 3000) != 0)
                return -1;
            sent += (size_t)rc;
            deadline = proxy_monotonic_ms() + TTYD_PROXY_CONNECT_TIMEOUT_MS;
            continue;
        }
        if (rc == PROXY_IO_WANT_READ)
            events = POLLIN;
        else if (rc == PROXY_IO_WANT_WRITE)
            events = POLLOUT;
        else
            return -1;
        if (proxy_wait_fd(upstream->fd, events, deadline) <= 0)
            return -1;
    }
    return 0;
}

static int proxy_response_connection_names(const struct proxy_response_head *head,
                                           struct proxy_slice name)
{
    const char *text = (const char *)head->data;
    const char *headers_end = text + head->header_length - 4;
    const char *line_end = memmem(text, head->header_length, "\r\n", 2);
    const char *p;
    char candidate[64];

    if (!line_end || proxy_slice_copy(name, candidate, sizeof(candidate)) != 0)
        return 0;
    p = line_end + 2;
    while (p < headers_end) {
        const char *colon;
        struct proxy_slice header_name;
        struct proxy_slice value;

        line_end = memmem(p, (size_t)(headers_end + 2 - p), "\r\n", 2);
        if (!line_end || !(colon = memchr(p, ':', (size_t)(line_end - p))))
            return 0;
        header_name.ptr = p;
        header_name.len = (size_t)(colon - p);
        value.ptr = colon + 1;
        value.len = (size_t)(line_end - colon - 1);
        if (proxy_slice_equal_ci(header_name, "Connection") &&
            proxy_header_token(proxy_trim(value), candidate))
            return 1;
        p = line_end + 2;
    }
    return 0;
}

static int proxy_response_header_drop(const struct proxy_response_head *head,
                                      struct proxy_slice name, int websocket)
{
    static const char *const always[] = {
        "Set-Cookie", "Proxy-Authenticate", "Proxy-Authorization",
        "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
        "X-Frame-Options", "Sec-WebSocket-Extensions"
    };
    static const char *const hop[] = {
        "Connection", "Keep-Alive", "Proxy-Connection", "Upgrade"
    };
    size_t i;

    for (i = 0; i < sizeof(always) / sizeof(always[0]); i++)
        if (proxy_slice_equal_ci(name, always[i]))
            return 1;
    if (!websocket)
        for (i = 0; i < sizeof(hop) / sizeof(hop[0]); i++)
            if (proxy_slice_equal_ci(name, hop[i]))
                return 1;
    if (websocket && (proxy_slice_equal_ci(name, "Connection") ||
                      proxy_slice_equal_ci(name, "Upgrade")))
        return 1;
    return proxy_response_connection_names(head, name);
}

static int proxy_build_response_header(const struct proxy_response_head *head,
                                       int websocket,
                                       struct proxy_dynamic *out)
{
    const char *text = (const char *)head->data;
    const char *headers_end = text + head->header_length - 4;
    const char *line_end = memmem(text, head->header_length, "\r\n", 2);
    const char *p;

    memset(out, 0, sizeof(*out));
    if (!line_end || proxy_dynamic_append(out, text,
                                          (size_t)(line_end + 2 - text)) != 0)
        goto failed;
    p = line_end + 2;
    while (p < headers_end) {
        const char *colon;
        struct proxy_slice name;
        struct proxy_slice value;

        line_end = memmem(p, (size_t)(headers_end + 2 - p), "\r\n", 2);
        if (!line_end || line_end == p || *p == ' ' || *p == '\t')
            goto failed;
        colon = memchr(p, ':', (size_t)(line_end - p));
        if (!colon)
            goto failed;
        name.ptr = p;
        name.len = (size_t)(colon - p);
        value.ptr = colon + 1;
        value.len = (size_t)(line_end - colon - 1);
        value = proxy_trim(value);
        if (!proxy_header_name_ok(name) || !proxy_value_ok(value))
            goto failed;
        /* A 101 response must return ttyd's selected subprotocol unchanged. */
        if (websocket &&
            proxy_slice_equal_ci(name, TTYD_PROXY_WS_SUBPROTOCOL_HEADER)) {
            if (proxy_append_header(out, name, value) != 0)
                goto failed;
            p = line_end + 2;
            continue;
        }
        if (!proxy_response_header_drop(head, name, websocket) &&
            proxy_append_header(out, name, value) != 0)
            goto failed;
        p = line_end + 2;
    }
    if (websocket) {
        if (proxy_dynamic_text(out,
                "Connection: Upgrade\r\nUpgrade: websocket\r\n") != 0)
            goto failed;
    } else if (proxy_dynamic_text(out, "Connection: close\r\n") != 0) {
        goto failed;
    }
    if (proxy_dynamic_text(out,
            "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n") != 0)
        goto failed;
    return 0;
failed:
    free(out->data);
    memset(out, 0, sizeof(*out));
    return -1;
}

static void proxy_buffer_compact(struct proxy_buffer *buffer)
{
    if (!buffer->length) {
        buffer->offset = 0;
    } else if (buffer->offset &&
               buffer->offset + buffer->length == sizeof(buffer->data)) {
        memmove(buffer->data, buffer->data + buffer->offset, buffer->length);
        buffer->offset = 0;
    }
}

static int proxy_tunnel(struct proxy_upstream *upstream, int client_fd,
                        int bidirectional, unsigned int idle_timeout_ms,
                        struct system_ttyd_proxy_result *result)
{
    struct proxy_buffer to_upstream = {0};
    struct proxy_buffer to_client = {0};
    int client_eof = !bidirectional;
    int upstream_eof = 0;
    int upstream_read_want = PROXY_IO_WANT_READ;
    int upstream_write_want = PROXY_IO_WANT_WRITE;
    int64_t deadline = proxy_monotonic_ms() + idle_timeout_ms;

    if (proxy_set_nonblocking(client_fd) != 0)
        return -1;
    for (;;) {
        struct pollfd fds[2];
        int timeout;
        int rc;
        int64_t now;
        int progress = 0;

        proxy_buffer_compact(&to_upstream);
        proxy_buffer_compact(&to_client);
        if (upstream_eof && !to_client.length)
            return 0;
        if (client_eof && !to_upstream.length && bidirectional)
            return 0;
        now = proxy_monotonic_ms();
        if (now >= deadline) {
            if (result)
                result->idle_timeout = 1;
            return 1;
        }
        timeout = (int)(deadline - now);
        memset(fds, 0, sizeof(fds));
        fds[0].fd = client_fd;
        if (!client_eof && to_upstream.offset + to_upstream.length <
                           sizeof(to_upstream.data))
            fds[0].events |= POLLIN;
        if (to_client.length)
            fds[0].events |= POLLOUT;
        fds[1].fd = upstream->fd;
        if (!upstream_eof && to_client.offset + to_client.length <
                             sizeof(to_client.data))
            fds[1].events |= upstream_read_want == PROXY_IO_WANT_WRITE ?
                             POLLOUT : POLLIN;
        if (to_upstream.length)
            fds[1].events |= upstream_write_want == PROXY_IO_WANT_READ ?
                             POLLIN : POLLOUT;
        if (upstream->ssl && SSL_pending(upstream->ssl) > 0)
            fds[1].events |= POLLIN;
        rc = poll(fds, 2, timeout);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0)
            return -1;
        if (rc == 0) {
            if (result)
                result->idle_timeout = 1;
            return 1;
        }

        if (!client_eof && (fds[0].revents & (POLLIN | POLLHUP))) {
            ssize_t got = recv(client_fd,
                to_upstream.data + to_upstream.offset + to_upstream.length,
                sizeof(to_upstream.data) - to_upstream.offset - to_upstream.length,
                0);
            if (got > 0) {
                to_upstream.length += (size_t)got;
                progress = 1;
            } else if (got == 0) {
                client_eof = 1;
            } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
        }
        if (to_client.length && (fds[0].revents & POLLOUT)) {
            ssize_t sent = send(client_fd, to_client.data + to_client.offset,
                                to_client.length, MSG_NOSIGNAL);
            if (sent > 0) {
                to_client.offset += (size_t)sent;
                to_client.length -= (size_t)sent;
                progress = 1;
            } else if (sent < 0 && errno != EINTR && errno != EAGAIN &&
                       errno != EWOULDBLOCK) {
                return -1;
            }
        }
        if (!upstream_eof &&
            ((fds[1].revents & (POLLIN | POLLOUT | POLLHUP)) ||
             (upstream->ssl && SSL_pending(upstream->ssl) > 0)) &&
            to_client.offset + to_client.length < sizeof(to_client.data)) {
            int got = proxy_upstream_read(upstream,
                to_client.data + to_client.offset + to_client.length,
                sizeof(to_client.data) - to_client.offset - to_client.length);
            if (got > 0) {
                to_client.length += (size_t)got;
                upstream_read_want = PROXY_IO_WANT_READ;
                progress = 1;
            } else if (got == PROXY_IO_EOF) {
                upstream_eof = 1;
            } else if (got == PROXY_IO_WANT_READ || got == PROXY_IO_WANT_WRITE) {
                upstream_read_want = got;
            } else {
                return -1;
            }
        }
        if (to_upstream.length &&
            (fds[1].revents & (POLLIN | POLLOUT))) {
            int sent = proxy_upstream_write(upstream,
                to_upstream.data + to_upstream.offset, to_upstream.length);
            if (sent > 0) {
                to_upstream.offset += (size_t)sent;
                to_upstream.length -= (size_t)sent;
                upstream_write_want = PROXY_IO_WANT_WRITE;
                progress = 1;
            } else if (sent == PROXY_IO_WANT_READ ||
                       sent == PROXY_IO_WANT_WRITE) {
                upstream_write_want = sent;
            } else {
                return -1;
            }
        }
        if (fds[0].revents & (POLLERR | POLLNVAL))
            return -1;
        if (fds[1].revents & (POLLERR | POLLNVAL))
            return -1;
        if (progress)
            deadline = proxy_monotonic_ms() + idle_timeout_ms;
    }
}

int system_ttyd_proxy_handle_authenticated(
    const struct system_ttyd_proxy_request *request,
    struct system_ttyd_proxy_result *result)
{
    struct proxy_http_request parsed;
    struct proxy_endpoint endpoint;
    struct proxy_upstream upstream;
    struct proxy_dynamic outbound = {0};
    struct proxy_dynamic response_header = {0};
    struct proxy_response_head response;
    const char *error = NULL;
    unsigned int idle_timeout;
    int status = 400;
    int rc;

    proxy_result_init(result);
    if (!request || request->client_fd < 0) {
        proxy_result_error(result, 400, "ttyd_proxy_invalid_context");
        return -1;
    }
    if (request->access != SYSTEM_TTYD_PROXY_ACCESS_ADMIN &&
        request->access != SYSTEM_TTYD_PROXY_ACCESS_OWNER)
        return proxy_send_error(request->client_fd, 403,
                                "ttyd_proxy_forbidden", result);
    if (!request->parent_connection_permit)
        return proxy_send_error(request->client_fd, 503,
                                "ttyd_proxy_connection_slot_required", result);
    rc = proxy_parse_request(request->raw_request, request->raw_request_len,
                             &parsed, &error);
    if (rc != 0)
        return proxy_send_error(request->client_fd,
                                rc == -2 ? 413 : 400, error, result);
    if (proxy_request_security(&parsed, request, &error, &status) != 0)
        return proxy_send_error(request->client_fd, status, error, result);
    if (proxy_load_first_enabled(&endpoint, &error) != 0)
        return proxy_send_error(request->client_fd, 503, error, result);
    if (proxy_build_upstream_request(&parsed, request, &outbound) != 0)
        return proxy_send_error(request->client_fd, 503,
                                "ttyd_proxy_resource_unavailable", result);
    if (proxy_upstream_connect(&endpoint, &upstream) != 0) {
        free(outbound.data);
        return proxy_send_error(request->client_fd, 502,
                                "ttyd_proxy_upstream_connect_failed", result);
    }
    if (result)
        result->upstream_connected = 1;
    if (proxy_upstream_write_all(&upstream, outbound.data, outbound.length) != 0 ||
        (parsed.body_len &&
         proxy_upstream_write_all(&upstream, parsed.body, parsed.body_len) != 0)) {
        proxy_upstream_close(&upstream);
        free(outbound.data);
        return proxy_send_error(request->client_fd, 502,
                                "ttyd_proxy_upstream_write_failed", result);
    }
    free(outbound.data);
    if (proxy_read_response_head(&upstream, &response) != 0) {
        proxy_upstream_close(&upstream);
        return proxy_send_error(request->client_fd, 502,
                                "ttyd_proxy_upstream_response_read_failed", result);
    }
    if (proxy_response_parse_status(&response) != 0) {
        proxy_upstream_close(&upstream);
        return proxy_send_error(request->client_fd, 502,
                                "ttyd_proxy_invalid_upstream_status", result);
    }
    if (proxy_response_parse_framing(&response) != 0) {
        proxy_upstream_close(&upstream);
        return proxy_send_error(request->client_fd, 502,
                                "ttyd_proxy_invalid_upstream_framing", result);
    }
    if (result) {
        result->upstream_status = response.status;
        result->http_status = response.status;
    }
    if ((!parsed.websocket || response.status != 101) &&
        !proxy_slice_equal_ci(parsed.method, "HEAD") &&
        response.status != 204 && response.status != 304 &&
        !response.content_length_present) {
        proxy_upstream_close(&upstream);
        return proxy_send_error(request->client_fd, 502,
                                "ttyd_proxy_upstream_length_required", result);
    }
    if (proxy_build_response_header(&response,
                                    parsed.websocket && response.status == 101,
                                    &response_header) != 0 ||
        proxy_write_plain_all(request->client_fd, response_header.data,
                              response_header.length, 3000) != 0) {
        free(response_header.data);
        proxy_upstream_close(&upstream);
        return -1;
    }
    free(response_header.data);
    if (!(parsed.websocket && response.status == 101)) {
        size_t buffered = response.length - response.header_length;
        int no_body = proxy_slice_equal_ci(parsed.method, "HEAD") ||
                      (response.status >= 100 && response.status < 200) ||
                      response.status == 204 || response.status == 304;

        rc = no_body ? (buffered ? -1 : 0) :
             proxy_forward_fixed_body(&upstream, request->client_fd,
                 response.data + response.header_length, buffered,
                 response.content_length);
        proxy_upstream_close(&upstream);
        if (rc != 0) {
            proxy_result_error(result, response.status,
                               "ttyd_proxy_response_body_failed");
            return -1;
        }
        return 0;
    }
    if (result)
        result->websocket_upgraded = 1;
    if (response.length > response.header_length &&
        proxy_write_plain_all(request->client_fd,
            response.data + response.header_length,
            response.length - response.header_length, 3000) != 0) {
        proxy_upstream_close(&upstream);
        return -1;
    }
    idle_timeout = request->idle_timeout_ms ? request->idle_timeout_ms :
                   TTYD_PROXY_DEFAULT_IDLE_MS;
    if (idle_timeout < TTYD_PROXY_MIN_IDLE_MS)
        idle_timeout = TTYD_PROXY_MIN_IDLE_MS;
    if (idle_timeout > TTYD_PROXY_MAX_IDLE_MS)
        idle_timeout = TTYD_PROXY_MAX_IDLE_MS;
    rc = proxy_tunnel(&upstream, request->client_fd,
                      parsed.websocket && response.status == 101,
                      idle_timeout, result);
    proxy_upstream_close(&upstream);
    if (rc < 0) {
        proxy_result_error(result, response.status,
                           "ttyd_proxy_stream_closed");
        return -1;
    }
    if (rc > 0)
        proxy_result_error(result, response.status,
                           "ttyd_proxy_idle_timeout");
    return 0;
}
