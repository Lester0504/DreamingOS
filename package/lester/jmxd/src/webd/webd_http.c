// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DreamingWrt webd HTTP response helpers.
 *
 * This file owns only raw HTTP response writing and constrained public file
 * serving. Route decisions stay in jmx_app_api.c / webd_static.c.
 */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stddef.h>
#include "webd_http.h"

static const char *http_status_text(int status)
{
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Content Too Large";
    case 428: return "Precondition Required";
    case 429: return "Too Many Requests";
    case 502: return "Bad Gateway";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 500: return "Internal Server Error";
    default: return "Bad Request";
    }
}

static int http_write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }

    return 0;
}

int http_send(int fd, int status, const char *status_text,
              const char *content_type, const char *body, int body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match,Accept\r\n"
        "Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n",
        status, status_text, content_type, body_len);
    if (hlen <= 0 || hlen >= (int)sizeof(header))
        return -1;
    if (http_write_all(fd, header, (size_t)hlen) != 0)
        return -1;
    if (body && body_len > 0 && http_write_all(fd, body, (size_t)body_len) != 0)
        return -1;
    return 0;
}

int http_send_raw(int fd, int status, const char *content_type,
                  const void *body, size_t body_len,
                  const char *cache_control)
{
    char header[768];
    const char *status_text = http_status_text(status);
    int hlen;

    if (!content_type || !content_type[0])
        content_type = "application/octet-stream";
    if (!cache_control || !cache_control[0])
        cache_control = "no-cache";

    hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match,Accept\r\n"
        "Access-Control-Allow-Methods: GET,HEAD,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: %s\r\n"
        "\r\n",
        status, status_text, content_type, (unsigned long long)body_len,
        cache_control);
    if (hlen <= 0 || hlen >= (int)sizeof(header))
        return -1;
    if (http_write_all(fd, header, (size_t)hlen) != 0)
        return -1;
    if (body && body_len > 0 && http_write_all(fd, (const char *)body, body_len) != 0)
        return -1;
    return 0;
}

static const char *webd_mime_type(const char *path)
{
    const char *ext = path ? strrchr(path, '.') : NULL;

    if (!ext) return "application/octet-stream";
    ext++;
    if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm")) return "text/html; charset=utf-8";
    if (!strcasecmp(ext, "css")) return "text/css; charset=utf-8";
    if (!strcasecmp(ext, "js") || !strcasecmp(ext, "mjs")) return "application/javascript; charset=utf-8";
    if (!strcasecmp(ext, "json")) return "application/json";
    if (!strcasecmp(ext, "svg")) return "image/svg+xml";
    if (!strcasecmp(ext, "png")) return "image/png";
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg")) return "image/jpeg";
    if (!strcasecmp(ext, "webp")) return "image/webp";
    if (!strcasecmp(ext, "gif")) return "image/gif";
    if (!strcasecmp(ext, "ico")) return "image/x-icon";
    if (!strcasecmp(ext, "mp4")) return "video/mp4";
    if (!strcasecmp(ext, "webm")) return "video/webm";
    if (!strcasecmp(ext, "woff2")) return "font/woff2";
    return "application/octet-stream";
}

static int webd_file_is_html(const char *path)
{
    const char *ext = path ? strrchr(path, '.') : NULL;

    if (!ext)
        return 0;
    ext++;
    return !strcasecmp(ext, "html") || !strcasecmp(ext, "htm");
}

static const char *webd_file_cache_control(const char *path)
{
    if (webd_file_is_html(path))
        return "no-store, no-cache, must-revalidate, max-age=0";
    return "public, max-age=86400";
}

static int webd_public_path_ok(const char *path)
{
    const unsigned char *p;

    if (!path || !path[0] || strstr(path, "..") || strchr(path, '\\'))
        return 0;
    if (strncmp(path, "/www/", 5) && strncmp(path, "www/", 4))
        return 0;
    for (p = (const unsigned char *)path; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

int http_send_file_path(int fd, const char *path, const char *method)
{
    return http_send_file_path_encoded(fd, path, method, 0);
}

int http_send_file_path_encoded(int fd, const char *path, const char *method, int accepts_gzip)
{
    int f;
    struct stat st;
    char header[768];
    int hlen;
    char buf[8192];
    char gzip_path[512];
    const char *served_path = path;
    int gzip = 0;

    if (!webd_public_path_ok(path))
        return -1;
    if (accepts_gzip && snprintf(gzip_path, sizeof(gzip_path), "%s.gz", path) < (int)sizeof(gzip_path)) {
        struct stat gzst;
        if (webd_public_path_ok(gzip_path) && stat(gzip_path, &gzst) == 0 && S_ISREG(gzst.st_mode)) {
            served_path = gzip_path;
            gzip = 1;
        }
    }
    f = open(served_path, O_RDONLY | O_CLOEXEC);
    if (f < 0)
        return -1;
    if (fstat(f, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(f);
        return -1;
    }

    hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lld\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match,Accept\r\n"
        "Access-Control-Allow-Methods: GET,HEAD,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: %s\r\n"
        "%s"
        "%s"
        "%s%s"
        "%s"
        "\r\n",
        webd_mime_type(path), (long long)st.st_size,
        webd_file_cache_control(path),
        webd_file_is_html(path) ? "Pragma: no-cache\r\n" : "",
        webd_file_is_html(path) ? "Expires: 0\r\n" : "",
        gzip ? "Content-Encoding: " : "", gzip ? "gzip\r\n" : "",
        gzip ? "Vary: Accept-Encoding\r\n" : "");
    if (hlen <= 0 || hlen >= (int)sizeof(header) || http_write_all(fd, header, (size_t)hlen) != 0) {
        close(f);
        return -1;
    }
    if (method && !strcmp(method, "HEAD")) {
        close(f);
        return 0;
    }
    for (;;) {
        ssize_t n = read(f, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(f);
            return -1;
        }
        if (n == 0)
            break;
        if (http_write_all(fd, buf, (size_t)n) != 0) {
            close(f);
            return -1;
        }
    }
    close(f);
    return 0;
}

int http_send_json(int fd, int status, struct json_object *resp)
{
    const char *s = resp ? json_object_to_json_string(resp) : "{}";
    int slen = (int)strlen(s);
    unsigned int hash = 5381;
    int i;
    char etag[32];
    char header[768];
    const char *status_text = http_status_text(status);
    int hlen;

    for (i = 0; i < slen; i++) hash = ((hash << 5) + hash) + (unsigned char)s[i];
    snprintf(etag, sizeof(etag), "\"%08x\"", hash);

    hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match,Accept\r\n"
        "Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: max-age=0\r\n"
        "ETag: %s\r\n"
        "\r\n",
        status, status_text, slen, etag);
    if (hlen <= 0 || hlen >= (int)sizeof(header))
        return -1;
    if (http_write_all(fd, header, (size_t)hlen) != 0)
        return -1;
    if (slen > 0 && http_write_all(fd, s, (size_t)slen) != 0)
        return -1;
    return 0;
}

int http_send_json_cookie(int fd, int status, struct json_object *resp,
                          const char *cookie)
{
    const char *s = resp ? json_object_to_json_string(resp) : "{}";
    int slen = (int)strlen(s);
    char header[1024];
    const char *status_text = http_status_text(status);
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization,Content-Type,If-None-Match,Accept\r\n"
        "Access-Control-Allow-Methods: GET,POST,PATCH,PUT,DELETE,OPTIONS\r\n"
        "Cache-Control: max-age=0\r\n"
        "%s%s"
        "\r\n",
        status, status_text, slen,
        cookie && cookie[0] ? "Set-Cookie: " : "",
        cookie && cookie[0] ? cookie : "");
    if (hlen <= 0 || hlen >= (int)sizeof(header))
        return -1;
    if (http_write_all(fd, header, (size_t)hlen) != 0)
        return -1;
    if (slen > 0 && http_write_all(fd, s, (size_t)slen) != 0)
        return -1;
    return 0;
}

int http_send_sse_header(int fd)
{
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache, no-transform\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "X-Accel-Buffering: no\r\n"
        "\r\n";
    return http_write_all(fd, hdr, strlen(hdr));
}
