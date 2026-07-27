// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt webd unauthenticated static/login shell serving. */
#include <stdio.h>
#include <string.h>
#include "webd_http.h"
#include "webd_static.h"

#define WEBD_PUBLIC_ROOT "/www/dreamingwrt"

static int webd_static_rel_ok(const char *rel)
{
    const unsigned char *p;

    if (!rel || !rel[0] || rel[0] == '/')
        return 0;
    if (strstr(rel, "..") || strchr(rel, '\\'))
        return 0;
    for (p = (const unsigned char *)rel; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

int webd_send_static(int fd, const char *path, const char *method, int accepts_gzip)
{
    const char *root = NULL;
    const char *fallback_root = NULL;
    const char *rel = NULL;
    char full[512];
    char fallback[512];

    if (!path)
        return 0;
    if (!strcmp(path, "/app") || !strcmp(path, "/app/")) {
        if (http_send_file_path_encoded(fd, WEBD_PUBLIC_ROOT "/app/index.html", method, accepts_gzip) == 0)
            return 1;
        http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
        return 1;
    } else if (!strcmp(path, "/login") || !strcmp(path, "/login/")) {
        if (http_send_file_path_encoded(fd, WEBD_PUBLIC_ROOT "/login/index.html", method, accepts_gzip) == 0)
            return 1;
        if (http_send_file_path_encoded(fd, "/www/login/index.html", method, accepts_gzip) == 0)
            return 1;
        http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
        return 1;
    } else if (!strcmp(path, "/favicon.ico")) {
        if (http_send_file_path_encoded(fd, WEBD_PUBLIC_ROOT "/static/images/favicon.ico", method, accepts_gzip) == 0)
            return 1;
        if (http_send_file_path_encoded(fd, WEBD_PUBLIC_ROOT "/favicon.ico", method, accepts_gzip) == 0)
            return 1;
        if (http_send_file_path_encoded(fd, "/www/favicon.ico", method, accepts_gzip) == 0)
            return 1;
        http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
        return 1;
    } else if (!strncmp(path, "/static/", 8)) {
        root = WEBD_PUBLIC_ROOT "/static";
        rel = path + 8;
    } else if (!strncmp(path, "/plugins/", 9)) {
        root = WEBD_PUBLIC_ROOT "/plugins";
        rel = path + 9;
    } else if (!strcmp(path, "/dynamic/menu/1.json")) {
        return 0;
    } else if (!strncmp(path, "/dynamic/", 9)) {
        root = WEBD_PUBLIC_ROOT "/dynamic";
        rel = path + 9;
    } else if (!strncmp(path, "/assets/", 8)) {
        root = WEBD_PUBLIC_ROOT "/assets";
        fallback_root = "/www/assets";
        rel = path + 8;
    } else if (!strncmp(path, "/app/", 5)) {
        root = WEBD_PUBLIC_ROOT "/app";
        rel = path + 5;
    } else if (!strncmp(path, "/login/", 7)) {
        root = WEBD_PUBLIC_ROOT "/login";
        fallback_root = "/www/login";
        rel = path + 7;
    } else if (!strncmp(path, "/luci-static/", 13)) {
        root = "/www/luci-static";
        rel = path + 13;
    } else {
        return 0;
    }

    if (!webd_static_rel_ok(rel)) {
        http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
        return 1;
    }
    if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full)) {
        http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
        return 1;
    }
    if (http_send_file_path_encoded(fd, full, method, accepts_gzip) == 0)
        return 1;
    if (fallback_root) {
        if (snprintf(fallback, sizeof(fallback), "%s/%s", fallback_root, rel) >= (int)sizeof(fallback)) {
            http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
            return 1;
        }
        if (http_send_file_path_encoded(fd, fallback, method, accepts_gzip) == 0)
            return 1;
    }

    http_send(fd, 404, "Not Found", "text/plain", "not found", 9);
    return 1;
}

int webd_send_console_shell(int fd, const char *method)
{
    static const char *candidates[] = {
        WEBD_PUBLIC_ROOT "/index.html",
        WEBD_PUBLIC_ROOT "/login/index.html",
        "/www/dreamingwrt-console/index.html",
        "/www/dreamingwrt-console/login/index.html",
        "/www/luci-static/dreamingwrt/dashboard/index.html",
        NULL
    };
    int i;

    for (i = 0; candidates[i]; i++) {
        if (http_send_file_path(fd, candidates[i], method) == 0)
            return 0;
    }

    {
        const char *html =
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>DreamingWrt</title></head>"
            "<body><main id=\"root\" data-api=\"/api/v1\"></main>"
            "<script>window.DREAMINGWRT_API_BASE='/api/v1';</script></body></html>";
        return http_send(fd, 200, "OK", "text/html; charset=utf-8", html, (int)strlen(html));
    }
}
