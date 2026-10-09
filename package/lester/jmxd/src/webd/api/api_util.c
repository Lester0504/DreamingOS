// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Time, io and lock primitives shared by the other api/ modules.
 *
 * These eight are not json, not error mapping and not ubus, but each of those
 * three needs some of them: webd_meta() wants now_s() and webd_request_id(), the
 * shared-json cache wants webd_now_ms(), webd_write_all(),
 * webd_ws_file_mtime_ms() and webd_shared_lock_open(), and the ubus deadline
 * plumbing wants the two timespec helpers. Without this module they would either
 * be duplicated or left behind in jmx_app_api.c with the new modules calling back
 * into it.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "api_json.h"
#include "api_util.h"

void webd_timespec_add_ms(struct timespec *ts, int timeout_ms)
{
    if (!ts || timeout_ms <= 0)
        return;
    ts->tv_sec += timeout_ms / 1000;
    ts->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_nsec -= 1000000000L;
        ts->tv_sec++;
    }
}

int webd_timespec_remaining_ms(const struct timespec *deadline)
{
    struct timespec now;
    int64_t ns;

    if (!deadline || clock_gettime(CLOCK_REALTIME, &now) != 0)
        return 0;
    ns = ((int64_t)deadline->tv_sec - (int64_t)now.tv_sec) * 1000000000LL +
         ((int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec);
    if (ns <= 0)
        return 0;
    return (int)((ns + 999999LL) / 1000000LL);
}

int64_t now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

int64_t webd_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

int webd_write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);

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

int64_t webd_ws_file_mtime_ms(const struct stat *st)
{
    if (!st)
        return 0;
#if defined(__APPLE__)
    return (int64_t)st->st_mtimespec.tv_sec * 1000 +
           (int64_t)(st->st_mtimespec.tv_nsec / 1000000);
#else
    return (int64_t)st->st_mtim.tv_sec * 1000 +
           (int64_t)(st->st_mtim.tv_nsec / 1000000);
#endif
}

void webd_request_id(char *buf, size_t len)
{
    if (!buf || len == 0)
        return;
    snprintf(buf, len, "webd-%lld-%ld", (long long)now_s(), random());
}

int webd_shared_lock_open(const char *lock_path)
{
    int fd;

    if (!lock_path || (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST))
        return -1;
    fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

/* -- Small text, data-URL and address helpers (Phase 8C) ---------------------
 * Case-insensitive substring, base64 digit / data-URL MIME sniffing, the
 * first-non-empty pickers, the jmx {code,data} unwrapper and IPv6 scope
 * tests. Lifted verbatim out of jmx_app_api.c, which no longer calls any of
 * them; each api/ caller carries its own declaration.
 */
int webd_str_contains_i(const char *haystack, const char *needle)
{
    char h[2048];
    char n[256];

    if (!needle || !needle[0])
        return 1;
    if (!haystack)
        return 0;
    snprintf(h, sizeof(h), "%s", haystack);
    snprintf(n, sizeof(n), "%s", needle);
    for (char *p = h; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    for (char *p = n; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return strstr(h, n) != NULL;
}

int webd_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int webd_data_url_main_mime(const char *data_url, const char *base64_marker,
                                   char *out, size_t out_len)
{
    const char *start;
    const char *end;
    const char *semi;
    size_t len;

    if (!data_url || !base64_marker || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (strncasecmp(data_url, "data:", 5))
        return -1;
    start = data_url + 5;
    end = base64_marker;
    semi = memchr(start, ';', (size_t)(end - start));
    if (semi)
        end = semi;
    while (start < end && isspace((unsigned char)*start))
        start++;
    while (end > start && isspace((unsigned char)end[-1]))
        end--;
    if (end <= start)
        return -1;
    len = (size_t)(end - start);
    if (len >= out_len)
        return -1;
    for (size_t i = 0; i < len; i++)
        out[i] = (char)tolower((unsigned char)start[i]);
    out[len] = '\0';
    return 0;
}

struct json_object *webd_jmx_data_ref(struct json_object *resp)
{
    return webd_data_from_jmx_response(resp);
}

const char *webd_first_nonempty4(const char *a, const char *b,
                                        const char *c, const char *d)
{
    if (a && a[0]) return a;
    if (b && b[0]) return b;
    if (c && c[0]) return c;
    if (d && d[0]) return d;
    return "";
}

const char *webd_first_nonempty6(const char *a, const char *b,
                                        const char *c, const char *d,
                                        const char *e, const char *f)
{
    if (a && a[0]) return a;
    if (b && b[0]) return b;
    if (c && c[0]) return c;
    if (d && d[0]) return d;
    if (e && e[0]) return e;
    if (f && f[0]) return f;
    return "";
}

int webd_ipv6_is_link_local(const char *addr)
{
    return addr && addr[0] && !strncasecmp(addr, "fe80:", 5);
}

int webd_ipv6_is_ula(const char *addr)
{
    return addr && addr[0] &&
           (!strncasecmp(addr, "fc", 2) || !strncasecmp(addr, "fd", 2));
}

int webd_ipv6_is_loopback(const char *addr)
{
    return addr && (!strcmp(addr, "::1") || !strcasecmp(addr, "0:0:0:0:0:0:0:1"));
}
