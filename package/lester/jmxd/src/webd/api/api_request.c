// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#include <string.h>

#include "api_request.h"

int webd_hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void webd_query_decode(const char *src, size_t src_len,
                       char *out, size_t out_len)
{
    size_t i = 0, j = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!src)
        return;
    while (i < src_len && j + 1 < out_len) {
        if (src[i] == '%' && i + 2 < src_len) {
            int hi = webd_hex_value(src[i + 1]);
            int lo = webd_hex_value(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out[j++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out[j++] = src[i] == '+' ? ' ' : src[i];
        i++;
    }
    out[j] = '\0';
}

int webd_query_get(const char *query, const char *key,
                   char *out, size_t out_len)
{
    size_t key_len;
    const char *p;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!query || !query[0] || !key || !key[0])
        return 0;
    key_len = strlen(key);
    p = query;
    while (*p) {
        const char *pair_end = strchr(p, '&');
        const char *eq;
        const char *name_end;
        const char *value;

        if (!pair_end)
            pair_end = p + strlen(p);
        eq = memchr(p, '=', (size_t)(pair_end - p));
        name_end = eq ? eq : pair_end;
        if ((size_t)(name_end - p) == key_len && !strncmp(p, key, key_len)) {
            value = eq ? eq + 1 : pair_end;
            webd_query_decode(value, (size_t)(pair_end - value), out, out_len);
            return 1;
        }
        p = *pair_end ? pair_end + 1 : pair_end;
    }
    return 0;
}
