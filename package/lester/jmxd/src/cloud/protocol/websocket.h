// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef CW_WEBSOCKET_H
#define CW_WEBSOCKET_H
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <strings.h>

/* HTTP upgrade policy only. WebSocket frames remain opaque end to end. */
static inline int cw_ws_token(const char *list, const char *token)
{
    if (!list) return 0;
    while (*list) {
        while (*list == ' ' || *list == '\t' || *list == ',') ++list;
        const char *end = strchr(list, ',');
        if (!end) end = list + strlen(list);
        const char *trim = end;
        while (trim > list && (trim[-1] == ' ' || trim[-1] == '\t')) --trim;
        if ((size_t)(trim - list) == strlen(token) &&
            !strncasecmp(list, token, (size_t)(trim - list))) return 1;
        list = *end ? end + 1 : end;
    }
    return 0;
}

static inline const char *cw_ws_header(struct json_object *headers,
                                       const char *name, int *count)
{
    const char *value = NULL;
    *count = 0;
    for (size_t i = 0; i < json_object_array_length(headers); ++i) {
        struct json_object *pair = json_object_array_get_idx(headers, i);
        const char *n = json_object_get_string(json_object_array_get_idx(pair, 0));
        if (n && !strcasecmp(n, name)) {
            ++*count;
            value = json_object_get_string(json_object_array_get_idx(pair, 1));
        }
    }
    return value;
}

static inline void cw_ws_add(struct json_object *headers, const char *name,
                              const char *value)
{
    struct json_object *pair = json_object_new_array();
    json_object_array_add(pair, json_object_new_string(name));
    json_object_array_add(pair, json_object_new_string(value));
    json_object_array_add(headers, pair);
}

/* 0 ordinary HTTP, 1 valid WebSocket request, -1 malformed/unsupported upgrade. */
static inline int cw_ws_request(const char *method, struct json_object *headers,
                                 char accept[29])
{
    int nu, nc, nk, nv, nf;
    const char *upgrade = cw_ws_header(headers, "upgrade", &nu);
    const char *connection = cw_ws_header(headers, "connection", &nc);
    const char *key = cw_ws_header(headers, "sec-websocket-key", &nk);
    const char *version = cw_ws_header(headers, "sec-websocket-version", &nv);
    if (!nu && !nk && !nv && !cw_ws_token(connection, "upgrade")) return 0;
    if (strcmp(method, "GET") || nu != 1 || nc != 1 || nk != 1 || nv != 1 ||
        strcasecmp(upgrade, "websocket") || !cw_ws_token(connection, "upgrade") ||
        strcmp(version, "13") || strlen(key) != 24) return -1;
    cw_ws_header(headers, "transfer-encoding", &nf);
    if (nf) return -1;
    cw_ws_header(headers, "content-length", &nf);
    if (nf) return -1;
    unsigned char decoded[18], canonical[25], digest[SHA_DIGEST_LENGTH];
    if (EVP_DecodeBlock(decoded, (const unsigned char *)key, 24) != 18) return -1;
    EVP_EncodeBlock(canonical, decoded, 16);
    if (strcmp((char *)canonical, key)) return -1;
    char input[61];
    memcpy(input, key, 24);
    memcpy(input + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 37);
    SHA1((unsigned char *)input, 60, digest);
    EVP_EncodeBlock((unsigned char *)accept, digest, sizeof digest);
    return 1;
}

static inline int cw_ws_response(struct json_object *headers, const char *accept)
{
    int nu, nc, na, nf;
    const char *upgrade = cw_ws_header(headers, "upgrade", &nu);
    const char *connection = cw_ws_header(headers, "connection", &nc);
    const char *actual = cw_ws_header(headers, "sec-websocket-accept", &na);
    cw_ws_header(headers, "content-length", &nf);
    if (nf) return -1;
    cw_ws_header(headers, "transfer-encoding", &nf);
    return nf || nu != 1 || nc != 1 || na != 1 ||
        strcasecmp(upgrade, "websocket") || !cw_ws_token(connection, "upgrade") ||
        strcmp(actual, accept) ? -1 : 0;
}
#endif
