// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "cloud_web_client.h"
#include "protocol/webframe.h"
#include "protocol/websocket.h"
#include "vendor/picohttpparser/picohttpparser.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <json-c/json.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CWC_TX_MAX (4u * 1024u * 1024u)
#define CWC_STREAMS 32
#define CWC_HEAD_MAX 65536u

struct cwc_connection;
struct cwc_raw {
    char buffer[CWC_HEAD_MAX];
    size_t len, pos;
    int connected, phase, eof, ready, chunked, sized;
    uint64_t remaining, received;
    struct phr_chunked_decoder decoder;
    curl_socket_t fd;
};
struct cwc_request {
    struct cwc_connection *connection;
    uint32_t id;
    struct cw_web_open head;
    struct json_object *headers;
    struct json_object *response_headers;
    size_t response_header_bytes;
    unsigned char *body;
    size_t body_len, body_cap;
    uint64_t upload_expected, upload_received;
    int upload_streaming, upload_fin, upload_paused, upload_unknown;
    CURL *easy;
    struct curl_slist *curl_headers;
    struct curl_slist *resolve;
    int attached;
    int response_sent;
    int paused;
    size_t paused_bytes;
    int done;
    int64_t started;
    int websocket;
    char ws_accept[29];
    struct cwc_raw *raw;
};

struct cwc_connection {
    const struct cwc_config *config;
    const struct cwc_hooks *hooks;
    CURL *transport;
    CURLM *multi;
    curl_socket_t fd;
    struct cw_session session;
    struct cwc_request requests[CWC_STREAMS];
    unsigned char rx[CW_WIRE_MSG_MAX];
    size_t rx_len;
    unsigned char *tx;
    size_t tx_pos, tx_len;
    uint32_t last_id, generation;
    int64_t revision, last_rx, last_ping, last_tx;
    unsigned heartbeat;
    int stage;
    int failed;
};

static int64_t cwc_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int cwc_running(struct cwc_connection *c)
{
    return !c->hooks->running || c->hooks->running(c->hooks->user);
}

static void cwc_status(struct cwc_connection *c, const char *state, const char *why)
{
    if (c->hooks->status)
        c->hooks->status(c->hooks->user, state, why, c->generation,
                         c->revision, c->session.n_services);
}

int cwc_host_valid(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    size_t label = 0;
    if (!n || n > 253 || s[0] == '.' || s[n - 1] == '.')
        return 0;
    for (size_t i = 0; i < n; ++i) {
        if (!((s[i] >= 'a' && s[i] <= 'z') ||
              (s[i] >= '0' && s[i] <= '9') || s[i] == '-' || s[i] == '.'))
            return 0;
        if (s[i] == '.') {
            if (!label || s[i - 1] == '-')
                return 0;
            label = 0;
        } else {
            if ((!label && s[i] == '-') || ++label > 63)
                return 0;
        }
    }
    return s[n - 1] != '-';
}

int cwc_address_allowed(const char *address, int container)
{
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, address, &a4) == 1) {
        uint32_t ip = ntohl(a4.s_addr);
        if ((ip >> 24) == 127)
            return container && ip == 0x7f000001u;
        return (ip >> 24) == 10 || (ip >> 20) == 0xac1 ||
               (ip >> 16) == 0xc0a8;
    }
    if (inet_pton(AF_INET6, address, &a6) == 1) {
        if (IN6_IS_ADDR_LOOPBACK(&a6))
            return container;
        return (a6.s6_addr[0] & 0xfe) == 0xfc; /* ULA, not link-local/metadata */
    }
    return 0;
}

int cwc_service_valid(const struct cwc_service *s)
{
    struct in_addr a4;
    struct in6_addr a6;
    if (!s || !cw_web_is_service_id(s->id) || !cwc_host_valid(s->public_host))
        return 0;
    if (s->tls_pin[0]) {
        unsigned char decoded[36], canonical[45];
        if (!s->https || s->management || !s->ca_path[0] ||
            strlen(s->tls_pin) != 52 || strncmp(s->tls_pin, "sha256//", 8) ||
            EVP_DecodeBlock(decoded, (const unsigned char *)s->tls_pin + 8, 44) != 33)
            return 0;
        EVP_EncodeBlock(canonical, decoded, 32);
        if (strcmp((char *)canonical, s->tls_pin + 8)) return 0;
    }
    if (s->management)
        return !strcmp(s->id, "web") && !s->target_host[0] && !s->port &&
               !s->container;
    if (!strcmp(s->id, "web") || !s->port ||
        (!cwc_host_valid(s->target_host) && inet_pton(AF_INET6, s->target_host, &a6) != 1) ||
        (s->server_name[0] && !cwc_host_valid(s->server_name)))
        return 0;
    if ((inet_pton(AF_INET, s->target_host, &a4) == 1 ||
         inet_pton(AF_INET6, s->target_host, &a6) == 1) &&
        !cwc_address_allowed(s->target_host, s->container))
        return 0;
    /* Management and infrastructure ports are never generic published targets. */
    switch (s->port) {
    case 22: case 53: case 12517: case 12518:
        return 0;
    default:
        return !s->container || s->port >= 1024;
    }
}

static const struct cwc_service *cwc_service(const struct cwc_config *c,
                                              const char *id)
{
    for (int i = 0; i < c->n_services; ++i)
        if (!strcmp(c->services[i].id, id))
            return &c->services[i];
    return NULL;
}

static int cwc_b64(const char *s, unsigned char *out, size_t len)
{
    unsigned char raw[96];
    unsigned char canonical[129];
    size_t n = s ? strlen(s) : 0;
    if (n != 4 * ((len + 2) / 3) || n >= sizeof(canonical))
        return -1;
    int got = EVP_DecodeBlock(raw, (const unsigned char *)s, (int)n);
    if (got < (int)len)
        return -1;
    EVP_EncodeBlock(canonical, raw, (int)len);
    if (strcmp((const char *)canonical, s))
        return -1;
    memcpy(out, raw, len);
    return 0;
}

int cwc_auth(const struct cwc_config *c, const char *payload, size_t len,
             char *out, size_t cap)
{
    struct cw_ctl_auth_challenge challenge;
    struct cw_ctl_auth_response response;
    unsigned char pub[32], sig[64], both[64], digest[32];
    char message[192], rid[40];
    size_t pub_len = sizeof(pub), sig_len = sizeof(sig);
    EVP_MD_CTX *ctx = NULL;
    int rc = -1;
    if (!c || !c->sign_key ||
        cw_ctl_auth_challenge_decode(payload, len, &challenge) != 0 ||
        EVP_PKEY_get_raw_public_key(c->sign_key, pub, &pub_len) != 1 || pub_len != 32)
        return -1;
    memcpy(both, c->kex_pub, 32);
    memcpy(both + 32, pub, 32);
    SHA256(both, sizeof(both), digest);
    memcpy(rid, "router-", 7);
    for (int i = 0; i < 16; ++i)
        snprintf(rid + 7 + 2 * i, 3, "%02x", digest[i]);
    if (strcmp(rid, c->router_id))
        return -1;
    int n = snprintf(message, sizeof(message), CWC_CONTEXT "\ntunnel-auth\n%s\n%s",
                     c->router_id, challenge.nonce);
    ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, c->sign_key) == 1 &&
        EVP_DigestSign(ctx, sig, &sig_len, (unsigned char *)message, (size_t)n) == 1 &&
        sig_len == 64) {
        EVP_EncodeBlock((unsigned char *)response.sign_pub, pub, 32);
        EVP_EncodeBlock((unsigned char *)response.kex_pub, c->kex_pub, 32);
        EVP_EncodeBlock((unsigned char *)response.signature, sig, 64);
        rc = (int)cw_ctl_auth_response_encode(&response, out, cap);
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

int cwc_manifest(const struct cwc_config *c, const char *payload, size_t len,
                 int64_t previous, struct cw_session *session, int64_t *revision)
{
    struct cw_ctl_services manifest;
    struct json_object *root = NULL, *array = NULL, *canonical = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char sig[64];
    char ids[CWC_MAX_SERVICES][64], *message = NULL;
    const char *pointers[CWC_MAX_SERVICES];
    int rc = -1;
    if (!c || !session || !revision ||
        cw_ctl_services_decode(payload, len, &manifest) != 0 ||
        manifest.revision < previous || manifest.n_services > CWC_MAX_SERVICES ||
        cwc_b64(manifest.sig, sig, 64))
        return -1;
    char *json = strndup(payload, len);
    if (!json)
        return -1;
    root = json_tokener_parse(json);
    free(json);
    canonical = json_object_new_array();
    if (!root || !canonical || !json_object_object_get_ex(root, "services", &array))
        goto done;
    for (int i = 0; i < manifest.n_services; ++i) {
        struct cw_web_service service;
        struct json_object *item = json_object_array_get_idx(array, (size_t)i);
        const char *text = json_object_to_json_string_ext(item, JSON_C_TO_STRING_PLAIN);
        if (cw_web_service_decode(text, strlen(text), &service) ||
            !cwc_service(c, service.service_id) ||
            (i && strcmp(ids[i - 1], service.service_id) >= 0))
            goto done;
        strcpy(ids[i], service.service_id);
        pointers[i] = ids[i];
        struct json_object *entry = json_object_new_object();
        json_object_object_add(entry, "service_id", json_object_new_string(ids[i]));
        json_object_array_add(canonical, entry);
    }
    const char *text = json_object_to_json_string_ext(canonical, JSON_C_TO_STRING_PLAIN);
    if (asprintf(&message, CWC_CONTEXT "\nservices-manifest\n%s\n%lld\n%s",
                 c->router_id, (long long)manifest.revision, text) < 0)
        goto done;
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, c->services_key, 32);
    ctx = EVP_MD_CTX_new();
    if (!key || !ctx || EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestVerify(ctx, sig, 64, (unsigned char *)message, strlen(message)) != 1)
        goto done;
    if (cw_session_set_services(session, pointers, manifest.n_services))
        goto done;
    *revision = manifest.revision;
    rc = 0;
done:
    free(message);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    json_object_put(canonical);
    json_object_put(root);
    return rc;
}

static int cwc_state(struct cwc_connection *c, int write_state)
{
    const char *path = c->config->state_path;
    char temporary[300], buf[96];
    unsigned generation;
    long long revision;
    if (!path[0])
        return -1;
    if (!write_state) {
        FILE *f = fopen(path, "r");
        if (!f)
            return errno == ENOENT ? 0 : -1;
        int n = fscanf(f, "%u %lld", &generation, &revision);
        fclose(f);
        if (n != 2 || !generation || revision < 0)
            return -1;
        c->generation = generation;
        c->revision = revision;
        return 0;
    }
    snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", path);
    int fd = mkstemp(temporary);
    if (fd < 0)
        return -1;
    int n = snprintf(buf, sizeof(buf), "%u %lld\n", c->generation, (long long)c->revision);
    int ok = fchmod(fd, 0600) == 0 && write(fd, buf, (size_t)n) == n &&
             fsync(fd) == 0;
    if (close(fd))
        ok = 0;
    if (!ok || rename(temporary, path)) {
        unlink(temporary);
        return -1;
    }
    return 0;
}

static int cwc_queue(struct cwc_connection *c, uint8_t op, uint16_t flags,
                      uint32_t id, const void *body, size_t size)
{
    if (size > CW_WIRE_FRAME_MAX || c->tx_len - c->tx_pos + size +
        CW_WIRE_HDR > CWC_TX_MAX)
        return -1;
    if (c->tx_pos) {
        memmove(c->tx, c->tx + c->tx_pos, c->tx_len - c->tx_pos);
        c->tx_len -= c->tx_pos;
        c->tx_pos = 0;
    }
    long n = cw_wire_encode(c->tx + c->tx_len, CWC_TX_MAX - c->tx_len,
                            op, flags, id, body, (uint32_t)size);
    if (n < 0)
        return -1;
    if (!c->tx_len)
        c->last_tx = cwc_now();
    c->tx_len += (size_t)n;
    return 0;
}

static int cwc_number(struct cwc_connection *c, uint8_t op, uint32_t id, uint32_t n)
{
    unsigned char body[] = {n >> 24, n >> 16, n >> 8, n};
    return cwc_queue(c, op, 0, id, body, 4);
}

static void cwc_free_request(struct cwc_request *r)
{
    struct cwc_connection *c = r->connection;
    if (r->attached)
        curl_multi_remove_handle(c->multi, r->easy);
    curl_easy_cleanup(r->easy);
    curl_slist_free_all(r->curl_headers);
    curl_slist_free_all(r->resolve);
    json_object_put(r->headers);
    json_object_put(r->response_headers);
    /* Return only bytes whose memory has actually been released. */
    if (r->body_len && c && !c->failed) {
        if (cw_session_on_window(&c->session, 0, CW_DIR_UP, (uint32_t)r->body_len) ||
            cwc_number(c, CW_OP_WINDOW, 0, (uint32_t)r->body_len))
            c->failed = 1;
    }
    free(r->body);
    free(r->raw);
    memset(r, 0, sizeof(*r));
}

static void cwc_reset(struct cwc_connection *c, uint32_t id, int error)
{
    if (cwc_number(c, CW_OP_RESET, id, (uint32_t)error))
        c->failed = 1;
    cw_session_on_reset(&c->session, id);
    for (int i = 0; i < CWC_STREAMS; ++i)
        if (c->requests[i].id == id)
            cwc_free_request(&c->requests[i]);
}

static int cwc_hop_header(const char *n)
{
    return !strcmp(n, "connection") || !strcmp(n, "transfer-encoding") ||
           !strcmp(n, "keep-alive") || !strcmp(n, "upgrade") || !strcmp(n, "te") ||
           !strcmp(n, "trailer") || !strncmp(n, "proxy-", 6);
}

static int cwc_upload_length(struct cwc_request *r)
{
    for (size_t i = 0; i < json_object_array_length(r->headers); ++i) {
        struct json_object *h = json_object_array_get_idx(r->headers, i);
        const char *name = json_object_get_string(json_object_array_get_idx(h, 0));
        if (!strcmp(name, "transfer-encoding")) {
            const char *value = json_object_get_string(json_object_array_get_idx(h, 1));
            if (r->upload_streaming || strcmp(value, "chunked")) return -1;
            r->upload_streaming = r->upload_unknown = 1;
            continue;
        }
        if (strcmp(name, "content-length"))
            continue;
        const char *value = json_object_get_string(json_object_array_get_idx(h, 1));
        if (r->upload_streaming || !*value)
            return -1;
        uint64_t n = 0;
        for (const char *p = value; *p; ++p) {
            if (*p < '0' || *p > '9' || n > CWC_STREAM_UPLOAD_MAX / 10)
                return -1;
            n = n * 10 + (unsigned)(*p - '0');
            if (n > CWC_STREAM_UPLOAD_MAX)
                return -1;
        }
        r->upload_streaming = 1;
        r->upload_expected = n;
    }
    return 0;
}

/* libcurl pulls from a bounded receive window, never from a whole upload. */
static size_t cwc_upload_read(char *out, size_t size, size_t count, void *user)
{
    struct cwc_request *r = user;
    struct cwc_connection *c = r->connection;
    if (!r->body_len) {
        if (r->upload_fin) return 0;
        r->upload_paused = 1;
        return CURL_READFUNC_PAUSE;
    }
    size_t n = size * count;
    if (n > r->body_len) n = r->body_len;
    memcpy(out, r->body, n);
    r->body_len -= n;
    memmove(r->body, r->body + n, r->body_len);
    const struct cw_stream *st = cw_session_find(&c->session, r->id);
    if (cw_session_on_window(&c->session, 0, CW_DIR_UP, (uint32_t)n) ||
        cwc_number(c, CW_OP_WINDOW, 0, (uint32_t)n) ||
        (st && !st->fin[CW_DIR_UP] &&
         (cw_session_on_window(&c->session, r->id, CW_DIR_UP, (uint32_t)n) ||
          cwc_number(c, CW_OP_WINDOW, r->id, (uint32_t)n)))) {
        c->failed = 1;
        return CURL_READFUNC_ABORT;
    }
    r->started = cwc_now();
    return n;
}

static int cwc_headers(struct cwc_request *r, const struct cwc_service *s)
{
    const char *origin = NULL;
    int origins = 0, hosts = 0;
    char line[CW_WEB_HDR_NAME_MAX + CW_WEB_HDR_VALUE_MAX + 4];
    for (size_t i = 0; i < json_object_array_length(r->headers); ++i) {
        struct json_object *h = json_object_array_get_idx(r->headers, i);
        const char *n = json_object_get_string(json_object_array_get_idx(h, 0));
        const char *v = json_object_get_string(json_object_array_get_idx(h, 1));
        if (!strcmp(n, "origin")) {
            origin = v;
            ++origins;
        }
        if (!strcmp(n, "host")) {
            ++hosts;
            if (strcmp(v, s->public_host))
                return -1;
        }
        if ((cwc_hop_header(n) && !(r->websocket &&
             (!strcmp(n, "connection") || !strcmp(n, "upgrade")))) ||
            !strcmp(n, "content-length") ||
            !strcmp(n, "expect") || !strcmp(n, "host") ||
            !strcmp(n, "forwarded") || !strncmp(n, "x-forwarded-", 12) ||
            !strcmp(n, "x-real-ip") || !strncmp(n, "x-dreaming", 10))
            continue;
        snprintf(line, sizeof(line), "%s: %s", n, v);
        struct curl_slist *next = curl_slist_append(r->curl_headers, line);
        if (!next)
            return -1;
        r->curl_headers = next;
    }
    snprintf(line, sizeof(line), "https://%s", s->public_host);
    if (hosts > 1 || origins > 1 || (origin && strcmp(origin, line)) ||
        (!origin && (r->websocket || (strcmp(r->head.method, "GET") &&
         strcmp(r->head.method, "HEAD") && strcmp(r->head.method, "OPTIONS")))))
        return -1;
    snprintf(line, sizeof(line), "Host: %s", s->public_host);
    struct curl_slist *next = curl_slist_append(r->curl_headers, line);
    if (!next)
        return -1;
    r->curl_headers = next;
    next = curl_slist_append(r->curl_headers, "Expect:");
    if (!next)
        return -1;
    r->curl_headers = next;
    return 0;
}

/* libcurl parses HTTP; this callback receives one already-framed header line. */
static size_t cwc_response_header(char *p, size_t size, size_t count, void *user)
{
    struct cwc_request *r = user;
    size_t n = size * count;
    char name[CW_WEB_HDR_NAME_MAX + 1], value[CW_WEB_HDR_VALUE_MAX + 1];
    if (r->response_sent)
        return n; /* trailers do not become a second response */
    r->response_header_bytes += n;
    if (r->response_header_bytes > CWC_HEAD_MAX)
        return 0;
    r->started = cwc_now();
    if (n >= 5 && !memcmp(p, "HTTP/", 5)) {
        json_object_put(r->response_headers);
        r->response_headers = json_object_new_array();
        return r->response_headers ? n : 0;
    }
    if (n == 2 && !memcmp(p, "\r\n", 2)) {
        long status = 0;
        curl_easy_getinfo(r->easy, CURLINFO_RESPONSE_CODE, &status);
        if (status < 200)
            return status == 101 ? 0 : n;
        char head[CWC_HEAD_MAX + 1];
        const char *headers = json_object_to_json_string_ext(
            r->response_headers, JSON_C_TO_STRING_PLAIN);
        long len = cw_web_resp_encode((int)status, headers, head, sizeof(head));
        if (len < 0 || cwc_queue(r->connection, CW_OP_RESP, CW_FLAG_END_HEAD,
                                r->id, head, (size_t)len) ||
            cw_session_on_resp(&r->connection->session, r->id))
            return 0;
        r->response_sent = 1;
        return n;
    }
    char *colon = memchr(p, ':', n);
    if (!colon)
        return 0;
    size_t nn = (size_t)(colon - p);
    if (!nn || nn >= sizeof(name))
        return 0;
    for (size_t i = 0; i < nn; ++i)
        name[i] = (char)tolower((unsigned char)p[i]);
    name[nn] = 0;
    const char *v = colon + 1, *end = p + n;
    while (v < end && (*v == ' ' || *v == '\t')) ++v;
    while (end > v && (end[-1] == '\r' || end[-1] == '\n')) --end;
    size_t vn = (size_t)(end - v);
    if (vn >= sizeof(value))
        return 0;
    if (cwc_hop_header(name))
        return n;
    memcpy(value, v, vn);
    value[vn] = 0;
    struct json_object *h = json_object_new_array();
    json_object_array_add(h, json_object_new_string(name));
    json_object_array_add(h, json_object_new_string(value));
    json_object_array_add(r->response_headers, h);
    return json_object_array_length(r->response_headers) <= CW_WEB_MAX_HEADERS ? n : 0;
}

static size_t cwc_response_body(char *p, size_t size, size_t count, void *user)
{
    struct cwc_request *r = user;
    struct cwc_connection *c = r->connection;
    size_t n = size * count;
    const struct cw_stream *st = cw_session_find(&c->session, r->id);
    if (!r->response_sent || !st || n > CW_WIRE_FRAME_MAX)
        return 0;
    if (n > st->win[CW_DIR_DOWN] || n > c->session.conn_win[CW_DIR_DOWN] ||
        c->tx_len - c->tx_pos + n + CW_WIRE_HDR > CWC_TX_MAX - CWC_HEAD_MAX) {
        r->paused = 1;
        r->paused_bytes = n;
        return CURL_WRITEFUNC_PAUSE;
    }
    if (cwc_queue(c, CW_OP_DATA, 0, r->id, p, n) ||
        cw_session_on_data(&c->session, r->id, CW_DIR_DOWN, (uint32_t)n, 0))
        return 0;
    r->started = cwc_now();
    return n;
}

static int cwc_resolve(struct cwc_request *r, const struct cwc_service *s,
                        const char *server_name)
{
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC};
    struct addrinfo *list = NULL;
    struct ifaddrs *interfaces = NULL;
    char chosen[INET6_ADDRSTRLEN] = "", text[INET6_ADDRSTRLEN], entry[600];
    if (getaddrinfo(s->target_host, NULL, &hints, &list))
        return -1;
    int rc = -1;
    if (getifaddrs(&interfaces))
        goto done;
    for (struct addrinfo *a = list; a; a = a->ai_next) {
        const void *addr;
        if (a->ai_family == AF_INET)
            addr = &((struct sockaddr_in *)a->ai_addr)->sin_addr;
        else if (a->ai_family == AF_INET6)
            addr = &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
        else
            goto done;
        if (!inet_ntop(a->ai_family, addr, text, sizeof(text)) ||
            !cwc_address_allowed(text, s->container))
            goto done;
        for (struct ifaddrs *i = interfaces; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != a->ai_family)
                continue;
            const void *local = a->ai_family == AF_INET ?
                (const void *)&((struct sockaddr_in *)i->ifa_addr)->sin_addr :
                (const void *)&((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr;
            if (!memcmp(local, addr, a->ai_family == AF_INET ? 4 : 16) &&
                !(s->container && (!strcmp(text, "127.0.0.1") || !strcmp(text, "::1"))))
                goto done;
        }
        if (!chosen[0])
            snprintf(chosen, sizeof(chosen), "%s", text);
    }
    if (!chosen[0])
        goto done;
    /* Lock the validated answer into curl: it must not resolve a second time. */
    snprintf(entry, sizeof(entry), "%s%s%s:%u:%s%s%s",
             strchr(server_name, ':') ? "[" : "", server_name,
             strchr(server_name, ':') ? "]" : "", s->port,
             strchr(chosen, ':') ? "[" : "", chosen, strchr(chosen, ':') ? "]" : "");
    r->resolve = curl_slist_append(NULL, entry);
    rc = r->resolve ? 0 : -1;
done:
    freeifaddrs(interfaces);
    freeaddrinfo(list);
    return rc;
}

struct json_object *cwc_service_probe(const struct cwc_service *s)
{
    struct json_object *result = json_object_new_object();
    struct cwc_request request = {0};
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char url[600], host[280];
    long status = 0;
    const char *error = "invalid_target";
    if (!cwc_service_valid(s) || s->management) goto done;
    const char *name = s->server_name[0] ? s->server_name : s->target_host;
    if (cwc_resolve(&request, s, name)) goto done;
    curl = curl_easy_init();
    if (!curl) { error = "service_unreachable"; goto done; }
    snprintf(url, sizeof(url), "%s://%s%s%s:%u/", s->https ? "https" : "http",
             strchr(name, ':') ? "[" : "", name, strchr(name, ':') ? "]" : "", s->port);
    snprintf(host, sizeof(host), "Host: %s", s->public_host);
    headers = curl_slist_append(NULL, host);
    if (!headers) { error = "service_unreachable"; goto done; }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_RESOLVE, request.resolve);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (s->ca_path[0]) curl_easy_setopt(curl, CURLOPT_CAINFO, s->ca_path);
    if (s->tls_pin[0] && curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, s->tls_pin)) goto done;
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 8000L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    error = rc == CURLE_OK && status >= 200 && status <= 599 ? "" :
        rc == CURLE_PEER_FAILED_VERIFICATION || rc == CURLE_SSL_CACERT_BADFILE ||
        rc == CURLE_SSL_PINNEDPUBKEYNOTMATCH ?
        "tls_validation_failed" : "service_unreachable";
done:
    json_object_object_add(result, "reachable", json_object_new_boolean(!error[0]));
    json_object_object_add(result, "http_status", status ? json_object_new_int64(status) : NULL);
    json_object_object_add(result, "error", error[0] ? json_object_new_string(error) : NULL);
    curl_slist_free_all(headers);
    curl_slist_free_all(request.resolve);
    curl_easy_cleanup(curl);
    return result;
}

static int cwc_upstream(struct cwc_request *r)
{
    const struct cwc_service *s = cwc_service(r->connection->config, r->head.service_id);
    char url[CW_WEB_PATH_MAX + 300];
    if (!s || cwc_headers(r, s))
        return CW_ERR_SERVICE;
    r->easy = curl_easy_init();
    if (!r->easy)
        return CW_ERR_INTERNAL;
    const char *name = s->server_name[0] ? s->server_name : s->target_host;
    const char *path = r->head.path;
    if (s->management && !strcmp(path, "/"))
        path = "/app/";
    if (s->management) {
        snprintf(url, sizeof(url), "http://%s%s", s->public_host, path);
        curl_easy_setopt(r->easy, CURLOPT_UNIX_SOCKET_PATH, CWC_SOCKET);
    } else {
        if (cwc_resolve(r, s, name))
            return CW_ERR_SERVICE;
        snprintf(url, sizeof(url), "%s://%s%s%s:%u%s", s->https ? "https" : "http",
                 strchr(name, ':') ? "[" : "", name, strchr(name, ':') ? "]" : "",
                 s->port, path);
        curl_easy_setopt(r->easy, CURLOPT_RESOLVE, r->resolve);
    }
    curl_easy_setopt(r->easy, CURLOPT_URL, url);
    curl_easy_setopt(r->easy, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(r->easy, CURLOPT_PROXY, "");
    curl_easy_setopt(r->easy, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(r->easy, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(r->easy, CURLOPT_PATH_AS_IS, 1L);
    curl_easy_setopt(r->easy, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(r->easy, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(r->easy, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (s->ca_path[0])
        curl_easy_setopt(r->easy, CURLOPT_CAINFO, s->ca_path);
    if (s->tls_pin[0] && curl_easy_setopt(r->easy, CURLOPT_PINNEDPUBLICKEY, s->tls_pin))
        return CW_ERR_SERVICE;
    curl_easy_setopt(r->easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(r->easy, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    /* The pump enforces idle progress, not a total response duration. */
    curl_easy_setopt(r->easy, CURLOPT_TIMEOUT_MS, 0L);
    if (!r->websocket) curl_easy_setopt(r->easy, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(r->easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(r->easy, CURLOPT_HTTPHEADER, r->curl_headers);
    curl_easy_setopt(r->easy, CURLOPT_CUSTOMREQUEST, r->head.method);
    if (r->websocket) {
        r->raw = calloc(1, sizeof(*r->raw));
        if (!r->raw) return CW_ERR_INTERNAL;
        r->raw->phase = 1;
        r->raw->fd = CURL_SOCKET_BAD;
        int n = snprintf(r->raw->buffer, sizeof(r->raw->buffer), "GET %s HTTP/1.1\r\n", path);
        if (n < 0 || (size_t)n >= sizeof(r->raw->buffer)) return CW_ERR_INTERNAL;
        r->raw->len = (size_t)n;
        for (struct curl_slist *h = r->curl_headers; h; h = h->next) {
            if (!strcmp(h->data, "Expect:")) continue;
            n = snprintf(r->raw->buffer + r->raw->len,
                sizeof(r->raw->buffer) - r->raw->len, "%s\r\n", h->data);
            if (n < 0 || (size_t)n >= sizeof(r->raw->buffer) - r->raw->len)
                return CW_ERR_FRAME_TOO_BIG;
            r->raw->len += (size_t)n;
        }
        if (r->raw->len + 2 > sizeof(r->raw->buffer)) return CW_ERR_FRAME_TOO_BIG;
        memcpy(r->raw->buffer + r->raw->len, "\r\n", 2);
        r->raw->len += 2;
        curl_easy_setopt(r->easy, CURLOPT_CONNECT_ONLY, 1L);
    } else if (!strcmp(r->head.method, "HEAD"))
        curl_easy_setopt(r->easy, CURLOPT_NOBODY, 1L);
    else if (r->upload_streaming && (r->upload_unknown || r->upload_expected ||
             (strcmp(r->head.method, "GET") && strcmp(r->head.method, "OPTIONS")))) {
        curl_easy_setopt(r->easy, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(r->easy, CURLOPT_INFILESIZE_LARGE,
                         r->upload_unknown ? (curl_off_t)-1 : (curl_off_t)r->upload_expected);
        curl_easy_setopt(r->easy, CURLOPT_READFUNCTION, cwc_upload_read);
        curl_easy_setopt(r->easy, CURLOPT_READDATA, r);
    } else if (!r->upload_streaming && (r->body_len || (strcmp(r->head.method, "GET") &&
                            strcmp(r->head.method, "OPTIONS")))) {
        curl_easy_setopt(r->easy, CURLOPT_POSTFIELDS, r->body ? (char *)r->body : "");
        curl_easy_setopt(r->easy, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)r->body_len);
    }
    curl_easy_setopt(r->easy, CURLOPT_HEADERFUNCTION, cwc_response_header);
    curl_easy_setopt(r->easy, CURLOPT_HEADERDATA, r);
    curl_easy_setopt(r->easy, CURLOPT_WRITEFUNCTION, cwc_response_body);
    curl_easy_setopt(r->easy, CURLOPT_WRITEDATA, r);
    curl_easy_setopt(r->easy, CURLOPT_PRIVATE, r);
    if (curl_multi_add_handle(r->connection->multi, r->easy) != CURLM_OK)
        return CW_ERR_INTERNAL;
    r->attached = 1;
    return 0;
}

static int cwc_frame(struct cwc_connection *c, const struct cw_frame *f)
{
    char payload[CW_WIRE_FRAME_MAX + 1];
    if (f->length)
        memcpy(payload, f->payload, f->length);
    payload[f->length] = 0;
    if (cw_wire_is_control(f->type) && f->flags)
        return -1;
    if (f->type == CW_OP_GOAWAY)
        return -1;
    if (c->stage == 0) {
        if (f->type != CW_OP_AUTH_CHALLENGE)
            return -1;
        char response[512];
        int n = cwc_auth(c->config, payload, f->length, response, sizeof(response));
        if (n < 0 || cwc_queue(c, CW_OP_AUTH_RESPONSE, 0, 0, response, (size_t)n))
            return -1;
        c->stage = 1;
        return 0;
    }
    if (c->stage == 1) {
        struct cw_ctl_welcome w;
        if (f->type != CW_OP_WELCOME ||
            cw_ctl_welcome_decode(payload, f->length, &w) ||
            w.generation < c->generation ||
            w.limits.stream_window > CWC_UPLOAD_MAX ||
            w.limits.conn_window > CW_WIRE_CONN_WINDOW)
            return -1;
        c->generation = w.generation;
        c->heartbeat = w.heartbeat;
        cw_session_init(&c->session, w.generation, w.limits.max_streams,
                         w.limits.stream_window, w.limits.conn_window);
        c->stage = 2;
        return 0;
    }
    if (f->type == CW_OP_SERVICES) {
        /* Replacing a manifest also cancels all work admitted under the old one. */
        for (int i = 0; i < CWC_STREAMS; ++i)
            if (c->requests[i].id)
                cwc_reset(c, c->requests[i].id, CW_ERR_REVOKED);
        if (cwc_manifest(c->config, payload, f->length, c->revision,
                          &c->session, &c->revision) || cwc_state(c, 1))
            return -1;
        c->stage = 3;
        cwc_status(c, c->session.n_services ? "connected" : "unpublished", "");
        return 0;
    }
    if (c->stage != 3)
        return -1;
    if (f->type == CW_OP_PING)
        return cwc_queue(c, CW_OP_PONG, 0, 0, f->payload, f->length);
    if (f->type == CW_OP_PONG)
        return 0;
    if (f->type == CW_OP_GENERATION) {
        struct cw_ctl_generation g;
        if (cw_ctl_generation_decode(payload, f->length, &g))
            return -1;
        if (g.generation > c->generation) {
            c->generation = g.generation;
            if (cwc_state(c, 1))
                return -1;
        }
        return -1; /* never carry old streams across revoke/supersede */
    }
    if (f->type == CW_OP_WINDOW) {
        if (f->flags)
            return -1;
        /* WINDOWs already in flight may arrive after our FIN/RESET. */
        if (f->stream_id && !cw_session_find(&c->session, f->stream_id))
            return f->stream_id <= c->last_id ? 0 : -1;
        return cw_session_on_window(&c->session, f->stream_id, CW_DIR_DOWN,
                                     cw_wire_read_u32(f->payload)) ? -1 : 0;
    }
    struct cwc_request *r = NULL;
    for (int i = 0; i < CWC_STREAMS; ++i)
        if (c->requests[i].id == f->stream_id)
            r = &c->requests[i];
    if (f->type == CW_OP_RESET) {
        if (f->flags)
            return -1;
        cw_session_on_reset(&c->session, f->stream_id);
        if (r)
            cwc_free_request(r);
        return 0;
    }
    if (f->type == CW_OP_OPEN) {
        struct cw_web_open head;
        if (f->flags != CW_FLAG_END_HEAD || f->stream_id <= c->last_id ||
            cw_web_open_decode(payload, f->length, &head))
            return -1;
        c->last_id = f->stream_id;
        if (!strncmp(head.path, "//", 2) ||
            !strncmp(head.path, "/.well-known/dreamingos-cloud/", 29)) {
            cwc_reset(c, f->stream_id, CW_ERR_SERVICE);
            return 0;
        }
        int err = cw_session_open(&c->session, f->stream_id, head.service_id);
        if (!err) {
            for (int i = 0; i < CWC_STREAMS; ++i)
                if (!c->requests[i].id) {
                    r = &c->requests[i];
                    break;
                }
            if (!r)
                err = CW_ERR_STREAM_LIMIT;
        }
        if (err) {
            cwc_reset(c, f->stream_id, err);
            return 0;
        }
        r->connection = c;
        r->id = f->stream_id;
        r->head = head;
        r->started = cwc_now();
        struct json_object *root = json_tokener_parse(payload), *headers = NULL;
        if (root && json_object_object_get_ex(root, "headers", &headers))
            r->headers = json_object_get(headers);
        json_object_put(root);
        if (!r->headers) {
            cwc_reset(c, r->id, CW_ERR_INTERNAL);
        } else if ((r->websocket = cw_ws_request(r->head.method, r->headers, r->ws_accept)) < 0) {
            cwc_reset(c, r->id, CW_ERR_PROTOCOL);
        } else if (cwc_upload_length(r)) {
            cwc_reset(c, r->id, CW_ERR_FRAME_TOO_BIG);
        } else if (r->upload_streaming || r->websocket) {
            err = cwc_upstream(r);
            if (err) cwc_reset(c, r->id, err);
        }
        return 0;
    }
    if (!r) {
        /* DATA sent before RESET can still be in flight. It occupies no local
         * buffer now, but the peer must recover the connection credit it spent. */
        if (f->type == CW_OP_DATA && f->stream_id <= c->last_id &&
            !(f->flags & ~CW_FLAG_FIN) && f->length <= c->session.conn_win[CW_DIR_UP])
            return f->length ? cwc_number(c, CW_OP_WINDOW, 0, f->length) : 0;
        cwc_reset(c, f->stream_id, CW_ERR_PROTOCOL);
        return 0;
    }
    int err;
    int fin = f->type == CW_OP_FIN || (f->flags & CW_FLAG_FIN);
    if ((f->type != CW_OP_DATA && f->type != CW_OP_FIN) ||
        (f->flags & ~CW_FLAG_FIN) || (f->type == CW_OP_FIN && f->flags))
        return -1;
    if (f->type == CW_OP_DATA) {
        err = cw_session_on_data(&c->session, r->id, CW_DIR_UP, f->length, fin);
        if (!err && ((r->websocket && (!r->response_sent || r->raw->phase != 3)) ||
            r->body_len + f->length > c->session.init_stream_window ||
            (r->websocket && r->upload_received + f->length > CWC_STREAM_UPLOAD_MAX) ||
            (r->upload_streaming && r->upload_received + f->length >
             (r->upload_unknown ? CWC_STREAM_UPLOAD_MAX : r->upload_expected)))) {
            if (cw_session_on_window(&c->session, 0, CW_DIR_UP, f->length) ||
                cwc_number(c, CW_OP_WINDOW, 0, f->length))
                return -1;
            err = CW_ERR_FRAME_TOO_BIG;
        }
        if (!err && f->length) {
            if (r->body_len + f->length > r->body_cap) {
                size_t capacity = r->body_cap ? r->body_cap : 16384;
                while (capacity < r->body_len + f->length) capacity *= 2;
                if (capacity > c->session.init_stream_window) capacity = c->session.init_stream_window;
                unsigned char *body = realloc(r->body, capacity);
                if (!body) return -1;
                r->body = body;
                r->body_cap = capacity;
            }
            memcpy(r->body + r->body_len, f->payload, f->length);
            r->body_len += f->length;
            r->upload_received += f->length;
            r->started = cwc_now();
        }
    } else {
        err = cw_session_on_fin(&c->session, r->id, CW_DIR_UP);
    }
    if (!err && fin) {
        r->upload_fin = 1;
        if (r->websocket) {
            /* EOF cancels a byte tunnel after pending writes have drained. */
        } else if (r->upload_streaming) {
            if (!r->upload_unknown && r->upload_received != r->upload_expected)
                err = CW_ERR_PROTOCOL;
        } else {
            err = cwc_upstream(r);
        }
    }
    if (err)
        cwc_reset(c, r->id, err);
    return 0;
}

static int cwc_flush(struct cwc_connection *c)
{
    while (c->tx_pos < c->tx_len) {
        size_t n = 0;
        CURLcode rc = curl_easy_send(c->transport, c->tx + c->tx_pos,
                                     c->tx_len - c->tx_pos, &n);
        if (rc == CURLE_AGAIN)
            return 0;
        if (rc != CURLE_OK || !n)
            return -1;
        c->tx_pos += n;
        c->last_tx = cwc_now();
    }
    c->tx_pos = c->tx_len = 0;
    return 0;
}

static int cwc_receive(struct cwc_connection *c)
{
    for (int budget = 0; budget < 64; ++budget) {
        size_t n = 0;
        CURLcode rc = curl_easy_recv(c->transport, c->rx + c->rx_len,
                                     sizeof(c->rx) - c->rx_len, &n);
        if (rc == CURLE_AGAIN)
            return 0;
        if (rc != CURLE_OK || !n)
            return -1;
        c->rx_len += n;
        for (;;) {
            struct cw_frame f;
            size_t used = 0;
            int error = 0;
            int parsed = cw_wire_decode(c->rx, c->rx_len, &f, &used, &error);
            if (parsed == CW_WIRE_NEED_MORE)
                break;
            if (parsed != CW_WIRE_OK || cwc_frame(c, &f))
                return -1;
            c->last_rx = cwc_now();
            c->rx_len -= used;
            memmove(c->rx, c->rx + used, c->rx_len);
        }
    }
    return 0;
}

static int cwc_connect(struct cwc_connection *c)
{
    char url[320], hello[256];
    struct cw_ctl_hello h = {.proto = CW_WIRE_VERSION, .generation = c->generation};
    snprintf(url, sizeof(url), "https://%s:%u", c->config->tunnel_host,
             c->config->tunnel_port);
    c->transport = curl_easy_init();
    if (!c->transport)
        return -1;
    curl_easy_setopt(c->transport, CURLOPT_URL, url);
    curl_easy_setopt(c->transport, CURLOPT_PROXY, "");
    curl_easy_setopt(c->transport, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(c->transport, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(c->transport, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c->transport, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(c->transport, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(c->transport, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(c->transport, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c->transport, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
    if (c->config->ca_path[0])
        curl_easy_setopt(c->transport, CURLOPT_CAINFO, c->config->ca_path);
    CURLcode rc = curl_easy_perform(c->transport);
    if (rc != CURLE_OK) {
        cwc_status(c, "backoff", curl_easy_strerror(rc));
        return -1;
    }
    if (curl_easy_getinfo(c->transport, CURLINFO_ACTIVESOCKET, &c->fd) != CURLE_OK)
        return -1;
    strcpy(h.relay_router_id, c->config->router_id);
    long n = cw_ctl_hello_encode(&h, hello, sizeof(hello));
    c->last_rx = c->last_ping = c->last_tx = cwc_now();
    return n < 0 ? -1 : cwc_queue(c, CW_OP_HELLO, 0, 0, hello, (size_t)n);
}

static void cwc_finish_request(struct cwc_request *r)
{
    struct cwc_connection *c = r->connection;
    if (cwc_queue(c, CW_OP_FIN, 0, r->id, NULL, 0) ||
        cw_session_on_fin(&c->session, r->id, CW_DIR_DOWN))
        c->failed = 1;
    if (cw_session_find(&c->session, r->id)) {
        if (cwc_number(c, CW_OP_RESET, r->id, CW_ERR_CANCEL)) c->failed = 1;
        cw_session_on_reset(&c->session, r->id);
    }
    cwc_free_request(r);
}

/* picohttpparser frames the HTTP handshake; libcurl owns TCP/TLS throughout. */
static int cwc_raw_head(struct cwc_request *r)
{
    struct cwc_raw *w = r->raw;
    struct phr_header headers[CW_WEB_MAX_HEADERS];
    size_t count = CW_WEB_MAX_HEADERS, message_len;
    const char *message;
    int version, status;
    int used = phr_parse_response(w->buffer, w->len, &version, &status,
                                  &message, &message_len, headers, &count, 0);
    if (used == -2) return w->len == sizeof(w->buffer) ? -1 : 0;
    if (used < 0 || status < 100 || status > 599 || (status == 101 && version != 1))
        return -1;
    r->response_header_bytes += (size_t)used;
    if (r->response_header_bytes > CWC_HEAD_MAX) return -1;
    json_object_put(r->response_headers);
    r->response_headers = json_object_new_array();
    for (size_t i = 0; i < count; ++i) {
        char name[CW_WEB_HDR_NAME_MAX + 1], value[CW_WEB_HDR_VALUE_MAX + 1];
        if (!headers[i].name || !headers[i].name_len ||
            headers[i].name_len >= sizeof(name) || headers[i].value_len >= sizeof(value))
            return -1;
        for (size_t j = 0; j < headers[i].name_len; ++j)
            name[j] = (char)tolower((unsigned char)headers[i].name[j]);
        name[headers[i].name_len] = 0;
        memcpy(value, headers[i].value, headers[i].value_len);
        value[headers[i].value_len] = 0;
        cw_ws_add(r->response_headers, name, value);
    }
    w->len -= (size_t)used;
    memmove(w->buffer, w->buffer + used, w->len);
    if (status < 200 && status != 101) return 0;
    if (status == 101) {
        if (cw_ws_response(r->response_headers, r->ws_accept)) return -1;
        w->phase = 3;
    } else {
        int nc, nt;
        const char *length = cw_ws_header(r->response_headers, "content-length", &nc);
        const char *transfer = cw_ws_header(r->response_headers, "transfer-encoding", &nt);
        if (nc > 1 || nt > 1 || (nc && nt) || (nt && strcasecmp(transfer, "chunked")))
            return -1;
        if (nc) {
            if (!*length) return -1;
            for (const char *p = length; *p; ++p) {
                if (*p < '0' || *p > '9' || w->remaining > CWC_STREAM_UPLOAD_MAX / 10)
                    return -1;
                w->remaining = w->remaining * 10 + (unsigned)(*p - '0');
                if (w->remaining > CWC_STREAM_UPLOAD_MAX) return -1;
            }
            w->sized = 1;
        }
        w->chunked = nt;
        w->decoder.consume_trailer = 1;
        w->phase = 4;
        w->eof = (nc && !w->remaining) || status == 204 || status == 304;
    }
    char head[CWC_HEAD_MAX + 1];
    const char *text = json_object_to_json_string_ext(r->response_headers, JSON_C_TO_STRING_PLAIN);
    long len = cw_web_resp_encode(status, text, head, sizeof(head));
    if (len < 0 || cwc_queue(r->connection, CW_OP_RESP, CW_FLAG_END_HEAD, r->id, head, (size_t)len) ||
        cw_session_on_resp(&r->connection->session, r->id)) return -1;
    r->response_sent = 1;
    return 0;
}

static int cwc_pump_raw(struct cwc_request *r)
{
    struct cwc_raw *w = r->raw;
    if (!w->connected) return 0;
    for (int budget = 0; budget < 32; ++budget) {
        size_t n = 0;
        CURLcode rc;
        if (w->phase == 1) {
            rc = curl_easy_send(r->easy, w->buffer + w->pos, w->len - w->pos, &n);
            if (rc == CURLE_AGAIN) return 0;
            if (rc || !n) return -1;
            w->pos += n;
            r->started = cwc_now();
            if (w->pos < w->len) continue;
            w->pos = w->len = 0;
            w->phase = 2;
        }
        if (w->phase == 2 && w->len) {
            size_t before = w->len;
            if (cwc_raw_head(r)) return -1;
            if (w->phase == 2 && w->len < before) continue;
        }
        if (w->phase >= 3) {
            if (w->phase == 3 && r->body_len) {
                size_t send_len = r->body_len < 16384 ? r->body_len : 16384;
                rc = curl_easy_send(r->easy, r->body, send_len, &n);
                if (rc != CURLE_AGAIN) {
                    if (rc || !n) return -1;
                    /* Reuse the upload accounting only after socket consumption. */
                    char consumed[16384];
                    if (n > sizeof(consumed) || cwc_upload_read(consumed, 1, n, r) != n)
                        return -1;
                }
            }
            if (w->len && !w->ready) {
                size_t raw = w->len;
                if (w->phase == 4 && w->chunked) {
                    ssize_t decoded = phr_decode_chunked(&w->decoder, w->buffer, &w->len);
                    if (decoded == -1 || decoded > 0) return -1;
                    if (!decoded) w->eof = 1;
                } else if (w->phase == 4 && w->sized) {
                    if (w->len > w->remaining) return -1;
                    w->remaining -= w->len;
                    if (!w->remaining) w->eof = 1;
                }
                if (w->received + w->len > CWC_STREAM_UPLOAD_MAX) return -1;
                w->received += w->len;
                w->ready = 1;
                if (raw) r->started = cwc_now();
            }
            if (w->len) {
                size_t result = cwc_response_body(w->buffer, 1, w->len, r);
                if (result == CURL_WRITEFUNC_PAUSE) {
                    r->paused = 0; /* raw sockets resume via WINDOW, not curl_easy_pause */
                    return 0;
                }
                if (result != w->len) return -1;
                w->len = 0;
            }
            w->ready = 0;
            if (w->eof || (r->upload_fin && !r->body_len)) {
                cwc_finish_request(r);
                return 0;
            }
        }
        size_t capacity = w->phase == 2 ? sizeof(w->buffer) - w->len : 16384;
        if (!capacity) return -1;
        rc = curl_easy_recv(r->easy, w->buffer + w->len, capacity, &n);
        if (rc == CURLE_AGAIN) return 0;
        if (rc) return -1;
        if (!n) {
            if (!r->response_sent || (w->phase == 4 &&
                ((w->sized && w->remaining) || (w->chunked && !w->eof)))) return -1;
            w->eof = 1;
        }
        w->len += n;
    }
    return 0;
}

static void cwc_pump_http(struct cwc_connection *c)
{
    int running = 0, left;
    for (int i = 0; i < CWC_STREAMS; ++i) {
        struct cwc_request *r = &c->requests[i];
        if (!r->id)
            continue;
        if (cwc_now() - r->started > 65000) {
            cwc_reset(c, r->id, CW_ERR_CANCEL);
            continue;
        }
        if (r->raw) {
            if (cwc_pump_raw(r)) cwc_reset(c, r->id, CW_ERR_UPSTREAM);
            continue;
        }
        int unpause = 0;
        if (r->paused) {
            const struct cw_stream *st = cw_session_find(&c->session, r->id);
            if (st && st->win[CW_DIR_DOWN] >= r->paused_bytes &&
                c->session.conn_win[CW_DIR_DOWN] >= r->paused_bytes &&
                c->tx_len - c->tx_pos < CWC_TX_MAX / 2) {
                r->paused = 0;
                unpause = 1;
            }
        }
        if (r->upload_paused && (r->body_len || r->upload_fin)) {
            r->upload_paused = 0;
            unpause = 1;
        }
        if (unpause && curl_easy_pause(r->easy,
            (r->paused ? CURLPAUSE_RECV : 0) | (r->upload_paused ? CURLPAUSE_SEND : 0)) != CURLE_OK)
            cwc_reset(c, r->id, CW_ERR_UPSTREAM);
    }
    if (curl_multi_perform(c->multi, &running) != CURLM_OK) {
        c->failed = 1;
        return;
    }
    CURLMsg *msg;
    while ((msg = curl_multi_info_read(c->multi, &left))) {
        if (msg->msg != CURLMSG_DONE)
            continue;
        struct cwc_request *r = NULL;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &r);
        if (!r)
            continue;
        if (r->raw && msg->data.result == CURLE_OK) {
            r->raw->connected = 1;
            if (curl_easy_getinfo(r->easy, CURLINFO_ACTIVESOCKET, &r->raw->fd) != CURLE_OK)
                cwc_reset(c, r->id, CW_ERR_UPSTREAM);
        } else if (msg->data.result != CURLE_OK || !r->response_sent) {
            cwc_reset(c, r->id, CW_ERR_UPSTREAM);
        } else {
            cwc_finish_request(r);
        }
    }
}

int cwc_run(const struct cwc_config *config, const struct cwc_hooks *hooks)
{
    if (!config || !hooks || !config->sign_key ||
        !cwc_host_valid(config->tunnel_host) || !config->tunnel_port ||
        config->n_services < 0 || config->n_services > CWC_MAX_SERVICES)
        return -1;
    for (int i = 0; i < config->n_services; ++i)
        if (!cwc_service_valid(&config->services[i]))
            return -1;
    struct cwc_connection *c = calloc(1, sizeof(*c));
    if (!c)
        return -1;
    c->config = config;
    c->hooks = hooks;
    c->generation = 1;
    c->tx = malloc(CWC_TX_MAX);
    if (!c->tx || cwc_state(c, 0)) {
        cwc_status(c, "error", "manifest_state_unavailable");
        free(c->tx);
        free(c);
        return -1;
    }
    unsigned attempt = 0;
    while (cwc_running(c)) {
        struct cwc_publication publication = {0};
        int64_t connected_at = cwc_now();
        c->multi = curl_multi_init();
        if (!c->multi)
            break;
        if (config->api_host[0]) {
            cwc_status(c, "publishing", "");
            if (hooks->publication) hooks->publication(hooks->user, NULL);
            if (cwc_publish(config, 1, &publication))
                goto reconnect;
            if (publication.generation < c->generation ||
                publication.revision < c->revision) {
                snprintf(publication.error, sizeof(publication.error), "publication_rollback");
                goto reconnect;
            }
            c->generation = publication.generation;
            if (hooks->publication) hooks->publication(hooks->user, &publication);
        }
        cwc_status(c, "connecting", "");
        if (!cwc_connect(c)) {
            while (cwc_running(c) && !c->failed) {
                if (cwc_flush(c) || cwc_receive(c))
                    break;
                cwc_pump_http(c);
                int64_t now = cwc_now();
                if (now - c->last_rx > (c->stage < 3 ? 10000 : 60000) ||
                    (c->tx_len && now - c->last_tx > 10000))
                    break;
                if (c->stage == 3 && now - c->last_ping >= c->heartbeat * 1000) {
                    if (cwc_queue(c, CW_OP_PING, 0, 0, NULL, 0))
                        break;
                    c->last_ping = now;
                }
                struct curl_waitfd extra[CWC_STREAMS + 1] = {{
                    .fd = c->fd, .events = CURL_WAIT_POLLIN |
                        (c->tx_len ? CURL_WAIT_POLLOUT : 0)
                }};
                unsigned nfds = 1;
                for (int i = 0; i < CWC_STREAMS; ++i) {
                    struct cwc_request *r = &c->requests[i];
                    const struct cw_stream *st = cw_session_find(&c->session, r->id);
                    if (!r->raw || !r->raw->connected || !st) continue;
                    short events = (r->raw->phase == 1 || r->body_len) ? CURL_WAIT_POLLOUT : 0;
                    if (!r->response_sent || (st->win[CW_DIR_DOWN] &&
                        c->session.conn_win[CW_DIR_DOWN] && c->tx_len < CWC_TX_MAX / 2))
                        events |= CURL_WAIT_POLLIN;
                    if (events) extra[nfds++] = (struct curl_waitfd){.fd = r->raw->fd, .events = events};
                }
                curl_multi_poll(c->multi, extra, nfds, 50, NULL);
            }
        }
        if (c->stage == 3 && cwc_now() - connected_at > 60000)
            attempt = 0;
reconnect:
        c->failed = 1;
        for (int i = 0; i < CWC_STREAMS; ++i)
            cwc_free_request(&c->requests[i]);
        curl_multi_cleanup(c->multi);
        c->multi = NULL;
        curl_easy_cleanup(c->transport);
        c->transport = NULL;
        c->failed = c->stage = 0;
        c->rx_len = c->tx_len = c->tx_pos = 0;
        c->last_id = 0;
        memset(&c->session, 0, sizeof(c->session));
        if (!cwc_running(c))
            break;
        cwc_status(c, "backoff", publication.error[0] ? publication.error : "tunnel_closed");
        uint32_t random = 0;
        RAND_bytes((unsigned char *)&random, sizeof(random));
        uint32_t delay = cw_wire_backoff_ms(attempt, random / 4294967296.0);
        if (publication.retry_after > 0 && delay < (uint32_t)publication.retry_after * 1000)
            delay = (uint32_t)publication.retry_after * 1000;
        if (attempt < 30) ++attempt;
        for (uint32_t slept = 0; slept < delay && cwc_running(c); slept += 100)
            usleep(100000);
    }
    cwc_status(c, "stopped", "");
    free(c->tx);
    free(c);
    return 0;
}
