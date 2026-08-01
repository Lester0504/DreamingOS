// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Replays an unsealed inner request against the local webd.
 *
 * This is the point where attacker-influenced data becomes a request against a
 * trusted local service, so the rules are deliberately narrow:
 *
 *   - only /api/v1/ paths, and only a fixed method set,
 *   - the path is rebuilt from validated bytes; no header is copied through
 *     from the frame, so header injection has no surface,
 *   - the access token travels in Authorization: Bearer, which means webd's
 *     existing session, permission and CSRF logic applies unchanged. This
 *     daemon deliberately grants no authority of its own.
 *
 * The connection is plain HTTP to 127.0.0.1 because that is the same loopback
 * hop webd already serves to nginx; the App's end-to-end encryption terminates
 * here, inside the router.
 */
#include "cloud_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#define CLOUD_LOCAL_TIMEOUT_MS 15000
#define CLOUD_LOCAL_RESPONSE_MAX (256U * 1024U)

void cloud_local_response_free(struct cloud_local_response *response)
{
    if (!response)
        return;
    free(response->body);
    memset(response, 0, sizeof(*response));
}

int cloud_local_method_allowed(const char *method)
{
    static const char *const allowed[] = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
    };
    size_t i;

    if (!method || !method[0])
        return 0;
    for (i = 0; i < ARRAY_SIZE(allowed); i++)
        if (!strcmp(method, allowed[i]))
            return 1;
    return 0;
}

/*
 * Only the versioned API surface is reachable. Static files, the terminal
 * proxy and anything else webd serves stay local-only.
 *
 * Rejecting CR/LF and any byte outside a conservative set is what keeps the
 * request line from being split; the check is on raw bytes rather than after
 * any decoding, so a percent-encoded newline cannot slip past either.
 */
int cloud_local_path_allowed(const char *path)
{
    size_t length = path ? strlen(path) : 0;
    size_t i;

    if (length < 8 || length > 2048)
        return 0;
    if (strncmp(path, "/api/v1/", 8))
        return 0;
    if (strstr(path, ".."))
        return 0;

    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)path[i];

        if (c <= 0x20 || c >= 0x7f)
            return 0;
        /* Query strings are allowed; fragments and raw quoting are not. */
        switch (c) {
        case '"': case '\'': case '<': case '>': case '\\':
        case '{': case '}': case '|': case '^': case '`': case '#':
            return 0;
        default:
            break;
        }
    }
    return 1;
}

/*
 * The access token is placed in a header, so it must not be able to terminate
 * that header. webd's own tokens are hex, but the value arrives from the frame
 * and is validated rather than trusted.
 */
static int cloud_local_token_valid(const char *token)
{
    size_t length = token ? strlen(token) : 0;
    size_t i;

    if (!length)
        return 1;   /* absent token is legitimate for unauthenticated routes */
    if (length > 256)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)token[i];

        if (c <= 0x20 || c >= 0x7f)
            return 0;
    }
    return 1;
}

static int cloud_local_connect(void)
{
    struct sockaddr_in address;
    int fd;
    int flags;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    if ((flags = fcntl(fd, F_GETFD, 0)) >= 0)
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(CLOUD_LOCAL_PORT);
    if (inet_pton(AF_INET, CLOUD_LOCAL_HOST, &address.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int cloud_local_write_all(int fd, const unsigned char *data, size_t length,
                                 int64_t deadline)
{
    size_t sent = 0;

    while (sent < length) {
        struct pollfd descriptor = { .fd = fd, .events = POLLOUT };
        int64_t now = cloud_monotonic_ms();
        ssize_t written;
        int ready;

        if (now < 0 || now >= deadline)
            return -1;
        ready = poll(&descriptor, 1, (int)(deadline - now));
        if (ready <= 0) {
            if (ready < 0 && errno == EINTR)
                continue;
            return -1;
        }
        written = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -1;
        }
        if (!written)
            return -1;
        sent += (size_t)written;
    }
    return 0;
}

/* Reads until the peer closes or the cap is hit. webd sends
 * Connection: close for these requests, so EOF is the frame boundary. */
static int cloud_local_read_all(int fd, unsigned char **out, size_t *out_length,
                                int64_t deadline)
{
    size_t capacity = 8192, length = 0;
    unsigned char *buffer;

    buffer = malloc(capacity);
    if (!buffer)
        return -1;

    for (;;) {
        struct pollfd descriptor = { .fd = fd, .events = POLLIN };
        int64_t now = cloud_monotonic_ms();
        ssize_t got;
        int ready;

        if (now < 0 || now >= deadline)
            goto fail;
        ready = poll(&descriptor, 1, (int)(deadline - now));
        if (ready <= 0) {
            if (ready < 0 && errno == EINTR)
                continue;
            goto fail;
        }
        if (length + 4096 > capacity) {
            unsigned char *next;

            if (capacity >= CLOUD_LOCAL_RESPONSE_MAX)
                goto fail;
            capacity *= 2;
            next = realloc(buffer, capacity);
            if (!next)
                goto fail;
            buffer = next;
        }
        got = recv(fd, buffer + length, capacity - length, 0);
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            goto fail;
        }
        if (!got)
            break;
        length += (size_t)got;
    }
    *out = buffer;
    *out_length = length;
    return 0;
fail:
    free(buffer);
    return -1;
}

/*
 * Splits the HTTP response into status plus body. Only the status line is
 * interpreted; headers are dropped because the App consumes the JSON body and
 * the router's own headers carry nothing it needs.
 */
static int cloud_local_parse_response(const unsigned char *raw, size_t length,
                                      struct cloud_local_response *out)
{
    const unsigned char *separator;
    const char *text = (const char *)raw;
    size_t header_length, body_length;
    int status = 0;

    if (length < 12 || strncmp(text, "HTTP/1.", 7))
        return -1;
    if (sscanf(text, "HTTP/1.%*d %d", &status) != 1 ||
        status < 100 || status > 599)
        return -1;

    separator = (const unsigned char *)memmem(raw, length, "\r\n\r\n", 4);
    if (!separator)
        return -1;
    header_length = (size_t)(separator - raw) + 4;
    body_length = length - header_length;

    out->status = status;
    out->body_length = body_length;
    out->body = NULL;
    if (body_length) {
        out->body = malloc(body_length);
        if (!out->body)
            return -1;
        memcpy(out->body, raw + header_length, body_length);
    }
    return 0;
}

int cloud_local_execute(const struct cloud_inner_request *request,
                        struct cloud_local_response *out)
{
    unsigned char *raw = NULL;
    unsigned char *payload = NULL;
    size_t raw_length = 0, payload_length = 0, header_length;
    char header[4096];
    int64_t deadline;
    int fd = -1;
    int rc = -1;

    if (!request || !out)
        return -1;
    memset(out, 0, sizeof(*out));

    if (!cloud_local_method_allowed(request->method) ||
        !cloud_local_path_allowed(request->path) ||
        !cloud_local_token_valid(request->access_token))
        return -1;

    /*
     * X-Forwarded-For is set to the loopback address on purpose. webd derives
     * client identity for rate limiting and audit from the peer or this header,
     * and forwarding an App-supplied address would let a caller forge the
     * source recorded in the audit log.
     */
    header_length = (size_t)snprintf(header, sizeof(header),
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s/%s\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "X-DreamingOS-Access-Path: relay\r\n"
        "%s%s%s"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        request->method, request->path,
        CLOUD_LOCAL_HOST, CLOUD_LOCAL_PORT,
        CLOUD_SERVICE_NAME, CLOUD_CONTRACT_VERSION,
        request->access_token ? "Authorization: Bearer " : "",
        request->access_token ? request->access_token : "",
        request->access_token ? "\r\n" : "",
        request->body_length);
    if (header_length >= sizeof(header))
        return -1;

    deadline = cloud_monotonic_ms();
    if (deadline < 0)
        return -1;
    deadline += CLOUD_LOCAL_TIMEOUT_MS;

    fd = cloud_local_connect();
    if (fd < 0)
        return -1;

    payload_length = header_length + request->body_length;
    payload = malloc(payload_length);
    if (!payload)
        goto done;
    memcpy(payload, header, header_length);
    if (request->body_length)
        memcpy(payload + header_length, request->body, request->body_length);

    if (cloud_local_write_all(fd, payload, payload_length, deadline) != 0)
        goto done;
    if (cloud_local_read_all(fd, &raw, &raw_length, deadline) != 0)
        goto done;
    if (cloud_local_parse_response(raw, raw_length, out) != 0)
        goto done;
    rc = 0;
done:
    if (payload) {
        OPENSSL_cleanse(payload, payload_length);
        free(payload);
    }
    free(raw);
    if (fd >= 0)
        close(fd);
    OPENSSL_cleanse(header, sizeof(header));
    return rc;
}
