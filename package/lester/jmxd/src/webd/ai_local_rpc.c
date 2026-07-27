// SPDX-License-Identifier: GPL-2.0-or-later
/* Root-only local bridge from jmctl to the webd-owned AI provider runtime. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <libubox/uloop.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../ai_local_rpc_protocol.h"
#include "ai_local_rpc.h"
#include "ai_runtime.h"

#define AI_LOCAL_ACCEPT_BUDGET 4
#define AI_LOCAL_IO_TIMEOUT_S 10

static struct uloop_fd g_ai_local_listener = { .fd = -1 };
static struct webd_ai_local_rpc_hooks g_ai_local_hooks;

static int ai_local_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ? -1 : 0;
}

static int ai_local_set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    return flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0 ? -1 : 0;
}

static void ai_local_set_timeout(int fd)
{
    struct timeval tv = { .tv_sec = AI_LOCAL_IO_TIMEOUT_S, .tv_usec = 0 };

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int ai_local_read_all(int fd, void *buffer, size_t length)
{
    unsigned char *out = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t got = recv(fd, out + offset, length - offset, 0);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        offset += (size_t)got;
    }
    return 0;
}

static int ai_local_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *input = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t sent = send(fd, input + offset, length - offset, MSG_NOSIGNAL);

        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (sent == 0)
            return -1;
        offset += (size_t)sent;
    }
    return 0;
}

static struct json_object *ai_local_error(int status, const char *code,
                                          const char *message)
{
    struct json_object *root = json_object_new_object();
    struct json_object *error = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "code", json_object_new_int(status));
    json_object_object_add(error, "code", json_object_new_string(code));
    json_object_object_add(error, "message", json_object_new_string(message));
    json_object_object_add(root, "error", error);
    return root;
}

static int ai_local_send_json(int fd, struct json_object *response)
{
    const char *json = json_object_to_json_string_ext(
        response, JSON_C_TO_STRING_PLAIN);
    size_t length = json ? strlen(json) : 0;
    uint32_t frame_length;

    if (!json || length == 0 || length > DREAMINGWRT_AI_LOCAL_RESPONSE_MAX)
        return -1;
    frame_length = htonl((uint32_t)length);
    return ai_local_write_all(fd, &frame_length, sizeof(frame_length)) == 0 &&
           ai_local_write_all(fd, json, length) == 0 ? 0 : -1;
}

static void ai_local_serve(int fd, const struct ucred *peer)
{
    uint32_t frame_length = 0;
    size_t length;
    char *payload = NULL;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    char actor[96];
    int http_status = 400;

    ai_local_set_timeout(fd);
    if (!peer || peer->uid != 0) {
        response = ai_local_error(403, "local_peer_denied",
                                  "jmctl AI access requires uid 0");
        goto done;
    }
    if (ai_local_read_all(fd, &frame_length, sizeof(frame_length)) != 0) {
        response = ai_local_error(400, "invalid_local_request",
                                  "local request header is incomplete");
        goto done;
    }
    length = (size_t)ntohl(frame_length);
    if (length == 0 || length > DREAMINGWRT_AI_LOCAL_REQUEST_MAX) {
        response = ai_local_error(413, "local_request_too_large",
                                  "local AI request exceeds the size limit");
        goto done;
    }
    payload = calloc(1, length + 1);
    if (!payload || ai_local_read_all(fd, payload, length) != 0) {
        response = ai_local_error(400, "invalid_local_request",
                                  "local request body is incomplete");
        goto done;
    }
    request = json_tokener_parse(payload);
    if (!request || !json_object_is_type(request, json_type_object)) {
        response = ai_local_error(400, "invalid_local_request",
                                  "local request body must be a JSON object");
        goto done;
    }
    json_object_object_del(request, "actor");
    json_object_object_del(request, "role");
    json_object_object_del(request, "provider");
    json_object_object_add(request, "source", json_object_new_string("jmctl"));
    snprintf(actor, sizeof(actor), "jmctl:uid=%lu:pid=%ld",
             (unsigned long)peer->uid, (long)peer->pid);
    response = webd_ai_runtime_chat(request, actor, &http_status);

done:
    if (!response)
        response = ai_local_error(500, "local_runtime_failed",
                                  "webd AI runtime returned no response");
    ai_local_send_json(fd, response);
    json_object_put(response);
    if (request)
        json_object_put(request);
    free(payload);
}

static void ai_local_accept_cb(struct uloop_fd *ufd, unsigned int events)
{
    int accepted = 0;

    (void)events;
    while (accepted++ < AI_LOCAL_ACCEPT_BUDGET) {
        struct ucred peer;
        socklen_t peer_len = sizeof(peer);
        int cfd = accept(ufd->fd, NULL, NULL);
        pid_t pid;

        if (cfd < 0) {
            if (errno == EINTR) {
                accepted--;
                continue;
            }
            return;
        }
        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
            peer_len != sizeof(peer)) {
            memset(&peer, 0xff, sizeof(peer));
        }
        ai_local_set_blocking(cfd);
        pid = fork();
        if (pid == 0) {
            if (g_ai_local_listener.fd >= 0 && g_ai_local_listener.fd != cfd)
                close(g_ai_local_listener.fd);
            if (g_ai_local_hooks.worker_prepare)
                g_ai_local_hooks.worker_prepare();
            ai_local_serve(cfd, &peer);
            close(cfd);
            _exit(0);
        }
        close(cfd);
        if (pid > 0 && g_ai_local_hooks.worker_track &&
            g_ai_local_hooks.worker_track(pid) != 0)
            kill(pid, SIGTERM);
    }
}

int webd_ai_local_rpc_init(const struct webd_ai_local_rpc_hooks *hooks)
{
    struct sockaddr_un address;
    int fd;

    memset(&g_ai_local_hooks, 0, sizeof(g_ai_local_hooks));
    if (hooks)
        g_ai_local_hooks = *hooks;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                 DREAMINGWRT_AI_LOCAL_SOCKET) >= (int)sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    unlink(DREAMINGWRT_AI_LOCAL_SOCKET);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(DREAMINGWRT_AI_LOCAL_SOCKET, 0600) != 0 ||
        ai_local_set_nonblock(fd) != 0 || listen(fd, 8) != 0) {
        close(fd);
        unlink(DREAMINGWRT_AI_LOCAL_SOCKET);
        return -1;
    }
    g_ai_local_listener.fd = fd;
    g_ai_local_listener.cb = ai_local_accept_cb;
    if (uloop_fd_add(&g_ai_local_listener, ULOOP_READ) != 0) {
        close(fd);
        g_ai_local_listener.fd = -1;
        unlink(DREAMINGWRT_AI_LOCAL_SOCKET);
        return -1;
    }
    return 0;
}

void webd_ai_local_rpc_done(void)
{
    if (g_ai_local_listener.fd >= 0) {
        uloop_fd_delete(&g_ai_local_listener);
        close(g_ai_local_listener.fd);
        g_ai_local_listener.fd = -1;
    }
    unlink(DREAMINGWRT_AI_LOCAL_SOCKET);
    memset(&g_ai_local_hooks, 0, sizeof(g_ai_local_hooks));
}
