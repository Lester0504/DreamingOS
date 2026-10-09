/* SPDX-License-Identifier: GPL-2.0-or-later
 * Generic installed-App WebSocket transport. Included by api_appstore.c so it
 * shares the existing signed registry gate; no application business state. */
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "api_pair_internal.h"
#include "api_directory_internal.h"
#include "api_realtime_internal.h"

static int appstore_ws_origin_ok(const struct http_req *req)
{
    const char *host = NULL;
    if (!strncmp(req->origin, "https://", 8)) host = req->origin + 8;
    else if (!strncmp(req->origin, "http://", 7)) host = req->origin + 7;
    if (!host || !req->host[0] || strpbrk(host, "/?#@\\\r\n") || strcasecmp(host, req->host)) return 0;
    if (req->forwarded_proto[0] && ((req->origin[4] == 's') != !strcmp(req->forwarded_proto, "https"))) return 0;
    return strcmp(req->sec_fetch_site, "cross-site") != 0 && strcmp(req->sec_fetch_site, "same-site") != 0;
}
static int appstore_ws_valid(struct jmx_api_ctx *ctx, const char *id,
                              const char *socket_path, const struct stat *original)
{
    int token_state = 0, allowed = 0;
    char *principal = jmx_app_validate_token_mode(ctx->req->auth_token, &token_state, 0);
    char role[32]; struct stat current;
    if (!principal || strcmp(principal, ctx->device_id) || strncmp(principal, "web:", 4) ||
        !webd_user_get_role(principal + 4, role, sizeof(role)) || strcmp(role, ctx->authenticated_role) ||
        !jmx_perm_check(ctx->role, JMX_RISK_MEDIUM) || webd_group_permission_allows(principal, JMX_RISK_MEDIUM, NULL) != 1) goto done;
    if (lstat(socket_path, &current) || current.st_ino != original->st_ino || current.st_dev != original->st_dev ||
        !S_ISSOCK(current.st_mode) || current.st_uid || (current.st_mode & 0077)) goto done;
    struct json_object *reg = appstore_registry_load(id), *mf = NULL, *launch = NULL;
    char route[160]; snprintf(route, sizeof(route), "/api/v1/appstore/apps/%s/web/", id);
    if (reg) json_object_object_get_ex(reg, "manifest", &mf);
    if (mf) json_object_object_get_ex(mf, "launch", &launch);
    allowed = launch && !strcmp(app_nc_json_str(launch, "route", ""), route) && !strcmp(app_nc_json_str(launch, "kind", ""), "web");
    if (reg) json_object_put(reg);
done:
    free(principal); return allowed;
}
static int appstore_ws_write(int fd, const void *data, size_t length)
{
    const char *p = data;
    while (length) { ssize_t n = send(fd, p, length, MSG_NOSIGNAL); if (n < 0 && errno == EINTR) continue; if (n <= 0) return -1; p += n; length -= (size_t)n; }
    return 0;
}
static struct json_object *appstore_web_ws(struct jmx_api_ctx *ctx, const char *id,
                                           const char *suffix, const char *socket_path,
                                           const struct stat *original)
{
    int upstream = -1, result = 503; const char *reason = "app_service_unavailable";
    char request[2048], response[16384], accept[128];
    if (strcmp(ctx->req->method, "GET") || !ctx->req->auth_via_cookie || strncmp(ctx->device_id, "web:", 4) ||
        !ctx->device_id[4] || !appstore_ws_origin_ok(ctx->req) || ctx->req->query[0]) {
        ctx->status = 403; return webd_error("app_stream_forbidden", "same-origin user session required; query credentials are not accepted", "", "webd.appstore");
    }
    if (!jmx_perm_check(ctx->role, JMX_RISK_MEDIUM) || webd_group_permission_allows(ctx->device_id, JMX_RISK_MEDIUM, NULL) != 1) { ctx->status = 403; return webd_error("forbidden", "application control requires write permission", "", "webd.appstore"); }
    if (strlen(ctx->req->ws_key) != 24 || strspn(ctx->req->ws_key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != 24) { ctx->status=400; return webd_error("invalid_websocket_key", "invalid WebSocket key", "", "webd.appstore"); }
    if (webd_ws_accept_key(ctx->req->ws_key, accept, sizeof(accept)) != 0) { ctx->status = 400; return webd_error("invalid_websocket_key", "invalid WebSocket handshake", "", "webd.appstore"); }
    if (!appstore_ws_valid(ctx, id, socket_path, original)) { ctx->status = 401; return webd_error("unauthorized", "login or application is no longer available", "", "webd.appstore"); }
    upstream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); if (upstream < 0) goto failed;
    struct timeval timeout = {3, 0};
    setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); setsockopt(upstream, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un address = {.sun_family = AF_UNIX}; snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(upstream, (struct sockaddr *)&address, sizeof(address))) goto failed;
    int n = snprintf(request, sizeof(request), "GET /%s HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nX-DreamingOS-Actor: %s\r\nX-DreamingOS-Role: %s\r\n\r\n", suffix, ctx->req->ws_key, ctx->device_id, ctx->authenticated_role);
    if (n < 0 || n >= (int)sizeof(request) || appstore_ws_write(upstream, request, (size_t)n)) goto failed;
    size_t used = 0;
    while (used < sizeof(response)-1) { ssize_t got = recv(upstream, response+used, 1, 0); if (got <= 0) goto failed; used++; if (used >= 4 && !memcmp(response+used-4, "\r\n\r\n", 4)) break; }
    response[used] = 0; int code = 0;
    if (sscanf(response, "HTTP/1.1 %d", &code) != 1) goto failed;
    if (code != 101) { if (code >= 400 && code <= 599) result = code; reason = code == 409 ? "app_stream_conflict" : "app_stream_rejected"; goto failed; }
    char expected[192]; snprintf(expected, sizeof(expected), "\r\nSec-WebSocket-Accept: %s\r\n", accept);
    if (!strcasestr(response, expected) || !strcasestr(response, "\r\nUpgrade: websocket\r\n")) goto failed;
    n = snprintf(response, sizeof(response), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nCache-Control: no-store\r\n\r\n", accept);
    if (appstore_ws_write(ctx->fd, response, (size_t)n)) goto closed;
    struct { unsigned char data[65536]; size_t size, offset; int eof; } q[2] = {0};
    int fd[2] = {ctx->fd, upstream}; time_t checked = time(NULL);
    for (int i=0;i<2;i++) fcntl(fd[i], F_SETFL, fcntl(fd[i], F_GETFL) | O_NONBLOCK);
    for (;;) {
        /* Revalidation does not record activity: frames/pings cannot renew login. */
        if (time(NULL)-checked >= 2) { checked = time(NULL); if (!appstore_ws_valid(ctx, id, socket_path, original)) break; }
        struct pollfd p[2];
        for (int i=0;i<2;i++) p[i]=(struct pollfd){fd[i], (q[i].eof || q[i].size ? 0:POLLIN) | (q[1-i].size ? POLLOUT:0), 0};
        int ready = poll(p,2,500); if (ready < 0 && errno == EINTR) continue; if (ready < 0) break;
        for (int i=0;i<2;i++) {
            if (p[i].revents & (POLLERR|POLLNVAL)) goto closed;
            if (p[i].revents & POLLOUT) {
                ssize_t sent = send(fd[i], q[1-i].data+q[1-i].offset, q[1-i].size, MSG_NOSIGNAL);
                if (sent > 0) { q[1-i].offset+=(size_t)sent; q[1-i].size-=(size_t)sent; }
                else if (sent == 0 || (errno != EAGAIN && errno != EINTR)) goto closed;
            }
            if (!q[i].eof && !q[i].size && (p[i].revents & (POLLIN|POLLHUP))) {
                ssize_t got=recv(fd[i],q[i].data,sizeof(q[i].data),0);
                if (got > 0) { q[i].size=(size_t)got; q[i].offset=0; }
                else if (!got) q[i].eof=1;
                else if (errno != EAGAIN && errno != EINTR) goto closed;
            }
            if (q[i].eof && !q[i].size) shutdown(fd[1-i],SHUT_WR);
        }
        if ((q[0].eof || q[1].eof) && !q[0].size && !q[1].size) break;
    }
closed:
    if (upstream >= 0) close(upstream);
    ctx->status=101; return NULL;
failed:
    if (upstream >= 0) close(upstream);
    ctx->status=result; return webd_error(reason,"application control channel unavailable","","webd.appstore");
}
