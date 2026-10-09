// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "webd_cloud_access.h"
#include "webd_http.h"
#include "webd_passkey.h"
#include "../cloud/cloud_web_client.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <uci.h>
#include <unistd.h>

static struct uloop_fd cloud_listener = {.fd = -1};
static int cloud_lock = -1;
static struct uloop_timeout cloud_watch;
static void (*cloud_callback)(struct uloop_fd *, unsigned int);

static int cloud_settings(char *host, size_t host_size, char *portal, size_t portal_size)
{
    struct uci_context *u = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_element *e;
    int enabled = 0;
    host[0] = portal[0] = 0;
    if (!u)
        return 0;
    if (!uci_load(u, "cloud_web", &p)) {
        uci_foreach_element(&p->sections, e) {
            struct uci_section *s = uci_to_section(e);
            const char *on = uci_lookup_option_string(u, s, "enabled");
            if (!strcmp(s->type, "browser")) {
                enabled = on && !strcmp(on, "1");
                const char *origin = uci_lookup_option_string(u, s, "portal_origin");
                if (origin && strlen(origin) < portal_size)
                    strcpy(portal, origin);
            } else if (!strcmp(s->type, "service") && !strcmp(s->e.name, "web") &&
                       on && !strcmp(on, "1")) {
                const char *value = uci_lookup_option_string(u, s, "public_host");
                if (value && strlen(value) < host_size)
                    strcpy(host, value);
            }
        }
    }
    uci_free_context(u);
    return enabled && host[0];
}

static int cloud_listener_open(void)
{
    char host[256], portal[300];
    if (!cloud_settings(host, sizeof(host), portal, sizeof(portal)))
        return 0;
    cloud_lock = open(CWC_SOCKET ".lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (cloud_lock < 0 || flock(cloud_lock, LOCK_EX | LOCK_NB))
        goto fail;
    struct stat st;
    if (!lstat(CWC_SOCKET, &st)) {
        if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid() || unlink(CWC_SOCKET))
            goto fail;
    } else if (errno != ENOENT) {
        goto fail;
    }
    cloud_listener.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (cloud_listener.fd < 0)
        goto fail;
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CWC_SOCKET);
    mode_t mask = umask(0077);
    int rc = bind(cloud_listener.fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(mask);
    if (rc || chmod(CWC_SOCKET, 0600) || listen(cloud_listener.fd, 32))
        goto fail;
    cloud_listener.cb = cloud_callback;
    if (uloop_fd_add(&cloud_listener, ULOOP_READ))
        goto fail;
    return 0;
fail:
    if (cloud_listener.fd >= 0) {
        close(cloud_listener.fd);
        cloud_listener.fd = -1;
        unlink(CWC_SOCKET);
    }
    if (cloud_lock >= 0) close(cloud_lock);
    cloud_lock = -1;
    return -1;
}

static void cloud_listener_close(void)
{
    if (cloud_listener.fd >= 0) {
        uloop_fd_delete(&cloud_listener);
        close(cloud_listener.fd);
        cloud_listener.fd = -1;
        unlink(CWC_SOCKET);
    }
    if (cloud_lock >= 0) close(cloud_lock);
    cloud_lock = -1;
}

static void cloud_listener_refresh(struct uloop_timeout *timer)
{
    char host[256], portal[300];
    int enabled = cloud_settings(host, sizeof(host), portal, sizeof(portal));
    if (enabled && cloud_listener.fd < 0) (void)cloud_listener_open();
    if (!enabled && cloud_listener.fd >= 0) cloud_listener_close();
    uloop_timeout_set(timer, 250);
}

int webd_cloud_listener_start(void (*callback)(struct uloop_fd *, unsigned int))
{
    cloud_callback = callback;
    cloud_watch.cb = cloud_listener_refresh;
    uloop_timeout_set(&cloud_watch, 250);
    return cloud_listener_open();
}

void webd_cloud_listener_poll(void)
{
    if (cloud_listener.fd >= 0)
        cloud_listener.cb(&cloud_listener, ULOOP_READ);
}

void webd_cloud_listener_close_child(void)
{
    uloop_timeout_cancel(&cloud_watch);
    if (cloud_listener.fd >= 0)
        close(cloud_listener.fd);
    if (cloud_lock >= 0)
        close(cloud_lock);
    cloud_listener.fd = cloud_lock = -1;
}

void webd_cloud_listener_stop(void)
{
    uloop_timeout_cancel(&cloud_watch);
    cloud_listener_close();
}

int webd_cloud_peer(int fd, struct http_req *req)
{
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(fd, (struct sockaddr *)&addr, &len) ||
        addr.sun_family != AF_UNIX || strcmp(addr.sun_path, CWC_SOCKET))
        return 0;
    /* Invalid as an IP on purpose: every existing local-subnet guard fails closed. */
    snprintf(req->client_ip, sizeof(req->client_ip), "%s", "remote_web");
    snprintf(req->peer_ip, sizeof(req->peer_ip), "%s", "remote_web");
    snprintf(req->ip_source, sizeof(req->ip_source), "%s", "remote_web");
    snprintf(req->forwarded_proto, sizeof(req->forwarded_proto), "%s", "https");
    return 1;
}

static int cloud_origin(const char *raw, char *out, size_t cap)
{
    const char *p = strstr(raw, "\r\n");
    int count = 0;
    out[0] = 0;
    while (p && p[2] && p[2] != '\r') {
        p += 2;
        const char *end = strstr(p, "\r\n");
        if (!end)
            return -1;
        if (!strncasecmp(p, "Origin:", 7)) {
            const char *v = p + 7;
            while (v < end && (*v == ' ' || *v == '\t')) ++v;
            if (++count != 1 || (size_t)(end - v) >= cap)
                return -1;
            memcpy(out, v, (size_t)(end - v));
            out[end - v] = 0;
        }
        p = end;
    }
    return count;
}

int webd_cloud_guard(int fd, const char *raw, struct http_req *req)
{
    int remote = !strcmp(req->ip_source, "remote_web");
    int launch = !strcmp(req->path, "/.well-known/dreamingos-cloud/launch");
    if (!remote && !launch)
        return 0;
    char host[256], portal[300], origin[300], expected[300], rp[256] = "";
    int enabled = cloud_settings(host, sizeof(host), portal, sizeof(portal));
    int origins = cloud_origin(raw, origin, sizeof(origin));
    (void)webd_passkey_rp_id(rp, sizeof(rp));
    if (!host[0] && rp[0])
        snprintf(host, sizeof(host), "%s", rp);
    snprintf(expected, sizeof(expected), "https://%s", host);
    int write_request = strcmp(req->method, "GET") && strcmp(req->method, "HEAD") &&
                        strcmp(req->method, "OPTIONS");
    if (!host[0] || strcmp(host, req->host) || origins < 0 ||
        (remote && (!enabled || (rp[0] && strcmp(host, rp)) || launch ||
                    (origins && strcmp(origin, expected)) ||
                    (write_request && origins != 1))))
        goto denied;
    if (remote) {
        /* First binding and credential recovery stay local even with a valid session. */
        if (write_request &&
            (!strncmp(req->path, "/api/v1/cloud/bind", 18) ||
             !strncmp(req->path, "/api/v1/cloud/local-domain", 26) ||
             !strncmp(req->path, "/api/v1/app/pair", 16) ||
             !strncmp(req->path, "/api/v1/setup", 13)))
            goto denied;
        return 0;
    }
    if (strcmp(req->method, "POST") || req->query[0] || !portal[0] ||
        origins != 1 || strcmp(origin, portal) || strcmp(req->forwarded_proto, "https") ||
        strncmp(req->content_type, "application/x-www-form-urlencoded", 33))
        goto denied;
    /* Discard the ticket. No account/administrator session is created on LAN. */
    static const char redirect[] =
        "HTTP/1.1 303 See Other\r\nLocation: /app/\r\nCache-Control: no-store\r\n"
        "Referrer-Policy: no-referrer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    size_t offset = 0;
    while (offset < sizeof(redirect) - 1) {
        ssize_t sent = write(fd, redirect + offset, sizeof(redirect) - 1 - offset);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            break;
        offset += (size_t)sent;
    }
    return 1;
denied:
    {
        static const char body[] = "{\"ok\":false,\"error\":\"remote_web_forbidden\"}";
        http_send(fd, 403, "Forbidden", "application/json", body, sizeof(body) - 1);
    }
    return 1;
}
