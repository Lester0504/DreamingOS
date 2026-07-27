// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_init_control.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define WEBD_INIT_RESPONSE_MAX (64U * 1024U)

static void control_error(char *err, size_t err_len, const char *value)
{
    if (err && err_len)
        snprintf(err, err_len, "%s", value ? value : "init_control_failed");
}

static int action_allowed(const char *action)
{
    return action &&
        (!strcmp(action, "status") ||
         !strcmp(action, "arm") ||
         !strcmp(action, "confirm") ||
         !strcmp(action, "rollback"));
}

static int write_all(int fd, const char *data, size_t len)
{
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        written += (size_t)n;
    }
    return 0;
}

int webd_init_config_restore_request_at(const char *socket_path,
                                        const char *action,
                                        char **response,
                                        size_t *response_len,
                                        char *err,
                                        size_t err_len)
{
    struct sockaddr_un addr;
    struct timeval timeout = { .tv_sec = 8, .tv_usec = 0 };
    char command[96];
    char *buf = NULL;
    size_t used = 0;
    size_t capacity = 4096;
    int fd = -1;
    int rc = -1;

    if (response)
        *response = NULL;
    if (response_len)
        *response_len = 0;
    if (!response || !socket_path || !socket_path[0] ||
        strlen(socket_path) >= sizeof(addr.sun_path) || !action_allowed(action)) {
        control_error(err, err_len, "invalid_init_control_request");
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        control_error(err, err_len, "init_control_socket_failed");
        goto out;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        control_error(err, err_len, "init_control_unavailable");
        goto out;
    }
    snprintf(command, sizeof(command), "config-restore %s --json\n", action);
    if (write_all(fd, command, strlen(command)) != 0 || shutdown(fd, SHUT_WR) != 0) {
        control_error(err, err_len, "init_control_write_failed");
        goto out;
    }

    buf = malloc(capacity);
    if (!buf) {
        control_error(err, err_len, "init_control_allocation_failed");
        goto out;
    }
    for (;;) {
        ssize_t n;

        if (capacity - used < 2048) {
            size_t next = capacity * 2;
            char *grown;

            if (next > WEBD_INIT_RESPONSE_MAX + 1)
                next = WEBD_INIT_RESPONSE_MAX + 1;
            if (next <= capacity) {
                control_error(err, err_len, "init_control_response_too_large");
                goto out;
            }
            grown = realloc(buf, next);
            if (!grown) {
                control_error(err, err_len, "init_control_allocation_failed");
                goto out;
            }
            buf = grown;
            capacity = next;
        }
        n = read(fd, buf + used, capacity - used - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            control_error(err, err_len,
                          (errno == EAGAIN || errno == EWOULDBLOCK) ?
                          "init_control_timeout" : "init_control_read_failed");
            goto out;
        }
        if (n == 0)
            break;
        used += (size_t)n;
        if (used > WEBD_INIT_RESPONSE_MAX) {
            control_error(err, err_len, "init_control_response_too_large");
            goto out;
        }
    }
    if (!used) {
        control_error(err, err_len, "init_control_empty_response");
        goto out;
    }
    buf[used] = '\0';
    *response = buf;
    buf = NULL;
    if (response_len)
        *response_len = used;
    rc = 0;
out:
    free(buf);
    if (fd >= 0)
        close(fd);
    return rc;
}

int webd_init_config_restore_request(const char *action,
                                     char **response,
                                     size_t *response_len,
                                     char *err,
                                     size_t err_len)
{
    return webd_init_config_restore_request_at(WEBD_INIT_CONTROL_SOCKET, action,
                                               response, response_len, err, err_len);
}
