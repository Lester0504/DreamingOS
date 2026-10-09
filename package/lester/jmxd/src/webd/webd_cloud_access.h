// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_CLOUD_ACCESS_H
#define WEBD_CLOUD_ACCESS_H
#include <libubox/uloop.h>
#include "api/webd_http_req.h"

int webd_cloud_listener_start(void (*callback)(struct uloop_fd *, unsigned int));
void webd_cloud_listener_poll(void);
void webd_cloud_listener_close_child(void);
void webd_cloud_listener_stop(void);
int webd_cloud_peer(int fd, struct http_req *req);
int webd_cloud_guard(int fd, const char *raw, struct http_req *req);
#endif
