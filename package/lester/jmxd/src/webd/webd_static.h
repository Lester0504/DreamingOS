// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_STATIC_H__
#define __DREAMINGWRT_WEBD_STATIC_H__

int webd_send_static(int fd, const char *path, const char *method, int accepts_gzip);
int webd_send_console_shell(int fd, const char *method);

#endif
