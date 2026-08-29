// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Time, io and lock primitives shared by the other api/ modules.
 *
 * These eight are not json, not error mapping and not ubus, but each of those
 * three needs some of them: webd_meta() wants now_s() and webd_request_id(), the
 * shared-json cache wants webd_now_ms(), webd_write_all(),
 * webd_ws_file_mtime_ms() and webd_shared_lock_open(), and the ubus deadline
 * plumbing wants the two timespec helpers. Without this module they would either
 * be duplicated or left behind in jmx_app_api.c with the new modules calling back
 * into it.
 */
#ifndef WEBD_API_UTIL_H
#define WEBD_API_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <time.h>

void webd_timespec_add_ms(struct timespec *ts, int timeout_ms);
int webd_timespec_remaining_ms(const struct timespec *deadline);
int64_t now_s(void);
int64_t webd_now_ms(void);
int webd_write_all(int fd, const void *buf, size_t len);
int64_t webd_ws_file_mtime_ms(const struct stat *st);
void webd_request_id(char *buf, size_t len);
int webd_shared_lock_open(const char *lock_path);

#endif /* WEBD_API_UTIL_H */
