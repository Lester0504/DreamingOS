// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * The cross-process json cache webd shares with itself.
 *
 * Three functions: a bounded read that refuses anything older than max_age_ms, and
 * two writes that go through a temporary file plus rename so a reader never sees a
 * partial object. The locked variant exists for callers that already hold the
 * flock and would deadlock taking it again.
 */
#ifndef WEBD_API_SHARED_JSON_H
#define WEBD_API_SHARED_JSON_H

#include <stddef.h>
#include <json-c/json.h>

struct json_object *webd_shared_json_read(const char *path, int max_age_ms,
                                                 size_t max_bytes, int *age_ms);
int webd_shared_json_write(const char *path, const char *lock_path,
                                  size_t max_bytes, struct json_object *obj);
int webd_shared_json_write_locked(const char *path, size_t max_bytes,
                                         struct json_object *obj, int lock_fd);

#endif /* WEBD_API_SHARED_JSON_H */
