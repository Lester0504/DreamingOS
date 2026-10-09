// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <json-c/json.h>

#include "api_shared_json.h"
#include "api_util.h"

/*
 * Persistent last-known-good snapshots are deliberately plain JSON files in
 * tmpfs. They are shared by the persistent workers, published with rename(),
 * and never treated as authoritative configuration. This closes the gap where
 * one worker dies or core is briefly busy while another worker has a valid
 * answer that the old per-process cache could not see.
 */
struct json_object *webd_shared_json_read(const char *path, int max_age_ms,
                                                 size_t max_bytes, int *age_ms)
{
    struct stat st;
    int64_t age;
    struct json_object *obj;

    if (age_ms)
        *age_ms = 0;
    if (!path || max_age_ms <= 0 || stat(path, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (size_t)st.st_size > max_bytes)
        return NULL;
    age = webd_now_ms() - webd_ws_file_mtime_ms(&st);
    if (age < 0 || age > max_age_ms)
        return NULL;
    obj = json_object_from_file(path);
    if (!obj || !json_object_is_type(obj, json_type_object)) {
        if (obj)
            json_object_put(obj);
        return NULL;
    }
    if (age_ms)
        *age_ms = (int)age;
    return obj;
}

int webd_shared_json_write(const char *path, const char *lock_path,
                                  size_t max_bytes, struct json_object *obj)
{
    int lock_fd = -1;
    int rc = -1;

    if (!path || !lock_path || !obj || !json_object_is_type(obj, json_type_object))
        return -1;
    lock_fd = webd_shared_lock_open(lock_path);
    if (lock_fd < 0)
        return -1;
    rc = webd_shared_json_write_locked(path, max_bytes, obj, lock_fd);
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return rc;
}

/* Publish while the caller already owns the per-snapshot flock. This avoids
 * reopening the same lock path from inside a single-flight refresh, which
 * would deadlock on systems where flock is associated with open descriptions.
 */
int webd_shared_json_write_locked(const char *path, size_t max_bytes,
                                         struct json_object *obj, int lock_fd)
{
    char tmp[256];
    const char *json;
    int fd = -1;

    if (!path || lock_fd < 0 || !obj || !json_object_is_type(obj, json_type_object))
        return -1;
    json = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    if (!json || strlen(json) > max_bytes ||
        snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
            (int)sizeof(tmp))
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0 && webd_write_all(fd, json, strlen(json)) == 0 &&
        close(fd) == 0 && rename(tmp, path) == 0)
        return 0;
    if (fd >= 0)
        close(fd);
    unlink(tmp);
    return -1;
}
