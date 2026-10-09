// SPDX-License-Identifier: GPL-2.0-or-later
/* Atomic bootstrap file writer.  See apd_bootstrap_write.h. */
#include "apd_bootstrap_write.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <json-c/json.h>

int apd_bootstrap_write_bytes(const void *data, size_t length,
                              const char *path)
{
    size_t path_len;
    char temporary[512];
    int fd;
    size_t offset = 0;

    if ((!data && length) || !path || !path[0])
        return -1;
    /* Ensure the parent directory exists. */
    {
        char dir_buf[512];
        snprintf(dir_buf, sizeof(dir_buf), "%s", path);
        if (mkdir(dirname(dir_buf), 0700) != 0 && errno != EEXIST)
            return -1;
    }
    path_len = strlen(path);
    if (path_len + 4 >= sizeof(temporary))
        return -1;
    memcpy(temporary, path, path_len);
    memcpy(temporary + path_len, ".tmp", 5);

    fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
              0600);
    if (fd < 0)
        return -1;
    while (offset < length) {
        ssize_t written = write(fd, (const unsigned char *)data + offset,
                                length - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            close(fd);
            unlink(temporary);
            return -1;
        }
        offset += (size_t)written;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(temporary);
        return -1;
    }
    close(fd);
    if (rename(temporary, path) != 0) {
        unlink(temporary);
        return -1;
    }
    return 0;
}

int apd_bootstrap_write_json(struct json_object *root, const char *path)
{
    const char *text;

    if (!root)
        return -1;
    text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    return apd_bootstrap_write_bytes(text, strlen(text), path);
}
