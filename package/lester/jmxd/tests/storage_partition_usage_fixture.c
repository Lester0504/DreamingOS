/* Drives the real blkdev_add_partition_usage() / blkdev_add_partition_extent()
 * extracted from src/storage/storage_blockdev.c against paths supplied on the
 * command line, so the numbers can be reconciled with df on a live system. */
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "usage_under_test.h"

int main(int argc, char **argv)
{
    struct json_object *out = json_object_new_array();
    int i;

    for (i = 1; i < argc; i++) {
        struct json_object *part = json_object_new_object();
        const char *arg = argv[i];
        const char *colon = strchr(arg, ':');
        char name[64] = "";
        const char *mount_point = arg;
        int mounted = 1;

        /* "name:mountpoint" tests both helpers; "name:" means unmounted. */
        if (colon) {
            size_t len = (size_t)(colon - arg);

            if (len >= sizeof(name))
                len = sizeof(name) - 1;
            memcpy(name, arg, len);
            name[len] = '\0';
            mount_point = colon + 1;
            if (!mount_point[0])
                mounted = 0;
        }
        json_object_object_add(part, "input", json_object_new_string(arg));
        blkdev_add_partition_extent(part, name);
        blkdev_add_partition_usage(part, mount_point, mounted);
        json_object_array_add(out, part);
    }
    printf("%s\n", json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
    json_object_put(out);
    return 0;
}
