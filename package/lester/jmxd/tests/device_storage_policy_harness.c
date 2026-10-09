// SPDX-License-Identifier: GPL-2.0-or-later
/* Unused discovery/mount code is discarded; this harness never mounts a disk. */
#include "../src/storage/storage_policy.c"

int main(int argc, char **argv)
{
    struct disks result = {0};
    int rc;
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "authorized") && argc == 3) {
        char target[PATH_MAX] = "";
        const char *reason = NULL;
        rc = authorized(argv[2], target, sizeof(target), &reason);
        printf("%d\n%s\n%s\n", rc, reason, target);
        return 0;
    }
    if (!strcmp(argv[1], "mountpoint") && argc == 3) {
        printf("%d\n", empty_mountpoint(argv[2]));
        return 0;
    }
    if (!strcmp(argv[1], "rank") && argc == 4) {
        printf("%d\n", priority_rank(argv[2], argv[3]));
        return 0;
    }
    if (!strcmp(argv[1], "system"))
        rc = system_disks(&result);
    else if (!strcmp(argv[1], "trace") && argc == 3)
        rc = physical_node(argv[2], &result, 0);
    else if (!strcmp(argv[1], "media") && argc == 3) {
        char reason[128] = "";
        disk_add(&result, argv[2]);
        printf("%s\n%s\n", media_class(&result, reason, sizeof(reason)), reason);
        return 0;
    } else
        return 2;
    printf("%d\n", rc);
    for (size_t i = 0; i < result.count; i++)
        puts(result.names[i]);
    return 0;
}
