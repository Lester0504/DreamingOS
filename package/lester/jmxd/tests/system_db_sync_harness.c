// SPDX-License-Identifier: GPL-2.0-or-later
#include "system_db_sync.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct dwrt_system_db_status status;
    int apply = argc > 1 && !strcmp(argv[1], "sync");
    size_t i;
    int rc = apply ? dwrt_system_db_sync(&status) :
                     dwrt_system_db_inspect(&status);

    printf("rc=%d changed=%d errors=%d conflicts=%d\n", rc, status.changed,
           status.errors, status.conflicts);
    for (i = 0; i < status.count; i++)
        printf("%s action=%s changed=%d selection=%s source=%s target=%s error=%s\n",
               status.items[i].name, status.items[i].action,
               status.items[i].changed, status.items[i].source_selection,
               status.items[i].source_sha256,
               status.items[i].target_sha256, status.items[i].error);
    return rc == 0 ? 0 : 1;
}
