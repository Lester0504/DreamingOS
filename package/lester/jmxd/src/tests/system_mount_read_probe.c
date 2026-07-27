#define JMX_SYSTEM_MOUNT_CONTRACT_ONLY 1

#include "jmx_system.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    struct jmx_system_mount_runtime_entry runtime[JMX_SYSTEM_MOUNT_READ_MAX];
    struct jmx_system_mount_config_entry configured[JMX_SYSTEM_MOUNT_READ_MAX];
    size_t runtime_count = 0, configured_count = 0, i;
    char error[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    int rc;

    rc = jmx_system_mount_read(NULL, runtime, JMX_SYSTEM_MOUNT_READ_MAX,
                               &runtime_count, configured,
                               JMX_SYSTEM_MOUNT_READ_MAX, &configured_count,
                               error, sizeof(error));
    printf("rc=%d runtime=%zu configured=%zu error=%s\n",
           rc, runtime_count, configured_count, error);
    if (rc != 0)
        return 1;
    for (i = 0; i < runtime_count; i++)
        printf("R\t%s\t%s\t%s\t%s\t%s\t%llu\t%llu\t%llu\t%d\t%d\t%d\n",
               runtime[i].device, runtime[i].source, runtime[i].target,
               runtime[i].fstype, runtime[i].root,
               runtime[i].size_bytes, runtime[i].used_bytes,
               runtime[i].available_bytes, runtime[i].used_percent,
               runtime[i].bind_mount, runtime[i].configured);
    for (i = 0; i < configured_count; i++)
        printf("C\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
               configured[i].section, configured[i].source,
               configured[i].target, configured[i].fstype,
               configured[i].options, configured[i].enabled,
               configured[i].check_fs, configured[i].mounted,
               configured[i].editable);
    return 0;
}
