#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jmx_network.h"
#include "jmx_utils.h"

static int command_proc(int argc, char **argv)
{
    if (argc != 4)
        return 2;
    return jmx_update_proc_value(argv[2], argv[3]) == 0 ? 0 : 1;
}

static int command_capture(int argc, char **argv)
{
    char *output;

    if (argc != 3)
        return 2;
    output = get_interface_status_buf(argv[2]);
    if (!output)
        return 1;
    fputs(output, stdout);
    free(output);
    return 0;
}

static int command_parse(int argc, char **argv)
{
    iface_status_t status;

    if (argc != 3)
        return 2;
    memset(&status, 0x5a, sizeof(status));
    if (jmx_iface_status_parse_json(argv[2], &status) != 0) {
        const unsigned char *bytes = (const unsigned char *)&status;
        size_t i;

        for (i = 0; i < sizeof(status); i++) {
            if (bytes[i] != 0x5a)
                return 3;
        }
        return 1;
    }
    printf("%s|%s|%s|%s|%s|%s\n", status.ip, status.mask,
           status.gateway, status.dns1, status.dns2, status.ipv6);
    return 0;
}

static int command_ifname(int argc, char **argv)
{
    int require_existing;

    if (argc != 4)
        return 2;
    require_existing = atoi(argv[3]);
    return jmx_interface_name_valid(argv[2], require_existing) ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    if (strcmp(argv[1], "proc") == 0)
        return command_proc(argc, argv);
    if (strcmp(argv[1], "capture") == 0)
        return command_capture(argc, argv);
    if (strcmp(argv[1], "parse") == 0)
        return command_parse(argc, argv);
    if (strcmp(argv[1], "ifname") == 0)
        return command_ifname(argc, argv);
    return 2;
}
