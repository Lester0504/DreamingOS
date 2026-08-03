/* Fixture for route_status's kernel-nexthop resolution.
 *
 * route_proc_device_nexthop() is extracted from src/routed/jmx_route.c and given
 * a fixture-supplied /proc/net/route, so this runs shipped parsing code against
 * real kernel output captured from the live router. Acceptance found route_status,
 * route_config_get and `ip route` reporting three different gateways (A-013);
 * the byte-order and PPPoE-peer handling here is where that gets decided.
 *
 *   argv[1] = path to a file laid out like /proc/net/route
 *   argv[2] = device name to resolve
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Production reads the real procfs path; the fixture substitutes a captured
 * copy so the test does not depend on the host's routing table. */
static const char *g_route_path;
#define fopen(path, mode) fixture_fopen((path), (mode))

static FILE *fixture_fopen(const char *path, const char *mode)
{
    if (path && !strcmp(path, "/proc/net/route"))
        path = g_route_path;
    return (fopen)(path, mode);
}

#include "route_gateway_extracted.h"

#undef fopen

int main(int argc, char **argv)
{
    char out[64] = "";
    int via_peer = -1;
    int rc;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <route file> <device>\n", argv[0]);
        return 2;
    }
    g_route_path = argv[1];
    rc = route_proc_device_nexthop(argv[2], out, sizeof(out), &via_peer);
    printf("{\"rc\":%d,\"nexthop\":\"%s\",\"via_peer\":%s}\n",
           rc, out, via_peer ? "true" : "false");
    return 0;
}
