#include "jmx_netconfig_db.h"

#include <json-c/json.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    struct json_object *request;
    int rc;

    if (argc != 2)
        return 2;
    request = json_tokener_parse(argv[1]);
    if (!request)
        return 3;
    rc = jmx_firewall_service_validate(request);
    json_object_put(request);
    printf("%d\n", rc);
    return rc == 0 ? 0 : 1;
}
