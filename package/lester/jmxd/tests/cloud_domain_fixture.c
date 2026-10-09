// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/webd/api/api_cloud_domain.h"
#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <uci.h>

int main(int argc, char **argv)
{
    struct uci_context *uci = uci_alloc_context();
    struct json_object *snapshot;

    assert(argc == 5 && uci);
    assert(uci_set_confdir(uci, argv[1]) == UCI_OK);
    assert(uci_set_savedir(uci, argv[1]) == UCI_OK);
    snapshot = webd_cloud_domain_snapshot(uci, argv[4], argv[2], argv[3]);
    assert(snapshot);
    puts(json_object_to_json_string_ext(snapshot, JSON_C_TO_STRING_PLAIN));
    json_object_put(snapshot);
    uci_free_context(uci);
    return 0;
}
