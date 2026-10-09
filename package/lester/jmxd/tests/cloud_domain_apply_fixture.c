// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/webd/api/api_cloud_domain.h"
#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <uci.h>

struct reload_state { const char *mode; int calls; };
static int reload(void *opaque)
{
    struct reload_state *s = opaque;
    s->calls++;
    return !strcmp(s->mode, "fail-always") || (!strcmp(s->mode, "fail-once") && s->calls == 1) ? -1 : 0;
}

int main(int argc, char **argv)
{
    assert(argc == 9);
    struct uci_context *uci = uci_alloc_context();
    char delta[1024];
    snprintf(delta, sizeof(delta), "%s/delta", argv[8]);
    mkdir(delta, 0700);
    assert(uci && uci_set_confdir(uci, argv[1]) == UCI_OK && uci_set_savedir(uci, delta) == UCI_OK);
    char dhcp[1024], managed[1024], backups[1024];
    snprintf(dhcp, sizeof(dhcp), "%s/dhcp", argv[1]);
    snprintf(managed, sizeof(managed), "%s/managed.hosts", argv[8]);
    snprintf(backups, sizeof(backups), "%s/backups", argv[8]);
    struct webd_cloud_domain_paths paths = {dhcp, managed, backups};
    struct json_object *snapshot = webd_cloud_domain_snapshot(uci, argv[4], argv[2], argv[3]);
    struct json_object *plan = webd_cloud_domain_plan(snapshot, argv[5], &paths);
    struct json_object *output = json_object_new_object();
    json_object_object_add(output, "plan", plan);
    if (!strcmp(argv[6], "apply")) {
        struct reload_state s = {argv[7], 0};
        json_object_object_add(output, "result", webd_cloud_domain_apply(uci, plan, &paths, reload, &s));
        json_object_object_add(output, "reload_calls", json_object_new_int(s.calls));
    }
    puts(json_object_to_json_string_ext(output, JSON_C_TO_STRING_PLAIN));
    json_object_put(snapshot); json_object_put(output); uci_free_context(uci);
    return 0;
}
