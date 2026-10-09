#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "../src/routed/jmx_direction_snapshot.h"

int main(void)
{
    struct json_object *lan_data = json_object_new_object();
    struct json_object *lans = json_object_new_array();
    struct json_object *lan = json_object_new_object();
    struct json_object *wans = json_object_new_array();
    struct json_object *wan = json_object_new_object();
    struct jmx_direction_snapshot snapshot;
    struct jmx_direction_snapshot current;
    char error[128];
    uint64_t unready_generation;

    assert(lan_data && lans && lan && wans && wan);
    json_object_object_add(lan, "ifindex", json_object_new_int(1));
    json_object_object_add(lan, "ipaddr",
                           json_object_new_string("127.0.0.1"));
    json_object_object_add(lan, "prefix", json_object_new_int(8));
    json_object_array_add(lans, lan);
    json_object_object_add(lan_data, "lans", lans);

    json_object_object_add(wan, "id", json_object_new_int(7));
    json_object_object_add(wan, "ifindex", json_object_new_int(2));
    json_object_object_add(wan, "route_identity", json_object_new_int(0x10007));
    json_object_array_add(wans, wan);

    assert(jmx_direction_snapshot_build_json(lan_data, wans, 1, 42,
                                             &snapshot, error, sizeof(error)) == 0);
    assert(snapshot.ready && snapshot.generation == 42);
    assert(snapshot.lan_prefix_count >= 1);
    assert(snapshot.local_address_count >= 1);
    assert(snapshot.wan_count == 1 && snapshot.wans[0].wan_id == 7);
    assert(jmx_direction_snapshot_validate(&snapshot) == 0);

    assert(jmx_direction_snapshot_publish_unready(1) == 0);
    assert(jmx_direction_snapshot_read_current(&current) == 0);
    assert(!current.ready);
    unready_generation = current.generation;
    assert(jmx_direction_snapshot_refresh_json(lan_data, wans, 1) == 0);
    assert(jmx_direction_snapshot_read_current(&current) == 0);
    assert(current.ready && current.generation > unready_generation);

    json_object_put(lan_data);
    json_object_put(wans);
    puts("ok: jmx direction snapshot JSON fixture passed");
    return 0;
}
