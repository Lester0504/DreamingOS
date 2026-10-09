#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>
#include "safeops/port_revision.h"

struct http_req { int unused; };
static sqlite3 *g_app_db;
static int supported = 1, writes, reads;
static struct json_object *last_request;
static const char *app_nc_json_str(struct json_object *o, const char *k, const char *fallback)
{
    struct json_object *v = json_object_object_get(o, k);
    return v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : fallback;
}
static int app_nc_json_int(struct json_object *o, const char *k, int fallback)
{
    struct json_object *v = json_object_object_get(o, k);
    return v ? json_object_get_int(v) : fallback;
}
static int app_nc_json_bool(struct json_object *o, const char *k, int fallback)
{
    struct json_object *v = json_object_object_get(o, k);
    return v ? json_object_get_boolean(v) : fallback;
}
static struct json_object *webd_obj_child_obj(struct json_object *o, const char *k)
{
    struct json_object *v = json_object_object_get(o, k);
    return json_object_is_type(v, json_type_object) ? v : NULL;
}
static struct json_object *webd_obj_child_array(struct json_object *o, const char *k)
{
    struct json_object *v = json_object_object_get(o, k);
    return json_object_is_type(v, json_type_array) ? v : NULL;
}
static struct json_object *webd_json_clone(struct json_object *o)
{
    return json_tokener_parse(json_object_to_json_string(o));
}
static struct json_object *webd_data_or_self_from_jmx_response(struct json_object *o)
{
    struct json_object *data = webd_obj_child_obj(o, "data");
    return json_object_get(data ? data : o);
}
static int webd_port_vlan_id_ok(int v, int allow_zero)
{
    return v >= (allow_zero ? 0 : 1) && v <= 4094;
}
static struct json_object *jmx_tasks_get(int id)
{
    struct json_object *task = json_tokener_parse("{\"ok\":true,\"state\":\"pending\",\"idempotency_key\":\"same\"}");
    json_object_object_add(task, "task_id", json_object_new_int(id));
    return task;
}
static struct json_object *webd_port_vlan_snapshot(const char *id, int *status)
{
    struct json_object *snapshot = json_tokener_parse(
        "{\"revision\":\"v1\",\"config\":{\"bridge\":\"br-lan\",\"native_vlan\":1,\"tagged_vlans\":[20,30]},"
        "\"unavailable_reason\":\"not_a_linux_bridge_port\"}");
    assert(!strcmp(id, "lan1"));
    reads++;
    *status = 200;
    json_object_object_add(snapshot, "write_supported", json_object_new_boolean(supported));
    return snapshot;
}
static struct json_object *webd_topology_port_plan_response(const struct http_req *req,
    struct json_object *body, int apply, const char *actor, int *status)
{
    (void)req; (void)actor;
    json_object_put(last_request);
    last_request = json_object_get(body);
    assert(!json_object_object_get(body, "confirm"));
    *status = apply ? 202 : 200;
    if (apply) {
        writes++;
        return json_tokener_parse("{\"ok\":true,\"data\":{\"ok\":true,\"transaction\":{\"task_id\":7}}}");
    }
    return json_tokener_parse("{\"ok\":true,\"data\":{\"plan\":{\"can_apply\":true}}}");
}

#include "port_vlan_adapter.inc"

static void sql(const char *text)
{
    assert(sqlite3_exec(g_app_db, text, NULL, NULL, NULL) == SQLITE_OK);
}
static struct json_object *call(const char *patch, const char *revision, int apply, int status)
{
    struct json_object *body = json_object_new_object(), *resp;
    int actual = 0;
    json_object_object_add(body, "id", json_object_new_string("lan1"));
    json_object_object_add(body, "if_revision", json_object_new_string(revision));
    json_object_object_add(body, "config", json_tokener_parse(patch));
    json_object_object_add(body, "idempotency_key", json_object_new_string("same"));
    json_object_object_add(body, "confirm_risk", json_object_new_boolean(1));
    resp = webd_port_vlan_request(NULL, body, apply, &actual);
    assert(actual == status);
    json_object_put(body);
    return resp;
}
int main(void)
{
    char path[] = "/tmp/f17-vlan-network-XXXXXX", a[72], b[72];
    int fd = mkstemp(path), count;
    struct json_object *resp;
    assert(fd >= 0 && write(fd, "network", 7) == 7);
    close(fd);
    assert(sqlite3_open(":memory:", &g_app_db) == SQLITE_OK);
    sql("CREATE TABLE physical_port(name TEXT,owner_type TEXT,owner_id TEXT,status TEXT);"
        "CREATE TABLE physical_port_config(ifname TEXT,configured_speed_mbps INTEGER,configured_duplex TEXT,"
        "configured_autoneg INTEGER,profile_id TEXT,native_vlan INTEGER,tagged_vlans_json TEXT,poe_enabled INTEGER,"
        "poe_mode TEXT,display_name TEXT,sort_order INTEGER);"
        "CREATE TABLE physical_port_profile(id TEXT,native_vlan INTEGER,tagged_vlans_json TEXT);"
        "CREATE TABLE config_apply_tasks(id INTEGER,idempotency_key TEXT);"
        "INSERT INTO physical_port VALUES('lan1','lan','lan','up');");
    assert(safeops_port_revision(g_app_db, path, "lan1", a) == 0);
    sql("UPDATE physical_port SET status='down'");
    assert(safeops_port_revision(g_app_db, path, "lan1", b) == 0 && !strcmp(a, b));
    sql("INSERT INTO physical_port_config(ifname,native_vlan,profile_id) VALUES('lan1',1,'p1')");
    assert(safeops_port_revision(g_app_db, path, "lan1", b) == 0 && strcmp(a, b));
    strcpy(a, b);
    sql("INSERT INTO physical_port_profile VALUES('p1',1,'[20]')");
    assert(safeops_port_revision(g_app_db, path, "lan1", b) == 0 && strcmp(a, b));
    strcpy(a, b);
    sql("UPDATE physical_port SET owner_id='lan2'");
    assert(safeops_port_revision(g_app_db, path, "lan1", b) == 0 && strcmp(a, b));
    strcpy(a, b);
    fd = open(path, O_WRONLY | O_APPEND);
    assert(fd >= 0 && write(fd, "changed", 7) == 7);
    close(fd);
    sql("BEGIN IMMEDIATE");
    assert(safeops_port_revision(g_app_db, path, "lan1", b) == 0 && strcmp(a, b));
    sql("ROLLBACK");
    unlink(path);
    assert(safeops_port_revision(g_app_db, path, "lan1", b) == -1 && !b[0]);

    json_object_put(call("{\"native_vlan\":2}", "", 0, 428));
    json_object_put(call("{\"native_vlan\":2}", "old", 0, 409));
    supported = 0;
    json_object_put(call("{\"native_vlan\":2}", "v1", 1, 409));
    assert(writes == 0);
    supported = 1;
    const char *invalid[] = {"{}", "{\"native_vlan\":0}", "{\"native_vlan\":4095}",
        "{\"native_vlan\":\"2\"}", "{\"native_vlan\":2.5}", "{\"tagged_vlans\":null}",
        "{\"tagged_vlans\":[20,20]}", "{\"tagged_vlans\":[1]}", "{\"tagged_vlans\":[\"20\"]}",
        "{\"enabled\":false}", "{\"native_vlan\":1}"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++)
        json_object_put(call(invalid[i], "v1", 0, 400));
    resp = call("{\"native_vlan\":2}", "v1", 0, 200);
    assert(app_nc_json_bool(resp, "valid", 0));
    assert(json_object_array_length(webd_obj_child_array(last_request, "tagged_vlans")) == 2);
    assert(!strcmp(app_nc_json_str(last_request, "expected_port_revision", ""), "v1"));
    json_object_put(resp);
    json_object_put(call("{\"tagged_vlans\":[]}", "v1", 1, 202));
    assert(writes == 1 && app_nc_json_int(last_request, "native_vlan", 0) == 1);
    assert(json_object_array_length(webd_obj_child_array(last_request, "tagged_vlans")) == 0);
    assert(!strcmp(app_nc_json_str(last_request, "idempotency_key", ""), "same"));
    sql("INSERT INTO config_apply_tasks VALUES(7,'same')");
    supported = 0;
    count = reads;
    resp = call("{\"native_vlan\":2}", "old", 1, 200);
    assert(app_nc_json_int(resp, "task_id", 0) == 7 && writes == 1 && reads == count);
    assert(app_nc_json_bool(resp, "idempotent_replay", 0));
    json_object_put(resp);
    json_object_put(last_request);
    sqlite3_close(g_app_db);
    puts("port VLAN revision and real adapter checks passed");
    return 0;
}
