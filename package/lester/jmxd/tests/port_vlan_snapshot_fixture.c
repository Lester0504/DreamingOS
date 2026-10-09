#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <json-c/json.h>
#include "safeops/port_revision.h"

static sqlite3 *g_app_db, *g_config_db;
static char network_path[] = "/tmp/f17-vlan-snapshot-XXXXXX";
#define WEBD_NETWORK_CONFIG_PATH network_path

struct uci_context { int unused; };
static struct uci_context uci;
static struct uci_context *uci_alloc_context(void) { return &uci; }
static void uci_free_context(struct uci_context *ctx) { assert(ctx == &uci); }
static const char *app_nc_json_str(struct json_object *o, const char *key, const char *fallback)
{
    struct json_object *v = json_object_object_get(o, key);
    return json_object_is_type(v, json_type_string) ? json_object_get_string(v) : fallback;
}
static struct json_object *webd_obj_child_obj(struct json_object *o, const char *key)
{
    struct json_object *v = json_object_object_get(o, key);
    return json_object_is_type(v, json_type_object) ? v : NULL;
}
static int webd_port_ifname_strict_ok(const char *name) { return !strcmp(name, "lan1"); }
static int webd_port_uci_section_strict_ok(const char *name) { return !strcmp(name, "br-lan"); }
static int webd_file_read_first_line(const char *path, char *out, size_t size)
{
    (void)path; (void)out; (void)size;
    return -1;
}
static const char *webd_bridge_cmd_path(void) { return "/sbin/bridge"; }
static struct json_object *webd_physical_port_find(const char *name)
{
    assert(!strcmp(name, "lan1"));
    return json_tokener_parse("{\"owner_type\":\"lan\",\"stp\":{\"bridge\":\"br-lan\"}}");
}
static const char *webd_port_vlan_read_config(struct uci_context *ctx, const char *ifname,
                                             const char *bridge, struct json_object *config)
{
    assert(ctx && !strcmp(ifname, "lan1") && !strcmp(bridge, "br-lan"));
    json_object_object_add(config, "native_vlan", json_object_new_int(1));
    json_object_object_add(config, "tagged_vlans", json_tokener_parse("[20,30]"));
    return "";
}
static int absent_sysfs(const char *path, int mode)
{
    (void)mode;
    assert(!strncmp(path, "/sys/class/net/", 15));
    return -1;
}
#define access absent_sysfs
#include "port_vlan_snapshot.inc"
#undef access

int main(void)
{
    char revision[72];
    int status = 0, app_changes, config_changes;
    int fd = mkstemp(network_path);
    struct json_object *result;
    assert(fd >= 0 && write(fd, "network", 7) == 7);
    close(fd);
    assert(sqlite3_open(":memory:", &g_app_db) == SQLITE_OK);
    assert(sqlite3_open(":memory:", &g_config_db) == SQLITE_OK);
    assert(sqlite3_exec(g_app_db,
        "CREATE TABLE config_apply_tasks(id INTEGER PRIMARY KEY,idempotency_key TEXT);",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_exec(g_config_db,
        "CREATE TABLE physical_port(name TEXT PRIMARY KEY,owner_type TEXT,owner_id TEXT);"
        "CREATE TABLE physical_port_config(ifname TEXT PRIMARY KEY,configured_speed_mbps INTEGER,"
        "configured_duplex TEXT,configured_autoneg INTEGER,profile_id TEXT,native_vlan INTEGER,"
        "tagged_vlans_json TEXT,poe_enabled INTEGER,poe_mode TEXT,display_name TEXT,sort_order INTEGER);"
        "CREATE TABLE physical_port_profile(id TEXT PRIMARY KEY,native_vlan INTEGER,tagged_vlans_json TEXT);"
        "INSERT INTO physical_port VALUES('lan1','lan','lan');",
        NULL, NULL, NULL) == SQLITE_OK);
    app_changes = sqlite3_total_changes(g_app_db);
    config_changes = sqlite3_total_changes(g_config_db);
    assert(safeops_port_revision(g_config_db, network_path, "lan1", revision) == 0);
    result = webd_port_vlan_snapshot("lan1", &status);
    assert(status == 200);
    assert(!strcmp(app_nc_json_str(result, "revision", ""), revision));
    assert(!strcmp(app_nc_json_str(result, "unavailable_reason", ""), "not_a_linux_bridge_port"));
    assert(!json_object_get_boolean(json_object_object_get(result, "write_supported")));
    assert(json_object_get_int(json_object_object_get(webd_obj_child_obj(result, "config"), "native_vlan")) == 1);
    assert(sqlite3_total_changes(g_app_db) == app_changes);
    assert(sqlite3_total_changes(g_config_db) == config_changes);
    json_object_put(result);
    sqlite3_close(g_app_db);
    sqlite3_close(g_config_db);
    unlink(network_path);
    puts("real VLAN snapshot reads config DB, not task DB; no database writes");
    return 0;
}
