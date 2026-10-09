/* Real IPTV input resolver with synthetic netifd status; no network changes. */
#define _GNU_SOURCE
#define IPTV_TESTING
static char fixture_path[4096], igmp_root[4096];
#define IPTV_IGMP_SYSCTL_ROOT igmp_root
#define IPTV_NETIFD_FIXTURE fixture_path
#include "../src/iptv/iptv_inputs.c"
#include <assert.h>
#include <sys/stat.h>

const char *iptv_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v ? json_object_get_string(v) : "";
}
int iptv_integer(struct json_object *o, const char *key, int fallback)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v ? json_object_get_int(v) : fallback;
}
struct json_object *iptv_fail(struct iptv_error *e, int status, const char *code, const char *field)
{
    e->status = status;
    snprintf(e->code, sizeof(e->code), "%s", code);
    snprintf(e->field, sizeof(e->field), "%s", field);
    return NULL;
}
int iptv_access_resolve(sqlite3 *db, struct json_object *c, char *out, size_t size, struct iptv_error *e)
{
    (void)db; (void)e;
    return snprintf(out, size, "%s", iptv_string(c, "source_url")) >= (int)size ? -1 : 0;
}
static void sql(sqlite3 *db, const char *query)
{
    assert(sqlite3_exec(db, query, NULL, NULL, NULL) == SQLITE_OK);
}
static void status_write(const char *device, int up, const char *address, int default_gateway)
{
    FILE *f = fopen(fixture_path, "w");
    assert(f);
    fprintf(f, "{\"interface\":[{\"interface\":\"iptv-fixture\",\"l3_device\":\"%s\","
        "\"up\":%s,\"ipv4-address\":[{\"address\":\"%s\",\"mask\":8}],\"route\":[%s]}]}",
        device, up ? "true" : "false", address,
        default_gateway ? "{\"target\":\"0.0.0.0\",\"mask\":0,\"nexthop\":\"127.0.0.2\"}" : "");
    assert(!fclose(f));
}
static struct json_object *input(sqlite3 *db)
{
    struct iptv_error e = {0};
    struct json_object *list = iptv_inputs(db, &e);
    assert(list && !e.status);
    struct json_object *row = json_object_get(json_object_array_get_idx(json_object_object_get(list, "items"), 0));
    assert(json_object_object_get(list, "network_mutation_supported") == NULL);
    assert(!strcmp(iptv_string(list, "network_mutation_authority"), "config.snapshot:iptv"));
    json_object_put(list);
    return row;
}
static int checks;
static void expect(sqlite3 *db, const char *reason)
{
    struct json_object *row = input(db);
    assert(!strcmp(iptv_string(row, "reason"), reason));
    assert(iptv_integer(row, "available", 0) == !*reason);
    json_object_put(row);
    checks++;
}
int main(int argc, char **argv)
{
    assert(argc == 2 && !strncmp(argv[1], "/tmp/", 5));
    snprintf(fixture_path, sizeof(fixture_path), "%s/netifd.json", argv[1]);
    sqlite3 *db = NULL;
    assert(sqlite3_open(":memory:", &db) == SQLITE_OK);
    sql(db, "CREATE TABLE wan(id TEXT,name TEXT,device TEXT,access_mode TEXT,enabled INT,vlan_id TEXT,role TEXT DEFAULT 'iptv');"
        "CREATE TABLE wan_advanced(wan_id TEXT,default_route INT,dhcp_vendor_class TEXT,iptv_igmp_version INTEGER DEFAULT 0,iptv_multicast_source TEXT DEFAULT 'session',iptv_carrier_mode TEXT DEFAULT 'dhcp',iptv_carrier_address TEXT DEFAULT '',iptv_carrier_prefix INTEGER DEFAULT 24);"
        "INSERT INTO wan(id,name,device,access_mode,enabled,vlan_id) VALUES('iptv-fixture','fixture','carrier-not-local','dhcp',1,'88');"
        "INSERT INTO wan_advanced(wan_id,default_route,dhcp_vendor_class) VALUES('iptv-fixture',0,'fixture-option60');");
    status_write("lo", 1, "127.0.0.1", 0);
    expect(db, "");
    struct json_object *row = input(db), *groups = NULL;
    assert(!strcmp(iptv_string(row, "runtime_device"), "lo"));
    assert(!strcmp(iptv_string(row, "device"), "carrier-not-local"));
    assert(!strcmp(iptv_string(row, "local_address"), "127.0.0.1"));
    assert(!strcmp(iptv_string(row, "option60"), "fixture-option60"));
    assert(json_object_object_get_ex(row, "interface_groups", &groups) && json_object_is_type(groups, json_type_array));
    assert(json_object_object_get_ex(row, "media_received", &groups) && !groups);
    json_object_put(row); checks++;
    sql(db, "UPDATE wan SET access_mode='pppoe'");
    expect(db, "");
    sql(db,"UPDATE wan_advanced SET iptv_multicast_source='carrier'");
    expect(db,"network_runtime_unavailable");
    /* A live PPP session is not the selected multicast carrier. */
    FILE *carrier_file=fopen(fixture_path,"w");assert(carrier_file);
    fputs("{\"interface\":[{\"interface\":\"iptv-fixture_mc\",\"l3_device\":\"lo\",\"up\":true,\"ipv4-address\":[{\"address\":\"127.0.0.1\"}],\"route\":[]}]}",carrier_file);fclose(carrier_file);
    expect(db,"");
    row=input(db);assert(!strcmp(iptv_string(row,"multicast_interface"),"iptv-fixture_mc"));json_object_put(row);
    sql(db,"UPDATE wan_advanced SET iptv_igmp_version=2");
    snprintf(igmp_root,sizeof(igmp_root),"%s/sysctl",argv[1]);
    expect(db,"igmp_runtime_unavailable");
    char igmp_path[8192];snprintf(igmp_path,sizeof(igmp_path),"%s/lo",igmp_root);assert(!mkdir(igmp_root,0700));assert(!mkdir(igmp_path,0700));
    strncat(igmp_path,"/force_igmp_version",sizeof(igmp_path)-strlen(igmp_path)-1);
    carrier_file=fopen(igmp_path,"w");assert(carrier_file);fputs("3\n",carrier_file);fclose(carrier_file);expect(db,"igmp_version_pending");
    carrier_file=fopen(igmp_path,"w");assert(carrier_file);fputs("2\n",carrier_file);fclose(carrier_file);expect(db,"");
    sql(db,"UPDATE wan_advanced SET iptv_igmp_version=0,iptv_multicast_source='session'");status_write("lo",1,"127.0.0.1",0);

    struct iptv_error e = {0};
    struct json_object *channel = json_tokener_parse("{\"source_url\":\"udp://239.255.19.1:19764\",\"mode\":\"managed\",\"input_id\":\"iptv-fixture\"}");
    char url[4096];
    assert(!iptv_source_url(db, channel, url, sizeof(url), 1, &e));
    assert(!strcmp(url, "udp://239.255.19.1:19764?localaddr=127.0.0.1&reuse=1")); checks++;
    status_write("lo", 0, "127.0.0.1", 0); expect(db, "input_link_down");
    assert(iptv_source_url(db, channel, url, sizeof(url), 1, &e) == -1);
    assert(!strcmp(e.code, "input_link_down")); checks++;
    status_write("lo", 1, "127.0.0.1", 1); expect(db, "input_is_default_route");
    status_write("lo", 1, "127.0.0.2", 0); expect(db, "input_address_unavailable");
    status_write("missing-vlan", 1, "127.0.0.1", 0); expect(db, "input_address_unavailable");
    status_write("lo", 1, "127.0.0.1", 0);
    sql(db, "UPDATE wan_advanced SET default_route=1"); expect(db, "input_is_default_route");
    sql(db, "UPDATE wan_advanced SET default_route=0; UPDATE wan SET enabled=0"); expect(db, "input_disabled");
    sql(db, "UPDATE wan SET enabled=1,access_mode='pppoe_multi'"); expect(db, "input_access_mode_not_supported");
    sql(db, "UPDATE wan SET access_mode='static',id='missing-netifd',device='lo'"); expect(db, "network_runtime_unavailable");
    json_object_put(channel); sqlite3_close(db); unlink(fixture_path);
    printf("{\"passed\":%d,\"scope\":\"real input resolver, synthetic netifd, real loopback and proc; no DHCP/PPPoE/VLAN apply\"}\n", checks);
    return 0;
}
