// SPDX-License-Identifier: GPL-2.0-or-later
/* Real libuci and IPTV renderer, with a minimal WAN setter and no live reload. */
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <uci.h>
#include "../src/jmx_exec.h"
#include "../src/safeops/network_snapshot.h"
#include "../src/netconfig/network_transaction_uci.h"
static sqlite3 *g_netconfig_db;
static char config_dir[256];
#define NC_TX_CONFIG_DIR config_dir
static const char *nc_json_str(struct json_object *o,const char *key,const char *fallback)
{struct json_object *v=NULL;return o&&json_object_object_get_ex(o,key,&v)&&v?json_object_get_string(v):fallback;}
static int nc_json_int(struct json_object *o,const char *key,int fallback)
{struct json_object *v=NULL;return o&&json_object_object_get_ex(o,key,&v)&&v?json_object_get_int(v):fallback;}
#define nc_json_bool nc_json_int
static int nc_uci_section_name_ok(const char *s)
{return s&&*s&&strlen(s)<40&&strspn(s,"abcdefghijklmnopqrstuvwxyz0123456789_")==strlen(s);}
static int nc_uci_delete_loaded_section(struct uci_context *ctx,struct uci_package *pkg,struct uci_section *s)
{struct uci_ptr p={.p=pkg,.s=s};return uci_delete(ctx,&p);}
#include "iptv_uci_helpers.inc"
static int nc_iptv_same_carrier(const char *a,const char *b)
{return *b&&(!strcmp(a,b)||(!strncmp(a,b,strlen(b))&&a[strlen(b)]=='.'));}
static struct json_object *old_config;
static struct json_object *nc_iptv_canonical(const char *id,int *supported)
{(void)id;*supported=old_config!=NULL;return old_config?json_object_get(old_config):NULL;}
static void nc_add_field_error(struct json_object *errors,const char *field,const char *reason,const char *message)
{(void)field;(void)message;json_object_array_add(errors,json_object_new_string(reason));}
static int jmx_netconfig_wan_set(struct json_object *config)
{
    char *sql=sqlite3_mprintf("INSERT INTO wan VALUES(%Q,%Q,%Q) ON CONFLICT(id) DO UPDATE SET username=excluded.username,password_ref=CASE WHEN excluded.password_ref='' THEN wan.password_ref ELSE excluded.password_ref END",
        nc_json_str(config,"id",""),nc_json_str(config,"username",""),nc_json_str(config,"password",""));
    int rc=sqlite3_exec(g_netconfig_db,sql,NULL,NULL,NULL);sqlite3_free(sql);return rc==SQLITE_OK?0:-1;
}
#include "../src/netconfig/042_nc_iptv_apply.c"
static struct uci_context *parsed;
static struct uci_package *package;
static void load_prepared(struct json_object *files,const char *name)
{
    if(parsed)uci_free_context(parsed);
    package=NULL;
    parsed=uci_alloc_context();const char *text=nc_json_str(files,name,"");assert(*text);
    FILE *stream=fmemopen((void *)text,strlen(text),"r");assert(stream);
    assert(uci_import(parsed,stream,name,&package,true)==UCI_OK);fclose(stream);
}
static const char *option(const char *section,const char *key)
{
    struct uci_ptr p={0};char path[160];snprintf(path,sizeof(path),"%s.%s.%s",package->e.name,section,key);
    if(uci_lookup_ptr(parsed,&p,path,true)!=UCI_OK||!p.o||p.o->type!=UCI_TYPE_STRING)return "";
    return p.o->v.string;
}
int main(void)
{
    char dir[]="/tmp/iptv-uci-XXXXXX";assert(mkdtemp(dir));snprintf(config_dir,sizeof(config_dir),"%s",dir);
    const char *original="config interface 'lan'\n\toption proto 'static'\n\toption device 'br-lan'\n\toption ipaddr '192.0.2.1/24'\n";
    for(int n=0;n<2;n++) {char path[512];snprintf(path,sizeof(path),"%s/%s",dir,n?"firewall":"network");FILE *f=fopen(path,"w");assert(f);fputs(n?"config zone 'existing'\n\toption name 'lan'\n":original,f);fclose(f);}
    assert(sqlite3_open(":memory:",&g_netconfig_db)==SQLITE_OK);
    assert(sqlite3_exec(g_netconfig_db,"CREATE TABLE wan(id TEXT PRIMARY KEY,username TEXT,password_ref TEXT);"
        "CREATE TABLE wan_address(wan_id TEXT);CREATE TABLE wan_advanced(wan_id TEXT PRIMARY KEY,iptv_igmp_version INTEGER DEFAULT 0,iptv_multicast_source TEXT DEFAULT 'session',iptv_carrier_mode TEXT DEFAULT 'dhcp',iptv_carrier_address TEXT DEFAULT '',iptv_carrier_prefix INTEGER DEFAULT 24);CREATE TABLE wan_bond(wan_id TEXT);"
        "CREATE TABLE wan_dns_policy(wan_id TEXT);CREATE TABLE hybrid_line(parent_wan_id TEXT);",NULL,NULL,NULL)==SQLITE_OK);
    struct json_object *config=json_tokener_parse("{\"id\":\"iptv_1234\",\"name\":\"IPTV\",\"device\":\"eth9\",\"enabled\":true,\"access_mode\":\"dhcp\",\"vlan_enabled\":true,\"vlan_id\":\"88\",\"option60\":\"IPTV 'quoted' value\",\"mtu\":1500}");
    struct json_object *files=json_object_new_object();assert(!nc_iptv_prepare(config,"create",files));
    load_prepared(files,"network");
    assert(!strcmp(option("iptv_1234","device"),"eth9.88"));assert(!strcmp(option("iptv_1234_dev","vid"),"88"));
    assert(!strcmp(option("iptv_1234","defaultroute"),"0"));assert(!strcmp(option("iptv_1234","peerdns"),"0"));
    assert(!strcmp(option("iptv_1234","vendorid"),"IPTV 'quoted' value"));assert(!strcmp(option("lan","ipaddr"),"192.0.2.1/24"));
    struct json_object *errors=json_object_new_array();nc_iptv_uci_check(parsed,package,"iptv_1234","eth9",errors);assert(!json_object_array_length(errors));
    /* Preparation must not publish either package. */
    char path[512],bytes[512];snprintf(path,sizeof(path),"%s/network",dir);FILE *f=fopen(path,"r");assert(f);size_t length=fread(bytes,1,sizeof(bytes)-1,f);bytes[length]=0;fclose(f);assert(!strcmp(bytes,original));
    load_prepared(files,"firewall");assert(!strcmp(option("iptv_1234_zone","input"),"REJECT"));assert(!strcmp(option("iptv_1234_zone","forward"),"REJECT"));
    assert(!strcmp(option("iptv_1234_udp","dest_ip"),"224.0.0.0/4"));assert(!strcmp(option("iptv_1234_dhcp","dest_port"),"68"));
    for(int n=0;n<2;n++){const char *name=n?"firewall":"network";snprintf(path,sizeof(path),"%s/%s",dir,name);f=fopen(path,"w");assert(f);fputs(nc_json_str(files,name,""),f);fclose(f);}
    json_object_put(files);files=json_object_new_object();
    json_object_object_add(config,"access_mode",json_object_new_string("pppoe"));json_object_object_add(config,"username",json_object_new_string("test-user"));json_object_object_add(config,"password",json_object_new_string("fixture-secret"));
    json_object_object_add(config,"vlan_enabled",json_object_new_boolean(0));
    assert(!nc_iptv_prepare(config,"update",files));load_prepared(files,"network");
    assert(!strcmp(option("iptv_1234","device"),"eth9"));assert(!strcmp(option("iptv_1234","password"),"fixture-secret"));
    assert(!*option("iptv_1234","vendorid"));assert(!*option("iptv_1234_dev","vid"));
    json_object_object_add(config,"igmp_version",json_object_new_int(2));
    json_object_put(files);files=json_object_new_object();assert(!nc_iptv_prepare(config,"update",files));load_prepared(files,"network");
    assert(!strcmp(option("iptv_1234_mcast","name"),"pppoe-iptv_1234"));
    assert(!strcmp(option("iptv_1234_mcast","igmpversion"),"2"));
    assert(!*option("iptv_1234_mc","proto"));
    json_object_object_add(config,"multicast_source",json_object_new_string("carrier"));
    json_object_object_add(config,"carrier_access_mode",json_object_new_string("dhcp"));
    json_object_object_add(config,"igmp_version",json_object_new_int(3));
    json_object_put(files);files=json_object_new_object();assert(!nc_iptv_prepare(config,"update",files));load_prepared(files,"network");
    assert(!strcmp(option("iptv_1234_mc","proto"),"dhcp"));assert(!strcmp(option("iptv_1234_mc","device"),"eth9"));
    assert(!strcmp(option("iptv_1234_dev","igmpversion"),"3"));
    assert(!strcmp(option("iptv_1234_mc","defaultroute"),"0"));assert(!strcmp(option("iptv_1234_mc","peerdns"),"0"));
    assert(!strcmp(option("iptv_1234_mc","vendorid"),"IPTV 'quoted' value"));assert(!*option("iptv_1234_mcast","name"));
    load_prepared(files,"firewall");assert(!strcmp(option("iptv_1234_zone","network"),"iptv_1234 iptv_1234_mc"));
    json_object_object_add(config,"carrier_access_mode",json_object_new_string("static"));
    json_object_object_add(config,"carrier_address",json_object_new_string("198.18.1.2"));
    json_object_object_add(config,"carrier_prefix",json_object_new_int(24));
    json_object_put(files);files=json_object_new_object();assert(!nc_iptv_prepare(config,"update",files));load_prepared(files,"network");
    assert(!strcmp(option("iptv_1234_mc","ipaddr"),"198.18.1.2/24"));assert(!*option("iptv_1234_mc","vendorid"));
    sqlite3_stmt *saved=NULL;assert(sqlite3_prepare_v2(g_netconfig_db,"SELECT iptv_igmp_version,iptv_multicast_source,iptv_carrier_address FROM wan_advanced WHERE wan_id='iptv_1234'",-1,&saved,NULL)==SQLITE_OK);
    assert(sqlite3_step(saved)==SQLITE_ROW&&sqlite3_column_int(saved,0)==3&&!strcmp((char*)sqlite3_column_text(saved,1),"carrier")&&!strcmp((char*)sqlite3_column_text(saved,2),"198.18.1.2"));sqlite3_finalize(saved);
    struct json_object *rollback=safeops_network_rows(g_netconfig_db,"iptv","iptv_1234");assert(rollback);
    assert(sqlite3_exec(g_netconfig_db,"UPDATE wan_advanced SET iptv_igmp_version=2,iptv_multicast_source='session'",NULL,NULL,NULL)==SQLITE_OK);
    assert(!safeops_network_restore_rows(g_netconfig_db,"iptv","iptv_1234",rollback));json_object_put(rollback);
    assert(sqlite3_prepare_v2(g_netconfig_db,"SELECT iptv_igmp_version,iptv_multicast_source FROM wan_advanced WHERE wan_id='iptv_1234'",-1,&saved,NULL)==SQLITE_OK);
    assert(sqlite3_step(saved)==SQLITE_ROW&&sqlite3_column_int(saved,0)==3&&!strcmp((char*)sqlite3_column_text(saved,1),"carrier"));sqlite3_finalize(saved);
    /* Persist the generated carrier sections, then confirm mode switch removes
     * all owned carrier/protocol settings while preserving unrelated network. */
    for(int n=0;n<2;n++){const char *name=n?"firewall":"network";snprintf(path,sizeof(path),"%s/%s",dir,name);f=fopen(path,"w");assert(f);fputs(nc_json_str(files,name,""),f);fclose(f);}
    json_object_object_add(config,"multicast_source",json_object_new_string("session"));
    json_object_object_add(config,"igmp_version",json_object_new_int(0));
    json_object_object_add(config,"access_mode",json_object_new_string("static"));
    json_object_object_add(config,"addresses",json_tokener_parse("[{\"ip\":\"198.51.100.2\",\"prefix\":24}]"));
    json_object_put(files);files=json_object_new_object();assert(!nc_iptv_prepare(config,"update",files));load_prepared(files,"network");
    assert(!strcmp(option("iptv_1234","ipaddr"),"198.51.100.2/24"));assert(!*option("iptv_1234","password"));assert(!*option("iptv_1234_mc","proto"));assert(!*option("iptv_1234_mcast","igmpversion"));
    assert(!nc_uci_set_pkg(parsed,"network","lan","device","eth9"));nc_iptv_uci_check(parsed,package,"iptv_1234","eth9",errors);assert(json_object_array_length(errors)>0);
    char device[IFNAMSIZ];assert(!nc_iptv_route_device("127.0.0.1",device)&&!strcmp(device,"lo"));assert(nc_iptv_route_device("forged",device));
    struct json_object *request=json_tokener_parse("{\"peer_ip\":\"127.0.0.1\",\"operation\":\"create\"}");
    /* Reads both isolated UCI packages; no real interface or reload occurs. */
    old_config=json_tokener_parse("{\"device\":\"lo\",\"exists\":true}");
    nc_iptv_platform_check(config,request,errors);
    assert(strstr(json_object_to_json_string(errors),"management_path_in_use"));
    json_object_put(old_config);old_config=NULL;json_object_put(request);
    json_object_put(files);files=json_object_new_object();assert(!nc_iptv_prepare(config,"delete",files));load_prepared(files,"network");
    assert(!*option("iptv_1234","device"));assert(!*option("iptv_1234_dev","vid"));assert(!strcmp(option("lan","device"),"br-lan"));
    load_prepared(files,"firewall");assert(!*option("iptv_1234_zone","name"));assert(!strcmp(option("existing","name"),"lan"));
    puts("ok: real libuci IPTV VLAN/DHCP/PPPoE/static/no default route/no peer DNS/firewall/scoped delete/no publication/ownership/management route");
    json_object_put(config);json_object_put(files);json_object_put(errors);uci_free_context(parsed);sqlite3_close(g_netconfig_db);return 0;
}
