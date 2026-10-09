// SPDX-License-Identifier: GPL-2.0-or-later
/* Actual capability code with real SQLite; no user or device state changes. */
#include <assert.h>
#include "../src/tvhome/tvhome_store.c"
static void test_sql(sqlite3 *db,const char *s){assert(sqlite3_exec(db,s,NULL,NULL,NULL)==SQLITE_OK);}
static void expect_live(sqlite3 *db,const char *term,const char *reason,int available,int enabled,int permitted)
{
    struct json_object *caps=tvh_capabilities(db,term),*live=jobj(caps,"live");
    assert(!strcmp(jstr(live,"reason"),reason));
    assert(jbool(live,"available",0)==available&&jbool(live,"enabled",0)==enabled&&jbool(live,"permitted",0)==permitted);
    if(available){assert(!strcmp(jstr(live,"provider_id"),"iptv.local"));assert(!strcmp(jstr(live,"api_base"),"/api/v1/iptv/client/"));}
    assert(jbool(jobj(caps,"apps"),"available",0));
    json_object_put(caps);
}
int main(void)
{
    sqlite3 *db=NULL;assert(sqlite3_open(":memory:",&db)==SQLITE_OK);
    test_sql(db,"CREATE TABLE tvhome_settings(id PRIMARY KEY,pin_required,modules_json,media_principal_id);"
        "INSERT INTO tvhome_settings VALUES(1,0,'{\"live\":true}','web:alice');"
        "CREATE TABLE tvhome_terminal(id,media_principal_id);"
        "INSERT INTO tvhome_terminal VALUES('tv-a',''),('tv-b','web:bob');"
        "CREATE TABLE web_users(username,status);INSERT INTO web_users VALUES('alice','enabled'),('bob','disabled');");
    expect_live(db,"tv-a","provider_not_configured",0,0,0);
    test_sql(db,"CREATE TABLE iptv_record(kind,id,body);INSERT INTO iptv_record VALUES('settings','main','{\"enabled\":true}');");
    expect_live(db,"tv-a","channel_not_authorized",1,1,0);
    test_sql(db,"INSERT INTO iptv_record VALUES('viewers','alice','{\"principal_id\":\"web:alice\",\"enabled\":true,\"all_categories\":true,\"expires_at\":0}');");
    expect_live(db,"tv-a","available",1,1,1);
    expect_live(db,"tv-b","media_identity_unavailable",1,1,0);
    test_sql(db,"UPDATE tvhome_settings SET pin_required=1");expect_live(db,"tv-a","pin_required",1,1,0);
    test_sql(db,"UPDATE tvhome_settings SET pin_required=0,modules_json='{\"live\":{\"enabled\":false}}'");expect_live(db,"tv-a","live_disabled",1,0,1);
    test_sql(db,"UPDATE tvhome_settings SET modules_json='{\"live\":{\"enabled\":true,\"provider_id\":\"iptv.local\"}}';UPDATE iptv_record SET body='{\"enabled\":false}' WHERE kind='settings';");expect_live(db,"tv-a","module_disabled",1,0,1);
    test_sql(db,"UPDATE iptv_record SET body='{\"enabled\":true}' WHERE kind='settings';UPDATE iptv_record SET body=json_set(body,'$.expires_at',1) WHERE kind='viewers';");expect_live(db,"tv-a","channel_not_authorized",1,1,0);
    test_sql(db,"UPDATE iptv_record SET body=json_set(body,'$.expires_at',0,'$.enabled',json('false')) WHERE kind='viewers';");expect_live(db,"tv-a","channel_not_authorized",1,1,0);
    test_sql(db,"UPDATE tvhome_settings SET modules_json='{\"live\":{\"enabled\":true,\"provider_id\":\"unknown\"}}'");expect_live(db,"tv-a","provider_not_configured",0,0,0);
    test_sql(db,"UPDATE tvhome_settings SET modules_json='{\"live\":\"true\"}'");expect_live(db,"tv-a","live_disabled",1,0,0);
    sqlite3_close(db);
    puts("PASS: TV Live real SQLite capability, local provider, terminal/global identity, disabled user, grant/revocation/expiry, Live/module switches and PIN denial");
    return 0;
}
