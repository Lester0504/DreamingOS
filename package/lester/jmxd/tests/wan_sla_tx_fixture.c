// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise the production transaction against SQLite without daemon dependencies. */
#define DREAMINGWRT_FLOWD_INTERNAL_H
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <sqlite3.h>
#define FLOWD_MAX_JSON 8192
#define FLOWD_MAX_ID 96
static sqlite3 *g_flowd_config_db;
static int flowd_db_init(void) { return 0; }
static int64_t flowd_now_s(void) { return 1000; }
static struct json_object *lookup(struct json_object *o,const char *key)
{ struct json_object *v=NULL; if(o)json_object_object_get_ex(o,key,&v); return v; }
static const char *flowd_json_str(struct json_object *o,const char *k,const char *d)
{ struct json_object *v=lookup(o,k); return v?json_object_get_string(v):d; }
static int flowd_json_int(struct json_object *o,const char *k,int d)
{ struct json_object *v=lookup(o,k); return v?json_object_get_int(v):d; }
static int flowd_json_bool(struct json_object *o,const char *k,int d)
{ struct json_object *v=lookup(o,k); return v?json_object_get_boolean(v):d; }
static int flowd_text_ok(const char *s,size_t n) { return s && strlen(s)<=n; }
static int flowd_id_ok(const char *s) { return s && *s && strlen(s)<FLOWD_MAX_ID; }
static int flowd_json_fits(struct json_object *o,size_t n)
{ return strlen(json_object_to_json_string(o))<=n; }
static void flowd_make_id(const char *s,char *out,size_t n) { snprintf(out,n,"%s-fixture",s); }
static sqlite3_stmt *flowd_config_prepare(const char *s)
{ sqlite3_stmt *st=NULL; if(sqlite3_prepare_v2(g_flowd_config_db,s,-1,&st,NULL)!=SQLITE_OK)return NULL; return st; }
static const char *flowd_sqlite_text(sqlite3_stmt *s,int c,const char *d)
{ const unsigned char *v=sqlite3_column_text(s,c); return v?(const char *)v:d; }
__attribute__((unused)) static struct json_object *flowd_json_parse_or_array(const char *s)
{ struct json_object *o=json_tokener_parse(s); return o?o:json_object_new_array(); }
__attribute__((unused)) static struct json_object *flowd_json_parse_or_object(const char *s)
{ struct json_object *o=json_tokener_parse(s); return o?o:json_object_new_object(); }
static struct json_object *flowd_error(const char *code,const char *message)
{
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"ok",json_object_new_boolean(0));
    json_object_object_add(o,"error",json_object_new_string(code));
    json_object_object_add(o,"message",json_object_new_string(message)); return o;
}
#include "../src/flowd/wan_sla_tx.c"
#include "../src/flowd/wan_sla_config.c"

int flowd_wan_sla_shadow_ready(void) { return 0; }
void flowd_wan_sla_config_changed(void) {}
int flowd_wan_sla_dry_probe_matches(struct json_object *plan) { (void)plan; return 0; }
struct json_object *flowd_wan_sla_runtime_item(const char *id)
{
    struct json_object *o=json_object_new_object(); (void)id;
    json_object_object_add(o,"available",json_object_new_boolean(0)); return o;
}

static void success(struct json_object *o)
{ if(!flowd_json_bool(o,"ok",0))fprintf(stderr,"%s\n",json_object_to_json_string(o)); assert(flowd_json_bool(o,"ok",0)); }

static struct json_object *preview(const char *s)
{
    struct json_object *req=json_tokener_parse(s),*out=flowd_wan_sla_preview(req);
    json_object_put(req); success(out); return out;
}

int main(void)
{
    struct json_object *p,*r,*again,*list,*bad;
    assert(sqlite3_open(":memory:",&g_flowd_config_db)==SQLITE_OK);
    assert(!sla_exec("CREATE TABLE wan(id TEXT PRIMARY KEY,enabled INTEGER); INSERT INTO wan VALUES('wan',1);"
        "CREATE TABLE flowd_wan_health(id TEXT PRIMARY KEY,name TEXT,enabled INTEGER,wan TEXT,method TEXT,targets_json TEXT,"
        "interval_s INTEGER,timeout_ms INTEGER,loss_threshold_pct INTEGER,latency_threshold_ms INTEGER,fail_count INTEGER,recover_count INTEGER,"
        "remark TEXT,revision INTEGER,created_at INTEGER,updated_at INTEGER)"));
    p=preview("{\"id\":\"sla\",\"wan\":\"wan\",\"expected_revision\":0,\"targets\":[\"a\",\"b\",\"c\"],\"reliability\":2}");
    /*
     * Commit the FRESH plan after a JSON text round-trip, as every UI/REST/ubus
     * client does. The round-trip reparses the canonical double thresholds as
     * json_type_int, which strict json_object_equal would reject; commit must
     * accept it by digest. Without that fix this first commit returns 422.
     */
    {
        struct json_object *rt=json_tokener_parse(json_object_to_json_string(p));
        r=flowd_wan_sla_commit(rt); json_object_put(rt);
    }
    success(r);
    assert(flowd_json_int(lookup(r,"readback"),"reliability",0)==2);
    assert(flowd_json_int(lookup(r,"readback"),"revision",0)==1);
    again=flowd_wan_sla_commit(p); success(again);
    assert(flowd_json_bool(again,"replayed",0)); json_object_put(again);
    bad=json_tokener_parse(json_object_to_json_string(p));
    json_object_object_add(lookup(bad,"plan"),"name",json_object_new_string("tampered"));
    again=flowd_wan_sla_commit(bad);
    assert(flowd_json_int(again,"http_status",0)==422);
    json_object_put(again); json_object_put(bad);
    json_object_put(p); json_object_put(r);
    p=preview("{\"id\":\"sla\",\"expected_revision\":1,\"name\":\"new\",\"reliability\":3}");
    bad=json_tokener_parse(json_object_to_json_string(p));
    json_object_object_add(bad,"plan_digest",json_object_new_string("bad"));
    r=flowd_wan_sla_commit(bad); assert(flowd_json_int(r,"http_status",0)==422);
    json_object_put(r); json_object_put(bad);
    r=flowd_wan_sla_commit(p); success(r); json_object_put(r);
    bad=json_tokener_parse("{\"id\":\"sla\",\"expected_revision\":1}");
    r=flowd_wan_sla_preview(bad); assert(flowd_json_int(r,"http_status",0)==409);
    json_object_put(r); json_object_put(bad); json_object_put(p);
    p=preview("{\"id\":\"sla\",\"expected_revision\":2,\"operation\":\"delete\"}");
    r=flowd_wan_sla_commit(p); success(r); json_object_put(r);
    r=flowd_wan_sla_commit(p); success(r); assert(flowd_json_bool(r,"replayed",0));
    json_object_put(r); json_object_put(p);
    list=flowd_wan_sla_list(NULL);success(list);assert(flowd_json_int(list,"total",-1)==0);json_object_put(list);
    p=preview("{\"id\":\"rollback\",\"wan\":\"wan\",\"expected_revision\":0,\"targets\":[\"a\"]}");
    assert(!sla_exec("CREATE TRIGGER receipt_fail BEFORE INSERT ON flowd_wan_sla_commit_receipt BEGIN SELECT RAISE(ABORT,'injected'); END"));
    r=flowd_wan_sla_commit(p);assert(flowd_json_int(r,"http_status",0)==500);json_object_put(r);json_object_put(p);
    assert(!sla_load("rollback"));
    assert(sqlite3_get_autocommit(g_flowd_config_db));
    sqlite3_close(g_flowd_config_db);
    puts("ok: SLA create/update/delete replay, revision 409, digest 422, profile readback and receipt rollback");
    return 0;
}
