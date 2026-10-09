/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include "../src/system/memory_profile.h"
static sqlite3 *db;
static struct dw_memory_profile published;
static int publish_fails;
static int nc_prepare(sqlite3_stmt **st, const char *sql) { return sqlite3_prepare_v2(db,sql,-1,st,NULL)==SQLITE_OK?0:-1; }
static int nc_exec(const char *sql) { return sqlite3_exec(db,sql,NULL,NULL,NULL)==SQLITE_OK?0:-1; }
static int nc_step_done(sqlite3_stmt *st) { return sqlite3_step(st)==SQLITE_DONE?0:-1; }
static int nc_txn_begin(void) { return nc_exec("BEGIN IMMEDIATE"); }
static int nc_txn_end(int rc) { return nc_exec(rc ? "ROLLBACK" : "COMMIT"); }
static int jmx_netconfig_db_init(void) { return 0; }
static int64_t nc_now_s(void) { return time(NULL); }
static void nc_sys_read_first_line(const char *path,char *out,size_t n) { (void)path; snprintf(out,n,"AX1800Pro"); }
static void fixture_memory(const char *path,struct dw_memory_profile *p) { (void)path; p->total_bytes=384*DW_MP_MIB; p->available_bytes=128*DW_MP_MIB; p->available_known=1; }
static int fixture_publish(const struct dw_memory_profile *p) { if(publish_fails)return -1; published=*p; return 0; }
static struct json_object *dw_rm_registry_status_json(void) { return json_tokener_parse("{\"resources\":[]}"); }
#define dw_mp_memory fixture_memory
#define dw_mp_publish fixture_publish
#define LOG_WARN(...) ((void)0)
#define API_CODE_SUCCESS 0
#define API_CODE_ERROR 1
static struct json_object *jmx_gen_api_response_data(int code,struct json_object *data) {
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"code",json_object_new_int(code));json_object_object_add(o,"data",data);return o;
}
#include "../src/netconfig/025_nc_memory_profile.c"
static struct json_object *request(const char *text,int apply) {
    struct json_object *req=json_tokener_parse(text), *response=jmx_system_memory_profile_change(req,apply), *data;
    json_object_put(req); assert(json_object_object_get_ex(response,"data",&data));
    json_object_get(data);json_object_put(response);return data;
}
static int64_t number(struct json_object *o,const char *key) {struct json_object *v;assert(json_object_object_get_ex(o,key,&v));return json_object_get_int64(v);}
int main(void) {
    assert(sqlite3_open(":memory:",&db)==SQLITE_OK);
    assert(nc_exec("CREATE TABLE system_settings(id INTEGER PRIMARY KEY,memory_mode TEXT,memory_revision INTEGER,memory_activated_at INTEGER);INSERT INTO system_settings VALUES(1,'auto',1,0)")==0);
    nc_mp_boot_publish(); assert(published.compact && published.revision==1);
    struct json_object *o=request("{\"requested_mode\":\"standard\",\"config_revision\":1}",0);
    assert(number(o,"preview")==1 && published.revision==1);json_object_put(o);
    o=request("{\"requested_mode\":\"standard\",\"config_revision\":1}",1);
    assert(number(o,"ok")==1 && number(o,"config_revision")==2 && !published.compact);json_object_put(o);
    o=request("{\"requested_mode\":\"compact\",\"config_revision\":1}",1);
    assert(number(o,"http_status")==409 && published.revision==2);json_object_put(o);
    o=request("{\"requested_mode\":\"bad\",\"config_revision\":2}",1);
    assert(number(o,"http_status")==422 && sqlite3_get_autocommit(db));json_object_put(o);
    o=request("{\"requested_mode\":\"compact\",\"config_revision\":2,\"unexpected\":1}",1);
    assert(number(o,"http_status")==422);json_object_put(o);
    publish_fails=1;
    o=request("{\"requested_mode\":\"compact\",\"config_revision\":2}",1);
    assert(number(o,"ok")==0 && number(o,"http_status")==503 && number(o,"config_revision")==3);json_object_put(o);
    publish_fails=0;
    o=request("{\"requested_mode\":\"compact\",\"config_revision\":3}",1);
    assert(number(o,"ok")==1 && published.compact && published.revision==3);json_object_put(o);
    o=request("{\"requested_mode\":\"standard\",\"config_revision\":3}",1);
    assert(number(o,"config_revision")==4 && !published.compact);json_object_put(o);
    sqlite3_close(db);puts("memory profile API preview, CAS, rollback selection, projection retry: PASS");return 0;
}
