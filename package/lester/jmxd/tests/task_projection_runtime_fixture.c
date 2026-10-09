// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
static char test_db[PATH_MAX];
#define WEBD_TASKS_CONFIG_DB test_db
#include "../src/webd/api/api_tasks.c"

struct json_object *app_ubus_route_or_error(const char *object, const char *method,
    struct json_object *params, int timeout, int *status)
{
    (void)params;
    assert(!strcmp(object,"dreamingwrt.otad"));
    assert(!strcmp(method,"task_projection"));
    assert(timeout==2000);
    *status=503;
    return json_tokener_parse("{\"ok\":false,\"error\":{\"code\":\"method_not_registered\"}}");
}
struct json_object *webd_error(const char *code, const char *message,
                              const char *field, const char *source)
{
    (void)message;(void)field;(void)source;
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"error",json_object_new_string(code));
    return o;
}
static void exec_sql(sqlite3 *db,const char *sql)
{
    char *error=NULL;int rc=sqlite3_exec(db,sql,NULL,NULL,&error);
    if(rc!=SQLITE_OK)fprintf(stderr,"fixture SQL: %s\n",error);
    sqlite3_free(error);assert(rc==SQLITE_OK);
}
static struct json_object *get(struct json_object *o,const char *key)
{
    struct json_object *v=NULL;assert(json_object_object_get_ex(o,key,&v));return v;
}
int main(void)
{
    char dir[]="/tmp/task-projection-XXXXXX";assert(mkdtemp(dir));
    snprintf(test_db,sizeof(test_db),"%s/config.db",dir);
    struct jmx_api_ctx ctx={0};struct json_object *o=wifi_tasks(&ctx);
    assert(ctx.status==503);assert(access(test_db,F_OK)!=0);json_object_put(o);
    sqlite3 *db=NULL;assert(sqlite3_open(test_db,&db)==SQLITE_OK);
    o=wifi_tasks(&ctx);assert(ctx.status==503);json_object_put(o);
    exec_sql(db,"CREATE TABLE ac_transactions(transaction_id TEXT PRIMARY KEY,state TEXT,created_at INTEGER,updated_at INTEGER);CREATE TABLE ac_transaction_targets(transaction_id TEXT,ap_id TEXT,state TEXT);");
    o=wifi_tasks(&ctx);assert(ctx.status==200);
    assert(json_object_array_length(get(get(o,"data"),"tasks"))==0);json_object_put(o);
    char sql[1024];long now=(long)time(NULL);
    snprintf(sql,sizeof(sql),"INSERT INTO ac_transactions VALUES('pending-old','pending',1,1),('finished','applied',%ld,%ld),('expired','applied',2,2),('partial','partially_applied',%ld,%ld);INSERT INTO ac_transaction_targets VALUES('pending-old','ap-a','applied'),('pending-old','ap-b','running'),('finished','ap-a','applied');",now,now,now,now);exec_sql(db,sql);
    o=wifi_tasks(&ctx);assert(ctx.status==200);struct json_object *rows=get(get(o,"data"),"tasks");
    assert(json_object_array_length(rows)==3);
    struct json_object *first=json_object_array_get_idx(rows,0);
    assert(!strcmp(json_object_get_string(get(first,"task_id")),"pending-old"));
    assert(json_object_get_int(get(first,"progress"))==50);
    assert(!strstr(json_object_to_json_string(o),"candidate_json"));json_object_put(o);
    for(int i=0;i<70;i++){snprintf(sql,sizeof(sql),"INSERT INTO ac_transactions VALUES('t-%d','applied',%ld,%ld)",i,now+i,now);exec_sql(db,sql);}
    o=wifi_tasks(&ctx);assert(ctx.status==200);
    assert(json_object_array_length(get(get(o,"data"),"tasks"))==64);
    assert(json_object_get_boolean(get(get(o,"data"),"truncated")));json_object_put(o);
    assert(!strcmp(wifi_task_state("partially_applied"),"failed"));
    assert(!strcmp(wifi_task_state("rollback_failed"),"failed"));
    assert(!strcmp(wifi_task_state("rolling_back"),"in_progress"));
    assert(!strcmp(wifi_task_state("rolled_back"),"rolled_back"));
    o=ota_task(&ctx);assert(ctx.status==503);json_object_put(o);
    assert(!strcmp(tasks_api_routes[0].path,"/api/v1/system/ota/task"));
    assert(!strcmp(tasks_api_routes[1].path,"/api/v1/wifi/tasks"));
    sqlite3_close(db);unlink(test_db);rmdir(dir);
    puts("PASS: actual SQLite journal, missing source/schema, retention, progress, active ordering, bounds and OTA failure forwarding");
    return 0;
}
