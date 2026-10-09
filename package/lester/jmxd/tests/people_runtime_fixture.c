// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/webd/api/api_people.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

sqlite3 *g_config_db;
static int audits;
static struct json_object *last;
struct json_object *webd_error(const char *code, const char *message, const char *field, const char *source)
{
    (void)message; (void)field; (void)source;
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"error",json_object_new_string(code)); return o;
}
struct json_object *webd_envelope(struct json_object *data, const char *source)
{
    (void)source;
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"ok",json_object_new_boolean(1));
    json_object_object_add(o,"data",data); return o;
}
void jmx_app_audit_log_response(const char *actor,const char *device,const char *action,
    const char *risk,const char *target,const char *ip,struct json_object *reply,int status)
{
    (void)action; (void)target; (void)ip; (void)reply;
    assert(!strcmp(actor,"session-person-admin") && !strcmp(device,actor));
    assert(!strcmp(risk,"medium") && status < 400); audits++;
}
static int invoke(const char *path,const char *method,jmx_role_t role,const char *body)
{
    struct http_req req={0};struct jmx_api_ctx ctx={0};
    snprintf(req.path,sizeof(req.path),"%s",path);snprintf(req.method,sizeof(req.method),"%s",method);
    ctx.req=&req;ctx.role=role;ctx.device_id="session-person-admin";
    ctx.body=body?json_tokener_parse(body):NULL;
    if(last) json_object_put(last);
    last=NULL;
    for(const struct jmx_api_route *r=people_api_routes;r->path;r++) {
        if((r->flags&JMX_API_PREFIX)?strncmp(path,r->path,strlen(r->path)):strcmp(path,r->path))continue;
        last=r->handler(&ctx);break;
    }
    json_object_put(ctx.body);return ctx.status;
}
static void sql(const char *s){assert(sqlite3_exec(g_config_db,s,NULL,NULL,NULL)==SQLITE_OK);}
static struct json_object *data(void){return json_object_object_get(last,"data");}
static void error_is(const char *s){assert(!strcmp(json_object_get_string(json_object_object_get(last,"error")),s));}
static void open_db(const char *path){assert(sqlite3_open(path,&g_config_db)==SQLITE_OK);sql("PRAGMA foreign_keys=ON");assert(webd_people_init(g_config_db)==0);}
int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--request")) {
        open_db(argv[2]);
        char *line = NULL; size_t capacity = 0;
        assert(getline(&line, &capacity, stdin) > 0);
        struct json_object *request = json_tokener_parse(line);
        assert(request); free(line);
        struct json_object *body = json_object_object_get(request, "body");
        int status = invoke(json_object_get_string(json_object_object_get(request, "path")),
            json_object_get_string(json_object_object_get(request, "method")),
            json_object_get_int(json_object_object_get(request, "role")),
            body ? json_object_to_json_string(body) : NULL);
        struct json_object *out = json_object_new_object();
        json_object_object_add(out, "status", json_object_new_int(status));
        json_object_object_add(out, "body", last);
        puts(json_object_to_json_string(out));
        json_object_put(out); json_object_put(request); sqlite3_close(g_config_db);
        return 0;
    }
    char file[]="/tmp/people-runtime-XXXXXX";int fd=mkstemp(file);assert(fd>=0);close(fd);open_db(file);
    assert(invoke("/api/v1/people","GET",JMX_ROLE_VIEWER,NULL)==200);
    assert(!json_object_get_boolean(json_object_object_get(data(),"can_write")));
    assert(json_object_array_length(json_object_object_get(data(),"people"))==0);
    int before=audits;
    for(int role=JMX_ROLE_VIEWER;role<=JMX_ROLE_AI_AGENT;role++) {
        if(jmx_perm_check(role,JMX_RISK_MEDIUM))continue;
        assert(invoke("/api/v1/people","POST",role,"{\"name\":\"No\"}")==403);
    }
    assert(before==audits);
    assert(invoke("/api/v1/people","POST",JMX_ROLE_ADMIN,"{\"name\":\"  陈晓  \"}")==201);
    char id[64],path[128],body[128];snprintf(id,sizeof(id),"%s",json_object_get_string(json_object_object_get(data(),"id")));
    snprintf(path,sizeof(path),"/api/v1/people/%s",id);
    snprintf(body,sizeof(body),"{\"person_id\":\"%s\"}",id);
    assert(invoke(path,"GET",JMX_ROLE_VIEWER,NULL)==200);
    struct json_object *p=json_object_array_get_idx(json_object_object_get(data(),"people"),0);
    assert(!strcmp(json_object_get_string(json_object_object_get(p,"name")),"陈晓"));
    assert(invoke("/api/v1/people-bindings/AA:BB:CC:DD:EE:02","PUT",JMX_ROLE_ADMIN,body)==200);
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:03","PUT",JMX_ROLE_ADMIN,body)==200);
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:02","PUT",JMX_ROLE_ADMIN,body)==200);
    assert(invoke(path,"GET",JMX_ROLE_VIEWER,NULL)==200);
    p=json_object_array_get_idx(json_object_object_get(data(),"people"),0);
    assert(json_object_get_int(json_object_object_get(p,"device_count"))==2);
    assert(invoke(path,"DELETE",JMX_ROLE_ADMIN,NULL)==409);error_is("person_has_devices");
    assert(invoke(path,"PUT",JMX_ROLE_ADMIN,"{\"name\":\"晓陈\"}")==200);
    sqlite3_close(g_config_db);open_db(file);
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:02","GET",JMX_ROLE_VIEWER,NULL)==200);
    assert(!strcmp(json_object_get_string(json_object_object_get(data(),"name")),"晓陈"));
    assert(!strcmp(json_object_get_string(json_object_object_get(data(),"scope")),"current_assignment"));
    struct json_object *clients=json_tokener_parse("{\"data\":{\"clients\":[{\"mac\":\"AA:BB:CC:DD:EE:02\"},{\"mac\":\"aa:bb:cc:dd:ee:99\",\"person_id\":\"stale\",\"person_name\":\"stale\"}]}}");
    webd_people_project_clients(clients);
    struct json_object *rows=json_object_object_get(json_object_object_get(clients,"data"),"clients");
    assert(!strcmp(json_object_get_string(json_object_object_get(json_object_array_get_idx(rows,0),"person_id")),id));
    assert(!json_object_object_get(json_object_array_get_idx(rows,1),"person_id"));json_object_put(clients);
    assert(invoke("/api/v1/people","POST",JMX_ROLE_ADMIN,"{\"name\":\"\"}")==400);
    assert(invoke("/api/v1/people","POST",JMX_ROLE_ADMIN,"{\"name\":42}")==400);
    assert(invoke("/api/v1/people","POST",JMX_ROLE_ADMIN,"{\"name\":\"X\",\"actor\":\"forged\"}")==400);
    assert(invoke("/api/v1/people","POST",JMX_ROLE_ADMIN,"{\"name\":\"a\\u0000b\"}")==400);
    assert(invoke("/api/v1/people-bindings/not-mac","PUT",JMX_ROLE_ADMIN,body)==400);
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:02","PUT",JMX_ROLE_ADMIN,"{\"person_id\":\"person-00000000000000000000000000000000\"}")==404);
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:02","GET",JMX_ROLE_VIEWER,NULL)==200);
    assert(!strcmp(json_object_get_string(json_object_object_get(data(),"id")),id));
    sql("CREATE TRIGGER person_fail BEFORE UPDATE ON local_person BEGIN SELECT RAISE(ABORT,'write failure'); END");
    assert(invoke(path,"PUT",JMX_ROLE_ADMIN,"{\"name\":\"lost\"}")==503);
    sql("DROP TRIGGER person_fail");
    assert(invoke(path,"GET",JMX_ROLE_VIEWER,NULL)==200);
    p=json_object_array_get_idx(json_object_object_get(data(),"people"),0);
    assert(!strcmp(json_object_get_string(json_object_object_get(p,"name")),"晓陈"));
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:02","DELETE",JMX_ROLE_ADMIN,NULL)==200);
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:02","GET",JMX_ROLE_VIEWER,NULL)==200);
    assert(!json_object_get_boolean(json_object_object_get(data(),"available")));
    assert(!strcmp(json_object_get_string(json_object_object_get(data(),"reason")),"unassigned"));
    assert(invoke("/api/v1/people-bindings/aa:bb:cc:dd:ee:03","DELETE",JMX_ROLE_ADMIN,NULL)==200);
    assert(invoke(path,"DELETE",JMX_ROLE_ADMIN,NULL)==200);
    assert(invoke(path,"GET",JMX_ROLE_VIEWER,NULL)==404);
    sqlite3_close(g_config_db);g_config_db=NULL;
    assert(invoke("/api/v1/people","GET",JMX_ROLE_VIEWER,NULL)==503);
    json_object_put(last);unlink(file);
    puts("ok: real SQLite CRUD, restart, one-person/multiple-devices, normalized MAC, viewer denied writes, current projection, failed-write rollback, bound-delete conflict, unbind and unavailable store");
}
