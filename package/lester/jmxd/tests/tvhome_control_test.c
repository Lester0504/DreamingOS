// SPDX-License-Identifier: GPL-2.0-or-later
/* Host integration test. Compile with TVH_DB_PATH pointing inside a fresh /tmp directory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include "tvhome/tvhome_store.h"
#ifndef TVH_DB_PATH
#error TVH_DB_PATH must name a disposable test database
#endif
int tvhome_ws_count(const char *id) { (void)id; return 0; }
static int checks;
#define CHECK(c) do { checks++; if(!(c)) {fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#c);exit(1);} } while(0)
static struct json_object *parse(const char *s) { struct json_object *o=json_tokener_parse(s);CHECK(o);return o; }
static const char *str(struct json_object *o,const char *k) { struct json_object *v=NULL;json_object_object_get_ex(o,k,&v);return v?json_object_get_string(v):""; }
static void sql(const char *q) { sqlite3 *db=NULL;CHECK(sqlite3_open(TVH_DB_PATH,&db)==SQLITE_OK);CHECK(sqlite3_exec(db,q,NULL,NULL,NULL)==SQLITE_OK);sqlite3_close(db); }
int main(void)
{
    CHECK(!strncmp(TVH_DB_PATH,"/tmp/",5));unlink(TVH_DB_PATH);
    struct tvhome_err e={0}; struct json_object *body=parse("{\"device\":{\"device_id\":\"box-a\",\"model\":\"test TV\",\"sdk_int\":33,\"supported_abis\":[\"arm64-v8a\"]}}");
    struct json_object *request=tvhome_activation_request(body,&e);CHECK(request && !e.http_status);
    char *id=strdup(str(request,"id")),*poll=strdup(str(request,"poll_token"));
    struct json_object *r=tvhome_activations(id,poll,&e);CHECK(r && !strcmp(str(r,"status"),"pending"));json_object_put(r);
    r=tvhome_activations(id,"wrong",&e);CHECK(!r && e.http_status==404);
    r=tvhome_activations(NULL,NULL,&e);CHECK(r && !strstr(json_object_to_json_string(r),poll));json_object_put(r);
    struct json_object *approval=tvhome_activation_decide(id,1,NULL,&e);CHECK(approval && !e.http_status);
    char *code=strdup(str(approval,"activation_code")),*tid=strdup(str(approval,"terminal_id"));
    CHECK(strcmp(code,tid));
    struct json_object *activation=json_object_new_object();json_object_object_add(activation,"code",json_object_new_string(code));json_object_object_add(body,"activation",activation);
    struct json_object *dev=NULL;json_object_object_get_ex(body,"device",&dev);
    json_object_object_add(dev,"device_id",json_object_new_string("box-b"));
    r=tvhome_session_create(body,&e);CHECK(!r && e.http_status==403 && !strcmp(e.code,"device_bound"));
    json_object_object_add(dev,"device_id",json_object_new_string("box-a"));
    r=tvhome_session_create(body,&e);CHECK(r && !e.http_status);char *token=strdup(str(r,"token"));json_object_put(r);
    r=tvhome_session_create(body,&e);CHECK(!r && e.http_status==401 && !strcmp(e.code,"activation_consumed"));
    r=tvhome_bootstrap(token,&e);CHECK(r && !e.http_status);json_object_put(r);
    r=tvhome_session_refresh(token,&e);CHECK(r && !e.http_status);char *next=strdup(str(r,"token"));CHECK(strcmp(token,next));json_object_put(r);
    r=tvhome_bootstrap(token,&e);CHECK(!r && e.http_status==401);
    r=tvhome_terminal_action(tid,"disable",&e);CHECK(r && !e.http_status);json_object_put(r);
    r=tvhome_bootstrap(next,&e);CHECK(!r && e.http_status==401);
    r=tvhome_terminal_action(tid,"enable",&e);CHECK(r && !e.http_status);json_object_put(r);
    r=tvhome_bootstrap(next,&e);CHECK(!r && e.http_status==401);
    r=tvhome_activation_decide(id,1,NULL,&e);CHECK(!r && e.http_status==409);
    struct json_object *second=tvhome_activation_request(body,&e);CHECK(second);char *id2=strdup(str(second,"id"));
    r=tvhome_activation_decide(id2,1,NULL,&e);CHECK(r);json_object_object_add(activation,"code",json_object_new_string(str(r,"activation_code")));json_object_put(r);
    sql("UPDATE tvhome_activation SET expires_at_ms=1 WHERE status='approved'");
    r=tvhome_session_create(body,&e);CHECK(!r && !strcmp(e.code,"activation_expired"));
    /* Locked storage must not consume an approval or issue a usable phantom token. */
    sqlite3 *lock=NULL;CHECK(sqlite3_open(TVH_DB_PATH,&lock)==SQLITE_OK);CHECK(sqlite3_exec(lock,"BEGIN EXCLUSIVE",NULL,NULL,NULL)==SQLITE_OK);
    r=tvhome_activation_request(body,&e);CHECK(!r && e.http_status==503);sqlite3_exec(lock,"ROLLBACK",NULL,NULL,NULL);sqlite3_close(lock);
    json_object_put(second);json_object_put(request);json_object_put(approval);json_object_put(body);
    free(id);free(id2);free(poll);free(code);free(tid);free(token);free(next);
    printf("PASS %d checks: approval, identity isolation, single-use, rotation, disable, expiry, locked DB\n",checks);
    return 0;
}
