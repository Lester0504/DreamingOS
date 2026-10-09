/* Real history SQL on an isolated SQLite DB; no router state or provider calls. */
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <json-c/json.h>
#include <sqlite3.h>
#define NC_AI_CONVERSATION_ID_MAX 95
#define NC_AI_TITLE_MAX 512
#define NC_AI_MODEL_MAX 128
#define NC_AI_EFFORT_MAX 32
#define NC_AI_MESSAGES_MAX 512
#define NC_AI_MESSAGE_CONTENT_MAX (256 * 1024)
#define NC_AI_HISTORY_CONTENT_MAX (4 * 1024 * 1024)
#define NC_AI_ATTACHMENTS_MAX 8
#define NC_AI_ATTACHMENT_NAME_MAX 255
#define NC_AI_ATTACHMENT_TYPE_MAX 128
#define API_CODE_ERROR 5000
#define API_CODE_SUCCESS 2000
#define JMX_AI_HISTORY_DELETE_OK 0
#define JMX_AI_HISTORY_DELETE_NOT_FOUND 1
static sqlite3 *db;
static int jmx_netconfig_db_init(void) { return 0; }
static int nc_exec(const char *sql) { return sqlite3_exec(db,sql,0,0,0)==SQLITE_OK ? 0 : -1; }
static int nc_prepare(sqlite3_stmt **st,const char *sql) { return sqlite3_prepare_v2(db,sql,-1,st,0)==SQLITE_OK ? 0 : -1; }
static int nc_step_done(sqlite3_stmt *st) { return sqlite3_step(st)==SQLITE_DONE ? 0 : -1; }
static int nc_sqlite_changes(void) { return sqlite3_changes(db); }
static int64_t nc_now_s(void) { return 1790942400; }
static const char *nc_json_str_def(struct json_object *o,const char *k,const char *d) { struct json_object *v=0; return o&&json_object_object_get_ex(o,k,&v)&&v ? json_object_get_string(v) : d; }
static int nc_json_int_def(struct json_object *o,const char *k,int d) { struct json_object *v=0; return o&&json_object_object_get_ex(o,k,&v)&&v ? json_object_get_int(v) : d; }
static void nc_add_text(struct json_object *o,const char *k,sqlite3_stmt *st,int col) { const char *v=(const char *)sqlite3_column_text(st,col); json_object_object_add(o,k,json_object_new_string(v?v:"")); }
static struct json_object *jmx_gen_api_response_data(int code,struct json_object *d) { struct json_object *r=json_object_new_object(); json_object_object_add(r,"code",json_object_new_int(code)); json_object_object_add(r,"data",d); return r; }
#include "../src/netconfig/002_nc_ai_history.c"
static struct json_object *data(struct json_object *r) { struct json_object *d=0; assert(json_object_object_get_ex(r,"data",&d)); return d; }
static void expect_error(struct json_object *r,const char *code) { assert(!strcmp(nc_json_str_def(data(r),"error",""),code)); json_object_put(r); }
static struct json_object *save(const char *actor,const char *id,int rev,const char *text) {
 struct json_object *q=json_object_new_object(),*messages=json_object_new_array(),*m=json_object_new_object();
 json_object_object_add(q,"id",json_object_new_string(id));
 if(rev>=0) json_object_object_add(q,"revision",json_object_new_int(rev));
 json_object_object_add(q,"execution_backend",json_object_new_string("api"));
 json_object_object_add(q,"provider",json_object_new_string("test-provider"));
 json_object_object_add(m,"id",json_object_new_string("m1"));
 json_object_object_add(m,"role",json_object_new_string("assistant"));
 json_object_object_add(m,"content",json_object_new_string(text));
 json_object_object_add(m,"status",json_object_new_string("interrupted"));
 json_object_object_add(m,"response_id",json_object_new_string("resp-1"));
 json_object_array_add(messages,m); json_object_object_add(q,"messages",messages);
 struct json_object *r=jmx_ai_history_save(actor,q); json_object_put(q); return r;
}
static void init_history_db(void) {
 assert(sqlite3_open(":memory:",&db)==SQLITE_OK);
 assert(!nc_exec("PRAGMA foreign_keys=ON; CREATE TABLE ai_conversation(id TEXT PRIMARY KEY,title TEXT,model TEXT,reasoning_effort TEXT,message_count INTEGER,prompt_tokens INTEGER,completion_tokens INTEGER,total_tokens INTEGER,created_at INTEGER,updated_at INTEGER,owner TEXT NOT NULL DEFAULT '',revision INTEGER NOT NULL DEFAULT 0,execution_backend TEXT NOT NULL DEFAULT 'api',provider TEXT NOT NULL DEFAULT ''); CREATE TABLE ai_message(id INTEGER PRIMARY KEY,conversation_id TEXT REFERENCES ai_conversation(id) ON DELETE CASCADE,message_id TEXT,role TEXT,content TEXT,attachments_json TEXT,created_at INTEGER,metadata_json TEXT DEFAULT '{}');"));
 assert(!nc_exec("INSERT INTO ai_conversation(id,owner,revision) VALUES('legacy','',0)"));
}
int main(void) {
 init_history_db();
 expect_error(jmx_ai_history_list(NULL,10,0,""),"identity_required");
 struct json_object *r=save("user:alice","a",0,"needle password=secret"); assert(nc_json_int_def(data(r),"revision",0)==1); json_object_put(r);
 expect_error(jmx_ai_history_get("user:bob","a"),"not_found");
 expect_error(save("user:bob","a",1,"stolen"),"not_found");
 expect_error(save("user:alice","legacy",0,"claim"),"not_found");
 assert(jmx_ai_history_delete("user:bob","a")==JMX_AI_HISTORY_DELETE_NOT_FOUND);
 expect_error(save("user:alice","a",-1,"unversioned"),"conversation_conflict");
 r=save("user:alice","a",1,"new needle password=secret");assert(nc_json_int_def(data(r),"revision",0)==2);json_object_put(r);
 expect_error(save("user:alice","a",1,"stale window"),"conversation_conflict");
 r=jmx_ai_history_get("user:alice","a");struct json_object *item=0,*msgs=0; assert(json_object_object_get_ex(data(r),"item",&item));assert(json_object_object_get_ex(item,"messages",&msgs));struct json_object *m=json_object_array_get_idx(msgs,0);assert(strstr(nc_json_str_def(m,"content",""),"new needle"));assert(!strstr(nc_json_str_def(m,"content",""),"secret"));assert(!strcmp(nc_json_str_def(m,"status",""),"interrupted"));assert(!strcmp(nc_json_str_def(m,"response_id",""),"resp-1"));assert(!json_object_object_get(item,"usage"));json_object_put(r);
 for(int i=0;i<105;i++){char id[32];snprintf(id,sizeof(id),"n%03d",i);r=save("user:alice",id,0,"page marker");assert(nc_json_int_def(data(r),"revision",0)==1);json_object_put(r);}
 r=save("user:bob","b",0,"page marker");json_object_put(r);
 r=jmx_ai_history_list("user:alice",10,100,"page marker");assert(nc_json_int_def(data(r),"total",0)==105);json_object_object_get_ex(data(r),"items",&msgs);assert(json_object_array_length(msgs)==5);json_object_put(r);
 r=jmx_ai_history_list("user:alice",10,0,"needle");assert(nc_json_int_def(data(r),"total",0)==1);json_object_put(r);
 r=jmx_ai_history_list("user:alice",10,0,"%_");assert(nc_json_int_def(data(r),"total",-1)==0);json_object_put(r);
 assert(!jmx_ai_history_clear("user:alice")); r=jmx_ai_history_list("user:bob",10,0,"");assert(nc_json_int_def(data(r),"total",0)==1);json_object_put(r);
 sqlite3_stmt *st=0;nc_prepare(&st,"SELECT COUNT(*) FROM ai_conversation WHERE id='legacy'");assert(sqlite3_step(st)==SQLITE_ROW&&sqlite3_column_int(st,0)==1);sqlite3_finalize(st);
 sqlite3_close(db);puts("PASS: private history, legacy preservation, literal search >100, revision conflict, metadata roundtrip, scoped clear");return 0;
}
