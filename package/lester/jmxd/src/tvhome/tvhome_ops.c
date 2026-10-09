// SPDX-License-Identifier: GPL-2.0-or-later
/* Local TV operations: durable commands are reconciled through bootstrap. */
#include "tvhome_ops.h"
#include "tvhome_assets.h"
#include "tvhome_packages.h"
#include <openssl/rand.h>
#include <stdlib.h>

int tvhome_ops_schema(sqlite3 *db)
{
 return tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_theme_flags(theme_id TEXT PRIMARY KEY,enabled INTEGER NOT NULL)",0) || tvhome_assets_schema(db) || tvhome_packages_schema(db) || tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_notice(id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,body TEXT NOT NULL);",0) ||
 tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_command(id TEXT PRIMARY KEY,body TEXT NOT NULL,state TEXT NOT NULL,issued INTEGER NOT NULL,expires INTEGER NOT NULL);",0) ||
 tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_command_result(command_id TEXT NOT NULL,terminal_id TEXT NOT NULL,delivery TEXT NOT NULL DEFAULT 'pending',application TEXT NOT NULL DEFAULT 'unknown',detail TEXT NOT NULL DEFAULT '',updated INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(command_id,terminal_id));",0) ||
 tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_event(id INTEGER PRIMARY KEY AUTOINCREMENT,terminal_id TEXT NOT NULL,client_id TEXT NOT NULL,kind TEXT NOT NULL,time_ms INTEGER NOT NULL,body TEXT NOT NULL,UNIQUE(terminal_id,client_id));",0) ||
 tv_run(db,"CREATE INDEX IF NOT EXISTS tvhome_event_time ON tvhome_event(time_ms);",0);
}
static struct json_object *copy(struct json_object *o) {return o?json_tokener_parse(tv_json(o)):NULL;}
static void string(struct json_object *o,const char *k,const char *v) {json_object_object_add(o,k,json_object_new_string(v));}
static void number(struct json_object *o,const char *k,int64_t v) {json_object_object_add(o,k,json_object_new_int64(v));}
static int contains(struct json_object *a,const char *s) {
 for(size_t i=0;i<json_object_array_length(a);i++){struct json_object *v=json_object_array_get_idx(a,i);if(json_object_is_type(v,json_type_string)&&!strcmp(json_object_get_string(v),s))return 1;}return 0;
}
int tvhome_target_matches(struct json_object *target,const char *id,const char *group)
{
 const char *mode=tv_str(target,"mode");if(!strcmp(mode,"all"))return 1;
 return contains(tv_get(target,"ids"),!strcmp(mode,"groups")?group:id);
}
struct json_object *tvhome_target_members(sqlite3 *db,struct json_object *target,struct tvhome_err *e)
{
 const char *mode=tv_str(target,"mode");struct json_object *ids=tv_get(target,"ids"),*members=json_object_new_array();sqlite3_stmt *s=NULL;
 int all=!strcmp(mode,"all"),groups=!strcmp(mode,"groups");
 if((!all&&!groups&&strcmp(mode,"terminals")) || !json_object_is_type(ids,json_type_array) ||
    (all?json_object_array_length(ids)!=0:json_object_array_length(ids)==0) || json_object_array_length(ids)>500)goto invalid;
 for(size_t i=0;i<json_object_array_length(ids);i++){
  struct json_object *v=json_object_array_get_idx(ids,i);
  if(!json_object_is_type(v,json_type_string)||!tv_exists(db,groups?"SELECT 1 FROM tvhome_group WHERE id=?":"SELECT 1 FROM tvhome_terminal WHERE id=?",json_object_get_string(v)))goto invalid;
 }
 if(sqlite3_prepare_v2(db,"SELECT id,group_id FROM tvhome_terminal ORDER BY id",-1,&s,NULL)!=SQLITE_OK)goto invalid;
 while(sqlite3_step(s)==SQLITE_ROW)if(tvhome_target_matches(target,tv_col(s,0),tv_col(s,1)))json_object_array_add(members,json_object_new_string(tv_col(s,0)));
 sqlite3_finalize(s);return members;
invalid:
 json_object_put(members);tvhome_error(e,400,"invalid_target","target","Use explicit all, nonempty existing terminals, or nonempty existing groups");return NULL;
}
static struct json_object *notice_read(sqlite3 *db)
{
 sqlite3_stmt *s=NULL;struct json_object *o=NULL;
 if(sqlite3_prepare_v2(db,"SELECT body,revision FROM tvhome_notice WHERE id=1",-1,&s,NULL)==SQLITE_OK){
  if(sqlite3_step(s)==SQLITE_ROW){o=json_tokener_parse(tv_col(s,0));if(o)number(o,"revision",sqlite3_column_int64(s,1));}sqlite3_finalize(s);
 }
 if(!o)o=json_tokener_parse("{\"enabled\":false,\"text\":\"\",\"speed\":60,\"start_at_ms\":0,\"end_at_ms\":0,\"target\":{\"mode\":\"all\",\"ids\":[]},\"revision\":0}");return o;
}
struct json_object *tvhome_notice_get(struct tvhome_err *e) {sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;struct json_object *o=notice_read(db);sqlite3_close(db);return o;}
struct json_object *tvhome_notice_put(struct json_object *body,struct tvhome_err *e)
{
 sqlite3 *db=NULL;struct json_object *members,*old,*o;char revision[32];
 int enabled=json_object_get_boolean(tv_get(body,"enabled"));int64_t start=tv_num(body,"start_at_ms"),end=tv_num(body,"end_at_ms");
 if(!json_object_is_type(tv_get(body,"enabled"),json_type_boolean)||strlen(tv_str(body,"text"))>2000 ||
   (enabled&&(!*tv_str(body,"text")||end<=start||end<=tv_now()))||tv_num(body,"speed")<10||tv_num(body,"speed")>200)
  return tvhome_error(e,400,"invalid_parameter","notice","Text, speed (10–200), and a finite valid time window are required");
 if(tvhome_db_open(&db,e))return NULL;
 if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);
 if(tvhome_assets_validate(db,body,e)){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
 members=tvhome_target_members(db,tv_get(body,"target"),e);if(!members){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}json_object_put(members);
 old=notice_read(db);int64_t rev=tv_num(old,"revision");json_object_put(old);
 if(!tv_get(body,"expected_revision")||tv_num(body,"expected_revision")!=rev){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"revision_conflict","expected_revision","Notice changed; reload before saving");}
 o=copy(body);json_object_object_del(o,"expected_revision");json_object_object_del(o,"revision");snprintf(revision,sizeof(revision),"%lld",(long long)rev+1);
 if(tv_run(db,"INSERT OR REPLACE INTO tvhome_notice(id,revision,body) VALUES(1,?,?)",2,revision,tv_json(o))||tv_changed(db)||tv_run(db,"COMMIT",0)){json_object_put(o);return tv_db_error(db,e);}
 json_object_put(o);o=notice_read(db);sqlite3_close(db);return o;
}
struct json_object *tvhome_notice_for_terminal(sqlite3 *db,const char *terminal)
{
 struct json_object *o=notice_read(db);sqlite3_stmt *s=NULL;int matches=0;
 if(json_object_get_boolean(tv_get(o,"enabled")) && tv_num(o,"start_at_ms")<=tv_now() && tv_num(o,"end_at_ms")>tv_now() &&
 sqlite3_prepare_v2(db,"SELECT group_id FROM tvhome_terminal WHERE id=?",-1,&s,NULL)==SQLITE_OK){
  sqlite3_bind_text(s,1,terminal,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW)matches=tvhome_target_matches(tv_get(o,"target"),terminal,tv_col(s,0));sqlite3_finalize(s);
 }if(!matches){json_object_put(o);return NULL;}return o;
}
static struct json_object *command_row(sqlite3_stmt *s)
{
 struct json_object *o=json_tokener_parse(tv_col(s,1));if(!o)o=json_object_new_object();
 string(o,"command_id",tv_col(s,0));const char *state=tv_col(s,2);if(!strcmp(state,"active")&&sqlite3_column_int64(s,4)<=tv_now())state="expired";
 string(o,"state",state);number(o,"issued_at_ms",sqlite3_column_int64(s,3));number(o,"expires_at_ms",sqlite3_column_int64(s,4));return o;
}
static struct json_object *command_read(sqlite3 *db,const char *id)
{
 sqlite3_stmt *s=NULL;struct json_object *o=NULL,*results=json_object_new_array();
 if(sqlite3_prepare_v2(db,"SELECT id,body,state,issued,expires FROM tvhome_command WHERE id=?",-1,&s,NULL)==SQLITE_OK){
  sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW)o=command_row(s);sqlite3_finalize(s);
 }if(!o){json_object_put(results);return NULL;}
 if(sqlite3_prepare_v2(db,"SELECT r.terminal_id,r.delivery,r.application,r.detail,r.updated,t.last_seen_ms FROM tvhome_command_result r LEFT JOIN tvhome_terminal t ON t.id=r.terminal_id WHERE command_id=? ORDER BY r.terminal_id",-1,&s,NULL)==SQLITE_OK){
  sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);
  while(sqlite3_step(s)==SQLITE_ROW){struct json_object *r=json_object_new_object();string(r,"terminal_id",tv_col(s,0));string(r,"delivery",tv_col(s,1));string(r,"application",tv_col(s,2));string(r,"detail",tv_col(s,3));number(r,"updated_at_ms",sqlite3_column_int64(s,4));if(!strcmp(tv_col(s,1),"pending")&&sqlite3_column_int64(s,5)<tv_now()-180000)string(r,"reason","offline");json_object_array_add(results,r);}sqlite3_finalize(s);
 }json_object_object_add(o,"results",results);return o;
}
struct json_object *tvhome_commands_get(const char *id,struct tvhome_err *e)
{
 sqlite3 *db=NULL;sqlite3_stmt *s=NULL;struct json_object *o;if(tvhome_db_open(&db,e))return NULL;
 if(id&&*id){o=command_read(db,id);sqlite3_close(db);return o?o:tvhome_error(e,404,"resource_not_found","command_id","Command not found");}
 o=json_object_new_object();struct json_object *a=json_object_new_array();
 if(sqlite3_prepare_v2(db,"SELECT id FROM tvhome_command ORDER BY issued DESC LIMIT 100",-1,&s,NULL)==SQLITE_OK){while(sqlite3_step(s)==SQLITE_ROW)json_object_array_add(a,command_read(db,tv_col(s,0)));sqlite3_finalize(s);}
 json_object_object_add(o,"commands",a);sqlite3_close(db);return o;
}
struct json_object *tvhome_command_create(struct json_object *body,struct tvhome_err *e)
{
 sqlite3 *db=NULL;struct json_object *members,*o;const char *type=tv_str(body,"type"),*kind=tv_str(tv_get(body,"payload"),"kind");
 int64_t expires=tv_num(body,"expires_at_ms"),now=tv_now();char id[48]="cmd-",time[32],end[32];unsigned char entropy[16];
 if((strcmp(type,"emergency")&&strcmp(type,"refresh"))||expires<=now||expires>now+86400000)
  return tvhome_error(e,400,"invalid_parameter","expires_at_ms","Command requires a finite expiry within 24 hours");
 if(!strcmp(type,"emergency")&&((strcmp(kind,"text")&&strcmp(kind,"image")&&strcmp(kind,"video"))||
   (!strcmp(kind,"text")?(!*tv_str(tv_get(body,"payload"),"text")||strlen(tv_str(tv_get(body,"payload"),"text"))>4000):!*tv_str(tv_get(body,"payload"),"asset_id"))))
  return tvhome_error(e,400,"invalid_parameter","payload","Emergency requires bounded text or an image/video asset");
 if(RAND_bytes(entropy,sizeof(entropy))!=1)return tvhome_error(e,503,"service_not_ready","","Random source unavailable");
 for(int i=0;i<16;i++)snprintf(id+4+i*2,3,"%02x",entropy[i]);
 if(tvhome_db_open(&db,e))return NULL;if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);
 if(tvhome_assets_validate(db,body,e)){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
 members=tvhome_target_members(db,tv_get(body,"target"),e);if(!members){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
 if(!json_object_array_length(members)){json_object_put(members);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,400,"no_targets","target","No terminal matches the explicit target");}
 snprintf(time,sizeof(time),"%lld",(long long)now);snprintf(end,sizeof(end),"%lld",(long long)expires);
 o=json_object_new_object();string(o,"type",type);json_object_object_add(o,"target",copy(tv_get(body,"target")));json_object_object_add(o,"payload",copy(tv_get(body,"payload")));
 int rc=tv_run(db,"INSERT INTO tvhome_command VALUES(?,?,'active',?,?)",4,id,tv_json(o),time,end);json_object_put(o);
 for(size_t i=0;!rc&&i<json_object_array_length(members);i++)rc=tv_run(db,"INSERT INTO tvhome_command_result(command_id,terminal_id) VALUES(?,?)",2,id,json_object_get_string(json_object_array_get_idx(members,i)));
 json_object_put(members);if(rc||tv_changed(db)||tv_run(db,"COMMIT",0))return tv_db_error(db,e);o=command_read(db,id);sqlite3_close(db);return o;
}
struct json_object *tvhome_command_stop(const char *id,struct tvhome_err *e)
{
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);
 if(!tv_exists(db,"SELECT 1 FROM tvhome_command WHERE id=?",id)){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,404,"resource_not_found","command_id","Command not found");}
 if(tv_run(db,"UPDATE tvhome_command SET state='stopped' WHERE id=?",1,id)||tv_changed(db)||tv_run(db,"COMMIT",0))return tv_db_error(db,e);
 struct json_object *o=command_read(db,id);sqlite3_close(db);return o;
}
struct json_object *tvhome_commands_for_terminal(sqlite3 *db,const char *terminal)
{
 sqlite3_stmt *s=NULL;struct json_object *a=json_object_new_array();
 if(sqlite3_prepare_v2(db,"SELECT c.id,c.body,c.state,c.issued,c.expires FROM tvhome_command c JOIN tvhome_command_result r ON r.command_id=c.id WHERE r.terminal_id=? ORDER BY c.issued DESC LIMIT 200",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,terminal,-1,SQLITE_TRANSIENT);while(sqlite3_step(s)==SQLITE_ROW)json_object_array_add(a,command_row(s));sqlite3_finalize(s);}return a;
}
struct json_object *tvhome_command_ack(const char *token,const char *id,struct json_object *body,struct tvhome_err *e)
{
 sqlite3 *db=NULL;char terminal[96],when[32];const char *stage=tv_str(body,"stage");
 if(strcmp(stage,"received")&&strcmp(stage,"displayed")&&strcmp(stage,"applied")&&strcmp(stage,"stopped")&&strcmp(stage,"failed"))return tvhome_error(e,400,"invalid_parameter","stage","Unknown acknowledgement stage");
 if(tvhome_db_open(&db,e))return NULL;if(tvhome_authorize(db,token,terminal,sizeof(terminal),e)){sqlite3_close(db);return NULL;}
 if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);sqlite3_stmt *s=NULL;int found=0,active=0,refresh=0;
 if(sqlite3_prepare_v2(db,"SELECT c.state,c.expires,c.body FROM tvhome_command_result r JOIN tvhome_command c ON c.id=r.command_id WHERE r.command_id=? AND r.terminal_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,terminal,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW){found=1;active=!strcmp(tv_col(s,0),"active")&&sqlite3_column_int64(s,1)>tv_now();struct json_object *command=json_tokener_parse(tv_col(s,2));refresh=!strcmp(tv_str(command,"type"),"refresh");json_object_put(command);}sqlite3_finalize(s);}
 if(!found||(!active&&(!strcmp(stage,"displayed")||!strcmp(stage,"applied")))||(!strcmp(stage,"applied")&&!refresh)||(!strcmp(stage,"displayed")&&refresh)){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,found?409:404,found?"command_inactive":"resource_not_found","command_id","Command is not available for this acknowledgement");}
 snprintf(when,sizeof(when),"%lld",(long long)tv_now());
 /* Receiving a retried command never downgrades an application receipt. */
 int rc=tv_run(db,"UPDATE tvhome_command_result SET delivery='received',application=CASE WHEN ?='received' THEN application WHEN application='stopped' THEN application ELSE ? END,updated=? WHERE command_id=? AND terminal_id=?",5,stage,stage,when,id,terminal);
 if(rc||tv_run(db,"COMMIT",0))return tv_db_error(db,e);sqlite3_close(db);struct json_object *o=json_object_new_object();string(o,"command_id",id);string(o,"stage",stage);return o;
}
static struct json_object *redact(struct json_object *o,int depth)
{
 if(depth>8)return json_object_new_string("[depth limit]");
 if(json_object_is_type(o,json_type_object)){struct json_object *r=json_object_new_object();json_object_object_foreach(o,k,v){
  char key[128];snprintf(key,sizeof(key),"%s",k);for(char *p=key;*p;p++)if(*p>='A'&&*p<='Z')*p+=32;
  if(strstr(key,"token")||strstr(key,"password")||strstr(key,"pin")||strstr(key,"authorization")||strstr(key,"secret"))continue;
  json_object_object_add(r,k,redact(v,depth+1));}return r;}
 if(json_object_is_type(o,json_type_array)){struct json_object *a=json_object_new_array();for(size_t i=0;i<json_object_array_length(o);i++)json_object_array_add(a,redact(json_object_array_get_idx(o,i),depth+1));return a;}
 if(json_object_is_type(o,json_type_string)){const char *s=json_object_get_string(o);if(strstr(s,"Bearer ")||strstr(s,"tv_sess_")||strstr(s,"password=")||strstr(s,"token="))return json_object_new_string("[redacted]");
  /* Playback URLs, including userinfo and query credentials, are not diagnostics. */
  if(strstr(s,"://"))return json_object_new_string("[URL omitted]");}
 return copy(o);
}
struct json_object *tvhome_event_create(const char *token,struct json_object *body,struct tvhome_err *e)
{
 static const char *kinds[]={"crash","anr","playerError","playerFallback","lowSpec","install","upgrade","log","login","configApplied","noticeDisplayed",NULL};
 const char *kind=tv_str(body,"kind"),*client=tv_str(body,"client_event_id");int allowed=0;for(int i=0;kinds[i];i++)if(!strcmp(kind,kinds[i]))allowed=1;
 if(!allowed||!*client||strlen(client)>96||strlen(tv_json(body))>4096)return tvhome_error(e,400,"invalid_parameter","event","Known kind, unique client_event_id, and at most 4096 bytes required");
 sqlite3 *db=NULL;char terminal[96],when[32];if(tvhome_db_open(&db,e))return NULL;if(tvhome_authorize(db,token,terminal,sizeof(terminal),e)){sqlite3_close(db);return NULL;}
 struct json_object *clean=redact(body,0);json_object_object_del(clean,"terminal_id");snprintf(when,sizeof(when),"%lld",(long long)tv_now());
 if(tv_run(db,"BEGIN IMMEDIATE",0)){json_object_put(clean);return tv_db_error(db,e);}
 int rc=tv_run(db,"INSERT OR IGNORE INTO tvhome_event(terminal_id,client_id,kind,time_ms,body) VALUES(?,?,?,?,?)",5,terminal,client,kind,when,tv_json(clean));json_object_put(clean);
 if(rc||tv_run(db,"DELETE FROM tvhome_event WHERE time_ms<(CAST(strftime('%s','now') AS INTEGER)-2592000)*1000 OR id IN (SELECT id FROM tvhome_event ORDER BY id DESC LIMIT -1 OFFSET 10000)",0)||tv_run(db,"COMMIT",0))return tv_db_error(db,e);
 sqlite3_close(db);struct json_object *o=json_object_new_object();string(o,"client_event_id",client);json_object_object_add(o,"accepted",json_object_new_boolean(1));return o;
}
struct json_object *tvhome_events_get(struct json_object *params,struct tvhome_err *e)
{
 sqlite3 *db=NULL;sqlite3_stmt *s=NULL;if(tvhome_db_open(&db,e))return NULL;
 int limit=(int)tv_num(params,"limit");if(limit<=0||limit>300)limit=100;int64_t before=tv_num(params,"before_ms");if(before<=0)before=INT64_MAX;int64_t before_id=tv_num(params,"before_id");
 struct json_object *o=json_object_new_object(),*a=json_object_new_array();
 if(sqlite3_prepare_v2(db,"SELECT id,terminal_id,kind,time_ms,body FROM tvhome_event WHERE (?='' OR terminal_id=?) AND (?='' OR kind=?) AND (time_ms<? OR (time_ms=? AND id<?)) ORDER BY time_ms DESC,id DESC LIMIT ?",-1,&s,NULL)!=SQLITE_OK){json_object_put(a);json_object_put(o);return tv_db_error(db,e);}
 sqlite3_bind_text(s,1,tv_str(params,"terminal_id"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,tv_str(params,"terminal_id"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,3,tv_str(params,"kind"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,4,tv_str(params,"kind"),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(s,5,before);sqlite3_bind_int64(s,6,before);sqlite3_bind_int64(s,7,before_id);sqlite3_bind_int(s,8,limit);
 int64_t oldest=0,last_id=0;while(sqlite3_step(s)==SQLITE_ROW){struct json_object *r=json_tokener_parse(tv_col(s,4));last_id=sqlite3_column_int64(s,0);number(r,"id",last_id);string(r,"terminal_id",tv_col(s,1));string(r,"kind",tv_col(s,2));oldest=sqlite3_column_int64(s,3);number(r,"time_ms",oldest);json_object_array_add(a,r);}sqlite3_finalize(s);sqlite3_close(db);
 json_object_object_add(o,"events",a);number(o,"next_before_ms",oldest);number(o,"next_before_id",last_id);number(o,"retention_days",30);return o;
}
