// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_community.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
static struct json_object *get(struct json_object *o,const char *key){struct json_object *v=NULL;if(o)json_object_object_get_ex(o,key,&v);return v;}
static const char *str(struct json_object *o,const char *key){const char *s=json_object_get_string(get(o,key));return s?s:"";}
static void txt(struct json_object *o,const char *key,const char *v){json_object_object_add(o,key,json_object_new_string(v?v:""));}
static struct json_object *error(int *status,int n,const char *code,const char *message){*status=n;struct json_object *o=json_object_new_object(),*e=json_object_new_object();json_object_object_add(o,"ok",json_object_new_boolean(0));txt(e,"code",code);txt(e,"message",message);json_object_object_add(o,"error",e);return o;}
static struct json_object *ok(struct json_object *data,int *status){*status=200;struct json_object *o=json_object_new_object();json_object_object_add(o,"ok",json_object_new_boolean(1));json_object_object_add(o,"data",data);return o;}
static int random_hex(char out[65]){unsigned char bytes[32];if(RAND_bytes(bytes,32)!=1)return -1;for(int i=0;i<32;++i)snprintf(out+i*2,3,"%02x",bytes[i]);return 0;}
static void digest(const char *value,char out[65]){unsigned char bytes[32];SHA256((const unsigned char*)value,strlen(value),bytes);for(int i=0;i<32;++i)snprintf(out+i*2,3,"%02x",bytes[i]);}
static const char *column(sqlite3_stmt *q,int i){const unsigned char *v=sqlite3_column_text(q,i);return v?(const char*)v:"";}
int community_config_load(struct support_config *config){int rc=support_config_load_file(config,COMMUNITY_CONFIG_PATH);snprintf(config->db_path,sizeof(config->db_path),"%s",COMMUNITY_DB_PATH);snprintf(config->proof_domain,sizeof(config->proof_domain),"dreamingos-community-v1");return rc;}
int community_db_open(const char *path,sqlite3 **db){*db=NULL;if(sqlite3_open_v2(path,db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,NULL)!=SQLITE_OK)goto bad;chmod(path,0600);sqlite3_busy_timeout(*db,5000);if(sqlite3_exec(*db,"PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS community_sessions(subject TEXT PRIMARY KEY,token TEXT NOT NULL DEFAULT '',pair_id TEXT NOT NULL DEFAULT '',secret TEXT NOT NULL DEFAULT '',request_id TEXT NOT NULL DEFAULT '',pair_data TEXT NOT NULL DEFAULT '{}');CREATE TABLE IF NOT EXISTS community_tickets(hash TEXT PRIMARY KEY,subject TEXT NOT NULL,expires INTEGER NOT NULL);",NULL,NULL,NULL)!=SQLITE_OK)goto bad;return 0;bad:if(*db)sqlite3_close(*db);*db=NULL;return -1;}
static int local_state(sqlite3 *db,const char *subject,char token[65],char pair[65],char secret[65],char rid[65],struct json_object **pair_data){sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(db,"SELECT token,pair_id,secret,request_id,pair_data FROM community_sessions WHERE subject=?",-1,&q,NULL)!=SQLITE_OK)return -1;sqlite3_bind_text(q,1,subject,-1,SQLITE_TRANSIENT);int found=sqlite3_step(q)==SQLITE_ROW;if(found){snprintf(token,65,"%s",column(q,0));snprintf(pair,65,"%s",column(q,1));snprintf(secret,65,"%s",column(q,2));snprintf(rid,65,"%s",column(q,3));if(pair_data)*pair_data=json_tokener_parse(column(q,4));}sqlite3_finalize(q);return found;}
static struct json_object *remote(sqlite3 *db,const struct support_config *config,const char *subject,const char *method,const char *path,struct json_object *query,struct json_object *params,int *status){char token[65]="",pair[65]="",secret[65]="",rid[65]="";if(local_state(db,subject,token,pair,secret,rid,NULL)<0)return error(status,503,"storage_unavailable","社区会话存储不可用");struct json_object *body=json_object_new_object();txt(body,"session_token",token);json_object_object_add(body,"params",params?json_object_get(params):json_object_new_object());struct json_object *r=support_remote(config,subject,method,path,query,body,status);json_object_put(body);return r;}
struct json_object *community_handle(sqlite3 *db,const struct support_config *config,const char *subject,int writable,const char *method,const char *path,struct json_object *query,struct json_object *body,int *status){
 if(!strcmp(path,"capabilities")&&!strcmp(method,"GET")){
  if(!config->url[0]){struct json_object *d=json_object_new_object();json_object_object_add(d,"configured",json_object_new_boolean(0));txt(d,"reason","社区服务尚未配置");json_object_object_add(d,"auth_methods",json_object_new_array());return ok(d,status);}
  struct json_object *r=remote(db,config,subject,"GET",path,query,NULL,status);if(*status==200){struct json_object *d=get(r,"data");json_object_object_add(d,"can_login",json_object_new_boolean(writable));txt(d,"local_subject",subject);}return r;
 }
 if(strcmp(method,"GET")&&!writable)return error(status,403,"permission_denied","当前设备账号仅可查看");
 if(!config->url[0])return error(status,503,"community_unconfigured","社区服务尚未配置");
 if(!strcmp(path,"session")&&!strcmp(method,"POST")){
  char token[65]="",pair[65]="",secret[65]="",rid[65]="";struct json_object *saved=NULL;int found=local_state(db,subject,token,pair,secret,rid,&saved);if(found<0)return error(status,503,"storage_unavailable","无法保存授权请求");
  if(saved&&json_object_get_int64(get(saved,"expires_at"))>time(NULL)){return ok(saved,status);}if(saved)json_object_put(saved);
  // Persist the secret and request ID before calling the cloud: a timeout must
  // retry the same pair, not silently create an unrelated authorization request.
  if(!secret[0]||pair[0]){if(random_hex(secret)||random_hex(rid))return error(status,503,"random_unavailable","无法创建授权请求");sqlite3_stmt *q=NULL;
   if(sqlite3_prepare_v2(db,"INSERT INTO community_sessions(subject,secret,request_id) VALUES(?,?,?) ON CONFLICT(subject) DO UPDATE SET secret=excluded.secret,request_id=excluded.request_id,pair_id='',pair_data='{}'",-1,&q,NULL)!=SQLITE_OK)return error(status,503,"storage_unavailable","无法保存授权请求");sqlite3_bind_text(q,1,subject,-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,2,secret,-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,3,rid,-1,SQLITE_TRANSIENT);int rc=sqlite3_step(q);sqlite3_finalize(q);if(rc!=SQLITE_DONE)return error(status,503,"storage_unavailable","无法保存授权请求");}
  struct json_object *params=json_object_new_object();txt(params,"request_id",rid);txt(params,"secret",secret);struct json_object *r=remote(db,config,subject,"POST","pair",NULL,params,status);json_object_put(params);
  if(*status==200){struct json_object *d=get(r,"data");sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(db,"UPDATE community_sessions SET pair_id=?,pair_data=? WHERE subject=?",-1,&q,NULL)!=SQLITE_OK){json_object_put(r);return error(status,503,"storage_unavailable","授权响应保存失败，请重试");}sqlite3_bind_text(q,1,str(d,"pair_id"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,2,json_object_to_json_string_ext(d,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,3,subject,-1,SQLITE_TRANSIENT);int rc=sqlite3_step(q);sqlite3_finalize(q);if(rc!=SQLITE_DONE){json_object_put(r);return error(status,503,"storage_unavailable","授权响应保存失败，请重试");}}
  return r;
 }
 if(!strcmp(path,"session/complete")&&!strcmp(method,"POST")){
  char token[65]="",pair[65]="",secret[65]="",rid[65]="";if(local_state(db,subject,token,pair,secret,rid,NULL)<=0||!pair[0])return error(status,409,"authorization_required","请先发起社区登录");
  struct json_object *p=json_object_new_object();txt(p,"pair_id",pair);txt(p,"secret",secret);struct json_object *r=remote(db,config,subject,"POST","claim",NULL,p,status);json_object_put(p);
  if(*status==200&&!json_object_get_boolean(get(get(r,"data"),"pending"))){struct json_object *d=get(r,"data");const char *value=str(d,"session_token");sqlite3_stmt *q=NULL;if(strlen(value)!=64||sqlite3_prepare_v2(db,"UPDATE community_sessions SET token=? WHERE subject=?",-1,&q,NULL)!=SQLITE_OK){json_object_put(r);return error(status,503,"storage_unavailable","无法保存社区会话，请重试");}sqlite3_bind_text(q,1,value,-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,2,subject,-1,SQLITE_TRANSIENT);int rc=sqlite3_step(q);sqlite3_finalize(q);json_object_object_del(d,"session_token");if(rc!=SQLITE_DONE){json_object_put(r);return error(status,503,"storage_unavailable","无法保存社区会话，请重试");}}
  return r;
 }
 if(!strcmp(path,"session")&&!strcmp(method,"DELETE")){
  struct json_object *r=remote(db,config,subject,"POST","logout",NULL,NULL,status);if(*status==200||*status==401||*status==403){sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(db,"DELETE FROM community_sessions WHERE subject=?",-1,&q,NULL)==SQLITE_OK){sqlite3_bind_text(q,1,subject,-1,SQLITE_TRANSIENT);int rc=sqlite3_step(q);sqlite3_finalize(q);if(rc!=SQLITE_DONE){json_object_put(r);return error(status,503,"storage_unavailable","本地退出失败，请重试");}}else{json_object_put(r);return error(status,503,"storage_unavailable","本地退出失败，请重试");}json_object_put(r);struct json_object *d=json_object_new_object();json_object_object_add(d,"logged_out",json_object_new_boolean(1));return ok(d,status);}return r;
 }
 if(!strcmp(path,"connection-ticket")&&!strcmp(method,"POST")){
  struct json_object *r=remote(db,config,subject,"GET","session",NULL,NULL,status);if(*status!=200)return r;json_object_put(r);char ticket[65],hashed[65];if(random_hex(ticket))return error(status,503,"random_unavailable","无法创建连接");digest(ticket,hashed);sqlite3_stmt *q=NULL;sqlite3_exec(db,"DELETE FROM community_tickets WHERE expires<CAST(strftime('%s','now') AS INTEGER)",NULL,NULL,NULL);if(sqlite3_prepare_v2(db,"INSERT INTO community_tickets VALUES(?,?,?)",-1,&q,NULL)!=SQLITE_OK)return error(status,503,"storage_unavailable","无法创建连接");sqlite3_bind_text(q,1,hashed,-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,2,subject,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(q,3,time(NULL)+30);int rc=sqlite3_step(q);sqlite3_finalize(q);if(rc!=SQLITE_DONE)return error(status,503,"storage_unavailable","无法创建连接");struct json_object *d=json_object_new_object();txt(d,"ticket",ticket);json_object_object_add(d,"expires_in",json_object_new_int(30));return ok(d,status);
 }
 const char *reads[]={"session","profile","messages","members",NULL};const char *writes[]={"messages","attachments","read","moderation","whisper",NULL};int allowed=0;for(int i=0;reads[i];++i)if(!strcmp(method,"GET")&&!strcmp(path,reads[i]))allowed=1;for(int i=0;writes[i];++i)if(!strcmp(method,"POST")&&!strcmp(path,writes[i]))allowed=1;if(!strcmp(method,"GET")&&!strncmp(path,"attachments/att-",16))allowed=1;if(!strcmp(method,"PUT")&&!strcmp(path,"profile"))allowed=1;
 if(!allowed)return error(status,404,"not_found","社区接口不存在");return remote(db,config,subject,!strcmp(method,"PUT")?"POST":method,path,query,body,status);
}
#ifndef COMMUNITY_TEST
#include "api/webd_http_req.h"
#include "api/api_realtime_internal.h"
#include "api/api_request.h"
#include "jmx_app_perms.h"
#include "api/api_util.h"
#include "api/api_keys_internal.h"
#include "api/api_client_control_internal.h"
#include "webd_http.h"
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
void community_ws_session(int fd,const struct http_req *req,const char *device_id){
 struct support_config config;sqlite3 *db=NULL;char subject[65],ticket[80],hashed[65],accept[128],header[512],connection[65]="",after[32]="0";int status=200;struct json_object *r=NULL;
 if(!webd_identity_is_user(device_id)||support_subject(g_config_db,webd_identity_username(device_id),subject)||community_config_load(&config)||community_db_open(config.db_path,&db))goto unavailable;
 if(!req->websocket||!webd_query_get(req->query,"ticket",ticket,sizeof(ticket))||strlen(ticket)!=64||webd_ws_accept_key(req->ws_key,accept,sizeof(accept)))goto unauthorized;
 digest(ticket,hashed);sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(db,"DELETE FROM community_tickets WHERE hash=? AND subject=? AND expires>?",-1,&q,NULL)!=SQLITE_OK)goto unavailable;sqlite3_bind_text(q,1,hashed,-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,2,subject,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(q,3,time(NULL));int rc=sqlite3_step(q);sqlite3_finalize(q);if(rc!=SQLITE_DONE||sqlite3_changes(db)!=1)goto unauthorized;
 r=remote(db,&config,subject,"POST","connect",NULL,NULL,&status);if(status!=200){http_send_json(fd,status,r);goto cleanup;}snprintf(connection,sizeof(connection),"%s",str(get(r,"data"),"connection_id"));json_object_put(r);r=NULL;
 int n=snprintf(header,sizeof(header),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nCache-Control: no-store\r\n\r\n",accept);if(webd_write_all(fd,header,(size_t)n))goto cleanup;
 struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));time_t started=time(NULL),last_push=0,last_auth=0,last_ping=0;int ready=0;
 r=json_object_new_object();txt(r,"type","connected");txt(r,"connection_id",connection);webd_ws_send_json(fd,r);json_object_put(r);r=NULL;
 while(time(NULL)-started<600){time_t t=time(NULL);
  if(t-last_auth>=10){char *check=jmx_app_validate_token_mode(req->auth_token,NULL,0);int valid=check&&!strcmp(check,device_id);free(check);if(!valid){webd_ws_send_close(fd,4001,"device_session_expired");break;}last_auth=t;}
  if(ready&&t-last_push>=2){struct json_object *p=json_object_new_object();txt(p,"connection_id",connection);txt(p,"after",after);r=remote(db,&config,subject,"POST","events",NULL,p,&status);json_object_put(p);if(status!=200){txt(r,"type","connection.error");webd_ws_send_json(fd,r);json_object_put(r);r=NULL;webd_ws_send_close(fd,status==401||status==403?4003:1011,"community_unavailable");break;}struct json_object *d=get(r,"data"),*items=get(d,"items");txt(d,"type","events");if(webd_ws_send_json(fd,d)){json_object_put(r);r=NULL;break;}size_t len=json_object_array_length(items);if(len)snprintf(after,sizeof(after),"%s",str(json_object_array_get_idx(items,len-1),"cursor"));json_object_put(r);r=NULL;last_push=t;}
  if(t-last_ping>=15){if(webd_ws_send_frame(fd,9,""))break;last_ping=t;}
  struct pollfd pollfd={fd,POLLIN,0};int polled=poll(&pollfd,1,200);if(polled<0){if(errno==EINTR)continue;break;}if(polled&&(pollfd.revents&(POLLERR|POLLHUP|POLLNVAL)))break;if(polled&&(pollfd.revents&POLLIN)){char payload[2049];int opcode=0;int len=webd_ws_read_frame(fd,payload,sizeof(payload),&opcode);if(len<0||opcode==8)break;if(opcode==9){if(webd_ws_send_frame(fd,10,payload))break;}else if(opcode==1){struct json_object *msg=json_tokener_parse(payload);if(msg&&!strcmp(str(msg,"type"),"resume")){const char *cursor=str(msg,"after");if(strlen(cursor)<sizeof(after)&&strspn(cursor,"0123456789")==strlen(cursor)){snprintf(after,sizeof(after),"%s",cursor[0]?cursor:"0");ready=1;last_push=0;}}if(msg)json_object_put(msg);}}
 }
 webd_ws_send_close(fd,1001,"reconnect_required");goto cleanup;
unauthorized:r=error(&status,401,"connection_ticket_invalid","连接授权无效或已使用");http_send_json(fd,status,r);goto cleanup;
unavailable:r=error(&status,503,"community_unavailable","社区连接暂不可用");http_send_json(fd,status,r);
cleanup:if(r)json_object_put(r);if(db&&connection[0]){struct json_object *p=json_object_new_object();txt(p,"connection_id",connection);r=remote(db,&config,subject,"POST","disconnect",NULL,p,&status);json_object_put(p);if(r)json_object_put(r);}if(db)sqlite3_close(db);
}
#endif
