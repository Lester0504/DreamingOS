// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt IPTV: management catalogue and revocable preview sessions.
 * Owns only iptv_* tables. No parallel network or account authority. */
#include "iptv.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef IPTV_DB_PATH
#define IPTV_DB_PATH "/etc/dreamingwrt/config.db"
#endif
#define IPTV_TOKEN_TTL 300

const char *iptv_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o,key,&v) &&
        json_object_is_type(v,json_type_string) ? json_object_get_string(v) : "";
}
int iptv_integer(struct json_object *o, const char *key, int fallback)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o,key,&v) &&
        (json_object_is_type(v,json_type_int)||json_object_is_type(v,json_type_boolean))
        ? json_object_get_int(v) : fallback;
}
struct json_object *iptv_fail(struct iptv_error *e, int s, const char *c, const char *f)
{
    if(e) { e->status=s; snprintf(e->code,sizeof(e->code),"%s",c);
        snprintf(e->field,sizeof(e->field),"%s",f?f:""); }
    return NULL;
}
int iptv_id(char *out, size_t size)
{
    unsigned char b[24]; size_t done=0; int fd;
    if(size<49) return -1;
    fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC); if(fd<0) return -1;
    while(done<sizeof(b)) { ssize_t n=read(fd,b+done,sizeof(b)-done);
        if(n<=0) {close(fd);return -1;} done+=(size_t)n; }
    close(fd);
    for(size_t i=0;i<sizeof(b);i++) snprintf(out+i*2,3,"%02x",b[i]);
    return 0;
}
int iptv_valid_id(const char *s)
{
    if(!s||!*s||strlen(s)>96) return 0;
    for(;*s;s++) if(!isalnum((unsigned char)*s)&&*s!='-'&&*s!='_') return 0;
    return 1;
}
static void bind(sqlite3_stmt *s,int n,const char *v)
{ sqlite3_bind_text(s,n,v?v:"",-1,SQLITE_TRANSIENT); }
static struct json_object *copy(struct json_object *o)
{ return o?json_tokener_parse(json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN)):NULL; }
static struct json_object *ok(void)
{ return json_tokener_parse("{\"persisted\":true,\"applied\":true}"); }
sqlite3 *iptv_db(struct iptv_error *e)
{
    sqlite3 *db=NULL;
    if(sqlite3_open_v2(IPTV_DB_PATH,&db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,NULL)!=SQLITE_OK)
        goto bad;
    sqlite3_busy_timeout(db,1000);
    static pthread_mutex_t schema_lock=PTHREAD_MUTEX_INITIALIZER;
    static int initialized=0;
    pthread_mutex_lock(&schema_lock);
    if(initialized){pthread_mutex_unlock(&schema_lock);return db;}
    const char *schema=
        "CREATE TABLE IF NOT EXISTS iptv_record(kind TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(kind,id));"
        "CREATE TABLE IF NOT EXISTS iptv_meta(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL);"
        "INSERT OR IGNORE INTO iptv_meta VALUES(1,1);"
        "CREATE TABLE IF NOT EXISTS iptv_preview(token TEXT PRIMARY KEY,actor TEXT NOT NULL,channel TEXT NOT NULL,expires INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS iptv_view_lease(ticket TEXT PRIMARY KEY,principal TEXT NOT NULL,origin TEXT NOT NULL,parent_token TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS iptv_recording_lease(ticket TEXT PRIMARY KEY,recording TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS iptv_deferred_lease(ticket TEXT PRIMARY KEY);"
        "CREATE TABLE IF NOT EXISTS iptv_subject_state(principal TEXT NOT NULL,provider TEXT NOT NULL,kind TEXT NOT NULL,resource_id TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(principal,provider,kind,resource_id));"
        "CREATE TABLE IF NOT EXISTS iptv_subject_request(principal TEXT NOT NULL,provider TEXT NOT NULL,idempotency_key TEXT NOT NULL,request TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(principal,provider,idempotency_key));"
        "CREATE INDEX IF NOT EXISTS iptv_preview_channel ON iptv_preview(channel,expires);"
        "INSERT OR IGNORE INTO iptv_record VALUES('settings','main',1,'{\"id\":\"main\",\"revision\":1,\"enabled\":false,\"cache_path\":\"\",\"max_streams\":1,\"segment_seconds\":2,\"window_segments\":6,\"first_segment_seconds\":20,\"idle_seconds\":30}');";
    if(sqlite3_exec(db,schema,NULL,NULL,NULL)==SQLITE_OK){initialized=1;pthread_mutex_unlock(&schema_lock);return db;}
    pthread_mutex_unlock(&schema_lock);
bad:
    if(db)sqlite3_close(db);
    iptv_fail(e,503,"config_db_unavailable","");return NULL;
}
struct json_object *iptv_record(sqlite3 *db,const char *kind,const char *id)
{
    sqlite3_stmt *s=NULL;struct json_object *o=NULL;
    if(sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind=?1 AND id=?2",-1,&s,NULL)==SQLITE_OK){
        bind(s,1,kind);bind(s,2,id);
        if(sqlite3_step(s)==SQLITE_ROW)o=json_tokener_parse((const char*)sqlite3_column_text(s,0));
    }
    sqlite3_finalize(s);return o;
}
struct json_object *iptv_settings(sqlite3 *db)
{
    struct json_object *settings=iptv_record(db,"settings","main"),*value=NULL;
    if(settings&&!json_object_object_get_ex(settings,"cache_limit_mb",&value))
        json_object_object_add(settings,"cache_limit_mb",json_object_new_int(128));
    if(settings){
        if(!json_object_object_get_ex(settings,"max_transcodes",&value))json_object_object_add(settings,"max_transcodes",json_object_new_int(1));
        if(!json_object_object_get_ex(settings,"recording_auto_cleanup",&value))json_object_object_add(settings,"recording_auto_cleanup",json_object_new_boolean(0));
        const char *keys[]={"recording_path","recording_limit_mb","recording_segment_seconds","recording_retention_days",NULL};
        for(int i=0;keys[i];i++)if(!json_object_object_get_ex(settings,keys[i],&value))json_object_object_add(settings,keys[i],i==0?json_object_new_string(""):json_object_new_int(i==1?1024:i==2?300:7));
    }
    return settings;
}
int iptv_revision(sqlite3 *db)
{
    sqlite3_stmt *s=NULL;int r=0;
    if(sqlite3_prepare_v2(db,"SELECT revision FROM iptv_meta WHERE id=1",-1,&s,NULL)==SQLITE_OK&&sqlite3_step(s)==SQLITE_ROW)r=sqlite3_column_int(s,0);
    sqlite3_finalize(s);return r;
}
int iptv_channel_enabled(sqlite3 *db,struct json_object *channel)
{
    if(!channel||!iptv_integer(channel,"enabled",0))return 0;
    const char *category=iptv_string(channel,"category_id");
    if(!*category)return 1;
    struct json_object *c=iptv_record(db,"categories",category);
    int yes=c&&iptv_integer(c,"enabled",0);if(c)json_object_put(c);return yes;
}
struct json_object *iptv_list(sqlite3 *db,const char *kind,struct iptv_error *e)
{
    sqlite3_stmt *s=NULL;struct json_object *o=json_object_new_object(),*a=json_object_new_array();
    if(sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind=?1 ORDER BY json_extract(body,'$.position'),id",-1,&s,NULL)!=SQLITE_OK){
        json_object_put(o);json_object_put(a);return iptv_fail(e,503,"config_db_unavailable","");}
    bind(s,1,kind);int rc;
    while((rc=sqlite3_step(s))==SQLITE_ROW){struct json_object *v=json_tokener_parse((const char*)sqlite3_column_text(s,0));
        if(v){if(!strcmp(kind,"channels"))json_object_object_add(v,"runtime",iptv_runtime_state(iptv_string(v,"id")));json_object_array_add(a,v);}}
    sqlite3_finalize(s);
    if(rc!=SQLITE_DONE){json_object_put(o);json_object_put(a);return iptv_fail(e,503,"config_db_unavailable","");}
    json_object_object_add(o,"items",a);json_object_object_add(o,"revision",json_object_new_int(iptv_revision(db)));
    json_object_object_add(o,"server_time",json_object_new_int64(time(NULL)));return o;
}
static int allowed_keys(struct json_object *o,const char *keys,struct iptv_error *e)
{
    if(!o||!json_object_is_type(o,json_type_object)){iptv_fail(e,400,"invalid_parameter","body");return 0;}
    json_object_object_foreach(o,k,v){(void)v;char needle[100];snprintf(needle,sizeof(needle),"|%s|",k);
        if(strlen(k)>90||!strstr(keys,needle)){iptv_fail(e,400,"unknown_field",k);return 0;}}
    return 1;
}
static int range(struct json_object *o,const char *key,int min,int max,struct iptv_error *e)
{
    struct json_object *v=NULL;
    if(!json_object_object_get_ex(o,key,&v)||!json_object_is_type(v,json_type_int)||json_object_get_int64(v)<min||json_object_get_int64(v)>max){iptv_fail(e,400,"invalid_parameter",key);return 0;}return 1;
}
static int boolean(struct json_object *o,const char *key,struct iptv_error *e)
{
    struct json_object *v=NULL;
    if(!json_object_object_get_ex(o,key,&v)||!json_object_is_type(v,json_type_boolean)){iptv_fail(e,400,"invalid_parameter",key);return 0;}return 1;
}
int iptv_validate(sqlite3 *db,const char *kind,struct json_object *o,struct iptv_error *e)
{
    if(!boolean(o,"enabled",e))return 0;
    if(!strcmp(kind,"settings")){
        struct json_object *auto_cleanup=NULL;
        if(json_object_object_get_ex(o,"recording_auto_cleanup",&auto_cleanup)&&!boolean(o,"recording_auto_cleanup",e))return 0;
        const char *p=iptv_string(o,"cache_path");
        if(*p&&(p[0]!='/'||strstr(p,"/../")||strlen(p)>350)) {iptv_fail(e,400,"invalid_parameter","cache_path");return 0;}
        struct json_object *limit=NULL;if(json_object_object_get_ex(o,"cache_limit_mb",&limit)&&!range(o,"cache_limit_mb",128,8192,e))return 0;
        if(json_object_object_get_ex(o,"max_transcodes",&limit)&&!range(o,"max_transcodes",0,4,e))return 0;
        if(*iptv_string(o,"recording_path")&&(iptv_string(o,"recording_path")[0]!='/'||strlen(iptv_string(o,"recording_path"))>350)){iptv_fail(e,400,"invalid_parameter","recording_path");return 0;}
        const char *recording_keys[]={"recording_limit_mb","recording_segment_seconds","recording_retention_days",NULL};
        for(int i=0;recording_keys[i];i++){struct json_object *v=NULL;if(json_object_object_get_ex(o,recording_keys[i],&v)&&!range(o,recording_keys[i],i==0?128:i==1?10:1,i==0?1048576:i==1?3600:365,e))return 0;}
        return range(o,"max_streams",1,4,e)&&range(o,"segment_seconds",1,10,e)&&range(o,"window_segments",3,12,e)&&range(o,"first_segment_seconds",5,60,e)&&range(o,"idle_seconds",10,120,e);
    }
    if(!*iptv_string(o,"name")||strlen(iptv_string(o,"name"))>128||strpbrk(iptv_string(o,"name"),"\r\n")){iptv_fail(e,400,"invalid_parameter","name");return 0;}
    if(!range(o,"position",0,100000,e))return 0;
    if(!strcmp(kind,"categories"))return 1;
    if(!strcmp(kind,"viewers")){
        if(!iptv_principal_exists(db,iptv_string(o,"principal_id"))){iptv_fail(e,400,"media_principal_not_found","principal_id");return 0;}
        struct json_object *ids=NULL,*expires=NULL;
        if(!boolean(o,"all_categories",e)||!json_object_object_get_ex(o,"category_ids",&ids)||!json_object_is_type(ids,json_type_array)||!json_object_object_get_ex(o,"expires_at",&expires)||!json_object_is_type(expires,json_type_int)||json_object_get_int64(expires)<0){iptv_fail(e,400,"invalid_parameter","category_ids");return 0;}
        for(size_t i=0;i<json_object_array_length(ids);i++){
            struct json_object *id=json_object_array_get_idx(ids,i);
            if(!json_object_is_type(id,json_type_string)){iptv_fail(e,400,"invalid_parameter","category_ids");return 0;}
            const char *v=json_object_get_string(id);struct json_object *category=*v?iptv_record(db,"categories",v):NULL;
            if(*v&&!category){iptv_fail(e,400,"category_not_found","category_ids");return 0;}
            if(category)json_object_put(category);
        }return 1;
    }
    if(!strcmp(kind,"epg-sources")){
        const char *url=iptv_string(o,"url");
        if((strncmp(url,"http://",7)&&strncmp(url,"https://",8))||strlen(url)>2048||strpbrk(url,"\r\n\t ")||strchr(url,'@')||strchr(url,'?')){iptv_fail(e,400,"invalid_parameter","url");return 0;}
        return range(o,"interval_hours",1,168,e);
    }
    const char *mode=iptv_string(o,"mode"),*cat=iptv_string(o,"category_id");
    if(strcmp(mode,"managed")&&strcmp(mode,"external")){iptv_fail(e,400,"invalid_parameter","mode");return 0;}
    char source[2304];
    if(iptv_source_url(db,o,source,sizeof(source),0,e))return 0;
    if(iptv_access_validate(o,e))return 0;
    if(!iptv_encoder_validate(o,e))return 0;
    struct json_object *rate=NULL;
    if(json_object_object_get_ex(o,"video_bitrate_kbps",&rate)&&!range(o,"video_bitrate_kbps",128,20000,e))return 0;
    if(json_object_object_get_ex(o,"audio_bitrate_kbps",&rate)&&!range(o,"audio_bitrate_kbps",64,512,e))return 0;
    struct json_object *clear_access=NULL;
    if(json_object_object_get_ex(o,"clear_access_url",&clear_access)&&!boolean(o,"clear_access_url",e))return 0;
    if(*cat){struct json_object *c=iptv_record(db,"categories",cat);if(!c){iptv_fail(e,409,"category_not_found","category_id");return 0;}json_object_put(c);}
    const char *epg_source=iptv_string(o,"epg_source_id");
    if(*epg_source){struct json_object *source=iptv_record(db,"epg-sources",epg_source);if(!source){iptv_fail(e,409,"epg_source_not_found","epg_source_id");return 0;}json_object_put(source);}
    const char *text_keys[]={"epg_id","logo_url",NULL};
    for(int i=0;text_keys[i];i++){struct json_object *v=NULL;
        if(json_object_object_get_ex(o,text_keys[i],&v)&&(!json_object_is_type(v,json_type_string)||strlen(iptv_string(o,text_keys[i]))>2048||strpbrk(iptv_string(o,text_keys[i]),"\r\n"))){iptv_fail(e,400,"invalid_parameter",text_keys[i]);return 0;}}
    const char *logo=iptv_string(o,"logo_url");
    if(*logo&&strncmp(logo,"http://",7)&&strncmp(logo,"https://",8)){iptv_fail(e,400,"invalid_parameter","logo_url");return 0;}
    const char *container=iptv_string(o,"hls_container");
    if(*container&&strcmp(container,"mpegts")&&strcmp(container,"fmp4")){iptv_fail(e,400,"invalid_parameter","hls_container");return 0;}
    struct json_object *retention=NULL;if(json_object_object_get_ex(o,"timeshift_minutes",&retention)&&!range(o,"timeshift_minutes",0,60,e))return 0;
    if(!strcmp(mode,"external")&&iptv_integer(o,"timeshift_minutes",0)){iptv_fail(e,400,"external_source_not_hosted","timeshift_minutes");return 0;}
    struct json_object *option=NULL;
    if(json_object_object_get_ex(o,"program_id",&option)&&!range(o,"program_id",0,65535,e))return 0;
    const char *transport=iptv_string(o,"rtsp_transport"),*agent=iptv_string(o,"user_agent");
    if(*transport&&strcmp(transport,"tcp")&&strcmp(transport,"udp")){iptv_fail(e,400,"invalid_parameter","rtsp_transport");return 0;}
    if(strlen(agent)>256||strpbrk(agent,"\r\n")){iptv_fail(e,400,"invalid_parameter","user_agent");return 0;}
    if(*agent&&strncmp(iptv_string(o,"source_url"),"http://",7)&&strncmp(iptv_string(o,"source_url"),"https://",8)){iptv_fail(e,400,"http_option_required","user_agent");return 0;}
    return range(o,"number",0,99999,e);
}
struct json_object *iptv_save(sqlite3 *db,const char *kind,const char *id,struct json_object *body,int create,struct iptv_error *e)
{
    const char *keys=!strcmp(kind,"settings")?"|if_revision||enabled||cache_path||max_streams||max_transcodes||segment_seconds||window_segments||first_segment_seconds||idle_seconds||cache_limit_mb||recording_path||recording_limit_mb||recording_segment_seconds||recording_retention_days||recording_auto_cleanup|":
        !strcmp(kind,"viewers")?"|if_revision||name||enabled||position||principal_id||all_categories||category_ids||expires_at|":!strcmp(kind,"epg-sources")?"|if_revision||name||enabled||position||url||interval_hours|":!strcmp(kind,"categories")?"|if_revision||name||enabled||position|":"|if_revision||name||enabled||position||number||mode||source_url||category_id||epg_id||epg_source_id||logo_url||hls_container||input_id||timeshift_minutes||program_id||rtsp_transport||user_agent||access_url||clear_access_url||video_encoder||audio_encoder||video_bitrate_kbps||audio_bitrate_kbps|";
    if(!allowed_keys(body,keys,e))return NULL;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return iptv_fail(e,409,"config_busy","");
    struct json_object *old=iptv_record(db,kind,id),*o=NULL,*result=NULL;
    sqlite3_stmt *s=NULL;
    if(create&&old){iptv_fail(e,409,"already_exists","id");goto out;}
    if(!create&&!old){iptv_fail(e,404,"resource_not_found","id");goto out;}
    if(old&&iptv_integer(body,"if_revision",-1)!=iptv_integer(old,"revision",0)){iptv_fail(e,409,"revision_conflict","if_revision");goto out;}
    o=old?copy(old):json_tokener_parse("{\"enabled\":true,\"position\":0,\"number\":0,\"category_id\":\"\",\"mode\":\"managed\"}");
    json_object_object_foreach(body,k,v){if(strcmp(k,"if_revision"))json_object_object_add(o,k,json_object_get(v));}
    json_object_object_add(o,"id",json_object_new_string(id));
    json_object_object_add(o,"revision",json_object_new_int(old?iptv_integer(old,"revision",0)+1:1));
    if(!iptv_validate(db,kind,o,e))goto out;
    if(!strcmp(kind,"settings")&&
       (strcmp(iptv_string(o,"cache_path"),iptv_string(old,"cache_path"))||
        strcmp(iptv_string(o,"recording_path"),iptv_string(old,"recording_path"))||
        (iptv_integer(o,"enabled",0)&&!iptv_integer(old,"enabled",0)))){
        struct json_object *preflight=iptv_storage_preflight(o),*checks=NULL;
        int valid=iptv_integer(preflight,"valid",0);json_object_object_get_ex(preflight,"checks",&checks);
        if(!valid)for(size_t i=0;i<json_object_array_length(checks);i++){
            struct json_object *check=json_object_array_get_idx(checks,i);
            if(!iptv_integer(check,"valid",0)){iptv_fail(e,409,iptv_string(check,"error"),iptv_string(check,"field"));break;}
        }
        json_object_put(preflight);if(!valid)goto out;
    }
    if(!strcmp(kind,"viewers")){
        if(sqlite3_prepare_v2(db,"SELECT 1 FROM iptv_record WHERE kind='viewers' AND id<>?1 AND json_extract(body,'$.principal_id')=?2",-1,&s,NULL)!=SQLITE_OK)goto sql_error;
        bind(s,1,id);bind(s,2,iptv_string(o,"principal_id"));int exists=sqlite3_step(s)==SQLITE_ROW;sqlite3_finalize(s);s=NULL;
        if(exists){iptv_fail(e,409,"principal_already_granted","principal_id");goto out;}
    }
    if(!strcmp(kind,"channels")&&iptv_access_save(db,o,old,e))goto out;
    if(sqlite3_prepare_v2(db,"INSERT INTO iptv_record VALUES(?1,?2,?3,?4) ON CONFLICT(kind,id) DO UPDATE SET revision=excluded.revision,body=excluded.body",-1,&s,NULL)!=SQLITE_OK)goto sql_error;
    bind(s,1,kind);bind(s,2,id);sqlite3_bind_int(s,3,iptv_integer(o,"revision",0));bind(s,4,json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN));
    if(sqlite3_step(s)!=SQLITE_DONE)goto sql_error;
    if(sqlite3_exec(db,"UPDATE iptv_meta SET revision=revision+1 WHERE id=1;COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto sql_error;
    result=ok();json_object_object_add(result,"record",copy(o));
    struct json_object *pending=iptv_runtime_pending();
    json_object_object_add(result,"applied",json_object_new_boolean(json_object_array_length(pending)==0));
    json_object_object_add(result,"pending_channels",pending);
    /* Existing streams retain their snapshot. New sessions use the new record;
     * withdrawing a channel is enforced on every media request. */
    json_object_object_add(result,"runtime_policy",json_object_new_string("existing_streams_keep_snapshot"));goto out;
sql_error:iptv_fail(e,503,"config_db_unavailable","");
out:
    sqlite3_finalize(s);if(!sqlite3_get_autocommit(db))sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(old)json_object_put(old);
    if(o)json_object_put(o);
    return result;
}
struct json_object *iptv_remove(sqlite3 *db,const char *kind,const char *id,struct json_object *body,struct iptv_error *e)
{
    if(!allowed_keys(body,"|if_revision|",e))return NULL;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return iptv_fail(e,409,"config_busy","");
    struct json_object *o=iptv_record(db,kind,id),*result=NULL;sqlite3_stmt *s=NULL;
    if(!o){iptv_fail(e,404,"resource_not_found","id");goto out;}
    if(iptv_integer(body,"if_revision",-1)!=iptv_integer(o,"revision",0)){iptv_fail(e,409,"revision_conflict","if_revision");goto out;}
    if(!strcmp(kind,"categories")||!strcmp(kind,"epg-sources")){
        const char *references=!strcmp(kind,"categories")?"SELECT 1 FROM iptv_record WHERE kind='channels' AND json_extract(body,'$.category_id')=?1":"SELECT 1 FROM iptv_record WHERE kind='channels' AND json_extract(body,'$.epg_source_id')=?1";
        if(sqlite3_prepare_v2(db,references,-1,&s,NULL)!=SQLITE_OK)goto bad;
        bind(s,1,id);if(sqlite3_step(s)==SQLITE_ROW){iptv_fail(e,409,!strcmp(kind,"categories")?"category_in_use":"epg_source_in_use","id");goto out;}sqlite3_finalize(s);s=NULL;
    }
    if(!strcmp(kind,"channels")&&iptv_access_remove(db,o,e))goto out;
    if(sqlite3_prepare_v2(db,"DELETE FROM iptv_record WHERE kind=?1 AND id=?2",-1,&s,NULL)!=SQLITE_OK)goto bad;
    bind(s,1,kind);bind(s,2,id);if(sqlite3_step(s)!=SQLITE_DONE)goto bad;
    if(sqlite3_exec(db,"UPDATE iptv_meta SET revision=revision+1 WHERE id=1;COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto bad;
    if(!strcmp(kind,"channels"))iptv_snapshot_remove(db,id);result=ok();goto out;
bad:iptv_fail(e,503,"config_db_unavailable","");
out:sqlite3_finalize(s);if(o)json_object_put(o);if(!sqlite3_get_autocommit(db))sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);return result;
}
struct json_object *iptv_preview_issue(sqlite3 *db,const char *id,const char *actor,struct iptv_error *e)
{
    struct json_object *c=iptv_record(db,"channels",id),*cfg=iptv_settings(db),*r=NULL;
    if(!iptv_channel_enabled(db,c)){iptv_fail(e,403,"channel_unavailable","channel_id");goto out;}
    if(!cfg||!iptv_integer(cfg,"enabled",0)){iptv_fail(e,409,"module_disabled","enabled");goto out;}
    if(!strcmp(iptv_string(c,"mode"),"external")){
        char source[2304];if(iptv_source_url(db,c,source,sizeof(source),1,e))goto out;
        r=json_object_new_object();json_object_object_add(r,"mode",json_object_new_string("external"));
        json_object_object_add(r,"url",json_object_new_string(source));goto out;
    }
    /* Persist the lease before starting media, so an admitted stream always has
     * a holder. Stream start failure revokes this lease below. */
    char token[49],url[256];sqlite3_stmt *s=NULL;
    if(iptv_id(token,sizeof(token))||sqlite3_prepare_v2(db,"INSERT INTO iptv_preview VALUES(?1,?2,?3,?4)",-1,&s,NULL)!=SQLITE_OK){iptv_fail(e,503,"session_create_failed","");goto out;}
    bind(s,1,token);bind(s,2,actor);bind(s,3,id);sqlite3_bind_int64(s,4,time(NULL)+IPTV_TOKEN_TTL);
    int rc=sqlite3_step(s);sqlite3_finalize(s);
    if(rc!=SQLITE_DONE){iptv_fail(e,503,"session_create_failed","");goto out;}
    r=iptv_runtime_start(c,cfg,0,e);
    if(!r){if(sqlite3_prepare_v2(db,"DELETE FROM iptv_preview WHERE token=?1",-1,&s,NULL)==SQLITE_OK){bind(s,1,token);sqlite3_step(s);}sqlite3_finalize(s);goto out;}
    snprintf(url,sizeof(url),"/api/v1/iptv/media/%s/%s/index.m3u8",token,id);
    json_object_object_add(r,"session_id",json_object_new_string(token));
    json_object_object_add(r,"url",json_object_new_string(url));
    json_object_object_add(r,"expires_at",json_object_new_int64(time(NULL)+IPTV_TOKEN_TTL));
    json_object_object_add(r,"mode",json_object_new_string("managed"));
out:if(c)json_object_put(c);if(cfg)json_object_put(cfg);return r;
}
struct json_object *iptv_media_authorize(const char *token,const char *id,struct iptv_error *e)
{
    sqlite3 *db=iptv_db(e);if(!db)return NULL;
    sqlite3_stmt *s=NULL;struct json_object *c=NULL,*cfg=NULL;int yes=0,recording=0;
    if(strlen(token)!=48||!iptv_valid_id(token)||!iptv_valid_id(id)){iptv_fail(e,401,"media_session_expired","");goto out;}
    if(sqlite3_prepare_v2(db,"SELECT EXISTS(SELECT 1 FROM iptv_recording_lease WHERE ticket=?1) FROM iptv_preview WHERE token=?1 AND channel=?2 AND expires>?3",-1,&s,NULL)!=SQLITE_OK){iptv_fail(e,503,"config_db_unavailable","");goto out;}
    bind(s,1,token);bind(s,2,id);sqlite3_bind_int64(s,3,time(NULL));yes=sqlite3_step(s)==SQLITE_ROW;if(yes)recording=sqlite3_column_int(s,0);
    sqlite3_finalize(s);s=NULL;
    if(!yes){iptv_fail(e,401,"media_session_expired","");goto out;}
    c=iptv_record(db,"channels",id);cfg=iptv_settings(db);
    /* Historical files remain manageable after their channel is deleted.
     * This exception is limited to a management recording ticket: a viewer
     * still needs a current enabled channel and category on every byte read. */
    if(!c&&sqlite3_prepare_v2(db,"SELECT r.body FROM iptv_recording_lease l JOIN iptv_record r ON r.kind='recordings' AND r.id=l.recording WHERE l.ticket=? AND NOT EXISTS(SELECT 1 FROM iptv_view_lease v WHERE v.ticket=l.ticket)",-1,&s,NULL)==SQLITE_OK){
        bind(s,1,token);
        if(sqlite3_step(s)==SQLITE_ROW){c=json_tokener_parse((const char*)sqlite3_column_text(s,0));if(c){json_object_object_add(c,"enabled",json_object_new_boolean(1));json_object_object_add(c,"category_id",json_object_new_string(""));}}
        sqlite3_finalize(s);s=NULL;
    }
    if(!iptv_channel_enabled(db,c)||!cfg||!iptv_integer(cfg,"enabled",0)){if(c)json_object_put(c);c=NULL;iptv_fail(e,403,"channel_unavailable","");goto out;}
    if(!iptv_view_ticket_valid(db,token,c)){json_object_put(c);c=NULL;iptv_fail(e,403,"watching_not_permitted","");goto out;}
    if(!recording)iptv_runtime_hold(id);
out:sqlite3_finalize(s);if(cfg)json_object_put(cfg);sqlite3_close(db);return c;
}
int iptv_media_read(const char *token,const char *id,const char *name,char **data,size_t *length,const char **type,struct iptv_error *e)
{
    sqlite3 *db=iptv_db(e);if(!db)return -1;sqlite3_stmt *stmt=NULL;int recording=0,deferred=0;
    if(sqlite3_prepare_v2(db,"SELECT 1 FROM iptv_recording_lease WHERE ticket=?",-1,&stmt,NULL)==SQLITE_OK){bind(stmt,1,token);recording=sqlite3_step(stmt)==SQLITE_ROW;}
    sqlite3_finalize(stmt);stmt=NULL;
    if(sqlite3_prepare_v2(db,"SELECT 1 FROM iptv_deferred_lease WHERE ticket=?",-1,&stmt,NULL)==SQLITE_OK){bind(stmt,1,token);deferred=sqlite3_step(stmt)==SQLITE_ROW;}
    sqlite3_finalize(stmt);sqlite3_close(db);
    if(recording){iptv_fail(e,403,"recording_ticket_scope","");return -1;}
    struct json_object *c=iptv_media_authorize(token,id,e);if(!c)return -1;
    if(deferred&&!strcmp(name,"index.m3u8")){
        sqlite3 *config_db=iptv_db(e);if(!config_db){json_object_put(c);return -1;}
        struct json_object *cfg=iptv_settings(config_db);sqlite3_close(config_db);
        struct json_object *started=iptv_runtime_start(c,cfg,0,e);if(cfg)json_object_put(cfg);
        if(!started){json_object_put(c);return -1;}json_object_put(started);
        config_db=iptv_db(e);if(!config_db){json_object_put(c);return -1;}
        stmt=NULL;if(sqlite3_prepare_v2(config_db,"DELETE FROM iptv_deferred_lease WHERE ticket=?",-1,&stmt,NULL)==SQLITE_OK){bind(stmt,1,token);sqlite3_step(stmt);}sqlite3_finalize(stmt);sqlite3_close(config_db);
    }
    json_object_put(c);return iptv_runtime_read(id,name,data,length,type,e);
}
static int recording_fd(const char *token,const char *channel,const char *name,struct iptv_error *e)
{
    struct json_object *allowed=iptv_media_authorize(token,channel,e);if(!allowed)return -1;json_object_put(allowed);
    sqlite3 *db=iptv_db(e);if(!db)return -1;
    sqlite3_stmt *stmt=NULL;int permitted=0,fd=-1;
    if(sqlite3_prepare_v2(db,"SELECT 1 FROM iptv_recording_lease WHERE ticket=? AND 'record-'||recording||'.mp4'=?",-1,&stmt,NULL)==SQLITE_OK){bind(stmt,1,token);bind(stmt,2,name);permitted=sqlite3_step(stmt)==SQLITE_ROW;}
    sqlite3_finalize(stmt);
    if(permitted)fd=iptv_recording_open(db,channel,name,e);else iptv_fail(e,403,"recording_ticket_scope","");
    sqlite3_close(db);return fd;
}
struct json_object *iptv_recording_info(const char *token,const char *channel,const char *name,struct iptv_error *e)
{
    int fd=recording_fd(token,channel,name,e);if(fd<0)return NULL;struct stat st;
    int rc=fstat(fd,&st);close(fd);if(rc)return iptv_fail(e,410,"recording_file_missing","");
    struct json_object *info=json_object_new_object();json_object_object_add(info,"size",json_object_new_int64(st.st_size));return info;
}
int iptv_recording_read(const char *token,const char *channel,const char *name,int64_t offset,size_t maximum,char **data,size_t *length,struct iptv_error *e)
{
    *data=NULL;*length=0;
    if(offset<0||!maximum||maximum>1024*1024){iptv_fail(e,400,"invalid_parameter","range");return -1;}
    int fd=recording_fd(token,channel,name,e);if(fd<0)return -1;
    char *bytes=malloc(maximum);if(!bytes){close(fd);iptv_fail(e,503,"out_of_memory","");return -1;}
    ssize_t n;do{n=pread(fd,bytes,maximum,(off_t)offset);}while(n<0&&errno==EINTR);close(fd);
    if(n<=0){free(bytes);iptv_fail(e,416,"range_not_satisfiable","");return -1;}
    *data=bytes;*length=(size_t)n;return 0;
}
struct json_object *iptv_request(const char *method,const char *path,struct json_object *body,const char *actor,struct iptv_error *e)
{
    static pthread_mutex_t mutations=PTHREAD_MUTEX_INITIALIZER;
    int writing=strcmp(method,"GET")!=0;
    if(writing)pthread_mutex_lock(&mutations);
    memset(e,0,sizeof(*e));struct json_object *r=NULL;sqlite3 *db=iptv_db(e);if(!db){if(writing)pthread_mutex_unlock(&mutations);return NULL;}
    char kind[32]="",id[97]="",action[32]="",extra=0;
    int parts=sscanf(path,"%31[^/]/%96[^/]/%31[^/]%c",kind,id,action,&extra);
    if(parts<1||parts>3){iptv_fail(e,404,"resource_not_found","");goto out;}
    if(strcmp(method,"GET")&&(!actor||!*actor)){iptv_fail(e,403,"forbidden","");goto out;}
    if(!strncmp(method,"WEB_VIEW",8)||!strncmp(method,"TV_VIEW",7)){r=iptv_view_request(db,method[0]=='T'?"tv":"web",actor,path,body,strstr(method,"_POST")!=NULL,e);goto out;}
    if((!strcmp(path,"channels/batch")||!strcmp(path,"viewers/batch"))&&!strcmp(method,"POST")){r=iptv_catalog_request(db,method,path,body,e);goto out;}
    if(!strcmp(kind,"recordings")||!strcmp(kind,"captures")){r=iptv_recordings_request(db,method,path,body,actor,e);goto out;}
    if(!strcmp(kind,"scans")||!strcmp(kind,"jobs")||!strcmp(kind,"snapshots")||!strcmp(path,"imports/fetch")){r=iptv_jobs_request(db,method,path,body,e);goto out;}
    if(!strcmp(kind,"encoders")){
        if((parts==1&&!strcmp(method,"GET"))||(parts==3&&!strcmp(action,"probe")&&(!strcmp(method,"POST")||!strcmp(method,"DELETE")))){
            struct json_object *cfg=iptv_settings(db);r=iptv_encoder_request(method,id,cfg,e);if(cfg)json_object_put(cfg);
        }else iptv_fail(e,405,"method_not_allowed","");
        goto out;
    }
    if(!strcmp(kind,"probes")){
        if(parts==1&&!strcmp(method,"POST")){
            if(!allowed_keys(body,"|name||enabled||position||number||mode||source_url||category_id||epg_id||epg_source_id||logo_url||hls_container||input_id||timeshift_minutes||program_id||rtsp_transport||user_agent||access_url||clear_access_url||video_encoder||audio_encoder||video_bitrate_kbps||audio_bitrate_kbps|",e))goto out;
            struct json_object *draft=copy(body);char serial[49],operation[64];
            if(!iptv_validate(db,"channels",draft,e)){json_object_put(draft);goto out;}
            if(iptv_id(serial,sizeof(serial))){json_object_put(draft);iptv_fail(e,503,"entropy_unavailable","");goto out;}
            snprintf(operation,sizeof(operation),"draft-%s",serial);
            json_object_object_add(draft,"id",json_object_new_string(operation));
            r=iptv_runtime_probe(draft,e);json_object_put(draft);
            if(r){json_object_object_add(r,"operation_id",json_object_new_string(operation));json_object_object_add(r,"persisted",json_object_new_boolean(0));}
        }else if(parts==2&&!strncmp(id,"draft-",6)&&iptv_valid_id(id)){
            if(!strcmp(method,"GET"))r=iptv_runtime_state(id);
            else if(!strcmp(method,"DELETE"))r=iptv_runtime_stop(id,e);
            else iptv_fail(e,405,"method_not_allowed","");
        }else iptv_fail(e,404,"resource_not_found","");
        goto out;
    }
    if(!strcmp(path,"inputs")&&!strcmp(method,"GET")){r=iptv_inputs(db,e);goto out;}
    if(!strcmp(kind,"principals")&&!strcmp(method,"GET")&&parts==1){r=iptv_principals(db,e);goto out;}
    if(!strcmp(kind,"epg")||(!strcmp(kind,"epg-sources")&&parts==3)){r=iptv_epg_request(db,method,path,body,e);goto out;}
    if(!strcmp(kind,"imports")||!strcmp(kind,"exports")||!strcmp(kind,"playlist")){r=iptv_catalog_request(db,method,path,body,e);goto out;}
    if(!strcmp(kind,"capabilities")&&!strcmp(method,"GET")&&parts==1){r=iptv_runtime_capabilities();goto out;}
    if(!strcmp(kind,"overview")&&!strcmp(method,"GET")&&parts==1){
        r=json_object_new_object();json_object_object_add(r,"provider_id",json_object_new_string("iptv.local"));
        json_object_object_add(r,"channels",iptv_list(db,"channels",e));json_object_object_add(r,"categories",iptv_list(db,"categories",e));
        json_object_object_add(r,"capabilities",iptv_runtime_capabilities());json_object_object_add(r,"settings",iptv_settings(db));
        json_object_object_add(r,"epg_sources",iptv_list(db,"epg-sources",e));json_object_object_add(r,"viewers",iptv_list(db,"viewers",e));
        json_object_object_add(r,"epg_jobs",iptv_epg_request(db,"GET","epg/jobs",NULL,e));goto out;}
    if(!strcmp(path,"settings/preflight")&&!strcmp(method,"POST")){
        struct json_object *cfg=iptv_settings(db);
        if(!cfg){iptv_fail(e,503,"config_db_unavailable","");goto out;}
        if(iptv_integer(body,"if_revision",-1)!=iptv_integer(cfg,"revision",0)){json_object_put(cfg);iptv_fail(e,409,"revision_conflict","if_revision");goto out;}
        if(body&&json_object_is_type(body,json_type_object)){json_object_object_foreach(body,k,v){if(strcmp(k,"if_revision"))json_object_object_add(cfg,k,json_object_get(v));}}
        if(iptv_validate(db,"settings",cfg,e))r=iptv_storage_preflight(cfg);json_object_put(cfg);goto out;
    }
    if(!strcmp(kind,"settings")&&parts==1){
        if(!strcmp(method,"GET"))r=iptv_settings(db);
        else if(!strcmp(method,"PUT"))r=iptv_save(db,kind,"main",body,0,e);
        else iptv_fail(e,405,"method_not_allowed","");
        goto out;}
    if(!strcmp(kind,"sessions")&&((parts==1&&!strcmp(method,"GET"))||(parts==3&&!strcmp(action,"revoke")&&!strcmp(method,"POST")))){r=iptv_view_sessions(db,method,path,body,e);goto out;}
    if(!strcmp(kind,"sessions")&&parts==3&&iptv_valid_id(id)&&!strcmp(action,"renew")&&!strcmp(method,"POST")){
        sqlite3_stmt *stmt=NULL;
        if(sqlite3_prepare_v2(db,"UPDATE iptv_preview SET expires=?1 WHERE token=?2 AND actor=?3 AND expires>?4",-1,&stmt,NULL)!=SQLITE_OK){iptv_fail(e,503,"config_db_unavailable","");goto out;}
        sqlite3_bind_int64(stmt,1,time(NULL)+IPTV_TOKEN_TTL);bind(stmt,2,id);bind(stmt,3,actor);sqlite3_bind_int64(stmt,4,time(NULL));
        int rc=sqlite3_step(stmt);int changed=sqlite3_changes(db);sqlite3_finalize(stmt);
        if(rc==SQLITE_DONE&&changed){r=ok();json_object_object_add(r,"expires_at",json_object_new_int64(time(NULL)+IPTV_TOKEN_TTL));}
        else iptv_fail(e,401,"media_session_expired","");
        goto out;
    }
    if(!strcmp(kind,"sessions")&&parts==2&&iptv_valid_id(id)&&!strcmp(method,"DELETE")){
        sqlite3_stmt *s=NULL;
        if(sqlite3_prepare_v2(db,"DELETE FROM iptv_preview WHERE token=?1 AND actor=?2",-1,&s,NULL)!=SQLITE_OK){iptv_fail(e,503,"config_db_unavailable","");goto out;}
        bind(s,1,id);bind(s,2,actor);int rc=sqlite3_step(s);sqlite3_finalize(s);
        if(rc==SQLITE_DONE)r=ok();else iptv_fail(e,503,"config_db_unavailable","");goto out;}
    if(strcmp(kind,"channels")&&strcmp(kind,"categories")&&strcmp(kind,"epg-sources")&&strcmp(kind,"viewers")){iptv_fail(e,404,"resource_not_found","");goto out;}
    if(parts==1){
        if(!strcmp(method,"GET"))r=iptv_list(db,kind,e);
        else if(!strcmp(method,"POST")){char generated[49];if(iptv_id(generated,sizeof(generated)))iptv_fail(e,503,"entropy_unavailable","");else r=iptv_save(db,kind,generated,body,1,e);}
        else iptv_fail(e,405,"method_not_allowed","");
        goto out;
    }
    if(!iptv_valid_id(id)){iptv_fail(e,400,"invalid_parameter","id");goto out;}
    if(parts==2){
        if(!strcmp(method,"GET")){r=iptv_record(db,kind,id);if(!r)iptv_fail(e,404,"resource_not_found","id");else if(!strcmp(kind,"channels"))json_object_object_add(r,"runtime",iptv_runtime_state(id));}
        else if(!strcmp(method,"PUT"))r=iptv_save(db,kind,id,body,0,e);
        else if(!strcmp(method,"DELETE"))r=iptv_remove(db,kind,id,body,e);
        else iptv_fail(e,405,"method_not_allowed","");
        goto out;
    }
    if(!strcmp(kind,"channels")&&parts==3&&!strcmp(action,"timeshift")&&!strcmp(method,"GET")){r=iptv_runtime_window(id,e);goto out;}
    if(!strcmp(kind,"channels")&&!strcmp(method,"POST")){
        if(!strcmp(action,"preview"))r=iptv_preview_issue(db,id,actor,e);
        else if(!strcmp(action,"timeshift")){
            struct json_object *window=iptv_runtime_window(id,e);char *playlist=NULL;size_t length=0;
            int from=iptv_integer(body,"start",0);
            if(window&&from>0&&!iptv_window_playlist(window,from,0,&playlist,&length,e)){
                r=iptv_preview_issue(db,id,actor,e);if(r){char url[300];snprintf(url,sizeof(url),"/api/v1/iptv/media/%s/%s/at%d.m3u8",iptv_string(r,"session_id"),id,from);json_object_object_add(r,"url",json_object_new_string(url));}
            }else if(!e->status)iptv_fail(e,400,"invalid_parameter","start");
            free(playlist);if(window)json_object_put(window);
        }
        else if(!strcmp(action,"start")){
            struct json_object *c=iptv_record(db,kind,id),*cfg=iptv_settings(db);
            if(!c)iptv_fail(e,404,"resource_not_found","id");
            else if(!iptv_integer(cfg,"enabled",0)||!iptv_channel_enabled(db,c))iptv_fail(e,409,"channel_unavailable","");
            else if(!strcmp(iptv_string(c,"mode"),"external"))iptv_fail(e,409,"external_source_not_hosted","");
            else r=iptv_runtime_start(c,cfg,1,e);
            if(c)json_object_put(c);if(cfg)json_object_put(cfg);
        }
        else if(!strcmp(action,"probe")){
            struct json_object *c=iptv_record(db,kind,id);if(!c)iptv_fail(e,404,"resource_not_found","id");
            else {r=iptv_runtime_probe(c,e);json_object_put(c);}
        }else if(!strcmp(action,"stop")){if(!iptv_integer(body,"confirm",0))iptv_fail(e,409,"requires_confirmation","confirm");else r=iptv_runtime_stop(id,e);}
        else iptv_fail(e,404,"resource_not_found","");
    }else iptv_fail(e,405,"method_not_allowed","");
out:sqlite3_close(db);if(writing)pthread_mutex_unlock(&mutations);if(!r&&!e->status)iptv_fail(e,500,"internal_error","");return r;
}
