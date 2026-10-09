// SPDX-License-Identifier: GPL-2.0-or-later
/* Record the closed TS segments of the shared live stream. Recording failures
 * have their own state and never turn a healthy live stream into success for
 * the recorder. All paths below are generated beneath an explicit data mount. */
#define _GNU_SOURCE
#include "iptv.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t guard=PTHREAD_MUTEX_INITIALIZER;
static pthread_t worker;
static atomic_int stopping;
static int started;
static int remove_file(sqlite3 *db,struct json_object *r,int force,struct iptv_error *e);
static void str(struct json_object *o,const char *k,const char *v)
{json_object_object_add(o,k,json_object_new_string(v?v:""));}
static double number(struct json_object *o,const char *k)
{struct json_object *v=NULL;json_object_object_get_ex(o,k,&v);return json_object_get_double(v);}
static void num(struct json_object *o,const char *k,double v)
{json_object_object_add(o,k,json_object_new_double(v));}
static void bindstr(sqlite3_stmt *s,int n,const char *v)
{sqlite3_bind_text(s,n,v,-1,SQLITE_TRANSIENT);}
static int write_record(sqlite3 *db,const char *kind,struct json_object *record)
{
    int revision=iptv_integer(record,"revision",0)+1;sqlite3_stmt *s=NULL;
    json_object_object_add(record,"revision",json_object_new_int(revision));
    if(sqlite3_prepare_v2(db,"INSERT INTO iptv_record(kind,id,revision,body) VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET revision=excluded.revision,body=excluded.body",-1,&s,NULL)!=SQLITE_OK)return -1;
    bindstr(s,1,kind);bindstr(s,2,iptv_string(record,"id"));sqlite3_bind_int(s,3,revision);
    bindstr(s,4,json_object_to_json_string(record));int rc=sqlite3_step(s);sqlite3_finalize(s);return rc==SQLITE_DONE?0:-1;
}
static struct json_object *records(sqlite3 *db,const char *kind)
{
    struct json_object *items=json_object_new_array();sqlite3_stmt *s=NULL;
    if(sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind=? ORDER BY json_extract(body,'$.start') DESC,id LIMIT 10000",-1,&s,NULL)==SQLITE_OK){
        bindstr(s,1,kind);while(sqlite3_step(s)==SQLITE_ROW){struct json_object *o=json_tokener_parse((const char*)sqlite3_column_text(s,0));if(o)json_object_array_add(items,o);}
    }sqlite3_finalize(s);return items;
}
static int location_ok(struct json_object *r)
{
    struct stat st;
    const char *root=iptv_string(r,"root");
    return *root&&!lstat(root,&st)&&S_ISDIR(st.st_mode)&&
        st.st_dev==(dev_t)number(r,"device")&&st.st_ino==(ino_t)number(r,"inode");
}
static int has_space(struct json_object *r)
{struct statvfs fs;return !statvfs(iptv_string(r,"root"),&fs)&&fs.f_bavail*(unsigned long long)fs.f_frsize>=64ULL*1024*1024;}
static int path_for(struct json_object *r,const char *file,char *path,size_t size)
{
    return !iptv_valid_id(iptv_string(r,"id"))||
        snprintf(path,size,"%s/%s/%s",iptv_string(r,"root"),iptv_string(r,"id"),file)>=(int)size?-1:0;
}
static void finish(sqlite3 *db,struct json_object *capture,const char *error)
{
    const char *id=iptv_string(capture,"current_id");
    struct json_object *r=*id?iptv_record(db,"recordings",id):NULL;
    if(r){str(r,"state",number(r,"bytes")>0?"pending_archive":"failed");
        if(error&&*error)str(r,"continuity_error",error);
        write_record(db,"recordings",r);json_object_put(r);}
    str(capture,"current_id","");
}
static void capture_failure(sqlite3 *db,struct json_object *c,const char *error)
{
    finish(db,c,error);str(c,"state","error");str(c,"error",error);
    iptv_runtime_capture_release(iptv_string(c,"id"));write_record(db,"captures",c);
}
static unsigned long long usage(sqlite3 *db)
{
    unsigned long long bytes=0;sqlite3_stmt *s=NULL;
    if(sqlite3_prepare_v2(db,"SELECT COALESCE(sum(COALESCE(json_extract(body,'$.bytes'),0)+COALESCE(json_extract(body,'$.archive_bytes'),0)),0) FROM iptv_record WHERE kind='recordings'",-1,&s,NULL)==SQLITE_OK&&sqlite3_step(s)==SQLITE_ROW)bytes=(unsigned long long)sqlite3_column_int64(s,0);
    sqlite3_finalize(s);return bytes;
}
static struct json_object *begin_file(sqlite3 *db,struct json_object *c,struct json_object *segment)
{
    char id[49],dir[PATH_MAX];if(iptv_id(id,sizeof(id)))return NULL;
    if(snprintf(dir,sizeof(dir),"%s/%s",iptv_string(c,"root"),id)>=(int)sizeof(dir)||mkdir(dir,0700))return NULL;
    struct json_object *r=json_object_new_object();str(r,"id",id);str(r,"channel_id",iptv_string(c,"id"));
    const char *keys[]={"root","name","category_id",NULL};
    for(int i=0;keys[i];i++)str(r,keys[i],iptv_string(c,keys[i]));
    num(r,"device",number(c,"device"));num(r,"inode",number(c,"inode"));
    num(r,"start",number(segment,"start"));num(r,"end",number(segment,"start"));num(r,"bytes",0);
    str(r,"state","writing");json_object_object_add(r,"locked",json_object_new_boolean(0));
    if(write_record(db,"recordings",r)){json_object_put(r);rmdir(dir);return NULL;}
    str(c,"current_id",id);write_record(db,"captures",c);return r;
}
static void capture_tick(sqlite3 *db,struct json_object *c,struct json_object *cfg)
{
    const char *channel=iptv_string(c,"id");
    if(!strcmp(iptv_string(c,"state"),"stopping")){
        finish(db,c,"");str(c,"state","stopped");iptv_runtime_capture_release(channel);write_record(db,"captures",c);return;
    }
    if(strcmp(iptv_string(c,"state"),"recording"))return;
    if(!location_ok(c)||!has_space(c)){capture_failure(db,c,"recording_storage_unavailable");return;}
    struct json_object *runtime=iptv_runtime_state(channel);
    int ended=!strcmp(iptv_string(runtime,"state"),"error")||!strcmp(iptv_string(runtime,"state"),"stopped");
    if(ended){capture_failure(db,c,*iptv_string(runtime,"error")?iptv_string(runtime,"error"):"stream_stopped");json_object_put(runtime);return;}
    json_object_put(runtime);
    struct iptv_error e={0};struct json_object *window=iptv_runtime_capture_window(channel,&e),*segments=NULL;
    if(!window)return;
    json_object_object_get_ex(window,"segments",&segments);
    if(strcmp(iptv_string(c,"generation"),iptv_string(window,"generation"))){finish(db,c,"stream_generation_changed");str(c,"generation",iptv_string(window,"generation"));str(c,"last_segment","");}
    for(size_t i=0;i<json_object_array_length(segments);i++){
        struct json_object *segment=json_object_array_get_idx(segments,i);
        const char *name=iptv_string(segment,"name"),*last=iptv_string(c,"last_segment");
        if(*last&&strcmp(name,last)<=0)continue;
        unsigned long long limit=(unsigned long long)iptv_integer(cfg,"recording_limit_mb",1024)*1024*1024;
        if(usage(db)+(unsigned long long)number(segment,"bytes")>=limit){capture_failure(db,c,"recording_quota_exceeded");break;}
        struct json_object *r=*iptv_string(c,"current_id")?iptv_record(db,"recordings",iptv_string(c,"current_id")):NULL;
        if(r&&(iptv_integer(segment,"discontinuity",0)||number(segment,"start")-number(r,"end")>.25||number(segment,"start")<number(r,"end")-.25||number(r,"end")-number(r,"start")>=iptv_integer(cfg,"recording_segment_seconds",300))){
            finish(db,c,iptv_integer(segment,"discontinuity",0)?"source_discontinuity":"");json_object_put(r);r=NULL;
        }
        if(!r)r=begin_file(db,c,segment);
        if(!r){capture_failure(db,c,"recording_index_failed");break;}
        char *data=NULL,path[PATH_MAX];size_t length=0;const char *type=NULL;
        if(iptv_runtime_read(channel,name,&data,&length,&type,&e)||path_for(r,"source.ts",path,sizeof(path))){json_object_put(r);capture_failure(db,c,"recording_segment_missing");free(data);break;}
        int fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);size_t done=0;
        while(fd>=0&&done<length){ssize_t n=write(fd,data+done,length-done);if(n<0&&errno==EINTR)continue;if(n<=0)break;done+=(size_t)n;}
        int failed=fd<0||done!=length||(fd>=0&&fdatasync(fd));if(fd>=0)close(fd);free(data);
        if(failed){json_object_put(r);capture_failure(db,c,"recording_write_failed");break;}
        num(r,"bytes",number(r,"bytes")+length);num(r,"end",number(segment,"end"));str(c,"last_segment",name);
        if(write_record(db,"recordings",r)||write_record(db,"captures",c)){json_object_put(r);capture_failure(db,c,"recording_index_failed");break;}
        json_object_put(r);
    }
    json_object_put(window);
}
static void archive_tick(sqlite3 *db,struct json_object *r,struct json_object *cfg)
{
    const char *state=iptv_string(r,"state");int pending=!strcmp(state,"pending_archive"),archiving=!strcmp(state,"archiving"),verifying=!strcmp(state,"verifying");
    if(!pending&&!archiving&&!verifying)return;
    char task[97],source[PATH_MAX],output[PATH_MAX];snprintf(task,sizeof(task),"archive-%s",iptv_string(r,"id"));
    if(!location_ok(r)||!has_space(r)){iptv_runtime_stop(task,NULL);str(r,"state","archive_failed");str(r,"error","recording_storage_unavailable");write_record(db,"recordings",r);return;}
    if(path_for(r,"source.ts",source,sizeof(source))||path_for(r,"archive.mp4",output,sizeof(output)))return;
    struct iptv_error e={0};struct json_object *run=iptv_runtime_state(task);
    if(pending){
        json_object_put(run);
        if(usage(db)+(unsigned long long)number(r,"bytes")>=(unsigned long long)iptv_integer(cfg,"recording_limit_mb",1024)*1024*1024){str(r,"state","archive_failed");str(r,"error","recording_quota_exceeded");write_record(db,"recordings",r);return;}
        run=iptv_runtime_archive(task,source,output,0,cfg,&e);
        if(run){str(r,"state","archiving");write_record(db,"recordings",r);}
        else if(e.status!=429){str(r,"state","archive_failed");str(r,"error",e.code);write_record(db,"recordings",r);}
    }else if(!strcmp(iptv_string(run,"state"),"archive_complete")&&archiving){
        json_object_put(run);run=iptv_runtime_archive(task,source,output,1,cfg,&e);
        if(run){str(r,"state","verifying");write_record(db,"recordings",r);}
    }else if(!strcmp(iptv_string(run,"state"),"archive_verified")&&verifying){
        struct stat st;if(!lstat(output,&st)&&S_ISREG(st.st_mode)&&st.st_size>0){str(r,"state","ready");num(r,"archive_bytes",st.st_size);num(r,"archive_inode",st.st_ino);str(r,"error","");}
        else{str(r,"state","archive_failed");str(r,"error","archive_missing");}
        write_record(db,"recordings",r);iptv_runtime_stop(task,NULL);
    }else if(!strcmp(iptv_string(run,"state"),"error")||!strcmp(iptv_string(run,"state"),"stopped")){
        str(r,"state","archive_failed");str(r,"error",*iptv_string(run,"error")?iptv_string(run,"error"):"archive_interrupted");write_record(db,"recordings",r);iptv_runtime_stop(task,NULL);
    }
    if(run)json_object_put(run);
}
static void *record_worker(void *unused)
{
    (void)unused;
    while(!atomic_load(&stopping)){
        sleep(1);pthread_mutex_lock(&guard);struct iptv_error e={0};sqlite3 *db=iptv_db(&e);
        if(db){struct json_object *cfg=iptv_settings(db),*captures=records(db,"captures");
            for(size_t i=0;i<json_object_array_length(captures);i++)capture_tick(db,json_object_array_get_idx(captures,i),cfg);
            json_object_put(captures);struct json_object *files=records(db,"recordings");
            double cutoff=time(NULL)-iptv_integer(cfg,"recording_retention_days",7)*86400.0;
            for(size_t i=0;i<json_object_array_length(files);i++){
                struct json_object *r=json_object_array_get_idx(files,i);
                archive_tick(db,r,cfg);
                if(iptv_integer(cfg,"recording_auto_cleanup",0)&&number(r,"end")>0&&number(r,"end")<cutoff&&!iptv_integer(r,"locked",0)){
                    struct iptv_error cleanup_error={0};remove_file(db,r,0,&cleanup_error);
                }
            }
            json_object_put(files);json_object_put(cfg);sqlite3_close(db);}
        pthread_mutex_unlock(&guard);
    }return NULL;
}
int iptv_recordings_start(struct iptv_error *e)
{
    sqlite3 *db=iptv_db(e);if(!db)return -1;
    /* Persisted process IDs are never trusted after restart. Preserve files and
     * explicitly require a new start for interrupted continuous recording. */
    int rc=sqlite3_exec(db,"UPDATE iptv_record SET revision=revision+1,body=json_set(body,'$.revision',revision+1,'$.state','interrupted','$.error','service_restarted') WHERE (kind='captures' AND json_extract(body,'$.state') IN('recording','stopping')) OR (kind='recordings' AND json_extract(body,'$.state') IN('writing','archiving','verifying'))",NULL,NULL,NULL);
    sqlite3_close(db);if(rc!=SQLITE_OK)return -1;
    atomic_store(&stopping,0);if(pthread_create(&worker,NULL,record_worker,NULL))return -1;started=1;return 0;
}
void iptv_recordings_shutdown(void)
{if(started){atomic_store(&stopping,1);pthread_join(worker,NULL);started=0;}}

static int active_state(struct json_object *r)
{const char *s=iptv_string(r,"state");return !strcmp(s,"writing")||!strcmp(s,"pending_archive")||!strcmp(s,"archiving")||!strcmp(s,"verifying");}
static struct json_object *public_record(struct json_object *r)
{
    struct json_object *out=json_tokener_parse(json_object_to_json_string(r));
    const char *private[]={"root","device","inode","archive_inode","generation","last_segment","current_id",NULL};
    for(int i=0;private[i];i++)json_object_object_del(out,private[i]);
    json_object_object_add(out,"media_ready",json_object_new_boolean(!strcmp(iptv_string(r,"state"),"ready")));return out;
}
static int remove_file(sqlite3 *db,struct json_object *r,int force,struct iptv_error *e)
{
    if(active_state(r)){iptv_fail(e,409,"recording_busy","");return -1;}
    if(iptv_integer(r,"locked",0)&&!force){iptv_fail(e,409,"recording_locked","");return -1;}
    sqlite3_stmt *s=NULL;int playing=0;
    if(sqlite3_prepare_v2(db,"SELECT 1 FROM iptv_recording_lease WHERE recording=? AND ticket IN(SELECT token FROM iptv_preview WHERE expires>unixepoch())",-1,&s,NULL)==SQLITE_OK){bindstr(s,1,iptv_string(r,"id"));playing=sqlite3_step(s)==SQLITE_ROW;}
    sqlite3_finalize(s);if(playing){iptv_fail(e,409,"recording_in_use","");return -1;}
    if(!location_ok(r)){iptv_fail(e,409,"recording_storage_unavailable","");return -1;}
    char path[PATH_MAX];const char *files[]={"source.ts","archive.mp4",NULL};
    for(int i=0;files[i];i++)if(path_for(r,files[i],path,sizeof(path))||(unlink(path)&&errno!=ENOENT)){iptv_fail(e,500,"recording_delete_failed","");return -1;}
    if(path_for(r,"",path,sizeof(path))||rmdir(path)){iptv_fail(e,500,"recording_delete_failed","");return -1;}
    if(sqlite3_prepare_v2(db,"DELETE FROM iptv_record WHERE kind='recordings' AND id=?",-1,&s,NULL)!=SQLITE_OK)return -1;
    bindstr(s,1,iptv_string(r,"id"));int rc=sqlite3_step(s);sqlite3_finalize(s);return rc==SQLITE_DONE?0:-1;
}
static struct json_object *handle(sqlite3 *db,const char *method,const char *path,struct json_object *body,const char *actor,struct iptv_error *e)
{
    char kind[32]="",id[97]="",action[32]="",extra;int parts=sscanf(path,"%31[^/]/%96[^/]/%31[^/]%c",kind,id,action,&extra);
    if(parts==1&&!strcmp(method,"GET")){
        struct json_object *out=json_object_new_object();const char *kinds[]={"recordings","captures"};
        for(int k=0;k<2;k++){struct json_object *all=records(db,kinds[k]),*items=json_object_new_array();
            for(size_t i=0;i<json_object_array_length(all);i++)json_object_array_add(items,public_record(json_object_array_get_idx(all,i)));
            json_object_object_add(out,k?"captures":"items",items);json_object_put(all);}
        num(out,"used_bytes",usage(db));return out;
    }
    if(!strcmp(id,"cleanup-preview")&&parts==2&&!strcmp(method,"POST")){
        struct json_object *out=json_object_new_object(),*all=records(db,"recordings"),*items=json_object_new_array();
        struct json_object *cfg=iptv_settings(db);double cutoff=time(NULL)-iptv_integer(cfg,"recording_retention_days",7)*86400.0,bytes=0;
        for(size_t i=0;i<json_object_array_length(all);i++){struct json_object *r=json_object_array_get_idx(all,i);
            if(!active_state(r)&&!iptv_integer(r,"locked",0)&&number(r,"end")<cutoff){json_object_array_add(items,public_record(r));bytes+=number(r,"bytes")+number(r,"archive_bytes");}}
        json_object_object_add(out,"items",items);num(out,"bytes",bytes);json_object_put(all);json_object_put(cfg);return out;
    }
    if(!strcmp(id,"cleanup")&&parts==2&&!strcmp(method,"POST")){
        struct json_object *items=NULL;if(!iptv_integer(body,"confirm",0)||!json_object_object_get_ex(body,"items",&items)||!json_object_is_type(items,json_type_array)||json_object_array_length(items)>1000)return iptv_fail(e,400,"invalid_parameter","items");
        struct json_object *out=json_object_new_object(),*rows=json_object_new_array(),*cfg=iptv_settings(db);
        double cutoff=time(NULL)-iptv_integer(cfg,"recording_retention_days",7)*86400.0;json_object_put(cfg);
        for(size_t i=0;i<json_object_array_length(items);i++){struct json_object *item=json_object_array_get_idx(items,i),*r=iptv_record(db,"recordings",iptv_string(item,"id")),*row=json_object_new_object();struct iptv_error failure={0};str(row,"id",iptv_string(item,"id"));
            if(!r)iptv_fail(&failure,404,"recording_not_found","");
            else if(iptv_integer(r,"revision",0)!=iptv_integer(item,"revision",-1))iptv_fail(&failure,409,"revision_conflict","");
            else if(number(r,"end")>=cutoff)iptv_fail(&failure,409,"recording_not_expired","");
            else if(remove_file(db,r,0,&failure)&&!failure.status)iptv_fail(&failure,500,"recording_delete_failed","");
            str(row,"error",failure.code);json_object_object_add(row,"deleted",json_object_new_boolean(!failure.status));json_object_array_add(rows,row);if(r)json_object_put(r);}
        json_object_object_add(out,"items",rows);return out;
    }
    if(!iptv_valid_id(id)||parts<2||parts>3)return iptv_fail(e,404,"resource_not_found","");
    if(!strcmp(kind,"captures")){
        struct json_object *c=iptv_record(db,"captures",id),*out=NULL;
        if(parts==3&&!strcmp(action,"start")&&!strcmp(method,"POST")){
            struct json_object *channel=iptv_record(db,"channels",id),*cfg=iptv_settings(db),*run=NULL;char root[PATH_MAX];struct stat st;
            if(!iptv_integer(body,"confirm",0))iptv_fail(e,409,"requires_confirmation","confirm");
            else if(!iptv_channel_enabled(db,channel)||!iptv_integer(cfg,"enabled",0))iptv_fail(e,409,"channel_unavailable","");
            else if(strcmp(iptv_string(channel,"mode"),"managed")||!strcmp(iptv_string(channel,"hls_container"),"fmp4"))iptv_fail(e,409,"recording_requires_managed_ts","");
            else if(iptv_integer(body,"if_revision",-1)!=iptv_integer(channel,"revision",0))iptv_fail(e,409,"revision_conflict","if_revision");
            else if(c&&!strcmp(iptv_string(c,"state"),"recording"))out=public_record(c);
            else if(c&&!strcmp(iptv_string(c,"state"),"stopping"))iptv_fail(e,409,"recording_busy","");
            else if(!iptv_storage_root(cfg,"recording_path",".dreamingwrt-recordings",root,sizeof(root),e)&&!lstat(root,&st)){
                run=iptv_runtime_start(channel,cfg,2,e);
                if(run){if(!c)c=json_object_new_object();str(c,"id",id);str(c,"name",iptv_string(channel,"name"));str(c,"category_id",iptv_string(channel,"category_id"));str(c,"root",root);num(c,"device",st.st_dev);num(c,"inode",st.st_ino);str(c,"state","recording");str(c,"error","");str(c,"current_id","");str(c,"last_segment","");str(c,"generation","");num(c,"start",time(NULL));
                    if(write_record(db,"captures",c)){iptv_runtime_capture_release(id);iptv_fail(e,503,"recording_index_failed","");}else out=public_record(c);}
            }
            if(run)json_object_put(run);if(channel)json_object_put(channel);if(cfg)json_object_put(cfg);
        }else if(parts==3&&!strcmp(action,"stop")&&!strcmp(method,"POST")&&c){str(c,"state","stopping");write_record(db,"captures",c);out=public_record(c);}
        else iptv_fail(e,404,"resource_not_found","");
        if(c)json_object_put(c);return out;
    }
    struct json_object *r=iptv_record(db,"recordings",id),*out=NULL;
    if(!r)return iptv_fail(e,404,"recording_not_found","");
    if(parts==2&&!strcmp(method,"GET"))out=public_record(r);
    else if(parts==3&&!strcmp(action,"preview")&&!strcmp(method,"POST")){
        if(strcmp(iptv_string(r,"state"),"ready")||!location_ok(r))iptv_fail(e,409,"recording_not_playable","");
        else{char token[49],url[384];sqlite3_stmt *s=NULL;
            if(!iptv_id(token,sizeof(token))&&sqlite3_prepare_v2(db,"INSERT INTO iptv_preview VALUES(?,?,?,unixepoch()+300)",-1,&s,NULL)==SQLITE_OK){bindstr(s,1,token);bindstr(s,2,actor);bindstr(s,3,iptv_string(r,"channel_id"));int rc=sqlite3_step(s);sqlite3_finalize(s);s=NULL;
                if(rc==SQLITE_DONE&&sqlite3_prepare_v2(db,"INSERT INTO iptv_recording_lease VALUES(?,?)",-1,&s,NULL)==SQLITE_OK){bindstr(s,1,token);bindstr(s,2,id);if(sqlite3_step(s)==SQLITE_DONE){out=json_object_new_object();str(out,"session_id",token);snprintf(url,sizeof(url),"/api/v1/iptv/media/%s/%s/record-%s.mp4",token,iptv_string(r,"channel_id"),id);str(out,"url",url);str(out,"mode","recording");num(out,"expires_at",time(NULL)+300);}}sqlite3_finalize(s);}
            if(!out)iptv_fail(e,503,"session_create_failed","");}
    }else if(iptv_integer(body,"if_revision",-1)!=iptv_integer(r,"revision",0))iptv_fail(e,409,"revision_conflict","if_revision");
    else if(parts==2&&!strcmp(method,"PUT")){
        struct json_object *value=NULL;if(!json_object_object_get_ex(body,"locked",&value)||!json_object_is_type(value,json_type_boolean))iptv_fail(e,400,"invalid_parameter","locked");
        else{json_object_object_add(r,"locked",json_object_get(value));if(!write_record(db,"recordings",r))out=public_record(r);}
    }else if(parts==2&&!strcmp(method,"DELETE")){
        if(!iptv_integer(body,"confirm",0))iptv_fail(e,409,"requires_confirmation","confirm");
        else if(!remove_file(db,r,iptv_integer(body,"confirm_locked",0),e))out=json_tokener_parse("{\"deleted\":true}");
    }else if(parts==3&&!strcmp(action,"archive")&&!strcmp(method,"POST")&&!active_state(r)){
        str(r,"state","pending_archive");str(r,"error","");write_record(db,"recordings",r);out=public_record(r);
    }else iptv_fail(e,405,"method_not_allowed","");
    json_object_put(r);return out;
}
struct json_object *iptv_recordings_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,const char *actor,struct iptv_error *e)
{pthread_mutex_lock(&guard);struct json_object *out=handle(db,method,path,body,actor,e);pthread_mutex_unlock(&guard);return out;}
int iptv_recording_open(sqlite3 *db,const char *channel,const char *name,struct iptv_error *e)
{
    char id[49]="";int consumed=0;
    if(sscanf(name,"record-%48[0-9a-f].mp4%n",id,&consumed)!=1||!consumed||name[consumed]||strlen(id)!=48){iptv_fail(e,404,"recording_not_found","");return -1;}
    struct json_object *r=iptv_record(db,"recordings",id);int fd=-1;char path[PATH_MAX];struct stat st;
    if(!r||strcmp(iptv_string(r,"channel_id"),channel)||strcmp(iptv_string(r,"state"),"ready"))iptv_fail(e,404,"recording_not_found","");
    else if(!location_ok(r)||path_for(r,"archive.mp4",path,sizeof(path)))iptv_fail(e,409,"recording_storage_unavailable","");
    else if((fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW))<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_dev!=(dev_t)number(r,"device")||st.st_ino!=(ino_t)number(r,"archive_inode")){if(fd>=0)close(fd);fd=-1;iptv_fail(e,410,"recording_file_missing","");}
    if(r)json_object_put(r);return fd;
}
