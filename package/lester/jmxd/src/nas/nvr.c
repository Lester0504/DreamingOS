// SPDX-License-Identifier: GPL-2.0-or-later
/* Independent manual-RTSP recorder. A browser never owns recording lifetime. */
#define _GNU_SOURCE
#include "nvr.h"
#include "storage/storage_files.h"
#include "storage/data_storage.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef NVR_SEGMENT_SECONDS
#define NVR_SEGMENT_SECONDS "30"
#endif
#define MAX_RECORDERS 2
struct recorder {long camera;pid_t pid;int dir;char folder[160];time_t started,retry;off_t imported;};
static sqlite3 *db;
static struct json_object *storage_snapshot;
static int data_fd=-1;
static char config_file[PATH_MAX],data_root[48],data_path[PATH_MAX];
static struct recorder recorders[MAX_RECORDERS];
static pid_t export_pid;
static long export_job;
static char export_name[80];
static char *encoded(const char *s);
static const char *str(struct json_object *o,const char *k){struct json_object *v=NULL;return o&&json_object_object_get_ex(o,k,&v)&&json_object_is_type(v,json_type_string)?json_object_get_string(v):"";}
static double num(struct json_object *o,const char *k){struct json_object *v=NULL;return o&&json_object_object_get_ex(o,k,&v)?json_object_get_double(v):0;}
static void add(struct json_object *o,const char *k,const char *v){json_object_object_add(o,k,json_object_new_string(v));}
static struct json_object *reply(struct json_object *d,int status,int *http){struct json_object *o=json_object_new_object();*http=status;add(d,"contract_version","nvr.v1");json_object_object_add(o,"code",json_object_new_int(status<400?2000:4000));json_object_object_add(o,"data",d);return o;}
static struct json_object *error(const char *s,int status,int *http){struct json_object *o=json_object_new_object();add(o,"error",s);return reply(o,status,http);}
static sqlite3_stmt *prepare(const char *sql){sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(db,sql,-1,&q,NULL)!=SQLITE_OK)return NULL;return q;}
static void bind(sqlite3_stmt *q,int n,const char *s){sqlite3_bind_text(q,n,s,-1,SQLITE_TRANSIENT);}
static int execute(sqlite3_stmt *q){if(!q)return -1;int rc=sqlite3_step(q);sqlite3_finalize(q);return rc==SQLITE_DONE?0:-1;}
static struct json_object *rows(sqlite3_stmt *q){struct json_object *a=json_object_new_array();if(!q)return a;while(sqlite3_step(q)==SQLITE_ROW){struct json_object *o=json_object_new_object();for(int i=0;i<sqlite3_column_count(q);i++){const char *k=sqlite3_column_name(q,i);int type=sqlite3_column_type(q,i);json_object_object_add(o,k,type==SQLITE_INTEGER?json_object_new_int64(sqlite3_column_int64(q,i)):type==SQLITE_FLOAT?json_object_new_double(sqlite3_column_double(q,i)):type==SQLITE_NULL?NULL:json_object_new_string((const char *)sqlite3_column_text(q,i)));}json_object_array_add(a,o);}sqlite3_finalize(q);return a;}
static struct json_object *ref(const char *relative){struct json_object *o=json_object_new_object();char *path=NULL;if(asprintf(&path,"%s/.dreamingos-nvr/%s",data_path,relative)<0){json_object_put(o);return NULL;}add(o,"root_id",data_root);add(o,"path",path);free(path);return o;}
static int storage_ready(void) {
    if (data_fd < 0 || !db) return 0;
    struct json_object *state = data_storage_app_resolve(storage_snapshot), *available = NULL;
    int usable = json_object_object_get_ex(state, "available", &available) && json_object_get_boolean(available);
    if (!usable) { json_object_put(state); return 0; }
    const char *why = ""; char canonical[PATH_MAX]; struct stat a, b;
    int fd = storage_files_open_dir(str(state,"root_id"),str(state,"path"),1,canonical,sizeof(canonical),&why);
    int current = fd >= 0 ? openat(fd,".dreamingos-nvr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) : -1;
    int ready = current >= 0 && !fstat(current,&a) && !fstat(data_fd,&b) && a.st_dev==b.st_dev && a.st_ino==b.st_ino;
    if (current >= 0) close(current);
    if (fd >= 0) close(fd);
    if (ready) {
        snprintf(data_root,sizeof(data_root),"%s",str(state,"root_id"));
        snprintf(data_path,sizeof(data_path),"%s",str(state,"path"));
    }
    json_object_put(state);
    return ready;
}
static int space_ready(void){struct statvfs v;return data_fd>=0&&!fstatvfs(data_fd,&v)&&(unsigned long long)v.f_bavail*v.f_frsize>=16*1024*1024;}
static void camera_state(long id,const char *state,const char *reason){sqlite3_stmt *q=prepare("UPDATE cameras SET state=?,error=? WHERE id=? AND (state<>? OR error<>?)");bind(q,1,state);bind(q,2,reason);sqlite3_bind_int64(q,3,id);bind(q,4,state);bind(q,5,reason);execute(q);}
static void terminate(pid_t pid){if(pid<=0)return;kill(-pid,SIGTERM);struct timespec delay={0,20000000};int status;for(int i=0;i<50;i++){pid_t done=waitpid(pid,&status,WNOHANG);if(done==pid||(done<0&&errno==ECHILD))return;nanosleep(&delay,NULL);}kill(-pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){}}
static int valid_clip(const char *name){if(strncmp(name,"rec-",4))return 0;const char *p=name+4;int n=0;while(*p>='0'&&*p<='9'){p++;n++;}return n>0&&!strcmp(p,".ts");}
static void clip_playlist(struct recorder *r,const char *name,double duration){
    char *path=NULL,*manifest=NULL,*temporary=NULL;
    if(asprintf(&path,"%s/.dreamingos-nvr/%s/%s",data_path,r->folder,name)<0)return;
    char *url=encoded(path),*root=encoded(data_root);free(path);
    if(!url||!root)goto done;
    if(asprintf(&manifest,"%s.m3u8",name)<0)goto done;
    if(asprintf(&temporary,"%s.tmp",manifest)<0)goto done;
    int fd=openat(r->dir,temporary,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd>=0){
        int rc=dprintf(fd,"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:%.3f,\n/api/v1/storage/files/raw?root_id=%s&path=%s\n#EXT-X-ENDLIST\n",(int)duration+1,duration,root,url);
        close(fd);
        if(rc>0)renameat(r->dir,temporary,r->dir,manifest);
        unlinkat(r->dir,temporary,0);
    }
done:free(url);free(root);free(manifest);free(temporary);
}
static void import_clips(struct recorder *r){
    int fd=openat(r->dir,"segments.csv",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return;
    FILE *file=fdopen(fd,"r");if(!file){close(fd);return;}fseeko(file,r->imported,SEEK_SET);
    char line[512],name[160];double start,end;
    while(fgets(line,sizeof(line),file)){
        if(!strchr(line,'\n'))break;
        r->imported=ftello(file);
        if(sscanf(line,"%159[^,],%lf,%lf",name,&start,&end)!=3||!valid_clip(name)||!isfinite(start)||!isfinite(end)||start<0||end<=start)continue;
        struct stat st;if(fstatat(r->dir,name,&st,AT_SYMLINK_NOFOLLOW)||!S_ISREG(st.st_mode)||st.st_size<=0)continue;
        char relative[320];if(snprintf(relative,sizeof(relative),"%s/%s",r->folder,name)>=(int)sizeof(relative))continue;
        clip_playlist(r,name,end-start);
        sqlite3_stmt *q=prepare("INSERT OR IGNORE INTO recordings(camera_id,path,started_unix,duration_seconds,size_bytes) VALUES(?,?,?,?,?)");
        sqlite3_bind_int64(q,1,r->camera);bind(q,2,relative);sqlite3_bind_double(q,3,r->started+start);sqlite3_bind_double(q,4,end-start);sqlite3_bind_int64(q,5,st.st_size);execute(q);
    }fclose(file);
}
static void stop_recorder(struct recorder *r){if(!r->camera)return;terminate(r->pid);r->pid=0;if(r->dir>=0){import_clips(r);close(r->dir);}memset(r,0,sizeof(*r));}
static char *encoded(const char *s){static const char hex[]="0123456789ABCDEF";char *out=malloc(strlen(s)*3+1),*p=out;if(!out)return NULL;for(const unsigned char *v=(const unsigned char *)s;*v;v++){if((*v>='a'&&*v<='z')||(*v>='A'&&*v<='Z')||(*v>='0'&&*v<='9')||*v=='-'||*v=='_'||*v=='.')*p++=*v;else{*p++='%';*p++=hex[*v>>4];*p++=hex[*v&15];}}*p=0;return out;}
static int start_recorder(struct recorder *r,long id,const char *url){
    char parent[64],run[80];snprintf(parent,sizeof(parent),"camera-%ld",id);if(mkdirat(data_fd,parent,0700)&&errno!=EEXIST)return -1;
    int camera=openat(data_fd,parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(camera<0)return -1;
    static unsigned int serial;time_t now=time(NULL);snprintf(run,sizeof(run),"run-%ld-%ld-%u",(long)now,(long)getpid(),++serial);
    if(mkdirat(camera,run,0700)){close(camera);return -1;}int dir=openat(camera,run,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(camera);if(dir<0)return -1;
    memset(r,0,sizeof(*r));r->camera=id;r->dir=dir;r->started=now;if(snprintf(r->folder,sizeof(r->folder),"%s/%s",parent,run)>=(int)sizeof(r->folder)){close(dir);memset(r,0,sizeof(*r));return -1;}
    struct json_object *meta=json_object_new_object();json_object_object_add(meta,"camera_id",json_object_new_int64(id));json_object_object_add(meta,"started_unix",json_object_new_int64(now));int md=openat(dir,"session.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(md>=0){json_object_to_fd(md,meta,JSON_C_TO_STRING_PLAIN);close(md);}json_object_put(meta);
    pid_t parent_pid=getpid();r->pid=fork();
    if(!r->pid){
        setpgid(0,0);prctl(PR_SET_PDEATHSIG,SIGKILL);if(getppid()!=parent_pid)_exit(1);
        if(fchdir(dir))_exit(1);
        int null=open("/dev/null",O_RDWR);dup2(null,STDIN_FILENO);dup2(null,STDOUT_FILENO);
        /* Do not write camera credentials from tool diagnostics into logs. */
        dup2(null,STDERR_FILENO);
        struct rlimit limit={128LL*1024*1024,128LL*1024*1024};setrlimit(RLIMIT_FSIZE,&limit);
        char *path=NULL;
        if(asprintf(&path,"%s/.dreamingos-nvr/%s/",data_path,r->folder)<0)_exit(1);
        char *p=encoded(path),*root=encoded(data_root),*base=NULL;
        free(path);
        if(!p||!root||asprintf(&base,"/api/v1/storage/files/raw?root_id=%s&path=%s",root,p)<0)_exit(1);
        execl("/usr/bin/ffmpeg","/usr/bin/ffmpeg","-nostdin","-v","error","-rtsp_transport","tcp","-timeout","10000000","-i",url,
            "-map","0:v:0","-map","0:a:0?","-c:v","copy","-c:a","aac","-ac","2","-b:a","96k","-threads","1",
            "-f","hls","-hls_time","2","-hls_list_size","6","-hls_flags","delete_segments+temp_file","-hls_base_url",base,"-hls_segment_filename","live-%06d.ts","live.m3u8",
            "-map","0:v:0","-map","0:a:0?","-c:v","copy","-c:a","aac","-ac","2","-b:a","96k","-threads","1",
            "-f","segment","-segment_time",NVR_SEGMENT_SECONDS,"-segment_format","mpegts","-reset_timestamps","1","-segment_list","segments.csv","-segment_list_type","csv","rec-%06d.ts",(char *)NULL);_exit(127);
    }
    if(r->pid<0){close(dir);memset(r,0,sizeof(*r));return -1;}setpgid(r->pid,r->pid);camera_state(id,"connecting","");return 0;
}
static void recover_clips(void){
    int copy=openat(data_fd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);DIR *top=copy>=0?fdopendir(copy):NULL;if(!top)return;struct dirent *e;
    while((e=readdir(top))){if(strncmp(e->d_name,"camera-",7))continue;int cf=openat(data_fd,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(cf<0)continue;DIR *cd=fdopendir(cf);struct dirent *run;
        while(cd&&(run=readdir(cd))){if(strncmp(run->d_name,"run-",4))continue;int fd=openat(cf,run->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)continue;int mf=openat(fd,"session.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct json_object *m=mf>=0?json_object_from_fd(mf):NULL;if(mf>=0)close(mf);
            if(m){struct recorder r={.camera=(long)num(m,"camera_id"),.dir=fd,.started=(time_t)num(m,"started_unix")};if(snprintf(r.folder,sizeof(r.folder),"%s/%s",e->d_name,run->d_name)<(int)sizeof(r.folder))import_clips(&r);json_object_put(m);}close(fd);
        }if(cd)closedir(cd);else close(cf);
    }closedir(top);
}
static int select_storage(const char *root,const char *path,int persist){
    const char *why="";char canonical[PATH_MAX];int fd=storage_files_open_dir(root,path,1,canonical,sizeof(canonical),&why);if(fd<0)return -1;
    if(mkdirat(fd,".dreamingos-nvr",0700)&&errno!=EEXIST){close(fd);return -1;}int dir=openat(fd,".dreamingos-nvr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);if(dir<0)return -1;
    int dbfile=openat(dir,"recordings.sqlite3",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);if(dbfile<0){close(dir);return -1;}close(dbfile);
    char file[100];snprintf(file,sizeof(file),"/proc/self/fd/%d/recordings.sqlite3",dir);sqlite3 *selected=NULL;
    if(sqlite3_open(file,&selected)!=SQLITE_OK){if(selected)sqlite3_close(selected);close(dir);return -1;}
    const char *schema="PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;CREATE TABLE IF NOT EXISTS cameras(id INTEGER PRIMARY KEY,name TEXT NOT NULL,url TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,deleted INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'stopped',error TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS recordings(id INTEGER PRIMARY KEY,camera_id INTEGER NOT NULL,path TEXT UNIQUE NOT NULL,started_unix REAL NOT NULL,duration_seconds REAL NOT NULL,size_bytes INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS exports(id INTEGER PRIMARY KEY,state TEXT NOT NULL,path TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',created_unix INTEGER NOT NULL);";
    if(sqlite3_exec(selected,schema,NULL,NULL,NULL)!=SQLITE_OK){sqlite3_close(selected);close(dir);return -1;}sqlite3_busy_timeout(selected,1000);
    if(persist){char tmp[PATH_MAX];if(snprintf(tmp,sizeof(tmp),"%s.tmp.%ld",config_file,(long)getpid())>=(int)sizeof(tmp)){sqlite3_close(selected);close(dir);return -1;}int out=open(tmp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);struct json_object *o=json_object_new_object();add(o,"root_id",root);add(o,"path",canonical);int saved=out>=0&&!json_object_to_fd(out,o,JSON_C_TO_STRING_PLAIN)&&!fsync(out)&&!rename(tmp,config_file);json_object_put(o);if(out>=0)close(out);unlink(tmp);if(!saved){sqlite3_close(selected);close(dir);return -1;}}
    if(db)sqlite3_close(db);
    if(data_fd>=0)close(data_fd);
    db=selected;data_fd=dir;snprintf(data_root,sizeof(data_root),"%s",root);snprintf(data_path,sizeof(data_path),"%s",canonical);
    sqlite3_exec(db,"UPDATE exports SET state='failed',error='service_restarted' WHERE state='running';UPDATE cameras SET state=CASE WHEN enabled=1 THEN 'queued' ELSE 'stopped' END,error=''",NULL,NULL,NULL);recover_clips();return 0;
}
static void inherit_storage(void) {
    if (db) return;
    if (!storage_snapshot || !strcmp(str(storage_snapshot, "source"), "unconfigured")) {
        if (storage_snapshot) json_object_put(storage_snapshot);
        storage_snapshot = data_storage_app_load(config_file);
    }
    struct json_object *state = data_storage_app_resolve(storage_snapshot), *available = NULL;
    snprintf(data_root, sizeof(data_root), "%s", str(state, "root_id"));
    snprintf(data_path, sizeof(data_path), "%s", str(state, "path"));
    if (json_object_object_get_ex(state, "available", &available) && json_object_get_boolean(available))
        select_storage(data_root, data_path, 0);
    json_object_put(state);
}
int nvr_init(const char *config) {
    snprintf(config_file, sizeof(config_file), "%s", config);
    if (storage_snapshot) json_object_put(storage_snapshot);
    storage_snapshot = data_storage_app_load(config);
    inherit_storage();
    return 0;
}
void nvr_close(void){for(int i=0;i<MAX_RECORDERS;i++)stop_recorder(&recorders[i]);terminate(export_pid);export_pid=0;if(db)sqlite3_close(db);db=NULL;if(data_fd>=0)close(data_fd);data_fd=-1;}
void nvr_tick(void){
    if(!db){
        static time_t retry;
        if(time(NULL)<retry)return;
        retry=time(NULL)+5;
        inherit_storage();
        if(!db)return;
    }
    int ready=storage_ready(),space=ready&&space_ready();
    for(int i=0;i<MAX_RECORDERS;i++){
        struct recorder *r=&recorders[i];if(!r->camera)continue;
        sqlite3_stmt *q=prepare("SELECT enabled FROM cameras WHERE id=? AND deleted=0");sqlite3_bind_int64(q,1,r->camera);int enabled=sqlite3_step(q)==SQLITE_ROW&&sqlite3_column_int(q,0);sqlite3_finalize(q);
        if(!enabled||!space){long id=r->camera;stop_recorder(r);camera_state(id,!enabled?"stopped":!ready?"storage_unavailable":"storage_full","");continue;}
        import_clips(r);if(r->pid>0){int status;pid_t done=waitpid(r->pid,&status,WNOHANG);if(done==r->pid){r->pid=0;r->retry=time(NULL)+5;camera_state(r->camera,"reconnecting","stream_interrupted");}else{struct stat st;if(!fstatat(r->dir,"live.m3u8",&st,AT_SYMLINK_NOFOLLOW)&&st.st_size>0)camera_state(r->camera,"recording","");}}
        if(!r->pid&&time(NULL)>=r->retry){long id=r->camera;close(r->dir);memset(r,0,sizeof(*r));camera_state(id,"reconnecting","stream_interrupted");}
    }
    if(space&&!access("/usr/bin/ffmpeg",X_OK)){
        sqlite3_stmt *q=prepare("SELECT id,url FROM cameras WHERE enabled=1 AND deleted=0 ORDER BY id");
        while(sqlite3_step(q)==SQLITE_ROW){long id=sqlite3_column_int64(q,0);int assigned=0;struct recorder *slot=NULL;for(int i=0;i<MAX_RECORDERS;i++){if(recorders[i].camera==id)assigned=1;else if(!recorders[i].camera&&!slot)slot=&recorders[i];}if(!assigned&&slot){if(start_recorder(slot,id,(const char *)sqlite3_column_text(q,1)))camera_state(id,"failed","recorder_unavailable");}else if(!assigned)camera_state(id,"queued","recorder_limit");}sqlite3_finalize(q);
    }
    if(export_pid>0&&!space){
        terminate(export_pid);export_pid=0;
        sqlite3_stmt *q=prepare("UPDATE exports SET state='failed',error=? WHERE id=?");bind(q,1,ready?"storage_full":"storage_unavailable");sqlite3_bind_int64(q,2,export_job);execute(q);unlinkat(data_fd,export_name,0);
    }
    if(export_pid>0){int status;pid_t done=waitpid(export_pid,&status,WNOHANG);if(done==export_pid){export_pid=0;struct stat st;int good=WIFEXITED(status)&&!WEXITSTATUS(status)&&!fstatat(data_fd,export_name,&st,AT_SYMLINK_NOFOLLOW)&&st.st_size>0;sqlite3_stmt *q=prepare("UPDATE exports SET state=?,error=? WHERE id=?");bind(q,1,good?"succeeded":"failed");bind(q,2,good?"":"export_failed");sqlite3_bind_int64(q,3,export_job);execute(q);if(!good)unlinkat(data_fd,export_name,0);}}
}
static int valid_url(const char *url){if(strncmp(url,"rtsp://",7)&&strncmp(url,"rtsps://",8))return 0;if(strlen(url)>2048)return 0;for(const unsigned char *p=(const unsigned char *)url;*p;p++)if(*p<=32||*p==127)return 0;return strlen(url)>8;}
struct json_object *nvr_request(const char *method,const char *route,struct json_object *input,int *http){
    nvr_tick();if(!strncmp(route,"/nvr/",5))route+=4;int ready=storage_ready();
    if(!strcmp(route,"/status")&&!strcmp(method,"GET")){struct json_object *o=json_object_new_object(),*p=json_object_new_object(),*s=data_storage_app_resolve(storage_snapshot);json_object_object_add(p,"installed",json_object_new_boolean(1));add(p,"state","ready");json_object_object_add(o,"package",p);add(s,"state",ready?"ready":"storage_unavailable");add(s,"root_id",data_root);add(s,"path",data_path);if(!ready&&!str(s,"reason")[0])add(s,"reason","storage_unavailable");json_object_object_add(s,"free_space_ok",json_object_new_boolean(ready&&space_ready()));json_object_object_add(o,"storage",s);json_object_object_add(o,"ffmpeg",json_object_new_boolean(!access("/usr/bin/ffmpeg",X_OK)));json_object_object_add(o,"max_recorders",json_object_new_int(MAX_RECORDERS));add(o,"preview_profile","H.264 video / AAC audio, no video transcoding");add(o,"retention","manual; recordings are never deleted by disabling or uninstalling");return reply(o,200,http);}
    if(!strcmp(route,"/settings")&&!strcmp(method,"POST")){for(int i=0;i<MAX_RECORDERS;i++)if(recorders[i].camera)return error("recording_active",409,http);if(export_pid)return error("export_running",409,http);if(!str(input,"root_id")[0]||!str(input,"path")[0])return error("invalid_request",400,http);if(select_storage(str(input,"root_id"),str(input,"path"),1))return error("storage_unavailable",409,http);if(storage_snapshot)json_object_put(storage_snapshot);storage_snapshot=data_storage_app_load(config_file);return nvr_request("GET","/status",NULL,http);}
    if(!ready)return error("storage_unavailable",409,http);
    if(!strcmp(route,"/cameras")&&!strcmp(method,"GET")){sqlite3_stmt *q=prepare("SELECT id,name,enabled,state,error FROM cameras WHERE deleted=0 ORDER BY id");struct json_object *o=json_object_new_object(),*a=rows(q);for(size_t n=0;n<json_object_array_length(a);n++){struct json_object *c=json_object_array_get_idx(a,n);long id=(long)num(c,"id");for(int i=0;i<MAX_RECORDERS;i++)if(recorders[i].camera==id&&recorders[i].pid>0){struct stat st;if(!fstatat(recorders[i].dir,"live.m3u8",&st,AT_SYMLINK_NOFOLLOW)&&st.st_size>0){char path[180];snprintf(path,sizeof(path),"%s/live.m3u8",recorders[i].folder);json_object_object_add(c,"preview",ref(path));}}json_object_object_add(c,"ptz",json_object_new_boolean(0));}json_object_object_add(o,"items",a);return reply(o,200,http);}
    if(!strcmp(route,"/cameras")&&!strcmp(method,"POST")){const char *name=str(input,"name"),*url=str(input,"url");if(!*name||strlen(name)>128||!valid_url(url))return error("invalid_request",400,http);sqlite3_stmt *q=prepare("INSERT INTO cameras(name,url) VALUES(?,?)");bind(q,1,name);bind(q,2,url);if(execute(q))return error("storage_failed",500,http);struct json_object *o=json_object_new_object();json_object_object_add(o,"id",json_object_new_int64(sqlite3_last_insert_rowid(db)));return reply(o,201,http);}
    if((!strcmp(route,"/cameras/action")||!strcmp(route,"/cameras/update"))&&!strcmp(method,"POST")){long id=(long)num(input,"id");sqlite3_stmt *q=prepare("SELECT enabled FROM cameras WHERE id=? AND deleted=0");sqlite3_bind_int64(q,1,id);int found=sqlite3_step(q)==SQLITE_ROW;int enabled=found&&sqlite3_column_int(q,0);sqlite3_finalize(q);if(!found)return error("not_found",404,http);
        if(!strcmp(route,"/cameras/update")){if(enabled)return error("recording_active",409,http);if(!str(input,"name")[0]||strlen(str(input,"name"))>128||!valid_url(str(input,"url")))return error("invalid_request",400,http);q=prepare("UPDATE cameras SET name=?,url=? WHERE id=?");bind(q,1,str(input,"name"));bind(q,2,str(input,"url"));sqlite3_bind_int64(q,3,id);}
        else{const char *action=str(input,"action");if(strcmp(action,"start")&&strcmp(action,"stop")&&strcmp(action,"remove"))return error("invalid_request",400,http);if(!strcmp(action,"start")&&(access("/usr/bin/ffmpeg",X_OK)||!space_ready()))return error(access("/usr/bin/ffmpeg",X_OK)?"dependency_missing":"storage_full",409,http);q=prepare("UPDATE cameras SET enabled=?,deleted=?,state=? WHERE id=?");sqlite3_bind_int(q,1,!strcmp(action,"start"));sqlite3_bind_int(q,2,!strcmp(action,"remove"));bind(q,3,!strcmp(action,"start")?"queued":"stopped");sqlite3_bind_int64(q,4,id);}
        if(execute(q))return error("storage_failed",500,http);
        struct json_object *o=json_object_new_object();add(o,"state","accepted");return reply(o,202,http);
    }
    if(!strcmp(route,"/recordings")&&!strcmp(method,"GET")){sqlite3_stmt *q=prepare("SELECT r.*,c.name AS camera_name FROM recordings r LEFT JOIN cameras c ON c.id=r.camera_id WHERE (?=0 OR camera_id=?) AND (?=0 OR started_unix>=?) AND (?=0 OR started_unix<?) ORDER BY started_unix DESC LIMIT 200");long camera=(long)num(input,"camera_id");double from=num(input,"from_unix"),to=num(input,"to_unix");sqlite3_bind_int64(q,1,camera);sqlite3_bind_int64(q,2,camera);sqlite3_bind_double(q,3,from);sqlite3_bind_double(q,4,from);sqlite3_bind_double(q,5,to);sqlite3_bind_double(q,6,to);struct json_object *o=json_object_new_object(),*a=rows(q);for(size_t n=0;n<json_object_array_length(a);n++){struct json_object *c=json_object_array_get_idx(a,n);json_object_object_add(c,"file",ref(str(c,"path")));char *playlist=NULL;if(asprintf(&playlist,"%s.m3u8",str(c,"path"))>=0){json_object_object_add(c,"playback",ref(playlist));free(playlist);}}json_object_object_add(o,"items",a);json_object_object_add(o,"limit",json_object_new_int(200));return reply(o,200,http);}
    if(!strcmp(route,"/exports")&&!strcmp(method,"GET")){struct json_object *o=json_object_new_object(),*a=rows(prepare("SELECT * FROM exports ORDER BY id DESC LIMIT 100"));for(size_t n=0;n<json_object_array_length(a);n++){struct json_object *j=json_object_array_get_idx(a,n);if(!strcmp(str(j,"state"),"succeeded"))json_object_object_add(j,"file",ref(str(j,"path")));}json_object_object_add(o,"items",a);return reply(o,200,http);}
    if(!strcmp(route,"/exports")&&!strcmp(method,"POST")){
        if(export_pid)return error("export_running",409,http);
        if(access("/usr/bin/ffmpeg",X_OK))return error("dependency_missing",409,http);
        sqlite3_stmt *q=prepare("SELECT path,duration_seconds FROM recordings WHERE id=?");sqlite3_bind_int64(q,1,(long)num(input,"recording_id"));if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return error("not_found",404,http);}char relative[320];snprintf(relative,sizeof(relative),"%s",sqlite3_column_text(q,0));double duration=sqlite3_column_double(q,1),start=num(input,"start_seconds"),end=num(input,"end_seconds");sqlite3_finalize(q);if(end==0)end=duration;if(!isfinite(start)||!isfinite(end)||start<0||end<=start||end>duration+.1||end-start>600)return error("invalid_range",400,http);
        struct json_object *location=ref(relative);struct storage_files_stream source;const char *why="";int opened=storage_files_open_stream(data_root,str(location,"path"),&source,&why);json_object_put(location);if(opened)return error("source_unavailable",409,http);
        q=prepare("INSERT INTO exports(state,created_unix) VALUES('running',?)");sqlite3_bind_int64(q,1,time(NULL));if(execute(q)){close(source.fd);return error("storage_failed",500,http);}export_job=sqlite3_last_insert_rowid(db);snprintf(export_name,sizeof(export_name),"export-%ld.mp4",export_job);int out=openat(data_fd,export_name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(out<0){close(source.fd);q=prepare("UPDATE exports SET state='failed',error='destination_unavailable' WHERE id=?");sqlite3_bind_int64(q,1,export_job);execute(q);return error("destination_unavailable",409,http);}q=prepare("UPDATE exports SET path=? WHERE id=?");bind(q,1,export_name);sqlite3_bind_int64(q,2,export_job);execute(q);
        pid_t parent=getpid();export_pid=fork();if(!export_pid){setpgid(0,0);prctl(PR_SET_PDEATHSIG,SIGKILL);if(getppid()!=parent)_exit(1);fcntl(source.fd,F_SETFD,0);dup2(out,STDOUT_FILENO);int null=open("/dev/null",O_RDWR);dup2(null,STDERR_FILENO);dup2(null,STDIN_FILENO);struct rlimit limit={128LL*1024*1024,128LL*1024*1024};setrlimit(RLIMIT_FSIZE,&limit);char input[80],at[40],len[40];snprintf(input,sizeof(input),"/proc/self/fd/%d",source.fd);snprintf(at,sizeof(at),"%.3f",start);snprintf(len,sizeof(len),"%.3f",end-start);execl("/usr/bin/ffmpeg","/usr/bin/ffmpeg","-nostdin","-v","error","-threads","1","-filter_threads","1","-i",input,"-ss",at,"-t",len,"-map","0:v:0","-map","0:a:0?","-c:v","libx264","-preset","veryfast","-vf","scale=w='min(1280,iw)':h='min(720,ih)':force_original_aspect_ratio=decrease:force_divisible_by=2","-threads","1","-c:a","aac","-movflags","frag_keyframe+empty_moov","-f","mp4","pipe:1",(char *)NULL);_exit(127);}close(out);close(source.fd);
        if(export_pid<0){export_pid=0;q=prepare("UPDATE exports SET state='failed',error='worker_unavailable' WHERE id=?");sqlite3_bind_int64(q,1,export_job);execute(q);unlinkat(data_fd,export_name,0);return error("worker_unavailable",503,http);}setpgid(export_pid,export_pid);struct json_object *o=json_object_new_object();json_object_object_add(o,"job_id",json_object_new_int64(export_job));add(o,"state","running");return reply(o,202,http);
    }
    return error("not_found",404,http);
}
