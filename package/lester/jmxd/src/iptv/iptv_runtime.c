// SPDX-License-Identifier: GPL-2.0-or-later
/* Bounded media supervisor. FFmpeg/ffprobe run as child process groups;
 * no request holds a DB transaction while waiting for media. */
#define _GNU_SOURCE
#include "iptv.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
#define MAX_STREAMS 4
#define MAX_MEDIA_BYTES (16*1024*1024)
#ifndef IPTV_FFMPEG
#define IPTV_FFMPEG "/usr/bin/ffmpeg"
#endif
#ifndef IPTV_FFPROBE
#define IPTV_FFPROBE "/usr/bin/ffprobe"
#endif
/* Inspect tool builds once at supervisor startup, without connecting to any
 * source. Runtime source/codec success is reported by each explicit probe. */
static char tool_protocols[2][16384],tool_demuxers[2][32768];
static char tool_muxers[32768];
static char tool_encoders[65536];
static int tools_inspected;
static time_t tools_probed_at;
static int inspect_tool(const char *tool,const char *option,char *out,size_t cap)
{
    int fds[2];if(pipe2(fds,O_CLOEXEC))return -1;
    posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions,fds[1],1);
    posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0);
    posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0);
    posix_spawn_file_actions_addclose(&actions,fds[0]);
    posix_spawnattr_t attr;posix_spawnattr_init(&attr);posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP);posix_spawnattr_setpgroup(&attr,0);
    char *argv[]={(char*)tool,"-hide_banner",(char*)option,NULL};pid_t child;
    int rc=posix_spawn(&child,tool,&actions,&attr,argv,environ);posix_spawnattr_destroy(&attr);posix_spawn_file_actions_destroy(&actions);close(fds[1]);
    if(rc){close(fds[0]);return -1;}
    size_t used=0;int status=0,finished=0;struct timespec start,now;clock_gettime(CLOCK_MONOTONIC,&start);
    while(used<cap-1){
        struct pollfd fd={fds[0],POLLIN,0};poll(&fd,1,100);
        if(fd.revents&(POLLIN|POLLHUP)){ssize_t n=read(fds[0],out+used,cap-1-used);if(n<=0){finished=1;break;}used+=n;}
        clock_gettime(CLOCK_MONOTONIC,&now);if(now.tv_sec-start.tv_sec>=5)break;
    }
    close(fds[0]);if(!finished)kill(-child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}
    out[used]=0;return finished&&WIFEXITED(status)&&!WEXITSTATUS(status)?0:-1;
}
void iptv_tools_inspect(void)
{
    const char *tools[]={IPTV_FFMPEG,IPTV_FFPROBE};tools_inspected=1;
    for(int i=0;i<2;i++)if(inspect_tool(tools[i],"-protocols",tool_protocols[i],sizeof(tool_protocols[i]))||inspect_tool(tools[i],"-demuxers",tool_demuxers[i],sizeof(tool_demuxers[i])))tools_inspected=0;
    if(inspect_tool(IPTV_FFMPEG,"-muxers",tool_muxers,sizeof(tool_muxers)))tools_inspected=0;
    inspect_tool(IPTV_FFMPEG,"-encoders",tool_encoders,sizeof(tool_encoders));
    tools_probed_at=time(NULL);
}
static int has_input(const char *list,const char *name)
{
    const char *end=strstr(list,"Output:");const char *p=strstr(list,"Input:");if(!p)return 0;
    char pattern[40];snprintf(pattern,sizeof(pattern),"\n  %s\n",name);p=strstr(p,pattern);return p&&(!end||p<end);
}
static int protocol_compiled(const char *name)
{
    if(!tools_inspected)return 0;
    if(!strcmp(name,"rtsp"))return strstr(tool_demuxers[0]," rtsp ")&&strstr(tool_demuxers[1]," rtsp ");
    return has_input(tool_protocols[0],name)&&has_input(tool_protocols[1],name);
}
static int input_gate(struct json_object *c,struct iptv_error *e)
{
    char protocol[16];if(sscanf(iptv_string(c,"source_url"),"%15[^:]",protocol)!=1||!protocol_compiled(protocol)){
        iptv_fail(e,409,tools_inspected?"input_protocol_not_compiled":"media_capabilities_unavailable","source_url");return -1;
    }return 0;
}
struct encoder {
    const char *id,*codec,*type,*hardware;
    int available,testing;
    time_t probed_at;
    char error[64];
};
static struct encoder encoders[]={
    {"libx264","h264","video","software"},{"libx265","hevc","video","software"},
    {"h264_nvenc","h264","video","nvenc"},{"hevc_nvenc","hevc","video","nvenc"},
    {"h264_rkmpp","h264","video","rkmpp"},{"hevc_rkmpp","hevc","video","rkmpp"},
    {"h264_qsv","h264","video","qsv"},{"hevc_qsv","hevc","video","qsv"},
    {"h264_vaapi","h264","video","vaapi"},{"hevc_vaapi","hevc","video","vaapi"},
    {"aac","aac","audio","software"},{"ac3","ac3","audio","software"},
    {"eac3","eac3","audio","software"},{"mp2","mp2","audio","software"},
    {"libopus","opus","audio","software"}
};
#define ENCODER_COUNT ((int)(sizeof(encoders)/sizeof(encoders[0])))
static int encoder_index(const char *id)
{for(int i=0;i<ENCODER_COUNT;i++)if(!strcmp(encoders[i].id,id))return i;return -1;}
static int encoder_compiled(int index)
{char needle[96];snprintf(needle,sizeof(needle)," %s ",encoders[index].id);return strstr(tool_encoders,needle)!=NULL;}
int iptv_encoder_validate(struct json_object *channel,struct iptv_error *e)
{
    const char *keys[]={"video_encoder","audio_encoder"};
    for(int i=0;i<2;i++){
        struct json_object *value=NULL;if(!json_object_object_get_ex(channel,keys[i],&value))continue;
        if(!json_object_is_type(value,json_type_string))return iptv_fail(e,400,"invalid_parameter",keys[i]),0;
        const char *name=iptv_string(channel,keys[i]);if(!strcmp(name,"copy"))continue;
        int index=encoder_index(name);
        if(index<0||strcmp(encoders[index].type,i?"audio":"video"))return iptv_fail(e,400,"encoder_unknown",keys[i]),0;
        if(!strcmp(iptv_string(channel,"mode"),"external"))return iptv_fail(e,409,"external_source_not_hosted",keys[i]),0;
        if(!i&&!strcmp(encoders[index].codec,"hevc")&&strcmp(iptv_string(channel,"hls_container"),"fmp4"))return iptv_fail(e,409,"hevc_requires_fmp4","hls_container"),0;
    }
    return 1;
}
/* Same codec options for smoke and live. No implicit encoder substitution. */
static int encoder_options(int index,char **argv,int n)
{
    struct encoder *codec=&encoders[index];
    argv[n++]=!strcmp(codec->type,"video")?"-c:v":"-c:a";argv[n++]=(char*)codec->id;
    if(!strcmp(codec->type,"video")){
        argv[n++]="-threads:v";argv[n++]="1";
        if(!strcmp(codec->hardware,"vaapi")){argv[n++]="-vf";argv[n++]="format=nv12,hwupload";}
        else {argv[n++]="-pix_fmt";argv[n++]="yuv420p";}
        if(!strcmp(codec->id,"libx264")||!strcmp(codec->id,"libx265")){argv[n++]="-preset";argv[n++]="veryfast";}
        if(!strcmp(codec->id,"libx265")){argv[n++]="-x265-params";argv[n++]="pools=1:frame-threads=1";}
    }
    return n;
}
struct stream {
    char id[97],dir[PATH_MAX],state[24],error[64];
    pid_t pid;
    time_t started,last_request,last_segment;
    int timeout,idle,revision,settings_revision,manual,probing,retries,live_count,timeshift_minutes,cache_limit_mb,recording;
    int sensitive_input,transcoding,encoder;
    time_t retry_at;
    dev_t storage_device; ino_t storage_inode;
    char *argv[96];
};
static struct stream streams[MAX_STREAMS];
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_t monitor;
static int running=0,monitor_started=0;
static time_t monotime(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec;}
static struct json_object *describe(struct stream *s)
{
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"state",json_object_new_string(s?s->state:"stopped"));
    json_object_object_add(o,"process_running",json_object_new_boolean(s&&s->pid>0));
    json_object_object_add(o,"media_ready",json_object_new_boolean(s&&!strcmp(s->state,"media_ready")));
    json_object_object_add(o,"last_segment_at",s&&s->last_segment?json_object_new_int64(s->last_segment):NULL);
    json_object_object_add(o,"configuration_revision",s?json_object_new_int(s->revision):NULL);
    json_object_object_add(o,"error",s&&*s->error?json_object_new_string(s->error):NULL);
    json_object_object_add(o,"retries",json_object_new_int(s?s->retries:0));
    json_object_object_add(o,"settings_revision",s?json_object_new_int(s->settings_revision):NULL);
    json_object_object_add(o,"recording_hold",json_object_new_boolean(s&&s->recording));
    json_object_object_add(o,"manual_hold",json_object_new_boolean(s&&s->manual));
    json_object_object_add(o,"timeshift_minutes",json_object_new_int(s?s->timeshift_minutes:0));
    if(s&&!s->probing){
        json_object_object_add(o,"transcoding",json_object_new_boolean(s->transcoding));
        for(int i=0;s->argv[i]&&s->argv[i+1];i++){
            if(!strcmp(s->argv[i],"-c:v"))json_object_object_add(o,"video_encoder",json_object_new_string(s->argv[i+1]));
            if(!strcmp(s->argv[i],"-c:a"))json_object_object_add(o,"audio_encoder",json_object_new_string(s->argv[i+1]));
        }
    }
    if(s&&s->probing==1&&!strcmp(s->state,"probe_complete")){
        char p[PATH_MAX];
        if(snprintf(p,sizeof(p),"%s/probe.json",s->dir)<(int)sizeof(p)){
            struct json_object *probe=json_object_from_file(p);
            if(probe)json_object_object_add(o,"probe",probe);
        }
    }
    return o;
}
static struct stream *find(const char *id)
{for(int i=0;i<MAX_STREAMS;i++)if(!strcmp(streams[i].id,id))return &streams[i];return NULL;}
struct json_object *iptv_runtime_state(const char *id)
{pthread_mutex_lock(&lock);struct json_object *o=describe(find(id));pthread_mutex_unlock(&lock);return o;}
static int readfile(const char *p,char **data,size_t *len)
{
    *data=NULL;*len=0;int fd=open(p,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>MAX_MEDIA_BYTES){close(fd);return -1;}
    char *buf=malloc((size_t)st.st_size+1);if(!buf){close(fd);return -1;}
    size_t n=0;while(n<(size_t)st.st_size){ssize_t got=read(fd,buf+n,(size_t)st.st_size-n);if(got<0&&errno==EINTR)continue;if(got<=0){free(buf);close(fd);return -1;}n+=(size_t)got;}
    close(fd);buf[n]=0;*data=buf;*len=n;return 0;
}
static void kill_group(struct stream *s)
{
    if(s->pid<=0)return;
    /* The sole owner of this pid is this supervisor. Never signal a persisted
     * pid after daemon restart. Reap the direct child after killing its group. */
    kill(-s->pid,SIGKILL);
    while(waitpid(s->pid,NULL,0)<0&&errno==EINTR){}
    s->pid=0;
}
static int media_name(const char *name)
{
    if(!strcmp(name,"index.m3u8")||!strcmp(name,"init.mp4"))return 1;
    if(strncmp(name,"seg",3))return 0;
    const char *p=name+3;if(*p<'0'||*p>'9')return 0;
    while(*p>='0'&&*p<='9')p++;
    return !strcmp(p,".ts")||!strcmp(p,".m4s");
}
static void cleanup(struct stream *s)
{
    for(int i=0;i<96;i++){free(s->argv[i]);s->argv[i]=NULL;}
    if(!*s->dir)return;
    DIR *d=opendir(s->dir);if(!d)return;
    struct dirent *de;
    while((de=readdir(d))){
        if(media_name(de->d_name)||!strcmp(de->d_name,"snapshot.jpg")||!strcmp(de->d_name,"smoke.raw")||!strcmp(de->d_name,"window.m3u8")||!strcmp(de->d_name,"window.m3u8.tmp")||!strcmp(de->d_name,"index.m3u8.tmp")||!strcmp(de->d_name,"probe.json")||!strcmp(de->d_name,"error.log")||(!strncmp(de->d_name,"seg",3)&&strstr(de->d_name,".tmp"))){
            char p[PATH_MAX];if(snprintf(p,sizeof(p),"%s/%s",s->dir,de->d_name)<(int)sizeof(p))unlink(p);
        }
    }
    closedir(d);rmdir(s->dir);s->dir[0]=0;
}
static int storage_path(struct json_object *cfg,const char *key,char resolved[PATH_MAX],struct iptv_error *e)
{
    const char *p=iptv_string(cfg,key);
    if(!*p||!realpath(p,resolved)){iptv_fail(e,409,"storage_path_unavailable",key);return -1;}
#ifndef IPTV_TESTING
    FILE *fp=fopen("/proc/self/mounts","r");int mounted=0;char line[4096];
    if(fp){while(fgets(line,sizeof(line),fp)){
        char dev[512],mount[PATH_MAX],type[64];
        if(sscanf(line,"%511s %4095s %63s",dev,mount,type)!=3)continue;
        size_t n=strlen(mount);
        if(n>1&&!strncmp(resolved,mount,n)&&(resolved[n]==0||resolved[n]=='/')&&
            strcmp(type,"tmpfs")&&strcmp(type,"overlay")&&strcmp(type,"squashfs"))mounted=1;
    }fclose(fp);}
    if(!mounted){iptv_fail(e,409,"storage_mount_required",key);return -1;}
#endif
    struct stat st;struct statvfs fs;
    if(stat(resolved,&st)||!S_ISDIR(st.st_mode)||access(resolved,W_OK|X_OK)){iptv_fail(e,507,"storage_not_writable",key);return -1;}
    if(statvfs(resolved,&fs)||fs.f_bavail*(unsigned long long)fs.f_frsize<128ULL*1024*1024){iptv_fail(e,507,"storage_space_insufficient",key);return -1;}
    return 0;
}
int iptv_storage_root(struct json_object *cfg,const char *key,const char *module,char *out,size_t size,struct iptv_error *e)
{
    char resolved[PATH_MAX];if(storage_path(cfg,key,resolved,e))return -1;
    if(snprintf(out,size,"%s/%s",resolved,module)>=(int)size){iptv_fail(e,400,"invalid_parameter",key);return -1;}
    if(mkdir(out,0700)&&errno!=EEXIST){iptv_fail(e,507,"storage_not_writable",key);return -1;}
    struct stat st;if(lstat(out,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()){iptv_fail(e,409,"storage_path_unavailable",key);return -1;}return 0;
}
struct json_object *iptv_storage_preflight(struct json_object *cfg)
{
    struct json_object *out=json_object_new_object(),*checks=json_object_new_array();int valid=1;
    const char *keys[]={"cache_path","recording_path"};
    for(int i=0;i<2;i++){
        if(!*iptv_string(cfg,keys[i])&&(i||!iptv_integer(cfg,"enabled",0)))continue;
        struct json_object *row=json_object_new_object();struct iptv_error error={0};char resolved[PATH_MAX];
        int rc=storage_path(cfg,keys[i],resolved,&error);if(rc)valid=0;
        json_object_object_add(row,"field",json_object_new_string(keys[i]));json_object_object_add(row,"path",json_object_new_string(iptv_string(cfg,keys[i])));
        json_object_object_add(row,"valid",json_object_new_boolean(!rc));json_object_object_add(row,"error",rc?json_object_new_string(error.code):NULL);
        if(!rc){struct statvfs fs;if(!statvfs(resolved,&fs)){json_object_object_add(row,"free_bytes",json_object_new_int64(fs.f_bavail*(unsigned long long)fs.f_frsize));json_object_object_add(row,"total_bytes",json_object_new_int64(fs.f_blocks*(unsigned long long)fs.f_frsize));}}
        json_object_array_add(checks,row);
    }
    json_object_object_add(out,"valid",json_object_new_boolean(valid));json_object_object_add(out,"checks",checks);
    json_object_object_add(out,"pending_channels",iptv_runtime_pending());
    json_object_object_add(out,"file_policy",json_object_new_string("existing_tasks_keep_directory_no_move_or_delete"));
    return out;
}
static int cache_root(struct json_object *cfg,char *out,size_t size,struct iptv_error *e)
{return iptv_storage_root(cfg,"cache_path",".dreamingwrt-iptv",out,size,e);}
static int storage_ok(struct stream *s)
{
    struct stat st;struct statvfs fs;
    if(stat(s->dir,&st)||st.st_dev!=s->storage_device||st.st_ino!=s->storage_inode)return 0;
    if(statvfs(s->dir,&fs)||fs.f_bavail*(unsigned long long)fs.f_frsize<64ULL*1024*1024)return 0;
    /* Bound a live cache even for malformed inputs with unusually long GOPs. */
    DIR *dir=opendir(s->dir);if(!dir)return 0;struct dirent *ent;unsigned long long bytes=0;
    while((ent=readdir(dir))){char path[PATH_MAX];
        if(snprintf(path,sizeof(path),"%s/%s",s->dir,ent->d_name)<(int)sizeof(path)&&!lstat(path,&st)&&S_ISREG(st.st_mode))bytes+=(unsigned long long)st.st_size;
    }closedir(dir);return bytes<(unsigned long long)(s->cache_limit_mb?s->cache_limit_mb:128)*1024*1024;
}
static int remember_argv(struct stream *s,char *const *argv)
{
    for(int i=0;argv[i];i++){if(i>=95||!(s->argv[i]=strdup(argv[i])))return -1;}
    struct stat st;if(stat(s->dir,&st))return -1;s->storage_device=st.st_dev;s->storage_inode=st.st_ino;return 0;
}
static int spawn_media(struct stream *s,char *const *argv,const char *stdout_name)
{
    char out[PATH_MAX],err[PATH_MAX];
    if(snprintf(out,sizeof(out),"%s/%s",s->dir,stdout_name)>=(int)sizeof(out)||snprintf(err,sizeof(err),"%s/error.log",s->dir)>=(int)sizeof(err))return -1;
    int output=open(out,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
    /* Upstream tools can echo credential URLs in errors. Keep the typed
     * supervisor failure, and do not persist their raw stderr for such inputs. */
    int errors=open(s->sensitive_input?"/dev/null":err,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
    int input=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if(output<0||errors<0||input<0){if(output>=0)close(output);if(errors>=0)close(errors);if(input>=0)close(input);return -1;}
    pid_t parent=getpid();
    s->pid=fork();
    if(s->pid==0){
        /* Only async-signal-safe syscalls between fork and exec. Parent death
         * cannot leave a source connection running without its supervisor. */
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||setpgid(0,0))_exit(126);
        if(dup2(input,0)<0||dup2(output,1)<0||dup2(errors,2)<0)_exit(126);
        close(input);close(output);close(errors);
        execve(argv[0],argv,environ);_exit(127);
    }
    close(input);close(output);close(errors);
    if(s->pid<0){s->pid=0;return -1;}
    setpgid(s->pid,s->pid);
    return 0;
}
static int ready(struct stream *s)
{
    char p[PATH_MAX],*data=NULL;size_t len;
    if(snprintf(p,sizeof(p),"%s/window.m3u8",s->dir)>=(int)sizeof(p)||readfile(p,&data,&len))return 0;
    char *line=strstr(data,"\nseg");int yes=0;
    while(line){char name[64];if(sscanf(line+1,"%63[^\r\n]",name)==1&&media_name(name)){
        struct stat st;if(snprintf(p,sizeof(p),"%s/%s",s->dir,name)>=(int)sizeof(p)){free(data);return 0;}
        if(!stat(p,&st)&&st.st_size>0){yes=1;if(st.st_mtime>s->last_segment)s->last_segment=st.st_mtime;}
    }line=strstr(line+1,"\nseg");}
    free(data);return yes;
}
static int lease_count(sqlite3 *db,const char *id)
{
    sqlite3_stmt *s=NULL;int n=0;
    if(sqlite3_prepare_v2(db,"SELECT count(*) FROM iptv_preview WHERE channel=?1 AND expires>?2 AND token NOT IN(SELECT ticket FROM iptv_recording_lease) AND token NOT IN(SELECT ticket FROM iptv_deferred_lease)",-1,&s,NULL)==SQLITE_OK){
        sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(s,2,time(NULL));if(sqlite3_step(s)==SQLITE_ROW)n=sqlite3_column_int(s,0);
    }sqlite3_finalize(s);return n;
}
static int still_enabled(sqlite3 *db,const char *id)
{
    struct json_object *channel=iptv_record(db,"channels",id),*cfg=iptv_settings(db);
    int yes=iptv_channel_enabled(db,channel)&&iptv_integer(cfg,"enabled",0);
    if(channel)json_object_put(channel);
    if(cfg)json_object_put(cfg);
    return yes;
}
static void failed(struct stream *s,const char *error,time_t now)
{
    kill_group(s);snprintf(s->error,sizeof(s->error),"%s",error);
    if(s->retries<2&&!s->probing&&s->argv[0]){s->retries++;s->retry_at=now+3*s->retries;strcpy(s->state,"retrying");}
    else strcpy(s->state,"error");
}
static void encoder_finished(struct stream *s,int success,const char *error)
{
    struct encoder *codec=&encoders[s->encoder];
    codec->testing=0;codec->available=success;codec->probed_at=time(NULL);
    snprintf(codec->error,sizeof(codec->error),"%s",success?"":error);
    kill_group(s);cleanup(s);memset(s,0,sizeof(*s));
}
static void *supervise(void *arg)
{
    (void)arg;
    for(;;){sleep(1);pthread_mutex_lock(&lock);if(!running){pthread_mutex_unlock(&lock);break;}
        struct iptv_error e={0};sqlite3 *db=iptv_db(&e);time_t now=monotime();
        for(int i=0;i<MAX_STREAMS;i++){struct stream *s=&streams[i];
            if(!*s->id)continue;
            if(!s->probing&&(s->pid>0||!strcmp(s->state,"retrying"))&&db&&!still_enabled(db,s->id)){
                kill_group(s);cleanup(s);strcpy(s->state,"stopped");strcpy(s->error,"channel_unavailable");continue;
            }
            if(!s->probing&&!s->manual&&!s->recording&&db&&lease_count(db,s->id)==0&&now-s->last_request>s->idle){
                kill_group(s);cleanup(s);strcpy(s->state,"stopped");continue;
            }
            if(!strcmp(s->state,"retrying")&&now>=s->retry_at){
                if(!storage_ok(s)){strcpy(s->state,"error");strcpy(s->error,"storage_unavailable_or_budget_exceeded");continue;}
                s->started=now;s->last_segment=0;
                if(spawn_media(s,s->argv,"probe.json"))failed(s,"media_spawn_failed",now);
                else strcpy(s->state,"starting");
            }
            if(s->pid<=0)continue;
            if(s->probing==4){
                int status=0;pid_t done=waitpid(s->pid,&status,WNOHANG);
                if(done==s->pid){s->pid=0;encoder_finished(s,WIFEXITED(status)&&!WEXITSTATUS(status),"encoder_smoke_failed");}
                else if(now-s->started>s->timeout)encoder_finished(s,0,"encoder_smoke_timeout");
                else if(!storage_ok(s))encoder_finished(s,0,"storage_unavailable_or_budget_exceeded");
                continue;
            }
            if(!storage_ok(s)){kill_group(s);strcpy(s->state,"error");strcpy(s->error,"storage_unavailable_or_budget_exceeded");continue;}
            int status=0;pid_t done=waitpid(s->pid,&status,WNOHANG);
            if(done==s->pid){s->pid=0;
                if(s->probing>=2){int success=WIFEXITED(status)&&WEXITSTATUS(status)==0;strcpy(s->state,success?(s->probing==5?"snapshot_complete":s->probing==2?"archive_complete":"archive_verified"):"error");if(!success)strcpy(s->error,s->probing==5?"snapshot_failed":s->probing==2?"archive_failed":"archive_invalid");continue;}snprintf(s->state,sizeof(s->state),"%s",s->probing&&WIFEXITED(status)&&WEXITSTATUS(status)==0?"probe_complete":"error");
                if(!strcmp(s->state,"error"))failed(s,s->probing?"source_probe_failed":"media_process_exited",now);
                if(!strcmp(s->state,"probe_complete")){
                    char p[PATH_MAX];int video=0;
                    if(snprintf(p,sizeof(p),"%s/probe.json",s->dir)<(int)sizeof(p)){
                        struct json_object *probe=json_object_from_file(p),*tracks=NULL;
                        if(probe&&json_object_object_get_ex(probe,"streams",&tracks)&&json_object_is_type(tracks,json_type_array)){
                            for(size_t n=0;n<json_object_array_length(tracks);n++)if(!strcmp(iptv_string(json_object_array_get_idx(tracks,n),"codec_type"),"video"))video=1;
                        }
                        if(probe)json_object_put(probe);
                    }
                    if(!video){strcpy(s->state,"error");strcpy(s->error,"video_stream_not_found");}
                }
                continue;}
            if(s->probing){if(now-s->started>s->timeout){kill_group(s);strcpy(s->state,"error");strcpy(s->error,"source_timeout");}continue;}
            if(ready(s)&&s->last_segment>=time(NULL)-(now-s->started)){strcpy(s->state,"media_ready");s->error[0]=0;}
            if(!s->last_segment&&now-s->started>s->timeout){failed(s,"first_segment_timeout",now);}
            else if(s->last_segment&&time(NULL)-s->last_segment>30){failed(s,"stream_stalled",now);}
            
        }
        if(db){sqlite3_exec(db,"DELETE FROM iptv_preview WHERE expires<=unixepoch();DELETE FROM iptv_view_lease WHERE ticket NOT IN(SELECT token FROM iptv_preview);DELETE FROM iptv_recording_lease WHERE ticket NOT IN(SELECT token FROM iptv_preview);DELETE FROM iptv_deferred_lease WHERE ticket NOT IN(SELECT token FROM iptv_preview)",NULL,NULL,NULL);sqlite3_close(db);}
        pthread_mutex_unlock(&lock);
    }return NULL;
}
static int ensure_monitor(struct iptv_error *e)
{
    if(monitor_started)return 0;
    running=1;if(pthread_create(&monitor,NULL,supervise,NULL)){running=0;iptv_fail(e,503,"supervisor_unavailable","");return -1;}
    monitor_started=1;return 0;
}
static struct json_object *encoder_list(void)
{
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    for(int i=0;i<ENCODER_COUNT;i++){
        struct encoder *codec=&encoders[i];int compiled=encoder_compiled(i);
        struct json_object *row=json_object_new_object();
        json_object_object_add(row,"id",json_object_new_string(codec->id));
        json_object_object_add(row,"codec",json_object_new_string(codec->codec));
        json_object_object_add(row,"type",json_object_new_string(codec->type));
        json_object_object_add(row,"hardware",json_object_new_string(codec->hardware));
        json_object_object_add(row,"compiled",json_object_new_boolean(compiled));
        json_object_object_add(row,"runtime_available",codec->probed_at?json_object_new_boolean(codec->available):NULL);
        json_object_object_add(row,"state",json_object_new_string(codec->testing?"testing":codec->available?"available":codec->probed_at?"failed":"untested"));
        json_object_object_add(row,"reason",json_object_new_string(!compiled?"encoder_not_compiled":codec->testing?"encoder_smoke_pending":codec->available?"":*codec->error?codec->error:"encoder_smoke_required"));
        json_object_object_add(row,"probed_at",codec->probed_at?json_object_new_int64(codec->probed_at):NULL);
        json_object_array_add(items,row);
    }
    json_object_object_add(out,"items",items);return out;
}
struct json_object *iptv_encoder_request(const char *method,const char *id,struct json_object *cfg,struct iptv_error *e)
{
    pthread_mutex_lock(&lock);struct json_object *result=NULL;
    if(!strcmp(method,"GET")){result=encoder_list();goto out;}
    int index=encoder_index(id);if(index<0){iptv_fail(e,404,"encoder_unknown","id");goto out;}
    if(!strcmp(method,"DELETE")){
        for(int i=0;i<MAX_STREAMS;i++)if(streams[i].probing==4&&streams[i].encoder==index)encoder_finished(&streams[i],0,"encoder_smoke_cancelled");
        result=encoder_list();goto out;
    }
    if(strcmp(method,"POST")){iptv_fail(e,405,"method_not_allowed","");goto out;}
    if(!encoder_compiled(index)){iptv_fail(e,409,"encoder_not_compiled","id");goto out;}
    if(encoders[index].testing){iptv_fail(e,409,"encoder_smoke_pending","id");goto out;}
    int active=0;struct stream *s=NULL;
    for(int i=0;i<MAX_STREAMS;i++){
        if(streams[i].pid>0||!strcmp(streams[i].state,"retrying"))active++;
        else if(!s&&!(streams[i].probing>=2&&strcmp(streams[i].state,"stopped")))s=&streams[i];
    }
    if(!s||active>=iptv_integer(cfg,"max_streams",1)){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    char root[PATH_MAX],serial[49];if(cache_root(cfg,root,sizeof(root),e)||iptv_id(serial,sizeof(serial)))goto out;
    cleanup(s);memset(s,0,sizeof(*s));snprintf(s->id,sizeof(s->id),"encoder-%s",id);
    if(snprintf(s->dir,sizeof(s->dir),"%s/%s",root,serial)>=(int)sizeof(s->dir)||mkdir(s->dir,0700)){iptv_fail(e,507,"storage_not_writable","");goto out;}
    char input[PATH_MAX];snprintf(input,sizeof(input),"%s/smoke.raw",s->dir);
    int video=!strcmp(encoders[index].type,"video"),bytes=video?640*360*3/2:48000*2*2;
    unsigned char *sample=calloc(1,(size_t)bytes);FILE *fp=fopen(input,"wb");int good=sample&&fp;
    if(good){if(video){memset(sample,80,640*360);memset(sample+640*360,128,640*360/2);}
        for(int i=0;i<(video?25:1);i++)if(fwrite(sample,1,(size_t)bytes,fp)!=(size_t)bytes){good=0;break;}}
    if(fp&&fclose(fp))good=0;free(sample);
    if(!good){cleanup(s);iptv_fail(e,507,"storage_not_writable","");goto out;}
    char *argv[64]={IPTV_FFMPEG,"-nostdin","-v","error","-f",video?"rawvideo":"s16le",NULL};int n=6;
    if(video){argv[n++]="-pixel_format";argv[n++]="yuv420p";argv[n++]="-video_size";argv[n++]="640x360";argv[n++]="-framerate";argv[n++]="25";}
    else {argv[n++]="-ar";argv[n++]="48000";argv[n++]="-ac";argv[n++]="2";}
    if(!strcmp(encoders[index].hardware,"vaapi")){argv[n++]="-vaapi_device";argv[n++]="/dev/dri/renderD128";}
    argv[n++]="-i";argv[n++]=input;n=encoder_options(index,argv,n);
    argv[n++]=video?"-b:v":"-b:a";argv[n++]=video?"2000k":"192k";
    argv[n++]="-t";argv[n++]="1";argv[n++]="-f";argv[n++]="null";argv[n++]="-";argv[n]=NULL;
    s->probing=4;s->encoder=index;s->timeout=30;s->started=monotime();
    if(remember_argv(s,argv)||ensure_monitor(e)||spawn_media(s,argv,"probe.json")){cleanup(s);if(!e->status)iptv_fail(e,503,"media_spawn_failed","");goto out;}
    encoders[index].testing=1;encoders[index].available=0;strcpy(s->state,"testing");result=encoder_list();
out:pthread_mutex_unlock(&lock);return result;
}
struct json_object *iptv_runtime_capabilities(void)
{
    struct json_object *o=json_tokener_parse("{\"catalogue\":true,\"draft_probe\":true,\"input_options\":true,\"preview_sessions\":true,\"http_managed\":false,\"external_http\":true,\"input_bindings\":true,\"scans\":true,\"epg\":true,\"timeshift\":true,\"recordings\":true,\"viewer_grants\":true,\"provider_adapter\":true,\"m3u_import\":true,\"xlsx_import\":true,\"transcoding\":false,\"hls_containers\":[\"mpegts\",\"fmp4\"],\"video_modes\":[\"copy\"],\"audio_modes\":[\"copy\"]}");
    int available=protocol_compiled("http")&&strstr(tool_muxers," hls ");
    json_object_object_add(o,"ffmpeg_installed",json_object_new_boolean(access(IPTV_FFMPEG,X_OK)==0));
    json_object_object_add(o,"ffprobe_installed",json_object_new_boolean(access(IPTV_FFPROBE,X_OK)==0));
    json_object_object_add(o,"http_managed",json_object_new_boolean(available));
    json_object_object_add(o,"media_reason",available?NULL:json_object_new_string("media_dependency_missing"));
    struct json_object *protocols=json_object_new_array(),*matrix=json_object_new_array();
    const char *names[]={"http","https","udp","rtp","rtsp","rtmp",NULL};
    for(int i=0;names[i];i++){
        int compiled=protocol_compiled(names[i]);if(compiled)json_object_array_add(protocols,json_object_new_string(names[i]));
        struct json_object *row=json_object_new_object();json_object_object_add(row,"name",json_object_new_string(names[i]));
        json_object_object_add(row,"compiled",json_object_new_boolean(compiled));
        json_object_object_add(row,"runtime_available",NULL);
        json_object_object_add(row,"reason",json_object_new_string(compiled?"source_probe_required":"input_protocol_not_compiled"));
        json_object_object_add(row,"probed_at",json_object_new_int64(tools_probed_at));json_object_array_add(matrix,row);
    }
    json_object_object_add(o,"input_protocols",protocols);json_object_object_add(o,"input_capabilities",matrix);
    json_object_object_add(o,"snapshots",json_object_new_boolean(strstr(tool_encoders," mjpeg ")!=NULL));
    json_object_object_add(o,"network_apply",json_object_new_boolean(0));
    json_object_object_add(o,"scan_limit",json_object_new_int(128));
    json_object_object_add(o,"url_import",json_object_new_boolean(1));
    struct iptv_error ignored={0};sqlite3 *db=iptv_db(&ignored);
    int secrets=db&&iptv_access_available(db);if(db)sqlite3_close(db);
    json_object_object_add(o,"source_credentials",json_object_new_boolean(secrets));
    json_object_object_add(o,"source_credentials_reason",secrets?NULL:json_object_new_string("source_secret_store_unavailable"));
    struct json_object *codecs=iptv_encoder_request("GET","",NULL,&ignored),*items=NULL;
    json_object_object_get_ex(codecs,"items",&items);json_object_object_add(o,"encoders",json_object_get(items));
    struct json_object *video=json_object_new_array(),*audio=json_object_new_array();int transcode=0;
    json_object_array_add(video,json_object_new_string("copy"));json_object_array_add(audio,json_object_new_string("copy"));
    for(size_t i=0;i<json_object_array_length(items);i++){
        struct json_object *row=json_object_array_get_idx(items,i);if(!iptv_integer(row,"runtime_available",0))continue;
        json_object_array_add(!strcmp(iptv_string(row,"type"),"video")?video:audio,json_object_new_string(iptv_string(row,"id")));transcode=1;
    }
    json_object_object_add(o,"video_modes",video);json_object_object_add(o,"audio_modes",audio);
    json_object_object_add(o,"transcoding",json_object_new_boolean(transcode));json_object_put(codecs);
    return o;
}
struct json_object *iptv_runtime_start(struct json_object *c,struct json_object *cfg,int manual,struct iptv_error *e)
{
    if(access(IPTV_FFMPEG,X_OK)||access(IPTV_FFPROBE,X_OK))return iptv_fail(e,503,"media_dependency_missing","");
    if(input_gate(c,e))return NULL;
    if(!strstr(tool_muxers," hls "))return iptv_fail(e,409,"hls_output_not_compiled","");
    sqlite3 *input_db=iptv_db(e);if(!input_db)return NULL;
    char input[2304];int input_rc=iptv_source_url(input_db,c,input,sizeof(input),1,e);sqlite3_close(input_db);if(input_rc)return NULL;
    int fmp4=!strcmp(iptv_string(c,"hls_container"),"fmp4"),aac=0;
    char root[PATH_MAX],serial[49];if(cache_root(cfg,root,sizeof(root),e)||iptv_id(serial,sizeof(serial)))return NULL;
    pthread_mutex_lock(&lock);struct json_object *r=NULL;struct stream *s=find(iptv_string(c,"id"));
    if(s&&!s->probing&&(s->pid>0||!strcmp(s->state,"retrying"))){s->last_request=monotime();if(manual==1)s->manual=1;if(manual==2)s->recording=1;r=describe(s);goto out;}
    int video=encoder_index(iptv_string(c,"video_encoder")),audio=encoder_index(iptv_string(c,"audio_encoder"));
    if((video>=0&&!encoders[video].available)||(audio>=0&&!encoders[audio].available)){iptv_fail(e,409,"encoder_smoke_required",video>=0&&!encoders[video].available?"video_encoder":"audio_encoder");goto out;}
    int transcoding=video>=0||audio>=0,transcodes=0;
    for(int i=0;i<MAX_STREAMS;i++)if(streams[i].transcoding&&(streams[i].pid>0||!strcmp(streams[i].state,"retrying")))transcodes++;
    if(transcoding&&transcodes>=iptv_integer(cfg,"max_transcodes",1)){iptv_fail(e,429,"transcode_budget_exhausted","");goto out;}
    const char *source=iptv_string(c,"source_url");
    if(strncmp(source,"http://",7)&&strncmp(source,"https://",8)&&(!s||s->probing!=1||strcmp(s->state,"probe_complete")||s->revision!=iptv_integer(c,"revision",0))){iptv_fail(e,409,"source_probe_required","source_url");goto out;}
    int active=0;for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid>0||!strcmp(streams[i].state,"retrying"))active++;
    if(active>=iptv_integer(cfg,"max_streams",1)){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    if(!s)for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid<=0&&strcmp(streams[i].state,"retrying")&&!(streams[i].probing>=2&&strcmp(streams[i].state,"stopped"))){s=&streams[i];break;}
    if(!s){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    if(s->pid>0){iptv_fail(e,409,"probe_in_progress","");goto out;}
    if(fmp4){
        if(!s->probing||strcmp(s->state,"probe_complete")||s->revision!=iptv_integer(c,"revision",0)){iptv_fail(e,409,"source_probe_required","hls_container");goto out;}
        char path[PATH_MAX];struct json_object *probe=NULL,*tracks=NULL;
        if(snprintf(path,sizeof(path),"%s/probe.json",s->dir)<(int)sizeof(path))probe=json_object_from_file(path);
        if(probe&&json_object_object_get_ex(probe,"streams",&tracks))for(size_t i=0;i<json_object_array_length(tracks);i++){
            struct json_object *track=json_object_array_get_idx(tracks,i);
            if(!strcmp(iptv_string(track,"codec_type"),"audio")){aac=!strcmp(iptv_string(track,"codec_name"),"aac");break;}
        }
        if(probe)json_object_put(probe);
    }
    cleanup(s);memset(s,0,sizeof(*s));
    s->sensitive_input=iptv_integer(c,"has_access_url",0)||*iptv_string(c,"access_url");
    s->transcoding=transcoding;
    snprintf(s->id,sizeof(s->id),"%s",iptv_string(c,"id"));
    if(snprintf(s->dir,sizeof(s->dir),"%s/%s",root,serial)>=(int)sizeof(s->dir)||mkdir(s->dir,0700)){iptv_fail(e,507,"storage_not_writable","");goto out;}
    char segment[PATH_MAX],playlist[PATH_MAX],duration[16],count[16];
    if(snprintf(segment,sizeof(segment),fmp4?"%s/seg%%09d.m4s":"%s/seg%%09d.ts",s->dir)>=(int)sizeof(segment)||snprintf(playlist,sizeof(playlist),"%s/window.m3u8",s->dir)>=(int)sizeof(playlist)){iptv_fail(e,400,"invalid_parameter","cache_path");goto out;}
    s->timeshift_minutes=iptv_integer(c,"timeshift_minutes",0);s->live_count=iptv_integer(cfg,"window_segments",6);s->cache_limit_mb=iptv_integer(cfg,"cache_limit_mb",128);
    int seconds=iptv_integer(cfg,"segment_seconds",2),retention=s->timeshift_minutes*60/seconds;
    snprintf(duration,sizeof(duration),"%d",seconds);snprintf(count,sizeof(count),"%d",retention>s->live_count?retention:s->live_count);
    char video_map[40]="0:v:0",audio_map[40]="0:a:0?";
    int program=iptv_integer(c,"program_id",0);
    if(program){snprintf(video_map,sizeof(video_map),"0:p:%d:v:0",program);snprintf(audio_map,sizeof(audio_map),"0:p:%d:a:0?",program);}
    char *argv[96]={IPTV_FFMPEG,"-nostdin","-hide_banner","-loglevel","error",!strncmp(input,"rtsp://",7)?"-timeout":"-rw_timeout","10000000",
        "-protocol_whitelist","http,https,tcp,tls,crypto,udp,rtp,rtmp","-i",input,
        "-map",video_map,"-map",audio_map,"-c","copy","-f","hls","-hls_time",duration,"-hls_list_size",count,
        "-hls_flags","delete_segments+temp_file+omit_endlist+discont_start+program_date_time","-hls_start_number_source","epoch",
        "-hls_segment_type",fmp4?"fmp4":"mpegts","-hls_fmp4_init_filename","init.mp4","-hls_segment_filename",segment,NULL};
    int argc=0;while(argv[argc])argc++;
    /* The RTP demuxer consumes the URL itself and does not accept rw_timeout.
     * Its startup/stall deadline is enforced by the supervisor above. */
    if(!strncmp(input,"rtp://",6)){
        memmove(argv+5,argv+7,(argc-7+1)*sizeof(*argv));argc-=2;
    }
    if(!strncmp(input,"rtsp://",7)||*iptv_string(c,"user_agent")){
        int at=0;while(argv[at]&&strcmp(argv[at],"-i"))at++;
        memmove(argv+at+2,argv+at,(argc-at+1)*sizeof(*argv));argc+=2;
        argv[at]=!strncmp(input,"rtsp://",7)?"-rtsp_transport":"-user_agent";
        argv[at+1]=(char*)(!strncmp(input,"rtsp://",7)?(*iptv_string(c,"rtsp_transport")?iptv_string(c,"rtsp_transport"):"tcp"):iptv_string(c,"user_agent"));
    }
    if(video>=0&&!strcmp(encoders[video].hardware,"vaapi")){
        int at=0;while(argv[at]&&strcmp(argv[at],"-i"))at++;
        memmove(argv+at+2,argv+at,(argc-at+1)*sizeof(*argv));argc+=2;argv[at]="-vaapi_device";argv[at+1]="/dev/dri/renderD128";
    }
    char video_rate[24],audio_rate[24],keyframes[48];
    if(video>=0){
        argc=encoder_options(video,argv,argc);snprintf(video_rate,sizeof(video_rate),"%dk",iptv_integer(c,"video_bitrate_kbps",2000));
        argv[argc++]="-b:v";argv[argc++]=video_rate;
        snprintf(keyframes,sizeof(keyframes),"expr:gte(t,n_forced*%d)",seconds);argv[argc++]="-force_key_frames";argv[argc++]=keyframes;
        if(!strcmp(encoders[video].codec,"hevc")){argv[argc++]="-tag:v";argv[argc++]="hvc1";}
    }else {argv[argc++]="-c:v";argv[argc++]="copy";}
    if(audio>=0){
        argc=encoder_options(audio,argv,argc);snprintf(audio_rate,sizeof(audio_rate),"%dk",iptv_integer(c,"audio_bitrate_kbps",192));
        argv[argc++]="-b:a";argv[argc++]=audio_rate;argv[argc++]="-ar";argv[argc++]="48000";argv[argc++]="-ac";argv[argc++]="2";
    }else {argv[argc++]="-c:a";argv[argc++]="copy";}
    if(fmp4&&aac&&audio<0){argv[argc++]="-bsf:a";argv[argc++]="aac_adtstoasc";}
    argv[argc++]=playlist;argv[argc]=NULL;
    s->timeout=iptv_integer(cfg,"first_segment_seconds",20);s->idle=iptv_integer(cfg,"idle_seconds",30);
    s->revision=iptv_integer(c,"revision",0);s->settings_revision=iptv_integer(cfg,"revision",0);s->manual=manual==1;s->recording=manual==2;s->started=s->last_request=monotime();
    if(remember_argv(s,argv)||ensure_monitor(e)||spawn_media(s,argv,"probe.json")){cleanup(s);if(!e->status)iptv_fail(e,503,"media_spawn_failed","");goto out;}
    strcpy(s->state,"starting");r=describe(s);
out:pthread_mutex_unlock(&lock);return r;
}
struct json_object *iptv_runtime_stop(const char *id,struct iptv_error *e)
{
    (void)e;pthread_mutex_lock(&lock);struct stream *s=find(id);
    if(s){kill_group(s);strcpy(s->state,"stopped");strcpy(s->error,"stopped_by_operator");cleanup(s);}
    struct json_object *r=describe(s);pthread_mutex_unlock(&lock);return r;
}
static struct json_object *runtime_inspect(struct json_object *c,const char *operation,int snapshot,struct iptv_error *e)
{
    if(!strcmp(iptv_string(c,"mode"),"external"))return iptv_fail(e,409,"external_source_not_hosted","");
    if(access(IPTV_FFPROBE,X_OK))return iptv_fail(e,503,"media_dependency_missing","");
    if(input_gate(c,e))return NULL;
    sqlite3 *db=iptv_db(e);if(!db)return NULL;struct json_object *cfg=iptv_settings(db);sqlite3_close(db);
    char input[2304];db=iptv_db(e);if(!db){json_object_put(cfg);return NULL;}int input_rc=iptv_source_url(db,c,input,sizeof(input),1,e);sqlite3_close(db);if(input_rc){json_object_put(cfg);return NULL;}
    char root[PATH_MAX],serial[49];int rc=cache_root(cfg,root,sizeof(root),e);int max=iptv_integer(cfg,"max_streams",1);json_object_put(cfg);
    if(rc||iptv_id(serial,sizeof(serial)))return NULL;
    pthread_mutex_lock(&lock);struct json_object *r=NULL;struct stream *s=find(operation);int active=0;
    if(s&&s->pid>0){iptv_fail(e,409,"channel_busy","");goto out;}
    for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid>0||!strcmp(streams[i].state,"retrying"))active++;
    if(active>=max){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    if(!s)for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid<=0&&strcmp(streams[i].state,"retrying")&&!(streams[i].probing>=2&&strcmp(streams[i].state,"stopped"))){s=&streams[i];break;}
    if(!s){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    cleanup(s);memset(s,0,sizeof(*s));snprintf(s->id,sizeof(s->id),"%s",operation);
    s->sensitive_input=iptv_integer(c,"has_access_url",0)||*iptv_string(c,"access_url");
    if(snprintf(s->dir,sizeof(s->dir),"%s/%s",root,serial)>=(int)sizeof(s->dir)||mkdir(s->dir,0700)){iptv_fail(e,507,"storage_not_writable","");goto out;}
    char *argv[32]={IPTV_FFPROBE,"-v","error",!strncmp(input,"rtsp://",7)?"-timeout":"-rw_timeout","5000000","-protocol_whitelist","http,https,tcp,tls,crypto,udp,rtp,rtmp","-analyzeduration","3000000","-probesize","3000000","-show_entries","stream:program:format=format_name,duration,bit_rate","-of","json",input,NULL};
    int argc=0;while(argv[argc])argc++;
    if(!strncmp(input,"rtp://",6)){
        memmove(argv+3,argv+5,(argc-5+1)*sizeof(*argv));argc-=2;
    }
    if(!strncmp(input,"rtsp://",7)||*iptv_string(c,"user_agent")){
        memmove(argv+argc+1,argv+argc-1,2*sizeof(*argv));
        argv[argc-1]=!strncmp(input,"rtsp://",7)?"-rtsp_transport":"-user_agent";
        argv[argc]=(char*)(!strncmp(input,"rtsp://",7)?(*iptv_string(c,"rtsp_transport")?iptv_string(c,"rtsp_transport"):"tcp"):iptv_string(c,"user_agent"));
    }
    char output[PATH_MAX],map[48]="0:v:0";
    snprintf(output,sizeof(output),"%s/snapshot.jpg",s->dir);
    if(iptv_integer(c,"program_id",0))snprintf(map,sizeof(map),"0:p:%d:v:0",iptv_integer(c,"program_id",0));
    char *shot[48]={IPTV_FFMPEG,"-nostdin","-v","error","-rw_timeout","5000000","-protocol_whitelist","http,https,tcp,tls,crypto,udp,rtp,rtmp",NULL};int n=8;
    if(!strncmp(input,"rtp://",6)){memmove(shot+4,shot+6,3*sizeof(*shot));n-=2;}
    if(!strncmp(input,"rtsp://",7)){shot[4]="-timeout";shot[n++]="-rtsp_transport";shot[n++]=(char*)(*iptv_string(c,"rtsp_transport")?iptv_string(c,"rtsp_transport"):"tcp");}
    if(*iptv_string(c,"user_agent")){shot[n++]="-user_agent";shot[n++]=(char*)iptv_string(c,"user_agent");}
    char *tail[]={"-i",input,"-map",map,"-frames:v","1","-vf","scale=640:360:force_original_aspect_ratio=decrease","-c:v","mjpeg","-q:v","3","-f","image2","-update","1","-y",output,NULL};
    for(int i=0;tail[i];i++)shot[n++]=tail[i];shot[n]=NULL;
    char **command=snapshot?shot:argv;
    s->revision=iptv_integer(c,"revision",0);s->probing=snapshot?5:1;s->timeout=iptv_integer(c,"probe_seconds",10);s->started=monotime();
    if(remember_argv(s,command)||ensure_monitor(e)||spawn_media(s,command,"probe.json")){cleanup(s);if(!e->status)iptv_fail(e,503,"media_spawn_failed","");goto out;}
    strcpy(s->state,"probing");r=describe(s);
out:pthread_mutex_unlock(&lock);return r;
}
struct json_object *iptv_runtime_probe(struct json_object *c,struct iptv_error *e)
{return runtime_inspect(c,iptv_string(c,"id"),0,e);}
struct json_object *iptv_runtime_snapshot(struct json_object *c,const char *operation,struct iptv_error *e)
{return runtime_inspect(c,operation,1,e);}
int iptv_runtime_snapshot_read(const char *operation,char **data,size_t *length,struct iptv_error *e)
{
    pthread_mutex_lock(&lock);struct stream *s=find(operation);int rc=-1;char path[PATH_MAX];
    *data=NULL;*length=0;
    if(!s||s->probing!=5||strcmp(s->state,"snapshot_complete"))iptv_fail(e,409,"snapshot_not_ready","");
    else if(snprintf(path,sizeof(path),"%s/snapshot.jpg",s->dir)>=(int)sizeof(path)||readfile(path,data,length)||*length>512*1024||*length<4||memcmp(*data,"\xff\xd8",2)){
        free(*data);*data=NULL;*length=0;iptv_fail(e,409,"snapshot_invalid","");
    }else rc=0;
    pthread_mutex_unlock(&lock);return rc;
}
void iptv_runtime_hold(const char *id)
{pthread_mutex_lock(&lock);struct stream *s=find(id);if(s)s->last_request=monotime();pthread_mutex_unlock(&lock);}
int iptv_runtime_read(const char *id,const char *name,char **data,size_t *len,const char **type,struct iptv_error *e)
{
    long long from=0;int used=0,shift=sscanf(name,"at%lld.m3u8%n",&from,&used)==1&&used>0&&name[used]==0&&from>0;
    *data=NULL;*len=0;if(!media_name(name)&&!shift){iptv_fail(e,404,"resource_not_found","");return -1;}
    pthread_mutex_lock(&lock);struct stream *s=find(id);char p[PATH_MAX];int rc=-1;
    if(!s||s->probing||strcmp(s->state,"media_ready")){iptv_fail(e,503,s&&*s->error?s->error:"first_segment_pending","");goto out;}
    if(!strcmp(name,"index.m3u8")||shift){
        if(shift&&!s->timeshift_minutes){iptv_fail(e,409,"timeshift_disabled","");goto out;}
        struct json_object *window=iptv_window_read(s->dir,e);if(!window)goto out;
        rc=iptv_window_playlist(window,shift?(double)from:0,s->live_count,data,len,e);json_object_put(window);
        *type="application/vnd.apple.mpegurl";goto out;
    }
    if(snprintf(p,sizeof(p),"%s/%s",s->dir,name)>=(int)sizeof(p)||readfile(p,data,len)){iptv_fail(e,410,"segment_expired","");goto out;}
    *type=!strcmp(name,"index.m3u8")?"application/vnd.apple.mpegurl":strstr(name,".mp4")||strstr(name,".m4s")?"video/mp4":"video/mp2t";rc=0;
out:pthread_mutex_unlock(&lock);return rc;
}
void iptv_shutdown(void)
{
    pthread_mutex_lock(&lock);running=0;for(int i=0;i<MAX_STREAMS;i++){kill_group(&streams[i]);cleanup(&streams[i]);}
    int join=monitor_started;pthread_mutex_unlock(&lock);if(join)pthread_join(monitor,NULL);monitor_started=0;
}

struct json_object *iptv_runtime_pending(void)
{
    struct json_object *ids=json_object_new_array();pthread_mutex_lock(&lock);
    for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid>0||!strcmp(streams[i].state,"retrying"))json_object_array_add(ids,json_object_new_string(streams[i].id));
    pthread_mutex_unlock(&lock);return ids;
}

struct json_object *iptv_runtime_window(const char *id,struct iptv_error *e)
{
    pthread_mutex_lock(&lock);struct stream *s=find(id);struct json_object *o=NULL;
    if(!s||!s->timeshift_minutes)iptv_fail(e,409,"timeshift_disabled","");
    else if(s->probing||strcmp(s->state,"media_ready"))iptv_fail(e,503,"first_segment_pending","");
    else {o=iptv_window_read(s->dir,e);if(o){json_object_object_add(o,"generation",json_object_new_string(strrchr(s->dir,'/')+1));json_object_object_add(o,"configured_minutes",json_object_new_int(s->timeshift_minutes));}}
    pthread_mutex_unlock(&lock);return o;
}

void iptv_runtime_capture_release(const char *id)
{pthread_mutex_lock(&lock);struct stream *s=find(id);if(s)s->recording=0;pthread_mutex_unlock(&lock);}
struct json_object *iptv_runtime_capture_window(const char *id,struct iptv_error *e)
{
    pthread_mutex_lock(&lock);struct stream *s=find(id);struct json_object *window=NULL;
    if(!s||s->probing||strcmp(s->state,"media_ready"))iptv_fail(e,503,s&&*s->error?s->error:"first_segment_pending","");
    else{window=iptv_window_read(s->dir,e);if(window)json_object_object_add(window,"generation",json_object_new_string(strrchr(s->dir,'/')+1));}
    pthread_mutex_unlock(&lock);return window;
}
struct json_object *iptv_runtime_archive(const char *id,const char *input,const char *output,int verify,struct json_object *cfg,struct iptv_error *e)
{
    char root[PATH_MAX],serial[49];if(cache_root(cfg,root,sizeof(root),e)||iptv_id(serial,sizeof(serial)))return NULL;
    pthread_mutex_lock(&lock);struct json_object *result=NULL;struct stream *s=find(id);int active=0;
    if(s&&s->pid>0){result=describe(s);goto out;}
    for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid>0||!strcmp(streams[i].state,"retrying"))active++;
    if(active>=iptv_integer(cfg,"max_streams",1)){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    if(!s)for(int i=0;i<MAX_STREAMS;i++)if(streams[i].pid<=0&&strcmp(streams[i].state,"retrying")&&!(streams[i].probing>=2&&strcmp(streams[i].state,"stopped"))){s=&streams[i];break;}
    if(!s){iptv_fail(e,429,"media_budget_exhausted","");goto out;}
    cleanup(s);memset(s,0,sizeof(*s));snprintf(s->id,sizeof(s->id),"%s",id);
    if(snprintf(s->dir,sizeof(s->dir),"%s/%s",root,serial)>=(int)sizeof(s->dir)||mkdir(s->dir,0700)){iptv_fail(e,507,"storage_not_writable","");goto out;}
    char *remux[]={IPTV_FFMPEG,"-nostdin","-v","error","-i",(char*)input,"-map","0:v:0","-map","0:a:0?","-c","copy","-avoid_negative_ts","make_zero","-movflags","+faststart","-f","mp4","-y",(char*)output,NULL};
    char *decode[]={IPTV_FFMPEG,"-nostdin","-v","error","-xerror","-i",(char*)output,"-t","3","-f","null","-",NULL};
    char **argv=verify?decode:remux;s->probing=verify?3:2;s->timeout=60;s->started=monotime();
    if(remember_argv(s,argv)||ensure_monitor(e)||spawn_media(s,argv,"probe.json")){cleanup(s);if(!e->status)iptv_fail(e,503,"media_spawn_failed","");goto out;}
    strcpy(s->state,verify?"verifying":"archiving");result=describe(s);
out:pthread_mutex_unlock(&lock);return result;
}
