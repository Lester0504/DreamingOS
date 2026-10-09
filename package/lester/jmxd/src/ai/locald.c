/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <curl/curl.h>
#include "local_ipc.h"
#define STATE_DIR "/etc/dreamingwrt/ai-local"
#define CATALOG "/usr/share/dreamingwrt/ai-local/catalog.json"
#define ENGINE "/usr/libexec/dreamingwrt-ai-rkllm"
static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
static sqlite3 *db;
static struct json_object *catalog,*config,*task;
static int task_busy,engine_busy,engine_fd=-1,clients;
static atomic_int cancel_task;
static pid_t engine_pid;
static char loaded[96],loaded_volume[512],active_id[128],active_actor[128],service_state[32]="stopped";
static int64_t now(void){return (int64_t)time(NULL);}
static int valid_id(const char *s){size_t n=strlen(s);if(!n||n>80)return 0;for(size_t i=0;i<n;i++)if(!((s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||s[i]=='-'||s[i]=='_'))return 0;return 1;}
static struct json_object *copy(struct json_object *j){return j?json_tokener_parse(json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN)):json_object_new_object();}
static int put(const char *key,struct json_object *j){sqlite3_stmt *s=NULL;int rc=sqlite3_prepare_v2(db,"INSERT OR REPLACE INTO state(k,v) VALUES(?,?)",-1,&s,NULL);if(!rc){sqlite3_bind_text(s,1,key,-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);rc=sqlite3_step(s)==SQLITE_DONE?0:-1;}sqlite3_finalize(s);return rc;}
static struct json_object *get(const char *key){sqlite3_stmt *s=NULL;struct json_object *j=NULL;if(!sqlite3_prepare_v2(db,"SELECT v FROM state WHERE k=?",-1,&s,NULL)){sqlite3_bind_text(s,1,key,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW)j=json_tokener_parse((const char*)sqlite3_column_text(s,0));}sqlite3_finalize(s);return j;}
static int task_save(void){char k[128];snprintf(k,sizeof(k),"task/%s",al_s(task,"task_id"));al_num(task,"updated_at",now());return put(k,task)||put("last_task",task)?-1:0;}
static struct json_object *model(const char *id){struct json_object *a=json_object_object_get(catalog,"models");for(size_t i=0;i<json_object_array_length(a);i++){struct json_object *m=json_object_array_get_idx(a,i);if(!strcmp(al_s(m,"id"),id))return m;}return NULL;}
static int64_t memory_free(void){FILE *f=fopen("/proc/meminfo","r");char b[256];long long k;if(!f)return -1;while(fgets(b,sizeof(b),f))if(sscanf(b,"MemAvailable: %lld kB",&k)==1){fclose(f);return k*1024;}fclose(f);return -1;}
static struct json_object *volumes(void){struct json_object *a=json_object_new_array();FILE *f=setmntent("/proc/mounts","r");struct mntent *m;if(!f)return a;
    while((m=getmntent(f))){if(!strcmp(m->mnt_dir,"/")||hasmntopt(m,"ro")||(strcmp(m->mnt_type,"ext4")&&strcmp(m->mnt_type,"ext3")&&strcmp(m->mnt_type,"btrfs")&&strcmp(m->mnt_type,"xfs")&&strcmp(m->mnt_type,"f2fs")))continue;
        struct statvfs s;if(statvfs(m->mnt_dir,&s))continue;struct json_object *v=json_object_new_object();al_str(v,"id",m->mnt_dir);al_str(v,"path",m->mnt_dir);al_str(v,"filesystem",m->mnt_type);al_num(v,"available_bytes",(int64_t)s.f_bavail*s.f_frsize);json_object_array_add(a,v);
    }endmntent(f);return a;
}
static int volume_ok(const char *id,int64_t need){struct json_object *a=volumes();int ok=0;for(size_t i=0;i<json_object_array_length(a);i++){struct json_object *v=json_object_array_get_idx(a,i);if(!strcmp(al_s(v,"id"),id)&&al_i(v,"available_bytes")>=need)ok=1;}json_object_put(a);return ok;}
static int file_path(char *out,size_t n,const char *vol,const char *id,const char *suffix){if(!valid_id(id)||!volume_ok(vol,0))return -1;return snprintf(out,n,"%s/.dreamingwrt-ai/%s%s",vol,id,suffix)>=(int)n?-1:0;}
static int hash_file(const char *path,char out[65],int64_t expected){int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat st;if(fd<0)return -1;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size!=expected){close(fd);return -1;}EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned char b[65536],hash[32];unsigned int n=0;int ok=ctx&&EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1;ssize_t r=0;
    while(ok&&(r=read(fd,b,sizeof(b)))>0)ok=EVP_DigestUpdate(ctx,b,(size_t)r)==1;
    if(r<0)ok=0;if(ok)ok=EVP_DigestFinal_ex(ctx,hash,&n)==1&&n==32;EVP_MD_CTX_free(ctx);close(fd);if(!ok)return -1;for(unsigned i=0;i<n;i++)snprintf(out+i*2,3,"%02x",hash[i]);return 0;
}
static int model_valid(struct json_object *m){const char *sha=al_s(m,"sha256");if(!m||!valid_id(al_s(m,"id"))||strcmp(al_s(m,"format"),"rkllm")||strcmp(al_s(m,"runtime"),"rkllm-1.3.1")||strcmp(al_s(m,"profile_id"),"rk3588-rkllm-1.3.1")||strlen(sha)!=64||al_i(m,"size_bytes")<=0||al_i(m,"required_memory_bytes")<=0)return 0;for(int i=0;i<64;i++)if(!strchr("0123456789abcdef",sha[i]))return 0;return !strncmp(al_s(m,"url"),"https://",8)&&!strcmp(al_s(m,"template"),"chatml")&&al_i(m,"context_tokens")>0&&al_i(m,"context_tokens")<=8192&&al_i(m,"max_tokens")>0&&al_i(m,"max_tokens")<=4096;}
static const char *hardware_reason(struct json_object **profile_out){char compat[512]={0},driver[128]={0};FILE *f=fopen("/proc/device-tree/compatible","r");size_t n=f?fread(compat,1,sizeof(compat)-1,f):0;if(f)fclose(f);for(size_t i=0;i<n;i++)if(!compat[i])compat[i]=' ';
    if(!n){struct utsname u;if(uname(&u)||!strncmp(u.machine,"aarch",5)||!strncmp(u.machine,"arm",3))return "hardware_detection_failed";}
    if(!strstr(compat,"rockchip,rk3588"))return "no_supported_inference_device";
    struct json_object *a=json_object_object_get(catalog,"profiles"),*p=NULL;for(size_t i=0;i<json_object_array_length(a);i++){struct json_object *x=json_object_array_get_idx(a,i);if(!strcmp(al_s(x,"compatible"),"rockchip,rk3588")){p=x;break;}}
    if(profile_out)*profile_out=p;if(!p||!al_i(p,"validated"))return "hardware_profile_unverified";
    if(access(ENGINE,X_OK)||access("/usr/lib/librkllmrt.so",R_OK))return "runtime_missing";
    f=fopen("/sys/module/rknpu/version","r");if(f){if(!fgets(driver,sizeof(driver),f))driver[0]=0;fclose(f);driver[strcspn(driver,"\r\n")]=0;}
    if(!driver[0]||strcmp(driver,al_s(p,"driver_version")))return "runtime_incompatible";
    /* The published profile pins both the SDK ABI and runtime binary. */
    struct stat st;char hash[65],libpath[4096];if(!realpath("/usr/lib/librkllmrt.so",libpath)||stat(libpath,&st)||hash_file(libpath,hash,st.st_size)||strcmp(hash,al_s(p,"library_sha256"))||strcmp(al_s(p,"runtime"),"rkllm-1.3.1"))return "runtime_incompatible";
    return "";
}
static void engine_check(void){if(!task_busy&&!engine_busy&&engine_pid&&waitpid(engine_pid,NULL,WNOHANG)==engine_pid){engine_pid=0;if(engine_fd>=0)close(engine_fd);engine_fd=-1;loaded[0]=0;snprintf(service_state,sizeof(service_state),"failed");}}
static int installed(struct json_object *m,const char *vol){char key[700],path[768];struct stat s;if(!m||file_path(path,sizeof(path),vol,al_s(m,"id"),".rkllm"))return 0;snprintf(key,sizeof(key),"model/%s/%s",vol,al_s(m,"id"));struct json_object *j=get(key);int ok=j&&!strcmp(al_s(j,"sha256"),al_s(m,"sha256"))&&!lstat(path,&s)&&S_ISREG(s.st_mode)&&s.st_size==al_i(m,"size_bytes");if(j)json_object_put(j);return ok;}
static struct json_object *status_data(void){engine_check();struct json_object *j=json_object_new_object(),*hw=json_object_new_object(),*rt=json_object_new_object(),*res=json_object_new_object(),*md=json_object_new_object(),*svc=json_object_new_object(),*ops=json_object_new_object(),*p=NULL;struct utsname u;int detected=uname(&u)==0;const char *hw_reason=hardware_reason(&p),*reason=hw_reason;struct json_object *m=model(al_s(config,"model_id"));int have=installed(m,al_s(config,"volume_id"));
    if(!reason[0]&&!m)reason="model_missing";else if(!reason[0]&&!have)reason="model_missing";else if(!reason[0]&&!engine_pid)reason=!strcmp(service_state,"failed")?"inference_unavailable":"service_stopped";
    al_bool(j,"implemented",1);al_bool(j,"detection_implemented",1);json_object_object_add(j,"supported",!strcmp(hw_reason,"hardware_detection_failed")?NULL:json_object_new_boolean(!hw_reason[0]));al_bool(j,"ready",engine_pid&&!engine_busy&&!task_busy&&!strcmp(service_state,"ready"));al_str(j,"state",engine_busy?"busy":task_busy?al_s(task,"phase"):!reason[0]?"ready":reason);al_str(j,"reason",reason);al_num(j,"checked_at",now());
    al_str(hw,"architecture",detected?u.machine:NULL);al_str(hw,"device",p?al_s(p,"compatible"):NULL);al_str(hw,"profile_id",p?al_s(p,"id"):NULL);al_bool(hw,"validated",p&&al_i(p,"validated"));
    al_str(rt,"adapter","rkllm");al_str(rt,"version","1.3.1");al_bool(rt,"installed",access(ENGINE,X_OK)==0&&access("/usr/lib/librkllmrt.so",R_OK)==0);al_str(rt,"driver_abi",!hw_reason[0]?"matched":"unverified");al_bool(rt,"healthy",engine_pid>0);
    int64_t mem=memory_free();json_object_object_add(res,"available_memory_bytes",mem<0?NULL:json_object_new_int64(mem));al_str(res,"volume_id",al_s(config,"volume_id"));json_object_object_add(res,"required_memory_bytes",m?json_object_new_int64(al_i(m,"required_memory_bytes")):NULL);json_object_object_add(res,"required_storage_bytes",m?json_object_new_int64(al_i(m,"size_bytes")):NULL);struct statvfs disk;json_object_object_add(res,"available_storage_bytes",volume_ok(al_s(config,"volume_id"),0)&&!statvfs(al_s(config,"volume_id"),&disk)?json_object_new_int64((int64_t)disk.f_bavail*disk.f_frsize):NULL);
    al_str(md,"selected_id",al_s(config,"model_id"));al_str(md,"loaded_id",loaded[0]?loaded:NULL);al_str(md,"format","rkllm");al_str(md,"state",have?"ready":"model_missing");al_str(svc,"state",engine_busy?"busy":service_state);al_bool(svc,"healthy",engine_pid>0);al_bool(svc,"managed",1);al_bool(svc,"tool_calling",0);
    const char *names[]={"download","cancel_download","start","stop","switch","generate"};int supported=!hw_reason[0];int avail[]={supported&&!task_busy,supported&&task_busy&&!strcmp(al_s(task,"action"),"download"),supported&&have&&!task_busy&&!engine_pid,engine_pid&&!engine_busy&&!task_busy,supported&&have&&!task_busy&&!engine_busy,engine_pid&&!engine_busy&&!task_busy};
    for(int i=0;i<6;i++){struct json_object *v=json_object_new_object();al_bool(v,"available",avail[i]);al_str(v,"reason",avail[i]?"":task_busy?"task_in_progress":engine_busy?"model_in_use":reason);json_object_object_add(ops,names[i],v);}
    json_object_object_add(j,"hardware",hw);json_object_object_add(j,"runtime",rt);json_object_object_add(j,"resources",res);json_object_object_add(j,"model",md);json_object_object_add(j,"service",svc);json_object_object_add(j,"operations",ops);json_object_object_add(j,"config",copy(config));json_object_object_add(j,"task",task?copy(task):NULL);al_str(j,"status_endpoint","/api/v1/ai/local/status");al_str(j,"models_endpoint","/api/v1/ai/local/models");return j;
}
static int engine_stop(void){if(!engine_pid)return 0;kill(engine_pid,SIGTERM);for(int i=0;i<100;i++){if(waitpid(engine_pid,NULL,WNOHANG)==engine_pid)goto done;usleep(100000);}kill(engine_pid,SIGKILL);waitpid(engine_pid,NULL,0);
 done:engine_pid=0;if(engine_fd>=0)close(engine_fd);engine_fd=-1;loaded[0]=0;loaded_volume[0]=0;snprintf(service_state,sizeof(service_state),"stopped");return 0;}
static int engine_start(struct json_object *m,const char *path){int pair[2];if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair))return -1;char context[32],tokens[32];snprintf(context,sizeof(context),"%lld",(long long)al_i(m,"context_tokens"));snprintf(tokens,sizeof(tokens),"%lld",(long long)al_i(m,"max_tokens"));pid_t pid=fork();if(pid<0){close(pair[0]);close(pair[1]);return -1;}if(!pid){dup2(pair[1],3);fcntl(3,F_SETFD,0);for(int i=4;i<1024;i++)close(i);execl(ENGINE,ENGINE,path,context,tokens,al_s(m,"id"),(char*)NULL);_exit(127);}close(pair[1]);struct json_object *j=al_recv(pair[0],180000);int ok=j&&!strcmp(al_s(j,"event"),"loaded");if(j)json_object_put(j);
    pthread_mutex_lock(&mu);engine_pid=pid;engine_fd=pair[0];if(!ok){engine_stop();snprintf(service_state,sizeof(service_state),"failed");pthread_mutex_unlock(&mu);return -1;}
    snprintf(loaded,sizeof(loaded),"%s",al_s(m,"id"));snprintf(service_state,sizeof(service_state),"ready");pthread_mutex_unlock(&mu);return 0;}
struct download {int fd;int64_t size,done;time_t updated;};
static size_t download_write(char *b,size_t n,size_t z,void *arg){struct download *d=arg;size_t len=n*z;if(atomic_load(&cancel_task)||len>(uint64_t)(d->size-d->done))return 0;size_t off=0;while(off<len){ssize_t k=write(d->fd,b+off,len-off);if(k<0&&errno==EINTR)continue;if(k<=0)return 0;off+=(size_t)k;}d->done+=(int64_t)len;if(time(NULL)!=d->updated){d->updated=time(NULL);pthread_mutex_lock(&mu);al_num(task,"downloaded_bytes",d->done);task_save();pthread_mutex_unlock(&mu);}return len;}
static int download_progress(void *p,curl_off_t a,curl_off_t b,curl_off_t c,curl_off_t d){(void)p;(void)a;(void)b;(void)c;(void)d;return atomic_load(&cancel_task);}
static const char *download_model(struct json_object *m,const char *vol){char path[768],partial[768],dir[600];if(file_path(path,sizeof(path),vol,al_s(m,"id"),".rkllm"))return "volume_offline";if(file_path(partial,sizeof(partial),vol,al_s(task,"task_id"),".part"))return "volume_offline";
    snprintf(dir,sizeof(dir),"%s/.dreamingwrt-ai",vol);struct stat st;if(mkdir(dir,0700)&&errno!=EEXIST)return "storage_not_writable";if(lstat(dir,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid())return "storage_not_writable";
    struct download d={.fd=open(partial,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600),.size=al_i(m,"size_bytes")};if(d.fd<0)return "storage_not_writable";
    CURL *c=curl_easy_init();if(!c){close(d.fd);unlink(partial);return "download_unavailable";}
    curl_easy_setopt(c,CURLOPT_URL,al_s(m,"url"));curl_easy_setopt(c,CURLOPT_PROTOCOLS_STR,"https");curl_easy_setopt(c,CURLOPT_REDIR_PROTOCOLS_STR,"https");curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,1L);curl_easy_setopt(c,CURLOPT_MAXREDIRS,5L);curl_easy_setopt(c,CURLOPT_FAILONERROR,1L);curl_easy_setopt(c,CURLOPT_CONNECTTIMEOUT,20L);curl_easy_setopt(c,CURLOPT_LOW_SPEED_LIMIT,1024L);curl_easy_setopt(c,CURLOPT_LOW_SPEED_TIME,90L);curl_easy_setopt(c,CURLOPT_NOSIGNAL,1L);curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,download_write);curl_easy_setopt(c,CURLOPT_WRITEDATA,&d);curl_easy_setopt(c,CURLOPT_NOPROGRESS,0L);curl_easy_setopt(c,CURLOPT_XFERINFOFUNCTION,download_progress);
    CURLcode rc=curl_easy_perform(c);curl_easy_cleanup(c);int synced=fsync(d.fd);close(d.fd);const char *error=NULL;
    if(atomic_load(&cancel_task))error="download_cancelled";else if(rc!=CURLE_OK||d.done!=d.size||synced)error="download_failed";
    if(!error){pthread_mutex_lock(&mu);al_str(task,"phase","verifying");al_num(task,"downloaded_bytes",d.done);task_save();pthread_mutex_unlock(&mu);char hash[65];if(hash_file(partial,hash,d.size)||strcmp(hash,al_s(m,"sha256")))error="checksum_mismatch";}
    if(!error&&atomic_load(&cancel_task))error="download_cancelled";
    if(!error&&(!volume_ok(vol,0)||rename(partial,path)))error="model_register_failed";
    if(error)unlink(partial);else{int fd=open(dir,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd>=0){fsync(fd);close(fd);}pthread_mutex_lock(&mu);char key[700];snprintf(key,sizeof(key),"model/%s/%s",vol,al_s(m,"id"));if(put(key,m))error="model_register_failed";pthread_mutex_unlock(&mu);}return error;
}
static void *task_run(void *arg){(void)arg;pthread_mutex_lock(&mu);struct json_object *t=copy(task),*m=copy(model(al_s(task,"model_id")));pthread_mutex_unlock(&mu);const char *action=al_s(t,"action"),*vol=al_s(t,"volume_id"),*error=NULL;
    if(!strcmp(action,"download"))error=download_model(m,vol);
    else if(!strcmp(action,"stop")){pthread_mutex_lock(&mu);snprintf(service_state,sizeof(service_state),"stopping");engine_stop();pthread_mutex_unlock(&mu);}
    else{char path[768],hash[65];if(file_path(path,sizeof(path),vol,al_s(m,"id"),".rkllm"))error="volume_offline";else if(hash_file(path,hash,al_i(m,"size_bytes"))||strcmp(hash,al_s(m,"sha256")))error="checksum_mismatch";else if(memory_free()<al_i(m,"required_memory_bytes"))error="insufficient_memory";
        if(!error){pthread_mutex_lock(&mu);engine_stop();snprintf(service_state,sizeof(service_state),"starting");pthread_mutex_unlock(&mu);
            /* No control path touches the engine while task_busy is set. */
            if(engine_start(m,path))error="model_load_failed";else{pthread_mutex_lock(&mu);snprintf(loaded_volume,sizeof(loaded_volume),"%s",vol);pthread_mutex_unlock(&mu);}
        }
    }
    pthread_mutex_lock(&mu);al_str(task,"state",error?!strcmp(error,"download_cancelled")?"cancelled":"failed":"completed");al_str(task,"phase",al_s(task,"state"));al_str(task,"error",error);task_busy=0;task_save();pthread_mutex_unlock(&mu);json_object_put(t);json_object_put(m);return NULL;
}
static struct json_object *start_task(struct json_object *req){const char *action=al_s(req,"action"),*id=al_s(req,"model_id"),*vol=al_s(req,"volume_id"),*reason=hardware_reason(NULL);struct json_object *m=model(id);int stop=!strcmp(action,"stop"),download=!strcmp(action,"download");
    if(strcmp(action,"start")&&strcmp(action,"switch")&&!stop&&!download)return al_error("invalid_action",400);
    if(task_busy)return al_error("task_in_progress",409);if(engine_busy&&!download)return al_error("model_in_use",409);if(!stop&&reason[0])return al_error(reason,409);if(!stop&&!model_valid(m))return al_error("model_incompatible",422);
    if(!stop&&!volume_ok(vol,download?al_i(m,"size_bytes")+64*1024*1024:0))return al_error("insufficient_storage",507);
    if(download&&installed(m,vol))return al_error("model_already_installed",409);
    if(!stop&&!download&&!installed(m,vol))return al_error("model_missing",409);if(!strcmp(action,"start")&&engine_pid)return al_error("model_in_use",409);
    if(!download&&!stop&&memory_free()<al_i(m,"required_memory_bytes"))return al_error("insufficient_memory",409);
    if(task)json_object_put(task);task=json_object_new_object();char tid[80];snprintf(tid,sizeof(tid),"local-%lld-%ld",(long long)now(),(long)clock());al_str(task,"task_id",tid);al_str(task,"actor",al_s(req,"actor"));al_str(task,"action",action);al_str(task,"model_id",id);al_str(task,"volume_id",vol);al_str(task,"state","running");al_str(task,"phase",download?"downloading":stop?"stopping":"starting");al_num(task,"created_at",now());al_num(task,"downloaded_bytes",0);json_object_object_add(task,"total_bytes",download?json_object_new_int64(al_i(m,"size_bytes")):NULL);al_bool(task,"resumable",0);task_busy=1;atomic_store(&cancel_task,0);if(task_save()){task_busy=0;al_str(task,"state","failed");al_str(task,"error","task_storage_failed");return al_error("task_storage_failed",507);}pthread_t th;if(pthread_create(&th,NULL,task_run,NULL)){task_busy=0;al_str(task,"state","failed");al_str(task,"error","worker_unavailable");task_save();return al_error("worker_unavailable",503);}pthread_detach(th);struct json_object *j=al_ok(copy(task));al_num(j,"status",202);return j;
}
static struct json_object *request(struct json_object *req){const char *op=al_s(req,"op");if(!strcmp(op,"status"))return al_ok(status_data());if(!strcmp(op,"models")){struct json_object *d=status_data(),*a=json_object_new_array(),*all=json_object_object_get(catalog,"models");for(size_t i=0;i<json_object_array_length(all);i++){struct json_object *m=json_object_array_get_idx(all,i);if(!model_valid(m))continue;struct json_object *x=copy(m);al_bool(x,"installed",installed(m,al_s(config,"volume_id")));al_bool(x,"loaded",!strcmp(loaded,al_s(m,"id")));json_object_array_add(a,x);}json_object_object_add(d,"items",a);json_object_object_add(d,"volumes",volumes());return al_ok(d);}
    if(!strcmp(op,"config")){if(al_i(req,"write")){const char *id=al_s(req,"model_id"),*vol=al_s(req,"volume_id");if(!model_valid(model(id)))return al_error("model_incompatible",422);if(!volume_ok(vol,0))return al_error("volume_offline",409);if(al_i(req,"revision")!=al_i(config,"revision"))return al_error("config_conflict",409);struct json_object *next=json_object_new_object();al_str(next,"model_id",id);al_str(next,"volume_id",vol);al_num(next,"revision",al_i(config,"revision")+1);if(put("config",next)){json_object_put(next);return al_error("config_save_failed",507);}json_object_put(config);config=next;}return al_ok(copy(config));}
    if(!strcmp(op,"task")){char key[128];if(!valid_id(al_s(req,"task_id")))return al_error("not_found",404);snprintf(key,sizeof(key),"task/%s",al_s(req,"task_id"));struct json_object *t=get(key);if(!t||strcmp(al_s(t,"actor"),al_s(req,"actor"))){if(t)json_object_put(t);return al_error("not_found",404);}return al_ok(t);}
    if(!strcmp(op,"cancel_task")){if(!task||strcmp(al_s(task,"task_id"),al_s(req,"task_id"))||strcmp(al_s(task,"actor"),al_s(req,"actor")))return al_error("not_found",404);if(task_busy&&strcmp(al_s(task,"action"),"download"))return al_error("task_not_cancellable",409);atomic_store(&cancel_task,1);return al_ok(copy(task));}
    if(!strcmp(op,"service"))return start_task(req);
    if(!strcmp(op,"cancel")){if(!engine_busy||strcmp(active_id,al_s(req,"response_id"))||strcmp(active_actor,al_s(req,"actor")))return al_error("not_found",404);kill(engine_pid,SIGUSR1);struct json_object *d=json_object_new_object();al_bool(d,"requested",1);return al_ok(d);}
    return al_error("not_found",404);
}
static char *prompt_text(struct json_object *req){struct json_object *a=json_object_object_get(req,"messages");size_t n=json_object_array_length(a),used=0;char *out=calloc(1,AL_FRAME_MAX);if(!out||!n||n>128){free(out);return NULL;}
    for(size_t i=0;i<n;i++){struct json_object *m=json_object_array_get_idx(a,i);const char *role=al_s(m,"role"),*s=al_s(m,"content");if(strcmp(role,"user")&&strcmp(role,"assistant")&&strcmp(role,"system")){free(out);return NULL;}int z=snprintf(out+used,AL_FRAME_MAX-used,"<|im_start|>%s\n%s<|im_end|>\n",role,s);if(z<0||(size_t)z>=AL_FRAME_MAX-used){free(out);return NULL;}used+=(size_t)z;}
    const char *end="<|im_start|>assistant\n";if(used+strlen(end)>=AL_FRAME_MAX){free(out);return NULL;}strcpy(out+used,end);return out;
}
static void generate(int fd,struct json_object *req){pthread_mutex_lock(&mu);engine_check();struct json_object *error=NULL;const char *id=al_s(req,"model_id");if(task_busy||engine_busy)error=al_error("model_in_use",409);else if(!engine_pid||strcmp(id,loaded)||!volume_ok(loaded_volume,0))error=al_error("local_not_ready",409);else if(!al_s(req,"actor")[0]||!al_s(req,"response_id")[0])error=al_error("identity_required",401);
    char *prompt=error?NULL:prompt_text(req);if(!error&&!prompt)error=al_error("invalid_context",400);if(error){pthread_mutex_unlock(&mu);al_send(fd,error);json_object_put(error);return;}
    engine_busy=1;snprintf(active_id,sizeof(active_id),"%s",al_s(req,"response_id"));snprintf(active_actor,sizeof(active_actor),"%s",al_s(req,"actor"));int engine=engine_fd;pthread_mutex_unlock(&mu);
    struct json_object *cmd=json_object_new_object();al_str(cmd,"prompt",prompt);free(prompt);al_num(cmd,"max_tokens",al_i(req,"max_tokens"));int failed=al_send(engine,cmd);json_object_put(cmd);struct json_object *accepted=json_object_new_object();al_str(accepted,"event","started");al_str(accepted,"model",id);if(!failed&&al_send(fd,accepted))failed=1;json_object_put(accepted);
    int done=0;time_t deadline=time(NULL)+600;
    while(!failed&&!done&&time(NULL)<deadline){struct pollfd p[2]={{engine,POLLIN,0},{fd,POLLIN,0}};int r=poll(p,2,500);if(r<0&&errno==EINTR)continue;if(r<0||p[1].revents){failed=1;break;}if(!p[0].revents)continue;struct json_object *j=al_recv(engine,5000);if(!j){failed=1;break;}done=!strcmp(al_s(j,"event"),"completed")||!strcmp(al_s(j,"event"),"failed");if(al_send(fd,j))failed=1;json_object_put(j);}
    pthread_mutex_lock(&mu);if(failed||!done){engine_stop();snprintf(service_state,sizeof(service_state),"failed");struct json_object *e=al_error("inference_interrupted",503);al_send(fd,e);json_object_put(e);}engine_busy=0;active_id[0]=active_actor[0]=0;pthread_mutex_unlock(&mu);
}
static void *client(void *arg){int fd=(int)(intptr_t)arg;struct json_object *req=al_recv(fd,5000);if(req){if(!strcmp(al_s(req,"op"),"generate"))generate(fd,req);else{pthread_mutex_lock(&mu);struct json_object *j=request(req);pthread_mutex_unlock(&mu);al_send(fd,j);json_object_put(j);}json_object_put(req);}close(fd);pthread_mutex_lock(&mu);clients--;pthread_mutex_unlock(&mu);return NULL;}
int main(void){umask(0077);signal(SIGPIPE,SIG_IGN);mkdir("/etc/dreamingwrt",0700);if(mkdir(STATE_DIR,0700)&&errno!=EEXIST)return 1;
    if(sqlite3_open(STATE_DIR"/state.sqlite",&db)!=SQLITE_OK)return 1;sqlite3_busy_timeout(db,3000);if(sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS state(k TEXT PRIMARY KEY,v TEXT NOT NULL)",NULL,NULL,NULL))return 1;
    catalog=json_object_from_file(CATALOG);if(!catalog)catalog=json_object_new_object();config=get("config");if(!config)config=json_object_new_object();task=get("last_task");if(task&&!strcmp(al_s(task,"state"),"running")){al_str(task,"state","interrupted");al_str(task,"phase","interrupted");al_str(task,"error","service_restarted");char partial[768];if(!strcmp(al_s(task,"action"),"download")&&!file_path(partial,sizeof(partial),al_s(task,"volume_id"),al_s(task,"task_id"),".part"))unlink(partial);task_save();}
    curl_global_init(CURL_GLOBAL_DEFAULT);int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);struct sockaddr_un a={.sun_family=AF_UNIX};snprintf(a.sun_path,sizeof(a.sun_path),"%s",AL_SOCKET);int probe=al_connect();if(probe>=0){close(probe);return 1;}unlink(AL_SOCKET);if(bind(fd,(struct sockaddr*)&a,sizeof(a))||chmod(AL_SOCKET,0600)||listen(fd,8))return 1;
    for(;;){int c=accept4(fd,NULL,NULL,SOCK_CLOEXEC);if(c<0){if(errno==EINTR)continue;break;}struct ucred cred;socklen_t len=sizeof(cred);if(getsockopt(c,SOL_SOCKET,SO_PEERCRED,&cred,&len)||cred.uid!=geteuid()){close(c);continue;}pthread_mutex_lock(&mu);if(clients>=8){pthread_mutex_unlock(&mu);close(c);continue;}clients++;pthread_mutex_unlock(&mu);pthread_t t;if(pthread_create(&t,NULL,client,(void*)(intptr_t)c)){close(c);pthread_mutex_lock(&mu);clients--;pthread_mutex_unlock(&mu);}else pthread_detach(t);
    }return 1;
}
