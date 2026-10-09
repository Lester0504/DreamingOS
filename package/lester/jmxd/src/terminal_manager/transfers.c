// SPDX-License-Identifier: GPL-2.0-or-later
/* Bounded browser staging -> owned background transfer -> atomic remote rename. */
#include "tm.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <unistd.h>

char tm_spool[512]="/tmp/dreamingwrt-terminal-transfers";
static pthread_mutex_t transfer_lock=PTHREAD_MUTEX_INITIALIZER;
struct transfer {char id[33],owner[128],session_id[33],direction[16],path[4096],local[640],state[32],reason[96];int used,cancel,replace,running;int64_t size,bytes,created;struct tm_session *session;};
static struct transfer transfers[TM_MAX_TRANSFERS];
static int active_downloads;
struct download_stream { int fd, file; int64_t size; char filename[4096]; };
static void *send_download(void *arg) {
    struct download_stream *stream=arg;
    struct timeval timeout={10,0};
    setsockopt(stream->fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    char encoded[sizeof(stream->filename)*3],header[sizeof(encoded)+512],buffer[TM_CHUNK];
    static const char hex[]="0123456789ABCDEF";
    size_t at=0;
    for(const unsigned char *p=(const unsigned char *)stream->filename;*p;p++) {
        encoded[at++]='%';encoded[at++]=hex[*p>>4];encoded[at++]=hex[*p&15];
    }
    encoded[at]=0;
    int n=snprintf(header,sizeof(header),"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=download; filename*=UTF-8''%s\r\nContent-Length: %lld\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",encoded,(long long)stream->size);
    int rc=tm_write_all(stream->fd,header,n);
    while(!rc&&(n=read(stream->file,buffer,sizeof(buffer)))>0)rc=tm_write_all(stream->fd,buffer,n);
    close(stream->file);close(stream->fd);free(stream);
    pthread_mutex_lock(&transfer_lock);active_downloads--;pthread_mutex_unlock(&transfer_lock);
    return NULL;
}


static J *transfer_json(struct transfer *t) {J *j=json_object_new_object();tm_string(j,"id",t->id);tm_string(j,"task_id",t->id);tm_string(j,"session_id",t->session_id);tm_string(j,"direction",t->direction);tm_string(j,"path",t->path);tm_string(j,"state",t->state);tm_string(j,"reason",t->reason);tm_number(j,"bytes",t->bytes);tm_number(j,"total_bytes",t->size);tm_number(j,"created_at",t->created);tm_boolean(j,"accepted",strcmp(t->state,"uploading")!=0);return j;}

static void persist(struct transfer *t) {
    J *j=transfer_json(t);pthread_mutex_lock(&tm_store_lock);sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(tm_db,"INSERT INTO records(owner,kind,id,revision,doc) VALUES(?,'transfers',?,1,?) ON CONFLICT(owner,kind,id) DO UPDATE SET doc=excluded.doc,revision=revision+1",-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,t->owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,t->id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);sqlite3_step(st);}sqlite3_finalize(st);pthread_mutex_unlock(&tm_store_lock);json_object_put(j);
}

int tm_transfers_init(void) {if(mkdir(tm_spool,0700)&&errno!=EEXIST)return -1;struct stat st;if(lstat(tm_spool,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077))return -1;
    return sqlite3_exec(tm_db,"UPDATE records SET doc=json_set(doc,'$.state','interrupted','$.reason','runtime_restarted') WHERE kind='transfers' AND json_extract(doc,'$.state') NOT IN ('completed','failed','cancelled','interrupted')",NULL,NULL,NULL)==SQLITE_OK?0:-1;
}

static int session_ref(struct transfer *t) {
    pthread_mutex_lock(&tm_sessions_lock);struct tm_session *s=tm_find_session(t->owner,t->session_id);if(s)pthread_mutex_lock(&s->lock);pthread_mutex_unlock(&tm_sessions_lock);
    if(!s)return -1;int ok=!strcmp(s->state,"ready")&&s->sftp&&!s->stop;if(ok){s->transfer_refs++;t->session=s;}pthread_mutex_unlock(&s->lock);return ok?0:-1;
}

static void ssh_lock(struct tm_session *s) {pthread_mutex_lock(&s->lock);libssh2_session_set_blocking(s->ssh,1);libssh2_session_set_timeout(s->ssh,5000);}
static void ssh_unlock(struct tm_session *s) {libssh2_session_set_blocking(s->ssh,0);pthread_mutex_unlock(&s->lock);}

static void *transfer_run(void *arg) {
    struct transfer *t=arg;struct tm_session *s=t->session;int upload=!strcmp(t->direction,"upload"),ok=0;LIBSSH2_SFTP_HANDLE *remote=NULL;char temporary[4096]="";int local=-1;char buf[TM_CHUNK];int64_t offset=0,download_size=0;
    pthread_mutex_lock(&transfer_lock);snprintf(t->state,sizeof(t->state),"transferring");t->bytes=0;persist(t);pthread_mutex_unlock(&transfer_lock);
    local=open(t->local,upload?O_RDONLY|O_NOFOLLOW:O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(local<0)goto finish;
    ssh_lock(s);
    if(upload){LIBSSH2_SFTP_ATTRIBUTES a;if(!t->replace&&!libssh2_sftp_lstat(s->sftp,t->path,&a)){snprintf(t->reason,sizeof(t->reason),"file_conflict");ssh_unlock(s);goto finish;}
        if(snprintf(temporary,sizeof(temporary),"%s.dwrt-%s.partial",t->path,t->id)>=(int)sizeof(temporary)){ssh_unlock(s);goto finish;}
        remote=libssh2_sftp_open(s->sftp,temporary,LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_EXCL,0600);
    }else {LIBSSH2_SFTP_ATTRIBUTES a;if(libssh2_sftp_stat(s->sftp,t->path,&a)||!LIBSSH2_SFTP_S_ISREG(a.permissions)||a.filesize>(uint64_t)1024*1024*1024){snprintf(t->reason,sizeof(t->reason),"download_size_or_type");ssh_unlock(s);goto finish;}download_size=a.filesize;remote=libssh2_sftp_open(s->sftp,t->path,LIBSSH2_FXF_READ,0);}
    ssh_unlock(s);if(!remote)goto finish;if(!upload){pthread_mutex_lock(&transfer_lock);t->size=download_size;pthread_mutex_unlock(&transfer_lock);}
    while(offset<t->size){pthread_mutex_lock(&transfer_lock);int cancel=t->cancel;pthread_mutex_unlock(&transfer_lock);if(cancel)goto finish;
        ssize_t n;if(upload){n=read(local,buf,sizeof(buf));if(n<=0)goto finish;size_t wrote=0;while(wrote<(size_t)n){ssh_lock(s);ssize_t rc=libssh2_sftp_write(remote,buf+wrote,n-wrote);ssh_unlock(s);if(rc<=0)goto finish;wrote+=rc;}}
        else {ssh_lock(s);n=libssh2_sftp_read(remote,buf,sizeof(buf));ssh_unlock(s);if(n<=0)goto finish;size_t wrote=0;while(wrote<(size_t)n){ssize_t rc=write(local,buf+wrote,n-wrote);if(rc<=0)goto finish;wrote+=rc;}}
        offset+=n;pthread_mutex_lock(&transfer_lock);t->bytes=offset;pthread_mutex_unlock(&transfer_lock);
    }
    ssh_lock(s);int close_rc=libssh2_sftp_close(remote);remote=NULL;ssh_unlock(s);if(close_rc)goto finish;
    pthread_mutex_lock(&transfer_lock);int cancel=t->cancel;pthread_mutex_unlock(&transfer_lock);if(cancel)goto finish;
    if(upload){ssh_lock(s);int rc=libssh2_sftp_rename_ex(s->sftp,temporary,strlen(temporary),t->path,strlen(t->path),LIBSSH2_SFTP_RENAME_ATOMIC|(t->replace?LIBSSH2_SFTP_RENAME_OVERWRITE:0));ssh_unlock(s);if(rc){snprintf(t->reason,sizeof(t->reason),"atomic_replace_failed");goto finish;}temporary[0]=0;}
    else if(fsync(local))goto finish;
    ok=1;
finish:
    if(local>=0)close(local);ssh_lock(s);if(remote)libssh2_sftp_close(remote);if(temporary[0])libssh2_sftp_unlink(s->sftp,temporary);s->transfer_refs--;ssh_unlock(s);
    pthread_mutex_lock(&transfer_lock);if(!ok||upload)unlink(t->local);snprintf(t->state,sizeof(t->state),"%s",ok?"completed":t->cancel?"cancelled":"failed");if(!ok&&!t->reason[0])snprintf(t->reason,sizeof(t->reason),"%s",t->cancel?"user_cancelled":"transfer_failed");t->running=0;t->session=NULL;persist(t);pthread_mutex_unlock(&transfer_lock);return NULL;
}

static int start_transfer(struct transfer *t) {if(session_ref(t))return -1;pthread_t thread;t->running=1;snprintf(t->state,sizeof(t->state),"accepted");persist(t);if(pthread_create(&thread,NULL,transfer_run,t)){pthread_mutex_lock(&t->session->lock);t->session->transfer_refs--;pthread_mutex_unlock(&t->session->lock);t->running=0;return -1;}pthread_detach(thread);return 0;}

static J *saved_transfers(const char *owner,const char *id,int *status) {
    pthread_mutex_lock(&tm_store_lock);sqlite3_stmt *st=NULL;J *out=json_object_new_object(),*items=json_object_new_array();
    const char *sql=id?"SELECT doc FROM records WHERE owner=? AND kind='transfers' AND id=?":"SELECT doc FROM records WHERE owner=? AND kind='transfers' ORDER BY json_extract(doc,'$.created_at') DESC LIMIT 100";
    if(sqlite3_prepare_v2(tm_db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);if(id)sqlite3_bind_text(st,2,id,-1,SQLITE_TRANSIENT);while(sqlite3_step(st)==SQLITE_ROW){J *j=json_tokener_parse((const char *)sqlite3_column_text(st,0));if(j)json_object_array_add(items,j);}}sqlite3_finalize(st);pthread_mutex_unlock(&tm_store_lock);
    if(id){if(json_object_array_length(items)){J *j=json_object_get(json_object_array_get_idx(items,0));json_object_put(items);json_object_put(out);return j;}json_object_put(items);json_object_put(out);return tm_error(status,404,"not_found","传输任务不存在");}json_object_object_add(out,"items",items);tm_number(out,"limit",100);return out;
}

J *tm_transfers_route(const char *method,const char *path,const char *owner,J *body,int fd,int *status) {
    pthread_mutex_lock(&transfer_lock);J *r=NULL;
    if(!strcmp(path,"transfers")&&!strcmp(method,"GET")){r=saved_transfers(owner,NULL,status);J *items=tm_get(r,"items");for(size_t i=0;i<json_object_array_length(items);i++){J *item=json_object_array_get_idx(items,i);for(int k=0;k<TM_MAX_TRANSFERS;k++)if(transfers[k].used&&!strcmp(transfers[k].owner,owner)&&!strcmp(transfers[k].id,tm_str(item,"id",""))){json_object_array_put_idx(items,i,transfer_json(&transfers[k]));break;}}goto done;}
    if(!strcmp(path,"transfers")&&!strcmp(method,"POST")) {
        const char *direction=tm_str(body,"direction",""),*remote=tm_str(body,"path","");int64_t size=tm_int(body,"size",0);
        if((strcmp(direction,"upload")&&strcmp(direction,"download"))||!tm_path_valid(remote)||size<0||size>(int64_t)1024*1024*1024){r=tm_error(status,422,"invalid_transfer","请提供传输方向、绝对路径及不超过 1 GiB 的文件");goto done;}
        struct statvfs vfs;if(statvfs(tm_spool,&vfs)||(!strcmp(direction,"upload")&&(uint64_t)size>(uint64_t)vfs.f_bavail*vfs.f_frsize)){r=tm_error(status,507,"staging_no_space","设备临时空间不足");goto done;}
        struct transfer *t=NULL;for(int i=0;i<TM_MAX_TRANSFERS;i++)if(!transfers[i].used||(!transfers[i].running&&strcmp(transfers[i].state,"uploading")&&(strcmp(transfers[i].state,"completed")||!strcmp(transfers[i].direction,"upload")))){t=&transfers[i];break;}
        if(!t){r=tm_error(status,429,"transfer_limit","传输或待下载文件达到上限，请清理已完成下载");goto done;}
        memset(t,0,sizeof(*t));t->used=1;tm_uuid(t->id);snprintf(t->owner,sizeof(t->owner),"%s",owner);snprintf(t->session_id,sizeof(t->session_id),"%s",tm_str(body,"session_id",""));snprintf(t->direction,sizeof(t->direction),"%s",direction);snprintf(t->path,sizeof(t->path),"%s",remote);snprintf(t->local,sizeof(t->local),"%s/%s",tm_spool,t->id);t->replace=tm_bool(body,"replace",0);t->size=size;t->created=tm_now();
        if(!strcmp(direction,"upload")){if(session_ref(t)){t->used=0;r=tm_error(status,409,"session_not_ready","SFTP 会话已失效");goto done;}pthread_mutex_lock(&t->session->lock);t->session->transfer_refs--;pthread_mutex_unlock(&t->session->lock);t->session=NULL;int file=open(t->local,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(file<0){t->used=0;r=tm_error(status,507,"staging_failed","无法暂存上传");goto done;}close(file);snprintf(t->state,sizeof(t->state),"uploading");persist(t);}
        else if(start_transfer(t)){t->used=0;r=tm_error(status,409,"session_not_ready","SFTP 会话已失效");goto done;}
        r=transfer_json(t);*status=202;goto done;
    }
    if(strncmp(path,"transfers/",10)){r=tm_error(status,404,"not_found","传输任务不存在");goto done;}
    const char *start=path+10,*slash=strchr(start,'/');size_t len=slash?(size_t)(slash-start):strlen(start);char id[33];if(len!=32){r=tm_error(status,404,"not_found","传输任务不存在");goto done;}memcpy(id,start,32);id[32]=0;const char *op=slash?slash+1:"";
    struct transfer *t=NULL;for(int i=0;i<TM_MAX_TRANSFERS;i++)if(transfers[i].used&&!strcmp(transfers[i].id,id)&&!strcmp(transfers[i].owner,owner)){t=&transfers[i];break;}
    if(!*op&&!strcmp(method,"GET")){r=t?transfer_json(t):saved_transfers(owner,id,status);goto done;}
    if(!t){r=tm_error(status,404,"not_found","任务暂存内容不可用");goto done;}
    if(!strcmp(op,"cancel")&&!strcmp(method,"POST")){t->cancel=1;if(!t->running){unlink(t->local);snprintf(t->state,sizeof(t->state),"cancelled");persist(t);}r=transfer_json(t);}
    else if(!strcmp(op,"chunk")&&!strcmp(method,"POST")&&!strcmp(t->state,"uploading")) {
        size_t size=0;unsigned char *data=tm_unbase64(tm_str(body,"data",""),&size);if(!data||size>TM_CHUNK||tm_int(body,"offset",-1)!=t->bytes||t->bytes+(int64_t)size>t->size){free(data);r=tm_error(status,409,"upload_offset_conflict","上传分段或偏移不匹配");goto done;}
        int file=open(t->local,O_WRONLY|O_APPEND|O_NOFOLLOW);ssize_t n=file>=0?write(file,data,size):-1;if(file>=0)close(file);free(data);if(n!=(ssize_t)size){r=tm_error(status,507,"staging_failed","上传暂存失败");goto done;}t->bytes+=size;r=transfer_json(t);
    }else if(!strcmp(op,"commit")&&!strcmp(method,"POST")&&!strcmp(t->state,"uploading")) {
        if(t->bytes!=t->size)r=tm_error(status,409,"upload_incomplete","浏览器尚未上传完整文件");else if(start_transfer(t))r=tm_error(status,409,"session_not_ready","SFTP 会话已失效；上传尚未受理");else {r=transfer_json(t);*status=202;}
    }else if(!strcmp(op,"content")&&!strcmp(method,"GET")&&!strcmp(t->direction,"download")&&!strcmp(t->state,"completed")&&fd>=0) {
        int file=open(t->local,O_RDONLY|O_NOFOLLOW);if(file<0){r=tm_error(status,410,"download_expired","下载暂存文件已过期");goto done;}
        if(active_downloads>=TM_MAX_TRANSFERS){close(file);r=tm_error(status,429,"download_limit","同时下载数已达上限");goto done;}
        struct download_stream *stream=malloc(sizeof(*stream));
        if(!stream){close(file);r=tm_error(status,503,"download_unavailable","暂时无法创建下载");goto done;}
        *stream=(struct download_stream){.fd=fd,.file=file,.size=t->size};
        const char *basename=strrchr(t->path,'/');
        snprintf(stream->filename,sizeof(stream->filename),"%s",basename?basename+1:t->path);
        pthread_t thread;active_downloads++;
        if(pthread_create(&thread,NULL,send_download,stream)){active_downloads--;free(stream);close(file);r=tm_error(status,503,"download_unavailable","暂时无法创建下载");goto done;}
        pthread_detach(thread);
        /* Return ownership immediately: webd must not time out into an active byte stream. */
        r=json_object_new_object();tm_boolean(r,"fd_owned",1);
    }else r=tm_error(status,409,"transfer_state_conflict","此任务当前不能执行该操作");
done:
    pthread_mutex_unlock(&transfer_lock);return r;
}
