// SPDX-License-Identifier: GPL-2.0-or-later
#include "tm.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct tm_session tm_sessions[TM_MAX_SESSIONS];
pthread_mutex_t tm_sessions_lock=PTHREAD_MUTEX_INITIALIZER;

void tm_sessions_init(void) { for(int i=0;i<TM_MAX_SESSIONS;i++){pthread_mutex_init(&tm_sessions[i].lock,NULL);tm_sessions[i].ws=-1;tm_sessions[i].stream=-1;} }

int tm_ws_send(struct tm_session *s,int op,const void *p,size_t n) {
    if(s->ws<0||n>TM_FRAME_MAX)return -1;
    unsigned char head[10];size_t h=2;head[0]=0x80|op;
    if(n<126)head[1]=n;else if(n<=65535){head[1]=126;head[2]=n>>8;head[3]=n;h=4;}else {head[1]=127;for(int i=0;i<8;i++)head[2+i]=(uint64_t)n>>(56-i*8);h=10;}
    return tm_write_all(s->ws,head,h)||tm_write_all(s->ws,p,n)?-1:0;
}

J *tm_session_json(struct tm_session *s) {
    J *j=json_object_new_object(),*caps=json_object_new_object();tm_string(j,"id",s->id);tm_string(j,"session_id",s->id);tm_string(j,"workspace_id",s->workspace);tm_string(j,"owner",s->owner);tm_string(j,"state",s->state);tm_string(j,"reason",s->reason);tm_number(j,"created_at",s->created);tm_number(j,"ready_at",s->ready);tm_number(j,"ended_at",s->ended);
    J *host=tm_copy(s->host);json_object_object_del(host,"auth");json_object_object_add(j,"host",host);tm_string(j,"connection_type",tm_str(s->host,"type",""));
    tm_string(j,"cwd",s->cwd[0]?s->cwd:NULL);tm_string(j,"cwd_source",s->cwd_source[0]?s->cwd_source:"unknown");
    tm_string(j,"fingerprint",s->fingerprint);tm_string(j,"previous_fingerprint",s->old_fingerprint);
    tm_boolean(caps,"sftp",s->sftp!=NULL);tm_boolean(caps,"resize",!s->serial);tm_boolean(caps,"input",!s->readonly);tm_boolean(caps,"telemetry",s->ssh!=NULL||(s->child>0&&strcmp(tm_str(s->host,"type",""),"lxc")));tm_boolean(caps,"authenticated",s->ssh?libssh2_userauth_authenticated(s->ssh):0);
    if(!strcmp(tm_str(s->host,"type",""),"docker"))tm_string(j,"exec_id",s->docker_exec);
    json_object_object_add(j,"capabilities",caps);return j;
}

void tm_state(struct tm_session *s,const char *state,const char *reason) {
    if(state!=s->state)snprintf(s->state,sizeof(s->state),"%s",state);if(reason!=s->reason)snprintf(s->reason,sizeof(s->reason),"%s",reason);
    if(!strcmp(state,"ready"))s->ready=tm_now();
    if(!strcmp(state,"failed")||!strcmp(state,"closed")||!strcmp(state,"disconnected"))s->ended=tm_now();
    if(s->ws>=0){J *j=tm_session_json(s);tm_string(j,"type","state");const char *p=json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN);tm_ws_send(s,1,p,strlen(p));json_object_put(j);}
}

static int ws_message(struct tm_session *s,int op,const char *data,size_t len) {
    if(op==8)return -1;if(op==9)return tm_ws_send(s,10,data,len);if(op==10)return 0;
    if(op==2)return tm_engine_input(s,data,len);
    if(op!=1)return -1;
    struct json_tokener *tok=json_tokener_new();J *j=json_tokener_parse_ex(tok,data,len);json_tokener_free(tok);if(!j)return -1;
    int rc=0;const char *type=tm_str(j,"type","");
    if(!strcmp(type,"input")){J *text=tm_get(j,"data");const char *p=tm_str(j,"data","");size_t n=text?json_object_get_string_len(text):0;
        if(n==1&&p[0]==127&&!strcmp(tm_str(s->host,"backspace","del"),"bs"))p="\b";
        rc=tm_engine_input(s,p,n);
    }else if(!strcmp(type,"resize"))tm_engine_resize(s,tm_int(j,"cols",0),tm_int(j,"rows",0));
    else if(!strcmp(type,"ping")){const char *pong="{\"type\":\"pong\"}";tm_ws_send(s,1,pong,strlen(pong));}
    else rc=-1;
    tm_scrub(j);json_object_put(j);return rc;
}

static int ws_read(struct tm_session *s) {
    ssize_t n=recv(s->ws,s->wsbuf+s->wslen,sizeof(s->wsbuf)-s->wslen,MSG_DONTWAIT);
    if(n==0)return -1;if(n<0)return errno==EAGAIN||errno==EINTR?0:-1;s->wslen+=n;
    size_t used=0;
    while(s->wslen-used>=2){unsigned char *b=s->wsbuf+used;int fin=b[0]&128,op=b[0]&15;uint64_t len=b[1]&127;size_t h=2;
        if((b[0]&0x70)||!(b[1]&128))return -1;
        if(len==126){if(s->wslen-used<4)break;len=(b[2]<<8)|b[3];h=4;}
        else if(len==127){if(s->wslen-used<10)break;len=0;for(int i=0;i<8;i++)len=(len<<8)|b[2+i];h=10;}
        if(len>TM_FRAME_MAX||(op>=8&&(!fin||len>125)))return -1;if(s->wslen-used<h+4+len)break;
        unsigned char *mask=b+h,*p=b+h+4;for(size_t i=0;i<len;i++)p[i]^=mask[i%4];
        int rc=0;
        if(op>=8)rc=ws_message(s,op,(const char *)p,len);
        else if(op==0){if(!s->fragop||s->fraglen+len>TM_FRAME_MAX)return -1;memcpy(s->fragment+s->fraglen,p,len);s->fraglen+=len;if(fin){rc=ws_message(s,s->fragop,s->fragment,s->fraglen);s->fragop=0;s->fraglen=0;}}
        else if(s->fragop)return -1;
        else if(!fin){s->fragop=op;s->fraglen=len;memcpy(s->fragment,p,len);}
        else rc=ws_message(s,op,(const char *)p,len);
        if(rc)return -1;used+=h+4+len;
    }
    if(used){memmove(s->wsbuf,s->wsbuf+used,s->wslen-used);s->wslen-=used;}return s->wslen>=sizeof(s->wsbuf)?-1:0;
}

static void *session_run(void *arg) {
    struct tm_session *s=arg;pthread_mutex_lock(&s->lock);
    /* Attach the interaction channel before starting the process, preserving its first output. */
    while(s->ws<0&&!s->stop&&tm_now()<s->created+20){pthread_mutex_unlock(&s->lock);usleep(20000);pthread_mutex_lock(&s->lock);}
    if(s->ws<0||s->stop)tm_state(s,"failed","channel_not_attached");
    else if(!tm_engine_open(s)) {
        tm_state(s,"ready","");tm_host_success(s->owner,tm_str(s->host,"id",""));
        /* Authentication has completed. No reconnect implicitly reuses these secrets. */
        if(s->auth){tm_scrub(s->auth);json_object_put(s->auth);s->auth=NULL;}
        int64_t keepalive=tm_now();
        while(!s->stop){
            if(tm_now()>s->lease){tm_state(s,"disconnected","authorization_lease_expired");break;}
            if(tm_now()>s->activity+TM_IDLE_SECONDS){tm_state(s,"disconnected","idle_timeout");break;}
            if(s->ws<0){tm_state(s,"disconnected","channel_closed");break;}
            if(ws_read(s)){tm_state(s,"disconnected","channel_closed");break;}
            if(tm_engine_read(s)){tm_state(s,"disconnected",s->serial?"serial_removed":"remote_closed");break;}
            if(s->ssh&&tm_now()>keepalive+30){int seconds=0;int rc=libssh2_keepalive_send(s->ssh,&seconds);if(rc&&rc!=LIBSSH2_ERROR_EAGAIN){tm_state(s,"disconnected","connection_lost");break;}keepalive=tm_now();}
            pthread_mutex_unlock(&s->lock);usleep(10000);pthread_mutex_lock(&s->lock);
        }
        if(s->stop&&strcmp(s->state,"failed"))tm_state(s,"closed","user_disconnected");
    }else if(!s->ended)tm_state(s,"failed","engine_failed");
    if(s->ws>=0){tm_ws_send(s,8,"",0);close(s->ws);s->ws=-1;}
    /* Accepted transfers own the SFTP transport after the interactive channel closes. */
    if(s->channel){libssh2_session_set_blocking(s->ssh,1);libssh2_session_set_timeout(s->ssh,1000);libssh2_channel_free(s->channel);s->channel=NULL;libssh2_session_set_blocking(s->ssh,0);}
    while(s->transfer_refs){pthread_mutex_unlock(&s->lock);usleep(20000);pthread_mutex_lock(&s->lock);}
    tm_engine_close(s);s->finished=1;pthread_mutex_unlock(&s->lock);return NULL;
}

J *tm_capabilities(int manage) {
    J *r=json_object_new_object(),*types=json_object_new_array(),*p=json_object_new_object();
    tm_boolean(r,"engine_available",1);
    const char *names[]={"local","ssh","telnet","serial"};
    for(int i=0;i<4;i++){J *j=json_object_new_object();tm_string(j,"type",names[i]);tm_boolean(j,"implemented",1);tm_boolean(j,"available",manage);tm_string(j,"reason",manage?(i==3?"requires_stable_device_id":""):"owner_or_admin_required");tm_boolean(j,"resize",i!=3);tm_boolean(j,"sftp",i==1);tm_boolean(j,"telemetry",i<2);tm_boolean(j,"compression",0);tm_boolean(j,"flow_control",i==3);json_object_array_add(types,j);}
    json_object_object_add(r,"connection_types",types);tm_boolean(p,"read",1);tm_boolean(p,"manage",manage);tm_boolean(p,"connect",manage);json_object_object_add(r,"permissions",p);
    tm_number(r,"max_sessions",TM_MAX_SESSIONS);tm_number(r,"max_transfers",TM_MAX_TRANSFERS);tm_number(r,"input_limit",TM_FRAME_MAX);tm_number(r,"upload_chunk_bytes",TM_CHUNK);tm_number(r,"max_transfer_bytes",(int64_t)1024*1024*1024);tm_number(r,"authorization_lease_seconds",TM_LEASE_SECONDS);tm_number(r,"idle_timeout_seconds",TM_IDLE_SECONDS);tm_boolean(r,"saved_credentials",tm_secrets!=NULL);tm_boolean(r,"connection_test",0);tm_boolean(r,"serial_stable_id_required",1);tm_string(r,"local_policy","ttyd command/uid/gid/readonly; once/max_clients instances use existing /terminal/ proxy");
    json_object_object_add(r,"preference_defaults",tm_defaults());return r;
}

/* Caller holds tm_sessions_lock, then the returned session lock. */
struct tm_session *tm_find_session(const char *owner,const char *id) {
    for(int i=0;i<TM_MAX_SESSIONS;i++)if(tm_sessions[i].used&&!strcmp(tm_sessions[i].id,id)&&!strcmp(tm_sessions[i].owner,owner))return &tm_sessions[i];return NULL;
}

static int attach_ws(struct tm_session *s,J *body,int fd) {
    const char *key=tm_str(body,"websocket_key","");if(strlen(key)!=24||s->ws>=0||s->finished||fd<0)return -1;
    char input[128];snprintf(input,sizeof(input),"%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",key);unsigned char hash[SHA_DIGEST_LENGTH];SHA1((const unsigned char *)input,strlen(input),hash);char *accept=tm_base64(hash,sizeof(hash));if(!accept)return -1;
    char header[512];int n=snprintf(header,sizeof(header),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",accept);free(accept);
    struct timeval timeout={0,250000};setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));if(tm_write_all(fd,header,n))return -1;
    s->ws=fd;tm_state(s,s->state[0]?s->state:"connecting",s->reason);return 0;
}

static int session_scope(J *host){const char *type=tm_str(host,"type","");return !strcmp(type,"docker")?1:!strcmp(type,"lxc")?2:0;}

J *tm_sessions_route(const char *method,const char *path,const char *owner,J *body,int fd,int scope,int *status) {
    pthread_mutex_lock(&tm_sessions_lock);
    J *r=NULL;
    if(!strcmp(path,"sessions")&&!strcmp(method,"GET")){r=json_object_new_object();J *items=json_object_new_array();for(int i=0;i<TM_MAX_SESSIONS;i++){struct tm_session *s=&tm_sessions[i];pthread_mutex_lock(&s->lock);if(s->used&&!strcmp(s->owner,owner)&&scope==session_scope(s->host))json_object_array_add(items,tm_session_json(s));pthread_mutex_unlock(&s->lock);}json_object_object_add(r,"items",items);goto done;}
    if(!strcmp(path,"sessions")&&!strcmp(method,"POST")) {
        J *host=NULL;
        if(scope){
            if(!json_object_is_type(body,json_type_object)){r=tm_error(status,422,"invalid_field","需要容器会话参数");goto done;}
            json_object_object_foreach(body,key,value){(void)value;if(strcmp(key,"container_id")&&strcmp(key,"shell")&&strcmp(key,"workspace_id")&&(scope!=2||strcmp(key,"identity"))){r=tm_error(status,422,"invalid_field","不支持此会话参数");tm_string(r,"field",key);goto done;}}
            host=json_object_new_object();tm_string(host,"type",scope==2?"lxc":"docker");if(scope==2)tm_string(host,"identity",tm_str(body,"identity",""));tm_string(host,"name","容器终端");tm_string(host,"container_id",tm_str(body,"container_id",""));tm_string(host,"shell",tm_str(body,"shell","/bin/sh"));
        }else host=*tm_str(body,"host_id","")?tm_store_host(owner,tm_str(body,"host_id",""),1):tm_copy(tm_get(body,"host"));
        if(!host){r=tm_error(status,404,"host_not_found","主机不存在");goto done;}
        if(!*tm_str(host,"name",""))tm_string(host,"name",!strcmp(tm_str(host,"type",""),"local")?"本机终端":"临时连接");
        const char *bad=scope==2?tm_lxc_validate(host):scope==1?tm_docker_validate(host):tm_validate_host(host);if(bad){r=tm_error(status,422,"invalid_field","连接参数不受支持");tm_string(r,"field",bad);tm_scrub(tm_get(host,"auth"));json_object_put(host);goto done;}
        if(strlen(tm_str(body,"workspace_id",""))>95||!*tm_str(body,"workspace_id","")){json_object_put(host);r=tm_error(status,422,"workspace_required","缺少工作区标识");goto done;}
        struct tm_session *s=NULL;
        for(int i=0;i<TM_MAX_SESSIONS;i++){pthread_mutex_lock(&tm_sessions[i].lock);if(!tm_sessions[i].used||tm_sessions[i].finished){s=&tm_sessions[i];break;}pthread_mutex_unlock(&tm_sessions[i].lock);}
        if(!s){json_object_put(host);r=tm_error(status,429,"session_limit","已达到活动会话上限");goto done;}
        json_object_put(s->host);json_object_put(s->sample);if(s->auth){tm_scrub(s->auth);json_object_put(s->auth);}
        /* Preserve the initialized mutex; reset every other field. */
        memset((char *)s+sizeof(s->lock),0,sizeof(*s)-sizeof(s->lock));s->used=1;s->host=host;s->ws=-1;s->stream=-1;s->docker_pidfd=-1;s->lxc_pidfd=-1;
        s->auth=tm_copy(tm_get(body,"auth")?tm_get(body,"auth"):tm_get(host,"auth"));tm_scrub(tm_get(host,"auth"));json_object_object_del(host,"auth");tm_uuid(s->id);snprintf(s->owner,sizeof(s->owner),"%s",owner);snprintf(s->workspace,sizeof(s->workspace),"%s",tm_str(body,"workspace_id",""));s->cols=120;s->rows=36;s->created=s->activity=tm_now();s->lease=tm_now()+TM_LEASE_SECONDS;snprintf(s->state,sizeof(s->state),"connecting");
        pthread_t thread;if(pthread_create(&thread,NULL,session_run,s)){s->finished=1;r=tm_error(status,503,"engine_unavailable","无法创建会话运行时");}else {pthread_detach(thread);r=tm_session_json(s);*status=202;}pthread_mutex_unlock(&s->lock);goto done;
    }
    if(strncmp(path,"sessions/",9)){r=tm_error(status,404,"not_found","会话不存在");goto done;}
    char id[33];const char *sub=path+9;const char *slash=strchr(sub,'/');size_t n=slash?(size_t)(slash-sub):strlen(sub);if(n!=32){r=tm_error(status,404,"not_found","会话不存在");goto done;}memcpy(id,sub,32);id[32]=0;sub=slash?slash+1:"";
    struct tm_session *s=tm_find_session(owner,id);if(!s){r=tm_error(status,404,"not_found","会话不存在");goto done;}
    pthread_mutex_lock(&s->lock);
    /* Release global slot lock before bounded remote operations. The session lock prevents recycling. */
    pthread_mutex_unlock(&tm_sessions_lock);
    if(scope!=session_scope(s->host)){r=tm_error(status,404,"not_found","会话不存在");pthread_mutex_unlock(&s->lock);return r;}
    if(!*sub&&!strcmp(method,"GET"))r=tm_session_json(s);
    else if(!strcmp(sub,"lease")&&!strcmp(method,"POST")){if(s->finished||s->stop)r=tm_error(status,409,"session_closed","会话已结束");else {s->lease=tm_now()+TM_LEASE_SECONDS;r=tm_session_json(s);}}
    else if(!strcmp(sub,"disconnect")&&!strcmp(method,"POST")){s->stop=1;r=tm_session_json(s);tm_string(r,"state",s->finished?s->state:"disconnecting");}
    else if(!strcmp(sub,"trust")&&!strcmp(method,"POST")) {
        if(strcmp(s->state,"host_key_confirmation_required")||strcmp(tm_str(body,"fingerprint",""),s->fingerprint)||s->old_fingerprint[0])r=tm_error(status,409,"fingerprint_conflict","指纹或会话状态已变化");
        else if(tm_trust_key(owner,tm_str(s->host,"address",""),tm_int(s->host,"port",22),"",s->fingerprint))r=tm_error(status,409,"fingerprint_conflict","另一连接已更新指纹，请重新连接核对");
        else {s->trusted=1;r=tm_session_json(s);}
    }
    else if(!strcmp(sub,"ws")&&!strcmp(method,"GET")){if(attach_ws(s,body,fd))r=tm_error(status,409,"channel_unavailable","交互通道不可用");else {r=json_object_new_object();tm_boolean(r,"fd_owned",1);}}
    else if(scope==2)r=tm_error(status,422,"lxc_session_operation_unsupported","LXC 会话仅提供容器终端");
    else if(!strcmp(s->state,"ready")) {
        if(!strcmp(method,"GET")&&(!strcmp(sub,"system-info")||!strcmp(sub,"processes")||!strcmp(sub,"disks")))r=tm_telemetry(s,sub,status);
        else if((!strcmp(sub,"files")&&!strcmp(method,"GET"))||(!strncmp(sub,"files/",6)&&!strcmp(method,"POST")))r=tm_files_route(s,sub,body,status);
        else r=tm_error(status,404,"not_found","操作不存在");
    }else r=tm_error(status,409,"session_not_ready","会话尚未就绪或已结束");
    pthread_mutex_unlock(&s->lock);return r;
done:
    pthread_mutex_unlock(&tm_sessions_lock);return r;
}
