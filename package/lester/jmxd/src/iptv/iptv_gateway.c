// SPDX-License-Identifier: GPL-2.0-or-later
/* webd worker client. The supervisor and all stream state live in iptvd. */
#include "iptv.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/un.h>
#include "iptv_ipc.h"
struct json_object *iptv_fail(struct iptv_error *e,int status,const char *code,const char *field)
{
    e->status=status;snprintf(e->code,sizeof(e->code),"%s",code);snprintf(e->field,sizeof(e->field),"%s",field?field:"");return NULL;
}
static struct json_object *failure(struct iptv_error *e)
{e->status=503;snprintf(e->code,sizeof(e->code),"%s","iptv_service_unavailable");e->field[0]=0;return NULL;}
static struct json_object *rpc(struct json_object *request,char **bytes,size_t *len,const char **type,struct iptv_error *e)
{
    memset(e,0,sizeof(*e));int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(fd<0)return failure(e);
    struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    struct sockaddr_un addr={.sun_family=AF_UNIX};snprintf(addr.sun_path,sizeof(addr.sun_path),"%s",IPTV_SOCKET);
    if(connect(fd,(struct sockaddr*)&addr,sizeof(addr))||iptv_send(fd,request)){close(fd);return failure(e);}
    struct json_object *response=iptv_recv(fd),*v=NULL,*result=NULL;
    if(!response){close(fd);return failure(e);}
    if(json_object_object_get_ex(response,"status",&v))e->status=json_object_get_int(v);
    if(e->status){if(json_object_object_get_ex(response,"code",&v))snprintf(e->code,sizeof(e->code),"%s",json_object_get_string(v));
        if(json_object_object_get_ex(response,"field",&v))snprintf(e->field,sizeof(e->field),"%s",json_object_get_string(v));
        if(json_object_object_get_ex(response,"data",&v)&&v)result=json_object_get(v);}
    else if(bytes){
        int64_t size=0;if(json_object_object_get_ex(response,"length",&v))size=json_object_get_int64(v);
        if(size<=0||size>16*1024*1024||!(*bytes=malloc((size_t)size+1))||iptv_io(fd,*bytes,(size_t)size,0)){
            free(*bytes);*bytes=NULL;failure(e);
        }else{(*bytes)[size]=0;*len=(size_t)size;
            const char *s=json_object_object_get_ex(response,"type",&v)?json_object_get_string(v):"";
            *type=!strcmp(s,"application/vnd.apple.mpegurl")?"application/vnd.apple.mpegurl":!strcmp(s,"video/mp4")?"video/mp4":"video/mp2t";
            result=json_object_new_object();}
    }else if(json_object_object_get_ex(response,"data",&v)&&v)result=json_object_get(v);
    if(!result&&!e->status)failure(e);
    json_object_put(response);close(fd);return result;
}
struct json_object *iptv_request(const char *method,const char *resource,struct json_object *body,const char *actor,struct iptv_error *e)
{
    struct json_object *q=json_object_new_object();
    json_object_object_add(q,"method",json_object_new_string(method));json_object_object_add(q,"resource",json_object_new_string(resource));
    json_object_object_add(q,"actor",json_object_new_string(actor?actor:""));json_object_object_add(q,"body",body?json_object_get(body):NULL);
    struct json_object *r=rpc(q,NULL,NULL,NULL,e);json_object_put(q);return r;
}
int iptv_media_read(const char *token,const char *id,const char *name,char **bytes,size_t *len,const char **type,struct iptv_error *e)
{
    *bytes=NULL;*len=0;struct json_object *q=json_object_new_object();
    json_object_object_add(q,"method",json_object_new_string("MEDIA"));json_object_object_add(q,"token",json_object_new_string(token));
    json_object_object_add(q,"channel",json_object_new_string(id));json_object_object_add(q,"name",json_object_new_string(name));
    struct json_object *r=rpc(q,bytes,len,type,e);json_object_put(q);if(!r)return -1;json_object_put(r);return 0;
}
static struct json_object *record_request(const char *method,const char *token,const char *channel,const char *name)
{
    struct json_object *q=json_object_new_object();
    json_object_object_add(q,"method",json_object_new_string(method));
    json_object_object_add(q,"token",json_object_new_string(token));
    json_object_object_add(q,"channel",json_object_new_string(channel));
    json_object_object_add(q,"name",json_object_new_string(name));return q;
}
struct json_object *iptv_recording_info(const char *token,const char *channel,const char *name,struct iptv_error *e)
{
    struct json_object *q=record_request("MEDIA_RECORD_INFO",token,channel,name),*result=rpc(q,NULL,NULL,NULL,e);json_object_put(q);return result;
}
int iptv_recording_read(const char *token,const char *channel,const char *name,int64_t offset,size_t maximum,char **data,size_t *length,struct iptv_error *e)
{
    *data=NULL;*length=0;const char *type=NULL;
    struct json_object *q=record_request("MEDIA_RECORD_READ",token,channel,name);
    json_object_object_add(q,"offset",json_object_new_int64(offset));json_object_object_add(q,"maximum",json_object_new_int64(maximum));
    struct json_object *r=rpc(q,data,length,&type,e);json_object_put(q);if(r)json_object_put(r);return r?0:-1;
}
