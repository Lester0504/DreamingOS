// SPDX-License-Identifier: GPL-2.0-or-later
#include "api_iptv.h"
#include "api_error.h"
#include "iptv/iptv.h"
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#define IPTV_PREFIX "/api/v1/iptv/"
static struct json_object *reply(struct jmx_api_ctx *ctx,struct json_object *o,struct iptv_error *e)
{
    if(o&&!e->status){ctx->status=200;return webd_envelope(o,"webd.iptv");}
    ctx->status=e->status?e->status:500;
    struct json_object *out=webd_error(*e->code?e->code:"internal_error",*e->code?e->code:"internal_error",e->field,"webd.iptv");
    if(o)json_object_object_add(out,"data",o);
    return out;
}
static struct json_object *management(struct jmx_api_ctx *ctx)
{
    struct iptv_error e={0};
    const char *actor=ctx->device_id?ctx->device_id:"";
    struct json_object *o=iptv_request(ctx->req->method,ctx->req->path+strlen(IPTV_PREFIX),ctx->body,actor,&e);
    if(o){json_object_object_add(o,"can_manage",json_object_new_boolean(jmx_perm_check(ctx->role,JMX_RISK_MEDIUM)!=0));}
    return reply(ctx,o,&e);
}
static struct json_object *viewer(struct jmx_api_ctx *ctx,int tv)
{
    struct iptv_error e={0};
    const char *path=ctx->req->path+strlen(tv?IPTV_PREFIX "client/":IPTV_PREFIX "view/");
    int post=!strcmp(ctx->req->method,"POST");
    int lease=!strncmp(path,"release/",8)||!strncmp(path,"renew/",6);
    int state=!strncmp(path,"favorites/",10)||!strncmp(path,"progress/",9);
    if((lease&&!post)||(!lease&&!state&&post)||(!post&&strcmp(ctx->req->method,"GET"))){
        iptv_fail(&e,405,"method_not_allowed","");return reply(ctx,NULL,&e);
    }
    struct json_object *body=post&&state&&ctx->body?json_object_get(ctx->body):json_object_new_object();
    if(lease)json_object_object_add(body,"confirmed",json_object_new_boolean(1));
    if(!strcmp(path,"playlist")){
        const char *host=ctx->req->host;int valid=*host!=0;
        for(const char *p=host;*p;p++)if(!isalnum((unsigned char)*p)&&!strchr(".:-[]",*p))valid=0;
        if(!valid){json_object_put(body);iptv_fail(&e,400,"invalid_host","");return reply(ctx,NULL,&e);}
        char origin[280];snprintf(origin,sizeof(origin),"%s://%s",!strcmp(ctx->req->forwarded_proto,"https")?"https":"http",host);
        json_object_object_add(body,"origin_url",json_object_new_string(origin));
    }
    const char *method=tv?(post?"TV_VIEW_POST":"TV_VIEW"):(post?"WEB_VIEW_POST":"WEB_VIEW");
    struct json_object *o=iptv_request(method,path,body,ctx->req->auth_token,&e);
    json_object_put(body);return reply(ctx,o,&e);
}
static struct json_object *web_view(struct jmx_api_ctx *ctx){return viewer(ctx,0);}
static struct json_object *tv_view(struct jmx_api_ctx *ctx){return viewer(ctx,1);}
static int send_all(int fd,const void *data,size_t len)
{
    const char *p=data;while(len){ssize_t n=send(fd,p,len,MSG_NOSIGNAL);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;len-=(size_t)n;}return 0;
}
static struct json_object *media(struct jmx_api_ctx *ctx)
{
    char token[49],channel[97],name[64],extra;struct iptv_error e={0};
    const char *p=ctx->req->path+strlen(IPTV_PREFIX "media/");
    if(sscanf(p,"%48[^/]/%96[^/]/%63[^/]%c",token,channel,name,&extra)!=3){iptv_fail(&e,404,"resource_not_found","");return reply(ctx,NULL,&e);}
    char *data=NULL;size_t len=0;const char *type=NULL;
    int recording=!strncmp(name,"record-",7);
    if(recording){
        struct json_object *info=iptv_recording_info(token,channel,name,&e),*size=NULL;
        if(!info)return reply(ctx,NULL,&e);
        json_object_object_get_ex(info,"size",&size);int64_t total=json_object_get_int64(size);json_object_put(info);
        if(total<=0||(uint64_t)total>SIZE_MAX){iptv_fail(&e,410,"recording_file_missing","");return reply(ctx,NULL,&e);}
        len=(size_t)total;type="video/mp4";
    }else if(iptv_media_read(token,channel,name,&data,&len,&type,&e))return reply(ctx,NULL,&e);
    size_t start=0,end=len-1;int status=200;char range[160]="";
    if(*ctx->req->range){
        unsigned long long first=0,last=0;int used=0,n=0;
        if(sscanf(ctx->req->range,"bytes=%llu-%llu%n",&first,&last,&used)==2&&ctx->req->range[used]==0){start=(size_t)first;end=last<len?(size_t)last:len-1;n=1;}
        else if(sscanf(ctx->req->range,"bytes=%llu-%n",&first,&used)==1&&used>0&&ctx->req->range[used]==0){start=(size_t)first;n=1;}
        else if(sscanf(ctx->req->range,"bytes=-%llu%n",&last,&used)==1&&ctx->req->range[used]==0&&last>0){start=last<len?len-(size_t)last:0;n=1;}
        if(!n||start>=len||end<start){
            char rejected[256];int size=snprintf(rejected,sizeof(rejected),"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */%zu\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",len);
            if(size>0&&size<(int)sizeof(rejected))send_all(ctx->fd,rejected,(size_t)size);
            free(data);ctx->status=416;return NULL;
        }
        status=206;snprintf(range,sizeof(range),"Content-Range: bytes %zu-%zu/%zu\r\n",start,end,len);
    }
    char header[640];size_t count=end-start+1;
    int n=snprintf(header,sizeof(header),"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nAccept-Ranges: bytes\r\n%sConnection: close\r\n\r\n",status,status==206?"Partial Content":"OK",type,count,range);
    struct timeval timeout={5,0};setsockopt(ctx->fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    if(n>0&&n<(int)sizeof(header)&&!send_all(ctx->fd,header,(size_t)n)&&strcmp(ctx->req->method,"HEAD")){
        if(!recording)send_all(ctx->fd,data+start,count);
        else while(count){
            size_t chunk=0;char *bytes=NULL;size_t limit=count>1024*1024?1024*1024:count;
            if(iptv_recording_read(token,channel,name,(int64_t)start,limit,&bytes,&chunk,&e))break;
            int rc=send_all(ctx->fd,bytes,chunk);free(bytes);if(rc)break;start+=chunk;count-=chunk;
        }
    }
    free(data);ctx->status=status;return NULL;
}
const struct jmx_api_route iptv_api_routes[]={
    JMX_API_ROUTE(1112,"/api/v1/iptv/view/","GET,POST",JMX_API_PREFIX|JMX_API_PREAUTH,web_view),
    JMX_API_ROUTE(1113,"/api/v1/iptv/client/","GET,POST",JMX_API_PREFIX|JMX_API_PREAUTH,tv_view),
    JMX_API_ROUTE(1108,"/api/v1/iptv/media/","GET,HEAD",JMX_API_PREFIX|JMX_API_PREAUTH|JMX_API_RAW_FD,media),
    JMX_API_ROUTE(1109,"/api/v1/iptv/","GET,POST,PUT,DELETE",JMX_API_PREFIX,management),
    JMX_API_ROUTE_END
};
