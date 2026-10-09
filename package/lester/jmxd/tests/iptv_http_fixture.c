/* Transport fixture: uses the actual IPTV raw route and IPC gateway. It does
 * not exercise the outer webd login/role dispatcher. Only a /tmp IPC daemon
 * compiled with IPTV_TESTING is permitted by the companion build invocation. */
#include "webd/api/api_iptv.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int jmx_perm_check(jmx_role_t role,jmx_risk_t risk){(void)risk;return role==JMX_ROLE_OWNER;}
struct json_object *webd_envelope(struct json_object *data,const char *source){(void)source;return data;}
struct json_object *webd_error(const char *code,const char *message,const char *missing,const char *source)
{(void)message;(void)missing;(void)source;struct json_object *o=json_object_new_object();json_object_object_add(o,"code",json_object_new_string(code));return o;}
static void *request(void *opaque)
{
    struct jmx_api_ctx *ctx=opaque;const struct jmx_api_route *route=iptv_api_routes;
    while(route->path&&strcmp(route->path,"/api/v1/iptv/media/"))route++;
    struct json_object *error=route->handler(ctx);
    if(error){dprintf(ctx->fd,"HTTP/1.1 %d Error\r\nConnection: close\r\n\r\n%s",ctx->status,json_object_to_json_string(error));json_object_put(error);}
    shutdown(ctx->fd,SHUT_WR);close(ctx->fd);return NULL;
}
int main(int argc,char **argv)
{
    if(argc<3||strncmp(argv[2],"/api/v1/iptv/media/",19))return 2;
    struct http_req req={0};snprintf(req.method,sizeof(req.method),"%s",argv[1]);snprintf(req.path,sizeof(req.path),"%s",argv[2]);
    if(argc>3)snprintf(req.range,sizeof(req.range),"%s",argv[3]);
    int fd[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,fd))return 2;
    struct jmx_api_ctx ctx={.req=&req,.fd=fd[1],.status=200,.role=JMX_ROLE_OWNER};pthread_t thread;
    if(pthread_create(&thread,NULL,request,&ctx))return 2;
    char buf[8192];ssize_t n;while((n=read(fd[0],buf,sizeof(buf)))>0)if(fwrite(buf,1,(size_t)n,stdout)!=(size_t)n)return 2;
    close(fd[0]);pthread_join(thread,NULL);return 0;
}
