/* Actual IPTV API adapter + IPC gateway, isolated daemon only. */
#include "webd/api/api_iptv.h"
#include <stdio.h>
#include <string.h>
int jmx_perm_check(jmx_role_t r,jmx_risk_t risk){(void)r;(void)risk;return 1;}
struct json_object *webd_envelope(struct json_object *data,const char *source)
{(void)source;struct json_object *o=json_object_new_object();json_object_object_add(o,"ok",json_object_new_boolean(1));json_object_object_add(o,"data",data);return o;}
struct json_object *webd_error(const char *code,const char *message,const char *field,const char *source)
{(void)message;(void)source;struct json_object *o=json_object_new_object(),*e=json_object_new_object();json_object_object_add(o,"ok",json_object_new_boolean(0));json_object_object_add(e,"code",json_object_new_string(code));json_object_object_add(e,"field",json_object_new_string(field));json_object_object_add(o,"error",e);return o;}
int main(int argc,char **argv)
{
    if(argc!=5)return 2;
    struct http_req req={0};snprintf(req.method,sizeof(req.method),"%s",argv[1]);snprintf(req.path,sizeof(req.path),"%s",argv[2]);snprintf(req.auth_token,sizeof(req.auth_token),"%s",argv[3]);
    struct jmx_api_ctx ctx={.req=&req,.body=json_tokener_parse(argv[4]),.status=200};
    const struct jmx_api_route *route=iptv_api_routes;
    while(route->path&&strncmp(req.path,route->path,strlen(route->path)))route++;
    if(!route->path)return 2;
    struct json_object *body=route->handler(&ctx),*out=json_object_new_object();json_object_object_add(out,"status",json_object_new_int(ctx.status));json_object_object_add(out,"body",body);puts(json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN));
    json_object_put(out);if(ctx.body)json_object_put(ctx.body);return 0;
}
