// SPDX-License-Identifier: GPL-2.0-or-later
#include "api_netboot.h"
#include "api_ubus.h"
#include "api_error.h"
#include "api_request.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"
#include <stdlib.h>
#include <string.h>

static struct json_object *netboot_dispatch(struct jmx_api_ctx *ctx)
{
    char tail[256],decoded_id[256];const char *suffix=ctx->req->path+strlen("/api/v1/netboot/");
    if(strlen(suffix)>=sizeof tail){ctx->status=404;return NULL;}
    strcpy(tail,suffix);char *id=strchr(tail,'/'),*action=NULL;
    if(id){*id++=0;action=strchr(id,'/');if(action)*action++=0;}
    /* The HTTP parser preserves %3A in MAC identifiers sent by the browser. */
    if(id) {
        size_t n=0;
        for(size_t i=0;id[i];i++) {
            unsigned char c=id[i];
            if(c=='%') {
                if(!id[i+1]||!id[i+2])goto invalid_id;
                int hi=webd_hex_value(id[i+1]),lo=webd_hex_value(id[i+2]);
                if(hi<0||lo<0)goto invalid_id;
                c=(unsigned char)((hi<<4)|lo);i+=2;
            }
            if(!c||c=='/'||c=='\\')goto invalid_id;
            decoded_id[n++]=c;
        }
        decoded_id[n]=0;id=decoded_id;
    }
    struct json_object *p=json_object_new_object();
    json_object_object_add(p,"method",json_object_new_string(ctx->req->method));
    json_object_object_add(p,"resource",json_object_new_string(tail));
    json_object_object_add(p,"id",json_object_new_string(id?id:""));
    json_object_object_add(p,"action",json_object_new_string(action?action:""));
    struct json_object *body=ctx->body?json_object_get(ctx->body):json_object_new_object();
    if(!strcmp(ctx->req->method,"GET")&&!strcmp(tail,"logs")) {
        char offset[20]="0",limit[20]="20";
        webd_query_get(ctx->req->query,"offset",offset,sizeof offset);webd_query_get(ctx->req->query,"limit",limit,sizeof limit);
        json_object_object_add(body,"offset",json_object_new_int(atoi(offset)));json_object_object_add(body,"limit",json_object_new_int(atoi(limit)));
    }
    json_object_object_add(p,"body",body);
    struct json_object *response=app_ubus_invoke_timeout("netboot",p,30000),*http=NULL;json_object_put(p);
    if(response&&json_object_object_get_ex(response,"http_status",&http))ctx->status=json_object_get_int(http);
    else ctx->status=app_response_status(response,502);
    if(strcmp(ctx->req->method,"GET")&&strcmp(tail,"preflight"))
        jmx_app_audit_log(ctx->device_id&&ctx->device_id[0]?ctx->device_id:"http",ctx->device_id,"netboot.manage","medium",ctx->req->path,"",ctx->status<400?"success":"failed");
    return response;
invalid_id:
    ctx->status=400;
    return webd_error("invalid_id","Invalid Netboot identifier",NULL,"netboot");
}
const struct jmx_api_route netboot_api_routes[]={
    JMX_API_ROUTE(1111,"/api/v1/netboot/","GET,POST,PUT,DELETE",JMX_API_PREFIX,netboot_dispatch),
    JMX_API_ROUTE_END
};
