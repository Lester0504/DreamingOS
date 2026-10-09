// SPDX-License-Identifier: GPL-2.0-or-later
#include "api_community.h"
#include "api_error.h"
#include "api_request.h"
#include "api_keys_internal.h"
#include "api_client_control_internal.h"
#include "../webd_community.h"
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
static struct json_object *community_dispatch(struct jmx_api_ctx *ctx){
 if(!webd_identity_is_user(ctx->device_id)){ctx->status=403;return webd_error("personal_session_required","社区需要个人Web会话","","webd.community");}
 if(strcmp(ctx->req->method,"GET")&&ctx->req->auth_via_cookie&&strcmp(ctx->req->sec_fetch_site,"same-origin")){ctx->status=403;return webd_error("same_origin_required","请从设备页面提交操作","","webd.community");}
 char subject[65];if(support_subject(g_config_db,webd_identity_username(ctx->device_id),subject)){ctx->status=503;return webd_error("subject_unavailable","无法解析当前账号","","webd.community");}
 if(mkdir(COMMUNITY_STATE_DIR,0700)&&errno!=EEXIST){ctx->status=503;return webd_error("storage_unavailable","社区存储不可用","","webd.community");}
 sqlite3 *db=NULL;if(community_db_open(COMMUNITY_DB_PATH,&db)){ctx->status=503;return webd_error("storage_unavailable","社区存储不可用","","webd.community");}
 struct support_config config;community_config_load(&config);struct json_object *query=json_object_new_object();char value[128];const char *keys[]={"before","after","limit",NULL};for(int i=0;keys[i];++i)if(webd_query_get(ctx->req->query,keys[i],value,sizeof(value)))json_object_object_add(query,keys[i],json_object_new_string(value));
 struct json_object *r=community_handle(db,&config,subject,ctx->role!=JMX_ROLE_VIEWER,ctx->req->method,ctx->req->path+strlen("/api/v1/community/"),query,ctx->body,&ctx->status);json_object_put(query);sqlite3_close(db);return r;
}
const struct jmx_api_route community_api_routes[]={JMX_API_ROUTE(1125,"/api/v1/community/","GET,POST,PUT,DELETE",JMX_API_PREFIX,community_dispatch),JMX_API_ROUTE_END};
