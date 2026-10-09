/* SPDX-License-Identifier: GPL-2.0-or-later
 * Included by ai_runtime.c: keep the existing history/response ownership path. */
#include "../ai/local_ipc.h"
static struct json_object *ai_local_call(struct json_object *request,int *status)
{
    int fd=al_connect();struct json_object *j=NULL;
    if(fd>=0){if(!al_send(fd,request))j=al_recv(fd,5000);close(fd);}
    if(!j){if(status)*status=503;return ai_error("local_manager_unavailable","本机推理管理服务未安装或未运行",503,0,NULL,NULL);}
    if(status)*status=al_i(j,"status")?(int)al_i(j,"status"):json_object_get_boolean(json_object_object_get(j,"ok"))?200:503;
    return j;
}
struct json_object *webd_ai_local_request(const char *method,const char *path,
    struct json_object *body,const char *actor,int *status)
{
    struct json_object *q=json_object_new_object();const char *base="/api/v1/ai/local/",*tail=path+strlen(base);
    const char *fields[]={"model_id","volume_id","revision","action",NULL};
    for(int i=0;fields[i];i++){struct json_object *v=body?json_object_object_get(body,fields[i]):NULL;if(v)json_object_object_add(q,fields[i],json_object_get(v));}
    al_str(q,"actor",actor);int valid=1;
    if(!strcmp(method,"GET")&&(!strcmp(tail,"status")||!strcmp(tail,"models")))al_str(q,"op",tail);
    else if(!strcmp(tail,"config")&&(!strcmp(method,"GET")||!strcmp(method,"PUT"))){al_str(q,"op","config");al_bool(q,"write",!strcmp(method,"PUT"));}
    else if(!strcmp(tail,"service")&&!strcmp(method,"POST"))al_str(q,"op","service");
    else if(!strncmp(tail,"models/",7)&&!strcmp(method,"POST")){const char *end=strstr(tail+7,"/download");if(!end||end[9]||end-tail-7>80)valid=0;else{char id[81]={0};memcpy(id,tail+7,(size_t)(end-tail-7));al_str(q,"model_id",id);al_str(q,"op","service");al_str(q,"action","download");}}
    else if(!strncmp(tail,"tasks/",6)){const char *end=strchr(tail+6,'/');size_t n=end?(size_t)(end-tail-6):strlen(tail+6);if(!n||n>80)valid=0;else{char id[81]={0};memcpy(id,tail+6,n);al_str(q,"task_id",id);if(!end&&!strcmp(method,"GET"))al_str(q,"op","task");else if(end&&!strcmp(end,"/cancel")&&!strcmp(method,"POST"))al_str(q,"op","cancel_task");else valid=0;}}
    else valid=0;
    struct json_object *j;if(valid)j=ai_local_call(q,status);else{if(status)*status=404;j=ai_error("not_found","Local AI endpoint not found",404,0,NULL,NULL);}json_object_put(q);return j;
}
