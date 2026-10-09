// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "terminal_manager.h"
#include "../terminal_manager/tm.h"
#include "api/api_request.h"
#include "webd_http.h"
#include "jmx_app_api.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int webd_terminal_manager_handle(int fd,const struct http_req *req,J *body,const char *owner,int manage,int api_key) {
    const char prefix[]="/api/v1/terminal-manager/";
    const char docker_prefix[]="/api/v1/container_service/docker/terminal/";
    const char lxc_prefix[]="/api/v1/container_service/lxc/terminal/";
    int docker=!strncmp(req->path,docker_prefix,sizeof(docker_prefix)-1),lxc=!strncmp(req->path,lxc_prefix,sizeof(lxc_prefix)-1);
    if(!docker&&!lxc&&strncmp(req->path,prefix,sizeof(prefix)-1))return 0;
    int status=200,client=-1;J *result=NULL,*response=NULL,*request=NULL;const char *path=req->path+(docker?sizeof(docker_prefix)-1:lxc?sizeof(lxc_prefix)-1:sizeof(prefix)-1);
    /* The generic bridge cannot be used to bypass the Docker route boundary. */
    if(!docker&&!lxc&&(!strncmp(path,"docker/",7)||!strncmp(path,"lxc/",4))){result=tm_error(&status,404,"not_found","接口不存在");goto reply;}
    int websocket=strlen(path)>3&&!strcmp(path+strlen(path)-3,"/ws");
    int download=strlen(path)>8&&!strcmp(path+strlen(path)-8,"/content");
    if(api_key){result=tm_error(&status,403,"terminal_api_key_forbidden","终端管理器需要用户会话");goto reply;}
    if(!manage&&strcmp(path,"capabilities")){result=tm_error(&status,403,"terminal_forbidden","终端需要 owner/admin 权限");goto reply;}
    if(websocket){char origin[320],token[128];snprintf(origin,sizeof(origin),"%s://%s",!strcmp(req->forwarded_proto,"https")?"https":"http",req->host);
        if(!req->websocket||strcmp(req->origin,origin)||webd_query_get(req->query,"token",token,sizeof(token))||webd_query_get(req->query,"access_token",token,sizeof(token))){result=tm_error(&status,403,"websocket_origin_denied","交互通道必须使用同源认证会话");goto reply;}}
    client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path,sizeof(address.sun_path),"%s",TM_SOCKET);
    struct timeval timeout={8,0};if(client>=0){setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));}
    if(client<0||connect(client,(struct sockaddr *)&address,sizeof(address))){
        if(!strcmp(path,"capabilities")&&!strcmp(req->method,"GET")){result=json_object_new_object();tm_boolean(result,"engine_available",0);if(docker||lxc){tm_boolean(result,"terminal",0);tm_boolean(result,"connect",0);}tm_string(result,"reason","terminal_runtime_unavailable");J *permissions=json_object_new_object();tm_boolean(permissions,"read",1);tm_boolean(permissions,"manage",0);tm_boolean(permissions,"connect",0);json_object_object_add(result,"permissions",permissions);json_object_object_add(result,"connection_types",json_object_new_array());}
        else result=tm_error(&status,503,"terminal_runtime_unavailable","终端运行服务未安装或未启动");goto reply;
    }
    request=json_object_new_object();tm_string(request,"owner",owner);tm_boolean(request,"manage",manage);tm_string(request,"method",req->method);tm_string(request,"path",path);J *payload=tm_copy(body);
    if(docker||lxc){char scoped[1024];snprintf(scoped,sizeof(scoped),"%s/%s",lxc?"lxc":"docker",path);tm_string(request,"path",scoped);}
    if(websocket)tm_string(payload,"websocket_key",req->ws_key);
    if(!strcmp(req->method,"GET")){char value[4096];if(webd_query_get(req->query,"path",value,sizeof(value)))tm_string(payload,"path",value);if(webd_query_get(req->query,"show_hidden",value,sizeof(value)))tm_boolean(payload,"show_hidden",!strcmp(value,"true")||!strcmp(value,"1"));}
    json_object_object_add(request,"body",payload);
    char marker=websocket||download?'F':'J';struct iovec io={&marker,1};char control[CMSG_SPACE(sizeof(int))]={0};struct msghdr message={.msg_iov=&io,.msg_iovlen=1};
    if(websocket||download){message.msg_control=control;message.msg_controllen=sizeof(control);struct cmsghdr *c=CMSG_FIRSTHDR(&message);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&fd,sizeof(fd));}
    if(sendmsg(client,&message,MSG_NOSIGNAL)!=1||tm_send_json(client,request)||(response=tm_receive_json(client))==NULL){result=tm_error(&status,503,"terminal_runtime_unavailable","终端服务响应未完成");goto reply;}
    status=tm_int(response,"status",502);result=json_object_get(tm_get(response,"data"));if(!result)result=tm_error(&status,502,"terminal_bad_response","终端服务响应格式无效");
reply:
    if(strcmp(req->method,"GET")&&strstr(path,"/lease")==NULL&&strstr(path,"/chunk")==NULL){
        /* Only operation + subject + result, never host credentials, command text or terminal output. */
        jmx_app_audit_log_ex(owner,owner,docker?"docker.terminal.operation":lxc?"lxc.terminal.operation":"terminal_manager.operation","medium",req->path,req->client_ip,status<400?"success":"failed",status<400?"":tm_str(result,"error","terminal_failed"));
    }
    if(!tm_bool(result,"fd_owned",0))http_send_json(fd,status,result);
    if(request){tm_scrub(tm_get(request,"body"));json_object_put(request);}json_object_put(result);json_object_put(response);if(client>=0)close(client);return 1;
}
