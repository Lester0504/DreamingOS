// SPDX-License-Identifier: GPL-2.0-or-later
/* Link the production TV worker and webd framing. Only the DB paths are replaced. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "tvhome/tvhome_store.h"
#include "tvhome/tvhome_ws.h"
#include "webd/api/webd_http_req.h"
#ifndef TVH_DB_PATH
#error Disposable TVH_DB_PATH required
#endif
static int checks;
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#c);exit(1); } } while(0)
static const char *str(struct json_object *o,const char *key) { struct json_object *v=NULL;json_object_object_get_ex(o,key,&v);return v?json_object_get_string(v):""; }
static void exact(int fd,void *p,size_t n) { while(n) { struct pollfd f={fd,POLLIN,0};CHECK(poll(&f,1,5000)>0);ssize_t r=read(fd,p,n);CHECK(r>0);p=(char *)p+r;n-=r; } }
static int frame(int fd,char *out) {
    unsigned char h[4];exact(fd,h,2);int op=h[0]&15;size_t n=h[1]&127;
    if(n==126) {exact(fd,h+2,2);n=(h[2]<<8)|h[3];}CHECK(n<4096);
    exact(fd,out,n);out[n]=0;
    if(op==9) {unsigned char pong[]={0x8a,0x80,1,2,3,4};CHECK(write(fd,pong,sizeof(pong))==sizeof(pong));return frame(fd,out);}
    return op;
}
static int open_ws(const char *token,pid_t *pid) {
    int fd[2];CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);*pid=fork();CHECK(*pid>=0);
    if(!*pid) {close(fd[0]);struct http_req req={0};req.websocket=1;snprintf(req.auth_token,sizeof(req.auth_token),"%s",token);strcpy(req.ws_key,"dGhlIHNhbXBsZSBub25jZQ==");tvhome_ws_session(fd[1],&req);close(fd[1]);_exit(0);}
    close(fd[1]);char h[1024]={0};size_t n=0;
    while(n<sizeof(h)-1 && !strstr(h,"\r\n\r\n")) {exact(fd[0],h+n,1);n++;}
    CHECK(strstr(h,"101 Switching Protocols"));CHECK(strstr(h,"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));return fd[0];
}
int main(void) {
    signal(SIGPIPE,SIG_IGN);alarm(25);CHECK(!strncmp(TVH_DB_PATH,"/tmp/",5));unlink(TVH_DB_PATH);
    struct tvhome_err e={0};struct json_object *body=json_tokener_parse("{\"device\":{\"device_id\":\"ws-box\",\"model\":\"WS test\"}}");
    struct json_object *r=tvhome_activation_request(body,&e);CHECK(r);char *id=strdup(str(r,"id"));json_object_put(r);
    r=tvhome_activation_decide(id,1,NULL,&e);CHECK(r);char *terminal=strdup(str(r,"terminal_id"));
    struct json_object *activation=json_object_new_object();json_object_object_add(activation,"code",json_object_new_string(str(r,"activation_code")));json_object_object_add(body,"activation",activation);json_object_put(r);
    r=tvhome_session_create(body,&e);CHECK(r);char *token=strdup(str(r,"token"));json_object_put(r);
    CHECK(tvhome_ws_count(terminal)==0);pid_t pid;char payload[4096];int fd=open_ws(token,&pid);
    CHECK(frame(fd,payload)==1 && strstr(payload,"hello"));
    for(int i=0;i<20 && !tvhome_ws_count(terminal);i++) usleep(10000);
    CHECK(tvhome_ws_count(terminal)==1);
    r=tvhome_terminal_action(terminal,"refresh",&e);CHECK(r);json_object_put(r);
    CHECK(frame(fd,payload)==1 && strstr(payload,"reload"));
    close(fd);CHECK(waitpid(pid,NULL,0)==pid);CHECK(tvhome_ws_count(terminal)==0);
    r=tvhome_bootstrap(token,&e);CHECK(r);json_object_put(r); /* disconnect != logout */
    fd=open_ws(token,&pid);CHECK(frame(fd,payload)==1 && strstr(payload,"hello"));
    r=tvhome_terminal_action(terminal,"kick",&e);CHECK(r);json_object_put(r);
    CHECK(frame(fd,payload)==8);CHECK((unsigned char)payload[0]==15 && (unsigned char)payload[1]==161); /* 4001 */
    close(fd);CHECK(waitpid(pid,NULL,0)==pid);CHECK(tvhome_ws_count(terminal)==0);
    CHECK(!tvhome_bootstrap(token,&e) && e.http_status==401);
    free(id);free(terminal);free(token);json_object_put(body);
    printf("PASS %d checks: real 101/accept key, hello, reload, socket leases, reconnect, revoke/4001\n",checks);return 0;
}
