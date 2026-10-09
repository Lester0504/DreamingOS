// SPDX-License-Identifier: GPL-2.0-or-later
#include "tm.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static int listener=-1;
static void stop_handler(int signal) {(void)signal;stopping=1;if(listener>=0)close(listener);listener=-1;}

static void *serve(void *arg) {
    int fd=(int)(intptr_t)arg,passed=-1;struct timeval timeout={10,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    struct ucred peer;socklen_t peer_len=sizeof(peer);
    if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&peer_len)||peer.uid!=geteuid()){close(fd);return NULL;}
    char marker;char control[CMSG_SPACE(sizeof(int))];struct iovec io={&marker,1};struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    if(recvmsg(fd,&msg,MSG_CMSG_CLOEXEC)!=1){close(fd);return NULL;}for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS)memcpy(&passed,CMSG_DATA(c),sizeof(passed));
    J *request=tm_receive_json(fd),*result=NULL;int status=200,owned=0;
    if(!request){result=tm_error(&status,400,"invalid_request","请求格式无效");goto reply;}
    const char *owner=tm_str(request,"owner",""),*method=tm_str(request,"method","GET"),*path=tm_str(request,"path","");J *body=tm_get(request,"body");int manage=tm_bool(request,"manage",0);
    if(!*owner||strlen(owner)>127){result=tm_error(&status,401,"unauthenticated","需要登录");goto reply;}
    if(!strcmp(path,"capabilities")&&!strcmp(method,"GET"))result=tm_capabilities(manage);
    else if(!strcmp(path,"docker/capabilities")&&!strcmp(method,"GET"))result=tm_docker_capabilities(manage);
    else if(!strcmp(path,"lxc/capabilities")&&!strcmp(method,"GET"))result=tm_lxc_capabilities(manage);
    else if(!manage)result=tm_error(&status,403,"terminal_forbidden","连接与资料管理需要 owner/admin 权限");
    else if(!strcmp(path,"serial-ports")&&!strcmp(method,"GET"))result=tm_serial_ports();
    else if(!strncmp(path,"lxc/",4))result=tm_sessions_route(method,path+4,owner,body,passed,2,&status);
    else if(!strncmp(path,"docker/",7))result=tm_sessions_route(method,path+7,owner,body,passed,1,&status);
    else if(!strncmp(path,"sessions",8))result=tm_sessions_route(method,path,owner,body,passed,0,&status);
    else if(!strncmp(path,"transfers",9))result=tm_transfers_route(method,path,owner,body,passed,&status);
    else result=tm_store_route(method,path,owner,body,&status);
reply:
    if(result)owned=tm_bool(result,"fd_owned",0);
    J *response=json_object_new_object();tm_number(response,"status",status);json_object_object_add(response,"data",result);tm_send_json(fd,response);json_object_put(response);
    if(request){tm_scrub(tm_get(request,"body"));json_object_put(request);}if(passed>=0&&!owned)close(passed);close(fd);return NULL;
}

int main(int argc,char **argv) {
    const char *socket_path=TM_SOCKET,*store=TM_STORE,*key=TM_SECRET_KEY;
    /* Arguments are service/test paths, never accepted from HTTP. */
    for(int i=1;i+1<argc;i+=2){if(!strcmp(argv[i],"--socket"))socket_path=argv[i+1];else if(!strcmp(argv[i],"--store"))store=argv[i+1];else if(!strcmp(argv[i],"--key"))key=argv[i+1];else if(!strcmp(argv[i],"--spool"))snprintf(tm_spool,sizeof(tm_spool),"%s",argv[i+1]);else return 2;}
    umask(077);signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_handler);signal(SIGINT,stop_handler);
    if(libssh2_init(0)||tm_store_open(store,key)||tm_transfers_init())return 1;tm_sessions_init();
    listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(listener<0)return 1;
    struct sockaddr_un address={.sun_family=AF_UNIX};if(strlen(socket_path)>=sizeof(address.sun_path))return 1;snprintf(address.sun_path,sizeof(address.sun_path),"%s",socket_path);
    /* Never unlink a live peer's socket. */
    int probe=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(connect(probe,(struct sockaddr *)&address,sizeof(address))==0){close(probe);return 1;}close(probe);unlink(socket_path);
    if(bind(listener,(struct sockaddr *)&address,sizeof(address))||chmod(socket_path,0600)||listen(listener,16))return 1;
    while(!stopping){int fd=accept4(listener,NULL,NULL,SOCK_CLOEXEC);if(fd<0){if(errno==EINTR)continue;break;}pthread_t thread;if(pthread_create(&thread,NULL,serve,(void *)(intptr_t)fd))close(fd);else pthread_detach(thread);}
    for(int i=0;i<TM_MAX_SESSIONS;i++){pthread_mutex_lock(&tm_sessions[i].lock);tm_sessions[i].stop=1;pthread_mutex_unlock(&tm_sessions[i].lock);}for(int j=0;j<100;j++){int live=0;for(int i=0;i<TM_MAX_SESSIONS;i++){pthread_mutex_lock(&tm_sessions[i].lock);live+=tm_sessions[i].used&&!tm_sessions[i].finished;pthread_mutex_unlock(&tm_sessions[i].lock);}if(!live)break;usleep(100000);}
    unlink(socket_path);return 0;
}
