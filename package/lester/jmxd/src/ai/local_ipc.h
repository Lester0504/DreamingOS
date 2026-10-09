/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DW_AI_LOCAL_IPC_H
#define DW_AI_LOCAL_IPC_H
#include <json-c/json.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#define AL_SOCKET "/var/run/dreamingwrt-ai-local.sock"
#define AL_FRAME_MAX (512 * 1024)
static const char *al_s(struct json_object *j, const char *k) {
    struct json_object *v = j ? json_object_object_get(j,k) : NULL;
    return v && json_object_is_type(v,json_type_string) ? json_object_get_string(v) : "";
}
static int64_t al_i(struct json_object *j,const char *k) {return json_object_get_int64(j ? json_object_object_get(j,k) : NULL);}
static void al_str(struct json_object *j,const char *k,const char *v) {json_object_object_add(j,k,v ? json_object_new_string(v) : NULL);}
static void al_num(struct json_object *j,const char *k,int64_t v) {json_object_object_add(j,k,json_object_new_int64(v));}
static void al_bool(struct json_object *j,const char *k,int v) {json_object_object_add(j,k,json_object_new_boolean(v));}
static struct json_object *al_error(const char *code,int status) {
    struct json_object *j=json_object_new_object(),*e=json_object_new_object();
    al_bool(j,"ok",0);al_num(j,"status",status);al_str(e,"code",code);al_str(e,"message",code);json_object_object_add(j,"error",e);return j;
}
static struct json_object *al_ok(struct json_object *d) {struct json_object *j=json_object_new_object();al_bool(j,"ok",1);json_object_object_add(j,"data",d);return j;}
static int al_bytes(int fd,void *buf,size_t n,int writing,int timeout) {
    size_t off=0;
    while(off<n){struct pollfd p={fd,(short)(writing?POLLOUT:POLLIN),0};int r=poll(&p,1,timeout);
        if(r<0&&errno==EINTR)continue;if(r<=0){if(!r)errno=ETIMEDOUT;return -1;}
        ssize_t k=writing?send(fd,(char*)buf+off,n-off,MSG_NOSIGNAL):recv(fd,(char*)buf+off,n-off,0);
        if(k<0&&errno==EINTR)continue;if(k<=0)return -1;off+=(size_t)k;
    }return 0;
}
static int al_send(int fd,struct json_object *j) {
    const char *s=json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN);size_t n=strlen(s);uint32_t z=htonl((uint32_t)n);
    if(n>AL_FRAME_MAX)return -1;return al_bytes(fd,&z,4,1,5000)||al_bytes(fd,(void*)s,n,1,5000)?-1:0;
}
static struct json_object *al_recv(int fd,int timeout) {
    uint32_t n;if(al_bytes(fd,&n,4,0,timeout))return NULL;n=ntohl(n);if(!n||n>AL_FRAME_MAX)return NULL;
    char *s=(char*)calloc(1,(size_t)n+1);if(!s)return NULL;if(al_bytes(fd,s,n,0,5000)){free(s);return NULL;}
    struct json_object *j=json_tokener_parse(s);free(s);return j;
}
static int al_connect(void) {
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
    struct sockaddr_un a={.sun_family=AF_UNIX};snprintf(a.sun_path,sizeof(a.sun_path),"%s",AL_SOCKET);
    if(connect(fd,(struct sockaddr*)&a,sizeof(a))){close(fd);return -1;}return fd;
}
#endif
