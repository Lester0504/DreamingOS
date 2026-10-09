// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_IPTV_IPC_H
#define DWRT_IPTV_IPC_H
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <json-c/json.h>
#ifndef IPTV_SOCKET
#define IPTV_SOCKET "/var/run/dreamingwrt-iptv.sock"
#endif
#define IPTV_IPC_MAX (2U*1024U*1024U)
static int iptv_io(int fd,void *buf,size_t size,int writing)
{
    char *p=buf;
    while(size){ssize_t n=writing?send(fd,p,size,MSG_NOSIGNAL):recv(fd,p,size,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        p+=n;size-=(size_t)n;}
    return 0;
}
static int iptv_send(int fd,struct json_object *o)
{
    const char *s=json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN);
    size_t len=strlen(s);if(len>IPTV_IPC_MAX)return -1;
    uint32_t n=htonl((uint32_t)len);
    return iptv_io(fd,&n,4,1)||iptv_io(fd,(void*)s,len,1)?-1:0;
}
static struct json_object *iptv_recv(int fd)
{
    uint32_t n;if(iptv_io(fd,&n,4,0))return NULL;n=ntohl(n);
    if(!n||n>IPTV_IPC_MAX)return NULL;
    char *s=malloc(n+1);if(!s)return NULL;
    if(iptv_io(fd,s,n,0)){free(s);return NULL;}s[n]=0;
    struct json_object *o=json_tokener_parse(s);free(s);return o;
}
#endif
