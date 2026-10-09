// SPDX-License-Identifier: GPL-2.0-or-later
/* Boot traffic never enters the administrator API or carries its session. */
#include "netboot_internal.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NB_CONNECTIONS 8
#define NB_SESSIONS 64
struct boot_session {char token[65],mac[18],ip[48],arch[16],password_hash[65];time_t expires;};
struct connection {int used,fd;char ip[48],image[65];};
static pthread_mutex_t http_lock=PTHREAD_MUTEX_INITIALIZER,event_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t idle=PTHREAD_COND_INITIALIZER;
static pthread_t listener_thread;
static int listener=-1,stopping;
static char bind_ip[48];static int bind_port;static unsigned net_prefix;
static struct connection connections[NB_CONNECTIONS];
static struct boot_session sessions[NB_SESSIONS];
static struct json_object *events,*observations;

void nb_event(const char *type,const char *mac,const char *image,const char *reason)
{
    pthread_mutex_lock(&event_lock);
    if(!events)events=json_object_new_array();
    if(json_object_array_length(events)>=NB_MAX_EVENTS)json_object_array_del_idx(events,0,1);
    struct json_object *e=json_object_new_object();nb_text(e,"type",type);nb_text(e,"mac",mac);nb_text(e,"image_id",image);nb_text(e,"reason",reason);nb_int(e,"time",time(NULL));
    json_object_array_add(events,e);pthread_mutex_unlock(&event_lock);
}
struct json_object *nb_events(int offset,int limit)
{
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    if(offset<0)offset=0;if(limit<=0)limit=20;if(limit>100)limit=100;
    pthread_mutex_lock(&event_lock);int count=events?(int)json_object_array_length(events):0;
    for(int i=count-1-offset;i>=0&&limit-->0;i--)json_object_array_add(items,nb_clone(json_object_array_get_idx(events,i)));
    pthread_mutex_unlock(&event_lock);nb_int(out,"total",count);nb_int(out,"offset",offset);nb_text(out,"retention","memory_256_events");json_object_object_add(out,"items",items);return out;
}
void nb_events_clear(void)
{pthread_mutex_lock(&event_lock);if(events)json_object_put(events);events=json_object_new_array();pthread_mutex_unlock(&event_lock);}
void nb_observe_client(const char *mac,const char *ip,const char *arch,const char *platform)
{
    pthread_mutex_lock(&event_lock);if(!observations)observations=json_object_new_array();
    struct json_object *o=nb_find(observations,mac);
    if(!o) {
        if(json_object_array_length(observations)>=NB_MAX_CLIENTS)json_object_array_del_idx(observations,0,1);
        o=json_object_new_object();nb_text(o,"id",mac);nb_text(o,"mac",mac);nb_text(o,"source","observed");nb_flag(o,"allowed",0);nb_text(o,"name","");json_object_array_add(observations,o);
    }
    nb_text(o,"ip",ip);nb_text(o,"arch",arch);nb_text(o,"platform",platform);nb_int(o,"last_seen",time(NULL));pthread_mutex_unlock(&event_lock);
}
struct json_object *nb_observed_clients(void)
{pthread_mutex_lock(&event_lock);struct json_object *o=observations?nb_clone(observations):json_object_new_array();pthread_mutex_unlock(&event_lock);return o;}
int nb_http_busy(const char *id)
{
    int busy=0;pthread_mutex_lock(&http_lock);
    for(int i=0;i<NB_CONNECTIONS;i++)if(connections[i].used&&*connections[i].image&&(!*id||!strcmp(connections[i].image,id)))busy++;
    pthread_mutex_unlock(&http_lock);return busy;
}
int nb_http_ready(const char *address,int port)
{pthread_mutex_lock(&http_lock);int ready=listener>=0&&!stopping&&!strcmp(address,bind_ip)&&port==bind_port;pthread_mutex_unlock(&http_lock);return ready;}
static int send_all(int fd,const void *buffer,size_t size)
{
    const char *p=buffer;
    while(size){ssize_t n=send(fd,p,size,MSG_NOSIGNAL);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;size-=n;}return 0;
}
static void text_response(int fd,int status,const char *body,int head)
{
    char h[512];size_t len=strlen(body);
    snprintf(h,sizeof h,"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",status,status==200?"OK":status==403?"Forbidden":"Error",len);
    if(!send_all(fd,h,strlen(h))&&!head)send_all(fd,body,len);
}
static int decode(char *dst,size_t size,const char *src,int form)
{
    size_t n=0;for(;*src;src++) {
        unsigned char ch=*src;
        if(ch=='%') {
            if(!src[1]||!src[2]||!isxdigit((unsigned char)src[1])||!isxdigit((unsigned char)src[2]))return -1;
            char hex[3]={src[1],src[2],0};ch=strtoul(hex,NULL,16);src+=2;
        } else if(ch=='+'&&form)ch=' ';
        if(ch<32||ch==127||n+1>=size)return -1;dst[n++]=ch;
    }dst[n]=0;return 0;
}
static int form_value(const char *body,const char *key,char *out,size_t size)
{
    char copy[2049];if(strlen(body)>=sizeof copy)return -1;strcpy(copy,body);char *save=NULL;out[0]=0;
    for(char *part=strtok_r(copy,"&",&save);part;part=strtok_r(NULL,"&",&save)) {
        char *eq=strchr(part,'=');if(!eq)continue;*eq=0;if(!strcmp(part,key))return decode(out,size,eq+1,1);
    }return 0;
}
static int client_allowed(struct json_object *cfg,const char *mac)
{
    struct json_object *client=nb_find(nb_value(cfg,"clients"),mac);
    return client?nb_bool(client,"allowed"):nb_bool(nb_value(cfg,"settings"),"allow_unknown");
}
static int session_load(const char *token,const char *ip,struct json_object *cfg,struct boot_session *out)
{
    int ok=0;pthread_mutex_lock(&http_lock);
    for(int i=0;i<NB_SESSIONS;i++)if(!strcmp(sessions[i].token,token)&&sessions[i].expires>time(NULL)&&!strcmp(sessions[i].ip,ip)) {*out=sessions[i];ok=1;break;}
    pthread_mutex_unlock(&http_lock);
    return ok&&nb_bool(nb_value(cfg,"settings"),"enabled")&&client_allowed(cfg,out->mac)&&
        !strcmp(out->password_hash,nb_string(nb_value(cfg,"settings"),"password_hash"));
}
static int session_create(const char *body,const char *ip,struct json_object *cfg,struct boot_session *out)
{
    char mac[64],password[129],arch[32],platform[16];
    if(form_value(body,"mac",mac,sizeof mac)||form_value(body,"password",password,sizeof password)||form_value(body,"arch",arch,sizeof arch)||form_value(body,"platform",platform,sizeof platform)||nb_mac(mac,out->mac))return -1;
    nb_observe_client(out->mac,ip,arch,!strcmp(platform,"pcbios")||!strcmp(platform,"efi")?platform:"");
    if(strcmp(arch,"x86_64")||!client_allowed(cfg,out->mac)||!nb_password_check(nb_value(cfg,"settings"),password)) {
        nb_event("denied",out->mac,"","client_policy_or_password");return -1;
    }
    unsigned char random[32];if(RAND_bytes(random,sizeof random)!=1)return -1;
    for(int i=0;i<32;i++)sprintf(out->token+i*2,"%02x",random[i]);
    snprintf(out->ip,sizeof out->ip,"%s",ip);snprintf(out->arch,sizeof out->arch,"%s",arch);
    snprintf(out->password_hash,sizeof out->password_hash,"%s",nb_string(nb_value(cfg,"settings"),"password_hash"));out->expires=time(NULL)+12*3600;
    pthread_mutex_lock(&http_lock);int index=0;
    for(int i=0;i<NB_SESSIONS;i++)if(sessions[i].expires<sessions[index].expires)index=i;
    sessions[index]=*out;pthread_mutex_unlock(&http_lock);return 0;
}
static int image_allowed(struct json_object *image,struct boot_session *session)
{
    if(!image||!nb_bool(image,"enabled"))return 0;
    nb_image_observe(image);
    return !strcmp(nb_string(image,"image_status"),"ready")&&!strcmp(nb_string(image,"arch"),session->arch)&&!strcmp(nb_string(image,"method"),"rhel9-http");
}
static void safe_label(const char *s,char *out,size_t size)
{
    size_t i=0;for(;*s&&i+1<size;s++){unsigned char c=*s;out[i++]=(c<32||strchr("$;&|\\",c))?' ':c;}out[i]=0;
}
static char *menu_script(struct json_object *cfg,struct boot_session *session)
{
    char *text=NULL;size_t length=0;FILE *f=open_memstream(&text,&length);if(!f)return NULL;
    struct json_object *s=nb_value(cfg,"settings"),*items=nb_value(cfg,"images"),*client=nb_find(nb_value(cfg,"clients"),session->mac);
    const char *preferred=*nb_string(client,"default_image_id")?nb_string(client,"default_image_id"):nb_string(s,"default_image_id");
    int valid=image_allowed(nb_find(items,preferred),session);
    fprintf(f,"#!ipxe\nmenu DreamingWrt\nitem local Boot from local disk\n");
    for(size_t i=0;i<json_object_array_length(items);i++) {
        struct json_object *image=json_object_array_get_idx(items,i);if(!image_allowed(image,session))continue;
        char label[256];safe_label(nb_string(image,"name"),label,sizeof label);fprintf(f,"item %s %s\n",nb_string(image,"id"),label);
    }
    fprintf(f,"choose --timeout %lld --default %s target || goto local\niseq ${target} local && goto local || goto selected\n:selected\n"
        "chain http://%s:%d/s/%s/boot/${target}.ipxe || goto local\n:local\nexit\n",
        (long long)nb_number(s,"menu_timeout")*1000,valid?preferred:"local",bind_ip,bind_port,session->token);
    fclose(f);nb_event("menu",session->mac,"",valid?"":"default_fallback_local");return text;
}
static char *boot_script(struct json_object *image,struct boot_session *session)
{
    char *text=NULL,*base=NULL;
    if(asprintf(&base,"http://%s:%d/s/%s/image/%s",bind_ip,bind_port,session->token,nb_string(image,"id"))<0)return NULL;
    if(asprintf(&text,"#!ipxe\nkernel %s/images/pxeboot/vmlinuz initrd=initrd.img ip=dhcp inst.repo=%s inst.stage2=%s || goto failed\n"
        "initrd --name initrd.img %s/images/pxeboot/initrd.img || goto failed\nboot || goto failed\n:failed\necho Installer boot request failed\nexit\n",base,base,base,base)<0)text=NULL;
    free(base);nb_event("boot-script-requested",session->mac,nb_string(image,"id"),"");return text;
}
static int parse_number(const char *s,char **end,unsigned long long *value)
{if(!isdigit((unsigned char)*s))return -1;errno=0;*value=strtoull(s,end,10);return errno?-1:0;}
static void stream_file(int sock,int fd,const char *range,int head)
{
    struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)){text_response(sock,404,"file_unavailable\n",head);return;}
    unsigned long long size=st.st_size,first=0,last=size?size-1:0;int partial=range&&*range;
    if(partial) {
        if(strncmp(range,"bytes=",6)||strchr(range,','))goto invalid;
        const char *p=range+6;char *end=NULL;unsigned long long value;
        if(*p=='-') {if(parse_number(p+1,&end,&value)||*end||!value||!size)goto invalid;first=value>=size?0:size-value;}
        else {
            if(parse_number(p,&end,&first)||*end!='-'||first>=size)goto invalid;
            p=end+1;
            if(*p){if(parse_number(p,&end,&value)||*end||value<first)goto invalid;last=value>=size?size-1:value;}
        }
    }
    char header[640],extra[160]="";unsigned long long length=size?last-first+1:0;
    if(partial)snprintf(extra,sizeof extra,"Content-Range: bytes %llu-%llu/%llu\r\n",first,last,size);
    snprintf(header,sizeof header,"HTTP/1.1 %d %s\r\nContent-Type: application/octet-stream\r\nAccept-Ranges: bytes\r\nContent-Length: %llu\r\n%sCache-Control: private, no-store\r\nConnection: close\r\n\r\n",partial?206:200,partial?"Partial Content":"OK",length,extra);
    if(send_all(sock,header,strlen(header))||head)return;
    char buffer[65536];off_t offset=first;
    while(length) {
        ssize_t n=pread(fd,buffer,length<sizeof buffer?length:sizeof buffer,offset);
        if(n<0&&errno==EINTR)continue;if(n<=0||send_all(sock,buffer,n))break;offset+=n;length-=n;
    }return;
invalid:
    snprintf(header,sizeof header,"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */%llu\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",size);send_all(sock,header,strlen(header));
}
/* Recheck the selected LAN for every new resource request. Network edits can
 * invalidate an address/pool while a previously issued boot session is alive. */
static int scope_current(struct json_object *cfg)
{
    sqlite3 *db=nb_open(0);struct json_object *rows=nb_interfaces(db);
    struct json_object *s=nb_value(cfg,"settings"),*ids=nb_value(s,"interface_ids");
    struct json_object *lan=json_object_array_length(ids)==1?
        nb_find(rows,json_object_get_string(json_object_array_get_idx(ids,0))):NULL;
    int ok=lan&&nb_bool(lan,"available")&&!strcmp(nb_string(lan,"ipv4"),bind_ip)&&nb_number(s,"http_port")==bind_port;
    if(rows)json_object_put(rows);if(db)sqlite3_close(db);return ok;
}
static void *serve(void *opaque)
{
    struct connection *c=opaque;int sock=c->fd;char request[12289],method[12],target[4096],range[128]="";size_t used=0;char *body=NULL;int head=0;
    struct json_object *cfg=NULL;
    for(;;) {
        if(used==sizeof request-1)goto bad;
        ssize_t n=recv(sock,request+used,sizeof request-1-used,0);if(n<=0)goto done;used+=n;request[used]=0;
        body=strstr(request,"\r\n\r\n");if(body)break;
    }
    if(sscanf(request,"%11s %4095s",method,target)!=2)goto bad;head=!strcmp(method,"HEAD");
    if(strcmp(method,"GET")&&strcmp(method,"POST")&&!head){text_response(sock,405,"method_not_allowed\n",head);goto done;}
    char *headers=strstr(request,"\r\n");if(!headers)goto bad;*body=0;body+=4;size_t content_length=0;char *save=NULL;
    for(char *h=strtok_r(headers+2,"\r\n",&save);h;h=strtok_r(NULL,"\r\n",&save)) {
        if(!strncasecmp(h,"Content-Length:",15)){char *end;unsigned long long value;const char *p=h+15;while(*p==' ')p++;if(parse_number(p,&end,&value)||*end||value>2048)goto bad;content_length=value;}
        if(!strncasecmp(h,"Range:",6)){const char *p=h+6;while(*p==' ')p++;if(strlen(p)>=sizeof range)goto bad;strcpy(range,p);}
        if(!strncasecmp(h,"Transfer-Encoding:",18))goto bad;
    }
    size_t body_start=body-request;if(body_start+content_length>=sizeof request)goto bad;
    while(used<body_start+content_length){ssize_t n=recv(sock,request+used,body_start+content_length-used,0);if(n<=0)goto done;used+=n;}
    body[content_length]=0;
    cfg=nb_config_snapshot();if(!cfg||!nb_bool(nb_value(cfg,"settings"),"enabled")){text_response(sock,503,"netboot_disabled\n",head);goto done;}
    if(!scope_current(cfg)){text_response(sock,503,"interface_unavailable\n",head);goto done;}
    if(!strcmp(target,"/boot.ipxe")&&strcmp(method,"POST")) {
        char script[2048];int password=*nb_string(nb_value(cfg,"settings"),"password_hash")!=0;
        /* A NIC ROM can advertise iPXE without PARAM_CMD (for example QEMU's
         * BIOS ROM). Load our complete firmware before requesting a password. */
        snprintf(script,sizeof script,
            "#!ipxe\ncpuid --ext 29 || goto unsupported\nparams || goto firmware\n%s"
            "param mac ${netX/mac}\nparam arch x86_64\nparam platform ${platform}\nparam password ${dwpassword}\n"
            "chain http://%s:%d/menu.ipxe##params || goto failed\nexit\n"
            ":firmware\niseq ${platform} efi && goto efi || goto bios\n"
            ":bios\nchain http://%s:%d/bin/undionly.kpxe || goto failed\nexit\n"
            ":efi\nchain http://%s:%d/bin/snponly.efi || goto failed\nexit\n"
            ":unsupported\necho This boot profile requires x86_64\nexit\n"
            ":failed\necho Network boot access denied or unavailable\nexit\n",
            password?"echo Network boot password:\nread dwpassword\n":"clear dwpassword\n",
            bind_ip,bind_port,bind_ip,bind_port,bind_ip,bind_port);
        text_response(sock,200,script,head);goto done;
    }
    if(!strncmp(target,"/bin/",5)&&strcmp(method,"POST")) {
        const char *file=target+5,*path;
        if(!strcmp(file,"undionly.kpxe"))path=NB_BOOT_DIR "/undionly.kpxe";
        else if(!strcmp(file,"snponly.efi"))path=NB_BOOT_DIR "/snponly.efi";
        else goto denied;
        int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(fd<0)text_response(sock,404,"boot_file_missing\n",head);else{stream_file(sock,fd,range,head);close(fd);}goto done;
    }
    struct boot_session session={0};char *route=NULL;
    if(!strcmp(target,"/menu.ipxe")&&!strcmp(method,"POST")) {
        if(session_create(body,c->ip,cfg,&session))goto denied;route="menu.ipxe";
    } else {
        if(!strncmp(target,"/s/",3)&&strlen(target)>68&&target[67]=='/') {
            target[67]=0;route=target+68;if(!session_load(target+3,c->ip,cfg,&session))goto denied;
        }else goto denied;
        if(!strcmp(method,"POST"))goto bad;
    }
    if(!strcmp(route,"menu.ipxe")){char *script=menu_script(cfg,&session);text_response(sock,script?200:503,script?script:"unavailable\n",head);free(script);goto done;}
    int boot=!strncmp(route,"boot/",5),file=!strncmp(route,"image/",6);if(!boot&&!file)goto denied;
    char *id=route+(boot?5:6),*relative=NULL;
    if(boot){char *ext=strstr(id,".ipxe");if(!ext||strcmp(ext,".ipxe"))goto denied;*ext=0;}
    else {relative=strchr(id,'/');if(!relative)goto denied;*relative++=0;}
    size_t id_len=strlen(id);if(id_len>=sizeof c->image)goto denied;
    struct json_object *image=nb_find(nb_value(cfg,"images"),id);if(!image_allowed(image,&session))goto denied;
    pthread_mutex_lock(&http_lock);memcpy(c->image,id,id_len+1);pthread_mutex_unlock(&http_lock);
    if(boot){char *script=boot_script(image,&session);text_response(sock,script?200:503,script?script:"unavailable\n",head);free(script);goto done;}
    if(!*relative){text_response(sock,200,"",head);goto done;}
    char path[4096];if(decode(path,sizeof path,relative,0))goto bad;
    int fd=nb_image_open(image,path);if(fd<0)text_response(sock,404,"image_file_unavailable\n",head);else{stream_file(sock,fd,range,head);close(fd);}goto done;
denied:
    text_response(sock,403,"netboot_access_denied\n",head);goto done;
bad:
    text_response(sock,400,"invalid_request\n",head);
done:
    if(cfg)json_object_put(cfg);shutdown(sock,SHUT_RDWR);close(sock);
    pthread_mutex_lock(&http_lock);c->used=0;c->fd=-1;c->image[0]=0;pthread_cond_broadcast(&idle);pthread_mutex_unlock(&http_lock);return NULL;
}
static void *accept_connections(void *unused)
{
    (void)unused;
    for(;;) {
        struct sockaddr_in peer;socklen_t size=sizeof peer;
        pthread_mutex_lock(&http_lock);int fd=listener,stop=stopping;pthread_mutex_unlock(&http_lock);if(stop||fd<0)break;
        int client=accept4(fd,(struct sockaddr *)&peer,&size,SOCK_CLOEXEC);if(client<0){if(errno==EINTR)continue;break;}
        struct in_addr local;inet_pton(AF_INET,bind_ip,&local);uint32_t mask=net_prefix?htonl(0xffffffffU<<(32-net_prefix)):0;
        if((peer.sin_addr.s_addr&mask)!=(local.s_addr&mask)){close(client);continue;}
        struct timeval timeout={.tv_sec=20};setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof timeout);
        pthread_mutex_lock(&http_lock);struct connection *slot=NULL;
        if(!stopping)for(int i=0;i<NB_CONNECTIONS;i++)if(!connections[i].used){slot=&connections[i];break;}
        if(slot){slot->used=1;slot->fd=client;slot->image[0]=0;inet_ntop(AF_INET,&peer.sin_addr,slot->ip,sizeof slot->ip);}
        pthread_mutex_unlock(&http_lock);
        if(!slot){text_response(client,503,"netboot_busy\n",0);close(client);continue;}
        pthread_t thread;if(pthread_create(&thread,NULL,serve,slot)){close(client);pthread_mutex_lock(&http_lock);slot->used=0;pthread_mutex_unlock(&http_lock);}else pthread_detach(thread);
    }return NULL;
}
void nb_http_stop(void)
{
    pthread_mutex_lock(&http_lock);int fd=listener;stopping=1;listener=-1;
    if(fd>=0)shutdown(fd,SHUT_RDWR);
    for(int i=0;i<NB_CONNECTIONS;i++)if(connections[i].used)shutdown(connections[i].fd,SHUT_RDWR);
    pthread_mutex_unlock(&http_lock);
    if(fd>=0){pthread_join(listener_thread,NULL);close(fd);}
    pthread_mutex_lock(&http_lock);
    for(;;){int count=0;for(int i=0;i<NB_CONNECTIONS;i++)count+=connections[i].used;if(!count)break;pthread_cond_wait(&idle,&http_lock);}
    memset(sessions,0,sizeof sessions);pthread_mutex_unlock(&http_lock);
}
int nb_http_start(struct json_object *cfg,struct json_object *interface)
{
    const char *ip=nb_string(interface,"ipv4"),*device=nb_string(interface,"device");int port=nb_number(nb_value(cfg,"settings"),"http_port");
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
    int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
    if(inet_pton(AF_INET,ip,&address.sin_addr)!=1||setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,device,strlen(device)+1)||
       bind(fd,(struct sockaddr *)&address,sizeof address)||listen(fd,16)){close(fd);return -1;}
    pthread_mutex_lock(&http_lock);snprintf(bind_ip,sizeof bind_ip,"%s",ip);bind_port=port;net_prefix=nb_number(interface,"prefix");
    if(net_prefix>32)net_prefix=32;listener=fd;stopping=0;pthread_mutex_unlock(&http_lock);
    if(pthread_create(&listener_thread,NULL,accept_connections,NULL)){close(fd);pthread_mutex_lock(&http_lock);listener=-1;pthread_mutex_unlock(&http_lock);return -1;}return 0;
}
