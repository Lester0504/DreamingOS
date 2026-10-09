// SPDX-License-Identifier: GPL-2.0-or-later
/* Native connection engines. No commands or output are written to logs. */
#include "tm.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <poll.h>
#include <pty.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#ifndef TM_TESTING
#include <uci.h>
#endif
#include <unistd.h>

static int tcp_connect(const char *host,int port) {
    struct addrinfo hints={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM},*result=NULL;char service[8];snprintf(service,sizeof(service),"%d",port);
    if(getaddrinfo(host,service,&hints,&result))return -1;
    int fd=-1;
    for(struct addrinfo *p=result;p;p=p->ai_next){fd=socket(p->ai_family,SOCK_STREAM|SOCK_CLOEXEC,p->ai_protocol);if(fd<0)continue;
        fcntl(fd,F_SETFL,O_NONBLOCK);int rc=connect(fd,p->ai_addr,p->ai_addrlen);
        if(rc&&errno==EINPROGRESS){struct pollfd pollfd={fd,POLLOUT,0};rc=poll(&pollfd,1,5000);int error=0;socklen_t len=sizeof(error);if(rc>0&&getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&len)==0&&!error)rc=0;else rc=-1;}
        if(!rc){fcntl(fd,F_SETFL,0);struct timeval tv={5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));break;}close(fd);fd=-1;
    }freeaddrinfo(result);return fd;
}

static void keyboard_auth(const char *name,int name_len,const char *instruction,int instruction_len,int count,const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,void **abstract) {
    (void)name;(void)name_len;(void)instruction;(void)instruction_len;
    struct tm_session *s=*abstract;
    /* Password-only keyboard interaction: do not fabricate OTP responses. */
    if(count==1&&!prompts[0].echo){const char *password=tm_str(s->auth,"password","");responses[0].text=strdup(password);responses[0].length=strlen(password);}
}

int tm_connect_ssh(struct tm_session *s) {
    const char *address=tm_str(s->host,"address","");int port=tm_int(s->host,"port",22);
    s->stream=tcp_connect(address,port);if(s->stream<0){tm_state(s,"failed","connection_failed");return -1;}
    s->ssh=libssh2_session_init_ex(NULL,NULL,NULL,s);if(!s->ssh)return -1;
    libssh2_session_set_timeout(s->ssh,5000);libssh2_session_set_blocking(s->ssh,1);
    if(libssh2_session_handshake(s->ssh,s->stream)){tm_state(s,"failed","ssh_handshake_failed");return -1;}
    size_t keylen=0;int keytype=0;const char *key=libssh2_session_hostkey(s->ssh,&keylen,&keytype);unsigned char digest[SHA256_DIGEST_LENGTH];
    if(!key||!SHA256((const unsigned char *)key,keylen,digest)){tm_state(s,"failed","host_key_unavailable");return -1;}
    char *b64=tm_base64(digest,sizeof(digest));if(!b64)return -1;char *padding=strchr(b64,'=');if(padding)*padding=0;snprintf(s->fingerprint,sizeof(s->fingerprint),"SHA256:%s",b64);free(b64);
    if(tm_known_key(s->owner,address,port,s->old_fingerprint)) {
        if(strcmp(s->fingerprint,s->old_fingerprint)){tm_state(s,"failed","host_key_changed");return -1;}
        s->trusted=1;
    } else {
        tm_state(s,"host_key_confirmation_required","");
        int64_t deadline=tm_now()+120;
        while(!s->trusted&&!s->stop&&tm_now()<deadline){pthread_mutex_unlock(&s->lock);usleep(50000);pthread_mutex_lock(&s->lock);}
        if(!s->trusted||s->stop){tm_state(s,"failed","host_key_not_confirmed");return -1;}
    }
    tm_state(s,"authenticating","");const char *user=tm_str(s->host,"username","");const char *auth_type=tm_str(s->auth,"type","password");int rc=-1;
    if(!strcmp(auth_type,"key")) {const char *private_key=tm_str(s->auth,"private_key","");rc=libssh2_userauth_publickey_frommemory(s->ssh,user,strlen(user),NULL,0,private_key,strlen(private_key),tm_str(s->auth,"passphrase",""));}
    else if(!strcmp(auth_type,"keyboard-interactive"))rc=libssh2_userauth_keyboard_interactive_ex(s->ssh,user,strlen(user),keyboard_auth);
    else {const char *password=tm_str(s->auth,"password","");rc=libssh2_userauth_password_ex(s->ssh,user,strlen(user),password,strlen(password),NULL);}
    if(rc||!libssh2_userauth_authenticated(s->ssh)){tm_state(s,"failed","ssh_auth_failed");return -1;}
    s->channel=libssh2_channel_open_session(s->ssh);
    if(!s->channel||libssh2_channel_request_pty_ex(s->channel,"xterm-256color",14,NULL,0,s->cols,s->rows,0,0)||libssh2_channel_shell(s->channel)){tm_state(s,"failed","ssh_pty_failed");return -1;}
    s->sftp=libssh2_sftp_init(s->ssh);
    if(s->sftp){char home[4096];int n=libssh2_sftp_realpath(s->sftp,".",home,sizeof(home)-1);if(n>0){home[n]=0;snprintf(s->cwd,sizeof(s->cwd),"%s",home);snprintf(s->cwd_source,sizeof(s->cwd_source),"sftp_home");}}
    libssh2_keepalive_config(s->ssh,1,30);libssh2_session_set_blocking(s->ssh,0);
    return 0;
}

static int open_serial(struct tm_session *s) {
    const char *device=tm_str(s->host,"device_id","");char real[4096];struct stat st;
    if(!realpath(device,real)||strncmp(real,"/dev/",5)||stat(real,&st)||!S_ISCHR(st.st_mode)){tm_state(s,"failed","serial_not_found");return -1;}
    J *ports=tm_serial_ports();int allowed=0;J *items=tm_get(ports,"items");for(size_t i=0;i<json_object_array_length(items);i++){J *p=json_object_array_get_idx(items,i);if(!strcmp(device,tm_str(p,"device_id",""))&&!strcmp(real,tm_str(p,"path","")))allowed=1;}json_object_put(ports);
    if(!allowed||strncmp(device,"/dev/serial/by-id/",18)){tm_state(s,"failed","serial_identity_changed");return -1;}
    int fd=open(device,O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC);if(fd<0){tm_state(s,"failed",errno==EBUSY?"serial_busy":"serial_open_failed");return -1;}
    if(flock(fd,LOCK_EX|LOCK_NB)||ioctl(fd,TIOCEXCL)){close(fd);tm_state(s,"failed","serial_busy");return -1;}
    struct termios t;if(tcgetattr(fd,&t)){close(fd);return -1;}cfmakeraw(&t);t.c_cflag|=CLOCAL|CREAD;t.c_cflag&=~CSIZE;
    int bits=tm_int(s->host,"data_bits",8);t.c_cflag|=bits==5?CS5:bits==6?CS6:bits==7?CS7:CS8;
    const char *parity=tm_str(s->host,"parity","none");t.c_cflag&=~(PARENB|PARODD|CSTOPB|CRTSCTS);
    if(strcmp(parity,"none")){t.c_cflag|=PARENB;if(!strcmp(parity,"odd"))t.c_cflag|=PARODD;}
    if(tm_int(s->host,"stop_bits",1)==2)t.c_cflag|=CSTOPB;
    const char *flow=tm_str(s->host,"flow_control","none");if(!strcmp(flow,"rtscts"))t.c_cflag|=CRTSCTS;else if(!strcmp(flow,"xonxoff"))t.c_iflag|=IXON|IXOFF;
    int baud=tm_int(s->host,"baud_rate",115200);speed_t speed=baud==9600?B9600:baud==19200?B19200:baud==38400?B38400:baud==57600?B57600:B115200;
    cfsetispeed(&t,speed);cfsetospeed(&t,speed);t.c_cc[VMIN]=0;t.c_cc[VTIME]=0;
    if(tcsetattr(fd,TCSANOW,&t)){close(fd);tm_state(s,"failed","serial_parameters_rejected");return -1;}
    s->stream=fd;s->serial=1;return 0;
}

static int open_local(struct tm_session *s) {
    char command[4096]="/bin/login",term[128]="xterm-256color";uid_t uid=geteuid();gid_t gid=getegid();int enabled=0;
#ifdef TM_TESTING
    snprintf(command,sizeof(command),"/bin/sh");enabled=1;
#else
    struct uci_context *ctx=uci_alloc_context();struct uci_package *pkg=NULL;
    if(ctx&&uci_load(ctx,"ttyd",&pkg)==UCI_OK){struct uci_element *e;uci_foreach_element(&pkg->sections,e){struct uci_section *section=uci_to_section(e);if(strcmp(section->type,"ttyd"))continue;
        const char *wanted=tm_str(s->host,"instance_id","");if(*wanted&&strcmp(wanted,e->name))continue;
        const char *v=uci_lookup_option_string(ctx,section,"enable");if(!v||strcmp(v,"1"))continue;enabled=1;
        v=uci_lookup_option_string(ctx,section,"command");if(v&&*v)snprintf(command,sizeof(command),"%s",v);
        v=uci_lookup_option_string(ctx,section,"terminal_type");if(v&&*v)snprintf(term,sizeof(term),"%s",v);
        v=uci_lookup_option_string(ctx,section,"uid");if(v&&*v)uid=(uid_t)strtoul(v,NULL,10);
        v=uci_lookup_option_string(ctx,section,"gid");if(v&&*v)gid=(gid_t)strtoul(v,NULL,10);
        v=uci_lookup_option_string(ctx,section,"readonly");s->readonly=v&&!strcmp(v,"1");
        /* once/max_clients are ttyd service-wide policies, not a separate PTY budget. */
        v=uci_lookup_option_string(ctx,section,"once");if(v&&!strcmp(v,"1"))enabled=0;
        v=uci_lookup_option_string(ctx,section,"max_clients");if(v&&atoi(v)>0)enabled=0;
        break;}}if(ctx)uci_free_context(ctx);
#endif
    if(!enabled){tm_state(s,"failed","local_ttyd_policy_requires_proxy");return -1;}
    struct winsize size={.ws_row=s->rows,.ws_col=s->cols};int master=-1;pid_t pid=forkpty(&master,NULL,NULL,&size);
    if(pid<0){tm_state(s,"failed","pty_unavailable");return -1;}
    if(!pid){for(int fd=3;fd<1024;fd++)close(fd);setenv("TERM",term,1);struct passwd *pw=getpwuid(uid);if(pw){setenv("HOME",pw->pw_dir,1);setenv("USER",pw->pw_name,1);if(chdir(pw->pw_dir)!=0)_exit(126);}if(geteuid()==0&&(setgroups(0,NULL)||setgid(gid)||setuid(uid)))_exit(126);execl("/bin/sh","sh","-c",command,(char *)NULL);_exit(127);}
    s->stream=master;s->child=pid;fcntl(master,F_SETFL,O_NONBLOCK);fcntl(master,F_SETFD,FD_CLOEXEC);return 0;
}

J *tm_serial_ports(void) {
    J *r=json_object_new_object(),*items=json_object_new_array();const char *patterns[]={"/dev/serial/by-id/*","/dev/ttyUSB*","/dev/ttyACM*",NULL};
    for(int p=0;patterns[p];p++){glob_t g={0};if(!glob(patterns[p],0,NULL,&g))for(size_t i=0;i<g.gl_pathc;i++){char real[4096];struct stat st;if(!realpath(g.gl_pathv[i],real)||stat(real,&st)||!S_ISCHR(st.st_mode))continue;
        int dup=0;for(size_t k=0;k<json_object_array_length(items);k++)if(!strcmp(real,tm_str(json_object_array_get_idx(items,k),"path","")))dup=1;if(dup)continue;
        J *j=json_object_new_object();tm_string(j,"device_id",g.gl_pathv[i]);tm_string(j,"path",real);tm_boolean(j,"stable_id",p==0);tm_string(j,"reason",p==0?"":"physical_port_identity_unavailable");tm_boolean(j,"available",p==0&&access(real,R_OK|W_OK)==0);json_object_array_add(items,j);
    }globfree(&g);}json_object_object_add(r,"items",items);return r;
}

#include "lxc.inc"

int tm_engine_open(struct tm_session *s) {
    const char *type=tm_str(s->host,"type","");
    if(!strcmp(type,"docker"))return tm_docker_open(s);
    if(!strcmp(type,"lxc"))return tm_lxc_open(s);
    if(!strcmp(type,"ssh"))return tm_connect_ssh(s);
    if(!strcmp(type,"serial"))return open_serial(s);
    if(!strcmp(type,"local"))return open_local(s);
    s->stream=tcp_connect(tm_str(s->host,"address",""),tm_int(s->host,"port",23));if(s->stream<0){tm_state(s,"failed","connection_failed");return -1;}fcntl(s->stream,F_SETFL,O_NONBLOCK);return 0;
}

void tm_engine_resize(struct tm_session *s,int cols,int rows) {
    if(cols<2||cols>500||rows<1||rows>300||s->serial)return;s->cols=cols;s->rows=rows;
    if(!strcmp(tm_str(s->host,"type",""),"docker"))tm_docker_resize(s,cols,rows);
    else if(s->channel)libssh2_channel_request_pty_size(s->channel,cols,rows);
    else if(s->child){struct winsize w={.ws_row=rows,.ws_col=cols};ioctl(s->stream,TIOCSWINSZ,&w);}
    else if(!strcmp(tm_str(s->host,"type",""),"telnet")){unsigned char size[]={255,250,31,(unsigned char)(cols>>8),(unsigned char)cols,(unsigned char)(rows>>8),(unsigned char)rows,255,240};unsigned char out[20];size_t n=0;for(size_t i=0;i<sizeof(size);i++){out[n++]=size[i];if(i>=3&&i<=6&&size[i]==255)out[n++]=255;}send(s->stream,out,n,MSG_NOSIGNAL);}
}

int tm_engine_input(struct tm_session *s,const char *data,size_t len) {
    if(s->readonly||strcmp(s->state,"ready"))return -1;
    size_t offset=0;int64_t deadline=tm_now()+5;
    while(offset<len&&!s->stop&&tm_now()<=deadline){ssize_t n;
        if(s->channel)n=libssh2_channel_write(s->channel,data+offset,len-offset);
        else n=write(s->stream,data+offset,len-offset);
        if(n>0){offset+=n;continue;}if((s->channel&&n==LIBSSH2_ERROR_EAGAIN)||(!s->channel&&(errno==EAGAIN||errno==EINTR))){struct pollfd p={s->stream,POLLOUT,0};poll(&p,1,25);continue;}return -1;
    }s->activity=tm_now();return offset==len?0:-1;
}

/* Telnet IAC is parsed across TCP reads; negotiation never enters the terminal. */
static size_t telnet_decode(struct tm_session *s,unsigned char *data,size_t len) {
    size_t n=0;
    for(size_t i=0;i<len;i++){unsigned char c=data[i];
        if(s->telnet_state==0){if(c==255)s->telnet_state=1;else data[n++]=c;}
        else if(s->telnet_state==1){if(c==255){data[n++]=c;s->telnet_state=0;}else if(c==250)s->telnet_state=3;else if(c>=251&&c<=254){s->telnet_cmd=c;s->telnet_state=2;}else s->telnet_state=0;}
        else if(s->telnet_state==2){unsigned char reply[]={255,0,c};int cmd=s->telnet_cmd;reply[1]=(cmd==253)?((c==31||c==3)?251:252):cmd==251?((c==1||c==3)?253:254):0;if(reply[1])send(s->stream,reply,3,MSG_NOSIGNAL);if(cmd==253&&c==31)tm_engine_resize(s,s->cols,s->rows);s->telnet_state=0;}
        else if(s->telnet_state==3){if(c==255)s->telnet_state=4;}else if(s->telnet_state==4)s->telnet_state=c==240?0:3;
    }return n;
}

int tm_engine_read(struct tm_session *s) {
    unsigned char out[16384];ssize_t n=s->channel?libssh2_channel_read(s->channel,(char *)out,sizeof(out)):read(s->stream,out,sizeof(out));
    if(n>0){if(!strcmp(tm_str(s->host,"type",""),"telnet"))n=telnet_decode(s,out,n);if(n&&s->ws>=0&&tm_ws_send(s,2,out,n))return -1;return 0;}
    if(s->channel){if(libssh2_channel_eof(s->channel)){s->exit_code=libssh2_channel_get_exit_status(s->channel);return -1;}return n==LIBSSH2_ERROR_EAGAIN||n==0?0:-1;}
    if(n==0&&!s->serial)return -1;
    return n<0&&(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)?-1:0;
}

void tm_engine_close(struct tm_session *s) {
    if(!strcmp(tm_str(s->host,"type",""),"docker"))tm_docker_close(s);
    if(!strcmp(tm_str(s->host,"type",""),"lxc"))tm_lxc_close(s);
    if(s->channel){libssh2_session_set_blocking(s->ssh,1);libssh2_session_set_timeout(s->ssh,1000);libssh2_channel_free(s->channel);s->channel=NULL;}
    if(s->child>0){kill(-s->child,SIGHUP);for(int i=0;i<10;i++){if(waitpid(s->child,NULL,WNOHANG)==s->child){s->child=0;break;}usleep(10000);}if(s->child>0){kill(-s->child,SIGKILL);waitpid(s->child,NULL,0);s->child=0;}}
    if(s->ssh){if(s->sftp)libssh2_sftp_shutdown(s->sftp);s->sftp=NULL;libssh2_session_free(s->ssh);s->ssh=NULL;}
    if(s->stream>=0){if(s->serial)ioctl(s->stream,TIOCNXCL);close(s->stream);s->stream=-1;}
    if(s->auth){tm_scrub(s->auth);json_object_put(s->auth);s->auth=NULL;}
}
