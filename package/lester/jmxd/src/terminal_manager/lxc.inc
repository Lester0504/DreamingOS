/* LXC attach engine. Included by engines.c; no host command is accepted by HTTP. */
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <spawn.h>
#include <sys/syscall.h>
#ifndef TM_LXC_BIN_DIR
#define TM_LXC_BIN_DIR "/usr/bin"
#endif
#ifndef TM_LXC_CONFIG_DB
#define TM_LXC_CONFIG_DB "/etc/dreamingwrt/config.db"
#endif
extern char **environ;

static int lxc_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
    return syscall(SYS_pidfd_open,pid,0);
#else
    (void)pid;return -1;
#endif
}
static int lxc_signal(int fd,int sig)
{
#ifdef SYS_pidfd_send_signal
    return syscall(SYS_pidfd_send_signal,fd,sig,NULL,0);
#else
    (void)fd;(void)sig;return -1;
#endif
}

static int lxc_probe(char *const argv[],char *out,size_t size)
{
    int pipes[2],status=0;pid_t pid;
    if(pipe2(pipes,O_CLOEXEC))return -1;
    posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions,pipes[1],STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);
    int rc=posix_spawn(&pid,argv[0],&actions,NULL,argv,environ);
    posix_spawn_file_actions_destroy(&actions);close(pipes[1]);out[0]=0;
    if(rc){close(pipes[0]);return -1;}
    fcntl(pipes[0],F_SETFL,O_NONBLOCK);size_t used=0;int finished=0;int64_t deadline=tm_now()+3;
    while(tm_now()<=deadline){
        struct pollfd p={pipes[0],POLLIN,0};poll(&p,1,20);
        ssize_t n=read(pipes[0],out+used,size-1-used);
        if(n>0){used+=n;if(used==size-1)break;}
        if(waitpid(pid,&status,WNOHANG)==pid){finished=1;while(used<size-1&&(n=read(pipes[0],out+used,size-1-used))>0)used+=n;break;}
    }
    if(!finished){kill(pid,SIGKILL);waitpid(pid,&status,0);}
    close(pipes[0]);out[used]=0;
    while(used&&isspace((unsigned char)out[used-1]))out[--used]=0;
    return finished&&WIFEXITED(status)&&!WEXITSTATUS(status)&&used<size-1?0:-1;
}

const char *tm_lxc_validate(J *host)
{
    const char *name=tm_str(host,"container_id","");
    if(!isalnum((unsigned char)*name)||strlen(name)>63)return "container_id";
    for(const char *p=name;*p;p++)if(!isalnum((unsigned char)*p)&&*p!='_'&&*p!='-'&&*p!='.')return "container_id";
    const char *identity=tm_str(host,"identity","");
    if(!*identity||strlen(identity)>79||!strchr(identity,':'))return "identity";
    for(const char *p=identity;*p;p++)if(!isdigit((unsigned char)*p)&&*p!=':')return "identity";
    const char *shell=tm_str(host,"shell","/bin/sh");
    if(strcmp(shell,"/bin/sh")&&strcmp(shell,"/bin/ash")&&strcmp(shell,"/bin/bash"))return "shell";
    return NULL;
}

J *tm_lxc_capabilities(int manage)
{
    int probe=lxc_pidfd(getpid()),cleanup=probe>=0&&!lxc_signal(probe,0);
    if(probe>=0)close(probe);
    int commands=!access(TM_LXC_BIN_DIR "/lxc-attach",X_OK)&&!access(TM_LXC_BIN_DIR "/lxc-info",X_OK)&&!access(TM_LXC_BIN_DIR "/lxc-config",X_OK);
    J *r=json_object_new_object(),*shells=json_object_new_array();
    tm_boolean(r,"engine_available",commands);tm_boolean(r,"terminal",commands&&cleanup);tm_boolean(r,"connect",commands&&cleanup&&manage);
    tm_string(r,"reason",!commands?"lxc_command_missing":!cleanup?"lxc_attach_cleanup_unavailable":!manage?"owner_or_admin_required":"");
    const char *names[]={"/bin/sh","/bin/ash","/bin/bash"};for(int i=0;i<3;i++)json_object_array_add(shells,json_object_new_string(names[i]));
    json_object_object_add(r,"shells",shells);tm_number(r,"authorization_lease_seconds",TM_LEASE_SECONDS);tm_number(r,"max_sessions",TM_MAX_SESSIONS);
    return r;
}

static int lxc_identity_matches(const char *root,J *host)
{
    char directory[4096],identity[80],config[4096];struct stat st;
    if(snprintf(directory,sizeof(directory),"%s/%s",root,tm_str(host,"container_id",""))>=(int)sizeof(directory)||lstat(directory,&st)||!S_ISDIR(st.st_mode))return 0;
    snprintf(identity,sizeof(identity),"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);
    if(strcmp(identity,tm_str(host,"identity","")))return 0;
    if(snprintf(config,sizeof(config),"%s/config",directory)>=(int)sizeof(config)||lstat(config,&st)||!S_ISREG(st.st_mode))return 0;
    return 1;
}

static int lxc_resolve_root(char *root,size_t size,J *host)
{
    char fallback[4096]="",real[4096],mismatch[4096]="";
    char *args[]={TM_LXC_BIN_DIR "/lxc-config","lxc.lxcpath",NULL};
    if(!lxc_probe(args,fallback,sizeof(fallback))&&fallback[0]=='/'&&!strchr(fallback,'\n')&&
       realpath(fallback,real)&&!strcmp(real,fallback)&&lxc_identity_matches(real,host)){
        return snprintf(root,size,"%s",real)>=(int)size?-1:0;
    }
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;int found=0;
    if(sqlite3_open_v2(TM_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK){
        const char *queries[]={"SELECT path FROM lxc_roots LIMIT 32","SELECT DISTINCT substr(path,1,length(path)-length(name)-8) FROM lxc_config_document LIMIT 32"};
        for(int i=0;i<2&&!found;i++){
            if(sqlite3_prepare_v2(db,queries[i],-1,&st,NULL)==SQLITE_OK){
                while(sqlite3_step(st)==SQLITE_ROW){
                    const char *candidate=(const char *)sqlite3_column_text(st,0);
                    if(!candidate||!realpath(candidate,real)||strcmp(candidate,real))continue;
                    if(lxc_identity_matches(real,host)&&snprintf(root,size,"%s",real)<(int)size){found=1;break;}
                    /* Keep a known object's root for the identity-change diagnostic;
                     * an exact identity in any later root still takes precedence. */
                    char directory[4096];struct stat object;
                    if(!mismatch[0]&&snprintf(directory,sizeof(directory),"%s/%s",real,tm_str(host,"container_id",""))<(int)sizeof(directory)&&
                       !lstat(directory,&object)&&S_ISDIR(object.st_mode))snprintf(mismatch,sizeof(mismatch),"%s",real);
                }
            }
            if(st)sqlite3_finalize(st);
            st=NULL;
        }
    }
    if(db)sqlite3_close(db);
    if(found)return 0;
    if(mismatch[0])return snprintf(root,size,"%s",mismatch)>=(int)size?-1:0;
    /* Preserve the original not-found/identity diagnostics for the runtime's
     * default root when no recorded root matches this exact object. */
    if(fallback[0]=='/'&&!strchr(fallback,'\n')&&realpath(fallback,real)&&!strcmp(real,fallback))
        return snprintf(root,size,"%s",real)>=(int)size?-1:0;
    return -1;
}

static int lxc_child_parent(pid_t child,pid_t parent)
{
    char path[96],line[256];snprintf(path,sizeof(path),"/proc/%d/status",child);
    FILE *f=fopen(path,"r");if(!f)return 0;int matches=0;
    while(fgets(line,sizeof(line),f)){
        long value;char extra;
        if(!strncmp(line,"PPid:",5)&&sscanf(line+5,"%ld %c",&value,&extra)==1){matches=value==parent;break;}
    }
    fclose(f);return matches;
}

/* The attach process owns the shell as a direct child. Some target kernels
 * omit /proc/.../children, so use PPid, then pin and verify the PID namespace. */
static int lxc_pin_shell(struct tm_session *s,const struct stat *expected)
{
    DIR *proc=opendir("/proc");if(!proc)return -1;struct dirent *entry;int result=-1;
    while((entry=readdir(proc))){
        char *end;long value=strtol(entry->d_name,&end,10);if(*end||value<=1||value>INT_MAX)continue;
        pid_t child=(pid_t)value;if(!lxc_child_parent(child,s->child))continue;
        int fd=lxc_pidfd(child);if(fd<0)continue;
        char path[128];struct stat actual;snprintf(path,sizeof(path),"/proc/%d/ns/pid",child);
        if(!stat(path,&actual)&&actual.st_dev==expected->st_dev&&actual.st_ino==expected->st_ino&&
           lxc_child_parent(child,s->child)&&!lxc_signal(fd,0)){
            s->lxc_pidfd=fd;tm_number(s->host,"attached_pid",child);result=0;break;
        }
        close(fd);
    }
    closedir(proc);return result;
}

int tm_lxc_open(struct tm_session *s)
{
    const char *bad=tm_lxc_validate(s->host);if(bad){tm_state(s,"failed","lxc_target_invalid");return -1;}
    J *caps=tm_lxc_capabilities(1);int available=tm_bool(caps,"connect",0);
    if(!available)tm_state(s,"failed",tm_str(caps,"reason","lxc_attach_unavailable"));json_object_put(caps);if(!available)return -1;
    char root[4096],value[128],ns_path[128];
    if(lxc_resolve_root(root,sizeof(root),s->host)){
        tm_state(s,"failed","lxc_path_invalid");return -1;
    }
    char directory[4096];struct stat object;
    if(snprintf(directory,sizeof(directory),"%s/%s",root,tm_str(s->host,"container_id",""))>=(int)sizeof(directory)){tm_state(s,"failed","lxc_path_invalid");return -1;}
    if(lstat(directory,&object)){tm_state(s,"failed",errno==ENOENT?"lxc_container_not_found":"lxc_container_unreadable");return -1;}
    if(!lxc_identity_matches(root,s->host)){tm_state(s,"failed","container_identity_changed");return -1;}
    char *name=(char *)tm_str(s->host,"container_id","");
    char *state_args[]={TM_LXC_BIN_DIR "/lxc-info","-P",root,"-n",name,"-sH",NULL};
    if(lxc_probe(state_args,value,sizeof(value))||strcmp(value,"RUNNING")){tm_state(s,"failed","lxc_container_not_running");return -1;}
    char *pid_args[]={TM_LXC_BIN_DIR "/lxc-info","-P",root,"-n",name,"-pH",NULL};
    if(lxc_probe(pid_args,value,sizeof(value))){tm_state(s,"failed","lxc_attach_failed");return -1;}
    char *end;long init=strtol(value,&end,10);struct stat expected,own;
    snprintf(ns_path,sizeof(ns_path),"/proc/%ld/ns/pid",init);
    if(init<=1||*end||stat(ns_path,&expected)||stat("/proc/self/ns/pid",&own)||expected.st_ino==own.st_ino){tm_state(s,"failed","lxc_namespace_unavailable");return -1;}
    const char *shell=tm_str(s->host,"shell","/bin/sh");
    char *args[]={TM_LXC_BIN_DIR "/lxc-attach","-P",root,"-n",name,"--clear-env","--keep-var","TERM","--",(char *)shell,"-c","printf '\036DWRT-LXC-READY\037'; exec \"$0\" -i",(char *)shell,NULL};
    struct winsize size={.ws_row=s->rows,.ws_col=s->cols};int master=-1;pid_t pid=forkpty(&master,NULL,NULL,&size);
    if(pid<0){tm_state(s,"failed","pty_unavailable");return -1;}
    if(!pid){for(int fd=3;fd<1024;fd++)close(fd);execve(args[0],args,environ);_exit(127);}
    s->child=pid;s->stream=master;fcntl(master,F_SETFD,FD_CLOEXEC);fcntl(master,F_SETFL,O_NONBLOCK);
    char output[4096];size_t used=0;int64_t deadline=tm_now()+5;const char marker[]="\036DWRT-LXC-READY\037";
    while(!s->stop&&tm_now()<=deadline&&used<sizeof(output)-1){
        struct pollfd p={master,POLLIN,0};poll(&p,1,25);ssize_t n=read(master,output+used,sizeof(output)-1-used);
        if(n>0){used+=n;output[used]=0;char *ready=strstr(output,marker);
            if(ready){
                if(!lxc_identity_matches(root,s->host)||lxc_pin_shell(s,&expected)){tm_state(s,"failed","lxc_attach_identity_unconfirmed");return -1;}
                ready+=strlen(marker);size_t remaining=used-(size_t)(ready-output);if(remaining)tm_ws_send(s,2,ready,remaining);
                tm_string(s->host,"lxcpath",root);return 0;
            }
        }else if(n==0||(n<0&&errno!=EAGAIN&&errno!=EINTR))break;
    }
    siginfo_t exited={0};
    /* Keep the child waitable for tm_engine_close(), including failed exec. */
    for(int i=0;i<10;i++){
        if(waitid(P_PID,pid,&exited,WEXITED|WNOHANG|WNOWAIT)||exited.si_pid)break;
        usleep(10000);
    }
    tm_state(s,"failed",exited.si_code==CLD_EXITED&&exited.si_status==127?"lxc_shell_unavailable":
        exited.si_code==CLD_EXITED&&exited.si_status==126?"lxc_shell_not_executable":"lxc_attach_failed");return -1;
}

void tm_lxc_close(struct tm_session *s)
{
    if(s->lxc_pidfd<0)return;
    lxc_signal(s->lxc_pidfd,SIGHUP);struct pollfd p={s->lxc_pidfd,POLLIN,0};
    if(poll(&p,1,250)<=0){lxc_signal(s->lxc_pidfd,SIGKILL);if(poll(&p,1,1000)<=0)tm_state(s,"failed","lxc_attach_cleanup_failed");}
    close(s->lxc_pidfd);s->lxc_pidfd=-1;
}
