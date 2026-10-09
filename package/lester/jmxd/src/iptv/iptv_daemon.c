// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "iptv.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <fcntl.h>
#include "iptv_ipc.h"
static volatile sig_atomic_t stopping=0;
static int listener=-1;
static void stop(int sig){(void)sig;stopping=1;if(listener>=0){shutdown(listener,SHUT_RDWR);close(listener);}listener=-1;}
static void serve_client(int fd)
{
    struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    struct json_object *q=iptv_recv(fd),*response=json_object_new_object(),*body=NULL,*data=NULL;struct iptv_error e={0};
    char *bytes=NULL;size_t len=0;const char *type="";
    if(!q||!json_object_is_type(q,json_type_object))iptv_fail(&e,400,"invalid_parameter","");
    else if(!strcmp(iptv_string(q,"method"),"MEDIA_RECORD_INFO"))data=iptv_recording_info(iptv_string(q,"token"),iptv_string(q,"channel"),iptv_string(q,"name"),&e);
    else if(!strcmp(iptv_string(q,"method"),"MEDIA_RECORD_READ")){
        struct json_object *offset=NULL;json_object_object_get_ex(q,"offset",&offset);
        iptv_recording_read(iptv_string(q,"token"),iptv_string(q,"channel"),iptv_string(q,"name"),json_object_get_int64(offset),(size_t)iptv_integer(q,"maximum",0),&bytes,&len,&e);type="video/mp4";
    }
    else if(!strcmp(iptv_string(q,"method"),"MEDIA"))iptv_media_read(iptv_string(q,"token"),iptv_string(q,"channel"),iptv_string(q,"name"),&bytes,&len,&type,&e);
    else{json_object_object_get_ex(q,"body",&body);data=iptv_request(iptv_string(q,"method"),iptv_string(q,"resource"),body,iptv_string(q,"actor"),&e);}
    json_object_object_add(response,"status",json_object_new_int(e.status));json_object_object_add(response,"code",json_object_new_string(e.code));json_object_object_add(response,"field",json_object_new_string(e.field));
    json_object_object_add(response,"data",data);json_object_object_add(response,"length",json_object_new_int64(len));json_object_object_add(response,"type",json_object_new_string(type));
    if(!iptv_send(fd,response)&&bytes&&!e.status)iptv_io(fd,bytes,len,1);
    free(bytes);if(q)json_object_put(q);json_object_put(response);close(fd);

}
static void *worker(void *unused)
{
    (void)unused;
    /* Persistent workers: Linux PDEATHSIG follows the creating thread, so a
     * per-request thread must never own FFmpeg's lifetime. */
    while(!stopping){
        int fd=accept4(listener,NULL,NULL,SOCK_CLOEXEC);
        if(fd<0){if(errno==EINTR)continue;break;}
        serve_client(fd);
    }
    return NULL;
}
int main(void)
{
    umask(0077);int guard=open(IPTV_SOCKET ".lock",O_CREAT|O_RDWR|O_CLOEXEC,0600);
    if(guard<0||flock(guard,LOCK_EX|LOCK_NB)){fprintf(stderr,"iptvd: socket lock unavailable\n");return 1;}
    struct iptv_error e={0};sqlite3 *db=iptv_db(&e);if(!db){close(guard);return 1;}
    /* In-memory stream state does not survive a restart. Old tickets cannot
     * silently attach to a different stream generation. */
    if(sqlite3_exec(db,"DELETE FROM iptv_preview;DELETE FROM iptv_view_lease;DELETE FROM iptv_recording_lease;DELETE FROM iptv_deferred_lease",NULL,NULL,NULL)!=SQLITE_OK){sqlite3_close(db);close(guard);return 1;}
    sqlite3_close(db);
    iptv_tools_inspect();
    if(iptv_epg_start(&e)||iptv_jobs_start(&e)||iptv_recordings_start(&e)){close(guard);return 1;}
    struct sigaction sa={0};sa.sa_handler=stop;sigemptyset(&sa.sa_mask);sigaction(SIGTERM,&sa,NULL);sigaction(SIGINT,&sa,NULL);signal(SIGPIPE,SIG_IGN);
    listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path,sizeof(address.sun_path),"%s",IPTV_SOCKET);
    unlink(IPTV_SOCKET);
    if(listener<0||bind(listener,(struct sockaddr*)&address,sizeof(address))||listen(listener,8)){fprintf(stderr,"iptvd: socket unavailable\n");close(guard);return 1;}
    pthread_t workers[4];int started=0;
    for(int i=0;i<4;i++){
        if(pthread_create(&workers[i],NULL,worker,NULL)){stop(0);break;}
        started++;
    }
    while(!stopping)pause();
    for(int i=0;i<started;i++)pthread_join(workers[i],NULL);
    iptv_recordings_shutdown();iptv_jobs_shutdown();iptv_epg_shutdown();iptv_shutdown();unlink(IPTV_SOCKET);close(guard);return 0;
}
