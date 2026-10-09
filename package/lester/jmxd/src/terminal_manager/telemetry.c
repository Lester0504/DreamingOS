// SPDX-License-Identifier: GPL-2.0-or-later
#include "tm.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Fixed read-only script, separate SSH exec channel. Never includes user paths or terminal input. */
static const char snapshot_script[]=
"printf 'HOST\\t'; uname -n; printf 'KERNEL\\t'; uname -sr; "
"printf 'UPTIME\\t'; cat /proc/uptime; "
"awk '/^MemTotal:|^MemAvailable:|^MemFree:/{print \"MEM\\t\"$1\"\\t\"$2}' /proc/meminfo; "
"awk '/^cpu /{print \"CPU\\t\"$0} /^cpu[0-9]/{n++} END{print \"CORES\\t\"n}' /proc/stat; "
"awk 'NR>2{gsub(\":\",\" \");print \"NET\\t\"$1\"\\t\"$2\"\\t\"$10}' /proc/net/dev; "
"awk '{print \"IO\\t\"$3\"\\t\"$4\"\\t\"$6\"\\t\"$8\"\\t\"$10\"\\t\"$13}' /proc/diskstats; "
"df -Pk 2>/dev/null | awk 'NR>1{print \"DISK\\t\"$1\"\\t\"$2\"\\t\"$3\"\\t\"$4\"\\t\"$6}'; "
"n=0; for p in /proc/[0-9]*; do [ -r \"$p/stat\" ] || continue; "
"IFS= read -r line < \"$p/stat\" || continue; printf 'PROC\\t%s\\n' \"$line\"; n=$((n+1)); [ \"$n\" -lt 512 ] || break; done";

static char *read_snapshot(struct tm_session *s,int *truncated) {
    size_t cap=TM_FRAME_MAX-8192,len=0;char *buffer=calloc(1,cap+1);if(!buffer)return NULL;int fail=0;
    if(s->ssh){libssh2_session_set_blocking(s->ssh,1);libssh2_session_set_timeout(s->ssh,5000);LIBSSH2_CHANNEL *ch=libssh2_channel_open_session(s->ssh);if(!ch||libssh2_channel_exec(ch,snapshot_script)){if(ch)libssh2_channel_free(ch);free(buffer);libssh2_session_set_blocking(s->ssh,0);return NULL;}
        while(len<cap){ssize_t n=libssh2_channel_read(ch,buffer+len,cap-len);if(n>0)len+=n;else {if(n<0)fail=1;break;}}
        if(len==cap)*truncated=1;libssh2_channel_free(ch);libssh2_session_set_blocking(s->ssh,0);
    }else {int fds[2];if(pipe(fds)){free(buffer);return NULL;}pid_t pid=fork();if(!pid){dup2(fds[1],STDOUT_FILENO);close(fds[0]);close(fds[1]);for(int fd=3;fd<1024;fd++)close(fd);execl("/bin/sh","sh","-c",snapshot_script,(char *)NULL);_exit(127);}close(fds[1]);if(pid<0){close(fds[0]);free(buffer);return NULL;}
        int64_t end=tm_now()+5;while(len<cap&&tm_now()<=end){struct pollfd p={fds[0],POLLIN,0};if(poll(&p,1,100)<=0)continue;ssize_t n=read(fds[0],buffer+len,cap-len);if(n<=0)break;len+=n;}if(len==cap)*truncated=1;if(tm_now()>end)fail=1;close(fds[0]);if(fail||*truncated)kill(pid,SIGKILL);waitpid(pid,NULL,0);
    }if(fail){free(buffer);return NULL;}return buffer;
}

static double number(J *j,const char *key,double d) {J *v=tm_get(j,key);return v?json_object_get_double(v):d;}
static void real(J *j,const char *key,double value) {json_object_object_add(j,key,value>=0?json_object_new_double(value):NULL);}

J *tm_telemetry(struct tm_session *s,const char *kind,int *status) {
    if(!s->ssh&&!s->child)return tm_error(status,422,"telemetry_unsupported","Telnet 与串口不注入诊断命令");
    int truncated=0;char *raw=read_snapshot(s,&truncated);if(!raw)return tm_error(status,502,"telemetry_unavailable","无法读取目标的 /proc 采样");
    struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);double now=ts.tv_sec+ts.tv_nsec/1e9,previous=number(s->sample,"monotonic",now),dt=now-previous;
    J *sample=json_object_new_object(),*process_map=json_object_new_object(),*io_map=json_object_new_object(),*net_map=json_object_new_object();
    J *r=json_object_new_object(),*procs=json_object_new_array(),*disks=json_object_new_array(),*io=json_object_new_array(),*net=json_object_new_array();
    tm_number(r,"sampled_at",tm_now());tm_string(r,"source",s->ssh?"ssh_exec_procfs":"local_procfs");tm_boolean(r,"truncated",truncated);real(r,"sample_interval_seconds",dt>0?dt:-1);real(sample,"monotonic",now);
    uint64_t total=0,idle=0;int cores=1;char *save=NULL,*line=strtok_r(raw,"\n",&save);
    while(line){
        if(!strncmp(line,"HOST\t",5))tm_string(r,"hostname",line+5);
        else if(!strncmp(line,"KERNEL\t",7))tm_string(r,"kernel",line+7);
        else if(!strncmp(line,"UPTIME\t",7))real(r,"uptime_seconds",strtod(line+7,NULL));
        else if(!strncmp(line,"MEM\t",4)){char key[64];unsigned long long k;if(sscanf(line+4,"%63s %llu",key,&k)==2){const char *field=!strcmp(key,"MemTotal:")?"memory_total_bytes":!strcmp(key,"MemAvailable:")?"memory_available_bytes":"memory_free_bytes";tm_number(r,field,k*1024);}}
        else if(!strncmp(line,"CPU\t",4)){unsigned long long c[10]={0};int n=sscanf(line+4,"cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",c,c+1,c+2,c+3,c+4,c+5,c+6,c+7,c+8,c+9);for(int i=0;i<n&&i<8;i++)total+=c[i];idle=c[3]+c[4];tm_number(sample,"cpu_total",total);tm_number(sample,"cpu_idle",idle);}
        else if(!strncmp(line,"CORES\t",6)){cores=atoi(line+6);tm_number(r,"logical_cpus",cores);}
        else if(!strncmp(line,"NET\t",4)){char dev[128];unsigned long long rx,tx;if(sscanf(line+4,"%127s %llu %llu",dev,&rx,&tx)==3){J *j=json_object_new_object(),*old=tm_get(tm_get(s->sample,"net"),dev);tm_string(j,"name",dev);tm_number(j,"rx_bytes",rx);tm_number(j,"tx_bytes",tx);real(j,"rx_bytes_per_second",old&&dt>0&&rx>=(uint64_t)tm_int(old,"rx_bytes",0)?(rx-tm_int(old,"rx_bytes",0))/dt:-1);real(j,"tx_bytes_per_second",old&&dt>0&&tx>=(uint64_t)tm_int(old,"tx_bytes",0)?(tx-tm_int(old,"tx_bytes",0))/dt:-1);json_object_object_add(net_map,dev,tm_copy(j));json_object_array_add(net,j);}}
        else if(!strncmp(line,"IO\t",3)){char dev[128];unsigned long long reads,rsec,writes,wsec,busy;if(sscanf(line+3,"%127s %llu %llu %llu %llu %llu",dev,&reads,&rsec,&writes,&wsec,&busy)==6){J *j=json_object_new_object(),*old=tm_get(tm_get(s->sample,"io"),dev);tm_string(j,"name",dev);tm_number(j,"read_sectors",rsec);tm_number(j,"write_sectors",wsec);tm_number(j,"operations",reads+writes);tm_number(j,"busy_ms",busy);real(j,"read_bytes_per_second",old&&dt>0&&rsec>=(uint64_t)tm_int(old,"read_sectors",0)?(rsec-tm_int(old,"read_sectors",0))*512.0/dt:-1);real(j,"write_bytes_per_second",old&&dt>0&&wsec>=(uint64_t)tm_int(old,"write_sectors",0)?(wsec-tm_int(old,"write_sectors",0))*512.0/dt:-1);real(j,"iops",old&&dt>0&&reads+writes>=(uint64_t)tm_int(old,"operations",0)?(reads+writes-tm_int(old,"operations",0))/dt:-1);real(j,"busy_percent",old&&dt>0&&busy>=(uint64_t)tm_int(old,"busy_ms",0)?(busy-tm_int(old,"busy_ms",0))/dt/10:-1);json_object_object_add(io_map,dev,tm_copy(j));json_object_array_add(io,j);}}
        else if(!strncmp(line,"DISK\t",5)){char dev[256],mount[4096];unsigned long long size,used,avail;if(sscanf(line+5,"%255s %llu %llu %llu %4095s",dev,&size,&used,&avail,mount)==5){J *j=json_object_new_object();tm_string(j,"device",dev);tm_string(j,"mountpoint",mount);tm_number(j,"size_bytes",size*1024);tm_number(j,"used_bytes",used*1024);tm_number(j,"available_bytes",avail*1024);json_object_array_add(disks,j);}}
        else if(!strncmp(line,"PROC\t",5)){char *p=line+5,*begin=strchr(p,'('),*end=strrchr(p,')');if(begin&&end&&end>begin){int pid=atoi(p);*end=0;J *j=json_object_new_object();tm_number(j,"pid",pid);tm_string(j,"name",begin+1);char *field_save=NULL,*field=strtok_r(end+2," ",&field_save);int index=3;int64_t ticks=0,start=0,rss=0;while(field){if(index==3)tm_string(j,"state",field);if(index==14||index==15)ticks+=strtoll(field,NULL,10);if(index==22)start=strtoll(field,NULL,10);if(index==24)rss=strtoll(field,NULL,10);field=strtok_r(NULL," ",&field_save);index++;}tm_number(j,"cpu_ticks",ticks);tm_number(j,"start_ticks",start);tm_number(j,"resident_pages",rss);char id[32];snprintf(id,sizeof(id),"%d",pid);J *old=tm_get(tm_get(s->sample,"processes"),id);int64_t delta=(int64_t)total-tm_int(s->sample,"cpu_total",total);real(j,"cpu_percent",old&&start==tm_int(old,"start_ticks",-1)&&delta>0&&ticks>=tm_int(old,"cpu_ticks",0)?(ticks-tm_int(old,"cpu_ticks",0))*100.0*cores/delta:-1);json_object_object_add(process_map,id,tm_copy(j));json_object_array_add(procs,j);}}
        line=strtok_r(NULL,"\n",&save);
    }
    int64_t delta=(int64_t)total-tm_int(s->sample,"cpu_total",total),idle_delta=(int64_t)idle-tm_int(s->sample,"cpu_idle",idle);real(r,"cpu_percent",delta>0&&idle_delta>=0&&idle_delta<=delta?100.0*(delta-idle_delta)/delta:-1);
    const char *missing[]={"hostname","kernel","uptime_seconds","memory_total_bytes","memory_available_bytes","memory_free_bytes",NULL};for(int i=0;missing[i];i++)if(!tm_get(r,missing[i]))json_object_object_add(r,missing[i],NULL);
    json_object_object_add(sample,"processes",process_map);json_object_object_add(sample,"io",io_map);json_object_object_add(sample,"net",net_map);json_object_put(s->sample);s->sample=sample;
    if(!strcmp(kind,"processes")){json_object_object_add(r,"items",procs);tm_number(r,"limit",512);tm_boolean(r,"truncated",truncated||json_object_array_length(procs)>=512);}else json_object_put(procs);
    if(!strcmp(kind,"disks")){json_object_object_add(r,"items",disks);json_object_object_add(r,"io",io);}else {json_object_put(disks);json_object_put(io);}
    json_object_object_add(r,"network",net);free(raw);return r;
}
