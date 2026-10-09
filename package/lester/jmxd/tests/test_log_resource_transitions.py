#!/usr/bin/env python3
"""Real inventory scan and transition code with isolated sysfs/state/transport."""
from pathlib import Path
import importlib.util, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('helpers',ROOT/'src/logd/test_log_event_semantics.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=(ROOT/'src/logd/logd_collectors.c').read_text()
head=r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <json-c/json.h>
static struct json_object *states,*events;
static int fail_scan,fail_publish,fail_state;
static const char *boot="boot-fixture-1";
static int64_t logd_now_s(void){return 123456;}
static const char *logd_json_str(struct json_object *o,const char *k,const char *f){struct json_object*v=NULL;return json_object_object_get_ex(o,k,&v)&&json_object_is_type(v,json_type_string)?json_object_get_string(v):f;}
static int logd_collector_state_get(const char *c,const char *key,char *out,size_t n,const char *fallback){(void)c;struct json_object*v=NULL;int found=json_object_object_get_ex(states,key,&v);snprintf(out,n,"%s",found?json_object_get_string(v):fallback);return fail_state?-1:found?0:1;}
static int logd_collector_state_set(const char *c,const char *key,const char *v){(void)c;json_object_object_add(states,key,json_object_new_string(v));return 0;}
static int logd_collector_state_delete(const char*c,const char*key){(void)c;json_object_object_del(states,key);return 0;}
static int logd_file_read_line(const char *path,char *out,size_t n){
 if(!strcmp(path,"/proc/sys/kernel/random/boot_id")){snprintf(out,n,"%s",boot);return 0;}
 if(fail_scan)return -1;
 FILE*f=fopen(path,"r");if(!f)return -1;char*r=fgets(out,(int)n,f);fclose(f);if(!r)return -1;out[strcspn(out,"\r\n")]=0;return 0;
}
static void logd_hash_hex(const char *s,char*out,size_t n){snprintf(out,n,"%zu",strlen(s));}
static int logd_cooldown_allow(const char*c,const char*k,int s){(void)c;(void)k;(void)s;return 1;}
static void logd_cooldown_mark(const char*c,const char*k,int s){(void)c;(void)k;(void)s;}
static int logd_publish_event(const char*sev,const char*cat,const char*id,const char*src,const char*target,const char*title,const char*dedupe,struct json_object*d){
 (void)sev;(void)cat;(void)src;(void)target;(void)title;(void)dedupe;
 if(fail_publish)return -1;
 struct json_object*o=json_object_new_object();json_object_object_add(o,"event",json_object_new_string(id));
 json_object_object_add(o,"detail",json_tokener_parse(json_object_to_json_string_ext(d,JSON_C_TO_STRING_PLAIN)));json_object_array_add(events,o);return 0;
}
'''
parts=[m.c_function(source,x) for x in ['static void logd_collect_resource_one(','static struct json_object *logd_block_inventory(','static void logd_collect_block_inventory(','static void logd_collect_boot(','static void logd_collect_restore_state(']]
tail=r'''
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %d\n",__LINE__);return 1;}}while(0)
#define COUNT json_object_array_length(events)
static void putfile(const char*p,const char*s){FILE*f=fopen(p,"w");if(!f)exit(2);fputs(s,f);fclose(f);}
int main(int argc,char**argv){CHECK(argc==2);char disk[1024],dev[1024],part[1024];
 states=json_object_new_object();events=json_object_new_array();
 snprintf(disk,sizeof(disk),"%s/sda",argv[1]);mkdir(disk,0700);
 snprintf(dev,sizeof(dev),"%s/sda/dev",argv[1]);putfile(dev,"8:0\n");
 snprintf(part,sizeof(part),"%s/sda1",argv[1]);mkdir(part,0700);
 snprintf(part,sizeof(part),"%s/sda1/partition",argv[1]);putfile(part,"1\n");
 logd_collect_block_inventory(argv[1]);CHECK(COUNT==1);
 logd_collect_block_inventory(argv[1]);CHECK(COUNT==1);
 fail_scan=1;logd_collect_block_inventory(argv[1]);CHECK(COUNT==1);fail_scan=0;
 unlink(dev);rmdir(disk);fail_publish=1;logd_collect_block_inventory(argv[1]);CHECK(COUNT==1);
 fail_publish=0;logd_collect_block_inventory(argv[1]);CHECK(COUNT==2);
 CHECK(!strcmp(logd_json_str(json_object_array_get_idx(events,1),"event",""),"STORAGE_DEVICE_REMOVED"));
 logd_collect_block_inventory(argv[1]);CHECK(COUNT==2);
 logd_collect_boot();CHECK(COUNT==3);logd_collect_boot();CHECK(COUNT==3);
 boot="boot-fixture-2";fail_publish=1;logd_collect_boot();CHECK(COUNT==3);fail_publish=0;logd_collect_boot();CHECK(COUNT==4);
 boot="boot-fixture-3";fail_state=1;logd_collect_boot();CHECK(COUNT==4);fail_state=0;
 struct json_object*d=json_tokener_parse("{\"metric\":\"disk\",\"unit\":\"percent\"}");
 logd_collect_resource_one("disk",50,90,97,300,d);CHECK(COUNT==4);
 logd_collect_resource_one("disk",98,90,97,300,d);CHECK(COUNT==5);
 logd_collect_resource_one("disk",70,90,97,300,d);CHECK(COUNT==6);
 CHECK(!strcmp(logd_json_str(json_object_array_get_idx(events,5),"event",""),"SYSTEM_RESOURCE_RECOVERED"));
 logd_collect_resource_one("disk",60,90,97,300,d);CHECK(COUNT==6);
 snprintf(dev,sizeof(dev),"%s/restore.json",argv[1]);
 putfile(dev,"{\"operation_id\":\"restore-1\",\"phase\":\"armed\"}");logd_collect_restore_state(dev);CHECK(COUNT==7);
 logd_collect_restore_state(dev);CHECK(COUNT==7);
 putfile(dev,"{\"operation_id\":\"restore-1\",\"phase\":\"confirmed\"}");logd_collect_restore_state(dev);CHECK(COUNT==8);
 putfile(dev,"{\"operation_id\":\"restore-1\",\"phase\":\"rolled_back\",\"error\":\"confirmation_timeout\"}");logd_collect_restore_state(dev);CHECK(COUNT==9);
 putfile(dev,"{broken");logd_collect_restore_state(dev);CHECK(COUNT==9);
 json_object_put(d);json_object_put(states);json_object_put(events);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='log-resource-') as raw:
 tmp=Path(raw);(tmp/'blocks').mkdir();(tmp/'fixture.c').write_text(head+'\n'.join(parts)+tail)
 flags=subprocess.check_output(['pkg-config','--cflags','--libs','json-c'],text=True).split()
 subprocess.run(['cc','-std=c99','-Wall','-Wextra','-Werror',str(tmp/'fixture.c'),*flags,'-o',str(tmp/'fixture')],check=True)
 subprocess.run([str(tmp/'fixture'),str(tmp/'blocks')],check=True)
print('PASS 20 transition checks: discovery/removal, partitions, failed scans/persistence, boot identity, resource recovery, durable restore phases')
