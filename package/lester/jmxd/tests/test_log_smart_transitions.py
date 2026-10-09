#!/usr/bin/env python3
"""Exercise the actual SMART cache transition producer without touching a disk."""
from pathlib import Path
import importlib.util
import re
import subprocess
import tempfile

base = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("helpers", base / "src/logd/test_log_event_semantics.py")
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
source = (base / "src/storage/storage_overview.c").read_text()
collectors = (base / "src/logd/logd_collectors.c").read_text()
head = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "event_semantics.h"
#define syslog capture_syslog
#include "dw_business_event.h"
#undef syslog
#define STORAGE_MAX_DISKS 64
#define STORAGE_MAX_PARTITIONS 128
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
static int emitted;
static char captured[2048];
void capture_syslog(int priority,const char *fmt,...) {
    (void)priority; va_list ap; va_start(ap,fmt);
    vsnprintf(captured,sizeof(captured),fmt,ap); va_end(ap); emitted++;
}
static const char *logd_json_str(struct json_object *o,const char *k,const char *fallback) {
    struct json_object *v=NULL;
    return json_object_object_get_ex(o,k,&v) && json_object_is_type(v,json_type_string) ? json_object_get_string(v) : fallback;
}
'''
structs = "\n".join(re.search(r"struct " + name + r" \{[\s\S]*?\n\};", source).group()
                    for name in ["storage_partition", "storage_smart", "storage_disk", "storage_smart_cache_entry"])
parts = [helpers.c_function(source, "static void storage_smart_log_transition("),
         helpers.c_function(source, "static void storage_smart_cache_store("),
         helpers.c_function(collectors, "static int logd_business_line(")]
tail = r'''
static int verify(const char *event,const char *previous,const char *level,const char *word) {
    const char *category="",*found="";
    struct json_object *detail=json_object_new_object(),*row=json_object_new_object();
    if(!logd_business_line(captured,"dreamingwrt-core",&category,&found,detail) ||
       strcmp(category,"STORAGE") || strcmp(found,event) ||
       strcmp(logd_json_str(detail,"previous_smart_status",""),previous) ||
       strcmp(dw_event_effective_severity(found,detail,"notice"),level)) return 1;
    json_object_object_add(row,"event",json_object_new_string(found));
    json_object_object_add(row,"detail_json",detail); dw_event_payload_present(row,"zh-CN");
    const char *text=json_object_to_json_string_ext(row,JSON_C_TO_STRING_PLAIN);
    if(!strstr(text,word)||!strstr(text,"fixture-disk")||strlen(captured)>616) return 2;
    puts(text);json_object_put(row);return 0;
}
static void sample(struct storage_disk *disk,const char *status) {
    snprintf(disk->smart.status,sizeof(disk->smart.status),"%s",status);
    storage_smart_cache_store(disk,1000+emitted);
}
int main(void) {
    struct storage_disk disk={0};
    snprintf(disk.id,sizeof(disk.id),"fixture-disk");snprintf(disk.model,sizeof(disk.model),"Test model");
    snprintf(disk.device,sizeof(disk.device),"/dev/fixture");
    sample(&disk,"PASSED");sample(&disk,"PASSED");sample(&disk,"UNAVAILABLE");
    if(emitted!=0)return 1;
    sample(&disk,"FAILED");if(emitted!=1 || verify("STORAGE_SMART_FAILED","PASSED","error","检查失败"))return 2;
    sample(&disk,"FAILED");sample(&disk,"TIMEOUT");sample(&disk,"UNSUPPORTED");sample(&disk,"FAILED");
    if(emitted!=1)return 3;
    sample(&disk,"PASSED");if(emitted!=2 || verify("STORAGE_SMART_RECOVERED","FAILED","info","恢复通过"))return 4;
    sample(&disk,"PASSED");if(emitted!=2)return 5;
    memset(g_storage_smart_cache,0,sizeof(g_storage_smart_cache));
    sample(&disk,"UNAVAILABLE");sample(&disk,"PASSED");if(emitted!=2)return 6;
    memset(g_storage_smart_cache,0,sizeof(g_storage_smart_cache));
    sample(&disk,"FAILED");if(emitted!=3 || verify("STORAGE_SMART_FAILED","","error","检查失败"))return 7;
    /* Reusing a full cache slot must not attribute another disk's failure. */
    for(int i=0;i<STORAGE_MAX_DISKS;i++){
        g_storage_smart_cache[i].used=1;
        snprintf(g_storage_smart_cache[i].disk_id,sizeof(g_storage_smart_cache[i].disk_id),"other-%d",i);
        snprintf(g_storage_smart_cache[i].last_known_health,24,"FAILED");
    }
    sample(&disk,"PASSED");if(emitted!=3)return 8;
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="log-smart-") as tmp:
    out = Path(tmp)
    (out / "fixture.c").write_text(head + structs + "\nstatic struct storage_smart_cache_entry g_storage_smart_cache[STORAGE_MAX_DISKS];\n" + "\n".join(parts) + tail)
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "json-c"], text=True).split()
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I" + str(base / "src"),
                    str(out / "fixture.c"), str(base / "src/event_semantics.c"), "-o", str(out / "fixture"), *flags], check=True)
    subprocess.run([str(out / "fixture")], stdout=subprocess.DEVNULL, check=True)
print("PASS 14 SMART observations: first failure, recovery, unchanged cache, unavailable reads, restart and disk identity")
