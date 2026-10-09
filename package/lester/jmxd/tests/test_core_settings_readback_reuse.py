#!/usr/bin/env python3
"""Compare the GET's values and write gates with its previous readback contract."""
import argparse
from pathlib import Path
import os, json, re, shlex, subprocess
from test_core_resource_cost import function

ROOT=Path(__file__).resolve().parents[1]
PREFIX=r"""
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <json-c/json.h>
#include "system/system_settings_runtime.h"
#include "system/system_alg_runtime.h"
static int scenario;
static int calls[4];
#ifdef FAKE_READBACK
void ssr_paths_default(struct ssr_paths *p){memset(p,0,sizeof(*p));}
static int probe(struct ssr_probe*p){memset(p,0,sizeof(*p));p->available=1;p->apply_supported=scenario!=2;p->readback_supported=1;p->rollback_supported=scenario!=3;return 0;}
int ssr_time_probe(const struct ssr_paths*p,struct ssr_probe*q){(void)p;return probe(q);}
int ssr_log_probe(const struct ssr_paths*p,struct ssr_probe*q){(void)p;return probe(q);}
int ssr_zram_probe(const struct ssr_paths*p,struct ssr_probe*q){(void)p;return probe(q);}
int ssr_time_readback(const struct ssr_paths*p,const struct ssr_executor*e,struct ssr_time_state*s,char*x,size_t n){(void)p;(void)e;(void)x;(void)n;calls[0]++;memset(s,0,sizeof(*s));strcpy(s->settings.timezone,"UTC");strcpy(s->settings.interval,"15m");s->settings.client_enabled=1;s->settings.server_count=1;strcpy(s->settings.servers[0],"clock.example");return scenario==1?-1:0;}
int ssr_log_readback(const struct ssr_paths*p,const struct ssr_executor*e,struct ssr_log_state*s,char*x,size_t n){(void)p;(void)e;(void)x;(void)n;calls[1]++;memset(s,0,sizeof(*s));strcpy(s->settings.kernel_level,"4");strcpy(s->settings.cron_level,"5");s->settings.buffer_kib=64;return scenario==4?-1:0;}
int ssr_zram_readback(const struct ssr_paths*p,const struct ssr_executor*e,struct ssr_zram_state*s,char*x,size_t n){(void)p;(void)e;(void)x;(void)n;calls[2]++;memset(s,0,sizeof(*s));s->active=1;s->settings.size_mib=128;strcpy(s->settings.algorithm,"lz4");return scenario==5?-1:0;}
int jmx_system_alg_helper_parse(const char*n,enum jmx_system_alg_helper*h){const char*names[]={"ftp","tftp","sip","h323"};for(int i=0;i<4;i++)if(!strcmp(n,names[i])){*h=i;return 0;}return -1;}
int jmx_system_alg_probe(const struct jmx_system_alg_options*o,enum jmx_system_alg_helper h,struct jmx_system_alg_state*s,char*e,size_t n){(void)o;(void)e;(void)n;calls[3]++;memset(s,0,sizeof(*s));s->conntrack_available=1;s->nat_available=!(scenario==6&&h==JMX_SYSTEM_ALG_SIP);s->running_known=scenario!=7;s->running=1;s->ports_writable=1;strcpy(s->ports,"21");return scenario==8&&h==JMX_SYSTEM_ALG_H323?-1:0;}
#endif
"""
MAIN=r"""
static long micros(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000000L+t.tv_nsec/1000;}
int main(int argc,char**argv){scenario=argc>1?atoi(argv[1]):0;
 for(int round=0;round<2;round++){
  memset(calls,0,sizeof(calls));
  struct json_object*g=json_object_new_object(),*a=json_object_new_object(),*meta=json_object_new_object(),*result=json_object_new_object();
  for(int i=0;i<4;i++)json_object_object_add(meta,nc_adv_alg_helpers[i].field,json_object_new_object());
  json_object_object_add(a,"alg_meta",meta);
  long start=micros();struct rusage before,after;getrusage(RUSAGE_SELF,&before);
  GET_READBACK
  getrusage(RUSAGE_SELF,&after);long wall=micros()-start;
  json_object_object_add(result,"general",g);json_object_object_add(result,"advanced",a);
  json_object_object_add(result,"time_write",json_object_new_boolean(t));json_object_object_add(result,"logs_write",json_object_new_boolean(l));json_object_object_add(result,"zram_write",json_object_new_boolean(z));json_object_object_add(result,"alg_write",json_object_new_boolean(alg));
  printf("%s\n",json_object_to_json_string_ext(result,JSON_C_TO_STRING_PLAIN));
  fprintf(stderr,"round=%d wall_us=%ld cpu_us=%ld calls=%d,%d,%d,%d\n",round,wall,(after.ru_utime.tv_sec-before.ru_utime.tv_sec+after.ru_stime.tv_sec-before.ru_stime.tv_sec)*1000000L+after.ru_utime.tv_usec-before.ru_utime.tv_usec+after.ru_stime.tv_usec-before.ru_stime.tv_usec,calls[0],calls[1],calls[2],calls[3]);
  EXPECT_CALLS
  json_object_put(result);
 }
}
"""

def code(source,new,fake):
    settings=(ROOT/'src/netconfig/024_nc_system_settings.c').read_text()
    begin=settings.index('/* ALG helper modules.');end=settings.index('/* True when the conntrack helper',begin)
    text=PREFIX+settings[begin:end]
    for name in ['static int nc_ssr_time_writable(', 'static int nc_ssr_log_writable(', 'static int nc_ssr_zram_writable(', 'static int nc_alg_helper_writable(', 'static int nc_alg_group_writable(']:
        text+=function(source,name)+'\n'
    if new:
        a=source.index('struct nc_system_runtime_capabilities {');b=source.index('};',a)+2;text+=source[a:b]+'\n'
    text+=function(source,'static void nc_system_settings_runtime_overlay(')
    read=('struct nc_system_runtime_capabilities c;nc_system_settings_runtime_overlay(g,a,&c);int t=c.time_write,l=c.logs_write,z=c.zram_write,alg=c.alg_write;' if new else 'nc_system_settings_runtime_overlay(g,a);int t=nc_ssr_time_writable(),l=nc_ssr_log_writable(),z=nc_ssr_zram_writable(),alg=nc_alg_group_writable();assert(t==nc_ssr_time_writable()&&l==nc_ssr_log_writable()&&z==nc_ssr_zram_writable());')
    check='assert(calls[0]==1&&calls[1]==1&&calls[2]==1&&calls[3]==4);' if fake and new else ''
    return ('#define FAKE_READBACK\n' if fake else '')+text+MAIN.replace('GET_READBACK',read).replace('EXPECT_CALLS',check)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--before',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--generate-only',action='store_true');args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    current=(ROOT/'src/netconfig/025_nc_system_runtime_draft.c').read_text();old=args.before.read_text()
    for mode in ['fake','live']:
        for version,source in [('before',old),('after',current)]:
            (args.out/(mode+'-'+version+'.c')).write_text(code(source,version=='after',mode=='fake'))
    if args.generate_only:return
    flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','json-c'],text=True))
    cc=shlex.split(os.environ.get('CC','cc'))
    for version in ('before','after'):
        subprocess.run(cc+['-O2','-Wall','-Wextra','-Wno-unused-function','-I'+str(ROOT/'src'),str(args.out/('fake-'+version+'.c')),*flags,'-o',str(args.out/version)],check=True)
    for scenario in range(9):
        values=[]
        for version in ('before','after'):
            res=subprocess.run([str(args.out/version),str(scenario)],text=True,capture_output=True,check=True);values.append([json.loads(line) for line in res.stdout.splitlines()])
        assert values[0]==values[1],scenario
    print('PASS 9 readback/probe/ALG cases, parity, per-request freshness, exactly one read per subsystem')
if __name__=='__main__':main()
