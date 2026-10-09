#!/usr/bin/env python3
"""Runtime checks and isolated before/after probes for core collection costs.

Run on Linux, with optional --baseline pointing at the pre-change src files.
All build products and reports go under --out, never into the source tree.
The JSON deep-copy branch is a rejected experiment retained for reproducibility.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def function(text, marker):
    start = text.index(marker)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


EXEC_CONTRACT = r'''
#define _GNU_SOURCE
#include "jmx_exec.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    struct jmx_exec_result r;
    int fd = open("/dev/null", O_RDONLY);
    assert(fd >= 0 && dup2(fd, 400) == 400); close(fd);
    setenv("DW_COST_SENTINEL", "not-in-child", 1);
    char *check[] = {"/bin/sh", "-c",
        "test ! -e /proc/self/fd/400 && test -z \"$DW_COST_SENTINEL\" && "
        "test \"$LANG\" = C && test -z \"$(cat)\" && printf okay", NULL};
    assert(jmx_exec_capture(check[0],check,64,1000,&r)==0);
    assert(r.exit_code==0 && !r.timed_out && !strcmp(r.output,"okay"));
    jmx_exec_result_free(&r); close(400);
    char *missing[]={"/definitely-missing-dw-cost",NULL};
    assert(jmx_exec_capture(missing[0],missing,64,1000,&r)==0 && r.exit_code==127);
    jmx_exec_result_free(&r);
    char *oversize[]={"/usr/bin/printf","123456",NULL};
    assert(jmx_exec_capture(oversize[0],oversize,3,1000,&r)==0);
    assert(r.exit_code==0 && r.truncated && r.output_len==3 && !strcmp(r.output,"123"));
    jmx_exec_result_free(&r);
    char *timeout[]={"/bin/sh","-c","trap '' TERM; sleep 3",NULL};
    assert(jmx_exec_wait(timeout[0],timeout,30,&r)==0 && r.timed_out && r.term_signal);
    jmx_exec_result_free(&r);
    char *descendant[]={"/bin/sh","-c","sleep 3 & exit 0",NULL};
    assert(jmx_exec_capture(descendant[0],descendant,32,30,&r)==0);
    assert(r.truncated && r.exit_code==0); jmx_exec_result_free(&r);
    puts("PASS fd/environment/stdin/exec-failure/truncation/timeout/process-group");
}
'''

BENCH_PREFIX = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
static int64_t now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (int64_t)t.tv_sec*1000000+t.tv_nsec/1000; }
static int64_t tv_us(struct timeval t) { return (int64_t)t.tv_sec*1000000+t.tv_usec; }
static int cmp(const void *a,const void *b) { int64_t x=*(const int64_t*)a,y=*(const int64_t*)b; return (x>y)-(x<y); }
'''

EXEC_BENCH = BENCH_PREFIX + r'''
#include "jmx_exec.h"
#include <pthread.h>
#include <stdatomic.h>
static atomic_int stop_writer;
static unsigned char *arena;
static void *writer(void *unused) {
    (void)unused; unsigned char generation=0;
    while (!atomic_load(&stop_writer)) {
        for (size_t i=0;i<64U*1024*1024;i+=4096) arena[i]=++generation;
        usleep(1000);
    }
    return NULL;
}
int main(void) {
    enum {N=80}; int64_t samples[N],start=now_us(); struct rusage a,b;
    pthread_t thread; arena=malloc(64U*1024*1024); assert(arena);
    memset(arena,1,64U*1024*1024); assert(!pthread_create(&thread,NULL,writer,NULL));
    usleep(20000); getrusage(RUSAGE_SELF,&a); start=now_us();
    for(int i=0;i<N;i++) { struct jmx_exec_result r; char *argv[]={"/bin/true",NULL};
        int64_t t=now_us(); assert(jmx_exec_wait(argv[0],argv,1000,&r)==0 && r.exit_code==0);
        samples[i]=now_us()-t; jmx_exec_result_free(&r);
    }
    int64_t elapsed=now_us()-start; getrusage(RUSAGE_SELF,&b);
    atomic_store(&stop_writer,1); pthread_join(thread,NULL); free(arena); qsort(samples,N,sizeof(*samples),cmp);
    printf("{\"calls\":%d,\"wall_us\":%lld,\"user_us\":%lld,\"system_us\":%lld,\"minor_faults\":%ld,\"p50_us\":%lld,\"p95_us\":%lld}\n",N,(long long)elapsed,(long long)(tv_us(b.ru_utime)-tv_us(a.ru_utime)),(long long)(tv_us(b.ru_stime)-tv_us(a.ru_stime)),b.ru_minflt-a.ru_minflt,(long long)samples[N/2],(long long)samples[(N*95+99)/100-1]);
}
'''

CLONE_BENCH = r'''
#include <json-c/json.h>
#include <malloc.h>
''' + BENCH_PREFIX.replace('#define _GNU_SOURCE\n', '') + r'''
CLONE_IMPLEMENTATION
static long rss_kib(void) {long total=0,resident=0;FILE *f=fopen("/proc/self/statm","r");if(!f)return -1;if(fscanf(f,"%ld %ld",&total,&resident)!=2)resident=-1;fclose(f);return resident<0?-1:resident*(sysconf(_SC_PAGESIZE)/1024);}
int main(void) {
    enum {N=80}; struct json_object *root=json_object_new_array(); char value[129];
    memset(value,'x',128); value[128]=0;
    for(int i=0;i<3000;i++) {struct json_object *row=json_object_new_object();
        json_object_object_add(row,"index",json_object_new_int(i));
        json_object_object_add(row,"name",json_object_new_string(value));
        json_object_object_add(row,"ratio",json_object_new_double(0.25));
        json_object_object_add(row,"nullable",NULL); json_object_array_add(root,row);}
    long rss_before=rss_kib(); struct mallinfo2 m0=mallinfo2(); struct rusage a,b; getrusage(RUSAGE_SELF,&a);
    int64_t samples[N],start=now_us();
    for(int i=0;i<N;i++) {int64_t t=now_us(); struct json_object *copy=dw_read_json_clone(root);
        assert(copy && copy!=root && json_object_equal(copy,root));
        json_object_object_add(json_object_array_get_idx(copy,0),"index",json_object_new_int(-1));
        assert(json_object_get_int(json_object_object_get(json_object_array_get_idx(root,0),"index"))==0);
        json_object_put(copy); samples[i]=now_us()-t;}
    int64_t elapsed=now_us()-start; getrusage(RUSAGE_SELF,&b); struct mallinfo2 m1=mallinfo2();
    qsort(samples,N,sizeof(*samples),cmp);
    printf("{\"rows\":3000,\"calls\":%d,\"wall_us\":%lld,\"user_us\":%lld,\"system_us\":%lld,\"minor_faults\":%ld,\"live_retained_delta\":%lld,\"arena_free_delta\":%lld,\"mmap_live_delta\":%lld,\"rss_before_kib\":%ld,\"rss_after_kib\":%ld,\"maxrss_kib\":%ld,\"p50_us\":%lld,\"p95_us\":%lld}\n",N,(long long)elapsed,(long long)(tv_us(b.ru_utime)-tv_us(a.ru_utime)),(long long)(tv_us(b.ru_stime)-tv_us(a.ru_stime)),b.ru_minflt-a.ru_minflt,(long long)m1.uordblks-(long long)m0.uordblks,(long long)m1.fordblks-(long long)m0.fordblks,(long long)m1.hblkhd-(long long)m0.hblkhd,rss_before,rss_kib(),b.ru_maxrss,(long long)samples[N/2],(long long)samples[(N*95+99)/100-1]);
    json_object_put(root);
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    import apd_test_deps
    json_flags = apd_test_deps.package_flags('json-c')
    cc = shlex.split(os.environ.get('CC', 'cc'))
    results = {}
    with (args.out/'tests.log').open('w') as log:
        def compile_run(name, text, extra, repeat=1):
            source=args.out/(name+'.c'); binary=args.out/name; source.write_text(text)
            command=cc+['-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT/'src'),str(source)]+extra+['-o',str(binary)]
            log.write(shlex.join(command)+'\n');log.flush()
            subprocess.run(command,check=True,stdout=log,stderr=log)
            output=[]
            for _ in range(repeat):
                run=subprocess.run([str(binary)],capture_output=True,text=True,check=True,timeout=30)
                log.write(run.stdout+run.stderr);log.flush();output.append(run.stdout.strip())
            return output
        results['exec_contract']=compile_run('exec-contract',EXEC_CONTRACT,[str(ROOT/'src/jmx_exec.c')])
        results['fork_fallback_contract']=compile_run('fork-contract',EXEC_CONTRACT,['-DJMX_EXEC_FORCE_FORK=1',str(ROOT/'src/jmx_exec.c')])
        for version,src in [('new',ROOT/'src'),('old',args.baseline)]:
            if src is None: continue
            results['exec_'+version]=[json.loads(x) for x in compile_run('exec-'+version,EXEC_BENCH,[str(src/'jmx_exec.c'),'-lpthread'],3)]
            fixture=args.out/'ifstatus-fixture'
            if not fixture.exists():
                compile_run('ifstatus-fixture','#include <stdio.h>\nint main(void){puts("{\\\"up\\\":true,\\\"ipv4-address\\\":[]}");return 0;}\n',[])
            network_bench=EXEC_BENCH.replace('#include "jmx_exec.h"','#include "jmx_network.h"')
            network_bench=network_bench.replace('struct jmx_exec_result r; char *argv[]={"/bin/true",NULL};','')
            network_bench=network_bench.replace('assert(jmx_exec_wait(argv[0],argv,1000,&r)==0 && r.exit_code==0);','char *response=get_interface_status_buf("wan"); assert(response && strstr(response,"true")); free(response);')
            network_bench=network_bench.replace(' jmx_exec_result_free(&r);','')
            results['ifstatus_'+version]=[json.loads(x) for x in compile_run('ifstatus-'+version,network_bench,[str(src/'jmx_network.c'),'-DJMX_NETWORK_DEFENSIVE_ONLY=1',f'-DJMX_IFSTATUS_PATH="{fixture}"','-lpthread',*json_flags],3)]
            body=function((src/'dw_read_cache.c').read_text(),'static struct json_object *dw_read_json_clone(')
            if version=='new':
                body='static struct json_object *dw_read_json_clone(struct json_object *o) {struct json_object *c=NULL;if(!o)return json_object_new_object();if(json_object_deep_copy(o,&c,NULL)==0)return c;if(c)json_object_put(c);return json_object_new_object();}'
            results['clone_'+('rejected_candidate' if version=='new' else version)]=[json.loads(x) for x in compile_run('clone-'+version,CLONE_BENCH.replace('CLONE_IMPLEMENTATION',body),json_flags,3)]
    (args.out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results))


if __name__=='__main__': main()
