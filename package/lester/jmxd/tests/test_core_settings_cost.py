#!/usr/bin/env python3
"""Compare native fstab reads with the real UCI CLI, using temporary configs."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from test_core_resource_cost import function

ROOT=Path(__file__).resolve().parents[1]

PREFIX=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uci.h>
#include <json-c/json.h>
static const char *config_dir;
static struct uci_context *test_context(void) {
    struct uci_context *ctx=uci_alloc_context();
    if(ctx) {uci_set_confdir(ctx,config_dir);uci_set_savedir(ctx,config_dir);}
    return ctx;
}
#define uci_alloc_context test_context
'''
MAIN=r'''
int main(int argc,char **argv) {
    assert(argc==2);config_dir=argv[1];struct json_object *out=json_object_new_object();
    nc_sys_fstab_json(out);int value=0;
    assert(nc_adv_uci_read_int("fstab.@global[0].check_fs",&value)==0 && value==1);
    assert(nc_adv_uci_read_int("fstab.@global[0].missing",&value)==-1);
    assert(nc_adv_uci_read_int("fstab.cfgfoo.uuid",&value)==-1);
    puts(json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN));json_object_put(out);
}
'''
SERVICE_PREFIX=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define NC_SYS_SERVICE_SCRIPT_SCAN_MAX (128U*1024U)
struct nc_sys_service_handle { int fd; };
static size_t requested;
static void *measured_malloc(size_t n) { requested=n;return malloc(n); }
#define malloc measured_malloc
'''
SERVICE_MAIN=r'''
int main(int argc,char **argv) {
    assert(argc==2);struct nc_sys_service_handle h={.fd=open(argv[1],O_RDONLY)};
    assert(h.fd>=0);assert(nc_sys_service_supports_reload(&h)==1);
    struct stat st;assert(!fstat(h.fd,&st));assert(requested==(size_t)st.st_size+1);
    close(h.fd);printf("PASS reload detector allocation=%zu script_bytes=%lld\n",requested,(long long)st.st_size);
}
'''


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--prefix',type=Path,required=True);parser.add_argument('--uci',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    test_env=dict(os.environ,LD_LIBRARY_PATH=str(args.prefix/'lib')+':'+os.environ.get('LD_LIBRARY_PATH',''))
    source=(ROOT/'src/netconfig/024_nc_system_settings.c').read_text()
    code=PREFIX+'\n'.join(function(source,x) for x in [
        'static int nc_adv_uci_read_int(', 'static void nc_sys_fstab_quote(', 'static void nc_sys_fstab_json('])+MAIN
    flags=['-I'+str(args.prefix/'include'),'-L'+str(args.prefix/'lib'),'-Wl,-rpath,'+str(args.prefix/'lib'),'-luci','-ljson-c']
    cc=shlex.split(os.environ.get('CC','cc'))
    with (args.out/'settings-tests.log').open('w') as log:
        def compile(name,text,extra):
            c=args.out/(name+'.c');b=args.out/name;c.write_text(text)
            subprocess.run(cc+['-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(c),*extra,'-o',str(b)],check=True,stdout=log,stderr=log)
            return b
        binary=compile('fstab-test',code,flags)
        with tempfile.TemporaryDirectory(prefix='dw-cost-fstab-') as tmp:
            config=Path(tmp)/'fstab'
            config.write_text('''config global
 option anon_swap '1'
 option auto_swap '0'
 option auto_mount '0'
 option check_fs '1'
config mount
 option target '/anonymous'
config mount cfgfoo
 option uuid 'alpha'
 option target '/mnt/a b'
 option note "O'Reilly"
 list options 'rw'
 list options 'noatime'
config mount other
 option target '/ignored'
''')
            cli=subprocess.run([str(args.uci),'-c',tmp,'-P',tmp,'-q','show','fstab'],capture_output=True,text=True,check=True,env=test_env).stdout
            old=[]
            for line in cli.splitlines():
                if line.startswith('fstab.cfg'):
                    k,v=line.split('=',1);old.append({'uci_section':k,'uci_value':v})
            actual=json.loads(subprocess.check_output([str(binary),tmp],text=True,env=test_env))
            assert actual=={'auto_mount':False,'auto_swap':False,'check_fs':True,'fstab_config':old},(actual,old)
            log.write('PASS exact fstab CLI parity: anonymous/named/quoted/list/boolean\n')
            Path(tmp,'script').write_text('#!/bin/sh\nreload_service() { :; }\n')
            service=compile('service-buffer-test',SERVICE_PREFIX+function(source,'static int nc_sys_service_supports_reload(')+SERVICE_MAIN,[])
            log.write(subprocess.check_output([str(service),str(Path(tmp,'script'))],text=True))
    print('PASS fstab libuci/CLI parity and service buffer sizing')


if __name__=='__main__':main()
