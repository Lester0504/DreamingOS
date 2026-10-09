#!/usr/bin/env python3
"""Check effective OpenSSH values, config-only selection, and legacy fallback."""
import argparse
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
struct nc_sys_openssh_state {int port,password_login,keyboard_interactive_login,root_password_login,idle_timeout_min;};
'''
MAIN=r'''
int main(int argc,char**argv){struct nc_sys_openssh_state s;assert(argc==2);nc_sys_openssh_state_load(&s);
 if(atoi(argv[1])==2)assert(s.port==22&&s.password_login==1&&s.keyboard_interactive_login==1&&s.root_password_login==0&&s.idle_timeout_min==0);
 else assert(s.port==11504&&s.password_login==0&&s.keyboard_interactive_login==0&&s.root_password_login==0&&s.idle_timeout_min==2);
 printf("%d %d %d %d %d\n",s.port,s.password_login,s.keyboard_interactive_login,s.root_password_login,s.idle_timeout_min);
}
'''
FIXTURE='''#!/bin/sh
printf '%s %s\\n' "$1" "$OPENSSL_CONF" >> "$CALL_LOG"
if [ "$CASE" = 2 ]; then exit 1; fi
if [ "$CASE" = 1 ] && [ "$1" = -G ]; then printf 'port 1\\n'; exit 1; fi
printf '%s\\n' 'port 11504' 'port 22' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitrootlogin prohibit-password' 'clientaliveinterval 120'
'''
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=True)
 source=(ROOT/'src/netconfig/024_nc_system_settings.c').read_text();c=args.out/'ssh-read.c';c.write_text(PREFIX+function(source,'static void nc_sys_openssh_state_load(')+MAIN)
 binary=args.out/'ssh-read';subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-O2','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
 with tempfile.TemporaryDirectory(prefix='dw-ssh-read-') as directory:
  d=Path(directory);sshd=d/'sshd';sshd.write_text(FIXTURE);sshd.chmod(0o700)
  for case,expected in [(0,['-G /dev/null']),(1,['-G /dev/null','-T original-config']),(2,['-G /dev/null','-T original-config'])]:
   log=d/('calls-'+str(case));env=dict(os.environ,PATH=str(d)+':'+os.environ['PATH'],CASE=str(case),CALL_LOG=str(log),OPENSSL_CONF='original-config')
   subprocess.run([str(binary),str(case)],env=env,check=True,stdout=subprocess.DEVNULL)
   assert log.read_text().splitlines()==expected
 print('PASS config-only, unknown-option fallback, failed-config defaults, first-port and auth/idle fields')
if __name__=='__main__':main()
