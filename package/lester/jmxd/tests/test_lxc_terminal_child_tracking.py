#!/usr/bin/env python3
"""Real Linux child tracking without CONFIG_PROC_CHILDREN; no LXC/host changes."""
from pathlib import Path
import subprocess,tempfile
from test_container_service_runtime import _definition,json_c_flags
ROOT=Path(__file__).resolve().parents[1]
def main():
 source=(ROOT/'src/terminal_manager/lxc.inc').read_text()
 code=r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <json-c/json.h>
struct tm_session {pid_t child;int lxc_pidfd;struct json_object *host;};
static void tm_number(struct json_object *j,const char *key,int64_t value){json_object_object_add(j,key,json_object_new_int64(value));}
'''
 code+='\n'.join(_definition(source,name) for name in ['lxc_pidfd','lxc_signal','lxc_child_parent','lxc_pin_shell'])
 code+=r'''
int main(void){
 int ready[2];assert(!pipe(ready));
 pid_t parent=fork();assert(parent>=0);
 if(!parent){
  close(ready[0]);pid_t shell=fork();if(!shell){for(;;)pause();}
  assert(write(ready[1],&shell,sizeof(shell))==sizeof(shell));close(ready[1]);
  int status;waitpid(shell,&status,0);_exit(WIFSIGNALED(status)&&WTERMSIG(status)==SIGTERM?0:1);
 }
 close(ready[1]);pid_t selected;assert(read(ready[0],&selected,sizeof(selected))==sizeof(selected));close(ready[0]);
 pid_t unrelated=fork();assert(unrelated>=0);if(!unrelated){for(;;)pause();}
 char path[128];snprintf(path,sizeof(path),"/proc/%d/ns/pid",selected);struct stat expected;assert(!stat(path,&expected));
 struct tm_session s={.child=parent,.lxc_pidfd=-1,.host=json_object_new_object()};
 struct stat wrong=expected;wrong.st_ino++;assert(lxc_pin_shell(&s,&wrong)==-1);
 assert(!lxc_pin_shell(&s,&expected));assert(json_object_get_int(json_object_object_get(s.host,"attached_pid"))==selected);
 assert(!lxc_signal(s.lxc_pidfd,SIGTERM));close(s.lxc_pidfd);
 int status;assert(waitpid(parent,&status,0)==parent&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 assert(!kill(unrelated,0));kill(unrelated,SIGTERM);waitpid(unrelated,NULL,0);json_object_put(s.host);
 puts("PASS correct direct child pinned, wrong namespace rejected, unrelated process preserved, pidfd cleanup");
}
'''
 with tempfile.TemporaryDirectory(prefix='lxc-child-') as directory:
  t=Path(directory);(t/'test.c').write_text(code)
  subprocess.run(['cc','-std=c11','-Wall','-Wextra',str(t/'test.c'),*json_c_flags(),'-o',str(t/'test')],check=True)
  subprocess.run([str(t/'test')],check=True,timeout=15)
if __name__=='__main__':main()
