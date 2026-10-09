#!/usr/bin/env python3
"""Execute the production LXC read layer with bounded CLI fault fixtures."""
import json, os, subprocess, tempfile
from pathlib import Path
from test_container_service_runtime import _definition, json_c_flags
from apd_test_deps import package_flags
ROOT=Path(__file__).resolve().parents[1]
PRELUDE=r'''
#define _GNU_SOURCE
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#define NC_CONTAINER_OUTPUT_MAX 65536
#define API_CODE_SUCCESS 2000
#define API_CODE_ERROR 5000
struct nc_exec_result {char *output;int rc,timed_out,truncated;};
static int nc_docker_migration_guard(void){return -2;}
static int64_t nc_now_s(void){return time(NULL);}
static int nc_json_bool_def(struct json_object *o,const char *k,int d){struct json_object *v=json_object_object_get(o,k);return v?json_object_get_boolean(v):d;}
static int nc_json_int_def(struct json_object *o,const char *k,int d){struct json_object *v=json_object_object_get(o,k);return v?json_object_get_int(v):d;}
static const char *nc_json_str_def(struct json_object *o,const char *k,const char *d){struct json_object *v=json_object_object_get(o,k);return v?json_object_get_string(v):d;}
static char *nc_sys_read_file_text(const char *path,size_t limit){FILE *f=fopen(path,"r");if(!f)return NULL;char *s=calloc(1,limit+1);size_t n=fread(s,1,limit,f);int error=ferror(f);fclose(f);if(error){free(s);return NULL;}s[n]=0;return s;}
static int nc_cmd_exists(const char *name){char path[4096];snprintf(path,sizeof(path),"%s/%s",getenv("LXC_TEST_BIN"),name);return access(path,X_OK)==0;}
static struct json_object *jmx_gen_api_response_data(int code,struct json_object *data){struct json_object *r=json_object_new_object();json_object_object_add(r,"code",json_object_new_int(code));json_object_object_add(r,"data",data);return r;}
'''
MAIN=r'''
int main(int argc,char **argv){struct json_object *r=NULL;
if(argc<2)return 1;
if(!strcmp(argv[1],"get"))r=jmx_container_lxc_get();
else if(!strcmp(argv[1],"config"))r=jmx_lxc_container_config_get(argv[2]);
else if(!strcmp(argv[1],"logs"))r=jmx_lxc_container_logs(argv[2],NULL);
else if(!strcmp(argv[1],"stats"))r=jmx_lxc_container_stats(argv[2]);
else if(!strcmp(argv[1],"processes"))r=jmx_lxc_container_processes(argv[2]);
else if(!strcmp(argv[1],"templates"))r=jmx_lxc_templates_get();
else if(!strcmp(argv[1],"settings"))r=jmx_lxc_config_get();
if(!r)return 2;puts(json_object_to_json_string_ext(r,JSON_C_TO_STRING_PLAIN));json_object_put(r);return 0;}
'''
def main():
 with tempfile.TemporaryDirectory(prefix='lxc-reads-') as directory:
  t=Path(directory);b=t/'bin';b.mkdir();root=t/'containers';root.mkdir();(root/'sample').mkdir();(root/'sample/config').write_text('lxc.start.auto = 0\nlxc.net.0.type = empty\n')
  (t/'lxc.conf').write_text('lxc.lxcpath = '+str(root)+'\n');(t/'templates').mkdir();(t/'templates/lxc-local').touch()
  source=(ROOT/'src/netconfig/033_nc_container.c').read_text();names=['nc_container_monotonic_ms','nc_exec_result_free','nc_exec_trim_output','nc_exec_argv_capture_ex','nc_exec_argv_capture']
  reads=(ROOT/'src/netconfig/033_nc_lxc_read.inc').read_text()
  # Keep the production parser; substitute only the remote network transport.
  reads=reads.replace(_definition(reads,'nc_lxc_catalog_fetch'),'''static char *nc_lxc_catalog_fetch(struct json_object *out){const char *text=getenv("LXC_TEST_INDEX");if(!text){nc_lxc_error(out,"template_source_unavailable");return NULL;}return strdup(text);}''')
  (t/'fixture.c').write_text(PRELUDE+'\n'+'\n'.join(_definition(source,n) for n in names)+'\n'+reads+'\n'+MAIN)
  build=subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror=implicit-function-declaration',f'-DNC_LXC_SYSTEM_CONFIG="{t}/lxc.conf"',f'-DNC_LXC_CONFIG_DB="{t}/config.db"',f'-DNC_LXC_TEMPLATE_DIR="{t}/templates"',f'-DNC_LXC_PROC_ROOT="{t}/proc"',f'-DNC_LXC_CGROUP_ROOT="{t}/cgroup"',str(t/'fixture.c'),*json_c_flags(),*package_flags('libcurl'),'-lsqlite3','-o',str(t/'read')],capture_output=True,text=True)
  assert build.returncode==0,build.stderr
  env=dict(os.environ,LXC_TEST_BIN=str(b),PATH=str(b)+':'+os.environ['PATH'])
  def get(*args):return json.loads(subprocess.check_output([str(t/'read'),*args],env=env,text=True))
  absent=get('get')['data'];assert absent['environment_state']=='not_installed' and absent['containers'] is None and absent['container_count'] is None,absent
  assert absent['config']['lxcpath']==str(root) and absent['uci_config']==absent['config']
  assert get('config','../sample')['data']['error']=='invalid_name'
  assert get('config','missing')['data']['error']=='container_not_found'
  assert get('config','sample')['data']['config'].endswith('lxc.net.0.type = empty\n')
  assert get('logs','sample')['data']['error']=='lxc_log_source_unavailable'
  assert get('templates')['data']['scripts'][0]['creatable'] is False
  assert get('templates')['data']['error']=='template_source_unavailable'
  env['LXC_TEST_INDEX']='alpine;3.22;amd64;default;20261005_13:00;/images/alpine/3.22/amd64/default/20261005_13:00/\n'
  env['LXC_TEST_INDEX']+='alpine;3.22;amd64;default;20261005_13:00;https://unexpected.example/evil/\n'
  env['LXC_TEST_INDEX']+='alpine;3.22;arm64;default;20261005_13:00;/images/alpine/3.22/arm64/default/20261005_13:00/\n'
  catalog=get('templates')['data'];assert catalog['ok'] and len(catalog['catalog'])==2,catalog
  assert all(not v['creatable'] and v['source_verified'] for v in catalog['catalog'])
  assert catalog['catalog'][0]['rootfs_url'].startswith('https://images.linuxcontainers.org/images/alpine/')
  assert sum(v['compatible'] for v in catalog['catalog'])<=1
  env['LXC_TEST_INDEX']='invalid';assert get('templates')['data']['error']=='template_catalog_no_supported_images'

  table=''.join(f'{v:<{w}}' for v,w in zip(['NAME','STATE','AUTOSTART','IPV4','IPV6','UNPRIVILEGED'],[15,10,10,32,30,15]))+'\n'
  table+=''.join(f'{v:<{w}}' for v,w in zip(['sample','RUNNING','0','192.0.2.1, 192.0.2.2','2001:db8::1','true'],[15,10,10,32,30,15]))+'\n'
  (b/'lxc-ls').write_text('#!/bin/sh\ncat '+str(t/'table')+'\n');(b/'lxc-ls').chmod(0o755);(t/'table').write_text(table)
  data=get('get')['data'];assert data['ok'] and data['container_count']==1 and data['containers'][0]['ipv4']=='192.0.2.1, 192.0.2.2' and data['containers'][0]['unprivileged'] is True,data
  (t/'table').write_text('nonsense');assert get('get')['data']['error']=='lxc_list_format_invalid'
  (b/'lxc-ls').write_text('#!/bin/sh\necho failed >&2\nexit 1\n');data=get('get')['data'];assert not data['ok'] and data['containers'] is None and data['exit_code']==1,data
  (b/'lxc-info').write_text('#!/bin/sh\nprintf "State: RUNNING\\nPID: 42\\nCPU use: 2.50 seconds\\nMemory use: 12.00 MiB\\nBytes received: 2.00 KiB\\nBytes sent: 3.00 KiB\\n"\n');(b/'lxc-info').chmod(0o755)
  stats=get('stats','sample')['data'];assert stats['memory_usage_bytes']==12582912 and stats['cpu_seconds']==2.5 and stats['cpu_percent'] is None and stats['network_rx_bytes']==2048,stats
  (b/'lxc-info').write_text('#!/bin/sh\nprintf "State: RUNNING\\nPID: 42\\nLink: veth0\\n TX bytes: 3.00 KiB\\n RX bytes: 2.00 KiB\\n"\n')
  stats=get('stats','sample')['data'];assert stats['cpu_seconds'] is None and stats['memory_usage_bytes'] is None and stats['network_rx_bytes']==2048 and stats['network_tx_bytes']==3072,stats
  proc=t/'proc';(proc/'self/ns').mkdir(parents=True);(proc/'42/ns').mkdir(parents=True);(proc/'42/net').mkdir()
  (proc/'self/ns/pid').touch();(proc/'42/ns/pid').touch()
  (proc/'42/cgroup').write_text('0::/lxc.payload.sample\n')
  group=t/'cgroup/lxc.payload.sample';group.mkdir(parents=True)
  (group/'cpu.stat').write_text('usage_usec 3250123\nuser_usec 1000000\nsystem_usec 2250123\n')
  (group/'memory.current').write_text('6250496\n');(group/'memory.max').write_text('134217728\n')
  (proc/'42/net/dev').write_text('Inter-| Receive | Transmit\nlo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\neth0: 279240 732 0 0 0 0 0 0 2874 27 0 0 0 0 0 0\neth1: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n')
  stats=get('stats','sample')['data'];assert stats['cpu_seconds']==3.250123 and stats['memory_usage_bytes']==6250496 and stats['memory_limit_bytes']==134217728 and stats['network_rx_bytes']==279340 and stats['network_tx_bytes']==3074,stats
  (group/'memory.max').write_text('max\n');assert get('stats','sample')['data']['memory_limit_bytes'] is None
  # A host PID must not be reported as the container, and stopped objects have no sample.
  (proc/'42/ns/pid').unlink();os.link(proc/'self/ns/pid',proc/'42/ns/pid')
  assert get('stats','sample')['data']['cpu_seconds'] is None
  (b/'lxc-info').write_text('#!/bin/sh\nprintf "State: STOPPED\\n"\n')
  stats=get('stats','sample')['data'];assert stats['cpu_seconds'] is None and stats['network_rx_bytes'] is None
  (b/'lxc-attach').write_text('#!/bin/sh\nexit 1\n');(b/'lxc-attach').chmod(0o755);assert not get('processes','sample')['data']['ok']
  log=t/'runtime.log';log.write_text('started\n');(root/'sample/config').write_text('lxc.log.file = '+str(log)+'\n')
  assert get('logs','sample')['data']['logs']=='started'
  log.unlink();assert not get('logs','sample')['data']['ok']
  (b/'lxc-ls').write_text('#!/usr/bin/env python3\nprint("x"*70000)\n');data=get('get')['data'];assert data['error']=='lxc_output_truncated' and data['containers'] is None,data
  print('PASS: missing/degraded, runtime path, invalid/not-found, source-aware logs, multi-address columns, failed/truncated reads, LXC7/v2/exact namespace stats, stopped/unlimited nulls, template script classification')
if __name__=='__main__':main()
