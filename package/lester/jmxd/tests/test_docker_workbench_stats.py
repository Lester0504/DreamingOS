#!/usr/bin/env python3
"""Exercise production numeric sampling with exact byte counters and CPU deltas."""
from pathlib import Path
import subprocess
import tempfile
import json
from test_container_service_runtime import _definition, json_c_flags

ROOT = Path(__file__).resolve().parents[1]

def main():
    read = (ROOT / 'src/netconfig/033_nc_docker_read.inc').read_text()
    stats = (ROOT / 'src/netconfig/033_nc_docker_stats.inc').read_text()
    with tempfile.TemporaryDirectory(prefix='docker-stats-') as directory:
        temp = Path(directory)
        source = r'''
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
static int64_t nc_now_s(void) { return 1700000000; }
static const char *nc_json_str_def(struct json_object *o,const char *k,const char *f) {
 struct json_object *v=NULL;return o&&json_object_object_get_ex(o,k,&v)?json_object_get_string(v):f;
}
static int nc_json_int_def(struct json_object *o,const char *k,int f) {
 struct json_object *v=NULL;return o&&json_object_object_get_ex(o,k,&v)?json_object_get_int(v):f;
}
static struct json_object *nc_docker_previous_stats;
'''
        source += _definition(read, 'nc_docker_member') + '\n'
        source += _definition(read, 'nc_docker_copy') + '\n'
        source += _definition(stats, 'nc_docker_stats_sample') + '\n'
        source += r'''
int main(void) {
 nc_docker_previous_stats=json_object_new_object();
 char *lines[]={
 "{\"id\":\"abc\",\"cpu_stats\":{\"cpu_usage\":{\"total_usage\":100},\"system_cpu_usage\":1000,\"online_cpus\":2},\"memory_stats\":{\"usage\":12345,\"limit\":67108864},\"networks\":{\"eth0\":{\"rx_bytes\":123,\"tx_bytes\":456}}}",
 "{\"id\":\"abc\",\"cpu_stats\":{\"cpu_usage\":{\"total_usage\":300},\"system_cpu_usage\":2000,\"online_cpus\":2},\"memory_stats\":{\"usage\":12346,\"limit\":67108864},\"networks\":{\"eth0\":{\"rx_bytes\":130,\"tx_bytes\":460},\"eth1\":{\"rx_bytes\":5,\"tx_bytes\":6}}}",
 "{\"id\":\"new\",\"cpu_stats\":{},\"memory_stats\":{}}"};
 for(int i=0;i<3;i++) {struct json_object *raw=json_tokener_parse(lines[i]),*sample=nc_docker_stats_sample(raw);puts(json_object_to_json_string(sample));json_object_put(sample);json_object_put(raw);}
 json_object_put(nc_docker_previous_stats);return 0;
}
'''
        (temp/'sample.c').write_text(source)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(temp/'sample.c'),*json_c_flags(),'-o',str(temp/'sample')],check=True,capture_output=True)
        rows=[json.loads(x) for x in subprocess.check_output([str(temp/'sample')],text=True).splitlines()]
        assert rows[0]['cpu_percent'] is None and rows[0]['cpu_available'] is False
        assert rows[0]['memory_usage_bytes']==12345 and rows[0]['memory_limit_bytes']==67108864
        assert rows[1]['cpu_percent']==40 and rows[1]['cpu_available'] is True
        assert rows[1]['network_rx_bytes']==135 and rows[1]['network_tx_bytes']==466
        assert rows[2]['memory_usage_bytes'] is None and rows[2]['network_rx_bytes'] is None
        print('ok: numeric CPU deltas, exact memory/network bytes, missing samples stay null')

if __name__ == '__main__':
    main()
