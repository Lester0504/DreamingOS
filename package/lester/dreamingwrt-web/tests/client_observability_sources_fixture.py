#!/usr/bin/env python3
"""Emit raw DNS contract rows using production sample_json(), without probes.

Only the slot/rule/probe-result inputs are controlled test values. The JSON
serializer is extracted from the current C source and compiled in /tmp.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'jmxd/tests'))
import apd_test_deps


def dns_rows():
    source = (ROOT / 'jmxd/src/flowd/wan_sla_runtime.c').read_text()
    start = source.index('static struct json_object *sample_json(')
    stop = source.index('\nstatic void worker_done(', start)
    serializer = source[start:stop]
    preamble = r'''
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "healthd/wan_probe.h"
struct sla_slot { char id[96], wan[32]; int64_t revision; };
static struct json_object *value(struct json_object *o, const char *k) {
    struct json_object *v = NULL; json_object_object_get_ex(o, k, &v); return v;
}
static const char *flowd_json_str(struct json_object *o, const char *k, const char *d) {
    struct json_object *v = value(o, k); return v ? json_object_get_string(v) : d;
}
'''
    main = r'''
int main(void) {
    struct sla_slot slot = { .id="dns-contract-fixture", .wan="wan", .revision=1 };
    struct wan_probe_result r = { .ok=1, .valid=1, .address_family=2,
        .started_at=1791439200, .finished_at=1791439201,
        .dns_ms=0, .latency_ms=-1, .tcp_ms=-1, .tls_ms=-1,
        .source_ifname="wan0", .source_address="192.0.2.2" };
    struct json_object *rule = json_tokener_parse(
        "{\"method\":\"dns\",\"targets\":[\"dns://192.0.2.53:53/probe.example\",\"dns://192.0.2.54:53/probe.example\"]}");
    struct json_object *rows = json_object_new_array();
    json_object_array_add(rows, sample_json(&slot,"fixture-1",rule,0,&r));
    r.ok=0; r.dns_ms=-1; r.started_at+=10; r.finished_at+=10;
    snprintf(r.error_class,sizeof(r.error_class),"dns_timeout");
    json_object_array_add(rows, sample_json(&slot,"fixture-2",rule,0,&r));
    r.ok=1; r.dns_ms=2.5; r.started_at+=10; r.finished_at+=10; r.error_class[0]=0;
    json_object_array_add(rows, sample_json(&slot,"fixture-3",rule,0,&r));
    slot.revision=2; r.started_at+=10; r.finished_at+=10;
    json_object_array_add(rows, sample_json(&slot,"fixture-4",rule,0,&r));
    json_object_array_add(rows, sample_json(&slot,"fixture-4",rule,1,&r));
    snprintf(slot.wan,sizeof(slot.wan),"wan2");
    json_object_array_add(rows, sample_json(&slot,"fixture-other-wan",rule,0,&r));
    json_object_object_add(rule,"method",json_object_new_string("icmp"));
    json_object_array_add(rows, sample_json(&slot,"fixture-icmp",rule,0,&r));
    puts(json_object_to_json_string_ext(rows,JSON_C_TO_STRING_PLAIN));
    json_object_put(rows); json_object_put(rule); return 0;
}
'''
    flags, libs = apd_test_deps.split_package_flags('json-c')
    with tempfile.TemporaryDirectory(prefix='client-observability-source-', dir='/tmp') as temp:
        c = Path(temp) / 'sample.c'
        binary = Path(temp) / 'sample'
        c.write_text(preamble + serializer + main)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT / 'jmxd/src'), *flags, str(c), *libs,
                        '-o', str(binary)], check=True, capture_output=True, text=True)
        return json.loads(subprocess.check_output([str(binary)], text=True))


if __name__ == '__main__':
    print(json.dumps(dns_rows(), ensure_ascii=False))
