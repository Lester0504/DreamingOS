#!/usr/bin/env python3
"""Resolve managed terminal roots without losing identity-change diagnostics."""
from pathlib import Path
import json
import sqlite3
import subprocess
import tempfile
from test_container_service_runtime import _definition, json_c_flags

ROOT = Path(__file__).resolve().parents[1]

def main():
    source = (ROOT / 'src/terminal_manager/lxc.inc').read_text()
    with tempfile.TemporaryDirectory(prefix='lxc-terminal-roots-') as directory:
        work = Path(directory)
        default, first, selected = [work / name for name in ['default', 'first', 'selected']]
        for root in [default, first, selected]:
            root.mkdir()
        for root in [first, selected]:
            (root / 'same-name').mkdir()
            (root / 'same-name/config').write_text('# fixture\n')
        dbpath = work / 'config.db'
        with sqlite3.connect(dbpath) as db:
            db.execute('CREATE TABLE lxc_roots (path TEXT)')
            db.executemany('INSERT INTO lxc_roots VALUES (?)', [(str(first),), (str(selected),)])
            db.execute('CREATE TABLE lxc_config_document (path TEXT, name TEXT)')
        identity = (selected / 'same-name').stat()
        code = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <json-c/json.h>
typedef struct json_object J;
#define TM_LXC_BIN_DIR "/unused"
static const char *tm_str(J *j,const char *key,const char *fallback){
    J *value=NULL;return json_object_object_get_ex(j,key,&value)?json_object_get_string(value):fallback;
}
'''
        code += '#define TM_LXC_CONFIG_DB ' + json.dumps(str(dbpath)) + '\n'
        code += 'static int lxc_probe(char *const argv[],char *out,size_t size){(void)argv;snprintf(out,size,"%s",' + json.dumps(str(default)) + ');return 0;}\n'
        code += '\n'.join(_definition(source, name) for name in ['lxc_identity_matches', 'lxc_resolve_root'])
        code += r'''
int main(int argc,char **argv){
    if(argc!=3)return 2;
    J *host=json_object_new_object();char root[4096];
    json_object_object_add(host,"container_id",json_object_new_string(argv[1]));
    json_object_object_add(host,"identity",json_object_new_string(argv[2]));
    if(lxc_resolve_root(root,sizeof(root),host))return 3;
    printf("%s\n%d\n",root,lxc_identity_matches(root,host));
    json_object_put(host);return 0;
}
'''
        (work / 'test.c').write_text(code)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', str(work / 'test.c'), *json_c_flags(), '-lsqlite3', '-o', str(work / 'test')], check=True)
        def result(name, token):
            return subprocess.check_output([str(work / 'test'), name, token], text=True).splitlines()
        assert result('same-name', f'{identity.st_dev}:{identity.st_ino}') == [str(selected), '1']
        assert result('same-name', '0:0') == [str(first), '0']
        assert result('missing-name', '0:0') == [str(default), '0']
        print('PASS exact identity wins across roots; known nondefault name preserves identity rejection; missing target remains missing')

if __name__ == '__main__':
    main()
