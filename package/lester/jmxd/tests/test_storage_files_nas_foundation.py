#!/usr/bin/env python3
"""NAS prerequisite regressions: actual filesystem operations; optional ASan."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_storage_files_runtime import json_c_flags

SOURCE = Path(__file__).resolve().parents[1] / 'src/storage/storage_files.c'
HARNESS = r'''
#include "storage/storage_files.c"
struct json_object *jmx_gen_api_response_data(int code, struct json_object *data) {
    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "code", json_object_new_int(code));
    json_object_object_add(out, "data", data);
    return out;
}
int main(int argc, char **argv) {
    struct json_object *r = NULL;
    const char *op = argc > 1 ? argv[1] : "";
    if (!strcmp(op, "list")) r = jmx_storage_files_list("", "/", "");
    else if (!strcmp(op, "init")) r = jmx_storage_files_upload_init(argv[2], argv[3], argv[4], argv[8], atoll(argv[6]), atoi(argv[5]), atoi(argv[7]));
    else if (!strcmp(op, "chunk")) r = jmx_storage_files_upload_chunk(argv[2], argv[3], atoi(argv[4]), (const unsigned char *)argv[5], strlen(argv[5]));
    else if (!strcmp(op, "complete")) r = jmx_storage_files_upload_complete(argv[2], argv[3]);
    else if (!strcmp(op, "cancel")) r = jmx_storage_files_upload_cancel(argv[2], argv[3]);
    else if (!strcmp(op, "mutate")) { struct json_object *p = json_tokener_parse(argv[2]); r = jmx_storage_files_mutate(p); json_object_put(p); }
    else if (!strcmp(op, "normalize")) {
        struct storage_file_root root = {.path="/"};
        char rel[PATH_MAX], disp[PATH_MAX]; const char *why = "";
        if (storage_files_relative_path(&root, argv[2], rel, sizeof(rel), disp, sizeof(disp))) return 3;
        r = json_object_new_object();
        json_object_object_add(r,"display",json_object_new_string(disp));
        json_object_object_add(r,"denied",json_object_new_boolean(storage_files_content_denied(disp, "example.txt", &why)));
    }
    if (!r) return 2;
    puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN)); json_object_put(r); return 0;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='nas-foundation-') as directory:
        base = Path(directory)
        disk = base / 'disk'; disk.mkdir()
        protected = disk / 'folder'; protected.mkdir()
        (protected/'note.txt').write_text('ordinary')
        # Fictional, non-sensitive fixture with a protected suffix.
        (protected/'example.key').write_text('not a credential')
        (disk/'dest').mkdir()
        (disk/'image.jpg').write_bytes(b'\xff\xd8\xff\xe0\x00')
        mountinfo = base/'mountinfo'
        dev = disk.stat().st_dev
        mountinfo.write_text(f'91 1 {os.major(dev)}:{os.minor(dev)} / {disk} rw - ext4 /dev/test rw\n')
        harness = base/'fixture.c'; harness.write_text(HARNESS)
        binary = base/'fixture'
        incs, libs = json_c_flags()
        flags = ['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if os.getenv('SANITIZE') == '1' else []
        subprocess.run([os.getenv('CC','cc'), '-std=gnu11','-Wall','-Wextra','-Werror',*flags,
            '-DSTORAGE_FILES_TEST_ALLOW_PROTECTED_DEVICE=1', '-DSTORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT=1',
            f'-DSTORAGE_FILES_MOUNTINFO="{mountinfo}"', '-I',str(SOURCE.parents[1]),*incs,str(harness),*libs,'-o',str(binary)],check=True)
        checks = 0
        def run(*args):
            nonlocal checks
            p = subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,check=True)
            assert 'Sanitizer' not in p.stderr, p.stderr
            checks += 1
            v=json.loads(p.stdout); return v.get('data',v)
        listing=run('list'); rid=listing['root_id']
        entries={e['name']:e for e in listing['entries']}
        assert listing['capabilities']['upload'] and listing['limits']['max_edit_bytes']==262144
        assert entries['image.jpg']['capabilities']['preview'] and entries['image.jpg']['capabilities']['download']
        assert run('normalize','//etc///config//example.txt') == {'display':'/etc/config/example.txt','denied':True}
        def init(name='result.txt',size=6,count=2,overwrite=0): return run('init',rid,disk,name,count,size,overwrite,'test-upload')
        assert not init()['resumed']
        assert run('chunk',rid,'test-upload',0,'abc')['received']
        assert init()['uploaded_chunks']==[0]
        for kwargs in ({'name':'other.txt'},{'size':7},{'count':3},{'overwrite':1}):
            assert init(**kwargs)['error']=='upload_metadata_conflict'
        assert run('chunk',rid,'test-upload',2,'x')['error']=='invalid_chunk'
        assert run('complete',rid,'test-upload')['error']=='upload_incomplete'
        assert run('chunk',rid,'test-upload',1,'de')['received']
        assert run('complete',rid,'test-upload')['error']=='upload_size_mismatch'
        assert not (disk/'result.txt').exists()
        run('chunk',rid,'test-upload',1,'def')
        done=run('complete',rid,'test-upload')
        assert done['stored'] and done['path']==str(disk/'result.txt') and done['size_bytes']==6
        assert (disk/'result.txt').read_text()=='abcdef'
        assert not done['cleanup_pending'] and not (disk/'.dwrt-upload/test-upload').exists()
        assert run('cancel',rid,'test-upload')['cancelled']
        init(); run('chunk',rid,'test-upload',0,'abc'); run('chunk',rid,'test-upload',1,'def')
        assert run('complete',rid,'test-upload')['error']=='file_exists'
        assert (disk/'result.txt').read_text()=='abcdef'
        # Cleanup failure must be visible. A non-regular protected fixture in staging.
        (disk/'.dwrt-upload/test-upload/example.key').write_text('fixture')
        assert run('cancel',rid,'test-upload')['error']=='upload_cleanup_failed'
        (disk/'.dwrt-upload/test-upload/example.key').unlink()
        assert run('cancel',rid,'test-upload')['cancelled']
        for action in ['copy','move','delete']:
            payload={'root_id':rid,'path':str(protected),'source':str(protected),'target':str(disk/'dest'),'action':action,'confirm':True}
            result=run('mutate',json.dumps(payload)); assert result['failed']==1,result
            assert (protected/'note.txt').read_text()=='ordinary'
            assert (protected/'example.key').exists()
            assert not (disk/'dest/folder').exists()
        (disk/'plain').mkdir();(disk/'plain/note.txt').write_text('safe')
        result=run('mutate',json.dumps({'root_id':rid,'path':str(disk/'plain'),'action':'rename','new_name':'renamed','confirm':True}))
        assert result['persisted'] and (disk/'renamed/note.txt').read_text()=='safe'
        print(f'PASS: {checks} filesystem calls; upload identity/size/lifetime/cleanup, capabilities, canonical protection, recursive protection, directory rename')

if __name__=='__main__': main()
