"""Run real logd SQLite storage/queue code, without touching production paths."""
from pathlib import Path
import os
import shlex
import subprocess
import sys
import pytest
from apd_test_deps import package_flags

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture(scope='module')
def runtime(tmp_path_factory):
    out = tmp_path_factory.mktemp('ap-log-runtime')
    role = out / 'role'
    target = ROOT.parents[2] / 'staging_dir/target-x86_64_glibc/usr/include'
    includes = [f'-I{target}'] if target.exists() else []
    # The headers describe unused ubus members; the linker drops those functions.
    if not includes:
        prefix = os.environ.get('APD_TEST_UBUS_PREFIX', '/tmp/dwrt-test-deps')
        includes = [f'-I{prefix}/include']
    command = ['cc','-std=gnu11','-D_GNU_SOURCE','-O1','-ffunction-sections','-fdata-sections',
               '-Wall','-Wextra','-Wno-unused-parameter',f'-DLOGD_ROLE_PATH="{role}"',
               f'-I{ROOT / "src"}',*includes,
               str(ROOT / 'tests/ap_log_runtime_fixture.c'),
               str(ROOT / 'src/logd/logd_db.c'),str(ROOT / 'src/logd/logd_common.c'),
               str(ROOT / 'src/jmx_storage_guard.c'),
               '-Wl,--gc-sections',*package_flags('json-c','sqlite3','openssl'),
               '-o',str(out/'fixture')]
    built = subprocess.run(command,capture_output=True,text=True)
    assert built.returncode == 0, built.stderr[-8000:]
    return out,role

@pytest.mark.parametrize('mode',['ap','gateway'])
def test_actual_log_storage(runtime,mode):
    out,role=runtime
    role.write_text(mode+'\n')
    result=subprocess.run([str(out/'fixture'),mode,str(out/(mode+'.db'))],capture_output=True,text=True)
    assert result.returncode == 0,(result.stdout,result.stderr)
    assert 'ok' in result.stdout
