from pathlib import Path
import shlex
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]

def test_vm_real_reference_shapes():
    source=(ROOT/'src/vm/vm_libvirt.c').read_text()
    start=source.index('static int vm_xml_attribute(')
    end=source.index('/* Case-sensitive substring;',start)
    with tempfile.TemporaryDirectory(prefix='vm-references-') as directory:
        path=Path(directory)
        (path/'lists.inc').write_text(source[start:end])
        flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','json-c'],text=True))
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I',str(path),
                        str(ROOT/'tests/vm_reference_lists_1006.c'),*flags,'-o',str(path/'fixture')],check=True)
        result=subprocess.run([str(path/'fixture')],capture_output=True,text=True,check=True)
        assert 'PASS: VM' in result.stdout

def test_vm_gateway_and_ubus_readonly():
    source=(ROOT/'src/webd/api/api_vm.c').read_text()
    ubus=(ROOT/'src/vm/vm_ubus.c').read_text()
    for noun in ('pool','network'):
        assert f'"/api/v1/vm/{noun}s", "GET", JMX_API_EXACT' in source
        assert f'vm_gw_call(ctx, "{noun}_list", vm_query_params(ctx->req->query))' in source
        assert f'UBUS_METHOD("{noun}_list", vm_m_{noun}_list, vm_req_policy)' in ubus
        assert f'vm_{noun}_list_json(vm_j_int(rq, "page", 1)' in ubus
