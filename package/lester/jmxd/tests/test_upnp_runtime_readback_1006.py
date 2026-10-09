"""Run production UPnP parser/apply rollback branches without changing a router."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/netconfig/010_nc_upnp.c"


def section(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def test_generated_config_and_apply_rollback():
    source = SRC.read_text()
    parser = section(source, "static int nc_upnp_config_matches(", "/* 0: generated config verified;")
    apply = section(source, "int jmx_upnp_service_apply(", "static struct json_object *nc_upnp_result(")
    fixture = (ROOT / "tests/upnp_runtime_readback_1006.c").read_text()
    with tempfile.TemporaryDirectory(prefix="upnp-readback-") as directory:
        path = Path(directory)
        (path / "runtime.inc").write_text(parser)
        (path / "apply.inc").write_text(apply)
        (path / "fixture.c").write_text(fixture)
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                        "-Wno-unused-parameter", "-I", str(path), str(path / "fixture.c"),
                        "-o", str(path / "fixture")], check=True)
        result = subprocess.run([str(path / "fixture"), str(path / "runtime.conf")],
                                text=True, capture_output=True, check=True)
        assert "PASS: generated config" in result.stdout


def test_import_and_snapshot_failure_contract():
    source = SRC.read_text()
    importer = section(source, "static int nc_upnp_import_uci_once(", "struct json_object *jmx_upnp_service_get(")
    for key in ("stun_port=?19", "clean_interval=?20", 'config, "enable_pcp_pmp", 0',
                'config, "clean_ruleset_interval", 0'):
        assert key in importer
    tx = section(source, "struct json_object *jmx_upnp_service_save_apply_result(",
                 "struct json_object *jmx_upnp_acl_save_apply_result(")
    assert tx.index("nc_upnp_restore_snapshot(before)") < tx.index("g_nc_upnp_readback_failed = 1")
    assert '"upnp_runtime_readback_mismatch"' in tx
    caps = section(source, "static void nc_upnp_add_caps(", "static int nc_upnp_parse_port_range(")
    for key in ("pcp", "stun", "stun_host", "stun_port", "clean_interval"):
        assert f'"{key}", json_object_new_boolean(runtime_ok)' in caps


def test_packaged_init_generates_readback_fields():
    relative = 'feeds/packages/net/miniupnpd/files/miniupnpd.init'
    init_path = next(base / relative for base in (ROOT.parent, ROOT.parents[2]) if (base / relative).exists())
    init = init_path.read_text()
    bool_writer = section(init, 'upnpd_write_bool() {', '\nupnpd() {')
    begin = init.index('\t\tupnpd_write_bool use_stun')
    end = init.index('\n\t\t[ -n "$upload" ]', begin)
    renderer = '''config_get_bool() {
    case "$3" in
      use_stun) val="$STUN";;
      enable_pcp_pmp) val="$PCP";;
      *) val=0;;
    esac
}
''' + bool_writer + '''
render() {
    local clean_interval="$CLEAN" use_stun="$STUN"
    local stun_host="stun.example.org" stun_port=3479
    local ipv6_disable=0 ext_allow_private_ipv4=0
''' + init[begin:end] + '\n}\nrender\n'
    parser = section(SRC.read_text(), 'static int nc_upnp_config_matches(', '/* 0: generated config verified;')
    with tempfile.TemporaryDirectory(prefix='upnp-init-') as directory:
        path = Path(directory)
        source = '#include <stdio.h>\n#include <string.h>\n#include <ctype.h>\n#include <stdlib.h>\n' + parser
        source += '\nint main(int n,char **v){if(n!=5)return 2;return nc_upnp_config_matches(v[1],atoi(v[2]),"stun.example.org",3479,atoi(v[3]),atoi(v[4]))==0?0:1;}\n'
        (path / 'parser.c').write_text(source)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(path / 'parser.c'), '-o', str(path / 'parser')], check=True)
        import os
        for stun, pcp, clean in [('1', '1', '60'), ('0', '0', '0')]:
            result = subprocess.run(['sh'], input=renderer, env=dict(os.environ, STUN=stun, PCP=pcp, CLEAN=clean), capture_output=True, text=True, check=True)
            (path / 'runtime.conf').write_text(result.stdout)
            subprocess.run([str(path / 'parser'), str(path / 'runtime.conf'), stun, pcp, clean], check=True)
        assert 'clean_ruleset_interval=0' in result.stdout
