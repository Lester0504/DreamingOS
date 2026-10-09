#!/usr/bin/env python3
"""Exercise the shared device release reader against canonical and legacy files."""
from pathlib import Path
import json, subprocess, tempfile
from otad_test_deps import find_host_dependencies
ROOT = Path(__file__).resolve().parents[1]
deps = find_host_dependencies(ROOT, require_crypto_library=False)
with tempfile.TemporaryDirectory(prefix="canonical-release-") as td:
    td=Path(td); primary=td/"dreamingos-release.json"; legacy=td/"dreamingwrt-release.json"
    src=td/"test.c"; binary=td/"test"
    src.write_text(r'''#include "jmx_release.h"
int main(int argc, char **argv) {
 const char *source=NULL; char display[256];
 struct json_object *r=dw_release_read_paths(argv[1],argv[2],&source);
 dw_release_display(r,display,sizeof(display));
 printf("%s\n%s\n%s\n", source,dw_release_version(r),display);
 if(r) json_object_put(r); return 0;
}''')
    subprocess.run(["cc","-Wall","-I",str(ROOT/"src"),"-I",str(deps.json_include),str(src),str(deps.json_library),"-o",str(binary)],check=True)
    def read(): return subprocess.check_output([str(binary),str(primary),str(legacy)],text=True).splitlines()
    legacy.write_text(json.dumps({"dreamingwrt_version":"2026.09.30","build_id":"Build202609301748"}))
    assert read()[1:]==["2026.09.30","2026.09.30"]
    canonical={"product":"DreamingOS","version":"1.0.0","dreamingwrt_version":"stale-alias","model":"BPI-R4","build_id":"Build202610051800"}
    primary.write_text(json.dumps(canonical))
    assert read()==[str(primary),"1.0.0","DreamingOS_BPI-R4_1.0.0_Build202610051800"]
    primary.write_text("invalid")
    assert read()==[str(primary),"",""]
    primary.write_text(json.dumps({"version":"1.0.1"}))
    assert read()[1:]==["1.0.1","1.0.1"]  # Unknown model is never fabricated.
print("ok: canonical priority, legacy transition, invalid canonical, model truth")
