#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
API = webd_dispatch_text()
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


for route, method in {
    "/api/v1/system/flash/signature-update/validate": "POST",
    "/api/v1/system/flash/signature-update/apply": "POST",
    "/api/v1/system/flash/signature-update/status": "GET",
}.items():
    assert route in API, route
    start = PERMS.index(route)
    assert method in PERMS[start:start + 180], route
    assert "JMX_RISK_HIGH" in PERMS[start:start + 180], route

assert 'app_nc_json_has(body, "path")' in API
assert 'strcmp(meta.upload_type, "signature")' in API
assert 'strcmp(meta.status, "finalized")' in API
assert "webd_upload_open_final_readonly(owner_id, upload_id" in API
assert "mkstemp(path)" in API
assert "fchmod(output_fd, 0600)" in API
assert "unlink(temp_path)" in API
assert 'app_ubus_invoke_timeout(!strcmp(action, "apply")' in API
assert '"signature_update_apply"' in API
assert '"signature_update_validate"' in API
assert '"signature_update_status"' in API
assert 'json_object_object_del(data, "path")' in API
assert '"signature_update_browser_upload"' in API

print("ok: owner-scoped signature upload BFF validates type/state/hash and hides core paths")
