#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
OTAD_UBUS = (ROOT / "src/otad/otad_ubus.c").read_text(encoding="utf-8")
OTAD_FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
UPLOAD = (ROOT / "src/webd/webd_upload_staging.c").read_text(encoding="utf-8")
UPLOAD_HEADER = (ROOT / "src/webd/webd_upload_staging.h").read_text(encoding="utf-8")
OTAD_INTERNAL = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


assert 'UBUS_METHOD("operation_status", otad_handle_operation_status' in OTAD_UBUS
status_handler = between(
    OTAD_UBUS,
    "static int otad_handle_operation_status",
    "static int otad_handle_rollback",
)
assert "otad_operation_status(otad_payload_or_self(body))" in status_handler
assert '(strcmp(eq, "1") && strcmp(eq, "2"))' in OTAD_FIRMWARE
assert "UPLOAD_MAX_FIRMWARE (8ULL * 1024ULL * 1024ULL * 1024ULL)" in UPLOAD
assert 'WEBD_UPLOAD_DEFAULT_ROOT "/data/persist/var/lib/dreamingwrt/upload-staging"' in UPLOAD_HEADER
assert "/tmp/dreamingwrt/upload-staging" not in UPLOAD_HEADER
assert 'OTAD_UPLOAD_STAGING_ROOT "/data/persist/var/lib/dreamingwrt/upload-staging"' in OTAD_INTERNAL
assert "production_data_mount_ready" in UPLOAD
assert 'root_st.st_dev != data_st.st_dev' in UPLOAD
assert '"data_mount_unavailable"' in UPLOAD

ownership = between(
    WEB,
    "static int webd_firmware_upload_owned",
    "static struct json_object *webd_firmware_operation_lookup",
)
assert "webd_upload_get(owner_id, upload_id" in ownership
assert 'strcmp(meta->upload_type, "firmware")' in ownership
assert 'strcmp(meta->status, "finalized")' in ownership
assert "webd_upload_open_final_readonly(owner_id, upload_id" in ownership

lookup = between(
    WEB,
    "static struct json_object *webd_firmware_operation_lookup",
    "static struct json_object *webd_firmware_verify_response",
)
assert '"dreamingwrt.otad", "operation_status"' in lookup
assert "webd_firmware_upload_owned(owner_id, upload_id" in lookup

verify = between(
    WEB,
    "static struct json_object *webd_firmware_verify_response",
    "static struct json_object *webd_firmware_apply_response",
)
assert "webd_firmware_body_forbidden(body)" in verify
assert "webd_firmware_upload_owned(owner_id, upload_id" in verify
assert '"dreamingwrt.otad", "verify"' in verify

apply = between(
    WEB,
    "static struct json_object *webd_firmware_apply_response",
    "static struct json_object *webd_firmware_status_response",
)
assert 'app_nc_json_has(body, "upload_id")' in apply
assert "webd_firmware_operation_lookup(owner_id, operation_id" in apply
assert '"dreamingwrt.otad", "apply"' in apply

dispatch = between(
    WEB,
    'else if (!strcmp(req.path, "/api/v1/system/flash/signature-update/status")',
    "/* ── Flash: factory reset ── */",
)
for path in (
    "/api/v1/system/flash/firmware/verify",
    "/api/v1/system/flash/firmware/apply",
    "/api/v1/system/flash/firmware/status",
    "/api/v1/system/flash/upload_firmware",
    "/api/v1/system/flash/sysupgrade",
):
    assert path in dispatch
assert "/api/v1/system/ota/verify" in WEB
assert "/api/v1/system/ota/apply" in WEB
assert 'app_ubus_invoke("system_flash_upload_firmware"' not in dispatch
assert 'app_ubus_invoke("system_flash_sysupgrade"' not in dispatch
assert 'app_nc_json_str(resp, "state"' in dispatch
assert 'resp = webd_firmware_verify_response(device_id, body_json, &status);' in WEB
assert 'resp = webd_firmware_apply_response(device_id, body_json, &status);' in WEB

csrf = between(
    WEB,
    "if ((!strncmp(req.path, \"/api/v1/uploads\"",
    "const char *required_permission",
)
assert '"/api/v1/system/flash/firmware"' in csrf
assert '"/api/v1/system/flash/upload_firmware"' in csrf
assert '"/api/v1/system/flash/sysupgrade"' in csrf
assert '"/api/v1/system/ota"' in csrf

assert '{ "/api/v1/system/flash/firmware",           "", JMX_RISK_HIGH }' in PERMS
assert '{ "/api/v1/system/flash/upload_firmware",   "POST,PUT", JMX_RISK_HIGH }' in PERMS
assert '{ "/api/v1/system/flash/upload_firmware",   "POST,PUT", JMX_RISK_MEDIUM }' not in PERMS
assert '{ "/api/v1/system/ota/verify",             "POST", JMX_RISK_HIGH }' in PERMS

capabilities = between(
    WEB,
    "static struct json_object *webd_capabilities_data(void)",
    "static struct json_object *webd_setup_data_fast",
)
assert '"dreamingwrt.otad", "status"' in capabilities
for capability in (
    "flash_browser_upload",
    "flash_firmware_validate",
    "flash_operation_status",
    "flash_sysupgrade",
    "flash_ab_update",
):
    assert capability in capabilities
assert "json_object_new_boolean(ab_available)" in capabilities

print("ok: firmware Web API is owner-scoped, path-free, CSRF guarded, and routed through otad")
