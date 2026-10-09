#!/usr/bin/env python3
"""Contract checks for the per-device relay link switch.

The cloud daemon already consumes ``app_devices.relay_access``.  These checks
keep webd's migration, read surface, strict input contract, and atomic write
path together so a later merge cannot ship only one half of the switch.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
WEB = webd_dispatch_text()


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


db_init = between(WEB, "static int app_db_init", "static sqlite3_stmt *app_prepare")
assert "relay_access INTEGER NOT NULL DEFAULT 1" in db_init
assert 'app_db_add_column_if_missing(\n            "app_devices", "relay_access"' in db_init

devices = between(WEB, "struct json_object *jmx_app_devices_list",
                  "static struct json_object *jmx_app_pair_status")
assert "relay_access " in devices
assert 'json_object_object_add(o, "relay_access"' in devices

patch = between(WEB, "static int jmx_app_device_patch_atomic",
                "static int jmx_app_device_delete_atomic")
assert "has_relay_access" in patch
assert "SELECT role,enabled,relay_access FROM app_devices" in patch
assert "BEGIN IMMEDIATE" in patch
assert "UPDATE app_devices SET role=?1,enabled=?2,relay_access=?3 WHERE id=?4" in patch
assert "COMMIT" in patch and "ROLLBACK" in patch

route = between(WEB, "/* ── Devices ── */", "/* ── Delete device ── */")
assert '"relay_access_write", json_object_new_boolean(1)' in route
assert '"remote_access_compat_input", json_object_new_boolean(1)' in route
assert 'json_object_object_get_ex(body_json, "relay_access"' in route
assert 'json_object_object_get_ex(body_json, "remote_access"' in route
assert "relay_access conflicts with remote_access" in route
assert "relay_access and remote_access must be boolean" in route
assert "relay_access_changed" in route

print("ok: relay_access schema, readback, strict alias handling and atomic PATCH are wired")
