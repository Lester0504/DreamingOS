#!/usr/bin/env python3
"""System-settings writes stay admin-writable while owner-only fields remain gated."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
WEB = webd_dispatch_text()


def test_system_settings_routes_are_admin_writable():
    for route in ("/api/v1/save_system_settings", "/api/v1/system/settings"):
        row = next(line for line in PERMS.splitlines() if '"%s"' % route in line)
        assert '"POST,PUT,PATCH"' in row and "JMX_RISK_MEDIUM" in row, route
        assert "JMX_RISK_HIGH" not in row, route


def test_permission_gate_still_distinguishes_owner_only_actions():
    assert "if (risk == JMX_RISK_HIGH)\n        return (role == JMX_ROLE_OWNER) ? 1 : 0;" in PERMS
    assert "if (risk == JMX_RISK_MEDIUM)\n        return (role == JMX_ROLE_ADMIN || role == JMX_ROLE_OWNER) ? 1 : 0;" in PERMS


def test_owner_only_admin_fields_keep_their_preflight():
    save_start = WEB.index("static struct json_object *webd_system_settings_save_response")
    save_end = WEB.index("static struct json_object *webd_system_health_history_response", save_start)
    save = WEB[save_start:save_end]
    assert "webd_system_settings_admin_preflight(body, current_username, status)" in save
    assert '"owner_web_session_required"' in WEB
    assert "role != JMX_ROLE_OWNER" in WEB
    assert "webd_system_settings_admin_targets_current(" in WEB

    preflight_start = WEB.index("static struct json_object *webd_system_settings_admin_preflight")
    preflight_end = WEB.index("static struct json_object *webd_system_settings_save_response", preflight_start)
    preflight = WEB[preflight_start:preflight_end]
    assert "webd_system_settings_has_admin_write(body)" in preflight
    assert "password_len < 8 || password_len > 256" in preflight
    assert '"conflicting_avatar_sources"' in preflight


if __name__ == "__main__":
    test_system_settings_routes_are_admin_writable()
    test_permission_gate_still_distinguishes_owner_only_actions()
    test_owner_only_admin_fields_keep_their_preflight()
    print("ok: system-settings bulk saves are admin-writable; admin credential writes remain owner-only")
