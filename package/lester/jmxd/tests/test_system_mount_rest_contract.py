#!/usr/bin/env python3
"""Static REST/ubus wiring checks for transactional mount point operations."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src" / "jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
DB = (ROOT / "src" / "jmx_netconfig_db.c").read_text(encoding="utf-8")
WEB = (ROOT / "src" / "webd" / "jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src" / "webd" / "jmx_app_perms.c").read_text(encoding="utf-8")


def main() -> None:
    for method in (
        "system_mount_save_point",
        "system_mount_delete_point",
        "system_mount_unmount",
        "system_mount_discover",
        "system_mount_generate_config",
        "system_mount_connected",
    ):
        assert f'UBUS_METHOD("{method}"' in CORE
        assert f'"{method}"' in WEB
    for path in ("save-point", "delete-point", "unmount", "discovery",
                 "generate-config", "mount-connected"):
        assert f'/api/v1/system/mounts/{path}' in WEB
        assert f'/api/v1/system/mounts/{path}' in PERMS
    assert "status = app_jmx_response_http_status(resp, 200);" in WEB
    assert '"mounts_save_point",json_object_new_boolean(1)' in DB
    assert '"mounts_delete_point",json_object_new_boolean(1)' in DB
    assert '"mounts_unmount",json_object_new_boolean(1)' in DB
    assert '"mounts_generate_config",json_object_new_boolean(gen)' in DB
    assert '"mounts_mount_connected",json_object_new_boolean(mnt)' in DB
    assert '"implicit_mount",json_object_new_boolean(0)' in DB
    assert '"stable_id_required",json_object_new_boolean(1)' in DB
    assert '"system_mount_generate_config"' in WEB
    assert '"system_mount_connected"' in WEB
    assert '"system_mount_discover"' in WEB
    assert '"explicit-stable-source-candidates"' in WEB
    assert '"candidate_field_too_long"' in (ROOT / "src" / "jmx_system.c").read_text(encoding="utf-8")
    assert "df -P" not in DB
    assert "jmx_system_mounts_read_json()" in DB
    assert '"mounted_filesystems"' in (ROOT / "src" / "jmx_system.c").read_text(encoding="utf-8")
    assert '"configured_points"' in (ROOT / "src" / "jmx_system.c").read_text(encoding="utf-8")
    assert '"mounts_runtime_split",json_object_new_boolean(1)' in DB
    assert '"mounts_fstype",json_object_new_boolean(1)' in DB
    for path in ("discovery", "generate-config", "mount-connected"):
        route = f'{{ "/api/v1/system/mounts/{path}"'
        assert route in PERMS and "JMX_RISK_HIGH" in PERMS[PERMS.index(route):PERMS.index(route)+120]
    print("system_mount_rest_contract: PASS")


if __name__ == "__main__":
    main()
