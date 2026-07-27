#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def test_profile_delete_rejects_dependencies_and_protects_builtins() -> None:
    start = DB.index("jmx_netconfig_physical_port_profile_delete")
    end = DB.index("static void nc_json_copy_key", start)
    section = DB[start:end]

    assert '"BEGIN IMMEDIATE"' in section
    assert 'FROM physical_port_config WHERE profile_id=?1' in section
    assert '"profile_in_use"' in section
    assert '"reference_count"' in section
    assert '!strcmp(id, "default-lan")' in section
    assert '!strcmp(id, "all")' in section
    assert '"COMMIT"' in section
    assert '"ROLLBACK"' in section


def test_profile_path_id_cannot_be_overridden_by_body() -> None:
    assert '"port_profile_id_conflict"' in WEBD
    assert "port profile path id and body id must match" in WEBD
    assert '"profile_in_use"' in WEBD
    assert '"invalid_or_protected_profile_id"' in WEBD
    assert 'app_nc_json_bool(response_data, "protected", 0)' in WEBD
    assert '*http_status = 409' in WEBD


def test_topology_ports_share_infrastructure_stale_cache() -> None:
    start = WEBD.index("static struct json_object *webd_topology_node_ports_response(")
    end = WEBD.index("static int webd_capture_mkdir", start)
    section = WEBD[start:end]

    assert 'webd_topology_infrastructure_cached_response(http_status)' in section
    assert '"stale"' in section
    assert '"degraded"' in section
    assert '"source_error"' in section
    assert '"configured_display_name"' in section
    assert '"configured_sort_order"' in section
    assert '"display_metadata_source"' in section
    assert '"ifname_fallback"' in section
    assert 'app_ubus_invoke_timeout("topology_infrastructure", NULL, 2000)' not in section

    shared_start = WEBD.index(
        "static struct json_object *webd_topology_infrastructure_cached_response(")
    shared_end = WEBD.index("static struct json_object *webd_dashboard_live_response(",
                            shared_start)
    shared = WEBD[shared_start:shared_end]
    assert "WEBD_TOPOLOGY_INFRA_CACHE_PATH" in WEBD
    assert "WEBD_TOPOLOGY_INFRA_LOCK_PATH" in WEBD
    assert "flock(lock_fd, LOCK_EX)" in shared
    assert "lock_held" in shared
    assert "webd_topology_infrastructure_shared_cache_read" in shared
    assert "webd_topology_infrastructure_shared_cache_write" in shared
    assert "WEBD_TOPOLOGY_TTL_SEC" in shared
    assert "WEBD_TOPOLOGY_STALE_SEC" in shared
    assert "WEBD_TOPOLOGY_TIMEOUT_MS" in shared
    assert '"topology_infrastructure_timeout_stale_cache"' in shared
    assert '"topology_infrastructure_invalid_response_stale_cache"' in shared
    assert 'data ? 502 : 503' in shared
    assert "webd_topology_infrastructure_cache_invalidate" in WEBD
    assert "unlink(WEBD_TOPOLOGY_INFRA_CACHE_PATH)" in WEBD


if __name__ == "__main__":
    test_profile_delete_rejects_dependencies_and_protects_builtins()
    test_profile_path_id_cannot_be_overridden_by_body()
    test_topology_ports_share_infrastructure_stale_cache()
    print("ok: port profile integrity and topology port cache contracts")
