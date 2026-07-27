#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "webd" / "jmx_app_api.c"
PERMS = ROOT / "webd" / "jmx_app_perms.c"
MAKEFILE = ROOT / "Makefile"


def main() -> None:
    api = API.read_text(encoding="utf-8")
    perms = PERMS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    for route, method in {
        "/api/v1/uploads/begin": "POST",
        "/api/v1/system/flash/backups": "POST",
        "/api/v1/system/flash/restore_backup": "POST",
        "/api/v1/system/flash/restore-status": "GET",
        "/api/v1/system/flash/restore-confirm": "POST",
        "/api/v1/system/flash/restore-rollback": "POST",
    }.items():
        assert route in api, route
        occurrences = [
            api[pos:pos + 1000]
            for pos in range(len(api))
            if api.startswith(route, pos)
        ]
        assert any(method in occurrence for occurrence in occurrences), (route, method)

    assert 'webd_config_backup_route_id(req.path, "/download"' in api
    assert 'app_nc_json_has(body, "path")' in api
    assert 'webd_config_restore_control_response("arm"' in api
    assert '"next_dreamingwrt_init_start"' in api
    assert '"dreamingwrt-init config-restore apply --force"' in api
    assert '"?mode=ro&immutable=1"' in api
    assert 'flock(lockfd, LOCK_EX)' in api

    for route in (
        "/api/v1/uploads",
        "/api/v1/system/flash/backups",
        "/api/v1/system/flash/restore_backup",
        "/api/v1/system/flash/restore-status",
        "/api/v1/system/flash/restore-confirm",
        "/api/v1/system/flash/restore-rollback",
    ):
        start = perms.index(route)
        assert "JMX_RISK_HIGH" in perms[start:start + 180], route

    assert "webd/webd_upload_staging.o" in makefile
    assert "webd/webd_init_control.o" in makefile
    print("config_backup_http_routes_contract: PASS")


if __name__ == "__main__":
    main()
