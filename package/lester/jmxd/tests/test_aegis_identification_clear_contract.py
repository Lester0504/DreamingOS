#!/usr/bin/env python3
"""Static and executable contracts for Aegis identification and traffic clear."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
NETCONFIG = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
NETCONFIG_H = (ROOT / "src/jmx_netconfig_db.h").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
CORE_MAIN = (ROOT / "src/main.c").read_text(encoding="utf-8")
IDENTITYD = (ROOT / "src/identityd/identityd_main.c").read_text(encoding="utf-8")
AEGIS_STATUS = (ROOT / "src/aegisxd/aegisxd_status.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def test_config_db_authority_and_legacy_migration() -> None:
    assert "jmx_identification_mode_get" in NETCONFIG_H
    assert "jmx_identification_mode_set" in NETCONFIG_H
    assert "UPDATE firewall_global SET identify_mode=?1" in NETCONFIG
    assert "UPDATE network_control_global SET record_enabled=?1" in NETCONFIG
    assert "device_and_traffic" in NETCONFIG
    assert "traffic_only" in NETCONFIG
    assert "disabled" in NETCONFIG
    assert "WHERE identify_mode='' OR identify_mode='traffic'" in NETCONFIG


def test_runtime_apply_and_restart_replay() -> None:
    assert 'DW_JMX_RECORD_ENABLE_PATH "/proc/sys/dreamingwrt/jmx/record_enable"' in CORE
    assert "dw_write_proc_int_readback" in CORE
    assert "kernel_record_readback_failed_rolled_back" in CORE
    assert 'update_jmx_proc_u32_value("record_enable", traffic_record_enabled)' in CORE_MAIN
    assert 'IDENTITY_RUNTIME_STATE IDENTITY_RUNTIME_DIR "/identityd-state.json"' in IDENTITYD
    assert "identity_mode_reconcile" in IDENTITYD
    assert "jmx_identity_collector_close" in IDENTITYD
    assert "device_identification_active" in IDENTITYD


def test_status_capabilities_do_not_leave_frontend_false_disabled() -> None:
    for needle in (
        '"identification_mode_supported"',
        '"identification_runtime_readback"',
        '"traffic_history_clear_supported"',
        '"traffic_history_clear_confirm_required"',
        '"traffic_history_clear_owner_only"',
        '"identification"',
    ):
        assert needle in AEGIS_STATUS


def test_clear_contract_is_confirmed_and_has_readback() -> None:
    start = CORE.index("static int dw_handle_audit_clear_traffic")
    end = CORE.index("static int dw_handle_identification_get", start)
    body = CORE[start:end]
    assert 'dw_json_get_bool(in, "confirm", 0)' in body
    assert '"confirmation_required"' in body
    assert '"before"' in body
    assert '"after"' in body
    assert 'dw_audit_clear_db("traffic")' in body
    assert 'UBUS_METHOD("audit_clear_traffic"' in CORE


def test_authenticated_rest_and_owner_only_rbac() -> None:
    for path in (
        "/api/v1/aegis/identification",
        "/api/v1/aegis/traffic-history/clear",
    ):
        assert path in WEBD
        assert path in PERMS
    clear_line = next(line for line in PERMS.splitlines()
                      if '"/api/v1/aegis/traffic-history/clear"' in line)
    assert '"POST", JMX_RISK_HIGH' in clear_line
    set_line = next(line for line in PERMS.splitlines()
                    if '"/api/v1/aegis/identification"' in line and 'POST' in line)
    assert "JMX_RISK_MEDIUM" in set_line

    harness = r'''
#include <assert.h>
#include "jmx_app_perms.h"
int main(void) {
    assert(jmx_perm_route_risk("GET", "/api/v1/aegis/identification") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("PUT", "/api/v1/aegis/identification") == JMX_RISK_MEDIUM);
    assert(jmx_perm_route_risk("POST", "/api/v1/aegis/traffic-history/clear") == JMX_RISK_HIGH);
    assert(!jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_HIGH));
    assert(jmx_perm_check(JMX_ROLE_OWNER, JMX_RISK_HIGH));
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "aegis_identification_perms.c"
        binary = Path(td) / "aegis_identification_perms"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "src/webd"), str(source),
            str(ROOT / "src/webd/jmx_app_perms.c"), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Aegis identification/clear tests")
