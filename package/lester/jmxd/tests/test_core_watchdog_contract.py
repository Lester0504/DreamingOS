#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "src/main.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")
DW_API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WATCHDOG_C = (ROOT / "src/jmx_core_watchdog.c").read_text(encoding="utf-8")
WATCHDOG_H = (ROOT / "src/jmx_core_watchdog.h").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")


def body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.DOTALL)
    assert match, f"missing function {name}"
    start = source.index("{", match.start())
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(source)):
        c = source[i]
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:i+1]
    raise AssertionError(f"unterminated function {name}")


def test_core_status_exports_watchdog_loop_and_ubus_contract_fields():
    assert 'jmx_core_watchdog_append_status(data)' in MAIN
    assert 'jmx_core_watchdog_start();' in MAIN
    assert 'jmx_core_watchdog_stop();' in MAIN
    for field in (
        '"watchdog"', '"main_loop"', '"ubus_dispatch"',
        '"active_handler"', '"current_handler"', '"last_handler"',
        '"slowest_handler"', '"last_handler_duration_ms"',
        '"slowest_handler_duration_ms"', '"slow_handler_count"',
        '"loop_lag_ms"', '"loop_max_lag_ms"', '"loop_heartbeat_age_ms"',
        '"observer_only"', '"auto_restart"', '"thresholds"',
    ):
        assert field in WATCHDOG_C, field
    assert '#define JMX_CORE_WATCHDOG_CONTRACT_VERSION "1.0"' in WATCHDOG_H


def test_all_core_ubus_methods_use_a_shared_dispatcher():
    assert 'jmx_core_dispatch_jmx_method' in UBUS
    assert 'dw_core_dispatch_method' in DW_API
    assert 'jmx_object_install_dispatcher();' in UBUS
    assert 'dw_install_core_dispatcher();' in DW_API
    for source, dispatcher, object_name in (
        (UBUS, 'jmx_core_dispatch_jmx_method', '"jmx"'),
        (DW_API, 'dw_core_dispatch_method', '"dreamingwrt"'),
    ):
        b = body(source, dispatcher)
        assert 'jmx_core_ubus_dispatch_enter' in b
        assert object_name in b
        assert 'jmx_core_ubus_dispatch_leave' in b
        assert 'UBUS_STATUS_METHOD_NOT_FOUND' in b
        assert re.search(r'original_handlers\[i\].*\(ctx, obj, req, method, msg\)', b, re.DOTALL)


def test_legacy_common_dispatcher_refines_current_handler_to_nested_api():
    assert 'jmx_core_ubus_dispatch_update_current("jmx", tracked_method)' in UBUS
    assert '"common:%s"' in UBUS
    assert 'snprintf(tracked_method, sizeof(tracked_method)' in UBUS


def test_watchdog_recovery_is_sanctioned_abort_only_no_other_control_planes():
    observer = body(WATCHDOG_C, 'jmx_core_watchdog_thread')
    assert 'observer_iterations++' in observer
    assert 'last_observed_unhealthy' in observer
    # The only process action the observer thread may take is abort() for hard
    # recovery (the supervisor then respawns a fresh core). Everything else —
    # ubus, shell, sqlite, json-c, uloop, direct signals — stays forbidden here.
    forbidden = (
        'ubus_', 'system(', 'popen(', 'exec', 'sqlite3_', 'json_object_',
        'jmx_core_watchdog_start', 'kill', 'raise(', 'uloop_',
    )
    for token in forbidden:
        assert token not in observer, token
    # Hard recovery is default-on (env-tunable, 0 disables) and guarded by a
    # min-uptime grace so a slow first boot never trips a false restart.
    assert 'abort()' in observer
    assert 'hard_recover_ms' in observer
    assert 'JMX_CORE_HARD_RECOVER_MIN_UPTIME_MS' in observer
    assert 'auto_restart", json_object_new_boolean(hard_recover_ms > 0)' in WATCHDOG_C
    assert 'observer_only", json_object_new_boolean(hard_recover_ms <= 0)' in WATCHDOG_C


def test_fixed_thresholds_and_fixed_memory_are_explicit():
    for define in (
        'JMX_CORE_UBUS_SLOW_THRESHOLD_MS 1000LL',
        'JMX_CORE_UBUS_STUCK_THRESHOLD_MS 5000LL',
        'JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS 1000LL',
        'JMX_CORE_LOOP_STALL_THRESHOLD_MS 5000LL',
    ):
        assert define in WATCHDOG_H
    assert 'malloc(' not in WATCHDOG_C
    assert 'calloc(' not in WATCHDOG_C
    assert 'realloc(' not in WATCHDOG_C
    assert 'char active_method[JMX_WD_NAME_LEN]' in WATCHDOG_C
    assert 'pthread_mutex_t g_wd_lock' in WATCHDOG_C
    assert 'jmx_core_watchdog.o' in MAKEFILE


def test_response_health_fields_share_one_current_snapshot():
    append = body(WATCHDOG_C, 'jmx_core_watchdog_append_status')
    assert 'loop_stalled = heartbeat_age_ms < 0' in append
    assert 'handler_stuck = snap.ubus.active &&' in append
    assert 'jmx_wd_state_name(&snap, loop_stalled, handler_stuck)' in append
    assert 'json_object_new_boolean(loop_stalled)' in append
    assert 'json_object_new_boolean(handler_stuck)' in append
    assert 'json_object_new_boolean(snap.watchdog.loop_stalled)' not in append
    assert 'json_object_new_boolean(snap.watchdog.handler_stuck)' not in append


if __name__ == "__main__":
    test_core_status_exports_watchdog_loop_and_ubus_contract_fields()
    test_all_core_ubus_methods_use_a_shared_dispatcher()
    test_legacy_common_dispatcher_refines_current_handler_to_nested_api()
    test_watchdog_recovery_is_sanctioned_abort_only_no_other_control_planes()
    test_fixed_thresholds_and_fixed_memory_are_explicit()
    test_response_health_fields_share_one_current_snapshot()
    print("ok: core watchdog observer contract")
