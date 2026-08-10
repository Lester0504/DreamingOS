#!/usr/bin/env python3
"""Static and executable contract for the system-power data module."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/system/power.c"
HEADER = ROOT / "src/system/power.h"
MAKEFILE = ROOT / "src/Makefile"
CORE_API = ROOT / "src/jmx_dreamingwrt_api.c"
WEBD_API = ROOT / "src/webd/jmx_app_api.c"
WEBD_PERMS = ROOT / "src/webd/jmx_app_perms.c"
MAINTENANCED = ROOT / "src/maintenanced/maintenanced_main.c"


def read(path: Path) -> str:
    assert path.is_file(), f"missing production source: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


C = read(SOURCE)
H = read(HEADER)
WIRING = "\n".join(read(path) for path in (
    MAKEFILE, CORE_API, WEBD_API, WEBD_PERMS, MAINTENANCED,
))


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def test_public_abi_and_envelopes() -> None:
    require_all(H, (
        "jmx_system_power_get(void)",
        "jmx_system_power_schedule_upsert(",
        "jmx_system_power_schedule_delete(",
        "jmx_system_power_scheduler_tick(",
        "jmx_system_power_immediate_action(",
        'JMX_SYSTEM_POWER_CONTRACT_VERSION "system-power.v1"',
    ), "public ABI")
    require_all(C, (
        "#define POWER_API_OK 2000", "#define POWER_API_ERROR 4000",
        '"contract_version"', '"ok"', '"error"', '"reason"',
    ), "stable envelope")
    assert not re.search(r"#define\s+POWER_API_\w+\s+(4090|4290|5000)\b", C)


def test_persistent_schema_and_optimistic_revision() -> None:
    require_all(C, (
        "CREATE TABLE IF NOT EXISTS power_schedule_meta",
        "CREATE TABLE IF NOT EXISTS power_schedule(",
        "CREATE TABLE IF NOT EXISTS power_schedule_history",
        "BEGIN IMMEDIATE", "revision=?13", "revision=?2",
        '"schedule_conflict"', '"revision_required"',
    ), "persistent schedules")
    require_all(C, (
        "WHERE id=1 AND (schema_version<>?1 OR contract_version<>?2)",
        "power_schema_is_current",
        "(!power_schema_is_current(db) && power_schema_create(db) != 0)",
    ), "idempotent schema metadata")


def test_time_rules_and_month_end_are_explicit() -> None:
    require_all(C, (
        '"once"', '"daily"', '"weekly"', '"monthly"',
        "power_local_candidate", "tm_isdst = -1", "power_days_in_month",
        "Do not clamp 29/30/31 to month end", "power_next_run",
        '"invalid_time"', '"invalid_weekdays"', '"invalid_month_day"',
    ), "local calendar scheduler")


def test_executor_and_cross_process_lock_are_bounded() -> None:
    require_all(C, (
        "pending_action_id", "pending_owner", "pending_expires_at",
        "last_action_at", "POWER_ACTION_RATE_LIMIT_SECONDS 30",
        '"immediate_action_pending"', '"rate_limited"',
        "power_action_lock_acquire", "power_action_lock_finish",
        "pipe2(handshake, O_CLOEXEC)", "dispatcher = fork()",
        "socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, release_gate)",
        "detached = fork()", "setsid()", "execv(argv[0], argv)",
        "sleep(POWER_DISPATCH_DELAY_SECONDS)",
        "POWER_DISPATCH_DELAY_SECONDS 2", "waitpid(dispatcher",
        "power_detached_exec_failure", "power_exec_release", "power_exec_cancel",
        "MSG_NOSIGNAL",
        '"dispatched"', '"accepted"',
    ), "guarded action executor")
    assert "system(" not in C, "power module must never invoke a shell"
    assert "popen(" not in C, "power module must never invoke a shell"
    assert re.search(r'char \*reboot_argv\[\].*JMX_SYSTEM_POWER_REBOOT_PATH', C)
    assert re.search(r'char \*shutdown_argv\[\].*JMX_SYSTEM_POWER_SHUTDOWN_PATH', C)


def test_rest_cannot_turn_a_production_action_into_dry_run() -> None:
    require_all(C, (
        "JMX_SYSTEM_POWER_TESTING", "JMX_SYSTEM_POWER_HARNESS",
        '"execute_override_forbidden"',
        '"production_requests_cannot_disable_power_execution"',
    ), "dry-run trust boundary")
    request_mode = C.split("static int power_request_execute_mode", 1)[1].split(
        "static int power_exec_fixed", 1
    )[0]
    assert "present && !value && !power_harness_mode()" in request_mode


def test_core_webd_and_maintenance_wiring() -> None:
    require_all(WIRING, (
        "OBJS += system/power.o",
        '#include "system/power.h"',
        'UBUS_METHOD("system_power_get"',
        'UBUS_METHOD("system_power_schedule_upsert"',
        'UBUS_METHOD("system_power_schedule_delete"',
        'UBUS_METHOD("system_power_action"',
        '"/api/v1/system/power"',
        '"/api/v1/system/power/schedules"',
        '"/api/v1/system/reboot"',
        '"/api/v1/system/shutdown"',
        '"system_power_read"',
        "webd_cookie_write_csrf_ok(&req)",
        "JMX_RISK_HIGH",
        '"schedule_not_found"',
        '"schedule_conflict"',
        '"schedule_pending"',
        '"immediate_action_pending"',
        '"rate_limited"',
        '"storage_unavailable"',
        "jmx_app_audit_log_ex",
        '"source_ip"',
        '"failure_reason"',
        '"source_ip,result,failure_reason) "',
        "MAINTENANCED_POWER_TICKS 5",
        'blobmsg_add_u32(&maintenance_blob, "power_schedule"',
    ), "core/webd/maintenanced wiring")
    # Exactly one risk-table row, in webd/jmx_app_perms.c.  This asserted 2
    # while src/jmx_app_perms.c held a second, independent copy of the table;
    # that copy was collapsed into a forwarding header (see
    # src/jmx_app_perms.h) precisely so a second definition cannot drift, so
    # a count of 2 would now mean the duplicate came back.
    assert WIRING.count(
        '{ "/api/v1/system/shutdown",  "POST", JMX_RISK_HIGH }'
    ) == 1
    assert 'json_object_object_add(params, "execute", json_object_new_boolean(1))' in WIRING


def test_tick_claims_and_archives_or_advances() -> None:
    tick = C.split("jmx_system_power_scheduler_tick", 1)[1]
    require_all(tick, (
        "power_scheduler_preview", "power_action_lock_acquire",
        "power_scheduler_has_work",
        "Advance or archive before dispatch", "next_run_at=?2",
        "claim_token='',claim_until=0", "archived_at=?4",
        "power_next_run", "power_meta_bump", "power_exec_fixed(schedule.event, action_id",
        "power_action_mark_dispatched",
    ), "scheduler tick")
    assert tick.index("power_sql_exec(db, \"COMMIT\")") < tick.index(
        "power_exec_fixed(schedule.event, action_id"
    ), "schedule must advance and commit before detached dispatch"
    no_due = tick.split("if (rc == SQLITE_DONE)", 1)[1].split(
        "if (rc != SQLITE_ROW", 1
    )[0]
    assert "UPDATE power_schedule_meta" not in no_due
    assert "last_tick_at" not in no_due
    assert '"success"' not in tick
    assert "UPDATE power_schedule SET last_result='dispatched'" in C


def pkg_config_flags() -> list[str]:
    explicit = os.environ.get("SYSTEM_POWER_TEST_FLAGS", "").strip()
    if explicit:
        return shlex.split(explicit)
    # Returning [] on a pkg-config miss turned into a silent skip on 31.6, where
    # json-c has no .pc file. Resolve it instead so the fixture actually runs.
    try:
        return apd_test_deps.package_flags("json-c", "sqlite3")
    except AssertionError:
        return []


def test_executable_contract_when_native_dependencies_exist() -> None:
    compiler = shutil.which("cc") or shutil.which("gcc")
    flags = pkg_config_flags()
    if not compiler or not flags:
        print("skip: native json-c/sqlite3 development dependencies unavailable")
        return
    # power.c reaches the OS through pipe2()/SOCK_CLOEXEC, which are Linux-only
    # and absent from the macOS SDK under every feature macro.  The target is
    # Linux, so this is a host limitation rather than a defect in power.c; the
    # static contracts above still run everywhere.
    if sys.platform == "darwin":
        print("skip: pipe2()/SOCK_CLOEXEC are Linux-only; run this on the target host")
        return
    with tempfile.TemporaryDirectory(prefix="system-power-contract-") as temp_name:
        temp = Path(temp_name)
        db = temp / "config.db"
        harness = temp / "harness.c"
        executable = temp / "harness"
        harness.write_text(textwrap.dedent(r'''
            #define _GNU_SOURCE
            #include <assert.h>
            #include <json-c/json.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <time.h>
            #include "power.h"

            static struct json_object *data(struct json_object *root) {
                struct json_object *d = NULL;
                assert(root && json_object_object_get_ex(root, "data", &d));
                return d;
            }
            static const char *str(struct json_object *o, const char *key) {
                struct json_object *v = NULL;
                assert(json_object_object_get_ex(o, key, &v));
                return json_object_get_string(v);
            }
            static long long integer(struct json_object *o, const char *key) {
                struct json_object *v = NULL;
                assert(json_object_object_get_ex(o, key, &v));
                return (long long)json_object_get_int64(v);
            }
            static struct json_object *call_upsert(const char *id, const char *json) {
                struct json_object *request = json_tokener_parse(json);
                struct json_object *response = jmx_system_power_schedule_upsert(id, request);
                json_object_put(request);
                return response;
            }
            int main(void) {
                struct json_object *r, *d, *schedule, *schedules;
                char id[96]; long long rev, next;

                setenv("TZ", "UTC", 1); tzset();
                r = call_upsert(NULL, "{\"confirm\":true,\"name\":\"monthly\",\"event\":\"reboot\",\"period\":\"monthly\",\"date\":null,\"time\":\"04:30\",\"weekdays\":[],\"month_day\":31,\"enabled\":true}");
                d = data(r); assert(integer(d, "ok") == 1);
                assert(json_object_object_get_ex(d, "schedule", &schedule));
                snprintf(id, sizeof(id), "%s", str(schedule, "id"));
                rev = integer(schedule, "revision"); next = integer(schedule, "next_run_at");
                assert(next > 0); json_object_put(r);

                r = call_upsert(id, "{\"confirm\":true,\"revision\":999,\"name\":\"stale\",\"event\":\"reboot\",\"period\":\"daily\",\"date\":null,\"time\":\"04:30\",\"weekdays\":[],\"month_day\":null,\"enabled\":true}");
                d = data(r); assert(integer(d, "ok") == 0); assert(!strcmp(str(d, "error"), "schedule_conflict")); json_object_put(r);

                char update[512];
                snprintf(update, sizeof(update), "{\"confirm\":true,\"revision\":%lld,\"name\":\"daily\",\"event\":\"shutdown\",\"period\":\"daily\",\"date\":null,\"time\":\"04:31\",\"weekdays\":[],\"month_day\":null,\"enabled\":true}", rev);
                r = call_upsert(id, update); d = data(r); assert(integer(d, "ok") == 1); json_object_put(r);

                r = call_upsert(NULL, "{\"confirm\":true,\"name\":\"weekly\",\"event\":\"reboot\",\"period\":\"weekly\",\"date\":null,\"time\":\"02:00\",\"weekdays\":[1,5],\"month_day\":null,\"enabled\":true}");
                assert(integer(data(r), "ok") == 1); json_object_put(r);
                r = call_upsert(NULL, "{\"confirm\":true,\"name\":\"once\",\"event\":\"reboot\",\"period\":\"once\",\"date\":\"2099-12-31\",\"time\":\"23:59\",\"weekdays\":[],\"month_day\":null,\"enabled\":true}");
                assert(integer(data(r), "ok") == 1); json_object_put(r);

                r = jmx_system_power_get(); d = data(r); assert(integer(d, "ok") == 1);
                assert(!strcmp(str(d, "contract_version"), "system-power.v1"));
                assert(json_object_object_get_ex(d, "schedules", &schedules));
                assert(json_object_array_length(schedules) == 3); json_object_put(r);

                r = jmx_system_power_scheduler_tick(1, 0); d = data(r);
                assert(integer(d, "ok") == 1); assert(integer(d, "executed") == 0); json_object_put(r);

                r = jmx_system_power_immediate_action("reboot", json_tokener_parse("{\"confirm\":true,\"execute\":false}"));
                d = data(r); assert(integer(d, "ok") == 1); assert(integer(d, "dry_run") == 1); json_object_put(r);
                r = jmx_system_power_immediate_action("reboot", json_tokener_parse("{\"confirm\":true,\"execute\":false}"));
                d = data(r); assert(integer(d, "ok") == 1); assert(integer(d, "dry_run") == 1); json_object_put(r);
                puts("system_power_runtime_ok");
                return 0;
            }
        '''), encoding="utf-8")
        command = [
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-DJMX_SYSTEM_POWER_TESTING=1",
            f'-DJMX_SYSTEM_POWER_DB_PATH="{db}"',
            "-I", str(ROOT / "src/system"), str(SOURCE), str(harness),
            "-o", str(executable), *flags,
        ]
        compiled = subprocess.run(command, text=True, capture_output=True)
        assert compiled.returncode == 0, compiled.stderr
        ran = subprocess.run([str(executable)], text=True, capture_output=True, timeout=20)
        assert ran.returncode == 0, ran.stderr + ran.stdout
        assert "system_power_runtime_ok" in ran.stdout
        with sqlite3.connect(db) as connection:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            assert {"power_schedule_meta", "power_schedule", "power_schedule_history"} <= tables
            assert connection.execute(
                "SELECT COUNT(*) FROM power_schedule_history WHERE source='immediate'"
            ).fetchone()[0] == 0


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    failures: list[str] = []
    for test in tests:
        try:
            test()
        except (AssertionError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{test.__name__}: {exc}")
    if failures:
        raise SystemExit("system-power contract failures:\n- " + "\n- ".join(failures))
    print(f"ok: system-power data layer contracts ({len(tests)} checks)")
