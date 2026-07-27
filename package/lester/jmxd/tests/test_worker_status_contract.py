#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKERS = {
    "flowd": (ROOT / "src/flowd/flowd_db.c", "flowd_status_json"),
    "logd": (ROOT / "src/logd/logd_db.c", "logd_status_json"),
    "notifyd": (ROOT / "src/notifyd/notifyd_db.c", "notifyd_status_json"),
    "otad": (ROOT / "src/otad/otad_status.c", "otad_status_json"),
    "aegisxd": (ROOT / "src/aegisxd/aegisxd_status.c", "aegisxd_status_json"),
    "routed": (ROOT / "src/routed/routed_control.c", "routed_status_json"),
    "auditd": (ROOT / "src/audit/jmx_auditd.c", "handle_status"),
}
REQUIRED_FIELDS = (
    "service",
    "version",
    "schema_version",
    "schema_source",
    "migration_state",
    "dependencies",
    "datasets",
    "last_error",
    "updated_at",
    "ts",
    "ok",
    "state",
    "degraded",
)
WRITE_SQL = re.compile(
    r'"\s*(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|VACUUM|REINDEX|BEGIN|COMMIT|ROLLBACK)\b',
    re.IGNORECASE,
)


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.DOTALL)
    assert match, f"function not found: {name}"
    start = source.index("{", match.start())
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(source)):
        char = source[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {name}")


def test_all_native_worker_statuses_expose_the_stable_contract():
    for worker, (path, function) in WORKERS.items():
        source = path.read_text(encoding="utf-8")
        body = function_body(source, function)

        assert '#define WORKER_STATUS_VERSION "1.0"' in source, worker
        for field in REQUIRED_FIELDS:
            assert f'"{field}"' in body, f"{worker} missing {field}"


def test_schema_sources_are_truthful_and_explicit():
    expected = {
        "flowd": "compiled:FLOWD_SCHEMA_VERSION",
        "logd": "log.db:log_meta.schema_version",
        "notifyd": "notify.db:notify_meta.schema_version",
        "otad": "config.db:ota_state.schema_version",
        "aegisxd": "aegis.db:aegis_state.schema_version",
        "routed": "none:unversioned routed tables in shared config.db",
        "auditd": "none:unversioned audit.db schema",
    }
    for worker, schema_source in expected.items():
        path, _ = WORKERS[worker]
        assert schema_source in path.read_text(encoding="utf-8")

    for worker in ("routed", "auditd"):
        path, function = WORKERS[worker]
        body = function_body(path.read_text(encoding="utf-8"), function)
        assert re.search(
            r'"schema_version"\s*,\s*(?:json_object_new_int\()?0\)?', body
        )
        assert '"migration_state"' in body
        assert '"not_tracked"' in body


def test_status_contract_queries_are_read_only():
    helper_functions = {
        "flowd": ("flowd_status_metadata_load",),
        "otad": ("otad_status_query_config", "otad_status_query_inventory"),
        "aegisxd": ("aegisxd_status_contract_load",),
    }
    forbidden_calls = (
        "sqlite3_exec(",
        "flowd_exec(",
        "logd_exec(",
        "notifyd_exec(",
        "otad_exec(",
        "otad_state_set(",
        "aegisxd_exec(",
        "aegisxd_state_set(",
        "routed_exec(",
        "routed_db_open(",
    )

    for worker, (path, function) in WORKERS.items():
        source = path.read_text(encoding="utf-8")
        bodies = [function_body(source, function)]
        bodies.extend(function_body(source, helper) for helper in helper_functions.get(worker, ()))
        status_code = "\n".join(bodies)

        assert not WRITE_SQL.search(status_code), worker
        for call in forbidden_calls:
            assert call not in status_code, f"{worker} status writes via {call}"

    routed_source = WORKERS["routed"][0].read_text(encoding="utf-8")
    routed_body = function_body(routed_source, "routed_status_json")
    assert "SQLITE_OPEN_READONLY" in routed_body


def test_status_does_not_claim_a_firmware_version():
    for worker, (path, function) in WORKERS.items():
        source = path.read_text(encoding="utf-8")
        body = function_body(source, function)

        assert "WORKER_STATUS_VERSION" in body, worker
        assert '"version", json_object_new_string(OTAD_RELEASE' not in body
        assert '"version", release' not in body


if __name__ == "__main__":
    test_all_native_worker_statuses_expose_the_stable_contract()
    test_schema_sources_are_truthful_and_explicit()
    test_status_contract_queries_are_read_only()
    test_status_does_not_claim_a_firmware_version()
    print("ok: native worker status contracts are stable and read-only")
