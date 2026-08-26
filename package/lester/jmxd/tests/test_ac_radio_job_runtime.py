#!/usr/bin/env python3
"""Runtime and source contracts for the AC radio scan job control plane."""

from __future__ import annotations

import concurrent.futures
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import glob


ROOT = Path(__file__).resolve().parents[1]
DB_SOURCE = ROOT / "src/ac/ac_db.c"
PROTOCOL = ROOT / "src/ac/ac_protocol.c"
UBUS = ROOT / "src/ac/ac_ubus.c"
FIXTURE = ROOT / "tests/ac_radio_job_runtime_fixture.c"
OPENSSL = Path("/opt/homebrew/opt/openssl@3")
AP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OTHER_AP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def compile_fixture(output: Path) -> None:
    prefix = Path(os.environ.get("AC_RADIO_JOB_TEST_PREFIX", OPENSSL))
    json_candidates = [prefix, Path("/opt/homebrew/opt/json-c")]
    json_candidates.extend(Path(value) for value in glob.glob(
        "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/*"
    ))
    json_prefix = next((value for value in json_candidates
                        if (value / "include/json-c/json.h").is_file() and
                           ((value / "lib/libjson-c.a").is_file() or
                            (value / "lib/libjson-c.so").is_file())), None)
    assert json_prefix, "json-c headers and static library are required"
    json_static = json_prefix / "lib/libjson-c.a"
    json_link = ([str(json_static)] if json_static.is_file() else
                 [f"-L{json_prefix / 'lib'}",
                  f"-Wl,-rpath,{json_prefix / 'lib'}", "-ljson-c"])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-Wall", "-Wextra", "-Werror",
        f"-I{prefix / 'include'}", f"-I{json_prefix / 'include'}",
        f"-L{prefix / 'lib'}",
        f"-Wl,-rpath,{prefix / 'lib'}", str(FIXTURE), str(DB_SOURCE),
        "-lcrypto", *json_link,
        "-lsqlite3", "-lm", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def run(binary: Path, database: Path, *args: str,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DREAMINGWRT_AC_DB_PATH"] = str(database)
    return subprocess.run([str(binary), *args], env=env, check=check,
                          capture_output=True, text=True)


def fields(output: str) -> dict[str, str]:
    return dict(re.findall(r"([a-z_]+)=([^\s]+)", output))


def schema_version() -> int:
    match = re.search(r"#define AC_SCHEMA_VERSION (\d+)",
                      DB_SOURCE.read_text(encoding="utf-8"))
    assert match, "AC_SCHEMA_VERSION not found in ac_db.c"
    return int(match.group(1))


def create(binary: Path, database: Path, mode: str, key: str) -> dict[str, str]:
    result = fields(run(binary, database, "create", AP_ID, "phy0", mode, key).stdout)
    assert result["result"] in {"0", "1"}
    assert len(result["job_id"]) == 36
    return result


def test_schema_target_validation_and_idempotency(binary: Path, database: Path) -> None:
    run(binary, database, "seed", AP_ID, "phy0")
    first = create(binary, database, "neighbor", "request-1")
    duplicate = create(binary, database, "neighbor", "request-1")
    assert duplicate["result"] == "1" and duplicate["job_id"] == first["job_id"]

    conflict = fields(run(binary, database, "create", AP_ID, "phy0", "survey",
                          "request-1").stdout)
    assert conflict["result"] == "3" and conflict["job_id"] == first["job_id"]
    for ap_id, radio_id in ((OTHER_AP_ID, "phy0"), (AP_ID, "phy9"),
                            (AP_ID, f"ap:{AP_ID}:radio:phy0")):
        rejected = fields(run(binary, database, "create", ap_id, radio_id,
                              "neighbor", f"bad-{len(radio_id)}").stdout)
        assert rejected["result"] == "4"
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(ac_radio_jobs)")}
        required = {
            "job_id", "ap_id", "radio_id", "mode", "state", "created_at",
            "updated_at", "lease_owner", "lease_expires_at", "session_epoch",
            "attempt_id", "dispatch_generation", "request_digest", "finish_id",
            "finish_digest", "last_progress_at", "reconcile_deadline",
            "result_count", "result_bytes", "result_digest", "result_complete",
            "error_code", "expected_impact", "idempotency_key",
        }
        assert required <= columns
        assert connection.execute(
            "SELECT version FROM ac_schema_meta"
        ).fetchone() == (schema_version(),)
        runtime_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(ac_ap_runtime)")
        }
        assert {"control_protocol_version", "session_connected"} <= runtime_columns
        assert "result_json" in columns


def test_atomic_concurrent_dedup(binary: Path, database: Path) -> None:
    def invoke(_: int) -> dict[str, str]:
        return fields(run(binary, database, "create", AP_ID, "phy0", "survey",
                          "concurrent-key").stdout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(invoke, range(24)))
    assert sum(item["result"] == "0" for item in results) == 1
    assert all(item["result"] in {"0", "1"} for item in results)
    assert len({item["job_id"] for item in results}) == 1


def test_status_list_cancel_and_result_metadata(binary: Path, database: Path) -> None:
    created = create(binary, database, "neighbor", "cancel-me")
    status = fields(run(binary, database, "status", created["job_id"]).stdout)
    assert status["state"] == "queued"
    listing = run(binary, database, "list", AP_ID).stdout
    assert created["job_id"] in listing and "count=" in listing
    cancelled = fields(run(binary, database, "cancel", created["job_id"]).stdout)
    assert cancelled["state"] == "cancelled"
    assert run(binary, database, "cancel", created["job_id"], check=False).returncode != 0
    metadata = fields(run(binary, database, "result", created["job_id"]).stdout)
    assert metadata["result_complete"] == "0" and metadata["result_count"] == "0"


def test_restart_recovery_is_truthful(binary: Path, database: Path) -> None:
    leased = create(binary, database, "neighbor", "recover-leased")
    running = create(binary, database, "neighbor", "recover-running")
    cancelling = create(binary, database, "survey", "recover-cancelling")
    completed = create(binary, database, "survey", "recover-completed")
    for item, state, complete in (
        (leased, "leased", "0"), (running, "running", "0"),
        (cancelling, "cancel_requested", "0"), (completed, "completed", "1"),
    ):
        run(binary, database, "set-state", item["job_id"], state, "", complete)

    run(binary, database, "init")
    after = {
        name: fields(run(binary, database, "status", item["job_id"]).stdout)
        for name, item in (("leased", leased), ("running", running),
                           ("cancelling", cancelling), ("completed", completed))
    }
    for name in ("leased", "running", "cancelling"):
        assert after[name]["state"] in {"leased", "running", "cancel_requested"}
        assert after[name]["error"] == "controller_restart_reconcile_pending"
        assert after[name]["result_complete"] == "0"
    assert after["completed"]["state"] == "completed"
    assert after["completed"]["result_complete"] == "1"

    run(binary, database, "expire", str(int(__import__("time").time()) + 300))
    expired = {
        name: fields(run(binary, database, "status", item["job_id"]).stdout)
        for name, item in (("leased", leased), ("running", running),
                           ("cancelling", cancelling))
    }
    assert expired["leased"]["state"] == "failed"
    assert expired["leased"]["error"] == "delivery_unknown"
    assert expired["running"]["state"] == "failed"
    assert expired["running"]["error"] == "execution_unknown"
    assert expired["cancelling"]["state"] == "failed"
    assert expired["cancelling"]["error"] == "cancellation_unknown"


def test_lease_binding_finish_and_payload(binary: Path, database: Path) -> None:
    epoch = "1" * 64
    other_epoch = "2" * 64
    now = int(__import__("time").time())
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ac_radio_jobs SET state='cancelled' "
            "WHERE state IN ('queued','leased','running','cancel_requested')"
        )
    first = create(binary, database, "neighbor", "lease-first")
    second = create(binary, database, "survey", "lease-second")
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE ac_radio_jobs SET created_at=? WHERE job_id=?",
                           (now - 2, first["job_id"]))
        connection.execute("UPDATE ac_radio_jobs SET created_at=? WHERE job_id=?",
                           (now - 1, second["job_id"]))

    lifecycle = run(binary, database, "lifecycle", AP_ID, epoch, other_epoch,
                    first["job_id"], second["job_id"]).stdout
    assert "lifecycle=ok" in lifecycle
    assert '"bssid":"02:00:00:00:00:01"' in lifecycle

    newest = create(binary, database, "neighbor", "latest-neighbor")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ac_radio_jobs SET state='completed', updated_at=?, "
            "result_count=1, result_bytes=?, result_complete=0, "
            "result_json=? WHERE job_id=?",
            (now + 10, len('[{\"bssid\":\"02:00:00:00:00:02\"}]'),
             '[{\"bssid\":\"02:00:00:00:00:02\"}]', newest["job_id"]),
        )
        connection.execute(
            "UPDATE ac_radio_jobs SET state='completed', updated_at=?, "
            "result_count=1, result_bytes=?, result_complete=1, "
            "result_json=? WHERE job_id=?",
            (now + 20, len('[{\"survey\":true}]'),
             '[{\"survey\":true}]', second["job_id"]),
        )

    latest = json.loads(run(binary, database, "latest").stdout)
    assert latest["ok"] is True
    assert latest["count"] == 1
    assert latest["limited"] is False and latest["limit"] == 128
    sample = latest["samples"][0]
    assert sample["job_id"] == newest["job_id"]
    assert sample["ap_id"] == AP_ID and sample["radio_id"] == "phy0"
    assert sample["item_count"] == 1
    assert sample["complete"] is False and sample["truncated"] is True
    assert sample["items"] == [{"bssid": "02:00:00:00:00:02"}]


def test_interrupted_rebind_and_cross_session_finish_replay(
        binary: Path, database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ac_radio_jobs SET state='cancelled' "
            "WHERE state IN ('queued','leased','running','cancel_requested')"
        )
    job = create(binary, database, "neighbor", "interrupted-replay")
    output = run(
        binary, database, "interrupted-replay", AP_ID, "7" * 64, "8" * 64,
        "9" * 64, job["job_id"],
    ).stdout
    assert "interrupted_replay=ok" in output
    assert "stale_result=3" in output
    assert "replay_result=1" in output
    assert "changed_result=3" in output
    assert "changed_error_result=3" in output
    assert "changed_identity_result=3" in output
    status = fields(run(binary, database, "status", job["job_id"]).stdout)
    assert status["state"] == "failed"
    assert status["error"] == "apd_restarted_during_execution"


def test_cancelled_finish_is_not_failed(binary: Path, database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ac_radio_jobs SET state='cancelled' "
            "WHERE state IN ('queued','leased','running','cancel_requested')"
        )
    job = create(binary, database, "neighbor", "cancelled-finish")
    output = run(binary, database, "cancelled-finish", AP_ID, "9" * 64,
                 job["job_id"]).stdout
    assert "cancelled_finish=ok" in output
    assert "state=cancelled" in output and "result_complete=1" in output
    status = fields(run(binary, database, "status", job["job_id"]).stdout)
    assert status["state"] == "cancelled"
    assert status["error"] == "controller_cancelled"


def test_bounded_list_and_terminal_retention(binary: Path, database: Path) -> None:
    old_latest = "70000000-0000-4000-8000-000000000001"
    old_queued = "70000000-0000-4000-8000-000000000002"
    terminal_rows = [
        (f"71000000-0000-4000-8000-{index:012d}", OTHER_AP_ID, "phy0", "survey",
         "failed", f"retention-{index}", 1000 + index, 1000 + index,
         "survey_channel_dwell_only", "retention_fixture")
        for index in range(140)
    ]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO ac_radio_jobs(job_id,ap_id,radio_id,mode,state,"
            "idempotency_key,created_at,updated_at,expected_impact,result_json,"
            "result_count,result_bytes,result_complete) "
            "VALUES(?,?,?,?,?,?,?,?,?,'[]',0,2,1)",
            (old_latest, OTHER_AP_ID, "phy9", "neighbor", "completed",
             "retention-latest-neighbor", 100, 100,
             "radio_may_leave_working_channel"),
        )
        connection.execute(
            "INSERT INTO ac_radio_jobs(job_id,ap_id,radio_id,mode,state,"
            "idempotency_key,created_at,updated_at,expected_impact) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (old_queued, OTHER_AP_ID, "phy0", "survey", "queued",
             "retention-nonterminal", 99, 99, "survey_channel_dwell_only"),
        )
        connection.executemany(
            "INSERT INTO ac_radio_jobs(job_id,ap_id,radio_id,mode,state,"
            "idempotency_key,created_at,updated_at,expected_impact,error_code) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)", terminal_rows,
        )

    listing = run(binary, database, "list", OTHER_AP_ID).stdout
    assert "count=128" in listing and "limited=1" in listing and "limit=128" in listing
    assert fields(run(binary, database, "prune", "200000").stdout)["result"] == "12"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT state FROM ac_radio_jobs WHERE job_id=?", (old_latest,)
        ).fetchone() == ("completed",)
        assert connection.execute(
            "SELECT state FROM ac_radio_jobs WHERE job_id=?", (old_queued,)
        ).fetchone() == ("queued",)
        assert connection.execute(
            "SELECT COUNT(*) FROM ac_radio_jobs WHERE idempotency_key LIKE 'retention-%' "
            "AND state='failed'"
        ).fetchone() == (128,)
    assert fields(run(binary, database, "prune", "200000").stdout)["result"] == "0"


def test_control_plane_contract_claims_closed_execution_chain() -> None:
    protocol = PROTOCOL.read_text(encoding="utf-8")
    ubus = UBUS.read_text(encoding="utf-8")
    assert '"scan_job_store", 1' in protocol
    assert '"scan_job_control_plane", 1' in protocol
    assert '"scan_dispatch", scan_execution' in protocol
    assert '"scan_execution", scan_execution' in protocol
    assert '"no_online_ap_control_v2_session"' in protocol
    assert 'json_object_new_array()' in protocol
    assert '"accepted", json_object_new_boolean(1)' in protocol
    assert '"persisted", json_object_new_boolean(1)' in protocol
    assert '"scan_job_queued"' in protocol
    assert '"result_truncated"' in protocol
    for field in ("attempt_id", "dispatch_generation", "request_digest",
                  "finish_id", "finish_digest", "last_progress_at",
                  "reconcile_deadline"):
        assert f'"{field}"' in protocol
    for method in ("radio_job_create", "radio_job_status", "radio_job_cancel",
                   "radio_job_result", "radio_job_list"):
        assert f'UBUS_METHOD("{method}"' in ubus
    assert "ac_message_is_strict" in ubus
    assert "radio_job_dispatch" not in ubus and "radio_job_execute" not in ubus


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-radio-job-") as temp:
        directory = Path(temp)
        binary = directory / "fixture"
        database = directory / "config.db"
        compile_fixture(binary)
        test_schema_target_validation_and_idempotency(binary, database)
        test_atomic_concurrent_dedup(binary, database)
        test_status_list_cancel_and_result_metadata(binary, database)
        test_restart_recovery_is_truthful(binary, database)
        test_lease_binding_finish_and_payload(binary, database)
        test_interrupted_rebind_and_cross_session_finish_replay(binary, database)
        test_cancelled_finish_is_not_failed(binary, database)
        test_bounded_list_and_terminal_retention(binary, database)
        test_control_plane_contract_claims_closed_execution_chain()
    print("ok: AC radio job DB, idempotency, recovery, metadata and ubus contracts")


if __name__ == "__main__":
    main()
