#!/usr/bin/env python3
"""Run Docker create jobs against temporary SQLite and a fake argv recorder."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/jmx_netconfig_db.c"
FIXTURE = ROOT / "tests/container_service_runtime_fixture.c"

FUNCTIONS = (
    "nc_cmd_exists",
    "nc_container_job_register_worker",
    "nc_container_monotonic_ms",
    "nc_exec_result_free",
    "nc_exec_trim_output",
    "nc_exec_argv_capture_ex",
    "nc_docker_name_valid",
    "nc_docker_image_id_valid",
    "nc_docker_hostname_valid",
    "nc_docker_label_key_valid",
    "nc_docker_label_value_valid",
    "nc_docker_restart_policy_valid",
    "nc_docker_container_id_from_output",
    "nc_docker_create_error",
    "nc_docker_create_field_supported",
    "nc_container_label_compare",
    "nc_docker_create_normalize",
    "nc_docker_confirmation_required",
    "nc_docker_invalid",
    "nc_container_job_db_open",
    "nc_container_job_id_valid",
    "nc_container_job_worker_matches",
    "nc_container_jobs_reconcile",
    "nc_container_job_spawn",
    "nc_container_job_submit",
    "jmx_docker_container_create",
    "jmx_docker_job_worker",
    "jmx_docker_job_cancel",
)

MACROS = (
    "NC_CONTAINER_OUTPUT_MAX",
    "NC_CONTAINER_JOB_ID_LEN",
    "NC_CONTAINER_JOB_RETENTION_SEC",
    "NC_CONTAINER_JOB_MAX_ROWS",
    "NC_CONTAINER_JOB_ACTIVE_MAX",
    "NC_CONTAINER_JOB_WORKER_COMM",
    "NC_CONTAINER_CREATE_COMMAND_MAX",
    "NC_CONTAINER_CREATE_COMMAND_ITEM_MAX",
    "NC_CONTAINER_CREATE_COMMAND_TOTAL_MAX",
    "NC_CONTAINER_CREATE_LABEL_MAX",
    "NC_CONTAINER_CREATE_LABEL_KEY_MAX",
    "NC_CONTAINER_CREATE_LABEL_VALUE_MAX",
    "NC_CONTAINER_CREATE_ARGV_MAX",
    "NC_CONTAINER_CREATE_JSON_MAX",
)

LEGACY_SCHEMA = """
CREATE TABLE container_job (
 id TEXT PRIMARY KEY,kind TEXT NOT NULL,target TEXT NOT NULL,state TEXT NOT NULL,
 progress INTEGER NOT NULL DEFAULT 0,worker_pid INTEGER NOT NULL DEFAULT 0,
 rc INTEGER NOT NULL DEFAULT -1,output TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,started_at INTEGER NOT NULL DEFAULT 0,
 updated_at INTEGER NOT NULL,completed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_container_job_state_updated ON container_job(state,updated_at DESC);
INSERT INTO container_job(id,kind,target,state,progress,rc,created_at,updated_at,completed_at)
VALUES('job-00000000000000000000000000000000','image_pull','legacy/app:1',
       'success',100,0,1,2,2);
"""

CONTAINER_ID = "a" * 64


def _definition(source: str, name: str) -> str:
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", source):
        line_start = source.rfind("\n", 0, match.start()) + 1
        prefix = source[line_start:match.start()]
        if "typedef" in prefix or prefix.lstrip().startswith("#"):
            continue
        opening = source.find("{", match.end())
        semicolon = source.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        state = "code"
        quote = ""
        escaped = False
        depth = 0
        index = opening
        while index < len(source):
            char = source[index]
            nxt = source[index + 1] if index + 1 < len(source) else ""
            if state == "line_comment":
                if char == "\n":
                    state = "code"
            elif state == "block_comment":
                if char == "*" and nxt == "/":
                    state = "code"
                    index += 1
            elif state == "string":
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    state = "code"
            elif char == "/" and nxt == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and nxt == "*":
                state = "block_comment"
                index += 1
            elif char in ('"', "'"):
                state = "string"
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[line_start:index + 1]
            index += 1
    raise AssertionError(f"production function not found: {name}")


def _macro(source: str, name: str) -> str:
    match = re.search(rf"(?m)^#define\s+{re.escape(name)}(?:\s|$).*", source)
    assert match, f"production macro not found: {name}"
    end = match.end()
    while source[match.start():end].rstrip().endswith("\\"):
        next_end = source.find("\n", end + 1)
        end = len(source) if next_end < 0 else next_end
    return source[match.start():end]


def write_production_includes(defs_path: Path, impl_path: Path) -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert "#ifndef NC_CONTAINER_JOB_DB_PATH" in source
    assert "#ifndef NC_CONTAINER_JOB_EXEC_PATH" in source
    assert "execl(NC_CONTAINER_JOB_EXEC_PATH" in source
    defs_path.write_text(
        "\n".join(_macro(source, name) for name in MACROS) + "\n",
        encoding="utf-8",
    )
    impl_path.write_text(
        "\n\n".join(_definition(source, name) for name in FUNCTIONS) + "\n",
        encoding="utf-8",
    )


def json_c_flags() -> list[str]:
    configured = os.environ.get("CONTAINER_SERVICE_TEST_JSON_C_ROOT", "")
    if configured:
        prefix = Path(configured)
        header = prefix / "include/json-c/json.h"
        shared_library = prefix / "lib/libjson-c.so"
        static_library = prefix / "lib/libjson-c.a"
        assert header.is_file(), f"json-c header missing below {prefix}"
        if shared_library.is_file():
            return ["-I", str(prefix / "include"), "-L", str(prefix / "lib"),
                    "-ljson-c", f"-Wl,-rpath,{prefix / 'lib'}"]
        assert static_library.is_file(), f"json-c library missing below {prefix}"
        return ["-I", str(prefix / "include"), str(static_library)]

    # pkg-config is consulted inside the resolver. Both former fallbacks
    # (brew --prefix, then the temporary cellar) resolved on 31.6 to an LTO
    # archive the host linker rejects with "bytecode stream ... generated with
    # LTO version 16.0", so defer to the shared resolver, which prefers a
    # linkable .so and knows about the staging_dir.
    return apd_test_deps.package_flags("json-c")


def compile_fixture(temp: Path, db: Path) -> Path:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "native C compiler unavailable"
    defs = temp / "container_service_runtime_defs.inc"
    implementation = temp / "container_service_runtime_impl.inc"
    executable = temp / "container-runtime"
    write_production_includes(defs, implementation)
    command = [
        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I", str(temp),
        f'-DNC_CONTAINER_JOB_DB_PATH="{db}"',
        f'-DNC_CONTAINER_JOB_EXEC_PATH="{executable}"',
        str(FIXTURE), "-lsqlite3", *json_c_flags(), "-o", str(executable),
    ]
    proc = subprocess.run(command, text=True, capture_output=True)
    assert proc.returncode == 0, f"fixture compile failed:\n{proc.stdout}\n{proc.stderr}"
    return executable


def install_fake_docker(bin_dir: Path, record: Path) -> None:
    fake = bin_dir / "docker"
    fake.write_text(
        """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

record = Path(os.environ["DREAMINGWRT_FAKE_DOCKER_RECORD"])
with record.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:], separators=(",", ":")) + "\\n")
if sys.argv[1:2] == ["create"]:
    if "registry.example/slow:1" in sys.argv[2:]:
        import time
        time.sleep(30)
    print(os.environ["DREAMINGWRT_FAKE_CONTAINER_ID"])
elif sys.argv[1:2] == ["inspect"]:
    print("/runtime-generated")
else:
    print("unexpected fake docker argv", file=sys.stderr)
    raise SystemExit(64)
""",
        encoding="utf-8",
    )
    fake.chmod(0o755)


def run(executable: Path, env: dict[str, str], *args: str,
        expected: int = 0) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run([str(executable), *args], env=env, text=True,
                          capture_output=True, timeout=15)
    assert proc.returncode == expected, (
        f"command returned {proc.returncode}, expected {expected}: {args}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    return proc


def insert_job(db: Path, job_id: str, state: str, request_json: str,
               *, target: str = "registry.example/app:1", pid: int = 0,
               age: int = 0) -> None:
    now = int(time.time()) - age
    with sqlite3.connect(db) as conn:
        conn.execute(
            """INSERT INTO container_job(
               id,kind,target,state,progress,worker_pid,rc,output,error,
               created_at,started_at,updated_at,completed_at,request_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (job_id, "container_create", target, state,
             10 if state == "running" else 0, pid, -1, "", "",
             now, now if state == "running" else 0, now, 0, request_json),
        )


def row(db: Path, job_id: str) -> sqlite3.Row:
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        value = conn.execute("SELECT * FROM container_job WHERE id=?", (job_id,)).fetchone()
        assert value is not None, f"missing job row: {job_id}"
        return value


def wait_terminal(db: Path, job_id: str) -> sqlite3.Row:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = row(db, job_id)
        if value["state"] in ("success", "failed", "cancelled"):
            return value
        time.sleep(0.025)
    raise AssertionError(f"job did not reach terminal state: {dict(row(db, job_id))}")


def wait_state(db: Path, job_id: str, state: str) -> sqlite3.Row:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = row(db, job_id)
        if value["state"] == state:
            return value
        if value["state"] in ("success", "failed", "cancelled"):
            break
        time.sleep(0.025)
    raise AssertionError(
        f"job did not reach {state}: {dict(row(db, job_id))}"
    )


def records(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="container-create-runtime-") as temp_name:
        temp = Path(temp_name)
        db = temp / "jobs.db"
        record = temp / "docker-argv.jsonl"
        bin_dir = temp / "bin"
        bin_dir.mkdir()
        install_fake_docker(bin_dir, record)
        with sqlite3.connect(db) as conn:
            conn.executescript(LEGACY_SCHEMA)
        executable = compile_fixture(temp, db)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
        env["DREAMINGWRT_FAKE_DOCKER_RECORD"] = str(record)
        env["DREAMINGWRT_FAKE_CONTAINER_ID"] = CONTAINER_ID

        # Opening an old table performs only additive migration and preserves rows.
        run(executable, env, "migrate")
        with sqlite3.connect(db) as conn:
            columns = {value[1] for value in conn.execute("PRAGMA table_info(container_job)")}
            assert {"request_json", "result_id", "result_name", "output_truncated"} <= columns
            legacy = conn.execute(
                "SELECT state,request_json,result_id,result_name,output_truncated "
                "FROM container_job WHERE id='job-00000000000000000000000000000000'"
            ).fetchone()
            assert legacy == ("success", "", "", "", 0)

        request = {
            "labels": {"z.last": "last", "a.first": "first"},
            "command": ["serve", "--listen", "0.0.0.0:8080"],
            "network": "bridge",
            "restart_policy": "unless-stopped",
            "hostname": "runtime.local",
            "name": "runtime-test",
            "image": "registry.example/app:1",
            "action": "create",
            "id": "ignored-route-id",
            "confirm": True,
        }
        normalized = run(executable, env, "normalize", json.dumps(request)).stdout.strip()
        normalized_object = json.loads(normalized)
        assert list(normalized_object) == [
            "image", "name", "hostname", "restart_policy", "network", "command", "labels"
        ]
        assert list(normalized_object["labels"]) == ["a.first", "z.last"]
        assert normalized_object == {
            "image": "registry.example/app:1",
            "name": "runtime-test",
            "hostname": "runtime.local",
            "restart_policy": "unless-stopped",
            "network": "bridge",
            "command": ["serve", "--listen", "0.0.0.0:8080"],
            "labels": {"a.first": "first", "z.last": "last"},
        }
        canonical = normalized
        submitted = json.loads(run(
            executable, env, "create", json.dumps(request, separators=(",", ":"))
        ).stdout)
        assert submitted["ok"] is True and submitted["state"] == "queued"
        job_id = submitted["job_id"]
        value = wait_terminal(db, job_id)
        assert value["request_json"] == canonical
        assert value["state"] == "success" and value["rc"] == 0
        assert value["result_id"] == CONTAINER_ID
        assert value["result_name"] == "runtime-test"
        assert records(record)[0] == [
            "create", "--name", "runtime-test", "--hostname", "runtime.local",
            "--restart", "unless-stopped", "--network", "bridge",
            "--label", "a.first=first", "--label", "z.last=last",
            "registry.example/app:1", "serve", "--listen", "0.0.0.0:8080",
        ]

        # Without a requested name the worker persists Docker's inspected name.
        second_request = {"confirm": True, "image": "registry.example/unnamed:2"}
        submitted = json.loads(run(
            executable, env, "create", json.dumps(second_request)
        ).stdout)
        second = wait_terminal(db, submitted["job_id"])
        assert second["state"] == "success"
        assert second["result_id"] == CONTAINER_ID
        assert second["result_name"] == "runtime-generated"
        assert records(record)[-2:] == [
            ["create", "registry.example/unnamed:2"],
            ["inspect", "--format", "{{.Name}}", CONTAINER_ID],
        ]

        # The worker validates persisted JSON again and never executes tampered work.
        bad_id = "job-11111111111111111111111111111111"
        before = records(record)
        insert_job(
            db, bad_id, "queued",
            '{"labels":{"z.last":"last","a.first":"first"},'
            '"image":"registry.example/app:1"}',
        )
        run(executable, env, "worker", bad_id, expected=1)
        bad = row(db, bad_id)
        assert bad["state"] == "failed" and bad["rc"] == 125
        assert bad["error"] == "invalid_persisted_request"
        assert records(record) == before

        mismatch_id = "job-66666666666666666666666666666666"
        insert_job(
            db, mismatch_id, "queued", normalized,
            target="registry.example/different:9",
        )
        run(executable, env, "worker", mismatch_id, expected=1)
        mismatch = row(db, mismatch_id)
        assert mismatch["state"] == "failed" and mismatch["rc"] == 125
        assert mismatch["error"] == "invalid_persisted_request"
        assert records(record) == before

        # Fresh queued work is cancellable; terminal work is not.
        cancel_id = "job-22222222222222222222222222222222"
        insert_job(db, cancel_id, "queued", '{"image":"registry.example/app:1"}')
        cancelled = json.loads(run(executable, env, "cancel", cancel_id).stdout)
        assert cancelled["ok"] is True and cancelled["state"] == "cancelled"
        cancelled_row = row(db, cancel_id)
        assert (cancelled_row["state"], cancelled_row["rc"], cancelled_row["error"]) == (
            "cancelled", 130, "cancelled_by_user"
        )
        refused = json.loads(run(executable, env, "cancel", cancel_id, expected=1).stdout)
        assert refused["error"] == "container_job_not_cancellable"
        assert refused["state"] == "cancelled"

        if sys.platform.startswith("linux") and Path("/proc/self/comm").is_file():
            slow_request = {"confirm": True, "image": "registry.example/slow:1"}
            slow_submit = json.loads(run(
                executable, env, "create", json.dumps(slow_request)
            ).stdout)
            slow_id = slow_submit["job_id"]
            running = wait_state(db, slow_id, "running")
            assert running["worker_pid"] > 1
            slow_cancel = json.loads(run(executable, env, "cancel", slow_id).stdout)
            assert slow_cancel["ok"] is True and slow_cancel["state"] == "cancelled"
            slow_row = row(db, slow_id)
            assert (
                slow_row["state"], slow_row["worker_pid"], slow_row["rc"], slow_row["error"]
            ) == ("cancelled", 0, 130, "cancelled_by_user")
        else:
            print("skip: in-flight worker process-group cancellation requires Linux /proc")

        # Reconciliation converts interrupted running and stale queued jobs to failures.
        running_id = "job-33333333333333333333333333333333"
        stale_id = "job-44444444444444444444444444444444"
        fresh_id = "job-55555555555555555555555555555555"
        persisted = '{"image":"registry.example/app:1"}'
        insert_job(db, running_id, "running", persisted, pid=999999, age=1)
        insert_job(db, stale_id, "queued", persisted, age=10)
        insert_job(db, fresh_id, "queued", persisted, age=0)
        run(executable, env, "reconcile")
        for interrupted_id in (running_id, stale_id):
            interrupted = row(db, interrupted_id)
            assert interrupted["state"] == "failed"
            assert interrupted["rc"] == 125
            assert interrupted["error"] == "worker_interrupted"
            assert interrupted["worker_pid"] == 0
        assert row(db, fresh_id)["state"] == "queued"

        print("ok: isolated Docker container-create migration, job worker, argv, cancel, and reconcile")


if __name__ == "__main__":
    main()
