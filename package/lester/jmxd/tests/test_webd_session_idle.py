#!/usr/bin/env python3
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/webd/webd_session_idle.c"
HEADER = ROOT / "src/webd/webd_session_idle.h"
HARNESS = ROOT / "tests/webd_session_idle_test.c"
MAKEFILE = ROOT / "src/Makefile"


def sqlite_flags() -> list[str]:
    result = subprocess.run(
        ["pkg-config", "--cflags", "--libs", "sqlite3"],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, "sqlite3 development files are required"
    return shlex.split(result.stdout)


def test_module_contract_markers() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    for marker in (
        "WEBD_SESSION_IDLE_MIN_MIN 1",
        "WEBD_SESSION_IDLE_MAX_MIN 1440",
        "WEBD_SESSION_IDLE_TOUCH_INTERVAL_S 30",
        'WEBD_SESSION_IDLE_ERROR "web_session_idle_timeout"',
        "webd_session_idle_access_check",
        "webd_session_idle_refresh_issue",
    ):
        assert marker in header, f"missing idle-session contract: {marker}"
    for marker in (
        "web_login_timeout_min",
        "last_activity_at",
        "session_id",
        "BEGIN IMMEDIATE",
        "idle_timeout_recheck_and_revoke",
        "WHERE username=?1 AND session_id=?2 AND revoked=0",
    ):
        assert marker in source, f"missing idle-session implementation: {marker}"
    assert "webd/webd_session_idle.o" in makefile
    assert "jmx_app_api" not in source
    assert "json-c" not in source


def test_compiled_sqlite_runtime_contract() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    assert compiler, "a C compiler is required"
    with tempfile.TemporaryDirectory(prefix="webd-session-idle-") as temp_name:
        executable = Path(temp_name) / "webd_session_idle_test"
        command = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT / "src/webd"),
            str(SOURCE),
            str(HARNESS),
            "-o",
            str(executable),
            *sqlite_flags(),
        ]
        compiled = subprocess.run(command, text=True, capture_output=True)
        assert compiled.returncode == 0, compiled.stderr
        ran = subprocess.run(
            [str(executable)], text=True, capture_output=True, timeout=10
        )
        assert ran.returncode == 0, ran.stderr + ran.stdout
        assert "webd_session_idle_runtime_ok" in ran.stdout


if __name__ == "__main__":
    test_module_contract_markers()
    test_compiled_sqlite_runtime_contract()
    print("ok: web session idle timeout helper contracts")
