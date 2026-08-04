#!/usr/bin/env python3
"""Contract tests for the TOTP gate on irreversible operations."""
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "src/webd/jmx_app_api.c"
HARNESS = ROOT / "tests/webd_otp_gate_fixture.c"


def _flags() -> list[str]:
    result = subprocess.run(
        ["pkg-config", "--cflags", "--libs", "sqlite3", "openssl"],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return ["-lsqlite3", "-lcrypto"]
    return shlex.split(result.stdout)


def test_factory_reset_is_gated_and_audited_before_execution() -> None:
    """The gate must run before the wipe, and the audit must be durable first.

    Ordering is the whole point: a factory reset destroys the storage the audit
    row lives on, so a record written afterwards is a record that never existed.
    """
    source = API.read_text(encoding="utf-8")

    for marker in (
        "webd_otp_gate_check",
        "webd_otp_gate_error",
        "jmx_app_audit_log_durable",
        "WEBD_OTP_GATE_CHANNEL_FORBIDDEN",
        "twofa_required_not_bound",
        "otp_required",
        "otp_invalid",
        "otp_channel_not_supported",
        "requires_otp",
        "SQLITE_CHECKPOINT_TRUNCATE",
    ):
        assert marker in source, f"missing OTP gate contract: {marker}"

    # The gate consumes the counter itself, so a code cannot be spent twice.
    gate = source[source.index("webd_otp_gate_check(const char *identity"):]
    gate = gate[: gate.index("\n}\n")]
    assert "webd_user_twofa_touch_counter" in gate, (
        "the gate must consume the matched counter, otherwise a code is replayable"
    )
    assert "webd_identity_is_user" in gate, (
        "API-Key and app-device callers must be refused, not exempted"
    )

    # Ordering inside the factory_reset route.
    route = source[source.index('"/api/v1/system/flash/factory_reset"'):]
    route = route[: route.index("/api/v1/system/flash/preserve_config")]
    gate_at = route.index("webd_otp_gate_check")
    audit_at = route.index("jmx_app_audit_log_durable")
    invoke_at = route.index('app_ubus_core_route("system_flash_factory_reset"')
    assert gate_at < audit_at < invoke_at, (
        "order must be: verify OTP, persist audit durably, then execute"
    )

    # A build missing the core method is a contract gap, not a transient 500.
    helper = source[source.index("static struct json_object *app_ubus_core_route"):]
    helper = helper[: helper.index("\n}\n")]
    assert "UBUS_STATUS_METHOD_NOT_FOUND" in helper
    assert '*http_status = 501' in helper
    assert 'webd_error("method_not_registered"' in helper


def test_compiled_replay_guard_runtime() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    assert compiler, "a C compiler is required"
    with tempfile.TemporaryDirectory(prefix="webd-otp-gate-") as temp_name:
        executable = Path(temp_name) / "webd_otp_gate_fixture"
        build = subprocess.run(
            [compiler, "-O1", "-Wall", "-Wextra", "-o", str(executable), str(HARNESS)]
            + _flags(),
            text=True,
            capture_output=True,
        )
        assert build.returncode == 0, build.stderr
        run = subprocess.run([str(executable)], text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + run.stderr
        assert "all checks passed" in run.stdout
