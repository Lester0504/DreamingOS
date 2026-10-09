#!/usr/bin/env python3
"""Exercise the opt-in QSDK RRM forwarding ownership lifecycle."""

from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def check_init_runtime_directory(root: Path) -> None:
    state = root / "init-state"
    runtime = root / "init-runtime"
    state.mkdir()
    command = """
. "$1"
APD_BIN="$2"
APD_STATE_DIR="$3"
APD_RUNTIME_DIR="$4"
procd_open_instance() { :; }
procd_set_param() { :; }
procd_close_instance() { :; }
start_service
"""
    args = [
        "sh", "-eu", "-c", command, "sh",
        str(ROOT / "files/dreamingwrt-apd.init"),
        shutil.which("true"), str(state), str(runtime),
    ]
    subprocess.run(args, check=True, capture_output=True, text=True)
    assert not runtime.exists(), "opt-out startup must stay inert"
    (state / "rrm-forward.conf").touch()
    subprocess.run(args, check=True, capture_output=True, text=True)
    assert runtime.is_dir(), "opt-in startup must create the journal directory"
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o750


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-rrm-forward-") as raw:
        check_init_runtime_directory(Path(raw))
        binary = Path(raw) / "fixture"
        built = subprocess.run(
            [
                "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Werror", str(ROOT / "tests/apd_rrm_forward_fixture.c"),
                "-o", str(binary),
            ],
            cwd=raw,
            capture_output=True,
            text=True,
        )
        assert built.returncode == 0, built.stderr
        result = subprocess.run(
            [str(binary)], cwd=raw, capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, result.stderr
        print(result.stdout.strip())


if __name__ == "__main__":
    main()
