#!/usr/bin/env python3
"""Check superfan PWM readback against exact and EMC2305 thermal drivers."""

from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "tools/qsdk-superfan-control.sh").read_text()
    functions = []
    for name in ("clamp", "is_uint", "write_pwm"):
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.M | re.S)
        assert match, name
        functions.append(match.group())
    shell = "\n".join(functions) + r"""
fan_file="$1"
pwm_max_state="$2"
readback="$3"
cat() {
    command cat "$@" >/dev/null || return 1
    printf '%s\n' "$readback"
}
write_pwm "$4"
"""
    cases = [
        (0, "38", 38, True),
        (0, "26", 38, False),
        (10, "26", 38, True),
        (10, "51", 38, True),
        (10, "0", 38, False),
        (10, "255", 255, True),
        (10, "230", 255, False),
        (10, "invalid", 38, False),
        (10, "300", 38, False),
    ]
    with tempfile.TemporaryDirectory(prefix="superfan-pwm-") as raw:
        path = Path(raw) / "pwm"
        for states, actual, target, expected in cases:
            result = subprocess.run(
                ["sh", "-c", shell, "superfan-test", str(path),
                 str(states), actual, str(target)],
                capture_output=True, text=True, timeout=3,
            )
            assert (result.returncode == 0) == expected, (
                states, actual, target, result.returncode, result.stderr,
            )
            assert path.read_text() == f"{target}\n"
        result = subprocess.run(
            ["sh", "-c", shell, "superfan-test", str(Path(raw) / "missing/pwm"),
             "10", "26", "38"],
            capture_output=True, text=True, timeout=3,
        )
        assert result.returncode != 0
        assert not result.stderr, result.stderr
        poisoned_printf = shell.replace(
            'write_pwm "$4"',
            'printf() { command printf "$@"; return 1; }\nwrite_pwm "$4"',
        )
        result = subprocess.run(
            ["sh", "-c", poisoned_printf, "superfan-test", str(path),
             "10", "26", "38"],
            capture_output=True, text=True, timeout=3,
        )
        assert result.returncode == 0, result.stderr
        assert path.read_text() == "38\n"
        if Path("/dev/full").exists():
            result = subprocess.run(
                ["sh", "-c", shell, "superfan-test", "/dev/full",
                 "10", "26", "38"],
                capture_output=True, text=True, timeout=3,
            )
            assert result.returncode != 0
    assert 'detect_pwm_resolution\nif ! validate_settings' in source
    assert '${pwm_readback:-$pwm}' in source
    print("ok: exact/quantized PWM, thermal override, procd printf and write failures")


if __name__ == "__main__":
    main()
