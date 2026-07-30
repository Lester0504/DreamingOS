#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
FIXTURE = ROOT / "tests/jmx_defensive_runtime_fixture.c"


def json_c_flags() -> list[str]:
    pkg_config = shutil.which("pkg-config")
    if pkg_config:
        result = subprocess.run(
            [pkg_config, "--cflags", "--libs", "json-c"],
            text=True, capture_output=True,
        )
        if result.returncode == 0:
            return shlex.split(result.stdout)
    brew = shutil.which("brew")
    if brew:
        prefix = subprocess.check_output(
            [brew, "--prefix", "json-c"], text=True
        ).strip()
        return [f"-I{prefix}/include", f"-L{prefix}/lib", "-ljson-c",
                f"-Wl,-rpath,{prefix}/lib"]
    raise AssertionError("json-c development files unavailable")


def run(binary: Path, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *args], text=True, capture_output=True, check=check,
    )


def compile_fixture(temp: Path, proc_root: Path, ifstatus: Path) -> Path:
    compiler = shutil.which("cc") or shutil.which("clang")
    assert compiler, "host C compiler unavailable"
    binary = temp / "jmx-defensive-runtime"
    subprocess.run([
        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-DJMX_NETWORK_DEFENSIVE_ONLY=1",
        f'-DJMX_PROC_SYS_ROOT="{proc_root}"',
        f'-DJMX_IFSTATUS_PATH="{ifstatus}"',
        f"-I{SOURCE}", str(SOURCE / "jmx_utils.c"),
        str(SOURCE / "jmx_network.c"), str(FIXTURE),
        *json_c_flags(), "-o", str(binary),
    ], check=True)
    return binary


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="jmx-defensive-") as temporary:
        temp = Path(temporary)
        proc_root = temp / "proc"
        proc_root.mkdir()
        loopback = "lo0" if os.uname().sysname == "Darwin" else "lo"
        for name, value in {
            "lan_ifname": "x" * len(loopback), "lan_ip": "0", "lan_mask": "0",
            "record_enable": "0", "work_mode": "0",
        }.items():
            (proc_root / name).write_text(value, encoding="ascii")

        marker = temp / "shell-marker"
        ifstatus = temp / "ifstatus"
        ifstatus.write_text(
            "#!/bin/sh\n"
            "printf '%s' \"$1\"\n",
            encoding="ascii",
        )
        ifstatus.chmod(0o755)
        binary = compile_fixture(temp, proc_root, ifstatus)

        assert run(binary, "proc", "lan_ifname", loopback).returncode == 0
        assert (proc_root / "lan_ifname").read_text(encoding="ascii") == loopback
        (proc_root / "lan_ifname").write_text("long-interface", encoding="ascii")
        assert run(binary, "proc", "lan_ifname", loopback).returncode == 1
        assert (proc_root / "lan_ifname").read_text(encoding="ascii") != loopback
        (proc_root / "lan_ifname").write_text(loopback, encoding="ascii")
        assert run(binary, "proc", "../../escape", "1").returncode == 1
        assert run(binary, "proc", "work_mode", "1;touch x").returncode == 1
        assert run(binary, "proc", "lan_ifname", "x;touch y").returncode == 1
        assert not marker.exists()
        assert (proc_root / "work_mode").read_text(encoding="ascii") == "0"

        injected = f"lo;touch {marker}"
        captured = run(binary, "capture", injected)
        assert captured.returncode == 1
        assert not marker.exists()
        valid = run(binary, "capture", "wan.test-1", check=True)
        assert valid.stdout == "wan.test-1"

        good = {
            "ipv4-address": [{"address": "192.0.2.10", "mask": 24}],
            "route": [{"nexthop": "192.0.2.1"}],
            "dns-server": ["1.1.1.1", "8.8.8.8"],
            "ipv6-address": [
                {"address": "fe80::1"}, {"address": "2001:db8::5"}
            ],
        }
        parsed = run(binary, "parse", json.dumps(good), check=True)
        assert parsed.stdout.strip() == (
            "192.0.2.10|255.255.255.0|192.0.2.1|1.1.1.1|8.8.8.8|2001:db8::5"
        )
        invalid = [
            {**good, "ipv4-address": [{"address": 1234, "mask": 24}]},
            {**good, "ipv4-address": [{"address": "192.0.2.010", "mask": 24}]},
            {**good, "ipv4-address": [{"address": "192.0.2.10", "mask": "24"}]},
            {**good, "ipv4-address": [{"address": "192.0.2.10", "mask": 33}]},
            {**good, "route": [{"nexthop": "x" * 256}]},
            {**good, "dns-server": ["1.1.1.01"]},
        ]
        for payload in invalid:
            assert run(binary, "parse", json.dumps(payload)).returncode == 1
        assert run(binary, "parse", json.dumps(good) + "garbage").returncode == 1

        assert run(binary, "ifname", "br-lan", "0").returncode == 0
        assert run(binary, "ifname", "br lan", "0").returncode == 1
        assert run(binary, "ifname", "x" * 64, "0").returncode == 1
        assert run(binary, "ifname", loopback, "1").returncode == 0
        assert run(binary, "ifname", "definitely-missing", "1").returncode == 1


def test_system_transaction_contract() -> None:
    system = (SOURCE / "jmx_system.c").read_text(encoding="utf-8")
    start = system.index("struct json_object *jmx_api_set_system_info")
    end = system.index("static int jmx_mount_json_bool", start)
    body = system[start:end]
    validate = body.index("jmx_interface_name_valid(lan_ifname, 1)")
    read_old = body.index("jmx_legacy_settings_get(&old_settings)")
    runtime = body.index('jmx_update_proc_value("lan_ifname", lan_ifname)')
    commit = body.index("jmx_legacy_settings_set_system(lan_ifname, theme_mode)")
    rollback = body.index('jmx_update_proc_value("lan_ifname", old_settings.lan_ifname)')
    assert validate < read_old < runtime < commit < rollback
    assert "update_jmx_proc_value(\"lan_ifname\", lan_ifname)" not in body

    utils = (SOURCE / "jmx_utils.c").read_text(encoding="utf-8")
    network = (SOURCE / "jmx_network.c").read_text(encoding="utf-8")
    assert "system(cmd_buf)" not in utils
    assert 'sprintf(file_path, "/proc/sys/dreamingwrt/jmx/%s"' not in utils
    assert "popen(cmd, \"r\")" not in network
    assert "strcpy(status->" not in network


if __name__ == "__main__":
    test_runtime()
    test_system_transaction_contract()
    print("ok: U-01/U-05/U-06 defensive runtime contracts")
