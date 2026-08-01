#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def json_c_flags() -> tuple[list[str], list[str]]:
    configured = os.environ.get("STORAGE_TEST_JSON_C_ROOT", "")
    if configured:
        prefix = Path(configured)
        assert (prefix / "include/json-c/json.h").is_file()
        return (["-I", str(prefix / "include")],
                ["-L", str(prefix / "lib"), "-ljson-c",
                 f"-Wl,-rpath,{prefix / 'lib'}"])
    probe = subprocess.run(["pkg-config", "--cflags", "--libs", "json-c"],
                           text=True, capture_output=True)
    if probe.returncode == 0:
        flags = probe.stdout.split()
        return ([flag for flag in flags if flag.startswith("-I")],
                [flag for flag in flags if not flag.startswith("-I")])
    raise AssertionError("json-c development files unavailable")


def main() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
    assert compiler
    cflags, libs = json_c_flags()
    with tempfile.TemporaryDirectory(prefix="storage-extents-") as raw:
        temp = Path(raw)
        lsblk = temp / "lsblk"
        sfdisk = temp / "sfdisk"
        binary = temp / "fixture"
        lsblk.write_text("""#!/bin/sh
cat <<'EOF'
{"blockdevices":[{"name":"sdb","path":"/dev/sdb","type":"disk","size":107374182400,"pttype":"gpt","log-sec":512,"phy-sec":4096,"children":[{"name":"sdb1","path":"/dev/sdb1","type":"part","size":53687091200,"fstype":"ext4"}]}]}
EOF
""", encoding="ascii")
        sfdisk.write_text("""#!/bin/sh
case "$SFDISK_MODE" in
  valid) printf '%s\n' '{"partitiontable":{"sectorsize":512,"partitions":[{"start":104859648,"size":104847360}]}}' ;;
  overlap) printf '%s\n' '{"partitiontable":{"sectorsize":512,"partitions":[{"start":4096,"size":100},{"start":4000,"size":100}]}}' ;;
  bounds) printf '%s\n' '{"partitiontable":{"sectorsize":512,"partitions":[{"start":209715199,"size":2}]}}' ;;
  *) exit 9 ;;
esac
""", encoding="ascii")
        lsblk.chmod(0o755)
        sfdisk.chmod(0o755)
        subprocess.run([
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            f'-DSTORAGE_BLOCKDEV_LSBLK_PATH="{lsblk}"',
            f'-DSTORAGE_BLOCKDEV_SFDISK_PATH="{sfdisk}"',
            "-I", str(ROOT / "src"), *cflags,
            str(ROOT / "src/storage/storage_blockdev.c"),
            str(ROOT / "tests/test_storage_blockdev_extents_fixture.c"),
            *libs, "-o", str(binary),
        ], check=True)

        def disk(mode: str) -> dict:
            env = os.environ.copy()
            env["SFDISK_MODE"] = mode
            output = subprocess.run([str(binary)], env=env, text=True,
                                    capture_output=True, check=True).stdout
            return json.loads(output)["storage"]["disks"][0]

        valid = disk("valid")
        assert valid["unallocated_space_supported"] is True
        assert valid["unallocated_bytes"] == 104847360 * 512
        assert valid["unallocated_extents"] == [{
            "start_sector": 104859648,
            "end_sector": 209707007,
            "sector_count": 104847360,
            "capacity_bytes": 104847360 * 512,
        }]
        assert valid["unallocated_source"] == "sfdisk_partition_table_free_regions"
        for mode, reason in (("failure", "sfdisk_list_free_failed"),
                             ("overlap", "sfdisk_invalid_free_extent"),
                             ("bounds", "sfdisk_free_extent_out_of_bounds")):
            rejected = disk(mode)
            assert rejected["unallocated_space_supported"] is False
            assert rejected["unallocated_bytes"] is None
            assert rejected["unallocated_extents"] == []
            assert rejected["unallocated_reason"] == reason

    print("ok: storage partition free extents are authoritative and fail closed")


if __name__ == "__main__":
    main()
