#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def json_c_flags() -> tuple[list[str], list[str]]:
    """Locate json-c on both the Mac workstation and the dev-tree host.

    31.6 has no pkg-config entry for json-c and its libjson-c.a is built with a
    mismatched LTO version, so a linkable shared object has to be found instead.
    The shared resolver does that, and derives the staging_dir from this file's
    location rather than a hard-coded /home/lester path.
    """
    configured = os.environ.get("STORAGE_TEST_JSON_C_ROOT", "")
    if configured:
        prefix = Path(configured)
        cflags = ["-I", str(prefix / "include")]
        if (prefix / "lib/libjson-c.dylib").is_file():
            return (cflags, ["-L", str(prefix / "lib"), "-ljson-c"])
        if (prefix / "lib/libjson-c.so").is_file():
            return (cflags, ["-L", str(prefix / "lib"), "-ljson-c",
                             f"-Wl,-rpath,{prefix / 'lib'}"])
    return apd_test_deps.split_package_flags("json-c")


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
        # Real sfdisk (util-linux 2.42.2 on the lab router) refuses to combine
        # these two flags:
        #   sfdisk: options --json and --list-free cannot be combined
        # The previous fixture answered regardless of argv, so this test stayed
        # green while the feature could never work on a real device. It now
        # rejects the combination exactly like the shipped tool does, and serves
        # the partition table for a plain --json call.
        sfdisk.write_text("""#!/bin/sh
want_json=0
want_list_free=0
for arg in "$@"; do
  case "$arg" in
    --json) want_json=1 ;;
    --list-free) want_list_free=1 ;;
  esac
done
if [ "$want_json" = 1 ] && [ "$want_list_free" = 1 ]; then
  echo "sfdisk: options --json and --list-free cannot be combined" >&2
  exit 1
fi
if [ "$want_json" != 1 ]; then
  echo "sfdisk: unsupported invocation in fixture" >&2
  exit 9
fi
case "$SFDISK_MODE" in
  valid) printf '%s\\n' '{"partitiontable":{"sectorsize":512,"firstlba":2048,"lastlba":209715166,"partitions":[{"start":2048,"size":104857600}]}}' ;;
  overlap) printf '%s\\n' '{"partitiontable":{"sectorsize":512,"firstlba":2048,"lastlba":209715166,"partitions":[{"start":4096,"size":100},{"start":4000,"size":100}]}}' ;;
  bounds) printf '%s\\n' '{"partitiontable":{"sectorsize":512,"firstlba":2048,"lastlba":209715166,"partitions":[{"start":209715199,"size":2}]}}' ;;
  nofree) printf '%s\\n' '{"partitiontable":{"sectorsize":512,"firstlba":2048,"lastlba":209715166,"partitions":[{"start":2048,"size":209713119}]}}' ;;
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

        # One 50GiB partition at sector 2048 inside a 100GiB disk: the free tail
        # runs from 104859648 to lastlba (209715166).
        valid = disk("valid")
        assert valid["unallocated_space_supported"] is True, \
            f'unallocated space still unsupported: {valid.get("unallocated_reason")!r}'
        free_sectors = 209715166 - 104859648 + 1
        assert valid["unallocated_bytes"] == free_sectors * 512, \
            f'unexpected free bytes {valid["unallocated_bytes"]}'
        assert valid["unallocated_extents"] == [{
            "start_sector": 104859648,
            "end_sector": 209715166,
            "sector_count": free_sectors,
            "capacity_bytes": free_sectors * 512,
        }], valid["unallocated_extents"]
        assert valid["unallocated_source"] == "sfdisk_partition_table_free_regions"

        # A fully allocated disk is a supported answer of zero, not a failure.
        nofree = disk("nofree")
        assert nofree["unallocated_space_supported"] is True, \
            f'fully allocated disk reported as unsupported: {nofree.get("unallocated_reason")!r}'
        assert nofree["unallocated_bytes"] == 0, nofree["unallocated_bytes"]
        assert nofree["unallocated_extents"] == []

        for mode, reason in (("failure", "sfdisk_json_failed"),
                             ("overlap", "sfdisk_invalid_partition_extent"),
                             ("bounds", "sfdisk_partition_out_of_bounds")):
            rejected = disk(mode)
            assert rejected["unallocated_space_supported"] is False
            assert rejected["unallocated_bytes"] is None
            assert rejected["unallocated_extents"] == []
            assert rejected["unallocated_reason"] == reason, \
                f'{mode}: got {rejected["unallocated_reason"]!r}'

        # Per-partition placement and usage. The fixture disk is "sdb1", which
        # does not exist under /sys/class/block here, so the honest answer is a
        # null with a reason rather than a fabricated zero.
        partition = valid["partitions"][0]
        for key in ("start_sector", "end_sector", "sector_count"):
            assert key in partition, f"partition object is missing {key}"
        if partition["start_sector"] is None:
            assert partition["extent_reason"] == \
                "sysfs_partition_geometry_unavailable", \
                f'unexpected extent_reason {partition.get("extent_reason")!r}'
        else:
            assert partition["end_sector"] == \
                partition["start_sector"] + partition["sector_count"] - 1
            assert partition["extent_source"] == "sysfs_block_geometry"

        for key in ("used_bytes", "available_bytes", "usage_percent",
                    "usage_available"):
            assert key in partition, f"partition object is missing {key}"
        # Unmounted in the fixture: usage must be an explicit unavailable, and
        # the reason must distinguish it from a backend that never tried.
        assert partition["usage_available"] is False
        assert partition["usage_reason"] == "not_mounted", \
            f'unexpected usage_reason {partition.get("usage_reason")!r}'
        assert partition["used_bytes"] is None
        assert partition["available_bytes"] is None

    print("ok: storage partition free extents are authoritative and fail closed")


if __name__ == "__main__":
    main()
