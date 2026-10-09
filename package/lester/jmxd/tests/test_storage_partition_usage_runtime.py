#!/usr/bin/env python3
"""Partition usage and placement must be measured, not invented.

Acceptance reported (user item 2) that `storage_partitions` published no
start_sector/end_sector and no usage at all, so the UI could only show "--" and
"usage unknown". These helpers are lifted verbatim out of
src/storage/storage_blockdev.c, compiled, and run against real paths on this
machine; the usage figures are then reconciled against the OS's own numbers.

The unmounted case is asserted too: usage there must be an explicit
usage_available=false plus usage_reason=not_mounted, so the frontend can tell a
physical limit from a missing backend feature.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/storage/storage_blockdev.c"
FIXTURE = ROOT / "tests/storage_partition_usage_fixture.c"

MARKERS = (
    "static int64_t blkdev_sysfs_u64(const char *name, const char *attr)",
    "static void blkdev_add_partition_extent(struct json_object *part,",
    "static void blkdev_add_partition_usage(struct json_object *part,",
)
SYSFS_ROOT_LITERAL = '"/sys/class/block/%s/%s"'
HELPERS = (
    "static void blkdev_add_str(struct json_object *o, const char *key,",
    "static void blkdev_add_i64(struct json_object *o, const char *key, int64_t v)",
)

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def take_block(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise SystemExit("FAIL: marker not found in storage_blockdev.c: " + marker)
    brace = source.find("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise SystemExit("FAIL: unbalanced braces after " + marker)


def json_c_flags() -> tuple[list[str], list[str]]:
    """Locate json-c on both the Mac workstation and the dev-tree host.

    31.6 ships a libjson-c.a built with a mismatched LTO version that cannot
    link, and has no pkg-config entry, so a real shared object has to be found.
    The shared resolver does that and is not tied to one machine's layout.
    """
    configured = os.environ.get("STORAGE_TEST_JSON_C_ROOT", "")
    if configured:
        prefix = Path(configured)
        cflags = ["-I", str(prefix / "include")]
        if (prefix / "lib/libjson-c.dylib").is_file():
            return (cflags, ["-L", str(prefix / "lib"), "-ljson-c"])
        if (prefix / "lib/libjson-c.so").is_file():
            return (cflags, ["-L", str(prefix / "lib"),
                             "-Wl,-rpath," + str(prefix / "lib"), "-ljson-c"])
    return apd_test_deps.split_package_flags("json-c")


def main() -> None:
    src = SRC.read_text()

    # The partition builder must actually call both helpers.
    builder = take_block(
        src, "static struct json_object *blkdev_partition_from_lsblk(")
    check("blkdev_add_partition_extent(part, name)" in builder,
          "blkdev_partition_from_lsblk() does not publish start/end sectors")
    check("blkdev_add_partition_usage(part," in builder,
          "blkdev_partition_from_lsblk() does not publish partition usage")

    unit = ["#define _GNU_SOURCE", "#include <errno.h>", "#include <limits.h>",
            "#include <stdint.h>", "#include <stdio.h>", "#include <stdlib.h>",
            "#include <string.h>", "#include <sys/statvfs.h>",
            "#include <json-c/json.h>", '#include "usage_under_test.h"', ""]
    for marker in HELPERS + MARKERS:
        unit.append(take_block(src, marker))
        unit.append("")

    # The traversal guard has to be provable on a machine without /sys (this
    # test also runs on the Mac workstation). Point the extracted sysfs reader at
    # a temp directory that really does contain start/size files, so a device
    # name that escapes it would otherwise succeed.
    check(SYSFS_ROOT_LITERAL in src,
          "sysfs geometry path changed; update this test's root redirection")

    header = "\n".join([
        "#ifndef USAGE_UNDER_TEST_H",
        "#define USAGE_UNDER_TEST_H",
        "#include <json-c/json.h>",
        "void blkdev_add_partition_extent(struct json_object *part,",
        "                                const char *name);",
        "void blkdev_add_partition_usage(struct json_object *part,",
        "                               const char *mount_point, int mounted);",
        "#endif",
        "",
    ])

    cflags, libs = json_c_flags()
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
    check(compiler is not None, "no C compiler available")
    if not compiler:
        print("FAIL: no C compiler available")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="storage-usage-") as raw:
        tmp = Path(raw)
        (tmp / "usage_under_test.h").write_text(header)
        # The extracted helpers are static in the shipped file; drop the keyword
        # so the fixture can link against them unchanged otherwise.
        body = "\n".join(unit)
        body = body.replace("static void blkdev_add_partition_extent(",
                            "void blkdev_add_partition_extent(")
        body = body.replace("static void blkdev_add_partition_usage(",
                            "void blkdev_add_partition_usage(")
        # Redirect only the directory prefix; the guard itself is untouched.
        fake_sysfs = tmp / "sysfs"
        (fake_sysfs / "sdz9").mkdir(parents=True)
        (fake_sysfs / "sdz9" / "start").write_text("2048\n")
        (fake_sysfs / "sdz9" / "size").write_text("4096\n")
        # A sibling the traversal attempt would reach if the guard were gone.
        (fake_sysfs.parent / "outside").mkdir()
        (fake_sysfs.parent / "outside" / "start").write_text("999999\n")
        (fake_sysfs.parent / "outside" / "size").write_text("512\n")
        body = body.replace(SYSFS_ROOT_LITERAL,
                            '"' + str(fake_sysfs) + '/%s/%s"')
        (tmp / "usage_under_test.c").write_text(body)
        binary = tmp / "usage_fixture"
        built = subprocess.run(
            [compiler, "-std=gnu11", "-Wall", "-O1", "-I", str(tmp), *cflags,
             str(tmp / "usage_under_test.c"), str(FIXTURE), *libs,
             "-o", str(binary)],
            capture_output=True, text=True)
        if built.returncode != 0:
            print("FAIL: could not compile the extracted usage helpers")
            print(built.stderr[-4000:])
            sys.exit(1)

        probe_root = "/"
        run = subprocess.run(
            [str(binary), "sdz9:" + probe_root, "definitely_not_a_block_dev:",
             "../outside:" + probe_root],
            capture_output=True, text=True, timeout=30)
        if run.returncode != 0:
            print("FAIL: fixture exited " + str(run.returncode))
            print(run.stderr[-4000:])
            sys.exit(1)
        rows = json.loads(run.stdout)

    mounted = rows[0]
    check(mounted.get("start_sector") == 2048,
          "geometry was not read from sysfs: expected start_sector 2048, got "
          + repr(mounted.get("start_sector")))
    check(mounted.get("end_sector") == 2048 + 4096 - 1,
          "end_sector must be inclusive (start + size - 1), got "
          + repr(mounted.get("end_sector")))
    check(mounted.get("extent_source") == "sysfs_block_geometry",
          "extent_source must name where the geometry came from")
    check(mounted["usage_available"] is True,
          "usage on a mounted filesystem must be available, got reason "
          + str(mounted.get("usage_reason")))
    check(mounted.get("usage_source") == "statvfs",
          "usage_source must name where the numbers came from")
    for key in ("used_bytes", "available_bytes", "filesystem_total_bytes"):
        check(isinstance(mounted.get(key), int) and mounted[key] >= 0,
              key + " must be a real byte count, got " + repr(mounted.get(key)))
    check(isinstance(mounted.get("usage_percent"), (int, float)),
          "usage_percent must be numeric for a mounted filesystem")

    # Reconcile with the OS: same source of truth statvfs reads, so the totals
    # must agree closely. A few blocks of drift is normal on a live filesystem.
    vfs = os.statvfs(probe_root)
    expected_total = vfs.f_blocks * vfs.f_frsize
    check(abs(mounted["filesystem_total_bytes"] - expected_total)
          <= vfs.f_frsize * 16,
          "filesystem_total_bytes " + str(mounted["filesystem_total_bytes"]) +
          " disagrees with os.statvfs " + str(expected_total))
    expected_used = (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize
    drift = abs(mounted["used_bytes"] - expected_used)
    check(drift <= max(expected_total // 100, vfs.f_frsize * 4096),
          "used_bytes " + str(mounted["used_bytes"]) +
          " is not within tolerance of " + str(expected_used))
    if mounted["usage_percent"] is not None:
        check(0.0 <= mounted["usage_percent"] <= 100.0,
              "usage_percent out of range: " + str(mounted["usage_percent"]))

    unmounted = rows[1]
    check(unmounted["usage_available"] is False,
          "an unmounted partition must not claim usable numbers")
    check(unmounted.get("usage_reason") == "not_mounted",
          "an unmounted partition must say not_mounted, got "
          + str(unmounted.get("usage_reason")))
    check(unmounted.get("used_bytes") is None,
          "an unmounted partition must report null usage, not 0")
    check(unmounted.get("start_sector") is None and
          unmounted.get("extent_reason") ==
          "sysfs_partition_geometry_unavailable",
          "a nonexistent block device must report the geometry as unavailable "
          "with a reason, got " + repr(unmounted.get("extent_reason")))

    # A name containing a path separator must never be used to build a sysfs
    # path; it has to be rejected outright.
    traversal = rows[2]
    check(traversal.get("start_sector") is None,
          "a device name containing '/' must be rejected, not resolved; it "
          "resolved to start_sector " + repr(traversal.get("start_sector")))
    check(traversal.get("extent_reason") ==
          "sysfs_partition_geometry_unavailable",
          "path traversal in the device name must fail closed")

    if failures:
        for item in failures:
            print("FAIL: " + item)
        sys.exit(1)
    print("ok: partition usage measured via statvfs and reconciled with the OS; "
          "geometry from sysfs fails closed")


if __name__ == "__main__":
    main()
