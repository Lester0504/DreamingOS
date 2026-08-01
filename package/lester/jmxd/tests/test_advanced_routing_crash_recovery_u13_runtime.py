#!/usr/bin/env python3
"""Executable fault tests for the U-13 advanced-routing publish journal."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
START = SOURCE.index("struct nc_adv_artifact {")
END = SOURCE.index("static int nc_adv_generate_rt_tables(", START)
IMPLEMENTATION = SOURCE[START:END]
CC = os.environ.get("CC", "cc")
CRASH_EXIT = 86
TXID = "1020304050607080"


def c_string(value: Path) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def build_harness(base: Path) -> Path:
    rt_dir = base / "rt"
    config_dir = base / "config"
    state_dir = base / "state"
    for directory in (rt_dir, config_dir, state_dir):
        directory.mkdir(mode=0o700)

    harness = base / "u13_harness.c"
    binary = base / "u13_harness"
    harness.write_text(
        f"""
#define _GNU_SOURCE
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int fault_count;
static int fault_at;
static void fault_point(const char *point)
{{
    (void)point;
    fault_count++;
    if (fault_at > 0 && fault_count == fault_at)
        _exit({CRASH_EXIT});
}}

#define LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
#define NC_ADV_RT_TABLES_DIR "{c_string(rt_dir)}"
#define NC_ADV_CONFIG_DIR "{c_string(config_dir)}"
#define NC_ADV_STATE_DIR "{c_string(state_dir)}"
#define NC_ADV_TRUSTED_UID ((uid_t)getuid())
#define NC_ADV_DIR_IS_TRUSTED(st) \
    ((((st).st_uid == 0) || ((st).st_uid == getuid())) && \
     (((st).st_mode & S_IWOTH) == 0))
#define NC_ADV_FSYNC_DIR(fd) (0)
#define NC_ADV_FAULT_POINT(point) fault_point(point)

{IMPLEMENTATION}

static int write_value(const char *path, const char *value, mode_t mode)
{{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    size_t len = strlen(value);
    int rc = fd < 0 || write(fd, value, len) != (ssize_t)len || fsync(fd) != 0;
    if (fd >= 0 && close(fd) != 0)
        rc = 1;
    return rc ? -1 : 0;
}}

static int seed_old(void)
{{
    char path[PATH_MAX];
    for (size_t i = 0; i < NC_ADV_ARTIFACT_COUNT; i++) {{
        if (snprintf(path, sizeof(path), "%s/%s", nc_adv_artifact_specs[i].dir_path,
                     nc_adv_artifact_specs[i].name) >= (int)sizeof(path) ||
            write_value(path, "old\\n", nc_adv_artifact_specs[i].mode) != 0)
            return -1;
    }}
    return 0;
}}

static int stage_and_publish(void)
{{
    struct nc_adv_artifact artifacts[NC_ADV_ARTIFACT_COUNT];
    uint64_t txid = nc_adv_transaction_id();

    if (txid == 0)
        txid = UINT64_C(0x{TXID});

    nc_adv_artifacts_init(artifacts, NC_ADV_ARTIFACT_COUNT);
    for (size_t i = 0; i < NC_ADV_ARTIFACT_COUNT; i++) {{
        if (nc_adv_artifact_open(&artifacts[i], txid, i) != 0) {{
            fprintf(stderr, "artifact_open[%zu]: %s\\n", i, strerror(errno));
            nc_adv_artifacts_abort(artifacts, NC_ADV_ARTIFACT_COUNT, 0);
            nc_adv_artifacts_close(artifacts, NC_ADV_ARTIFACT_COUNT);
            return -1;
        }}
        if (fputs("new\\n", artifacts[i].fp) < 0 ||
            nc_adv_artifact_finish(&artifacts[i]) != 0) {{
            fprintf(stderr, "artifact_finish[%zu]: %s\\n", i, strerror(errno));
            nc_adv_artifacts_abort(artifacts, NC_ADV_ARTIFACT_COUNT, 0);
            nc_adv_artifacts_close(artifacts, NC_ADV_ARTIFACT_COUNT);
            return -1;
        }}
    }}
    int rc = nc_adv_artifacts_publish(artifacts, NC_ADV_ARTIFACT_COUNT, txid,
                                      NC_ADV_JOURNAL_DIR);
    nc_adv_artifacts_close(artifacts, NC_ADV_ARTIFACT_COUNT);
    return rc;
}}

static int recover(void)
{{
    return nc_adv_recover_pending_publish();
}}

static int verify(const char *expected)
{{
    char path[PATH_MAX];
    char value[16];
    for (size_t i = 0; i < NC_ADV_ARTIFACT_COUNT; i++) {{
        int fd;
        ssize_t got;
        if (snprintf(path, sizeof(path), "%s/%s", nc_adv_artifact_specs[i].dir_path,
                     nc_adv_artifact_specs[i].name) >= (int)sizeof(path))
            return -1;
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
            return -1;
        got = read(fd, value, sizeof(value) - 1);
        close(fd);
        if (got < 0)
            return -1;
        value[got] = '\\0';
        if (strcmp(value, expected))
            return -1;
    }}
    return 0;
}}

int main(int argc, char **argv)
{{
    const char *fault = getenv("FAULT_AT");
    fault_at = fault ? atoi(fault) : 0;
    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "seed"))
        return seed_old() == 0 ? 0 : 1;
    if (!strcmp(argv[1], "publish"))
        return stage_and_publish() == 0 ? 0 : 1;
    if (!strcmp(argv[1], "recover"))
        return recover() == 0 ? 0 : 1;
    if (!strcmp(argv[1], "verify-old"))
        return verify("old\\n") == 0 ? 0 : 1;
    if (!strcmp(argv[1], "verify-new"))
        return verify("new\\n") == 0 ? 0 : 1;
    return 2;
}}
""",
        encoding="utf-8",
    )
    compiled = subprocess.run(
        [CC, "-std=c11", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert compiled.returncode == 0, compiled.stderr
    return binary


def run(binary: Path, operation: str, fault_at: int = 0, expected: int = 0) -> None:
    env = os.environ.copy()
    if fault_at:
        env["FAULT_AT"] = str(fault_at)
    result = subprocess.run(
        [str(binary), operation], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    assert result.returncode == expected, (
        f"{operation} fault={fault_at}: rc={result.returncode}, "
        f"stdout={result.stdout!r}, stderr={result.stderr!r}"
    )


def fresh_case(root: Path, name: str) -> tuple[Path, Path]:
    case = root / name
    case.mkdir(mode=0o700)
    binary = build_harness(case)
    run(binary, "seed")
    return case, binary


def test_publish_crashes(root: Path) -> None:
    # Prepared journal contributes four points, each old-file publish two,
    # committed journal two, then committed marker and four cleanup points.
    for point in range(1, 20):
        _, binary = fresh_case(root, f"publish-{point}")
        run(binary, "publish", fault_at=point, expected=CRASH_EXIT)
        run(binary, "recover")
        try:
            run(binary, "verify-old" if point < 14 else "verify-new")
        except AssertionError as error:
            raise AssertionError(f"publish point {point}: {error}") from error
        case = binary.parent
        debris = [
            path for directory in (case / "rt", case / "config", case / "state")
            for path in directory.iterdir()
            if path.name.endswith((".tmp", ".rollback")) or
            path.name == ".advanced_routing_publish.journal"
        ]
        assert not debris, f"publish point {point} left recovery debris: {debris}"


def test_recovery_crashes(root: Path) -> None:
    for publish_point, expected in ((11, "verify-old"), (14, "verify-new")):
        for recovery_point in range(1, 6):
            _, binary = fresh_case(root, f"recover-{publish_point}-{recovery_point}")
            run(binary, "publish", fault_at=publish_point, expected=CRASH_EXIT)
            result = subprocess.run(
                [str(binary), "recover"],
                env={**os.environ, "FAULT_AT": str(recovery_point)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if result.returncode == CRASH_EXIT:
                run(binary, "recover")
            else:
                assert result.returncode == 0, result.stderr
            run(binary, expected)


def test_fail_closed(root: Path) -> None:
    case, binary = fresh_case(root, "corrupt")
    run(binary, "publish", fault_at=11, expected=CRASH_EXIT)
    journal = case / "state" / ".advanced_routing_publish.journal"
    journal.write_bytes(b"corrupt")
    run(binary, "recover", expected=1)
    assert journal.exists(), "ambiguous journal must remain for operator recovery"

    case, binary = fresh_case(root, "symlink")
    run(binary, "publish", fault_at=11, expected=CRASH_EXIT)
    target = case / "config" / "dreamingwrt_advanced_routing"
    target.unlink()
    target.symlink_to(case / "outside")
    run(binary, "recover", expected=1)
    assert target.is_symlink(), "fail-closed recovery must not follow or replace symlinks"

    case, binary = fresh_case(root, "untrusted")
    run(binary, "publish", fault_at=11, expected=CRASH_EXIT)
    (case / "config").chmod(0o707)
    run(binary, "recover", expected=1)
    assert (case / "state" / ".advanced_routing_publish.journal").exists()


def main() -> None:
    # The implementation verifies every parent directory.  A source checkout
    # may be owned by another account when CI runs as root, so keep the runtime
    # fixture under the executing account's trusted home instead.
    runtime_parent = Path.home()
    temp = Path(tempfile.mkdtemp(prefix=".u13-crash-", dir=runtime_parent))
    try:
        test_publish_crashes(temp)
        test_recovery_crashes(temp)
        test_fail_closed(temp)
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    print("ok: U-13 durable journal recovers every injected publish/recovery crash")


if __name__ == "__main__":
    main()
