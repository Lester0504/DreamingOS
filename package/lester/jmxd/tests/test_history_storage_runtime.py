#!/usr/bin/env python3
"""Compile the production U-02 fd helpers and exercise destructive boundaries."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")


def production_helpers() -> str:
    start = SOURCE.index("#define JMX_HISTORY_MAX_DEPTH")
    end = SOURCE.index("struct json_object *jmx_api_get_record_base(", start)
    helpers = SOURCE[start:end]
    helpers = re.sub(
        r"static struct json_object \*jmx_history_error\(.*?\n}\n\n",
        "",
        helpers,
        count=1,
        flags=re.S,
    )
    return helpers


def c_string(value: Path) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def main() -> None:
    compiler = shutil.which("cc") or shutil.which("clang")
    assert compiler, "host C compiler unavailable"
    with tempfile.TemporaryDirectory(prefix="jhu02-", dir="/tmp") as temporary:
        temp = Path(temporary)
        root = temp / "mnt" / "disk"
        root.mkdir(parents=True)
        device = root.stat().st_dev
        mountinfo = temp / "mountinfo"
        mountinfo.write_text(
            f"91 1 {os.major(device)}:{os.minor(device)} / {root} rw,relatime "
            "- ext4 /dev/test rw\n",
            encoding="utf-8",
        )
        source_path = root / "old"
        target_path = root / "new"
        final_path = root / "final"
        occupied_path = root / "occupied"
        fixture = temp / "fixture.c"
        fixture.write_text(
            """
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
"""
            + f'#define JMX_HISTORY_MOUNTINFO "{c_string(mountinfo)}"\n'
            + "#define JMX_HISTORY_TEST_ALLOW_ANY_MOUNT_ROOT 1\n"
            + "#define JMX_HISTORY_TEST_ALLOW_PROTECTED_DEVICE 1\n"
            + "#ifndef __linux__\n#undef SYS_renameat2\n#endif\n"
            + production_helpers()
            + r'''
static void keep_test_helpers(void)
{
    (void)jmx_history_device_protected;
    (void)jmx_history_migration_rollback;
    (void)jmx_history_locations_overlap;
}

static int put_file(int dirfd, const char *name, const char *content)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    int rc = fd < 0 ? -1 : jmx_history_write_all(fd, content, strlen(content));
    if (fd >= 0 && close(fd) != 0)
        rc = -1;
    return rc;
}

int main(int argc, char **argv)
{
    struct jmx_history_location source, target, occupied, escape;
    enum jmx_history_move_kind kind = JMX_HISTORY_MOVE_NONE;
    uint64_t bytes = 0;
    int empty = 0, nested = -1;

    if (argc != 5)
        return 90;
    keep_test_helpers();
    if (jmx_history_location_open(argv[1], 1, 1, &source) != 0)
        return 1;
    if (mkdirat(source.data_fd, "nested", 0700) != 0 ||
        (nested = openat(source.data_fd, "nested", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        put_file(source.data_fd, "one", "12345") != 0 ||
        put_file(nested, "two", "abcdefg") != 0 || close(nested) != 0)
        return 2;
    if (jmx_history_tree_size(source.data_fd, &bytes) != 0 || bytes != 12)
        return 3;
    if (symlinkat("/", source.parent_fd, "escape") != 0)
        return 4;
    {
        char escaped[PATH_MAX];
        if (snprintf(escaped, sizeof(escaped), "%s/escape", argv[1]) >= (int)sizeof(escaped) ||
            jmx_history_location_open(escaped, 0, 0, &escape) == 0)
            return 5;
    }
    if (jmx_history_location_open(argv[3], 1, 1, &occupied) != 0 ||
        put_file(occupied.data_fd, "busy", "x") != 0)
        return 6;
    if (jmx_history_migrate(&source, &occupied, &kind) == 0 ||
        kind != JMX_HISTORY_MOVE_NONE ||
        jmx_history_tree_size(source.data_fd, &bytes) != 0)
        return 7;
    jmx_history_location_close(&occupied);
    if (unlinkat(source.parent_fd, "escape", 0) != 0) {
        perror("remove test symlink");
        return 86;
    }
    if (jmx_history_location_open(argv[4], 1, 1, &target) != 0) {
        perror("reopen target");
        return 83;
    }
    if (jmx_history_migrate(&source, &target, &kind) != 0) {
        perror("second migrate");
        return 84;
    }
    if (jmx_history_migration_finish(&source, kind) != 0) {
        perror("finish");
        return 85;
    }
    bytes = 0;
    if (jmx_history_tree_size(target.data_fd, &bytes) != 0 || bytes != 12 ||
        jmx_history_clear_fd(target.data_fd) != 0 ||
        jmx_history_directory_empty(target.data_fd, &empty) != 0 || !empty)
        return 9;
    jmx_history_location_close(&source);
    jmx_history_location_close(&target);
    return 0;
}
''',
            encoding="utf-8",
        )
        binary = temp / "fixture"
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
             str(fixture), "-o", str(binary)],
            check=True,
        )
        subprocess.run(
            [str(binary), str(source_path), str(target_path), str(occupied_path),
             str(final_path)],
            check=True,
        )
    print("ok: history storage fd migration, rejection, sizing, and clear")


if __name__ == "__main__":
    main()
