#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import List


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/storage/storage_files.c"
FIXTURE = ROOT / "tests/test_storage_files_fixture.c"


def run(binary: Path, *args: str) -> dict:
    result = subprocess.run([str(binary), *args], text=True,
                            capture_output=True, check=True)
    return json.loads(result.stdout)


def content(binary: Path, root_id: str, path: Path) -> dict:
    return data(run(binary, "content", root_id, str(path)))


def data(response: dict) -> dict:
    return response.get("data", {})


def json_c_flags() -> tuple[List[str], List[str]]:
    configured = os.environ.get("STORAGE_FILES_TEST_JSON_C_ROOT", "")
    if configured:
        prefix = Path(configured)
        header = prefix / "include/json-c/json.h"
        static_library = prefix / "lib/libjson-c.a"
        shared_library = prefix / "lib/libjson-c.so"
        assert header.is_file(), f"json-c header missing below {prefix}"
        if shared_library.is_file():
            return (["-I", str(prefix / "include")],
                    ["-L", str(prefix / "lib"), "-ljson-c",
                     f"-Wl,-rpath,{prefix / 'lib'}"])
        assert static_library.is_file(), f"json-c library missing below {prefix}"
        return (["-I", str(prefix / "include")], [str(static_library)])

    pkg_config = shutil.which("pkg-config")
    if pkg_config:
        probe = subprocess.run(
            [pkg_config, "--cflags", "--libs", "json-c"],
            text=True, capture_output=True,
        )
        if probe.returncode == 0:
            flags = probe.stdout.split()
            return ([flag for flag in flags if flag.startswith("-I")],
                    [flag for flag in flags if not flag.startswith("-I")])

    brew = shutil.which("brew")
    if brew:
        probe = subprocess.run([brew, "--prefix", "json-c"], text=True,
                               capture_output=True)
        if probe.returncode == 0:
            prefix = Path(probe.stdout.strip())
            header = prefix / "include/json-c/json.h"
            library = prefix / "lib/libjson-c.a"
            if header.is_file() and library.is_file():
                return (["-I", str(prefix / "include")], [str(library)])

    temporary_cellar = Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c")
    for header in sorted(temporary_cellar.glob("*/include/json-c/json.h"),
                         reverse=True):
        prefix = header.parents[2]
        library = prefix / "lib/libjson-c.a"
        if library.is_file():
            return (["-I", str(prefix / "include")], [str(library)])
    raise AssertionError("json-c development headers and library unavailable")


def main() -> None:
    compiler = shutil.which("cc") or shutil.which("clang")
    assert compiler, "host C compiler unavailable"
    json_c_cflags, json_c_libs = json_c_flags()
    with tempfile.TemporaryDirectory(prefix="storage-files-runtime-") as temporary:
        temp = Path(temporary)
        mount = temp / "mnt" / "disk"
        mount.mkdir(parents=True)
        (mount / "alpha.txt").write_text("alpha", encoding="utf-8")
        (mount / "unicode.txt").write_bytes(
            b"hello \xf0\x9f\x8c\x8f\r\nsecond\r\n")
        (mount / "binary.bin").write_bytes(b"before\x00after")
        (mount / "invalid.txt").write_bytes(b"bad\xc0\xaf")
        (mount / "large.txt").write_bytes(b"x" * (256 * 1024 + 1))
        (mount / "folder").mkdir()
        (mount / "folder" / "inside.txt").write_text("inside", encoding="utf-8")
        os.mkfifo(mount / "pipe")
        (mount / "escape").symlink_to("/")
        device = mount.stat().st_dev
        major, minor = os.major(device), os.minor(device)
        mountinfo = temp / "mountinfo"
        mountinfo.write_text(
            f"91 1 {major}:{minor} / {mount} rw,relatime,errors=remount-ro "
            "- ext4 /dev/test rw\n",
            encoding="utf-8",
        )
        binary = temp / "storage-files-fixture"
        subprocess.run([
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-DSTORAGE_FILES_TEST_ALLOW_PROTECTED_DEVICE=1",
            "-DSTORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT=1",
            f'-DSTORAGE_FILES_MOUNTINFO="{mountinfo}"',
            "-I", str(ROOT / "src"), *json_c_cflags,
            str(SOURCE), str(FIXTURE), *json_c_libs, "-o", str(binary),
        ], check=True)

        listing = data(run(binary))
        assert listing["contract_version"] == "storage-files.v1"
        assert listing["path"] == str(mount)
        assert listing["capabilities"]["list"] is True
        assert listing["capabilities"]["read"] is False
        assert listing["capabilities"]["download"] is False
        assert listing["limits"]["max_text_read_bytes"] == 256 * 1024
        assert listing["limits"]["max_text_probe_bytes_per_listing"] == 4 * 1024 * 1024
        assert listing["roots"][0]["read_only"] is False
        by_name = {entry["name"]: entry for entry in listing["entries"]}
        assert {"alpha.txt", "unicode.txt", "binary.bin", "invalid.txt",
                "large.txt", "folder", "pipe", "escape"} <= set(by_name)
        assert by_name["folder"]["capabilities"]["list"] is True
        assert by_name["alpha.txt"]["kind"] == "text"
        assert by_name["alpha.txt"]["mime"] == "text/plain; charset=utf-8"
        assert by_name["alpha.txt"]["capabilities"]["read"] is True
        assert by_name["alpha.txt"]["capabilities"]["preview"] is True
        assert by_name["alpha.txt"]["capabilities"]["download"] is False
        assert by_name["binary.bin"]["capabilities"]["read"] is False
        assert by_name["invalid.txt"]["capabilities"]["read"] is False
        assert by_name["large.txt"]["capabilities"]["read"] is False
        assert by_name["escape"]["kind"] == "symlink"
        assert by_name["escape"]["capabilities"]["list"] is False
        assert by_name["pipe"]["kind"] == "other"

        root_id = listing["root_id"]
        alpha = content(binary, root_id, mount / "alpha.txt")
        assert alpha["content"] == "alpha"
        assert alpha["text"] == "alpha"
        assert alpha["mime"] == "text/plain; charset=utf-8"
        assert alpha["encoding"] == "utf-8"
        assert alpha["newline"] == "none"
        assert alpha["size_bytes"] == 5
        assert alpha["read_only"] is True
        assert alpha["truncated"] is False
        assert alpha["etag"].startswith('W/"')
        unicode_text = content(binary, root_id, mount / "unicode.txt")
        assert unicode_text["content"].endswith("second\r\n")
        assert unicode_text["newline"] == "crlf"
        assert content(binary, root_id, mount / "binary.bin")["error"] == "not_utf8_text"
        assert content(binary, root_id, mount / "invalid.txt")["error"] == "not_utf8_text"
        assert content(binary, root_id, mount / "large.txt")["error"] == "text_too_large"
        assert content(binary, root_id, mount / "pipe")["error"] == "mount_boundary_rejected"
        assert content(binary, root_id, mount / "folder")["error"] == "mount_boundary_rejected"
        assert content(binary, root_id, mount / "escape")["error"] == "mount_boundary_rejected"
        assert content(binary, root_id, mount / "..")["error"] == "invalid_relative_path"
        nested = data(run(binary, root_id, str(mount / "folder")))
        assert [entry["name"] for entry in nested["entries"]] == ["inside.txt"]
        filtered = data(run(binary, root_id, str(mount), "ALPHA"))
        assert [entry["name"] for entry in filtered["entries"]] == ["alpha.txt"]
        for invalid in (str(mount / ".."), str(mount / "escape"), "/etc"):
            rejected = data(run(binary, root_id, invalid))
            assert rejected["error"] in {
                "invalid_relative_path", "mount_boundary_rejected",
                "directory_unavailable"
            }

        outside = temp / "media" / "duplicate"
        outside.mkdir(parents=True)
        os.chmod(outside, stat.S_IRWXU)
        mountinfo.write_text(
            mountinfo.read_text(encoding="utf-8") +
            f"92 1 {major}:{minor} / {outside} rw,relatime - ext4 /dev/test rw\n",
            encoding="utf-8",
        )
        roots = data(run(binary))["roots"]
        assert len({root["id"] for root in roots}) == 2

        mountinfo.write_text(
            f"91 1 {major}:{minor} / {mount} ro,relatime "
            "- ext4 /dev/test ro\n",
            encoding="utf-8",
        )
        read_only = data(run(binary))
        assert read_only["roots"][0]["read_only"] is True

    print("ok: storage-files descriptor walk and bounded UTF-8 text read")


if __name__ == "__main__":
    main()
