#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/storage/storage_files.c"
FIXTURE = ROOT / "tests/test_storage_files_fixture.c"


def run(binary: Path, *args: str) -> dict:
    result = subprocess.run([str(binary), *args], text=True,
                            capture_output=True, check=True)
    return json.loads(result.stdout)


def content(binary: Path, root_id: str, path: Path) -> dict:
    return data(run(binary, "content", root_id, str(path)))


def stream(binary: Path, root_id: str, path: Path) -> dict:
    """Byte-stream open. Returns the fixture's own object, not a data envelope."""
    return run(binary, "stream", root_id, str(path))


def mutate(binary: Path, payload: dict) -> dict:
    return data(run(binary, "mutate", json.dumps(payload, separators=(",", ":"))))


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

    # Every former fallback below pkg-config ended at a Homebrew static
    # archive, which on 31.6 is an LTO archive built by a different compiler
    # and fails the link. The shared resolver prefers a real .so and knows the
    # staging_dir layout, so the fixture compiles on both machines.
    return apd_test_deps.split_package_flags("json-c")


def main() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
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
            # gnu11, not c11: PATH_MAX/NAME_MAX are POSIX rather than ISO C, and
            # strict -std=c11 switches off glibc's default _DEFAULT_SOURCE, so
            # <limits.h> stops declaring them and storage_files.h fails to
            # compile on the Linux tree.  The macOS SDK defines them
            # unconditionally, which is why this only broke there.
            # Passing -D_GNU_SOURCE instead is not an option: storage_files.c
            # already defines it itself, and the redefinition is fatal under
            # -Werror.
            compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
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
        # A writable root reports exactly the four actions
        # POST /storage/files/mutate accepts.  These were pinned false until
        # 2026-08-08, which greyed out the file manager's create/save/rename
        # buttons even after the write route was wired.
        for capability in ("mkdir", "create", "rename", "write"):
            assert listing["capabilities"][capability] is True, (
                f"{capability} must follow root writability"
            )
        # Everything below has no backend endpoint; reporting it true would
        # enable UI controls that cannot work.
        for capability in ("upload", "delete", "copy", "move", "compress",
                           "extract", "permissions", "download_url",
                           "install_package"):
            assert listing["capabilities"][capability] is False, (
                f"{capability} has no backend endpoint and must stay false"
            )
        # The write route is wired, so no stale "jobs pending" attribution.
        assert "write" not in listing["capability_reasons"], (
            "a writable root has nothing to explain about write"
        )
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

        denied = mutate(binary, {
            "action": "mkdir", "root_id": root_id, "path": str(mount),
            "name": "denied",
        })
        assert denied["error"] == "confirmation_required"
        assert not (mount / "denied").exists()

        made = mutate(binary, {
            "action": "mkdir", "root_id": root_id, "path": str(mount),
            "name": "created", "confirm": True,
        })
        assert made["persisted"] is True and made["applied"] is True
        assert made["readback_verified"] is True
        assert (mount / "created").is_dir()

        created = mutate(binary, {
            "action": "create", "root_id": root_id,
            "path": str(mount / "created"), "name": "note.txt",
            "content": "first\n", "confirm": True,
        })
        note = mount / "created" / "note.txt"
        if sys.platform.startswith("linux"):
            assert created["persisted"] is True
            assert note.read_text(encoding="utf-8") == "first\n"
        else:
            assert created["error"] == "filesystem_transaction_failed"
            assert not note.exists()
            note.write_text("first\n", encoding="utf-8")
        first = content(binary, root_id, note)

        stale = mutate(binary, {
            "action": "write", "root_id": root_id, "path": str(note),
            "content": "bad\n", "expected_etag": 'W/"stale"',
            "confirm": True,
        })
        assert stale["error"] == "revision_conflict"
        assert note.read_text(encoding="utf-8") == "first\n"

        replaced = mutate(binary, {
            "action": "write", "root_id": root_id, "path": str(note),
            "content": "second\n", "expected_etag": first["etag"],
            "confirm": True,
        })
        if sys.platform.startswith("linux"):
            assert replaced["persisted"] is True
            assert replaced["readback_verified"] is True
            assert note.read_text(encoding="utf-8") == "second\n"
        else:
            assert replaced["error"] == "filesystem_transaction_failed"
            assert replaced["persisted"] is False
            assert note.read_text(encoding="utf-8") == "first\n"
        assert not list(note.parent.glob(".dreamingwrt-tx-*"))

        old_inode = note.stat().st_ino
        renamed = mutate(binary, {
            "action": "rename", "root_id": root_id, "path": str(note),
            "new_name": "renamed.txt", "confirm": True,
        })
        renamed_path = note.parent / "renamed.txt"
        if sys.platform.startswith("linux"):
            assert renamed["persisted"] is True
            assert not note.exists() and renamed_path.stat().st_ino == old_inode
        else:
            assert renamed["error"] == "filesystem_transaction_failed"
            assert note.exists() and note.stat().st_ino == old_inode
            assert not renamed_path.exists()

        escaped = mutate(binary, {
            "action": "create", "root_id": root_id, "path": str(mount),
            "name": "../escape.txt", "content": "x", "confirm": True,
        })
        assert escaped["error"] == "invalid_name"
        symlink_parent = mutate(binary, {
            "action": "create", "root_id": root_id,
            "path": str(mount / "escape"), "name": "escape.txt",
            "content": "x", "confirm": True,
        })
        assert symlink_parent["error"] == "directory_unavailable"
        unicode_text = content(binary, root_id, mount / "unicode.txt")
        assert unicode_text["content"].endswith("second\r\n")
        assert unicode_text["newline"] == "crlf"
        assert content(binary, root_id, mount / "binary.bin")["error"] == "not_utf8_text"
        assert content(binary, root_id, mount / "invalid.txt")["error"] == "not_utf8_text"
        assert content(binary, root_id, mount / "large.txt")["error"] == "text_too_large"

        # The byte stream exists precisely to serve what the text endpoint above
        # refuses. If these three ever start failing the same way /content does,
        # image and video preview and file download are all dead again.
        for name, expect_size in (("binary.bin", 12),
                                  ("invalid.txt", 5),
                                  ("large.txt", 256 * 1024 + 1)):
            opened = stream(binary, root_id, mount / name)
            assert opened["ok"] is True, f"{name} must stream: {opened}"
            assert opened["size_bytes"] == expect_size, (name, opened)
            assert opened["basename"] == name
            assert opened["root_id"] == root_id
            assert opened["bytes_read"] > 0, (
                f"{name} opened but read nothing; the descriptor must be "
                "positioned at offset 0 and blocking")
        # First bytes really are the file's own, so the descriptor is not
        # mid-file or pointed somewhere else.
        assert stream(binary, root_id, mount / "binary.bin")["head_hex"] == "6265666f"

        # Guards the stream must keep, in the same shape the text path reports
        # them: escaping the root, following a symlink out, leaving the mount.
        for invalid, expected in (
            (mount / "escape", {"invalid_relative_path",
                                "mount_boundary_rejected", "file_unavailable"}),
            (mount / ".." / "outside.txt", {"invalid_relative_path",
                                            "file_unavailable"}),
            (mount / "folder", {"file_unavailable", "mount_boundary_rejected"}),
            (mount / "pipe", {"file_unavailable", "mount_boundary_rejected"}),
        ):
            refused = stream(binary, root_id, invalid)
            assert refused["ok"] is False, (str(invalid), refused)
            assert refused["reason"] in expected, (str(invalid), refused)
        # A directory and a fifo are not streamable: open_regular() enforces
        # S_ISREG, so neither can be served as a file.
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
        # A read-only root keeps all four false.  The mutate handler refuses it
        # anyway, but a disabled button beats an error after the click.
        for capability in ("mkdir", "create", "rename", "write"):
            assert read_only["capabilities"][capability] is False, (
                f"{capability} must be false on a read-only root"
            )
        assert read_only["capability_reasons"]["write"] == "storage_root_read_only"
        rejected_write = mutate(binary, {
            "action": "mkdir", "root_id": root_id, "path": str(mount),
            "name": "read-only", "confirm": True,
        })
        assert rejected_write["error"] == "storage_root_read_only"
        assert not (mount / "read-only").exists()

    print("ok: storage-files descriptor walk and bounded UTF-8 text read")


if __name__ == "__main__":
    main()
