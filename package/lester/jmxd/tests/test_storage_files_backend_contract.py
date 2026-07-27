#!/usr/bin/env python3
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FILES = (SRC / "storage/storage_files.c").read_text(encoding="utf-8")
HEADER = (SRC / "storage/storage_files.h").read_text(encoding="utf-8")
MAKE = (SRC / "Makefile").read_text(encoding="utf-8")
UBUS = (SRC / "jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEB = (SRC / "webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (SRC / "webd/jmx_app_perms.c").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing {missing}"


def test_phase_two_text_read_is_wired_end_to_end() -> None:
    require_all(HEADER, ("jmx_storage_files_list", "jmx_storage_files_content"),
                "public header")
    require_all(MAKE, ("storage/storage_files.o",), "core object list")
    require_all(UBUS, ('"storage_files"', "dw_handle_storage_files",
                       "jmx_storage_files_list"), "ubus")
    require_all(UBUS, ('"storage_file_content"',
                       "dw_handle_storage_file_content",
                       "jmx_storage_files_content"), "content ubus")
    require_all(WEB, ('"/api/v1/storage/files"', '"storage_files"',
                      '"root_id"', '"path"', '"search"'), "REST")
    require_all(PERMS, ('"/api/v1/storage/files"', '"GET"', "JMX_RISK_LOW"),
                "permission registry")
    require_all(WEB, ('"/api/v1/storage/files/content"',
                      '"storage_file_content"', '"root_id"', '"path"'),
                "content REST")
    require_all(PERMS, ('"/api/v1/storage/files/content"', '"GET"',
                        "JMX_RISK_LOW"), "content permission registry")
    require_all(FILES, ('"storage-files.v1"', '"mountinfo+openat-nofollow"',
                        '"entries"', '"roots"', '"capabilities"',
                        '"entries_truncated"', '"list"',
                        '"no_eligible_storage_roots"'), "response contract")
    for capability in ("download", "preview", "write", "mkdir", "create",
                       "rename", "permissions", "upload", "download_url",
                       "copy", "move", "compress", "extract", "delete",
                       "install_package"):
        assert f'"{capability}"' in FILES
    assert "json_object_new_boolean(0)" in FILES


def test_small_utf8_text_read_is_bounded_and_fail_closed() -> None:
    require_all(FILES, (
        "STORAGE_FILES_MAX_TEXT_BYTES (256U * 1024U)",
        "STORAGE_FILES_MAX_PROBE_BYTES (4U * 1024U * 1024U)",
        "storage_files_open_regular", "storage_files_read_text_fd",
        "storage_files_utf8_text", "storage_files_stat_unchanged",
        "O_NOFOLLOW | O_NONBLOCK", "RESOLVE_BENEATH",
        "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_XDEV",
        '"text_too_large"', '"not_utf8_text"', '"file_read_failed"',
        '"text/plain; charset=utf-8"', '"encoding"', '"newline"',
        '"etag"', '"read_only"', '"truncated"',
        '"max_text_read_bytes"', '"max_text_probe_bytes_per_listing"',
    ), "bounded text read")
    for forbidden in ("fopen(display", "fopen(path", "system(", "popen("):
        assert forbidden not in FILES


def test_content_route_compiled_permission_boundary() -> None:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "a C compiler is required for the permission contract"
    harness = r'''
#include <stdio.h>
#include "jmx_app_perms.h"

int main(void)
{
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files/content") != JMX_RISK_LOW ||
        jmx_perm_route_risk("HEAD", "/api/v1/storage/files/content") != JMX_RISK_LOW ||
        jmx_perm_route_risk("PUT", "/api/v1/storage/files/content") != JMX_RISK_MEDIUM) {
        fputs("storage content route risk mismatch\n", stderr);
        return 1;
    }
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="storage-files-perms-") as raw:
        temporary = Path(raw)
        include = temporary / "include/json-c"
        include.mkdir(parents=True)
        (include / "json.h").write_text("", encoding="utf-8")
        source = temporary / "contract.c"
        binary = temporary / "contract"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
            "-I", str(temporary / "include"),
            "-I", str(SRC / "webd"),
            str(SRC / "webd/jmx_app_perms.c"), str(source),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


def test_roots_are_real_external_mounts_not_rootfs_or_pseudo_filesystems() -> None:
    require_all(FILES, (
        'STORAGE_FILES_MOUNTINFO "/proc/self/mountinfo"',
        'storage_files_path_prefix(path, "/mnt")',
        'storage_files_path_prefix(path, "/media")',
        '"proc", "sysfs", "devtmpfs"', '"tmpfs", "overlay"',
        "(unsigned int)major(st.st_dev) != maj",
        "(unsigned int)minor(st.st_dev) != min",
        'storage_files_option_present(fields[5], "ro")',
        'open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)',
        "SYS_openat2", "RESOLVE_BENEATH", "RESOLVE_NO_SYMLINKS",
        "RESOLVE_NO_XDEV",
        '"/", "/data", "/etc/dreamingwrt", "/boot"',
        "storage_files_protected_device(st.st_dev)",
    ), "root discovery")
    assert 'storage_files_path_prefix(path, "/")' not in FILES
    assert 'strstr(fields[5], "ro")' not in FILES
    assert "#ifndef STORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT" in FILES


def test_path_walk_never_follows_links_or_crosses_mounts() -> None:
    require_all(FILES, (
        'openat(fd, part,', 'O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW',
        "st.st_dev != root->dev", 'strcmp(part, "..")',
        "STORAGE_FILES_MAX_PATH_DEPTH", "AT_SYMLINK_NOFOLLOW",
        '"mount_boundary_rejected"', '"invalid_relative_path"',
        "root_stat.st_dev != root->dev",
    ), "descriptor-relative path walk")
    for forbidden in ("realpath(", "chdir(", "system(", "popen(", "glob("):
        assert forbidden not in FILES


def test_directory_work_is_bounded_and_special_files_are_not_readable() -> None:
    require_all(FILES, (
        "STORAGE_FILES_MAX_ENTRIES 1000", "STORAGE_FILES_MAX_SEARCH 128",
        "emitted >= STORAGE_FILES_MAX_ENTRIES", '"symlink"', '"other"',
        "storage_files_capabilities(S_ISDIR(st.st_mode) &&",
    ), "bounded listing")
    assert "fopen(item_path" not in FILES
    assert "readlink(" not in FILES


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} storage-files Phase 1/2A contracts")
