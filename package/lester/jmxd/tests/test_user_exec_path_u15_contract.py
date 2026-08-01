#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_user.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(rf"{re.escape(name)}\s*\([^;]*?\)\s*\{{", SOURCE, re.S)
    if not match:
        raise AssertionError(name)
    start = match.start()
    brace = SOURCE.index("{", match.start())
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(name)


def test_neighbor_collection_uses_shared_bounded_argv_exec() -> None:
    collector = function("static void client_collect_ip_neigh")
    assert '"/bin/ip", family == AF_INET6 ? "-6" : "-4"' in collector
    assert '"neigh", "show", NULL' in collector
    assert "jmx_exec_capture(" in collector
    for state in ("timed_out", "truncated", "term_signal", "exit_code"):
        assert f"result.{state}" in collector
    update = function("void update_client_from_kernel")
    assert "client_collect_ip_neigh(AF_INET6);" in update
    assert "client_collect_ip_neigh(AF_INET);" in update
    assert "popen(" not in update
    assert "pclose(" not in update


def test_history_directory_creation_is_fd_relative_and_rejects_symlinks() -> None:
    mkdir = function("static int ensure_dir_exists")
    assert "path[0] != '/'" in mkdir
    for token in ("mkdirat(", "openat(", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"):
        assert token in mkdir
    assert 'strcmp(cursor, "..")' in mkdir
    assert "system(" not in mkdir
    assert "popen(" not in mkdir


def test_history_size_check_uses_bounded_argv_exec() -> None:
    cleanup = function("void check_and_cleanup_history_data_by_size")
    assert '"/usr/bin/du", "-sm", "--", (char *)data_dir, NULL' in cleanup
    assert "jmx_exec_capture(" in cleanup
    for state in ("timed_out", "truncated", "term_signal", "exit_code"):
        assert f"result.{state}" in cleanup
    assert "strtoull(result.output, &endptr, 10)" in cleanup
    for forbidden in ("exec_with_result_line", "system(", "popen(", "| awk"):
        assert forbidden not in cleanup


if __name__ == "__main__":
    test_neighbor_collection_uses_shared_bounded_argv_exec()
    test_history_directory_creation_is_fd_relative_and_rejects_symlinks()
    test_history_size_check_uses_bounded_argv_exec()
    print("ok: U-15 user neighbor and history paths avoid root shell")
