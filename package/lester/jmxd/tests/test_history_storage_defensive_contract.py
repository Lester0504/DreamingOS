#!/usr/bin/env python3
"""U-02 history storage must stay inside descriptor-scoped roots."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")


def function_body(name: str, next_name: str) -> str:
    start = SOURCE.index(f"struct json_object *{name}(")
    end = SOURCE.index(f"struct json_object *{next_name}(", start)
    return SOURCE[start:end]


def test_history_roots_match_storage_files_contract() -> None:
    helper = SOURCE[SOURCE.index("#define JMX_HISTORY_MAX_DEPTH"):
                    SOURCE.index("struct json_object *jmx_api_get_record_base(")]
    for required in (
        'JMX_HISTORY_MOUNTINFO "/proc/self/mountinfo"',
        'jmx_history_path_prefix(mount_path, "/mnt")',
        'jmx_history_path_prefix(mount_path, "/media")',
        '"/", "/data", "/etc/dreamingwrt", "/boot"',
        'O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW',
        'fstatat(directory_fd, entry->d_name, &status,\n                    AT_SYMLINK_NOFOLLOW)',
        'openat(', 'mkdirat(', 'unlinkat(', 'fdopendir(',
    ):
        assert required in SOURCE, required
    for forbidden in ("system(", "popen(", "glob(", "exec_with_result_line"):
        assert forbidden not in helper, forbidden


def test_get_set_and_clear_use_only_fd_relative_helpers() -> None:
    get_body = function_body("jmx_api_get_record_base", "jmx_api_set_record_base")
    set_body = function_body("jmx_api_set_record_base", "jmx_api_record_action")
    clear_body = function_body("jmx_api_record_action", "jmx_api_get_device_list")

    assert "jmx_history_tree_size" in get_body
    assert '"data_size"' in get_body and '"data_size_unit"' in get_body
    assert "jmx_history_location_open" in set_body
    assert "jmx_history_migrate" in set_body
    assert "jmx_history_migration_finish" in set_body
    assert "jmx_history_migration_rollback" in set_body
    assert set_body.index("jmx_history_migration_finish") < set_body.index(
        "jmx_legacy_settings_set_record"
    )
    assert "jmx_history_clear_fd" in clear_body
    for body in (get_body, set_body, clear_body):
        for forbidden in ("system(", "popen(", "exec_with_result_line", "rm -rf", "mv "):
            assert forbidden not in body, forbidden


def test_stable_failure_reasons_are_exposed_in_existing_envelope() -> None:
    for reason in (
        "invalid_history_data_path",
        "history_path_unavailable",
        "history_source_unavailable",
        "history_path_overlap",
        "history_migration_failed",
        "history_migration_finalize_failed",
        "history_settings_commit_failed",
        "history_migration_rollback_failed",
        "history_clear_failed",
    ):
        assert f'"{reason}"' in SOURCE, reason
    assert 'json_object_object_add(data, "error"' in SOURCE
    assert 'json_object_object_add(data, "reason"' in SOURCE
    assert "jmx_gen_api_response_data(API_CODE_ERROR, data)" in SOURCE


if __name__ == "__main__":
    test_history_roots_match_storage_files_contract()
    test_get_set_and_clear_use_only_fd_relative_helpers()
    test_stable_failure_reasons_are_exposed_in_existing_envelope()
    print("ok: history storage is descriptor-scoped and fail-closed")
