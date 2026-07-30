#!/usr/bin/env python3
"""U-13C record_enable must fail closed with path/runtime compensation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")


def function_body(name: str, next_name: str) -> str:
    start = SOURCE.index(f"struct json_object *{name}(")
    end = SOURCE.index(f"struct json_object *{next_name}(", start)
    return SOURCE[start:end]


def if_block(body: str, marker: str) -> str:
    start = body.index(marker)
    opening = body.index("{", start)
    depth = 0
    for offset in range(opening, len(body)):
        if body[offset] == "{":
            depth += 1
        elif body[offset] == "}":
            depth -= 1
            if depth == 0:
                return body[start:offset + 1]
    raise AssertionError(f"unterminated branch: {marker}")


def test_record_enable_uses_verified_runtime_writer() -> None:
    helper_start = SOURCE.index("static int jmx_record_enable_runtime_set(")
    helper_end = SOURCE.index("struct json_object *jmx_api_set_record_base(", helper_start)
    helper = SOURCE[helper_start:helper_end]

    assert 'jmx_update_proc_value("record_enable", value)' in helper
    assert "return jmx_update_proc_value" in helper


def test_runtime_is_verified_before_irreversible_commits() -> None:
    body = function_body("jmx_api_set_record_base", "jmx_api_record_action")
    migrate = body.index("jmx_history_migrate(")
    runtime = body.index("jmx_record_enable_runtime_set(enable)")
    finish = body.index("jmx_history_migration_finish(")
    database = body.index("jmx_legacy_settings_set_record(enable,")
    success = body.index("jmx_gen_api_response_data(API_CODE_SUCCESS")

    assert migrate < runtime < finish < database < success
    assert 'update_jmx_proc_u32_value("record_enable", enable)' not in body


def test_each_post_runtime_failure_compensates_runtime_and_path() -> None:
    body = function_body("jmx_api_set_record_base", "jmx_api_record_action")
    runtime_failure = if_block(
        body, "if (jmx_record_enable_runtime_set(enable) != 0)"
    )
    finalize_failure = if_block(
        body,
        "if (path_changed &&\n"
        "        jmx_history_migration_finish(&old_location, move_kind) != 0)",
    )
    database_failure = if_block(
        body, "if (jmx_legacy_settings_set_record(enable,"
    )

    for branch in (runtime_failure, finalize_failure, database_failure):
        assert "jmx_record_enable_runtime_set(old_settings.record_enabled)" in branch
        assert "jmx_history_migration_rollback" in branch
        assert "record_enable_compensation_failed" in branch
        assert "API_CODE_SUCCESS" not in branch

    assert '"record_enable_runtime_apply_failed"' in runtime_failure
    assert '"history_migration_finalize_failed"' in finalize_failure
    assert '"history_settings_commit_failed"' in database_failure


if __name__ == "__main__":
    test_record_enable_uses_verified_runtime_writer()
    test_runtime_is_verified_before_irreversible_commits()
    test_each_post_runtime_failure_compensates_runtime_and_path()
    print("ok: U-13C record_enable transaction fails closed and compensates")
