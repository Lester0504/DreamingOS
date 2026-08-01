#!/usr/bin/env python3
"""Contract for advanced-routing apply failure propagation and runtime truth."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def function_source(signature: str) -> str:
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def main() -> None:
    generate = function_source("static int nc_adv_generate_runtime(")
    emit_route = function_source("static int nc_adv_emit_route_cmd(")
    artifact_open = function_source("static int nc_adv_artifact_open(")
    finish = function_source("static int nc_adv_artifact_finish(")
    publish = function_source("static int nc_adv_artifacts_publish(")
    recover = function_source("static int nc_adv_recover_publish_locked(")
    trusted_dir = function_source("static int nc_adv_open_trusted_dir(")
    db_init = function_source("int jmx_netconfig_db_init(")
    apply = function_source("struct json_object *jmx_advanced_routing_apply(")
    run_script = function_source("static int nc_adv_run_script(")

    assert '"#!/bin/sh\\nset -eu\\n' in generate
    assert "route_failed" in emit_route
    assert "exit 5" in emit_route
    assert "nft -f /etc/dreamingwrt/advanced_routing_pbr.nft" in generate
    assert 'ip rule add pref %d fwmark' in generate
    assert 'ip rule add pref %d fwmark 0x%04x/0xffff table %d 2>/dev/null || true' not in generate
    assert 'nc_adv_table_id_by_name(table, &tid) != 0' in generate
    assert "WIFEXITED(status) ? WEXITSTATUS(status) : -1" in run_script

    for operation in ("fflush", "ferror", "fsync", "fchmod", "fclose"):
        assert operation in finish, f"missing checked file operation: {operation}"
    for token in ("openat", "O_EXCL", "O_NOFOLLOW", "AT_SYMLINK_NOFOLLOW"):
        assert token in artifact_open
    for operation in ("linkat", "renameat", "fsync", "flock"):
        assert operation in SOURCE, f"missing durable publish operation: {operation}"
    assert "NC_ADV_JOURNAL_PREPARED" in publish
    assert "NC_ADV_JOURNAL_COMMITTED" in publish
    assert publish.index("NC_ADV_JOURNAL_PREPARED") < publish.index("renameat")
    assert "goto rollback" in publish
    assert "nc_adv_recover_publish_locked" in publish
    assert "nc_adv_journal_checksum" in SOURCE
    assert "nc_adv_file_identity" in SOURCE
    assert "transaction_id" in SOURCE
    assert "journal.state == NC_ADV_JOURNAL_PREPARED" in recover
    assert "journal.state == NC_ADV_JOURNAL_COMMITTED" in recover
    assert "AT_SYMLINK_NOFOLLOW" in recover
    assert "nc_adv_identity_matches" in recover
    assert "NC_ADV_FSYNC_DIR(artifacts[i].dirfd)" in recover
    assert "O_NOFOLLOW" in trusted_dir
    assert "NC_ADV_DIR_IS_TRUSTED" in trusted_dir
    assert db_init.index("nc_adv_recover_pending_publish()") < db_init.index("sqlite3_open(")
    assert apply.index("nc_adv_artifact_finish(&artifacts[3])") < apply.index(
        "nc_adv_artifacts_publish(artifacts, artifact_count, transaction_id"
    )
    assert "nc_adv_recover_pending_publish()" in apply
    assert 'failed_stage = "recover_pending_publish"' in apply

    for field in (
        '"artifact_generated"',
        '"runtime_attempted"',
        '"runtime_applied"',
        '"readback_verified"',
        '"failed_stage"',
        '"reason"',
        '"apply_state"',
    ):
        assert field in apply

    assert 'apply_state = "staged"' in apply
    assert 'apply_state = "runtime_unverified"' in apply
    assert 'apply_state = "failed"' in apply
    assert 'nc_adv_set_apply_state("failed", 0)' in apply
    assert 'json_object_new_boolean(readback_verified)' in apply
    assert 'json_object_object_add(d, "applied", json_object_new_boolean(0))' in apply
    assert "apply_state='applied'" not in apply
    assert 'json_object_new_boolean(!dry)' not in apply
    assert 'nc_exec("UPDATE advanced_routing_global SET apply_state=' not in apply

    for stage in (
        "database_init",
        "generate_rt_tables",
        "generate_draft_config",
        "generate_runtime_artifacts",
        "publish_runtime_artifacts",
        "open_runtime_log",
        "runtime_apply",
        "persist_runtime_state",
    ):
        assert f'failed_stage = "{stage}"' in apply

    print("ok: U-13 advanced routing never reports applied before runtime readback")


if __name__ == "__main__":
    main()
