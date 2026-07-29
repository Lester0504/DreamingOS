#!/usr/bin/env python3
"""Contracts preventing Aegis feed work from blocking the daemon ubus loop."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AEGIS = ROOT / "src" / "aegisxd"
FEEDS = (AEGIS / "aegisxd_feeds.c").read_text(encoding="utf-8")
IMPORT = (AEGIS / "aegisxd_import.c").read_text(encoding="utf-8")
MAIN = (AEGIS / "aegisxd_main.c").read_text(encoding="utf-8")
INTERNAL = (AEGIS / "aegisxd_internal.h").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def test_feed_update_defaults_to_background_worker() -> None:
    start = FEEDS.index("struct json_object *aegisxd_feed_update_start")
    body = FEEDS[start:]
    require_all(body, (
        'aegisxd_json_bool(body, "async", 1)',
        "if (!background)",
        "aegisxd_feed_update_run(body)",
        "aegisxd_job_running_count()",
        '"--feed-update-worker"',
        '"background", json_object_new_boolean(1)',
        "aegisxd_job_record_pid(job_id, pid)",
    ), "feed update background job")


def test_feed_import_defaults_to_background_worker() -> None:
    start = IMPORT.index("struct json_object *aegisxd_feed_import_start")
    end = IMPORT.index("static struct json_object *aegisxd_feed_import_run", start)
    body = IMPORT[start:end]
    require_all(body, (
        'aegisxd_json_bool(body, "async", 1)',
        "if (!background)",
        "aegisxd_feed_import_run(body)",
        "aegisxd_job_running_count()",
        '"--feed-import-worker"',
        '"background", json_object_new_boolean(1)',
        "aegisxd_job_record_pid(job_id, pid)",
    ), "feed import background job")


def test_import_worker_is_reexeced_and_records_completion() -> None:
    require_all(MAIN, (
        '"--feed-import-worker"',
        "aegisxd_feed_import_worker_main(job_id, feed_id)",
        "curl_global_cleanup()",
    ), "feed import worker dispatch")
    require_all(IMPORT, (
        "int aegisxd_feed_import_worker_main",
        "aegisxd_db_init()",
        "aegisxd_job_result_ok(result)",
        "aegisxd_job_record_finish(job_id, result)",
        "aegisxd_db_close()",
    ), "feed import worker lifecycle")


def test_update_and_import_share_one_job_bookkeeping_contract() -> None:
    for symbol in (
        "aegisxd_job_result_ok",
        "aegisxd_job_running_count",
        "aegisxd_job_record_start",
        "aegisxd_job_record_pid",
        "aegisxd_job_record_finish",
    ):
        assert f"static int {symbol}" not in FEEDS
        assert f"static void {symbol}" not in FEEDS
        assert symbol in INTERNAL
        assert symbol in IMPORT
    assert "aegisxd_feed_import_worker_main" in INTERNAL
