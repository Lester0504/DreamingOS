#!/usr/bin/env python3
"""Contracts preventing Aegis feed work from blocking the daemon ubus loop."""

from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
AEGIS = ROOT / "src" / "aegisxd"
FEEDS = (AEGIS / "aegisxd_feeds.c").read_text(encoding="utf-8")
IMPORT = (AEGIS / "aegisxd_import.c").read_text(encoding="utf-8")
MAIN = (AEGIS / "aegisxd_main.c").read_text(encoding="utf-8")
INTERNAL = (AEGIS / "aegisxd_internal.h").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def c_function(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise AssertionError(f"unterminated C function: {signature}")


def test_feed_update_defaults_to_background_worker() -> None:
    start = FEEDS.index("struct json_object *aegisxd_feed_update_start")
    body = FEEDS[start:]
    require_all(body, (
        'aegisxd_json_bool(body, "async", 1)',
        "if (!background)",
        "aegisxd_feed_update_run(body, NULL)",
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


def test_update_job_persists_continuous_progress_in_existing_result_json() -> None:
    require_all(FEEDS, (
        "void aegisxd_job_record_progress",
        "UPDATE aegis_job_state SET result_json=? WHERE job_id=? AND state='running'",
        '"phase"', '"current_feed"', '"completed_feeds"', '"total_feeds"',
        '"bytes_done"', '"bytes_total"', '"percent"', '"percent_known"',
        '"updated_at"',
        "CURLOPT_XFERINFOFUNCTION",
        'aegisxd_job_record_progress(job_id, "download"',
        'aegisxd_job_record_progress(job_id, "verify"',
        'aegisxd_job_record_progress(job_id, "feed_complete"',
    ), "feed update progress")
    assert "ALTER TABLE" not in c_function(FEEDS, "void aegisxd_job_record_progress")
    assert 'json_object_object_add(progress, "percent", NULL)' not in FEEDS


def test_feed_splay_and_due_calculation_execute() -> None:
    splay = c_function(FEEDS, "uint32_t aegisxd_feed_splay_seconds")
    due = c_function(FEEDS, "int64_t aegisxd_feed_next_due_at")
    harness = f"""
        #include <assert.h>
        #include <stdint.h>
        #include <string.h>
        #define AEGISXD_FEED_INTERVAL_HOURS 24
        #define AEGISXD_FEED_RETRY_SEC 3600
        {splay}
        {due}
        int main(void) {{
            uint32_t a = aegisxd_feed_splay_seconds("feed-a", 3600);
            uint32_t b = aegisxd_feed_splay_seconds("feed-b", 3600);
            assert(a == aegisxd_feed_splay_seconds("feed-a", 3600));
            assert(a < 3600 && b < 3600 && a != b);
            assert(aegisxd_feed_splay_seconds("feed-a", 0) == 0);
            assert(aegisxd_feed_next_due_at("feed-a", 1000, 900, 24, 0)
                   == 1000 + 24 * 3600 + a);
            assert(aegisxd_feed_next_due_at("feed-a", 0, 10000, 24, 1)
                   >= 10000 + 3600);
            return 0;
        }}
    """
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "feed_splay.c"
        binary = Path(tmp) / "feed_splay"
        source.write_text(harness, encoding="utf-8")
        subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


def test_scheduler_uses_splay_single_job_guard_and_retry_backoff() -> None:
    require_all(FEEDS, (
        "static void aegisxd_feed_scheduler_tick",
        "aegisxd_job_running_count() > 0",
        "aegisxd_feed_next_due_at(",
        "aegisxd_feed_update_start(body)",
        "AEGISXD_FEED_RETRY_SEC",
        "uloop_timeout_set(&g_feed_scheduler_timer, AEGISXD_FEED_SCHEDULER_POLL_MS)",
    ), "feed periodic scheduler")
    require_all(MAIN, (
        "aegisxd_feed_scheduler_start()",
        "aegisxd_feed_scheduler_stop()",
    ), "feed scheduler lifecycle")
