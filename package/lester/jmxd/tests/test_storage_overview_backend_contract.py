from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/storage/storage_overview.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/storage/storage_overview.h").read_text(encoding="utf-8")
DB = (ROOT / "src/jmx_db.c").read_text(encoding="utf-8")


def function_body(signature: str) -> str:
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for pos in range(brace, len(SOURCE)):
        if SOURCE[pos] == "{":
            depth += 1
        elif SOURCE[pos] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[brace : pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


def test_public_integration_abi_returns_jmx_envelope():
    signature = "struct json_object *jmx_storage_overview_get(const char *range)"
    assert signature + ";" in HEADER
    body = function_body(signature)
    assert "jmx_gen_api_response_data(API_CODE_SUCCESS, data)" in body
    assert "jmx_gen_api_response_data(API_CODE_ERROR, data)" in body
    assert 'json_object_new_string("storage-overview.v1")' in body
    assert "struct json_object *storage_overview_get(" not in HEADER
    assert "int storage_overview_sample(" not in HEADER


def test_only_real_physical_disks_are_enumerated():
    assert 'opendir(STORAGE_SYS_BLOCK)' in SOURCE
    for prefix in ('"loop"', '"zram"', '"nbd"', '"ram"', '"fd"'):
        assert prefix in SOURCE
    assert 'device/type' in SOURCE
    assert '!strcmp(type, "5")' in SOURCE
    assert '"/devices/virtual/block/"' in SOURCE
    assert 'sectors == 0' in SOURCE
    assert 'json_object_new_string("physical")' in SOURCE


def test_identity_is_stable_and_not_array_position_based():
    body = function_body("static void storage_stable_id(")
    assert '"/dev/disk/by-id"' in SOURCE
    assert '"by-id:%s"' in body
    assert '"wwid:%s"' in body
    assert '"serial:%s"' in body
    assert '"sysfs:%s"' in body
    assert not re.search(r"disk->id[^;]*(?:count|index|\bi\b)", body)


def test_mount_usage_uses_mountinfo_device_identity_and_statvfs():
    body = function_body("static int storage_read_mounts(")
    assert 'fopen("/proc/self/mountinfo", "r")' in body
    assert 'sscanf(dev, "%u:%u"' in body
    assert "statvfs(mount_path, &fs)" in body
    assert "storage_disk_owns_dev" in SOURCE
    assert "duplicate" in body


def test_diskstats_uses_cached_cumulative_samples_without_request_sleep():
    body = function_body("static void storage_measure_io(")
    assert body.count("storage_read_diskstats(") == 1
    assert "storage_now_ms()" in body
    assert "g_storage_io_cache" in body
    assert "sectors_read - entry->counter.sectors_read" in body
    assert "sectors_written - entry->counter.sectors_written" in body
    assert "* 512.0 / elapsed" in body
    assert "read_ms / (double)reads" in body
    assert "write_ms / (double)writes" in body
    assert "if (reads)" in body
    assert "if (writes)" in body
    assert "nanosleep(" not in SOURCE
    assert '"first_sample"' in body
    assert '"counter_reset"' in body
    assert "json_object_new_null()" in SOURCE


def test_smartctl_is_argv_exec_with_limits_and_structured_degradation():
    executor = function_body("static int storage_exec_capture(")
    collector = function_body("static void storage_collect_smart(")
    parser = function_body("static void storage_parse_smart(")
    assert "fork()" in executor
    assert "execv(argv[0], argv)" in executor
    assert "popen(" not in SOURCE
    assert "system(" not in SOURCE
    assert "STORAGE_SMART_OUTPUT_MAX" in collector
    assert "STORAGE_SMART_TIMEOUT_MS" in collector
    assert "SIGTERM" in executor and "SIGKILL" in executor
    assert "waitpid(" in executor
    assert '(char *)"-j"' in collector
    for reason in (
        "smartctl_timeout",
        "smartctl_not_installed",
        "smartctl_json_invalid",
        "smart_not_supported",
    ):
        assert reason in parser or reason in collector
    assert '"temperature"' in parser
    assert '"power_on_time"' in parser
    assert "Reallocated_Sector_Ct" in SOURCE


def test_smart_cache_and_whole_request_budget_are_bounded():
    collector = function_body("static void storage_collect_smart(")
    api = function_body("struct json_object *jmx_storage_overview_get(")
    assert "STORAGE_SMART_CACHE_MS" in SOURCE
    assert "5LL * 60LL * 1000LL" in SOURCE
    assert "storage_smart_cache_find" in collector
    assert "storage_smart_cache_store" in collector
    assert "STORAGE_REQUEST_BUDGET_MS 3900" in SOURCE
    assert "request_deadline_ms" in api
    assert "storage_collect_smart(&disks[i], request_deadline_ms)" in api
    assert "storage_persist_samples(disks, disk_count, now," in api
    assert "storage_history_json(normalized_range, now," in api
    assert '"probe_budget_exhausted"' in SOURCE
    assert "timeout_ms = (int)(deadline_ms - now_ms" in collector
    assert SOURCE.count("sqlite3_busy_timeout(db, 50)") == 2


def test_runtime_db_schema_and_history_semantics():
    # Deliberately no assertion on JMX_DB_SCHEMA_VERSION here. This file is a
    # storage-overview contract; pinning the global schema version made every
    # unrelated migration turn it red (it was left at 6 while the source moved to
    # 7 and then 8, so the whole test was failing and masking real regressions).
    # The version gate belongs to test_core_startup_schema_contract.py, which
    # asserts it alongside the upgrade/downgrade logic that gives it meaning.
    # What this test needs is that the storage sample schema exists, which the
    # assertions below already cover by name.
    assert "CREATE TABLE IF NOT EXISTS storage_disk_sample" in DB
    assert "PRIMARY KEY(ts,disk_id)" in DB
    assert "idx_storage_disk_sample_ts" in DB
    assert "idx_storage_disk_sample_disk_ts" in DB
    assert "ON CONFLICT(ts,disk_id) DO UPDATE" in SOURCE
    history = function_body("static struct json_object *storage_history_json(")
    assert "ORDER BY bucket_ts ASC,disk_id ASC" in history
    assert "AVG(used_percent)" in history
    assert "AVG(read_bps)" in history
    assert "AVG(read_latency_ms)" in history
    assert '"1h"' in SOURCE and '"1d"' in SOURCE and '"7d"' in SOURCE
    assert "STORAGE_HISTORY_RETENTION_SEC" in SOURCE
    assert "DELETE FROM storage_disk_sample WHERE ts < ?1" in SOURCE


def test_unallocated_space_uses_authoritative_partition_table_extents():
    helper = function_body("static uint64_t storage_partitioned_bytes(")
    disk_json = function_body("static struct json_object *storage_disk_json(")
    api = function_body("struct json_object *jmx_storage_overview_get(")
    assert "disk->partitions[i].capacity_bytes" in helper
    assert "mounts[i].major == disk->major" in helper
    assert "mounts[i].minor == disk->minor" in helper
    assert "partitioned = disk->capacity_bytes" in helper
    assert "jmx_storage_unallocated_extents" in api
    assert "disk->capacity_bytes - partitioned_bytes" not in disk_json
    assert "disk->capacity_bytes - disk_partitioned" not in api
    assert '"partitioned_bytes"' in disk_json
    assert '"unallocated_bytes"' in disk_json
    assert '"unallocated_extents"' in disk_json
    assert '"unallocated_space_supported"' in disk_json
    assert '"sfdisk_partition_table_free_regions"' in api
    assert '"unallocated_space"' in api


def test_forbidden_integration_files_are_not_referenced_by_test_scope():
    # This phase intentionally exposes a data-layer function only. Ubus, webd,
    # netconfig, file-service, and build wiring are separate integration work.
    assert "jmx_dreamingwrt_api" not in SOURCE
    assert "webd" not in SOURCE
    assert "jmx_netconfig_db" not in SOURCE
