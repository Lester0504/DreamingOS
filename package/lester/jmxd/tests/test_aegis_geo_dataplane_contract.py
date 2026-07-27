#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GEO = (ROOT / "src/aegisxd/aegisxd_geo.c").read_text()
INTERNAL = (ROOT / "src/aegisxd/aegisxd_internal.h").read_text()
UBUS = (ROOT / "src/aegisxd/aegisxd_ubus.c").read_text()
STATUS = (ROOT / "src/aegisxd/aegisxd_status.c").read_text()
MAKE = (ROOT / "src/Makefile").read_text()


def between(text: str, start: str, end: str) -> str:
    left = text.index(start)
    right = text.index(end, left)
    return text[left:right]


def test_sql_authorities_are_read_only_and_exact() -> None:
    assert '#define GEO_MMDB_PATH "/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb"' in GEO
    for table in ("firewall_geo_country", "firewall_geo_rule", "firewall_geo_meta"):
        assert table in GEO
    assert "SELECT network FROM geoip_country_prefix" not in GEO
    assert "geoip_country_prefix_missing" not in GEO
    assert "GEO_SIGNATURE_DB_PATH" not in GEO
    assert "SQLITE_OPEN_READONLY" in GEO
    assert "sqlite3_open_v2(AEGISXD_CONFIG_DB_PATH" not in GEO
    assert "CREATE TABLE" not in GEO
    assert "dwrt_geoip_country_prefix_load" in GEO
    assert "per_packet_mmdb_lookup" in GEO
    assert "sqlite_prefix_table_required" in GEO


def test_nft_is_independent_interval_and_has_no_empty_sets() -> None:
    assert '#define GEO_NFT_TABLE "dreamingwrt_aegis_geo"' in GEO
    assert '#define GEO_NFT_LOG AEGISXD_RUNTIME_DIR "/geo-nft.log"' in GEO
    assert "flags interval\\n" in GEO
    assert "auto-merge\\n    elements = {\\n      " in GEO
    write_set = between(GEO, "static int geo_write_set(", "static int geo_write_rule_line(")
    assert "count <= 0" in write_set
    assert "plan->prefixes.items" in write_set
    assert "inet_ntop" in write_set
    assert "sqlite3_prepare" not in write_set


def test_direction_action_and_zone_are_compiled_fail_closed() -> None:
    load = between(GEO, "static int geo_plan_load(", "static int geo_log_contains(")
    assert 'strcmp(action, "block")' in load and 'strcmp(action, "allow")' in load
    for direction in ("inbound", "outbound", "both"):
        assert f'strcmp(direction, "{direction}")' in load
    assert 'geo_plan_block(plan, "geo_zone_unresolved", detail)' in load
    zone = between(GEO, "static int geo_zone_resolve(", "static int geo_load_revision(")
    assert "return !zone || !zone[0];" in GEO
    assert 'geo_zone_load_table(db, "wan"' in zone
    assert 'geo_zone_load_table(db, "lan"' in zone
    assert 'return ifaces->count > 0 ? 0 : -1;' in zone
    emit = between(GEO, "static int geo_write_rule_line(", "static int geo_render_chain_rules(")
    assert '"iifname"' in emit and '"oifname"' in emit
    assert '"drop" : "accept"' in emit
    assert '!strcmp(direction, "inbound") ? "s" : "d"' in emit


def test_preview_confirm_revision_check_apply_readback_and_rollback() -> None:
    apply = between(GEO, "static struct json_object *geo_apply_plan(",
                    "static int geo_previous_state(")
    assert '"%s/geo-plan-%ld.nft"' in apply
    assert "geo_render_nft(&plan, artifact, table_before)" in apply
    assert "geo_nft_file_run(artifact, 1)" in apply
    assert "geo_runtime_space_check(&plan, table_before, &space)" in apply
    assert "table_before = geo_nft_table_state()" in apply
    assert '"nft_table_probe_failed"' in apply
    assert apply.index("geo_runtime_space_check(&plan, table_before, &space)") < apply.index(
        "geo_render_nft(&plan, artifact, table_before)"
    )
    assert "if (!confirm)" in apply
    assert '"artifact_retained"' in apply
    assert '"nft_artifact"' not in apply
    assert '"revision_required"' in apply
    assert '"revision_conflict"' in apply
    assert apply.index("geo_revision_now(&current_revision)") < apply.index(
        "geo_nft_file_run(artifact, 0)"
    )
    assert "geo_snapshot_table(snapshot)" in apply
    assert "geo_capture_readback(&readback)" in apply
    assert "geo_readback_matches_plan(&plan, &readback)" in apply
    matcher = between(GEO, "static int geo_readback_matches_plan(",
                      "struct json_object *aegisxd_geo_get_json(")
    assert "readback->set_count != plan->set_count" in matcher
    assert "readback->rule_count != plan->compiled_rule_count" in matcher
    assert "readback->element_count != plan->prefix_count" in matcher
    assert "readback->sets[j].element_count == expected" in matcher
    assert "geo_restore_transaction(table_before, snapshot, had_active, active_snapshot)" in apply
    assert apply.index("geo_capture_readback(&readback)") < apply.index(
        "geo_write_json_atomic(GEO_ACTIVE_PATH, active)"
    )
    parser = between(GEO, "/* GEO_READBACK_STREAM_BEGIN",
                     "/* GEO_READBACK_STREAM_END */")
    assert "struct geo_readback_parser" in parser
    assert "geo_readback_entry_commit" in parser
    assert "GEO_NFT_ENTRY_SET" in parser
    assert "GEO_NFT_ENTRY_ELEMENT" in parser
    assert "target_table_count != 1" in parser
    assert "GEO_JSON_MAX_TOKENS" in parser
    assert "GEO_READBACK_MAX_ELEMENTS" in parser
    assert "json_object" not in parser
    assert "GEO_JSON_MAX_TOKENS 16000000ULL" in GEO
    assert "7ULL * (uint64_t)GEO_SELECTED_PREFIX_MAX + 65536ULL" in GEO

    capture = between(GEO, "static int geo_capture_readback(",
                      "static int geo_snapshot_table(")
    assert "pipe(pipefd)" in capture
    assert "poll(&pfd" in capture
    assert "GEO_READBACK_MAX_BYTES" in capture
    assert "GEO_READBACK_TIMEOUT_MS" in capture
    assert "geo_readback_child_reap(pid, 1" in capture
    assert "geo_readback_child_reap(pid, 0" in capture
    assert "GEO_LEGACY_READBACK_PATH" in capture
    child = between(GEO, "static int geo_readback_child_reap(",
                    "static int geo_capture_readback(")
    assert "SIGTERM" in child
    assert "SIGKILL" in child
    assert "waitpid" in child

    nft_runner = between(GEO, "static int geo_nft_run(",
                         "static uint64_t geo_u64_add(")
    assert "GEO_NFT_TIMEOUT_MS" in nft_runner
    assert "GEO_NFT_FILE_MAX_BYTES" in nft_runner
    assert "GEO_NFT_LOG_MAX_BYTES" in nft_runner
    assert "geo_readback_child_reap" in nft_runner
    assert "O_NONBLOCK" in nft_runner
    assert "rename(tmp, output_path)" in nft_runner
    assert "WEXITSTATUS(status) == 0" in nft_runner

    storage = between(GEO, "static uint64_t geo_u64_add(",
                      "static int geo_write_ifaces(")
    assert "geo_runtime_space_check" in storage
    assert "statvfs(AEGISXD_RUNTIME_DIR" in storage
    assert "GEO_RUNTIME_RESERVE_BYTES" in storage
    assert "snapshot = table_present ? GEO_NFT_FILE_MAX_BYTES : 0" in storage
    table_probe = between(GEO, "static int geo_nft_table_state(",
                          "/* GEO_NFT_RUNNER_BEGIN */")
    assert "return 1" in table_probe and "return 0" in table_probe
    assert "return -1" in table_probe
    assert "rc != 0" in table_probe
    assert "unlink(GEO_NFT_LOG)" in table_probe
    assert 'geo_log_contains("No such file or directory")' in table_probe
    assert 'setenv("LC_ALL", "C", 1)' in nft_runner


def test_disable_rollback_ubus_status_and_build_wiring() -> None:
    operations = between(GEO, "static struct json_object *geo_disable_or_rollback(",
                         "struct json_object *aegisxd_geo_apply_json(")
    assert '"disable"' in operations and '"rollback"' in operations
    assert "geo_previous_state" in operations
    assert "geo_nft_file_run(batch, 1)" in operations
    assert "geo_revision_now(&recheck)" in operations
    assert "geo_restore_transaction(table_before, before, had_active, before_active)" in operations
    assert "table_before = geo_nft_table_state()" in operations
    assert "table_after = geo_nft_table_state()" in operations
    assert "aegisxd_geo_get_json" in INTERNAL
    assert "aegisxd_geo_apply_json" in INTERNAL
    assert 'UBUS_METHOD("geo_get", aegisxd_handle_geo_get' in UBUS
    assert 'UBUS_METHOD("geo_apply", aegisxd_handle_geo_apply' in UBUS
    assert '"geo_country", aegisxd_geo_status_json()' in STATUS
    assert "aegisxd/aegisxd_geo.o" in MAKE
    assert "geoip/mmdb_country_prefix.o" in MAKE
    assert "-lmaxminddb" in MAKE


if __name__ == "__main__":
    test_sql_authorities_are_read_only_and_exact()
    test_nft_is_independent_interval_and_has_no_empty_sets()
    test_direction_action_and_zone_are_compiled_fail_closed()
    test_preview_confirm_revision_check_apply_readback_and_rollback()
    test_disable_rollback_ubus_status_and_build_wiring()
    print("ok: AegisXD Geo SQL, nft, zone, guarded apply, readback, and rollback contract")
