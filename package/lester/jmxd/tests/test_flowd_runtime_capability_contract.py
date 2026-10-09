#!/usr/bin/env python3
"""Static and executable contracts for flowd runtime/apply capability truth."""

from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "jmxd" / "tests"))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
FLOWD = ROOT / "src" / "flowd"
DB = (FLOWD / "flowd_db.c").read_text(encoding="utf-8")
CONTRACT = (FLOWD / "flowd_runtime_contract.h").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def test_status_settings_and_runtime_share_fail_closed_contract() -> None:
    require_all(CONTRACT, (
        'FLOWD_RUNTIME_CONTRACT_VERSION "flow-engine-runtime-v1"',
        'FLOWD_EFFECTIVE_APPLY_MODE "managed"',
        'FLOWD_APPLY_MODE_DISABLED_REASON "flowd_apply_mode_disabled"',
        'FLOWD_APPLY_UNAVAILABLE_REASON "dataplane_apply_executor_missing"',
        'FLOWD_READBACK_UNAVAILABLE_REASON "dataplane_readback_not_implemented"',
        'FLOWD_RUNTIME_DB_MISSING_REASON "runtime_db_missing"',
        'FLOWD_RUNTIME_NOT_APPLIED_REASON "runtime_not_applied"',
        'FLOWD_RUNTIME_NOT_POPULATED_REASON "runtime_not_populated"',
        '"configured_enabled"',
        '"configured_apply_mode"',
        '"worker_available"',
        '"runtime_snapshot_available"',
        '"runtime_db_present"',
        '"runtime_db_openable"',
        '"runtime_populated"',
        '"runtime_applied"',
        '"runtime_reason"',
        '"flow_engine_read"',
        '"flow_engine_config_write"',
        '"flow_engine_apply"',
        '"flow_engine_runtime_readback"',
        '"config_store_unavailable"',
        '"reasons"',
    ), "flowd runtime capability contract")
    assert DB.count("flowd_runtime_contract_add(resp, &runtime_contract)") == 4
    assert DB.count("runtime_contract.runtime_snapshot_available = 1") == 1
    assert "flowd_runtime_db_probe" not in DB
    assert "flowd_runtime_db_probe" not in CONTRACT
    assert DB.count("runtime_contract.nft_binary_available = access(FLOWD_NFT_BINARY, X_OK) == 0") == 3
    assert DB.count("runtime_contract.runtime_dir_available = flowd_dir_exists(") == 3
    for text, scope in ((DB, "flowd_db.c"), (CONTRACT, "flowd_runtime_contract.h")):
        assert "plan-only" not in text, f"{scope} still contains plan-only"
        assert "running-plan-only" not in text, f"{scope} still contains running-plan-only"


def test_dataplane_write_requires_managed_mode() -> None:
    require_all(DB, (
        "UPDATE flowd_settings SET apply_mode='managed'",
        "WHERE id=1 AND apply_mode='disabled' AND updated_at=0",
        "apply_mode TEXT NOT NULL DEFAULT 'managed'",
        '"managed"',
        's.enabled && !strcmp(s.apply_mode, "managed") ? "running" : "disabled"',
        "settings_available = flowd_settings_load(&settings) == 0",
        "flowd_dataplane_write_guard",
        "flowd_runtime_consumer_unavailable",
    ), "flowd effective apply mode guard")
    assert "WHERE apply_mode NOT IN ('disabled','managed')" in DB
    assert '!strcmp(apply_mode, "disabled") ||' in DB
    assert "updated_at > 0" in DB
    assert "flowd_apply_mode_disabled" in DB


def test_settings_partial_update_preserves_paths_and_fails_closed() -> None:
    require_all(DB, (
        "char geoip_dir_default[FLOWD_MAX_TEXT]",
        "char runtime_dir_default[FLOWD_MAX_TEXT]",
        "char apply_mode_default[sizeof(s.apply_mode)]",
        'flowd_json_str(body, "geoip_dir", geoip_dir_default)',
        'flowd_json_str(body, "runtime_dir", runtime_dir_default)',
        'flowd_json_str(body, "apply_mode", apply_mode_default)',
        "if (flowd_mkdir_p(runtime_dir, 0755) != 0)",
        'flowd_error("runtime_dir_unavailable"',
    ), "flowd settings partial update contract")
    assert 'flowd_json_str(body, "geoip_dir", s.geoip_dir)' not in DB
    assert 'flowd_json_str(body, "runtime_dir", s.runtime_dir)' not in DB
    assert 'flowd_json_str(body, "apply_mode", s.apply_mode)' not in DB


def test_enabled_counts_are_explicitly_configuration_intent() -> None:
    require_all(DB, (
        "flowd_status_configured_count_aliases",
        '"configured_%s"',
        '"configured_enabled_prefix"',
        '"configuration rows with enabled=1; not kernel-applied rules"',
        '"legacy_enabled_prefix"',
        '"compatibility alias of configured_enabled_*"',
        '"runtime_truth_field"',
        '"runtime_applied"',
    ), "flowd configured count aliases")
    for field in (
        "sources", "country_policies", "objects", "custom_protocols",
        "route_groups", "wan_capacity", "wan_health", "split_rules",
        "domain_rules", "qos_classes", "qos_rules", "smart_qos_categories",
        "quota_rules", "conn_limit_rules", "app_rules",
    ):
        assert f'"enabled_{field}"' in DB


def test_runtime_contract_behavior() -> None:
    harness = textwrap.dedent(r'''
        #include <assert.h>
        #include <string.h>
        #include <json-c/json.h>
        #include "flowd_runtime_contract.h"

        static struct json_object *field(struct json_object *o, const char *name) {
            struct json_object *value = NULL;
            assert(json_object_object_get_ex(o, name, &value));
            return value;
        }

        static void verify(int enabled, const char *mode, int config_store,
                           int snapshot, int nft_binary, int runtime_dir,
                           const char *reason, int expected_config_write,
                           int expected_apply, int expected_ready,
                           int expected_readback, const char *readback_reason) {
            struct flowd_runtime_contract_input input = {
                .configured_enabled = enabled,
                .configured_apply_mode = mode,
                .config_store_available = config_store,
                .runtime_snapshot_available = snapshot,
                .nft_binary_available = nft_binary,
                .runtime_dir_available = runtime_dir,
                .tc_binary_available = nft_binary,
                .apply_executor_available = nft_binary,
                .runtime_readback_available = nft_binary,
                .runtime_db_present = snapshot,
                .runtime_db_openable = snapshot,
                .runtime_populated = snapshot,
            };
            struct json_object *response = json_object_new_object();
            struct json_object *capabilities;
            struct json_object *reasons;

            flowd_runtime_contract_add(response, &input);
            assert(json_object_get_boolean(field(response, "worker_available")) == 1);
            assert(json_object_get_boolean(field(response, "runtime_applied")) == 0);
            assert(json_object_get_boolean(field(response, "degraded")) == 1);
            assert(json_object_get_boolean(field(response, "runtime_snapshot_available")) == snapshot);
            assert(json_object_get_boolean(field(response, "runtime_db_present")) == snapshot);
            assert(json_object_get_boolean(field(response, "runtime_db_openable")) == snapshot);
            assert(json_object_get_boolean(field(response, "runtime_populated")) == snapshot);
            assert(strcmp(json_object_get_string(field(response, "configured_apply_mode")), mode) == 0);
            assert(strcmp(json_object_get_string(field(response, "apply_mode")), mode) == 0);
            assert(strcmp(json_object_get_string(field(response, "runtime_reason")), reason) == 0);

            capabilities = field(response, "capabilities");
            assert(json_object_get_boolean(field(capabilities, "flow_engine_read")) == 1);
            assert(json_object_get_boolean(field(capabilities, "flow_engine_config_write")) == expected_config_write);
            assert(json_object_get_boolean(field(capabilities, "flow_engine_apply")) == expected_apply);
            assert(json_object_get_boolean(field(capabilities, "flow_engine_apply_ready")) == expected_ready);
            assert(json_object_get_boolean(field(capabilities, "flow_engine_runtime_readback")) == expected_readback);
            assert(json_object_get_boolean(field(capabilities, "nft_revision_transaction")) ==
                   (config_store && nft_binary));
            assert(json_object_get_boolean(field(capabilities, "nft_revision_readback")) ==
                   (config_store && nft_binary && runtime_dir));
            assert(json_object_get_boolean(field(capabilities, "nft_revision_sentinel_only")) == 1);
            reasons = field(capabilities, "reasons");
            assert(strcmp(json_object_get_string(field(reasons, "flow_engine_apply")), reason) == 0);
            assert(strcmp(json_object_get_string(field(reasons, "flow_engine_runtime_readback")),
                          readback_reason) == 0);
            if (!config_store)
                assert(strcmp(json_object_get_string(field(reasons, "flow_engine_config_write")),
                              "config_store_unavailable") == 0);
            if (!config_store || !nft_binary) {
                const char *nft_reason = config_store
                    ? "nft_binary_unavailable" : "config_store_unavailable";
                assert(strcmp(json_object_get_string(field(reasons, "nft_revision_transaction")),
                              nft_reason) == 0);
                assert(strcmp(json_object_get_string(field(reasons, "nft_revision_readback")),
                              nft_reason) == 0);
            } else if (!runtime_dir) {
                assert(strcmp(json_object_get_string(field(reasons, "nft_revision_readback")),
                              "runtime_dir_unavailable") == 0);
            }
            json_object_put(response);
        }

        int main(void) {
            verify(1, "disabled", 1, 0, 1, 1, "flowd_apply_mode_disabled", 0, 0, 0, 0,
                   "flowd_apply_mode_disabled");
            verify(1, "managed", 1, 0, 1, 1, "runtime_db_missing", 1, 0, 0, 0,
                   "runtime_db_missing");
            verify(1, "managed", 1, 1, 1, 1, "runtime_not_applied", 1, 1, 1, 1,
                   "runtime_not_applied");
            verify(0, "managed", 1, 1, 1, 1, "flow_engine_disabled", 0, 0, 0, 0,
                   "flow_engine_disabled");
            verify(1, "managed", 1, 1, 0, 1, "dataplane_apply_executor_missing", 1, 0, 0, 0,
                   "dataplane_readback_not_implemented");
            verify(1, "disabled", 0, 0, 1, 1, "flowd_apply_mode_disabled", 0, 0, 0, 0,
                   "flowd_apply_mode_disabled");
            return 0;
        }
    ''')
    # Keyed on real resolvability: pkg-config has no json-c entry on 31.6, so
    # the old probe printed "skip" there and the contract went unexercised.
    if not apd_test_deps.have_package("json-c"):
        print("skip: executable flowd contract fixture requires host json-c development metadata")
        return
    flags = apd_test_deps.package_flags("json-c")
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "flowd_runtime_contract_test.c"
        binary = Path(td) / "flowd_runtime_contract_test"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-I", str(FLOWD), str(source), *flags, "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    test_status_settings_and_runtime_share_fail_closed_contract()
    test_dataplane_write_requires_managed_mode()
    test_enabled_counts_are_explicitly_configuration_intent()
    test_runtime_contract_behavior()
    print("ok: flowd runtime capability contract remains fail-closed until managed apply/readback exist")
