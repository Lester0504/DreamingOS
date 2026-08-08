#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
STATUS = (ROOT / "src/otad/otad_status.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/otad/otad_ubus.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")


def require(source: str, *needles: str) -> None:
    for needle in needles:
        assert needle in source, f"missing contract token: {needle}"


require(
    FIRMWARE,
    "OTAD_STATUS_PROBE_VERIFIED",
    "OTAD_STATUS_PROBE_STALE",
    "OTAD_STATUS_PROBE_UNAVAILABLE",
    "otad_status_topology_identity_equal",
    "otad_status_ota_metadata_fingerprint",
    "ota_metadata_fingerprint",
    "SELECT key,value FROM ota_state WHERE key IN (",
    "'active_slot','pending_slot','pending_operation_id',",
    "'slot_a_valid','slot_b_valid') ORDER BY key",
    "FROM ota_slots ORDER BY slot_name",
    "otad_status_probe_store_verified",
    "otad_status_probe_store_failure",
    'return "live";',
    'return "cached";',
    'return "stale";',
    'return "unavailable";',
    '"probed_at"',
    '"probe_age_ms"',
    '"probe_generation"',
)
assert FIRMWARE.count("otad_slot_status_cache_invalidate();") >= 5
assert FIRMWARE.index("otad_slot_status_cache_invalidate();") < FIRMWARE.index(
    "otad_firmware_worker_start(operation_id)"
)
worker_done = FIRMWARE[
    FIRMWARE.index("static void otad_operation_process_done") :
    FIRMWARE.index("static int otad_firmware_worker_start")
]
assert "otad_slot_status_cache_invalidate();" in worker_done
assert "probe_state == OTAD_STATUS_PROBE_VERIFIED" in FIRMWARE
assert "boot_state_verified = topology_verified &&" in FIRMWARE
assert "otad_ab_topology_readonly_probe(" in FIRMWARE
assert "otad_ab_topology_discover(&verified_topology" in FIRMWARE
assert "OTAD_STATUS_PROBE_FAILURE_TTL_MS" in FIRMWARE
assert "ota_metadata_fingerprint !=" in FIRMWARE
assert "PRAGMA data_version" not in FIRMWARE

require(HEADER, "OTAD_STATUS_PROBE_CACHE_TTL_MS", "OTAD_STATUS_PROBE_FAILURE_TTL_MS")
require(STATUS, 'otad_json_bool(body, "refresh", 0)')
require(UBUS, "otad_json_from_blob(msg)", "otad_payload_or_self(body)")

print("otad_status_probe_cache_contract: PASS")
