#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
TOPOLOGY = (ROOT / "src/otad/otad_topology.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


otad_package = between(
    MAKEFILE,
    "define Package/dreamingwrt-otad",
    "define Package/dreamingwrt-otad/description",
)
jmxd_package = between(
    MAKEFILE,
    "define Package/jmxd",
    "define Package/jmxd/description",
)

assert "-DOTAD_AB_SLOTS_SUPPORTED=" in MAKEFILE
assert "$(CONFIG_TARGET_x86)" in MAKEFILE
assert "DREAMINGWRT_OTAD_BOOTENV_DEPENDS += +grub2-editenv" in MAKEFILE
assert "$(DREAMINGWRT_OTAD_BOOTENV_DEPENDS)" in otad_package
assert "+grub2-editenv" not in otad_package
assert "DREAMINGWRT_JMXD_OTAD_DEPENDS += +dreamingwrt-otad" in MAKEFILE
assert "$(DREAMINGWRT_JMXD_OTAD_DEPENDS)" in jmxd_package
assert "+dreamingwrt-otad" not in jmxd_package

assert '#define OTAD_AB_SLOTS_SUPPORTED 1' in TOPOLOGY
discover = between(
    TOPOLOGY,
    "static int topology_discover(",
    "int otad_ab_topology_readonly_probe(",
)
assert discover.index("if (!OTAD_AB_SLOTS_SUPPORTED)") < discover.index(
    "topology_partition_load(OTAD_SLOT_A_LABEL"
)
assert '"ab_slots_not_supported_on_target"' in discover

for start, end in (
    ("struct json_object *otad_firmware_preflight(",
     "struct json_object *otad_firmware_verify("),
    ("struct json_object *otad_firmware_apply(",
     "struct json_object *otad_confirm_boot("),
    ("struct json_object *otad_confirm_boot(",
     "void otad_reconcile_boot_state("),
    ("struct json_object *otad_firmware_rollback(",
     "static void otad_topology_missing_evidence("),
):
    function = between(FIRMWARE, start, end)
    assert "if (!OTAD_AB_SLOTS_SUPPORTED)" in function
    assert '"ab_slots_not_supported_on_target"' in function

worker = between(
    FIRMWARE,
    "int otad_operation_worker(",
    "struct json_object *otad_firmware_apply(",
)
assert "if (!OTAD_AB_SLOTS_SUPPORTED)" in worker
assert '"ab_slots_not_supported_on_target"' in worker
assert worker.index("if (!OTAD_AB_SLOTS_SUPPORTED)") < worker.index(
    "json_tokener_parse(work.options_json)"
)

slot_status = between(
    FIRMWARE,
    "struct json_object *otad_slot_status_json(",
    "static void otad_confirm_timer_cb(",
)
for contract in (
    '"ab_slots_supported"',
    '"single_slot"',
    '"mode", "single_slot"',
    '"layout", "single_slot"',
    '"ab_slots_not_supported_on_target"',
    '"resolver", "target_capability"',
):
    assert contract in slot_status
assert slot_status.index("if (!OTAD_AB_SLOTS_SUPPORTED)") < slot_status.index(
    "otad_ab_topology_readonly_probe("
)

print("ok: non-x86 otad exposes single-slot capability and fails A/B operations closed")
