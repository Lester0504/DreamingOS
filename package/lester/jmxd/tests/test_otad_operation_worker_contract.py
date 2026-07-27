#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "src/otad/otad_main.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


worker_dispatch = MAIN.index('!strcmp(argv[1], "--operation-worker")')
ubus_start = MAIN.index("otad_ubus_start()")

assert worker_dispatch < ubus_start
assert "otad_operation_worker(argv[2])" in MAIN
assert MAIN.index("otad_db_init()") < worker_dispatch
assert MAIN.index("otad_db_close();", worker_dispatch) < ubus_start
assert 'execlp("dreamingwrt-otad", "dreamingwrt-otad",' in FIRMWARE
assert '"/usr/sbin/tune2fs", "-L", label, target' in FIRMWARE
assert "e2label" not in FIRMWARE
assert "otad_partlabel_path(label, dev, dev_len) != 0 ||" in FIRMWARE
assert "otad_label_path(" not in FIRMWARE
assert "static int otad_run_exit_code" in FIRMWARE
assert "(fsck_rc & ~(1 | 2)) != 0" in FIRMWARE
for error in (
    "inactive_slot_fsck_failed",
    "inactive_slot_uuid_update_failed",
    "inactive_slot_label_update_failed",
    "inactive_slot_resize_failed",
    "inactive_slot_post_resize_fsck_failed",
):
    assert error in FIRMWARE
assert FIRMWARE.count("fsck_rc = otad_run_exit_code(fsck_argv);") == 2
assert "otad_grubenv_clear_target(current, pending)" in FIRMWARE
assert '"rollback_requested"' in FIRMWARE
assert "otad_operation_find_active_firmware_apply(operation_id)" in FIRMWARE

otad_package = MAKEFILE[
    MAKEFILE.index("define Package/dreamingwrt-otad") :
    MAKEFILE.index("define Package/dreamingwrt-otad/description")
]
assert "+tune2fs" in otad_package
assert "+e2label" not in otad_package

print("ok: otad operation worker entrypoint and filesystem labeling contract")
