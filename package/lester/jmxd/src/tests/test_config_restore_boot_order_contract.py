#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "init" / "dreamingwrt_init.c"
INIT_SCRIPT = ROOT.parent / "files" / "dreamingwrt-init.init"
PERSIST_SCRIPT = ROOT.parents[1] / "dreamingwrt-installer" / "files" / "dreamingwrt-persist.init"


def start_order(path: Path) -> int:
    match = re.search(r"^START=(\d+)\s*$", path.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, path
    return int(match.group(1))


def main() -> None:
    source = INIT.read_text(encoding="utf-8")
    if PERSIST_SCRIPT.is_file():
        assert start_order(PERSIST_SCRIPT) < start_order(INIT_SCRIPT)
    else:
        # dreamingwrt-installer is not part of the 26.07.1 public tree; the
        # boot-order half of this contract is checked where that package exists.
        print("skip: dreamingwrt-persist.init is not part of the public tree")
    assert 'maybe_apply_armed_config_restore("supervisor_start")' in source
    assert 'maybe_apply_armed_config_restore("persistent_store_ready")' in source
    assert "g_config_restore_attempted_operation" in source
    assert source.index('maybe_apply_armed_config_restore("persistent_store_ready")') > source.index("while (!g_stop_requested)")
    print("config_restore_boot_order_contract: PASS")


if __name__ == "__main__":
    main()
