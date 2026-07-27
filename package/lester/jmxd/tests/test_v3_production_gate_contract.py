#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "src" / "jmx_v3_gate.h"
MAIN = ROOT.parent / "jmx" / "src" / "jmx_main.c"
RULES = ROOT.parent / "jmx" / "src" / "jmx_v3_rules.c"


def test_v3_production_gate_is_closed() -> None:
    gate = GATE.read_text(encoding="utf-8")
    assert "#define JMX_V3_PRODUCTION_GATE_ENABLED 0" in gate
    assert "return JMX_V3_MODE_OFF;" in gate


def test_shadow_match_cannot_reach_conntrack_appid_write() -> None:
    main = MAIN.read_text(encoding="utf-8")
    rules = RULES.read_text(encoding="utf-8")
    assert "v3_active_appid = jmx_v3_appid_for_commit(v3_appid, v3_mode);" in main
    assert "ct->jmx_data.app_id = v3_active_appid;" in main
    assert "ct->jmx_data.app_id = v3_appid;" not in main
    assert "return mode == JMX_V3_MODE_ACTIVE ? appid : 0;" in rules


if __name__ == "__main__":
    test_v3_production_gate_is_closed()
    test_shadow_match_cannot_reach_conntrack_appid_write()
    print("ok: v3 production gate and shadow write contract passed")
