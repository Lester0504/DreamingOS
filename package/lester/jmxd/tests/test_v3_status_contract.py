#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_core_status_exposes_v3_database_kernel_and_nack_state() -> None:
    main = (ROOT / "src/main.c").read_text(encoding="utf-8")
    loader = (ROOT / "src/jmx_signature_db.c").read_text(encoding="utf-8")
    for field in (
        "db_rules", "verified_rules", "enabled_rules", "loaded_rules",
        "userspace_catalog_bytes",
        "active_generation", "active_mode", "active_rules", "active_steps",
        "active_ports", "engine_capabilities", "last_nack_generation",
        "last_nack_reason", "last_nack_detail",
    ):
        assert f'"{field}"' in main
    assert "chain_verified_rules" in loader
    assert "chain_enabled_rules" in loader
    assert "rule_capacity * sizeof(*g_v3_chain_rules.rules)" in main
    assert "step_capacity * sizeof(*g_v3_chain_rules.steps)" in main
    assert "port_capacity * sizeof(*g_v3_chain_rules.ports)" in main


if __name__ == "__main__":
    test_core_status_exposes_v3_database_kernel_and_nack_state()
    print("ok: v3 status contract passed")
