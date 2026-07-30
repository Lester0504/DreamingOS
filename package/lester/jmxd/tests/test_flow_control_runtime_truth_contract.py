#!/usr/bin/env python3
"""Legacy flow-control remains config-only until flowd owns verified apply."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_netconfig_db.c").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    start = SOURCE.index(f"struct json_object *{name}(")
    next_fn = SOURCE.find("\nstruct json_object *", start + 1)
    return SOURCE[start:] if next_fn < 0 else SOURCE[start:next_fn]


def test_legacy_apply_is_fail_closed() -> None:
    body = function_body("jmx_flow_control_apply")
    for required in (
        '"runtime_applied",json_object_new_boolean(0)',
        '"dataplane_apply_executor_missing"',
        '"capability_disabled"',
        'dry?API_CODE_SUCCESS:API_CODE_ERROR',
        '"planned",json_object_new_boolean(dry)',
    ):
        assert required in body, required
    for forbidden in (
        'fopen("/etc/config/dreamingwrt_flow"',
        "apply_state='applied'",
        '"applied",json_object_new_boolean(!dry)',
    ):
        assert forbidden not in body, forbidden


def test_read_model_labels_configuration_and_runtime_truth() -> None:
    for required in (
        "UPDATE flow_global SET apply_state='draft',last_apply_at=0 WHERE apply_state='applied'",
        '"source_of_truth",json_object_new_string("legacy_flow_control_config")',
        '"authoritative_runtime_source",json_object_new_string("dreamingwrt.flowd")',
        '"legacy_config_model",json_object_new_boolean(1)',
        '"configured_enabled"',
        '"runtime_applied",json_object_new_boolean(0)',
    ):
        assert required in SOURCE, required


if __name__ == "__main__":
    test_legacy_apply_is_fail_closed()
    test_read_model_labels_configuration_and_runtime_truth()
    print("ok: legacy flow-control cannot claim dataplane apply")
