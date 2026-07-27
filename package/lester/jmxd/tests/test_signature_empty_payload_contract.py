import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "augment_protocol_library.py"
SPEC = importlib.util.spec_from_file_location("augment_protocol_library", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def source_rule(match_method: int, pattern_b64: str):
    return MODULE.SourceRule(
        source_app_id=1,
        proto=6,
        direction=1,
        pkt_seq=1,
        pattern_b64=pattern_b64,
        match_method=match_method,
        offset=None,
        ports=(),
        priority=50,
        source_rule_id=99,
    )


def test_empty_exact_and_bm_payloads_are_rejected():
    assert source_rule(0, "").runtime_validation_error() == "empty_fixed_payload"
    assert source_rule(5, "").runtime_validation_error() == "empty_fixed_payload"


def test_non_fixed_empty_payload_keeps_its_separate_validation_path():
    assert source_rule(1, "").runtime_validation_error() is None
    assert source_rule(2, "").runtime_validation_error() is None


def test_non_empty_exact_payload_is_accepted():
    assert source_rule(0, "AQ==").runtime_validation_error() is None
    assert source_rule(0, "AQ==").pattern() == b"\x01"
