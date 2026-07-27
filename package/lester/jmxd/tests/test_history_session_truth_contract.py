#!/usr/bin/env python3
"""Legacy session history must not synthesize samples from the current count."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")


def section(start: str, end: str) -> str:
    begin = SOURCE.index(start)
    finish = SOURCE.index(end, begin)
    return SOURCE[begin:finish]


def test_history_session_is_explicitly_degraded_without_a_producer() -> None:
    body = section(
        "struct json_object *jmx_api_get_history_session(struct json_object *req_obj) {",
        "/* ── get_feature_info",
    )
    assert '"current_supported", json_object_new_boolean(1)' in body
    assert '"history_supported", json_object_new_boolean(0)' in body
    assert '"complete", json_object_new_boolean(0)' in body
    assert '"source", json_object_new_string("proc_af_conn_current")' in body
    assert '"history_aggregation_unavailable"' in body
    assert '"avg", json_object_new_null()' in body
    assert '"peak", json_object_new_null()' in body
    assert "struct json_object *list = json_object_new_array();" in body
    assert "json_object_array_add(list" not in body
    assert "json_object_new_int(current)" not in body.split(
        '"current", json_object_new_int(current)', 1
    )[1]


if __name__ == "__main__":
    test_history_session_is_explicitly_degraded_without_a_producer()
    print("ok: legacy session history returns real current data and an explicit empty history")
