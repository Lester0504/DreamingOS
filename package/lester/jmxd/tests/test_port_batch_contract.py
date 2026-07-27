#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def section(start: str, end: str) -> str:
    begin = WEBD.index(start)
    finish = WEBD.index(end, begin)
    return WEBD[begin:finish]


def test_port_batch_reuses_single_port_executor() -> None:
    batch = section(
        "static struct json_object *webd_topology_port_batch_response(",
        "static struct json_object *webd_topology_port_transaction_validate_response(",
    )

    assert 'webd_topology_port_plan_response(req, request, 0' in batch
    assert 'webd_topology_port_plan_response(req, request, 1' in batch
    assert '"port_batch_preflight_failed"' in batch
    assert '"confirmation_required"' in batch
    assert '"atomic", json_object_new_boolean(0)' in batch
    assert '"partial", json_object_new_boolean(1)' in batch
    assert '"ordered_single_port_transactions"' in batch
    assert '"stop_on_error"' in batch
    assert '"partially_applied"' in batch
    assert '"stopped_after_error"' in batch
    assert "WEBD_PORT_BATCH_MAX 64" in WEBD


def test_port_batch_routes_precede_generic_ports_route() -> None:
    preview = '"/api/v1/topology/node/ports/batch/preview"'
    apply = '"/api/v1/topology/node/ports/batch/apply"'
    generic = '"/api/v1/topology/node/ports"'
    dispatch = WEBD.index("static void handle_client")

    assert WEBD.index(preview, dispatch) < WEBD.index(generic, dispatch)
    assert WEBD.index(apply, dispatch) < WEBD.index(generic, dispatch)
    assert 'webd_topology_port_batch_response(&req, body_json, apply' in WEBD
    assert '"method_not_allowed", "port batch requires POST"' in WEBD


def test_port_batch_capability_is_not_overclaimed() -> None:
    caps = section(
        "static struct json_object *webd_topology_port_write_capabilities(",
        "static int webd_array_add_unique_str(",
    )

    assert '"port_batch_preview", json_object_new_boolean(1)' in caps
    assert '"port_batch_apply", json_object_new_boolean(1)' in caps
    assert '"port_batch_atomic", json_object_new_boolean(0)' in caps
    assert '"port_batch_partial", json_object_new_boolean(1)' in caps
    assert '"port_batch_max_ports", json_object_new_int(WEBD_PORT_BATCH_MAX)' in caps


if __name__ == "__main__":
    test_port_batch_reuses_single_port_executor()
    test_port_batch_routes_precede_generic_ports_route()
    test_port_batch_capability_is_not_overclaimed()
    print("ok: port batch preview/apply contract")
