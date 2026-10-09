#!/usr/bin/env python3
"""DHCP operation audit semantic contract.

The DHCP editor writes an entire scope when it changes one reservation. The
ledger must therefore classify the reservation delta, retain actor/IP
provenance, and emit one semantic event rather than a URL-shaped fallback.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
WEB = webd_dispatch_text()


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


def test_schema_and_publisher_preserve_failure_stage() -> None:
    assert '" failure_stage TEXT DEFAULT' in WEB
    assert 'app_db_add_column_if_missing("api_audit_log", "failure_stage"' in WEB
    assert '"failure_stage", json_object_new_string(safe_stage' in WEB
    insert = between(
        WEB,
        "static void jmx_app_audit_log_full_stage",
        "static void jmx_app_audit_log_full(",
    )
    assert "failure_stage) " in insert
    assert "sqlite3_bind_text(st, 16, failure_stage" in insert


def test_dhcp_events_are_named_and_redact_reservation_notes() -> None:
    helper = between(
        WEB,
        "struct webd_dhcp_audit_operation",
        "static int app_setup_is_initialized",
    )
    for action in (
        "network.dhcp.scope.update",
        "network.dhcp.reservation.create",
        "network.dhcp.reservation.update",
        "network.dhcp.reservation.delete",
        "network.dhcp.apply.failed",
        "network.dhcp.rollback.failed",
    ):
        assert action in helper
    target = between(
        helper,
        "static void webd_dhcp_audit_target",
        "static void webd_dhcp_audit_classify_put",
    )
    assert '"lan=%s reservation=%s' in target
    assert '"remark"' not in target
    assert '"name"' not in target
    equal = between(
        helper,
        "static int webd_dhcp_reservation_semantic_equal",
        "static void webd_dhcp_audit_target",
    )
    assert '"remark"' in equal


def test_full_scope_put_classifies_one_reservation_delta() -> None:
    classify = between(
        WEB,
        "static void webd_dhcp_audit_classify_put",
        "static void webd_dhcp_audit_classify_request",
    )
    assert "creates == 1 && updates == 0 && deletes == 0" in classify
    assert "creates == 0 && updates == 1 && deletes == 0" in classify
    assert "network.dhcp.reservation.create" in classify
    assert "network.dhcp.reservation.update" in classify
    assert "network.dhcp.scope.update" in classify
    assert "webd_dhcp_reservation_semantic_equal" in classify


def test_every_dhcp_write_path_uses_the_same_emitter() -> None:
    routes = between(
        WEB,
        "    /* ── DHCP service ── */",
        "    /* ── DNS service ── */",
    )
    assert routes.count("webd_dhcp_audit_classify_request") == 2
    assert routes.count("webd_dhcp_audit_emit") == 2
    assert 'app_ubus_invoke_timeout("dhcp_service_set", merged_body, 15000)' in routes
    assert 'app_ubus_invoke_timeout("dhcp_reservation_delete", params, 15000)' in routes


def test_denials_and_api_key_success_are_deduplicated() -> None:
    auth = between(
        WEB,
        "    /* ── All remaining routes require Bearer token ── */",
        "    /* Scratch buffer for the API-Key management routes below;",
    )
    assert auth.count("webd_dhcp_audit_emit") >= 3
    assert "if (!webd_dhcp_route_is_write(req.method, req.path))" in auth
    assert "role_forbidden" in auth
    assert "group_forbidden" in auth
    assert "WEBD_API_KEY_SCOPE_DENIED" in auth
    assert "csrf_rejected" in WEB
    csrf = between(
        WEB,
        "if ((!strncmp(req.path, \"/api/v1/uploads\"",
        "const char *required_permission",
    )
    assert "webd_dhcp_audit_emit" in csrf


def test_actor_and_ip_provenance_remain_structured() -> None:
    actor = between(
        WEB,
        "static const char *webd_dhcp_audit_actor",
        "static void webd_dhcp_audit_emit",
    )
    assert 'return "api_key"' in actor
    assert "webd_identity_is_user(device_id)" in actor
    assert '"app:%s"' in actor
    emit = between(
        WEB,
        "static void webd_dhcp_audit_emit",
        "static int app_setup_is_initialized",
    )
    assert "g_webd_audit_source_ip" in emit
    publisher = between(
        WEB,
        "static void webd_audit_publish_logd_full",
        "static void webd_audit_publish_logd(",
    )
    for field in ("actor_channel", "client_ip", "peer_ip", "ip_source"):
        assert f'"{field}"' in publisher


if __name__ == "__main__":
    test_schema_and_publisher_preserve_failure_stage()
    test_dhcp_events_are_named_and_redact_reservation_notes()
    test_full_scope_put_classifies_one_reservation_delta()
    test_every_dhcp_write_path_uses_the_same_emitter()
    test_denials_and_api_key_success_are_deduplicated()
    test_actor_and_ip_provenance_remain_structured()
    print("ok: DHCP semantic audit contract")
