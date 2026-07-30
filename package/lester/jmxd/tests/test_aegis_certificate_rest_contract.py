#!/usr/bin/env python3
"""Static REST/RBAC contract for AegisX inspection CA management."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/aegisxd/aegisxd_ubus.c").read_text(encoding="utf-8")
STATUS = (ROOT / "src/aegisxd/aegisxd_status.c").read_text(encoding="utf-8")


def test_rest_routes_and_binary_download() -> None:
    routes = [
        "/api/v1/aegis/certificates/inspection-ca",
        "/api/v1/aegis/certificates/inspection-ca/generate",
        "/api/v1/aegis/certificates/inspection-ca/rotate",
        "/api/v1/aegis/certificates/inspection-ca/revoke",
        "/api/v1/aegis/certificates/inspection-ca/download",
        "/api/v1/aegis/certificates/inspection-ca/distributions",
    ]
    for route in routes:
        assert route in WEB
    assert "webd_aegis_certificate_download_response" in WEB
    assert "http_send_download" in WEB
    assert "content_base64" in WEB
    assert "aegis.certificate.generate" in WEB
    assert "aegis.certificate.rotate" in WEB
    assert "aegis.certificate.revoke" in WEB
    assert '"certificate_distribution_superseded"' in WEB
    assert '"certificate_distribution_ca_revoked"' in WEB
    assert "return 410" in WEB


def test_ubus_and_capability_truthfulness() -> None:
    for method in [
        "certificate_status", "certificate_generate", "certificate_rotate",
        "certificate_revoke", "certificate_download", "certificate_distributions",
        "certificate_distribution_downloaded", "certificate_distribution_create",
        "certificate_distribution_get",
    ]:
        assert f'UBUS_METHOD("{method}"' in UBUS
    assert '"ssl_inspection", json_object_new_boolean(0)' in STATUS
    assert '"inspection_ca_management", json_object_new_boolean(1)' in STATUS
    assert '"inspection_ca_automatic_distribution", json_object_new_boolean(0)' in STATUS
    assert "trusted_terminal_certificate_agent_missing" in STATUS


def test_owner_only_ca_lifecycle_and_admin_manual_distribution() -> None:
    for suffix in ["generate", "rotate", "revoke"]:
        line = next(line for line in PERMS.splitlines()
                    if f'inspection-ca/{suffix}"' in line)
        assert "JMX_RISK_HIGH" in line
    distribution_write = next(
        line for line in PERMS.splitlines()
        if 'inspection-ca/distributions"' in line and '"POST"' in line
    )
    assert "JMX_RISK_MEDIUM" in distribution_write
