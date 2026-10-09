#!/usr/bin/env python3
"""Static contract for the APD BLE provisioning backend."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APD = ROOT / "src/apd"


def test_protocol_constants_and_frame_limits() -> None:
    header = (APD / "apd_ble.h").read_text(encoding="utf-8")
    for token in (
        "APD_BLE_PROTOCOL_VERSION 1",
        "APD_BLE_SERVICE_UUID",
        "APD_BLE_DEVICE_INFO_UUID",
        "APD_BLE_CONTROL_UUID",
        "APD_BLE_EVENTS_UUID",
        "APD_BLE_MTU 247U",
        "APD_BLE_MAX_FRAME 244U",
        "APD_BLE_MAX_REQUEST 16384U",
        "APD_BLE_X25519_KEY_LEN 32U",
        "APD_BLE_TAG_LEN 16U",
    ):
        assert token in header
    assert "APD_BLE_MAX_FRAGMENT_PLAINTEXT" in header


def test_ubus_surface_is_complete() -> None:
    ubus = (APD / "apd_ubus.c").read_text(encoding="utf-8")
    for method in (
        "ble_provision_begin",
        "ble_provision_physical_confirm",
        "ble_provision_stage",
        "ble_provision_commit",
        "ble_provision_status",
        "ble_provision_cancel",
    ):
        assert f'"{method}"' in ubus
    assert "apd_ble_begin_json" in ubus
    assert "apd_ble_stage_json" in ubus
    assert "apd_ble_commit_json" in ubus
    assert "apd_ble_status_json" in ubus
    assert "apd_ble_cancel_json" in ubus


def test_security_boundaries() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    db = (APD / "apd_ble_db.c").read_text(encoding="utf-8")
    crypto = (APD / "apd_ble_crypto.c").read_text(encoding="utf-8")

    assert "physical_auth_required" in ble
    assert "APD_BLE_ERR_REPLAY" in crypto
    assert "APD_BLE_FRAME_MAGIC" in crypto
    assert "EVP_chacha20_poly1305()" in crypto
    assert "HKDF" in crypto
    assert "OPENSSL_cleanse" in ble
    assert "request_digest" in db
    assert "private_key" not in db
    assert "bootstrap_nonce" in db
    assert "CREATE TABLE IF NOT EXISTS apd_ble_session" in db


def test_gattdb_uses_user_managed_value() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    assert "APD_BG_GATTDB_USER_MANAGED_VALUE" in ble
    assert "APD_BG_EVT_GATTS_USER_READ_REQUEST" in ble
    assert "APD_BG_EVT_GATTS_USER_WRITE_REQUEST" in ble
    assert "APD_BG_CMD_GATTS_SEND_USER_READ_RSP" in ble
    assert "APD_BG_CMD_GATTS_SEND_USER_WRITE_RSP" in ble


def test_commit_validates_protocol_version() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    assert "protocol_version_mismatch" in ble
    assert "unsupported_protocol" in ble


def test_commit_applies_wifi_before_bootstrap() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    # wifi apply must come before bootstrap write
    wifi_pos = ble.find("wifi config applied")
    bootstrap_pos = ble.find("bootstrap written")
    assert wifi_pos > 0, "wifi config applied log not found"
    assert bootstrap_pos > 0, "bootstrap written log not found"
    assert wifi_pos < bootstrap_pos, "wifi must be applied before bootstrap"


def test_commit_returns_enrollment_pending() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    assert "enrollment_pending" in ble
    assert "wifi_apply_failed" in ble


def test_init_ordering() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    memset_pos = ble.find("memset(&g_apd_ble")
    recover_pos = ble.find("apd_ble_db_recover()")
    assert memset_pos > 0, "memset not found"
    assert recover_pos > 0, "db_recover not found"
    assert memset_pos < recover_pos, "memset must come before db_recover"


def test_notification_includes_connection_handle() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    assert "connection_valid" in ble
    assert "connection_handle" in ble
    assert "g_apd_ble_device_info_cache" in ble


def test_setup_code_uses_eth0_mac_suffix() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    assert "apd_ble_setup_code_matches_eth0" in ble
    assert '/sys/class/net/eth0/address' in ble
    assert "strlen(setup_code) != 4" in ble
    assert "expected[0] = mac[12]" in ble
    assert "expected[2] = mac[15]" in ble
    assert 'return apd_ble_error("setup_code_invalid")' in ble
    assert 'return apd_ble_error("physical_auth_unavailable")' in ble
    assert "apd_ble_db_physical_confirm(session_id)" in ble


def test_handshake_and_fail_closed_guards() -> None:
    ble = (APD / "apd_ble.c").read_text(encoding="utf-8")
    ubus = (APD / "apd_ubus.c").read_text(encoding="utf-8")
    assert "APD_BLE_HANDSHAKE_LEN" in ble
    assert 'memcmp(data, "DWHS", 4)' in ble
    assert "handshake_required" in ble
    assert "config_executor_unavailable" in ble
    assert "apd_ble_begin_json_ex" in ubus
    assert "apd_ble_physical_confirm_json_ex" in ubus


def test_http_bridge_contract() -> None:
    webd = ROOT / "src/webd"
    bridge = (webd / "api/api_ble_provision.c").read_text(encoding="utf-8")
    router = (webd / "api/api_router.c").read_text(encoding="utf-8")
    perms = (webd / "jmx_app_perms.c").read_text(encoding="utf-8")
    makefile = (ROOT / "src/Makefile").read_text(encoding="utf-8")
    for path in (
        "/api/v1/ac/ble-provision/begin",
        "/api/v1/ac/ble-provision/physical-confirm",
        "/api/v1/ac/ble-provision/status",
        "/api/v1/ac/ble-provision/commit",
        "/api/v1/ac/ble-provision/cancel",
    ):
        assert path in bridge
        assert path in perms
    assert "ble_provision_api_routes" in router
    assert "api_ble_provision.o" in makefile
    assert '"dreamingwrt.apd"' in bridge
    for token in (
        '"bootstrap_id"', '"request_id"', '"app_public_key"',
        '"ble_peripheral_id"', '"setup_code"', '"session_id"',
        "ble_body_allowed", "ble_query_session", "physical_auth_unavailable",
    ):
        assert token in bridge


if __name__ == "__main__":
    # Every test defined above must be listed here.  31.6's copy called a
    # test_commit_does_not_claim_success_without_executor() that no version of
    # this file ever defined, so the module died with NameError after three
    # tests and the remaining nine -- including the whole handshake / HTTP
    # bridge group -- never ran while the file reported failure for a wiring
    # reason rather than a contract violation.
    test_protocol_constants_and_frame_limits()
    test_ubus_surface_is_complete()
    test_security_boundaries()
    test_gattdb_uses_user_managed_value()
    test_commit_validates_protocol_version()
    test_commit_applies_wifi_before_bootstrap()
    test_commit_returns_enrollment_pending()
    test_init_ordering()
    test_notification_includes_connection_handle()
    test_setup_code_uses_eth0_mac_suffix()
    test_handshake_and_fail_closed_guards()
    test_http_bridge_contract()
    print("ok: APD BLE provisioning static contract")
