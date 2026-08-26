#!/usr/bin/env python3
"""Fail-closed capability and IPC contract for AP control Phase 0."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def read_required(path: Path) -> str:
    assert path.is_file(), f"required production file is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def source_bundle(directory: Path) -> str:
    paths = sorted(path for path in directory.glob("*") if path.suffix in {".c", ".h"})
    assert paths, f"required production source directory is missing or empty: {directory.relative_to(ROOT)}"
    return "\n".join(read_required(path) for path in paths)


def function_body(text: str, symbol: str) -> str:
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert match, f"production function body is missing: {symbol}"
    start = match.end()
    depth = 1
    pos = start
    quote = ""
    line_comment = False
    block_comment = False
    while pos < len(text) and depth:
        char = text[pos]
        next_char = text[pos + 1] if pos + 1 < len(text) else ""
        if line_comment:
            line_comment = char != "\n"
            pos += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                pos += 2
            else:
                pos += 1
            continue
        if quote:
            if char == "\\":
                pos += 2
                continue
            if char == quote:
                quote = ""
            pos += 1
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            pos += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            pos += 2
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"could not delimit production function: {symbol}"
    return text[start:pos - 1]


def ubus_methods(source: str) -> set[str]:
    return set(re.findall(r'UBUS_METHOD(?:_NOARG)?\(\s*"([^"]+)"', source))


def assert_boolean_false(body: str, capability: str) -> None:
    pattern = rf'\b(?:ac|apd)_capability\s*\([^;]*?"{re.escape(capability)}"\s*,\s*0\s*,'
    assert re.search(pattern, body), f"Phase 0 write capability must be explicitly false: {capability}"


def assert_boolean_dynamic(body: str, capability: str) -> None:
    pattern = rf'\b(?:ac|apd)_capability\s*\([^;]*?"{re.escape(capability)}"\s*,\s*wifi_write_execution\s*,'
    assert re.search(pattern, body), (
        f"managed-AP capability must follow the live v3 write gate: {capability}"
    )


def test_all_phase0_write_capabilities_are_explicitly_false() -> None:
    ac = source_bundle(SRC / "ac")
    capabilities = function_body(ac, "ac_capabilities_json")
    for capability in (
        "certificate_rotation",
        "ssid_create",
        "ssid_update",
        "ssid_delete",
        "password_rotation",
        "offline_queue",
    ):
        assert_boolean_false(capabilities, capability)
    for capability in ("radio_update", "transactional_apply", "automatic_rollback"):
        assert_boolean_dynamic(capabilities, capability)
    assert "ac_transport_reason()" in capabilities


def test_write_dispatch_is_gated_and_candidate_aware() -> None:
    ac = source_bundle(SRC / "ac")
    apd = source_bundle(SRC / "apd")
    for source, helper in (
        (ac, "ac_write_disabled_json"),
        (apd, "apd_write_disabled_json"),
    ):
        rejection = function_body(source, helper)
        for token in (
            '"capability_disabled"',
            '"persisted"',
            'json_object_new_boolean(0)',
            '"applied"',
        ):
            assert token in rejection, f"{helper} lacks fail-closed evidence: {token}"
        assert "sqlite3_exec" not in rejection and "sqlite3_step" not in rejection
        assert "system(" not in rejection and "popen(" not in rejection

    openwrt = read_required(SRC / "apd/apd_backend_openwrt.c")
    for symbol, operation in (
        ("apd_openwrt_validate", "apd_config_candidate_validate"),
        ("apd_openwrt_stage", "apd_config_stage"),
        ("apd_openwrt_apply", "apd_config_apply"),
        ("apd_openwrt_readback", "apd_config_readback"),
        ("apd_openwrt_rollback", "apd_config_rollback"),
    ):
        body = function_body(openwrt, symbol)
        assert operation in body, (
            f"candidate executor backend operation is not live: {symbol}"
        )


def test_local_ubus_has_bounded_management_and_public_readback() -> None:
    ac_ubus = read_required(SRC / "ac/ac_ubus.c")
    apd_ubus = read_required(SRC / "apd/apd_ubus.c")
    assert '"dreamingwrt.ac"' in ac_ubus
    assert '"dreamingwrt.apd"' in apd_ubus
    ac_methods = ubus_methods(ac_ubus)
    apd_methods = ubus_methods(apd_ubus)
    assert ac_methods == {
        "status", "capabilities", "aps_list", "pairing_token_create",
        "pairing_token_list", "pairing_token_status", "pairing_token_revoke",
        "radio_job_create", "radio_job_status", "radio_job_cancel",
        "radio_job_result", "radio_job_list", "radio_job_latest_results",
        "survey_history", "station_events", "wifi_transaction_validate",
        "wifi_transaction_apply", "wifi_transaction_status",
        # Read-only enumeration of APs seen on the wire but not yet adopted.
        "discovery_list",
        # Inventory-only write. Its policy accepts exactly ap_id, name and
        # model_override; ac_db_ap_update() UPDATEs only those two label columns
        # on ac_aps WHERE adoption_state='adopted', bumps no desired_revision,
        # and opens no session to the AP. So it cannot reach AP configuration
        # and does not widen the frozen transactional-apply surface. Renaming
        # an AP is deliberately available while apply stays closed.
        "ap_update",
        # Periodic survey scheduling. Bounded on purpose and justified before
        # being allowed through this gate:
        #   * survey_schedule_get is read-only.
        #   * survey_schedule_set writes one settings row (enabled +
        #     interval_seconds) and creates no job itself; the uloop tick does,
        #     through ac_db_radio_job_create() with the same eligibility checks
        #     the manual path enforces.
        #   * mode is fixed at 'survey' by a schema CHECK and the set policy
        #     accepts no mode field, so neighbour scans -- the only mode that
        #     leaves the working channel and interrupts clients -- cannot be
        #     scheduled. A survey job dwells on the in-use channel reading
        #     driver airtime counters.
        # So this reaches no AP configuration and does not widen the frozen
        # transactional-apply surface.
        "survey_schedule_get",
        "survey_schedule_set",
        # Read-only history query over ac_radio_tx_retry_bucket, the retry twin
        # of survey_history. It runs SELECTs against buckets the telemetry
        # ingest already wrote, takes no interface or command name, dispatches
        # nothing to the AP, and its policy accepts only ap_id, radio_id, the
        # time window, a fixed 300s resolution and paging. So it reaches no AP
        # configuration and does not widen the frozen transactional-apply
        # surface.
        "tx_retry_history",
    }, (
        "AC ubus must expose only health, managed-AP readback, administrator "
        "pairing-token methods, the bounded radio scan job control plane, "
        "the bounded survey/station-event history queries and the read-only "
        "W1 transaction validate, plus discovery enumeration and the "
        "inventory-only ap_update; "
        f"actual methods: {sorted(ac_methods)}"
    )
    validate_body = function_body(ac_ubus,
                                  "ac_handle_wifi_transaction_validate")
    for forbidden in ("sqlite3_exec", "INSERT", "UPDATE", "DELETE",
                      "system(", "popen("):
        assert forbidden not in validate_body, (
            f"W1 validate handler must stay read-only: {forbidden}"
        )
    aps_list = function_body(ac_ubus, "ac_handle_aps_list")
    assert "ac_db_aps_list_json(" in aps_list
    assert "blob_len(msg) != 0" in aps_list
    for forbidden in ("sqlite3_exec", "sqlite3_step", "system(", "popen(",
                      "pairing_token", "write_disabled"):
        assert forbidden not in aps_list, (
            f"managed-AP readback handler contains a write/secret/exec path: {forbidden}"
        )
    assert "pairing_token_redeem" not in ac_methods, (
        "node token redemption must not be exposed by the local management ubus"
    )
    assert apd_methods == {
        "status", "capabilities", "identity", "pairing_status",
        # Destructive but AP-local and consent-gated: apd_unpair_json() refuses
        # without {"confirm": true}, and it only clears this AP's own
        # certificate, enrollment, bootstrap and pairing state. It revokes an
        # adoption rather than configuring anything, and its REST path
        # /api/v1/apd/unpair is registered JMX_RISK_HIGH, so viewer and operator
        # roles cannot reach it.
        "unpair",
    }, (
        "APD ubus must expose only health, identity, non-secret pairing "
        "readback, and the consent-gated AP-local unpair; "
        f"actual methods: {sorted(apd_methods)}"
    )
    # ubus_methods() only sees the UBUS_METHOD macros, so a method declared with
    # a plain struct initializer (currently "snapshot") slips past the set
    # comparison above. Pin it explicitly rather than leaving the gate blind to
    # that declaration style.
    apd_ubus_source = read_required(SRC / "apd/apd_ubus.c")
    # Scope to the methods array: .name also labels blobmsg policy fields and
    # the ubus object names, which are not methods.
    methods_array = apd_ubus_source[
        apd_ubus_source.index("static const struct ubus_method apd_methods[]"):
    ]
    methods_array = methods_array[: methods_array.index("\n};")]
    struct_declared = set(re.findall(r'\.name\s*=\s*"([^"]+)"', methods_array))
    assert struct_declared <= {"snapshot"}, (
        "a new APD ubus method is declared with a struct initializer and would "
        f"bypass this gate: {sorted(struct_declared)}"
    )


def test_ac_health_is_independent_of_local_wifi_phy() -> None:
    ac = source_bundle(SRC / "ac")
    status = function_body(ac, "ac_status_json")
    for token in ('"controller"', '"local_wifi"', '"managed_aps"', '"no_phy_detected"'):
        assert token in status, f"AC status lacks no-PHY model evidence: {token}"
    for token in ("ac_db_managed_ap_counts", '"online_timeout_seconds"',
                  '"heartbeat_readback"'):
        assert token in status, f"AC status lacks authenticated heartbeat readback: {token}"
    ac_protocol = read_required(SRC / "ac/ac_protocol.c")
    apd_protocol = read_required(SRC / "apd/apd_protocol.c")
    assert '"heartbeat", ac_transport_listening()' in ac_protocol
    assert '"heartbeat", apd_transport_connected()' in apd_protocol
    assert re.search(r'"available"\s*,\s*json_object_new_boolean\(\s*1\s*\)', status), (
        "AC controller availability must remain true without a local PHY"
    )
    for forbidden in ("/sys/class/ieee80211", "phy0", "wifi_radios", "wifi_ssids"):
        assert forbidden not in ac, f"AC must not derive managed APs from local Wi-Fi state: {forbidden}"
    for mutation in ("INSERT INTO ac_aps", "UPDATE ac_aps", "DELETE FROM ac_aps"):
        assert mutation not in status, "health readback must not synthesize or mutate AP assets"


def test_apd_openwrt_backend_is_behind_the_single_vtable_boundary() -> None:
    internal = read_required(SRC / "apd/apd_internal.h")
    backend = read_required(SRC / "apd/apd_backend.c")
    openwrt = read_required(SRC / "apd/apd_backend_openwrt.c")
    protocol = read_required(SRC / "apd/apd_protocol.c")
    required_ops = ("probe", "snapshot", "validate", "stage", "apply", "readback", "rollback")
    vtable = re.search(r"struct apd_backend_ops\s*\{(.*?)\};", internal, re.DOTALL)
    assert vtable, "struct apd_backend_ops is missing"
    missing = [operation for operation in required_ops if f"(*{operation})" not in vtable.group(1)]
    assert not missing, f"APD backend vtable is missing operations: {missing}"
    assert "static const struct apd_backend_ops openwrt_backend" in openwrt
    assert "const struct apd_backend_ops *apd_backend_openwrt(void)" in openwrt
    dispatch = function_body(backend, "apd_backend")
    assert "return apd_backend_openwrt();" in dispatch
    for operation in required_ops:
        assert f".{operation} = apd_openwrt_{operation}" in openwrt
    for forbidden in ("uci ", "hostapd_cli", "iw ", "system(", "popen("):
        assert forbidden not in protocol, f"APD protocol bypasses its backend boundary: {forbidden}"


def test_no_shell_or_ssh_remote_control_exists() -> None:
    ac = source_bundle(SRC / "ac")
    apd = source_bundle(SRC / "apd")
    for forbidden in (
        "system(",
        "popen(",
        "/bin/sh",
        "/bin/ash",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        '"ssh"',
        '"scp"',
    ):
        assert forbidden not in ac + apd, f"AP control contains forbidden shell/SSH control: {forbidden}"
    for forbidden in ("execv(", "execve(", "execl(", "posix_spawn("):
        assert forbidden not in ac, f"AC must never execute node-management commands: {forbidden}"


def test_status_event_and_readback_outputs_cannot_serialize_secrets() -> None:
    public_sources = "\n".join(
        read_required(path)
        for path in (
            SRC / "ac/ac_protocol.c",
            SRC / "ac/ac_transport.c",
            SRC / "ac/ac_ubus.c",
            SRC / "apd/apd_protocol.c",
            SRC / "apd/apd_transport.c",
            SRC / "apd/apd_ubus.c",
            SRC / "apd/apd_backend.c",
            SRC / "apd/apd_backend_openwrt.c",
        )
    )
    forbidden_keys = (
        "password",
        "passphrase",
        "psk",
        "secret",
        "secret_value",
        "ciphertext",
        "private_key",
        "pairing_token",
    )
    leaked = [
        key for key in forbidden_keys
        if re.search(
            rf'json_object_object_add\s*\([^;]{{0,240}}"{key}"\s*,',
            public_sources,
            re.I | re.DOTALL,
        )
    ]
    assert not leaked, f"Phase 0 status/event/readback serializes secret fields: {leaked}"
    readback = function_body(
        read_required(SRC / "apd/apd_backend_openwrt.c"),
        "apd_openwrt_readback",
    )
    assert "apd_config_readback(" in readback, (
        "candidate readback must stay behind the executor contract"
    )


def test_phase1e_node_transport_is_authenticated_and_bounded() -> None:
    ac_internal = read_required(SRC / "ac/ac_internal.h")
    apd_internal = read_required(SRC / "apd/apd_internal.h")
    ac_transport = read_required(SRC / "ac/ac_transport.c")
    apd_transport = read_required(SRC / "apd/apd_transport.c")
    assert re.search(r"#define\s+AC_NODE_TRANSPORT_ENABLED\s+1\b", ac_internal), (
        "AC transport must be enabled after the authenticated Phase 1E gate"
    )
    assert re.search(r"#define\s+APD_NODE_TRANSPORT_ENABLED\s+1\b", apd_internal), (
        "APD transport must be enabled after the authenticated Phase 1E gate"
    )
    combined = ac_transport + apd_transport
    for required in (
        "TLS1_3_VERSION", "AP_CONTROL_ALPN", "ap_control_ssl_handshake",
        "ap_control_ssl_read_json", "ap_control_ssl_write_json",
    ):
        assert required in combined, f"authenticated transport missing: {required}"
    assert "SSL_VERIFY_PEER" in combined
    assert "AC_TRANSPORT_WORKERS_MAX" in ac_transport
    assert "AP_CONTROL_IO_TIMEOUT_MS" in combined


if __name__ == "__main__":
    test_all_phase0_write_capabilities_are_explicitly_false()
    test_write_dispatch_is_gated_and_candidate_aware()
    test_local_ubus_has_bounded_management_and_public_readback()
    test_ac_health_is_independent_of_local_wifi_phy()
    test_apd_openwrt_backend_is_behind_the_single_vtable_boundary()
    test_no_shell_or_ssh_remote_control_exists()
    test_status_event_and_readback_outputs_cannot_serialize_secrets()
    test_phase1e_node_transport_is_authenticated_and_bounded()
    print("ok: AP control Phase 0 capabilities, local IPC, backend boundary, and disabled transport")
