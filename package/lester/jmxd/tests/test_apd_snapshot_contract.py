#!/usr/bin/env python3
"""Normalized read-only wireless snapshot contract for APD Phase 1."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
APD = ROOT / "src/apd"


def read(name: str) -> str:
    return (APD / name).read_text(encoding="utf-8")


def function_body(text: str, symbol: str) -> str:
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert match, f"missing production function: {symbol}"
    start = match.end()
    pos = start
    depth = 1
    quote = ""
    while pos < len(text) and depth:
        char = text[pos]
        if quote:
            if char == "\\":
                pos += 2
                continue
            if char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"could not delimit production function: {symbol}"
    return text[start : pos - 1]


def test_snapshot_is_a_real_vtable_capability_and_read_only_ubus_method() -> None:
    internal = read("apd_internal.h")
    backend = read("apd_backend_openwrt.c")
    protocol = read("apd_protocol.c")
    ubus = read("apd_ubus.c")

    assert '#define APD_SNAPSHOT_VERSION "wireless-snapshot.v1"' in internal
    assert "int snapshot_supported;" in internal
    assert ".snapshot_supported = 1" in backend
    assert ".snapshot = apd_openwrt_snapshot" in backend
    assert "backend->snapshot_supported &&" in protocol
    assert 'apd_capability(cap, reasons, "snapshot", snapshot_supported' in protocol
    assert 'apd_capability(cap, reasons, "local_station_telemetry", snapshot_supported' in protocol
    assert 'return apd_backend_disabled("snapshot"' in protocol
    assert 'struct json_object *response = apd_snapshot_json();' in ubus
    assert '.name = "snapshot"' in ubus
    assert ".handler = apd_handle_snapshot" in ubus


def test_all_sources_are_scoped_and_truthful() -> None:
    backend = read("apd_backend_openwrt.c")
    snapshot = function_body(backend, "apd_openwrt_snapshot")

    for source in (
        "sysfs_ieee80211",
        "uci_wireless",
        "ubus_network_wireless",
        "iw_dev",
        "hostapd_control",
    ):
        assert f'"{source}"' in backend, f"missing source: {source}"
    for field in ("source", "scope", "available", "complete", "stale", "reason", "observed_at"):
        assert f'"{field}"' in backend, f"source metadata is missing: {field}"
    assert 'json_object_new_boolean(0)' in function_body(backend, "apd_source_state")
    assert '"scope", json_object_new_string("desired")' in snapshot
    assert 'json_object_object_add(root, "desired", desired)' in snapshot
    assert 'json_object_object_add(root, "radios", radios)' in snapshot
    assert 'json_object_object_add(root, "ssids", ssids)' in snapshot
    assert 'reason = "partial_runtime_sources"' in snapshot
    assert 'reason = "no_phy_detected"' in snapshot
    assert '"STA-FIRST"' in backend and '"STA-NEXT %s"' in backend
    assert 'apd_hostapd_request(remote_path, "STATUS"' in backend
    assert '"control_sockets_unavailable"' in backend
    assert '"control_directory_unavailable"' in backend
    assert '"control_directory_untrusted"' in backend
    assert '"per_interface_control_unavailable"' in backend
    assert '"hostapd_status_timeout"' in backend
    assert '"hostapd_station_timeout"' in backend
    assert '"hostapd_station_query_unsupported"' in backend
    assert "stale=true" not in backend and "json_object_new_boolean(1)); /* stale" not in backend


def test_uci_is_desired_only_and_secret_fields_are_not_read_or_serialized() -> None:
    backend = read("apd_backend_openwrt.c")
    collect = function_body(backend, "apd_collect_uci")

    assert 'uci_load(ctx, "wireless", &package)' in collect
    assert '"wifi-device"' in collect and '"wifi-iface"' in collect
    assert '"scope", json_object_new_string("desired")' in backend
    assert re.search(r'"runtime"\s*,\s*apd_runtime_meta\(', backend)
    for forbidden in (
        '"key"',
        '"password"',
        '"passphrase"',
        '"psk"',
        '"secret"',
        '"private_key"',
    ):
        assert forbidden not in backend, f"snapshot reads or serializes a secret field: {forbidden}"
    assert "uci_set(" not in backend
    assert "uci_save(" not in backend
    assert "uci_commit(" not in backend


def test_external_probe_uses_fixed_argv_without_a_shell_or_request_input() -> None:
    backend = read("apd_backend_openwrt.c")
    command_source = read("apd_readonly_command.c")
    # The 2026-07-23 refactor moved execution into
    # apd_readonly_command_bounded(); apd_readonly_command() is now the
    # default-budget wrapper around it.
    command = function_body(command_source, "apd_readonly_command_bounded")
    wrapper = function_body(command_source, "apd_readonly_command")
    child_wait = function_body(command_source, "apd_child_wait")
    collect_iw = function_body(backend, "apd_collect_iw")
    main = read("apd_main.c")

    assert "execv(path, argv);" in command
    assert "apd_readonly_command_bounded(path, argv," in wrapper
    assert 'char *const argv[] = { (char *)path, "dev", NULL };' in collect_iw
    assert "APD_READONLY_COMMAND_TIMEOUT_MS" in wrapper
    assert "APD_UBUS_TIMEOUT_MS" in backend
    assert "APD_COMMAND_LIMIT" in wrapper
    assert "remaining <= 0" in command and "break;" in command
    assert "POLLERR | POLLNVAL" in command
    assert "status_valid" in command
    assert "errno == ECHILD" in child_wait
    assert "sigaction(SIGCHLD, &child_action, NULL)" in main
    assert "child_action.sa_handler = SIG_DFL" in main
    for forbidden in ("system(", "popen(", "/bin/sh", "/bin/ash", "execvp(", "execlp("):
        assert forbidden not in backend + command_source, (
            f"snapshot has a shell/string command path: {forbidden}"
        )
    assert "apd_readonly_command(path, argv" in collect_iw
    assert "candidate" not in collect_iw and "request" not in collect_iw


def test_hostapd_runtime_is_bounded_secret_safe_and_normalized() -> None:
    backend = read("apd_backend_openwrt.c")
    request = function_body(backend, "apd_hostapd_request")
    collect = function_body(backend, "apd_hostapd_collect_raw")
    collect_bss = function_body(backend, "apd_hostapd_collect_bss")
    status = function_body(backend, "apd_hostapd_parse_status")
    station = function_body(backend, "apd_hostapd_parse_station")
    snapshot = function_body(backend, "apd_openwrt_snapshot")

    assert "socket(AF_UNIX, SOCK_DGRAM" in request
    assert "connect(fd, (struct sockaddr *)&remote" in request
    assert "poll(&pfd" in request
    assert "APD_HOSTAPD_TIMEOUT_MS" in request
    assert "APD_HOSTAPD_COLLECTION_TIMEOUT_MS" in backend
    assert '"hostapd_collection_timeout"' in backend
    assert "APD_HOSTAPD_RESPONSE_LIMIT" in request
    assert "MSG_TRUNC" in request
    assert "FD_CLOEXEC" in request
    assert "local_st.st_ino" in request and "cleanup_st.st_ino" in request
    assert "S_IWGRP | S_IWOTH" in backend
    assert "st.st_uid != APD_HOSTAPD_EXPECTED_UID" in collect
    assert "name_len = strlen(entry->d_name)" in collect
    assert "name_len >= sizeof(names[0])" in collect
    assert "memcpy(names[name_count], entry->d_name, name_len + 1)" in collect
    assert "apd_hostapd_copy_text(bss->interface" in collect
    assert '"hostapd_interface_name_invalid"' in collect
    for limit in (
        "APD_HOSTAPD_BSS_LIMIT",
        "APD_HOSTAPD_STATION_LIMIT",
        "APD_HOSTAPD_STATIONS_PER_BSS_LIMIT",
        "APD_HOSTAPD_SOCKET_SCAN_LIMIT",
    ):
        assert limit in collect + collect_bss
    assert collect.index("if (phy_count == 0)") < collect.index("opendir(APD_HOSTAPD_RUN_DIR)")
    assert '"no_phy_detected"' in collect
    for safe_key in (
        '"state"',
        '"bssid"',
        '"ssid[0]"',
        '"freq"',
        '"channel"',
        '"num_sta"',
        '"num_sta[0]"',
        '"signal"',
        '"rx_bytes"',
        '"tx_bytes"',
        '"connected_time"',
        '"mld_addr"',
        '"link_id"',
    ):
        assert safe_key in status + station
    for secret in ('"psk"', '"password"', '"sae_password"', '"passphrase"'):
        assert secret not in status + station
    assert 'json_object_object_add(root, "station_count"' in snapshot
    assert 'json_object_object_add(root, "stations", stations)' in snapshot
    assert '"mlo_relation_complete"' in backend
    assert '"mlo_relation_state"' in backend
    assert '"partial"' in backend and '"unavailable"' in backend
    assert '"hostapd_mlo_relation_partial"' in backend
    assert '"not_reported_by_hostapd"' in backend
    assert "static struct apd_hostapd_observation" not in backend


def test_no_phy_is_an_honest_empty_runtime_snapshot() -> None:
    backend = read("apd_backend_openwrt.c")
    snapshot = function_body(backend, "apd_openwrt_snapshot")
    collect_iw = function_body(backend, "apd_collect_iw")

    assert "phy_count == 0" in snapshot
    assert 'json_object_new_boolean(inventory_available && phy_count > 0)' in snapshot
    assert 'json_object_new_int((int)json_object_array_length(radios))' in snapshot
    assert 'json_object_new_int((int)json_object_array_length(ssids))' in snapshot
    assert "desired_radios" in snapshot and "desired_ssids" in snapshot
    assert "apd_collect_uci(&desired_radios, &desired_ssids" in snapshot
    assert "apd_collect_iw(phy_count, &radios, &ssids" in snapshot
    no_phy = collect_iw.index("if (phy_count == 0)")
    invoke = collect_iw.index("apd_readonly_command(path, argv")
    assert no_phy < invoke, "no-PHY must return before executing or parsing iw"


def test_all_write_operations_remain_fail_closed() -> None:
    backend = read("apd_backend_openwrt.c")
    for symbol in (
        "apd_openwrt_validate",
        "apd_openwrt_stage",
        "apd_openwrt_apply",
        "apd_openwrt_readback",
        "apd_openwrt_rollback",
    ):
        assert "apd_openwrt_disabled(" in function_body(backend, symbol)


if __name__ == "__main__":
    test_snapshot_is_a_real_vtable_capability_and_read_only_ubus_method()
    test_all_sources_are_scoped_and_truthful()
    test_uci_is_desired_only_and_secret_fields_are_not_read_or_serialized()
    test_external_probe_uses_fixed_argv_without_a_shell_or_request_input()
    test_hostapd_runtime_is_bounded_secret_safe_and_normalized()
    test_no_phy_is_an_honest_empty_runtime_snapshot()
    test_all_write_operations_remain_fail_closed()
    print("ok: APD Phase 1 normalized read-only wireless snapshot contract")
