#!/usr/bin/env python3
"""Static production contracts for Honeypot + Aegis Phase 0/1.

These tests deliberately inspect production sources.  They do not provide a
fake daemon, fake capability response, or an in-memory replacement for either
config.db or aegis_events.  Until the production implementation is present,
the suite is expected to fail with the missing contract as its assertion.
"""

from pathlib import Path
import json
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def read_required(path: Path) -> str:
    assert path.is_file(), f"required production file is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def source_bundle(directory: Path) -> str:
    paths = sorted(
        path for path in directory.glob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    )
    assert paths, f"required production source directory is missing or empty: {directory.relative_to(ROOT)}"
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def aegis_sources() -> str:
    return source_bundle(SRC / "aegisxd")


def aegis_honeypot_sources() -> str:
    # Do not require a particular file split.  The production symbols and SQL
    # below identify the control plane without constraining its layout.
    return aegis_sources()


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} is missing contract evidence: {missing}"


def require_one(text: str, needles: tuple[str, ...], scope: str) -> None:
    assert any(needle in text for needle in needles), (
        f"{scope} needs one of these production evidences: {needles}"
    )


def macro_int_any(text: str, names: tuple[str, ...], scope: str) -> int:
    for name in names:
        match = re.search(rf"^\s*#\s*define\s+{re.escape(name)}\s+(\d+)\b", text, re.MULTILINE)
        if match:
            return int(match.group(1))
    raise AssertionError(f"{scope} needs a reviewable hard-limit macro: {names}")


def c_string_literals(text: str) -> str:
    """Join C string literals so split SQLite schema statements are testable."""
    return "".join(
        match.group(1).replace(r'\"', '"')
        for match in re.finditer(r'"((?:\\.|[^"\\])*)"', text)
    )


def route_window(text: str, path: str, radius: int = 2600) -> str:
    pos = text.find(f'"{path}"')
    assert pos >= 0, f"REST route is missing: {path}"
    return text[max(0, pos - radius):min(len(text), pos + radius)]


def ubus_handler(ubus: str, method: str) -> str:
    match = re.search(
        rf'UBUS_METHOD(?:_NOARG)?\(\s*"{re.escape(method)}"\s*,\s*([A-Za-z0-9_]+)',
        ubus,
    )
    assert match, f"dreamingwrt.aegis ubus method is missing: {method}"
    return match.group(1)


def function_body(text: str, symbol: str) -> str:
    start_match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert start_match, f"production function body is missing: {symbol}"
    start = start_match.end()
    depth = 1
    pos = start
    quote = ""
    line_comment = False
    block_comment = False
    while pos < len(text) and depth:
        char = text[pos]
        next_char = text[pos + 1] if pos + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
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


def function_body_any(text: str, symbols: tuple[str, ...], scope: str) -> str:
    for symbol in symbols:
        if re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL):
            return function_body(text, symbol)
    raise AssertionError(f"{scope} needs one of these production functions: {symbols}")


def test_real_honeypotd_package_supervisor_and_component() -> None:
    honeypotd = source_bundle(SRC / "honeypotd")
    src_make = read_required(SRC / "Makefile")
    package_make = read_required(ROOT / "Makefile")
    acl_path = ROOT / "files/acl.d/dreamingwrt-honeypotd.json"
    acl = json.loads(read_required(acl_path))
    supervisor = read_required(SRC / "init/dreamingwrt_init.c")
    component_status = read_required(SRC / "jmx_dreamingwrt_api.c")

    assert "int main(" in honeypotd, "dreamingwrt-honeypotd production main() is missing"
    require_all(
        src_make,
        (
            "HONEYPOTD_EXEC := dreamingwrt-honeypotd",
            "$(HONEYPOTD_EXEC): $(HONEYPOTD_OBJS)",
        ),
        "src/Makefile Honeypot target",
    )
    require_all(
        package_make,
        (
            "define Package/dreamingwrt-honeypotd",
            "define Package/dreamingwrt-honeypotd/install",
            "$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-honeypotd",
            "./files/acl.d/dreamingwrt-honeypotd.json",
            "$(eval $(call BuildPackage,dreamingwrt-honeypotd))",
            "+dreamingwrt-honeypotd",
        ),
        "OpenWrt Honeypot package",
    )
    require_all(
        supervisor,
        (
            '.name = "dreamingwrt-honeypotd"',
            '.path = "/usr/bin/dreamingwrt-honeypotd"',
        ),
        "dreamingwrt-init component registry",
    )
    assert "dreamingwrt-honeypotd" in component_status, (
        "system component status must expose the real dreamingwrt-honeypotd process"
    )
    assert acl.get("user") == "nobody"
    access = acl.get("access", {})
    assert access == {
        "dreamingwrt.aegis": {"methods": ["honeypot_event_ingest"]}
    }, "honeypotd ACL must grant only the internal event-ingest method"


def test_capabilities_and_runtime_are_real_readbacks() -> None:
    aegis = aegis_sources()

    for capability in (
        "honeypot_supported",
        "honeypot_config_supported",
        "honeypot_events_supported",
        "honeypot_event_ingest_supported",
    ):
        assert f'"{capability}"' in aegis, f"Aegis capability is missing: {capability}"

    for capability in (
        "honeypot_supported",
        "honeypot_config_supported",
        "honeypot_events_supported",
        "honeypot_event_ingest_supported",
    ):
        serialized = re.search(
            rf'"{capability}"\s*,\s*json_object_new_boolean\(\s*([^\)]+)\)',
            aegis,
        )
        assert serialized, f"Aegis capability must be serialized: {capability}"
        assert serialized.group(1).strip() not in {"0", "false"}, (
            f"completed Phase 0/1 must not advertise {capability}=false"
        )
    require_all(
        aegis,
        (
            "/usr/bin/dreamingwrt-honeypotd",
            "X_OK",
            "honeypot_binary_available",
            "honeypot_runtime_active",
            "honeypot_runtime_state",
        ),
        "Aegis Honeypot capability/runtime readback",
    )
    runtime = function_body_any(
        aegis,
        ("aegisxd_honeypot_runtime_active", "aegisxd_honeypot_active"),
        "Honeypot runtime active readback",
    )
    assert "honeypot_binary_available" in runtime
    require_one(
        runtime,
        ("honeypot_config_active", "honeypot_enabled_count", "honeypot_config_enabled"),
        "active Honeypot configuration readback",
    )
    require_one(
        runtime,
        ("honeypot_process_running", "honeypot_pid_running", "kill(pid, 0)"),
        "Honeypot runtime process readback",
    )
    assert "&&" in runtime, "runtime active must require every production prerequisite"
    assert not re.search(
        r'"honeypot_runtime_active"\s*,\s*json_object_new_boolean\(\s*[01]\s*\)',
        aegis,
    )
    assert not re.search(
        r'"honeypot(?:_supported)?"\s*,\s*json_object_new_boolean\(\s*0\s*\)',
        aegis,
    ), "completed Phase 0/1 must remove the old hard-coded Honeypot false capability"
    require_all(
        aegis,
        (
            '"honeypot_hits"',
            "aegis_events",
            "honeypot_hit",
        ),
        "Honeypot hit statistics",
    )


def test_aegis_ubus_methods_are_production_handlers() -> None:
    ubus = read_required(SRC / "aegisxd/aegisxd_ubus.c")
    aegis = aegis_sources()

    for method in (
        "honeypot_get",
        "honeypot_validate",
        "honeypot_set",
        "honeypot_delete",
        "honeypot_event_ingest",
    ):
        handler = ubus_handler(ubus, method)
        body = function_body(ubus, handler)
        assert "safe_not_implemented" not in body
        assert "not_implemented" not in body
        require_one(
            body,
            (f"aegisxd_{method}(", f"aegisxd_{method}_json("),
            f"ubus handler for {method}",
        )
        assert f"aegisxd_{method}" in aegis


def test_authenticated_rest_routes_map_to_exact_ubus_contract() -> None:
    webd = read_required(SRC / "webd/jmx_app_api.c")
    perms = read_required(SRC / "webd/jmx_app_perms.c")

    require_all(
        webd,
        (
            '"/api/v1/aegis/honeypot"',
            '"/api/v1/aegis/honeypot/validate"',
            '"/api/v1/aegis/honeypot/config"',
            '"/api/v1/aegis/honeypot/events"',
            '"honeypot_get"',
            '"honeypot_validate"',
            '"honeypot_set"',
            '"honeypot_delete"',
        ),
        "Honeypot REST routing",
    )
    base = route_window(webd, "/api/v1/aegis/honeypot")
    validate = route_window(webd, "/api/v1/aegis/honeypot/validate")
    config = route_window(webd, "/api/v1/aegis/honeypot/config")
    events = route_window(webd, "/api/v1/aegis/honeypot/events")
    require_all(base, ('"GET"', '"honeypot_get"'), "Honeypot GET route")
    require_all(validate, ('"POST"', '"honeypot_validate"'), "Honeypot validation route")
    require_all(config, ('"PUT"', '"DELETE"', '"honeypot_set"', '"honeypot_delete"'),
                "Honeypot config write routes")
    require_all(events, ('"GET"', "honeypot"), "Honeypot event query route")
    assert '"/api/v1/aegis/honeypot/config/"' in webd, (
        "DELETE /api/v1/aegis/honeypot/config/:id must parse a non-empty config id"
    )
    require_all(
        webd,
        (
            'webd_query_get(req.query, "limit"',
            'webd_query_get(req.query, "offset"',
        ),
        "Honeypot events pagination",
    )
    for path in (
        "/api/v1/aegis/honeypot",
        "/api/v1/aegis/honeypot/validate",
        "/api/v1/aegis/honeypot/config",
        "/api/v1/aegis/honeypot/events",
    ):
        assert path in perms, f"authenticated permission entry is missing: {path}"
    require_all(perms, ("POST", "PUT", "DELETE"), "Honeypot write permissions")


def test_config_db_is_authoritative_and_events_are_persisted() -> None:
    db = read_required(SRC / "aegisxd/aegisxd_db.c")
    honeypot = aegis_honeypot_sources()
    internal = read_required(SRC / "aegisxd/aegisxd_internal.h")

    assert '#define AEGISXD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"' in internal
    schema = c_string_literals(db)
    table = re.search(
        r"CREATE TABLE IF NOT EXISTS\s+(?:aegis_)?honeypot(?:_configs?|s)\s*\((.*?)\)",
        schema,
        re.DOTALL,
    )
    assert table, "config.db schema must own a Honeypot configuration table"
    columns = table.group(1)
    require_all(columns, ("id", "network", "created_at", "updated_at"),
                "Honeypot config.db schema")
    require_one(columns, ("active", "enabled"), "Honeypot active-state column")
    require_one(columns, ("ipv4", "address"), "Honeypot dark-address column")
    require_one(columns, ("service", "services_json"), "Honeypot service column")

    get_body = function_body_any(
        honeypot,
        ("aegisxd_honeypot_get_json", "aegisxd_honeypot_get"),
        "Honeypot config read",
    )
    set_body = function_body_any(
        honeypot,
        ("aegisxd_honeypot_set_json", "aegisxd_honeypot_set"),
        "Honeypot config write",
    )
    delete_body = function_body_any(
        honeypot,
        ("aegisxd_honeypot_delete_json", "aegisxd_honeypot_delete"),
        "Honeypot config delete",
    )
    config_paths = get_body + set_body + delete_body
    require_one(config_paths, ("aegisxd_honeypot", "honeypot_config"),
                "Honeypot config handlers")
    require_all(
        honeypot,
        (
            "aegisxd_config_prepare(",
            "INSERT INTO",
            "DELETE FROM",
            "BEGIN IMMEDIATE",
            "COMMIT",
            "ROLLBACK",
        ),
        "transactional Honeypot config persistence",
    )
    for operation in ("get", "set", "delete"):
        assert f"aegisxd_honeypot_{operation}" in honeypot
    ingest_body = function_body_any(
        honeypot,
        ("aegisxd_honeypot_event_ingest", "aegisxd_honeypot_event_ingest_json"),
        "Honeypot event ingest",
    )
    require_all(
        honeypot,
        (
            "INSERT INTO aegis_events",
            "honeypot_hit",
            "Internal Honeypot",
            "lateral_movement",
            "dark_address_service_access",
            "aegisxd.honeypot",
            "sqlite3_bind_",
        ),
        "Honeypot event normalization and persistence",
    )
    for field in (
        "schema_version",
        "event_type",
        "timestamp_ms",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "transport",
        "service",
        "stage",
    ):
        assert f'"{field}"' in honeypot, f"event ingest validation is missing: {field}"
    require_one(
        honeypot,
        ("HONEYPOT_MAX_EVENT_BYTES", "AEGISXD_HONEYPOT_MAX_EVENT_BYTES"),
        "bounded event ingest",
    )
    events_body = function_body_any(
        honeypot,
        ("aegisxd_honeypot_events_json", "aegisxd_honeypot_events"),
        "persisted Honeypot event query",
    )
    require_all(
        events_body,
        ("SELECT", "FROM aegis_events", "event_type", "honeypot_hit"),
        "persisted Honeypot event query",
    )


def test_validation_and_network_apply_have_atomic_rollback_evidence() -> None:
    honeypot = aegis_honeypot_sources()

    for service in ("ssh", "telnet", "http", "ftp", "dns"):
        assert f'"{service}"' in honeypot, f"configuration service allow-list is missing: {service}"
    require_all(
        honeypot,
        (
            "inet_pton",
            "network_id",
            "address_conflict",
            "gateway",
            "dhcp",
            "static",
            "client",
            "dry_run",
        ),
        "Honeypot address/service validation",
    )
    require_one(
        honeypot,
        ("management_port_conflict", "reserved_port_conflict", "gateway_service_conflict"),
        "gateway management-service port conflict validation",
    )
    require_one(
        honeypot,
        ("max_addresses", "HONEYPOT_MAX_ADDRESSES_PER_NETWORK", "address_count > 4"),
        "one-to-four dark addresses per network",
    )
    require_all(
        honeypot,
        (
            "nft",
            "dummy",
            "/32",
            "rollback",
            "readback",
            "iifname",
            "ip daddr",
            "wan",
        ),
        "nftables/dummy guarded apply",
    )
    require_one(honeypot, ("-c", "--check"), "nftables preflight validation")
    require_one(honeypot, ("-f", "nft_run_file"), "nftables transaction file apply")
    require_one(
        honeypot,
        ("ip link add", "IP_CMD_LINK_ADD", "honeypot_dummy_create"),
        "dummy interface creation",
    )
    require_one(
        honeypot,
        ("ip link delete", "IP_CMD_LINK_DELETE", "honeypot_dummy_delete"),
        "dummy interface rollback",
    )
    require_one(
        honeypot,
        ("nft list table", "nft_snapshot", "nft_backup", "before_config", "previous_config"),
        "nftables rollback source",
    )
    require_one(
        honeypot,
        ("apply_failed_rollback_failed", "rollback_failed"),
        "observable partial rollback failure",
    )
    require_one(
        honeypot,
        ("aegisxd_honeypot_apply_atomic", "aegisxd_honeypot_network_apply_atomic"),
        "explicit atomic network apply boundary",
    )


def test_honeypotd_protocols_event_boundary_and_resource_limits() -> None:
    daemon = source_bundle(SRC / "honeypotd")

    for protocol in ("ssh", "telnet", "http", "ftp", "dns"):
        assert f'"{protocol}"' in daemon, f"honeypotd service is missing: {protocol}"
    require_all(
        daemon,
        (
            "SSH-2.0-OpenSSH",
            "USER",
            "PASS",
            "220",
            "530",
            "Host",
            "User-Agent",
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "honeypot_hit",
            "schema_version",
            "source_ip",
            "destination_ip",
            "service",
            "stage",
        ),
        "Phase 1 protocol and event wire contract",
    )
    require_one(daemon, ("NXDOMAIN", "REFUSED", '"nxdomain"', '"refused"',
                         "DNS_RCODE_REFUSED", "DNS_RCODE_NXDOMAIN"),
                "valid bounded DNS response")
    require_one(daemon, ("uloop", "epoll", "poll("), "single event loop")
    assert "pthread_create(" not in daemon, "honeypotd must not create one thread per connection"
    assert "sqlite3_open" not in daemon and "aegis_events" not in daemon, (
        "honeypotd must emit events to aegisxd and must not own SQLite"
    )
    require_one(daemon, ("AF_UNIX", "ubus_invoke", "ubus_invoke_async"),
                "honeypotd-to-aegisxd structured event transport")

    max_connections = macro_int_any(
        daemon,
        ("HONEYPOT_DEFAULT_MAX_CONNECTIONS", "HP_MAX_SESSIONS"),
        "maximum concurrent connections",
    )
    per_source = macro_int_any(
        daemon,
        ("HONEYPOT_DEFAULT_MAX_CONNECTIONS_PER_SOURCE", "HP_MAX_PER_SOURCE_HARD"),
        "per-source concurrent connections",
    )
    capture_bytes = macro_int_any(
        daemon,
        ("HONEYPOT_MAX_SESSION_CAPTURE_BYTES", "HP_CAPTURE_HARD_LIMIT"),
        "per-session capture bytes",
    )
    queue_capacity = macro_int_any(
        daemon,
        ("HONEYPOT_EVENT_QUEUE_CAPACITY", "HP_MAX_EVENTS"),
        "bounded event queue",
    )

    assert 1 <= max_connections <= 128
    assert 1 <= per_source <= 8
    assert 1 <= capture_bytes <= 4096
    assert 1 <= queue_capacity <= 1024
    require_all(
        daemon,
        (
            "source_rate_per_minute = 20",
            "idle_timeout_seconds = 20",
            "session_timeout_seconds = 60",
        ),
        "default connection-rate and timeout limits",
    )
    assert re.search(r'"source_rate_per_minute"[^;]{0,220}\b20\b[^;]{0,220}\b(?:20|[2-9]\d|1[01]\d|120)\b', daemon)
    assert re.search(r'"idle_timeout_seconds"[^;]{0,220}\b20\b[^;]{0,220}\b30\b', daemon)
    assert re.search(r'"session_timeout_seconds"[^;]{0,220}\b60\b[^;]{0,220}\b60\b', daemon)
    require_all(
        daemon,
        (
            "setrlimit",
            "RLIMIT_NOFILE",
            "RLIMIT_CORE",
            "setgid",
            "setuid",
            "dropped",
        ),
        "honeypotd process and queue limits",
    )
    require_one(daemon, ("RLIMIT_AS", "RLIMIT_DATA", "mallopt"), "honeypotd memory limit")
    for forbidden in ("system(", "popen(", "execl(", "execv("):
        assert forbidden not in daemon, f"honeypotd must not invoke a shell or child command: {forbidden}"
    assert 'json_object_object_add(envelope, "payload"' in daemon, (
        "honeypotd events must use the standard ubus payload envelope"
    )
    assert not re.search(r'json_object_object_add\(\s*payload\s*,\s*"password"', daemon), (
        "honeypotd must never put plaintext passwords in an event payload"
    )
    assert "hp_payload_add_password_digest" in daemon
    daemon_main = read_required(SRC / "honeypotd/main.c")
    main_body = function_body(daemon_main, "main")
    assert main_body.index("hp_drop_privileges()") < main_body.index("hp_events_init("), (
        "the ubus connection must be opened after privilege drop"
    )
    require_all(
        daemon,
        ("SO_ORIGINAL_DST", "hp_runtime_mapping_for_original"),
        "shared TCP listener original-destination mapping",
    )
    require_all(
        daemon,
        ("listener->transport == HP_TRANSPORT_UDP", "listener->address", "recvfrom("),
        "per-honeypot DNS listener mapping",
    )


if __name__ == "__main__":
    test_real_honeypotd_package_supervisor_and_component()
    test_capabilities_and_runtime_are_real_readbacks()
    test_aegis_ubus_methods_are_production_handlers()
    test_authenticated_rest_routes_map_to_exact_ubus_contract()
    test_config_db_is_authoritative_and_events_are_persisted()
    test_validation_and_network_apply_have_atomic_rollback_evidence()
    test_honeypotd_protocols_event_boundary_and_resource_limits()
    print("ok: Honeypot + Aegis Phase 0/1 production contracts")
