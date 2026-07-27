#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/webd/system_ttyd_proxy.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/webd/system_ttyd_proxy.h").read_text(encoding="utf-8")
PARSER_TEST = (ROOT / "tests/system_ttyd_proxy_parse_test.c").read_text(encoding="utf-8")


def require(text: str, *needles: str) -> None:
    for needle in needles:
        assert needle in text, f"missing ttyd proxy contract marker: {needle}"


def test_public_api_requires_authenticated_parent_context() -> None:
    require(
        HEADER,
        "system_ttyd_proxy_handle_authenticated",
        "SYSTEM_TTYD_PROXY_ACCESS_ADMIN",
        "SYSTEM_TTYD_PROXY_ACCESS_OWNER",
        "parent_connection_permit",
        "external_host",
        "external_proto",
        "idle_timeout_ms",
    )
    require(
        SOURCE,
        '"ttyd_proxy_forbidden"',
        '"ttyd_proxy_connection_slot_required"',
    )
    assert "/api/v1/" not in SOURCE


def test_uci_first_enabled_instance_is_the_only_upstream_authority() -> None:
    require(
        SOURCE,
        '#define SYSTEM_TTYD_PROXY_CONFIG_PATH "/etc/config/ttyd"',
        "proxy_load_first_enabled",
        "uci_alloc_context",
        "uci_load",
        'strcmp(section->type, "ttyd")',
        'uci_lookup_option_string(ctx, section, "enable")',
        "break;",
    )
    assert "config.db" not in SOURCE
    assert "sqlite" not in SOURCE.lower()


def test_tcp_unix_and_local_only_resolution_are_supported() -> None:
    require(
        SOURCE,
        "AF_UNIX",
        "struct sockaddr_un",
        "AF_INET",
        "AF_INET6",
        "proxy_address_is_local",
        "proxy_address_from_interface",
        "proxy_network_endpoint",
        'interface[0] == \'@\'',
        '"127.0.0.1"',
        '"::1"',
        "proxy_unix_path_ok",
    )


def test_terminal_prefix_is_stripped_and_query_is_preserved() -> None:
    require(
        SOURCE,
        '#define TTYD_PROXY_PREFIX "/terminal"',
        "proxy_upstream_target",
        "path->ptr = target + prefix_len",
        "query->ptr = question",
        "proxy_dynamic_slice(out, query)",
        'path->ptr = "/"',
    )


def test_origin_host_and_forwarded_context_are_strict() -> None:
    require(
        SOURCE,
        "proxy_origin_same",
        "proxy_host_ok",
        '"ttyd_proxy_host_mismatch"',
        '"ttyd_proxy_forwarded_proto_mismatch"',
        '"ttyd_proxy_forwarded_host_mismatch"',
        '"ttyd_proxy_origin_forbidden"',
        '"ttyd_proxy_cross_site_forbidden"',
        'strcmp(request->external_proto, "http")',
        'strcmp(request->external_proto, "https")',
    )


def test_credentials_and_hop_by_hop_headers_are_not_forwarded() -> None:
    require(
        SOURCE,
        '"Authorization"',
        '"Cookie"',
        '"Proxy-Authorization"',
        '"Set-Cookie"',
        '"Forwarded"',
        "proxy_connection_named_header",
        "X-Forwarded-Prefix: /terminal",
    )
    assert "fprintf(" not in SOURCE
    assert "dprintf(" not in SOURCE
    assert "syslog(" not in SOURCE


def test_websocket_is_an_opaque_bidirectional_stream() -> None:
    require(
        SOURCE,
        'proxy_header_token(connection, "upgrade")',
        'proxy_slice_equal_ci(value, "websocket")',
        '"Connection: Upgrade\\r\\nUpgrade: websocket\\r\\n\\r\\n"',
        "proxy_tunnel",
        "poll(fds, 2, timeout)",
        "POLLIN",
        "POLLOUT",
        "SSL_pending",
        "proxy_response_connection_names",
        'TTYD_PROXY_WS_SUBPROTOCOL_HEADER "Sec-WebSocket-Protocol"',
        "Preserve the client's requested ttyd subprotocol byte-for-byte",
        "A 101 response must return ttyd's selected subprotocol unchanged",
        '"Sec-WebSocket-Extensions"',
    )
    forbidden_parsers = (
        "websocket_frame",
        "ws_frame",
        "opcode",
        "ping_frame",
        "pong_frame",
        "close_code",
        "terminal_input",
        "terminal_output",
    )
    for marker in forbidden_parsers:
        assert marker not in SOURCE.lower()
    request_builder = SOURCE[
        SOURCE.index("static int proxy_build_upstream_request") :
        SOURCE.index("static int proxy_uci_bool")
    ]
    response_builder = SOURCE[
        SOURCE.index("static int proxy_build_response_header") :
        SOURCE.index("static void proxy_buffer_compact")
    ]
    assert "proxy_append_header(out, header->name, header->value)" in request_builder
    assert "proxy_append_header(out, name, value)" in response_builder


def test_idle_timeout_and_stable_errors_are_explicit() -> None:
    require(
        SOURCE,
        "TTYD_PROXY_DEFAULT_IDLE_MS",
        "TTYD_PROXY_MIN_IDLE_MS",
        "TTYD_PROXY_MAX_IDLE_MS",
        "result->idle_timeout = 1",
        '"ttyd_proxy_upstream_connect_failed"',
        '"ttyd_proxy_upstream_response_read_failed"',
        '"ttyd_proxy_invalid_upstream_status"',
        '"ttyd_proxy_invalid_upstream_framing"',
        '"ttyd_proxy_upstream_length_required"',
        '"ttyd_proxy_response_body_failed"',
        '"ttyd_proxy_resource_unavailable"',
        '"HTTP/1.1 %d %s\\r\\n"',
        '"Content-Type: application/json\\r\\n"',
        '"Cache-Control: no-store\\r\\n"',
    )
    assert "PROXY_IO_WANT_READ = -2" in SOURCE
    assert "PROXY_IO_WANT_WRITE = -3" in SOURCE
    require(
        SOURCE,
        "proxy_response_parse_framing",
        "proxy_forward_fixed_body",
        'proxy_slice_equal_ci(name, "Transfer-Encoding")',
        "initial_length > content_length",
        "TTYD_PROXY_MAX_HTTP_BODY",
    )


def test_final_request_header_crlf_is_included_in_parser_boundary() -> None:
    require(
        SOURCE,
        "headers_end + 2 - p",
        "headers_end points at the CRLF terminating the final header",
    )
    require(
        PARSER_TEST,
        "proxy_parse_request",
        "GET /terminal/ HTTP/1.1\\r\\n",
        "Content-Length: 2\\r\\n\\r\\n{}",
        "Connection: keep-alive, Upgrade",
        "ttyd_proxy_incomplete_headers",
        "proxy_build_response_header",
        "content-length: 729693",
    )
    assert SOURCE.count("headers_end + 2 - p") == 4


def test_module_stays_independent_of_routing_and_control_plane() -> None:
    assert "jmx_app_api.c" not in SOURCE
    assert "jmx_app_perms" not in SOURCE
    assert "system_ttyd_get" not in SOURCE
    assert "system_ttyd_apply" not in SOURCE
    assert "system_ttyd_validate" not in SOURCE
    assert "fork(" not in SOURCE


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("system ttyd same-origin proxy contract: ok")
