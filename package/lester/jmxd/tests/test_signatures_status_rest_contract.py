#!/usr/bin/env python3
"""Static REST contract: the signature-count overview endpoint (iOS gap
#2) forwards the already-registered signature_db_status ubus method."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_status_route_forwards_ubus() -> None:
    route = between(
        WEB,
        'else if (!strcmp(req.path, "/api/v1/signatures/status")',
        'else if (!strcmp(req.path, "/api/v1/signatures/rules")',
    )
    assert '!strcmp(req.method, "GET")' in route
    assert 'app_ubus_invoke("signature_db_status"' in route


def test_ubus_method_exists() -> None:
    # The ubus method was already registered; this endpoint only exposes
    # it over HTTP.  Keep the two in lockstep.
    assert 'UBUS_METHOD("signature_db_status"' in CORE


def main() -> None:
    test_status_route_forwards_ubus()
    test_ubus_method_exists()
    print("ok: signatures/status REST forwards signature_db_status")


if __name__ == "__main__":
    main()
