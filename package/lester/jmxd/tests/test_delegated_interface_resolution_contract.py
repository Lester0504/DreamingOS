#!/usr/bin/env python3
"""Delegated service creation must not fail on an empty interface.

The delegated interface is an optional free-text field in the UI, and the write
path used to reject an empty value with delegated_interface_not_found, which made
every default-shaped create fail. These assertions pin the resolver contract:
empty resolves to the preferred enabled WAN, a named line still has to exist and
be enabled, and each failure is attributable to a form field.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
SRC = ROOT / "src"
WRITE = (SRC / "authd/authd_write.c").read_text(encoding="utf-8")
DB = (SRC / "authd/authd_db.c").read_text(encoding="utf-8")
COMMON = (SRC / "authd/authd_common.c").read_text(encoding="utf-8")
HEADER = (SRC / "authd/authd_internal.h").read_text(encoding="utf-8")
WEBD = webd_dispatch_text()


def _upsert_body() -> str:
    start = WRITE.index("struct json_object *authd_delegated_upsert")
    return WRITE[start:WRITE.index("struct json_object *authd_delegated_delete", start)]


def _normalize_body() -> str:
    start = WRITE.index("static int authd_delegated_wan_normalize")
    return WRITE[start:WRITE.index("static int authd_delegated_account_exists", start)]


def test_empty_interface_resolves_instead_of_failing() -> None:
    body = _normalize_body()
    # An empty value must reach the default resolver, not the reject path.
    assert "authd_delegated_interface_default(out, out_len)" in body
    assert "if (!input || !input[0]) {" in body
    # The old unconditional rejection of empty input must be gone.
    assert "if (!input || !input[0] || !authd_text_ok(input, 128, 1))" not in body
    # A non-empty value is still matched against enabled WANs only.
    assert "SELECT id FROM wan WHERE enabled=1 AND (id=?1 OR ifname=?1 OR device=?1)" in body
    assert "authd_text_ok(input, 128, 1)" in body


def test_default_resolver_is_deterministic_and_reads_enabled_wans() -> None:
    start = DB.index("int authd_delegated_interface_default")
    body = DB[start:DB.index("static struct json_object *authd_notifications_data", start)]
    assert "FROM wan WHERE enabled=1" in body
    # Route preference order, so the fallback is predictable rather than arbitrary.
    assert "ORDER BY metric, priority, id LIMIT 1" in body
    assert "int authd_delegated_interface_default(char *out, size_t out_len);" in HEADER


def test_interface_options_are_enumerable_for_the_ui() -> None:
    start = DB.index("struct json_object *authd_delegated_interface_options")
    body = DB[start:DB.index("int authd_delegated_interface_default", start)]
    assert "FROM wan WHERE enabled=1" in body
    assert "ORDER BY metric, priority, id" in body
    for key in ("value", "label", "ifname", "device", "role"):
        assert f'json_object_object_add(item, "{key}"' in body
    # Exposed on both the paged read and the aggregate the page actually loads.
    assert DB.count('"interface_options",') >= 2
    assert 'json_object_object_add(delegated, "interface_options"' in DB
    assert '"delegated_interface_options", json_object_new_boolean(1)' in COMMON
    assert '"delegated_interface_optional", json_object_new_boolean(1)' in COMMON


def test_failures_name_the_offending_field() -> None:
    body = _upsert_body()
    assert "authd_field_error" in WRITE
    # A missing WAN and a mistyped WAN are different problems.
    assert '"delegated_interface_unavailable"' in body
    assert '"delegated_interface_not_found"' in body
    assert "authd_delegated_interface_options()" in body
    for field in ('"interface"', '"delegated_account"', '"password"'):
        assert field in body
    # The field/options hints have to survive into the response payload.
    helper = WRITE[WRITE.index("static struct json_object *authd_field_error"):
                   WRITE.index("static int authd_delegated_wan_normalize")]
    assert 'json_object_object_add(data, "field"' in helper
    assert 'json_object_object_add(data, "options", options)' in helper
    assert "json_object_put(options)" in helper


def test_resolved_interface_is_reported_back() -> None:
    body = _upsert_body()
    assert 'json_object_object_add(success_data, "interface"' in body
    assert 'json_object_object_add(success_data, "interface_defaulted"' in body


def test_no_enabled_wan_is_a_conflict_not_a_bad_request() -> None:
    marker = '!strcmp(code_s, "delegated_interface_unavailable")'
    assert marker in WEBD
    conflict_block = WEBD[WEBD.index('!strcmp(code_s, "authorization_not_pending")'):]
    conflict_block = conflict_block[:conflict_block.index("return 409;")]
    assert marker in conflict_block
