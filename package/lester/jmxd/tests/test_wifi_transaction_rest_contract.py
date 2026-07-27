#!/usr/bin/env python3
"""Static REST contract for the W3 managed Wi-Fi transaction surface.

The endpoint exists but is fail-closed: it returns 409 capability_disabled
until an AP declares a config executor on a live session (W4,
user-authorized).  The orchestration DAO is exercised by
test_ac_wifi_transaction_runtime; this test pins the dormant REST shape."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
AC_DB = (ROOT / "src/ac/ac_db.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_transactions_post_is_capability_disabled() -> None:
    route = between(
        WEB,
        'else if (!strcmp(req.path, "/api/v1/wifi/transactions") &&',
        'else if (!strncmp(req.path, "/api/v1/wifi/transactions/",',
    )
    assert '!strcmp(req.method, "POST")' in route
    assert '!strcmp(req.method, "PUT")' in route
    assert "status = 409" in route
    assert '"capability_disabled"' in route
    assert '"transactional_apply"' in route
    assert 'json_object_new_boolean(0)' in route  # persisted/applied false


def test_transactions_get_is_capability_disabled() -> None:
    route = between(
        WEB,
        'else if (!strncmp(req.path, "/api/v1/wifi/transactions/",',
        'else if (!strcmp(req.path, "/api/v1/wifi/status")',
    )
    assert '!strcmp(req.method, "GET")' in route
    assert "status = 409" in route
    assert '"capability_disabled"' in route


def test_orchestration_dao_is_atomic_and_dormant() -> None:
    # The apply DAO exists, fans out inside one IMMEDIATE transaction, and
    # is never reachable from a ubus method (dispatch is internal until W4).
    assert "int ac_db_wifi_transaction_apply(" in AC_DB
    # Slice the definition, not the standalone-test forward declaration:
    # anchor on the comment that only precedes the real body.
    apply = between(AC_DB, "Fans one apply out to a",
                    "struct json_object *ac_db_wifi_transaction_status_json(\n"
                    "    const char *transaction_id)\n{")
    assert "BEGIN IMMEDIATE" in apply
    assert '"revision_conflict"' in apply
    assert "ac_transaction_targets" in apply
    assert "ac_config_jobs" in apply
    ubus = (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")
    assert "wifi_transaction_apply" not in ubus


def main() -> None:
    test_transactions_post_is_capability_disabled()
    test_transactions_get_is_capability_disabled()
    test_orchestration_dao_is_atomic_and_dormant()
    print("ok: W3 wifi transaction REST is fail-closed and dormant")


if __name__ == "__main__":
    main()
