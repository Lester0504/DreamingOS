#!/usr/bin/env python3
"""Static REST contract for managed Wi-Fi transaction create/status."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
AC = (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")
PROTOCOL = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
AC_DB = (ROOT / "src/ac/ac_db.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_transactions_post_calls_ac_apply() -> None:
    route = between(
        WEB,
        'else if (!strcmp(req.path, "/api/v1/wifi/transactions") &&',
        'else if (!strncmp(req.path, "/api/v1/wifi/transactions/",',
    )
    assert '!strcmp(req.method, "POST")' in route
    assert '!strcmp(req.method, "PUT")' in route
    assert 'webd_wifi_transaction_create_params' in route
    assert '"wifi_transaction_apply"' in route
    assert 'webd_ac_http_status' in route
    assert '"wifi.transaction.apply"' in route
    assert '"capability_disabled"' not in route


def test_transactions_get_calls_ac_status() -> None:
    route = between(
        WEB,
        'else if (!strncmp(req.path, "/api/v1/wifi/transactions/",',
        'else if (!strcmp(req.path, "/api/v1/wifi/status")',
    )
    assert '!strcmp(req.method, "GET")' in route
    assert '"wifi_transaction_status"' in route
    assert '"transaction_id"' in route
    assert '"invalid_transaction_id"' in route
    assert '"capability_disabled"' not in route


def test_webd_derives_actor_and_serializes_targets() -> None:
    helper = between(
        WEB,
        'static struct json_object *webd_wifi_transaction_create_params(',
        '/*\n * Operator-supplied AP inventory label',
    )
    assert 'webd_wifi_transaction_actor_id' in helper
    assert 'json_object_new_string(actor_id)' in helper
    assert 'json_object_to_json_string_ext(targets,' in helper
    assert 'JSON_C_TO_STRING_PLAIN' in helper
    assert '"actor_id"' in helper
    assert 'webd_ac_radio_job_key_valid' in helper
    assert 'webd_wifi_transaction_digest_valid' in helper


def test_ac_methods_and_status_mapping_are_live() -> None:
    assert 'UBUS_METHOD("wifi_transaction_apply"' in AC
    assert 'UBUS_METHOD("wifi_transaction_status"' in AC
    assert '"capability_unavailable"' in PROTOCOL
    assert '"transaction_not_found"' in AC_DB
    assert '"database_error"' in AC_DB
    apply = between(
        PROTOCOL,
        'struct json_object *ac_wifi_transaction_apply_json(',
        'struct json_object *ac_wifi_transaction_status_json(',
    )
    assert 'state && json_object_is_type' in apply
    assert '"applied"' in apply


def main() -> None:
    test_transactions_post_calls_ac_apply()
    test_transactions_get_calls_ac_status()
    test_webd_derives_actor_and_serializes_targets()
    test_ac_methods_and_status_mapping_are_live()
    print("ok: managed Wi-Fi transaction REST calls AC journal and preserves gate errors")


if __name__ == "__main__":
    main()
