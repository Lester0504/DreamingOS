#!/usr/bin/env python3
"""Static REST and aggregation contracts for bounded Wi-Fi Survey history."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
AC_UBUS = (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_status_aggregation_uses_fixed_bounded_history_window() -> None:
    aggregate = between(
        WEB,
        "static struct json_object *webd_wifi_aggregate_response(int runtime_status)\n{",
        "static int webd_flowd_runtime_empty",
    )
    assert '"dreamingwrt.ac", "survey_history", survey_params, 1500' in aggregate
    assert "WEBD_WIFI_SURVEY_HISTORY_STATUS_WINDOW_S 43200" in WEB
    assert 'json_object_new_string("300")' in aggregate
    assert "WEBD_WIFI_SURVEY_HISTORY_DEFAULT_LIMIT" in aggregate
    assert "webd_wifi_merge_survey_history(data, survey_history)" in aggregate
    assert "if (data && runtime_status)" in aggregate
    assert "json_object_put(survey_history)" in aggregate
    assert "json_object_put(survey_params)" in aggregate


def test_rest_route_is_get_only_and_bridges_to_ac() -> None:
    wifi = between(WEB, "/* ── WiFi ── */",
                   "/* ── AC controller management plane ── */")
    route = between(
        wifi,
        'else if (!strcmp(req.path, "/api/v1/wifi/environment/survey-history")',
        'else if (!strcmp(req.path, "/api/v1/wifi/scan")',
    )
    assert '!strcmp(req.method, "GET")' in route
    assert "webd_wifi_survey_history_params(req.query" in route
    assert 'app_ubus_invoke_object_diag("dreamingwrt.ac",' in route
    assert '"survey_history", params' in route
    assert "webd_ac_http_status(resp, status)" in route
    assert "json_object_put(params)" in route
    # A reachable AC that rejects the arguments must surface as HTTP 400
    # with a diagnosable reason; only real transport failures stay 503.
    assert "diag.rc == UBUS_STATUS_INVALID_ARGUMENT" in route
    assert '"upstream_rejected_request"' in route
    assert "status = 400" in route
    assert "status = 503" in route
    assert 'stage=%s rc=%d' in route
    assert '"source_unavailable"' in route
    for forbidden in (
        "radio_job_create",
        "radio_job_latest_results",
        "neighbor",
        "survey_scan",
    ):
        assert forbidden not in route


def test_webd_invoke_diag_separates_transport_stages() -> None:
    helper = between(
        WEB,
        "struct app_ubus_call_diag {",
        "static struct json_object *app_ubus_invoke_object(",
    )
    assert 'diag->stage = "connect"' in helper
    assert 'diag->stage = "lookup"' in helper
    assert 'diag->stage = "invoke"' in helper
    assert "diag->rc = rc" in helper
    assert ("app_ubus_invoke_object_diag(object, method, params, "
            "timeout_ms, NULL)") in helper


def test_ac_accepts_int32_encoded_int64_contract_fields() -> None:
    # JSON bridges (webd REST and the ubus CLI) encode integers with the
    # smallest blobmsg width, so INT64 contract fields legally arrive as
    # INT32 whenever the value fits in 32 bits (current Unix timestamps
    # do).  The AC must accept that lossless widening or every
    # start/end-bounded Survey history request fails as
    # UBUS_STATUS_INVALID_ARGUMENT and webd reports a fake 503.
    assert "static int ac_policy_type_compatible(" in AC_UBUS
    assert ("policy_type == BLOBMSG_TYPE_INT64 &&\n"
            "           attr_type == BLOBMSG_TYPE_INT32") in AC_UBUS
    assert "static int64_t ac_attr_get_s64(" in AC_UBUS
    assert "(int64_t)(int32_t)blobmsg_get_u32(attr)" in AC_UBUS
    strict = between(AC_UBUS, "static int ac_message_is_strict(",
                     "static int ac_site_id_valid(")
    assert "ac_policy_type_compatible((int)policy[i].type," in strict
    # Registration policy keeps the authoritative INT64 introspection
    # types; only the parse-side policy relaxes the three 64-bit fields.
    registration = between(
        AC_UBUS,
        "static const struct blobmsg_policy ac_survey_history_policy[",
        "static const struct blobmsg_policy ac_survey_history_parse_policy[",
    )
    for field in ("start", "end", "after_id"):
        assert f'.name = "{field}", .type = BLOBMSG_TYPE_INT64' in registration
    parse_policy = between(
        AC_UBUS,
        "static const struct blobmsg_policy ac_survey_history_parse_policy[",
        "static const struct blobmsg_policy ac_create_policy[",
    )
    for field in ("start", "end", "after_id"):
        assert f'.name = "{field}", .type = BLOBMSG_TYPE_UNSPEC' in parse_policy
    handler = between(AC_UBUS, "static int ac_handle_survey_history(",
                      "static int ac_parse_token_id(")
    assert "ac_message_is_strict(msg, ac_survey_history_policy" in handler
    assert ("blobmsg_parse(ac_survey_history_parse_policy, __AC_SURVEY_MAX, tb,"
            in handler)
    assert "start = ac_attr_get_s64(tb[AC_SURVEY_START])" in handler
    assert "end = ac_attr_get_s64(tb[AC_SURVEY_END])" in handler
    assert "after_id = ac_attr_get_s64(tb[AC_SURVEY_AFTER_ID])" in handler


def test_query_parser_has_exact_allowlist_and_rejects_duplicates_unknowns() -> None:
    decoder = between(
        WEB,
        "static int webd_wifi_query_decode_strict(",
        "static int webd_wifi_parse_int64_strict",
    )
    parser = between(
        WEB,
        "static int webd_wifi_survey_history_parse_pair(",
        "static struct json_object *webd_ac_radio_job_create_params",
    )
    for name in (
        "ap_id",
        "radio_id",
        "start",
        "end",
        "resolution",
        "limit",
        "after_id",
    ):
        assert f'!strcmp(name, "{name}")' in parser
    assert "else\n        return 0;" in parser
    assert "if (parsed->present & bit)" in parser
    assert "if (*pair_end && !pair_end[1])" in parser
    assert "equals == cursor" in parser
    assert "equals + 1 == pair_end" in parser
    assert "webd_wifi_query_decode_strict" in parser
    assert "value == '\\0'" in decoder
    assert "i + 2 >= src_len" in decoder
    assert "j + 1 >= out_len" in decoder


def test_query_boundaries_fail_closed() -> None:
    parser = between(
        WEB,
        "static int webd_wifi_survey_history_parse_pair(",
        "static struct json_object *webd_ac_radio_job_create_params",
    )
    assert "webd_ac_token_id_valid(value)" in parser
    assert "webd_ac_radio_id_valid(value)" in parser
    assert "WEBD_WIFI_SURVEY_RADIO_ID" in parser
    assert "WEBD_WIFI_SURVEY_AP_ID" in parser
    assert "strcmp(value, \"auto\")" in parser
    assert "strcmp(value, \"300\")" in parser
    assert "strcmp(value, \"3600\")" in parser
    assert "webd_wifi_parse_int64_strict" in parser
    assert "errno == ERANGE" in WEB
    assert "number < 0" in parser
    assert "number < 1 || number > WEBD_WIFI_SURVEY_HISTORY_MAX_LIMIT" in parser
    assert "WEBD_WIFI_SURVEY_HISTORY_MAX_LIMIT 4096" in WEB
    assert "parsed.start > parsed.end" in parser


def test_defaults_and_forwarded_types_match_ac_contract() -> None:
    parser = between(
        WEB,
        "static struct json_object *webd_wifi_survey_history_params(",
        "static struct json_object *webd_ac_radio_job_create_params",
    )
    assert ".limit = WEBD_WIFI_SURVEY_HISTORY_DEFAULT_LIMIT" in parser
    assert "WEBD_WIFI_SURVEY_HISTORY_DEFAULT_LIMIT 2048" in WEB
    assert 'json_object_object_add(params, "limit", json_object_new_int(parsed.limit))' in parser
    for field in ("start", "end", "after_id"):
        assert f'json_object_object_add(params, "{field}",' in parser
        assert "json_object_new_int64" in parser
    assert 'json_object_new_string(parsed.resolution)' in parser
    assert 'json_object_new_string(parsed.ap_id)' in parser
    assert 'json_object_new_string(parsed.radio_id)' in parser


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Wi-Fi Survey history REST contracts")
