#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_network.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    start = SOURCE.index(name)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(name)


def test_network_service_actions_use_shared_bounded_exec() -> None:
    helper = function("static int jmx_network_service_action")
    assert 'path = "/etc/init.d/network"' in helper
    assert 'path = "/etc/init.d/dnsmasq"' in helper
    assert 'strcmp(action, "reload")' in helper
    assert 'strcmp(action, "restart")' in helper
    assert "jmx_exec_wait(path, argv, JMX_SERVICE_ACTION_TIMEOUT_MS, &result)" in helper
    assert "result.timed_out" in helper
    assert "result.term_signal" in helper
    assert "result.exit_code == 0" in helper


def test_legacy_network_setters_fail_when_runtime_apply_fails() -> None:
    lan = function("struct json_object *jmx_api_set_lan_info")
    wan = function("struct json_object *jmx_api_set_wan_info")
    assert 'jmx_network_service_action("network", "restart")' in lan
    assert 'jmx_network_service_action("dnsmasq", "restart")' in lan
    assert 'jmx_network_service_action("network", "reload")' in wan
    for body in (lan, wan):
        assert "system(" not in body
        action = body.index("jmx_network_service_action(")
        error = body.index("API_CODE_ERROR", action)
        success = body.rindex("API_CODE_SUCCESS")
        assert action < error < success


def test_network_warning_cleanup_does_not_regress() -> None:
    assert "static int ensure_dhcp_lan_section(" not in SOURCE
    assert "size_t len;" in function("static int interface_name_matches")
    for name in (
        "jmx_api_get_lan_list",
        "jmx_api_get_wan_list",
        "jmx_api_get_lan_info",
        "jmx_api_get_wan_info",
        "jmx_api_get_work_mode",
    ):
        assert "(void)req_obj;" in function(name), name


if __name__ == "__main__":
    test_network_service_actions_use_shared_bounded_exec()
    test_legacy_network_setters_fail_when_runtime_apply_fails()
    test_network_warning_cleanup_does_not_regress()
    print("ok: U-15 legacy network service actions use bounded argv exec")
