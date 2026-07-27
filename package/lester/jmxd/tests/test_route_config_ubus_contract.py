from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_route_config_methods_are_exposed_on_dreamingwrt_object():
    source = (ROOT / "src" / "jmx_dreamingwrt_api.c").read_text()

    assert "dw_handle_route_config_get" in source
    assert "dw_handle_route_config_set" in source
    assert 'UBUS_METHOD("route_config_get", dw_handle_route_config_get' in source
    assert 'UBUS_METHOD("route_config_set", dw_handle_route_config_set' in source
    assert "jmx_api_route_config_get(NULL)" in source
    assert "jmx_api_route_config_set(in)" in source
