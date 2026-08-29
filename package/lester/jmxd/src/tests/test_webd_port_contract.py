#!/usr/bin/env python3
"""Keep the webd private-port migration aligned across supervisor and nginx."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "init" / "dreamingwrt_init.c"
WEB_LOCATIONS = ROOT.parents[1] / "dreamingwrt-web" / "files/etc/nginx/conf.d/dreamingwrt-webd.locations"
MDNS = ROOT.parents[1] / "jmxd" / "files/dreamingwrt-mdns-advert.sh"


def main() -> None:
    init = INIT.read_text(encoding="utf-8")
    locations = WEB_LOCATIONS.read_text(encoding="utf-8")
    mdns = MDNS.read_text(encoding="utf-8")

    component_start = init.index('{ .name = "dreamingwrt-webd"')
    component_end = init.index("\n    {", component_start + 1)
    component = init[component_start:component_end]
    assert '"WEBD_PORT=12518"' in component
    assert '"WEBD_BIND=127.0.0.1"' in component

    helper_start = init.index("static const char *component_env_value")
    argv_start = init.index("static int build_argv", helper_start)
    argv_end = init.index("\nstatic int start_component", argv_start)
    argv = init[argv_start:argv_end]
    assert 'component_env_value(c, "WEBD_PORT")' in argv
    assert 'component_env_value(c, "WEBD_BIND")' in argv
    assert 'port && port[0] ? port : "12517"' in argv
    assert 'bind && bind[0] ? bind : "0.0.0.0"' in argv

    assert "proxy_pass http://127.0.0.1:12518;" in locations
    assert "proxy_pass http://127.0.0.1:12517;" not in locations
    assert locations.count("\tinclude restrict_locally;") == 8
    assert "DEFAULT_PORT=12518" in mdns
    assert "DEFAULT_PORT=12517" not in mdns

    print("webd_port_contract: PASS")


if __name__ == "__main__":
    main()
