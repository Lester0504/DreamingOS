from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
HTTP = (ROOT / "src/webd/webd_http.c").read_text(encoding="utf-8")


def main() -> None:
    assert '#include "system_ttyd.h"' in API
    assert '#include "system_ttyd_proxy.h"' in API
    assert '"/api/v1/system/ttyd/validate"' in API
    assert "system_ttyd_get(&status)" in API
    assert "system_ttyd_validate(body_json, &status)" in API
    assert "system_ttyd_apply(body_json, &status)" in API
    assert '"system_ttyd_read"' in API
    assert '"system_ttyd_write"' in API
    assert '"system_ttyd_multi_instance"' in API
    assert '"system_ttyd_proxy"' in API
    assert '"/api/v1/system/ttyd",           "GET",      JMX_RISK_MEDIUM' in PERMS
    assert '"/api/v1/system/ttyd/validate",  "POST",     JMX_RISK_MEDIUM' in PERMS
    assert '"/api/v1/system/ttyd",           "PUT",      JMX_RISK_MEDIUM' in PERMS
    assert '"/terminal",                     "GET,HEAD,POST", JMX_RISK_MEDIUM' in PERMS
    assert 'case 428: return "Precondition Required";' in HTTP
    assert "system_ttyd_proxy_handle_authenticated" in API
    assert '"system.ttyd.proxy.open"' in API
    assert '"system.ttyd.proxy.close"' in API
    assert "app_api_terminal_route(path)" in API
    assert "else if (is_ws)" in API
    assert "app_api_send_busy(cfd, 1)" in API
    print("system ttyd webd REST/RBAC/capability integration: ok")


if __name__ == "__main__":
    main()
