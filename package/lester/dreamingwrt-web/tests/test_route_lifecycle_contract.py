#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHELL = (ROOT / "files/www/dreamingwrt/static/js/menu-shell.js").read_text(encoding="utf-8")
APP = (ROOT / "files/www/dreamingwrt/app/index.html").read_text(encoding="utf-8")

assert '/static/js/dwrt-data-registry.js?v=20260721-02' in APP
assert "routeAbortController: null" in SHELL
assert "state.routeAbortController?.abort('route-unmount')" in SHELL
assert "const routeController = new AbortController()" in SHELL
assert "signal: routeController.signal" in SHELL
assert "registry: window.DWRT_DATA_REGISTRY" in SHELL
assert "capabilities: Object.freeze({ ...state.capabilities })" in SHELL
assert "fetch: (name, url, retry = true) => fetchApiResource(name, url, retry, routeController.signal)" in SHELL
assert "configureDataRegistry();" in SHELL
for key in (
    "system.runtime",
    "system.health",
    "network.lans",
    "network.wans",
    "network.physicalPorts",
    "clients.inventory",
    "policy.runtime",
    "dashboard.aggregate",
    "services.dns",
    "policy.objects",
    "policy.regions",
    "policy.zoneMatrix",
    "policy.table",
):
    assert f"'{key}'" in SHELL

print("ok: route modules receive Registry/capabilities/Abort context and abort before unmount")
