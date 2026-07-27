#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


assert '"/api/v1/route_status"' in API
assert 'webd_route_status_response(body_json, &status)' in API
assert 'app_ubus_or_error("route_status", params)' in API
assert 'webd_merge_wans_from_runtime(wans, line_load_wans, 0)' in API
assert '"wan_id"' in API
assert '"kernel_wan_id"' in API
assert 'app_nc_json_int(runtime, "connections", -1)' in API
assert '"active_flows_source", "line_load_per_wan_conntrack_sum"' in API
assert '"/api/v1/route_status",                       "GET", JMX_RISK_LOW' in PERMS

print("ok: route_status REST endpoint delegates to core and merges cached per-WAN runtime")
