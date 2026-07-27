#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


assert "int route_status;" in API
assert 'else if (!strcmp(topic, "route.status"))' in API
assert "topics->route_status = enabled" in API
assert "out.route_status = topics->route_status" in API
assert "webd_ws_snapshot_overlay_route_status(resp, topics)" in API
assert "webd_route_status_response(NULL, &status)" in API
assert 'json_object_object_add(data, "route.status", webd_ws_route_status_data())' in API
assert 'WEBD_WS_EMIT_TOPIC(topics && topics->route_status, "route.status")' in API
assert 'wan.metrics,route.status,clients.metrics' in API
assert '"active_flows_source", "line_load_per_wan_conntrack_sum"' in API
assert 'json_object_object_add(root, "seq"' in API
assert "__sync_add_and_fetch(&sequence, 1)" in API
assert 'webd_ws_send_snapshot_topics(fd, push_now ? "snapshot" : "event"' in API
assert "webd_ws_semantic_hash" in API
assert "webd_ws_send_route_status_if_changed" in API
assert "fast.route_status = 0" in API
assert '!strcmp(key, "sample_age_ms")' in API

print("ok: route.status websocket topic reuses the REST route-status enrichment contract")
