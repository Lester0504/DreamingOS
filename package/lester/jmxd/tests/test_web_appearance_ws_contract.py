#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
CORE_DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def test_core_emits_authoritative_appearance_event() -> None:
    assert 'jmx_events_emit("web.appearance", "updated", event_data)' in CORE_DB
    assert 'json_object_object_add(dw, "accent_color"' in CORE_DB
    assert 'json_object_object_add(dw, "material_glass"' in CORE_DB
    assert 'json_object_object_add(event_data, "wallpaper", event_wall)' in CORE_DB


def test_websocket_accepts_and_snapshots_appearance_topic() -> None:
    assert "int web_appearance;" in API
    assert 'else if (!strcmp(topic, "web.appearance"))' in API
    assert "topics->web_appearance = enabled" in API
    assert "out.web_appearance = topics->web_appearance" in API
    assert "webd_ws_snapshot_overlay_appearance(resp, topics)" in API
    assert 'json_object_object_add(data, "web.appearance", webd_public_appearance_data())' in API
    assert 'WEBD_WS_EMIT_TOPIC(topics && topics->web_appearance, "web.appearance")' in API
    assert "webd_public_appearance_data()" in API
    assert '"accent_color", "wallpaper_directory"' in API
    assert '"accent_color", json_object_new_string(accent_color)' in API


def test_events_are_semantically_deduplicated() -> None:
    assert "webd_ws_send_appearance_if_changed" in API
    assert 'webd_ws_send_topic_data(fd, kind, "web.appearance", data)' in API
    assert "last_appearance_hash" in API
    assert "webd_ws_appearance_row_hash" in API
    assert 'SELECT * FROM appearance_settings WHERE id=1' in API
    assert "fast.web_appearance = 0" in API
    assert "webd_ws_topics_need_core_snapshot" in API


if __name__ == "__main__":
    test_core_emits_authoritative_appearance_event()
    test_websocket_accepts_and_snapshots_appearance_topic()
    test_events_are_semantically_deduplicated()
    print("ok: web.appearance websocket subscription, snapshot, payload, and dedupe contract")
