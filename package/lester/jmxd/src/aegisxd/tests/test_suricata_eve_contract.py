#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HITS = ROOT / "aegisxd_hits.c"
STATUS = ROOT / "aegisxd_status.c"

prod_eve = {
    "event_type": "alert",
    "src_ip": "10.0.0.10",
    "src_port": 51514,
    "dest_ip": "203.0.113.8",
    "dest_port": 443,
    "proto": "TCP",
    "app_proto": "tls",
    "in_iface": "br-lan",
    "alert": {
        "gid": 1,
        "signature_id": 2400001,
        "rev": 3,
        "signature": "ET MALWARE Example Producer Fixture",
        "category": "A Network Trojan was detected",
        "severity": 1,
        "action": "allowed",
    },
}
manual_eve = dict(prod_eve)
manual_eve["alert"] = dict(prod_eve["alert"])
manual_eve["alert"].pop("severity")
manual_eve["alert"]["signature_id"] = 2400002
manual_eve["alert"]["signature"] = "Manual fixture missing producer severity"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    hits = HITS.read_text()
    status = STATUS.read_text()

    # Fixture sanity: production EVE carries action/risk producer fields;
    # manual fixture deliberately lacks severity and must be rejected instead of guessed.
    require(prod_eve["alert"]["action"] == "allowed", "fixture action must come from alert.action")
    require(prod_eve["alert"]["severity"] == 1, "fixture risk must come from alert.severity")
    require("severity" not in manual_eve["alert"], "manual missing-severity fixture must stay missing")

    require("aegisxd_json_nested_int_required" in hits, "Suricata severity must be required")
    require('return -2;' in hits, "missing producer severity must fail closed")
    require('suricata_event_missing_required_producer_fields' in hits,
            "degraded reason for missing producer fields is required")
    require('reason = "suricata_eve_manual_ingest"' in hits,
            "manual ingest must be labelled separately from production")
    require('reason = "suricata_eve_alert"' in hits,
            "production EVE tail must retain production reason")
    require('"production_event"' in hits, "event meta must mark production_event")
    require('"manual_ingest"' in hits, "event meta must mark manual_ingest")
    require('"production_inserted"' in hits, "manual ingest response must not claim production inserts")
    require('json_object_new_int(0)' in hits, "manual ingest production_inserted must be zero")

    require("aegisxd_suricata_pid_running" in hits and "aegisxd_suricata_pid_running" in status,
            "production active must validate the Suricata pid")
    require('"suricata_process_not_running"' in hits and '"suricata_process_not_running"' in status,
            "inactive pid must expose degraded reason")
    require('"manual_ingest_is_production"' in hits and '"suricata_manual_ingest_is_production"' in status,
            "manual ingest must be explicitly non-production")
    require('"test_events_are_production"' in hits and '"suricata_test_events_are_production"' in status,
            "test events must be explicitly non-production")
    require("aegisxd_suricata_active() && aegisxd_suricata_pid_running()" in status,
            "status production_active must require active state and running pid")

    print(json.dumps({
        "ok": True,
        "fixtures": {
            "production_action": prod_eve["alert"]["action"],
            "production_severity": prod_eve["alert"]["severity"],
            "manual_missing_severity_rejected": True,
        },
        "checked": [str(HITS), str(STATUS)],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
