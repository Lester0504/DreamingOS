#!/usr/bin/env python3
"""Real SQLite projection of audited candidate measurements; never scans/probes."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = Path(os.environ.get("AC_SURVEY_TEST_PREFIX", "/opt/homebrew/opt/json-c"))
MAC = "AA:BB:CC:DD:EE:01"
END = 1800000000


def main():
    with tempfile.TemporaryDirectory(prefix="ac-client-candidates-") as tmp:
        tmp = Path(tmp)
        binary, database = tmp / "fixture", tmp / "audit.db"
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I" + str(PREFIX / "include"), str(ROOT / "tests/ac_client_candidates_fixture.c"),
            str(ROOT / "src/ac/ac_client_candidates.c"), "-L" + str(PREFIX / "lib"),
            "-Wl,-rpath," + str(PREFIX / "lib"), "-ljson-c", "-lsqlite3", "-o", str(binary),
        ], check=True)

        def query(start=END-300, end=END, now=END, mac=MAC, missing=False):
            result = subprocess.run([str(binary), "-" if missing else str(database)],
                input=json.dumps(dict(mac=mac, start=start*1000, end=end*1000, now=now*1000)),
                text=True, capture_output=True, check=True)
            return json.loads(result.stdout)

        assert query(missing=True)["reason"] == "candidate_store_unavailable"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE unrelated(value TEXT)")
        assert query()["meta"]["status"] == "candidate_table_unavailable"
        with sqlite3.connect(database) as db:
            db.executescript("""
                CREATE TABLE ac_roaming_audit(audit_id INTEGER PRIMARY KEY,
                    station_mac TEXT, observed_at INTEGER, candidates_json TEXT);
                CREATE TABLE ac_aps(ap_id TEXT PRIMARY KEY,name TEXT);
                INSERT INTO ac_aps VALUES('ap-one','Office AP');
            """)
        assert query()["meta"]["status"] == "no_candidate_samples"

        def candidate(ap="ap-one", radio="phy0", age=10, rssi=-60,
                      source="ieee80211k_beacon_report", **changes):
            value = dict(ap_id=ap, radio_id=radio, signal_estimate_dbm=rssi,
                signal_source=source, signal_direction="uplink" if source == "ap_probe_request" else "downlink",
                signal_observed_at=END-age, signal_measured=True, signal_randomized=False,
                score=99, proximity="fabricated", station_count=0)
            value.update(changes)
            return value

        def put(items, observed=END, mac=MAC):
            with sqlite3.connect(database) as db:
                db.execute("INSERT INTO ac_roaming_audit(station_mac,observed_at,candidates_json) "
                           "VALUES(?,?,?)", (mac, observed, json.dumps(items)))

        # A newer audit can repeat an older cached observation. Measurement time
        # wins over audit ordering, and AP/radio identity is never flattened.
        put([candidate(age=5, rssi=-55), candidate(radio="phy1", age=120, rssi=-80, source="ieee80211k_beacon_table")],
            observed=END-2)
        put([candidate(age=20, rssi=-77),
             candidate(ap="ap-two", age=30, source="ap_probe_request"),
             candidate(ap="expired-k", age=121),
             candidate(ap="expired-probe", age=31, source="ap_probe_request"),
             candidate(ap="random", signal_randomized=True),
             candidate(ap="not-measured", signal_measured=False),
             candidate(ap="fallback", source="station_current_rssi_fallback"),
             candidate(ap="wrong-direction", signal_direction="uplink"),
             candidate(ap="future", age=-1),
             candidate(ap="relative-future", age=5)], observed=END-10)
        # Put eligible probe and exact-age boundaries at a compatible audit time.
        put([candidate(ap="ap-two", age=30, source="ap_probe_request"),
             candidate(ap="expired-k", age=121),
             candidate(ap="expired-probe", age=31, source="ap_probe_request")])
        put([candidate(ap="other-client")], mac="aa:bb:cc:dd:ee:02")
        data = query(mac=MAC.lower())
        entries = {(r["ap_id"], r["radio_id"]): r for r in data["candidates"]}
        assert set(entries) == {("ap-one", "phy0"), ("ap-one", "phy1"), ("ap-two", "phy0")}
        assert entries["ap-one", "phy0"]["signal_dbm"] == -55
        assert entries["ap-one", "phy0"]["name"] == "Office AP"
        assert entries["ap-two", "phy0"]["name"] is None
        assert entries["ap-one", "phy1"]["age_ms"] == 120000
        assert entries["ap-two", "phy0"]["age_ms"] == 30000
        assert entries["ap-two", "phy0"]["direction"] == "uplink"
        assert data["scope"] == MAC.lower() and data["meta"]["excluded_measurements"] > 0
        for row in entries.values():
            assert not {"score", "proximity", "station_count", "signal_estimate_dbm"} & row.keys()
            assert row["observed_at"] <= END*1000

        # Historical requests are fresh at their end, not at today's wall clock.
        assert len(query(now=END+86400)["candidates"]) == 3
        assert len(query(start=END-5)["candidates"]) == 1  # closed start includes exact boundary
        assert len(query(start=END-4)["candidates"]) == 0  # measurement predates window
        assert query(end=END+31, now=END+31)["meta"]["status"] == "available"
        assert ("ap-two", "phy0") not in {(r["ap_id"], r["radio_id"])
            for r in query(end=END+31, now=END+31)["candidates"]}
        assert query(end=END+121, now=END+121)["meta"]["status"] == "candidate_measurements_expired"
        assert query(mac="not-a-mac")["reason"] == "invalid_candidate_query"
        assert query(start=END+1)["reason"] == "invalid_candidate_query"
        # Producer's +5s tolerance never admits future measurements.
        put([candidate(ap="future-now", age=-1)], observed=END+2)
        assert not any(r["ap_id"] == "future-now" for r in query(end=END+3)["candidates"])
        with sqlite3.connect(database) as db:
            db.execute("DELETE FROM ac_roaming_audit")
            db.execute("INSERT INTO ac_roaming_audit VALUES(1,?,?,?)", (MAC, END, "null"))
        assert query()["reason"] == "candidate_data_invalid"
        with sqlite3.connect(database) as db:
            db.execute("DELETE FROM ac_roaming_audit")
            db.executemany("INSERT INTO ac_roaming_audit(station_mac,observed_at,candidates_json) VALUES(?,?,?)",
                           [(MAC, END, json.dumps([candidate()]))] * 2049)
        capped = query()
        assert capped["meta"]["truncated"] and capped["meta"]["rows_scanned"] == 2048
        assert not capped["complete"]
        print("ok: read-only SQLite; exact MAC/window; real/fallback/random/future; "
              "120s/30s expiry; latest AP/radio; name lookup; no score/proximity; "
              "historical freshness; missing/corrupt source; bounded read")


if __name__ == "__main__":
    main()
