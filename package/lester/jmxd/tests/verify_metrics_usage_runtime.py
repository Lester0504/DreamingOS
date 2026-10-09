#!/usr/bin/env python3
"""Cross-check Dashboard usage against reset-aware metrics checkpoints.

The summary response carries the current per-WAN raw counters while metrics.db
contains cumulative checkpoints. Reconstructing the in-memory tail from those
two sources matches jmx_metrics_usage_query(); comparing only two persisted
checkpoints incorrectly drops traffic since the last checkpoint.
"""

import argparse
import json
import sqlite3
from pathlib import Path


def summary_data(document: dict) -> dict:
    data = document.get("data", document)
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    if not isinstance(data, dict):
        raise ValueError("summary response has no data object")
    return data


def checkpoint(db: sqlite3.Connection, wan_id: str, sql: str, params: tuple):
    return db.execute(sql, (wan_id, *params)).fetchone()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary_json", type=Path)
    parser.add_argument("metrics_db", type=Path)
    parser.add_argument("--minimum-tolerance", type=int, default=10 * 1024 * 1024)
    args = parser.parse_args()

    summary = summary_data(json.loads(args.summary_json.read_text(encoding="utf-8")))
    traffic = summary["traffic"]
    start = int(traffic["today_period_start"])
    end = int(traffic["today_period_end"])
    wans = {row["id"]: row for row in summary.get("wans", []) if row.get("id")}
    db = sqlite3.connect(f"file:{args.metrics_db}?mode=ro", uri=True)

    reconstructed_up = 0
    reconstructed_down = 0
    checked = 0
    for wan_id, wan in sorted(wans.items()):
        base = checkpoint(
            db,
            wan_id,
            "SELECT bucket_ts,total_tx,total_rx FROM counter_checkpoint "
            "WHERE wan_id=? AND bucket_ts>=? AND bucket_ts<=? "
            "ORDER BY bucket_ts LIMIT 1",
            (start, end),
        )
        latest = checkpoint(
            db,
            wan_id,
            "SELECT bucket_ts,raw_tx,raw_rx,total_tx,total_rx FROM counter_checkpoint "
            "WHERE wan_id=? AND bucket_ts<=? ORDER BY bucket_ts DESC LIMIT 1",
            (end,),
        )
        if not base or not latest:
            continue
        current_tx = int(wan.get("tx_bytes", wan.get("device_up_bytes", 0)))
        current_rx = int(wan.get("rx_bytes", wan.get("device_down_bytes", 0)))
        tail_tx = current_tx - latest[1] if current_tx >= latest[1] else current_tx
        tail_rx = current_rx - latest[2] if current_rx >= latest[2] else current_rx
        reconstructed_up += latest[3] + tail_tx - base[1]
        reconstructed_down += latest[4] + tail_rx - base[2]
        checked += 1
    db.close()

    if not checked:
        raise SystemExit("FAIL: no WAN had both a checkpoint and a current counter")
    api_up = int(traffic["today_up"])
    api_down = int(traffic["today_down"])
    api_total = int(traffic["today_total"])
    if api_total != api_up + api_down:
        raise SystemExit("FAIL: API today_total is not today_up + today_down")

    interval = max(10.0, float(traffic.get("sample_interval_ms", 0)) / 1000.0 + 5.0)
    live_rate = max(0, int(traffic.get("up_rate", 0))) + max(0, int(traffic.get("down_rate", 0)))
    tolerance = max(args.minimum_tolerance, int(live_rate * interval))
    reconstructed_total = reconstructed_up + reconstructed_down
    difference = abs(reconstructed_total - api_total)
    if difference > tolerance:
        raise SystemExit(
            f"FAIL: reconstructed={reconstructed_total} api={api_total} "
            f"difference={difference} tolerance={tolerance}"
        )
    print(
        "ok: reset-aware current-counter reconstruction matches Dashboard usage; "
        f"wans={checked} reconstructed={reconstructed_total} api={api_total} "
        f"difference={difference} tolerance={tolerance}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
