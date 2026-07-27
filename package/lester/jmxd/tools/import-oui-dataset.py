#!/usr/bin/env python3
"""Import OUI/vendor datasets into DreamingWrt signature DB fingerprint rules."""

from __future__ import annotations

import argparse
import csv
import re
import sqlite3
import sys
import time
from pathlib import Path


HEX_RE = re.compile(r"^[0-9a-fA-F]{6,12}$")
BAD_VENDOR_NAMES = {"", "reserved", "private", "unknown"}


def normalize_vendor(raw: str) -> str:
    name = " ".join((raw or "").replace("\t", " ").split()).strip()
    for suffix in (" (base 16)", " (hex)", " (ma-l)", " (ma-m)", " (ma-s)"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)].strip()
    return name


def normalize_name(raw: str) -> str:
    return normalize_vendor(raw).lower()


def normalize_oui(raw: str) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    text = text.split("/", 1)[0].strip()
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    text = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(text) < 6:
        return None
    if len(text) not in (6, 7, 8, 9, 10, 11, 12):
        return None
    if not HEX_RE.match(text):
        return None
    return text.upper()


def parse_ieee_csv(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        dialect = csv.Sniffer().sniff(sample) if "," in sample else csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            return rows
        fields = {f.lower().strip(): f for f in reader.fieldnames}
        prefix_key = (
            fields.get("assignment")
            or fields.get("oui")
            or fields.get("registry")
            or fields.get("mac prefix")
        )
        name_key = (
            fields.get("organization name")
            or fields.get("organization")
            or fields.get("vendor")
            or fields.get("company")
        )
        if not prefix_key or not name_key:
            return rows
        for row in reader:
            oui = normalize_oui(row.get(prefix_key, ""))
            vendor = normalize_vendor(row.get(name_key, ""))
            if oui and vendor and vendor.lower() not in BAD_VENDOR_NAMES:
                rows.append((oui, vendor))
    return rows


def parse_text(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if "(base 16)" in line.lower() or "(hex)" in line.lower():
                left, right = line.split(")", 1)
                oui = normalize_oui(left)
                vendor = normalize_vendor(right)
            else:
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                oui = normalize_oui(parts[0])
                vendor = normalize_vendor(parts[1].split("#", 1)[0])
            if oui and vendor and vendor.lower() not in BAD_VENDOR_NAMES:
                rows.append((oui, vendor))
    return rows


def parse_inputs(paths: list[Path]) -> tuple[list[tuple[str, str]], dict[str, int]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    stats = {"files": 0, "rows": 0, "accepted": 0, "duplicates": 0, "invalid": 0}

    for path in paths:
        stats["files"] += 1
        parsed = parse_ieee_csv(path) if path.suffix.lower() == ".csv" else parse_text(path)
        if not parsed and path.suffix.lower() != ".csv":
            parsed = parse_ieee_csv(path)
        for oui, vendor in parsed:
            stats["rows"] += 1
            if not oui or not vendor:
                stats["invalid"] += 1
                continue
            key = f"{oui}:{normalize_name(vendor)}"
            if key in seen:
                stats["duplicates"] += 1
                continue
            seen.add(key)
            out.append((oui, vendor))
            stats["accepted"] += 1
    out.sort(key=lambda item: (item[0], normalize_name(item[1])))
    return out, stats


def ensure_schema(con: sqlite3.Connection) -> None:
    required = {"device_vendor", "device_fingerprint_rule", "meta"}
    rows = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    present = {r[0] for r in rows}
    missing = sorted(required - present)
    if missing:
        raise RuntimeError(f"missing required table(s): {', '.join(missing)}")


def next_vendor_id(con: sqlite3.Connection) -> int:
    row = con.execute("SELECT COALESCE(MAX(vendor_id), 19999) + 1 FROM device_vendor").fetchone()
    value = int(row[0]) if row and row[0] is not None else 20000
    return max(value, 20000)


def get_or_create_vendor(con: sqlite3.Connection, name: str, source: str,
                         vendor_id_state: list[int]) -> int:
    normalized = normalize_name(name)
    row = con.execute(
        "SELECT vendor_id FROM device_vendor WHERE normalized_name=? ORDER BY vendor_id LIMIT 1",
        (normalized,),
    ).fetchone()
    if row:
        return int(row[0])
    vendor_id = vendor_id_state[0]
    vendor_id_state[0] += 1
    con.execute(
        """
        INSERT INTO device_vendor(vendor_id, name, normalized_name, legacy_id, source)
        VALUES (?, ?, ?, ?, ?)
        """,
        (vendor_id, name, normalized, f"oui:{vendor_id}", source),
    )
    return vendor_id


def apply_import(args: argparse.Namespace, rows: list[tuple[str, str]]) -> dict[str, int]:
    now = int(time.time())
    con = sqlite3.connect(args.db)
    changed = 0
    vendors_created = 0
    rules_written = 0
    rules_updated = 0
    vendor_id_state = [0]
    try:
        ensure_schema(con)
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("BEGIN IMMEDIATE")
        if args.replace:
            con.execute("DELETE FROM device_fingerprint_rule WHERE source=? AND match_type='oui'", (args.source,))
        vendor_id_state[0] = next_vendor_id(con)
        for oui, vendor in rows:
            before_vendor = con.total_changes
            vendor_id = get_or_create_vendor(con, vendor, args.source, vendor_id_state)
            if con.total_changes > before_vendor:
                vendors_created += 1
            sort_key = f"oui|{oui}|{normalize_name(vendor)}"
            before_rule = con.total_changes
            con.execute(
                """
                UPDATE device_fingerprint_rule
                SET confidence=?, enabled=1, legacy_id=?, vendor_name=?, sort_key=?
                WHERE source=? AND match_type='oui' AND pattern=? AND vendor_id=?
                """,
                (args.confidence, f"oui:{oui}", vendor, sort_key, args.source, oui, vendor_id),
            )
            if con.total_changes > before_rule:
                rules_updated += 1
                continue
            before_rule = con.total_changes
            con.execute(
                """
                INSERT INTO device_fingerprint_rule(
                  source, match_type, pattern, vendor_id, type_id, os_name, model,
                  confidence, enabled, legacy_id, vendor_name, type_name, sort_key
                )
                VALUES (?, 'oui', ?, ?, NULL, '', '', ?, 1, ?, ?, '', ?)
                """,
                (args.source, oui, vendor_id, args.confidence, f"oui:{oui}", vendor, sort_key),
            )
            if con.total_changes > before_rule:
                rules_written += 1
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"oui_dataset.{args.source}.updated_at", str(now)),
        )
        con.commit()
        changed = vendors_created + rules_written + rules_updated
        return {
            "vendors_created": vendors_created,
            "rules_written": rules_written,
            "rules_updated": rules_updated,
            "changed": changed,
        }
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--source", default="ieee_oui")
    parser.add_argument("--confidence", type=float, default=30.0)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"DB not found: {args.db}")
    for path in args.input:
        if not path.is_file():
            parser.error(f"input not found: {path}")
    if args.confidence < 0 or args.confidence > 100:
        parser.error("--confidence must be between 0 and 100")

    rows, stats = parse_inputs(args.input)
    result = {"vendors_created": 0, "rules_written": 0, "rules_updated": 0, "changed": 0}
    if args.apply:
        result = apply_import(args, rows)

    print(f"db={args.db}")
    print(f"source={args.source}")
    print(
        "files={files} rows={rows} accepted={accepted} duplicates={duplicates} invalid={invalid}".format(**stats)
    )
    print(
        "mode={} oui={} vendors_created={} rules_written={} rules_updated={} changed={}".format(
            "apply" if args.apply else "dry-run",
            len(rows),
            result["vendors_created"],
            result["rules_written"],
            result["rules_updated"],
            result["changed"],
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
