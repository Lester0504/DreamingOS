#!/usr/bin/env python3
"""Import GeoIP country metadata into dreamingwrt_signatures.db."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any


ISO2_RE = re.compile(r"^[A-Z]{2}$")
EXTRA_COUNTRY_CODES = {"XK"}
FIELD_ALIASES = {
    "iso_code": ("iso_code", "iso", "code", "country_code", "alpha2", "alpha_2"),
    "name_en": ("name_en", "english_name", "name", "country", "country_name"),
    "name_zh": ("name_zh", "chinese_name", "zh_name", "name_cn", "name_zh_cn"),
    "continent": ("continent", "continent_code", "region"),
    "flag_asset": ("flag_asset", "flag", "flag_path"),
    "source": ("source", "dataset_source"),
    "enabled": ("enabled", "is_enabled"),
}


def normalize_iso(raw: Any) -> str | None:
    code = str(raw or "").strip().replace("_", "-").upper()
    if ISO2_RE.match(code):
        return code
    if code in EXTRA_COUNTRY_CODES:
        return code
    return None


def normalize_text(raw: Any) -> str:
    return " ".join(str(raw or "").replace("\t", " ").split()).strip()


def normalize_bool(raw: Any, default: int = 1) -> int:
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return 1 if raw else 0
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled"}:
        return 1
    if text in {"0", "false", "no", "n", "off", "disabled"}:
        return 0
    return default


def pick(row: dict[str, Any], field: str) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in FIELD_ALIASES[field]:
        if key in lowered:
            return lowered[key]
    return None


def read_iso3166_tab(path: Path | None) -> dict[str, str]:
    names: dict[str, str] = {}
    if not path or not path.is_file():
        return names
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            text = line.strip()
            if not text or text.startswith("#") or "\t" not in text:
                continue
            code, name = text.split("\t", 1)
            iso = normalize_iso(code)
            if iso and ISO2_RE.match(iso):
                names[iso] = normalize_text(name)
    return names


def flag_rows(flags_dir: Path | None, iso_names: dict[str, str],
              source: str) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    rows: dict[str, dict[str, Any]] = {}
    stats = {"flag_files": 0, "flag_accepted": 0, "flag_invalid": 0}
    if not flags_dir:
        return rows, stats
    if not flags_dir.is_dir():
        raise RuntimeError(f"flags dir not found: {flags_dir}")
    for path in sorted(flags_dir.glob("*.svg")):
        stats["flag_files"] += 1
        iso = normalize_iso(path.stem)
        if not iso or (iso not in iso_names and iso not in EXTRA_COUNTRY_CODES):
            stats["flag_invalid"] += 1
            continue
        name_en = iso_names.get(iso, "")
        rows[iso] = {
            "iso_code": iso,
            "name_en": name_en,
            "name_zh": "",
            "continent": "",
            "flag_asset": f"flags/4x3/{path.name}",
            "source": source,
            "enabled": 1,
        }
        stats["flag_accepted"] += 1
    return rows, stats


def parse_csv(path: Path, source: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample) if "," in sample or "\t" in sample else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            return out
        for row in reader:
            iso = normalize_iso(pick(row, "iso_code"))
            if not iso:
                out.append({"_invalid": True})
                continue
            out.append({
                "iso_code": iso,
                "name_en": normalize_text(pick(row, "name_en")),
                "name_zh": normalize_text(pick(row, "name_zh")),
                "continent": normalize_text(pick(row, "continent")),
                "flag_asset": normalize_text(pick(row, "flag_asset")),
                "source": normalize_text(pick(row, "source")) or source,
                "enabled": normalize_bool(pick(row, "enabled"), 1),
            })
    return out


def flatten_json_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("countries", "geoip_country", "items", "rows", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        if all(isinstance(v, dict) for v in data.values()):
            rows: list[dict[str, Any]] = []
            for key, value in data.items():
                row = dict(value)
                row.setdefault("iso_code", key)
                rows.append(row)
            return rows
    return []


def parse_json(path: Path, source: str) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for row in flatten_json_rows(raw):
        iso = normalize_iso(pick(row, "iso_code"))
        if not iso:
            rows.append({"_invalid": True})
            continue
        rows.append({
            "iso_code": iso,
            "name_en": normalize_text(pick(row, "name_en")),
            "name_zh": normalize_text(pick(row, "name_zh")),
            "continent": normalize_text(pick(row, "continent")),
            "flag_asset": normalize_text(pick(row, "flag_asset")),
            "source": normalize_text(pick(row, "source")) or source,
            "enabled": normalize_bool(pick(row, "enabled"), 1),
        })
    return rows


def parse_inputs(paths: list[Path], source: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    stats = {"input_files": 0, "input_rows": 0, "input_invalid": 0}
    for path in paths:
        stats["input_files"] += 1
        parsed = parse_json(path, source) if path.suffix.lower() == ".json" else parse_csv(path, source)
        for row in parsed:
            stats["input_rows"] += 1
            if row.get("_invalid"):
                stats["input_invalid"] += 1
            rows.append(row)
    return rows, stats


def merge_rows(base: dict[str, dict[str, Any]], input_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    stats = {"accepted": 0, "duplicates": 0, "invalid": 0, "missing_flags": 0}
    seen_inputs: set[str] = set()
    for row in input_rows:
        iso = normalize_iso(row.get("iso_code"))
        if not iso:
            stats["invalid"] += 1
            continue
        if iso in seen_inputs:
            stats["duplicates"] += 1
            continue
        seen_inputs.add(iso)
        merged = dict(base.get(iso, {
            "iso_code": iso,
            "name_en": "",
            "name_zh": "",
            "continent": "",
            "flag_asset": "",
            "source": row.get("source", ""),
            "enabled": 1,
        }))
        for key in ("name_en", "name_zh", "continent", "flag_asset", "source"):
            value = normalize_text(row.get(key))
            if value:
                merged[key] = value
        merged["enabled"] = normalize_bool(row.get("enabled"), int(merged.get("enabled", 1)))
        base[iso] = merged

    out = []
    for iso, row in sorted(base.items()):
        if not normalize_text(row.get("flag_asset")):
            stats["missing_flags"] += 1
        out.append(row)
        stats["accepted"] += 1
    return out, stats


def ensure_schema(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS geoip_country (
          iso_code TEXT PRIMARY KEY,
          name_en TEXT NOT NULL DEFAULT '',
          name_zh TEXT NOT NULL DEFAULT '',
          continent TEXT NOT NULL DEFAULT '',
          flag_asset TEXT NOT NULL DEFAULT '',
          source TEXT NOT NULL DEFAULT 'dreamingwrt',
          enabled INTEGER NOT NULL DEFAULT 1,
          updated_at INTEGER NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_geoip_country_enabled
        ON geoip_country(enabled, iso_code)
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
        """
    )


def apply_import(args: argparse.Namespace, rows: list[dict[str, Any]]) -> dict[str, int]:
    now = int(time.time())
    con = sqlite3.connect(args.db)
    inserted = 0
    updated = 0
    unchanged = 0
    try:
        con.execute("BEGIN IMMEDIATE")
        ensure_schema(con)
        if args.replace:
            con.execute("DELETE FROM geoip_country WHERE source=?", (args.source,))
        for row in rows:
            values = (
                row["iso_code"],
                normalize_text(row.get("name_en")),
                normalize_text(row.get("name_zh")),
                normalize_text(row.get("continent")),
                normalize_text(row.get("flag_asset")),
                normalize_text(row.get("source")) or args.source,
                normalize_bool(row.get("enabled"), 1),
            )
            existing = con.execute(
                """
                SELECT name_en, name_zh, continent, flag_asset, source, enabled
                FROM geoip_country WHERE iso_code=?
                """,
                (row["iso_code"],),
            ).fetchone()
            if existing is not None:
                current = (
                    str(existing[0] or ""),
                    str(existing[1] or ""),
                    str(existing[2] or ""),
                    str(existing[3] or ""),
                    str(existing[4] or ""),
                    int(existing[5] or 0),
                )
                desired = values[1:]
                if current == desired:
                    unchanged += 1
                    continue
                con.execute(
                    """
                    UPDATE geoip_country
                    SET name_en=?, name_zh=?, continent=?, flag_asset=?,
                        source=?, enabled=?, updated_at=?
                    WHERE iso_code=?
                    """,
                    (values[1], values[2], values[3], values[4], values[5], values[6], now, values[0]),
                )
                updated += 1
            else:
                con.execute(
                    """
                    INSERT INTO geoip_country(
                      iso_code, name_en, name_zh, continent, flag_asset, source, enabled, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values + (now,),
                )
                inserted += 1
        changed = inserted + updated
        total = int(con.execute("SELECT COUNT(*) FROM geoip_country").fetchone()[0])
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"geoip_country.{args.source}.updated_at", str(now)),
        )
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"geoip_country.{args.source}.rows", str(total)),
        )
        con.commit()
        return {
            "written": len(rows),
            "changed": changed,
            "total": total,
            "inserted": inserted,
            "updated": updated,
            "unchanged": unchanged,
        }
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def default_iso3166_path() -> Path | None:
    for raw in ("/usr/share/zoneinfo/iso3166.tab", "/usr/share/misc/iso3166"):
        path = Path(raw)
        if path.is_file():
            return path
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", default=[])
    parser.add_argument("--flags-dir", type=Path)
    parser.add_argument("--iso3166-tab", type=Path, default=default_iso3166_path())
    parser.add_argument("--source", default="dreamingwrt_geoip")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"DB not found: {args.db}")
    for path in args.input:
        if not path.is_file():
            parser.error(f"input not found: {path}")

    iso_names = read_iso3166_tab(args.iso3166_tab)
    base, flag_stats = flag_rows(args.flags_dir, iso_names, args.source)
    input_rows, input_stats = parse_inputs(args.input, args.source)
    rows, merge_stats = merge_rows(base, input_rows)
    result = {"written": 0, "changed": 0, "total": 0, "inserted": 0, "updated": 0, "unchanged": 0}
    if args.apply:
        result = apply_import(args, rows)

    print(f"db={args.db}")
    print(f"source={args.source}")
    print(f"iso3166_tab={args.iso3166_tab or ''} names={len(iso_names)}")
    print(
        "flags files={flag_files} accepted={flag_accepted} invalid={flag_invalid}".format(**flag_stats)
    )
    print(
        "inputs files={input_files} rows={input_rows} invalid={input_invalid}".format(**input_stats)
    )
    print(
        "mode={} countries={} duplicates={} invalid={} missing_flags={}".format(
            "apply" if args.apply else "dry-run",
            len(rows),
            merge_stats["duplicates"],
            merge_stats["invalid"],
            merge_stats["missing_flags"],
        )
    )
    print(
        "written={written} inserted={inserted} updated={updated} unchanged={unchanged} changed={changed} total={total}".format(**result)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
