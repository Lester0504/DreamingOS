#!/usr/bin/env python3
"""Offline diagnostic importer for normalized GeoIP country prefixes.

AegisXD reads GeoLite2-Country.mmdb directly and does not use this SQLite table.
Importing a complete Country MMDB can add roughly 583 MiB and is intentionally
not part of the default build, update, or runtime path.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator


ISO2_RE = re.compile(r"^[A-Z]{2}$")
OFFICIAL_ISO_CODES = frozenset(
    """AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
    CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO
    JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR
    MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO
    RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV
    TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW""".split()
)
LOCATION_ID_KEYS = ("geoname_id", "registered_country_geoname_id", "represented_country_geoname_id")
COUNTRY_KEYS = ("country_iso_code", "registered_country_iso_code", "represented_country_iso_code", "iso_code", "country")


def normalize_iso(raw: Any) -> str | None:
    code = str(raw or "").strip().upper()
    if ISO2_RE.match(code) and code in OFFICIAL_ISO_CODES:
        return code
    return None


def open_csv(path: Path) -> csv.DictReader:
    fh = path.open("r", encoding="utf-8-sig", errors="strict", newline="")
    sample = fh.read(4096)
    fh.seek(0)
    try:
        dialect = csv.Sniffer().sniff(sample) if "," in sample or "\t" in sample else csv.excel
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(fh, dialect=dialect)
    reader._dwrt_file = fh  # type: ignore[attr-defined]
    return reader


def close_csv(reader: csv.DictReader) -> None:
    fh = getattr(reader, "_dwrt_file", None)
    if fh:
        fh.close()


def pick(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    lowered = {str(k).strip().lower(): str(v or "").strip() for k, v in row.items()}
    for key in keys:
        value = lowered.get(key)
        if value:
            return value
    return ""


def load_locations(paths: list[Path], strict: bool) -> tuple[dict[str, str], dict[str, int]]:
    mapping: dict[str, str] = {}
    stats = {"files": 0, "rows": 0, "accepted": 0, "duplicates": 0, "invalid": 0}
    for path in paths:
        stats["files"] += 1
        reader = open_csv(path)
        try:
            if not reader.fieldnames:
                raise RuntimeError(f"missing CSV header: {path}")
            for row in reader:
                stats["rows"] += 1
                geoname_id = str(row.get("geoname_id") or "").strip()
                iso = normalize_iso(pick(row, COUNTRY_KEYS))
                if not geoname_id or not iso:
                    stats["invalid"] += 1
                    if strict:
                        raise RuntimeError(f"invalid location row {stats['rows']} in {path}")
                    continue
                if geoname_id in mapping:
                    stats["duplicates"] += 1
                    if strict and mapping[geoname_id] != iso:
                        raise RuntimeError(f"conflicting location {geoname_id} in {path}")
                    continue
                mapping[geoname_id] = iso
                stats["accepted"] += 1
        finally:
            close_csv(reader)
    return mapping, stats


def row_country(row: dict[str, Any], locations: dict[str, str]) -> str | None:
    iso = normalize_iso(pick(row, COUNTRY_KEYS))
    if iso:
        return iso
    for key in LOCATION_ID_KEYS:
        geoname_id = str(row.get(key) or "").strip()
        if geoname_id and geoname_id in locations:
            return locations[geoname_id]
    return None


def normalized_rows(paths: list[Path], locations: dict[str, str], strict: bool,
                    stats: dict[str, int]) -> Iterator[tuple[str, str, int, int, str, str]]:
    for path in paths:
        stats["files"] += 1
        reader = open_csv(path)
        try:
            if not reader.fieldnames:
                raise RuntimeError(f"missing CSV header: {path}")
            fields = {str(field).strip().lower() for field in reader.fieldnames}
            if "network" not in fields:
                raise RuntimeError(f"missing network column: {path}")
            for row in reader:
                stats["rows"] += 1
                raw_network = str(row.get("network") or "").strip()
                iso = row_country(row, locations)
                try:
                    network_object = ipaddress.ip_network(raw_network, strict=False)
                except ValueError:
                    stats["invalid"] += 1
                    if strict:
                        raise RuntimeError(
                            f"invalid network at row {stats['rows']} in {path}: {raw_network!r}"
                        )
                    continue
                if not iso:
                    stats["invalid"] += 1
                    if strict:
                        raise RuntimeError(
                            f"invalid or non-official country at row {stats['rows']} in {path}"
                        )
                    continue
                network = str(network_object)
                first = int(network_object.network_address)
                last = int(network_object.broadcast_address)
                family = network_object.version
                yield (
                    network,
                    iso,
                    family,
                    network_object.prefixlen,
                    f"{first:032x}" if family == 6 else f"{first:08x}",
                    f"{last:032x}" if family == 6 else f"{last:08x}",
                )
        finally:
            close_csv(reader)


def stage_blocks(args: argparse.Namespace, locations: dict[str, str]) -> tuple[Path, dict[str, int]]:
    stats = {
        "files": 0,
        "rows": 0,
        "accepted": 0,
        "duplicates": 0,
        "invalid": 0,
        "ipv4": 0,
        "ipv6": 0,
    }
    descriptor, raw_path = tempfile.mkstemp(prefix="dreamingwrt-geoip-prefix-", suffix=".sqlite3")
    os.close(descriptor)
    stage_path = Path(raw_path)
    connection = sqlite3.connect(stage_path)
    strict = not args.allow_invalid
    try:
        connection.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE prefix (
              network TEXT PRIMARY KEY,
              iso_code TEXT NOT NULL,
              family INTEGER NOT NULL,
              prefix_len INTEGER NOT NULL,
              first_ip_hex TEXT NOT NULL,
              last_ip_hex TEXT NOT NULL
            ) WITHOUT ROWID;
            """
        )
        connection.execute("BEGIN")
        for item in normalized_rows(args.blocks, locations, strict, stats):
            try:
                connection.execute(
                    "INSERT INTO prefix(network,iso_code,family,prefix_len,first_ip_hex,last_ip_hex) "
                    "VALUES(?,?,?,?,?,?)",
                    item,
                )
            except sqlite3.IntegrityError:
                stats["duplicates"] += 1
                existing = connection.execute(
                    "SELECT iso_code FROM prefix WHERE network=?", (item[0],)
                ).fetchone()
                if strict:
                    detail = "duplicate" if existing and existing[0] == item[1] else "conflicting country"
                    raise RuntimeError(f"{detail} for network {item[0]}")
                continue
            stats["accepted"] += 1
            stats["ipv6" if item[2] == 6 else "ipv4"] += 1
            if stats["accepted"] > args.max_prefixes:
                raise RuntimeError(f"prefix limit exceeded: {args.max_prefixes}")
        if stats["accepted"] == 0:
            raise RuntimeError("no valid country prefixes found; refusing empty import")
        connection.execute(
            "CREATE INDEX prefix_order ON prefix(family,first_ip_hex,prefix_len,iso_code)"
        )
        connection.commit()
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if quick_check != "ok":
            raise RuntimeError(f"staging SQLite quick_check failed: {quick_check}")
        return stage_path, stats
    except Exception:
        connection.rollback()
        connection.close()
        stage_path.unlink(missing_ok=True)
        raise
    finally:
        if connection:
            connection.close()


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS geoip_country_prefix (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          iso_code TEXT NOT NULL,
          network TEXT NOT NULL,
          family INTEGER NOT NULL,
          prefix_len INTEGER NOT NULL,
          first_ip_hex TEXT NOT NULL,
          last_ip_hex TEXT NOT NULL,
          source TEXT NOT NULL DEFAULT 'dreamingwrt',
          enabled INTEGER NOT NULL DEFAULT 1,
          updated_at INTEGER NOT NULL,
          UNIQUE(source, network)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_geoip_country_prefix_country "
        "ON geoip_country_prefix(enabled, iso_code, family)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_geoip_country_prefix_range "
        "ON geoip_country_prefix(family, first_ip_hex, last_ip_hex)"
    )
    connection.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


def apply_import(args: argparse.Namespace, stage_path: Path, row_count: int) -> dict[str, int]:
    now = int(time.time())
    result = {"inserted": 0, "updated": 0, "unchanged": 0, "changed": 0, "total": 0}
    connection = sqlite3.connect(args.db)
    stage_attached = False
    try:
        connection.execute("ATTACH DATABASE ? AS staged", (str(stage_path),))
        stage_attached = True
        connection.execute("BEGIN IMMEDIATE")
        ensure_schema(connection)
        if args.replace:
            connection.execute("DELETE FROM geoip_country_prefix WHERE source=?", (args.source,))
            result["inserted"] = row_count
        else:
            existing, unchanged = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(
                  target.iso_code=stage.iso_code AND target.family=stage.family AND
                  target.prefix_len=stage.prefix_len AND target.first_ip_hex=stage.first_ip_hex AND
                  target.last_ip_hex=stage.last_ip_hex AND target.enabled=1
                ), 0)
                FROM staged.prefix AS stage
                JOIN geoip_country_prefix AS target
                  ON target.source=? AND target.network=stage.network
                """,
                (args.source,),
            ).fetchone()
            result["unchanged"] = int(unchanged)
            result["updated"] = int(existing) - result["unchanged"]
            result["inserted"] = row_count - int(existing)
        connection.execute(
            """
            INSERT INTO geoip_country_prefix(
              iso_code,network,family,prefix_len,first_ip_hex,last_ip_hex,source,enabled,updated_at
            )
            SELECT iso_code,network,family,prefix_len,first_ip_hex,last_ip_hex,?,1,?
            FROM staged.prefix WHERE 1
            ON CONFLICT(source,network) DO UPDATE SET
              iso_code=excluded.iso_code,
              family=excluded.family,
              prefix_len=excluded.prefix_len,
              first_ip_hex=excluded.first_ip_hex,
              last_ip_hex=excluded.last_ip_hex,
              enabled=excluded.enabled,
              updated_at=CASE WHEN
                geoip_country_prefix.iso_code<>excluded.iso_code OR
                geoip_country_prefix.family<>excluded.family OR
                geoip_country_prefix.prefix_len<>excluded.prefix_len OR
                geoip_country_prefix.first_ip_hex<>excluded.first_ip_hex OR
                geoip_country_prefix.last_ip_hex<>excluded.last_ip_hex OR
                geoip_country_prefix.enabled<>excluded.enabled
              THEN excluded.updated_at ELSE geoip_country_prefix.updated_at END
            """,
            (args.source, now),
        )
        result["changed"] = result["inserted"] + result["updated"]
        result["total"] = int(
            connection.execute("SELECT COUNT(*) FROM geoip_country_prefix").fetchone()[0]
        )
        connection.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"geoip_country_prefix.{args.source}.updated_at", str(now)),
        )
        connection.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"geoip_country_prefix.{args.source}.rows", str(row_count)),
        )
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if quick_check != "ok":
            raise RuntimeError(f"SQLite quick_check failed before commit: {quick_check}")
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise
    finally:
        if stage_attached:
            connection.execute("DETACH DATABASE staged")
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--blocks", type=Path, action="append", required=True)
    parser.add_argument("--locations", type=Path, action="append", default=[])
    parser.add_argument("--source", default="maxmind_geolite2_country")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--allow-invalid", action="store_true",
        help="skip invalid/duplicate rows instead of failing the entire import",
    )
    parser.add_argument("--max-prefixes", type=int, default=3_000_000)
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"DB not found: {args.db}")
    for path in args.blocks:
        if not path.is_file():
            parser.error(f"blocks file not found: {path}")
    for path in args.locations:
        if not path.is_file():
            parser.error(f"locations file not found: {path}")
    if args.max_prefixes <= 0:
        parser.error("--max-prefixes must be positive")

    strict = not args.allow_invalid
    locations, location_stats = load_locations(args.locations, strict)
    stage_path: Path | None = None
    try:
        stage_path, block_stats = stage_blocks(args, locations)
        result = {"inserted": 0, "updated": 0, "unchanged": 0, "changed": 0, "total": 0}
        if args.apply:
            result = apply_import(args, stage_path, block_stats["accepted"])
    finally:
        if stage_path is not None:
            stage_path.unlink(missing_ok=True)

    print(f"db={args.db}")
    print(f"source={args.source}")
    print(
        "locations files={files} rows={rows} accepted={accepted} duplicates={duplicates} invalid={invalid}".format(
            **location_stats
        )
    )
    print(
        "blocks files={files} rows={rows} accepted={accepted} ipv4={ipv4} ipv6={ipv6} "
        "duplicates={duplicates} invalid={invalid}".format(**block_stats)
    )
    print(
        "mode={} prefixes={} inserted={inserted} updated={updated} unchanged={unchanged} "
        "changed={changed} total={total}".format(
            "apply" if args.apply else "dry-run", block_stats["accepted"], **result
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"geoip country prefix import failed: {error}", file=sys.stderr)
        sys.exit(1)
