#!/usr/bin/env python3
"""Import reputation IP/domain/URL datasets into dreamingwrt_signatures.db."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]{0,62}$")
BAD_DOMAINS = {"localhost", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}
VALUE_KEYS = (
    "value", "indicator", "ioc", "ioc_value", "ip", "cidr", "network",
    "domain", "hostname", "host", "url",
)
KIND_KEYS = ("kind", "type", "threat_type", "category", "classification", "ioc_type")


def normalize_kind(raw: Any, default: str) -> str:
    text = normalize_text(raw or default).lower()
    text = re.sub(r"[^a-z0-9_.-]+", "_", text).strip("_")
    return text or default


def normalize_text(raw: Any) -> str:
    return " ".join(str(raw or "").replace("\t", " ").split()).strip()


def clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        out = int(float(str(value).strip()))
    except (TypeError, ValueError):
        out = default
    return max(low, min(high, out))


def clamp_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        out = float(str(value).strip())
    except (TypeError, ValueError):
        out = default
    return max(low, min(high, out))


def strip_inline_comment(raw: str) -> str:
    text = raw.strip()
    if not text or text.startswith(("#", ";", "!", "//")):
        return ""
    for marker in (" #", "\t#", " ;", "\t;"):
        if marker in text:
            text = text.split(marker, 1)[0].strip()
    return text.strip().strip("'\"")


def normalize_domain(raw: str) -> str | None:
    text = strip_inline_comment(raw).lower()
    if not text:
        return None
    if text.startswith(("0.0.0.0 ", "127.0.0.1 ", "::1 ")):
        parts = text.split()
        text = parts[1] if len(parts) > 1 else ""
    elif " " in text or "\t" in text:
        text = text.split()[0]
    if text.startswith("||"):
        text = text[2:]
    if text.startswith("|"):
        text = text[1:]
    text = text.replace("^", " ").replace("$", " ").split()[0]
    text = text.strip(".")
    if text.startswith("*."):
        text = text[2:]
    if "/" in text:
        text = text.split("/", 1)[0]
    if ":" in text or not text or text in BAD_DOMAINS:
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if is_ip_or_network(text) or not DOMAIN_RE.match(text):
        return None
    return text


def is_ip_or_network(raw: str) -> bool:
    try:
        ipaddress.ip_network(raw, strict=False)
        return True
    except ValueError:
        return False


def normalize_network(raw: str) -> tuple[str, int, int] | None:
    text = strip_inline_comment(raw)
    if not text:
        return None
    if " " in text or "\t" in text:
        text = text.split()[0]
    text = text.strip("[]")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return str(net), net.version, net.prefixlen


def normalize_url(raw: str) -> tuple[str, str] | None:
    text = strip_inline_comment(raw)
    if not text or "://" not in text:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.strip("[]").lower()
    domain = normalize_domain(host) or host
    if not domain or domain in BAD_DOMAINS:
        return None
    netloc = domain
    if parts.port:
        netloc = f"{domain}:{parts.port}"
    path = parts.path or "/"
    normalized = urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))
    return normalized, domain


def classify_value(raw: Any) -> tuple[str, dict[str, Any]] | None:
    text = strip_inline_comment(str(raw or ""))
    if not text:
        return None
    url = normalize_url(text)
    if url:
        value, domain = url
        return "url", {"value": value, "domain": domain}
    net = normalize_network(text)
    if net:
        value, family, prefix_len = net
        return "ip", {"value": value, "family": family, "prefix_len": prefix_len}
    domain = normalize_domain(text)
    if domain:
        return "domain", {"value": domain}
    return None


def first_present(row: dict[str, Any], keys: tuple[str, ...]) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        if key in lowered and lowered[key] not in (None, ""):
            return lowered[key]
    return None


def parse_text(path: Path, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    stats = {"lines": 0, "invalid": 0}
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            stats["lines"] += 1
            value = strip_inline_comment(raw)
            if not value:
                continue
            if "," in value and "://" not in value:
                value = next(csv.reader([value]))[0].strip()
            item = classify_value(value)
            if not item:
                stats["invalid"] += 1
                continue
            table, data = item
            data.update({
                "table": table,
                "kind": args.kind,
                "severity": args.severity,
                "confidence": args.confidence,
                "note": "",
            })
            rows.append(data)
    return rows, stats


def parse_csv_file(path: Path, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    stats = {"lines": 0, "invalid": 0}
    with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample) if "," in sample or "\t" in sample else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            return parse_text(path, args)
        fields = {str(field).strip().lower() for field in reader.fieldnames}
        if not fields.intersection(VALUE_KEYS):
            return parse_text(path, args)
        for row in reader:
            stats["lines"] += 1
            value = first_present(row, VALUE_KEYS)
            item = classify_value(value)
            if not item:
                stats["invalid"] += 1
                continue
            table, data = item
            data.update({
                "table": table,
                "kind": normalize_kind(first_present(row, KIND_KEYS), args.kind),
                "severity": clamp_int(row.get("severity"), args.severity, 0, 100),
                "confidence": clamp_float(row.get("confidence"), args.confidence, 0.0, 100.0),
                "note": normalize_text(row.get("note") or row.get("description") or ""),
            })
            rows.append(data)
    return rows, stats


def flatten_json(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("items", "rows", "data", "indicators", "iocs", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        if all(isinstance(v, dict) for v in data.values()):
            rows = []
            for key, value in data.items():
                row = dict(value)
                row.setdefault("value", key)
                rows.append(row)
            return rows
    return []


def parse_json_file(path: Path, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    stats = {"lines": 0, "invalid": 0}
    for row in flatten_json(raw):
        stats["lines"] += 1
        value = first_present(row, VALUE_KEYS)
        item = classify_value(value)
        if not item:
            stats["invalid"] += 1
            continue
        table, data = item
        data.update({
            "table": table,
            "kind": normalize_kind(first_present(row, KIND_KEYS), args.kind),
            "severity": clamp_int(row.get("severity"), args.severity, 0, 100),
            "confidence": clamp_float(row.get("confidence"), args.confidence, 0.0, 100.0),
            "note": normalize_text(row.get("note") or row.get("description") or ""),
        })
        rows.append(data)
    return rows, stats


def parse_inputs(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    stats = {
        "files": 0,
        "lines": 0,
        "ip": 0,
        "domain": 0,
        "url": 0,
        "duplicates": 0,
        "invalid": 0,
    }
    for path in args.input:
        stats["files"] += 1
        if path.suffix.lower() == ".json":
            rows, local = parse_json_file(path, args)
        elif path.suffix.lower() == ".csv":
            rows, local = parse_csv_file(path, args)
        else:
            rows, local = parse_text(path, args)
        stats["lines"] += local["lines"]
        stats["invalid"] += local["invalid"]
        for row in rows:
            key = (row["table"], row["value"])
            if key in seen:
                stats["duplicates"] += 1
                continue
            seen.add(key)
            stats[row["table"]] += 1
            out.append(row)
    out.sort(key=lambda item: (item["table"], item["value"]))
    return out, stats


def ensure_schema(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS reputation_source (
          source TEXT PRIMARY KEY,
          kind TEXT NOT NULL DEFAULT 'threat',
          description TEXT NOT NULL DEFAULT '',
          default_severity INTEGER NOT NULL DEFAULT 50,
          default_confidence REAL NOT NULL DEFAULT 70,
          enabled INTEGER NOT NULL DEFAULT 1,
          updated_at INTEGER NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS reputation_ip_entry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          value TEXT NOT NULL,
          family INTEGER NOT NULL,
          prefix_len INTEGER NOT NULL,
          kind TEXT NOT NULL,
          severity INTEGER NOT NULL DEFAULT 50,
          confidence REAL NOT NULL DEFAULT 70,
          source TEXT NOT NULL,
          first_seen INTEGER NOT NULL,
          last_seen INTEGER NOT NULL,
          expires_at INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          note TEXT NOT NULL DEFAULT '',
          UNIQUE(source, value)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS reputation_domain_entry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          kind TEXT NOT NULL,
          severity INTEGER NOT NULL DEFAULT 50,
          confidence REAL NOT NULL DEFAULT 70,
          source TEXT NOT NULL,
          first_seen INTEGER NOT NULL,
          last_seen INTEGER NOT NULL,
          expires_at INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          note TEXT NOT NULL DEFAULT '',
          UNIQUE(source, domain)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS reputation_url_entry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          url TEXT NOT NULL,
          domain TEXT NOT NULL DEFAULT '',
          kind TEXT NOT NULL,
          severity INTEGER NOT NULL DEFAULT 50,
          confidence REAL NOT NULL DEFAULT 70,
          source TEXT NOT NULL,
          first_seen INTEGER NOT NULL,
          last_seen INTEGER NOT NULL,
          expires_at INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          note TEXT NOT NULL DEFAULT '',
          UNIQUE(source, url)
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_reputation_ip_enabled ON reputation_ip_entry(enabled, source, kind)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_reputation_domain_enabled ON reputation_domain_entry(enabled, source, kind)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_reputation_url_enabled ON reputation_url_entry(enabled, source, kind)")
    con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


def upsert_entry(con: sqlite3.Connection, table: str, source: str,
                 row: dict[str, Any], now: int, expires_at: int) -> str:
    if table == "ip":
        existing = con.execute(
            """
            SELECT kind, severity, confidence, expires_at, enabled, note
            FROM reputation_ip_entry WHERE source=? AND value=?
            """,
            (source, row["value"]),
        ).fetchone()
        desired = (row["kind"], row["severity"], row["confidence"], expires_at, 1, row["note"])
        if existing is None:
            con.execute(
                """
                INSERT INTO reputation_ip_entry(
                  value, family, prefix_len, kind, severity, confidence, source,
                  first_seen, last_seen, expires_at, enabled, note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    row["value"], row["family"], row["prefix_len"], row["kind"],
                    row["severity"], row["confidence"], source, now, now, expires_at, row["note"],
                ),
            )
            return "inserted"
        if (
            str(existing[0] or ""), int(existing[1] or 0), float(existing[2] or 0.0),
            int(existing[3] or 0), int(existing[4] or 0), str(existing[5] or "")
        ) == desired:
            return "unchanged"
        con.execute(
            """
            UPDATE reputation_ip_entry
            SET family=?, prefix_len=?, kind=?, severity=?, confidence=?,
                last_seen=?, expires_at=?, enabled=1, note=?
            WHERE source=? AND value=?
            """,
            (
                row["family"], row["prefix_len"], row["kind"], row["severity"],
                row["confidence"], now, expires_at, row["note"], source, row["value"],
            ),
        )
        return "updated"

    if table == "domain":
        existing = con.execute(
            """
            SELECT kind, severity, confidence, expires_at, enabled, note
            FROM reputation_domain_entry WHERE source=? AND domain=?
            """,
            (source, row["value"]),
        ).fetchone()
        desired = (row["kind"], row["severity"], row["confidence"], expires_at, 1, row["note"])
        if existing is None:
            con.execute(
                """
                INSERT INTO reputation_domain_entry(
                  domain, kind, severity, confidence, source, first_seen,
                  last_seen, expires_at, enabled, note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (row["value"], row["kind"], row["severity"], row["confidence"], source, now, now, expires_at, row["note"]),
            )
            return "inserted"
        if (
            str(existing[0] or ""), int(existing[1] or 0), float(existing[2] or 0.0),
            int(existing[3] or 0), int(existing[4] or 0), str(existing[5] or "")
        ) == desired:
            return "unchanged"
        con.execute(
            """
            UPDATE reputation_domain_entry
            SET kind=?, severity=?, confidence=?, last_seen=?,
                expires_at=?, enabled=1, note=?
            WHERE source=? AND domain=?
            """,
            (row["kind"], row["severity"], row["confidence"], now, expires_at, row["note"], source, row["value"]),
        )
        return "updated"

    existing = con.execute(
        """
        SELECT domain, kind, severity, confidence, expires_at, enabled, note
        FROM reputation_url_entry WHERE source=? AND url=?
        """,
        (source, row["value"]),
    ).fetchone()
    desired = (row["domain"], row["kind"], row["severity"], row["confidence"], expires_at, 1, row["note"])
    if existing is None:
        con.execute(
            """
            INSERT INTO reputation_url_entry(
              url, domain, kind, severity, confidence, source, first_seen,
              last_seen, expires_at, enabled, note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (row["value"], row["domain"], row["kind"], row["severity"], row["confidence"], source, now, now, expires_at, row["note"]),
        )
        return "inserted"
    if (
        str(existing[0] or ""), str(existing[1] or ""), int(existing[2] or 0),
        float(existing[3] or 0.0), int(existing[4] or 0), int(existing[5] or 0),
        str(existing[6] or "")
    ) == desired:
        return "unchanged"
    con.execute(
        """
        UPDATE reputation_url_entry
        SET domain=?, kind=?, severity=?, confidence=?, last_seen=?,
            expires_at=?, enabled=1, note=?
        WHERE source=? AND url=?
        """,
        (row["domain"], row["kind"], row["severity"], row["confidence"], now, expires_at, row["note"], source, row["value"]),
    )
    return "updated"


def apply_import(args: argparse.Namespace, rows: list[dict[str, Any]]) -> dict[str, int]:
    now = int(time.time())
    expires_at = now + args.ttl_days * 86400 if args.ttl_days > 0 else 0
    stats = {"inserted": 0, "updated": 0, "unchanged": 0, "changed": 0, "total": 0}
    con = sqlite3.connect(args.db)
    try:
        con.execute("BEGIN IMMEDIATE")
        ensure_schema(con)
        if args.replace:
            con.execute("DELETE FROM reputation_ip_entry WHERE source=?", (args.source,))
            con.execute("DELETE FROM reputation_domain_entry WHERE source=?", (args.source,))
            con.execute("DELETE FROM reputation_url_entry WHERE source=?", (args.source,))
        con.execute(
            """
            INSERT INTO reputation_source(
              source, kind, description, default_severity, default_confidence, enabled, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(source) DO UPDATE SET
              kind=excluded.kind,
              description=excluded.description,
              default_severity=excluded.default_severity,
              default_confidence=excluded.default_confidence,
              enabled=1,
              updated_at=excluded.updated_at
            """,
            (args.source, args.kind, args.description, args.severity, args.confidence, now),
        )
        for row in rows:
            result = upsert_entry(con, row["table"], args.source, row, now, expires_at)
            stats[result] += 1
        stats["changed"] = stats["inserted"] + stats["updated"]
        stats["total"] = int(con.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM reputation_ip_entry) +
              (SELECT COUNT(*) FROM reputation_domain_entry) +
              (SELECT COUNT(*) FROM reputation_url_entry)
            """
        ).fetchone()[0])
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"reputation.{args.source}.updated_at", str(now)),
        )
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"reputation.{args.source}.rows", str(len(rows))),
        )
        con.commit()
        return stats
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--kind", default="threat")
    parser.add_argument("--description", default="")
    parser.add_argument("--severity", type=int, default=50)
    parser.add_argument("--confidence", type=float, default=70.0)
    parser.add_argument("--ttl-days", type=int, default=0)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"DB not found: {args.db}")
    for path in args.input:
        if not path.is_file():
            parser.error(f"input not found: {path}")
    if args.severity < 0 or args.severity > 100:
        parser.error("--severity must be between 0 and 100")
    if args.confidence < 0 or args.confidence > 100:
        parser.error("--confidence must be between 0 and 100")
    if args.ttl_days < 0:
        parser.error("--ttl-days must be >= 0")
    args.kind = normalize_kind(args.kind, "threat")

    rows, stats = parse_inputs(args)
    result = {"inserted": 0, "updated": 0, "unchanged": 0, "changed": 0, "total": 0}
    if args.apply:
        result = apply_import(args, rows)

    print(f"db={args.db}")
    print(f"source={args.source} kind={args.kind}")
    print(
        "files={files} lines={lines} ip={ip} domain={domain} url={url} duplicates={duplicates} invalid={invalid}".format(**stats)
    )
    print(
        "mode={} rows={} inserted={inserted} updated={updated} unchanged={unchanged} changed={changed} total={total}".format(
            "apply" if args.apply else "dry-run",
            len(rows),
            **result,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
