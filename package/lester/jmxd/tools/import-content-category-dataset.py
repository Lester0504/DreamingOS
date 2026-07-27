#!/usr/bin/env python3
"""Import content category/domain datasets into dreamingwrt_signatures.db."""

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


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]{0,62}$")
BAD_TOKENS = {"localhost", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}
DOMAIN_KEYS = ("domain", "hostname", "host", "value", "indicator", "name")
CATEGORY_KEYS = ("category", "category_code", "code", "type", "classification")
NAME_KEYS = ("name", "label", "title", "display_name", "category_name")
DESC_KEYS = ("description", "desc", "note")


def slugify(raw: Any, default: str = "") -> str:
    text = str(raw or default).strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or default


def normalize_text(raw: Any) -> str:
    return " ".join(str(raw or "").replace("\t", " ").split()).strip()


def pick(row: dict[str, Any], keys: tuple[str, ...]) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        if key in lowered and lowered[key] not in (None, ""):
            return lowered[key]
    return None


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


def normalize_domain(raw: Any) -> str | None:
    text = str(raw or "").strip().lower()
    if not text or text.startswith(("#", ";", "!", "//")):
        return None
    for marker in (" #", "\t#", " ;", "\t;"):
        if marker in text:
            text = text.split(marker, 1)[0].strip()
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
    if ":" in text or not text or text in BAD_TOKENS:
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.match(text):
        return None
    return text


def parse_category_csv(path: Path, args: argparse.Namespace) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    categories: dict[str, dict[str, Any]] = {}
    stats = {"rows": 0, "invalid": 0, "duplicates": 0}
    with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample) if "," in sample or "\t" in sample else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            return categories, stats
        fields = {str(f).strip().lower() for f in reader.fieldnames}
        if not fields.intersection(CATEGORY_KEYS):
            return categories, stats
        for row in reader:
            stats["rows"] += 1
            slug = slugify(pick(row, CATEGORY_KEYS))
            if not slug:
                stats["invalid"] += 1
                continue
            if slug in categories:
                stats["duplicates"] += 1
                continue
            categories[slug] = {
                "slug": slug,
                "name": normalize_text(pick(row, NAME_KEYS)) or slug.replace("_", " ").title(),
                "description": normalize_text(pick(row, DESC_KEYS)),
                "source": normalize_text(row.get("source")) or args.source,
                "enabled": normalize_bool(row.get("enabled"), 1),
            }
    return categories, stats


def flatten_json(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("categories", "items", "rows", "data", "domains"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        if all(isinstance(v, dict) for v in data.values()):
            out = []
            for key, value in data.items():
                row = dict(value)
                row.setdefault("category", key)
                out.append(row)
            return out
    return []


def parse_category_json(path: Path, args: argparse.Namespace) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    categories: dict[str, dict[str, Any]] = {}
    stats = {"rows": 0, "invalid": 0, "duplicates": 0}
    for row in flatten_json(raw):
        stats["rows"] += 1
        slug = slugify(pick(row, CATEGORY_KEYS))
        if not slug:
            stats["invalid"] += 1
            continue
        if slug in categories:
            stats["duplicates"] += 1
            continue
        categories[slug] = {
            "slug": slug,
            "name": normalize_text(pick(row, NAME_KEYS)) or slug.replace("_", " ").title(),
            "description": normalize_text(pick(row, DESC_KEYS)),
            "source": normalize_text(row.get("source")) or args.source,
            "enabled": normalize_bool(row.get("enabled"), 1),
        }
    return categories, stats


def load_categories(args: argparse.Namespace) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    out: dict[str, dict[str, Any]] = {}
    stats = {"files": 0, "rows": 0, "invalid": 0, "duplicates": 0}
    for path in args.category_codes:
        stats["files"] += 1
        if path.suffix.lower() == ".json":
            categories, local = parse_category_json(path, args)
        else:
            categories, local = parse_category_csv(path, args)
        stats["rows"] += local["rows"]
        stats["invalid"] += local["invalid"]
        stats["duplicates"] += local["duplicates"]
        for slug, category in categories.items():
            if slug in out:
                stats["duplicates"] += 1
                continue
            out[slug] = category
    return out, stats


def parse_domain_csv(path: Path, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
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
            return parse_domain_text(path, args)
        fields = {str(f).strip().lower() for f in reader.fieldnames}
        if not fields.intersection(DOMAIN_KEYS):
            return parse_domain_text(path, args)
        for row in reader:
            stats["lines"] += 1
            domain = normalize_domain(pick(row, DOMAIN_KEYS))
            category = slugify(pick(row, CATEGORY_KEYS), args.category)
            if not domain or not category:
                stats["invalid"] += 1
                continue
            rows.append({
                "domain": domain,
                "category": category,
                "source": normalize_text(row.get("source")) or args.source,
                "confidence": clamp_float(row.get("confidence"), args.confidence, 0.0, 100.0),
                "enabled": normalize_bool(row.get("enabled"), 1),
                "note": normalize_text(pick(row, DESC_KEYS)),
            })
    return rows, stats


def parse_domain_json(path: Path, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    stats = {"lines": 0, "invalid": 0}
    for row in flatten_json(raw):
        stats["lines"] += 1
        domain = normalize_domain(pick(row, DOMAIN_KEYS))
        category = slugify(pick(row, CATEGORY_KEYS), args.category)
        if not domain or not category:
            stats["invalid"] += 1
            continue
        rows.append({
            "domain": domain,
            "category": category,
            "source": normalize_text(row.get("source")) or args.source,
            "confidence": clamp_float(row.get("confidence"), args.confidence, 0.0, 100.0),
            "enabled": normalize_bool(row.get("enabled"), 1),
            "note": normalize_text(pick(row, DESC_KEYS)),
        })
    return rows, stats


def parse_domain_text(path: Path, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    stats = {"lines": 0, "invalid": 0}
    category = slugify(args.category)
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            stats["lines"] += 1
            domain = normalize_domain(raw)
            if not domain or not category:
                stats["invalid"] += 1
                continue
            rows.append({
                "domain": domain,
                "category": category,
                "source": args.source,
                "confidence": args.confidence,
                "enabled": 1,
                "note": "",
            })
    return rows, stats


def clamp_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        out = float(str(value).strip())
    except (TypeError, ValueError):
        out = default
    return max(low, min(high, out))


def load_domains(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, int]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    stats = {"files": 0, "lines": 0, "accepted": 0, "duplicates": 0, "invalid": 0}
    for path in args.input:
        stats["files"] += 1
        if path.suffix.lower() == ".json":
            rows, local = parse_domain_json(path, args)
        elif path.suffix.lower() == ".csv":
            rows, local = parse_domain_csv(path, args)
        else:
            rows, local = parse_domain_text(path, args)
        stats["lines"] += local["lines"]
        stats["invalid"] += local["invalid"]
        for row in rows:
            key = (row["category"], row["domain"])
            if key in seen:
                stats["duplicates"] += 1
                continue
            seen.add(key)
            stats["accepted"] += 1
            out.append(row)
    out.sort(key=lambda item: (item["category"], item["domain"]))
    return out, stats


def ensure_schema(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS content_category (
          category TEXT PRIMARY KEY,
          name TEXT NOT NULL DEFAULT '',
          description TEXT NOT NULL DEFAULT '',
          source TEXT NOT NULL DEFAULT 'dreamingwrt',
          enabled INTEGER NOT NULL DEFAULT 1,
          updated_at INTEGER NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS content_domain_entry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          category TEXT NOT NULL,
          source TEXT NOT NULL DEFAULT 'dreamingwrt',
          confidence REAL NOT NULL DEFAULT 70,
          enabled INTEGER NOT NULL DEFAULT 1,
          note TEXT NOT NULL DEFAULT '',
          updated_at INTEGER NOT NULL,
          UNIQUE(category, domain)
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_content_domain_enabled ON content_domain_entry(enabled, category)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_content_domain_lookup ON content_domain_entry(domain)")
    con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


def apply_import(args: argparse.Namespace, categories: dict[str, dict[str, Any]],
                 rows: list[dict[str, Any]]) -> dict[str, int]:
    now = int(time.time())
    result = {
        "categories_inserted": 0,
        "categories_updated": 0,
        "categories_unchanged": 0,
        "domains_inserted": 0,
        "domains_updated": 0,
        "domains_unchanged": 0,
        "domains_total": 0,
        "categories_total": 0,
    }
    con = sqlite3.connect(args.db)
    try:
        con.execute("BEGIN IMMEDIATE")
        ensure_schema(con)
        if args.replace:
            con.execute("DELETE FROM content_domain_entry WHERE source=?", (args.source,))
        referenced = {row["category"] for row in rows}
        for category in sorted(referenced):
            categories.setdefault(category, {
                "slug": category,
                "name": category.replace("_", " ").title(),
                "description": "",
                "source": args.source,
                "enabled": 1,
            })
        for slug, category in sorted(categories.items()):
            existing = con.execute(
                "SELECT name, description, source, enabled FROM content_category WHERE category=?",
                (slug,),
            ).fetchone()
            desired = (
                normalize_text(category.get("name")),
                normalize_text(category.get("description")),
                normalize_text(category.get("source")) or args.source,
                normalize_bool(category.get("enabled"), 1),
            )
            if existing is None:
                con.execute(
                    """
                    INSERT INTO content_category(category, name, description, source, enabled, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (slug,) + desired + (now,),
                )
                result["categories_inserted"] += 1
            elif (
                str(existing[0] or ""), str(existing[1] or ""),
                str(existing[2] or ""), int(existing[3] or 0)
            ) == desired:
                result["categories_unchanged"] += 1
            else:
                con.execute(
                    """
                    UPDATE content_category
                    SET name=?, description=?, source=?, enabled=?, updated_at=?
                    WHERE category=?
                    """,
                    desired + (now, slug),
                )
                result["categories_updated"] += 1
        for row in rows:
            existing = con.execute(
                """
                SELECT source, confidence, enabled, note
                FROM content_domain_entry WHERE category=? AND domain=?
                """,
                (row["category"], row["domain"]),
            ).fetchone()
            desired = (
                row["source"],
                row["confidence"],
                row["enabled"],
                row["note"],
            )
            if existing is None:
                con.execute(
                    """
                    INSERT INTO content_domain_entry(
                      domain, category, source, confidence, enabled, note, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["domain"], row["category"], row["source"], row["confidence"],
                        row["enabled"], row["note"], now,
                    ),
                )
                result["domains_inserted"] += 1
            elif (
                str(existing[0] or ""), float(existing[1] or 0.0),
                int(existing[2] or 0), str(existing[3] or "")
            ) == desired:
                result["domains_unchanged"] += 1
            else:
                con.execute(
                    """
                    UPDATE content_domain_entry
                    SET source=?, confidence=?, enabled=?, note=?, updated_at=?
                    WHERE category=? AND domain=?
                    """,
                    (
                        row["source"], row["confidence"], row["enabled"], row["note"],
                        now, row["category"], row["domain"],
                    ),
                )
                result["domains_updated"] += 1
        result["categories_total"] = int(con.execute("SELECT COUNT(*) FROM content_category").fetchone()[0])
        result["domains_total"] = int(con.execute("SELECT COUNT(*) FROM content_domain_entry").fetchone()[0])
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"content.{args.source}.updated_at", str(now)),
        )
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"content.{args.source}.domains", str(len(rows))),
        )
        con.commit()
        return result
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--category-codes", type=Path, action="append", default=[])
    parser.add_argument("--category", default="")
    parser.add_argument("--source", required=True)
    parser.add_argument("--confidence", type=float, default=70.0)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"DB not found: {args.db}")
    for path in args.input:
        if not path.is_file():
            parser.error(f"input not found: {path}")
    for path in args.category_codes:
        if not path.is_file():
            parser.error(f"category codes not found: {path}")
    if args.confidence < 0 or args.confidence > 100:
        parser.error("--confidence must be between 0 and 100")
    if not args.category and not args.category_codes:
        parser.error("--category is required when no category field/category-codes are provided")
    args.category = slugify(args.category)

    categories, category_stats = load_categories(args)
    rows, domain_stats = load_domains(args)
    result = {
        "categories_inserted": 0,
        "categories_updated": 0,
        "categories_unchanged": 0,
        "domains_inserted": 0,
        "domains_updated": 0,
        "domains_unchanged": 0,
        "domains_total": 0,
        "categories_total": 0,
    }
    if args.apply:
        result = apply_import(args, categories, rows)

    print(f"db={args.db}")
    print(f"source={args.source}")
    print(
        "category_files={files} category_rows={rows} category_invalid={invalid} category_duplicates={duplicates}".format(**category_stats)
    )
    print(
        "domain_files={files} domain_lines={lines} accepted={accepted} duplicates={duplicates} invalid={invalid}".format(**domain_stats)
    )
    print(
        "mode={} rows={} categories={} categories_inserted={} categories_updated={} categories_unchanged={} domains_inserted={} domains_updated={} domains_unchanged={} domains_total={}".format(
            "apply" if args.apply else "dry-run",
            len(rows),
            len(categories),
            result["categories_inserted"],
            result["categories_updated"],
            result["categories_unchanged"],
            result["domains_inserted"],
            result["domains_updated"],
            result["domains_unchanged"],
            result["domains_total"],
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
