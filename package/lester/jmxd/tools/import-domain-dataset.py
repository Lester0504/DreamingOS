#!/usr/bin/env python3
"""Import domain content/reputation datasets into dreamingwrt_signatures.db."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sqlite3
import sys
import time
from pathlib import Path


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]{0,62}$")
BAD_TOKENS = {"localhost", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}


def normalize_domain(raw: str) -> str | None:
    text = raw.strip().lower()
    if not text or text.startswith(("!", "#", "//", ";")):
        return None
    text = text.split("#", 1)[0].split(";", 1)[0].strip()
    if not text:
        return None

    if text.startswith(("0.0.0.0 ", "127.0.0.1 ", "::1 ")):
        parts = text.split()
        text = parts[1] if len(parts) > 1 else ""
    elif " " in text or "\t" in text:
        parts = text.split()
        if parts and looks_like_ip(parts[0]) and len(parts) > 1:
            text = parts[1]
        else:
            text = parts[0]

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
    if ":" in text:
        return None
    if text in BAD_TOKENS:
        return None
    if looks_like_ip(text):
        return None
    if not DOMAIN_RE.match(text):
        return None
    return text


def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def iter_domains(paths: list[Path]) -> tuple[list[str], dict[str, int]]:
    domains: set[str] = set()
    stats = {"lines": 0, "accepted": 0, "duplicates": 0, "invalid": 0}

    for path in paths:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                stats["lines"] += 1
                domain = normalize_domain(line)
                if not domain:
                    stats["invalid"] += 1
                    continue
                if domain in domains:
                    stats["duplicates"] += 1
                    continue
                domains.add(domain)
                stats["accepted"] += 1
    return sorted(domains), stats


def ensure_group(con: sqlite3.Connection, category: str, subcategory: str,
                 source: str, now: int) -> int:
    sort_key = f"{category}|{subcategory}"
    con.execute(
        """
        INSERT INTO domain_group(category, subcategory, source, sort_key, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(category, subcategory) DO UPDATE SET
          source=excluded.source,
          sort_key=excluded.sort_key,
          updated_at=excluded.updated_at
        """,
        (category, subcategory, source, sort_key, now),
    )
    row = con.execute(
        "SELECT group_id FROM domain_group WHERE category=? AND subcategory=?",
        (category, subcategory),
    ).fetchone()
    if not row:
        raise RuntimeError("domain_group upsert failed")
    return int(row[0])


def apply_import(args: argparse.Namespace, domains: list[str]) -> dict[str, int]:
    now = int(time.time())
    con = sqlite3.connect(args.db)
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("BEGIN IMMEDIATE")
        group_id = ensure_group(con, args.category, args.subcategory, args.source, now)
        if args.replace:
            con.execute("DELETE FROM domain_entry WHERE group_id=?", (group_id,))
        inserted = 0
        updated = 0
        for domain in domains:
            before = con.total_changes
            con.execute(
                """
                INSERT INTO domain_entry(domain, group_id, remark, source, sort_key, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                  group_id=excluded.group_id,
                  remark=excluded.remark,
                  source=excluded.source,
                  sort_key=excluded.sort_key,
                  updated_at=excluded.updated_at
                """,
                (domain, group_id, args.remark, args.source, domain, now),
            )
            if con.total_changes > before:
                inserted += 1
            else:
                updated += 1
        con.execute(
            """
            INSERT INTO meta(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"domain_dataset.{args.source}.{args.category}.{args.subcategory}.updated_at", str(now)),
        )
        con.commit()
        return {"group_id": group_id, "written": len(domains), "changed": inserted + updated}
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--subcategory", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--remark", default="")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not args.db.is_file():
        parser.error(f"DB not found: {args.db}")
    for path in args.input:
        if not path.is_file():
            parser.error(f"input not found: {path}")

    domains, stats = iter_domains(args.input)
    result: dict[str, int] = {"group_id": 0, "written": 0, "changed": 0}
    if args.apply:
        result = apply_import(args, domains)

    print(f"db={args.db}")
    print(f"group={args.category}/{args.subcategory}")
    print(f"source={args.source}")
    print(f"lines={stats['lines']} accepted={stats['accepted']} duplicates={stats['duplicates']} invalid={stats['invalid']}")
    print(f"mode={'apply' if args.apply else 'dry-run'} domains={len(domains)} written={result['written']} changed={result['changed']} group_id={result['group_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
