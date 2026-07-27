#!/usr/bin/env python3
"""Report app icon mapping and asset gaps without modifying the database."""

from __future__ import annotations

import argparse
import csv
import re
import sqlite3
import unicodedata
from pathlib import Path


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").casefold()
    return re.sub(r"[^0-9a-z\u3400-\u9fff]+", "", value)


def candidates(name: str, files: list[Path]) -> list[str]:
    target = normalize(name)
    ascii_tokens = [token.casefold() for token in re.findall(r"[A-Za-z0-9]+", name)
                    if len(token) >= 4]
    exact: list[str] = []
    related: list[str] = []
    for path in files:
        stem = path.stem
        normalized_stem = normalize(stem)
        if normalized_stem == target:
            exact.append(path.name)
        elif any(token in stem.casefold() for token in ascii_tokens):
            related.append(path.name)
    return sorted(dict.fromkeys(exact + related))[:8]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--icons", type=Path, required=True)
    parser.add_argument("--extra-icons", type=Path)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    roots = [args.icons]
    if args.extra_icons:
        roots.append(args.extra_icons)
    files_by_root = {
        str(root): sorted(path for path in root.glob("*") if path.is_file())
        for root in roots
    }
    conn = sqlite3.connect(f"file:{args.database}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT a.app_id,a.name,COALESCE(a.family,''),COALESCE(a.category_id,99),"
        "COALESCE(a.batch,''),COALESCE(i.icon_key,''),COALESCE(x.icon_file,'') "
        "FROM app a LEFT JOIN app_icon i ON i.app_id=a.app_id "
        "LEFT JOIN icon_asset x ON x.icon_key=i.icon_key ORDER BY a.app_id"
    ).fetchall()
    conn.close()

    gaps: list[dict[str, str | int]] = []
    for app_id, name, family, category_id, batch, icon_key, icon_file in rows:
        expected_name = Path(icon_file).name if icon_file else ""
        present = bool(expected_name and (args.icons / expected_name).is_file())
        if icon_key and present:
            continue
        repo_candidates = candidates(name, files_by_root[str(args.icons)])
        extra_candidates = (candidates(name, files_by_root[str(args.extra_icons)])
                            if args.extra_icons else [])
        status = "unmapped" if not icon_key else "mapped_asset_missing"
        gaps.append({
            "app_id": app_id,
            "name": name,
            "family": family,
            "category_id": category_id,
            "batch": batch,
            "status": status,
            "icon_key": icon_key,
            "expected_file": expected_name,
            "repo_candidates": ";".join(repo_candidates),
            "extra_candidates": ";".join(extra_candidates),
            "review": "manual_required" if repo_candidates or extra_candidates else "asset_required",
        })

    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(gaps[0]) if gaps else ["app_id"])
        writer.writeheader()
        writer.writerows(gaps)

    unmapped = sum(row["status"] == "unmapped" for row in gaps)
    missing = sum(row["status"] == "mapped_asset_missing" for row in gaps)
    candidates_count = sum(row["review"] == "manual_required" for row in gaps)
    lines = [
        "# DreamingWrt app icon gap report",
        "",
        f"- Database: `{args.database}`",
        f"- Primary icon directory: `{args.icons}`",
        f"- Apps without `app_icon` mapping: **{unmapped}**",
        f"- Existing mappings whose files are missing: **{missing}**",
        f"- Rows with filename candidates requiring manual review: **{candidates_count}**",
        f"- Total gaps: **{len(gaps)}**",
        "",
        "Candidates are evidence only. This report never writes `app_icon` or `icon_asset`.",
        "",
        "| app_id | name | family | status | expected | candidates |",
        "|---:|---|---|---|---|---|",
    ]
    for row in gaps:
        candidate_text = row["repo_candidates"] or row["extra_candidates"] or "-"
        lines.append(
            f"| {row['app_id']} | {str(row['name']).replace('|', '/')} | "
            f"{row['family']} | {row['status']} | {row['expected_file'] or '-'} | "
            f"{candidate_text} |"
        )
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"gaps={len(gaps)} unmapped={unmapped} mapped_asset_missing={missing} "
          f"manual_candidates={candidates_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
