#!/usr/bin/env python3
"""Report database-backed app/vendor logo gaps without modifying runtime data."""

from __future__ import annotations

import argparse
import csv
import re
import sqlite3
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path


FIELDS = [
    "kind", "id", "name", "expected_icon", "current_icon", "status",
    "reason", "source_table", "priority",
]


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").casefold()
    return re.sub(r"[^0-9a-z\u3400-\u9fff]+", "", value)


def basename(value: str) -> str:
    return Path(value or "").name


def priority(references: int, kind: str) -> str:
    if kind == "brand":
        if references >= 100:
            return "P0"
        if references >= 20:
            return "P1"
        if references >= 5:
            return "P2"
        return "P3"
    if references >= 10:
        return "P0"
    if references >= 4:
        return "P1"
    if references >= 1:
        return "P2"
    return "P3"


def load_suggestions(path: Path | None) -> dict[tuple[str, str], str]:
    suggestions: dict[tuple[str, str], str] = {}
    if not path or not path.is_file():
        return suggestions
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            expected = row.get("expected_icon", "").strip()
            if expected:
                suggestions[(row.get("kind", ""), row.get("id", ""))] = expected
    return suggestions


def unique_candidate(
    name: str,
    expected: str,
    files: set[str],
    files_by_stem: dict[str, list[str]],
) -> str:
    if expected and expected in files:
        return expected
    matches = files_by_stem.get(normalize(name), [])
    return matches[0] if len(matches) == 1 else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--logo-dir", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--suggestions-csv", type=Path)
    args = parser.parse_args()

    suggestions = load_suggestions(args.suggestions_csv)
    files = {path.name for path in args.logo_dir.iterdir() if path.is_file()}
    files_by_stem: dict[str, list[str]] = defaultdict(list)
    for filename in sorted(files):
        files_by_stem[normalize(Path(filename).stem)].append(filename)

    con = sqlite3.connect(f"file:{args.database}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows: list[dict[str, str | int]] = []
    ready = Counter()

    vendors = con.execute(
        "SELECT v.vendor_id,v.name,COALESCE(v.logo_key,'') logo_key,"
        "COALESCE(ia.icon_file,'') icon_file,"
        "COUNT(r.rule_id) references_count "
        "FROM device_vendor v "
        "LEFT JOIN icon_asset ia ON ia.icon_key=v.logo_key "
        "LEFT JOIN device_fingerprint_rule r ON r.vendor_id=v.vendor_id AND r.enabled=1 "
        "GROUP BY v.vendor_id ORDER BY v.vendor_id"
    ).fetchall()
    for row in vendors:
        item_id = str(row["vendor_id"])
        current = basename(row["icon_file"])
        expected = current or suggestions.get(("brand", item_id), "")
        candidate = unique_candidate(row["name"], expected, files, files_by_stem)
        refs = int(row["references_count"])
        if normalize(row["name"]) in {"未知", "未知厂商", "unknown", "unknownvendor"}:
            rows.append({
                "kind": "brand", "id": item_id, "name": row["name"],
                "expected_icon": "", "current_icon": current,
                "status": "not_applicable",
                "reason": "generic unknown-vendor bucket intentionally has no brand logo",
                "source_table": "device_vendor", "priority": "P3",
            })
            continue
        if row["logo_key"] and current in files:
            ready["brand"] += 1
            continue
        if row["logo_key"]:
            status = "mapped_asset_missing"
            reason = f"logo_key={row['logo_key']} points to missing file {current or '(empty)'}; {refs} enabled fingerprint rules"
        elif candidate:
            status = "asset_present_mapping_missing"
            current = candidate
            expected = candidate
            reason = f"physical asset exists but device_vendor.logo_key is empty; {refs} enabled fingerprint rules"
        else:
            status = "missing_icon"
            expected = expected or f"vendor-{item_id}.svg"
            reason = f"no database mapping or defensible exact physical asset; {refs} enabled fingerprint rules"
        rows.append({
            "kind": "brand", "id": item_id, "name": row["name"],
            "expected_icon": expected, "current_icon": current,
            "status": status, "reason": reason,
            "source_table": "device_vendor;icon_asset;device_fingerprint_rule",
            "priority": priority(refs, "brand"),
        })

    apps = con.execute(
        "SELECT a.app_id,a.name,COALESCE(ai.icon_key,'') icon_key,"
        "COALESCE(ia.icon_file,'') icon_file,COUNT(r.rule_id) references_count "
        "FROM app a LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
        "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
        "LEFT JOIN dpi_rule r ON r.app_id=a.app_id AND r.enabled=1 "
        "WHERE a.enabled=1 GROUP BY a.app_id ORDER BY a.app_id"
    ).fetchall()
    for row in apps:
        item_id = str(row["app_id"])
        current = basename(row["icon_file"])
        expected = current or suggestions.get(("app", item_id), "")
        candidate = unique_candidate(row["name"], expected, files, files_by_stem)
        refs = int(row["references_count"])
        if row["icon_key"] and current in files:
            ready["app"] += 1
            continue
        if row["icon_key"]:
            status = "mapped_asset_missing"
            reason = f"icon_key={row['icon_key']} points to missing file {current or '(empty)'}; {refs} enabled DPI rules"
        elif candidate:
            status = "asset_present_mapping_missing"
            current = candidate
            expected = candidate
            reason = f"physical asset exists but app_icon row is absent; {refs} enabled DPI rules"
        else:
            status = "missing_icon_and_mapping"
            expected = expected or f"app-{item_id}.png"
            reason = f"no app_icon row or defensible exact physical asset; {refs} enabled DPI rules"
        rows.append({
            "kind": "app", "id": item_id, "name": row["name"],
            "expected_icon": expected, "current_icon": current,
            "status": status, "reason": reason,
            "source_table": "app;app_icon;icon_asset;dpi_rule",
            "priority": priority(refs, "app"),
        })

    referenced_files = {
        basename(row[0]) for row in con.execute(
            "SELECT icon_file FROM icon_asset WHERE COALESCE(icon_file,'')<>''"
        )
    }
    for filename in sorted(files - referenced_files):
        rows.append({
            "kind": "asset", "id": filename, "name": filename,
            "expected_icon": filename, "current_icon": filename,
            "status": "orphan_asset",
            "reason": "physical file has no icon_asset row",
            "source_table": "filesystem;icon_asset", "priority": "P3",
        })
    con.close()

    rows.sort(key=lambda row: (
        {"P0": 0, "P1": 1, "P2": 2, "P3": 3}[str(row["priority"])],
        {"brand": 0, "app": 1, "asset": 2}[str(row["kind"])],
        str(row["name"]),
    ))
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    status_counts = Counter(str(row["status"]) for row in rows)
    action_rows = [
        row for row in rows
        if row["priority"] in ("P0", "P1") and row["kind"] in ("brand", "app")
    ]
    lines = [
        "# DreamingWrt Logo 数据库缺口审计（2026-07-13）",
        "",
        "## 结论",
        "",
        f"- 唯一映射源：`{args.database}`。",
        f"- 统一物理目录：`{args.logo_dir}`。",
        f"- 已就绪品牌：**{ready['brand']}**；已就绪应用：**{ready['app']}**。",
        f"- 缺口/待复核行：**{len(rows)}**；物理孤儿资产：**{status_counts['orphan_asset']}**。",
        "- 本报告不生成 JSON、不写数据库；`device_vendor.logo_key` 和 `app_icon.icon_key` 是运行合同。",
        "",
        "## 状态统计",
        "",
        "| status | rows |",
        "|---|---:|",
    ]
    for status, count in sorted(status_counts.items()):
        lines.append(f"| `{status}` | {count} |")
    lines.extend([
        "",
        "## P0/P1 待办",
        "",
        "| priority | kind | id | name | status | expected/current |",
        "|---|---|---:|---|---|---|",
    ])
    for row in action_rows:
        filename = row["current_icon"] or row["expected_icon"] or "-"
        lines.append(
            f"| {row['priority']} | {row['kind']} | {row['id']} | "
            f"{str(row['name']).replace('|', '/')} | `{row['status']}` | `{filename}` |"
        )
    lines.extend([
        "",
        "## JSON 边界",
        "",
        "- Logo 归属不使用 `icon_map.json`、`vendor-logo-map.json` 或其他派生映射 JSON。",
        "- `fingerprint.db` 是设备图库权威索引，不参与 app/vendor Logo 归属。",
        "",
        f"完整逐项证据见 `{args.csv.name}`。",
    ])
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"ready_brands={ready['brand']} ready_apps={ready['app']} "
        f"gap_rows={len(rows)} orphan_assets={status_counts['orphan_asset']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
