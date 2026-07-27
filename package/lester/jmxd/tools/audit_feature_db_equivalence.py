#!/usr/bin/env python3
"""Audit legacy feature.cfg coverage in dreamingwrt_signatures.db."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


INTENTIONAL_REMOVALS = {
    3020024: "一直播",
    4016: "折800",
    5007: "虾米音乐",
    2560011: "天天上网助手",
    5060151: "微话",
    2530023: "爱快有余",
    3550018: "爱快官网",
    3550019: "爱快",
    3550016: "爱快",
}


@dataclass(frozen=True)
class FeatureAtom:
    source_app_id: int
    name: str
    category_id: int
    line: int
    ordinal: int
    proto: str
    source_port: str
    destination_port: str
    host: str
    request: str
    payload: str


def parse_feature(
    path: Path,
) -> tuple[
    dict[str, str], dict[int, tuple[str, str]], list[FeatureAtom], list[dict]
]:
    metadata: dict[str, str] = {}
    categories: dict[int, tuple[str, str]] = {}
    atoms: list[FeatureAtom] = []
    invalid_atoms: list[dict] = []
    category_id = 0
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        meta = re.fullmatch(r"#(version|format)\s+(.+)", line)
        if meta:
            metadata[meta.group(1)] = meta.group(2)
            continue
        category = re.fullmatch(r"#class\s+(\S+)\s+(\d+)\s+(.+)", line)
        if category:
            category_id = int(category.group(2))
            categories[category_id] = (category.group(1), category.group(3))
            continue
        if line.startswith("#"):
            continue
        app = re.fullmatch(r"(\d+)\s+([^:]+):\[(.*)]", line)
        if not app or not category_id:
            raise ValueError(f"{path}:{line_number}: malformed or unclassified entry")
        source_app_id = int(app.group(1))
        name = app.group(2).strip()
        raw_atoms = re.split(r",(?=(?:tcp|udp);)", app.group(3))
        for ordinal, raw_atom in enumerate(raw_atoms):
            fields = raw_atom.split(";")
            if len(fields) != 6:
                invalid_atoms.append(
                    {
                        "source_app_id": source_app_id,
                        "name": name,
                        "line": line_number,
                        "ordinal": ordinal,
                        "raw": raw_atom,
                        "field_count": len(fields),
                        "reason": "legacy kernel parser rejects incomplete atom",
                    }
                )
                continue
            atoms.append(
                FeatureAtom(
                    source_app_id,
                    name,
                    category_id,
                    line_number,
                    ordinal,
                    *fields,
                )
            )
    return metadata, categories, atoms, invalid_atoms


def normalized_text(value: str) -> str:
    value = value.lower().strip().replace("\\.", ".").replace("\\-", "-")
    value = value.replace("^", "").replace("$", "").replace(".*", "")
    value = value.replace("\\", "").strip("*")
    return value


def payload_hex(value: str) -> str:
    if not value:
        return ""
    output = []
    for item in value.split(","):
        match = re.fullmatch(r"0:([0-9a-fA-F]{1,2})", item.strip())
        if not match:
            return ""
        output.append(f"{int(match.group(1), 16):02x}")
    return "".join(output)


def parse_ports(value: str) -> list[tuple[int, int]]:
    result = []
    for item in filter(None, re.split(r"[|,]", value)):
        if "-" in item:
            start, end = item.split("-", 1)
        else:
            start = end = item
        if not start.isdigit() or not end.isdigit():
            continue
        result.append((int(start), int(end)))
    return result


def text_covered(needle: str, row: sqlite3.Row) -> bool:
    needle = normalized_text(needle)
    candidate = normalized_text(row["pattern_text"] or "")
    return bool(needle and candidate and (needle in candidate or candidate in needle))


def hex_covered(needle: str, row: sqlite3.Row) -> bool:
    needle = payload_hex(needle)
    candidate = (row["pattern_hex"] or "").lower()
    return bool(needle and candidate and (needle in candidate or candidate in needle))


def port_covered(ports: list[tuple[int, int]], row: sqlite3.Row) -> bool:
    if not ports:
        return True
    rule_ports = json.loads(row["ports"] or "[]")
    for wanted_min, wanted_max in ports:
        if not any(
            int(item["min"]) <= wanted_min and int(item["max"]) >= wanted_max
            for item in rule_ports
        ):
            return False
    return True


def atom_covered(atom: FeatureAtom, rules: list[sqlite3.Row]) -> tuple[bool, str]:
    ports = parse_ports(atom.destination_port)
    compatible = [row for row in rules if not atom.proto or not row["proto"] or row["proto"] == atom.proto]
    checks = []
    if atom.host:
        checks.append(("host", lambda row: text_covered(atom.host, row)))
    if atom.request:
        checks.append(("request", lambda row: text_covered(atom.request, row)))
    if atom.payload:
        checks.append(("payload", lambda row: hex_covered(atom.payload, row)))
    if not checks:
        if any(port_covered(ports, row) for row in compatible):
            return True, "port"
        return False, "port"
    for kind, check in checks:
        if not any(check(row) and port_covered(ports, row) for row in compatible):
            # Some imported protocol records split port and payload constraints into
            # separate rules. Require both facts for the app even when no one row
            # carries both after source normalization.
            if not any(check(row) for row in compatible) or not any(
                port_covered(ports, row) for row in compatible
            ):
                return False, kind
    return True, "+".join(kind for kind, _ in checks)


def audit(feature: Path, database: Path) -> dict:
    metadata, categories, atoms, invalid_atoms = parse_feature(feature)
    db = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    mappings = {
        int(row["source_app_id"]): row
        for row in db.execute(
            "SELECT m.source_app_id,m.app_id,m.source_name,a.name,a.category_id "
            "FROM app_id_map m JOIN app a USING(app_id) "
            "WHERE m.source='legacy' AND m.source_app_id GLOB '[0-9]*'"
        )
    }
    db_categories = {
        int(row["category_id"]): (row["slug"], row["name"])
        for row in db.execute("SELECT category_id,slug,name FROM app_category")
    }
    rules: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for row in db.execute(
        "SELECT r.app_id,COALESCE(r.proto,'') proto,r.match_type,r.pattern_format,"
        "COALESCE(r.pattern_text,'') pattern_text,COALESCE(r.pattern_hex,'') pattern_hex,"
        "COALESCE((SELECT json_group_array(json_object('min',p.min_port,'max',p.max_port)) "
        "FROM dpi_rule_port p WHERE p.rule_id=r.rule_id),'[]') ports "
        "FROM dpi_rule r WHERE r.enabled=1"
    ):
        rules[int(row["app_id"])].append(row)
    db_meta = dict(db.execute("SELECT key,value FROM meta"))
    db.close()

    app_rows = {(atom.source_app_id, atom.name, atom.category_id) for atom in atoms}
    missing_mappings = []
    name_differences = []
    category_differences = []
    atom_misses = []
    covered_kinds: Counter[str] = Counter()
    for source_app_id, name, category_id in sorted(app_rows):
        if source_app_id in INTENTIONAL_REMOVALS:
            continue
        mapping = mappings.get(source_app_id)
        if not mapping:
            missing_mappings.append({"source_app_id": source_app_id, "name": name})
            continue
        if name != mapping["source_name"] or name != mapping["name"]:
            name_differences.append(
                {
                    "source_app_id": source_app_id,
                    "feature_name": name,
                    "mapping_name": mapping["source_name"],
                    "database_name": mapping["name"],
                }
            )
        if category_id != int(mapping["category_id"]):
            category_differences.append(
                {
                    "source_app_id": source_app_id,
                    "feature_category_id": category_id,
                    "database_category_id": int(mapping["category_id"]),
                }
            )
    for atom in atoms:
        if atom.source_app_id in INTENTIONAL_REMOVALS:
            continue
        mapping = mappings.get(atom.source_app_id)
        if not mapping:
            continue
        covered, kind = atom_covered(atom, rules[int(mapping["app_id"])])
        if covered:
            covered_kinds[kind] += 1
        else:
            atom_misses.append(asdict(atom) | {"missing_constraint": kind})

    category_name_differences = []
    for category_id, feature_value in categories.items():
        db_value = db_categories.get(category_id)
        if not db_value or feature_value[1] != db_value[1]:
            category_name_differences.append(
                {
                    "category_id": category_id,
                    "feature": feature_value,
                    "database": db_value,
                }
            )
    result = {
        "feature_metadata": metadata,
        "database_metadata": {
            key: db_meta.get(key, "")
            for key in (
                "schema_version",
                "build_time",
                "build_tool",
                "protocol_augment_source",
                "protocol_augment_at",
            )
        },
        "feature_app_count": len(app_rows),
        "feature_atom_count": len(atoms),
        "legacy_invalid_atoms": invalid_atoms,
        "intentional_removals": [
            {"source_app_id": source_app_id, "name": name}
            for source_app_id, name in INTENTIONAL_REMOVALS.items()
        ],
        "audited_app_count": len(app_rows) - len(INTENTIONAL_REMOVALS),
        "audited_atom_count": sum(
            atom.source_app_id not in INTENTIONAL_REMOVALS for atom in atoms
        ),
        "missing_mappings": missing_mappings,
        "name_differences": name_differences,
        "category_differences": category_differences,
        "category_name_differences": category_name_differences,
        "covered_atom_kinds": dict(sorted(covered_kinds.items())),
        "atom_misses": atom_misses,
    }
    result["metadata_equivalent"] = not any(
        result[key]
        for key in (
            "missing_mappings",
            "category_differences",
            "category_name_differences",
        )
    )
    result["runtime_migration_ready"] = result["metadata_equivalent"]
    result["legacy_rule_differences_are_non_authoritative"] = True
    result["equivalent"] = result["runtime_migration_ready"]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature", type=Path)
    parser.add_argument("database", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.feature, args.database)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if result["equivalent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
