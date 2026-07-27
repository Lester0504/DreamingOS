#!/usr/bin/env python3
"""Audit and incrementally augment a DreamingWrt signature database.

The default mode is report-only. Source IDs are evidence only and are never
used as DreamingWrt primary keys. Existing apps and rules are never replaced.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import sqlite3
import time
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator


SOURCE = "protocol-3.0.23-augment"
METHOD_NAMES = {0: "exact", 1: "regex", 2: "no_fixed", 5: "bm"}
PROTO_NAMES = {0: None, 6: "tcp", 17: "udp"}
DIRECTION_NAMES = {0: None, 1: "original", 2: "reply"}


def normalize_name(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").casefold()
    return re.sub(r"[\s_\-·./\\()（）\[\]【】]+", "", value)


EXPLICIT_ALIASES = {
    normalize_name("腾讯私有协议"): normalize_name("腾讯专用协议"),
    normalize_name("Apple私有协议"): normalize_name("Apple专用协议"),
    normalize_name("360私有协议"): normalize_name("360专用协议"),
    normalize_name("搜狗私有协议"): normalize_name("搜狗专用协议"),
    normalize_name("腾讯手游私有协议"): normalize_name("腾讯手游专用协议"),
    normalize_name("小米游戏私有协议"): normalize_name("小米游戏专用协议"),
    normalize_name("明朝游戏私有协议"): normalize_name("明朝游戏专用协议"),
    normalize_name("叠纸游戏私有协议"): normalize_name("叠纸游戏专用协议"),
    normalize_name("米哈游私有协议"): normalize_name("米哈游专用协议"),
    normalize_name("腾讯游戏私有协议"): normalize_name("腾讯游戏专用协议"),
    normalize_name("盛趣游戏私有协议"): normalize_name("盛趣游戏专用协议"),
    normalize_name("迅雷私有协议"): normalize_name("迅雷专用协议"),
    normalize_name("快车私有协议"): normalize_name("快车专用协议"),
    normalize_name("QQ旋风私有协议"): normalize_name("QQ旋风专用协议"),
    normalize_name("vagaa私有协议"): normalize_name("vagaa专用协议"),
    normalize_name("Grok"): normalize_name("Grok (xAI)"),
}


def semantic_name(value: str) -> str:
    normalized = normalize_name(value)
    return EXPLICIT_ALIASES.get(normalized, normalized)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data) and shift <= 63:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
    raise ValueError("invalid protobuf varint")


def wire_fields(data: bytes) -> Iterator[tuple[int, int, int | bytes]]:
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        field = key >> 3
        wire_type = key & 7
        if not field:
            raise ValueError("invalid protobuf field zero")
        if wire_type == 0:
            value, pos = read_varint(data, pos)
            yield field, wire_type, value
        elif wire_type == 1:
            if pos + 8 > len(data):
                raise ValueError("truncated protobuf fixed64")
            yield field, wire_type, data[pos : pos + 8]
            pos += 8
        elif wire_type == 2:
            size, pos = read_varint(data, pos)
            if pos + size > len(data):
                raise ValueError("truncated protobuf bytes")
            yield field, wire_type, data[pos : pos + size]
            pos += size
        elif wire_type == 5:
            if pos + 4 > len(data):
                raise ValueError("truncated protobuf fixed32")
            yield field, wire_type, data[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")


def first_varint(data: bytes, field_number: int, default: int = 0) -> int:
    for field, wire_type, value in wire_fields(data):
        if field == field_number and wire_type == 0:
            return int(value)
    return default


def all_messages(data: bytes, field_number: int) -> list[bytes]:
    return [bytes(value) for field, wire_type, value in wire_fields(data)
            if field == field_number and wire_type == 2]


@dataclass(frozen=True)
class SourceApp:
    source_id: int
    name: str
    line: int


@dataclass(frozen=True)
class SourceRule:
    source_app_id: int
    proto: int
    direction: int
    pkt_seq: int
    pattern_b64: str
    match_method: int
    offset: int | None
    ports: tuple[tuple[int, int], ...]
    priority: int
    source_rule_id: int
    rule_kind: str = "ik_app"

    def pattern(self) -> bytes:
        try:
            return base64.b64decode(self.pattern_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"invalid base64 payload for source rule {self.source_rule_id}"
            ) from exc

    def runtime_validation_error(self) -> str | None:
        if self.match_method in (0, 5) and not self.pattern():
            return "empty_fixed_payload"
        return None

    def content_key(self, app_name: str) -> str:
        payload = {
            "app": normalize_name(app_name),
            "proto": self.proto,
            "direction": self.direction,
            "pkt_seq": self.pkt_seq,
            "pattern_b64": self.pattern_b64,
            "match_method": self.match_method,
            "offset": self.offset,
            "ports": self.ports,
            "priority": self.priority,
            "rule_kind": self.rule_kind,
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


def parse_protocols(path: Path) -> list[SourceApp]:
    apps: list[SourceApp] = []
    for line_number, line in enumerate(
            path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
        text = line.strip().rstrip("{").rstrip().strip()
        match = re.match(r"^(.*?)(?:\s+|,)(\d+)(?::(\d+))?\s*$", text)
        if not match or match.group(3):
            continue
        name = match.group(1).strip().rstrip(",").strip()
        if name:
            apps.append(SourceApp(int(match.group(2)), name, line_number))
    return apps


def parse_port_range(message: bytes) -> tuple[int, int]:
    return first_varint(message, 1), first_varint(message, 2)


def parse_ik_app(message: bytes) -> SourceRule:
    values: dict[int, list[int | bytes]] = {}
    for field, _wire_type, value in wire_fields(message):
        values.setdefault(field, []).append(value)

    def vint(field: int, default: int = 0) -> int:
        for value in values.get(field, []):
            if isinstance(value, int):
                return value
        return default

    pattern = next((bytes(value) for value in values.get(5, [])
                    if isinstance(value, bytes)), b"")
    ports = tuple(parse_port_range(bytes(value)) for value in values.get(10, [])
                  if isinstance(value, bytes))
    offset_values = [value for value in values.get(8, []) if isinstance(value, int)]
    offset = offset_values[0] if offset_values else None
    if offset is not None:
        offset &= 0xFFFFFFFF
        if offset & (1 << 31):
            offset -= 1 << 32
    return SourceRule(
        source_app_id=vint(7), proto=vint(2), direction=vint(3),
        pkt_seq=vint(4), pattern_b64=base64.b64encode(pattern).decode(),
        match_method=vint(9), offset=offset, ports=ports,
        priority=vint(19), source_rule_id=vint(20),
    )


def parse_app5(path: Path) -> list[SourceRule]:
    top = path.read_bytes()
    extend_messages = all_messages(top, 5)
    if len(extend_messages) != 1:
        raise ValueError("app5.dat must contain exactly one extend_ik_data message")
    extend = extend_messages[0]
    rules: list[SourceRule] = []
    for slot in all_messages(extend, 1):
        rules.extend(parse_ik_app(message) for message in all_messages(slot, 1))
        for multi in all_messages(slot, 2):
            rules.extend(parse_ik_app(message) for message in all_messages(multi, 1))
    for field_number in (7, 9, 11):
        for group in all_messages(extend, field_number):
            rules.extend(parse_ik_app(message) for message in all_messages(group, 1))
    for wrapper in all_messages(extend, 17):
        for group in all_messages(wrapper, 3):
            rules.extend(parse_ik_app(message) for message in all_messages(group, 1))
    return rules


def db_apps(conn: sqlite3.Connection) -> dict[str, list[tuple[int, str]]]:
    by_name: dict[str, list[tuple[int, str]]] = {}
    for app_id, name in conn.execute("SELECT app_id,name FROM app ORDER BY app_id"):
        by_name.setdefault(semantic_name(name), []).append((app_id, name))
    return by_name


def choose_app_targets(conn: sqlite3.Connection, apps: list[SourceApp],
                       rules: list[SourceRule]) -> tuple[dict[int, int], list[dict]]:
    by_name = db_apps(conn)
    rules_by_app: dict[int, list[SourceRule]] = {}
    for rule in rules:
        rules_by_app.setdefault(rule.source_app_id, []).append(rule)
    imported_rule_targets = {
        str(source_rule_id): app_id
        for source_rule_id, app_id in conn.execute(
            "SELECT source_rule_id,app_id FROM dpi_rule "
            "WHERE source_rule_id IS NOT NULL AND source_rule_id<>''")
    }
    targets: dict[int, int] = {}
    decisions: list[dict] = []
    for app in apps:
        candidates = by_name.get(semantic_name(app.name), [])
        if not candidates:
            decisions.append({"source_id": app.source_id, "name": app.name,
                              "target_app_id": None, "reason": "new_app"})
            continue
        evidence = {app_id: 0 for app_id, _name in candidates}
        for rule in rules_by_app.get(app.source_id, []):
            target = imported_rule_targets.get(str(rule.source_rule_id))
            if target in evidence:
                evidence[target] += 1
        ranked = []
        for app_id, db_name in candidates:
            rule_count = conn.execute(
                "SELECT COUNT(*) FROM dpi_rule WHERE app_id=?", (app_id,)).fetchone()[0]
            icon_count = conn.execute(
                "SELECT COUNT(*) FROM app_icon WHERE app_id=?", (app_id,)).fetchone()[0]
            ranked.append((evidence[app_id], rule_count, icon_count, app_id, db_name))
        ranked.sort(reverse=True)
        chosen = ranked[0]
        targets[app.source_id] = chosen[3]
        decisions.append({
            "source_id": app.source_id,
            "name": app.name,
            "target_app_id": chosen[3],
            "target_name": chosen[4],
            "reason": "existing_rule_evidence" if chosen[0] else
                      "existing_rule_count" if chosen[1] else
                      "existing_icon" if chosen[2] else "deterministic_existing_id",
            "evidence_rules": chosen[0],
            "candidate_count": len(candidates),
        })
    return targets, decisions


def existing_rule_keys(conn: sqlite3.Connection) -> set[str]:
    keys: set[str] = set()
    query = """
        SELECT a.name,r.proto,r.direction,r.match_type,r.pattern_format,
               COALESCE(r.pattern_text,''),COALESCE(r.pattern_hex,''),
               r.offset,r.priority,r.pkt_seq,
               COALESCE(group_concat(p.min_port||'-'||p.max_port,','),'')
        FROM dpi_rule r JOIN app a ON a.app_id=r.app_id
        LEFT JOIN dpi_rule_port p ON p.rule_id=r.rule_id
        GROUP BY r.rule_id
    """
    for row in conn.execute(query):
        name, proto, direction, match_type, pattern_format, text, hex_value, offset, priority, pkt_seq, ports = row
        if pattern_format == "hex":
            try:
                pattern = bytes.fromhex(hex_value or "")
            except ValueError:
                pattern = b""
        else:
            pattern = (text or "").encode()
        port_pairs = []
        for item in (ports or "").split(","):
            if "-" in item:
                lo, hi = item.split("-", 1)
                if lo.isdigit() and hi.isdigit():
                    port_pairs.append((int(lo), int(hi)))
        source_rule = SourceRule(
            source_app_id=0,
            proto={"tcp": 6, "udp": 17}.get((proto or "").lower(), 0),
            direction={"original": 1, "reply": 2}.get((direction or "").lower(), 0),
            pkt_seq=int(pkt_seq or 0),
            pattern_b64=base64.b64encode(pattern).decode(),
            match_method={"exact": 0, "regex": 1, "no_fixed": 2,
                          "bm": 5}.get((match_type or "").lower(), -1),
            offset=offset,
            ports=tuple(port_pairs), priority=int(priority or 0),
            source_rule_id=0,
        )
        keys.add(source_rule.content_key(name))
    return keys


def family_for_name(name: str) -> tuple[str, int]:
    normalized = normalize_name(name)
    if any(token in normalized for token in
           ("游戏", "王者", "洛克", "米哈游", "小7游戏")):
        return "games", 2
    if any(token in normalized for token in ("视频", "直播")):
        return "video_platforms", 3
    if any(token in normalized for token in
           ("外研", "读书郎", "轻松学", "错题本", "loilonote", "padlet",
            "国家开放大学", "外语通", "爱点读", "googleclassroom")):
        return "education", 9
    if any(token in normalized for token in
           ("grok", "大模型", "nousresearch", "trae", "cursor", "codebuddy")):
        return "ai_tools", 17
    if any(token in normalized for token in
           ("apifox", "qoder", "figma", "jsonschema", "githubproxy", "ugit",
            "ghostty", "chocolatey", "golang", "posthog", "adobecreativecloud")):
        return "developer_tools", 11
    if any(token in normalized for token in ("腾讯", "微信", "qq", "搜狗")):
        return "tencent", 11
    if any(token in normalized for token in
           ("apple", "小米", "oppo", "vivo", "荣耀", "金立")):
        return "mobile_vendors", 10
    return "tools_utilities", 11


def build_report(protocols: Path, app5: Path, database: Path) -> dict:
    apps = parse_protocols(protocols)
    rules = parse_app5(app5)
    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    by_name = db_apps(conn)
    db_rule_keys = existing_rule_keys(conn)
    db_source_rule_ids = {
        str(value) for (value,) in conn.execute(
            "SELECT source_rule_id FROM dpi_rule WHERE source_rule_id IS NOT NULL AND source_rule_id<>''")
    }
    targets, target_decisions = choose_app_targets(conn, apps, rules)
    conn.close()
    source_names = {app.source_id: app.name for app in apps}
    missing_apps = [app for app in apps if semantic_name(app.name) not in by_name]
    source_rule_keys = set()
    rule_counts: dict[int, int] = {}
    new_rules = []
    invalid_rules = []
    for rule in rules:
        name = source_names.get(rule.source_app_id, "")
        if not name:
            continue
        validation_error = rule.runtime_validation_error()
        if validation_error:
            invalid_rules.append({
                "source_app_id": rule.source_app_id,
                "source_rule_id": rule.source_rule_id,
                "match_method": METHOD_NAMES.get(rule.match_method, str(rule.match_method)),
                "reason": validation_error,
            })
            continue
        source_rule_keys.add(rule.content_key(name))
        rule_counts[rule.source_app_id] = rule_counts.get(rule.source_app_id, 0) + 1
        if str(rule.source_rule_id) not in db_source_rule_ids and rule.content_key(name) not in db_rule_keys:
            new_rules.append(rule)
    missing_with_rules = [app for app in missing_apps if rule_counts.get(app.source_id, 0)]
    report = {
        "mode": "report_only",
        "source": SOURCE,
        "protocols": str(protocols),
        "app5": str(app5),
        "database": str(database),
        "source_app_count": len(apps),
        "source_rule_count": len(rules),
        "source_rule_app_count": len(rule_counts),
        "name_covered_count": len(apps) - len(missing_apps),
        "name_missing_count": len(missing_apps),
        "name_missing_with_rules_count": len(missing_with_rules),
        "source_id_conflict_count": 0,
        "content_rule_new_count": len(source_rule_keys - db_rule_keys),
        "stable_source_rule_new_count": len(new_rules),
        "invalid_source_rule_count": len(invalid_rules),
        "invalid_source_rules": invalid_rules,
        "target_existing_app_count": len(targets),
        "missing_apps": [asdict(app) | {"source_rule_count": rule_counts.get(app.source_id, 0)}
                         for app in missing_apps],
        "missing_apps_with_rules": [asdict(app) | {"source_rule_count": rule_counts[app.source_id]}
                                    for app in missing_with_rules],
        "target_decisions": target_decisions,
    }
    return report


def apply_augmentation(report: dict, source_apps: list[SourceApp],
                       source_rules: list[SourceRule], database: Path,
                       output: Path) -> None:
    shutil.copy2(database, output)
    conn = sqlite3.connect(output)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("BEGIN IMMEDIATE")
    try:
        meta_next_app_id = int(conn.execute(
            "SELECT value FROM meta WHERE key='next_app_id'").fetchone()[0])
        next_app_id = max(meta_next_app_id, int(conn.execute(
            "SELECT COALESCE(MAX(app_id),0)+1 FROM app").fetchone()[0]))
        now = int(time.time())
        rules_by_app: dict[int, list[SourceRule]] = {}
        for rule in source_rules:
            rules_by_app.setdefault(rule.source_app_id, []).append(rule)
        missing_ids = {item["source_id"] for item in report["missing_apps_with_rules"]}
        added = 0
        for app in sorted((item for item in source_apps if item.source_id in missing_ids),
                          key=lambda item: hashlib.sha256(
                              f"{SOURCE}:{item.name}".encode()).hexdigest()):
            family, category_id = family_for_name(app.name)
            app_id = next_app_id + added
            conn.execute(
                "INSERT INTO app(app_id,name,normalized_name,category_id,family,batch,description,enabled,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (app_id, app.name, normalize_name(app.name), category_id, family,
                 SOURCE, "Incremental protocol library supplement", 1, now, now))
            conn.execute(
                "INSERT INTO app_id_map(app_id,source,source_app_id,source_name,confidence,note) "
                "VALUES(?,?,?,?,?,?)",
                (app_id, SOURCE, str(app.source_id), app.name, 1.0,
                 "source id retained only as audit evidence; DreamingWrt id reassigned"))
            added += 1
        targets = {
            int(item["source_id"]): int(item["target_app_id"])
            for item in report["target_decisions"] if item.get("target_app_id") is not None
        }
        for row in conn.execute(
                "SELECT app_id,source_app_id FROM app_id_map WHERE source=?", (SOURCE,)):
            targets[int(row[1])] = int(row[0])
        source_names = {app.source_id: app.name for app in source_apps}
        existing_ids = {
            str(value) for (value,) in conn.execute(
                "SELECT source_rule_id FROM dpi_rule WHERE source_rule_id IS NOT NULL AND source_rule_id<>''")
        }
        existing_keys = existing_rule_keys(conn)
        candidates = []
        skipped_unsupported = 0
        skipped_invalid = 0
        for rule in source_rules:
            app_id = targets.get(rule.source_app_id)
            name = source_names.get(rule.source_app_id, "")
            key = rule.content_key(name)
            if not app_id or str(rule.source_rule_id) in existing_ids or key in existing_keys:
                continue
            if rule.match_method not in METHOD_NAMES or rule.proto not in PROTO_NAMES or \
                    rule.direction not in DIRECTION_NAMES:
                skipped_unsupported += 1
                continue
            if rule.runtime_validation_error():
                skipped_invalid += 1
                continue
            candidates.append((key, app_id, rule))
        candidates.sort(key=lambda item: hashlib.sha256(
            f"{SOURCE}:{item[2].source_rule_id}:{item[0]}".encode()).hexdigest())
        meta_next_rule_id = int(conn.execute(
            "SELECT value FROM meta WHERE key='next_rule_id'").fetchone()[0])
        next_rule_id = max(meta_next_rule_id, int(conn.execute(
            "SELECT COALESCE(MAX(rule_id),0)+1 FROM dpi_rule").fetchone()[0]))
        added_rules = 0
        for _key, app_id, rule in candidates:
            pattern = rule.pattern()
            printable = bool(pattern) and all(
                byte in (9, 10, 13) or 32 <= byte < 127 for byte in pattern)
            pattern_format = "text" if printable else "hex"
            pattern_text = pattern.decode("ascii") if printable else None
            pattern_hex = None if printable else pattern.hex()
            rule_id = next_rule_id + added_rules
            raw_json = json.dumps({
                "source": SOURCE,
                "source_app_id": rule.source_app_id,
                "source_rule_id": rule.source_rule_id,
                "content_sha256": _key,
                "ports_over_runtime_limit": max(0, len(rule.ports) - 8),
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            conn.execute(
                "INSERT INTO dpi_rule(rule_id,app_id,proto,direction,match_type,pattern_format,"
                "pattern_text,pattern_hex,offset,priority,pkt_seq,tls_match,source,source_rule_id,"
                "raw_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rule_id, app_id, PROTO_NAMES[rule.proto], DIRECTION_NAMES[rule.direction],
                 METHOD_NAMES[rule.match_method], pattern_format, pattern_text, pattern_hex,
                 rule.offset, rule.priority or 50, rule.pkt_seq, None, SOURCE,
                 str(rule.source_rule_id), raw_json, 1, now, now))
            for min_port, max_port in rule.ports:
                conn.execute(
                    "INSERT INTO dpi_rule_port(rule_id,min_port,max_port) VALUES(?,?,?)",
                    (rule_id, min_port, max_port))
            added_rules += 1
        conn.execute("UPDATE meta SET value=? WHERE key='next_app_id'",
                     (str(next_app_id + added),))
        conn.execute("UPDATE meta SET value=? WHERE key='next_rule_id'",
                     (str(next_rule_id + added_rules),))
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('protocol_augment_source',?)",
                     (SOURCE,))
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('protocol_augment_at',?)",
                     (str(now),))
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('protocol_augment_cursor_repaired',?)",
                     ("1" if next_app_id != meta_next_app_id or
                              next_rule_id != meta_next_rule_id else "0",))
        conn.execute(
            "INSERT OR REPLACE INTO batch_log(batch,family,extracted_at,app_count,rule_count,icon_count,note) "
            "VALUES(?,?,?,?,?,?,?)",
            (SOURCE, "incremental", now, added, added_rules, 0,
             f"append-only import; unsupported_rules={skipped_unsupported}; "
             f"invalid_rules={skipped_invalid}; source IDs audit-only"))
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError("foreign key check failed")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("integrity check failed")
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        output.unlink(missing_ok=True)
        raise
    conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocols", type=Path, required=True)
    parser.add_argument("--app5", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--apply", action="store_true",
                        help="write a new DB copy; never modifies --database")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_report(args.protocols, args.app5, args.database)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    if args.apply:
        if not args.output or args.output.resolve() == args.database.resolve():
            parser.error("--apply requires a distinct --output database path")
        apply_augmentation(report, parse_protocols(args.protocols), parse_app5(args.app5),
                           args.database, args.output)
    print(json.dumps({key: value for key, value in report.items()
                      if key.endswith("_count") or key in ("mode", "source")},
                     ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
