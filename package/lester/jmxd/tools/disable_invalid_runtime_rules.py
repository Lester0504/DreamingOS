#!/usr/bin/env python3
"""Create a signature DB copy with invalid fixed payload rules disabled."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sqlite3
from pathlib import Path


INVALID_WHERE = """
enabled=1
AND lower(match_type) IN ('exact','fixed','bm')
AND length(
  CASE WHEN lower(pattern_format)='hex'
       THEN COALESCE(pattern_hex,'')
       ELSE COALESCE(pattern_text,'') END
)=0
"""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def migrate(source: Path, output: Path) -> tuple[int, str]:
    if source.resolve() == output.resolve():
        raise ValueError("output must differ from source")
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output)
    connection = sqlite3.connect(output)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            f"SELECT rule_id FROM dpi_rule WHERE {INVALID_WHERE} ORDER BY rule_id"
        ).fetchall()
        connection.execute(
            f"UPDATE dpi_rule SET enabled=0,updated_at=strftime('%s','now') "
            f"WHERE {INVALID_WHERE}"
        )
        connection.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
            (
                "empty_fixed_payload_migration",
                "disable-invalid-preserve-rule-id-source-evidence",
            ),
        )
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        remaining = connection.execute(
            f"SELECT COUNT(*) FROM dpi_rule WHERE {INVALID_WHERE}"
        ).fetchone()[0]
        if foreign_keys or integrity != "ok" or remaining:
            raise RuntimeError(
                f"validation failed integrity={integrity} "
                f"foreign_keys={len(foreign_keys)} remaining={remaining}"
            )
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        output.unlink(missing_ok=True)
        raise
    connection.close()
    return len(rows), sha256(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    count, digest = migrate(args.database, args.output)
    print(f"disabled_invalid_runtime_rules={count}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
