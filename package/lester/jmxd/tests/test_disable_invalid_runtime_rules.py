import importlib.util
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "disable_invalid_runtime_rules.py"
SPEC = importlib.util.spec_from_file_location("disable_invalid_runtime_rules", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_migration_disables_only_empty_fixed_rules(tmp_path):
    source = tmp_path / "source.db"
    output = tmp_path / "output.db"
    db = sqlite3.connect(source)
    db.executescript(
        """
        CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE dpi_rule(
          rule_id INTEGER PRIMARY KEY, match_type TEXT, pattern_format TEXT,
          pattern_text TEXT, pattern_hex TEXT, enabled INTEGER, updated_at INTEGER
        );
        INSERT INTO dpi_rule VALUES(1,'exact','hex',NULL,'',1,0);
        INSERT INTO dpi_rule VALUES(2,'bm','text','abc',NULL,1,0);
        INSERT INTO dpi_rule VALUES(3,'regex','text','',NULL,1,0);
        """
    )
    db.commit()
    db.close()

    disabled, digest = MODULE.migrate(source, output)
    assert disabled == 1
    assert len(digest) == 64
    check = sqlite3.connect(output)
    assert check.execute(
        "SELECT rule_id,enabled FROM dpi_rule ORDER BY rule_id"
    ).fetchall() == [(1, 0), (2, 1), (3, 1)]
    assert check.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    check.close()
