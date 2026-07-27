#!/usr/bin/env python3

import hashlib
import importlib.util
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "tools" / "export-mmdb-country-prefix.c"
SHARED = ROOT / "src" / "geoip" / "mmdb_country_prefix.c"
IMPORTER = ROOT / "tools" / "import-geoip-country-prefix.py"
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def load_importer():
    spec = importlib.util.spec_from_file_location("geoip_prefix_importer", IMPORTER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExporterContractTests(unittest.TestCase):
    def test_exporter_uses_search_tree_and_ipv4_start_node(self):
        source = SHARED.read_text(encoding="utf-8")
        self.assertIn("MMDB_read_node", source)
        self.assertIn("ipv4_start_node.node_value", source)
        self.assertIn("ipv4_compat_or_mapped", source)
        self.assertIn('"country", "iso_code"', source)
        self.assertIn("MMDB_RECORD_TYPE_DATA", source)
        self.assertIn("visited node count exceeds configured limit", source)
        self.assertIn("selected prefix count exceeds configured limit", source)
        self.assertIn("selected_country(ctx, code)", source)

    def test_exporter_is_deterministic_and_atomic(self):
        source = SHARED.read_text(encoding="utf-8")
        self.assertIn("qsort", source)
        self.assertIn("can_merge", source)
        self.assertIn("mkstemp", source)
        self.assertIn("fsync", source)
        self.assertIn("rename(temporary, output)", source)

    def test_official_country_catalog_is_exact(self):
        importer = load_importer()
        self.assertEqual(249, len(importer.OFFICIAL_ISO_CODES))
        self.assertIn("CN", importer.OFFICIAL_ISO_CODES)
        self.assertIn("US", importer.OFFICIAL_ISO_CODES)
        self.assertNotIn("XK", importer.OFFICIAL_ISO_CODES)
        self.assertNotIn("UN", importer.OFFICIAL_ISO_CODES)

    def test_makefile_builds_optional_non_dataplane_tool_package(self):
        self.assertIn("PKG_BUILD_DEPENDS:=libmaxminddb", MAKEFILE)
        self.assertIn("define Package/dreamingwrt-geoip-tools", MAKEFILE)
        self.assertIn("+libmaxminddb +python3-light +python3-sqlite3", MAKEFILE)
        self.assertIn("./tools/export-mmdb-country-prefix.c", MAKEFILE)
        self.assertIn("./src/geoip/mmdb_country_prefix.c", MAKEFILE)
        self.assertIn("/usr/libexec/dreamingwrt/dreamingwrt-geoip-prefix-export", MAKEFILE)
        self.assertIn("retained for diagnostics only", MAKEFILE)
        jmxd_dependencies = MAKEFILE.split("define Package/jmxd", 1)[1].split("endef", 1)[0]
        self.assertNotIn("dreamingwrt-geoip-tools", jmxd_dependencies)


class ImporterContractTests(unittest.TestCase):
    def make_db(self, directory: Path) -> Path:
        db = directory / "signatures.db"
        with sqlite3.connect(db) as connection:
            connection.execute("CREATE TABLE sentinel(value TEXT)")
            connection.execute("INSERT INTO sentinel VALUES('unchanged')")
        return db

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run_import(self, db: Path, csv_path: Path, *extra: str):
        return subprocess.run(
            [
                "python3", str(IMPORTER), "--db", str(db), "--blocks", str(csv_path),
                "--source", "contract_test", *extra,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_ipv4_ipv6_normalization_and_idempotence(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            db = self.make_db(directory)
            csv_path = directory / "prefixes.csv"
            csv_path.write_text(
                "network,country_iso_code\n1.2.3.99/24,CN\n2001:db8::1234/48,US\n",
                encoding="utf-8",
            )
            first = self.run_import(db, csv_path, "--replace", "--apply")
            self.assertEqual(0, first.returncode, first.stderr)
            with sqlite3.connect(db) as connection:
                rows = connection.execute(
                    "SELECT iso_code,network,family,prefix_len FROM geoip_country_prefix "
                    "ORDER BY family,first_ip_hex"
                ).fetchall()
                self.assertEqual("ok", connection.execute("PRAGMA quick_check").fetchone()[0])
            self.assertEqual(
                [("CN", "1.2.3.0/24", 4, 24), ("US", "2001:db8::/48", 6, 48)], rows
            )
            second = self.run_import(db, csv_path, "--apply")
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertIn("changed=0", second.stdout)

    def test_invalid_or_duplicate_input_never_modifies_target(self):
        fixtures = (
            "network,country_iso_code\n1.2.3.0/24,XK\n",
            "network,country_iso_code\n1.2.3.0/24,CN\n1.2.3.0/24,US\n",
            "network,country_iso_code\nnot-a-network,CN\n",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                with tempfile.TemporaryDirectory() as raw_directory:
                    directory = Path(raw_directory)
                    db = self.make_db(directory)
                    csv_path = directory / "invalid.csv"
                    csv_path.write_text(fixture, encoding="utf-8")
                    before = self.digest(db)
                    result = self.run_import(db, csv_path, "--replace", "--apply")
                    self.assertNotEqual(0, result.returncode)
                    self.assertEqual(before, self.digest(db))
                    with sqlite3.connect(db) as connection:
                        tables = {
                            row[0] for row in connection.execute(
                                "SELECT name FROM sqlite_master WHERE type='table'"
                            )
                        }
                    self.assertNotIn("geoip_country_prefix", tables)


if __name__ == "__main__":
    unittest.main()
