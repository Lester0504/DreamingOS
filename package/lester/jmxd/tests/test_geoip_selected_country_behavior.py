#!/usr/bin/env python3

import csv
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "GeoIP2-Country-Test.mmdb"
FIXTURE_SHA256 = "b37601903448683d241af52893c8cbf0fed461e0cdebe0bfaca01891fdeb6db9"


class SelectedCountryBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._build_dir = tempfile.TemporaryDirectory()
        configured = os.environ.get("DREAMINGWRT_GEOIP_TEST_EXPORTER")
        if configured:
            cls.exporter = Path(configured)
            return
        # 31.6 ships libmaxminddb in the staging_dir but with no .pc file, so
        # the pkg-config probe skipped this suite on the very host where it
        # matters. Ask the shared resolver whether the dependency is reachable.
        if not shutil.which("cc") or not apd_test_deps.have_package("libmaxminddb"):
            raise unittest.SkipTest("libmaxminddb development files are unavailable")
        cls.exporter = Path(cls._build_dir.name) / "geo-export"
        flags = apd_test_deps.package_flags("libmaxminddb")
        subprocess.run(
            [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                str(ROOT / "tools" / "export-mmdb-country-prefix.c"),
                str(ROOT / "src" / "geoip" / "mmdb_country_prefix.c"),
                *flags, "-o", str(cls.exporter),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls._build_dir.cleanup()

    def run_export(self, directory: Path, name: str, *countries: str, mmdb=FIXTURE):
        output = directory / f"{name}.csv"
        command = [str(self.exporter), "--mmdb", str(mmdb), "--output", str(output)]
        for country in countries:
            command.extend(("--country", country))
        return subprocess.run(command, text=True, capture_output=True, check=False), output

    @staticmethod
    def rows(path: Path):
        with path.open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))

    def test_fixture_integrity(self):
        self.assertEqual(FIXTURE_SHA256, hashlib.sha256(FIXTURE.read_bytes()).hexdigest())

    def test_selected_country_filter_and_ipv4_ipv6(self):
        with tempfile.TemporaryDirectory() as raw:
            result, output = self.run_export(Path(raw), "cn", "CN")
            self.assertEqual(0, result.returncode, result.stderr)
            rows = self.rows(output)
            self.assertTrue(rows)
            self.assertEqual({"CN"}, {row["country_iso_code"] for row in rows})
            self.assertTrue(any(":" not in row["network"] for row in rows))
            self.assertTrue(any(":" in row["network"] for row in rows))

    def test_country_order_does_not_change_output(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            first, first_path = self.run_export(directory, "first", "US", "CN")
            second, second_path = self.run_export(directory, "second", "CN", "US")
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            self.assertEqual({"CN", "US"}, {r["country_iso_code"] for r in self.rows(first_path)})

    def test_missing_database_fails_without_output(self):
        with tempfile.TemporaryDirectory() as raw:
            result, output = self.run_export(Path(raw), "missing", "CN",
                                             mmdb=Path(raw) / "missing.mmdb")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("mmdb_missing", result.stderr)
            self.assertFalse(output.exists())

    def test_invalid_database_fails_without_output(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            invalid = directory / "invalid.mmdb"
            invalid.write_bytes(b"not-a-maxmind-database")
            result, output = self.run_export(directory, "invalid", "CN", mmdb=invalid)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("mmdb_invalid", result.stderr)
            self.assertFalse(output.exists())

    def test_selected_country_without_data_fails_without_output(self):
        with tempfile.TemporaryDirectory() as raw:
            result, output = self.run_export(Path(raw), "empty", "AU")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("mmdb_country_empty", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
