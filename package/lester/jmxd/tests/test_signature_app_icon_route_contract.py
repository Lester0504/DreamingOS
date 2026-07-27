#!/usr/bin/env python3
from pathlib import Path
import sqlite3
import unittest


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
DB = ROOT / "files/signatures/dreamingwrt_signatures.db"
LOGOS = ROOT / "files/logo"


class SignatureAppIconRouteContract(unittest.TestCase):
    def test_route_resolves_the_canonical_database_mapping(self):
        start = API.index("static struct json_object *webd_signature_app_icon_response")
        end = API.index("static int webd_shared_vendor_logo_for", start)
        helper = API[start:end]
        for marker in (
            "app_parse_positive_int_segment(id_segment, &app_id)",
            "FROM app a ",
            "LEFT JOIN app_icon ai ON ai.app_id=a.app_id",
            "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key",
            "a.app_id=?1 AND a.enabled=1",
            "WEBD_LOGO_DIR",
            "WEBD_LOGO_URL_PREFIX",
            '"app_icon_not_mapped"',
            '"app_icon_file_missing"',
        ):
            self.assertIn(marker, helper)
        self.assertNotIn("not_implemented", helper)

    def test_route_rejects_unsafe_ids_and_icon_basenames(self):
        self.assertIn("app_parse_positive_int_segment", API)
        self.assertIn("*p < 0x20 || *p == 0x7f", API)
        self.assertIn("strstr(name, \"..\")", API)
        self.assertIn("strchr(name, '/')", API)
        self.assertIn("strchr(name, '\\\\')", API)
        route = API[API.index("/* ── App Icon ── */") :]
        route = route[: route.index("/* ── Client Policies")]
        self.assertIn("app_id_buf", route)
        self.assertIn("webd_signature_app_icon_response(app_id_buf, &status)", route)
        self.assertNotIn("status = 501", route)

    def test_packaged_mapping_resolves_to_a_real_shared_asset(self):
        if not DB.is_file() or not LOGOS.is_dir():
            self.skipTest("private signature and logo libraries are not part of the public tree")
        with sqlite3.connect(DB) as connection:
            row = connection.execute(
                "SELECT a.app_id,ia.icon_file FROM app a "
                "JOIN app_icon ai ON ai.app_id=a.app_id "
                "JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
                "WHERE a.enabled=1 AND COALESCE(ia.icon_file,'')<>'' "
                "ORDER BY a.app_id LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        app_id, icon_file = row
        self.assertGreater(app_id, 0)
        public_file = icon_file[6:] if icon_file.startswith("icons/") else icon_file
        self.assertTrue((LOGOS / public_file).is_file(), public_file)


if __name__ == "__main__":
    unittest.main()
