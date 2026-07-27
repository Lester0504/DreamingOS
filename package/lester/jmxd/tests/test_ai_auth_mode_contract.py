#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text()
API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text()


class AiAuthModeContract(unittest.TestCase):
    def test_schema_and_read_contract_expose_auth_mode(self):
        self.assertIn('"auth_mode TEXT NOT NULL DEFAULT \'api_key\',"', DB)
        self.assertIn('nc_add_text(data, "auth_mode", st, 11)', DB)

    def test_only_api_key_or_oauth_are_accepted(self):
        self.assertIn('strcmp(requested_mode, "api_key")', DB)
        self.assertIn('strcmp(requested_mode, "oauth")', DB)
        self.assertIn('"invalid_auth_mode"', API)

    def test_omitted_auth_mode_preserves_existing_selection(self):
        self.assertIn('SELECT auth_mode FROM ai_config WHERE id=1', DB)
        self.assertIn('sqlite3_bind_text(st, 11, auth_mode', DB)
        self.assertIn('sqlite3_bind_text(st, 12, auth_mode', DB)

    def test_api_key_clear_is_independent_from_auth_mode(self):
        self.assertIn('clear_api_key', DB)
        self.assertIn('auth_mode=excluded.auth_mode', DB)


if __name__ == "__main__":
    unittest.main()
