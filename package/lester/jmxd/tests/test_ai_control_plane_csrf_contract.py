#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text()
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text()


class AiControlPlaneCsrfContract(unittest.TestCase):
    def test_all_ai_cookie_writes_require_same_origin(self):
        self.assertIn('!strncmp(req.path, "/api/v1/ai/", 11)', API)
        self.assertIn('strcmp(req.method, "OPTIONS")', API)
        self.assertIn('webd_cookie_write_csrf_ok(&req)', API)

    def test_oauth_risk_classification(self):
        self.assertIn('{ "/api/v1/ai/oauth/providers", "GET", JMX_RISK_LOW }', PERMS)
        self.assertIn('{ "/api/v1/ai/oauth/start",     "POST", JMX_RISK_MEDIUM }', PERMS)
        self.assertIn('{ "/api/v1/ai/oauth/poll",      "POST", JMX_RISK_MEDIUM }', PERMS)
        self.assertIn('{ "/api/v1/ai/oauth/disconnect", "POST,DELETE", JMX_RISK_HIGH }', PERMS)


if __name__ == "__main__":
    unittest.main()
