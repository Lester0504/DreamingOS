#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RULE_MANAGER = ROOT / "files" / "rule_manager.lua"


class RulesdSysctlNamespaceContractTest(unittest.TestCase):
    def test_rulesd_uses_registered_dreamingwrt_namespace(self):
        source = RULE_MANAGER.read_text(encoding="utf-8")

        for name in ("appfilter_enable", "macfilter_enable", "record_enable"):
            self.assertIn(f'"/proc/sys/dreamingwrt/jmx/{name}"', source)
            self.assertNotIn(f'"/proc/sys/jmx/{name}"', source)


if __name__ == "__main__":
    unittest.main()
