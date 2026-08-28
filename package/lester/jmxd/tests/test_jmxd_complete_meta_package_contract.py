#!/usr/bin/env python3

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


class JmxdCompleteMetaPackageContract(unittest.TestCase):
    def test_router_runtime_daemons_are_selected(self) -> None:
        package = MAKEFILE.split("define Package/jmxd", 1)[1].split("endef", 1)[0]
        dependencies = set(re.findall(r"\+([A-Za-z0-9_.+-]+)", package))

        self.assertIn("dreamingwrt-ac", dependencies)
        self.assertIn("dreamingos-cloud", dependencies)

    def test_ap_node_daemon_remains_separate(self) -> None:
        package = MAKEFILE.split("define Package/jmxd", 1)[1].split("endef", 1)[0]

        self.assertNotIn("+dreamingwrt-apd", package)


if __name__ == "__main__":
    unittest.main()
