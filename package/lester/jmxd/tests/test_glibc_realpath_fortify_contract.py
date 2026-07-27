#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class GlibcRealpathFortifyContract(unittest.TestCase):
    def test_realpath_does_not_use_fixed_size_output_buffers(self):
        sources = list((ROOT / "src").rglob("*.c"))
        fixed_buffer_call = re.compile(r"\brealpath\s*\([^,]+,\s*(?!NULL\b)[A-Za-z_]\w*\s*\)")

        offenders = []
        for source in sources:
            text = source.read_text(errors="replace")
            for match in fixed_buffer_call.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{source.relative_to(ROOT)}:{line}: {match.group(0)}")

        self.assertEqual(
            offenders,
            [],
            "glibc fortify requires realpath(path, NULL); fixed output buffers may abort: "
            + "; ".join(offenders),
        )

    def test_dynamic_realpath_results_are_freed(self):
        netconfig = (ROOT / "src/jmx_netconfig_db.c").read_text()
        inventory = (ROOT / "src/otad/otad_inventory.c").read_text()

        self.assertIn("resolved = realpath(path, NULL);", netconfig)
        self.assertIn("free(resolved);", netconfig)
        self.assertIn("char *resolved = realpath(path, NULL);", inventory)
        self.assertIn("free(resolved);", inventory)


if __name__ == "__main__":
    unittest.main()
