#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "jmx_client_fs.c"


class ClientVisitIteratorContractTest(unittest.TestCase):
    def test_global_iterator_skips_clients_without_visit_rows(self):
        source = SOURCE.read_text(encoding="utf-8")

        self.assertIn("while (st->client_bucket < MAX_AF_CLIENT_HASH_SIZE", source)
        self.assertIn("visit = af_client_visit_get_next_visit(seq, client);", source)
        self.assertIn("if (visit)\n\t\t\treturn visit;", source)
        self.assertGreaterEqual(
            source.count("if (!next)\n\t\t\tnext = af_client_visit_get_next_client(s);"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
