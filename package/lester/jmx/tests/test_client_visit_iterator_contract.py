#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "jmx_client_fs.c"


def function_body(source, name):
    match = re.search(
        rf"static\s+[^;{{]*?\b{re.escape(name)}\s*\([^;{{]*\)\s*\{{",
        source,
    )
    if not match:
        raise AssertionError(f"function not found: {name}")

    start = match.end()
    depth = 1
    for offset, char in enumerate(source[start:], start=start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:offset]
    raise AssertionError(f"unterminated function: {name}")


class VisitIteratorModel:
    """Small model of the global iterator's externally visible positions."""

    def __init__(self, client_buckets):
        self.rows = [
            row
            for clients in client_buckets
            for visit_buckets in clients
            for bucket in visit_buckets
            for row in bucket
        ]

    def start(self, pos):
        if pos == 0:
            return "HEADER"
        index = pos - 1
        return self.rows[index] if index < len(self.rows) else None

    def read_chunks(self, chunk_size):
        pos = 0
        chunks = []
        while True:
            chunk = []
            while len(chunk) < chunk_size:
                value = self.start(pos)
                if value is None:
                    break
                chunk.append(value)
                pos += 1
            if chunk:
                chunks.append(chunk)
            if self.start(pos) is None:
                return chunks


class ClientVisitIteratorContractTest(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding="utf-8")

    def test_global_iterator_skips_clients_without_visit_rows(self):
        self.assertIn("while (st->client_bucket < MAX_AF_CLIENT_HASH_SIZE", self.source)
        self.assertIn("visit = af_client_visit_get_next_visit(seq, client);", self.source)
        self.assertIn("if (visit)\n\t\t\treturn visit;", self.source)
        self.assertGreaterEqual(
            self.source.count("if (!next)\n\t\t\tnext = af_client_visit_get_next_client(s);"),
            1,
        )

    def test_seq_start_does_not_rewind_persistent_position(self):
        body = function_body(self.source, "af_client_visit_seq_start")

        self.assertIn("loff_t remaining = *pos;", body)
        self.assertNotRegex(body, r"\(\*pos\)\s*(?:\+\+|--|[+\-*/]?=)")

    def test_restart_resets_visit_cursor_state(self):
        body = function_body(self.source, "af_client_visit_get_first_client")

        self.assertIn("st->current_client = NULL;", body)
        self.assertIn("st->current_visit_node = NULL;", body)
        self.assertIn("st->visit_bucket = 0;", body)

    def test_chunked_reads_emit_each_cross_client_row_once_then_eof(self):
        model = VisitIteratorModel(
            [
                [[], [["client-a/app-1"], [], ["client-a/app-2"]]],
                [],
                [[[], ["client-b/app-3", "client-b/app-4"]], []],
            ]
        )

        chunks = model.read_chunks(chunk_size=2)
        flattened = [item for chunk in chunks for item in chunk]

        self.assertEqual(
            flattened,
            [
                "HEADER",
                "client-a/app-1",
                "client-a/app-2",
                "client-b/app-3",
                "client-b/app-4",
            ],
        )
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertIsNone(model.start(len(flattened)))


if __name__ == "__main__":
    unittest.main()
