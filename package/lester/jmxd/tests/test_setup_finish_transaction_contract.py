#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    start = SETUP.index(name)
    brace = SETUP.index("{", start)
    depth = 0
    for index in range(brace, len(SETUP)):
        if SETUP[index] == "{":
            depth += 1
        elif SETUP[index] == "}":
            depth -= 1
            if depth == 0:
                return SETUP[start:index + 1]
    raise AssertionError(f"unterminated function: {name}")


class SetupFinishTransactionContract(unittest.TestCase):
    def test_finish_state_meta_and_drafts_are_one_transaction(self):
        finish = function("struct json_object *jmx_setup_finish")
        begin = finish.index('nc_exec("BEGIN IMMEDIATE")')
        update = finish.index("UPDATE setup_state SET initialized=1")
        meta = finish.index('nc_setup_set_meta("setup.initialized", "1")')
        drafts = finish.index("nc_setup_clear_drafts()")
        readback = finish.index("nc_setup_add_state_json(d)")
        commit = finish.index('nc_exec("COMMIT")')
        self.assertLess(begin, update)
        self.assertLess(update, meta)
        self.assertLess(meta, drafts)
        self.assertLess(drafts, readback)
        self.assertLess(readback, commit)
        self.assertIn('nc_exec("ROLLBACK")', finish)
        self.assertIn("WHERE id=1 AND initialized=0", finish)
        self.assertIn("started_at,setup_version FROM setup_state", finish)
        self.assertNotIn('nc_json_str_def(cfg, "version"', finish)

    def test_finish_returns_stable_revision_fields(self):
        state = function("static void nc_setup_add_state_json")
        for field in (
            '"setup_finished_at"',
            '"setup_finished_by"',
            '"setup_version"',
        ):
            self.assertIn(field, state)
        finish = function("struct json_object *jmx_setup_finish")
        self.assertIn('"finish_readback_verified"', finish)
        self.assertIn("nc_setup_json_int64_def", finish)
        self.assertIn("nc_sql_text(st, 5)", finish)

    def test_setup_security_advertises_actor_bound_twofa_routes(self):
        security = function("static struct json_object *nc_setup_security_json")
        self.assertIn('"requires_setup_session"', security)
        self.assertIn('"setup_actor_bound"', security)
        self.assertIn('"/api/setup/security/2fa/prepare"', security)
        self.assertIn('"/api/setup/security/2fa/enable"', security)


if __name__ == "__main__":
    unittest.main()
