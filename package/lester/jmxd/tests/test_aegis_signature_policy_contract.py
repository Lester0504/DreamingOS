#!/usr/bin/env python3
"""Static and executable contracts for AegisXD Suricata signature policy overrides."""

from __future__ import annotations

from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import textwrap

ROOT = Path(__file__).resolve().parents[1]
AEGIS = ROOT / "src" / "aegisxd"
DB = (AEGIS / "aegisxd_db.c").read_text(encoding="utf-8")
INTERNAL = (AEGIS / "aegisxd_internal.h").read_text(encoding="utf-8")
POLICY_PATH = AEGIS / "aegisxd_signature_policy.c"
POLICY = POLICY_PATH.read_text(encoding="utf-8")
UBUS = (AEGIS / "aegisxd_ubus.c").read_text(encoding="utf-8")
DATAPLANE = (AEGIS / "aegisxd_dataplane.c").read_text(encoding="utf-8")
STATUS = (AEGIS / "aegisxd_status.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src" / "Makefile").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [n for n in needles if n not in text]
    assert not missing, f"{scope} missing: {missing}"


def test_schema_is_independent_config_db_override_and_version_bumped() -> None:
    assert "#define AEGISXD_SCHEMA_VERSION 8" in INTERNAL
    require_all(DB, (
        "CREATE TABLE IF NOT EXISTS aegis_signature_policy_overrides",
        "PRIMARY KEY(gid,sid)",
        "gid INTEGER NOT NULL DEFAULT 1 CHECK(gid=1)",
        "enabled_override INTEGER NOT NULL DEFAULT -1 CHECK(enabled_override IN (-1,0,1))",
        "action TEXT NOT NULL DEFAULT 'inherit' CHECK(action IN ('inherit','alert','drop','reject','pass'))",
        "target_rev INTEGER NOT NULL",
        "revision INTEGER NOT NULL DEFAULT 1",
        "apply_state TEXT NOT NULL DEFAULT 'apply_required'",
    ), "config.db signature override schema")
    assert "aegis_suricata_rules" in DB
    assert "aegis_signature_policy_overrides" not in (AEGIS / "aegisxd_import.c").read_text(encoding="utf-8"), \
        "feed import must not write user overrides into feed-owned Suricata rules"


def test_ubus_method_names_are_fixed_and_not_safe_disabled() -> None:
    for method, handler in {
        "signature_policies": "aegisxd_handle_signature_policies",
        "set_signature_policy": "aegisxd_handle_set_signature_policy",
        "suppress_signature": "aegisxd_handle_suppress_signature",
        "unsuppress_signature": "aegisxd_handle_unsuppress_signature",
    }.items():
        line = next(l for l in UBUS.splitlines() if f'UBUS_METHOD("{method}"' in l)
        assert handler in line
        assert "safe_disabled" not in line
    assert "aegisxd_signature_policy.o" in MAKEFILE


def test_validation_and_stable_errors() -> None:
    require_all(POLICY, (
        "invalid_signature_id",
        "revision_required",
        "signature_not_found",
        "signature_revision_mismatch",
        "revision_conflict",
        "signature_policy_save_failed",
        "target_rev != rule.rev",
        "expected_revision != (old.exists ? old.revision : 0)",
        'sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE"',
        "expected_revision != (current.exists ? current.revision : 0)",
        'sqlite3_exec(g_aegisxd_config_db, "COMMIT"',
        "gid != 1",
        "enabled_override != -1 && enabled_override != 0 && enabled_override != 1",
        "aegisxd_signature_action_ok",
        "gid = 1",
    ), "strict SID/GID/rev validation")


def test_artifact_compiler_applies_override_and_fails_closed() -> None:
    require_all(DATAPLANE, (
        "aegisxd_signature_policy_problem_count() > 0",
        "aegisxd_signature_policy_effective_rule_text",
        "Suppressed or disabled signatures are intentionally omitted",
        "signature_revision_mismatch",
        "return ok ? written : -1",
        "suricata_enabled = aegisxd_signature_policy_effective_enabled_count();",
        "signature_policy_overrides",
    ), "Suricata artifact override compiler")
    require_all(POLICY, (
        "ov.suppressed",
        "ov.enabled_override >= 0",
        "strcmp(ov.action, \"inherit\")",
        "snprintf(out, out_len, \"%s%s\", action, p + token_len)",
    ), "effective rule mutation")


def test_status_capabilities_and_counts() -> None:
    require_all(STATUS + DATAPLANE, (
        "suricata_signature_policy",
        "suricata_signature_policy_persisted",
        "suricata_signature_policy_apply_required",
        "suricata_signature_suppress",
        "aegisxd_signature_policy_counts_json",
        "ids_ips_signature_policy_counts",
    ), "status capabilities/counts")


def test_no_runtime_dataplane_false_claim_on_policy_set() -> None:
    writer_start = POLICY.index("static struct json_object *aegisxd_signature_policy_write")
    writer = POLICY[writer_start:]
    require_all(writer, (
        '"persisted"',
        '"apply_required"',
        '"dataplane_changed", json_object_new_boolean(0)',
        'aegisxd_suricata_runtime_available()',
        '"suricata_apply_required"',
        '"suricata_runtime_missing"',
    ), "policy write response")
    assert "suricata_start" not in writer
    assert "nft" not in writer.lower()


def test_sqlite_override_survives_feed_update_and_effective_rule_contract() -> None:
    schema = re.search(r'"CREATE TABLE IF NOT EXISTS aegis_signature_policy_overrides \("(.*?)" PRIMARY KEY\(gid,sid\)\)"', DB, re.S)
    assert schema, "override schema string is present"
    with tempfile.TemporaryDirectory(prefix="aegis-signature-policy-") as td:
        db_path = Path(td) / "config.db"
        conn = sqlite3.connect(db_path)
        conn.executescript("""
        CREATE TABLE aegis_signature_policy_overrides (
          gid INTEGER NOT NULL DEFAULT 1,
          sid INTEGER NOT NULL,
          target_rev INTEGER NOT NULL,
          enabled_override INTEGER NOT NULL DEFAULT -1 CHECK(enabled_override IN (-1,0,1)),
          action TEXT NOT NULL DEFAULT 'inherit' CHECK(action IN ('inherit','alert','drop','reject','pass')),
          suppressed INTEGER NOT NULL DEFAULT 0,
          reason TEXT NOT NULL DEFAULT '',
          revision INTEGER NOT NULL DEFAULT 1,
          apply_state TEXT NOT NULL DEFAULT 'apply_required',
          last_error TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL DEFAULT 0,
          updated_at INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(gid,sid)
        );
        CREATE TABLE aegis_suricata_rules (
          sid INTEGER PRIMARY KEY, rev INTEGER NOT NULL DEFAULT 0,
          enabled_default INTEGER NOT NULL DEFAULT 1, action TEXT NOT NULL DEFAULT '',
          rule_text TEXT NOT NULL DEFAULT ''
        );
        INSERT INTO aegis_suricata_rules VALUES
          (1001,3,1,'alert','alert tcp any any -> any 80 (msg:"a"; sid:1001; rev:3;)'),
          (1002,7,1,'alert','alert udp any any -> any 53 (msg:"b"; sid:1002; rev:7;)');
        INSERT INTO aegis_signature_policy_overrides
          (gid,sid,target_rev,enabled_override,action,suppressed,reason,revision,apply_state,created_at,updated_at)
          VALUES (1,1001,3,-1,'drop',0,'unit',1,'apply_required',1,2);
        """)
        conn.commit()
        # Simulate a feed refresh: rules are replaced/upserted, but config.db override must survive.
        conn.execute("UPDATE aegis_suricata_rules SET rule_text=? WHERE sid=1001",
                     ('alert tcp any any -> any 443 (msg:"a2"; sid:1001; rev:3;)',))
        row = conn.execute("SELECT action,reason,revision FROM aegis_signature_policy_overrides WHERE gid=1 AND sid=1001").fetchone()
        assert row == ("drop", "unit", 1)
        conn.execute("INSERT INTO aegis_signature_policy_overrides (gid,sid,target_rev,enabled_override,action,suppressed,reason,revision,apply_state,created_at,updated_at) VALUES (1,1002,7,-1,'inherit',1,'suppress',1,'apply_required',1,2)")
        assert conn.execute("SELECT COUNT(*) FROM aegis_signature_policy_overrides").fetchone()[0] == 2
        conn.close()


def test_effective_rule_helper_executable() -> None:
    helper = POLICY[POLICY.index("static int aegisxd_suricata_action_token_len"):]
    helper = helper[: helper.index("int aegisxd_signature_policy_effective_rule_text")]
    body = POLICY[POLICY.index("int aegisxd_signature_policy_effective_rule_text"):]
    body = body[: body.index("\n}\n", body.index("int aegisxd_signature_policy_effective_rule_text")) + 3]
    harness = textwrap.dedent(f'''
        #include <assert.h>
        #include <ctype.h>
        #include <stddef.h>
        #include <stdio.h>
        #include <string.h>
        struct aegisxd_signature_override {{
            int exists; int gid; int sid; int target_rev; int enabled_override;
            char action[32]; int suppressed; char reason[512]; int revision;
            char apply_state[32]; char last_error[128]; long long created_at; long long updated_at;
        }};
        static struct aegisxd_signature_override g_ov;
        static int aegisxd_signature_override_load(int gid, int sid, struct aegisxd_signature_override *ov) {{
            (void)gid; (void)sid; *ov = g_ov; return 0;
        }}
        static int aegisxd_signature_action_ok(const char *action) {{
            return action && (!strcmp(action, "inherit") || !strcmp(action, "alert") ||
                              !strcmp(action, "drop") || !strcmp(action, "reject") ||
                              !strcmp(action, "pass"));
        }}
        {helper}
        {body}
        int main(void) {{
            char out[512]; int enabled = -1; const char *err = "";
            memset(&g_ov, 0, sizeof(g_ov));
            g_ov.exists = 1; g_ov.target_rev = 3; g_ov.enabled_override = -1; strcpy(g_ov.action, "drop");
            assert(aegisxd_signature_policy_effective_rule_text(1, 42, 3, 1, "alert",
                "alert tcp any any -> any 443 (msg:\\"x\\"; sid:42; rev:3;)", out, sizeof(out), &enabled, &err) == 0);
            assert(enabled == 1);
            assert(strncmp(out, "drop tcp", 8) == 0);
            g_ov.suppressed = 1;
            assert(aegisxd_signature_policy_effective_rule_text(1, 42, 3, 1, "alert",
                "alert tcp any any -> any 443 (msg:\\"x\\"; sid:42; rev:3;)", out, sizeof(out), &enabled, &err) == 0);
            assert(enabled == 0 && out[0] == '\\0');
            g_ov.suppressed = 0; g_ov.target_rev = 4;
            assert(aegisxd_signature_policy_effective_rule_text(1, 42, 3, 1, "alert",
                "alert tcp any any -> any 443 (msg:\\"x\\"; sid:42; rev:3;)", out, sizeof(out), &enabled, &err) != 0);
            assert(!strcmp(err, "signature_revision_mismatch"));
            return 0;
        }}
    ''')
    with tempfile.TemporaryDirectory(prefix="aegis-signature-helper-") as td:
        src = Path(td) / "harness.c"
        binary = Path(td) / "harness"
        src.write_text(harness, encoding="utf-8")
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(src), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Aegis signature policy tests")
