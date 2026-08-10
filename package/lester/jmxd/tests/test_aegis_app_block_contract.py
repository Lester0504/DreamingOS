#!/usr/bin/env python3
import json
import re
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/jmx_netconfig_db.h").read_text(encoding="utf-8")
API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
RULESD = (ROOT / "files/rule_manager.lua").read_text(encoding="utf-8")
JMX_ROOT = ROOT.parent / "jmx" / "src"
KERNEL_FILTER = (JMX_ROOT / "jmx_app_filter.c").read_text(encoding="utf-8")
KERNEL_MAIN = (JMX_ROOT / "jmx_main.c").read_text(encoding="utf-8")
KERNEL_FILTER_H = (JMX_ROOT / "jmx_app_filter.h").read_text(encoding="utf-8")


def _defined_int(source: str, name: str) -> int:
    match = re.search(rf"^#define\s+{name}\s+(\d+)\s*$", source, re.MULTILINE)
    assert match, f"{name} not found"
    return int(match.group(1))


# 从真实源码读取上限，避免测试里写死数字后与实现脱节。
MAX_RULES = _defined_int(DB, "NC_AEGIS_APPFILTER_MAX_RULES")
KERNEL_MAX_RULES = _defined_int(KERNEL_FILTER_H, "MAX_APP_FILTER_RULE_NUM")


def test_userspace_and_kernel_rule_caps_agree() -> None:
    """
    webd 与 kmod 的上限必须一致，否则 webd 会接受内核拒收的规则，
    表现为 applied_rule_count 少于配置条数(静默不生效)。
    """
    assert MAX_RULES == KERNEL_MAX_RULES


def between(source: str, start: str, end: str) -> str:
    offset = source.index(start)
    return source[offset:source.index(end, offset)]


def strip_comments(source: str) -> str:
    """Drop /* */ and // comments so prose cannot trip a code assertion.

    The "no nft" check below matches substrings across a 1600-line span that
    happens to hold several unrelated features. A MAC ACL comment reading
    "how many nft rules a bound rule expands to" was enough to fail it, which
    says nothing about whether app filtering calls nft. Comparing code only
    keeps the assertion pointed at behavior.
    """
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", source)


def test_ubus_surface_and_authority_are_explicit() -> None:
    for method in (
        "aegis_app_blocks",
        "aegis_app_block_validate",
        "aegis_app_block_upsert",
        "aegis_app_block_delete",
    ):
        assert f'UBUS_METHOD("{method}"' in API
        assert f"jmx_{method}" in HEADER

    control = between(DB, "#define NC_AEGIS_APPFILTER_REINIT_FILE", "static int nc_rulesd_save_runtime_fields")
    assert "network_control_rule" in control
    assert "network_control_app_rule" in control
    assert "config.db:network_control_rule+network_control_app_rule" in control
    # The intent is that app-filter delivery goes through rulesd + /dev/jmx and
    # never shells out to nft, so only executable text is examined. The string
    # literals that reach a shell still count, so a real regression is caught.
    control_code = strip_comments(control)
    assert "nft " not in control_code
    assert "flowd" not in control_code


def test_validation_is_strict_and_limited_to_rulesd_semantics() -> None:
    normalize = between(
        DB,
        "static int nc_aegis_app_block_normalize",
        "static struct json_object *nc_aegis_app_block_schedule_json",
    )
    schedule = between(
        DB,
        "static int nc_aegis_app_block_schedule_normalize",
        "static int nc_aegis_app_block_normalize",
    )
    for field in (
        '"id"', '"name"', '"enabled"', '"source"', '"app_ids"',
        '"schedule"', '"action"', '"filter_quic"',
    ):
        assert field in normalize
    assert 'strcmp(json_object_get_string(value), "block")' in normalize
    assert "(app_id = json_object_get_int64(id)) <= 0" in normalize
    assert "app_id > INT_MAX" in normalize
    assert "NC_AEGIS_APPFILTER_MAX_APP_IDS" in normalize
    assert 'strcmp(source, "any")' in normalize
    assert "nc_netctl_mac_ok(source)" in normalize
    assert 'json_object_get_string(value), "always"' in schedule
    for field in ('"weekdays"', '"start_time"', '"end_time"'):
        assert field in schedule
    assert "(weekday = json_object_get_int(day)) < 0" in schedule and "weekday > 6" in schedule
    assert "nc_aegis_app_block_time_ok" in schedule
    assert "nc_aegis_app_block_field_ok" in normalize
    assert "nc_aegis_app_block_text_ok" in normalize
    assert 'json_type_boolean' in normalize
    assert "start_minutes <= end_minutes" in RULESD
    assert "current_info.minutes >= start_minutes or current_info.minutes <= end_minutes" in RULESD


def test_preview_confirm_revision_and_transactions_fail_closed() -> None:
    upsert = between(DB, "struct json_object *jmx_aegis_app_block_upsert", "struct json_object *jmx_aegis_app_block_delete")
    delete = between(DB, "struct json_object *jmx_aegis_app_block_delete", "static int nc_rulesd_save_runtime_fields")
    for body in (upsert, delete):
        assert 'nc_json_bool_def(cfg, "preview", 0)' in body
        assert 'nc_json_bool_def(cfg, "confirm", 0)' in body
        assert '"confirmation_required"' in body
        assert '"revision_required"' in body
        assert '"revision_conflict"' in body
        assert 'nc_exec("BEGIN IMMEDIATE")' in body
        assert 'nc_exec("ROLLBACK")' in body
        assert 'nc_exec("COMMIT")' in body
        assert "revision=revision+1" in body
        assert '"rule_type_conflict"' in body
    assert "DELETE FROM network_control_rule WHERE id=?1 AND type='app'" in delete
    assert "DELETE FROM network_control_rule" not in upsert

    runtime = between(DB, "static void nc_aegis_app_block_runtime_fields", "static struct json_object *nc_aegis_app_block_error")
    for marker in (
        '"runtime", json_object_new_string("apply_pending")',
        '"applied", json_object_new_boolean(0)',
        '"degraded", json_object_new_boolean(1)',
        '"runtime_readback_supported", json_object_new_boolean(0)',
        '"appfilter_global_disabled"',
        '"appfilter_global_state_unavailable"',
        '"runtime_readback_unavailable_apply_pending"',
    ):
        assert marker in runtime
    assert "NC_AEGIS_APPFILTER_RUNTIME_FILE" in DB
    assert "nc_aegis_app_runtime_load" in DB
    assert "nc_aegis_app_expected_fingerprint" in DB
    assert "json_type_string" in DB
    assert "strtoll" in DB
    assert "duplicate" in DB
    assert "installed->app_hash_xor == app_hash_xor" in DB
    assert "installed->app_hash_sum == app_hash_sum" in DB
    assert "installed->mac_value == mac_value" in DB
    assert '"runtime_readback_supported", json_object_new_boolean(1)' in DB


def test_existing_rulesd_and_kernel_dataplane_are_the_only_apply_path() -> None:
    assert '#define NC_AEGIS_APPFILTER_REINIT_FILE "/tmp/appfilter_rules_state"' in DB
    assert 'local APPFILTER_STATE_FILE = "/tmp/appfilter_rules_state"' in RULESD
    assert 'core_call("rulesd_config_get")' in RULESD
    for call in (
        '"api":"add_app_filter_rule"',
        '"api":"mod_app_filter_rule"',
        '"api":"flush_app_filter_rule"',
    ):
        assert call in RULESD
    assert 'local dev_file = "/dev/jmx"' in RULESD
    assert "set_appfilter_rule_mac_list" in RULESD
    assert "set_appfilter_rule_app_id_list" in RULESD
    assert '"filter_quic_supported", json_object_new_boolean(0)' in DB
    assert f"NC_AEGIS_APPFILTER_MAX_RULES {MAX_RULES}" in DB
    assert "NC_AEGIS_APPFILTER_MAX_APP_IDS 1024" in DB
    assert "nc_aegis_app_block_runtime_id" in DB
    assert "nc_rulesd_repair_app_runtime_ids" in DB
    assert "SAVEPOINT repair_app_runtime_ids" in DB
    assert "ROLLBACK TO repair_app_runtime_ids" in DB
    assert "runtime_rule_id=excluded.runtime_rule_id" in DB
    assert '"runtime_rule_id_unavailable"' in DB
    assert "local mac_ok = set_appfilter_rule_mac_list" in RULESD
    assert "local app_ok = mac_ok and set_appfilter_rule_app_id_list" in RULESD
    assert "local numeric_id = tonumber(app_id)" in RULESD
    assert "table.insert(app_id_strs, tostring(numeric_id))" in RULESD
    assert "local quic_ok = app_ok and (tonumber(rule.filter_quic) or 0) == 0" in RULESD
    assert "partial kernel rule removed" in RULESD
    assert "local write_ok, write_err = file:write(json_str)" in RULESD
    assert "kernel_write_rejected" in RULESD
    assert "jmx_match_app_filter_rule_record" in KERNEL_FILTER
    assert "jmx_match_app_filter_rule_record(appid, client->mac, &rule_id)" in KERNEL_MAIN
    assert '"add_app_filter_rule"' in (JMX_ROOT / "jmx_config.c").read_text(encoding="utf-8")


def _schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE network_control_global(
          id INTEGER PRIMARY KEY, revision INTEGER NOT NULL, apply_state TEXT, updated_at INTEGER
        );
        CREATE TABLE network_control_rule(
          id TEXT PRIMARY KEY, type TEXT NOT NULL, enabled INTEGER NOT NULL,
          name TEXT NOT NULL, source TEXT NOT NULL, schedule TEXT NOT NULL,
          runtime_rule_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE network_control_app_rule(
          rule_id TEXT PRIMARY KEY, app_ids TEXT NOT NULL, action TEXT NOT NULL,
          filter_quic INTEGER NOT NULL
        );
        INSERT INTO network_control_global VALUES(1,1,'draft',0);
        INSERT INTO network_control_rule VALUES('keep-mac','mac',1,'keep','any','always',88);
        INSERT INTO network_control_rule VALUES('keep-url','url_access',1,'keep','any','always',0);
        """
    )


def _upsert(db: sqlite3.Connection, revision: int, rule: dict) -> int:
    try:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute("SELECT revision FROM network_control_global WHERE id=1").fetchone()[0]
        if current != revision:
            raise ValueError("revision_conflict")
        existing = db.execute("SELECT type,runtime_rule_id FROM network_control_rule WHERE id=?", (rule["id"],)).fetchone()
        if existing and existing[0] != "app":
            raise ValueError("rule_type_conflict")
        current_runtime_id = existing[1] if existing else 0
        used_runtime_ids = {
            row[0] for row in db.execute(
                "SELECT runtime_rule_id FROM network_control_rule WHERE type='app' AND id<>?",
                (rule["id"],),
            ).fetchall() if 0 < row[0] <= MAX_RULES
        }
        if current_runtime_id <= 0 or current_runtime_id in used_runtime_ids:
            current_runtime_id = next(candidate for candidate in range(1, MAX_RULES + 1)
                                      if candidate not in used_runtime_ids)
        changed = db.execute(
            "UPDATE network_control_global SET revision=revision+1 WHERE id=1 AND revision=?",
            (revision,),
        ).rowcount
        if changed != 1:
            raise ValueError("revision_conflict")
        db.execute(
            "INSERT INTO network_control_rule(id,type,enabled,name,source,schedule,runtime_rule_id) "
            "VALUES(?,'app',?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "enabled=excluded.enabled,name=excluded.name,source=excluded.source,schedule=excluded.schedule,"
            "runtime_rule_id=excluded.runtime_rule_id",
            (rule["id"], rule["enabled"], rule["name"], rule["source"], rule["schedule"],
             current_runtime_id),
        )
        db.execute(
            "INSERT INTO network_control_app_rule(rule_id,app_ids,action,filter_quic) VALUES(?,?,?,?) "
            "ON CONFLICT(rule_id) DO UPDATE SET app_ids=excluded.app_ids,action=excluded.action,"
            "filter_quic=excluded.filter_quic",
            (rule["id"], json.dumps(rule["app_ids"]), "block", rule["filter_quic"]),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return db.execute("SELECT revision FROM network_control_global WHERE id=1").fetchone()[0]


def _delete(db: sqlite3.Connection, revision: int, rule_id: str) -> int:
    try:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute("SELECT revision FROM network_control_global WHERE id=1").fetchone()[0]
        if current != revision:
            raise ValueError("revision_conflict")
        existing = db.execute("SELECT type FROM network_control_rule WHERE id=?", (rule_id,)).fetchone()
        if not existing:
            raise ValueError("rule_not_found")
        if existing[0] != "app":
            raise ValueError("rule_type_conflict")
        db.execute("UPDATE network_control_global SET revision=revision+1 WHERE id=1 AND revision=?", (revision,))
        db.execute("DELETE FROM network_control_app_rule WHERE rule_id=?", (rule_id,))
        db.execute("DELETE FROM network_control_rule WHERE id=? AND type='app'", (rule_id,))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return db.execute("SELECT revision FROM network_control_global WHERE id=1").fetchone()[0]


def _repair_runtime_ids(db: sqlite3.Connection) -> None:
    rows = db.execute(
        "SELECT id,runtime_rule_id FROM network_control_rule WHERE type='app' ORDER BY id"
    ).fetchall()
    if len(rows) > MAX_RULES:
        raise ValueError("runtime_rule_id_unavailable")
    used: set[int] = set()
    repaired: list[tuple[str, int]] = []
    for rule_id, runtime_id in rows:
        if 0 < runtime_id <= MAX_RULES and runtime_id not in used:
            used.add(runtime_id)
            repaired.append((rule_id, runtime_id))
        else:
            repaired.append((rule_id, 0))
    db.execute("SAVEPOINT repair_app_runtime_ids")
    try:
        for rule_id, runtime_id in repaired:
            if runtime_id:
                continue
            candidate = next(value for value in range(1, MAX_RULES + 1)
                             if value not in used)
            db.execute(
                "UPDATE network_control_rule SET runtime_rule_id=? WHERE id=? AND type='app'",
                (candidate, rule_id),
            )
            used.add(candidate)
        db.execute("RELEASE repair_app_runtime_ids")
    except Exception:
        db.execute("ROLLBACK TO repair_app_runtime_ids")
        db.execute("RELEASE repair_app_runtime_ids")
        raise


def test_legacy_zero_duplicate_and_out_of_range_runtime_ids_are_repaired() -> None:
    db = sqlite3.connect(":memory:")
    _schema(db)
    for rule_id, runtime_id in (
        ("app-a", 0),
        ("app-b", 7),
        ("app-c", 7),
        ("app-d", 999),
    ):
        db.execute(
            "INSERT INTO network_control_rule VALUES(?,?,1,?,'any','always',?)",
            (rule_id, "app", rule_id, runtime_id),
        )
        db.execute(
            "INSERT INTO network_control_app_rule VALUES(?,'[1001]','block',0)",
            (rule_id,),
        )
    _repair_runtime_ids(db)
    repaired = db.execute(
        "SELECT runtime_rule_id FROM network_control_rule WHERE type='app' ORDER BY id"
    ).fetchall()
    assert all(0 < row[0] <= MAX_RULES for row in repaired)
    assert len({row[0] for row in repaired}) == len(repaired)
    assert db.execute(
        "SELECT runtime_rule_id FROM network_control_rule WHERE id='app-b'"
    ).fetchone()[0] == 7


def test_sqlite_transaction_preserves_non_app_rules_and_locks_revision() -> None:
    db = sqlite3.connect(":memory:")
    _schema(db)
    rule = {
        "id": "aegis-youtube",
        "enabled": 1,
        "name": "Block YouTube",
        "source": "bc:24:11:90:f7:ca",
        "schedule": "always",
        "app_ids": [1001, 1002],
        "filter_quic": 1,
    }
    assert _upsert(db, 1, rule) == 2
    first_runtime_id = db.execute(
        "SELECT runtime_rule_id FROM network_control_rule WHERE id=?", (rule["id"],)
    ).fetchone()[0]
    assert first_runtime_id > 0
    second = {**rule, "id": "aegis-tiktok", "name": "Block TikTok", "app_ids": [2001]}
    assert _upsert(db, 2, second) == 3
    second_runtime_id = db.execute(
        "SELECT runtime_rule_id FROM network_control_rule WHERE id=?", (second["id"],)
    ).fetchone()[0]
    assert second_runtime_id > 0 and second_runtime_id != first_runtime_id
    assert _upsert(db, 3, {**rule, "name": "Block YouTube Updated"}) == 4
    assert db.execute(
        "SELECT runtime_rule_id FROM network_control_rule WHERE id=?", (rule["id"],)
    ).fetchone()[0] == first_runtime_id
    assert db.execute("SELECT id,type FROM network_control_rule ORDER BY id").fetchall() == [
        ("aegis-tiktok", "app"), ("aegis-youtube", "app"), ("keep-mac", "mac"),
        ("keep-url", "url_access")
    ]
    try:
        _upsert(db, 3, {**rule, "name": "stale"})
        raise AssertionError("stale revision unexpectedly committed")
    except ValueError as exc:
        assert str(exc) == "revision_conflict"
    assert db.execute("SELECT name FROM network_control_rule WHERE id=?", (rule["id"],)).fetchone()[0] == "Block YouTube Updated"
    assert _delete(db, 4, rule["id"]) == 5
    assert db.execute("SELECT id,type FROM network_control_rule ORDER BY id").fetchall() == [
        ("aegis-tiktok", "app"), ("keep-mac", "mac"), ("keep-url", "url_access")
    ]


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Aegis app block contract tests")
