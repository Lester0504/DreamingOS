from pathlib import Path
import re
import sqlite3


ROOT = Path(__file__).resolve().parents[1]
LOGD = (ROOT / "src/logd/logd_event.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


SOURCE_SQL = """
(CASE
 WHEN COALESCE(NULLIF(json_extract(detail_json,'$.source_id'),''),'')<>''
 THEN json_extract(detail_json,'$.source_id')
 WHEN category='kernel' OR source IN ('kernel','kernel_log') THEN 'kernel'
 WHEN category='audit' OR source='audit' THEN 'audit'
 WHEN source IN ('notification','notifyd') THEN 'notification'
 WHEN source='alarm' THEN 'alarm'
 WHEN source='syslog' THEN 'syslog'
 ELSE 'general' END)
"""

AUDIT_SQL = """
COALESCE(NULLIF(json_extract(detail_json,'$.source_id'),''),'')='audit'
OR source='audit' OR category='audit'
OR COALESCE(json_extract(detail_json,'$.web_audit'),0)=1
"""


def fixture_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE log_events(id TEXT, source TEXT, category TEXT, detail_json TEXT)")
    db.executemany(
        "INSERT INTO log_events VALUES(?,?,?,?)",
        [
            ("kernel", "kernel_log", "kernel", '{}'),
            ("web", "audit", "audit", '{"source_id":"audit","web_audit":true}'),
            ("dropbear", "system_log", "auth", '{"program":"dropbear"}'),
            ("notify", "notifyd", "system", '{}'),
            ("syslog", "syslog", "system", '{}'),
            ("general", "system_log", "system", '{}'),
        ],
    )
    return db


def ids(db, predicate="1=1", params=()):
    return {
        row[0]
        for row in db.execute(
            f"SELECT id FROM log_events WHERE {predicate}", params
        )
    }


def test_type_sets_are_disjoint_and_complete():
    db = fixture_db()
    audit = ids(db, f"({AUDIT_SQL})")
    general = ids(db, f"NOT ({AUDIT_SQL})")
    all_rows = ids(db)
    assert audit == {"web"}
    assert "dropbear" in general
    assert audit.isdisjoint(general)
    assert audit | general == all_rows


def test_source_filter_uses_emitted_canonical_source_id():
    db = fixture_db()
    assert ids(db, f"{SOURCE_SQL}=?", ("kernel",)) == {"kernel"}
    assert ids(db, f"{SOURCE_SQL}=?", ("audit",)) == {"web"}
    assert ids(db, f"{SOURCE_SQL}=?", ("notification",)) == {"notify"}
    assert ids(db, f"{SOURCE_SQL} IN (?,?)", ("syslog", "general")) == {
        "syslog", "dropbear", "general"
    }


def test_all_source_aliases_and_strict_type_validation_are_wired():
    assert '{ "sources", "sourceIds", "source_ids" }' in LOGD
    assert 'return -2;' in LOGD
    assert 'else if (type[0])' not in LOGD
    for capability in ("log_type_filter", "log_source_filter", "web_audit_stream"):
        assert capability in LOGD
        assert capability in WEBD


def test_search_response_is_flat_and_keeps_exact_pagination():
    assert 'webd_logs_v2_flat_response("unifi_search"' in WEBD
    flatten = re.search(
        r"static struct json_object \*webd_logs_flatten_payload\(.*?\n}\n",
        WEBD,
        re.S,
    )
    assert flatten
    body = flatten.group(0)
    assert '"items"' in body and '"data"' in body
    assert '"total_element_count"' in body
    assert '"total_page_count"' in LOGD


def test_web_audit_is_dual_written_and_redacted():
    assert 'INSERT INTO api_audit_log' in WEBD
    assert '"dreamingwrt.logd", "event_add"' in WEBD
    assert '"source_id", json_object_new_string("audit")' in WEBD
    assert '"web_audit", json_object_new_boolean(1)' in WEBD
    assert 'webd_ai_redact_text(before_value' in WEBD
    assert 'webd_ai_redact_text(after_value' in WEBD
    assert 'webd_ai_redact_text(failure_reason' in WEBD
    for secret in ("password", "token", "secret", "authorization", "cookie", "private_key", "api_key", "otp"):
        assert secret in WEBD


def test_login_success_and_failure_enter_audit_without_request_payload():
    helper = re.search(
        r"static void webd_audit_login_result\(.*?\n}\n", WEBD, re.S
    )
    assert helper
    body = helper.group(0)
    assert "auth.login.success" in body
    assert "auth.login.failed" in body
    assert "source_ip" in body
    assert 'app_nc_json_str(request, "username", "")' in body
    assert 'app_nc_json_str(request, "password"' not in body
    assert 'app_nc_json_str(request, "otp"' not in body
    assert 'app_nc_json_str(request, "token"' not in body
    assert WEBD.count("webd_audit_login_result(body_json") == 2
