#!/usr/bin/env python3
"""PCDN content-filter storage, REST, parser, and guarded-apply contracts."""

from pathlib import Path
import subprocess
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
AEGIS = ROOT / "src" / "aegisxd"
DB = (AEGIS / "aegisxd_db.c").read_text(encoding="utf-8")
PCDN = (AEGIS / "aegisxd_pcdn.c").read_text(encoding="utf-8")
CONTENT = (AEGIS / "aegisxd_content.c").read_text(encoding="utf-8")
DATAPLANE = (AEGIS / "aegisxd_dataplane.c").read_text(encoding="utf-8")
STATUS = (AEGIS / "aegisxd_status.c").read_text(encoding="utf-8")
HITS = (AEGIS / "aegisxd_hits.c").read_text(encoding="utf-8")
UBUS = (AEGIS / "aegisxd_ubus.c").read_text(encoding="utf-8")
MAIN = (AEGIS / "aegisxd_main.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src" / "webd" / "jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src" / "webd" / "jmx_app_perms.c").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def test_config_db_keeps_only_low_frequency_pcdn_metadata() -> None:
    require_all(DB, (
        "CREATE TABLE IF NOT EXISTS aegis_pcdn_settings",
        "artifact_path TEXT NOT NULL DEFAULT ''",
        "artifact_sha256 TEXT NOT NULL DEFAULT ''",
        "rule_count INTEGER NOT NULL DEFAULT 0",
        "DROP TABLE IF EXISTS aegis_pcdn_rules",
    ), "PCDN config metadata schema")
    assert "CREATE TABLE IF NOT EXISTS aegis_pcdn_rules" not in DB
    assert "INSERT INTO aegis_pcdn_rules" not in PCDN
    assert "DELETE FROM aegis_pcdn_rules" not in PCDN


def test_runtime_paths_are_overrideable_without_changing_production_defaults() -> None:
    internal = (AEGIS / "aegisxd_internal.h").read_text(encoding="utf-8")
    require_all(internal, (
        "#ifndef AEGISXD_CONFIG_DIR",
        '#define AEGISXD_CONFIG_DIR "/etc/dreamingwrt"',
        '#define AEGISXD_CONFIG_DB_PATH AEGISXD_CONFIG_DIR "/config.db"',
        '#define AEGISXD_DB_PATH AEGISXD_CONFIG_DIR "/aegis.db"',
        "#ifndef AEGISXD_RUNTIME_DIR",
        "#ifndef AEGISXD_WORK_DIR",
        '#define AEGISXD_FEED_DIR AEGISXD_WORK_DIR "/feeds"',
    ), "overrideable Aegis runtime paths")
    assert "aegisxd_mkdir_p(AEGISXD_CONFIG_DIR" in DB


def test_verified_artifact_is_content_addressed_and_guarded() -> None:
    require_all(PCDN, (
        'AEGISXD_FEED_DIR "/pcdn-openhosts-"',
        'PCDN_ARTIFACT_SUFFIX ".domains"',
        "pcdn_sha256_file(canonical, sha256)",
        "pcdn_artifact_path_ok",
        "pcdn_artifact_ready",
        "pcdn_artifact_verified",
        "lstat(s->artifact_path",
        "PCDN_MAX_BYTES",
        "PCDN_MAX_RULES",
        "pcdn_rules_invalid_or_empty",
        "pcdn_artifact_repair_failed",
        "pcdn_artifact_install",
        "previous verified artifact remains authoritative",
        "revision=revision+1",
        "enabled=1 OR apply_state IN ('active','pending','applying')",
        'do_apply ? "applying" : "pending"',
        "pcdn_cleanup_artifacts(final, previous.artifact_path)",
        '"retained_max"',
    ), "verified PCDN feed lifecycle")
    assert "system(" not in PCDN and "popen(" not in PCDN


def test_installed_state_is_persisted_and_read_back() -> None:
    require_all(PCDN, (
        "aegisxd_pcdn_active_state_json",
        'AEGISXD_RUNTIME_DIR "/active.json"',
        '"artifact_sha256"',
        '"rule_count"',
        '"readback_ok"',
        '"effective_blocking"',
        '"effective_monitoring"',
        'aegisxd_json_bool(installed, "blocking", 0)',
    ), "PCDN installed-state readback")
    require_all(DATAPLANE, (
        "struct json_object *pcdn = aegisxd_pcdn_active_state_json()",
        'json_object_object_add(o, "pcdn", pcdn)',
        "aegisxd_apply_write_state(state)",
    ), "PCDN active state persistence")


def test_dnsmasq_compilation_streams_rules_and_preserves_allow_priority() -> None:
    require_all(PCDN, (
        "int aegisxd_pcdn_write_dnsmasq",
        "pcdn_artifact_verified(&settings)",
        "allow_cb(domain, opaque)",
        '"# aegis pcdn-mode=monitor source=%s artifact=%s rules=%d\\n"',
        "aegisxd_pcdn_effective_rule_count",
        'address=/%s/0.0.0.0',
        'address=/%s/::',
        "seen > PCDN_MAX_RULES",
        "seen != (size_t)settings.rule_count",
    ), "PCDN dnsmasq artifact compiler")
    require_all(CONTENT, (
        "content_pcdn_allow_cb",
        "content_domain_list_matches(&f->allows, domain)",
        "aegisxd_pcdn_write_dnsmasq",
    ), "PCDN allow-before-block merge")
    require_all(DATAPLANE, (
        "explicit_count = aegisxd_content_filter_write_explicit_blocks(filter, sink)",
        "explicit_count < 0",
        "explicit_written = aegisxd_content_filter_write_explicit_blocks(filter, fp)",
        "explicit_written < 0",
        "ok = 0;",
    ), "PCDN compiler failure propagation")


def test_contract_exposes_real_first_phase_boundaries() -> None:
    for text in (PCDN, STATUS):
        require_all(text, (
            '"pcdn_filter_supported"',
            '"pcdn_feed_update"',
            '"pcdn_guarded_apply"',
            '"pcdn_monitor_supported"',
            '"pcdn_hit_monitoring_supported"',
            '"dnsmasq_domain_block_or_query_monitor"',
        ), "PCDN capabilities")
    assert '"hit_count_supported"' in PCDN
    assert '"blocked_count"' in PCDN
    assert '"observed_count"' in PCDN
    assert '"pcdn_hit_count_supported"' in STATUS
    require_all(PCDN, (
        'PCDN_SOURCE_LICENSE "MIT"',
        '"743859910/OpenHosts"',
        '"port_protocol_block_supported"',
        '"wildcard_regex_supported"',
        'json_object_new_string("monitor")',
        '"dnsmasq_query_monitor"',
    ), "PCDN source and unsupported boundaries")


def test_installed_dnsmasq_provenance_drives_pcdn_hit_attribution() -> None:
    require_all(DATAPLANE, (
        '"# aegis-provenance-version=1\\n"',
        '"# aegis provenance=category source=domain_reputation domain=%s\\n"',
        '"content_revision"',
    ), "installed dnsmasq provenance")
    require_all(CONTENT, (
        "aegisxd_content_installed_dns_rule_match",
        "content_provenance_ensure",
        "content_provenance_load_file",
    ), "installed provenance parser")
    require_all(HITS, (
        '"pcdn_dns_observed"',
        '"pcdn_dnsmasq_query_observed"',
        'monitor ? "info" : "warning"',
        'monitor ? "monitor" : "block"',
        "aegisxd_pcdn_installed_monitor_match",
    ), "PCDN monitor event attribution")
    require_all(PCDN, (
        '"# aegis provenance=pcdn source=%s domain=%s\\n"',
        "aegisxd_pcdn_installed_domain_match",
        "aegisxd_content_installed_dns_rule_match",
        "pcdn_match_cache_load",
    ), "PCDN installed attribution")
    hits = (AEGIS / "aegisxd_hits.c").read_text(encoding="utf-8")
    require_all(hits, (
        '"pcdn_dns_block"',
        '"aegisxd.pcdn"',
        '"pcdn_dnsmasq_sinkhole"',
        '"attribution_precision"',
        '"occurrence_count=occurrence_count+1,"',
        '"events_unattributed_ignored"',
        '"restart_replay_prevented"',
        '"inode_rotation_supported"',
        '"partial_line_buffering_supported"',
    ), "PCDN DNS hit producer")


def test_ubus_worker_rest_rbac_csrf_and_audit_are_wired() -> None:
    require_all(UBUS, (
        'UBUS_METHOD("content_pcdn_get"',
        'UBUS_METHOD("content_pcdn_validate"',
        'UBUS_METHOD("content_pcdn_set"',
        'UBUS_METHOD("content_pcdn_sync"',
    ), "PCDN ubus")
    require_all(MAIN, (
        '"--pcdn-sync-worker"',
        "aegisxd_pcdn_sync_worker_main(job_id)",
    ), "PCDN background worker")
    require_all(WEBD, (
        '"/api/v1/aegis/content-policy/pcdn"',
        '"/api/v1/aegis/content-policy/pcdn/validate"',
        '"/api/v1/aegis/content-policy/pcdn/sync"',
        '"aegis.content.pcdn.sync"',
        '"aegis.content.pcdn.set"',
        '"pcdn_revision_conflict"',
        '"pcdn_revision_required"',
        '"invalid_pcdn_revision"',
    ), "PCDN authenticated REST and audit")
    require_all(PERMS, (
        '{ "/api/v1/aegis/content-policy/pcdn",   "GET", JMX_RISK_LOW }',
        '{ "/api/v1/aegis/content-policy/pcdn",   "PUT,PATCH", JMX_RISK_MEDIUM }',
        '{ "/api/v1/aegis/content-policy/pcdn/sync", "POST", JMX_RISK_MEDIUM }',
    ), "PCDN RBAC")
    assert "webd_cookie_write_csrf_ok" in WEBD


def test_parser_behavior() -> None:
    harness = textwrap.dedent(r'''
        #include <assert.h>
        #include <stdio.h>
        #include <string.h>
        #include "aegisxd_pcdn_parser.h"

        static void accept(const char *raw, const char *expected) {
            char line[512], out[AEGISXD_PCDN_DOMAIN_BUFSZ];
            snprintf(line, sizeof(line), "%s", raw);
            assert(aegisxd_pcdn_parse_line(line, out, sizeof(out)) == 1);
            assert(strcmp(out, expected) == 0);
        }
        static void ignore(const char *raw) {
            char line[512], out[AEGISXD_PCDN_DOMAIN_BUFSZ];
            snprintf(line, sizeof(line), "%s", raw);
            assert(aegisxd_pcdn_parse_line(line, out, sizeof(out)) == 0);
        }
        static void reject(const char *raw) {
            char line[512], out[AEGISXD_PCDN_DOMAIN_BUFSZ];
            int rc;
            snprintf(line, sizeof(line), "%s", raw);
            rc = aegisxd_pcdn_parse_line(line, out, sizeof(out));
            if (rc != -1) fprintf(stderr, "reject mismatch raw=%s rc=%d out=%s\n", raw, rc, out);
            assert(rc == -1);
        }
        int main(void) {
            accept("||PCDN.Example.COM^", "pcdn.example.com");
            accept("0.0.0.0 cache.example.net # comment", "cache.example.net");
            accept("127.0.0.1 p2p.example.cn", "p2p.example.cn");
            accept("::1 v6-host.example.org", "v6-host.example.org");
            accept("bare.example.com", "bare.example.com");
            ignore("# comment"); ignore("   "); ignore("! adblock header");
            reject("@@||allow.example.com^");
            reject("||*pcdn*.example.com^");
            reject("/.*pcdn.*example\\.com/");
            reject("https://evil.example/x");
            reject("1.2.3.4");
            reject("bad_domain.example.com");
            reject("-bad.example.com");
            return 0;
        }
    ''')
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "pcdn_parser_test.c"
        binary = Path(td) / "pcdn_parser_test"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-I", str(AEGIS), str(source), str(AEGIS / "aegisxd_pcdn_parser.c"),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)
