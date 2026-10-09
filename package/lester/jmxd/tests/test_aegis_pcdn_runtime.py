#!/usr/bin/env python3
"""Isolated runtime tests for PCDN SQLite and artifact lifecycle."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
AEGIS = ROOT / "src" / "aegisxd"


def _pkg_config(*packages: str) -> list[str]:
    # PKG_CONFIG is still honoured inside the resolver; the difference is that a
    # package with no .pc file (json-c on 31.6) now falls back to a prefix
    # search instead of aborting the fixture.
    return apd_test_deps.package_flags(*packages)


def _run_binary(binary: Path) -> None:
    runner = shlex.split(os.environ.get("AEGISXD_TEST_RUNNER", ""))
    subprocess.run([*runner, str(binary)], check=True)


def _write_stub_headers(root: Path) -> None:
    (root / "libubox").mkdir(parents=True)
    (root / "libubox" / "blobmsg.h").write_text(
        "struct blob_attr { int unused; }; struct blob_buf { int unused; };\n",
        encoding="ascii",
    )
    (root / "libubox" / "blobmsg_json.h").write_text(
        "char *blobmsg_format_json(struct blob_attr *, int);\n", encoding="ascii"
    )
    (root / "libubox" / "uloop.h").write_text("\n", encoding="ascii")
    (root / "libubox" / "utils.h").write_text(
        "#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))\n", encoding="ascii"
    )
    (root / "libubus.h").write_text(
        "struct ubus_context { int unused; };\n", encoding="ascii"
    )


def test_pcdn_sqlite_revision_artifact_and_readback_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-pcdn-runtime-") as tmp:
        sandbox = Path(tmp)
        include = sandbox / "include"
        config = sandbox / "etc" / "dreamingwrt"
        work = sandbox / "opt" / "aegis"
        runtime = sandbox / "run" / "aegis"
        _write_stub_headers(include)

        source = sandbox / "pcdn_runtime.c"
        binary = sandbox / "pcdn_runtime"
        source.write_text(
            textwrap.dedent(
                r'''
                #include <assert.h>
                #include "aegisxd_internal.h"
                int aegisxd_certificate_schema_init(void) { return 0; }
                #include "aegisxd_db.c"
                #include "aegisxd_pcdn_parser.c"
                #include "aegisxd_pcdn.c"

                sqlite3 *g_aegisxd_config_db;
                sqlite3 *g_aegisxd_db;
                struct ubus_context *g_aegisxd_ubus;
                struct blob_buf g_aegisxd_blob;
                static int monitor_provenance;

                int aegisxd_content_revision_get(void) { return 0; }
                int aegisxd_content_dns_provenance_ready(void) { return 1; }
                int aegisxd_content_installed_dns_rule_match(const char *domain,
                    char kind[32], char source_id[64], char matched_rule[254]) {
                    snprintf(kind, 32, "%s", monitor_provenance ? "pcdn_monitor" : "pcdn");
                    snprintf(source_id, 64, "%s", "openhosts-pcdn");
                    snprintf(matched_rule, 254, "%s", monitor_provenance && domain &&
                             !strcmp(domain, "edge.p2p.example.net") ?
                             "p2p.example.net" : (domain ? domain : ""));
                    return domain && domain[0];
                }

                int64_t aegisxd_now_s(void) { return (int64_t)time(NULL); }

                int aegisxd_mkdir_p(const char *path, mode_t mode) {
                    char buf[AEGISXD_MAX_PATH], *p;
                    if (!path || path[0] != '/' || strlen(path) >= sizeof(buf)) return -1;
                    snprintf(buf, sizeof(buf), "%s", path);
                    for (p = buf + 1; *p; p++) {
                        if (*p != '/') continue;
                        *p = '\0';
                        if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
                        *p = '/';
                    }
                    return mkdir(buf, mode) == 0 || errno == EEXIST ? 0 : -1;
                }

                void aegisxd_json_add_string(struct json_object *o, const char *key,
                                             const char *value) {
                    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
                }
                const char *aegisxd_json_str(struct json_object *o, const char *key,
                                             const char *def) {
                    struct json_object *v = NULL;
                    return o && json_object_object_get_ex(o, key, &v) &&
                           json_object_is_type(v, json_type_string) ? json_object_get_string(v) : def;
                }
                int aegisxd_json_bool(struct json_object *o, const char *key, int def) {
                    struct json_object *v = NULL;
                    return o && json_object_object_get_ex(o, key, &v) ?
                           !!json_object_get_boolean(v) : def;
                }
                struct json_object *aegisxd_error(const char *code, const char *message) {
                    struct json_object *o = json_object_new_object();
                    json_object_object_add(o, "ok", json_object_new_boolean(0));
                    aegisxd_json_add_string(o, "error", code);
                    aegisxd_json_add_string(o, "message", message);
                    return o;
                }
                const char *aegisxd_sqlite_text(sqlite3_stmt *st, int col, const char *def) {
                    const unsigned char *s = sqlite3_column_text(st, col);
                    return s ? (const char *)s : def;
                }
                int aegisxd_seed_builtin_feeds(void) { return 0; }
                int aegisxd_job_result_ok(struct json_object *result) {
                    return aegisxd_json_bool(result, "ok", 0);
                }
                int aegisxd_job_running_count(void) { return 0; }
                int aegisxd_job_record_start(const char *job_id, const char *op,
                                             const char *feed_id, int dry_run) {
                    (void)job_id; (void)op; (void)feed_id; (void)dry_run; return 0;
                }
                void aegisxd_job_record_pid(const char *job_id, pid_t pid) {
                    (void)job_id; (void)pid;
                }
                void aegisxd_job_record_finish(const char *job_id,
                                               struct json_object *result) {
                    (void)job_id; (void)result;
                }
                struct json_object *aegisxd_feed_jobs_json(int *running_out) {
                    if (running_out) *running_out = 0;
                    return json_object_new_array();
                }
                struct json_object *aegisxd_apply(struct json_object *body) {
                    struct json_object *o = json_object_new_object();
                    (void)body;
                    json_object_object_add(o, "ok", json_object_new_boolean(1));
                    json_object_object_add(o, "dataplane_changed", json_object_new_boolean(0));
                    return o;
                }
                char *blobmsg_format_json(struct blob_attr *msg, int list) {
                    (void)msg; (void)list; return NULL;
                }

                static void must_exec(sqlite3 *db, const char *sql) {
                    char *error = NULL;
                    if (sqlite3_exec(db, sql, NULL, NULL, &error) != SQLITE_OK) {
                        fprintf(stderr, "SQL failed: %s\n", error ? error : "unknown");
                        sqlite3_free(error);
                        abort();
                    }
                }
                static int scalar_int(sqlite3 *db, const char *sql) {
                    sqlite3_stmt *st = NULL;
                    int value;
                    assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
                    assert(sqlite3_step(st) == SQLITE_ROW);
                    value = sqlite3_column_int(st, 0);
                    sqlite3_finalize(st);
                    return value;
                }
                static const char *error_code(struct json_object *o) {
                    return aegisxd_json_str(o, "error", "");
                }
                static void write_text(const char *path, const char *text) {
                    FILE *fp = fopen(path, "wb");
                    assert(fp);
                    assert(fwrite(text, 1, strlen(text), fp) == strlen(text));
                    assert(fclose(fp) == 0);
                }
                static int allow_all(const char *domain, void *opaque) {
                    (void)domain;
                    (void)opaque;
                    return 1;
                }
                static void sha_path(const char *text, char path[AEGISXD_MAX_PATH],
                                     char sha[65]) {
                    char tmp[AEGISXD_MAX_PATH];
                    snprintf(tmp, sizeof(tmp), "%s/hash-input", AEGISXD_RUNTIME_DIR);
                    write_text(tmp, text);
                    assert(pcdn_sha256_file(tmp, sha) == 0);
                    unlink(tmp);
                    assert(snprintf(path, AEGISXD_MAX_PATH, PCDN_ARTIFACT_PREFIX "%s"
                                    PCDN_ARTIFACT_SUFFIX, sha) < AEGISXD_MAX_PATH);
                }

                int main(void) {
                    sqlite3 *legacy = NULL;
                    struct json_object *body, *resp, *active, *cleanup;
                    struct json_object *installed = NULL, *settings = NULL;
                    char artifact[AEGISXD_MAX_PATH], sha[65], dns[AEGISXD_MAX_PATH];
                    char old1[AEGISXD_MAX_PATH], old2[AEGISXD_MAX_PATH];
                    char candidate[AEGISXD_MAX_PATH], installed_path[AEGISXD_MAX_PATH];
                    char actual_sha[65];
                    int installed_new = 0, repaired = 0;
                    const char *rules = "cache.example.com\np2p.example.net\n";
                    FILE *rendered;

                    assert(aegisxd_mkdir_p(AEGISXD_CONFIG_DIR, 0755) == 0);
                    assert(sqlite3_open(AEGISXD_CONFIG_DB_PATH, &legacy) == SQLITE_OK);
                    must_exec(legacy,
                        "CREATE TABLE aegis_pcdn_settings("
                        "id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0,"
                        "mode TEXT NOT NULL DEFAULT 'block' CHECK(mode='block'),"
                        "source_id TEXT NOT NULL DEFAULT 'openhosts-pcdn',"
                        "revision INTEGER NOT NULL DEFAULT 1,apply_state TEXT NOT NULL DEFAULT 'disabled',"
                        "last_error TEXT NOT NULL DEFAULT '',sync_state TEXT NOT NULL DEFAULT 'never',"
                        "sync_error TEXT NOT NULL DEFAULT '',rule_count INTEGER NOT NULL DEFAULT 0,"
                        "rejected_count INTEGER NOT NULL DEFAULT 0,last_sync_at INTEGER NOT NULL DEFAULT 0,"
                        "created_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0);"
                        "INSERT INTO aegis_pcdn_settings(id) VALUES(1);"
                        "CREATE TABLE aegis_pcdn_rules(domain TEXT PRIMARY KEY);");
                    sqlite3_close(legacy);

                    assert(aegisxd_db_init() == 0);
                    assert(scalar_int(g_aegisxd_config_db,
                        "SELECT COUNT(*) FROM pragma_table_info('aegis_pcdn_settings') "
                        "WHERE name IN ('artifact_path','artifact_sha256')") == 2);
                    assert(scalar_int(g_aegisxd_config_db,
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                        "AND name='aegis_pcdn_rules'") == 0);
                    must_exec(g_aegisxd_config_db,
                        "UPDATE aegis_pcdn_settings SET mode='monitor' WHERE id=1;");
                    assert(scalar_int(g_aegisxd_config_db,
                        "SELECT COUNT(*) FROM aegis_pcdn_settings WHERE mode='monitor'") == 1);
                    must_exec(g_aegisxd_config_db,
                        "UPDATE aegis_pcdn_settings SET mode='block' WHERE id=1;");

                    body = json_object_new_object();
                    json_object_object_add(body, "confirm", json_object_new_boolean(1));
                    resp = aegisxd_pcdn_set_json(body);
                    assert(!strcmp(error_code(resp), "pcdn_revision_required"));
                    json_object_put(resp);
                    json_object_object_add(body, "revision", json_object_new_int(99));
                    resp = aegisxd_pcdn_set_json(body);
                    assert(!strcmp(error_code(resp), "pcdn_revision_conflict"));
                    json_object_put(resp);
                    json_object_object_add(body, "revision", json_object_new_int(1));
                    resp = aegisxd_pcdn_set_json(body);
                    assert(aegisxd_json_bool(resp, "ok", 0));
                    json_object_put(resp);
                    json_object_put(body);
                    assert(scalar_int(g_aegisxd_config_db,
                                      "SELECT revision FROM aegis_pcdn_settings WHERE id=1") == 2);
                    body = json_object_new_object();
                    json_object_object_add(body, "enabled", json_object_new_boolean(0));
                    json_object_object_add(body, "mode", json_object_new_string("monitor"));
                    json_object_object_add(body, "confirm", json_object_new_boolean(1));
                    json_object_object_add(body, "revision", json_object_new_int(2));
                    resp = aegisxd_pcdn_set_json(body);
                    assert(aegisxd_json_bool(resp, "ok", 0));
                    json_object_put(resp);
                    json_object_put(body);
                    assert(scalar_int(g_aegisxd_config_db,
                        "SELECT COUNT(*) FROM aegis_pcdn_settings WHERE mode='monitor' AND revision=3") == 1);
                    must_exec(g_aegisxd_config_db,
                        "UPDATE aegis_pcdn_settings SET mode='block' WHERE id=1;");

                    sha_path(rules, artifact, sha);
                    write_text(artifact, rules);
                    {
                        sqlite3_stmt *st = NULL;
                        assert(sqlite3_prepare_v2(g_aegisxd_config_db,
                            "UPDATE aegis_pcdn_settings SET enabled=1,apply_state='active',"
                            "artifact_path=?,artifact_sha256=?,rule_count=2 WHERE id=1",
                            -1, &st, NULL) == SQLITE_OK);
                        sqlite3_bind_text(st, 1, artifact, -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(st, 2, sha, -1, SQLITE_TRANSIENT);
                        assert(sqlite3_step(st) == SQLITE_DONE);
                        sqlite3_finalize(st);
                    }
                    active = aegisxd_pcdn_active_state_json();
                    assert(aegisxd_json_bool(active, "enabled", 0));
                    json_object_put(active);
                    snprintf(dns, sizeof(dns), "%s/monitor.conf", AEGISXD_RUNTIME_DIR);
                    rendered = fopen(dns, "w+");
                    assert(rendered && aegisxd_pcdn_write_dnsmasq(rendered, NULL, NULL) == 2);
                    fclose(rendered);
                    must_exec(g_aegisxd_config_db,
                        "UPDATE aegis_pcdn_settings SET mode='monitor' WHERE id=1;");
                    active = aegisxd_pcdn_active_state_json();
                    assert(aegisxd_json_bool(active, "enabled", 0));
                    assert(aegisxd_json_bool(active, "monitoring", 0));
                    assert(!aegisxd_json_bool(active, "blocking", 1));
                    json_object_put(active);
                    rendered = tmpfile();
                    assert(rendered && aegisxd_pcdn_write_dnsmasq(rendered, NULL, NULL) == 2);
                    rewind(rendered);
                    { char monitor_line[512];
                      int control = 0, provenance = 0, address = 0;
                      while (fgets(monitor_line, sizeof(monitor_line), rendered)) {
                          control |= strstr(monitor_line, "# aegis pcdn-mode=monitor") != NULL;
                          provenance |= strstr(monitor_line, "# aegis monitor=pcdn") != NULL;
                          address |= strstr(monitor_line, "address=/") != NULL;
                      }
                      assert(control);
                      assert(provenance);
                      assert(!address); }
                    fclose(rendered);
                    assert(aegisxd_pcdn_effective_rule_count(dns) == 2);

                    rendered = fopen(dns, "w+");
                    assert(rendered && aegisxd_pcdn_write_dnsmasq(
                        rendered, allow_all, NULL) == 0);
                    rewind(rendered);
                    { char monitor_line[512];
                      int control = 0, provenance = 0, address = 0;
                      while (fgets(monitor_line, sizeof(monitor_line), rendered)) {
                          control |= strstr(monitor_line, "# aegis pcdn-mode=monitor") != NULL;
                          provenance |= strstr(monitor_line, "# aegis monitor=pcdn") != NULL;
                          address |= strstr(monitor_line, "address=/") != NULL;
                      }
                      assert(control);
                      assert(!provenance);
                      assert(!address); }
                    fclose(rendered);
                    assert(aegisxd_pcdn_effective_rule_count(dns) == 0);
                    {
                        char state[4096];
                        snprintf(state, sizeof(state),
                            "{\"scope\":\"dns_filter\",\"content_revision\":0,"
                            "\"dnsmasq_conf_file\":\"%s\",\"pcdn\":{\"enabled\":true,"
                            "\"mode\":\"monitor\",\"artifact_sha256\":\"%s\","
                            "\"rule_count\":2,\"effective_rule_count\":0,"
                            "\"dataplane\":\"dnsmasq_query_monitor\"}}", dns, sha);
                        snprintf(old1, sizeof(old1), "%s/active.json", AEGISXD_RUNTIME_DIR);
                        write_text(old1, state);
                    }
                    resp = aegisxd_pcdn_get_json();
                    assert(json_object_object_get_ex(resp, "installed", &installed));
                    assert(json_object_get_int(json_object_object_get(
                        installed, "effective_rule_count")) == 0);
                    assert(aegisxd_json_bool(installed, "monitoring", 0));
                    assert(!aegisxd_json_bool(installed, "blocking", 1));
                    assert(json_object_object_get_ex(resp, "settings", &settings));
                    assert(aegisxd_json_bool(settings, "effective_monitoring", 0));
                    assert(!aegisxd_json_bool(settings, "effective_blocking", 1));
                    json_object_put(resp);
                    must_exec(g_aegisxd_config_db,
                        "UPDATE aegis_pcdn_settings SET mode='block' WHERE id=1;");

                    unlink(artifact);
                    assert(symlink("missing", artifact) == 0);
                    active = aegisxd_pcdn_active_state_json();
                    assert(!aegisxd_json_bool(active, "enabled", 1));
                    json_object_put(active);
                    rendered = tmpfile();
                    assert(rendered && aegisxd_pcdn_write_dnsmasq(rendered, NULL, NULL) == -1);
                    fclose(rendered);
                    unlink(artifact);

                    write_text(artifact, "corrupt.example\n");
                    active = aegisxd_pcdn_active_state_json();
                    assert(!aegisxd_json_bool(active, "enabled", 1));
                    json_object_put(active);
                    snprintf(candidate, sizeof(candidate), "%s/repair-candidate",
                             AEGISXD_RUNTIME_DIR);
                    write_text(candidate, rules);
                    assert(pcdn_artifact_install(candidate, sha, installed_path,
                                                 &installed_new, &repaired) == 0);
                    assert(!strcmp(installed_path, artifact));
                    assert(installed_new == 0 && repaired == 1);
                    assert(pcdn_sha256_file(artifact, actual_sha) == 0);
                    assert(!strcmp(actual_sha, sha));

                    unlink(artifact);
                    snprintf(candidate, sizeof(candidate), "%s/new-candidate",
                             AEGISXD_RUNTIME_DIR);
                    write_text(candidate, rules);
                    installed_new = repaired = 0;
                    assert(pcdn_artifact_install(candidate, sha, installed_path,
                                                 &installed_new, &repaired) == 0);
                    assert(!strcmp(installed_path, artifact));
                    assert(installed_new == 1 && repaired == 0);

                    snprintf(dns, sizeof(dns), "%s/installed.conf", AEGISXD_RUNTIME_DIR);
                    write_text(dns,
                        "# aegis provenance=pcdn source=openhosts-pcdn "
                        "domain=cache.example.com\n"
                        "address=/cache.example.com/0.0.0.0\n");
                    {
                        char state[4096];
                        snprintf(state, sizeof(state),
                            "{\"scope\":\"dns_filter\",\"content_revision\":0,"
                            "\"dnsmasq_conf_file\":\"%s\",\"pcdn\":{\"enabled\":true,"
                            "\"artifact_sha256\":\"%s\",\"rule_count\":2,"
                            "\"dataplane\":\"dnsmasq_domain_block\"}}", dns, sha);
                        snprintf(old1, sizeof(old1), "%s/active.json", AEGISXD_RUNTIME_DIR);
                        write_text(old1, state);
                    }
                    resp = aegisxd_pcdn_get_json();
                    assert(json_object_object_get_ex(resp, "installed", &installed));
                    assert(aegisxd_json_bool(installed, "readback_ok", 0));
                    assert(json_object_object_get_ex(resp, "settings", &settings));
                    assert(aegisxd_json_bool(settings, "effective_blocking", 0));
                    json_object_put(resp);
                    write_text(dns,
                        "# aegis pcdn-mode=monitor source=openhosts-pcdn artifact=test rules=2\n"
                        "# aegis monitor=pcdn source=openhosts-pcdn "
                        "domain=cache.example.com\n");
                    {
                        char state[4096];
                        snprintf(state, sizeof(state),
                            "{\"scope\":\"dns_filter\",\"content_revision\":0,"
                            "\"dnsmasq_conf_file\":\"%s\",\"pcdn\":{\"enabled\":true,"
                            "\"mode\":\"monitor\",\"artifact_sha256\":\"%s\",\"rule_count\":2,"
                            "\"dataplane\":\"dnsmasq_query_monitor\"}}", dns, sha);
                        write_text(old1, state);
                    }
                    resp = aegisxd_pcdn_get_json();
                    assert(json_object_object_get_ex(resp, "installed", &installed));
                    assert(aegisxd_json_bool(installed, "readback_ok", 0));
                    assert(aegisxd_json_bool(installed, "monitoring", 0));
                    assert(!aegisxd_json_bool(installed, "blocking", 1));
                    assert(json_object_object_get_ex(resp, "settings", &settings));
                    assert(aegisxd_json_bool(settings, "effective_monitoring", 0));
                    assert(!aegisxd_json_bool(settings, "effective_blocking", 1));
                    json_object_put(resp);
                    {
                        char matched[254], installed_sha[65];
                        monitor_provenance = 1;
                        assert(aegisxd_pcdn_installed_monitor_match(
                            "edge.p2p.example.net", matched, installed_sha));
                        assert(!strcmp(matched, "p2p.example.net"));
                        assert(!strcmp(installed_sha, sha));
                        assert(!aegisxd_pcdn_installed_monitor_match(
                            "outside.example", matched, installed_sha));
                        monitor_provenance = 0;
                    }

                    snprintf(old1, sizeof(old1), PCDN_ARTIFACT_PREFIX
                             "1111111111111111111111111111111111111111111111111111111111111111"
                             PCDN_ARTIFACT_SUFFIX);
                    snprintf(old2, sizeof(old2), PCDN_ARTIFACT_PREFIX
                             "2222222222222222222222222222222222222222222222222222222222222222"
                             PCDN_ARTIFACT_SUFFIX);
                    write_text(old1, "old-one.example\n");
                    write_text(old2, "old-two.example\n");
                    cleanup = pcdn_cleanup_artifacts(artifact, old1);
                    assert(aegisxd_json_bool(cleanup, "ok", 0));
                    assert(access(artifact, F_OK) == 0);
                    assert(access(old1, F_OK) == 0);
                    assert(access(old2, F_OK) != 0);
                    assert(json_object_get_int(json_object_object_get(cleanup,
                                                                     "retained_max")) == 3);
                    json_object_put(cleanup);

                    aegisxd_db_close();
                    return 0;
                }
                '''
            ),
            encoding="ascii",
        )

        defines = [
            f'-DAEGISXD_CONFIG_DIR="{config}"',
            f'-DAEGISXD_RUNTIME_DIR="{runtime}"',
            f'-DAEGISXD_WORK_DIR="{work}"',
        ]
        command = [
            *shlex.split(os.environ.get("CC", "cc")),
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(include),
            "-I",
            str(AEGIS),
            *defines,
            str(source),
            "-o",
            str(binary),
            *_pkg_config("json-c", "sqlite3", "libcurl", "openssl"),
            *shlex.split(os.environ.get("AEGISXD_TEST_LDFLAGS", "")),
        ]
        subprocess.run(command, check=True)
        _run_binary(binary)
