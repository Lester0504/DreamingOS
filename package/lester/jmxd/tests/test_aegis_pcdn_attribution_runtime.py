#!/usr/bin/env python3
"""Isolated behavior tests for installed DNS provenance and hit aggregation."""

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


def _stub_headers(root: Path) -> None:
    (root / "libubox").mkdir(parents=True, exist_ok=True)
    (root / "libubox" / "blobmsg.h").write_text(
        "struct blob_attr { int unused; }; struct blob_buf { int unused; };\n",
        encoding="ascii",
    )
    (root / "libubox" / "blobmsg_json.h").write_text(
        "char *blobmsg_format_json(struct blob_attr *, int);\n", encoding="ascii"
    )
    (root / "libubox" / "uloop.h").write_text(
        textwrap.dedent(
            """
            struct uloop_timeout { void (*cb)(struct uloop_timeout *); };
            static inline void uloop_timeout_set(struct uloop_timeout *t, int ms) {
                (void)t; (void)ms;
            }
            static inline void uloop_timeout_cancel(struct uloop_timeout *t) { (void)t; }
            """
        ),
        encoding="ascii",
    )
    (root / "libubox" / "utils.h").write_text(
        "#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))\n", encoding="ascii"
    )
    (root / "libubus.h").write_text(
        "struct ubus_context { int unused; };\n", encoding="ascii"
    )


def _compile_and_run(source_text: str, sandbox: Path, defines: list[str]) -> None:
    include = sandbox / "include"
    source = sandbox / "fixture.c"
    binary = sandbox / "fixture"
    _stub_headers(include)
    source.write_text(textwrap.dedent(source_text), encoding="ascii")
    command = [
        *shlex.split(os.environ.get("CC", "cc")),
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        "-Werror=implicit-function-declaration",
        "-ffunction-sections",
        "-fdata-sections",
        "-I",
        str(include),
        "-I",
        str(AEGIS),
        *defines,
        str(source),
        "-Wl,-dead_strip" if os.uname().sysname == "Darwin" else "-Wl,--gc-sections",
        "-o",
        str(binary),
        *_pkg_config("json-c", "sqlite3", "libcurl", "openssl"),
        *shlex.split(os.environ.get("AEGISXD_TEST_LDFLAGS", "")),
    ]
    subprocess.run(command, check=True)
    runner = shlex.split(os.environ.get("AEGISXD_TEST_RUNNER", ""))
    subprocess.run([*runner, str(binary)], check=True)


def test_installed_dnsmasq_provenance_longest_suffix_and_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-pcdn-provenance-") as tmp:
        sandbox = Path(tmp)
        runtime = sandbox / "run"
        runtime.mkdir()
        artifact = runtime / "installed.conf"
        active = runtime / "active.json"
        artifact.write_text(
            "# aegis-provenance-version=1\n"
            "# aegis provenance=category source=domain_reputation domain=example.com\n"
            "address=/example.com/0.0.0.0\naddress=/example.com/::\n"
            "# aegis provenance=explicit_block source=domain_override domain=exact.example.com\n"
            "address=/exact.example.com/0.0.0.0\naddress=/exact.example.com/::\n"
            "# aegis provenance=pcdn source=openhosts-pcdn domain=p2p.example.net\n"
            "address=/p2p.example.net/0.0.0.0\naddress=/p2p.example.net/::\n"
            "# aegis monitor=pcdn source=openhosts-pcdn domain=observe.example.org\n",
            encoding="ascii",
        )
        active.write_text(
            '{"scope":"all","content_revision":7,"dnsmasq_conf_file":"'
            + str(artifact)
            + '"}',
            encoding="ascii",
        )
        _compile_and_run(
            r'''
            #include <assert.h>
            #include "aegisxd_internal.h"
            #include "aegisxd_content.c"

            sqlite3 *g_aegisxd_config_db;
            sqlite3 *g_aegisxd_db;
            struct ubus_context *g_aegisxd_ubus;
            struct blob_buf g_aegisxd_blob;

            int64_t aegisxd_now_s(void) { return 1000; }
            sqlite3_stmt *aegisxd_config_prepare(const char *sql) { (void)sql; return NULL; }
            sqlite3_stmt *aegisxd_prepare(const char *sql) { (void)sql; return NULL; }
            const char *aegisxd_sqlite_text(sqlite3_stmt *st, int col, const char *def) {
                (void)st; (void)col; return def;
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
                (void)code; (void)message; return json_object_new_object();
            }
            struct json_object *aegisxd_apply(struct json_object *body) {
                (void)body; return json_object_new_object();
            }
            int aegisxd_pcdn_write_dnsmasq(FILE *fp,
                int (*allow_cb)(const char *, void *), void *opaque) {
                (void)fp; (void)allow_cb; (void)opaque; return 0;
            }

            static void match(const char *domain, const char *kind,
                              const char *source, const char *rule) {
                char got_kind[32], got_source[64], got_rule[254];
                assert(aegisxd_content_installed_dns_rule_match(
                    domain, got_kind, got_source, got_rule));
                assert(!strcmp(got_kind, kind));
                assert(!strcmp(got_source, source));
                assert(!strcmp(got_rule, rule));
            }

            int main(void) {
                char kind[32], source[64], rule[254];
                assert(aegisxd_content_dns_provenance_ready());
                match("www.example.com", "category", "domain_reputation", "example.com");
                match("x.exact.example.com", "explicit_block", "domain_override",
                      "exact.example.com");
                match("P2P.EXAMPLE.NET.", "pcdn", "openhosts-pcdn", "p2p.example.net");
                match("edge.observe.example.org", "pcdn_monitor", "openhosts-pcdn",
                      "observe.example.org");
                assert(!aegisxd_content_installed_dns_rule_match(
                    "unrelated.example", kind, source, rule));
                return 0;
            }
            ''',
            sandbox,
            [f'-DAEGISXD_RUNTIME_DIR="{runtime}"'],
        )

        artifact.write_text(
            "address=/p2p.example.net/0.0.0.0\naddress=/p2p.example.net/::\n",
            encoding="ascii",
        )
        _compile_and_run(
            r'''
            #include <assert.h>
            #include "aegisxd_internal.h"
            #include "aegisxd_content.c"
            sqlite3 *g_aegisxd_config_db; sqlite3 *g_aegisxd_db;
            struct ubus_context *g_aegisxd_ubus; struct blob_buf g_aegisxd_blob;
            int64_t aegisxd_now_s(void) { return 1000; }
            sqlite3_stmt *aegisxd_config_prepare(const char *s) { (void)s; return NULL; }
            sqlite3_stmt *aegisxd_prepare(const char *s) { (void)s; return NULL; }
            const char *aegisxd_sqlite_text(sqlite3_stmt *s,int c,const char *d){(void)s;(void)c;return d;}
            void aegisxd_json_add_string(struct json_object *o,const char *k,const char *v){json_object_object_add(o,k,json_object_new_string(v?v:""));}
            const char *aegisxd_json_str(struct json_object *o,const char *k,const char *d){struct json_object *v=NULL;return o&&json_object_object_get_ex(o,k,&v)&&json_object_is_type(v,json_type_string)?json_object_get_string(v):d;}
            int aegisxd_json_bool(struct json_object *o,const char *k,int d){struct json_object *v=NULL;return o&&json_object_object_get_ex(o,k,&v)?!!json_object_get_boolean(v):d;}
            struct json_object *aegisxd_error(const char *c,const char *m){(void)c;(void)m;return json_object_new_object();}
            struct json_object *aegisxd_apply(struct json_object *b){(void)b;return json_object_new_object();}
            int aegisxd_pcdn_write_dnsmasq(FILE *f,int (*cb)(const char *,void *),void *o){(void)f;(void)cb;(void)o;return 0;}
            int main(void) { char k[32],s[64],r[254]; assert(!aegisxd_content_dns_provenance_ready()); assert(!aegisxd_content_installed_dns_rule_match("p2p.example.net",k,s,r)); return 0; }
            ''',
            sandbox,
            [f'-DAEGISXD_RUNTIME_DIR="{runtime}"'],
        )


def test_dns_hits_aggregate_and_log_reader_does_not_replay() -> None:
    with tempfile.TemporaryDirectory(prefix="aegis-pcdn-hits-") as tmp:
        sandbox = Path(tmp)
        runtime = sandbox / "run"
        runtime.mkdir()
        log = sandbox / "dnsmasq.log"
        log.write_text(
            "dnsmasq[1]: 1 query[A] p2p.example.net\n"
            "dnsmasq[1]: 1 config p2p.example.net is 0.0.0.0\n",
            encoding="ascii",
        )
        (runtime / "active.json").write_text("{}", encoding="ascii")
        _compile_and_run(
            r'''
            #include <assert.h>
            #include "aegisxd_internal.h"
            #include "aegisxd_hits.c"

            sqlite3 *g_aegisxd_config_db;
            sqlite3 *g_aegisxd_db;
            struct ubus_context *g_aegisxd_ubus;
            struct blob_buf g_aegisxd_blob;
            static int64_t fake_now = 1000;
            static int monitor_enabled;

            int64_t aegisxd_now_s(void) { return fake_now; }
            sqlite3_stmt *aegisxd_prepare(const char *sql) {
                sqlite3_stmt *st = NULL;
                return sqlite3_prepare_v2(g_aegisxd_db, sql, -1, &st, NULL) == SQLITE_OK ? st : NULL;
            }
            sqlite3_stmt *aegisxd_config_prepare(const char *sql) { (void)sql; return NULL; }
            const char *aegisxd_sqlite_text(sqlite3_stmt *st, int col, const char *def) {
                const unsigned char *s = sqlite3_column_text(st, col); return s ? (const char *)s : def;
            }
            void aegisxd_json_add_string(struct json_object *o, const char *key,
                                         const char *value) {
                json_object_object_add(o, key, json_object_new_string(value ? value : ""));
            }
            const char *aegisxd_json_str(struct json_object *o, const char *key,
                                         const char *def) {
                struct json_object *v = NULL; return o && json_object_object_get_ex(o,key,&v) &&
                    json_object_is_type(v,json_type_string) ? json_object_get_string(v) : def;
            }
            int aegisxd_json_bool(struct json_object *o,const char *key,int def) {
                struct json_object *v=NULL; return o&&json_object_object_get_ex(o,key,&v)?!!json_object_get_boolean(v):def;
            }
            int aegisxd_content_installed_dns_rule_match(const char *domain,
                char kind[32], char source_id[64], char matched_rule[254]) {
                if (!domain || strcmp(domain, "p2p.example.net")) return 0;
                snprintf(kind,32,"pcdn"); snprintf(source_id,64,"openhosts-pcdn");
                snprintf(matched_rule,254,"p2p.example.net"); return 1;
            }
            int aegisxd_pcdn_installed_domain_match(const char *domain, char sha[65]) {
                if (monitor_enabled || !domain || strcmp(domain, "p2p.example.net")) return 0;
                memset(sha, 'a', 64); sha[64] = 0; return 1;
            }
            int aegisxd_pcdn_installed_monitor_match(const char *domain,
                char matched_rule[254], char sha[65]) {
                if (!monitor_enabled || !domain || strcmp(domain, "p2p.example.net")) return 0;
                snprintf(matched_rule,254,"p2p.example.net");
                memset(sha, 'b', 64); sha[64] = 0; return 1;
            }

            static void sql(const char *statement) {
                char *error = NULL; assert(sqlite3_exec(g_aegisxd_db, statement, NULL, NULL, &error) == SQLITE_OK); sqlite3_free(error);
            }
            static int scalar(const char *statement) {
                sqlite3_stmt *st = NULL; int n; assert(sqlite3_prepare_v2(g_aegisxd_db,statement,-1,&st,NULL)==SQLITE_OK); assert(sqlite3_step(st)==SQLITE_ROW); n=sqlite3_column_int(st,0); sqlite3_finalize(st); return n;
            }
            static void append(const char *text) {
                FILE *fp=fopen(AEGISXD_DNSMASQ_LOG_PATH,"ab"); assert(fp); assert(fwrite(text,1,strlen(text),fp)==strlen(text)); assert(fclose(fp)==0);
            }

            int main(void) {
                assert(sqlite3_open(":memory:", &g_aegisxd_db) == SQLITE_OK);
                sql("CREATE TABLE aegis_domain_categories(domain TEXT,category TEXT,source_feed TEXT,confidence INTEGER);"
                    "CREATE TABLE aegis_reputation_items(kind TEXT,value TEXT,category TEXT,source_feed TEXT,severity INTEGER,confidence INTEGER);"
                    "CREATE TABLE aegis_events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER,event_type TEXT,level TEXT,action TEXT,policy_id TEXT,policy_name TEXT,policy_type TEXT,rule_id TEXT,rule_name TEXT,risk TEXT,risk_category TEXT,source_ip TEXT,source_mac TEXT DEFAULT '',source_port INTEGER DEFAULT 0,destination_ip TEXT DEFAULT '',destination_host TEXT,destination_port INTEGER,protocol TEXT,app_id TEXT DEFAULT '',app_name TEXT DEFAULT '',in_interface TEXT DEFAULT '',out_interface TEXT DEFAULT '',rx_bytes INTEGER DEFAULT 0,tx_bytes INTEGER DEFAULT 0,flow_id TEXT DEFAULT '',reason TEXT,source TEXT,occurrence_count INTEGER DEFAULT 1,first_seen INTEGER DEFAULT 0,last_seen INTEGER DEFAULT 0,meta_json TEXT DEFAULT '{}');");
                assert(aegisxd_hits_insert_dns_event("p2p.example.net","","aa:bb:cc:dd:ee:ff","br-lan","fixture","A",0) == 0);
                fake_now = 1005;
                assert(aegisxd_hits_insert_dns_event("p2p.example.net","","aa:bb:cc:dd:ee:ff","br-lan","fixture","AAAA",0) == 0);
                assert(scalar("SELECT COUNT(*) FROM aegis_events") == 1);
                assert(scalar("SELECT occurrence_count FROM aegis_events") == 2);
                assert(scalar("SELECT first_seen FROM aegis_events") == 1000);
                assert(scalar("SELECT last_seen FROM aegis_events") == 1005);
                assert(aegisxd_hits_insert_dns_event("outside.example","","","","","A",0) == 0);
                assert(scalar("SELECT COUNT(*) FROM aegis_events") == 1);
                assert(g_events_unattributed == 1);

                aegisxd_hits_follow_from_eof();
                aegisxd_hits_read_log();
                assert(scalar("SELECT occurrence_count FROM aegis_events") == 2);
                append("dnsmasq[9]: 88 query[A] p2p.example.net");
                aegisxd_hits_read_log();
                assert(scalar("SELECT occurrence_count FROM aegis_events") == 2);
                append("\ndnsmasq[9]: 88 config p2p.example.net is ::\n");
                aegisxd_hits_read_log();
                assert(scalar("SELECT occurrence_count FROM aegis_events") == 3);

                assert(rename(AEGISXD_DNSMASQ_LOG_PATH, AEGISXD_DNSMASQ_LOG_PATH ".old") == 0);
                { FILE *fp=fopen(AEGISXD_DNSMASQ_LOG_PATH,"wb"); assert(fp); fputs("dnsmasq[10]: 99 query[AAAA] p2p.example.net\ndnsmasq[10]: 99 config p2p.example.net is 0.0.0.0\n",fp); fclose(fp); }
                fake_now = 1040;
                aegisxd_hits_read_log();
                assert(scalar("SELECT COUNT(*) FROM aegis_events") == 2);
                assert(scalar("SELECT SUM(occurrence_count) FROM aegis_events") == 4);
                monitor_enabled = 1;
                append("dnsmasq[11]: 100 query[A] p2p.example.net from 192.0.2.5\n");
                fake_now = 1045;
                aegisxd_hits_read_log();
                assert(scalar("SELECT COUNT(*) FROM aegis_events WHERE event_type='pcdn_dns_observed' AND action='monitor'") == 1);
                assert(scalar("SELECT occurrence_count FROM aegis_events WHERE event_type='pcdn_dns_observed'") == 1);
                assert(scalar("SELECT COUNT(*) FROM aegis_events WHERE event_type='pcdn_dns_block'") == 2);
                sqlite3_close(g_aegisxd_db);
                return 0;
            }
            ''',
            sandbox,
            [
                f'-DAEGISXD_RUNTIME_DIR="{runtime}"',
                f'-DAEGISXD_DNSMASQ_LOG_PATH="{log}"',
            ],
        )
