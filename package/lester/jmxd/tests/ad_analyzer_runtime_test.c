// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "../src/webd/ad_analyzer.h"
#include <assert.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static int checks;
#define CHECK(v)                                                                                   \
    do {                                                                                           \
        checks++;                                                                                  \
        if (!(v)) {                                                                                \
            fprintf(stderr, "failed at line %d: %s\n", __LINE__, #v);                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static struct json_object *at(struct json_object *o, const char *k) {
    struct json_object *v = NULL;
    json_object_object_get_ex(o, k, &v);
    return v;
}
static const char *s(struct json_object *o, const char *k) {
    return json_object_get_string(at(o, k));
}
static int n(struct json_object *o, const char *k) { return json_object_get_int(at(o, k)); }
static struct json_object *call(struct ada_environment *e, const char *who, int operate,
                                const char *method, const char *path, const char *body,
                                int expected) {
    int status = 0;
    struct json_object *b = json_tokener_parse(body ? body : "{}"), *q = json_object_new_object();
    struct json_object *r = ada_handle(e, who, operate, method, path, q, b, &status);
    if (status != expected)
        fprintf(stderr, "expected %d got %d: %s\n", expected, status,
                json_object_to_json_string(r));
    CHECK(status == expected);
    json_object_put(b);
    json_object_put(q);
    return r;
}
static void line(FILE *f, int64_t now, int pid, int serial, const char *v) {
    char ts[64];
    time_t t = now;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(f, "%s dnsmasq[%d]: %d %s\n", ts, pid, serial, v);
}
int main(int argc, char **argv) {
    if (argc == 7 || argc == 8) {
        struct ada_environment e = {argv[1], argv[2], argv[3], time(NULL)};
        int status = 200;
        struct json_object *b = json_tokener_parse(argv[6]),
                           *q = argc == 8 ? json_tokener_parse(argv[7]) : json_object_new_object(), *r;
        if (!strcmp(argv[4], "TICK")) {
            status = ada_tick(&e, 0);
            r = json_object_new_object();
        } else
            r = ada_handle(&e, "user:test", 1, argv[4], argv[5], q, b, &status);
        json_object_object_add(r, "http_status", json_object_new_int(status));
        puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
        json_object_put(b);
        json_object_put(q);
        json_object_put(r);
        return status >= 400 ? 1 : 0;
    }
    char dir[] = "/tmp/ad-analyzer-test-XXXXXX";
    CHECK(mkdtemp(dir));
    char db[256], log[256], leases[256];
    snprintf(db, sizeof(db), "%s/db", dir);
    snprintf(log, sizeof(log), "%s/dns.log", dir);
    snprintf(leases, sizeof(leases), "%s/leases", dir);
    struct ada_environment e = {db, log, leases, time(NULL)};
    FILE *f = fopen(log, "w");
    line(f, e.now - 30, 100, 1, "query[A] historical.test from 192.168.30.16");
    fclose(f);
    f = fopen(leases, "w");
    fprintf(f, "0 aa:bb:cc:dd:ee:ff 192.168.30.16 TestDevice *\n");
    fclose(f);
    struct json_object *r =
        call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"device_id\":\"aa:bb:cc:dd:ee:ff\",\"mode\":\"find_"
             "ads\",\"observe_ttl\":30,\"request_id\":\"create-1\"}",
             201);
    struct json_object *listing=call(&e,"user:a",1,"GET","sessions",NULL,200);
    CHECK(json_object_array_length(at(listing,"sessions"))==1);CHECK(n(json_object_array_get_idx(at(listing,"sessions"),0),"total_connections")==0);json_object_put(listing);
    char id[80], path[160];
    snprintf(id, sizeof(id), "%s", s(r, "session_id"));
    CHECK(n(r, "revision") == 1);
    json_object_put(r);
    r = call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"device_id\":\"aa:bb:cc:dd:ee:ff\",\"mode\":\"find_"
             "ads\",\"observe_ttl\":30,\"request_id\":\"create-1\"}",
             201);
    CHECK(!strcmp(s(r, "session_id"), id));
    json_object_put(r);
    r = call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.160\",\"mode\":\"find_ads\",\"request_id\":\"create-1\"}",
             409);
    json_object_put(r);
    r = call(&e, "user:b", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"other\"}",
             409);
    json_object_put(r);
    f = fopen(log, "a");
    line(f, e.now, 100, 10, "query[A] shared.test from 192.168.30.16");
    line(f, e.now, 100, 11, "query[A] shared.test from 192.168.30.160");
    line(f, e.now, 100, 11, "reply shared.test is 203.0.113.160");
    line(f, e.now, 100, 10, "reply shared.test is 203.0.113.16");
    line(f, e.now, 200, 10, "config shared.test is 0.0.0.0");
    line(f, e.now, 100, 12, "query[AAAA] v6.test from 192.168.30.16");
    line(f, e.now, 100, 12, "reply v6.test is <CNAME>");
    line(f, e.now, 100, 12, "reply origin.test is 2001:db8::1");
    line(f, e.now, 100, 13, "query[A] blocked.test from 192.168.30.16");
    line(f, e.now, 100, 13, "config blocked.test is 0.0.0.0");
    fclose(f);
    CHECK(ada_tick(&e, 0) == 0);
    snprintf(path, sizeof(path), "sessions/%s/observations", id);
    r = call(&e, "viewer", 0, "GET", path, NULL, 200);
    CHECK(n(r, "total") == 3);
    struct json_object *rows = at(r, "observations");
    int found = 0;
    for (size_t i = 0; i < json_object_array_length(rows); i++) {
        struct json_object *d = json_object_array_get_idx(rows, i);
        if (!strcmp(s(d, "domain"), "shared.test")) {
            found = 1;
            CHECK(n(d, "dns_count") == 1);
            CHECK(n(d, "blocked_observed") == 0);
            CHECK(json_object_array_length(at(d, "resolved_ips")) == 1);
            CHECK(
                !strcmp(json_object_get_string(json_object_array_get_idx(at(d, "resolved_ips"), 0)),
                        "203.0.113.16"));
        }
        if (!strcmp(s(d, "domain"), "v6.test")) {
            CHECK(json_object_array_length(at(d, "cnames")) == 1);
            CHECK(!strcmp(json_object_get_string(json_object_array_get_idx(at(d, "cnames"), 0)),
                          "origin.test"));
        }
    }
    CHECK(found);
    json_object_put(r);
    CHECK(ada_tick(&e, 0) == 0);
    r = call(&e, "viewer", 0, "GET", path, NULL, 200);
    CHECK(n(r, "total") == 3);
    json_object_put(r);
    f = fopen(log, "a");
    for (int i = 1; i < 40; i++) {
        char answer[160];
        snprintf(answer, sizeof(answer), "cached origin.test is 2001:db8::%x", i);
        line(f, e.now, 100, 12, answer);
    }
    fclose(f);
    CHECK(ada_tick(&e, 0) == 0);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(n(r, "evidence_dropped") > 0 && n(r, "truncated") == 1);
    json_object_put(r);
    snprintf(path, sizeof(path), "sessions/%s/end", id);
    r = call(&e, "user:b", 1, "POST", path,
             "{\"request_id\":\"wrong-user\",\"expected_revision\":1}", 403);
    json_object_put(r);
    r = call(&e, "viewer", 0, "POST", path, "{\"request_id\":\"viewer\",\"expected_revision\":1}",
             403);
    json_object_put(r);
    snprintf(path, sizeof(path), "sessions/%s/trial", id);
    r = call(&e, "user:a", 1, "POST", path,
             "{\"request_id\":\"trial\",\"expected_revision\":1,\"rules\":[{\"domain\":\"shared."
             "test\",\"action\":\"allow\",\"match\":\"exact\"}]}",
             409);
    CHECK(!strcmp(s(at(r, "error"), "code"), "exact_device_domain_provider_unavailable"));
    json_object_put(r);
    /* Rotation preserves existing observations, but does not import old entries. */
    f = fopen(log, "w");
    line(f, e.now - 60, 300, 2, "query[A] old-rotated.test from 192.168.30.16");
    line(f, e.now, 300, 3, "query[A] after-rotation.test from 192.168.30.16");
    fclose(f);
    CHECK(ada_tick(&e, 0) == 0);
    snprintf(path, sizeof(path), "sessions/%s/observations", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(n(r, "total") == 4);
    CHECK(n(r, "truncated") == 1);
    json_object_put(r);
    /* No browser needed for expiration and report persistence. */
    e.now += 31;
    CHECK(ada_tick(&e, 0) == 0);
    snprintf(path, sizeof(path), "sessions/%s", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(!strcmp(s(r, "state"), "expired"));
    CHECK(!strcmp(s(r, "report_state"), "saved"));
    char report[80];
    snprintf(report, sizeof(report), "%s", s(r, "report_id"));
    json_object_put(r);
    f = fopen(log, "a");
    line(f, e.now, 300, 4, "query[A] after-stop.test from 192.168.30.16");
    fclose(f);
    CHECK(ada_tick(&e, 0) == 0);
    snprintf(path, sizeof(path), "sessions/%s/observations", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(n(r, "total") == 4);
    json_object_put(r);
    snprintf(path, sizeof(path), "reports/%s", report);
    r = call(&e, "user:a", 1, "PATCH", path,
             "{\"request_id\":\"note\",\"expected_revision\":1,\"label\":\"测试备注\"}", 200);
    CHECK(n(r, "report_revision") == 2);
    json_object_put(r);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(!strcmp(s(r, "label"), "测试备注"));
    json_object_put(r);
    r = call(&e, "user:a", 1, "DELETE", path, "{\"request_id\":\"delete\",\"expected_revision\":1}",
             409);
    json_object_put(r);
    r = call(&e, "user:a", 1, "DELETE", path,
             "{\"request_id\":\"delete-2\",\"expected_revision\":2}", 200);
    json_object_put(r);
    r = call(&e, "user:a", 1, "GET", path, NULL, 404);
    json_object_put(r);
    /* A zero-event capture survives a service restart as a diagnostic report. */
    r = call(
        &e, "user:a", 1, "POST", "sessions",
        "{\"device_ip\":\"192.168.30.16\",\"mode\":\"false_positive\",\"request_id\":\"restart\"}",
        201);
    snprintf(id, sizeof(id), "%s", s(r, "session_id"));
    json_object_put(r);
    CHECK(ada_tick(&e, 1) == 0);
    snprintf(path, sizeof(path), "sessions/%s", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(!strcmp(s(r, "state"), "failed"));
    CHECK(!strcmp(s(r, "report_state"), "saved"));
    json_object_put(r);
    /* DHCP reuse cannot attach the next device's queries to this session. */
    r = call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"dhcp\"}", 201);
    snprintf(id, sizeof(id), "%s", s(r, "session_id"));
    json_object_put(r);
    f = fopen(leases, "w");
    fprintf(f, "0 00:11:22:33:44:55 192.168.30.16 Replacement *\n");
    fclose(f);
    f = fopen(log, "a");
    line(f, e.now, 300, 40, "query[A] replacement.test from 192.168.30.16");
    fclose(f);
    CHECK(ada_tick(&e, 0) == 0);
    snprintf(path, sizeof(path), "sessions/%s", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(!strcmp(s(r, "state"), "failed"));
    CHECK(!strcmp(s(r, "stop_reason"), "target_identity_changed"));
    snprintf(path, sizeof(path), "reports/%s", s(r, "report_id"));
    json_object_put(r);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(json_object_object_length(at(r, "domains")) == 0);
    CHECK(!at(r, "operator_id") && !at(r, "log_inode") && !at(r, "cursor"));
    json_object_put(r);
    /* Domain/answer growth ends with a persisted, bounded partial report. */
    r = call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"volume\"}", 201);
    snprintf(id, sizeof(id), "%s", s(r, "session_id"));
    json_object_put(r);
    f = fopen(log, "a");
    for (int i = 0; i < 2000; i++) {
        char v[200];
        snprintf(v, sizeof(v), "query[A] domain-%04d.test from 192.168.30.16", i);
        line(f, e.now, 300, 100 + i, v);
        snprintf(v, sizeof(v), "reply domain-%04d.test is 203.0.113.12", i);
        line(f, e.now, 300, 100 + i, v);
    }
    fclose(f);
    CHECK(ada_tick(&e, 0) == 0);
    snprintf(path, sizeof(path), "sessions/%s", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(!strcmp(s(r, "stop_reason"), "resource_limit"));
    CHECK(!strcmp(s(r, "report_state"), "saved"));
    snprintf(path, sizeof(path), "reports/%s", s(r, "report_id"));
    snprintf(report, sizeof(report), "%s", s(r, "report_id"));
    json_object_put(r);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(strlen(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN)) < 768 * 1024);
    CHECK(json_object_object_length(at(r, "domains")) > 500);
    /* History transfer must not reuse the 32-entry per-domain evidence limit. */
    struct json_object *reuse = json_object_new_object(), *candidates = json_object_new_array();
    json_object_object_foreach(at(r, "domains"), domain, value) {
        (void)value;
        if (json_object_array_length(candidates) < 100)
            json_object_array_add(candidates, json_object_new_string(domain));
    }
    json_object_object_add(reuse, "device_ip", json_object_new_string("192.168.30.16"));
    json_object_object_add(reuse, "mode", json_object_new_string("find_ads"));
    json_object_object_add(reuse, "request_id", json_object_new_string("reuse-100"));
    json_object_object_add(reuse, "reuse_report_id", json_object_new_string(report));
    json_object_object_add(reuse, "candidates", candidates);
    json_object_put(r);
    r = call(&e, "user:a", 1, "POST", "sessions", json_object_to_json_string(reuse), 201);
    CHECK(json_object_array_length(at(r, "candidates")) == 100);
    char reuse_path[160];
    snprintf(reuse_path, sizeof(reuse_path), "sessions/%s/end", s(r, "session_id"));
    json_object_put(r);
    json_object_put(reuse);
    r = call(&e, "user:a", 1, "POST", reuse_path,
             "{\"request_id\":\"end-reuse\",\"expected_revision\":1}", 200);
    json_object_put(r);
    /* A finite idempotency window bounds large report-edit responses. */
    for (int i = 0; i < 10; i++) {
        char b[150];
        snprintf(b, sizeof(b), "{\"request_id\":\"large-note-%d\",\"expected_revision\":%d,\"label\":\"revision-%d\"}", i, i + 1, i);
        r = call(&e, "user:a", 1, "PATCH", path, b, 200);
        json_object_put(r);
    }
    sqlite3 *storage = NULL;
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_open(db, &storage) == SQLITE_OK);
    CHECK(sqlite3_prepare_v2(storage, "SELECT sum(length(CAST(signature AS BLOB))+length(CAST(response AS BLOB))) FROM analyzer_requests", -1, &st, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int64(st, 0) <= 4 * 1024 * 1024);
    sqlite3_finalize(st);
    /* Seed retained reports near the byte limit; next finalization evicts old rows. */
    CHECK(sqlite3_prepare_v2(storage, "INSERT INTO analyzer_reports SELECT ?1,?1,owner,'192.168.30.16',mode,created-?2,document FROM analyzer_reports WHERE id=?3", -1, &st, NULL) == SQLITE_OK);
    for (int i = 0; i < 28; i++) {
        char seed[40];
        snprintf(seed, sizeof(seed), "retention-seed-%d", i);
        sqlite3_bind_text(st, 1, seed, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, i + 1);
        sqlite3_bind_text(st, 3, report, -1, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE);
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    r = call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"retain\"}", 201);
    snprintf(path, sizeof(path), "sessions/%s/stop", s(r, "session_id"));
    json_object_put(r);
    r = call(&e, "user:a", 1, "POST", path, "{\"request_id\":\"retain-stop\",\"expected_revision\":1}", 200);
    CHECK(n(r, "report_saved") == 1);
    json_object_put(r);
    CHECK(sqlite3_prepare_v2(storage, "SELECT count(*),sum(length(CAST(document AS BLOB))) FROM analyzer_reports", -1, &st, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) <= 24 && sqlite3_column_int64(st, 1) <= 16 * 1024 * 1024);
    sqlite3_finalize(st);
    /* A failed report insert cannot mark the session/report as saved. */
    CHECK(sqlite3_exec(storage, "CREATE TRIGGER reject_report BEFORE INSERT ON analyzer_reports BEGIN SELECT RAISE(ABORT,'test full'); END", NULL, NULL, NULL) == SQLITE_OK);
    r = call(&e, "user:a", 1, "POST", "sessions",
             "{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"save-retry\"}", 201);
    snprintf(id, sizeof(id), "%s", s(r, "session_id"));
    snprintf(path, sizeof(path), "sessions/%s/stop", id);
    json_object_put(r);
    r = call(&e, "user:a", 1, "POST", path,
             "{\"request_id\":\"failed-stop\",\"expected_revision\":1}", 503);
    json_object_put(r);
    snprintf(path, sizeof(path), "sessions/%s", id);
    r = call(&e, "user:a", 1, "GET", path, NULL, 200);
    CHECK(!strcmp(s(r, "report_state"), "not_finalized") && n(r, "revision") == 1);
    json_object_put(r);
    CHECK(sqlite3_exec(storage, "DROP TRIGGER reject_report", NULL, NULL, NULL) == SQLITE_OK);
    snprintf(path, sizeof(path), "sessions/%s/stop", id);
    r = call(&e, "user:a", 1, "POST", path,
             "{\"request_id\":\"failed-stop\",\"expected_revision\":1}", 200);
    CHECK(n(r, "report_saved") == 1);
    json_object_put(r);
    sqlite3_close(storage);
    char ct[256];snprintf(ct,sizeof(ct),"%s/conntrack",dir);e.conntrack=ct;
    f=fopen(ct,"w");fprintf(f,"ipv4 2 udp 17 100 src=192.168.30.16 dst=198.51.100.42 sport=1001 dport=443 packets=1 bytes=100 src=198.51.100.42 dst=192.168.30.16 sport=443 dport=1001 [UNREPLIED]\n");fprintf(f,"ipv4 2 tcp 6 100 src=192.168.30.160 dst=198.51.100.43 sport=1002 dport=443 packets=1\n");fclose(f);
    r=call(&e,"user:a",1,"POST","sessions","{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"connections-groups\"}",201);
    CHECK(json_object_object_length(at(r,"connections"))==1);snprintf(id,sizeof(id),"%s",s(r,"session_id"));json_object_put(r);
    f=fopen(log,"a");line(f,e.now,800,1,"query[A] a.example.co.uk from 192.168.30.16");line(f,e.now,800,2,"query[A] a.city.kawasaki.jp from 192.168.30.16");line(f,e.now,800,3,"query[A] a.b.ck from 192.168.30.16");line(f,e.now,800,4,"query[A] a.www.ck from 192.168.30.16");line(f,e.now,800,5,"query[A] a.test.github.io from 192.168.30.16");fclose(f);CHECK(ada_tick(&e,0)==0);
    snprintf(path,sizeof(path),"sessions/%s/observations",id);r=call(&e,"user:a",1,"GET",path,NULL,200);struct json_object *group_rows=at(r,"observations");CHECK(json_object_array_length(group_rows)==5);
    const char *groups[]={"example.co.uk","a.b.ck","city.kawasaki.jp","test.github.io","www.ck"};
    /* lookup by domain rather than relying on score order */
    for(size_t i=0;i<json_object_array_length(group_rows);i++){struct json_object *d=json_object_array_get_idx(group_rows,i);int found=0;for(int j=0;j<5;j++)if(!strcmp(s(d,"group_key"),groups[j]))found=1;CHECK(found);}
    CHECK(json_object_array_length(at(r,"direct_ips"))==1);json_object_put(r);
    f=fopen(log,"a");
    line(f,e.now,800,1,"policy a.example.co.uk is block rule=parent-test matched=example.co.uk match=suffix");
    line(f,e.now,800,1,"reply a.example.co.uk is 198.51.100.42");
    fclose(f);CHECK(ada_tick(&e,0)==0);
    struct json_object *query=json_tokener_parse("{\"connection\":\"1\",\"parent\":\"1\"}"), *empty=json_object_new_object();
    int query_status=0;
    r=ada_handle(&e,"user:a",1,"GET",path,query,empty,&query_status);
    CHECK(query_status==200 && n(r,"total")==1);
    struct json_object *filtered=json_object_array_get_idx(at(r,"observations"),0);
    CHECK(!strcmp(s(filtered,"domain"),"a.example.co.uk"));
    CHECK(n(filtered,"has_connection_clue") && n(filtered,"parent_rule_observed"));
    CHECK(!strcmp(s(filtered,"connection_attribution"),"inferred_same_device_ip_or_host"));
    json_object_put(r);json_object_put(query);json_object_put(empty);

    snprintf(path,sizeof(path),"sessions/%s/stop",id);r=call(&e,"user:a",1,"POST",path,"{\"request_id\":\"connections-stop\",\"expected_revision\":1}",200);json_object_put(r);
    unlink(log);
    r = call(
        &e, "user:a", 1, "POST", "sessions",
        "{\"device_ip\":\"192.168.30.16\",\"mode\":\"find_ads\",\"request_id\":\"missing-log\"}",
        409);
    json_object_put(r);
    printf("PASS %d checks; artifacts %s\n", checks, dir);
    return 0;
}
