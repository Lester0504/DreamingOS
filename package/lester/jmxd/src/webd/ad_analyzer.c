// SPDX-License-Identifier: GPL-2.0-or-later
/* Independently authored device observation and reversible DNS trials. */
#define _GNU_SOURCE
#include "ad_analyzer.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_CAPTURE 2
#define MAX_SESSIONS 12
#define MAX_DOMAINS 2000
#define MAX_REPORTS 120
#define PER_DEVICE_REPORTS 24
#define MAX_DOCUMENT (768 * 1024)
#define REPORT_BYTES (16 * 1024 * 1024)
#define REQUEST_BYTES (4 * 1024 * 1024)
#define READ_BYTES (1024 * 1024)
#define PAGE_MAX 500
#define LOG_FRESH 120
#define OBS_DEFAULT 600
#define OBS_MAX 1800

static struct json_object *provider_request(const struct ada_environment *,const char *,struct json_object *,struct json_object *,int *);
static int provider_ready(const struct ada_environment *);
static int trial_live(struct json_object *);
static struct json_object *withdraw(const struct ada_environment *,struct json_object *,struct json_object *,int *);
static int report_conclusions(sqlite3 *,struct json_object *,const struct ada_environment *);
static int lease_target(const struct ada_environment *, const char *, char *, size_t,
                        char *, size_t);

static struct json_object *obj(void) { return json_object_new_object(); }
static struct json_object *arr(void) { return json_object_new_array(); }
static struct json_object *child(struct json_object *o, const char *k) {
    struct json_object *v = NULL;
    if (o)
        json_object_object_get_ex(o, k, &v);
    return v;
}
static const char *str(struct json_object *o, const char *k) {
    struct json_object *v = child(o, k);
    return v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}
static int64_t num(struct json_object *o, const char *k) {
    return json_object_get_int64(child(o, k));
}
static void text(struct json_object *o, const char *k, const char *v) {
    json_object_object_add(o, k, json_object_new_string(v ? v : ""));
}
static void number(struct json_object *o, const char *k, int64_t v) {
    json_object_object_add(o, k, json_object_new_int64(v));
}
static void boolean(struct json_object *o, const char *k, int v) {
    json_object_object_add(o, k, json_object_new_boolean(v));
}
static struct json_object *copy(struct json_object *o) {
    return o ? json_tokener_parse(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)) : NULL;
}
static const char *json(struct json_object *o) {
    return json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
}
static struct json_object *error(int *status, int http, const char *code, const char *message) {
    struct json_object *r = obj(), *e = obj();
    *status = http;
    boolean(r, "ok", 0);
    text(e, "code", code);
    text(e, "message", message);
    boolean(e, "retryable", http == 503 || http == 409);
    json_object_object_add(r, "error", e);
    return r;
}
static struct json_object *ok(struct json_object *r) {
    boolean(r, "ok", 1);
    return r;
}
static int unique(struct json_object *a, const char *s, size_t limit) {
    for (size_t i = 0; i < json_object_array_length(a); i++)
        if (!strcmp(json_object_get_string(json_object_array_get_idx(a, i)), s))
            return 0;
    if (json_object_array_length(a) >= limit)
        return -1;
    json_object_array_add(a, json_object_new_string(s));
    return 1;
}
static void evidence_value(struct json_object *s, struct json_object *d,
                           const char *key, const char *value) {
    if (unique(child(d, key), value, 32) < 0) {
        boolean(d, "evidence_truncated", 1);
        number(s, "evidence_dropped", num(s, "evidence_dropped") + 1);
        boolean(s, "truncated", 1);
        text(s, "coverage_reason", "domain_evidence_limit");
    }
}
static int id_ok(const char *s) {
    if (!s || !*s || strlen(s) > 80)
        return 0;
    for (; *s; s++) {
        if (!isalnum((unsigned char)*s) && *s != '-' && *s != '_')
            return 0;
    }
    return 1;
}
static int make_id(char *out, size_t n, const char *prefix) {
    unsigned char b[16];
    char h[33];
    if (RAND_bytes(b, sizeof(b)) != 1)
        return -1;
    for (size_t i = 0; i < sizeof(b); i++) {
        snprintf(h + 2 * i, 3, "%02x", b[i]);
    }
    snprintf(out, n, "%s%s", prefix, h);
    return 0;
}
static void mutation_id(char *out,size_t n,const char *prefix,const char *owner,const char *request) {
    char input[320],hex[33];unsigned char digest[SHA256_DIGEST_LENGTH];
    snprintf(input,sizeof(input),"%s|%s|%s",prefix,owner,request);
    SHA256((unsigned char *)input,strlen(input),digest);
    for(int i=0;i<16;i++)snprintf(hex+2*i,3,"%02x",digest[i]);
    snprintf(out,n,"%s%s",prefix,hex);
}
static int ip_normalize(const char *in, char *out, size_t n) {
    unsigned char v[16];
    int af = strchr(in, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(af, in, v) != 1)
        return 0;
    if (af == AF_INET && (v[0] == 0 || v[0] == 127 || v[0] >= 224))
        return 0;
    if (af == AF_INET6 && (v[0] == 255 || !memcmp(v, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15)))
        return 0;
    return inet_ntop(af, v, out, n) != NULL;
}
static int domain_normalize(const char *in, char *out, size_t n) {
    size_t z = strlen(in);
    if (z && in[z - 1] == '.')
        z--;
    if (!z || z > 253 || z >= n)
        return 0;
    size_t label = 0;
    for (size_t i = 0; i < z; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)in[i]);
        if (c == '.') {
            if (!label || label > 63 || out[i - 1] == '-')
                return 0;
            label = 0;
        } else {
            if (!isalnum(c) && c != '-' && c != '_')
                return 0;
            if (!label && c == '-')
                return 0;
            label++;
        }
        out[i] = (char)c;
    }
    out[z] = 0;
    return label > 0 && label <= 63 && out[z - 1] != '-';
}
static int open_db(const struct ada_environment *e, sqlite3 **db) {
    if (sqlite3_open_v2(e->database, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) !=
        SQLITE_OK) {
        if (*db)
            sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    chmod(e->database, 0600);
    sqlite3_busy_timeout(*db, 2000);
    const char *schema =
        "PRAGMA journal_mode=WAL;PRAGMA max_page_count=8192;"
        "CREATE TABLE IF NOT EXISTS analyzer_sessions(id TEXT PRIMARY KEY,owner TEXT NOT NULL,ip "
        "TEXT NOT NULL,active INTEGER NOT NULL,created INTEGER NOT NULL,document TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS analyzer_reports(id TEXT PRIMARY KEY,session_id TEXT "
        "UNIQUE,owner TEXT NOT NULL,ip TEXT NOT NULL,mode TEXT NOT NULL,created INTEGER NOT "
        "NULL,document TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS analyzer_requests(owner TEXT,request_id TEXT,signature "
        "TEXT,response TEXT,status INTEGER,created INTEGER,PRIMARY KEY(owner,request_id));";
    if (sqlite3_exec(*db, schema, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    return 0;
}
static struct json_object *load(sqlite3 *db, const char *table, const char *id) {
    char sql[160];
    sqlite3_stmt *st = NULL;
    struct json_object *r = NULL;
    snprintf(sql, sizeof(sql), "SELECT document FROM %s WHERE id=?1", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            r = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    return r;
}
static int active(struct json_object *s) {
    const char *v = str(s, "state");
    return !strcmp(v, "capturing") || !strcmp(v, "degraded");
}
static int save_session(sqlite3 *db, struct json_object *s) {
    sqlite3_stmt *st = NULL;
    const char *data = json(s);
    if (strlen(data) > MAX_DOCUMENT)
        return -1;
    if (sqlite3_prepare_v2(
            db,
            "INSERT INTO analyzer_sessions VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET "
            "active=excluded.active,document=excluded.document",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, str(s, "session_id"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, str(s, "operator_id"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, str(s, "device_ip"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, active(s));
    sqlite3_bind_int64(st, 5, num(s, "started_at"));
    sqlite3_bind_text(st, 6, data, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}
static struct json_object *public_session(struct json_object *s, int detail, const char *who,
                                          int operate) {
    struct json_object *r = copy(s);
    const char *priv[] = {"queries",     "cursor",  "log_inode", "log_anchor",
                          "operator_id", "domains", NULL};
    for (int i = 0; priv[i]; i++)
        json_object_object_del(r, priv[i]);
    boolean(r, "can_operate", operate && !strcmp(str(s, "operator_id"), who));
    boolean(r, "trial_supported", num(s,"trial_supported"));
    if (!detail) {
        json_object_object_del(r,"candidates");json_object_object_del(r,"connections");
        json_object_object_del(r,"trial_history");json_object_object_del(r,"bisect");
        number(r,"total_connections",child(s,"connections")?json_object_object_length(child(s,"connections")):0);
    }
    return r;
}
static struct json_object *public_report(struct json_object *s, const char *who, int operate) {
    struct json_object *r = copy(s);
    const char *priv[] = {"queries", "cursor", "log_inode", "log_anchor", "operator_id", NULL};
    for (int i = 0; priv[i]; i++)
        json_object_object_del(r, priv[i]);
    boolean(r, "can_operate", operate && !strcmp(str(s, "operator_id"), who));
    return r;
}
#include "ad_analyzer_connections.inc"

static int fresh(const struct ada_environment *e, struct stat *st) {
    return stat(e->dns_log, st) == 0 && S_ISREG(st->st_mode) &&
           e->now - st->st_mtime <= LOG_FRESH && e->now >= st->st_mtime;
}
static struct json_object *sources(const char *dns_state) {
    struct json_object *a = arr(), *v = obj();
    text(v, "id", "dns");
    boolean(v, "available", 1);
    text(v, "state", dns_state);
    text(v, "precision", "source_ip_query_id");
    json_object_array_add(a, v);
    const char *missing[] = {"conn", "tls_sni", "http_host", "udp443_ip", NULL};
    for (int i = 0; missing[i]; i++) {
        v = obj();
        text(v, "id", missing[i]);
        boolean(v, "available", 0);
        text(v, "state", "unavailable");
        text(v, "reason", i ? "observer_unavailable" : "session_observer_not_connected");
        json_object_array_add(a, v);
    }
    return a;
}
static struct json_object *capabilities(const struct ada_environment *e, int operate) {
    struct stat st;
    int native = provider_ready(e);
    int ready = native || (!e->provider && fresh(e, &st));
    struct json_object *r = obj(), *a = obj(), *l = obj(), *p = obj(), *ob = obj();
    text(r, "version", "device-dns-session-v2");
    text(p, "id", "aegisxd-content-policy");
    text(p, "management_route", "/app/#/policy-engine/aegisx");
    text(p, "device_enforcement", native ? "exact_query_mac_ip" : "unavailable");
    json_object_object_add(r, "provider", p);
    json_object_object_add(ob, "sources", sources(ready ? "ready" : "requires_action"));
    boolean(ob, "ipv4", 1);
    boolean(ob, "ipv6", 1);
    text(ob, "attribution", "exact_ip; device identity is a DHCP lease snapshot when available");
    if(e->conntrack&&access(e->conntrack,R_OK)==0){
        struct json_object *ss=child(ob,"sources");for(size_t i=0;i<json_object_array_length(ss);i++){struct json_object *v=json_object_array_get_idx(ss,i);if(!strcmp(str(v,"id"),"conn")||!strcmp(str(v,"id"),"udp443_ip")){boolean(v,"available",1);text(v,"state","ready");text(v,"reason","ip_tuple_snapshots_only");}}
    }
    json_object_object_add(r, "observation", ob);
    boolean(a, "can_observe", ready && operate);
    boolean(a, "can_trial_block", native && operate);
    boolean(a, "can_trial_allow", native && operate);
    boolean(a, "can_commit_block", native && operate);
    boolean(a, "can_commit_allow", native && operate);
    boolean(a, "can_bisect", native && operate);
    text(a, "reason", native ? "" : "native_dns_provider_not_ready");
    text(a,"message",native ? "设备精确 DNS 试验已就绪。放行保留正常上游与 DNSSEC；连接层阻断会单独报告冲突。" : "需要支持 DWAD1 的原生 DNS 设备执行点。可查看历史报告。");
    json_object_object_add(r, "actions", a);
    p = obj();
    boolean(p, "read", 1);
    boolean(p, "operate", operate);
    boolean(p, "configure", operate && native);
    json_object_object_add(r, "permissions", p);
    number(l, "max_concurrent_capture", MAX_CAPTURE);
    number(l, "max_sessions_retained", MAX_SESSIONS);
    number(l, "observe_ttl_default", OBS_DEFAULT);
    number(l,"trial_ttl_min",30);number(l,"trial_ttl_max",900);number(l,"trial_ttl_default",120);number(l,"max_candidates",128);number(l,"max_connection_tuples",512);
    boolean(a,"ipv6_source_trial",0);text(a,"trial_scope","DHCP-bound IPv4 source; A and AAAA questions; DNS only");
    number(l, "observe_ttl_max", OBS_MAX);
    number(l, "max_domains_per_session", MAX_DOMAINS);
    number(l, "observations_page_max", PAGE_MAX);
    number(l, "report_retention_per_device", PER_DEVICE_REPORTS);
    number(l, "report_list_max", MAX_REPORTS);
    number(l, "max_document_bytes", MAX_DOCUMENT);
    number(l, "report_total_bytes_max", REPORT_BYTES);
    number(l, "idempotency_total_bytes_max", REQUEST_BYTES);
    number(l, "idempotency_max_requests", 256);
    number(l, "database_bytes_max", 32 * 1024 * 1024);
    json_object_object_add(r, "limits", l);
    text(r, "preparation_reason", ready ? "" : "query_log_not_ready");
    text(r, "preparation_message",
         ready ? ""
               : "需要现有 DNS 查询工作日志。当前版本不会自动开启长期日志或重启 "
                 "DNS；可先查看历史报告。");
    return ok(r);
}
/* dnsmasq extra includes daemon pid, query serial and often client/ip:port.
 * The daemon id prevents query serial reuse after a restart from joining data. */
static int token(const char *p, char *out, size_t n) {
    size_t i = 0;
    while (*p && !isspace((unsigned char)*p)) {
        if (i + 1 >= n)
            return 0;
        out[i++] = *p++;
    }
    out[i] = 0;
    return i > 0;
}
static int line_header(const char *line, char *key, size_t n, int64_t now, int64_t *ts) {
    struct tm tm = {0}, cur;
    time_t t = (time_t)now;
    localtime_r(&t, &cur);
    char *end = strptime(line, "%b %d %H:%M:%S", &tm);
    if (end) {
        tm.tm_year = cur.tm_year;
        tm.tm_isdst = -1;
        *ts = mktime(&tm);
        if (*ts > now + 86400) {
            tm.tm_year--;
            *ts = mktime(&tm);
        }
    } else {
        memset(&tm, 0, sizeof(tm));
        end = strptime(line, "%Y-%m-%d %H:%M:%S", &tm);
        if (!end)
            return 0;
        tm.tm_isdst = -1;
        *ts = mktime(&tm);
    }
    const char *p = strstr(end, "dnsmasq[");
    char pid[24], serial[32];
    if (!p)
        return 0;
    p += 8;
    int a = 0;
    while (isdigit((unsigned char)*p) && a < 23)
        pid[a++] = *p++;
    pid[a] = 0;
    if (!a || strncmp(p, "]: ", 3))
        return 0;
    p += 3;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    a = 0;
    while (isdigit((unsigned char)*p) && a < 31)
        serial[a++] = *p++;
    serial[a] = 0;
    if (!a || !isspace((unsigned char)*p))
        return 0;
    snprintf(key, n, "%s:%s", pid, serial);
    return 1;
}
static void factor(struct json_object *a, const char *code, int delta, const char *why) {
    struct json_object *f = obj();
    text(f, "code", code);
    number(f, "delta", delta);
    text(f, "detail", why);
    json_object_array_add(a, f);
}
#include "../dns_policy/ad_public_suffix.inc"
static int suffix_compare(const void *a,const void *b){return strcmp(*(const char *const *)a,*(const char *const *)b);}
static int suffix_has(const char *s){return bsearch(&s,ad_public_suffixes,sizeof(ad_public_suffixes)/sizeof(*ad_public_suffixes),sizeof(*ad_public_suffixes),suffix_compare)!=NULL;}
static const char *registered_domain(const char *name){
    const char *labels[128];size_t n=0;labels[n++]=name;for(const char *p=name;*p&&n<128;p++)if(*p=='.')labels[n++]=p+1;
    size_t suffix=1;
    for(size_t i=0;i<n;i++){char key[256];snprintf(key,sizeof(key),"!%s",labels[i]);if(suffix_has(key)){suffix=n-i-1;break;}if(suffix_has(labels[i])&&n-i>suffix)suffix=n-i;if(i+1<n){snprintf(key,sizeof(key),"*.%s",labels[i+1]);if(suffix_has(key)&&n-i>suffix)suffix=n-i;}}
    return n>suffix?labels[n-suffix-1]:name;
}
static void score(struct json_object *d) {
    int total = 0;
    const char *name = str(d, "domain");
    struct json_object *f = arr();
    const char *hints[] = {"adservice", "adserver", "doubleclick", "telemetry",
                           "analytics", "tracker",  NULL};
    for (int i = 0; hints[i]; i++)
        if (strstr(name, hints[i])) {
            total += 24;
            factor(f, "domain_hint", 24, hints[i]);
            break;
        }
    if (num(d, "blocked_observed")) {
        total += 32;
        factor(f, "dns_block_answer", 32, "本会话收到零地址应答；并不证明广告用途");
    }
    if (num(d, "dns_count") >= 8) {
        total += 8;
        factor(f, "repeated_query", 8, "重复 DNS 查询，不是广告展示次数");
    }
    if (strstr(name, "login") || strstr(name, "auth") || strstr(name, "payment")) {
        total -= 18;
        factor(f, "business_risk", -18, "名称涉及登录、认证或支付；应检查正常功能");
    }
    if (total < 0)
        total = 0;
    number(d, "clue_score", total);
    text(d, "clue_level",
         total >= 55   ? "high"
         : total >= 30 ? "suspicious"
         : total > 0   ? "low"
                       : "none");
    text(d, "score_version", "dwrt-dns-clues-1");
    json_object_object_add(d, "clue_factors", f);
    text(d,"group_key",registered_domain(name));
    text(d,"group_basis","public_suffix_list_20261002");
}
static struct json_object *domain_entry(struct json_object *s, const char *name, int64_t ts) {
    struct json_object *map = child(s, "domains"), *d = child(map, name);
    if (d)
        return d;
    if (json_object_object_length(map) >= MAX_DOMAINS) {
        number(s, "dropped", num(s, "dropped") + 1);
        return NULL;
    }
    d = obj();
    text(d, "id", name);
    text(d, "domain", name);
    number(d, "dns_count", 0);
    number(d, "first_seen", ts);
    number(d, "last_seen", ts);
    text(d, "attribution", "exact_source_ip");
    const char *arrays[] = {"qtypes", "resolved_ips", "answers", "cnames", "response_codes", NULL};
    for (int i = 0; arrays[i]; i++)
        json_object_object_add(d, arrays[i], arr());
    json_object_object_add(d, "rule", NULL);
    text(d, "rule_state", "unknown");
    text(d, "actual_action", "unknown");
    json_object_object_add(map, name, d);
    return d;
}
static void parse_line(struct json_object *s, const char *line, int64_t now) {
    char key[72], name[256], raw[512], ip[80], qtype[24];
    int64_t ts = 0;
    if (!line_header(line, key, sizeof(key), now, &ts) || ts < num(s, "started_at") ||
        ts > now + 2 || ts > num(s, "expires_at"))
        return;
    struct json_object *queries = child(s, "queries");
    const char *p = strstr(line, " query[");
    if (p) {
        const char *r = strchr(p, ']'), *from = strstr(p, " from ");
        if (!r || !from)
            return;
        size_t n = (size_t)(r - (p + 7));
        if (!n || n >= sizeof(qtype))
            return;
        memcpy(qtype, p + 7, n);
        qtype[n] = 0;
        /* Clear even a different client's reuse of this serial. */
        json_object_object_del(queries, key);
        if (!token(from + 6, raw, sizeof(raw)) || !ip_normalize(raw, ip, sizeof(ip)) ||
            strcmp(ip, str(s, "device_ip")))
            return;
        if (!token(r + 2, raw, sizeof(raw)) || !domain_normalize(raw, name, sizeof(name))) {
            number(s, "dropped", num(s, "dropped") + 1);
            return;
        }
        struct json_object *d = domain_entry(s, name, ts);
        if (!d)
            return;
        number(d, "dns_count", num(d, "dns_count") + 1);
        number(d, "last_seen", ts);
        evidence_value(s, d, "qtypes", qtype);
        score(d);
        struct json_object *q = obj();
        text(q, "domain", name);
        number(q, "time", ts);
        json_object_object_add(queries, key, q);
        if (json_object_object_length(queries) > 512) {
            json_object_object_add(s, "queries", obj());
            number(s, "correlation_dropped", num(s, "correlation_dropped") + 1);
        }
        number(s, "last_event_at", ts);
        return;
    }
    struct json_object *q = child(queries, key);
    if (!q || ts < num(q, "time") || ts - num(q, "time") > 30)
        return;
    struct json_object *d = child(child(s, "domains"), str(q, "domain"));
    if (!d)
        return;
    const char *policy=strstr(line," policy ");
    if(policy){char domain[256],action[16],id[96],matchdomain[256],match[16];
        if(sscanf(policy," policy %255s is %15s rule=%95s matched=%255s match=%15s",domain,action,id,matchdomain,match)==5&&!strcmp(domain,str(d,"domain"))){
            struct json_object *rule=obj();text(rule,"id",id);text(rule,"provider","aegisxd-content-policy");text(rule,"matched_domain",matchdomain);text(rule,"match",match);text(rule,"action",action);text(rule,"evidence","native_dns_query_decision");number(rule,"observed_at",ts);json_object_object_add(d,"rule",rule);text(d,"rule_state","matched_query_decision");
        }return;
    }
    const char *answer = strstr(line, " reply ");
    const char *origin = "reply";
    if (!answer) { answer = strstr(line, " cached "); origin = "cached"; }
    if (!answer) { answer = strstr(line, " config "); origin = "config"; }
    if (!answer)
        return;
    p = strstr(line, " is ");
    if (!p || !token(p + 4, raw, sizeof(raw)))
        return;
    evidence_value(s, d, "answers", raw);
    text(d, "last_answer_source", origin);
    /* Extra-log serials preserve the actual CNAME chain. A different response
     * name on the same query is a target, not an independent client query. */
    char answer_name[256];
    if (token(answer + strlen(origin) + 2, name, sizeof(name)) &&
        domain_normalize(name, answer_name, sizeof(answer_name)) &&
        strcmp(answer_name, str(d, "domain")))
        evidence_value(s, d, "cnames", answer_name);
    number(d, "last_seen", ts);
    if(!strcmp(raw,"<CNAME>")){char cname[256],normalized[256];if(token(p+4+strlen(raw)+1,cname,sizeof(cname))&&domain_normalize(cname,normalized,sizeof(normalized)))evidence_value(s,d,"cnames",normalized);}
    if (!strcmp(raw, "0.0.0.0") || !strcmp(raw, "::")) {
        boolean(d, "blocked_observed", 1);
        text(d, "actual_action", "dns_zero_answer");
        if (!child(d, "rule")) text(d, "rule_state", "blocking_answer_rule_unknown");
    } else if (ip_normalize(raw, ip, sizeof(ip)))
        evidence_value(s, d, "resolved_ips", ip);
    const char *codes[] = {"NXDOMAIN", "NODATA", "SERVFAIL", "REFUSED", NULL};
    for (int i = 0; codes[i]; i++)
        if (!strcmp(raw, codes[i]))
            evidence_value(s, d, "response_codes", codes[i]);
    score(d);
}
/* An anchor detects log truncation followed by regrowth on the same inode. */
static void anchor(FILE *f, int64_t offset, char out[65]) {
    unsigned char b[32];
    size_t n = offset < 32 ? (size_t)offset : 32;
    out[0] = 0;
    if (!n)
        return;
    if (fseeko(f, offset - (off_t)n, SEEK_SET))
        return;
    n = fread(b, 1, n, f);
    for (size_t i = 0; i < n; i++)
        snprintf(out + i * 2, 3, "%02x", b[i]);
}
static int capture(const struct ada_environment *e, struct json_object *s) {
    if (*str(s, "device_id")) {
        char mac[80], label[128];
        if (!lease_target(e, str(s, "device_ip"), mac, sizeof(mac), label, sizeof(label)) ||
            strcmp(mac, str(s, "device_id"))) {
            text(s, "stop_reason", "target_identity_changed");
            text(s, "coverage_reason", "dhcp_identity_lost_or_changed");
            boolean(s, "truncated", 1);
            return 0;
        }
    }
    struct stat st;
    FILE *f = fopen(e->dns_log, "r");
    if (!f || fstat(fileno(f), &st)) {
        if (f)
            fclose(f);
        text(s, "state", "degraded");
        text(s, "source_reason", "query_log_unavailable");
        capture_connections(e,s,0);return 0;
    }
    int64_t offset = num(s, "cursor");
    char before[65];
    anchor(f, offset, before);
    if (st.st_ino != (ino_t)num(s, "log_inode") || st.st_size < offset ||
        strcmp(before, str(s, "log_anchor"))) {
        offset = 0;
        number(s, "log_rotations", num(s, "log_rotations") + 1);
        json_object_object_add(s, "queries", obj());
        boolean(s, "truncated", 1);
        text(s, "coverage_reason", "log_rotated_or_truncated");
    }
    if (fseeko(f, offset, SEEK_SET)) {
        fclose(f);
        return -1;
    }
    int64_t barrier = st.st_size, consumed = 0;
    unsigned lines = 0;
    char line[4096];
    while (ftello(f) < barrier && consumed < READ_BYTES) {
        off_t start = ftello(f);
        if (!fgets(line, sizeof(line), f))
            break;
        size_t len = strlen(line);
        if (!len)
            continue;
        if (line[len - 1] != '\n') {
            if (feof(f)) {
                fseeko(f, start, SEEK_SET);
                break;
            }
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {
            }
            number(s, "dropped", num(s, "dropped") + 1);
        } else
            parse_line(s, line, e->now);
        consumed += ftello(f) - start;
        if (++lines % 16 == 0 && strlen(json(s)) > MAX_DOCUMENT - 65536) {
            boolean(s, "truncated", 1);
            text(s, "coverage_reason", "session_byte_limit");
            text(s, "stop_reason", "resource_limit");
            break;
        }
    }
    offset = ftello(f);
    char after[65];
    anchor(f, offset, after);
    fclose(f);
    text(s, "log_anchor", after);
    number(s, "cursor", offset);
    number(s, "log_inode", st.st_ino);
    number(s, "last_updated_at", e->now);
    boolean(s, "backlog", offset < barrier);
    int ready = e->provider ? provider_ready(e) : e->now - st.st_mtime <= LOG_FRESH;
    text(s, "state", ready ? "capturing" : "degraded");
    text(s, "source_reason", ready ? "" : "no_recent_log_events");
    json_object_object_add(s, "sources", sources(ready ? "ready" : "idle_or_unavailable"));
    capture_connections(e,s,0);
    return 0;
}
/* Called inside the write transaction, before inserting the new document. */
static int reserve_bytes(sqlite3 *db, const char *table, const char *measure, int64_t budget) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "DELETE FROM %s WHERE rowid IN (SELECT rowid FROM (SELECT rowid,"
             "sum(%s) OVER (ORDER BY created DESC,rowid DESC) AS bytes FROM %s) WHERE bytes>%lld)",
             table, measure, table, (long long)budget);
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}
static int finalize(sqlite3 *db, const struct ada_environment *e, struct json_object *s,
                    const char *reason) {
    char id[48], reason_copy[96];
    snprintf(reason_copy, sizeof(reason_copy), "%s", reason);
    reason = reason_copy;
    if (*str(s, "report_id"))
        return 0;
    if (make_id(id, sizeof(id), "report_"))
        return -1;
    text(s, "state",
         !strcmp(reason, "observe_ttl")       ? "expired"
         : !strcmp(reason, "service_restart") || !strcmp(reason, "target_identity_changed") ? "failed"
                                              : "stopped");
    text(s, "stop_reason", reason);
    number(s, "stopped_at", e->now);
    number(s, "revision", num(s, "revision") + 1);
    text(s, "report_id", id);
    text(s, "report_state", "saved");
    struct json_object *r = copy(s);
    json_object_object_del(r, "queries");
    json_object_object_del(r, "cursor");
    json_object_object_del(r, "log_anchor");
    json_object_object_del(r, "log_inode");
    text(r, "id", id);
    text(r, "label", "");
    number(r, "report_revision", 1);
    number(r, "captured_at", e->now);
    if(!child(r,"conclusions"))json_object_object_add(r,"conclusions",arr());
    if(!child(r,"trial_history"))json_object_object_add(r,"trial_history",arr());
    sqlite3_stmt *st = NULL;
    int rc = -1;
    size_t report_bytes = strlen(json(r));
    if (report_bytes <= MAX_DOCUMENT &&
        !reserve_bytes(db, "analyzer_reports", "length(CAST(document AS BLOB))",
                       REPORT_BYTES - (int64_t)report_bytes) &&
        sqlite3_prepare_v2(db, "INSERT INTO analyzer_reports VALUES(?1,?2,?3,?4,?5,?6,?7)", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, str(s, "session_id"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, str(s, "operator_id"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, str(s, "device_ip"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, str(s, "mode"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, e->now);
        sqlite3_bind_text(st, 7, json(r), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    }
    sqlite3_finalize(st);
    json_object_put(r);
    if (rc || save_session(db, s))
        return -1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
                           "DELETE FROM analyzer_reports WHERE ip=?1 AND id NOT IN (SELECT id FROM "
                           "analyzer_reports WHERE ip=?1 ORDER BY created DESC,id DESC LIMIT ?2)",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, str(s, "device_ip"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, PER_DEVICE_REPORTS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    return sqlite3_exec(db,
                        "DELETE FROM analyzer_reports WHERE id NOT IN (SELECT id FROM "
                        "analyzer_reports ORDER BY created DESC,id DESC LIMIT 120)",
                        NULL, NULL, NULL) == SQLITE_OK
               ? 0
               : -1;
}
int ada_tick(const struct ada_environment *e, int service_start) {
    sqlite3 *db = NULL;
    if (open_db(e, &db))
        return -1;
    sqlite3_busy_timeout(db, 25);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    struct json_object *all = arr();
    if (sqlite3_prepare_v2(db, "SELECT document FROM analyzer_sessions ORDER BY created LIMIT 12", -1,
                           &st, NULL) == SQLITE_OK)
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *s = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
            if (s)
                json_object_array_add(all, s);
        }
    sqlite3_finalize(st);
    int rc = 0;
    for (size_t i = 0; i < json_object_array_length(all); i++) {
        struct json_object *s = json_object_array_get_idx(all, i);
        const char *why = service_start                    ? "service_restart"
                          : e->now >= num(s, "expires_at") ? "observe_ttl"
                                                           : NULL;
        if (e->provider) {
            int status=200;struct json_object *request=obj();char rid[80];
            snprintf(rid,sizeof(rid),"maint-%s-%lld",str(s,"session_id"),(long long)e->now);
            text(request,"request_id",rid);
            if(trial_live(s)) {
                const char *reason=service_start?"service_restart":num(child(s,"trial"),"expires_at")<=e->now?"trial_ttl":NULL;
                char mac[80],label[128];
                if(!lease_target(e,str(s,"device_ip"),mac,sizeof(mac),label,sizeof(label))||strcmp(mac,str(s,"device_id")))reason="target_identity_changed";
                struct json_object *reply=provider_request(e,"status",s,NULL,&status);
                if(status<400&&!child(reply,"trial"))reason="provider_restarted_or_reverted";
                json_object_put(reply);
                if(reason) {
                    status=200;reply=withdraw(e,s,request,&status);json_object_put(reply);
                    if(status>=400)text(child(s,"trial"),"apply_state","reverting");
                    else {text(child(s,"trial"),"end_reason",reason);if(child(s,"bisect"))text(child(s,"bisect"),"state","expired");}
                    number(s,"revision",num(s,"revision")+1);
                    if(report_conclusions(db,s,e)){json_object_put(request);rc=-1;break;}
                }
            }
            if(why&&active(s)){
                snprintf(rid,sizeof(rid),"stop-%s-%lld",str(s,"session_id"),(long long)e->now);text(request,"request_id",rid);
                struct json_object *reply=provider_request(e,"stop",s,request,&status);json_object_put(reply);
            }
            json_object_put(request);
        }
        if (!active(s)){if(save_session(db,s))rc=-1;if(rc)break;continue;}
        if (!service_start && capture(e, s)) {
            rc = -1;
            break;
        }
        if (*str(s, "stop_reason"))
            why = str(s, "stop_reason");
        if (why) {
            if (num(s, "backlog")) {
                boolean(s, "truncated", 1);
                text(s, "coverage_reason", "capture_end_backlog");
            }
            if (finalize(db, e, s, why)) {
                rc = -1;
                break;
            }
        } else if (save_session(db, s)) {
            rc = -1;
            break;
        }
    }
    json_object_put(all);
    if (sqlite3_exec(db, rc ? "ROLLBACK" : "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        rc = -1;
    sqlite3_close(db);
    return rc;
}
static int page_number(struct json_object *q, const char *key, int def, int max) {
    const char *s = str(q, key);
    if (!*s)
        return def;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    return end && !*end && v >= 0 ? (v > max ? max : (int)v) : def;
}
static struct json_object *list_rows(sqlite3 *db, const char *table, struct json_object *q,
                                     const char *who, int operate) {
    struct json_object *r = obj(), *items = arr();
    sqlite3_stmt *st = NULL;
    char sql[220];
    int reports = !strcmp(table, "analyzer_reports");
    int offset = page_number(q, "offset", 0, 100000), limit = page_number(q, "limit", 30, 200);
    if (!limit)
        limit = 30;
    snprintf(sql, sizeof(sql),
             "SELECT document FROM %s WHERE (?1='' OR ip=?1) ORDER BY created DESC,id DESC", table);
    int total = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, str(q, "device_ip"), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *s = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
            if (!s)
                continue;
            if (*str(q, "mode") && strcmp(str(q, "mode"), str(s, "mode"))) {
                json_object_put(s);
                continue;
            }
            if (total >= offset && total < offset + limit) {
                struct json_object *v = public_session(s, 0, who, operate);
                if (reports)
                    number(v, "total_domains", json_object_object_length(child(s, "domains")));
                json_object_array_add(items, v);
            }
            total++;
            json_object_put(s);
        }
    }
    sqlite3_finalize(st);
    json_object_object_add(r, reports ? "reports" : "sessions", items);
    number(r, "total", total);
    number(r, "offset", offset);
    number(r, "limit", limit);
    return ok(r);
}
static int compare_domain(const void *aa, const void *bb) {
    struct json_object *a = *(struct json_object *const *)aa, *b = *(struct json_object *const *)bb;
    int diff = (int)(num(b, "clue_score") - num(a, "clue_score"));
    return diff ? diff : strcmp(str(a, "domain"), str(b, "domain"));
}
static struct json_object *observations(struct json_object *s, struct json_object *q) {
    struct json_object *r = obj(), *a = arr(), *map = child(s, "domains");
    int total = 0;
    struct json_object **rows = calloc(json_object_object_length(map) + 1, sizeof(*rows));
    if (!rows) {
        json_object_put(a);
        json_object_put(r);
        return NULL;
    }
    struct json_object *ips = obj(), *hosts = obj(), *connections = child(s, "connections");
    if (connections) { json_object_object_foreach(connections, key, entry) {
        (void)key;
        if (*str(entry, "destination_ip")) boolean(ips, str(entry, "destination_ip"), 1);
        if (*str(entry, "domain_hint")) boolean(hosts, str(entry, "domain_hint"), 1);
    }}
    json_object_object_foreach(map, k, v) {
        (void)k;
        if (*str(q, "q") && !strcasestr(str(v, "domain"), str(q, "q")) &&
            !strcasestr(json(child(v, "clue_factors")), str(q, "q")))
            continue;
        if (*str(q, "level") && strcmp(str(q, "level"), str(v, "clue_level")))
            continue;
        if (!strcmp(str(q, "blocked"), "1") && !num(v, "blocked_observed"))
            continue;
        int connected = child(hosts, str(v, "domain")) != NULL;
        struct json_object *addresses = child(v, "resolved_ips"), *rule = child(v, "rule");
        for (size_t j = 0; addresses && j < json_object_array_length(addresses) && !connected; j++)
            connected = child(ips, json_object_get_string(json_object_array_get_idx(addresses, j))) != NULL;
        int parent = rule && !strcmp(str(rule, "match"), "suffix") &&
                     *str(rule, "matched_domain") && strcmp(str(rule, "matched_domain"), str(v, "domain"));
        if ((!strcmp(str(q, "connection"), "1") && !connected) ||
            (!strcmp(str(q, "parent"), "1") && !parent)) continue;
        struct json_object *row = copy(v);
        boolean(row, "has_connection_clue", connected);
        text(row, "connection_attribution", connected ? "inferred_same_device_ip_or_host" : "not_observed");
        boolean(row, "parent_rule_observed", parent);
        rows[total++] = row;
    }
    qsort(rows, total, sizeof(*rows), compare_domain);
    int offset = page_number(q, "offset", 0, 100000),
        limit = page_number(q, "limit", 100, PAGE_MAX);
    if (!limit)
        limit = 100;
    for (int i = offset; i < total && i < offset + limit; i++) {
        json_object_array_add(a, json_object_get(rows[i]));
    }
    for (int i = 0; i < total; i++) json_object_put(rows[i]);
    free(rows);
    json_object_put(ips); json_object_put(hosts);
    json_object_object_add(r, "observations", a);
    number(r, "total", total);
    number(r, "offset", offset);
    number(r, "limit", limit);
    number(r, "last_updated_at", num(s, "last_updated_at"));
    number(r, "dropped", num(s, "dropped"));
    number(r, "evidence_dropped", num(s, "evidence_dropped"));
    number(r, "correlation_dropped", num(s, "correlation_dropped"));
    boolean(r, "truncated", num(s, "truncated"));
    text(r, "coverage_reason", str(s, "coverage_reason"));
    struct json_object *direct=arr();
    if(connections){json_object_object_foreach(connections,k,v){(void)k;json_object_array_add(direct,copy(v));}}
    json_object_object_add(r,"direct_ips",direct);
    text(r,"direct_ip_state",connections?"observed":"unavailable");
    return ok(r);
}
static int lease_target(const struct ada_environment *e, const char *ip, char *mac, size_t mn,
                        char *label, size_t ln) {
    FILE *f = fopen(e->leases, "r");
    char line[1024], addr[80], raw[80], name[128];
    long long expiry;
    mac[0] = label[0] = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "%lld %79s %79s %127s", &expiry, raw, addr, name) == 4) {
            char normalized[80];
            if ((!expiry || expiry > e->now) &&
                ip_normalize(addr, normalized, sizeof(normalized)) && !strcmp(ip, normalized)) {
                snprintf(mac, mn, "%s", raw);
                for (char *p = mac; *p; p++)
                    *p = (char)tolower((unsigned char)*p);
                if (strcmp(name, "*"))
                    snprintf(label, ln, "%s", name);
                fclose(f);
                return 1;
            }
        }
    fclose(f);
    return 0;
}
static struct json_object *create_session(sqlite3 *db, const struct ada_environment *e,
                                          const char *who, struct json_object *b, int *status) {
    char ip[80], mac[80], label[128], id[48];
    const char *mode = str(b, "mode");
    if (!ip_normalize(str(b, "device_ip"), ip, sizeof(ip)))
        return error(status, 400, "invalid_target", "请输入合法单播 IP 地址");
    if (strcmp(mode, "find_ads") && strcmp(mode, "false_positive"))
        return error(status, 400, "invalid_mode", "请选择找广告或查误伤");
    int ttl = child(b, "observe_ttl") ? (int)num(b, "observe_ttl") : OBS_DEFAULT;
    if (ttl < 30 || ttl > OBS_MAX)
        return error(status, 400, "invalid_ttl", "采集时限必须为 30–1800 秒");
    lease_target(e, ip, mac, sizeof(mac), label, sizeof(label));
    if (*str(b, "device_id") && strcasecmp(str(b, "device_id"), mac))
        return error(status, 409, "device_identity_changed",
                     "该 IP 当前租约与所选设备不一致，请重新选择；无法确认时可使用明确的 IP 会话");
    sqlite3_stmt *st = NULL;
    int count = 0, total = 0;
    if (sqlite3_prepare_v2(db, "SELECT document FROM analyzer_sessions", -1, &st, NULL) ==
        SQLITE_OK)
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *s = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
            total++;
            if (active(s)) {
                count++;
                if (!strcmp(str(s, "device_ip"), ip)) {
                    struct json_object *r = error(status, 409, "device_capture_in_use",
                                                  "此 IP 已有活动会话，请切换会话或结束后重开");
                    text(r, "session_id", str(s, "session_id"));
                    json_object_put(s);
                    sqlite3_finalize(st);
                    return r;
                }
            }
            json_object_put(s);
        }
    sqlite3_finalize(st);
    if (count >= MAX_CAPTURE)
        return error(status, 429, "capture_capacity", "并发采集已达上限");
    struct stat info;
    if (!(e->provider ? provider_ready(e) : fresh(e, &info)))
        return error(status, 409, "query_log_not_ready",
                     "DNS 查询日志尚未就绪。未启动采集，也未修改 DNS 配置。");
    mutation_id(id,sizeof(id),"session_",who,str(b,"request_id"));
    struct json_object *s = obj();
    text(s, "session_id", id);
    text(s, "operator_id", who);
    text(s, "device_ip", ip);
    text(s, "device_id", mac);
    text(s, "device_label", *label ? label : ip);
    text(s, "identity_basis", *mac ? "dhcp_lease_snapshot" : "ip_only");
    text(s, "mode", mode);
    text(s, "state", "capturing");
    text(s, "report_state", "not_finalized");
    number(s, "revision", 1);
    number(s, "started_at", e->now);
    number(s, "expires_at", e->now + ttl);
    number(s, "observe_ttl", ttl);
    number(s, "last_updated_at", e->now);
    memset(&info,0,sizeof(info));stat(e->dns_log,&info);
    number(s, "cursor", info.st_size);
    number(s, "log_inode", info.st_ino);
    json_object_object_add(s, "domains", obj());
    json_object_object_add(s, "queries", obj());
    json_object_object_add(s, "sources", sources("ready"));
    json_object_object_add(s, "candidates", arr());
    FILE *f = fopen(e->dns_log, "r");
    char tail[65] = "";
    if (f) {
        anchor(f, info.st_size, tail);
        fclose(f);
    }
    text(s, "log_anchor", tail);
    if (*str(b, "reuse_report_id")) {
        struct json_object *old = load(db, "analyzer_reports", str(b, "reuse_report_id"));
        if (!old || strcmp(str(old, "device_ip"), ip) || strcmp(str(old, "mode"), mode)) {
            if (old)
                json_object_put(old);
            json_object_put(s);
            return error(status, 409, "report_target_mismatch",
                         "历史候选必须明确沿用原目标 IP 和模式");
        }
        struct json_object *selected = child(b, "candidates"), *c = arr();
        if (!json_object_is_type(selected, json_type_array) ||
            json_object_array_length(selected) > 128) {
            json_object_put(old);
            json_object_put(c);
            json_object_put(s);
            return error(status, 400, "invalid_candidates", "历史候选最多 128 条");
        }
        for (size_t i = 0; i < json_object_array_length(selected); i++) {
            const char *name = json_object_get_string(json_object_array_get_idx(selected, i));
            if (name && child(child(old, "domains"), name))
                unique(c, name, 128);
        }
        json_object_object_add(s, "candidates", c);
        json_object_put(old);
    }
    if (total >= MAX_SESSIONS &&
        sqlite3_exec(db,
                     "DELETE FROM analyzer_sessions WHERE active=0 AND coalesce(json_extract(document,'$.trial.apply_state'),'') NOT IN ('applied','reverting') AND id=(SELECT id FROM "
                     "analyzer_sessions WHERE active=0 AND coalesce(json_extract(document,'$.trial.apply_state'),'') NOT IN ('applied','reverting') ORDER BY created,id LIMIT 1)",
                     NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(s);
        return error(status, 503, "storage_unavailable", "无法轮换会话记录");
    }
    capture_connections(e,s,1);
    if (e->provider) {
        struct json_object *request=copy(b);number(request,"observe_ttl",ttl);
        struct json_object *reply=provider_request(e,"observe",s,request,status);json_object_put(request);
        if(*status>=400){json_object_put(s);return reply;}json_object_put(reply);
        boolean(s,"trial_supported",*mac!=0);
        text(s,"observation_provider","native_dns");
    }
    if (save_session(db, s)) {
        json_object_put(s);
        return error(status, 503, "storage_unavailable", "会话未能保存");
    }
    struct json_object *r = public_session(s, 1, who, 1);
    json_object_put(s);
    *status = 201;
    return ok(r);
}
static struct json_object *preview(struct json_object *s, struct json_object *b, int *status) {
    struct json_object *rules = child(b, "rules"), *out = arr(), *seen = obj();
    size_t n = json_object_array_length(rules);
    if (!json_object_is_type(rules, json_type_array) || !n || n > 128) {
        json_object_put(out);
        json_object_put(seen);
        return error(status, 400, "invalid_rules", "规则必须为 1–128 条显式 block/allow 条目");
    }
    if (strcmp(str(child(b, "scope"), "type"), "device") ||
        strcmp(str(child(b, "scope"), "device_id"), str(s, "device_id"))) {
        json_object_put(out);
        json_object_put(seen);
        return error(status, 409, "scope_conflict", "预览必须绑定本会话目标设备");
    }
    for (size_t i = 0; i < n; i++) {
        struct json_object *it = json_object_array_get_idx(rules, i);
        char name[256];
        const char *action = str(it, "action"), *match = str(it, "match");
        if (!domain_normalize(str(it, "domain"), name, sizeof(name)) ||
            (strcmp(action, "block") && strcmp(action, "allow")) || strcmp(match, "exact")) {
            json_object_put(out);
            json_object_put(seen);
            return error(status, 400, "invalid_rule",
                         "必须指定完整域名、exact 和 block/allow 动作");
        }
        struct json_object *previous = child(seen, name);
        if (previous) {
            if (strcmp(json_object_get_string(previous), action)) {
                json_object_put(out);
                json_object_put(seen);
                return error(status, 409, "action_conflict", "同一域名不能同时拦截和放行");
            }
            continue;
        }
        text(seen, name, action);
        struct json_object *r = copy(it);
        text(r, "domain", name);
        text(r, "provider", "aegisxd-content-policy");
        text(r, "operation", "not_saved");
        text(r, "conflict",
             !strcmp(action, "allow") ? "exact_device_allow_unavailable"
                                      : "shared_address_isolation_unavailable");
        json_object_array_add(out, r);
    }
    json_object_put(seen);
    struct json_object *r = obj();
    json_object_object_add(r, "rules", out);
    json_object_object_add(r, "scope", copy(child(b, "scope")));
    number(r, "revision", num(s, "revision"));
    boolean(r, "can_commit", 0);
    text(r, "reason", "exact_device_domain_provider_unavailable");
    return ok(r);
}
#include "ad_analyzer_trials.inc"

static struct json_object *dispatch(sqlite3 *db, const struct ada_environment *e, const char *who,
                                    int operate, const char *method, const char *path,
                                    struct json_object *q, struct json_object *b, int *status) {
    int get = !strcmp(method, "GET");
    if (!strcmp(path, "capabilities") && get)
        return capabilities(e, operate);
    if (!strcmp(path, "sessions")) {
        if (get)
            return list_rows(db, "analyzer_sessions", q, who, operate);
        if (!strcmp(method, "POST"))
            return create_session(db, e, who, b, status);
    }
    if (!strcmp(path, "reports") && get)
        return list_rows(db, "analyzer_reports", q, who, operate);
    int report = !strncmp(path, "reports/", 8), session = !strncmp(path, "sessions/", 9);
    if (!report && !session)
        return error(status, 404, "not_found", "接口不存在");
    const char *begin = path + (report ? 8 : 9), *slash = strchr(begin, '/');
    size_t len = slash ? (size_t)(slash - begin) : strlen(begin);
    char id[81];
    if (!len || len >= sizeof(id))
        return error(status, 400, "invalid_id", "资源 ID 非法");
    memcpy(id, begin, len);
    id[len] = 0;
    if (!id_ok(id))
        return error(status, 400, "invalid_id", "资源 ID 非法");
    const char *suffix = slash ? slash + 1 : "";
    struct json_object *s = load(db, report ? "analyzer_reports" : "analyzer_sessions", id),
                       *r = NULL;
    if (!s)
        return error(status, 404, "not_found", "会话或报告不存在");
    if (get) {
        if (!*suffix) {
            r = report ? public_report(s, who, operate) : public_session(s, 1, who, operate);
            json_object_object_del(r, "operator_id");
            boolean(r, "can_operate", operate && !strcmp(str(s, "operator_id"), who));
        } else if (session && !strcmp(suffix, "observations"))
            r = observations(s, q);
        else
            r = error(status, 404, "not_found", "接口不存在");
        json_object_put(s);
        return r ? r : error(status, 503, "memory_unavailable", "读取失败");
    }
    if (strcmp(str(s, "operator_id"), who)) {
        json_object_put(s);
        return error(status, 403, "resource_owner_required",
                     "此资源由另一操作者创建，不能修改或撤回");
    }
    int64_t revision = report ? num(s, "report_revision") : num(s, "revision");
    if (!child(b, "expected_revision") || num(b, "expected_revision") != revision) {
        json_object_put(s);
        return error(status, 409, "revision_conflict", "资源版本已变化，请回读后重试");
    }
    if (report && !*suffix) {
        sqlite3_stmt *st = NULL;
        if (!strcmp(method, "DELETE")) {
            if (sqlite3_prepare_v2(db, "DELETE FROM analyzer_reports WHERE id=?1", -1, &st, NULL) ==
                SQLITE_OK) {
                sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(st) == SQLITE_DONE) {
                    r = obj();
                    boolean(r, "deleted", 1);
                    boolean(r, "rules_changed", 0);
                }
            }
        } else if (!strcmp(method, "PATCH")) {
            const char *label = str(b, "label");
            if (strlen(label) > 512)
                r = error(status, 400, "label_too_long", "备注最多 512 字节");
            else {
                text(s, "label", label);
                number(s, "report_revision", revision + 1);
                if (sqlite3_prepare_v2(db, "UPDATE analyzer_reports SET document=?2 WHERE id=?1",
                                       -1, &st, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 2, json(s), -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(st) == SQLITE_DONE) {
                        r = public_report(s, who, operate);
                    }
                }
            }
        }
        sqlite3_finalize(st);
    } else if (session && !strcmp(method, "POST") &&
               (!strcmp(suffix, "stop") || !strcmp(suffix, "end"))) {
        if(e->provider){
            struct json_object *request=copy(b);char rid[96];
            snprintf(rid,sizeof(rid),"s-%s",str(b,"request_id"));text(request,"request_id",rid);
            struct json_object *reply=provider_request(e,"stop",s,request,status);
            if(*status>=400)r=reply;else json_object_put(reply);
            if(!r&&!strcmp(suffix,"end")){
                snprintf(rid,sizeof(rid),"r-%s",str(b,"request_id"));text(request,"request_id",rid);
                reply=withdraw(e,s,request,status);if(*status>=400)r=reply;else json_object_put(reply);
                if(!r&&child(s,"bisect"))text(child(s,"bisect"),"state","ended");
            }
            json_object_put(request);
        }
        if (!r&&active(s)) {
            capture(e, s);
            if (num(s, "backlog")) {
                boolean(s, "truncated", 1);
                text(s, "coverage_reason", "capture_end_backlog");
            }
            if (finalize(db, e, s, *str(s, "stop_reason") ? str(s, "stop_reason") : "user_stopped"))
                r = error(status, 503, "report_save_failed",
                          "报告保存失败；采集停止尚未提交，可重试");
        }
        if (!r) {
            if(!strcmp(suffix,"end")) {boolean(s,"ended",1);number(s,"revision",num(s,"revision")+1);}
            if(save_session(db,s)||report_conclusions(db,s,e))r=error(status,503,"storage_unavailable","会话结束状态未能保存，请重试");
        }
        if (!r) {
            r = public_session(s, 1, who, operate);
            boolean(r, "ended", !strcmp(suffix, "end"));
            boolean(r, "report_saved", !strcmp(str(s, "report_state"), "saved"));
        }
    } else if (session && (!strcmp(suffix,"trial") || !strcmp(suffix,"trial/feedback") ||
                         !strncmp(suffix,"bisect",6) || !strncmp(suffix,"conclusions/",12)))
        r = e->provider ? trial_change(db,e,s,method,suffix,b,status) :
            (!strcmp(suffix,"conclusions/preview") ? preview(s,b,status) :
             error(status,409,"exact_device_domain_provider_unavailable","设备执行点未连接"));
    else
        r = error(status, 405, "method_not_allowed", "不支持此操作");
    json_object_put(s);
    return r ? r : error(status, 503, "storage_unavailable", "存储操作失败");
}
struct json_object *ada_handle(const struct ada_environment *e, const char *who, int operate,
                               const char *method, const char *path, struct json_object *q,
                               struct json_object *b, int *status) {
    *status = 200;
    int write = strcmp(method, "GET") != 0;
    if (!who || !*who)
        return error(status, 403, "identity_required", "需要可识别的登录会话");
    if (write && !operate)
        return error(status, 403, "read_only", "只读账号不能创建会话或修改记录");
    const char *rid = str(b, "request_id");
    if (write && !id_ok(rid))
        return error(status, 400, "request_id_required", "写操作需要稳定的 request_id");
    if (write && strlen(json(b)) > 128 * 1024)
        return error(status, 413, "request_too_large", "请求超过 128 KiB 上限");
    sqlite3 *db = NULL;
    if (open_db(e, &db))
        return error(status, 503, "storage_unavailable", "分析记录存储不可用");
    if (write && sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return error(status, 409, "resource_busy", "采集或另一操作正在更新，请稍后重试");
    }
    char *signature = NULL;
    sqlite3_stmt *st = NULL;
    if (write) {
        if (asprintf(&signature, "%s %s %s", method, path, json(b)) < 0)
            signature = NULL;
        if (!signature) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            sqlite3_close(db);
            return error(status, 503, "memory_unavailable", "请求未执行");
        }
        if (sqlite3_prepare_v2(db,
                               "SELECT signature,response,status FROM analyzer_requests WHERE "
                               "owner=?1 AND request_id=?2",
                               -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, who, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, rid, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                struct json_object *r;
                if (strcmp((const char *)sqlite3_column_text(st, 0), signature))
                    r = error(status, 409, "request_id_conflict", "request_id 已用于不同请求");
                else {
                    r = json_tokener_parse((const char *)sqlite3_column_text(st, 1));
                    *status = sqlite3_column_int(st, 2);
                }
                sqlite3_finalize(st);
                sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
                sqlite3_close(db);
                free(signature);
                return r;
            }
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    struct json_object *r = dispatch(db, e, who, operate, method, path, q, b, status);
    int failed = *status >= 400;
    if (write && !failed) {
        int64_t bytes = (int64_t)(strlen(signature) + strlen(json(r)));
        if (reserve_bytes(db, "analyzer_requests",
                          "length(CAST(response AS BLOB))+length(CAST(signature AS BLOB))",
                          REQUEST_BYTES - bytes) ||
            sqlite3_prepare_v2(db, "INSERT INTO analyzer_requests VALUES(?1,?2,?3,?4,?5,?6)", -1,
                               &st, NULL) != SQLITE_OK)
            failed = 1;
        else {
            sqlite3_bind_text(st, 1, who, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, rid, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, signature, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, json(r), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 5, *status);
            sqlite3_bind_int64(st, 6, e->now);
            failed = sqlite3_step(st) != SQLITE_DONE;
        }
        sqlite3_finalize(st);
        if (!failed &&
            sqlite3_exec(db,
                         "DELETE FROM analyzer_requests WHERE rowid NOT IN (SELECT rowid FROM "
                         "analyzer_requests ORDER BY created DESC,rowid DESC LIMIT 256)",
                         NULL, NULL, NULL) != SQLITE_OK)
            failed = 1;
    }
    if (write) {
        int rc = sqlite3_exec(db, failed ? "ROLLBACK" : "COMMIT", NULL, NULL, NULL);
        if (rc != SQLITE_OK || (failed && *status < 400)) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            json_object_put(r);
            r = error(status, 503, "storage_unavailable",
                      "操作未能持久化，请使用同一 request_id 重试");
        }
    }
    free(signature);
    sqlite3_close(db);
    return r;
}
