// SPDX-License-Identifier: GPL-2.0-or-later
#include "logd_internal.h"

#define WORKER_STATUS_VERSION "1.0"

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define LOGD_SYSLOG_CERT_DIR "/etc/dreamingwrt/syslog"
#define LOGD_SYSLOG_CERT_MAX_BYTES 65536
#define LOGD_SYSLOG_DEFAULT_CATEGORIES "general,audit,security,wan,client,vpn"
#define LOGD_SYSLOG_DEFAULT_PROFILE_ID "default"
#define LOGD_SYSLOG_DEFAULT_PROFILE_NAME "Default Syslog"

static int logd_exec(const char *sql)
{
    char *err = NULL;
    int rc;

    if (!g_logd_db || !sql)
        return -1;
    rc = sqlite3_exec(g_logd_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-logd] sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(g_logd_db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int logd_kernel_structured_v2_migrate(void)
{
    sqlite3_stmt *st;
    const char *value = NULL;
    int done = 0;

    st = logd_prepare("SELECT value FROM log_meta WHERE key='structured_kernel_v2'");
    if (st) {
        if (sqlite3_step(st) == SQLITE_ROW)
            value = (const char *)sqlite3_column_text(st, 0);
        done = value && !strcmp(value, "done");
        sqlite3_finalize(st);
    }
    if (done) {
        (void)logd_exec("PRAGMA wal_checkpoint(TRUNCATE)");
        return 0;
    }
    if (logd_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (logd_exec(
        "CREATE TEMP TABLE logd_kernel_legacy_pairs("
        " keep_id TEXT PRIMARY KEY, drop_id TEXT NOT NULL UNIQUE) WITHOUT ROWID") != 0 ||
        logd_exec(
        "INSERT OR IGNORE INTO logd_kernel_legacy_pairs(keep_id,drop_id) "
        "SELECT s.id,k.id FROM log_events s JOIN log_events k "
        "ON json_extract(s.detail_json,'$.message')=json_extract(k.detail_json,'$.line') "
        "WHERE s.source='system_log' "
        "AND lower(json_extract(s.detail_json,'$.module'))='kernel' "
        "AND k.source='kernel_log' AND k.category='kernel' "
        "AND ABS(s.ts-k.ts)<=120") != 0 ||
        logd_exec(
        "UPDATE log_events SET "
        "category='kernel',event=CASE WHEN lower(json_extract(detail_json,'$.message')) LIKE '%callbacks suppressed%' "
        "THEN 'callbacks_suppressed' ELSE event END,source='kernel',"
        "severity=CASE lower(COALESCE(json_extract(detail_json,'$.facility'),'')) "
        "WHEN 'kern.emerg' THEN 'critical' WHEN 'kern.alert' THEN 'critical' WHEN 'kern.crit' THEN 'critical' "
        "WHEN 'kern.err' THEN 'error' WHEN 'kern.error' THEN 'error' "
        "WHEN 'kern.warn' THEN 'warning' WHEN 'kern.warning' THEN 'warning' "
        "WHEN 'kern.notice' THEN 'notice' ELSE severity END,"
        "title=COALESCE(NULLIF(json_extract(detail_json,'$.message'),''),title),count=1,"
        "detail_json=json_set(detail_json,"
        "'$.kernel',json('true'),'$.source_id','kernel','$.source_label','Kernel logs',"
        "'$.program','kernel','$.program_label','Kernel','$.package','',"
        "'$.raw',COALESCE(json_extract(detail_json,'$.line'),title),"
        "'$.facility','kern',"
        "'$.facility_level',CASE WHEN instr(COALESCE(json_extract(detail_json,'$.facility'),''),'.')>0 "
        "THEN substr(json_extract(detail_json,'$.facility'),instr(json_extract(detail_json,'$.facility'),'.')+1) ELSE '' END,"
        "'$.event_fingerprint','legacy:'||id,"
        "'$.collectors',CASE WHEN id IN (SELECT keep_id FROM logd_kernel_legacy_pairs) "
        "THEN json('[\"system_log\",\"kernel_log\"]') ELSE json('[\"system_log\"]') END) "
        "WHERE source='system_log' AND lower(json_extract(detail_json,'$.module'))='kernel'") != 0 ||
        logd_exec(
        "DELETE FROM log_read_events WHERE event_id IN (SELECT drop_id FROM logd_kernel_legacy_pairs)") != 0 ||
        logd_exec(
        "DELETE FROM log_event_ack WHERE event_id IN (SELECT drop_id FROM logd_kernel_legacy_pairs)") != 0 ||
        logd_exec(
        "DELETE FROM log_events WHERE id IN (SELECT drop_id FROM logd_kernel_legacy_pairs)") != 0 ||
        logd_exec(
        "UPDATE log_events SET source='kernel',"
        "event=CASE WHEN lower(COALESCE(json_extract(detail_json,'$.line'),title)) LIKE '%callbacks suppressed%' "
        "THEN 'callbacks_suppressed' ELSE event END,count=1,"
        "detail_json=json_set(detail_json,"
        "'$.kernel',json('true'),'$.source_id','kernel','$.source_label','Kernel logs',"
        "'$.program','kernel','$.program_label','Kernel','$.package','',"
        "'$.raw',COALESCE(json_extract(detail_json,'$.line'),title),"
        "'$.message',COALESCE(json_extract(detail_json,'$.message'),json_extract(detail_json,'$.line'),title),"
        "'$.event_fingerprint','legacy:'||id,'$.collectors',json('[\"kernel_log\"]')) "
        "WHERE source='kernel_log' AND category='kernel'") != 0 ||
        logd_exec(
        "INSERT INTO log_meta(key,value) VALUES('structured_kernel_v2','done') "
        "ON CONFLICT(key) DO UPDATE SET value='done'") != 0 ||
        logd_exec("COMMIT") != 0) {
        logd_exec("ROLLBACK");
        return -1;
    }
    if (logd_exec("PRAGMA wal_checkpoint(TRUNCATE)") != 0)
        fprintf(stderr, "[dreamingwrt-logd] kernel migration checkpoint deferred: %s\n",
                sqlite3_errmsg(g_logd_db));
    return 0;
}

sqlite3_stmt *logd_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_logd_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_logd_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-logd] sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_logd_db), sql);
        return NULL;
    }
    return st;
}

static int logd_config_exec(const char *sql)
{
    char *err = NULL;
    int rc;

    if (!g_config_db || !sql)
        return -1;
    rc = sqlite3_exec(g_config_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-logd] config sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(g_config_db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

sqlite3_stmt *logd_config_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_config_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_config_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-logd] config sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_config_db), sql);
        return NULL;
    }
    return st;
}

static int logd_config_column_exists(const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int found = 0;

    if (!table || !column)
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(g_config_db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);

        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int logd_config_add_column_if_missing(const char *table, const char *column,
                                             const char *definition)
{
    char sql[256];

    if (!table || !column || !definition)
        return -1;
    if (logd_config_column_exists(table, column))
        return 0;
    snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s", table, column, definition);
    return logd_config_exec(sql);
}

static int logd_column_exists(const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int found = 0;

    if (!table || !column)
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(g_logd_db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);

        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int logd_add_column_if_missing(const char *table, const char *column,
                                      const char *definition)
{
    char sql[256];

    if (!table || !column || !definition)
        return -1;
    if (logd_column_exists(table, column))
        return 0;
    snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s", table, column, definition);
    return logd_exec(sql);
}

static void logd_response_set_first_error(struct json_object *resp, const char *error)
{
    struct json_object *existing = NULL;

    if (!resp || !error || !error[0])
        return;
    if (json_object_object_get_ex(resp, "error", &existing) && existing)
        return;
    json_object_object_add(resp, "error", json_object_new_string(error));
}

struct json_object *logd_syslog_queue_status(struct json_object *body);

struct logd_syslog_tls_config {
    char ca_path[256];
    char client_cert_path[256];
    char client_key_path[256];
    char sni[256];
    int verify_peer;
    int verify_host;
};

struct logd_syslog_profile {
    char profile_id[64];
    char name[128];
    int enabled;
    char server[256];
    int port;
    char protocol[16];
    char facility[32];
    char min_level[32];
    char categories[512];
    struct logd_syslog_tls_config tls;
    int sort_order;
    int is_default;
    int updated_at;
};

static void logd_syslog_tls_config_init(struct logd_syslog_tls_config *cfg)
{
    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->verify_peer = 1;
    cfg->verify_host = 1;
}

static int logd_syslog_tls_path_allowed(const char *path)
{
    const char *certs = "/etc/dreamingwrt/certs/";
    const char *syslog = "/etc/dreamingwrt/syslog/";

    if (!path || !path[0])
        return 1;
    if (strlen(path) >= 256 || path[0] != '/')
        return 0;
    if (strstr(path, "/../") || strstr(path, "/..") || strstr(path, "../"))
        return 0;
    return !strncmp(path, certs, strlen(certs)) ||
           !strncmp(path, syslog, strlen(syslog));
}

static int logd_json_copy_str_if_present(struct json_object *obj, const char *key,
                                         char *out, size_t out_len)
{
    struct json_object *v = NULL;
    const char *s;

    if (!obj || !key || !out || out_len == 0 ||
        !json_object_object_get_ex(obj, key, &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return 0;
    s = json_object_get_string(v);
    snprintf(out, out_len, "%s", s ? s : "");
    return 1;
}

static void logd_syslog_tls_config_from_json(struct logd_syslog_tls_config *cfg,
                                             struct json_object *syslog)
{
    struct json_object *tls = NULL;

    if (!cfg || !syslog || !json_object_is_type(syslog, json_type_object))
        return;
    if (json_object_object_get_ex(syslog, "tls", &tls) && tls &&
        json_object_is_type(tls, json_type_object)) {
        logd_json_copy_str_if_present(tls, "ca_path", cfg->ca_path, sizeof(cfg->ca_path));
        logd_json_copy_str_if_present(tls, "ca_file", cfg->ca_path, sizeof(cfg->ca_path));
        logd_json_copy_str_if_present(tls, "client_cert_path", cfg->client_cert_path, sizeof(cfg->client_cert_path));
        logd_json_copy_str_if_present(tls, "client_key_path", cfg->client_key_path, sizeof(cfg->client_key_path));
        logd_json_copy_str_if_present(tls, "sni", cfg->sni, sizeof(cfg->sni));
        cfg->verify_peer = logd_json_bool(tls, "verify_peer", cfg->verify_peer);
        cfg->verify_host = logd_json_bool(tls, "verify_host", cfg->verify_host);
    }
    logd_json_copy_str_if_present(syslog, "tls_ca_path", cfg->ca_path, sizeof(cfg->ca_path));
    logd_json_copy_str_if_present(syslog, "tls_ca_file", cfg->ca_path, sizeof(cfg->ca_path));
    logd_json_copy_str_if_present(syslog, "tls_client_cert_path", cfg->client_cert_path, sizeof(cfg->client_cert_path));
    logd_json_copy_str_if_present(syslog, "tls_client_key_path", cfg->client_key_path, sizeof(cfg->client_key_path));
    logd_json_copy_str_if_present(syslog, "tls_sni", cfg->sni, sizeof(cfg->sni));
    cfg->verify_peer = logd_json_bool(syslog, "tls_verify_peer", cfg->verify_peer);
    cfg->verify_host = logd_json_bool(syslog, "tls_verify_host", cfg->verify_host);
}

static int logd_syslog_tls_config_valid(const struct logd_syslog_tls_config *cfg)
{
    if (!cfg)
        return 1;
    if (!logd_syslog_tls_path_allowed(cfg->ca_path) ||
        !logd_syslog_tls_path_allowed(cfg->client_cert_path) ||
        !logd_syslog_tls_path_allowed(cfg->client_key_path))
        return 0;
    if ((cfg->client_cert_path[0] && !cfg->client_key_path[0]) ||
        (!cfg->client_cert_path[0] && cfg->client_key_path[0]))
        return 0;
    if (!logd_text_ok(cfg->sni, sizeof(cfg->sni) - 1))
        return 0;
    return 1;
}

static int logd_syslog_categories_from_json(struct json_object *v, char *out, size_t out_len)
{
    int n;

    if (!out || out_len == 0)
        return -1;
    out[0] = 0;
    if (!v) {
        snprintf(out, out_len, "%s", LOGD_SYSLOG_DEFAULT_CATEGORIES);
        return 0;
    }
    if (json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        char buf[512];
        char *save = NULL;
        char *tok;

        snprintf(buf, sizeof(buf), "%s", s ? s : "");
        tok = strtok_r(buf, ",", &save);
        while (tok) {
            while (*tok == ' ' || *tok == '\t')
                tok++;
            if (*tok) {
                if (!logd_token_ok(tok, 32))
                    return -1;
                if (out[0])
                    strncat(out, ",", out_len - strlen(out) - 1);
                strncat(out, tok, out_len - strlen(out) - 1);
            }
            tok = strtok_r(NULL, ",", &save);
        }
        if (!out[0])
            snprintf(out, out_len, "%s", LOGD_SYSLOG_DEFAULT_CATEGORIES);
        return 0;
    }
    if (!json_object_is_type(v, json_type_array))
        return -1;
    n = json_object_array_length(v);
    for (int i = 0; i < n; i++) {
        const char *s = json_object_get_string(json_object_array_get_idx(v, i));

        if (!s || !s[0])
            continue;
        if (!logd_token_ok(s, 32))
            return -1;
        if (out[0])
            strncat(out, ",", out_len - strlen(out) - 1);
        strncat(out, s, out_len - strlen(out) - 1);
    }
    if (!out[0])
        snprintf(out, out_len, "%s", LOGD_SYSLOG_DEFAULT_CATEGORIES);
    return 0;
}

static struct json_object *logd_syslog_tls_config_json(const struct logd_syslog_tls_config *cfg)
{
    struct json_object *tls = json_object_new_object();
    int mtls;

    if (!cfg)
        return tls;
    mtls = cfg->client_cert_path[0] && cfg->client_key_path[0];
    json_object_object_add(tls, "ca_path", json_object_new_string(cfg->ca_path));
    json_object_object_add(tls, "client_cert_path", json_object_new_string(cfg->client_cert_path));
    json_object_object_add(tls, "client_key_path", json_object_new_string(cfg->client_key_path));
    json_object_object_add(tls, "verify_peer", json_object_new_boolean(cfg->verify_peer));
    json_object_object_add(tls, "verify_host", json_object_new_boolean(cfg->verify_host));
    json_object_object_add(tls, "sni", json_object_new_string(cfg->sni));
    json_object_object_add(tls, "custom_ca_configured", json_object_new_boolean(cfg->ca_path[0]));
    json_object_object_add(tls, "client_cert_configured", json_object_new_boolean(mtls));
    json_object_object_add(tls, "mtls_configured", json_object_new_boolean(mtls));
    json_object_object_add(tls, "allowed_path_prefix", json_object_new_string("/etc/dreamingwrt/certs/ or /etc/dreamingwrt/syslog/"));
    return tls;
}


struct logd_syslog_preset {
    const char *id;
    const char *name;
    const char *vendor;
    const char *product;
    const char *description;
    const char *server_hint;
    int port;
    const char *protocol;
    const char *facility;
    const char *min_level;
    const char *categories;
    const char *format;
    int tls_recommended;
    int mtls_supported;
    const char *default_sni_hint;
    const char *docs_hint;
};

static const struct logd_syslog_preset g_logd_syslog_presets[] = {
    {
        "generic_udp", "Generic Syslog UDP", "generic", "syslog",
        "RFC5424-style syslog over UDP. Fire-and-forget; receiver acknowledgement is not available.",
        "syslog.example.local", 514, "udp", "local7", "notice",
        LOGD_SYSLOG_DEFAULT_CATEGORIES, "rfc5424", 0, 0, "", "generic_udp_514"
    },
    {
        "generic_tcp", "Generic Syslog TCP", "generic", "syslog",
        "RFC5424-style syslog over TCP with delivery retry queue.",
        "syslog.example.local", 514, "tcp", "local7", "notice",
        LOGD_SYSLOG_DEFAULT_CATEGORIES, "rfc5424", 0, 0, "", "generic_tcp_514"
    },
    {
        "generic_tls", "Generic Syslog TLS", "generic", "syslog",
        "RFC5425-style TLS syslog on port 6514. Supports custom CA and optional client certificate.",
        "syslog.example.local", 6514, "tls", "local7", "notice",
        LOGD_SYSLOG_DEFAULT_CATEGORIES, "rfc5424", 1, 1, "syslog.example.local", "generic_tls_6514"
    },
    {
        "splunk_hec_syslog", "Splunk Connect for Syslog", "splunk", "sc4s",
        "Splunk commonly ingests network-device events through Splunk Connect for Syslog; use TLS when available.",
        "sc4s.example.local", 6514, "tls", "local7", "notice",
        "general,audit,security,wan,client,vpn", "rfc5424", 1, 1, "sc4s.example.local", "splunk_connect_for_syslog"
    },
    {
        "elastic_agent_syslog", "Elastic Agent / Logstash Syslog", "elastic", "elastic_agent",
        "Elastic Agent or Logstash syslog input. TLS is recommended for routed networks.",
        "elastic-agent.example.local", 6514, "tls", "local7", "notice",
        "general,audit,security,wan,client,vpn", "rfc5424", 1, 1, "elastic-agent.example.local", "elastic_syslog_input"
    },
    {
        "graylog_syslog_tls", "Graylog Syslog TLS", "graylog", "graylog",
        "Graylog syslog input with TLS. Configure the matching TCP/TLS input on the Graylog side.",
        "graylog.example.local", 6514, "tls", "local7", "notice",
        "general,audit,security,wan,client,vpn", "rfc5424", 1, 1, "graylog.example.local", "graylog_syslog_tls_input"
    },
    {
        "wazuh_syslog", "Wazuh / OSSEC Syslog", "wazuh", "wazuh",
        "Wazuh can ingest network device syslog through its syslog collector or an upstream rsyslog/Logstash hop.",
        "wazuh.example.local", 514, "tcp", "local7", "notice",
        "audit,security,wan,vpn", "rfc5424", 0, 0, "", "wazuh_remote_syslog"
    },
    {
        "sentinel_syslog_cef", "Microsoft Sentinel CEF Connector", "microsoft", "sentinel",
        "Microsoft Sentinel commonly receives network events through a CEF/syslog forwarder. DreamingWrt currently emits RFC5424 with structured data; CEF export is available separately.",
        "sentinel-forwarder.example.local", 514, "tcp", "local7", "warning",
        "audit,security,wan,vpn", "rfc5424_structured;cef_export_supported", 0, 0, "", "sentinel_cef_forwarder"
    },
    {
        "rsyslog_relay_tls", "rsyslog Relay TLS", "rsyslog", "rsyslog",
        "Local or LAN rsyslog relay using TLS. Useful before forwarding to a cloud SIEM.",
        "rsyslog.example.local", 6514, "tls", "local7", "notice",
        LOGD_SYSLOG_DEFAULT_CATEGORIES, "rfc5424", 1, 1, "rsyslog.example.local", "rsyslog_gtls"
    },
    {
        "syslog_ng_tls", "syslog-ng TLS", "syslog-ng", "syslog-ng",
        "syslog-ng TLS destination/source profile with RFC5424 payloads.",
        "syslog-ng.example.local", 6514, "tls", "local7", "notice",
        LOGD_SYSLOG_DEFAULT_CATEGORIES, "rfc5424", 1, 1, "syslog-ng.example.local", "syslog_ng_tls"
    },
};

static const struct logd_syslog_preset *logd_syslog_find_preset(const char *id)
{
    size_t i;

    if (!id || !id[0])
        return NULL;
    for (i = 0; i < sizeof(g_logd_syslog_presets) / sizeof(g_logd_syslog_presets[0]); i++) {
        if (!strcmp(g_logd_syslog_presets[i].id, id))
            return &g_logd_syslog_presets[i];
    }
    return NULL;
}

static struct json_object *logd_syslog_preset_json(const struct logd_syslog_preset *p)
{
    struct json_object *o = json_object_new_object();
    struct json_object *defaults = json_object_new_object();
    struct json_object *tls = json_object_new_object();
    struct json_object *warnings = json_object_new_array();
    struct json_object *cats;
    char cat_csv[512];
    char *save = NULL;
    char *tok;

    if (!o || !p)
        return o ? o : json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string(p->id));
    json_object_object_add(o, "name", json_object_new_string(p->name));
    json_object_object_add(o, "vendor", json_object_new_string(p->vendor));
    json_object_object_add(o, "product", json_object_new_string(p->product));
    json_object_object_add(o, "description", json_object_new_string(p->description));
    json_object_object_add(o, "docs_hint", json_object_new_string(p->docs_hint));
    json_object_object_add(o, "format", json_object_new_string(p->format));
    json_object_object_add(o, "server_hint", json_object_new_string(p->server_hint));
    json_object_object_add(o, "port", json_object_new_int(p->port));
    json_object_object_add(o, "protocol", json_object_new_string(p->protocol));
    json_object_object_add(o, "facility", json_object_new_string(p->facility));
    json_object_object_add(o, "min_level", json_object_new_string(p->min_level));
    json_object_object_add(o, "tls_recommended", json_object_new_boolean(p->tls_recommended));
    json_object_object_add(o, "mtls_supported", json_object_new_boolean(p->mtls_supported));

    json_object_object_add(tls, "verify_peer", json_object_new_boolean(1));
    json_object_object_add(tls, "verify_host", json_object_new_boolean(1));
    json_object_object_add(tls, "sni_hint", json_object_new_string(p->default_sni_hint));
    json_object_object_add(tls, "custom_ca_supported", json_object_new_boolean(1));
    json_object_object_add(tls, "client_cert_supported", json_object_new_boolean(p->mtls_supported));
    json_object_object_add(o, "tls", tls);

    cats = json_object_new_array();
    snprintf(cat_csv, sizeof(cat_csv), "%s", p->categories ? p->categories : "");
    tok = strtok_r(cat_csv, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok)
            json_object_array_add(cats, json_object_new_string(tok));
        tok = strtok_r(NULL, ",", &save);
    }
    json_object_object_add(o, "categories", cats);

    json_object_object_add(defaults, "server", json_object_new_string(p->server_hint));
    json_object_object_add(defaults, "port", json_object_new_int(p->port));
    json_object_object_add(defaults, "protocol", json_object_new_string(p->protocol));
    json_object_object_add(defaults, "facility", json_object_new_string(p->facility));
    json_object_object_add(defaults, "min_level", json_object_new_string(p->min_level));
    json_object_object_add(defaults, "categories", json_object_new_string(p->categories));
    json_object_object_add(defaults, "tls_verify_peer", json_object_new_boolean(1));
    json_object_object_add(defaults, "tls_verify_host", json_object_new_boolean(1));
    json_object_object_add(defaults, "tls_sni", json_object_new_string(p->default_sni_hint));
    json_object_object_add(defaults, "enabled", json_object_new_boolean(0));
    json_object_object_add(o, "defaults", defaults);

    if (strstr(p->format, "cef_export_supported"))
        json_object_array_add(warnings, json_object_new_string("live_syslog_payload_is_rfc5424_structured;cef_is_export_path_for_now"));
    if (!strcmp(p->protocol, "udp"))
        json_object_array_add(warnings, json_object_new_string("udp_has_no_receiver_acknowledgement"));
    json_object_object_add(o, "warnings", warnings);
    return o;
}

struct json_object *logd_syslog_presets_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *cap = logd_unifi_capabilities_json();
    const char *vendor = logd_json_str(body, "vendor", "");
    const char *preset_id = logd_json_str(body, "preset_id", logd_json_str(body, "id", ""));
    const char *apply_id = logd_json_str(body, "apply_preset_id", "");
    const char *server = logd_json_str(body, "server", "");
    int preview = logd_json_bool(body, "preview", 1);
    int enabled = logd_json_bool(body, "enabled", 1);
    size_t i;

    for (i = 0; i < sizeof(g_logd_syslog_presets) / sizeof(g_logd_syslog_presets[0]); i++) {
        const struct logd_syslog_preset *p = &g_logd_syslog_presets[i];
        if (vendor && vendor[0] && strcmp(vendor, p->vendor))
            continue;
        if (preset_id && preset_id[0] && strcmp(preset_id, p->id))
            continue;
        json_object_array_add(items, logd_syslog_preset_json(p));
    }

    if (apply_id && apply_id[0]) {
        const struct logd_syslog_preset *p = logd_syslog_find_preset(apply_id);
        struct json_object *profile = json_object_new_object();
        struct json_object *cats = json_object_new_array();
        char profile_id[64];
        char cat_csv[512];
        char *save = NULL;
        char *tok;

        if (!p) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("unknown_syslog_preset"));
            json_object_object_add(resp, "items", items);
            json_object_object_add(resp, "capabilities", cap);
            return resp;
        }
        snprintf(profile_id, sizeof(profile_id), "%s", logd_json_str(body, "profile_id", p->id));
        json_object_object_add(profile, "id", json_object_new_string(profile_id));
        json_object_object_add(profile, "profile_id", json_object_new_string(profile_id));
        json_object_object_add(profile, "name", json_object_new_string(logd_json_str(body, "name", p->name)));
        json_object_object_add(profile, "enabled", json_object_new_boolean(enabled));
        json_object_object_add(profile, "server", json_object_new_string(server && server[0] ? server : p->server_hint));
        json_object_object_add(profile, "port", json_object_new_int(logd_json_int(body, "port", p->port)));
        json_object_object_add(profile, "protocol", json_object_new_string(logd_json_str(body, "protocol", p->protocol)));
        json_object_object_add(profile, "facility", json_object_new_string(logd_json_str(body, "facility", p->facility)));
        json_object_object_add(profile, "min_level", json_object_new_string(logd_json_str(body, "min_level", p->min_level)));
        json_object_object_add(profile, "sort_order", json_object_new_int(logd_json_int(body, "sort_order", 100)));
        json_object_object_add(profile, "is_default", json_object_new_boolean(logd_json_bool(body, "is_default", !strcmp(profile_id, LOGD_SYSLOG_DEFAULT_PROFILE_ID))));
        snprintf(cat_csv, sizeof(cat_csv), "%s", logd_json_str(body, "categories", p->categories));
        tok = strtok_r(cat_csv, ",", &save);
        while (tok) {
            while (*tok == ' ' || *tok == '\t')
                tok++;
            if (*tok)
                json_object_array_add(cats, json_object_new_string(tok));
            tok = strtok_r(NULL, ",", &save);
        }
        json_object_object_add(profile, "categories", cats);
        json_object_object_add(profile, "preset_id", json_object_new_string(p->id));
        json_object_object_add(profile, "preset_vendor", json_object_new_string(p->vendor));
        json_object_object_add(profile, "preset_warning", json_object_new_string(server && server[0] ? "" : "server_is_hint_replace_before_enable"));
        json_object_object_add(resp, "profile_preview", profile);
        json_object_object_add(resp, "apply_preview", json_object_new_boolean(1));
        json_object_object_add(resp, "applied", json_object_new_boolean(0));
        json_object_object_add(resp, "preview", json_object_new_boolean(preview));
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "items", items);
    json_object_object_add(resp, "count", json_object_new_int(json_object_array_length(items)));
    json_object_object_add(resp, "source", json_object_new_string("dreamingwrt-logd.syslog_presets"));
    json_object_object_add(resp, "capabilities", cap);
    return resp;
}

static int logd_syslog_profile_id_ok(const char *id)
{
    const unsigned char *p;
    size_t len;

    if (!id || !id[0])
        return 0;
    len = strlen(id);
    if (len > 63 || id[0] == '.' || strstr(id, "..") || strchr(id, '/'))
        return 0;
    for (p = (const unsigned char *)id; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static void logd_syslog_profile_init(struct logd_syslog_profile *p,
                                     const char *id, const char *name)
{
    if (!p)
        return;
    memset(p, 0, sizeof(*p));
    snprintf(p->profile_id, sizeof(p->profile_id), "%s",
             id && id[0] ? id : LOGD_SYSLOG_DEFAULT_PROFILE_ID);
    snprintf(p->name, sizeof(p->name), "%s",
             name && name[0] ? name : LOGD_SYSLOG_DEFAULT_PROFILE_NAME);
    p->port = 514;
    snprintf(p->protocol, sizeof(p->protocol), "%s", "udp");
    snprintf(p->facility, sizeof(p->facility), "%s", "local7");
    snprintf(p->min_level, sizeof(p->min_level), "%s", "notice");
    snprintf(p->categories, sizeof(p->categories), "%s", LOGD_SYSLOG_DEFAULT_CATEGORIES);
    logd_syslog_tls_config_init(&p->tls);
}

static int logd_syslog_profile_valid(const struct logd_syslog_profile *p)
{
    if (!p)
        return 0;
    if (!logd_syslog_profile_id_ok(p->profile_id) ||
        !logd_text_ok(p->name, sizeof(p->name) - 1) ||
        (p->server[0] && !logd_text_ok(p->server, sizeof(p->server) - 1)) ||
        p->port < 1 || p->port > 65535 ||
        (strcmp(p->protocol, "udp") && strcmp(p->protocol, "tcp") && strcmp(p->protocol, "tls")) ||
        !logd_token_ok(p->facility, sizeof(p->facility) - 1) ||
        !logd_token_ok(p->min_level, sizeof(p->min_level) - 1) ||
        !logd_syslog_tls_config_valid(&p->tls))
        return 0;
    return 1;
}

static int logd_syslog_profile_from_json(struct logd_syslog_profile *p,
                                         struct json_object *obj,
                                         int allow_missing_id)
{
    struct json_object *v = NULL;
    const char *s;

    if (!p || !obj || !json_object_is_type(obj, json_type_object))
        return -1;
    if (json_object_object_get_ex(obj, "id", &v) ||
        json_object_object_get_ex(obj, "profile_id", &v)) {
        s = json_object_get_string(v);
        snprintf(p->profile_id, sizeof(p->profile_id), "%s", s ? s : "");
    } else if (!allow_missing_id) {
        return -1;
    }
    if (json_object_object_get_ex(obj, "name", &v) ||
        json_object_object_get_ex(obj, "profile_name", &v) ||
        json_object_object_get_ex(obj, "display_name", &v)) {
        s = json_object_get_string(v);
        snprintf(p->name, sizeof(p->name), "%s", s && s[0] ? s : p->profile_id);
    }
    p->enabled = logd_json_bool(obj, "enabled", p->enabled);
    p->port = logd_json_int(obj, "port", p->port);
    if (json_object_object_get_ex(obj, "server", &v) && v && json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        snprintf(p->server, sizeof(p->server), "%s", s ? s : "");
    }
    if (json_object_object_get_ex(obj, "host", &v) && v && json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        snprintf(p->server, sizeof(p->server), "%s", s ? s : "");
    }
    if (json_object_object_get_ex(obj, "protocol", &v) && v && json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        snprintf(p->protocol, sizeof(p->protocol), "%s", s ? s : "udp");
    }
    if (json_object_object_get_ex(obj, "facility", &v) && v && json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        snprintf(p->facility, sizeof(p->facility), "%s", s ? s : "local7");
    }
    if (json_object_object_get_ex(obj, "min_level", &v) && v && json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        snprintf(p->min_level, sizeof(p->min_level), "%s", s ? s : "notice");
    }
    if (json_object_object_get_ex(obj, "severity", &v) && v && json_object_is_type(v, json_type_string)) {
        s = json_object_get_string(v);
        snprintf(p->min_level, sizeof(p->min_level), "%s", s ? s : "notice");
    }
    if (json_object_object_get_ex(obj, "categories", &v) && v) {
        if (logd_syslog_categories_from_json(v, p->categories, sizeof(p->categories)) != 0)
            return -1;
    }
    p->sort_order = logd_json_int(obj, "sort_order", p->sort_order);
    logd_syslog_tls_config_from_json(&p->tls, obj);
    if (!p->name[0])
        snprintf(p->name, sizeof(p->name), "%s", p->profile_id);
    return logd_syslog_profile_valid(p) ? 0 : -1;
}

static void logd_syslog_profile_categories_json(const char *csv, struct json_object *profile)
{
    struct json_object *categories = json_object_new_array();
    char buf[512];
    char *save = NULL;
    char *tok;

    snprintf(buf, sizeof(buf), "%s", csv && csv[0] ? csv : LOGD_SYSLOG_DEFAULT_CATEGORIES);
    tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok)
            json_object_array_add(categories, json_object_new_string(tok));
        tok = strtok_r(NULL, ",", &save);
    }
    json_object_object_add(profile, "categories", categories);
}

static struct json_object *logd_syslog_profile_json(const struct logd_syslog_profile *p)
{
    struct json_object *o = json_object_new_object();

    if (!p)
        return o;
    json_object_object_add(o, "id", json_object_new_string(p->profile_id));
    json_object_object_add(o, "profile_id", json_object_new_string(p->profile_id));
    json_object_object_add(o, "name", json_object_new_string(p->name));
    json_object_object_add(o, "enabled", json_object_new_boolean(p->enabled));
    json_object_object_add(o, "server", json_object_new_string(p->server));
    json_object_object_add(o, "port", json_object_new_int(p->port));
    json_object_object_add(o, "protocol", json_object_new_string(p->protocol));
    json_object_object_add(o, "facility", json_object_new_string(p->facility));
    json_object_object_add(o, "min_level", json_object_new_string(p->min_level));
    json_object_object_add(o, "sort_order", json_object_new_int(p->sort_order));
    json_object_object_add(o, "default", json_object_new_boolean(p->is_default));
    json_object_object_add(o, "is_default", json_object_new_boolean(p->is_default));
    json_object_object_add(o, "updated_at", json_object_new_int64(p->updated_at));
    logd_syslog_profile_categories_json(p->categories, o);
    json_object_object_add(o, "tls", logd_syslog_tls_config_json(&p->tls));
    return o;
}

static int logd_syslog_cert_name_ok(const char *name)
{
    const unsigned char *p;
    size_t len;

    if (!name || !name[0])
        return 0;
    len = strlen(name);
    if (len > 96 || name[0] == '.' || strstr(name, "..") || strchr(name, '/'))
        return 0;
    for (p = (const unsigned char *)name; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static const char *logd_syslog_cert_kind(const char *kind)
{
    if (!kind || !kind[0])
        return "ca";
    if (!strcmp(kind, "ca") || !strcmp(kind, "client_cert") ||
        !strcmp(kind, "client_key") || !strcmp(kind, "cert") ||
        !strcmp(kind, "key"))
        return kind;
    return NULL;
}

static const char *logd_syslog_cert_ext_for_kind(const char *kind)
{
    if (kind && (!strcmp(kind, "client_key") || !strcmp(kind, "key")))
        return "key";
    return "pem";
}

static int logd_syslog_pem_looks_ok(const char *pem, const char *kind, size_t *out_len)
{
    size_t len;

    if (!pem)
        return 0;
    len = strlen(pem);
    if (out_len)
        *out_len = len;
    if (len < 32 || len > LOGD_SYSLOG_CERT_MAX_BYTES)
        return 0;
    if (!strstr(pem, "-----BEGIN ") || !strstr(pem, "-----END "))
        return 0;
    if (kind && (!strcmp(kind, "client_key") || !strcmp(kind, "key"))) {
        if (!strstr(pem, "PRIVATE KEY-----"))
            return 0;
    } else if (!strstr(pem, "CERTIFICATE-----")) {
        return 0;
    }
    return 1;
}

static int logd_syslog_cert_build_name(const char *kind, const char *name,
                                       char *safe, size_t safe_len,
                                       char *path, size_t path_len)
{
    const char *ext = logd_syslog_cert_ext_for_kind(kind);

    if (!safe || !path || safe_len == 0 || path_len == 0)
        return -1;
    if (name && name[0]) {
        if (!logd_syslog_cert_name_ok(name))
            return -1;
        snprintf(safe, safe_len, "%s", name);
    } else {
        snprintf(safe, safe_len, "%s-%lld.%s", kind ? kind : "ca",
                 (long long)logd_now_s(), ext);
    }
    if (!strchr(safe, '.')) {
        size_t n = strlen(safe);
        if (n + 1 + strlen(ext) >= safe_len)
            return -1;
        strncat(safe, ".", safe_len - strlen(safe) - 1);
        strncat(safe, ext, safe_len - strlen(safe) - 1);
    }
    if (!logd_syslog_cert_name_ok(safe))
        return -1;
    snprintf(path, path_len, "%s/%s", LOGD_SYSLOG_CERT_DIR, safe);
    return 0;
}

static int logd_syslog_cert_file_kind(const char *name, char *kind, size_t kind_len)
{
    if (!kind || kind_len == 0)
        return -1;
    snprintf(kind, kind_len, "%s", "ca");
    if (!name)
        return 0;
    if (strstr(name, "key")) {
        snprintf(kind, kind_len, "%s", "client_key");
    } else if (strstr(name, "client") || strstr(name, "cert")) {
        snprintf(kind, kind_len, "%s", "client_cert");
    }
    return 0;
}

int logd_db_init(void)
{
    if (g_logd_db)
        return 0;
    mkdir("/etc/dreamingwrt", 0755);
    if (sqlite3_open(LOGD_DB_PATH, &g_logd_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-logd] open %s failed: %s\n",
                LOGD_DB_PATH, g_logd_db ? sqlite3_errmsg(g_logd_db) : "no db handle");
        if (g_logd_db) {
            sqlite3_close(g_logd_db);
            g_logd_db = NULL;
        }
        return -1;
    }
    sqlite3_busy_timeout(g_logd_db, 3000);
    if (logd_exec("PRAGMA journal_mode=WAL") != 0)
        goto fail;
    if (logd_exec("PRAGMA foreign_keys=ON") != 0)
        goto fail;
    if (logd_exec(
        "CREATE TABLE IF NOT EXISTS log_meta ("
        " key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')") != 0)
        goto fail;
    if (logd_exec(
        "CREATE TABLE IF NOT EXISTS log_events ("
        " id TEXT PRIMARY KEY,"
        " seq INTEGER NOT NULL DEFAULT 0,"
        " ts INTEGER NOT NULL,"
        " severity TEXT NOT NULL DEFAULT 'info',"
        " category TEXT NOT NULL DEFAULT 'system',"
        " event TEXT NOT NULL,"
        " source TEXT NOT NULL DEFAULT '',"
        " iface TEXT NOT NULL DEFAULT '',"
        " wan_id TEXT NOT NULL DEFAULT '',"
        " ip TEXT NOT NULL DEFAULT '',"
        " mac TEXT NOT NULL DEFAULT '',"
        " username TEXT NOT NULL DEFAULT '',"
        " actor TEXT NOT NULL DEFAULT '',"
        " title TEXT NOT NULL DEFAULT '',"
        " detail_json TEXT NOT NULL DEFAULT '{}',"
        " dedupe_key TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'active',"
        " first_seen INTEGER NOT NULL,"
        " last_seen INTEGER NOT NULL,"
        " count INTEGER NOT NULL DEFAULT 1,"
        " created_at INTEGER NOT NULL)") != 0)
        goto fail;
    if (logd_add_column_if_missing("log_events", "seq", "INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (logd_exec("UPDATE log_events SET seq=rowid WHERE seq=0") != 0)
        goto fail;
    if (logd_exec("CREATE INDEX IF NOT EXISTS idx_log_events_ts ON log_events(ts DESC)") != 0 ||
        logd_exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_log_events_seq ON log_events(seq)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_events_category_ts ON log_events(category, ts DESC)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_events_severity_ts ON log_events(severity, ts DESC)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_events_event_ts ON log_events(event, ts DESC)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_events_dedupe ON log_events(dedupe_key, category, event, state)") != 0 ||
        logd_exec("INSERT OR IGNORE INTO log_meta(key,value) VALUES('schema_version','1')") != 0)
        goto fail;
    if (logd_exec(
        "INSERT OR REPLACE INTO log_meta(key,value) "
        "SELECT 'event_seq_next', CAST(COALESCE(MAX(seq),0)+1 AS TEXT) FROM log_events") != 0)
        goto fail;
    if (logd_exec(
        "CREATE TABLE IF NOT EXISTS log_read_cursors ("
        " actor TEXT PRIMARY KEY,"
        " cursor_rowid INTEGER NOT NULL DEFAULT 0,"
        " cursor_seq INTEGER NOT NULL DEFAULT 0,"
        " cursor_ts INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_add_column_if_missing("log_read_cursors", "cursor_seq", "INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (logd_exec(
        "CREATE TABLE IF NOT EXISTS log_read_events ("
        " actor TEXT NOT NULL,"
        " event_id TEXT NOT NULL,"
        " rowid INTEGER NOT NULL DEFAULT 0,"
        " seq INTEGER NOT NULL DEFAULT 0,"
        " read_at INTEGER NOT NULL,"
        " PRIMARY KEY(actor,event_id))") != 0)
        goto fail;
    if (logd_add_column_if_missing("log_read_events", "seq", "INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (logd_exec(
        "CREATE TABLE IF NOT EXISTS log_event_ack ("
        " actor TEXT NOT NULL,"
        " event_id TEXT NOT NULL,"
        " rowid INTEGER NOT NULL DEFAULT 0,"
        " seq INTEGER NOT NULL DEFAULT 0,"
        " acked_at INTEGER NOT NULL,"
        " note TEXT NOT NULL DEFAULT '',"
        " PRIMARY KEY(actor,event_id))") != 0)
        goto fail;
    if (logd_add_column_if_missing("log_event_ack", "seq", "INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (logd_exec("CREATE INDEX IF NOT EXISTS idx_log_read_events_actor_rowid ON log_read_events(actor,rowid)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_read_events_actor_seq ON log_read_events(actor,seq)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_event_ack_actor_rowid ON log_event_ack(actor,rowid)") != 0 ||
        logd_exec("CREATE INDEX IF NOT EXISTS idx_log_event_ack_actor_seq ON log_event_ack(actor,seq)") != 0)
        goto fail;
    if (logd_kernel_structured_v2_migrate() != 0)
        fprintf(stderr, "[dreamingwrt-logd] structured kernel migration deferred: %s\n",
                sqlite3_errmsg(g_logd_db));
    return 0;

fail:
    if (g_logd_db) {
        sqlite3_close(g_logd_db);
        g_logd_db = NULL;
    }
    return -1;
}

int logd_config_db_init(void)
{
    if (g_config_db)
        return 0;
    mkdir("/etc/dreamingwrt", 0755);
    if (sqlite3_open(LOGD_CONFIG_DB_PATH, &g_config_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-logd] open %s failed: %s\n",
                LOGD_CONFIG_DB_PATH, g_config_db ? sqlite3_errmsg(g_config_db) : "no db handle");
        if (g_config_db) {
            sqlite3_close(g_config_db);
            g_config_db = NULL;
        }
        return -1;
    }
    sqlite3_busy_timeout(g_config_db, 3000);
    if (logd_config_exec("PRAGMA journal_mode=WAL") != 0)
        goto fail;
    if (logd_config_exec("PRAGMA foreign_keys=ON") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_settings ("
        " id INTEGER PRIMARY KEY CHECK (id=1),"
        " retention_days INTEGER NOT NULL DEFAULT 30,"
        " kernel_retention_days INTEGER NOT NULL DEFAULT 7,"
        " max_size_mb INTEGER NOT NULL DEFAULT 128,"
        " max_events INTEGER NOT NULL DEFAULT 50000,"
        " auto_cleanup INTEGER NOT NULL DEFAULT 1,"
        " archive_compress INTEGER NOT NULL DEFAULT 1,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_config_add_column_if_missing("logd_settings", "kernel_retention_days", "INTEGER NOT NULL DEFAULT 7") != 0 ||
        logd_config_add_column_if_missing("logd_settings", "max_size_mb", "INTEGER NOT NULL DEFAULT 128") != 0 ||
        logd_config_add_column_if_missing("logd_settings", "auto_cleanup", "INTEGER NOT NULL DEFAULT 1") != 0 ||
        logd_config_add_column_if_missing("logd_settings", "archive_compress", "INTEGER NOT NULL DEFAULT 1") != 0 ||
        /* Independent log levels for the device / management / remote access /
         * system groups. 'auto' keeps the existing behavior, so upgrading an
         * existing database does not silently start dropping events.
         */
        logd_config_add_column_if_missing("logd_settings", "log_level_device", "TEXT NOT NULL DEFAULT 'auto'") != 0 ||
        logd_config_add_column_if_missing("logd_settings", "log_level_management", "TEXT NOT NULL DEFAULT 'auto'") != 0 ||
        logd_config_add_column_if_missing("logd_settings", "log_level_remote_access", "TEXT NOT NULL DEFAULT 'auto'") != 0 ||
        logd_config_add_column_if_missing("logd_settings", "log_level_system", "TEXT NOT NULL DEFAULT 'auto'") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_syslog_config ("
        " id INTEGER PRIMARY KEY CHECK (id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " server TEXT NOT NULL DEFAULT '',"
        " port INTEGER NOT NULL DEFAULT 514,"
        " protocol TEXT NOT NULL DEFAULT 'udp',"
        " facility TEXT NOT NULL DEFAULT 'local7',"
        " min_level TEXT NOT NULL DEFAULT 'notice',"
        " categories TEXT NOT NULL DEFAULT 'general,audit,security,wan,client,vpn',"
        " tls_ca_path TEXT NOT NULL DEFAULT '',"
        " tls_client_cert_path TEXT NOT NULL DEFAULT '',"
        " tls_client_key_path TEXT NOT NULL DEFAULT '',"
        " tls_verify_peer INTEGER NOT NULL DEFAULT 1,"
        " tls_verify_host INTEGER NOT NULL DEFAULT 1,"
        " tls_sni TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_config_add_column_if_missing("logd_syslog_config", "tls_ca_path", "TEXT NOT NULL DEFAULT ''") != 0 ||
        logd_config_add_column_if_missing("logd_syslog_config", "tls_client_cert_path", "TEXT NOT NULL DEFAULT ''") != 0 ||
        logd_config_add_column_if_missing("logd_syslog_config", "tls_client_key_path", "TEXT NOT NULL DEFAULT ''") != 0 ||
        logd_config_add_column_if_missing("logd_syslog_config", "tls_verify_peer", "INTEGER NOT NULL DEFAULT 1") != 0 ||
        logd_config_add_column_if_missing("logd_syslog_config", "tls_verify_host", "INTEGER NOT NULL DEFAULT 1") != 0 ||
        logd_config_add_column_if_missing("logd_syslog_config", "tls_sni", "TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_syslog_profiles ("
        " profile_id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " server TEXT NOT NULL DEFAULT '',"
        " port INTEGER NOT NULL DEFAULT 514,"
        " protocol TEXT NOT NULL DEFAULT 'udp',"
        " facility TEXT NOT NULL DEFAULT 'local7',"
        " min_level TEXT NOT NULL DEFAULT 'notice',"
        " categories TEXT NOT NULL DEFAULT 'general,audit,security,wan,client,vpn',"
        " tls_ca_path TEXT NOT NULL DEFAULT '',"
        " tls_client_cert_path TEXT NOT NULL DEFAULT '',"
        " tls_client_key_path TEXT NOT NULL DEFAULT '',"
        " tls_verify_peer INTEGER NOT NULL DEFAULT 1,"
        " tls_verify_host INTEGER NOT NULL DEFAULT 1,"
        " tls_sni TEXT NOT NULL DEFAULT '',"
        " sort_order INTEGER NOT NULL DEFAULT 100,"
        " is_default INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_syslog_state ("
        " id INTEGER PRIMARY KEY CHECK (id=1),"
        " last_test_at INTEGER NOT NULL DEFAULT 0,"
        " last_success_at INTEGER NOT NULL DEFAULT 0,"
        " last_error_at INTEGER NOT NULL DEFAULT 0,"
        " last_ok INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " last_message TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_syslog_queue ("
        " id TEXT PRIMARY KEY,"
        " event_id TEXT NOT NULL DEFAULT '',"
        " ts INTEGER NOT NULL,"
        " protocol TEXT NOT NULL DEFAULT 'udp',"
        " server TEXT NOT NULL DEFAULT '',"
        " port INTEGER NOT NULL DEFAULT 514,"
        " profile_id TEXT NOT NULL DEFAULT 'default',"
        " profile_name TEXT NOT NULL DEFAULT 'Default Syslog',"
        " facility TEXT NOT NULL DEFAULT 'local7',"
        " severity TEXT NOT NULL DEFAULT 'info',"
        " category TEXT NOT NULL DEFAULT '',"
        " event TEXT NOT NULL DEFAULT '',"
        " payload TEXT NOT NULL DEFAULT '',"
        " status TEXT NOT NULL DEFAULT 'pending',"
        " attempts INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " next_retry_at INTEGER NOT NULL DEFAULT 0,"
        " sent_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_config_add_column_if_missing("logd_syslog_queue", "profile_id", "TEXT NOT NULL DEFAULT 'default'") != 0 ||
        logd_config_add_column_if_missing("logd_syslog_queue", "profile_name", "TEXT NOT NULL DEFAULT 'Default Syslog'") != 0)
        goto fail;
    if (logd_config_exec("CREATE INDEX IF NOT EXISTS idx_logd_syslog_queue_status_retry ON logd_syslog_queue(status,next_retry_at,created_at)") != 0 ||
        logd_config_exec("CREATE INDEX IF NOT EXISTS idx_logd_syslog_queue_profile_status ON logd_syslog_queue(profile_id,status,created_at)") != 0 ||
        logd_config_exec("CREATE INDEX IF NOT EXISTS idx_logd_syslog_queue_event_id ON logd_syslog_queue(event_id)") != 0)
        goto fail;
    if (logd_config_exec("INSERT OR IGNORE INTO logd_settings(id,retention_days,kernel_retention_days,max_size_mb,max_events,auto_cleanup,archive_compress,updated_at) VALUES(1,30,7,128,50000,1,1,0)") != 0)
        goto fail;
    if (logd_config_exec("INSERT OR IGNORE INTO logd_syslog_config(id) VALUES(1)") != 0)
        goto fail;
    if (logd_config_exec("INSERT OR IGNORE INTO logd_syslog_state(id) VALUES(1)") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_collector_settings ("
        " name TEXT PRIMARY KEY,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " interval_s INTEGER NOT NULL DEFAULT 30,"
        " cooldown_s INTEGER NOT NULL DEFAULT 60,"
        " options_json TEXT NOT NULL DEFAULT '{}',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (logd_config_exec(
        "CREATE TABLE IF NOT EXISTS logd_collector_state ("
        " name TEXT NOT NULL,"
        " key TEXT NOT NULL,"
        " value TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(name,key))") != 0)
        goto fail;
    if (logd_config_exec("INSERT OR IGNORE INTO logd_collector_settings(name,enabled,interval_s,cooldown_s,options_json,updated_at) VALUES('system_log',1,15,60,'{}',0)") != 0 ||
        logd_config_exec("INSERT OR IGNORE INTO logd_collector_settings(name,enabled,interval_s,cooldown_s,options_json,updated_at) VALUES('kernel_log',1,15,60,'{}',0)") != 0 ||
        logd_config_exec("INSERT OR IGNORE INTO logd_collector_settings(name,enabled,interval_s,cooldown_s,options_json,updated_at) VALUES('resource',1,30,300,'{\"cpu_warn\":85,\"cpu_critical\":95,\"mem_warn\":85,\"mem_critical\":95,\"disk_warn\":90,\"disk_critical\":97,\"inode_warn\":90,\"inode_critical\":97,\"temp_warn\":80,\"temp_critical\":90}',0)") != 0 ||
        logd_config_exec("INSERT OR IGNORE INTO logd_collector_settings(name,enabled,interval_s,cooldown_s,options_json,updated_at) VALUES('port',1,5,30,'{}',0)") != 0 ||
        logd_config_exec("INSERT OR IGNORE INTO logd_collector_settings(name,enabled,interval_s,cooldown_s,options_json,updated_at) VALUES('dhcp_lease',1,15,0,'{}',0)") != 0)
        goto fail;
    return 0;

fail:
    if (g_config_db) {
        sqlite3_close(g_config_db);
        g_config_db = NULL;
    }
    return -1;
}

void logd_db_close(void)
{
    if (g_logd_db) {
        sqlite3_close(g_logd_db);
        g_logd_db = NULL;
    }
    if (g_config_db) {
        sqlite3_close(g_config_db);
        g_config_db = NULL;
    }
}

int logd_prune_if_needed(void)
{
    sqlite3_stmt *st;
    int retention_days = 30;
    int max_events = 50000;
    int64_t cutoff;
    int rc;

    st = logd_config_prepare("SELECT retention_days,max_events,auto_cleanup FROM logd_settings WHERE id=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            retention_days = sqlite3_column_int(st, 0);
            max_events = sqlite3_column_int(st, 1);
            if (!sqlite3_column_int(st, 2))
                retention_days = 365;
        } else if (rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
    } else {
        return -1;
    }
    if (retention_days < 1) retention_days = 30;
    if (max_events < 1000) max_events = 1000;
    cutoff = logd_now_s() - (int64_t)retention_days * 86400;
    st = logd_prepare("DELETE FROM log_events WHERE ts<?");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, cutoff);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    st = logd_prepare(
        "DELETE FROM log_events WHERE id IN ("
        " SELECT id FROM log_events ORDER BY ts DESC LIMIT -1 OFFSET ?)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, max_events);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    return 0;
}

int logd_collector_state_prune(void)
{
    sqlite3_stmt *st;
    int64_t cutoff = logd_now_s() - LOGD_COOLDOWN_STATE_RETENTION_SEC;
    int rc;

    st = logd_config_prepare(
        "DELETE FROM logd_collector_state "
        "WHERE key LIKE 'cooldown:%' AND updated_at<?1");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, cutoff);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = logd_config_prepare(
        "DELETE FROM logd_collector_state "
        "WHERE key LIKE 'cooldown:%' AND rowid IN ("
        " SELECT rowid FROM logd_collector_state "
        " WHERE key LIKE 'cooldown:%' "
        " ORDER BY updated_at DESC LIMIT -1 OFFSET ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, LOGD_COOLDOWN_STATE_MAX_ROWS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    logd_config_exec("PRAGMA wal_checkpoint(PASSIVE)");
    return 0;
}

int logd_collector_state_get(const char *name, const char *key,
	                             char *out, size_t out_len, const char *def)
{
    sqlite3_stmt *st;
    const char *v = NULL;
    int found = 0;

    if (!out || out_len == 0)
        return -1;
    snprintf(out, out_len, "%s", def ? def : "");
    if (!name || !key)
        return -1;
    st = logd_config_prepare("SELECT value FROM logd_collector_state WHERE name=?1 AND key=?2");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        v = (const char *)sqlite3_column_text(st, 0);
        snprintf(out, out_len, "%s", v ? v : "");
        found = 1;
    }
    sqlite3_finalize(st);
    return found ? 0 : 1;
}

int logd_collector_state_set(const char *name, const char *key, const char *value)
{
    sqlite3_stmt *st;
    int ok = -1;

    if (!name || !key || !value)
        return -1;
    st = logd_config_prepare(
        "INSERT OR REPLACE INTO logd_collector_state(name,key,value,updated_at) VALUES(?1,?2,?3,?4)");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, logd_now_s());
    if (sqlite3_step(st) == SQLITE_DONE)
        ok = 0;
    sqlite3_finalize(st);
    return ok;
}

int logd_collector_state_delete(const char *name, const char *key)
{
    sqlite3_stmt *st;
    int ok = -1;

    if (!name || !key)
        return -1;
    st = logd_config_prepare("DELETE FROM logd_collector_state WHERE name=?1 AND key=?2");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        ok = 0;
    sqlite3_finalize(st);
    return ok;
}

struct json_object *logd_status_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    struct json_object *events = json_object_new_object();
    struct json_object *syslog_queue = json_object_new_object();
    char last_error[LOGD_MAX_TEXT] = "";
    int schema_version = 0;
    int64_t updated_at = 0;
    int ok = 1;
    int degraded;
    int rc;
    struct jmx_storage_guard_stats storage_guard;

    memset(&storage_guard, 0, sizeof(storage_guard));
    jmx_storage_guard_get_stats(&storage_guard);
    (void)jmx_storage_guard_check("/", &storage_guard.state);

    st = logd_prepare("SELECT COUNT(*),MIN(ts),MAX(ts) FROM log_events");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(resp, "total", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(resp, "oldest_ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(resp, "newest_ts", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(events, "total", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(events, "oldest_ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(events, "newest_ts", json_object_new_int64(sqlite3_column_int64(st, 2)));
            updated_at = sqlite3_column_int64(st, 2);
        } else {
            ok = 0;
            logd_response_set_first_error(resp, "status_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "status_query_failed");
    }
    st = logd_prepare("SELECT CAST(value AS INTEGER) FROM log_meta WHERE key='schema_version'");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW)
            schema_version = sqlite3_column_int(st, 0);
        else {
            ok = 0;
            logd_response_set_first_error(resp, "schema_version_unavailable");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "schema_version_unavailable");
    }
    st = logd_config_prepare(
        "SELECT last_error,updated_at FROM logd_syslog_state WHERE id=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            snprintf(last_error, sizeof(last_error), "%s", logd_sqlite_text(st, 0, ""));
            if (sqlite3_column_int64(st, 1) > updated_at)
                updated_at = sqlite3_column_int64(st, 1);
        } else if (rc != SQLITE_DONE) {
            ok = 0;
            logd_response_set_first_error(resp, "syslog_state_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "syslog_state_query_failed");
    }
    st = logd_config_prepare(
        "SELECT SUM(status='pending'),SUM(status='retry'),SUM(status='failed') "
        "FROM logd_syslog_queue");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(syslog_queue, "pending", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(syslog_queue, "retry", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(syslog_queue, "failed", json_object_new_int(sqlite3_column_int(st, 2)));
        } else {
            ok = 0;
            logd_response_set_first_error(resp, "syslog_queue_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "syslog_queue_query_failed");
    }
    if (!ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "status_query_failed");
    degraded = !ok || last_error[0];
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "service", json_object_new_string("dreamingwrt-logd"));
    json_object_object_add(resp, "version", json_object_new_string(WORKER_STATUS_VERSION));
    json_object_object_add(resp, "schema_version", json_object_new_int(schema_version));
    json_object_object_add(resp, "schema_source",
                           json_object_new_string("log.db:log_meta.schema_version"));
    json_object_object_add(resp, "migration_state", json_object_new_string(
        schema_version == LOGD_SCHEMA_VERSION ? "current" :
        (schema_version > 0 ? "version_mismatch" : "unknown")));
    json_object_object_add(resp, "state", json_object_new_string(degraded ? "degraded" : "running"));
    json_object_object_add(resp, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(resp, "last_error", json_object_new_string(last_error));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(resp, "db_path", json_object_new_string(LOGD_DB_PATH));
    json_object_object_add(resp, "storage_pressure",
                           json_object_new_string(jmx_storage_pressure_name(storage_guard.state.pressure)));
    json_object_object_add(resp, "storage_reason", json_object_new_string(storage_guard.state.reason));
    json_object_object_add(resp, "storage_total_bytes",
                           json_object_new_int64((int64_t)storage_guard.state.total_bytes));
    json_object_object_add(resp, "storage_available_bytes",
                           json_object_new_int64((int64_t)storage_guard.state.available_bytes));
    json_object_object_add(resp, "storage_used_pct",
                           json_object_new_int((int)storage_guard.state.used_pct));
    json_object_object_add(resp, "storage_checked_at",
                           json_object_new_int64(storage_guard.state.checked_at));
    json_object_object_add(resp, "storage_suppressed_writes",
                           json_object_new_int64((int64_t)g_logd_storage_suppressed));
    json_object_object_add(resp, "storage_last_suppressed_at",
                           json_object_new_int64(g_logd_storage_last_suppressed_at));
    json_object_object_add(dependencies, "event_db", json_object_new_boolean(g_logd_db != NULL));
    json_object_object_add(dependencies, "config_db", json_object_new_boolean(g_config_db != NULL));
    json_object_object_add(resp, "dependencies", dependencies);
    json_object_object_add(datasets, "log_events", events);
    json_object_object_add(datasets, "syslog_queue", syslog_queue);
    json_object_object_add(resp, "datasets", datasets);
    json_object_object_add(resp, "ts", json_object_new_int64(logd_now_s()));
    return resp;
}

/* Configured level for one group.
 *
 * The ingest path calls this for every event, so the four values are cached for
 * a short window. The cache is invalidated on write in logd_settings_update(),
 * so a settings change takes effect immediately rather than after the TTL.
 */
static struct {
    char device[16];
    char management[16];
    char remote_access[16];
    char system[16];
    int64_t loaded_at;
    int valid;
} g_logd_level_cache;

void logd_log_level_cache_invalidate(void)
{
    g_logd_level_cache.valid = 0;
}

int logd_log_level_for_group(const char *group, char *out, size_t out_len)
{
    int64_t now = logd_now_s();

    if (!out || !out_len)
        return -1;
    if (!g_logd_level_cache.valid ||
        now - g_logd_level_cache.loaded_at > 5 || now < g_logd_level_cache.loaded_at) {
        sqlite3_stmt *st = logd_config_prepare(
            "SELECT log_level_device,log_level_management,log_level_remote_access,"
            "log_level_system FROM logd_settings WHERE id=1");

        if (!st)
            return -1;
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(g_logd_level_cache.device, sizeof(g_logd_level_cache.device), "%s",
                 logd_log_level(logd_sqlite_text(st, 0, "auto")));
        snprintf(g_logd_level_cache.management, sizeof(g_logd_level_cache.management), "%s",
                 logd_log_level(logd_sqlite_text(st, 1, "auto")));
        snprintf(g_logd_level_cache.remote_access, sizeof(g_logd_level_cache.remote_access), "%s",
                 logd_log_level(logd_sqlite_text(st, 2, "auto")));
        snprintf(g_logd_level_cache.system, sizeof(g_logd_level_cache.system), "%s",
                 logd_log_level(logd_sqlite_text(st, 3, "auto")));
        sqlite3_finalize(st);
        g_logd_level_cache.loaded_at = now;
        g_logd_level_cache.valid = 1;
    }
    if (!strcmp(group, "device"))
        snprintf(out, out_len, "%s", g_logd_level_cache.device);
    else if (!strcmp(group, "management"))
        snprintf(out, out_len, "%s", g_logd_level_cache.management);
    else if (!strcmp(group, "remote_access"))
        snprintf(out, out_len, "%s", g_logd_level_cache.remote_access);
    else
        snprintf(out, out_len, "%s", g_logd_level_cache.system);
    return 0;
}

struct json_object *logd_settings_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *syslog = json_object_new_object();
    struct json_object *syslog_status = json_object_new_object();
    struct json_object *profiles = json_object_new_array();
    int ok = 1;
    int rc;

    json_object_object_add(resp, "db_path", json_object_new_string(LOGD_DB_PATH));
    json_object_object_add(resp, "config_db_path", json_object_new_string(LOGD_CONFIG_DB_PATH));
    st = logd_config_prepare("SELECT retention_days,kernel_retention_days,max_size_mb,max_events,auto_cleanup,archive_compress,updated_at,log_level_device,log_level_management,log_level_remote_access,log_level_system FROM logd_settings WHERE id=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(resp, "retention_days", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(resp, "kernel_retention_days", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(resp, "max_size_mb", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(resp, "max_events", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(resp, "auto_cleanup", json_object_new_boolean(sqlite3_column_int(st, 4)));
            json_object_object_add(resp, "archive_compress", json_object_new_boolean(sqlite3_column_int(st, 5)));
            json_object_object_add(resp, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
            {
                struct json_object *levels = json_object_new_object();
                static const char *const group_keys[4] = {
                    "device", "management", "remote_access", "system"
                };
                int col;

                for (col = 0; col < 4; col++) {
                    const char *level = logd_log_level(logd_sqlite_text(st, 7 + col, "auto"));
                    struct json_object *entry = json_object_new_object();

                    json_object_object_add(entry, "level", json_object_new_string(level));
                    json_object_object_add(entry, "min_severity_rank",
                                           json_object_new_int(logd_log_level_min_rank(level)));
                    json_object_object_add(entry, "keeps_debug",
                                           json_object_new_boolean(!strcmp(level, "debug")));
                    json_object_object_add(levels, group_keys[col], entry);
                }
                json_object_object_add(resp, "log_levels", levels);
            }
        } else {
            ok = 0;
            logd_response_set_first_error(resp, rc == SQLITE_DONE ? "settings_missing" : "settings_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "settings_query_failed");
    }
    st = logd_config_prepare("SELECT enabled,server,port,protocol,facility,min_level,categories,updated_at,tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni FROM logd_syslog_config WHERE id=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            const char *cats = logd_sqlite_text(st, 6, "general,audit,security,wan,client,vpn");
            struct logd_syslog_tls_config tls_cfg;
            struct logd_syslog_profile default_profile;
            struct json_object *categories = json_object_new_array();
            char buf[512];
            char *save = NULL;
            char *tok;

            logd_syslog_profile_init(&default_profile,
                                     LOGD_SYSLOG_DEFAULT_PROFILE_ID,
                                     LOGD_SYSLOG_DEFAULT_PROFILE_NAME);
            logd_syslog_tls_config_init(&tls_cfg);
            snprintf(tls_cfg.ca_path, sizeof(tls_cfg.ca_path), "%s", logd_sqlite_text(st, 8, ""));
            snprintf(tls_cfg.client_cert_path, sizeof(tls_cfg.client_cert_path), "%s", logd_sqlite_text(st, 9, ""));
            snprintf(tls_cfg.client_key_path, sizeof(tls_cfg.client_key_path), "%s", logd_sqlite_text(st, 10, ""));
            tls_cfg.verify_peer = sqlite3_column_int(st, 11) ? 1 : 0;
            tls_cfg.verify_host = sqlite3_column_int(st, 12) ? 1 : 0;
            snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", logd_sqlite_text(st, 13, ""));
            json_object_object_add(syslog, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
            json_object_object_add(syslog, "server", json_object_new_string(logd_sqlite_text(st, 1, "")));
            json_object_object_add(syslog, "port", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(syslog, "protocol", json_object_new_string(logd_sqlite_text(st, 3, "udp")));
            json_object_object_add(syslog, "facility", json_object_new_string(logd_sqlite_text(st, 4, "local7")));
            json_object_object_add(syslog, "min_level", json_object_new_string(logd_sqlite_text(st, 5, "notice")));
            json_object_object_add(syslog, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_object_add(syslog, "tls", logd_syslog_tls_config_json(&tls_cfg));
            json_object_object_add(syslog, "tls_ca_path", json_object_new_string(tls_cfg.ca_path));
            json_object_object_add(syslog, "tls_client_cert_path", json_object_new_string(tls_cfg.client_cert_path));
            json_object_object_add(syslog, "tls_client_key_path", json_object_new_string(tls_cfg.client_key_path));
            json_object_object_add(syslog, "tls_verify_peer", json_object_new_boolean(tls_cfg.verify_peer));
            json_object_object_add(syslog, "tls_verify_host", json_object_new_boolean(tls_cfg.verify_host));
            json_object_object_add(syslog, "tls_sni", json_object_new_string(tls_cfg.sni));
            snprintf(buf, sizeof(buf), "%s", cats ? cats : "");
            tok = strtok_r(buf, ",", &save);
            while (tok) {
                while (*tok == ' ' || *tok == '\t')
                    tok++;
                if (*tok)
                    json_object_array_add(categories, json_object_new_string(tok));
                tok = strtok_r(NULL, ",", &save);
            }
            json_object_object_add(syslog, "categories", categories);
            default_profile.enabled = sqlite3_column_int(st, 0);
            snprintf(default_profile.server, sizeof(default_profile.server), "%s", logd_sqlite_text(st, 1, ""));
            default_profile.port = sqlite3_column_int(st, 2);
            snprintf(default_profile.protocol, sizeof(default_profile.protocol), "%s", logd_sqlite_text(st, 3, "udp"));
            snprintf(default_profile.facility, sizeof(default_profile.facility), "%s", logd_sqlite_text(st, 4, "local7"));
            snprintf(default_profile.min_level, sizeof(default_profile.min_level), "%s", logd_sqlite_text(st, 5, "notice"));
            snprintf(default_profile.categories, sizeof(default_profile.categories), "%s", cats ? cats : LOGD_SYSLOG_DEFAULT_CATEGORIES);
            default_profile.tls = tls_cfg;
            default_profile.sort_order = 0;
            default_profile.is_default = 1;
            default_profile.updated_at = (int)sqlite3_column_int64(st, 7);
            json_object_array_add(profiles, logd_syslog_profile_json(&default_profile));
        } else {
            ok = 0;
            logd_response_set_first_error(resp, rc == SQLITE_DONE ? "syslog_settings_missing" : "syslog_settings_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "syslog_settings_query_failed");
    }
    st = logd_config_prepare(
        "SELECT profile_id,name,enabled,server,port,protocol,facility,min_level,categories,"
        "tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni,"
        "sort_order,is_default,updated_at "
        "FROM logd_syslog_profiles ORDER BY sort_order,profile_id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct logd_syslog_profile p;

            logd_syslog_profile_init(&p, logd_sqlite_text(st, 0, ""), logd_sqlite_text(st, 1, ""));
            p.enabled = sqlite3_column_int(st, 2);
            snprintf(p.server, sizeof(p.server), "%s", logd_sqlite_text(st, 3, ""));
            p.port = sqlite3_column_int(st, 4);
            snprintf(p.protocol, sizeof(p.protocol), "%s", logd_sqlite_text(st, 5, "udp"));
            snprintf(p.facility, sizeof(p.facility), "%s", logd_sqlite_text(st, 6, "local7"));
            snprintf(p.min_level, sizeof(p.min_level), "%s", logd_sqlite_text(st, 7, "notice"));
            snprintf(p.categories, sizeof(p.categories), "%s", logd_sqlite_text(st, 8, LOGD_SYSLOG_DEFAULT_CATEGORIES));
            snprintf(p.tls.ca_path, sizeof(p.tls.ca_path), "%s", logd_sqlite_text(st, 9, ""));
            snprintf(p.tls.client_cert_path, sizeof(p.tls.client_cert_path), "%s", logd_sqlite_text(st, 10, ""));
            snprintf(p.tls.client_key_path, sizeof(p.tls.client_key_path), "%s", logd_sqlite_text(st, 11, ""));
            p.tls.verify_peer = sqlite3_column_int(st, 12) ? 1 : 0;
            p.tls.verify_host = sqlite3_column_int(st, 13) ? 1 : 0;
            snprintf(p.tls.sni, sizeof(p.tls.sni), "%s", logd_sqlite_text(st, 14, ""));
            p.sort_order = sqlite3_column_int(st, 15);
            p.is_default = sqlite3_column_int(st, 16) ? 1 : 0;
            p.updated_at = (int)sqlite3_column_int64(st, 17);
            if (strcmp(p.profile_id, LOGD_SYSLOG_DEFAULT_PROFILE_ID))
                json_object_array_add(profiles, logd_syslog_profile_json(&p));
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        logd_response_set_first_error(resp, "syslog_profiles_query_failed");
    }
    st = logd_config_prepare("SELECT last_test_at,last_success_at,last_error_at,last_ok,last_error,last_message,updated_at FROM logd_syslog_state WHERE id=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(syslog_status, "last_test_at", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(syslog_status, "last_success_at", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(syslog_status, "last_error_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(syslog_status, "last_ok", json_object_new_boolean(sqlite3_column_int(st, 3)));
            json_object_object_add(syslog_status, "last_error", json_object_new_string(logd_sqlite_text(st, 4, "")));
            json_object_object_add(syslog_status, "last_message", json_object_new_string(logd_sqlite_text(st, 5, "")));
            json_object_object_add(syslog_status, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
        } else {
            json_object_object_add(syslog_status, "last_test_at", json_object_new_int64(0));
            json_object_object_add(syslog_status, "last_ok", json_object_new_boolean(0));
            json_object_object_add(syslog_status, "last_error", json_object_new_string("not_tested"));
        }
        sqlite3_finalize(st);
    } else {
        json_object_object_add(syslog_status, "last_test_at", json_object_new_int64(0));
        json_object_object_add(syslog_status, "last_ok", json_object_new_boolean(0));
        json_object_object_add(syslog_status, "last_error", json_object_new_string("state_query_failed"));
    }
    json_object_object_add(syslog, "status", syslog_status);
    json_object_object_add(syslog, "queue", logd_syslog_queue_status(NULL));
    json_object_object_add(syslog, "profiles", profiles);
    json_object_object_add(syslog, "profiles_count", json_object_new_int(json_object_array_length(profiles)));
    json_object_object_add(resp, "syslog", syslog);
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    return resp;
}

static int logd_settings_categories_csv(struct json_object *arr, char *out, size_t out_len)
{
    return logd_syslog_categories_from_json(arr, out, out_len);
}

static int logd_syslog_profile_upsert(const struct logd_syslog_profile *p)
{
    sqlite3_stmt *st;
    int rc;

    if (!logd_syslog_profile_valid(p))
        return -1;
    st = logd_config_prepare(
        "INSERT INTO logd_syslog_profiles("
        "profile_id,name,enabled,server,port,protocol,facility,min_level,categories,"
        "tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni,"
        "sort_order,is_default,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) "
        "ON CONFLICT(profile_id) DO UPDATE SET "
        "name=excluded.name,enabled=excluded.enabled,server=excluded.server,port=excluded.port,"
        "protocol=excluded.protocol,facility=excluded.facility,min_level=excluded.min_level,"
        "categories=excluded.categories,tls_ca_path=excluded.tls_ca_path,"
        "tls_client_cert_path=excluded.tls_client_cert_path,tls_client_key_path=excluded.tls_client_key_path,"
        "tls_verify_peer=excluded.tls_verify_peer,tls_verify_host=excluded.tls_verify_host,"
        "tls_sni=excluded.tls_sni,sort_order=excluded.sort_order,is_default=excluded.is_default,"
        "updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, p->profile_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, p->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, p->enabled);
    sqlite3_bind_text(st, 4, p->server, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, p->port);
    sqlite3_bind_text(st, 6, p->protocol, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, p->facility, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, p->min_level, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, p->categories, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, p->tls.ca_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, p->tls.client_cert_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, p->tls.client_key_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, p->tls.verify_peer);
    sqlite3_bind_int(st, 14, p->tls.verify_host);
    sqlite3_bind_text(st, 15, p->tls.sni, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 16, p->sort_order);
    sqlite3_bind_int(st, 17, p->is_default);
    sqlite3_bind_int64(st, 18, logd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

struct json_object *logd_settings_update(struct json_object *body)
{
    int retention_days = 30;
    int kernel_retention_days = 7;
    int max_size_mb = 128;
    int max_events = 50000;
    int auto_cleanup = 1;
    int archive_compress = 1;
    int syslog_enabled = 0;
    int syslog_port = 514;
    char server_buf[256] = "";
    char level_device[16] = "auto";
    char level_management[16] = "auto";
    char level_remote_access[16] = "auto";
    char level_system[16] = "auto";
    int levels_changed = 0;
    char protocol_buf[16] = "udp";
    char facility_buf[32] = "local7";
    char min_level_buf[32] = "notice";
    char categories[512];
    struct logd_syslog_tls_config tls_cfg;
    struct json_object *syslog = NULL;
    struct json_object *cat_arr = NULL;
    struct json_object *profiles_arr = NULL;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int rc;
    int replace_profiles = 0;

    logd_syslog_tls_config_init(&tls_cfg);
    st = logd_config_prepare("SELECT retention_days,kernel_retention_days,max_size_mb,max_events,auto_cleanup,archive_compress,log_level_device,log_level_management,log_level_remote_access,log_level_system FROM logd_settings WHERE id=1");
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_query_failed"));
        return resp;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        retention_days = sqlite3_column_int(st, 0);
        kernel_retention_days = sqlite3_column_int(st, 1);
        max_size_mb = sqlite3_column_int(st, 2);
        max_events = sqlite3_column_int(st, 3);
        auto_cleanup = sqlite3_column_int(st, 4);
        archive_compress = sqlite3_column_int(st, 5);
        snprintf(level_device, sizeof(level_device), "%s",
                 logd_log_level(logd_sqlite_text(st, 6, "auto")));
        snprintf(level_management, sizeof(level_management), "%s",
                 logd_log_level(logd_sqlite_text(st, 7, "auto")));
        snprintf(level_remote_access, sizeof(level_remote_access), "%s",
                 logd_log_level(logd_sqlite_text(st, 8, "auto")));
        snprintf(level_system, sizeof(level_system), "%s",
                 logd_log_level(logd_sqlite_text(st, 9, "auto")));
    } else {
        sqlite3_finalize(st);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string(rc == SQLITE_DONE ? "settings_missing" : "settings_query_failed"));
        return resp;
    }
    sqlite3_finalize(st);

    retention_days = logd_json_int(body, "retention_days", retention_days);
    kernel_retention_days = logd_json_int(body, "kernel_retention_days", kernel_retention_days);
    max_size_mb = logd_json_int(body, "max_size_mb", max_size_mb);
    max_events = logd_json_int(body, "max_events", max_events);
    auto_cleanup = logd_json_bool(body, "auto_cleanup", auto_cleanup);
    archive_compress = logd_json_bool(body, "archive_compress", archive_compress);

    if (retention_days < 1 || retention_days > 365 ||
        kernel_retention_days < 1 || kernel_retention_days > 90 ||
        max_size_mb < 32 || max_size_mb > 2048 ||
        max_events < 1000 || max_events > 1000000) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_logd_settings"));
        return resp;
    }
    /* Independent per-group log levels.
     *
     * Unknown group keys and unknown level values are rejected instead of being
     * silently dropped, so the caller never believes a level was applied when it
     * was not.
     */
    {
        struct json_object *levels = NULL;

        if (json_object_object_get_ex(body, "log_levels", &levels) && levels) {
            struct { const char *key; char *slot; size_t size; } groups[4] = {
                { "device", level_device, sizeof(level_device) },
                { "management", level_management, sizeof(level_management) },
                { "remote_access", level_remote_access, sizeof(level_remote_access) },
                { "system", level_system, sizeof(level_system) },
            };

            if (!json_object_is_type(levels, json_type_object)) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error",
                                       json_object_new_string("invalid_log_levels"));
                return resp;
            }
            json_object_object_foreach(levels, key, value) {
                const char *requested;
                int index = -1;
                int i;

                for (i = 0; i < 4; i++)
                    if (!strcmp(key, groups[i].key)) {
                        index = i;
                        break;
                    }
                if (index < 0) {
                    json_object_object_add(resp, "ok", json_object_new_boolean(0));
                    json_object_object_add(resp, "error",
                                           json_object_new_string("unknown_log_level_group"));
                    json_object_object_add(resp, "reason", json_object_new_string(key));
                    return resp;
                }
                if (!value || !json_object_is_type(value, json_type_string)) {
                    json_object_object_add(resp, "ok", json_object_new_boolean(0));
                    json_object_object_add(resp, "error",
                                           json_object_new_string("invalid_log_level"));
                    json_object_object_add(resp, "reason", json_object_new_string(key));
                    return resp;
                }
                requested = json_object_get_string(value);
                if (!requested || strcmp(requested, logd_log_level(requested))) {
                    json_object_object_add(resp, "ok", json_object_new_boolean(0));
                    json_object_object_add(resp, "error",
                                           json_object_new_string("invalid_log_level"));
                    json_object_object_add(resp, "reason",
                                           json_object_new_string(requested ? requested : ""));
                    return resp;
                }
                snprintf(groups[index].slot, groups[index].size, "%s", requested);
                levels_changed = 1;
            }
        }
    }
    if (json_object_object_get_ex(body, "syslog", &syslog) && syslog &&
        json_object_is_type(syslog, json_type_object)) {
        st = logd_config_prepare("SELECT enabled,server,port,protocol,facility,min_level,categories,tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni FROM logd_syslog_config WHERE id=1");
        if (!st) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("syslog_settings_query_failed"));
            return resp;
        }
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            syslog_enabled = sqlite3_column_int(st, 0);
            snprintf(server_buf, sizeof(server_buf), "%s", logd_sqlite_text(st, 1, ""));
            syslog_port = sqlite3_column_int(st, 2);
            snprintf(protocol_buf, sizeof(protocol_buf), "%s", logd_sqlite_text(st, 3, "udp"));
            snprintf(facility_buf, sizeof(facility_buf), "%s", logd_sqlite_text(st, 4, "local7"));
            snprintf(min_level_buf, sizeof(min_level_buf), "%s", logd_sqlite_text(st, 5, "notice"));
            snprintf(categories, sizeof(categories), "%s", logd_sqlite_text(st, 6, "general,audit,security,wan,client,vpn"));
            snprintf(tls_cfg.ca_path, sizeof(tls_cfg.ca_path), "%s", logd_sqlite_text(st, 7, ""));
            snprintf(tls_cfg.client_cert_path, sizeof(tls_cfg.client_cert_path), "%s", logd_sqlite_text(st, 8, ""));
            snprintf(tls_cfg.client_key_path, sizeof(tls_cfg.client_key_path), "%s", logd_sqlite_text(st, 9, ""));
            tls_cfg.verify_peer = sqlite3_column_int(st, 10) ? 1 : 0;
            tls_cfg.verify_host = sqlite3_column_int(st, 11) ? 1 : 0;
            snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", logd_sqlite_text(st, 12, ""));
        } else {
            snprintf(categories, sizeof(categories), "%s", "general,audit,security,wan,client,vpn");
        }
        sqlite3_finalize(st);
        syslog_enabled = logd_json_bool(syslog, "enabled", syslog_enabled);
        syslog_port = logd_json_int(syslog, "port", syslog_port);
        {
            struct json_object *sv = NULL;
            const char *s;

            if (json_object_object_get_ex(syslog, "server", &sv) && sv &&
                json_object_is_type(sv, json_type_string)) {
                s = json_object_get_string(sv);
                snprintf(server_buf, sizeof(server_buf), "%s", s ? s : "");
            }
            if (json_object_object_get_ex(syslog, "protocol", &sv) && sv &&
                json_object_is_type(sv, json_type_string)) {
                s = json_object_get_string(sv);
                snprintf(protocol_buf, sizeof(protocol_buf), "%s", s ? s : "udp");
            }
            if (json_object_object_get_ex(syslog, "facility", &sv) && sv &&
                json_object_is_type(sv, json_type_string)) {
                s = json_object_get_string(sv);
                snprintf(facility_buf, sizeof(facility_buf), "%s", s ? s : "local7");
            }
            if (json_object_object_get_ex(syslog, "min_level", &sv) && sv &&
                json_object_is_type(sv, json_type_string)) {
                s = json_object_get_string(sv);
                snprintf(min_level_buf, sizeof(min_level_buf), "%s", s ? s : "notice");
            }
        }
        logd_syslog_tls_config_from_json(&tls_cfg, syslog);
        if (json_object_object_get_ex(syslog, "categories", &cat_arr) && cat_arr) {
            if (logd_settings_categories_csv(cat_arr, categories, sizeof(categories)) != 0) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("invalid_syslog_categories"));
                return resp;
            }
        }
        if ((server_buf[0] && !logd_text_ok(server_buf, 255)) ||
            syslog_port < 1 || syslog_port > 65535 ||
            (strcmp(protocol_buf, "udp") && strcmp(protocol_buf, "tcp") && strcmp(protocol_buf, "tls")) ||
            !logd_token_ok(facility_buf, 32) || !logd_token_ok(min_level_buf, 32) ||
            !logd_syslog_tls_config_valid(&tls_cfg)) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_syslog_settings"));
            return resp;
        }
        if (json_object_object_get_ex(syslog, "profiles", &profiles_arr) && profiles_arr) {
            int n;
            char seen[LOGD_SYSLOG_MAX_PROFILES + 1][64];

            if (!json_object_is_type(profiles_arr, json_type_array)) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("invalid_syslog_profiles"));
                return resp;
            }
            n = json_object_array_length(profiles_arr);
            if (n > LOGD_SYSLOG_MAX_PROFILES) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("too_many_syslog_profiles"));
                return resp;
            }
            memset(seen, 0, sizeof(seen));
            for (int i = 0; i < n; i++) {
                struct json_object *po = json_object_array_get_idx(profiles_arr, i);
                struct logd_syslog_profile p;

                logd_syslog_profile_init(&p, "", "");
                p.sort_order = i + 1;
                if (logd_syslog_profile_from_json(&p, po, 0) != 0) {
                    json_object_object_add(resp, "ok", json_object_new_boolean(0));
                    json_object_object_add(resp, "error", json_object_new_string("invalid_syslog_profile"));
                    return resp;
                }
                for (int j = 0; j < i; j++) {
                    if (seen[j][0] && !strcmp(seen[j], p.profile_id)) {
                        json_object_object_add(resp, "ok", json_object_new_boolean(0));
                        json_object_object_add(resp, "error", json_object_new_string("duplicate_syslog_profile"));
                        return resp;
                    }
                }
                snprintf(seen[i], sizeof(seen[i]), "%s", p.profile_id);
            }
            replace_profiles = 1;
        }
    }
    st = logd_config_prepare("UPDATE logd_settings SET retention_days=?1,kernel_retention_days=?2,max_size_mb=?3,max_events=?4,auto_cleanup=?5,archive_compress=?6,updated_at=?7,log_level_device=?8,log_level_management=?9,log_level_remote_access=?10,log_level_system=?11 WHERE id=1");
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_prepare_failed"));
        return resp;
    }
    sqlite3_bind_int(st, 1, retention_days);
    sqlite3_bind_int(st, 2, kernel_retention_days);
    sqlite3_bind_int(st, 3, max_size_mb);
    sqlite3_bind_int(st, 4, max_events);
    sqlite3_bind_int(st, 5, auto_cleanup);
    sqlite3_bind_int(st, 6, archive_compress);
    sqlite3_bind_int64(st, 7, logd_now_s());
    sqlite3_bind_text(st, 8, level_device, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, level_management, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, level_remote_access, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, level_system, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_update_failed"));
        return resp;
    }
    sqlite3_finalize(st);
    if (levels_changed)
        logd_log_level_cache_invalidate();
    if (syslog) {
        st = logd_config_prepare("UPDATE logd_syslog_config SET enabled=?1,server=?2,port=?3,protocol=?4,facility=?5,min_level=?6,categories=?7,tls_ca_path=?8,tls_client_cert_path=?9,tls_client_key_path=?10,tls_verify_peer=?11,tls_verify_host=?12,tls_sni=?13,updated_at=?14 WHERE id=1");
        if (!st) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("syslog_settings_prepare_failed"));
            return resp;
        }
        sqlite3_bind_int(st, 1, syslog_enabled);
        sqlite3_bind_text(st, 2, server_buf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, syslog_port);
        sqlite3_bind_text(st, 4, protocol_buf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, facility_buf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, min_level_buf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, categories, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, tls_cfg.ca_path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, tls_cfg.client_cert_path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, tls_cfg.client_key_path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 11, tls_cfg.verify_peer);
        sqlite3_bind_int(st, 12, tls_cfg.verify_host);
        sqlite3_bind_text(st, 13, tls_cfg.sni, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 14, logd_now_s());
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("syslog_settings_update_failed"));
            return resp;
        }
        sqlite3_finalize(st);
        if (replace_profiles) {
            st = logd_config_prepare("DELETE FROM logd_syslog_profiles");
            if (!st) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("syslog_profiles_prepare_failed"));
                return resp;
            }
            if (sqlite3_step(st) != SQLITE_DONE) {
                sqlite3_finalize(st);
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("syslog_profiles_clear_failed"));
                return resp;
            }
            sqlite3_finalize(st);
            for (size_t i = 0; i < json_object_array_length(profiles_arr); i++) {
                struct json_object *po = json_object_array_get_idx(profiles_arr, i);
                struct logd_syslog_profile p;

                logd_syslog_profile_init(&p, "", "");
                p.sort_order = i + 1;
                if (logd_syslog_profile_from_json(&p, po, 0) != 0) {
                    json_object_object_add(resp, "ok", json_object_new_boolean(0));
                    json_object_object_add(resp, "error", json_object_new_string("invalid_syslog_profile"));
                    return resp;
                }
                if (!strcmp(p.profile_id, LOGD_SYSLOG_DEFAULT_PROFILE_ID)) {
                    syslog_enabled = p.enabled;
                    snprintf(server_buf, sizeof(server_buf), "%s", p.server);
                    syslog_port = p.port;
                    snprintf(protocol_buf, sizeof(protocol_buf), "%s", p.protocol);
                    snprintf(facility_buf, sizeof(facility_buf), "%s", p.facility);
                    snprintf(min_level_buf, sizeof(min_level_buf), "%s", p.min_level);
                    snprintf(categories, sizeof(categories), "%s", p.categories);
                    tls_cfg = p.tls;
                    continue;
                }
                if (logd_syslog_profile_upsert(&p) != 0) {
                    json_object_object_add(resp, "ok", json_object_new_boolean(0));
                    json_object_object_add(resp, "error", json_object_new_string("syslog_profile_update_failed"));
                    return resp;
                }
            }
            st = logd_config_prepare("UPDATE logd_syslog_config SET enabled=?1,server=?2,port=?3,protocol=?4,facility=?5,min_level=?6,categories=?7,tls_ca_path=?8,tls_client_cert_path=?9,tls_client_key_path=?10,tls_verify_peer=?11,tls_verify_host=?12,tls_sni=?13,updated_at=?14 WHERE id=1");
            if (!st) {
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("syslog_settings_prepare_failed"));
                return resp;
            }
            sqlite3_bind_int(st, 1, syslog_enabled);
            sqlite3_bind_text(st, 2, server_buf, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 3, syslog_port);
            sqlite3_bind_text(st, 4, protocol_buf, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, facility_buf, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, min_level_buf, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, categories, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 8, tls_cfg.ca_path, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 9, tls_cfg.client_cert_path, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 10, tls_cfg.client_key_path, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 11, tls_cfg.verify_peer);
            sqlite3_bind_int(st, 12, tls_cfg.verify_host);
            sqlite3_bind_text(st, 13, tls_cfg.sni, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 14, logd_now_s());
            if (sqlite3_step(st) != SQLITE_DONE) {
                sqlite3_finalize(st);
                json_object_object_add(resp, "ok", json_object_new_boolean(0));
                json_object_object_add(resp, "error", json_object_new_string("syslog_settings_update_failed"));
                return resp;
            }
            sqlite3_finalize(st);
        }
    }
    logd_prune_if_needed();
    json_object_put(resp);
    return logd_settings_json();
}

static int logd_syslog_state_save(int ok, const char *error, const char *message)
{
    sqlite3_stmt *st;
    int64_t now = logd_now_s();
    int rc;

    st = logd_config_prepare(
        "INSERT INTO logd_syslog_state(id,last_test_at,last_success_at,last_error_at,last_ok,last_error,last_message,updated_at) "
        "VALUES(1,?1,?2,?3,?4,?5,?6,?1) "
        "ON CONFLICT(id) DO UPDATE SET "
        "last_test_at=excluded.last_test_at,"
        "last_success_at=CASE WHEN excluded.last_ok THEN excluded.last_test_at ELSE last_success_at END,"
        "last_error_at=CASE WHEN excluded.last_ok THEN last_error_at ELSE excluded.last_test_at END,"
        "last_ok=excluded.last_ok,last_error=excluded.last_error,last_message=excluded.last_message,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, ok ? now : 0);
    sqlite3_bind_int64(st, 3, ok ? 0 : now);
    sqlite3_bind_int(st, 4, ok ? 1 : 0);
    sqlite3_bind_text(st, 5, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, message ? message : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int logd_syslog_state_note_delivery(int ok, const char *error, const char *message)
{
    sqlite3_stmt *st;
    int64_t now = logd_now_s();
    int rc;

    st = logd_config_prepare(
        "INSERT INTO logd_syslog_state(id,last_test_at,last_success_at,last_error_at,last_ok,last_error,last_message,updated_at) "
        "VALUES(1,0,?2,?1,?3,?4,?5,?1) "
        "ON CONFLICT(id) DO UPDATE SET "
        "last_success_at=CASE WHEN ?3 THEN ?1 ELSE last_success_at END,"
        "last_error_at=CASE WHEN ?3 THEN last_error_at ELSE ?1 END,"
        "last_ok=?3,last_error=?4,last_message=?5,updated_at=?1");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, ok ? 0 : now);
    sqlite3_bind_int(st, 3, ok ? 1 : 0);
    sqlite3_bind_text(st, 4, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, message ? message : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int logd_socket_connect_timeout(int fd, const struct sockaddr *addr,
                                       socklen_t addrlen, int timeout_ms,
                                       char *error, size_t error_len)
{
    int flags;
    int rc;
    struct pollfd pfd;
    int so_error = 0;
    socklen_t so_len = sizeof(so_error);

    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    rc = connect(fd, addr, addrlen);
    if (rc == 0)
        goto done;
    if (errno != EINPROGRESS) {
        snprintf(error, error_len, "connect:%s", strerror(errno));
        return -1;
    }
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0) {
        snprintf(error, error_len, "%s", "connect_timeout");
        return -1;
    }
    if (rc < 0) {
        snprintf(error, error_len, "poll:%s", strerror(errno));
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0) {
        snprintf(error, error_len, "getsockopt:%s", strerror(errno));
        return -1;
    }
    if (so_error != 0) {
        snprintf(error, error_len, "connect:%s", strerror(so_error));
        return -1;
    }
done:
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags);
    return 0;
}

static int logd_send_all_timeout(int fd, const char *payload, size_t payload_len,
                                 int timeout_ms, char *error, size_t error_len)
{
    size_t sent = 0;

    while (sent < payload_len) {
        struct pollfd pfd;
        ssize_t n;
        int rc;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLOUT;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc == 0) {
            snprintf(error, error_len, "%s", "send_timeout");
            return -1;
        }
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            snprintf(error, error_len, "poll:%s", strerror(errno));
            return -1;
        }
        n = send(fd, payload + sent, payload_len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            snprintf(error, error_len, "send:%s", strerror(errno));
            return -1;
        }
        if (n == 0) {
            snprintf(error, error_len, "%s", "send_closed");
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int logd_ssl_wait(SSL *ssl, int fd, int ssl_rc, int timeout_ms,
                         char *error, size_t error_len)
{
    int err = SSL_get_error(ssl, ssl_rc);
    struct pollfd pfd;
    int rc;

    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        unsigned long e = ERR_get_error();
        if (e)
            snprintf(error, error_len, "tls:%s", ERR_error_string(e, NULL));
        else
            snprintf(error, error_len, "tls_error:%d", err);
        return -1;
    }
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0) {
        snprintf(error, error_len, "%s", err == SSL_ERROR_WANT_READ ? "tls_read_timeout" : "tls_write_timeout");
        return -1;
    }
    if (rc < 0) {
        snprintf(error, error_len, "tls_poll:%s", strerror(errno));
        return -1;
    }
    return 1;
}

static int logd_tls_write_payload(int fd, const char *server,
                                  const struct logd_syslog_tls_config *tls_cfg,
                                  const char *payload,
                                  size_t payload_len, int timeout_ms,
                                  char *error, size_t error_len)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    size_t sent = 0;
    const char *tls_name = server;
    int ok = -1;

    if (tls_cfg && !logd_syslog_tls_config_valid(tls_cfg)) {
        snprintf(error, error_len, "%s", "tls_config_invalid");
        goto out;
    }
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        snprintf(error, error_len, "%s", "tls_ctx_new_failed");
        goto out;
    }
    if (!tls_cfg || tls_cfg->verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (tls_cfg && tls_cfg->ca_path[0]) {
            if (SSL_CTX_load_verify_locations(ctx, tls_cfg->ca_path, NULL) != 1) {
                snprintf(error, error_len, "%s", "tls_ca_load_failed");
                goto out;
            }
        } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            snprintf(error, error_len, "%s", "tls_default_ca_load_failed");
            goto out;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    if (tls_cfg && tls_cfg->client_cert_path[0]) {
        if (SSL_CTX_use_certificate_file(ctx, tls_cfg->client_cert_path, SSL_FILETYPE_PEM) != 1) {
            snprintf(error, error_len, "%s", "tls_client_cert_load_failed");
            goto out;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, tls_cfg->client_key_path, SSL_FILETYPE_PEM) != 1) {
            snprintf(error, error_len, "%s", "tls_client_key_load_failed");
            goto out;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            snprintf(error, error_len, "%s", "tls_client_key_mismatch");
            goto out;
        }
    }
    ssl = SSL_new(ctx);
    if (!ssl) {
        snprintf(error, error_len, "%s", "tls_new_failed");
        goto out;
    }
    SSL_set_fd(ssl, fd);
    if (tls_cfg && tls_cfg->sni[0])
        tls_name = tls_cfg->sni;
    if (tls_name && tls_name[0]) {
        SSL_set_tlsext_host_name(ssl, tls_name);
        if (!tls_cfg || tls_cfg->verify_host)
            SSL_set1_host(ssl, tls_name);
    }
    SSL_set_connect_state(ssl);
    for (;;) {
        int rc = SSL_connect(ssl);
        if (rc == 1)
            break;
        rc = logd_ssl_wait(ssl, fd, rc, timeout_ms, error, error_len);
        if (rc < 0)
            goto out;
    }
    while (sent < payload_len) {
        int rc = SSL_write(ssl, payload + sent, (int)(payload_len - sent));
        if (rc > 0) {
            sent += (size_t)rc;
            continue;
        }
        rc = logd_ssl_wait(ssl, fd, rc, timeout_ms, error, error_len);
        if (rc < 0)
            goto out;
    }
    ok = 0;
out:
    if (ssl) {
        if (ok == 0)
            SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx)
        SSL_CTX_free(ctx);
    return ok;
}

static int logd_syslog_send_payload(const char *server, int port,
                                    const char *protocol, const char *payload,
                                    const struct logd_syslog_tls_config *tls_cfg,
                                    int timeout_ms,
                                    char *message, size_t message_len,
                                    char *error, size_t error_len)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char port_s[16];
    int socktype;
    int sent = 0;
    int rc;
    size_t payload_len = payload ? strlen(payload) : 0;

    if (!server || !server[0]) {
        snprintf(error, error_len, "%s", "missing_syslog_server");
        return 0;
    }
    if (!payload || payload_len == 0) {
        snprintf(error, error_len, "%s", "empty_syslog_payload");
        return 0;
    }
    socktype = (!strcmp(protocol, "tcp") || !strcmp(protocol, "tls")) ? SOCK_STREAM : SOCK_DGRAM;
    snprintf(port_s, sizeof(port_s), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = socktype;
    hints.ai_family = AF_UNSPEC;
    rc = getaddrinfo(server, port_s, &hints, &res);
    if (rc != 0) {
        snprintf(error, error_len, "resolve:%s", gai_strerror(rc));
        return 0;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (fd < 0) {
            snprintf(error, error_len, "socket:%s", strerror(errno));
            continue;
        }
        if (!strcmp(protocol, "tcp")) {
            if (logd_socket_connect_timeout(fd, ai->ai_addr, ai->ai_addrlen,
                                            timeout_ms, error, error_len) != 0) {
                close(fd);
                continue;
            }
            rc = logd_send_all_timeout(fd, payload, payload_len, timeout_ms, error, error_len);
        } else if (!strcmp(protocol, "tls")) {
            if (logd_socket_connect_timeout(fd, ai->ai_addr, ai->ai_addrlen,
                                            timeout_ms, error, error_len) != 0) {
                close(fd);
                continue;
            }
            rc = logd_tls_write_payload(fd, server, tls_cfg, payload, payload_len,
                                        timeout_ms, error, error_len);
        } else {
            rc = (int)sendto(fd, payload, payload_len, 0, ai->ai_addr, ai->ai_addrlen);
            if (rc >= 0)
                rc = 0;
        }
        close(fd);
        if (rc < 0) {
            if (!error[0])
                snprintf(error, error_len, "send:%s", strerror(errno));
            continue;
        }
        sent = 1;
        break;
    }
    freeaddrinfo(res);
    if (!sent)
        return 0;
    if (!strcmp(protocol, "udp"))
        snprintf(message, message_len, "%s", "UDP test packet sent; receiver acknowledgement is not available for UDP syslog");
    else if (!strcmp(protocol, "tcp"))
        snprintf(message, message_len, "%s", "TCP syslog connection and test write succeeded");
    else
        snprintf(message, message_len, "%s", "TLS syslog handshake and test write succeeded");
    error[0] = 0;
    return 1;
}

static int logd_syslog_send_test_packet(const char *server, int port,
                                        const char *protocol,
                                        const struct logd_syslog_tls_config *tls_cfg,
                                        int timeout_ms,
                                        char *message, size_t message_len,
                                        char *error, size_t error_len)
{
    char packet[512];

    snprintf(packet, sizeof(packet),
             "<134>1 %lld dreamingwrt logd - syslog-test - DreamingWrt log center syslog test\n",
             (long long)logd_now_s());
    return logd_syslog_send_payload(server, port, protocol, packet, tls_cfg, timeout_ms,
                                    message, message_len, error, error_len);
}

static int logd_syslog_category_allowed(const char *csv, const char *category)
{
    char buf[512];
    char *save = NULL;
    char *tok;

    if (!category || !category[0])
        return 1;
    if (!csv || !csv[0])
        return 1;
    snprintf(buf, sizeof(buf), "%s", csv);
    tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (!strcmp(tok, "*") || !strcmp(tok, "all") || !strcmp(tok, category))
            return 1;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static int logd_syslog_severity_rank(const char *severity)
{
    if (!severity)
        return 6;
    if (!strcmp(severity, "critical"))
        return 2;
    if (!strcmp(severity, "error"))
        return 3;
    if (!strcmp(severity, "warning"))
        return 4;
    if (!strcmp(severity, "notice"))
        return 5;
    return 6;
}

static int logd_syslog_facility_code(const char *facility)
{
    if (!facility)
        return 23;
    if (!strcmp(facility, "kern")) return 0;
    if (!strcmp(facility, "user")) return 1;
    if (!strcmp(facility, "mail")) return 2;
    if (!strcmp(facility, "daemon")) return 3;
    if (!strcmp(facility, "auth")) return 4;
    if (!strcmp(facility, "syslog")) return 5;
    if (!strcmp(facility, "lpr")) return 6;
    if (!strcmp(facility, "news")) return 7;
    if (!strcmp(facility, "uucp")) return 8;
    if (!strcmp(facility, "cron")) return 9;
    if (!strcmp(facility, "authpriv")) return 10;
    if (!strcmp(facility, "ftp")) return 11;
    if (!strncmp(facility, "local", 5) && isdigit((unsigned char)facility[5])) {
        int n = facility[5] - '0';
        if (n >= 0 && n <= 7 && facility[6] == '\0')
            return 16 + n;
    }
    return 23;
}

static void logd_syslog_escape_msg(const char *in, char *out, size_t out_len)
{
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)(in ? in : "");

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    while (*p && n + 1 < out_len) {
        unsigned char c = *p++;

        if (c == '\r' || c == '\n')
            c = ' ';
        if (c < 32 && c != '\t')
            continue;
        out[n++] = (char)c;
    }
    out[n] = 0;
}

static void logd_syslog_build_payload(struct json_object *body,
                                      const char *event_id,
                                      const char *facility,
                                      char *out, size_t out_len)
{
    const char *severity = logd_severity(logd_json_str(body, "severity", "info"));
    const char *event = logd_json_str(body, "event", "event");
    const char *source = logd_json_str(body, "source", "dreamingwrt-logd");
    const char *title = logd_json_str(body, "title", event);
    const char *hostname = "dreamingwrt";
    int pri = logd_syslog_facility_code(facility) * 8 + logd_syslog_severity_rank(severity);
    int64_t ts = logd_json_i64(body, "ts", logd_now_s());
    char msg[1024];
    char sd[512];
    char title_e[512];
    char event_e[128];

    logd_syslog_escape_msg(title && title[0] ? title : event, title_e, sizeof(title_e));
    logd_syslog_escape_msg(event, event_e, sizeof(event_e));
    snprintf(sd, sizeof(sd),
             "[dreamingwrt@51717 event=\"%s\" category=\"%s\" severity=\"%s\" source=\"%s\" id=\"%s\"]",
             event_e,
             logd_json_str(body, "category", ""),
             severity,
             source && source[0] ? source : "dreamingwrt-logd",
             event_id && event_id[0] ? event_id : "-");
    snprintf(msg, sizeof(msg), "%s", title_e[0] ? title_e : event_e);
    snprintf(out, out_len, "<%d>1 %lld %s %s - %s %s %s\n",
             pri, (long long)ts, hostname,
             source && source[0] ? source : "dreamingwrt-logd",
             event_id && event_id[0] ? event_id : "-",
             sd, msg);
}

static int logd_syslog_queue_prune_over_limit(void)
{
    sqlite3_stmt *st;
    int64_t total = 0;
    int rc = 0;

    st = logd_config_prepare("SELECT COUNT(*) FROM logd_syslog_queue");
    if (!st)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        total = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (total < LOGD_SYSLOG_QUEUE_MAX_ROWS)
        return 0;

    st = logd_config_prepare(
        "DELETE FROM logd_syslog_queue WHERE id IN ("
        "SELECT id FROM logd_syslog_queue "
        "ORDER BY CASE status WHEN 'sent' THEN 0 WHEN 'failed' THEN 1 ELSE 2 END, created_at ASC "
        "LIMIT ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, total - LOGD_SYSLOG_QUEUE_MAX_ROWS + 1);
    if (sqlite3_step(st) != SQLITE_DONE)
        rc = -1;
    sqlite3_finalize(st);
    return rc;
}

static int logd_syslog_enqueue_profile(struct json_object *body,
                                       const struct logd_syslog_profile *profile)
{
    sqlite3_stmt *st = NULL;
    char id[128];
    char payload[LOGD_SYSLOG_QUEUE_MAX_LINE];
    const char *event_id = logd_json_str(body, "id", "");
    const char *category = logd_json_str(body, "category", "");
    const char *severity = logd_severity(logd_json_str(body, "severity", "info"));
    int64_t now = logd_now_s();
    int rc = -1;

    if (!body || !profile)
        return -1;
    if (!profile->enabled || !profile->server[0])
        return 0;
    if (logd_syslog_severity_rank(severity) > logd_syslog_severity_rank(logd_severity(profile->min_level)))
        return 0;
    if (!logd_syslog_category_allowed(profile->categories, category))
        return 0;
    if (strcmp(profile->protocol, "udp") && strcmp(profile->protocol, "tcp") && strcmp(profile->protocol, "tls"))
        return -1;
    if (logd_syslog_queue_prune_over_limit() != 0)
        return -1;
    logd_syslog_build_payload(body, event_id, profile->facility, payload, sizeof(payload));
    snprintf(id, sizeof(id), "syslog-%s-%llx-%s",
             profile->profile_id,
             (unsigned long long)logd_hash64(payload),
             event_id && event_id[0] ? event_id : "event");
    st = logd_config_prepare(
        "INSERT OR IGNORE INTO logd_syslog_queue(id,event_id,ts,protocol,server,port,profile_id,profile_name,facility,severity,category,event,payload,status,created_at,updated_at,next_retry_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending',?14,?14,?14)");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, logd_json_i64(body, "ts", now));
    sqlite3_bind_text(st, 4, profile->protocol, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, profile->server, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, profile->port);
    sqlite3_bind_text(st, 7, profile->profile_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, profile->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, profile->facility, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, severity, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, logd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, payload, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 14, now);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = sqlite3_changes(g_config_db) > 0 ? 1 : 0;
    sqlite3_finalize(st);
    return rc;
}

int logd_syslog_enqueue_event(struct json_object *body)
{
    sqlite3_stmt *st = NULL;
    struct logd_syslog_profile p;
    int total = 0;
    int errors = 0;

    if (!body)
        return -1;
    logd_syslog_profile_init(&p,
                             LOGD_SYSLOG_DEFAULT_PROFILE_ID,
                             LOGD_SYSLOG_DEFAULT_PROFILE_NAME);
    st = logd_config_prepare(
        "SELECT enabled,server,port,protocol,facility,min_level,categories,"
        "tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni,updated_at "
        "FROM logd_syslog_config WHERE id=1");
    if (st) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            p.enabled = sqlite3_column_int(st, 0);
            snprintf(p.server, sizeof(p.server), "%s", logd_sqlite_text(st, 1, ""));
            p.port = sqlite3_column_int(st, 2);
            snprintf(p.protocol, sizeof(p.protocol), "%s", logd_sqlite_text(st, 3, "udp"));
            snprintf(p.facility, sizeof(p.facility), "%s", logd_sqlite_text(st, 4, "local7"));
            snprintf(p.min_level, sizeof(p.min_level), "%s", logd_sqlite_text(st, 5, "notice"));
            snprintf(p.categories, sizeof(p.categories), "%s", logd_sqlite_text(st, 6, LOGD_SYSLOG_DEFAULT_CATEGORIES));
            snprintf(p.tls.ca_path, sizeof(p.tls.ca_path), "%s", logd_sqlite_text(st, 7, ""));
            snprintf(p.tls.client_cert_path, sizeof(p.tls.client_cert_path), "%s", logd_sqlite_text(st, 8, ""));
            snprintf(p.tls.client_key_path, sizeof(p.tls.client_key_path), "%s", logd_sqlite_text(st, 9, ""));
            p.tls.verify_peer = sqlite3_column_int(st, 10) ? 1 : 0;
            p.tls.verify_host = sqlite3_column_int(st, 11) ? 1 : 0;
            snprintf(p.tls.sni, sizeof(p.tls.sni), "%s", logd_sqlite_text(st, 12, ""));
            p.updated_at = (int)sqlite3_column_int64(st, 13);
        }
        sqlite3_finalize(st);
        int rc = logd_syslog_enqueue_profile(body, &p);
        if (rc > 0)
            total += rc;
        else if (rc < 0)
            errors++;
    } else {
        errors++;
    }

    st = logd_config_prepare(
        "SELECT profile_id,name,enabled,server,port,protocol,facility,min_level,categories,"
        "tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni,"
        "sort_order,is_default,updated_at "
        "FROM logd_syslog_profiles ORDER BY sort_order,profile_id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            logd_syslog_profile_init(&p, logd_sqlite_text(st, 0, ""), logd_sqlite_text(st, 1, ""));
            if (!strcmp(p.profile_id, LOGD_SYSLOG_DEFAULT_PROFILE_ID))
                continue;
            p.enabled = sqlite3_column_int(st, 2);
            snprintf(p.server, sizeof(p.server), "%s", logd_sqlite_text(st, 3, ""));
            p.port = sqlite3_column_int(st, 4);
            snprintf(p.protocol, sizeof(p.protocol), "%s", logd_sqlite_text(st, 5, "udp"));
            snprintf(p.facility, sizeof(p.facility), "%s", logd_sqlite_text(st, 6, "local7"));
            snprintf(p.min_level, sizeof(p.min_level), "%s", logd_sqlite_text(st, 7, "notice"));
            snprintf(p.categories, sizeof(p.categories), "%s", logd_sqlite_text(st, 8, LOGD_SYSLOG_DEFAULT_CATEGORIES));
            snprintf(p.tls.ca_path, sizeof(p.tls.ca_path), "%s", logd_sqlite_text(st, 9, ""));
            snprintf(p.tls.client_cert_path, sizeof(p.tls.client_cert_path), "%s", logd_sqlite_text(st, 10, ""));
            snprintf(p.tls.client_key_path, sizeof(p.tls.client_key_path), "%s", logd_sqlite_text(st, 11, ""));
            p.tls.verify_peer = sqlite3_column_int(st, 12) ? 1 : 0;
            p.tls.verify_host = sqlite3_column_int(st, 13) ? 1 : 0;
            snprintf(p.tls.sni, sizeof(p.tls.sni), "%s", logd_sqlite_text(st, 14, ""));
            p.sort_order = sqlite3_column_int(st, 15);
            p.is_default = sqlite3_column_int(st, 16) ? 1 : 0;
            p.updated_at = (int)sqlite3_column_int64(st, 17);
            int rc = logd_syslog_enqueue_profile(body, &p);
            if (rc > 0)
                total += rc;
            else if (rc < 0)
                errors++;
        }
        sqlite3_finalize(st);
    } else {
        errors++;
    }
    if (errors && total == 0)
        return -1;
    return total;
}

static int logd_syslog_queue_mark(const char *id, int ok, const char *error)
{
    sqlite3_stmt *st;
    int64_t now = logd_now_s();
    int retry_after = 30;
    int attempts = 0;
    int rc;

    if (!id || !id[0])
        return -1;
    st = logd_config_prepare("SELECT attempts FROM logd_syslog_queue WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            attempts = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    if (attempts > 0)
        retry_after = 30 * (attempts + 1);
    if (retry_after > 1800)
        retry_after = 1800;
    st = logd_config_prepare(
        "UPDATE logd_syslog_queue SET status=?1,attempts=attempts+1,last_error=?2,updated_at=?3,next_retry_at=?4,sent_at=?5 WHERE id=?6");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, ok ? "sent" : "failed", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_int64(st, 4, ok ? 0 : now + retry_after);
    sqlite3_bind_int64(st, 5, ok ? now : 0);
    sqlite3_bind_text(st, 6, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int logd_syslog_process_queue(int limit)
{
    sqlite3_stmt *st = NULL;
    char ids[LOGD_SYSLOG_QUEUE_BATCH][128];
    int n = 0;
    int sent = 0;
    int failed = 0;
    int64_t now = logd_now_s();

    if (limit <= 0 || limit > LOGD_SYSLOG_QUEUE_BATCH)
        limit = LOGD_SYSLOG_QUEUE_BATCH;
    st = logd_config_prepare(
        "SELECT id FROM logd_syslog_queue WHERE status IN ('pending','failed') AND next_retry_at<=?1 ORDER BY created_at LIMIT ?2");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int(st, 2, limit);
    while (n < limit && sqlite3_step(st) == SQLITE_ROW) {
        snprintf(ids[n], sizeof(ids[n]), "%s", logd_sqlite_text(st, 0, ""));
        n++;
    }
    sqlite3_finalize(st);
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *row;
        char protocol[16] = "";
        char server[256] = "";
        char profile_id[64] = LOGD_SYSLOG_DEFAULT_PROFILE_ID;
        char payload[LOGD_SYSLOG_QUEUE_MAX_LINE] = "";
        char error[256] = "";
        char message[512] = "";
        int port = 514;
        int ok = 0;

        row = logd_config_prepare("SELECT protocol,server,port,payload,profile_id FROM logd_syslog_queue WHERE id=?1");
        if (!row)
            continue;
        sqlite3_bind_text(row, 1, ids[i], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(row) == SQLITE_ROW) {
            snprintf(protocol, sizeof(protocol), "%s", logd_sqlite_text(row, 0, "udp"));
            snprintf(server, sizeof(server), "%s", logd_sqlite_text(row, 1, ""));
            port = sqlite3_column_int(row, 2);
            snprintf(payload, sizeof(payload), "%s", logd_sqlite_text(row, 3, ""));
            snprintf(profile_id, sizeof(profile_id), "%s", logd_sqlite_text(row, 4, LOGD_SYSLOG_DEFAULT_PROFILE_ID));
        }
        sqlite3_finalize(row);
        struct logd_syslog_tls_config tls_cfg;

        logd_syslog_tls_config_init(&tls_cfg);
        if (!strcmp(profile_id, LOGD_SYSLOG_DEFAULT_PROFILE_ID))
            row = logd_config_prepare("SELECT tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni FROM logd_syslog_config WHERE id=1");
        else
            row = logd_config_prepare("SELECT tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni FROM logd_syslog_profiles WHERE profile_id=?1");
        if (row) {
            if (strcmp(profile_id, LOGD_SYSLOG_DEFAULT_PROFILE_ID))
                sqlite3_bind_text(row, 1, profile_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(row) == SQLITE_ROW) {
                snprintf(tls_cfg.ca_path, sizeof(tls_cfg.ca_path), "%s", logd_sqlite_text(row, 0, ""));
                snprintf(tls_cfg.client_cert_path, sizeof(tls_cfg.client_cert_path), "%s", logd_sqlite_text(row, 1, ""));
                snprintf(tls_cfg.client_key_path, sizeof(tls_cfg.client_key_path), "%s", logd_sqlite_text(row, 2, ""));
                tls_cfg.verify_peer = sqlite3_column_int(row, 3) ? 1 : 0;
                tls_cfg.verify_host = sqlite3_column_int(row, 4) ? 1 : 0;
                snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", logd_sqlite_text(row, 5, ""));
            }
            sqlite3_finalize(row);
        }
        ok = logd_syslog_send_payload(server, port, protocol, payload, &tls_cfg, 3000,
                                      message, sizeof(message), error, sizeof(error));
        if (logd_syslog_queue_mark(ids[i], ok, error) == 0) {
            if (ok)
                sent++;
            else
                failed++;
            logd_syslog_state_note_delivery(ok, error, ok ? "syslog delivery succeeded" : "syslog delivery failed");
        }
    }
    st = logd_config_prepare("DELETE FROM logd_syslog_queue WHERE status='sent' AND updated_at<?1");
    if (st) {
        sqlite3_bind_int64(st, 1, now - LOGD_SYSLOG_QUEUE_SENT_RETENTION_SEC);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    st = logd_config_prepare("DELETE FROM logd_syslog_queue WHERE status='failed' AND updated_at<?1");
    if (st) {
        sqlite3_bind_int64(st, 1, now - LOGD_SYSLOG_QUEUE_FAILED_RETENTION_SEC);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    (void)logd_syslog_queue_prune_over_limit();
    (void)failed;
    return sent;
}

struct json_object *logd_syslog_queue_status(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *by_status = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *watermark = json_object_new_object();
    sqlite3_stmt *st;
    int limit = logd_json_int(body, "limit", 20);
    int64_t total_rows = 0;
    int64_t oldest_created_at = 0;
    int64_t newest_created_at = 0;
    int64_t pending_retry_due = 0;
    int64_t now = logd_now_s();
    double used_ratio = 0.0;

    if (limit < 0) limit = 0;
    if (limit > 100) limit = 100;
    st = logd_config_prepare("SELECT status,COUNT(*) FROM logd_syslog_queue GROUP BY status");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW)
            json_object_object_add(by_status, logd_sqlite_text(st, 0, "unknown"),
                                   json_object_new_int64(sqlite3_column_int64(st, 1)));
        sqlite3_finalize(st);
    }
    st = logd_config_prepare("SELECT COUNT(*),COALESCE(MIN(created_at),0),COALESCE(MAX(created_at),0),SUM(CASE WHEN status IN ('pending','failed') AND next_retry_at<=?1 THEN 1 ELSE 0 END) FROM logd_syslog_queue");
    if (st) {
        sqlite3_bind_int64(st, 1, now);
        if (sqlite3_step(st) == SQLITE_ROW) {
            total_rows = sqlite3_column_int64(st, 0);
            oldest_created_at = sqlite3_column_int64(st, 1);
            newest_created_at = sqlite3_column_int64(st, 2);
            pending_retry_due = sqlite3_column_int64(st, 3);
        }
        sqlite3_finalize(st);
    }
    struct json_object *by_profile = json_object_new_object();

    st = logd_config_prepare("SELECT profile_id,status,COUNT(*) FROM logd_syslog_queue GROUP BY profile_id,status");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *pid = logd_sqlite_text(st, 0, LOGD_SYSLOG_DEFAULT_PROFILE_ID);
            const char *status = logd_sqlite_text(st, 1, "unknown");
            struct json_object *po = NULL;

            if (!json_object_object_get_ex(by_profile, pid, &po) || !po) {
                po = json_object_new_object();
                json_object_object_add(by_profile, pid, po);
            }
            json_object_object_add(po, status, json_object_new_int64(sqlite3_column_int64(st, 2)));
        }
        sqlite3_finalize(st);
    }
    st = logd_config_prepare(
        "SELECT id,event_id,ts,protocol,server,port,status,attempts,last_error,created_at,updated_at,next_retry_at,sent_at,profile_id,profile_name "
        "FROM logd_syslog_queue ORDER BY created_at DESC LIMIT ?1");
    if (st) {
        sqlite3_bind_int(st, 1, limit);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_string(logd_sqlite_text(st, 0, "")));
            json_object_object_add(o, "event_id", json_object_new_string(logd_sqlite_text(st, 1, "")));
            json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(o, "protocol", json_object_new_string(logd_sqlite_text(st, 3, "")));
            json_object_object_add(o, "server", json_object_new_string(logd_sqlite_text(st, 4, "")));
            json_object_object_add(o, "port", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_object_add(o, "status", json_object_new_string(logd_sqlite_text(st, 6, "")));
            json_object_object_add(o, "attempts", json_object_new_int(sqlite3_column_int(st, 7)));
            json_object_object_add(o, "last_error", json_object_new_string(logd_sqlite_text(st, 8, "")));
            json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
            json_object_object_add(o, "next_retry_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
            json_object_object_add(o, "sent_at", json_object_new_int64(sqlite3_column_int64(st, 12)));
            json_object_object_add(o, "profile_id", json_object_new_string(logd_sqlite_text(st, 13, LOGD_SYSLOG_DEFAULT_PROFILE_ID)));
            json_object_object_add(o, "profile_name", json_object_new_string(logd_sqlite_text(st, 14, LOGD_SYSLOG_DEFAULT_PROFILE_NAME)));
            json_object_array_add(items, o);
        }
        sqlite3_finalize(st);
    }
    used_ratio = LOGD_SYSLOG_QUEUE_MAX_ROWS > 0 ? ((double)total_rows / (double)LOGD_SYSLOG_QUEUE_MAX_ROWS) : 0.0;
    json_object_object_add(watermark, "max_rows", json_object_new_int(LOGD_SYSLOG_QUEUE_MAX_ROWS));
    json_object_object_add(watermark, "used_rows", json_object_new_int64(total_rows));
    json_object_object_add(watermark, "used_ratio", json_object_new_double(used_ratio));
    json_object_object_add(watermark, "oldest_created_at", json_object_new_int64(oldest_created_at));
    json_object_object_add(watermark, "newest_created_at", json_object_new_int64(newest_created_at));
    json_object_object_add(watermark, "pending_retry_due", json_object_new_int64(pending_retry_due));
    json_object_object_add(watermark, "sent_retention_sec", json_object_new_int(LOGD_SYSLOG_QUEUE_SENT_RETENTION_SEC));
    json_object_object_add(watermark, "failed_retention_sec", json_object_new_int(LOGD_SYSLOG_QUEUE_FAILED_RETENTION_SEC));
    json_object_object_add(watermark, "degraded", json_object_new_boolean(total_rows >= LOGD_SYSLOG_QUEUE_MAX_ROWS));
    json_object_object_add(watermark, "level", json_object_new_string(total_rows >= LOGD_SYSLOG_QUEUE_MAX_ROWS ? "critical" : (used_ratio >= 0.8 ? "warning" : "ok")));
    json_object_object_add(watermark, "reason", json_object_new_string(total_rows >= LOGD_SYSLOG_QUEUE_MAX_ROWS ? "syslog_queue_row_limit_reached" : (used_ratio >= 0.8 ? "syslog_queue_high_watermark" : "ok")));

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "by_status", by_status);
    json_object_object_add(resp, "by_profile", by_profile);
    json_object_object_add(resp, "items", items);
    json_object_object_add(resp, "total_rows", json_object_new_int64(total_rows));
    json_object_object_add(resp, "watermark", watermark);
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_syslog_queue_flush(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    int limit = logd_json_int(body, "limit", LOGD_SYSLOG_QUEUE_BATCH);
    int sent = logd_syslog_process_queue(limit);

    json_object_object_add(resp, "ok", json_object_new_boolean(sent >= 0));
    json_object_object_add(resp, "sent", json_object_new_int(sent >= 0 ? sent : 0));
    if (sent < 0)
        json_object_object_add(resp, "error", json_object_new_string("syslog_queue_flush_failed"));
    json_object_object_add(resp, "status", logd_syslog_queue_status(NULL));
    return resp;
}

static int logd_syslog_status_token(const char *csv, const char *needle)
{
    char buf[128];
    char *save = NULL;
    char *tok;

    if (!csv || !needle || !needle[0])
        return 0;
    snprintf(buf, sizeof(buf), "%s", csv);
    tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (!strcmp(tok, needle))
            return 1;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

struct json_object *logd_syslog_queue_clear(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *statuses = json_object_new_array();
    sqlite3_stmt *st;
    const char *status = logd_json_str(body, "status", "");
    int include_pending = logd_json_bool(body, "include_pending", 0);
    int clear_sent = 1;
    int clear_failed = 1;
    int clear_pending = include_pending;
    int rc;

    if (status && status[0]) {
        clear_sent = !strcmp(status, "all") || logd_syslog_status_token(status, "sent");
        clear_failed = !strcmp(status, "all") || logd_syslog_status_token(status, "failed");
        clear_pending = logd_syslog_status_token(status, "pending") ||
                        (!strcmp(status, "all") && include_pending);
    } else if (body) {
        clear_sent = logd_json_bool(body, "sent", 1);
        clear_failed = logd_json_bool(body, "failed", 1);
        clear_pending = logd_json_bool(body, "pending", include_pending);
    }
    if (!clear_sent && !clear_failed && !clear_pending) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("no_queue_status_selected"));
        json_object_object_add(resp, "status", logd_syslog_queue_status(NULL));
        return resp;
    }
    if (clear_pending)
        st = logd_config_prepare("DELETE FROM logd_syslog_queue WHERE status IN (?1,?2,?3)");
    else
        st = logd_config_prepare("DELETE FROM logd_syslog_queue WHERE status IN (?1,?2)");
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("syslog_queue_clear_prepare_failed"));
        return resp;
    }
    sqlite3_bind_text(st, 1, clear_sent ? "sent" : "__none__", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, clear_failed ? "failed" : "__none__", -1, SQLITE_TRANSIENT);
    if (clear_pending)
        sqlite3_bind_text(st, 3, "pending", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    json_object_object_add(resp, "ok", json_object_new_boolean(rc == SQLITE_DONE));
    json_object_object_add(resp, "cleared", json_object_new_int(rc == SQLITE_DONE ? sqlite3_changes(g_config_db) : 0));
    if (clear_sent)
        json_object_array_add(statuses, json_object_new_string("sent"));
    if (clear_failed)
        json_object_array_add(statuses, json_object_new_string("failed"));
    if (clear_pending)
        json_object_array_add(statuses, json_object_new_string("pending"));
    json_object_object_add(resp, "cleared_statuses", statuses);
    if (rc != SQLITE_DONE)
        json_object_object_add(resp, "error", json_object_new_string("syslog_queue_clear_failed"));
    json_object_object_add(resp, "status", logd_syslog_queue_status(NULL));
    return resp;
}

struct json_object *logd_syslog_cert_list(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    DIR *dir;
    (void)body;

    mkdir("/etc/dreamingwrt", 0755);
    mkdir(LOGD_SYSLOG_CERT_DIR, 0700);
    dir = opendir(LOGD_SYSLOG_CERT_DIR);
    if (!dir) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("cert_dir_unavailable"));
        json_object_object_add(resp, "items", items);
        return resp;
    }
    for (;;) {
        struct dirent *de = readdir(dir);
        struct stat st;
        struct json_object *o;
        char path[320];
        char kind[32];

        if (!de)
            break;
        if (!logd_syslog_cert_name_ok(de->d_name))
            continue;
        snprintf(path, sizeof(path), "%s/%s", LOGD_SYSLOG_CERT_DIR, de->d_name);
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        logd_syslog_cert_file_kind(de->d_name, kind, sizeof(kind));
        o = json_object_new_object();
        json_object_object_add(o, "name", json_object_new_string(de->d_name));
        json_object_object_add(o, "kind", json_object_new_string(kind));
        json_object_object_add(o, "path", json_object_new_string(path));
        json_object_object_add(o, "size_bytes", json_object_new_int64((int64_t)st.st_size));
        json_object_object_add(o, "mtime", json_object_new_int64((int64_t)st.st_mtime));
        json_object_array_add(items, o);
    }
    closedir(dir);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "dir", json_object_new_string(LOGD_SYSLOG_CERT_DIR));
    json_object_object_add(resp, "items", items);
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_syslog_cert_upload(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    const char *kind = logd_syslog_cert_kind(logd_json_str(body, "kind",
        logd_json_str(body, "type", "ca")));
    const char *name = logd_json_str(body, "name",
        logd_json_str(body, "filename", ""));
    const char *pem = logd_json_str(body, "pem",
        logd_json_str(body, "content", logd_json_str(body, "certificate", "")));
    int activate = logd_json_bool(body, "activate", 0);
    char safe[128];
    char path[320];
    char tmp[352];
    size_t pem_len = 0;
    FILE *fp;

    if (!kind) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_cert_kind"));
        return resp;
    }
    if (!logd_syslog_pem_looks_ok(pem, kind, &pem_len) ||
        logd_syslog_cert_build_name(kind, name, safe, sizeof(safe), path, sizeof(path)) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_cert_upload"));
        return resp;
    }
    mkdir("/etc/dreamingwrt", 0755);
    mkdir(LOGD_SYSLOG_CERT_DIR, 0700);
    snprintf(tmp, sizeof(tmp), "%s.tmp-%lld", path, (long long)logd_now_s());
    fp = fopen(tmp, "wb");
    if (!fp) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("cert_write_failed"));
        return resp;
    }
    if (fwrite(pem, 1, pem_len, fp) != pem_len || fputc('\n', fp) == EOF) {
        fclose(fp);
        unlink(tmp);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("cert_write_failed"));
        return resp;
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("cert_write_failed"));
        return resp;
    }
    chmod(tmp, (!strcmp(kind, "client_key") || !strcmp(kind, "key")) ? 0600 : 0644);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("cert_rename_failed"));
        return resp;
    }
    if (activate) {
        struct json_object *set = json_object_new_object();
        struct json_object *syslog = json_object_new_object();
        struct json_object *tls = json_object_new_object();
        struct json_object *set_resp;

        if (!strcmp(kind, "ca"))
            json_object_object_add(tls, "ca_path", json_object_new_string(path));
        else if (!strcmp(kind, "client_key") || !strcmp(kind, "key"))
            json_object_object_add(tls, "client_key_path", json_object_new_string(path));
        else
            json_object_object_add(tls, "client_cert_path", json_object_new_string(path));
        json_object_object_add(syslog, "tls", tls);
        json_object_object_add(set, "syslog", syslog);
        set_resp = logd_settings_update(set);
        json_object_object_add(resp, "settings", set_resp);
        json_object_put(set);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "kind", json_object_new_string(kind));
    json_object_object_add(resp, "name", json_object_new_string(safe));
    json_object_object_add(resp, "path", json_object_new_string(path));
    json_object_object_add(resp, "size_bytes", json_object_new_int64((int64_t)pem_len + 1));
    json_object_object_add(resp, "activated", json_object_new_boolean(activate));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_syslog_cert_delete(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    const char *name = logd_json_str(body, "name",
        logd_json_str(body, "filename", ""));
    char path[320];

    if (!logd_syslog_cert_name_ok(name)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_cert_name"));
        return resp;
    }
    snprintf(path, sizeof(path), "%s/%s", LOGD_SYSLOG_CERT_DIR, name);
    if (unlink(path) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string(errno == ENOENT ? "cert_not_found" : "cert_delete_failed"));
        return resp;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "name", json_object_new_string(name));
    json_object_object_add(resp, "path", json_object_new_string(path));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}

struct json_object *logd_syslog_test(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *syslog = NULL;
    sqlite3_stmt *st;
    char server[256] = "";
    char protocol[16] = "udp";
    char facility[32] = "local7";
    char min_level[32] = "notice";
    char error[256] = "";
    char message[512] = "";
    struct logd_syslog_tls_config tls_cfg;
    int port = 514;
    int timeout_ms;
    int ok;
    int rc;

    logd_syslog_tls_config_init(&tls_cfg);
    st = logd_config_prepare("SELECT server,port,protocol,facility,min_level,tls_ca_path,tls_client_cert_path,tls_client_key_path,tls_verify_peer,tls_verify_host,tls_sni FROM logd_syslog_config WHERE id=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            snprintf(server, sizeof(server), "%s", logd_sqlite_text(st, 0, ""));
            port = sqlite3_column_int(st, 1);
            snprintf(protocol, sizeof(protocol), "%s", logd_sqlite_text(st, 2, "udp"));
            snprintf(facility, sizeof(facility), "%s", logd_sqlite_text(st, 3, "local7"));
            snprintf(min_level, sizeof(min_level), "%s", logd_sqlite_text(st, 4, "notice"));
            snprintf(tls_cfg.ca_path, sizeof(tls_cfg.ca_path), "%s", logd_sqlite_text(st, 5, ""));
            snprintf(tls_cfg.client_cert_path, sizeof(tls_cfg.client_cert_path), "%s", logd_sqlite_text(st, 6, ""));
            snprintf(tls_cfg.client_key_path, sizeof(tls_cfg.client_key_path), "%s", logd_sqlite_text(st, 7, ""));
            tls_cfg.verify_peer = sqlite3_column_int(st, 8) ? 1 : 0;
            tls_cfg.verify_host = sqlite3_column_int(st, 9) ? 1 : 0;
            snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", logd_sqlite_text(st, 10, ""));
        }
        sqlite3_finalize(st);
    }
    if (body && json_object_object_get_ex(body, "syslog", &syslog) && syslog &&
        json_object_is_type(syslog, json_type_object)) {
        const char *s;

        s = logd_json_str(syslog, "server", NULL);
        if (s)
            snprintf(server, sizeof(server), "%s", s);
        port = logd_json_int(syslog, "port", port);
        s = logd_json_str(syslog, "protocol", NULL);
        if (s)
            snprintf(protocol, sizeof(protocol), "%s", s);
        s = logd_json_str(syslog, "facility", NULL);
        if (s)
            snprintf(facility, sizeof(facility), "%s", s);
        s = logd_json_str(syslog, "min_level", NULL);
        if (s)
            snprintf(min_level, sizeof(min_level), "%s", s);
        logd_syslog_tls_config_from_json(&tls_cfg, syslog);
    } else if (body) {
        const char *s;

        s = logd_json_str(body, "server", NULL);
        if (s)
            snprintf(server, sizeof(server), "%s", s);
        port = logd_json_int(body, "port", port);
        s = logd_json_str(body, "protocol", NULL);
        if (s)
            snprintf(protocol, sizeof(protocol), "%s", s);
        logd_syslog_tls_config_from_json(&tls_cfg, body);
    }
    timeout_ms = logd_json_int(body, "timeout_ms", 3000);
    if (timeout_ms < 500)
        timeout_ms = 500;
    if (timeout_ms > 15000)
        timeout_ms = 15000;
    if (!logd_text_ok(server, 255) || port < 1 || port > 65535 ||
        (strcmp(protocol, "udp") && strcmp(protocol, "tcp") && strcmp(protocol, "tls")) ||
        !logd_token_ok(facility, 32) || !logd_token_ok(min_level, 32) ||
        !logd_syslog_tls_config_valid(&tls_cfg)) {
        snprintf(error, sizeof(error), "%s", "invalid_syslog_settings");
        ok = 0;
    } else {
        ok = logd_syslog_send_test_packet(server, port, protocol, &tls_cfg, timeout_ms,
                                          message, sizeof(message),
                                          error, sizeof(error));
    }
    if (logd_syslog_state_save(ok, error, message) != 0 && ok) {
        ok = 0;
        snprintf(error, sizeof(error), "%s", "state_save_failed");
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "tested_at", json_object_new_int64(logd_now_s()));
    json_object_object_add(resp, "server", json_object_new_string(server));
    json_object_object_add(resp, "port", json_object_new_int(port));
    json_object_object_add(resp, "protocol", json_object_new_string(protocol));
    json_object_object_add(resp, "facility", json_object_new_string(facility));
    json_object_object_add(resp, "min_level", json_object_new_string(min_level));
    json_object_object_add(resp, "tls", logd_syslog_tls_config_json(&tls_cfg));
    json_object_object_add(resp, "timeout_ms", json_object_new_int(timeout_ms));
    if (message[0])
        json_object_object_add(resp, "message", json_object_new_string(message));
    if (error[0])
        json_object_object_add(resp, "error", json_object_new_string(error));
    json_object_object_add(resp, "capabilities", logd_unifi_capabilities_json());
    return resp;
}
