// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"
#include <arpa/inet.h>

struct aegisxd_import_feed {
    char feed_id[128];
    char kind[64];
    char format[64];
    char artifact_path[AEGISXD_MAX_PATH];
    char sha256[65];
};

struct aegisxd_import_counts {
    int imported;
    int skipped;
    int derived_ip_reputation;
};

static int aegisxd_import_exec(const char *sql)
{
    char *err = NULL;
    int rc;

    if (!g_aegisxd_db || !sql)
        return -1;
    rc = sqlite3_exec(g_aegisxd_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] import sql failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(g_aegisxd_db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int aegisxd_import_feed_load(const char *feed_id, struct aegisxd_import_feed *out)
{
    sqlite3_stmt *st;
    int rc = -1;

    if (!feed_id || !feed_id[0] || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    st = aegisxd_prepare(
        "SELECT feed_id,kind,format,artifact_path,sha256 "
        "FROM aegis_feeds WHERE feed_id=? AND enabled=1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, feed_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out->feed_id, sizeof(out->feed_id), "%s", aegisxd_sqlite_text(st, 0, ""));
        snprintf(out->kind, sizeof(out->kind), "%s", aegisxd_sqlite_text(st, 1, ""));
        snprintf(out->format, sizeof(out->format), "%s", aegisxd_sqlite_text(st, 2, ""));
        snprintf(out->artifact_path, sizeof(out->artifact_path), "%s", aegisxd_sqlite_text(st, 3, ""));
        snprintf(out->sha256, sizeof(out->sha256), "%s", aegisxd_sqlite_text(st, 4, ""));
        rc = out->artifact_path[0] ? 0 : -1;
    }
    sqlite3_finalize(st);
    return rc;
}

static struct json_object *aegisxd_import_feed_ids_json(void)
{
    sqlite3_stmt *st;
    struct json_object *arr = json_object_new_array();

    st = aegisxd_prepare(
        "SELECT feed_id FROM aegis_feeds "
        "WHERE enabled=1 AND artifact_path!='' ORDER BY feed_id");
    if (!st)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW)
        json_object_array_add(arr, json_object_new_string(aegisxd_sqlite_text(st, 0, "")));
    sqlite3_finalize(st);
    return arr;
}

static void aegisxd_import_state_begin(const struct aegisxd_import_feed *feed)
{
    sqlite3_stmt *st;
    sqlite3_int64 now = aegisxd_now_s();

    if (!feed)
        return;
    st = aegisxd_prepare(
        "INSERT INTO aegis_import_state"
        "(feed_id,state,last_started_at,last_finished_at,last_error,imported_count,skipped_count,artifact_sha256,meta_json) "
        "VALUES(?,'running',?,0,'',0,0,?,'{}') "
        "ON CONFLICT(feed_id) DO UPDATE SET "
        "state='running',last_started_at=excluded.last_started_at,last_finished_at=0,"
        "last_error='',imported_count=0,skipped_count=0,artifact_sha256=excluded.artifact_sha256");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, feed->feed_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, feed->sha256, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static void aegisxd_import_state_finish(const struct aegisxd_import_feed *feed,
                                        const char *state, const char *error,
                                        int imported, int skipped,
                                        struct json_object *meta)
{
    sqlite3_stmt *st;
    const char *meta_s = meta ? json_object_to_json_string(meta) : "{}";

    if (!feed)
        return;
    st = aegisxd_prepare(
        "INSERT INTO aegis_import_state"
        "(feed_id,state,last_started_at,last_finished_at,last_error,imported_count,skipped_count,artifact_sha256,meta_json) "
        "VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(feed_id) DO UPDATE SET "
        "state=excluded.state,last_finished_at=excluded.last_finished_at,last_error=excluded.last_error,"
        "imported_count=excluded.imported_count,skipped_count=excluded.skipped_count,"
        "artifact_sha256=excluded.artifact_sha256,meta_json=excluded.meta_json");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, feed->feed_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, state ? state : "done", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, aegisxd_now_s());
    sqlite3_bind_int64(st, 4, aegisxd_now_s());
    sqlite3_bind_text(st, 5, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, imported);
    sqlite3_bind_int(st, 7, skipped);
    sqlite3_bind_text(st, 8, feed->sha256, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);

    st = aegisxd_prepare(
        "UPDATE aegis_feeds SET item_count=?,last_error=?,updated_at=? WHERE feed_id=?");
    if (!st)
        return;
    sqlite3_bind_int(st, 1, imported);
    sqlite3_bind_text(st, 2, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, aegisxd_now_s());
    sqlite3_bind_text(st, 4, feed->feed_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static void aegisxd_import_delete_old(const struct aegisxd_import_feed *feed)
{
    sqlite3_stmt *st;
    const char *tables[] = {
        "aegis_suricata_rules",
        "aegis_signature_metadata",
        "aegis_domain_categories",
        "aegis_reputation_items",
    };
    size_t i;

    if (!feed)
        return;
    for (i = 0; i < ARRAY_SIZE(tables); i++) {
        char sql[160];

        snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE source_feed=?", tables[i]);
        st = aegisxd_prepare(sql);
        if (!st)
            continue;
        sqlite3_bind_text(st, 1, feed->feed_id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

static void aegisxd_strtrim(char *s)
{
    char *p;
    size_t len;

    if (!s)
        return;
    p = s;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

static int aegisxd_domain_char_ok(int c)
{
    return isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.';
}

static int aegisxd_normalize_domain_token(const char *token, char *out, size_t out_len)
{
    const char *p;
    size_t i = 0;
    int dot = 0;

    if (!token || !out || out_len < 4)
        return 0;
    while (*token == ' ' || *token == '\t')
        token++;
    if (!strncmp(token, "||", 2))
        token += 2;
    while (*token == '*' || *token == '.')
        token++;
    if (!strncmp(token, "http://", 7))
        token += 7;
    else if (!strncmp(token, "https://", 8))
        token += 8;
    p = token;
    while (*p && *p != '/' && *p != '^' && *p != '$' && *p != '#') {
        if (*p == ':' || isspace((unsigned char)*p))
            break;
        if (!aegisxd_domain_char_ok((unsigned char)*p))
            return 0;
        if (*p == '.')
            dot = 1;
        if (i + 1 >= out_len)
            return 0;
        out[i++] = (char)tolower((unsigned char)*p);
        p++;
    }
    while (i > 0 && out[i - 1] == '.')
        i--;
    out[i] = '\0';
    if (!dot || i < 3)
        return 0;
    if (!strcmp(out, "localhost") || !strcmp(out, "localdomain"))
        return 0;
    return 1;
}

static int aegisxd_domain_from_line(char *line, char *out, size_t out_len)
{
    char first[1024] = {0};
    char second[1024] = {0};
    int n;

    if (!line || !out)
        return 0;
    aegisxd_strtrim(line);
    if (!line[0] || line[0] == '#')
        return 0;
    n = sscanf(line, "%1023s %1023s", first, second);
    if (n <= 0)
        return 0;
    if (n >= 2 && (!strcmp(first, "0.0.0.0") || !strcmp(first, "127.0.0.1") ||
                   !strcmp(first, "::1") || !strcmp(first, "255.255.255.255")))
        return aegisxd_normalize_domain_token(second, out, out_len);
    return aegisxd_normalize_domain_token(first, out, out_len);
}

static const char *aegisxd_feed_category_hint(const char *feed_id)
{
    if (!feed_id)
        return "uncategorized";
    if (!strcmp(feed_id, "urlhaus-hostfile"))
        return "malware_c2";
    if (!strcmp(feed_id, "oisd-big"))
        return "ads_trackers_mixed";
    if (!strcmp(feed_id, "stevenblack-hosts"))
        return "ads_trackers_malware";
    if (!strcmp(feed_id, "stevenblack-fakenews-gambling-porn"))
        return "fakenews_gambling_adult";
    return "uncategorized";
}

static int aegisxd_insert_domain_category(sqlite3_stmt *st, const char *domain,
                                          const char *category, const char *source,
                                          int confidence)
{
    sqlite3_int64 now = aegisxd_now_s();
    int rc;

    if (!st || !domain || !domain[0] || !category || !source)
        return -1;
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    sqlite3_bind_text(st, 1, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, confidence);
    sqlite3_bind_int64(st, 5, now);
    sqlite3_bind_int64(st, 6, now);
    rc = sqlite3_step(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int aegisxd_insert_reputation_item(sqlite3_stmt *st, const char *kind,
                                          const char *value, const char *category,
                                          int severity, int confidence,
                                          const char *source)
{
    sqlite3_int64 now = aegisxd_now_s();
    int rc;

    if (!st || !kind || !value || !value[0] || !source)
        return -1;
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, category ? category : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, severity);
    sqlite3_bind_int(st, 5, confidence);
    sqlite3_bind_text(st, 6, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, now);
    sqlite3_bind_int64(st, 8, now);
    rc = sqlite3_step(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int aegisxd_ipv4_public_ok(const unsigned char *a)
{
    if (!a)
        return 0;
    if (a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224)
        return 0;
    if (a[0] == 100 && a[1] >= 64 && a[1] <= 127)
        return 0;
    if (a[0] == 169 && a[1] == 254)
        return 0;
    if (a[0] == 172 && a[1] >= 16 && a[1] <= 31)
        return 0;
    if (a[0] == 192 && a[1] == 168)
        return 0;
    if (a[0] == 192 && a[1] == 0 && a[2] == 0)
        return 0;
    if (a[0] == 192 && a[1] == 0 && a[2] == 2)
        return 0;
    if (a[0] == 198 && (a[1] == 18 || a[1] == 19))
        return 0;
    if (a[0] == 198 && a[1] == 51 && a[2] == 100)
        return 0;
    if (a[0] == 203 && a[1] == 0 && a[2] == 113)
        return 0;
    if (a[0] == 255 && a[1] == 255 && a[2] == 255 && a[3] == 255)
        return 0;
    return 1;
}

static int aegisxd_ipv6_public_ok(const unsigned char *a)
{
    int all_zero = 1;
    size_t i;

    if (!a)
        return 0;
    for (i = 0; i < 16; i++) {
        if (a[i]) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero)
        return 0;
    if (!memcmp(a, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16))
        return 0;
    if (a[0] == 0xff)
        return 0;
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80)
        return 0;
    if ((a[0] & 0xfe) == 0xfc)
        return 0;
    return (a[0] & 0xe0) == 0x20;
}

static int aegisxd_suricata_ip_token_normalize(const char *token, char *out,
                                               size_t out_len, const char **kind_out)
{
    char buf[128];
    char addr[128];
    char *slash;
    unsigned char bin[16];
    long prefix = -1;
    char *end = NULL;
    size_t i = 0;
    int family;

    if (!token || !out || out_len < 8)
        return 0;
    while (*token == ' ' || *token == '\t' || *token == '[' || *token == '(')
        token++;
    if (*token == '!')
        return 0;
    if (!*token || *token == '$' || !strcasecmp(token, "any"))
        return 0;
    while (*token && *token != ',' && *token != ']' && *token != ')' &&
           !isspace((unsigned char)*token) && i + 1 < sizeof(buf)) {
        buf[i++] = *token++;
    }
    while (i > 0 && (buf[i - 1] == ';' || buf[i - 1] == ']'))
        i--;
    buf[i] = '\0';
    if (!buf[0] || strchr(buf, '$') || strchr(buf, '-'))
        return 0;
    snprintf(addr, sizeof(addr), "%s", buf);
    slash = strchr(addr, '/');
    if (slash) {
        *slash++ = '\0';
        if (!*slash)
            return 0;
        prefix = strtol(slash, &end, 10);
        if (!end || *end)
            return 0;
    }
    family = strchr(addr, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(family, addr, bin) != 1)
        return 0;
    if (family == AF_INET) {
        if (!aegisxd_ipv4_public_ok(bin))
            return 0;
        if (prefix >= 0 && (prefix < 24 || prefix > 32))
            return 0;
        /* out_len is only guaranteed to be 8, so a caller buffer too small for
         * the CIDR must fail rather than yield a shortened prefix that would be
         * imported as a different network. */
        if ((size_t)snprintf(out, out_len, "%s%s%s", addr,
                             prefix >= 0 ? "/" : "",
                             prefix >= 0 ? slash : "") >= out_len)
            return 0;
        if (kind_out)
            *kind_out = "ipv4";
        return 1;
    }
    if (!aegisxd_ipv6_public_ok(bin))
        return 0;
    if (prefix >= 0 && (prefix < 48 || prefix > 128))
        return 0;
    if ((size_t)snprintf(out, out_len, "%s%s%s", addr, prefix >= 0 ? "/" : "",
                         prefix >= 0 ? slash : "") >= out_len)
        return 0;
    if (kind_out)
        *kind_out = "ipv6";
    return 1;
}

static int aegisxd_suricata_reputation_severity(int priority, const char *category)
{
    if (priority <= 1)
        return 90;
    if (priority == 2)
        return 75;
    if (priority == 3)
        return 60;
    if (category && (strstr(category, "malware") || strstr(category, "bot") ||
                     strstr(category, "c2") || strstr(category, "exploit")))
        return 80;
    return 60;
}

static int aegisxd_suricata_import_addr_ips(sqlite3_stmt *rep_st, const char *source,
                                            const char *category, int severity,
                                            const char *addr_token)
{
    char tmp[512];
    char *p;
    int inserted = 0;

    if (!rep_st || !source || !addr_token)
        return 0;
    snprintf(tmp, sizeof(tmp), "%s", addr_token);
    p = tmp;
    while (*p) {
        char *next = strchr(p, ',');
        char ip[128];
        const char *kind = NULL;

        if (next)
            *next = '\0';
        if (aegisxd_suricata_ip_token_normalize(p, ip, sizeof(ip), &kind) &&
            aegisxd_insert_reputation_item(rep_st, kind, ip,
                                           category ? category : "suricata",
                                           severity, 70, source) == 0)
            inserted++;
        if (!next)
            break;
        p = next + 1;
    }
    return inserted;
}

static int aegisxd_suricata_import_header_ips(sqlite3_stmt *rep_st, const char *source,
                                              const char *category, int severity,
                                              const char *rule)
{
    char action[32] = "";
    char proto[32] = "";
    char src[512] = "";
    char src_port[128] = "";
    char direction[16] = "";
    char dst[512] = "";
    char dst_port[128] = "";

    if (!rep_st || !rule)
        return 0;
    if (sscanf(rule, "%31s %31s %511s %127s %15s %511s %127s",
               action, proto, src, src_port, direction, dst, dst_port) < 7)
        return 0;
    if (strcmp(direction, "->") && strcmp(direction, "<>"))
        return 0;
    return aegisxd_suricata_import_addr_ips(rep_st, source, category, severity, src) +
           aegisxd_suricata_import_addr_ips(rep_st, source, category, severity, dst);
}

static int aegisxd_import_text_feed(const struct aegisxd_import_feed *feed,
                                    struct aegisxd_import_counts *counts)
{
    FILE *fp;
    char line[4096];
    sqlite3_stmt *domain_st = NULL;
    sqlite3_stmt *rep_st = NULL;
    const char *category;

    if (!feed || !counts)
        return -1;
    fp = fopen(feed->artifact_path, "r");
    if (!fp)
        return -1;
    category = aegisxd_feed_category_hint(feed->feed_id);
    domain_st = aegisxd_prepare(
        "INSERT INTO aegis_domain_categories"
        "(domain,category,source_feed,confidence,first_seen,last_seen) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(domain,category,source_feed) DO UPDATE SET "
        "confidence=CASE WHEN excluded.confidence>confidence THEN excluded.confidence ELSE confidence END,"
        "last_seen=excluded.last_seen");
    rep_st = aegisxd_prepare(
        "INSERT INTO aegis_reputation_items"
        "(kind,value,category,severity,confidence,source_feed,first_seen,last_seen) "
        "VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(kind,value,source_feed) DO UPDATE SET "
        "category=excluded.category,severity=excluded.severity,"
        "confidence=CASE WHEN excluded.confidence>confidence THEN excluded.confidence ELSE confidence END,"
        "last_seen=excluded.last_seen");
    if (!domain_st || !rep_st) {
        if (domain_st)
            sqlite3_finalize(domain_st);
        if (rep_st)
            sqlite3_finalize(rep_st);
        fclose(fp);
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        char domain[512];

        if (!aegisxd_domain_from_line(line, domain, sizeof(domain))) {
            counts->skipped++;
            continue;
        }
        if (aegisxd_insert_domain_category(domain_st, domain, category, feed->feed_id, 60) == 0) {
            counts->imported++;
            if (!strcmp(feed->kind, "reputation_items"))
                aegisxd_insert_reputation_item(rep_st, "domain", domain, category, 80, 80, feed->feed_id);
        } else {
            counts->skipped++;
        }
    }
    sqlite3_finalize(domain_st);
    sqlite3_finalize(rep_st);
    fclose(fp);
    return 0;
}

static int aegisxd_tar_octal(const unsigned char *p, size_t len)
{
    int v = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        if (p[i] == '\0' || p[i] == ' ')
            continue;
        if (p[i] < '0' || p[i] > '7')
            break;
        v = (v << 3) + (p[i] - '0');
    }
    return v;
}

static int aegisxd_gz_read_exact(gzFile gz, void *buf, size_t len)
{
    unsigned char *p = buf;

    while (len > 0) {
        unsigned int chunk = len > 32768 ? 32768 : (unsigned int)len;
        int n = gzread(gz, p, chunk);

        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int aegisxd_tar_skip(gzFile gz, size_t len)
{
    unsigned char buf[4096];

    while (len > 0) {
        size_t chunk = len > sizeof(buf) ? sizeof(buf) : len;

        if (aegisxd_gz_read_exact(gz, buf, chunk) != 0)
            return -1;
        len -= chunk;
    }
    return 0;
}

static int aegisxd_tar_zero_block(const unsigned char *buf)
{
    size_t i;

    for (i = 0; i < 512; i++) {
        if (buf[i])
            return 0;
    }
    return 1;
}

static int aegisxd_suffix(const char *s, const char *suffix)
{
    size_t sl, xl;

    if (!s || !suffix)
        return 0;
    sl = strlen(s);
    xl = strlen(suffix);
    return sl >= xl && !strcmp(s + sl - xl, suffix);
}

static void aegisxd_suricata_category_from_name(const char *name, char *out, size_t out_len)
{
    const char *base = name ? strrchr(name, '/') : NULL;
    char tmp[128];
    char *p;

    if (!out || out_len == 0)
        return;
    base = base ? base + 1 : (name ? name : "");
    snprintf(tmp, sizeof(tmp), "%s", base);
    if (!strncmp(tmp, "emerging-", 9))
        memmove(tmp, tmp + 9, strlen(tmp + 9) + 1);
    p = strstr(tmp, ".rules");
    if (p)
        *p = '\0';
    for (p = tmp; *p; p++) {
        if (*p == '-' || *p == ' ')
            *p = '_';
        else
            *p = (char)tolower((unsigned char)*p);
    }
    snprintf(out, out_len, "%s", tmp[0] ? tmp : "uncategorized");
}

static const char *aegisxd_rule_option_ptr(const char *rule, const char *key)
{
    size_t key_len;
    const char *p;

    if (!rule || !key)
        return NULL;
    key_len = strlen(key);
    for (p = rule; (p = strstr(p, key)) != NULL; p += key_len) {
        if (p > rule && (isalnum((unsigned char)p[-1]) || p[-1] == '_' || p[-1] == '-'))
            continue;
        if (p[key_len] != ':')
            continue;
        p += key_len + 1;
        while (*p == ' ' || *p == '\t')
            p++;
        return p;
    }
    return NULL;
}

static int aegisxd_rule_int_option(const char *rule, const char *key)
{
    const char *p = aegisxd_rule_option_ptr(rule, key);

    if (!p)
        return 0;
    return atoi(p);
}

static void aegisxd_rule_text_option(const char *rule, const char *key,
                                     char *out, size_t out_len)
{
    const char *p;
    size_t i = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    p = aegisxd_rule_option_ptr(rule, key);
    if (!p)
        return;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && i + 1 < out_len)
            out[i++] = *p++;
    } else {
        while (*p && *p != ';' && *p != ')' && !isspace((unsigned char)*p) && i + 1 < out_len)
            out[i++] = *p++;
    }
    out[i] = '\0';
}

static int aegisxd_suricata_insert(sqlite3_stmt *rule_st, sqlite3_stmt *meta_st,
                                   sqlite3_stmt *rep_st,
                                   const char *source, const char *category,
                                   const char *line,
                                   struct aegisxd_import_counts *counts)
{
    char work[8192];
    char *p;
    char action[32] = "";
    char proto[32] = "";
    char msg[512] = "";
    char classtype[128] = "";
    int enabled = 1;
    int sid;
    int rev;
    int severity;
    int rc;

    if (!rule_st || !meta_st || !source || !category || !line)
        return -1;
    snprintf(work, sizeof(work), "%s", line);
    aegisxd_strtrim(work);
    if (!work[0])
        return -1;
    if (work[0] == '#') {
        enabled = 0;
        p = work + 1;
        while (*p == ' ' || *p == '\t')
            p++;
    } else {
        p = work;
    }
    if (strncmp(p, "alert ", 6) && strncmp(p, "drop ", 5) &&
        strncmp(p, "reject ", 7) && strncmp(p, "pass ", 5))
        return -1;
    if (sscanf(p, "%31s %31s", action, proto) < 2)
        return -1;
    sid = aegisxd_rule_int_option(p, "sid");
    if (sid <= 0)
        return -1;
    rev = aegisxd_rule_int_option(p, "rev");
    severity = aegisxd_rule_int_option(p, "priority");
    aegisxd_rule_text_option(p, "msg", msg, sizeof(msg));
    aegisxd_rule_text_option(p, "classtype", classtype, sizeof(classtype));

    sqlite3_reset(rule_st);
    sqlite3_clear_bindings(rule_st);
    sqlite3_bind_int(rule_st, 1, sid);
    sqlite3_bind_int(rule_st, 2, rev);
    sqlite3_bind_text(rule_st, 3, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(rule_st, 4, classtype, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(rule_st, 5, severity);
    sqlite3_bind_text(rule_st, 6, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(rule_st, 7, proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(rule_st, 8, msg, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(rule_st, 9, enabled);
    sqlite3_bind_text(rule_st, 10, p, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(rule_st, 11, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(rule_st, 12, aegisxd_now_s());
    rc = sqlite3_step(rule_st);
    if (rc != SQLITE_DONE)
        return -1;

    sqlite3_reset(meta_st);
    sqlite3_clear_bindings(meta_st);
    sqlite3_bind_int(meta_st, 1, sid);
    sqlite3_bind_text(meta_st, 2, msg, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(meta_st, 3, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(meta_st, 4, aegisxd_now_s());
    sqlite3_step(meta_st);
    if (enabled && rep_st && counts) {
        int rep_severity = aegisxd_suricata_reputation_severity(severity, category);

        counts->derived_ip_reputation +=
            aegisxd_suricata_import_header_ips(rep_st, source, category,
                                               rep_severity, p);
    }
    return 0;
}

static int aegisxd_import_suricata_text(const struct aegisxd_import_feed *feed,
                                        const char *name, char *buf,
                                        struct aegisxd_import_counts *counts)
{
    sqlite3_stmt *rule_st;
    sqlite3_stmt *meta_st;
    sqlite3_stmt *rep_st;
    char category[128];
    char *save = NULL;
    char *line;

    rule_st = aegisxd_prepare(
        "INSERT INTO aegis_suricata_rules"
        "(sid,rev,category,classtype,severity,action,protocol,msg,enabled_default,rule_text,source_feed,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(sid) DO UPDATE SET "
        "rev=excluded.rev,category=excluded.category,classtype=excluded.classtype,"
        "severity=excluded.severity,action=excluded.action,protocol=excluded.protocol,"
        "msg=excluded.msg,enabled_default=excluded.enabled_default,rule_text=excluded.rule_text,"
        "source_feed=excluded.source_feed,updated_at=excluded.updated_at");
    meta_st = aegisxd_prepare(
        "INSERT INTO aegis_signature_metadata(sid,name,source_feed,updated_at) "
        "VALUES(?,?,?,?) "
        "ON CONFLICT(sid) DO UPDATE SET "
        "name=excluded.name,source_feed=excluded.source_feed,updated_at=excluded.updated_at");
    rep_st = aegisxd_prepare(
        "INSERT INTO aegis_reputation_items"
        "(kind,value,category,severity,confidence,source_feed,first_seen,last_seen) "
        "VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(kind,value,source_feed) DO UPDATE SET "
        "category=excluded.category,severity=excluded.severity,"
        "confidence=CASE WHEN excluded.confidence>confidence THEN excluded.confidence ELSE confidence END,"
        "last_seen=excluded.last_seen");
    if (!rule_st || !meta_st || !rep_st) {
        if (rule_st)
            sqlite3_finalize(rule_st);
        if (meta_st)
            sqlite3_finalize(meta_st);
        if (rep_st)
            sqlite3_finalize(rep_st);
        return -1;
    }
    aegisxd_suricata_category_from_name(name, category, sizeof(category));
    for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (aegisxd_suricata_insert(rule_st, meta_st, rep_st, feed->feed_id,
                                    category, line, counts) == 0)
            counts->imported++;
        else
            counts->skipped++;
    }
    sqlite3_finalize(rule_st);
    sqlite3_finalize(meta_st);
    sqlite3_finalize(rep_st);
    return 0;
}

static int aegisxd_import_suricata_tar_gz(const struct aegisxd_import_feed *feed,
                                          struct aegisxd_import_counts *counts)
{
    gzFile gz;
    unsigned char hdr[512];
    int rc = 0;

    if (!feed || !counts)
        return -1;
    gz = gzopen(feed->artifact_path, "rb");
    if (!gz)
        return -1;
    while (aegisxd_gz_read_exact(gz, hdr, sizeof(hdr)) == 0) {
        char name[AEGISXD_MAX_PATH] = "";
        char entry[101] = "";
        char prefix[156] = "";
        int size;
        size_t padded;
        char typeflag;

        if (aegisxd_tar_zero_block(hdr))
            break;
        snprintf(entry, sizeof(entry), "%.*s", 100, (const char *)hdr);
        snprintf(prefix, sizeof(prefix), "%.*s", 155, (const char *)(hdr + 345));
        if (prefix[0])
            snprintf(name, sizeof(name), "%s/%s", prefix, entry);
        else
            snprintf(name, sizeof(name), "%s", entry);
        size = aegisxd_tar_octal(hdr + 124, 12);
        if (size < 0) {
            rc = -1;
            break;
        }
        padded = ((size_t)size + 511U) & ~511U;
        typeflag = (char)hdr[156];
        if ((typeflag == '\0' || typeflag == '0') && size > 0 && aegisxd_suffix(name, ".rules")) {
            char *buf = calloc(1, (size_t)size + 1);

            if (!buf || aegisxd_gz_read_exact(gz, buf, (size_t)size) != 0) {
                free(buf);
                rc = -1;
                break;
            }
            buf[size] = '\0';
            if (aegisxd_import_suricata_text(feed, name, buf, counts) != 0)
                rc = -1;
            free(buf);
            if (rc != 0)
                break;
            if (padded > (size_t)size &&
                aegisxd_tar_skip(gz, padded - (size_t)size) != 0) {
                rc = -1;
                break;
            }
        } else if (aegisxd_tar_skip(gz, padded) != 0) {
            rc = -1;
            break;
        }
    }
    gzclose(gz);
    return rc;
}

static int aegisxd_import_one_loaded(const struct aegisxd_import_feed *feed,
                                     struct aegisxd_import_counts *counts)
{
    if (!feed || !counts || !feed->artifact_path[0])
        return -1;
    memset(counts, 0, sizeof(*counts));
    aegisxd_import_state_begin(feed);
    if (access(feed->artifact_path, R_OK) != 0)
        return -1;
    if (aegisxd_import_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    aegisxd_import_delete_old(feed);
    if (!strcmp(feed->format, "suricata_tar_gz")) {
        if (aegisxd_import_suricata_tar_gz(feed, counts) != 0) {
            aegisxd_import_exec("ROLLBACK");
            return -1;
        }
    } else if (!strcmp(feed->format, "hosts") || !strcmp(feed->format, "domain_list")) {
        if (aegisxd_import_text_feed(feed, counts) != 0) {
            aegisxd_import_exec("ROLLBACK");
            return -1;
        }
    } else {
        aegisxd_import_exec("ROLLBACK");
        return -1;
    }
    if (aegisxd_import_exec("COMMIT") != 0)
        return -1;
    return 0;
}

struct json_object *aegisxd_import_feed_id(const char *feed_id)
{
    struct json_object *result = json_object_new_object();
    struct json_object *meta = json_object_new_object();
    struct aegisxd_import_feed feed;
    struct aegisxd_import_counts counts;
    int ok;

    aegisxd_json_add_string(result, "feed_id", feed_id ? feed_id : "");
    if (aegisxd_import_feed_load(feed_id, &feed) != 0) {
        json_object_object_add(result, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(result, "error", "feed_artifact_unavailable");
        json_object_put(meta);
        return result;
    }
    json_object_object_add(meta, "dataplane_changed", json_object_new_boolean(0));
    aegisxd_json_add_string(meta, "format", feed.format);
    ok = aegisxd_import_one_loaded(&feed, &counts) == 0;
    json_object_object_add(result, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(result, "kind", feed.kind);
    aegisxd_json_add_string(result, "format", feed.format);
    aegisxd_json_add_string(result, "artifact_path", feed.artifact_path);
    aegisxd_json_add_string(result, "sha256", feed.sha256);
    json_object_object_add(result, "imported_count", json_object_new_int(counts.imported));
    json_object_object_add(result, "skipped_count", json_object_new_int(counts.skipped));
    json_object_object_add(result, "derived_ip_reputation_count",
                           json_object_new_int(counts.derived_ip_reputation));
    json_object_object_add(meta, "derived_ip_reputation_count",
                           json_object_new_int(counts.derived_ip_reputation));
    json_object_object_add(result, "dataplane_changed", json_object_new_boolean(0));
    if (ok) {
        aegisxd_import_state_finish(&feed, "done", "", counts.imported, counts.skipped, meta);
    } else {
        aegisxd_json_add_string(result, "error", "import_failed");
        aegisxd_import_state_finish(&feed, "error", "import_failed",
                                    counts.imported, counts.skipped, meta);
    }
    json_object_put(meta);
    return result;
}

static struct json_object *aegisxd_feed_import_run(struct json_object *body);

int aegisxd_feed_import_worker_main(const char *job_id, const char *feed_id)
{
    struct json_object *body;
    struct json_object *result;
    int ok;

    if (aegisxd_db_init() != 0) {
        result = aegisxd_error("db_init_failed",
                               "failed to initialize aegis database in import worker");
    } else {
        body = json_object_new_object();
        if (feed_id && feed_id[0])
            aegisxd_json_add_string(body, "feed_id", feed_id);
        result = aegisxd_feed_import_run(body);
        json_object_put(body);
    }
    ok = aegisxd_job_result_ok(result);
    aegisxd_job_record_finish(job_id, result);
    json_object_put(result);
    aegisxd_db_close();
    return ok ? 0 : 1;
}

struct json_object *aegisxd_feed_import_start(struct json_object *body)
{
    const char *req_feed_id = aegisxd_json_str(body, "feed_id", "");
    int background = aegisxd_json_bool(body, "background",
                       aegisxd_json_bool(body, "async", 1));
    char job_id[128];
    pid_t pid;

    if (!background)
        return aegisxd_feed_import_run(body);
    if (aegisxd_job_running_count() > 0) {
        struct json_object *busy = aegisxd_error("job_already_running",
            "another aegis feed job is already running");

        aegisxd_json_add_string(busy, "state", "running");
        json_object_object_add(busy, "running", json_object_new_boolean(1));
        json_object_object_add(busy, "jobs", aegisxd_feed_jobs_json(NULL));
        return busy;
    }
    snprintf(job_id, sizeof(job_id), "feed-import-%lld-%ld",
             (long long)aegisxd_now_s(), (long)getpid());
    if (aegisxd_job_record_start(job_id, "feed_import", req_feed_id, 0) != 0)
        return aegisxd_error("job_record_failed", "failed to record aegis feed job");
    pid = fork();
    if (pid < 0) {
        struct json_object *err = aegisxd_error("fork_failed",
                                                "failed to start feed import worker");

        aegisxd_job_record_finish(job_id, err);
        return err;
    }
    if (pid == 0) {
        execl("/usr/bin/dreamingwrt-aegisxd", "dreamingwrt-aegisxd",
              "--feed-import-worker", job_id, req_feed_id ? req_feed_id : "",
              (char *)NULL);
        _exit(127);
    }
    aegisxd_job_record_pid(job_id, pid);
    {
        struct json_object *resp = json_object_new_object();

        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
        aegisxd_json_add_string(resp, "state", "running");
        json_object_object_add(resp, "running", json_object_new_boolean(1));
        json_object_object_add(resp, "background", json_object_new_boolean(1));
        aegisxd_json_add_string(resp, "job_id", job_id);
        aegisxd_json_add_string(resp, "op", "feed_import");
        aegisxd_json_add_string(resp, "feed_id", req_feed_id);
        json_object_object_add(resp, "pid", json_object_new_int((int)pid));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        return resp;
    }
}

static struct json_object *aegisxd_feed_import_run(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *results = json_object_new_array();
    const char *feed_id = aegisxd_json_str(body, "feed_id", "");
    int ok_count = 0;
    int fail_count = 0;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "state", "done");
    json_object_object_add(resp, "running", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    if (feed_id && feed_id[0]) {
        struct json_object *r = aegisxd_import_feed_id(feed_id);
        struct json_object *okv = NULL;

        if (json_object_object_get_ex(r, "ok", &okv) && json_object_get_boolean(okv))
            ok_count++;
        else
            fail_count++;
        json_object_array_add(results, r);
    } else {
        struct json_object *ids = aegisxd_import_feed_ids_json();
        int n = json_object_array_length(ids);
        int i;

        for (i = 0; i < n; i++) {
            const char *id = json_object_get_string(json_object_array_get_idx(ids, i));
            struct json_object *r = aegisxd_import_feed_id(id);
            struct json_object *okv = NULL;

            if (json_object_object_get_ex(r, "ok", &okv) && json_object_get_boolean(okv))
                ok_count++;
            else
                fail_count++;
            json_object_array_add(results, r);
        }
        json_object_put(ids);
    }
    json_object_object_add(resp, "ok_count", json_object_new_int(ok_count));
    json_object_object_add(resp, "fail_count", json_object_new_int(fail_count));
    json_object_object_add(resp, "results", results);
    if (fail_count > 0)
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
    return resp;
}

static int aegisxd_count_table(const char *table)
{
    sqlite3_stmt *st;
    char sql[128];
    int n = 0;

    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table ? table : "");
    st = aegisxd_prepare(sql);
    if (!st)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

struct json_object *aegisxd_feed_import_status_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *imports = json_object_new_array();
    struct json_object *counts = json_object_new_object();
    sqlite3_stmt *st;

    st = aegisxd_prepare(
        "SELECT feed_id,state,last_started_at,last_finished_at,last_error,imported_count,skipped_count,artifact_sha256 "
        "FROM aegis_import_state ORDER BY feed_id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();

            aegisxd_json_add_string(o, "feed_id", aegisxd_sqlite_text(st, 0, ""));
            aegisxd_json_add_string(o, "state", aegisxd_sqlite_text(st, 1, ""));
            json_object_object_add(o, "last_started_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(o, "last_finished_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
            aegisxd_json_add_string(o, "last_error", aegisxd_sqlite_text(st, 4, ""));
            json_object_object_add(o, "imported_count", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_object_add(o, "skipped_count", json_object_new_int(sqlite3_column_int(st, 6)));
            aegisxd_json_add_string(o, "artifact_sha256", aegisxd_sqlite_text(st, 7, ""));
            json_object_array_add(imports, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(counts, "suricata_rules",
                           json_object_new_int(aegisxd_count_table("aegis_suricata_rules")));
    json_object_object_add(counts, "signature_metadata",
                           json_object_new_int(aegisxd_count_table("aegis_signature_metadata")));
    json_object_object_add(counts, "domain_categories",
                           json_object_new_int(aegisxd_count_table("aegis_domain_categories")));
    json_object_object_add(counts, "reputation_items",
                           json_object_new_int(aegisxd_count_table("aegis_reputation_items")));
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "state", "idle");
    json_object_object_add(resp, "running", json_object_new_boolean(0));
    json_object_object_add(resp, "counts", counts);
    json_object_object_add(resp, "imports", imports);
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    return resp;
}
