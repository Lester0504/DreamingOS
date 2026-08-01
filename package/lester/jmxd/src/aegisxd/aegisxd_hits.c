// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

#include <fcntl.h>

#include "jmx_exec.h"

#define AEGISXD_HIT_TICK_MS 1000
#define AEGISXD_HIT_READ_BUDGET 65536
#define AEGISXD_HIT_MAX_LINE 2048
#define AEGISXD_HIT_DEDUPE_S 30
#define AEGISXD_HIT_LOG_MAX_BYTES (512 * 1024)
#define AEGISXD_SURICATA_EVE_MAX_BYTES (4 * 1024 * 1024)
#define AEGISXD_HIT_EVENT_RETENTION_DAYS 14
#define AEGISXD_HIT_EVENT_MAX_ROWS 20000
#define AEGISXD_NFT_HIT_POLL_S 5
#define AEGISXD_REPUTATION_FLOW_POLL_S 30
#define AEGISXD_REPUTATION_FLOW_MAX_SCAN 3000
#define AEGISXD_REPUTATION_FLOW_MAX_EVENTS_PER_POLL 32
#define AEGISXD_REPUTATION_FLOW_DEDUPE_S 600
#define AEGISXD_POLICY_HIT_POLL_S 10
#define AEGISXD_NFT_TABLE "dreamingwrt_aegis"
#define AEGISXD_NFT_ACTIVE_FILE AEGISXD_RUNTIME_DIR "/nft-active.json"
#define AEGISXD_POLICY_DB_PATH "/etc/dreamingwrt/dreamingwrt.db"
#define AEGISXD_POLICY_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define AEGISXD_POLICY_FLOW_DB_PATH "/etc/dreamingwrt/flow.db"
#define AEGISXD_POLICY_ROUTE_DB_PATH "/var/lib/dreamingwrt/network_state.db"

struct aegisxd_dns_query_seen {
    char serial[32];
    char domain[256];
    char source_ip[64];
    char source_mac[32];
    char in_interface[32];
    char client_lookup_source[32];
    char qtype[16];
    int64_t ts;
};

struct aegisxd_nft_counter_seen {
    char rule_id[96];
    char rule_name[160];
    uint64_t packets;
    uint64_t bytes;
    int initialized;
};

struct aegisxd_policy_counter_row {
    char rule_id[96];
    char rule_name[160];
    char action[32];
    char target[96];
    int64_t hit_count;
    int64_t last_hit;
    int64_t updated_at;
};

struct aegisxd_reputation_flow_seen {
    char key[256];
    int64_t ts;
};

struct aegisxd_conntrack_tuple {
    char proto[16];
    char src[80];
    char dst[80];
    int sport;
    int dport;
    int64_t orig_packets;
    int64_t orig_bytes;
    int64_t reply_packets;
    int64_t reply_bytes;
};

struct aegisxd_reputation_match {
    char category[128];
    char source_feed[128];
    int severity;
    int confidence;
};

static struct uloop_timeout g_hit_timer;
static int g_hit_started;
static off_t g_hit_offset;
static dev_t g_hit_device;
static ino_t g_hit_inode;
static int g_hit_file_initialized;
static char g_hit_partial[AEGISXD_HIT_MAX_LINE];
static int g_hit_partial_len;
static int g_hit_partial_dropping;
static struct aegisxd_dns_query_seen g_seen[128];
static int g_seen_pos;
static int64_t g_last_event_at;
static int64_t g_last_prune_at;
static int g_last_event_id;
static int g_events_inserted;
static int g_events_aggregated;
static int g_events_unattributed;
static int g_lines_scanned;
static struct aegisxd_nft_counter_seen g_nft_seen[8];
static int64_t g_nft_last_poll_at;
static int64_t g_nft_last_event_at;
static int g_nft_last_event_id;
static int g_nft_events_inserted;
static int g_nft_counters_seen;
static int g_nft_table_present;
static char g_nft_last_error[96] = "not_polled";
static int64_t g_reputation_flow_last_poll_at;
static int64_t g_reputation_flow_last_event_at;
static int g_reputation_flow_last_event_id;
static int g_reputation_flow_events_inserted;
static int g_reputation_flow_flows_scanned;
static int g_reputation_flow_matches_seen;
static int g_reputation_flow_feed_ips;
static char g_reputation_flow_last_error[128] = "not_polled";
static struct aegisxd_reputation_flow_seen g_reputation_flow_seen[256];
static int g_reputation_flow_seen_pos;
static off_t g_suricata_offset;
static time_t g_suricata_inode_mtime;
static int64_t g_suricata_last_event_at;
static int64_t g_suricata_last_poll_at;
static int g_suricata_last_event_id;
static int g_suricata_events_inserted;
static int g_suricata_lines_scanned;
static int g_suricata_alerts_seen;
static int g_suricata_manual_ingest_events;
static int64_t g_suricata_last_manual_ingest_at;
static char g_suricata_last_error[96] = "not_polled";
static int64_t g_policy_last_poll_at;
static int64_t g_policy_last_event_at;
static int g_policy_last_event_id;
static int g_policy_events_inserted;
static int g_policy_samples_seen;
static int g_policy_verified_samples_seen;

static void aegisxd_hits_follow_from_eof(void)
{
    struct stat st;

    g_hit_partial_len = 0;
    g_hit_partial_dropping = 0;
    if (stat(AEGISXD_DNSMASQ_LOG_PATH, &st) == 0 && S_ISREG(st.st_mode)) {
        g_hit_offset = st.st_size;
        g_hit_device = st.st_dev;
        g_hit_inode = st.st_ino;
    } else {
        g_hit_offset = 0;
        g_hit_device = 0;
        g_hit_inode = 0;
    }
    g_hit_file_initialized = 1;
}
static int g_policy_rules_seen;
static int g_policy_sources_seen;
static int g_policy_baselined;
static int g_policy_route_decision_samples_seen;
static int g_policy_route_decision_samples_imported;
static int g_policy_route_decision_samples_skipped;
static int g_policy_route_decision_candidate_seen;
static char g_policy_last_error[128] = "not_polled";

static void aegisxd_hit_tick(struct uloop_timeout *t);

static int aegisxd_active_state_present(void)
{
    return access(AEGISXD_RUNTIME_DIR "/active.json", F_OK) == 0;
}

static int aegisxd_dns_log_present(void)
{
    return access(AEGISXD_DNSMASQ_LOG_PATH, R_OK) == 0;
}

static int aegisxd_nft_active_state_present(void)
{
    return access(AEGISXD_NFT_ACTIVE_FILE, F_OK) == 0;
}

static int aegisxd_suricata_active_state_present(void)
{
    return access(AEGISXD_SURICATA_ACTIVE_PATH, F_OK) == 0;
}

static int aegisxd_suricata_eve_present(void)
{
    return access(AEGISXD_SURICATA_EVE_PATH, R_OK) == 0;
}

static int aegisxd_suricata_pid_running(void)
{
    FILE *fp;
    long pid = 0;

    fp = fopen(AEGISXD_SURICATA_PID_PATH, "r");
    if (!fp)
        return 0;
    if (fscanf(fp, "%ld", &pid) != 1)
        pid = 0;
    fclose(fp);
    if (pid <= 1)
        return 0;
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

int aegisxd_dns_hit_producer_active(void)
{
    return g_hit_started && aegisxd_active_state_present();
}

int aegisxd_nft_hit_producer_active(void)
{
    return g_hit_started && g_nft_table_present && aegisxd_nft_active_state_present();
}

static int aegisxd_reputation_flow_producer_active(void)
{
    return g_hit_started && g_reputation_flow_feed_ips > 0 &&
        g_reputation_flow_flows_scanned > 0;
}

int aegisxd_suricata_hit_producer_active(void)
{
    return g_hit_started && aegisxd_suricata_active_state_present() &&
        aegisxd_suricata_eve_present() && aegisxd_suricata_pid_running();
}

int aegisxd_policy_hit_producer_active(void)
{
    return g_hit_started && g_policy_sources_seen > 0 && g_policy_verified_samples_seen > 0;
}

int aegisxd_policy_hit_producer_connected(void)
{
    return g_hit_started && g_policy_sources_seen > 0;
}

static void aegisxd_hits_trim_domain(char *s)
{
    size_t n;

    if (!s)
        return;
    while (*s && isspace((unsigned char)*s))
        memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && (isspace((unsigned char)s[n - 1]) || s[n - 1] == '.'))
        s[--n] = '\0';
}

static int aegisxd_hits_domain_ok(const char *s)
{
    int dot = 0;

    if (!s || !s[0] || strlen(s) > 253)
        return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;

        if (c == '.') {
            dot = 1;
            continue;
        }
        if (isalnum(c) || c == '-' || c == '_')
            continue;
        return 0;
    }
    return dot;
}

static int aegisxd_hits_mac_ok(const char *mac)
{
    int hex = 0;
    int colon = 0;
    int nonzero = 0;

    if (!mac || strlen(mac) != 17)
        return 0;
    for (int i = 0; mac[i]; i++) {
        unsigned char c = (unsigned char)mac[i];

        if ((i + 1) % 3 == 0) {
            if (c != ':')
                return 0;
            colon++;
            continue;
        }
        if (!isxdigit(c))
            return 0;
        if (c != '0')
            nonzero = 1;
        hex++;
    }
    return hex == 12 && colon == 5 && nonzero;
}

static int aegisxd_hits_source_ip_safe(const char *ip)
{
    if (!ip || !ip[0] || strlen(ip) > 96)
        return 0;
    for (const char *p = ip; *p; p++) {
        unsigned char c = (unsigned char)*p;

        if (isalnum(c) || c == '.' || c == ':' || c == '%' || c == '_' || c == '-')
            continue;
        return 0;
    }
    return 1;
}

static int aegisxd_hits_lookup_arp(const char *ip, char *mac, size_t mac_len,
                                   char *ifname, size_t ifname_len)
{
    FILE *fp;
    char line[256];

    if (!ip || !ip[0] || strchr(ip, ':'))
        return 0;
    fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return 0;
    (void)fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        char aip[64] = "";
        char hwtype[32] = "";
        char flags_s[32] = "";
        char hwaddr[64] = "";
        char mask[64] = "";
        char dev[64] = "";
        char *end = NULL;
        long flags;

        if (sscanf(line, "%63s %31s %31s %63s %63s %63s",
                   aip, hwtype, flags_s, hwaddr, mask, dev) != 6)
            continue;
        if (strcmp(aip, ip))
            continue;
        flags = strtol(flags_s, &end, 0);
        if (!end || end == flags_s || !(flags & 0x2))
            continue;
        if (!aegisxd_hits_mac_ok(hwaddr))
            continue;
        snprintf(mac, mac_len, "%s", hwaddr);
        snprintf(ifname, ifname_len, "%s", dev);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

/*
 * U-15: aegisxd used to reach external tools through popen(), so an operator
 * or feed supplied address landed in a root shell command line. These helpers
 * run fixed argv with a hard output and time budget, and treat timeout,
 * truncation, signals and non-zero exits as failure instead of empty output.
 */
#define AEGISXD_EXEC_TIMEOUT_MS 5000
#define AEGISXD_EXEC_IP_OUTPUT_MAX (64U * 1024U)
#define AEGISXD_EXEC_NFT_OUTPUT_MAX (256U * 1024U)
#define AEGISXD_IP_PATH "/sbin/ip"
#define AEGISXD_NFT_PATH "/usr/sbin/nft"

/*
 * A budget above the primitive ceiling is rejected by jmx_exec_capture()
 * before the fork, so the caller would fail every single time instead of
 * capturing anything. Keep that a build error, not a silent dead path.
 */
_Static_assert(AEGISXD_EXEC_IP_OUTPUT_MAX <= JMX_EXEC_OUTPUT_LIMIT_MAX,
               "aegisxd ip capture budget exceeds jmx_exec ceiling");
_Static_assert(AEGISXD_EXEC_NFT_OUTPUT_MAX <= JMX_EXEC_OUTPUT_LIMIT_MAX,
               "aegisxd nft capture budget exceeds jmx_exec ceiling");

static int aegisxd_exec_capture_text(const char *path, char *const argv[],
                                     size_t output_limit, char **out)
{
    struct jmx_exec_result result;

    if (!out)
        return -1;
    *out = NULL;
    if (jmx_exec_capture(path, argv, output_limit, AEGISXD_EXEC_TIMEOUT_MS,
                         &result) != 0)
        return -1;
    if (result.timed_out || result.truncated || result.term_signal != 0 ||
        result.exit_code != 0 || !result.output) {
        jmx_exec_result_free(&result);
        return -1;
    }
    *out = result.output;
    result.output = NULL;
    jmx_exec_result_free(&result);
    return 0;
}

/*
 * Same bounded contract, but a non-zero exit is reported to the caller instead
 * of being folded into a generic failure. "nft list table" exits non-zero when
 * the table simply does not exist, which is a normal disabled state and must
 * stay distinguishable from a broken or hung nft.
 */
static int aegisxd_exec_capture_text_allow_exit(const char *path,
                                                char *const argv[],
                                                size_t output_limit,
                                                char **out)
{
    struct jmx_exec_result result;

    if (!out)
        return -1;
    *out = NULL;
    if (jmx_exec_capture(path, argv, output_limit, AEGISXD_EXEC_TIMEOUT_MS,
                         &result) != 0)
        return -1;
    if (result.timed_out || result.truncated || result.term_signal != 0 ||
        !result.output) {
        jmx_exec_result_free(&result);
        return -1;
    }
    *out = result.output;
    result.output = NULL;
    jmx_exec_result_free(&result);
    return 0;
}

static int aegisxd_hits_lookup_ip_neigh(const char *ip, char *mac, size_t mac_len,
                                        char *ifname, size_t ifname_len)
{
    char *argv[] = { (char *)AEGISXD_IP_PATH, "neigh", "show", "to",
                     (char *)ip, NULL };
    char *output = NULL;
    char *line;
    char *line_save = NULL;
    int rc = 0;

    if (!aegisxd_hits_source_ip_safe(ip))
        return 0;
    if (aegisxd_exec_capture_text(AEGISXD_IP_PATH, argv,
                                  AEGISXD_EXEC_IP_OUTPUT_MAX, &output) != 0)
        return 0;
    for (line = strtok_r(output, "\r\n", &line_save); line;
         line = strtok_r(NULL, "\r\n", &line_save)) {
        char work[512];
        char *save = NULL;
        char *tok;
        char found_mac[32] = "";
        char found_if[32] = "";

        snprintf(work, sizeof(work), "%s", line);
        tok = strtok_r(work, " \t\r\n", &save);
        while (tok) {
            if (!strcmp(tok, "dev")) {
                tok = strtok_r(NULL, " \t\r\n", &save);
                if (tok)
                    snprintf(found_if, sizeof(found_if), "%s", tok);
            } else if (!strcmp(tok, "lladdr")) {
                tok = strtok_r(NULL, " \t\r\n", &save);
                if (tok && aegisxd_hits_mac_ok(tok))
                    snprintf(found_mac, sizeof(found_mac), "%s", tok);
            }
            tok = strtok_r(NULL, " \t\r\n", &save);
        }
        if (found_mac[0]) {
            snprintf(mac, mac_len, "%s", found_mac);
            snprintf(ifname, ifname_len, "%s", found_if);
            rc = 1;
            break;
        }
    }
    free(output);
    return rc;
}

static int aegisxd_hits_lookup_client_identity(const char *source_ip,
                                               char *source_mac,
                                               size_t source_mac_len,
                                               char *in_interface,
                                               size_t in_interface_len,
                                               char *lookup_source,
                                               size_t lookup_source_len)
{
    if (source_mac && source_mac_len)
        source_mac[0] = '\0';
    if (in_interface && in_interface_len)
        in_interface[0] = '\0';
    if (lookup_source && lookup_source_len)
        lookup_source[0] = '\0';
    if (!source_ip || !source_ip[0])
        return 0;
    if (!strchr(source_ip, ':') &&
        aegisxd_hits_lookup_arp(source_ip, source_mac, source_mac_len,
                                in_interface, in_interface_len)) {
        snprintf(lookup_source, lookup_source_len, "%s", "arp_cache");
        return 1;
    }
    if (aegisxd_hits_lookup_ip_neigh(source_ip, source_mac, source_mac_len,
                                     in_interface, in_interface_len)) {
        snprintf(lookup_source, lookup_source_len, "%s", "ip_neigh");
        return 1;
    }
    snprintf(lookup_source, lookup_source_len, "%s", "neighbor_not_found");
    return 0;
}

static int aegisxd_hits_domain_lookup(const char *domain, char *category,
                                      size_t category_len, char *source_feed,
                                      size_t source_feed_len, int *severity,
                                      int *confidence)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (category && category_len)
        category[0] = 0;
    if (source_feed && source_feed_len)
        source_feed[0] = 0;
    if (severity)
        *severity = 0;
    if (confidence)
        *confidence = 50;
    if (!domain || !domain[0])
        return 0;

    st = aegisxd_prepare(
        "SELECT category,source_feed,severity,confidence FROM ("
        " SELECT category,source_feed,100 AS severity,confidence FROM aegis_domain_categories WHERE domain=?1"
        " UNION ALL "
        " SELECT category,source_feed,severity,confidence FROM aegis_reputation_items WHERE kind='domain' AND value=?1"
        ") ORDER BY severity DESC,confidence DESC,source_feed LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, domain, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(category, category_len, "%s", aegisxd_sqlite_text(st, 0, "domain_blocklist"));
        snprintf(source_feed, source_feed_len, "%s", aegisxd_sqlite_text(st, 1, ""));
        if (severity)
            *severity = sqlite3_column_int(st, 2);
        if (confidence)
            *confidence = sqlite3_column_int(st, 3);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static int aegisxd_reputation_ip_lookup(const char *ip,
                                        struct aegisxd_reputation_match *match)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (match)
        memset(match, 0, sizeof(*match));
    if (!ip || !ip[0])
        return 0;
    st = aegisxd_prepare(
        "SELECT category,source_feed,severity,confidence "
        "FROM aegis_reputation_items "
        "WHERE (kind='ip' OR kind='ipv4' OR kind='ipv6') AND value=?1 "
        "ORDER BY severity DESC,confidence DESC,source_feed LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, ip, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (match) {
            snprintf(match->category, sizeof(match->category), "%s",
                     aegisxd_sqlite_text(st, 0, "ip_reputation"));
            snprintf(match->source_feed, sizeof(match->source_feed), "%s",
                     aegisxd_sqlite_text(st, 1, ""));
            match->severity = sqlite3_column_int(st, 2);
            match->confidence = sqlite3_column_int(st, 3);
        }
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static const char *aegisxd_hits_risk_from_category(const char *category, int severity)
{
    if (severity >= 80)
        return "high";
    if (severity >= 50)
        return "medium";
    if (category && (strstr(category, "malware") || strstr(category, "c2") ||
                     strstr(category, "phishing") || strstr(category, "threat")))
        return "high";
    if (category && (strstr(category, "ads") || strstr(category, "tracking")))
        return "medium";
    return "medium";
}

static void aegisxd_hits_prune_if_needed(int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (g_last_prune_at > 0 && now - g_last_prune_at < 3600)
        return;
    g_last_prune_at = now;
    st = aegisxd_prepare("DELETE FROM aegis_events WHERE ts<?");
    if (st) {
        sqlite3_bind_int64(st, 1, now - (int64_t)AEGISXD_HIT_EVENT_RETENTION_DAYS * 86400);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    st = aegisxd_prepare(
        "DELETE FROM aegis_events WHERE id IN ("
        "SELECT id FROM aegis_events ORDER BY ts DESC,id DESC LIMIT -1 OFFSET ?1)");
    if (st) {
        sqlite3_bind_int(st, 1, AEGISXD_HIT_EVENT_MAX_ROWS);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

static int aegisxd_hits_insert_dns_event(const char *domain, const char *source_ip,
                                         const char *source_mac,
                                         const char *in_interface,
                                         const char *client_lookup_source,
                                         const char *qtype, int monitor)
{
    sqlite3_stmt *st = NULL;
    struct json_object *meta = NULL;
    char category[128] = "";
    char source_feed[128] = "";
    char lookup_mac[32] = "";
    char lookup_if[32] = "";
    char lookup_source[32] = "";
    char rule_kind[32] = "";
    char rule_source_id[64] = "";
    char matched_rule[254] = "";
    char artifact_sha256[65] = "";
    int severity = 0;
    int confidence = 50;
    int is_pcdn = 0;
    int aggregated = 0;
    const char *risk;
    const char *event_type;
    const char *policy_id;
    const char *policy_name;
    const char *event_source;
    const char *reason;
    const char *meta_s;
    const char *event_source_mac = source_mac ? source_mac : "";
    const char *event_in_interface = in_interface ? in_interface : "";
    const char *event_lookup_source = client_lookup_source ? client_lookup_source : "";
    int64_t now = aegisxd_now_s();
    int rc = -1;

    if (!domain || !domain[0])
        return -1;
    if (monitor) {
        is_pcdn = aegisxd_pcdn_installed_monitor_match(domain, matched_rule,
                                                        artifact_sha256);
        if (!is_pcdn)
            return 0;
        snprintf(rule_kind, sizeof(rule_kind), "%s", "pcdn_monitor");
        snprintf(rule_source_id, sizeof(rule_source_id), "%s", "openhosts-pcdn");
    } else {
        if (!aegisxd_content_installed_dns_rule_match(domain, rule_kind,
                rule_source_id, matched_rule)) {
            g_events_unattributed++;
            return 0;
        }
        is_pcdn = !strcmp(rule_kind, "pcdn") &&
            aegisxd_pcdn_installed_domain_match(domain, artifact_sha256);
        if (!strcmp(rule_kind, "pcdn") && !is_pcdn) {
            g_events_unattributed++;
            return 0;
        }
    }
    event_type = monitor ? "pcdn_dns_observed" :
        (is_pcdn ? "pcdn_dns_block" : "dns_filter_block");
    policy_id = is_pcdn ? "pcdn" : "dns_filter";
    policy_name = is_pcdn ? "PCDN Filter" : "DNS Filter";
    event_source = is_pcdn ? "aegisxd.pcdn" : "aegisxd.dns_filter";
    reason = monitor ? "pcdn_dnsmasq_query_observed" :
        (is_pcdn ? "pcdn_dnsmasq_sinkhole" : "dnsmasq_address_sinkhole");
    if ((!event_source_mac[0] || !event_in_interface[0]) && source_ip && source_ip[0]) {
        (void)aegisxd_hits_lookup_client_identity(source_ip,
            lookup_mac, sizeof(lookup_mac), lookup_if, sizeof(lookup_if),
            lookup_source, sizeof(lookup_source));
        if (!event_source_mac[0])
            event_source_mac = lookup_mac;
        if (!event_in_interface[0])
            event_in_interface = lookup_if;
        if (!event_lookup_source[0])
            event_lookup_source = lookup_source;
    }
    aegisxd_hits_domain_lookup(domain, category, sizeof(category),
                               source_feed, sizeof(source_feed),
                               &severity, &confidence);
    if (!category[0])
        snprintf(category, sizeof(category), "%s", "domain_blocklist");
    risk = aegisxd_hits_risk_from_category(category, severity);
    meta = json_object_new_object();
    aegisxd_json_add_string(meta, "feed", source_feed);
    aegisxd_json_add_string(meta, "source_feed", source_feed);
    aegisxd_json_add_string(meta, "rule_source", monitor ?
                            "dnsmasq_query_monitor" : "dnsmasq_address_blocklist");
    aegisxd_json_add_string(meta, "dns_rule_kind", rule_kind);
    aegisxd_json_add_string(meta, "source_id", rule_source_id);
    aegisxd_json_add_string(meta, "matched_rule", matched_rule);
    aegisxd_json_add_string(meta, "effective_source", is_pcdn ? "pcdn" : rule_kind);
    aegisxd_json_add_string(meta, "artifact_sha256", artifact_sha256);
    aegisxd_json_add_string(meta, "attribution_precision", monitor ?
                            "verified_pcdn_artifact_longest_suffix" :
                            "installed_dnsmasq_provenance_longest_suffix");
    aegisxd_json_add_string(meta, "pcdn_mode", monitor ? "monitor" : "block");
    json_object_object_add(meta, "pcdn_match", json_object_new_boolean(is_pcdn));
    aegisxd_json_add_string(meta, "qtype", qtype ? qtype : "");
    aegisxd_json_add_string(meta, "dnsmasq_query_source_ip", source_ip ? source_ip : "");
    aegisxd_json_add_string(meta, "client_lookup_source", event_lookup_source);
    json_object_object_add(meta, "client_identity_found",
                           json_object_new_boolean(event_source_mac && event_source_mac[0]));
    json_object_object_add(meta, "severity", json_object_new_int(severity));
    json_object_object_add(meta, "confidence", json_object_new_int(confidence));
    meta_s = json_object_to_json_string(meta);

    st = aegisxd_prepare(
        "UPDATE aegis_events SET ts=?1,last_seen=?1,"
        "occurrence_count=occurrence_count+1,"
        "source_mac=CASE WHEN ?2<>'' THEN ?2 ELSE source_mac END,"
        "in_interface=CASE WHEN ?3<>'' THEN ?3 ELSE in_interface END,meta_json=?4 "
        "WHERE id=(SELECT id FROM aegis_events WHERE event_type=?5 AND policy_id=?6 "
        "AND policy_type='dns_filter' AND source=?7 AND destination_host=?8 "
        "AND source_ip=?9 AND last_seen>=?10 ORDER BY id DESC LIMIT 1)");
    if (!st)
        goto out;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, event_source_mac ? event_source_mac : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, event_in_interface ? event_in_interface : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, policy_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, event_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, source_ip ? source_ip : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, now - AEGISXD_HIT_DEDUPE_S);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto out;
    aggregated = sqlite3_changes(g_aegisxd_db) > 0;
    sqlite3_finalize(st);
    st = NULL;
    if (aggregated) {
        st = aegisxd_prepare(
            "SELECT id FROM aegis_events WHERE event_type=?1 AND policy_id=?2 "
            "AND policy_type='dns_filter' AND source=?3 AND destination_host=?4 AND source_ip=?5 "
            "ORDER BY last_seen DESC,id DESC LIMIT 1");
        if (st) {
            sqlite3_bind_text(st, 1, event_type, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, policy_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, event_source, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, domain, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, source_ip ? source_ip : "", -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW)
                g_last_event_id = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
            st = NULL;
        }
        g_last_event_at = now;
        g_events_aggregated++;
        rc = 0;
        goto out;
    }

    st = aegisxd_prepare(
        "INSERT INTO aegis_events("
        "ts,event_type,level,action,policy_id,policy_name,policy_type,rule_id,rule_name,"
        "risk,risk_category,source_ip,source_mac,destination_host,destination_port,protocol,"
        "in_interface,reason,source,occurrence_count,first_seen,last_seen,meta_json"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,"
        "?16,?17,?18,?19,1,?20,?21,?22)");
    if (!st)
        goto out;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, monitor ? "info" : "warning", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, monitor ? "monitor" : "block", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, policy_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, policy_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, "dns_filter", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, risk, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 11, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, source_ip ? source_ip : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, event_source_mac ? event_source_mac : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 14, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 15, 53);
    sqlite3_bind_text(st, 16, "dns", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 17, event_in_interface ? event_in_interface : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 18, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 19, event_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 20, now);
    sqlite3_bind_int64(st, 21, now);
    sqlite3_bind_text(st, 22, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE) {
        rc = 0;
        g_last_event_id = (int)sqlite3_last_insert_rowid(g_aegisxd_db);
        g_last_event_at = now;
        g_events_inserted++;
        aegisxd_hits_prune_if_needed(now);
    }
out:
    if (st)
        sqlite3_finalize(st);
    if (meta)
        json_object_put(meta);
    return rc;
}

static const char *aegisxd_nft_rule_id_from_comment(const char *comment)
{
    if (!comment)
        return "";
    if (strstr(comment, "local reputation destination ipv4"))
        return "nft_reputation_local_destination_ipv4";
    if (strstr(comment, "local reputation destination ipv6"))
        return "nft_reputation_local_destination_ipv6";
    if (strstr(comment, "reputation source ipv4"))
        return "nft_reputation_source_ipv4";
    if (strstr(comment, "reputation destination ipv4"))
        return "nft_reputation_destination_ipv4";
    if (strstr(comment, "reputation source ipv6"))
        return "nft_reputation_source_ipv6";
    if (strstr(comment, "reputation destination ipv6"))
        return "nft_reputation_destination_ipv6";
    return "";
}

static struct aegisxd_nft_counter_seen *aegisxd_nft_seen_get(const char *rule_id,
                                                            const char *rule_name)
{
    int empty = -1;

    if (!rule_id || !rule_id[0])
        return NULL;
    for (size_t i = 0; i < ARRAY_SIZE(g_nft_seen); i++) {
        if (g_nft_seen[i].rule_id[0] && !strcmp(g_nft_seen[i].rule_id, rule_id))
            return &g_nft_seen[i];
        if (empty < 0 && !g_nft_seen[i].rule_id[0])
            empty = (int)i;
    }
    if (empty < 0)
        empty = 0;
    memset(&g_nft_seen[empty], 0, sizeof(g_nft_seen[empty]));
    snprintf(g_nft_seen[empty].rule_id, sizeof(g_nft_seen[empty].rule_id),
             "%s", rule_id);
    snprintf(g_nft_seen[empty].rule_name, sizeof(g_nft_seen[empty].rule_name),
             "%s", rule_name ? rule_name : rule_id);
    return &g_nft_seen[empty];
}

static int aegisxd_hits_insert_nft_counter_delta(const char *rule_id,
                                                 const char *rule_name,
                                                 uint64_t delta_packets,
                                                 uint64_t delta_bytes,
                                                 uint64_t total_packets,
                                                 uint64_t total_bytes)
{
    sqlite3_stmt *st = NULL;
    struct json_object *meta = NULL;
    const char *meta_s;
    int64_t now = aegisxd_now_s();
    int rc = -1;

    if (!rule_id || !rule_id[0] || delta_packets == 0)
        return -1;
    meta = json_object_new_object();
    aegisxd_json_add_string(meta, "counter_source", "nftables");
    aegisxd_json_add_string(meta, "table", AEGISXD_NFT_TABLE);
    aegisxd_json_add_string(meta, "rule_id", rule_id);
    aegisxd_json_add_string(meta, "rule_name", rule_name ? rule_name : rule_id);
    json_object_object_add(meta, "delta_packets", json_object_new_int64((int64_t)delta_packets));
    json_object_object_add(meta, "delta_bytes", json_object_new_int64((int64_t)delta_bytes));
    json_object_object_add(meta, "total_packets", json_object_new_int64((int64_t)total_packets));
    json_object_object_add(meta, "total_bytes", json_object_new_int64((int64_t)total_bytes));
    json_object_object_add(meta, "aggregate_counter", json_object_new_boolean(1));
    json_object_object_add(meta, "drop_confirmed", json_object_new_boolean(1));
    json_object_object_add(meta, "sampled_flow", json_object_new_boolean(0));
    aegisxd_json_add_string(meta, "precision", "aggregate_rule_counter");
    aegisxd_json_add_string(meta, "match_precision", "aggregate_rule_counter");
    aegisxd_json_add_string(meta, "dataplane_action", "nft_drop");
    aegisxd_json_add_string(meta, "dataplane", "nftables");
    meta_s = json_object_to_json_string(meta);

    st = aegisxd_prepare(
        "INSERT INTO aegis_events("
        "ts,event_type,level,action,policy_id,policy_name,policy_type,rule_id,rule_name,"
        "risk,risk_category,reason,source,meta_json"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    if (!st)
        goto out;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, "nft_reputation_block", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, "warning", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, "drop", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, "nft_reputation", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, "IP Reputation", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 7, "reputation_ip", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, rule_name ? rule_name : rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, "unknown", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 11, "ip_reputation", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 12, "nft_rule_counter_delta", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 13, "aegisxd.nft_reputation", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 14, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE) {
        rc = 0;
        g_last_event_id = (int)sqlite3_last_insert_rowid(g_aegisxd_db);
        g_last_event_at = now;
        g_events_inserted++;
        g_nft_last_event_id = g_last_event_id;
        g_nft_last_event_at = now;
        g_nft_events_inserted++;
        aegisxd_hits_prune_if_needed(now);
    }
out:
    if (st)
        sqlite3_finalize(st);
    if (meta)
        json_object_put(meta);
    return rc;
}

static int aegisxd_reputation_flow_recent_duplicate(const char *key, int64_t now)
{
    if (!key || !key[0])
        return 1;
    for (size_t i = 0; i < ARRAY_SIZE(g_reputation_flow_seen); i++) {
        if (g_reputation_flow_seen[i].key[0] &&
            !strcmp(g_reputation_flow_seen[i].key, key) &&
            now - g_reputation_flow_seen[i].ts < AEGISXD_REPUTATION_FLOW_DEDUPE_S) {
            g_reputation_flow_seen[i].ts = now;
            return 1;
        }
    }
    snprintf(g_reputation_flow_seen[g_reputation_flow_seen_pos].key,
             sizeof(g_reputation_flow_seen[g_reputation_flow_seen_pos].key),
             "%s", key);
    g_reputation_flow_seen[g_reputation_flow_seen_pos].ts = now;
    g_reputation_flow_seen_pos =
        (g_reputation_flow_seen_pos + 1) % (int)ARRAY_SIZE(g_reputation_flow_seen);
    return 0;
}

static int aegisxd_reputation_ip_publicish(const char *ip)
{
    unsigned a, b, c, d;

    if (!ip || !ip[0])
        return 0;
    if (strchr(ip, ':')) {
        if (!strncasecmp(ip, "fe80:", 5) || !strncasecmp(ip, "fc", 2) ||
            !strncasecmp(ip, "fd", 2) || !strcmp(ip, "::1"))
            return 0;
        return 1;
    }
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    if (a == 0 || a == 10 || a == 127 || a >= 224)
        return 0;
    if (a == 100 && b >= 64 && b <= 127)
        return 0;
    if (a == 169 && b == 254)
        return 0;
    if (a == 172 && b >= 16 && b <= 31)
        return 0;
    if (a == 192 && b == 168)
        return 0;
    return 1;
}

static int aegisxd_conntrack_parse_line(const char *line,
                                        struct aegisxd_conntrack_tuple *ct)
{
    char work[4096];
    char *save = NULL;
    char *tok;
    int tuple = 0;
    int orig_packets_set = 0;
    int orig_bytes_set = 0;
    int reply_packets_set = 0;
    int reply_bytes_set = 0;

    if (!line || !ct)
        return 0;
    memset(ct, 0, sizeof(*ct));
    snprintf(work, sizeof(work), "%s", line);
    tok = strtok_r(work, " \t\r\n", &save);
    if (!tok)
        return 0;
    tok = strtok_r(NULL, " \t\r\n", &save); /* l3 proto number */
    tok = strtok_r(NULL, " \t\r\n", &save); /* l4 proto */
    if (!tok)
        return 0;
    snprintf(ct->proto, sizeof(ct->proto), "%s", tok);
    while ((tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        if (!strncmp(tok, "src=", 4)) {
            if (tuple == 0 && !ct->src[0])
                snprintf(ct->src, sizeof(ct->src), "%s", tok + 4);
            else if (tuple == 0 && ct->src[0] && ct->dst[0])
                tuple = 1;
        } else if (!strncmp(tok, "dst=", 4)) {
            if (tuple == 0 && !ct->dst[0])
                snprintf(ct->dst, sizeof(ct->dst), "%s", tok + 4);
            else if (tuple == 0 && ct->src[0] && ct->dst[0])
                tuple = 1;
        } else if (!strncmp(tok, "sport=", 6)) {
            if (tuple == 0 && ct->sport <= 0)
                ct->sport = atoi(tok + 6);
        } else if (!strncmp(tok, "dport=", 6)) {
            if (tuple == 0 && ct->dport <= 0)
                ct->dport = atoi(tok + 6);
        } else if (!strncmp(tok, "packets=", 8)) {
            if (!orig_packets_set) {
                ct->orig_packets = atoll(tok + 8);
                orig_packets_set = 1;
            } else if (!reply_packets_set) {
                ct->reply_packets = atoll(tok + 8);
                reply_packets_set = 1;
            }
        } else if (!strncmp(tok, "bytes=", 6)) {
            if (!orig_bytes_set) {
                ct->orig_bytes = atoll(tok + 6);
                orig_bytes_set = 1;
            } else if (!reply_bytes_set) {
                ct->reply_bytes = atoll(tok + 6);
                reply_bytes_set = 1;
            }
        }
    }
    return ct->src[0] && ct->dst[0];
}

static int aegisxd_hits_insert_reputation_flow(const struct aegisxd_conntrack_tuple *ct,
                                               const char *matched_ip,
                                               const char *direction,
                                               const struct aegisxd_reputation_match *match)
{
    sqlite3_stmt *st = NULL;
    struct json_object *meta = NULL;
    const char *meta_s;
    const char *risk;
    int64_t now = aegisxd_now_s();
    int64_t bytes;
    int rc = -1;

    if (!ct || !matched_ip || !matched_ip[0] || !match)
        return -1;
    bytes = ct->orig_bytes + ct->reply_bytes;
    risk = aegisxd_hits_risk_from_category(match->category, match->severity);
    meta = json_object_new_object();
    aegisxd_json_add_string(meta, "producer_source", "conntrack_scan");
    aegisxd_json_add_string(meta, "precision", "conntrack_flow_snapshot");
    aegisxd_json_add_string(meta, "matched_ip", matched_ip);
    aegisxd_json_add_string(meta, "match_direction", direction ? direction : "");
    aegisxd_json_add_string(meta, "source_feed", match->source_feed);
    json_object_object_add(meta, "severity", json_object_new_int(match->severity));
    json_object_object_add(meta, "confidence", json_object_new_int(match->confidence));
    json_object_object_add(meta, "orig_packets", json_object_new_int64(ct->orig_packets));
    json_object_object_add(meta, "orig_bytes", json_object_new_int64(ct->orig_bytes));
    json_object_object_add(meta, "reply_packets", json_object_new_int64(ct->reply_packets));
    json_object_object_add(meta, "reply_bytes", json_object_new_int64(ct->reply_bytes));
    json_object_object_add(meta, "sampled_flow", json_object_new_boolean(1));
    json_object_object_add(meta, "drop_confirmed", json_object_new_boolean(0));
    meta_s = json_object_to_json_string(meta);

    st = aegisxd_prepare(
        "INSERT INTO aegis_events("
        "ts,event_type,level,action,policy_id,policy_name,policy_type,rule_id,rule_name,"
        "risk,risk_category,source_ip,source_port,destination_ip,destination_port,protocol,"
        "rx_bytes,tx_bytes,reason,source,meta_json"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    if (!st)
        goto out;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, "reputation_ip_flow_match", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, "warning", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, "alert", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, "nft_reputation", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, "IP Reputation", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 7, "reputation_ip", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, matched_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, matched_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, risk, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 11, match->category[0] ? match->category : "ip_reputation", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, ct->src, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, ct->sport);
    sqlite3_bind_text(st, 14, ct->dst, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 15, ct->dport);
    sqlite3_bind_text(st, 16, ct->proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 17, ct->reply_bytes);
    sqlite3_bind_int64(st, 18, ct->orig_bytes > 0 ? ct->orig_bytes : bytes);
    sqlite3_bind_text(st, 19, "reputation_conntrack_flow_match", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 20, "aegisxd.reputation_flow", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 21, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE) {
        rc = 0;
        g_last_event_id = (int)sqlite3_last_insert_rowid(g_aegisxd_db);
        g_last_event_at = now;
        g_events_inserted++;
        g_reputation_flow_last_event_id = g_last_event_id;
        g_reputation_flow_last_event_at = now;
        g_reputation_flow_events_inserted++;
        aegisxd_hits_prune_if_needed(now);
    }
out:
    if (st)
        sqlite3_finalize(st);
    if (meta)
        json_object_put(meta);
    return rc;
}

static void aegisxd_reputation_flow_poll(void)
{
    FILE *fp;
    const char *paths[] = { "/proc/net/nf_conntrack", "/proc/net/ip_conntrack" };
    char line[4096];
    int scanned = 0;
    int matches = 0;
    int inserted = 0;

    g_reputation_flow_feed_ips = 0;
    {
        sqlite3_stmt *st = aegisxd_prepare(
            "SELECT COUNT(*) FROM aegis_reputation_items "
            "WHERE kind='ip' OR kind='ipv4' OR kind='ipv6'");
        if (st) {
            if (sqlite3_step(st) == SQLITE_ROW)
                g_reputation_flow_feed_ips = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
        }
    }
    if (g_reputation_flow_feed_ips <= 0) {
        snprintf(g_reputation_flow_last_error, sizeof(g_reputation_flow_last_error),
                 "%s", "reputation_ip_feed_empty");
        return;
    }
    fp = NULL;
    for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
        fp = fopen(paths[i], "r");
        if (fp)
            break;
    }
    if (!fp) {
        snprintf(g_reputation_flow_last_error, sizeof(g_reputation_flow_last_error),
                 "%s", "conntrack_proc_unavailable");
        return;
    }
    while (fgets(line, sizeof(line), fp) && scanned < AEGISXD_REPUTATION_FLOW_MAX_SCAN) {
        struct aegisxd_conntrack_tuple ct;
        struct aegisxd_reputation_match match;
        char key[256];
        const char *matched_ip = NULL;
        const char *direction = NULL;
        int64_t now = aegisxd_now_s();

        scanned++;
        if (!aegisxd_conntrack_parse_line(line, &ct))
            continue;
        if (aegisxd_reputation_ip_publicish(ct.dst) &&
            aegisxd_reputation_ip_lookup(ct.dst, &match)) {
            matched_ip = ct.dst;
            direction = "destination";
        } else if (aegisxd_reputation_ip_publicish(ct.src) &&
                   aegisxd_reputation_ip_lookup(ct.src, &match)) {
            matched_ip = ct.src;
            direction = "source";
        } else {
            continue;
        }
        matches++;
        snprintf(key, sizeof(key), "%s|%s|%s|%d|%d",
                 ct.proto, ct.src, ct.dst, ct.sport, ct.dport);
        if (aegisxd_reputation_flow_recent_duplicate(key, now))
            continue;
        if (aegisxd_hits_insert_reputation_flow(&ct, matched_ip, direction, &match) == 0)
            inserted++;
        if (inserted >= AEGISXD_REPUTATION_FLOW_MAX_EVENTS_PER_POLL)
            break;
    }
    fclose(fp);
    g_reputation_flow_flows_scanned = scanned;
    g_reputation_flow_matches_seen = matches;
    if (matches > 0)
        snprintf(g_reputation_flow_last_error, sizeof(g_reputation_flow_last_error), "%s",
                 inserted > 0 ? "" : "matches_deduped");
    else
        snprintf(g_reputation_flow_last_error, sizeof(g_reputation_flow_last_error), "%s",
                 "no_reputation_flow_match");
}

static const char *aegisxd_json_nested_str(struct json_object *o, const char *outer,
                                           const char *inner, const char *def)
{
    struct json_object *child = NULL;
    struct json_object *v = NULL;

    if (!o || !outer || !inner ||
        !json_object_object_get_ex(o, outer, &child) || !child ||
        !json_object_object_get_ex(child, inner, &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

static int aegisxd_json_nested_int(struct json_object *o, const char *outer,
                                   const char *inner, int def)
{
    struct json_object *child = NULL;
    struct json_object *v = NULL;

    if (!o || !outer || !inner ||
        !json_object_object_get_ex(o, outer, &child) || !child ||
        !json_object_object_get_ex(child, inner, &v) || !v)
        return def;
    return json_object_get_int(v);
}

static int aegisxd_json_nested_int_required(struct json_object *o, const char *outer,
                                            const char *inner, int *out)
{
    struct json_object *child = NULL;
    struct json_object *v = NULL;

    if (!out || !o || !outer || !inner ||
        !json_object_object_get_ex(o, outer, &child) || !child ||
        !json_object_object_get_ex(child, inner, &v) || !v ||
        !json_object_is_type(v, json_type_int))
        return 0;
    *out = json_object_get_int(v);
    return 1;
}

static int64_t aegisxd_json_int64_field(struct json_object *o, const char *key,
                                        int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

static const char *aegisxd_suricata_action_from_event(const char *event_type,
                                                      const char *alert_action)
{
    if (event_type && (!strcmp(event_type, "drop") || !strcmp(event_type, "blocked")))
        return "drop";
    if (alert_action && (!strcmp(alert_action, "blocked") ||
                         !strcmp(alert_action, "drop") ||
                         !strcmp(alert_action, "dropped")))
        return "drop";
    return "alert";
}

static const char *aegisxd_suricata_risk_from_severity(int severity)
{
    if (severity <= 1)
        return "critical";
    if (severity == 2)
        return "high";
    if (severity == 3)
        return "medium";
    return "low";
}

static int aegisxd_hits_insert_suricata_event_ex(struct json_object *eve,
                                                  const char *ingest_source,
                                                  int test_event)
{
    sqlite3_stmt *st = NULL;
    struct json_object *meta = NULL;
    struct json_object *alert = NULL;
    const char *event_type;
    const char *signature;
    const char *category;
    const char *proto;
    const char *src_ip;
    const char *dst_ip;
    const char *flow_id;
    const char *app_proto;
    const char *alert_action;
    const char *action;
    const char *risk;
    const char *meta_s;
    const char *event_source;
    const char *reason;
    const char *in_iface;
    int manual_ingest;
    int production_event;
    int64_t now = aegisxd_now_s();
    int64_t event_ts = now;
    int sid;
    int gid;
    int rev;
    int severity;
    int src_port;
    int dst_port;
    int rc = -1;

    if (!eve || !json_object_is_type(eve, json_type_object))
        return -1;
    event_type = aegisxd_json_str(eve, "event_type", "");
    if (strcmp(event_type, "alert") && strcmp(event_type, "drop"))
        return 0;
    if (!json_object_object_get_ex(eve, "alert", &alert) || !alert)
        return 0;

    signature = aegisxd_json_nested_str(eve, "alert", "signature", "");
    category = aegisxd_json_nested_str(eve, "alert", "category", "suricata_alert");
    sid = aegisxd_json_nested_int(eve, "alert", "signature_id", 0);
    gid = aegisxd_json_nested_int(eve, "alert", "gid", 0);
    rev = aegisxd_json_nested_int(eve, "alert", "rev", 0);
    if (!aegisxd_json_nested_int_required(eve, "alert", "severity", &severity))
        return -2;
    proto = aegisxd_json_str(eve, "proto", "");
    src_ip = aegisxd_json_str(eve, "src_ip", "");
    dst_ip = aegisxd_json_str(eve, "dest_ip", "");
    src_port = (int)aegisxd_json_int64_field(eve, "src_port", 0);
    dst_port = (int)aegisxd_json_int64_field(eve, "dest_port", 0);
    flow_id = aegisxd_json_str(eve, "flow_id", "");
    app_proto = aegisxd_json_str(eve, "app_proto", "");
    alert_action = aegisxd_json_nested_str(eve, "alert", "action", "");
    action = aegisxd_suricata_action_from_event(event_type, alert_action);
    risk = aegisxd_suricata_risk_from_severity(severity);
    event_source = (ingest_source && ingest_source[0]) ? ingest_source : "aegisxd.suricata";
    manual_ingest = strstr(event_source, ".manual") != NULL ||
        strstr(event_source, "manual_") != NULL ||
        strstr(event_source, "manual") != NULL;
    production_event = !manual_ingest && !test_event;
    if (test_event)
        reason = "suricata_eve_manual_test_ingest";
    else if (manual_ingest)
        reason = "suricata_eve_manual_ingest";
    else
        reason = "suricata_eve_alert";
    in_iface = aegisxd_json_str(eve, "in_iface", "");

    meta = json_object_new_object();
    aegisxd_json_add_string(meta, "event_type", event_type);
    aegisxd_json_add_string(meta, "alert_action", alert_action);
    aegisxd_json_add_string(meta, "signature", signature);
    aegisxd_json_add_string(meta, "category", category);
    aegisxd_json_add_string(meta, "app_proto", app_proto);
    json_object_object_add(meta, "gid", json_object_new_int(gid));
    json_object_object_add(meta, "sid", json_object_new_int(sid));
    json_object_object_add(meta, "rev", json_object_new_int(rev));
    json_object_object_add(meta, "severity", json_object_new_int(severity));
    aegisxd_json_add_string(meta, "precision",
                           !strcmp(action, "drop") ? "eve_drop" : "eve_alert");
    aegisxd_json_add_string(meta, "eve_path", AEGISXD_SURICATA_EVE_PATH);
    aegisxd_json_add_string(meta, "ingest_source", event_source);
    json_object_object_add(meta, "test_event", json_object_new_boolean(test_event));
    json_object_object_add(meta, "manual_ingest", json_object_new_boolean(manual_ingest));
    json_object_object_add(meta, "production_event", json_object_new_boolean(production_event));
    aegisxd_json_add_string(meta, "ingest_kind",
                           production_event ? "production" :
                           (test_event ? "manual_test" : "manual"));
    json_object_object_add(meta, "drop_confirmed",
                           json_object_new_boolean(!strcmp(action, "drop")));
    json_object_object_add(meta, "pre_conntrack",
                           json_object_new_boolean(
                               aegisxd_json_bool(eve, "pre_conntrack", 0)));
    aegisxd_json_add_string(meta, "producer_source", "suricata_eve");
    aegisxd_json_add_string(meta, "in_interface", in_iface);
    meta_s = json_object_to_json_string(meta);

    st = aegisxd_prepare(
        "INSERT INTO aegis_events("
        "ts,event_type,level,action,policy_id,policy_name,policy_type,rule_id,rule_name,"
        "risk,risk_category,source_ip,source_port,destination_ip,destination_port,protocol,"
        "app_id,app_name,in_interface,flow_id,reason,source,meta_json"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    if (!st)
        goto out;
    sqlite3_bind_int64(st, 1, event_ts);
    sqlite3_bind_text(st, 2, strcmp(action, "drop") ? "suricata_alert" : "suricata_drop", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, strcmp(action, "drop") ? "warning" : "critical", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, action, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, "suricata", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, "Suricata IDS/IPS", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 7, "ids_ips", -1, SQLITE_STATIC);
    if (sid > 0) {
        char sid_buf[32];

        snprintf(sid_buf, sizeof(sid_buf), "%d", sid);
        sqlite3_bind_text(st, 8, sid_buf, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(st, 8, "", -1, SQLITE_STATIC);
    }
    sqlite3_bind_text(st, 9, signature, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, risk, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 11, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, src_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, src_port);
    sqlite3_bind_text(st, 14, dst_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 15, dst_port);
    sqlite3_bind_text(st, 16, proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, app_proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 18, app_proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 19, in_iface, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 20, flow_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 21, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 22, event_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 23, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE) {
        rc = 0;
        g_last_event_id = (int)sqlite3_last_insert_rowid(g_aegisxd_db);
        g_last_event_at = now;
        g_events_inserted++;
        g_suricata_last_event_id = g_last_event_id;
        g_suricata_last_event_at = now;
        g_suricata_events_inserted++;
        g_suricata_alerts_seen++;
        if (manual_ingest) {
            g_suricata_manual_ingest_events++;
            g_suricata_last_manual_ingest_at = now;
        }
        aegisxd_hits_prune_if_needed(now);
    }
out:
    if (st)
        sqlite3_finalize(st);
    if (meta)
        json_object_put(meta);
    return rc;
}

static int aegisxd_hits_insert_suricata_event(struct json_object *eve)
{
    return aegisxd_hits_insert_suricata_event_ex(eve, "aegisxd.suricata", 0);
}

static void aegisxd_suricata_ingest_result_add_reason(struct json_object *resp,
                                                      const char *reason)
{
    struct json_object *arr = NULL;

    if (!resp || !reason || !reason[0])
        return;
    if (!json_object_object_get_ex(resp, "reasons", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array)) {
        arr = json_object_new_array();
        json_object_object_add(resp, "reasons", arr);
    }
    json_object_array_add(arr, json_object_new_string(reason));
}

static int aegisxd_suricata_ingest_one(struct json_object *item, const char *source,
                                       int test_event, struct json_object *resp)
{
    struct json_object *eve = item;
    int parsed_from_string = 0;
    int inserted_before = g_suricata_events_inserted;
    int rc;

    if (!item) {
        aegisxd_suricata_ingest_result_add_reason(resp, "null_event");
        return -1;
    }
    if (json_object_is_type(item, json_type_string)) {
        const char *line = json_object_get_string(item);

        if (!line || !line[0]) {
            aegisxd_suricata_ingest_result_add_reason(resp, "empty_line");
            return -1;
        }
        eve = json_tokener_parse(line);
        parsed_from_string = 1;
        if (!eve) {
            aegisxd_suricata_ingest_result_add_reason(resp, "invalid_eve_json");
            return -1;
        }
    }
    if (!json_object_is_type(eve, json_type_object)) {
        if (parsed_from_string)
            json_object_put(eve);
        aegisxd_suricata_ingest_result_add_reason(resp, "event_not_object");
        return -1;
    }
    rc = aegisxd_hits_insert_suricata_event_ex(eve, source, test_event);
    if (parsed_from_string)
        json_object_put(eve);
    if (rc == -2) {
        aegisxd_suricata_ingest_result_add_reason(resp,
            "suricata_event_missing_required_producer_fields");
        return -1;
    }
    if (rc != 0 || g_suricata_events_inserted == inserted_before) {
        aegisxd_suricata_ingest_result_add_reason(resp, "not_inserted_or_unsupported_event_type");
        return -1;
    }
    return 0;
}

struct json_object *aegisxd_ingest_suricata_eve(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *line = NULL;
    struct json_object *event = NULL;
    struct json_object *events = NULL;
    const char *source;
    int test_event;
    int requested = 0;
    int inserted_before = g_suricata_events_inserted;
    int failed = 0;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "method", "ingest_suricata_eve");
    json_object_object_add(resp, "production_runtime_required", json_object_new_boolean(0));
    json_object_object_add(resp, "manual_ingest", json_object_new_boolean(1));
    json_object_object_add(resp, "production_event", json_object_new_boolean(0));

    test_event = aegisxd_json_bool(body, "test", 1);
    source = aegisxd_json_str(body, "source", "");
    if (!source || !source[0])
        source = test_event ? "aegisxd.suricata.manual_test" : "aegisxd.suricata.manual";
    json_object_object_add(resp, "test_event", json_object_new_boolean(test_event));
    aegisxd_json_add_string(resp, "source", source);
    aegisxd_json_add_string(resp, "ingest_kind", test_event ? "manual_test" : "manual");
    aegisxd_json_add_string(resp, "policy_type", "ids_ips");

    if (body && json_object_object_get_ex(body, "line", &line) && line) {
        requested++;
        if (aegisxd_suricata_ingest_one(line, source, test_event, resp) != 0)
            failed++;
    }
    if (body && json_object_object_get_ex(body, "event", &event) && event) {
        requested++;
        if (aegisxd_suricata_ingest_one(event, source, test_event, resp) != 0)
            failed++;
    }
    if (body && json_object_object_get_ex(body, "events", &events) && events &&
        json_object_is_type(events, json_type_array)) {
        int n = json_object_array_length(events);
        int i;

        for (i = 0; i < n; i++) {
            requested++;
            if (aegisxd_suricata_ingest_one(json_object_array_get_idx(events, i),
                                            source, test_event, resp) != 0)
                failed++;
        }
    }

    json_object_object_add(resp, "requested", json_object_new_int(requested));
    json_object_object_add(resp, "inserted",
                           json_object_new_int(g_suricata_events_inserted - inserted_before));
    json_object_object_add(resp, "production_inserted", json_object_new_int(0));
    json_object_object_add(resp, "failed", json_object_new_int(failed));
    json_object_object_add(resp, "last_event_id",
                           g_suricata_last_event_id > 0 ?
                           json_object_new_int(g_suricata_last_event_id) : json_object_new_null());
    json_object_object_add(resp, "last_event_at",
                           g_suricata_last_event_at > 0 ?
                           json_object_new_int64(g_suricata_last_event_at) : json_object_new_null());
    json_object_object_add(resp, "suricata_runtime_available",
                           json_object_new_boolean(access("/usr/bin/suricata", X_OK) == 0 ||
                                                   access("/usr/sbin/suricata", X_OK) == 0));
    aegisxd_json_add_string(resp, "runtime_note",
                            "manual EVE ingest validates the aegis_events pipeline; production IDS/IPS still requires a Suricata binary and active eve.json tail");
    if (requested <= 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "error", "missing_event");
        aegisxd_json_add_string(resp, "message", "provide line, event, or events[]");
    } else if (failed > 0) {
        json_object_object_add(resp, "degraded", json_object_new_boolean(1));
    } else {
        json_object_object_add(resp, "degraded", json_object_new_boolean(0));
    }
    return resp;
}

static int aegisxd_hits_table_exists(sqlite3 *db, const char *table)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!db || !table || !table[0])
        return 0;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

static int64_t aegisxd_hits_state_int64(const char *key, int64_t def)
{
    sqlite3_stmt *st = NULL;
    int64_t out = def;

    if (!key || !key[0])
        return def;
    st = aegisxd_prepare("SELECT value FROM aegis_state WHERE key=?1 LIMIT 1");
    if (!st)
        return def;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *s = aegisxd_sqlite_text(st, 0, "");
        char *end = NULL;
        int64_t v = strtoll(s, &end, 10);

        if (end && end != s)
            out = v;
    }
    sqlite3_finalize(st);
    return out;
}

static int aegisxd_hits_state_set_int64(const char *key, int64_t value)
{
    sqlite3_stmt *st = NULL;
    char buf[64];
    int rc;

    if (!key || !key[0])
        return -1;
    snprintf(buf, sizeof(buf), "%" PRId64, value);
    st = aegisxd_prepare(
        "INSERT INTO aegis_state(key,value,updated_at) VALUES(?1,?2,?3) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, buf, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void aegisxd_hits_state_key(char *buf, size_t len, const char *prefix,
                                   const char *source_name, const char *id)
{
    char clean[160];
    size_t n = 0;

    if (!buf || !len)
        return;
    if (!id)
        id = "";
    for (const char *p = id; *p && n + 1 < sizeof(clean); p++) {
        unsigned char c = (unsigned char)*p;

        clean[n++] = (isalnum(c) || c == '_' || c == '-' || c == '.') ? (char)c : '_';
    }
    clean[n] = '\0';
    snprintf(buf, len, "%s_%s_%s", prefix ? prefix : "state",
             source_name && source_name[0] ? source_name : "db", clean);
}

static const char *aegisxd_policy_action_normalize(const char *action)
{
    if (!action || !action[0])
        return "route";
    if (!strcasecmp(action, "deny") || !strcasecmp(action, "block"))
        return "block";
    if (!strcasecmp(action, "drop") || !strcasecmp(action, "reject"))
        return "drop";
    if (!strcasecmp(action, "allow") || !strcasecmp(action, "accept"))
        return "allow";
    if (!strcasecmp(action, "route_table") || !strcasecmp(action, "route") ||
        !strcasecmp(action, "wan") || !strcasecmp(action, "redirect") ||
        !strcasecmp(action, "policy_route"))
        return "route";
    if (!strcasecmp(action, "limit") || !strcasecmp(action, "rate_limit"))
        return "limit";
    return action;
}

static const char *aegisxd_policy_event_type(const char *action)
{
    const char *a = aegisxd_policy_action_normalize(action);

    if (!strcmp(a, "block") || !strcmp(a, "drop"))
        return "policy_route_block";
    if (!strcmp(a, "limit"))
        return "policy_route_limit";
    if (!strcmp(a, "allow"))
        return "policy_route_allow";
    return "policy_route_match";
}

static const char *aegisxd_policy_level(const char *action)
{
    const char *a = aegisxd_policy_action_normalize(action);

    if (!strcmp(a, "block") || !strcmp(a, "drop"))
        return "warning";
    return "info";
}

static int aegisxd_policy_insert_event(int64_t sample_id, int64_t ts,
                                       const char *rule_id,
                                       const char *rule_name,
                                       const char *client,
                                       const char *source_ip,
                                       const char *destination,
                                       const char *app,
                                       const char *route_table,
                                       const char *wan,
                                       const char *action,
                                       const char *reason,
                                       int64_t up_bytes,
                                       int64_t down_bytes,
                                       int64_t bytes,
                                       const char *producer_source,
                                       int verified,
                                       int policy_hit,
                                       int aggregate_counter,
                                       int64_t counter_delta,
                                       int64_t total_hits,
                                       const char *sample_source)
{
    sqlite3_stmt *st = NULL;
    struct json_object *meta = NULL;
    const char *meta_s;
    const char *norm_action = aegisxd_policy_action_normalize(action);
    int64_t now = aegisxd_now_s();
    int rc = -1;

    if (!rule_id || !rule_id[0])
        rule_id = "policy_route";
    if (ts <= 0)
        ts = now;
    meta = json_object_new_object();
    json_object_object_add(meta, "sample_id", json_object_new_int64(sample_id));
    aegisxd_json_add_string(meta, "producer_source", producer_source ? producer_source : "");
    aegisxd_json_add_string(meta, "sample_source", sample_source ? sample_source : "");
    json_object_object_add(meta, "verified", json_object_new_boolean(verified));
    json_object_object_add(meta, "policy_hit", json_object_new_boolean(policy_hit));
    json_object_object_add(meta, "security_event", json_object_new_boolean(policy_hit));
    json_object_object_add(meta, "aggregate_counter", json_object_new_boolean(aggregate_counter));
    if (aggregate_counter) {
        aegisxd_json_add_string(meta, "counter_source", "jmx_route_kernel");
        aegisxd_json_add_string(meta, "match_precision", "aggregate_rule_counter");
        json_object_object_add(meta, "delta_hits", json_object_new_int64(counter_delta));
        json_object_object_add(meta, "total_hits", json_object_new_int64(total_hits));
    }
    aegisxd_json_add_string(meta, "route_table", route_table ? route_table : "");
    aegisxd_json_add_string(meta, "wan", wan ? wan : "");
    aegisxd_json_add_string(meta, "app", app ? app : "");
    json_object_object_add(meta, "bytes", json_object_new_int64(bytes));
    aegisxd_json_add_string(meta, "precision",
                            reason && strstr(reason, "aggregate_rule_counter") ?
                            "aggregate_rule_counter" : "policy_hit_sample");
    meta_s = json_object_to_json_string(meta);

    st = aegisxd_prepare(
        "INSERT INTO aegis_events("
        "ts,event_type,level,action,policy_id,policy_name,policy_type,rule_id,rule_name,"
        "risk,risk_category,source_ip,destination_ip,destination_host,protocol,"
        "app_id,app_name,out_interface,rx_bytes,tx_bytes,reason,source,meta_json"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    if (!st)
        goto out;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_text(st, 2, aegisxd_policy_event_type(norm_action), -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, aegisxd_policy_level(norm_action), -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, norm_action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, rule_name && rule_name[0] ? rule_name : rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, "policy_route", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, rule_name && rule_name[0] ? rule_name : rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, "unknown", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 11, "policy_route", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 12, source_ip && source_ip[0] ? source_ip : client ? client : "", -1, SQLITE_TRANSIENT);
    if (destination && strchr(destination, ':') == NULL &&
        strspn(destination, "0123456789.") == strlen(destination)) {
        sqlite3_bind_text(st, 13, destination, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, "", -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_text(st, 13, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 14, destination ? destination : "", -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(st, 15, "", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 16, app ? app : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, app ? app : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 18, wan && wan[0] ? wan : route_table ? route_table : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 19, down_bytes > 0 ? down_bytes : bytes);
    sqlite3_bind_int64(st, 20, up_bytes > 0 ? up_bytes : bytes);
    sqlite3_bind_text(st, 21, reason && reason[0] ? reason : "policy_hit_sample", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 22, "aegisxd.policy_route", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 23, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE) {
        rc = 0;
        g_last_event_id = (int)sqlite3_last_insert_rowid(g_aegisxd_db);
        g_last_event_at = ts;
        g_events_inserted++;
        g_policy_last_event_id = g_last_event_id;
        g_policy_last_event_at = ts;
        g_policy_events_inserted++;
        aegisxd_hits_prune_if_needed(now);
    }
out:
    if (st)
        sqlite3_finalize(st);
    if (meta)
        json_object_put(meta);
    return rc;
}

static int aegisxd_policy_poll_policy_route_hit_sample(sqlite3 *db,
                                                       const char *state_key,
                                                       const char *source_name,
                                                       int *rules_seen)
{
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *max_st = NULL;
    int64_t last_id;
    int64_t max_id = 0;
    int imported = 0;
    int rows = 0;
    int has_rule_table;

    if (!db || !aegisxd_hits_table_exists(db, "policy_route_hit_sample"))
        return 0;
    if (rules_seen && aegisxd_hits_table_exists(db, "policy_route_rule")) {
        sqlite3_stmt *rs = NULL;

        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM policy_route_rule",
                               -1, &rs, NULL) == SQLITE_OK &&
            sqlite3_step(rs) == SQLITE_ROW)
            *rules_seen += sqlite3_column_int(rs, 0);
        if (rs)
            sqlite3_finalize(rs);
    }
    if (sqlite3_prepare_v2(db, "SELECT COALESCE(MAX(id),0) FROM policy_route_hit_sample",
                           -1, &max_st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(max_st) == SQLITE_ROW)
        max_id = sqlite3_column_int64(max_st, 0);
    sqlite3_finalize(max_st);
    last_id = aegisxd_hits_state_int64(state_key, -1);
    if (last_id < 0) {
        aegisxd_hits_state_set_int64(state_key, max_id);
        if (max_id > 0)
            g_policy_baselined = 1;
        return 0;
    }
    has_rule_table = aegisxd_hits_table_exists(db, "policy_route_rule");
    if (sqlite3_prepare_v2(db, has_rule_table ?
            "SELECT h.id,h.ts,h.rule_id,COALESCE(r.name,h.rule_id),h.client,"
            "h.source,h.destination,h.app,h.route_table,h.action,h.reason,h.bytes "
            "FROM policy_route_hit_sample h "
            "LEFT JOIN policy_route_rule r ON r.id=h.rule_id "
            "WHERE h.id>?1 ORDER BY h.id ASC LIMIT 200" :
            "SELECT h.id,h.ts,h.rule_id,h.rule_id,h.client,"
            "h.source,h.destination,h.app,h.route_table,h.action,h.reason,h.bytes "
            "FROM policy_route_hit_sample h "
            "WHERE h.id>?1 ORDER BY h.id ASC LIMIT 200",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, last_id);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(st, 0);

        rows++;
        if (aegisxd_policy_insert_event(id, sqlite3_column_int64(st, 1),
                aegisxd_sqlite_text(st, 2, ""),
                aegisxd_sqlite_text(st, 3, ""),
                aegisxd_sqlite_text(st, 4, ""),
                aegisxd_sqlite_text(st, 5, ""),
                aegisxd_sqlite_text(st, 6, ""),
                aegisxd_sqlite_text(st, 7, ""),
                aegisxd_sqlite_text(st, 8, ""),
                "",
                aegisxd_sqlite_text(st, 9, ""),
                aegisxd_sqlite_text(st, 10, ""),
                0, 0, sqlite3_column_int64(st, 11),
                source_name,
                1, 1, 0, 0, 0, "policy_route_hit_sample") == 0)
            imported++;
        if (id > last_id)
            last_id = id;
    }
    sqlite3_finalize(st);
    if (rows > 0)
        aegisxd_hits_state_set_int64(state_key, last_id);
    return imported;
}

static int aegisxd_policy_route_decision_verified(const char *rule_id,
                                                 const char *rule_name,
                                                 const char *reason,
                                                 const char *source_name)
{
    if (reason && reason[0]) {
        if (strstr(reason, "candidate") || strstr(reason, "diagnostic") ||
            strstr(reason, "unverified") || strstr(reason, "default_route") ||
            strstr(reason, "runtime_candidate") || strstr(reason, "候选") ||
            strstr(reason, "待接") || strstr(reason, "默认规则候选"))
            return 0;
        if (strstr(reason, "verified") || strstr(reason, "policy_hit") ||
            strstr(reason, "conntrack_mark") || strstr(reason, "fwmark") ||
            strstr(reason, "jmx_route_kernel") || strstr(reason, "route_rule_counter"))
            return 1;
    }
    if (rule_id && rule_id[0] && strcmp(rule_id, "runtime-sample") &&
        strcmp(rule_id, "default") && strcmp(rule_id, "default_route") &&
        strcmp(rule_id, "policy_route") && strncmp(rule_id, "diagnostic", 10) &&
        strncmp(rule_id, "candidate", 9))
        return 1;
    if (rule_name && rule_name[0] && strstr(rule_name, "候选"))
        return 0;
    (void)source_name;
    return 0;
}

static int aegisxd_policy_poll_route_decision_sample(sqlite3 *db,
                                                     const char *state_key,
                                                     const char *source_name,
                                                     int *rules_seen)
{
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *max_st = NULL;
    int64_t last_id;
    int64_t max_id = 0;
    int imported = 0;
    int rows = 0;

    if (!db || !aegisxd_hits_table_exists(db, "route_decision_sample"))
        return 0;
    if (rules_seen && aegisxd_hits_table_exists(db, "route_rule_counter")) {
        sqlite3_stmt *rs = NULL;

        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM route_rule_counter",
                               -1, &rs, NULL) == SQLITE_OK &&
            sqlite3_step(rs) == SQLITE_ROW)
            *rules_seen += sqlite3_column_int(rs, 0);
        if (rs)
            sqlite3_finalize(rs);
    }
    if (sqlite3_prepare_v2(db, "SELECT COALESCE(MAX(id),0) FROM route_decision_sample",
                           -1, &max_st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(max_st) == SQLITE_ROW)
        max_id = sqlite3_column_int64(max_st, 0);
    sqlite3_finalize(max_st);
    last_id = aegisxd_hits_state_int64(state_key, -1);
    if (last_id < 0) {
        aegisxd_hits_state_set_int64(state_key, max_id);
        if (max_id > 0)
            g_policy_baselined = 1;
        return 0;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT id,ts,rule_id,rule_name,client_id,ip,destination,app,path,wan,"
            "action,reason,up_bytes,down_bytes FROM route_decision_sample "
            "WHERE id>?1 ORDER BY id ASC LIMIT 200",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, last_id);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(st, 0);

        const char *rule_id = aegisxd_sqlite_text(st, 2, "");
        const char *rule_name = aegisxd_sqlite_text(st, 3, "");
        const char *reason = aegisxd_sqlite_text(st, 11, "");

        rows++;
        g_policy_route_decision_samples_seen++;
        if (!aegisxd_policy_route_decision_verified(rule_id, rule_name, reason, source_name)) {
            g_policy_route_decision_samples_skipped++;
            g_policy_route_decision_candidate_seen++;
            if (id > last_id)
                last_id = id;
            continue;
        }
        if (aegisxd_policy_insert_event(id, sqlite3_column_int64(st, 1),
                rule_id,
                rule_name,
                aegisxd_sqlite_text(st, 4, ""),
                aegisxd_sqlite_text(st, 5, ""),
                aegisxd_sqlite_text(st, 6, ""),
                aegisxd_sqlite_text(st, 7, ""),
                aegisxd_sqlite_text(st, 8, ""),
                aegisxd_sqlite_text(st, 9, ""),
                aegisxd_sqlite_text(st, 10, ""),
                reason,
                sqlite3_column_int64(st, 12), sqlite3_column_int64(st, 13), 0,
                source_name,
                1, 1, 0, 0, 0, "verified_route_decision_sample") == 0) {
            imported++;
            g_policy_route_decision_samples_imported++;
            g_policy_verified_samples_seen++;
        }
        if (id > last_id)
            last_id = id;
    }
    sqlite3_finalize(st);
    if (rows > 0)
        aegisxd_hits_state_set_int64(state_key, last_id);
    return imported;
}

static int aegisxd_policy_insert_counter_event(const struct aegisxd_policy_counter_row *row,
                                               int64_t delta,
                                               const char *source_name)
{
    char reason[192];

    if (!row || !row->rule_id[0] || delta <= 0)
        return -1;
    snprintf(reason, sizeof(reason),
             "route_rule_counter delta=%" PRId64 " precision=aggregate_rule_counter",
             delta);
    return aegisxd_policy_insert_event(-row->hit_count,
        row->last_hit > 0 ? row->last_hit : aegisxd_now_s(),
        row->rule_id,
        row->rule_name[0] ? row->rule_name : row->rule_id,
        "",
        "",
        "",
        "",
        row->target,
        row->target,
        row->action[0] ? row->action : "route",
        reason,
        0, 0, delta,
        source_name,
        1, 1, 1, delta, row->hit_count, "route_rule_counter");
}

static int aegisxd_policy_poll_route_rule_counter(sqlite3 *db,
                                                  const char *source_name,
                                                  int *rules_seen,
                                                  int *samples_seen)
{
    sqlite3_stmt *st = NULL;
    int imported = 0;
    int rows = 0;

    if (!db || !aegisxd_hits_table_exists(db, "route_rule_counter"))
        return 0;
    if (sqlite3_prepare_v2(db,
            "SELECT rule_id,name,action,target,hit_count,last_hit,updated_at "
            "FROM route_rule_counter ORDER BY prio,rule_id LIMIT 1000",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct aegisxd_policy_counter_row row;
        char state_key[240];
        int64_t last_seen;
        int64_t delta;

        memset(&row, 0, sizeof(row));
        snprintf(row.rule_id, sizeof(row.rule_id), "%s", aegisxd_sqlite_text(st, 0, ""));
        snprintf(row.rule_name, sizeof(row.rule_name), "%s", aegisxd_sqlite_text(st, 1, ""));
        snprintf(row.action, sizeof(row.action), "%s", aegisxd_sqlite_text(st, 2, "route"));
        snprintf(row.target, sizeof(row.target), "%s", aegisxd_sqlite_text(st, 3, ""));
        row.hit_count = sqlite3_column_int64(st, 4);
        row.last_hit = sqlite3_column_int64(st, 5);
        row.updated_at = sqlite3_column_int64(st, 6);
        if (!row.rule_id[0])
            continue;
        rows++;
        if (row.hit_count > 0)
            g_policy_verified_samples_seen++;
        aegisxd_hits_state_key(state_key, sizeof(state_key),
                               "policy_counter_last", source_name, row.rule_id);
        last_seen = aegisxd_hits_state_int64(state_key, -1);
        if (last_seen < 0) {
            aegisxd_hits_state_set_int64(state_key, row.hit_count);
            if (row.hit_count > 0)
                g_policy_baselined = 1;
            continue;
        }
        if (row.hit_count < last_seen) {
            aegisxd_hits_state_set_int64(state_key, row.hit_count);
            continue;
        }
        delta = row.hit_count - last_seen;
        if (delta > 0) {
            if (aegisxd_policy_insert_counter_event(&row, delta, source_name) == 0)
                imported++;
            aegisxd_hits_state_set_int64(state_key, row.hit_count);
        }
    }
    sqlite3_finalize(st);
    if (rules_seen)
        *rules_seen += rows;
    if (samples_seen)
        *samples_seen += rows;
    return imported;
}

static void aegisxd_policy_poll_db(const char *path, const char *source_name,
                                   int *sources_seen, int *rules_seen,
                                   int *samples_seen, int *imported)
{
    sqlite3 *db = NULL;
    char state_key[160];

    if (!path || !path[0] || access(path, R_OK) != 0)
        return;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        snprintf(g_policy_last_error, sizeof(g_policy_last_error),
                 "open_failed:%s", source_name ? source_name : path);
        if (db)
            sqlite3_close(db);
        return;
    }
    sqlite3_busy_timeout(db, 500);
    (*sources_seen)++;
    snprintf(state_key, sizeof(state_key), "policy_hit_last_%s_policy_route_hit_sample",
             source_name ? source_name : "db");
    *imported += aegisxd_policy_poll_policy_route_hit_sample(db, state_key,
        source_name, rules_seen);
    if (aegisxd_hits_table_exists(db, "policy_route_hit_sample")) {
        sqlite3_stmt *st = NULL;

        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM policy_route_hit_sample",
                               -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            {
                int c = sqlite3_column_int(st, 0);
                *samples_seen += c;
                g_policy_verified_samples_seen += c;
            }
        if (st)
            sqlite3_finalize(st);
    }
    snprintf(state_key, sizeof(state_key), "policy_hit_last_%s_route_decision_sample",
             source_name ? source_name : "db");
    *imported += aegisxd_policy_poll_route_decision_sample(db, state_key,
        source_name, rules_seen);
    if (aegisxd_hits_table_exists(db, "route_decision_sample")) {
        sqlite3_stmt *st = NULL;

        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM route_decision_sample",
                               -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            *samples_seen += sqlite3_column_int(st, 0);
        if (st)
            sqlite3_finalize(st);
    }
    *imported += aegisxd_policy_poll_route_rule_counter(db, source_name,
        rules_seen, samples_seen);
    sqlite3_close(db);
}

static void aegisxd_policy_poll_hits(void)
{
    int sources_seen = 0;
    int rules_seen = 0;
    int samples_seen = 0;
    int imported = 0;

    g_policy_verified_samples_seen = 0;
    g_policy_route_decision_samples_seen = 0;
    g_policy_route_decision_samples_imported = 0;
    g_policy_route_decision_samples_skipped = 0;
    g_policy_route_decision_candidate_seen = 0;

    aegisxd_policy_poll_db(AEGISXD_POLICY_DB_PATH, "dreamingwrt_db",
                           &sources_seen, &rules_seen, &samples_seen, &imported);
    aegisxd_policy_poll_db(AEGISXD_POLICY_CONFIG_DB_PATH, "config_db",
                           &sources_seen, &rules_seen, &samples_seen, &imported);
    aegisxd_policy_poll_db(AEGISXD_POLICY_FLOW_DB_PATH, "flow_db",
                           &sources_seen, &rules_seen, &samples_seen, &imported);
    aegisxd_policy_poll_db(AEGISXD_POLICY_ROUTE_DB_PATH, "route_state_db",
                           &sources_seen, &rules_seen, &samples_seen, &imported);
    g_policy_sources_seen = sources_seen;
    g_policy_rules_seen = rules_seen;
    g_policy_samples_seen = samples_seen;
    if (sources_seen <= 0)
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "policy_sources_missing");
    else if (samples_seen <= 0)
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "no_policy_hit_samples");
    else if (imported > 0)
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "");
    else if (g_policy_route_decision_candidate_seen > 0 && g_policy_verified_samples_seen <= 0)
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "candidate_route_decisions_skipped");
    else if (g_policy_verified_samples_seen <= 0)
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "no_verified_policy_hit_samples");
    else if (g_policy_baselined)
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "baseline_only");
    else
        snprintf(g_policy_last_error, sizeof(g_policy_last_error), "%s", "no_new_policy_hit_samples");
}

static int aegisxd_nft_parse_counter_line(const char *line, char *rule_id,
                                          size_t rule_id_len, char *rule_name,
                                          size_t rule_name_len,
                                          uint64_t *packets, uint64_t *bytes)
{
    const char *p;
    const char *c;
    char comment[160] = "";
    char *end = NULL;
    unsigned long long pkt;
    unsigned long long byt;
    size_t n = 0;

    if (!line || !rule_id || !rule_name || !packets || !bytes)
        return 0;
    p = strstr(line, "counter packets ");
    c = strstr(line, " comment \"");
    if (!p || !c || !strstr(line, "dreamingwrt-aegis"))
        return 0;
    p += strlen("counter packets ");
    pkt = strtoull(p, &end, 10);
    if (!end || strncmp(end, " bytes ", 7))
        return 0;
    p = end + 7;
    byt = strtoull(p, &end, 10);
    if (!end)
        return 0;
    c += strlen(" comment \"");
    while (*c && *c != '"' && n + 1 < sizeof(comment))
        comment[n++] = *c++;
    comment[n] = 0;
    p = aegisxd_nft_rule_id_from_comment(comment);
    if (!p || !p[0])
        return 0;
    snprintf(rule_id, rule_id_len, "%s", p);
    snprintf(rule_name, rule_name_len, "%s", comment);
    *packets = (uint64_t)pkt;
    *bytes = (uint64_t)byt;
    return 1;
}

static void aegisxd_nft_poll_counters(void)
{
    char *argv[] = { (char *)AEGISXD_NFT_PATH, "list", "table", "inet",
                     (char *)AEGISXD_NFT_TABLE, NULL };
    char *output = NULL;
    char *line;
    char *line_save = NULL;
    int found = 0;

    if (!aegisxd_nft_active_state_present()) {
        g_nft_table_present = 0;
        snprintf(g_nft_last_error, sizeof(g_nft_last_error), "%s", "inactive_state_missing");
        return;
    }
    if (aegisxd_exec_capture_text_allow_exit(AEGISXD_NFT_PATH, argv,
                                             AEGISXD_EXEC_NFT_OUTPUT_MAX,
                                             &output) != 0) {
        g_nft_table_present = 0;
        snprintf(g_nft_last_error, sizeof(g_nft_last_error), "%s", "nft_command_failed");
        return;
    }
    for (line = strtok_r(output, "\r\n", &line_save); line;
         line = strtok_r(NULL, "\r\n", &line_save)) {
        char rule_id[96];
        char rule_name[160];
        uint64_t packets = 0;
        uint64_t bytes = 0;
        struct aegisxd_nft_counter_seen *seen;

        if (!aegisxd_nft_parse_counter_line(line, rule_id, sizeof(rule_id),
                                            rule_name, sizeof(rule_name),
                                            &packets, &bytes))
            continue;
        found++;
        seen = aegisxd_nft_seen_get(rule_id, rule_name);
        if (!seen)
            continue;
        if (seen->initialized && packets >= seen->packets && bytes >= seen->bytes &&
            packets > seen->packets) {
            (void)aegisxd_hits_insert_nft_counter_delta(rule_id, rule_name,
                packets - seen->packets, bytes - seen->bytes, packets, bytes);
        }
        seen->packets = packets;
        seen->bytes = bytes;
        seen->initialized = 1;
    }
    free(output);
    g_nft_counters_seen = found;
    g_nft_table_present = found > 0;
    snprintf(g_nft_last_error, sizeof(g_nft_last_error), "%s",
             found > 0 ? "" : "table_or_counters_missing");
}

static void aegisxd_parse_suricata_eve_line(const char *line)
{
    struct json_object *eve = NULL;
    int rc;

    if (!line || !line[0])
        return;
    g_suricata_lines_scanned++;
    eve = json_tokener_parse(line);
    if (!eve) {
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "invalid_eve_json");
        return;
    }
    rc = aegisxd_hits_insert_suricata_event(eve);
    if (rc == 0)
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "");
    else if (rc == -2)
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s",
                 "suricata_event_missing_required_producer_fields");
    json_object_put(eve);
}

static void aegisxd_suricata_read_eve(void)
{
    int fd;
    struct stat st;
    off_t file_size = 0;
    char buf[8192];
    char line[AEGISXD_HIT_MAX_LINE];
    ssize_t n;
    int used = 0;
    int budget = 0;
    int eof = 0;

    if (!aegisxd_suricata_active_state_present()) {
        g_suricata_offset = 0;
        g_suricata_inode_mtime = 0;
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "inactive_state_missing");
        return;
    }
    fd = open(AEGISXD_SURICATA_EVE_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "eve_missing");
        return;
    }
    if (fstat(fd, &st) == 0) {
        file_size = st.st_size;
        if (g_suricata_inode_mtime == 0 && g_suricata_offset == 0) {
            g_suricata_offset = file_size;
            g_suricata_inode_mtime = st.st_mtime;
            close(fd);
            snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "baseline_at_eof");
            return;
        }
        if (g_suricata_inode_mtime != st.st_mtime || g_suricata_offset > st.st_size) {
            if (g_suricata_offset > st.st_size)
                g_suricata_offset = 0;
            g_suricata_inode_mtime = st.st_mtime;
        }
    }
    if (lseek(fd, g_suricata_offset, SEEK_SET) < 0) {
        close(fd);
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "eve_seek_failed");
        return;
    }
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                line[used] = 0;
                if (used > 0)
                    aegisxd_parse_suricata_eve_line(line);
                used = 0;
            } else if (used + 1 < (int)sizeof(line)) {
                line[used++] = buf[i];
            } else {
                used = 0;
                snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "eve_line_too_long");
            }
        }
        budget += (int)n;
        if (budget >= AEGISXD_HIT_READ_BUDGET)
            break;
    }
    if (n == 0)
        eof = 1;
    g_suricata_offset = lseek(fd, 0, SEEK_CUR);
    close(fd);
    if (eof && file_size > AEGISXD_SURICATA_EVE_MAX_BYTES && g_suricata_offset >= file_size) {
        int wfd = open(AEGISXD_SURICATA_EVE_PATH, O_WRONLY | O_TRUNC | O_CLOEXEC);

        if (wfd >= 0)
            close(wfd);
        g_suricata_offset = 0;
        g_suricata_inode_mtime = 0;
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "eve_truncated_after_read");
    } else if (!g_suricata_last_error[0]) {
        snprintf(g_suricata_last_error, sizeof(g_suricata_last_error), "%s", "");
    }
}

static void aegisxd_hits_seen_remember(const char *serial, const char *domain,
                                       const char *source_ip, const char *qtype)
{
    struct aegisxd_dns_query_seen *s;
    char source_mac[32] = "";
    char in_interface[32] = "";
    char lookup_source[32] = "";

    if (!serial || !serial[0] || !domain || !domain[0])
        return;
    (void)aegisxd_hits_lookup_client_identity(source_ip,
        source_mac, sizeof(source_mac), in_interface, sizeof(in_interface),
        lookup_source, sizeof(lookup_source));
    s = &g_seen[g_seen_pos];
    snprintf(s->serial, sizeof(s->serial), "%s", serial);
    snprintf(s->domain, sizeof(s->domain), "%s", domain);
    snprintf(s->source_ip, sizeof(s->source_ip), "%s", source_ip ? source_ip : "");
    snprintf(s->source_mac, sizeof(s->source_mac), "%s", source_mac);
    snprintf(s->in_interface, sizeof(s->in_interface), "%s", in_interface);
    snprintf(s->client_lookup_source, sizeof(s->client_lookup_source), "%s", lookup_source);
    snprintf(s->qtype, sizeof(s->qtype), "%s", qtype ? qtype : "");
    s->ts = aegisxd_now_s();
    g_seen_pos = (g_seen_pos + 1) % (int)ARRAY_SIZE(g_seen);
}

static struct aegisxd_dns_query_seen *aegisxd_hits_seen_find(const char *serial)
{
    int64_t now = aegisxd_now_s();

    if (!serial || !serial[0])
        return NULL;
    for (size_t i = 0; i < ARRAY_SIZE(g_seen); i++) {
        if (g_seen[i].serial[0] && !strcmp(g_seen[i].serial, serial) &&
            now - g_seen[i].ts <= 30)
            return &g_seen[i];
    }
    return NULL;
}

static int aegisxd_parse_dnsmasq_serial(const char *line, char *serial, size_t serial_len)
{
    const char *p;
    size_t n = 0;

    if (!line || !serial || serial_len == 0)
        return -1;
    serial[0] = 0;
    p = strstr(line, "dnsmasq[");
    if (!p)
        p = strstr(line, "dnsmasq-dhcp[");
    if (!p)
        return -1;
    p = strchr(p, ':');
    if (!p)
        return -1;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    while (isdigit((unsigned char)*p) && n + 1 < serial_len) {
        serial[n++] = *p++;
    }
    serial[n] = 0;
    return n > 0 ? 0 : -1;
}

static void aegisxd_parse_dnsmasq_query_line(const char *line)
{
    char serial[32];
    char domain[256];
    char source_ip[64];
    char qtype[16];
    const char *q;
    const char *from;
    int n;

    if (!line || !strstr(line, " query["))
        return;
    if (aegisxd_parse_dnsmasq_serial(line, serial, sizeof(serial)) != 0)
        return;
    q = strstr(line, " query[");
    if (!q)
        return;
    q += strlen(" query[");
    n = 0;
    while (*q && *q != ']' && n + 1 < (int)sizeof(qtype))
        qtype[n++] = *q++;
    qtype[n] = 0;
    if (*q == ']')
        q++;
    while (*q && isspace((unsigned char)*q))
        q++;
    n = 0;
    while (*q && !isspace((unsigned char)*q) && n + 1 < (int)sizeof(domain))
        domain[n++] = (char)tolower((unsigned char)*q++);
    domain[n] = 0;
    aegisxd_hits_trim_domain(domain);
    from = strstr(q, " from ");
    source_ip[0] = 0;
    if (from) {
        from += strlen(" from ");
        n = 0;
        while (*from && !isspace((unsigned char)*from) && n + 1 < (int)sizeof(source_ip))
            source_ip[n++] = *from++;
        source_ip[n] = 0;
    }
    if (!aegisxd_hits_domain_ok(domain))
        return;
    aegisxd_hits_seen_remember(serial, domain, source_ip, qtype);
    (void)aegisxd_hits_insert_dns_event(domain, source_ip, "", "", "", qtype, 1);
}

static void aegisxd_parse_dnsmasq_config_line(const char *line)
{
    char serial[32];
    char domain[256] = "";
    char dest[80] = "";
    struct aegisxd_dns_query_seen *seen = NULL;
    const char *p;
    int n;

    if (!line || !strstr(line, " config "))
        return;
    if (!strstr(line, " is 0.0.0.0") && !strstr(line, " is ::"))
        return;
    if (aegisxd_parse_dnsmasq_serial(line, serial, sizeof(serial)) != 0)
        return;
    p = strstr(line, " config ");
    if (!p)
        return;
    p += strlen(" config ");
    n = 0;
    while (*p && !isspace((unsigned char)*p) && n + 1 < (int)sizeof(domain))
        domain[n++] = (char)tolower((unsigned char)*p++);
    domain[n] = 0;
    aegisxd_hits_trim_domain(domain);
    p = strstr(p, " is ");
    if (p) {
        p += strlen(" is ");
        n = 0;
        while (*p && !isspace((unsigned char)*p) && n + 1 < (int)sizeof(dest))
            dest[n++] = *p++;
        dest[n] = 0;
    }
    if (strcmp(dest, "0.0.0.0") && strcmp(dest, "::"))
        return;
    seen = aegisxd_hits_seen_find(serial);
    if (seen && seen->domain[0])
        snprintf(domain, sizeof(domain), "%s", seen->domain);
    if (!aegisxd_hits_domain_ok(domain))
        return;
    (void)aegisxd_hits_insert_dns_event(domain,
        seen ? seen->source_ip : "",
        seen ? seen->source_mac : "",
        seen ? seen->in_interface : "",
        seen ? seen->client_lookup_source : "",
        seen ? seen->qtype : "", 0);
}

static void aegisxd_parse_dnsmasq_log_line(const char *line)
{
    g_lines_scanned++;
    aegisxd_parse_dnsmasq_query_line(line);
    aegisxd_parse_dnsmasq_config_line(line);
}

static void aegisxd_hits_read_log(void)
{
    int fd;
    struct stat st;
    off_t file_size = 0;
    char buf[8192];
    ssize_t n;
    int budget = 0;
    int eof = 0;

    if (!aegisxd_active_state_present()) {
        aegisxd_hits_follow_from_eof();
        memset(g_seen, 0, sizeof(g_seen));
        return;
    }
    fd = open(AEGISXD_DNSMASQ_LOG_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    if (fstat(fd, &st) == 0) {
        file_size = st.st_size;
        if (!g_hit_file_initialized) {
            /* Existing bytes predate this producer process and must not be replayed. */
            g_hit_offset = st.st_size;
            g_hit_device = st.st_dev;
            g_hit_inode = st.st_ino;
            g_hit_file_initialized = 1;
        } else if (g_hit_device != st.st_dev || g_hit_inode != st.st_ino ||
                   g_hit_offset > st.st_size) {
            g_hit_offset = 0;
            g_hit_device = st.st_dev;
            g_hit_inode = st.st_ino;
            g_hit_partial_len = 0;
            g_hit_partial_dropping = 0;
            memset(g_seen, 0, sizeof(g_seen));
        }
    }
    if (lseek(fd, g_hit_offset, SEEK_SET) < 0) {
        close(fd);
        return;
    }
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                if (!g_hit_partial_dropping && g_hit_partial_len > 0) {
                    g_hit_partial[g_hit_partial_len] = 0;
                    aegisxd_parse_dnsmasq_log_line(g_hit_partial);
                }
                g_hit_partial_len = 0;
                g_hit_partial_dropping = 0;
            } else if (!g_hit_partial_dropping &&
                       g_hit_partial_len + 1 < (int)sizeof(g_hit_partial)) {
                g_hit_partial[g_hit_partial_len++] = buf[i];
            } else {
                g_hit_partial_len = 0;
                g_hit_partial_dropping = 1;
            }
        }
        budget += (int)n;
        if (budget >= AEGISXD_HIT_READ_BUDGET)
            break;
    }
    if (n == 0)
        eof = 1;
    g_hit_offset = lseek(fd, 0, SEEK_CUR);
    close(fd);
    if (eof && file_size > AEGISXD_HIT_LOG_MAX_BYTES && g_hit_offset >= file_size) {
        int wfd = open(AEGISXD_DNSMASQ_LOG_PATH, O_WRONLY | O_TRUNC | O_CLOEXEC);

        if (wfd >= 0)
            close(wfd);
        g_hit_offset = 0;
        g_hit_partial_len = 0;
        g_hit_partial_dropping = 0;
    }
}

static void aegisxd_hit_tick(struct uloop_timeout *t)
{
    int64_t now = aegisxd_now_s();

    (void)t;
    aegisxd_hits_read_log();
    if (now - g_nft_last_poll_at >= AEGISXD_NFT_HIT_POLL_S) {
        g_nft_last_poll_at = now;
        aegisxd_nft_poll_counters();
    }
    if (now - g_reputation_flow_last_poll_at >= AEGISXD_REPUTATION_FLOW_POLL_S) {
        g_reputation_flow_last_poll_at = now;
        aegisxd_reputation_flow_poll();
    }
    if (now - g_policy_last_poll_at >= AEGISXD_POLICY_HIT_POLL_S) {
        g_policy_last_poll_at = now;
        aegisxd_policy_poll_hits();
    }
    if (aegisxd_suricata_active_state_present()) {
        g_suricata_last_poll_at = now;
        aegisxd_suricata_read_eve();
    }
    if (g_hit_started)
        uloop_timeout_set(&g_hit_timer, AEGISXD_HIT_TICK_MS);
}

void aegisxd_hit_producer_start(void)
{
    if (g_hit_started)
        return;
    memset(&g_hit_timer, 0, sizeof(g_hit_timer));
    g_hit_timer.cb = aegisxd_hit_tick;
    g_hit_started = 1;
    aegisxd_hits_follow_from_eof();
    uloop_timeout_set(&g_hit_timer, AEGISXD_HIT_TICK_MS);
}

void aegisxd_hit_producer_stop(void)
{
    if (!g_hit_started)
        return;
    g_hit_started = 0;
    uloop_timeout_cancel(&g_hit_timer);
}

struct json_object *aegisxd_dns_hit_producer_status_json(void)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "started", json_object_new_boolean(g_hit_started));
    json_object_object_add(o, "active", json_object_new_boolean(aegisxd_dns_hit_producer_active()));
    json_object_object_add(o, "active_state_present", json_object_new_boolean(aegisxd_active_state_present()));
    json_object_object_add(o, "log_present", json_object_new_boolean(aegisxd_dns_log_present()));
    aegisxd_json_add_string(o, "log_path", AEGISXD_DNSMASQ_LOG_PATH);
    json_object_object_add(o, "last_event_at",
                           g_last_event_at > 0 ? json_object_new_int64(g_last_event_at) : json_object_new_null());
    json_object_object_add(o, "last_event_id",
                           g_last_event_id > 0 ? json_object_new_int(g_last_event_id) : json_object_new_null());
    json_object_object_add(o, "events_inserted", json_object_new_int(g_events_inserted));
    json_object_object_add(o, "events_aggregated", json_object_new_int(g_events_aggregated));
    json_object_object_add(o, "events_unattributed_ignored",
                           json_object_new_int(g_events_unattributed));
    json_object_object_add(o, "lines_scanned", json_object_new_int(g_lines_scanned));
    json_object_object_add(o, "aggregation_window_sec", json_object_new_int(AEGISXD_HIT_DEDUPE_S));
    json_object_object_add(o, "restart_replay_prevented", json_object_new_boolean(1));
    json_object_object_add(o, "inode_rotation_supported", json_object_new_boolean(1));
    json_object_object_add(o, "partial_line_buffering_supported", json_object_new_boolean(1));
    json_object_object_add(o, "work_log_max_bytes", json_object_new_int(AEGISXD_HIT_LOG_MAX_BYTES));
    json_object_object_add(o, "retention_days", json_object_new_int(AEGISXD_HIT_EVENT_RETENTION_DAYS));
    json_object_object_add(o, "max_events", json_object_new_int(AEGISXD_HIT_EVENT_MAX_ROWS));
    return o;
}

struct json_object *aegisxd_nft_hit_producer_status_json(void)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "started", json_object_new_boolean(g_hit_started));
    json_object_object_add(o, "active", json_object_new_boolean(aegisxd_nft_hit_producer_active()));
    json_object_object_add(o, "active_state_present", json_object_new_boolean(aegisxd_nft_active_state_present()));
    json_object_object_add(o, "table_present", json_object_new_boolean(g_nft_table_present));
    aegisxd_json_add_string(o, "table", AEGISXD_NFT_TABLE);
    aegisxd_json_add_string(o, "active_state_path", AEGISXD_NFT_ACTIVE_FILE);
    json_object_object_add(o, "counters_seen", json_object_new_int(g_nft_counters_seen));
    json_object_object_add(o, "last_poll_at",
                           g_nft_last_poll_at > 0 ? json_object_new_int64(g_nft_last_poll_at) : json_object_new_null());
    json_object_object_add(o, "last_event_at",
                           g_nft_last_event_at > 0 ? json_object_new_int64(g_nft_last_event_at) : json_object_new_null());
    json_object_object_add(o, "last_event_id",
                           g_nft_last_event_id > 0 ? json_object_new_int(g_nft_last_event_id) : json_object_new_null());
    json_object_object_add(o, "events_inserted", json_object_new_int(g_nft_events_inserted));
    json_object_object_add(o, "poll_interval_sec", json_object_new_int(AEGISXD_NFT_HIT_POLL_S));
    json_object_object_add(o, "aggregate_only", json_object_new_boolean(1));
    aegisxd_json_add_string(o, "precision", "aggregate_rule_counter");
    json_object_object_add(o, "per_flow_supported", json_object_new_boolean(1));
    json_object_object_add(o, "per_flow_active",
                           json_object_new_boolean(aegisxd_reputation_flow_producer_active()));
    json_object_object_add(o, "per_flow_events_inserted",
                           json_object_new_int(g_reputation_flow_events_inserted));
    json_object_object_add(o, "per_flow_flows_scanned",
                           json_object_new_int(g_reputation_flow_flows_scanned));
    json_object_object_add(o, "per_flow_matches_seen",
                           json_object_new_int(g_reputation_flow_matches_seen));
    json_object_object_add(o, "per_flow_feed_ips",
                           json_object_new_int(g_reputation_flow_feed_ips));
    json_object_object_add(o, "per_flow_poll_interval_sec",
                           json_object_new_int(AEGISXD_REPUTATION_FLOW_POLL_S));
    json_object_object_add(o, "per_flow_max_scan",
                           json_object_new_int(AEGISXD_REPUTATION_FLOW_MAX_SCAN));
    json_object_object_add(o, "per_flow_last_poll_at",
                           g_reputation_flow_last_poll_at > 0 ?
                           json_object_new_int64(g_reputation_flow_last_poll_at) :
                           json_object_new_null());
    json_object_object_add(o, "per_flow_last_event_at",
                           g_reputation_flow_last_event_at > 0 ?
                           json_object_new_int64(g_reputation_flow_last_event_at) :
                           json_object_new_null());
    json_object_object_add(o, "per_flow_last_event_id",
                           g_reputation_flow_last_event_id > 0 ?
                           json_object_new_int(g_reputation_flow_last_event_id) :
                           json_object_new_null());
    aegisxd_json_add_string(o, "per_flow_precision", "conntrack_flow_snapshot");
    aegisxd_json_add_string(o, "per_flow_last_error", g_reputation_flow_last_error);
    aegisxd_json_add_string(o, "last_error", g_nft_last_error);
    return o;
}

struct json_object *aegisxd_suricata_hit_producer_status_json(void)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "started", json_object_new_boolean(g_hit_started));
    json_object_object_add(o, "active", json_object_new_boolean(aegisxd_suricata_hit_producer_active()));
    json_object_object_add(o, "active_state_present", json_object_new_boolean(aegisxd_suricata_active_state_present()));
    json_object_object_add(o, "eve_present", json_object_new_boolean(aegisxd_suricata_eve_present()));
    json_object_object_add(o, "pid_running", json_object_new_boolean(aegisxd_suricata_pid_running()));
    json_object_object_add(o, "production_active", json_object_new_boolean(aegisxd_suricata_hit_producer_active()));
    aegisxd_json_add_string(o, "active_state_path", AEGISXD_SURICATA_ACTIVE_PATH);
    aegisxd_json_add_string(o, "eve_path", AEGISXD_SURICATA_EVE_PATH);
    aegisxd_json_add_string(o, "pid_path", AEGISXD_SURICATA_PID_PATH);
    json_object_object_add(o, "last_poll_at",
                           g_suricata_last_poll_at > 0 ? json_object_new_int64(g_suricata_last_poll_at) : json_object_new_null());
    json_object_object_add(o, "last_event_at",
                           g_suricata_last_event_at > 0 ? json_object_new_int64(g_suricata_last_event_at) : json_object_new_null());
    json_object_object_add(o, "last_event_id",
                           g_suricata_last_event_id > 0 ? json_object_new_int(g_suricata_last_event_id) : json_object_new_null());
    json_object_object_add(o, "events_inserted", json_object_new_int(g_suricata_events_inserted));
    json_object_object_add(o, "lines_scanned", json_object_new_int(g_suricata_lines_scanned));
    json_object_object_add(o, "alerts_seen", json_object_new_int(g_suricata_alerts_seen));
    json_object_object_add(o, "manual_ingest_events", json_object_new_int(g_suricata_manual_ingest_events));
    json_object_object_add(o, "last_manual_ingest_at",
                           g_suricata_last_manual_ingest_at > 0 ?
                           json_object_new_int64(g_suricata_last_manual_ingest_at) : json_object_new_null());
    json_object_object_add(o, "manual_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(o, "manual_ingest_is_production", json_object_new_boolean(0));
    json_object_object_add(o, "test_events_are_production", json_object_new_boolean(0));
    json_object_object_add(o, "work_log_max_bytes", json_object_new_int(AEGISXD_SURICATA_EVE_MAX_BYTES));
    aegisxd_json_add_string(o, "precision", "eve_alert");
    aegisxd_json_add_string(o, "production_precision", "eve_alert");
    if (!aegisxd_suricata_active_state_present())
        aegisxd_json_add_string(o, "reason", "inactive_state_missing");
    else if (!aegisxd_suricata_pid_running())
        aegisxd_json_add_string(o, "reason", "suricata_process_not_running");
    else if (!aegisxd_suricata_eve_present())
        aegisxd_json_add_string(o, "reason", "eve_missing");
    else
        aegisxd_json_add_string(o, "reason", g_suricata_last_error);
    json_object_object_add(o, "degraded",
                           json_object_new_boolean(!aegisxd_suricata_hit_producer_active()));
    aegisxd_json_add_string(o, "last_error", g_suricata_last_error);
    return o;
}

struct json_object *aegisxd_policy_hit_producer_status_json(void)
{
    struct json_object *o = json_object_new_object();
    struct json_object *paths = json_object_new_object();
    int connected = aegisxd_policy_hit_producer_connected();
    int active = aegisxd_policy_hit_producer_active();

    json_object_object_add(o, "started", json_object_new_boolean(g_hit_started));
    json_object_object_add(o, "connected", json_object_new_boolean(connected));
    json_object_object_add(o, "active", json_object_new_boolean(active));
    json_object_object_add(o, "available", json_object_new_boolean(active));
    json_object_object_add(o, "sample_supported", json_object_new_boolean(active));
    json_object_object_add(o, "aggregate_counter_supported", json_object_new_boolean(connected));
    json_object_object_add(o, "event_supported", json_object_new_boolean(active));
    json_object_object_add(o, "sources_seen", json_object_new_int(g_policy_sources_seen));
    json_object_object_add(o, "rules_seen", json_object_new_int(g_policy_rules_seen));
    json_object_object_add(o, "samples_seen", json_object_new_int(g_policy_samples_seen));
    json_object_object_add(o, "verified_samples_seen", json_object_new_int(g_policy_verified_samples_seen));
    json_object_object_add(o, "candidate_samples_do_not_activate", json_object_new_boolean(1));
    json_object_object_add(o, "route_decision_sample_import_requires_verified", json_object_new_boolean(1));
    json_object_object_add(o, "route_decision_samples_seen", json_object_new_int(g_policy_route_decision_samples_seen));
    json_object_object_add(o, "route_decision_samples_imported", json_object_new_int(g_policy_route_decision_samples_imported));
    json_object_object_add(o, "route_decision_samples_skipped", json_object_new_int(g_policy_route_decision_samples_skipped));
    json_object_object_add(o, "candidate_route_decisions_seen", json_object_new_int(g_policy_route_decision_candidate_seen));
    if (!connected)
        aegisxd_json_add_string(o, "reason", "policy_sources_missing");
    else if (!active)
        aegisxd_json_add_string(o, "reason", g_policy_last_error[0] ? g_policy_last_error : "no_verified_policy_hit_samples");
    else
        aegisxd_json_add_string(o, "reason", "");
    json_object_object_add(o, "baseline_only", json_object_new_boolean(g_policy_baselined));
    json_object_object_add(o, "last_poll_at",
                           g_policy_last_poll_at > 0 ? json_object_new_int64(g_policy_last_poll_at) : json_object_new_null());
    json_object_object_add(o, "last_event_at",
                           g_policy_last_event_at > 0 ? json_object_new_int64(g_policy_last_event_at) : json_object_new_null());
    json_object_object_add(o, "last_event_id",
                           g_policy_last_event_id > 0 ? json_object_new_int(g_policy_last_event_id) : json_object_new_null());
    json_object_object_add(o, "events_inserted", json_object_new_int(g_policy_events_inserted));
    json_object_object_add(o, "poll_interval_sec", json_object_new_int(AEGISXD_POLICY_HIT_POLL_S));
    aegisxd_json_add_string(o, "precision", "policy_hit_sample_or_aggregate_rule_counter");
    aegisxd_json_add_string(o, "sample_precision", "policy_hit_sample");
    aegisxd_json_add_string(o, "route_decision_precision", "verified_route_decision_sample_only");
    aegisxd_json_add_string(o, "candidate_decision_policy", "skip_not_security_event");
    aegisxd_json_add_string(o, "counter_precision", "aggregate_rule_counter");
    aegisxd_json_add_string(o, "last_error", g_policy_last_error);
    aegisxd_json_add_string(paths, "dreamingwrt_db", AEGISXD_POLICY_DB_PATH);
    aegisxd_json_add_string(paths, "config_db", AEGISXD_POLICY_CONFIG_DB_PATH);
    aegisxd_json_add_string(paths, "flow_db", AEGISXD_POLICY_FLOW_DB_PATH);
    aegisxd_json_add_string(paths, "route_state_db", AEGISXD_POLICY_ROUTE_DB_PATH);
    json_object_object_add(o, "paths", paths);
    return o;
}
