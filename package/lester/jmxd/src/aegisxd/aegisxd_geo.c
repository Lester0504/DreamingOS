// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"
#include "../geoip/mmdb_country_prefix.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/statvfs.h>

#define GEO_MMDB_PATH "/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb"
#define GEO_NFT_TABLE "dreamingwrt_aegis_geo"
#define GEO_LOCK_PATH AEGISXD_RUNTIME_DIR "/geo.lock"
#define GEO_NFT_PATH AEGISXD_RUNTIME_DIR "/geo-current.nft"
#define GEO_ACTIVE_PATH AEGISXD_RUNTIME_DIR "/geo-active.json"
#define GEO_LEGACY_READBACK_PATH AEGISXD_RUNTIME_DIR "/geo-nft-readback.json"
#define GEO_PREVIOUS_NFT_PATH AEGISXD_RUNTIME_DIR "/geo-previous.nft"
#define GEO_PREVIOUS_ACTIVE_PATH AEGISXD_RUNTIME_DIR "/geo-previous-active.json"
#define GEO_PREVIOUS_META_PATH AEGISXD_RUNTIME_DIR "/geo-previous.json"
#define GEO_NFT_LOG AEGISXD_RUNTIME_DIR "/geo-nft.log"
#define GEO_MAX_COUNTRIES 249
#define GEO_MAX_RULES 64
#define GEO_MAX_IFACES 64
#define GEO_MMDB_MAX_BYTES (128ULL * 1024ULL * 1024ULL)
#define GEO_SELECTED_PREFIX_MAX 1000000ULL
#define GEO_MMDB_TIMEOUT_MS 30000ULL
#ifndef GEO_NFT_TIMEOUT_MS
#define GEO_NFT_TIMEOUT_MS 30000ULL
#endif
#ifndef GEO_NFT_FILE_MAX_BYTES
#define GEO_NFT_FILE_MAX_BYTES (192ULL * 1024ULL * 1024ULL)
#endif
#ifndef GEO_NFT_LOG_MAX_BYTES
#define GEO_NFT_LOG_MAX_BYTES (1ULL * 1024ULL * 1024ULL)
#endif
#ifndef GEO_RUNTIME_RESERVE_BYTES
#define GEO_RUNTIME_RESERVE_BYTES (128ULL * 1024ULL * 1024ULL)
#endif
#define GEO_RUNTIME_METADATA_BYTES (4ULL * 1024ULL * 1024ULL)
#ifndef GEO_READBACK_MAX_BYTES
#define GEO_READBACK_MAX_BYTES (256ULL * 1024ULL * 1024ULL)
#endif
#ifndef GEO_READBACK_TIMEOUT_MS
#define GEO_READBACK_TIMEOUT_MS 30000ULL
#endif
#ifndef GEO_READBACK_CHUNK_BYTES
#define GEO_READBACK_CHUNK_BYTES 16384U
#endif
#ifndef GEO_JSON_MAX_DEPTH
#define GEO_JSON_MAX_DEPTH 128U
#endif
#ifndef GEO_JSON_TOKEN_BYTES
#define GEO_JSON_TOKEN_BYTES 256U
#endif
#ifndef GEO_JSON_MAX_TOKENS
#define GEO_JSON_MAX_TOKENS 16000000ULL
#endif
#ifndef GEO_READBACK_MAX_ELEMENTS
#define GEO_READBACK_MAX_ELEMENTS ((int64_t)GEO_SELECTED_PREFIX_MAX)
#endif
#define GEO_READBACK_MAX_SETS (GEO_MAX_COUNTRIES * 2)
#define GEO_READBACK_MAX_RULES (GEO_MAX_RULES * GEO_MAX_COUNTRIES * 4)

/* nft 1.1.6 prefix JSON costs at least seven structural/key/value tokens. */
_Static_assert(GEO_JSON_MAX_TOKENS >=
               (7ULL * (uint64_t)GEO_SELECTED_PREFIX_MAX + 65536ULL),
               "Geo JSON token limit must cover every materializable prefix");

struct geo_runtime_set {
    char name[16];
    int64_t element_count;
};

/* Counter readback is attributed with the generated
 * `aegis_geo:<rule_id>:<direction>:<COUNTRY>` comment written by
 * geo_write_rule_line(), so every packet/byte total belongs to an exact rule,
 * direction and country. Nothing is inferred from rule order or nft handles.
 *
 * A single apply can materialize GEO_MAX_RULES * GEO_MAX_COUNTRIES * 4 rule
 * lines, so per-line records are never retained. Totals are folded into fixed
 * per-rule and per-country buckets while streaming, keeping this parser
 * stack-safe and independent of table size.
 */
struct geo_counter_totals {
    uint64_t inbound_packets;
    uint64_t inbound_bytes;
    uint64_t outbound_packets;
    uint64_t outbound_bytes;
    int rule_lines;
    int counter_lines;
};

struct geo_rule_counter {
    char rule_id[65];
    struct geo_counter_totals totals;
};

struct geo_country_counter {
    char country[3];
    struct geo_counter_totals totals;
};

struct geo_country {
    char code[3];
    int ipv4_prefixes;
    int ipv6_prefixes;
};

struct geo_ifaces {
    char names[GEO_MAX_IFACES][64];
    int count;
};

struct geo_rule {
    char id[65];
    char action[8];
    char direction[9];
    char src_zone[65];
    char dst_zone[65];
    struct geo_ifaces src;
    struct geo_ifaces dst;
};

struct geo_plan {
    sqlite3 *config_db;
    struct dwrt_geoip_prefix_list prefixes;
    struct dwrt_geoip_stats prefix_stats;
    int64_t revision;
    struct geo_country countries[GEO_MAX_COUNTRIES];
    int country_count;
    struct geo_rule rules[GEO_MAX_RULES];
    int rule_count;
    int set_count;
    int64_t prefix_count;
    int compiled_rule_count;
    char blocker[128];
    char blocker_detail[256];
};

struct geo_runtime_counts {
    int table_found;
    int set_count;
    int rule_count;
    int64_t element_count;
    struct geo_runtime_set sets[GEO_READBACK_MAX_SETS];
    struct geo_counter_totals counter_totals;
    struct geo_rule_counter rule_counters[GEO_MAX_RULES];
    int rule_counter_count;
    struct geo_country_counter country_counters[GEO_MAX_COUNTRIES];
    int country_counter_count;
    int owned_rule_lines;
    int foreign_rule_lines;
    int rule_lines_without_counter;
    int rule_counter_bucket_overflow;
};

struct geo_runtime_space {
    uint64_t required_bytes;
    uint64_t available_bytes;
    uint64_t artifact_estimate_bytes;
    uint64_t snapshot_estimate_bytes;
    int ok;
    char reason[64];
};

struct geo_prefix_cache {
    struct dwrt_geoip_prefix_list prefixes;
    struct dwrt_geoip_stats stats;
    dev_t device;
    ino_t inode;
    off_t size;
    time_t mtime;
    char countries[GEO_MAX_COUNTRIES][3];
    int country_count;
    int valid;
};

static struct geo_prefix_cache g_geo_prefix_cache;

static uint64_t geo_monotonic_ms(void);
static int geo_readback_child_reap(pid_t pid, int terminate, uint64_t deadline,
                                   int *status_out);
static int geo_nft_run(char *const argv[], const char *output_path);

static const char *geo_nft_binary(void)
{
    static const char *paths[] = { "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft" };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(paths); i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return "";
}

static int geo_safe_token(const char *s, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t n;

    if (!s || !s[0] || (n = strlen(s)) > max_len)
        return 0;
    for (; *p; p++)
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.' &&
            *p != ':' && *p != '@')
            return 0;
    return 1;
}

static void geo_plan_block(struct geo_plan *plan, const char *code, const char *detail)
{
    if (!plan || plan->blocker[0])
        return;
    snprintf(plan->blocker, sizeof(plan->blocker), "%s", code ? code : "geo_plan_failed");
    snprintf(plan->blocker_detail, sizeof(plan->blocker_detail), "%s", detail ? detail : "");
}

static int geo_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!db || !name || sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int geo_open_readonly(const char *path, sqlite3 **out)
{
    sqlite3 *db = NULL;

    if (!path || !out || sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 1500);
    *out = db;
    return 0;
}

static void geo_plan_close(struct geo_plan *plan)
{
    if (!plan)
        return;
    if (plan->config_db)
        sqlite3_close(plan->config_db);
    plan->config_db = NULL;
    memset(&plan->prefixes, 0, sizeof(plan->prefixes));
}

static int geo_ifaces_add(struct geo_ifaces *ifaces, const char *name)
{
    int i;

    if (!ifaces || !geo_safe_token(name, 63))
        return -1;
    for (i = 0; i < ifaces->count; i++)
        if (!strcmp(ifaces->names[i], name))
            return 0;
    if (ifaces->count >= GEO_MAX_IFACES)
        return -1;
    snprintf(ifaces->names[ifaces->count++], sizeof(ifaces->names[0]), "%s", name);
    return 0;
}

static int geo_zone_is_any(const char *zone)
{
    return !zone || !zone[0];
}

static int geo_zone_load_table(sqlite3 *db, const char *table, const char *id,
                               struct geo_ifaces *ifaces)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int rc;

    if (snprintf(sql, sizeof(sql),
                 id ? "SELECT ifname FROM %s WHERE enabled=1 AND id=?1 ORDER BY id" :
                      "SELECT ifname FROM %s WHERE enabled=1 ORDER BY id", table) >= (int)sizeof(sql) ||
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (id)
        sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 0);
        if (!name || geo_ifaces_add(ifaces, name) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int geo_zone_resolve(sqlite3 *db, const char *zone, struct geo_ifaces *ifaces)
{
    if (!db || !ifaces)
        return -1;
    memset(ifaces, 0, sizeof(*ifaces));
    if (geo_zone_is_any(zone))
        return 0;
    if (!geo_safe_token(zone, 64))
        return -1;
    if (!strcmp(zone, "wan")) {
        if (geo_zone_load_table(db, "wan", NULL, ifaces) != 0)
            return -1;
    } else if (!strcmp(zone, "lan")) {
        if (geo_zone_load_table(db, "lan", NULL, ifaces) != 0)
            return -1;
    } else {
        if (geo_zone_load_table(db, "wan", zone, ifaces) != 0 ||
            geo_zone_load_table(db, "lan", zone, ifaces) != 0)
            return -1;
    }
    return ifaces->count > 0 ? 0 : -1;
}

static int geo_load_revision(sqlite3 *db, int64_t *revision)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || !revision || sqlite3_prepare_v2(db,
        "SELECT revision FROM firewall_geo_meta WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *revision = sqlite3_column_int64(st, 0);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int geo_load_mmdb_prefixes(struct geo_plan *plan)
{
    char selected[GEO_MAX_COUNTRIES][3];
    int country_index[26][26];
    struct dwrt_geoip_options options;
    struct dwrt_geoip_prefix_list loaded;
    struct dwrt_geoip_stats loaded_stats;
    struct stat st;
    char detail[256] = "";
    int rc;
    size_t prefix_index;
    int i;

    memset(&options, 0, sizeof(options));
    memset(country_index, 0xff, sizeof(country_index));
    for (i = 0; i < plan->country_count; i++) {
        memcpy(selected[i], plan->countries[i].code, 3);
        country_index[(unsigned)selected[i][0] - 'A'][(unsigned)selected[i][1] - 'A'] = i;
    }
    if (lstat(GEO_MMDB_PATH, &st) != 0) {
        geo_plan_block(plan, errno == ENOENT ? "mmdb_missing" : "mmdb_open_failed",
                       strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        geo_plan_block(plan, "mmdb_not_regular", "MMDB source must be a regular file");
        return -1;
    }
    if (g_geo_prefix_cache.valid && g_geo_prefix_cache.device == st.st_dev &&
        g_geo_prefix_cache.inode == st.st_ino && g_geo_prefix_cache.size == st.st_size &&
        g_geo_prefix_cache.mtime == st.st_mtime &&
        g_geo_prefix_cache.country_count == plan->country_count &&
        !memcmp(g_geo_prefix_cache.countries, selected,
                (size_t)plan->country_count * sizeof(selected[0]))) {
        plan->prefixes = g_geo_prefix_cache.prefixes;
        plan->prefix_stats = g_geo_prefix_cache.stats;
        goto count_prefixes;
    }
    options.countries = (const char (*)[3])selected;
    options.country_count = (size_t)plan->country_count;
    options.max_nodes = DWRT_GEOIP_DEFAULT_MAX_NODES;
    options.max_prefixes = GEO_SELECTED_PREFIX_MAX;
    options.timeout_ms = GEO_MMDB_TIMEOUT_MS;
    options.max_source_bytes = GEO_MMDB_MAX_BYTES;
    options.merge = 1;
    memset(&loaded, 0, sizeof(loaded));
    memset(&loaded_stats, 0, sizeof(loaded_stats));
    rc = dwrt_geoip_country_prefix_load(GEO_MMDB_PATH, &options, &loaded,
                                        &loaded_stats, detail, sizeof(detail));
    if (rc != DWRT_GEOIP_OK) {
        geo_plan_block(plan, dwrt_geoip_status_code(rc), detail);
        return -1;
    }
    {
        struct stat after;
        if (lstat(GEO_MMDB_PATH, &after) != 0 || !S_ISREG(after.st_mode) ||
            after.st_dev != st.st_dev || after.st_ino != st.st_ino ||
            after.st_size != st.st_size || after.st_mtime != st.st_mtime) {
            dwrt_geoip_prefix_list_free(&loaded);
            geo_plan_block(plan, "mmdb_changed_during_compile",
                           "MMDB authority changed while compiling selected countries");
            return -1;
        }
    }
    dwrt_geoip_prefix_list_free(&g_geo_prefix_cache.prefixes);
    memset(&g_geo_prefix_cache, 0, sizeof(g_geo_prefix_cache));
    g_geo_prefix_cache.prefixes = loaded;
    g_geo_prefix_cache.stats = loaded_stats;
    g_geo_prefix_cache.device = st.st_dev;
    g_geo_prefix_cache.inode = st.st_ino;
    g_geo_prefix_cache.size = st.st_size;
    g_geo_prefix_cache.mtime = st.st_mtime;
    memcpy(g_geo_prefix_cache.countries, selected,
           (size_t)plan->country_count * sizeof(selected[0]));
    g_geo_prefix_cache.country_count = plan->country_count;
    g_geo_prefix_cache.valid = 1;
    plan->prefixes = g_geo_prefix_cache.prefixes;
    plan->prefix_stats = g_geo_prefix_cache.stats;
count_prefixes:
    for (prefix_index = 0; prefix_index < plan->prefixes.count; prefix_index++) {
        const struct dwrt_geoip_prefix *prefix = &plan->prefixes.items[prefix_index];
        int index = country_index[(unsigned)prefix->iso_code[0] - 'A']
                                 [(unsigned)prefix->iso_code[1] - 'A'];

        if (index < 0 || index >= plan->country_count) {
            geo_plan_block(plan, "mmdb_country_filter_mismatch",
                           "selected-prefix output contains an unrequested country");
            return -1;
        }
        if ((prefix->family == 4 && plan->countries[index].ipv4_prefixes == INT_MAX) ||
            (prefix->family == 6 && plan->countries[index].ipv6_prefixes == INT_MAX)) {
            geo_plan_block(plan, "mmdb_prefix_limit", "country prefix count exceeds integer range");
            return -1;
        }
        if (prefix->family == 4)
            plan->countries[index].ipv4_prefixes++;
        else if (prefix->family == 6)
            plan->countries[index].ipv6_prefixes++;
        else {
            geo_plan_block(plan, "mmdb_invalid", "selected-prefix output has invalid family");
            return -1;
        }
        plan->prefix_count++;
    }
    for (i = 0; i < plan->country_count; i++) {
        if (plan->countries[i].ipv4_prefixes)
            plan->set_count++;
        if (plan->countries[i].ipv6_prefixes)
            plan->set_count++;
    }
    return 0;
}

static int geo_plan_load(struct geo_plan *plan)
{
    sqlite3_stmt *st = NULL;
    int rc;

    memset(plan, 0, sizeof(*plan));
    if (geo_open_readonly(AEGISXD_CONFIG_DB_PATH, &plan->config_db) != 0) {
        geo_plan_block(plan, "config_db_unavailable", AEGISXD_CONFIG_DB_PATH);
        return -1;
    }
    if (!geo_table_exists(plan->config_db, "firewall_geo_country") ||
        !geo_table_exists(plan->config_db, "firewall_geo_rule") ||
        !geo_table_exists(plan->config_db, "firewall_geo_meta") ||
        !geo_table_exists(plan->config_db, "wan") || !geo_table_exists(plan->config_db, "lan")) {
        geo_plan_block(plan, "geo_config_schema_missing", "required Geo/WAN/LAN authority table missing");
        return -1;
    }
    if (geo_load_revision(plan->config_db, &plan->revision) != 0) {
        geo_plan_block(plan, "geo_revision_unavailable", "firewall_geo_meta.id=1 missing");
        return -1;
    }
    if (sqlite3_prepare_v2(plan->config_db,
        "SELECT UPPER(COALESCE(NULLIF(code,''),id)) FROM firewall_geo_country "
        "WHERE enabled=1 AND official=1 "
        "ORDER BY UPPER(COALESCE(NULLIF(code,''),id)),id", -1, &st, NULL) != SQLITE_OK) {
        geo_plan_block(plan, "geo_country_query_failed", sqlite3_errmsg(plan->config_db));
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *code = (const char *)sqlite3_column_text(st, 0);
        if (plan->country_count >= GEO_MAX_COUNTRIES || !code || strlen(code) != 2 ||
            !isupper((unsigned char)code[0]) || !isupper((unsigned char)code[1])) {
            sqlite3_finalize(st);
            geo_plan_block(plan, "invalid_enabled_country", code ? code : "");
            return -1;
        }
        snprintf(plan->countries[plan->country_count++].code, 3, "%s", code);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE) {
        geo_plan_block(plan, "geo_country_query_failed", sqlite3_errmsg(plan->config_db));
        return -1;
    }
    if (plan->country_count <= 0) {
        geo_plan_block(plan, "enabled_geo_countries_empty", "enable at least one official country");
        return -1;
    }
    if (sqlite3_prepare_v2(plan->config_db,
        "SELECT id,action,direction,src_zone,dst_zone FROM firewall_geo_rule "
        "WHERE enabled=1 ORDER BY rowid,id", -1, &st, NULL) != SQLITE_OK) {
        geo_plan_block(plan, "geo_rule_query_failed", sqlite3_errmsg(plan->config_db));
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct geo_rule *rule;
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *action = (const char *)sqlite3_column_text(st, 1);
        const char *direction = (const char *)sqlite3_column_text(st, 2);
        const char *src_zone = (const char *)sqlite3_column_text(st, 3);
        const char *dst_zone = (const char *)sqlite3_column_text(st, 4);
        char detail[256];

        if (plan->rule_count >= GEO_MAX_RULES || !geo_safe_token(id, 64) ||
            (!action || (strcmp(action, "block") && strcmp(action, "allow"))) ||
            (!direction || (strcmp(direction, "inbound") && strcmp(direction, "outbound") &&
                            strcmp(direction, "both")))) {
            sqlite3_finalize(st);
            geo_plan_block(plan, "invalid_enabled_geo_rule", id ? id : "");
            return -1;
        }
        rule = &plan->rules[plan->rule_count];
        snprintf(rule->id, sizeof(rule->id), "%s", id);
        snprintf(rule->action, sizeof(rule->action), "%s", action);
        snprintf(rule->direction, sizeof(rule->direction), "%s", direction);
        snprintf(rule->src_zone, sizeof(rule->src_zone), "%s", src_zone ? src_zone : "");
        snprintf(rule->dst_zone, sizeof(rule->dst_zone), "%s", dst_zone ? dst_zone : "");
        if (geo_zone_resolve(plan->config_db, rule->src_zone, &rule->src) != 0) {
            snprintf(detail, sizeof(detail), "rule=%s side=src zone=%s", rule->id, rule->src_zone);
            sqlite3_finalize(st);
            geo_plan_block(plan, "geo_zone_unresolved", detail);
            return -1;
        }
        if (geo_zone_resolve(plan->config_db, rule->dst_zone, &rule->dst) != 0) {
            snprintf(detail, sizeof(detail), "rule=%s side=dst zone=%s", rule->id, rule->dst_zone);
            sqlite3_finalize(st);
            geo_plan_block(plan, "geo_zone_unresolved", detail);
            return -1;
        }
        plan->rule_count++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        geo_plan_block(plan, "geo_rule_query_failed", sqlite3_errmsg(plan->config_db));
        return -1;
    }
    if (plan->rule_count <= 0) {
        geo_plan_block(plan, "enabled_geo_rules_empty", "enable at least one Geo rule");
        return -1;
    }
    if (geo_load_mmdb_prefixes(plan) != 0 && !plan->blocker[0])
        geo_plan_block(plan, "mmdb_prefix_load_failed", GEO_MMDB_PATH);
    return plan->blocker[0] ? -1 : 0;
}

static int geo_log_contains(const char *needle)
{
    char buffer[4097];
    int fd;
    ssize_t n;

    if (!needle || (fd = open(GEO_NFT_LOG, O_RDONLY | O_CLOEXEC)) < 0)
        return 0;
    n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buffer[n] = '\0';
    return strstr(buffer, needle) != NULL;
}

static int geo_nft_table_state(void)
{
    const char *nft = geo_nft_binary();
    char *argv[] = { (char *)nft, "list", "table", "inet", GEO_NFT_TABLE, NULL };
    int rc;

    if (!nft[0])
        return -1;
    unlink(GEO_NFT_LOG);
    rc = geo_nft_run(argv, NULL);
    if (rc == 0)
        return 1;
    if (rc != 0 && (geo_log_contains("No such file or directory") ||
                    geo_log_contains("No such file")))
        return 0;
    return -1;
}

/* GEO_NFT_RUNNER_BEGIN */
static int geo_nft_run(char *const argv[], const char *output_path)
{
    unsigned char buf[16384];
    struct pollfd pfds[2];
    char tmp[AEGISXD_MAX_PATH] = {0};
    uint64_t started, stdout_bytes = 0, stderr_bytes = 0;
    int outpipe[2] = {-1, -1}, errpipe[2] = {-1, -1};
    int outfd = -1, logfd = -1, status = 0, failed = 0;
    int out_eof = 0, err_eof = 0, child_done = 0;
    pid_t pid;

    if (!argv || !argv[0] || pipe(outpipe) != 0 || pipe(errpipe) != 0)
        goto failed_before_fork;
    if (output_path) {
        if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", output_path, (long)getpid()) >=
            (int)sizeof(tmp) ||
            (outfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
            goto failed_before_fork;
    }
    logfd = open(GEO_NFT_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (logfd < 0)
        goto failed_before_fork;
    pid = fork();
    if (pid < 0)
        goto failed_before_fork;
    if (pid == 0) {
        close(outpipe[0]); close(errpipe[0]);
        if (dup2(outpipe[1], STDOUT_FILENO) < 0 ||
            dup2(errpipe[1], STDERR_FILENO) < 0)
            _exit(127);
        if (outpipe[1] > STDERR_FILENO) close(outpipe[1]);
        if (errpipe[1] > STDERR_FILENO) close(errpipe[1]);
        if (outfd >= 0) close(outfd);
        if (logfd >= 0) close(logfd);
        (void)setenv("LC_ALL", "C", 1);
        execv(argv[0], argv);
        _exit(127);
    }
    close(outpipe[1]); outpipe[1] = -1;
    close(errpipe[1]); errpipe[1] = -1;
    {
        int outflags = fcntl(outpipe[0], F_GETFL, 0);
        int errflags = fcntl(errpipe[0], F_GETFL, 0);
        if (outflags < 0 || errflags < 0 ||
            fcntl(outpipe[0], F_SETFL, outflags | O_NONBLOCK) < 0 ||
            fcntl(errpipe[0], F_SETFL, errflags | O_NONBLOCK) < 0) {
            uint64_t now = geo_monotonic_ms();
            if (geo_readback_child_reap(pid, 1,
                                        now ? now + 250ULL : UINT64_MAX, &status) == 0)
                child_done = 1;
            failed = 1;
        }
    }
    started = geo_monotonic_ms();
    while (!failed && (!child_done || !out_eof || !err_eof)) {
        uint64_t now = geo_monotonic_ms();
        int poll_rc, i;
        pid_t waited;

        if (!started || !now || now - started >= GEO_NFT_TIMEOUT_MS) {
            failed = 1;
            break;
        }
        if (!child_done) {
            do { waited = waitpid(pid, &status, WNOHANG); }
            while (waited < 0 && errno == EINTR);
            if (waited == pid) child_done = 1;
            else if (waited < 0) { failed = 1; break; }
        }
        pfds[0].fd = out_eof ? -1 : outpipe[0]; pfds[0].events = POLLIN | POLLHUP;
        pfds[1].fd = err_eof ? -1 : errpipe[0]; pfds[1].events = POLLIN | POLLHUP;
        do { poll_rc = poll(pfds, 2, 50); } while (poll_rc < 0 && errno == EINTR);
        if (poll_rc < 0) { failed = 1; break; }
        for (i = 0; i < 2; i++) {
            int fd = i ? errpipe[0] : outpipe[0];
            int *eof = i ? &err_eof : &out_eof;
            if (*eof || !(pfds[i].revents & (POLLIN | POLLHUP))) continue;
            for (;;) {
                ssize_t n = read(fd, buf, sizeof(buf));
                if (n > 0) {
                    uint64_t *total = i ? &stderr_bytes : &stdout_bytes;
                    uint64_t limit = i ? GEO_NFT_LOG_MAX_BYTES : GEO_NFT_FILE_MAX_BYTES;
                    int target = i ? logfd : outfd;
                    ssize_t off = 0;
                    if ((uint64_t)n > limit - *total) { failed = 1; break; }
                    *total += (uint64_t)n;
                    if (target >= 0)
                        while (off < n) {
                            ssize_t written = write(target, buf + off, (size_t)(n - off));
                            if (written <= 0) { failed = 1; break; }
                            off += written;
                        }
                    if (failed) break;
                } else if (n == 0) { *eof = 1; break; }
                else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                else if (errno != EINTR) { failed = 1; break; }
            }
            if (failed) break;
        }
        if (failed) break;
    }
    if (!child_done) {
        uint64_t now = geo_monotonic_ms();
        if (geo_readback_child_reap(pid, failed, now ? now + 250ULL : UINT64_MAX,
                                    &status) == 0)
            child_done = 1;
        failed = 1;
    }
    if (outpipe[0] >= 0) close(outpipe[0]);
    if (errpipe[0] >= 0) close(errpipe[0]);
    if (outfd >= 0) {
        if (fsync(outfd) != 0)
            failed = 1;
        if (close(outfd) != 0)
            failed = 1;
        outfd = -1;
    }
    if (logfd >= 0) { (void)fsync(logfd); close(logfd); logfd = -1; }
    if (!failed && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (!output_path || rename(tmp, output_path) == 0)
            return 0;
        failed = 1;
    }
    if (tmp[0]) unlink(tmp);
    if (failed || !WIFEXITED(status) || WEXITSTATUS(status) == 0)
        return -1;
    return WEXITSTATUS(status);

failed_before_fork:
    if (outpipe[0] >= 0) close(outpipe[0]);
    if (outpipe[1] >= 0) close(outpipe[1]);
    if (errpipe[0] >= 0) close(errpipe[0]);
    if (errpipe[1] >= 0) close(errpipe[1]);
    if (outfd >= 0) close(outfd);
    if (logfd >= 0) close(logfd);
    if (tmp[0]) unlink(tmp);
    return -1;
}
/* GEO_NFT_RUNNER_END */

static uint64_t geo_u64_add(uint64_t left, uint64_t right)
{
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static uint64_t geo_file_size_capped(const char *path, uint64_t cap)
{
    struct stat st;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
        return 0;
    return (uint64_t)st.st_size > cap ? cap : (uint64_t)st.st_size;
}

static uint64_t geo_plan_artifact_estimate(const struct geo_plan *plan)
{
    uint64_t bytes;
    uint64_t rules;

    if (!plan || plan->prefix_count < 0 || plan->rule_count < 0 || plan->set_count < 0)
        return GEO_NFT_FILE_MAX_BYTES;
    bytes = GEO_RUNTIME_METADATA_BYTES;
    if ((uint64_t)plan->prefix_count > (GEO_NFT_FILE_MAX_BYTES - bytes) / 96ULL)
        return GEO_NFT_FILE_MAX_BYTES;
    bytes += (uint64_t)plan->prefix_count * 96ULL;
    rules = (uint64_t)plan->rule_count * (uint64_t)plan->set_count * 4ULL;
    if (rules > GEO_READBACK_MAX_RULES)
        rules = GEO_READBACK_MAX_RULES;
    if (rules > (GEO_NFT_FILE_MAX_BYTES - bytes) / 1024ULL)
        return GEO_NFT_FILE_MAX_BYTES;
    bytes += rules * 1024ULL;
    return bytes > GEO_NFT_FILE_MAX_BYTES ? GEO_NFT_FILE_MAX_BYTES : bytes;
}

static int geo_runtime_space_check(const struct geo_plan *plan, int table_present,
                                   struct geo_runtime_space *space)
{
    struct statvfs fs;
    uint64_t block_size;
    uint64_t artifact;
    uint64_t snapshot;
    uint64_t required;

    if (!space)
        return -1;
    memset(space, 0, sizeof(*space));
    artifact = geo_plan_artifact_estimate(plan);
    /* The live ruleset can be larger than the last retained source artifact. */
    snapshot = table_present ? GEO_NFT_FILE_MAX_BYTES : 0;
    space->artifact_estimate_bytes = artifact;
    space->snapshot_estimate_bytes = snapshot;
    /* render tmp + current artifact + before snapshot + restore batch + previous tmp */
    required = geo_u64_add(artifact, artifact);
    required = geo_u64_add(required, snapshot);
    required = geo_u64_add(required, snapshot);
    required = geo_u64_add(required, snapshot);
    required = geo_u64_add(required, GEO_NFT_LOG_MAX_BYTES);
    required = geo_u64_add(required, GEO_RUNTIME_METADATA_BYTES);
    required = geo_u64_add(required, GEO_RUNTIME_RESERVE_BYTES);
    space->required_bytes = required;
    if (required == UINT64_MAX || statvfs(AEGISXD_RUNTIME_DIR, &fs) != 0) {
        snprintf(space->reason, sizeof(space->reason), "%s",
                 required == UINT64_MAX ? "space_budget_overflow" : "statvfs_failed");
        return -1;
    }
    block_size = fs.f_frsize ? (uint64_t)fs.f_frsize : (uint64_t)fs.f_bsize;
    if (block_size && (uint64_t)fs.f_bavail > UINT64_MAX / block_size) {
        snprintf(space->reason, sizeof(space->reason), "available_bytes_overflow");
        return -1;
    }
    space->available_bytes = (uint64_t)fs.f_bavail * block_size;
    space->ok = space->available_bytes >= space->required_bytes;
    snprintf(space->reason, sizeof(space->reason), "%s",
             space->ok ? "ok" : "available_bytes_below_geo_transaction_budget");
    return space->ok ? 0 : -1;
}

static void geo_add_runtime_space_json(struct json_object *o,
                                       const struct geo_runtime_space *space)
{
    struct json_object *storage = json_object_new_object();

    aegisxd_json_add_string(storage, "path", AEGISXD_RUNTIME_DIR);
    json_object_object_add(storage, "tmpfs_expected", json_object_new_boolean(1));
    json_object_object_add(storage, "single_nft_file_max_bytes",
                           json_object_new_int64((int64_t)GEO_NFT_FILE_MAX_BYTES));
    json_object_object_add(storage, "log_max_bytes",
                           json_object_new_int64((int64_t)GEO_NFT_LOG_MAX_BYTES));
    json_object_object_add(storage, "reserve_bytes",
                           json_object_new_int64((int64_t)GEO_RUNTIME_RESERVE_BYTES));
    if (space) {
        json_object_object_add(storage, "ok", json_object_new_boolean(space->ok));
        json_object_object_add(storage, "required_bytes",
                               json_object_new_int64((int64_t)space->required_bytes));
        json_object_object_add(storage, "available_bytes",
                               json_object_new_int64((int64_t)space->available_bytes));
        json_object_object_add(storage, "artifact_estimate_bytes",
                               json_object_new_int64((int64_t)space->artifact_estimate_bytes));
        json_object_object_add(storage, "snapshot_estimate_bytes",
                               json_object_new_int64((int64_t)space->snapshot_estimate_bytes));
        aegisxd_json_add_string(storage, "reason", space->reason);
    }
    json_object_object_add(o, "runtime_storage", storage);
}

static int geo_write_ifaces(FILE *fp, const char *keyword, const struct geo_ifaces *ifaces)
{
    int i;

    if (!ifaces || ifaces->count <= 0)
        return 0;
    if (fprintf(fp, "%s ", keyword) < 0)
        return -1;
    if (ifaces->count == 1)
        return fprintf(fp, "\"%s\" ", ifaces->names[0]) < 0 ? -1 : 0;
    if (fputs("{ ", fp) == EOF)
        return -1;
    for (i = 0; i < ifaces->count; i++)
        if (fprintf(fp, "%s\"%s\"", i ? ", " : "", ifaces->names[i]) < 0)
            return -1;
    return fputs(" } ", fp) == EOF ? -1 : 0;
}

static int geo_write_set(struct geo_plan *plan, FILE *fp, const char *code, int family)
{
    char lower[3] = { (char)tolower((unsigned char)code[0]),
                      (char)tolower((unsigned char)code[1]), '\0' };
    size_t i;
    int count = 0;

    if (fprintf(fp, "  set geo_%s_v%d {\n    type %s_addr\n    flags interval\n"
                    "    auto-merge\n    elements = {\n      ",
                lower, family, family == 4 ? "ipv4" : "ipv6") < 0)
        return -1;
    for (i = 0; i < plan->prefixes.count; i++) {
        const struct dwrt_geoip_prefix *prefix = &plan->prefixes.items[i];
        char address[INET6_ADDRSTRLEN];

        if (strcmp(prefix->iso_code, code) || prefix->family != family)
            continue;
        if (!inet_ntop(family == 4 ? AF_INET : AF_INET6, prefix->address,
                       address, sizeof(address)) ||
            fprintf(fp, "%s%s/%u", count ? ",\n      " : "", address,
                    (unsigned)prefix->prefix_len) < 0)
            return -1;
        count++;
    }
    if (count <= 0)
        return -1;
    return fputs("\n    }\n  }\n\n", fp) == EOF ? -1 : 0;
}

static int geo_write_rule_line(FILE *fp, struct geo_plan *plan, const struct geo_rule *rule,
                               const struct geo_country *country, int family,
                               const char *chain, const char *direction)
{
    char lower[3] = { (char)tolower((unsigned char)country->code[0]),
                      (char)tolower((unsigned char)country->code[1]), '\0' };
    const char *verdict = !strcmp(rule->action, "block") ? "drop" : "accept";

    if (fprintf(fp, "    ") < 0)
        return -1;
    if (!strcmp(chain, "geo_input")) {
        if (geo_write_ifaces(fp, "iifname", &rule->src) != 0)
            return -1;
    } else if (!strcmp(chain, "geo_output")) {
        if (geo_write_ifaces(fp, "oifname", &rule->dst) != 0)
            return -1;
    } else {
        if (geo_write_ifaces(fp, "iifname", &rule->src) != 0 ||
            geo_write_ifaces(fp, "oifname", &rule->dst) != 0)
            return -1;
    }
    if (fprintf(fp, "%s %saddr @geo_%s_v%d counter %s "
                    "comment \"aegis_geo:%s:%s:%s\"\n",
                family == 4 ? "ip" : "ip6",
                !strcmp(direction, "inbound") ? "s" : "d", lower, family,
                verdict, rule->id, direction, country->code) < 0)
        return -1;
    plan->compiled_rule_count++;
    return 0;
}

static int geo_render_chain_rules(FILE *fp, struct geo_plan *plan, const char *chain)
{
    int i, j, family;

    for (i = 0; i < plan->rule_count; i++) {
        struct geo_rule *rule = &plan->rules[i];
        int inbound = !strcmp(rule->direction, "inbound") || !strcmp(rule->direction, "both");
        int outbound = !strcmp(rule->direction, "outbound") || !strcmp(rule->direction, "both");

        for (j = 0; j < plan->country_count; j++) {
            struct geo_country *country = &plan->countries[j];
            for (family = 4; family <= 6; family += 2) {
                int prefixes = family == 4 ? country->ipv4_prefixes : country->ipv6_prefixes;
                if (prefixes <= 0)
                    continue;
                if (inbound && (!strcmp(chain, "geo_forward") ||
                    (!strcmp(chain, "geo_input") && rule->dst.count == 0)))
                    if (geo_write_rule_line(fp, plan, rule, country, family, chain, "inbound") != 0)
                        return -1;
                if (outbound && (!strcmp(chain, "geo_forward") ||
                    (!strcmp(chain, "geo_output") && rule->src.count == 0)))
                    if (geo_write_rule_line(fp, plan, rule, country, family, chain, "outbound") != 0)
                        return -1;
            }
        }
    }
    return 0;
}

static int geo_render_nft(struct geo_plan *plan, const char *path, int replace_existing)
{
    FILE *fp;
    char tmp[AEGISXD_MAX_PATH];
    int i;

    if (!plan || !path || snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp))
        return -1;
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    fprintf(fp, "# Generated from config.db firewall_geo_* revision=%" PRId64 "\n", plan->revision);
    fprintf(fp, "# Prefix authority: %s (selected countries only)\n", GEO_MMDB_PATH);
    if (replace_existing)
        fprintf(fp, "delete table inet %s\n", GEO_NFT_TABLE);
    fprintf(fp, "table inet %s {\n", GEO_NFT_TABLE);
    for (i = 0; i < plan->country_count; i++) {
        if (plan->countries[i].ipv4_prefixes > 0 &&
            geo_write_set(plan, fp, plan->countries[i].code, 4) != 0)
            goto failed;
        if (plan->countries[i].ipv6_prefixes > 0 &&
            geo_write_set(plan, fp, plan->countries[i].code, 6) != 0)
            goto failed;
    }
    plan->compiled_rule_count = 0;
    if (fputs("  chain geo_input {\n    type filter hook input priority -5; policy accept;\n", fp) == EOF ||
        geo_render_chain_rules(fp, plan, "geo_input") != 0 || fputs("  }\n\n", fp) == EOF)
        goto failed;
    if (fputs("  chain geo_forward {\n    type filter hook forward priority -5; policy accept;\n", fp) == EOF ||
        geo_render_chain_rules(fp, plan, "geo_forward") != 0 || fputs("  }\n\n", fp) == EOF)
        goto failed;
    if (fputs("  chain geo_output {\n    type filter hook output priority -5; policy accept;\n", fp) == EOF ||
        geo_render_chain_rules(fp, plan, "geo_output") != 0 || fputs("  }\n}\n", fp) == EOF)
        goto failed;
    if (plan->compiled_rule_count <= 0 || fflush(fp) != 0 ||
        ftello(fp) < 0 || (uint64_t)ftello(fp) > GEO_NFT_FILE_MAX_BYTES ||
        fsync(fileno(fp)) != 0 ||
        fclose(fp) != 0 || rename(tmp, path) != 0) {
        fp = NULL;
        goto failed;
    }
    return 0;
failed:
    if (fp)
        fclose(fp);
    unlink(tmp);
    return -1;
}

static int geo_copy_file(const char *src, const char *dst)
{
    char tmp[AEGISXD_MAX_PATH];
    unsigned char buf[16384];
    int in = -1, out = -1;
    ssize_t n;
    uint64_t total = 0;
    int rc = -1;

    if (!src || !dst || snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dst, (long)getpid()) >=
        (int)sizeof(tmp) || (in = open(src, O_RDONLY)) < 0 ||
        (out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
        goto done;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        if ((uint64_t)n > GEO_NFT_FILE_MAX_BYTES - total)
            goto done;
        total += (uint64_t)n;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0)
                goto done;
            off += w;
        }
    }
    if (n < 0 || fsync(out) != 0 || close(out) != 0) {
        out = -1;
        goto done;
    }
    out = -1;
    if (rename(tmp, dst) == 0)
        rc = 0;
done:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    if (rc != 0) unlink(tmp);
    return rc;
}

static int geo_write_json_atomic(const char *path, struct json_object *obj)
{
    char tmp[AEGISXD_MAX_PATH];
    const char *text;
    size_t len, off = 0;
    int fd;

    if (!path || !obj || snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp))
        return -1;
    text = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    len = strlen(text);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n <= 0) {
            close(fd); unlink(tmp); return -1;
        }
        off += (size_t)n;
    }
    if (write(fd, "\n", 1) != 1 || fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static struct json_object *geo_read_json(const char *path)
{
    struct json_object *o = NULL;
    FILE *fp;
    char *buf;
    long n;

    fp = fopen(path, "r");
    if (!fp || fseek(fp, 0, SEEK_END) != 0 || (n = ftell(fp)) < 0 || n > 16 * 1024 * 1024 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        if (fp) fclose(fp);
        return NULL;
    }
    buf = calloc(1, (size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, fp) == (size_t)n)
        o = json_tokener_parse(buf);
    free(buf);
    fclose(fp);
    return o;
}

/* GEO_READBACK_STREAM_BEGIN
 * This parser deliberately has no json-c DOM. A large interval set can make
 * `nft -j list table` hundreds of MiB, while the structural state needed for
 * an exact readback is fixed and small.
 */
enum geo_json_container_type {
    GEO_JSON_OBJECT = 1,
    GEO_JSON_ARRAY = 2,
};

enum geo_json_container_state {
    GEO_JSON_OBJECT_KEY_OR_END = 1,
    GEO_JSON_OBJECT_KEY_REQUIRED,
    GEO_JSON_OBJECT_COLON,
    GEO_JSON_OBJECT_VALUE,
    GEO_JSON_OBJECT_COMMA_OR_END,
    GEO_JSON_ARRAY_VALUE_OR_END,
    GEO_JSON_ARRAY_VALUE_REQUIRED,
    GEO_JSON_ARRAY_COMMA_OR_END,
};

enum geo_json_role {
    GEO_JSON_ROLE_GENERIC = 0,
    GEO_JSON_ROLE_ROOT,
    GEO_JSON_ROLE_NFTABLES,
    GEO_JSON_ROLE_ENTRY,
    GEO_JSON_ROLE_ENTRY_VALUE,
    GEO_JSON_ROLE_ELEMS,
    GEO_JSON_ROLE_EXPR,
    GEO_JSON_ROLE_EXPR_ITEM,
    GEO_JSON_ROLE_COUNTER,
};

enum geo_json_value_type {
    GEO_JSON_VALUE_OBJECT = 1,
    GEO_JSON_VALUE_ARRAY,
    GEO_JSON_VALUE_STRING,
    GEO_JSON_VALUE_NUMBER,
    GEO_JSON_VALUE_TRUE,
    GEO_JSON_VALUE_FALSE,
    GEO_JSON_VALUE_NULL,
};

enum geo_json_lexer_state {
    GEO_JSON_LEX_NORMAL = 0,
    GEO_JSON_LEX_STRING,
    GEO_JSON_LEX_ESCAPE,
    GEO_JSON_LEX_LOW_SURROGATE_ESCAPE,
    GEO_JSON_LEX_LOW_SURROGATE_U,
    GEO_JSON_LEX_UNICODE,
    GEO_JSON_LEX_NUMBER,
    GEO_JSON_LEX_LITERAL,
};

enum geo_json_number_state {
    GEO_JSON_NUM_MINUS = 1,
    GEO_JSON_NUM_ZERO,
    GEO_JSON_NUM_INTEGER,
    GEO_JSON_NUM_DOT,
    GEO_JSON_NUM_FRACTION,
    GEO_JSON_NUM_EXP,
    GEO_JSON_NUM_EXP_SIGN,
    GEO_JSON_NUM_EXP_DIGIT,
};

enum geo_nft_entry_kind {
    GEO_NFT_ENTRY_NONE = 0,
    GEO_NFT_ENTRY_TABLE,
    GEO_NFT_ENTRY_SET,
    GEO_NFT_ENTRY_RULE,
    GEO_NFT_ENTRY_ELEMENT,
};

struct geo_json_container {
    unsigned char type;
    unsigned char state;
    unsigned char role;
    char key[GEO_JSON_TOKEN_BYTES];
};

struct geo_json_entry {
    enum geo_nft_entry_kind kind;
    unsigned int seen;
    int64_t elements;
    char family[16];
    char table[128];
    char name[128];
    char comment[160];
    int counter_seen;
    int counter_packets_seen;
    int counter_bytes_seen;
    uint64_t counter_packets;
    uint64_t counter_bytes;
};

struct geo_readback_parser {
    struct geo_json_container stack[GEO_JSON_MAX_DEPTH];
    size_t depth;
    int root_started;
    int root_done;
    int nftables_seen;
    int target_table_count;
    int failed;
    enum geo_json_lexer_state lexer;
    enum geo_json_number_state number;
    int string_is_key;
    int token_overflow;
    int token_has_nul;
    char token[GEO_JSON_TOKEN_BYTES];
    size_t token_len;
    const char *literal;
    size_t literal_at;
    unsigned int unicode_value;
    unsigned int unicode_digits;
    unsigned int high_surrogate;
    unsigned int utf8_value;
    unsigned int utf8_min;
    unsigned int utf8_remaining;
    uint64_t token_count;
    struct geo_json_entry entry;
    struct geo_runtime_counts counts;
};

#define GEO_ENTRY_SEEN_KIND   (1U << 0)
#define GEO_ENTRY_SEEN_FAMILY (1U << 1)
#define GEO_ENTRY_SEEN_TABLE  (1U << 2)
#define GEO_ENTRY_SEEN_NAME   (1U << 3)
#define GEO_ENTRY_SEEN_ELEM   (1U << 4)
#define GEO_ENTRY_SEEN_COMMENT (1U << 5)
#define GEO_ENTRY_SEEN_EXPR    (1U << 6)

static int geo_readback_parser_fail(struct geo_readback_parser *parser)
{
    parser->failed = 1;
    return -1;
}

static int geo_json_token_count(struct geo_readback_parser *parser)
{
    if (parser->token_count == GEO_JSON_MAX_TOKENS)
        return geo_readback_parser_fail(parser);
    parser->token_count++;
    return 0;
}

static int geo_json_token_append(struct geo_readback_parser *parser,
                                 const unsigned char *bytes, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (bytes[i] == '\0')
            parser->token_has_nul = 1;
        if (parser->token_len + 1 < sizeof(parser->token))
            parser->token[parser->token_len++] = (char)bytes[i];
        else
            parser->token_overflow = 1;
    }
    return 0;
}

static int geo_json_token_append_codepoint(struct geo_readback_parser *parser,
                                           unsigned int value)
{
    unsigned char encoded[4];
    size_t len;

    if (value <= 0x7f) {
        encoded[0] = (unsigned char)value;
        len = 1;
    } else if (value <= 0x7ff) {
        encoded[0] = 0xc0U | (unsigned char)(value >> 6);
        encoded[1] = 0x80U | (unsigned char)(value & 0x3fU);
        len = 2;
    } else if (value <= 0xffff) {
        encoded[0] = 0xe0U | (unsigned char)(value >> 12);
        encoded[1] = 0x80U | (unsigned char)((value >> 6) & 0x3fU);
        encoded[2] = 0x80U | (unsigned char)(value & 0x3fU);
        len = 3;
    } else if (value <= 0x10ffff) {
        encoded[0] = 0xf0U | (unsigned char)(value >> 18);
        encoded[1] = 0x80U | (unsigned char)((value >> 12) & 0x3fU);
        encoded[2] = 0x80U | (unsigned char)((value >> 6) & 0x3fU);
        encoded[3] = 0x80U | (unsigned char)(value & 0x3fU);
        len = 4;
    } else {
        return geo_readback_parser_fail(parser);
    }
    return geo_json_token_append(parser, encoded, len);
}

static int geo_json_entry_kind(const char *key, enum geo_nft_entry_kind *kind)
{
    if (!strcmp(key, "table"))
        *kind = GEO_NFT_ENTRY_TABLE;
    else if (!strcmp(key, "set"))
        *kind = GEO_NFT_ENTRY_SET;
    else if (!strcmp(key, "rule"))
        *kind = GEO_NFT_ENTRY_RULE;
    else if (!strcmp(key, "element"))
        *kind = GEO_NFT_ENTRY_ELEMENT;
    else
        return 0;
    return 1;
}

static int geo_json_relevant_entry_field(const char *key, unsigned int *bit,
                                         enum geo_json_value_type *required)
{
    if (!strcmp(key, "family")) {
        *bit = GEO_ENTRY_SEEN_FAMILY;
        *required = GEO_JSON_VALUE_STRING;
    } else if (!strcmp(key, "table")) {
        *bit = GEO_ENTRY_SEEN_TABLE;
        *required = GEO_JSON_VALUE_STRING;
    } else if (!strcmp(key, "name")) {
        *bit = GEO_ENTRY_SEEN_NAME;
        *required = GEO_JSON_VALUE_STRING;
    } else if (!strcmp(key, "elem")) {
        *bit = GEO_ENTRY_SEEN_ELEM;
        *required = GEO_JSON_VALUE_ARRAY;
    } else if (!strcmp(key, "comment")) {
        *bit = GEO_ENTRY_SEEN_COMMENT;
        *required = GEO_JSON_VALUE_STRING;
    } else if (!strcmp(key, "expr")) {
        *bit = GEO_ENTRY_SEEN_EXPR;
        *required = GEO_JSON_VALUE_ARRAY;
    } else {
        return 0;
    }
    return 1;
}

/* Parse the exact `aegis_geo:<rule_id>:<direction>:<COUNTRY>` comment written by
 * geo_write_rule_line(). A rule line carrying any other comment, or a malformed
 * one, is reported as foreign/unparsed instead of being attributed to a rule.
 */
static int geo_parse_owned_comment(const char *comment, char *rule_id, size_t rule_id_size,
                                   int *inbound, char *country)
{
    const char *cursor, *direction_end, *country_start;
    size_t rule_len, direction_len;

    if (!comment || strncmp(comment, "aegis_geo:", 10))
        return 0;
    cursor = comment + 10;
    direction_end = strchr(cursor, ':');
    if (!direction_end || direction_end == cursor)
        return 0;
    rule_len = (size_t)(direction_end - cursor);
    if (rule_len >= rule_id_size)
        return 0;
    memcpy(rule_id, cursor, rule_len);
    rule_id[rule_len] = '\0';

    cursor = direction_end + 1;
    country_start = strchr(cursor, ':');
    if (!country_start)
        return 0;
    direction_len = (size_t)(country_start - cursor);
    if (direction_len == 7 && !memcmp(cursor, "inbound", 7))
        *inbound = 1;
    else if (direction_len == 8 && !memcmp(cursor, "outbound", 8))
        *inbound = 0;
    else
        return 0;

    country_start++;
    if (strlen(country_start) != 2 ||
        country_start[0] < 'A' || country_start[0] > 'Z' ||
        country_start[1] < 'A' || country_start[1] > 'Z')
        return 0;
    country[0] = country_start[0];
    country[1] = country_start[1];
    country[2] = '\0';
    return 1;
}

static int geo_counter_totals_add(struct geo_counter_totals *totals, int inbound,
                                  int counter_present, uint64_t packets, uint64_t bytes)
{
    uint64_t *packet_slot = inbound ? &totals->inbound_packets : &totals->outbound_packets;
    uint64_t *byte_slot = inbound ? &totals->inbound_bytes : &totals->outbound_bytes;

    if (totals->rule_lines == INT_MAX)
        return -1;
    totals->rule_lines++;
    if (!counter_present)
        return 0;
    if (packets > UINT64_MAX - *packet_slot || bytes > UINT64_MAX - *byte_slot ||
        totals->counter_lines == INT_MAX)
        return -1;
    *packet_slot += packets;
    *byte_slot += bytes;
    totals->counter_lines++;
    return 0;
}

/* Fold one owned rule line into the fixed per-rule and per-country buckets.
 * A rule line whose counter expression is absent is counted as a rule line but
 * never contributes fabricated zero traffic, so callers can tell "no counter"
 * apart from "counter reads zero".
 */
static int geo_readback_rule_counter_commit(struct geo_readback_parser *parser,
                                           const struct geo_json_entry *entry)
{
    struct geo_rule_counter *rule_bucket = NULL;
    struct geo_country_counter *country_bucket = NULL;
    char rule_id[65];
    char country[3];
    int inbound = 0;
    int counter_present;
    int i;

    if (!(entry->seen & GEO_ENTRY_SEEN_COMMENT) ||
        !geo_parse_owned_comment(entry->comment, rule_id, sizeof(rule_id), &inbound, country)) {
        if (parser->counts.foreign_rule_lines != INT_MAX)
            parser->counts.foreign_rule_lines++;
        return 0;
    }

    counter_present = entry->counter_seen && entry->counter_packets_seen &&
                      entry->counter_bytes_seen;
    if (entry->counter_seen && !counter_present)
        return geo_readback_parser_fail(parser);

    if (parser->counts.owned_rule_lines == INT_MAX)
        return geo_readback_parser_fail(parser);
    parser->counts.owned_rule_lines++;
    if (!counter_present && parser->counts.rule_lines_without_counter != INT_MAX)
        parser->counts.rule_lines_without_counter++;

    for (i = 0; i < parser->counts.rule_counter_count; i++)
        if (!strcmp(parser->counts.rule_counters[i].rule_id, rule_id)) {
            rule_bucket = &parser->counts.rule_counters[i];
            break;
        }
    if (!rule_bucket) {
        if (parser->counts.rule_counter_count >= GEO_MAX_RULES) {
            parser->counts.rule_counter_bucket_overflow = 1;
        } else {
            rule_bucket = &parser->counts.rule_counters[parser->counts.rule_counter_count++];
            memcpy(rule_bucket->rule_id, rule_id, strlen(rule_id) + 1);
        }
    }

    for (i = 0; i < parser->counts.country_counter_count; i++)
        if (!strcmp(parser->counts.country_counters[i].country, country)) {
            country_bucket = &parser->counts.country_counters[i];
            break;
        }
    if (!country_bucket) {
        if (parser->counts.country_counter_count >= GEO_MAX_COUNTRIES) {
            parser->counts.rule_counter_bucket_overflow = 1;
        } else {
            country_bucket =
                &parser->counts.country_counters[parser->counts.country_counter_count++];
            memcpy(country_bucket->country, country, 3);
        }
    }

    if ((rule_bucket &&
         geo_counter_totals_add(&rule_bucket->totals, inbound, counter_present,
                                entry->counter_packets, entry->counter_bytes) != 0) ||
        (country_bucket &&
         geo_counter_totals_add(&country_bucket->totals, inbound, counter_present,
                                entry->counter_packets, entry->counter_bytes) != 0) ||
        geo_counter_totals_add(&parser->counts.counter_totals, inbound, counter_present,
                               entry->counter_packets, entry->counter_bytes) != 0)
        return geo_readback_parser_fail(parser);
    return 0;
}

static int geo_readback_entry_commit(struct geo_readback_parser *parser)
{
    struct geo_json_entry *entry = &parser->entry;
    struct geo_runtime_set *set = NULL;
    int target;
    int i;

    if (entry->kind == GEO_NFT_ENTRY_NONE)
        return 0;
    if (!(entry->seen & GEO_ENTRY_SEEN_FAMILY))
        return geo_readback_parser_fail(parser);
    if (entry->kind == GEO_NFT_ENTRY_TABLE) {
        if (!(entry->seen & GEO_ENTRY_SEEN_NAME))
            return geo_readback_parser_fail(parser);
        if (!strcmp(entry->family, "inet") && !strcmp(entry->name, GEO_NFT_TABLE)) {
            if (++parser->target_table_count != 1)
                return geo_readback_parser_fail(parser);
            parser->counts.table_found = 1;
        }
        return 0;
    }
    if (!(entry->seen & GEO_ENTRY_SEEN_TABLE))
        return geo_readback_parser_fail(parser);
    target = !strcmp(entry->family, "inet") && !strcmp(entry->table, GEO_NFT_TABLE);
    if (!target)
        return 0;
    if (entry->kind == GEO_NFT_ENTRY_SET) {
        if (!(entry->seen & GEO_ENTRY_SEEN_NAME) ||
            strlen(entry->name) >= sizeof(parser->counts.sets[0].name) ||
            parser->counts.set_count >= GEO_READBACK_MAX_SETS)
            return geo_readback_parser_fail(parser);
        for (i = 0; i < parser->counts.set_count; i++)
            if (!strcmp(parser->counts.sets[i].name, entry->name))
                return geo_readback_parser_fail(parser);
        set = &parser->counts.sets[parser->counts.set_count++];
        memcpy(set->name, entry->name, strlen(entry->name) + 1);
    } else if (entry->kind == GEO_NFT_ENTRY_RULE) {
        if (parser->counts.rule_count >= GEO_READBACK_MAX_RULES)
            return geo_readback_parser_fail(parser);
        parser->counts.rule_count++;
        if (geo_readback_rule_counter_commit(parser, entry) != 0)
            return -1;
    } else if (entry->kind == GEO_NFT_ENTRY_ELEMENT) {
        if (!(entry->seen & GEO_ENTRY_SEEN_NAME))
            return geo_readback_parser_fail(parser);
        for (i = 0; i < parser->counts.set_count; i++)
            if (!strcmp(parser->counts.sets[i].name, entry->name)) {
                set = &parser->counts.sets[i];
                break;
            }
        if (!set)
            return geo_readback_parser_fail(parser);
    }
    if (entry->kind == GEO_NFT_ENTRY_SET || entry->kind == GEO_NFT_ENTRY_ELEMENT) {
        if (!set || entry->elements > GEO_READBACK_MAX_ELEMENTS - parser->counts.element_count ||
            entry->elements > INT64_MAX - set->element_count)
            return geo_readback_parser_fail(parser);
        parser->counts.element_count += entry->elements;
        set->element_count += entry->elements;
    }
    return 0;
}

static int geo_json_value_begin(struct geo_readback_parser *parser,
                                enum geo_json_value_type type,
                                enum geo_json_role *new_role)
{
    struct geo_json_container *parent;
    enum geo_nft_entry_kind kind;
    enum geo_json_value_type required;
    unsigned int bit;

    *new_role = GEO_JSON_ROLE_GENERIC;
    if (geo_json_token_count(parser) != 0)
        return -1;
    if (!parser->depth) {
        if (parser->root_started || type != GEO_JSON_VALUE_OBJECT)
            return geo_readback_parser_fail(parser);
        parser->root_started = 1;
        *new_role = GEO_JSON_ROLE_ROOT;
        return 0;
    }
    parent = &parser->stack[parser->depth - 1];
    if (parent->type == GEO_JSON_OBJECT) {
        if (parent->state != GEO_JSON_OBJECT_VALUE)
            return geo_readback_parser_fail(parser);
        if (parent->role == GEO_JSON_ROLE_ROOT && !strcmp(parent->key, "nftables")) {
            if (parser->nftables_seen || type != GEO_JSON_VALUE_ARRAY)
                return geo_readback_parser_fail(parser);
            parser->nftables_seen = 1;
            *new_role = GEO_JSON_ROLE_NFTABLES;
        } else if (parent->role == GEO_JSON_ROLE_ENTRY &&
                   geo_json_entry_kind(parent->key, &kind)) {
            if ((parser->entry.seen & GEO_ENTRY_SEEN_KIND) ||
                type != GEO_JSON_VALUE_OBJECT)
                return geo_readback_parser_fail(parser);
            parser->entry.seen |= GEO_ENTRY_SEEN_KIND;
            parser->entry.kind = kind;
            *new_role = GEO_JSON_ROLE_ENTRY_VALUE;
        } else if (parent->role == GEO_JSON_ROLE_ENTRY_VALUE &&
                   geo_json_relevant_entry_field(parent->key, &bit, &required)) {
            if ((parser->entry.seen & bit) || type != required)
                return geo_readback_parser_fail(parser);
            parser->entry.seen |= bit;
            if (bit == GEO_ENTRY_SEEN_ELEM &&
                (parser->entry.kind == GEO_NFT_ENTRY_SET ||
                 parser->entry.kind == GEO_NFT_ENTRY_ELEMENT))
                *new_role = GEO_JSON_ROLE_ELEMS;
            if (bit == GEO_ENTRY_SEEN_EXPR && parser->entry.kind == GEO_NFT_ENTRY_RULE)
                *new_role = GEO_JSON_ROLE_EXPR;
        } else if (parent->role == GEO_JSON_ROLE_EXPR_ITEM &&
                   !strcmp(parent->key, "counter") &&
                   type == GEO_JSON_VALUE_OBJECT) {
            /* `counter` can also appear as a non-object (for example
             * `"counter": null` in a stateless listing). Only a real counter
             * object carries packets/bytes, and anything else must still fall
             * through to the normal container state transition below.
             */
            if (parser->entry.counter_seen)
                return geo_readback_parser_fail(parser);
            parser->entry.counter_seen = 1;
            *new_role = GEO_JSON_ROLE_COUNTER;
        }
        parent->state = GEO_JSON_OBJECT_COMMA_OR_END;
    } else {
        if (parent->state != GEO_JSON_ARRAY_VALUE_OR_END &&
            parent->state != GEO_JSON_ARRAY_VALUE_REQUIRED)
            return geo_readback_parser_fail(parser);
        if (parent->role == GEO_JSON_ROLE_NFTABLES) {
            if (type != GEO_JSON_VALUE_OBJECT)
                return geo_readback_parser_fail(parser);
            memset(&parser->entry, 0, sizeof(parser->entry));
            *new_role = GEO_JSON_ROLE_ENTRY;
        } else if (parent->role == GEO_JSON_ROLE_EXPR) {
            if (type == GEO_JSON_VALUE_OBJECT)
                *new_role = GEO_JSON_ROLE_EXPR_ITEM;
        } else if (parent->role == GEO_JSON_ROLE_ELEMS) {
            if (parser->entry.elements >= GEO_READBACK_MAX_ELEMENTS)
                return geo_readback_parser_fail(parser);
            parser->entry.elements++;
        }
        parent->state = GEO_JSON_ARRAY_COMMA_OR_END;
    }
    return 0;
}

static int geo_json_push(struct geo_readback_parser *parser,
                         enum geo_json_container_type type,
                         enum geo_json_role role)
{
    struct geo_json_container *container;

    if (parser->depth >= GEO_JSON_MAX_DEPTH)
        return geo_readback_parser_fail(parser);
    container = &parser->stack[parser->depth++];
    memset(container, 0, sizeof(*container));
    container->type = (unsigned char)type;
    container->role = (unsigned char)role;
    container->state = type == GEO_JSON_OBJECT ? GEO_JSON_OBJECT_KEY_OR_END :
                                                GEO_JSON_ARRAY_VALUE_OR_END;
    return 0;
}

static int geo_json_close(struct geo_readback_parser *parser,
                          enum geo_json_container_type type)
{
    struct geo_json_container *container;
    enum geo_json_role role;

    if (!parser->depth)
        return geo_readback_parser_fail(parser);
    container = &parser->stack[parser->depth - 1];
    if (container->type != type)
        return geo_readback_parser_fail(parser);
    if (type == GEO_JSON_OBJECT &&
        container->state != GEO_JSON_OBJECT_KEY_OR_END &&
        container->state != GEO_JSON_OBJECT_COMMA_OR_END)
        return geo_readback_parser_fail(parser);
    if (type == GEO_JSON_ARRAY &&
        container->state != GEO_JSON_ARRAY_VALUE_OR_END &&
        container->state != GEO_JSON_ARRAY_COMMA_OR_END)
        return geo_readback_parser_fail(parser);
    role = (enum geo_json_role)container->role;
    parser->depth--;
    if (role == GEO_JSON_ROLE_ENTRY && geo_readback_entry_commit(parser) != 0)
        return -1;
    if (!parser->depth)
        parser->root_done = 1;
    return 0;
}

static int geo_json_string_complete(struct geo_readback_parser *parser)
{
    struct geo_json_container *container;
    char *destination = NULL;
    size_t destination_size = 0;

    parser->token[parser->token_len < sizeof(parser->token) ? parser->token_len :
                                                            sizeof(parser->token) - 1] = '\0';
    if (!parser->depth)
        return geo_readback_parser_fail(parser);
    container = &parser->stack[parser->depth - 1];
    if (parser->string_is_key) {
        if (container->type != GEO_JSON_OBJECT ||
            (container->state != GEO_JSON_OBJECT_KEY_OR_END &&
             container->state != GEO_JSON_OBJECT_KEY_REQUIRED) ||
            parser->token_overflow || parser->token_has_nul)
            return geo_readback_parser_fail(parser);
        if (geo_json_token_count(parser) != 0)
            return -1;
        snprintf(container->key, sizeof(container->key), "%s", parser->token);
        container->state = GEO_JSON_OBJECT_COLON;
        return 0;
    }
    if (parser->token_overflow || parser->token_has_nul)
        return geo_readback_parser_fail(parser);
    if (container->role != GEO_JSON_ROLE_ENTRY_VALUE)
        return 0;
    if (!strcmp(container->key, "family")) {
        destination = parser->entry.family;
        destination_size = sizeof(parser->entry.family);
    } else if (!strcmp(container->key, "table")) {
        destination = parser->entry.table;
        destination_size = sizeof(parser->entry.table);
    } else if (!strcmp(container->key, "name")) {
        destination = parser->entry.name;
        destination_size = sizeof(parser->entry.name);
    } else if (!strcmp(container->key, "comment")) {
        destination = parser->entry.comment;
        destination_size = sizeof(parser->entry.comment);
    }
    if (destination) {
        if (parser->token_overflow || parser->token_has_nul ||
            parser->token_len >= destination_size)
            return geo_readback_parser_fail(parser);
        memcpy(destination, parser->token, parser->token_len + 1);
    }
    return 0;
}

static int geo_json_start_string(struct geo_readback_parser *parser, int is_key)
{
    parser->lexer = GEO_JSON_LEX_STRING;
    parser->string_is_key = is_key;
    parser->token_len = 0;
    parser->token_overflow = 0;
    parser->token_has_nul = 0;
    parser->high_surrogate = 0;
    parser->utf8_value = 0;
    parser->utf8_min = 0;
    parser->utf8_remaining = 0;
    return 0;
}

static int geo_json_number_accepting(enum geo_json_number_state state)
{
    return state == GEO_JSON_NUM_ZERO || state == GEO_JSON_NUM_INTEGER ||
           state == GEO_JSON_NUM_FRACTION || state == GEO_JSON_NUM_EXP_DIGIT;
}

/* Only `counter.packets` / `counter.bytes` are retained. Both must be exact
 * unsigned integers; nft emits plain integers there, so a fractional, negative,
 * exponent or overflowing value means the assumed contract no longer holds and
 * the readback fails instead of reporting a rounded number.
 */
static int geo_json_number_complete(struct geo_readback_parser *parser)
{
    struct geo_json_container *container;
    uint64_t value = 0;
    size_t i;

    if (!parser->depth)
        return geo_readback_parser_fail(parser);
    container = &parser->stack[parser->depth - 1];
    if (container->type != GEO_JSON_OBJECT ||
        container->role != GEO_JSON_ROLE_COUNTER)
        return 0;
    if (strcmp(container->key, "packets") && strcmp(container->key, "bytes"))
        return 0;
    if (parser->token_overflow || parser->token_has_nul || !parser->token_len)
        return geo_readback_parser_fail(parser);
    for (i = 0; i < parser->token_len; i++) {
        unsigned char digit = (unsigned char)parser->token[i];

        if (digit < '0' || digit > '9')
            return geo_readback_parser_fail(parser);
        if (value > (UINT64_MAX - (uint64_t)(digit - '0')) / 10ULL)
            return geo_readback_parser_fail(parser);
        value = value * 10ULL + (uint64_t)(digit - '0');
    }
    if (!strcmp(container->key, "packets")) {
        if (parser->entry.counter_packets_seen)
            return geo_readback_parser_fail(parser);
        parser->entry.counter_packets_seen = 1;
        parser->entry.counter_packets = value;
    } else {
        if (parser->entry.counter_bytes_seen)
            return geo_readback_parser_fail(parser);
        parser->entry.counter_bytes_seen = 1;
        parser->entry.counter_bytes = value;
    }
    return 0;
}

static int geo_json_number_char(struct geo_readback_parser *parser, unsigned char ch,
                                int *consumed)
{
    *consumed = 1;
    switch (parser->number) {
    case GEO_JSON_NUM_MINUS:
        if (ch == '0') parser->number = GEO_JSON_NUM_ZERO;
        else if (ch >= '1' && ch <= '9') parser->number = GEO_JSON_NUM_INTEGER;
        else return geo_readback_parser_fail(parser);
        break;
    case GEO_JSON_NUM_ZERO:
        if (ch == '.') parser->number = GEO_JSON_NUM_DOT;
        else if (ch == 'e' || ch == 'E') parser->number = GEO_JSON_NUM_EXP;
        else *consumed = 0;
        break;
    case GEO_JSON_NUM_INTEGER:
        if (ch >= '0' && ch <= '9') break;
        if (ch == '.') parser->number = GEO_JSON_NUM_DOT;
        else if (ch == 'e' || ch == 'E') parser->number = GEO_JSON_NUM_EXP;
        else *consumed = 0;
        break;
    case GEO_JSON_NUM_DOT:
        if (ch >= '0' && ch <= '9') parser->number = GEO_JSON_NUM_FRACTION;
        else return geo_readback_parser_fail(parser);
        break;
    case GEO_JSON_NUM_FRACTION:
        if (ch >= '0' && ch <= '9') break;
        if (ch == 'e' || ch == 'E') parser->number = GEO_JSON_NUM_EXP;
        else *consumed = 0;
        break;
    case GEO_JSON_NUM_EXP:
        if (ch == '+' || ch == '-') parser->number = GEO_JSON_NUM_EXP_SIGN;
        else if (ch >= '0' && ch <= '9') parser->number = GEO_JSON_NUM_EXP_DIGIT;
        else return geo_readback_parser_fail(parser);
        break;
    case GEO_JSON_NUM_EXP_SIGN:
        if (ch >= '0' && ch <= '9') parser->number = GEO_JSON_NUM_EXP_DIGIT;
        else return geo_readback_parser_fail(parser);
        break;
    case GEO_JSON_NUM_EXP_DIGIT:
        if (ch < '0' || ch > '9') *consumed = 0;
        break;
    default:
        return geo_readback_parser_fail(parser);
    }
    if (!*consumed) {
        if (!geo_json_number_accepting(parser->number))
            return geo_readback_parser_fail(parser);
        parser->lexer = GEO_JSON_LEX_NORMAL;
        return geo_json_number_complete(parser);
    }
    if (parser->token_len + 1 < sizeof(parser->token))
        parser->token[parser->token_len++] = (char)ch;
    else
        parser->token_overflow = 1;
    return 0;
}

static void geo_readback_parser_init(struct geo_readback_parser *parser)
{
    memset(parser, 0, sizeof(*parser));
}

static int geo_readback_parser_feed(struct geo_readback_parser *parser,
                                    const unsigned char *data, size_t len)
{
    size_t offset = 0;

    if (!parser || (!data && len) || parser->failed)
        return -1;
    while (offset < len) {
        unsigned char ch = data[offset];
        struct geo_json_container *container;
        enum geo_json_role role;
        int consumed = 1;

        if (parser->lexer == GEO_JSON_LEX_STRING) {
            if (parser->utf8_remaining) {
                if ((ch & 0xc0U) != 0x80U)
                    return geo_readback_parser_fail(parser);
                parser->utf8_value = (parser->utf8_value << 6) | (ch & 0x3fU);
                parser->utf8_remaining--;
                geo_json_token_append(parser, &ch, 1);
                if (!parser->utf8_remaining &&
                    (parser->utf8_value < parser->utf8_min ||
                     parser->utf8_value > 0x10ffffU ||
                     (parser->utf8_value >= 0xd800U && parser->utf8_value <= 0xdfffU)))
                    return geo_readback_parser_fail(parser);
            } else if (parser->high_surrogate) {
                if (ch != '\\') return geo_readback_parser_fail(parser);
                parser->lexer = GEO_JSON_LEX_LOW_SURROGATE_ESCAPE;
            } else if (ch == '"') {
                parser->lexer = GEO_JSON_LEX_NORMAL;
                if (geo_json_string_complete(parser) != 0) return -1;
            } else if (ch == '\\') {
                parser->lexer = GEO_JSON_LEX_ESCAPE;
            } else if (ch < 0x20) {
                return geo_readback_parser_fail(parser);
            } else if (ch >= 0x80) {
                if (ch >= 0xc2 && ch <= 0xdf) {
                    parser->utf8_value = ch & 0x1fU;
                    parser->utf8_min = 0x80U;
                    parser->utf8_remaining = 1;
                } else if (ch >= 0xe0 && ch <= 0xef) {
                    parser->utf8_value = ch & 0x0fU;
                    parser->utf8_min = 0x800U;
                    parser->utf8_remaining = 2;
                } else if (ch >= 0xf0 && ch <= 0xf4) {
                    parser->utf8_value = ch & 0x07U;
                    parser->utf8_min = 0x10000U;
                    parser->utf8_remaining = 3;
                } else {
                    return geo_readback_parser_fail(parser);
                }
                geo_json_token_append(parser, &ch, 1);
            } else {
                geo_json_token_append(parser, &ch, 1);
            }
            offset++;
            continue;
        }
        if (parser->lexer == GEO_JSON_LEX_ESCAPE) {
            unsigned char decoded;
            if (ch == 'u') {
                parser->unicode_value = 0;
                parser->unicode_digits = 0;
                parser->lexer = GEO_JSON_LEX_UNICODE;
            } else {
                switch (ch) {
                case '"': case '\\': case '/': decoded = ch; break;
                case 'b': decoded = '\b'; break;
                case 'f': decoded = '\f'; break;
                case 'n': decoded = '\n'; break;
                case 'r': decoded = '\r'; break;
                case 't': decoded = '\t'; break;
                default: return geo_readback_parser_fail(parser);
                }
                geo_json_token_append(parser, &decoded, 1);
                parser->lexer = GEO_JSON_LEX_STRING;
            }
            offset++;
            continue;
        }
        if (parser->lexer == GEO_JSON_LEX_LOW_SURROGATE_ESCAPE) {
            if (ch != 'u') return geo_readback_parser_fail(parser);
            parser->unicode_value = 0;
            parser->unicode_digits = 0;
            parser->lexer = GEO_JSON_LEX_LOW_SURROGATE_U;
            offset++;
            continue;
        }
        if (parser->lexer == GEO_JSON_LEX_UNICODE ||
            parser->lexer == GEO_JSON_LEX_LOW_SURROGATE_U) {
            unsigned int digit;
            int low = parser->lexer == GEO_JSON_LEX_LOW_SURROGATE_U;
            if (ch >= '0' && ch <= '9') digit = ch - '0';
            else if (ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10U;
            else if (ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10U;
            else return geo_readback_parser_fail(parser);
            parser->unicode_value = parser->unicode_value * 16U + digit;
            parser->unicode_digits++;
            offset++;
            if (parser->unicode_digits != 4)
                continue;
            if (low) {
                unsigned int codepoint;
                if (parser->unicode_value < 0xdc00 || parser->unicode_value > 0xdfff)
                    return geo_readback_parser_fail(parser);
                codepoint = 0x10000U + ((parser->high_surrogate - 0xd800U) << 10) +
                            (parser->unicode_value - 0xdc00U);
                parser->high_surrogate = 0;
                if (geo_json_token_append_codepoint(parser, codepoint) != 0) return -1;
            } else if (parser->unicode_value >= 0xd800 && parser->unicode_value <= 0xdbff) {
                parser->high_surrogate = parser->unicode_value;
            } else {
                if (parser->unicode_value >= 0xdc00 && parser->unicode_value <= 0xdfff)
                    return geo_readback_parser_fail(parser);
                if (geo_json_token_append_codepoint(parser, parser->unicode_value) != 0) return -1;
            }
            parser->lexer = GEO_JSON_LEX_STRING;
            continue;
        }
        if (parser->lexer == GEO_JSON_LEX_NUMBER) {
            if (geo_json_number_char(parser, ch, &consumed) != 0) return -1;
            if (consumed) {
                offset++;
                continue;
            }
        }
        if (parser->lexer == GEO_JSON_LEX_LITERAL) {
            if (!parser->literal || ch != (unsigned char)parser->literal[parser->literal_at])
                return geo_readback_parser_fail(parser);
            parser->literal_at++;
            offset++;
            if (!parser->literal[parser->literal_at])
                parser->lexer = GEO_JSON_LEX_NORMAL;
            continue;
        }
        if (parser->root_done) {
            if (!isspace(ch)) return geo_readback_parser_fail(parser);
            offset++;
            continue;
        }
        container = parser->depth ? &parser->stack[parser->depth - 1] : NULL;
        if (isspace(ch)) {
            offset++;
        } else if (ch == '"') {
            if (container && container->type == GEO_JSON_OBJECT &&
                (container->state == GEO_JSON_OBJECT_KEY_OR_END ||
                 container->state == GEO_JSON_OBJECT_KEY_REQUIRED)) {
                geo_json_start_string(parser, 1);
            } else {
                if (geo_json_value_begin(parser, GEO_JSON_VALUE_STRING, &role) != 0) return -1;
                geo_json_start_string(parser, 0);
            }
            offset++;
        } else if (ch == '{' || ch == '[') {
            enum geo_json_value_type value_type = ch == '{' ? GEO_JSON_VALUE_OBJECT :
                                                               GEO_JSON_VALUE_ARRAY;
            if (geo_json_value_begin(parser, value_type, &role) != 0 ||
                geo_json_push(parser, ch == '{' ? GEO_JSON_OBJECT : GEO_JSON_ARRAY, role) != 0)
                return -1;
            offset++;
        } else if (ch == '}' || ch == ']') {
            if (geo_json_close(parser, ch == '}' ? GEO_JSON_OBJECT : GEO_JSON_ARRAY) != 0)
                return -1;
            offset++;
        } else if (ch == ':') {
            if (!container || container->type != GEO_JSON_OBJECT ||
                container->state != GEO_JSON_OBJECT_COLON)
                return geo_readback_parser_fail(parser);
            container->state = GEO_JSON_OBJECT_VALUE;
            offset++;
        } else if (ch == ',') {
            if (!container) return geo_readback_parser_fail(parser);
            if (container->type == GEO_JSON_OBJECT &&
                container->state == GEO_JSON_OBJECT_COMMA_OR_END)
                container->state = GEO_JSON_OBJECT_KEY_REQUIRED;
            else if (container->type == GEO_JSON_ARRAY &&
                     container->state == GEO_JSON_ARRAY_COMMA_OR_END)
                container->state = GEO_JSON_ARRAY_VALUE_REQUIRED;
            else
                return geo_readback_parser_fail(parser);
            offset++;
        } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
            if (geo_json_value_begin(parser, GEO_JSON_VALUE_NUMBER, &role) != 0) return -1;
            parser->lexer = GEO_JSON_LEX_NUMBER;
            parser->number = ch == '-' ? GEO_JSON_NUM_MINUS :
                             ch == '0' ? GEO_JSON_NUM_ZERO : GEO_JSON_NUM_INTEGER;
            parser->token_len = 0;
            parser->token_overflow = 0;
            parser->token_has_nul = 0;
            parser->token[parser->token_len++] = (char)ch;
            offset++;
        } else if (ch == 't' || ch == 'f' || ch == 'n') {
            enum geo_json_value_type value_type = ch == 't' ? GEO_JSON_VALUE_TRUE :
                                                       ch == 'f' ? GEO_JSON_VALUE_FALSE :
                                                                   GEO_JSON_VALUE_NULL;
            if (geo_json_value_begin(parser, value_type, &role) != 0) return -1;
            parser->literal = ch == 't' ? "true" : ch == 'f' ? "false" : "null";
            parser->literal_at = 1;
            parser->lexer = GEO_JSON_LEX_LITERAL;
            offset++;
        } else {
            return geo_readback_parser_fail(parser);
        }
    }
    return 0;
}

static int geo_readback_parser_finish(struct geo_readback_parser *parser,
                                      struct geo_runtime_counts *counts)
{
    if (!parser || !counts || parser->failed)
        return -1;
    if (parser->lexer == GEO_JSON_LEX_NUMBER &&
        geo_json_number_accepting(parser->number)) {
        if (geo_json_number_complete(parser) != 0)
            return -1;
        parser->lexer = GEO_JSON_LEX_NORMAL;
    }
    if (parser->lexer != GEO_JSON_LEX_NORMAL || parser->depth ||
        !parser->root_done || !parser->nftables_seen || parser->target_table_count != 1)
        return geo_readback_parser_fail(parser);
    *counts = parser->counts;
    return 0;
}
/* GEO_READBACK_STREAM_END */

/* GEO_READBACK_CAPTURE_BEGIN */
static uint64_t geo_monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}

static int geo_readback_child_reap(pid_t pid, int terminate, uint64_t deadline,
                                   int *status_out)
{
    int status = 0;
    pid_t waited;

    if (terminate)
        (void)kill(pid, SIGTERM);
    for (;;) {
        uint64_t now = geo_monotonic_ms();

        do {
            waited = waitpid(pid, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid) {
            if (status_out) *status_out = status;
            return 0;
        }
        if (waited < 0 && errno == ECHILD)
            return -1;
        if (!now || now >= deadline)
            break;
        usleep(10000);
    }
    (void)kill(pid, SIGKILL);
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited == pid && status_out) *status_out = status;
    return waited == pid ? 0 : -1;
}

static int geo_capture_readback(struct geo_runtime_counts *counts)
{
    const char *nft = geo_nft_binary();
    struct geo_readback_parser parser;
    unsigned char chunk[GEO_READBACK_CHUNK_BYTES];
    struct pollfd pfd;
    uint64_t started, total = 0;
    int pipefd[2] = { -1, -1 };
    int logfd = -1, status = 0, parse_rc = 0, eof = 0;
    pid_t pid;

    memset(counts, 0, sizeof(*counts));
    unlink(GEO_LEGACY_READBACK_PATH);
    if (!nft[0] || pipe(pipefd) != 0)
        return -1;
    (void)fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        logfd = open(GEO_NFT_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        close(pipefd[0]);
        if (logfd < 0)
            _exit(127);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        {
            struct rlimit limit = { GEO_NFT_LOG_MAX_BYTES, GEO_NFT_LOG_MAX_BYTES };
            (void)setrlimit(RLIMIT_FSIZE, &limit);
            (void)dup2(logfd, STDERR_FILENO);
        }
        if (pipefd[1] > STDERR_FILENO) close(pipefd[1]);
        if (logfd > STDERR_FILENO) close(logfd);
        (void)setenv("LC_ALL", "C", 1);
        execl(nft, nft, "-j", "list", "table", "inet", GEO_NFT_TABLE, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    if (fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK) < 0)
        parse_rc = -1;
    geo_readback_parser_init(&parser);
    started = geo_monotonic_ms();
    pfd.fd = pipefd[0];
    pfd.events = POLLIN | POLLHUP;
    while (!parse_rc && !eof) {
        uint64_t now = geo_monotonic_ms();
        int timeout, poll_rc;

        if (!started || !now || now - started >= GEO_READBACK_TIMEOUT_MS) {
            parse_rc = -1;
            break;
        }
        timeout = (int)(GEO_READBACK_TIMEOUT_MS - (now - started));
        if (timeout > 250) timeout = 250;
        do {
            poll_rc = poll(&pfd, 1, timeout);
        } while (poll_rc < 0 && errno == EINTR);
        if (poll_rc < 0 || (pfd.revents & (POLLERR | POLLNVAL))) {
            parse_rc = -1;
            break;
        }
        if (!poll_rc)
            continue;
        for (;;) {
            ssize_t n = read(pipefd[0], chunk, sizeof(chunk));
            if (n > 0) {
                uint64_t now = geo_monotonic_ms();
                if (!now || now - started >= GEO_READBACK_TIMEOUT_MS ||
                    (uint64_t)n > GEO_READBACK_MAX_BYTES - total ||
                    geo_readback_parser_feed(&parser, chunk, (size_t)n) != 0) {
                    parse_rc = -1;
                    break;
                }
                total += (uint64_t)n;
            } else if (n == 0) {
                eof = 1;
                break;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno != EINTR) {
                parse_rc = -1;
                break;
            }
        }
    }
    close(pipefd[0]);
    pipefd[0] = -1;
    if (parse_rc || !eof) {
        uint64_t now = geo_monotonic_ms();
        (void)geo_readback_child_reap(pid, 1,
                                     now ? now + 250ULL : UINT64_MAX, &status);
        return -1;
    }
    if (geo_readback_child_reap(pid, 0, started + GEO_READBACK_TIMEOUT_MS, &status) != 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        geo_readback_parser_finish(&parser, counts) != 0)
        return -1;
    return 0;
}
/* GEO_READBACK_CAPTURE_END */

static int geo_snapshot_table(const char *path)
{
    const char *nft = geo_nft_binary();
    char *argv[] = { (char *)nft, "-s", "list", "table", "inet", GEO_NFT_TABLE, NULL };
    return nft[0] ? geo_nft_run(argv, path) : -1;
}

static int geo_nft_file_run(const char *path, int check)
{
    const char *nft = geo_nft_binary();
    char *check_argv[] = { (char *)nft, "-c", "-f", (char *)path, NULL };
    char *apply_argv[] = { (char *)nft, "-f", (char *)path, NULL };
    return nft[0] ? geo_nft_run(check ? check_argv : apply_argv, NULL) : -1;
}

static int geo_write_restore_batch(const char *path, int current_present,
                                   int restore_present, const char *snapshot)
{
    FILE *out;
    FILE *in = NULL;
    char line[4096];
    uint64_t total = 0;

    out = fopen(path, "w");
    if (!out)
        return -1;
    if (current_present)
        fprintf(out, "delete table inet %s\n", GEO_NFT_TABLE);
    if (restore_present) {
        in = fopen(snapshot, "r");
        if (!in)
            goto failed;
        while (fgets(line, sizeof(line), in)) {
            size_t length = strlen(line);
            if (length > GEO_NFT_FILE_MAX_BYTES - total || fputs(line, out) == EOF)
                goto failed;
            total += length;
        }
        if (ferror(in))
            goto failed;
    }
    if (in) fclose(in);
    if (fflush(out) != 0 || ftello(out) < 0 ||
        (uint64_t)ftello(out) > GEO_NFT_FILE_MAX_BYTES ||
        fsync(fileno(out)) != 0 || fclose(out) != 0)
        return -1;
    return 0;
failed:
    if (in) fclose(in);
    fclose(out);
    return -1;
}

static int geo_restore_transaction(int had_table, const char *snapshot,
                                   int had_active, const char *active_snapshot)
{
    char batch[AEGISXD_MAX_PATH];
    int current = geo_nft_table_state();

    if (current < 0)
        return -1;

    snprintf(batch, sizeof(batch), "%s/geo-restore-%ld.nft", AEGISXD_RUNTIME_DIR, (long)getpid());
    if ((current || had_table) &&
        (geo_write_restore_batch(batch, current, had_table, snapshot) != 0 ||
         geo_nft_file_run(batch, 1) != 0 || geo_nft_file_run(batch, 0) != 0)) {
        unlink(batch);
        return -1;
    }
    unlink(batch);
    current = geo_nft_table_state();
    if (current < 0 || current != !!had_table)
        return -1;
    if (had_active) {
        if (geo_copy_file(active_snapshot, GEO_ACTIVE_PATH) != 0)
            return -1;
    } else {
        unlink(GEO_ACTIVE_PATH);
    }
    return 0;
}

static int geo_save_previous(int had_table, const char *snapshot,
                             int had_active, const char *active_snapshot)
{
    struct json_object *meta = json_object_new_object();
    int rc = 0;

    if ((had_table && geo_file_size_capped(snapshot, GEO_NFT_FILE_MAX_BYTES) == 0) ||
        (had_active && geo_file_size_capped(active_snapshot,
                                            GEO_RUNTIME_METADATA_BYTES) == 0)) {
        json_object_put(meta);
        return -1;
    }
    if (had_table) {
        if (geo_copy_file(snapshot, GEO_PREVIOUS_NFT_PATH) != 0)
            rc = -1;
    } else {
        unlink(GEO_PREVIOUS_NFT_PATH);
    }
    if (rc == 0 && had_active) {
        if (geo_copy_file(active_snapshot, GEO_PREVIOUS_ACTIVE_PATH) != 0)
            rc = -1;
    } else if (!had_active) {
        unlink(GEO_PREVIOUS_ACTIVE_PATH);
    }
    json_object_object_add(meta, "had_table", json_object_new_boolean(had_table));
    json_object_object_add(meta, "had_active_state", json_object_new_boolean(had_active));
    json_object_object_add(meta, "saved_at", json_object_new_int64(aegisxd_now_s()));
    aegisxd_json_add_string(meta, "nft_table", GEO_NFT_TABLE);
    if (rc == 0 && geo_write_json_atomic(GEO_PREVIOUS_META_PATH, meta) != 0)
        rc = -1;
    json_object_put(meta);
    return rc;
}

static int geo_request_revision(struct json_object *body, int64_t *revision)
{
    struct json_object *v = NULL;
    if (!body || !json_object_object_get_ex(body, "revision", &v) || !v ||
        !json_object_is_type(v, json_type_int))
        return -1;
    *revision = json_object_get_int64(v);
    return 0;
}

static int geo_revision_now(int64_t *revision)
{
    sqlite3 *db = NULL;
    int rc;
    if (geo_open_readonly(AEGISXD_CONFIG_DB_PATH, &db) != 0)
        return -1;
    rc = geo_load_revision(db, revision);
    sqlite3_close(db);
    return rc;
}

static void geo_add_plan_json(struct json_object *o, const struct geo_plan *plan)
{
    struct json_object *countries = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    int i;

    json_object_object_add(o, "revision", json_object_new_int64(plan->revision));
    json_object_object_add(o, "country_count", json_object_new_int(plan->country_count));
    json_object_object_add(o, "rule_count", json_object_new_int(plan->rule_count));
    json_object_object_add(o, "set_count", json_object_new_int(plan->set_count));
    json_object_object_add(o, "prefix_count", json_object_new_int64(plan->prefix_count));
    json_object_object_add(o, "compiled_rule_count", json_object_new_int(plan->compiled_rule_count));
    for (i = 0; i < plan->country_count; i++) {
        struct json_object *c = json_object_new_object();
        aegisxd_json_add_string(c, "code", plan->countries[i].code);
        json_object_object_add(c, "ipv4_prefixes", json_object_new_int(plan->countries[i].ipv4_prefixes));
        json_object_object_add(c, "ipv6_prefixes", json_object_new_int(plan->countries[i].ipv6_prefixes));
        json_object_array_add(countries, c);
    }
    for (i = 0; i < plan->rule_count; i++) {
        struct json_object *r = json_object_new_object();
        aegisxd_json_add_string(r, "id", plan->rules[i].id);
        aegisxd_json_add_string(r, "action", plan->rules[i].action);
        aegisxd_json_add_string(r, "direction", plan->rules[i].direction);
        aegisxd_json_add_string(r, "src_zone", plan->rules[i].src_zone);
        aegisxd_json_add_string(r, "dst_zone", plan->rules[i].dst_zone);
        json_object_object_add(r, "src_ifname_count", json_object_new_int(plan->rules[i].src.count));
        json_object_object_add(r, "dst_ifname_count", json_object_new_int(plan->rules[i].dst.count));
        json_object_array_add(rules, r);
    }
    json_object_object_add(o, "countries", countries);
    json_object_object_add(o, "rules", rules);
}

static void geo_add_capabilities(struct json_object *o, int ready)
{
    struct json_object *cap = json_object_new_object();
    struct geo_runtime_space space;
    int nft = geo_nft_binary()[0] != '\0';
    int mmdb = access(GEO_MMDB_PATH, R_OK) == 0;

    json_object_object_add(cap, "compiled", json_object_new_boolean(1));
    json_object_object_add(cap, "dataplane_supported", json_object_new_boolean(nft));
    json_object_object_add(cap, "dataplane_ready", json_object_new_boolean(nft && ready));
    json_object_object_add(cap, "mmdb_source", json_object_new_boolean(1));
    json_object_object_add(cap, "mmdb_present", json_object_new_boolean(mmdb));
    json_object_object_add(cap, "mmdb_validated_for_plan", json_object_new_boolean(ready));
    aegisxd_json_add_string(cap, "mmdb_path", GEO_MMDB_PATH);
    json_object_object_add(cap, "sqlite_prefix_table_required", json_object_new_boolean(0));
    json_object_object_add(cap, "selected_country_materialization", json_object_new_boolean(1));
    json_object_object_add(cap, "preview", json_object_new_boolean(1));
    json_object_object_add(cap, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "revision_recheck", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_check", json_object_new_boolean(nft));
    json_object_object_add(cap, "atomic_apply", json_object_new_boolean(nft));
    json_object_object_add(cap, "active_readback", json_object_new_boolean(nft));
    json_object_object_add(cap, "rollback", json_object_new_boolean(nft));
    /* Per-country and per-rule packet/byte counters are read back from the
     * generated nft rule comments, so they are available whenever the nft
     * dataplane is available. Hit *events* are a separate producer and are not
     * claimed here.
     */
    json_object_object_add(cap, "counters_supported", json_object_new_boolean(nft));
    json_object_object_add(cap, "per_country_counters", json_object_new_boolean(nft));
    json_object_object_add(cap, "per_rule_counters", json_object_new_boolean(nft));
    json_object_object_add(cap, "counter_events_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "per_packet_mmdb_lookup", json_object_new_boolean(0));
    memset(&space, 0, sizeof(space));
    (void)geo_runtime_space_check(NULL, geo_file_size_capped(GEO_NFT_PATH, 1) > 0,
                                  &space);
    geo_add_runtime_space_json(cap, &space);
    json_object_object_add(o, "capabilities", cap);
}

static struct json_object *geo_error_response(const char *code, const char *detail,
                                              int64_t revision)
{
    struct json_object *o = aegisxd_error(code, detail);
    json_object_object_add(o, "revision", json_object_new_int64(revision));
    json_object_object_add(o, "changed", json_object_new_boolean(0));
    json_object_object_add(o, "dataplane_changed", json_object_new_boolean(0));
    aegisxd_json_add_string(o, "nft_table", GEO_NFT_TABLE);
    geo_add_capabilities(o, 0);
    return o;
}

static int geo_readback_matches_plan(const struct geo_plan *plan,
                                     const struct geo_runtime_counts *readback)
{
    int i;

    if (!plan || !readback || !readback->table_found ||
        readback->set_count != plan->set_count ||
        readback->rule_count != plan->compiled_rule_count ||
        readback->element_count != plan->prefix_count)
        return 0;
    for (i = 0; i < plan->country_count; i++) {
        int family;
        for (family = 4; family <= 6; family += 2) {
            char expected_name[16];
            char lower[3] = {
                (char)tolower((unsigned char)plan->countries[i].code[0]),
                (char)tolower((unsigned char)plan->countries[i].code[1]), '\0'
            };
            int expected = family == 4 ? plan->countries[i].ipv4_prefixes :
                                         plan->countries[i].ipv6_prefixes;
            int j, found = 0;

            if (expected <= 0)
                continue;
            snprintf(expected_name, sizeof(expected_name), "geo_%s_v%d", lower, family);
            for (j = 0; j < readback->set_count; j++)
                if (!strcmp(readback->sets[j].name, expected_name) &&
                    readback->sets[j].element_count == expected) {
                    found = 1;
                    break;
                }
            if (!found)
                return 0;
        }
    }
    return 1;
}

static void geo_add_counter_totals_json(struct json_object *target,
                                        const struct geo_counter_totals *totals)
{
    uint64_t packets = totals->inbound_packets + totals->outbound_packets;
    uint64_t bytes = totals->inbound_bytes + totals->outbound_bytes;

    json_object_object_add(target, "packets", json_object_new_uint64(packets));
    json_object_object_add(target, "bytes", json_object_new_uint64(bytes));
    json_object_object_add(target, "inbound_packets",
                           json_object_new_uint64(totals->inbound_packets));
    json_object_object_add(target, "inbound_bytes",
                           json_object_new_uint64(totals->inbound_bytes));
    json_object_object_add(target, "outbound_packets",
                           json_object_new_uint64(totals->outbound_packets));
    json_object_object_add(target, "outbound_bytes",
                           json_object_new_uint64(totals->outbound_bytes));
    json_object_object_add(target, "rule_lines", json_object_new_int(totals->rule_lines));
    json_object_object_add(target, "counter_lines", json_object_new_int(totals->counter_lines));
}

/* Live nft counter readback for the AegisXD-owned Geo table.
 *
 * Totals come only from rule lines carrying the generated
 * `aegis_geo:<rule_id>:<direction>:<COUNTRY>` comment, so per-rule and
 * per-country attribution is exact. When the table is absent the response is an
 * explicit unsupported/inactive state rather than zeroed counters that would
 * look like real "no traffic" data.
 */
struct json_object *aegisxd_geo_counters_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *rules, *countries;
    struct geo_runtime_counts readback;
    int table_state = geo_nft_table_state();
    int i;

    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "scope", "geo_country_counters");
    aegisxd_json_add_string(resp, "nft_table", GEO_NFT_TABLE);
    json_object_object_add(resp, "counters_supported",
                           json_object_new_boolean(geo_nft_binary()[0] != '\0'));
    if (!geo_nft_binary()[0]) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "active", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "error", "nft_binary_missing");
        return resp;
    }
    if (table_state < 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "active", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "error", "nft_table_probe_failed");
        aegisxd_json_add_string(resp, "reason", GEO_NFT_LOG);
        return resp;
    }
    if (table_state == 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "active", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "reason", "geo_nft_table_absent");
        return resp;
    }
    if (geo_capture_readback(&readback) != 0 || !readback.table_found) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "active", json_object_new_boolean(1));
        aegisxd_json_add_string(resp, "error", "geo_counter_readback_failed");
        aegisxd_json_add_string(resp, "reason", GEO_NFT_LOG);
        return resp;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "active", json_object_new_boolean(1));
    json_object_object_add(resp, "collected_at", json_object_new_int64(aegisxd_now_s()));
    json_object_object_add(resp, "runtime_rule_line_count",
                           json_object_new_int(readback.rule_count));
    json_object_object_add(resp, "owned_rule_line_count",
                           json_object_new_int(readback.owned_rule_lines));
    json_object_object_add(resp, "foreign_rule_line_count",
                           json_object_new_int(readback.foreign_rule_lines));
    json_object_object_add(resp, "rule_lines_without_counter",
                           json_object_new_int(readback.rule_lines_without_counter));
    json_object_object_add(resp, "counters_truncated",
                           json_object_new_boolean(readback.rule_counter_bucket_overflow));
    geo_add_counter_totals_json(resp, &readback.counter_totals);

    rules = json_object_new_array();
    for (i = 0; i < readback.rule_counter_count; i++) {
        struct json_object *item = json_object_new_object();

        aegisxd_json_add_string(item, "rule_id", readback.rule_counters[i].rule_id);
        geo_add_counter_totals_json(item, &readback.rule_counters[i].totals);
        json_object_array_add(rules, item);
    }
    json_object_object_add(resp, "rules", rules);

    countries = json_object_new_array();
    for (i = 0; i < readback.country_counter_count; i++) {
        struct json_object *item = json_object_new_object();

        aegisxd_json_add_string(item, "country_code", readback.country_counters[i].country);
        geo_add_counter_totals_json(item, &readback.country_counters[i].totals);
        json_object_array_add(countries, item);
    }
    json_object_object_add(resp, "countries", countries);
    return resp;
}

struct json_object *aegisxd_geo_get_json(void)
{
    struct geo_plan plan;
    struct json_object *resp = json_object_new_object();
    struct json_object *active = geo_read_json(GEO_ACTIVE_PATH);
    int ready = geo_plan_load(&plan) == 0;
    int table_state = geo_nft_table_state();
    int table = table_state == 1;

    json_object_object_add(resp, "ok", json_object_new_boolean(ready && table_state >= 0));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "scope", "geo_country");
    aegisxd_json_add_string(resp, "nft_table", GEO_NFT_TABLE);
    aegisxd_json_add_string(resp, "config_source", AEGISXD_CONFIG_DB_PATH ":firewall_geo_country,firewall_geo_rule,firewall_geo_meta");
    aegisxd_json_add_string(resp, "prefix_source", GEO_MMDB_PATH);
    if (plan.revision >= 0)
        json_object_object_add(resp, "revision", json_object_new_int64(plan.revision));
    if (ready)
        geo_add_plan_json(resp, &plan);
    else {
        aegisxd_json_add_string(resp, "error", plan.blocker[0] ? plan.blocker : "geo_plan_failed");
        aegisxd_json_add_string(resp, "reason", plan.blocker_detail);
    }
    json_object_object_add(resp, "nft_table_probe_ok",
                           json_object_new_boolean(table_state >= 0));
    if (table_state < 0) {
        aegisxd_json_add_string(resp, "runtime_error", "nft_table_probe_failed");
        aegisxd_json_add_string(resp, "runtime_reason", GEO_NFT_LOG);
    }
    json_object_object_add(resp, "nft_table_present", json_object_new_boolean(table));
    json_object_object_add(resp, "active", json_object_new_boolean(table && active != NULL));
    if (active)
        json_object_object_add(resp, "active_readback", active);
    else
        json_object_object_add(resp, "active_readback", json_object_new_null());
    geo_add_capabilities(resp, ready && table_state >= 0);
    geo_plan_close(&plan);
    return resp;
}

static struct json_object *geo_apply_plan(struct json_object *body, int confirm)
{
    struct geo_plan plan;
    struct geo_runtime_counts readback;
    struct json_object *resp = NULL;
    struct json_object *active = NULL;
    int table_before;
    int had_active;
    int check_rc;
    int apply_rc = -1;
    int rollback_rc = 0;
    int64_t request_revision = -1, current_revision = -1;
    char snapshot[AEGISXD_MAX_PATH], artifact[AEGISXD_MAX_PATH];
    char active_snapshot[AEGISXD_MAX_PATH];
    struct geo_runtime_space space;

    memset(&plan, 0, sizeof(plan));
    snprintf(snapshot, sizeof(snapshot), "%s/geo-before-%ld.nft", AEGISXD_RUNTIME_DIR, (long)getpid());
    snprintf(artifact, sizeof(artifact), "%s/geo-plan-%ld.nft", AEGISXD_RUNTIME_DIR, (long)getpid());
    snprintf(active_snapshot, sizeof(active_snapshot), "%s/geo-before-active-%ld.json", AEGISXD_RUNTIME_DIR, (long)getpid());
    if (geo_plan_load(&plan) != 0) {
        resp = geo_error_response(plan.blocker, plan.blocker_detail, plan.revision);
        goto done;
    }
    table_before = geo_nft_table_state();
    if (table_before < 0) {
        resp = geo_error_response("nft_table_probe_failed", GEO_NFT_LOG,
                                  plan.revision);
        goto done;
    }
    if (geo_runtime_space_check(&plan, table_before, &space) != 0) {
        resp = geo_error_response("geo_runtime_space_insufficient", space.reason,
                                  plan.revision);
        geo_add_runtime_space_json(resp, &space);
        goto done;
    }
    if (geo_render_nft(&plan, artifact, table_before) != 0) {
        resp = geo_error_response("geo_nft_render_failed", "failed to render validated prefix/rule plan", plan.revision);
        goto done;
    }
    check_rc = geo_nft_file_run(artifact, 1);
    if (check_rc != 0) {
        resp = geo_error_response("geo_nft_check_failed", GEO_NFT_LOG, plan.revision);
        json_object_object_add(resp, "nft_check_exit_status", json_object_new_int(check_rc));
        goto done;
    }
    if (!confirm) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "preview", json_object_new_boolean(1));
        json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "operation", "apply");
        aegisxd_json_add_string(resp, "nft_table", GEO_NFT_TABLE);
        json_object_object_add(resp, "artifact_retained", json_object_new_boolean(0));
        json_object_object_add(resp, "artifact_size_bytes",
                               json_object_new_int64((int64_t)geo_file_size_capped(
                                   artifact, GEO_NFT_FILE_MAX_BYTES)));
        json_object_object_add(resp, "nft_check_exit_status", json_object_new_int(0));
        geo_add_plan_json(resp, &plan);
        geo_add_runtime_space_json(resp, &space);
        geo_add_capabilities(resp, 1);
        goto done;
    }
    if (geo_request_revision(body, &request_revision) != 0) {
        resp = geo_error_response("revision_required", "confirmed Geo apply requires integer revision", plan.revision);
        goto done;
    }
    if (request_revision != plan.revision) {
        resp = geo_error_response("revision_conflict", "Geo configuration changed before compile", plan.revision);
        goto done;
    }
    if (geo_revision_now(&current_revision) != 0 || current_revision != request_revision) {
        resp = geo_error_response("revision_conflict", "Geo configuration changed after nft check", current_revision);
        goto done;
    }
    had_active = access(GEO_ACTIVE_PATH, R_OK) == 0;
    if ((table_before && geo_snapshot_table(snapshot) != 0) ||
        (had_active && geo_copy_file(GEO_ACTIVE_PATH, active_snapshot) != 0)) {
        resp = geo_error_response("geo_snapshot_failed", "refusing apply without rollback snapshot", plan.revision);
        goto done;
    }
    apply_rc = geo_nft_file_run(artifact, 0);
    if (apply_rc != 0 || geo_capture_readback(&readback) != 0 ||
        !geo_readback_matches_plan(&plan, &readback)) {
        rollback_rc = geo_restore_transaction(table_before, snapshot, had_active, active_snapshot);
        resp = geo_error_response(rollback_rc == 0 ? "geo_apply_readback_failed" :
                                  "geo_apply_failed_rollback_failed",
                                  GEO_NFT_LOG, plan.revision);
        json_object_object_add(resp, "nft_apply_exit_status", json_object_new_int(apply_rc));
        json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_rc == 0));
        goto done;
    }
    active = json_object_new_object();
    json_object_object_add(active, "active", json_object_new_boolean(1));
    json_object_object_add(active, "revision", json_object_new_int64(plan.revision));
    json_object_object_add(active, "applied_at", json_object_new_int64(aegisxd_now_s()));
    aegisxd_json_add_string(active, "nft_table", GEO_NFT_TABLE);
    aegisxd_json_add_string(active, "config_source", AEGISXD_CONFIG_DB_PATH);
    aegisxd_json_add_string(active, "prefix_source", GEO_MMDB_PATH);
    json_object_object_add(active, "mmdb_source_bytes",
                           json_object_new_int64((int64_t)plan.prefix_stats.source_bytes));
    json_object_object_add(active, "mmdb_nodes_visited",
                           json_object_new_int64((int64_t)plan.prefix_stats.nodes_visited));
    json_object_object_add(active, "mmdb_raw_selected_prefixes",
                           json_object_new_int64((int64_t)plan.prefix_stats.raw_prefixes));
    json_object_object_add(active, "mmdb_merged_prefixes",
                           json_object_new_int64((int64_t)plan.prefix_stats.merged_prefixes));
    json_object_object_add(active, "country_count", json_object_new_int(plan.country_count));
    json_object_object_add(active, "source_rule_count", json_object_new_int(plan.rule_count));
    json_object_object_add(active, "compiled_rule_count", json_object_new_int(plan.compiled_rule_count));
    json_object_object_add(active, "set_count", json_object_new_int(plan.set_count));
    json_object_object_add(active, "source_prefix_count", json_object_new_int64(plan.prefix_count));
    json_object_object_add(active, "runtime_element_count", json_object_new_int64(readback.element_count));
    if (geo_write_json_atomic(GEO_ACTIVE_PATH, active) != 0 ||
        geo_save_previous(table_before, snapshot, had_active, active_snapshot) != 0) {
        rollback_rc = geo_restore_transaction(table_before, snapshot, had_active, active_snapshot);
        resp = geo_error_response(rollback_rc == 0 ? "geo_active_state_write_failed" :
                                  "geo_apply_failed_rollback_failed", GEO_ACTIVE_PATH, plan.revision);
        json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_rc == 0));
        goto done;
    }
    if (geo_copy_file(artifact, GEO_NFT_PATH) != 0) {
        rollback_rc = geo_restore_transaction(table_before, snapshot, had_active, active_snapshot);
        resp = geo_error_response(rollback_rc == 0 ? "geo_active_artifact_write_failed" :
                                  "geo_apply_failed_rollback_failed", GEO_NFT_PATH,
                                  plan.revision);
        json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_rc == 0));
        goto done;
    }
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "preview", json_object_new_boolean(0));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(0));
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(1));
    json_object_object_add(resp, "nft_check_exit_status", json_object_new_int(0));
    json_object_object_add(resp, "nft_apply_exit_status", json_object_new_int(0));
    json_object_object_add(resp, "active_readback", json_object_get(active));
    aegisxd_json_add_string(resp, "operation", "apply");
    geo_add_plan_json(resp, &plan);
    geo_add_runtime_space_json(resp, &space);
    geo_add_capabilities(resp, 1);
done:
    if (active) json_object_put(active);
    unlink(snapshot);
    unlink(artifact);
    unlink(active_snapshot);
    geo_plan_close(&plan);
    return resp ? resp : geo_error_response("geo_apply_failed", "unknown error", current_revision);
}

static int geo_previous_state(int *had_table, int *had_active)
{
    struct json_object *meta = geo_read_json(GEO_PREVIOUS_META_PATH);
    if (!meta)
        return -1;
    *had_table = aegisxd_json_bool(meta, "had_table", 0);
    *had_active = aegisxd_json_bool(meta, "had_active_state", 0);
    json_object_put(meta);
    if (*had_table && access(GEO_PREVIOUS_NFT_PATH, R_OK) != 0)
        return -1;
    if (*had_active && access(GEO_PREVIOUS_ACTIVE_PATH, R_OK) != 0)
        return -1;
    return 0;
}

static struct json_object *geo_disable_or_rollback(struct json_object *body,
                                                   const char *operation, int confirm)
{
    struct json_object *resp;
    struct geo_runtime_counts readback;
    int table_before = geo_nft_table_state();
    int had_active = access(GEO_ACTIVE_PATH, R_OK) == 0;
    int restore_table = 0, restore_active = 0;
    int64_t revision = -1, request_revision = -1, recheck = -1;
    char before[AEGISXD_MAX_PATH], before_active[AEGISXD_MAX_PATH], batch[AEGISXD_MAX_PATH];
    int rc, rollback_rc = 0;
    struct geo_runtime_space space;

    snprintf(before, sizeof(before), "%s/geo-before-%ld.nft", AEGISXD_RUNTIME_DIR, (long)getpid());
    snprintf(before_active, sizeof(before_active), "%s/geo-before-active-%ld.json", AEGISXD_RUNTIME_DIR, (long)getpid());
    snprintf(batch, sizeof(batch), "%s/geo-operation-%ld.nft", AEGISXD_RUNTIME_DIR, (long)getpid());
    if (table_before < 0)
        return geo_error_response("nft_table_probe_failed", GEO_NFT_LOG, -1);
    if (geo_revision_now(&revision) != 0)
        return geo_error_response("geo_revision_unavailable", AEGISXD_CONFIG_DB_PATH, revision);
    if (!strcmp(operation, "rollback") && geo_previous_state(&restore_table, &restore_active) != 0)
        return geo_error_response("geo_rollback_snapshot_unavailable", GEO_PREVIOUS_META_PATH, revision);
    if (!confirm) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "preview", json_object_new_boolean(1));
        json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
        json_object_object_add(resp, "revision", json_object_new_int64(revision));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        json_object_object_add(resp, "would_remove", json_object_new_boolean(!strcmp(operation, "disable") && table_before));
        json_object_object_add(resp, "would_restore_table", json_object_new_boolean(!strcmp(operation, "rollback") && restore_table));
        aegisxd_json_add_string(resp, "operation", operation);
        geo_add_capabilities(resp, 1);
        return resp;
    }
    if (geo_request_revision(body, &request_revision) != 0)
        return geo_error_response("revision_required", "confirmed Geo operation requires integer revision", revision);
    if (request_revision != revision)
        return geo_error_response("revision_conflict", "Geo configuration changed before operation", revision);
    if (geo_runtime_space_check(NULL, table_before || restore_table, &space) != 0) {
        resp = geo_error_response("geo_runtime_space_insufficient", space.reason, revision);
        geo_add_runtime_space_json(resp, &space);
        goto done;
    }
    if ((table_before && geo_snapshot_table(before) != 0) ||
        (had_active && geo_copy_file(GEO_ACTIVE_PATH, before_active) != 0))
        return geo_error_response("geo_snapshot_failed", "refusing operation without rollback snapshot", revision);
    if (!strcmp(operation, "disable")) {
        restore_table = 0;
        restore_active = 0;
    }
    if (geo_write_restore_batch(batch, table_before, restore_table, GEO_PREVIOUS_NFT_PATH) != 0 ||
        ((table_before || restore_table) && geo_nft_file_run(batch, 1) != 0)) {
        resp = geo_error_response("geo_nft_check_failed", GEO_NFT_LOG, revision);
        goto done;
    }
    if (geo_revision_now(&recheck) != 0 || recheck != request_revision) {
        resp = geo_error_response("revision_conflict", "Geo configuration changed after nft check", recheck);
        goto done;
    }
    rc = (table_before || restore_table) ? geo_nft_file_run(batch, 0) : 0;
    {
        int table_after = geo_nft_table_state();
        if (rc != 0 || table_after < 0 || table_after != !!restore_table ||
            (restore_table && (geo_capture_readback(&readback) != 0 ||
                               readback.set_count <= 0 || readback.rule_count <= 0 ||
                               readback.element_count <= 0))) {
            rollback_rc = geo_restore_transaction(table_before, before, had_active, before_active);
            resp = geo_error_response(rollback_rc == 0 ? "geo_operation_readback_failed" :
                                      "geo_operation_failed_rollback_failed", GEO_NFT_LOG, revision);
            json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_rc == 0));
            goto done;
        }
    }
    if (restore_active) {
        if (geo_copy_file(GEO_PREVIOUS_ACTIVE_PATH, GEO_ACTIVE_PATH) != 0) {
            rollback_rc = geo_restore_transaction(table_before, before, had_active, before_active);
            resp = geo_error_response(rollback_rc == 0 ? "geo_active_state_restore_failed" :
                                      "geo_operation_failed_rollback_failed", GEO_ACTIVE_PATH, revision);
            json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_rc == 0));
            goto done;
        }
    } else {
        unlink(GEO_ACTIVE_PATH);
    }
    if (geo_save_previous(table_before, before, had_active, before_active) != 0) {
        rollback_rc = geo_restore_transaction(table_before, before, had_active, before_active);
        resp = geo_error_response(rollback_rc == 0 ? "geo_rollback_rotation_failed" :
                                  "geo_operation_failed_rollback_failed", GEO_PREVIOUS_META_PATH, revision);
        json_object_object_add(resp, "rollback_ok", json_object_new_boolean(rollback_rc == 0));
        goto done;
    }
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "preview", json_object_new_boolean(0));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(0));
    json_object_object_add(resp, "revision", json_object_new_int64(revision));
    json_object_object_add(resp, "changed",
                           json_object_new_boolean(table_before != restore_table ||
                                                   had_active != restore_active));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(table_before != restore_table));
    json_object_object_add(resp, "nft_table_present", json_object_new_boolean(restore_table));
    aegisxd_json_add_string(resp, "operation", operation);
    geo_add_runtime_space_json(resp, &space);
    geo_add_capabilities(resp, 1);
done:
    unlink(before); unlink(before_active); unlink(batch);
    return resp;
}

struct json_object *aegisxd_geo_apply_json(struct json_object *body)
{
    struct json_object *resp;
    const char *operation = aegisxd_json_str(body, "operation", "apply");
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int lockfd;

    if (strcmp(operation, "apply") && strcmp(operation, "preview") &&
        strcmp(operation, "disable") && strcmp(operation, "rollback"))
        return geo_error_response("unsupported_geo_operation", operation, -1);
    if (aegisxd_mkdir_p(AEGISXD_RUNTIME_DIR, 0755) != 0)
        return geo_error_response("geo_runtime_dir_unavailable", AEGISXD_RUNTIME_DIR, -1);
    lockfd = open(GEO_LOCK_PATH, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0) {
        if (lockfd >= 0) close(lockfd);
        return geo_error_response("geo_apply_lock_failed", GEO_LOCK_PATH, -1);
    }
    if (!strcmp(operation, "disable") || !strcmp(operation, "rollback"))
        resp = geo_disable_or_rollback(body, operation, confirm);
    else
        resp = geo_apply_plan(body, !strcmp(operation, "preview") ? 0 : confirm);
    flock(lockfd, LOCK_UN);
    close(lockfd);
    return resp;
}

struct json_object *aegisxd_geo_status_json(void)
{
    struct json_object *get = aegisxd_geo_get_json();
    struct json_object *status = json_object_new_object();
    struct json_object *v = NULL;
    int ready = 0;
    int active = 0;

    if (json_object_object_get_ex(get, "ok", &v))
        ready = json_object_get_boolean(v);
    if (json_object_object_get_ex(get, "active", &v))
        active = json_object_get_boolean(v);
    json_object_object_add(status, "supported", json_object_new_boolean(1));
    json_object_object_add(status, "ready", json_object_new_boolean(ready && geo_nft_binary()[0]));
    json_object_object_add(status, "active", json_object_new_boolean(active));
    json_object_object_add(status, "nft_available", json_object_new_boolean(geo_nft_binary()[0]));
    json_object_object_add(status, "preview_supported", json_object_new_boolean(1));
    json_object_object_add(status, "rollback_supported", json_object_new_boolean(geo_nft_binary()[0]));
    aegisxd_json_add_string(status, "nft_table", GEO_NFT_TABLE);
    if (!ready && json_object_object_get_ex(get, "error", &v))
        json_object_object_add(status, "reason", json_object_get(v));
    else if (!geo_nft_binary()[0])
        aegisxd_json_add_string(status, "reason", "nft_binary_missing");
    else
        aegisxd_json_add_string(status, "reason", "");
    json_object_put(get);
    return status;
}
