// SPDX-License-Identifier: GPL-2.0-or-later
/* PCDN DNS filtering. Remote rules are normalized data, never executable input. */
#include "aegisxd_internal.h"
#include "aegisxd_pcdn_parser.h"

#define PCDN_SOURCE_ID "openhosts-pcdn"
#define PCDN_SOURCE_NAME "OpenHosts PCDN domains"
#define PCDN_SOURCE_URL "https://raw.githubusercontent.com/743859910/OpenHosts/master/Block_PCDN_Domain.txt"
#define PCDN_SOURCE_LICENSE "MIT"
#define PCDN_ARTIFACT_PREFIX AEGISXD_FEED_DIR "/pcdn-openhosts-"
#define PCDN_ARTIFACT_SUFFIX ".domains"
#define PCDN_MAX_BYTES (2U * 1024U * 1024U)
#define PCDN_MAX_RULES 20000U
#define PCDN_MAX_REJECTED 10000U
/* Rejected-rule samples recorded so a source format change can be audited
 * without re-downloading; the count alone cannot say what was dropped. */
#define PCDN_REJECT_SAMPLES 8
#define PCDN_REJECT_SAMPLE_BUFSZ 128

struct pcdn_download {
    FILE *fp;
    size_t written;
    int too_large;
};

struct pcdn_rules {
    char (*items)[AEGISXD_PCDN_DOMAIN_BUFSZ];
    size_t count;
    size_t capacity;
    size_t rejected;
    char samples[PCDN_REJECT_SAMPLES][PCDN_REJECT_SAMPLE_BUFSZ];
    const char *sample_reasons[PCDN_REJECT_SAMPLES];
    size_t sample_count;
};

struct pcdn_settings {
    int enabled;
    int revision;
    char mode[16];
    char source_id[64];
    char apply_state[32];
    char artifact_path[AEGISXD_MAX_PATH];
    char artifact_sha256[65];
    int rule_count;
};

struct pcdn_match_cache {
    struct pcdn_rules rules;
    char artifact_path[AEGISXD_MAX_PATH];
    char artifact_sha256[65];
    int content_revision;
    off_t size;
    time_t mtime;
    int64_t verified_at;
};

static struct pcdn_match_cache g_pcdn_match_cache;

static int pcdn_revision_get(struct json_object *body, int *revision)
{
    struct json_object *v = NULL;

    if (!body || !revision || !json_object_object_get_ex(body, "revision", &v))
        return 0;
    if (!v || !json_object_is_type(v, json_type_int) || json_object_get_int(v) < 0)
        return -1;
    *revision = json_object_get_int(v);
    return 1;
}

static size_t pcdn_write_cb(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct pcdn_download *d = opaque;
    size_t bytes;

    if (!d || !d->fp || (size != 0 && nmemb > SIZE_MAX / size))
        return 0;
    bytes = size * nmemb;
    if (d->written > PCDN_MAX_BYTES || bytes > PCDN_MAX_BYTES - d->written) {
        d->too_large = 1;
        return 0;
    }
    if (fwrite(ptr, 1, bytes, d->fp) != bytes)
        return 0;
    d->written += bytes;
    return bytes;
}

static int pcdn_sha256_file(const char *path, char out[65])
{
    unsigned char buf[16384], digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = NULL;
    FILE *fp = NULL;
    size_t n;
    int ok = 0;

    fp = fopen(path, "rb");
    ctx = EVP_MD_CTX_new();
    if (!fp || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto out;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        if (EVP_DigestUpdate(ctx, buf, n) != 1)
            goto out;
    if (ferror(fp) || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != 32)
        goto out;
    for (unsigned int i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    ok = 1;
out:
    if (fp)
        fclose(fp);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int pcdn_artifact_path_ok(const char *path)
{
    const char *name;
    size_t len, suffix_len = strlen(PCDN_ARTIFACT_SUFFIX);

    if (!path || strncmp(path, PCDN_ARTIFACT_PREFIX, strlen(PCDN_ARTIFACT_PREFIX)))
        return 0;
    name = path + strlen(PCDN_ARTIFACT_PREFIX);
    len = strlen(name);
    if (len != 64 + suffix_len || strchr(name, '/'))
        return 0;
    for (size_t i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)name[i]))
            return 0;
    return !strcmp(name + 64, PCDN_ARTIFACT_SUFFIX);
}

static int pcdn_settings_load(struct pcdn_settings *out)
{
    sqlite3_stmt *st;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    st = aegisxd_config_prepare(
        "SELECT enabled,mode,source_id,revision,apply_state,artifact_path,"
        "artifact_sha256,rule_count FROM aegis_pcdn_settings WHERE id=1");
    if (!st || sqlite3_step(st) != SQLITE_ROW) {
        if (st)
            sqlite3_finalize(st);
        return -1;
    }
    out->enabled = sqlite3_column_int(st, 0);
    snprintf(out->mode, sizeof(out->mode), "%s", aegisxd_sqlite_text(st, 1, "block"));
    snprintf(out->source_id, sizeof(out->source_id), "%s", aegisxd_sqlite_text(st, 2, PCDN_SOURCE_ID));
    out->revision = sqlite3_column_int(st, 3);
    snprintf(out->apply_state, sizeof(out->apply_state), "%s", aegisxd_sqlite_text(st, 4, "disabled"));
    snprintf(out->artifact_path, sizeof(out->artifact_path), "%s", aegisxd_sqlite_text(st, 5, ""));
    snprintf(out->artifact_sha256, sizeof(out->artifact_sha256), "%s", aegisxd_sqlite_text(st, 6, ""));
    out->rule_count = sqlite3_column_int(st, 7);
    sqlite3_finalize(st);
    return 0;
}

static int pcdn_artifact_ready(const struct pcdn_settings *s)
{
    struct stat st;

    return s && s->rule_count > 0 && strlen(s->artifact_sha256) == 64 &&
        pcdn_artifact_path_ok(s->artifact_path) &&
        lstat(s->artifact_path, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size > 0 && st.st_size <= (off_t)PCDN_MAX_BYTES;
}

static int pcdn_artifact_verified(const struct pcdn_settings *s)
{
    char actual_sha256[65] = "";

    return pcdn_artifact_ready(s) &&
        pcdn_sha256_file(s->artifact_path, actual_sha256) == 0 &&
        !strcasecmp(actual_sha256, s->artifact_sha256);
}

struct json_object *aegisxd_pcdn_active_state_json(void)
{
    struct json_object *o = json_object_new_object();
    struct pcdn_settings current;
    int loaded = pcdn_settings_load(&current) == 0;
    int active = loaded && current.enabled &&
        (!strcmp(current.mode, "block") || !strcmp(current.mode, "monitor")) &&
        pcdn_artifact_verified(&current);

    json_object_object_add(o, "enabled", json_object_new_boolean(active));
    aegisxd_json_add_string(o, "mode", loaded ? current.mode : "block");
    aegisxd_json_add_string(o, "source_id", loaded ? current.source_id : PCDN_SOURCE_ID);
    aegisxd_json_add_string(o, "artifact_sha256", active ? current.artifact_sha256 : "");
    json_object_object_add(o, "rule_count",
                           json_object_new_int(active ? current.rule_count : 0));
    aegisxd_json_add_string(o, "dataplane", loaded && !strcmp(current.mode, "monitor") ?
                            "dnsmasq_query_monitor" : "dnsmasq_domain_block");
    json_object_object_add(o, "blocking",
                           json_object_new_boolean(active && !strcmp(current.mode, "block")));
    json_object_object_add(o, "monitoring",
                           json_object_new_boolean(active && !strcmp(current.mode, "monitor")));
    return o;
}

static struct json_object *pcdn_installed_state_json(void)
{
    struct json_object *installed = json_object_new_object();
    struct json_object *active_root = NULL, *active_pcdn = NULL;
    const char *dns_file = "";
    char mode[16] = "off";
    int active = 0, effective_rules = 0;

    active_root = json_object_from_file(AEGISXD_RUNTIME_DIR "/active.json");
    if (active_root && json_object_is_type(active_root, json_type_object)) {
        dns_file = aegisxd_json_str(active_root, "dnsmasq_conf_file", "");
        if (dns_file[0] && access(dns_file, R_OK) == 0 &&
            json_object_object_get_ex(active_root, "pcdn", &active_pcdn) &&
            active_pcdn && json_object_is_type(active_pcdn, json_type_object) &&
            aegisxd_json_bool(active_pcdn, "enabled", 0)) {
            json_object_put(installed);
            installed = json_object_get(active_pcdn);
            active = 1;
        }
    }
    if (active) {
        snprintf(mode, sizeof(mode), "%s", aegisxd_json_str(installed, "mode", ""));
        if (strcmp(mode, "block") && strcmp(mode, "monitor"))
            snprintf(mode, sizeof(mode), "%s",
                     !strcmp(aegisxd_json_str(installed, "dataplane", ""),
                             "dnsmasq_query_monitor") ? "monitor" : "block");
        effective_rules = json_object_get_int(
            json_object_object_get(installed, "effective_rule_count"));
        if (effective_rules <= 0)
            effective_rules = aegisxd_pcdn_effective_rule_count(dns_file);
        json_object_object_add(installed, "effective_rule_count",
                               json_object_new_int(effective_rules));
        aegisxd_json_add_string(installed, "mode", mode);
        json_object_object_add(installed, "blocking",
                               json_object_new_boolean(!strcmp(mode, "block") &&
                                                       effective_rules > 0));
        json_object_object_add(installed, "monitoring",
                               json_object_new_boolean(!strcmp(mode, "monitor")));
    }
    if (!active) {
        json_object_object_add(installed, "enabled", json_object_new_boolean(0));
        aegisxd_json_add_string(installed, "artifact_sha256", "");
        json_object_object_add(installed, "rule_count", json_object_new_int(0));
        json_object_object_add(installed, "effective_rule_count", json_object_new_int(0));
        aegisxd_json_add_string(installed, "mode", "off");
        aegisxd_json_add_string(installed, "dataplane", "none");
        json_object_object_add(installed, "blocking", json_object_new_boolean(0));
        json_object_object_add(installed, "monitoring", json_object_new_boolean(0));
    }
    json_object_object_add(installed, "readback_ok", json_object_new_boolean(active));
    aegisxd_json_add_string(installed, "readback_source", AEGISXD_RUNTIME_DIR "/active.json");
    if (active_root)
        json_object_put(active_root);
    return installed;
}

static int pcdn_active_artifact_path(char out[AEGISXD_MAX_PATH])
{
    struct json_object *root = NULL, *pcdn = NULL;
    const char *sha256 = "";
    int ok = 0;

    if (!out)
        return -1;
    out[0] = '\0';
    root = json_object_from_file(AEGISXD_RUNTIME_DIR "/active.json");
    if (!root || !json_object_is_type(root, json_type_object) ||
        !json_object_object_get_ex(root, "pcdn", &pcdn) || !pcdn ||
        !json_object_is_type(pcdn, json_type_object) ||
        !aegisxd_json_bool(pcdn, "enabled", 0))
        goto out;
    sha256 = aegisxd_json_str(pcdn, "artifact_sha256", "");
    if (strlen(sha256) != 64)
        goto out;
    for (size_t i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)sha256[i]))
            goto out;
    if (snprintf(out, AEGISXD_MAX_PATH, PCDN_ARTIFACT_PREFIX "%s" PCDN_ARTIFACT_SUFFIX,
                 sha256) >= AEGISXD_MAX_PATH)
        out[0] = '\0';
    else
        ok = 1;
out:
    if (root)
        json_object_put(root);
    return ok ? 0 : -1;
}

static struct json_object *pcdn_cleanup_artifacts(const char *current,
                                                  const char *previous)
{
    struct json_object *o = json_object_new_object();
    char active[AEGISXD_MAX_PATH] = "";
    DIR *dir = opendir(AEGISXD_FEED_DIR);
    struct dirent *de;
    int scanned = 0, removed = 0, failed = 0;

    (void)pcdn_active_artifact_path(active);
    if (!dir) {
        json_object_object_add(o, "ok", json_object_new_boolean(errno == ENOENT));
        aegisxd_json_add_string(o, "error", errno == ENOENT ? "" : "pcdn_artifact_dir_unavailable");
        return o;
    }
    while ((de = readdir(dir)) != NULL) {
        char path[AEGISXD_MAX_PATH];
        size_t prefix_len = strlen("pcdn-openhosts-");
        size_t suffix_len = strlen(PCDN_ARTIFACT_SUFFIX);
        size_t len = strlen(de->d_name);

        if (len != prefix_len + 64 + suffix_len ||
            strncmp(de->d_name, "pcdn-openhosts-", prefix_len) ||
            strcmp(de->d_name + len - suffix_len, PCDN_ARTIFACT_SUFFIX))
            continue;
        for (size_t i = prefix_len; i < prefix_len + 64; i++)
            if (!isxdigit((unsigned char)de->d_name[i]))
                goto next_entry;
        scanned++;
        if (snprintf(path, sizeof(path), "%s/%s", AEGISXD_FEED_DIR, de->d_name) >=
            (int)sizeof(path)) {
            failed++;
            continue;
        }
        if ((current && current[0] && !strcmp(path, current)) ||
            (previous && previous[0] && !strcmp(path, previous)) ||
            (active[0] && !strcmp(path, active)))
            continue;
        if (unlink(path) == 0)
            removed++;
        else
            failed++;
next_entry:
        ;
    }
    closedir(dir);
    json_object_object_add(o, "ok", json_object_new_boolean(failed == 0));
    json_object_object_add(o, "files_scanned", json_object_new_int(scanned));
    json_object_object_add(o, "files_removed", json_object_new_int(removed));
    json_object_object_add(o, "files_failed", json_object_new_int(failed));
    json_object_object_add(o, "retained_max", json_object_new_int(3));
    return o;
}

static struct json_object *pcdn_capabilities(void)
{
    struct json_object *o = json_object_new_object();
    struct json_object *modes = json_object_new_array();
    struct json_object *formats = json_object_new_array();

    json_object_array_add(modes, json_object_new_string("block"));
    json_object_array_add(modes, json_object_new_string("monitor"));
    json_object_array_add(formats, json_object_new_string("domain"));
    json_object_array_add(formats, json_object_new_string("hosts"));
    json_object_array_add(formats, json_object_new_string("adblock_domain"));
    json_object_object_add(o, "pcdn_filter_supported", json_object_new_boolean(1));
    json_object_object_add(o, "pcdn_feed_update", json_object_new_boolean(1));
    json_object_object_add(o, "pcdn_guarded_apply", json_object_new_boolean(1));
    json_object_object_add(o, "pcdn_rollback", json_object_new_boolean(1));
    json_object_object_add(o, "pcdn_monitor_supported", json_object_new_boolean(1));
    json_object_object_add(o, "pcdn_hit_monitoring_supported", json_object_new_boolean(1));
    json_object_object_add(o, "pcdn_hit_attribution_ready",
                           json_object_new_boolean(aegisxd_pcdn_hit_attribution_ready()));
    json_object_object_add(o, "device_attribution_supported", json_object_new_boolean(1));
    aegisxd_json_add_string(o, "device_attribution_precision", "source_ip_with_neighbor_mac_best_effort");
    json_object_object_add(o, "modes", modes);
    json_object_object_add(o, "source_formats", formats);
    aegisxd_json_add_string(o, "dataplane", "dnsmasq_domain_block_or_query_monitor");
    json_object_object_add(o, "port_protocol_block_supported", json_object_new_boolean(0));
    json_object_object_add(o, "wildcard_regex_supported", json_object_new_boolean(0));
    json_object_object_add(o, "hit_count_supported", json_object_new_boolean(1));
    aegisxd_json_add_string(o, "hit_count_precision", "dnsmasq_block_or_monitor_matches_aggregated_30s");
    return o;
}

static struct json_object *pcdn_hit_summary_json(void)
{
    struct json_object *summary = json_object_new_object();
    struct json_object *domains = json_object_new_array();
    struct json_object *clients = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int64_t total = 0, blocked = 0, observed = 0, rows = 0;
    int64_t unique_domains = 0, unique_clients = 0;
    int64_t last_hit = 0;

    st = aegisxd_prepare(
        "SELECT COALESCE(SUM(occurrence_count),0),"
        "COALESCE(SUM(CASE WHEN event_type='pcdn_dns_block' THEN occurrence_count ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN event_type='pcdn_dns_observed' THEN occurrence_count ELSE 0 END),0),COUNT(*),"
        "COUNT(DISTINCT destination_host),"
        "COUNT(DISTINCT NULLIF(CASE WHEN source_mac<>'' THEN source_mac ELSE source_ip END,'')),"
        "COALESCE(MAX(last_seen),0) FROM aegis_events WHERE policy_id='pcdn' "
        "AND policy_type='dns_filter' AND source='aegisxd.pcdn'");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        total = sqlite3_column_int64(st, 0);
        blocked = sqlite3_column_int64(st, 1);
        observed = sqlite3_column_int64(st, 2);
        rows = sqlite3_column_int64(st, 3);
        unique_domains = sqlite3_column_int64(st, 4);
        unique_clients = sqlite3_column_int64(st, 5);
        last_hit = sqlite3_column_int64(st, 6);
    }
    if (st)
        sqlite3_finalize(st);
    st = aegisxd_prepare(
        "SELECT destination_host,SUM(occurrence_count),MAX(last_seen),"
        "SUM(CASE WHEN event_type='pcdn_dns_block' THEN occurrence_count ELSE 0 END),"
        "SUM(CASE WHEN event_type='pcdn_dns_observed' THEN occurrence_count ELSE 0 END) FROM aegis_events "
        "WHERE policy_id='pcdn' AND policy_type='dns_filter' AND source='aegisxd.pcdn' "
        "GROUP BY destination_host ORDER BY SUM(occurrence_count) DESC,MAX(last_seen) DESC LIMIT 20");
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();

        aegisxd_json_add_string(item, "domain", aegisxd_sqlite_text(st, 0, ""));
        json_object_object_add(item, "hit_count", json_object_new_int64(sqlite3_column_int64(st, 1)));
        json_object_object_add(item, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(item, "blocked_count", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(item, "observed_count", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_array_add(domains, item);
    }
    if (st)
        sqlite3_finalize(st);
    st = aegisxd_prepare(
        "SELECT source_ip,MAX(source_mac),SUM(occurrence_count),MAX(last_seen),"
        "SUM(CASE WHEN event_type='pcdn_dns_block' THEN occurrence_count ELSE 0 END),"
        "SUM(CASE WHEN event_type='pcdn_dns_observed' THEN occurrence_count ELSE 0 END) FROM aegis_events "
        "WHERE policy_id='pcdn' AND policy_type='dns_filter' AND source='aegisxd.pcdn' "
        "GROUP BY source_ip ORDER BY SUM(occurrence_count) DESC,MAX(last_seen) DESC LIMIT 20");
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();

        aegisxd_json_add_string(item, "source_ip", aegisxd_sqlite_text(st, 0, ""));
        aegisxd_json_add_string(item, "source_mac", aegisxd_sqlite_text(st, 1, ""));
        json_object_object_add(item, "hit_count", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(item, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(item, "blocked_count", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(item, "observed_count", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_array_add(clients, item);
    }
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(summary, "available", json_object_new_boolean(total > 0));
    json_object_object_add(summary, "attribution_ready",
                           json_object_new_boolean(aegisxd_pcdn_hit_attribution_ready()));
    json_object_object_add(summary, "hit_count", json_object_new_int64(total));
    json_object_object_add(summary, "blocked_count", json_object_new_int64(blocked));
    json_object_object_add(summary, "observed_count", json_object_new_int64(observed));
    json_object_object_add(summary, "event_rows", json_object_new_int64(rows));
    json_object_object_add(summary, "unique_domains", json_object_new_int64(unique_domains));
    json_object_object_add(summary, "unique_clients", json_object_new_int64(unique_clients));
    json_object_object_add(summary, "last_hit_at",
                           last_hit > 0 ? json_object_new_int64(last_hit) : json_object_new_null());
    json_object_object_add(summary, "top_domains", domains);
    json_object_object_add(summary, "top_clients", clients);
    return summary;
}

static struct json_object *pcdn_source_json(void)
{
    struct json_object *o = json_object_new_object();

    aegisxd_json_add_string(o, "id", PCDN_SOURCE_ID);
    aegisxd_json_add_string(o, "name", PCDN_SOURCE_NAME);
    aegisxd_json_add_string(o, "url", PCDN_SOURCE_URL);
    aegisxd_json_add_string(o, "license", PCDN_SOURCE_LICENSE);
    aegisxd_json_add_string(o, "repository", "743859910/OpenHosts");
    aegisxd_json_add_string(o, "format", "adblock_domain_list");
    json_object_object_add(o, "enabled", json_object_new_boolean(1));
    json_object_object_add(o, "max_bytes", json_object_new_int64(PCDN_MAX_BYTES));
    json_object_object_add(o, "max_rules", json_object_new_int64(PCDN_MAX_RULES));
    return o;
}

struct json_object *aegisxd_pcdn_get_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *settings = json_object_new_object();
    struct json_object *sources = json_object_new_array();
    struct json_object *installed = pcdn_installed_state_json();
    struct pcdn_settings current;
    sqlite3_stmt *st;
    int ok = pcdn_settings_load(&current) == 0;

    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "operation", "content_pcdn_get");
    if (ok) {
        json_object_object_add(settings, "enabled", json_object_new_boolean(current.enabled));
        aegisxd_json_add_string(settings, "mode", current.mode);
        aegisxd_json_add_string(settings, "source_id", current.source_id);
        json_object_object_add(settings, "revision", json_object_new_int(current.revision));
        aegisxd_json_add_string(settings, "apply_state", current.apply_state);
        aegisxd_json_add_string(settings, "artifact_path", current.artifact_path);
        aegisxd_json_add_string(settings, "artifact_sha256", current.artifact_sha256);
        json_object_object_add(settings, "rule_count", json_object_new_int(current.rule_count));
        json_object_object_add(settings, "effective_rule_count", json_object_new_int(
            json_object_get_int(json_object_object_get(installed, "effective_rule_count"))));
        json_object_object_add(settings, "rules_ready", json_object_new_boolean(pcdn_artifact_verified(&current)));
        json_object_object_add(settings, "effective_blocking", json_object_new_boolean(
            aegisxd_json_bool(installed, "blocking", 0)));
        json_object_object_add(settings, "effective_monitoring", json_object_new_boolean(
            aegisxd_json_bool(installed, "monitoring", 0)));
    }
    st = aegisxd_config_prepare(
        "SELECT sync_state,sync_error,rejected_count,last_sync_at,last_error,created_at,updated_at "
        "FROM aegis_pcdn_settings WHERE id=1");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        aegisxd_json_add_string(settings, "sync_state", aegisxd_sqlite_text(st, 0, "never"));
        aegisxd_json_add_string(settings, "sync_error", aegisxd_sqlite_text(st, 1, ""));
        json_object_object_add(settings, "rejected_count", json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_object_add(settings, "last_sync_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        aegisxd_json_add_string(settings, "last_error", aegisxd_sqlite_text(st, 4, ""));
        json_object_object_add(settings, "created_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(settings, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
    }
    if (st)
        sqlite3_finalize(st);
    json_object_object_add(resp, "settings", settings);
    json_object_object_add(resp, "installed", installed);
    json_object_array_add(sources, pcdn_source_json());
    json_object_object_add(resp, "sources", sources);
    json_object_object_add(resp, "capabilities", pcdn_capabilities());
    json_object_object_add(resp, "hit_summary", pcdn_hit_summary_json());
    json_object_object_add(resp, "jobs", aegisxd_feed_jobs_json(NULL));
    return resp;
}

struct json_object *aegisxd_pcdn_validate_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *blockers = json_object_new_array();
    struct json_object *v = NULL;
    const char *mode = aegisxd_json_str(body, "mode", "block");
    const char *source = aegisxd_json_str(body, "source_id", PCDN_SOURCE_ID);
    int valid = 1;

    if (body && json_object_object_get_ex(body, "enabled", &v) &&
        !json_object_is_type(v, json_type_boolean)) {
        json_object_array_add(blockers, json_object_new_string("invalid_pcdn_enabled"));
        valid = 0;
    }
    if (strcmp(mode, "block") && strcmp(mode, "monitor")) {
        json_object_array_add(blockers, json_object_new_string("invalid_pcdn_mode"));
        valid = 0;
    }
    if (strcmp(source, PCDN_SOURCE_ID)) {
        json_object_array_add(blockers, json_object_new_string("pcdn_source_not_allowed"));
        valid = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(valid));
    json_object_object_add(resp, "valid", json_object_new_boolean(valid));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "enabled", json_object_new_boolean(aegisxd_json_bool(body, "enabled", 0)));
    aegisxd_json_add_string(resp, "mode", mode);
    aegisxd_json_add_string(resp, "source_id", source);
    json_object_object_add(resp, "blockers", blockers);
    json_object_object_add(resp, "capabilities", pcdn_capabilities());
    return resp;
}

static int pcdn_content_meta_mark(const char *state, const char *error)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "UPDATE aegis_content_meta SET managed=(CASE WHEN "
        "(SELECT COUNT(*) FROM aegis_content_policies)+"
        "(SELECT COUNT(*) FROM aegis_domain_overrides)+"
        "(SELECT COUNT(*) FROM aegis_pcdn_settings WHERE enabled=1)>0 THEN 1 ELSE 0 END),"
        "revision=revision+1,last_apply_state=?1,last_error=?2,updated_at=?3 WHERE id=1");
    int rc;

    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int pcdn_apply(struct json_object **result)
{
    struct json_object *req = json_object_new_object();
    struct json_object *blockers = NULL;
    int empty = 0;

    json_object_object_add(req, "confirm", json_object_new_boolean(1));
    aegisxd_json_add_string(req, "operation", "apply");
    aegisxd_json_add_string(req, "scope", "dns_filter");
    aegisxd_json_add_string(req, "requested_by", "content_pcdn");
    json_object_object_add(req, "force", json_object_new_boolean(1));
    *result = aegisxd_apply(req);
    if (!aegisxd_json_bool(*result, "ok", 0) &&
        json_object_object_get_ex(*result, "blockers", &blockers) &&
        json_object_is_type(blockers, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(blockers); i++) {
            struct json_object *v = json_object_array_get_idx(blockers, i);

            if (v && json_object_is_type(v, json_type_string) &&
                !strcmp(json_object_get_string(v), "dnsmasq_rules_empty")) {
                empty = 1;
                break;
            }
        }
    }
    if (empty) {
        json_object_put(*result);
        json_object_object_del(req, "force");
        json_object_object_del(req, "requested_by");
        json_object_object_del(req, "operation");
        aegisxd_json_add_string(req, "operation", "disable");
        *result = aegisxd_apply(req);
    }
    json_object_put(req);
    return aegisxd_json_bool(*result, "ok", 0) ? 0 : -1;
}

struct json_object *aegisxd_pcdn_set_json(struct json_object *body)
{
    struct json_object *validation = aegisxd_pcdn_validate_json(body);
    struct json_object *apply = NULL, *resp;
    struct pcdn_settings previous;
    int enabled = aegisxd_json_bool(body, "enabled", 0);
    const char *mode = aegisxd_json_str(body, "mode", "block");
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int do_apply = aegisxd_json_bool(body, "apply", 0);
    int expected_revision = -1;
    int revision_state;
    sqlite3_stmt *st;
    int rc;

    if (!aegisxd_json_bool(validation, "ok", 0) || !confirm)
        return validation;
    json_object_put(validation);
    revision_state = pcdn_revision_get(body, &expected_revision);
    if (revision_state == 0)
        return aegisxd_error("pcdn_revision_required", "revision is required for confirmed PCDN writes");
    if (revision_state < 0)
        return aegisxd_error("invalid_pcdn_revision", "revision must be a non-negative integer");
    if (pcdn_settings_load(&previous) != 0)
        return aegisxd_error("pcdn_storage_unavailable", "PCDN settings are unavailable");
    if (expected_revision != previous.revision)
        return aegisxd_error("pcdn_revision_conflict", "PCDN settings changed; reload before saving");
    if (enabled && do_apply && !pcdn_artifact_verified(&previous))
        return aegisxd_error("pcdn_rules_not_ready", "sync and validate a PCDN feed before applying the selected mode");
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return aegisxd_error("storage_error", "PCDN settings transaction could not start");
    st = aegisxd_config_prepare(
        "UPDATE aegis_pcdn_settings SET enabled=?1,mode=?2,source_id=?3,revision=revision+1,"
        "apply_state=?4,last_error='',updated_at=?5 WHERE id=1");
    if (!st)
        goto rollback;
    sqlite3_bind_int(st, 1, enabled);
    sqlite3_bind_text(st, 2, mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, PCDN_SOURCE_ID, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, do_apply ? "applying" : "pending", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || pcdn_content_meta_mark(do_apply ? "applying" : "pending", "") != 0)
        goto rollback;
    if (do_apply && pcdn_apply(&apply) != 0)
        goto rollback_apply;
    if (do_apply) {
        st = aegisxd_config_prepare(
            "UPDATE aegis_pcdn_settings SET apply_state=?1,last_error='',updated_at=?2 WHERE id=1");
        if (!st)
            goto rollback_apply;
        sqlite3_bind_text(st, 1, enabled ? "active" : "disabled", -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, aegisxd_now_s());
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE)
            goto rollback_apply;
    }
    if (sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback_apply;
    resp = aegisxd_pcdn_get_json();
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(
        apply && aegisxd_json_bool(apply, "dataplane_changed", 0)));
    if (apply)
        json_object_object_add(resp, "apply", apply);
    return resp;

rollback_apply:
    if (apply)
        json_object_put(apply);
rollback:
    sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    if (do_apply) {
        struct json_object *restore = NULL;
        (void)pcdn_apply(&restore);
        if (restore)
            json_object_put(restore);
    }
    resp = aegisxd_error("pcdn_apply_failed",
                         "PCDN settings were not committed; the previous configuration remains authoritative");
    json_object_object_add(resp, "rollback_ok", json_object_new_boolean(1));
    return resp;
}

static int pcdn_rule_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int pcdn_rules_add(struct pcdn_rules *rules, const char *domain)
{
    void *next;

    if (rules->count >= PCDN_MAX_RULES)
        return -1;
    if (rules->count == rules->capacity) {
        size_t cap = rules->capacity ? rules->capacity * 2 : 256;

        if (cap > PCDN_MAX_RULES)
            cap = PCDN_MAX_RULES;
        next = realloc(rules->items, cap * sizeof(*rules->items));
        if (!next)
            return -1;
        rules->items = next;
        rules->capacity = cap;
    }
    snprintf(rules->items[rules->count++], AEGISXD_PCDN_DOMAIN_BUFSZ, "%s", domain);
    return 0;
}

static void pcdn_reject_record(struct pcdn_rules *rules, const char *line,
                               const char *reason)
{
    size_t i, o = 0;

    if (rules->sample_count >= PCDN_REJECT_SAMPLES)
        return;
    i = rules->sample_count++;
    /* Remote text is untrusted and lands in logs and JSON, so keep only
     * printable ASCII and cap the length. */
    for (const char *p = line ? line : ""; *p && o < PCDN_REJECT_SAMPLE_BUFSZ - 1; p++)
        rules->samples[i][o++] = (*p >= 0x20 && *p < 0x7f) ? *p : '.';
    rules->samples[i][o] = '\0';
    rules->sample_reasons[i] = reason ? reason : "unspecified";
}

/* rejected_count alone cannot say whether the source changed format or the
 * parser is too strict, so publish a bounded sample of what was dropped. */
static struct json_object *pcdn_rejected_samples_json(const struct pcdn_rules *rules)
{
    struct json_object *arr = json_object_new_array();

    for (size_t i = 0; i < rules->sample_count; i++) {
        struct json_object *o = json_object_new_object();

        aegisxd_json_add_string(o, "line", rules->samples[i]);
        aegisxd_json_add_string(o, "reason", rules->sample_reasons[i]);
        json_object_array_add(arr, o);
    }
    return arr;
}

static int pcdn_rules_load(const char *path, struct pcdn_rules *rules)
{
    FILE *fp = fopen(path, "r");
    char line[2048], domain[AEGISXD_PCDN_DOMAIN_BUFSZ];

    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        int parsed;
        const char *reason = "unspecified";

        if (!strchr(line, '\n') && !feof(fp)) {
            int c;
            while ((c = fgetc(fp)) != '\n' && c != EOF) {}
            pcdn_reject_record(rules, line, "line_too_long");
            if (++rules->rejected > PCDN_MAX_REJECTED)
                goto fail;
            continue;
        }
        parsed = aegisxd_pcdn_parse_line_ex(line, domain, sizeof(domain), &reason);
        if (parsed == 0)
            continue;
        if (parsed < 0) {
            pcdn_reject_record(rules, line, reason);
            if (++rules->rejected > PCDN_MAX_REJECTED)
                goto fail;
            continue;
        }
        if (pcdn_rules_add(rules, domain) != 0)
            goto fail;
    }
    if (ferror(fp) || !rules->count)
        goto fail;
    fclose(fp);
    qsort(rules->items, rules->count, sizeof(*rules->items), pcdn_rule_cmp);
    {
        size_t dst = 0;
        for (size_t i = 0; i < rules->count; i++)
            if (!dst || strcmp(rules->items[i], rules->items[dst - 1]))
                memcpy(rules->items[dst++], rules->items[i], sizeof(*rules->items));
        rules->count = dst;
    }
    return rules->count ? 0 : -1;
fail:
    fclose(fp);
    return -1;
}

static int pcdn_rules_write(const char *path, const struct pcdn_rules *rules)
{
    FILE *fp = fopen(path, "wb");
    int ok = 1;

    if (!fp)
        return -1;
    for (size_t i = 0; i < rules->count; i++)
        if (fprintf(fp, "%s\n", rules->items[i]) < 0)
            goto fail;
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        ok = 0;
    if (fclose(fp) != 0)
        ok = 0;
    return ok ? 0 : -1;
fail:
    fclose(fp);
    return -1;
}

static void pcdn_match_cache_reset(void)
{
    free(g_pcdn_match_cache.rules.items);
    memset(&g_pcdn_match_cache, 0, sizeof(g_pcdn_match_cache));
    g_pcdn_match_cache.content_revision = -1;
}

static int pcdn_installed_settings_load(struct pcdn_settings *settings,
                                        int *content_revision)
{
    struct json_object *root = NULL, *pcdn = NULL, *revision = NULL;
    const char *dns_file, *sha256;
    struct stat dns_stat;
    int ok = 0;

    if (!settings || !content_revision)
        return -1;
    memset(settings, 0, sizeof(*settings));
    *content_revision = -1;
    root = json_object_from_file(AEGISXD_RUNTIME_DIR "/active.json");
    if (!root || !json_object_is_type(root, json_type_object) ||
        (strcmp(aegisxd_json_str(root, "scope", ""), "dns_filter") &&
         strcmp(aegisxd_json_str(root, "scope", ""), "all")) ||
        !json_object_object_get_ex(root, "content_revision", &revision) ||
        !revision || !json_object_is_type(revision, json_type_int) ||
        !json_object_object_get_ex(root, "pcdn", &pcdn) || !pcdn ||
        !json_object_is_type(pcdn, json_type_object) ||
        !aegisxd_json_bool(pcdn, "enabled", 0))
        goto out;
    *content_revision = json_object_get_int(revision);
    dns_file = aegisxd_json_str(root, "dnsmasq_conf_file", "");
    if (!dns_file[0] || lstat(dns_file, &dns_stat) != 0 ||
        !S_ISREG(dns_stat.st_mode) || access(dns_file, R_OK) != 0)
        goto out;
    sha256 = aegisxd_json_str(pcdn, "artifact_sha256", "");
    if (strlen(sha256) != 64)
        goto out;
    for (size_t i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)sha256[i]))
            goto out;
    settings->enabled = 1;
    snprintf(settings->mode, sizeof(settings->mode), "%s",
             aegisxd_json_str(pcdn, "mode", "block"));
    if (strcmp(settings->mode, "block") && strcmp(settings->mode, "monitor"))
        goto out;
    snprintf(settings->source_id, sizeof(settings->source_id), "%s", PCDN_SOURCE_ID);
    snprintf(settings->artifact_sha256, sizeof(settings->artifact_sha256), "%s", sha256);
    settings->rule_count = json_object_get_int(
        json_object_object_get(pcdn, "rule_count"));
    if (snprintf(settings->artifact_path, sizeof(settings->artifact_path),
                 PCDN_ARTIFACT_PREFIX "%s" PCDN_ARTIFACT_SUFFIX, sha256) >=
        (int)sizeof(settings->artifact_path))
        goto out;
    ok = pcdn_artifact_ready(settings);
out:
    if (root)
        json_object_put(root);
    return ok ? 0 : -1;
}

static int pcdn_match_cache_load(char artifact_sha256[65])
{
    struct pcdn_settings installed;
    struct pcdn_rules loaded = { 0 };
    struct stat st;
    int revision = -1;
    int64_t now = aegisxd_now_s();

    if (pcdn_installed_settings_load(&installed, &revision) != 0 ||
        lstat(installed.artifact_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        pcdn_match_cache_reset();
        return -1;
    }
    if (g_pcdn_match_cache.rules.items &&
        !strcmp(g_pcdn_match_cache.artifact_sha256, installed.artifact_sha256) &&
        !strcmp(g_pcdn_match_cache.artifact_path, installed.artifact_path) &&
        g_pcdn_match_cache.content_revision == revision &&
        g_pcdn_match_cache.size == st.st_size &&
        g_pcdn_match_cache.mtime == st.st_mtime &&
        now - g_pcdn_match_cache.verified_at < 30) {
        if (artifact_sha256)
            snprintf(artifact_sha256, 65, "%s", g_pcdn_match_cache.artifact_sha256);
        return 0;
    }
    if (!pcdn_artifact_verified(&installed) ||
        pcdn_rules_load(installed.artifact_path, &loaded) != 0 ||
        loaded.count != (size_t)installed.rule_count) {
        free(loaded.items);
        pcdn_match_cache_reset();
        return -1;
    }
    pcdn_match_cache_reset();
    g_pcdn_match_cache.rules = loaded;
    snprintf(g_pcdn_match_cache.artifact_path,
             sizeof(g_pcdn_match_cache.artifact_path), "%s", installed.artifact_path);
    snprintf(g_pcdn_match_cache.artifact_sha256,
             sizeof(g_pcdn_match_cache.artifact_sha256), "%s", installed.artifact_sha256);
    g_pcdn_match_cache.content_revision = revision;
    g_pcdn_match_cache.size = st.st_size;
    g_pcdn_match_cache.mtime = st.st_mtime;
    g_pcdn_match_cache.verified_at = now;
    if (artifact_sha256)
        snprintf(artifact_sha256, 65, "%s", installed.artifact_sha256);
    return 0;
}

int aegisxd_pcdn_hit_attribution_ready(void)
{
    struct pcdn_settings installed;
    int revision = -1;

    if (pcdn_installed_settings_load(&installed, &revision) != 0 ||
        pcdn_match_cache_load(NULL) != 0)
        return 0;
    return aegisxd_content_dns_provenance_ready();
}

int aegisxd_pcdn_installed_domain_match(const char *domain,
                                        char artifact_sha256[65])
{
    char kind[32] = "", source_id[64] = "", matched_rule[254] = "";
    struct pcdn_settings installed;
    int revision = -1;

    if (artifact_sha256)
        artifact_sha256[0] = '\0';
    if (pcdn_installed_settings_load(&installed, &revision) != 0 ||
        strcmp(installed.mode, "block") ||
        !aegisxd_content_installed_dns_rule_match(domain, kind, source_id,
                                                  matched_rule) ||
        strcmp(kind, "pcdn") || strcmp(source_id, PCDN_SOURCE_ID) ||
        pcdn_match_cache_load(artifact_sha256) != 0)
        return 0;
    return bsearch(matched_rule, g_pcdn_match_cache.rules.items,
                   g_pcdn_match_cache.rules.count,
                   sizeof(*g_pcdn_match_cache.rules.items), pcdn_rule_cmp) != NULL;
}

int aegisxd_pcdn_installed_monitor_match(const char *domain,
                                         char matched_rule[254],
                                         char artifact_sha256[65])
{
    struct pcdn_settings installed;
    char kind[32] = "", source_id[64] = "", effective_rule[254] = "";
    int revision = -1;

    if (matched_rule)
        matched_rule[0] = '\0';
    if (artifact_sha256)
        artifact_sha256[0] = '\0';
    if (!domain || pcdn_installed_settings_load(&installed, &revision) != 0 ||
        strcmp(installed.mode, "monitor") ||
        !aegisxd_content_installed_dns_rule_match(domain, kind, source_id,
                                                   effective_rule) ||
        strcmp(kind, "pcdn_monitor") || strcmp(source_id, PCDN_SOURCE_ID) ||
        pcdn_match_cache_load(artifact_sha256) != 0)
        return 0;
    if (bsearch(effective_rule, g_pcdn_match_cache.rules.items,
                g_pcdn_match_cache.rules.count,
                sizeof(*g_pcdn_match_cache.rules.items), pcdn_rule_cmp)) {
        if (matched_rule)
            snprintf(matched_rule, 254, "%s", effective_rule);
        return 1;
    }
    if (artifact_sha256)
        artifact_sha256[0] = '\0';
    return 0;
}

int aegisxd_pcdn_monitor_configured(void)
{
    struct pcdn_settings settings;

    return pcdn_settings_load(&settings) == 0 && settings.enabled &&
        !strcmp(settings.mode, "monitor") && pcdn_artifact_verified(&settings);
}

int aegisxd_pcdn_configured(void)
{
    struct pcdn_settings settings;

    return pcdn_settings_load(&settings) == 0 && settings.enabled &&
        (!strcmp(settings.mode, "block") || !strcmp(settings.mode, "monitor")) &&
        pcdn_artifact_verified(&settings);
}

int aegisxd_pcdn_effective_rule_count(const char *path)
{
    FILE *fp;
    char line[1024];
    int count = 0;

    if (!path || !path[0] || !(fp = fopen(path, "r")))
        return 0;
    while (fgets(line, sizeof(line), fp))
        if (!strncmp(line, "# aegis provenance=pcdn source=",
                     sizeof("# aegis provenance=pcdn source=") - 1) ||
            !strncmp(line, "# aegis monitor=pcdn source=",
                     sizeof("# aegis monitor=pcdn source=") - 1))
            count++;
    fclose(fp);
    return count;
}

static int pcdn_artifact_install(const char *canonical, const char *sha256,
                                 char final[AEGISXD_MAX_PATH],
                                 int *installed_new, int *repaired)
{
    char existing_sha256[65] = "";
    struct stat st;

    if (!canonical || !canonical[0] || !sha256 || strlen(sha256) != 64 ||
        !final || !installed_new || !repaired)
        return -1;
    *installed_new = 0;
    *repaired = 0;
    if (snprintf(final, AEGISXD_MAX_PATH, PCDN_ARTIFACT_PREFIX "%s"
                 PCDN_ARTIFACT_SUFFIX, sha256) >= AEGISXD_MAX_PATH)
        return -1;
    if (lstat(final, &st) != 0) {
        if (errno != ENOENT || rename(canonical, final) != 0)
            return -1;
        *installed_new = 1;
        return 0;
    }
    if (S_ISREG(st.st_mode) && pcdn_sha256_file(final, existing_sha256) == 0 &&
        !strcasecmp(existing_sha256, sha256))
        return unlink(canonical) == 0 ? 0 : -1;
    *repaired = 1;
    if (rename(canonical, final) != 0)
        return -1;
    return 0;
}

static void pcdn_sync_error(const char *error)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "UPDATE aegis_pcdn_settings SET sync_state='failed',sync_error=?1,updated_at=?2 WHERE id=1");

    if (!st)
        return;
    sqlite3_bind_text(st, 1, error ? error : "pcdn_sync_failed", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, aegisxd_now_s());
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* A bare "pcdn_download_failed" cannot distinguish a transient network blip
 * from a source that is gone, and those need opposite responses.  Keep the
 * stable prefix for existing consumers and append the libcurl symbol plus the
 * HTTP status when one was received. */
static void pcdn_download_error_detail(CURLcode cc, long http_status,
                                      char *out, size_t out_len)
{
    const char *name = curl_easy_strerror(cc);
    int n;

    n = snprintf(out, out_len, "pcdn_download_failed:CURLE_%d", (int)cc);
    if (n < 0 || (size_t)n >= out_len)
        return;
    if (http_status > 0)
        n += snprintf(out + n, out_len - (size_t)n, ":http_%ld", http_status);
    if (n < 0 || (size_t)n >= out_len || !name || !name[0])
        return;
    snprintf(out + n, out_len - (size_t)n, ":%s", name);
}

static struct json_object *pcdn_sync_run(void)
{
    struct json_object *resp;
    struct pcdn_download download = { 0 };
    struct pcdn_rules rules = { 0 };
    struct pcdn_settings previous;
    CURL *curl = NULL;
    CURLcode cc = CURLE_FAILED_INIT;
    char raw[AEGISXD_MAX_PATH] = "", canonical[AEGISXD_MAX_PATH] = "";
    char final[AEGISXD_MAX_PATH] = "", sha256[65] = "";
    char download_error[192] = "";
    long http_status = 0;
    sqlite3_stmt *st = NULL;
    const char *error = "pcdn_sync_failed";
    int installed = 0, repaired = 0;

    if (pcdn_settings_load(&previous) != 0) {
        error = "pcdn_storage_unavailable";
        goto fail;
    }
    if (aegisxd_mkdir_p(AEGISXD_FEED_DIR, 0755) != 0) {
        error = "pcdn_workdir_failed";
        goto fail;
    }
    snprintf(raw, sizeof(raw), AEGISXD_FEED_DIR "/.pcdn-raw.%ld", (long)getpid());
    snprintf(canonical, sizeof(canonical), AEGISXD_FEED_DIR "/.pcdn-domains.%ld", (long)getpid());
    download.fp = fopen(raw, "wb");
    curl = curl_easy_init();
    if (!download.fp || !curl) {
        error = "pcdn_download_init_failed";
        goto fail;
    }
    curl_easy_setopt(curl, CURLOPT_URL, PCDN_SOURCE_URL);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 90L);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)PCDN_MAX_BYTES);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-aegisxd-pcdn/1");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pcdn_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &download);
    cc = curl_easy_perform(curl);
    /* Read the status before the handle is released; on CURLE_HTTP_RETURNED_ERROR
     * this is what separates 403/429 rate limiting from a 404 dead source. */
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) != CURLE_OK)
        http_status = 0;
    if (fflush(download.fp) != 0 || fsync(fileno(download.fp)) != 0) {
        error = "pcdn_download_write_failed";
        goto fail;
    }
    if (fclose(download.fp) != 0) {
        download.fp = NULL;
        error = "pcdn_download_write_failed";
        goto fail;
    }
    download.fp = NULL;
    curl_easy_cleanup(curl);
    curl = NULL;
    if (cc != CURLE_OK) {
        if (download.too_large) {
            error = "pcdn_source_too_large";
        } else {
            pcdn_download_error_detail(cc, http_status, download_error,
                                       sizeof(download_error));
            error = download_error;
        }
        goto fail;
    }
    if (pcdn_rules_load(raw, &rules) != 0) {
        error = "pcdn_rules_invalid_or_empty";
        goto fail;
    }
    if (rules.rejected)
        for (size_t i = 0; i < rules.sample_count; i++)
            fprintf(stderr, "[dreamingwrt-aegisxd] pcdn rejected rule %zu/%zu reason=%s line=%s\n",
                    i + 1, rules.rejected, rules.sample_reasons[i], rules.samples[i]);
    if (pcdn_rules_write(canonical, &rules) != 0 || pcdn_sha256_file(canonical, sha256) != 0) {
        error = "pcdn_artifact_validation_failed";
        goto fail;
    }
    if (pcdn_artifact_install(canonical, sha256, final, &installed, &repaired) != 0) {
        error = repaired ? "pcdn_artifact_repair_failed" : "pcdn_artifact_install_failed";
        goto fail;
    }
    canonical[0] = '\0';
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        error = "pcdn_storage_busy";
        goto fail;
    }
    st = aegisxd_config_prepare(
        "UPDATE aegis_pcdn_settings SET sync_state='ready',sync_error='',artifact_path=?1,"
        "artifact_sha256=?2,rule_count=?3,rejected_count=?4,last_sync_at=?5,updated_at=?5,"
        "revision=revision+1,"
        "apply_state=CASE WHEN enabled=1 OR apply_state IN ('active','pending','applying') THEN 'pending' "
        "ELSE 'disabled' END WHERE id=1");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, final, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, sha256, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, (int)rules.count);
    sqlite3_bind_int(st, 4, (int)rules.rejected);
    sqlite3_bind_int64(st, 5, aegisxd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (previous.enabled && pcdn_content_meta_mark("pending", "") != 0)
        goto rollback;
    if (sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
        error = "pcdn_storage_commit_failed";
        goto fail;
    }
    unlink(raw);
    resp = aegisxd_pcdn_get_json();
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "apply_required", json_object_new_boolean(previous.enabled));
    json_object_object_add(resp, "downloaded_bytes", json_object_new_int64((int64_t)download.written));
    json_object_object_add(resp, "rejected_count", json_object_new_int((int)rules.rejected));
    json_object_object_add(resp, "rejected_samples", pcdn_rejected_samples_json(&rules));
    json_object_object_add(resp, "rejected_samples_truncated",
                           json_object_new_boolean(rules.rejected > rules.sample_count));
    json_object_object_add(resp, "artifact_cleanup",
                           pcdn_cleanup_artifacts(final, previous.artifact_path));
    free(rules.items);
    return resp;

rollback:
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    error = "pcdn_storage_update_failed";
fail:
    if (download.fp)
        fclose(download.fp);
    if (curl)
        curl_easy_cleanup(curl);
    if (raw[0])
        unlink(raw);
    if (canonical[0])
        unlink(canonical);
    if (installed && final[0])
        unlink(final);
    free(rules.items);
    pcdn_sync_error(error);
    resp = aegisxd_error(error,
                         "PCDN rules were not replaced; the previous verified artifact remains authoritative");
    json_object_object_add(resp, "rollback_ok", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    return resp;
}

struct json_object *aegisxd_pcdn_sync_json(struct json_object *body)
{
    char job_id[96];
    pid_t pid;
    struct json_object *resp;

    if (!aegisxd_json_bool(body, "confirm", 0)) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
        json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        json_object_object_add(resp, "source", pcdn_source_json());
        return resp;
    }
    if (aegisxd_job_running_count() > 0)
        return aegisxd_error("aegis_job_running", "another Aegis background job is already running");
    snprintf(job_id, sizeof(job_id), "pcdn-sync-%" PRId64 "-%ld", aegisxd_now_s(), (long)getpid());
    if (aegisxd_job_record_start(job_id, "pcdn_sync", PCDN_SOURCE_ID, 0) != 0)
        return aegisxd_error("pcdn_job_create_failed", "failed to persist PCDN sync job");
    pid = fork();
    if (pid < 0) {
        resp = aegisxd_error("fork_failed", "failed to start PCDN sync worker");
        aegisxd_job_record_finish(job_id, resp);
        return resp;
    }
    if (pid == 0) {
        execl("/usr/bin/dreamingwrt-aegisxd", "dreamingwrt-aegisxd",
              "--pcdn-sync-worker", job_id, (char *)NULL);
        _exit(127);
    }
    aegisxd_job_record_pid(job_id, pid);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "operation", "content_pcdn_sync");
    aegisxd_json_add_string(resp, "state", "running");
    json_object_object_add(resp, "running", json_object_new_boolean(1));
    json_object_object_add(resp, "background", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "job_id", job_id);
    json_object_object_add(resp, "pid", json_object_new_int((int)pid));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    return resp;
}

int aegisxd_pcdn_sync_worker_main(const char *job_id)
{
    struct json_object *result;
    int ok;

    if (!job_id || !job_id[0] || aegisxd_db_init() != 0)
        return 1;
    result = pcdn_sync_run();
    ok = aegisxd_json_bool(result, "ok", 0);
    aegisxd_job_record_finish(job_id, result);
    json_object_put(result);
    aegisxd_db_close();
    return ok ? 0 : 1;
}

int aegisxd_pcdn_write_dnsmasq(FILE *fp,
                               int (*allow_cb)(const char *domain, void *opaque),
                               void *opaque)
{
    struct pcdn_settings settings;
    FILE *rules;
    char line[512], domain[AEGISXD_PCDN_DOMAIN_BUFSZ], last[AEGISXD_PCDN_DOMAIN_BUFSZ] = "";
    size_t seen = 0;
    int written = 0;
    if (!fp || pcdn_settings_load(&settings) != 0)
        return -1;
    if (!settings.enabled)
        return 0;
    if ((strcmp(settings.mode, "block") && strcmp(settings.mode, "monitor")) ||
        !pcdn_artifact_verified(&settings))
        return -1;
    if (!strcmp(settings.mode, "monitor") &&
        fprintf(fp, "# aegis pcdn-mode=monitor source=%s artifact=%s rules=%d\n",
                PCDN_SOURCE_ID, settings.artifact_sha256, settings.rule_count) < 0)
        return -1;
    rules = fopen(settings.artifact_path, "r");
    if (!rules)
        return -1;
    while (fgets(line, sizeof(line), rules)) {
        int parsed;

        if (++seen > PCDN_MAX_RULES || (!strchr(line, '\n') && !feof(rules)))
            goto fail;
        parsed = aegisxd_pcdn_parse_line(line, domain, sizeof(domain));
        if (parsed != 1 || (last[0] && strcmp(last, domain) >= 0))
            goto fail;
        snprintf(last, sizeof(last), "%s", domain);
        if (allow_cb && allow_cb(domain, opaque))
            continue;
        if (!strcmp(settings.mode, "monitor")) {
            if (fprintf(fp, "# aegis monitor=pcdn source=%s domain=%s\n",
                        PCDN_SOURCE_ID, domain) < 0)
                goto fail;
            written++;
            continue;
        }
        if (fprintf(fp, "# aegis provenance=pcdn source=%s domain=%s\n",
                    PCDN_SOURCE_ID, domain) < 0 ||
            fprintf(fp, "address=/%s/0.0.0.0\naddress=/%s/::\n", domain, domain) < 0)
            goto fail;
        written++;
    }
    if (ferror(rules) || seen != (size_t)settings.rule_count)
        goto fail;
    fclose(rules);
    return written;
fail:
    fclose(rules);
    return -1;
}
