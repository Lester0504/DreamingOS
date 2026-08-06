// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"
#include "jmx_identification_runtime.h"

#define WORKER_STATUS_VERSION "1.0"
#define AEGISXD_IDENTITY_RUNTIME_PATH "/run/dreamingwrt/identityd-state.json"
#define AEGISXD_RECORD_ENABLE_PATH "/proc/sys/dreamingwrt/jmx/record_enable"

static struct json_object *aegisxd_read_json_file(const char *path, size_t max_bytes)
{
    struct stat st;
    FILE *fp = NULL;
    char *buf = NULL;
    size_t n;
    struct json_object *value = NULL;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > max_bytes)
        return NULL;
    buf = calloc(1, (size_t)st.st_size + 1);
    if (!buf)
        return NULL;
    fp = fopen(path, "rb");
    if (!fp)
        goto out;
    n = fread(buf, 1, (size_t)st.st_size, fp);
    if (n != (size_t)st.st_size || ferror(fp))
        goto out;
    value = json_tokener_parse(buf);
    if (value && !json_object_is_type(value, json_type_object)) {
        json_object_put(value);
        value = NULL;
    }
out:
    if (fp)
        fclose(fp);
    free(buf);
    return value;
}

static struct json_object *aegisxd_identification_json(void)
{
    struct json_object *out = json_object_new_object();
    struct json_object *runtime = aegisxd_read_json_file(
        AEGISXD_IDENTITY_RUNTIME_PATH, 64U * 1024U);
    struct jmx_identification_runtime readback;
    sqlite3_stmt *st = NULL;
    char mode[32] = "unavailable";
    int record_enabled = 0;
    int config_available = 0;
    int applied = 0;

    st = aegisxd_config_prepare(
        "SELECT f.identify_mode,g.record_enabled FROM firewall_global f "
        "JOIN network_control_global g ON g.id=f.id WHERE f.id=1");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        snprintf(mode, sizeof(mode), "%s", aegisxd_sqlite_text(st, 0,
                 "device_and_traffic"));
        if (!strcmp(mode, "traffic"))
            snprintf(mode, sizeof(mode), "%s", "device_and_traffic");
        record_enabled = sqlite3_column_int(st, 1) ? 1 : 0;
        config_available = 1;
    }
    if (st)
        sqlite3_finalize(st);
    memset(&readback, 0, sizeof(readback));
    if (config_available &&
        jmx_identification_runtime_probe(mode, record_enabled, &readback) == 0)
        applied = readback.applied;
    json_object_object_add(out, "available", json_object_new_boolean(config_available));
    aegisxd_json_add_string(out, "mode", mode);
    json_object_object_add(out, "device_identification_enabled",
                           json_object_new_boolean(!strcmp(mode, "device_and_traffic")));
    json_object_object_add(out, "traffic_identification_enabled",
                           json_object_new_boolean(record_enabled));
    json_object_object_add(out, "kernel_readback_available",
                           json_object_new_boolean(readback.kernel_readback_available));
    if (readback.kernel_readback_available)
        json_object_object_add(out, "kernel_record_enabled",
                               json_object_new_boolean(readback.kernel_record_enabled));
    json_object_object_add(out, "identityd_readback_available",
                           json_object_new_boolean(readback.identityd_readback_available));
    json_object_object_add(out, "identityd_process_running",
                           json_object_new_boolean(readback.identityd_process_running));
    json_object_object_add(out, "identityd_state_fresh",
                           json_object_new_boolean(readback.identityd_state_fresh));
    json_object_object_add(out, "traffic_dataplane_active",
                           json_object_new_boolean(readback.traffic_dataplane_matches));
    json_object_object_add(out, "device_dataplane_active",
                           json_object_new_boolean(readback.device_dataplane_matches));
    json_object_object_add(out, "collector_ready",
                           json_object_new_boolean(readback.collector_ready));
    json_object_object_add(out, "listeners_ready",
                           json_object_new_int(readback.listeners_ready));
    json_object_object_add(out, "applied", json_object_new_boolean(applied));
    aegisxd_json_add_string(out, "apply_state",
                            applied ? "active" : config_available ?
                            "pending_readback" : "unavailable");
    aegisxd_json_add_string(out, "reason",
                            applied ? "" : config_available ? readback.reason :
                            "identification_config_unavailable");
    if (runtime)
        json_object_object_add(out, "identityd", runtime);
    return out;
}

static int aegisxd_feed_count(const char *kind)
{
    sqlite3_stmt *st;
    int n = 0;

    st = aegisxd_prepare("SELECT COALESCE(SUM(item_count),0) FROM aegis_feeds WHERE kind=? AND enabled=1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, kind ? kind : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int aegisxd_table_count(const char *table)
{
    sqlite3_stmt *st;
    char sql[128];
    int n = 0;

    if (!table || !table[0])
        return 0;
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    st = aegisxd_prepare(sql);
    if (!st)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int aegisxd_count_sql(const char *sql)
{
    sqlite3_stmt *st;
    int n = 0;

    st = aegisxd_prepare(sql);
    if (!st)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int aegisxd_status_contract_load(char *state, size_t state_len,
                                        char *last_error, size_t last_error_len,
                                        int *schema_version, int64_t *updated_at,
                                        int64_t *last_error_at,
                                        struct json_object *datasets)
{
    sqlite3_stmt *st;
    int rc;
    int ok = 1;

    st = aegisxd_prepare(
        "SELECT value,updated_at FROM aegis_state WHERE key='state'");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            snprintf(state, state_len, "%s", aegisxd_sqlite_text(st, 0, "idle"));
            *updated_at = sqlite3_column_int64(st, 1);
        } else if (rc != SQLITE_DONE) {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    st = aegisxd_prepare(
        "SELECT CAST(value AS INTEGER),updated_at FROM aegis_state WHERE key='schema_version'");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            *schema_version = sqlite3_column_int(st, 0);
            if (sqlite3_column_int64(st, 1) > *updated_at)
                *updated_at = sqlite3_column_int64(st, 1);
        } else {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    /* aegis_feeds and aegis_import_state are keyed per feed and cleared on
     * success, so a non-empty last_error there is genuinely current.
     * aegis_job_state is append-only history: every failed job keeps its error
     * row forever, so the old query surfaced a long-dead failure even after a
     * later sync of the same op succeeded.  Consider only the newest job per
     * op, which lets a success supersede the failure it replaced.
     * The GROUP BY uses SQLite's documented bare-column rule: with a single
     * MAX() aggregate, the non-aggregated columns come from the matching row.
     * That keeps this a single scan; aegis_job_state is never pruned, so a
     * correlated per-row subquery here would degrade as history grows. */
    st = aegisxd_prepare(
        "SELECT error,ts FROM ("
        "SELECT last_error AS error,updated_at AS ts FROM aegis_feeds WHERE last_error<>'' "
        "UNION ALL SELECT last_error,last_finished_at FROM aegis_import_state WHERE last_error<>'' "
        "UNION ALL SELECT error,ts FROM ("
        "SELECT last_error AS error,MAX(MAX(started_at,finished_at)) AS ts "
        "FROM aegis_job_state GROUP BY op) WHERE error<>'') "
        "ORDER BY ts DESC");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *err = aegisxd_sqlite_text(st, 0, "");
            int64_t ts = sqlite3_column_int64(st, 1);

            if (ts > *updated_at)
                *updated_at = ts;
            if (err[0] && !last_error[0]) {
                snprintf(last_error, last_error_len, "%s", err);
                if (last_error_at)
                    *last_error_at = ts;
            }
        }
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    st = aegisxd_prepare(
        "SELECT (SELECT COUNT(*) FROM aegis_feeds),"
        "(SELECT COUNT(*) FROM aegis_domain_categories),"
        "(SELECT COUNT(*) FROM aegis_reputation_items),"
        "(SELECT COUNT(*) FROM aegis_suricata_rules),"
        "(SELECT COUNT(*) FROM aegis_events)");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(datasets, "feeds", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(datasets, "domain_categories", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(datasets, "reputation_items", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(datasets, "suricata_rules", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(datasets, "events", json_object_new_int(sqlite3_column_int(st, 4)));
        } else {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    return ok;
}

static int aegisxd_nft_reputation_active(void)
{
    return access("/run/dreamingwrt/aegis/nft-active.json", F_OK) == 0;
}

static const char *aegisxd_suricata_binary_path(void)
{
    if (access("/usr/bin/suricata", X_OK) == 0)
        return "/usr/bin/suricata";
    if (access("/usr/sbin/suricata", X_OK) == 0)
        return "/usr/sbin/suricata";
    return "";
}

static int aegisxd_suricata_config_available(void)
{
    return access(AEGISXD_SURICATA_CONFIG_PATH, R_OK) == 0;
}

static int aegisxd_suricata_active(void)
{
    return access(AEGISXD_SURICATA_ACTIVE_PATH, F_OK) == 0;
}

static int aegisxd_suricata_pid_running(void)
{
    FILE *fp;
    long pid = 0;
    char path[64];
    char exe[AEGISXD_MAX_PATH];
    const char *base;
    ssize_t n;

    fp = fopen(AEGISXD_SURICATA_PID_PATH, "r");
    if (!fp)
        return 0;
    if (fscanf(fp, "%ld", &pid) != 1)
        pid = 0;
    fclose(fp);
    if (pid <= 1)
        return 0;
    if (kill((pid_t)pid, 0) != 0 && errno != EPERM)
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/exe", pid);
    n = readlink(path, exe, sizeof(exe) - 1);
    if (n <= 0 || (size_t)n >= sizeof(exe) - 1)
        return 0;
    exe[n] = '\0';
    base = strrchr(exe, '/');
    base = base ? base + 1 : exe;
    return !strcmp(base, "suricata");
}

static int aegisxd_suricata_eve_available(void)
{
    return access(AEGISXD_SURICATA_EVE_PATH, R_OK) == 0;
}

static int aegisxd_suricata_process_matches(const struct aegisxd_settings *settings)
{
    FILE *fp;
    long pid = 0;
    char path[64];
    char cmdline[AEGISXD_MAX_TEXT];
    size_t n;
    char expected[IFNAMSIZ + 32];

    if (!settings)
        return 0;
    fp = fopen(AEGISXD_SURICATA_PID_PATH, "r");
    if (!fp)
        return 0;
    if (fscanf(fp, "%ld", &pid) != 1)
        pid = 0;
    fclose(fp);
    if (pid <= 1)
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
    fp = fopen(path, "rb");
    if (!fp)
        return 0;
    n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);
    if (!n)
        return 0;
    cmdline[n] = '\0';
    for (size_t i = 0; i + 1 < n; i++) {
        if (cmdline[i] == '\0')
            cmdline[i] = ' ';
    }
    if (!strcmp(settings->mode, "monitor")) {
        snprintf(expected, sizeof(expected), "--af-packet=%s",
                 settings->suricata_interface);
        return strstr(cmdline, expected) != NULL;
    }
    if (!strcmp(settings->mode, "protect")) {
        snprintf(expected, sizeof(expected), "-q %d", settings->suricata_queue_num);
        return strstr(cmdline, expected) != NULL;
    }
    return 0;
}

static int aegisxd_ids_ips_settings_load(struct aegisxd_settings *settings)
{
    memset(settings, 0, sizeof(*settings));
    return aegisxd_settings_load(settings) == 0;
}

static int aegisxd_ids_ips_capture_configured(const struct aegisxd_settings *settings)
{
    if (!settings)
        return 0;
    if (!strcmp(settings->mode, "monitor"))
        return settings->suricata_interface[0] &&
               if_nametoindex(settings->suricata_interface) != 0;
    if (!strcmp(settings->mode, "protect"))
        return settings->suricata_queue_num >= 0 &&
               settings->suricata_queue_num <= 65535;
    return 0;
}

static int aegisxd_ids_ips_nfqueue_required(const struct aegisxd_settings *settings)
{
    return settings && !strcmp(settings->mode, "protect");
}

static int aegisxd_ids_ips_nfqueue_active_cached(void)
{
    static time_t checked_at;
    static int active;
    time_t now = time(NULL);

    if (!checked_at || now != checked_at) {
        active = aegisxd_suricata_nfqueue_runtime_active();
        checked_at = now;
    }
    return active;
}

static const char *aegisxd_ids_ips_runtime_reason(const char *suricata_bin)
{
    struct aegisxd_settings settings;

    if (!suricata_bin || !suricata_bin[0])
        return "suricata_runtime_missing";
    if (!aegisxd_ids_ips_settings_load(&settings))
        return "suricata_settings_unavailable";
    if (strcmp(settings.mode, "monitor") && strcmp(settings.mode, "protect"))
        return "suricata_capture_mode_not_configured";
    if (!aegisxd_ids_ips_capture_configured(&settings))
        return !strcmp(settings.mode, "monitor") && !settings.suricata_interface[0] ?
            "suricata_capture_interface_missing" :
            "suricata_capture_interface_unavailable";
    if (!aegisxd_suricata_config_available())
        return "suricata_config_missing";
    if (!aegisxd_suricata_active())
        return "suricata_ready_not_active";
    if (!aegisxd_suricata_pid_running())
        return "suricata_process_not_running";
    if (!aegisxd_suricata_process_matches(&settings))
        return "suricata_process_capture_mismatch";
    if (aegisxd_ids_ips_nfqueue_required(&settings) &&
        !aegisxd_ids_ips_nfqueue_active_cached())
        return "suricata_nfqueue_not_active";
    if (!aegisxd_suricata_eve_available())
        return "suricata_eve_missing";
    return "";
}

static int aegisxd_suricata_rules_total(void)
{
    return aegisxd_table_count("aegis_suricata_rules");
}

static int aegisxd_suricata_rules_enabled(void)
{
    return aegisxd_signature_policy_effective_enabled_count();
}

static int aegisxd_ids_ips_runtime_binary_available(const char *suricata_bin)
{
    return suricata_bin && suricata_bin[0];
}

static int aegisxd_ids_ips_production_active(const char *suricata_bin)
{
    struct aegisxd_settings settings;

    return aegisxd_ids_ips_runtime_binary_available(suricata_bin) &&
           aegisxd_ids_ips_settings_load(&settings) &&
           aegisxd_ids_ips_capture_configured(&settings) &&
           aegisxd_suricata_active() && aegisxd_suricata_pid_running() &&
           aegisxd_suricata_process_matches(&settings) &&
           (!aegisxd_ids_ips_nfqueue_required(&settings) ||
            aegisxd_ids_ips_nfqueue_active_cached()) &&
           aegisxd_suricata_eve_available();
}

static const char *aegisxd_ids_ips_runtime_state(const char *suricata_bin)
{
    struct aegisxd_settings settings;
    int rules_ready = aegisxd_suricata_rules_enabled() > 0;

    if (!rules_ready)
        return "rules_missing";
    if (!aegisxd_ids_ips_runtime_binary_available(suricata_bin))
        return "rules_ready_runtime_missing";
    if (!aegisxd_ids_ips_settings_load(&settings) ||
        (strcmp(settings.mode, "monitor") && strcmp(settings.mode, "protect")))
        return "rules_ready_capture_mode_missing";
    if (!aegisxd_ids_ips_capture_configured(&settings))
        return "rules_ready_capture_source_missing";
    if (!aegisxd_suricata_config_available())
        return "rules_ready_config_missing";
    if (!aegisxd_suricata_active())
        return "rules_ready_not_active";
    if (!aegisxd_suricata_pid_running())
        return "active_state_without_process";
    if (!aegisxd_suricata_process_matches(&settings))
        return "active_state_capture_mismatch";
    if (aegisxd_ids_ips_nfqueue_required(&settings) &&
        !aegisxd_ids_ips_nfqueue_active_cached())
        return "active_state_without_nfqueue";
    if (!aegisxd_suricata_eve_available())
        return "active_waiting_for_eve";
    return "active";
}

static const char *aegisxd_ids_ips_next_action(const char *suricata_bin)
{
    struct aegisxd_settings settings;

    if (aegisxd_suricata_rules_enabled() <= 0)
        return "import_suricata_rules";
    if (!aegisxd_ids_ips_runtime_binary_available(suricata_bin))
        return "install_suricata_runtime";
    if (!aegisxd_ids_ips_settings_load(&settings) ||
        !aegisxd_ids_ips_capture_configured(&settings))
        return "configure_suricata_capture";
    if (!aegisxd_suricata_config_available() || !aegisxd_suricata_active())
        return "apply_suricata_with_confirm";
    if (!aegisxd_suricata_pid_running())
        return "restart_suricata_with_confirm";
    if (!aegisxd_suricata_eve_available())
        return "wait_for_or_check_eve_log";
    return "";
}

static void aegisxd_add_ids_ips_runtime_fields(struct json_object *o,
                                               const char *suricata_bin)
{
    int rules_total = aegisxd_suricata_rules_total();
    int rules_enabled = aegisxd_suricata_rules_enabled();
    int runtime_available = aegisxd_ids_ips_runtime_binary_available(suricata_bin);
    int production_active = aegisxd_ids_ips_production_active(suricata_bin);
    int manual_ingest_active = aegisxd_suricata_hit_producer_active();
    struct aegisxd_settings settings;
    int settings_ok = aegisxd_ids_ips_settings_load(&settings);

    if (!o)
        return;
    json_object_object_add(o, "ids_ips_rules_imported", json_object_new_int(rules_total));
    json_object_object_add(o, "ids_ips_rules_enabled", json_object_new_int(rules_enabled));
    json_object_object_add(o, "ids_ips_signature_policy_counts", aegisxd_signature_policy_counts_json());
    json_object_object_add(o, "ids_ips_rules_ready", json_object_new_boolean(rules_enabled > 0));
    json_object_object_add(o, "ids_ips_runtime_binary_available", json_object_new_boolean(runtime_available));
    aegisxd_json_add_string(o, "ids_ips_runtime_binary", runtime_available ? suricata_bin : "");
    json_object_object_add(o, "ids_ips_runtime_available", json_object_new_boolean(runtime_available));
    aegisxd_json_add_string(o, "ids_ips_runtime_reason", aegisxd_ids_ips_runtime_reason(suricata_bin));
    aegisxd_json_add_string(o, "ids_ips_runtime_state", aegisxd_ids_ips_runtime_state(suricata_bin));
    aegisxd_json_add_string(o, "ids_ips_next_action", aegisxd_ids_ips_next_action(suricata_bin));
    json_object_object_add(o, "ids_ips_production_active", json_object_new_boolean(production_active));
    json_object_object_add(o, "ids_ips_capture_configured",
                           json_object_new_boolean(settings_ok &&
                                                   aegisxd_ids_ips_capture_configured(&settings)));
    aegisxd_json_add_string(o, "ids_ips_capture_mode",
                            settings_ok && !strcmp(settings.mode, "monitor") ? "af-packet" :
                            (settings_ok && !strcmp(settings.mode, "protect") ? "nfqueue" : ""));
    aegisxd_json_add_string(o, "ids_ips_capture_interface",
                            settings_ok ? settings.suricata_interface : "");
    json_object_object_add(o, "ids_ips_nfqueue_num",
                           json_object_new_int(settings_ok ? settings.suricata_queue_num : 0));
    json_object_object_add(o, "ids_ips_nfqueue_active",
                           json_object_new_boolean(settings_ok &&
                               aegisxd_ids_ips_nfqueue_required(&settings) &&
                               aegisxd_ids_ips_nfqueue_active_cached()));
    json_object_object_add(o, "ids_ips_production_events_supported", json_object_new_boolean(production_active));
    json_object_object_add(o, "ids_ips_runtime_pid_running",
                           json_object_new_boolean(aegisxd_suricata_pid_running()));
    json_object_object_add(o, "ids_ips_manual_eve_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(o, "ids_ips_manual_eve_ingest_active", json_object_new_boolean(manual_ingest_active));
    json_object_object_add(o, "ids_ips_manual_eve_ingest_is_production", json_object_new_boolean(0));
    json_object_object_add(o, "ids_ips_test_events_are_production", json_object_new_boolean(0));
    json_object_object_add(o, "ids_ips_runtime_package_option", json_object_new_string("CONFIG_DREAMINGWRT_AEGISXD_WITH_SURICATA=y"));
    json_object_object_add(o, "ids_ips_runtime_package_required", json_object_new_boolean(!runtime_available));
    aegisxd_json_add_string(o, "ids_ips_runtime_package", "suricata");
}

/* Per-feed fetch health.  The service-wide last_error cannot say which feed
 * failed, so callers had no way to tell one unreachable blocklist from a broken
 * engine.  Counters are reported alongside so the caller can judge severity. */
static struct json_object *aegisxd_feed_health_json(int *total, int *failing,
                                                    int *never_succeeded)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st;

    if (total)
        *total = 0;
    if (failing)
        *failing = 0;
    if (never_succeeded)
        *never_succeeded = 0;
    st = aegisxd_prepare(
        "SELECT feed_id,name,kind,url,enabled,last_success_at,last_error,item_count "
        "FROM aegis_feeds ORDER BY feed_id");
    if (!st)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        const char *err = aegisxd_sqlite_text(st, 6, "");
        int64_t success_at = sqlite3_column_int64(st, 5);
        int enabled = sqlite3_column_int(st, 4);

        aegisxd_json_add_string(o, "feed_id", aegisxd_sqlite_text(st, 0, ""));
        aegisxd_json_add_string(o, "name", aegisxd_sqlite_text(st, 1, ""));
        aegisxd_json_add_string(o, "kind", aegisxd_sqlite_text(st, 2, ""));
        aegisxd_json_add_string(o, "url", aegisxd_sqlite_text(st, 3, ""));
        json_object_object_add(o, "enabled", json_object_new_boolean(enabled));
        json_object_object_add(o, "last_success_at", json_object_new_int64(success_at));
        aegisxd_json_add_string(o, "last_error", err);
        json_object_object_add(o, "item_count", json_object_new_int(sqlite3_column_int(st, 7)));
        json_object_object_add(o, "healthy", json_object_new_boolean(!err[0] && success_at > 0));
        json_object_object_add(o, "failing", json_object_new_boolean(err[0] != '\0'));
        /* Never fetched even once, so this feed contributes nothing at all
         * rather than merely being stale. */
        json_object_object_add(o, "never_succeeded", json_object_new_boolean(success_at <= 0));
        aegisxd_json_add_string(o, "failure_reason", err);
        json_object_array_add(arr, o);
        if (total)
            (*total)++;
        if (err[0] && failing)
            (*failing)++;
        if (success_at <= 0 && never_succeeded)
            (*never_succeeded)++;
    }
    sqlite3_finalize(st);
    return arr;
}

static int aegisxd_feed_rows(void)
{
    sqlite3_stmt *st;
    int n = 0;

    st = aegisxd_prepare("SELECT COUNT(*) FROM aegis_feeds");
    if (!st)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int64_t aegisxd_feed_last_success(void)
{
    sqlite3_stmt *st;
    int64_t ts = 0;

    st = aegisxd_prepare("SELECT COALESCE(MAX(last_success_at),0) FROM aegis_feeds");
    if (!st)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        ts = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return ts;
}

static struct json_object *aegisxd_feed_counts_json(void)
{
    struct json_object *feeds = json_object_new_object();

    json_object_object_add(feeds, "configured", json_object_new_int(aegisxd_feed_rows()));
    json_object_object_add(feeds, "suricata_rules",
                           json_object_new_int(aegisxd_feed_count("suricata_rules")));
    json_object_object_add(feeds, "domain_categories",
                           json_object_new_int(aegisxd_feed_count("domain_categories")));
    json_object_object_add(feeds, "reputation_items",
                           json_object_new_int(aegisxd_feed_count("reputation_items")));
    json_object_object_add(feeds, "imported_suricata_rules",
                           json_object_new_int(aegisxd_table_count("aegis_suricata_rules")));
    json_object_object_add(feeds, "imported_domain_categories",
                           json_object_new_int(aegisxd_table_count("aegis_domain_categories")));
    json_object_object_add(feeds, "imported_reputation_items",
                           json_object_new_int(aegisxd_table_count("aegis_reputation_items")));
    json_object_object_add(feeds, "last_success_at",
                           json_object_new_int64(aegisxd_feed_last_success()));
    return feeds;
}

static struct json_object *aegisxd_enhanced_json(void)
{
    struct json_object *enhanced = json_object_new_object();

    json_object_object_add(enhanced, "available", json_object_new_boolean(0));
    aegisxd_json_add_string(enhanced, "reason", "proofpoint_cloudflare_feeds_unavailable");
    json_object_object_add(enhanced, "proofpoint_signatures", json_object_new_boolean(0));
    json_object_object_add(enhanced, "cloudflare_categories", json_object_new_boolean(0));
    return enhanced;
}

static struct json_object *aegisxd_sources_json(void)
{
    struct json_object *arr = json_object_new_array();
    const char *sources[] = {
        "emerging-threats-open-suricata",
        "urlhaus-hostfile",
        "oisd-big",
        "stevenblack-hosts",
        "stevenblack-fakenews-gambling-porn"
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(sources); i++)
        json_object_array_add(arr, json_object_new_string(sources[i]));
    return arr;
}

static struct json_object *aegisxd_capabilities_json(void)
{
    struct json_object *cap = json_object_new_object();
    const char *suricata_bin = aegisxd_suricata_binary_path();

    aegisxd_add_ids_ips_runtime_fields(cap, suricata_bin);
    json_object_object_add(cap, "feed_update", json_object_new_boolean(1));
    json_object_object_add(cap, "feed_download_dry_run", json_object_new_boolean(1));
    json_object_object_add(cap, "feed_import", json_object_new_boolean(1));
    json_object_object_add(cap, "compile", json_object_new_boolean(1));
    json_object_object_add(cap, "apply", json_object_new_boolean(1));
    json_object_object_add(cap, "apply_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "apply_confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "ids_monitor", json_object_new_boolean(suricata_bin[0] != 0));
    json_object_object_add(cap, "ips_protect", json_object_new_boolean(suricata_bin[0] != 0));
    json_object_object_add(cap, "ids_ips_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "ids_ips_rules_ready",
                           json_object_new_boolean(aegisxd_table_count("aegis_suricata_rules") > 0));
    json_object_object_add(cap, "ids_ips_runtime_available",
                           json_object_new_boolean(suricata_bin[0] != 0));
    aegisxd_json_add_string(cap, "ids_ips_runtime_reason",
                            aegisxd_ids_ips_runtime_reason(suricata_bin));
    json_object_object_add(cap, "ids_ips_event_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "ids_ips_manual_eve_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "ids_ips_event_ingest_active",
                           json_object_new_boolean(aegisxd_suricata_hit_producer_active()));
    json_object_object_add(cap, "dns_filter", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_compile_plan", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_guarded_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_runtime_include", json_object_new_boolean(1));
    json_object_object_add(cap, "dnsmasq_restart_required", json_object_new_boolean(1));
    json_object_object_add(cap, "reputation", json_object_new_boolean(1));
    json_object_object_add(cap, "reputation_compile_plan", json_object_new_boolean(1));
    json_object_object_add(cap, "dataplane_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_public_ip_only", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_compile_plan", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_signature_policy", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_signature_policy_persisted", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_signature_policy_apply_required", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_signature_suppress", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_config_render", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_test_config", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_ruleset_available",
                           json_object_new_boolean(aegisxd_table_count("aegis_suricata_rules") > 0));
    json_object_object_add(cap, "suricata_signature_policy_counts", aegisxd_signature_policy_counts_json());
    json_object_object_add(cap, "suricata_runtime_available",
                           json_object_new_boolean(suricata_bin[0] != 0));
    aegisxd_json_add_string(cap, "suricata_binary", suricata_bin);
    json_object_object_add(cap, "suricata_config_available",
                           json_object_new_boolean(aegisxd_suricata_config_available()));
    aegisxd_json_add_string(cap, "suricata_apply_reason",
                            suricata_bin[0] ? "suricata_guarded_apply_ready" :
                            "suricata_runtime_missing");
    aegisxd_json_add_string(cap, "ids_ips_event_ingest_reason",
                            aegisxd_suricata_hit_producer_active() ? "" :
                            aegisxd_ids_ips_runtime_reason(suricata_bin));
    json_object_object_add(cap, "policy_hit_log_schema", json_object_new_boolean(1));
    json_object_object_add(cap, "policy_hit_logging", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_hit_logging", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_hit_producer", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_hit_log_work_file", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_client_attribution", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_client_mac_lookup", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_client_interface_lookup", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "dns_filter_client_identity_sources", "dnsmasq_query_source_ip,/proc/net/arp,ip_neigh");
    json_object_object_add(cap, "nft_hit_producer", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_hit_producer_aggregate_only", json_object_new_boolean(1));
    json_object_object_add(cap, "reputation_ip_per_flow_hit_producer", json_object_new_boolean(1));
    json_object_object_add(cap, "reputation_ip_per_flow_precision",
                           json_object_new_string("conntrack_flow_snapshot"));
    json_object_object_add(cap, "suricata_eve_hit_producer", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "suricata_eve_path", AEGISXD_SURICATA_EVE_PATH);
    json_object_object_add(cap, "honeypot",
                           json_object_new_boolean(aegisxd_honeypot_binary_available()));
    json_object_object_add(cap, "honeypot_supported",
                           json_object_new_boolean(aegisxd_honeypot_binary_available()));
    json_object_object_add(cap, "honeypot_config_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_events_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_event_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_config", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_validate", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_guarded_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_event_ingest", json_object_new_boolean(1));
    json_object_object_add(cap, "honeypot_active",
                           json_object_new_boolean(aegisxd_honeypot_active()));
    json_object_object_add(cap, "content_policy_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "content_policy_crud_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "domain_overrides_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "content_filter_ad_block_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "content_filter_safe_search_supported", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "content_filter_safe_search_providers",
                            "google,bing,youtube");
    aegisxd_json_add_string(cap, "content_filter_safe_search_merge", "logical_or");
    json_object_object_add(cap, "content_filter_safe_search_dnsmasq_artifact",
                           json_object_new_boolean(1));
    json_object_object_add(cap, "content_filter_schedule_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "content_filter_all_scope_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "content_filter_device_scope_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "content_filter_network_scope_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "pcdn_filter_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_feed_update", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_guarded_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_monitor_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_hit_monitoring_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_hit_attribution_ready",
                           json_object_new_boolean(aegisxd_pcdn_hit_attribution_ready()));
    json_object_object_add(cap, "pcdn_hit_count_supported", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "pcdn_modes", "block,monitor");
    aegisxd_json_add_string(cap, "pcdn_dataplane", "dnsmasq_domain_block_or_query_monitor");
    json_object_object_add(cap, "geo_country", aegisxd_geo_status_json());
    json_object_object_add(cap, "identification_mode_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "identification_runtime_readback", json_object_new_boolean(1));
    json_object_object_add(cap, "traffic_history_clear_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "traffic_history_clear_confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "traffic_history_clear_owner_only", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "identification_modes",
                            "disabled,device_and_traffic,traffic_only");
    json_object_object_add(cap, "ssl_inspection", json_object_new_boolean(0));
    json_object_object_add(cap, "inspection_ca_management", json_object_new_boolean(1));
    json_object_object_add(cap, "inspection_ca_download", json_object_new_boolean(1));
    json_object_object_add(cap, "inspection_ca_rotation", json_object_new_boolean(1));
    json_object_object_add(cap, "inspection_ca_revocation", json_object_new_boolean(1));
    json_object_object_add(cap, "inspection_ca_manual_distribution", json_object_new_boolean(1));
    json_object_object_add(cap, "inspection_ca_automatic_distribution", json_object_new_boolean(0));
    aegisxd_json_add_string(cap, "inspection_ca_automatic_distribution_reason",
                            "trusted_terminal_certificate_agent_missing");
    return cap;
}

static struct json_object *aegisxd_paths_json(void)
{
    struct json_object *paths = json_object_new_object();

    aegisxd_json_add_string(paths, "config_db", AEGISXD_CONFIG_DB_PATH);
    aegisxd_json_add_string(paths, "aegis_db", AEGISXD_DB_PATH);
    aegisxd_json_add_string(paths, "runtime_dir", AEGISXD_RUNTIME_DIR);
    aegisxd_json_add_string(paths, "work_dir", AEGISXD_WORK_DIR);
    aegisxd_json_add_string(paths, "feed_dir", AEGISXD_FEED_DIR);
    aegisxd_json_add_string(paths, "legacy_feed_dir", AEGISXD_LEGACY_FEED_DIR);
    return paths;
}

struct json_object *aegisxd_runtime_json(void)
{
    struct json_object *runtime = json_object_new_object();
    const char *active = "/run/dreamingwrt/aegis/active.json";
    const char *state = access(active, F_OK) == 0 ? "enabled" : "stopped";
    const char *suricata_bin = aegisxd_suricata_binary_path();
    struct json_object *producer = aegisxd_dns_hit_producer_status_json();
    struct json_object *last_event = NULL;

    aegisxd_add_ids_ips_runtime_fields(runtime, suricata_bin);
    aegisxd_json_add_string(runtime, "suricata", aegisxd_suricata_active() ? "enabled" : "stopped");
    json_object_object_add(runtime, "suricata_ruleset_ready",
                           json_object_new_boolean(aegisxd_table_count("aegis_suricata_rules") > 0));
    json_object_object_add(runtime, "suricata_enabled_rules",
                           json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_suricata_rules WHERE enabled_default=1")));
    json_object_object_add(runtime, "suricata_runtime_available",
                           json_object_new_boolean(suricata_bin[0] != 0));
    aegisxd_json_add_string(runtime, "suricata_binary", suricata_bin);
    json_object_object_add(runtime, "suricata_config_available",
                           json_object_new_boolean(aegisxd_suricata_config_available()));
    aegisxd_json_add_string(runtime, "suricata_config_path", AEGISXD_SURICATA_CONFIG_PATH);
    aegisxd_json_add_string(runtime, "suricata_eve_path", AEGISXD_SURICATA_EVE_PATH);
    aegisxd_json_add_string(runtime, "suricata_pid_path", AEGISXD_SURICATA_PID_PATH);
    aegisxd_json_add_string(runtime, "suricata_reason",
                            aegisxd_ids_ips_runtime_reason(suricata_bin));
    json_object_object_add(runtime, "ids_ips_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "ids_ips_rules_ready",
                           json_object_new_boolean(aegisxd_table_count("aegis_suricata_rules") > 0));
    json_object_object_add(runtime, "ids_ips_runtime_available",
                           json_object_new_boolean(suricata_bin[0] != 0));
    aegisxd_json_add_string(runtime, "ids_ips_runtime_reason",
                            aegisxd_ids_ips_runtime_reason(suricata_bin));
    json_object_object_add(runtime, "ids_ips_event_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "ids_ips_manual_eve_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "ids_ips_event_ingest_active",
                           json_object_new_boolean(aegisxd_suricata_hit_producer_active()));
    aegisxd_json_add_string(runtime, "ids_ips_event_ingest_reason",
                            aegisxd_suricata_hit_producer_active() ? "" :
                            aegisxd_ids_ips_runtime_reason(suricata_bin));
    aegisxd_json_add_string(runtime, "dns_filter", state);
    aegisxd_json_add_string(runtime, "dns_filter_reason",
                            access(active, F_OK) != 0 ? "dns_filter_not_applied" :
                            (aegisxd_dns_hit_producer_active() ? "" :
                             "dns_filter_hit_producer_waiting_for_log"));
    aegisxd_json_add_string(runtime, "reputation", aegisxd_nft_reputation_active() ? "enabled" : "stopped");
    {
        struct json_object *honeypot = aegisxd_honeypot_runtime_json();
        struct json_object *honeypot_state = NULL;
        if (json_object_object_get_ex(honeypot, "state", &honeypot_state) && honeypot_state)
            aegisxd_json_add_string(runtime, "honeypot", json_object_get_string(honeypot_state));
        else
            aegisxd_json_add_string(runtime, "honeypot", "stopped");
        json_object_object_add(runtime, "honeypot_runtime", honeypot);
    }
    json_object_object_add(runtime, "content_filter", aegisxd_content_runtime_json());
    json_object_object_add(runtime, "geo_country", aegisxd_geo_status_json());
    aegisxd_json_add_string(runtime, "compile", "compile-and-guarded-dns-apply");
    aegisxd_json_add_string(runtime, "active_state_path", active);
    if (json_object_object_get_ex(producer, "last_event_at", &last_event) && last_event)
        json_object_object_add(runtime, "last_event_at", json_object_get(last_event));
    else
        json_object_object_add(runtime, "last_event_at", json_object_new_null());
    json_object_object_add(runtime, "events_buffered",
                           json_object_new_int(aegisxd_table_count("aegis_events")));
    json_object_object_add(runtime, "dataplane_enabled", json_object_new_boolean(access(active, F_OK) == 0));
    json_object_object_add(runtime, "apply_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "dns_filter_apply_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "dns_filter_client_attribution_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "dns_filter_client_mac_lookup_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "nft_apply_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "nft_reputation_active", json_object_new_boolean(aegisxd_nft_reputation_active()));
    json_object_object_add(runtime, "nft_reputation_apply_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "suricata_apply_supported", json_object_new_boolean(1));
    json_object_object_add(runtime, "dns_hit_producer", producer);
    json_object_object_add(runtime, "nft_hit_producer", aegisxd_nft_hit_producer_status_json());
    json_object_object_add(runtime, "suricata_hit_producer", aegisxd_suricata_hit_producer_status_json());
    return runtime;
}

struct json_object *aegisxd_status_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    struct aegisxd_settings settings;
    char state[64] = "idle";
    char last_error[AEGISXD_MAX_TEXT] = "";
    int schema_version = 0;
    int64_t updated_at = 0;
    int64_t last_error_at = 0;
    int settings_ok;
    int ok;
    int degraded;
    struct json_object *feed_health;
    int feeds_total = 0;
    int feeds_failing = 0;
    int feeds_never_succeeded = 0;

    settings_ok = aegisxd_settings_load(&settings) == 0;
    ok = aegisxd_status_contract_load(state, sizeof(state), last_error, sizeof(last_error),
                                      &schema_version, &updated_at, &last_error_at,
                                      datasets);
    ok = ok && settings_ok;
    if (!ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "status_query_failed");
    feed_health = aegisxd_feed_health_json(&feeds_total, &feeds_failing,
                                           &feeds_never_succeeded);
    /* A single feed that cannot be fetched is a per-feed fault, not a service
     * fault.  Previously any non-empty last_error anywhere pulled the whole
     * service to degraded, which hid the difference between "one blocklist is
     * unreachable" and "the engine is broken". */
    degraded = !ok || !strcmp(state, "failed") || !strcmp(state, "error") ||
               (feeds_total > 0 && feeds_failing >= feeds_total);
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "version", WORKER_STATUS_VERSION);
    aegisxd_json_add_string(resp, "stage", "p4-guarded-dns-dataplane-apply");
    aegisxd_json_add_string(resp, "state", degraded ? "degraded" : state);
    json_object_object_add(resp, "degraded", json_object_new_boolean(degraded));
    aegisxd_json_add_string(resp, "last_error", last_error);
    /* Without a timestamp a sticky error reads as a current fault.  Callers can
     * now tell how old it is instead of guessing. */
    json_object_object_add(resp, "last_error_at", json_object_new_int64(last_error_at));
    json_object_object_add(resp, "feed_health", feed_health);
    json_object_object_add(resp, "feeds_total", json_object_new_int(feeds_total));
    json_object_object_add(resp, "feeds_failing", json_object_new_int(feeds_failing));
    json_object_object_add(resp, "feeds_healthy",
                           json_object_new_int(feeds_total - feeds_failing));
    json_object_object_add(resp, "feeds_never_succeeded",
                           json_object_new_int(feeds_never_succeeded));
    /* last_error is retained for compatibility but is only one of possibly
     * several faults; feed_health carries the per-feed detail. */
    json_object_object_add(resp, "last_error_is_service_wide",
                           json_object_new_boolean(feeds_total > 0 &&
                                                   feeds_failing >= feeds_total));
    aegisxd_json_add_string(resp, "feed_degradation_scope",
                            feeds_failing <= 0 ? "none" :
                            (feeds_failing >= feeds_total ? "all_feeds" : "partial_feeds"));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(resp, "schema_version", json_object_new_int(schema_version));
    aegisxd_json_add_string(resp, "schema_source", "aegis.db:aegis_state.schema_version");
    aegisxd_json_add_string(resp, "migration_state",
                            schema_version == AEGISXD_SCHEMA_VERSION ? "current" :
                            (schema_version > 0 ? "version_mismatch" : "unknown"));
    json_object_object_add(dependencies, "config_db",
                           json_object_new_boolean(g_aegisxd_config_db != NULL));
    json_object_object_add(dependencies, "aegis_db",
                           json_object_new_boolean(g_aegisxd_db != NULL));
    json_object_object_add(dependencies, "suricata_binary",
                           json_object_new_boolean(aegisxd_suricata_binary_path()[0]));
    json_object_object_add(resp, "dependencies", dependencies);
    json_object_object_add(resp, "datasets", datasets);
    json_object_object_add(resp, "enabled", json_object_new_boolean(settings.enabled));
    aegisxd_json_add_string(resp, "mode", settings.mode);
    aegisxd_json_add_string(resp, "source_level", settings.source_level);
    aegisxd_json_add_string(resp, "suricata_version", settings.suricata_version);
    aegisxd_json_add_string(resp, "default_action", settings.default_action);
    json_object_object_add(resp, "logging_enabled", json_object_new_boolean(settings.logging_enabled));
    aegisxd_json_add_string(resp, "suricata_interface", settings.suricata_interface);
    json_object_object_add(resp, "suricata_queue_num",
                           json_object_new_int(settings.suricata_queue_num));
    json_object_object_add(resp, "suricata_fail_open",
                           json_object_new_boolean(settings.suricata_fail_open));
    aegisxd_add_ids_ips_runtime_fields(resp, aegisxd_suricata_binary_path());
    json_object_object_add(resp, "apply_enabled", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_enabled", json_object_new_boolean(access("/run/dreamingwrt/aegis/active.json", F_OK) == 0));
    json_object_object_add(resp, "compile_plan_enabled", json_object_new_boolean(1));
    json_object_object_add(resp, "enhanced", aegisxd_enhanced_json());
    json_object_object_add(resp, "sources", aegisxd_sources_json());
    json_object_object_add(resp, "feeds", aegisxd_feed_counts_json());
    json_object_object_add(resp, "runtime", aegisxd_runtime_json());
    json_object_object_add(resp, "identification", aegisxd_identification_json());
    json_object_object_add(resp, "paths", aegisxd_paths_json());
    json_object_object_add(resp, "capabilities", aegisxd_capabilities_json());
    json_object_object_add(resp, "ts", json_object_new_int64(aegisxd_now_s()));
    return resp;
}

struct json_object *aegisxd_feeds_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *feeds = json_object_new_array();
    sqlite3_stmt *st;

    st = aegisxd_prepare(
        "SELECT feed_id,name,kind,url,enabled,version,sha256,last_success_at,last_error,item_count,"
        "format,content_type,artifact_path "
        "FROM aegis_feeds ORDER BY feed_id");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();

            aegisxd_json_add_string(o, "feed_id", aegisxd_sqlite_text(st, 0, ""));
            aegisxd_json_add_string(o, "name", aegisxd_sqlite_text(st, 1, ""));
            aegisxd_json_add_string(o, "kind", aegisxd_sqlite_text(st, 2, ""));
            aegisxd_json_add_string(o, "url", aegisxd_sqlite_text(st, 3, ""));
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 4)));
            aegisxd_json_add_string(o, "version", aegisxd_sqlite_text(st, 5, ""));
            aegisxd_json_add_string(o, "sha256", aegisxd_sqlite_text(st, 6, ""));
            json_object_object_add(o, "last_success_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
            aegisxd_json_add_string(o, "last_error", aegisxd_sqlite_text(st, 8, ""));
            json_object_object_add(o, "item_count", json_object_new_int(sqlite3_column_int(st, 9)));
            aegisxd_json_add_string(o, "format", aegisxd_sqlite_text(st, 10, ""));
            aegisxd_json_add_string(o, "content_type", aegisxd_sqlite_text(st, 11, ""));
            aegisxd_json_add_string(o, "artifact_path", aegisxd_sqlite_text(st, 12, ""));
            json_object_array_add(feeds, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "counts", aegisxd_feed_counts_json());
    json_object_object_add(resp, "paths", aegisxd_paths_json());
    json_object_object_add(resp, "feeds", feeds);
    return resp;
}

struct json_object *aegisxd_feed_status_json(void)
{
    struct json_object *resp = json_object_new_object();
    int running = 0;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "jobs", aegisxd_feed_jobs_json(&running));
    aegisxd_json_add_string(resp, "state", running ? "running" : "idle");
    json_object_object_add(resp, "running", json_object_new_boolean(running));
    json_object_object_add(resp, "last_success_at", json_object_new_int64(aegisxd_feed_last_success()));
    json_object_object_add(resp, "counts", aegisxd_feed_counts_json());
    json_object_object_add(resp, "paths", aegisxd_paths_json());
    return resp;
}

static struct json_object *aegisxd_group_counts_json(const char *sql)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st;

    st = aegisxd_prepare(sql);
    if (!st)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();

        aegisxd_json_add_string(o, "category", aegisxd_sqlite_text(st, 0, ""));
        json_object_object_add(o, "count", json_object_new_int(sqlite3_column_int(st, 1)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

struct json_object *aegisxd_categories_json(void)
{
    struct json_object *resp = json_object_new_object();
    int count = aegisxd_table_count("aegis_domain_categories");

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "available", json_object_new_boolean(count > 0));
    if (count <= 0)
        aegisxd_json_add_string(resp, "reason", "feeds_not_imported");
    json_object_object_add(resp, "total", json_object_new_int(count));
    json_object_object_add(resp, "categories",
        aegisxd_group_counts_json(
            "SELECT category,COUNT(*) FROM aegis_domain_categories "
            "GROUP BY category ORDER BY COUNT(*) DESC,category"));
    return resp;
}

struct json_object *aegisxd_signature_categories_json(void)
{
    struct json_object *resp = json_object_new_object();
    int count = aegisxd_table_count("aegis_suricata_rules");

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "available", json_object_new_boolean(count > 0));
    if (count <= 0)
        aegisxd_json_add_string(resp, "reason", "suricata_rules_not_imported");
    json_object_object_add(resp, "total", json_object_new_int(count));
    json_object_object_add(resp, "categories",
        aegisxd_group_counts_json(
            "SELECT category,COUNT(*) FROM aegis_suricata_rules "
            "GROUP BY category ORDER BY COUNT(*) DESC,category"));
    return resp;
}


static void aegisxd_event_add_meta_fields(struct json_object *event, const char *meta_s,
                                          const char *reason, const char *source)
{
    struct json_object *meta = NULL;
    int test_event = 0;
    int manual_ingest = 0;

    if (!event)
        return;
    if (reason && (strstr(reason, "manual") || strstr(reason, "manual_test")))
        manual_ingest = 1;
    if (source && strstr(source, ".manual"))
        manual_ingest = 1;
    if (reason && strstr(reason, "manual_test"))
        test_event = 1;
    if (source && strstr(source, "manual_test"))
        test_event = 1;
    if (meta_s && meta_s[0]) {
        meta = json_tokener_parse(meta_s);
        if (meta) {
            test_event = test_event || aegisxd_json_bool(meta, "test_event", 0);
            manual_ingest = manual_ingest || aegisxd_json_bool(meta, "manual_ingest", 0) ||
                (strstr(aegisxd_json_str(meta, "ingest_source", ""), ".manual") != NULL);
            json_object_object_add(event, "meta", meta);
            if (json_object_object_get(meta, "severity"))
                json_object_object_add(event, "severity", json_object_get(json_object_object_get(meta, "severity")));
            if (json_object_object_get(meta, "sid"))
                json_object_object_add(event, "sid", json_object_get(json_object_object_get(meta, "sid")));
            if (json_object_object_get(meta, "gid"))
                json_object_object_add(event, "gid", json_object_get(json_object_object_get(meta, "gid")));
            if (json_object_object_get(meta, "rev"))
                json_object_object_add(event, "rev", json_object_get(json_object_object_get(meta, "rev")));
            if (json_object_object_get(meta, "signature"))
                json_object_object_add(event, "signature", json_object_get(json_object_object_get(meta, "signature")));
            if (json_object_object_get(meta, "category"))
                json_object_object_add(event, "category", json_object_get(json_object_object_get(meta, "category")));
            if (json_object_object_get(meta, "ingest_source"))
                json_object_object_add(event, "ingest_source", json_object_get(json_object_object_get(meta, "ingest_source")));
        }
    }
    json_object_object_add(event, "test_event", json_object_new_boolean(test_event));
    json_object_object_add(event, "manual_ingest", json_object_new_boolean(manual_ingest));
    json_object_object_add(event, "production_event",
                           json_object_new_boolean(!manual_ingest && !test_event));
}

struct json_object *aegisxd_events_recent_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *events = json_object_new_array();
    struct json_object *cap = json_object_new_object();
    sqlite3_stmt *st;
    int total = aegisxd_table_count("aegis_events");
    int limit = 100;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "available", json_object_new_boolean(total > 0));
    if (total <= 0)
        aegisxd_json_add_string(resp, "reason", "no_policy_hit_events");
    json_object_object_add(resp, "total", json_object_new_int(total));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    st = aegisxd_prepare(
        "SELECT id,ts,event_type,level,action,policy_id,policy_name,policy_type,"
        "rule_id,rule_name,risk,risk_category,source_ip,source_mac,source_port,"
        "destination_ip,destination_host,destination_port,protocol,app_id,app_name,"
        "in_interface,out_interface,rx_bytes,tx_bytes,flow_id,reason,source,meta_json,"
        "occurrence_count,first_seen,last_seen "
        "FROM aegis_events ORDER BY ts DESC,id DESC LIMIT 100");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
            aegisxd_json_add_string(o, "event_type", aegisxd_sqlite_text(st, 2, ""));
            aegisxd_json_add_string(o, "level", aegisxd_sqlite_text(st, 3, ""));
            aegisxd_json_add_string(o, "action", aegisxd_sqlite_text(st, 4, ""));
            aegisxd_json_add_string(o, "policy_id", aegisxd_sqlite_text(st, 5, ""));
            aegisxd_json_add_string(o, "policy_name", aegisxd_sqlite_text(st, 6, ""));
            aegisxd_json_add_string(o, "policy_type", aegisxd_sqlite_text(st, 7, ""));
            aegisxd_json_add_string(o, "rule_id", aegisxd_sqlite_text(st, 8, ""));
            aegisxd_json_add_string(o, "rule_name", aegisxd_sqlite_text(st, 9, ""));
            aegisxd_json_add_string(o, "risk", aegisxd_sqlite_text(st, 10, ""));
            aegisxd_json_add_string(o, "risk_category", aegisxd_sqlite_text(st, 11, ""));
            aegisxd_json_add_string(o, "source_ip", aegisxd_sqlite_text(st, 12, ""));
            aegisxd_json_add_string(o, "source_mac", aegisxd_sqlite_text(st, 13, ""));
            json_object_object_add(o, "source_port", json_object_new_int(sqlite3_column_int(st, 14)));
            aegisxd_json_add_string(o, "destination_ip", aegisxd_sqlite_text(st, 15, ""));
            aegisxd_json_add_string(o, "destination_host", aegisxd_sqlite_text(st, 16, ""));
            json_object_object_add(o, "destination_port", json_object_new_int(sqlite3_column_int(st, 17)));
            aegisxd_json_add_string(o, "protocol", aegisxd_sqlite_text(st, 18, ""));
            aegisxd_json_add_string(o, "app_id", aegisxd_sqlite_text(st, 19, ""));
            aegisxd_json_add_string(o, "app_name", aegisxd_sqlite_text(st, 20, ""));
            aegisxd_json_add_string(o, "in_interface", aegisxd_sqlite_text(st, 21, ""));
            aegisxd_json_add_string(o, "out_interface", aegisxd_sqlite_text(st, 22, ""));
            json_object_object_add(o, "rx_bytes", json_object_new_int64(sqlite3_column_int64(st, 23)));
            json_object_object_add(o, "tx_bytes", json_object_new_int64(sqlite3_column_int64(st, 24)));
            const char *reason = aegisxd_sqlite_text(st, 26, "");
            const char *source = aegisxd_sqlite_text(st, 27, "");
            const char *meta_json = aegisxd_sqlite_text(st, 28, "{}");

            aegisxd_json_add_string(o, "flow_id", aegisxd_sqlite_text(st, 25, ""));
            aegisxd_json_add_string(o, "reason", reason);
            aegisxd_json_add_string(o, "source", source);
            aegisxd_json_add_string(o, "meta_json", meta_json);
            json_object_object_add(o, "occurrence_count",
                                   json_object_new_int64(sqlite3_column_int64(st, 29)));
            json_object_object_add(o, "first_seen",
                                   json_object_new_int64(sqlite3_column_int64(st, 30)));
            json_object_object_add(o, "last_seen",
                                   json_object_new_int64(sqlite3_column_int64(st, 31)));
            aegisxd_event_add_meta_fields(o, meta_json, reason, source);
            json_object_array_add(events, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "events", events);
    json_object_object_add(cap, "schema_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "producer_connected", json_object_new_boolean(aegisxd_dns_hit_producer_active()));
    json_object_object_add(cap, "policy_supported", json_object_new_boolean(total > 0 || aegisxd_dns_hit_producer_active()));
    json_object_object_add(cap, "dataplane_action_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_action_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_hit_logging", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_action_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_action_precision", json_object_new_string("aggregate_rule_counter"));
    json_object_object_add(cap, "reputation_ip_per_flow_action_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "reputation_ip_per_flow_action_precision",
                           json_object_new_string("conntrack_flow_snapshot"));
    json_object_object_add(cap, "suricata_action_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_action_precision", json_object_new_string("eve_alert"));
    json_object_object_add(cap, "suricata_manual_ingest_is_production", json_object_new_boolean(0));
    json_object_object_add(cap, "suricata_test_events_are_production", json_object_new_boolean(0));
    json_object_object_add(cap, "route_policy_action_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "route_policy_action_precision", json_object_new_string("policy_hit_sample_or_aggregate_rule_counter"));
    json_object_object_add(cap, "route_policy_sample_precision", json_object_new_string("policy_hit_sample"));
    json_object_object_add(cap, "route_policy_counter_precision", json_object_new_string("aggregate_rule_counter"));
    json_object_object_add(cap, "hit_producer", aegisxd_dns_hit_producer_status_json());
    json_object_object_add(cap, "nft_hit_producer", aegisxd_nft_hit_producer_status_json());
    json_object_object_add(cap, "suricata_hit_producer", aegisxd_suricata_hit_producer_status_json());
    json_object_object_add(cap, "policy_hit_producer", aegisxd_policy_hit_producer_status_json());
    json_object_object_add(resp, "capabilities", cap);
    json_object_object_add(resp, "degraded", json_object_new_boolean(0));
    return resp;
}

struct json_object *aegisxd_stats_json(void)
{
    struct json_object *resp = json_object_new_object();
    int total = aegisxd_table_count("aegis_events");

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "events", json_object_new_int(total));
    json_object_object_add(resp, "alerts",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE action='alert'")));
    json_object_object_add(resp, "blocks",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE action IN ('drop','block','reject')")));
    json_object_object_add(resp, "dns_blocks",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type='dns_filter' AND action IN ('drop','block','reject')")));
    json_object_object_add(resp, "reputation_blocks",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type LIKE 'reputation%' AND action IN ('drop','block','reject')")));
    json_object_object_add(resp, "suricata_alerts",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type='ids_ips'")));
    json_object_object_add(resp, "suricata_test_events",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type='ids_ips' AND (reason LIKE '%manual_test%' OR source LIKE '%manual_test%' OR meta_json LIKE '%\"test_event\":true%')")));
    json_object_object_add(resp, "suricata_manual_ingest_events",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type='ids_ips' AND (reason LIKE '%manual%' OR source LIKE '%manual%')")));
    json_object_object_add(resp, "suricata_production_events",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type='ids_ips' AND reason='suricata_eve_alert' AND source='aegisxd.suricata'")));
    json_object_object_add(resp, "route_policy_hits",
        json_object_new_int(aegisxd_count_sql("SELECT COUNT(*) FROM aegis_events WHERE policy_type='policy_route' AND source='aegisxd.policy_route'")));
    json_object_object_add(resp, "honeypot_hits",
                           json_object_new_int(aegisxd_honeypot_hit_count()));
    json_object_object_add(resp, "policy_hit_log_schema_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "producer_connected", json_object_new_boolean(aegisxd_dns_hit_producer_active()));
    json_object_object_add(resp, "dns_filter_hit_logging", json_object_new_boolean(1));
    json_object_object_add(resp, "nft_hit_producer_connected", json_object_new_boolean(aegisxd_nft_hit_producer_active()));
    json_object_object_add(resp, "nft_hit_producer", aegisxd_nft_hit_producer_status_json());
    json_object_object_add(resp, "suricata_hit_producer_connected", json_object_new_boolean(aegisxd_suricata_hit_producer_active()));
    json_object_object_add(resp, "suricata_hit_producer", aegisxd_suricata_hit_producer_status_json());
    json_object_object_add(resp, "ids_ips_event_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "ids_ips_manual_eve_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "policy_hit_producer_connected", json_object_new_boolean(aegisxd_policy_hit_producer_connected()));
    json_object_object_add(resp, "policy_hit_producer_available", json_object_new_boolean(aegisxd_policy_hit_producer_active()));
    json_object_object_add(resp, "policy_hit_producer", aegisxd_policy_hit_producer_status_json());
    return resp;
}

struct json_object *aegisxd_health_json(void)
{
    struct json_object *resp = json_object_new_object();
    const char *suricata_bin = aegisxd_suricata_binary_path();
    int active = aegisxd_dns_hit_producer_active();

    aegisxd_add_ids_ips_runtime_fields(resp, suricata_bin);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "status", "ok");
    json_object_object_add(resp, "degraded", json_object_new_boolean(!active && access("/run/dreamingwrt/aegis/active.json", F_OK) == 0));
    aegisxd_json_add_string(resp, "reason", active ? "" :
                            (access("/run/dreamingwrt/aegis/active.json", F_OK) == 0 ?
                             "dns_filter_hit_producer_waiting_for_log" :
                             "dns_filter_not_applied"));
    json_object_object_add(resp, "dataplane_enabled", json_object_new_boolean(access("/run/dreamingwrt/aegis/active.json", F_OK) == 0));
    json_object_object_add(resp, "dns_filter_apply_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "dns_filter_client_attribution_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "dns_filter_client_mac_lookup_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "policy_hit_log_schema_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "policy_hit_producer_connected",
                           json_object_new_boolean(active || aegisxd_nft_hit_producer_active() ||
                                                   aegisxd_suricata_hit_producer_active() ||
                                                   aegisxd_policy_hit_producer_connected()));
    json_object_object_add(resp, "route_policy_hit_available",
                           json_object_new_boolean(aegisxd_policy_hit_producer_active()));
    json_object_object_add(resp, "dns_hit_producer", aegisxd_dns_hit_producer_status_json());
    json_object_object_add(resp, "nft_hit_producer", aegisxd_nft_hit_producer_status_json());
    json_object_object_add(resp, "suricata_hit_producer", aegisxd_suricata_hit_producer_status_json());
    json_object_object_add(resp, "ids_ips_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "ids_ips_rules_ready",
                           json_object_new_boolean(aegisxd_table_count("aegis_suricata_rules") > 0));
    json_object_object_add(resp, "ids_ips_runtime_available",
                           json_object_new_boolean(suricata_bin[0] != 0));
    aegisxd_json_add_string(resp, "ids_ips_runtime_reason",
                            aegisxd_ids_ips_runtime_reason(suricata_bin));
    json_object_object_add(resp, "ids_ips_event_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "ids_ips_manual_eve_ingest_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "ids_ips_event_ingest_active",
                           json_object_new_boolean(aegisxd_suricata_hit_producer_active()));
    json_object_object_add(resp, "policy_hit_producer", aegisxd_policy_hit_producer_status_json());
    return resp;
}
