// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"
#include "jmx_strbuf.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>

#define AEGISXD_DNSMASQ_ACTIVE_FILE "dreamingwrt-aegis.conf"
#define AEGISXD_DNSMASQ_MANAGED_GLOB "/tmp/dnsmasq.*.d/" AEGISXD_DNSMASQ_ACTIVE_FILE
#define AEGISXD_NFT_TABLE "dreamingwrt_aegis"
#define AEGISXD_NFT_ACTIVE_FILE AEGISXD_RUNTIME_DIR "/nft-active.json"
#define AEGISXD_NFT_LOG "/tmp/dreamingwrt-aegis-nft.log"
#define AEGISXD_SURICATA_LOG "/tmp/dreamingwrt-aegis-suricata.log"
#define AEGISXD_SURICATA_START_WAIT_STEPS 50
#define AEGISXD_SURICATA_START_WAIT_US 100000
#define AEGISXD_DNSMASQ_RELOAD_CMD \
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin /etc/init.d/dnsmasq restart >/tmp/dreamingwrt-aegis-dnsmasq-reload.log 2>&1"

int aegisxd_content_safe_search_effective_values(int *google, int *bing,
                                                  int *youtube,
                                                  int *policy_count,
                                                  int *provider_count,
                                                  int *rule_count);

static const char *aegisxd_suricata_binary_path(void)
{
    if (access("/usr/bin/suricata", X_OK) == 0)
        return "/usr/bin/suricata";
    if (access("/usr/sbin/suricata", X_OK) == 0)
        return "/usr/sbin/suricata";
    return "";
}

int aegisxd_suricata_runtime_available(void)
{
    return aegisxd_suricata_binary_path()[0] != '\0';
}

static int aegisxd_suricata_config_available(void)
{
    return access(AEGISXD_SURICATA_CONFIG_PATH, R_OK) == 0;
}

static int aegisxd_suricata_active(void)
{
    return access(AEGISXD_SURICATA_ACTIVE_PATH, F_OK) == 0;
}

static int aegisxd_plan_count_sql(const char *sql)
{
    sqlite3_stmt *st = NULL;
    int n = 0;

    st = aegisxd_prepare(sql);
    if (!st)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int aegisxd_dataplane_run_quiet_log(const char *cmd, const char *log_path)
{
    pid_t pid;
    int status = 0;
    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int have_old_chld = 0;

    if (!cmd || !cmd[0])
        return -1;
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, &dfl_chld, &old_chld) == 0)
        have_old_chld = 1;
    pid = fork();
    if (pid < 0) {
        if (have_old_chld)
            sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        int fd = open(log_path && log_path[0] ? log_path : "/tmp/dreamingwrt-aegis-run.log",
                      O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        if (have_old_chld)
            sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (have_old_chld)
        sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return -1;
}

static int aegisxd_dataplane_run_quiet(const char *cmd)
{
    return aegisxd_dataplane_run_quiet_log(cmd, "/tmp/dreamingwrt-aegis-dnsmasq-reload.log");
}

static int aegisxd_file_copy_atomic(const char *src, const char *dst)
{
    FILE *in = NULL;
    FILE *out = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];
    char buf[8192];
    size_t n;
    int rc = -1;

    if (!src || !dst || src[0] != '/' || dst[0] != '/')
        return -1;
    in = fopen(src, "r");
    if (!in)
        goto out;
    snprintf(tmp, sizeof(tmp), "%s.tmp", dst);
    out = fopen(tmp, "w");
    if (!out)
        goto out;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n)
            goto out;
    }
    if (ferror(in))
        goto out;
    if (fflush(out) != 0)
        goto out;
    if (rename(tmp, dst) != 0)
        goto out;
    rc = 0;
out:
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int aegisxd_settings_update(const char *field, const char *value_s,
                                   int value_b, int use_bool)
{
    sqlite3_stmt *st;
    char sql[192];
    int rc;

    if (!field || !field[0])
        return -1;
    if (strcmp(field, "enabled") && strcmp(field, "mode") &&
        strcmp(field, "source_level") && strcmp(field, "suricata_version") &&
        strcmp(field, "default_action") && strcmp(field, "logging_enabled") &&
        strcmp(field, "suricata_interface") &&
        strcmp(field, "suricata_queue_num") &&
        strcmp(field, "suricata_fail_open"))
        return -1;
    snprintf(sql, sizeof(sql), "UPDATE aegis_settings SET %s=?1,updated_at=?2 WHERE id=1", field);
    st = aegisxd_config_prepare(sql);
    if (!st)
        return -1;
    if (use_bool)
        sqlite3_bind_int(st, 1, value_b);
    else
        sqlite3_bind_text(st, 1, value_s ? value_s : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int aegisxd_mode_ok(const char *mode)
{
    return mode && (!strcmp(mode, "off") || !strcmp(mode, "monitor") ||
                    !strcmp(mode, "protect") || !strcmp(mode, "dns_filter"));
}

static int aegisxd_suricata_interface_syntax_ok(const char *ifname)
{
    const unsigned char *p = (const unsigned char *)ifname;

    if (!ifname || !ifname[0] || strlen(ifname) >= IFNAMSIZ)
        return 0;
    for (; *p; p++) {
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.')
            return 0;
    }
    return 1;
}

static int aegisxd_suricata_interface_runtime_ok(const char *ifname)
{
    return aegisxd_suricata_interface_syntax_ok(ifname) &&
           if_nametoindex(ifname) != 0;
}

struct json_object *aegisxd_set_enabled(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    int enabled = aegisxd_json_bool(body, "enabled", 0);
    int rc = aegisxd_settings_update("enabled", NULL, enabled, 1);

    json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(resp, "changed", json_object_new_boolean(rc == 0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "enabled", json_object_new_boolean(enabled));
    aegisxd_json_add_string(resp, "operation", "set_enabled");
    if (rc != 0)
        aegisxd_json_add_string(resp, "error", "settings_update_failed");
    return resp;
}

struct json_object *aegisxd_set_mode(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct aegisxd_settings current;
    const char *mode;
    const char *ifname = NULL;
    struct json_object *v = NULL;
    int queue_num = 0;
    int fail_open = 1;
    int has_ifname = 0;
    int has_queue = 0;
    int has_fail_open = 0;
    int rc = -1;

    memset(&current, 0, sizeof(current));
    if (aegisxd_settings_load(&current) != 0) {
        aegisxd_json_add_string(resp, "error", "settings_unavailable");
        mode = "off";
        goto out;
    }
    mode = aegisxd_json_str(body, "mode", current.mode);
    if (body && json_object_object_get_ex(body, "suricata_interface", &v)) {
        has_ifname = 1;
        if (!v || !json_object_is_type(v, json_type_string))
            goto invalid;
        ifname = json_object_get_string(v);
        if (ifname[0] && !aegisxd_suricata_interface_syntax_ok(ifname))
            goto invalid;
    }
    if (body && json_object_object_get_ex(body, "suricata_queue_num", &v)) {
        has_queue = 1;
        if (!v || !json_object_is_type(v, json_type_int))
            goto invalid;
        queue_num = json_object_get_int(v);
        if (queue_num < 0 || queue_num > 65535)
            goto invalid;
    }
    if (body && json_object_object_get_ex(body, "suricata_fail_open", &v)) {
        has_fail_open = 1;
        if (!v || !json_object_is_type(v, json_type_boolean))
            goto invalid;
        fail_open = json_object_get_boolean(v) ? 1 : 0;
    }
    if (!aegisxd_mode_ok(mode))
        goto invalid;
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        goto out;
    if (aegisxd_settings_update("mode", mode, 0, 0) != 0 ||
        (has_ifname && aegisxd_settings_update("suricata_interface", ifname, 0, 0) != 0) ||
        (has_queue && aegisxd_settings_update("suricata_queue_num", NULL, queue_num, 1) != 0) ||
        (has_fail_open && aegisxd_settings_update("suricata_fail_open", NULL, fail_open, 1) != 0)) {
        sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
        goto out;
    }
    if (sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
        goto out;
    }
    rc = 0;
    goto out;
invalid:
    aegisxd_json_add_string(resp, "error", "invalid_suricata_runtime_settings");
out:
    json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(resp, "changed", json_object_new_boolean(rc == 0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    aegisxd_json_add_string(resp, "operation", "set_mode");
    aegisxd_json_add_string(resp, "mode", mode);
    if (has_ifname)
        aegisxd_json_add_string(resp, "suricata_interface", ifname ? ifname : "");
    if (has_queue)
        json_object_object_add(resp, "suricata_queue_num", json_object_new_int(queue_num));
    if (has_fail_open)
        json_object_object_add(resp, "suricata_fail_open", json_object_new_boolean(fail_open));
    if (rc != 0 && !json_object_object_get(resp, "error"))
        aegisxd_json_add_string(resp, "error", aegisxd_mode_ok(mode) ? "settings_update_failed" : "invalid_mode");
    return resp;
}

struct json_object *aegisxd_set_profile(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    const char *source_level = aegisxd_json_str(body, "source_level", NULL);
    const char *default_action = aegisxd_json_str(body, "default_action", NULL);
    struct json_object *tmp = NULL;
    int logging_enabled = aegisxd_json_bool(body, "logging_enabled", 1);
    int ok = 1;
    int changed = 0;

    if (source_level && (!strcmp(source_level, "open") || !strcmp(source_level, "enhanced") ||
                         !strcmp(source_level, "custom"))) {
        if (aegisxd_settings_update("source_level", source_level, 0, 0) != 0)
            ok = 0;
        else
            changed = 1;
    }
    if (default_action && (!strcmp(default_action, "alert") || !strcmp(default_action, "block") ||
                           !strcmp(default_action, "drop") || !strcmp(default_action, "reject"))) {
        if (aegisxd_settings_update("default_action", default_action, 0, 0) != 0)
            ok = 0;
        else
            changed = 1;
    }
    if (body && json_object_object_get_ex(body, "logging_enabled", &tmp)) {
        if (aegisxd_settings_update("logging_enabled", NULL, logging_enabled, 1) != 0)
            ok = 0;
        else
            changed = 1;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "changed", json_object_new_boolean(ok && changed));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    aegisxd_json_add_string(resp, "operation", "set_profile");
    if (!ok)
        aegisxd_json_add_string(resp, "error", "settings_update_failed");
    return resp;
}

/*
 * Traffic-log collection scope and the three source toggles.
 *
 * Every field is optional and an omitted one stays unchanged, so the UI can
 * save a single control without resending the rest. An unknown scope is a hard
 * error rather than a silent fallback to "all": quietly widening collection
 * after the user asked for "blocked" would be the worse failure.
 */
struct json_object *aegisxd_set_traffic_log(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *sources = NULL, *tmp = NULL;
    const char *scope = aegisxd_json_str(body, "traffic_log_scope", NULL);
    int gateway_dns = -1, aegisx_service = -1, device_admin = -1;
    int rc;

    if (!scope)
        scope = aegisxd_json_str(body, "scope", NULL);
    /* Accept the toggles flat or nested, since the read side reports both. */
    if (body && json_object_object_get_ex(body, "traffic_log", &tmp) && tmp) {
        if (!scope)
            scope = aegisxd_json_str(tmp, "scope", NULL);
        json_object_object_get_ex(tmp, "sources", &sources);
    }
    if (!sources && body)
        json_object_object_get_ex(body, "traffic_log_sources", &sources);

    if (scope && !aegisxd_traffic_log_scope_valid(scope)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "operation", "set_traffic_log");
        aegisxd_json_add_string(resp, "error", "invalid_traffic_log_scope");
        aegisxd_json_add_string(resp, "expected", "all|blocked");
        return resp;
    }

    if (sources && json_object_is_type(sources, json_type_object)) {
        if (json_object_object_get_ex(sources, "gateway_dns", &tmp))
            gateway_dns = json_object_get_boolean(tmp) ? 1 : 0;
        if (json_object_object_get_ex(sources, "aegisx_service", &tmp))
            aegisx_service = json_object_get_boolean(tmp) ? 1 : 0;
        if (json_object_object_get_ex(sources, "device_admin", &tmp))
            device_admin = json_object_get_boolean(tmp) ? 1 : 0;
    }
    if (body) {
        if (json_object_object_get_ex(body, "traffic_log_gateway_dns", &tmp))
            gateway_dns = json_object_get_boolean(tmp) ? 1 : 0;
        if (json_object_object_get_ex(body, "traffic_log_aegisx_service", &tmp))
            aegisx_service = json_object_get_boolean(tmp) ? 1 : 0;
        if (json_object_object_get_ex(body, "traffic_log_device_admin", &tmp))
            device_admin = json_object_get_boolean(tmp) ? 1 : 0;
    }

    if (!scope && gateway_dns < 0 && aegisx_service < 0 && device_admin < 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        aegisxd_json_add_string(resp, "operation", "set_traffic_log");
        aegisxd_json_add_string(resp, "error", "no_traffic_log_fields");
        return resp;
    }

    rc = aegisxd_traffic_log_settings_save(scope, gateway_dns, aegisx_service,
                                           device_admin);
    json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(resp, "changed", json_object_new_boolean(rc == 0));
    /* Nothing here touches nftables or dnsmasq: it selects what the hit
     * producers persist, so the dataplane ruleset is untouched. */
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    aegisxd_json_add_string(resp, "operation", "set_traffic_log");
    if (rc == 0) {
        struct aegisxd_settings settings;

        /* Echo the stored state so the caller does not have to re-read status
         * to learn what the omitted fields ended up as. */
        if (aegisxd_settings_load(&settings) == 0) {
            struct json_object *stored = json_object_new_object();
            struct json_object *out = json_object_new_object();

            aegisxd_json_add_string(stored, "scope", settings.traffic_log_scope);
            json_object_object_add(out, "gateway_dns",
                                   json_object_new_boolean(settings.traffic_log_gateway_dns));
            json_object_object_add(out, "aegisx_service",
                                   json_object_new_boolean(settings.traffic_log_aegisx_service));
            json_object_object_add(out, "device_admin",
                                   json_object_new_boolean(settings.traffic_log_device_admin));
            json_object_object_add(stored, "sources", out);
            json_object_object_add(resp, "traffic_log", stored);
        }
        /* Existing rows are left alone; only later writes are filtered. */
        aegisxd_json_add_string(resp, "applies_to", "future_writes_only");
        json_object_object_add(resp, "history_rewritten",
                               json_object_new_boolean(0));
    } else {
        aegisxd_json_add_string(resp, "error",
                                rc == -2 ? "invalid_traffic_log_scope" :
                                           "settings_update_failed");
    }
    return resp;
}

static int aegisxd_plan_count_where(const char *table, const char *where)
{
    char sql[256];

    if (!table || !table[0])
        return -1;
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s%s%s",
             table, where && where[0] ? " WHERE " : "", where && where[0] ? where : "");
    return aegisxd_plan_count_sql(sql);
}

static int aegisxd_plan_domain_union_count(void)
{
    sqlite3_stmt *st = NULL;
    void *filter = aegisxd_content_filter_load();
    char last_counted[254] = "";
    int explicit_count = 0;
    int count = 0;

    if (!filter)
        return -1;
    st = aegisxd_prepare(
        "SELECT value,category,reputation FROM ("
        " SELECT domain AS value,category,0 AS reputation FROM aegis_domain_categories WHERE domain<>''"
        " UNION "
        " SELECT value,category,1 AS reputation FROM aegis_reputation_items WHERE kind='domain' AND value<>''"
        ") ORDER BY value");
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        const char *domain = aegisxd_sqlite_text(st, 0, "");

        if (!strcmp(domain, last_counted))
            continue;
        if (aegisxd_content_filter_domain_blocked(filter, domain,
                aegisxd_sqlite_text(st, 1, ""), sqlite3_column_int(st, 2))) {
            count++;
            snprintf(last_counted, sizeof(last_counted), "%s", domain);
        }
    }
    if (st)
        sqlite3_finalize(st);
    {
        FILE *sink = tmpfile();
        if (!sink)
            count = -1;
        else {
            explicit_count = aegisxd_content_filter_write_explicit_blocks(filter, sink);
            if (fclose(sink) != 0 || explicit_count < 0)
                count = -1;
            else
                count += explicit_count;
        }
    }
    aegisxd_content_filter_free(filter);
    return count;
}

static void aegisxd_plan_add_step(struct json_object *steps, const char *id,
                                  const char *state, const char *detail,
                                  int dataplane_changed)
{
    struct json_object *o;

    if (!steps)
        return;
    o = json_object_new_object();
    aegisxd_json_add_string(o, "id", id);
    aegisxd_json_add_string(o, "state", state);
    aegisxd_json_add_string(o, "detail", detail);
    json_object_object_add(o, "dataplane_changed", json_object_new_boolean(dataplane_changed));
    json_object_array_add(steps, o);
}

static void aegisxd_plan_add_blocker(struct json_object *arr, const char *code)
{
    if (arr && code && code[0])
        json_object_array_add(arr, json_object_new_string(code));
}

static void aegisxd_plan_add_warning(struct json_object *arr, const char *msg)
{
    if (arr && msg && msg[0])
        json_object_array_add(arr, json_object_new_string(msg));
}

static int aegisxd_plan_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

static int aegisxd_plan_write_json_atomic(const char *path, struct json_object *obj)
{
    char tmp[AEGISXD_MAX_PATH + 8];
    const char *s;
    FILE *fp;
    size_t len;
    int rc = -1;

    if (!path || !path[0] || !obj)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    len = s ? strlen(s) : 0;
    if (len == 0 || fwrite(s, 1, len, fp) != len)
        goto out;
    if (fputc('\n', fp) == EOF)
        goto out;
    if (fflush(fp) != 0)
        goto out;
    rc = 0;
out:
    fclose(fp);
    if (rc == 0) {
        if (rename(tmp, path) != 0)
            rc = -1;
    }
    if (rc != 0)
        unlink(tmp);
    return rc;
}

struct aegisxd_artifact_job {
    char id[96];
    int64_t ts;
};

static int aegisxd_plan_parse_job_id(const char *name, char *id, size_t id_len,
                                     int64_t *ts_out)
{
    const char *prefix = "aegis-compile-";
    const char *p;
    int64_t ts = 0;
    size_t n;

    if (!name || !id || id_len == 0 || strncmp(name, prefix, strlen(prefix)))
        return 0;
    p = name + strlen(prefix);
    if (!isdigit((unsigned char)*p))
        return 0;
    while (isdigit((unsigned char)*p)) {
        ts = ts * 10 + (*p - '0');
        p++;
    }
    if (*p != '.' && *p != '\0')
        return 0;
    n = (size_t)(p - name);
    if (n == 0 || n >= id_len)
        return 0;
    memcpy(id, name, n);
    id[n] = '\0';
    if (ts_out)
        *ts_out = ts;
    return 1;
}

static int aegisxd_plan_job_index(struct aegisxd_artifact_job *jobs, int count,
                                  const char *id)
{
    int i;

    for (i = 0; i < count; i++) {
        if (!strcmp(jobs[i].id, id))
            return i;
    }
    return -1;
}

static int aegisxd_plan_job_cmp_desc(const void *a, const void *b)
{
    const struct aegisxd_artifact_job *ja = a;
    const struct aegisxd_artifact_job *jb = b;

    if (ja->ts < jb->ts)
        return 1;
    if (ja->ts > jb->ts)
        return -1;
    return strcmp(jb->id, ja->id);
}

static int aegisxd_plan_job_keep(struct aegisxd_artifact_job *jobs, int count,
                                 const char *id, int keep)
{
    int i;

    if (keep < 1)
        keep = 1;
    for (i = 0; i < count && i < keep; i++) {
        if (!strcmp(jobs[i].id, id))
            return 1;
    }
    return 0;
}

static struct json_object *aegisxd_plan_cleanup_artifacts(int keep)
{
    struct json_object *o = json_object_new_object();
    DIR *dir;
    struct dirent *de;
    struct aegisxd_artifact_job jobs[128];
    int job_count = 0;
    int scanned = 0;
    int removed = 0;
    int failed = 0;

    if (keep < 1)
        keep = 1;
    if (keep > 32)
        keep = 32;
    dir = opendir(AEGISXD_RUNTIME_DIR);
    if (!dir) {
        json_object_object_add(o, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(o, "error", "runtime_dir_unavailable");
        json_object_object_add(o, "keep", json_object_new_int(keep));
        return o;
    }
    while ((de = readdir(dir)) != NULL) {
        char id[96];
        int64_t ts = 0;
        int idx;

        if (!aegisxd_plan_parse_job_id(de->d_name, id, sizeof(id), &ts))
            continue;
        scanned++;
        idx = aegisxd_plan_job_index(jobs, job_count, id);
        if (idx >= 0) {
            if (ts > jobs[idx].ts)
                jobs[idx].ts = ts;
            continue;
        }
        if (job_count >= (int)ARRAY_SIZE(jobs))
            continue;
        snprintf(jobs[job_count].id, sizeof(jobs[job_count].id), "%s", id);
        jobs[job_count].ts = ts;
        job_count++;
    }
    closedir(dir);
    qsort(jobs, (size_t)job_count, sizeof(jobs[0]), aegisxd_plan_job_cmp_desc);

    dir = opendir(AEGISXD_RUNTIME_DIR);
    if (!dir) {
        json_object_object_add(o, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(o, "error", "runtime_dir_unavailable");
        json_object_object_add(o, "keep", json_object_new_int(keep));
        return o;
    }
    while ((de = readdir(dir)) != NULL) {
        char id[96];
        char path[AEGISXD_MAX_PATH];
        int64_t ts = 0;

        if (!aegisxd_plan_parse_job_id(de->d_name, id, sizeof(id), &ts))
            continue;
        if (aegisxd_plan_job_keep(jobs, job_count, id, keep))
            continue;
        snprintf(path, sizeof(path), "%s/%s", AEGISXD_RUNTIME_DIR, de->d_name);
        if (unlink(path) == 0)
            removed++;
        else
            failed++;
    }
    closedir(dir);

    json_object_object_add(o, "ok", json_object_new_boolean(failed == 0));
    json_object_object_add(o, "keep", json_object_new_int(keep));
    json_object_object_add(o, "jobs_seen", json_object_new_int(job_count));
    json_object_object_add(o, "files_scanned", json_object_new_int(scanned));
    json_object_object_add(o, "files_removed", json_object_new_int(removed));
    json_object_object_add(o, "files_failed", json_object_new_int(failed));
    return o;
}

static int aegisxd_plan_value_domain_ok(const char *s)
{
    int dot = 0;
    size_t i;

    if (!s || !s[0] || strlen(s) > 253)
        return 0;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '.')
            dot = 1;
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.'))
            return 0;
    }
    return dot;
}

static int aegisxd_plan_value_ip_ok(const char *s)
{
    size_t i;

    if (!s || !s[0] || strlen(s) > 128)
        return 0;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (!(isxdigit(c) || c == '.' || c == ':' || c == '/'))
            return 0;
    }
    return 1;
}

static int aegisxd_ipv4_is_global_public(const struct in_addr *a)
{
    uint32_t v;

    if (!a)
        return 0;
    v = ntohl(a->s_addr);
    if ((v & 0xff000000U) == 0x00000000U)
        return 0;
    if ((v & 0xff000000U) == 0x0a000000U)
        return 0;
    if ((v & 0xff000000U) == 0x7f000000U)
        return 0;
    if ((v & 0xffc00000U) == 0x64400000U)
        return 0;
    if ((v & 0xffff0000U) == 0xa9fe0000U)
        return 0;
    if ((v & 0xfff00000U) == 0xac100000U)
        return 0;
    if ((v & 0xffff0000U) == 0xc0a80000U)
        return 0;
    if ((v & 0xffffff00U) == 0xc0000000U)
        return 0;
    if ((v & 0xffffff00U) == 0xc0000200U)
        return 0;
    if ((v & 0xffffff00U) == 0xc6336400U)
        return 0;
    if ((v & 0xffffff00U) == 0xcb007100U)
        return 0;
    if ((v & 0xf0000000U) == 0xe0000000U)
        return 0;
    if ((v & 0xf0000000U) == 0xf0000000U)
        return 0;
    return 1;
}

struct aegisxd_nft_ipv4_item {
    uint32_t addr;
    int prefix;
    char text[64];
};

static int aegisxd_nft_parse_ipv4_item(const char *s, struct aegisxd_nft_ipv4_item *out)
{
    char buf[128];
    char *slash;
    char *end = NULL;
    struct in_addr a4;
    long prefix = 32;

    if (!s || !out || !aegisxd_plan_value_ip_ok(s) || strchr(s, ':'))
        return 0;
    /* aegisxd_plan_value_ip_ok admits up to 128 characters, one more than buf
     * can hold with its NUL, so refuse the copy instead of parsing a silently
     * shortened address that would match a different network. */
    if (jmx_strbuf_copy(buf, sizeof(buf), s) != 0)
        return 0;
    slash = strchr(buf, '/');
    if (slash) {
        *slash++ = '\0';
        if (!*slash)
            return 0;
        prefix = strtol(slash, &end, 10);
        if (!end || *end || prefix < 1 || prefix > 32)
            return 0;
    }
    if (inet_pton(AF_INET, buf, &a4) != 1 || !aegisxd_ipv4_is_global_public(&a4))
        return 0;
    memset(out, 0, sizeof(*out));
    out->addr = ntohl(a4.s_addr);
    out->prefix = (int)prefix;
    snprintf(out->text, sizeof(out->text), "%s", s);
    return 1;
}

static uint32_t aegisxd_nft_ipv4_mask(int prefix)
{
    if (prefix <= 0)
        return 0;
    if (prefix >= 32)
        return UINT32_MAX;
    return UINT32_MAX << (32 - prefix);
}

static int aegisxd_nft_ipv4_cmp(const void *a, const void *b)
{
    const struct aegisxd_nft_ipv4_item *ia = a;
    const struct aegisxd_nft_ipv4_item *ib = b;

    if (ia->addr < ib->addr)
        return -1;
    if (ia->addr > ib->addr)
        return 1;
    if (ia->prefix < ib->prefix)
        return -1;
    if (ia->prefix > ib->prefix)
        return 1;
    return strcmp(ia->text, ib->text);
}

static int aegisxd_nft_ipv4_covered(const struct aegisxd_nft_ipv4_item *items,
                                    int count, const struct aegisxd_nft_ipv4_item *cur)
{
    int i;

    if (!items || !cur)
        return 0;
    for (i = 0; i < count; i++) {
        uint32_t mask;

        if (items[i].prefix > cur->prefix)
            continue;
        mask = aegisxd_nft_ipv4_mask(items[i].prefix);
        if ((items[i].addr & mask) == (cur->addr & mask))
            return 1;
    }
    return 0;
}

static int aegisxd_ipv6_is_global_public(const struct in6_addr *a)
{
    const unsigned char *b;

    if (!a)
        return 0;
    b = a->s6_addr;
    if (IN6_IS_ADDR_UNSPECIFIED(a) || IN6_IS_ADDR_LOOPBACK(a) ||
        IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_MULTICAST(a))
        return 0;
    if ((b[0] & 0xfe) == 0xfc)
        return 0;
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        return 0;
    return (b[0] & 0xe0) == 0x20;
}

static int aegisxd_plan_value_public_ip_ok(const char *s, int *family_out)
{
    char buf[128];
    char *slash;
    struct in_addr a4;
    struct in6_addr a6;

    if (family_out)
        *family_out = 0;
    if (!aegisxd_plan_value_ip_ok(s))
        return 0;
    /* Same 128-vs-128 boundary as aegisxd_nft_parse_ipv4_item: a truncated
     * address must not be treated as public. */
    if (jmx_strbuf_copy(buf, sizeof(buf), s) != 0)
        return 0;
    slash = strchr(buf, '/');
    if (slash)
        *slash = '\0';
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        if (family_out)
            *family_out = 4;
        return aegisxd_ipv4_is_global_public(&a4);
    }
    if (inet_pton(AF_INET6, buf, &a6) == 1) {
        if (family_out)
            *family_out = 6;
        return aegisxd_ipv6_is_global_public(&a6);
    }
    return 0;
}

static void aegisxd_plan_tsv_write_field(FILE *fp, const char *s)
{
    const char *p;

    if (!fp)
        return;
    for (p = s ? s : ""; *p; p++) {
        if (*p == '\t' || *p == '\r' || *p == '\n')
            fputc(' ', fp);
        else
            fputc(*p, fp);
    }
}

static int aegisxd_plan_writer_open(const char *path, char *tmp, size_t tmp_len, FILE **fp_out)
{
    FILE *fp;

    if (!path || !path[0] || !tmp || tmp_len == 0 || !fp_out)
        return -1;
    snprintf(tmp, tmp_len, "%s.tmp", path);
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    *fp_out = fp;
    return 0;
}

static int aegisxd_plan_writer_finish(const char *path, const char *tmp, FILE *fp, int ok)
{
    int rc = ok ? 0 : -1;

    if (fp) {
        if (fflush(fp) != 0)
            rc = -1;
        fclose(fp);
    }
    if (rc == 0) {
        if (rename(tmp, path) != 0)
            rc = -1;
    }
    if (rc != 0 && tmp)
        unlink(tmp);
    return rc;
}

static int aegisxd_plan_write_dnsmasq(const char *path, const char *job_id)
{
    sqlite3_stmt *st = NULL;
    FILE *fp = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];
    struct aegisxd_settings settings;
    int written = 0;
    int explicit_written = 0;
    int ok = 1;
    void *filter = NULL;
    char last_written[254] = "";

    if (aegisxd_plan_writer_open(path, tmp, sizeof(tmp), &fp) != 0)
        return -1;
    fprintf(fp, "# Generated by dreamingwrt-aegisxd compile plan\n");
    fprintf(fp, "# job_id=%s\n", job_id ? job_id : "");
    fprintf(fp, "# aegis-provenance-version=1\n");
    fprintf(fp, "# This artifact is not active until guarded apply installs it.\n");
    if ((aegisxd_settings_load(&settings) == 0 && settings.logging_enabled) ||
        aegisxd_pcdn_monitor_configured()) {
        fprintf(fp, "# DNS event work log; aegisxd stores only matched block or monitor events.\n");
        fprintf(fp, "log-facility=%s\n", AEGISXD_DNSMASQ_LOG_PATH);
        fprintf(fp, "log-queries=extra\n");
        fprintf(fp, "log-async=25\n");
    }
    filter = aegisxd_content_filter_load();
    if (!filter) {
        ok = 0;
        goto out;
    }
    st = aegisxd_prepare(
        "SELECT value,category,reputation FROM ("
        " SELECT domain AS value,category,0 AS reputation FROM aegis_domain_categories WHERE domain<>''"
        " UNION "
        " SELECT value,category,1 AS reputation FROM aegis_reputation_items WHERE kind='domain' AND value<>''"
        ") ORDER BY value");
    if (!st) {
        ok = 0;
        goto out;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *domain = aegisxd_sqlite_text(st, 0, "");
        const char *category = aegisxd_sqlite_text(st, 1, "");

        if (!strcmp(domain, last_written) || !aegisxd_plan_value_domain_ok(domain) ||
            aegisxd_content_filter_domain_explicitly_blocked(filter, domain) ||
            !aegisxd_content_filter_domain_blocked(filter, domain, category,
                                                    sqlite3_column_int(st, 2)))
            continue;
        fprintf(fp, "# aegis provenance=category source=domain_reputation domain=%s\n",
                domain);
        fprintf(fp, "address=/%s/0.0.0.0\n", domain);
        fprintf(fp, "address=/%s/::\n", domain);
        if (aegisxd_content_filter_mark_category_emitted(filter, domain) != 0) {
            ok = 0;
            goto out;
        }
        written++;
        snprintf(last_written, sizeof(last_written), "%s", domain);
    }
    sqlite3_finalize(st);
    st = NULL;
    explicit_written = aegisxd_content_filter_write_explicit_blocks(filter, fp);
    if (explicit_written < 0) {
        ok = 0;
        goto out;
    }
    written += explicit_written;
    {
        /*
         * Device- and time-scoped policies cannot be expressed as address=
         * rewrites, which apply to every client. They are emitted as nftset=
         * directives so dnsmasq records resolved addresses into per-policy sets
         * that the companion nft ruleset matches against the scoped MACs.
         */
        int scoped_written = aegisxd_content_filter_write_scoped_dnsmasq(filter, fp);

        if (scoped_written < 0) {
            ok = 0;
            goto out;
        }
        written += scoped_written;
    }
out:
    if (st)
        sqlite3_finalize(st);
    aegisxd_content_filter_free(filter);
    if (aegisxd_plan_writer_finish(path, tmp, fp, ok) != 0)
        return -1;
    return written;
}

/*
 * Companion artifact to the dnsmasq nftset= directives: the sets the resolver
 * fills, plus one reject rule per scoped policy and family. Returns the number
 * of rules written, or 0 when no policy is scoped (in which case no table is
 * emitted and apply tears down any stale one).
 */
static int aegisxd_plan_write_content_scope_nft(const char *path, const char *job_id)
{
    FILE *fp = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];
    void *filter = NULL;
    int rules = 0;
    int ok = 1;

    if (aegisxd_plan_writer_open(path, tmp, sizeof(tmp), &fp) != 0)
        return -1;
    fprintf(fp, "# Generated by dreamingwrt-aegisxd compile plan\n");
    fprintf(fp, "# job_id=%s\n", job_id ? job_id : "");
    fprintf(fp, "# Device- and schedule-scoped content policies.\n");
    fprintf(fp, "# This artifact is not active until guarded apply loads it.\n");
    filter = aegisxd_content_filter_load();
    if (!filter)
        ok = 0;
    else {
        rules = aegisxd_content_filter_write_scoped_nft(filter, fp);
        if (rules < 0)
            ok = 0;
    }
    aegisxd_content_filter_free(filter);
    if (aegisxd_plan_writer_finish(path, tmp, fp, ok) != 0)
        return -1;
    return rules;
}

static int aegisxd_plan_write_domain_index(const char *path, const char *job_id)
{
    sqlite3_stmt *st;
    FILE *fp = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];
    int written = 0;
    int ok = 1;

    if (aegisxd_plan_writer_open(path, tmp, sizeof(tmp), &fp) != 0)
        return -1;
    fprintf(fp, "# Generated by dreamingwrt-aegisxd compile plan\n");
    fprintf(fp, "# job_id=%s\n", job_id ? job_id : "");
    fprintf(fp, "kind\tvalue\tcategory\tseverity\tconfidence\tsource_feed\n");
    st = aegisxd_prepare(
        "SELECT kind,value,category,severity,confidence,source_feed "
        "FROM aegis_reputation_items "
        "WHERE (kind='domain' OR kind='url') AND value<>'' "
        "ORDER BY kind,value,source_feed");
    if (!st) {
        ok = 0;
        goto out;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *kind = aegisxd_sqlite_text(st, 0, "");
        const char *value = aegisxd_sqlite_text(st, 1, "");

        if (!strcmp(kind, "domain") && !aegisxd_plan_value_domain_ok(value))
            continue;
        aegisxd_plan_tsv_write_field(fp, kind);
        fputc('\t', fp);
        aegisxd_plan_tsv_write_field(fp, value);
        fputc('\t', fp);
        aegisxd_plan_tsv_write_field(fp, aegisxd_sqlite_text(st, 2, ""));
        fprintf(fp, "\t%d\t%d\t", sqlite3_column_int(st, 3), sqlite3_column_int(st, 4));
        aegisxd_plan_tsv_write_field(fp, aegisxd_sqlite_text(st, 5, ""));
        fputc('\n', fp);
        written++;
    }
    sqlite3_finalize(st);
out:
    if (aegisxd_plan_writer_finish(path, tmp, fp, ok) != 0)
        return -1;
    return written;
}

static int aegisxd_plan_write_nft_set(FILE *fp, const char *name, const char *type,
                                      const char *where, int *written_out)
{
    sqlite3_stmt *st;
    struct aegisxd_nft_ipv4_item *ipv4_items = NULL;
    int ipv4_count = 0;
    int ipv4_cap = 0;
    int first = 1;
    int written = 0;
    char sql[256];

    fprintf(fp, "  set %s {\n", name);
    fprintf(fp, "    type %s\n", type);
    fprintf(fp, "    flags interval\n");
    snprintf(sql, sizeof(sql),
             "SELECT DISTINCT value FROM aegis_reputation_items WHERE %s ORDER BY value",
             where ? where : "0");
    st = aegisxd_prepare(sql);
    if (!st)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *value = aegisxd_sqlite_text(st, 0, "");
        int family = 0;

        if (!aegisxd_plan_value_public_ip_ok(value, &family))
            continue;
        if (!strcmp(type, "ipv4_addr") && family != 4)
            continue;
        if (!strcmp(type, "ipv6_addr") && family != 6)
            continue;
        if (!strcmp(type, "ipv4_addr")) {
            struct aegisxd_nft_ipv4_item item;

            if (!aegisxd_nft_parse_ipv4_item(value, &item))
                continue;
            if (ipv4_count >= ipv4_cap) {
                int next_cap = ipv4_cap ? ipv4_cap * 2 : 512;
                struct aegisxd_nft_ipv4_item *next =
                    realloc(ipv4_items, (size_t)next_cap * sizeof(*next));

                if (!next) {
                    sqlite3_finalize(st);
                    free(ipv4_items);
                    return -1;
                }
                ipv4_items = next;
                ipv4_cap = next_cap;
            }
            ipv4_items[ipv4_count++] = item;
            continue;
        }
        if (first) {
            fprintf(fp, "    elements = { ");
            first = 0;
        } else {
            fprintf(fp, ", ");
        }
        fprintf(fp, "%s", value);
        written++;
    }
    sqlite3_finalize(st);
    if (!strcmp(type, "ipv4_addr") && ipv4_count > 0) {
        int kept = 0;
        int i;

        qsort(ipv4_items, (size_t)ipv4_count, sizeof(*ipv4_items),
              aegisxd_nft_ipv4_cmp);
        for (i = 0; i < ipv4_count; i++) {
            if (i > 0 && ipv4_items[i].addr == ipv4_items[i - 1].addr &&
                ipv4_items[i].prefix == ipv4_items[i - 1].prefix)
                continue;
            if (aegisxd_nft_ipv4_covered(ipv4_items, kept, &ipv4_items[i]))
                continue;
            if (first) {
                fprintf(fp, "    elements = { ");
                first = 0;
            } else {
                fprintf(fp, ", ");
            }
            fprintf(fp, "%s", ipv4_items[i].text);
            ipv4_items[kept++] = ipv4_items[i];
            written++;
        }
    }
    free(ipv4_items);
    if (!first)
        fprintf(fp, " }\n");
    fprintf(fp, "  }\n");
    if (written_out)
        *written_out = written;
    return 0;
}

static int aegisxd_plan_write_nft(const char *path, const char *job_id)
{
    FILE *fp = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];
    int v4 = 0;
    int v6 = 0;
    int ok = 1;

    if (aegisxd_plan_writer_open(path, tmp, sizeof(tmp), &fp) != 0)
        return -1;
    fprintf(fp, "# Generated by dreamingwrt-aegisxd compile plan\n");
    fprintf(fp, "# job_id=%s\n", job_id ? job_id : "");
    fprintf(fp, "# This artifact is not active until guarded apply loads it.\n");
    fprintf(fp, "table inet " AEGISXD_NFT_TABLE " {\n");
    if (aegisxd_plan_write_nft_set(fp, "reputation_ipv4", "ipv4_addr",
        "(kind='ip' OR kind='ipv4') AND value<>'' AND instr(value, ':')=0", &v4) != 0)
        ok = 0;
    if (aegisxd_plan_write_nft_set(fp, "reputation_ipv6", "ipv6_addr",
        "(kind='ipv6' OR kind='ip') AND value<>'' AND instr(value, ':')>0", &v6) != 0)
        ok = 0;
    fprintf(fp, "  chain prerouting {\n");
    fprintf(fp, "    type filter hook prerouting priority -151; policy accept;\n");
    fprintf(fp, "    ip saddr @reputation_ipv4 counter drop comment \"dreamingwrt-aegis reputation source ipv4\"\n");
    fprintf(fp, "    ip daddr @reputation_ipv4 counter drop comment \"dreamingwrt-aegis reputation destination ipv4\"\n");
    fprintf(fp, "    ip6 saddr @reputation_ipv6 counter drop comment \"dreamingwrt-aegis reputation source ipv6\"\n");
    fprintf(fp, "    ip6 daddr @reputation_ipv6 counter drop comment \"dreamingwrt-aegis reputation destination ipv6\"\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "  chain output {\n");
    fprintf(fp, "    type filter hook output priority -151; policy accept;\n");
    fprintf(fp, "    ip daddr @reputation_ipv4 counter drop comment \"dreamingwrt-aegis local reputation destination ipv4\"\n");
    fprintf(fp, "    ip6 daddr @reputation_ipv6 counter drop comment \"dreamingwrt-aegis local reputation destination ipv6\"\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    if (aegisxd_plan_writer_finish(path, tmp, fp, ok) != 0)
        return -1;
    return v4 + v6;
}

static int aegisxd_plan_write_suricata(const char *path, const char *job_id)
{
    sqlite3_stmt *st;
    FILE *fp = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];
    int written = 0;
    int ok = 1;
    const char *err = "";

    if (aegisxd_signature_policy_problem_count() > 0)
        return -1; /* stale/orphan override: signature_revision_mismatch fail closed */
    if (aegisxd_plan_writer_open(path, tmp, sizeof(tmp), &fp) != 0)
        return -1;
    fprintf(fp, "# Generated by dreamingwrt-aegisxd compile plan\n");
    fprintf(fp, "# job_id=%s\n", job_id ? job_id : "");
    fprintf(fp, "# Signature overrides are applied from config.db/%s at compile time.\n",
            "aegis_signature_policy_overrides");
    fprintf(fp, "# Suppressed or disabled signatures are intentionally omitted.\n");
    fprintf(fp, "# This artifact is not active until guarded apply starts Suricata.\n");
    st = aegisxd_prepare(
        "SELECT sid,rev,enabled_default,action,rule_text FROM aegis_suricata_rules "
        "WHERE rule_text<>'' ORDER BY sid");
    if (!st) {
        ok = 0;
        goto out;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        int sid = sqlite3_column_int(st, 0);
        int rev = sqlite3_column_int(st, 1);
        int enabled_default = sqlite3_column_int(st, 2) ? 1 : 0;
        const char *action = aegisxd_sqlite_text(st, 3, "alert");
        const char *rule = aegisxd_sqlite_text(st, 4, "");
        char effective[8192];
        int enabled = 0;

        if (aegisxd_signature_policy_effective_rule_text(1, sid, rev,
                enabled_default, action, rule, effective, sizeof(effective),
                &enabled, &err) != 0) {
            ok = 0;
            break;
        }
        if (!enabled || !effective[0])
            continue;
        fprintf(fp, "%s\n", effective);
        written++;
    }
    sqlite3_finalize(st);
out:
    if (!ok && err && err[0])
        fprintf(fp, "# compile failed closed: %s\n", err);
    if (aegisxd_plan_writer_finish(path, tmp, fp, ok) != 0)
        return -1;
    return ok ? written : -1;
}

static void aegisxd_plan_top_values(struct json_object *arr, const char *sql,
                                    const char *value_key)
{
    sqlite3_stmt *st;

    if (!arr || !sql)
        return;
    st = aegisxd_prepare(sql);
    if (!st)
        return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();

        aegisxd_json_add_string(o, value_key ? value_key : "value",
                                aegisxd_sqlite_text(st, 0, ""));
        aegisxd_json_add_string(o, "category", aegisxd_sqlite_text(st, 1, ""));
        aegisxd_json_add_string(o, "source_feed", aegisxd_sqlite_text(st, 2, ""));
        json_object_object_add(o, "severity", json_object_new_int(sqlite3_column_int(st, 3)));
        json_object_object_add(o, "confidence", json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
}

static void aegisxd_plan_feed_breakdown(struct json_object *arr, const char *sql)
{
    sqlite3_stmt *st;

    if (!arr || !sql)
        return;
    st = aegisxd_prepare(sql);
    if (!st)
        return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();

        aegisxd_json_add_string(o, "source_feed", aegisxd_sqlite_text(st, 0, ""));
        aegisxd_json_add_string(o, "category", aegisxd_sqlite_text(st, 1, ""));
        json_object_object_add(o, "count", json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
}

static void aegisxd_plan_artifact_json(struct json_object *artifacts, const char *key,
                                       const char *kind, const char *path,
                                       int planned_items, const char *executor,
                                       int apply_supported)
{
    struct json_object *o;

    if (!artifacts || !key)
        return;
    o = json_object_new_object();
    aegisxd_json_add_string(o, "kind", kind);
    aegisxd_json_add_string(o, "path", path);
    aegisxd_json_add_string(o, "executor", executor);
    json_object_object_add(o, "planned_items", json_object_new_int(planned_items < 0 ? 0 : planned_items));
    json_object_object_add(o, "write_supported", json_object_new_boolean(1));
    json_object_object_add(o, "apply_supported", json_object_new_boolean(apply_supported));
    json_object_object_add(o, "applied", json_object_new_boolean(0));
    json_object_object_add(o, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(artifacts, key, o);
}

static void aegisxd_plan_artifact_mark_written(struct json_object *artifacts, const char *key,
                                               int write_requested, int written_count)
{
    struct json_object *o = NULL;

    if (!artifacts || !key || !json_object_object_get_ex(artifacts, key, &o) || !o)
        return;
    json_object_object_add(o, "write_requested", json_object_new_boolean(write_requested));
    json_object_object_add(o, "written", json_object_new_boolean(write_requested && written_count >= 0));
    json_object_object_add(o, "written_items", json_object_new_int(written_count < 0 ? 0 : written_count));
    if (write_requested && written_count < 0)
        aegisxd_json_add_string(o, "write_error", "artifact_write_failed");
}

static const char *aegisxd_compile_scope_canonical(const char *scope)
{
    if (!scope || !scope[0] || !strcmp(scope, "all"))
        return "all";
    if (!strcmp(scope, "dns_filter") || !strcmp(scope, "dns") ||
        !strcmp(scope, "dnsmasq"))
        return "dns_filter";
    if (!strcmp(scope, "nft_reputation") || !strcmp(scope, "reputation") ||
        !strcmp(scope, "ip_reputation") || !strcmp(scope, "reputation_ip") ||
        !strcmp(scope, "nft"))
        return "nft_reputation";
    if (!strcmp(scope, "domain_reputation") || !strcmp(scope, "reputation_domain") ||
        !strcmp(scope, "domain_index") || !strcmp(scope, "resolver_policy"))
        return "domain_reputation";
    if (!strcmp(scope, "suricata") || !strcmp(scope, "ids") ||
        !strcmp(scope, "ips") || !strcmp(scope, "ids_ips"))
        return "suricata";
    return "";
}

static int aegisxd_compile_scope_selected(const char *scope, const char *artifact_scope)
{
    if (!scope || !scope[0] || !artifact_scope)
        return 0;
    if (!strcmp(scope, "all"))
        return 1;
    return !strcmp(scope, artifact_scope);
}

struct json_object *aegisxd_compile_plan(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *plan = json_object_new_object();
    struct json_object *inputs = json_object_new_object();
    struct json_object *settings = json_object_new_object();
    struct json_object *counts = json_object_new_object();
    struct json_object *artifacts = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *blockers = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *domain_breakdown = json_object_new_array();
    struct json_object *rep_breakdown = json_object_new_array();
    struct json_object *sample_domains = json_object_new_array();
    struct json_object *sample_ips = json_object_new_array();
    struct aegisxd_settings s;
    const char *requested_by;
    const char *scope_requested;
    const char *scope;
    int dry_run;
    int write_plan;
    int scope_supported;
    int write_dns;
    int write_nft;
    int write_domain_index;
    int write_suricata;
    int domain_categories;
    int reputation_items;
    int reputation_domains;
    int reputation_ips;
    int reputation_urls;
    int suricata_rules;
    int suricata_enabled;
    int blocklist_domains;
    int safe_search_google = 0;
    int safe_search_bing = 0;
    int safe_search_youtube = 0;
    int safe_search_policies = 0;
    int safe_search_providers = 0;
    int safe_search_rules = 0;
    int safe_search_ok;
    int ok = 1;
    int written = 0;
    int settings_ok;
    int artifact_write_failed = 0;
    int retention_keep;
    int dns_written = -1;
    int nft_written = -1;
    int content_scope_written = -1;
    int domain_index_written = -1;
    int suricata_written = -1;
    char job_id[96];
    char plan_path[AEGISXD_MAX_PATH];
    char dns_path[AEGISXD_MAX_PATH];
    char nft_path[AEGISXD_MAX_PATH];
    char content_scope_path[AEGISXD_MAX_PATH];
    int64_t now = aegisxd_now_s();

    if (!body || !json_object_is_type(body, json_type_object))
        body = NULL;
    dry_run = aegisxd_json_bool(body, "dry_run", 1);
    write_plan = aegisxd_json_bool(body, "write", 0);
    retention_keep = aegisxd_plan_json_int(body, "retention_keep", 6);
    requested_by = aegisxd_json_str(body, "requested_by", "api");
    scope_requested = aegisxd_json_str(body, "scope", "all");
    scope = aegisxd_compile_scope_canonical(scope_requested);
    scope_supported = scope[0] != 0;
    if (retention_keep <= 0)
        retention_keep = 6;
    if (retention_keep > 32)
        retention_keep = 32;

    snprintf(job_id, sizeof(job_id), "aegis-compile-%" PRId64, now);
    snprintf(plan_path, sizeof(plan_path), "%s/%s.json", AEGISXD_RUNTIME_DIR, job_id);
    snprintf(dns_path, sizeof(dns_path), "%s/%s.dnsmasq.conf", AEGISXD_RUNTIME_DIR, job_id);
    snprintf(nft_path, sizeof(nft_path), "%s/%s.nft", AEGISXD_RUNTIME_DIR, job_id);
    snprintf(content_scope_path, sizeof(content_scope_path),
             "%s/%s.content-scope.nft", AEGISXD_RUNTIME_DIR, job_id);
    char domain_index_path[AEGISXD_MAX_PATH];
    char suricata_path[AEGISXD_MAX_PATH];

    snprintf(domain_index_path, sizeof(domain_index_path), "%s/%s.domain-reputation.tsv",
             AEGISXD_RUNTIME_DIR, job_id);
    snprintf(suricata_path, sizeof(suricata_path), "%s/%s.suricata.rules",
             AEGISXD_RUNTIME_DIR, job_id);

    settings_ok = aegisxd_settings_load(&s) == 0;
    if (!settings_ok) {
        ok = 0;
        aegisxd_plan_add_blocker(blockers, "settings_unavailable");
        aegisxd_plan_add_warning(warnings, "aegis settings are unavailable; compile input state cannot be trusted");
    }
    if (!dry_run)
        aegisxd_plan_add_warning(warnings, "compile remains non-applying; use apply with confirm=true for guarded dns filter installation");
    if (!scope_supported) {
        ok = 0;
        aegisxd_plan_add_blocker(blockers, "unsupported_scope");
        aegisxd_plan_add_warning(warnings, "unknown compile scope; no artifacts will be written");
    }

    domain_categories = aegisxd_plan_count_where("aegis_domain_categories", NULL);
    reputation_items = aegisxd_plan_count_where("aegis_reputation_items", NULL);
    reputation_domains = aegisxd_plan_count_where("aegis_reputation_items", "kind='domain'");
    reputation_ips = aegisxd_plan_count_where("aegis_reputation_items", "kind='ip' OR kind='ipv4' OR kind='ipv6'");
    reputation_urls = aegisxd_plan_count_where("aegis_reputation_items", "kind='url'");
    suricata_rules = aegisxd_plan_count_where("aegis_suricata_rules", NULL);
    suricata_enabled = aegisxd_signature_policy_effective_enabled_count();
    blocklist_domains = aegisxd_plan_domain_union_count();
    safe_search_ok = aegisxd_content_safe_search_effective_values(
        &safe_search_google, &safe_search_bing, &safe_search_youtube,
        &safe_search_policies, &safe_search_providers, &safe_search_rules) == 0;

    if (domain_categories < 0 || reputation_items < 0 || suricata_rules < 0 ||
        blocklist_domains < 0 || !safe_search_ok) {
        ok = 0;
        aegisxd_plan_add_blocker(blockers, "aegis_db_inputs_unavailable");
    }
    if ((domain_categories <= 0 && reputation_items <= 0 && suricata_rules <= 0 &&
         safe_search_rules <= 0))
        aegisxd_plan_add_warning(warnings, "no imported aegis feeds are available; run feed update/import before compiling dataplane artifacts");

    aegisxd_plan_feed_breakdown(domain_breakdown,
        "SELECT source_feed,category,COUNT(*) FROM aegis_domain_categories "
        "GROUP BY source_feed,category ORDER BY COUNT(*) DESC,source_feed LIMIT 32");
    aegisxd_plan_feed_breakdown(rep_breakdown,
        "SELECT source_feed,category,COUNT(*) FROM aegis_reputation_items "
        "GROUP BY source_feed,category ORDER BY COUNT(*) DESC,source_feed LIMIT 32");
    aegisxd_plan_top_values(sample_domains,
        "SELECT value,category,source_feed,severity,confidence FROM aegis_reputation_items "
        "WHERE kind='domain' ORDER BY severity DESC,confidence DESC,value LIMIT 24",
        "domain");
    aegisxd_plan_top_values(sample_ips,
        "SELECT value,category,source_feed,severity,confidence FROM aegis_reputation_items "
        "WHERE kind='ip' OR kind='ipv4' OR kind='ipv6' ORDER BY severity DESC,confidence DESC,value LIMIT 24",
        "ip");

    aegisxd_plan_add_step(steps, "feed_import_check",
                          (domain_categories + reputation_items + suricata_rules) > 0 ? "ready" : "empty",
                          "Read imported Emerging Threats, URLhaus, OISD, StevenBlack, and compatible local feed tables", 0);
    aegisxd_plan_add_step(steps, "dns_filter_artifact",
                          (blocklist_domains + safe_search_rules) > 0 ? "compile-ready" : "idle",
                          "Plan the existing dnsmasq artifact from filtered domains and effective Safe Search providers; no resolver reload is performed", 0);
    aegisxd_plan_add_step(steps, "reputation_artifact",
                          (reputation_ips + reputation_domains + reputation_urls) > 0 ? "compile-ready" : "idle",
                          "Plan reputation indexes for DNS and nftables decisions; nft apply is guarded and only allowed when public IP reputation samples exist", 0);
    aegisxd_plan_add_step(steps, "suricata_ruleset",
                          suricata_enabled > 0 ? "compile-ready" : "idle",
                          "Plan Suricata IDS/IPS ruleset handoff; runtime apply remains guarded by binary/config/test checks", 0);
    aegisxd_plan_add_step(steps, "policy_hit_logging", "dns-filter-ready",
                          "DNS filter, nft aggregate counters, and Suricata EVE alerts can be exposed as policy hit events when their dataplanes are active", 0);
    aegisxd_plan_add_step(steps, "dns_filter_apply_executor", "guarded-ready",
                          "DNS filter can be installed into the current dnsmasq runtime include directory only through explicit apply confirm=true", 0);
    aegisxd_plan_add_step(steps, "nft_reputation_apply_executor",
                          reputation_ips > 0 ? "guarded-ready" : "blocked",
                          "nftables reputation sets can be installed into an isolated inet table only through explicit apply confirm=true", 0);
    if (aegisxd_compile_scope_selected(scope, "nft_reputation") &&
        reputation_ips <= 0)
        aegisxd_plan_add_blocker(blockers, "nft_reputation_ip_samples_missing");
    aegisxd_plan_add_step(steps, "suricata_apply_executor",
                          aegisxd_suricata_binary_path()[0] ? "guarded-ready" : "blocked",
                          aegisxd_suricata_binary_path()[0] ?
                          "Suricata runtime apply can render config, run suricata -T, and start only with explicit confirm=true" :
                          "Suricata rules are available, but the Suricata runtime binary is not installed", 0);
    if (aegisxd_compile_scope_selected(scope, "suricata")) {
        if (!aegisxd_suricata_binary_path()[0])
            aegisxd_plan_add_blocker(blockers, "suricata_runtime_missing");
    }

    aegisxd_plan_artifact_json(artifacts, "dnsmasq_domain_blocklist", "dns_filter", dns_path,
                               (blocklist_domains < 0 ? 0 : blocklist_domains) +
                               (safe_search_rules < 0 ? 0 : safe_search_rules),
                               "dnsmasq", 1);
    aegisxd_plan_artifact_json(artifacts, "nft_content_scope_rules", "dns_filter",
                               content_scope_path, 0, "nftables", 1);
    aegisxd_plan_artifact_json(artifacts, "nft_ip_reputation_sets", "reputation_ip", nft_path,
                               reputation_ips, "nftables", 1);
    aegisxd_plan_artifact_json(artifacts, "domain_reputation_index", "reputation_domain",
                               domain_index_path,
                               reputation_domains + reputation_urls, "resolver_policy", 0);
    aegisxd_plan_artifact_json(artifacts, "suricata_ruleset", "ids_ips", suricata_path,
                               suricata_enabled,
                               "suricata", 1);
    {
        struct json_object *suricata_art = NULL;

        if (json_object_object_get_ex(artifacts, "suricata_ruleset", &suricata_art) &&
            suricata_art) {
            const char *bin = aegisxd_suricata_binary_path();

            json_object_object_add(suricata_art, "runtime_available",
                                   json_object_new_boolean(bin[0] != 0));
            aegisxd_json_add_string(suricata_art, "runtime_binary", bin);
            json_object_object_add(suricata_art, "config_available",
                                   json_object_new_boolean(aegisxd_suricata_config_available()));
            aegisxd_json_add_string(suricata_art, "config_path", AEGISXD_SURICATA_CONFIG_PATH);
            aegisxd_json_add_string(suricata_art, "apply_reason",
                                    bin[0] ? "suricata_guarded_apply_ready" :
                                    "suricata_runtime_missing");
            aegisxd_json_add_string(suricata_art, "eve_path", AEGISXD_SURICATA_EVE_PATH);
        }
    }

    json_object_object_add(settings, "available", json_object_new_boolean(settings_ok));
    json_object_object_add(settings, "enabled", json_object_new_boolean(settings_ok ? s.enabled : 0));
    aegisxd_json_add_string(settings, "mode", settings_ok ? s.mode : "off");
    aegisxd_json_add_string(settings, "default_action", settings_ok ? s.default_action : "alert");
    aegisxd_json_add_string(settings, "source_level", settings_ok ? s.source_level : "open");
    json_object_object_add(settings, "logging_enabled", json_object_new_boolean(settings_ok ? s.logging_enabled : 0));
    aegisxd_json_add_string(settings, "suricata_interface",
                            settings_ok ? s.suricata_interface : "");
    json_object_object_add(settings, "suricata_queue_num",
                           json_object_new_int(settings_ok ? s.suricata_queue_num : 0));
    json_object_object_add(settings, "suricata_fail_open",
                           json_object_new_boolean(settings_ok ? s.suricata_fail_open : 1));

    json_object_object_add(counts, "domain_categories", json_object_new_int(domain_categories < 0 ? 0 : domain_categories));
    json_object_object_add(counts, "blocklist_domains", json_object_new_int(blocklist_domains < 0 ? 0 : blocklist_domains));
    json_object_object_add(counts, "safe_search_active_policies",
                           json_object_new_int(safe_search_policies));
    json_object_object_add(counts, "safe_search_providers",
                           json_object_new_int(safe_search_providers));
    json_object_object_add(counts, "safe_search_rules",
                           json_object_new_int(safe_search_rules));
    json_object_object_add(counts, "reputation_items", json_object_new_int(reputation_items < 0 ? 0 : reputation_items));
    json_object_object_add(counts, "reputation_domains", json_object_new_int(reputation_domains < 0 ? 0 : reputation_domains));
    json_object_object_add(counts, "reputation_ips", json_object_new_int(reputation_ips < 0 ? 0 : reputation_ips));
    json_object_object_add(counts, "reputation_urls", json_object_new_int(reputation_urls < 0 ? 0 : reputation_urls));
    json_object_object_add(counts, "suricata_rules", json_object_new_int(suricata_rules < 0 ? 0 : suricata_rules));
    json_object_object_add(counts, "suricata_enabled_rules", json_object_new_int(suricata_enabled < 0 ? 0 : suricata_enabled));
    json_object_object_add(counts, "signature_policy_overrides", aegisxd_signature_policy_counts_json());

    json_object_object_add(inputs, "settings", settings);
    json_object_object_add(inputs, "counts", counts);
    json_object_object_add(inputs, "domain_breakdown", domain_breakdown);
    json_object_object_add(inputs, "reputation_breakdown", rep_breakdown);
    json_object_object_add(inputs, "sample_domain_reputation", sample_domains);
    json_object_object_add(inputs, "sample_ip_reputation", sample_ips);
    {
        struct json_object *safe_search = json_object_new_object();
        struct json_object *providers = json_object_new_object();
        struct json_object *enabled_providers = json_object_new_array();

        json_object_object_add(providers, "google",
                               json_object_new_boolean(safe_search_google));
        json_object_object_add(providers, "bing",
                               json_object_new_boolean(safe_search_bing));
        json_object_object_add(providers, "youtube",
                               json_object_new_boolean(safe_search_youtube));
        if (safe_search_google)
            json_object_array_add(enabled_providers, json_object_new_string("google"));
        if (safe_search_bing)
            json_object_array_add(enabled_providers, json_object_new_string("bing"));
        if (safe_search_youtube)
            json_object_array_add(enabled_providers, json_object_new_string("youtube"));
        json_object_object_add(safe_search, "providers", providers);
        json_object_object_add(safe_search, "enabled_providers", enabled_providers);
        json_object_object_add(safe_search, "provider_count",
                               json_object_new_int(safe_search_providers));
        json_object_object_add(safe_search, "rule_count",
                               json_object_new_int(safe_search_rules));
        json_object_object_add(safe_search, "active_policy_count",
                               json_object_new_int(safe_search_policies));
        aegisxd_json_add_string(safe_search, "merge", "logical_or");
        aegisxd_json_add_string(safe_search, "artifact", "dnsmasq_domain_blocklist");
        json_object_object_add(inputs, "safe_search", safe_search);
    }

    json_object_object_add(plan, "version", json_object_new_int(AEGISXD_SCHEMA_VERSION));
    aegisxd_json_add_string(plan, "kind", "aegisxd-compile");
    aegisxd_json_add_string(plan, "job_id", job_id);
    json_object_object_add(plan, "generated_at", json_object_new_int64(now));
    aegisxd_json_add_string(plan, "requested_by", requested_by);
    aegisxd_json_add_string(plan, "scope", scope_supported ? scope : scope_requested);
    aegisxd_json_add_string(plan, "effective_scope", scope_supported ? scope : "");
    if (strcmp(scope_requested, scope_supported ? scope : ""))
        aegisxd_json_add_string(plan, "requested_scope", scope_requested);
    json_object_object_add(plan, "scope_supported", json_object_new_boolean(scope_supported));
    json_object_object_add(plan, "dry_run", json_object_new_boolean(1));
    json_object_object_add(plan, "applies_dataplane", json_object_new_boolean(0));
    json_object_object_add(plan, "dataplane_changed", json_object_new_boolean(0));
    aegisxd_json_add_string(plan, "note", "compile-only plan; no live dataplane was changed. DNS filter and nft reputation apply are guarded and require confirm=true");
    json_object_object_add(plan, "artifacts", artifacts);
    json_object_object_add(plan, "inputs", inputs);
    json_object_object_add(plan, "steps", steps);
    json_object_object_add(plan, "blockers", blockers);
    json_object_object_add(plan, "warnings", warnings);

    write_dns = write_plan && scope_supported &&
        aegisxd_compile_scope_selected(scope, "dns_filter");
    write_nft = write_plan && scope_supported &&
        aegisxd_compile_scope_selected(scope, "nft_reputation");
    write_domain_index = write_plan && scope_supported &&
        aegisxd_compile_scope_selected(scope, "domain_reputation");
    write_suricata = write_plan && scope_supported &&
        aegisxd_compile_scope_selected(scope, "suricata");

    if (write_plan) {
        if (aegisxd_mkdir_p(AEGISXD_RUNTIME_DIR, 0755) != 0) {
            ok = 0;
            artifact_write_failed = 1;
        } else {
            if (write_dns)
                dns_written = aegisxd_plan_write_dnsmasq(dns_path, job_id);
            /*
             * Scoped rules ride with the dns_filter scope: the nft sets are
             * useless without the nftset= directives that fill them, so the two
             * artifacts are always produced together.
             */
            if (write_dns)
                content_scope_written =
                    aegisxd_plan_write_content_scope_nft(content_scope_path, job_id);
            if (write_nft)
                nft_written = aegisxd_plan_write_nft(nft_path, job_id);
            if (write_domain_index)
                domain_index_written = aegisxd_plan_write_domain_index(domain_index_path, job_id);
            if (write_suricata)
                suricata_written = aegisxd_plan_write_suricata(suricata_path, job_id);
            if ((write_dns && dns_written < 0) ||
                (write_dns && content_scope_written < 0) ||
                (write_nft && nft_written < 0) ||
                (write_domain_index && domain_index_written < 0) ||
                (write_suricata && suricata_written < 0)) {
                ok = 0;
                artifact_write_failed = 1;
            }
        }
        aegisxd_plan_artifact_mark_written(artifacts, "dnsmasq_domain_blocklist", write_dns, dns_written);
        aegisxd_plan_artifact_mark_written(artifacts, "nft_content_scope_rules", write_dns,
                                           content_scope_written);
        aegisxd_plan_artifact_mark_written(artifacts, "nft_ip_reputation_sets", write_nft, nft_written);
        aegisxd_plan_artifact_mark_written(artifacts, "domain_reputation_index", write_domain_index, domain_index_written);
        aegisxd_plan_artifact_mark_written(artifacts, "suricata_ruleset", write_suricata, suricata_written);
        if (artifact_write_failed)
            aegisxd_plan_add_blocker(blockers, "artifact_write_failed");
        json_object_object_add(plan, "retention", aegisxd_plan_cleanup_artifacts(retention_keep));
        if (!artifact_write_failed && aegisxd_plan_write_json_atomic(plan_path, plan) == 0) {
            written = 1;
        } else {
            ok = 0;
        }
    } else {
        aegisxd_plan_artifact_mark_written(artifacts, "dnsmasq_domain_blocklist", 0, -1);
        aegisxd_plan_artifact_mark_written(artifacts, "nft_content_scope_rules", 0, -1);
        aegisxd_plan_artifact_mark_written(artifacts, "nft_ip_reputation_sets", 0, -1);
        aegisxd_plan_artifact_mark_written(artifacts, "domain_reputation_index", 0, -1);
        aegisxd_plan_artifact_mark_written(artifacts, "suricata_ruleset", 0, -1);
        json_object_object_add(plan, "retention", json_object_new_null());
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "compiled", json_object_new_boolean(ok));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
    json_object_object_add(resp, "write_requested", json_object_new_boolean(write_plan));
    json_object_object_add(resp, "written", json_object_new_boolean(written));
    aegisxd_json_add_string(resp, "plan_path", write_plan ? plan_path : "");
    aegisxd_json_add_string(resp, "state", ok ? "compiled" : "failed");
    if (!ok)
        aegisxd_json_add_string(resp, "error", "compile_inputs_unavailable");
    json_object_object_add(resp, "plan", plan);
    return resp;
}

static struct json_object *aegisxd_apply_state_json(const char *state, const char *mode,
                                                    const char *scope,
                                                    const char *dns_dir,
                                                    const char *dns_file,
                                                    const char *nft_table,
                                                    const char *nft_file,
                                                    const char *job_id,
                                                    int rules)
{
    struct json_object *o = json_object_new_object();
    struct json_object *safe_search = NULL;
    struct json_object *providers = NULL;
    struct json_object *enabled_providers = NULL;
    int google = 0, bing = 0, youtube = 0;
    int policies = 0, provider_count = 0, rule_count = 0;
    int safe_ok = aegisxd_content_safe_search_effective_values(
        &google, &bing, &youtube, &policies, &provider_count, &rule_count) == 0;

    aegisxd_json_add_string(o, "state", state);
    aegisxd_json_add_string(o, "mode", mode);
    aegisxd_json_add_string(o, "scope", scope ? scope : "");
    aegisxd_json_add_string(o, "dnsmasq_conf_dir", dns_dir);
    aegisxd_json_add_string(o, "dnsmasq_conf_file", dns_file);
    aegisxd_json_add_string(o, "nft_table", nft_table);
    aegisxd_json_add_string(o, "nft_file", nft_file);
    aegisxd_json_add_string(o, "job_id", job_id);
    json_object_object_add(o, "rules", json_object_new_int(rules < 0 ? 0 : rules));
    if (scope && aegisxd_compile_scope_selected(scope, "dns_filter")) {
        json_object_object_add(o, "content_revision",
                               json_object_new_int(aegisxd_content_revision_get()));
        safe_search = json_object_new_object();
        providers = json_object_new_object();
        enabled_providers = json_object_new_array();
        json_object_object_add(providers, "google",
                               json_object_new_boolean(safe_ok && google));
        json_object_object_add(providers, "bing",
                               json_object_new_boolean(safe_ok && bing));
        json_object_object_add(providers, "youtube",
                               json_object_new_boolean(safe_ok && youtube));
        if (safe_ok && google)
            json_object_array_add(enabled_providers, json_object_new_string("google"));
        if (safe_ok && bing)
            json_object_array_add(enabled_providers, json_object_new_string("bing"));
        if (safe_ok && youtube)
            json_object_array_add(enabled_providers, json_object_new_string("youtube"));
        json_object_object_add(safe_search, "providers", providers);
        json_object_object_add(safe_search, "enabled_providers", enabled_providers);
        json_object_object_add(safe_search, "provider_count",
                               json_object_new_int(safe_ok ? provider_count : 0));
        json_object_object_add(safe_search, "rule_count",
                               json_object_new_int(safe_ok ? rule_count : 0));
        json_object_object_add(safe_search, "active_policy_count",
                               json_object_new_int(safe_ok ? policies : 0));
        json_object_object_add(safe_search, "configuration_valid",
                               json_object_new_boolean(safe_ok));
        aegisxd_json_add_string(safe_search, "merge", "logical_or");
        aegisxd_json_add_string(safe_search, "artifact", "dnsmasq_domain_blocklist");
        json_object_object_add(o, "safe_search", safe_search);
        {
            struct json_object *pcdn = aegisxd_pcdn_active_state_json();
            const char *pcdn_mode = aegisxd_json_str(pcdn, "mode", "block");
            int pcdn_effective = aegisxd_pcdn_effective_rule_count(dns_file);

            json_object_object_add(pcdn, "effective_rule_count",
                                   json_object_new_int(pcdn_effective));
            json_object_object_add(pcdn, "blocking", json_object_new_boolean(
                aegisxd_json_bool(pcdn, "enabled", 0) && !strcmp(pcdn_mode, "block") &&
                pcdn_effective > 0));
            json_object_object_add(pcdn, "monitoring", json_object_new_boolean(
                aegisxd_json_bool(pcdn, "enabled", 0) && !strcmp(pcdn_mode, "monitor")));
            json_object_object_add(o, "pcdn", pcdn);
        }
    }
    json_object_object_add(o, "updated_at", json_object_new_int64(aegisxd_now_s()));
    return o;
}

static int aegisxd_apply_write_state_path(const char *path, struct json_object *state)
{
    return aegisxd_plan_write_json_atomic(path, state);
}

static int aegisxd_apply_write_state(struct json_object *state)
{
    char path[AEGISXD_MAX_PATH];

    snprintf(path, sizeof(path), "%s/active.json", AEGISXD_RUNTIME_DIR);
    return aegisxd_apply_write_state_path(path, state);
}

static int aegisxd_apply_count_dns_rules(const char *path)
{
    FILE *fp;
    char line[512];
    char last_host[256] = "";
    int n = 0;

    if (!path || !path[0])
        return 0;
    fp = fopen(path, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strncmp(line, "address=/", 9)) {
            const char *start = line + 9;
            const char *end = strchr(start, '/');
            size_t len = end ? (size_t)(end - start) : 0;

            if (!len || len >= sizeof(last_host))
                continue;
            if (strlen(last_host) == len && !strncmp(last_host, start, len))
                continue;
            memcpy(last_host, start, len);
            last_host[len] = '\0';
            n++;
        }
    }
    fclose(fp);
    return n;
}

static int aegisxd_apply_count_nft_elements(const char *path)
{
    FILE *fp;
    char line[1024];
    int n = 0;
    int in_elements = 0;

    if (!path || !path[0])
        return 0;
    fp = fopen(path, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;

        if (strstr(line, "elements = {"))
            in_elements = 1;
        if (!in_elements)
            continue;
        while ((p = strchr(p, ',')) != NULL) {
            n++;
            p++;
        }
        if (strchr(line, '}')) {
            if (strstr(line, "elements = {") && !strstr(line, "{ }"))
                n++;
            in_elements = 0;
        }
    }
    fclose(fp);
    return n;
}

static int aegisxd_nft_table_active(void)
{
    return aegisxd_dataplane_run_quiet_log(
        "nft list table inet " AEGISXD_NFT_TABLE " >/dev/null 2>&1",
        AEGISXD_NFT_LOG) == 0;
}

static int aegisxd_nft_delete_table(void)
{
    return aegisxd_dataplane_run_quiet_log(
        "nft delete table inet " AEGISXD_NFT_TABLE " >/dev/null 2>&1 || true",
        AEGISXD_NFT_LOG);
}

static int aegisxd_nft_delete_content_scope_table(void)
{
    return aegisxd_dataplane_run_quiet_log(
        "nft delete table inet " AEGISXD_CONTENT_NFT_TABLE " >/dev/null 2>&1 || true",
        AEGISXD_NFT_LOG);
}

static int aegisxd_nft_check_file(const char *path)
{
    char cmd[AEGISXD_MAX_PATH + 128];

    if (!path || path[0] != '/' || access(path, R_OK) != 0)
        return -1;
    snprintf(cmd, sizeof(cmd), "nft -c -f '%s'", path);
    return aegisxd_dataplane_run_quiet_log(cmd, AEGISXD_NFT_LOG);
}

static int aegisxd_nft_apply_file(const char *path)
{
    char cmd[AEGISXD_MAX_PATH + 128];

    if (!path || path[0] != '/' || access(path, R_OK) != 0)
        return -1;
    snprintf(cmd, sizeof(cmd), "nft -f '%s'", path);
    return aegisxd_dataplane_run_quiet_log(cmd, AEGISXD_NFT_LOG);
}

static int aegisxd_suricata_count_rules(const char *path)
{
    FILE *fp;
    char line[1024];
    int n = 0;

    if (!path || !path[0])
        return 0;
    fp = fopen(path, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;

        while (*p && isspace((unsigned char)*p))
            p++;
        if (*p == '#' || !*p)
            continue;
        if (strchr(p, '(') && strchr(p, ')'))
            n++;
    }
    fclose(fp);
    return n;
}

static int aegisxd_suricata_write_config(const char *rules_path,
                                         const struct aegisxd_settings *settings)
{
    FILE *fp = NULL;
    char tmp[AEGISXD_MAX_PATH + 8];

    if (!rules_path || rules_path[0] != '/' || access(rules_path, R_OK) != 0)
        return -1;
    if (aegisxd_mkdir_p(AEGISXD_SURICATA_LOG_DIR, 0755) != 0)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", AEGISXD_SURICATA_CONFIG_PATH);
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    fprintf(fp, "%%YAML 1.1\n---\n");
    fprintf(fp, "vars:\n");
    fprintf(fp, "  address-groups:\n");
    fprintf(fp, "    HOME_NET: \"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,fc00::/7]\"\n");
    fprintf(fp, "    EXTERNAL_NET: \"!$HOME_NET\"\n");
    fprintf(fp, "  port-groups:\n");
    fprintf(fp, "    HTTP_PORTS: \"80\"\n");
    fprintf(fp, "default-rule-path: %s\n", AEGISXD_RUNTIME_DIR);
    fprintf(fp, "rule-files:\n");
    fprintf(fp, "  - %s\n", strrchr(rules_path, '/') ? strrchr(rules_path, '/') + 1 : rules_path);
    fprintf(fp, "classification-file: /etc/suricata/classification.config\n");
    fprintf(fp, "reference-config-file: /etc/suricata/reference.config\n");
    fprintf(fp, "default-log-dir: %s\n", AEGISXD_SURICATA_LOG_DIR);
    fprintf(fp, "stats:\n");
    fprintf(fp, "  enabled: yes\n");
    fprintf(fp, "outputs:\n");
    fprintf(fp, "  - eve-log:\n");
    fprintf(fp, "      enabled: yes\n");
    fprintf(fp, "      filetype: regular\n");
    fprintf(fp, "      filename: %s\n", AEGISXD_SURICATA_EVE_PATH);
    fprintf(fp, "      types:\n");
    fprintf(fp, "        - alert\n");
    fprintf(fp, "        - drop\n");
    fprintf(fp, "        - flow\n");
    fprintf(fp, "logging:\n");
    fprintf(fp, "  default-log-level: notice\n");
    if (settings && !strcmp(settings->mode, "monitor")) {
        fprintf(fp, "af-packet:\n");
        fprintf(fp, "  - interface: %s\n", settings->suricata_interface);
        fprintf(fp, "    cluster-id: 99\n");
        fprintf(fp, "    cluster-type: cluster_flow\n");
        fprintf(fp, "    defrag: yes\n");
    }
    fprintf(fp, "app-layer:\n");
    fprintf(fp, "  protocols:\n");
    fprintf(fp, "    tls:\n");
    fprintf(fp, "      enabled: yes\n");
    fprintf(fp, "    http:\n");
    fprintf(fp, "      enabled: yes\n");
    fprintf(fp, "dreamingwrt:\n");
    fprintf(fp, "  generated_by: dreamingwrt-aegisxd\n");
    fprintf(fp, "  mode: %s\n", settings && settings->mode[0] ?
            settings->mode : "monitor");
    fprintf(fp, "  capture-interface: %s\n",
            settings ? settings->suricata_interface : "");
    fprintf(fp, "  nfqueue: %d\n", settings ? settings->suricata_queue_num : 0);
    fprintf(fp, "  fail-open: %s\n",
            !settings || settings->suricata_fail_open ? "yes" : "no");
    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp);
        return -1;
    }
    fclose(fp);
    if (rename(tmp, AEGISXD_SURICATA_CONFIG_PATH) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int aegisxd_suricata_test_config(const char *bin)
{
    char cmd[AEGISXD_MAX_PATH + 256];

    if (!bin || !bin[0] || access(bin, X_OK) != 0 ||
        access(AEGISXD_SURICATA_CONFIG_PATH, R_OK) != 0)
        return -1;
    snprintf(cmd, sizeof(cmd), "'%s' -T -c '%s'", bin, AEGISXD_SURICATA_CONFIG_PATH);
    return aegisxd_dataplane_run_quiet_log(cmd, AEGISXD_SURICATA_LOG);
}

static pid_t aegisxd_suricata_pid(void)
{
    FILE *fp;
    long value = 0;

    fp = fopen(AEGISXD_SURICATA_PID_PATH, "r");
    if (!fp)
        return 0;
    if (fscanf(fp, "%ld", &value) != 1)
        value = 0;
    fclose(fp);
    if (value <= 1 || value > INT_MAX)
        return 0;
    return (pid_t)value;
}

static int aegisxd_suricata_pid_running(void)
{
    pid_t pid = aegisxd_suricata_pid();
    char path[64];
    char exe[AEGISXD_MAX_PATH];
    const char *base;
    ssize_t n;

    if (pid <= 1 || (kill(pid, 0) != 0 && errno != EPERM))
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    n = readlink(path, exe, sizeof(exe) - 1);
    if (n <= 0 || (size_t)n >= sizeof(exe) - 1)
        return 0;
    exe[n] = '\0';
    base = strrchr(exe, '/');
    base = base ? base + 1 : exe;
    return !strcmp(base, "suricata");
}

static int aegisxd_suricata_stop(void)
{
    pid_t pid = aegisxd_suricata_pid();
    int i;

    if (pid <= 1) {
        unlink(AEGISXD_SURICATA_PID_PATH);
        return 0;
    }
    if (kill(pid, SIGTERM) != 0 && errno != ESRCH)
        return -1;
    for (i = 0; i < 20; i++) {
        if (kill(pid, 0) != 0 && errno == ESRCH)
            break;
        usleep(100000);
    }
    if (i == 20 && kill(pid, SIGKILL) != 0 && errno != ESRCH)
        return -1;
    unlink(AEGISXD_SURICATA_PID_PATH);
    return 0;
}

int aegisxd_suricata_nfqueue_runtime_active(void)
{
    return aegisxd_dataplane_run_quiet_log(
        "nft list table inet " AEGISXD_SURICATA_NFQ_TABLE " >/dev/null 2>&1",
        AEGISXD_SURICATA_LOG) == 0;
}

static int aegisxd_suricata_nfqueue_delete(void)
{
    if (!aegisxd_suricata_nfqueue_runtime_active())
        return 0;
    return aegisxd_dataplane_run_quiet_log(
        "nft delete table inet " AEGISXD_SURICATA_NFQ_TABLE,
        AEGISXD_SURICATA_LOG);
}

static int aegisxd_suricata_nfqueue_write(const struct aegisxd_settings *settings)
{
    FILE *fp;
    char tmp[AEGISXD_MAX_PATH + 8];

    if (!settings || strcmp(settings->mode, "protect") ||
        settings->suricata_queue_num < 0 || settings->suricata_queue_num > 65535)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", AEGISXD_SURICATA_NFQ_PATH);
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    fprintf(fp, "# owned-by=dreamingwrt-aegisxd scope=suricata-nfqueue\n");
    fprintf(fp, "table inet %s {\n", AEGISXD_SURICATA_NFQ_TABLE);
    fprintf(fp, " chain forward {\n");
    fprintf(fp, "  type filter hook forward priority -10; policy accept;\n");
    fprintf(fp, "  counter queue num %d%s\n", settings->suricata_queue_num,
            settings->suricata_fail_open ? " bypass" : "");
    fprintf(fp, " }\n}\n");
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, AEGISXD_SURICATA_NFQ_PATH) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int aegisxd_suricata_nfqueue_check(void)
{
    char cmd[AEGISXD_MAX_PATH + 64];

    snprintf(cmd, sizeof(cmd), "nft -c -f '%s'", AEGISXD_SURICATA_NFQ_PATH);
    return aegisxd_dataplane_run_quiet_log(cmd, AEGISXD_SURICATA_LOG);
}

static int aegisxd_suricata_nfqueue_apply(void)
{
    char cmd[AEGISXD_MAX_PATH + 64];

    snprintf(cmd, sizeof(cmd), "nft -f '%s'", AEGISXD_SURICATA_NFQ_PATH);
    return aegisxd_dataplane_run_quiet_log(cmd, AEGISXD_SURICATA_LOG);
}

static int aegisxd_suricata_start(const char *bin,
                                  const struct aegisxd_settings *settings)
{
    char cmd[AEGISXD_MAX_PATH + IFNAMSIZ + 512];
    int rc;
    int i;

    if (!settings || !bin || !bin[0] || access(bin, X_OK) != 0 ||
        access(AEGISXD_SURICATA_CONFIG_PATH, R_OK) != 0)
        return -1;
    if (!strcmp(settings->mode, "monitor")) {
        if (!aegisxd_suricata_interface_runtime_ok(settings->suricata_interface))
            return -1;
    } else if (strcmp(settings->mode, "protect") ||
               settings->suricata_queue_num < 0 || settings->suricata_queue_num > 65535) {
        return -1;
    }
    snprintf(cmd, sizeof(cmd),
             "mkdir -p '%s' && rm -f '%s' && "
             "'%s' -D -c '%s' --pidfile '%s' %s%s",
             AEGISXD_SURICATA_LOG_DIR, AEGISXD_SURICATA_EVE_PATH,
             bin, AEGISXD_SURICATA_CONFIG_PATH, AEGISXD_SURICATA_PID_PATH,
             !strcmp(settings->mode, "monitor") ? "--af-packet=" : "-q ",
             !strcmp(settings->mode, "monitor") ? settings->suricata_interface : "0");
    if (!strcmp(settings->mode, "protect"))
        snprintf(cmd, sizeof(cmd),
                 "mkdir -p '%s' && rm -f '%s' && "
                 "'%s' -D -c '%s' --pidfile '%s' -q %d",
                 AEGISXD_SURICATA_LOG_DIR, AEGISXD_SURICATA_EVE_PATH,
                 bin, AEGISXD_SURICATA_CONFIG_PATH, AEGISXD_SURICATA_PID_PATH,
                 settings->suricata_queue_num);
    rc = aegisxd_dataplane_run_quiet_log(cmd, AEGISXD_SURICATA_LOG);
    if (rc != 0)
        return rc;
    for (i = 0; i < AEGISXD_SURICATA_START_WAIT_STEPS; i++) {
        if (aegisxd_suricata_pid_running() &&
            access(AEGISXD_SURICATA_EVE_PATH, R_OK) == 0)
            return 0;
        usleep(AEGISXD_SURICATA_START_WAIT_US);
    }
    return -1;
}

static int aegisxd_suricata_settings_from_active(struct json_object *state,
                                                  struct aegisxd_settings *settings)
{
    const char *mode;
    struct json_object *value = NULL;

    if (!state || !settings || !json_object_is_type(state, json_type_object))
        return -1;
    memset(settings, 0, sizeof(*settings));
    mode = aegisxd_json_str(state, "mode", "");
    if (strcmp(mode, "monitor") && strcmp(mode, "protect"))
        return -1;
    snprintf(settings->mode, sizeof(settings->mode), "%s", mode);
    snprintf(settings->suricata_interface, sizeof(settings->suricata_interface), "%s",
             aegisxd_json_str(state, "suricata_interface", ""));
    settings->suricata_queue_num = 0;
    settings->suricata_fail_open = 1;
    if (json_object_object_get_ex(state, "suricata_queue_num", &value) && value &&
        json_object_is_type(value, json_type_int))
        settings->suricata_queue_num = json_object_get_int(value);
    if (json_object_object_get_ex(state, "suricata_fail_open", &value) && value &&
        json_object_is_type(value, json_type_boolean))
        settings->suricata_fail_open = json_object_get_boolean(value) ? 1 : 0;
    if (!strcmp(settings->mode, "monitor") &&
        !aegisxd_suricata_interface_runtime_ok(settings->suricata_interface))
        return -1;
    if (!strcmp(settings->mode, "protect") &&
        (settings->suricata_queue_num < 0 || settings->suricata_queue_num > 65535))
        return -1;
    return 0;
}

static int aegisxd_suricata_restore_previous(const char *bin,
                                              struct json_object *previous_state)
{
    struct aegisxd_settings previous;
    int rc;

    if (aegisxd_suricata_settings_from_active(previous_state, &previous) != 0)
        return -1;
    rc = aegisxd_suricata_start(bin, &previous);
    if (rc != 0)
        return -1;
    if (!strcmp(previous.mode, "protect")) {
        if (aegisxd_suricata_nfqueue_write(&previous) != 0 ||
            aegisxd_suricata_nfqueue_check() != 0 ||
            aegisxd_suricata_nfqueue_apply() != 0 ||
            !aegisxd_suricata_nfqueue_runtime_active()) {
            (void)aegisxd_suricata_nfqueue_delete();
            (void)aegisxd_suricata_stop();
            return -1;
        }
    }
    return 0;
}

static int aegisxd_suricata_restore_file(const char *backup_path,
                                         const char *active_path,
                                         int previous_saved)
{
    int rc = 0;

    if (previous_saved)
        rc = aegisxd_file_copy_atomic(backup_path, active_path);
    else if (unlink(active_path) != 0 && errno != ENOENT)
        rc = -1;
    unlink(backup_path);
    return rc;
}

static void aegisxd_apply_add_capabilities(struct json_object *resp)
{
    struct json_object *cap = json_object_new_object();

    json_object_object_add(cap, "preview", json_object_new_boolean(1));
    json_object_object_add(cap, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "safe_search_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "safe_search_dnsmasq_artifact", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "safe_search_providers", "google,bing,youtube");
    json_object_object_add(cap, "dnsmasq_restart_required", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_public_ip_only", json_object_new_boolean(1));
    json_object_object_add(cap, "nft_reputation_table", json_object_new_string(AEGISXD_NFT_TABLE));
    json_object_object_add(cap, "suricata_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_compile_plan", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_signature_policy", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_signature_suppress", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_config_render", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_test_config", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_af_packet_monitor", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_nfqueue_protect", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_runtime_readback", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_runtime_available",
                           json_object_new_boolean(aegisxd_suricata_binary_path()[0] != 0));
    aegisxd_json_add_string(cap, "suricata_binary", aegisxd_suricata_binary_path());
    json_object_object_add(cap, "suricata_config_available",
                           json_object_new_boolean(aegisxd_suricata_config_available()));
    aegisxd_json_add_string(cap, "suricata_config_path", AEGISXD_SURICATA_CONFIG_PATH);
    json_object_object_add(cap, "policy_hit_logging", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_hit_logging", json_object_new_boolean(1));
    json_object_object_add(cap, "dns_filter_hit_log_work_file", json_object_new_boolean(1));
    json_object_object_add(cap, "suricata_eve_hit_producer", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "suricata_eve_path", AEGISXD_SURICATA_EVE_PATH);
    json_object_object_add(resp, "capabilities", cap);
}

static void aegisxd_apply_add_blocker(struct json_object *arr, const char *code)
{
    if (arr && code && code[0])
        json_object_array_add(arr, json_object_new_string(code));
}

static int aegisxd_apply_find_dnsmasq_dir(char *out, size_t out_len)
{
    DIR *dir;
    struct dirent *de;

    if (!out || out_len == 0)
        return -1;
    out[0] = 0;
    dir = opendir("/tmp");
    if (!dir)
        return -1;
    while ((de = readdir(dir)) != NULL) {
        char path[AEGISXD_MAX_PATH];
        struct stat st;
        int n;

        if (strncmp(de->d_name, "dnsmasq.", 8) || !strstr(de->d_name, ".d"))
            continue;
        n = snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        if ((size_t)n >= out_len) {
            closedir(dir);
            return -1;
        }
        snprintf(out, out_len, "%s", path);
        closedir(dir);
        return 0;
    }
    closedir(dir);
    return -1;
}

static int aegisxd_apply_join_path(char *out, size_t out_len,
                                   const char *dir, const char *name)
{
    int n;

    if (!out || out_len == 0 || !dir || !dir[0] || !name || !name[0])
        return -1;
    n = snprintf(out, out_len, "%s/%s", dir, name);
    return n > 0 && (size_t)n < out_len ? 0 : -1;
}

static struct json_object *aegisxd_apply_disable(struct json_object *body,
                                                 const char *operation)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *blockers = json_object_new_array();
    char dns_dir[AEGISXD_MAX_PATH] = "";
    char dns_file[AEGISXD_MAX_PATH] = "";
    char dns_previous[AEGISXD_MAX_PATH] = "";
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int existed = 0;
    int ok = 1;
    int reload_rc = 0;
    int previous_saved = 0;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "operation", operation ? operation : "disable");
    json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
    if (aegisxd_apply_find_dnsmasq_dir(dns_dir, sizeof(dns_dir)) == 0) {
        if (aegisxd_apply_join_path(dns_file, sizeof(dns_file), dns_dir,
                                    AEGISXD_DNSMASQ_ACTIVE_FILE) != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "dnsmasq_conf_path_too_long");
        }
    } else {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "dnsmasq_conf_dir_not_found");
    }
    existed = dns_file[0] && access(dns_file, F_OK) == 0;
    json_object_object_add(resp, "would_remove", json_object_new_boolean(existed));
    aegisxd_json_add_string(resp, "dnsmasq_conf_dir", dns_dir);
    aegisxd_json_add_string(resp, "dnsmasq_conf_file", dns_file);
    if (!confirm) {
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        json_object_object_add(resp, "blockers", blockers);
        aegisxd_apply_add_capabilities(resp);
        return resp;
    }
    if (existed) {
        snprintf(dns_previous, sizeof(dns_previous),
                 "%s/dnsmasq-disable-previous.conf", AEGISXD_RUNTIME_DIR);
        if (aegisxd_file_copy_atomic(dns_file, dns_previous) != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "backup_dnsmasq_artifact_failed");
        } else {
            previous_saved = 1;
        }
    }
    if (ok && dns_file[0] && existed && unlink(dns_file) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "remove_dnsmasq_conf_failed");
    }
    if (ok && dns_dir[0] && (reload_rc = aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD)) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "dnsmasq_reload_failed");
        if (previous_saved && aegisxd_file_copy_atomic(dns_previous, dns_file) == 0) {
            int rollback_rc = aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD);
            json_object_object_add(resp, "rollback_ok",
                                   json_object_new_boolean(rollback_rc == 0));
            json_object_object_add(resp, "rollback_reload_exit_status",
                                   json_object_new_int(rollback_rc));
        } else {
            json_object_object_add(resp, "rollback_ok", json_object_new_boolean(0));
        }
    }
    if (ok) {
        char active_path[AEGISXD_MAX_PATH];

        snprintf(active_path, sizeof(active_path), "%s/active.json", AEGISXD_RUNTIME_DIR);
        if (unlink(active_path) != 0 && errno != ENOENT) {
            int rollback_rc = -1;

            ok = 0;
            aegisxd_apply_add_blocker(blockers, "active_state_remove_failed");
            if (previous_saved &&
                aegisxd_file_copy_atomic(dns_previous, dns_file) == 0)
                rollback_rc = aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD);
            json_object_object_add(resp, "rollback_ok",
                                   json_object_new_boolean(rollback_rc == 0));
            json_object_object_add(resp, "rollback_reload_exit_status",
                                   json_object_new_int(rollback_rc));
        }
    }
    if (previous_saved)
        unlink(dns_previous);
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "reload_exit_status", json_object_new_int(reload_rc));
    json_object_object_add(resp, "changed", json_object_new_boolean(ok && existed));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(ok && existed));
    json_object_object_add(resp, "blockers", blockers);
    if (!ok)
        aegisxd_json_add_string(resp, "error", "dns_filter_disable_failed");
    aegisxd_apply_add_capabilities(resp);
    return resp;
}

static struct json_object *aegisxd_apply_nft_rollback(struct json_object *body,
                                                      const char *operation)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *blockers = json_object_new_array();
    char active_path[AEGISXD_MAX_PATH];
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int active = aegisxd_nft_table_active();
    int rc = 0;

    snprintf(active_path, sizeof(active_path), "%s", AEGISXD_NFT_ACTIVE_FILE);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "operation", operation ? operation : "rollback");
    aegisxd_json_add_string(resp, "scope", "nft_reputation");
    json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "would_remove", json_object_new_boolean(active));
    json_object_object_add(resp, "nft_table_active", json_object_new_boolean(active));
    aegisxd_json_add_string(resp, "nft_table", AEGISXD_NFT_TABLE);
    aegisxd_json_add_string(resp, "active_state_path", active_path);
    if (!confirm) {
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        json_object_object_add(resp, "blockers", blockers);
        aegisxd_apply_add_capabilities(resp);
        return resp;
    }
    rc = aegisxd_nft_delete_table();
    if (rc == 0)
        unlink(active_path);
    else
        aegisxd_apply_add_blocker(blockers, "nft_delete_table_failed");
    json_object_object_add(resp, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(resp, "changed", json_object_new_boolean(rc == 0 && active));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(rc == 0 && active));
    json_object_object_add(resp, "nft_exit_status", json_object_new_int(rc));
    aegisxd_json_add_string(resp, "nft_log", AEGISXD_NFT_LOG);
    json_object_object_add(resp, "blockers", blockers);
    if (rc != 0)
        aegisxd_json_add_string(resp, "error", "nft_reputation_rollback_failed");
    aegisxd_apply_add_capabilities(resp);
    return resp;
}

static struct json_object *aegisxd_apply_nft_reputation(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *compile_req = json_object_new_object();
    struct json_object *compile = NULL;
    struct json_object *plan = NULL;
    struct json_object *artifacts = NULL;
    struct json_object *nft_art = NULL;
    struct json_object *blockers = json_object_new_array();
    struct aegisxd_settings s;
    const char *nft_src = "";
    const char *job_id = "";
    char active_path[AEGISXD_MAX_PATH];
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int force = aegisxd_json_bool(body, "force", 0);
    int rules = 0;
    int ok = 1;
    int check_rc = -1;
    int apply_rc = 0;

    snprintf(active_path, sizeof(active_path), "%s", AEGISXD_NFT_ACTIVE_FILE);
    json_object_object_add(compile_req, "write", json_object_new_boolean(1));
    json_object_object_add(compile_req, "dry_run", json_object_new_boolean(1));
    json_object_object_add(compile_req, "retention_keep",
                           json_object_new_int(aegisxd_plan_json_int(body, "retention_keep", 6)));
    aegisxd_json_add_string(compile_req, "requested_by", aegisxd_json_str(body, "requested_by", "nft_apply"));
    aegisxd_json_add_string(compile_req, "scope", "nft_reputation");
    compile = aegisxd_compile_plan(compile_req);
    json_object_object_add(resp, "compile", compile);

    if (aegisxd_settings_load(&s) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "settings_unavailable");
    }
    if (!force && (!s.enabled || !strcmp(s.mode, "off"))) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "aegis_not_enabled");
    }
    if (compile &&
        json_object_object_get_ex(compile, "plan", &plan) &&
        plan &&
        json_object_object_get_ex(plan, "job_id", &artifacts))
        job_id = json_object_get_string(artifacts);
    artifacts = NULL;
    if (plan &&
        json_object_object_get_ex(plan, "artifacts", &artifacts) &&
        artifacts &&
        json_object_object_get_ex(artifacts, "nft_ip_reputation_sets", &nft_art) &&
        nft_art) {
        nft_src = aegisxd_json_str(nft_art, "path", "");
        rules = aegisxd_plan_json_int(nft_art, "written_items", 0);
    }
    if (!nft_src || !nft_src[0] || access(nft_src, R_OK) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "nft_artifact_unavailable");
    }
    if (rules <= 0) {
        int counted = aegisxd_apply_count_nft_elements(nft_src);

        if (counted > 0)
            rules = counted;
    }
    if (rules <= 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "nft_reputation_rules_empty");
    }
    if (ok) {
        check_rc = aegisxd_nft_check_file(nft_src);
        if (check_rc != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "nft_check_failed");
        }
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(resp, "operation", "apply");
    aegisxd_json_add_string(resp, "scope", "nft_reputation");
    json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    json_object_object_add(resp, "rules", json_object_new_int(rules));
    aegisxd_json_add_string(resp, "nft_table", AEGISXD_NFT_TABLE);
    aegisxd_json_add_string(resp, "nft_artifact", nft_src);
    aegisxd_json_add_string(resp, "nft_log", AEGISXD_NFT_LOG);
    aegisxd_json_add_string(resp, "active_state_path", active_path);
    aegisxd_json_add_string(resp, "job_id", job_id);
    json_object_object_add(resp, "nft_check_exit_status", json_object_new_int(check_rc));
    json_object_object_add(resp, "blockers", blockers);
    aegisxd_apply_add_capabilities(resp);

    if (!ok) {
        aegisxd_json_add_string(resp, "state", "blocked");
        aegisxd_json_add_string(resp, "error", "nft_reputation_apply_blocked");
        json_object_put(compile_req);
        return resp;
    }
    if (!confirm) {
        aegisxd_json_add_string(resp, "state", "preview");
        json_object_put(compile_req);
        return resp;
    }
    (void)aegisxd_nft_delete_table();
    apply_rc = aegisxd_nft_apply_file(nft_src);
    if (apply_rc != 0) {
        (void)aegisxd_nft_delete_table();
        aegisxd_json_add_string(resp, "state", "rolled_back");
        aegisxd_json_add_string(resp, "error", "nft_apply_failed");
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "nft_exit_status", json_object_new_int(apply_rc));
        json_object_put(compile_req);
        return resp;
    }
    {
        struct json_object *state = aegisxd_apply_state_json("enabled", s.mode,
                                                             "nft_reputation",
                                                             "", "", AEGISXD_NFT_TABLE,
                                                             nft_src, job_id, rules);

        (void)aegisxd_apply_write_state_path(active_path, state);
        json_object_put(state);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "nft_exit_status", json_object_new_int(apply_rc));
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(1));
    json_object_object_add(resp, "applied", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "state", "applied");
    json_object_put(compile_req);
    return resp;
}

static struct json_object *aegisxd_apply_suricata(struct json_object *body,
                                                  const char *operation)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *compile_req = json_object_new_object();
    struct json_object *compile = NULL;
    struct json_object *plan = NULL;
    struct json_object *artifacts = NULL;
    struct json_object *suricata_art = NULL;
    struct json_object *blockers = json_object_new_array();
    const char *suricata_src = "";
    const char *job_id = "";
    const char *bin = aegisxd_suricata_binary_path();
    struct aegisxd_settings s;
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int force = aegisxd_json_bool(body, "force", 0);
    int rules = 0;
    int ok = 1;
    int config_rc = -1;
    int test_rc = -1;
    int start_rc = -1;
    int stop_rc = 0;
    int nfq_check_rc = -1;
    int nfq_apply_rc = -1;
    int nfq_active = 0;
    int write_ruleset = 0;
    int previous_runtime_active = 0;
    int previous_config_saved = 0;
    int previous_nfq_saved = 0;
    int config_changed = 0;
    int nfq_changed = 0;
    int restore_rc = -1;
    char previous_config[AEGISXD_MAX_PATH];
    char previous_nfq[AEGISXD_MAX_PATH];
    struct json_object *previous_state = NULL;

    memset(&s, 0, sizeof(s));
    snprintf(previous_config, sizeof(previous_config), "%s.previous",
             AEGISXD_SURICATA_CONFIG_PATH);
    snprintf(previous_nfq, sizeof(previous_nfq), "%s.previous",
             AEGISXD_SURICATA_NFQ_PATH);

    if (!operation || !operation[0])
        operation = "apply";
    if (!strcmp(operation, "rollback") || !strcmp(operation, "disable") ||
        !strcmp(operation, "clear")) {
        int active = aegisxd_suricata_active();
        int queue_active = aegisxd_suricata_nfqueue_runtime_active();

        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        aegisxd_json_add_string(resp, "operation", operation);
        aegisxd_json_add_string(resp, "scope", "suricata");
        json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
        json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
        json_object_object_add(resp, "would_stop", json_object_new_boolean(active));
        json_object_object_add(resp, "suricata_active", json_object_new_boolean(active));
        json_object_object_add(resp, "nfqueue_active", json_object_new_boolean(queue_active));
        aegisxd_json_add_string(resp, "active_state_path", AEGISXD_SURICATA_ACTIVE_PATH);
        aegisxd_json_add_string(resp, "pid_path", AEGISXD_SURICATA_PID_PATH);
        aegisxd_json_add_string(resp, "suricata_log", AEGISXD_SURICATA_LOG);
        if (!confirm) {
            json_object_object_add(resp, "changed", json_object_new_boolean(0));
            json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
            json_object_object_add(resp, "blockers", blockers);
            aegisxd_apply_add_capabilities(resp);
            json_object_put(compile_req);
            return resp;
        }
        stop_rc = aegisxd_suricata_stop();
        nfq_apply_rc = aegisxd_suricata_nfqueue_delete();
        if (stop_rc == 0 && nfq_apply_rc == 0) {
            unlink(AEGISXD_SURICATA_ACTIVE_PATH);
            unlink(AEGISXD_SURICATA_NFQ_PATH);
        } else {
            ok = 0;
            if (stop_rc != 0)
                aegisxd_apply_add_blocker(blockers, "suricata_stop_failed");
            if (nfq_apply_rc != 0)
                aegisxd_apply_add_blocker(blockers, "suricata_nfqueue_remove_failed");
        }
        json_object_object_add(resp, "ok", json_object_new_boolean(ok));
        json_object_object_add(resp, "changed", json_object_new_boolean(ok && (active || queue_active)));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(ok && (active || queue_active)));
        json_object_object_add(resp, "suricata_stop_exit_status", json_object_new_int(stop_rc));
        json_object_object_add(resp, "nfqueue_remove_exit_status", json_object_new_int(nfq_apply_rc));
        json_object_object_add(resp, "blockers", blockers);
        if (!ok)
            aegisxd_json_add_string(resp, "error", "suricata_rollback_failed");
        aegisxd_apply_add_capabilities(resp);
        json_object_put(compile_req);
        return resp;
    }

    json_object_object_add(compile_req, "write", json_object_new_boolean(0));
    json_object_object_add(compile_req, "dry_run", json_object_new_boolean(1));
    json_object_object_add(compile_req, "retention_keep",
                           json_object_new_int(aegisxd_plan_json_int(body, "retention_keep", 6)));
    aegisxd_json_add_string(compile_req, "requested_by", aegisxd_json_str(body, "requested_by", "suricata_apply"));
    aegisxd_json_add_string(compile_req, "scope", "suricata");
    compile = aegisxd_compile_plan(compile_req);
    json_object_object_add(resp, "compile", compile);

    if (compile &&
        json_object_object_get_ex(compile, "plan", &plan) &&
        plan &&
        json_object_object_get_ex(plan, "job_id", &artifacts))
        job_id = json_object_get_string(artifacts);
    artifacts = NULL;
    if (plan &&
        json_object_object_get_ex(plan, "artifacts", &artifacts) &&
        artifacts &&
        json_object_object_get_ex(artifacts, "suricata_ruleset", &suricata_art) &&
        suricata_art) {
        suricata_src = aegisxd_json_str(suricata_art, "path", "");
        rules = aegisxd_plan_json_int(suricata_art, "written_items", 0);
        if (rules <= 0)
            rules = aegisxd_plan_json_int(suricata_art, "planned_items", 0);
    }

    if (aegisxd_settings_load(&s) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "settings_unavailable");
    }
    if (!force && (!s.enabled || !strcmp(s.mode, "off"))) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "aegis_not_enabled");
    }
    if (rules <= 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "suricata_rules_empty");
    }
    if (!bin[0]) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "suricata_runtime_missing");
    }
    if (ok && strcmp(s.mode, "monitor") && strcmp(s.mode, "protect")) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "suricata_capture_mode_not_configured");
    }
    if (ok && !strcmp(s.mode, "monitor") &&
        !aegisxd_suricata_interface_runtime_ok(s.suricata_interface)) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers,
            s.suricata_interface[0] ? "suricata_capture_interface_unavailable" :
                                      "suricata_capture_interface_missing");
    }
    if (ok && !strcmp(s.mode, "protect") &&
        (s.suricata_queue_num < 0 || s.suricata_queue_num > 65535)) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "suricata_nfqueue_invalid");
    }
    if (ok && bin[0]) {
        json_object_put(compile_req);
        compile_req = json_object_new_object();
        json_object_object_add(compile_req, "write", json_object_new_boolean(1));
        json_object_object_add(compile_req, "dry_run", json_object_new_boolean(1));
        json_object_object_add(compile_req, "retention_keep",
                               json_object_new_int(aegisxd_plan_json_int(body, "retention_keep", 6)));
        aegisxd_json_add_string(compile_req, "requested_by",
                                aegisxd_json_str(body, "requested_by", "suricata_apply"));
        aegisxd_json_add_string(compile_req, "scope", "suricata");
        compile = aegisxd_compile_plan(compile_req);
        json_object_object_add(resp, "compile", compile);
        plan = NULL;
        artifacts = NULL;
        suricata_art = NULL;
        suricata_src = "";
        rules = 0;
        if (compile &&
            json_object_object_get_ex(compile, "plan", &plan) &&
            plan &&
            json_object_object_get_ex(plan, "job_id", &artifacts))
            job_id = json_object_get_string(artifacts);
        artifacts = NULL;
        if (plan &&
            json_object_object_get_ex(plan, "artifacts", &artifacts) &&
            artifacts &&
            json_object_object_get_ex(artifacts, "suricata_ruleset", &suricata_art) &&
            suricata_art) {
            suricata_src = aegisxd_json_str(suricata_art, "path", "");
            rules = aegisxd_plan_json_int(suricata_art, "written_items", 0);
            if (rules <= 0)
                rules = aegisxd_plan_json_int(suricata_art, "planned_items", 0);
        }
        write_ruleset = 1;
        if (!suricata_src || !suricata_src[0] || access(suricata_src, R_OK) != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "suricata_artifact_unavailable");
        }
        if (rules <= 0) {
            int counted = aegisxd_suricata_count_rules(suricata_src);

            if (counted > 0)
                rules = counted;
        }
        if (rules <= 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "suricata_rules_empty");
        }
    }
    if (ok && bin[0] && confirm) {
        previous_runtime_active = aegisxd_suricata_active() &&
                                  aegisxd_suricata_pid_running();
        if (previous_runtime_active)
            previous_state = json_object_from_file(AEGISXD_SURICATA_ACTIVE_PATH);
        unlink(previous_config);
        unlink(previous_nfq);
        if (access(AEGISXD_SURICATA_CONFIG_PATH, R_OK) == 0) {
            previous_config_saved =
                aegisxd_file_copy_atomic(AEGISXD_SURICATA_CONFIG_PATH,
                                          previous_config) == 0;
            if (!previous_config_saved) {
                ok = 0;
                aegisxd_apply_add_blocker(blockers, "suricata_config_backup_failed");
            }
        }
        if (ok && access(AEGISXD_SURICATA_NFQ_PATH, R_OK) == 0) {
            previous_nfq_saved =
                aegisxd_file_copy_atomic(AEGISXD_SURICATA_NFQ_PATH,
                                          previous_nfq) == 0;
            if (!previous_nfq_saved) {
                ok = 0;
                aegisxd_apply_add_blocker(blockers, "suricata_nfqueue_backup_failed");
            }
        }
    }
    if (ok && bin[0] && confirm) {
        config_rc = aegisxd_suricata_write_config(suricata_src, &s);
        if (config_rc != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "suricata_config_render_failed");
        } else
            config_changed = 1;
    }
    if (ok && bin[0] && confirm) {
        test_rc = aegisxd_suricata_test_config(bin);
        if (test_rc != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "suricata_config_test_failed");
        }
    }
    if (ok && confirm && !strcmp(s.mode, "protect")) {
        if (aegisxd_suricata_nfqueue_write(&s) != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "suricata_nfqueue_render_failed");
        } else {
            nfq_changed = 1;
        }
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(resp, "operation", operation);
    aegisxd_json_add_string(resp, "scope", "suricata");
    json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    json_object_object_add(resp, "rules", json_object_new_int(rules));
    json_object_object_add(resp, "ruleset_write_requested", json_object_new_boolean(write_ruleset));
    aegisxd_json_add_string(resp, "suricata_artifact", suricata_src);
    aegisxd_json_add_string(resp, "suricata_binary", bin);
    aegisxd_json_add_string(resp, "suricata_config", AEGISXD_SURICATA_CONFIG_PATH);
    aegisxd_json_add_string(resp, "suricata_eve", AEGISXD_SURICATA_EVE_PATH);
    aegisxd_json_add_string(resp, "suricata_log", AEGISXD_SURICATA_LOG);
    aegisxd_json_add_string(resp, "active_state_path", AEGISXD_SURICATA_ACTIVE_PATH);
    aegisxd_json_add_string(resp, "pid_path", AEGISXD_SURICATA_PID_PATH);
    aegisxd_json_add_string(resp, "capture_mode",
                            !strcmp(s.mode, "monitor") ? "af-packet" :
                            (!strcmp(s.mode, "protect") ? "nfqueue" : ""));
    aegisxd_json_add_string(resp, "suricata_interface", s.suricata_interface);
    json_object_object_add(resp, "suricata_queue_num",
                           json_object_new_int(s.suricata_queue_num));
    json_object_object_add(resp, "suricata_fail_open",
                           json_object_new_boolean(s.suricata_fail_open));
    aegisxd_json_add_string(resp, "nfqueue_table", AEGISXD_SURICATA_NFQ_TABLE);
    aegisxd_json_add_string(resp, "nfqueue_path", AEGISXD_SURICATA_NFQ_PATH);
    aegisxd_json_add_string(resp, "job_id", job_id);
    json_object_object_add(resp, "runtime_available", json_object_new_boolean(bin[0] != 0));
    json_object_object_add(resp, "config_available",
                           json_object_new_boolean(aegisxd_suricata_config_available()));
    json_object_object_add(resp, "config_render_exit_status", json_object_new_int(config_rc));
    json_object_object_add(resp, "suricata_test_exit_status", json_object_new_int(test_rc));
    json_object_object_add(resp, "nfqueue_check_exit_status", json_object_new_int(nfq_check_rc));
    json_object_object_add(resp, "blockers", blockers);
    aegisxd_apply_add_capabilities(resp);

    if (!ok) {
        if (confirm && config_changed) {
            (void)aegisxd_suricata_restore_file(previous_config,
                                                AEGISXD_SURICATA_CONFIG_PATH,
                                                previous_config_saved);
        }
        if (confirm && nfq_changed) {
            (void)aegisxd_suricata_restore_file(previous_nfq,
                                                AEGISXD_SURICATA_NFQ_PATH,
                                                previous_nfq_saved);
        }
        if (previous_state)
            json_object_put(previous_state);
        aegisxd_json_add_string(resp, "state", "blocked");
        aegisxd_json_add_string(resp, "error", "suricata_apply_blocked");
        json_object_put(compile_req);
        return resp;
    }
    if (!confirm) {
        aegisxd_json_add_string(resp, "state", "preview");
        if (previous_state)
            json_object_put(previous_state);
        json_object_put(compile_req);
        return resp;
    }

    stop_rc = aegisxd_suricata_stop();
    if (stop_rc != 0) {
        start_rc = -1;
    } else {
        (void)aegisxd_suricata_nfqueue_delete();
        if (!strcmp(s.mode, "protect"))
            nfq_check_rc = aegisxd_suricata_nfqueue_check();
        if (nfq_check_rc != 0 && !strcmp(s.mode, "protect"))
            start_rc = -1;
        else
            start_rc = aegisxd_suricata_start(bin, &s);
    }
    json_object_object_add(resp, "suricata_stop_exit_status", json_object_new_int(stop_rc));
    json_object_object_add(resp, "suricata_start_exit_status", json_object_new_int(start_rc));
    if (start_rc != 0) {
        if (stop_rc == 0) {
            (void)aegisxd_suricata_stop();
            (void)aegisxd_suricata_nfqueue_delete();
        }
        (void)aegisxd_suricata_restore_file(previous_config,
                                            AEGISXD_SURICATA_CONFIG_PATH,
                                            previous_config_saved);
        (void)aegisxd_suricata_restore_file(previous_nfq,
                                            AEGISXD_SURICATA_NFQ_PATH,
                                            previous_nfq_saved);
        if (stop_rc != 0 && previous_runtime_active &&
            aegisxd_suricata_pid_running())
            restore_rc = 0;
        else
            restore_rc = previous_runtime_active ?
                aegisxd_suricata_restore_previous(bin, previous_state) : -1;
        if (restore_rc != 0)
            unlink(AEGISXD_SURICATA_ACTIVE_PATH);
        aegisxd_json_add_string(resp, "state",
                                restore_rc == 0 ? "rolled_back" :
                                                  "stopped_after_failed_apply");
        aegisxd_json_add_string(resp, "error",
                                nfq_check_rc != 0 && !strcmp(s.mode, "protect") ?
                                    "suricata_nfqueue_check_failed" :
                                    "suricata_start_failed");
        json_object_object_add(resp, "rollback_ok",
                               json_object_new_boolean(restore_rc == 0));
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        if (previous_state)
            json_object_put(previous_state);
        json_object_put(compile_req);
        return resp;
    }
    if (!strcmp(s.mode, "protect")) {
        nfq_apply_rc = aegisxd_suricata_nfqueue_apply();
        nfq_active = nfq_apply_rc == 0 && aegisxd_suricata_nfqueue_runtime_active();
        json_object_object_add(resp, "nfqueue_apply_exit_status",
                               json_object_new_int(nfq_apply_rc));
        json_object_object_add(resp, "nfqueue_active", json_object_new_boolean(nfq_active));
        if (!nfq_active) {
            (void)aegisxd_suricata_nfqueue_delete();
            (void)aegisxd_suricata_stop();
            (void)aegisxd_suricata_restore_file(previous_config,
                                                AEGISXD_SURICATA_CONFIG_PATH,
                                                previous_config_saved);
            (void)aegisxd_suricata_restore_file(previous_nfq,
                                                AEGISXD_SURICATA_NFQ_PATH,
                                                previous_nfq_saved);
            restore_rc = previous_runtime_active ?
                aegisxd_suricata_restore_previous(bin, previous_state) : -1;
            if (restore_rc != 0)
                unlink(AEGISXD_SURICATA_ACTIVE_PATH);
            aegisxd_json_add_string(resp, "state",
                                    restore_rc == 0 ? "rolled_back" :
                                                      "stopped_after_failed_apply");
            aegisxd_json_add_string(resp, "error", "suricata_nfqueue_apply_failed");
            json_object_object_add(resp, "rollback_ok",
                                   json_object_new_boolean(restore_rc == 0));
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            if (previous_state)
                json_object_put(previous_state);
            json_object_put(compile_req);
            return resp;
        }
    }
    {
        struct json_object *state = aegisxd_apply_state_json("enabled", s.mode,
                                                             "suricata",
                                                             "", "",
                                                             "", suricata_src,
                                                             job_id, rules);

        aegisxd_json_add_string(state, "suricata_binary", bin);
        aegisxd_json_add_string(state, "suricata_config", AEGISXD_SURICATA_CONFIG_PATH);
        aegisxd_json_add_string(state, "suricata_eve", AEGISXD_SURICATA_EVE_PATH);
        aegisxd_json_add_string(state, "pid_path", AEGISXD_SURICATA_PID_PATH);
        aegisxd_json_add_string(state, "capture_mode",
                                !strcmp(s.mode, "monitor") ? "af-packet" : "nfqueue");
        aegisxd_json_add_string(state, "suricata_interface", s.suricata_interface);
        json_object_object_add(state, "suricata_queue_num",
                               json_object_new_int(s.suricata_queue_num));
        json_object_object_add(state, "suricata_fail_open",
                               json_object_new_boolean(s.suricata_fail_open));
        aegisxd_json_add_string(state, "nfqueue_table", AEGISXD_SURICATA_NFQ_TABLE);
        if (aegisxd_apply_write_state_path(AEGISXD_SURICATA_ACTIVE_PATH, state) != 0) {
            (void)aegisxd_suricata_nfqueue_delete();
            (void)aegisxd_suricata_stop();
            json_object_put(state);
            (void)aegisxd_suricata_restore_file(previous_config,
                                                AEGISXD_SURICATA_CONFIG_PATH,
                                                previous_config_saved);
            (void)aegisxd_suricata_restore_file(previous_nfq,
                                                AEGISXD_SURICATA_NFQ_PATH,
                                                previous_nfq_saved);
            restore_rc = previous_runtime_active ?
                aegisxd_suricata_restore_previous(bin, previous_state) : -1;
            if (restore_rc != 0)
                unlink(AEGISXD_SURICATA_ACTIVE_PATH);
            aegisxd_json_add_string(resp, "state",
                                    restore_rc == 0 ? "rolled_back" :
                                                      "stopped_after_failed_apply");
            aegisxd_json_add_string(resp, "error", "suricata_active_state_write_failed");
            json_object_object_add(resp, "rollback_ok",
                                   json_object_new_boolean(restore_rc == 0));
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            if (previous_state)
                json_object_put(previous_state);
            json_object_put(compile_req);
            return resp;
        }
        json_object_put(state);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(1));
    json_object_object_add(resp, "applied", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "state", "applied");
    if (!strcmp(s.mode, "monitor"))
        unlink(AEGISXD_SURICATA_NFQ_PATH);
    unlink(previous_config);
    unlink(previous_nfq);
    if (previous_state)
        json_object_put(previous_state);
    json_object_put(compile_req);
    return resp;
}

static int aegisxd_resp_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

static struct json_object *aegisxd_apply_scope_body(struct json_object *body,
                                                    const char *scope,
                                                    const char *operation)
{
    struct json_object *o = json_object_new_object();

    aegisxd_json_add_string(o, "scope", scope ? scope : "");
    aegisxd_json_add_string(o, "operation", operation ? operation : "apply");
    json_object_object_add(o, "confirm",
                           json_object_new_boolean(aegisxd_json_bool(body, "confirm", 0)));
    json_object_object_add(o, "force",
                           json_object_new_boolean(aegisxd_json_bool(body, "force", 0)));
    json_object_object_add(o, "retention_keep",
                           json_object_new_int(aegisxd_plan_json_int(body, "retention_keep", 6)));
    aegisxd_json_add_string(o, "requested_by",
                            aegisxd_json_str(body, "requested_by", "all_apply"));
    return o;
}

static struct json_object *aegisxd_apply_all(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *subscopes = json_object_new_object();
    struct json_object *rollback = json_object_new_object();
    struct json_object *dns_body = NULL;
    struct json_object *nft_body = NULL;
    struct json_object *suricata_body = NULL;
    struct json_object *dns = NULL;
    struct json_object *nft = NULL;
    struct json_object *suricata = NULL;
    struct json_object *rb = NULL;
    const char *operation = aegisxd_json_str(body, "operation", "apply");
    int include_suricata = aegisxd_json_bool(body, "include_suricata", 0);
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int dns_ok, nft_ok, suricata_ok = 1;
    int dns_changed, nft_changed, suricata_changed = 0;
    int ok;

    /*
     * scope=all used to fall through to the dns_filter branch only.  Keep the
     * operation guarded, but make the contract honest: all means DNS filter +
     * nft reputation.  Suricata is opt-in because many router builds do not
     * ship the runtime binary; including it by default would block otherwise
     * useful protection.
     */
    dns_body = aegisxd_apply_scope_body(body, "dns_filter", operation);
    nft_body = aegisxd_apply_scope_body(body, "nft_reputation", operation);
    dns = aegisxd_apply(dns_body);
    nft = aegisxd_apply(nft_body);
    json_object_put(dns_body);
    json_object_put(nft_body);

    dns_ok = aegisxd_resp_bool(dns, "ok", 0);
    nft_ok = aegisxd_resp_bool(nft, "ok", 0);
    dns_changed = aegisxd_resp_bool(dns, "dataplane_changed", 0);
    nft_changed = aegisxd_resp_bool(nft, "dataplane_changed", 0);

    if (include_suricata) {
        suricata_body = aegisxd_apply_scope_body(body, "suricata", operation);
        suricata = aegisxd_apply(suricata_body);
        json_object_put(suricata_body);
        suricata_ok = aegisxd_resp_bool(suricata, "ok", 0);
        suricata_changed = aegisxd_resp_bool(suricata, "dataplane_changed", 0);
    }

    ok = dns_ok && nft_ok && suricata_ok;

    if (confirm && !ok && dns_changed &&
        strcmp(operation, "rollback") && strcmp(operation, "disable") &&
        strcmp(operation, "clear")) {
        struct json_object *rb_body =
            aegisxd_apply_scope_body(body, "dns_filter", "rollback");

        rb = aegisxd_apply(rb_body);
        json_object_put(rb_body);
        json_object_object_add(rollback, "dns_filter", rb ? rb : json_object_new_object());
    }
    if (confirm && !ok && nft_changed &&
        strcmp(operation, "rollback") && strcmp(operation, "disable") &&
        strcmp(operation, "clear")) {
        struct json_object *rb_body =
            aegisxd_apply_scope_body(body, "nft_reputation", "rollback");

        rb = aegisxd_apply(rb_body);
        json_object_put(rb_body);
        json_object_object_add(rollback, "nft_reputation", rb ? rb : json_object_new_object());
    }

    json_object_object_add(subscopes, "dns_filter", dns ? dns : json_object_new_object());
    json_object_object_add(subscopes, "nft_reputation", nft ? nft : json_object_new_object());
    if (suricata) {
        json_object_object_add(subscopes, "suricata", suricata);
    } else {
        struct json_object *skipped = json_object_new_object();

        json_object_object_add(skipped, "ok", json_object_new_boolean(1));
        aegisxd_json_add_string(skipped, "state", "skipped");
        aegisxd_json_add_string(skipped, "reason",
                                "suricata_not_included_by_default; set include_suricata=true");
        json_object_object_add(skipped, "included", json_object_new_boolean(0));
        json_object_object_add(subscopes, "suricata", skipped);
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(resp, "operation", operation);
    aegisxd_json_add_string(resp, "scope", "all");
    json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "changed",
                           json_object_new_boolean(dns_changed || nft_changed || suricata_changed));
    json_object_object_add(resp, "dataplane_changed",
                           json_object_new_boolean(dns_changed || nft_changed || suricata_changed));
    json_object_object_add(resp, "applied",
                           json_object_new_boolean(confirm && ok));
    json_object_object_add(resp, "partial",
                           json_object_new_boolean(confirm && !ok &&
                                                   (dns_changed || nft_changed || suricata_changed)));
    json_object_object_add(resp, "rollback_on_partial", json_object_new_boolean(1));
    json_object_object_add(resp, "include_suricata", json_object_new_boolean(include_suricata));
    json_object_object_add(resp, "subscopes", subscopes);
    json_object_object_add(resp, "rollback", rollback);
    if (!ok)
        aegisxd_json_add_string(resp, "error", "aegis_all_apply_subscope_failed");
    aegisxd_apply_add_capabilities(resp);
    return resp;
}

struct json_object *aegisxd_apply(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *compile_req = json_object_new_object();
    struct json_object *compile = NULL;
    struct json_object *plan = NULL;
    struct json_object *artifacts = NULL;
    struct json_object *dns_art = NULL;
    struct json_object *scope_art = NULL;
    struct json_object *blockers = json_object_new_array();
    struct aegisxd_settings s;
    const char *operation = aegisxd_json_str(body, "operation", "apply");
    const char *scope = aegisxd_json_str(body, "scope", "dns_filter");
    const char *dns_src = "";
    const char *scope_src = "";
    const char *job_id = "";
    char dns_dir[AEGISXD_MAX_PATH] = "";
    char dns_file[AEGISXD_MAX_PATH] = "";
    char dns_previous[AEGISXD_MAX_PATH] = "";
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int force = aegisxd_json_bool(body, "force", 0);
    int rules = 0;
    int scope_rules = 0;
    int ok = 1;
    int reload_rc = 0;
    int previous_saved = 0;
    int previous_existed = 0;

    if (!strcmp(scope, "all"))
        return aegisxd_apply_all(body);

    if (!strcmp(scope, "nft_reputation") || !strcmp(scope, "reputation") ||
        !strcmp(scope, "ip_reputation")) {
        if (!strcmp(operation, "rollback") || !strcmp(operation, "disable") ||
            !strcmp(operation, "clear")) {
            json_object_put(resp);
            json_object_put(blockers);
            json_object_put(compile_req);
            return aegisxd_apply_nft_rollback(body, operation);
        }
        json_object_put(resp);
        json_object_put(blockers);
        json_object_put(compile_req);
        return aegisxd_apply_nft_reputation(body);
    }

    if (!strcmp(scope, "suricata") || !strcmp(scope, "ids") ||
        !strcmp(scope, "ips") || !strcmp(scope, "ids_ips")) {
        json_object_put(resp);
        json_object_put(blockers);
        json_object_put(compile_req);
        return aegisxd_apply_suricata(body, operation);
    }

    if (!strcmp(operation, "rollback") || !strcmp(operation, "disable") ||
        !strcmp(operation, "clear")) {
        json_object_put(resp);
        json_object_put(blockers);
        json_object_put(compile_req);
        return aegisxd_apply_disable(body, operation);
    }

    json_object_object_add(compile_req, "write", json_object_new_boolean(1));
    json_object_object_add(compile_req, "dry_run", json_object_new_boolean(1));
    json_object_object_add(compile_req, "retention_keep",
                           json_object_new_int(aegisxd_plan_json_int(body, "retention_keep", 6)));
    aegisxd_json_add_string(compile_req, "requested_by", aegisxd_json_str(body, "requested_by", "apply"));
    aegisxd_json_add_string(compile_req, "scope", scope);
    compile = aegisxd_compile_plan(compile_req);
    json_object_object_add(resp, "compile", compile);

    if (aegisxd_settings_load(&s) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "settings_unavailable");
    }
    if (!force && (!s.enabled || !strcmp(s.mode, "off"))) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "aegis_not_enabled");
    }
    if (strcmp(scope, "dns_filter") && strcmp(scope, "all")) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "unsupported_scope");
    }
    if (aegisxd_apply_find_dnsmasq_dir(dns_dir, sizeof(dns_dir)) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "dnsmasq_conf_dir_not_found");
    } else {
        if (aegisxd_apply_join_path(dns_file, sizeof(dns_file), dns_dir,
                                    AEGISXD_DNSMASQ_ACTIVE_FILE) != 0) {
            ok = 0;
            aegisxd_apply_add_blocker(blockers, "dnsmasq_conf_path_too_long");
        }
    }
    if (compile &&
        json_object_object_get_ex(compile, "plan", &plan) &&
        plan &&
        json_object_object_get_ex(plan, "job_id", &artifacts))
        job_id = json_object_get_string(artifacts);
    artifacts = NULL;
    if (plan &&
        json_object_object_get_ex(plan, "artifacts", &artifacts) &&
        artifacts &&
        json_object_object_get_ex(artifacts, "dnsmasq_domain_blocklist", &dns_art) &&
        dns_art) {
        dns_src = aegisxd_json_str(dns_art, "path", "");
        rules = aegisxd_plan_json_int(dns_art, "written_items", 0);
    }
    if (artifacts &&
        json_object_object_get_ex(artifacts, "nft_content_scope_rules", &scope_art) &&
        scope_art) {
        scope_src = aegisxd_json_str(scope_art, "path", "");
        scope_rules = aegisxd_plan_json_int(scope_art, "written_items", 0);
    }
    /*
     * Reject a scoped ruleset that nft will not parse before anything is
     * installed. Without this the dnsmasq half could go live while the nft half
     * failed, leaving the nftset= directives filling sets that no rule reads —
     * a policy that looks applied and blocks nothing.
     */
    if (scope_rules > 0 &&
        (!scope_src[0] || access(scope_src, R_OK) != 0 ||
         aegisxd_nft_check_file(scope_src) != 0)) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "content_scope_ruleset_invalid");
    }
    if (!dns_src || !dns_src[0] || access(dns_src, R_OK) != 0) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "dnsmasq_artifact_unavailable");
    }
    if (rules <= 0) {
        int counted = aegisxd_apply_count_dns_rules(dns_src);

        if (counted > 0)
            rules = counted;
    }
    if (rules <= 0 && !aegisxd_pcdn_configured()) {
        ok = 0;
        aegisxd_apply_add_blocker(blockers, "dnsmasq_rules_empty");
    }

    json_object_object_add(resp, "ok", json_object_new_boolean(ok && (confirm || !confirm)));
    aegisxd_json_add_string(resp, "operation", "apply");
    aegisxd_json_add_string(resp, "scope", scope);
    json_object_object_add(resp, "preview", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(!confirm));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "applied", json_object_new_boolean(0));
    json_object_object_add(resp, "rules", json_object_new_int(rules));
    aegisxd_json_add_string(resp, "dnsmasq_conf_dir", dns_dir);
    aegisxd_json_add_string(resp, "dnsmasq_conf_file", dns_file);
    aegisxd_json_add_string(resp, "dnsmasq_artifact", dns_src);
    json_object_object_add(resp, "content_scope_rules", json_object_new_int(scope_rules));
    aegisxd_json_add_string(resp, "content_scope_artifact", scope_src);
    aegisxd_json_add_string(resp, "content_scope_nft_table",
                            scope_rules > 0 ? AEGISXD_CONTENT_NFT_TABLE : "");
    aegisxd_json_add_string(resp, "job_id", job_id);
    json_object_object_add(resp, "blockers", blockers);
    aegisxd_apply_add_capabilities(resp);

    if (!ok) {
        aegisxd_json_add_string(resp, "error", "aegis_apply_blocked");
        json_object_put(compile_req);
        return resp;
    }
    if (!confirm) {
        aegisxd_json_add_string(resp, "state", "preview");
        json_object_put(compile_req);
        return resp;
    }
    previous_existed = dns_file[0] && access(dns_file, F_OK) == 0;
    if (previous_existed) {
        snprintf(dns_previous, sizeof(dns_previous),
                 "%s/dnsmasq-previous-%s.conf", AEGISXD_RUNTIME_DIR,
                 job_id && job_id[0] ? job_id : "apply");
        if (aegisxd_file_copy_atomic(dns_file, dns_previous) != 0) {
            aegisxd_json_add_string(resp, "state", "failed");
            aegisxd_json_add_string(resp, "error", "backup_dnsmasq_artifact_failed");
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_put(compile_req);
            return resp;
        }
        previous_saved = 1;
    }
    if (aegisxd_file_copy_atomic(dns_src, dns_file) != 0) {
        aegisxd_json_add_string(resp, "state", "failed");
        aegisxd_json_add_string(resp, "error", "install_dnsmasq_artifact_failed");
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        if (previous_saved)
            unlink(dns_previous);
        json_object_put(compile_req);
        return resp;
    }
    /*
     * Load the scoped table before reloading dnsmasq: the resolver starts
     * filling the sets as soon as it reads nftset=, and a set that does not
     * exist yet makes it log an error per query. Replaced wholesale rather than
     * merged so a policy the user deleted cannot leave a rule behind.
     */
    if (scope_rules > 0) {
        (void)aegisxd_nft_delete_content_scope_table();
        if (aegisxd_nft_apply_file(scope_src) != 0) {
            if (previous_saved) {
                (void)aegisxd_file_copy_atomic(dns_previous, dns_file);
                unlink(dns_previous);
            } else
                unlink(dns_file);
            (void)aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD);
            aegisxd_json_add_string(resp, "state", "rolled_back");
            aegisxd_json_add_string(resp, "error", "content_scope_apply_failed");
            aegisxd_json_add_string(resp, "nft_log", AEGISXD_NFT_LOG);
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_put(compile_req);
            return resp;
        }
    } else
        /* No scoped policy left; drop a table from an earlier apply. */
        (void)aegisxd_nft_delete_content_scope_table();
    reload_rc = aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD);
    if (reload_rc != 0) {
        int rollback_rc;
        int rollback_restored;

        /*
         * The resolver never came back with the new config, so the sets will not
         * be populated; leaving the table would keep rules matching a stale set.
         */
        (void)aegisxd_nft_delete_content_scope_table();
        if (previous_saved)
            rollback_restored = aegisxd_file_copy_atomic(dns_previous, dns_file) == 0;
        else {
            unlink(dns_file);
            rollback_restored = access(dns_file, F_OK) != 0;
        }
        rollback_rc = rollback_restored ?
            aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD) : -1;
        aegisxd_json_add_string(resp, "state",
                                rollback_restored && rollback_rc == 0 ?
                                "rolled_back" : "rollback_failed");
        aegisxd_json_add_string(resp, "error", "dnsmasq_reload_failed");
        json_object_object_add(resp, "reload_exit_status", json_object_new_int(reload_rc));
        json_object_object_add(resp, "rollback_ok",
                               json_object_new_boolean(rollback_restored && rollback_rc == 0));
        json_object_object_add(resp, "rollback_reload_exit_status",
                               json_object_new_int(rollback_rc));
        aegisxd_json_add_string(resp, "reload_log", "/tmp/dreamingwrt-aegis-dnsmasq-reload.log");
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        if (previous_saved)
            unlink(dns_previous);
        json_object_put(compile_req);
        return resp;
    }
    {
        struct json_object *state = aegisxd_apply_state_json("enabled", s.mode,
                                                             "dns_filter",
                                                             dns_dir, dns_file,
                                                             "", "",
                                                             job_id, rules);
        int state_rc = aegisxd_apply_write_state(state);
        json_object_put(state);
        if (state_rc != 0) {
            int rollback_rc;
            int rollback_restored;

            if (previous_saved)
                rollback_restored = aegisxd_file_copy_atomic(dns_previous, dns_file) == 0;
            else {
                unlink(dns_file);
                rollback_restored = access(dns_file, F_OK) != 0;
            }
            rollback_rc = rollback_restored ?
                aegisxd_dataplane_run_quiet(AEGISXD_DNSMASQ_RELOAD_CMD) : -1;
            aegisxd_json_add_string(resp, "state",
                                    rollback_restored && rollback_rc == 0 ?
                                    "rolled_back" : "rollback_failed");
            aegisxd_json_add_string(resp, "error", "active_state_write_failed");
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "rollback_ok",
                                   json_object_new_boolean(rollback_restored && rollback_rc == 0));
            json_object_object_add(resp, "rollback_reload_exit_status",
                                   json_object_new_int(rollback_rc));
            if (previous_saved)
                unlink(dns_previous);
            json_object_put(compile_req);
            return resp;
        }
    }
    if (previous_saved)
        unlink(dns_previous);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "reload_exit_status", json_object_new_int(reload_rc));
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(1));
    json_object_object_add(resp, "applied", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "state", "applied");
    aegisxd_json_add_string(resp, "active_file_glob", AEGISXD_DNSMASQ_MANAGED_GLOB);
    json_object_put(compile_req);
    return resp;
}
