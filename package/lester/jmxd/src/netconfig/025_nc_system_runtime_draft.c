    const char *username = nc_json_str_def(req, "username", "");
    const char *avatar_url = nc_json_str_def(req, "avatar_url", "");
    const char *content = nc_json_str_def(req, "base64_content", "");
    const char *ext = nc_json_str_def(req, "ext", "png");
    if (!username[0]) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("missing_username"));
        return -1;
    }
    for (const char *p = username; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("invalid_username"));
            return -1;
        }
    }
    if (!content[0] && !avatar_url[0]) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("missing_avatar_source"));
        return -1;
    }
    if (jmx_netconfig_db_init() != 0 || nc_web_users_ensure_schema() != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("avatar_storage_unavailable"));
        return -1;
    }
    if (!nc_admin_avatar_ext_ok(ext)) ext = "png";
    char dir[256];
    snprintf(dir, sizeof(dir), "/www/luci-static/dreamingwrt/avatar");
    mkdir(dir, 0755);
    if (content[0]) {
        size_t need = strlen(content);
        size_t max_decoded = (need * 3) / 4 + 4;
        if (max_decoded > 10 * 1024 * 1024) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("avatar_too_large"));
            return -1;
        }
        unsigned char *buf = (unsigned char *)malloc(max_decoded);
        if (!buf) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("oom"));
            return -1;
        }
        size_t n = nc_base64_decode(content, buf, max_decoded);
        if (n < 64) {
            free(buf);
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("invalid_avatar_content"));
            return -1;
        }
        char path[320];
        snprintf(path, sizeof(path), "%s/%s.%s", dir, username, ext);
        FILE *fp = fopen(path, "wb");
        if (!fp) {
            free(buf);
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("avatar_write_failed"));
            return -1;
        }
        fwrite(buf, 1, n, fp);
        fclose(fp);
        free(buf);
        char url[320];
        snprintf(url, sizeof(url), "/luci-static/dreamingwrt/avatar/%s.%s", username, ext);
        if (nc_web_user_avatar_persist(username, url) != 0) {
            unlink(path);
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("avatar_user_not_found_or_persist_failed"));
            return -1;
        }
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "username", json_object_new_string(username));
        json_object_object_add(out, "avatar_url", json_object_new_string(url));
        json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
        return 0;
    }
    /* URL mode: only allow local static path under /luci-static/... */
    if (strncmp(avatar_url, "/luci-static/", 13) != 0 || strstr(avatar_url, "..")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_avatar_url"));
        return -1;
    }
    {
        char path[512];
        struct stat st;

        if (snprintf(path, sizeof(path), "/www%s", avatar_url) >= (int)sizeof(path) ||
            stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("avatar_file_not_found"));
            return -1;
        }
    }
    if (nc_web_user_avatar_persist(username, avatar_url) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("avatar_user_not_found_or_persist_failed"));
        return -1;
    }
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "username", json_object_new_string(username));
    json_object_object_add(out, "avatar_url", json_object_new_string(avatar_url));
    json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
    return 0;
}

int jmx_admin_rename(struct json_object *req, struct json_object *out)
{
    if (!req || !out) return -1;
    const char *old_name = nc_json_str_def(req, "old_username", "");
    const char *new_name = nc_json_str_def(req, "new_username", "");
    if (!old_name[0] || strcmp(old_name, "root") != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("unsupported_source_user"));
        json_object_object_add(out, "message", json_object_new_string("only root can be renamed now"));
        return -1;
    }
    int rc = nc_admin_rename_safe(new_name, out);
    json_object_object_add(out, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "old_username", json_object_new_string(old_name));
    json_object_object_add(out, "new_username", json_object_new_string(new_name));
    json_object_object_add(out, "rpcd_reloaded", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "session_invalidated", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
    return rc;
}

int jmx_admin_password_set_ex(struct json_object *req, struct json_object *out,
                              int create_if_missing)
{
    struct json_object *sync_obj = NULL;
    int sync_system = 0;
    int web_rc;
    int sys_ok = 1;

    if (!req || !out) return -1;
    const char *username = nc_json_str_def(req, "username", "");
    const char *pw = nc_json_str_def(req, "new_password", "");
    const char *confirm = nc_json_str_def(req, "confirm_password", "");
    if (!pw[0])
        pw = nc_json_str_def(req, "password", "");
    if (!confirm[0])
        confirm = pw;
    if (!username[0] || !pw[0]) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("missing_fields"));
        return -1;
    }
    if (strcmp(pw, confirm) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("password_mismatch"));
        return -1;
    }
    if (!nc_admin_password_complexity_ok(pw)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("password_complexity"));
        json_object_object_add(out, "message", json_object_new_string("password must be 8+ chars and include upper/lower/digit/special"));
        return -1;
    }
    char safe_user[128];
    snprintf(safe_user, sizeof(safe_user), "%s", username);
    for (char *p = safe_user; *p; p++) if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-' || *p == '.')) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_username"));
        return -1;
    }

    web_rc = nc_web_user_password_set(safe_user, pw, create_if_missing, out);

    if (json_object_object_get_ex(req, "sync_system_password", &sync_obj))
        sync_system = json_object_get_boolean(sync_obj);
    if (sync_system) {
        sys_ok = nc_chpasswd_stdin(safe_user, pw) == 0;
    }

    json_object_object_add(out, "ok", json_object_new_boolean(web_rc == 0 && sys_ok));
    json_object_object_add(out, "username", json_object_new_string(safe_user));
    json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
    json_object_object_add(out, "system_password_synced", json_object_new_boolean(sync_system && sys_ok));
    if (web_rc != 0)
        json_object_object_add(out, "error", json_object_new_string("web_password_update_failed"));
    else if (!sys_ok)
        json_object_object_add(out, "error", json_object_new_string("chpasswd_failed"));
    return (web_rc == 0 && sys_ok) ? 0 : -1;
}

int jmx_admin_password_set(struct json_object *req, struct json_object *out)
{
    return jmx_admin_password_set_ex(req, out, 0);
}

/*
 * ── system settings runtime executor capability probes ───────────────
 *
 * The time / logging / ZRam / ALG capability bits are no longer asserted as
 * constants. They reflect whether the corresponding runtime executor is fully
 * backed on this build: available, and able to apply, read back, and roll back.
 * kernel_slim / scheduler / crash_dump / collect_diagnostics remain gated by
 * their own contract blocks because no runtime executor is wired for them yet.
 */
static int nc_ssr_time_writable(void)
{
    struct ssr_paths paths;
    struct ssr_probe probe;
    struct ssr_time_state state;
    char error[SSR_ERROR_MAX];

    ssr_paths_default(&paths);
    if (ssr_time_probe(&paths, &probe) != 0)
        return 0;
    return probe.available && probe.apply_supported &&
           probe.readback_supported && probe.rollback_supported &&
           ssr_time_readback(&paths, NULL, &state, error, sizeof(error)) == 0;
}

static int nc_ssr_log_writable(void)
{
    struct ssr_paths paths;
    struct ssr_probe probe;
    struct ssr_log_state state;
    char error[SSR_ERROR_MAX];

    ssr_paths_default(&paths);
    if (ssr_log_probe(&paths, &probe) != 0)
        return 0;
    return probe.available && probe.apply_supported &&
           probe.readback_supported && probe.rollback_supported &&
           ssr_log_readback(&paths, NULL, &state, error, sizeof(error)) == 0;
}

static int nc_ssr_zram_writable(void)
{
    struct ssr_paths paths;
    struct ssr_probe probe;
    struct ssr_zram_state state;
    char error[SSR_ERROR_MAX];

    ssr_paths_default(&paths);
    if (ssr_zram_probe(&paths, &probe) != 0)
        return 0;
    return probe.available && probe.apply_supported &&
           probe.readback_supported && probe.rollback_supported &&
           ssr_zram_readback(&paths, NULL, &state, error, sizeof(error)) == 0;
}

/* One ALG helper is toggleable when its modules exist and the probe completed. */
static int nc_alg_helper_writable(enum jmx_system_alg_helper helper)
{
    struct jmx_system_alg_state state;
    char error[JMX_SYSTEM_ALG_ERROR_MAX];

    if (jmx_system_alg_probe(NULL, helper, &state, error, sizeof(error)) !=
        JMX_SYSTEM_ALG_OK)
        return 0;
    return state.conntrack_available && state.nat_available &&
           state.running_known;
}

/*
 * The advanced ALG group is presented as one write gate on the page, so it is
 * true only when every helper's toggle is fully backed. A single missing module
 * keeps the whole group read-only rather than offering a control that fails.
 */
static int nc_alg_group_writable(void)
{
    return nc_alg_helper_writable(JMX_SYSTEM_ALG_FTP) &&
           nc_alg_helper_writable(JMX_SYSTEM_ALG_TFTP) &&
           nc_alg_helper_writable(JMX_SYSTEM_ALG_SIP) &&
           nc_alg_helper_writable(JMX_SYSTEM_ALG_H323);
}

/* Values and write gates in one GET use the same fresh readback. */
struct nc_system_runtime_capabilities {
    int time_write;
    int logs_write;
    int zram_write;
    int alg_write;
};

static void nc_system_settings_runtime_overlay(struct json_object *general,
                                               struct json_object *advanced,
                                               struct nc_system_runtime_capabilities *caps)
{
    struct ssr_paths paths;
    struct ssr_time_state time_state;
    struct ssr_log_state log_state;
    struct ssr_zram_state zram_state;
    char error[JMX_SYSTEM_ALG_ERROR_MAX];
    size_t i;
    struct ssr_probe probe;
    int read_ok;

    memset(caps, 0, sizeof(*caps));
    caps->alg_write = 1;

    ssr_paths_default(&paths);
    read_ok = ssr_time_readback(&paths, NULL, &time_state, error,
                                sizeof(error)) == 0;
    caps->time_write = read_ok && ssr_time_probe(&paths, &probe) == 0 &&
        probe.available && probe.apply_supported &&
        probe.readback_supported && probe.rollback_supported;
    if (general && read_ok) {
        struct json_object *servers = json_object_new_array();

        json_object_object_add(general, "timezone",
            json_object_new_string(time_state.settings.timezone));
        json_object_object_add(general, "time_sync",
            json_object_new_boolean(time_state.settings.client_enabled));
        json_object_object_add(general, "ntp_mode",
            json_object_new_string(time_state.settings.client_enabled ?
                (time_state.settings.server_enabled ? "both" : "client") :
                (time_state.settings.server_enabled ? "server" : "disabled")));
        json_object_object_add(general, "ntp_interval",
            json_object_new_string(time_state.settings.interval));
        json_object_object_add(general, "ntp_server_enabled",
            json_object_new_boolean(time_state.settings.server_enabled));
        json_object_object_add(general, "ntp_use_dhcp",
            json_object_new_boolean(time_state.settings.use_dhcp));
        for (i = 0; i < time_state.settings.server_count; i++)
            json_object_array_add(servers,
                json_object_new_string(time_state.settings.servers[i]));
        json_object_object_add(general, "ntp_servers", servers);
    }
    read_ok = ssr_log_readback(&paths, NULL, &log_state, error,
                               sizeof(error)) == 0;
    caps->logs_write = read_ok && ssr_log_probe(&paths, &probe) == 0 &&
        probe.available && probe.apply_supported &&
        probe.readback_supported && probe.rollback_supported;
    if (general && read_ok) {
        json_object_object_add(general, "kernel_log_level",
            json_object_new_string(log_state.settings.kernel_level));
        json_object_object_add(general, "cron_log_level",
            json_object_new_string(log_state.settings.cron_level));
        json_object_object_add(general, "log_buffer_kb",
            json_object_new_int((int)log_state.settings.buffer_kib));
        json_object_object_add(general, "remote_log_enabled",
            json_object_new_boolean(log_state.settings.remote_enabled));
        json_object_object_add(general, "remote_log_host",
            json_object_new_string(log_state.settings.remote_host));
        json_object_object_add(general, "remote_log_port",
            json_object_new_int((int)log_state.settings.remote_port));
        json_object_object_add(general, "remote_log_protocol",
            json_object_new_string(log_state.settings.remote_protocol));
        json_object_object_add(general, "log_file_path",
            json_object_new_string(log_state.settings.file_path));
    }
    read_ok = ssr_zram_readback(&paths, NULL, &zram_state, error,
                                sizeof(error)) == 0;
    caps->zram_write = read_ok && ssr_zram_probe(&paths, &probe) == 0 &&
        probe.available && probe.apply_supported &&
        probe.readback_supported && probe.rollback_supported;
    if (advanced && read_ok) {
        json_object_object_add(advanced, "zram_enabled",
            json_object_new_boolean(zram_state.active));
        json_object_object_add(advanced, "zram_size_mb",
            json_object_new_int64((int64_t)zram_state.settings.size_mib));
        json_object_object_add(advanced, "zram_algorithm",
            json_object_new_string(zram_state.settings.algorithm));
        json_object_object_add(advanced, "zram_priority",
            json_object_new_int(zram_state.priority));
    }
    if (advanced) {
        struct json_object *meta_map = NULL;

        json_object_object_get_ex(advanced, "alg_meta", &meta_map);
        for (i = 0; i < sizeof(nc_adv_alg_helpers) /
                        sizeof(nc_adv_alg_helpers[0]); i++) {
            const nc_adv_alg_helper_t *entry = &nc_adv_alg_helpers[i];
            struct jmx_system_alg_state state;
            struct json_object *meta = NULL;
            enum jmx_system_alg_helper helper;

            if (jmx_system_alg_helper_parse(entry->field + 4, &helper) !=
                    JMX_SYSTEM_ALG_OK ||
                jmx_system_alg_probe(NULL, helper, &state, error,
                                     sizeof(error)) != JMX_SYSTEM_ALG_OK) {
                caps->alg_write = 0;
                continue;
            }
            if (!state.conntrack_available || !state.nat_available ||
                !state.running_known)
                caps->alg_write = 0;
            json_object_object_add(advanced, entry->field,
                json_object_new_boolean(state.running));
            if (entry->ports_field)
                json_object_object_add(advanced, entry->ports_field,
                    state.ports[0] ? json_object_new_string(state.ports) :
                                     json_object_new_null());
            if (meta_map && json_object_object_get_ex(meta_map, entry->field,
                                                      &meta) && meta) {
                int writable = state.conntrack_available &&
                               state.nat_available && state.running_known;

                json_object_object_add(meta, "loaded",
                    json_object_new_boolean(state.running));
                json_object_object_add(meta, "writable",
                    json_object_new_boolean(writable));
                json_object_object_add(meta, "reason",
                    json_object_new_string(writable ?
                        "helper_module_toggle_supported" :
                        "helper_module_toggle_unavailable"));
                if (entry->ports_field)
                    json_object_object_add(meta, "ports_writable",
                        json_object_new_boolean(state.ports_writable));
            }
        }
    }
}

struct json_object *jmx_system_settings_get(void)
{
    struct nc_system_runtime_capabilities runtime_caps;
    struct dw_runtime_cost total_started = dw_runtime_cost_now();
    struct dw_runtime_cost phase_started = total_started;
    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    struct json_object *cost = json_object_new_object();
    nc_sys_settings_db_init();nc_sys_sync_disabled_from_file();char hostname[128]="",model[256]="",ver[256]="";const char*ver_source="";nc_sys_read_first_line("/proc/sys/kernel/hostname",hostname,sizeof(hostname));nc_sys_read_first_line("/tmp/sysinfo/model",model,sizeof(model));nc_sys_release_version(ver,sizeof(ver),&ver_source);struct json_object*d=json_object_new_object();json_object_object_add(d,"ts",json_object_new_int64(nc_now_s()));
    sqlite3_stmt*st=NULL;struct json_object*g=json_object_new_object();if(nc_prepare(&st,"SELECT hostname,timezone,language,led_policy,update_channel,description,note,time_format,show_timezone_name,ntp_mode,ntp_interval,ntp_server_enabled,ntp_use_dhcp,log_level,kernel_log_level,log_buffer_kb,cron_log_level,remote_log_enabled,remote_log_host,remote_log_port,remote_log_protocol,log_file_path,table_filter,interface_density,number_format,last_time_sync_at,date_format FROM system_settings WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){const char*dbhost=(const char*)sqlite3_column_text(st,0);json_object_object_add(g,"hostname",json_object_new_string(dbhost&&dbhost[0]?dbhost:hostname));json_object_object_add(g,"model",json_object_new_string(model[0]?model:"DreamingWrt Router"));json_object_object_add(g,"version",ver[0]?json_object_new_string(ver):NULL);json_object_object_add(g,"version_source",ver_source[0]?json_object_new_string(ver_source):NULL);json_object_object_add(g,"version_error",ver[0]?NULL:json_object_new_string("release_version_unavailable"));nc_add_text(g,"timezone",st,1);nc_add_text(g,"language",st,2);nc_add_text(g,"led_policy",st,3);json_object_object_add(g,"time_sync",json_object_new_boolean(1));struct json_object*ntp=json_object_new_array();sqlite3_stmt*ns=NULL;if(nc_prepare(&ns,"SELECT server FROM system_ntp_server WHERE enabled=1 ORDER BY priority,id")==0){while(sqlite3_step(ns)==SQLITE_ROW)json_object_array_add(ntp,json_object_new_string((const char*)sqlite3_column_text(ns,0)));sqlite3_finalize(ns);}if(json_object_array_length(ntp)==0){json_object_array_add(ntp,json_object_new_string("ntp.aliyun.com"));json_object_array_add(ntp,json_object_new_string("time.cloudflare.com"));}json_object_object_add(g,"ntp_servers",ntp);nc_add_text(g,"update_channel",st,4);nc_add_text(g,"description",st,5);nc_add_text(g,"note",st,6);nc_add_text(g,"time_format",st,7);json_object_object_add(g,"show_timezone_name",json_object_new_boolean(sqlite3_column_int(st,8)));nc_add_text(g,"ntp_mode",st,9);nc_add_text(g,"ntp_interval",st,10);json_object_object_add(g,"ntp_server_enabled",json_object_new_boolean(sqlite3_column_int(st,11)));json_object_object_add(g,"ntp_use_dhcp",json_object_new_boolean(sqlite3_column_int(st,12)));nc_add_text(g,"log_level",st,13);nc_add_text(g,"kernel_log_level",st,14);json_object_object_add(g,"log_buffer_kb",json_object_new_int(sqlite3_column_int(st,15)));nc_add_text(g,"cron_log_level",st,16);json_object_object_add(g,"remote_log_enabled",json_object_new_boolean(sqlite3_column_int(st,17)));nc_add_text(g,"remote_log_host",st,18);json_object_object_add(g,"remote_log_port",json_object_new_int(sqlite3_column_int(st,19)));nc_add_text(g,"remote_log_protocol",st,20);nc_add_text(g,"log_file_path",st,21);json_object_object_add(g,"table_filter",json_object_new_boolean(sqlite3_column_int(st,22)));nc_add_text(g,"interface_density",st,23);nc_add_text(g,"number_format",st,24);json_object_object_add(g,"last_time_sync_at",json_object_new_int64(sqlite3_column_int64(st,25)));nc_add_text(g,"date_format",st,26);sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT custom_domain FROM system_settings WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){nc_add_text(g,"custom_domain",st,0);sqlite3_finalize(st);}
    nc_json_add_string_default(g,"hostname",hostname[0]?hostname:"DreamingWrt");
    nc_json_add_string_default(g,"custom_domain","");
    {
        sqlite3_stmt *apply_st = NULL;
        const char *configured = "";
        const char *apply_state = "pending";
        const char *apply_error = "";
        int64_t last_apply_at = 0;

        if (nc_prepare(&apply_st,
            "SELECT hostname,apply_state,last_apply_at,apply_error FROM system_settings WHERE id=1") == 0 &&
            sqlite3_step(apply_st) == SQLITE_ROW) {
            configured = (const char *)sqlite3_column_text(apply_st, 0);
            apply_state = (const char *)sqlite3_column_text(apply_st, 1);
            last_apply_at = sqlite3_column_int64(apply_st, 2);
            apply_error = (const char *)sqlite3_column_text(apply_st, 3);
            json_object_object_add(g, "configured_hostname",
                                   json_object_new_string(configured ? configured : ""));
            json_object_object_add(g, "runtime_hostname",
                                   json_object_new_string(hostname));
            json_object_object_add(g, "hostname_in_sync",
                                   json_object_new_boolean(configured && !strcmp(configured, hostname)));
            json_object_object_add(g, "apply_state",
                                   json_object_new_string(apply_state ? apply_state : "pending"));
            json_object_object_add(g, "last_apply_at", json_object_new_int64(last_apply_at));
            json_object_object_add(g, "apply_error",
                                   json_object_new_string(apply_error ? apply_error : ""));
            sqlite3_finalize(apply_st);
        }
    }
    json_object_object_add(g, "hostname",
                           json_object_new_string(hostname[0] ? hostname : "DreamingWrt"));
    nc_json_add_string_default(g,"model",model[0]?model:"DreamingWrt Router");
    nc_json_add_string_default(g,"version",ver[0]?ver:"DreamingWrt");
    nc_json_add_string_default(g,"timezone","Asia/Shanghai");
    nc_json_add_string_default(g,"language","zh-cn");
    nc_json_add_bool_default(g,"time_sync",1);
    nc_json_add_string_default(g,"description","");
    nc_json_add_string_default(g,"note","");
    nc_json_add_string_default(g,"time_format","24h");
    nc_json_add_string_default(g,"date_format","M/D/YY");
    nc_json_add_bool_default(g,"show_timezone_name",1);
    nc_json_add_string_default(g,"ntp_mode","client");
    nc_json_add_string_default(g,"ntp_interval","auto");
    nc_json_add_i64_default(g,"last_time_sync_at",0);
    nc_json_add_string_default(g,"log_level","");
    nc_json_add_string_default(g,"kernel_log_level","");
    nc_json_add_int_default(g,"log_buffer_kb",0);
    nc_json_add_string_default(g,"cron_log_level","disabled");
    nc_json_add_bool_default(g,"remote_log_enabled",0);
    nc_json_add_string_default(g,"remote_log_host","");
    nc_json_add_int_default(g,"remote_log_port",514);
    nc_json_add_string_default(g,"remote_log_protocol","udp");
    nc_json_add_string_default(g,"log_file_path","/tmp/system.log");
    nc_json_add_bool_default(g,"ntp_server_enabled",0);
    nc_json_add_bool_default(g,"ntp_use_dhcp",0);
    nc_json_add_bool_default(g,"table_filter",0);
    nc_json_add_string_default(g,"interface_density","comfortable");
    nc_json_add_string_default(g,"number_format","auto");
    json_object_object_add(d,"general",g);
    const char *admin_user = "root";
    const char *admin_role = "超级管理员";
    char logged_user[64] = "";
    char admin_role_buf[32] = "";
    char admin_avatar_url[320] = "";
    {
        sqlite3_stmt *admin_st = NULL;

        if (nc_web_users_ensure_schema() == 0 &&
            nc_prepare(&admin_st,
                "SELECT username,role,avatar_url FROM web_users WHERE status='enabled' "
                "ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,username LIMIT 1") == 0) {
            if (sqlite3_step(admin_st) == SQLITE_ROW) {
                const char *u = (const char *)sqlite3_column_text(admin_st, 0);
                const char *r = (const char *)sqlite3_column_text(admin_st, 1);
                const char *a = (const char *)sqlite3_column_text(admin_st, 2);

                snprintf(logged_user, sizeof(logged_user), "%s", u ? u : "");
                snprintf(admin_role_buf, sizeof(admin_role_buf), "%s", r ? r : "");
                snprintf(admin_avatar_url, sizeof(admin_avatar_url), "%s", a ? a : "");
            }
            sqlite3_finalize(admin_st);
        }
    }
    if (logged_user[0]) admin_user = logged_user;
    if (admin_role_buf[0]) admin_role = admin_role_buf;
    struct json_object*admins=json_object_new_array();struct json_object*root=json_object_new_object();json_object_object_add(root,"id",json_object_new_string(admin_user));json_object_object_add(root,"username",json_object_new_string(admin_user));json_object_object_add(root,"role",json_object_new_string(admin_role));struct json_object*lm=json_object_new_array();json_object_array_add(lm,json_object_new_string("password"));json_object_array_add(lm,json_object_new_string("ssh-key"));json_object_object_add(root,"login_methods",lm);json_object_object_add(root,"last_login",json_object_new_int64(0));json_object_object_add(root,"last_ip",json_object_new_string(""));json_object_object_add(root,"two_factor",json_object_new_boolean(0));json_object_array_add(admins,root);json_object_object_add(d,"admins",admins);
    struct json_object*admin=json_object_new_object();json_object_object_add(admin,"username",json_object_new_string(admin_user));json_object_object_add(admin,"role",json_object_new_string(admin_role));json_object_object_add(admin,"avatar_url",json_object_new_string(admin_avatar_url));json_object_object_add(d,"admin",admin);
    dw_runtime_cost_phase(cost, "config_general_admin", &phase_started);
    {
        const char *provider = nc_sys_ssh_provider();
        const char *auth_path = !strcmp(provider, "openssh") ? NC_OPENSSH_AUTH_KEYS_PATH : NC_DROPBEAR_AUTH_KEYS_PATH;
        struct nc_sys_openssh_state openssh_state;
        int password_login;
        int keyboard_interactive_login;
        int root_password_login;
        int ssh_port;
        int idle_timeout_min;
        int key_count = nc_sys_authorized_keys_count_path(auth_path);
        char *auth_text = nc_sys_read_file_text(auth_path, 1 << 16);
        struct json_object *ssh = json_object_new_object();

        if (!strcmp(provider, "openssh")) {
            nc_sys_openssh_state_load(&openssh_state);
            password_login = openssh_state.password_login;
            keyboard_interactive_login = openssh_state.keyboard_interactive_login;
            root_password_login = openssh_state.root_password_login;
            ssh_port = openssh_state.port;
            idle_timeout_min = openssh_state.idle_timeout_min;
        } else {
            password_login = nc_sys_dropbear_password_login();
            keyboard_interactive_login = password_login;
            root_password_login = nc_sys_dropbear_root_password_login();
            ssh_port = nc_sys_dropbear_port();
            idle_timeout_min = nc_sys_dropbear_idle_timeout();
        }

        json_object_object_add(ssh, "provider", json_object_new_string(provider));
        json_object_object_add(ssh, "config_path", json_object_new_string(!strcmp(provider, "openssh") ? NC_OPENSSH_CONFIG_PATH : "/etc/config/dropbear"));
        json_object_object_add(ssh, "authorized_keys_path", json_object_new_string(auth_path));
        json_object_object_add(ssh, "enabled", json_object_new_boolean(!strcmp(provider, "openssh") ? nc_sys_openssh_enabled() : nc_sys_dropbear_enabled()));
        json_object_object_add(ssh, "port", json_object_new_int(ssh_port));
        json_object_object_add(ssh, "password_login", json_object_new_boolean(password_login));
        json_object_object_add(ssh, "keyboard_interactive_login", json_object_new_boolean(keyboard_interactive_login));
        json_object_object_add(ssh, "root_password_login", json_object_new_boolean(root_password_login));
        json_object_object_add(ssh, "key_only", json_object_new_boolean(key_count > 0 && !password_login && !keyboard_interactive_login && !root_password_login));
        json_object_object_add(ssh, "idle_timeout_min", json_object_new_int(idle_timeout_min));
        json_object_object_add(ssh, "authorized_keys_count", json_object_new_int(key_count));
        json_object_object_add(ssh, "authorized_keys", nc_sys_authorized_keys_array(auth_path));
        json_object_object_add(ssh, "authorized_keys_text", json_object_new_string(auth_text ? auth_text : ""));
        json_object_object_add(ssh, "key_management", json_object_new_boolean(1));
        json_object_object_add(d, "ssh", ssh);
        if (auth_text) free(auth_text);
    }
    dw_runtime_cost_phase(cost, "ssh", &phase_started);
    struct json_object*startup=json_object_new_object();char*local_script=nc_sys_read_file_text("/etc/rc.local",1<<16);int services_truncated=0,services_degraded=0;struct json_object*startup_services=nc_sys_services_json(&services_truncated,&services_degraded);json_object_object_add(startup,"local_script_path",json_object_new_string("/etc/rc.local"));json_object_object_add(startup,"local_script",json_object_new_string(local_script?local_script:""));json_object_object_add(startup,"services",startup_services?startup_services:json_object_new_array());json_object_object_add(startup,"services_truncated",json_object_new_boolean(services_truncated));json_object_object_add(startup,"services_degraded",json_object_new_boolean(services_degraded));if(local_script)free(local_script);json_object_object_add(d,"startup",startup);dw_runtime_cost_phase(cost, "startup_services", &phase_started);struct json_object*cron=json_object_new_object();char*ctext=nc_sys_crontab_text();struct stat cron_st;int64_t cron_mtime=stat("/etc/crontabs/root",&cron_st)==0?(int64_t)cron_st.st_mtime:0;json_object_object_add(cron,"text",json_object_new_string(ctext?ctext:""));json_object_object_add(cron,"path",json_object_new_string("/etc/crontabs/root"));json_object_object_add(cron,"last_modified_at",json_object_new_int64(cron_mtime));json_object_object_add(cron,"last_reload_at",json_object_new_int64(0));json_object_object_add(cron,"reload_state",json_object_new_string("unknown"));json_object_object_add(cron,"apply",json_object_new_string("atomic_file_restart_readback_rollback"));json_object_object_add(cron,"special_times_supported",json_object_new_boolean(jmx_system_crontab_special_times_supported()));json_object_object_add(cron,"jobs",nc_sys_cron_jobs_json());if(ctext)free(ctext);json_object_object_add(d,"crontab",cron);dw_runtime_cost_phase(cost, "crontab", &phase_started);struct json_object*mounts=jmx_system_mounts_read_json();json_object_object_add(d,"mounts",mounts);
    nc_sys_fstab_json(mounts);
    dw_runtime_cost_phase(cost, "mounts_fstab", &phase_started);
    struct json_object*adv=json_object_new_object();if(nc_prepare(&st,"SELECT packet_steering,flow_offloading,irq_balance,config_backend FROM system_settings WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){json_object_object_add(adv,"collect_diagnostics",json_object_new_boolean(0));json_object_object_add(adv,"crash_dump",json_object_new_boolean(0));json_object_object_add(adv,"disabled_func_path",json_object_new_string(nc_sys_features_mode()?DWRT_FEATURES_PATH:"/etc/disabled_func"));json_object_object_add(adv,"disabled_functions",nc_sys_disabled_json());nc_add_text(adv,"config_backend",st,3);sqlite3_finalize(st);}
    /*
     * packet_steering / irq_balance / flow_offloading come from the device, not
     * from system_settings. The DB holds intent; reading it back reported IRQ
     * balancing as on when irqbalance was not installed, and flow offloading as
     * "software" when the firewall had it disabled and nft had zero flowtables.
     */
    {
        int steering = nc_adv_uci_int("network.globals.packet_steering", 0);
        int irqbalance_present = nc_sys_file_exists("/etc/init.d/irqbalance");
        int irqbalance_running = nc_adv_process_running("irqbalance");
        int offload_sw = nc_adv_uci_int("firewall.@defaults[0].flow_offloading", 0);
        int offload_hw = nc_adv_uci_int("firewall.@defaults[0].flow_offloading_hw", 0);
        int flowtables = 0;
        int flowtables_ok = nc_adv_nft_flowtable_count(&flowtables) == 0;
        const char *offload_state;

        json_object_object_add(adv, "packet_steering",
                               json_object_new_boolean(steering > 0));
        json_object_object_add(adv, "packet_steering_value",
                               json_object_new_int(steering));
        json_object_object_add(adv, "packet_steering_source",
                               json_object_new_string("uci:network.globals.packet_steering"));

        json_object_object_add(adv, "irq_balance",
                               json_object_new_boolean(irqbalance_running));
        json_object_object_add(adv, "irq_balance_installed",
                               json_object_new_boolean(irqbalance_present));
        json_object_object_add(adv, "irq_balance_running",
                               json_object_new_boolean(irqbalance_running));
        json_object_object_add(adv, "irq_balance_source",
                               json_object_new_string("proc_cmdline_scan+init_script_presence"));
        if (!irqbalance_present)
            json_object_object_add(adv, "irq_balance_reason",
                                   json_object_new_string("irqbalance_not_installed"));
        else if (!irqbalance_running)
            json_object_object_add(adv, "irq_balance_reason",
                                   json_object_new_string("irqbalance_installed_but_not_running"));
        else
            json_object_object_add(adv, "irq_balance_reason", json_object_new_null());

        /* hw beats sw; both off means off no matter what the DB stored. */
        if (!flowtables_ok)
            offload_state = "unknown";
        else if (offload_hw > 0 && flowtables > 0)
            offload_state = "hardware";
        else if (offload_sw > 0 && flowtables > 0)
            offload_state = "software";
        else
            offload_state = "disabled";
        json_object_object_add(adv, "flow_offloading",
                               json_object_new_string(offload_state));
        json_object_object_add(adv, "flow_offloading_uci_sw",
                               json_object_new_boolean(offload_sw > 0));
        json_object_object_add(adv, "flow_offloading_uci_hw",
                               json_object_new_boolean(offload_hw > 0));
        json_object_object_add(adv, "flow_offloading_flowtables",
                               flowtables_ok ? json_object_new_int(flowtables) :
                                               json_object_new_null());
        json_object_object_add(adv, "flow_offloading_readback_verified",
                               json_object_new_boolean(flowtables_ok));
        json_object_object_add(adv, "flow_offloading_source",
                               json_object_new_string("uci:firewall.@defaults[0]+nft_flowtable_count"));
    }
    /* conntrack timeouts: real procfs values, with the accepted range. */
    {
        struct json_object *ct_meta = json_object_new_object();
        size_t i;

        for (i = 0; i < sizeof(nc_adv_conntrack_knobs) / sizeof(nc_adv_conntrack_knobs[0]); i++) {
            const nc_adv_conntrack_knob_t *k = &nc_adv_conntrack_knobs[i];
            struct json_object *meta = json_object_new_object();
            char value[64] = "";
            int present = (nc_adv_read_line(k->path, value, sizeof(value)) == 0);
            int writable = present ? nc_adv_path_writable(k->path) : 0;

            /* No value means null, never a plausible-looking default. */
            if (present)
                json_object_object_add(adv, k->field, json_object_new_int(atoi(value)));
            else
                json_object_object_add(adv, k->field, json_object_new_null());
            json_object_object_add(meta, "path", json_object_new_string(k->path));
            json_object_object_add(meta, "present", json_object_new_boolean(present));
            json_object_object_add(meta, "writable", json_object_new_boolean(writable));
            json_object_object_add(meta, "min", json_object_new_int64((int64_t)k->min));
            json_object_object_add(meta, "max", json_object_new_int64((int64_t)k->max));
            if (!present)
                json_object_object_add(meta, "reason",
                                       json_object_new_string("sysctl_absent_kernel_lacks_knob"));
            else if (!writable)
                json_object_object_add(meta, "reason",
                                       json_object_new_string("sysctl_read_only"));
            else
                json_object_object_add(meta, "reason", json_object_new_null());
            json_object_object_add(ct_meta, k->field, meta);
        }
        json_object_object_add(adv, "conntrack_meta", ct_meta);
        json_object_object_add(adv, "conntrack_persistent", json_object_new_boolean(0));
    }
    /* TCP congestion control: report the real algorithm and what is available. */
    {
        char cc[128] = "";
        char avail[256] = "";
        int have_cc = (nc_adv_read_line("/proc/sys/net/ipv4/tcp_congestion_control",
                                        cc, sizeof(cc)) == 0);
        int have_avail = (nc_adv_read_line("/proc/sys/net/ipv4/tcp_available_congestion_control",
                                          avail, sizeof(avail)) == 0);

        if (have_cc) {
            json_object_object_add(adv, "tcp_congestion_control",
                                   json_object_new_string(cc));
            /* tcp_bbr was a bool that ignored bbrplus/brutal/cubic entirely. */
            json_object_object_add(adv, "tcp_bbr",
                                   json_object_new_boolean(!strncmp(cc, "bbr", 3)));
        } else {
            json_object_object_add(adv, "tcp_congestion_control", json_object_new_null());
            json_object_object_add(adv, "tcp_bbr", json_object_new_null());
        }
        if (have_avail) {
            struct json_object *list = json_object_new_array();
            char *save = NULL;
            char *tok = strtok_r(avail, " \t", &save);

            while (tok) {
                if (*tok) json_object_array_add(list, json_object_new_string(tok));
                tok = strtok_r(NULL, " \t", &save);
            }
            json_object_object_add(adv, "tcp_congestion_available", list);
        } else {
            json_object_object_add(adv, "tcp_congestion_available", json_object_new_null());
        }
        json_object_object_add(adv, "tcp_congestion_writable",
                               json_object_new_boolean(
                                   nc_adv_path_writable("/proc/sys/net/ipv4/tcp_congestion_control")));
    }
    /* ALG helpers: module presence is the truth, ports come from the module. */
    {
        struct json_object *alg_meta = json_object_new_object();
        size_t i;

        for (i = 0; i < sizeof(nc_adv_alg_helpers) / sizeof(nc_adv_alg_helpers[0]); i++) {
            const nc_adv_alg_helper_t *h = &nc_adv_alg_helpers[i];
            struct json_object *meta = json_object_new_object();
            int loaded = nc_adv_alg_loaded(h->module);
            char ports[128] = "";

            json_object_object_add(adv, h->field, json_object_new_boolean(loaded));
            json_object_object_add(meta, "module", json_object_new_string(h->module));
            json_object_object_add(meta, "loaded", json_object_new_boolean(loaded));
            /*
             * Module load/unload is not wired up here, so the switch is
             * reported read-only rather than pretending to accept a write.
             */
            json_object_object_add(meta, "writable", json_object_new_boolean(0));
            json_object_object_add(meta, "reason",
                                   json_object_new_string("helper_module_toggle_not_implemented"));
            if (h->ports_field) {
                if (loaded && nc_adv_alg_ports(h->module, ports, sizeof(ports)) == 0)
                    json_object_object_add(adv, h->ports_field,
                                           json_object_new_string(ports));
                else
                    json_object_object_add(adv, h->ports_field, json_object_new_null());
                json_object_object_add(meta, "ports_field",
                                       json_object_new_string(h->ports_field));
                json_object_object_add(meta, "ports_writable",
                                       json_object_new_boolean(0));
            } else {
                /* h323 exposes no ports parameter in this kernel. */
                json_object_object_add(meta, "ports_field", json_object_new_null());
                json_object_object_add(meta, "ports_reason",
                                       json_object_new_string("module_has_no_ports_parameter"));
            }
            json_object_object_add(alg_meta, h->field, meta);
        }
        json_object_object_add(adv, "alg_meta", alg_meta);
    }
    json_object_object_add(adv,"zram_enabled",json_object_new_boolean(nc_sys_file_exists("/sys/block/zram0")));
    {
        char mem[64]="";
        nc_sys_cmd_first("awk '/^MemTotal:/{printf \"%d\",$2/1024}' /proc/meminfo",mem,sizeof(mem));
        json_object_object_add(adv,"memory_total_mb",json_object_new_int(atoi(mem)));
    }
    {
        char algo[64]="lz4";
        char path[128];
        snprintf(path,sizeof(path),"/sys/block/zram0/comp_algorithm");
        FILE*fp=fopen(path,"r");
        if(fp){
            char buf[256]="";
            if(fgets(buf,sizeof(buf),fp)){
                buf[strcspn(buf,"\r\n")]=0;
                char*p2=strstr(buf,"[");
                if(p2){
                    char*p3=strstr(p2,"]");
                    if(p3){*p3=0;snprintf(algo,sizeof(algo),"%s",p2+1);}
                }
            }
            fclose(fp);
        }
        json_object_object_add(adv,"zram_algorithm",json_object_new_string(algo));
    }
    {
        char sz[64]="0";
        char path[128];
        snprintf(path,sizeof(path),"/sys/block/zram0/disksize");
        FILE*fp=fopen(path,"r");
        if(fp){
            char buf[64]="";
            if(fgets(buf,sizeof(buf),fp)){
                long long bytes=atoll(buf);
                snprintf(sz,sizeof(sz),"%lld",bytes/(1024*1024));
            }
            fclose(fp);
        }
        json_object_object_add(adv,"zram_size_mb",json_object_new_int(atoi(sz)));
    }
    {
        char pri[32]="100";
        char path[128];
        snprintf(path,sizeof(path),"/sys/block/zram0/priority");
        FILE*fp=fopen(path,"r");
        if(fp){
            char buf[32]="";
            if(fgets(buf,sizeof(buf),fp)){
                buf[strcspn(buf,"\r\n")]=0;
                snprintf(pri,sizeof(pri),"%s",buf);
            }
            fclose(fp);
        }
        json_object_object_add(adv,"zram_priority",json_object_new_int(atoi(pri)));
    }
    {
        char thr[32]="0";
        char buf[32]="";
        FILE*fp=popen("uci -q get system.@system[0].zram_size_mb 2>/dev/null","r");
        if(fp){if(fgets(buf,sizeof(buf),fp)){buf[strcspn(buf,"\r\n")]=0;snprintf(thr,sizeof(thr),"%s",buf);}pclose(fp);}
        json_object_object_add(adv,"zram_memory_threshold",json_object_new_int(atoi(thr)));
    }
    json_object_object_add(d,"advanced",adv);
    nc_system_settings_runtime_overlay(g, adv, &runtime_caps);
    struct json_object*cap=json_object_new_object();json_object_object_add(cap,"general_description",json_object_new_boolean(1));json_object_object_add(cap,"general_time",json_object_new_boolean(0));json_object_object_add(cap,"general_time_read",json_object_new_boolean(1));json_object_object_add(cap,"general_time_write",json_object_new_boolean(0));json_object_object_add(cap,"general_logs",json_object_new_boolean(0));json_object_object_add(cap,"general_logs_read",json_object_new_boolean(1));json_object_object_add(cap,"general_logs_write",json_object_new_boolean(0));json_object_object_add(cap,"general_language",json_object_new_boolean(1));json_object_object_add(cap,"general_ui_metadata_write",json_object_new_boolean(1));json_object_object_add(cap,"system_hostname_write",json_object_new_boolean(1));json_object_object_add(cap,"system_hostname_readback",json_object_new_boolean(1));json_object_object_add(cap,"system_custom_domain_write",json_object_new_boolean(1));json_object_object_add(cap,"system_custom_domain_readback",json_object_new_boolean(1));json_object_object_add(cap,"system_settings_save",json_object_new_boolean(1));json_object_object_add(cap,"system_settings_apply",json_object_new_boolean(1));json_object_object_add(cap,"system_settings_field_results",json_object_new_boolean(1));json_object_object_add(cap,"system_settings_fail_closed",json_object_new_boolean(1));json_object_object_add(cap,"system_settings_partial_write",json_object_new_boolean(1));json_object_object_add(cap,"system_settings_rejected_field_results",json_object_new_boolean(1));json_object_object_add(cap,"zram",json_object_new_boolean(1));json_object_object_add(cap,"zram_read",json_object_new_boolean(1));json_object_object_add(cap,"zram_write",json_object_new_boolean(0));json_object_object_add(cap,"time_sync_actions",json_object_new_boolean(1));json_object_object_add(cap,"crontab_text",json_object_new_boolean(1));json_object_object_add(cap,"crontab_apply",json_object_new_boolean(1));json_object_object_add(cap,"crontab_validate",json_object_new_boolean(1));json_object_object_add(cap,"cron_reload",json_object_new_boolean(1));json_object_object_add(cap,"admin_rename",json_object_new_boolean(1));json_object_object_add(cap,"admin_password_set",json_object_new_boolean(1));json_object_object_add(cap,"admin_rpcd_sync",json_object_new_boolean(1));json_object_object_add(cap,"admin_avatar",json_object_new_boolean(1));json_object_object_add(cap,"ssh_config",json_object_new_boolean(1));json_object_object_add(cap,"ssh_key_only",json_object_new_boolean(1));json_object_object_add(cap,"ssh_authorized_keys",json_object_new_boolean(1));json_object_object_add(cap,"ssh_provider_aware",json_object_new_boolean(1));json_object_object_add(cap,"ssh_idle_timeout",json_object_new_boolean(1));json_object_object_add(cap,"appearance_accent_write",json_object_new_boolean(1));json_object_object_add(cap,"appearance_glass_write",json_object_new_boolean(1));json_object_object_add(cap,"appearance_wallpaper_write",json_object_new_boolean(1));json_object_object_add(cap,"appearance_runtime_apply",json_object_new_boolean(1));json_object_object_add(d,"capabilities",cap);
    json_object_object_add(cap,"advanced_packet_steering",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_packet_steering_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_packet_steering_reason",json_object_new_string("uci_write_not_implemented"));
    json_object_object_add(cap,"advanced_irq_balance",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_irq_balance_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_irq_balance_reason",json_object_new_string(nc_sys_file_exists("/etc/init.d/irqbalance")?"service_toggle_not_implemented":"irqbalance_not_installed"));
    json_object_object_add(cap,"advanced_flow_offloading",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_flow_offloading_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_flow_offloading_reason",json_object_new_string("firewall_write_not_implemented"));
    /*
     * conntrack timeouts and congestion control are plain sysctls: writable is
     * decided by probing one representative file, not asserted.
     */
    json_object_object_add(cap,"advanced_conntrack_timeouts_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_conntrack_timeouts_write",json_object_new_boolean(nc_adv_path_writable("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established")));
    json_object_object_add(cap,"advanced_tcp_congestion_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_tcp_congestion_write",json_object_new_boolean(nc_adv_path_writable("/proc/sys/net/ipv4/tcp_congestion_control")));
    /* ALG helper state is observable; toggling the modules is not built. */
    json_object_object_add(cap,"advanced_alg_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_alg_write",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_alg_reason",json_object_new_string("helper_module_toggle_not_implemented"));
    /*
     * Runtime-executor capability truth. The literals above are the fail-closed
     * defaults; here each bit is re-evaluated against its executor's probe so a
     * build that cannot apply/read back/roll back keeps reporting 0. json-c's
     * json_object_object_add() replaces the earlier key, so the probed value is
     * the one shipped. kernel_slim / scheduler / crash_dump / collect_diagnostics
     * are deliberately left untouched: no executor is wired for them.
     */
    {
        int time_write = runtime_caps.time_write;
        int logs_write = runtime_caps.logs_write;
        int zram_write = runtime_caps.zram_write;
        int alg_write = runtime_caps.alg_write;

        json_object_object_add(cap, "general_time_write",
                               json_object_new_boolean(time_write));
        json_object_object_add(cap, "general_logs_write",
                               json_object_new_boolean(logs_write));
        json_object_object_add(cap, "zram_write",
                               json_object_new_boolean(zram_write));
        json_object_object_add(cap, "advanced_alg_write",
                               json_object_new_boolean(alg_write));
        if (alg_write)
            json_object_object_add(cap, "advanced_alg_reason",
                                   json_object_new_string("helper_module_toggle_supported"));
    }
    /* Runtime sysctl values reset on reboot; nothing here is persisted yet. */
    json_object_object_add(cap,"advanced_sysctl_persistent",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_kernel_slim_mode",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_kernel_slim_mode_reason",json_object_new_string("module_unload_not_implemented_high_risk_needs_approval"));
    {
        struct json_object *contract = json_object_new_object();
        struct json_object *blockers = json_object_new_array();
        json_object_array_add(blockers, json_object_new_string("module_dependency_graph_executor_missing"));
        json_object_array_add(blockers, json_object_new_string("protected_management_modules_not_classified"));
        json_object_object_add(contract, "supported", json_object_new_boolean(0));
        json_object_object_add(contract, "temporary_runtime", json_object_new_boolean(0));
        json_object_object_add(contract, "persistent_reboot", json_object_new_boolean(0));
        json_object_object_add(contract, "snapshot_supported", json_object_new_boolean(0));
        json_object_object_add(contract, "readback_supported", json_object_new_boolean(0));
        json_object_object_add(contract, "rollback_supported", json_object_new_boolean(0));
        json_object_object_add(contract, "risk", json_object_new_string("high"));
        json_object_object_add(contract, "blockers", blockers);
        json_object_object_add(cap, "advanced_kernel_slim_mode_contract", contract);
    }
    json_object_object_add(cap,"advanced_scheduler_priority",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_scheduler_priority_reason",json_object_new_string("rt_scheduling_not_implemented_high_risk_needs_approval"));
    {
        struct json_object *contract = json_object_new_object();
        struct json_object *targets = json_object_new_array();
        struct json_object *blockers = json_object_new_array();
        json_object_array_add(targets, json_object_new_string("dreamingwrt-core"));
        json_object_array_add(targets, json_object_new_string("dreamingwrt-webd"));
        json_object_array_add(targets, json_object_new_string("dreamingwrt-metricsd"));
        json_object_array_add(blockers, json_object_new_string("sched_set_and_setpriority_executor_missing"));
        json_object_array_add(blockers, json_object_new_string("watchdog_and_cpu_quota_preflight_missing"));
        json_object_object_add(contract, "supported", json_object_new_boolean(0));
        json_object_object_add(contract, "allowed_targets", targets);
        json_object_object_add(contract, "pid_arbitrary", json_object_new_boolean(0));
        json_object_object_add(contract, "nice_range", json_object_new_string("not_enabled"));
        json_object_object_add(contract, "realtime_policy", json_object_new_boolean(0));
        json_object_object_add(contract, "restart_cleanup", json_object_new_boolean(0));
        json_object_object_add(contract, "rollback_supported", json_object_new_boolean(0));
        json_object_object_add(contract, "risk", json_object_new_string("high"));
        json_object_object_add(contract, "blockers", blockers);
        json_object_object_add(cap, "advanced_scheduler_priority_contract", contract);
    }
    json_object_object_add(cap,"advanced_crash_dump",json_object_new_boolean(0));
    {
        int crash_node = nc_sys_file_exists("/sys/kernel/kexec_crash_loaded");
        int kexec_node = nc_sys_file_exists("/sys/kernel/kexec_loaded");
        int crash_loaded = nc_sys_file_is_one("/sys/kernel/kexec_crash_loaded");
        int kexec_loaded = nc_sys_file_is_one("/sys/kernel/kexec_loaded");
        int crashkernel = nc_sys_cmdline_has_crashkernel();
        int kexec_tools = access("/usr/sbin/kexec", X_OK) == 0 ||
                          access("/sbin/kexec", X_OK) == 0;
        const char *reason = !crashkernel ? "crashkernel_not_configured" :
                             !crash_node ? "kexec_crash_loaded_node_missing" :
                             !crash_loaded ? "crash_kernel_not_loaded" :
                             !kexec_node ? "kexec_loaded_node_missing" :
                             !kexec_loaded ? "kexec_not_loaded" :
                             !kexec_tools ? "kexec_tools_missing" :
                             "crash_dump_storage_and_persistence_not_ready";
        json_object_object_add(cap,"advanced_crash_dump_reason",
                               json_object_new_string(reason));
    }
    json_object_object_add(cap,"advanced_cpu_interrupts_set",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_cpu_irq_affinity_read",json_object_new_boolean(1));
    json_object_object_add(cap,"advanced_cpu_irq_affinity_write",json_object_new_boolean(nc_irq_affinity_any_writable()));
    json_object_object_add(cap,"advanced_cpu_softirq_toggle",json_object_new_boolean(0));
    json_object_object_add(cap,"advanced_cpu_hardirq_toggle",json_object_new_boolean(0));
    /* advanced_cpufreq_{read,write,overclock,reason}; all probed, see 038_nc_cpufreq.c */
    nc_cpufreq_capabilities(cap);
    json_object_object_add(cap,"advanced_collect_diagnostics",json_object_new_boolean(0));
    {
        struct json_object *contract = json_object_new_object();
        struct json_object *blockers = json_object_new_array();
        json_object_array_add(blockers, json_object_new_string("diagnostics_collector_executor_missing"));
        json_object_array_add(blockers, json_object_new_string("quota_and_retention_store_missing"));
        json_object_object_add(contract, "supported", json_object_new_boolean(0));
        json_object_object_add(contract, "status_states", json_object_new_string("running,completed,failed,expired,space_protected"));
        json_object_object_add(contract, "scope", json_object_new_string("proc,sysfs,service_logs,network_snapshot_without_config_db"));
        json_object_object_add(contract, "sensitive_redaction", json_object_new_boolean(0));
        json_object_object_add(contract, "download_role", json_object_new_string("admin_only"));
        json_object_object_add(contract, "delete_role", json_object_new_string("admin_only"));
        json_object_object_add(contract, "blockers", blockers);
        json_object_object_add(cap, "advanced_collect_diagnostics_contract", contract);
    }
    {
        struct json_object *contract = json_object_new_object();
        struct json_object *blockers = json_object_new_array();
        int crash_node = nc_sys_file_exists("/sys/kernel/kexec_crash_loaded");
        int kexec_node = nc_sys_file_exists("/sys/kernel/kexec_loaded");
        int crash_loaded = nc_sys_file_is_one("/sys/kernel/kexec_crash_loaded");
        int kexec_loaded = nc_sys_file_is_one("/sys/kernel/kexec_loaded");
        int crashkernel = nc_sys_cmdline_has_crashkernel();
        int kexec_tools = access("/usr/sbin/kexec", X_OK) == 0 ||
                          access("/sbin/kexec", X_OK) == 0;
        int pstore = nc_sys_dir_usable("/sys/fs/pstore") ||
                     nc_sys_dir_usable("/sys/kernel/debug/pstore");
        int storage_quota_ready = 0;
        if (!crashkernel)
            json_object_array_add(blockers, json_object_new_string("crashkernel_not_configured"));
        if (!crash_node)
            json_object_array_add(blockers, json_object_new_string("kexec_crash_loaded_node_missing"));
        else if (!crash_loaded)
            json_object_array_add(blockers, json_object_new_string("crash_kernel_not_loaded"));
        if (!kexec_node)
            json_object_array_add(blockers, json_object_new_string("kexec_loaded_node_missing"));
        else if (!kexec_loaded)
            json_object_array_add(blockers, json_object_new_string("kexec_not_loaded"));
        if (!kexec_tools)
            json_object_array_add(blockers, json_object_new_string("kexec_tools_missing"));
        if (!pstore)
            json_object_array_add(blockers, json_object_new_string("pstore_mount_missing"));
        json_object_array_add(blockers, json_object_new_string("crash_dump_storage_quota_unverified"));
        json_object_object_add(contract, "supported", json_object_new_boolean(0));
        json_object_object_add(contract, "crashkernel_configured", json_object_new_boolean(crashkernel));
        json_object_object_add(contract, "kexec_crash_loaded", json_object_new_boolean(crash_loaded));
        json_object_object_add(contract, "kexec_loaded", json_object_new_boolean(kexec_loaded));
        json_object_object_add(contract, "kexec_tools_present", json_object_new_boolean(kexec_tools));
        json_object_object_add(contract, "pstore_present", json_object_new_boolean(pstore));
        json_object_object_add(contract, "storage_quota_ready", json_object_new_boolean(storage_quota_ready));
        json_object_object_add(contract, "persistent_enable_supported", json_object_new_boolean(0));
        json_object_object_add(contract, "rollback_supported", json_object_new_boolean(0));
        json_object_object_add(contract, "reboot_required", json_object_new_boolean(1));
        json_object_object_add(contract, "blockers", blockers);
        json_object_object_add(cap, "advanced_crash_dump_contract", contract);
    }
    json_object_object_add(cap,"advanced_kernel_restore_defaults",json_object_new_boolean(1));
    {
        struct json_object *contracts = json_object_new_object();
        struct json_object *hostname_contract = json_object_new_object();
        struct json_object *domain_contract = json_object_new_object();
        struct json_object *ui_contract = json_object_new_object();
        struct json_object *date_contract = json_object_new_object();
        struct json_object *time_contract = json_object_new_object();
        struct json_object *logs_contract = json_object_new_object();
        struct json_object *zram_contract = json_object_new_object();
        int time_write = runtime_caps.time_write;
        int logs_write = runtime_caps.logs_write;
        int zram_write = runtime_caps.zram_write;

        json_object_object_add(hostname_contract,"write",json_object_new_boolean(1));
        json_object_object_add(hostname_contract,"persisted",json_object_new_boolean(1));
        json_object_object_add(hostname_contract,"applied",json_object_new_boolean(1));
        json_object_object_add(hostname_contract,"observed",json_object_new_boolean(1));
        json_object_object_add(hostname_contract,"source",json_object_new_string("config.db+uci+kernel"));
        json_object_object_add(contracts,"general.hostname",hostname_contract);
        json_object_object_add(domain_contract,"write",json_object_new_boolean(1));
        json_object_object_add(domain_contract,"persisted",json_object_new_boolean(1));
        json_object_object_add(domain_contract,"applied",json_object_new_boolean(1));
        json_object_object_add(domain_contract,"observed",json_object_new_boolean(1));
        json_object_object_add(domain_contract,"source",json_object_new_string("config.db+uci+dnsmasq"));
        json_object_object_add(domain_contract,"forbidden_suffix",json_object_new_string(".local"));
        json_object_object_add(contracts,"general.custom_domain",domain_contract);
        json_object_object_add(ui_contract,"write",json_object_new_boolean(1));
        json_object_object_add(ui_contract,"state",json_object_new_string("saved_only"));
        json_object_object_add(ui_contract,"source",json_object_new_string("config.db"));
        json_object_object_add(contracts,"general.ui_metadata",ui_contract);
        /* Date formatting is a persisted presentation preference, not a clock
         * or NTP operation. Keep it on its own contract so an unavailable time
         * executor cannot lock this field. */
        json_object_object_add(date_contract,"write",json_object_new_boolean(1));
        json_object_object_add(date_contract,"persisted",json_object_new_boolean(1));
        json_object_object_add(date_contract,"observed",json_object_new_boolean(1));
        json_object_object_add(date_contract,"state",json_object_new_string("saved_only"));
        json_object_object_add(date_contract,"source",json_object_new_string("config.db"));
        json_object_object_add(date_contract,"reason",json_object_new_string("ui_preference_saved"));
        json_object_object_add(contracts,"general.date_format",date_contract);
        /* time_format, timezone, show_timezone_name are also persisted UI
         * preferences in system_settings — independent of the NTP executor. */
        {
            struct json_object *tf = json_object_new_object();
            json_object_object_add(tf,"write",json_object_new_boolean(1));
            json_object_object_add(tf,"persisted",json_object_new_boolean(1));
            json_object_object_add(tf,"observed",json_object_new_boolean(1));
            json_object_object_add(tf,"state",json_object_new_string("saved_only"));
            json_object_object_add(tf,"source",json_object_new_string("config.db"));
            json_object_object_add(tf,"reason",json_object_new_string("ui_preference_saved"));
            json_object_object_add(contracts,"general.time_format",tf);
        }
        {
            struct json_object *tz = json_object_new_object();
            json_object_object_add(tz,"write",json_object_new_boolean(1));
            json_object_object_add(tz,"persisted",json_object_new_boolean(1));
            json_object_object_add(tz,"observed",json_object_new_boolean(1));
            json_object_object_add(tz,"state",json_object_new_string("saved_only"));
            json_object_object_add(tz,"source",json_object_new_string("config.db"));
            json_object_object_add(tz,"reason",json_object_new_string("ui_preference_saved"));
            json_object_object_add(contracts,"general.timezone",tz);
        }
        {
            struct json_object *stz = json_object_new_object();
            json_object_object_add(stz,"write",json_object_new_boolean(1));
            json_object_object_add(stz,"persisted",json_object_new_boolean(1));
            json_object_object_add(stz,"observed",json_object_new_boolean(1));
            json_object_object_add(stz,"state",json_object_new_string("saved_only"));
            json_object_object_add(stz,"source",json_object_new_string("config.db"));
            json_object_object_add(stz,"reason",json_object_new_string("ui_preference_saved"));
            json_object_object_add(contracts,"general.show_timezone_name",stz);
        }
        json_object_object_add(time_contract,"write",json_object_new_boolean(time_write));
        json_object_object_add(time_contract,"observed",json_object_new_boolean(time_write));
        json_object_object_add(time_contract,"source",json_object_new_string("uci_system+timeserver+cron"));
        json_object_object_add(time_contract,"reason",
                               json_object_new_string(time_write ?
                                   "runtime_executor_ready" :
                                   "time_executor_unavailable"));
        json_object_object_add(contracts,"general.time_policy",time_contract);
        json_object_object_add(logs_contract,"write",json_object_new_boolean(logs_write));
        json_object_object_add(logs_contract,"observed",json_object_new_boolean(logs_write));
        json_object_object_add(logs_contract,"source",json_object_new_string("uci_system"));
        /*
         * general.log_level (the local logd level) has no writer on this
         * platform, so ssr_log_validate() rejects it. The group is writable but
         * that one field stays out of the whitelist; the Web keeps its control
         * disabled via this note.
         */
        json_object_object_add(logs_contract,"local_log_level_writable",
                               json_object_new_boolean(0));
        json_object_object_add(logs_contract,"local_log_level_reason",
                               json_object_new_string("local_log_level_unsupported_by_logd"));
        json_object_object_add(logs_contract,"reason",
                               json_object_new_string(logs_write ?
                                   "runtime_executor_ready" :
                                   "log_executor_unavailable"));
        json_object_object_add(contracts,"general.logging",logs_contract);
        json_object_object_add(zram_contract,"read",json_object_new_boolean(1));
        json_object_object_add(zram_contract,"write",json_object_new_boolean(zram_write));
        json_object_object_add(zram_contract,"observed",json_object_new_boolean(zram_write));
        json_object_object_add(zram_contract,"source",json_object_new_string("sysfs+uci"));
        json_object_object_add(zram_contract,"reboot_required",json_object_new_boolean(0));
        json_object_object_add(zram_contract,"reason",
                               json_object_new_string(zram_write ?
                                   "runtime_executor_ready" :
                                   "zram_device_unavailable"));
        json_object_object_add(contracts,"advanced.zram",zram_contract);
        json_object_object_add(d,"field_contracts",contracts);
    }
    json_object_object_add(cap,"ssh_idle_timeout",json_object_new_boolean(1));
    int mounts_gen = jmx_system_mount_runtime_capability(0);
    int mounts_exec = jmx_system_mount_runtime_capability(1);
    json_object_object_add(cap,"mounts_read",json_object_new_boolean(1));
    json_object_object_add(cap,"mounts_save_point",json_object_new_boolean(1));
    json_object_object_add(cap,"mounts_delete_point",json_object_new_boolean(1));
    json_object_object_add(cap,"mounts_discovery",json_object_new_boolean(mounts_gen));
    json_object_object_add(cap,"mounts_mount_connected",json_object_new_boolean(mounts_exec));
    json_object_object_add(cap,"mounts_unmount",json_object_new_boolean(1));
    json_object_object_add(cap,"mounts_generate_config",json_object_new_boolean(mounts_gen));
    json_object_object_add(cap,"flash_read",json_object_new_boolean(1));
    json_object_object_add(cap,"flash_factory_reset",json_object_new_boolean(0));
    struct json_object*flash=json_object_new_object();json_object_object_add(flash,"current_firmware",ver[0]?json_object_new_string(ver):NULL);{int64_t bt=nc_sys_release_build_time();json_object_object_add(flash,"build_time",bt?json_object_new_int64(bt):NULL);}json_object_object_add(flash,"backup_size",NULL);json_object_object_add(flash,"keep_settings",json_object_new_boolean(1));json_object_object_add(flash,"last_backup_at",NULL);json_object_object_add(flash,"auto_backup",NULL);json_object_object_add(flash,"backup_state_source",json_object_new_string("webd_backup_store"));json_object_object_add(d,"flash",flash);
    {
        char kern[256]="";
        nc_sys_read_first_line("/proc/version",kern,sizeof(kern));
        json_object_object_add(flash,"kernel",json_object_new_string(kern[0]?kern:""));
    }
    struct json_object*dw=json_object_new_object(),*wall=json_object_new_object(),*dash=json_object_new_object();if(nc_prepare(&st,"SELECT ui_mode,sidebar_collapsed,default_view,show_status_rail,animation_level,density FROM system_ui_settings WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){nc_add_text(dw,"ui_mode",st,0);json_object_object_add(dw,"sidebar_collapsed",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(dash,"default_view",st,2);json_object_object_add(dash,"show_status_rail",json_object_new_boolean(sqlite3_column_int(st,3)));nc_add_text(dash,"animation_level",st,4);nc_add_text(dash,"density",st,5);sqlite3_finalize(st);}{struct nc_appearance_config appearance;if(nc_appearance_load(&appearance)==0)nc_appearance_to_json(&appearance,dw,wall);}json_object_object_add(dw,"wallpaper",wall);json_object_object_add(dw,"dashboard",dash);json_object_object_add(d,"dreamingwrt",dw);
    dw_runtime_cost_phase(cost, "advanced_and_capabilities", &phase_started);
    json_object_object_add(cost, "total", dw_runtime_cost_json(
        dw_runtime_cost_delta(total_started, dw_runtime_cost_now())));
    json_object_object_add(cost, "scope", json_object_new_string("calling_thread_excludes_children"));
    json_object_object_add(d, "collection_cost", cost);
    return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

/*
 * Applies the writable advanced-section fields to the running kernel.
 *
 * Returns 0 when every present field was accepted and read back, -1 otherwise.
 * Values are re-validated here against the same bounds published by the read
 * surface, so a direct ubus caller cannot skip the range check.
 */
static int nc_adv_apply_runtime_sysctls(struct json_object *adv)
{
    size_t i;
    struct json_object *v = NULL;

    if (!adv || !json_object_is_type(adv, json_type_object))
        return 0;

    for (i = 0; i < sizeof(nc_adv_conntrack_knobs) / sizeof(nc_adv_conntrack_knobs[0]); i++) {
        const nc_adv_conntrack_knob_t *k = &nc_adv_conntrack_knobs[i];
        long long requested;
        char buf[64];
        char readback[64] = "";
        FILE *fp;

        if (!json_object_object_get_ex(adv, k->field, &v) || !v)
            continue;
        if (json_object_is_type(v, json_type_int)) {
            requested = (long long)json_object_get_int64(v);
        } else if (json_object_is_type(v, json_type_string)) {
            const char *raw = json_object_get_string(v);
            char *end = NULL;

            requested = strtoll(raw ? raw : "", &end, 10);
            if (!raw || !*raw || !end || *end != 0)
                return -1;
        } else {
            return -1;
        }
        if (requested < k->min || requested > k->max)
            return -1;
        if (!nc_adv_path_writable(k->path))
            return -1;
        snprintf(buf, sizeof(buf), "%lld", requested);
        fp = fopen(k->path, "w");
        if (!fp)
            return -1;
        if (fprintf(fp, "%s\n", buf) < 0 || fflush(fp) != 0) {
            fclose(fp);
            return -1;
        }
        if (fclose(fp) != 0)
            return -1;
        /* Confirm the kernel kept the value instead of trusting the write. */
        if (nc_adv_read_line(k->path, readback, sizeof(readback)) != 0)
            return -1;
        if (atoll(readback) != requested)
            return -1;
    }

    if (json_object_object_get_ex(adv, "tcp_congestion_control", &v) && v &&
        json_object_is_type(v, json_type_string)) {
        const char *want = json_object_get_string(v);
        const char *path = "/proc/sys/net/ipv4/tcp_congestion_control";
        char avail[256] = "";
        char readback[128] = "";
        int allowed = 0;
        FILE *fp;
        char *save = NULL;
        char *tok;

        if (!want || !*want || strlen(want) > 32)
            return -1;
        /* Only algorithms the kernel advertises are accepted. */
        if (nc_adv_read_line("/proc/sys/net/ipv4/tcp_available_congestion_control",
                             avail, sizeof(avail)) != 0)
            return -1;
        tok = strtok_r(avail, " \t", &save);
        while (tok) {
            if (!strcmp(tok, want)) { allowed = 1; break; }
            tok = strtok_r(NULL, " \t", &save);
        }
        if (!allowed)
            return -1;
        if (!nc_adv_path_writable(path))
            return -1;
        fp = fopen(path, "w");
        if (!fp)
            return -1;
        if (fprintf(fp, "%s\n", want) < 0 || fflush(fp) != 0) {
            fclose(fp);
            return -1;
        }
        if (fclose(fp) != 0)
            return -1;
        if (nc_adv_read_line(path, readback, sizeof(readback)) != 0)
            return -1;
        if (strcmp(readback, want))
            return -1;
    }
    return 0;
}

static int nc_sys_date_format_valid(const char *value);

int jmx_system_settings_set(struct json_object *cfg)
{
    struct json_object *only_ssh = NULL;
    struct json_object *appearance_dw = NULL;
    struct nc_appearance_config appearance;
    int appearance_touched = 0;
    int db_txn;

    if (!cfg)
        return -1;
    db_txn = !(json_object_object_length(cfg) == 1 &&
               json_object_object_get_ex(cfg, "ssh", &only_ssh) && only_ssh);
    if (db_txn) {
        if (jmx_netconfig_db_init() != 0)
            return -1;
        nc_sys_settings_db_init();
    }
    if (json_object_object_get_ex(cfg, "dreamingwrt", &appearance_dw) &&
        nc_appearance_requested(appearance_dw)) {
        if (nc_appearance_load(&appearance) != 0 ||
            nc_appearance_patch(appearance_dw, &appearance) != 0)
            return -1;
        appearance_touched = 1;
    }
    if (db_txn) {
        if (nc_exec("BEGIN IMMEDIATE") != 0)
            return -1;
    }
    struct json_object*v=NULL;sqlite3_int64 now=(sqlite3_int64)nc_now_s();
    if (json_object_object_get_ex(cfg, "general", &v) && v) {
        const char *hn = nc_json_str_def(v, "hostname", "");
        struct json_object *domain_obj = NULL;
        const char *custom_domain = "";
        int custom_domain_present = json_object_object_get_ex(v, "custom_domain",
                                                               &domain_obj);
        const char *date_format = nc_json_str_def(v, "date_format", "");
        sqlite3_stmt *st = NULL;
        struct json_object *tmp = NULL;
        int idx = 1;

        if (hn[0] && !nc_sys_hostname_ok(hn)) {
            nc_exec("ROLLBACK");
            return -1;
        }
        if (custom_domain_present) {
            if (!domain_obj || !json_object_is_type(domain_obj, json_type_string)) {
                nc_exec("ROLLBACK");
                return -1;
            }
            custom_domain = json_object_get_string(domain_obj);
            if (!nc_sys_custom_domain_ok(custom_domain)) {
                nc_exec("ROLLBACK");
                return -1;
            }
        }
        if (date_format[0] && !nc_sys_date_format_valid(date_format)) {
            nc_exec("ROLLBACK");
            return -1;
        }
        if (nc_prepare(&st,
            "UPDATE system_settings SET "
            "hostname=CASE WHEN ?!='' THEN ? ELSE hostname END,"
            "custom_domain=CASE WHEN ? IS NOT NULL THEN ? ELSE custom_domain END,"
            "language=COALESCE(NULLIF(?,''),language),"
            "description=CASE WHEN ? IS NOT NULL THEN ? ELSE description END,"
            "note=CASE WHEN ? IS NOT NULL THEN ? ELSE note END,"
            "time_format=COALESCE(NULLIF(?,''),time_format),"
            "date_format=COALESCE(NULLIF(?,''),date_format),"
            "show_timezone_name=CASE WHEN ? IS NOT NULL THEN ? ELSE show_timezone_name END,"
            "table_filter=CASE WHEN ? IS NOT NULL THEN ? ELSE table_filter END,"
            "interface_density=CASE WHEN ? IS NOT NULL THEN ? ELSE interface_density END,"
            "number_format=CASE WHEN ? IS NOT NULL THEN ? ELSE number_format END,"
            "apply_state='pending',apply_error='',"
            "updated_at=? WHERE id=1") == 0) {
            sqlite3_bind_text(st, idx++, hn, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, idx++, hn, -1, SQLITE_TRANSIENT);
            if (custom_domain_present) {
                sqlite3_bind_int(st, idx++, 1);
                sqlite3_bind_text(st, idx++, custom_domain, -1, SQLITE_TRANSIENT);
            } else {
                sqlite3_bind_null(st, idx++);
                sqlite3_bind_null(st, idx++);
            }
            sqlite3_bind_text(st, idx++, nc_json_str_def(v, "language", ""), -1, SQLITE_TRANSIENT);

#define NC_BIND_OPT_TEXT_FIELD(_field) \
            do { \
                if (json_object_object_get_ex(v, (_field), &tmp)) { \
                    sqlite3_bind_int(st, idx++, 1); \
                    sqlite3_bind_text(st, idx++, json_object_get_string(tmp), -1, SQLITE_TRANSIENT); \
                } else { \
                    sqlite3_bind_null(st, idx++); \
                    sqlite3_bind_null(st, idx++); \
                } \
            } while (0)
#define NC_BIND_OPT_BOOL_FIELD(_field) \
            do { \
                if (json_object_object_get_ex(v, (_field), &tmp)) { \
                    sqlite3_bind_int(st, idx++, 1); \
                    sqlite3_bind_int(st, idx++, json_object_get_boolean(tmp)); \
                } else { \
                    sqlite3_bind_null(st, idx++); \
                    sqlite3_bind_null(st, idx++); \
                } \
            } while (0)
            NC_BIND_OPT_TEXT_FIELD("description");
            NC_BIND_OPT_TEXT_FIELD("note");
            sqlite3_bind_text(st, idx++, nc_json_str_def(v, "time_format", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, idx++, nc_json_str_def(v, "date_format", ""), -1, SQLITE_TRANSIENT);
            NC_BIND_OPT_BOOL_FIELD("show_timezone_name");
            NC_BIND_OPT_BOOL_FIELD("table_filter");
            NC_BIND_OPT_TEXT_FIELD("interface_density");
            NC_BIND_OPT_TEXT_FIELD("number_format");
            sqlite3_bind_int64(st, idx++, now);
            if (nc_step_done(st) != 0) {
                sqlite3_finalize(st);
                nc_exec("ROLLBACK");
                return -1;
            }
            sqlite3_finalize(st);
#undef NC_BIND_OPT_TEXT_FIELD
#undef NC_BIND_OPT_BOOL_FIELD
        }
    }
    if (json_object_object_get_ex(cfg, "dreamingwrt", &v) && v) {
        struct json_object *dash = NULL;
        struct json_object *tmp = NULL;
        json_object_object_get_ex(v, "dashboard", &dash);
        sqlite3_stmt *st = NULL;
        if (nc_prepare(&st,
            "UPDATE system_ui_settings SET "
            "ui_mode=COALESCE(NULLIF(?,''),ui_mode),"
            "sidebar_collapsed=CASE WHEN ? IS NOT NULL THEN ? ELSE sidebar_collapsed END,"
            "default_view=COALESCE(NULLIF(?,''),default_view),"
            "show_status_rail=CASE WHEN ? IS NOT NULL THEN ? ELSE show_status_rail END,"
            "animation_level=COALESCE(NULLIF(?,''),animation_level),"
            "density=COALESCE(NULLIF(?,''),density),updated_at=? WHERE id=1") == 0) {
            sqlite3_bind_text(st, 1, nc_json_str_def(v, "ui_mode", ""), -1, SQLITE_TRANSIENT);
            if (json_object_object_get_ex(v, "sidebar_collapsed", &tmp)) {
                sqlite3_bind_int(st, 2, 1);
                sqlite3_bind_int(st, 3, json_object_get_boolean(tmp));
            } else {
                sqlite3_bind_null(st, 2);
                sqlite3_bind_null(st, 3);
            }
            sqlite3_bind_text(st, 4, dash ? nc_json_str_def(dash, "default_view", "") : "", -1, SQLITE_TRANSIENT);
            if (dash && json_object_object_get_ex(dash, "show_status_rail", &tmp)) {
                sqlite3_bind_int(st, 5, 1);
                sqlite3_bind_int(st, 6, json_object_get_boolean(tmp));
            } else {
                sqlite3_bind_null(st, 5);
                sqlite3_bind_null(st, 6);
            }
            sqlite3_bind_text(st, 7, dash ? nc_json_str_def(dash, "animation_level", "") : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 8, dash ? nc_json_str_def(dash, "density", "") : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 9, now);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    /*
     * advanced: conntrack timeouts and congestion control are runtime sysctls
     * with no column in system_settings, so they are applied to the kernel
     * rather than stored. Validation happens here as well as in the delta
     * filter, because a caller reaching this function directly must still be
     * refused a value that would break forwarding.
     */
    if (json_object_object_get_ex(cfg, "advanced", &v) && v) {
        if (nc_adv_apply_runtime_sysctls(v) != 0) {
            if (db_txn) nc_exec("ROLLBACK");
            return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "ssh", &v) && v) {
        if (nc_sys_ssh_settings_apply(v) != 0) {
            if (db_txn) nc_exec("ROLLBACK");
            return -1;
        }
    }
    if (appearance_touched && nc_appearance_save(&appearance, now) != 0) {
        if (db_txn) nc_exec("ROLLBACK");
        return -1;
    }
    if (db_txn && nc_exec("COMMIT") != 0) {
        return -1;
    }
    if (appearance_touched) {
        struct json_object *event_data = json_object_new_object();
        struct json_object *event_wall = json_object_new_object();
        nc_appearance_to_json(&appearance, event_data, event_wall);
        json_object_object_add(event_data, "wallpaper", event_wall);
        jmx_events_emit("web.appearance", "updated", event_data);
        json_object_put(event_data);
    }
    return 0;
}

static int nc_sys_runtime_hostname_matches(const char *expected)
{
    char actual[128];

    if (!expected || gethostname(actual, sizeof(actual) - 1) != 0)
        return 0;
    actual[sizeof(actual) - 1] = '\0';
    return strcmp(actual, expected) == 0;
}

static int nc_sys_runtime_console_domain(char *out, size_t out_len)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int found = 0;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &pkg) != UCI_OK || !pkg)
        goto done;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *section = uci_to_section(e);
        const char *value;

        if (!section || strcmp(section->type, "system"))
            continue;
        value = uci_lookup_option_string(ctx, section, "console_domain");
        snprintf(out, out_len, "%s", value ? value : "");
        found = 1;
        break;
    }
done:
    if (ctx)
        uci_free_context(ctx);
    return found;
}

static int nc_sys_lan_ipv4(char *out, size_t out_len)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *lan;
    const char *value;
    char *slash;
    int prefix = 24;
    int ok = 0;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (nc_dhcp_lan_primary("lan", out, out_len, &prefix) &&
        nc_ipv4_ok(out))
        return 1;
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "network", &pkg) != UCI_OK || !pkg)
        goto done;
    lan = uci_lookup_section(ctx, pkg, "lan");
    value = lan ? uci_lookup_option_string(ctx, lan, "ipaddr") : NULL;
    if (value && value[0]) {
        snprintf(out, out_len, "%s", value);
        slash = strchr(out, '/');
        if (slash)
            *slash = '\0';
        ok = nc_ipv4_ok(out);
    }
done:
    if (ctx)
        uci_free_context(ctx);
    return ok;
}

static int nc_sys_uci_identity_matches(const char *hostname,
                                       const char *custom_domain,
                                       const char *dnsmasq_rule)
{
    struct uci_context *ctx = NULL;
    struct uci_package *system_pkg = NULL;
    struct uci_package *dhcp_pkg = NULL;
    struct uci_element *e;
    struct uci_section *system_section = NULL;
    struct uci_section *dnsmasq_section = NULL;
    const char *value;
    int matched = 0;

    if (!hostname || !custom_domain || !dnsmasq_rule ||
        !(ctx = uci_alloc_context()))
        return 0;
    if (uci_load(ctx, "system", &system_pkg) == UCI_OK && system_pkg) {
        uci_foreach_element(&system_pkg->sections, e) {
            struct uci_section *s = uci_to_section(e);

            if (!s || strcmp(s->type, "system"))
                continue;
            system_section = s;
            break;
        }
    }
    if (!system_section)
        goto done;
    value = uci_lookup_option_string(ctx, system_section, "hostname");
    if (!value || strcmp(value, hostname))
        goto done;
    value = uci_lookup_option_string(ctx, system_section, "console_domain");
    if (strcmp(value ? value : "", custom_domain))
        goto done;
    value = uci_lookup_option_string(ctx, system_section,
                                     "console_domain_address");
    if (strcmp(value ? value : "", dnsmasq_rule))
        goto done;
    if (!dnsmasq_rule[0]) {
        matched = 1;
        goto done;
    }
    if (uci_load(ctx, "dhcp", &dhcp_pkg) != UCI_OK || !dhcp_pkg)
        goto done;
    uci_foreach_element(&dhcp_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (s && !strcmp(s->type, "dnsmasq")) {
            dnsmasq_section = s;
            break;
        }
    }
    matched = dnsmasq_section &&
              nc_uci_list_has_value(dnsmasq_section, "address", dnsmasq_rule);
done:
    uci_free_context(ctx);
    return matched;
}

static int nc_sys_console_identity_refresh(void)
{
    if (access("/etc/init.d/dnsmasq", X_OK) != 0 ||
        nc_run_quiet("/etc/init.d/dnsmasq reload >/tmp/dw-console-dnsmasq.log 2>&1 || /etc/init.d/dnsmasq restart >>/tmp/dw-console-dnsmasq.log 2>&1") != 0)
        return -1;
    if (access("/etc/init.d/avahi-daemon", X_OK) != 0 ||
        nc_run_quiet("/etc/init.d/avahi-daemon restart >/tmp/dw-console-mdns.log 2>&1") != 0)
        return -1;
    if (access("/etc/init.d/dreamingwrt-mdns", X_OK) != 0 ||
        nc_run_quiet("/etc/init.d/dreamingwrt-mdns restart >>/tmp/dw-console-mdns.log 2>&1") != 0)
        return -1;
    if (access("/usr/libexec/dreamingwrt/dreamingwrt-web-tls-cert", X_OK) != 0 ||
        nc_run_quiet("/usr/libexec/dreamingwrt/dreamingwrt-web-tls-cert refresh >/tmp/dw-console-tls.log 2>&1") != 0)
        return -1;
    return 0;
}

/* Apply hostname, custom console domain, DNS, mDNS and TLS as one identity. */
int jmx_system_settings_apply(struct json_object *cfg)
{
    struct uci_context *ctx = NULL;
    struct uci_package *system_pkg = NULL;
    struct uci_package *dhcp_pkg = NULL;
    struct uci_element *e;
    struct uci_section *system_section = NULL;
    struct uci_section *dnsmasq_section = NULL;
    sqlite3_stmt *st = NULL;
    char hostname[128] = "";
    char custom_domain[254] = "";
    char lan_ip[64] = "";
    char old_rule[384] = "";
    char new_rule[384] = "";
    char old_runtime[128] = "";
    char system_backup[256] = "";
    char dhcp_backup[256] = "";
    int dry;
    int rc = -1;

    if (jmx_netconfig_db_init() != 0)
        return -1;
    nc_sys_settings_db_init();
    dry = nc_json_bool_def(cfg, "dry_run", 0);
    if (nc_prepare(&st, "SELECT hostname,custom_domain FROM system_settings WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *value = (const char *)sqlite3_column_text(st, 0);
        if (value)
            snprintf(hostname, sizeof(hostname), "%s", value);
        value = (const char *)sqlite3_column_text(st, 1);
        if (value)
            snprintf(custom_domain, sizeof(custom_domain), "%s", value);
        sqlite3_finalize(st);
        st = NULL;
    }
    if (!hostname[0] && gethostname(hostname, sizeof(hostname) - 1) == 0) {
        sqlite3_stmt *migrate = NULL;
        char *p;

        hostname[sizeof(hostname) - 1] = '\0';
        for (p = hostname; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        if (nc_sys_hostname_ok(hostname) &&
            nc_prepare(&migrate,
                "UPDATE system_settings SET hostname=?1,apply_state='pending',apply_error='',updated_at=strftime('%s','now') WHERE id=1") == 0) {
            sqlite3_bind_text(migrate, 1, hostname, -1, SQLITE_TRANSIENT);
            (void)nc_step_done(migrate);
            sqlite3_finalize(migrate);
        }
    }
    if (!nc_sys_hostname_ok(hostname) || !nc_sys_custom_domain_ok(custom_domain))
        goto failed;
    if (custom_domain[0] && !nc_sys_lan_ipv4(lan_ip, sizeof(lan_ip)))
        goto failed;
    if (custom_domain[0] &&
        snprintf(new_rule, sizeof(new_rule), "/%s/%s", custom_domain,
                 lan_ip) >= (int)sizeof(new_rule))
        goto failed;
    if (dry)
        return 0;
    if (gethostname(old_runtime, sizeof(old_runtime) - 1) != 0 ||
        nc_backup_config("system", system_backup, sizeof(system_backup)) != 0 ||
        nc_backup_config("dhcp", dhcp_backup, sizeof(dhcp_backup)) != 0)
        goto failed;
    old_runtime[sizeof(old_runtime) - 1] = '\0';
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &system_pkg) != UCI_OK || !system_pkg ||
        uci_load(ctx, "dhcp", &dhcp_pkg) != UCI_OK || !dhcp_pkg)
        goto rollback;
    uci_foreach_element(&system_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (s && !strcmp(s->type, "system")) {
            system_section = s;
            break;
        }
    }
    if (!system_section &&
        uci_add_section(ctx, system_pkg, "system", &system_section) != UCI_OK)
        goto rollback;
    uci_foreach_element(&dhcp_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (s && !strcmp(s->type, "dnsmasq")) {
            dnsmasq_section = s;
            break;
        }
    }
    if (!dnsmasq_section &&
        uci_add_section(ctx, dhcp_pkg, "dnsmasq", &dnsmasq_section) != UCI_OK)
        goto rollback;
    {
        const char *managed = uci_lookup_option_string(
            ctx, system_section, "console_domain_address");
        if (managed)
            snprintf(old_rule, sizeof(old_rule), "%s", managed);
    }
    if (old_rule[0] &&
        nc_uci_del_list_pkg(ctx, "dhcp", dnsmasq_section->e.name,
                            "address", old_rule) != UCI_OK)
        goto rollback;
    if (new_rule[0] &&
        !nc_uci_list_has_value(dnsmasq_section, "address", new_rule) &&
        nc_uci_add_list_pkg(ctx, "dhcp", dnsmasq_section->e.name,
                            "address", new_rule) != UCI_OK)
        goto rollback;
    if (nc_uci_set_pkg(ctx, "system", system_section->e.name, "hostname",
                       hostname) != UCI_OK)
        goto rollback;
    if (custom_domain[0]) {
        if (nc_uci_set_pkg(ctx, "system", system_section->e.name,
                           "console_domain", custom_domain) != UCI_OK ||
            nc_uci_set_pkg(ctx, "system", system_section->e.name,
                           "console_domain_address", new_rule) != UCI_OK)
            goto rollback;
    } else if (nc_uci_delete_pkg(ctx, "system", system_section->e.name,
                                 "console_domain") != UCI_OK ||
               nc_uci_delete_pkg(ctx, "system", system_section->e.name,
                                 "console_domain_address") != UCI_OK) {
        goto rollback;
    }
    if (jmx_uci_commit(ctx, "dhcp") != UCI_OK ||
        jmx_uci_commit(ctx, "system") != UCI_OK ||
        sethostname(hostname, strlen(hostname)) != 0 ||
        !nc_sys_uci_identity_matches(hostname, custom_domain, new_rule) ||
        !nc_sys_runtime_hostname_matches(hostname) ||
        nc_sys_console_identity_refresh() != 0)
        goto rollback;
    rc = 0;
    goto done;

rollback:
    nc_restore_config("system", system_backup);
    nc_restore_config("dhcp", dhcp_backup);
    if (old_runtime[0])
        /*
         * Best-effort restore on a path that is already failing; there is no
         * better recovery than the failure we are reporting, so the result is
         * deliberately discarded rather than checked.
         */
        (void)!sethostname(old_runtime, strlen(old_runtime));
    (void)nc_sys_console_identity_refresh();
failed:
    nc_exec("UPDATE system_settings SET apply_state='failed',apply_error='console_identity_apply_or_readback_failed',updated_at=strftime('%s','now') WHERE id=1");
done:
    if (ctx)
        uci_free_context(ctx);
    nc_cleanup_backup(system_backup);
    nc_cleanup_backup(dhcp_backup);
    if (rc == 0)
        nc_exec("UPDATE system_settings SET apply_state='console_identity_applied',last_apply_at=strftime('%s','now'),apply_error='',updated_at=strftime('%s','now') WHERE id=1");
    return rc;
}

static int nc_sys_json_equal(struct json_object *left, struct json_object *right)
{
    enum json_type lt;
    enum json_type rt;

    if (left == right)
        return 1;
    if (!left || !right)
        return 0;
    lt = json_object_get_type(left);
    rt = json_object_get_type(right);
    if ((lt == json_type_int || lt == json_type_double) &&
        (rt == json_type_int || rt == json_type_double))
        return json_object_get_double(left) == json_object_get_double(right);
    if (lt != rt)
        return 0;
    switch (lt) {
    case json_type_null:
        return 1;
    case json_type_boolean:
        return json_object_get_boolean(left) == json_object_get_boolean(right);
    case json_type_string:
        return !strcmp(json_object_get_string(left), json_object_get_string(right));
    case json_type_array: {
        int count = json_object_array_length(left);

        if (count != json_object_array_length(right))
            return 0;
        for (int i = 0; i < count; i++) {
            if (!nc_sys_json_equal(json_object_array_get_idx(left, i),
                                   json_object_array_get_idx(right, i)))
                return 0;
        }
        return 1;
    }
    case json_type_object:
        if (json_object_object_length(left) != json_object_object_length(right))
            return 0;
        json_object_object_foreach(left, key, value) {
            struct json_object *other = NULL;

            if (!json_object_object_get_ex(right, key, &other) ||
                !nc_sys_json_equal(value, other))
                return 0;
        }
        return 1;
    default:
        return 0;
    }
}

static int nc_sys_name_in_list(const char *name, const char *const *names)
{
    if (!name || !names)
        return 0;
    for (int i = 0; names[i]; i++) {
        if (!strcmp(name, names[i]))
            return 1;
    }
    return 0;
}

/* Account for values the Web normalizer projects from an empty legacy value. */
static int nc_sys_projected_value_equal(const char *section, const char *field,
                                        struct json_object *requested,
                                        struct json_object *current)
{
    if (nc_sys_json_equal(requested, current))
        return 1;
    if (!strcmp(section, "general") && current) {
        const char *old = json_object_get_string(current);
        const char *next = json_object_get_string(requested);

        if (!strcmp(field, "log_level") && old && next && !old[0] &&
            !strcmp(next, "warning"))
            return 1;
        if (!strcmp(field, "cron_log_level") && old && next &&
            !strcmp(old, "disabled") && !strcmp(next, "error"))
            return 1;
        if (!strcmp(field, "log_buffer_kb") &&
            json_object_get_int(current) == 0 && json_object_get_int(requested) == 128)
            return 1;
    }
    if (!strcmp(section, "advanced") && !strcmp(field, "zram_size_mb") &&
        current && json_object_get_int(current) == 0 &&
        json_object_get_int(requested) == 256)
        return 1;
    return 0;
}

static struct json_object *nc_sys_response_data(struct json_object *response)
{
    struct json_object *data = NULL;

    if (response && json_object_object_get_ex(response, "data", &data) && data)
        return data;
    return NULL;
}

/*
 * Error responses used to carry only a machine token in `reason`, and webd
 * copies that token straight into `error.message`, so the save bar rendered
 * bare strings like `transactional_runtime_executor_pending`. Produce a human
 * readable sentence here while leaving `error`/`field`/`capability`/`reason`
 * untouched for callers that key off them.
 *
 * The caller supplies the buffer: core creates worker threads, so a shared
 * static would be a data race.
 */
static const char *nc_sys_settings_reason_message(char *message, size_t len,
                                                 const char *error,
                                                 const char *field,
                                                 const char *capability,
                                                 const char *reason)
{
    const char *path = (field && field[0]) ? field : "system_settings";
    const char *cap = (capability && capability[0]) ? capability : "";

    if (!message || !len)
        return "";
    if (error && !strcmp(error, "capability_disabled")) {
        snprintf(message, len,
                 "'%s' cannot be changed on this build: capability '%s' is "
                 "disabled and the runtime executor is not available yet.",
                 path, cap);
        return message;
    }
    if (error && !strcmp(error, "invalid_request")) {
        snprintf(message, len,
                 "system settings payload must be a JSON object");
        return message;
    }
    if (error && !strcmp(error, "source_unavailable")) {
        snprintf(message, len,
                 "current system settings snapshot could not be read, so no "
                 "change was attempted");
        return message;
    }
    if (error && !strcmp(error, "snapshot_failed")) {
        snprintf(message, len,
                 "rollback snapshot could not be built, so no change was "
                 "attempted");
        return message;
    }
    if (error && !strcmp(error, "apply_failed")) {
        snprintf(message, len,
                 "applying '%s' failed and the previous values were restored",
                 path);
        return message;
    }
    if (error && !strcmp(error, "rollback_failed")) {
        snprintf(message, len,
                 "applying '%s' failed and restoring the previous values also "
                 "failed; settings may be partially written",
                 path);
        return message;
    }
    if (error && !strcmp(error, "no_writable_fields")) {
        snprintf(message, len,
                 "none of the submitted fields are writable on this build; see "
                 "field_results for the per-field reason");
        return message;
    }
    if (error && !strcmp(error, "allocation_failed")) {
        snprintf(message, len,
                 "system settings save could not allocate its field result map; "
                 "no change was attempted");
        return message;
    }
    snprintf(message, len, "system settings save rejected: %s",
             (reason && reason[0]) ? reason : (error ? error : "unknown"));
    return message;
}

static struct json_object *nc_sys_settings_error(const char *error,
                                                  const char *field,
                                                  const char *capability,
                                                  const char *reason)
{
    struct json_object *data = json_object_new_object();
    struct json_object *result = json_object_new_object();
    struct json_object *results = json_object_new_object();
    char message[320];

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(error));
    json_object_object_add(data, "field", json_object_new_string(field ? field : ""));
    json_object_object_add(data, "capability",
                           json_object_new_string(capability ? capability : ""));
    json_object_object_add(data, "reason", json_object_new_string(reason));
    json_object_object_add(data, "message",
                           json_object_new_string(
                               nc_sys_settings_reason_message(message,
                                                             sizeof(message),
                                                             error, field,
                                                             capability, reason)));
    json_object_object_add(data, "persisted", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(result, "supported", json_object_new_boolean(0));
    json_object_object_add(result, "persisted", json_object_new_boolean(0));
    json_object_object_add(result, "applied", json_object_new_boolean(0));
    json_object_object_add(result, "running", json_object_new_boolean(0));
    json_object_object_add(result, "capability",
                           json_object_new_string(capability ? capability : ""));
    json_object_object_add(result, "reason", json_object_new_string(reason));
    json_object_object_add(results, field ? field : "unknown", result);
    json_object_object_add(data, "field_results", results);
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static void nc_sys_field_result(struct json_object *results, const char *field,
                                int persisted, int applied, int running,
                                const char *state)
{
    struct json_object *result = json_object_new_object();

    json_object_object_add(result, "supported", json_object_new_boolean(1));
    json_object_object_add(result, "persisted", json_object_new_boolean(persisted));
    json_object_object_add(result, "applied", json_object_new_boolean(applied));
    json_object_object_add(result, "running", json_object_new_boolean(running));
    json_object_object_add(result, "state", json_object_new_string(state));
    json_object_object_add(results, field, result);
}

static void nc_sys_runtime_field_result(struct json_object *results,
                                        const char *field, int persisted,
                                        int applied, int running, int rollback,
                                        int reboot_required,
                                        const char *state,
                                        const char *reason)
{
    struct json_object *result;

    if (!results || !field)
        return;
    result = json_object_new_object();
    if (!result)
        return;
    json_object_object_add(result, "supported", json_object_new_boolean(1));
    json_object_object_add(result, "persisted",
                           json_object_new_boolean(persisted));
    json_object_object_add(result, "applied",
                           json_object_new_boolean(applied));
    json_object_object_add(result, "running",
                           json_object_new_boolean(running));
    json_object_object_add(result, "rollback",
                           json_object_new_boolean(rollback));
    json_object_object_add(result, "reboot_required",
                           json_object_new_boolean(reboot_required));
    json_object_object_add(result, "state",
                           json_object_new_string(state ? state : "unknown"));
    json_object_object_add(result, "reason",
                           json_object_new_string(reason ? reason : ""));
    json_object_object_add(results, field, result);
}

static const char *nc_sys_general_capability(const char *field)
{
    static const char *const time_fields[] = {
        "time_sync", "ntp_mode", "ntp_interval",
        "ntp_server_enabled", "ntp_use_dhcp", "ntp_servers", NULL
    };
    static const char *const log_fields[] = {
        "log_level", "kernel_log_level", "log_buffer_kb", "cron_log_level",
        "remote_log_enabled", "remote_log_host", "remote_log_port",
        "remote_log_protocol", "log_file_path", NULL
    };

    if (nc_sys_name_in_list(field, time_fields))
        return "general_time_write";
    if (nc_sys_name_in_list(field, log_fields))
        return "general_logs_write";
    return "system_settings_runtime_write";
}

static int nc_sys_date_format_valid(const char *value)
{
    static const char *const formats[] = {
        "M/D/YY", "D/M/YY", "M/D/YYYY", "DD/MM/YYYY", "DD.MM.YYYY",
        "DD-MM-YYYY", "YYYY/M/D", "YYYY.MM.DD", "YYYY-MM-DD", NULL
    };
    return nc_sys_name_in_list(value ? value : "", formats);
}

static const char *nc_sys_advanced_capability(const char *field)
{
    if (!strncmp(field, "zram_", 5))
        return "zram_write";
    /* Names the real gate so the UI can grey the control and say why. */
    if (nc_adv_conntrack_find(field))
        return "advanced_conntrack_timeouts_write";
    if (!strcmp(field, "tcp_congestion_control") || !strcmp(field, "tcp_bbr"))
        return "advanced_tcp_congestion_write";
    if (!strncmp(field, "alg_", 4))
        return "advanced_alg_write";
    if (!strcmp(field, "packet_steering"))
        return "advanced_packet_steering";
    if (!strcmp(field, "irq_balance"))
        return "advanced_irq_balance";
    if (!strcmp(field, "flow_offloading"))
        return "advanced_flow_offloading";
    if (!strcmp(field, "kernel_slim_mode"))
        return "advanced_kernel_slim_mode";
    if (!strcmp(field, "scheduler_priority"))
        return "advanced_scheduler_priority";
    if (!strcmp(field, "collect_diagnostics"))
        return "advanced_collect_diagnostics";
    if (!strcmp(field, "crash_dump"))
        return "advanced_crash_dump";
    return "advanced_runtime_write";
}

static int nc_sys_runtime_field_writable(const char *section,
                                         const char *field)
{
    if (!strcmp(section, "general")) {
        if (!strcmp(field, "log_level"))
            return 0;
        if (!strcmp(nc_sys_general_capability(field), "general_time_write"))
            return nc_ssr_time_writable();
        if (!strcmp(nc_sys_general_capability(field), "general_logs_write"))
            return nc_ssr_log_writable();
        return 1;
    }
    if (!strcmp(section, "advanced")) {
        if (!strcmp(nc_sys_advanced_capability(field), "zram_write"))
            return nc_ssr_zram_writable();
        if (!strcmp(nc_sys_advanced_capability(field), "advanced_alg_write"))
            return nc_alg_group_writable();
    }
    return 1;
}

/*
 * Records one field the delta builder refused to write. The caller keeps
 * collecting writable fields, so a single gated field no longer voids the whole
 * form; the rejected set is returned to the client in `field_results`.
 */
static void nc_sys_denied_field_result(struct json_object *results,
                                       const char *section, const char *field,
                                       const char *capability)
{
    struct json_object *result;
    const char *reason = (!strcmp(section, "general") &&
                          !strcmp(field, "log_level")) ?
                         "local_log_level_unsupported_by_logd" :
                         "capability_disabled";
    char path[192];
    char message[320];

    if (!results)
        return;
    snprintf(path, sizeof(path), "%s.%s", section, field);
    result = json_object_new_object();
    if (!result)
        return;
    json_object_object_add(result, "supported", json_object_new_boolean(0));
    json_object_object_add(result, "persisted", json_object_new_boolean(0));
    json_object_object_add(result, "applied", json_object_new_boolean(0));
    json_object_object_add(result, "running", json_object_new_boolean(0));
    json_object_object_add(result, "state", json_object_new_string("rejected"));
    json_object_object_add(result, "capability",
                           json_object_new_string(capability ? capability : ""));
    json_object_object_add(result, "reason",
                           json_object_new_string(reason));
    json_object_object_add(result, "message",
                           json_object_new_string(
                               nc_sys_settings_reason_message(message,
                                                             sizeof(message),
                                                             reason,
                                                             path, capability,
                                                             reason)));
    json_object_object_add(results, path, result);
}

static int nc_sys_add_changed_fields(struct json_object *target,
                                     struct json_object *requested,
                                     struct json_object *current,
                                     const char *section,
                                     const char *const *writable,
                                     const char *const *read_only,
                                     struct json_object *denied)
{
    json_object_object_foreach(requested, field, value) {
        struct json_object *old = NULL;

        if (current)
            json_object_object_get_ex(current, field, &old);
        if (nc_sys_name_in_list(field, read_only))
            continue;
        if (nc_sys_projected_value_equal(section, field, value, old))
            continue;
        if (!nc_sys_name_in_list(field, writable)) {
            /*
             * Skip instead of aborting. A gated field used to void the entire
             * request, so one closed capability (a log level, a timezone) made
             * the writable fields next to it, including the hostname, fail with
             * it.
             */
            nc_sys_denied_field_result(denied, section, field,
                                       !strcmp(section, "general") ?
                                       nc_sys_general_capability(field) :
                                       nc_sys_advanced_capability(field));
            continue;
        }
        if (!nc_sys_runtime_field_writable(section, field)) {
            nc_sys_denied_field_result(denied, section, field,
                                       !strcmp(section, "general") ?
                                       nc_sys_general_capability(field) :
                                       nc_sys_advanced_capability(field));
            continue;
        }
        json_object_object_add(target, field, json_object_get(value));
    }
    return 0;
}

static struct json_object *nc_sys_build_settings_delta(
    struct json_object *cfg, struct json_object *current,
    const char **denied_field, const char **denied_capability,
    struct json_object *denied)
{
    static const char *const general_writable[] = {
        "hostname", "custom_domain", "description", "note", "time_format", "date_format", "show_timezone_name",
        "language", "table_filter", "interface_density", "number_format",
        "timezone", "time_sync", "ntp_mode", "ntp_interval",
        "ntp_server_enabled", "ntp_use_dhcp", "ntp_servers",
        "kernel_log_level", "log_buffer_kb", "cron_log_level",
        "remote_log_enabled", "remote_log_host", "remote_log_port",
        "remote_log_protocol", "log_file_path", NULL
    };
    /*
     * Derived or observed values that GET reports but no writer accepts. They
     * are skipped outright rather than reported as rejections, because the Web
     * echoes the whole snapshot back and a read-only key drifting is not a
     * user-visible failure.
     */
    static const char *const general_read_only[] = {
        "model", "version", "configured_hostname", "runtime_hostname",
        "hostname_in_sync", "apply_state", "last_apply_at", "apply_error",
        "last_time_sync_at", "version_source", "version_error", NULL
    };
    /*
     * Previously an empty list, which silently dropped every advanced.* field
     * the user edited. Only knobs that are genuinely applied belong here: the
     * conntrack timeouts and congestion control, all plain sysctls. ALG
     * helpers, kernel_slim_mode, scheduler_priority, crash_dump and
     * collect_diagnostics stay out until they are actually implemented, so they
     * are refused by name with a capability reason instead of being accepted
     * and ignored.
     */
    static const char *const advanced_writable[] = {
        "nf_tcp_syn_sent", "nf_tcp_syn_recv", "nf_tcp_established",
        "nf_tcp_fin_wait", "nf_tcp_close_wait", "nf_tcp_last_ack",
        "nf_tcp_time_wait", "nf_tcp_close", "nf_udp_timeout",
        "nf_udp_stream", "nf_icmp_timeout",
        "tcp_congestion_control", "zram_size_mb", "zram_algorithm",
        "alg_ftp", "alg_ftp_ports", "alg_tftp", "alg_tftp_ports",
        "alg_sip", "alg_sip_ports", "alg_h323", NULL
    };
    static const char *const advanced_read_only[] = {
        "memory_total_mb", "zram_enabled", "zram_priority",
        "zram_memory_threshold", "cpu_interrupts", "nic_interrupts",
        "config_backend", "interrupt_runtime_source", "disabled_func_path",
        /* Observed device state and metadata: echoed back, never written. */
        "conntrack_meta", "alg_meta", "conntrack_persistent",
        "tcp_congestion_available", "tcp_congestion_writable",
        "packet_steering_value", "packet_steering_source",
        "irq_balance_installed", "irq_balance_running", "irq_balance_source",
        "irq_balance_reason",
        "flow_offloading_uci_sw", "flow_offloading_uci_hw",
        "flow_offloading_flowtables", "flow_offloading_source",
        "disabled_functions",
        NULL
    };
    static const char *const ssh_writable[] = {
        "enabled", "port", "password_login", "keyboard_interactive_login",
        "root_password_login", "key_only", "idle_timeout_min",
        "authorized_keys", "authorized_keys_text", NULL
    };
    static const char *const ssh_read_only[] = {
        "provider", "config_path", "authorized_keys_path",
        "authorized_keys_count", "key_management", NULL
    };
    static const char *const dreamingwrt_writable[] = {
        "ui_mode", "sidebar_collapsed", "accent_color", "glass_opacity",
        "glass_highlight", "glass_blur", "glass_saturate", "material_glass",
        "menu_liquid_glass", "wallpaper", "dashboard", NULL
    };
    static const char *const dreamingwrt_read_only[] = {
        "signature_update", NULL
    };
    struct json_object *delta = json_object_new_object();
    struct json_object *requested = NULL;
    struct json_object *observed = NULL;
    struct json_object *part = NULL;
    static const char *const accepted_sections[] = {
        "general", "advanced", "ssh", "dreamingwrt", NULL
    };

    if (!delta)
        return NULL;
    json_object_object_foreach(cfg, section_name, ignored) {
        size_t path_len;
        char *path;

        (void)ignored;
        if (nc_sys_name_in_list(section_name, accepted_sections))
            continue;
        path_len = strlen(section_name) + sizeof("system_settings.");
        path = malloc(path_len);
        if (path)
            snprintf(path, path_len, "system_settings.%s", section_name);
        *denied_field = path ? path : "system_settings.unknown";
        *denied_capability = "system_settings_section_write";
        json_object_put(delta);
        return NULL;
    }
#define NC_SYS_FILTER_SECTION(_name, _writable, _readonly) \
    do { \
        requested = observed = NULL; \
        if (json_object_object_get_ex(cfg, (_name), &requested) && requested && \
            json_object_is_type(requested, json_type_object)) { \
            json_object_object_get_ex(current, (_name), &observed); \
            part = json_object_new_object(); \
            if (!part || nc_sys_add_changed_fields(part, requested, observed, (_name), \
                                                    (_writable), (_readonly), \
                                                    denied) != 0) { \
                if (part) json_object_put(part); \
                json_object_put(delta); \
                return NULL; \
            } \
            if (json_object_object_length(part) > 0) \
                json_object_object_add(delta, (_name), part); \
            else \
                json_object_put(part); \
        } \
    } while (0)
    NC_SYS_FILTER_SECTION("general", general_writable, general_read_only);
    NC_SYS_FILTER_SECTION("advanced", advanced_writable, advanced_read_only);
    NC_SYS_FILTER_SECTION("ssh", ssh_writable, ssh_read_only);
    NC_SYS_FILTER_SECTION("dreamingwrt", dreamingwrt_writable,
                          dreamingwrt_read_only);
#undef NC_SYS_FILTER_SECTION
    return delta;
}

static struct json_object *nc_sys_settings_snapshot(struct json_object *delta,
                                                     struct json_object *current)
{
    struct json_object *snapshot = json_object_new_object();

    if (!snapshot)
        return NULL;
    json_object_object_foreach(delta, section, ignored) {
        struct json_object *old = NULL;

        (void)ignored;
        if (json_object_object_get_ex(current, section, &old) && old)
            json_object_object_add(snapshot, section, json_object_get(old));
    }
    return snapshot;
}

static void nc_sys_settings_add_changed_results(struct json_object *results,
                                                 struct json_object *delta,
                                                 int applied)
{
    json_object_object_foreach(delta, section, fields) {
        if (!json_object_is_type(fields, json_type_object))
            continue;
        json_object_object_foreach(fields, field, ignored) {
            char path[160];
            struct json_object *existing = NULL;

            (void)ignored;
            snprintf(path, sizeof(path), "%s.%s", section, field);
            if (json_object_object_get_ex(results, path, &existing))
                continue;
            if (!strcmp(path, "general.hostname") ||
                !strcmp(path, "general.custom_domain"))
                nc_sys_field_result(results, path, 1, applied, applied,
                                    applied ? "applied_verified" : "apply_failed");
            else if (!strcmp(section, "general"))
                nc_sys_field_result(results, path, 1, 0, 0, "saved_only");
            else
                nc_sys_field_result(results, path, 1, 1, 1, "applied_verified");
        }
    }
}

static int nc_sys_object_has_any(struct json_object *object,
                                 const char *const *fields)
{
    size_t i;

    if (!object || !json_object_is_type(object, json_type_object))
        return 0;
    for (i = 0; fields[i]; i++) {
        struct json_object *value = NULL;

        if (json_object_object_get_ex(object, fields[i], &value))
            return 1;
    }
    return 0;
}

static void nc_sys_copy_text(char *out, size_t out_len, const char *value)
{
    if (!out || !out_len)
        return;
    snprintf(out, out_len, "%s", value ? value : "");
}

static void nc_sys_ssr_results(struct json_object *results,
                               const char *section,
                               struct json_object *mask,
                               const char *const *fields,
                               const struct ssr_result *runtime,
                               const char *fallback_reason)
{
    const struct ssr_field_result *group = NULL;
    const char *reason;
    size_t i;

    if (!results || !runtime)
        return;
    if (runtime->field_count > 0)
        group = &runtime->fields[0];
    reason = runtime->error[0] ? runtime->error : fallback_reason;
    for (i = 0; fields[i]; i++) {
        struct json_object *ignored = NULL;
        char path[160];

        if (!json_object_object_get_ex(mask, fields[i], &ignored))
            continue;
        snprintf(path, sizeof(path), "%s.%s", section, fields[i]);
        nc_sys_runtime_field_result(results, path,
            group ? group->persisted : 0,
            group ? group->applied : 0,
            group ? group->running : 0,
            group ? group->rollback : runtime->rollback_ok,
            runtime->reboot_required,
            runtime->ok ? "applied_verified" : "apply_failed",
            runtime->ok ? "runtime_readback_verified" : reason);
    }
}

static int nc_sys_time_settings_patch(struct ssr_time_settings *settings,
                                      struct json_object *values,
                                      char *reason, size_t reason_len)
{
    struct json_object *value = NULL;

    if (json_object_object_get_ex(values, "timezone", &value))
        nc_sys_copy_text(settings->timezone, sizeof(settings->timezone),
                         json_object_get_string(value));
    if (json_object_object_get_ex(values, "time_sync", &value))
        settings->client_enabled = json_object_get_boolean(value);
    if (json_object_object_get_ex(values, "ntp_mode", &value)) {
        const char *mode = json_object_get_string(value);

        if (!strcmp(mode, "client")) {
            settings->client_enabled = 1;
            settings->server_enabled = 0;
        } else if (!strcmp(mode, "server")) {
            settings->client_enabled = 0;
            settings->server_enabled = 1;
        } else if (!strcmp(mode, "both")) {
            settings->client_enabled = 1;
            settings->server_enabled = 1;
        } else if (!strcmp(mode, "disabled")) {
            settings->client_enabled = 0;
            settings->server_enabled = 0;
        } else {
            snprintf(reason, reason_len, "invalid_ntp_mode");
            return -1;
        }
    }
    if (json_object_object_get_ex(values, "ntp_interval", &value))
        nc_sys_copy_text(settings->interval, sizeof(settings->interval),
                         json_object_get_string(value));
    if (json_object_object_get_ex(values, "ntp_server_enabled", &value))
        settings->server_enabled = json_object_get_boolean(value);
    if (json_object_object_get_ex(values, "ntp_use_dhcp", &value))
        settings->use_dhcp = json_object_get_boolean(value);
    if (json_object_object_get_ex(values, "ntp_servers", &value)) {
        int count;
        int i;

        if (!json_object_is_type(value, json_type_array)) {
            snprintf(reason, reason_len, "invalid_ntp_servers");
            return -1;
        }
        count = json_object_array_length(value);
        if (count < 0 || count > (int)SSR_TIME_SERVERS_MAX) {
            snprintf(reason, reason_len, "too_many_ntp_servers");
            return -1;
        }
        settings->server_count = 0;
        for (i = 0; i < count; i++) {
            struct json_object *server = json_object_array_get_idx(value, i);
            const char *text_value;

            if (!server || !json_object_is_type(server, json_type_string)) {
                snprintf(reason, reason_len, "invalid_ntp_server");
                return -1;
            }
            text_value = json_object_get_string(server);
            if (!text_value || strlen(text_value) > SSR_SERVER_MAX) {
                snprintf(reason, reason_len, "invalid_ntp_server");
                return -1;
            }
            nc_sys_copy_text(settings->servers[settings->server_count],
                             sizeof(settings->servers[0]), text_value);
            settings->server_count++;
        }
    }
    return 0;
}

static int nc_sys_log_settings_patch(struct ssr_log_settings *settings,
                                     struct json_object *values)
{
    struct json_object *value = NULL;

    if (!settings->cron_level[0])
        nc_sys_copy_text(settings->cron_level, sizeof(settings->cron_level),
                         "disabled");
    if (settings->buffer_kib == 0)
        settings->buffer_kib = 128U;
    if (settings->remote_port == 0)
        settings->remote_port = 514U;
    if (!settings->remote_protocol[0])
        nc_sys_copy_text(settings->remote_protocol,
                         sizeof(settings->remote_protocol), "udp");
    if (!settings->file_path[0])
        nc_sys_copy_text(settings->file_path, sizeof(settings->file_path),
                         "/tmp/system.log");
    if (json_object_object_get_ex(values, "kernel_log_level", &value))
        nc_sys_copy_text(settings->kernel_level, sizeof(settings->kernel_level),
                         json_object_get_string(value));
    if (json_object_object_get_ex(values, "cron_log_level", &value))
        nc_sys_copy_text(settings->cron_level, sizeof(settings->cron_level),
                         json_object_get_string(value));
    if (json_object_object_get_ex(values, "log_buffer_kb", &value))
        settings->buffer_kib = (unsigned int)json_object_get_int64(value);
    if (json_object_object_get_ex(values, "remote_log_enabled", &value))
        settings->remote_enabled = json_object_get_boolean(value);
    if (json_object_object_get_ex(values, "remote_log_host", &value))
        nc_sys_copy_text(settings->remote_host, sizeof(settings->remote_host),
                         json_object_get_string(value));
    if (json_object_object_get_ex(values, "remote_log_port", &value))
        settings->remote_port = (unsigned int)json_object_get_int64(value);
    if (json_object_object_get_ex(values, "remote_log_protocol", &value))
        nc_sys_copy_text(settings->remote_protocol,
                         sizeof(settings->remote_protocol),
                         json_object_get_string(value));
    if (json_object_object_get_ex(values, "log_file_path", &value))
        nc_sys_copy_text(settings->file_path, sizeof(settings->file_path),
                         json_object_get_string(value));
    settings->local_level[0] = '\0';
    return 0;
}

static int nc_sys_runtime_apply(struct json_object *values,
                                struct json_object *mask,
                                struct json_object *results,
                                char *failed_field, size_t failed_field_len,
                                char *failed_reason, size_t failed_reason_len)
{
    static const char *const time_fields[] = {
        "time_sync", "ntp_mode", "ntp_interval",
        "ntp_server_enabled", "ntp_use_dhcp", "ntp_servers", NULL
    };
    static const char *const log_fields[] = {
        "kernel_log_level", "log_buffer_kb", "cron_log_level",
        "remote_log_enabled", "remote_log_host", "remote_log_port",
        "remote_log_protocol", "log_file_path", NULL
    };
    static const char *const zram_fields[] = {
        "zram_size_mb", "zram_algorithm", NULL
    };
    struct json_object *general_values = NULL;
    struct json_object *general_mask = NULL;
    struct json_object *advanced_values = NULL;
    struct json_object *advanced_mask = NULL;
    struct ssr_paths paths;
    char error[JMX_SYSTEM_ALG_ERROR_MAX] = "";

    ssr_paths_default(&paths);
    json_object_object_get_ex(values, "general", &general_values);
    json_object_object_get_ex(mask, "general", &general_mask);
    json_object_object_get_ex(values, "advanced", &advanced_values);
    json_object_object_get_ex(mask, "advanced", &advanced_mask);

    if (nc_sys_object_has_any(general_mask, time_fields)) {
        struct ssr_time_state state;
        struct ssr_result runtime;

        error[0] = '\0';
        ssr_result_reset(&runtime);
        if (ssr_time_readback(&paths, NULL, &state, error, sizeof(error)) != 0 ||
            nc_sys_time_settings_patch(&state.settings, general_values,
                                       error, sizeof(error)) != 0 ||
            ssr_time_apply(&paths, NULL, &state.settings, &runtime) != 0) {
            if (!runtime.error[0] && error[0])
                nc_sys_copy_text(runtime.error, sizeof(runtime.error), error);
            nc_sys_ssr_results(results, "general", general_mask, time_fields,
                               &runtime, "time_apply_failed");
            snprintf(failed_field, failed_field_len, "general.time_policy");
            snprintf(failed_reason, failed_reason_len, "%s",
                     runtime.error[0] ? runtime.error : "time_apply_failed");
            return -1;
        }
        nc_sys_ssr_results(results, "general", general_mask, time_fields,
                           &runtime, "runtime_readback_verified");
    }

    if (nc_sys_object_has_any(general_mask, log_fields)) {
        struct ssr_log_state state;
        struct ssr_result runtime;

        error[0] = '\0';
        ssr_result_reset(&runtime);
        if (ssr_log_readback(&paths, NULL, &state, error, sizeof(error)) != 0 ||
            nc_sys_log_settings_patch(&state.settings, general_values) != 0 ||
            ssr_log_apply(&paths, NULL, &state.settings, &runtime) != 0) {
            if (!runtime.error[0] && error[0])
                nc_sys_copy_text(runtime.error, sizeof(runtime.error), error);
            nc_sys_ssr_results(results, "general", general_mask, log_fields,
                               &runtime, "log_apply_failed");
            snprintf(failed_field, failed_field_len, "general.logging");
            snprintf(failed_reason, failed_reason_len, "%s",
                     runtime.error[0] ? runtime.error : "log_apply_failed");
            return -1;
        }
        nc_sys_ssr_results(results, "general", general_mask, log_fields,
                           &runtime, "runtime_readback_verified");
    }

    if (nc_sys_object_has_any(advanced_mask, zram_fields)) {
        struct ssr_zram_state state;
        struct ssr_result runtime;
        struct json_object *value = NULL;

        error[0] = '\0';
        ssr_result_reset(&runtime);
        memset(&state, 0, sizeof(state));
        if (ssr_zram_readback(&paths, NULL, &state, error, sizeof(error)) == 0) {
            if (json_object_object_get_ex(advanced_values, "zram_size_mb", &value))
                state.settings.size_mib = (uint64_t)json_object_get_int64(value);
            if (json_object_object_get_ex(advanced_values, "zram_algorithm", &value))
                nc_sys_copy_text(state.settings.algorithm,
                                 sizeof(state.settings.algorithm),
                                 json_object_get_string(value));
        }
        if (error[0] || ssr_zram_apply(&paths, NULL, &state.settings,
                                       &runtime) != 0) {
            if (!runtime.error[0] && error[0])
                nc_sys_copy_text(runtime.error, sizeof(runtime.error), error);
            nc_sys_ssr_results(results, "advanced", advanced_mask, zram_fields,
                               &runtime, "zram_apply_failed");
            snprintf(failed_field, failed_field_len, "advanced.zram");
            snprintf(failed_reason, failed_reason_len, "%s",
                     runtime.error[0] ? runtime.error : "zram_apply_failed");
            return -1;
        }
        nc_sys_ssr_results(results, "advanced", advanced_mask, zram_fields,
                           &runtime, "runtime_readback_verified");
    }

    if (advanced_mask) {
        size_t i;

        for (i = 0; i < sizeof(nc_adv_alg_helpers) /
                        sizeof(nc_adv_alg_helpers[0]); i++) {
            const nc_adv_alg_helper_t *entry = &nc_adv_alg_helpers[i];
            struct json_object *enabled_value = NULL;
            struct json_object *ports_value = NULL;
            struct jmx_system_alg_state before;
            struct jmx_system_alg_request request;
            struct jmx_system_alg_result runtime;
            enum jmx_system_alg_helper helper;
            int enabled_touched;
            int ports_touched;
            char path[160];

            enabled_touched = json_object_object_get_ex(advanced_mask,
                                                         entry->field,
                                                         &enabled_value);
            ports_touched = entry->ports_field &&
                json_object_object_get_ex(advanced_mask, entry->ports_field,
                                          &ports_value);
            if (!enabled_touched && !ports_touched)
                continue;
            error[0] = '\0';
            if (jmx_system_alg_helper_parse(entry->field + 4, &helper) !=
                    JMX_SYSTEM_ALG_OK ||
                jmx_system_alg_probe(NULL, helper, &before, error,
                                     sizeof(error)) != JMX_SYSTEM_ALG_OK) {
                snprintf(failed_field, failed_field_len, "advanced.%s",
                         entry->field);
                snprintf(failed_reason, failed_reason_len, "%s",
                         error[0] ? error : "alg_probe_failed");
                return -1;
            }
            memset(&request, 0, sizeof(request));
            memset(&runtime, 0, sizeof(runtime));
            request.helper = helper;
            request.enabled = before.running;
            if (json_object_object_get_ex(advanced_values, entry->field,
                                          &enabled_value))
                request.enabled = json_object_get_boolean(enabled_value);
            if (entry->ports_field &&
                json_object_object_get_ex(advanced_values, entry->ports_field,
                                          &ports_value) &&
                !json_object_is_type(ports_value, json_type_null))
                request.ports = json_object_get_string(ports_value);
            if (jmx_system_alg_apply(NULL, &request, &runtime) !=
                    JMX_SYSTEM_ALG_OK) {
                snprintf(path, sizeof(path), "advanced.%s", entry->field);
                nc_sys_runtime_field_result(results, path, 0,
                    runtime.applied, runtime.running_known && runtime.running,
                    runtime.rollback_succeeded, runtime.reboot_required,
                    "apply_failed", runtime.error[0] ? runtime.error :
                                    runtime.failure_stage);
                if (entry->ports_field && ports_touched) {
                    snprintf(path, sizeof(path), "advanced.%s",
                             entry->ports_field);
                    nc_sys_runtime_field_result(results, path,
                        0, runtime.applied,
                        runtime.running_known && runtime.running,
                        runtime.rollback_succeeded, runtime.reboot_required,
                        "apply_failed", runtime.error[0] ? runtime.error :
                                        runtime.failure_stage);
                }
                snprintf(failed_field, failed_field_len, "advanced.%s",
                         entry->field);
                snprintf(failed_reason, failed_reason_len, "%s",
                         runtime.error[0] ? runtime.error :
                         (runtime.failure_stage[0] ? runtime.failure_stage :
                                                    "alg_apply_failed"));
                return -1;
            }
            if (enabled_touched) {
                snprintf(path, sizeof(path), "advanced.%s", entry->field);
                nc_sys_runtime_field_result(results, path, 1,
                    runtime.applied, runtime.running_known && runtime.running,
                    0, runtime.reboot_required, "applied_verified",
                    "runtime_readback_verified");
            }
            if (entry->ports_field && ports_touched) {
                snprintf(path, sizeof(path), "advanced.%s",
                         entry->ports_field);
                nc_sys_runtime_field_result(results, path, 1,
                    runtime.applied, runtime.running_known && runtime.running,
                    0, runtime.reboot_required,
                    runtime.reboot_required ? "persisted_reboot_required" :
                                              "applied_verified",
                    runtime.reboot_required ? "ports_apply_on_next_module_load" :
                                              "runtime_readback_verified");
            }
        }
    }
    return 0;
}

static void nc_sys_mark_runtime_results_rolled_back(struct json_object *results,
                                                    struct json_object *rollback,
                                                    int rollback_ok)
{
    if (!results)
        return;
    json_object_object_foreach(results, path, result) {
        struct json_object *runtime_marker = NULL;
        struct json_object *restored = NULL;
        struct json_object *value = NULL;

        (void)path;
        if (!result || !json_object_is_type(result, json_type_object) ||
            !json_object_object_get_ex(result, "reboot_required",
                                       &runtime_marker))
            continue;
        json_object_object_add(result, "rollback",
                               json_object_new_boolean(rollback_ok));
        json_object_object_add(result, "state",
                               json_object_new_string(rollback_ok ?
                                                      "rolled_back" :
                                                      "rollback_failed"));
        json_object_object_add(result, "reason",
                               json_object_new_string(rollback_ok ?
                                  "compensated_after_group_failure" :
                                  "compensation_failed"));
        if (rollback_ok) {
            if (rollback && json_object_object_get_ex(rollback, path,
                                                      &restored) && restored) {
                if (json_object_object_get_ex(restored, "running", &value))
                    json_object_object_add(result, "running",
                                           json_object_get(value));
                if (json_object_object_get_ex(restored, "reboot_required",
                                              &value))
                    json_object_object_add(result, "reboot_required",
                                           json_object_get(value));
            }
            json_object_object_add(result, "persisted",
                                   json_object_new_boolean(0));
            json_object_object_add(result, "applied",
                                   json_object_new_boolean(0));
        }
    }
}

/* Folds the per-field rejections collected by the delta builder into the
 * response's field_results, so a caller sees both what was written and what was
 * refused in one place. */
static void nc_sys_merge_field_results(struct json_object *results,
                                       struct json_object *extra)
{
    if (!results || !extra)
        return;
    json_object_object_foreach(extra, path, value)
        json_object_object_add(results, path, json_object_get(value));
}

static void nc_sys_audit_value_summary(struct json_object *value,
                                       char *out, size_t out_len)
{
    if (!out || !out_len)
        return;
    if (!value || json_object_is_type(value, json_type_null))
        snprintf(out, out_len, "null");
    else if (json_object_is_type(value, json_type_boolean))
        snprintf(out, out_len, "bool:%s",
                 json_object_get_boolean(value) ? "true" : "false");
    else if (json_object_is_type(value, json_type_int))
        snprintf(out, out_len, "int:%lld",
                 (long long)json_object_get_int64(value));
    else if (json_object_is_type(value, json_type_double))
        snprintf(out, out_len, "number");
    else if (json_object_is_type(value, json_type_string))
        snprintf(out, out_len, "string:length=%zu",
                 strlen(json_object_get_string(value)));
    else if (json_object_is_type(value, json_type_array))
        snprintf(out, out_len, "array:count=%zu",
                 json_object_array_length(value));
    else if (json_object_is_type(value, json_type_object))
        snprintf(out, out_len, "object:keys=%d",
                 json_object_object_length(value));
    else
        snprintf(out, out_len, "unknown");
}

static void nc_sys_settings_audit(struct json_object *delta,
                                  struct json_object *before,
                                  struct json_object *results,
                                  int ok, int rollback_ok,
                                  const char *failure_reason)
{
    struct json_object *event;
    struct json_object *changes;
    char *detail;
    int bridged = 0;
    int bridge_failed = 0;
    char bridge_error[128] = "";

    if (!delta || !results || jmx_netconfig_db_init() != 0)
        return;
    nc_log_db_init();
    changes = json_object_new_array();
    if (!changes)
        return;
    json_object_object_foreach(delta, section, fields) {
        struct json_object *old_section = NULL;

        if (!fields || !json_object_is_type(fields, json_type_object))
            continue;
        if (before)
            json_object_object_get_ex(before, section, &old_section);
        json_object_object_foreach(fields, field, new_value) {
            struct json_object *old_value = NULL;
            struct json_object *field_result = NULL;
            struct json_object *item = json_object_new_object();
            char path[160];
            char old_summary[64];
            char new_summary[64];

            if (!item)
                continue;
            snprintf(path, sizeof(path), "%s.%s", section, field);
            if (old_section)
                json_object_object_get_ex(old_section, field, &old_value);
            json_object_object_get_ex(results, path, &field_result);
            nc_sys_audit_value_summary(old_value, old_summary,
                                       sizeof(old_summary));
            nc_sys_audit_value_summary(new_value, new_summary,
                                       sizeof(new_summary));
            json_object_object_add(item, "field", json_object_new_string(path));
            json_object_object_add(item, "old", json_object_new_string(old_summary));
            json_object_object_add(item, "new", json_object_new_string(new_summary));
            json_object_object_add(item, "state",
                json_object_new_string(field_result ?
                    nc_json_str_def(field_result, "state", ok ? "applied" :
                                                          "failed") :
                    (ok ? "applied" : "failed")));
            json_object_object_add(item, "rollback",
                json_object_new_boolean(field_result ?
                    nc_json_bool_def(field_result, "rollback", 0) : 0));
            json_object_array_add(changes, item);
        }
    }
    event = json_object_new_object();
    if (!event) {
        json_object_put(changes);
        return;
    }
    detail = strdup(json_object_to_json_string_ext(changes,
                                                    JSON_C_TO_STRING_PLAIN));
    json_object_put(changes);
    json_object_object_add(event, "type", json_object_new_string("user"));
    json_object_object_add(event, "level",
                           json_object_new_string(ok ? "info" : "warning"));
    json_object_object_add(event, "category", json_object_new_string("audit"));
    json_object_object_add(event, "module", json_object_new_string("system"));
    json_object_object_add(event, "source",
                           json_object_new_string("system_settings"));
    json_object_object_add(event, "username", json_object_new_string(""));
    json_object_object_add(event, "auth_ip", json_object_new_string(""));
    json_object_object_add(event, "title",
                           json_object_new_string("System settings changed"));
    json_object_object_add(event, "event",
                           json_object_new_string("system_settings_change"));
    json_object_object_add(event, "detail",
                           json_object_new_string(detail ? detail : "[]"));
    json_object_object_add(event, "state",
                           json_object_new_string(ok ? "applied" :
                               (rollback_ok ? "rolled_back" :
                                              "rollback_failed")));
    json_object_object_add(event, "target",
                           json_object_new_string(failure_reason ?
                                                  failure_reason : ""));
    (void)nc_log_center_event_store(event, &bridged, &bridge_failed,
                                    bridge_error, sizeof(bridge_error));
    free(detail);
    json_object_put(event);
}

struct json_object *jmx_system_settings_apply_result(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *results = json_object_new_object();
    char configured_hostname[128] = "";
    char configured_domain[254] = "";
    char observed_hostname[128] = "";
    char observed_domain[254] = "";
    sqlite3_stmt *st = NULL;
    int rc = jmx_system_settings_apply(cfg);
    int domain_observed = 0;

    if (jmx_netconfig_db_init() == 0 &&
        nc_prepare(&st, "SELECT hostname,custom_domain FROM system_settings WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *value = (const char *)sqlite3_column_text(st, 0);
        snprintf(configured_hostname, sizeof(configured_hostname), "%s",
                 value ? value : "");
        value = (const char *)sqlite3_column_text(st, 1);
        snprintf(configured_domain, sizeof(configured_domain), "%s",
                 value ? value : "");
        sqlite3_finalize(st);
    }
    if (gethostname(observed_hostname, sizeof(observed_hostname) - 1) != 0)
        observed_hostname[0] = '\0';
    domain_observed = nc_sys_runtime_console_domain(observed_domain,
                                                     sizeof(observed_domain));
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "persisted", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "configured_hostname",
                           json_object_new_string(configured_hostname));
    json_object_object_add(data, "runtime_hostname",
                           json_object_new_string(observed_hostname));
    json_object_object_add(data, "hostname_in_sync",
                           json_object_new_boolean(configured_hostname[0] &&
                                                   !strcmp(configured_hostname,
                                                           observed_hostname)));
    json_object_object_add(data, "configured_custom_domain",
                           json_object_new_string(configured_domain));
    json_object_object_add(data, "runtime_custom_domain",
                           json_object_new_string(observed_domain));
    json_object_object_add(data, "custom_domain_in_sync",
                           json_object_new_boolean(domain_observed &&
                                                   !strcmp(configured_domain,
                                                           observed_domain)));
    nc_sys_field_result(results, "general.hostname", 1, rc == 0, rc == 0,
                        rc == 0 ? "applied_verified" : "apply_failed");
    nc_sys_field_result(results, "general.custom_domain", 1, rc == 0,
                        rc == 0, rc == 0 ? "applied_verified" : "apply_failed");
    json_object_object_add(data, "field_results", results);
    if (rc != 0) {
        json_object_object_add(data, "error", json_object_new_string("apply_failed"));
        json_object_object_add(data, "reason",
                               json_object_new_string("console_identity_apply_or_readback_failed"));
    }
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

struct json_object *jmx_system_settings_save_apply_result(struct json_object *cfg)
{
    const char *denied_field = NULL;
    const char *denied_capability = NULL;
    struct json_object *current_response = NULL;
    struct json_object *current = NULL;
    struct json_object *delta = NULL;
    struct json_object *snapshot = NULL;
    struct json_object *results = NULL;
    struct json_object *denied = NULL;
    struct json_object *final_response = NULL;
    struct json_object *final_data = NULL;
    struct json_object *general = NULL;
    struct json_object *runtime_results = NULL;
    char runtime_failed_field[160] = "system_settings";
    char runtime_failed_reason[JMX_SYSTEM_ALG_ERROR_MAX] = "apply_failed";
    int console_identity_changed = 0;
    int runtime_applied = 0;
    int rollback_ok = 1;
    struct json_object *rollback_results = NULL;

    if (!cfg || !json_object_is_type(cfg, json_type_object))
        return nc_sys_settings_error("invalid_request", "system_settings",
                                     "system_settings_save", "object_payload_required");
    current_response = jmx_system_settings_get();
    current = nc_sys_response_data(current_response);
    if (!current) {
        if (current_response) json_object_put(current_response);
        return nc_sys_settings_error("source_unavailable", "system_settings",
                                     "system_settings_save", "authoritative_snapshot_unavailable");
    }
    denied = json_object_new_object();
    if (!denied) {
        json_object_put(current_response);
        return nc_sys_settings_error("allocation_failed", "system_settings",
                                     "system_settings_save",
                                     "field_results_allocation_failed");
    }
    delta = nc_sys_build_settings_delta(cfg, current, &denied_field,
                                        &denied_capability, denied);
    if (!delta) {
        struct json_object *error = nc_sys_settings_error(
            "capability_disabled", denied_field ? denied_field : "system_settings",
            denied_capability ? denied_capability : "system_settings_runtime_write",
            "transactional_runtime_executor_pending");

        if (denied_field && strcmp(denied_field, "system_settings.unknown"))
            free((void *)denied_field);
        if (denied) json_object_put(denied);
        json_object_put(current_response);
        return error;
    }
    if (json_object_object_length(delta) == 0) {
        /*
         * Nothing writable left. If every changed field was gated, saying "ok,
         * nothing changed" would hide the fact that the user's edits were
         * dropped, so report a failure that names them.
         */
        if (json_object_object_length(denied) > 0) {
            struct json_object *error = nc_sys_settings_error(
                "no_writable_fields", "system_settings",
                "system_settings_save", "all_requested_fields_gated");
            struct json_object *error_data = nc_sys_response_data(error);

            if (error_data)
                json_object_object_add(error_data, "field_results",
                                       json_object_get(denied));
            json_object_put(denied);
            json_object_put(delta);
            json_object_put(current_response);
            return error;
        }
        final_data = json_object_get(current);
        results = json_object_new_object();
        json_object_object_add(final_data, "ok", json_object_new_boolean(1));
        json_object_object_add(final_data, "changed", json_object_new_boolean(0));
        json_object_object_add(final_data, "persisted", json_object_new_boolean(0));
        json_object_object_add(final_data, "applied", json_object_new_boolean(0));
        json_object_object_add(final_data, "field_results", results);
        final_response = jmx_gen_api_response_data(API_CODE_SUCCESS, final_data);
        json_object_put(denied);
        json_object_put(delta);
        json_object_put(current_response);
        return final_response;
    }
    snapshot = nc_sys_settings_snapshot(delta, current);
    if (!snapshot) {
        json_object_put(denied);
        json_object_put(delta);
        json_object_put(current_response);
        return nc_sys_settings_error("snapshot_failed", "system_settings",
                                     "system_settings_save", "rollback_snapshot_unavailable");
    }
    runtime_results = json_object_new_object();
    if (!runtime_results) {
        json_object_put(snapshot);
        json_object_put(denied);
        json_object_put(delta);
        json_object_put(current_response);
        return nc_sys_settings_error("allocation_failed", "system_settings",
                                     "system_settings_save",
                                     "runtime_field_results_allocation_failed");
    }
    if (json_object_object_get_ex(delta, "general", &general) && general) {
        struct json_object *hostname_value = NULL;
        struct json_object *domain_value = NULL;

        console_identity_changed =
            json_object_object_get_ex(general, "hostname", &hostname_value) ||
            json_object_object_get_ex(general, "custom_domain", &domain_value);
    }
    if (jmx_system_settings_set(delta) != 0)
        goto failed;
    if (console_identity_changed && jmx_system_settings_apply(NULL) != 0)
        goto failed;
    if (nc_sys_runtime_apply(delta, delta, runtime_results,
                             runtime_failed_field,
                             sizeof(runtime_failed_field),
                             runtime_failed_reason,
                             sizeof(runtime_failed_reason)) != 0)
        goto failed;
    runtime_applied = json_object_object_length(runtime_results) > 0;
    if (!console_identity_changed)
        nc_exec("UPDATE system_settings SET apply_state='saved_only',apply_error='',updated_at=strftime('%s','now') WHERE id=1");
    final_response = jmx_system_settings_get();
    final_data = nc_sys_response_data(final_response);
    if (!final_data)
        goto failed;
    results = json_object_new_object();
    nc_sys_merge_field_results(results, runtime_results);
    nc_sys_settings_add_changed_results(results, delta, 1);
    nc_sys_merge_field_results(results, denied);
    json_object_object_add(final_data, "ok", json_object_new_boolean(1));
    json_object_object_add(final_data, "changed", json_object_new_boolean(1));
    json_object_object_add(final_data, "persisted", json_object_new_boolean(1));
    json_object_object_add(final_data, "applied",
                           json_object_new_boolean(console_identity_changed ||
                                                   runtime_applied));
    json_object_object_add(final_data, "field_results", results);
    json_object_object_add(final_data, "rejected_fields",
                           json_object_new_int(
                               (int)json_object_object_length(denied)));
    nc_sys_settings_audit(delta, snapshot, results, 1, 1, "");
    json_object_put(denied);
    json_object_put(runtime_results);
    json_object_put(snapshot);
    json_object_put(delta);
    json_object_put(current_response);
    return final_response;

failed:
    if (final_response) {
        json_object_put(final_response);
        final_response = NULL;
    }
    rollback_ok = jmx_system_settings_set(snapshot) == 0;
    if (rollback_ok && console_identity_changed)
        rollback_ok = jmx_system_settings_apply(NULL) == 0;
    if (rollback_ok && runtime_results &&
        json_object_object_length(runtime_results) > 0) {
        char rollback_field[160] = "system_settings";
        char rollback_reason[JMX_SYSTEM_ALG_ERROR_MAX] = "rollback_failed";

        rollback_results = json_object_new_object();
        if (!rollback_results ||
            nc_sys_runtime_apply(snapshot, delta, rollback_results,
                                 rollback_field, sizeof(rollback_field),
                                 rollback_reason,
                                 sizeof(rollback_reason)) != 0)
            rollback_ok = 0;
    }
    nc_sys_mark_runtime_results_rolled_back(runtime_results, rollback_results,
                                            rollback_ok);
    final_response = nc_sys_settings_error(
        rollback_ok ? "apply_failed" : "rollback_failed",
        runtime_failed_field[0] ? runtime_failed_field : "system_settings",
        "system_settings_apply", rollback_ok ?
        (runtime_failed_reason[0] ? runtime_failed_reason :
         "changes_compensated_after_apply_failure") : "compensation_failed");
    final_data = nc_sys_response_data(final_response);
    if (final_data) {
        json_object_object_add(final_data, "compensated",
                               json_object_new_boolean(rollback_ok));
        json_object_object_add(final_data, "partial",
                               json_object_new_boolean(!rollback_ok));
        {
            struct json_object *error_results = NULL;

            if (json_object_object_get_ex(final_data, "field_results",
                                          &error_results) && error_results)
                nc_sys_merge_field_results(error_results, runtime_results);
            if (json_object_object_get_ex(final_data, "field_results",
                                          &error_results) && error_results)
                nc_sys_merge_field_results(error_results, denied);
        }
    }
    nc_sys_settings_audit(delta, snapshot, runtime_results, 0, rollback_ok,
                          runtime_failed_reason);
    json_object_put(denied);
    if (runtime_results) json_object_put(runtime_results);
    if (rollback_results) json_object_put(rollback_results);
    json_object_put(snapshot);
    json_object_put(delta);
    json_object_put(current_response);
    return final_response;
}

/* ── system_settings_draft_apply: lightweight UCI draft only ─────── */
struct json_object *jmx_system_settings_draft_apply(struct json_object *cfg)
{
    return jmx_system_settings_apply_result(cfg);
}
/*
 * Validates one stored cron job. `schedule` used to be checked only for being
 * non-empty, so a malformed or multi-line value could be persisted and would
 * corrupt the crontab if anything ever rendered this table into a real file.
 * Rather than writing a second validator, the schedule and command are joined
 * into the crontab line they represent and handed to the existing full-line
 * checker, which also rejects control characters and embedded newlines.
 */
static int nc_sys_cron_job_valid(const char *id, const char *sch, const char *cmd)
{
    char line[4608];
    char err[128];
    size_t bad_line = 0;

    if (!nc_valid_name(id) || !sch || !sch[0] || !cmd || !cmd[0])
        return 0;
    /* Commands are limited to the two managed prefixes. `..` is rejected so a
     * relative path cannot climb out of them. */
    if (strncmp(cmd, "/usr/libexec/dreamingwrt/", 25) != 0 &&
        strncmp(cmd, "/etc/init.d/", 12) != 0)
        return 0;
    if (strstr(cmd, ".."))
        return 0;
    if (snprintf(line, sizeof(line), "%s %s", sch, cmd) >= (int)sizeof(line))
        return 0;
    return jmx_system_crontab_validate_text(line, &bad_line, err, sizeof(err)) ==
           JMX_SYSTEM_MOUNT_OK;
}

int jmx_system_cron_set(struct json_object *cfg)
{
    struct json_object *jobs = NULL;
    sqlite3_int64 now;
    int i, n, rc = 0;

    if (!cfg || jmx_netconfig_db_init() != 0) return -1;
    nc_sys_settings_db_init();
    if (!json_object_object_get_ex(cfg, "jobs", &jobs) ||
        !json_object_is_type(jobs, json_type_array))
        return -1;
    now = (sqlite3_int64)nc_now_s();
    if (nc_txn_begin() != 0) return -1;
    if (nc_exec("DELETE FROM system_cron_job") != 0)
        return nc_txn_end(-1);
    n = json_object_array_length(jobs);
    for (i = 0; i < n; i++) {
        struct json_object *o = json_object_array_get_idx(jobs, i);
        const char *id = nc_json_str_def(o, "id", "");
        const char *sch = nc_json_str_def(o, "schedule", "");
        const char *cmd = nc_json_str_def(o, "command", "");
        sqlite3_stmt *st = NULL;

        if (!nc_sys_cron_job_valid(id, sch, cmd))
            return nc_txn_end(-1);
        /* A failed prepare or step used to be skipped silently, so a partial
         * job list was reported as a successful save. */
        if (nc_prepare(&st, "INSERT INTO system_cron_job(id,enabled,schedule,command,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?)") != 0)
            return nc_txn_end(-1);
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool_def(o, "enabled", 1));
        sqlite3_bind_text(st, 3, sch, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, cmd, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str_def(o, "desc", nc_json_str_def(o, "description", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        sqlite3_bind_int64(st, 7, now);
        if (nc_step_done(st) != 0)
            rc = -1;
        sqlite3_finalize(st);
        if (rc != 0)
            return nc_txn_end(rc);
    }
    return nc_txn_end(rc);
}

/*
 * Services whose init script must not be driven from the API. `nc_valid_name()`
 * already blocks command injection (no space, slash, or shell metacharacter can
 * get through), so the remaining risk is denial of service: stopping the SSH
 * daemon, the web server, DNS, or jmxd itself costs the operator their
 * management path. A deny list of three names left all of those reachable.
 */
static int nc_sys_service_protected(const char *name)
{
    static const char *const protected_names[] = {
        "network", "firewall", "rpcd",
        "dropbear", "sshd", "uhttpd", "nginx",
        "dnsmasq", "odhcpd",
        "jmxd", "dreamingwrt-core", "dreamingwrt-webd", "dreamingwrt-init",
        "dreamingwrt-authd", "dreamingwrt-apid", "ubus", "ubusd", "netifd",
        /* Base system services: stopping these takes down logging, the boot
         * pipeline, or the terminal the operator may be recovering through. */
        "log", "system", "boot", "ttyd", "dbus", "sysntpd", "cron",
        "dreamingwrt-persist", "dreamingwrt-installer",
        NULL
    };
    int i;

    for (i = 0; protected_names[i]; i++)
        if (!strcmp(name, protected_names[i]))
            return 1;
    return 0;
}

struct json_object *jmx_system_service_set(struct json_object *cfg)
{
    const char *name = nc_json_str_def(cfg, "name", "");
    if (!nc_valid_name(name) || nc_sys_service_protected(name))
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    const char *action = nc_json_str_def(cfg, "action", "");
    int ok = 0;
    if(!strcmp(action, "enable")) {
        char cmd[256]; snprintf(cmd, sizeof(cmd), "/etc/init.d/%s enable 2>/dev/null", name);
        ok = (system(cmd) == 0);
    } else if(!strcmp(action, "disable")) {
        char cmd[256]; snprintf(cmd, sizeof(cmd), "/etc/init.d/%s disable 2>/dev/null", name);
        ok = (system(cmd) == 0);
    } else if(!strcmp(action, "restart")) {
        char cmd[256]; snprintf(cmd, sizeof(cmd), "/etc/init.d/%s restart 2>/dev/null", name);
        ok = (system(cmd) == 0);
    } else if(!strcmp(action, "stop")) {
        char cmd[256]; snprintf(cmd, sizeof(cmd), "/etc/init.d/%s stop 2>/dev/null", name);
        ok = (system(cmd) == 0);
    } else if(!strcmp(action, "start")) {
        char cmd[256]; snprintf(cmd, sizeof(cmd), "/etc/init.d/%s start 2>/dev/null", name);
        ok = (system(cmd) == 0);
    }
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "ok", json_object_new_boolean(ok));
    json_object_object_add(d, "name", json_object_new_string(name));
    json_object_object_add(d, "action", json_object_new_string(action));
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

/* ── Small closure APIs: safe read-only / SQLite-only helpers ─────────── */
static const char *nc_simple_status_name(int rc){return rc==0?"ok":"error";}

struct json_object *jmx_system_disabled_functions_get(void)
{if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);nc_sys_settings_db_init();nc_sys_sync_disabled_from_file();nc_sys_hwprobe_disabled();struct json_object*d=json_object_new_object();{int features=nc_sys_features_mode();json_object_object_add(d,"path",json_object_new_string(features?DWRT_FEATURES_PATH:"/etc/disabled_func"));json_object_object_add(d,"items",nc_sys_disabled_json());json_object_object_add(d,"status",json_object_new_string(features?"synced_from_features":"synced_from_file"));}return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_system_disabled_functions_set(struct json_object *cfg)
{if(!cfg||jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);nc_sys_settings_db_init();struct json_object*arr=NULL;if(!json_object_object_get_ex(cfg,"items",&arr)&&!json_object_object_get_ex(cfg,"disabled_functions",&arr))return jmx_gen_api_response_data(API_CODE_ERROR,NULL);if(!json_object_is_type(arr,json_type_array))return jmx_gen_api_response_data(API_CODE_ERROR,NULL);sqlite3_int64 now=(sqlite3_int64)nc_now_s();if(nc_txn_begin()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);if(nc_exec("DELETE FROM disabled_function")!=0){nc_txn_end(-1);return jmx_gen_api_response_data(API_CODE_ERROR,NULL);}int n=json_object_array_length(arr);for(int i=0;i<n;i++){const char*code=json_object_get_string(json_object_array_get_idx(arr,i));if(!nc_sys_disabled_code_ok(code)){nc_exec("ROLLBACK");return jmx_gen_api_response_data(API_CODE_ERROR,NULL);}sqlite3_stmt*st=NULL;if(nc_prepare(&st,"INSERT OR REPLACE INTO disabled_function(code,source,updated_at) VALUES(?,'user',?)")==0){sqlite3_bind_text(st,1,code,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,now);sqlite3_step(st);sqlite3_finalize(st);}}nc_sys_write_disabled_file();nc_exec("COMMIT");return jmx_system_disabled_functions_get();}

struct json_object *jmx_system_services_status(struct json_object *cfg)
{(void)cfg;int truncated=0,degraded=0;struct json_object*d=json_object_new_object();struct json_object*services=nc_sys_services_json(&truncated,&degraded);json_object_object_add(d,"services",services?services:json_object_new_array());json_object_object_add(d,"truncated",json_object_new_boolean(truncated));json_object_object_add(d,"degraded",json_object_new_boolean(degraded));json_object_object_add(d,"protected",json_object_new_string("network,firewall,rpcd,dreamingwrt-init"));json_object_object_add(d,"apply",json_object_new_string("trusted_argv_readback_rollback"));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_system_mounts_status(struct json_object *cfg)
{(void)cfg;int gen=jmx_system_mount_runtime_capability(0);int mnt=jmx_system_mount_runtime_capability(1);struct json_object*d=jmx_system_mounts_read_json();struct json_object*cap=json_object_new_object();json_object_object_add(d,"edit",json_object_new_string("transactional_explicit_candidates"));json_object_object_add(d,"auto_mount",json_object_new_boolean(1));json_object_object_add(d,"auto_swap",json_object_new_boolean(0));json_object_object_add(d,"check_fs",json_object_new_boolean(0));json_object_object_add(cap,"mounts_read",json_object_new_boolean(1));json_object_object_add(cap,"mounts_runtime_split",json_object_new_boolean(1));json_object_object_add(cap,"mounts_fstype",json_object_new_boolean(1));json_object_object_add(cap,"mounts_discovery",json_object_new_boolean(gen));json_object_object_add(cap,"mounts_generate_config",json_object_new_boolean(gen));json_object_object_add(cap,"mounts_mount_connected",json_object_new_boolean(mnt));json_object_object_add(cap,"mounts_unmount",json_object_new_boolean(1));json_object_object_add(cap,"mounts_save_point",json_object_new_boolean(1));json_object_object_add(cap,"mounts_delete_point",json_object_new_boolean(1));json_object_object_add(d,"capabilities",cap);json_object_object_add(d,"stable_id_required",json_object_new_boolean(1));json_object_object_add(d,"implicit_mount",json_object_new_boolean(0));if(!gen)json_object_object_add(d,"reason",json_object_new_string("block_discovery_runtime_unavailable"));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_system_cron_get(struct json_object *cfg)
{if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);(void)cfg;nc_sys_settings_db_init();struct json_object*d=json_object_new_object();char*text=nc_sys_crontab_text();struct stat st;int64_t mtime=stat("/etc/crontabs/root",&st)==0?(int64_t)st.st_mtime:0;json_object_object_add(d,"jobs",nc_sys_cron_jobs_json());json_object_object_add(d,"text",json_object_new_string(text?text:""));json_object_object_add(d,"path",json_object_new_string("/etc/crontabs/root"));json_object_object_add(d,"last_modified_at",json_object_new_int64(mtime));json_object_object_add(d,"last_reload_at",json_object_new_int64(0));json_object_object_add(d,"reload_state",json_object_new_string("unknown"));json_object_object_add(d,"apply",json_object_new_string("atomic_file_restart_readback_rollback"));json_object_object_add(d,"special_times_supported",json_object_new_boolean(jmx_system_crontab_special_times_supported()));if(text)free(text);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_wifi_capabilities_get(struct json_object *cfg)
{(void)cfg;struct json_object*d=json_object_new_object();struct json_object*disabled=NULL;struct json_object*df=jmx_system_disabled_functions_get();json_object_object_get_ex(json_object_object_get(df,"data"),"items",&disabled);if(disabled)json_object_get(disabled);json_object_put(df);json_object_object_add(d,"disabled_functions",disabled?disabled:json_object_new_array());json_object_object_add(d,"wifi_available",json_object_new_boolean(access("/sys/class/ieee80211",F_OK)==0));json_object_object_add(d,"apply_mode",json_object_new_string("guarded_reload_default"));json_object_object_add(d,"reload",json_object_new_string("implemented_copy_reload_rollback"));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_cellular_runtime_status(struct json_object *cfg)
{(void)cfg;struct json_object*d=json_object_new_object();int has_mmcli=(system("command -v mmcli >/dev/null 2>&1")==0);json_object_object_add(d,"modemmanager",json_object_new_string(has_mmcli?"available":"missing"));json_object_object_add(d,"mmcli",json_object_new_boolean(has_mmcli));json_object_object_add(d,"runtime",json_object_new_string(has_mmcli?"probe_available":"pending_modemmanager_integration"));json_object_object_add(d,"at_write",json_object_new_string("disabled_until_whitelist"));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_runtime_pending_matrix(struct json_object *cfg)
{
    (void)cfg;
    struct json_object*d=json_object_new_object();
    json_object_object_add(d,"system_settings_apply",json_object_new_string("draft_written_pending_uci_commit"));
    json_object_object_add(d,"wifi_reload",json_object_new_string("implemented_guarded_reload_and_rollback"));
    json_object_object_add(d,"cellular_runtime",json_object_new_string("pending_modemmanager_integration"));
    json_object_object_add(d,"advanced_routing_runtime",json_object_new_string("implemented_ip_route_rule_nft_pbr"));
    json_object_object_add(d,"network_control_nft",json_object_new_string("implemented_guarded_apply_default"));
    json_object_object_add(d,"network_control_tc",json_object_new_string("implemented_guarded_apply_default"));
    json_object_object_add(d,"log_delivery_worker",json_object_new_string("implemented_claim_lease_stats"));
    json_object_object_add(d,"syslog_forwarder",json_object_new_string("implemented_local_file"));
    json_object_object_add(d,"wan_netifd_apply",json_object_new_string("implemented_uci_commit_reload"));
    json_object_object_add(d,"lan_write_apply",json_object_new_string("implemented_uci_commit_reload"));
    return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_jmxd_phase_summary(struct json_object *cfg)
{(void)cfg;struct json_object*d=json_object_new_object();json_object_object_add(d,"schema_and_api",json_object_new_string("mostly_phase1_complete"));json_object_object_add(d,"runtime_apply",json_object_new_string("mostly_implemented_guarded_runtime"));json_object_object_add(d,"safe_simple_items_closed",json_object_new_int(30));
    json_object_object_add(d,"phase2_uci_drafts",json_object_new_string("wan+lan+wifi+vpn+flow+nft+tc"));
    json_object_object_add(d,"services_real_actions",json_object_new_string("enable/disable/restart/stop/start"));
    json_object_object_add(d,"next_recommended",json_object_new_string("dpi_runtime_consumer_l7_l4_matching"));json_object_object_add(d,"generated_at",json_object_new_int64(nc_now_s()));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}
/* DreamingWrt bundled signature DB status/catalog helpers
 *
 * The authoritative signature catalog/query implementation now lives in
 * jmx_signature_update.c. Keep this historical monolith block disabled so
 * transitional core builds do not export duplicate jmx_signature_db_* symbols.
 */
#if 0
#ifndef JMX_SIGNATURE_DB_DEFAULT
#define JMX_SIGNATURE_DB_DEFAULT "/etc/dreamingwrt/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SIGNATURE_DB_SHARE
#define JMX_SIGNATURE_DB_SHARE "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db"
#endif

static int nc_signature_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    return jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                                 &source, error, sizeof(error));
}

int nc_sig_open(sqlite3 **db)
{
    char path[512];

    if (!db || nc_signature_db_path(path, sizeof(path)) != 0)
        return -1;
    return jmx_signature_db_open_path(path, db) == SQLITE_OK ? 0 : -1;
}

static int nc_sig_scalar_i(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL; int v = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    return v;
}

static void nc_sig_meta(sqlite3 *db, struct json_object *meta)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT key,value FROM meta ORDER BY key", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *k = (const char *)sqlite3_column_text(st, 0);
            const char *v = (const char *)sqlite3_column_text(st, 1);
            if (k) json_object_object_add(meta, k, json_object_new_string(v ? v : ""));
        }
    }
    if (st) sqlite3_finalize(st);
}

struct json_object *jmx_signature_db_status(struct json_object *cfg)
{
    char path[512] = {0};
    (void)cfg; sqlite3 *db = NULL; struct stat st;
    struct json_object *d = json_object_new_object(), *counts = json_object_new_object(), *meta = json_object_new_object();
    (void)nc_signature_db_path(path, sizeof(path));
    json_object_object_add(d, "path", json_object_new_string(path));
    json_object_object_add(d, "exists", json_object_new_boolean(access(path, R_OK) == 0));
    json_object_object_add(d, "source", json_object_new_string("dreamingwrt_signatures.db"));
    json_object_object_add(d, "legacy_app_dat", json_object_new_string("disabled"));
    json_object_object_add(d, "legacy_ikuai_audit", json_object_new_string("disabled"));
    if (stat(path, &st) == 0) { json_object_object_add(d, "size_bytes", json_object_new_int64(st.st_size)); json_object_object_add(d, "mtime", json_object_new_int64(st.st_mtime)); }
    if (nc_sig_open(&db) == 0) {
        json_object_object_add(d, "ok", json_object_new_boolean(1));
        json_object_object_add(counts, "apps", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM app WHERE enabled=1")));
        json_object_object_add(counts, "dpi_rules", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM dpi_rule WHERE enabled=1")));
        json_object_object_add(counts, "domain_groups", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM domain_group")));
        json_object_object_add(counts, "domain_entries", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM domain_entry")));
        json_object_object_add(counts, "device_vendors", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM device_vendor")));
        json_object_object_add(counts, "device_types", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM device_type")));
        json_object_object_add(counts, "device_fingerprint_rules", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM device_fingerprint_rule WHERE enabled=1")));
        json_object_object_add(counts, "carrier_prefixes", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM carrier_prefix WHERE enabled=1")));
        json_object_object_add(counts, "icons", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM app_icon")));
        nc_sig_meta(db, meta); sqlite3_close(db);
    } else {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("cannot_open_signature_db"));
    }
    json_object_object_add(d, "counts", counts); json_object_object_add(d, "meta", meta);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_signature_db_apps(struct json_object *cfg)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int limit = 200, offset = 0; const char *q = "";
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    if (cfg) { limit = nc_json_int_def(cfg, "limit", 200); offset = nc_json_int_def(cfg, "offset", 0); q = nc_json_str_def(cfg, "q", ""); }
    if (limit <= 0 || limit > 1000) limit = 200; if (offset < 0) offset = 0;
    { char path[512] = {0}; (void)nc_signature_db_path(path, sizeof(path)); json_object_object_add(d, "path", json_object_new_string(path)); }
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "apps", arr); return jmx_gen_api_response_data(API_CODE_SUCCESS, d); }
    const char *sql = "SELECT a.app_id,a.name,COALESCE(c.slug,''),COALESCE(c.name,''),COALESCE(a.family,''),"
                      "(SELECT COUNT(*) FROM dpi_rule r WHERE r.app_id=a.app_id AND r.enabled=1) AS rules "
                      "FROM app a LEFT JOIN app_category c ON c.category_id=a.category_id "
                      "WHERE a.enabled=1 AND (?1='' OR a.name LIKE '%'||?1||'%' OR a.normalized_name LIKE '%'||?1||'%') "
                      "ORDER BY a.app_id LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, q, -1, SQLITE_TRANSIENT); sqlite3_bind_int(st, 2, limit); sqlite3_bind_int(st, 3, offset);
        while (sqlite3_step(st) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            json_object_object_add(o, "app_id", json_object_new_int(sqlite3_column_int(st,0)));
            json_object_object_add(o, "name", json_object_new_string((const char*)sqlite3_column_text(st,1)));
            json_object_object_add(o, "category_slug", json_object_new_string((const char*)sqlite3_column_text(st,2)));
            json_object_object_add(o, "category", json_object_new_string((const char*)sqlite3_column_text(st,3)));
            json_object_object_add(o, "family", json_object_new_string((const char*)sqlite3_column_text(st,4)));
            json_object_object_add(o, "rules", json_object_new_int(sqlite3_column_int(st,5)));
            json_object_array_add(arr, o); }
    }
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    json_object_object_add(d, "ok", json_object_new_boolean(1)); json_object_object_add(d, "limit", json_object_new_int(limit)); json_object_object_add(d, "offset", json_object_new_int(offset)); json_object_object_add(d, "apps", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_signature_db_rules(struct json_object *cfg)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int limit = 200, offset = 0, app_id = 0;
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    if (cfg) { limit = nc_json_int_def(cfg, "limit", 200); offset = nc_json_int_def(cfg, "offset", 0); app_id = nc_json_int_def(cfg, "app_id", 0); }
    if (limit <= 0 || limit > 1000) limit = 200; if (offset < 0) offset = 0;
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "rules", arr); return jmx_gen_api_response_data(API_CODE_SUCCESS, d); }
    const char *sql = "SELECT r.rule_id,r.app_id,a.name,r.proto,r.direction,r.match_type,r.pattern_format,COALESCE(r.pattern_text,''),COALESCE(r.pattern_hex,''),r.offset,r.priority,r.pkt_seq "
                      "FROM dpi_rule r LEFT JOIN app a ON a.app_id=r.app_id WHERE r.enabled=1 AND (?1=0 OR r.app_id=?1) ORDER BY r.priority,r.rule_id LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, app_id); sqlite3_bind_int(st, 2, limit); sqlite3_bind_int(st, 3, offset);
        while (sqlite3_step(st) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            json_object_object_add(o, "rule_id", json_object_new_int(sqlite3_column_int(st,0)));
            json_object_object_add(o, "app_id", json_object_new_int(sqlite3_column_int(st,1)));
            json_object_object_add(o, "app_name", json_object_new_string((const char*)sqlite3_column_text(st,2)));
            json_object_object_add(o, "proto", json_object_new_string((const char*)sqlite3_column_text(st,3)));
            json_object_object_add(o, "direction", json_object_new_string((const char*)sqlite3_column_text(st,4)));
            json_object_object_add(o, "match_type", json_object_new_string((const char*)sqlite3_column_text(st,5)));
            json_object_object_add(o, "pattern_format", json_object_new_string((const char*)sqlite3_column_text(st,6)));
            json_object_object_add(o, "pattern_text", json_object_new_string((const char*)sqlite3_column_text(st,7)));
            json_object_object_add(o, "pattern_hex", json_object_new_string((const char*)sqlite3_column_text(st,8)));
            json_object_object_add(o, "offset", json_object_new_int(sqlite3_column_int(st,9)));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st,10)));
            json_object_object_add(o, "pkt_seq", json_object_new_int(sqlite3_column_int(st,11)));
            json_object_array_add(arr, o); }
    }
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    json_object_object_add(d, "ok", json_object_new_boolean(1)); json_object_object_add(d, "app_id", json_object_new_int(app_id)); json_object_object_add(d, "limit", json_object_new_int(limit)); json_object_object_add(d, "offset", json_object_new_int(offset)); json_object_object_add(d, "rules", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_signature_db_carriers(struct json_object *cfg)
{
    (void)cfg; sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "carriers", arr); return jmx_gen_api_response_data(API_CODE_SUCCESS, d); }
    const char *sql = "SELECT carrier,carrier_id,MAX(carrier_name),COUNT(*),MIN(updated_at),MAX(updated_at) FROM carrier_prefix WHERE enabled=1 GROUP BY carrier,carrier_id ORDER BY carrier_id";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            json_object_object_add(o, "carrier", json_object_new_string((const char*)sqlite3_column_text(st,0)));
            json_object_object_add(o, "carrier_id", json_object_new_int(sqlite3_column_int(st,1)));
            json_object_object_add(o, "name", json_object_new_string((const char*)sqlite3_column_text(st,2)));
            json_object_object_add(o, "prefixes", json_object_new_int(sqlite3_column_int(st,3)));
            json_object_object_add(o, "first_updated_at", json_object_new_int64(sqlite3_column_int64(st,4)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st,5)));
            json_object_array_add(arr, o); }
    }
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    { char path[512] = {0}; (void)nc_signature_db_path(path, sizeof(path)); json_object_object_add(d, "ok", json_object_new_boolean(1)); json_object_object_add(d, "path", json_object_new_string(path)); } json_object_object_add(d, "carriers", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_signature_db_carrier_prefixes(struct json_object *cfg)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int limit = 500, offset = 0; const char *carrier = "";
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    if (cfg) { limit = nc_json_int_def(cfg, "limit", 500); offset = nc_json_int_def(cfg, "offset", 0); carrier = nc_json_str_def(cfg, "carrier", ""); }
    if (limit <= 0 || limit > 5000) limit = 500; if (offset < 0) offset = 0;
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "prefixes", arr); return jmx_gen_api_response_data(API_CODE_SUCCESS, d); }
    const char *sql = "SELECT carrier,carrier_id,carrier_name,cidr,source,sort_key FROM carrier_prefix WHERE enabled=1 AND (?1='' OR carrier=?1) ORDER BY sort_key LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, carrier, -1, SQLITE_TRANSIENT); sqlite3_bind_int(st, 2, limit); sqlite3_bind_int(st, 3, offset);
        while (sqlite3_step(st) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            json_object_object_add(o, "carrier", json_object_new_string((const char*)sqlite3_column_text(st,0)));
            json_object_object_add(o, "carrier_id", json_object_new_int(sqlite3_column_int(st,1)));
            json_object_object_add(o, "name", json_object_new_string((const char*)sqlite3_column_text(st,2)));
            json_object_object_add(o, "cidr", json_object_new_string((const char*)sqlite3_column_text(st,3)));
            json_object_object_add(o, "source", json_object_new_string((const char*)sqlite3_column_text(st,4)));
            json_object_object_add(o, "sort_key", json_object_new_string((const char*)sqlite3_column_text(st,5)));
            json_object_array_add(arr, o); }
    }
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    json_object_object_add(d, "ok", json_object_new_boolean(1)); json_object_object_add(d, "carrier", json_object_new_string(carrier)); json_object_object_add(d, "limit", json_object_new_int(limit)); json_object_object_add(d, "offset", json_object_new_int(offset)); json_object_object_add(d, "prefixes", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}
struct json_object *jmx_signature_db_domain_groups(struct json_object *cfg)
{
    (void)cfg; sqlite3 *db=NULL; sqlite3_stmt *st=NULL;
    struct json_object *d=json_object_new_object(), *arr=json_object_new_array();
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"groups",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);} 
    const char *sql="SELECT g.group_id,g.category,g.subcategory,COUNT(e.domain),COALESCE(g.source,''),COALESCE(g.sort_key,'') FROM domain_group g LEFT JOIN domain_entry e ON e.group_id=g.group_id GROUP BY g.group_id,g.category,g.subcategory,g.source,g.sort_key ORDER BY g.sort_key,g.group_id";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"group_id",json_object_new_int(sqlite3_column_int(st,0)));json_object_object_add(o,"category",json_object_new_string((const char*)sqlite3_column_text(st,1)));json_object_object_add(o,"subcategory",json_object_new_string((const char*)sqlite3_column_text(st,2)));json_object_object_add(o,"domains",json_object_new_int(sqlite3_column_int(st,3)));json_object_object_add(o,"source",json_object_new_string((const char*)sqlite3_column_text(st,4)));json_object_object_add(o,"sort_key",json_object_new_string((const char*)sqlite3_column_text(st,5)));json_object_array_add(arr,o);}}
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(1));json_object_object_add(d,"groups",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_signature_db_domains(struct json_object *cfg)
{
    sqlite3 *db=NULL; sqlite3_stmt *st=NULL; int limit=500,offset=0,group_id=0; const char*q="";
    struct json_object*d=json_object_new_object(),*arr=json_object_new_array();
    if(cfg){limit=nc_json_int_def(cfg,"limit",500);offset=nc_json_int_def(cfg,"offset",0);group_id=nc_json_int_def(cfg,"group_id",0);q=nc_json_str_def(cfg,"q","");}
    if(limit<=0||limit>5000)limit=500;if(offset<0)offset=0;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"domains",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);} 
    const char*sql="SELECT e.domain,e.remark,e.source,e.group_id,g.category,g.subcategory,COALESCE(e.sort_key,'') FROM domain_entry e JOIN domain_group g ON g.group_id=e.group_id WHERE (?1=0 OR e.group_id=?1) AND (?2='' OR e.domain LIKE '%'||?2||'%' OR e.remark LIKE '%'||?2||'%') ORDER BY e.sort_key,e.domain LIMIT ?3 OFFSET ?4";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_int(st,1,group_id);sqlite3_bind_text(st,2,q,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,limit);sqlite3_bind_int(st,4,offset);while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"domain",json_object_new_string((const char*)sqlite3_column_text(st,0)));json_object_object_add(o,"remark",json_object_new_string((const char*)sqlite3_column_text(st,1)));json_object_object_add(o,"source",json_object_new_string((const char*)sqlite3_column_text(st,2)));json_object_object_add(o,"group_id",json_object_new_int(sqlite3_column_int(st,3)));json_object_object_add(o,"category",json_object_new_string((const char*)sqlite3_column_text(st,4)));json_object_object_add(o,"subcategory",json_object_new_string((const char*)sqlite3_column_text(st,5)));json_object_object_add(o,"sort_key",json_object_new_string((const char*)sqlite3_column_text(st,6)));json_object_array_add(arr,o);}}
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(1));json_object_object_add(d,"group_id",json_object_new_int(group_id));json_object_object_add(d,"q",json_object_new_string(q));json_object_object_add(d,"limit",json_object_new_int(limit));json_object_object_add(d,"offset",json_object_new_int(offset));json_object_object_add(d,"domains",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_signature_db_device_vendors(struct json_object *cfg)
{
    sqlite3 *db=NULL;sqlite3_stmt*st=NULL;int limit=500,offset=0;const char*q="";struct json_object*d=json_object_new_object(),*arr=json_object_new_array();
    if(cfg){limit=nc_json_int_def(cfg,"limit",500);offset=nc_json_int_def(cfg,"offset",0);q=nc_json_str_def(cfg,"q","");} if(limit<=0||limit>5000)limit=500;if(offset<0)offset=0;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"vendors",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);} 
    const char*sql="SELECT vendor_id,name,normalized_name,COALESCE(legacy_id,''),COALESCE(source,''),(SELECT COUNT(*) FROM device_fingerprint_rule r WHERE r.vendor_id=v.vendor_id AND r.enabled=1) FROM device_vendor v WHERE (?1='' OR name LIKE '%'||?1||'%' OR normalized_name LIKE '%'||?1||'%') ORDER BY vendor_id LIMIT ?2 OFFSET ?3";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,q,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,limit);sqlite3_bind_int(st,3,offset);while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"vendor_id",json_object_new_int(sqlite3_column_int(st,0)));json_object_object_add(o,"name",json_object_new_string((const char*)sqlite3_column_text(st,1)));json_object_object_add(o,"normalized_name",json_object_new_string((const char*)sqlite3_column_text(st,2)));json_object_object_add(o,"legacy_id",json_object_new_string((const char*)sqlite3_column_text(st,3)));json_object_object_add(o,"source",json_object_new_string((const char*)sqlite3_column_text(st,4)));json_object_object_add(o,"rules",json_object_new_int(sqlite3_column_int(st,5)));json_object_array_add(arr,o);}}
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(1));json_object_object_add(d,"vendors",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_signature_db_device_types(struct json_object *cfg)
{
    sqlite3 *db=NULL;sqlite3_stmt*st=NULL;struct json_object*d=json_object_new_object(),*arr=json_object_new_array();(void)cfg;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"types",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);} 
    const char*sql="SELECT type_id,slug,name,COALESCE(legacy_id,''),COALESCE(source,''),(SELECT COUNT(*) FROM device_fingerprint_rule r WHERE r.type_id=t.type_id AND r.enabled=1) FROM device_type t ORDER BY type_id";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"type_id",json_object_new_int(sqlite3_column_int(st,0)));json_object_object_add(o,"slug",json_object_new_string((const char*)sqlite3_column_text(st,1)));json_object_object_add(o,"name",json_object_new_string((const char*)sqlite3_column_text(st,2)));json_object_object_add(o,"legacy_id",json_object_new_string((const char*)sqlite3_column_text(st,3)));json_object_object_add(o,"source",json_object_new_string((const char*)sqlite3_column_text(st,4)));json_object_object_add(o,"rules",json_object_new_int(sqlite3_column_int(st,5)));json_object_array_add(arr,o);}}
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(1));json_object_object_add(d,"types",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_signature_db_fingerprint_rules(struct json_object *cfg)
{
    sqlite3 *db=NULL;sqlite3_stmt*st=NULL;int limit=500,offset=0;const char*match_type="",*q="";struct json_object*d=json_object_new_object(),*arr=json_object_new_array();
    if(cfg){limit=nc_json_int_def(cfg,"limit",500);offset=nc_json_int_def(cfg,"offset",0);match_type=nc_json_str_def(cfg,"match_type","");q=nc_json_str_def(cfg,"q","");} if(limit<=0||limit>5000)limit=500;if(offset<0)offset=0;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"rules",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);} 
    const char*sql="SELECT rule_id,source,match_type,pattern,COALESCE(pattern2,''),vendor_id,type_id,COALESCE(vendor_name,''),COALESCE(type_name,''),COALESCE(os_name,''),COALESCE(model,''),confidence,COALESCE(legacy_id,''),COALESCE(sort_key,'') FROM device_fingerprint_rule WHERE enabled=1 AND (?1='' OR match_type=?1) AND (?2='' OR pattern LIKE '%'||?2||'%' OR model LIKE '%'||?2||'%' OR vendor_name LIKE '%'||?2||'%') ORDER BY sort_key,rule_id LIMIT ?3 OFFSET ?4";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,match_type,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,q,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,limit);sqlite3_bind_int(st,4,offset);while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"rule_id",json_object_new_int(sqlite3_column_int(st,0)));json_object_object_add(o,"source",json_object_new_string((const char*)sqlite3_column_text(st,1)));json_object_object_add(o,"match_type",json_object_new_string((const char*)sqlite3_column_text(st,2)));json_object_object_add(o,"pattern",json_object_new_string((const char*)sqlite3_column_text(st,3)));json_object_object_add(o,"pattern2",json_object_new_string((const char*)sqlite3_column_text(st,4)));json_object_object_add(o,"vendor_id",json_object_new_int(sqlite3_column_int(st,5)));json_object_object_add(o,"type_id",json_object_new_int(sqlite3_column_int(st,6)));json_object_object_add(o,"vendor",json_object_new_string((const char*)sqlite3_column_text(st,7)));json_object_object_add(o,"type",json_object_new_string((const char*)sqlite3_column_text(st,8)));json_object_object_add(o,"os_name",json_object_new_string((const char*)sqlite3_column_text(st,9)));json_object_object_add(o,"model",json_object_new_string((const char*)sqlite3_column_text(st,10)));json_object_object_add(o,"confidence",json_object_new_double(sqlite3_column_double(st,11)));json_object_object_add(o,"legacy_id",json_object_new_string((const char*)sqlite3_column_text(st,12)));json_object_object_add(o,"sort_key",json_object_new_string((const char*)sqlite3_column_text(st,13)));json_object_array_add(arr,o);}}
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(1));json_object_object_add(d,"match_type",json_object_new_string(match_type));json_object_object_add(d,"q",json_object_new_string(q));json_object_object_add(d,"limit",json_object_new_int(limit));json_object_object_add(d,"offset",json_object_new_int(offset));json_object_object_add(d,"rules",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}
#endif
