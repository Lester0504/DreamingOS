/* ══════════════════════════════════════════════════════════════════════
 * Init / Close
 * ══════════════════════════════════════════════════════════════════════ */

sqlite3 *jmx_netconfig_db_write_connection(void)
{
    return jmx_netconfig_db_init() == 0 ? g_netconfig_db : NULL;
}

int jmx_netconfig_db_init(void)
{
    int rc;
    if (g_netconfig_db) return 0;
    nc_mkdirs();
    /*
     * A failed recovery is recorded, not fatal.
     *
     * This used to return -1, which meant sqlite was never even opened and every
     * netconfig reader -- gateway ports, physical ports, wan_list, lan_config --
     * answered "source unavailable" while the process reported itself healthy.
     * The blast radius of refusing to start was far larger than the risk being
     * defended against, which is a tampered advanced-routing publish artifact.
     *
     * The write path still fails closed: callers that publish artifacts check
     * their own trust conditions, and g_nc_adv_recovery_failed lets the
     * capability surface say so instead of pretending nothing happened.
     */
    if (nc_adv_recover_pending_publish() != 0) {
        g_nc_adv_recovery_failed = 1;
        LOG_WARN("advanced routing publish recovery failed; continuing with the "
                 "read path available and advanced-routing publish disabled\n");
    } else {
        g_nc_adv_recovery_failed = 0;
    }
    rc = sqlite3_open(g_netconfig_db_path, &g_netconfig_db);
    if (rc != SQLITE_OK) {
        LOG_ERROR("open netconfig db failed: %s\n",
                  g_netconfig_db ? sqlite3_errmsg(g_netconfig_db) : "oom");
        if (g_netconfig_db) sqlite3_close(g_netconfig_db);
        g_netconfig_db = NULL;
        return -1;
    }
    sqlite3_busy_timeout(g_netconfig_db, 3000);
    nc_exec("PRAGMA journal_mode=WAL");
    nc_exec("PRAGMA foreign_keys=ON");
    if (nc_schema() != 0) goto fail;
    if (jmx_gateway_shadow_schema_ensure() != 0) goto fail;
    nc_sys_settings_db_init();
    nc_mp_boot_publish();
    nc_wifi_db_init();
    if (nc_work_mode_import_uci_once() != 0)
        goto fail;
    if (nc_jmx_user_import_uci_once() != 0)
        goto fail;
    if (jmx_netconfig_migrate_from_uci() != 0)
        goto fail;
    if (nc_dns_config_compat_migrate_once() != 0)
        goto fail;
    return 0;
fail:
    sqlite3_close(g_netconfig_db);
    g_netconfig_db = NULL;
    return -1;
}

static int nc_work_mode_import_uci_once(void)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *ctx = NULL;
    int mode = 0;
    int imported = 0;
    int existing_updated_at = 0;
    char mode_value[16] = "";

    if (!g_netconfig_db)
        return -1;
    if (nc_prepare(&st,
        "SELECT 1 FROM config_migration WHERE name=?1 AND status='done'") != 0)
        return -1;
    sqlite3_bind_text(st, 1, NC_WORK_MODE_UCI_MIGRATION, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    st = NULL;

    if (nc_prepare(&st, "SELECT updated_at FROM work_mode_settings WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        existing_updated_at = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;

    if (!existing_updated_at) {
        ctx = uci_alloc_context();
        if (ctx && jmx_uci_get_value(ctx, "jmx.network.work_mode",
                                     mode_value, sizeof(mode_value)) == 0) {
            mode = atoi(mode_value);
            if (mode != 0 && mode != 1)
                mode = 0;
            imported = 1;
        }
        if (ctx)
            uci_free_context(ctx);
    }

    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (!existing_updated_at) {
        if (nc_prepare(&st,
            "UPDATE work_mode_settings SET mode=?1,wan_required=?2,"
            "dhcp_policy='enabled',nat_policy='enabled',apply_state='ready',"
            "last_error='',updated_at=?3 WHERE id=1") != 0)
            goto rollback;
        sqlite3_bind_int(st, 1, mode);
        sqlite3_bind_int(st, 2, mode == 0);
        sqlite3_bind_int64(st, 3, nc_now_s());
        if (nc_step_done(st) != 0) {
            sqlite3_finalize(st);
            st = NULL;
            goto rollback;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st,
        "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail) "
        "VALUES(?1,'done','uci:/etc/config/jmx',?2,?3,?4)") != 0)
        goto rollback;
    sqlite3_bind_text(st, 1, NC_WORK_MODE_UCI_MIGRATION, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, imported);
    sqlite3_bind_int64(st, 3, nc_now_s());
    sqlite3_bind_text(st, 4,
                      existing_updated_at ? "preserved_existing_config_db_value" :
                      imported ? "legacy_uci_imported" : "default_seeded_no_legacy_uci",
                      -1, SQLITE_STATIC);
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback;
    }
    sqlite3_finalize(st);
    return nc_exec("COMMIT");

rollback:
    if (st)
        sqlite3_finalize(st);
    nc_exec("ROLLBACK");
    return -1;
}

static int nc_legacy_mac_ok(const char *mac)
{
    size_t i;

    if (!mac || strlen(mac) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':')
                return 0;
        } else if (!isxdigit((unsigned char)mac[i])) {
            return 0;
        }
    }
    return 1;
}

static void nc_legacy_mac_normalize(const char *input, char *output, size_t output_len)
{
    size_t i;

    snprintf(output, output_len, "%s", input ? input : "");
    for (i = 0; output[i]; i++)
        output[i] = (char)tolower((unsigned char)output[i]);
}

static int nc_jmx_user_import_uci_once(void)
{
    sqlite3_stmt *st = NULL, *nickname_st = NULL;
    struct uci_context *ctx = NULL;
    int settings_initialized = 0, control_initialized = 0;
    int appfilter_enabled = 1, macfilter_enabled = 1, record_enabled = 1;
    int theme_mode = 1, record_time = 3, app_valid_time = 3;
    int health_flush_sec = 60, health_prune_sec = 300, health_max_age_days = 30;
    int imported_settings = 0, imported_nicknames = 0;
    char lan_ifname[32] = "br-lan";
    char history_data_size[64] = "10";
    char history_data_path[256] = "/tmp/jmx";
    char monitor_device[64] = "";
    int rc = -1;

    if (!g_netconfig_db)
        return -1;
    nc_netctl_db_init();
    if (nc_prepare(&st,
        "SELECT 1 FROM config_migration WHERE name=?1 AND status='done'") != 0)
        return -1;
    sqlite3_bind_text(st, 1, NC_JMX_USER_UCI_MIGRATION, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "SELECT updated_at FROM legacy_jmx_settings WHERE id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        return -1;
    settings_initialized = sqlite3_column_int64(st, 0) > 0;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "SELECT updated_at FROM network_control_global WHERE id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        return -1;
    control_initialized = sqlite3_column_int64(st, 0) > 0;
    sqlite3_finalize(st);
    st = NULL;

    ctx = uci_alloc_context();
    if (ctx && !settings_initialized) {
        char value[64];
        if (jmx_uci_get_value(ctx, "jmx.global.lan_ifname", value, sizeof(value)) == 0 &&
            value[0])
            JMX_STRBUF_COPY(lan_ifname, value);
        if (jmx_uci_get_value(ctx, "jmx.global.theme_mode", value, sizeof(value)) == 0)
            theme_mode = atoi(value) == 0 ? 0 : 1;
        if (jmx_uci_get_value(ctx, "jmx.record.record_time", value, sizeof(value)) == 0)
            record_time = atoi(value) >= 0 ? atoi(value) : 3;
        if (jmx_uci_get_value(ctx, "jmx.record.app_valid_time", value, sizeof(value)) == 0)
            app_valid_time = atoi(value) >= 0 ? atoi(value) : 3;
        if (jmx_uci_get_value(ctx, "jmx.record.history_data_size", value, sizeof(value)) == 0)
            snprintf(history_data_size, sizeof(history_data_size), "%s", value);
        if (jmx_uci_get_value(ctx, "jmx.record.history_data_path", history_data_path,
                              sizeof(history_data_path)) != 0 || !history_data_path[0])
            snprintf(history_data_path, sizeof(history_data_path), "%s", "/tmp/jmx");
        (void)jmx_uci_get_value(ctx, "jmx.dashboard.monitor_device", monitor_device,
                                sizeof(monitor_device));
        if (jmx_uci_get_value(ctx, "jmx.health.global.flush_sec", value,
                              sizeof(value)) == 0 && atoi(value) > 0)
            health_flush_sec = atoi(value);
        if (jmx_uci_get_value(ctx, "jmx.health.global.prune_sec", value,
                              sizeof(value)) == 0 && atoi(value) > 0)
            health_prune_sec = atoi(value);
        if (jmx_uci_get_value(ctx, "jmx.health.global.max_age_days", value,
                              sizeof(value)) == 0 && atoi(value) > 0)
            health_max_age_days = atoi(value);
        imported_settings = 1;
    }
    if (ctx && !control_initialized) {
        int value = jmx_uci_get_int_value(ctx, "jmx.appfilter.enable");
        if (value >= 0) appfilter_enabled = value ? 1 : 0;
        value = jmx_uci_get_int_value(ctx, "jmx.macfilter.enable");
        if (value >= 0) macfilter_enabled = value ? 1 : 0;
        value = jmx_uci_get_int_value(ctx, "jmx.record.enable");
        if (value >= 0) record_enabled = value ? 1 : 0;
    }
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (!settings_initialized) {
        if (nc_prepare(&st,
            "UPDATE legacy_jmx_settings SET lan_ifname=?1,theme_mode=?2,"
            "record_time=?3,app_valid_time=?4,history_data_size=?5,"
            "history_data_path=?6,monitor_device=?7,health_flush_sec=?8,"
            "health_prune_sec=?9,health_max_age_days=?10,updated_at=?11 WHERE id=1") != 0)
            goto rollback;
        sqlite3_bind_text(st, 1, lan_ifname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, theme_mode);
        sqlite3_bind_int(st, 3, record_time);
        sqlite3_bind_int(st, 4, app_valid_time);
        sqlite3_bind_text(st, 5, history_data_size, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, history_data_path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, monitor_device, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 8, health_flush_sec);
        sqlite3_bind_int(st, 9, health_prune_sec);
        sqlite3_bind_int(st, 10, health_max_age_days);
        sqlite3_bind_int64(st, 11, nc_now_s());
        if (nc_step_done(st) != 0)
            goto rollback;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (!control_initialized) {
        if (nc_prepare(&st,
            "UPDATE network_control_global SET appfilter_enabled=?1,"
            "macfilter_enabled=?2,record_enabled=?3,updated_at=?4 WHERE id=1") != 0)
            goto rollback;
        sqlite3_bind_int(st, 1, appfilter_enabled);
        sqlite3_bind_int(st, 2, macfilter_enabled);
        sqlite3_bind_int(st, 3, record_enabled);
        sqlite3_bind_int64(st, 4, nc_now_s());
        if (nc_step_done(st) != 0)
            goto rollback;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (ctx) {
        int count = jmx_uci_get_list_num(ctx, "user_info", "user_info");
        if (count > 0 && nc_prepare(&nickname_st,
            "INSERT INTO client_nickname(mac,nickname,updated_at) VALUES(?1,?2,?3) "
            "ON CONFLICT(mac) DO NOTHING") != 0)
            goto rollback;
        for (int i = 0; i < count; i++) {
            char mac[32] = "", normalized_mac[32] = "", nickname[128] = "";
            if (jmx_uci_get_array_value(ctx, "user_info.@user_info[%d].mac", i,
                                        mac, sizeof(mac)) != 0 ||
                jmx_uci_get_array_value(ctx, "user_info.@user_info[%d].nickname", i,
                                        nickname, sizeof(nickname)) != 0 || !nickname[0])
                continue;
            nc_legacy_mac_normalize(mac, normalized_mac, sizeof(normalized_mac));
            if (!nc_legacy_mac_ok(normalized_mac))
                continue;
            sqlite3_bind_text(nickname_st, 1, normalized_mac, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(nickname_st, 2, nickname, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(nickname_st, 3, nc_now_s());
            if (nc_step_done(nickname_st) != 0)
                goto rollback;
            imported_nicknames += nc_sqlite_changes() > 0;
            sqlite3_reset(nickname_st);
            sqlite3_clear_bindings(nickname_st);
        }
        sqlite3_finalize(nickname_st);
        nickname_st = NULL;
    }
    if (nc_prepare(&st,
        "SELECT s.lan_ifname,s.theme_mode,s.record_time,s.app_valid_time,"
        "s.history_data_size,s.history_data_path,g.appfilter_enabled,"
        "g.macfilter_enabled,g.record_enabled FROM legacy_jmx_settings s "
        "JOIN network_control_global g ON g.id=s.id WHERE s.id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW || !nc_sql_text(st, 0)[0] ||
        !nc_sql_text(st, 4)[0] || !nc_sql_text(st, 5)[0])
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail) "
        "VALUES(?1,'done','uci:/etc/config/jmx,user_info',?2,?3,?4)") != 0)
        goto rollback;
    sqlite3_bind_text(st, 1, NC_JMX_USER_UCI_MIGRATION, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, imported_settings + imported_nicknames);
    sqlite3_bind_int64(st, 3, nc_now_s());
    sqlite3_bind_text(st, 4,
        (settings_initialized || control_initialized)
            ? "preserved_existing_config_db_values_and_imported_missing_nicknames"
            : "legacy_uci_imported_and_read_back",
        -1, SQLITE_STATIC);
    if (nc_step_done(st) != 0)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_exec("COMMIT") != 0)
        goto rollback;
    rc = 0;
    goto done;

rollback:
    if (st) {
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nickname_st) {
        sqlite3_finalize(nickname_st);
        nickname_st = NULL;
    }
    nc_exec("ROLLBACK");
done:
    if (st)
        sqlite3_finalize(st);
    if (nickname_st)
        sqlite3_finalize(nickname_st);
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

int jmx_legacy_settings_get(jmx_legacy_settings_t *settings)
{
    sqlite3_stmt *st = NULL;

    if (!settings || jmx_netconfig_db_init() != 0)
        return -1;
    memset(settings, 0, sizeof(*settings));
    if (nc_prepare(&st,
        "SELECT s.lan_ifname,s.theme_mode,g.record_enabled,s.record_time,"
        "s.app_valid_time,s.history_data_size,s.history_data_path,s.monitor_device,"
        "s.health_flush_sec,s.health_prune_sec,s.health_max_age_days "
        "FROM legacy_jmx_settings s JOIN network_control_global g ON g.id=s.id "
        "WHERE s.id=1") != 0 || sqlite3_step(st) != SQLITE_ROW)
        goto failed;
    snprintf(settings->lan_ifname, sizeof(settings->lan_ifname), "%s", nc_sql_text(st, 0));
    settings->theme_mode = sqlite3_column_int(st, 1);
    settings->record_enabled = sqlite3_column_int(st, 2);
    settings->record_time = sqlite3_column_int(st, 3);
    settings->app_valid_time = sqlite3_column_int(st, 4);
    snprintf(settings->history_data_size, sizeof(settings->history_data_size), "%s", nc_sql_text(st, 5));
    snprintf(settings->history_data_path, sizeof(settings->history_data_path), "%s", nc_sql_text(st, 6));
    snprintf(settings->monitor_device, sizeof(settings->monitor_device), "%s", nc_sql_text(st, 7));
    settings->health_flush_sec = sqlite3_column_int(st, 8);
    settings->health_prune_sec = sqlite3_column_int(st, 9);
    settings->health_max_age_days = sqlite3_column_int(st, 10);
    sqlite3_finalize(st);
    return 0;
failed:
    if (st)
        sqlite3_finalize(st);
    return -1;
}

int jmx_legacy_settings_set_system(const char *lan_ifname, int theme_mode)
{
    sqlite3_stmt *st = NULL;
    char readback[32] = "";
    int rc = -1;

    if (!lan_ifname || !lan_ifname[0] || strlen(lan_ifname) >= sizeof(readback) ||
        (theme_mode != 0 && theme_mode != 1) || jmx_netconfig_db_init() != 0 ||
        nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE legacy_jmx_settings SET lan_ifname=?1,theme_mode=?2,updated_at=?3 WHERE id=1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, lan_ifname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, theme_mode);
    sqlite3_bind_int64(st, 3, nc_now_s());
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "SELECT lan_ifname,theme_mode FROM legacy_jmx_settings WHERE id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    snprintf(readback, sizeof(readback), "%s", nc_sql_text(st, 0));
    if (strcmp(readback, lan_ifname) || sqlite3_column_int(st, 1) != theme_mode)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    rc = nc_exec("COMMIT");
done:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0)
        nc_exec("ROLLBACK");
    return rc;
}

int jmx_legacy_settings_set_record(int enabled, int record_time,
                                   int app_valid_time,
                                   const char *history_data_size,
                                   const char *history_data_path)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if ((enabled != 0 && enabled != 1) || record_time < 0 || app_valid_time < 0 ||
        !history_data_size || !history_data_size[0] ||
        !history_data_path || !history_data_path[0] ||
        jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE legacy_jmx_settings SET record_time=?1,app_valid_time=?2,"
        "history_data_size=?3,history_data_path=?4,updated_at=?5 WHERE id=1") != 0)
        goto done;
    sqlite3_bind_int(st, 1, record_time);
    sqlite3_bind_int(st, 2, app_valid_time);
    sqlite3_bind_text(st, 3, history_data_size, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, history_data_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, nc_now_s());
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "UPDATE network_control_global SET record_enabled=?1,updated_at=?2 WHERE id=1") != 0)
        goto done;
    sqlite3_bind_int(st, 1, enabled);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "SELECT s.record_time,s.app_valid_time,s.history_data_size,s.history_data_path,"
        "g.record_enabled FROM legacy_jmx_settings s JOIN network_control_global g "
        "ON g.id=s.id WHERE s.id=1") != 0 || sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_int(st, 0) != record_time ||
        sqlite3_column_int(st, 1) != app_valid_time ||
        strcmp(nc_sql_text(st, 2), history_data_size) ||
        strcmp(nc_sql_text(st, 3), history_data_path) ||
        sqlite3_column_int(st, 4) != enabled)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    rc = nc_exec("COMMIT");
done:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0)
        nc_exec("ROLLBACK");
    return rc;
}

int jmx_legacy_settings_set_dashboard(const char *monitor_device)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!monitor_device || strlen(monitor_device) >= 64 ||
        jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE legacy_jmx_settings SET monitor_device=?1,updated_at=?2 WHERE id=1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, monitor_device, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "SELECT monitor_device FROM legacy_jmx_settings WHERE id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW || strcmp(nc_sql_text(st, 0), monitor_device))
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    rc = nc_exec("COMMIT");
done:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0)
        nc_exec("ROLLBACK");
    return rc;
}

int jmx_client_nickname_set(const char *mac, const char *nickname)
{
    sqlite3_stmt *st = NULL;
    char normalized_mac[32];
    int rc = -1;

    nc_legacy_mac_normalize(mac, normalized_mac, sizeof(normalized_mac));
    if (!nc_legacy_mac_ok(normalized_mac) || !nickname || strlen(nickname) >= 64 ||
        jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nickname[0]) {
        if (nc_prepare(&st,
            "INSERT INTO client_nickname(mac,nickname,updated_at) VALUES(?1,?2,?3) "
            "ON CONFLICT(mac) DO UPDATE SET nickname=excluded.nickname,updated_at=excluded.updated_at") != 0)
            goto done;
        sqlite3_bind_text(st, 1, normalized_mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, nickname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, nc_now_s());
    } else {
        if (nc_prepare(&st, "DELETE FROM client_nickname WHERE mac=?1") != 0)
            goto done;
        sqlite3_bind_text(st, 1, normalized_mac, -1, SQLITE_TRANSIENT);
    }
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, "SELECT nickname FROM client_nickname WHERE mac=?1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, normalized_mac, -1, SQLITE_TRANSIENT);
    if ((nickname[0] && (sqlite3_step(st) != SQLITE_ROW || strcmp(nc_sql_text(st, 0), nickname))) ||
        (!nickname[0] && sqlite3_step(st) != SQLITE_DONE))
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    rc = nc_exec("COMMIT");
done:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0)
        nc_exec("ROLLBACK");
    return rc;
}

int jmx_client_nickname_foreach(jmx_client_nickname_cb callback, void *arg)
{
    sqlite3_stmt *st = NULL;
    int rc = 0;

    if (!callback || jmx_netconfig_db_init() != 0 ||
        nc_prepare(&st, "SELECT mac,nickname FROM client_nickname ORDER BY mac") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (callback(nc_sql_text(st, 0), nc_sql_text(st, 1), arg) != 0) {
            rc = -1;
            break;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

int jmx_network_control_appfilter_enabled(void)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (jmx_netconfig_db_init() != 0 ||
        nc_prepare(&st,
            "SELECT enabled AND appfilter_enabled FROM network_control_global WHERE id=1") != 0)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0) ? 1 : 0;
    sqlite3_finalize(st);
    return enabled;
}

int jmx_network_control_macfilter_enabled(void)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (jmx_netconfig_db_init() != 0 ||
        nc_prepare(&st,
            "SELECT enabled AND macfilter_enabled FROM network_control_global WHERE id=1") != 0)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0) ? 1 : 0;
    sqlite3_finalize(st);
    return enabled;
}

int jmx_network_control_set_filter_enabled(const char *filter, int enabled)
{
    sqlite3_stmt *st = NULL;
    const char *sql;
    int readback = -1;
    int rc = -1;

    if (!filter || (enabled != 0 && enabled != 1))
        return -1;
    if (!strcmp(filter, "app"))
        sql = "UPDATE network_control_global SET appfilter_enabled=?1,updated_at=?2 WHERE id=1";
    else if (!strcmp(filter, "mac"))
        sql = "UPDATE network_control_global SET macfilter_enabled=?1,updated_at=?2 WHERE id=1";
    else
        return -1;
    if (jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st, sql) != 0)
        goto done;
    sqlite3_bind_int(st, 1, enabled);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st, !strcmp(filter, "app") ?
        "SELECT appfilter_enabled FROM network_control_global WHERE id=1" :
        "SELECT macfilter_enabled FROM network_control_global WHERE id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    readback = sqlite3_column_int(st, 0) ? 1 : 0;
    if (readback != enabled)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    rc = nc_exec("COMMIT");
done:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0)
        nc_exec("ROLLBACK");
    return rc;
}

int jmx_work_mode_config_get(int *mode, char *last_apply_id,
                             size_t last_apply_id_len,
                             char *apply_state, size_t apply_state_len)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!mode || jmx_netconfig_db_init() != 0)
        return -1;
    if (last_apply_id && last_apply_id_len)
        last_apply_id[0] = '\0';
    if (apply_state && apply_state_len)
        apply_state[0] = '\0';
    if (nc_prepare(&st,
        "SELECT mode,last_apply_id,apply_state FROM work_mode_settings WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *mode = sqlite3_column_int(st, 0);
        if (*mode != 0 && *mode != 1)
            *mode = 0;
        if (last_apply_id && last_apply_id_len)
            snprintf(last_apply_id, last_apply_id_len, "%s", nc_sql_text(st, 1));
        if (apply_state && apply_state_len)
            snprintf(apply_state, apply_state_len, "%s", nc_sql_text(st, 2));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

int jmx_netconfig_work_mode_is_side_router(void)
{
    int mode = 0;

    return jmx_work_mode_config_get(&mode, NULL, 0, NULL, 0) == 0 && mode == 1;
}

static const char *nc_side_router_executable(const char *const paths[])
{
    size_t i;

    for (i = 0; paths && paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}

static int nc_side_router_capture(const char *path, char *const argv[],
                                  struct jmx_exec_result *result)
{
    int rc;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    if (!path)
        return -1;
    rc = jmx_exec_capture(path, argv, 4096, 1500, result);
    return rc == 0 && result->exit_code == 0 && !result->timed_out &&
           !result->truncated && result->term_signal == 0 ? 0 : -1;
}

static void nc_side_router_lan_config(char *ip, size_t ip_len,
                                      char *gateway, size_t gateway_len,
                                      char *proto, size_t proto_len)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_section *lan = NULL;
    const char *value;

    if (ip && ip_len) ip[0] = '\0';
    if (gateway && gateway_len) gateway[0] = '\0';
    if (proto && proto_len) snprintf(proto, proto_len, "static");
    if (!ctx || uci_load(ctx, "network", &pkg) != UCI_OK)
        goto done;
    lan = uci_lookup_section(ctx, pkg, "lan");
    if (!lan)
        goto done;
    value = uci_lookup_option_string(ctx, lan, "ipaddr");
    if (value && ip && ip_len)
        snprintf(ip, ip_len, "%s", value);
    value = uci_lookup_option_string(ctx, lan, "gateway");
    if (value && gateway && gateway_len)
        snprintf(gateway, gateway_len, "%s", value);
    value = uci_lookup_option_string(ctx, lan, "proto");
    if (value && value[0] && proto && proto_len)
        snprintf(proto, proto_len, "%s", value);
done:
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
}

static void nc_side_router_default_route(char *gateway, size_t gateway_len,
                                         char *ifname, size_t ifname_len)
{
    static const char *const paths[] = { "/sbin/ip", "/usr/sbin/ip", NULL };
    const char *path = nc_side_router_executable(paths);
    struct jmx_exec_result result = {0};
    char *argv[] = { (char *)path, "-4", "route", "show", "default", NULL };
    char *line;
    char *save = NULL;

    if (ifname && ifname_len)
        snprintf(ifname, ifname_len, "br-lan");
    if (nc_side_router_capture(path, argv, &result) != 0 || !result.output)
        goto done;
    for (line = strtok_r(result.output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char candidate_gateway[64] = "";
        char candidate_ifname[IFNAMSIZ] = "";
        char *via = strstr(line, " via ");
        char *dev = strstr(line, " dev ");
        struct in_addr addr;

        if (via)
            (void)sscanf(via + 5, "%63s", candidate_gateway);
        if (dev)
            (void)sscanf(dev + 5, "%15s", candidate_ifname);
        if (!candidate_gateway[0] || inet_pton(AF_INET, candidate_gateway, &addr) != 1)
            continue;
        if (gateway && gateway_len)
            snprintf(gateway, gateway_len, "%s", candidate_gateway);
        if (ifname && ifname_len && candidate_ifname[0])
            snprintf(ifname, ifname_len, "%s", candidate_ifname);
        if (!strcmp(candidate_ifname, "br-lan"))
            break;
    }
done:
    jmx_exec_result_free(&result);
}

static int nc_side_router_ping(const char *gateway, double *latency_ms)
{
    static const char *const paths[] = { "/bin/ping", "/usr/bin/ping", NULL };
    const char *path = nc_side_router_executable(paths);
    struct jmx_exec_result result = {0};
    struct in_addr addr;
    char *time_value;
    char *argv[] = { (char *)path, "-c", "1", "-W", "1", (char *)gateway, NULL };
    double latency = -1.0;

    if (latency_ms)
        *latency_ms = -1.0;
    if (!gateway || inet_pton(AF_INET, gateway, &addr) != 1)
        return 0;
    if (nc_side_router_capture(path, argv, &result) != 0) {
        jmx_exec_result_free(&result);
        return 0;
    }
    if (result.output && (time_value = strstr(result.output, "time=")) != NULL &&
        sscanf(time_value + 5, "%lf", &latency) == 1 && latency_ms)
        *latency_ms = latency;
    jmx_exec_result_free(&result);
    return 1;
}

#define NC_SIDE_ROUTER_UPLINK_CACHE_MS 1000

struct nc_side_router_uplink_snapshot {
    int valid;
    int64_t sampled_at_ms;
    char ip[64];
    char gateway[64];
    char ifname[IFNAMSIZ];
    char proto[32];
    int reachable;
    double latency_ms;
};

static pthread_mutex_t g_nc_side_router_uplink_lock = PTHREAD_MUTEX_INITIALIZER;
static struct nc_side_router_uplink_snapshot g_nc_side_router_uplink;

static int64_t nc_side_router_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nc_side_router_uplink_snapshot(struct nc_side_router_uplink_snapshot *snapshot)
{
    char configured_gateway[64] = "";
    int64_t now_ms = nc_side_router_monotonic_ms();

    memset(snapshot, 0, sizeof(*snapshot));
    pthread_mutex_lock(&g_nc_side_router_uplink_lock);
    if (g_nc_side_router_uplink.valid && now_ms > 0 &&
        now_ms >= g_nc_side_router_uplink.sampled_at_ms &&
        now_ms - g_nc_side_router_uplink.sampled_at_ms < NC_SIDE_ROUTER_UPLINK_CACHE_MS) {
        *snapshot = g_nc_side_router_uplink;
        pthread_mutex_unlock(&g_nc_side_router_uplink_lock);
        return;
    }
    pthread_mutex_unlock(&g_nc_side_router_uplink_lock);

    snprintf(snapshot->ifname, sizeof(snapshot->ifname), "br-lan");
    snprintf(snapshot->proto, sizeof(snapshot->proto), "static");
    nc_side_router_lan_config(snapshot->ip, sizeof(snapshot->ip),
                              configured_gateway, sizeof(configured_gateway),
                              snapshot->proto, sizeof(snapshot->proto));
    nc_side_router_default_route(snapshot->gateway, sizeof(snapshot->gateway),
                                 snapshot->ifname, sizeof(snapshot->ifname));
    if (!snapshot->gateway[0] && configured_gateway[0])
        snprintf(snapshot->gateway, sizeof(snapshot->gateway), "%s", configured_gateway);
    snapshot->reachable = nc_side_router_ping(snapshot->gateway, &snapshot->latency_ms);
    snapshot->sampled_at_ms = now_ms > 0 ? now_ms : nc_side_router_monotonic_ms();
    snapshot->valid = 1;

    pthread_mutex_lock(&g_nc_side_router_uplink_lock);
    g_nc_side_router_uplink = *snapshot;
    pthread_mutex_unlock(&g_nc_side_router_uplink_lock);
}

struct json_object *jmx_netconfig_side_router_uplink(void)
{
    struct json_object *wan;
    struct nc_side_router_uplink_snapshot snapshot;
    int online;

    if (!jmx_netconfig_work_mode_is_side_router())
        return NULL;
    nc_side_router_uplink_snapshot(&snapshot);
    online = snapshot.reachable;

    wan = json_object_new_object();
    json_object_object_add(wan, "id", json_object_new_string("side-router-uplink"));
    json_object_object_add(wan, "wan_id", json_object_new_string("side-router-uplink"));
    json_object_object_add(wan, "name", json_object_new_string("共享上行"));
    json_object_object_add(wan, "type", json_object_new_string("wan"));
    json_object_object_add(wan, "work_mode", json_object_new_string("side-router"));
    json_object_object_add(wan, "canonical_mode", json_object_new_string("side-router"));
    json_object_object_add(wan, "logical_uplink", json_object_new_boolean(1));
    json_object_object_add(wan, "uplink_kind", json_object_new_string("shared_l2"));
    json_object_object_add(wan, "shared_l2", json_object_new_boolean(1));
    json_object_object_add(wan, "ifname", json_object_new_string("br-lan"));
    json_object_object_add(wan, "device", json_object_new_string("br-lan"));
    json_object_object_add(wan, "runtime_device", json_object_new_string("br-lan"));
    json_object_object_add(wan, "upstream_iface", json_object_new_string(snapshot.ifname));
    json_object_object_add(wan, "ip", json_object_new_string(snapshot.ip));
    json_object_object_add(wan, "ipv4", json_object_new_string(snapshot.ip));
    json_object_object_add(wan, "local_ip", json_object_new_string(snapshot.ip));
    json_object_object_add(wan, "public_ip", json_object_new_null());
    json_object_object_add(wan, "public_ip_applicable", json_object_new_boolean(0));
    json_object_object_add(wan, "public_ip_reason", json_object_new_string("shared_l2_public_ip_not_observed"));
    json_object_object_add(wan, "gateway", json_object_new_string(snapshot.gateway));
    json_object_object_add(wan, "upstream_gateway", json_object_new_string(snapshot.gateway));
    json_object_object_add(wan, "proto", json_object_new_string(snapshot.proto[0] ? snapshot.proto : "static"));
    json_object_object_add(wan, "online", json_object_new_boolean(online));
    json_object_object_add(wan, "reachable", json_object_new_boolean(online));
    json_object_object_add(wan, "status", json_object_new_string(online ? "ok" : "degraded"));
    json_object_object_add(wan, "health_measured", json_object_new_boolean(snapshot.gateway[0] != '\0'));
    json_object_object_add(wan, "health_source", json_object_new_string("shared_upstream_gateway_probe"));
    json_object_object_add(wan, "health_reason", json_object_new_string(online ? "" : "upstream_gateway_unreachable"));
    json_object_object_add(wan, "latency_ms", snapshot.latency_ms >= 0.0 ? json_object_new_double(snapshot.latency_ms) : json_object_new_null());
    json_object_object_add(wan, "latency", snapshot.latency_ms >= 0.0 ? json_object_new_double(snapshot.latency_ms) : json_object_new_null());
    json_object_object_add(wan, "loss_pct", online ? json_object_new_int(0) : json_object_new_null());
    json_object_object_add(wan, "loss", online ? json_object_new_int(0) : json_object_new_null());
    json_object_object_add(wan, "carrier", json_object_new_null());
    json_object_object_add(wan, "carrier_name", json_object_new_string("共享上游"));
    json_object_object_add(wan, "carrier_applicable", json_object_new_boolean(0));
    json_object_object_add(wan, "carrier_reason", json_object_new_string("shared_l2_no_dedicated_carrier"));
    json_object_object_add(wan, "dedicated_physical_wan", json_object_new_boolean(0));
    json_object_object_add(wan, "physical_port_id", json_object_new_null());
    json_object_object_add(wan, "port_role_partition_applicable", json_object_new_boolean(0));
    json_object_object_add(wan, "link_speed_mbps", json_object_new_null());
    json_object_object_add(wan, "link_speed_applicable", json_object_new_boolean(0));
    json_object_object_add(wan, "uptime", json_object_new_null());
    json_object_object_add(wan, "connected_seconds", json_object_new_null());
    json_object_object_add(wan, "dial_session_applicable", json_object_new_boolean(0));
    json_object_object_add(wan, "editable", json_object_new_boolean(0));
    json_object_object_add(wan, "edit_reason", json_object_new_string("shared_l2_uplink_is_derived_from_work_mode"));
    json_object_object_add(wan, "up_rate", json_object_new_int64(0));
    json_object_object_add(wan, "down_rate", json_object_new_int64(0));
    json_object_object_add(wan, "sample_valid", json_object_new_boolean(0));
    json_object_object_add(wan, "rate_source", json_object_new_string("shared_l2_interface_counter_pending"));
    json_object_object_add(wan, "zero_reason", json_object_new_string("shared_l2_rate_sample_pending"));
    json_object_object_add(wan, "order", json_object_new_int(1));
    return wan;
}

int jmx_work_mode_config_set_legacy(int mode)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if ((mode != 0 && mode != 1) || jmx_netconfig_db_init() != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE work_mode_settings SET mode=?1,wan_required=?2,apply_state='ready',"
        "last_error='',updated_at=?3 WHERE id=1") != 0)
        return -1;
    sqlite3_bind_int(st, 1, mode);
    sqlite3_bind_int(st, 2, mode == 0);
    sqlite3_bind_int64(st, 3, nc_now_s());
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

int jmx_work_mode_config_begin_apply(int target_mode, const char *rollback_id,
                                     int disable_dhcp, int disable_nat,
                                     int *previous_mode)
{
    sqlite3_stmt *st = NULL;
    int mode = 0, wan_required = 1;
    const char *dhcp_policy = "enabled";
    const char *nat_policy = "enabled";

    if ((target_mode != 0 && target_mode != 1) || !rollback_id || !rollback_id[0] ||
        jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "SELECT mode,wan_required,dhcp_policy,nat_policy FROM work_mode_settings WHERE id=1") != 0)
        goto rollback;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback;
    }
    mode = sqlite3_column_int(st, 0);
    wan_required = sqlite3_column_int(st, 1);
    dhcp_policy = strdup(nc_sql_text(st, 2));
    nat_policy = strdup(nc_sql_text(st, 3));
    sqlite3_finalize(st);
    st = NULL;
    if (!dhcp_policy || !nat_policy)
        goto rollback_free;
    if (nc_prepare(&st,
        "INSERT INTO work_mode_snapshot(rollback_id,previous_mode,previous_wan_required,"
        "previous_dhcp_policy,previous_nat_policy,created_at) VALUES(?1,?2,?3,?4,?5,?6)") != 0)
        goto rollback_free;
    sqlite3_bind_text(st, 1, rollback_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, mode);
    sqlite3_bind_int(st, 3, wan_required);
    sqlite3_bind_text(st, 4, dhcp_policy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, nat_policy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, nc_now_s());
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback_free;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "UPDATE work_mode_settings SET mode=?1,wan_required=?2,dhcp_policy=?3,"
        "nat_policy=?4,apply_state='applying',last_apply_id=?5,last_error='',"
        "updated_at=?6 WHERE id=1") != 0)
        goto rollback_free;
    sqlite3_bind_int(st, 1, target_mode);
    sqlite3_bind_int(st, 2, target_mode == 0);
    sqlite3_bind_text(st, 3, disable_dhcp ? "disabled" : "enabled", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, disable_nat ? "disabled" : "enabled", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, rollback_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, nc_now_s());
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        st = NULL;
        goto rollback_free;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (nc_exec("COMMIT") != 0)
        goto rollback_free;
    if (previous_mode)
        *previous_mode = mode;
    free((char *)dhcp_policy);
    free((char *)nat_policy);
    return 0;

rollback_free:
    free((char *)dhcp_policy);
    free((char *)nat_policy);
rollback:
    if (st)
        sqlite3_finalize(st);
    nc_exec("ROLLBACK");
    return -1;
}

int jmx_work_mode_config_finish_apply(int success, const char *error)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (jmx_netconfig_db_init() != 0 || nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (!success) {
        if (nc_prepare(&st,
            "UPDATE work_mode_settings SET "
            "mode=COALESCE((SELECT previous_mode FROM work_mode_snapshot WHERE rollback_id=last_apply_id),mode),"
            "wan_required=COALESCE((SELECT previous_wan_required FROM work_mode_snapshot WHERE rollback_id=last_apply_id),wan_required),"
            "dhcp_policy=COALESCE((SELECT previous_dhcp_policy FROM work_mode_snapshot WHERE rollback_id=last_apply_id),dhcp_policy),"
            "nat_policy=COALESCE((SELECT previous_nat_policy FROM work_mode_snapshot WHERE rollback_id=last_apply_id),nat_policy),"
            "apply_state='failed',last_error=?1,updated_at=?2 WHERE id=1") != 0)
            goto rollback;
    } else if (nc_prepare(&st,
        "UPDATE work_mode_settings SET apply_state='ready',last_error='',updated_at=?2 WHERE id=1") != 0) {
        goto rollback;
    }
    sqlite3_bind_text(st, 1, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    if (rc != 0)
        goto rollback;
    return nc_exec("COMMIT");
rollback:
    if (st)
        sqlite3_finalize(st);
    nc_exec("ROLLBACK");
    return -1;
}

int jmx_work_mode_config_begin_rollback(const char *rollback_id,
                                        int *target_mode)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!rollback_id || !rollback_id[0] || !target_mode ||
        jmx_netconfig_db_init() != 0)
        return -1;
    if (nc_prepare(&st,
        "SELECT previous_mode FROM work_mode_snapshot WHERE rollback_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, rollback_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *target_mode = sqlite3_column_int(st, 0);
        rc = (*target_mode == 0 || *target_mode == 1) ? 0 : -1;
    }
    sqlite3_finalize(st);
    return rc;
}

int jmx_work_mode_config_finish_rollback(int success,
                                         const char *rollback_id,
                                         const char *error)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!rollback_id || !rollback_id[0] || jmx_netconfig_db_init() != 0 ||
        nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (success) {
        if (nc_prepare(&st,
            "UPDATE work_mode_settings SET "
            "mode=(SELECT previous_mode FROM work_mode_snapshot WHERE rollback_id=?1),"
            "wan_required=(SELECT previous_wan_required FROM work_mode_snapshot WHERE rollback_id=?1),"
            "dhcp_policy=(SELECT previous_dhcp_policy FROM work_mode_snapshot WHERE rollback_id=?1),"
            "nat_policy=(SELECT previous_nat_policy FROM work_mode_snapshot WHERE rollback_id=?1),"
            "apply_state='ready',last_apply_id='',last_error='',updated_at=?2 WHERE id=1") != 0)
            goto rollback;
    } else if (nc_prepare(&st,
        "UPDATE work_mode_settings SET apply_state='rollback_failed',last_error=?3,"
        "updated_at=?2 WHERE id=1") != 0) {
        goto rollback;
    }
    sqlite3_bind_text(st, 1, rollback_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    sqlite3_bind_text(st, 3, error ? error : "", -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    st = NULL;
    if (rc != 0)
        goto rollback;
    if (success) {
        if (nc_prepare(&st, "DELETE FROM work_mode_snapshot WHERE rollback_id=?1") != 0)
            goto rollback;
        sqlite3_bind_text(st, 1, rollback_id, -1, SQLITE_TRANSIENT);
        rc = nc_step_done(st);
        sqlite3_finalize(st);
        st = NULL;
        if (rc != 0)
            goto rollback;
    }
    return nc_exec("COMMIT");
rollback:
    if (st)
        sqlite3_finalize(st);
    nc_exec("ROLLBACK");
    return -1;
}

/*
 * Device role is applied state, not setup intent. Reading setup_draft here
 * made merely saving the wizard form disable audit storage before apply had
 * succeeded, and also opened config.db from callers that only needed the role.
 * Missing or malformed state is the backwards-compatible gateway default.
 */
int jmx_device_role_get(char *role, size_t role_len)
{
    FILE *fp;
    char value[32] = "";

    if (!role || role_len < 8)
        return -1;
    snprintf(role, role_len, "gateway");
    fp = fopen("/etc/dreamingwrt/device_role", "r");
    if (!fp)
        return 0;
    if (fgets(value, sizeof(value), fp))
        value[strcspn(value, "\r\n")] = '\0';
    fclose(fp);
    if (!strcmp(value, "ap"))
        snprintf(role, role_len, "ap");
    else if (!strcmp(value, "controller"))
        snprintf(role, role_len, "controller");
    return 0;
}

/* Check if device is in AP mode. Returns 1 for AP and 0 otherwise. */
int jmx_device_role_is_ap(void)
{
    char role[16];
    if (jmx_device_role_get(role, sizeof(role)) != 0)
        return 0;
    return !strcmp(role, "ap") ? 1 : 0;
}

void jmx_netconfig_db_close(void)
{
    if (g_netconfig_db) { sqlite3_close(g_netconfig_db); g_netconfig_db = NULL; }
}
