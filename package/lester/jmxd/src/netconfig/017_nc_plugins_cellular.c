            if (!nc_safe_id_ok(id) || strlen(id) > 96) return "invalid_geo_feed_id";
            if (!name[0] || strlen(name) > 128) return "invalid_geo_feed_name";
            if (!nc_geo_source_url_ok(url)) return "invalid_geo_feed_url";
            if (!nc_geo_local_file_ok(local)) return "invalid_geo_feed_local_file";
            if (interval < 1 || interval > 8760) return "invalid_geo_feed_interval";
            if (!nc_geo_bool_field_strict(o, "enabled", 1, &enabled)) return "geo_feed_enabled_boolean_required";
            if (enabled && !url[0] && !local[0]) return "geo_feed_source_required";
            if (nc_geo_array_duplicate_id(arr, i, id)) return "duplicate_geo_feed";
        }
        if (feed_count) *feed_count = n;
    }
    return NULL;
}

struct json_object *jmx_geo_block_update(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = NULL;
    struct nc_geo_prefix_state prefix = {0, 0};
    sqlite3_stmt *st = NULL;
    const char *error;
    int64_t revision;
    int64_t requested_revision;
    int country_count = 0, rule_count = 0, feed_count = 0;
    int dry_run, confirm, apply, changed = 0;
    int countries_present, rules_present, feeds_present;
    int i, n;

    if (jmx_netconfig_db_init() != 0) {
        json_object_put(data);
        return nc_geo_error("storage_unavailable", 0);
    }
    nc_firewall_db_init();
    nc_geo_seed_countries();
    prefix = nc_geo_prefix_probe();
    revision = nc_geo_revision();
    error = nc_geo_validate(cfg, prefix, &country_count, &rule_count, &feed_count);
    if (error) {
        json_object_put(data);
        return nc_geo_error(error, revision);
    }
    dry_run = nc_json_bool_def(cfg, "dry_run", 0);
    confirm = nc_json_bool_def(cfg, "confirm", 0);
    apply = nc_json_bool_def(cfg, "apply", 0);
    requested_revision = json_object_get_int64(json_object_object_get(cfg, "revision"));
    countries_present = json_object_object_get_ex(cfg, "countries", &arr);
    rules_present = json_object_object_get_ex(cfg, "rules", &arr);
    feeds_present = json_object_object_get_ex(cfg, "feeds", &arr);

    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "valid", json_object_new_boolean(1));
    json_object_object_add(data, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(data, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    json_object_object_add(data, "country_count", json_object_new_int(country_count));
    json_object_object_add(data, "rule_count", json_object_new_int(rule_count));
    json_object_object_add(data, "feed_count", json_object_new_int(feed_count));
    json_object_object_add(data, "ready_for_save", json_object_new_boolean(1));
    json_object_object_add(data, "ready_for_apply", json_object_new_boolean(0));
    json_object_object_add(data, "dataplane_supported", json_object_new_boolean(0));
    json_object_object_add(data, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string(
        prefix.mmdb_available ? "draft" : "blocked"));
    json_object_object_add(data, "reason", json_object_new_string(
        !prefix.mmdb_available ? "geoip_country_mmdb_missing" :
        "geo_dataplane_status_via_aegisxd"));
    if (dry_run) {
        json_object_object_add(data, "saved", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    if (!confirm) {
        json_object_put(data);
        return nc_geo_error("confirmation_required", revision);
    }
    if (!json_object_object_get_ex(cfg, "revision", &arr)) {
        json_object_put(data);
        return nc_geo_error("revision_required", revision);
    }
    if (requested_revision != revision) {
        json_object_put(data);
        return nc_geo_error("revision_conflict", revision);
    }
    if (apply) {
        json_object_put(data);
        return nc_geo_error("geo_apply_requires_aegisxd_guarded_endpoint", revision);
    }
    if (nc_exec("BEGIN IMMEDIATE") != 0) goto failed;

    if (json_object_object_get_ex(cfg, "countries", &arr)) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id = nc_json_str_def(o, "id", nc_json_str_def(o, "code", ""));
            int enabled = nc_json_bool_def(o, "enabled", 0);
            if (nc_prepare(&st,
                "UPDATE firewall_geo_country SET enabled=?1,updated_at=?2 "
                "WHERE id=?3 AND official=1 AND enabled<>?1") != 0) goto failed;
            sqlite3_bind_int(st, 1, enabled);
            sqlite3_bind_int64(st, 2, nc_now_s());
            sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
            if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto failed; }
            changed += sqlite3_changes(g_netconfig_db);
            sqlite3_finalize(st); st = NULL;
        }
    }

    if (json_object_object_get_ex(cfg, "rules", &arr)) {
        if (nc_prepare(&st, "SELECT COUNT(*) FROM firewall_geo_rule") == 0 &&
            sqlite3_step(st) == SQLITE_ROW)
            changed += sqlite3_column_int(st, 0);
        sqlite3_finalize(st); st = NULL;
        if (nc_exec("DELETE FROM firewall_geo_rule") != 0) goto failed;
        n = json_object_array_length(arr);
        changed += n;
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id = nc_json_str_def(o, "id", "");
            if (nc_prepare(&st,
                "INSERT INTO firewall_geo_rule(id,name,action,direction,src_zone,dst_zone,enabled,updated_at) "
                "VALUES(?1,?2,?3,?4,?5,?6,?7,?8)") != 0) goto failed;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(o, "name", id), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, nc_json_str_def(o, "action", "block"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_json_str_def(o, "direction", "both"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, nc_json_str_def(o, "src_zone", "wan"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, nc_json_str_def(o, "dst_zone", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 7, nc_json_bool_def(o, "enabled", 1));
            sqlite3_bind_int64(st, 8, nc_now_s());
            if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto failed; }
            sqlite3_finalize(st); st = NULL;
        }
    }

    if (json_object_object_get_ex(cfg, "feeds", &arr)) {
        if (nc_prepare(&st, "SELECT COUNT(*) FROM firewall_geo_feed") == 0 &&
            sqlite3_step(st) == SQLITE_ROW)
            changed += sqlite3_column_int(st, 0);
        sqlite3_finalize(st); st = NULL;
        if (nc_exec("DELETE FROM firewall_geo_feed") != 0) goto failed;
        n = json_object_array_length(arr);
        changed += n;
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id = nc_json_str_def(o, "id", "");
            if (nc_prepare(&st,
                "INSERT INTO firewall_geo_feed(id,name,source_url,local_file,interval_hours,enabled) "
                "VALUES(?1,?2,?3,?4,?5,?6)") != 0) goto failed;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(o, "name", id), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, nc_json_str_def(o, "source_url", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_json_str_def(o, "local_file", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 5, nc_json_int_def(o, "interval_hours", 24));
            sqlite3_bind_int(st, 6, nc_json_bool_def(o, "enabled", 1));
            if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto failed; }
            sqlite3_finalize(st); st = NULL;
        }
    }

    if ((countries_present || rules_present || feeds_present) && nc_prepare(&st,
        "UPDATE firewall_geo_meta SET revision=revision+1,apply_state='draft',"
        "last_apply_ok=0,last_apply_error='geo_apply_pending',updated_at=?1 "
        "WHERE id=1") == 0) {
        sqlite3_bind_int64(st, 1, nc_now_s());
        if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto failed; }
        sqlite3_finalize(st); st = NULL;
    }
    if (nc_exec("COMMIT") != 0) goto failed_no_tx;
    json_object_object_add(data, "saved", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "changed", json_object_new_boolean(changed > 0));
    json_object_object_add(data, "revision", json_object_new_int64(nc_geo_revision()));
    json_object_object_add(data, "rollback_ok", json_object_new_boolean(1));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);

failed:
    sqlite3_finalize(st);
    nc_exec("ROLLBACK");
failed_no_tx:
    json_object_put(data);
    return nc_geo_error("geo_block_save_failed", revision);
}

int jmx_geo_block_set(struct json_object *cfg)
{
    struct json_object *response = jmx_geo_block_update(cfg);
    struct json_object *code = NULL;
    int ok = response && json_object_object_get_ex(response, "code", &code) &&
             code && json_object_get_int(code) == API_CODE_SUCCESS;
    if (response) json_object_put(response);
    return ok ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * Advanced Plugins: scan luci-app-* packages, return metadata
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *jmx_plugins_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) goto done;
    nc_plugin_db_init();

    /* Scan luci menu.d JSON files for installed plugins */
    DIR *dir = opendir("/usr/share/luci/menu.d");
    if (dir) {
        int64_t now = nc_now_s();
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            if (strncmp(ent->d_name, "luci-app-", 9) != 0) continue;
            char path[512];
            snprintf(path, sizeof(path), "/usr/share/luci/menu.d/%s", ent->d_name);
            FILE *fp = fopen(path, "r");
            if (!fp) continue;
            /* Read file content */
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            char *buf = malloc(sz + 1);
            if (!buf) { fclose(fp); continue; }
            /*
             * Terminate at the byte count actually read. Using sz assumed the
             * read always filled the buffer, so a short read left the tail
             * uninitialised and json_tokener_parse() ran over garbage.
             */
            buf[fread(buf, 1, (size_t)sz, fp)] = 0;
            fclose(fp);
            struct json_object *menu = json_tokener_parse(buf);
            free(buf);
            if (!menu || !json_object_is_type(menu, json_type_object)) { if (menu) json_object_put(menu); continue; }

            /* Extract first menu entry */
            json_object_object_foreach(menu, key, val) {
                if (!json_object_is_type(val, json_type_object)) continue;
                const char *title = nc_json_str_def(val, "title", ent->d_name + 9);
                /* Determine category from path prefix */
                const char *cat = "services";
                if (strstr(key, "/admin/network/")) cat = "network";
                else if (strstr(key, "/admin/system/")) cat = "system";
                else if (strstr(key, "/admin/services/")) cat = "services";
                else if (strstr(key, "/admin/vpn/")) cat = "vpn";
                else if (strstr(key, "/admin/nas/")) cat = "nas";

                /* Upsert into plugin_cache */
                if (nc_prepare(&st, "INSERT INTO plugin_cache(id,title,category,luci_path,package,installed,enabled,api_mode,risk,scanned_at) VALUES(?1,?2,?3,?4,?5,1,1,'luci_compat','low',?6) ON CONFLICT(id) DO UPDATE SET title=excluded.title,category=excluded.category,luci_path=excluded.luci_path,installed=1,scanned_at=excluded.scanned_at") == 0) {
                    sqlite3_bind_text(st, 1, ent->d_name + 9, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 2, title, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 3, cat, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 5, ent->d_name, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int64(st, 6, now);
                    nc_step_done(st); sqlite3_finalize(st); st = NULL;
                }
                break; /* one entry per file */
            }
            json_object_put(menu);
        }
        closedir(dir);
    }

    /* Return cached plugin list */
    if (nc_prepare(&st, "SELECT id,title,category,luci_path,icon,package,description,installed,enabled,api_mode,risk FROM plugin_cache ORDER BY category,title") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "title", st, 1); nc_add_text(o, "category", st, 2);
            nc_add_text(o, "luci_path", st, 3); nc_add_text(o, "icon", st, 4); nc_add_text(o, "package", st, 5);
            nc_add_text(o, "description", st, 6);
            json_object_object_add(o, "installed", json_object_new_boolean(sqlite3_column_int(st, 7)));
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 8)));
            nc_add_text(o, "api_mode", st, 9); nc_add_text(o, "risk", st, 10);
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(data, "plugins", arr);
    {
        struct json_object *cap = json_object_new_object();
        json_object_object_add(cap, "read", json_object_new_boolean(1));
        json_object_object_add(cap, "actions", json_object_new_boolean(0));
        json_object_object_add(cap, "install", json_object_new_boolean(0));
        json_object_object_add(cap, "remove", json_object_new_boolean(0));
        json_object_object_add(cap, "enable", json_object_new_boolean(0));
        json_object_object_add(cap, "disable", json_object_new_boolean(0));
        json_object_object_add(cap, "reason",
                               json_object_new_string("trusted_catalog_job_pipeline_pending"));
        json_object_object_add(data, "capabilities", cap);
    }
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_plugin_action(const char *id, const char *action)
{
    (void)id;
    (void)action;
    return -2;
}

/* ── Cellular / Modem DB Init ────────────────────────────────────────── */
static void nc_cellular_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS cellular_global (id INTEGER PRIMARY KEY CHECK (id = 1),enabled INTEGER NOT NULL DEFAULT 1,default_slot TEXT NOT NULL DEFAULT '',failover_mode TEXT NOT NULL DEFAULT 'none',failover_threshold INTEGER NOT NULL DEFAULT 3,probe_interval INTEGER NOT NULL DEFAULT 60,probe_host TEXT NOT NULL DEFAULT '8.8.8.8',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS cellular_slot (id TEXT PRIMARY KEY,name TEXT NOT NULL,modem_path TEXT NOT NULL DEFAULT '',dev_type TEXT NOT NULL DEFAULT 'unknown',enabled INTEGER NOT NULL DEFAULT 1,sim_id TEXT NOT NULL DEFAULT '',iccid TEXT NOT NULL DEFAULT '',imei TEXT NOT NULL DEFAULT '',operator TEXT NOT NULL DEFAULT '',signal INTEGER NOT NULL DEFAULT 0,apn TEXT NOT NULL DEFAULT 'cmnet',auth_type TEXT NOT NULL DEFAULT 'none',username TEXT NOT NULL DEFAULT '',password TEXT NOT NULL DEFAULT '',pincode TEXT NOT NULL DEFAULT '',network_type TEXT NOT NULL DEFAULT 'auto',roaming INTEGER NOT NULL DEFAULT 0,mTU INTEGER NOT NULL DEFAULT 1500,dial_num TEXT NOT NULL DEFAULT '*99#',remark TEXT NOT NULL DEFAULT '',sort_order INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS cellular_apn_profile (id TEXT PRIMARY KEY,name TEXT NOT NULL,apn TEXT NOT NULL,auth_type TEXT NOT NULL DEFAULT 'none',username TEXT NOT NULL DEFAULT '',password TEXT NOT NULL DEFAULT '',dial_num TEXT NOT NULL DEFAULT '*99#',network_type TEXT NOT NULL DEFAULT 'auto',remark TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS cellular_sms (id TEXT PRIMARY KEY,slot_id TEXT NOT NULL DEFAULT '',direction TEXT NOT NULL DEFAULT 'recv',phone TEXT NOT NULL DEFAULT '',content TEXT NOT NULL DEFAULT '',timestamp INTEGER NOT NULL DEFAULT 0,read_flag INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("INSERT OR IGNORE INTO cellular_global(id) VALUES(1)");
}

/* ── Cellular service_get: return all cellular config ── */
struct json_object *jmx_cellular_service_get(void)
{
    if (jmx_netconfig_db_init() != 0) return jmx_gen_api_response_data(API_CODE_ERROR, NULL); nc_cellular_db_init();
    struct json_object *resp = json_object_new_object(), *data = json_object_new_object(), *slots = json_object_new_array(), *apn_profiles = json_object_new_array(), *sms = json_object_new_array();
    sqlite3_stmt *st = NULL;
    /* global */
    if (nc_prepare(&st, "SELECT enabled,default_slot,failover_mode,failover_threshold,probe_interval,probe_host,updated_at FROM cellular_global WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *g = json_object_new_object();
            json_object_object_add(g, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
            nc_add_text(g, "default_slot", st, 1); nc_add_text(g, "failover_mode", st, 2);
            json_object_object_add(g, "failover_threshold", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(g, "probe_interval", json_object_new_int(sqlite3_column_int(st, 4)));
            nc_add_text(g, "probe_host", st, 5); json_object_object_add(g, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
            json_object_object_add(data, "global", g);
        }
        sqlite3_finalize(st);
    }
    /* slots */
    if (nc_prepare(&st, "SELECT id,name,modem_path,dev_type,enabled,sim_id,iccid,imei,operator,signal,apn,auth_type,username,password,pincode,network_type,roaming,mTU,dial_num,remark,sort_order,updated_at FROM cellular_slot ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "name", st, 1); nc_add_text(o, "modem_path", st, 2); nc_add_text(o, "dev_type", st, 3);
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 4)));
            nc_add_text(o, "sim_id", st, 5); nc_add_text(o, "iccid", st, 6); nc_add_text(o, "imei", st, 7); nc_add_text(o, "operator", st, 8);
            json_object_object_add(o, "signal", json_object_new_int(sqlite3_column_int(st, 9)));
            nc_add_text(o, "apn", st, 10); nc_add_text(o, "auth_type", st, 11); nc_add_text(o, "username", st, 12); nc_add_text(o, "password", st, 13);
            nc_add_text(o, "pincode", st, 14); nc_add_text(o, "network_type", st, 15);
            json_object_object_add(o, "roaming", json_object_new_boolean(sqlite3_column_int(st, 16)));
            json_object_object_add(o, "mTU", json_object_new_int(sqlite3_column_int(st, 17)));
            nc_add_text(o, "dial_num", st, 18); nc_add_text(o, "remark", st, 19);
            json_object_object_add(o, "sort_order", json_object_new_int(sqlite3_column_int(st, 20)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 21)));
            json_object_array_add(slots, o);
        }
        sqlite3_finalize(st);
    }
    /* apn profiles */
    if (nc_prepare(&st, "SELECT id,name,apn,auth_type,username,password,dial_num,network_type,remark,updated_at FROM cellular_apn_profile ORDER BY name") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "name", st, 1); nc_add_text(o, "apn", st, 2); nc_add_text(o, "auth_type", st, 3);
            nc_add_text(o, "username", st, 4); nc_add_text(o, "password", st, 5); nc_add_text(o, "dial_num", st, 6);
            nc_add_text(o, "network_type", st, 7); nc_add_text(o, "remark", st, 8);
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
            json_object_array_add(apn_profiles, o);
        }
        sqlite3_finalize(st);
    }
    /* sms */
    if (nc_prepare(&st, "SELECT id,slot_id,direction,phone,content,timestamp,read_flag,updated_at FROM cellular_sms ORDER BY timestamp DESC LIMIT 200") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "slot_id", st, 1); nc_add_text(o, "direction", st, 2);
            nc_add_text(o, "phone", st, 3); nc_add_text(o, "content", st, 4);
            json_object_object_add(o, "timestamp", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(o, "read_flag", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_array_add(sms, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "slots", slots);
    json_object_object_add(data, "apn_profiles", apn_profiles);
    json_object_object_add(data, "sms", sms);
    json_object_object_add(resp, "code", json_object_new_int(API_CODE_SUCCESS));
    json_object_object_add(resp, "data", data);
    return resp;
}

/* ── Cellular service_set: update global config ── */
int jmx_cellular_service_set(struct json_object *cfg)
{
    if (jmx_netconfig_db_init() != 0 || !cfg) return -1; nc_cellular_db_init();
    int enabled = nc_json_bool_def(cfg, "enabled", 1);
    const char *default_slot = nc_json_str_def(cfg, "default_slot", "");
    const char *failover_mode = nc_json_str_def(cfg, "failover_mode", "none");
    int failover_threshold = nc_json_int_def(cfg, "failover_threshold", 3);
    int probe_interval = nc_json_int_def(cfg, "probe_interval", 60);
    const char *probe_host = nc_json_str_def(cfg, "probe_host", "8.8.8.8");
    if (nc_txn_begin() != 0)
        return -1;
    int rc = 0;
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "UPDATE cellular_global SET enabled=?,default_slot=?,failover_mode=?,failover_threshold=?,probe_interval=?,probe_host=?,updated_at=? WHERE id=1") != 0) {
        rc = -1;
    } else {
        sqlite3_bind_int(st, 1, enabled); sqlite3_bind_text(st, 2, default_slot, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 3, failover_mode, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, failover_threshold); sqlite3_bind_int(st, 5, probe_interval); sqlite3_bind_text(st, 6, probe_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)nc_now_s());
        if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st);
    }
    return nc_txn_end(rc);
}

/* ── Cellular slot_set: add or update a modem slot ── */
int jmx_cellular_slot_set(struct json_object *cfg)
{
    if (jmx_netconfig_db_init() != 0 || !cfg)
        return -1;
    nc_cellular_db_init();
    const char *id = nc_json_str_def(cfg, "id", "");
    const char *name = nc_json_str_def(cfg, "name", "Modem");
    const char *modem_path = nc_json_str_def(cfg, "modem_path", "");
    const char *dev_type = nc_json_str_def(cfg, "dev_type", "unknown");
    int enabled = nc_json_bool_def(cfg, "enabled", 1);
    const char *apn = nc_json_str_def(cfg, "apn", "cmnet");
    const char *auth_type = nc_json_str_def(cfg, "auth_type", "none");
    const char *username = nc_json_str_def(cfg, "username", "");
    const char *password = nc_json_str_def(cfg, "password", "");
    const char *pincode = nc_json_str_def(cfg, "pincode", "");
    const char *network_type = nc_json_str_def(cfg, "network_type", "auto");
    int roaming = nc_json_bool_def(cfg, "roaming", 0);
    int mtu = nc_json_int_def(cfg, "mTU", 1500);
    const char *dial_num = nc_json_str_def(cfg, "dial_num", "*99#");
    const char *remark = nc_json_str_def(cfg, "remark", "");
    int sort_order = nc_json_int_def(cfg, "sort_order", 0);
    char uid[64]; snprintf(uid, sizeof(uid), "%s", id);
    if (!uid[0]) { snprintf(uid, sizeof(uid), "slot_%ld", nc_now_s()); }
    if (modem_path[0] && !jmx_mmcli_selector_ok(modem_path))
        return -1;
    /* Reject UCI-hostile values here rather than only when generating the
     * config file. Storing them would leave a row that can never produce a
     * valid /etc/config/dreamingwrt_cellular, so the failure would surface far
     * away from the request that caused it. */
    if (!jmx_uci_value_ok(uid) || !jmx_uci_value_ok(name) ||
        !jmx_uci_value_ok(modem_path) || !jmx_uci_value_ok(dev_type) ||
        !jmx_uci_value_ok(apn) || !jmx_uci_value_ok(auth_type) ||
        !jmx_uci_value_ok(username) || !jmx_uci_value_ok(password) ||
        !jmx_uci_value_ok(pincode) || !jmx_uci_value_ok(network_type) ||
        !jmx_uci_value_ok(dial_num) || !jmx_uci_value_ok(remark))
        return -1;
    if (nc_txn_begin() != 0)
        return -1;
    int rc = 0;
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT OR REPLACE INTO cellular_slot(id,name,modem_path,dev_type,enabled,apn,auth_type,username,password,pincode,network_type,roaming,mTU,dial_num,remark,sort_order,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)") != 0) {
        rc = -1;
    } else {
        sqlite3_bind_text(st, 1, uid, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, modem_path, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, dev_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, enabled); sqlite3_bind_text(st, 6, apn, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 7, auth_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, username, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 9, password, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, pincode, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 11, network_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 12, roaming); sqlite3_bind_int(st, 13, mtu); sqlite3_bind_text(st, 14, dial_num, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, remark, -1, SQLITE_TRANSIENT); sqlite3_bind_int(st, 16, sort_order);
        sqlite3_bind_int64(st, 17, (sqlite3_int64)nc_now_s());
        if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st);
    }
    return nc_txn_end(rc);
}

/* ── Cellular slot_delete ── */
int jmx_cellular_slot_delete(const char *id)
{
    if (jmx_netconfig_db_init() != 0 || !id || !id[0])
        return -1;
    nc_cellular_db_init();
    if (nc_txn_begin() != 0)
        return -1;
    int rc = 0;
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM cellular_slot WHERE id=?") != 0) {
        rc = -1;
    } else { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st); }
    return nc_txn_end(rc);
}

/* ── Cellular apn_profile_set: add or update APN profile ── */
int jmx_cellular_apn_profile_set(struct json_object *cfg)
{
    if (jmx_netconfig_db_init() != 0 || !cfg)
        return -1;
    nc_cellular_db_init();
    const char *id = nc_json_str_def(cfg, "id", "");
    const char *name = nc_json_str_def(cfg, "name", "");
    const char *apn = nc_json_str_def(cfg, "apn", "");
    const char *auth_type = nc_json_str_def(cfg, "auth_type", "none");
    const char *username = nc_json_str_def(cfg, "username", "");
    const char *password = nc_json_str_def(cfg, "password", "");
    const char *dial_num = nc_json_str_def(cfg, "dial_num", "*99#");
    const char *network_type = nc_json_str_def(cfg, "network_type", "auto");
    const char *remark = nc_json_str_def(cfg, "remark", "");
    char uid[64]; snprintf(uid, sizeof(uid), "%s", id);
    if (!uid[0]) { snprintf(uid, sizeof(uid), "apn_%ld", nc_now_s()); }
    if (nc_txn_begin() != 0)
        return -1;
    int rc = 0;
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT OR REPLACE INTO cellular_apn_profile(id,name,apn,auth_type,username,password,dial_num,network_type,remark,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)") != 0) {
        rc = -1;
    } else {
        sqlite3_bind_text(st, 1, uid, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, apn, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, auth_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, username, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 6, password, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, dial_num, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 8, network_type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, remark, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 10, (sqlite3_int64)nc_now_s());
        if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st);
    }
    return nc_txn_end(rc);
}

/* ── Cellular apn_profile_delete ── */
int jmx_cellular_apn_profile_delete(const char *id)
{
    if (jmx_netconfig_db_init() != 0 || !id || !id[0])
        return -1;
    nc_cellular_db_init();
    if (nc_txn_begin() != 0)
        return -1;
    int rc = 0;
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM cellular_apn_profile WHERE id=?") != 0) {
        rc = -1;
    } else { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st); }
    return nc_txn_end(rc);
}

/* ── Cellular sms_delete ── */
int jmx_cellular_sms_delete(const char *id)
{
    if (jmx_netconfig_db_init() != 0 || !id || !id[0])
        return -1;
    nc_cellular_db_init();
    if (nc_txn_begin() != 0)
        return -1;
    int rc = 0;
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM cellular_sms WHERE id=?") != 0) {
        rc = -1;
    } else { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st); }
