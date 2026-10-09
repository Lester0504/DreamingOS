/* ══════════════════════════════════════════════════════════════════════
 * Geo-Block: country list + rules + feeds + events
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_geo_seed_countries(void)
{
    sqlite3 *sig = NULL;
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *src = NULL;
    char path[512];
    enum jmx_system_db_source source;
    char error[64];
    int rc;
    int order = 0;

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, sizeof(path),
                              &source, error, sizeof(error)) != 0 ||
        jmx_signature_db_open_path(path, &sig) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(sig,
        "SELECT iso_code,name_en,name_zh,continent FROM geoip_country "
        "WHERE enabled=1 ORDER BY iso_code", -1, &src, NULL) != SQLITE_OK)
        goto done;
    while ((rc = sqlite3_step(src)) == SQLITE_ROW) {
        const char *code = (const char *)sqlite3_column_text(src, 0);
        const char *name_en = (const char *)sqlite3_column_text(src, 1);
        const char *name_zh = (const char *)sqlite3_column_text(src, 2);
        const char *continent = (const char *)sqlite3_column_text(src, 3);
        if (!code || strlen(code) != 2 || !isupper((unsigned char)code[0]) ||
            !isupper((unsigned char)code[1]))
            continue;
        if (nc_prepare(&st,
            "INSERT INTO firewall_geo_country("
            "id,name,continent,code,enabled,sort_order,name_en,name_zh,official,source,updated_at) "
            "VALUES(?1,?2,?3,?1,0,?4,?2,?5,1,'iso3166-1',?6) "
            "ON CONFLICT(id) DO UPDATE SET "
            "name=excluded.name,continent=excluded.continent,code=excluded.code,"
            "sort_order=excluded.sort_order,name_en=excluded.name_en,name_zh=excluded.name_zh,"
            "official=1,source=excluded.source,updated_at=excluded.updated_at "
            "WHERE firewall_geo_country.name<>excluded.name "
            "OR firewall_geo_country.continent<>excluded.continent "
            "OR firewall_geo_country.code<>excluded.code "
            "OR firewall_geo_country.sort_order<>excluded.sort_order "
            "OR firewall_geo_country.name_en<>excluded.name_en "
            "OR firewall_geo_country.name_zh<>excluded.name_zh "
            "OR firewall_geo_country.official<>1 "
            "OR firewall_geo_country.source<>excluded.source") == 0) {
            sqlite3_bind_text(st, 1, code, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, name_en ? name_en : code, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, continent ? continent : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 4, order++);
            sqlite3_bind_text(st, 5, name_zh ? name_zh : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 6, nc_now_s());
            nc_step_done(st);
            sqlite3_finalize(st);
            st = NULL;
        }
    }
done:
    sqlite3_finalize(src);
    if (sig) jmx_signature_db_close_path(sig);
}

struct nc_geo_prefix_state {
    int mmdb_available;
    int64_t source_bytes;
};

static struct nc_geo_prefix_state nc_geo_prefix_probe(void)
{
    struct nc_geo_prefix_state state = {0, 0};
    struct stat st;

    if (lstat("/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb", &st) == 0 &&
        S_ISREG(st.st_mode) && st.st_size > 0 &&
        access("/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb", R_OK) == 0) {
        state.mmdb_available = 1;
        state.source_bytes = (int64_t)st.st_size;
    }
    return state;
}

static int64_t nc_geo_revision(void)
{
    sqlite3_stmt *st = NULL;
    int64_t revision = 0;
    if (nc_prepare(&st, "SELECT revision FROM firewall_geo_meta WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW)
        revision = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return revision;
}

static void nc_geo_add_capabilities(struct json_object *data,
                                    struct nc_geo_prefix_state prefix,
                                    int catalog_count)
{
    struct json_object *caps = json_object_new_object();
    struct json_object *blockers = json_object_new_array();
    int prefix_ready = prefix.mmdb_available;

    json_object_object_add(caps, "catalog_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "catalog_complete", json_object_new_boolean(catalog_count == 249));
    json_object_object_add(caps, "catalog_count", json_object_new_int(catalog_count));
    json_object_object_add(caps, "strict_validation_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "preview_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "revision_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "confirm_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "prefix_index_supported", json_object_new_boolean(0));
    json_object_object_add(caps, "mmdb_source", json_object_new_boolean(1));
    json_object_object_add(caps, "mmdb_present", json_object_new_boolean(prefix_ready));
    json_object_object_add(caps, "mmdb_validation_deferred", json_object_new_boolean(prefix_ready));
    json_object_object_add(caps, "selected_country_materialization", json_object_new_boolean(1));
    json_object_object_add(caps, "sqlite_prefix_table_required", json_object_new_boolean(0));
    json_object_object_add(caps, "dataplane_supported", json_object_new_boolean(0));
    json_object_object_add(caps, "active_readback_supported", json_object_new_boolean(0));
    json_object_object_add(caps, "hit_counters_supported", json_object_new_boolean(0));
    json_object_object_add(caps, "rollback_supported", json_object_new_boolean(0));
    if (!prefix.mmdb_available)
        json_object_array_add(blockers, json_object_new_string("geoip_country_mmdb_missing"));
    else
        json_object_array_add(blockers, json_object_new_string("geo_dataplane_status_via_aegisxd"));
    json_object_object_add(data, "capabilities", caps);
    json_object_object_add(data, "blockers", blockers);
}

static void nc_plugin_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS plugin_cache ("
        "id TEXT PRIMARY KEY,"
        "title TEXT NOT NULL DEFAULT '',"
        "category TEXT NOT NULL DEFAULT 'services',"
        "luci_path TEXT NOT NULL DEFAULT '',"
        "icon TEXT NOT NULL DEFAULT '',"
        "package TEXT NOT NULL DEFAULT '',"
        "description TEXT NOT NULL DEFAULT '',"
        "installed INTEGER NOT NULL DEFAULT 0,"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "api_mode TEXT NOT NULL DEFAULT 'luci_compat',"
        "risk TEXT NOT NULL DEFAULT 'low',"
        "scanned_at INTEGER NOT NULL DEFAULT 0"
    ")");
}

struct json_object *jmx_geo_block_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *countries = json_object_new_array();
    struct json_object *rules = json_object_new_array();
    struct json_object *feeds = json_object_new_array();
    struct json_object *events = json_object_new_array();
    struct nc_geo_prefix_state prefix = {0, 0};
    sqlite3_stmt *st = NULL;
    int catalog_count = 0;
    int db_ready = jmx_netconfig_db_init() == 0;
    if (!db_ready) goto done;
    nc_firewall_db_init();
    nc_geo_seed_countries();
    prefix = nc_geo_prefix_probe();

    /* Countries */
    if (nc_prepare(&st,
        "SELECT id,name_en,name_zh,continent,code,enabled,official,sort_order "
        "FROM firewall_geo_country WHERE official=1 ORDER BY sort_order,code") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            const char *code = (const char *)sqlite3_column_text(st, 4);
            char flag_url[96];
            snprintf(flag_url, sizeof(flag_url), "/static/images/flags/%c%c.svg",
                     code ? tolower((unsigned char)code[0]) : 'x',
                     code ? tolower((unsigned char)code[1]) : 'x');
            nc_add_text(o, "id", st, 0);
            nc_add_text(o, "name_en", st, 1);
            nc_add_text(o, "name_zh", st, 2);
            nc_add_text(o, "continent", st, 3);
            nc_add_text(o, "code", st, 4);
            {
                const char *name_zh = (const char *)sqlite3_column_text(st, 2);
                const char *name_en = (const char *)sqlite3_column_text(st, 1);
                json_object_object_add(o, "name", json_object_new_string(
                    name_zh && name_zh[0] ? name_zh : name_en ? name_en : code ? code : ""));
            }
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 5)));
            json_object_object_add(o, "official", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "sort_order", json_object_new_int(sqlite3_column_int(st, 7)));
            json_object_object_add(o, "flag_url", json_object_new_string(flag_url));
            json_object_object_add(o, "ipv4_prefixes", json_object_new_null());
            json_object_object_add(o, "ipv6_prefixes", json_object_new_null());
            json_object_object_add(o, "prefix_count", json_object_new_null());
            json_object_object_add(o, "prefix_count_deferred", json_object_new_boolean(1));
            json_object_object_add(o, "dataplane_supported", json_object_new_boolean(0));
            json_object_object_add(o, "configurable", json_object_new_boolean(prefix.mmdb_available));
            json_object_object_add(o, "blocker", json_object_new_string(
                prefix.mmdb_available ? "geo_dataplane_status_via_aegisxd" :
                                        "geoip_country_mmdb_missing"));
            json_object_array_add(countries, o);
            catalog_count++;
        }
        sqlite3_finalize(st); st = NULL;
    }

    /* Rules */
    if (nc_prepare(&st, "SELECT id,name,action,direction,src_zone,dst_zone,enabled FROM firewall_geo_rule ORDER BY id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "name", st, 1); nc_add_text(o, "action", st, 2); nc_add_text(o, "direction", st, 3);
            nc_add_text(o, "src_zone", st, 4); nc_add_text(o, "dst_zone", st, 5);
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_array_add(rules, o);
        }
        sqlite3_finalize(st); st = NULL;
    }

    /* Feeds */
    if (nc_prepare(&st, "SELECT id,name,source_url,local_file,interval_hours,last_update,status,error,enabled FROM firewall_geo_feed ORDER BY id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0); nc_add_text(o, "name", st, 1); nc_add_text(o, "source_url", st, 2); nc_add_text(o, "local_file", st, 3);
            json_object_object_add(o, "interval_hours", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "last_update", json_object_new_int64(sqlite3_column_int64(st, 5)));
            nc_add_text(o, "status", st, 6); nc_add_text(o, "error", st, 7);
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 8)));
            json_object_array_add(feeds, o);
        }
        sqlite3_finalize(st); st = NULL;
    }

    /* Recent events (last 100) */
    if (nc_prepare(&st, "SELECT id,country_id,rule_id,action,src_ip,dst_ip,ts FROM firewall_geo_event ORDER BY ts DESC LIMIT 100") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            nc_add_text(o, "country_id", st, 1); nc_add_text(o, "rule_id", st, 2); nc_add_text(o, "action", st, 3);
            nc_add_text(o, "src_ip", st, 4); nc_add_text(o, "dst_ip", st, 5);
            json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(st, 6)));
            json_object_array_add(events, o);
        }
        sqlite3_finalize(st); st = NULL;
    }

done:
    json_object_object_add(data, "countries", countries);
    json_object_object_add(data, "rules", rules);
    json_object_object_add(data, "feeds", feeds);
    json_object_object_add(data, "events", events);
    json_object_object_add(data, "contract_version", json_object_new_string("geo-block.v2"));
    json_object_object_add(data, "revision", json_object_new_int64(db_ready ? nc_geo_revision() : 0));
    json_object_object_add(data, "catalog_count", json_object_new_int(catalog_count));
    json_object_object_add(data, "prefix_count", json_object_new_null());
    json_object_object_add(data, "prefix_source", json_object_new_string(
        "/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb"));
    json_object_object_add(data, "prefix_source_bytes", json_object_new_int64(prefix.source_bytes));
    json_object_object_add(data, "configuration_saved", json_object_new_boolean(db_ready));
    json_object_object_add(data, "dataplane_active", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string("blocked"));
    json_object_object_add(data, "reason", json_object_new_string(
        !db_ready ? "storage_unavailable" :
        !prefix.mmdb_available ? "geoip_country_mmdb_missing" :
        "geo_dataplane_status_via_aegisxd"));
    nc_geo_add_capabilities(data, prefix, catalog_count);
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(db_ready ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static struct json_object *nc_geo_error(const char *error, int64_t revision)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "valid", json_object_new_boolean(0));
    json_object_object_add(data, "saved", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(error ? error : "geo_block_validation_failed"));
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static int nc_geo_bool_field_strict(struct json_object *obj, const char *key, int def, int *out)
{
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(obj, key, &v)) {
        if (out) *out = def;
        return 1;
    }
    if (!v || !json_object_is_type(v, json_type_boolean)) return 0;
    if (out) *out = json_object_get_boolean(v);
    return 1;
}

static int nc_geo_country_official(const char *code)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (!code || strlen(code) != 2 || !isupper((unsigned char)code[0]) ||
        !isupper((unsigned char)code[1]))
        return 0;
    if (nc_prepare(&st,
        "SELECT 1 FROM firewall_geo_country WHERE id=?1 AND official=1 LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, code, -1, SQLITE_TRANSIENT);
        found = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return found;
}

static int nc_geo_array_duplicate_id(struct json_object *arr, int index, const char *id)
{
    int i;
    for (i = 0; i < index; i++) {
        struct json_object *old = json_object_array_get_idx(arr, i);
        const char *old_id = nc_json_str_def(old, "id", nc_json_str_def(old, "code", ""));
        if (!strcmp(old_id, id)) return 1;
    }
    return 0;
}

static int nc_geo_source_url_ok(const char *url)
{
    const unsigned char *p;
    if (!url || !url[0]) return 1;
    if (strncmp(url, "https://", 8) && strncmp(url, "http://", 7)) return 0;
    for (p = (const unsigned char *)url; *p; p++)
        if (*p < 0x20 || *p == 0x7f) return 0;
    return strlen(url) <= 1024;
}

static int nc_geo_local_file_ok(const char *path)
{
    if (!path || !path[0]) return 1;
    if (strstr(path, "..") || strlen(path) > 512) return 0;
    return !strncmp(path, "/etc/dreamingwrt/geoip/", 23) ||
           !strncmp(path, "/usr/share/dreamingwrt/geoip/", 29);
}

static const char *nc_geo_validate(struct json_object *cfg,
                                   struct nc_geo_prefix_state prefix,
                                   int *country_count, int *rule_count, int *feed_count)
{
    struct json_object *arr = NULL;
    int i, n;

    if (country_count) *country_count = 0;
    if (rule_count) *rule_count = 0;
    if (feed_count) *feed_count = 0;
    if (!cfg || !json_object_is_type(cfg, json_type_object)) return "request_object_required";

    if (json_object_object_get_ex(cfg, "countries", &arr)) {
        if (!arr || !json_object_is_type(arr, json_type_array)) return "countries_array_required";
        n = json_object_array_length(arr);
        if (n > 249) return "too_many_countries";
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id;
            int enabled;
            if (!o || !json_object_is_type(o, json_type_object)) return "country_object_required";
            id = nc_json_str_def(o, "id", nc_json_str_def(o, "code", ""));
            if (!nc_geo_country_official(id)) return "unknown_or_non_official_country";
            if (nc_geo_array_duplicate_id(arr, i, id)) return "duplicate_country";
            if (!nc_geo_bool_field_strict(o, "enabled", 0, &enabled)) return "country_enabled_boolean_required";
            if (enabled) {
                if (!prefix.mmdb_available) return "geoip_country_mmdb_missing";
            }
        }
        if (country_count) *country_count = n;
    }

    if (json_object_object_get_ex(cfg, "rules", &arr)) {
        if (!arr || !json_object_is_type(arr, json_type_array)) return "rules_array_required";
        n = json_object_array_length(arr);
        if (n > 64) return "too_many_geo_rules";
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id, *name, *action, *direction, *src_zone, *dst_zone;
            int enabled;
            if (!o || !json_object_is_type(o, json_type_object)) return "geo_rule_object_required";
            id = nc_json_str_def(o, "id", "");
            name = nc_json_str_def(o, "name", id);
            action = nc_json_str_def(o, "action", "block");
            direction = nc_json_str_def(o, "direction", "both");
            src_zone = nc_json_str_def(o, "src_zone", "wan");
            dst_zone = nc_json_str_def(o, "dst_zone", "");
            if (!nc_safe_id_ok(id) || strlen(id) > 96) return "invalid_geo_rule_id";
            if (!name[0] || strlen(name) > 128) return "invalid_geo_rule_name";
            if (strcmp(action, "block") && strcmp(action, "allow")) return "invalid_geo_rule_action";
            if (strcmp(direction, "both") && strcmp(direction, "inbound") &&
                strcmp(direction, "outbound")) return "invalid_geo_rule_direction";
            if (!nc_safe_id_ok(src_zone) || (dst_zone[0] && !nc_safe_id_ok(dst_zone)))
                return "invalid_geo_rule_zone";
            if (!nc_geo_bool_field_strict(o, "enabled", 1, &enabled)) return "geo_rule_enabled_boolean_required";
            if (nc_geo_array_duplicate_id(arr, i, id)) return "duplicate_geo_rule";
        }
        if (rule_count) *rule_count = n;
    }

    if (json_object_object_get_ex(cfg, "feeds", &arr)) {
        if (!arr || !json_object_is_type(arr, json_type_array)) return "feeds_array_required";
        n = json_object_array_length(arr);
        if (n > 32) return "too_many_geo_feeds";
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id, *name, *url, *local;
            int enabled, interval;
            if (!o || !json_object_is_type(o, json_type_object)) return "geo_feed_object_required";
            id = nc_json_str_def(o, "id", "");
            name = nc_json_str_def(o, "name", id);
            url = nc_json_str_def(o, "source_url", "");
            local = nc_json_str_def(o, "local_file", "");
            interval = nc_json_int_def(o, "interval_hours", 24);
