/* Included by 009_nc_dhcp.c. Reads never promote or repair stored rows. */
static struct json_object *nc_dhcp_base_get(const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *out = NULL, *dns = NULL;
    const char *columns[] = {"id", "lan_id", "tagname", "pool_start", "pool_end",
        "exclude_pool", "gateway", "netmask", "dns1", "dns2", "domain"};
    if (nc_prepare(&st,
        "SELECT COALESCE(ds.id,l.id),l.id,COALESCE(ds.tagname,ld.tagname,''),"
        "COALESCE(ds.pool_start,ld.pool_start,'100'),COALESCE(ds.pool_end,ld.pool_end,'249'),"
        "COALESCE(ds.exclude_pool,ld.exclude_pool_json,'[]'),COALESCE(ds.gateway,ld.gateway,''),"
        "COALESCE(ds.netmask,''),COALESCE(ds.dns1,''),COALESCE(ds.dns2,''),COALESCE(ds.domain,''),"
        "COALESCE(ds.enabled,ld.enabled,0),COALESCE(ds.lease_minutes,ld.lease_minutes,120),"
        "ds.id IS NOT NULL,COALESCE(ld.dns_json,'[]') FROM lan l "
        "LEFT JOIN dhcp_scope ds ON ds.lan_id=l.id LEFT JOIN lan_dhcp ld ON ld.lan_id=l.id "
        "WHERE l.id=?1") != 0) return NULL;
    sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        out = json_object_new_object();
        for (size_t i = 0; i < sizeof(columns) / sizeof(columns[0]); i++)
            json_object_object_add(out, columns[i], json_object_new_string(
                (const char *)sqlite3_column_text(st, (int)i)));
        json_object_object_add(out, "enabled", json_object_new_boolean(sqlite3_column_int(st, 11)));
        json_object_object_add(out, "lease_minutes", json_object_new_int(sqlite3_column_int(st, 12)));
        dns = json_object_new_array();
        if (sqlite3_column_int(st, 13)) {
            for (int i = 8; i <= 9; i++) {
                const char *ip = (const char *)sqlite3_column_text(st, i);
                if (ip && ip[0]) json_object_array_add(dns, json_object_new_string(ip));
            }
        } else {
            struct json_object *legacy = nc_dhcp_text_array((const char *)sqlite3_column_text(st, 14));
            for (size_t i = 0; i < json_object_array_length(legacy); i++) {
                const char *ip = json_object_get_string(json_object_array_get_idx(legacy, i));
                if (ip && !strncmp(ip, "6,", 2)) {
                    char buffer[512], *save = NULL, *part;
                    snprintf(buffer, sizeof(buffer), "%s", ip + 2);
                    for (part = strtok_r(buffer, ",", &save); part; part = strtok_r(NULL, ",", &save))
                        json_object_array_add(dns, json_object_new_string(part));
                } else if (ip && ip[0]) json_object_array_add(dns, json_object_new_string(ip));
            }
            json_object_put(legacy);
            for (size_t i = 0; i < 2; i++)
                json_object_object_add(out, i ? "dns2" : "dns1", json_object_new_string(
                    i < json_object_array_length(dns) ? json_object_get_string(json_object_array_get_idx(dns, i)) : ""));
        }
        json_object_object_add(out, "dns", dns);
    }
    sqlite3_finalize(st);
    return out;
}

static int nc_dhcp_base_validate(struct json_object *cfg, char *err, size_t size)
{
    const char *lan_id = nc_json_str_def(cfg, "lan_id", "");
    const char *start = nc_json_str_def(cfg, "pool_start", "");
    const char *end = nc_json_str_def(cfg, "pool_end", "");
    const char *fields[] = {"gateway", "dns1", "dns2"};
    struct json_object *dns = NULL;
    int lease = nc_json_int_def(cfg, "lease_minutes", 120);
    if (nc_dhcp_validate_scope(lan_id, start, end, NULL, err, size) != 0) return -1;
    if (lease < 1 || lease > 5256000) { snprintf(err, size, "invalid_lease_minutes"); return -1; }
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const char *ip = nc_json_str_def(cfg, fields[i], "");
        if (ip[0] && !nc_ipv4_ok(ip)) { snprintf(err, size, "invalid_%s", fields[i]); return -1; }
    }
    if (json_object_object_get_ex(cfg, "dns", &dns) && json_object_array_length(dns) > 2) {
        snprintf(err, size, "legacy_dns_count_not_supported"); return -1;
    }
    return 0;
}

static int nc_dhcp_project_lan(const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *base = nc_dhcp_base_get(lan_id), *exclude;
    int rc = -1;
    if (!base) return -1;
    exclude = nc_dhcp_text_array(nc_json_str_def(base, "exclude_pool", ""));
    if (nc_prepare(&st,
        "INSERT INTO lan_dhcp(lan_id,enabled,tagname,pool_start,pool_end,exclude_pool_json,gateway,dns_json,lease_minutes) "
        "SELECT lan_id,enabled,tagname,pool_start,pool_end,?2,gateway,"
        "CASE WHEN dns1<>'' AND dns2<>'' THEN json_array(dns1,dns2) "
        "WHEN dns1<>'' THEN json_array(dns1) WHEN dns2<>'' THEN json_array(dns2) ELSE '[]' END,lease_minutes "
        "FROM dhcp_scope WHERE lan_id=?1 ON CONFLICT(lan_id) DO UPDATE SET "
        "enabled=excluded.enabled,tagname=excluded.tagname,pool_start=excluded.pool_start,"
        "pool_end=excluded.pool_end,exclude_pool_json=excluded.exclude_pool_json,gateway=excluded.gateway,"
        "dns_json=excluded.dns_json,lease_minutes=excluded.lease_minutes") != 0) goto done;
    sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, json_object_to_json_string_ext(exclude, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    sqlite3_finalize(st);
done:
    json_object_put(exclude);
    json_object_put(base);
    return rc;
}

static int nc_dhcp_base_set(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    char err[128];
    const char *lan_id = nc_json_str_def(cfg, "lan_id", "");
    const char *id = nc_json_str_def(cfg, "id", lan_id);
    const char *fields[] = {"tagname", "pool_start", "pool_end", "exclude_pool",
        "gateway", "netmask", "dns1", "dns2", "domain"};
    int own = sqlite3_get_autocommit(g_netconfig_db), rc = -1;
    if (!nc_valid_name(id) || nc_dhcp_scope_conflicts(id, lan_id) != 0 ||
        nc_dhcp_base_validate(cfg, err, sizeof(err)) != 0) return -1;
    if (own && nc_exec("BEGIN IMMEDIATE") != 0) return -1;
    if (nc_prepare(&st,
        "INSERT INTO dhcp_scope(id,lan_id,enabled,lease_minutes,updated_at,tagname,pool_start,pool_end,"
        "exclude_pool,gateway,netmask,dns1,dns2,domain) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) "
        "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,lease_minutes=excluded.lease_minutes,"
        "updated_at=excluded.updated_at,tagname=excluded.tagname,pool_start=excluded.pool_start,"
        "pool_end=excluded.pool_end,exclude_pool=excluded.exclude_pool,gateway=excluded.gateway,"
        "netmask=excluded.netmask,dns1=excluded.dns1,dns2=excluded.dns2,domain=excluded.domain") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, nc_json_bool_def(cfg, "enabled", 0));
        sqlite3_bind_int(st, 4, nc_json_int_def(cfg, "lease_minutes", 120));
        sqlite3_bind_int64(st, 5, nc_now_s());
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
            sqlite3_bind_text(st, (int)i + 6, nc_json_str_def(cfg, fields[i], ""), -1, SQLITE_TRANSIENT);
        rc = nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (!rc) rc = nc_dhcp_project_lan(lan_id);
    if (own) {
        if (!rc && nc_exec("COMMIT") != 0) rc = -1;
        if (rc) nc_exec("ROLLBACK");
    }
    return rc;
}

static struct json_object *nc_dhcp_legacy_merge(const char *lan_id, struct json_object *patch)
{
    struct json_object *cfg = nc_dhcp_base_get(lan_id), *value = NULL;
    if (!cfg || !json_object_is_type(patch, json_type_object)) goto fail;
    const char *fields[] = {"id", "enabled", "tagname", "pool_start", "pool_end", "gateway", "dns1",
        "dns2", "lease_minutes", "netmask", "domain"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (json_object_object_get_ex(patch, fields[i], &value))
            json_object_object_add(cfg, fields[i], json_object_get(value));
    if (json_object_object_get_ex(patch, "pool", &value)) {
        char start[64], end[64];
        nc_split_pool(json_object_get_string(value), start, sizeof(start), end, sizeof(end));
        json_object_object_add(cfg, "pool_start", json_object_new_string(start));
        json_object_object_add(cfg, "pool_end", json_object_new_string(end));
    }
    if (json_object_object_get_ex(patch, "lease", &value))
        json_object_object_add(cfg, "lease_minutes", json_object_get(value));
    if (json_object_object_get_ex(patch, "exclude_pool", &value)) {
        char normalized[1024];
        nc_dhcp_normalize_exclude_pool(json_object_get_string(value), normalized, sizeof(normalized));
        json_object_object_add(cfg, "exclude_pool", json_object_new_string(normalized));
    }
    if (json_object_object_get_ex(patch, "dns", &value) || json_object_object_get_ex(patch, "dns_json", &value)) {
        struct json_object *raw = json_object_is_type(value, json_type_array) ?
            json_object_get(value) : nc_dhcp_text_array(json_object_get_string(value));
        struct json_object *dns = json_object_new_array();
        for (size_t i = 0; i < json_object_array_length(raw); i++) {
            const char *ip = json_object_get_string(json_object_array_get_idx(raw, i));
            if (ip && !strncmp(ip, "6,", 2)) {
                char buffer[512], *save = NULL, *part;
                snprintf(buffer, sizeof(buffer), "%s", ip + 2);
                for (part = strtok_r(buffer, ",", &save); part; part = strtok_r(NULL, ",", &save))
                    json_object_array_add(dns, json_object_new_string(part));
            } else if (ip && ip[0]) json_object_array_add(dns, json_object_new_string(ip));
        }
        json_object_put(raw);
        json_object_object_add(cfg, "dns", dns);
        if (json_object_array_length(dns) > 2) goto fail;
        for (size_t i = 0; i < 2; i++)
            json_object_object_add(cfg, i ? "dns2" : "dns1", json_object_new_string(
                i < json_object_array_length(dns) ? json_object_get_string(json_object_array_get_idx(dns, i)) : ""));
    }
    return cfg;
fail:
    if (cfg) json_object_put(cfg);
    return NULL;
}

static int nc_dhcp_legacy_set(const char *lan_id, struct json_object *patch)
{
    struct json_object *cfg = nc_dhcp_legacy_merge(lan_id, patch);
    if (!cfg) return -1;
    int rc = nc_dhcp_base_set(cfg);
    json_object_put(cfg);
    return rc;
}
