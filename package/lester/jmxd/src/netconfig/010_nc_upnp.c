/* ══════════════════════════════════════════════════════════════════════
 * UPnP IGD / miniupnpd: SQLite product config + UCI apply
 * ══════════════════════════════════════════════════════════════════════ */

int nc_file_exists(const char *path) { return path && access(path, F_OK) == 0; }
static int nc_port_range_ok(int start, int end) { return start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end; }

int nc_cidr_ok(const char *cidr)
{
    char ip[64];
    const char *slash;
    int prefix;
    struct in_addr a;
    if (!cidr || !cidr[0]) return 0;
    slash = strchr(cidr, '/');
    if (!slash) return inet_pton(AF_INET, cidr, &a) == 1;
    if ((size_t)(slash - cidr) >= sizeof(ip)) return 0;
    memcpy(ip, cidr, slash - cidr); ip[slash - cidr] = '\0';
    prefix = atoi(slash + 1);
    return inet_pton(AF_INET, ip, &a) == 1 && prefix >= 0 && prefix <= 32;
}

/* A generated config is the evidence that the installed init script consumes
 * these settings. Keep capabilities false after a failed transaction, even
 * when restoring its previous snapshot succeeds. */
static int g_nc_upnp_readback_failed;
static int nc_upnp_parse_acl_port_range(const char *range, int *start, int *end);

/* Keep the original row ID/order: this is an existing default permission,
 * not a new rule that may bypass a user's earlier deny. */
static int nc_upnp_managed_acl_id(char *id, size_t size)
{
    sqlite3_stmt *st = NULL;
    int rc;
    if (id && size) id[0] = '\0';
    if (nc_prepare(&st, "SELECT id FROM upnp_acl WHERE managed='port_range'") != 0) return -1;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (id && size) snprintf(id, size, "%s", (const char *)sqlite3_column_text(st, 0));
        rc = sqlite3_step(st) == SQLITE_DONE ? 1 : -1;
    } else rc = rc == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

static int nc_upnp_acl_config_matches(const char *path)
{
    sqlite3_stmt *st = NULL;
    FILE *fp = fopen(path, "r");
    char line[1024];
    int rc = -1;
    if (!fp) return -1;
    if (nc_prepare(&st, "SELECT action,external_ports,internal_cidr,internal_ports "
                        "FROM upnp_acl WHERE enabled=1 ORDER BY sort_order,id") != 0) goto done;
    while (fgets(line, sizeof(line), fp)) {
        char action[16], external[64], internal[96], ports[64], extra[2], expected[96];
        char *text = line, *comment;
        int es, ee, is, ie, des, dee, dis, die;
        while (isspace((unsigned char)*text)) text++;
        if (strncmp(text, "allow", 5) && strncmp(text, "deny", 4)) continue;
        comment = strchr(text, '#'); if (comment) *comment = '\0';
        if (sscanf(text, "%15s %63s %95s %63s %1s", action, external, internal, ports, extra) != 4 ||
            sqlite3_step(st) != SQLITE_ROW) goto done;
        const char *cidr = (const char *)sqlite3_column_text(st, 2);
        snprintf(expected, sizeof(expected), strchr(cidr, '/') ? "%s" : "%s/32", cidr);
        if (strcmp(action, (const char *)sqlite3_column_text(st, 0)) || strcmp(internal, expected) ||
            !nc_upnp_parse_acl_port_range(external, &es, &ee) ||
            !nc_upnp_parse_acl_port_range(ports, &is, &ie) ||
            !nc_upnp_parse_acl_port_range((const char *)sqlite3_column_text(st, 1), &des, &dee) ||
            !nc_upnp_parse_acl_port_range((const char *)sqlite3_column_text(st, 3), &dis, &die) ||
            es != des || ee != dee || is != dis || ie != die) goto done;
    }
    if (!ferror(fp) && sqlite3_step(st) == SQLITE_DONE) rc = 0;
done:
    if (st) sqlite3_finalize(st);
    fclose(fp);
    return rc;
}

static int nc_upnp_acl_uci_matches(struct uci_context *ctx, struct uci_package *pkg)
{
    sqlite3_stmt *st = NULL;
    struct uci_element *e;
    const char *keys[] = {"action", "ext_ports", "int_addr", "int_ports"};
    int rc = -1;
    if (nc_prepare(&st, "SELECT action,external_ports,internal_cidr,internal_ports "
                        "FROM upnp_acl WHERE enabled=1 ORDER BY sort_order,id") != 0) return -1;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *section = uci_to_section(e);
        if (strcmp(section->type, "perm_rule")) continue;
        if (sqlite3_step(st) != SQLITE_ROW) goto done;
        for (int i = 0; i < 4; i++)
            if (strcmp(nc_uci_str(ctx, section, keys[i], ""), (const char *)sqlite3_column_text(st, i))) goto done;
    }
    if (sqlite3_step(st) == SQLITE_DONE) rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static int nc_upnp_config_matches(const char *path, int use_stun,
                                  const char *stun_host, int stun_port,
                                  int pcp, int clean_interval)
{
    FILE *fp = fopen(path, "r");
    char line[1024], port[24], clean[24];
    int seen = 0, required = use_stun ? 31 : 25;
    if (!fp) return -1;
    snprintf(port, sizeof(port), "%d", stun_port);
    snprintf(clean, sizeof(clean), "%d", clean_interval);
    while (fgets(line, sizeof(line), fp)) {
        char *key = line, *eq, *end;
        const char *expected = NULL;
        int bit = 0;
        while (*key && isspace((unsigned char)*key)) key++;
        if (!*key || *key == '#') continue;
        eq = strchr(key, '=');
        if (!eq) continue;
        *eq++ = '\0';
        end = key + strlen(key);
        while (end > key && isspace((unsigned char)end[-1])) *--end = '\0';
        while (*eq && isspace((unsigned char)*eq)) eq++;
        end = eq + strlen(eq);
        while (end > eq && isspace((unsigned char)end[-1])) *--end = '\0';
        if (!strcmp(key, "ext_perform_stun")) { bit = 1; expected = use_stun ? "yes" : "no"; }
        else if (use_stun && !strcmp(key, "ext_stun_host")) { bit = 2; expected = stun_host; }
        else if (use_stun && !strcmp(key, "ext_stun_port")) { bit = 4; expected = port; }
        else if (!strcmp(key, "enable_pcp_pmp")) { bit = 8; expected = pcp ? "yes" : "no"; }
        else if (!strcmp(key, "clean_ruleset_interval")) { bit = 16; expected = clean; }
        if (bit) {
            /* Duplicate keys can be interpreted differently by consumers. */
            if ((seen & bit) || strcmp(eq, expected)) { fclose(fp); return -1; }
            seen |= bit;
        }
    }
    int failed = ferror(fp);
    fclose(fp);
    return !failed && seen == required ? 0 : -1;
}

/* 0: generated config verified; 1: disabled, no generated runtime; -1: mismatch. */
static int nc_upnp_runtime_readback(void)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    const char *path = "/var/etc/miniupnpd.conf";
    int rc = -1;
    if (nc_prepare(&st, "SELECT enabled,use_stun,stun_host,stun_port,pcp,clean_interval "
                        "FROM upnp_service WHERE id=1") != 0) return -1;
    if (sqlite3_step(st) != SQLITE_ROW) goto done;
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "upnpd", &pkg) != UCI_OK || !pkg) goto done;
    if (nc_upnp_acl_uci_matches(ctx, pkg) != 0) goto done;
    if (!sqlite3_column_int(st, 0)) { rc = 1; goto done; }
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *section = uci_to_section(e);
        if (!strcmp(section->e.name, "config")) {
            const char *custom = nc_uci_str(ctx, section, "config_file", "");
            if (custom[0]) path = custom;
            break;
        }
    }
    rc = nc_upnp_config_matches(path, sqlite3_column_int(st, 1),
        (const char *)sqlite3_column_text(st, 2), sqlite3_column_int(st, 3),
        sqlite3_column_int(st, 4), sqlite3_column_int(st, 5));
    if (rc == 0) rc = nc_upnp_acl_config_matches(path);
 done:
    sqlite3_finalize(st);
    if (ctx) uci_free_context(ctx);
    return rc;
}

static int nc_upnp_runtime_capable(void)
{
    return !g_nc_upnp_readback_failed && nc_upnp_runtime_readback() == 0;
}

static void nc_upnp_add_caps(struct json_object *root)
{
    struct json_object *caps = json_object_new_object();
    int has = nc_file_exists("/etc/init.d/miniupnpd") || nc_file_exists("/usr/sbin/miniupnpd") || nc_file_exists("/etc/config/upnpd");
    /* Static mappings live in our own nft table, so they depend on nft being
     * usable - NOT on miniupnpd, and NOT on the still-preview firewall path. */
    int nft_ok = nc_upnp_nft_available();
    int runtime_ok = has && nc_upnp_runtime_capable();
    int managed = nc_upnp_managed_acl_id(NULL, 0) == 1;
    /* A stopped service may be configured before its first start. Enabled
     * saves still require generated-config proof, and failure stays latched. */
    int range_ok = has && managed && !g_nc_upnp_readback_failed &&
                   nc_upnp_runtime_readback() >= 0;
    json_object_object_add(caps, "miniupnpd", json_object_new_boolean(has));
    json_object_object_add(caps, "natpmp", json_object_new_boolean(has));
    json_object_object_add(caps, "pcp", json_object_new_boolean(runtime_ok));
    json_object_object_add(caps, "stun", json_object_new_boolean(runtime_ok));
    json_object_object_add(caps, "service_update", json_object_new_boolean(has));
    json_object_object_add(caps, "acl_create", json_object_new_boolean(has));
    json_object_object_add(caps, "acl_update", json_object_new_boolean(has));
    json_object_object_add(caps, "acl_delete", json_object_new_boolean(has));
    json_object_object_add(caps, "dynamic_mapping_read", json_object_new_boolean(1));
    json_object_object_add(caps, "static_mapping_read", json_object_new_boolean(1));
    json_object_object_add(caps, "mapping_delete", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "live_packets", json_object_new_boolean(0));
    json_object_object_add(caps, "acl", json_object_new_boolean(1));
    json_object_object_add(caps, "mapping_create", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "mapping_update", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "save_upnp_mapping", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "delete_upnp_mapping", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "static_mapping_apply", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "static_mapping_readback", json_object_new_boolean(nft_ok));
    json_object_object_add(caps, "static_mapping_dataplane",
                           json_object_new_string(nft_ok ? "nft:inet " NC_UPNP_NFT_TABLE
                                                         : "unavailable"));
    if (!nft_ok)
        json_object_object_add(caps, "static_mapping_reason",
                               json_object_new_string("nft_unavailable"));
    /* IPv6 static mappings need a family column and filter (not DNAT)
     * semantics - separate contract, deliberately still false. */
    json_object_object_add(caps, "static_mapping_ipv6", json_object_new_boolean(0));
    json_object_object_add(caps, "stun_host", json_object_new_boolean(runtime_ok));
    json_object_object_add(caps, "stun_port", json_object_new_boolean(runtime_ok));
    json_object_object_add(caps, "port_range", json_object_new_boolean(range_ok));
    json_object_object_add(caps, "port_range_runtime_verified", json_object_new_boolean(managed && runtime_ok));
    if (!range_ok) {
        json_object_object_add(caps, "port_range_reason", json_object_new_string(
            !managed ? "upnp_port_range_no_managed_default" :
            g_nc_upnp_readback_failed ? "upnp_runtime_readback_mismatch" :
                                      "upnp_runtime_readback_pending"));
        if (managed) json_object_object_add(caps, "port_range_recovery", json_object_new_string("save_service"));
    }
    json_object_object_add(caps, "clean_interval", json_object_new_boolean(runtime_ok));
    json_object_object_add(caps, "lease_file", json_object_new_boolean(0));
    json_object_object_add(caps, "uuid", json_object_new_boolean(0));
    json_object_object_add(caps, "model_name", json_object_new_boolean(0));
    if (!runtime_ok)
        json_object_object_add(caps, "runtime_reason", json_object_new_string(
            g_nc_upnp_readback_failed ? "upnp_runtime_readback_mismatch" :
                                       "upnp_runtime_readback_pending"));
    json_object_object_add(caps, "service_fail_closed", json_object_new_boolean(1));
    json_object_object_add(caps, "service_field_results", json_object_new_boolean(1));
    json_object_object_add(root, "capabilities", caps);
}
static int nc_upnp_parse_port_range(const char *range, int *start, int *end)
{
    return nc_upnp_parse_acl_port_range(range, start, end) && nc_port_range_ok(*start, *end);
}

static int nc_upnp_parse_acl_port_range(const char *range, int *start, int *end)
{
    unsigned values[2] = {0, 0};
    int part = 0, digits = 0;
    if (!range || !*range) return 0;
    for (const unsigned char *p = (const unsigned char *)range; *p; p++) {
        if ((*p == '-' || *p == ':') && !part && digits) { part = 1; digits = 0; continue; }
        if (!isdigit(*p)) return 0;
        values[part] = values[part] * 10 + (*p - '0');
        if (values[part] > 65535) return 0;
        digits++;
    }
    if (!digits) return 0;
    *start = (int)values[0]; *end = (int)values[part];
    return *start <= *end;
}

/* Only adopt the shipped permission shape, once. Never synthesize an allow
 * into a custom policy, and never move it across any preceding deny. */
static int nc_upnp_manage_default_acl(void)
{
    sqlite3_stmt *st = NULL;
    char id[96] = "";
    int rc = -1;
    const char *shape = "action='allow' AND enabled=1 AND managed='' "
                        "AND external_ports IN ('1024-65535','1024:65535') "
                        "AND internal_cidr='0.0.0.0/0' "
                        "AND internal_ports IN ('1024-65535','1024:65535')";
    char sql[768];
    if (nc_prepare(&st, "SELECT 1 FROM upnp_migration_state WHERE key='default_allow_v1'") != 0) return -1;
    int marked = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st); st = NULL;
    if (marked) return 0;
    if (nc_exec("BEGIN IMMEDIATE") != 0) return -1;
    snprintf(sql, sizeof(sql), "SELECT id FROM upnp_acl WHERE %s ORDER BY sort_order,id LIMIT 1", shape);
    if (nc_prepare(&st, sql) != 0) goto done;
    if (sqlite3_step(st) == SQLITE_ROW) snprintf(id, sizeof(id), "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st); st = NULL;
    if (id[0]) {
        snprintf(sql, sizeof(sql), "DELETE FROM upnp_acl WHERE %s AND id<>?1", shape);
        if (nc_prepare(&st, sql) != 0) goto done;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto done;
        sqlite3_finalize(st); st = NULL;
        if (nc_prepare(&st, "UPDATE upnp_acl SET managed='port_range',external_ports='1024-65535' WHERE id=?1") != 0) goto done;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto done;
        sqlite3_finalize(st); st = NULL;
        /* Legacy service range was never applied; adopt the actual ACL value. */
        if (nc_exec("UPDATE upnp_service SET port_start=1024,port_end=65535 WHERE id=1") != 0) goto done;
    }
    if (nc_prepare(&st, "INSERT INTO upnp_migration_state(key,value,updated_at) VALUES('default_allow_v1',?1,?2)") != 0) goto done;
    sqlite3_bind_text(st, 1, id[0] ? id : "custom_acl_unchanged", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0) goto done;
    sqlite3_finalize(st); st = NULL;
    rc = nc_exec("COMMIT");
done:
    if (st) sqlite3_finalize(st);
    if (rc != 0) nc_exec("ROLLBACK");
    return rc;
}

static int nc_upnp_import_uci_once(void)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *config = NULL;
    struct uci_element *e;
    int marked = 0, default_state = 0, rc = -1, acl_order = 0;

    if (nc_prepare(&st, "SELECT 1 FROM upnp_migration_state WHERE key='uci_import_v1'") == 0) {
        marked = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st); st = NULL;
    }
    if (marked) return nc_upnp_manage_default_acl();
    if (nc_prepare(&st, "SELECT CASE WHEN enabled=0 AND external_iface='' "
                        "AND (SELECT COUNT(*) FROM upnp_internal_iface)=0 "
                        "AND (SELECT COUNT(*) FROM upnp_acl)=0 THEN 1 ELSE 0 END "
                        "FROM upnp_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) default_state = sqlite3_column_int(st, 0);
        sqlite3_finalize(st); st = NULL;
    }
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "upnpd", &pkg) != UCI_OK || !pkg) goto done;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (s && s->e.name && !strcmp(s->e.name, "config")) { config = s; break; }
    }
    if (!config) goto done;
    if (nc_exec("BEGIN IMMEDIATE") != 0) goto done;
    if (default_state) {
        int enabled = nc_uci_int(ctx, config, "enabled", 1);
        int natpmp = nc_uci_int(ctx, config, "enable_natpmp", 1);
        int secure = nc_uci_int(ctx, config, "secure_mode", 1);
        int down = nc_uci_int(ctx, config, "download", 0) / 128;
        int up = nc_uci_int(ctx, config, "upload", 0) / 128;
        int notify = nc_uci_int(ctx, config, "notify_interval", 30);
        int log_output = nc_uci_int(ctx, config, "log_output", 0);
        int uptime = nc_uci_int(ctx, config, "system_uptime", 1);
        const char *external = nc_uci_str(ctx, config, "external_iface", "");
        const char *presentation = nc_uci_str(ctx, config, "presentation_url", "");
        const char *lease_file = nc_uci_str(ctx, config, "upnp_lease_file", "/var/run/miniupnpd.leases");
        const char *uuid = nc_uci_str(ctx, config, "uuid", "8f8d9b36-dwrt-upnp");
        const char *model = nc_uci_str(ctx, config, "model_number", "DreamingWrt Gateway");
        int use_stun = nc_uci_int(ctx, config, "use_stun", 0);
        const char *stun_host = nc_uci_str(ctx, config, "stun_host", "");
        int stun_port = nc_uci_int(ctx, config, "stun_port", 3478);
        int pcp = nc_uci_int(ctx, config, "enable_pcp_pmp", 0);
        int clean_interval = nc_uci_int(ctx, config, "clean_ruleset_interval", 0);
        if (nc_prepare(&st, "UPDATE upnp_service SET enabled=?1,natpmp_enabled=?2,"
                            "secure_mode=?3,external_iface=?4,presentation_url=?5,"
                            "download_mbps=?6,upload_mbps=?7,lease_file=?8,uuid=?9,"
                            "model_name=?10,notify_interval=?11,log_packets=?12,"
                            "system_uptime=?13,use_stun=?15,stun_host=?16,pcp=?17,updated_at=?18,stun_port=?19,clean_interval=?20 "
                            "WHERE id=1") != 0) goto rollback;
        sqlite3_bind_int(st, 1, enabled); sqlite3_bind_int(st, 2, natpmp);
        sqlite3_bind_int(st, 3, secure); sqlite3_bind_text(st, 4, external, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, presentation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, down); sqlite3_bind_int(st, 7, up);
        sqlite3_bind_text(st, 8, lease_file, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, uuid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, model, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 11, notify); sqlite3_bind_int(st, 12, log_output);
        sqlite3_bind_int(st, 13, uptime);
        sqlite3_bind_int(st, 15, use_stun); sqlite3_bind_text(st, 16, stun_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 17, pcp); sqlite3_bind_int64(st, 18, nc_now_s());
        sqlite3_bind_int(st, 19, stun_port); sqlite3_bind_int(st, 20, clean_interval);
        if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
        sqlite3_finalize(st); st = NULL;
        {
            struct uci_option *o = uci_lookup_option(ctx, config, "internal_iface");
            if (o && o->type == UCI_TYPE_LIST) {
                struct uci_element *ie;
                uci_foreach_element(&o->v.list, ie) {
                    if (nc_prepare(&st, "INSERT OR IGNORE INTO upnp_internal_iface(service_id,lan_id) VALUES(1,?1)") != 0) goto rollback;
                    sqlite3_bind_text(st, 1, ie->name, -1, SQLITE_TRANSIENT);
                    if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
                    sqlite3_finalize(st); st = NULL;
                }
            } else {
                const char *iface = nc_uci_str(ctx, config, "internal_iface", "lan");
                char tmp[256], *save = NULL, *tok;
                snprintf(tmp, sizeof(tmp), "%s", iface);
                for (tok = strtok_r(tmp, " \t,", &save); tok; tok = strtok_r(NULL, " \t,", &save)) {
                    if (nc_prepare(&st, "INSERT OR IGNORE INTO upnp_internal_iface(service_id,lan_id) VALUES(1,?1)") != 0) goto rollback;
                    sqlite3_bind_text(st, 1, tok, -1, SQLITE_TRANSIENT);
                    if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
                    sqlite3_finalize(st); st = NULL;
                }
            }
        }
        uci_foreach_element(&pkg->sections, e) {
            struct uci_section *s = uci_to_section(e);
            char id[64];
            if (!s || strcmp(s->type, "perm_rule")) continue;
            snprintf(id, sizeof(id), "migrated_%d", acl_order);
            if (nc_prepare(&st, "INSERT INTO upnp_acl(id,action,external_ports,internal_cidr,"
                                "internal_ports,remark,enabled,sort_order) VALUES(?1,?2,?3,?4,?5,?6,1,?7)") != 0) goto rollback;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_uci_str(ctx, s, "action", "deny"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, nc_uci_str(ctx, s, "ext_ports", "0-65535"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_uci_str(ctx, s, "int_addr", "0.0.0.0/0"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, nc_uci_str(ctx, s, "int_ports", "0-65535"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, nc_uci_str(ctx, s, "comment", "Migrated UCI ACL"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 7, acl_order++);
            if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
            sqlite3_finalize(st); st = NULL;
        }
    }
    if (nc_prepare(&st, "INSERT OR REPLACE INTO upnp_migration_state(key,value,updated_at) "
                        "VALUES('uci_import_v1',?1,?2)") != 0) goto rollback;
    sqlite3_bind_text(st, 1, default_state ? "imported" : "skipped_nondefault", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
    sqlite3_finalize(st); st = NULL;
    if (nc_exec("COMMIT") != 0) goto done;
    rc = nc_upnp_manage_default_acl();
    goto done;
rollback:
    if (st) { sqlite3_finalize(st); st = NULL; }
    nc_exec("ROLLBACK");
done:
    if (st) sqlite3_finalize(st);
    if (ctx) uci_free_context(ctx);
    return rc;
}
static int nc_upnp_parse_lease_line(const char *line, char *proto, size_t proto_len,
                                    int *eport, char *int_ip, size_t ip_len,
                                    int *iport, char *desc, size_t desc_len,
                                    int *lease)
{
    char a[128] = "", b[128] = "", c[128] = "", d[128] = "", e[192] = "", f[64] = "";
    int n;
    if (!line) return 0;
    if (proto && proto_len) proto[0] = '\0'; if (int_ip && ip_len) int_ip[0] = '\0'; if (desc && desc_len) desc[0] = '\0';
    if (eport) *eport = 0; if (iport) *iport = 0; if (lease) *lease = 0;

    /* Format A: TCP 12345 192.168.1.2 54321 desc 3600 */
    n = sscanf(line, "%127s %127s %127s %127s %191s %63s", a, b, c, d, e, f);
    if (n >= 4 && (!strcasecmp(a,"TCP") || !strcasecmp(a,"UDP")) && nc_ipv4_ok(c)) {
        snprintf(proto, proto_len, "%s", a); *eport = atoi(b); snprintf(int_ip, ip_len, "%s", c); *iport = atoi(d); if (n >= 5) snprintf(desc, desc_len, "%s", e); if (n >= 6) *lease = atoi(f); return 1;
    }
    /* Format B: epoch proto eport ip iport desc */
    if (n >= 5 && (!strcasecmp(b,"TCP") || !strcasecmp(b,"UDP")) && nc_ipv4_ok(d)) {
        snprintf(proto, proto_len, "%s", b); *eport = atoi(c); snprintf(int_ip, ip_len, "%s", d); *iport = atoi(e); if (n >= 6) snprintf(desc, desc_len, "%s", f); *lease = atoi(a); return 1;
    }
    /* Format C: proto:eport:ip:iport:desc:lease */
    {
        char tmp[768], *save = NULL, *tok[8]; int i = 0;
        snprintf(tmp, sizeof(tmp), "%s", line);
        for (tok[i] = strtok_r(tmp, ":, \t\r\n", &save); tok[i] && i < 7; tok[++i] = strtok_r(NULL, ":, \t\r\n", &save));
        if (i >= 4 && tok[0] && (!strcasecmp(tok[0],"TCP") || !strcasecmp(tok[0],"UDP")) && nc_ipv4_ok(tok[2])) {
            snprintf(proto, proto_len, "%s", tok[0]); *eport = atoi(tok[1]); snprintf(int_ip, ip_len, "%s", tok[2]); *iport = atoi(tok[3]); if (i >= 5) snprintf(desc, desc_len, "%s", tok[4]); if (i >= 6) *lease = atoi(tok[5]); return 1;
        }
    }
    return 0;
}

static void nc_upnp_refresh_mappings(void)
{
    sqlite3_stmt *st = NULL;
    FILE *fp = NULL;
    char lease_file[256] = "/var/run/miniupnpd.leases";
    char line[768];
    int64_t now = nc_now_s();
    if (nc_prepare(&st, "SELECT lease_file FROM upnp_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st,0)) snprintf(lease_file, sizeof(lease_file), "%s", (const char *)sqlite3_column_text(st,0));
        sqlite3_finalize(st); st = NULL;
    }
    fp = fopen(lease_file, "r");
    if (!fp) fp = fopen("/var/run/miniupnpd.leases", "r");
    if (!fp) fp = fopen("/tmp/miniupnpd.leases", "r");
    if (!fp) return;
    /* Same as the DHCP lease refresh: without the transaction the DELETE would
     * commit on its own and briefly empty the cache. */
    if (nc_txn_begin() != 0) { fclose(fp); return; }
    if (nc_exec("DELETE FROM upnp_mapping_cache") != 0) {
        nc_txn_end(-1);
        fclose(fp);
        return;
    }
    while (fgets(line, sizeof(line), fp)) {
        char proto[16] = "", int_ip[64] = "", desc[192] = "", id[96];
        int eport = 0, iport = 0, lease = 0;
        if (!nc_upnp_parse_lease_line(line, proto, sizeof(proto), &eport, int_ip, sizeof(int_ip), &iport, desc, sizeof(desc), &lease)) continue;
        if ((!strcasecmp(proto,"TCP") || !strcasecmp(proto,"UDP")) && eport > 0 && iport > 0 && nc_ipv4_ok(int_ip)) {
            snprintf(id, sizeof(id), "%s_%d_%s_%d", proto, eport, int_ip, iport);
            if (nc_prepare(&st, "INSERT OR REPLACE INTO upnp_mapping_cache(id,protocol,external_port,internal_ip,internal_port,client,description,lease_seconds,packets,updated_at) VALUES(?1,?2,?3,?4,?5,'',?6,?7,0,?8)") == 0) {
                sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,proto,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,3,eport); sqlite3_bind_text(st,4,int_ip,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,5,iport); sqlite3_bind_text(st,6,desc,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,7,lease); sqlite3_bind_int64(st,8,now); nc_step_done(st); sqlite3_finalize(st); st=NULL;
            }
        }
    }
    fclose(fp);
    nc_exec("COMMIT");
}
static int nc_read_proc_net_dev_packets(const char *ifname, uint64_t *rxp, uint64_t *txp)
{
    FILE *fp = fopen("/proc/net/dev", "r"); char line[512];
    if (rxp) *rxp = 0; if (txp) *txp = 0;
    if (!fp || !ifname || !ifname[0]) { if(fp)fclose(fp); return -1; }
    while (fgets(line, sizeof(line), fp)) {
        char *colon = strchr(line, ':'); char name[64]; unsigned long long vals[16]; int n;
        if (!colon) continue; *colon = '\0'; sscanf(line, " %63s", name); if (strcmp(name, ifname)) continue;
        n = sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &vals[0],&vals[1],&vals[2],&vals[3],&vals[4],&vals[5],&vals[6],&vals[7],&vals[8],&vals[9],&vals[10],&vals[11],&vals[12],&vals[13],&vals[14],&vals[15]);
        fclose(fp); if (n >= 10) { if(rxp)*rxp=vals[1]; if(txp)*txp=vals[9]; return 0; } return -1;
    }
    fclose(fp); return -1;
}

static void nc_upnp_update_mapping_packets(void)
{
    sqlite3_stmt *st = NULL; uint64_t rxp = 0, txp = 0; int64_t packets;
    if (nc_read_proc_net_dev_packets("br-lan", &rxp, &txp) != 0) nc_read_proc_net_dev_packets("lan", &rxp, &txp);
    packets = (int64_t)(rxp + txp);
    if (packets <= 0) return;
    if (nc_prepare(&st, "UPDATE upnp_mapping_cache SET packets=?1 WHERE packets=0") == 0) { sqlite3_bind_int64(st,1,packets); nc_step_done(st); sqlite3_finalize(st); }
}

static void nc_upnp_add_mappings(struct json_object *root)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT id,protocol,external_port,internal_ip,internal_port,client,description,lease_seconds,packets FROM upnp_mapping_cache ORDER BY updated_at DESC,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *m = json_object_new_object();
            nc_add_text(m, "id", st, 0); nc_add_text(m, "protocol", st, 1);
            json_object_object_add(m, "external_port", json_object_new_int(sqlite3_column_int(st, 2)));
            nc_add_text(m, "internal_ip", st, 3);
            json_object_object_add(m, "internal_port", json_object_new_int(sqlite3_column_int(st, 4)));
            nc_add_text(m, "client", st, 5); nc_add_text(m, "description", st, 6);
            json_object_object_add(m, "lease", json_object_new_int(sqlite3_column_int(st, 7)));
            json_object_object_add(m, "packets", json_object_new_int(sqlite3_column_int(st, 8)));
            json_object_object_add(m, "enabled", json_object_new_boolean(1));
            json_object_object_add(m, "mapping_type", json_object_new_string("dynamic"));
            json_object_array_add(arr, m);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(root, "mappings", arr);
}

struct json_object *jmx_upnp_service_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *ifs = json_object_new_array();
    struct json_object *acl = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int active = 0;
    if (jmx_netconfig_db_init() != 0) goto done;
    if (nc_upnp_import_uci_once() != 0) goto done;
    nc_upnp_refresh_mappings();
    if (nc_prepare(&st, "SELECT enabled,natpmp_enabled,secure_mode,external_iface,presentation_url,download_mbps,upload_mbps,lease_file,uuid,model_name,port_start,port_end,notify_interval,clean_interval,log_packets,system_uptime,use_stun,stun_host,stun_port,pcp,updated_at FROM upnp_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *pr = json_object_new_object();
            json_object_object_add(data, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
            json_object_object_add(data, "natpmp_enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
            json_object_object_add(data, "secure_mode", json_object_new_boolean(sqlite3_column_int(st, 2)));
            nc_add_text(data, "external_iface", st, 3); nc_add_text(data, "presentation_url", st, 4);
            json_object_object_add(data, "download_mbps", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_object_add(data, "upload_mbps", json_object_new_int(sqlite3_column_int(st, 6)));
            nc_add_text(data, "lease_file", st, 7); nc_add_text(data, "uuid", st, 8); nc_add_text(data, "model_name", st, 9);
            json_object_object_add(pr, "start", json_object_new_int(sqlite3_column_int(st, 10)));
            json_object_object_add(pr, "end", json_object_new_int(sqlite3_column_int(st, 11)));
            char managed_id[96];
            int managed = nc_upnp_managed_acl_id(managed_id, sizeof(managed_id)) == 1;
            json_object_object_add(pr, "acl_id", managed ? json_object_new_string(managed_id) : NULL);
            json_object_object_add(data, "port_range", pr);
            json_object_object_add(data, "notify_interval", json_object_new_int(sqlite3_column_int(st, 12)));
            json_object_object_add(data, "clean_interval", json_object_new_int(sqlite3_column_int(st, 13)));
            json_object_object_add(data, "log_packets", json_object_new_boolean(sqlite3_column_int(st, 14)));
            json_object_object_add(data, "system_uptime", json_object_new_boolean(sqlite3_column_int(st, 15)));
            json_object_object_add(data, "use_stun", json_object_new_boolean(sqlite3_column_int(st, 16)));
            nc_add_text(data, "stun_host", st, 17);
            json_object_object_add(data, "stun_port", json_object_new_int(sqlite3_column_int(st, 18)));
            json_object_object_add(data, "pcp", json_object_new_boolean(sqlite3_column_int(st, 19)));
        }
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT lan_id FROM upnp_internal_iface WHERE service_id=1 ORDER BY lan_id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) json_object_array_add(ifs, json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT id,action,external_ports,internal_cidr,internal_ports,remark,enabled,sort_order,managed FROM upnp_acl ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *a = json_object_new_object();
            nc_add_text(a, "id", st, 0); nc_add_text(a, "action", st, 1); nc_add_text(a, "external", st, 2);
            nc_add_text(a, "internal", st, 3); nc_add_text(a, "internal_ports", st, 4); nc_add_text(a, "remark", st, 5);
            json_object_object_add(a, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(a, "sort_order", json_object_new_int(sqlite3_column_int(st, 7)));
            nc_add_text(a, "managed", st, 8);
            int editable = !strcmp((const char *)sqlite3_column_text(st, 8), "");
            json_object_object_add(a, "editable", json_object_new_boolean(editable));
            json_object_object_add(a, "deletable", json_object_new_boolean(editable));
            json_object_array_add(acl, a);
        }
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT COUNT(*) FROM upnp_mapping_cache") == 0) { if (sqlite3_step(st) == SQLITE_ROW) active = sqlite3_column_int(st, 0); sqlite3_finalize(st); }
done:
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    json_object_object_add(data, "internal_ifaces", ifs);
    json_object_object_add(data, "acl", acl);
    nc_upnp_add_mappings(data);
    { struct json_object *stats = json_object_new_object(); json_object_object_add(stats, "active_mappings", json_object_new_int(active)); json_object_object_add(stats, "requests_today", json_object_new_int(0)); json_object_object_add(stats, "denied_today", json_object_new_int(0)); json_object_object_add(stats, "last_change", json_object_new_int64(0)); json_object_object_add(data, "stats", stats); }
    nc_upnp_add_caps(data);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* Return 1 for an unchanged managed row accepted in a service snapshot, 0
 * for a custom row, -3 for attempts to change the managed contract. */
static int nc_upnp_acl_guard(struct json_object *a, int bulk, int start, int end)
{
    sqlite3_stmt *st = NULL;
    int rc = 0;
    if (!a || !json_object_is_type(a, json_type_object)) return -2;
    const char *id = nc_json_str_def(a, "id", "");
    const char *marker = nc_json_str_def(a, "managed", "");
    if (nc_prepare(&st, "SELECT action,external_ports,internal_cidr,internal_ports,remark,enabled,sort_order,managed FROM upnp_acl WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && !strcmp((const char *)sqlite3_column_text(st, 7), "port_range")) {
        rc = -3;
        if (bulk && (!marker[0] || !strcmp(marker, "port_range"))) {
            const char *action = (const char *)sqlite3_column_text(st, 0);
            const char *external = (const char *)sqlite3_column_text(st, 1);
            const char *internal = (const char *)sqlite3_column_text(st, 2);
            const char *ports = (const char *)sqlite3_column_text(st, 3);
            const char *remark = (const char *)sqlite3_column_text(st, 4);
            const char *supplied = nc_json_str_def(a, "external", nc_json_str_def(a, "external_ports", external));
            int es, ee, old_start, old_end;
            if (!strcmp(nc_json_str_def(a, "action", action), action) &&
                !strcmp(nc_json_str_def(a, "internal", nc_json_str_def(a, "internal_cidr", internal)), internal) &&
                !strcmp(nc_json_str_def(a, "internal_ports", ports), ports) &&
                !strcmp(nc_json_str_def(a, "remark", nc_json_str_def(a, "comment", remark)), remark) &&
                nc_json_bool_def(a, "enabled", sqlite3_column_int(st, 5)) == sqlite3_column_int(st, 5) &&
                nc_json_int_def(a, "sort_order", sqlite3_column_int(st, 6)) == sqlite3_column_int(st, 6) &&
                nc_upnp_parse_acl_port_range(supplied, &es, &ee) &&
                nc_upnp_parse_acl_port_range(external, &old_start, &old_end) &&
                ((es == old_start && ee == old_end) || (es == start && ee == end))) rc = 1;
        }
    } else if (marker[0]) rc = -3;
    sqlite3_finalize(st);
    return rc;
}

int jmx_upnp_acl_set(struct json_object *a)
{
    sqlite3_stmt *st = NULL;
    const char *id, *act, *ext, *cidr, *ports;
    if (!a) return -2;
    id = nc_json_str_def(a, "id", ""); act = nc_json_str_def(a, "action", "allow");
    ext = nc_json_str_def(a, "external", nc_json_str_def(a, "external_ports", "1024-65535"));
    cidr = nc_json_str_def(a, "internal", nc_json_str_def(a, "internal_cidr", "0.0.0.0/0"));
    ports = nc_json_str_def(a, "internal_ports", "1-65535");
    { int es=0, ee=0, is=0, ie=0; if (!id[0] || !nc_valid_name(id) || (strcmp(act, "allow") && strcmp(act, "deny")) || !nc_cidr_ok(cidr) || !nc_upnp_parse_acl_port_range(ext,&es,&ee) || !nc_upnp_parse_acl_port_range(ports,&is,&ie)) return -2; }
    if (jmx_netconfig_db_init() != 0 || nc_upnp_import_uci_once() != 0) return -1;
    int guard = nc_upnp_acl_guard(a, 0, 0, 0);
    if (guard != 0) return guard;
    if (nc_prepare(&st, "INSERT INTO upnp_acl(id,action,external_ports,internal_cidr,internal_ports,remark,enabled,sort_order) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET action=excluded.action,external_ports=excluded.external_ports,internal_cidr=excluded.internal_cidr,internal_ports=excluded.internal_ports,remark=excluded.remark,enabled=excluded.enabled,sort_order=excluded.sort_order") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 2, act, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ext, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 4, cidr, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 5, ports, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, nc_json_str_def(a, "remark", nc_json_str_def(a, "comment", "")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, nc_json_bool_def(a, "enabled", 1)); sqlite3_bind_int(st, 8, nc_json_int_def(a, "sort_order", 0));
    { int rc = nc_step_done(st); sqlite3_finalize(st); return rc; }
}

int jmx_upnp_acl_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    int rc, changed;
    if (!id || !id[0] || !nc_valid_name(id)) return -2;
    if (jmx_netconfig_db_init() != 0 || nc_upnp_import_uci_once() != 0) return -1;
    char managed_id[96];
    if (nc_upnp_managed_acl_id(managed_id, sizeof(managed_id)) == 1 && !strcmp(id, managed_id)) return -3;
    if (nc_prepare(&st, "DELETE FROM upnp_acl WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    changed = sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st);
    return rc == 0 && changed == 1 ? 0 : (rc == 0 ? 1 : -1);
}


/* ══════════════════════════════════════════════════════════════════════
 * UPnP static port mappings (admin intent, distinct from miniupnpd leases)
 *
 * Dataplane strategy: a DreamingWrt-owned nft table, deliberately NOT fw4
 * and NOT miniupnpd's own chains.
 *   - miniupnpd flushes upnp_prerouting/upnp_forward/upnp_postrouting on
 *     restart, so anything we wrote there would silently vanish.
 *   - `fw4 reload` rebuilds the whole inet fw4 table, same problem.
 *   - the existing `inet dreamingwrt_ipv6_load` table proves an independent
 *     table coexists fine with fw4.
 * Keeping our own table also means static mappings do NOT depend on the
 * still-preview-only /etc/config/dreamingwrt_firewall apply path.
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_upnp_db_init_mappings(void);

/* nft present and usable? Static mapping capability hangs off this. */
static int nc_upnp_nft_available(void)
{
    static int cached = -1;

    if (cached >= 0)
        return cached;
    cached = nc_run_quiet("nft --check --file /dev/null >/dev/null 2>&1") == 0 ? 1 : 0;
    if (!cached)
        cached = nc_file_exists("/usr/sbin/nft") || nc_file_exists("/sbin/nft") ? 1 : 0;
    return cached;
}

static int nc_upnp_proto_ok(const char *proto)
{
    return proto && (!strcmp(proto, "tcp") || !strcmp(proto, "udp"));
}

static int nc_upnp_port_ok(int port)
{
    return port >= 1 && port <= 65535;
}

/*
 * Only RFC1918 targets. A static DNAT pointing at a public address would turn
 * the router into an open relay for someone else's host.
 */
static int nc_upnp_private_ipv4(const char *ip)
{
    struct in_addr a;
    uint32_t h;

    if (!ip || !ip[0] || inet_pton(AF_INET, ip, &a) != 1)
        return 0;
    h = ntohl(a.s_addr);
    if ((h >> 24) == 10) return 1;                        /* 10/8      */
    if ((h >> 20) == ((172 << 4) | 1)) return 1;          /* 172.16/12 */
    if ((h >> 16) == ((192 << 8) | 168)) return 1;        /* 192.168/16 */
    return 0;
}

/*
 * A prerouting DNAT on a port the router itself listens on steals that
 * traffic from the local service. Two severities, and we must not conflate
 * them:
 *   NC_UPNP_PORT_MGMT  - ssh / webd / ttyd. Redirecting these locks the admin
 *                        out and the only recovery is serial console.
 *   NC_UPNP_PORT_LOCAL - any other local listener (samba, netdata, ac, ...).
 *                        Still a real conflict, but not a lockout.
 * Derived from what is actually listening rather than a hardcoded port list:
 * this box runs ssh on 11504 and webd on 12517, not the defaults, so any
 * static table would be wrong.
 */
#define NC_UPNP_PORT_FREE  0
#define NC_UPNP_PORT_MGMT  1
#define NC_UPNP_PORT_LOCAL 2

static int nc_upnp_port_is_mgmt_owner(const char *prog)
{
    static const char *mgmt[] = {
        "sshd", "dropbear", "dreamingwrt-w", "dreamingwrt-webd", "ttyd", "uhttpd", NULL
    };
    int i;

    if (!prog || !prog[0])
        return 0;
    for (i = 0; mgmt[i]; i++)
        if (strstr(prog, mgmt[i]))
            return 1;
    return 0;
}

/*
 * Returns NC_UPNP_PORT_*; when non-free, owner is filled with the listening
 * program name so the error message can name the actual blocker.
 */
static int nc_upnp_port_conflict(int port, char *owner, size_t owner_len)
{
    FILE *fp;
    char line[320];
    int result = NC_UPNP_PORT_FREE;

    if (owner && owner_len)
        owner[0] = '\0';
    if (port < 1 || port > 65535)
        return NC_UPNP_PORT_FREE;

    /* -p gives us the owning program, which is what turns a bare refusal into
     * an actionable one. Re-probed per call: listeners come and go. */
    fp = popen("netstat -lntp 2>/dev/null", "r");
    if (!fp)
        return NC_UPNP_PORT_FREE;
    while (fgets(line, sizeof(line), fp)) {
        char local[128] = {0}, prog[96] = {0};
        const char *colon;
        int lport;

        /* Proto Recv-Q Send-Q Local Foreign State PID/Program */
        if (sscanf(line, "%*s %*s %*s %127s %*s %*s %95[^\n]", local, prog) < 1)
            continue;
        colon = strrchr(local, ':');
        if (!colon)
            continue;
        lport = atoi(colon + 1);
        if (lport != port)
            continue;
        /* trim leading spaces off the PID/Program column */
        {
            char *p = prog;
            while (*p == ' ' || *p == '\t') p++;
            if (owner && owner_len)
                snprintf(owner, owner_len, "%s", p);
            if (nc_upnp_port_is_mgmt_owner(p)) {
                result = NC_UPNP_PORT_MGMT;
                break;               /* management wins, stop looking */
            }
            result = NC_UPNP_PORT_LOCAL;
        }
    }
    pclose(fp);
    return result;
}

/*
 * Render every enabled static mapping into one nft transaction and swap the
 * table atomically. Full rebuild rather than incremental diffing: the DB is
 * the single source of truth, so state drift is impossible by construction.
 */
static int nc_upnp_static_nft_apply(void)
{
    sqlite3_stmt *st = NULL;
    FILE *fp;
    char path[] = "/tmp/dw-upnp-static.nft";
    int rows = 0;

    if (!nc_upnp_nft_available())
        return -3;
    if (jmx_netconfig_db_init() != 0)
        return -1;
    nc_upnp_db_init_mappings();

    /* No enabled mappings: drop the table entirely rather than leaving an
     * empty chain with a registered nat hook doing nothing per packet. */
    if (nc_prepare(&st, "SELECT COUNT(*) FROM upnp_mapping WHERE enabled=1") == 0) {
        int enabled = 0;
        if (sqlite3_step(st) == SQLITE_ROW)
            enabled = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (enabled == 0) {
            nc_run_quiet("nft delete table inet " NC_UPNP_NFT_TABLE " >/dev/null 2>&1");
            return 0;
        }
    }

    fp = fopen(path, "w");
    if (!fp)
        return -1;
    /* delete is tolerated-if-missing via `nft -f` add-then-flush idiom */
    fprintf(fp, "table inet " NC_UPNP_NFT_TABLE " {}\n");
    fprintf(fp, "delete table inet " NC_UPNP_NFT_TABLE "\n");
    fprintf(fp, "table inet " NC_UPNP_NFT_TABLE " {\n");
    fprintf(fp, "  chain dw_upnp_prerouting {\n");
    fprintf(fp, "    type nat hook prerouting priority dstnat + 5; policy accept;\n");

    if (nc_prepare(&st,
        "SELECT protocol,external_port,internal_ip,internal_port,description "
        "FROM upnp_mapping WHERE enabled=1 ORDER BY external_port") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *proto = (const char *)sqlite3_column_text(st, 0);
            int eport = sqlite3_column_int(st, 1);
            const char *iip = (const char *)sqlite3_column_text(st, 2);
            int iport = sqlite3_column_int(st, 3);

            if (!nc_upnp_proto_ok(proto) || !nc_upnp_port_ok(eport) ||
                !nc_upnp_port_ok(iport) || !nc_upnp_private_ipv4(iip))
                continue;   /* never emit a row we would have rejected on write */
            fprintf(fp, "    %s dport %d counter dnat ip to %s:%d\n",
                    proto, eport, iip, iport);
            rows++;
        }
        sqlite3_finalize(st);
    }
    fprintf(fp, "  }\n}\n");
    fclose(fp);

    if (nc_run_quiet("nft -f /tmp/dw-upnp-static.nft >/tmp/dw-upnp-static.log 2>&1") != 0) {
        /* leave no half-applied table behind */
        nc_run_quiet("nft delete table inet " NC_UPNP_NFT_TABLE " >/dev/null 2>&1");
        return -1;
    }
    /* rows is the count we believe we installed; readback verifies it for real. */
    (void)rows;
    return 0;
}

/* Read back what the kernel actually holds, so the API never claims more
 * than the dataplane really has. */
static struct json_object *nc_upnp_static_nft_readback(void)
{
    struct json_object *out = json_object_new_object();
    struct json_object *rules = json_object_new_array();
    int installed = 0, count = 0;
    int db_enabled = -1;
    FILE *fp;
    char line[512];

    if (!nc_upnp_nft_available()) {
        json_object_object_add(out, "supported", json_object_new_boolean(0));
        json_object_object_add(out, "reason", json_object_new_string("nft_unavailable"));
        json_object_object_add(out, "rules", rules);
        return out;
    }
    fp = popen("nft list table inet " NC_UPNP_NFT_TABLE " 2>/dev/null", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *nl;
            if (strstr(line, "table inet " NC_UPNP_NFT_TABLE))
                installed = 1;
            if (!strstr(line, "dnat"))
                continue;
            nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            while (*line == ' ' || *line == '\t') memmove(line, line + 1, strlen(line));
            json_object_array_add(rules, json_object_new_string(line));
            count++;
        }
        pclose(fp);
    }
    /* How many rows the DB *thinks* are live, so drift is visible instead of
     * silently assumed away. */
    if (jmx_netconfig_db_init() == 0) {
        sqlite3_stmt *st = NULL;
        nc_upnp_db_init_mappings();
        if (nc_prepare(&st, "SELECT COUNT(*) FROM upnp_mapping WHERE enabled=1") == 0) {
            if (sqlite3_step(st) == SQLITE_ROW)
                db_enabled = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
        }
    }
    json_object_object_add(out, "supported", json_object_new_boolean(1));
    json_object_object_add(out, "table", json_object_new_string("inet " NC_UPNP_NFT_TABLE));
    json_object_object_add(out, "installed", json_object_new_boolean(installed));
    json_object_object_add(out, "rule_count", json_object_new_int(count));
    json_object_object_add(out, "db_enabled_count", json_object_new_int(db_enabled));
    if (db_enabled >= 0)
        json_object_object_add(out, "in_sync", json_object_new_boolean(db_enabled == count));
    json_object_object_add(out, "rules", rules);
    return out;
}

/*
 * Our nft table lives in kernel memory only, so a reboot (or an external
 * `nft flush ruleset`) wipes it while the DB still lists the mappings. Rather
 * than adding yet another boot script, reconcile lazily on the first UPnP
 * touch after core start: if the DB has enabled rows and the table is not
 * installed, re-render it. Idempotent and cheap (one `nft list` probe).
 */
static void nc_upnp_static_reconcile_once(void)
{
    static int done = 0;
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (done)
        return;
    done = 1;
    if (!nc_upnp_nft_available())
        return;
    if (jmx_netconfig_db_init() != 0)
        return;
    nc_upnp_db_init_mappings();
    if (nc_prepare(&st, "SELECT COUNT(*) FROM upnp_mapping WHERE enabled=1") != 0)
        return;
    if (sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (enabled <= 0)
        return;
    if (nc_run_quiet("nft list table inet " NC_UPNP_NFT_TABLE " >/dev/null 2>&1") == 0)
        return;   /* already present, nothing to restore */
    nc_upnp_static_nft_apply();
}

struct json_object *jmx_upnp_static_status(void)
{
    struct json_object *data;

    nc_upnp_static_reconcile_once();
    data = nc_upnp_static_nft_readback();
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_upnp_static_apply(void)
{
    return nc_upnp_static_nft_apply();
}

int jmx_upnp_mapping_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    int rc, changed;

    if (!id || !id[0] || !nc_valid_name(id)) return -2;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_upnp_db_init_mappings();
    if (nc_prepare(&st, "DELETE FROM upnp_mapping WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    changed = sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st);
    if (rc != 0) return -1;
    if (changed != 1) return 1;          /* not found */
    /* DB is source of truth; re-render the whole table from it. */
    if (nc_upnp_static_nft_apply() != 0) return -4;
    return 0;
}

static int nc_upnp_merge_range(struct json_object *cfg, int *start, int *end)
{
    struct json_object *range = NULL, *top = NULL, *nested = NULL;
    int values[2] = {*start, *end};
    const char *flat[] = {"port_start", "port_end"}, *part[] = {"start", "end"};
    if (json_object_object_get_ex(cfg, "port_range", &range) &&
        (!range || !json_object_is_type(range, json_type_object))) return -2;
    for (int i = 0; i < 2; i++) {
        int have_top = json_object_object_get_ex(cfg, flat[i], &top);
        int have_nested = range && json_object_object_get_ex(range, part[i], &nested);
        if ((have_top && (!top || !json_object_is_type(top, json_type_int))) ||
            (have_nested && (!nested || !json_object_is_type(nested, json_type_int)))) return -2;
        if (have_top && have_nested && json_object_get_int64(top) != json_object_get_int64(nested)) return -2;
        if (have_top || have_nested) {
            int64_t value = json_object_get_int64(have_top ? top : nested);
            if (value < 1 || value > 65535) return -2;
            values[i] = (int)value;
        }
    }
    if (!nc_port_range_ok(values[0], values[1])) return -2;
    *start = values[0]; *end = values[1];
    return 0;
}

static int nc_upnp_disabled_field_changed(struct json_object *cfg,
                                          const char **field,
                                          const char **capability,
                                          const char **reason)
{
    sqlite3_stmt *st = NULL;
    struct json_object *value = NULL;
    if (!cfg || !json_object_is_type(cfg, json_type_object)) return -2;
#define NC_UPNP_DENY(_field, _capability, _reason) \
    do { \
        if (field) *field = (_field); \
        if (capability) *capability = (_capability); \
        if (reason) *reason = (_reason); \
        sqlite3_finalize(st); \
        return 1; \
    } while (0)
    if (json_object_object_get_ex(cfg, "force_forwarding", &value))
        NC_UPNP_DENY("force_forwarding", "force_forwarding", "upnp_force_forwarding_removed");
    if (jmx_netconfig_db_init() != 0 || nc_upnp_import_uci_once() != 0) return -1;
    if (nc_prepare(&st, "SELECT port_start,port_end,lease_file,uuid,model_name FROM upnp_service WHERE id=1") != 0) return -1;
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    int start = sqlite3_column_int(st, 0), end = sqlite3_column_int(st, 1);
    if (nc_upnp_merge_range(cfg, &start, &end) != 0) { sqlite3_finalize(st); return -2; }
    if ((json_object_object_get_ex(cfg, "port_range", &value) ||
         json_object_object_get_ex(cfg, "port_start", &value) ||
         json_object_object_get_ex(cfg, "port_end", &value)) &&
        nc_upnp_managed_acl_id(NULL, 0) != 1)
        NC_UPNP_DENY("port_range", "port_range", "upnp_port_range_no_managed_default");
    const char *keys[] = {"lease_file", "uuid", "model_name"};
    const char *reasons[] = {"upnp_lease_file_runtime_contract_pending", "upnp_uuid_runtime_contract_pending", "upnp_model_name_runtime_contract_pending"};
    for (int i = 0; i < 3; i++) {
        const char *old = (const char *)sqlite3_column_text(st, i + 2);
        if (json_object_object_get_ex(cfg, keys[i], &value) &&
            strcmp(json_object_get_string(value) ? json_object_get_string(value) : "", old ? old : ""))
            NC_UPNP_DENY(keys[i], keys[i], reasons[i]);
    }
#undef NC_UPNP_DENY
    sqlite3_finalize(st);
    return 0;
}

int jmx_upnp_service_set(struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *arr = NULL, *v = NULL, *acl_arr = NULL;
    int rc = -1, i, n;
    int enabled = 0, natpmp = 1, secure = 1, down = 0, up = 0;
    int use_stun = 0, stun_port = 3478, pcp = 0, clean_interval = 0;
    int port_start = 1024, port_end = 65535;
    char managed_id[96] = "";
    char stun_host[256] = "";
    int notify = 30, log_packets = 0, system_uptime = 1;
    char external_iface[128] = "", presentation_url[256] = "";
    int gate;

    if (!cfg || !json_object_is_type(cfg, json_type_object)) return -2;
    if (jmx_netconfig_db_init() != 0) return -1;
    gate = nc_upnp_disabled_field_changed(cfg, NULL, NULL, NULL);
    if (gate != 0) return gate > 0 ? -3 : gate;
    if (nc_prepare(&st, "SELECT enabled,natpmp_enabled,secure_mode,external_iface,"
                        "presentation_url,download_mbps,upload_mbps,"
                        "notify_interval,log_packets,system_uptime,use_stun,stun_host,stun_port,pcp,clean_interval,port_start,port_end FROM upnp_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            enabled = sqlite3_column_int(st, 0); natpmp = sqlite3_column_int(st, 1);
            secure = sqlite3_column_int(st, 2);
            snprintf(external_iface, sizeof(external_iface), "%s", (const char *)sqlite3_column_text(st, 3));
            snprintf(presentation_url, sizeof(presentation_url), "%s", (const char *)sqlite3_column_text(st, 4));
            down = sqlite3_column_int(st, 5); up = sqlite3_column_int(st, 6);
            notify = sqlite3_column_int(st, 7);
            log_packets = sqlite3_column_int(st, 8);
            system_uptime = sqlite3_column_int(st, 9);
            use_stun = sqlite3_column_int(st, 10);
            snprintf(stun_host, sizeof(stun_host), "%s", (const char *)sqlite3_column_text(st, 11));
            stun_port = sqlite3_column_int(st, 12);
            pcp = sqlite3_column_int(st, 13);
            clean_interval = sqlite3_column_int(st, 14);
            port_start = sqlite3_column_int(st, 15);
            port_end = sqlite3_column_int(st, 16);
        }
        sqlite3_finalize(st); st = NULL;
    }
    if (nc_upnp_merge_range(cfg, &port_start, &port_end) != 0) return -2;
    if (nc_upnp_managed_acl_id(managed_id, sizeof(managed_id)) < 0) return -1;
    if (json_object_object_get_ex(cfg, "enabled", &v)) enabled = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "natpmp_enabled", &v)) natpmp = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "secure_mode", &v)) secure = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "external_iface", &v)) snprintf(external_iface, sizeof(external_iface), "%s", json_object_get_string(v));
    if (json_object_object_get_ex(cfg, "presentation_url", &v)) snprintf(presentation_url, sizeof(presentation_url), "%s", json_object_get_string(v));
    if (json_object_object_get_ex(cfg, "download_mbps", &v)) down = json_object_get_int(v);
    if (json_object_object_get_ex(cfg, "upload_mbps", &v)) up = json_object_get_int(v);
    if (json_object_object_get_ex(cfg, "notify_interval", &v)) notify = json_object_get_int(v);
    if (json_object_object_get_ex(cfg, "log_packets", &v)) log_packets = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "system_uptime", &v)) system_uptime = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "use_stun", &v)) use_stun = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "stun_host", &v)) snprintf(stun_host, sizeof(stun_host), "%s", json_object_get_string(v) ? json_object_get_string(v) : "");
    if (json_object_object_get_ex(cfg, "stun_port", &v)) stun_port = json_object_get_int(v);
    if (json_object_object_get_ex(cfg, "pcp", &v)) pcp = json_object_get_boolean(v);
    if (json_object_object_get_ex(cfg, "clean_interval", &v)) clean_interval = json_object_get_int(v);
    if (use_stun && !stun_host[0]) return -2; /* STUN enabled requires a host */
    if (stun_port < 1 || stun_port > 65535) return -2;
    for (const unsigned char *p = (const unsigned char *)stun_host; *p; ++p)
        if (isspace(*p) || iscntrl(*p) || *p == '=' || *p == '#') return -2;
    if (clean_interval < 0 || clean_interval > 86400) return -2;
    if (down < 0 || up < 0 || down > 1000000 || up > 1000000 ||
        notify < 5 || notify > 86400 || strlen(presentation_url) > 255)
        return -2;
    if (external_iface[0]) {
        int found = 0;
        if (nc_prepare(&st, "SELECT 1 FROM wan WHERE id=?1 OR ifname=?1 LIMIT 1") == 0) {
            sqlite3_bind_text(st, 1, external_iface, -1, SQLITE_TRANSIENT);
            found = sqlite3_step(st) == SQLITE_ROW;
            sqlite3_finalize(st); st = NULL;
        }
        if (!found) return -2;
    }
    if (json_object_object_get_ex(cfg, "internal_ifaces", &arr)) {
        if (!arr || !json_object_is_type(arr, json_type_array) || json_object_array_length(arr) > 32)
            return -2;
        n = (int)json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            const char *lan = json_object_get_string(json_object_array_get_idx(arr, i));
            int found = 0;
            if (!lan || !nc_valid_name(lan)) return -2;
            if (nc_prepare(&st, "SELECT 1 FROM lan WHERE id=?1 LIMIT 1") == 0) {
                sqlite3_bind_text(st, 1, lan, -1, SQLITE_TRANSIENT);
                found = sqlite3_step(st) == SQLITE_ROW;
                sqlite3_finalize(st); st = NULL;
            }
            if (!found) return -2;
        }
    }
    if (json_object_object_get_ex(cfg, "acl", &acl_arr)) {
        if (!acl_arr || !json_object_is_type(acl_arr, json_type_array)) return -2;
        for (size_t i = 0; i < json_object_array_length(acl_arr); i++) {
            int guard = nc_upnp_acl_guard(json_object_array_get_idx(acl_arr, i), 1, port_start, port_end);
            if (guard < 0) return guard;
        }
    }
    if (nc_exec("BEGIN IMMEDIATE") != 0) return -1;
    if (nc_prepare(&st, "UPDATE upnp_service SET enabled=?1,natpmp_enabled=?2,secure_mode=?3,external_iface=?4,presentation_url=?5,download_mbps=?6,upload_mbps=?7,notify_interval=?8,log_packets=?9,system_uptime=?10,use_stun=?12,stun_host=?13,stun_port=?14,pcp=?15,clean_interval=?16,port_start=?17,port_end=?18,updated_at=?11 WHERE id=1") == 0) {
        sqlite3_bind_int(st, 1, enabled); sqlite3_bind_int(st, 2, natpmp); sqlite3_bind_int(st, 3, secure);
        sqlite3_bind_text(st, 4, external_iface, -1, SQLITE_TRANSIENT); sqlite3_bind_text(st, 5, presentation_url, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, down); sqlite3_bind_int(st, 7, up);
        sqlite3_bind_int(st, 8, notify); sqlite3_bind_int(st, 9, log_packets);
        sqlite3_bind_int(st, 10, system_uptime); sqlite3_bind_int64(st, 11, nc_now_s());
        sqlite3_bind_int(st, 12, use_stun); sqlite3_bind_text(st, 13, stun_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 14, stun_port); sqlite3_bind_int(st, 15, pcp);
        sqlite3_bind_int(st, 16, clean_interval);
        sqlite3_bind_int(st, 17, port_start); sqlite3_bind_int(st, 18, port_end);
        if (nc_step_done(st) == 0) rc = 0; sqlite3_finalize(st);
    }
    if (rc == 0 && json_object_object_get_ex(cfg, "internal_ifaces", &arr)) { if (nc_prepare(&st, "DELETE FROM upnp_internal_iface WHERE service_id=1") == 0) { if (nc_step_done(st) != 0) rc=-1; sqlite3_finalize(st); } else rc=-1; if (rc==0) { n = (int)json_object_array_length(arr); for (i=0;i<n;i++) { const char *lan = json_object_get_string(json_object_array_get_idx(arr,i)); if (nc_prepare(&st, "INSERT OR IGNORE INTO upnp_internal_iface(service_id,lan_id) VALUES(1,?1)") == 0) { sqlite3_bind_text(st,1,lan,-1,SQLITE_TRANSIENT); if (nc_step_done(st) != 0) rc=-1; sqlite3_finalize(st); } else rc=-1; if(rc!=0)break; } } }
    if (rc == 0 && acl_arr) {
        rc = nc_exec("DELETE FROM upnp_acl WHERE managed=''");
        for (size_t i = 0; rc == 0 && i < json_object_array_length(acl_arr); i++) {
            struct json_object *entry = json_object_array_get_idx(acl_arr, i);
            if (managed_id[0] && !strcmp(nc_json_str_def(entry, "id", ""), managed_id)) continue;
            rc = jmx_upnp_acl_set(entry);
        }
    }
    if (rc == 0 && managed_id[0]) {
        char external[32];
        snprintf(external, sizeof(external), "%d-%d", port_start, port_end);
        if (nc_prepare(&st, "UPDATE upnp_acl SET external_ports=?1 WHERE id=?2 AND managed='port_range'") != 0) rc = -1;
        else {
            sqlite3_bind_text(st, 1, external, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, managed_id, -1, SQLITE_TRANSIENT);
            rc = nc_step_done(st); sqlite3_finalize(st);
        }
    }
    if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1;
    if (rc != 0) nc_exec("ROLLBACK");
    return rc;
}

int jmx_upnp_service_apply(void)
{
    struct uci_context *ctx = NULL; struct uci_package *pkg = NULL; sqlite3_stmt *st = NULL; char bak[256] = {0}; int rc = -1; int committed = 0; char b[32];
    if (jmx_netconfig_db_init() != 0 || nc_upnp_import_uci_once() != 0 || nc_backup_config("upnpd", bak, sizeof(bak)) != 0) return -1; ctx = uci_alloc_context(); if (!ctx) goto done;
    if (uci_load(ctx, "upnpd", &pkg) != UCI_OK || !pkg) goto done;
    if (nc_uci_ensure_section(ctx, pkg, "upnpd", "config", "upnpd") != 0) goto done;
    if (nc_prepare(&st, "SELECT enabled,natpmp_enabled,secure_mode,external_iface,presentation_url,download_mbps,upload_mbps,notify_interval,log_packets,system_uptime,use_stun,stun_host,stun_port,pcp,clean_interval FROM upnp_service WHERE id=1") == 0 && sqlite3_step(st) == SQLITE_ROW) {
        if (nc_uci_set_pkg(ctx,"upnpd","config","enabled",sqlite3_column_int(st,0)?"1":"0") != 0 ||
            nc_uci_set_pkg(ctx,"upnpd","config","enable_upnp",sqlite3_column_int(st,0)?"1":"0") != 0 ||
            nc_uci_set_pkg(ctx,"upnpd","config","enable_natpmp",sqlite3_column_int(st,1)?"1":"0") != 0 ||
            nc_uci_set_pkg(ctx,"upnpd","config","secure_mode",sqlite3_column_int(st,2)?"1":"0") != 0 ||
            nc_uci_set_pkg(ctx,"upnpd","config","external_iface",(const char*)sqlite3_column_text(st,3)) != 0 ||
            nc_uci_set_pkg(ctx,"upnpd","config","presentation_url",(const char*)sqlite3_column_text(st,4)) != 0) goto done;
        snprintf(b,sizeof(b),"%d",sqlite3_column_int(st,5) * 128); if (nc_uci_set_pkg(ctx,"upnpd","config","download",b) != 0) goto done;
        snprintf(b,sizeof(b),"%d",sqlite3_column_int(st,6) * 128); if (nc_uci_set_pkg(ctx,"upnpd","config","upload",b) != 0) goto done;
        snprintf(b,sizeof(b),"%d",sqlite3_column_int(st,7)); if (nc_uci_set_pkg(ctx,"upnpd","config","notify_interval",b) != 0) goto done;
        if (nc_uci_set_pkg(ctx,"upnpd","config","log_output",sqlite3_column_int(st,8)?"1":"0") != 0 ||
            nc_uci_set_pkg(ctx,"upnpd","config","system_uptime",sqlite3_column_int(st,9)?"1":"0") != 0) goto done;
        /* STUN: write to UCI; init.d already reads use_stun/stun_host/stun_port */
        if (nc_uci_set_pkg(ctx,"upnpd","config","use_stun",sqlite3_column_int(st,10)?"1":"0") != 0) goto done;
        if (nc_uci_set_pkg(ctx,"upnpd","config","stun_host",(const char*)sqlite3_column_text(st,11)) != 0) goto done;
        snprintf(b,sizeof(b),"%d",sqlite3_column_int(st,12)); if (nc_uci_set_pkg(ctx,"upnpd","config","stun_port",b) != 0) goto done;
        /* PCP and cleanup are consumed by the packaged init script. */
        if (nc_uci_set_pkg(ctx,"upnpd","config","enable_pcp_pmp",sqlite3_column_int(st,13)?"1":"0") != 0) goto done;
        /* Zero explicitly disables periodic cleanup; do not omit it. */
        snprintf(b,sizeof(b),"%d",sqlite3_column_int(st,14)); if (nc_uci_set_pkg(ctx,"upnpd","config","clean_ruleset_interval",b) != 0) goto done;
    } else goto done;
    if (st) { sqlite3_finalize(st); st=NULL; }
    if (nc_uci_delete_pkg(ctx,"upnpd","config","internal_iface") != 0) goto done;
    if (nc_prepare(&st,"SELECT lan_id FROM upnp_internal_iface WHERE service_id=1 ORDER BY lan_id") != 0) goto done;
    while(sqlite3_step(st)==SQLITE_ROW) if (nc_uci_add_list_pkg(ctx,"upnpd","config","internal_iface",(const char*)sqlite3_column_text(st,0)) != 0) goto done;
    sqlite3_finalize(st); st=NULL;
    nc_uci_delete_managed_sections(ctx,pkg,"upnpd","perm_rule","");
    if (nc_prepare(&st,"SELECT id,action,external_ports,internal_cidr,internal_ports,remark FROM upnp_acl WHERE enabled=1 ORDER BY sort_order,id") != 0) goto done;
    while(sqlite3_step(st)==SQLITE_ROW){char sec[96]; snprintf(sec,sizeof(sec),"dw_%s",(const char*)sqlite3_column_text(st,0)); if (nc_uci_ensure_section(ctx,pkg,"upnpd",sec,"perm_rule") != 0 || nc_uci_set_pkg(ctx,"upnpd",sec,"action",(const char*)sqlite3_column_text(st,1)) != 0 || nc_uci_set_pkg(ctx,"upnpd",sec,"ext_ports",(const char*)sqlite3_column_text(st,2)) != 0 || nc_uci_set_pkg(ctx,"upnpd",sec,"int_addr",(const char*)sqlite3_column_text(st,3)) != 0 || nc_uci_set_pkg(ctx,"upnpd",sec,"int_ports",(const char*)sqlite3_column_text(st,4)) != 0 || nc_uci_set_pkg(ctx,"upnpd",sec,"comment",(const char*)sqlite3_column_text(st,5)) != 0) goto done;}
    sqlite3_finalize(st); st=NULL;
    if (jmx_uci_commit(ctx, "upnpd") != UCI_OK) goto done;
    committed = 1;
    if (!nc_file_exists("/etc/init.d/miniupnpd") || nc_run_quiet("/etc/init.d/miniupnpd reload >/tmp/dw-upnp-apply.log 2>&1 || /etc/init.d/miniupnpd restart >>/tmp/dw-upnp-apply.log 2>&1") != 0) goto done;
    if (nc_upnp_runtime_readback() < 0) {
        g_nc_upnp_readback_failed = 1;
        rc = -5;
        goto done;
    }
    g_nc_upnp_readback_failed = 0;
    rc = 0;
done:
    if (st) sqlite3_finalize(st);
    if (ctx) uci_free_context(ctx);
    if (rc != 0) { nc_restore_config("upnpd", bak); if (committed && nc_file_exists("/etc/init.d/miniupnpd")) nc_run_quiet("/etc/init.d/miniupnpd reload >/tmp/dw-upnp-rollback.log 2>&1 || /etc/init.d/miniupnpd restart >>/tmp/dw-upnp-rollback.log 2>&1"); }
    nc_cleanup_backup(bak); return rc;
}

static struct json_object *nc_upnp_result(int saved, int applied, int rolled_back,
                                          const char *error)
{
    struct json_object *data = json_object_new_object();
    struct json_object *readback = jmx_upnp_service_get();
    struct json_object *readback_data = NULL;

    json_object_object_add(data, "ok", json_object_new_boolean(saved == 0 && applied == 0));
    json_object_object_add(data, "saved", json_object_new_boolean(saved == 0 && !rolled_back));
    json_object_object_add(data, "persisted", json_object_new_boolean(saved == 0 && !rolled_back));
    json_object_object_add(data, "applied", json_object_new_boolean(saved == 0 && applied == 0));
    json_object_object_add(data, "runtime_rolled_back", json_object_new_boolean(rolled_back));
    json_object_object_add(data, "apply_state", json_object_new_string(
        error && strstr(error, "_unsupported") ? "unsupported" :
        error && strstr(error, "_not_found") ? "not_found" :
        saved == -2 ? "validation_failed" : saved != 0 ? "save_failed" :
        applied == 0 ? "applied" : rolled_back ? "apply_failed_rolled_back" : "apply_failed_rollback_failed"));
    if (error && error[0]) json_object_object_add(data, "error", json_object_new_string(error));
    if (readback && json_object_object_get_ex(readback, "data", &readback_data) && readback_data)
        json_object_object_add(data, "readback", json_object_get(readback_data));
    if (readback) json_object_put(readback);
    return jmx_gen_api_response_data(saved == 0 && applied == 0 ? API_CODE_SUCCESS : API_CODE_ERROR,
                                     data);
}

static struct json_object *nc_upnp_capability_error(const char *field,
                                                     const char *capability,
                                                     const char *reason)
{
    struct json_object *data = json_object_new_object();
    struct json_object *field_results = json_object_new_object();
    struct json_object *result = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(data, "field", json_object_new_string(field));
    json_object_object_add(data, "capability", json_object_new_string(capability));
    json_object_object_add(data, "reason", json_object_new_string(reason));
    json_object_object_add(data, "saved", json_object_new_boolean(0));
    json_object_object_add(data, "persisted", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "runtime_rolled_back", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string("unsupported"));
    json_object_object_add(result, "supported", json_object_new_boolean(0));
    json_object_object_add(result, "persisted", json_object_new_boolean(0));
    json_object_object_add(result, "applied", json_object_new_boolean(0));
    json_object_object_add(result, "running", json_object_new_boolean(0));
    json_object_object_add(result, "capability", json_object_new_string(capability));
    json_object_object_add(result, "reason", json_object_new_string(reason));
    json_object_object_add(field_results, field, result);
    json_object_object_add(data, "field_results", field_results);
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static struct json_object *nc_upnp_snapshot_data(void)
{
    struct json_object *resp = jmx_upnp_service_get();
    struct json_object *data = NULL;
    struct json_object *snapshot = NULL;
    if (resp && json_object_object_get_ex(resp, "data", &data) && data)
        snapshot = json_object_get(data);
    if (resp) json_object_put(resp);
    return snapshot;
}

static int nc_upnp_restore_snapshot(struct json_object *snapshot)
{
    /* GET reports the legacy range even for custom-only policies. It is not
     * writable there and must not prevent restoring unrelated service data. */
    if (snapshot && nc_upnp_managed_acl_id(NULL, 0) == 0)
        json_object_object_del(snapshot, "port_range");
    if (!snapshot || jmx_upnp_service_set(snapshot) != 0)
        return -1;
    return jmx_upnp_service_apply();
}

struct json_object *jmx_upnp_service_save_apply_result(struct json_object *cfg)
{
    const char *field = NULL;
    const char *capability = NULL;
    const char *reason = NULL;
    int gate = nc_upnp_disabled_field_changed(cfg, &field, &capability, &reason);

    if (gate > 0)
        return nc_upnp_capability_error(field, capability, reason);
    if (gate == -2)
        return nc_upnp_result(-2, -1, 0, "upnp_validation_failed");
    if (gate != 0)
        return nc_upnp_result(-1, -1, 0, "upnp_source_unavailable");
    struct json_object *before = nc_upnp_snapshot_data();
    int saved = jmx_upnp_service_set(cfg);
    int applied = saved == 0 ? jmx_upnp_service_apply() : -1;
    int rolled_back = 0;
    const char *error = NULL;

    if (saved == -3) error = "upnp_acl_managed_by_port_range";
    else if (saved == -2) error = "upnp_validation_failed";
    else if (saved != 0) error = "upnp_save_failed";
    else if (applied != 0) {
        error = applied == -5 ? "upnp_runtime_readback_mismatch" : "upnp_apply_failed";
        rolled_back = before && nc_upnp_restore_snapshot(before) == 0;
        if (applied == -5) g_nc_upnp_readback_failed = 1;
    }
    if (before) json_object_put(before);
    return nc_upnp_result(saved, applied, rolled_back, error);
}

struct json_object *jmx_upnp_acl_save_apply_result(struct json_object *acl)
{
    struct json_object *before = nc_upnp_snapshot_data();
    int saved = jmx_upnp_acl_set(acl);
    int applied = saved == 0 ? jmx_upnp_service_apply() : -1;
    int rolled_back = 0;
    const char *error = NULL;

    if (saved == -3) error = "upnp_acl_managed_by_port_range";
    else if (saved == -2) error = "upnp_acl_validation_failed";
    else if (saved != 0) error = "upnp_acl_save_failed";
    else if (applied != 0) {
        error = applied == -5 ? "upnp_runtime_readback_mismatch" : "upnp_apply_failed";
        rolled_back = before && nc_upnp_restore_snapshot(before) == 0;
        if (applied == -5) g_nc_upnp_readback_failed = 1;
    }
    if (before) json_object_put(before);
    return nc_upnp_result(saved, applied, rolled_back, error);
}

struct json_object *jmx_upnp_acl_delete_apply_result(const char *id)
{
    struct json_object *before = nc_upnp_snapshot_data();
    int saved = jmx_upnp_acl_delete(id);
    int applied = saved == 0 ? jmx_upnp_service_apply() : -1;
    int rolled_back = 0;
    const char *error = NULL;

    if (saved == 1) error = "upnp_acl_not_found";
    else if (saved == -3) error = "upnp_acl_managed_by_port_range";
    else if (saved == -2) error = "upnp_acl_validation_failed";
    else if (saved != 0) error = "upnp_acl_delete_failed";
    else if (applied != 0) {
        error = applied == -5 ? "upnp_runtime_readback_mismatch" : "upnp_apply_failed";
        rolled_back = before && nc_upnp_restore_snapshot(before) == 0;
        if (applied == -5) g_nc_upnp_readback_failed = 1;
    }
    if (before) json_object_put(before);
    return nc_upnp_result(saved, applied, rolled_back, error);
}
/* ══════════════════════════════════════════════════════════════════════
 * DNS service: SQLite product config + dnsmasq first-slice apply
 * ══════════════════════════════════════════════════════════════════════ */

const char *nc_json_str_def(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v;
    const char *s;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    s = json_object_get_string(v);
    return s ? s : def;
}

int nc_json_int_def(struct json_object *o, const char *k, int def)
{
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int(v);
}

/*
 * 64-bit variant, for values that are absolute unix timestamps.
 * nc_json_int_def() returns int, which silently truncates past 2038 and would
 * turn a far-future expiry into a past one — i.e. a rule that never applies.
 */
int64_t nc_json_int64_def(struct json_object *o, const char *k, int64_t def)
{
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return (int64_t)json_object_get_int64(v);
}

int nc_json_bool_def(struct json_object *o, const char *k, int def)
{
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_boolean(v);
}

static int nc_dns_is_ip_literal(const char *s)
{
    struct in_addr a4;
    struct in6_addr a6;
    if (!s || !*s) return 0;
    if (inet_pton(AF_INET, s, &a4) == 1) return 1;
    if (inet_pton(AF_INET6, s, &a6) == 1) return 1;
    return 0;
}

static int nc_dns_is_ipv4_literal(const char *s)
{
    struct in_addr a4;

    return s && *s && inet_pton(AF_INET, s, &a4) == 1;
}

static int nc_dns_is_valid_host(const char *s)
{
    const char *p;
    size_t len;
    if (!s || !*s) return 0;
    len = strlen(s);
    if (len > 255) return 0;
    for (p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') continue;
        if (c == '[' || c == ']' || c == ':') continue;
        return 0;
    }
    return 1;
}

int nc_dns_valid_protocol(const char *p)
{
    return p && (!strcmp(p, "udp") || !strcmp(p, "tcp"));
}

static int nc_dns_known_protocol(const char *p)
{
    return nc_dns_valid_protocol(p) ||
           (p && (!strcmp(p, "dot") || !strcmp(p, "doh")));
}

static int nc_dns_valid_protocol_stored(const char *p)
{
    return nc_dns_known_protocol(p);
}

static int nc_dns_valid_upstream(const struct json_object *u)
{
    const char *addr = nc_json_str_def((struct json_object *)u, "address", "");
    const char *proto = nc_json_str_def((struct json_object *)u, "protocol", "udp");
    int port = nc_json_int_def((struct json_object *)u, "port", 53);
    if (!addr[0] || !nc_dns_valid_protocol(proto)) return 0;
    if (port < 1 || port > 65535) return 0;
    if (!nc_dns_is_ip_literal(addr) && !nc_dns_is_valid_host(addr)) return 0;
    return 1;
}

static int nc_dns_valid_upstream_stored(const struct json_object *u)
{
    const char *addr = nc_json_str_def((struct json_object *)u, "address", "");
    const char *proto = nc_json_str_def((struct json_object *)u, "protocol", "udp");
    int port = nc_json_int_def((struct json_object *)u, "port", 53);

    if (!addr[0] || !nc_dns_valid_protocol_stored(proto) || port < 1 || port > 65535)
        return 0;
    if (!strcmp(proto, "doh") || !strcmp(proto, "dot"))
        return 1;
    return nc_dns_is_ip_literal(addr) || nc_dns_is_valid_host(addr);
}

static int nc_dns_valid_upstream_request(const struct json_object *u)
{
    const char *proto = nc_json_str_def((struct json_object *)u, "protocol", "udp");

    if (nc_dns_valid_upstream(u))
        return 1;
    return !nc_json_bool_def((struct json_object *)u, "enabled", 1) &&
           nc_dns_known_protocol(proto) && nc_dns_valid_upstream_stored(u);
}

int nc_dns_valid_rule_type(const char *t)
{
    return t && (!strcmp(t, "host") || !strcmp(t, "forward") ||
                 !strcmp(t, "block") || !strcmp(t, "upstream"));
}

static int nc_dns_valid_rule_type_stored(const char *t)
{
    return nc_dns_valid_rule_type(t);
}

static int nc_dns_valid_domain_rule(const struct json_object *r)
{
    const char *domain = nc_json_str_def((struct json_object *)r, "domain", "");
    const char *type = nc_json_str_def((struct json_object *)r, "type", "");
    const char *target = nc_json_str_def((struct json_object *)r, "target", "");
    const char *p;
    size_t len;
    if (!domain[0] || !nc_dns_valid_rule_type(type)) return 0;
    len = strlen(domain);
    if (len > 253) return 0;
    if (domain[0] == '.') return 0;
    if (domain[len - 1] == '.') return 0;
    for (p = domain; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '*') continue;
        return 0;
    }
    if (!strcmp(type, "host")) {
        if (!target[0] || !nc_dns_is_ip_literal(target)) return 0;
    } else if (!strcmp(type, "forward") || !strcmp(type, "upstream")) {
        if (!target[0]) return 0;
        if (!nc_dns_is_ip_literal(target) && !nc_dns_is_valid_host(target)) return 0;
    }
    return 1;
}
static void nc_dns_add_wan_dns(struct json_object *data);
static int nc_dns_runtime_ready(int port, int wait_for_ready);
static int nc_dnsmasq_restart(const char *log_path);
static int nc_dnsmasq_restart_wait(const char *log_path);

enum nc_dns_listener_state {
    NC_DNS_LISTENER_UNAVAILABLE = -2,
    NC_DNS_LISTENER_INVALID = -1,
    NC_DNS_LISTENER_NOT_CONFIGURED = 0,
    NC_DNS_LISTENER_VALID = 1,
};

static int nc_dns_stored_listener_state(int enabled)
{
    sqlite3_stmt *st = NULL;
    int total = 0, valid = 0;

    if (!enabled)
        return NC_DNS_LISTENER_VALID;
    if (nc_prepare(&st,
        "SELECT COUNT(*),SUM(CASE WHEN l.id IS NOT NULL AND l.enabled=1 THEN 1 ELSE 0 END) "
        "FROM dns_listen_interface d LEFT JOIN lan l ON l.id=d.lan_id "
        "WHERE d.service_id=1") != 0)
        return NC_DNS_LISTENER_UNAVAILABLE;
    if (sqlite3_step(st) == SQLITE_ROW) {
        total = sqlite3_column_int(st, 0);
        valid = sqlite3_column_int(st, 1);
    } else {
        sqlite3_finalize(st);
        return NC_DNS_LISTENER_UNAVAILABLE;
    }
    sqlite3_finalize(st);
    if (total == 0)
        return NC_DNS_LISTENER_NOT_CONFIGURED;
    return total == valid ? NC_DNS_LISTENER_VALID : NC_DNS_LISTENER_INVALID;
}

static int nc_dns_config_degraded_reason(char *reason, size_t reason_len)
{
    sqlite3_stmt *st = NULL;
    int degraded = 0;
    int enabled = 0;
    int listener_state;

    if (reason && reason_len) reason[0] = '\0';
    if (nc_prepare(&st,
        "SELECT enabled,mode,hijack_protection,edns_client_subnet,ipv6_dns "
        "FROM dns_service WHERE id=1") != 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "dns_runtime_state_unavailable");
        return 1;
    }
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *mode;

        enabled = sqlite3_column_int(st, 0);
        mode = (const char *)sqlite3_column_text(st, 1);
        if ((mode && strcmp(mode, "proxy")) || sqlite3_column_int(st, 2) ||
            sqlite3_column_int(st, 3) || sqlite3_column_int(st, 4)) {
            degraded = 1;
            if (reason && reason_len)
                snprintf(reason, reason_len, "unsupported_dns_fields_configured");
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (degraded)
        return degraded;
    listener_state = nc_dns_stored_listener_state(enabled);
    if (listener_state != NC_DNS_LISTENER_VALID) {
        degraded = 1;
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s",
                listener_state == NC_DNS_LISTENER_NOT_CONFIGURED ?
                    "dns_listen_interface_not_configured" :
                listener_state == NC_DNS_LISTENER_INVALID ?
                    "dns_listen_interface_invalid" :
                    "dns_runtime_state_unavailable");
    }
    if (degraded)
        return degraded;
    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM dns_upstream WHERE enabled=1 "
        "AND protocol NOT IN ('udp','tcp')") != 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "dns_runtime_state_unavailable");
        return 1;
    }
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) > 0) {
        degraded = 1;
        if (reason && reason_len)
            snprintf(reason, reason_len, "unsupported_dns_transport_enabled");
    }
    sqlite3_finalize(st);
    if (degraded)
        return degraded;
    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM dns_rule WHERE enabled=1 "
        "AND type NOT IN ('host','forward','block','upstream')") != 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "dns_runtime_state_unavailable");
        return 1;
    }
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) > 0) {
        degraded = 1;
        if (reason && reason_len)
            snprintf(reason, reason_len, "unsupported_dns_rule_type_enabled");
    }
    sqlite3_finalize(st);
    return degraded;
}

static int nc_dns_complete_snapshot(const struct json_object *cfg)
{
    static const char *const required[] = {
        "enabled", "mode", "listen_port", "cache_enabled", "cache_size",
        "local_domain", "rebind_protection", "hijack_protection",
        "edns_client_subnet", "ipv6_dns", "listen_interfaces",
        "upstreams", "rules"
    };
    struct json_object *value = NULL;
    size_t i;

    if (!cfg || !json_object_is_type((struct json_object *)cfg, json_type_object))
        return 0;
    for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (!json_object_object_get_ex((struct json_object *)cfg, required[i], &value) || !value)
            return 0;
    }
    if (!json_object_object_get_ex((struct json_object *)cfg, "listen_interfaces", &value) ||
        !json_object_is_type(value, json_type_array) ||
        !json_object_object_get_ex((struct json_object *)cfg, "upstreams", &value) ||
        !json_object_is_type(value, json_type_array) ||
        !json_object_object_get_ex((struct json_object *)cfg, "rules", &value) ||
        !json_object_is_type(value, json_type_array))
        return 0;
    return 1;
}

static int nc_dns_snapshot_restorable(struct json_object *snapshot)
{
    struct json_object *arr = NULL;
    int i, n;

    if (!nc_dns_complete_snapshot(snapshot))
        return 0;
    json_object_object_get_ex(snapshot, "upstreams", &arr);
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *upstream = json_object_array_get_idx(arr, i);
        if (!upstream || !json_object_is_type(upstream, json_type_object) ||
            !nc_json_str_def(upstream, "id", "")[0] ||
            !nc_dns_valid_upstream_stored(upstream))
            return 0;
    }
    json_object_object_get_ex(snapshot, "rules", &arr);
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *rule = json_object_array_get_idx(arr, i);
        if (!rule || !json_object_is_type(rule, json_type_object) ||
            !nc_json_str_def(rule, "id", "")[0] ||
            !nc_json_str_def(rule, "domain", "")[0] ||
            !nc_dns_valid_rule_type_stored(nc_json_str_def(rule, "type", "")))
            return 0;
    }
    return 1;
}

static int nc_dns_listen_interfaces_valid(struct json_object *cfg)
{
    struct json_object *arr = NULL;
    int enabled = nc_json_bool_def(cfg, "enabled", 1);
    int i, n;

    if (!json_object_object_get_ex(cfg, "listen_interfaces", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array))
        return 0;
    n = (int)json_object_array_length(arr);
    if (enabled && n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        sqlite3_stmt *st = NULL;
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *lan;
        int j;

        if (!item || !json_object_is_type(item, json_type_string))
            return 0;
        lan = json_object_get_string(item);
        if (!lan || !lan[0])
            return 0;
        for (j = 0; j < i; j++) {
            const char *previous = json_object_get_string(json_object_array_get_idx(arr, j));
            if (previous && !strcmp(previous, lan))
                return 0;
        }
        if (!enabled)
            continue;
        if (nc_prepare(&st, "SELECT 1 FROM lan WHERE id=?1 AND enabled=1 LIMIT 1") != 0)
            return 0;
        sqlite3_bind_text(st, 1, lan, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            return 0;
        }
        sqlite3_finalize(st);
    }
    return 1;
}

static void nc_dns_apply_state_set(const char *state, const char *error)
{
    sqlite3_stmt *st = NULL;
    char value[256];

    snprintf(value, sizeof(value), "%s|%lld|%s", state ? state : "unknown",
             (long long)nc_now_s(), error ? error : "");
    if (nc_prepare(&st,
        "INSERT INTO network_meta(key,value) VALUES('dns_service.apply_state',?1) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value") == 0) {
        sqlite3_bind_text(st, 1, value, -1, SQLITE_TRANSIENT);
        (void)nc_step_done(st);
        sqlite3_finalize(st);
    }
}

static void nc_dns_apply_state_get(char *state, size_t state_len,
                                   int64_t *applied_at,
                                   char *error, size_t error_len)
{
    sqlite3_stmt *st = NULL;

    if (state && state_len) snprintf(state, state_len, "unknown");
    if (applied_at) *applied_at = 0;
    if (error && error_len) error[0] = '\0';
    if (nc_prepare(&st,
        "SELECT value FROM network_meta WHERE key='dns_service.apply_state'") == 0 &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *value = (const char *)sqlite3_column_text(st, 0);
        char copy[256];
        char *save = NULL;
        char *token;

        snprintf(copy, sizeof(copy), "%s", value ? value : "");
        token = strtok_r(copy, "|", &save);
        if (token && state && state_len) snprintf(state, state_len, "%s", token);
        token = strtok_r(NULL, "|", &save);
        if (token && applied_at) *applied_at = strtoll(token, NULL, 10);
        if (save && error && error_len) snprintf(error, error_len, "%s", save);
    }
    if (st) sqlite3_finalize(st);
}
static void nc_dns_add_stats(struct json_object *root)
{
    struct json_object *stats = json_object_new_object();
    sqlite3_stmt *st = NULL;
    json_object_object_add(stats, "queries_today", json_object_new_int(0));
    json_object_object_add(stats, "cache_hit_rate", json_object_new_int(0));
    json_object_object_add(stats, "blocked_today", json_object_new_int(0));
    json_object_object_add(stats, "avg_latency", json_object_new_int(0));
    if (nc_prepare(&st, "SELECT key,value FROM dns_runtime_stat") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *k = (const char *)sqlite3_column_text(st, 0);
            const char *v = (const char *)sqlite3_column_text(st, 1);
            if (k && v) json_object_object_add(stats, k, json_object_new_int(atoi(v)));
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(root, "stats", stats);
}
