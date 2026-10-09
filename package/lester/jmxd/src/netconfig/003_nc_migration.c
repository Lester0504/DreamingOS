/* ══════════════════════════════════════════════════════════════════════
 * First boot migration: UCI → SQLite
 * ══════════════════════════════════════════════════════════════════════ */

static int nc_ci_startswith(const char *s, const char *prefix)
{
    size_t n;
    if (!s || !prefix) return 0;
    n = strlen(prefix);
    return strlen(s) >= n && strncasecmp(s, prefix, n) == 0;
}

static const char *nc_uci_str(struct uci_context *ctx, struct uci_section *sec,
                              const char *opt, const char *def)
{
    const char *v = uci_lookup_option_string(ctx, sec, opt);
    return v ? v : def;
}

static int nc_uci_int(struct uci_context *ctx, struct uci_section *sec,
                      const char *opt, int def)
{
    const char *v = uci_lookup_option_string(ctx, sec, opt);
    return (v && v[0]) ? atoi(v) : def;
}

static int nc_netmask_to_prefix(const char *mask)
{
    struct in_addr a;
    uint32_t m;
    int cidr = 0;
    if (!mask || !mask[0]) return 24;
    if (strchr(mask, '/')) return atoi(strchr(mask, '/') + 1);
    if (inet_pton(AF_INET, mask, &a) != 1) return 24;
    m = ntohl(a.s_addr);
    while (m & 0x80000000) { cidr++; m <<= 1; }
    return cidr;
}

static int nc_parse_leasetime_minutes(const char *s, int def)
{
    int n;
    size_t len;
    if (!s || !s[0]) return def;
    n = atoi(s);
    len = strlen(s);
    if (len > 0) {
        char c = s[len - 1];
        if (c == 'h' || c == 'H') return n * 60;
        if (c == 'd' || c == 'D') return n * 24 * 60;
        if (c == 's' || c == 'S') return n / 60;
    }
    return n > 0 ? n : def;
}

static void nc_uci_list_json(struct uci_context *ctx, struct uci_section *sec,
                             const char *opt, char *out, size_t out_len)
{
    struct json_object *arr = json_object_new_array();
    struct uci_option *o;
    const char *s;
    if (!out || out_len == 0) return;
    snprintf(out, out_len, "[]");
    if (!arr) return;
    o = uci_lookup_option(ctx, sec, opt);
    if (o && o->type == UCI_TYPE_LIST) {
        struct uci_element *e;
        uci_foreach_element(&o->v.list, e) {
            if (e->name && e->name[0])
                json_object_array_add(arr, json_object_new_string(e->name));
        }
    } else if (o && o->type == UCI_TYPE_STRING && o->v.string && o->v.string[0]) {
        json_object_array_add(arr, json_object_new_string(o->v.string));
    } else {
        s = uci_lookup_option_string(ctx, sec, opt);
        if (s && s[0]) json_object_array_add(arr, json_object_new_string(s));
    }
    snprintf(out, out_len, "%s", json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN));
    json_object_put(arr);
}

static int nc_db_has_product_config(void)
{
    sqlite3_stmt *st = NULL;
    int n = 0;
    if (nc_prepare(&st, "SELECT (SELECT COUNT(*) FROM wan) + (SELECT COUNT(*) FROM lan)") != 0)
        return 1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n > 0;
}

static void nc_migrate_wan_address(const char *wan_id, const char *ip, const char *mask,
                                   int primary, int sort_order)
{
    sqlite3_stmt *st = NULL;
    char aid[128];
    int prefix;
    if (!wan_id || !wan_id[0] || !ip || !ip[0]) return;
    prefix = nc_netmask_to_prefix(mask);
    snprintf(aid, sizeof(aid), "%s_%s_%d", wan_id, ip, prefix);
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO wan_address(id,wan_id,ip,prefix,is_primary,sort_order) "
        "VALUES(?1,?2,?3,?4,?5,?6)") == 0) {
        sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, prefix);
        sqlite3_bind_int(st, 5, primary);
        sqlite3_bind_int(st, 6, sort_order);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
}

static void nc_migrate_lan_address(const char *lan_id, const char *ip, const char *mask,
                                   int primary, int sort_order)
{
    sqlite3_stmt *st = NULL;
    char aid[128];
    int prefix;
    if (!lan_id || !lan_id[0] || !ip || !ip[0]) return;
    prefix = nc_netmask_to_prefix(mask);
    snprintf(aid, sizeof(aid), "%s_%s_%d", lan_id, ip, prefix);
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO lan_address(id,lan_id,ip,prefix,is_primary,sort_order) "
        "VALUES(?1,?2,?3,?4,?5,?6)") == 0) {
        sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, prefix);
        sqlite3_bind_int(st, 5, primary);
        sqlite3_bind_int(st, 6, sort_order);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
}

static void nc_migrate_lan_ports(struct uci_context *ctx, struct uci_package *netpkg,
                                 const char *lan_id, const char *device)
{
    struct uci_element *e;
    int order = 0;
    if (!ctx || !netpkg || !lan_id || !lan_id[0] || !device || !device[0]) return;
    uci_foreach_element(&netpkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *type, *name;
        struct uci_option *ports;
        if (!s || strcmp(s->type, "device") != 0) continue;
        type = uci_lookup_option_string(ctx, s, "type");
        if (!type || strcmp(type, "bridge") != 0) continue;
        name = uci_lookup_option_string(ctx, s, "name");
        if ((!name || strcmp(name, device) != 0) && strcmp(s->e.name, device) != 0) continue;
        ports = uci_lookup_option(ctx, s, "ports");
        if (ports && ports->type == UCI_TYPE_LIST) {
            struct uci_element *pe;
            uci_foreach_element(&ports->v.list, pe) {
                sqlite3_stmt *st = NULL;
                char pid[128];
                if (!pe->name || !pe->name[0]) continue;
                snprintf(pid, sizeof(pid), "%s_%s", lan_id, pe->name);
                if (nc_prepare(&st,
                    "INSERT OR IGNORE INTO lan_port(id,lan_id,port,label,sort_order) "
                    "VALUES(?1,?2,?3,?4,?5)") == 0) {
                    sqlite3_bind_text(st, 1, pid, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 3, pe->name, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(st, 4, pe->name, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(st, 5, order++);
                    nc_step_done(st);
                    sqlite3_finalize(st);
                }
            }
        }
        break;
    }
}

static void nc_migrate_dhcp_for_lan(struct uci_context *ctx, struct uci_package *dhcppkg,
                                    const char *lan_id)
{
    struct uci_element *e;
    sqlite3_stmt *st = NULL;
    int found = 0;
    const char *start = "", *limit = "", *lease = "";
    int enabled = 0, lease_minutes = 120;
    if (!ctx || !dhcppkg || !lan_id || !lan_id[0]) return;

    uci_foreach_element(&dhcppkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *iface;
        if (!s || strcmp(s->type, "dhcp") != 0) continue;
        iface = uci_lookup_option_string(ctx, s, "interface");
        if ((iface && strcmp(iface, lan_id) == 0) || strcmp(s->e.name, lan_id) == 0) {
            const char *ignore = uci_lookup_option_string(ctx, s, "ignore");
            start = nc_uci_str(ctx, s, "start", "");
            limit = nc_uci_str(ctx, s, "limit", "");
            lease = nc_uci_str(ctx, s, "leasetime", "");
            enabled = !(ignore && strcmp(ignore, "1") == 0);
            lease_minutes = nc_parse_leasetime_minutes(lease, 120);
            found = 1;
            break;
        }
    }
    if (!found) return;
    if (nc_prepare(&st,
        "INSERT INTO lan_dhcp(lan_id,enabled,tagname,pool_start,pool_end,exclude_pool_json,gateway,dns_json,lease_minutes) "
        "VALUES(?1,?2,?3,?4,?5,'[]','','[]',?6) "
        "ON CONFLICT(lan_id) DO UPDATE SET enabled=excluded.enabled,pool_start=excluded.pool_start,"
        "pool_end=excluded.pool_end,lease_minutes=excluded.lease_minutes") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, enabled);
        sqlite3_bind_text(st, 3, lan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, start, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, limit, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, lease_minutes);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
}

static void nc_migrate_wans(struct uci_context *ctx, struct uci_package *wanpkg)
{
    struct uci_element *e;
    int64_t ts = nc_now_s();
    if (!ctx || !wanpkg) return;
    uci_foreach_element(&wanpkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        sqlite3_stmt *st = NULL;
        const char *id, *name, *device, *mode, *gateway, *ip, *mask;
        char dns_json[512];
        if (!s || strcmp(s->type, "wan") != 0) continue;
        id = s->e.name;
        name = nc_uci_str(ctx, s, "name", id);
        device = nc_uci_str(ctx, s, "device", id);
        mode = nc_uci_str(ctx, s, "access_mode", nc_uci_str(ctx, s, "proto", "dhcp"));
        gateway = nc_uci_str(ctx, s, "gateway", "");
        ip = nc_uci_str(ctx, s, "ipaddr", "");
        mask = nc_uci_str(ctx, s, "netmask", "24");
        nc_uci_list_json(ctx, s, "dns", dns_json, sizeof(dns_json));
        if (nc_prepare(&st,
            "INSERT INTO wan(id,name,note,carrier,ifname,device,port_label,access_mode,"
            "gateway,dns_json,ipv6_mode,ipv6_addr,delegated_prefix,vlan_enabled,vlan_id,"
            "mtu,metric,role,expected_down_mbps,expected_up_mbps,smart_queue,upnp,ddns,enabled,created_at,updated_at) "
            "VALUES(?1,?2,'','',?3,?4,'',?5,?6,?7,'disabled','','',0,'',?8,?9,'primary',0,0,0,0,0,?10,?11,?11) "
            "ON CONFLICT(id) DO NOTHING") == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, device, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, mode, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, gateway, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, dns_json, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 8, nc_uci_int(ctx, s, "mtu", 1500));
            sqlite3_bind_int(st, 9, nc_uci_int(ctx, s, "metric", 10));
            sqlite3_bind_int(st, 10, nc_uci_int(ctx, s, "enabled", 1));
            sqlite3_bind_int64(st, 11, ts);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
        if (ip && ip[0]) nc_migrate_wan_address(id, ip, mask, 1, 0);
        if (nc_prepare(&st,
            "INSERT INTO wan_advanced(wan_id,default_route,failover,link_time,health_enabled,health_mode,"
            "health_targets_json,dhcp_hostname,dhcp_vendor_class,dhcp_client_id,pppoe_timing_restart,"
            "pppoe_restart_week,pppoe_restart_time,pppoe_ac,pppoe_ac_mac,pppoe_service,pppoe_abnormal_ip_check,pppoe_abnormal_ip_prefixes) "
            "VALUES(?1,?2,1,'00:00-23:59',1,'ping',?3,'','','',0,'1234567','04:00','','','',0,'10,172,192.168') "
            "ON CONFLICT(wan_id) DO NOTHING") == 0) {
            char targets[256];
            const char *check_host = nc_uci_str(ctx, s, "check_host", "www.baidu.com");
            snprintf(targets, sizeof(targets), "[\"%s\"]", check_host && check_host[0] ? check_host : "www.baidu.com");
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, nc_uci_int(ctx, s, "default_route", 0));
            sqlite3_bind_text(st, 3, targets, -1, SQLITE_TRANSIENT);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
    }
}

static void nc_migrate_hybrid_lines(struct uci_context *ctx, struct uci_package *wanpkg)
{
    struct uci_element *e;
    if (!ctx || !wanpkg) return;
    uci_foreach_element(&wanpkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        sqlite3_stmt *st = NULL;
        const char *id, *parent, *name, *mode, *proto, *ip, *mask;
        if (!s || strcmp(s->type, "hybrid_line") != 0) continue;
        id = s->e.name;
        parent = nc_uci_str(ctx, s, "parent", nc_uci_str(ctx, s, "parent_wan_id", ""));
        if (!parent[0]) continue;
        name = nc_uci_str(ctx, s, "name", id);
        mode = nc_uci_str(ctx, s, "mode", "hybrid_macvlan");
        proto = nc_uci_str(ctx, s, "proto", nc_uci_str(ctx, s, "access_mode", "dhcp"));
        ip = nc_uci_str(ctx, s, "ipaddr", nc_uci_str(ctx, s, "ip", ""));
        mask = nc_uci_str(ctx, s, "netmask", "24");
        if (nc_prepare(&st,
            "INSERT INTO hybrid_line(id,parent_wan_id,name,comment,mode,vlan_id,mac,proto,enabled,default_route,failover,"
            "check_host,ip,prefix,gateway,username,password_ref,pppoe_ac,pppoe_ac_mac,pppoe_service,mtu,mru,upload_mbps,download_mbps) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'',?17,?18,?19,?20,?21,0,0) "
            "ON CONFLICT(id) DO NOTHING") == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, parent, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_uci_str(ctx, s, "comment", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, mode, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, nc_uci_str(ctx, s, "vlan_id", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, nc_uci_str(ctx, s, "mac", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 8, proto, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 9, nc_uci_int(ctx, s, "enabled", 1));
            sqlite3_bind_int(st, 10, nc_uci_int(ctx, s, "default_route", 0));
            sqlite3_bind_int(st, 11, nc_uci_int(ctx, s, "failover", 1));
            sqlite3_bind_text(st, 12, nc_uci_str(ctx, s, "check_host", "www.baidu.com"), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 13, ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 14, nc_netmask_to_prefix(mask));
            sqlite3_bind_text(st, 15, nc_uci_str(ctx, s, "gateway", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 16, nc_uci_str(ctx, s, "username", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 17, nc_uci_str(ctx, s, "pppoe_ac", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 18, nc_uci_str(ctx, s, "pppoe_ac_mac", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 19, nc_uci_str(ctx, s, "pppoe_service", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 20, nc_uci_int(ctx, s, "mtu", 1480));
            sqlite3_bind_int(st, 21, nc_uci_int(ctx, s, "mru", 1480));
            nc_step_done(st);
            sqlite3_finalize(st);
        }
    }
}

static void nc_migrate_lans(struct uci_context *ctx, struct uci_package *netpkg,
                            struct uci_package *dhcppkg)
{
    struct uci_element *e;
    int64_t ts = nc_now_s();
    if (!ctx || !netpkg) return;
    uci_foreach_element(&netpkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        sqlite3_stmt *st = NULL;
        const char *id, *device, *proto, *ip, *mask;
        if (!s || strcmp(s->type, "interface") != 0) continue;
        id = s->e.name;
        if (!nc_ci_startswith(id, "lan")) continue;
        device = nc_uci_str(ctx, s, "device", id);
        proto = nc_uci_str(ctx, s, "proto", "static");
        ip = nc_uci_str(ctx, s, "ipaddr", "");
        mask = nc_uci_str(ctx, s, "netmask", "24");
        if (nc_prepare(&st,
            "INSERT INTO lan(id,name,note,ifname,device,mode,parent_lan_id,vlan_id,mac_clone,speed,duplex,lan_visit,enabled,created_at,updated_at) "
            "VALUES(?1,?2,'',?3,?4,?5,'','','','0','0',1,?6,?7,?7) "
            "ON CONFLICT(id) DO NOTHING") == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, device, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, strcmp(proto, "static") == 0 ? "bridge" : proto, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 6, 1);
            sqlite3_bind_int64(st, 7, ts);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
        if (ip && ip[0]) nc_migrate_lan_address(id, ip, mask, 1, 0);
        nc_migrate_lan_ports(ctx, netpkg, id, device);
        nc_migrate_dhcp_for_lan(ctx, dhcppkg, id);
    }
}

static int jmx_netconfig_migrate_from_uci(void)
{
    struct uci_context *ctx = NULL;
    struct uci_package *wanpkg = NULL, *netpkg = NULL, *dhcppkg = NULL;
    int have_any = 0;

    if (nc_db_has_product_config()) return 0;

    ctx = uci_alloc_context();
    if (!ctx) return -1;

    if (uci_load(ctx, "dreamingwrt_wan", &wanpkg) == UCI_OK && wanpkg) {
        nc_migrate_wans(ctx, wanpkg);
        nc_migrate_hybrid_lines(ctx, wanpkg);
        have_any = 1;
    }
    if (uci_load(ctx, "network", &netpkg) == UCI_OK && netpkg) {
        (void)uci_load(ctx, "dhcp", &dhcppkg);
        nc_migrate_lans(ctx, netpkg, dhcppkg);
        have_any = 1;
    }

    if (dhcppkg) uci_unload(ctx, dhcppkg);
    if (netpkg) uci_unload(ctx, netpkg);
    if (wanpkg) uci_unload(ctx, wanpkg);
    uci_free_context(ctx);

    if (have_any) LOG_INFO("network.db migrated from UCI seed config\n");
    return 0;
}

static int nc_dns_config_compat_migrate_once(void)
{
    sqlite3_stmt *st = NULL;
    int changed = 0;
    int enabled = 0;
    int has_listener = 0;
    int listener_seeded = 0;

    if (nc_prepare(&st,
        "SELECT 1 FROM config_migration WHERE name=?1 AND status='done'") != 0)
        return -1;
    sqlite3_bind_text(st, 1, NC_DNS_CONFIG_COMPAT_MIGRATION, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    st = NULL;

    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE dns_service SET mode='proxy',hijack_protection=0,"
        "edns_client_subnet=0,ipv6_dns=0 WHERE id=1 AND "
        "(COALESCE(mode,'')<>'proxy' OR hijack_protection<>0 OR "
        "edns_client_subnet<>0 OR ipv6_dns<>0)") != 0)
        goto rollback;
    if (nc_step_done(st) != 0)
        goto rollback;
    changed += sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st);
    st = NULL;

    if (nc_prepare(&st,
        "SELECT enabled,EXISTS(SELECT 1 FROM dns_listen_interface WHERE service_id=1) "
        "FROM dns_service WHERE id=1") != 0)
        goto rollback;
    if (sqlite3_step(st) != SQLITE_ROW)
        goto rollback;
    enabled = sqlite3_column_int(st, 0);
    has_listener = sqlite3_column_int(st, 1);
    sqlite3_finalize(st);
    st = NULL;

    if (enabled && !has_listener) {
        if (nc_prepare(&st,
            "INSERT OR IGNORE INTO dns_listen_interface(service_id,lan_id) "
            "SELECT 1,id FROM lan WHERE enabled=1 "
            "ORDER BY CASE WHEN id='lan' THEN 0 ELSE 1 END,id LIMIT 1") != 0)
            goto rollback;
        if (nc_step_done(st) != 0)
            goto rollback;
        listener_seeded = sqlite3_changes(g_netconfig_db);
        changed += listener_seeded;
        sqlite3_finalize(st);
        st = NULL;

        /* LAN import can complete later in boot. Keep this migration pending
         * until a usable default listener can be seeded. */
        if (!listener_seeded)
            return nc_exec("COMMIT");
    }

    if (nc_prepare(&st,
        "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail) "
        "VALUES(?1,'done','config.db:dns_service+lan',?2,?3,"
        "'unsupported_fields_cleared_listener_compat_checked')") != 0)
        goto rollback;
    sqlite3_bind_text(st, 1, NC_DNS_CONFIG_COMPAT_MIGRATION, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, changed);
    sqlite3_bind_int64(st, 3, nc_now_s());
    if (nc_step_done(st) != 0)
        goto rollback;
    sqlite3_finalize(st);
    return nc_exec("COMMIT");

rollback:
    if (st) sqlite3_finalize(st);
    nc_exec("ROLLBACK");
    return -1;
}

