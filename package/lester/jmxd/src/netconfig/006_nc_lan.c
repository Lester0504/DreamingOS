/* ══════════════════════════════════════════════════════════════════════
 * LAN CRUD
 * ══════════════════════════════════════════════════════════════════════ */

static struct json_object *nc_lan_row_to_json(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    nc_add_text(o, "name", st, 1);
    nc_add_text(o, "note", st, 2);
    nc_add_text(o, "ifname", st, 3);
    nc_add_text(o, "device", st, 4);
    nc_add_text(o, "mode", st, 5);
    nc_add_text(o, "parent_lan_id", st, 6);
    nc_add_text(o, "vlan_id", st, 7);
    nc_add_text(o, "mac_clone", st, 8);
    nc_add_text(o, "speed", st, 9);
    nc_add_text(o, "duplex", st, 10);
    json_object_object_add(o, "lan_visit", json_object_new_boolean(sqlite3_column_int(st, 11)));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 12)));
    return o;
}

static void nc_lan_load_ports(const char *lan_id, struct json_object *lan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *ports = json_object_new_array();
    struct json_object *labels = json_object_new_array();
    if (nc_prepare(&st,
        "SELECT port,label FROM lan_port WHERE lan_id=?1 ORDER BY sort_order") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            json_object_array_add(ports, json_object_new_string(
                (const char *)sqlite3_column_text(st, 0)));
            json_object_array_add(labels, json_object_new_string(
                (const char *)sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : ""));
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(lan_obj, "ports", ports);
    json_object_object_add(lan_obj, "port_labels", labels);
}

static void nc_lan_load_addresses(const char *lan_id, struct json_object *lan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *extra = json_object_new_array();
    const char *primary_ip = "";
    int primary_prefix = 24;

    if (nc_prepare(&st,
        "SELECT ip,prefix,is_primary FROM lan_address WHERE lan_id=?1 ORDER BY sort_order") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(st, 0);
            int prefix = sqlite3_column_int(st, 1);
            int is_primary = sqlite3_column_int(st, 2);
            if (is_primary) {
                primary_ip = ip;
                primary_prefix = prefix;
                json_object_object_add(lan_obj, "ipaddr", json_object_new_string(ip));
                char mask[32], cidr[8];
                /* prefix to netmask */
                uint32_t m = prefix >= 32 ? 0xFFFFFFFF : htonl(~((1 << (32 - prefix)) - 1));
                struct in_addr a; a.s_addr = m;
                snprintf(mask, sizeof(mask), "%s", inet_ntoa(a));
                json_object_object_add(lan_obj, "netmask", json_object_new_string(mask));
                snprintf(cidr, sizeof(cidr), "%d", prefix);
                json_object_object_add(lan_obj, "cidr", json_object_new_string(cidr));
            } else {
                char cidr_str[64];
                snprintf(cidr_str, sizeof(cidr_str), "%s/%d", ip, prefix);
                json_object_array_add(extra, json_object_new_string(cidr_str));
            }
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(lan_obj, "extra_ips", extra);
    (void)primary_ip; (void)primary_prefix;
}

static struct json_object *nc_dhcp_base_get(const char *lan_id);
static struct json_object *nc_dhcp_text_array(const char *text);
static int nc_dhcp_legacy_set(const char *lan_id, struct json_object *dhcp);

static void nc_lan_load_dhcp(const char *lan_id, struct json_object *lan_obj)
{
    struct json_object *dhcp = nc_dhcp_base_get(lan_id);
    if (dhcp) {
        char pool[160];
        struct json_object *dns = json_object_object_get(dhcp, "dns");
        struct json_object *exclude = nc_dhcp_text_array(nc_json_str(dhcp, "exclude_pool", "[]"));
        snprintf(pool, sizeof(pool), "%s-%s", nc_json_str(dhcp, "pool_start", ""),
                 nc_json_str(dhcp, "pool_end", ""));
        json_object_object_add(dhcp, "pool", json_object_new_string(pool));
        json_object_object_add(dhcp, "lease", json_object_new_int(nc_json_int(dhcp, "lease_minutes", 120)));
        json_object_object_add(dhcp, "dns_json", json_object_new_string(json_object_to_json_string(dns)));
        json_object_object_add(dhcp, "exclude_pool_list", exclude ? exclude : json_object_new_array());
    }
    json_object_object_add(lan_obj, "dhcp", dhcp ? dhcp : json_object_new_object());
}

static void nc_lan_load_ipv6(const char *lan_id, struct json_object *lan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *ipv6 = json_object_new_object();
    if (nc_prepare(&st,
        "SELECT enabled,parent_wans_json,mode,dhcpv6,static_addr,"
        "use_dns6,dns6_json,prefix_len,ra_flags,ra_static,"
        "ra_mtu_set,ra_mtu,lease_minutes FROM lan_ipv6 WHERE lan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(ipv6, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
            nc_add_text(ipv6, "parent_json", st, 1);
            nc_add_text(ipv6, "mode", st, 2);
            json_object_object_add(ipv6, "dhcpv6", json_object_new_boolean(sqlite3_column_int(st, 3)));
            nc_add_text(ipv6, "addr", st, 4);
            json_object_object_add(ipv6, "use_dns6", json_object_new_boolean(sqlite3_column_int(st, 5)));
            nc_add_text(ipv6, "dns_json", st, 6);
            /* Parsed IPv6 DNS array alongside the legacy string field. */
            nc_add_array_text(ipv6, "dns6", st, 6);
            nc_add_text(ipv6, "prefix_len", st, 7);
            nc_add_text(ipv6, "ra_flags", st, 8);
            json_object_object_add(ipv6, "ra_static", json_object_new_boolean(sqlite3_column_int(st, 9)));
            json_object_object_add(ipv6, "ra_mtu_set", json_object_new_boolean(sqlite3_column_int(st, 10)));
            json_object_object_add(ipv6, "ra_mtu", json_object_new_int(sqlite3_column_int(st, 11)));
            json_object_object_add(ipv6, "leasetime", json_object_new_int(sqlite3_column_int(st, 12)));
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(lan_obj, "ipv6", ipv6);
}

/* True when an already-loaded network package has no interface section for
 * this id. Split out so both the list annotation and the delete check ask the
 * same question of the same source. */
static int nc_lan_missing_in_uci_pkg(struct uci_package *pkg, const char *lan_id)
{
    struct uci_element *e;

    if (!pkg || !lan_id || !lan_id[0])
        return 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || strcmp(s->type, "interface") != 0)
            continue;
        if (!strcmp(s->e.name, lan_id))
            return 0;
    }
    return 1;
}

/* True when config.db still holds this LAN but uci no longer does, i.e. the row
 * is a ghost the data plane does not back. Fails closed: if uci cannot be read
 * at all we report "not orphaned" so nothing treats a read error as licence to
 * discard a live LAN. */
static int nc_lan_is_orphaned(const char *lan_id)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    int orphaned = 0;

    if (!lan_id || !lan_id[0])
        return 0;
    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "network", &pkg) == UCI_OK && pkg) {
        orphaned = nc_lan_missing_in_uci_pkg(pkg, lan_id);
        uci_unload(ctx, pkg);
    }
    uci_free_context(ctx);
    return orphaned;
}

/* Annotate a LAN row with whether the data plane still backs it. Adds
 * orphaned=true plus a machine-readable reason when the uci interface section
 * is gone, so the UI can show it as stale instead of presenting it as a normal
 * LAN whose ports contradict network/ports ownership. Absent uci (no context,
 * package failed to load) leaves the row unannotated rather than declaring
 * every LAN an orphan. */
static void nc_lan_mark_orphaned(struct uci_context *ctx,
                                 struct uci_package *pkg,
                                 const char *lan_id,
                                 struct json_object *lan_obj)
{
    int orphaned;

    (void)ctx;
    if (!pkg || !lan_id || !lan_id[0] || !lan_obj)
        return;
    orphaned = nc_lan_missing_in_uci_pkg(pkg, lan_id);
    json_object_object_add(lan_obj, "orphaned", json_object_new_boolean(orphaned));
    if (orphaned)
        json_object_object_add(lan_obj, "orphan_reason",
                               json_object_new_string("uci_interface_section_missing"));
}

/* Single-column COUNT(*) with one optional text bind. Only used by the
 * deletability probe below, which asks the same counting questions the delete
 * path asks. Returns -1 when the query cannot run, so callers can tell "no
 * rows" from "could not look". */
static int nc_lan_count_one_bind(const char *sql, const char *bind)
{
    sqlite3_stmt *st = NULL;
    int count = -1;

    if (!sql || nc_prepare(&st, sql) != 0)
        return -1;
    if (bind)
        sqlite3_bind_text(st, 1, bind, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

/* Why a DELETE on this LAN would be refused, or NULL when nothing static
 * blocks it. This deliberately mirrors jmx_netconfig_lan_delete() check for
 * check and in the same order, so the button state the UI renders and the
 * verdict the delete actually returns cannot drift apart. The returned
 * literals are the same ones lan_delete_result reports, so the frontend can
 * reuse one translation table for both.
 *
 * Two of the delete path's outcomes are intentionally absent, because neither
 * is knowable while merely listing:
 *   - management_reachability_risk depends on the requesting client's IP
 *   - snapshot_failed depends on the state of /etc/config at delete time
 * So `deletable: true` means "no configured dependency blocks this", not a
 * promise the delete will succeed. The caller must still handle a refusal.
 *
 * pkg is the network package already loaded by the caller, reused so this does
 * not reload uci per row. When it is absent the orphan question fails closed
 * (not orphaned), matching nc_lan_is_orphaned(). */
static const char *nc_lan_delete_block_reason(struct uci_package *pkg,
                                             const char *lan_id,
                                             int enabled_lan_total)
{
    int count;

    if (!lan_id || !lan_id[0])
        return "lan_delete_failed";
    if (!strcmp(lan_id, "lan") || !strcmp(lan_id, "default-lan"))
        return "protected_management_lan";
    /* Every row in the list is enabled=1, so the list's own length is the
     * enabled count the delete path computes. */
    if (enabled_lan_total <= 1)
        return "last_enabled_lan";

    count = nc_lan_count_one_bind("SELECT COUNT(*) FROM lan_port WHERE lan_id=?1", lan_id);
    if (count > 0 && !(pkg && nc_lan_missing_in_uci_pkg(pkg, lan_id)))
        return "lan_ports_attached";

    count = nc_lan_count_one_bind("SELECT COUNT(*) FROM lan WHERE parent_lan_id=?1", lan_id);
    if (count > 0)
        return "child_lans_attached";

    if (nc_table_exists("ipam_network")) {
        count = nc_lan_count_one_bind(
            "SELECT COUNT(*) FROM ipam_network WHERE id=?1 OR ifname=?1", lan_id);
        if (count > 0)
            return "ipam_network_attached";
    }
    return NULL;
}

/* Annotate one LAN row with whether it can be deleted and why not. */
static void nc_lan_mark_deletable(struct uci_package *pkg,
                                  const char *lan_id,
                                  struct json_object *lan_obj,
                                  int enabled_lan_total)
{
    const char *reason;

    if (!lan_id || !lan_id[0] || !lan_obj)
        return;
    reason = nc_lan_delete_block_reason(pkg, lan_id, enabled_lan_total);
    json_object_object_add(lan_obj, "deletable", json_object_new_boolean(reason == NULL));
    if (reason)
        json_object_object_add(lan_obj, "delete_blocked_reason",
                               json_object_new_string(reason));
}

struct json_object *jmx_netconfig_lan_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    struct uci_context *lctx = NULL;
    struct uci_package *lpkg = NULL;

    if (jmx_netconfig_db_init() != 0) goto done;
    /* config.db is the write ledger, but uci is what the data plane actually
     * runs. When a LAN is removed outside of the web API (a hand edit of
     * /etc/config/network, which users are forced into while no DELETE route
     * exists) the ledger row survives and this list happily returned a LAN
     * that has no uci section and no bridge -- a ghost whose ports then look
     * claimed by both a LAN and a WAN. Load uci once here so each row can be
     * annotated rather than silently trusted. */
    lctx = uci_alloc_context();
    if (lctx && uci_load(lctx, "network", &lpkg) != UCI_OK)
        lpkg = NULL;
    if (nc_prepare(&st,
        "SELECT id,name,note,ifname,device,mode,parent_lan_id,vlan_id,"
        "mac_clone,speed,duplex,lan_visit,enabled "
        "FROM lan WHERE enabled=1 ORDER BY id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *lid = (const char *)sqlite3_column_text(st, 0);
            struct json_object *l = nc_lan_row_to_json(st);
            nc_lan_load_ports(lid, l);
            nc_lan_load_addresses(lid, l);
            nc_lan_load_dhcp(lid, l);
            nc_lan_load_ipv6(lid, l);
            nc_lan_mark_orphaned(lctx, lpkg, lid, l);
            json_object_array_add(arr, l);
        }
        sqlite3_finalize(st);
    }
done:
    /* Deletability is annotated in a second pass because "is this the last
     * enabled LAN" is a property of the whole set, not of one row, and the
     * query above only knows the total once it has finished. */
    {
        int total = (int)json_object_array_length(arr);
        int i;

        for (i = 0; i < total; i++) {
            struct json_object *l = json_object_array_get_idx(arr, i);

            nc_lan_mark_deletable(lpkg, nc_json_str(l, "id", ""), l, total);
        }
    }
    if (lctx) {
        if (lpkg) uci_unload(lctx, lpkg);
        uci_free_context(lctx);
    }
    json_object_object_add(data, "lans", arr);
    /* Attach capabilities so the UI can render availability up front rather
     * than discovering it from a rejected DELETE. Mirrors wan_list. */
    {
        struct json_object *caps_resp = jmx_netconfig_capabilities();
        if (caps_resp) {
            struct json_object *caps_data = NULL;
            if (json_object_object_get_ex(caps_resp, "data", &caps_data) && caps_data) {
                /* shallow-ref: consumed before caps_resp is freed */
                json_object_get(caps_data);
                json_object_object_add(data, "capabilities", caps_data);
            }
            json_object_put(caps_resp);
        }
    }
    json_object_object_add(data, "runtime_source",
                           json_object_new_string("config_db+uci_network+capabilities"));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_netconfig_lan_get(const char *id)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;

    if (!id || !id[0]) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (jmx_netconfig_db_init() != 0) goto done;
    if (nc_prepare(&st,
        "SELECT id,name,note,ifname,device,mode,parent_lan_id,vlan_id,"
        "mac_clone,speed,duplex,lan_visit,enabled "
        "FROM lan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *l = nc_lan_row_to_json(st);
            nc_lan_load_ports(id, l);
            nc_lan_load_addresses(id, l);
            nc_lan_load_dhcp(id, l);
            nc_lan_load_ipv6(id, l);
            json_object_object_add(data, "lan", l);
        }
        sqlite3_finalize(st);
    }
done:
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int nc_lan_save_addresses(const char *lan_id, struct json_object *lan_json)
{
    sqlite3_stmt *st = NULL;
    struct json_object *addresses = NULL, *extra = NULL;
    const char *ip = nc_json_str(lan_json, "ipaddr", "");
    const char *netmask = nc_json_str(lan_json, "netmask", "255.255.255.0");
    int prefix = nc_json_int(lan_json, "prefix", 24);
    int i, order = 0;

    if (netmask && netmask[0] && strchr(netmask, '.')) {
        struct in_addr a;
        if (inet_pton(AF_INET, netmask, &a) == 1) {
            uint32_t m = ntohl(a.s_addr);
            prefix = 0;
            while (m & 0x80000000U) { prefix++; m <<= 1; }
        }
    }

    if (nc_prepare(&st, "DELETE FROM lan_address WHERE lan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        nc_step_done(st);
        sqlite3_finalize(st);
    }

    json_object_object_get_ex(lan_json, "addresses", &addresses);
    if (addresses && json_object_is_type(addresses, json_type_array)) {
        int n = (int)json_object_array_length(addresses);
        for (i = 0; i < n; i++) {
            struct json_object *a = json_object_array_get_idx(addresses, i);
            const char *aip = nc_json_str(a, "ip", "");
            int aprefix = nc_json_int(a, "prefix", 24);
            int primary = nc_json_bool(a, "primary",
                                       nc_json_bool(a, "is_primary", i == 0));
            char aid[96];
            if (!aip[0]) continue;
            snprintf(aid, sizeof(aid), "%s_%s_%d", lan_id, aip, aprefix);
            if (nc_prepare(&st, "INSERT OR REPLACE INTO lan_address(id,lan_id,ip,prefix,is_primary,sort_order) VALUES(?1,?2,?3,?4,?5,?6)") == 0) {
                sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, aip, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 4, aprefix);
                sqlite3_bind_int(st, 5, primary);
                sqlite3_bind_int(st, 6, order++);
                nc_step_done(st);
                sqlite3_finalize(st);
            }
        }
        return 0;
    }

    if (ip[0]) {
        char aid[96];
        snprintf(aid, sizeof(aid), "%s_%s_%d", lan_id, ip, prefix);
        if (nc_prepare(&st, "INSERT OR REPLACE INTO lan_address(id,lan_id,ip,prefix,is_primary,sort_order) VALUES(?1,?2,?3,?4,1,?5)") == 0) {
            sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 4, prefix);
            sqlite3_bind_int(st, 5, order++);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
    }

    json_object_object_get_ex(lan_json, "extra_ips", &extra);
    if (extra && json_object_is_type(extra, json_type_array)) {
        int n = (int)json_object_array_length(extra);
        for (i = 0; i < n; i++) {
            const char *cidr = json_object_get_string(json_object_array_get_idx(extra, i));
            char ipbuf[64];
            int pfx = 24;
            char *slash;
            char aid[96];
            if (!cidr || !cidr[0]) continue;
            snprintf(ipbuf, sizeof(ipbuf), "%s", cidr);
            slash = strchr(ipbuf, '/');
            if (slash) { *slash = '\0'; pfx = atoi(slash + 1); }
            snprintf(aid, sizeof(aid), "%s_%s_%d", lan_id, ipbuf, pfx);
            if (nc_prepare(&st, "INSERT OR REPLACE INTO lan_address(id,lan_id,ip,prefix,is_primary,sort_order) VALUES(?1,?2,?3,?4,0,?5)") == 0) {
                sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, ipbuf, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 4, pfx);
                sqlite3_bind_int(st, 5, order++);
                nc_step_done(st);
                sqlite3_finalize(st);
            }
        }
    }
    return 0;
}

static int nc_lan_save_dhcp(const char *lan_id, struct json_object *lan_json)
{
    struct json_object *dhcp = NULL;
    if (!json_object_object_get_ex(lan_json, "dhcp", &dhcp) || !dhcp) return 0;
    return nc_dhcp_legacy_set(lan_id, dhcp);
}

static int nc_lan_save_ipv6(const char *lan_id, struct json_object *lan_json)
{
    sqlite3_stmt *st = NULL;
    struct json_object *ipv6 = NULL, *parents = NULL, *dns6 = NULL;
    char *parents_json = NULL, *dns6_json = NULL;
    if (!json_object_object_get_ex(lan_json, "ipv6", &ipv6) || !ipv6) return 0;
    json_object_object_get_ex(ipv6, "parent_wans", &parents);
    if (!parents) json_object_object_get_ex(ipv6, "parent_json", &parents);
    json_object_object_get_ex(ipv6, "dns6", &dns6);
    if (!dns6) json_object_object_get_ex(ipv6, "dns_json", &dns6);
    parents_json = nc_json_array_text_dup(parents, "[]");
    dns6_json = nc_json_array_text_dup(dns6, "[]");
    if (!parents_json || !dns6_json) {
        free(parents_json);
        free(dns6_json);
        return -1;
    }

    if (nc_prepare(&st,
        "INSERT INTO lan_ipv6(lan_id,enabled,parent_wans_json,mode,dhcpv6,static_addr,use_dns6,dns6_json,prefix_len,ra_flags,ra_static,ra_mtu_set,ra_mtu,lease_minutes) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) "
        "ON CONFLICT(lan_id) DO UPDATE SET enabled=excluded.enabled,parent_wans_json=excluded.parent_wans_json,"
        "mode=excluded.mode,dhcpv6=excluded.dhcpv6,static_addr=excluded.static_addr,use_dns6=excluded.use_dns6,"
        "dns6_json=excluded.dns6_json,prefix_len=excluded.prefix_len,ra_flags=excluded.ra_flags,"
        "ra_static=excluded.ra_static,ra_mtu_set=excluded.ra_mtu_set,ra_mtu=excluded.ra_mtu,lease_minutes=excluded.lease_minutes") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool(ipv6, "enabled", 0));
        sqlite3_bind_text(st, 3, parents_json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str(ipv6, "mode", "dhcp"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, nc_json_bool(ipv6, "dhcpv6", 1));
        sqlite3_bind_text(st, 6, nc_json_str(ipv6, "addr", nc_json_str(ipv6, "static_addr", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 7, nc_json_bool(ipv6, "use_dns6", 0));
        sqlite3_bind_text(st, 8, dns6_json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, nc_json_str(ipv6, "prefix_len", "auto"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, nc_json_str(ipv6, "ra_flags", "1"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 11, nc_json_bool(ipv6, "ra_static", 0));
        sqlite3_bind_int(st, 12, nc_json_bool(ipv6, "ra_mtu_set", 0));
        sqlite3_bind_int(st, 13, nc_json_int(ipv6, "ra_mtu", 1480));
        sqlite3_bind_int(st, 14, nc_json_int(ipv6, "leasetime", nc_json_int(ipv6, "lease_minutes", 120)));
        if (nc_step_done(st) != 0) {
            sqlite3_finalize(st);
            free(parents_json);
            free(dns6_json);
            return -1;
        }
        sqlite3_finalize(st);
    } else {
        free(parents_json);
        free(dns6_json);
        return -1;
    }
    free(parents_json);
    free(dns6_json);
    return 0;
}
int jmx_netconfig_lan_set(struct json_object *lan_json)
{
    sqlite3_stmt *st = NULL;
    const char *id;
    int64_t ts = nc_now_s();
    int rc = -1, own_transaction;

    if (!lan_json) return -1;
    id = nc_json_str(lan_json, "id", "");
    if (!nc_uci_section_name_ok(id)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    own_transaction = sqlite3_get_autocommit(g_netconfig_db);
    if (own_transaction && nc_exec("BEGIN IMMEDIATE") != 0) return -1;

    if (nc_prepare(&st,
        "INSERT INTO lan(id,name,note,ifname,device,mode,parent_lan_id,vlan_id,"
        "mac_clone,speed,duplex,lan_visit,enabled,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14) "
        "ON CONFLICT(id) DO UPDATE SET "
        "name=excluded.name,note=excluded.note,ifname=excluded.ifname,device=excluded.device,"
        "mode=excluded.mode,parent_lan_id=excluded.parent_lan_id,vlan_id=excluded.vlan_id,"
        "mac_clone=excluded.mac_clone,speed=excluded.speed,duplex=excluded.duplex,"
        "lan_visit=excluded.lan_visit,enabled=excluded.enabled,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, nc_json_str(lan_json, "name", id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, nc_json_str(lan_json, "note", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str(lan_json, "ifname", id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str(lan_json, "device", "br-lan"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, nc_json_str(lan_json, "mode", "bridge"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, nc_json_str(lan_json, "parent", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, nc_json_str(lan_json, "vlan_id", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, nc_json_str(lan_json, "mac_clone", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, nc_json_str(lan_json, "speed", "0"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, nc_json_str(lan_json, "duplex", "0"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 12, nc_json_bool(lan_json, "lan_visit", 1));
        sqlite3_bind_int(st, 13, nc_json_bool(lan_json, "enabled", 1));
        sqlite3_bind_int64(st, 14, ts);
        if (nc_step_done(st) == 0) rc = 0;
        sqlite3_finalize(st);
    }
    if (rc == 0) {
        struct json_object *ports = NULL;
        if (nc_lan_save_addresses(id, lan_json) != 0 ||
            nc_lan_save_dhcp(id, lan_json) != 0 ||
            nc_lan_save_ipv6(id, lan_json) != 0)
            rc = -1;
        if (json_object_object_get_ex(lan_json, "ports", &ports) && ports && json_object_is_type(ports, json_type_array))
            if (jmx_netconfig_lan_set_ports(id, ports) != 0)
                rc = -1;
    }
    if (own_transaction) {
        if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1;
        if (rc != 0) nc_exec("ROLLBACK");
    }
    return rc;
}

int jmx_netconfig_lan_set_enabled(const char *id, int enabled)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "UPDATE lan SET enabled=?1,updated_at=?2 WHERE id=?3") != 0)
        return -1;
    sqlite3_bind_int(st, 1, enabled ? 1 : 0);
    sqlite3_bind_int64(st, 2, nc_now_s());
    sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) == 0 && sqlite3_changes(g_netconfig_db) > 0)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

int jmx_netconfig_lan_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *uctx = NULL;
    struct uci_package *netpkg = NULL, *dhcppkg = NULL, *firepkg = NULL;
    char bak_network[256] = {0}, bak_dhcp[256] = {0}, bak_firewall[256] = {0};
    char device[96] = {0};
    char firewall_zone[112];
    int delete_device = 0;
    int target_enabled = 0;
    int db_tx = 0;
    int uci_changed = 0;
    int count = 0;
    int rc = -1;

    if (!id || !id[0] || !nc_valid_name(id)) return -1;
    if (!strcmp(id, "lan") || !strcmp(id, "default-lan"))
        return JMX_NETCONFIG_DELETE_PROTECTED;
    if (jmx_netconfig_db_init() != 0) return -1;

    if (nc_prepare(&st, "SELECT device,enabled FROM lan WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return JMX_NETCONFIG_DELETE_NOT_FOUND;
    }
    snprintf(device, sizeof(device), "%s", nc_sql_text(st, 0));
    target_enabled = sqlite3_column_int(st, 1);
    sqlite3_finalize(st);
    st = NULL;

    if (nc_prepare(&st, "SELECT COUNT(*) FROM lan WHERE enabled=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (target_enabled && count <= 1) return JMX_NETCONFIG_DELETE_LAST_LAN;

    if (nc_prepare(&st, "SELECT COUNT(*) FROM lan_port WHERE lan_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    /* Refuse only while the ledger's ports are still really this LAN's. Once
     * the uci interface section is gone the row is a ghost: its "attached"
     * ports have already been taken over by whatever now owns them (a WAN, in
     * the case that produced this fix), and refusing with lan_ports_attached
     * left the user unable to clean it up from the web at all -- they had to
     * hand-edit /etc/config/network. A ghost's port rows get dropped along
     * with it below, so this stays a decision about the data plane rather than
     * about a stale ledger. */
    if (count > 0 && !nc_lan_is_orphaned(id))
        return JMX_NETCONFIG_DELETE_PORTS_ATTACHED;

    if (nc_prepare(&st, "SELECT COUNT(*) FROM lan WHERE parent_lan_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (count > 0) return JMX_NETCONFIG_DELETE_CHILD_LAN;

    if (nc_table_exists("ipam_network") &&
        nc_prepare(&st, "SELECT COUNT(*) FROM ipam_network WHERE id=?1 OR ifname=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (count > 0) return JMX_NETCONFIG_DELETE_IPAM_ATTACHED;
    }

    if (device[0] && nc_prepare(&st,
        "SELECT (SELECT COUNT(*) FROM lan WHERE id<>?1 AND device=?2) + "
        "(SELECT COUNT(*) FROM wan WHERE device=?2 OR ifname=?2)") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, device, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            delete_device = sqlite3_column_int(st, 0) == 0;
        sqlite3_finalize(st);
        st = NULL;
    }

    if (nc_backup_config("network", bak_network, sizeof(bak_network)) != 0 ||
        nc_backup_config("dhcp", bak_dhcp, sizeof(bak_dhcp)) != 0 ||
        nc_backup_config("firewall", bak_firewall, sizeof(bak_firewall)) != 0) {
        rc = JMX_NETCONFIG_DELETE_SNAPSHOT_FAILED;
        goto done;
    }
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    db_tx = 1;

    if (nc_table_exists("dhcp_scope")) {
        if (nc_prepare(&st,
            "DELETE FROM dhcp_option WHERE scope_id IN "
            "(SELECT id FROM dhcp_scope WHERE lan_id=?1)") != 0)
            goto done;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto done;
        sqlite3_finalize(st); st = NULL;
        if (nc_prepare(&st,
            "DELETE FROM dhcp_reservation WHERE scope_id IN "
            "(SELECT id FROM dhcp_scope WHERE lan_id=?1)") != 0)
            goto done;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto done;
        sqlite3_finalize(st); st = NULL;
        if (nc_prepare(&st,
            "DELETE FROM dhcpv6_prefix_reservation WHERE scope_id IN "
            "(SELECT id FROM dhcp_scope WHERE lan_id=?1)") != 0)
            goto done;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto done;
        sqlite3_finalize(st); st = NULL;
        if (nc_prepare(&st, "DELETE FROM dhcp_scope WHERE lan_id=?1") != 0)
            goto done;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) goto done;
        sqlite3_finalize(st); st = NULL;
    }
    {
        const char *tables[] = { "lan_port", "lan_address", "lan_dhcp", "lan_ipv6" };
        size_t i;
        for (i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
            char sql[128];
            snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE lan_id=?1", tables[i]);
            if (nc_prepare(&st, sql) != 0) goto done;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            if (nc_step_done(st) != 0) goto done;
            sqlite3_finalize(st); st = NULL;
        }
    }
    if (nc_prepare(&st,
        "UPDATE physical_port SET owner_type='',owner_id='' "
        "WHERE owner_type='lan' AND owner_id=?1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0) goto done;
    sqlite3_finalize(st); st = NULL;
    if (nc_prepare(&st, "DELETE FROM lan WHERE id=?1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0 || sqlite3_changes(g_netconfig_db) <= 0)
        goto done;
    sqlite3_finalize(st); st = NULL;

    uctx = uci_alloc_context();
    if (!uctx || uci_load(uctx, "network", &netpkg) != UCI_OK ||
        uci_load(uctx, "dhcp", &dhcppkg) != UCI_OK ||
        uci_load(uctx, "firewall", &firepkg) != UCI_OK)
        goto done;
    if (nc_uci_delete_section_pkg(uctx, "network", id) != 0)
        goto done;
    if (delete_device && device[0] &&
        nc_uci_delete_network_device(uctx, netpkg, device) != 0)
        goto done;
    if (nc_uci_delete_section_pkg(uctx, "dhcp", id) != 0)
        goto done;
    snprintf(firewall_zone, sizeof(firewall_zone), "dw_%s", id);
    if (nc_uci_delete_section_pkg(uctx, "firewall", firewall_zone) != 0)
        goto done;
    uci_changed = 1;
    if (jmx_uci_commit(uctx, "network") != UCI_OK ||
        jmx_uci_commit(uctx, "dhcp") != UCI_OK ||
        jmx_uci_commit(uctx, "firewall") != UCI_OK)
        goto done;
    if (nc_reload_network_stack(1, 1, "/tmp/dw-lan-delete-reload.log") != 0)
        goto done;
    if (nc_exec("COMMIT") != 0)
        goto done;
    db_tx = 0;
    rc = 0;

done:
    if (st) sqlite3_finalize(st);
    if (rc != 0) {
        if (db_tx) {
            nc_exec("ROLLBACK");
            db_tx = 0;
        }
        if (uci_changed) {
            nc_restore_config("network", bak_network);
            nc_restore_config("dhcp", bak_dhcp);
            nc_restore_config("firewall", bak_firewall);
            nc_reload_network_stack(1, 1, "/tmp/dw-lan-delete-rollback.log");
        }
    }
    nc_cleanup_backup(bak_network);
    nc_cleanup_backup(bak_dhcp);
    nc_cleanup_backup(bak_firewall);
    if (uctx) uci_free_context(uctx);
    return rc;
}

int jmx_netconfig_lan_set_ports(const char *id, struct json_object *ports_json)
{
    sqlite3_stmt *st = NULL;
    int i, n;
    if (!id || !id[0] || !ports_json) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;

    /* delete existing */
    if (nc_prepare(&st, "DELETE FROM lan_port WHERE lan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        nc_step_done(st);
        sqlite3_finalize(st);
    }

    n = (int)json_object_array_length(ports_json);
    for (i = 0; i < n; i++) {
        const char *port = json_object_get_string(json_object_array_get_idx(ports_json, i));
        char pid[64];
        if (!port || !port[0]) continue;
        snprintf(pid, sizeof(pid), "%s_%s", id, port);
        if (nc_prepare(&st,
            "INSERT OR REPLACE INTO lan_port(id,lan_id,port,label,sort_order) "
            "VALUES(?1,?2,?3,'',?4)") == 0) {
            sqlite3_bind_text(st, 1, pid, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, port, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 4, i);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
    }
    return 0;
}
