    if (!stations || !json_object_is_type(stations, json_type_array) || !ifs)
        return 0;
    for (int i = 0; i < if_count; i++) {
        char cmd[128];
        FILE *fp;
        char line[512];
        struct json_object *cur = NULL;

        if (!ifs[i].ifname[0] || !nc_iface_name_ok(ifs[i].ifname))
            continue;
        snprintf(cmd, sizeof(cmd), "iw dev %s station dump 2>/dev/null", ifs[i].ifname);
        fp = popen(cmd, "r");
        if (!fp)
            continue;
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;

            nc_trim_line(p);
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!strncmp(p, "Station ", 8)) {
                char mac[32] = "";
                sscanf(p + 8, "%31s", mac);
                cur = json_object_new_object();
                json_object_object_add(cur, "mac", json_object_new_string(mac));
                json_object_object_add(cur, "ifname", json_object_new_string(ifs[i].ifname));
                json_object_object_add(cur, "phy", json_object_new_string(ifs[i].phy));
                json_object_object_add(cur, "ssid", json_object_new_string(ifs[i].ssid));
                json_object_object_add(cur, "radioBand", json_object_new_string(nc_wifi_band_from_freq(ifs[i].freq_mhz)));
                json_object_object_add(cur, "channel", json_object_new_int(ifs[i].channel));
                json_object_object_add(cur, "source", json_object_new_string("iw station dump"));
                json_object_array_add(stations, cur);
                total++;
                continue;
            }
            if (!cur)
                continue;
            if (!strncmp(p, "inactive time:", 14)) {
                int v = 0; sscanf(strchr(p, ':') + 1, "%d", &v);
                json_object_object_add(cur, "inactive_ms", json_object_new_int(v));
            } else if (!strncmp(p, "rx bytes:", 9)) {
                long long v = 0; sscanf(strchr(p, ':') + 1, "%lld", &v);
                json_object_object_add(cur, "rx_bytes", json_object_new_int64(v));
            } else if (!strncmp(p, "tx bytes:", 9)) {
                long long v = 0; sscanf(strchr(p, ':') + 1, "%lld", &v);
                json_object_object_add(cur, "tx_bytes", json_object_new_int64(v));
            } else if (!strncmp(p, "signal:", 7)) {
                int v = 0; sscanf(strchr(p, ':') + 1, "%d", &v);
                json_object_object_add(cur, "signal", json_object_new_int(v));
                json_object_object_add(cur, "rssi", json_object_new_int(v));
            } else if (!strncmp(p, "rx bitrate:", 11)) {
                char val[128] = ""; snprintf(val, sizeof(val), "%s", strchr(p, ':') ? strchr(p, ':') + 1 : ""); nc_trim_line(val);
                json_object_object_add(cur, "rx_bitrate", json_object_new_string(val));
            } else if (!strncmp(p, "tx bitrate:", 11)) {
                char val[128] = ""; snprintf(val, sizeof(val), "%s", strchr(p, ':') ? strchr(p, ':') + 1 : ""); nc_trim_line(val);
                json_object_object_add(cur, "tx_bitrate", json_object_new_string(val));
            }
        }
        pclose(fp);
    }
    return total;
}

static void nc_wifi_status_attach_runtime(struct json_object *data)
{
    struct json_object *runtime = json_object_new_object();
    struct json_object *interfaces = json_object_new_array();
    struct json_object *runtime_radios = json_object_new_array();
    struct json_object *stations = json_object_new_array();
    struct json_object *summary = json_object_new_object();
    struct json_object *cap = NULL;
    struct json_object *radios = NULL;
    struct nc_wifi_if_runtime ifs[32];
    int if_count = 0;
    int phy_count = nc_wifi_phy_count();
    int iw_available = nc_wifi_exec_available("iw");
    int iwinfo_available = nc_wifi_exec_available("iwinfo");
    int station_count = 0;
    int avg_signal = 0;
    int signal_sum = 0;
    int signal_samples = 0;

    if (!data)
        return;
    nc_wifi_runtime_add_phy_radios(runtime_radios);
    if (iw_available)
        nc_wifi_parse_iw_dev_interfaces(interfaces, ifs, &if_count, 32);
    station_count = iw_available ? nc_wifi_runtime_add_stations(stations, ifs, if_count) : 0;
    for (int i = 0; i < station_count; i++) {
        struct json_object *st = json_object_array_get_idx(stations, i);
        struct json_object *sig = NULL;
        if (st && json_object_object_get_ex(st, "signal", &sig) && sig) {
            signal_sum += json_object_get_int(sig);
            signal_samples++;
        }
    }
    if (signal_samples > 0)
        avg_signal = signal_sum / signal_samples;

    json_object_object_add(runtime, "supported", json_object_new_boolean(phy_count > 0 || if_count > 0));
    json_object_object_add(runtime, "available", json_object_new_boolean(iw_available && (phy_count > 0 || if_count > 0)));
    json_object_object_add(runtime, "phy_count", json_object_new_int(phy_count));
    json_object_object_add(runtime, "interface_count", json_object_new_int(if_count));
    json_object_object_add(runtime, "station_count", json_object_new_int(station_count));
    json_object_object_add(runtime, "iw_available", json_object_new_boolean(iw_available));
    json_object_object_add(runtime, "iwinfo_available", json_object_new_boolean(iwinfo_available));
    json_object_object_add(runtime, "radio_source", json_object_new_string("/sys/class/ieee80211"));
    json_object_object_add(runtime, "interface_source", json_object_new_string("iw dev"));
    /* Report the source that actually produced stations. Naming a tool that
     * returned nothing reads as "the source works and there are no clients",
     * which is the misreading this field caused on QCA drivers. When `iw` runs
     * but yields no stations, the source is unresolved, not confirmed. */
    json_object_object_add(runtime, "station_source",
        station_count > 0 ? json_object_new_string("iw station dump") :
                            json_object_new_null());
    json_object_object_add(runtime, "station_source_attempted",
                           json_object_new_string("iw station dump"));
    json_object_object_add(runtime, "complete", json_object_new_boolean(phy_count > 0 && iw_available));
    json_object_object_add(runtime, "reason", json_object_new_string(
        phy_count <= 0 ? "no_phy_detected" :
        (!iw_available ? "iw_unavailable" :
         (station_count > 0 ? "iw_runtime_station_mapping_available" :
                             "iw_station_dump_returned_no_stations"))));
    json_object_object_add(runtime, "interfaces", interfaces);
    json_object_object_add(runtime, "radios", json_object_get(runtime_radios));

    json_object_object_add(summary, "clients", json_object_new_int(station_count));
    json_object_object_add(summary, "station_count", json_object_new_int(station_count));
    json_object_object_add(summary, "interface_count", json_object_new_int(if_count));
    json_object_object_add(summary, "phy_count", json_object_new_int(phy_count));
    json_object_object_add(summary, "avg_signal", signal_samples > 0 ? json_object_new_int(avg_signal) : json_object_new_null());
    /* These three need channel-survey evidence this chain never collects.
     * A literal 0 reads as "measured zero utilization"; null plus a reason
     * says "not measured", which is the truth here. */
    json_object_object_add(summary, "avg_utilization", json_object_new_null());
    json_object_object_add(summary, "avg_retry_rate", json_object_new_null());
    json_object_object_add(summary, "worst_noise", json_object_new_null());
    json_object_object_add(summary, "airtime_reason",
                           json_object_new_string("local_survey_source_unavailable"));
    json_object_object_add(summary, "source", json_object_new_string("iw_runtime+config_db"));

    json_object_object_add(data, "summary", summary);
    json_object_object_add(data, "stations", stations);
    json_object_object_add(data, "runtime", runtime);
    json_object_object_add(data, "runtime_radios", runtime_radios);
    json_object_object_add(data, "interference", json_object_new_array());

    if (json_object_object_get_ex(data, "capabilities", &cap) && cap &&
        json_object_is_type(cap, json_type_object)) {
        json_object_object_add(cap, "runtime_status", json_object_new_boolean(1));
        json_object_object_add(cap, "runtime_station_mapping", json_object_new_boolean(iw_available));
        json_object_object_add(cap, "radio_runtime", json_object_new_boolean(phy_count > 0));
        json_object_object_add(cap, "ap_radio_mapping", json_object_new_boolean(iw_available && station_count > 0));
        json_object_object_add(cap, "runtime_reason", json_object_new_string(
            phy_count <= 0 ? "no_phy_detected" :
            (!iw_available ? "iw_unavailable" : "iw_runtime_station_mapping_available")));
    }

    if (nc_wifi_json_array_len_obj(data, "radios") == 0 &&
        json_object_object_get_ex(data, "radios", &radios) && radios &&
        json_object_is_type(radios, json_type_array)) {
        for (int i = 0; i < (int)json_object_array_length(runtime_radios); i++)
            json_object_array_add(radios, json_object_get(json_object_array_get_idx(runtime_radios, i)));
    }
}

struct json_object *jmx_wifi_status_get(void)
{
    struct json_object *resp = jmx_wifi_config_get();
    struct json_object *data = NULL;

    if (json_object_object_get_ex(resp, "data", &data) && data)
        nc_wifi_status_attach_runtime(data);
    return resp;
}

struct json_object *jmx_wifi_scan(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    (void)cfg;
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    json_object_object_add(d, "contract_version", json_object_new_string("wifi-scan.v1"));
    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(d, "capability", json_object_new_string("scan_jobs"));
    json_object_object_add(d, "supported", json_object_new_boolean(0));
    json_object_object_add(d, "invoked", json_object_new_boolean(0));
    json_object_object_add(d, "reason", json_object_new_string("asynchronous_job_lifecycle_pending"));
    json_object_object_add(d, "neighbors", arr);
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

/* ── Advanced Routing / Policy Route ─────────────────────────────────── */
static void nc_adv_route_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS advanced_routing_global (id INTEGER PRIMARY KEY CHECK (id = 1),enabled INTEGER NOT NULL DEFAULT 1,engine TEXT NOT NULL DEFAULT 'sqlite -> uci network + ip rule + nft set',apply_state TEXT NOT NULL DEFAULT 'draft',last_apply_at INTEGER NOT NULL DEFAULT 0,default_table TEXT NOT NULL DEFAULT 'main',object_revision INTEGER NOT NULL DEFAULT 0,health_aware INTEGER NOT NULL DEFAULT 1,log_policy_hits INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS route_table (id TEXT PRIMARY KEY,name TEXT NOT NULL,table_id INTEGER NOT NULL UNIQUE,role TEXT NOT NULL DEFAULT '',gateway TEXT NOT NULL DEFAULT '',metric INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS static_route (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL,family TEXT NOT NULL DEFAULT 'ipv4',destination TEXT NOT NULL,gateway TEXT NOT NULL DEFAULT '',interface TEXT NOT NULL DEFAULT '',route_table TEXT NOT NULL DEFAULT 'main',metric INTEGER NOT NULL DEFAULT 0,mtu INTEGER NOT NULL DEFAULT 1500,route_type TEXT NOT NULL DEFAULT 'unicast',comment TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS route_object (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL UNIQUE,object_type TEXT NOT NULL,family TEXT NOT NULL DEFAULT 'mixed',value TEXT NOT NULL DEFAULT '',comment TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS route_object_member (id INTEGER PRIMARY KEY AUTOINCREMENT,object_id TEXT NOT NULL,value TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',sort_order INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS cross_l3_service (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL,service_type TEXT NOT NULL DEFAULT 'snmp',server_ip TEXT NOT NULL DEFAULT '',scope TEXT NOT NULL DEFAULT '',listen_port TEXT NOT NULL DEFAULT '161',version TEXT NOT NULL DEFAULT 'V2',access_rate TEXT NOT NULL DEFAULT '',remark TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS policy_route_rule (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,priority INTEGER NOT NULL,name TEXT NOT NULL,source_object TEXT NOT NULL DEFAULT '',dest_object TEXT NOT NULL DEFAULT '',proto TEXT NOT NULL DEFAULT 'all',ports TEXT NOT NULL DEFAULT 'any',action TEXT NOT NULL DEFAULT 'route_table',target TEXT NOT NULL DEFAULT '',route_table TEXT NOT NULL DEFAULT '',schedule TEXT NOT NULL DEFAULT 'always',sticky INTEGER NOT NULL DEFAULT 1,comment TEXT NOT NULL DEFAULT '',hit_count INTEGER NOT NULL DEFAULT 0,last_hit INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS policy_route_hit_sample (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,rule_id TEXT NOT NULL,client TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT '',destination TEXT NOT NULL DEFAULT '',app TEXT NOT NULL DEFAULT '',route_table TEXT NOT NULL DEFAULT '',action TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',bytes INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE VIEW IF NOT EXISTS policy_table_index AS SELECT id, enabled, 'static' AS policy_type, '静态路由' AS type_label, name, destination || ' · ' || interface AS scope, gateway || ' · ' || route_table AS target, '高级路由' AS owner, comment, updated_at FROM static_route UNION ALL SELECT id, enabled, 'pbr' AS policy_type, '策略路由' AS type_label, name, source_object || ' -> ' || dest_object AS scope, action || ' · ' || target AS target, '高级路由' AS owner, comment, updated_at FROM policy_route_rule UNION ALL SELECT id, enabled, 'cross' AS policy_type, '跨三层服务' AS type_label, name, server_ip || ' · ' || scope AS scope, service_type || ' · ' || listen_port AS target, '高级路由' AS owner, remark AS comment, updated_at FROM cross_l3_service");
    nc_exec("INSERT OR IGNORE INTO advanced_routing_global(id) VALUES(1)");
    /*
     * PBR source dimension beyond "a group of IPs".
     *
     * The table shipped with source_object only, which is a route_object
     * reference, so the source side could never say "everything arriving on
     * lan2". These three columns add that without touching source_object, so
     * existing rows keep their meaning and keep being read by the old path:
     *
     *   source_kind  object (default, = legacy source_object) | interface |
     *                zone | network
     *   source_ref   the interface name, zone name or network name that
     *                source_kind selects. Ignored when source_kind=object.
     *   pin_wan      1 = this rule pins its flows to its own target and must
     *                not be re-spread by multi-WAN load balancing. See
     *                nc_adv_generate_runtime() for how that is enforced.
     */
    nc_add_column_if_missing("policy_route_rule", "source_kind",
                             "TEXT NOT NULL DEFAULT 'object'");
    nc_add_column_if_missing("policy_route_rule", "source_ref",
                             "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("policy_route_rule", "pin_wan",
                             "INTEGER NOT NULL DEFAULT 0");
}

static int nc_adv_id_ok(const char *s){return nc_valid_name(s);}
static int nc_adv_family_ok(const char*s){return s&&(!strcmp(s,"ipv4")||!strcmp(s,"ipv6")||!strcmp(s,"mixed"));}
static int nc_adv_table_id_ok(int id){return id>0 && id<32768 && id!=255 && id!=254 && id!=253;}

#define NC_ADV_MAX_ITEMS 512

static int nc_adv_text_ok(const char *text, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)(text ? text : "");

    if (strlen((const char *)p) > max_len)
        return 0;
    for (; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int nc_adv_ip_cidr_ok(const char *text, int family, int allow_empty)
{
    char copy[INET6_ADDRSTRLEN + 5];
    char *slash;
    char *end = NULL;
    long prefix;
    struct in_addr addr4;
    struct in6_addr addr6;

    if (!text || !text[0])
        return allow_empty;
    if (!strcmp(text, "default"))
        return 1;
    if (strlen(text) >= sizeof(copy))
        return 0;
    snprintf(copy, sizeof(copy), "%s", text);
    slash = strchr(copy, '/');
    if (slash) {
        *slash++ = '\0';
        if (!*slash || strchr(slash, '/'))
            return 0;
        errno = 0;
        prefix = strtol(slash, &end, 10);
        if (errno || !end || *end || prefix < 0 ||
            prefix > (family == AF_INET6 ? 128 : 32))
            return 0;
    }
    return family == AF_INET6 ? inet_pton(AF_INET6, copy, &addr6) == 1 :
                               inet_pton(AF_INET, copy, &addr4) == 1;
}

static int nc_adv_ifname_ok(const char *ifname, int require_runtime)
{
    if (!ifname || !ifname[0])
        return 1;
    if (!nc_physical_port_ifname_strict_ok(ifname))
        return 0;
    return !require_runtime || if_nametoindex(ifname) > 0;
}

static int nc_adv_route_type_ok(const char *type)
{
    return type && !strcmp(type, "unicast");
}

static int nc_adv_proto_ok(const char *proto)
{
    return proto && (!strcmp(proto, "all") || !strcmp(proto, "tcp") ||
                     !strcmp(proto, "udp"));
}

static int nc_adv_table_ref_ok(const char *table)
{
    return table && (!strcmp(table, "main") || !strcmp(table, "default") ||
                     !strcmp(table, "local") || nc_adv_id_ok(table));
}

static int nc_adv_object_value_ok(const char *value)
{
    return nc_adv_ip_cidr_ok(value, AF_INET, 0);
}

static int nc_adv_source_kind_ok(const char *kind)
{
    return kind && (!strcmp(kind, "object") || !strcmp(kind, "interface") ||
                    !strcmp(kind, "zone") || !strcmp(kind, "network"));
}

/*
 * Resolve a PBR source into the list of inbound devices it matches.
 *
 * interface: taken as a device name directly (br-lan2), or as a network name
 *            whose device is looked up, because the UI shows users network
 *            names while nft needs the device.
 * network:   network name -> lan.device.
 * zone:      firewall_zone.networks is a CSV of network names; each is resolved
 *            to its device. One zone can therefore yield several devices.
 *
 * Returns the number of devices written, or -1 on error. A return of 0 means
 * the source named nothing that exists, which callers must treat as a failure
 * rather than as "matches everything" -- an unresolved source that silently
 * became a match-all rule would route traffic the operator never asked for.
 */
static int nc_adv_network_device(const char *network, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!network || !network[0] || !out || !out_len)
        return -1;
    out[0] = '\0';
    if (nc_prepare(&st,
        "SELECT device FROM lan WHERE (id=?1 OR name=?1) AND enabled=1") != 0)
        return -1;
    if (sqlite3_bind_text(st, 1, network, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *dev = (const char *)sqlite3_column_text(st, 0);
        if (dev && dev[0]) {
            snprintf(out, out_len, "%s", dev);
            found = 1;
        }
    }
    sqlite3_finalize(st);
    return found;
}

#define NC_ADV_MAX_SRC_DEVS 8

static int nc_adv_resolve_source_devices(const char *kind, const char *ref,
                                         char devs[][32], int max_devs)
{
    int count = 0;

    if (!kind || !ref || !ref[0] || !devs || max_devs <= 0)
        return -1;

    if (!strcmp(kind, "interface")) {
        char dev[32] = "";

        /* A device name is accepted as-is; otherwise treat it as a network. */
        if (nc_physical_port_ifname_strict_ok(ref) &&
            if_nametoindex(ref) > 0) {
            snprintf(devs[count++], 32, "%s", ref);
            return count;
        }
        if (nc_adv_network_device(ref, dev, sizeof(dev)) == 1 &&
            nc_physical_port_ifname_strict_ok(dev)) {
            snprintf(devs[count++], 32, "%s", dev);
            return count;
        }
        return 0;
    }

    if (!strcmp(kind, "network")) {
        char dev[32] = "";

        if (nc_adv_network_device(ref, dev, sizeof(dev)) == 1 &&
            nc_physical_port_ifname_strict_ok(dev)) {
            snprintf(devs[count++], 32, "%s", dev);
            return count;
        }
        return 0;
    }

    if (!strcmp(kind, "zone")) {
        sqlite3_stmt *st = NULL;
        char networks[512] = "";
        char *save = NULL;
        char *tok;

        if (nc_prepare(&st,
            "SELECT networks FROM firewall_zone WHERE (id=?1 OR name=?1) "
            "AND enabled=1") != 0)
            return -1;
        if (sqlite3_bind_text(st, 1, ref, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
            sqlite3_finalize(st);
            return -1;
        }
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *csv = (const char *)sqlite3_column_text(st, 0);
            if (csv)
                snprintf(networks, sizeof(networks), "%s", csv);
        }
        sqlite3_finalize(st);
        if (!networks[0])
            return 0;
        for (tok = strtok_r(networks, ", \t", &save); tok && count < max_devs;
             tok = strtok_r(NULL, ", \t", &save)) {
            char dev[32] = "";
            int i;
            int dup = 0;

            if (nc_adv_network_device(tok, dev, sizeof(dev)) != 1 ||
                !nc_physical_port_ifname_strict_ok(dev))
                continue;
            for (i = 0; i < count; i++)
                if (!strcmp(devs[i], dev))
                    dup = 1;
            if (!dup)
                snprintf(devs[count++], 32, "%s", dev);
        }
        return count;
    }

    return -1;
}

static int nc_adv_validate_array(struct json_object *arr)
{
    int count;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return -1;
    count = json_object_array_length(arr);
    if (count < 0 || count > NC_ADV_MAX_ITEMS)
        return -1;
    for (int i = 0; i < count; i++)
        if (!json_object_array_get_idx(arr, i) ||
            !json_object_is_type(json_object_array_get_idx(arr, i), json_type_object))
            return -1;
    return 0;
}

static int nc_adv_validate_config(struct json_object *cfg, int require_runtime_ifname)
{
    static const char *array_keys[] = {
        "tables", "static_routes", "route_objects", "cross_services",
        "policy_rules", NULL
    };
    struct json_object *arr = NULL;
    struct json_object *global = NULL;
    int total = 0;

    if (!cfg || !json_object_is_type(cfg, json_type_object))
        return -1;
    if (json_object_object_get_ex(cfg, "global", &global) &&
        (!global || !json_object_is_type(global, json_type_object)))
        return -1;
    if (global && !nc_adv_table_ref_ok(
            nc_json_str_def(global, "default_table", "main")))
        return -1;
    for (int k = 0; array_keys[k]; k++) {
        if (!json_object_object_get_ex(cfg, array_keys[k], &arr))
            continue;
        if (nc_adv_validate_array(arr) != 0)
            return -1;
        total += json_object_array_length(arr);
        if (total > NC_ADV_MAX_ITEMS)
            return -1;
    }
    if (json_object_object_get_ex(cfg, "tables", &arr)) {
        for (int i = 0; i < json_object_array_length(arr); i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id = nc_json_str_def(o, "id", "");
            const char *gateway = nc_json_str_def(o, "gateway", "");
            if (!nc_adv_id_ok(id) ||
                !nc_adv_table_id_ok(nc_json_int_def(o, "table_id", 0)) ||
                !nc_adv_text_ok(nc_json_str_def(o, "name", id), 128) ||
                !nc_adv_ip_cidr_ok(gateway, AF_INET, 1))
                return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "static_routes", &arr)) {
        for (int i = 0; i < json_object_array_length(arr); i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id = nc_json_str_def(o, "id", "");
            const char *family = nc_json_str_def(o, "family", "ipv4");
            const char *gateway = nc_json_str_def(o, "gateway", "");
            const char *ifname = nc_json_str_def(o, "interface", "");
            const char *table = nc_json_str_def(o, "table",
                nc_json_str_def(o, "route_table", "main"));
            const char *type = nc_json_str_def(o, "type",
                nc_json_str_def(o, "route_type", "unicast"));
            int af = !strcmp(family, "ipv6") ? AF_INET6 : AF_INET;
            int metric = nc_json_int_def(o, "metric", 0);
            int mtu = nc_json_int_def(o, "mtu", 1500);

            if (!nc_adv_id_ok(id) ||
                (strcmp(family, "ipv4") && strcmp(family, "ipv6")) ||
                !nc_adv_ip_cidr_ok(nc_json_str_def(o, "destination", ""), af, 0) ||
                !nc_adv_ip_cidr_ok(gateway, af, 1) ||
                !nc_adv_ifname_ok(ifname, require_runtime_ifname) ||
                !nc_adv_table_ref_ok(table) || !nc_adv_route_type_ok(type) ||
                metric < 0 || metric > 1000000 || mtu < 576 || mtu > 65535 ||
                !nc_adv_text_ok(nc_json_str_def(o, "name", id), 128) ||
                !nc_adv_text_ok(nc_json_str_def(o, "comment", ""), 512))
                return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "route_objects", &arr)) {
        for (int i = 0; i < json_object_array_length(arr); i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            struct json_object *members = NULL;
            const char *id = nc_json_str_def(o, "id", "");
            const char *family = nc_json_str_def(o, "family", "ipv4");
            const char *type = nc_json_str_def(o, "type",
                nc_json_str_def(o, "object_type", "ip_group"));
            const char *value = nc_json_str_def(o, "value", "");

            if (!nc_adv_id_ok(id) || strcmp(type, "ip_group") ||
                strcmp(family, "ipv4") ||
                !nc_adv_text_ok(nc_json_str_def(o, "name", id), 128) ||
                (value[0] && !nc_adv_object_value_ok(value)))
                return -1;
            if (json_object_object_get_ex(o, "members", &members)) {
                if (!members || !json_object_is_type(members, json_type_array) ||
                    json_object_array_length(members) > NC_ADV_MAX_ITEMS)
                    return -1;
                for (int j = 0; j < json_object_array_length(members); j++) {
                    struct json_object *member = json_object_array_get_idx(members, j);
                    if (!member || !json_object_is_type(member, json_type_string) ||
                        !nc_adv_object_value_ok(json_object_get_string(member)))
                        return -1;
                }
            }
        }
    }
    if (json_object_object_get_ex(cfg, "policy_rules", &arr)) {
        for (int i = 0; i < json_object_array_length(arr); i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *id = nc_json_str_def(o, "id", "");
            const char *proto = nc_json_str_def(o, "proto", "all");
            const char *ports = nc_json_str_def(o, "ports", "any");
            const char *action = nc_json_str_def(o, "action", "route_table");
            const char *source = nc_json_str_def(o, "source_object", "");
            const char *destination = nc_json_str_def(o, "dest_object", "");
            const char *source_kind = nc_json_str_def(o, "source_kind", "object");
            const char *source_ref = nc_json_str_def(o, "source_ref", "");
            const char *table = nc_json_str_def(o, "table",
                nc_json_str_def(o, "route_table", nc_json_str_def(o, "target", "")));
            int priority = nc_json_int_def(o, "priority", 1000 + i);

            if (!nc_adv_id_ok(id) || (source[0] && !nc_adv_id_ok(source)) ||
                (destination[0] && !nc_adv_id_ok(destination)) ||
                !nc_adv_source_kind_ok(source_kind) ||
                (strcmp(source_kind, "object") &&
                 (!source_ref[0] || !nc_adv_id_ok(source_ref))) ||
                !nc_adv_proto_ok(proto) ||
                !nc_fw_port_expr_ok(ports) || strcmp(action, "route_table") ||
                !nc_adv_table_ref_ok(table) || !strcmp(table, "local") ||
                strcmp(nc_json_str_def(o, "schedule", "always"), "always") ||
                priority < 0 || priority > 1000000 ||
                !nc_adv_text_ok(nc_json_str_def(o, "name", id), 128) ||
                !nc_adv_text_ok(nc_json_str_def(o, "comment", ""), 512))
                return -1;
        }
    }
    return 0;
}

static char *nc_adv_array_text(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v=NULL; if(json_object_object_get_ex(o,key,&v)&&v&&json_object_is_type(v,json_type_array)) return nc_json_array_to_string(v,def); return strdup(nc_json_str_def(o,key,def));
}

static void nc_adv_add_table_json(struct json_object *arr)
{
    sqlite3_stmt*st=NULL; if(nc_prepare(&st,"SELECT t.id,t.name,t.table_id,t.role,t.gateway,t.metric,t.enabled,COUNT(sr.id) FROM route_table t LEFT JOIN static_route sr ON sr.route_table=t.id GROUP BY t.id ORDER BY t.table_id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);json_object_object_add(o,"table_id",json_object_new_int(sqlite3_column_int(st,2)));nc_add_text(o,"role",st,3);nc_add_text(o,"gateway",st,4);json_object_object_add(o,"metric",json_object_new_int(sqlite3_column_int(st,5)));json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,6)));json_object_object_add(o,"routes",json_object_new_int(sqlite3_column_int(st,7)));json_object_array_add(arr,o);}sqlite3_finalize(st);} }
static void nc_adv_add_static_routes_json(struct json_object *arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,enabled,name,family,destination,gateway,interface,route_table,metric,mtu,route_type,comment,updated_at FROM static_route ORDER BY metric,id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"family",st,3);nc_add_text(o,"destination",st,4);nc_add_text(o,"gateway",st,5);nc_add_text(o,"interface",st,6);nc_add_text(o,"table",st,7);json_object_object_add(o,"metric",json_object_new_int(sqlite3_column_int(st,8)));json_object_object_add(o,"mtu",json_object_new_int(sqlite3_column_int(st,9)));nc_add_text(o,"type",st,10);nc_add_text(o,"comment",st,11);json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,12)));json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_adv_add_objects_json(struct json_object *arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT o.id,o.enabled,o.name,o.object_type,o.family,o.value,o.comment,o.updated_at,COUNT(m.id) FROM route_object o LEFT JOIN route_object_member m ON m.object_id=o.id GROUP BY o.id ORDER BY o.name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();const char*oid=(const char*)sqlite3_column_text(st,0);nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"type",st,3);nc_add_text(o,"family",st,4);nc_add_text(o,"value",st,5);nc_add_text(o,"comment",st,6);json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,7)));json_object_object_add(o,"ref_count",json_object_new_int(0));json_object_object_add(o,"hit_count",json_object_new_int(0));struct json_object*ma=json_object_new_array();sqlite3_stmt*ms=NULL;if(nc_prepare(&ms,"SELECT label,value FROM route_object_member WHERE object_id=? ORDER BY sort_order,id")==0){sqlite3_bind_text(ms,1,oid,-1,SQLITE_TRANSIENT);while(sqlite3_step(ms)==SQLITE_ROW){const char*l=(const char*)sqlite3_column_text(ms,0);const char*v=(const char*)sqlite3_column_text(ms,1);json_object_array_add(ma,json_object_new_string((l&&l[0])?l:(v?v:"")));}sqlite3_finalize(ms);}json_object_object_add(o,"members",ma);json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_adv_add_cross_json(struct json_object *arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,enabled,name,service_type,server_ip,scope,listen_port,version,access_rate,remark,updated_at FROM cross_l3_service ORDER BY name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"service_type",st,3);nc_add_text(o,"server_ip",st,4);nc_add_text(o,"scope",st,5);nc_add_text(o,"listen_port",st,6);nc_add_text(o,"version",st,7);nc_add_text(o,"access_rate",st,8);nc_add_text(o,"remark",st,9);json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,10)));json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_adv_add_rules_json(struct json_object *arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,enabled,priority,name,source_object,dest_object,proto,ports,action,target,route_table,schedule,sticky,comment,hit_count,last_hit,updated_at,source_kind,source_ref,pin_wan FROM policy_route_rule ORDER BY priority,id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));json_object_object_add(o,"priority",json_object_new_int(sqlite3_column_int(st,2)));nc_add_text(o,"name",st,3);nc_add_text(o,"source_object",st,4);nc_add_text(o,"dest_object",st,5);nc_add_text(o,"proto",st,6);nc_add_text(o,"ports",st,7);nc_add_text(o,"action",st,8);nc_add_text(o,"target",st,9);nc_add_text(o,"table",st,10);nc_add_text(o,"schedule",st,11);json_object_object_add(o,"sticky",json_object_new_boolean(sqlite3_column_int(st,12)));nc_add_text(o,"comment",st,13);json_object_object_add(o,"hit_count",json_object_new_int64(sqlite3_column_int64(st,14)));json_object_object_add(o,"last_hit",json_object_new_int64(sqlite3_column_int64(st,15)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,16)));nc_add_text(o,"source_kind",st,17);nc_add_text(o,"source_ref",st,18);json_object_object_add(o,"pin_wan",json_object_new_boolean(sqlite3_column_int(st,19)));json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_adv_add_hits_json(struct json_object *arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT h.id,h.ts,COALESCE(r.name,h.rule_id),h.client,h.source,h.destination,h.app,h.route_table,h.action,h.reason,h.bytes FROM policy_route_hit_sample h LEFT JOIN policy_route_rule r ON r.id=h.rule_id ORDER BY h.ts DESC LIMIT 200")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();char id[64];snprintf(id,sizeof(id),"hit-%d",sqlite3_column_int(st,0));json_object_object_add(o,"id",json_object_new_string(id));json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,1)));nc_add_text(o,"rule",st,2);nc_add_text(o,"client",st,3);nc_add_text(o,"source",st,4);nc_add_text(o,"destination",st,5);nc_add_text(o,"app",st,6);nc_add_text(o,"table",st,7);nc_add_text(o,"action",st,8);nc_add_text(o,"reason",st,9);json_object_object_add(o,"bytes",json_object_new_int64(sqlite3_column_int64(st,10)));json_object_array_add(arr,o);}sqlite3_finalize(st);}}

struct json_object *jmx_advanced_routing_get(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_adv_route_db_init(); struct json_object*d=json_object_new_object(); json_object_object_add(d,"ts",json_object_new_int64(nc_now_s())); sqlite3_stmt*st=NULL;
    if(nc_prepare(&st,"SELECT enabled,engine,apply_state,last_apply_at,default_table,object_revision,health_aware,log_policy_hits FROM advanced_routing_global WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){struct json_object*g=json_object_new_object();json_object_object_add(g,"enabled",json_object_new_boolean(sqlite3_column_int(st,0)));nc_add_text(g,"engine",st,1);nc_add_text(g,"apply_state",st,2);json_object_object_add(g,"last_apply_at",json_object_new_int64(sqlite3_column_int64(st,3)));nc_add_text(g,"default_table",st,4);json_object_object_add(g,"object_revision",json_object_new_int(sqlite3_column_int(st,5)));json_object_object_add(g,"health_aware",json_object_new_boolean(sqlite3_column_int(st,6)));json_object_object_add(g,"log_policy_hits",json_object_new_boolean(sqlite3_column_int(st,7)));json_object_object_add(d,"global",g);sqlite3_finalize(st);} struct json_object*a=json_object_new_array();nc_adv_add_table_json(a);json_object_object_add(d,"tables",a);a=json_object_new_array();nc_adv_add_static_routes_json(a);json_object_object_add(d,"static_routes",a);a=json_object_new_array();nc_adv_add_objects_json(a);json_object_object_add(d,"route_objects",a);a=json_object_new_array();nc_adv_add_cross_json(a);json_object_object_add(d,"cross_services",a);a=json_object_new_array();nc_adv_add_rules_json(a);json_object_object_add(d,"policy_rules",a);json_object_object_add(d,"external_policies",json_object_new_array());a=json_object_new_array();nc_adv_add_hits_json(a);json_object_object_add(d,"rule_hits",a);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

static int nc_adv_statement_done(sqlite3_stmt *st, int bind_rc)
{
    int rc = bind_rc;
    if (!st)
        return -1;
    if (rc == 0 && nc_step_done(st) != 0)
        rc = -1;
    if (sqlite3_finalize(st) != SQLITE_OK)
        rc = -1;
    return rc;
}

static int nc_adv_set_global(struct json_object *g)
{
    sqlite3_stmt *st = NULL;
    int rc;
    if (!g) return 0;
    if (nc_prepare(&st, "UPDATE advanced_routing_global SET enabled=?1,default_table=?2,health_aware=?3,log_policy_hits=?4,updated_at=?5 WHERE id=1") != 0)
        return -1;
    rc = nc_fw_bind_int(st, 1, nc_json_bool_def(g, "enabled", 1)) ||
         nc_fw_bind_text(st, 2, nc_json_str_def(g, "default_table", "main")) ||
         nc_fw_bind_int(st, 3, nc_json_bool_def(g, "health_aware", 1)) ||
         nc_fw_bind_int(st, 4, nc_json_bool_def(g, "log_policy_hits", 1)) ||
         nc_fw_bind_int64(st, 5, nc_now_s());
    return nc_adv_statement_done(st, rc ? -1 : 0);
}

static int nc_adv_set_tables(struct json_object *arr)
{
    for (int i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        sqlite3_stmt *st = NULL;
        const char *id = nc_json_str_def(o, "id", "");
        int rc;
        if (nc_prepare(&st, "INSERT OR REPLACE INTO route_table(id,name,table_id,role,gateway,metric,enabled,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)") != 0)
            return -1;
        rc = nc_fw_bind_text(st, 1, id) || nc_fw_bind_text(st, 2, nc_json_str_def(o, "name", id)) ||
             nc_fw_bind_int(st, 3, nc_json_int_def(o, "table_id", 0)) || nc_fw_bind_text(st, 4, nc_json_str_def(o, "role", "")) ||
             nc_fw_bind_text(st, 5, nc_json_str_def(o, "gateway", "")) || nc_fw_bind_int(st, 6, nc_json_int_def(o, "metric", 0)) ||
             nc_fw_bind_int(st, 7, nc_json_bool_def(o, "enabled", 1)) || nc_fw_bind_int64(st, 8, nc_now_s());
        if (nc_adv_statement_done(st, rc ? -1 : 0) != 0) return -1;
    }
    return 0;
}

static int nc_adv_set_static_routes(struct json_object *arr)
{
    for (int i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        sqlite3_stmt *st = NULL;
        const char *id = nc_json_str_def(o, "id", "");
        int rc;
        if (nc_prepare(&st, "INSERT OR REPLACE INTO static_route(id,enabled,name,family,destination,gateway,interface,route_table,metric,mtu,route_type,comment,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)") != 0)
            return -1;
        rc = nc_fw_bind_text(st,1,id) || nc_fw_bind_int(st,2,nc_json_bool_def(o,"enabled",1)) ||
             nc_fw_bind_text(st,3,nc_json_str_def(o,"name",id)) || nc_fw_bind_text(st,4,nc_json_str_def(o,"family","ipv4")) ||
             nc_fw_bind_text(st,5,nc_json_str_def(o,"destination","")) || nc_fw_bind_text(st,6,nc_json_str_def(o,"gateway","")) ||
             nc_fw_bind_text(st,7,nc_json_str_def(o,"interface","")) || nc_fw_bind_text(st,8,nc_json_str_def(o,"table",nc_json_str_def(o,"route_table","main"))) ||
             nc_fw_bind_int(st,9,nc_json_int_def(o,"metric",0)) || nc_fw_bind_int(st,10,nc_json_int_def(o,"mtu",1500)) ||
             nc_fw_bind_text(st,11,nc_json_str_def(o,"type",nc_json_str_def(o,"route_type","unicast"))) ||
             nc_fw_bind_text(st,12,nc_json_str_def(o,"comment","")) || nc_fw_bind_int64(st,13,nc_now_s());
        if (nc_adv_statement_done(st, rc ? -1 : 0) != 0) return -1;
    }
    return 0;
}

static int nc_adv_set_objects(struct json_object *arr)
{
    for (int i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *o = json_object_array_get_idx(arr, i), *members = NULL;
        sqlite3_stmt *st = NULL;
        const char *id = nc_json_str_def(o, "id", "");
        int rc;
        /* Validate at the entry point, matching nc_fw_set_* above. The
         * generator also checks family, but relying on that alone means a
         * malformed value still reaches the table and only fails later. */
        if (!nc_adv_family_ok(nc_json_str_def(o, "family", "ipv4")))
            return -1;
        if (nc_prepare(&st, "INSERT OR REPLACE INTO route_object(id,enabled,name,object_type,family,value,comment,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)") != 0)
            return -1;
        rc = nc_fw_bind_text(st,1,id) || nc_fw_bind_int(st,2,nc_json_bool_def(o,"enabled",1)) ||
             nc_fw_bind_text(st,3,nc_json_str_def(o,"name",id)) || nc_fw_bind_text(st,4,nc_json_str_def(o,"type",nc_json_str_def(o,"object_type","ip_group"))) ||
             nc_fw_bind_text(st,5,nc_json_str_def(o,"family","ipv4")) || nc_fw_bind_text(st,6,nc_json_str_def(o,"value","")) ||
             nc_fw_bind_text(st,7,nc_json_str_def(o,"comment","")) || nc_fw_bind_int64(st,8,nc_now_s());
        if (nc_adv_statement_done(st, rc ? -1 : 0) != 0) return -1;
        if (nc_prepare(&st, "DELETE FROM route_object_member WHERE object_id=?1") != 0) return -1;
        if (nc_adv_statement_done(st, nc_fw_bind_text(st,1,id)) != 0) return -1;
        if (json_object_object_get_ex(o, "members", &members)) {
            for (int j = 0; j < json_object_array_length(members); j++) {
                const char *value = json_object_get_string(json_object_array_get_idx(members,j));
                if (nc_prepare(&st, "INSERT INTO route_object_member(object_id,value,label,sort_order) VALUES(?1,?2,?3,?4)") != 0) return -1;
                rc = nc_fw_bind_text(st,1,id) || nc_fw_bind_text(st,2,value) || nc_fw_bind_text(st,3,value) || nc_fw_bind_int(st,4,j);
                if (nc_adv_statement_done(st, rc ? -1 : 0) != 0) return -1;
            }
        }
    }
    return 0;
}

static int nc_adv_set_cross(struct json_object *arr)
{
    for (int i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        sqlite3_stmt *st = NULL;
        const char *id = nc_json_str_def(o,"id","");
        int rc;
        if (nc_prepare(&st,"INSERT OR REPLACE INTO cross_l3_service(id,enabled,name,service_type,server_ip,scope,listen_port,version,access_rate,remark,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)") != 0) return -1;
        rc = nc_fw_bind_text(st,1,id) || nc_fw_bind_int(st,2,nc_json_bool_def(o,"enabled",1)) || nc_fw_bind_text(st,3,nc_json_str_def(o,"name",id)) ||
             nc_fw_bind_text(st,4,nc_json_str_def(o,"service_type","snmp")) || nc_fw_bind_text(st,5,nc_json_str_def(o,"server_ip","")) ||
             nc_fw_bind_text(st,6,nc_json_str_def(o,"scope","")) || nc_fw_bind_text(st,7,nc_json_str_def(o,"listen_port","161")) ||
             nc_fw_bind_text(st,8,nc_json_str_def(o,"version","V2")) || nc_fw_bind_text(st,9,nc_json_str_def(o,"access_rate","")) ||
             nc_fw_bind_text(st,10,nc_json_str_def(o,"remark","")) || nc_fw_bind_int64(st,11,nc_now_s());
        if (nc_adv_statement_done(st, rc ? -1 : 0) != 0) return -1;
    }
    return 0;
}

static int nc_adv_set_rules(struct json_object *arr)
{
    for (int i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        sqlite3_stmt *st = NULL;
        const char *id = nc_json_str_def(o,"id","");
        int rc;
        if (nc_prepare(&st,"INSERT OR REPLACE INTO policy_route_rule(id,enabled,priority,name,source_object,dest_object,proto,ports,action,target,route_table,schedule,sticky,comment,updated_at,source_kind,source_ref,pin_wan) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)") != 0) return -1;
        rc = nc_fw_bind_text(st,1,id) || nc_fw_bind_int(st,2,nc_json_bool_def(o,"enabled",1)) || nc_fw_bind_int(st,3,nc_json_int_def(o,"priority",1000+i)) ||
             nc_fw_bind_text(st,4,nc_json_str_def(o,"name",id)) || nc_fw_bind_text(st,5,nc_json_str_def(o,"source_object","")) ||
             nc_fw_bind_text(st,6,nc_json_str_def(o,"dest_object","")) || nc_fw_bind_text(st,7,nc_json_str_def(o,"proto","all")) ||
             nc_fw_bind_text(st,8,nc_json_str_def(o,"ports","any")) || nc_fw_bind_text(st,9,nc_json_str_def(o,"action","route_table")) ||
             nc_fw_bind_text(st,10,nc_json_str_def(o,"target","")) || nc_fw_bind_text(st,11,nc_json_str_def(o,"table",nc_json_str_def(o,"route_table",""))) ||
             nc_fw_bind_text(st,12,nc_json_str_def(o,"schedule","always")) || nc_fw_bind_int(st,13,nc_json_bool_def(o,"sticky",1)) ||
             nc_fw_bind_text(st,14,nc_json_str_def(o,"comment","")) || nc_fw_bind_int64(st,15,nc_now_s()) ||
             nc_fw_bind_text(st,16,nc_json_str_def(o,"source_kind","object")) ||
             nc_fw_bind_text(st,17,nc_json_str_def(o,"source_ref","")) ||
             nc_fw_bind_int(st,18,nc_json_bool_def(o,"pin_wan",0));
        if (nc_adv_statement_done(st, rc ? -1 : 0) != 0) return -1;
    }
    return 0;
}

int jmx_advanced_routing_set(struct json_object *cfg)
{
    struct json_object *v = NULL;
    int rc = 0;

    if (nc_adv_validate_config(cfg, 0) != 0 || jmx_netconfig_db_init() != 0)
        return -1;
    nc_adv_route_db_init();
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (json_object_object_get_ex(cfg,"global",&v)) rc |= nc_adv_set_global(v);
    if (json_object_object_get_ex(cfg,"tables",&v)) rc |= nc_adv_set_tables(v);
    if (json_object_object_get_ex(cfg,"static_routes",&v)) rc |= nc_adv_set_static_routes(v);
    if (json_object_object_get_ex(cfg,"route_objects",&v)) rc |= nc_adv_set_objects(v);
    if (json_object_object_get_ex(cfg,"cross_services",&v)) rc |= nc_adv_set_cross(v);
    if (json_object_object_get_ex(cfg,"policy_rules",&v)) rc |= nc_adv_set_rules(v);
    if (rc == 0)
        rc = nc_exec("UPDATE advanced_routing_global SET object_revision=object_revision+1,apply_state='draft',updated_at=strftime('%s','now') WHERE id=1");
    if (rc == 0 && nc_exec("COMMIT") == 0)
        return 0;
    nc_exec("ROLLBACK");
    return -1;
}

static void nc_shquote(FILE *fp, const char *s)
{
    fputc('\'', fp);
    if(s) for(; *s; s++) { if(*s=='\'') fputs("'\\''", fp); else fputc(*s, fp); }
    fputc('\'', fp);
}

static int nc_adv_table_id_by_name(const char *name, int *table_id)
{
    sqlite3_stmt *st = NULL;
    int step_rc;
    int rc = -1;

    if (!table_id)
        return -1;
    *table_id = 0;
    if (!name || !name[0] || !strcmp(name, "main")) {
        *table_id = 254;
        return 0;
    }
    if (!strcmp(name, "default")) {
        *table_id = 253;
        return 0;
    }
    if (!strcmp(name, "local")) {
        *table_id = 255;
        return 0;
    }
    if (nc_prepare(&st,
        "SELECT table_id FROM route_table WHERE id=? AND enabled=1") != 0)
        return -1;
    if (sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK)
        goto out;
    step_rc = sqlite3_step(st);
    if (step_rc == SQLITE_ROW) {
        *table_id = sqlite3_column_int(st, 0);
        rc = 0;
    } else if (step_rc == SQLITE_DONE) {
        rc = 0;
    }
out:
    if (sqlite3_finalize(st) != SQLITE_OK)
        rc = -1;
    return rc;
}

/*
 * ip rule pref band owned by the PBR generator.
 *
 * Starts at 11000 rather than 10000 so it cannot collide with routed's per-WAN
 * fwmark rules, which live at 10000 + (table_id % 1000) and therefore occupy
 * 10000-10999 (jmx_route.c route_rule_priority). The cleanup loop and the rule
 * emission below both derive from this constant so the two cannot drift apart:
 * a cleanup band wider than the emission band deletes someone else's rules, and
 * a narrower one leaves stale rules behind.
 */
#define NC_ADV_PBR_PREF_BASE 11000
#define NC_ADV_PBR_PREF_SPAN 9000
_Static_assert(NC_ADV_PBR_PREF_BASE + NC_ADV_PBR_PREF_SPAN - 1 <= 19999,
               "PBR pref band must stay within 11000-19999");

/* Pinned iif rules sit below the fwmark band and must be evaluated first. */
#define NC_ADV_PIN_PREF_BASE 9000
#define NC_ADV_PIN_PREF_SPAN 900
_Static_assert(NC_ADV_PIN_PREF_BASE + NC_ADV_PIN_PREF_SPAN - 1 < NC_ADV_PBR_PREF_BASE,
               "pin band must not overlap the fwmark band");

/*
 * Route ownership marker for everything this generator installs.
 *
 * The generator used to clean up by flushing whole tables:
 *
 *     ip route flush table 'wan'      # and wan2, wan3, wan4 ...
 *
 * Those tables are not ours. routed owns the per-WAN default in each of them
 * (jmx_route.c jmx_route_apply_system_route emits "ip route replace default
 * dev pppoe-wanN table 10N"), and the script re-adds only static_route rows.
 * With route_table populated and static_route empty -- the real state on 30.1,
 * four live WANs -- a single apply deleted all four default routes and left
 * them deleted, cutting every multi-WAN path until routed's next 30s tick.
 *
 * So cleanup is now scoped by ownership instead of by table. Every route this
 * generator emits carries "proto 194", and cleanup deletes only routes carrying
 * that proto. Routes installed by anyone else are invisible to it.
 *
 * 194 is a number, not a name, on purpose: matching a name requires an
 * rt_protos.d entry to be present and readable at apply time, and if it is not,
 * "ip route flush proto dwrt" fails to parse and cleanup silently degrades. A
 * numeric proto always parses. The value sits in the unassigned range above the
 * reserved protocols in /etc/iproute2/rt_protos (highest reserved is babel=42)
 * and is unused on the target: routes there carry only kernel, boot and static.
 */
#define NC_ADV_ROUTE_PROTO 194
_Static_assert(NC_ADV_ROUTE_PROTO > 0 && NC_ADV_ROUTE_PROTO <= 255,
               "route proto must fit in the kernel's 8-bit rtm_protocol");

static unsigned nc_adv_rule_mark(const char *id, int prio)
{
    unsigned h = 2166136261u;
    const unsigned char *p = (const unsigned char *)(id?id:"");
    while(*p) { h ^= *p++; h *= 16777619u; }
    h ^= (unsigned)prio;
    h &= 0x0fff;
    return 0x7000u | (h ? h : 1u);
}

#define NC_ADV_RUNTIME_DIR "/run/dreamingwrt"

static int nc_adv_open_runtime_log(char *path, size_t path_len)
{
    struct stat st;
    int dirfd = -1;
    int fd = -1;
    int attempt;
    char name[128];

    if (!path || path_len == 0)
        return -1;
    path[0] = '\0';
    if (mkdir(NC_ADV_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open(NC_ADV_RUNTIME_DIR,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    for (attempt = 0; attempt < 32; attempt++) {
        snprintf(name, sizeof(name), "advanced-routing-%ld-%lld-%08lx-%d.log",
                 (long)getpid(), (long long)nc_now_s(),
                 (unsigned long)random(), attempt);
        fd = openat(dirfd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0) {
            if (snprintf(path, path_len, "%s/%s", NC_ADV_RUNTIME_DIR, name) >=
                (int)path_len) {
                close(fd);
                unlinkat(dirfd, name, 0);
                fd = -1;
            }
            break;
        }
        if (errno != EEXIST)
            break;
    }
out:
    if (dirfd >= 0)
        close(dirfd);
    return fd;
}

static int nc_adv_run_script(int logfd)
{
    const char *argv[] = { "/bin/sh", "/etc/dreamingwrt/advanced_routing_apply.sh", NULL };
    pid_t pid;
    int status;

    if (logfd < 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(logfd);
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (devnull >= 0) {
            if (dup2(devnull, STDIN_FILENO) < 0)
                _exit(126);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }
        if (dup2(logfd, STDOUT_FILENO) < 0 || dup2(logfd, STDERR_FILENO) < 0)
            _exit(126);
        if (logfd > STDERR_FILENO)
            close(logfd);
        clearenv();
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        execv(argv[0], (char * const *)argv);
        _exit(127);
    }
    close(logfd);
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

#define NC_ADV_READBACK_TIMEOUT_MS 5000
#define NC_ADV_READBACK_OUTPUT_MAX (256U * 1024U)

static int nc_adv_trusted_exec_path(const char *path)
{
    struct stat st;

    /* OpenWrt exposes /sbin/ip as a root-owned absolute symlink to ip-full.
     * Validate the resolved executable, not the link inode itself. */
    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
           (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

static const char *nc_adv_ip_path(void)
{
    if (nc_adv_trusted_exec_path("/sbin/ip"))
        return "/sbin/ip";
    if (nc_adv_trusted_exec_path("/usr/sbin/ip"))
        return "/usr/sbin/ip";
    return NULL;
}

static const char *nc_adv_nft_path(void)
{
    if (nc_adv_trusted_exec_path("/usr/sbin/nft"))
        return "/usr/sbin/nft";
    if (nc_adv_trusted_exec_path("/sbin/nft"))
        return "/sbin/nft";
    return NULL;
}

static int nc_adv_capture(char *const argv[], struct jmx_exec_result *result)
{
    const char *path;
    int rc;

    if (!argv || !argv[0] || !result)
        return -1;
    path = argv[0];
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    rc = jmx_exec_capture(path, argv, NC_ADV_READBACK_OUTPUT_MAX,
                          NC_ADV_READBACK_TIMEOUT_MS, result);
    if (rc != 0 || result->timed_out || result->truncated ||
        result->term_signal != 0 || result->exit_code != 0)
        return -1;
    return 0;
}

static int nc_adv_nonempty_lines(const char *text)
{
    int count = 0;
    const char *p = text;

    if (!text)
        return 0;
    while (*p) {
        const char *end = strchr(p, '\n');
        const char *q = p;
        if (!end)
            end = p + strlen(p);
        while (q < end && isspace((unsigned char)*q))
            q++;
        if (q < end)
            count++;
        p = *end ? end + 1 : end;
    }
    return count;
}

static int nc_adv_substring_count(const char *text, const char *needle)
{
    int count = 0;
    size_t needle_len;

    if (!text || !needle || !needle[0])
        return 0;
    needle_len = strlen(needle);
    while ((text = strstr(text, needle)) != NULL) {
        count++;
        text += needle_len;
    }
    return count;
}

static int nc_adv_count_query(const char *sql)
{
    sqlite3_stmt *st = NULL;
    int count = -1;

    if (!sql || nc_prepare(&st, sql) != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    if (sqlite3_finalize(st) != SQLITE_OK)
        return -1;
    return count;
}

static int nc_adv_runtime_readback(char *reason, size_t reason_len)
{
    const char *ip = nc_adv_ip_path();
    const char *nft = nc_adv_nft_path();
    struct jmx_exec_result ip4 = {0};
    struct jmx_exec_result ip6 = {0};
    struct jmx_exec_result rules4 = {0};
    struct jmx_exec_result rules6 = {0};
    struct jmx_exec_result nft_result = {0};
    char *ip4_argv[9];
    char *ip6_argv[9];
    char *rules4_argv[5];
    char *rules6_argv[5];
    char *nft_argv[6];
    int expected_v4;
    int expected_v6;
    int expected_rules;
    int actual_v4;
    int actual_v6;
    int actual_rules;
    int expected_nft_rules;
    int actual_nft_rules;
    int rc = -1;

    if (reason && reason_len)
        reason[0] = '\0';
    if (!ip || !nft) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "runtime_tool_missing");
        return -1;
    }
    expected_v4 = nc_adv_count_query(
        "SELECT COUNT(*) FROM static_route WHERE enabled=1 AND family='ipv4'");
    expected_v6 = nc_adv_count_query(
        "SELECT COUNT(*) FROM static_route WHERE enabled=1 AND family='ipv6'");
    expected_rules = nc_adv_count_query(
        "SELECT COUNT(*) FROM policy_route_rule WHERE enabled=1");
    expected_nft_rules = expected_rules;
    if (expected_v4 < 0 || expected_v6 < 0 || expected_rules < 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "runtime_readback_database_failed");
        goto out;
    }

    ip4_argv[0] = (char *)ip;
    ip4_argv[1] = (char *)"-4";
    ip4_argv[2] = (char *)"route";
    ip4_argv[3] = (char *)"show";
    ip4_argv[4] = (char *)"table";
    ip4_argv[5] = (char *)"all";
    ip4_argv[6] = (char *)"proto";
    ip4_argv[7] = (char *)"194";
    ip4_argv[8] = NULL;
    ip6_argv[0] = (char *)ip;
    ip6_argv[1] = (char *)"-6";
    ip6_argv[2] = (char *)"route";
    ip6_argv[3] = (char *)"show";
    ip6_argv[4] = (char *)"table";
    ip6_argv[5] = (char *)"all";
    ip6_argv[6] = (char *)"proto";
    ip6_argv[7] = (char *)"194";
    ip6_argv[8] = NULL;
    rules4_argv[0] = (char *)ip;
    rules4_argv[1] = (char *)"rule";
    rules4_argv[2] = (char *)"show";
    rules4_argv[3] = NULL;
    rules6_argv[0] = (char *)ip;
    rules6_argv[1] = (char *)"-6";
    rules6_argv[2] = (char *)"rule";
    rules6_argv[3] = (char *)"show";
    rules6_argv[4] = NULL;
    nft_argv[0] = (char *)nft;
    nft_argv[1] = (char *)"list";
    nft_argv[2] = (char *)"table";
    nft_argv[3] = (char *)"inet";
    nft_argv[4] = (char *)"dreamingwrt_pbr";
    nft_argv[5] = NULL;

    if (nc_adv_capture(ip4_argv, &ip4) != 0 ||
        nc_adv_capture(ip6_argv, &ip6) != 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "runtime_route_readback_failed");
        goto out;
    }
    actual_v4 = nc_adv_nonempty_lines(ip4.output);
    actual_v6 = nc_adv_nonempty_lines(ip6.output);
    if (actual_v4 != expected_v4 || actual_v6 != expected_v6) {
        if (reason && reason_len)
            snprintf(reason, reason_len,
                     "runtime_route_readback_mismatch");
        goto out;
    }
    if (nc_adv_capture(rules4_argv, &rules4) != 0 ||
        nc_adv_capture(rules6_argv, &rules6) != 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "runtime_rule_readback_failed");
        goto out;
    }
    actual_rules = nc_adv_substring_count(rules4.output, "fwmark 0x") +
                   nc_adv_substring_count(rules6.output, "fwmark 0x");
    if (actual_rules < expected_rules * 2) {
        if (reason && reason_len)
            snprintf(reason, reason_len,
                     "runtime_rule_readback_mismatch");
        goto out;
    }
    if (nc_adv_capture(nft_argv, &nft_result) != 0 || !nft_result.output ||
        !strstr(nft_result.output, "table inet dreamingwrt_pbr") ||
        !strstr(nft_result.output, "chain prerouting")) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "runtime_nft_readback_failed");
        goto out;
    }
    actual_nft_rules = nc_adv_substring_count(nft_result.output, "dwrt-pbr:");
    if (actual_nft_rules != expected_nft_rules) {
        if (reason && reason_len)
            snprintf(reason, reason_len,
                     "runtime_nft_readback_mismatch");
        goto out;
    }
    rc = 0;

out:
    jmx_exec_result_free(&ip4);
    jmx_exec_result_free(&ip6);
    jmx_exec_result_free(&rules4);
    jmx_exec_result_free(&rules6);
    jmx_exec_result_free(&nft_result);
    return rc;
}

static int nc_adv_emit_route_cmd(FILE *fp, const char *family, const char *dst,
                                 const char *gw, const char *ifn,
                                 const char *table, int metric, int mtu,
                                 const char *rtype)
{
    const int v6 = family && !strcmp(family,"ipv6");
    fprintf(fp, "%s route replace ", v6?"ip -6":"ip"); nc_shquote(fp, dst&&dst[0]?dst:(v6?"::/0":"0.0.0.0/0"));
    if(rtype && strcmp(rtype,"unicast")) { fprintf(fp, " type "); nc_shquote(fp, rtype); }
    if(gw && gw[0]) { fprintf(fp, " via "); nc_shquote(fp, gw); }
    if(ifn && ifn[0]) { fprintf(fp, " dev "); nc_shquote(fp, ifn); }
    if(metric > 0) fprintf(fp, " metric %d", metric);
    if(mtu > 0 && mtu != 1500) fprintf(fp, " mtu %d", mtu);
    /*
     * Stamp ownership on the route itself. This is what makes the scoped
     * cleanup above possible: without it a PBR route is indistinguishable from
     * routed's, and the only way to clear ours was to flush the whole table.
     */
    fprintf(fp, " proto %d", NC_ADV_ROUTE_PROTO);
    fprintf(fp, " table "); nc_shquote(fp, table&&table[0]?table:"main");
    fprintf(fp, " || { printf 'route_failed:%%s\\n' ");
    nc_shquote(fp, dst&&dst[0]?dst:"default");
    fprintf(fp, "; exit 5; }\n");
    return ferror(fp) ? -1 : 0;
}

static int nc_adv_emit_obj_nft(FILE *fp, const char *obj, const char *dir,
                               int *has_match)
{
    int step_rc;
    sqlite3_stmt *st=NULL;

    if(!obj || !obj[0]) return 0;
    if(nc_prepare(&st,"SELECT value FROM route_object WHERE id=? AND enabled=1 UNION ALL SELECT m.value FROM route_object_member m JOIN route_object o ON o.id=m.object_id WHERE o.id=? AND o.enabled=1 ORDER BY value")!=0)
        return -1;
    if (sqlite3_bind_text(st,1,obj,-1,SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st,2,obj,-1,SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int n=0;
    while((step_rc=sqlite3_step(st))==SQLITE_ROW){ const char *v=(const char*)sqlite3_column_text(st,0); if(!v||!v[0]) continue; if(!nc_adv_object_value_ok(v)){sqlite3_finalize(st);return -1;} if(n++==0) fprintf(fp," ip %s { ",dir); else fprintf(fp,", "); fprintf(fp,"%s",v); }
    if(n>0){ fprintf(fp," }"); if(has_match)*has_match=1; }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK || ferror(fp))
        return -1;
    return n;
}

static int nc_adv_generate_runtime(FILE *script_path, FILE *nft_fp)
{
    sqlite3_stmt *st=NULL;
    int step_rc;

    fprintf(script_path, "#!/bin/sh\nset -eu\ncommand -v ip >/dev/null 2>&1 || { echo missing_ip; exit 3; }\n");
    fprintf(script_path, "mkdir -p /etc/iproute2/rt_tables.d /etc/dreamingwrt\n");
    /*
     * Pre-flight guard, evaluated on the device before anything is touched.
     *
     * dwrt_keep_defaults records the default routes in a table that belong to
     * somebody else, and dwrt_check_defaults re-reads them after our cleanup. If
     * a foreign default went missing, the script stops non-zero and the caller
     * reports a failed apply instead of leaving the dataplane short a route.
     *
     * This is belt-and-braces on top of the proto-scoped flush: the flush is
     * what makes the routes survive, and this is what refuses to continue if
     * some future iproute2 or a hand-written table makes it not survive
     * anyway. Comparing counts is enough to catch the failure this guards
     * against -- a whole-table flush -- without trying to diff route text
     * across a reformatting `ip`.
     */
    fprintf(script_path,
        "dwrt_keep_defaults() {\n"
        "\tip route show table \"$1\" default 2>/dev/null | grep -c '^default' || true\n"
        "}\n"
        "dwrt_check_defaults() {\n"
        "\t_before=\"$2\"\n"
        "\t_after=$(dwrt_keep_defaults \"$1\")\n"
        "\tif [ \"$_after\" -lt \"$_before\" ]; then\n"
        "\t\tprintf 'foreign_default_lost:%%s:%%s:%%s\\n' \"$1\" \"$_before\" \"$_after\"\n"
        "\t\texit 6\n"
        "\tfi\n"
        "}\n");

    fprintf(nft_fp, "table inet dreamingwrt_pbr {\n\tchain prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n");

    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM cross_l3_service WHERE enabled=1") != 0)
        return -1;
    step_rc = sqlite3_step(st);
    if (step_rc != SQLITE_ROW || sqlite3_column_int(st, 0) != 0 ||
        sqlite3_finalize(st) != SQLITE_OK)
        return -1;
    st = NULL;

    if(nc_prepare(&st,"SELECT id,table_id FROM route_table WHERE enabled=1 ORDER BY table_id")!=0)
        return -1;
    /*
     * Delete only our own routes out of each table, keyed on the proto stamped
     * by nc_adv_emit_route_cmd(). "flush ... proto N" leaves every route with a
     * different proto in place, so routed's per-WAN default survives an apply
     * that emits nothing -- which is the whole point, and what flushing the
     * table by name got wrong.
     */
    while((step_rc=sqlite3_step(st))==SQLITE_ROW){
        const char *id=(const char*)sqlite3_column_text(st,0);
        if(!id)continue;
        if(!nc_adv_id_ok(id)){ sqlite3_finalize(st); return -1; }
        /*
         * One reused variable rather than a per-table name: a route_table id may
         * legally contain '-' or '.' (nc_valid_name), neither of which is valid
         * in a shell variable name. The check runs immediately after the flush
         * for the same table, so nothing needs to outlive the next iteration.
         */
        fprintf(script_path,"dwrt_before=$(dwrt_keep_defaults ");
        nc_shquote(script_path,id);
        fprintf(script_path,")\n");
        fprintf(script_path,"ip route flush table "); nc_shquote(script_path,id);
        fprintf(script_path," proto %d 2>/dev/null || true\n", NC_ADV_ROUTE_PROTO);
        fprintf(script_path,"ip -6 route flush table "); nc_shquote(script_path,id);
        fprintf(script_path," proto %d 2>/dev/null || true\n", NC_ADV_ROUTE_PROTO);
        fprintf(script_path,"dwrt_check_defaults ");
        nc_shquote(script_path,id);
        fprintf(script_path," \"$dwrt_before\"\n");
    }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK)
        return -1;
    st = NULL;
    /*
     * Clear only the bands this generator owns: 9000-9899 for the pinned iif
     * rules and 11000-19999 for the fwmark rules. Do not walk every integer in
     * those bands: an absent `ip rule del` still forks ip and performs a
     * netlink round-trip. On a normal four-WAN router that used to mean nearly
     * 22,000 subprocesses per apply, which is why an otherwise small apply held
     * the core uloop for 4-6 seconds. Enumerate the kernel's actual rules once
     * and delete only matching priorities. The 10000-10999 routed band remains
     * untouched.
     */
    fprintf(script_path,
        "dwrt_delete_owned_rules() {\n"
        "\t_family=\"$1\"\n"
        "\tif [ \"$_family\" = 6 ]; then ip -6 rule show; else ip rule show; fi | "
        "awk '$1 ~ /^[0-9]+:[[:space:]]*$/ { p=$1; sub(/:$/, \"\", p); "
        "if ((p >= %d && p <= %d) || (p >= %d && p <= %d)) print p }' | "
        "while IFS= read -r p; do\n"
        "\t\t[ -n \"$p\" ] || continue\n"
        "\t\tif [ \"$_family\" = 6 ]; then ip -6 rule del pref \"$p\" 2>/dev/null || true; "
        "else ip rule del pref \"$p\" 2>/dev/null || true; fi\n"
        "\tdone\n"
        "}\n"
        "dwrt_delete_owned_rules 4\n"
        "dwrt_delete_owned_rules 6\n",
        NC_ADV_PIN_PREF_BASE,
        NC_ADV_PIN_PREF_BASE + NC_ADV_PIN_PREF_SPAN - 1,
        NC_ADV_PBR_PREF_BASE,
        NC_ADV_PBR_PREF_BASE + NC_ADV_PBR_PREF_SPAN - 1);

    if(nc_prepare(&st,"SELECT family,destination,gateway,interface,route_table,metric,mtu,route_type FROM static_route WHERE enabled=1 ORDER BY metric,id")!=0)
        return -1;
    while((step_rc=sqlite3_step(st))==SQLITE_ROW) {
        const char *family = (const char *)sqlite3_column_text(st, 0);
        const char *destination = (const char *)sqlite3_column_text(st, 1);
        const char *gateway = (const char *)sqlite3_column_text(st, 2);
        const char *ifname = (const char *)sqlite3_column_text(st, 3);
        const char *table = (const char *)sqlite3_column_text(st, 4);
        const char *type = (const char *)sqlite3_column_text(st, 7);
        int af = family && !strcmp(family, "ipv6") ? AF_INET6 : AF_INET;
        int metric = sqlite3_column_int(st, 5);
        int mtu = sqlite3_column_int(st, 6);
        int table_id = 0;
        char table_text[16];

        if (!family || (strcmp(family, "ipv4") && strcmp(family, "ipv6")) ||
            !nc_adv_ip_cidr_ok(destination, af, 0) ||
            !nc_adv_ip_cidr_ok(gateway, af, 1) ||
            !nc_adv_ifname_ok(ifname, 1) || !nc_adv_route_type_ok(type) ||
            metric < 0 || metric > 1000000 || mtu < 576 || mtu > 65535 ||
            nc_adv_table_id_by_name(table, &table_id) != 0 || table_id <= 0) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(table_text, sizeof(table_text), "%d", table_id);
        if (nc_adv_emit_route_cmd(script_path, family, destination, gateway,
                                  ifname, table_text, metric, mtu, type) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK)
        return -1;
    st = NULL;

    if(nc_prepare(&st,"SELECT id,priority,source_object,dest_object,proto,ports,action,target,route_table,source_kind,source_ref,pin_wan FROM policy_route_rule WHERE enabled=1 ORDER BY priority,id")!=0)
        return -1;
    while((step_rc=sqlite3_step(st))==SQLITE_ROW){
            const char *id=(const char*)sqlite3_column_text(st,0), *src=(const char*)sqlite3_column_text(st,2), *dst=(const char*)sqlite3_column_text(st,3), *proto=(const char*)sqlite3_column_text(st,4), *ports=(const char*)sqlite3_column_text(st,5), *action=(const char*)sqlite3_column_text(st,6), *target=(const char*)sqlite3_column_text(st,7), *rt=(const char*)sqlite3_column_text(st,8);
            const char *src_kind=(const char*)sqlite3_column_text(st,9);
            const char *src_ref=(const char*)sqlite3_column_text(st,10);
            int pin_wan=sqlite3_column_int(st,11);
            char src_devs[NC_ADV_MAX_SRC_DEVS][32];
            int src_dev_count = 0;
            int tid = 0;
            int src_count, dst_count;
            int prio=sqlite3_column_int(st,1); const char *table=(rt&&rt[0])?rt:target; unsigned mark=nc_adv_rule_mark(id,prio);

            if (!src_kind || !src_kind[0])
                src_kind = "object";
            if (!nc_adv_source_kind_ok(src_kind)) {
                sqlite3_finalize(st);
                return -1;
            }
            if (strcmp(src_kind, "object")) {
                /* An interface/zone/network source must resolve to at least one
                 * real device. Emitting a rule with no iifname would match every
                 * inbound interface, which is the opposite of what the operator
                 * asked for, so an unresolved source fails the whole publish. */
                src_dev_count = nc_adv_resolve_source_devices(
                    src_kind, src_ref ? src_ref : "", src_devs,
                    NC_ADV_MAX_SRC_DEVS);
                if (src_dev_count <= 0) {
                    sqlite3_finalize(st);
                    return -1;
                }
            }
            if (!nc_adv_id_ok(id) || prio < 0 || prio > 1000000 ||
                !nc_adv_proto_ok(proto) || !nc_fw_port_expr_ok(ports) ||
                !action || strcmp(action, "route_table") ||
                nc_adv_table_id_by_name(table, &tid) != 0 || tid <= 0 || tid == 255) {
                sqlite3_finalize(st);
                return -1;
            }
            int has=0; fprintf(nft_fp,"\t\t");
            if (src_dev_count > 0) {
                /* iifname carries the source dimension for interface/zone rules;
                 * source_object is not consulted for those. */
                fprintf(nft_fp," iifname { ");
                for (int d = 0; d < src_dev_count; d++)
                    fprintf(nft_fp, "%s\"%s\"", d ? ", " : "", src_devs[d]);
                fprintf(nft_fp," }");
                has = 1;
                src_count = src_dev_count;
            } else {
                src_count = nc_adv_emit_obj_nft(nft_fp,src,"saddr",&has);
            }
            dst_count = nc_adv_emit_obj_nft(nft_fp,dst,"daddr",&has);
            if (src_count < 0 || dst_count < 0 ||
                (src_dev_count == 0 && src && src[0] && src_count == 0) ||
                (dst && dst[0] && dst_count == 0)) {
                sqlite3_finalize(st);
                return -1;
            }
            if(proto && (!strcmp(proto,"tcp")||!strcmp(proto,"udp"))) { fprintf(nft_fp," %s",proto); if(ports&&ports[0]&&strcmp(ports,"any")) fprintf(nft_fp," dport { %s }",ports); has=1; }
            if(!has) { sqlite3_finalize(st); return -1; }
            fprintf(nft_fp," meta mark set 0x%04x ct mark set 0x%04x comment \"dwrt-pbr:%s\"\n",mark,mark,id?id:"rule");
            fprintf(script_path,"ip rule add pref %d fwmark 0x%04x/0xffff table %d\n",NC_ADV_PBR_PREF_BASE+(prio%NC_ADV_PBR_PREF_SPAN),mark,tid);
            fprintf(script_path,"ip -6 rule add pref %d fwmark 0x%04x/0xffff table %d\n",NC_ADV_PBR_PREF_BASE+(prio%NC_ADV_PBR_PREF_SPAN),mark,tid);
            /*
             * "Pin this interface to this WAN, keep it out of load balancing."
             *
             * A fwmark rule alone cannot express that. The jmx kernel hook runs
             * at NF_IP_PRI_MANGLE+1, i.e. after this nft chain at mangle
             * priority, and jmx_route_maybe_bind() overwrites skb->mark with the
             * WAN its own selector picked. A mark set here is therefore not
             * guaranteed to survive to the route lookup.
             *
             * An `ip rule iif <dev>` entry does survive: it is evaluated on the
             * device the packet arrived on, which no mark rewrite can change. It
             * is installed at a lower pref than the fwmark rules above so it wins
             * for this interface, which is exactly the "does not participate"
             * semantic. Only whole-interface sources can be pinned this way --
             * an IP-group rule has no inbound device to key on.
             */
            if (pin_wan && src_dev_count > 0) {
                for (int d = 0; d < src_dev_count; d++) {
                    fprintf(script_path,"ip rule add pref %d iif ",
                            NC_ADV_PIN_PREF_BASE+(prio%NC_ADV_PIN_PREF_SPAN));
                    nc_shquote(script_path, src_devs[d]);
                    fprintf(script_path," table %d\n",tid);
                    fprintf(script_path,"ip -6 rule add pref %d iif ",
                            NC_ADV_PIN_PREF_BASE+(prio%NC_ADV_PIN_PREF_SPAN));
                    nc_shquote(script_path, src_devs[d]);
                    fprintf(script_path," table %d\n",tid);
                }
            }
    }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK)
        return -1;
    fprintf(nft_fp,"\t}\n}\n");
    /*
     * The generated ruleset declares the complete table. Remove the previous
     * instance in the shell first so an empty first apply is valid too: nft's
     * `flush table` is an error when the table does not exist, and that used to
     * make an otherwise safe empty PBR apply fail closed before creating its
     * own table. The delete is scoped to our table and remains idempotent.
     */
    fprintf(script_path,"command -v nft >/dev/null 2>&1 || { echo missing_nft; exit 4; }\nnft delete table inet dreamingwrt_pbr 2>/dev/null || true\nnft -f /etc/dreamingwrt/advanced_routing_pbr.nft\nip route flush cache 2>/dev/null || true\nexit 0\n");
    return ferror(script_path) || ferror(nft_fp) ? -1 : 0;
}

struct nc_adv_artifact {
    const char *dir_path;
    const char *name;
    mode_t mode;
    int dirfd;
    FILE *fp;
    char tmp_name[128];
    char backup_name[128];
    int backup_made;
    int published;
};

#ifndef NC_ADV_RT_TABLES_DIR
#define NC_ADV_RT_TABLES_DIR "/etc/iproute2/rt_tables.d"
#endif
#ifndef NC_ADV_CONFIG_DIR
#define NC_ADV_CONFIG_DIR "/etc/config"
#endif
#ifndef NC_ADV_STATE_DIR
#define NC_ADV_STATE_DIR "/etc/dreamingwrt"
#endif
#define NC_ADV_JOURNAL_DIR NC_ADV_STATE_DIR
#define NC_ADV_JOURNAL_NAME ".advanced_routing_publish.journal"
#define NC_ADV_LOCK_NAME ".advanced_routing_publish.lock"
#define NC_ADV_JOURNAL_MAGIC UINT64_C(0x445741524a4e4c31)
#define NC_ADV_JOURNAL_VERSION 1U
#define NC_ADV_JOURNAL_PREPARED 1U
#define NC_ADV_JOURNAL_COMMITTED 2U
#define NC_ADV_ARTIFACT_COUNT 4U

#ifndef NC_ADV_TRUSTED_UID
#define NC_ADV_TRUSTED_UID 0
#endif
#ifndef NC_ADV_DIR_IS_TRUSTED
#define NC_ADV_DIR_IS_TRUSTED(st) \
    ((st).st_uid == NC_ADV_TRUSTED_UID && \
     ((st).st_mode & (S_IWGRP | S_IWOTH)) == 0)
#endif
/*
 * Predicate for the directories *above* the target.
 *
 * An ancestor only has to be a root-owned directory. Requiring the full
 * NC_ADV_DIR_IS_TRUSTED test on every ancestor made a group-writable /etc
 * (0775, which is what OpenWrt ships) fail the walk, and because the caller
 * refused to start the whole netconfig database on failure, every read endpoint
 * went silently empty. Six other trust checks in this file validate only their
 * final directory; this one walking the entire parent chain was the outlier.
 *
 * The traversal itself still uses O_NOFOLLOW at each level, so the protection
 * that actually matters here -- no symlink may be substituted part-way along the
 * path -- is unchanged.
 */
#ifndef NC_ADV_ANCESTOR_IS_TRUSTED
#define NC_ADV_ANCESTOR_IS_TRUSTED(st) ((st).st_uid == NC_ADV_TRUSTED_UID)
#endif
#ifndef NC_ADV_FAULT_POINT
#define NC_ADV_FAULT_POINT(point) ((void)0)
#endif
#ifndef NC_ADV_FSYNC_DIR
#define NC_ADV_FSYNC_DIR(fd) fsync(fd)
#endif
/*
 * The traversal always starts here. Production is "/", and the walk below is
 * byte-identical with that value. It exists as a macro so the permission tests
 * can root the walk inside a temporary directory: the failure this check guards
 * against needs group-writable ancestors, which a build machine does not have
 * and a test cannot create above /tmp.
 */
#ifndef NC_ADV_TRUST_ROOT
#define NC_ADV_TRUST_ROOT "/"
#endif

struct nc_adv_artifact_spec {
    const char *dir_path;
    const char *name;
    mode_t mode;
};

static const struct nc_adv_artifact_spec nc_adv_artifact_specs[] = {
    { NC_ADV_RT_TABLES_DIR, "dreamingwrt.conf", 0644 },
    { NC_ADV_CONFIG_DIR, "dreamingwrt_advanced_routing", 0600 },
    { NC_ADV_STATE_DIR, "advanced_routing_apply.sh", 0700 },
    { NC_ADV_STATE_DIR, "advanced_routing_pbr.nft", 0600 },
};

struct nc_adv_file_identity {
    uint64_t dev;
    uint64_t ino;
};

struct nc_adv_journal_entry {
    struct nc_adv_file_identity old_file;
    struct nc_adv_file_identity new_file;
    uint32_t had_old;
    uint32_t reserved;
};

struct nc_adv_publish_journal {
    uint64_t magic;
    uint64_t transaction_id;
    uint32_t version;
    uint32_t state;
    uint32_t count;
    uint32_t reserved;
    struct nc_adv_journal_entry entries[NC_ADV_ARTIFACT_COUNT];
    uint64_t checksum;
};

static void nc_adv_artifacts_init(struct nc_adv_artifact *artifacts,
                                  size_t count);

static int nc_adv_open_trusted_dir(const char *path)
{
    struct stat st;
    char component[NAME_MAX + 1];
    const char *cursor;
    int fd = -1;

    if (!path || path[0] != '/')
        return -1;
    fd = open(NC_ADV_TRUST_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        !NC_ADV_ANCESTOR_IS_TRUSTED(st))
        goto fail;
    cursor = path + 1;
    while (*cursor) {
        const char *slash = strchr(cursor, '/');
        size_t len = slash ? (size_t)(slash - cursor) : strlen(cursor);
        int nextfd;

        if (len == 0 || len > NAME_MAX ||
            (len == 1 && cursor[0] == '.') ||
            (len == 2 && cursor[0] == '.' && cursor[1] == '.'))
            goto fail;
        memcpy(component, cursor, len);
        component[len] = '\0';
        nextfd = openat(fd, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (nextfd < 0) {
            goto fail;
        }
        close(fd);
        fd = nextfd;
        cursor = slash ? slash + 1 : cursor + len;
        /*
         * Ancestors are checked loosely, the destination strictly. Which one
         * this is depends on whether any component remains.
         */
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
            !(*cursor ? NC_ADV_ANCESTOR_IS_TRUSTED(st)
                      : NC_ADV_DIR_IS_TRUSTED(st)))
            goto fail;
    }
    /* Re-checked because a path with a trailing slash leaves the loop early. */
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        !NC_ADV_DIR_IS_TRUSTED(st))
        goto fail;
    return fd;

fail:
    if (fd >= 0)
        close(fd);
    return -1;
}

static int nc_adv_stat_regular_at(int dirfd, const char *name,
                                  struct stat *st, int *present)
{
    if (!name || !st || !present)
        return -1;
    if (fstatat(dirfd, name, st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            memset(st, 0, sizeof(*st));
            *present = 0;
            return 0;
        }
        return -1;
    }
    if (!S_ISREG(st->st_mode) || st->st_uid != NC_ADV_TRUSTED_UID ||
        (st->st_mode & (S_IWGRP | S_IWOTH)) != 0 || st->st_nlink != 1)
        return -1;
    *present = 1;
    return 0;
}

static struct nc_adv_file_identity nc_adv_identity(const struct stat *st)
{
    struct nc_adv_file_identity identity = { 0, 0 };

    if (st) {
        identity.dev = (uint64_t)st->st_dev;
        identity.ino = (uint64_t)st->st_ino;
    }
    return identity;
}

static int nc_adv_identity_matches(const struct stat *st,
                                   const struct nc_adv_file_identity *identity)
{
    return st && identity && (uint64_t)st->st_dev == identity->dev &&
        (uint64_t)st->st_ino == identity->ino;
}

static uint64_t nc_adv_journal_checksum(const struct nc_adv_publish_journal *journal)
{
    const unsigned char *bytes = (const unsigned char *)journal;
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t len = offsetof(struct nc_adv_publish_journal, checksum);

    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int nc_adv_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

static int nc_adv_read_all(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t got = read(fd, cursor, length);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        cursor += got;
        length -= (size_t)got;
    }
    return 0;
}

static uint64_t nc_adv_transaction_id(void)
{
    uint64_t id = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode) ||
            nc_adv_read_all(fd, &id, sizeof(id)) != 0)
            id = 0;
        close(fd);
    }
    if (id == 0) {
        id = ((uint64_t)(unsigned long)getpid() << 32) ^
            (uint64_t)time(NULL) ^ ((uint64_t)(unsigned long)random() << 1);
    }
    return id ? id : UINT64_C(1);
}

static int nc_adv_journal_tmp_name(char *buffer, size_t length, uint64_t txid)
{
    int n = snprintf(buffer, length, ".advanced_routing_publish.%016llx.tmp",
                     (unsigned long long)txid);
    return n > 0 && (size_t)n < length ? 0 : -1;
}

static int nc_adv_artifact_names(struct nc_adv_artifact *artifact,
                                 uint64_t txid, size_t index)
{
    int tmp_len;
    int backup_len;

    if (!artifact || !artifact->name || index >= NC_ADV_ARTIFACT_COUNT)
        return -1;
    tmp_len = snprintf(artifact->tmp_name, sizeof(artifact->tmp_name),
        ".%s.%016llx.%zu.tmp", artifact->name,
        (unsigned long long)txid, index);
    backup_len = snprintf(artifact->backup_name, sizeof(artifact->backup_name),
        ".%s.%016llx.%zu.rollback", artifact->name,
        (unsigned long long)txid, index);
    return tmp_len > 0 && (size_t)tmp_len < sizeof(artifact->tmp_name) &&
        backup_len > 0 && (size_t)backup_len < sizeof(artifact->backup_name)
        ? 0 : -1;
}

static int nc_adv_journal_write(int journal_dirfd,
                                struct nc_adv_publish_journal *journal,
                                int create_only)
{
    struct stat st;
    char tmp_name[96];
    int present = 0;
    int fd = -1;
    int rc = -1;

    if (!journal || nc_adv_journal_tmp_name(tmp_name, sizeof(tmp_name),
                                            journal->transaction_id) != 0)
        return -1;
    journal->checksum = nc_adv_journal_checksum(journal);
    fd = openat(journal_dirfd, tmp_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (fchmod(fd, 0600) != 0 ||
        nc_adv_write_all(fd, journal, sizeof(*journal)) != 0 ||
        fsync(fd) != 0)
        goto out;
    NC_ADV_FAULT_POINT("journal_file_synced");
    if (close(fd) != 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (create_only) {
        if (fstatat(journal_dirfd, NC_ADV_JOURNAL_NAME, &st,
                    AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
            goto out;
        if (linkat(journal_dirfd, tmp_name, journal_dirfd,
                   NC_ADV_JOURNAL_NAME, 0) != 0 || NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
            goto out;
        NC_ADV_FAULT_POINT("journal_linked");
        if (unlinkat(journal_dirfd, tmp_name, 0) != 0 ||
            NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
            goto out;
        NC_ADV_FAULT_POINT("journal_tmp_removed");
    } else {
        if (nc_adv_stat_regular_at(journal_dirfd, NC_ADV_JOURNAL_NAME,
                                   &st, &present) != 0 || !present)
            goto out;
        if (renameat(journal_dirfd, tmp_name, journal_dirfd,
                     NC_ADV_JOURNAL_NAME) != 0 || NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
            goto out;
        NC_ADV_FAULT_POINT("journal_replaced");
    }
    rc = 0;

out:
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlinkat(journal_dirfd, tmp_name, 0);
    return rc;
}

static int nc_adv_journal_read(int journal_dirfd,
                               struct nc_adv_publish_journal *journal)
{
    struct stat st;
    char extra;
    char tmp_name[96];
    int fd;

    if (!journal)
        return -1;
    if (fstatat(journal_dirfd, NC_ADV_JOURNAL_NAME, &st,
                AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != NC_ADV_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (st.st_nlink != 1 && st.st_nlink != 2) ||
        st.st_size != (off_t)sizeof(*journal))
        return -1;
    fd = openat(journal_dirfd, NC_ADV_JOURNAL_NAME,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != NC_ADV_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (st.st_nlink != 1 && st.st_nlink != 2) ||
        nc_adv_read_all(fd, journal, sizeof(*journal)) != 0 ||
        read(fd, &extra, 1) != 0) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0)
        return -1;
    if (journal->magic != NC_ADV_JOURNAL_MAGIC ||
        journal->version != NC_ADV_JOURNAL_VERSION ||
        journal->count != NC_ADV_ARTIFACT_COUNT ||
        (journal->state != NC_ADV_JOURNAL_PREPARED &&
         journal->state != NC_ADV_JOURNAL_COMMITTED) ||
        journal->reserved != 0 ||
        journal->checksum != nc_adv_journal_checksum(journal))
        return -1;
    for (size_t i = 0; i < journal->count; i++) {
        if (journal->entries[i].had_old > 1 ||
            journal->entries[i].reserved != 0 ||
            journal->entries[i].new_file.dev == 0 ||
            journal->entries[i].new_file.ino == 0 ||
            (journal->entries[i].had_old &&
             (journal->entries[i].old_file.dev == 0 ||
              journal->entries[i].old_file.ino == 0)))
            return -1;
    }
    if (nc_adv_journal_tmp_name(tmp_name, sizeof(tmp_name),
                                journal->transaction_id) != 0)
        return -1;
    return 0;
}

static int nc_adv_journal_read_named(int journal_dirfd, const char *name,
                                     struct nc_adv_publish_journal *journal)
{
    struct stat st;
    char extra;
    int fd;

    if (!name || !journal ||
        fstatat(journal_dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode) || st.st_uid != NC_ADV_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 || st.st_nlink != 1 ||
        st.st_size != (off_t)sizeof(*journal))
        return -1;
    fd = openat(journal_dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != NC_ADV_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 || st.st_nlink != 1 ||
        nc_adv_read_all(fd, journal, sizeof(*journal)) != 0 ||
        read(fd, &extra, 1) != 0) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0 || journal->magic != NC_ADV_JOURNAL_MAGIC ||
        journal->version != NC_ADV_JOURNAL_VERSION ||
        journal->transaction_id == 0 ||
        journal->count != NC_ADV_ARTIFACT_COUNT || journal->reserved != 0 ||
        (journal->state != NC_ADV_JOURNAL_PREPARED &&
         journal->state != NC_ADV_JOURNAL_COMMITTED) ||
        journal->checksum != nc_adv_journal_checksum(journal))
        return -1;
    for (size_t i = 0; i < journal->count; i++) {
        if (journal->entries[i].had_old > 1 ||
            journal->entries[i].reserved != 0 ||
            journal->entries[i].new_file.dev == 0 ||
            journal->entries[i].new_file.ino == 0 ||
            (journal->entries[i].had_old &&
             (journal->entries[i].old_file.dev == 0 ||
              journal->entries[i].old_file.ino == 0)))
            return -1;
    }
    return 0;
}

static int nc_adv_journal_same_transaction(
    const struct nc_adv_publish_journal *left,
    const struct nc_adv_publish_journal *right)
{
    return left && right && left->magic == right->magic &&
        left->transaction_id == right->transaction_id &&
        left->version == right->version && left->count == right->count &&
        !memcmp(left->entries, right->entries, sizeof(left->entries));
}

static int nc_adv_cleanup_unpublished_journal(
    int journal_dirfd, const char *journal_name,
    const struct nc_adv_publish_journal *journal)
{
    struct nc_adv_artifact artifacts[NC_ADV_ARTIFACT_COUNT];
    struct stat target_st;
    struct stat tmp_st;
    struct stat backup_st;
    int target_present;
    int tmp_present;
    int backup_present;
    int rc = -1;

    if (!journal_name || !journal ||
        journal->state != NC_ADV_JOURNAL_PREPARED)
        return -1;
    nc_adv_artifacts_init(artifacts, NC_ADV_ARTIFACT_COUNT);
    for (size_t i = 0; i < NC_ADV_ARTIFACT_COUNT; i++) {
        target_present = tmp_present = backup_present = 0;
        artifacts[i].dirfd = nc_adv_open_trusted_dir(artifacts[i].dir_path);
        if (artifacts[i].dirfd < 0 ||
            nc_adv_artifact_names(&artifacts[i], journal->transaction_id, i) != 0 ||
            nc_adv_stat_regular_at(artifacts[i].dirfd, artifacts[i].name,
                &target_st, &target_present) != 0 ||
            nc_adv_stat_regular_at(artifacts[i].dirfd, artifacts[i].tmp_name,
                &tmp_st, &tmp_present) != 0 ||
            nc_adv_stat_regular_at(artifacts[i].dirfd, artifacts[i].backup_name,
                &backup_st, &backup_present) != 0 || backup_present || !tmp_present ||
            !nc_adv_identity_matches(&tmp_st, &journal->entries[i].new_file))
            goto out;
        if (journal->entries[i].had_old) {
            if (!target_present ||
                !nc_adv_identity_matches(&target_st,
                                         &journal->entries[i].old_file))
                goto out;
        } else if (target_present) {
            goto out;
        }
    }
    for (size_t i = 0; i < NC_ADV_ARTIFACT_COUNT; i++) {
        if (unlinkat(artifacts[i].dirfd, artifacts[i].tmp_name, 0) != 0 ||
            NC_ADV_FSYNC_DIR(artifacts[i].dirfd) != 0)
            goto out;
    }
    if (unlinkat(journal_dirfd, journal_name, 0) != 0 ||
        NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
        goto out;
    rc = 0;

out:
    for (size_t i = 0; i < NC_ADV_ARTIFACT_COUNT; i++) {
        if (artifacts[i].dirfd >= 0)
            close(artifacts[i].dirfd);
    }
    return rc;
}

static int nc_adv_cleanup_orphan_journals(int journal_dirfd)
{
    static const char prefix[] = ".advanced_routing_publish.";
    static const char suffix[] = ".tmp";
    struct dirent *entry;
    DIR *dir;
    int scanfd;
    int rc = 0;

    scanfd = dup(journal_dirfd);
    if (scanfd < 0)
        return -1;
    dir = fdopendir(scanfd);
    if (!dir) {
        close(scanfd);
        return -1;
    }
    while ((entry = readdir(dir)) != NULL) {
        struct nc_adv_publish_journal journal;
        char expected[96];
        size_t name_len = strlen(entry->d_name);
        size_t prefix_len = sizeof(prefix) - 1;
        size_t suffix_len = sizeof(suffix) - 1;

        if (name_len != prefix_len + 16 + suffix_len ||
            memcmp(entry->d_name, prefix, prefix_len) != 0 ||
            memcmp(entry->d_name + name_len - suffix_len,
                   suffix, suffix_len) != 0)
            continue;
        for (size_t i = prefix_len; i < prefix_len + 16; i++) {
            if (!isxdigit((unsigned char)entry->d_name[i]) ||
                (entry->d_name[i] >= 'A' && entry->d_name[i] <= 'F')) {
                rc = -1;
                break;
            }
        }
        if (rc != 0 ||
            nc_adv_journal_read_named(journal_dirfd, entry->d_name,
                                      &journal) != 0 ||
            nc_adv_journal_tmp_name(expected, sizeof(expected),
                                    journal.transaction_id) != 0 ||
            strcmp(expected, entry->d_name) ||
            nc_adv_cleanup_unpublished_journal(journal_dirfd,
                                               entry->d_name, &journal) != 0) {
            rc = -1;
            break;
        }
    }
    closedir(dir);
    return rc;
}

static int nc_adv_artifact_open(struct nc_adv_artifact *artifact,
                                uint64_t txid, size_t index)
{
    struct stat dir_st;
    struct stat target_st;
    int fd = -1;

    if (!artifact || !artifact->dir_path || !artifact->name)
        return -1;
    artifact->dirfd = nc_adv_open_trusted_dir(artifact->dir_path);
    if (artifact->dirfd < 0 || fstat(artifact->dirfd, &dir_st) != 0 ||
        !S_ISDIR(dir_st.st_mode) || !NC_ADV_DIR_IS_TRUSTED(dir_st))
        goto fail;
    if (fstatat(artifact->dirfd, artifact->name, &target_st,
                AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(target_st.st_mode) ||
            target_st.st_uid != NC_ADV_TRUSTED_UID ||
            (target_st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            target_st.st_nlink != 1)
            goto fail;
    } else if (errno != ENOENT) {
        goto fail;
    }
    if (nc_adv_artifact_names(artifact, txid, index) != 0)
        goto fail;
    fd = openat(artifact->dirfd, artifact->tmp_name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                artifact->mode);
    if (fd < 0)
        goto fail;
    artifact->fp = fdopen(fd, "w");
    if (!artifact->fp) {
        close(fd);
        unlinkat(artifact->dirfd, artifact->tmp_name, 0);
        artifact->tmp_name[0] = '\0';
        goto fail;
    }
    return 0;
fail:
    if (artifact->dirfd >= 0) {
        close(artifact->dirfd);
        artifact->dirfd = -1;
    }
    return -1;
}

static int nc_adv_artifact_finish(struct nc_adv_artifact *artifact)
{
    FILE *fp = artifact ? artifact->fp : NULL;
    int rc = 0;

    if (!fp)
        return -1;
    if (fflush(fp) != 0 || ferror(fp) ||
        fchmod(fileno(fp), artifact->mode) != 0 || fsync(fileno(fp)) != 0)
        rc = -1;
    if (fclose(fp) != 0)
        rc = -1;
    artifact->fp = NULL;
    return rc;
}

static void nc_adv_artifacts_abort(struct nc_adv_artifact *artifacts,
                                   size_t count, int restore)
{
    while (count > 0) {
        struct nc_adv_artifact *artifact = &artifacts[--count];

        if (artifact->fp) {
            fclose(artifact->fp);
            artifact->fp = NULL;
        }
        if (artifact->dirfd < 0)
            continue;
        if (restore && artifact->published)
            unlinkat(artifact->dirfd, artifact->name, 0);
        if (restore && artifact->backup_made) {
            if (renameat(artifact->dirfd, artifact->backup_name,
                         artifact->dirfd, artifact->name) == 0)
                artifact->backup_made = 0;
        }
        if (artifact->tmp_name[0])
            unlinkat(artifact->dirfd, artifact->tmp_name, 0);
        (void)NC_ADV_FSYNC_DIR(artifact->dirfd);
    }
}

static int nc_adv_publish_lock(int journal_dirfd)
{
    struct stat st;
    int fd;

    fd = openat(journal_dirfd, NC_ADV_LOCK_NAME,
        O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != NC_ADV_TRUSTED_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 || st.st_nlink != 1 ||
        fchmod(fd, 0600) != 0 || fsync(fd) != 0 ||
        NC_ADV_FSYNC_DIR(journal_dirfd) != 0 || flock(fd, LOCK_EX) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static int nc_adv_recover_publish_locked(const char *journal_dir_path,
                                         struct nc_adv_artifact *artifacts,
                                         size_t count, int *committed_out)
{
    struct nc_adv_publish_journal journal;
    struct stat journal_st;
    struct stat target_st[NC_ADV_ARTIFACT_COUNT];
    struct stat tmp_st[NC_ADV_ARTIFACT_COUNT];
    struct stat backup_st[NC_ADV_ARTIFACT_COUNT];
    int target_present[NC_ADV_ARTIFACT_COUNT] = { 0 };
    int tmp_present[NC_ADV_ARTIFACT_COUNT] = { 0 };
    int backup_present[NC_ADV_ARTIFACT_COUNT] = { 0 };
    int journal_present = 0;
    int journal_dirfd = -1;
    int rc = -1;
    char journal_tmp_name[96] = "";

    if (committed_out)
        *committed_out = 0;
    if (!journal_dir_path || !artifacts || count != NC_ADV_ARTIFACT_COUNT)
        return -1;
    journal_dirfd = nc_adv_open_trusted_dir(journal_dir_path);
    if (journal_dirfd < 0)
        return -1;
    if (fstatat(journal_dirfd, NC_ADV_JOURNAL_NAME, &journal_st,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            rc = nc_adv_cleanup_orphan_journals(journal_dirfd);
        goto out;
    }
    journal_present = 1;
    if (nc_adv_journal_read(journal_dirfd, &journal) != 0)
        goto out;
    if (committed_out)
        *committed_out = journal.state == NC_ADV_JOURNAL_COMMITTED;
    if (nc_adv_journal_tmp_name(journal_tmp_name, sizeof(journal_tmp_name),
                                journal.transaction_id) != 0)
        goto out;
    {
        struct stat linked_tmp_st;
        if (fstatat(journal_dirfd, journal_tmp_name, &linked_tmp_st,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISREG(linked_tmp_st.st_mode))
                goto out;
            if (linked_tmp_st.st_dev != journal_st.st_dev ||
                linked_tmp_st.st_ino != journal_st.st_ino) {
                struct nc_adv_publish_journal pending;
                if (journal.state != NC_ADV_JOURNAL_PREPARED ||
                    nc_adv_journal_read_named(journal_dirfd, journal_tmp_name,
                                              &pending) != 0 ||
                    pending.state != NC_ADV_JOURNAL_COMMITTED ||
                    !nc_adv_journal_same_transaction(&journal, &pending))
                    goto out;
            }
            if (unlinkat(journal_dirfd, journal_tmp_name, 0) != 0 ||
                NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
                goto out;
        } else if (errno != ENOENT) {
            goto out;
        }
    }

    for (size_t i = 0; i < count; i++) {
        artifacts[i].dirfd = nc_adv_open_trusted_dir(artifacts[i].dir_path);
        if (artifacts[i].dirfd < 0 ||
            nc_adv_artifact_names(&artifacts[i], journal.transaction_id, i) != 0 ||
            nc_adv_stat_regular_at(artifacts[i].dirfd, artifacts[i].name,
                &target_st[i], &target_present[i]) != 0 ||
            nc_adv_stat_regular_at(artifacts[i].dirfd, artifacts[i].tmp_name,
                &tmp_st[i], &tmp_present[i]) != 0 ||
            nc_adv_stat_regular_at(artifacts[i].dirfd, artifacts[i].backup_name,
                &backup_st[i], &backup_present[i]) != 0)
            goto out;

        if (target_present[i] &&
            !nc_adv_identity_matches(&target_st[i], &journal.entries[i].old_file) &&
            !nc_adv_identity_matches(&target_st[i], &journal.entries[i].new_file))
            goto out;
        if (tmp_present[i] &&
            !nc_adv_identity_matches(&tmp_st[i], &journal.entries[i].new_file))
            goto out;
        if (backup_present[i] &&
            (!journal.entries[i].had_old ||
             !nc_adv_identity_matches(&backup_st[i], &journal.entries[i].old_file)))
            goto out;

        if (journal.state == NC_ADV_JOURNAL_PREPARED) {
            if (journal.entries[i].had_old) {
                int target_is_old = target_present[i] &&
                    nc_adv_identity_matches(&target_st[i], &journal.entries[i].old_file);
                int target_is_new = target_present[i] &&
                    nc_adv_identity_matches(&target_st[i], &journal.entries[i].new_file);
                if (backup_present[i]) {
                    if ((target_present[i] && !target_is_new) ||
                        (tmp_present[i] && target_is_new))
                        goto out;
                } else if (!target_is_old || target_is_new) {
                    goto out;
                }
            } else {
                int new_count = (target_present[i] ? 1 : 0) +
                    (tmp_present[i] ? 1 : 0);
                if (backup_present[i] || new_count > 1)
                    goto out;
            }
        } else {
            if (!target_present[i] ||
                !nc_adv_identity_matches(&target_st[i], &journal.entries[i].new_file) ||
                tmp_present[i] || (!journal.entries[i].had_old && backup_present[i]))
                goto out;
        }
    }

    if (journal.state == NC_ADV_JOURNAL_PREPARED) {
        for (size_t n = count; n > 0; n--) {
            size_t i = n - 1;
            if (journal.entries[i].had_old) {
                if (backup_present[i]) {
                    if (target_present[i] &&
                        unlinkat(artifacts[i].dirfd, artifacts[i].name, 0) != 0)
                        goto out;
                    if (tmp_present[i] &&
                        unlinkat(artifacts[i].dirfd, artifacts[i].tmp_name, 0) != 0)
                        goto out;
                    if (renameat(artifacts[i].dirfd, artifacts[i].backup_name,
                                 artifacts[i].dirfd, artifacts[i].name) != 0)
                        goto out;
                } else if (tmp_present[i] &&
                           unlinkat(artifacts[i].dirfd,
                                    artifacts[i].tmp_name, 0) != 0) {
                    goto out;
                }
            } else {
                if (target_present[i] &&
                    unlinkat(artifacts[i].dirfd, artifacts[i].name, 0) != 0)
                    goto out;
                if (tmp_present[i] &&
                    unlinkat(artifacts[i].dirfd, artifacts[i].tmp_name, 0) != 0)
                    goto out;
            }
            if (NC_ADV_FSYNC_DIR(artifacts[i].dirfd) != 0)
                goto out;
            NC_ADV_FAULT_POINT("recovery_artifact");
        }
    } else {
        for (size_t i = 0; i < count; i++) {
            if (backup_present[i] &&
                unlinkat(artifacts[i].dirfd, artifacts[i].backup_name, 0) != 0)
                goto out;
            if (NC_ADV_FSYNC_DIR(artifacts[i].dirfd) != 0)
                goto out;
            NC_ADV_FAULT_POINT("recovery_artifact");
        }
    }
    if (unlinkat(journal_dirfd, NC_ADV_JOURNAL_NAME, 0) != 0 ||
        NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
        goto out;
    journal_present = 0;
    NC_ADV_FAULT_POINT("recovery_journal_removed");
    if (journal_tmp_name[0]) {
        struct stat tmp_journal_st;
        int tmp_journal_present = 0;
        if (nc_adv_stat_regular_at(journal_dirfd, journal_tmp_name,
                &tmp_journal_st, &tmp_journal_present) != 0)
            goto out;
        if (tmp_journal_present &&
            (unlinkat(journal_dirfd, journal_tmp_name, 0) != 0 ||
             NC_ADV_FSYNC_DIR(journal_dirfd) != 0))
            goto out;
    }
    rc = 0;

out:
    if (journal_present && rc != 0)
        LOG_ERROR("advanced routing journal recovery refused unsafe or ambiguous state\n");
    for (size_t i = 0; i < count; i++) {
        if (artifacts[i].dirfd >= 0) {
            close(artifacts[i].dirfd);
            artifacts[i].dirfd = -1;
        }
    }
    if (journal_dirfd >= 0)
        close(journal_dirfd);
    return rc;
}

static int nc_adv_recover_publish(const char *journal_dir_path,
                                  struct nc_adv_artifact *artifacts,
                                  size_t count)
{
    int journal_dirfd;
    int lockfd;
    int rc;

    journal_dirfd = nc_adv_open_trusted_dir(journal_dir_path);
    if (journal_dirfd < 0)
        return -1;
    lockfd = nc_adv_publish_lock(journal_dirfd);
    if (lockfd < 0) {
        close(journal_dirfd);
        return -1;
    }
    rc = nc_adv_recover_publish_locked(journal_dir_path, artifacts, count, NULL);
    close(lockfd);
    close(journal_dirfd);
    return rc;
}

static int nc_adv_artifacts_publish(struct nc_adv_artifact *artifacts,
                                    size_t count, uint64_t transaction_id,
                                    const char *journal_dir_path)
{
    struct nc_adv_publish_journal journal;
    struct nc_adv_artifact recovery_artifacts[NC_ADV_ARTIFACT_COUNT];
    int journal_dirfd = -1;
    int lockfd = -1;
    int committed = 0;
    int journal_owned = 0;
    int recovered_committed = 0;
    size_t i;

    if (!artifacts || count != NC_ADV_ARTIFACT_COUNT ||
        !journal_dir_path || transaction_id == 0)
        return -1;
    memset(&journal, 0, sizeof(journal));
    journal.magic = NC_ADV_JOURNAL_MAGIC;
    journal.transaction_id = transaction_id;
    journal.version = NC_ADV_JOURNAL_VERSION;
    journal.state = NC_ADV_JOURNAL_PREPARED;
    journal.count = (uint32_t)count;
    journal_dirfd = nc_adv_open_trusted_dir(journal_dir_path);
    if (journal_dirfd < 0)
        return -1;
    lockfd = nc_adv_publish_lock(journal_dirfd);
    if (lockfd < 0)
        goto rollback;
    nc_adv_artifacts_init(recovery_artifacts, NC_ADV_ARTIFACT_COUNT);
    if (nc_adv_recover_publish_locked(journal_dir_path, recovery_artifacts,
                                      count, NULL) != 0)
        goto rollback;

    for (i = 0; i < count; i++) {
        struct nc_adv_artifact *artifact = &artifacts[i];
        struct stat target_st;
        struct stat tmp_st;
        int target_present = 0;
        int tmp_present = 0;

        if (nc_adv_stat_regular_at(artifact->dirfd, artifact->name,
                                   &target_st, &target_present) != 0 ||
            nc_adv_stat_regular_at(artifact->dirfd, artifact->tmp_name,
                                   &tmp_st, &tmp_present) != 0 || !tmp_present)
            goto rollback;
        journal.entries[i].had_old = target_present ? 1U : 0U;
        if (target_present)
            journal.entries[i].old_file = nc_adv_identity(&target_st);
        journal.entries[i].new_file = nc_adv_identity(&tmp_st);
    }
    journal_owned = 1;
    if (nc_adv_journal_write(journal_dirfd, &journal, 1) != 0)
        goto rollback;
    NC_ADV_FAULT_POINT("journal_prepared");

    for (i = 0; i < count; i++) {
        struct nc_adv_artifact *artifact = &artifacts[i];

        if (journal.entries[i].had_old) {
            if (renameat(artifact->dirfd, artifact->name, artifact->dirfd,
                         artifact->backup_name) != 0)
                goto rollback;
            artifact->backup_made = 1;
            if (NC_ADV_FSYNC_DIR(artifact->dirfd) != 0)
                goto rollback;
            NC_ADV_FAULT_POINT("artifact_backed_up");
        }
        if (renameat(artifact->dirfd, artifact->tmp_name, artifact->dirfd,
                     artifact->name) != 0)
            goto rollback;
        artifact->tmp_name[0] = '\0';
        artifact->published = 1;
        if (NC_ADV_FSYNC_DIR(artifact->dirfd) != 0)
            goto rollback;
        NC_ADV_FAULT_POINT("artifact_published");
    }

    journal.state = NC_ADV_JOURNAL_COMMITTED;
    if (nc_adv_journal_write(journal_dirfd, &journal, 0) != 0)
        goto rollback;
    committed = 1;
    NC_ADV_FAULT_POINT("journal_committed");
    for (i = 0; i < count; i++) {
        struct nc_adv_artifact *artifact = &artifacts[i];
        if (artifact->backup_made &&
            unlinkat(artifact->dirfd, artifact->backup_name, 0) != 0)
            goto rollback;
        artifact->backup_made = 0;
        if (NC_ADV_FSYNC_DIR(artifact->dirfd) != 0)
            goto rollback;
        NC_ADV_FAULT_POINT("artifact_cleanup");
    }
    if (unlinkat(journal_dirfd, NC_ADV_JOURNAL_NAME, 0) != 0 ||
        NC_ADV_FSYNC_DIR(journal_dirfd) != 0)
        goto rollback;
    close(lockfd);
    close(journal_dirfd);
    return 0;

rollback:
    if (!journal_owned) {
        nc_adv_artifacts_abort(artifacts, count, 0);
        if (lockfd >= 0)
            close(lockfd);
        if (journal_dirfd >= 0)
            close(journal_dirfd);
        return -1;
    }
    nc_adv_artifacts_init(recovery_artifacts, NC_ADV_ARTIFACT_COUNT);
    if (nc_adv_recover_publish_locked(journal_dir_path, recovery_artifacts,
                                      count, &recovered_committed) == 0) {
        if (lockfd >= 0)
            close(lockfd);
        if (journal_dirfd >= 0)
            close(journal_dirfd);
        return (committed || recovered_committed) ? 0 : -1;
    } else {
        LOG_ERROR("advanced routing publish rollback requires startup recovery\n");
    }
    if (lockfd >= 0)
        close(lockfd);
    if (journal_dirfd >= 0)
        close(journal_dirfd);
    return -1;
}

static void nc_adv_artifacts_close(struct nc_adv_artifact *artifacts,
                                   size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (artifacts[i].dirfd >= 0) {
            close(artifacts[i].dirfd);
            artifacts[i].dirfd = -1;
        }
    }
}

static void nc_adv_artifacts_init(struct nc_adv_artifact *artifacts,
                                  size_t count)
{
    if (!artifacts || count != NC_ADV_ARTIFACT_COUNT)
        return;
    memset(artifacts, 0, sizeof(*artifacts) * count);
    for (size_t i = 0; i < count; i++) {
        artifacts[i].dir_path = nc_adv_artifact_specs[i].dir_path;
        artifacts[i].name = nc_adv_artifact_specs[i].name;
        artifacts[i].mode = nc_adv_artifact_specs[i].mode;
        artifacts[i].dirfd = -1;
    }
}

static int nc_adv_recover_pending_publish(void)
{
    struct nc_adv_artifact artifacts[NC_ADV_ARTIFACT_COUNT];

    nc_adv_artifacts_init(artifacts, NC_ADV_ARTIFACT_COUNT);
    return nc_adv_recover_publish(NC_ADV_JOURNAL_DIR, artifacts,
                                  NC_ADV_ARTIFACT_COUNT);
}

static int nc_adv_generate_rt_tables(FILE *fp)
{
    sqlite3_stmt *st = NULL;
    int step_rc;

    if (!fp || nc_prepare(&st,
        "SELECT table_id,id FROM route_table WHERE enabled=1 ORDER BY table_id") != 0)
        return -1;
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 1);
        int table_id = sqlite3_column_int(st, 0);
        if (!id || !nc_adv_id_ok(id) || !nc_adv_table_id_ok(table_id) ||
            fprintf(fp, "%d dwrt_%s\n", table_id, id) < 0) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK || ferror(fp))
        return -1;
    return 0;
}

static int nc_adv_generate_draft_config(FILE *fp)
{
    sqlite3_stmt *st = NULL;
    int step_rc;

    if (!fp || fprintf(fp,
        "# generated by jmxd; runtime source for network route/route6 + policy routing\n") < 0 ||
        nc_prepare(&st,
        "SELECT id,family,destination,gateway,interface,route_table,metric,mtu,route_type,comment FROM static_route WHERE enabled=1 ORDER BY metric,id") != 0)
        return -1;
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *family = (const char *)sqlite3_column_text(st, 1);
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *destination = (const char *)sqlite3_column_text(st, 2);
        const char *gateway = (const char *)sqlite3_column_text(st, 3);
        const char *ifname = (const char *)sqlite3_column_text(st, 4);
        const char *table = (const char *)sqlite3_column_text(st, 5);
        const char *type = (const char *)sqlite3_column_text(st, 8);
        const char *comment = (const char *)sqlite3_column_text(st, 9);
        int af = family && !strcmp(family, "ipv6") ? AF_INET6 : AF_INET;
        int metric = sqlite3_column_int(st, 6);
        int mtu = sqlite3_column_int(st, 7);
        int table_id = 0;
        char table_text[16];

        if (!id || !nc_adv_id_ok(id) ||
            (!family || (strcmp(family, "ipv4") && strcmp(family, "ipv6"))) ||
            !nc_adv_ip_cidr_ok(destination, af, 0) ||
            !nc_adv_ip_cidr_ok(gateway, af, 1) ||
            !nc_adv_ifname_ok(ifname, 1) || !nc_adv_route_type_ok(type) ||
            !nc_adv_text_ok(comment, 512) || metric < 0 || metric > 1000000 ||
            mtu < 576 || mtu > 65535 ||
            nc_adv_table_id_by_name(table, &table_id) != 0 || table_id <= 0) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(table_text, sizeof(table_text), "%d", table_id);
        if (fprintf(fp, "config %s '%s'\n",
                    af == AF_INET6 ? "route6" : "route", id) < 0 ||
            (ifname && ifname[0] && nc_fw_uci_value(fp, "option interface", ifname) != 0) ||
            nc_fw_uci_value(fp, "option target", destination) != 0 ||
            (gateway && gateway[0] && nc_fw_uci_value(fp, "option gateway", gateway) != 0) ||
            nc_fw_uci_int(fp, "option metric", metric) != 0 ||
            nc_fw_uci_value(fp, "option table", table_text) != 0 ||
            nc_fw_uci_int(fp, "option mtu", mtu) != 0 ||
            nc_fw_uci_value(fp, "option type", type) != 0 ||
            nc_fw_uci_value(fp, "option comment", comment ? comment : "") != 0 ||
            fputc('\n', fp) == EOF) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK || ferror(fp))
        return -1;
    return 0;
}

static int nc_adv_set_apply_state(const char *state, int set_apply_time)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (nc_prepare(&st, set_apply_time
        ? "UPDATE advanced_routing_global SET apply_state=?1,last_apply_at=strftime('%s','now'),updated_at=strftime('%s','now') WHERE id=1"
        : "UPDATE advanced_routing_global SET apply_state=?1,updated_at=strftime('%s','now') WHERE id=1") != 0)
        return -1;
    if (sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        nc_step_done(st) == 0 && sqlite3_changes(g_netconfig_db) == 1)
        rc = 0;
    if (sqlite3_finalize(st) != SQLITE_OK)
        rc = -1;
    return rc;
}

struct json_object *jmx_advanced_routing_apply(struct json_object *cfg)
{
    const char *rt_path = "/etc/iproute2/rt_tables.d/dreamingwrt.conf";
    const char *draft_path = "/etc/config/dreamingwrt_advanced_routing";
    const char *script_path = "/etc/dreamingwrt/advanced_routing_apply.sh";
    const char *nft_path = "/etc/dreamingwrt/advanced_routing_pbr.nft";
    const char *failed_stage = "";
    const char *reason = "";
    const char *apply_state = "dry_run";
    int dry = nc_json_bool_def(cfg, "dry_run", 0);
    int apply_runtime = nc_json_bool_def(cfg, "apply_runtime", 1);
    int artifact_generated = 0;
    int runtime_attempted = 0;
    int runtime_applied = 0;
    int readback_verified = 0;
    int response_ok = 1;
    int apply_rc = 0;
    uint64_t transaction_id = 0;
    int tables = 0, routes = 0, objects = 0, cross = 0, rules = 0;
    char log_path[256] = "";
    char runtime_readback_reason[128] = "";
    struct json_object *d = json_object_new_object();
    struct json_object *warnings = json_object_new_array();
    struct json_object *summary = json_object_new_object();
    struct json_object *runtime = json_object_new_object();
    sqlite3_stmt *st = NULL;
    struct nc_adv_artifact artifacts[NC_ADV_ARTIFACT_COUNT];
    const size_t artifact_count = sizeof(artifacts) / sizeof(artifacts[0]);
