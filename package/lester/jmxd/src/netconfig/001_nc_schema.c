/* ══════════════════════════════════════════════════════════════════════
 * Schema
 * ══════════════════════════════════════════════════════════════════════ */

static int nc_schema(void)
{
    const char *sql =
        "CREATE TABLE IF NOT EXISTS network_meta ("
        " key TEXT PRIMARY KEY, value TEXT NOT NULL);"

        "CREATE TABLE IF NOT EXISTS config_migration ("
        " name TEXT PRIMARY KEY, status TEXT NOT NULL,"
        " source TEXT NOT NULL DEFAULT '', imported_rows INTEGER NOT NULL DEFAULT 0,"
        " imported_at INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '');"

        "CREATE TABLE IF NOT EXISTS legacy_jmx_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " lan_ifname TEXT NOT NULL DEFAULT 'br-lan',"
        " theme_mode INTEGER NOT NULL DEFAULT 1 CHECK(theme_mode IN (0,1)),"
        " record_time INTEGER NOT NULL DEFAULT 3 CHECK(record_time>=0),"
        " app_valid_time INTEGER NOT NULL DEFAULT 3 CHECK(app_valid_time>=0),"
        " history_data_size TEXT NOT NULL DEFAULT '10',"
        " history_data_path TEXT NOT NULL DEFAULT '/tmp/jmx',"
        " monitor_device TEXT NOT NULL DEFAULT '',"
        " health_flush_sec INTEGER NOT NULL DEFAULT 60 CHECK(health_flush_sec>0),"
        " health_prune_sec INTEGER NOT NULL DEFAULT 300 CHECK(health_prune_sec>0),"
        " health_max_age_days INTEGER NOT NULL DEFAULT 30 CHECK(health_max_age_days>0),"
        " updated_at INTEGER NOT NULL DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS observability_retention_profile ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " profile_name TEXT NOT NULL DEFAULT 'dwrt-observability-v1',"
        " version INTEGER NOT NULL DEFAULT 1 CHECK(version>0),"
        " age_days INTEGER NOT NULL DEFAULT 90 CHECK(age_days BETWEEN 1 AND 730),"
        " row_cap INTEGER NOT NULL DEFAULT 65536 CHECK(row_cap BETWEEN 1024 AND 1000000),"
        " byte_cap INTEGER NOT NULL DEFAULT 268435456 CHECK(byte_cap BETWEEN 16777216 AND 2147483648),"
        " updated_at INTEGER NOT NULL DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS client_nickname ("
        " mac TEXT PRIMARY KEY COLLATE NOCASE,"
        " nickname TEXT NOT NULL,"
        " updated_at INTEGER NOT NULL);"

        "CREATE TABLE IF NOT EXISTS work_mode_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " mode INTEGER NOT NULL DEFAULT 0 CHECK(mode IN (0,1)),"
        " wan_required INTEGER NOT NULL DEFAULT 1,"
        " dhcp_policy TEXT NOT NULL DEFAULT 'enabled',"
        " nat_policy TEXT NOT NULL DEFAULT 'enabled',"
        " apply_state TEXT NOT NULL DEFAULT 'ready',"
        " last_apply_id TEXT NOT NULL DEFAULT '',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS work_mode_snapshot ("
        " rollback_id TEXT PRIMARY KEY,"
        " previous_mode INTEGER NOT NULL CHECK(previous_mode IN (0,1)),"
        " previous_wan_required INTEGER NOT NULL,"
        " previous_dhcp_policy TEXT NOT NULL,"
        " previous_nat_policy TEXT NOT NULL,"
        " created_at INTEGER NOT NULL);"

        "CREATE TABLE IF NOT EXISTS wan ("
        " id TEXT PRIMARY KEY, name TEXT NOT NULL, note TEXT DEFAULT '',"
        " carrier TEXT DEFAULT '', ifname TEXT NOT NULL, device TEXT NOT NULL,"
        " port_label TEXT DEFAULT '', access_mode TEXT NOT NULL DEFAULT 'dhcp',"
        " gateway TEXT DEFAULT '', dns_json TEXT DEFAULT '[]',"
        " ipv6_mode TEXT DEFAULT 'disabled', ipv6_addr TEXT DEFAULT '',"
        " delegated_prefix TEXT DEFAULT '', vlan_enabled INTEGER DEFAULT 0,"
        " vlan_id TEXT DEFAULT '', mtu INTEGER DEFAULT 1500,"
        " metric INTEGER DEFAULT 10, role TEXT DEFAULT 'primary',"
        " expected_down_mbps INTEGER DEFAULT 0, expected_up_mbps INTEGER DEFAULT 0,"
        " smart_queue INTEGER DEFAULT 0, upnp INTEGER DEFAULT 0,"
        " ddns INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1,"
        " username TEXT DEFAULT '', password_ref TEXT DEFAULT '',"
        " pppoe_multi_json TEXT DEFAULT '{}',"
        /* Multi-WAN scheduling inputs, one per line.
         * weight: relative share under network_global.wan_mode='load_balance'.
         *   100 is the neutral default, matching flow_group_members.weight so
         *   the two models read on the same scale.
         * priority: order under wan_mode='failover'. 0 means "not set
         *   explicitly", and the projection then reports metric, which is what
         *   actually drives route selection today. */
        " weight INTEGER DEFAULT 100, priority INTEGER DEFAULT 0,"
        " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"

        "CREATE TABLE IF NOT EXISTS wan_dns_policy ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " wan_id TEXT NOT NULL,"
        " upstream_id TEXT DEFAULT '',"
        " mode TEXT NOT NULL DEFAULT 'auto',"
        " dns_servers TEXT DEFAULT '[]',"
        " domains TEXT DEFAULT '[]',"
        " sort_order INTEGER DEFAULT 0,"
        " enabled INTEGER DEFAULT 1,"
        " updated_at INTEGER NOT NULL,"
        " FOREIGN KEY(wan_id) REFERENCES wan(id) ON DELETE CASCADE);"

        "CREATE TABLE IF NOT EXISTS wan_address ("
        " id TEXT PRIMARY KEY, wan_id TEXT NOT NULL,"
        " ip TEXT NOT NULL, prefix INTEGER NOT NULL,"
        " is_primary INTEGER DEFAULT 0, sort_order INTEGER NOT NULL,"
        " UNIQUE(wan_id, ip, prefix));"

        "CREATE TABLE IF NOT EXISTS wan_advanced ("
        " wan_id TEXT PRIMARY KEY,"
        " default_route INTEGER DEFAULT 0, failover INTEGER DEFAULT 1,"
        " link_time TEXT DEFAULT '00:00-23:59',"
        " health_enabled INTEGER DEFAULT 1, health_mode TEXT DEFAULT 'ping',"
        " health_targets_json TEXT DEFAULT '[]',"
        " dhcp_hostname TEXT DEFAULT '', dhcp_vendor_class TEXT DEFAULT '',"
        " dhcp_client_id TEXT DEFAULT '',"
        " pppoe_timing_restart INTEGER DEFAULT 0,"
        " pppoe_restart_week TEXT DEFAULT '1234567',"
        " pppoe_restart_time TEXT DEFAULT '04:00',"
        " pppoe_abnormal_ip_check INTEGER DEFAULT 0,"
        " pppoe_abnormal_ip_prefixes TEXT DEFAULT '10,172,192.168');"

        "CREATE TABLE IF NOT EXISTS wan_bond ("
        " wan_id TEXT PRIMARY KEY,"
        " enabled INTEGER DEFAULT 0, bond_name TEXT DEFAULT '',"
        " mode TEXT DEFAULT '802.3ad', hash_policy TEXT DEFAULT 'layer3+4',"
        " members_json TEXT DEFAULT '[]');"

        "CREATE TABLE IF NOT EXISTS lan ("
        " id TEXT PRIMARY KEY, name TEXT NOT NULL, note TEXT DEFAULT '',"
        " ifname TEXT NOT NULL, device TEXT NOT NULL,"
        " mode TEXT NOT NULL DEFAULT 'bridge',"
        " parent_lan_id TEXT DEFAULT '', vlan_id TEXT DEFAULT '',"
        " mac_clone TEXT DEFAULT '', speed TEXT DEFAULT '0',"
        " duplex TEXT DEFAULT '0', lan_visit INTEGER DEFAULT 1,"
        " enabled INTEGER DEFAULT 1,"
        " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"

        "CREATE TABLE IF NOT EXISTS lan_port ("
        " id TEXT PRIMARY KEY, lan_id TEXT NOT NULL,"
        " port TEXT NOT NULL, label TEXT DEFAULT '',"
        " sort_order INTEGER NOT NULL, UNIQUE(lan_id, port));"

        "CREATE TABLE IF NOT EXISTS lan_address ("
        " id TEXT PRIMARY KEY, lan_id TEXT NOT NULL,"
        " ip TEXT NOT NULL, prefix INTEGER NOT NULL,"
        " is_primary INTEGER DEFAULT 0, sort_order INTEGER NOT NULL,"
        " UNIQUE(lan_id, ip, prefix));"

        "CREATE TABLE IF NOT EXISTS lan_dhcp ("
        " lan_id TEXT PRIMARY KEY,"
        " enabled INTEGER DEFAULT 1, tagname TEXT DEFAULT '',"
        " pool_start TEXT DEFAULT '', pool_end TEXT DEFAULT '',"
        " exclude_pool_json TEXT DEFAULT '[]',"
        " gateway TEXT DEFAULT '', dns_json TEXT DEFAULT '[]',"
        " lease_minutes INTEGER DEFAULT 120);"

        "CREATE TABLE IF NOT EXISTS lan_ipv6 ("
        " lan_id TEXT PRIMARY KEY,"
        " enabled INTEGER DEFAULT 0, parent_wans_json TEXT DEFAULT '[]',"
        " mode TEXT DEFAULT 'dhcp', dhcpv6 INTEGER DEFAULT 1,"
        " static_addr TEXT DEFAULT '', use_dns6 INTEGER DEFAULT 0,"
        " dns6_json TEXT DEFAULT '[]', prefix_len TEXT DEFAULT 'auto',"
        " ra_flags TEXT DEFAULT '1', ra_static INTEGER DEFAULT 0,"
        " ra_mtu_set INTEGER DEFAULT 0, ra_mtu INTEGER DEFAULT 1480,"
        " lease_minutes INTEGER DEFAULT 120);"

        "CREATE TABLE IF NOT EXISTS network_global ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " default_posture TEXT DEFAULT 'allow',"
        " mdns_proxy TEXT DEFAULT 'auto',"
        " igmp_snooping INTEGER DEFAULT 0,"
        " stp_mode TEXT DEFAULT 'rstp',"
        " rogue_dhcp_detection INTEGER DEFAULT 0,"
        " jumbo_frames INTEGER DEFAULT 0,"
        " flow_control INTEGER DEFAULT 0,"
        " dot1x INTEGER DEFAULT 0,"
        " wan_mode TEXT DEFAULT 'failover',"
        " bridge_stp INTEGER DEFAULT 1, bridge_forward_delay INTEGER DEFAULT 2);"

        "CREATE TABLE IF NOT EXISTS radius_server ("
        " id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " auth_addr TEXT DEFAULT '', auth_port INTEGER DEFAULT 1812,"
        " accounting_addr TEXT DEFAULT '', accounting_port INTEGER DEFAULT 1813,"
        " secret_ref TEXT DEFAULT '', enabled INTEGER DEFAULT 1);"

        "CREATE TABLE IF NOT EXISTS physical_port ("
        " name TEXT PRIMARY KEY, label TEXT DEFAULT '',"
        " kind TEXT DEFAULT 'ethernet', speed_label TEXT DEFAULT '',"
        " duplex TEXT DEFAULT '',"
        " owner_type TEXT DEFAULT '', owner_id TEXT DEFAULT '',"
        " status TEXT DEFAULT '', updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS physical_port_config ("
        " ifname TEXT PRIMARY KEY,"
        " configured_speed_mbps INTEGER DEFAULT 0,"
        " configured_duplex TEXT DEFAULT '',"
        " configured_autoneg INTEGER DEFAULT -1,"
        " profile_id TEXT DEFAULT '',"
        " native_vlan INTEGER DEFAULT 0,"
        " tagged_vlans_json TEXT DEFAULT '[]',"
        " poe_enabled INTEGER DEFAULT -1,"
        " poe_mode TEXT DEFAULT '',"
        " display_name TEXT DEFAULT '',"
        " sort_order INTEGER DEFAULT 0,"
        " updated_at INTEGER DEFAULT 0,"
        " last_apply_at INTEGER DEFAULT 0,"
        " last_apply_ok INTEGER DEFAULT 0,"
        " last_apply_error TEXT DEFAULT '');"

        "CREATE TABLE IF NOT EXISTS physical_port_profile ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " native_vlan INTEGER DEFAULT 0,"
        " tagged_vlans_json TEXT DEFAULT '[]',"
        " poe_enabled INTEGER DEFAULT -1,"
        " poe_mode TEXT DEFAULT '',"
        " stp_guard TEXT DEFAULT '',"
        " storm_control TEXT DEFAULT '',"
        " description TEXT DEFAULT '',"
        " updated_at INTEGER DEFAULT 0,"
        " created_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS hybrid_line ("
        " id TEXT PRIMARY KEY, parent_wan_id TEXT NOT NULL,"
        " name TEXT NOT NULL, comment TEXT DEFAULT '',"
        " mode TEXT NOT NULL, vlan_id TEXT DEFAULT '', mac TEXT DEFAULT '',"
        " proto TEXT NOT NULL, enabled INTEGER DEFAULT 1,"
        " default_route INTEGER DEFAULT 0, failover INTEGER DEFAULT 1,"
        " check_host TEXT DEFAULT 'www.baidu.com',"
        " ip TEXT DEFAULT '', prefix INTEGER DEFAULT 24,"
        " gateway TEXT DEFAULT '', username TEXT DEFAULT '',"
        " password_ref TEXT DEFAULT '',"
        " pppoe_ac TEXT DEFAULT '', pppoe_ac_mac TEXT DEFAULT '',"
        " pppoe_service TEXT DEFAULT '',"
        " mtu INTEGER DEFAULT 1480, mru INTEGER DEFAULT 1480,"
        " upload_mbps INTEGER DEFAULT 0, download_mbps INTEGER DEFAULT 0,"
        " UNIQUE(parent_wan_id, name));"

        "CREATE TABLE IF NOT EXISTS dhcp_scope ("
        " id TEXT PRIMARY KEY, lan_id TEXT NOT NULL, enabled INTEGER DEFAULT 1,"
        " tagname TEXT DEFAULT '', pool_start TEXT DEFAULT '', pool_end TEXT DEFAULT '',"
        " exclude_pool TEXT DEFAULT '', gateway TEXT DEFAULT '', netmask TEXT DEFAULT '',"
        " dns1 TEXT DEFAULT '', dns2 TEXT DEFAULT '', lease_minutes INTEGER DEFAULT 120,"
        " domain TEXT DEFAULT '', updated_at INTEGER DEFAULT 0, UNIQUE(lan_id));"

        "CREATE TABLE IF NOT EXISTS dhcp_option ("
        " id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, code TEXT NOT NULL,"
        " value TEXT NOT NULL, sort_order INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS dhcp_reservation ("
        " id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, name TEXT DEFAULT '',"
        " mac TEXT NOT NULL, ip TEXT NOT NULL, remark TEXT DEFAULT '', enabled INTEGER DEFAULT 1,"
        " UNIQUE(scope_id, mac), UNIQUE(scope_id, ip));"

        "CREATE TABLE IF NOT EXISTS dhcp_access_entry ("
        " id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, action TEXT NOT NULL,"
        " mac TEXT NOT NULL, name TEXT DEFAULT '', remark TEXT DEFAULT '',"
        " enabled INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0, updated_at INTEGER DEFAULT 0,"
        " CHECK(action IN ('allow','deny')), UNIQUE(scope_id, mac));"

        "CREATE TABLE IF NOT EXISTS dhcpv6_prefix_reservation ("
        " id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, lan_id TEXT NOT NULL,"
        " name TEXT DEFAULT '', duid TEXT NOT NULL, iaid TEXT DEFAULT '',"
        " prefix TEXT NOT NULL, hostid TEXT NOT NULL, prefix_len INTEGER NOT NULL,"
        " remark TEXT DEFAULT '', enabled INTEGER DEFAULT 1, lease_minutes INTEGER DEFAULT 120,"
        " sort_order INTEGER DEFAULT 0, apply_state TEXT DEFAULT 'pending',"
        " runtime_configured INTEGER DEFAULT 0, runtime_bound INTEGER DEFAULT 0,"
        " runtime_prefix TEXT DEFAULT '', runtime_duid TEXT DEFAULT '',"
        " last_apply_at INTEGER DEFAULT 0, created_at INTEGER DEFAULT 0, updated_at INTEGER DEFAULT 0,"
        " UNIQUE(scope_id, duid), UNIQUE(scope_id, prefix),"
        " CHECK(prefix_len BETWEEN 33 AND 64));"

        "CREATE TABLE IF NOT EXISTS dhcp_lease_cache ("
        " mac TEXT PRIMARY KEY, scope_id TEXT, hostname TEXT DEFAULT '', ip TEXT NOT NULL,"
        " expires_at INTEGER DEFAULT 0, online INTEGER DEFAULT 0, updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS upnp_service ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " enabled INTEGER DEFAULT 0, natpmp_enabled INTEGER DEFAULT 1, secure_mode INTEGER DEFAULT 1,"
        " external_iface TEXT DEFAULT '', presentation_url TEXT DEFAULT '',"
        " download_mbps INTEGER DEFAULT 0, upload_mbps INTEGER DEFAULT 0,"
        " lease_file TEXT DEFAULT '/var/run/miniupnpd.leases', uuid TEXT DEFAULT '',"
        " model_name TEXT DEFAULT 'DreamingWrt Gateway',"
        " port_start INTEGER DEFAULT 1024, port_end INTEGER DEFAULT 65535,"
        " notify_interval INTEGER DEFAULT 30, clean_interval INTEGER DEFAULT 600,"
        " log_packets INTEGER DEFAULT 0, system_uptime INTEGER DEFAULT 1,"
        " use_stun INTEGER DEFAULT 0, stun_host TEXT DEFAULT '', stun_port INTEGER DEFAULT 3478,"
        " pcp INTEGER DEFAULT 1, updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS upnp_internal_iface ("
        " service_id INTEGER NOT NULL DEFAULT 1, lan_id TEXT NOT NULL,"
        " PRIMARY KEY(service_id, lan_id));"

        "CREATE TABLE IF NOT EXISTS upnp_acl ("
        " id TEXT PRIMARY KEY, action TEXT NOT NULL DEFAULT 'allow',"
        " external_ports TEXT NOT NULL DEFAULT '1024-65535',"
        " internal_cidr TEXT NOT NULL DEFAULT '0.0.0.0/0',"
        " internal_ports TEXT NOT NULL DEFAULT '1-65535',"
        " remark TEXT DEFAULT '', enabled INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0,"
        " managed TEXT NOT NULL DEFAULT '');"

        "CREATE TABLE IF NOT EXISTS upnp_mapping_cache ("
        " id TEXT PRIMARY KEY, protocol TEXT NOT NULL, external_port INTEGER NOT NULL,"
        " internal_ip TEXT NOT NULL, internal_port INTEGER NOT NULL, client TEXT DEFAULT '',"
        " description TEXT DEFAULT '', lease_seconds INTEGER DEFAULT 0, packets INTEGER DEFAULT 0,"
        " updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS upnp_migration_state ("
        " key TEXT PRIMARY KEY, value TEXT DEFAULT '', updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS dns_service ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " enabled INTEGER DEFAULT 1, mode TEXT DEFAULT 'proxy',"
        " listen_port INTEGER DEFAULT 53,"
        " cache_enabled INTEGER DEFAULT 1, cache_size INTEGER DEFAULT 4096,"
        " local_domain TEXT DEFAULT 'lan',"
        " rebind_protection INTEGER DEFAULT 1,"
        " hijack_protection INTEGER DEFAULT 0,"
        " edns_client_subnet INTEGER DEFAULT 0,"
        " ipv6_dns INTEGER DEFAULT 0,"
        " updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS dns_listen_interface ("
        " service_id INTEGER NOT NULL DEFAULT 1,"
        " lan_id TEXT NOT NULL,"
        " PRIMARY KEY(service_id, lan_id));"

        "CREATE TABLE IF NOT EXISTS dns_upstream ("
        " id TEXT PRIMARY KEY, name TEXT DEFAULT '',"
        " address TEXT NOT NULL, port INTEGER DEFAULT 53,"
        " protocol TEXT DEFAULT 'udp', group_name TEXT DEFAULT '默认',"
        " enabled INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS dns_rule ("
        " id TEXT PRIMARY KEY, domain TEXT NOT NULL,"
        " type TEXT NOT NULL, target TEXT DEFAULT '',"
        " remark TEXT DEFAULT '', enabled INTEGER DEFAULT 1,"
        " sort_order INTEGER DEFAULT 0, UNIQUE(domain, type));"

        "CREATE TABLE IF NOT EXISTS dns_runtime_stat ("
        " key TEXT PRIMARY KEY, value TEXT DEFAULT '',"
        " updated_at INTEGER DEFAULT 0);"

        "CREATE TABLE IF NOT EXISTS client_control_rules ("
        " id TEXT PRIMARY KEY,"
        " mac TEXT NOT NULL,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " control_type TEXT NOT NULL DEFAULT 'IP限速',"
        " schedule_mode TEXT NOT NULL DEFAULT 'week',"
        " days_json TEXT NOT NULL DEFAULT '[]',"
        " days_text TEXT NOT NULL DEFAULT '',"
        " start_time TEXT NOT NULL DEFAULT '00:00',"
        " end_time TEXT NOT NULL DEFAULT '23:59',"
        " limit_mode TEXT NOT NULL DEFAULT '独立限速',"
        " up_limit INTEGER NOT NULL DEFAULT 0,"
        " up_unit TEXT NOT NULL DEFAULT 'KB/s',"
        " down_limit INTEGER NOT NULL DEFAULT 0,"
        " down_unit TEXT NOT NULL DEFAULT 'KB/s',"
        " line TEXT NOT NULL DEFAULT '',"
        " protocol TEXT NOT NULL DEFAULT '任意',"
        " note TEXT NOT NULL DEFAULT '',"
        " runtime_apply INTEGER NOT NULL DEFAULT 0,"
        " apply_state TEXT NOT NULL DEFAULT 'draft',"
        " apply_reason TEXT NOT NULL DEFAULT '',"
        " last_runtime_enabled INTEGER NOT NULL DEFAULT -1,"
        " last_runtime_apply_at INTEGER NOT NULL DEFAULT 0,"
        " last_runtime_reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_client_control_rules_mac "
        "ON client_control_rules(mac,enabled,updated_at);"

        "CREATE TABLE IF NOT EXISTS terminal_group ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL COLLATE NOCASE UNIQUE,"
        " description TEXT NOT NULL DEFAULT '',"
        " color TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS terminal_group_member ("
        " group_id TEXT NOT NULL,"
        " member_key TEXT NOT NULL,"
        " mac TEXT NOT NULL DEFAULT '',"
        " ip TEXT NOT NULL DEFAULT '',"
        " display_name TEXT NOT NULL DEFAULT '',"
        " position INTEGER NOT NULL DEFAULT 0,"
        " added_at INTEGER NOT NULL,"
        " PRIMARY KEY(group_id,member_key),"
        " FOREIGN KEY(group_id) REFERENCES terminal_group(id) ON DELETE CASCADE,"
        " CHECK(mac<>'' OR ip<>''));"
        "CREATE INDEX IF NOT EXISTS terminal_group_member_mac_idx "
        "ON terminal_group_member(mac) WHERE mac<>'';"
        "CREATE INDEX IF NOT EXISTS terminal_group_member_ip_idx "
        "ON terminal_group_member(ip) WHERE ip<>'';";

    if (nc_exec(sql) != 0) return -1;
    /* additive migrations for devices that already created network.db before these columns existed */
    nc_add_column_if_missing("wan_advanced", "pppoe_ac", "TEXT DEFAULT ''");
    nc_add_column_if_missing("wan_advanced", "pppoe_ac_mac", "TEXT DEFAULT ''");
    nc_add_column_if_missing("wan_advanced", "pppoe_service", "TEXT DEFAULT ''");
    nc_add_column_if_missing("wan_advanced", "iptv_igmp_version", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("wan_advanced", "iptv_multicast_source", "TEXT DEFAULT 'session'");
    nc_add_column_if_missing("wan_advanced", "iptv_carrier_mode", "TEXT DEFAULT 'dhcp'");
    nc_add_column_if_missing("wan_advanced", "iptv_carrier_address", "TEXT DEFAULT ''");
    nc_add_column_if_missing("wan_advanced", "iptv_carrier_prefix", "INTEGER DEFAULT 24");
    /* network_global.wan_mode: added after the table shipped, so existing
     * network.db files need it backfilled. 'failover' matches the column
     * default and the frontend's historical fallback, so a device upgrading
     * in place keeps its current observable behaviour. */
    nc_add_column_if_missing("network_global", "wan_mode", "TEXT DEFAULT 'failover'");
    /* UPnP: add stun_port and pcp columns if missing */
    nc_add_column_if_missing("upnp_service", "stun_port", "INTEGER DEFAULT 3478");
    nc_add_column_if_missing("upnp_service", "pcp", "INTEGER DEFAULT 1");
    /* C2 removes only the obsolete no-op column; DROP COLUMN preserves all
     * other (including future) service fields on an existing database. */
    if (nc_table_has_column("upnp_service", "force_forwarding") &&
        nc_exec("ALTER TABLE upnp_service DROP COLUMN force_forwarding") != 0)
        return -1;
    if (nc_add_column_if_missing("upnp_acl", "managed", "TEXT NOT NULL DEFAULT ''") != 0)
        return -1;
    nc_add_column_if_missing("physical_port", "speed_label", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port", "duplex", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port", "owner_type", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port", "owner_id", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port", "status", "TEXT DEFAULT ''");
    nc_exec("CREATE TABLE IF NOT EXISTS physical_port_config ("
            " ifname TEXT PRIMARY KEY,"
            " configured_speed_mbps INTEGER DEFAULT 0,"
            " configured_duplex TEXT DEFAULT '',"
            " configured_autoneg INTEGER DEFAULT -1,"
            " profile_id TEXT DEFAULT '',"
            " native_vlan INTEGER DEFAULT 0,"
            " tagged_vlans_json TEXT DEFAULT '[]',"
            " poe_enabled INTEGER DEFAULT -1,"
            " poe_mode TEXT DEFAULT '',"
            " display_name TEXT DEFAULT '',"
            " sort_order INTEGER DEFAULT 0,"
            " updated_at INTEGER DEFAULT 0,"
            " last_apply_at INTEGER DEFAULT 0,"
            " last_apply_ok INTEGER DEFAULT 0,"
            " last_apply_error TEXT DEFAULT '')");
    nc_add_column_if_missing("physical_port_config", "configured_speed_mbps", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_config", "configured_duplex", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_config", "configured_autoneg", "INTEGER DEFAULT -1");
    nc_add_column_if_missing("physical_port_config", "profile_id", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_config", "native_vlan", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_config", "tagged_vlans_json", "TEXT DEFAULT '[]'");
    nc_add_column_if_missing("physical_port_config", "poe_enabled", "INTEGER DEFAULT -1");
    nc_add_column_if_missing("physical_port_config", "poe_mode", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_config", "display_name", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_config", "sort_order", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_config", "updated_at", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_config", "last_apply_at", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_config", "last_apply_ok", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_config", "last_apply_error", "TEXT DEFAULT ''");
    nc_exec("CREATE TABLE IF NOT EXISTS physical_port_profile ("
            " id TEXT PRIMARY KEY,"
            " name TEXT NOT NULL DEFAULT '',"
            " native_vlan INTEGER DEFAULT 0,"
            " tagged_vlans_json TEXT DEFAULT '[]',"
            " poe_enabled INTEGER DEFAULT -1,"
            " poe_mode TEXT DEFAULT '',"
            " stp_guard TEXT DEFAULT '',"
            " storm_control TEXT DEFAULT '',"
            " description TEXT DEFAULT '',"
            " updated_at INTEGER DEFAULT 0,"
            " created_at INTEGER DEFAULT 0)");
    nc_add_column_if_missing("physical_port_profile", "name", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_profile", "native_vlan", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_profile", "tagged_vlans_json", "TEXT DEFAULT '[]'");
    nc_add_column_if_missing("physical_port_profile", "poe_enabled", "INTEGER DEFAULT -1");
    nc_add_column_if_missing("physical_port_profile", "poe_mode", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_profile", "stp_guard", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_profile", "storm_control", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_profile", "description", "TEXT DEFAULT ''");
    nc_add_column_if_missing("physical_port_profile", "updated_at", "INTEGER DEFAULT 0");
    nc_add_column_if_missing("physical_port_profile", "created_at", "INTEGER DEFAULT 0");
    nc_exec("CREATE TABLE IF NOT EXISTS client_control_rules ("
            " id TEXT PRIMARY KEY,"
            " mac TEXT NOT NULL,"
            " name TEXT NOT NULL DEFAULT '',"
            " enabled INTEGER NOT NULL DEFAULT 1,"
            " control_type TEXT NOT NULL DEFAULT 'IP限速',"
            " schedule_mode TEXT NOT NULL DEFAULT 'week',"
            " days_json TEXT NOT NULL DEFAULT '[]',"
            " days_text TEXT NOT NULL DEFAULT '',"
            " start_time TEXT NOT NULL DEFAULT '00:00',"
            " end_time TEXT NOT NULL DEFAULT '23:59',"
            " limit_mode TEXT NOT NULL DEFAULT '独立限速',"
            " up_limit INTEGER NOT NULL DEFAULT 0,"
            " up_unit TEXT NOT NULL DEFAULT 'KB/s',"
            " down_limit INTEGER NOT NULL DEFAULT 0,"
            " down_unit TEXT NOT NULL DEFAULT 'KB/s',"
            " line TEXT NOT NULL DEFAULT '',"
            " protocol TEXT NOT NULL DEFAULT '任意',"
            " note TEXT NOT NULL DEFAULT '',"
            " runtime_apply INTEGER NOT NULL DEFAULT 0,"
            " apply_state TEXT NOT NULL DEFAULT 'draft',"
            " apply_reason TEXT NOT NULL DEFAULT '',"
            " last_runtime_enabled INTEGER NOT NULL DEFAULT -1,"
            " last_runtime_apply_at INTEGER NOT NULL DEFAULT 0,"
            " last_runtime_reason TEXT NOT NULL DEFAULT '',"
            " created_at INTEGER NOT NULL DEFAULT 0,"
            " updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_add_column_if_missing("client_control_rules", "schedule_mode", "TEXT NOT NULL DEFAULT 'week'");
    nc_add_column_if_missing("client_control_rules", "days_json", "TEXT NOT NULL DEFAULT '[]'");
    nc_add_column_if_missing("client_control_rules", "days_text", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("client_control_rules", "runtime_apply", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("client_control_rules", "apply_state", "TEXT NOT NULL DEFAULT 'draft'");
    nc_add_column_if_missing("client_control_rules", "apply_reason", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("client_control_rules", "last_runtime_enabled", "INTEGER NOT NULL DEFAULT -1");
    nc_add_column_if_missing("client_control_rules", "last_runtime_apply_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("client_control_rules", "last_runtime_reason", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("client_control_rules", "created_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("client_control_rules", "updated_at", "INTEGER NOT NULL DEFAULT 0");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_client_control_rules_mac "
            "ON client_control_rules(mac,enabled,updated_at)");

    /* insert schema version */
    sqlite3_stmt *st = NULL;
    int64_t ts = nc_now_s();
    if (nc_prepare(&st,
        "INSERT INTO network_meta(key,value) VALUES('schema_version','1') "
        "ON CONFLICT(key) DO UPDATE SET value='1'") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    nc_exec("PRAGMA application_id=1146573396");
    nc_exec("PRAGMA user_version=1");

    /* ensure global row exists */
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO network_global(id) VALUES(1)") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO work_mode_settings(id) VALUES(1)") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO legacy_jmx_settings(id) VALUES(1)") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO observability_retention_profile(id) VALUES(1)") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    nc_add_column_if_missing("legacy_jmx_settings", "health_flush_sec",
                             "INTEGER NOT NULL DEFAULT 60");
    nc_add_column_if_missing("legacy_jmx_settings", "health_prune_sec",
                             "INTEGER NOT NULL DEFAULT 300");
    nc_add_column_if_missing("legacy_jmx_settings", "health_max_age_days",
                             "INTEGER NOT NULL DEFAULT 30");
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO upnp_service(id,uuid) VALUES(1,'8f8d9b36-dwrt-upnp')") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    nc_add_column_if_missing("network_global", "bridge_stp", "INTEGER DEFAULT 1");
    nc_add_column_if_missing("network_global", "bridge_forward_delay", "INTEGER DEFAULT 2");
    /* PPPoE credential storage for main WAN (hybrid_line already has username/password_ref) */
    nc_add_column_if_missing("wan", "username", "TEXT DEFAULT ''");
    nc_add_column_if_missing("wan", "password_ref", "TEXT DEFAULT ''");
    nc_add_column_if_missing("wan", "pppoe_multi_json", "TEXT DEFAULT '{}'");
    /* wan.weight / wan.priority: added after the table shipped, so an existing
     * network.db needs them backfilled. The defaults keep a device upgrading in
     * place on its current observable behaviour: weight 100 is an equal share,
     * and priority 0 means "unset", which makes the projection fall back to
     * metric - the value that already decides route order. */
    nc_add_column_if_missing("wan", "weight", "INTEGER DEFAULT 100");
    nc_add_column_if_missing("wan", "priority", "INTEGER DEFAULT 0");

    /* ensure dns service row exists */
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO dns_service(id,updated_at) VALUES(1,?1)") == 0) {
        sqlite3_bind_int64(st, 1, ts);
        nc_step_done(st);
        sqlite3_finalize(st);
    }

    /* AI history tables */
    if (nc_prepare(&st,
        "CREATE TABLE IF NOT EXISTS ai_conversation ("
        " id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '',"
        " model TEXT NOT NULL DEFAULT '',"
        " reasoning_effort TEXT NOT NULL DEFAULT 'auto',"
        " message_count INTEGER NOT NULL DEFAULT 0,"
        " prompt_tokens INTEGER NOT NULL DEFAULT 0,"
        " completion_tokens INTEGER NOT NULL DEFAULT 0,"
        " total_tokens INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st,
        "CREATE TABLE IF NOT EXISTS ai_message ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL,"
        " message_id TEXT NOT NULL DEFAULT '',"
        " role TEXT NOT NULL, content TEXT NOT NULL DEFAULT '',"
        " attachments_json TEXT NOT NULL DEFAULT '[]',"
        " created_at INTEGER NOT NULL,"
        " FOREIGN KEY(conversation_id) REFERENCES ai_conversation(id) ON DELETE CASCADE)") == 0) {
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    nc_add_column_if_missing("ai_conversation", "owner", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_conversation", "revision", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("ai_conversation", "execution_backend", "TEXT NOT NULL DEFAULT 'api'");
    nc_add_column_if_missing("ai_conversation", "provider", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_message", "metadata_json", "TEXT NOT NULL DEFAULT '{}'");
    nc_exec("CREATE INDEX IF NOT EXISTS ai_history_owner_updated ON ai_conversation(owner,updated_at DESC,id)");
    nc_add_column_if_missing("ai_message", "message_id", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("ai_message", "attachments_json", "TEXT NOT NULL DEFAULT '[]'");
    nc_exec("UPDATE ai_message SET message_id='msg-' || id WHERE message_id=''");
    nc_exec("CREATE UNIQUE INDEX IF NOT EXISTS ai_message_public_id_idx "
            "ON ai_message(conversation_id,message_id)");

    /* Setup wizard tables.
     *
     * These three shipped without ever being created here. jmx_setup.c only
     * ever reads them or issues "UPDATE ... WHERE id=1", so on a factory-new
     * device the table was absent, the UPDATE touched 0 rows, and
     * /api/setup/start answered 400 setup_state_update_failed -- the wizard
     * could not get past its first step. Devices that do have the tables got
     * them from an older build, so the fix has to adopt what is already there
     * rather than replace it: IF NOT EXISTS plus INSERT OR IGNORE keeps an
     * initialized=1 device exactly as it is, and nc_add_column_if_missing
     * below backfills any column a legacy layout is missing instead of
     * rebuilding the table and losing the completion state.
     */
    nc_exec("CREATE TABLE IF NOT EXISTS setup_state ("
            " id INTEGER PRIMARY KEY CHECK(id=1),"
            " initialized INTEGER NOT NULL DEFAULT 0,"
            " initialized_at INTEGER NOT NULL DEFAULT 0,"
            " initialized_version TEXT NOT NULL DEFAULT '',"
            " completed_by TEXT NOT NULL DEFAULT '',"
            " assist_mode TEXT NOT NULL DEFAULT 'manual',"
            " current_step TEXT NOT NULL DEFAULT 'intro',"
            " setup_id TEXT NOT NULL DEFAULT '',"
            " started_at INTEGER NOT NULL DEFAULT 0,"
            " source TEXT NOT NULL DEFAULT '',"
            " setup_version TEXT NOT NULL DEFAULT '',"
            " last_apply_id TEXT NOT NULL DEFAULT '',"
            " last_apply_state TEXT NOT NULL DEFAULT 'idle',"
            " last_apply_error TEXT NOT NULL DEFAULT '',"
            " last_apply_at INTEGER NOT NULL DEFAULT 0,"
            " last_test_ok INTEGER NOT NULL DEFAULT 0,"
            " last_test_json TEXT NOT NULL DEFAULT '{}',"
            " updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_add_column_if_missing("setup_state", "initialized", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_state", "initialized_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_state", "initialized_version", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "completed_by", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "assist_mode", "TEXT NOT NULL DEFAULT 'manual'");
    nc_add_column_if_missing("setup_state", "current_step", "TEXT NOT NULL DEFAULT 'intro'");
    nc_add_column_if_missing("setup_state", "setup_id", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "started_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_state", "source", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "setup_version", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "last_apply_id", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "last_apply_state", "TEXT NOT NULL DEFAULT 'idle'");
    nc_add_column_if_missing("setup_state", "last_apply_error", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_state", "last_apply_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_state", "last_test_ok", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_state", "last_test_json", "TEXT NOT NULL DEFAULT '{}'");
    nc_add_column_if_missing("setup_state", "updated_at", "INTEGER NOT NULL DEFAULT 0");

    nc_exec("CREATE TABLE IF NOT EXISTS setup_draft ("
            " kind TEXT PRIMARY KEY,"
            " payload_json TEXT NOT NULL DEFAULT '{}',"
            " updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_add_column_if_missing("setup_draft", "payload_json", "TEXT NOT NULL DEFAULT '{}'");
    nc_add_column_if_missing("setup_draft", "updated_at", "INTEGER NOT NULL DEFAULT 0");

    nc_exec("CREATE TABLE IF NOT EXISTS setup_wan_detect ("
            " id INTEGER PRIMARY KEY CHECK(id=1),"
            " state TEXT NOT NULL DEFAULT 'idle',"
            " started_at INTEGER NOT NULL DEFAULT 0,"
            " finished_at INTEGER NOT NULL DEFAULT 0,"
            " recommended_device TEXT NOT NULL DEFAULT '',"
            " recommended_proto TEXT NOT NULL DEFAULT '',"
            " confidence INTEGER NOT NULL DEFAULT 0,"
            " result_json TEXT NOT NULL DEFAULT '{}',"
            " error TEXT NOT NULL DEFAULT '',"
            " updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_add_column_if_missing("setup_wan_detect", "state", "TEXT NOT NULL DEFAULT 'idle'");
    nc_add_column_if_missing("setup_wan_detect", "started_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_wan_detect", "finished_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_wan_detect", "recommended_device", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_wan_detect", "recommended_proto", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_wan_detect", "confidence", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("setup_wan_detect", "result_json", "TEXT NOT NULL DEFAULT '{}'");
    nc_add_column_if_missing("setup_wan_detect", "error", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("setup_wan_detect", "updated_at", "INTEGER NOT NULL DEFAULT 0");

    /* Seed rows for the two singleton tables. Without an id=1 row the wizard's
     * "UPDATE ... WHERE id=1" still matches nothing, which is the same 400 as a
     * missing table. OR IGNORE leaves an existing row untouched. setup_draft is
     * keyed by kind and seeds itself on first save, so it needs no seed row. */
    nc_exec("INSERT OR IGNORE INTO setup_state(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO setup_wan_detect(id) VALUES(1)");

    (void)ts;
    LOG_INFO("network.db schema v1 ready\n");
    return 0;
}
