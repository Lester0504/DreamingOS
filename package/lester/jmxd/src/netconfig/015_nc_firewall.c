/* ══════════════════════════════════════════════════════════════════════
 * Firewall service: product state for firewall4/nftables
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_firewall_db_init(void)
{
    nc_netctl_db_init();
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_global (id INTEGER PRIMARY KEY CHECK (id = 1),geo_block INTEGER DEFAULT 0,identify_mode TEXT DEFAULT 'device_and_traffic',ids_enabled INTEGER DEFAULT 0,syn_flood INTEGER DEFAULT 1,invalid_drop INTEGER DEFAULT 0,fullcone_nat TEXT DEFAULT 'off',fullcone_nat6 INTEGER DEFAULT 0,nat6 INTEGER DEFAULT 0,flow_offload TEXT DEFAULT 'none',default_input TEXT DEFAULT 'accept',default_output TEXT DEFAULT 'accept',default_forward TEXT DEFAULT 'reject',updated_at INTEGER DEFAULT 0)");
    nc_add_column_if_missing("firewall_global", "conntrack_max", "INTEGER NOT NULL DEFAULT 0");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_zone (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,networks TEXT NOT NULL DEFAULT '',input TEXT NOT NULL DEFAULT 'reject',output TEXT NOT NULL DEFAULT 'accept',forward TEXT NOT NULL DEFAULT 'reject',masq INTEGER DEFAULT 0,mtu_fix INTEGER DEFAULT 0,forwards TEXT NOT NULL DEFAULT '',enabled INTEGER DEFAULT 1,sort_order INTEGER DEFAULT 1000)");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_rule (id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,name TEXT NOT NULL,stack TEXT DEFAULT 'ipv4',proto TEXT DEFAULT 'all',action TEXT DEFAULT 'reject',direction_match TEXT DEFAULT 'stateful',direction TEXT DEFAULT '',priority INTEGER DEFAULT 1000,src TEXT DEFAULT 'any',dest TEXT DEFAULT 'any',src_port TEXT DEFAULT 'any',dest_port TEXT DEFAULT 'any',in_iface TEXT DEFAULT '',out_iface TEXT DEFAULT '',schedule TEXT DEFAULT 'always',remark TEXT DEFAULT '',sort_order INTEGER DEFAULT 1000,updated_at INTEGER DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_forward (id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,name TEXT NOT NULL,proto TEXT DEFAULT 'tcp',src TEXT DEFAULT 'wan',src_dport TEXT DEFAULT '',dest TEXT DEFAULT 'lan',dest_ip TEXT DEFAULT '',dest_port TEXT DEFAULT '',reflection INTEGER DEFAULT 0,remark TEXT DEFAULT '',updated_at INTEGER DEFAULT 0)");
    /* Geo-block tables */
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_geo_country ("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL DEFAULT '',"
        "continent TEXT NOT NULL DEFAULT '',"
        "code TEXT NOT NULL DEFAULT '',"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "sort_order INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_add_column_if_missing("firewall_geo_country", "name_en", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("firewall_geo_country", "name_zh", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("firewall_geo_country", "official", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("firewall_geo_country", "source", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("firewall_geo_country", "updated_at", "INTEGER NOT NULL DEFAULT 0");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_geo_meta ("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "revision INTEGER NOT NULL DEFAULT 0,"
        "apply_state TEXT NOT NULL DEFAULT 'draft',"
        "last_apply_at INTEGER NOT NULL DEFAULT 0,"
        "last_apply_ok INTEGER NOT NULL DEFAULT 0,"
        "last_apply_error TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_geo_rule ("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL DEFAULT '',"
        "action TEXT NOT NULL DEFAULT 'block',"
        "direction TEXT NOT NULL DEFAULT 'both',"
        "src_zone TEXT NOT NULL DEFAULT 'wan',"
        "dst_zone TEXT NOT NULL DEFAULT '',"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "updated_at INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_geo_feed ("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL DEFAULT '',"
        "source_url TEXT NOT NULL DEFAULT '',"
        "local_file TEXT NOT NULL DEFAULT '',"
        "interval_hours INTEGER NOT NULL DEFAULT 24,"
        "last_update INTEGER NOT NULL DEFAULT 0,"
        "status TEXT NOT NULL DEFAULT 'pending',"
        "error TEXT NOT NULL DEFAULT '',"
        "enabled INTEGER NOT NULL DEFAULT 1"
    ")");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_geo_event ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "country_id TEXT NOT NULL DEFAULT '',"
        "rule_id TEXT NOT NULL DEFAULT '',"
        "action TEXT NOT NULL DEFAULT '',"
        "src_ip TEXT NOT NULL DEFAULT '',"
        "dst_ip TEXT NOT NULL DEFAULT '',"
        "ts INTEGER NOT NULL DEFAULT 0"
    ")");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_nat_rule (id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,name TEXT NOT NULL,type TEXT DEFAULT 'snat',src TEXT DEFAULT '',dest TEXT DEFAULT '',proto TEXT DEFAULT 'all',to_addr TEXT DEFAULT '',to_port TEXT DEFAULT '',remark TEXT DEFAULT '',updated_at INTEGER DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_ipset (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,family TEXT DEFAULT 'ipv4',match_type TEXT DEFAULT 'dest_ip',source TEXT DEFAULT 'manual',remark TEXT DEFAULT '',updated_at INTEGER DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_ipset_entry (ipset_id TEXT NOT NULL,value TEXT NOT NULL,comment TEXT DEFAULT '',expires_at INTEGER DEFAULT 0,PRIMARY KEY(ipset_id,value))");
    nc_exec("CREATE TABLE IF NOT EXISTS firewall_event (id TEXT PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,rule_id TEXT DEFAULT '',rule_name TEXT DEFAULT '',client TEXT DEFAULT '',src TEXT DEFAULT '',dest TEXT DEFAULT '',proto TEXT DEFAULT '',iface TEXT DEFAULT '')");
    nc_exec("INSERT OR IGNORE INTO firewall_global(id) VALUES(1)");
    {
        int runtime_conntrack = -1;
        char sql[160];

        runtime_conntrack = nc_read_int_file(
            "/proc/sys/net/netfilter/nf_conntrack_max", -1);
        if (runtime_conntrack >= 4096 && runtime_conntrack <= 1048576) {
            snprintf(sql, sizeof(sql),
                     "UPDATE firewall_global SET conntrack_max=%d "
                     "WHERE id=1 AND (conntrack_max IS NULL OR conntrack_max=0)",
                     runtime_conntrack);
            nc_exec(sql);
        }
    }
    nc_exec("UPDATE firewall_global SET identify_mode=CASE "
            "WHEN COALESCE((SELECT record_enabled FROM network_control_global WHERE id=1),1)=0 "
            "THEN 'disabled' ELSE 'device_and_traffic' END "
            "WHERE identify_mode='' OR identify_mode='traffic'");
    nc_exec("INSERT OR IGNORE INTO firewall_geo_meta(id) VALUES(1)");
}

static int nc_fw_policy_ok(const char *s){return s&&(!strcmp(s,"accept")||!strcmp(s,"reject")||!strcmp(s,"drop"));}
static int nc_fw_action_ok(const char *s){return s&&(!strcmp(s,"accept")||!strcmp(s,"reject")||!strcmp(s,"drop")||!strcmp(s,"redirect"));}
static int nc_fw_stack_ok(const char *s){return s&&(!strcmp(s,"ipv4")||!strcmp(s,"ipv6")||!strcmp(s,"ipv4/ipv6")||!strcmp(s,"any"));}
static int nc_fw_nat_type_ok(const char *s){return s&&(!strcmp(s,"snat")||!strcmp(s,"dnat")||!strcmp(s,"redirect")||!strcmp(s,"masquerade"));}
static int nc_fw_family_ok(const char *s){return s&&(!strcmp(s,"ipv4")||!strcmp(s,"ipv6")||!strcmp(s,"ipv4/ipv6"));}
static int nc_fw_flow_offload_ok(const char *s){return s&&(!strcmp(s,"none")||!strcmp(s,"software")||!strcmp(s,"hardware"));}
static int nc_fw_conntrack_max_ok(int value)
{
    return value >= 4096 && value <= 1048576;
}

static int nc_fw_conntrack_runtime_read(int *value_out)
{
    int value;

    if (!value_out)
        return -1;
    value = nc_read_int_file(
        "/proc/sys/net/netfilter/nf_conntrack_max", -1);
    if (!nc_fw_conntrack_max_ok(value))
        return -1;
    *value_out = value;
    return 0;
}

static int nc_fw_conntrack_runtime_write(int value)
{
    char buf[32];
    size_t len, off = 0;
    int fd;

    if (!nc_fw_conntrack_max_ok(value))
        return -1;
    fd = open("/proc/sys/net/netfilter/nf_conntrack_max",
              O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    len = (size_t)snprintf(buf, sizeof(buf), "%d", value);
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    return close(fd) == 0 ? 0 : -1;
}

static int nc_fw_conntrack_runtime_write_available(void)
{
    int value = 0;
    int fd;

    if (nc_fw_conntrack_runtime_read(&value) != 0)
        return 0;
    fd = open("/proc/sys/net/netfilter/nf_conntrack_max",
              O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

static int nc_fw_conntrack_config_read(int *value_out)
{
    sqlite3_stmt *st = NULL;
    int value = 0;

    if (!value_out || nc_prepare(&st,
            "SELECT conntrack_max FROM firewall_global WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int(st, 0);
    else {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    if (!nc_fw_conntrack_max_ok(value))
        return -1;
    *value_out = value;
    return 0;
}

static int nc_fw_conntrack_config_from_json(struct json_object *o)
{
    struct json_object *value = NULL;
    int current = 0;

    if (o && json_object_object_get_ex(o, "conntrack_max", &value))
        return json_object_get_int(value);
    if (nc_fw_conntrack_config_read(&current) == 0)
        return current;
    if (nc_fw_conntrack_runtime_read(&current) == 0)
        return current;
    return 0;
}
static int nc_fw_portish_ok(const char *s){const char*p; if(!s||!s[0]||!strcmp(s,"any"))return 1; for(p=s;*p;p++) if(!((*p>='0'&&*p<='9')||*p=='-'||*p==','||*p==':'||*p==' ')) return 0; return 1;}
static int nc_fw_zone_name_ok(const char *s){const char*p; if(!s||!s[0])return 0; for(p=s;*p;p++) if(!((*p>='A'&&*p<='Z')||(*p>='a'&&*p<='z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'))return 0; return 1;}

static int nc_identification_mode_ok(const char *mode)
{
    return mode && (!strcmp(mode, "disabled") ||
                    !strcmp(mode, "device_and_traffic") ||
                    !strcmp(mode, "traffic_only"));
}

int jmx_identification_mode_get(char *mode, size_t mode_len,
                                int *traffic_record_enabled)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!mode || mode_len == 0 || !traffic_record_enabled ||
        jmx_netconfig_db_init() != 0)
        return -1;
    mode[0] = '\0';
    *traffic_record_enabled = 0;
    nc_firewall_db_init();
    nc_netctl_db_init();
    if (nc_prepare(&st,
        "SELECT f.identify_mode,g.record_enabled FROM firewall_global f "
        "JOIN network_control_global g ON g.id=f.id WHERE f.id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        goto out;
    snprintf(mode, mode_len, "%s", nc_sql_text(st, 0));
    *traffic_record_enabled = sqlite3_column_int(st, 1) ? 1 : 0;
    if (!nc_identification_mode_ok(mode))
        snprintf(mode, mode_len, "%s", "device_and_traffic");
    rc = 0;
out:
    if (st)
        sqlite3_finalize(st);
    return rc;
}

int jmx_identification_mode_set(const char *mode)
{
    sqlite3_stmt *st = NULL;
    char readback[32] = "";
    int record_enabled;
    int readback_record = -1;
    int rc = -1;

    if (!nc_identification_mode_ok(mode) || jmx_netconfig_db_init() != 0)
        return -1;
    record_enabled = strcmp(mode, "disabled") != 0;
    nc_firewall_db_init();
    nc_netctl_db_init();
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE firewall_global SET identify_mode=?1,updated_at=?2 WHERE id=1") != 0)
        goto out;
    sqlite3_bind_text(st, 1, mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "UPDATE network_control_global SET record_enabled=?1,updated_at=?2 WHERE id=1") != 0)
        goto out;
    sqlite3_bind_int(st, 1, record_enabled);
    sqlite3_bind_int64(st, 2, nc_now_s());
    if (nc_step_done(st) != 0)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_prepare(&st,
        "SELECT f.identify_mode,g.record_enabled FROM firewall_global f "
        "JOIN network_control_global g ON g.id=f.id WHERE f.id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        goto out;
    snprintf(readback, sizeof(readback), "%s", nc_sql_text(st, 0));
    readback_record = sqlite3_column_int(st, 1) ? 1 : 0;
    if (strcmp(readback, mode) || readback_record != record_enabled)
        goto out;
    sqlite3_finalize(st);
    st = NULL;
    rc = nc_exec("COMMIT");
out:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0)
        nc_exec("ROLLBACK");
    return rc;
}

static int nc_firewall_priority_compare(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;

    return (a > b) - (a < b);
}

int jmx_firewall_service_validate(struct json_object *cfg)
{
    static const char *groups[] = {
        "zones", "rules", "forwards", "nat_rules", "ipsets", NULL
    };
    struct json_object *arr = NULL, *o = NULL, *value = NULL;
    int priorities[NC_FIREWALL_GROUP_MAX];
    size_t total = 0;
    int i, n;

    if (!cfg || !json_object_is_type(cfg, json_type_object))
        return -1;
    if (json_object_object_get_ex(cfg, "protect", &o)) {
        if (!o || !json_object_is_type(o, json_type_object))
            return -1;
        if (json_object_object_get_ex(o, "identify_mode", &value) &&
            (!value || !json_object_is_type(value, json_type_string)))
            return -1;
        if (!nc_identification_mode_ok(
                nc_json_str_def(o, "identify_mode", "device_and_traffic")))
            return -1;
        if (!nc_fw_flow_offload_ok(
                nc_json_str_def(o, "flow_offload", "none")))
            return -1;
        if (json_object_object_get_ex(o, "conntrack_max", &value) &&
            (!value || !json_object_is_type(value, json_type_int) ||
             !nc_fw_conntrack_max_ok(json_object_get_int(value))))
            return -1;
    }
    for (i = 0; groups[i]; i++) {
        if (!json_object_object_get_ex(cfg, groups[i], &arr))
            continue;
        if (!arr || !json_object_is_type(arr, json_type_array))
            return -1;
        n = json_object_array_length(arr);
        if (n < 0 || n > NC_FIREWALL_GROUP_MAX ||
            total > NC_FIREWALL_TOTAL_MAX - (size_t)n)
            return -1;
        total += (size_t)n;
        for (int item = 0; item < n; item++) {
            o = json_object_array_get_idx(arr, item);
            if (!o || !json_object_is_type(o, json_type_object))
                return -1;
        }
    }

    if (json_object_object_get_ex(cfg, "zones", &arr)) {
        for (i = 0, n = json_object_array_length(arr); i < n; i++) {
            o = json_object_array_get_idx(arr, i);
            if (!nc_safe_id_ok(nc_json_str_def(o, "id", "")) ||
                !nc_fw_zone_name_ok(nc_json_str_def(o, "name", "")) ||
                !nc_fw_policy_ok(nc_json_str_def(o, "input", "reject")) ||
                !nc_fw_policy_ok(nc_json_str_def(o, "output", "accept")) ||
                !nc_fw_policy_ok(nc_json_str_def(o, "forward", "reject")))
                return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "rules", &arr)) {
        for (i = 0, n = json_object_array_length(arr); i < n; i++) {
            o = json_object_array_get_idx(arr, i);
            if (!nc_safe_id_ok(nc_json_str_def(o, "id", "")) ||
                !nc_fw_stack_ok(nc_json_str_def(o, "stack", "ipv4")) ||
                !nc_fw_action_ok(nc_json_str_def(o, "action", "reject")) ||
                !nc_fw_portish_ok(nc_json_str_def(o, "src_port", "any")) ||
                !nc_fw_portish_ok(nc_json_str_def(o, "dest_port", "any")))
                return -1;
            if (json_object_object_get_ex(o, "priority", &value) &&
                (!value || !json_object_is_type(value, json_type_int)))
                return -1;
            priorities[i] = nc_json_int_def(o, "priority", 1000);
        }
        qsort(priorities, (size_t)n, sizeof(priorities[0]),
              nc_firewall_priority_compare);
        for (i = 1; i < n; i++)
            if (priorities[i - 1] == priorities[i])
                return -1;
    }
    if (json_object_object_get_ex(cfg, "forwards", &arr)) {
        for (i = 0, n = json_object_array_length(arr); i < n; i++) {
            o = json_object_array_get_idx(arr, i);
            if (!nc_safe_id_ok(nc_json_str_def(o, "id", "")) ||
                !nc_fw_portish_ok(nc_json_str_def(o, "src_dport", "")) ||
                !nc_fw_portish_ok(nc_json_str_def(o, "dest_port", "")))
                return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "nat_rules", &arr)) {
        for (i = 0, n = json_object_array_length(arr); i < n; i++) {
            o = json_object_array_get_idx(arr, i);
            if (!nc_safe_id_ok(nc_json_str_def(o, "id", "")) ||
                !nc_fw_nat_type_ok(nc_json_str_def(o, "type", "snat")) ||
                !nc_fw_portish_ok(nc_json_str_def(o, "to_port", "")))
                return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "ipsets", &arr)) {
        for (i = 0, n = json_object_array_length(arr); i < n; i++) {
            o = json_object_array_get_idx(arr, i);
            if (!nc_safe_id_ok(nc_json_str_def(o, "id", "")) ||
                !nc_fw_zone_name_ok(nc_json_str_def(o, "name", "")) ||
                !nc_fw_family_ok(nc_json_str_def(o, "family", "ipv4")))
                return -1;
        }
    }
    return 0;
}

static void nc_fw_add_csv_array(struct json_object *o,const char *key,const char *csv)
{
    struct json_object *a=json_object_new_array(); char tmp[1024],*save=NULL,*t; if(csv&&csv[0]){snprintf(tmp,sizeof(tmp),"%s",csv); for(t=strtok_r(tmp,", ",&save);t;t=strtok_r(NULL,", ",&save)) if(t[0]) json_object_array_add(a,json_object_new_string(t));} json_object_object_add(o,key,a);
}

static struct json_object *nc_fw_rw_capability(int read, int write, int apply,
                                                int readback, int rollback,
                                                const char *reason)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "read", json_object_new_boolean(read));
    json_object_object_add(o, "write", json_object_new_boolean(write));
    json_object_object_add(o, "apply", json_object_new_boolean(apply));
    json_object_object_add(o, "readback", json_object_new_boolean(readback));
    json_object_object_add(o, "rollback", json_object_new_boolean(rollback));
    json_object_object_add(o, "reason", json_object_new_string(
        reason && reason[0] ? reason : "capability_not_available"));
    return o;
}

struct json_object *jmx_firewall_service_get(void)
{
    struct json_object *data=json_object_new_object(),*protect=json_object_new_object(),*stats=json_object_new_object(),*zones=json_object_new_array(),*rules=json_object_new_array(),*forwards=json_object_new_array(),*nats=json_object_new_array(),*ipsets=json_object_new_array(),*events=json_object_new_array(); sqlite3_stmt *st=NULL;
    int persisted_conntrack_max = 0;
    int persisted_conntrack_valid = 0;
    if(jmx_netconfig_db_init()!=0)goto done; nc_firewall_db_init();
    if(nc_prepare(&st,"SELECT geo_block,identify_mode,ids_enabled,syn_flood,invalid_drop,fullcone_nat,fullcone_nat6,nat6,flow_offload,default_input,default_output,default_forward,conntrack_max FROM firewall_global WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){json_object_object_add(protect,"geo_block",json_object_new_boolean(sqlite3_column_int(st,0)));nc_add_text(protect,"identify_mode",st,1);json_object_object_add(protect,"ids_enabled",json_object_new_boolean(sqlite3_column_int(st,2)));json_object_object_add(protect,"syn_flood",json_object_new_boolean(sqlite3_column_int(st,3)));json_object_object_add(protect,"invalid_drop",json_object_new_boolean(sqlite3_column_int(st,4)));nc_add_text(protect,"fullcone_nat",st,5);json_object_object_add(protect,"fullcone_nat6",json_object_new_boolean(sqlite3_column_int(st,6)));json_object_object_add(protect,"nat6",json_object_new_boolean(sqlite3_column_int(st,7)));nc_add_text(protect,"flow_offload",st,8);nc_add_text(protect,"default_input",st,9);nc_add_text(protect,"default_output",st,10);nc_add_text(protect,"default_forward",st,11);persisted_conntrack_max = sqlite3_column_int(st,12);persisted_conntrack_valid = nc_fw_conntrack_max_ok(persisted_conntrack_max);json_object_object_add(protect,"conntrack_max",persisted_conntrack_valid ? json_object_new_int(persisted_conntrack_max) : json_object_new_null());sqlite3_finalize(st);st=NULL;}
    {
        int sw_value = 0, hw_value = 0, flowtables = 0;
        int hardware_flowtables = 0;
        int uci_ok = nc_adv_uci_read_int(
            "firewall.@defaults[0].flow_offloading", &sw_value) == 0 &&
            nc_adv_uci_read_int(
            "firewall.@defaults[0].flow_offloading_hw", &hw_value) == 0;
        int nft_ok = nc_adv_nft_flowtable_count(&flowtables) == 0;
        int nft_hw_ok = nc_adv_nft_flowtable_offload_count(
            &hardware_flowtables) == 0;
        int uci_sw = uci_ok && sw_value > 0;
        int uci_hw = uci_ok && hw_value > 0;
        const char *runtime_state = "unknown";
        const char *runtime_reason = !uci_ok ? "firewall_uci_readback_failed" :
                                     !nft_ok ? "nft_ruleset_readback_failed" :
                                     !nft_hw_ok ? "nft_hardware_flag_readback_failed" :
                                     "runtime_disabled_no_flowtable";

        if (uci_ok && nft_ok && nft_hw_ok && flowtables > 0 && uci_hw &&
            hardware_flowtables > 0 && nc_fw_nft_hw_offload_supported()) {
            runtime_state = "hardware";
            runtime_reason = "nft_flowtable_present_flags_offload_uci_hardware_enabled";
        } else if (uci_ok && nft_ok && nft_hw_ok && flowtables > 0 && uci_sw &&
                   !uci_hw && hardware_flowtables == 0) {
            runtime_state = "software";
            runtime_reason = "nft_flowtable_present_uci_software_enabled";
        } else if (uci_ok && nft_ok && flowtables > 0) {
            runtime_state = "unknown";
            runtime_reason = "nft_flowtable_present_uci_mode_unresolved";
        } else if (uci_ok && nft_ok && nft_hw_ok && !uci_sw && !uci_hw) {
            runtime_state = "none";
        } else if (uci_ok && nft_ok && nft_hw_ok) {
            runtime_state = "unknown";
            runtime_reason = "uci_flow_offload_enabled_but_nft_flowtable_missing";
        }
        json_object_object_add(protect, "flow_offload_runtime_state",
                               json_object_new_string(runtime_state));
        json_object_object_add(protect, "flow_offload_runtime_uci_software",
                               json_object_new_boolean(uci_sw));
        json_object_object_add(protect, "flow_offload_runtime_uci_hardware",
                               json_object_new_boolean(uci_hw));
        json_object_object_add(protect, "flow_offload_runtime_flowtables",
                               nft_ok ? json_object_new_int(flowtables) :
                                        json_object_new_null());
        json_object_object_add(protect, "flow_offload_runtime_readback_verified",
                               json_object_new_boolean(uci_ok && nft_ok && nft_hw_ok));
        json_object_object_add(protect, "flow_offload_runtime_reason",
                               json_object_new_string(runtime_reason));
        {
            int conntrack_max = -1;
            int conntrack_count = nc_read_int_file(
                "/proc/sys/net/netfilter/nf_conntrack_count", -1);
            int conntrack_readback = nc_fw_conntrack_runtime_read(&conntrack_max) == 0;
            int conntrack_matches = conntrack_readback && persisted_conntrack_valid &&
                                    conntrack_max == persisted_conntrack_max;
            json_object_object_add(protect, "conntrack_max",
                                   persisted_conntrack_valid ? json_object_new_int(persisted_conntrack_max) :
                                                                json_object_new_null());
            json_object_object_add(protect, "conntrack_max_runtime",
                                   conntrack_readback ? json_object_new_int(conntrack_max) :
                                                        json_object_new_null());
            json_object_object_add(protect, "conntrack_count",
                                   conntrack_count >= 0 ? json_object_new_int(conntrack_count) :
                                                          json_object_new_null());
            json_object_object_add(protect, "conntrack_max_runtime_readback_verified",
                                   json_object_new_boolean(conntrack_matches));
            json_object_object_add(protect, "conntrack_max_runtime_config_mismatch",
                                   json_object_new_boolean(conntrack_readback &&
                                                          persisted_conntrack_valid &&
                                                          !conntrack_matches));
            json_object_object_add(protect, "conntrack_max_runtime_reason",
                                   json_object_new_string(!conntrack_readback ?
                                       "conntrack_max_runtime_unavailable" :
                                       !persisted_conntrack_valid ?
                                       "conntrack_max_config_unavailable" :
                                       conntrack_matches ?
                                       "runtime_matches_persisted_config" :
                                       "conntrack_max_runtime_config_mismatch"));
        }
    }
    {
        struct json_object *runtime = json_object_new_object();
        struct json_object *runtime_state = NULL;
        const char *state = "unknown";
        const char *engine_id = "";
        const char *engine_label = "";
        const char *engine_driver = "";
        int conntrack_max = -1;
        int conntrack_count = nc_read_int_file(
            "/proc/sys/net/netfilter/nf_conntrack_count", -1);
        int conntrack_readback = nc_fw_conntrack_runtime_read(&conntrack_max) == 0;
        int conntrack_matches = conntrack_readback && persisted_conntrack_valid &&
                                conntrack_max == persisted_conntrack_max;
        struct json_object *fullcone_value = NULL;

        if (json_object_object_get_ex(protect, "flow_offload_runtime_state",
                                       &runtime_state) && runtime_state)
            state = json_object_get_string(runtime_state);
        if (!strcmp(state, "hardware")) {
            engine_id = "mtk-ppe";
            engine_label = "MediaTek PPE";
            engine_driver = "mtk_ppe";
        } else if (!strcmp(state, "software")) {
            engine_id = "software-flowtable";
            engine_label = "Software Flowtable";
            engine_driver = "nftables-flowtable";
        } else if (!strcmp(state, "none")) {
            engine_id = "none";
            engine_label = "Disabled";
            engine_driver = "none";
        }
        json_object_object_add(runtime, "flow_offload_engine_id",
                               json_object_new_string(engine_id));
        json_object_object_add(runtime, "flow_offload_engine_label",
                               json_object_new_string(engine_label));
        json_object_object_add(runtime, "flow_offload_engine_driver",
                               json_object_new_string(engine_driver));
        json_object_object_add(runtime, "flow_offload_engine_reason",
                               json_object_new_string(engine_id[0] ?
                                   "runtime_state_readback_verified" :
                                   "flow_offload_engine_runtime_unresolved"));
        json_object_object_add(runtime, "conntrack_max",
                               conntrack_readback ? json_object_new_int(conntrack_max) :
                                                    json_object_new_null());
        json_object_object_add(runtime, "conntrack_count",
                               conntrack_count >= 0 ? json_object_new_int(conntrack_count) :
                                                      json_object_new_null());
        json_object_object_add(runtime, "conntrack_max_runtime_readback_verified",
                               json_object_new_boolean(conntrack_matches));
        json_object_object_add(runtime, "conntrack_max_runtime_config_mismatch",
                               json_object_new_boolean(conntrack_readback &&
                                                      persisted_conntrack_valid &&
                                                      !conntrack_matches));
        json_object_object_add(runtime, "conntrack_max_reason",
                               json_object_new_string(!conntrack_readback ?
                                   "conntrack_max_runtime_unavailable" :
                                   !persisted_conntrack_valid ?
                                   "conntrack_max_config_unavailable" :
                                   conntrack_matches ?
                                   "runtime_matches_persisted_config" :
                                   "conntrack_max_runtime_config_mismatch"));
        json_object_object_add(runtime, "flow_offload_hw_passthrough_rate",
                               json_object_new_null());
        json_object_object_add(runtime, "flow_offload_hw_passthrough_rate_reason",
                               json_object_new_string("hardware_passthrough_counter_unavailable"));
        json_object_object_add(runtime, "udp_hw_redirect", json_object_new_null());
        json_object_object_add(runtime, "udp_hw_redirect_runtime", json_object_new_null());
        json_object_object_add(runtime, "udp_hw_redirect_runtime_readback_verified",
                               json_object_new_boolean(0));
        json_object_object_add(runtime, "udp_hw_redirect_reason",
                               json_object_new_string("udp_hardware_redirect_executor_unavailable"));
        if (json_object_object_get_ex(protect, "fullcone_nat", &fullcone_value) &&
            fullcone_value)
            json_object_object_add(runtime, "fullcone_nat",
                                   json_object_get(fullcone_value));
        else
            json_object_object_add(runtime, "fullcone_nat",
                                   json_object_new_string("off"));
        json_object_object_add(runtime, "fullcone_nat_readback_verified",
                               json_object_new_boolean(0));
        json_object_object_add(runtime, "fullcone_nat_reason",
                               json_object_new_string("fullcone_nat_executor_unavailable"));
        json_object_object_add(data, "runtime", runtime);
    }
    if(nc_prepare(&st,"SELECT id,name,networks,input,output,forward,masq,mtu_fix,forwards FROM firewall_zone WHERE enabled=1 ORDER BY sort_order,name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);nc_fw_add_csv_array(o,"networks",(const char*)sqlite3_column_text(st,2));nc_add_text(o,"input",st,3);nc_add_text(o,"output",st,4);nc_add_text(o,"forward",st,5);json_object_object_add(o,"masq",json_object_new_boolean(sqlite3_column_int(st,6)));json_object_object_add(o,"mtu_fix",json_object_new_boolean(sqlite3_column_int(st,7)));nc_fw_add_csv_array(o,"forwards",(const char*)sqlite3_column_text(st,8));json_object_object_add(o,"status",json_object_new_string("up"));json_object_array_add(zones,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT r.id,r.enabled,r.name,r.stack,r.proto,r.action,r.direction_match,r.direction,r.priority,r.src,r.dest,r.src_port,r.dest_port,r.in_iface,r.out_iface,r.schedule,r.remark,COALESCE((SELECT COUNT(*) FROM firewall_event e WHERE e.rule_id=r.id),0),COALESCE((SELECT max(ts) FROM firewall_event e WHERE e.rule_id=r.id),0) FROM firewall_rule r ORDER BY r.priority,r.sort_order,r.id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"stack",st,3);nc_add_text(o,"proto",st,4);nc_add_text(o,"action",st,5);nc_add_text(o,"direction_match",st,6);nc_add_text(o,"direction",st,7);json_object_object_add(o,"priority",json_object_new_int(sqlite3_column_int(st,8)));nc_add_text(o,"src",st,9);nc_add_text(o,"dest",st,10);nc_add_text(o,"src_port",st,11);nc_add_text(o,"dest_port",st,12);nc_add_text(o,"in_iface",st,13);nc_add_text(o,"out_iface",st,14);nc_add_text(o,"schedule",st,15);nc_add_text(o,"remark",st,16);json_object_object_add(o,"hits",json_object_new_int64(sqlite3_column_int64(st,17)));json_object_object_add(o,"last_hit",json_object_new_int64(sqlite3_column_int64(st,18)));json_object_array_add(rules,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT f.id,f.enabled,f.name,f.proto,f.src,f.src_dport,f.dest,f.dest_ip,f.dest_port,f.reflection,f.remark,COALESCE((SELECT COUNT(*) FROM firewall_event e WHERE e.rule_id=f.id),0),COALESCE((SELECT max(ts) FROM firewall_event e WHERE e.rule_id=f.id),0) FROM firewall_forward f ORDER BY id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"proto",st,3);nc_add_text(o,"src",st,4);nc_add_text(o,"src_dport",st,5);nc_add_text(o,"dest",st,6);nc_add_text(o,"dest_ip",st,7);nc_add_text(o,"dest_port",st,8);json_object_object_add(o,"reflection",json_object_new_boolean(sqlite3_column_int(st,9)));nc_add_text(o,"remark",st,10);json_object_object_add(o,"hits",json_object_new_int64(sqlite3_column_int64(st,11)));json_object_object_add(o,"last_hit",json_object_new_int64(sqlite3_column_int64(st,12)));json_object_array_add(forwards,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT id,enabled,name,type,src,dest,proto,to_addr,to_port,remark,0 FROM firewall_nat_rule ORDER BY id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"type",st,3);nc_add_text(o,"src",st,4);nc_add_text(o,"dest",st,5);nc_add_text(o,"proto",st,6);nc_add_text(o,"to_addr",st,7);nc_add_text(o,"to_port",st,8);nc_add_text(o,"remark",st,9);json_object_object_add(o,"hits",json_object_new_int64(sqlite3_column_int64(st,10)));json_object_array_add(nats,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT s.id,s.name,s.family,s.match_type,s.remark,COALESCE((SELECT COUNT(*) FROM firewall_ipset_entry e WHERE e.ipset_id=s.id),0),COALESCE((SELECT COUNT(*) FROM firewall_rule r WHERE instr(r.src,s.name)>0 OR instr(r.dest,s.name)>0),0) FROM firewall_ipset s ORDER BY s.name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);nc_add_text(o,"family",st,2);nc_add_text(o,"match",st,3);json_object_object_add(o,"entries",json_object_new_int64(sqlite3_column_int64(st,5)));json_object_object_add(o,"used_by",json_object_new_int64(sqlite3_column_int64(st,6)));nc_add_text(o,"remark",st,4);json_object_array_add(ipsets,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT id,ts,action,rule_name,client,src,dest,proto,iface FROM firewall_event ORDER BY ts DESC LIMIT 50")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,1)));nc_add_text(o,"action",st,2);nc_add_text(o,"rule",st,3);nc_add_text(o,"client",st,4);nc_add_text(o,"src",st,5);nc_add_text(o,"dest",st,6);nc_add_text(o,"proto",st,7);nc_add_text(o,"wan",st,8);json_object_array_add(events,o);}sqlite3_finalize(st);}
done:
    json_object_object_add(stats,"blocked_today",json_object_new_int(0));json_object_object_add(stats,"rules_hit_today",json_object_new_int(nc_vpn_count_table("firewall_event","WHERE ts > strftime('%s','now')-86400")));json_object_object_add(stats,"open_ports",json_object_new_int(nc_vpn_count_table("firewall_forward","WHERE enabled=1")));json_object_object_add(stats,"exposed_wans",json_object_new_int(0));json_object_object_add(stats,"last_block",json_object_new_int64(0));
    json_object_object_add(data,"ts",json_object_new_int64(nc_now_s()));json_object_object_add(data,"protect",protect);json_object_object_add(data,"stats",stats);json_object_object_add(data,"zones",zones);json_object_object_add(data,"rules",rules);json_object_object_add(data,"forwards",forwards);json_object_object_add(data,"nat_rules",nats);json_object_object_add(data,"ipsets",ipsets);json_object_object_add(data,"recent_events",events);

    struct json_object *fw_caps = json_object_new_object();
    json_object_object_add(fw_caps, "geo_block", json_object_new_boolean(0));
    json_object_object_add(fw_caps, "geo_block_rules", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "geo_block_feed", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "geo_block_counters", json_object_new_boolean(0));
    json_object_object_add(fw_caps, "geo_block_events", json_object_new_boolean(0));
    json_object_object_add(fw_caps, "geo_block_reason", json_object_new_string(
        "geo_block_dataplane_executor_missing"));
    json_object_object_add(fw_caps, "ids", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "syn_flood", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "fullcone_nat", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "fullcone_nat_contract",
                           nc_fw_rw_capability(1, 0, 0, 0, 0,
                               "fullcone_nat_executor_unavailable"));
    json_object_object_add(fw_caps, "fullcone_nat_reason",
                           json_object_new_string("fullcone_nat_executor_unavailable"));
    json_object_object_add(fw_caps, "nat6", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "flow_offload", json_object_new_boolean(1));
    /* Configuration support is separate from a live firewall4 executor. */
    {
        int sw = 0, hw = 0, flowtables = 0, hardware_flowtables = 0;
        int hardware_supported = nc_fw_nft_hw_offload_supported();
        int executor = nc_fw_runtime_tool_available("fw4");
        int readback = nc_adv_uci_read_int(
                           "firewall.@defaults[0].flow_offloading", &sw) == 0 &&
                       nc_adv_uci_read_int(
                           "firewall.@defaults[0].flow_offloading_hw", &hw) == 0 &&
                       nc_adv_nft_flowtable_count(&flowtables) == 0 &&
                       nc_adv_nft_flowtable_offload_count(&hardware_flowtables) == 0;
        int runtime = executor && readback &&
                      (hw == 0 || (hw > 0 && hardware_supported &&
                                   hardware_flowtables > 0));
        int rollback = executor && readback;
        int hardware_runtime = executor && readback && hardware_supported;
        const char *reason = !executor ? "firewall4_runtime_executor_unavailable" :
                             !readback ? "firewall4_runtime_readback_unavailable" :
                             hw > 0 && (!hardware_supported ||
                                        hardware_flowtables <= 0) ?
                                 "hardware_flow_offload_runtime_unsupported" :
                             hardware_supported ?
                                 "none_software_and_hardware_runtime_supported" :
                                 "none_and_software_runtime_supported";
        const char *hardware_reason = !executor ?
                             "firewall4_runtime_executor_unavailable" :
                             !readback ? "firewall4_runtime_readback_unavailable" :
                             hardware_supported ?
                                 "mtk_ppe_and_nft_hw_offload_supported" :
                                 "hardware_offload_not_detected_on_platform";

        json_object_object_add(fw_caps, "flow_offload_runtime",
                               json_object_new_boolean(runtime));
        json_object_object_add(fw_caps, "flow_offload_runtime_executor",
                               json_object_new_boolean(executor));
        json_object_object_add(fw_caps, "flow_offload_runtime_readback",
                               json_object_new_boolean(readback));
        json_object_object_add(fw_caps, "flow_offload_runtime_rollback",
                               json_object_new_boolean(rollback));
        json_object_object_add(fw_caps, "flow_offload_runtime_reason",
                               json_object_new_string(reason));
        json_object_object_add(fw_caps, "flow_offload_runtime_modes",
                               json_object_new_string(hardware_runtime ?
                                   "none,software,hardware" : "none,software"));
        json_object_object_add(fw_caps, "flow_offload_hardware_runtime",
                               json_object_new_boolean(hardware_runtime));
        json_object_object_add(fw_caps, "flow_offload_hardware_reason",
                               json_object_new_string(hardware_reason));
        {
            struct json_object *engines = json_object_new_array();
            int engine_readback = executor && readback;
            if (engine_readback) {
                struct json_object *software = json_object_new_object();
                struct json_object *modes = json_object_new_array();
                json_object_object_add(software, "id",
                                       json_object_new_string("software-flowtable"));
                json_object_object_add(software, "label",
                                       json_object_new_string("Software Flowtable"));
                json_object_object_add(software, "driver",
                                       json_object_new_string("nftables-flowtable"));
                json_object_array_add(modes, json_object_new_string("software"));
                json_object_object_add(software, "modes", modes);
                json_object_array_add(engines, software);
            }
            if (engine_readback && hardware_runtime) {
                struct json_object *hardware = json_object_new_object();
                struct json_object *modes = json_object_new_array();
                json_object_object_add(hardware, "id",
                                       json_object_new_string("mtk-ppe"));
                json_object_object_add(hardware, "label",
                                       json_object_new_string("MediaTek PPE"));
                json_object_object_add(hardware, "driver",
                                       json_object_new_string("mtk_ppe"));
                json_object_array_add(modes, json_object_new_string("hardware"));
                json_object_object_add(hardware, "modes", modes);
                json_object_array_add(engines, hardware);
            }
            json_object_object_add(fw_caps, "flow_offload_engines", engines);
            json_object_object_add(fw_caps, "flow_offload_engine_readback",
                                   json_object_new_boolean(engine_readback));
            json_object_object_add(fw_caps, "flow_offload_engine_reason",
                                   json_object_new_string(
                                       engine_readback && json_object_array_length(engines) > 0 ?
                                       "executor_and_runtime_readback_verified" :
                                       "flow_offload_engine_directory_unavailable"));
        }
    }
    {
        int conntrack_max = -1;
        int conntrack_readback = nc_fw_conntrack_runtime_read(
            &conntrack_max) == 0;
        int conntrack_write = conntrack_readback &&
                              nc_fw_conntrack_runtime_write_available();
        struct json_object *conntrack_cap = nc_fw_rw_capability(
            conntrack_readback, conntrack_write, conntrack_write,
            conntrack_write, conntrack_write,
            !conntrack_readback ? "conntrack_max_runtime_unavailable" :
            conntrack_write ? "procfs_write_readback_and_rollback_supported" :
                              "procfs_readback_only");
        json_object_object_add(conntrack_cap, "min", json_object_new_int(4096));
        json_object_object_add(conntrack_cap, "max", json_object_new_int(1048576));
        json_object_object_add(conntrack_cap, "step", json_object_new_int(1));
        json_object_object_add(fw_caps, "conntrack_max", conntrack_cap);
    }
    json_object_object_add(fw_caps, "flow_offload_hw_passthrough_rate",
                           nc_fw_rw_capability(0, 0, 0, 0, 0,
                               "hardware_passthrough_counter_unavailable"));
    json_object_object_add(fw_caps, "udp_hw_redirect",
                           nc_fw_rw_capability(0, 0, 0, 0, 0,
                               "udp_hardware_redirect_executor_unavailable"));
    json_object_object_add(fw_caps, "ipsets", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "zones", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "rules", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "forwards", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "nat_rules", json_object_new_boolean(1));
    json_object_object_add(fw_caps, "schedule", json_object_new_boolean(1));
    json_object_object_add(data, "capabilities", fw_caps);

    return jmx_gen_api_response_data(API_CODE_SUCCESS,data);
}

typedef int (*nc_fw_bind_row_fn)(sqlite3_stmt *st, struct json_object *row,
                                 int sort_order);

static int nc_fw_bind_text(sqlite3_stmt *st, int index, const char *value)
{
    return sqlite3_bind_text(st, index, value, -1, SQLITE_TRANSIENT) == SQLITE_OK
        ? 0 : -1;
}

static int nc_fw_bind_int(sqlite3_stmt *st, int index, int value)
{
    return sqlite3_bind_int(st, index, value) == SQLITE_OK ? 0 : -1;
}

static int nc_fw_bind_int64(sqlite3_stmt *st, int index, sqlite3_int64 value)
{
    return sqlite3_bind_int64(st, index, value) == SQLITE_OK ? 0 : -1;
}

static int nc_fw_bind_zone(sqlite3_stmt *st, struct json_object *o, int order)
{
    return nc_fw_bind_text(st, 1, nc_json_str_def(o, "id", "")) ||
           nc_fw_bind_text(st, 2, nc_json_str_def(o, "name", "")) ||
           nc_fw_bind_text(st, 3, nc_json_str_def(o, "networks", "")) ||
           nc_fw_bind_text(st, 4, nc_json_str_def(o, "input", "reject")) ||
           nc_fw_bind_text(st, 5, nc_json_str_def(o, "output", "accept")) ||
           nc_fw_bind_text(st, 6, nc_json_str_def(o, "forward", "reject")) ||
           nc_fw_bind_int(st, 7, nc_json_bool_def(o, "masq", 0)) ||
           nc_fw_bind_int(st, 8, nc_json_bool_def(o, "mtu_fix", 0)) ||
           nc_fw_bind_text(st, 9, nc_json_str_def(o, "forwards", "")) ||
           nc_fw_bind_int(st, 10, nc_json_bool_def(o, "enabled", 1)) ||
           nc_fw_bind_int(st, 11, nc_json_int_def(o, "sort_order", order))
        ? -1 : 0;
}

static int nc_fw_bind_rule(sqlite3_stmt *st, struct json_object *o, int order)
{
    return nc_fw_bind_text(st, 1, nc_json_str_def(o, "id", "")) ||
           nc_fw_bind_int(st, 2, nc_json_bool_def(o, "enabled", 1)) ||
           nc_fw_bind_text(st, 3, nc_json_str_def(o, "name", "")) ||
           nc_fw_bind_text(st, 4, nc_json_str_def(o, "stack", "ipv4")) ||
           nc_fw_bind_text(st, 5, nc_json_str_def(o, "proto", "all")) ||
           nc_fw_bind_text(st, 6, nc_json_str_def(o, "action", "reject")) ||
           nc_fw_bind_text(st, 7, nc_json_str_def(o, "direction_match", "stateful")) ||
           nc_fw_bind_text(st, 8, nc_json_str_def(o, "direction", "")) ||
           nc_fw_bind_int(st, 9, nc_json_int_def(o, "priority", 1000)) ||
           nc_fw_bind_text(st, 10, nc_json_str_def(o, "src", "any")) ||
           nc_fw_bind_text(st, 11, nc_json_str_def(o, "dest", "any")) ||
           nc_fw_bind_text(st, 12, nc_json_str_def(o, "src_port", "any")) ||
           nc_fw_bind_text(st, 13, nc_json_str_def(o, "dest_port", "any")) ||
           nc_fw_bind_text(st, 14, nc_json_str_def(o, "in_iface", "")) ||
           nc_fw_bind_text(st, 15, nc_json_str_def(o, "out_iface", "")) ||
           nc_fw_bind_text(st, 16, nc_json_str_def(o, "schedule", "always")) ||
           nc_fw_bind_text(st, 17, nc_json_str_def(o, "remark", "")) ||
           nc_fw_bind_int(st, 18, order) ||
           nc_fw_bind_int64(st, 19, nc_now_s())
        ? -1 : 0;
}

static int nc_fw_bind_forward(sqlite3_stmt *st, struct json_object *o, int order)
{
    (void)order;
    return nc_fw_bind_text(st, 1, nc_json_str_def(o, "id", "")) ||
           nc_fw_bind_int(st, 2, nc_json_bool_def(o, "enabled", 1)) ||
           nc_fw_bind_text(st, 3, nc_json_str_def(o, "name", "")) ||
           nc_fw_bind_text(st, 4, nc_json_str_def(o, "proto", "tcp")) ||
           nc_fw_bind_text(st, 5, nc_json_str_def(o, "src", "wan")) ||
           nc_fw_bind_text(st, 6, nc_json_str_def(o, "src_dport", "")) ||
           nc_fw_bind_text(st, 7, nc_json_str_def(o, "dest", "lan")) ||
           nc_fw_bind_text(st, 8, nc_json_str_def(o, "dest_ip", "")) ||
           nc_fw_bind_text(st, 9, nc_json_str_def(o, "dest_port", "")) ||
           nc_fw_bind_int(st, 10, nc_json_bool_def(o, "reflection", 0)) ||
           nc_fw_bind_text(st, 11, nc_json_str_def(o, "remark", "")) ||
           nc_fw_bind_int64(st, 12, nc_now_s())
        ? -1 : 0;
}

static int nc_fw_bind_nat(sqlite3_stmt *st, struct json_object *o, int order)
{
    (void)order;
    return nc_fw_bind_text(st, 1, nc_json_str_def(o, "id", "")) ||
           nc_fw_bind_int(st, 2, nc_json_bool_def(o, "enabled", 1)) ||
           nc_fw_bind_text(st, 3, nc_json_str_def(o, "name", "")) ||
           nc_fw_bind_text(st, 4, nc_json_str_def(o, "type", "snat")) ||
           nc_fw_bind_text(st, 5, nc_json_str_def(o, "src", "")) ||
           nc_fw_bind_text(st, 6, nc_json_str_def(o, "dest", "")) ||
           nc_fw_bind_text(st, 7, nc_json_str_def(o, "proto", "all")) ||
           nc_fw_bind_text(st, 8, nc_json_str_def(o, "to_addr", "")) ||
           nc_fw_bind_text(st, 9, nc_json_str_def(o, "to_port", "")) ||
           nc_fw_bind_text(st, 10, nc_json_str_def(o, "remark", "")) ||
           nc_fw_bind_int64(st, 11, nc_now_s())
        ? -1 : 0;
}

static int nc_fw_bind_ipset(sqlite3_stmt *st, struct json_object *o, int order)
{
    (void)order;
    return nc_fw_bind_text(st, 1, nc_json_str_def(o, "id", "")) ||
           nc_fw_bind_text(st, 2, nc_json_str_def(o, "name", "")) ||
           nc_fw_bind_text(st, 3, nc_json_str_def(o, "family", "ipv4")) ||
           nc_fw_bind_text(st, 4, nc_json_str_def(
               o, "match", nc_json_str_def(o, "match_type", "dest_ip"))) ||
           nc_fw_bind_text(st, 5, nc_json_str_def(o, "source", "manual")) ||
           nc_fw_bind_text(st, 6, nc_json_str_def(o, "remark", "")) ||
           nc_fw_bind_int64(st, 7, nc_now_s())
        ? -1 : 0;
}

static int nc_fw_replace_group(struct json_object *rows, const char *delete_sql,
                               const char *insert_sql, nc_fw_bind_row_fn bind_row)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    int count;

    if (nc_prepare(&st, insert_sql) != 0)
        return -1;
    if (nc_exec(delete_sql) != 0)
        goto out;
    count = json_object_array_length(rows);
    for (int i = 0; i < count; i++) {
        if (bind_row(st, json_object_array_get_idx(rows, i), i) != 0 ||
            nc_step_done(st) != 0 || sqlite3_reset(st) != SQLITE_OK ||
            sqlite3_clear_bindings(st) != SQLITE_OK)
            goto out;
    }
    rc = 0;
out:
    if (sqlite3_finalize(st) != SQLITE_OK)
        rc = -1;
    return rc;
}

static int nc_fw_save_protect(struct json_object *o)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (nc_prepare(&st,
        "INSERT INTO firewall_global(id,geo_block,identify_mode,ids_enabled,"
        "syn_flood,invalid_drop,fullcone_nat,fullcone_nat6,nat6,flow_offload,"
        "default_input,default_output,default_forward,conntrack_max,updated_at) "
        "VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) "
        "ON CONFLICT(id) DO UPDATE SET geo_block=excluded.geo_block,"
        "identify_mode=excluded.identify_mode,ids_enabled=excluded.ids_enabled,"
        "syn_flood=excluded.syn_flood,invalid_drop=excluded.invalid_drop,"
        "fullcone_nat=excluded.fullcone_nat,fullcone_nat6=excluded.fullcone_nat6,"
        "nat6=excluded.nat6,flow_offload=excluded.flow_offload,"
        "default_input=excluded.default_input,default_output=excluded.default_output,"
        "default_forward=excluded.default_forward,conntrack_max=excluded.conntrack_max,"
        "updated_at=excluded.updated_at") != 0)
        return -1;
    if (nc_fw_bind_int(st, 1, nc_json_bool_def(o, "geo_block", 0)) ||
        nc_fw_bind_text(st, 2, nc_json_str_def(o, "identify_mode", "device_and_traffic")) ||
        nc_fw_bind_int(st, 3, nc_json_bool_def(o, "ids_enabled", 0)) ||
        nc_fw_bind_int(st, 4, nc_json_bool_def(o, "syn_flood", 1)) ||
        nc_fw_bind_int(st, 5, nc_json_bool_def(o, "invalid_drop", 0)) ||
        nc_fw_bind_text(st, 6, nc_json_str_def(o, "fullcone_nat", "off")) ||
        nc_fw_bind_int(st, 7, nc_json_bool_def(o, "fullcone_nat6", 0)) ||
        nc_fw_bind_int(st, 8, nc_json_bool_def(o, "nat6", 0)) ||
        nc_fw_bind_text(st, 9, nc_json_str_def(o, "flow_offload", "none")) ||
        nc_fw_bind_text(st, 10, nc_json_str_def(o, "default_input", "accept")) ||
        nc_fw_bind_text(st, 11, nc_json_str_def(o, "default_output", "accept")) ||
        nc_fw_bind_text(st, 12, nc_json_str_def(o, "default_forward", "reject")) ||
        nc_fw_bind_int(st, 13, nc_fw_conntrack_config_from_json(o)) ||
        nc_fw_bind_int64(st, 14, nc_now_s()) || nc_step_done(st) != 0)
        goto out;
    rc = 0;
out:
    if (sqlite3_finalize(st) != SQLITE_OK)
        rc = -1;
    if (rc != 0)
        return -1;

    st = NULL;
    rc = -1;
    if (nc_prepare(&st,
        "UPDATE network_control_global SET record_enabled=?1,updated_at=?2 WHERE id=1") != 0)
        return -1;
    if (nc_fw_bind_int(st, 1, strcmp(nc_json_str_def(
            o, "identify_mode", "device_and_traffic"), "disabled") != 0) ||
        nc_fw_bind_int64(st, 2, nc_now_s()) || nc_step_done(st) != 0)
        goto finish;
    rc = 0;
finish:
    if (sqlite3_finalize(st) != SQLITE_OK)
        rc = -1;
    return rc;
}

static int nc_fw_finish_transaction(int write_rc)
{
    if (write_rc == 0 && nc_exec("COMMIT") == 0)
        return 0;
    nc_exec("ROLLBACK");
    return -1;
}

int jmx_firewall_service_set(struct json_object *cfg)
{
    struct json_object *value = NULL;

    if (jmx_firewall_service_validate(cfg) != 0 ||
        jmx_netconfig_db_init() != 0)
        return -1;
    nc_firewall_db_init();
    if(nc_exec("BEGIN IMMEDIATE")!=0)return -1;

    /* nc_fw_replace_group owns checked nc_exec("DELETE FROM firewall_*") calls. */

    if (json_object_object_get_ex(cfg, "protect", &value) &&
        nc_fw_save_protect(value) != 0)
        goto rollback;
    if (json_object_object_get_ex(cfg, "zones", &value) &&
        nc_fw_replace_group(value, "DELETE FROM firewall_zone",
            "INSERT INTO firewall_zone(id,name,networks,input,output,forward,masq,mtu_fix,forwards,enabled,sort_order) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", nc_fw_bind_zone) != 0)
        goto rollback;
    if (json_object_object_get_ex(cfg, "rules", &value) &&
        nc_fw_replace_group(value, "DELETE FROM firewall_rule",
            "INSERT INTO firewall_rule(id,enabled,name,stack,proto,action,direction_match,direction,priority,src,dest,src_port,dest_port,in_iface,out_iface,schedule,remark,sort_order,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)", nc_fw_bind_rule) != 0)
        goto rollback;
    if (json_object_object_get_ex(cfg, "forwards", &value) &&
        nc_fw_replace_group(value, "DELETE FROM firewall_forward",
            "INSERT INTO firewall_forward(id,enabled,name,proto,src,src_dport,dest,dest_ip,dest_port,reflection,remark,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", nc_fw_bind_forward) != 0)
        goto rollback;
    if (json_object_object_get_ex(cfg, "nat_rules", &value) &&
        nc_fw_replace_group(value, "DELETE FROM firewall_nat_rule",
            "INSERT INTO firewall_nat_rule(id,enabled,name,type,src,dest,proto,to_addr,to_port,remark,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", nc_fw_bind_nat) != 0)
        goto rollback;
    if (json_object_object_get_ex(cfg, "ipsets", &value) &&
        nc_fw_replace_group(value, "DELETE FROM firewall_ipset",
            "INSERT INTO firewall_ipset(id,name,family,match_type,source,remark,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7)", nc_fw_bind_ipset) != 0)
        goto rollback;

    if (nc_exec("COMMIT") != 0) {
        nc_exec("ROLLBACK");
        return -1;
    }
    return 0;
rollback:
    return nc_fw_finish_transaction(-1);
}

static const char *nc_fw_target_uc(const char *a){if(!strcmp(a,"accept"))return "ACCEPT"; if(!strcmp(a,"drop"))return "DROP"; if(!strcmp(a,"redirect"))return "REDIRECT"; return "REJECT";}

static int nc_fw_uci_text_ok(const char *s, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    if (strlen((const char *)p) > max_len)
        return 0;
    for (; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int nc_fw_proto_ok(const char *s)
{
    static const char *allowed[] = {
        "all", "any", "tcp", "udp", "icmp", "icmpv6", "esp", "ah",
        "gre", "sctp", "udplite", NULL
    };
    char copy[128], *save = NULL, *token;
    int count = 0;

    if (!s || !s[0] || strlen(s) >= sizeof(copy))
        return 0;
    snprintf(copy, sizeof(copy), "%s", s);
    for (token = strtok_r(copy, ", ", &save); token;
         token = strtok_r(NULL, ", ", &save)) {
        int matched = 0;
        for (int i = 0; allowed[i]; i++)
            if (!strcasecmp(token, allowed[i])) { matched = 1; break; }
        if (!matched || ++count > 8)
            return 0;
    }
    return count > 0;
}

static int nc_fw_port_expr_ok(const char *s)
{
    char copy[256], *save = NULL, *token;
    int count = 0;

    if (!s || !s[0] || !strcmp(s, "any"))
        return 1;
    if (strlen(s) >= sizeof(copy))
        return 0;
    snprintf(copy, sizeof(copy), "%s", s);
    for (token = strtok_r(copy, ", ", &save); token;
         token = strtok_r(NULL, ", ", &save)) {
        char *sep = strchr(token, '-');
        char *end = NULL;
        long first, last;

        if (!sep)
            sep = strchr(token, ':');
        if (sep)
            *sep++ = '\0';
        errno = 0;
        first = strtol(token, &end, 10);
        if (errno || !end || *end || first < 1 || first > 65535)
            return 0;
        last = first;
        if (sep) {
            errno = 0;
            last = strtol(sep, &end, 10);
            if (errno || !end || *end || last < first || last > 65535)
                return 0;
        }
        if (++count > 64)
            return 0;
    }
    return count > 0;
}

static int nc_fw_addr_expr_ok(const char *s, int allow_empty)
{
    char copy[512], *save = NULL, *token;
    int count = 0;

    if (!s || !s[0])
        return allow_empty;
    if (!strcmp(s, "any"))
        return 1;
    if (strlen(s) >= sizeof(copy))
        return 0;
    snprintf(copy, sizeof(copy), "%s", s);
    for (token = strtok_r(copy, ", ", &save); token;
         token = strtok_r(NULL, ", ", &save)) {
        struct in_addr a4;
        struct in6_addr a6;
        char *slash;
        char *end = NULL;
        long prefix;
        int family = AF_UNSPEC;

        if (*token == '!') token++;
        if (!*token) return 0;
        slash = strchr(token, '/');
        if (slash) *slash++ = '\0';
        if (inet_pton(AF_INET, token, &a4) == 1) family = AF_INET;
        else if (inet_pton(AF_INET6, token, &a6) == 1) family = AF_INET6;
        else return 0;
        if (slash) {
            errno = 0;
            prefix = strtol(slash, &end, 10);
            if (errno || !end || *end || prefix < 0 ||
                prefix > (family == AF_INET ? 32 : 128))
                return 0;
        }
        if (++count > 64) return 0;
    }
    return count > 0;
}

static int nc_fw_uci_value(FILE *fp, const char *keyword, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    const char *name;

    if (!fp || !keyword ||
        (strncmp(keyword, "option ", 7) && strncmp(keyword, "list ", 5)) ||
        !(name = strchr(keyword, ' ')) || !nc_fw_zone_name_ok(name + 1) ||
        !nc_fw_uci_text_ok((const char *)p, 1024))
        return -1;
    if (fprintf(fp, "\t%s '", keyword) < 0)
        return -1;
    for (; *p; p++) {
        if (*p == '\'' && fputs("'\\''", fp) == EOF)
            return -1;
        else if (*p != '\'' && fputc(*p, fp) == EOF)
            return -1;
    }
    return fputs("'\n", fp) == EOF ? -1 : 0;
}

static int nc_fw_uci_int(FILE *fp, const char *keyword, int value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", value);
    return nc_fw_uci_value(fp, keyword, buf);
}

static int nc_fw_runtime_tool_available(const char *name)
{
    char path[128];
    const char *prefixes[] = { "/sbin/", "/usr/sbin/", "/bin/", "/usr/bin/" };
    size_t i;

    if (!name || !name[0])
        return 0;
    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], name);
        if (access(path, X_OK) == 0)
            return 1;
    }
    return 0;
}

static const char *nc_fw_runtime_tool_path(const char *name)
{
    static const char *const prefixes[] = {
        "/sbin/", "/usr/sbin/", "/bin/", "/usr/bin/"
    };
    static char path[128];
    size_t i;

    if (!name || !name[0])
        return NULL;
    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], name);
        if (access(path, X_OK) == 0)
            return path;
    }
    return NULL;
}

/* MT7988 exposes PPE debugfs instances when the built-in mtk_eth offload path
 * is present. The nft dry-run below is still the kernel gate; this identifies a
 * platform where the hardware flag is meaningful rather than merely parseable. */
static int nc_fw_mtk_ppe_present(void)
{
    return nc_sys_file_exists("/sys/kernel/debug/ppe0") &&
           (nc_sys_file_exists("/sys/kernel/debug/ppe1") ||
            nc_sys_file_exists("/sys/kernel/debug/ppe2"));
}

/* nft resolves a flowtable's device list while it parses, so the dry-run needs a
 * netdev that exists on this board. A hardcoded name under-reports hardware
 * offload wherever that name is absent -- MT7988 presents lan1..lan4/wan through
 * DSA and need not carry an eth0 at all. Collect the physical netdevs instead (a
 * "device" link under /sys/class/net is what separates them from lo, bridges and
 * virtual interfaces) so the caller can try each in turn. */
#define NC_FW_OFFLOAD_PROBE_MAX 8

static size_t nc_fw_offload_probe_devices(char names[][IFNAMSIZ], size_t max)
{
    DIR *dir;
    struct dirent *entry;
    size_t count = 0;

    dir = opendir("/sys/class/net");
    if (!dir)
        return 0;
    while (count < max && (entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        char ifname[IFNAMSIZ];
        char path[sizeof("/sys/class/net/") + IFNAMSIZ + sizeof("/device")];
        size_t len;

        if (name[0] == '.' || !strcmp(name, "lo"))
            continue;
        if (!strncmp(name, "br-", 3) || !strncmp(name, "veth", 4) ||
            !strncmp(name, "tun", 3) || !strncmp(name, "tap", 3) ||
            !strncmp(name, "wg", 2) || !strncmp(name, "ppp", 3) ||
            !strncmp(name, "ifb", 3) || strchr(name, '.'))
            continue;
        len = strlen(name);
        if (len == 0 || len >= sizeof(ifname))
            continue;
        memcpy(ifname, name, len + 1);
        snprintf(path, sizeof(path), "/sys/class/net/%s/device", ifname);
        if (access(path, F_OK) != 0)
            continue;
        memcpy(names[count], ifname, len + 1);
        count++;
    }
    closedir(dir);
    return count;
}

static int nc_fw_nft_hw_offload_supported(void)
{
    char devices[NC_FW_OFFLOAD_PROBE_MAX][IFNAMSIZ];
    const char *nft;
    size_t count;
    size_t i;

    /* The debugfs probe costs nothing, so let it gate the forks below. */
    if (!nc_fw_mtk_ppe_present())
        return 0;
    nft = nc_fw_runtime_tool_path("nft");
    if (!nft)
        return 0;
    count = nc_fw_offload_probe_devices(devices, NC_FW_OFFLOAD_PROBE_MAX);
    for (i = 0; i < count; i++) {
        char ruleset[256];
        /* Copy the name into its own bounded buffer before formatting. Indexing
         * the flat probe array hands the compiler a pointer into 128 bytes, so it
         * has to assume a name up to 127 chars and reads the ruleset buffer as
         * possibly too small; a plain char[IFNAMSIZ] carries the real bound. */
        char ifname[IFNAMSIZ];
        size_t len = strlen(devices[i]);
        /* argv[0] has to be the program name: nc_fw_runtime_exec rejects a NULL
         * one, which is what made this probe report "no hardware" outright,
         * without ever asking the kernel. Nothing here calls tool_path again,
         * so its static buffer stays valid for the whole loop. */
        char *argv[] = { (char *)nft, "-c", NULL, NULL };

        if (len == 0 || len >= sizeof(ifname))
            continue;
        memcpy(ifname, devices[i], len + 1);
        snprintf(ruleset, sizeof(ruleset),
                 "add table inet dreamingwrt-fw-cap-test; "
                 "add flowtable inet dreamingwrt-fw-cap-test ft { "
                 "hook ingress priority 0; devices = { %s }; flags offload; }",
                 ifname);
        argv[2] = ruleset;
        if (nc_fw_runtime_exec(nft, argv) == 0)
            return 1;
    }
    return 0;
}

static int nc_fw_runtime_exec(const char *path, char *const argv[])
{
    struct jmx_exec_result result;
    int rc;

    if (!path || !argv || !argv[0])
        return -1;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_wait(path, argv, 15000, &result);
    if (rc != 0 || result.timed_out || result.truncated ||
        result.term_signal != 0 || result.exit_code != 0) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    return 0;
}

static int nc_fw_runtime_reload(void)
{
    const char *init = access("/etc/init.d/firewall", X_OK) == 0
        ? "/etc/init.d/firewall" : NULL;
    const char *fw4 = nc_fw_runtime_tool_path("fw4");
    char *init_argv[] = { (char *)init, "reload", NULL };
    char *fw4_argv[] = { (char *)fw4, "reload", NULL };

    if (init)
        return nc_fw_runtime_exec(init, init_argv);
    if (fw4)
        return nc_fw_runtime_exec(fw4, fw4_argv);
    return -1;
}

static int nc_fw_runtime_check(void)
{
    const char *fw4 = nc_fw_runtime_tool_path("fw4");
    char *argv[] = { (char *)fw4, "check", NULL };

    /* A reload-only init script is not enough to claim a dry-run check. */
    return fw4 ? nc_fw_runtime_exec(fw4, argv) : -1;
}

static int nc_fw_runtime_lock_open(void)
{
    struct stat st;
    int dirfd = -1;
    int lockfd = -1;

    if (mkdir("/run/dreamingwrt", 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open("/run/dreamingwrt",
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto done;
    lockfd = openat(dirfd, "firewall-flow-offload.lock",
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || fstat(lockfd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (lockfd >= 0)
            close(lockfd);
        lockfd = -1;
        goto done;
    }
    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        int busy = errno == EWOULDBLOCK || errno == EAGAIN;

        close(lockfd);
        lockfd = busy ? -2 : -1;
    }
done:
    if (dirfd >= 0)
        close(dirfd);
    return lockfd;
}

static int nc_fw_runtime_uci_write(int sw, int hw)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    struct uci_section *defaults = NULL;
    char sw_text[8], hw_text[8];
    int rc = -1;

    if (!ctx || uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg)
        goto done;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *section = uci_to_section(e);

        if (!strcmp(section->type, "defaults")) {
            defaults = section;
            break;
        }
    }
    if (!defaults)
        goto done;
    snprintf(sw_text, sizeof(sw_text), "%d", sw ? 1 : 0);
    snprintf(hw_text, sizeof(hw_text), "%d", hw ? 1 : 0);
    if (nc_uci_set_pkg(ctx, "firewall", defaults->e.name,
                       "flow_offloading", sw_text) != UCI_OK ||
        nc_uci_set_pkg(ctx, "firewall", defaults->e.name,
                       "flow_offloading_hw", hw_text) != UCI_OK ||
        jmx_uci_commit(ctx, "firewall") != UCI_OK)
        goto done;
    rc = 0;
done:
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

static int nc_fw_flow_mode_read(char *mode, size_t mode_len)
{
    sqlite3_stmt *st = NULL;

    if (!mode || mode_len == 0 || nc_prepare(&st,
        "SELECT flow_offload FROM firewall_global WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    snprintf(mode, mode_len, "%s", nc_sql_text(st, 0));
    sqlite3_finalize(st);
    return nc_fw_flow_offload_ok(mode) ? 0 : -1;
}

static int nc_fw_runtime_readback(const char *mode, int *flowtables_out)
{
    int sw = 0, hw = 0, flowtables = 0;
    int hardware_flowtables = 0;

    if (flowtables_out) *flowtables_out = 0;
    if (!mode || nc_adv_uci_read_int(
            "firewall.@defaults[0].flow_offloading", &sw) != 0 ||
        nc_adv_uci_read_int(
            "firewall.@defaults[0].flow_offloading_hw", &hw) != 0 ||
        nc_adv_nft_flowtable_count(&flowtables) != 0 ||
        nc_adv_nft_flowtable_offload_count(&hardware_flowtables) != 0)
        return 0;
    if (flowtables_out) *flowtables_out = flowtables;
    if (!strcmp(mode, "none"))
        return sw == 0 && hw == 0 && flowtables == 0 &&
               hardware_flowtables == 0;
    if (flowtables <= 0)
        return 0;
    if (!strcmp(mode, "software"))
        return sw > 0 && hw == 0 && hardware_flowtables == 0;
    if (!strcmp(mode, "hardware"))
        return sw > 0 && hw > 0 && hardware_flowtables > 0 &&
               nc_fw_nft_hw_offload_supported();
    return 0;
}

static int nc_fw_runtime_apply(const char *mode, struct json_object *data,
                               int *runtime_applied, int *readback_verified,
                               int *rollback_attempted, int *rollback_ok,
                               const char **reason_out,
                               const char **failure_stage_out)
{
    char old_mode[32] = "";
    int hw_supported = 0;
    int old_sw = 0, old_hw = 0, flowtables = 0;
    int desired_sw, desired_hw;
    int current_sw = 0, current_hw = 0;
    int desired_conntrack = 0, old_conntrack = 0, current_conntrack = -1;
    int conntrack_write_attempted = 0;
    int conntrack_runtime_applied = 0;
    int conntrack_readback_verified = 0;
    int conntrack_rollback_attempted = 0;
    int conntrack_rollback_ok = 1;
    int lockfd = -1;
    int rc = -1;
    const char *reason = "firewall4_runtime_apply_failed";
    const char *failure_stage = "runtime_flow_validation";
    const char *rollback_reason = "";
    const char *conntrack_rollback_reason = "";

    if (runtime_applied) *runtime_applied = 0;
    if (readback_verified) *readback_verified = 0;
    if (rollback_attempted) *rollback_attempted = 0;
    if (rollback_ok) *rollback_ok = 1;
    if (reason_out) *reason_out = reason;
    if (failure_stage_out) *failure_stage_out = failure_stage;
    if (!mode || !nc_fw_flow_offload_ok(mode)) {
        reason = "flow_offload_mode_unsupported";
        goto done;
    }
    if (!nc_fw_runtime_tool_available("fw4")) {
        reason = "firewall4_runtime_executor_unavailable";
        failure_stage = "runtime_flow_executor";
        goto done;
    }
    if (!strcmp(mode, "hardware")) {
        hw_supported = nc_fw_nft_hw_offload_supported();
        if (!hw_supported) {
            reason = "hardware_flow_offload_runtime_unsupported";
            failure_stage = "runtime_flow_capability";
            goto done;
        }
    }
    lockfd = nc_fw_runtime_lock_open();
    if (lockfd < 0) {
        reason = lockfd == -2 ? "firewall4_transaction_busy" :
                                "firewall4_transaction_lock_failed";
        failure_stage = "runtime_lock";
        goto done;
    }
    if (nc_fw_conntrack_config_read(&desired_conntrack) != 0) {
        reason = "conntrack_max_config_unavailable";
        failure_stage = "runtime_conntrack_snapshot";
        goto done;
    }
    if (nc_adv_uci_read_int("firewall.@defaults[0].flow_offloading", &old_sw) != 0 ||
        nc_adv_uci_read_int("firewall.@defaults[0].flow_offloading_hw", &old_hw) != 0 ||
        nc_adv_nft_flowtable_count(&flowtables) != 0 ||
        nc_fw_conntrack_runtime_read(&old_conntrack) != 0) {
        reason = "firewall_runtime_snapshot_failed";
        failure_stage = "runtime_snapshot";
        goto done;
    }
    snprintf(old_mode, sizeof(old_mode), "%s",
             old_hw > 0 ? "hardware" : old_sw > 0 ? "software" : "none");
    desired_sw = strcmp(mode, "none") != 0;
    desired_hw = !strcmp(mode, "hardware");
    if (nc_fw_runtime_uci_write(desired_sw, desired_hw) != 0 ||
        nc_fw_runtime_check() != 0 ||
        nc_fw_runtime_reload() != 0) {
        reason = "firewall4_runtime_apply_failed";
        failure_stage = "runtime_flow_apply";
        goto rollback;
    }
    if (!nc_fw_runtime_readback(mode, &flowtables)) {
        reason = "firewall4_runtime_readback_mismatch";
        failure_stage = "runtime_flow_readback";
        goto rollback;
    }
    if (old_conntrack != desired_conntrack) {
        if (!nc_fw_conntrack_runtime_write_available()) {
            reason = "conntrack_max_runtime_executor_unavailable";
            failure_stage = "runtime_conntrack_executor";
            goto rollback;
        }
        conntrack_write_attempted = 1;
        if (nc_fw_conntrack_runtime_write(desired_conntrack) != 0) {
            reason = "conntrack_max_runtime_write_failed";
            failure_stage = "runtime_conntrack_apply";
            goto rollback;
        }
    }
    if (nc_fw_conntrack_runtime_read(&current_conntrack) != 0 ||
        current_conntrack != desired_conntrack) {
        reason = "conntrack_max_runtime_readback_mismatch";
        failure_stage = "runtime_conntrack_readback";
        goto rollback;
    }
    conntrack_runtime_applied = 1;
    conntrack_readback_verified = 1;
    if (runtime_applied) *runtime_applied = 1;
    if (readback_verified) *readback_verified = 1;
    reason = "flow_and_conntrack_runtime_applied_and_readback_verified";
    failure_stage = "";
    rc = 0;
    goto done;

rollback:
    if (rollback_attempted) *rollback_attempted = 1;
    if (conntrack_write_attempted) {
        conntrack_rollback_attempted = 1;
        if (nc_fw_conntrack_runtime_read(&current_conntrack) != 0) {
            conntrack_rollback_ok = 0;
            conntrack_rollback_reason = "conntrack_max_rollback_read_failed";
        } else if (current_conntrack != desired_conntrack &&
                   current_conntrack != old_conntrack) {
            /* A writer outside this lock changed procfs; preserve its value. */
            conntrack_rollback_ok = 0;
            conntrack_rollback_reason = "conntrack_max_rollback_conflict";
        } else if (current_conntrack == desired_conntrack &&
                   desired_conntrack != old_conntrack &&
                   (nc_fw_conntrack_runtime_write(old_conntrack) != 0 ||
                    nc_fw_conntrack_runtime_read(&current_conntrack) != 0 ||
                    current_conntrack != old_conntrack)) {
            conntrack_rollback_ok = 0;
            conntrack_rollback_reason = "conntrack_max_rollback_failed";
        }
    }
    if (nc_adv_uci_read_int("firewall.@defaults[0].flow_offloading",
                            &current_sw) != 0 ||
        nc_adv_uci_read_int("firewall.@defaults[0].flow_offloading_hw",
                            &current_hw) != 0) {
        if (rollback_ok) *rollback_ok = 0;
        rollback_reason = "firewall4_runtime_rollback_read_failed";
    } else if ((current_sw != desired_sw || current_hw != desired_hw) &&
               (current_sw != old_sw || current_hw != old_hw)) {
        /* Another writer changed the same keys; never overwrite its values. */
        if (rollback_ok) *rollback_ok = 0;
        rollback_reason = "firewall4_runtime_rollback_conflict";
    } else if (current_sw == old_sw && current_hw == old_hw) {
        /* The failed operation never displaced the previous flow state. */
    } else if (nc_fw_runtime_uci_write(old_sw, old_hw) != 0 ||
               nc_fw_runtime_check() != 0 || nc_fw_runtime_reload() != 0 ||
               !nc_fw_runtime_readback(old_mode, NULL)) {
        if (rollback_ok) *rollback_ok = 0;
        rollback_reason = "firewall4_runtime_rollback_failed";
    }
    if (!conntrack_rollback_ok && rollback_ok) {
        *rollback_ok = 0;
        if (!rollback_reason[0])
            rollback_reason = conntrack_rollback_reason;
    }
done:
    if (nc_fw_conntrack_runtime_read(&current_conntrack) != 0)
        current_conntrack = -1;
    if (data) {
        json_object_object_add(data, "runtime_previous_mode",
                               json_object_new_string(old_mode));
        json_object_object_add(data, "runtime_flowtables",
                               json_object_new_int(flowtables));
        json_object_object_add(data, "conntrack_max_desired",
                               nc_fw_conntrack_max_ok(desired_conntrack) ?
                               json_object_new_int(desired_conntrack) :
                               json_object_new_null());
        json_object_object_add(data, "conntrack_max_previous",
                               nc_fw_conntrack_max_ok(old_conntrack) ?
                               json_object_new_int(old_conntrack) :
                               json_object_new_null());
        json_object_object_add(data, "conntrack_max_runtime_applied",
                               json_object_new_boolean(conntrack_runtime_applied));
        json_object_object_add(data,
                               "conntrack_max_runtime_readback_verified",
                               json_object_new_boolean(conntrack_readback_verified));
        json_object_object_add(data, "conntrack_max_rollback_attempted",
                               json_object_new_boolean(conntrack_rollback_attempted));
        json_object_object_add(data, "conntrack_max_rollback_ok",
                               json_object_new_boolean(conntrack_rollback_ok));
        json_object_object_add(data, "conntrack_max_rollback_reason",
                               json_object_new_string(
                                   conntrack_rollback_ok ? "" :
                                   conntrack_rollback_reason));
        json_object_object_add(data, "conntrack_max_runtime_final",
                               nc_fw_conntrack_max_ok(current_conntrack) ?
                               json_object_new_int(current_conntrack) :
                               json_object_new_null());
        json_object_object_add(data, "rollback_reason",
                               json_object_new_string(rollback_reason));
    }
    if (lockfd >= 0)
        close(lockfd);
    if (reason_out) *reason_out = reason;
    if (failure_stage_out) *failure_stage_out = failure_stage;
    return rc;
}

/*
 * Reasons are reported separately from the failure itself because the caller
 * used to collapse every outcome into write_failed = 1. "/etc/config is not a
 * trustworthy directory" and "the filesystem refused the write" need different
 * operator responses, and the first one is silent otherwise: a group-writable
 * /etc/config makes every preview fail with no indication of why.
 */
#define NC_FW_ARTIFACT_REASON_DIR_UNTRUSTED "firewall_artifact_directory_untrusted"
#define NC_FW_ARTIFACT_REASON_DIR_OPEN      "firewall_artifact_directory_open_failed"
#define NC_FW_ARTIFACT_REASON_CREATE        "firewall_artifact_create_failed"
#define NC_FW_ARTIFACT_REASON_WRITE         "firewall_artifact_write_failed"

static int nc_fw_artifact_open(int *dirfd_out, char *tmp_name, size_t tmp_len,
                               const char **reason_out)
{
    struct stat st;
    int dirfd, fd = -1;

    if (!dirfd_out || !tmp_name || tmp_len == 0) {
        if (reason_out) *reason_out = NC_FW_ARTIFACT_REASON_CREATE;
        return -1;
    }
    *dirfd_out = -1;
    dirfd = open("/etc/config", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        if (reason_out) *reason_out = NC_FW_ARTIFACT_REASON_DIR_OPEN;
        return -1;
    }
    if (fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(dirfd);
        if (reason_out) *reason_out = NC_FW_ARTIFACT_REASON_DIR_UNTRUSTED;
        return -1;
    }
    for (int attempt = 0; attempt < 32; attempt++) {
        snprintf(tmp_name, tmp_len, ".dreamingwrt_firewall.%ld.%08lx.%d.tmp",
                 (long)getpid(), (unsigned long)random(), attempt);
        fd = openat(dirfd, tmp_name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0) break;
        if (errno != EEXIST) break;
    }
    if (fd < 0) {
        close(dirfd);
        if (reason_out) *reason_out = NC_FW_ARTIFACT_REASON_CREATE;
        return -1;
    }
    *dirfd_out = dirfd;
    return fd;
}

struct json_object *jmx_firewall_service_apply(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *summary = json_object_new_object();
    struct json_object *warnings = json_object_new_array();
    sqlite3_stmt *st = NULL;
    FILE *fp = NULL;
    char tmp_name[128] = "";
    int dirfd = -1, fd = -1, dry = nc_json_bool_def(cfg, "dry_run", 0);
    int artifact_generated = 0, dry_run_verified = 0, validated = 1, write_failed = 0;
    int runtime_applied = 0, readback_verified = 0;
    int rollback_attempted = 0, rollback_ok = 1;
    int runtime_attempted = 0;
    const char *failure_stage = "";
    int step_rc = SQLITE_DONE;
    const char *write_reason = NULL;
    const char *runtime_reason = "firewall4_transaction_executor_pending";
    const char *runtime_failure_stage = "";
    char flow_mode[32] = "none";

    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("database_unavailable"));
        json_object_object_add(data, "failure_stage", json_object_new_string("snapshot"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    nc_firewall_db_init();
    if (nc_fw_flow_mode_read(flow_mode, sizeof(flow_mode)) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "persisted", json_object_new_boolean(0));
        json_object_object_add(data, "runtime_applied", json_object_new_boolean(0));
        json_object_object_add(data, "readback_verified", json_object_new_boolean(0));
        json_object_object_add(data, "apply_state",
                               json_object_new_string("runtime_apply_refused"));
        json_object_object_add(data, "runtime_reason",
                               json_object_new_string("flow_offload_config_unavailable"));
        json_object_object_add(data, "rollback_attempted", json_object_new_boolean(0));
        json_object_object_add(data, "rollback_ok", json_object_new_boolean(1));
        json_object_object_add(data, "error",
                               json_object_new_string("flow_offload_config_unavailable"));
        json_object_object_add(data, "failure_stage", json_object_new_string("snapshot"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    json_object_object_add(summary, "zones", json_object_new_int(nc_vpn_count_table("firewall_zone", "WHERE enabled=1")));
    json_object_object_add(summary, "rules", json_object_new_int(nc_vpn_count_table("firewall_rule", "WHERE enabled=1")));
    json_object_object_add(summary, "forwards", json_object_new_int(nc_vpn_count_table("firewall_forward", "WHERE enabled=1")));
    json_object_object_add(summary, "nat_rules", json_object_new_int(nc_vpn_count_table("firewall_nat_rule", "WHERE enabled=1")));
    json_object_object_add(summary, "ipsets", json_object_new_int(nc_vpn_count_table("firewall_ipset", "")));

    {
        fd = nc_fw_artifact_open(&dirfd, tmp_name, sizeof(tmp_name), &write_reason);
        if (fd < 0 || !(fp = fdopen(fd, "w"))) {
            if (fd >= 0) {
                close(fd);
                write_reason = NC_FW_ARTIFACT_REASON_CREATE;
            }
            write_failed = 1;
            goto artifact_done;
        }
        if (fputs("# generated by jmxd; preview artifact only, not live firewall4\n", fp) == EOF)
            write_failed = 1;

#define FW_VALUE(keyword, value) do { if (nc_fw_uci_value(fp, (keyword), (value)) != 0) write_failed = 1; } while (0)
#define FW_INT(keyword, value) do { if (nc_fw_uci_int(fp, (keyword), (value)) != 0) write_failed = 1; } while (0)
        if (!write_failed && nc_prepare(&st, "SELECT name,input,output,forward,masq,mtu_fix FROM firewall_zone WHERE enabled=1 ORDER BY sort_order,name") == 0) {
            while ((step_rc = sqlite3_step(st)) == SQLITE_ROW && !write_failed) {
                const char *name = nc_sql_text(st, 0), *input = nc_sql_text(st, 1);
                const char *output = nc_sql_text(st, 2), *forward = nc_sql_text(st, 3);
                if (!nc_fw_zone_name_ok(name) || !nc_fw_policy_ok(input) ||
                    !nc_fw_policy_ok(output) || !nc_fw_policy_ok(forward)) { validated = 0; break; }
                if (fputs("config zone\n", fp) == EOF) write_failed = 1;
                FW_VALUE("option name", name); FW_VALUE("option input", nc_fw_target_uc(input));
                FW_VALUE("option output", nc_fw_target_uc(output)); FW_VALUE("option forward", nc_fw_target_uc(forward));
                FW_INT("option masq", sqlite3_column_int(st, 4)); FW_INT("option mtu_fix", sqlite3_column_int(st, 5));
                if (fputc('\n', fp) == EOF) write_failed = 1;
            }
            sqlite3_finalize(st); st = NULL;
            if (step_rc != SQLITE_DONE && validated) write_failed = 1;
        } else if (!write_failed) write_failed = 1;

        step_rc = SQLITE_DONE;
        if (!write_failed && validated && nc_prepare(&st, "SELECT name,stack,proto,action,src,dest,src_port,dest_port,remark FROM firewall_rule WHERE enabled=1 ORDER BY priority,sort_order,id") == 0) {
            while ((step_rc = sqlite3_step(st)) == SQLITE_ROW && !write_failed) {
                const char *name=nc_sql_text(st,0),*stack=nc_sql_text(st,1),*proto=nc_sql_text(st,2),*action=nc_sql_text(st,3);
                const char *src=nc_sql_text(st,4),*dest=nc_sql_text(st,5),*sp=nc_sql_text(st,6),*dp=nc_sql_text(st,7),*remark=nc_sql_text(st,8);
                if (!nc_fw_uci_text_ok(name,128)||!nc_fw_stack_ok(stack)||!nc_fw_proto_ok(proto)||!nc_fw_action_ok(action)||
                    !nc_fw_addr_expr_ok(src,0)||!nc_fw_addr_expr_ok(dest,0)||!nc_fw_port_expr_ok(sp)||!nc_fw_port_expr_ok(dp)||!nc_fw_uci_text_ok(remark,512)) { validated=0; break; }
                if (fputs("config rule\n",fp)==EOF) write_failed=1;
                FW_VALUE("option name",name); FW_VALUE("option proto",proto); FW_VALUE("option target",nc_fw_target_uc(action));
                FW_VALUE("option src_ip",src); FW_VALUE("option dest_ip",dest); FW_VALUE("option src_port",sp); FW_VALUE("option dest_port",dp);
                FW_VALUE("option family",stack); FW_VALUE("option comment",remark); if(fputc('\n',fp)==EOF)write_failed=1;
            }
            sqlite3_finalize(st); st=NULL; if(step_rc!=SQLITE_DONE&&validated)write_failed=1;
        } else if (!write_failed && validated) write_failed=1;

        step_rc = SQLITE_DONE;
        if (!write_failed && validated && nc_prepare(&st,"SELECT name,proto,src,src_dport,dest,dest_ip,dest_port,reflection FROM firewall_forward WHERE enabled=1 ORDER BY id")==0) {
            while((step_rc=sqlite3_step(st))==SQLITE_ROW&&!write_failed){const char*name=nc_sql_text(st,0),*proto=nc_sql_text(st,1),*src=nc_sql_text(st,2),*sp=nc_sql_text(st,3),*dest=nc_sql_text(st,4),*dip=nc_sql_text(st,5),*dp=nc_sql_text(st,6);if(!nc_fw_uci_text_ok(name,128)||!nc_fw_proto_ok(proto)||!nc_fw_zone_name_ok(src)||!nc_fw_port_expr_ok(sp)||!nc_fw_zone_name_ok(dest)||!nc_fw_addr_expr_ok(dip,1)||!nc_fw_port_expr_ok(dp)){validated=0;break;}if(fputs("config redirect\n",fp)==EOF)write_failed=1;FW_VALUE("option name",name);FW_VALUE("option proto",proto);FW_VALUE("option src",src);FW_VALUE("option src_dport",sp);FW_VALUE("option dest",dest);FW_VALUE("option dest_ip",dip);FW_VALUE("option dest_port",dp);FW_INT("option reflection",sqlite3_column_int(st,7));if(fputc('\n',fp)==EOF)write_failed=1;}sqlite3_finalize(st);st=NULL;if(step_rc!=SQLITE_DONE&&validated)write_failed=1;
        } else if (!write_failed && validated) write_failed=1;

        step_rc = SQLITE_DONE;
        if (!write_failed && validated && nc_prepare(&st,"SELECT name,family,match_type FROM firewall_ipset ORDER BY name")==0) {
            while((step_rc=sqlite3_step(st))==SQLITE_ROW&&!write_failed){const char*name=nc_sql_text(st,0),*family=nc_sql_text(st,1),*match=nc_sql_text(st,2);if(!nc_fw_zone_name_ok(name)||!nc_fw_family_ok(family)||!nc_fw_zone_name_ok(match)){validated=0;break;}if(fputs("config ipset\n",fp)==EOF)write_failed=1;FW_VALUE("option name",name);FW_VALUE("option family",family);FW_VALUE("list match",match);if(fputc('\n',fp)==EOF)write_failed=1;}sqlite3_finalize(st);st=NULL;if(step_rc!=SQLITE_DONE&&validated)write_failed=1;
        } else if (!write_failed && validated) write_failed=1;
#undef FW_VALUE
#undef FW_INT
        if (fflush(fp) != 0) write_failed = 1;
        if (fsync(fileno(fp)) != 0) write_failed = 1;
        if (fclose(fp) != 0) write_failed = 1;
        fp = NULL;
        if (!write_failed && validated && !dry &&
            renameat(dirfd, tmp_name, dirfd, "dreamingwrt_firewall") == 0) {
            tmp_name[0] = '\0';
            if (fsync(dirfd) == 0)
                artifact_generated = 1;
            else {
                unlinkat(dirfd, "dreamingwrt_firewall", 0);
                (void)fsync(dirfd);
                write_failed = 1;
            }
        } else if (dry && !write_failed && validated) {
            dry_run_verified = 1;
        } else
            write_failed = write_failed || validated;
artifact_done:
        if (st) sqlite3_finalize(st);
        if (fp) fclose(fp);
        if (dirfd >= 0) { if (!artifact_generated && tmp_name[0]) unlinkat(dirfd,tmp_name,0); close(dirfd); }
    }
    if (!dry && validated && !write_failed && artifact_generated) {
        runtime_attempted = 1;
        if (nc_fw_runtime_apply(flow_mode, data, &runtime_applied,
                                &readback_verified, &rollback_attempted,
                                &rollback_ok, &runtime_reason,
                                &runtime_failure_stage) != 0)
            write_failed = 1;
    }
    if (!dry && !validated)
        failure_stage = "validation";
    else if (!dry && write_failed && !runtime_attempted)
        failure_stage = "artifact";
    else if (!dry && runtime_attempted && !runtime_applied)
        failure_stage = runtime_failure_stage[0] ?
                        runtime_failure_stage : "runtime";
    if (runtime_attempted && !runtime_applied)
        json_object_array_add(warnings,json_object_new_string(runtime_reason));
    json_object_object_add(data,"ok",json_object_new_boolean(
        dry ? dry_run_verified :
        (validated && artifact_generated && runtime_applied && readback_verified)));
    json_object_object_add(data,"dry_run",json_object_new_boolean(dry));
    json_object_object_add(data,"persisted",json_object_new_boolean(!dry));
    json_object_object_add(data,"artifact_generated",json_object_new_boolean(artifact_generated));
    json_object_object_add(data,"dry_run_verified",json_object_new_boolean(dry_run_verified));
    json_object_object_add(data,"validated",json_object_new_boolean(validated));
    if(dry)json_object_object_add(data,"validation_reason",json_object_new_string(dry_run_verified ? "preview_rendered_and_fsynced" : "preview_render_failed"));
    json_object_object_add(data,"flow_offload",json_object_new_string(flow_mode));
    json_object_object_add(data,"runtime_applied",json_object_new_boolean(runtime_applied));
    json_object_object_add(data,"readback_verified",json_object_new_boolean(readback_verified));
    json_object_object_add(data,"applied",json_object_new_boolean(runtime_applied && readback_verified));
    json_object_object_add(data,"apply_state",json_object_new_string(
        dry ? "dry_run" : (runtime_applied && readback_verified ? "runtime_applied" : "runtime_apply_failed")));
    json_object_object_add(data,"runtime_reason",json_object_new_string(runtime_reason));
    json_object_object_add(data,"failure_code",json_object_new_string(
        runtime_attempted && !runtime_applied ? runtime_reason :
        !validated ? "firewall_artifact_validation_failed" :
        write_failed ? (write_reason ? write_reason :
                        NC_FW_ARTIFACT_REASON_WRITE) : ""));
    json_object_object_add(data,"runtime_failure_stage",
                           json_object_new_string(runtime_failure_stage));
    json_object_object_add(data,"failure_stage",json_object_new_string(failure_stage));
    json_object_object_add(data,"rollback_attempted",json_object_new_boolean(rollback_attempted));
    json_object_object_add(data,"rollback_ok",json_object_new_boolean(rollback_ok));
    {
        struct json_object *previous_mode = NULL;
        const char *final_mode = runtime_applied ? flow_mode : "unknown";
        if (!runtime_applied && rollback_attempted && rollback_ok &&
            json_object_object_get_ex(data, "runtime_previous_mode", &previous_mode) &&
            previous_mode && json_object_is_type(previous_mode, json_type_string) &&
            json_object_get_string(previous_mode)[0])
            final_mode = json_object_get_string(previous_mode);
        json_object_object_add(data, "runtime_final_mode",
                               json_object_new_string(final_mode));
    }
    if(!dry&&(!validated||write_failed)){
        /*
         * "error" intentionally keeps its original two values: the frontend
         * matches on them. The specific cause goes in write_failure_reason.
         */
        json_object_object_add(data,"error",
            json_object_new_string(!validated ? "firewall_artifact_validation_failed"
                                : (runtime_attempted
                                   ? "firewall4_runtime_apply_failed"
                                   : NC_FW_ARTIFACT_REASON_WRITE)));
        json_object_object_add(data,"message",json_object_new_string(
            runtime_attempted ? "firewall runtime apply failed; inspect runtime_reason and rollback state"
                              : "firewall preview artifact was not published"));
        if(validated&&write_failed&&!runtime_attempted)
            json_object_object_add(data,"write_failure_reason",
                json_object_new_string(write_reason ? write_reason
                                                    : NC_FW_ARTIFACT_REASON_WRITE));
    }
    json_object_object_add(data,"summary",summary);json_object_object_add(data,"warnings",warnings);
    return jmx_gen_api_response_data((dry||(validated&&artifact_generated && runtime_applied && readback_verified))?API_CODE_SUCCESS:API_CODE_ERROR,data);
}
