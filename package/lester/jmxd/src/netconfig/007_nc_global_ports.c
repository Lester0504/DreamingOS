/* ══════════════════════════════════════════════════════════════════════
 * Hybrid WAN line CRUD
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_hybrid_row_to_json(sqlite3_stmt *st, struct json_object *o)
{
    const char *password_ref = (const char *)sqlite3_column_text(st, 16);
    int upload_mbps = sqlite3_column_int(st, 22);
    int download_mbps = sqlite3_column_int(st, 23);
    nc_add_text(o, "id", st, 0);
    nc_add_text(o, "parent", st, 1);
    nc_add_text(o, "parent_wan_id", st, 1);
    nc_add_text(o, "name", st, 2);
    nc_add_text(o, "comment", st, 3);
    nc_add_text(o, "mode", st, 4);
    nc_add_text(o, "vlan_id", st, 5);
    nc_add_text(o, "mac", st, 6);
    nc_add_text(o, "proto", st, 7);
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 8)));
    json_object_object_add(o, "default_route", json_object_new_boolean(sqlite3_column_int(st, 9)));
    json_object_object_add(o, "failover", json_object_new_boolean(sqlite3_column_int(st, 10)));
    nc_add_text(o, "check_host", st, 11);
    nc_add_text(o, "ipaddr", st, 12);
    nc_add_text(o, "ip", st, 12);
    json_object_object_add(o, "prefix", json_object_new_int(sqlite3_column_int(st, 13)));
    nc_add_text(o, "gateway", st, 14);
    nc_add_text(o, "username", st, 15);
    json_object_object_add(o, "password_configured",
                           json_object_new_boolean(password_ref && password_ref[0]));
    json_object_object_add(o, "secret_ref_state",
                           json_object_new_string(password_ref && password_ref[0] ?
                                                  "configured" : "not_configured"));
    nc_add_text(o, "pppoe_ac", st, 17);
    nc_add_text(o, "pppoe_ac_mac", st, 18);
    nc_add_text(o, "pppoe_service", st, 19);
    json_object_object_add(o, "mtu", json_object_new_int(sqlite3_column_int(st, 20)));
    json_object_object_add(o, "mru", json_object_new_int(sqlite3_column_int(st, 21)));
    json_object_object_add(o, "upload_mbps", json_object_new_int(upload_mbps));
    json_object_object_add(o, "download_mbps", json_object_new_int(download_mbps));
    json_object_object_add(o, "upload", json_object_new_int(upload_mbps));
    json_object_object_add(o, "download", json_object_new_int(download_mbps));
}

struct json_object *jmx_netconfig_hybrid_line_list(const char *parent_wan_id)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) goto done;
    if (parent_wan_id && parent_wan_id[0]) {
        if (nc_prepare(&st, "SELECT id,parent_wan_id,name,comment,mode,vlan_id,mac,proto,enabled,default_route,failover,check_host,ip,prefix,gateway,username,password_ref,pppoe_ac,pppoe_ac_mac,pppoe_service,mtu,mru,upload_mbps,download_mbps FROM hybrid_line WHERE parent_wan_id=?1 ORDER BY name,id") == 0)
            sqlite3_bind_text(st, 1, parent_wan_id, -1, SQLITE_TRANSIENT);
    } else {
        nc_prepare(&st, "SELECT id,parent_wan_id,name,comment,mode,vlan_id,mac,proto,enabled,default_route,failover,check_host,ip,prefix,gateway,username,password_ref,pppoe_ac,pppoe_ac_mac,pppoe_service,mtu,mru,upload_mbps,download_mbps FROM hybrid_line ORDER BY parent_wan_id,name,id");
    }
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_hybrid_row_to_json(st, o);
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(data, "lines", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_netconfig_hybrid_line_set(struct json_object *line_json)
{
    sqlite3_stmt *st = NULL;
    const char *id, *parent, *name, *mode, *proto, *mac;
    char idbuf[96];
    char *stored_password = NULL;
    const char *requested_password = NULL;
    int clear_password = 0;
    if (!line_json) return -1;
    parent = nc_json_str(line_json, "parent", nc_json_str(line_json, "parent_wan_id", ""));
    name = nc_json_str(line_json, "name", "");
    mode = nc_json_str(line_json, "mode", "hybrid_macvlan");
    proto = nc_json_str(line_json, "proto", "dhcp");
    mac = nc_json_str(line_json, "mac", "");
    id = nc_json_str(line_json, "id", "");
    if (!parent[0] || !name[0] || !nc_valid_name(parent) || !nc_valid_name(name)) return -1;
    if (!id[0]) { snprintf(idbuf, sizeof(idbuf), "line_%s_%s", parent, name); id = idbuf; }
    if (!nc_valid_name(id)) return -1;
    if (strcmp(mode, "hybrid_vlan") == 0) {
        int vid = nc_json_int(line_json, "vlan_id", atoi(nc_json_str(line_json, "vlan_id", "0")));
        if (vid < 1 || vid > 4094) return -1;
    }
    if (mac[0]) {
        /* loose validation is done in API layer for old callers; DB layer only rejects shell-unsafe names */
    }
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st,
        "SELECT password_ref FROM hybrid_line WHERE id=?1 AND parent_wan_id=?2") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, parent, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *old_password = (const char *)sqlite3_column_text(st, 0);
            stored_password = strdup(old_password ? old_password : "");
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    clear_password = nc_json_bool(line_json, "clear_password", 0);
    requested_password = nc_json_str(line_json, "password", "");
    if (!requested_password[0])
        requested_password = nc_json_str(line_json, "password_ref", "");
    if (!requested_password[0] && !clear_password)
        requested_password = stored_password ? stored_password : "";
    if (nc_prepare(&st,
        "INSERT INTO hybrid_line(id,parent_wan_id,name,comment,mode,vlan_id,mac,proto,enabled,default_route,failover,"
        "check_host,ip,prefix,gateway,username,password_ref,pppoe_ac,pppoe_ac_mac,pppoe_service,mtu,mru,upload_mbps,download_mbps) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24) "
        "ON CONFLICT(id) DO UPDATE SET parent_wan_id=excluded.parent_wan_id,name=excluded.name,comment=excluded.comment,"
        "mode=excluded.mode,vlan_id=excluded.vlan_id,mac=excluded.mac,proto=excluded.proto,enabled=excluded.enabled,"
        "default_route=excluded.default_route,failover=excluded.failover,check_host=excluded.check_host,ip=excluded.ip,"
        "prefix=excluded.prefix,gateway=excluded.gateway,username=excluded.username,password_ref=excluded.password_ref,"
        "pppoe_ac=excluded.pppoe_ac,pppoe_ac_mac=excluded.pppoe_ac_mac,pppoe_service=excluded.pppoe_service,"
        "mtu=excluded.mtu,mru=excluded.mru,upload_mbps=excluded.upload_mbps,download_mbps=excluded.download_mbps") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, parent, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str(line_json, "comment", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, mode, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, nc_json_str(line_json, "vlan_id", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, proto, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 9, nc_json_bool(line_json, "enabled", 1));
        sqlite3_bind_int(st, 10, nc_json_bool(line_json, "default_route", 0));
        sqlite3_bind_int(st, 11, nc_json_bool(line_json, "failover", 1));
        sqlite3_bind_text(st, 12, nc_json_str(line_json, "check_host", "www.baidu.com"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, nc_json_str(line_json, "ipaddr", nc_json_str(line_json, "ip", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 14, nc_json_int(line_json, "prefix", 24));
        sqlite3_bind_text(st, 15, nc_json_str(line_json, "gateway", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 16, nc_json_str(line_json, "username", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 17, clear_password ? "" : requested_password,
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 18, nc_json_str(line_json, "pppoe_ac", nc_json_str(line_json, "ac", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 19, nc_json_str(line_json, "pppoe_ac_mac", nc_json_str(line_json, "ac_mac", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 20, nc_json_str(line_json, "pppoe_service", nc_json_str(line_json, "service", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 21, nc_json_int(line_json, "mtu", 1480));
        sqlite3_bind_int(st, 22, nc_json_int(line_json, "mru", 1480));
        sqlite3_bind_int(st, 23, nc_json_int(line_json, "upload_mbps", nc_json_int(line_json, "upload", 0)));
        sqlite3_bind_int(st, 24, nc_json_int(line_json, "download_mbps", nc_json_int(line_json, "download", 0)));
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        if (stored_password) {
            memset(stored_password, 0, strlen(stored_password));
            free(stored_password);
        }
        return rc;
    }
    if (stored_password) {
        memset(stored_password, 0, strlen(stored_password));
        free(stored_password);
    }
    return -1;
}

int jmx_netconfig_hybrid_line_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "DELETE FROM hybrid_line WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    int rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

int jmx_netconfig_hybrid_line_enable(const char *id, int enabled)
{
    sqlite3_stmt *st = NULL;
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "UPDATE hybrid_line SET enabled=?1 WHERE id=?2") != 0) return -1;
    sqlite3_bind_int(st, 1, enabled ? 1 : 0);
    sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
    int rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * Global config + Physical port + Apply stubs
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *jmx_netconfig_global_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *global = json_object_new_object();
    struct json_object *capabilities = json_object_new_object();
    sqlite3_stmt *st = NULL;

    if (jmx_netconfig_db_init() != 0) goto done;
    if (nc_prepare(&st,
        "SELECT default_posture,mdns_proxy,igmp_snooping,stp_mode,"
        "rogue_dhcp_detection,jumbo_frames,flow_control,dot1x,bridge_stp,bridge_forward_delay,"
        "wan_mode "
        "FROM network_global WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            nc_add_text(global, "default_posture", st, 0);
            nc_add_text(global, "mdns_proxy", st, 1);
            json_object_object_add(global, "igmp_snooping", json_object_new_boolean(sqlite3_column_int(st, 2)));
            nc_add_text(global, "stp_mode", st, 3);
            json_object_object_add(global, "rogue_dhcp_detection", json_object_new_boolean(sqlite3_column_int(st, 4)));
            json_object_object_add(global, "jumbo_frames", json_object_new_boolean(sqlite3_column_int(st, 5)));
            json_object_object_add(global, "flow_control", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(global, "dot1x", json_object_new_boolean(sqlite3_column_int(st, 7)));
            json_object_object_add(global, "bridge_stp", json_object_new_boolean(sqlite3_column_int(st, 8)));
            json_object_object_add(global, "bridge_forward_delay", json_object_new_int(sqlite3_column_int(st, 9)));
            /*
             * wan_mode is "failover" | "load_balance". A row written before this
             * column existed reads as NULL/empty, which must not surface as ""
             * -- the frontend treats an empty string as a real value and would
             * select neither radio. Normalise to the documented default instead.
             */
            {
                const char *mode = (const char *)sqlite3_column_text(st, 10);

                if (!mode || !mode[0] || (strcmp(mode, "failover") && strcmp(mode, "load_balance")))
                    mode = "failover";
                json_object_object_add(global, "wan_mode", json_object_new_string(mode));
            }
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(global, "persisted", json_object_new_boolean(1));
    json_object_object_add(global, "applied", json_object_new_boolean(0));
    json_object_object_add(global, "apply_state", json_object_new_string("unsupported"));
    json_object_object_add(global, "runtime_reason",
                           json_object_new_string("transactional_global_network_executor_pending"));
    json_object_object_add(data, "global", global);
    json_object_object_add(capabilities, "read", json_object_new_boolean(1));
    json_object_object_add(capabilities, "save", json_object_new_boolean(0));
    json_object_object_add(capabilities, "apply", json_object_new_boolean(0));
    json_object_object_add(capabilities, "readback", json_object_new_boolean(0));
    json_object_object_add(capabilities, "rollback", json_object_new_boolean(0));
    json_object_object_add(capabilities, "reason",
                           json_object_new_string("transactional_global_network_executor_pending"));
    json_object_object_add(data, "capabilities", capabilities);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_netconfig_network_overview(void)
{
    struct json_object *data = json_object_new_object();
    int side_router = jmx_netconfig_work_mode_is_side_router();

    json_object_object_add(data, "work_mode",
                           json_object_new_string(side_router ? "side-router" : "gateway"));
    json_object_object_add(data, "canonical_mode",
                           json_object_new_string(side_router ? "side-router" : "gateway"));
    json_object_object_add(data, "port_role_partition_applicable",
                           json_object_new_boolean(!side_router));
    struct json_object *global = jmx_netconfig_global_get();
    struct json_object *global_data = NULL;
    if (global && json_object_object_get_ex(global, "data", &global_data)) {
        json_object_object_add(data, "global", json_object_get(global_data));
    }
    if (global) json_object_put(global);

    struct json_object *wans = jmx_netconfig_wan_list();
    struct json_object *wan_data = NULL;
    struct json_object *wan_caps = NULL;
    if (wans && json_object_object_get_ex(wans, "data", &wan_data)) {
        json_object_object_add(data, "wans", json_object_get(wan_data));
        if (json_object_object_get_ex(wan_data, "capabilities", &wan_caps) && wan_caps)
            json_object_object_add(data, "capabilities", json_object_get(wan_caps));
    }
    if (wans) json_object_put(wans);

    struct json_object *lans = jmx_netconfig_lan_list();
    struct json_object *lan_data = NULL;
    if (lans && json_object_object_get_ex(lans, "data", &lan_data)) {
        json_object_object_add(data, "lans", json_object_get(lan_data));
    }
    if (lans) json_object_put(lans);

    /* wan_list already computes the same capability projection. Keep a
     * standalone fallback for older/partial list responses. */
    if (!wan_caps) {
        struct json_object *caps = jmx_netconfig_capabilities();
        struct json_object *caps_data = NULL;
        if (caps && json_object_object_get_ex(caps, "data", &caps_data))
            json_object_object_add(data, "capabilities", json_object_get(caps_data));
        if (caps) json_object_put(caps);
    }

    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* validation error helper: check if LAN set needs global validation context */
static int nc_lan_requires_global(const char *mode)
{
    return (mode && (!strcmp(mode, "gateway") || !strcmp(mode, "bypass_router")));
}

/* Only these values are accepted anywhere wan_mode is read or written. */
static int nc_wan_mode_valid(const char *mode)
{
    return mode && (!strcmp(mode, "failover") || !strcmp(mode, "load_balance"));
}

int jmx_netconfig_wan_mode_get(char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;

    if (!out || out_len == 0)
        return -1;
    /* Default first, so every early return below is already safe. */
    snprintf(out, out_len, "failover");
    if (jmx_netconfig_db_init() != 0)
        return 0;
    if (nc_prepare(&st, "SELECT wan_mode FROM network_global WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *mode = (const char *)sqlite3_column_text(st, 0);

            if (nc_wan_mode_valid(mode))
                snprintf(out, out_len, "%s", mode);
        }
        sqlite3_finalize(st);
    }
    return 0;
}

/*
 * Global network write path.
 *
 * This deliberately implements a *whitelist of one*: wan_mode. Every other
 * column in network_global still has no transactional apply/readback/rollback
 * story, which is why POST/PUT /api/v1/network/global rejects them at the webd
 * layer. Widening this function is not a matter of adding binds here -- each
 * field needs a runtime executor first, or the UI gets a control that saves and
 * does nothing.
 *
 * Returns 0 on success, -2 when the payload carries no writable field (caller
 * maps that to the existing capability_disabled response), -1 on db failure.
 */
int jmx_netconfig_global_set(struct json_object *global_json)
{
    struct json_object *v = NULL;
    const char *mode;
    sqlite3_stmt *st = NULL;
    int rc;

    if (!global_json || !json_object_is_type(global_json, json_type_object))
        return -2;
    if (!json_object_object_get_ex(global_json, "wan_mode", &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return -2;
    mode = json_object_get_string(v);
    if (!nc_wan_mode_valid(mode))
        return -1;
    if (jmx_netconfig_db_init() != 0)
        return -1;
    /* id=1 is created by the schema, but INSERT..ON CONFLICT keeps this correct
     * on a database whose singleton row was never materialised. */
    if (nc_prepare(&st,
            "INSERT INTO network_global(id,wan_mode) VALUES(1,?1) "
            "ON CONFLICT(id) DO UPDATE SET wan_mode=excluded.wan_mode") != 0)
        return -1;
    sqlite3_bind_text(st, 1, mode, -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc == 0 ? 0 : -1;
}

int jmx_netconfig_global_apply(void)
{
    return -2;
}

static void nc_physical_port_owner(const char *port, char *owner_type, size_t owner_type_len,
                                   char *owner_id, size_t owner_id_len)
{
    sqlite3_stmt *st = NULL;
    owner_type[0] = owner_id[0] = '\0';
    if (nc_prepare(&st, "SELECT id FROM wan WHERE device=?1 OR ifname=?1 LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, port, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(owner_type, owner_type_len, "wan");
            snprintf(owner_id, owner_id_len, "%s", (const char *)sqlite3_column_text(st, 0));
            sqlite3_finalize(st); return;
        }
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st, "SELECT lan_id FROM lan_port WHERE port=?1 LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, port, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(owner_type, owner_type_len, "lan");
            snprintf(owner_id, owner_id_len, "%s", (const char *)sqlite3_column_text(st, 0));
            sqlite3_finalize(st); return;
        }
        sqlite3_finalize(st);
    }
}

static void nc_read_speed_label(const char *ifname, char *out, size_t out_len)
{
    char path[256], buf[64];
    FILE *fp;
    if (out_len > 0) out[0] = '\0';
    if ((size_t)snprintf(path, sizeof(path), "/sys/class/net/%s/speed",
                         ifname) >= sizeof(path))
        return;
    fp = fopen(path, "r");
    if (!fp) return;
    if (fgets(buf, sizeof(buf), fp)) {
        int mbps = atoi(buf);
        if (mbps > 0) snprintf(out, out_len, "%dM", mbps);
    }
    fclose(fp);
}

static void nc_trim_line(char *s)
{
    size_t len;

    if (!s)
        return;
    s[strcspn(s, "\r\n")] = 0;
    while (*s && isspace((unsigned char)*s))
        memmove(s, s + 1, strlen(s));
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = 0;
}

static int nc_read_int_file(const char *path, int def)
{
    FILE *fp;
    char buf[64];
    char *end = NULL;
    long v;

    fp = fopen(path, "r");
    if (!fp)
        return def;
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return def;
    }
    fclose(fp);
    nc_trim_line(buf);
    errno = 0;
    v = strtol(buf, &end, 10);
    if (errno || end == buf)
        return def;
    return (int)v;
}

static int nc_read_str_file(const char *path, char *out, size_t out_len)
{
    FILE *fp;

    if (!out || out_len == 0)
        return -1;
    out[0] = 0;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, out_len, fp)) {
        fclose(fp);
        out[0] = 0;
        return -1;
    }
    fclose(fp);
    nc_trim_line(out);
    return out[0] ? 0 : -1;
}

static int nc_read_u64_file(const char *path, uint64_t *out)
{
    FILE *fp;
    char buf[64];
    char *end = NULL;
    unsigned long long value;

    if (!path || !out)
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    errno = 0;
    value = strtoull(buf, &end, 10);
    if (errno || end == buf)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

#define NC_PORT_STAT_SAMPLE_MAX 64

struct nc_port_stat_sample {
    char ifname[32];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    int64_t sample_ms;
};

static struct nc_port_stat_sample g_port_stat_samples[NC_PORT_STAT_SAMPLE_MAX];

static int64_t nc_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static struct nc_port_stat_sample *nc_port_stat_sample_get(const char *ifname)
{
    struct nc_port_stat_sample *empty = NULL;
    int i;

    for (i = 0; i < NC_PORT_STAT_SAMPLE_MAX; i++) {
        if (g_port_stat_samples[i].ifname[0] &&
            !strcmp(g_port_stat_samples[i].ifname, ifname))
            return &g_port_stat_samples[i];
        if (!empty && !g_port_stat_samples[i].ifname[0])
            empty = &g_port_stat_samples[i];
    }
    if (empty)
        snprintf(empty->ifname, sizeof(empty->ifname), "%s", ifname);
    return empty;
}

static void nc_physical_port_add_statistics(struct json_object *port,
                                            struct json_object *runtime,
                                            const char *ifname)
{
    static const struct {
        const char *json_key;
        const char *sysfs_name;
    } counters[] = {
        { "rx_bytes", "rx_bytes" }, { "tx_bytes", "tx_bytes" },
        { "rx_packets", "rx_packets" }, { "tx_packets", "tx_packets" },
        { "rx_errors", "rx_errors" }, { "tx_errors", "tx_errors" },
        { "rx_dropped", "rx_dropped" }, { "tx_dropped", "tx_dropped" },
        { "rx_multicast", "multicast" }
    };
    struct json_object *stats = json_object_new_object();
    struct json_object *caps = json_object_new_object();
    struct nc_port_stat_sample *sample;
    uint64_t values[sizeof(counters) / sizeof(counters[0])] = {0};
    uint64_t rx_rate = 0;
    uint64_t tx_rate = 0;
    int64_t now_ms = nc_monotonic_ms();
    int64_t interval_ms = 0;
    int sample_valid = 0;
    const char *reason = "first_sample";
    char path[256];
    char mac[64] = "";
    int i;

    if (!port || !ifname || !ifname[0]) {
        json_object_put(stats);
        json_object_put(caps);
        return;
    }
    for (i = 0; i < (int)(sizeof(counters) / sizeof(counters[0])); i++) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/%s",
                 ifname, counters[i].sysfs_name);
        if (nc_read_u64_file(path, &values[i]) == 0) {
            json_object_object_add(port, counters[i].json_key,
                                   json_object_new_int64((int64_t)values[i]));
            json_object_object_add(stats, counters[i].json_key,
                                   json_object_new_int64((int64_t)values[i]));
        } else {
            json_object_object_add(port, counters[i].json_key, json_object_new_null());
            json_object_object_add(stats, counters[i].json_key, json_object_new_null());
        }
    }

    sample = nc_port_stat_sample_get(ifname);
    if (sample && sample->sample_ms > 0 && now_ms > sample->sample_ms) {
        interval_ms = now_ms - sample->sample_ms;
        if (values[0] >= sample->rx_bytes && values[1] >= sample->tx_bytes &&
            interval_ms >= 250) {
            rx_rate = (values[0] - sample->rx_bytes) * 1000 / (uint64_t)interval_ms;
            tx_rate = (values[1] - sample->tx_bytes) * 1000 / (uint64_t)interval_ms;
            sample_valid = 1;
            reason = "ok";
        } else if (values[0] < sample->rx_bytes || values[1] < sample->tx_bytes) {
            reason = "counter_reset";
        } else {
            reason = "sample_interval_too_short";
        }
    }
    if (sample && (!sample->sample_ms || interval_ms >= 250 ||
                   values[0] < sample->rx_bytes || values[1] < sample->tx_bytes)) {
        sample->rx_bytes = values[0];
        sample->tx_bytes = values[1];
        sample->sample_ms = now_ms;
    }

    json_object_object_add(port, "rx_rate", json_object_new_int64((int64_t)rx_rate));
    json_object_object_add(port, "tx_rate", json_object_new_int64((int64_t)tx_rate));
    json_object_object_add(stats, "rx_rate", json_object_new_int64((int64_t)rx_rate));
    json_object_object_add(stats, "tx_rate", json_object_new_int64((int64_t)tx_rate));
    json_object_object_add(stats, "rate_unit", json_object_new_string("bytes_per_second"));
    json_object_object_add(stats, "sample_valid", json_object_new_boolean(sample_valid));
    json_object_object_add(stats, "sample_interval_ms", json_object_new_int64(interval_ms));
    json_object_object_add(stats, "reason", json_object_new_string(reason));
    json_object_object_add(stats, "statistics_source", json_object_new_string("sysfs:netdev_statistics"));
    json_object_object_add(port, "sample_valid", json_object_new_boolean(sample_valid));
    json_object_object_add(port, "sample_interval_ms", json_object_new_int64(interval_ms));
    json_object_object_add(port, "statistics_source", json_object_new_string("sysfs:netdev_statistics"));

    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    if (nc_read_str_file(path, mac, sizeof(mac)) == 0) {
        json_object_object_add(port, "local_mac", json_object_new_string(mac));
        json_object_object_add(port, "mac_source", json_object_new_string("sysfs:address"));
    } else {
        json_object_object_add(port, "local_mac", json_object_new_null());
        json_object_object_add(port, "mac_source", json_object_new_string("unavailable"));
    }

    json_object_object_add(port, "tx_multicast", json_object_new_null());
    json_object_object_add(port, "rx_broadcast", json_object_new_null());
    json_object_object_add(port, "tx_broadcast", json_object_new_null());
    json_object_object_add(port, "activity_seconds", json_object_new_null());
    json_object_object_add(port, "link_up_at", json_object_new_null());
    json_object_object_add(caps, "rx_multicast", json_object_new_boolean(1));
    json_object_object_add(caps, "tx_multicast", json_object_new_boolean(0));
    json_object_object_add(caps, "broadcast_counters", json_object_new_boolean(0));
    json_object_object_add(caps, "link_up_time", json_object_new_boolean(0));
    json_object_object_add(stats, "capabilities", caps);
    json_object_object_add(port, "statistics", stats);
    if (runtime)
        json_object_object_add(runtime, "statistics", json_object_get(stats));
}

static int nc_str_contains_i_local(const char *haystack, const char *needle);

static const char *nc_stp_state_name(int state)
{
    switch (state) {
    case 0: return "disabled";
    case 1: return "listening";
    case 2: return "learning";
    case 3: return "forwarding";
    case 4: return "blocking";
    default: return "unknown";
    }
}

static struct json_object *nc_physical_port_stp_runtime(const char *ifname)
{
    struct json_object *stp = json_object_new_object();
    char path[256];
    char bridge_path[512];
    char bridge_name[128] = "";
    char *base;
    ssize_t n;
    int state;
    int port_no;
    int root_port = -1;
    int designated_root = 0;
    const char *role = "unknown";

    snprintf(path, sizeof(path), "/sys/class/net/%s/brport", ifname ? ifname : "");
    if (!ifname || !ifname[0] || access(path, F_OK) != 0) {
        json_object_object_add(stp, "supported", json_object_new_boolean(0));
        json_object_object_add(stp, "state", json_object_new_string("disabled"));
        json_object_object_add(stp, "role", json_object_new_string("none"));
        json_object_object_add(stp, "reason", json_object_new_string("not_a_linux_bridge_port"));
        json_object_object_add(stp, "source", json_object_new_string("sysfs:brport"));
        return stp;
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/brport/state", ifname);
    state = nc_read_int_file(path, -1);
    snprintf(path, sizeof(path), "/sys/class/net/%s/brport/port_no", ifname);
    port_no = nc_read_int_file(path, -1);
    snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge", ifname);
    n = readlink(path, bridge_path, sizeof(bridge_path) - 1);
    if (n > 0) {
        bridge_path[n] = 0;
        base = strrchr(bridge_path, '/');
        JMX_STRBUF_COPY(bridge_name, base ? base + 1 : bridge_path);
    }
    if (bridge_name[0]) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/bridge/root_port", bridge_name);
        root_port = nc_read_int_file(path, -1);
        snprintf(path, sizeof(path), "/sys/class/net/%s/bridge/root_id", bridge_name);
        {
            char root_id[128] = "";
            char bridge_id[128] = "";
            nc_read_str_file(path, root_id, sizeof(root_id));
            snprintf(path, sizeof(path), "/sys/class/net/%s/bridge/bridge_id", bridge_name);
            nc_read_str_file(path, bridge_id, sizeof(bridge_id));
            designated_root = root_id[0] && bridge_id[0] && !strcmp(root_id, bridge_id);
        }
    }
    if (state == 0)
        role = "disabled";
    else if (!designated_root && root_port > 0 && port_no == root_port)
        role = "root";
    else if (state == 4)
        role = "alternate";
    else if (state >= 1 && state <= 3)
        role = "designated";

    json_object_object_add(stp, "supported", json_object_new_boolean(state >= 0));
    json_object_object_add(stp, "state", json_object_new_string(nc_stp_state_name(state)));
    json_object_object_add(stp, "role", json_object_new_string(role));
    json_object_object_add(stp, "port_no", port_no >= 0 ? json_object_new_int(port_no) : json_object_new_null());
    json_object_object_add(stp, "bridge", json_object_new_string(bridge_name));
    json_object_object_add(stp, "bridge_is_root", json_object_new_boolean(designated_root));
    json_object_object_add(stp, "topology_change_count_supported", json_object_new_boolean(0));
    json_object_object_add(stp, "topology_change_count", json_object_new_null());
    json_object_object_add(stp, "last_topology_change_at", json_object_new_null());
    json_object_object_add(stp, "reason", json_object_new_string(state >= 0 ? "" : "brport_state_unavailable"));
    json_object_object_add(stp, "source", json_object_new_string("sysfs:brport+bridge"));
    return stp;
}

static void nc_physical_port_add_identity(struct json_object *port, const char *ifname,
                                          const char *display_name, int sort_order,
                                          const char *runtime_port_type)
{
    char path[256];
    char phys_name[128] = "";
    char phys_id[128] = "";
    const char *media = "unknown";
    int port_number = -1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/phys_port_name", ifname ? ifname : "");
    nc_read_str_file(path, phys_name, sizeof(phys_name));
    snprintf(path, sizeof(path), "/sys/class/net/%s/phys_port_id", ifname ? ifname : "");
    nc_read_str_file(path, phys_id, sizeof(phys_id));
    if (phys_name[0]) {
        const char *p = phys_name;
        while (*p && !isdigit((unsigned char)*p)) p++;
        if (*p) port_number = atoi(p);
    }
    if (runtime_port_type && runtime_port_type[0]) {
        if (nc_str_contains_i_local(runtime_port_type, "fibre")) media = "SFP";
        else if (nc_str_contains_i_local(runtime_port_type, "tp")) media = "RJ45";
        else if (nc_str_contains_i_local(runtime_port_type, "aui")) media = "AUI";
        else if (nc_str_contains_i_local(runtime_port_type, "bnc")) media = "BNC";
    }

    json_object_object_add(port, "display_name",
                           json_object_new_string(display_name && display_name[0] ? display_name : ifname));
    json_object_object_add(port, "alias", json_object_new_string(display_name ? display_name : ""));
    json_object_object_add(port, "sort_order", json_object_new_int(sort_order));
    json_object_object_add(port, "port_number", port_number >= 0 ? json_object_new_int(port_number) : json_object_new_null());
    json_object_object_add(port, "hardware_position", json_object_new_string(phys_name));
    json_object_object_add(port, "physical_port_id", json_object_new_string(phys_id));
    json_object_object_add(port, "media_type", json_object_new_string(media));
    json_object_object_add(port, "port_number_source",
                           json_object_new_string(port_number >= 0 ? "sysfs:phys_port_name" : "unavailable_not_guessed"));
    json_object_object_add(port, "display_metadata_source",
                           json_object_new_string(display_name && display_name[0] ? "config.db:physical_port_config" : "ifname_fallback"));
}

static void nc_normalize_duplex(const char *in, char *out, size_t out_len)
{
    size_t i;

    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "unknown");
    if (!in || !in[0])
        return;
    if (!strncasecmp(in, "full", 4)) {
        snprintf(out, out_len, "full");
        return;
    }
    if (!strncasecmp(in, "half", 4)) {
        snprintf(out, out_len, "half");
        return;
    }
    if (!strncasecmp(in, "unknown", 7)) {
        snprintf(out, out_len, "unknown");
        return;
    }
    snprintf(out, out_len, "%s", in);
    for (i = 0; out[i]; i++)
        out[i] = (char)tolower((unsigned char)out[i]);
}

static void nc_speed_label_from_mbps(int mbps, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (mbps <= 0)
        return;
    if (mbps >= 1000 && mbps % 1000 == 0)
        snprintf(out, out_len, "%dG", mbps / 1000);
    else
        snprintf(out, out_len, "%dM", mbps);
}

static int nc_json_array_has_int(struct json_object *arr, int v)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        if (json_object_get_int(json_object_array_get_idx(arr, i)) == v)
            return 1;
    }
    return 0;
}

static void nc_json_array_add_unique_int(struct json_object *arr, int v)
{
    if (!arr || v <= 0 || nc_json_array_has_int(arr, v))
        return;
    json_object_array_add(arr, json_object_new_int(v));
}

static int nc_json_array_has_str(struct json_object *arr, const char *s)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !s || !s[0])
        return 0;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        const char *cur = json_object_get_string(json_object_array_get_idx(arr, i));
        if (cur && !strcmp(cur, s))
            return 1;
    }
    return 0;
}

static void nc_json_array_add_unique_str(struct json_object *arr, const char *s)
{
    if (!arr || !s || !s[0] || nc_json_array_has_str(arr, s))
        return;
    json_object_array_add(arr, json_object_new_string(s));
}

static int nc_parse_speed_token_mbps(const char *tok)
{
    const char *p;
    char *end = NULL;
    long v;

    if (!tok || !isdigit((unsigned char)tok[0]) || !strstr(tok, "base") || !strchr(tok, '/'))
        return 0;
    errno = 0;
    v = strtol(tok, &end, 10);
    if (errno || end == tok || v <= 0 || v > 1000000)
        return 0;
    p = strstr(tok, "base");
    if (!p || p < end)
        return 0;
    return (int)v;
}

static void nc_port_runtime_parse_mode_token(const char *tok,
                                             struct json_object *speeds,
                                             struct json_object *duplexes,
                                             struct json_object *modes)
{
    int mbps;
    const char *slash;
    char duplex[16];

    if (!tok || !tok[0])
        return;
    mbps = nc_parse_speed_token_mbps(tok);
    if (mbps > 0)
        nc_json_array_add_unique_int(speeds, mbps);
    slash = strchr(tok, '/');
    if (slash && slash[1]) {
        nc_normalize_duplex(slash + 1, duplex, sizeof(duplex));
        if (strcmp(duplex, "unknown"))
            nc_json_array_add_unique_str(duplexes, duplex);
    }
    if (mbps > 0)
        nc_json_array_add_unique_str(modes, tok);
}

static void nc_port_runtime_parse_mode_line(const char *line,
                                            struct json_object *speeds,
                                            struct json_object *duplexes,
                                            struct json_object *modes)
{
    char buf[512];
    char *save = NULL;
    char *tok;

    if (!line || !line[0])
        return;
    snprintf(buf, sizeof(buf), "%s", line);
    for (tok = strtok_r(buf, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save))
        nc_port_runtime_parse_mode_token(tok, speeds, duplexes, modes);
}

static int nc_parse_ethtool_bool_tail(const char *line)
{
    const char *p = strchr(line ? line : "", ':');

    if (!p)
        return -1;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!strncasecmp(p, "yes", 3) || !strncasecmp(p, "on", 2))
        return 1;
    if (!strncasecmp(p, "no", 2) || !strncasecmp(p, "off", 3))
        return 0;
    return -1;
}

static int nc_parse_ethtool_speed_tail(const char *line)
{
    const char *p = strchr(line ? line : "", ':');
    char *end = NULL;
    long v;

    if (!p)
        return 0;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!isdigit((unsigned char)*p))
        return 0;
    errno = 0;
    v = strtol(p, &end, 10);
    if (errno || end == p || v <= 0 || v > 1000000)
        return 0;
    return (int)v;
}

static const char *nc_find_exec_bin(const char *name, char *buf, size_t len)
{
    static const char *dirs[] = { "/usr/sbin", "/usr/bin", "/sbin", "/bin", NULL };
    int i;

    if (!name || !buf || len == 0)
        return "";
    buf[0] = '\0';
    for (i = 0; dirs[i]; i++) {
        if (snprintf(buf, len, "%s/%s", dirs[i], name) >= (int)len)
            continue;
        if (access(buf, X_OK) == 0)
            return buf;
    }
    buf[0] = '\0';
    return "";
}

static int nc_json_array_contains_int_value(struct json_object *arr, int v)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    n = (int)json_object_array_length(arr);
    if (n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        if (json_object_get_int(json_object_array_get_idx(arr, i)) == v)
            return 1;
    }
    return 0;
}

static int nc_json_array_contains_str_value(struct json_object *arr, const char *v)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !v || !v[0])
        return 0;
    n = (int)json_object_array_length(arr);
    if (n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        const char *cur = json_object_get_string(json_object_array_get_idx(arr, i));
        if (cur && !strcmp(cur, v))
            return 1;
    }
    return 0;
}

static void nc_parse_ethtool_text_tail(const char *line, char *out, size_t out_len)
{
    const char *p = strchr(line ? line : "", ':');

    if (!out || out_len == 0)
        return;
    out[0] = 0;
    if (!p)
        return;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    snprintf(out, out_len, "%s", p);
    nc_trim_line(out);
}

static struct json_object *nc_physical_port_runtime_info(const char *ifname,
                                                         const char *db_speed_label,
                                                         const char *db_duplex,
                                                         const char *db_status)
{
    struct json_object *o = json_object_new_object();
    struct json_object *speeds = json_object_new_array();
    struct json_object *duplexes = json_object_new_array();
    struct json_object *modes = json_object_new_array();
    struct json_object *caps = json_object_new_object();
    char path[256];
    char cmd[256];
    char line[512];
    char speed_label[32] = "";
    char sys_duplex_raw[32] = "";
    char duplex[32] = "";
    char port_type[64] = "";
    int speed_mbps = 0;
    int sys_speed = 0;
    int carrier = -1;
    int link_detected = -1;
    int supports_autoneg = -1;
    int advertised_autoneg = -1;
    int autoneg = -1;
    int ethtool_ok = 0;
    int speed_read = 0;
    int duplex_read = 0;
    int supported_modes_read = 0;
    int degraded = 0;
    const char *reason = "";
    FILE *fp;

    if (!ifname || !ifname[0] || !nc_valid_name(ifname)) {
        json_object_object_add(o, "degraded", json_object_new_boolean(1));
        json_object_object_add(o, "reason", json_object_new_string("invalid_ifname"));
        json_object_put(speeds);
        json_object_put(duplexes);
        json_object_put(modes);
        json_object_put(caps);
        return o;
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
    sys_speed = nc_read_int_file(path, 0);
    if (sys_speed > 0) {
        speed_mbps = sys_speed;
        speed_read = 1;
        nc_json_array_add_unique_int(speeds, sys_speed);
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", ifname);
    if (nc_read_str_file(path, sys_duplex_raw, sizeof(sys_duplex_raw)) == 0) {
        nc_normalize_duplex(sys_duplex_raw, duplex, sizeof(duplex));
        duplex_read = strcmp(duplex, "unknown") != 0;
        if (duplex_read)
            nc_json_array_add_unique_str(duplexes, duplex);
    } else {
        nc_normalize_duplex(db_duplex, duplex, sizeof(duplex));
        duplex_read = strcmp(duplex, "unknown") != 0;
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/carrier", ifname);
    carrier = nc_read_int_file(path, -1);
    if (carrier >= 0)
        link_detected = carrier ? 1 : 0;

    snprintf(cmd, sizeof(cmd), "ethtool %s 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;

            line[strcspn(line, "\r\n")] = 0;
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!strncmp(p, "Supported link modes:", 21)) {
                ethtool_ok = 1;
                nc_port_runtime_parse_mode_line(strchr(p, ':') ? strchr(p, ':') + 1 : p,
                                                speeds, duplexes, modes);
            } else if (!strncmp(p, "Advertised link modes:", 22)) {
                ethtool_ok = 1;
                nc_port_runtime_parse_mode_line(strchr(p, ':') ? strchr(p, ':') + 1 : p,
                                                speeds, duplexes, modes);
            } else if (isdigit((unsigned char)*p) && strstr(p, "base")) {
                ethtool_ok = 1;
                nc_port_runtime_parse_mode_line(p, speeds, duplexes, modes);
            } else if (!strncmp(p, "Supports auto-negotiation:", 26)) {
                ethtool_ok = 1;
                supports_autoneg = nc_parse_ethtool_bool_tail(p);
            } else if (!strncmp(p, "Advertised auto-negotiation:", 28)) {
                ethtool_ok = 1;
                advertised_autoneg = nc_parse_ethtool_bool_tail(p);
            } else if (!strncmp(p, "Auto-negotiation:", 17)) {
                ethtool_ok = 1;
                autoneg = nc_parse_ethtool_bool_tail(p);
            } else if (!strncmp(p, "Speed:", 6)) {
                int s = nc_parse_ethtool_speed_tail(p);
                ethtool_ok = 1;
                if (s > 0) {
                    speed_mbps = s;
                    speed_read = 1;
                    nc_json_array_add_unique_int(speeds, s);
                }
            } else if (!strncmp(p, "Duplex:", 7)) {
                char raw[64];
                ethtool_ok = 1;
                nc_parse_ethtool_text_tail(p, raw, sizeof(raw));
                nc_normalize_duplex(raw, duplex, sizeof(duplex));
                duplex_read = strcmp(duplex, "unknown") != 0;
                if (duplex_read)
                    nc_json_array_add_unique_str(duplexes, duplex);
            } else if (!strncmp(p, "Port:", 5)) {
                nc_parse_ethtool_text_tail(p, port_type, sizeof(port_type));
            } else if (!strncmp(p, "Link detected:", 14)) {
                ethtool_ok = 1;
                link_detected = nc_parse_ethtool_bool_tail(p);
            }
        }
        pclose(fp);
    }

    supported_modes_read = json_object_array_length(modes) > 0;
    if (!speed_label[0] && db_speed_label && db_speed_label[0])
        snprintf(speed_label, sizeof(speed_label), "%s", db_speed_label);
    if (!speed_label[0])
        nc_speed_label_from_mbps(speed_mbps, speed_label, sizeof(speed_label));
    if (!speed_label[0] && speed_mbps > 0)
        snprintf(speed_label, sizeof(speed_label), "%dM", speed_mbps);

    if (!ethtool_ok && access("/usr/sbin/ethtool", X_OK) != 0 && access("/usr/bin/ethtool", X_OK) != 0) {
        degraded = 1;
        reason = "ethtool_unavailable";
    } else if (link_detected == 1 && speed_mbps <= 0) {
        degraded = 1;
        reason = "link_up_speed_unknown";
    } else if (link_detected == 1 && !duplex_read) {
        degraded = 1;
        reason = "link_up_duplex_unknown";
    } else if (ethtool_ok && !supported_modes_read) {
        degraded = 1;
        reason = "supported_modes_not_reported";
    }

    json_object_object_add(o, "speed_mbps", json_object_new_int(speed_mbps > 0 ? speed_mbps : 0));
    json_object_object_add(o, "link_speed_mbps", json_object_new_int(speed_mbps > 0 ? speed_mbps : 0));
    json_object_object_add(o, "speed_label", json_object_new_string(speed_label));
    json_object_object_add(o, "duplex", json_object_new_string(duplex[0] ? duplex : "unknown"));
    json_object_object_add(o, "autoneg", autoneg >= 0 ? json_object_new_boolean(autoneg) : json_object_new_null());
    json_object_object_add(o, "supports_autoneg", supports_autoneg >= 0 ? json_object_new_boolean(supports_autoneg) : json_object_new_null());
    json_object_object_add(o, "advertised_autoneg", advertised_autoneg >= 0 ? json_object_new_boolean(advertised_autoneg) : json_object_new_null());
    json_object_object_add(o, "link_detected", link_detected >= 0 ? json_object_new_boolean(link_detected) : json_object_new_null());
    json_object_object_add(o, "port_type", json_object_new_string(port_type));
    {
        struct json_object *stp = nc_physical_port_stp_runtime(ifname);
        struct json_object *supported = stp ? json_object_object_get(stp, "supported") : NULL;
        json_object_object_add(o, "stp", stp ? stp : json_object_new_object());
        json_object_object_add(o, "stp_state",
                               json_object_new_string(stp ? nc_json_str_def(stp, "state", "unknown") : "unknown"));
        json_object_object_add(o, "stp_role",
                               json_object_new_string(stp ? nc_json_str_def(stp, "role", "unknown") : "unknown"));
        json_object_object_add(caps, "stp_runtime",
                               json_object_new_boolean(supported && json_object_get_boolean(supported)));
    }
    json_object_object_add(o, "supported_speeds", speeds);
    json_object_object_add(o, "supported_duplex", duplexes);
    json_object_object_add(o, "supported_link_modes", modes);
    json_object_object_add(o, "capability_source", json_object_new_string(ethtool_ok ? "ethtool+sysfs" : "sysfs"));
    json_object_object_add(o, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(o, "reason", json_object_new_string(reason));
    json_object_object_add(o, "status", json_object_new_string(db_status && db_status[0] ? db_status : (link_detected == 1 ? "up" : (link_detected == 0 ? "down" : "unknown"))));

    json_object_object_add(caps, "read", json_object_new_boolean(1));
    json_object_object_add(caps, "runtime_state", json_object_new_boolean(1));
    json_object_object_add(caps, "speed_read", json_object_new_boolean(speed_read));
    json_object_object_add(caps, "duplex_read", json_object_new_boolean(duplex_read));
    json_object_object_add(caps, "autoneg_read", json_object_new_boolean(autoneg >= 0 || supports_autoneg >= 0));
    json_object_object_add(caps, "supported_modes_read", json_object_new_boolean(supported_modes_read));
    json_object_object_add(caps, "runtime_speed_config_detected", json_object_new_boolean(supported_modes_read));
    json_object_object_add(caps, "runtime_duplex_config_detected", json_object_new_boolean(json_object_array_length(duplexes) > 0));
    json_object_object_add(caps, "speed_config_possible", json_object_new_boolean(ethtool_ok && supported_modes_read));
    json_object_object_add(caps, "duplex_config_possible", json_object_new_boolean(ethtool_ok && json_object_array_length(duplexes) > 0));
    json_object_object_add(caps, "speed_config_persistent", json_object_new_boolean(1));
    json_object_object_add(caps, "duplex_config_persistent", json_object_new_boolean(1));
    json_object_object_add(caps, "vlan_config_possible", json_object_new_boolean(0));
    json_object_object_add(caps, "poe_config_possible", json_object_new_boolean(0));
    json_object_object_add(caps, "port_reassignment_possible", json_object_new_boolean(0));
    json_object_object_add(caps, "reason", json_object_new_string(ethtool_ok ? "runtime_ethtool_capability_visible; persistent_speed_duplex_apply_available" : "runtime_capability_partial"));
    json_object_object_add(o, "capabilities", caps);

    return o;
}

static void nc_physical_port_config_to_json(sqlite3_stmt *st, struct json_object *cfg)
{
    if (!st || !cfg)
        return;
    nc_add_text(cfg, "ifname", st, 0);
    json_object_object_add(cfg, "configured_speed_mbps", json_object_new_int(sqlite3_column_int(st, 1)));
    nc_add_text(cfg, "configured_duplex", st, 2);
    json_object_object_add(cfg, "configured_autoneg", json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(cfg, "autoneg_configured",
                           sqlite3_column_int(st, 3) < 0 ? json_object_new_null() :
                           json_object_new_boolean(sqlite3_column_int(st, 3)));
    nc_add_text(cfg, "profile_id", st, 4);
    json_object_object_add(cfg, "native_vlan", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(cfg, "tagged_vlans", nc_json_array_from_text((const char *)sqlite3_column_text(st, 6)));
    json_object_object_add(cfg, "poe_enabled",
                           sqlite3_column_int(st, 7) < 0 ? json_object_new_null() :
                           json_object_new_boolean(sqlite3_column_int(st, 7)));
    nc_add_text(cfg, "poe_mode", st, 8);
    nc_add_text(cfg, "display_name", st, 9);
    json_object_object_add(cfg, "sort_order", json_object_new_int(sqlite3_column_int(st, 10)));
    json_object_object_add(cfg, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
    json_object_object_add(cfg, "last_apply_at", json_object_new_int64(sqlite3_column_int64(st, 12)));
    json_object_object_add(cfg, "last_apply_ok", json_object_new_boolean(sqlite3_column_int(st, 13)));
    nc_add_text(cfg, "last_apply_error", st, 14);
}

static int nc_path_exists(const char *path)
{
    return path && path[0] && access(path, F_OK) == 0;
}

static int nc_executable_exists(const char *path)
{
    return path && path[0] && access(path, X_OK) == 0;
}

static int nc_str_contains_i_local(const char *haystack, const char *needle)
{
    size_t needle_len;

    if (!haystack || !needle || !needle[0])
        return 0;
    needle_len = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        if (!strncasecmp(p, needle, needle_len))
            return 1;
    }
    return 0;
}

static int nc_glob_has_match(const char *dir_path, const char *needle)
{
    DIR *dir;
    struct dirent *de;
    int hit = 0;

    if (!dir_path || !needle)
        return 0;
    dir = opendir(dir_path);
    if (!dir)
        return 0;
    while ((de = readdir(dir)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (nc_str_contains_i_local(de->d_name, needle)) {
            hit = 1;
            break;
        }
    }
    closedir(dir);
    return hit;
}

static struct json_object *nc_physical_port_poe_probe(const char *ifname,
                                                      int configured_enabled,
                                                      const char *configured_mode)
{
    struct json_object *poe = json_object_new_object();
    struct json_object *probe = json_object_new_object();
    struct json_object *controllers = json_object_new_array();
    struct json_object *checked = json_object_new_array();
    int ubnt_poe = nc_executable_exists("/usr/sbin/ubnt-poe") ||
                   nc_executable_exists("/sbin/ubnt-poe") ||
                   nc_executable_exists("/usr/bin/ubnt-poe") ||
                   nc_executable_exists("/bin/ubnt-poe");
    int poecli = nc_executable_exists("/usr/sbin/poecli") ||
                 nc_executable_exists("/sbin/poecli") ||
                 nc_executable_exists("/usr/bin/poecli") ||
                 nc_executable_exists("/bin/poecli");
    int pectl = nc_executable_exists("/usr/sbin/pectl") ||
                nc_executable_exists("/sbin/pectl") ||
                nc_executable_exists("/usr/bin/pectl") ||
                nc_executable_exists("/bin/pectl");
    int sys_class_poe = nc_path_exists("/sys/class/poe");
    int sys_class_pse = nc_path_exists("/sys/class/pse") ||
                        nc_path_exists("/sys/class/pse_control");
    int hwmon_poe = nc_glob_has_match("/sys/class/hwmon", "poe") ||
                    nc_glob_has_match("/sys/class/hwmon", "pse");
    int of_poe = nc_glob_has_match("/proc/device-tree", "poe") ||
                 nc_glob_has_match("/proc/device-tree", "pse");
    int supported;
    const char *reason;

    json_object_array_add(checked, json_object_new_string("/sys/class/poe"));
    json_object_array_add(checked, json_object_new_string("/sys/class/pse"));
    json_object_array_add(checked, json_object_new_string("/sys/class/pse_control"));
    json_object_array_add(checked, json_object_new_string("/sys/class/hwmon/*poe*"));
    json_object_array_add(checked, json_object_new_string("/proc/device-tree/*poe*"));
    json_object_array_add(checked, json_object_new_string("ubnt-poe"));
    json_object_array_add(checked, json_object_new_string("poecli"));
    json_object_array_add(checked, json_object_new_string("pectl"));

    if (ubnt_poe)
        json_object_array_add(controllers, json_object_new_string("ubnt-poe"));
    if (poecli)
        json_object_array_add(controllers, json_object_new_string("poecli"));
    if (pectl)
        json_object_array_add(controllers, json_object_new_string("pectl"));
    if (sys_class_poe)
        json_object_array_add(controllers, json_object_new_string("sysfs:/sys/class/poe"));
    if (sys_class_pse)
        json_object_array_add(controllers, json_object_new_string("sysfs:pse"));
    if (hwmon_poe)
        json_object_array_add(controllers, json_object_new_string("sysfs:hwmon_poe"));
    if (of_poe)
        json_object_array_add(controllers, json_object_new_string("device-tree:poe"));

    supported = json_object_array_length(controllers) > 0;
    if (supported)
        reason = "poe_controller_detected_but_runtime_apply_not_integrated";
    else if (configured_enabled >= 0 || (configured_mode && configured_mode[0]))
        reason = "poe_config_saved_but_no_controller_detected";
    else
        reason = "no_poe_controller_detected";

    json_object_object_add(probe, "ifname", json_object_new_string(ifname ? ifname : ""));
    json_object_object_add(probe, "checked", checked);
    json_object_object_add(probe, "controllers", controllers);
    json_object_object_add(probe, "sys_class_poe", json_object_new_boolean(sys_class_poe));
    json_object_object_add(probe, "sys_class_pse", json_object_new_boolean(sys_class_pse));
    json_object_object_add(probe, "hwmon_poe", json_object_new_boolean(hwmon_poe));
    json_object_object_add(probe, "device_tree_poe", json_object_new_boolean(of_poe));
    json_object_object_add(probe, "ubnt_poe_cli", json_object_new_boolean(ubnt_poe));
    json_object_object_add(probe, "poecli", json_object_new_boolean(poecli));
    json_object_object_add(probe, "pectl", json_object_new_boolean(pectl));
    json_object_object_add(probe, "reason", json_object_new_string(reason));

    json_object_object_add(poe, "supported", json_object_new_boolean(supported));
    json_object_object_add(poe, "runtime_read", json_object_new_boolean(supported));
    json_object_object_add(poe, "runtime_apply", json_object_new_boolean(0));
    json_object_object_add(poe, "configured", json_object_new_boolean(configured_enabled >= 0 ||
                                                                       (configured_mode && configured_mode[0])));
    json_object_object_add(poe, "enabled", configured_enabled < 0 ?
                           json_object_new_null() : json_object_new_boolean(configured_enabled));
    json_object_object_add(poe, "mode", json_object_new_string(configured_mode ? configured_mode : ""));
    json_object_object_add(poe, "power_w", json_object_new_null());
    json_object_object_add(poe, "voltage_v", json_object_new_null());
    json_object_object_add(poe, "current_ma", json_object_new_null());
    json_object_object_add(poe, "controller_count", json_object_new_int((int)json_object_array_length(controllers)));
    json_object_object_add(poe, "controller_probe", probe);
    json_object_object_add(poe, "reason", json_object_new_string(reason));
    return poe;
}

static void nc_physical_port_add_poe_capabilities(struct json_object *caps,
                                                  struct json_object *poe)
{
    const char *reason = "poe_probe_not_returned_by_core";

    if (!caps)
        return;
    if (poe)
        reason = nc_json_str_def(poe, "reason", reason);
    json_object_object_add(caps, "poe_probe", json_object_new_boolean(poe != NULL));
    json_object_object_add(caps, "poe_probe_source", json_object_new_string("physical_port_list.ports[].poe"));
    json_object_object_add(caps, "poe_supported", json_object_new_boolean(poe && nc_json_bool_def(poe, "supported", 0)));
    json_object_object_add(caps, "poe_runtime_read", json_object_new_boolean(poe && nc_json_bool_def(poe, "runtime_read", 0)));
    json_object_object_add(caps, "poe_runtime_apply", json_object_new_boolean(0));
    json_object_object_add(caps, "poe_controller_count", json_object_new_int(poe ? nc_json_int_def(poe, "controller_count", 0) : 0));
    json_object_object_add(caps, "poe_reason", json_object_new_string(reason && reason[0] ? reason : "unknown"));
}

static int nc_json_has_key(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;

    return o && k && json_object_object_get_ex(o, k, &v);
}

static int nc_json_has_any_key(struct json_object *o, const char *a, const char *b)
{
    return nc_json_has_key(o, a) || nc_json_has_key(o, b);
}

static int nc_vlan_id_ok(int vlan)
{
    return vlan >= 0 && vlan <= 4094;
}

static int nc_vlan_array_valid(struct json_object *arr, char *err, size_t err_len)
{
    int i, n, j;

    if (!arr)
        return 1;
    if (!json_object_is_type(arr, json_type_array)) {
        if (err && err_len) snprintf(err, err_len, "tagged_vlans_must_be_array");
        return 0;
    }
    n = (int)json_object_array_length(arr);
    if (n > 256) {
        if (err && err_len) snprintf(err, err_len, "too_many_tagged_vlans");
        return 0;
    }
    for (i = 0; i < n; i++) {
        struct json_object *vobj = json_object_array_get_idx(arr, i);
        int v;

        if (!vobj || !json_object_is_type(vobj, json_type_int)) {
            if (err && err_len) snprintf(err, err_len, "tagged_vlan_must_be_integer");
            return 0;
        }
        v = json_object_get_int(vobj);
        if (v <= 0 || v > 4094) {
            if (err && err_len) snprintf(err, err_len, "invalid_tagged_vlan_%d", v);
            return 0;
        }
        for (j = i + 1; j < n; j++) {
            struct json_object *next = json_object_array_get_idx(arr, j);
            if (next && json_object_is_type(next, json_type_int) &&
                json_object_get_int(next) == v) {
                if (err && err_len) snprintf(err, err_len, "duplicate_tagged_vlan_%d", v);
                return 0;
            }
        }
    }
    return 1;
}

static int nc_physical_port_ifname_strict_ok(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t len;

    if (!s || !s[0])
        return 0;
    len = strlen(s);
    if (len > 15 || s[0] == '-' || s[0] == '.' || strstr(s, ".."))
        return 0;
    for (; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')
            continue;
        return 0;
    }
    return 1;
}

static struct json_object *nc_physical_port_profile_lookup_plain(const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *profile = NULL;

    if (!id || !id[0] || jmx_netconfig_db_init() != 0)
        return NULL;
    if (nc_prepare(&st,
        "SELECT id,name,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,"
        "stp_guard,storm_control,description,updated_at,created_at "
        "FROM physical_port_profile WHERE id=?1") != 0)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        profile = json_object_new_object();
        nc_physical_port_profile_to_json(st, profile);
    }
    sqlite3_finalize(st);
    return profile;
}

static void nc_physical_port_config_existing_values(const char *ifname,
                                                    int *speed, char *duplex, size_t duplex_len,
                                                    int *autoneg,
                                                    char *profile_id, size_t profile_len,
                                                    int *native_vlan,
                                                    char *tagged_json, size_t tagged_len,
                                                    int *poe_enabled,
                                                    char *poe_mode, size_t poe_mode_len)
{
    sqlite3_stmt *st = NULL;

    if (speed) *speed = 0;
    if (duplex && duplex_len) duplex[0] = '\0';
    if (autoneg) *autoneg = -1;
    if (profile_id && profile_len) profile_id[0] = '\0';
    if (native_vlan) *native_vlan = 0;
    if (tagged_json && tagged_len) snprintf(tagged_json, tagged_len, "[]");
    if (poe_enabled) *poe_enabled = -1;
    if (poe_mode && poe_mode_len) poe_mode[0] = '\0';

    if (!ifname || !ifname[0] || jmx_netconfig_db_init() != 0)
        return;
    if (nc_prepare(&st,
        "SELECT configured_speed_mbps,configured_duplex,configured_autoneg,"
        "profile_id,native_vlan,tagged_vlans_json,poe_enabled,poe_mode "
        "FROM physical_port_config WHERE ifname=?1") != 0)
        return;
    sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (speed) *speed = sqlite3_column_int(st, 0);
        if (duplex && duplex_len)
            snprintf(duplex, duplex_len, "%s", nc_sql_text(st, 1));
        if (autoneg) *autoneg = sqlite3_column_int(st, 2);
        if (profile_id && profile_len)
            snprintf(profile_id, profile_len, "%s", nc_sql_text(st, 3));
        if (native_vlan) *native_vlan = sqlite3_column_int(st, 4);
        if (tagged_json && tagged_len)
            snprintf(tagged_json, tagged_len, "%s",
                     sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "[]");
        if (poe_enabled) *poe_enabled = sqlite3_column_int(st, 6);
        if (poe_mode && poe_mode_len)
            snprintf(poe_mode, poe_mode_len, "%s", nc_sql_text(st, 7));
    }
    sqlite3_finalize(st);
}

static struct json_object *nc_physical_port_config_lookup(const char *ifname)
{
    sqlite3_stmt *st = NULL;
    struct json_object *cfg = json_object_new_object();

    if (!cfg)
        return NULL;
    json_object_object_add(cfg, "ifname", json_object_new_string(ifname ? ifname : ""));
    json_object_object_add(cfg, "configured_speed_mbps", json_object_new_int(0));
    json_object_object_add(cfg, "configured_duplex", json_object_new_string(""));
    json_object_object_add(cfg, "configured_autoneg", json_object_new_int(-1));
    json_object_object_add(cfg, "autoneg_configured", json_object_new_null());
    json_object_object_add(cfg, "profile_id", json_object_new_string(""));
    json_object_object_add(cfg, "native_vlan", json_object_new_int(0));
    json_object_object_add(cfg, "tagged_vlans", json_object_new_array());
    json_object_object_add(cfg, "poe_enabled", json_object_new_null());
    json_object_object_add(cfg, "poe_mode", json_object_new_string(""));
    json_object_object_add(cfg, "display_name", json_object_new_string(""));
    json_object_object_add(cfg, "sort_order", json_object_new_int(0));
    json_object_object_add(cfg, "updated_at", json_object_new_int64(0));
    json_object_object_add(cfg, "last_apply_at", json_object_new_int64(0));
    json_object_object_add(cfg, "last_apply_ok", json_object_new_boolean(0));
    json_object_object_add(cfg, "last_apply_error", json_object_new_string(""));
    json_object_object_add(cfg, "saved", json_object_new_boolean(0));

    if (!ifname || !ifname[0] || jmx_netconfig_db_init() != 0)
        return cfg;
    if (nc_prepare(&st,
        "SELECT ifname,configured_speed_mbps,configured_duplex,configured_autoneg,"
        "profile_id,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,"
        "display_name,sort_order,updated_at,last_apply_at,last_apply_ok,last_apply_error "
        "FROM physical_port_config WHERE ifname=?1") == 0) {
        sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_put(cfg);
            cfg = json_object_new_object();
            nc_physical_port_config_to_json(st, cfg);
            json_object_object_add(cfg, "saved", json_object_new_boolean(1));
        }
        sqlite3_finalize(st);
    }
    return cfg;
}

static void nc_physical_port_config_attach_profile(struct json_object *cfg)
{
    const char *profile_id;
    struct json_object *profile;

    if (!cfg)
        return;
    profile_id = nc_json_str_def(cfg, "profile_id", "");
    if (!profile_id[0]) {
        json_object_object_add(cfg, "profile", json_object_new_null());
        return;
    }
    profile = nc_physical_port_profile_lookup_plain(profile_id);
    if (profile) {
        json_object_object_add(cfg, "profile", profile);
        json_object_object_add(cfg, "profile_found", json_object_new_boolean(1));
    } else {
        json_object_object_add(cfg, "profile", json_object_new_null());
        json_object_object_add(cfg, "profile_found", json_object_new_boolean(0));
        json_object_object_add(cfg, "profile_reason", json_object_new_string("profile_not_found"));
    }
}

struct json_object *jmx_netconfig_physical_port_config_get(const char *ifname)
{
    struct json_object *data = json_object_new_object();
    struct json_object *cfg = NULL;
    struct json_object *port = NULL;
    sqlite3_stmt *st = NULL;

    if (!ifname || !ifname[0] || !nc_physical_port_ifname_strict_ok(ifname)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_ifname"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("db_init_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    cfg = nc_physical_port_config_lookup(ifname);
    if (nc_prepare(&st,
        "SELECT name,label,kind,speed_label,duplex,owner_type,owner_id,status "
        "FROM physical_port WHERE name=?1") == 0) {
        sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *runtime;
            const char *name = nc_sql_text(st, 0);
            const char *speed_label = nc_sql_text(st, 3);
            const char *duplex = nc_sql_text(st, 4);
            const char *status = nc_sql_text(st, 7);

            port = json_object_new_object();
            nc_add_text(port, "name", st, 0);
            nc_add_text(port, "ifname", st, 0);
            nc_add_text(port, "label", st, 1);
            nc_add_text(port, "kind", st, 2);
            nc_add_text(port, "owner_type", st, 5);
            nc_add_text(port, "owner_id", st, 6);
            runtime = nc_physical_port_runtime_info(name, speed_label, duplex, status);
            if (runtime) {
                nc_json_copy_key(port, "speed_mbps", runtime, "speed_mbps");
                nc_json_copy_key(port, "link_speed_mbps", runtime, "link_speed_mbps");
                nc_json_copy_key(port, "speed_label", runtime, "speed_label");
                nc_json_copy_key(port, "duplex", runtime, "duplex");
                nc_json_copy_key(port, "autoneg", runtime, "autoneg");
                nc_json_copy_key(port, "supports_autoneg", runtime, "supports_autoneg");
                nc_json_copy_key(port, "supported_speeds", runtime, "supported_speeds");
                nc_json_copy_key(port, "supported_duplex", runtime, "supported_duplex");
                nc_json_copy_key(port, "stp", runtime, "stp");
                nc_json_copy_key(port, "stp_state", runtime, "stp_state");
                nc_json_copy_key(port, "stp_role", runtime, "stp_role");
                nc_json_copy_key(port, "capabilities", runtime, "capabilities");
                json_object_object_add(port, "runtime", runtime);
            }
            nc_physical_port_add_identity(port, name,
                                          nc_json_str_def(cfg, "display_name", ""),
                                          nc_json_int_def(cfg, "sort_order", 0),
                                          runtime ? nc_json_str_def(runtime, "port_type", "") : "");
        }
        sqlite3_finalize(st);
    }
    nc_physical_port_config_attach_profile(cfg);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "config", cfg ? cfg : json_object_new_object());
    json_object_object_add(data, "port", port ? port : json_object_new_null());
    {
        struct json_object *caps = json_object_new_object();
        struct json_object *poe = NULL;

        if (port) {
            const char *ifn = nc_json_str_def(port, "ifname", ifname);
            const char *mode = nc_json_str_def(cfg, "poe_mode", "");
            int enabled = -1;
            struct json_object *v = json_object_object_get(cfg, "poe_enabled");

            if (v && !json_object_is_type(v, json_type_null))
                enabled = json_object_get_boolean(v) ? 1 : 0;
            poe = nc_physical_port_poe_probe(ifn, enabled, mode);
            json_object_object_add(port, "poe", json_object_get(poe));
        }
        json_object_object_add(caps, "speed_config_persistent", json_object_new_boolean(1));
        json_object_object_add(caps, "duplex_config_persistent", json_object_new_boolean(1));
        json_object_object_add(caps, "vlan_profile_saved", json_object_new_boolean(1));
        json_object_object_add(caps, "vlan_runtime_apply", json_object_new_boolean(0));
        json_object_object_add(caps, "port_stp_runtime", json_object_new_boolean(1));
        json_object_object_add(caps, "port_alias_write", json_object_new_boolean(1));
        json_object_object_add(caps, "port_display_metadata", json_object_new_boolean(1));
        nc_physical_port_add_poe_capabilities(caps, poe);
        json_object_object_add(data, "capabilities", caps);
        if (poe)
            json_object_put(poe);
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int nc_physical_port_config_store(const char *ifname, int speed, const char *duplex,
                                         int autoneg, const char *profile_id, int native_vlan,
                                         const char *tagged_json, int poe_enabled,
                                         const char *poe_mode)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!ifname || !ifname[0] || !nc_iface_name_ok(ifname))
        return -1;
    if (jmx_netconfig_db_init() != 0)
        return -1;
    if (nc_prepare(&st,
        "INSERT INTO physical_port_config("
        "ifname,configured_speed_mbps,configured_duplex,configured_autoneg,"
        "profile_id,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,updated_at)"
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) "
        "ON CONFLICT(ifname) DO UPDATE SET "
        "configured_speed_mbps=excluded.configured_speed_mbps,"
        "configured_duplex=excluded.configured_duplex,"
        "configured_autoneg=excluded.configured_autoneg,"
        "profile_id=excluded.profile_id,"
        "native_vlan=excluded.native_vlan,"
        "tagged_vlans_json=excluded.tagged_vlans_json,"
        "poe_enabled=excluded.poe_enabled,"
        "poe_mode=excluded.poe_mode,"
        "updated_at=excluded.updated_at") != 0)
        return -1;
    sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, speed > 0 ? speed : 0);
    sqlite3_bind_text(st, 3, duplex ? duplex : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, autoneg);
    sqlite3_bind_text(st, 5, profile_id ? profile_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, native_vlan > 0 ? native_vlan : 0);
    sqlite3_bind_text(st, 7, tagged_json && tagged_json[0] ? tagged_json : "[]", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 8, poe_enabled);
    sqlite3_bind_text(st, 9, poe_mode ? poe_mode : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, nc_now_s());
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

static int nc_physical_port_metadata_store(const char *ifname,
                                           const char *display_name, int display_name_present,
                                           int sort_order, int sort_order_present)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!ifname || !ifname[0] || !nc_iface_name_ok(ifname) ||
        (!display_name_present && !sort_order_present)) return 0;
    if (display_name_present && (!display_name || strlen(display_name) > 96 ||
        strchr(display_name, '\n') || strchr(display_name, '\r'))) return -1;
    if (sort_order_present && (sort_order < -10000 || sort_order > 10000)) return -1;
    if (nc_prepare(&st,
        "INSERT INTO physical_port_config(ifname,display_name,sort_order,updated_at) "
        "VALUES(?1,?2,?3,?4) ON CONFLICT(ifname) DO UPDATE SET "
        "display_name=CASE WHEN ?5 THEN excluded.display_name ELSE display_name END,"
        "sort_order=CASE WHEN ?6 THEN excluded.sort_order ELSE sort_order END,"
        "updated_at=excluded.updated_at") != 0) return -1;
    sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, display_name_present ? display_name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, sort_order_present ? sort_order : 0);
    sqlite3_bind_int64(st, 4, nc_now_s());
    sqlite3_bind_int(st, 5, display_name_present ? 1 : 0);
    sqlite3_bind_int(st, 6, sort_order_present ? 1 : 0);
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

static int nc_physical_port_metadata_valid(const char *display_name, int display_name_present,
                                           int sort_order, int sort_order_present)
{
    if (display_name_present && (!display_name || strlen(display_name) > 96 ||
        strchr(display_name, '\n') || strchr(display_name, '\r')))
        return 0;
    if (sort_order_present && (sort_order < -10000 || sort_order > 10000))
        return 0;
    return 1;
}

static void nc_physical_port_config_mark_apply(const char *ifname, int ok, const char *err)
{
    sqlite3_stmt *st = NULL;

    if (!ifname || !ifname[0] || jmx_netconfig_db_init() != 0)
        return;
    if (nc_prepare(&st,
        "UPDATE physical_port_config SET last_apply_at=?2,last_apply_ok=?3,"
        "last_apply_error=?4 WHERE ifname=?1") == 0) {
        sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, nc_now_s());
        sqlite3_bind_int(st, 3, ok ? 1 : 0);
        sqlite3_bind_text(st, 4, err ? err : "", -1, SQLITE_TRANSIENT);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
}

static int nc_physical_port_ethtool_apply(const char *ifname, int speed, const char *duplex,
                                          int autoneg, struct json_object *port,
                                          char *err, size_t err_len)
{
    struct json_object *caps = NULL;
    struct json_object *supported_speeds = NULL;
    struct json_object *supported_duplex = NULL;
    char ethtool[64];
    char cmd[512];
    char qif[160];
    int supports_autoneg = -1;
    int rc;

    if (err && err_len)
        err[0] = 0;
    if (!ifname || !ifname[0] || !nc_iface_name_ok(ifname)) {
        if (err && err_len) snprintf(err, err_len, "invalid_ifname");
        return -1;
    }
    if (speed <= 0 && autoneg < 0 && (!duplex || !duplex[0])) {
        if (err && err_len) snprintf(err, err_len, "no_runtime_speed_duplex_change");
        return 0;
    }
    if (!nc_find_exec_bin("ethtool", ethtool, sizeof(ethtool))[0]) {
        if (err && err_len) snprintf(err, err_len, "ethtool_unavailable");
        return -2;
    }
    if (port) {
        json_object_object_get_ex(port, "supported_speeds", &supported_speeds);
        json_object_object_get_ex(port, "supported_duplex", &supported_duplex);
        json_object_object_get_ex(port, "capabilities", &caps);
        if (caps) {
            struct json_object *v = NULL;
            if (json_object_object_get_ex(caps, "autoneg_read", &v) && v)
                supports_autoneg = json_object_get_boolean(v) ? 1 : -1;
        }
        if (speed > 0 && supported_speeds && json_object_array_length(supported_speeds) > 0 &&
            !nc_json_array_contains_int_value(supported_speeds, speed)) {
            if (err && err_len) snprintf(err, err_len, "speed_not_advertised");
            return -3;
        }
        if (duplex && duplex[0] && supported_duplex && json_object_array_length(supported_duplex) > 0 &&
            !nc_json_array_contains_str_value(supported_duplex, duplex)) {
            if (err && err_len) snprintf(err, err_len, "duplex_not_advertised");
            return -4;
        }
    }
    if (autoneg >= 0 && supports_autoneg == 0) {
        if (err && err_len) snprintf(err, err_len, "autoneg_not_supported");
        return -5;
    }
    cmd[0] = '\0';
    snprintf(qif, sizeof(qif), "'%s'", ifname);
    if (autoneg == 1 && speed <= 0 && (!duplex || !duplex[0]))
        snprintf(cmd, sizeof(cmd), "%s -s %s autoneg on >/tmp/dw-port-ethtool.log 2>&1", ethtool, qif);
    else if (speed > 0) {
        char with_speed[512];
        snprintf(with_speed, sizeof(with_speed), "%s -s %s speed %d%s%s%s >/tmp/dw-port-ethtool.log 2>&1",
                 ethtool, qif, speed,
                 (duplex && duplex[0]) ? " duplex " : "",
                 (duplex && duplex[0]) ? duplex : "",
                 autoneg >= 0 ? (autoneg ? " autoneg on" : " autoneg off") : "");
        snprintf(cmd, sizeof(cmd), "%s", with_speed);
    } else if (duplex && duplex[0]) {
        if (err && err_len) snprintf(err, err_len, "duplex_change_requires_speed");
        return -7;
    } else if (autoneg == 0) {
        if (err && err_len) snprintf(err, err_len, "autoneg_off_requires_speed");
        return -8;
    }
    if (!cmd[0]) {
        if (err && err_len) snprintf(err, err_len, "no_runtime_speed_duplex_change");
        return 0;
    }
    rc = nc_run_quiet(cmd);
    if (rc != 0) {
        if (err && err_len) snprintf(err, err_len, "ethtool_apply_failed_rc_%d", rc);
        return -6;
    }
    return 0;
}

/* ── §12 item 4: post-apply link readback verdict ──────────────────────────
 * nc_port_link_readback_verify — PURE, side-effect-free.
 *
 * Returns 1 = verified, 0 = not verified, -1 = indeterminate.
 *
 * EVIDENCE ONLY.  The apply/rollback success gate stays runtime_rc /
 * last_apply_ok and is NOT changed by this verdict.  A legitimate no-op/auto
 * success (a port with no cable, or an admin-down port) must not be turned
 * into a failure, so this helper is deliberately not wired into any gate: it
 * only surfaces whether the REAL negotiated link matches intent, per §12
 * item 4.  If a hard gate is ever wanted it belongs at the caller as an
 * operator policy — intentionally left out here.
 *
 * Convention on the observed inputs:
 *   link_detected        : 1 up, 0 down, <0 unreadable (no /sys carrier and
 *                          ethtool silent) → honest indeterminate.
 *   observed_speed_mbps  : <=0 means the negotiated speed could not be read.
 *   observed_autoneg     : recorded as evidence by the caller; not part of the
 *                          verdict, so it is accepted and ignored here.
 * The auto/unset sentinel (intended speed<=0 && autoneg<0 && empty duplex) is
 * the core of the gap: for it, "verified" means the link actually came up and
 * negotiated a real speed, never merely that a no-op returned 0.
 */
static int nc_port_link_readback_verify(int intended_speed_mbps,
                                        const char *intended_duplex,
                                        int intended_autoneg,
                                        int observed_speed_mbps,
                                        const char *observed_duplex,
                                        int observed_autoneg,
                                        int link_detected,
                                        char *reason, size_t reason_len)
{
    int intended_auto;
    int idup_set;
    int odup_known;

    (void)observed_autoneg;
    if (reason && reason_len)
        reason[0] = 0;

    idup_set = intended_duplex && intended_duplex[0] &&
               strcasecmp(intended_duplex, "unknown") != 0;
    odup_known = observed_duplex && observed_duplex[0] &&
                 strcasecmp(observed_duplex, "unknown") != 0;
    intended_auto = (intended_speed_mbps <= 0 && intended_autoneg < 0 && !idup_set);

    /* The reader could not observe link state at all → honest indeterminate,
     * never a fake healthy or a fake failure. */
    if (link_detected < 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "link_state_unreadable");
        return -1;
    }

    if (intended_auto) {
        if (link_detected == 1 && observed_speed_mbps > 0) {
            if (reason && reason_len)
                snprintf(reason, reason_len, "auto_negotiated_link_up");
            return 1;
        }
        if (link_detected == 1) {
            /* link up but the negotiated speed is unreadable — cannot confirm */
            if (reason && reason_len)
                snprintf(reason, reason_len, "auto_link_up_speed_unreadable");
            return -1;
        }
        if (reason && reason_len)
            snprintf(reason, reason_len, "auto_but_link_down");
        return 0;
    }

    /* Explicit intent: speed and/or duplex and/or autoneg were forced. */
    if (link_detected != 1) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "link_down_after_apply");
        return 0;
    }
    if (intended_speed_mbps > 0) {
        if (observed_speed_mbps <= 0) {
            if (reason && reason_len)
                snprintf(reason, reason_len, "observed_speed_unreadable");
            return -1;
        }
        if (observed_speed_mbps != intended_speed_mbps) {
            if (reason && reason_len)
                snprintf(reason, reason_len,
                         "speed_mismatch_intended_%d_observed_%d",
                         intended_speed_mbps, observed_speed_mbps);
            return 0;
        }
    }
    if (idup_set && odup_known &&
        strcasecmp(intended_duplex, observed_duplex) != 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len,
                     "duplex_mismatch_intended_%s_observed_%s",
                     intended_duplex, observed_duplex);
        return 0;
    }
    if (reason && reason_len)
        snprintf(reason, reason_len, "explicit_link_matches_intended");
    return 1;
}

struct json_object *jmx_netconfig_physical_port_config_apply(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tagged = NULL;
    struct json_object *port = NULL;
    struct json_object *port_resp = NULL;
    struct json_object *port_data = NULL;
    struct json_object *ports = NULL;
    const char *ifname = nc_json_str_def(cfg, "ifname", "");
    const char *duplex_in = nc_json_str_def(cfg, "duplex", nc_json_str_def(cfg, "configured_duplex", ""));
    const char *profile_id = nc_json_str_def(cfg, "profile_id", nc_json_str_def(cfg, "profile", ""));
    const char *poe_mode = nc_json_str_def(cfg, "poe_mode", "");
    char duplex[16] = "";
    char tagged_json[1024] = "[]";
    char err[128] = "";
    char existing_duplex[16] = "";
    char existing_profile_id[128] = "";
    char existing_tagged_json[1024] = "[]";
    char existing_poe_mode[64] = "";
    int speed = nc_json_int_def(cfg, "speed_mbps", nc_json_int_def(cfg, "configured_speed_mbps", 0));
    int autoneg = -1;
    int native_vlan = nc_json_int_def(cfg, "native_vlan", nc_json_int_def(cfg, "vlan_id", 0));
    int poe_enabled = -1;
    int existing_speed = 0;
    int existing_autoneg = -1;
    int existing_native_vlan = 0;
    int existing_poe_enabled = -1;
    int runtime_rc = 0;
    int i;
    int speed_present = nc_json_has_any_key(cfg, "speed_mbps", "configured_speed_mbps");
    int duplex_present = nc_json_has_any_key(cfg, "duplex", "configured_duplex");
    int autoneg_present = nc_json_has_any_key(cfg, "autoneg", "configured_autoneg");
    int profile_present = nc_json_has_any_key(cfg, "profile_id", "profile");
    int native_vlan_present = nc_json_has_any_key(cfg, "native_vlan", "vlan_id");
    int tagged_present = nc_json_has_key(cfg, "tagged_vlans");
    int poe_enabled_present = nc_json_has_key(cfg, "poe_enabled");
    int poe_mode_present = nc_json_has_key(cfg, "poe_mode");
    int display_name_present = nc_json_has_any_key(cfg, "display_name", "alias");
    int sort_order_present = nc_json_has_key(cfg, "sort_order");
    const char *display_name = nc_json_str_def(cfg, "display_name", nc_json_str_def(cfg, "alias", ""));
    int sort_order = nc_json_int_def(cfg, "sort_order", 0);
    int runtime_speed_duplex_requested = speed_present || duplex_present || autoneg_present;

    if (!ifname || !ifname[0] || !nc_physical_port_ifname_strict_ok(ifname)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_ifname"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("db_init_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (profile_present && profile_id && profile_id[0] && !nc_valid_name(profile_id)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_profile_id"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (poe_mode_present && poe_mode && poe_mode[0] && !nc_valid_name(poe_mode)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_poe_mode"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (!nc_physical_port_metadata_valid(display_name, display_name_present,
                                         sort_order, sort_order_present)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_port_metadata"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    nc_physical_port_config_existing_values(ifname,
                                            &existing_speed, existing_duplex, sizeof(existing_duplex),
                                            &existing_autoneg,
                                            existing_profile_id, sizeof(existing_profile_id),
                                            &existing_native_vlan,
                                            existing_tagged_json, sizeof(existing_tagged_json),
                                            &existing_poe_enabled,
                                            existing_poe_mode, sizeof(existing_poe_mode));
    if (!speed_present)
        speed = existing_speed;
    if (duplex_in && duplex_in[0]) {
        nc_normalize_duplex(duplex_in, duplex, sizeof(duplex));
        if (!strcmp(duplex, "unknown"))
            duplex[0] = 0;
    }
    if (!duplex_present)
        snprintf(duplex, sizeof(duplex), "%s", existing_duplex);
    if (json_object_object_get_ex(cfg, "autoneg", &tagged) && tagged)
        autoneg = json_object_get_boolean(tagged) ? 1 : 0;
    else
        autoneg = nc_json_int_def(cfg, "configured_autoneg", -1);
    if (!autoneg_present)
        autoneg = existing_autoneg;
    if (!profile_present)
        profile_id = existing_profile_id;
    if (!native_vlan_present)
        native_vlan = existing_native_vlan;
    if (!poe_mode_present)
        poe_mode = existing_poe_mode;
    if (profile_present && profile_id && profile_id[0]) {
        struct json_object *profile = nc_physical_port_profile_lookup_plain(profile_id);
        struct json_object *pv = NULL;

        if (profile) {
            if (!native_vlan_present)
                native_vlan = nc_json_int_def(profile, "native_vlan", native_vlan);
            if (!tagged_present && json_object_object_get_ex(profile, "tagged_vlans", &pv) &&
                pv && json_object_is_type(pv, json_type_array)) {
                char *tmp = nc_json_array_to_string(pv, existing_tagged_json);
                snprintf(existing_tagged_json, sizeof(existing_tagged_json), "%s", tmp ? tmp : "[]");
                if (tmp) free(tmp);
            }
            if (!poe_mode_present)
                poe_mode = nc_json_str_def(profile, "poe_mode", poe_mode);
            json_object_put(profile);
        }
    }
    tagged = NULL;
    if (json_object_object_get_ex(cfg, "tagged_vlans", &tagged) && tagged &&
        json_object_is_type(tagged, json_type_array)) {
        if (!nc_vlan_array_valid(tagged, err, sizeof(err))) {
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string(err[0] ? err : "invalid_tagged_vlans"));
            return jmx_gen_api_response_data(API_CODE_ERROR, data);
        }
        snprintf(tagged_json, sizeof(tagged_json), "%s",
                 json_object_to_json_string_ext(tagged, JSON_C_TO_STRING_PLAIN));
    } else if (tagged_present) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("tagged_vlans_must_be_array"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    } else {
        snprintf(tagged_json, sizeof(tagged_json), "%s", existing_tagged_json);
    }
    if (!nc_vlan_id_ok(native_vlan)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_native_vlan"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (json_object_object_get_ex(cfg, "poe_enabled", &tagged) && tagged)
        poe_enabled = json_object_get_boolean(tagged) ? 1 : 0;
    else if (!poe_enabled_present)
        poe_enabled = existing_poe_enabled;

    if (poe_enabled_present || poe_mode_present) {
        struct json_object *poe_probe = nc_physical_port_poe_probe(ifname, poe_enabled, poe_mode);
        const char *poe_reason = nc_json_str_def(poe_probe, "reason", "poe_runtime_apply_not_integrated");

        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "saved", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("poe_config_apply_unsupported"));
        json_object_object_add(data, "message", json_object_new_string("PoE config is not saved or applied until a supported PoE controller adapter is integrated"));
        json_object_object_add(data, "reason", json_object_new_string(poe_reason && poe_reason[0] ? poe_reason : "poe_runtime_apply_not_integrated"));
        nc_physical_port_add_poe_capabilities(data, poe_probe);
        json_object_object_add(data, "poe", poe_probe);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    if (nc_physical_port_config_store(ifname, speed, duplex, autoneg, profile_id,
                                      native_vlan, tagged_json, poe_enabled, poe_mode) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("config_store_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_physical_port_metadata_store(ifname, display_name, display_name_present,
                                        sort_order, sort_order_present) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_or_unwritable_port_metadata"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    port_resp = jmx_netconfig_physical_port_list();
    port_data = port_resp ? json_object_object_get(port_resp, "data") : NULL;
    ports = port_data ? json_object_object_get(port_data, "ports") : NULL;
    if (ports && json_object_is_type(ports, json_type_array)) {
        for (i = 0; i < (int)json_object_array_length(ports); i++) {
            struct json_object *p = json_object_array_get_idx(ports, i);
            const char *name = nc_json_str_def(p, "name", "");
            const char *pi = nc_json_str_def(p, "ifname", "");
            if ((name[0] && !strcmp(name, ifname)) || (pi[0] && !strcmp(pi, ifname))) {
                port = json_object_get(p);
                break;
            }
        }
    }
    runtime_rc = runtime_speed_duplex_requested ?
        nc_physical_port_ethtool_apply(ifname, speed, duplex, autoneg, port, err, sizeof(err)) : 0;
    nc_physical_port_config_mark_apply(ifname, runtime_rc == 0, err);
    json_object_object_add(data, "ok", json_object_new_boolean(runtime_rc == 0));
    json_object_object_add(data, "applied", json_object_new_boolean(runtime_rc == 0));
    json_object_object_add(data, "saved", json_object_new_boolean(1));
    json_object_object_add(data, "runtime_apply", json_object_new_boolean(runtime_speed_duplex_requested && runtime_rc == 0));
    json_object_object_add(data, "runtime_speed_duplex_requested", json_object_new_boolean(runtime_speed_duplex_requested));
    json_object_object_add(data, "speed_duplex_runtime_apply", json_object_new_boolean(runtime_speed_duplex_requested && runtime_rc == 0));
    json_object_object_add(data, "runtime_apply_rc", json_object_new_int(runtime_rc));
    json_object_object_add(data, "runtime_apply_error", json_object_new_string(err));
    json_object_object_add(data, "runtime_apply_log", json_object_new_string("/tmp/dw-port-ethtool.log"));
    /* §12 item 4: additive link readback — read the REAL negotiated link state
     * after apply and surface a verdict.  EVIDENCE ONLY: this does NOT feed the
     * ok/applied/runtime_rc gate above, so a no-op/auto success on a port with
     * no cable stays a success while still reporting the true runtime state. */
    {
        struct json_object *rb = nc_physical_port_runtime_info(ifname, "", duplex, NULL);
        struct json_object *link_readback = json_object_new_object();
        struct json_object *rb_caps = NULL;
        struct json_object *jv = NULL;
        struct json_object *intended = json_object_new_object();
        struct json_object *rbc = json_object_new_object();
        const char *obs_duplex = "unknown";
        int obs_speed = 0;
        int obs_autoneg = -1;
        int obs_link = -1;
        int cap_speed = 0, cap_duplex = 0, cap_autoneg = 0;
        int verdict;
        char rb_reason[96] = "";

        if (rb) {
            if (json_object_object_get_ex(rb, "speed_mbps", &jv) && jv)
                obs_speed = json_object_get_int(jv);
            if (json_object_object_get_ex(rb, "duplex", &jv) && jv)
                obs_duplex = json_object_get_string(jv);
            if (json_object_object_get_ex(rb, "autoneg", &jv) && jv &&
                !json_object_is_type(jv, json_type_null))
                obs_autoneg = json_object_get_boolean(jv) ? 1 : 0;
            if (json_object_object_get_ex(rb, "link_detected", &jv) && jv &&
                !json_object_is_type(jv, json_type_null))
                obs_link = json_object_get_boolean(jv) ? 1 : 0;
            if (json_object_object_get_ex(rb, "capabilities", &rb_caps) && rb_caps) {
                if (json_object_object_get_ex(rb_caps, "speed_read", &jv) && jv)
                    cap_speed = json_object_get_boolean(jv) ? 1 : 0;
                if (json_object_object_get_ex(rb_caps, "duplex_read", &jv) && jv)
                    cap_duplex = json_object_get_boolean(jv) ? 1 : 0;
                if (json_object_object_get_ex(rb_caps, "autoneg_read", &jv) && jv)
                    cap_autoneg = json_object_get_boolean(jv) ? 1 : 0;
            }
        }

        verdict = nc_port_link_readback_verify(speed, duplex, autoneg,
                                               obs_speed, obs_duplex, obs_autoneg,
                                               obs_link, rb_reason, sizeof(rb_reason));

        json_object_object_add(link_readback, "speed_mbps", json_object_new_int(obs_speed));
        json_object_object_add(link_readback, "duplex", json_object_new_string(obs_duplex));
        json_object_object_add(link_readback, "autoneg",
                               obs_autoneg < 0 ? json_object_new_null() :
                               json_object_new_boolean(obs_autoneg));
        json_object_object_add(link_readback, "link_detected",
                               obs_link < 0 ? json_object_new_null() :
                               json_object_new_boolean(obs_link));
        json_object_object_add(link_readback, "carrier",
                               obs_link < 0 ? json_object_new_null() :
                               json_object_new_boolean(obs_link));

        json_object_object_add(rbc, "speed_read", json_object_new_boolean(cap_speed));
        json_object_object_add(rbc, "duplex_read", json_object_new_boolean(cap_duplex));
        json_object_object_add(rbc, "autoneg_read", json_object_new_boolean(cap_autoneg));
        json_object_object_add(link_readback, "capabilities", rbc);

        json_object_object_add(intended, "speed_mbps", json_object_new_int(speed > 0 ? speed : 0));
        json_object_object_add(intended, "duplex", json_object_new_string(duplex[0] ? duplex : ""));
        json_object_object_add(intended, "autoneg",
                               autoneg < 0 ? json_object_new_null() :
                               json_object_new_boolean(autoneg));
        json_object_object_add(link_readback, "intended", intended);

        /* Tri-state verdict: true / false / null(indeterminate) — never a fake
         * true and never a fake healthy.  Evidence only; ok/applied unchanged. */
        json_object_object_add(link_readback, "verified",
                               verdict < 0 ? json_object_new_null() :
                               json_object_new_boolean(verdict == 1));
        json_object_object_add(link_readback, "reason", json_object_new_string(rb_reason));
        json_object_object_add(link_readback, "evidence_only", json_object_new_boolean(1));
        json_object_object_add(link_readback, "runtime_speed_duplex_requested",
                               json_object_new_boolean(runtime_speed_duplex_requested));
        if (rb)
            json_object_put(rb);
        json_object_object_add(data, "link_readback", link_readback);
    }
    json_object_object_add(data, "partial_update", json_object_new_boolean(1));
    json_object_object_add(data, "display_metadata_saved",
                           json_object_new_boolean(display_name_present || sort_order_present));
    json_object_object_add(data, "vlan_profile_saved", json_object_new_boolean(profile_id[0] || native_vlan > 0 ||
                                                                                strcmp(tagged_json, "[]")));
    json_object_object_add(data, "vlan_runtime_apply", json_object_new_boolean(0));
    json_object_object_add(data, "vlan_runtime_reason", json_object_new_string("netifd_dsa_bridge_vlan_transaction_pending"));
    {
        struct json_object *poe = port ? json_object_object_get(port, "poe") : NULL;
        nc_physical_port_add_poe_capabilities(data, poe);
        if (poe)
            json_object_object_add(data, "poe", json_object_get(poe));
    }
    {
        struct json_object *saved_cfg = nc_physical_port_config_lookup(ifname);
        nc_physical_port_config_attach_profile(saved_cfg);
        json_object_object_add(data, "config", saved_cfg ? saved_cfg : json_object_new_object());
    }
    if (port)
        json_object_object_add(data, "port", port);
    if (port_resp)
        json_object_put(port_resp);
    return jmx_gen_api_response_data(runtime_rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

int jmx_netconfig_physical_port_apply_saved_all(void)
{
    struct nc_saved_port_config {
        char ifname[64];
        int speed;
        char duplex[16];
        int autoneg;
    };
    sqlite3_stmt *st = NULL;
    struct nc_saved_port_config *items = NULL;
    size_t count = 0;
    size_t capacity = 0;
    int applied = 0;

    if (jmx_netconfig_db_init() != 0)
        return -1;
    if (nc_prepare(&st,
        "SELECT ifname,configured_speed_mbps,configured_duplex,configured_autoneg "
        "FROM physical_port_config "
        "WHERE configured_speed_mbps>0 OR configured_duplex<>'' OR configured_autoneg>=0") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct nc_saved_port_config *next;

        if (count == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 8;

            next = realloc(items, new_capacity * sizeof(*items));
            if (!next) {
                sqlite3_finalize(st);
                free(items);
                return -1;
            }
            items = next;
            capacity = new_capacity;
        }
        snprintf(items[count].ifname, sizeof(items[count].ifname), "%s", nc_sql_text(st, 0));
        items[count].speed = sqlite3_column_int(st, 1);
        snprintf(items[count].duplex, sizeof(items[count].duplex), "%s", nc_sql_text(st, 2));
        items[count].autoneg = sqlite3_column_int(st, 3);
        count++;
    }
    sqlite3_finalize(st);

    for (size_t i = 0; i < count; i++) {
        char err[128] = "";
        int rc = nc_physical_port_ethtool_apply(items[i].ifname, items[i].speed,
                                                items[i].duplex, items[i].autoneg,
                                                NULL, err, sizeof(err));
        nc_physical_port_config_mark_apply(items[i].ifname, rc == 0, err);
        if (rc == 0)
            applied++;
    }
    free(items);
    return applied;
}

static void nc_physical_port_profile_to_json(sqlite3_stmt *st, struct json_object *o)
{
    if (!st || !o)
        return;
    nc_add_text(o, "id", st, 0);
    nc_add_text(o, "name", st, 1);
    json_object_object_add(o, "native_vlan", json_object_new_int(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "tagged_vlans", nc_json_array_from_text((const char *)sqlite3_column_text(st, 3)));
    json_object_object_add(o, "poe_enabled",
                           sqlite3_column_int(st, 4) < 0 ? json_object_new_null() :
                           json_object_new_boolean(sqlite3_column_int(st, 4)));
    nc_add_text(o, "poe_mode", st, 5);
    nc_add_text(o, "stp_guard", st, 6);
    nc_add_text(o, "storm_control", st, 7);
    nc_add_text(o, "description", st, 8);
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(o, "runtime_apply_supported", json_object_new_boolean(0));
    json_object_object_add(o, "runtime_apply_reason", json_object_new_string("netifd_dsa_bridge_vlan_transaction_pending"));
}

static struct json_object *nc_physical_port_profile_caps(void)
{
    struct json_object *cap = json_object_new_object();
    struct json_object *fields = json_object_new_array();

    json_object_array_add(fields, json_object_new_string("native_vlan"));
    json_object_array_add(fields, json_object_new_string("tagged_vlans"));
    json_object_array_add(fields, json_object_new_string("poe_enabled"));
    json_object_array_add(fields, json_object_new_string("poe_mode"));
    json_object_array_add(fields, json_object_new_string("stp_guard"));
    json_object_array_add(fields, json_object_new_string("storm_control"));
    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "write", json_object_new_boolean(1));
    json_object_object_add(cap, "delete", json_object_new_boolean(1));
    json_object_object_add(cap, "delete_dependency_check", json_object_new_boolean(1));
    json_object_object_add(cap, "built_in_profiles_protected", json_object_new_boolean(1));
    json_object_object_add(cap, "profile_persistent", json_object_new_boolean(1));
    json_object_object_add(cap, "runtime_vlan_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "poe_apply", json_object_new_boolean(0));
    json_object_object_add(cap, "supported_fields", fields);
    json_object_object_add(cap, "reason", json_object_new_string("profile catalog is persisted in config.db; runtime bridge vlan/poe apply remains pending"));
    return cap;
}

static void nc_physical_port_profile_ensure_defaults(void)
{
    sqlite3_stmt *st = NULL;
    sqlite3_int64 now = nc_now_s();

    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO physical_port_profile("
        "id,name,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,stp_guard,storm_control,description,created_at,updated_at)"
        "VALUES(?1,?2,?3,?4,-1,'','','',?5,?6,?6)") == 0) {
        sqlite3_bind_text(st, 1, "default-lan", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, "Default LAN", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, 1);
        sqlite3_bind_text(st, 4, "[]", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, "Default untagged LAN profile; runtime VLAN apply pending", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (nc_prepare(&st,
        "INSERT OR IGNORE INTO physical_port_profile("
        "id,name,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,stp_guard,storm_control,description,created_at,updated_at)"
        "VALUES(?1,?2,0,'[]',-1,'','','',?3,?4,?4)") == 0) {
        sqlite3_bind_text(st, 1, "all", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, "All / Trunk placeholder", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, "Trunk/profile placeholder for UI selection; runtime VLAN apply pending", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, now);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
}

struct json_object *jmx_netconfig_physical_port_profile_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("db_init_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    nc_physical_port_profile_ensure_defaults();
    if (nc_prepare(&st,
        "SELECT id,name,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,stp_guard,storm_control,description,updated_at,created_at "
        "FROM physical_port_profile ORDER BY id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_physical_port_profile_to_json(st, o);
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "profiles", arr);
    json_object_object_add(data, "capabilities", nc_physical_port_profile_caps());
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_netconfig_physical_port_profile_get(const char *id)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!id || !id[0] || !nc_valid_name(id)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_profile_id"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("db_init_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    nc_physical_port_profile_ensure_defaults();
    if (nc_prepare(&st,
        "SELECT id,name,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,stp_guard,storm_control,description,updated_at,created_at "
        "FROM physical_port_profile WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_physical_port_profile_to_json(st, o);
            json_object_object_add(data, "profile", o);
            found = 1;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "ok", json_object_new_boolean(found));
    if (!found)
        json_object_object_add(data, "error", json_object_new_string("profile_not_found"));
    json_object_object_add(data, "capabilities", nc_physical_port_profile_caps());
    return jmx_gen_api_response_data(found ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

struct json_object *jmx_netconfig_physical_port_profile_set(struct json_object *cfg)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tagged = NULL;
    char tagged_json[2048] = "[]";
    const char *id = nc_json_str_def(cfg, "id", "");
    const char *name = nc_json_str_def(cfg, "name", id);
    const char *poe_mode = nc_json_str_def(cfg, "poe_mode", "");
    const char *stp_guard = nc_json_str_def(cfg, "stp_guard", "");
    const char *storm_control = nc_json_str_def(cfg, "storm_control", "");
    const char *description = nc_json_str_def(cfg, "description", nc_json_str_def(cfg, "note", ""));
    int native_vlan = nc_json_int_def(cfg, "native_vlan", nc_json_int_def(cfg, "vlan_id", 0));
    int poe_enabled = -1;
    sqlite3_stmt *st = NULL;
    sqlite3_int64 now = nc_now_s();

    if (!id || !id[0] || !nc_valid_name(id) || (name && strlen(name) > 96)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_profile"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (native_vlan < 0 || native_vlan > 4094) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_native_vlan"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (json_object_object_get_ex(cfg, "tagged_vlans", &tagged) && tagged &&
        json_object_is_type(tagged, json_type_array)) {
        char verr[96] = "";
        if (!nc_vlan_array_valid(tagged, verr, sizeof(verr))) {
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string(verr[0] ? verr : "invalid_tagged_vlans"));
            return jmx_gen_api_response_data(API_CODE_ERROR, data);
        }
        char *tmp = nc_json_array_to_string(tagged, "[]");
        snprintf(tagged_json, sizeof(tagged_json), "%s", tmp ? tmp : "[]");
        if (tmp) free(tmp);
    } else if (json_object_object_get_ex(cfg, "tagged_vlans", &tagged) && tagged) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("tagged_vlans_must_be_array"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (json_object_object_get_ex(cfg, "poe_enabled", &tagged) && tagged)
        poe_enabled = json_object_get_boolean(tagged) ? 1 : 0;
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("db_init_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_prepare(&st,
        "INSERT INTO physical_port_profile(id,name,native_vlan,tagged_vlans_json,poe_enabled,poe_mode,stp_guard,storm_control,description,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) "
        "ON CONFLICT(id) DO UPDATE SET "
        "name=excluded.name,native_vlan=excluded.native_vlan,tagged_vlans_json=excluded.tagged_vlans_json,"
        "poe_enabled=excluded.poe_enabled,poe_mode=excluded.poe_mode,stp_guard=excluded.stp_guard,"
        "storm_control=excluded.storm_control,description=excluded.description,updated_at=excluded.updated_at") != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("prepare_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name && name[0] ? name : id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, native_vlan);
    sqlite3_bind_text(st, 4, tagged_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, poe_enabled);
    sqlite3_bind_text(st, 6, poe_mode ? poe_mode : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, stp_guard ? stp_guard : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, storm_control ? storm_control : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, description ? description : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, now);
    if (nc_step_done(st) != 0) {
        sqlite3_finalize(st);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("profile_store_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    sqlite3_finalize(st);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "saved", json_object_new_boolean(1));
    json_object_object_add(data, "runtime_apply", json_object_new_boolean(0));
    json_object_object_add(data, "runtime_apply_reason", json_object_new_string("netifd_dsa_bridge_vlan_transaction_pending"));
    {
        struct json_object *get = jmx_netconfig_physical_port_profile_get(id);
        struct json_object *get_data = NULL;
        struct json_object *profile = NULL;
        if (get && json_object_object_get_ex(get, "data", &get_data) && get_data &&
            json_object_object_get_ex(get_data, "profile", &profile) && profile)
            json_object_object_add(data, "profile", json_object_get(profile));
        if (get)
            json_object_put(get);
    }
    json_object_object_add(data, "capabilities", nc_physical_port_profile_caps());
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_netconfig_physical_port_profile_delete(const char *id)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;
    int changed = 0;
    int references = 0;

    if (!id || !id[0] || !nc_valid_name(id) ||
        !strcmp(id, "default-lan") || !strcmp(id, "all")) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_or_protected_profile_id"));
        json_object_object_add(data, "protected", json_object_new_boolean(
            id && (!strcmp(id, "default-lan") || !strcmp(id, "all"))));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("db_init_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_exec("BEGIN IMMEDIATE") != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("profile_delete_transaction_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM physical_port_config WHERE profile_id=?1") != 0) {
        nc_exec("ROLLBACK");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("profile_reference_check_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        references = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (references > 0) {
        nc_exec("ROLLBACK");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("profile_in_use"));
        json_object_object_add(data, "profile_id", json_object_new_string(id));
        json_object_object_add(data, "reference_count", json_object_new_int(references));
        json_object_object_add(data, "deleted", json_object_new_int(0));
        json_object_object_add(data, "capabilities", nc_physical_port_profile_caps());
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_prepare(&st, "DELETE FROM physical_port_profile WHERE id=?1") != 0) {
        nc_exec("ROLLBACK");
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("profile_delete_prepare_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) == 0)
        changed = sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st);
    st = NULL;
    if (changed > 0) {
        if (nc_exec("COMMIT") != 0) {
            nc_exec("ROLLBACK");
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string("profile_delete_commit_failed"));
            return jmx_gen_api_response_data(API_CODE_ERROR, data);
        }
    } else {
        nc_exec("ROLLBACK");
    }
    json_object_object_add(data, "ok", json_object_new_boolean(changed > 0));
    json_object_object_add(data, "deleted", json_object_new_int(changed));
    json_object_object_add(data, "reference_count", json_object_new_int(references));
    if (changed <= 0)
        json_object_object_add(data, "error", json_object_new_string("profile_not_found"));
    json_object_object_add(data, "capabilities", nc_physical_port_profile_caps());
    return jmx_gen_api_response_data(changed > 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

static void nc_json_copy_key(struct json_object *dst, const char *dst_key,
                             struct json_object *src, const char *src_key)
{
    struct json_object *v = NULL;

    if (!dst || !dst_key || !src || !src_key)
        return;
    if (json_object_object_get_ex(src, src_key, &v) && v)
        json_object_object_add(dst, dst_key, json_object_get(v));
}

static int nc_netdev_is_virtual(const char *ifname)
{
    char path[256];
    char *resolved;
    int is_virtual;

    if (!ifname || !ifname[0])
        return 1;
    if ((size_t)snprintf(path, sizeof(path), "/sys/class/net/%s",
                         ifname) >= sizeof(path))
        return 1;
    resolved = realpath(path, NULL);
    if (!resolved)
        return 1;
    is_virtual = strstr(resolved, "/devices/virtual/net/") != NULL;
    free(resolved);
    return is_virtual;
}

/*
 * nc_netdev_is_dsa_conduit - detect DSA CPU/conduit ports by sysfs topology.
 *
 * A DSA conduit/master port (e.g. cpu0 on MediaTek MT7988, Airoha AN7581)
 * carries a /sys/class/net/<name>/dsa directory with a tagging file that
 * identifies the switch fabric protocol.  User ports (the actual physical
 * switch ports like eth2-eth5) do not have this directory.  Bridges are
 * already excluded by the br- prefix filter above.
 *
 * This is topology-based (sysfs /dsa marker), not name-based: it works
 * across different SoC families regardless of the conduit's interface name.
 */
static int nc_netdev_is_dsa_conduit(const char *ifname)
{
    char path[256];

    if (!ifname || !ifname[0])
        return 0;
    if ((size_t)snprintf(path, sizeof(path), "/sys/class/net/%s",
                         ifname) >= sizeof(path))
        return 0;
    /* Check for /sys/class/net/<name>/dsa — the sysfs DSA conduit marker.
     * access() on a directory path succeeds if it exists. */
    if (strlcat(path, "/dsa", sizeof(path)) >= sizeof(path))
        return 0;
    return access(path, F_OK) == 0;
}

#define NC_GATEWAY_PORT_MAX 64

struct nc_gateway_wan_assignment {
    char id[64];
    char old_device[IFNAMSIZ];
    char new_device[IFNAMSIZ];
    int enabled;
};

struct nc_gateway_lan_return {
    char ifname[IFNAMSIZ];
    char lan_id[64];
};

struct nc_gateway_port_plan {
    struct nc_gateway_wan_assignment wans[NC_GATEWAY_PORT_MAX];
    struct nc_gateway_lan_return returns[NC_GATEWAY_PORT_MAX];
    int wan_count;
    int return_count;
    int change_count;
    char management_lan[64];
};

static struct json_object *nc_gateway_port_capabilities(void)
{
    struct json_object *cap = json_object_new_object();
    json_object_object_add(cap, "gateway_port_assignment_read", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_preview", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_atomic_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_requires_confirm", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_rollback", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_wan6_sync", json_object_new_boolean(1));
    json_object_object_add(cap, "gateway_port_assignment_max_ports", json_object_new_int(NC_GATEWAY_PORT_MAX));
    json_object_object_add(cap, "preview_endpoint", json_object_new_string("/api/v1/network/gateway-ports/preview"));
    json_object_object_add(cap, "apply_endpoint", json_object_new_string("/api/v1/network/gateway-ports/apply"));
    return cap;
}

static int nc_gateway_port_exists(const char *ifname)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (!nc_iface_name_ok(ifname) ||
        nc_prepare(&st, "SELECT 1 FROM physical_port WHERE name=?1 LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int nc_gateway_wan_exists(const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (!nc_uci_section_name_ok(wan_id) ||
        nc_prepare(&st, "SELECT 1 FROM wan WHERE id=?1 LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int nc_gateway_lan_exists(const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (!nc_uci_section_name_ok(lan_id) ||
        nc_prepare(&st, "SELECT 1 FROM lan WHERE id=?1 AND enabled=1 AND mode='bridge' LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int nc_gateway_plan_device_assigned(const struct nc_gateway_port_plan *plan,
                                           const char *ifname)
{
    int i;
    if (!plan || !ifname || !ifname[0]) return 0;
    for (i = 0; i < plan->wan_count; i++)
        if (plan->wans[i].new_device[0] && !strcmp(plan->wans[i].new_device, ifname))
            return 1;
    return 0;
}

static const char *nc_gateway_migration_lan(struct json_object *migrations,
                                            const char *ifname)
{
    int i, n;
    if (!migrations || !json_object_is_type(migrations, json_type_array) || !ifname)
        return "";
    n = (int)json_object_array_length(migrations);
    for (i = 0; i < n; i++) {
        struct json_object *m = json_object_array_get_idx(migrations, i);
        const char *m_ifname = nc_json_str_def(m, "ifname", "");
        const char *owner_type = nc_json_str_def(m, "target_owner_type", "");
        if (!strcmp(m_ifname, ifname) && !strcmp(owner_type, "lan"))
            return nc_json_str_def(m, "target_owner_id", "");
    }
    return "";
}

static int nc_gateway_lan_remaining_ports(const struct nc_gateway_port_plan *plan,
                                          const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    int count = 0, i;
    if (!plan || !lan_id || !lan_id[0]) return 0;
    if (nc_prepare(&st, "SELECT port FROM lan_port WHERE lan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *port = nc_sql_text(st, 0);
            if (!nc_gateway_plan_device_assigned(plan, port)) count++;
        }
        sqlite3_finalize(st);
    }
    for (i = 0; i < plan->return_count; i++)
        if (!strcmp(plan->returns[i].lan_id, lan_id) &&
            !nc_gateway_plan_device_assigned(plan, plan->returns[i].ifname))
            count++;
    return count;
}

static void nc_gateway_plan_add_change(struct json_object *changes,
                                       const char *ifname, const char *from_type,
                                       const char *from_id, const char *to_type,
                                       const char *to_id)
{
    struct json_object *change = json_object_new_object();
    json_object_object_add(change, "ifname", json_object_new_string(ifname ? ifname : ""));
    json_object_object_add(change, "from_owner_type", json_object_new_string(from_type ? from_type : ""));
    json_object_object_add(change, "from_owner_id", json_object_new_string(from_id ? from_id : ""));
    json_object_object_add(change, "to_owner_type", json_object_new_string(to_type ? to_type : ""));
    json_object_object_add(change, "to_owner_id", json_object_new_string(to_id ? to_id : ""));
    json_object_array_add(changes, change);
}

static int nc_gateway_port_plan_build(struct json_object *payload,
                                      struct nc_gateway_port_plan *plan,
                                      struct json_object *changes,
                                      char *error, size_t error_len)
{
    struct json_object *assignments = NULL, *migrations = NULL;
    sqlite3_stmt *st = NULL;
    int i, j;

    if (error && error_len) error[0] = '\0';
    if (!payload || !plan || !changes ||
        !json_object_object_get_ex(payload, "assignments", &assignments) ||
        !assignments || !json_object_is_type(assignments, json_type_object)) {
        if (error) snprintf(error, error_len, "assignments_object_required");
        return -1;
    }
    json_object_object_get_ex(payload, "migrations", &migrations);
    if (migrations && !json_object_is_type(migrations, json_type_array)) {
        if (error) snprintf(error, error_len, "migrations_array_required");
        return -1;
    }
    if (jmx_netconfig_db_init() != 0 || jmx_netconfig_physical_port_refresh() < 0) {
        if (error) snprintf(error, error_len, "physical_port_source_unavailable");
        return -1;
    }
    memset(plan, 0, sizeof(*plan));
    if (nc_prepare(&st, "SELECT id,device,enabled FROM wan ORDER BY id") != 0) {
        if (error) snprintf(error, error_len, "wan_query_failed");
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct nc_gateway_wan_assignment *w;
        struct json_object *assigned = NULL;
        const char *wan_id = nc_sql_text(st, 0);
        const char *old_device = nc_sql_text(st, 1);
        int enabled = sqlite3_column_int(st, 2);
        const char *new_device;
        if (plan->wan_count >= NC_GATEWAY_PORT_MAX) {
            sqlite3_finalize(st);
            if (error) snprintf(error, error_len, "too_many_wans");
            return -1;
        }
        w = &plan->wans[plan->wan_count++];
        snprintf(w->id, sizeof(w->id), "%s", wan_id);
        snprintf(w->old_device, sizeof(w->old_device), "%s", old_device);
        w->enabled = enabled;
        if (!json_object_object_get_ex(assignments, wan_id, &assigned) || !assigned ||
            json_object_is_type(assigned, json_type_null)) {
            if (enabled) {
                sqlite3_finalize(st);
                if (error) snprintf(error, error_len, "enabled_wan_requires_port:%s", wan_id);
                return -1;
            }
            snprintf(w->new_device, sizeof(w->new_device), "%s", old_device);
            continue;
        }
        new_device = json_object_get_string(assigned);
        if (!new_device || !nc_gateway_port_exists(new_device)) {
            sqlite3_finalize(st);
            if (error) snprintf(error, error_len, "unknown_physical_port:%s", new_device ? new_device : "");
            return -1;
        }
        snprintf(w->new_device, sizeof(w->new_device), "%s", new_device);
    }
    sqlite3_finalize(st);
    st = NULL;

    json_object_object_foreach(assignments, wan_id, assigned) {
        if (!nc_gateway_wan_exists(wan_id)) {
            if (error) snprintf(error, error_len, "unknown_wan:%s", wan_id);
            return -1;
        }
    }
    for (i = 0; i < plan->wan_count; i++) {
        if (!plan->wans[i].new_device[0]) continue;
        for (j = i + 1; j < plan->wan_count; j++) {
            if (plan->wans[j].new_device[0] &&
                !strcmp(plan->wans[i].new_device, plan->wans[j].new_device)) {
                if (error) snprintf(error, error_len, "physical_port_assigned_twice:%s",
                                    plan->wans[i].new_device);
                return -1;
            }
        }
    }

    if (nc_prepare(&st, "SELECT name,owner_id FROM physical_port WHERE owner_type='wan' ORDER BY name") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ifname = nc_sql_text(st, 0);
            const char *old_wan = nc_sql_text(st, 1);
            const char *lan_id;
            if (nc_gateway_plan_device_assigned(plan, ifname)) continue;
            lan_id = nc_gateway_migration_lan(migrations, ifname);
            if (!lan_id[0] || !nc_gateway_lan_exists(lan_id)) {
                sqlite3_finalize(st);
                if (error) snprintf(error, error_len,
                                    "displaced_wan_port_requires_bridge_lan:%s", ifname);
                return -1;
            }
            if (plan->return_count >= NC_GATEWAY_PORT_MAX) {
                sqlite3_finalize(st);
                if (error) snprintf(error, error_len, "too_many_lan_returns");
                return -1;
            }
            snprintf(plan->returns[plan->return_count].ifname,
                     sizeof(plan->returns[plan->return_count].ifname), "%s", ifname);
            snprintf(plan->returns[plan->return_count].lan_id,
                     sizeof(plan->returns[plan->return_count].lan_id), "%s", lan_id);
            plan->return_count++;
            nc_gateway_plan_add_change(changes, ifname, "wan", old_wan, "lan", lan_id);
            plan->change_count++;
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    for (i = 0; i < plan->wan_count; i++) {
        const char *old_owner_type = "";
        const char *old_owner_id = "";
        char owner_type[32] = "", owner_id[64] = "";
        if (!plan->wans[i].new_device[0] ||
            !strcmp(plan->wans[i].old_device, plan->wans[i].new_device))
            continue;
        if (nc_prepare(&st, "SELECT owner_type,owner_id FROM physical_port WHERE name=?1") == 0) {
            sqlite3_bind_text(st, 1, plan->wans[i].new_device, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                snprintf(owner_type, sizeof(owner_type), "%s", nc_sql_text(st, 0));
                snprintf(owner_id, sizeof(owner_id), "%s", nc_sql_text(st, 1));
            }
            sqlite3_finalize(st); st = NULL;
        }
        old_owner_type = owner_type;
        old_owner_id = owner_id;
        nc_gateway_plan_add_change(changes, plan->wans[i].new_device,
                                   old_owner_type, old_owner_id,
                                   "wan", plan->wans[i].id);
        plan->change_count++;
    }

    if (nc_prepare(&st, "SELECT id FROM lan WHERE enabled=1 AND mode='bridge' ORDER BY CASE WHEN id='lan' THEN 0 ELSE 1 END,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *lan_id = nc_sql_text(st, 0);
            if (!plan->management_lan[0])
                snprintf(plan->management_lan, sizeof(plan->management_lan), "%s", lan_id);
            if (nc_gateway_lan_remaining_ports(plan, lan_id) <= 0) {
                sqlite3_finalize(st);
                if (error) snprintf(error, error_len, "bridge_lan_would_have_no_ports:%s", lan_id);
                return -1;
            }
        }
        sqlite3_finalize(st);
    }
    if (!plan->management_lan[0]) {
        if (error) snprintf(error, error_len, "management_bridge_lan_missing");
        return -1;
    }
    return 0;
}

static struct json_object *nc_gateway_port_plan_response(struct json_object *payload,
                                                         struct nc_gateway_port_plan *plan_out)
{
    struct json_object *data = json_object_new_object();
    struct json_object *changes = json_object_new_array();
    struct nc_gateway_port_plan plan;
    char error[192] = "";
    int rc = nc_gateway_port_plan_build(payload, &plan, changes, error, sizeof(error));
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "ready", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "atomic", json_object_new_boolean(1));
    json_object_object_add(data, "partial", json_object_new_boolean(0));
    json_object_object_add(data, "requires_confirm", json_object_new_boolean(1));
    json_object_object_add(data, "change_count", json_object_new_int(rc == 0 ? plan.change_count : 0));
    json_object_object_add(data, "changes", changes);
    json_object_object_add(data, "capabilities", nc_gateway_port_capabilities());
    if (rc != 0)
        json_object_object_add(data, "error", json_object_new_string(error[0] ? error : "gateway_port_validation_failed"));
    else if (plan_out)
        *plan_out = plan;
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

struct json_object *jmx_netconfig_gateway_ports_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *assignments = json_object_new_object();
    struct json_object *wans = json_object_new_array();
    struct json_object *ports_response = NULL, *ports_data = NULL, *ports = NULL;
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_work_mode_is_side_router()) {
        struct json_object *caps = nc_gateway_port_capabilities();
        struct json_object *shared_uplink = jmx_netconfig_side_router_uplink();

        json_object_object_add(caps, "gateway_port_assignment_read", json_object_new_boolean(0));
        json_object_object_add(caps, "gateway_port_assignment_preview", json_object_new_boolean(0));
        json_object_object_add(caps, "gateway_port_assignment_atomic_apply", json_object_new_boolean(0));
        json_object_object_add(caps, "port_role_partition_applicable", json_object_new_boolean(0));
        json_object_object_add(caps, "reason", json_object_new_string("side_router_shared_l2_uplink_has_no_dedicated_wan_port"));
        ports_response = jmx_netconfig_physical_port_list();
        if (ports_response && json_object_object_get_ex(ports_response, "data", &ports_data) &&
            ports_data && json_object_object_get_ex(ports_data, "ports", &ports) && ports)
            json_object_object_add(data, "ports", json_object_get(ports));
        else
            json_object_object_add(data, "ports", json_object_new_array());
        if (ports_response) json_object_put(ports_response);
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "work_mode", json_object_new_string("side-router"));
        json_object_object_add(data, "port_role_partition_applicable", json_object_new_boolean(0));
        json_object_object_add(data, "assignments", assignments);
        json_object_object_add(data, "wans", wans);
        json_object_object_add(data, "shared_uplink", shared_uplink ? shared_uplink : json_object_new_null());
        json_object_object_add(data, "capabilities", caps);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("gateway_port_source_unavailable"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_prepare(&st, "SELECT id,name,device,enabled,role FROM wan ORDER BY id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *wan = json_object_new_object();
            const char *id = nc_sql_text(st, 0);
            const char *device = nc_sql_text(st, 2);
            json_object_object_add(wan, "id", json_object_new_string(id));
            json_object_object_add(wan, "name", json_object_new_string(nc_sql_text(st, 1)));
            json_object_object_add(wan, "device", json_object_new_string(device));
            json_object_object_add(wan, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
            json_object_object_add(wan, "role", json_object_new_string(nc_sql_text(st, 4)));
            json_object_array_add(wans, wan);
            if (device[0]) json_object_object_add(assignments, id, json_object_new_string(device));
        }
        sqlite3_finalize(st);
    }
    ports_response = jmx_netconfig_physical_port_list();
    if (ports_response && json_object_object_get_ex(ports_response, "data", &ports_data) &&
        ports_data && json_object_object_get_ex(ports_data, "ports", &ports) && ports)
        json_object_object_add(data, "ports", json_object_get(ports));
    else
        json_object_object_add(data, "ports", json_object_new_array());
    if (ports_response) json_object_put(ports_response);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "assignments", assignments);
    json_object_object_add(data, "wans", wans);
    json_object_object_add(data, "capabilities", nc_gateway_port_capabilities());
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_netconfig_gateway_ports_preview(struct json_object *payload)
{
    return nc_gateway_port_plan_response(payload, NULL);
}

static int nc_gateway_uci_section_exists(struct uci_context *ctx, const char *section)
{
    struct uci_ptr ptr = {0};
    char buf[128];
    if (!ctx || !nc_uci_section_name_ok(section)) return 0;
    snprintf(buf, sizeof(buf), "network.%s", section);
    return uci_lookup_ptr(ctx, &ptr, buf, true) == UCI_OK && ptr.s;
}

static int nc_gateway_runtime_object_exists(const char *interface_id)
{
    char cmd[320];
    if (!nc_uci_section_name_ok(interface_id)) return 0;
    snprintf(cmd, sizeof(cmd),
             "ubus -S call network.interface.%s status >/tmp/dw-gateway-port-health-%s.log 2>&1",
             interface_id, interface_id);
    return nc_run_quiet(cmd) == 0;
}

struct json_object *jmx_netconfig_gateway_ports_apply(struct json_object *payload)
{
    struct json_object *preview = NULL, *preview_data = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *rollback = json_object_new_object();
    struct nc_gateway_port_plan plan;
    struct uci_context *ctx = NULL;
    struct uci_package *netpkg = NULL;
    sqlite3_stmt *st = NULL;
    char bak_network[256] = "";
    int tx_started = 0, uci_committed = 0, runtime_applied = 0;
    int database_rollback_ok = 0, runtime_rollback_ok = 0;
    int rc = -1, i;

    if (!payload || !nc_json_bool_def(payload, "confirm", 0)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("confirmation_required"));
        json_object_object_add(data, "capabilities", nc_gateway_port_capabilities());
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    preview = nc_gateway_port_plan_response(payload, &plan);
    if (!preview || !json_object_object_get_ex(preview, "data", &preview_data) ||
        !preview_data || !nc_json_bool_def(preview_data, "ready", 0)) {
        if (preview) return preview;
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("gateway_port_validation_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    json_object_object_add(data, "change_count", json_object_new_int(plan.change_count));
    if (plan.change_count == 0) {
        struct json_object *readback = jmx_netconfig_gateway_ports_get();
        struct json_object *readback_data = NULL;
        if (readback) json_object_object_get_ex(readback, "data", &readback_data);
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "saved", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(1));
        json_object_object_add(data, "changed", json_object_new_boolean(0));
        json_object_object_add(data, "apply_state", json_object_new_string("noop"));
        json_object_object_add(data, "readback", readback_data ? json_object_get(readback_data) : json_object_new_object());
        json_object_object_add(data, "rollback", rollback);
        json_object_object_add(data, "capabilities", nc_gateway_port_capabilities());
        if (readback) json_object_put(readback);
        json_object_put(preview);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }

    if (nc_backup_config("network", bak_network, sizeof(bak_network)) != 0 ||
        nc_exec("BEGIN IMMEDIATE") != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string(
            bak_network[0] ? "gateway_port_transaction_begin_failed" : "gateway_port_snapshot_failed"));
        goto done;
    }
    tx_started = 1;
    for (i = 0; i < plan.wan_count; i++) {
        if (!plan.wans[i].new_device[0]) continue;
        if (nc_prepare(&st, "UPDATE wan SET device=?2,updated_at=?3 WHERE id=?1") != 0) goto done;
        sqlite3_bind_text(st, 1, plan.wans[i].id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, plan.wans[i].new_device, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, nc_now_s());
        if (nc_step_done(st) != 0 || sqlite3_changes(g_netconfig_db) != 1) {
            sqlite3_finalize(st); st = NULL; goto done;
        }
        sqlite3_finalize(st); st = NULL;
        if (nc_prepare(&st, "DELETE FROM lan_port WHERE port=?1") != 0) goto done;
        sqlite3_bind_text(st, 1, plan.wans[i].new_device, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto done; }
        sqlite3_finalize(st); st = NULL;
    }
    for (i = 0; i < plan.return_count; i++) {
        char row_id[160];
        int sort_order = 0;
        if (nc_prepare(&st, "DELETE FROM lan_port WHERE port=?1") != 0) goto done;
        sqlite3_bind_text(st, 1, plan.returns[i].ifname, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto done; }
        sqlite3_finalize(st); st = NULL;
        if (nc_prepare(&st, "SELECT COALESCE(MAX(sort_order),-1)+1 FROM lan_port WHERE lan_id=?1") == 0) {
            sqlite3_bind_text(st, 1, plan.returns[i].lan_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) sort_order = sqlite3_column_int(st, 0);
            sqlite3_finalize(st); st = NULL;
        }
        snprintf(row_id, sizeof(row_id), "%s_%s", plan.returns[i].lan_id, plan.returns[i].ifname);
        if (nc_prepare(&st, "INSERT INTO lan_port(id,lan_id,port,label,sort_order) VALUES(?1,?2,?3,?3,?4)") != 0) goto done;
        sqlite3_bind_text(st, 1, row_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, plan.returns[i].lan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, plan.returns[i].ifname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, sort_order);
        if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto done; }
        sqlite3_finalize(st); st = NULL;
    }

    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "network", &netpkg) != UCI_OK || !netpkg) goto done;
    for (i = 0; i < plan.wan_count; i++) {
        char wan6[72];
        if (!plan.wans[i].new_device[0] ||
            nc_uci_set_pkg(ctx, "network", plan.wans[i].id, "device", plan.wans[i].new_device) != UCI_OK)
            goto done;
        snprintf(wan6, sizeof(wan6), "%s6", plan.wans[i].id);
        if (nc_gateway_uci_section_exists(ctx, wan6) &&
            nc_uci_set_pkg(ctx, "network", wan6, "device", plan.wans[i].new_device) != UCI_OK)
            goto done;
    }
    if (nc_prepare(&st, "SELECT id,device FROM lan WHERE enabled=1 AND mode='bridge' ORDER BY id") != 0) goto done;
    while (sqlite3_step(st) == SQLITE_ROW)
        if (nc_apply_lan_ports(ctx, netpkg, nc_sql_text(st, 1), nc_sql_text(st, 0)) != 0) {
            sqlite3_finalize(st); st = NULL; goto done;
        }
    sqlite3_finalize(st); st = NULL;
    if (jmx_uci_commit(ctx, "network") != UCI_OK) goto done;
    uci_committed = 1;
    if (nc_reload_network_stack(0, 0, "/tmp/dw-gateway-port-apply.log") != 0) goto done;
    runtime_applied = 1;
    sleep(2);
    if (!nc_gateway_runtime_object_exists(plan.management_lan)) goto done;
    for (i = 0; i < plan.wan_count; i++)
        if (plan.wans[i].enabled && !nc_gateway_runtime_object_exists(plan.wans[i].id))
            goto done;
    if (nc_exec("COMMIT") != 0) goto done;
    tx_started = 0;
    rc = 0;

done:
    if (st) sqlite3_finalize(st);
    if (ctx) uci_free_context(ctx);
    if (rc != 0 && tx_started) {
        database_rollback_ok = nc_exec("ROLLBACK") == 0;
        tx_started = 0;
    }
    if (rc != 0 && bak_network[0]) {
        nc_restore_config("network", bak_network);
        runtime_rollback_ok = nc_reload_network_stack(0, 0,
            "/tmp/dw-gateway-port-rollback.log") == 0;
    }
    if (rc == 0) {
        struct json_object *readback = jmx_netconfig_gateway_ports_get();
        struct json_object *readback_data = NULL;
        if (readback) json_object_object_get_ex(readback, "data", &readback_data);
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "saved", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(1));
        json_object_object_add(data, "changed", json_object_new_boolean(1));
        json_object_object_add(data, "apply_state", json_object_new_string("applied"));
        json_object_object_add(data, "readback", readback_data ? json_object_get(readback_data) : json_object_new_object());
        json_object_object_add(rollback, "attempted", json_object_new_boolean(0));
        if (readback) json_object_put(readback);
    } else {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "saved", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "apply_state", json_object_new_string(
            database_rollback_ok && runtime_rollback_ok ? "rolled_back" : "failed"));
        json_object_object_add(data, "error", json_object_new_string("gateway_port_apply_failed"));
        json_object_object_add(data, "uci_committed", json_object_new_boolean(uci_committed));
        json_object_object_add(data, "runtime_applied", json_object_new_boolean(runtime_applied));
        json_object_object_add(rollback, "attempted", json_object_new_boolean(bak_network[0] != '\0'));
        json_object_object_add(rollback, "database", json_object_new_boolean(database_rollback_ok));
        json_object_object_add(rollback, "runtime", json_object_new_boolean(runtime_rollback_ok));
    }
    json_object_object_add(data, "rollback", rollback);
    json_object_object_add(data, "capabilities", nc_gateway_port_capabilities());
    nc_cleanup_backup(bak_network);
    if (preview) json_object_put(preview);
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

int jmx_netconfig_physical_port_refresh(void)
{
    DIR *d;
    struct dirent *de;
    sqlite3_stmt *st = NULL;
    int64_t ts = nc_now_s();
    int count = 0;
    if (jmx_netconfig_db_init() != 0) return -1;
    d = opendir("/sys/class/net");
    if (!d) return -1;
    nc_exec("DELETE FROM physical_port");
    while ((de = readdir(d)) != NULL) {
        char carrier_path[256], speed[32], owner_type[32], owner_id[64];
        const char *name = de->d_name;
        const char *kind = "ethernet";
        const char *status = "unknown";
        FILE *fp;
        char buf[32];
        if (!strcmp(name, ".") || !strcmp(name, "..") || !strcmp(name, "lo")) continue;
        if (!strncmp(name, "br-", 3) || strchr(name, '.') || !strncmp(name, "ifb", 3) || !strncmp(name, "ppp", 3) || !strncmp(name, "wg", 2) || !strncmp(name, "tun", 3)) continue;
        if (!nc_valid_name(name)) continue;
        if (nc_netdev_is_virtual(name)) continue;
        if (nc_netdev_is_dsa_conduit(name)) continue;
        if ((size_t)snprintf(carrier_path, sizeof(carrier_path),
                             "/sys/class/net/%s/carrier", name) >= sizeof(carrier_path))
            continue;
        fp = fopen(carrier_path, "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp)) status = atoi(buf) ? "up" : "down";
            fclose(fp);
        }
        nc_read_speed_label(name, speed, sizeof(speed));
        nc_physical_port_owner(name, owner_type, sizeof(owner_type), owner_id, sizeof(owner_id));

        /* duplex from /sys/class/net/<name>/duplex */
        char duplex[16] = {0};
        {
            char dpath[256];
            if ((size_t)snprintf(dpath, sizeof(dpath), "/sys/class/net/%s/duplex",
                                 name) < sizeof(dpath)) {
                fp = fopen(dpath, "r");
                if (fp) { if (fgets(duplex, sizeof(duplex), fp)) { size_t dl=strlen(duplex); while(dl>0&&(duplex[dl-1]=='\n'||duplex[dl-1]=='\r'))duplex[--dl]='\0'; } fclose(fp); }
            }
        }

        if (nc_prepare(&st,
            "INSERT INTO physical_port(name,label,kind,speed_label,duplex,owner_type,owner_id,status,updated_at) "
            "VALUES(?1,?1,?2,?3,?4,?5,?6,?7,?8) "
            "ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,speed_label=excluded.speed_label,"
            "duplex=excluded.duplex,owner_type=excluded.owner_type,owner_id=excluded.owner_id,status=excluded.status,updated_at=excluded.updated_at") == 0) {
            sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, speed, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, duplex, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 5, owner_type, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 6, owner_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 7, status, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 8, ts);
            if (nc_step_done(st) == 0) count++;
            sqlite3_finalize(st);
        }
    }
    closedir(d);
    return count;
}

struct json_object *jmx_netconfig_physical_port_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (jmx_netconfig_db_init() != 0) goto done;
    {
        int refreshed = jmx_netconfig_physical_port_refresh();
        if (refreshed < 0) {
            json_object_object_add(data, "degraded", json_object_new_boolean(1));
            json_object_object_add(data, "source_error", json_object_new_string("physical_port_refresh_failed"));
        } else {
            json_object_object_add(data, "refreshed", json_object_new_int(refreshed));
        }
    }
    if (nc_prepare(&st,
        "SELECT p.name,p.label,p.kind,p.speed_label,p.duplex,p.owner_type,p.owner_id,p.status,"
        "c.configured_speed_mbps,c.configured_duplex,c.configured_autoneg,c.profile_id,"
        "c.native_vlan,c.tagged_vlans_json,c.poe_enabled,c.poe_mode,c.updated_at,"
        "c.last_apply_at,c.last_apply_ok,c.last_apply_error,c.display_name,c.sort_order "
        "FROM physical_port p LEFT JOIN physical_port_config c ON c.ifname=p.name "
        "ORDER BY CASE WHEN c.sort_order IS NULL OR c.sort_order=0 THEN 1 ELSE 0 END,"
        "c.sort_order,p.name") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *p = json_object_new_object();
            struct json_object *runtime = NULL;
            struct json_object *config = json_object_new_object();
            int configured_poe_enabled = sqlite3_column_type(st, 14) == SQLITE_NULL ? -1 : sqlite3_column_int(st, 14);
            const char *configured_poe_mode = nc_sql_text(st, 15);
            const char *name = nc_sql_text(st, 0);
            const char *speed_label = nc_sql_text(st, 3);
            const char *duplex = nc_sql_text(st, 4);
            const char *status = nc_sql_text(st, 7);
            const char *display_name = nc_sql_text(st, 20);
            int sort_order = sqlite3_column_int(st, 21);
            nc_add_text(p, "name", st, 0);
            nc_add_text(p, "ifname", st, 0);
            nc_add_text(p, "label", st, 1);
            nc_add_text(p, "kind", st, 2);
            nc_add_text(p, "speed_label", st, 3);
            nc_add_text(p, "duplex", st, 4);
            nc_add_text(p, "owner_type", st, 5);
            nc_add_text(p, "owner_id", st, 6);
            nc_add_text(p, "status", st, 7);
            runtime = nc_physical_port_runtime_info(name, speed_label, duplex, status);
            if (runtime) {
                nc_json_copy_key(p, "speed_mbps", runtime, "speed_mbps");
                nc_json_copy_key(p, "link_speed_mbps", runtime, "link_speed_mbps");
                nc_json_copy_key(p, "speed_label", runtime, "speed_label");
                nc_json_copy_key(p, "duplex", runtime, "duplex");
                nc_json_copy_key(p, "autoneg", runtime, "autoneg");
                nc_json_copy_key(p, "supports_autoneg", runtime, "supports_autoneg");
                nc_json_copy_key(p, "advertised_autoneg", runtime, "advertised_autoneg");
                nc_json_copy_key(p, "link_detected", runtime, "link_detected");
                nc_json_copy_key(p, "port_type", runtime, "port_type");
                nc_json_copy_key(p, "stp", runtime, "stp");
                nc_json_copy_key(p, "stp_state", runtime, "stp_state");
                nc_json_copy_key(p, "stp_role", runtime, "stp_role");
                nc_json_copy_key(p, "supported_speeds", runtime, "supported_speeds");
                nc_json_copy_key(p, "supported_duplex", runtime, "supported_duplex");
                nc_json_copy_key(p, "supported_link_modes", runtime, "supported_link_modes");
                nc_json_copy_key(p, "capability_source", runtime, "capability_source");
                nc_json_copy_key(p, "degraded", runtime, "degraded");
                nc_json_copy_key(p, "reason", runtime, "reason");
                nc_json_copy_key(p, "status", runtime, "status");
                nc_json_copy_key(p, "capabilities", runtime, "capabilities");
                json_object_object_add(p, "runtime", runtime);
            }
            nc_physical_port_add_identity(p, name, display_name, sort_order,
                                          runtime ? nc_json_str_def(runtime, "port_type", "") : "");
            nc_physical_port_add_statistics(p, runtime, name);
            json_object_object_add(config, "configured_speed_mbps", json_object_new_int(sqlite3_column_int(st, 8)));
            nc_add_text(config, "configured_duplex", st, 9);
            json_object_object_add(config, "configured_autoneg", json_object_new_int(sqlite3_column_type(st, 10) == SQLITE_NULL ? -1 : sqlite3_column_int(st, 10)));
            json_object_object_add(config, "autoneg_configured",
                                   sqlite3_column_type(st, 10) == SQLITE_NULL || sqlite3_column_int(st, 10) < 0 ?
                                   json_object_new_null() : json_object_new_boolean(sqlite3_column_int(st, 10)));
            nc_add_text(config, "profile_id", st, 11);
            json_object_object_add(config, "native_vlan", json_object_new_int(sqlite3_column_int(st, 12)));
            json_object_object_add(config, "tagged_vlans", nc_json_array_from_text((const char *)sqlite3_column_text(st, 13)));
            json_object_object_add(config, "poe_enabled",
                                   sqlite3_column_type(st, 14) == SQLITE_NULL || sqlite3_column_int(st, 14) < 0 ?
                                   json_object_new_null() : json_object_new_boolean(sqlite3_column_int(st, 14)));
            nc_add_text(config, "poe_mode", st, 15);
            json_object_object_add(config, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 16)));
            json_object_object_add(config, "last_apply_at", json_object_new_int64(sqlite3_column_int64(st, 17)));
            json_object_object_add(config, "last_apply_ok", json_object_new_boolean(sqlite3_column_int(st, 18)));
            nc_add_text(config, "last_apply_error", st, 19);
            json_object_object_add(config, "display_name", json_object_new_string(display_name));
            json_object_object_add(config, "sort_order", json_object_new_int(sort_order));
            json_object_object_add(config, "saved", json_object_new_boolean(sqlite3_column_type(st, 8) != SQLITE_NULL));
            nc_physical_port_config_attach_profile(config);
            nc_json_copy_key(p, "configured_speed_mbps", config, "configured_speed_mbps");
            nc_json_copy_key(p, "configured_duplex", config, "configured_duplex");
            nc_json_copy_key(p, "configured_autoneg", config, "configured_autoneg");
            nc_json_copy_key(p, "profile_id", config, "profile_id");
            nc_json_copy_key(p, "native_vlan", config, "native_vlan");
            nc_json_copy_key(p, "tagged_vlans", config, "tagged_vlans");
            nc_json_copy_key(p, "configured_display_name", config, "display_name");
            nc_json_copy_key(p, "configured_sort_order", config, "sort_order");
            json_object_object_add(p, "config", config);
            json_object_object_add(p, "poe",
                                   nc_physical_port_poe_probe(name,
                                                              configured_poe_enabled,
                                                              configured_poe_mode));
            json_object_array_add(arr, p);
        }
        sqlite3_finalize(st);
    } else {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "source_error", json_object_new_string("physical_port_query_failed"));
    }
done:
    json_object_object_add(data, "ports", arr);
    json_object_object_add(data, "count", json_object_new_int((int)json_object_array_length(arr)));
    {
        int side_router = jmx_netconfig_work_mode_is_side_router();

        json_object_object_add(data, "work_mode",
                               json_object_new_string(side_router ? "side-router" : "gateway"));
        json_object_object_add(data, "port_role_partition_applicable",
                               json_object_new_boolean(!side_router));
        if (side_router)
            json_object_object_add(data, "port_role_partition_reason",
                                   json_object_new_string("shared_l2_uplink_uses_bridge_not_a_dedicated_physical_port"));
    }
    {
        struct json_object *caps = json_object_new_object();
        json_object_object_add(caps, "port_stp_runtime", json_object_new_boolean(1));
        json_object_object_add(caps, "port_alias_write", json_object_new_boolean(1));
        json_object_object_add(caps, "port_display_metadata", json_object_new_boolean(1));
        json_object_object_add(caps, "port_number_from_sysfs_only", json_object_new_boolean(1));
        json_object_object_add(caps, "port_local_mac", json_object_new_boolean(1));
        json_object_object_add(caps, "port_statistics_runtime", json_object_new_boolean(1));
        json_object_object_add(caps, "port_statistics_rate_unit",
                               json_object_new_string("bytes_per_second"));
        json_object_object_add(caps, "port_tx_multicast", json_object_new_boolean(0));
        json_object_object_add(caps, "port_broadcast_counters", json_object_new_boolean(0));
        json_object_object_add(caps, "port_link_up_time", json_object_new_boolean(0));
        json_object_object_add(caps, "port_anomaly_score_24h", json_object_new_boolean(0));
        json_object_object_add(caps, "port_anomaly_reason",
                               json_object_new_string("topology_event_port_identity_not_stable_enough_for_scoring"));
        json_object_object_add(caps, "port_role_partition_applicable",
                               json_object_new_boolean(!jmx_netconfig_work_mode_is_side_router()));
        json_object_object_add(data, "capabilities", caps);
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}
