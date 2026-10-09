    } else if (!strcasecmp(cfg_provider, "deepseek")) {
        if (!strncasecmp(cfg_model, "deepseek-chat", 13)) effort_supported = 0;
    } else if (!strcasecmp(cfg_provider, "qwen")) {
        if (strstr(cfg_model, "turbo")) effort_supported = 0;
    } else if (!strcasecmp(cfg_provider, "custom") && !nc_json_bool_def(data, "api_key_set", 0)) {
        effort_supported = 0;
    }
    if (!strcmp(cfg_shape, "responses")) effort_supported = 1;
    const char *req_effort = nc_json_str_def(req, "reasoning_effort", "");
    const char *effort = req_effort[0] ? req_effort : cfg_effort;
    const char *shape = cfg_shape;
    if (!effort_supported && strcmp(effort, "auto")) {
        json_object_object_add(data, "warning", json_object_new_string("reasoning_effort is not supported for the current model/provider, falling back to auto"));
        effort = "auto";
    }
    if (!strcmp(effort, "auto")) {
        json_object_object_add(data, "reasoning_effort", json_object_new_string("auto"));
        json_object_object_add(data, "reasoning_injected", json_object_new_boolean(0));
    } else if (!strcmp(shape, "responses")) {
        struct json_object *reasoning = json_object_new_object();
        json_object_object_add(reasoning, "effort", json_object_new_string(effort));
        json_object_object_add(data, "reasoning", reasoning);
        json_object_object_add(data, "reasoning_effort", json_object_new_string(effort));
        json_object_object_add(data, "reasoning_injected", json_object_new_boolean(1));
    } else {
        json_object_object_add(data, "reasoning_effort", json_object_new_string(effort));
        json_object_object_add(data, "reasoning_injected", json_object_new_boolean(1));
    }
    json_object_object_add(data, "reasoning_api_shape", json_object_new_string(shape));
    struct json_object *tools = jmx_ai_tools_get();
    struct json_object *tools_data = NULL;
    if (tools) json_object_object_get_ex(tools, "data", &tools_data);
    json_object_object_add(data, "status", json_object_new_string("ready"));
    json_object_object_add(data, "message", json_object_new_string("AI chat endpoint ready. LLM provider integration pending."));
    if (tools_data) {
        struct json_object *tl = NULL;
        json_object_object_get_ex(tools_data, "tools", &tl);
        if (tl) json_object_object_add(data, "available_tools", json_object_get(tl));
    }
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    if (tools) json_object_put(tools);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* Legacy names share the private history store, including revision checks. */
struct json_object *jmx_ai_conversations_list(const char *actor)
{
    struct json_object *r = jmx_ai_history_list(actor, 200, 0, ""), *d = NULL, *items = NULL;
    if (json_object_object_get_ex(r, "data", &d) && json_object_object_get_ex(d, "items", &items))
        json_object_object_add(d, "conversations", json_object_get(items));
    return r;
}

struct json_object *jmx_ai_conversation_get(const char *actor, const char *id)
{
    struct json_object *r = jmx_ai_history_get(actor, id), *d = NULL, *item = NULL;
    if (json_object_object_get_ex(r, "data", &d) && json_object_object_get_ex(d, "item", &item)) {
        json_object_object_foreach(item, key, val) {
            json_object_object_add(d, key, json_object_get(val));
        }
    }
    return r;
}

int jmx_ai_conversation_save(const char *actor, struct json_object *cfg)
{
    struct json_object *r = jmx_ai_history_save(actor, cfg), *d = NULL;
    int ok = json_object_object_get_ex(r, "data", &d) && nc_json_bool_def(d, "ok", 0);
    json_object_put(r);
    return ok ? 0 : -1;
}

int jmx_ai_conversation_delete(const char *actor, const char *id)
{
    return jmx_ai_history_delete(actor, id);
}

/* forward decl moved to line 3701 */
/* ── DNS: aggregate wan_dns[] with per-WAN policy ── */
static void nc_dns_add_wan_dns(struct json_object *data)
{
    struct json_object *arr = json_object_new_array();
    struct json_object *wans = jmx_netconfig_wan_list();
    if (!wans) { json_object_object_add(data, "wan_dns", arr); return; }
    struct json_object *wan_list = NULL;
    json_object_object_get_ex(wans, "wans", &wan_list);
    int n = wan_list ? json_object_array_length(wan_list) : 0;
    for (int i = 0; i < n; i++) {
        struct json_object *w = json_object_array_get_idx(wan_list, i);
        if (!w) continue;
        const char *wan_id = nc_json_str_def(w, "id", "");
        const char *ifname = nc_json_str_def(w, "ifname", "");
        const char *carrier = nc_json_str_def(w, "name", "");
        if (!wan_id[0]) continue;
        struct json_object *entry = json_object_new_object();
        json_object_object_add(entry, "wan_id", json_object_new_string(wan_id));
        json_object_object_add(entry, "ifname", json_object_new_string(ifname));
        json_object_object_add(entry, "carrier", json_object_new_string(carrier));
        json_object_object_add(entry, "enabled", json_object_new_boolean(1));
        /* Read per-WAN DNS policy */
        struct json_object *policies = jmx_wan_dns_policy_get(wan_id);
        if (policies) {
            struct json_object *pol_data = NULL;
            json_object_object_get_ex(policies, "data", &pol_data);
            if (pol_data) {
                struct json_object *items = NULL;
                json_object_object_get_ex(pol_data, "policies", &items);
                if (items && json_object_is_type(items, json_type_array)) {
                    struct json_object *p0 = NULL;
                    int j;

                    for (j = 0; j < (int)json_object_array_length(items); j++) {
                        struct json_object *candidate = json_object_array_get_idx(items, j);
                        struct json_object *domains = NULL;

                        if (!candidate || !json_object_is_type(candidate, json_type_object))
                            continue;
                        if (!json_object_object_get_ex(candidate, "domains", &domains) ||
                            !domains || !json_object_is_type(domains, json_type_array) ||
                            json_object_array_length(domains) == 0) {
                            p0 = candidate;
                            break;
                        }
                    }
                    if (p0) {
                        const char *mode = nc_json_str_def(p0, "mode", "auto");
                        struct json_object *dns_servers = NULL;

                        json_object_object_add(entry, "mode", json_object_new_string(mode));
                        json_object_object_get_ex(p0, "dns_servers", &dns_servers);
                        if (dns_servers && json_object_is_type(dns_servers, json_type_array) &&
                            json_object_array_length(dns_servers) >= 1) {
                            json_object_object_add(entry, "primary",
                                json_object_get(json_object_array_get_idx(dns_servers, 0)));
                            if (json_object_array_length(dns_servers) >= 2)
                                json_object_object_add(entry, "secondary",
                                    json_object_get(json_object_array_get_idx(dns_servers, 1)));
                        }
                    }
                }
            }
            json_object_put(policies);
        }
        json_object_object_add(entry, "remark", json_object_new_string(""));
        json_object_array_add(arr, entry);
    }
    json_object_put(wans);
    json_object_object_add(data, "wan_dns", arr);
}

/* ── UPnP mappings CRUD ── */
static void nc_upnp_db_init_mappings(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS upnp_mapping ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER DEFAULT 1,"
        "protocol TEXT DEFAULT 'tcp',"
        "external_port INTEGER DEFAULT 0,"
        "internal_ip TEXT DEFAULT '',"
        "internal_port INTEGER DEFAULT 0,"
        "client TEXT DEFAULT '',"
        "description TEXT DEFAULT '',"
        "lease INTEGER DEFAULT 0,"
        "packets INTEGER DEFAULT 0,"
        "created_at INTEGER DEFAULT 0,"
        "updated_at INTEGER DEFAULT 0"
        ")");
}

struct json_object *jmx_upnp_mappings_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) goto done;
    nc_upnp_db_init_mappings();
    nc_upnp_static_reconcile_once();
    if (nc_prepare(&st, "SELECT id,enabled,protocol,external_port,internal_ip,internal_port,client,description,lease,packets FROM upnp_mapping ORDER BY external_port") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *m = json_object_new_object();
            nc_add_text(m, "id", st, 0);
            json_object_object_add(m, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
            nc_add_text(m, "protocol", st, 2);
            json_object_object_add(m, "external_port", json_object_new_int(sqlite3_column_int(st, 3)));
            nc_add_text(m, "internal_ip", st, 4);
            json_object_object_add(m, "internal_port", json_object_new_int(sqlite3_column_int(st, 5)));
            nc_add_text(m, "client", st, 6);
            nc_add_text(m, "description", st, 7);
            json_object_object_add(m, "lease", json_object_new_int(sqlite3_column_int(st, 8)));
            json_object_object_add(m, "packets", json_object_new_int(sqlite3_column_int(st, 9)));
            json_object_object_add(m, "mapping_type", json_object_new_string("static"));
            json_object_array_add(arr, m);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(data, "mappings", arr);
    /* Real kernel state next to the DB rows: the UI must be able to tell
     * "stored" from "actually forwarding". */
    json_object_object_add(data, "dataplane", nc_upnp_static_nft_readback());
    json_object_object_add(data, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/*
 * Create or update a static mapping.
 * Return codes: 0 ok, -1 storage, -2 invalid input, -3 unsupported,
 *               -4 dataplane apply failed (DB rolled back),
 *               -5 external port conflicts with another mapping,
 *               -6 external port belongs to the management plane (lockout),
 *               -7 external port is already a local listener.
 */
int jmx_upnp_mapping_set_ex(struct json_object *cfg, char *owner, size_t owner_len)
{
    const char *id, *proto, *iip, *desc, *client;
    int eport, iport, enabled, lease;
    sqlite3_stmt *st = NULL;
    char gen_id[64];
    int rc, conflict;

    if (owner && owner_len) owner[0] = '\0';
    if (!cfg) return -2;
    if (!nc_upnp_nft_available()) return -3;

    id     = nc_json_str_def(cfg, "id", "");
    proto  = nc_json_str_def(cfg, "protocol", "tcp");
    iip    = nc_json_str_def(cfg, "internal_ip",
             nc_json_str_def(cfg, "internal_client", ""));
    desc   = nc_json_str_def(cfg, "description", nc_json_str_def(cfg, "remark", ""));
    client = nc_json_str_def(cfg, "client", "");
    eport  = nc_json_int_def(cfg, "external_port", 0);
    iport  = nc_json_int_def(cfg, "internal_port", 0);
    enabled = nc_json_bool_def(cfg, "enabled", 1);
    lease  = nc_json_int_def(cfg, "lease", 0);

    if (!nc_upnp_proto_ok(proto) || !nc_upnp_port_ok(eport) || !nc_upnp_port_ok(iport))
        return -2;
    if (!nc_upnp_private_ipv4(iip))
        return -2;
    if (strlen(desc) > 256 || strlen(client) > 128)
        return -2;
    /* Never hand a port the router itself is serving to a LAN host. */
    conflict = nc_upnp_port_conflict(eport, owner, owner_len);
    if (conflict == NC_UPNP_PORT_MGMT)
        return -6;
    if (conflict == NC_UPNP_PORT_LOCAL)
        return -7;

    if (jmx_netconfig_db_init() != 0) return -1;
    nc_upnp_db_init_mappings();

    if (!id[0]) {
        snprintf(gen_id, sizeof(gen_id), "map_%s_%d", proto, eport);
        id = gen_id;
    }
    if (!nc_valid_name(id)) return -2;

    /* (protocol, external_port) must be unique across mappings. */
    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM upnp_mapping WHERE protocol=?1 AND external_port=?2 AND id<>?3") == 0) {
        int dup = 0;
        sqlite3_bind_text(st, 1, proto, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, eport);
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) dup = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (dup > 0) return -5;
    }

    if (nc_prepare(&st,
        "INSERT INTO upnp_mapping(id,enabled,protocol,external_port,internal_ip,internal_port,"
        "client,description,lease,packets,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?10) "
        "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,protocol=excluded.protocol,"
        "external_port=excluded.external_port,internal_ip=excluded.internal_ip,"
        "internal_port=excluded.internal_port,client=excluded.client,"
        "description=excluded.description,lease=excluded.lease,updated_at=excluded.updated_at") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, enabled ? 1 : 0);
    sqlite3_bind_text(st, 3, proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, eport);
    sqlite3_bind_text(st, 5, iip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, iport);
    sqlite3_bind_text(st, 7, client, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, desc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, lease);
    sqlite3_bind_int64(st, 10, nc_now_s());
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    if (rc != 0) return -1;

    if (nc_upnp_static_nft_apply() != 0) {
        /* Do not leave a DB row claiming a mapping the kernel does not have. */
        if (nc_prepare(&st, "DELETE FROM upnp_mapping WHERE id=?1") == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
        nc_upnp_static_nft_apply();
        return -4;
    }
    return 0;
}

int jmx_upnp_mapping_set(struct json_object *cfg)
{
    return jmx_upnp_mapping_set_ex(cfg, NULL, 0);
}

/* ── Advanced Routing CRUD ── */
static void nc_routing_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS adv_static_route ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER DEFAULT 1,"
        "target TEXT DEFAULT '',"
        "via TEXT DEFAULT '',"
        "dev TEXT DEFAULT '',"
        "metric INTEGER DEFAULT 100,"
        "tbl TEXT DEFAULT 'main',"
        "remark TEXT DEFAULT '',"
        "created_at INTEGER DEFAULT 0,"
        "updated_at INTEGER DEFAULT 0"
        ")");
    nc_exec("CREATE TABLE IF NOT EXISTS adv_policy_rule ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER DEFAULT 1,"
        "src TEXT DEFAULT '',"
        "dst TEXT DEFAULT '',"
        "sport TEXT DEFAULT '',"
        "dport TEXT DEFAULT '',"
        "protocol TEXT DEFAULT '',"
        "action TEXT DEFAULT 'lookup',"
        "target TEXT DEFAULT 'main',"
        "remark TEXT DEFAULT '',"
        "created_at INTEGER DEFAULT 0,"
        "updated_at INTEGER DEFAULT 0"
        ")");
    nc_exec("CREATE TABLE IF NOT EXISTS adv_routing_table ("
        "id TEXT PRIMARY KEY,"
        "name TEXT DEFAULT '',"
        "family TEXT DEFAULT 'ipv4',"
        "priority INTEGER DEFAULT 100,"
        "created_at INTEGER DEFAULT 0,"
        "updated_at INTEGER DEFAULT 0"
        ")");
}

struct json_object *jmx_routing_static_routes_list(void)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) return arr;
    nc_routing_db_init();
    if (nc_prepare(&st, "SELECT id,enabled,target,via,dev,metric,tbl,remark FROM adv_static_route ORDER BY target") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *r = json_object_new_object();
            nc_add_text(r, "id", st, 0);
            json_object_object_add(r, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
            nc_add_text(r, "target", st, 2); nc_add_text(r, "via", st, 3); nc_add_text(r, "dev", st, 4);
            json_object_object_add(r, "metric", json_object_new_int(sqlite3_column_int(st, 5)));
            nc_add_text(r, "table", st, 6); nc_add_text(r, "remark", st, 7);
            json_object_array_add(arr, r);
        }
        sqlite3_finalize(st);
    }
    return arr;
}

int jmx_routing_static_route_set(struct json_object *cfg)
{
    if (!cfg) return -1;
    const char *id = nc_json_str_def(cfg, "id", "");
    if (!id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_routing_db_init();
    int64_t now = nc_now_s();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT INTO adv_static_route(id,enabled,target,via,dev,metric,tbl,remark,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,target=excluded.target,via=excluded.via,dev=excluded.dev,metric=excluded.metric,tbl=excluded.tbl,remark=excluded.remark,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool_def(cfg, "enabled", 1));
        sqlite3_bind_text(st, 3, nc_json_str_def(cfg, "target", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str_def(cfg, "via", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str_def(cfg, "dev", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, nc_json_int_def(cfg, "metric", 100));
        sqlite3_bind_text(st, 7, nc_json_str_def(cfg, "table", "main"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, nc_json_str_def(cfg, "remark", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 9, now);
        sqlite3_bind_int64(st, 10, now);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

int jmx_routing_static_route_delete(const char *id)
{
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_routing_db_init();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM adv_static_route WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

struct json_object *jmx_routing_policy_rules_list(void)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) return arr;
    nc_routing_db_init();
    if (nc_prepare(&st, "SELECT id,enabled,src,dst,sport,dport,protocol,action,target,remark FROM adv_policy_rule ORDER BY src") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *r = json_object_new_object();
            nc_add_text(r, "id", st, 0);
            json_object_object_add(r, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
            nc_add_text(r, "src", st, 2); nc_add_text(r, "dst", st, 3); nc_add_text(r, "sport", st, 4);
            nc_add_text(r, "dport", st, 5); nc_add_text(r, "protocol", st, 6); nc_add_text(r, "action", st, 7);
            nc_add_text(r, "target", st, 8); nc_add_text(r, "remark", st, 9);
            json_object_array_add(arr, r);
        }
        sqlite3_finalize(st);
    }
    return arr;
}

int jmx_routing_policy_rule_set(struct json_object *cfg)
{
    if (!cfg) return -1;
    const char *id = nc_json_str_def(cfg, "id", "");
    if (!id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_routing_db_init();
    int64_t now = nc_now_s();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT INTO adv_policy_rule(id,enabled,src,dst,sport,dport,protocol,action,target,remark,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,src=excluded.src,dst=excluded.dst,sport=excluded.sport,dport=excluded.dport,protocol=excluded.protocol,action=excluded.action,target=excluded.target,remark=excluded.remark,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool_def(cfg, "enabled", 1));
        sqlite3_bind_text(st, 3, nc_json_str_def(cfg, "src", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str_def(cfg, "dst", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str_def(cfg, "sport", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, nc_json_str_def(cfg, "dport", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, nc_json_str_def(cfg, "protocol", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, nc_json_str_def(cfg, "action", "lookup"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, nc_json_str_def(cfg, "target", "main"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, nc_json_str_def(cfg, "remark", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 11, now);
        sqlite3_bind_int64(st, 12, now);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

int jmx_routing_policy_rule_delete(const char *id)
{
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_routing_db_init();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM adv_policy_rule WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

struct json_object *jmx_routing_tables_list(void)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) return arr;
    nc_routing_db_init();
    if (nc_prepare(&st, "SELECT id,name,family,priority FROM adv_routing_table ORDER BY priority,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *t = json_object_new_object();
            nc_add_text(t, "id", st, 0); nc_add_text(t, "name", st, 1); nc_add_text(t, "family", st, 2);
            json_object_object_add(t, "priority", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_array_add(arr, t);
        }
        sqlite3_finalize(st);
    }
    return arr;
}

int jmx_routing_table_set(struct json_object *cfg)
