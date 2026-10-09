/* ══════════════════════════════════════════════════════════════════════
 * WAN CRUD
 * ══════════════════════════════════════════════════════════════════════ */

static const char *nc_carrier_key_normalize(const char *carrier)
{
    if (!carrier || !carrier[0] || !strcasecmp(carrier, "any") ||
        !strcasecmp(carrier, "custom") || !strcasecmp(carrier, "unknown") ||
        !strcasecmp(carrier, "wan"))
        return "";
    if (!strcasecmp(carrier, "telecom") || !strcasecmp(carrier, "ctcc"))
        return "telecom";
    if (!strcasecmp(carrier, "unicom") || !strcasecmp(carrier, "cucc"))
        return "unicom";
    if (!strcasecmp(carrier, "mobile") || !strcasecmp(carrier, "cmcc"))
        return "mobile";
    if (!strcasecmp(carrier, "edu") || !strcasecmp(carrier, "cernet"))
        return "edu";
    if (!strcasecmp(carrier, "other"))
        return "other";
    return "";
}

static const char *nc_carrier_display_name(const char *carrier)
{
    if (!strcmp(carrier, "telecom")) return "China Telecom";
    if (!strcmp(carrier, "unicom")) return "China Unicom";
    if (!strcmp(carrier, "mobile")) return "China Mobile";
    if (!strcmp(carrier, "edu")) return "CERNET";
    if (!strcmp(carrier, "other")) return "Other";
    return "Unknown";
}

static const char *nc_carrier_from_interface_name(const char *name)
{
    char lower[96];
    size_t i;

    if (!name || !name[0] || strlen(name) >= sizeof(lower))
        return "";
    for (i = 0; name[i]; i++)
        lower[i] = (char)tolower((unsigned char)name[i]);
    lower[i] = '\0';
    if (strstr(lower, "telecom") || strstr(lower, "ctcc")) return "telecom";
    if (strstr(lower, "unicom") || strstr(lower, "cucc")) return "unicom";
    if (strstr(lower, "mobile") || strstr(lower, "cmcc")) return "mobile";
    if (strstr(lower, "cernet") || strstr(lower, "edu")) return "edu";
    return "";
}

static void nc_carrier_contract_set(jmx_wan_carrier_contract_t *out,
                                    const char *carrier,
                                    const char *source,
                                    const char *evidence,
                                    const char *reason,
                                    const char *public_ip,
                                    int confidence)
{
    const char *key = nc_carrier_key_normalize(carrier);

    snprintf(out->carrier_key, sizeof(out->carrier_key), "%s",
             key[0] ? key : "unknown");
    snprintf(out->carrier_name, sizeof(out->carrier_name), "%s",
             nc_carrier_display_name(out->carrier_key));
    snprintf(out->carrier_source, sizeof(out->carrier_source), "%s",
             source ? source : "none");
    snprintf(out->carrier_evidence, sizeof(out->carrier_evidence), "%s",
             evidence ? evidence : "");
    snprintf(out->carrier_reason, sizeof(out->carrier_reason), "%s",
             reason ? reason : "carrier_not_configured");
    snprintf(out->public_ip, sizeof(out->public_ip), "%s",
             public_ip ? public_ip : "");
    out->confidence = confidence;
}

int jmx_netconfig_wan_carrier_resolve(const char *id, const char *ifname,
                                      const char *runtime_device,
                                      const char *public_ip,
                                      jmx_wan_carrier_contract_t *out)
{
    jmx_isp_entry_t isp;
    sqlite3_stmt *st = NULL;
    char configured[32] = "";
    const char *inferred;
    const char *evidence_name;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    /* A prefix match is the strongest runtime evidence. Use an already-known
     * address first, then the asynchronous per-interface ISP cache. */
    memset(&isp, 0, sizeof(isp));
    if (public_ip && public_ip[0] &&
        jmx_isp_detect_public_ip(public_ip, "ifstatus_public_ip", &isp) == 0) {
        nc_carrier_contract_set(out, isp.carrier_key,
                                "public_ip_carrier_prefix", isp.source,
                                "carrier_prefix_match", isp.public_ip,
                                isp.confidence);
        return 0;
    }
    if (runtime_device && runtime_device[0] &&
        jmx_isp_get(runtime_device, &isp) == 0 &&
        nc_carrier_key_normalize(isp.carrier_key)[0]) {
        nc_carrier_contract_set(out, isp.carrier_key,
                                "public_ip_carrier_prefix", isp.source,
                                "carrier_prefix_match", isp.public_ip,
                                isp.confidence);
        return 0;
    }
    if (ifname && ifname[0] &&
        (!runtime_device || strcmp(runtime_device, ifname)) &&
        jmx_isp_get(ifname, &isp) == 0 &&
        nc_carrier_key_normalize(isp.carrier_key)[0]) {
        nc_carrier_contract_set(out, isp.carrier_key,
                                "public_ip_carrier_prefix", isp.source,
                                "carrier_prefix_match", isp.public_ip,
                                isp.confidence);
        return 0;
    }

    if (jmx_netconfig_db_init() == 0 &&
        nc_prepare(&st,
            "SELECT carrier FROM wan WHERE id=?1 OR ifname=?2 "
            "ORDER BY CASE WHEN id=?1 THEN 0 ELSE 1 END LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, id ? id : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ifname ? ifname : "", -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *value = (const char *)sqlite3_column_text(st, 0);

            if (value)
                snprintf(configured, sizeof(configured), "%s", value);
        }
        sqlite3_finalize(st);
    }
    if (nc_carrier_key_normalize(configured)[0]) {
        nc_carrier_contract_set(out, configured, "config_db",
                                "config.db:wan.carrier",
                                "configured_carrier", public_ip, 90);
        return 0;
    }

    inferred = nc_carrier_from_interface_name(ifname);
    evidence_name = ifname;
    if (!inferred[0]) {
        inferred = nc_carrier_from_interface_name(id);
        evidence_name = id;
    }
    if (inferred[0]) {
        char evidence[96];

        snprintf(evidence, sizeof(evidence), "interface:%s",
                 evidence_name ? evidence_name : "");
        nc_carrier_contract_set(out, inferred, "interface_name", evidence,
                                "interface_name_match", public_ip, 40);
        return 0;
    }

    nc_carrier_contract_set(out, "", "none", "",
                            "carrier_not_configured", public_ip, 0);
    return 0;
}

static void nc_wan_carrier_contract_add(struct json_object *wan,
                                        const jmx_wan_carrier_contract_t *carrier)
{
    if (!wan || !carrier)
        return;
    json_object_object_add(wan, "carrier",
                           json_object_new_string(carrier->carrier_key));
    json_object_object_add(wan, "carrier_key",
                           json_object_new_string(carrier->carrier_key));
    json_object_object_add(wan, "carrier_name",
                           json_object_new_string(carrier->carrier_name));
    json_object_object_add(wan, "carrier_source",
                           json_object_new_string(carrier->carrier_source));
    json_object_object_add(wan, "carrier_evidence",
                           json_object_new_string(carrier->carrier_evidence));
    json_object_object_add(wan, "carrier_reason",
                           json_object_new_string(carrier->carrier_reason));
    json_object_object_add(wan, "carrier_confidence",
                           json_object_new_int(carrier->confidence));
    if (carrier->public_ip[0])
        json_object_object_add(wan, "public_ip",
                               json_object_new_string(carrier->public_ip));
}

static struct json_object *nc_wan_row_to_json(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    int col_count = sqlite3_column_count(st);
    const char *password_ref = NULL;
    const char *pppoe_multi_json = NULL;
    json_object_object_add(o, "id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    nc_add_text(o, "name", st, 1);
    nc_add_text(o, "note", st, 2);
    nc_add_text(o, "carrier", st, 3);
    nc_add_text(o, "ifname", st, 4);
    nc_add_text(o, "device", st, 5);
    nc_add_text(o, "port_label", st, 6);
    nc_add_text(o, "access_mode", st, 7);
    nc_add_text(o, "gateway", st, 8);
    nc_add_text(o, "dns_json", st, 9);
    /* Parsed DNS array alongside the legacy string field (no double-encode). */
    nc_add_array_text(o, "dns", st, 9);
    nc_add_text(o, "ipv6_mode", st, 10);
    nc_add_text(o, "ipv6_addr", st, 11);
    nc_add_text(o, "delegated_prefix", st, 12);
    json_object_object_add(o, "vlan_enabled", json_object_new_boolean(sqlite3_column_int(st, 13)));
    nc_add_text(o, "vlan_id", st, 14);
    json_object_object_add(o, "mtu", json_object_new_int(sqlite3_column_int(st, 15)));
    json_object_object_add(o, "metric", json_object_new_int(sqlite3_column_int(st, 16)));
    nc_add_text(o, "role", st, 17);
    json_object_object_add(o, "expected_down_mbps", json_object_new_int(sqlite3_column_int(st, 18)));
    json_object_object_add(o, "expected_up_mbps", json_object_new_int(sqlite3_column_int(st, 19)));
    json_object_object_add(o, "smart_queue", json_object_new_boolean(sqlite3_column_int(st, 20)));
    json_object_object_add(o, "upnp", json_object_new_boolean(sqlite3_column_int(st, 21)));
    json_object_object_add(o, "ddns", json_object_new_boolean(sqlite3_column_int(st, 22)));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 23)));
    if (col_count > 24)
        nc_add_text(o, "username", st, 24);
    else
        json_object_object_add(o, "username", json_object_new_string(""));
    if (col_count > 25)
        password_ref = (const char *)sqlite3_column_text(st, 25);
    json_object_object_add(o, "password_configured",
                           json_object_new_boolean(password_ref && password_ref[0]));
    json_object_object_add(o, "secret_ref_state",
                           json_object_new_string(password_ref && password_ref[0] ?
                                                  "configured" : "not_configured"));
    pppoe_multi_json = col_count > 26 ? (const char *)sqlite3_column_text(st, 26) : "{}";
    nc_add_json_object_from_text(o, "pppoe_multi", pppoe_multi_json);
    {
        struct json_object *multi = NULL;
        if (json_object_object_get_ex(o, "pppoe_multi", &multi) && multi)
            nc_redact_secret_fields(multi);
    }
    /* Multi-WAN scheduling projection. Both fields used to be absent entirely,
     * so the UI showed "--" for weight and silently fell back to metric for
     * priority - which happened to be right, but only by coincidence.
     *
     * priority is reported as an explicit number rather than left to the
     * consumer's fallback: when the stored value is 0 (unset) the effective
     * priority *is* metric, because metric is what the route table actually
     * orders on. priority_source says which of the two produced the number, so
     * the UI does not have to guess whether the user set it or inherited it.
     * The aliases mirror the names the shipped Web module already reads. */
    {
        int weight = col_count > 27 ? sqlite3_column_int(st, 27) : 100;
        int stored_priority = col_count > 28 ? sqlite3_column_int(st, 28) : 0;
        int metric = sqlite3_column_int(st, 16);
        int effective_priority = stored_priority > 0 ? stored_priority : metric;

        if (weight <= 0)
            weight = 100;
        json_object_object_add(o, "weight", json_object_new_int(weight));
        json_object_object_add(o, "load_balance_weight", json_object_new_int(weight));
        json_object_object_add(o, "priority", json_object_new_int(effective_priority));
        json_object_object_add(o, "failover_priority", json_object_new_int(effective_priority));
        json_object_object_add(o, "priority_source",
                               json_object_new_string(stored_priority > 0 ?
                                                      "wan_priority" : "wan_metric"));
        json_object_object_add(o, "weight_scale",
                               json_object_new_string("relative_share_default_100"));
    }
    {
        jmx_wan_carrier_contract_t carrier;
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *ifname = (const char *)sqlite3_column_text(st, 4);

        if (jmx_netconfig_wan_carrier_resolve(id, ifname, NULL, NULL,
                                              &carrier) == 0)
            nc_wan_carrier_contract_add(o, &carrier);
    }
    return o;
}

static void nc_wan_load_addresses(const char *wan_id, struct json_object *wan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *arr = json_object_new_array();
    if (nc_prepare(&st,
        "SELECT ip,prefix,is_primary,sort_order FROM wan_address WHERE wan_id=?1 ORDER BY sort_order") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *a = json_object_new_object();
            nc_add_text(a, "ip", st, 0);
            json_object_object_add(a, "prefix", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(a, "primary", json_object_new_boolean(sqlite3_column_int(st, 2)));
            json_object_array_add(arr, a);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(wan_obj, "addresses", arr);
}

static void nc_wan_load_advanced(const char *wan_id, struct json_object *wan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *adv = json_object_new_object();
    if (nc_prepare(&st,
        "SELECT default_route,failover,link_time,health_enabled,health_mode,health_targets_json,"
        "dhcp_hostname,dhcp_vendor_class,dhcp_client_id,"
        "pppoe_timing_restart,pppoe_restart_week,pppoe_restart_time,"
        "pppoe_ac,pppoe_ac_mac,pppoe_service,"
        "pppoe_abnormal_ip_check,pppoe_abnormal_ip_prefixes "
        "FROM wan_advanced WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(adv, "default_route", json_object_new_boolean(sqlite3_column_int(st, 0)));
            json_object_object_add(adv, "failover", json_object_new_boolean(sqlite3_column_int(st, 1)));
            nc_add_text(adv, "link_time", st, 2);
            struct json_object *hc = json_object_new_object();
            json_object_object_add(hc, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
            nc_add_text(hc, "mode", st, 4);
            json_object_object_add(hc, "targets_json", json_object_new_string(
                (const char *)sqlite3_column_text(st, 5) ? (const char *)sqlite3_column_text(st, 5) : "[]"));
            json_object_object_add(adv, "health_check", hc);
            struct json_object *dhcp_opt = json_object_new_object();
            nc_add_text(dhcp_opt, "hostname", st, 6);
            nc_add_text(dhcp_opt, "vendor_class", st, 7);
            nc_add_text(dhcp_opt, "client_id", st, 8);
            json_object_object_add(adv, "dhcp", dhcp_opt);
            struct json_object *pppoe_opt = json_object_new_object();
            json_object_object_add(pppoe_opt, "timing_restart", json_object_new_boolean(sqlite3_column_int(st, 9)));
            nc_add_text(pppoe_opt, "restart_week", st, 10);
            nc_add_text(pppoe_opt, "restart_time", st, 11);
            nc_add_text(pppoe_opt, "ac", st, 12);
            nc_add_text(pppoe_opt, "ac_mac", st, 13);
            nc_add_text(pppoe_opt, "service", st, 14);
            json_object_object_add(pppoe_opt, "abnormal_ip_check", json_object_new_boolean(sqlite3_column_int(st, 15)));
            nc_add_text(pppoe_opt, "abnormal_ip_prefixes", st, 16);
            json_object_object_add(adv, "pppoe", pppoe_opt);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(wan_obj, "advanced", adv);
}

static void nc_wan_load_bond(const char *wan_id, struct json_object *wan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *bond = json_object_new_object();
    json_object_object_add(bond, "enabled", json_object_new_boolean(0));
    if (nc_prepare(&st,
        "SELECT enabled,bond_name,mode,hash_policy,members_json FROM wan_bond WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(bond, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
            nc_add_text(bond, "bond_name", st, 1);
            nc_add_text(bond, "mode", st, 2);
            nc_add_text(bond, "hash_policy", st, 3);
            nc_add_text(bond, "members_json", st, 4);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(wan_obj, "bond", bond);
}

static void nc_wan_load_hybrid_lines(const char *wan_id, struct json_object *wan_obj)
{
    sqlite3_stmt *st = NULL;
    struct json_object *arr = json_object_new_array();
    if (!wan_id || !wan_obj) return;
    if (nc_prepare(&st,
        "SELECT id,parent_wan_id,name,comment,mode,vlan_id,mac,proto,enabled,default_route,failover,"
        "check_host,ip,prefix,gateway,username,password_ref,pppoe_ac,pppoe_ac_mac,pppoe_service,mtu,mru,upload_mbps,download_mbps "
        "FROM hybrid_line WHERE parent_wan_id=?1 ORDER BY name,id") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *line = json_object_new_object();
            nc_hybrid_row_to_json(st, line);
            json_object_array_add(arr, line);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(wan_obj, "hybrid_lines", arr);
}

struct json_object *jmx_netconfig_wan_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct json_object *shared_uplink = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *network_dump = NULL;

    shared_uplink = jmx_netconfig_side_router_uplink();
    if (shared_uplink) {
        json_object_array_add(arr, json_object_get(shared_uplink));
        json_object_object_add(data, "work_mode", json_object_new_string("side-router"));
        json_object_object_add(data, "canonical_mode", json_object_new_string("side-router"));
        json_object_object_add(data, "port_role_partition_applicable", json_object_new_boolean(0));
        json_object_object_add(data, "shared_uplink", shared_uplink);
        goto done;
    }
    json_object_object_add(data, "work_mode", json_object_new_string("gateway"));
    json_object_object_add(data, "canonical_mode", json_object_new_string("gateway"));
    json_object_object_add(data, "port_role_partition_applicable", json_object_new_boolean(1));
    if (jmx_netconfig_db_init() != 0) goto done;
    /* One immutable netifd dump serves every WAN and its optional IPv6 peer. */
    network_dump = nc_network_status_dump_json();
    if (nc_prepare(&st,
        "SELECT id,name,note,carrier,ifname,device,port_label,access_mode,"
        "gateway,dns_json,ipv6_mode,ipv6_addr,delegated_prefix,"
        "vlan_enabled,vlan_id,mtu,metric,role,"
        "expected_down_mbps,expected_up_mbps,smart_queue,upnp,ddns,enabled,"
        "username,password_ref,pppoe_multi_json,weight,priority "
        "FROM wan ORDER BY id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *wid = (const char *)sqlite3_column_text(st, 0);
            const char *wifname = (const char *)sqlite3_column_text(st, 4);
            struct json_object *w = nc_wan_row_to_json(st);
            nc_wan_load_addresses(wid, w);
            nc_wan_load_advanced(wid, w);
            nc_wan_load_bond(wid, w);
            nc_wan_load_hybrid_lines(wid, w);
            nc_wan_merge_runtime(wid, wifname, w, network_dump);
            json_object_array_add(arr, w);
        }
        sqlite3_finalize(st);
    }
done:
    if (network_dump)
        json_object_put(network_dump);
    json_object_object_add(data, "wans", arr);
    /* Attach capabilities so UI knows what features are available */
    {
        struct json_object *caps_resp = jmx_netconfig_capabilities();
        if (caps_resp) {
            struct json_object *caps_data = NULL;
            if (json_object_object_get_ex(caps_resp, "data", &caps_data) && caps_data) {
                /* shallow-ref: we'll consume it before freeing caps_resp */
                json_object_get(caps_data);
                json_object_object_add(data, "capabilities", caps_data);
            }
            json_object_put(caps_resp);
        }
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_netconfig_wan_configured(const char *id, const char *ifname)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if ((!id || !id[0]) && (!ifname || !ifname[0]))
        return 0;
    if (jmx_netconfig_db_init() != 0)
        return 0;
    if (nc_prepare(&st,
        "SELECT 1 FROM wan WHERE id=?1 OR ifname=?2 LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, id ? id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ifname ? ifname : "", -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

struct json_object *jmx_netconfig_wan_get(const char *id)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;

    if (!id || !id[0]) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (jmx_netconfig_db_init() != 0) goto done;
    if (nc_prepare(&st,
        "SELECT id,name,note,carrier,ifname,device,port_label,access_mode,"
        "gateway,dns_json,ipv6_mode,ipv6_addr,delegated_prefix,"
        "vlan_enabled,vlan_id,mtu,metric,role,"
        "expected_down_mbps,expected_up_mbps,smart_queue,upnp,ddns,enabled,"
        "username,password_ref,pppoe_multi_json,weight,priority "
        "FROM wan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *wifname = (const char *)sqlite3_column_text(st, 4);
            struct json_object *w = nc_wan_row_to_json(st);
            nc_wan_load_addresses(id, w);
            nc_wan_load_advanced(id, w);
            nc_wan_load_bond(id, w);
            nc_wan_load_hybrid_lines(id, w);
            nc_wan_merge_runtime(id, wifname, w, NULL);
            json_object_object_add(data, "wan", w);
        }
        sqlite3_finalize(st);
    }
done:
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

const char *nc_json_str(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    const char *s = json_object_get_string(v);
    return s ? s : def;
}
static int nc_json_int(struct json_object *o, const char *k, int def)
{
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int(v);
}
static int nc_json_bool(struct json_object *o, const char *k, int def)
{
    struct json_object *v;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_boolean(v);
}

static char *nc_json_to_string_dup(struct json_object *o, const char *def)
{
    const char *s = o ? json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN) : def;
    return strdup(s ? s : (def ? def : ""));
}

static char *nc_json_array_text_dup(struct json_object *value, const char *def)
{
    struct json_object *parsed = NULL;
    const char *text;
    char *out;

    if (!value)
        return strdup(def ? def : "[]");
    if (json_object_is_type(value, json_type_array))
        return nc_json_to_string_dup(value, def ? def : "[]");
    if (!json_object_is_type(value, json_type_string))
        return NULL;
    text = json_object_get_string(value);
    parsed = text && text[0] ? json_tokener_parse(text) : NULL;
    if (!parsed || !json_object_is_type(parsed, json_type_array)) {
        if (parsed) json_object_put(parsed);
        return NULL;
    }
    out = nc_json_to_string_dup(parsed, def ? def : "[]");
    json_object_put(parsed);
    return out;
}

static int nc_parse_pool(const char *pool, char *start, size_t start_len, char *end, size_t end_len)
{
    const char *dash;
    if (!start || !end) return -1;
    start[0] = end[0] = '\0';
    if (!pool || !pool[0]) return -1;
    dash = strchr(pool, '-');
    if (!dash) {
        snprintf(start, start_len, "%s", pool);
        return 0;
    }
    snprintf(start, start_len, "%.*s", (int)(dash - pool), pool);
    snprintf(end, end_len, "%s", dash + 1);
    return 0;
}

static int nc_wan_save_addresses(const char *wan_id, struct json_object *addresses)
{
    sqlite3_stmt *st = NULL;
    int i, n;
    /* delete existing */
    if (nc_prepare(&st, "DELETE FROM wan_address WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    if (!addresses) return 0;
    n = (int)json_object_array_length(addresses);
    for (i = 0; i < n; i++) {
        struct json_object *a = json_object_array_get_idx(addresses, i);
        const char *ip = nc_json_str(a, "ip", "");
        int prefix = nc_json_int(a, "prefix", 24);
        int primary = nc_json_bool(a, "primary", 0);
        char aid[64];
        if (!ip[0]) continue;
        snprintf(aid, sizeof(aid), "%s_%s_%d", wan_id, ip, prefix);
        if (nc_prepare(&st,
            "INSERT INTO wan_address(id,wan_id,ip,prefix,is_primary,sort_order) "
            "VALUES(?1,?2,?3,?4,?5,?6) "
            "ON CONFLICT(wan_id,ip,prefix) DO UPDATE SET is_primary=excluded.is_primary") == 0) {
            sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 4, prefix);
            sqlite3_bind_int(st, 5, primary);
            sqlite3_bind_int(st, 6, i);
            nc_step_done(st);
            sqlite3_finalize(st);
        }
    }
    return 0;
}

static int nc_wan_save_advanced(const char *wan_id, struct json_object *adv)
{
    sqlite3_stmt *st = NULL;
    struct json_object *hc = NULL, *dhcp = NULL, *pppoe = NULL;
    if (!adv) return 0;
    json_object_object_get_ex(adv, "health_check", &hc);
    json_object_object_get_ex(adv, "dhcp", &dhcp);
    json_object_object_get_ex(adv, "pppoe", &pppoe);

    if (nc_prepare(&st,
        "INSERT INTO wan_advanced(wan_id,default_route,failover,link_time,"
        "health_enabled,health_mode,health_targets_json,"
        "dhcp_hostname,dhcp_vendor_class,dhcp_client_id,"
        "pppoe_timing_restart,pppoe_restart_week,pppoe_restart_time,"
        "pppoe_ac,pppoe_ac_mac,pppoe_service,"
        "pppoe_abnormal_ip_check,pppoe_abnormal_ip_prefixes) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) "
        "ON CONFLICT(wan_id) DO UPDATE SET "
        "default_route=excluded.default_route,failover=excluded.failover,"
        "link_time=excluded.link_time,health_enabled=excluded.health_enabled,"
        "health_mode=excluded.health_mode,health_targets_json=excluded.health_targets_json,"
        "dhcp_hostname=excluded.dhcp_hostname,dhcp_vendor_class=excluded.dhcp_vendor_class,"
        "dhcp_client_id=excluded.dhcp_client_id,pppoe_timing_restart=excluded.pppoe_timing_restart,"
        "pppoe_restart_week=excluded.pppoe_restart_week,pppoe_restart_time=excluded.pppoe_restart_time,"
        "pppoe_ac=excluded.pppoe_ac,pppoe_ac_mac=excluded.pppoe_ac_mac,pppoe_service=excluded.pppoe_service,"
        "pppoe_abnormal_ip_check=excluded.pppoe_abnormal_ip_check,"
        "pppoe_abnormal_ip_prefixes=excluded.pppoe_abnormal_ip_prefixes") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool(adv, "default_route", 0));
        sqlite3_bind_int(st, 3, nc_json_bool(adv, "failover", 1));
        sqlite3_bind_text(st, 4, nc_json_str(adv, "link_time", "00:00-23:59"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, hc ? nc_json_bool(hc, "enabled", 1) : 1);
        sqlite3_bind_text(st, 6, hc ? nc_json_str(hc, "mode", "ping") : "ping", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, hc ? nc_json_str(hc, "targets_json", "[]") : "[]", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, dhcp ? nc_json_str(dhcp, "hostname", "") : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, dhcp ? nc_json_str(dhcp, "vendor_class", "") : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, dhcp ? nc_json_str(dhcp, "client_id", "") : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 11, pppoe ? nc_json_bool(pppoe, "timing_restart", 0) : 0);
        sqlite3_bind_text(st, 12, pppoe ? nc_json_str(pppoe, "restart_week", "1234567") : "1234567", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, pppoe ? nc_json_str(pppoe, "restart_time", "04:00") : "04:00", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, pppoe ? nc_json_str(pppoe, "ac", nc_json_str(pppoe, "pppoe_ac", "")) : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, pppoe ? nc_json_str(pppoe, "ac_mac", nc_json_str(pppoe, "pppoe_ac_mac", "")) : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 16, pppoe ? nc_json_str(pppoe, "service", nc_json_str(pppoe, "pppoe_service", "")) : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 17, pppoe ? nc_json_bool(pppoe, "abnormal_ip_check", 0) : 0);
        sqlite3_bind_text(st, 18, pppoe ? nc_json_str(pppoe, "abnormal_ip_prefixes", "10,172,192.168") : "10,172,192.168", -1, SQLITE_TRANSIENT);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    return 0;
}

static int nc_wan_save_bond(const char *wan_id, struct json_object *bond)
{
    sqlite3_stmt *st = NULL;
    if (!bond) return 0;
    if (nc_prepare(&st,
        "INSERT INTO wan_bond(wan_id,enabled,bond_name,mode,hash_policy,members_json) "
        "VALUES(?1,?2,?3,?4,?5,?6) "
        "ON CONFLICT(wan_id) DO UPDATE SET "
        "enabled=excluded.enabled,bond_name=excluded.bond_name,mode=excluded.mode,"
        "hash_policy=excluded.hash_policy,members_json=excluded.members_json") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool(bond, "enabled", 0));
        sqlite3_bind_text(st, 3, nc_json_str(bond, "bond_name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str(bond, "mode", "802.3ad"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str(bond, "hash_policy", "layer3+4"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, nc_json_str(bond, "members_json", "[]"), -1, SQLITE_TRANSIENT);
        nc_step_done(st);
        sqlite3_finalize(st);
    }
    return 0;
}
/* ══════════════════════════════════════════════════════════════════════
 * Field-level validation: returns JSON array of errors, or NULL if valid.
 * Caller must json_object_put() the returned array.
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_add_field_error(struct json_object *errors,
                               const char *field, const char *reason, const char *msg)
{
    struct json_object *e = json_object_new_object();
    json_object_object_add(e, "field", json_object_new_string(field));
    json_object_object_add(e, "reason", json_object_new_string(reason));
    json_object_object_add(e, "message", json_object_new_string(msg));
    json_object_array_add(errors, e);
}

static int nc_is_valid_ip(const char *ip)
{
    struct in_addr addr;
    return ip && ip[0] && inet_pton(AF_INET, ip, &addr) == 1;
}

static int nc_ip_in_subnet(const char *ip, const char *subnet_cidr)
{
    /* subnet_cidr = "192.168.1.0/24" */
    if (!ip || !subnet_cidr) return 1; /* no check if missing */
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", subnet_cidr);
    char *slash = strchr(tmp, '/');
    if (!slash) return 1;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    struct in_addr net_addr, ip_addr;
    if (inet_pton(AF_INET, tmp, &net_addr) != 1) return 1;
    if (inet_pton(AF_INET, ip, &ip_addr) != 1) return 1;
    uint32_t mask = prefix == 0 ? 0 : htonl(~((1U << (32 - prefix)) - 1));
    return (ntohl(net_addr.s_addr) & ntohl(mask)) == (ntohl(ip_addr.s_addr) & ntohl(mask));
}

/* The carrier vocabulary the data plane actually understands. carrier_id
 * matches enum jmx_carrier_id, which is what the kernel module matches rules
 * against, so a UI picker built from this list cannot produce a value routed
 * will later reject. logo_key is a stable slug for artwork.
 *
 * One table, two consumers: the published enumeration and the validator. They
 * used to disagree by omission -- carrier was published as a capability but
 * never checked -- which is how a typo reached the save path and came back as
 * a bare invalid_request. */
static const struct nc_carrier_def {
    const char *id;
    int carrier_id;
    const char *label;
    const char *logo_key;
} nc_carrier_defs[] = {
    { "any",     JMX_CARRIER_ANY,     "不限",       "generic" },
    { "telecom", JMX_CARRIER_TELECOM, "中国电信",   "ctcc"    },
    { "unicom",  JMX_CARRIER_UNICOM,  "中国联通",   "cucc"    },
    { "mobile",  JMX_CARRIER_MOBILE,  "中国移动",   "cmcc"    },
    { "edu",     JMX_CARRIER_EDU,     "中国教育网", "cernet"  },
    { "other",   JMX_CARRIER_OTHER,   "其他",       "generic" },
};

/* Accepts the canonical ids above plus the aliases routed's
 * carrier_from_string() already understands, so a value that works in a policy
 * rule is not rejected here. */
static int nc_carrier_id_known(const char *carrier)
{
    static const char *const aliases[] = {
        "ctcc", "cucc", "cmcc", "cernet", NULL
    };
    size_t i;

    if (!carrier || !carrier[0])
        return 1;
    for (i = 0; i < sizeof(nc_carrier_defs) / sizeof(nc_carrier_defs[0]); i++)
        if (!strcasecmp(carrier, nc_carrier_defs[i].id))
            return 1;
    for (i = 0; aliases[i]; i++)
        if (!strcasecmp(carrier, aliases[i]))
            return 1;
    return 0;
}

struct json_object *jmx_netconfig_carrier_values(void)
{
    struct json_object *arr = json_object_new_array();
    size_t i;

    for (i = 0; i < sizeof(nc_carrier_defs) / sizeof(nc_carrier_defs[0]); i++) {
        struct json_object *o = json_object_new_object();

        json_object_object_add(o, "id", json_object_new_string(nc_carrier_defs[i].id));
        json_object_object_add(o, "carrier_id", json_object_new_int(nc_carrier_defs[i].carrier_id));
        json_object_object_add(o, "label", json_object_new_string(nc_carrier_defs[i].label));
        json_object_object_add(o, "logo_key", json_object_new_string(nc_carrier_defs[i].logo_key));
        json_object_array_add(arr, o);
    }
    return arr;
}

struct json_object *jmx_netconfig_wan_validate(struct json_object *wan_json)
{
    struct json_object *errors = json_object_new_array();
    const char *id = nc_json_str(wan_json, "id", "");
    const char *device = nc_json_str(wan_json, "device", "");
    const char *access_mode = nc_json_str(wan_json, "access_mode", "dhcp");
    const char *gateway = nc_json_str(wan_json, "gateway", "");
    int mtu = nc_json_int(wan_json, "mtu", 1500);
    int metric = nc_json_int(wan_json, "metric", 10);
    int vlan_id = 0;
    struct json_object *bond = NULL;
    struct json_object *pppoe_multi = NULL;
    struct json_object *hybrid_lines = NULL;
    struct json_object *advanced = NULL;

    if (!id[0]) nc_add_field_error(errors, "wan.id", "missing", "WAN id is required");
    else if (!nc_uci_section_name_ok(id))
        nc_add_field_error(errors, "wan.id", "invalid_uci_section",
            "WAN id must contain only letters, digits, or underscore");
    if (!device[0]) nc_add_field_error(errors, "wan.device", "missing", "WAN device is required");

    if (strcmp(access_mode, "dhcp") && strcmp(access_mode, "static") &&
        strcmp(access_mode, "pppoe") && strcmp(access_mode, "bridge")) {
        nc_add_field_error(errors, "wan.access_mode", "invalid",
            "access_mode must be dhcp, static, pppoe, or bridge");
    }

    if (gateway[0] && !nc_is_valid_ip(gateway))
        nc_add_field_error(errors, "wan.gateway", "invalid_ip", "gateway must be a valid IPv4 address");

    /* carrier had no validation at all, so anything typed into the form was
     * accepted here and then failed later with a flat invalid_request that
     * named no field. Check it against the published vocabulary instead, and
     * say which value was rejected. */
    {
        struct json_object *carrier_val = NULL;

        if (json_object_object_get_ex(wan_json, "carrier", &carrier_val)) {
            if (!carrier_val) {
                nc_add_field_error(errors, "wan.carrier", "null_not_allowed",
                    "carrier must be a string or omitted, not null");
            } else if (json_object_is_type(carrier_val, json_type_string)) {
                const char *carrier = json_object_get_string(carrier_val);

                if (carrier && carrier[0] && !nc_carrier_id_known(carrier))
                    nc_add_field_error(errors, "wan.carrier", "unknown_carrier",
                        "carrier must be one of any, telecom, unicom, mobile, edu, other "
                        "(see GET /api/v1/network/carriers)");
            } else {
                nc_add_field_error(errors, "wan.carrier", "invalid_type",
                    "carrier must be a string");
            }
        }
    }

    if (mtu < 576 || mtu > 9000)
        nc_add_field_error(errors, "wan.mtu", "out_of_range", "mtu must be between 576 and 9000");

    if (metric < 0 || metric > 65535)
        nc_add_field_error(errors, "wan.metric", "out_of_range", "metric must be between 0 and 65535");

    if (json_object_object_get_ex(wan_json, "advanced", &advanced) && advanced) {
        struct json_object *hc = NULL;

        if (json_object_object_get_ex(advanced, "health_check", &hc) && hc) {
            static const char * const modes[] = {
                "http_gateway", "ping_gateway", "http_ping_gateway",
                "http", "ping", "http_ping", NULL
            };
            const char *mode = nc_json_str(hc, "mode", "http_ping_gateway");
            const char *targets_text = nc_json_str(hc, "targets_json", "{}");
            struct json_object *targets = json_tokener_parse(targets_text);
            int known = 0, i;

            for (i = 0; modes[i]; i++)
                if (!strcmp(mode, modes[i])) { known = 1; break; }
            if (!known)
                nc_add_field_error(errors, "wan.advanced.health_check.mode",
                    "invalid", "unsupported WAN health detection mode");
            if (!targets || (!json_object_is_type(targets, json_type_object) &&
                             !json_object_is_type(targets, json_type_array)))
                nc_add_field_error(errors, "wan.advanced.health_check.targets_json",
                    "invalid_json", "health targets must be a JSON object");
            if (targets) json_object_put(targets);
        }
    }

    if (json_object_object_get_ex(wan_json, "bond", &bond) && bond &&
        nc_json_bool(bond, "enabled", 0)) {
        nc_add_field_error(errors, "wan.bond", "unsupported_write",
            "WAN bonding standalone write is not enabled on this backend");
    }
    if (json_object_object_get_ex(wan_json, "pppoe_multi", &pppoe_multi) &&
        pppoe_multi && nc_json_bool(pppoe_multi, "enabled", 0)) {
        nc_add_field_error(errors, "wan.pppoe_multi", "unsupported_write",
            "PPPoE multi standalone write is not enabled on this backend");
    }
    if (json_object_object_get_ex(wan_json, "hybrid_lines", &hybrid_lines) &&
        hybrid_lines && json_object_is_type(hybrid_lines, json_type_array) &&
        json_object_array_length(hybrid_lines) > 0) {
        nc_add_field_error(errors, "wan.hybrid_lines", "unsupported_write",
            "hybrid WAN standalone write is not enabled on this backend");
    }

    struct json_object *vlan_obj = json_object_object_get(wan_json, "vlan_id");
    if (vlan_obj) {
        const char *vs = json_object_get_string(vlan_obj);
        if (vs && vs[0]) {
            vlan_id = atoi(vs);
            if (vlan_id < 1 || vlan_id > 4094)
                nc_add_field_error(errors, "wan.vlan_id", "out_of_range", "vlan_id must be 1-4094");
        }
    }

    /* DNS validation */
    struct json_object *dns_arr = NULL;
    if (json_object_object_get_ex(wan_json, "dns_json", &dns_arr) && json_object_is_type(dns_arr, json_type_array)) {
        int i, n = (int)json_object_array_length(dns_arr);
        for (i = 0; i < n; i++) {
            const char *d = json_object_get_string(json_object_array_get_idx(dns_arr, i));
            if (d && d[0] && !nc_is_valid_ip(d)) {
                char field[64];
                snprintf(field, sizeof(field), "wan.dns[%d]", i);
                nc_add_field_error(errors, field, "invalid_ip", "DNS server must be a valid IPv4 address");
            }
        }
    }

    if (json_object_array_length(errors) == 0) {
        json_object_put(errors);
        return NULL; /* valid */
    }
    return errors;
}

struct json_object *jmx_netconfig_lan_validate(struct json_object *lan_json)
{
    struct json_object *errors = json_object_new_array();
    const char *id = nc_json_str(lan_json, "id", "");
    const char *device = nc_json_str(lan_json, "device", "");
    const char *mode = nc_json_str(lan_json, "mode", "bridge");

    if (!id[0]) nc_add_field_error(errors, "lan.id", "missing", "LAN id is required");
    else if (!nc_uci_section_name_ok(id))
        nc_add_field_error(errors, "lan.id", "invalid_uci_section",
            "LAN id must contain only letters, digits, or underscore");
    if (!device[0]) nc_add_field_error(errors, "lan.device", "missing", "LAN device is required");

    if (strcmp(mode, "bridge") && strcmp(mode, "access") && strcmp(mode, "trunk")) {
        nc_add_field_error(errors, "lan.mode", "invalid",
            "mode must be bridge, access, or trunk");
    }

    /* Validate addresses */
    struct json_object *addrs = NULL;
    if (json_object_object_get_ex(lan_json, "addresses", &addrs) && json_object_is_type(addrs, json_type_array)) {
        int i, n = (int)json_object_array_length(addrs);
        int primary_count = 0;
        for (i = 0; i < n; i++) {
            struct json_object *a = json_object_array_get_idx(addrs, i);
            const char *ip = nc_json_str(a, "ip", "");
            int prefix = nc_json_int(a, "prefix", 0);
            char field[64];

            if (!ip[0]) {
                snprintf(field, sizeof(field), "lan.addresses[%d].ip", i);
                nc_add_field_error(errors, field, "missing", "IP address is required");
            } else if (!nc_is_valid_ip(ip)) {
                snprintf(field, sizeof(field), "lan.addresses[%d].ip", i);
                nc_add_field_error(errors, field, "invalid_ip", "Must be a valid IPv4 address");
            }

            if (prefix < 1 || prefix > 30) {
                snprintf(field, sizeof(field), "lan.addresses[%d].prefix", i);
                nc_add_field_error(errors, field, "out_of_range", "Prefix must be 1-30");
            }

            if (nc_json_bool(a, "primary",
                             nc_json_bool(a, "is_primary", 0)))
                primary_count++;
        }
        if (n > 0 && primary_count == 0)
            nc_add_field_error(errors, "lan.addresses", "no_primary", "At least one address must be marked as primary");
        if (primary_count > 1)
            nc_add_field_error(errors, "lan.addresses", "multiple_primary", "Only one address can be primary");
    }

    /* Validate DHCP pool */
    struct json_object *dhcp = NULL;
    if (json_object_object_get_ex(lan_json, "dhcp", &dhcp) && dhcp) {
        const char *pool_start = nc_json_str(dhcp, "pool_start", "");
        const char *pool_end = nc_json_str(dhcp, "pool_end", "");
        if (pool_start[0] && !nc_is_valid_ip(pool_start))
            nc_add_field_error(errors, "lan.dhcp.pool_start", "invalid_ip", "Must be a valid IPv4 address");
        if (pool_end[0] && !nc_is_valid_ip(pool_end))
            nc_add_field_error(errors, "lan.dhcp.pool_end", "invalid_ip", "Must be a valid IPv4 address");
        /* Check pool range */
        if (pool_start[0] && pool_end[0] && nc_is_valid_ip(pool_start) && nc_is_valid_ip(pool_end)) {
            struct in_addr sa, ea;
            inet_pton(AF_INET, pool_start, &sa);
            inet_pton(AF_INET, pool_end, &ea);
            if (ntohl(sa.s_addr) > ntohl(ea.s_addr))
                nc_add_field_error(errors, "lan.dhcp.pool", "invalid_range",
                    "pool_start must be less than or equal to pool_end");
        }
        /* Check pool is within subnet */
        if (pool_start[0] && nc_is_valid_ip(pool_start) && addrs && json_object_array_length(addrs) > 0) {
            struct json_object *pri = json_object_array_get_idx(addrs, 0);
            const char *gw = nc_json_str(pri, "ip", "");
            int pfx = nc_json_int(pri, "prefix", 24);
            if (gw[0] && pfx > 0) {
                char subnet[64];
                struct in_addr gwa;
                inet_pton(AF_INET, gw, &gwa);
                uint32_t mask = htonl(~((1U << (32 - pfx)) - 1));
                uint32_t net = ntohl(gwa.s_addr) & ntohl(mask);
                struct in_addr net_addr;
                net_addr.s_addr = htonl(net);
                snprintf(subnet, sizeof(subnet), "%s/%d", inet_ntoa(net_addr), pfx);
                if (!nc_ip_in_subnet(pool_start, subnet))
                    nc_add_field_error(errors, "lan.dhcp.pool_start", "outside_subnet",
                        "DHCP pool start is outside the LAN subnet");
                if (!nc_ip_in_subnet(pool_end, subnet))
                    nc_add_field_error(errors, "lan.dhcp.pool_end", "outside_subnet",
                        "DHCP pool end is outside the LAN subnet");
            }
        }
    }

    if (json_object_array_length(errors) == 0) {
        json_object_put(errors);
        return NULL; /* valid */
    }
    return errors;
}

int jmx_netconfig_wan_set(struct json_object *wan_json)
{
    sqlite3_stmt *st = NULL;
    const char *id, *ifname, *device, *access_mode;
    struct json_object *addresses = NULL, *advanced = NULL, *bond = NULL;
    struct json_object *pppoe_multi = NULL, *hybrid_lines = NULL;
    char *pppoe_multi_json = NULL;
    char *stored_password = NULL;
    char *stored_pppoe_multi_json = NULL;
    int stored_weight = 100;
    int stored_priority = 0;
    const char *requested_password = NULL;
    int clear_password = 0;
    int64_t ts = nc_now_s();
    int rc = -1;

    if (!wan_json) return -1;
    id = nc_json_str(wan_json, "id", "");
    ifname = nc_json_str(wan_json, "ifname", id);
    device = nc_json_str(wan_json, "device", "");
    access_mode = nc_json_str(wan_json, "access_mode", "dhcp");
    if (!nc_uci_section_name_ok(id) || !device[0]) return -1;

    if (jmx_netconfig_db_init() != 0) return -1;

    if (nc_prepare(&st,
        "SELECT password_ref,pppoe_multi_json,weight,priority FROM wan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *old_password = (const char *)sqlite3_column_text(st, 0);
            const char *old_multi = (const char *)sqlite3_column_text(st, 1);
            stored_password = strdup(old_password ? old_password : "");
            stored_pppoe_multi_json = strdup(old_multi ? old_multi : "{}");
            if (sqlite3_column_type(st, 2) != SQLITE_NULL)
                stored_weight = sqlite3_column_int(st, 2);
            if (sqlite3_column_type(st, 3) != SQLITE_NULL)
                stored_priority = sqlite3_column_int(st, 3);
            if (stored_weight <= 0)
                stored_weight = 100;
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    json_object_object_get_ex(wan_json, "addresses", &addresses);
    json_object_object_get_ex(wan_json, "advanced", &advanced);
    json_object_object_get_ex(wan_json, "bond", &bond);
    json_object_object_get_ex(wan_json, "pppoe_multi", &pppoe_multi);
    json_object_object_get_ex(wan_json, "hybrid_lines", &hybrid_lines);
    pppoe_multi_json = pppoe_multi ? nc_json_to_string_dup(pppoe_multi, "{}") :
        strdup(stored_pppoe_multi_json ? stored_pppoe_multi_json : "{}");
    clear_password = nc_json_bool(wan_json, "clear_password", 0);
    requested_password = nc_json_str(wan_json, "password", "");
    if (!requested_password[0])
        requested_password = nc_json_str(wan_json, "password_ref", "");
    if (!requested_password[0] && !clear_password)
        requested_password = stored_password ? stored_password : "";

    if (nc_prepare(&st,
        "INSERT INTO wan(id,name,note,carrier,ifname,device,port_label,access_mode,"
        "gateway,dns_json,ipv6_mode,ipv6_addr,delegated_prefix,"
        "vlan_enabled,vlan_id,mtu,metric,role,"
        "expected_down_mbps,expected_up_mbps,smart_queue,upnp,ddns,enabled,"
        "username,password_ref,pppoe_multi_json,weight,priority,"
        "created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?29,?30,?28,?28) "
        "ON CONFLICT(id) DO UPDATE SET "
        "name=excluded.name,note=excluded.note,carrier=excluded.carrier,"
        "ifname=excluded.ifname,device=excluded.device,port_label=excluded.port_label,"
        "access_mode=excluded.access_mode,gateway=excluded.gateway,"
        "dns_json=excluded.dns_json,ipv6_mode=excluded.ipv6_mode,"
        "ipv6_addr=excluded.ipv6_addr,delegated_prefix=excluded.delegated_prefix,"
        "vlan_enabled=excluded.vlan_enabled,vlan_id=excluded.vlan_id,"
        "mtu=excluded.mtu,metric=excluded.metric,role=excluded.role,"
        "expected_down_mbps=excluded.expected_down_mbps,"
        "expected_up_mbps=excluded.expected_up_mbps,"
        "smart_queue=excluded.smart_queue,upnp=excluded.upnp,"
        "ddns=excluded.ddns,enabled=excluded.enabled,"
        "username=excluded.username,password_ref=excluded.password_ref,"
        "pppoe_multi_json=excluded.pppoe_multi_json,"
        "weight=excluded.weight,priority=excluded.priority,"
        "updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, nc_json_str(wan_json, "name", id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, nc_json_str(wan_json, "note", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str(wan_json, "carrier", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, ifname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, device, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, nc_json_str(wan_json, "port_label", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, access_mode, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, nc_json_str(wan_json, "gateway", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, nc_json_str(wan_json, "dns_json", "[]"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, nc_json_str(wan_json, "ipv6_mode", "disabled"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, nc_json_str(wan_json, "ipv6_addr", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, nc_json_str(wan_json, "delegated_prefix", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 14, nc_json_bool(wan_json, "vlan_enabled", 0));
        sqlite3_bind_text(st, 15, nc_json_str(wan_json, "vlan_id", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 16, nc_json_int(wan_json, "mtu", 1500));
        sqlite3_bind_int(st, 17, nc_json_int(wan_json, "metric", 10));
        sqlite3_bind_text(st, 18, nc_json_str(wan_json, "role", "primary"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 19, nc_json_int(wan_json, "expected_down_mbps", 0));
        sqlite3_bind_int(st, 20, nc_json_int(wan_json, "expected_up_mbps", 0));
        sqlite3_bind_int(st, 21, nc_json_bool(wan_json, "smart_queue", 0));
        sqlite3_bind_int(st, 22, nc_json_bool(wan_json, "upnp", 0));
        sqlite3_bind_int(st, 23, nc_json_bool(wan_json, "ddns", 0));
        sqlite3_bind_int(st, 24, nc_json_bool(wan_json, "enabled", 1));
        sqlite3_bind_text(st, 25, nc_json_str(wan_json, "username", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 26, clear_password ? "" : requested_password,
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 27, pppoe_multi_json ? pppoe_multi_json : "{}", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 28, ts);
        /* Keep the stored value when the caller does not mention the field, so
         * a partial WAN write from a page with no weight/priority control does
         * not silently reset the schedule. */
        sqlite3_bind_int(st, 29, nc_json_int(wan_json, "weight",
                                             nc_json_int(wan_json, "load_balance_weight",
                                                         stored_weight)));
        sqlite3_bind_int(st, 30, nc_json_int(wan_json, "priority", stored_priority));
        if (nc_step_done(st) == 0) rc = 0;
        sqlite3_finalize(st);
    }

    if (rc == 0) {
        if (nc_wan_save_addresses(id, addresses) != 0 ||
            nc_wan_save_advanced(id, advanced) != 0 ||
            nc_wan_save_bond(id, bond) != 0)
            rc = -1;
        if (hybrid_lines && json_object_is_type(hybrid_lines, json_type_array)) {
            int i, n;
            char existing_ids[256][96];
            int existing_count = 0;

            if (nc_prepare(&st,
                "SELECT id FROM hybrid_line WHERE parent_wan_id=?1 ORDER BY id") == 0) {
                sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
                while (existing_count < 256 && sqlite3_step(st) == SQLITE_ROW) {
                    const char *existing_id = (const char *)sqlite3_column_text(st, 0);
                    snprintf(existing_ids[existing_count++], sizeof(existing_ids[0]),
                             "%s", existing_id ? existing_id : "");
                }
                sqlite3_finalize(st);
                st = NULL;
            }
            n = (int)json_object_array_length(hybrid_lines);
            for (i = 0; i < n; i++) {
                struct json_object *line = json_object_array_get_idx(hybrid_lines, i);
                if (!line || !json_object_is_type(line, json_type_object)) continue;
                json_object_object_add(line, "parent", json_object_new_string(id));
                json_object_object_add(line, "parent_wan_id", json_object_new_string(id));
                if (jmx_netconfig_hybrid_line_set(line) != 0) {
                    rc = -1;
                    break;
                }
            }
            if (rc == 0) {
                for (i = 0; i < existing_count; i++) {
                    int j, keep = 0;
                    for (j = 0; j < n; j++) {
                        struct json_object *line = json_object_array_get_idx(hybrid_lines, j);
                        if (line && !strcmp(nc_json_str(line, "id", ""), existing_ids[i])) {
                            keep = 1;
                            break;
                        }
                    }
                    if (!keep && jmx_netconfig_hybrid_line_delete(existing_ids[i]) != 0) {
                        rc = -1;
                        break;
                    }
                }
            }
        }
    }
    if (pppoe_multi_json) free(pppoe_multi_json);
    if (stored_password) {
        memset(stored_password, 0, strlen(stored_password));
        free(stored_password);
    }
    free(stored_pppoe_multi_json);
    return rc;
}

int jmx_netconfig_wan_set_enabled(const char *id, int enabled)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "UPDATE wan SET enabled=?1,updated_at=?2 WHERE id=?3") != 0)
        return -1;
    sqlite3_bind_int(st, 1, enabled ? 1 : 0);
    sqlite3_bind_int64(st, 2, nc_now_s());
    sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) == 0 && sqlite3_changes(g_netconfig_db) > 0)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

/* Read the running l3 device of a uci interface via ubus. Returns 0 and fills
 * out when the interface is up with a usable device, -1 otherwise. Caller must
 * have validated section as a uci section name: it reaches a shell command. */
static int nc_wan_runtime_l3_device(const char *section, char *out, size_t out_len)
{
    char command[192];
    char line[4096];
    struct json_object *root = NULL;
    struct json_object *value = NULL;
    FILE *fp;
    int rc = -1;

    if (!section || !out || !out_len)
        return -1;
    out[0] = '\0';
    snprintf(command, sizeof(command),
             "ubus -S call network.interface.%s status 2>/dev/null", section);
    fp = popen(command, "r");
    if (!fp)
        return -1;
    if (fgets(line, sizeof(line), fp))
        root = json_tokener_parse(line);
    pclose(fp);
    if (root && json_object_object_get_ex(root, "l3_device", &value) && value) {
        const char *device = json_object_get_string(value);

        if (device && device[0] && if_nametoindex(device) > 0) {
            snprintf(out, out_len, "%s", device);
            rc = 0;
        }
    }
    if (root)
        json_object_put(root);
    return rc;
}

/* Redial one WAN: ifdown then ifup on its uci interface section. Config is not
 * touched, so this is a runtime action rather than a write to the ledger.
 *
 * Returns 0 when the interface came back up with an l3 device before the
 * deadline, JMX_NETCONFIG_WAN_RECONNECT_TIMEOUT when the redial was issued but
 * the line had not come up yet (the caller must report that honestly instead of
 * calling it a failure -- pppoe routinely needs more than ten seconds),
 * JMX_NETCONFIG_WAN_RECONNECT_DISABLED for a WAN that exists but is disabled,
 * and -1 for a bad id or a WAN that does not exist.
 *
 * A disabled line is refused before ifdown/ifup runs. Redialling it would
 * report "pending" forever -- ifup on a disabled uci section never yields an
 * l3 device -- which reads to the caller as a slow success rather than a
 * configuration problem.
 *
 * id reaches a shell command, so it is validated as a uci section name first. */
int jmx_netconfig_wan_reconnect(const char *id, int wait_ms, char *state_out,
                                size_t state_len)
{
    sqlite3_stmt *st = NULL;
    char command[192];
    int exists = 0;
    int enabled = 0;
    int waited = 0;
    const int step_ms = 500;

    if (state_out && state_len)
        state_out[0] = '\0';
    if (!nc_uci_section_name_ok(id))
        return -1;
    if (jmx_netconfig_db_init() != 0)
        return -1;
    if (nc_prepare(&st, "SELECT enabled FROM wan WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        exists = 1;
        enabled = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    if (!exists)
        return -1;
    if (!enabled)
        return JMX_NETCONFIG_WAN_RECONNECT_DISABLED;

    snprintf(command, sizeof(command), "/sbin/ifdown %s >/dev/null 2>&1", id);
    if (system(command) == -1)
        return -1;
    snprintf(command, sizeof(command), "/sbin/ifup %s >/dev/null 2>&1", id);
    if (system(command) == -1)
        return -1;

    if (wait_ms < 0)
        wait_ms = 0;
    if (wait_ms > JMX_NETCONFIG_WAN_RECONNECT_MAX_WAIT_MS)
        wait_ms = JMX_NETCONFIG_WAN_RECONNECT_MAX_WAIT_MS;
    while (waited <= wait_ms) {
        char l3_device[64] = "";

        if (nc_wan_runtime_l3_device(id, l3_device, sizeof(l3_device)) == 0 &&
            l3_device[0]) {
            if (state_out && state_len)
                snprintf(state_out, state_len, "%s", l3_device);
            return 0;
        }
        if (waited == wait_ms)
            break;
        usleep((useconds_t)step_ms * 1000);
        waited += step_ms;
    }
    return JMX_NETCONFIG_WAN_RECONNECT_TIMEOUT;
}

int jmx_netconfig_wan_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *uctx = NULL;
    struct uci_package *netpkg = NULL, *firepkg = NULL;
    char bak_network[256] = {0}, bak_firewall[256] = {0};
    char hybrid_ids[256][96];
    int hybrid_count = 0;
    int i;
    int db_tx = 0;
    int uci_changed = 0;
    int rc = -1;

    if (!id || !id[0] || !nc_valid_name(id)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_backup_config("network", bak_network, sizeof(bak_network)) != 0 ||
        nc_backup_config("firewall", bak_firewall, sizeof(bak_firewall)) != 0)
        return -1;

    if (nc_prepare(&st,
        "SELECT id FROM hybrid_line WHERE parent_wan_id=?1 ORDER BY id") != 0)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while (hybrid_count < 256 && sqlite3_step(st) == SQLITE_ROW) {
        snprintf(hybrid_ids[hybrid_count++], sizeof(hybrid_ids[0]), "%s",
                 nc_sql_text(st, 0));
    }
    sqlite3_finalize(st);
    st = NULL;

    if (nc_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    db_tx = 1;

    {
        const char *tables[] = {
            "wan_dns_policy", "wan_address", "wan_advanced", "wan_bond"
        };
        size_t table_index;

        for (table_index = 0;
             table_index < sizeof(tables) / sizeof(tables[0]);
             table_index++) {
            char sql[128];
            snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE wan_id=?1",
                     tables[table_index]);
            if (nc_prepare(&st, sql) != 0)
                goto done;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            if (nc_step_done(st) != 0)
                goto done;
            sqlite3_finalize(st);
            st = NULL;
        }
    }
    if (nc_prepare(&st, "DELETE FROM hybrid_line WHERE parent_wan_id=?1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;

    if (nc_prepare(&st, "DELETE FROM wan WHERE id=?1") != 0)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) != 0 || sqlite3_changes(g_netconfig_db) <= 0)
        goto done;
    sqlite3_finalize(st);
    st = NULL;

    uctx = uci_alloc_context();
    if (!uctx)
        goto done;
    if (uci_load(uctx, "network", &netpkg) != UCI_OK ||
        uci_load(uctx, "firewall", &firepkg) != UCI_OK)
        goto done;
    if (nc_uci_delete_section_pkg(uctx, "network", id) != 0)
        goto done;
    if (nc_apply_wan_firewall_zone(uctx, firepkg, id, 0) != 0)
        goto done;
    for (i = 0; i < hybrid_count; i++) {
        if (nc_uci_delete_section_pkg(uctx, "network", hybrid_ids[i]) != 0 ||
            nc_apply_wan_firewall_zone(uctx, firepkg, hybrid_ids[i], 0) != 0)
            goto done;
    }
    uci_changed = 1;
    if (jmx_uci_commit(uctx, "network") != UCI_OK ||
        jmx_uci_commit(uctx, "firewall") != UCI_OK)
        goto done;

    if (nc_reload_network_stack(0, 1, "/tmp/dw-wan-delete-reload.log") != 0)
        goto done;
    if (nc_exec("COMMIT") != 0)
        goto done;
    db_tx = 0;
    /* The WAN is gone: end its open connection-time session (and those of its
     * hybrid children) so a WAN recreated under the same id counts from zero
     * instead of inheriting the deleted line's started_at. Runs after COMMIT
     * because wan_session lives in the runtime DB, not this transaction. */
    jmx_db_close_wan_session(id, "wan_deleted");
    for (i = 0; i < hybrid_count; i++)
        jmx_db_close_wan_session(hybrid_ids[i], "wan_deleted");
    rc = 0;

done:
    if (st)
        sqlite3_finalize(st);
    if (rc != 0) {
        if (db_tx) {
            nc_exec("ROLLBACK");
            db_tx = 0;
        }
        if (uci_changed) {
            nc_restore_config("network", bak_network);
            nc_restore_config("firewall", bak_firewall);
            nc_reload_network_stack(0, 1, "/tmp/dw-wan-delete-rollback.log");
        }
    }
    nc_cleanup_backup(bak_network);
    nc_cleanup_backup(bak_firewall);
    if (uctx)
        uci_free_context(uctx);
    return rc;
}
