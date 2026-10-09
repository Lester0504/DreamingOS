// SPDX-License-Identifier: GPL-2.0-or-later
/* Included by the guarded network transaction engine. IPTV owns a dedicated
 * WAN resource; it does not maintain a second network configuration database. */
static struct json_object *nc_tx_get(struct json_object *req);
static struct json_object *nc_tx_canonical(const char *domain, const char *id, int *supported);
static int nc_iptv_prepare(struct json_object *config, const char *operation,
                           struct json_object *prepared);
static void nc_iptv_platform_check(struct json_object *config, struct json_object *request,
                                    struct json_object *errors);
static struct json_object *nc_iptv_runtime(const char *id);
static int nc_iptv_reconnect(const char *id);

static struct json_object *nc_iptv_query(const char *sql)
{
    sqlite3_stmt *st = NULL;
    struct json_object *rows = json_object_new_array();
    int rc = sqlite3_prepare_v2(g_netconfig_db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK) goto fail;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *row = json_object_new_object();
        for (int n = 0; n < sqlite3_column_count(st); n++) {
            struct json_object *v = NULL;
            switch (sqlite3_column_type(st, n)) {
            case SQLITE_INTEGER: v = json_object_new_int64(sqlite3_column_int64(st, n)); break;
            case SQLITE_TEXT: v = json_object_new_string((const char *)sqlite3_column_text(st, n)); break;
            case SQLITE_NULL: break;
            default: json_object_put(row); goto fail;
            }
            json_object_object_add(row, sqlite3_column_name(st, n), v);
        }
        json_object_array_add(rows, row);
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return rows;
    json_object_put(rows);
    return NULL;
fail:
    if (st) sqlite3_finalize(st);
    json_object_put(rows);
    return NULL;
}

/* Guard inputs to ownership/preflight as part of the same revision and crash
 * journal. These rows are never restored: only the target WAN may be changed. */
static struct json_object *nc_iptv_dependencies(const char *id)
{
    static const char *const queries[] = {
        "SELECT * FROM wan ORDER BY id", "SELECT * FROM wan_address ORDER BY id",
        "SELECT * FROM wan_advanced ORDER BY wan_id", "SELECT * FROM wan_bond ORDER BY wan_id",
        "SELECT * FROM wan_dns_policy ORDER BY id", "SELECT * FROM hybrid_line ORDER BY id",
        "SELECT * FROM lan ORDER BY id", "SELECT * FROM lan_port ORDER BY id",
        "SELECT * FROM lan_address ORDER BY id",
        "SELECT name,kind,owner_type,owner_id FROM physical_port ORDER BY name",
        "SELECT * FROM physical_port_config ORDER BY ifname",
        "SELECT * FROM physical_port_profile ORDER BY id",
        "SELECT * FROM multicast_config ORDER BY id", "SELECT * FROM network_global ORDER BY id",
        "SELECT id,COALESCE(json_extract(body,'$.input_id'),'') AS input_id FROM iptv_record WHERE kind='channels' ORDER BY id", NULL
    };
    struct json_object *out = json_object_new_array();
    for (int n = 0; queries[n]; n++) {
        struct json_object *rows = nc_iptv_query(queries[n]);
        if (!rows) { json_object_put(out); return NULL; }
        /* Port ownership is a projection refreshed from WAN/LAN rows. This
         * target may appear/disappear there after apply; foreign owners remain
         * part of the dependency guard, as do all authoritative WAN/LAN rows. */
        if (n == 9) for (size_t i = 0; i < json_object_array_length(rows); i++) {
            struct json_object *port = json_object_array_get_idx(rows, i);
            if (!strcmp(nc_json_str(port, "owner_type", ""), "wan") &&
                !strcmp(nc_json_str(port, "owner_id", ""), id)) {
                json_object_object_add(port, "owner_type", json_object_new_string(""));
                json_object_object_add(port, "owner_id", json_object_new_string(""));
            }
        }
        json_object_array_add(out, rows);
    }
    return out;
}

static struct json_object *nc_iptv_canonical(const char *id, int *supported)
{
    struct json_object *rows = safeops_network_rows(g_netconfig_db, "iptv", id);
    if (!rows) return NULL;
    struct json_object *parents = json_object_object_get(rows, "wan");
    struct json_object *parent = json_object_array_get_idx(parents, 0), *out;
    int exists = parent != NULL;
    *supported = !strncmp(id, "iptv_", 5) && strlen(id) <= 9 &&
        (!exists || !strcmp(nc_json_str(parent, "role", ""), "iptv"));
    if (exists) {
        int ignored = 0;
        out = nc_tx_canonical("wan", id, &ignored);
        *supported = *supported && ignored;
    } else {
        out = json_tokener_parse("{\"name\":\"\",\"note\":\"\",\"device\":\"\","
            "\"access_mode\":\"dhcp\",\"enabled\":true,\"vlan_enabled\":false,\"vlan_id\":\"\","
            "\"mtu\":1500,\"metric\":1000,\"gateway\":\"\",\"dns_json\":\"[]\","
            "\"addresses\":[],\"username\":\"\",\"ipv6_mode\":\"disabled\"}");
        json_object_object_add(out, "id", json_object_new_string(id));
        json_object_object_add(out, "ifname", json_object_new_string(id));
        json_object_object_add(out, "role", json_object_new_string("iptv"));
    }
    if (out) {
        struct json_object *adv = json_object_array_get_idx(json_object_object_get(rows, "wan_advanced"), 0);
        json_object_object_add(out, "exists", json_object_new_boolean(exists));
        json_object_object_add(out, "enabled", json_object_new_boolean(nc_json_bool(out, "enabled", 1)));
        json_object_object_add(out, "vlan_enabled", json_object_new_boolean(nc_json_bool(out, "vlan_enabled", 0)));
        json_object_object_add(out, "option60", json_object_new_string(nc_json_str(adv, "dhcp_vendor_class", "")));
        json_object_object_add(out, "igmp_version", json_object_new_int(nc_json_int(adv, "iptv_igmp_version", 0)));
        json_object_object_add(out, "multicast_source", json_object_new_string(nc_json_str(adv, "iptv_multicast_source", "session")));
        json_object_object_add(out, "carrier_access_mode", json_object_new_string(nc_json_str(adv, "iptv_carrier_mode", "dhcp")));
        json_object_object_add(out, "carrier_address", json_object_new_string(nc_json_str(adv, "iptv_carrier_address", "")));
        json_object_object_add(out, "carrier_prefix", json_object_new_int(nc_json_int(adv, "iptv_carrier_prefix", 24)));
        json_object_object_add(out, "password_set", json_object_new_boolean(
            nc_json_str(parent, "password_ref", "")[0] != 0));
    }
    json_object_put(rows);
    return out;
}

static int nc_iptv_same_carrier(const char *a, const char *b)
{
    size_t n = strlen(b);
    return n && (!strcmp(a, b) || (!strncmp(a, b, n) && a[n] == '.'));
}

static struct json_object *nc_iptv_references(const char *id)
{
    struct json_object *rows = nc_iptv_query("SELECT id,body FROM iptv_record WHERE kind='channels' ORDER BY id");
    if (!rows) return NULL;
    struct json_object *refs = json_object_new_array();
    for (size_t n = 0; n < json_object_array_length(rows); n++) {
        struct json_object *row = json_object_array_get_idx(rows, n);
        struct json_object *body = json_tokener_parse(nc_json_str(row, "body", ""));
        if (!body) { json_object_put(rows); json_object_put(refs); return NULL; }
        if (!strcmp(nc_json_str(body, "input_id", ""), id))
            json_object_array_add(refs, json_object_new_string(nc_json_str(row, "id", "")));
        json_object_put(body);
    }
    json_object_put(rows);
    return refs;
}

static void nc_iptv_ownership(struct json_object *config, struct json_object *errors)
{
    const char *id = nc_json_str(config, "id", ""), *device = nc_json_str(config, "device", "");
    static const char *const checks[] = {
        "SELECT id,device FROM wan", "SELECT id,device FROM lan",
        "SELECT lan_id AS id,port AS device FROM lan_port", NULL
    };
    for (int c = 0; checks[c]; c++) {
        struct json_object *rows = nc_iptv_query(checks[c]);
        if (!rows) { nc_add_field_error(errors, "device", "ownership_unavailable", "Cannot read network ownership"); continue; }
        for (size_t n = 0; n < json_object_array_length(rows); n++) {
            struct json_object *row = json_object_array_get_idx(rows, n);
            if (c == 0 && !strcmp(nc_json_str(row, "id", ""), id)) continue;
            if (nc_iptv_same_carrier(nc_json_str(row, "device", ""), device))
                nc_add_field_error(errors, "device", "carrier_in_use", "Select a dedicated unused physical port");
        }
        json_object_put(rows);
    }
    struct json_object *ports = nc_iptv_query("SELECT name,kind,owner_type,owner_id FROM physical_port");
    int found = 0;
    for (size_t n = 0; ports && n < json_object_array_length(ports); n++) {
        struct json_object *port = json_object_array_get_idx(ports, n);
        if (strcmp(nc_json_str(port, "name", ""), device)) continue;
        found = !strcmp(nc_json_str(port, "kind", ""), "ethernet");
        if (nc_json_str(port, "owner_type", "")[0] && strcmp(nc_json_str(port, "owner_id", ""), id))
            nc_add_field_error(errors, "device", "carrier_in_use", "Physical port has another owner");
    }
    if (ports) json_object_put(ports);
    if (!found) nc_add_field_error(errors, "device", "physical_port_required", "Select a physical Ethernet port");
    struct json_object *profiles = nc_iptv_query("SELECT ifname,profile_id,native_vlan,tagged_vlans_json FROM physical_port_config");
    for (size_t n = 0; profiles && n < json_object_array_length(profiles); n++) {
        struct json_object *p = json_object_array_get_idx(profiles, n);
        if (!strcmp(nc_json_str(p, "ifname", ""), device) &&
            (nc_json_str(p, "profile_id", "")[0] || nc_json_int(p, "native_vlan", 0) ||
             strcmp(nc_json_str(p, "tagged_vlans_json", "[]"), "[]")))
            nc_add_field_error(errors, "device", "port_profile_in_use", "Port VLAN profile is already assigned");
    }
    if (profiles) json_object_put(profiles);
    struct json_object *services = nc_iptv_query("SELECT * FROM multicast_config");
    for (size_t n = 0; services && n < json_object_array_length(services); n++) {
        struct json_object *s = json_object_array_get_idx(services, n);
        const char *keys[] = {"upstream", "downstreams", "iptv_wan_iface", "iptv_lan_iface", "iptv_stb_ports", "udpxy_source_iface", NULL};
        if (!nc_json_bool(s, "igmp_enabled", 0) && !nc_json_bool(s, "iptv_enabled", 0) && !nc_json_bool(s, "udpxy_enabled", 0)) continue;
        for (int k = 0; keys[k]; k++) {
            const char *v = nc_json_str(s, keys[k], "");
            if (!strcmp(v, id) || nc_iptv_same_carrier(v, device) ||
                (strchr(v, '[') && (strstr(v, id) || (*device && strstr(v, device)))))
                nc_add_field_error(errors, "device", "multicast_service_in_use", "Existing multicast service owns this resource");
        }
    }
    if (services) json_object_put(services);
}

static struct json_object *nc_iptv_validate(struct json_object *req, struct json_object **merged)
{
    struct json_object *out = nc_tx_get(req), *config = NULL, *patch = json_object_object_get(req, "config");
    struct json_object *errors = json_object_new_array();
    const char *operation = nc_json_str(req, "operation", "update");
    if (merged) *merged = NULL;
    json_object_object_add(out, "errors", errors);
    if (!nc_json_bool(out, "ok", 0)) return out;
    if (!nc_json_bool(out, "write_supported", 0)) {
        json_object_object_add(out, "error", json_object_new_string("input_not_owned"));
        json_object_object_add(out, "code", json_object_new_int(409)); goto invalid;
    }
    if (!nc_json_str(req, "if_revision", "")[0] ||
        strcmp(nc_json_str(req, "if_revision", ""), nc_json_str(out, "revision", ""))) {
        int missing = !nc_json_str(req, "if_revision", "")[0];
        json_object_object_add(out, "error", json_object_new_string(missing ? "revision_required" : "revision_conflict"));
        json_object_object_add(out, "code", json_object_new_int(missing ? 428 : 409)); goto invalid;
    }
    config = json_tokener_parse(json_object_to_json_string(json_object_object_get(out, "config")));
    int exists = nc_json_bool(config, "exists", 0);
    if ((strcmp(operation, "create") && strcmp(operation, "update") && strcmp(operation, "delete") && strcmp(operation, "reconnect")) ||
        (!strcmp(operation, "create") ? exists : !exists))
        nc_add_field_error(errors, "operation", "invalid_input_operation", "Operation does not match the resource state");
    int editing = !strcmp(operation, "create") || !strcmp(operation, "update");
    if (editing && (!patch || !json_object_is_type(patch, json_type_object) || !json_object_object_length(patch)))
        nc_add_field_error(errors, "config", "config_patch_required", "Configuration patch required");
    if (!editing && patch && (!json_object_is_type(patch, json_type_object) || json_object_object_length(patch)))
        nc_add_field_error(errors, "config", "unexpected_config", "This operation does not edit configuration");
    if (editing && patch && json_object_is_type(patch, json_type_object)) {
        json_object_object_foreach(patch, key, value) {
            static const char *const text[] = {"name", "note", "device", "access_mode", "vlan_id", "gateway", "username", "password", "option60", "multicast_source", "carrier_access_mode", "carrier_address", NULL};
            int known = 0; enum json_type type = json_type_string;
            for (int n = 0; text[n]; n++) if (!strcmp(key, text[n])) known = 1;
            if (!strcmp(key, "enabled") || !strcmp(key, "vlan_enabled") || !strcmp(key, "clear_password")) { known = 1; type = json_type_boolean; }
            if (!strcmp(key, "mtu") || !strcmp(key, "igmp_version") || !strcmp(key, "carrier_prefix")) { known = 1; type = json_type_int; }
            if (!strcmp(key, "addresses")) { known = 1; type = json_type_array; }
            if (!known || !value || !json_object_is_type(value, type)) {
                nc_add_field_error(errors, key, known ? "invalid_type" : "unsupported_field", "Invalid input configuration field"); continue;
            }
            if (type == json_type_string && (strlen(json_object_get_string(value)) > 256 || strpbrk(json_object_get_string(value), "\r\n"))) {
                nc_add_field_error(errors, key, "invalid_text", "Text is too long or contains a line break"); continue;
            }
            json_object_object_add(config, key, json_object_get(value));
        }
    }
    const char *mode = nc_json_str(config, "access_mode", "");
    const char *device = nc_json_str(config, "device", "");

    const char *source = nc_json_str(config, "multicast_source", "session");
    const char *carrier_mode = nc_json_str(config, "carrier_access_mode", "dhcp");
    int igmp = nc_json_int(config, "igmp_version", 0);
    int carrier = !strcmp(mode, "pppoe") && !strcmp(source, "carrier");
    if (igmp != 0 && igmp != 2 && igmp != 3)
        nc_add_field_error(errors, "igmp_version", "invalid_igmp_version", "IGMP version must be 0 (default), 2 or 3");
    if ((strcmp(source, "session") && strcmp(source, "carrier")) || (!strcmp(source, "carrier") && strcmp(mode, "pppoe")))
        nc_add_field_error(errors, "multicast_source", "invalid_multicast_source", "Carrier multicast requires PPPoE");
    if (strcmp(carrier_mode, "dhcp") && strcmp(carrier_mode, "static"))
        nc_add_field_error(errors, "carrier_access_mode", "unsupported_mode", "Carrier addressing must be DHCP or static");
    if (carrier && !strcmp(carrier_mode, "static")) {
        struct in_addr ip;
        int prefix = nc_json_int(config, "carrier_prefix", 24);
        if (inet_pton(AF_INET, nc_json_str(config, "carrier_address", ""), &ip) != 1 || prefix < 1 || prefix > 30)
            nc_add_field_error(errors, "carrier_address", "invalid_address", "Carrier IPv4 address and prefix 1-30 required");
        else {
            uint32_t host = ntohl(ip.s_addr), mask = UINT32_MAX << (32-prefix);
            if (!(host & ~mask) || (host & ~mask) == ~mask || host >> 24 == 127 || host >> 24 == 0 || host >> 28 >= 14)
                nc_add_field_error(errors, "carrier_address", "invalid_address", "Carrier requires a unicast host address");
            struct json_object *used = nc_iptv_query("SELECT wan_id AS owner,ip,prefix FROM wan_address UNION ALL SELECT lan_id,ip,prefix FROM lan_address UNION ALL SELECT wan_id,iptv_carrier_address,iptv_carrier_prefix FROM wan_advanced WHERE iptv_multicast_source='carrier' AND iptv_carrier_mode='static'");
            if (!used) nc_add_field_error(errors, "carrier_address", "address_inventory_unavailable", "Cannot read existing subnets");
            for (size_t n=0; used && n<json_object_array_length(used); n++) {
                struct json_object *row=json_object_array_get_idx(used,n); struct in_addr old;
                int other=nc_json_int(row,"prefix",0);
                if (!strcmp(nc_json_str(row,"owner",""),nc_json_str(config,"id","")) || inet_pton(AF_INET,nc_json_str(row,"ip",""),&old)!=1 || other<1 || other>32) continue;
                uint32_t shared=UINT32_MAX << (32-(prefix<other?prefix:other));
                if ((host&shared)==(ntohl(old.s_addr)&shared)) nc_add_field_error(errors,"carrier_address","subnet_in_use","Carrier subnet overlaps another resource");
            }
            if (used) json_object_put(used);
        }
    }
    if (!*device || strlen(device) > 10 || strspn(device, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != strlen(device))
        nc_add_field_error(errors, "device", "invalid_device", "Invalid physical port name");
    if (!nc_json_str(config, "name", "")[0]) nc_add_field_error(errors, "name", "required", "Name required");
    if (strcmp(mode, "dhcp") && strcmp(mode, "static") && strcmp(mode, "pppoe"))
        nc_add_field_error(errors, "access_mode", "unsupported_mode", "Only DHCP, static IPv4 and PPPoE are supported");
    const char *vlan = nc_json_str(config, "vlan_id", "");
    if (nc_json_bool(config, "vlan_enabled", 0) && (!*vlan || strspn(vlan, "0123456789") != strlen(vlan) || atoi(vlan) < 1 || atoi(vlan) > 4094))
        nc_add_field_error(errors, "vlan_id", "invalid_vlan", "VLAN must be 1-4094");
    if (nc_json_int(config, "mtu", 1500) < 576 || nc_json_int(config, "mtu", 1500) > 1500)
        nc_add_field_error(errors, "mtu", "invalid_mtu", "MTU must be 576-1500");
    if (!strcmp(mode, "pppoe") && (!nc_json_str(config, "username", "")[0] ||
        (!nc_json_str(config, "password", "")[0] && (!nc_json_bool(config, "password_set", 0) || nc_json_bool(config, "clear_password", 0)))))
        nc_add_field_error(errors, "password", "pppoe_credentials_required", "PPPoE credentials required");
    if (strcmp(mode, "dhcp") && !(carrier && !strcmp(carrier_mode, "dhcp")) && nc_json_str(config, "option60", "")[0])
        nc_add_field_error(errors, "option60", "dhcp_required", "Option 60 requires DHCP");
    struct json_object *addresses = json_object_object_get(config, "addresses");
    if (!strcmp(mode, "static")) {
        if (!addresses || json_object_array_length(addresses) != 1)
            nc_add_field_error(errors, "addresses", "one_address_required", "One static IPv4 address is required");
        else {
            struct json_object *a = json_object_array_get_idx(addresses, 0);
            struct in_addr ip;
            struct json_object *prefix_value = json_object_object_get(a, "prefix");
            struct json_object *ip_value = json_object_object_get(a, "ip");
            int prefix = nc_json_int(a, "prefix", 0);
            if (!json_object_is_type(ip_value, json_type_string) || !json_object_is_type(prefix_value, json_type_int) ||
                inet_pton(AF_INET, nc_json_str(a, "ip", ""), &ip) != 1 || prefix < 1 || prefix > 30)
                nc_add_field_error(errors, "addresses", "invalid_address", "IPv4 and prefix 1-30 required");
            else {
                uint32_t host = ntohl(ip.s_addr), mask = UINT32_MAX << (32 - prefix);
                if (!(host & ~mask) || (host & ~mask) == ~mask || host >> 24 == 127 || host >> 24 == 0 || host >> 28 >= 14)
                    nc_add_field_error(errors, "addresses", "invalid_address", "A unicast host address is required");
                struct json_object *used = nc_iptv_query("SELECT wan_id AS owner,ip,prefix FROM wan_address UNION ALL SELECT lan_id,ip,prefix FROM lan_address UNION ALL SELECT wan_id,iptv_carrier_address,iptv_carrier_prefix FROM wan_advanced WHERE iptv_multicast_source='carrier' AND iptv_carrier_mode='static'");
                if (!used) nc_add_field_error(errors, "addresses", "address_inventory_unavailable", "Cannot read existing subnets");
                for (size_t n = 0; used && n < json_object_array_length(used); n++) {
                    struct json_object *row = json_object_array_get_idx(used, n); struct in_addr old;
                    int other = nc_json_int(row, "prefix", 0);
                    if (!strcmp(nc_json_str(row, "owner", ""), nc_json_str(config, "id", "")) ||
                        inet_pton(AF_INET, nc_json_str(row, "ip", ""), &old) != 1 || other < 1 || other > 32) continue;
                    uint32_t shared = UINT32_MAX << (32 - (prefix < other ? prefix : other));
                    if ((host & shared) == (ntohl(old.s_addr) & shared))
                        nc_add_field_error(errors, "addresses", "subnet_in_use", "Subnet overlaps another network resource");
                }
                if (used) json_object_put(used);
                json_object_object_add(a, "primary", json_object_new_boolean(1));
            }
        }
    } else json_object_object_add(config, "addresses", json_object_new_array());
    if (nc_json_str(config, "gateway", "")[0] && !nc_is_valid_ip(nc_json_str(config, "gateway", "")))
        nc_add_field_error(errors, "gateway", "invalid_address", "Invalid gateway IPv4");
    struct json_object *refs = nc_iptv_references(nc_json_str(config, "id", ""));
    if (!refs) nc_add_field_error(errors, "id", "references_unavailable", "Cannot read channel references");
    else {
        json_object_object_add(out, "channel_references", refs);
        if (!strcmp(operation, "delete") && json_object_array_length(refs))
            nc_add_field_error(errors, "id", "input_in_use", "Remove or migrate channel references before deletion");
    }
    if (!strcmp(operation, "reconnect") && !nc_json_bool(config, "enabled", 0))
        nc_add_field_error(errors, "enabled", "input_disabled", "Enable the input before reconnecting");
    struct json_object *stored = safeops_network_rows(g_netconfig_db, "iptv", nc_json_str(config, "id", ""));
    if (stored && (json_object_array_length(json_object_object_get(stored, "wan_dns_policy")) ||
                   json_object_array_length(json_object_object_get(stored, "hybrid_line"))))
        nc_add_field_error(errors, "id", "input_policy_in_use", "Input has shared DNS or hybrid WAN policy references");
    if (stored) json_object_put(stored);
    nc_iptv_ownership(config, errors);
    if (!json_object_array_length(errors)) nc_iptv_platform_check(config, req, errors);
    if (json_object_array_length(errors)) {
        json_object_object_add(out, "error", json_object_new_string("validation_failed"));
        json_object_object_add(out, "code", json_object_new_int(400)); goto invalid;
    }
    struct json_object *advanced = json_tokener_parse("{\"default_route\":false,\"failover\":false,\"health_check\":{\"enabled\":false}}");
    struct json_object *dhcp = json_object_new_object();
    json_object_object_add(dhcp, "vendor_class", json_object_new_string(nc_json_str(config, "option60", "")));
    json_object_object_add(advanced, "dhcp", dhcp);
    json_object_object_add(config, "advanced", advanced);
    json_object_object_add(config, "dns_json", json_object_new_string("[]"));
    json_object_object_add(config, "role", json_object_new_string("iptv"));
    json_object_object_add(config, "ipv6_mode", json_object_new_string("disabled"));
    json_object_object_add(out, "valid", json_object_new_boolean(1));
    json_object_object_add(out, "requires_confirm", json_object_new_boolean(1));
    json_object_object_add(out, "management_path_touched", json_object_new_string("no"));
    json_object_object_add(out, "default_route_changed", json_object_new_boolean(0));
    json_object_object_add(out, "dns_changed", json_object_new_boolean(0));
    json_object_object_add(out, "interrupts_input", json_object_new_boolean(exists));
    if (merged) *merged = config; else json_object_put(config);
    return out;
invalid:
    if (config) json_object_put(config);
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "valid", json_object_new_boolean(0));
    return out;
}
