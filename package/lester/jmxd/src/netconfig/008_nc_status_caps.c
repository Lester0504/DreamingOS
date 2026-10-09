/* Shared with the UPnP service capability response. */
static int nc_upnp_runtime_capable(void);

/* ══════════════════════════════════════════════════════════════════════
 * wan_status: merged config + runtime for one or all WANs
 * ══════════════════════════════════════════════════════════════════════ */

#define NC_NETWORK_STATUS_MAX (1024U * 1024U)

struct nc_ubus_json_result {
    struct json_object *json;
};

static void nc_ubus_json_cb(struct ubus_request *req, int type,
                            struct blob_attr *msg)
{
    struct nc_ubus_json_result *result = req ? req->priv : NULL;
    char *text;

    (void)type;
    if (!result || !msg)
        return;
    text = blobmsg_format_json(msg, true);
    if (!text)
        return;
    if (result->json)
        json_object_put(result->json);
    result->json = json_tokener_parse(text);
    free(text);
}

/* Direct libubus read path. The command fallback below remains for older or
 * transiently unavailable ubus setups, but normal WAN reads do not fork. */
static struct json_object *nc_ubus_call_json(const char *object,
                                             const char *method)
{
    struct nc_ubus_json_result result = { .json = NULL };
    struct blob_buf request = {};
    struct ubus_context *ctx = NULL;
    uint32_t id = 0;
    int rc;

    if (!object || !method)
        return NULL;
    ctx = ubus_connect(NULL);
    if (!ctx)
        return NULL;
    rc = ubus_lookup_id(ctx, object, &id);
    if (rc == UBUS_STATUS_OK) {
        blob_buf_init(&request, 0);
        rc = ubus_invoke(ctx, id, method, request.head,
                         nc_ubus_json_cb, &result, 3000);
        blob_buf_free(&request);
    }
    ubus_free(ctx);
    if (rc != UBUS_STATUS_OK) {
        if (result.json)
            json_object_put(result.json);
        return NULL;
    }
    return result.json;
}

static struct json_object *nc_network_status_json_from_dump(
    const struct json_object *dump, const char *ifname)
{
    struct json_object *interfaces = NULL;
    size_t i;

    if (!dump || !ifname || !ifname[0] ||
        !json_object_object_get_ex((struct json_object *)dump, "interface",
                                   &interfaces) ||
        !interfaces || !json_object_is_type(interfaces, json_type_array))
        return NULL;
    for (i = 0; i < json_object_array_length(interfaces); i++) {
        struct json_object *entry = json_object_array_get_idx(interfaces, i);
        struct json_object *name = NULL;

        if (!entry || !json_object_is_type(entry, json_type_object) ||
            !json_object_object_get_ex(entry, "interface", &name) || !name ||
            !json_object_is_type(name, json_type_string))
            continue;
        if (!strcmp(json_object_get_string(name), ifname))
            return json_object_get(entry);
    }
    return NULL;
}

static struct json_object *nc_network_status_dump_json(void)
{
    return nc_ubus_call_json("network.interface", "dump");
}

static int nc_buffer_append(char **buf, size_t *len, size_t *cap,
                            const void *data, size_t data_len, size_t max_len)
{
    size_t need;
    size_t next;
    char *grown;

    if (!buf || !len || !cap || (!data && data_len != 0) || *len > max_len ||
        data_len > max_len - *len)
        return -1;
    need = *len + data_len + 1;
    if (need < *len || need > max_len + 1)
        return -1;
    if (need > *cap) {
        next = *cap ? *cap : 4096;
        while (next < need) {
            if (next > (max_len + 1) / 2) {
                next = max_len + 1;
                break;
            }
            next *= 2;
        }
        grown = realloc(*buf, next);
        if (!grown)
            return -1;
        *buf = grown;
        *cap = next;
    }
    if (data_len)
        memcpy(*buf + *len, data, data_len);
    *len += data_len;
    (*buf)[*len] = '\0';
    return 0;
}

static char *nc_network_status_read(FILE *fp)
{
    char *buf = NULL;
    size_t len = 0;
    size_t cap = 0;
    char line[1024];

    if (!fp)
        return NULL;
    while (fgets(line, sizeof(line), fp)) {
        size_t line_len = strlen(line);
        if (nc_buffer_append(&buf, &len, &cap, line, line_len,
                             NC_NETWORK_STATUS_MAX) != 0) {
            free(buf);
            return NULL;
        }
    }
    if (ferror(fp)) {
        free(buf);
        return NULL;
    }
    return buf;
}

static struct json_object *nc_network_status_json(const char *ifname)
{
    char cmd[256];
    FILE *fp;
    char *buf = NULL;
    struct json_object *out = NULL;
    char object[128];

    if (!ifname || !ifname[0] || !nc_iface_name_ok(ifname)) return NULL;
    snprintf(object, sizeof(object), "network.interface.%s", ifname);
    out = nc_ubus_call_json(object, "status");
    if (out)
        return out;
    snprintf(cmd, sizeof(cmd), "/bin/ubus call network.interface.%s status 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (!fp) return NULL;
    buf = nc_network_status_read(fp);
    pclose(fp);
    if (buf && buf[0]) out = json_tokener_parse(buf);
    free(buf);
    return out;
}

static void nc_wan_merge_ipv6_runtime(struct json_object *rt, struct json_object *wan_obj,
                                      const char *wan_id, const char *ifname,
                                      const struct json_object *network_dump)
{
    char cand[2][96];
    int ci;
    const char *global = "";
    const char *prefix = "";
    int prefix_mask = -1;
    struct json_object *wan6 = NULL;

    if (!rt || !wan_obj) return;
    cand[0][0] = cand[1][0] = '\0';
    if (ifname && ifname[0]) snprintf(cand[0], sizeof(cand[0]), "%s6", ifname);
    if (wan_id && wan_id[0] && (!cand[0][0] || strcmp(cand[0], wan_id)))
        snprintf(cand[1], sizeof(cand[1]), "%s6", wan_id);

    for (ci = 0; ci < 2 && !wan6; ci++) {
        if (!cand[ci][0]) continue;
        wan6 = nc_network_status_json_from_dump(network_dump, cand[ci]);
        if (!wan6)
            wan6 = nc_network_status_json(cand[ci]);
    }
    if (!wan6) return;

    {
        struct json_object *ipv6_arr = json_object_object_get(wan6, "ipv6-address");
        if (ipv6_arr && json_object_is_type(ipv6_arr, json_type_array)) {
            int i, n = (int)json_object_array_length(ipv6_arr);
            for (i = 0; i < n; i++) {
                struct json_object *a = json_object_array_get_idx(ipv6_arr, i);
                struct json_object *addr = a ? json_object_object_get(a, "address") : NULL;
                const char *s = addr ? json_object_get_string(addr) : "";
                if (s && s[0] && strncasecmp(s, "fe80:", 5) != 0) { global = s; break; }
            }
        }
    }

    {
        struct json_object *prefix_arr = json_object_object_get(wan6, "ipv6-prefix");
        if (prefix_arr && json_object_is_type(prefix_arr, json_type_array) && json_object_array_length(prefix_arr) > 0) {
            struct json_object *p0 = json_object_array_get_idx(prefix_arr, 0);
            struct json_object *addr = p0 ? json_object_object_get(p0, "address") : NULL;
            struct json_object *mask = p0 ? json_object_object_get(p0, "mask") : NULL;
            prefix = addr ? json_object_get_string(addr) : "";
            prefix_mask = mask ? json_object_get_int(mask) : -1;
        }
    }

    if (global && global[0]) {
        struct json_object *old = NULL;
        if (json_object_object_get_ex(rt, "ipv6", &old) && old) {
            const char *old_s = json_object_get_string(old);
            if (old_s && old_s[0] && strncasecmp(old_s, "fe80:", 5) == 0)
                json_object_object_add(rt, "ipv6_link_local", json_object_new_string(old_s));
        }
        json_object_object_add(rt, "ipv6", json_object_new_string(global));
        json_object_object_add(rt, "ipv6_global", json_object_new_string(global));
        json_object_object_add(wan_obj, "ipv6", json_object_new_string(global));
        json_object_object_add(wan_obj, "ipv6_addr", json_object_new_string(global));
        json_object_object_add(wan_obj, "ipv6_global", json_object_new_string(global));
    }

    if (prefix && prefix[0]) {
        char cidr[96];
        if (prefix_mask >= 0) snprintf(cidr, sizeof(cidr), "%s/%d", prefix, prefix_mask);
        else snprintf(cidr, sizeof(cidr), "%s", prefix);
        json_object_object_add(rt, "delegated_prefix", json_object_new_string(cidr));
        json_object_object_add(rt, "ipv6_prefix", json_object_new_string(cidr));
        json_object_object_add(wan_obj, "delegated_prefix", json_object_new_string(cidr));
        json_object_object_add(wan_obj, "ipv6_prefix", json_object_new_string(cidr));
    }

    json_object_put(wan6);
}

static void nc_wan_merge_runtime(const char *wan_id, const char *ifname,
                                 struct json_object *wan_obj,
                                 const struct json_object *network_dump)
{
    /* runtime from ubus network.interface.<ifname> */
    struct json_object *ifst = NULL;

    /*
     * ifname is read back from the wan table and interpolated into the popen()
     * command below, so it is validated here rather than trusted: a stored name
     * carrying shell metacharacters would otherwise execute. An invalid name
     * takes the same empty-runtime path as a missing one, which the caller
     * already handles.
     */
    if (!ifname || !ifname[0] || !nc_valid_name(ifname)) {
        struct json_object *rt = json_object_new_object();
        json_object_object_add(rt, "online", json_object_new_boolean(0));
        json_object_object_add(rt, "ipv4", json_object_new_string(""));
        json_object_object_add(rt, "netmask", json_object_new_string(""));
        json_object_object_add(rt, "gateway", json_object_new_string(""));
        json_object_object_add(rt, "dns", json_object_new_array());
        json_object_object_add(rt, "ipv6", json_object_new_string(""));
        json_object_object_add(rt, "uptime", json_object_new_int(0));
        json_object_object_add(wan_obj, "runtime", rt);
        return;
    }

    ifst = nc_network_status_json_from_dump(network_dump, ifname);
    if (!ifst)
        ifst = nc_network_status_json(ifname);
    if (!ifst) {
        struct json_object *rt = json_object_new_object();
        json_object_object_add(rt, "online", json_object_new_boolean(0));
        json_object_object_add(wan_obj, "runtime", rt);
        return;
    }

    struct json_object *rt = json_object_new_object();
    char runtime_device[IFNAMSIZ] = "";
    {
            int up = 0;
            struct json_object *v = NULL;
            if (json_object_object_get_ex(ifst, "up", &v)) up = json_object_get_boolean(v);
            json_object_object_add(rt, "online", json_object_new_boolean(up));
            if (json_object_object_get_ex(ifst, "l3_device", &v) && v) {
                const char *l3 = json_object_get_string(v);

                if (l3 && l3[0] && strlen(l3) < sizeof(runtime_device))
                    snprintf(runtime_device, sizeof(runtime_device), "%s", l3);
            }

            /* IPv4 */
            struct json_object *ipv4_arr = json_object_object_get(ifst, "ipv4-address");
            if (ipv4_arr && json_object_array_length(ipv4_arr) > 0) {
                struct json_object *a0 = json_object_array_get_idx(ipv4_arr, 0);
                struct json_object *addr = json_object_object_get(a0, "address");
                struct json_object *mask = json_object_object_get(a0, "mask");
                if (addr) json_object_object_add(rt, "ipv4", json_object_new_string(json_object_get_string(addr)));
                if (mask) {
                    int m = json_object_get_int(mask);
                    char mask_str[16]; unsigned int mv = m > 0 ? htonl(~((1U << (32 - m)) - 1)) : 0;
                    struct in_addr ma; ma.s_addr = mv;
                    snprintf(mask_str, sizeof(mask_str), "%s", inet_ntoa(ma));
                    json_object_object_add(rt, "netmask", json_object_new_string(mask_str));
                }
            }

            /* gateway from route */
            struct json_object *routes = json_object_object_get(ifst, "route");
            if (routes && json_object_array_length(routes) > 0) {
                struct json_object *r0 = json_object_array_get_idx(routes, 0);
                struct json_object *nh = json_object_object_get(r0, "nexthop");
                if (nh) json_object_object_add(rt, "gateway", json_object_new_string(json_object_get_string(nh)));
            }

            /* DNS */
            struct json_object *dns_arr = json_object_object_get(ifst, "dns-server");
            struct json_object *dns_out = json_object_new_array();
            if (dns_arr && json_object_is_type(dns_arr, json_type_array)) {
                int di, dn = (int)json_object_array_length(dns_arr);
                for (di = 0; di < dn; di++) {
                    const char *ds = json_object_get_string(json_object_array_get_idx(dns_arr, di));
                    if (ds && ds[0]) json_object_array_add(dns_out, json_object_new_string(ds));
                }
            }
            json_object_object_add(rt, "dns", dns_out);

            /* IPv6 address */
            struct json_object *ipv6_arr = json_object_object_get(ifst, "ipv6-address");
            if (ipv6_arr && json_object_array_length(ipv6_arr) > 0) {
                struct json_object *a6 = json_object_array_get_idx(ipv6_arr, 0);
                struct json_object *a6addr = json_object_object_get(a6, "address");
                if (a6addr) json_object_object_add(rt, "ipv6", json_object_new_string(json_object_get_string(a6addr)));
            }

            /* uptime */
            struct json_object *upobj = json_object_object_get(ifst, "uptime");
            if (upobj) json_object_object_add(rt, "uptime", json_object_new_int64(json_object_get_int64(upobj)));

            json_object_put(ifst);
    }
    nc_wan_merge_ipv6_runtime(rt, wan_obj, wan_id, ifname, network_dump);
    if (!runtime_device[0] && ifname && ifname[0] && strlen(ifname) < sizeof(runtime_device))
        snprintf(runtime_device, sizeof(runtime_device), "%s", ifname);
    json_object_object_add(rt, "runtime_device", json_object_new_string(runtime_device));
    json_object_object_add(wan_obj, "runtime_device", json_object_new_string(runtime_device));
    jmx_iface_ipv6_contract_add_json(rt, runtime_device);
    jmx_iface_ipv6_contract_add_json(wan_obj, runtime_device);

    /* latest health from DB. The runtime samples live in wan_health_samples /
     * wan_health_bucket in the runtime database; keep the legacy wan_health
     * query only for config databases that never migrated. A missing health
     * table must not turn the whole wan runtime into an error, so it is
     * surfaced as health_unavailable. */
    {
        int latency_ms = -1, loss_pct = -1;
        int64_t health_ts = 0;
        if (jmx_db_read_wan_health_latest(ifname, &latency_ms, &loss_pct,
                                          &health_ts) == 0) {
            json_object_object_add(rt, "latency_ms", json_object_new_int(latency_ms));
            json_object_object_add(rt, "loss_pct", json_object_new_int(loss_pct));
            json_object_object_add(rt, "health_at", json_object_new_int64(health_ts));
            json_object_object_add(rt, "health_source", json_object_new_string("wan_health_samples"));
        } else if (nc_table_exists("wan_health")) {
            sqlite3_stmt *hst = NULL;
            if (nc_prepare(&hst,
                    "SELECT latency_ms,loss_pct,checked_at FROM wan_health "
                    "WHERE wan_id=?1 ORDER BY checked_at DESC LIMIT 1") == 0) {
                sqlite3_bind_text(hst, 1, wan_id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(hst) == SQLITE_ROW) {
                    json_object_object_add(rt, "latency_ms", json_object_new_int(sqlite3_column_int(hst, 0)));
                    json_object_object_add(rt, "loss_pct", json_object_new_int(sqlite3_column_int(hst, 1)));
                    json_object_object_add(rt, "health_at", json_object_new_int64(sqlite3_column_int64(hst, 2)));
                    json_object_object_add(rt, "health_source", json_object_new_string("wan_health"));
                }
                sqlite3_finalize(hst);
            }
        } else {
            json_object_object_add(rt, "health_unavailable", json_object_new_boolean(1));
        }
    }

    {
        struct json_object *v = NULL;
        const char *s = NULL;
        if (json_object_object_get_ex(rt, "ipv4", &v) && v) {
            s = json_object_get_string(v);
            if (s && s[0]) {
                json_object_object_add(wan_obj, "ipv4", json_object_new_string(s));
                json_object_object_add(wan_obj, "ip", json_object_new_string(s));
                json_object_object_add(wan_obj, "ipaddr", json_object_new_string(s));
            }
        }
        if (json_object_object_get_ex(rt, "ipv6", &v) && v) {
            s = json_object_get_string(v);
            if (s && s[0]) {
                json_object_object_add(wan_obj, "ipv6", json_object_new_string(s));
                json_object_object_add(wan_obj, "ipv6_addr", json_object_new_string(s));
            }
        }
        if (json_object_object_get_ex(rt, "gateway", &v) && v) {
            s = json_object_get_string(v);
            if (s && s[0]) json_object_object_add(wan_obj, "gateway", json_object_new_string(s));
        }
        if (json_object_object_get_ex(rt, "netmask", &v) && v) {
            s = json_object_get_string(v);
            if (s && s[0]) json_object_object_add(wan_obj, "netmask", json_object_new_string(s));
        }
        if (json_object_object_get_ex(rt, "dns", &v) && v && json_object_is_type(v, json_type_array)) {
            json_object_get(v);
            json_object_object_add(wan_obj, "dns", v);
        }
        if (json_object_object_get_ex(rt, "online", &v) && v) {
            int online = json_object_get_boolean(v);
            json_object_object_add(wan_obj, "health", json_object_new_boolean(online));
            json_object_object_add(wan_obj, "status", json_object_new_string(online ? "ok" : "down"));
        }
        if (json_object_object_get_ex(rt, "uptime", &v) && v)
            json_object_object_add(wan_obj, "uptime", json_object_new_int64(json_object_get_int64(v)));
    }
    {
        jmx_wan_carrier_contract_t carrier;
        const char *public_ip = nc_json_str_def(wan_obj, "ip", "");

        if (jmx_netconfig_wan_carrier_resolve(wan_id, ifname,
                                              runtime_device, public_ip,
                                              &carrier) == 0)
            nc_wan_carrier_contract_add(wan_obj, &carrier);
    }
    json_object_object_add(wan_obj, "runtime", rt);
}

static char *nc_csv_escape(const char *in, size_t *out_len)
{
    struct json_object *tmp = json_object_new_string(in ? in : "");
    const char *escaped = json_object_to_json_string(tmp);
    size_t len = strlen(escaped);
    char *out = (char *)malloc(len + 1);
    if (out) { memcpy(out, escaped, len); out[len] = '\0'; if (out_len) *out_len = len; }
    json_object_put(tmp);
    return out ? out : strdup("\"\"");
}

static void nc_json_csv_append(struct json_object *row, const char *key, FILE *fp, int last)
{
    const char *val = "";
    struct json_object *v = NULL;
    if (row && json_object_object_get_ex(row, key, &v) && v) {
        if (json_object_is_type(v, json_type_boolean)) val = json_object_get_boolean(v) ? "true" : "false";
        else if (json_object_is_type(v, json_type_int)) {
            char tmp[32]; snprintf(tmp, sizeof(tmp), "%lld", (long long)json_object_get_int64(v));
            fwrite(tmp, 1, strlen(tmp), fp);
            if (!last) fputc(',', fp);
            return;
        } else val = json_object_get_string(v);
    }
    size_t len = 0;
    char *esc = nc_csv_escape(val, &len);
    fwrite(esc, 1, len, fp);
    free(esc);
    if (!last) fputc(',', fp);
}

char *jmx_netconfig_wan_csv(size_t *out_len)
{
    char *buffer = NULL;
    size_t total = 0;
    if (out_len) *out_len = 0;
    struct json_object *resp = jmx_netconfig_wan_status(NULL);
    struct json_object *data = NULL, *wans = NULL;
    if (!resp) return NULL;
    json_object_object_get_ex(resp, "data", &data);
    json_object_object_get_ex(data, "wans", &wans);
    FILE *fp = open_memstream(&buffer, &total);
    if (!fp) { json_object_put(resp); return NULL; }
    fprintf(fp, "id,name,ifname,carrier,access_mode,role,enabled,online,ipv4,ipv6,gateway,latency_ms,loss_pct\n");
    if (wans && json_object_is_type(wans, json_type_array)) {
        int i, n = json_object_array_length(wans);
        for (i = 0; i < n; i++) {
            struct json_object *w = json_object_array_get_idx(wans, i);
            struct json_object *rt = NULL;
            json_object_object_get_ex(w, "runtime", &rt);
            nc_json_csv_append(w, "id", fp, 0);
            nc_json_csv_append(w, "name", fp, 0);
            nc_json_csv_append(w, "ifname", fp, 0);
            nc_json_csv_append(w, "carrier", fp, 0);
            nc_json_csv_append(w, "access_mode", fp, 0);
            nc_json_csv_append(w, "role", fp, 0);
            nc_json_csv_append(w, "enabled", fp, 0);
            nc_json_csv_append(rt, "online", fp, 0);
            nc_json_csv_append(rt, "ipv4", fp, 0);
            nc_json_csv_append(rt, "ipv6", fp, 0);
            nc_json_csv_append(rt, "gateway", fp, 0);
            nc_json_csv_append(rt, "latency_ms", fp, 0);
            nc_json_csv_append(rt, "loss_pct", fp, 1);
            fputc('\n', fp);
        }
    }
    fclose(fp);
    json_object_put(resp);
    if (out_len) *out_len = total;
    return buffer;
}

char *jmx_netconfig_lan_csv(size_t *out_len)
{
    char *buffer = NULL;
    size_t total = 0;
    if (out_len) *out_len = 0;
    struct json_object *resp = jmx_netconfig_lan_list();
    struct json_object *data = NULL, *lans = NULL;
    if (!resp) return NULL;
    json_object_object_get_ex(resp, "data", &data);
    json_object_object_get_ex(data, "lans", &lans);
    FILE *fp = open_memstream(&buffer, &total);
    if (!fp) { json_object_put(resp); return NULL; }
    fprintf(fp, "id,name,ifname,device,mode,vlan_id,enabled,ipaddr,netmask,cidr\n");
    if (lans && json_object_is_type(lans, json_type_array)) {
        int i, n = json_object_array_length(lans);
        for (i = 0; i < n; i++) {
            struct json_object *l = json_object_array_get_idx(lans, i);
            nc_json_csv_append(l, "id", fp, 0);
            nc_json_csv_append(l, "name", fp, 0);
            nc_json_csv_append(l, "ifname", fp, 0);
            nc_json_csv_append(l, "device", fp, 0);
            nc_json_csv_append(l, "mode", fp, 0);
            nc_json_csv_append(l, "vlan_id", fp, 0);
            nc_json_csv_append(l, "enabled", fp, 0);
            nc_json_csv_append(l, "ipaddr", fp, 0);
            nc_json_csv_append(l, "netmask", fp, 0);
            nc_json_csv_append(l, "cidr", fp, 1);
            fputc('\n', fp);
        }
    }
    fclose(fp);
    json_object_put(resp);
    if (out_len) *out_len = total;
    return buffer;
}

struct json_object *jmx_netconfig_wan_status(const char *id)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    struct json_object *network_dump = NULL;

    if (jmx_netconfig_db_init() != 0) goto done;
    /* One immutable netifd dump serves every WAN and its optional IPv6 peer. */
    network_dump = nc_network_status_dump_json();
    if (id && id[0]) {
        if (nc_prepare(&st,
            "SELECT id,name,note,carrier,ifname,device,port_label,access_mode,"
            "gateway,dns_json,ipv6_mode,ipv6_addr,delegated_prefix,"
            "vlan_enabled,vlan_id,mtu,metric,role,"
            "expected_down_mbps,expected_up_mbps,smart_queue,upnp,ddns,enabled,"
            "username,password_ref,pppoe_multi_json "
            "FROM wan WHERE id=?1") == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *wid = (const char *)sqlite3_column_text(st, 0);
                const char *wifname = (const char *)sqlite3_column_text(st, 4);
                struct json_object *w = nc_wan_row_to_json(st);
                nc_wan_load_addresses(wid, w);
                nc_wan_load_advanced(wid, w);
                nc_wan_load_bond(wid, w);
                nc_wan_load_hybrid_lines(wid, w);
                nc_wan_merge_runtime(wid, wifname, w, network_dump);
                json_object_object_add(data, "wan", w);
            }
            sqlite3_finalize(st);
        }
    } else {
        if (nc_prepare(&st,
            "SELECT id,name,note,carrier,ifname,device,port_label,access_mode,"
            "gateway,dns_json,ipv6_mode,ipv6_addr,delegated_prefix,"
            "vlan_enabled,vlan_id,mtu,metric,role,"
            "expected_down_mbps,expected_up_mbps,smart_queue,upnp,ddns,enabled,"
            "username,password_ref,pppoe_multi_json "
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
        json_object_object_add(data, "wans", arr);
    }

done:
    if (network_dump)
        json_object_put(network_dump);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ══════════════════════════════════════════════════════════════════════
 * bond_status: runtime state for a WAN's bond device
 * ══════════════════════════════════════════════════════════════════════ */

struct json_object *jmx_netconfig_bond_status(const char *wan_id)
{
    struct json_object *data = json_object_new_object();
    sqlite3_stmt *st = NULL;
    char bond_name[64] = {0};

    if (!wan_id || !wan_id[0]) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (jmx_netconfig_db_init() != 0) goto done;

    /* get bond config from DB */
    if (nc_prepare(&st, "SELECT enabled,bond_name,mode,hash_policy,members_json FROM wan_bond WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(data, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
            const char *bn = (const char *)sqlite3_column_text(st, 1);
            if (bn && bn[0]) snprintf(bond_name, sizeof(bond_name), "%s", bn);
            nc_add_text(data, "bond_name", st, 1);
            nc_add_text(data, "mode", st, 2);
            nc_add_text(data, "hash_policy", st, 3);
            nc_add_text(data, "members_json", st, 4);
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    /* runtime from /proc/net/bonding/<bond_name> */
    if (bond_name[0]) {
        char path[128];
        snprintf(path, sizeof(path), "/proc/net/bonding/%s", bond_name);
        FILE *fp = fopen(path, "r");
        if (fp) {
            char line[512];
            struct json_object *members = json_object_new_array();
            struct json_object *cur_member = NULL;
            int bonding_mode = -1;
            char mii_status[32] = {0};

            while (fgets(line, sizeof(line), fp)) {
                /* strip newline */
                size_t ll = strlen(line);
                while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';

                if (strncmp(line, "Bonding Mode: ", 14) == 0) {
                    json_object_object_add(data, "runtime_mode", json_object_new_string(line + 14));
                /* 21 stopped one byte before the literal's trailing space, so
                 * line+21 began on that space and runtime_hash_policy carried a
                 * leading blank (" layer2+3" instead of "layer2+3"). */
                } else if (strncmp(line, "Transmit Hash Policy: ", 22) == 0) {
                    json_object_object_add(data, "runtime_hash_policy", json_object_new_string(line + 22));
                } else if (strncmp(line, "MII Status: ", 12) == 0) {
                    JMX_STRBUF_COPY(mii_status, line + 12);
                    json_object_object_add(data, "mii_status", json_object_new_string(mii_status));
                } else if (strncmp(line, "Slave Interface: ", 17) == 0) {
                    if (cur_member) json_object_array_add(members, cur_member);
                    cur_member = json_object_new_object();
                    json_object_object_add(cur_member, "interface", json_object_new_string(line + 17));
                } else if (cur_member && strncmp(line, "MII Status: ", 12) == 0) {
                    json_object_object_add(cur_member, "mii_status", json_object_new_string(line + 12));
                } else if (cur_member && strncmp(line, "Speed: ", 7) == 0) {
                    json_object_object_add(cur_member, "speed", json_object_new_string(line + 7));
                } else if (cur_member && strncmp(line, "Duplex: ", 8) == 0) {
                    json_object_object_add(cur_member, "duplex", json_object_new_string(line + 8));
                } else if (cur_member && strncmp(line, "Link Failure Count: ", 20) == 0) {
                    json_object_object_add(cur_member, "link_failures", json_object_new_int(atoi(line + 20)));
                }
            }
            if (cur_member) json_object_array_add(members, cur_member);
            json_object_object_add(data, "slaves", members);
            json_object_object_add(data, "runtime_up", json_object_new_boolean(strcmp(mii_status, "up") == 0));
            fclose(fp);
        } else {
            json_object_object_add(data, "runtime_up", json_object_new_boolean(0));
            json_object_object_add(data, "runtime_note", json_object_new_string("bond device not found in /proc"));
        }
    }

done:
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ══════════════════════════════════════════════════════════════════════
 * capabilities: feature detection for UI
 * ══════════════════════════════════════════════════════════════════════ */

/* Static-mapping dataplane, defined further down with the UPnP mapping CRUD. */
#define NC_UPNP_NFT_TABLE "dreamingwrt_upnp"
static int nc_upnp_nft_available(void);

/* DNS engine discovery, defined further down with the DNS service code. */
static int nc_dns_encrypted_capable_engine(const char **engine_id);

struct json_object *jmx_netconfig_capabilities(void)
{
    struct json_object *data = json_object_new_object();

    /* ── Network / Global ── */

    /* multi_wan: DreamingWrt always supports multi-WAN */
    json_object_object_add(data, "multi_wan", json_object_new_boolean(1));

    /* multi_lan: DreamingWrt always supports multi-LAN */
    json_object_object_add(data, "multi_lan", json_object_new_boolean(1));
    json_object_object_add(data, "network_batch_preview", json_object_new_boolean(1));
    json_object_object_add(data, "network_batch_apply", json_object_new_boolean(1));
    json_object_object_add(data, "network_batch_atomic", json_object_new_boolean(0));
    json_object_object_add(data, "network_batch_partial", json_object_new_boolean(1));
    json_object_object_add(data, "network_batch_max_operations",
                           json_object_new_int(NC_NETWORK_BATCH_MAX));
    json_object_object_add(data, "network_batch_semantics",
                           json_object_new_string("ordered_single_item_transactions"));

    /* bypass_router_mode: supported by work mode subsystem */
    json_object_object_add(data, "bypass_router_mode", json_object_new_boolean(1));

    json_object_object_add(data, "network_global_read", json_object_new_boolean(1));
    json_object_object_add(data, "network_global_save", json_object_new_boolean(0));
    json_object_object_add(data, "network_global_apply", json_object_new_boolean(0));
    json_object_object_add(data, "network_global_readback", json_object_new_boolean(0));
    json_object_object_add(data, "network_global_rollback", json_object_new_boolean(0));
    json_object_object_add(data, "network_global_reason",
                           json_object_new_string("transactional_global_network_executor_pending"));
    json_object_object_add(data, "default_posture", json_object_new_boolean(0));
    json_object_object_add(data, "stp", json_object_new_boolean(0));
    json_object_object_add(data, "stp_mode", json_object_new_boolean(0));
    json_object_object_add(data, "igmp_snooping", json_object_new_boolean(0));
    json_object_object_add(data, "mdns_proxy", json_object_new_boolean(0));
    json_object_object_add(data, "rogue_dhcp_detection", json_object_new_boolean(0));
    json_object_object_add(data, "jumbo_frames", json_object_new_boolean(0));
    json_object_object_add(data, "flow_control", json_object_new_boolean(0));
    json_object_object_add(data, "dot1x", json_object_new_boolean(0));

    /* Port binding */
    json_object_object_add(data, "port_binding", json_object_new_boolean(1));

    /* VLAN networks: DSA bridge VLAN filtering */
    {
        int dsa = 0;
        FILE *fp = popen("ls /sys/class/net/*/bridge 2>/dev/null | head -1", "r");
        if (fp) { char l[64]; if (fgets(l, sizeof(l), fp) && l[0]) dsa = 1; pclose(fp); }
        json_object_object_add(data, "dsa_bridge_vlan", json_object_new_boolean(dsa));
        json_object_object_add(data, "vlan_networks", json_object_new_boolean(dsa));
    }

    /* IPv6 */
    json_object_object_add(data, "ipv6", json_object_new_boolean(
        access("/usr/sbin/odhcpd", X_OK) == 0 || access("/usr/bin/ip6tables", X_OK) == 0));

    /* IPv6 RA */
    json_object_object_add(data, "ipv6_ra", json_object_new_boolean(
        access("/usr/sbin/odhcpd", X_OK) == 0));

    /* DHCPv6 */
    json_object_object_add(data, "dhcpv6", json_object_new_boolean(
        access("/usr/sbin/odhcpd", X_OK) == 0));

    /* Physical ports */
    json_object_object_add(data, "physical_ports", json_object_new_boolean(1));

    /* RADIUS: check for hostapd (which supports RADIUS) */
    json_object_object_add(data, "radius", json_object_new_boolean(
        access("/usr/sbin/hostapd", X_OK) == 0));
    json_object_object_add(data, "radius_servers", json_object_new_boolean(1));

    /* ── WAN ── */

    /* SQM / smart queue: check for sqm-scripts or qos-script */
    json_object_object_add(data, "sqm", json_object_new_boolean(
        access("/usr/lib/sqm/run.sh", X_OK) == 0 || access("/etc/init.d/sqm", X_OK) == 0));
    json_object_object_add(data, "smart_queue", json_object_new_boolean(
        access("/usr/lib/sqm/run.sh", X_OK) == 0 || access("/etc/init.d/sqm", X_OK) == 0));

    /* DDNS: check for ddns-scripts */
    json_object_object_add(data, "ddns", json_object_new_boolean(
        access("/usr/lib/ddns/dynamic_dns_updater.sh", X_OK) == 0 || access("/etc/init.d/ddns", X_OK) == 0));

    /* UPnP: check for miniupnpd */
    json_object_object_add(data, "upnp", json_object_new_boolean(
        access("/usr/sbin/miniupnpd", X_OK) == 0 || access("/etc/init.d/miniupnpd", X_OK) == 0));

    /* Bonding: check if bonding module loaded or available */
    json_object_object_add(data, "bonding", json_object_new_boolean(
        access("/proc/net/bonding", F_OK) == 0 || access("/sys/module/bonding", F_OK) == 0));

    /* VLAN on WAN */
    json_object_object_add(data, "vlan", json_object_new_boolean(1));
    json_object_object_add(data, "vlan_enabled", json_object_new_boolean(1));

    /* Health check */
    json_object_object_add(data, "health_check", json_object_new_boolean(1));

    /* DHCP options */
    json_object_object_add(data, "dhcp_options", json_object_new_boolean(1));

    /* PPPoE advanced */
    json_object_object_add(data, "pppoe_advanced", json_object_new_boolean(1));
    json_object_object_add(data, "hybrid_wan_write", json_object_new_boolean(0));
    json_object_object_add(data, "pppoe_multi_write", json_object_new_boolean(0));
    json_object_object_add(data, "wan_bonding_write", json_object_new_boolean(0));
    json_object_object_add(data, "wan_bonding_write_reason",
                           json_object_new_string("bond runtime apply/readback is not transactionally closed"));
    /*
     * WAN mode (failover | load_balance) is now stored and read back in
     * network_global.wan_mode, and it is writable.
     *
     * The write is a whitelist of one: PUT /api/v1/network/global accepts a body
     * containing wan_mode and nothing else. Every other global field still has
     * no transactional apply/readback/rollback and keeps its 409, so this key
     * must not be read as "global network settings are writable".
     *
     * The mode has a real runtime consumer: route_rule_from_json() maps
     * "failover" onto the kernel's PRIMARY_BACKUP selector for the default
     * multi-WAN rule, and "load_balance" leaves the weighted selector in place.
     * It takes effect on routed's next config sync, which is why the write
     * response reports apply_state "pending_route_sync" rather than applied.
     *
     * wan_mode_write is the canonical key. The two names the frontend probes
      * today (wan_policy_write / wan_load_balance_write) are published as
      * aliases so the contract is discoverable from either side, and all three
     * report the same value.
     */
    json_object_object_add(data, "wan_mode_read", json_object_new_boolean(1));
    json_object_object_add(data, "wan_mode_write", json_object_new_boolean(1));
    json_object_object_add(data, "wan_policy_write", json_object_new_boolean(1));
    json_object_object_add(data, "wan_load_balance_write", json_object_new_boolean(1));
    json_object_object_add(data, "wan_mode_apply", json_object_new_string("pending_route_sync"));
    /* Other global fields are still refused; say so next to the writable one. */
    json_object_object_add(data, "global_network_write_scope",
                           json_object_new_string("wan_mode_only"));
    {
        struct json_object *modes = json_object_new_array();

        json_object_array_add(modes, json_object_new_string("failover"));
        json_object_array_add(modes, json_object_new_string("load_balance"));
        json_object_object_add(data, "wan_mode_values", modes);
    }
    json_object_object_add(data, "pppoe_secret_write_only", json_object_new_boolean(1));
    json_object_object_add(data, "pppoe_keep_password", json_object_new_boolean(1));

    /* Carrier profile */
    json_object_object_add(data, "carrier_profile", json_object_new_boolean(1));
    /* Enumerable carrier list, so the WAN form can offer a picker instead of a
     * free-text box the user has to guess the spelling of. */
    json_object_object_add(data, "carrier_enum", json_object_new_boolean(1));
    json_object_object_add(data, "carrier_values", jmx_netconfig_carrier_values());

    /* Expected bandwidth */
    json_object_object_add(data, "expected_bandwidth", json_object_new_boolean(1));

    /* WAN DNS policy */
    json_object_object_add(data, "wan_dns_policy", json_object_new_boolean(1));

    /*
     * WAN redial: POST /api/v1/network/wans/{id}/reconnect. Runtime action only
     * -- it does ifdown/ifup on the line's uci section and writes no config, so
     * it is published separately from every wan_*_write key above.
     *
     * The frontend gates its per-line reconnect button on this key alone and
     * must not probe by calling the route: an unregistered write path is refused
     * 403 by the permission layer, indistinguishable from a registered one the
     * caller may not use.
     *
     * wan_reconnect_wait_ms_max is the largest wait_ms the runtime will honour
     * before it answers state=pending. webd clamps the HTTP-facing value lower
     * than the core ceiling, so this reports the effective HTTP limit rather
     * than JMX_NETCONFIG_WAN_RECONNECT_MAX_WAIT_MS.
     */
    json_object_object_add(data, "wan_reconnect", json_object_new_boolean(1));
    json_object_object_add(data, "wan_reconnect_wait_ms_max",
                           json_object_new_int(20000));
    /* Disabled lines are refused with line_disabled instead of being redialled
     * into a pending state that can never resolve. */
    json_object_object_add(data, "wan_reconnect_requires_enabled",
                           json_object_new_boolean(1));

    /* save_by_id: always supported (SQLite stable id) */
    json_object_object_add(data, "save_by_id", json_object_new_boolean(1));

    /* ── LAN ── */

    json_object_object_add(data, "extra_ips", json_object_new_boolean(1));
    json_object_object_add(data, "dhcp_pool", json_object_new_boolean(1));
    json_object_object_add(data, "lan_isolation", json_object_new_boolean(1));
    /* delete_lan: the route and the executor both exist (webd
     * DELETE /api/v1/network/lans/{id} -> ubus lan_delete ->
     * jmx_netconfig_lan_delete). This bit says the capability is implemented,
     * not that any particular LAN may be removed; per-LAN permission is
     * reported as `deletable` / `delete_blocked_reason` on each lans[] entry. */
    json_object_object_add(data, "delete_lan", json_object_new_boolean(1));
    /* Per-entry deletability is published, so a UI can render button state
     * without probing with a real DELETE. */
    json_object_object_add(data, "lan_deletable_per_entry", json_object_new_boolean(1));

    /* ── DNS ── */

    json_object_object_add(data, "cache_enabled", json_object_new_boolean(1));
    json_object_object_add(data, "rebind_protection", json_object_new_boolean(1));
    json_object_object_add(data, "hijack_protection", json_object_new_boolean(1));
    json_object_object_add(data, "edns_client_subnet", json_object_new_boolean(1));
    json_object_object_add(data, "ipv6_dns", json_object_new_boolean(
        access("/usr/sbin/odhcpd", X_OK) == 0));
    /* Encrypted upstreams are an engine property; probed at runtime. Writing
     * one is still gated (see encrypted_upstream_write in the DNS service
     * capability block) until the engine config renderer exists. */
    json_object_object_add(data, "doh",
                           json_object_new_boolean(nc_dns_encrypted_capable_engine(NULL)));
    json_object_object_add(data, "dot",
                           json_object_new_boolean(nc_dns_encrypted_capable_engine(NULL)));
    json_object_object_add(data, "domain_forward", json_object_new_boolean(1));
    json_object_object_add(data, "domain_block", json_object_new_boolean(1));
    json_object_object_add(data, "upstream_rule", json_object_new_boolean(1));
    json_object_object_add(data, "domain_upstream", json_object_new_boolean(1));
    json_object_object_add(data, "multi_line_dns", json_object_new_boolean(1));
    json_object_object_add(data, "live_stats", json_object_new_boolean(0));

    /* ── UPnP ── */

    json_object_object_add(data, "natpmp", json_object_new_boolean(1));
    json_object_object_add(data, "natpmp_enabled", json_object_new_boolean(1));
    json_object_object_add(data, "secure_mode", json_object_new_boolean(1));
    json_object_object_add(data, "log_packets", json_object_new_boolean(1));
    json_object_object_add(data, "system_uptime", json_object_new_boolean(1));
    json_object_object_add(data, "use_stun", json_object_new_boolean(nc_upnp_runtime_capable()));
    json_object_object_add(data, "stun", json_object_new_boolean(nc_upnp_runtime_capable()));
    json_object_object_add(data, "pcp", json_object_new_boolean(nc_upnp_runtime_capable()));
    json_object_object_add(data, "mapping_delete", json_object_new_boolean(nc_upnp_nft_available()));
    json_object_object_add(data, "live_packets", json_object_new_boolean(0));
    json_object_object_add(data, "acl", json_object_new_boolean(1));

    /* ── Flow Control ── */

    json_object_object_add(data, "flow_control_engine", json_object_new_boolean(1));
    json_object_object_add(data, "qos", json_object_new_boolean(1));
    json_object_object_add(data, "scheduler", json_object_new_boolean(1));
    json_object_object_add(data, "classes", json_object_new_boolean(1));
    json_object_object_add(data, "groups", json_object_new_boolean(1));
    json_object_object_add(data, "rule_actions", json_object_new_boolean(1));
    json_object_object_add(data, "client_limits", json_object_new_boolean(1));
    json_object_object_add(data, "line_policy", json_object_new_boolean(1));
    json_object_object_add(data, "carrier_policy", json_object_new_boolean(1));
    json_object_object_add(data, "save_group_carrier", json_object_new_boolean(1));
    json_object_object_add(data, "export_wan_csv", json_object_new_boolean(1));
    json_object_object_add(data, "export_lan_csv", json_object_new_boolean(1));
    json_object_object_add(data, "dns_policy_integration", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_boolean(1));
    json_object_object_add(data, "rule_test", json_object_new_boolean(1));

    /* ── Advanced Routing ── */
    json_object_object_add(data, "advanced_routing", json_object_new_boolean(1));
    json_object_object_add(data, "static_routes", json_object_new_boolean(1));
    json_object_object_add(data, "route_objects", json_object_new_boolean(0));
    json_object_object_add(data, "cross_services", json_object_new_boolean(0));
    json_object_object_add(data, "policy_rules", json_object_new_boolean(1));
    json_object_object_add(data, "routing_tables", json_object_new_boolean(1));
    json_object_object_add(data, "rule_hits", json_object_new_boolean(0));
    json_object_object_add(data, "save_static_route", json_object_new_boolean(1));
    json_object_object_add(data, "delete_static_route", json_object_new_boolean(1));
    json_object_object_add(data, "save_route_object", json_object_new_boolean(0));
    json_object_object_add(data, "delete_route_object", json_object_new_boolean(0));
    json_object_object_add(data, "save_cross_service", json_object_new_boolean(0));
    json_object_object_add(data, "delete_cross_service", json_object_new_boolean(0));
    json_object_object_add(data, "save_policy_rule", json_object_new_boolean(1));
    json_object_object_add(data, "delete_policy_rule", json_object_new_boolean(1));
    json_object_object_add(data, "save_routing_table", json_object_new_boolean(1));
    json_object_object_add(data, "delete_routing_table", json_object_new_boolean(1));

    /* ── DNS rules ── */
    json_object_object_add(data, "dns_forward", json_object_new_boolean(1));
    json_object_object_add(data, "dns_forwarding", json_object_new_boolean(1));
    json_object_object_add(data, "conditional_forward", json_object_new_boolean(1));
    json_object_object_add(data, "conditional_forwarding", json_object_new_boolean(1));
    json_object_object_add(data, "domain_rules", json_object_new_boolean(1));
    json_object_object_add(data, "local_hosts", json_object_new_boolean(1));
    json_object_object_add(data, "dns_redirect", json_object_new_boolean(0));
    json_object_object_add(data, "ecs", json_object_new_boolean(0));
    json_object_object_add(data, "save_dns_rule", json_object_new_boolean(0));
    json_object_object_add(data, "delete_dns_rule", json_object_new_boolean(0));
    json_object_object_add(data, "dns_rules_bulk_update", json_object_new_boolean(1));
    json_object_object_add(data, "save_wan_dns_policy", json_object_new_boolean(1));

    /* ── UPnP mapping ── */
    /* STUN has no probe implementation and nc_upnp_disabled_field_changed()
     * actively rejects writes to these fields - report false, not true. */
    json_object_object_add(data, "stun_host", json_object_new_boolean(0));
    json_object_object_add(data, "stun_port", json_object_new_boolean(0));
    json_object_object_add(data, "mapping_create", json_object_new_boolean(nc_upnp_nft_available()));
    json_object_object_add(data, "mapping_update", json_object_new_boolean(nc_upnp_nft_available()));
    json_object_object_add(data, "save_upnp_mapping", json_object_new_boolean(nc_upnp_nft_available()));
    json_object_object_add(data, "delete_upnp_mapping", json_object_new_boolean(nc_upnp_nft_available()));

    /* ── Flow Control extras ── */
    json_object_object_add(data, "save_rule", json_object_new_boolean(1));
    json_object_object_add(data, "delete_rule", json_object_new_boolean(1));
    json_object_object_add(data, "save_global", json_object_new_boolean(1));

    /* ── AI ── */

    json_object_object_add(data, "ai_config", json_object_new_boolean(1));
    json_object_object_add(data, "ai_multi_provider", json_object_new_boolean(1));
    {
        struct json_object *strategies = json_object_new_array();
        json_object_array_add(strategies, json_object_new_string("single"));
        json_object_array_add(strategies, json_object_new_string("failover"));
        json_object_array_add(strategies, json_object_new_string("load_balance"));
        json_object_object_add(data, "ai_dispatch_strategies", strategies);
    }
    json_object_object_add(data, "model_list", json_object_new_boolean(1));
    json_object_object_add(data, "chat", json_object_new_boolean(1));
    json_object_object_add(data, "tool_call", json_object_new_boolean(1));
    json_object_object_add(data, "tool_authorization", json_object_new_boolean(1));
    json_object_object_add(data, "system_status_tool", json_object_new_boolean(1));
    json_object_object_add(data, "network_config_tool", json_object_new_boolean(1));
    json_object_object_add(data, "readonly_tools", json_object_new_boolean(1));
    json_object_object_add(data, "history", json_object_new_boolean(1));
    json_object_object_add(data, "history_persist", json_object_new_boolean(1));

    /* ── Plugins ── */
    json_object_object_add(data, "plugin_discovery", json_object_new_boolean(1));
    json_object_object_add(data, "plugin_luci_compat", json_object_new_boolean(1));
    json_object_object_add(data, "plugin_package_manage", json_object_new_boolean(1));
    json_object_object_add(data, "plugin_native_api", json_object_new_boolean(0));

    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}
struct json_object *jmx_netconfig_radius_list(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) goto done;
    if (nc_prepare(&st,
        "SELECT id,name,auth_addr,auth_port,accounting_addr,accounting_port,secret_ref,enabled "
        "FROM radius_server ORDER BY name,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *r = json_object_new_object();
            nc_add_text(r, "id", st, 0);
            nc_add_text(r, "name", st, 1);
            nc_add_text(r, "auth_addr", st, 2);
            json_object_object_add(r, "auth_port", json_object_new_int(sqlite3_column_int(st, 3)));
            nc_add_text(r, "accounting_addr", st, 4);
            json_object_object_add(r, "accounting_port", json_object_new_int(sqlite3_column_int(st, 5)));
            nc_add_text(r, "secret_ref", st, 6);
            json_object_object_add(r, "enabled", json_object_new_boolean(sqlite3_column_int(st, 7)));
            json_object_array_add(arr, r);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(data, "servers", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_netconfig_radius_set(struct json_object *radius_json)
{
    sqlite3_stmt *st = NULL;
    const char *id;
    if (!radius_json) return -1;
    id = nc_json_str(radius_json, "id", "");
    if (!id[0] || !nc_valid_name(id)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st,
        "INSERT INTO radius_server(id,name,auth_addr,auth_port,accounting_addr,accounting_port,secret_ref,enabled) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,auth_addr=excluded.auth_addr,auth_port=excluded.auth_port,"
        "accounting_addr=excluded.accounting_addr,accounting_port=excluded.accounting_port,secret_ref=excluded.secret_ref,enabled=excluded.enabled") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, nc_json_str(radius_json, "name", id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, nc_json_str(radius_json, "auth_addr", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, nc_json_int(radius_json, "auth_port", 1812));
        sqlite3_bind_text(st, 5, nc_json_str(radius_json, "accounting_addr", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, nc_json_int(radius_json, "accounting_port", 1813));
        sqlite3_bind_text(st, 7, nc_json_str(radius_json, "secret_ref", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 8, nc_json_bool(radius_json, "enabled", 1));
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

int jmx_netconfig_radius_delete(const char *id)
{
    sqlite3_stmt *st = NULL;
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "DELETE FROM radius_server WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    int rc = nc_step_done(st);
    sqlite3_finalize(st);
    return rc;
}
