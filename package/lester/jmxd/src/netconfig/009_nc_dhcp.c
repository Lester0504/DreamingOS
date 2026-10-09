/* ══════════════════════════════════════════════════════════════════════
 * DHCP Service: scopes/options/reservations/leases
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_split_pool(const char *pool, char *start, size_t start_len, char *end, size_t end_len)
{
    const char *dash;
    if (start && start_len) start[0] = '\0';
    if (end && end_len) end[0] = '\0';
    if (!pool) return;
    dash = strchr(pool, '-');
    if (!dash) { snprintf(start, start_len, "%s", pool); return; }
    snprintf(start, start_len, "%.*s", (int)(dash - pool), pool);
    snprintf(end, end_len, "%s", dash + 1);
}
static int nc_mac_normalize(const char *in, char *out, size_t out_len)
{
    int i;
    if (!in || strlen(in) != 17 || out_len < 18) return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) { if (in[i] != ':') return 0; out[i] = ':'; }
        else { if (!isxdigit((unsigned char)in[i])) return 0; out[i] = (char)tolower((unsigned char)in[i]); }
    }
    out[17] = '\0'; return 1;
}

int nc_ipv4_ok(const char *ip)
{
    struct in_addr a;
    return ip && ip[0] && inet_pton(AF_INET, ip, &a) == 1;
}

static int nc_ipv4_last_octet_int(const char *ip)
{
    const char *p = ip ? strrchr(ip, '.') : NULL;
    if (!p) return -1;
    return atoi(p + 1);
}

static int nc_ipv4_in_prefix(const char *ip, const char *net_ip, int prefix);
static uint32_t nc_ipv4_to_host_u32(const char *ip);

static int nc_dhcp_lan_primary(const char *lan_id, char *lan_ip, size_t lan_ip_len,
                               int *prefix_out)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (lan_ip && lan_ip_len)
        lan_ip[0] = '\0';
    if (prefix_out)
        *prefix_out = 24;
    if (!lan_id || !lan_id[0] || !nc_valid_name(lan_id))
        return 0;
    if (nc_prepare(&st,
        "SELECT COALESCE(la.ip,''),COALESCE(la.prefix,24) "
        "FROM lan l LEFT JOIN lan_address la ON la.lan_id=l.id AND la.is_primary=1 "
        "WHERE l.id=?1 LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *ip = (const char *)sqlite3_column_text(st, 0);
        int prefix = sqlite3_column_int(st, 1);

        found = 1;
        if (lan_ip && lan_ip_len && ip)
            snprintf(lan_ip, lan_ip_len, "%s", ip);
        if (prefix_out)
            *prefix_out = prefix;
    }
    sqlite3_finalize(st);
    return found;
}

static int nc_dhcp_expand_pool_address(const char *raw, const char *lan_ip,
                                       int prefix, char *out, size_t out_len)
{
    struct in_addr addr;
    uint32_t lan_host, mask, network, value;
    char *end = NULL;
    long offset;

    if (!raw || !raw[0] || !lan_ip || !nc_ipv4_ok(lan_ip) ||
        prefix < 1 || prefix > 30 || !out || out_len == 0)
        return -1;
    if (strchr(raw, '.')) {
        if (!nc_ipv4_ok(raw) || !nc_ipv4_in_prefix(raw, lan_ip, prefix))
            return -1;
        snprintf(out, out_len, "%s", raw);
        return 0;
    }
    errno = 0;
    offset = strtol(raw, &end, 10);
    if (errno || !end || *end || offset <= 0)
        return -1;
    inet_pton(AF_INET, lan_ip, &addr);
    lan_host = ntohl(addr.s_addr);
    mask = 0xffffffffU << (32 - prefix);
    network = lan_host & mask;
    if ((uint64_t)offset >= (1ULL << (32 - prefix)) - 1)
        return -1;
    value = network + (uint32_t)offset;
    addr.s_addr = htonl(value);
    if (!inet_ntop(AF_INET, &addr, out, out_len))
        return -1;
    return 0;
}

static int nc_dhcp_pool_offset(const char *full_ip, const char *lan_ip, int prefix)
{
    uint32_t ip_host, lan_host, mask;

    if (!nc_ipv4_ok(full_ip) || !nc_ipv4_ok(lan_ip) || prefix < 1 || prefix > 30)
        return -1;
    ip_host = nc_ipv4_to_host_u32(full_ip);
    lan_host = nc_ipv4_to_host_u32(lan_ip);
    mask = 0xffffffffU << (32 - prefix);
    if ((ip_host & mask) != (lan_host & mask))
        return -1;
    return (int)(ip_host - (lan_host & mask));
}

static struct json_object *nc_dhcp_text_array(const char *raw)
{
    struct json_object *arr = NULL;
    char buf[1024];
    char *save = NULL;
    char *token;

    if (raw && raw[0])
        arr = json_tokener_parse(raw);
    if (arr && json_object_is_type(arr, json_type_array))
        return arr;
    if (arr)
        json_object_put(arr);
    arr = json_object_new_array();
    if (!raw || !raw[0])
        return arr;
    snprintf(buf, sizeof(buf), "%s", raw);
    for (token = strtok_r(buf, ",; \t\r\n", &save); token;
         token = strtok_r(NULL, ",; \t\r\n", &save))
        if (token[0])
            json_object_array_add(arr, json_object_new_string(token));
    return arr;
}

static struct json_object *nc_dhcp_access_list_from_payload(struct json_object *dhcp)
{
    struct json_object *arr = NULL;
    struct json_object *lists = NULL;

    if (!dhcp || !json_object_is_type(dhcp, json_type_object))
        return NULL;
    if (json_object_object_get_ex(dhcp, "allow_deny_list", &arr) && arr)
        return arr;
    if (json_object_object_get_ex(dhcp, "access_list", &arr) && arr)
        return arr;
    if (json_object_object_get_ex(dhcp, "lists", &lists) && lists &&
        json_object_is_type(lists, json_type_object)) {
        if (json_object_object_get_ex(lists, "allow_deny", &arr) && arr)
            return arr;
        if (json_object_object_get_ex(lists, "allow_deny_list", &arr) && arr)
            return arr;
        if (json_object_object_get_ex(lists, "access", &arr) && arr)
            return arr;
    }
    return NULL;
}

static int nc_dhcp_json_int_field_ok(struct json_object *obj, const char *key,
                                     int def, int *out)
{
    struct json_object *v = NULL;
    enum json_type t;

    if (out)
        *out = def;
    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v)
        return 1;
    t = json_object_get_type(v);
    if (t != json_type_int && t != json_type_double)
        return 0;
    if (out)
        *out = json_object_get_int(v);
    return 1;
}

static int nc_dhcp_validate_access_list(struct json_object *arr, char *err, size_t err_len)
{
    int i, j, n;

    if (err && err_len)
        err[0] = '\0';
    if (!arr)
        return 0;
    if (!json_object_is_type(arr, json_type_array)) {
        snprintf(err, err_len, "access_list_must_be_array");
        return -1;
    }
    n = (int)json_object_array_length(arr);
    if (n > 1024) {
        snprintf(err, err_len, "access_list_too_large");
        return -1;
    }
    for (i = 0; i < n; i++) {
        struct json_object *entry = json_object_array_get_idx(arr, i);
        const char *id = nc_json_str_def(entry, "id", "");
        const char *action = nc_json_str_def(entry, "action", "");
        const char *mac = nc_json_str_def(entry, "mac", "");
        char macn[18];
        int sort_order = i * 10;

        if (!entry || !json_object_is_type(entry, json_type_object)) {
            snprintf(err, err_len, "access_entry_must_be_object");
            return -1;
        }
        if (id[0] && !nc_valid_name(id)) {
            snprintf(err, err_len, "invalid_access_id");
            return -1;
        }
        if (strcmp(action, "allow") && strcmp(action, "deny")) {
            snprintf(err, err_len, "invalid_access_action");
            return -1;
        }
        if (!nc_mac_normalize(mac, macn, sizeof(macn))) {
            snprintf(err, err_len, "invalid_access_mac");
            return -1;
        }
        if (!nc_dhcp_json_int_field_ok(entry, "sort_order", i * 10, &sort_order) ||
            sort_order < 0 || sort_order > 1000000) {
            snprintf(err, err_len, "invalid_access_sort_order");
            return -1;
        }
        for (j = i + 1; j < n; j++) {
            struct json_object *other = json_object_array_get_idx(arr, j);
            const char *mac2 = nc_json_str_def(other, "mac", "");
            char macn2[18];
            if (!nc_mac_normalize(mac2, macn2, sizeof(macn2))) {
                snprintf(err, err_len, "invalid_access_mac");
                return -1;
            }
            if (!strcasecmp(macn, macn2)) {
                snprintf(err, err_len, "duplicate_access_mac");
                return -1;
            }
        }
    }
    return 0;
}


static struct json_object *nc_dhcp_prefixes_from_payload(struct json_object *dhcp)
{
    struct json_object *arr = NULL;
    if (!dhcp || !json_object_is_type(dhcp, json_type_object))
        return NULL;
    if (json_object_object_get_ex(dhcp, "prefix_reservations", &arr) && arr)
        return arr;
    if (json_object_object_get_ex(dhcp, "prefixes", &arr) && arr)
        return arr;
    return NULL;
}

static int nc_hex_string_ok(const char *s, int allow_empty)
{
    size_t i, n;
    if (!s || !s[0]) return allow_empty;
    n = strlen(s);
    if (n > 64) return 0;
    for (i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static int nc_dhcp_duid_normalize(const char *raw, char *duid, size_t duid_len,
                                  char *iaid, size_t iaid_len)
{
    const char *pct;
    size_t i, n;
    if (duid && duid_len) duid[0] = '\0';
    if (iaid && iaid_len) iaid[0] = '\0';
    if (!raw || !raw[0] || !duid || duid_len < 3) return 0;
    pct = strchr(raw, '%');
    n = pct ? (size_t)(pct - raw) : strlen(raw);
    if (n == 0 || n >= duid_len || n > 256 || (n % 2) != 0) return 0;
    for (i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)raw[i])) return 0;
        duid[i] = (char)tolower((unsigned char)raw[i]);
    }
    duid[n] = '\0';
    if (pct) {
        const char *p = pct + 1;
        size_t m = strlen(p);
        if (!iaid || iaid_len == 0 || m == 0 || m >= iaid_len || m > 8)
            return 0;
        for (i = 0; i < m; i++) {
            if (!isxdigit((unsigned char)p[i])) return 0;
            iaid[i] = (char)tolower((unsigned char)p[i]);
        }
        iaid[m] = '\0';
    }
    return 1;
}

static int nc_ipv6_mask_host_zero(const struct in6_addr *addr, int prefix_len)
{
    int bit;
    const unsigned char *b = addr ? addr->s6_addr : NULL;
    if (!b || prefix_len < 0 || prefix_len > 128) return 0;
    for (bit = prefix_len; bit < 128; bit++)
        if (b[bit / 8] & (0x80 >> (bit % 8))) return 0;
    return 1;
}

static int nc_ipv6_prefix_contains(const struct in6_addr *parent, int parent_len,
                                   const struct in6_addr *child, int child_len)
{
    int bit;
    if (!parent || !child || parent_len < 0 || child_len < parent_len || child_len > 128)
        return 0;
    for (bit = 0; bit < parent_len; bit++) {
        int pb = !!(parent->s6_addr[bit / 8] & (0x80 >> (bit % 8)));
        int cb = !!(child->s6_addr[bit / 8] & (0x80 >> (bit % 8)));
        if (pb != cb) return 0;
    }
    return 1;
}

static int nc_ipv6_prefix_parse(const char *cidr, struct in6_addr *addr,
                                int *prefix_len, char *canon, size_t canon_len)
{
    char ip[INET6_ADDRSTRLEN + 1];
    char text[INET6_ADDRSTRLEN + 8];
    char *slash, *end = NULL;
    long plen;

    if (!cidr || !cidr[0] || !addr || !prefix_len) return 0;
    if (strlen(cidr) >= sizeof(text)) return 0;
    snprintf(text, sizeof(text), "%s", cidr);
    slash = strchr(text, '/');
    if (!slash || strchr(slash + 1, '/')) return 0;
    *slash++ = '\0';
    errno = 0;
    plen = strtol(slash, &end, 10);
    if (errno || !end || *end || plen < 33 || plen > 64) return 0;
    if (inet_pton(AF_INET6, text, addr) != 1) return 0;
    if (IN6_IS_ADDR_UNSPECIFIED(addr) || IN6_IS_ADDR_LOOPBACK(addr) ||
        IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MULTICAST(addr) ||
        (addr->s6_addr[0] & 0xfe) == 0xfc)
        return 0;
    if (!nc_ipv6_mask_host_zero(addr, (int)plen)) return 0;
    *prefix_len = (int)plen;
    if (canon && canon_len) {
        if (!inet_ntop(AF_INET6, addr, ip, sizeof(ip))) return 0;
        snprintf(canon, canon_len, "%s/%ld", ip, plen);
    }
    return 1;
}

static int nc_ipv6_prefix_high64(const struct in6_addr *addr, uint64_t *out)
{
    int i;
    uint64_t v = 0;
    if (!addr || !out) return 0;
    for (i = 0; i < 8; i++) v = (v << 8) | addr->s6_addr[i];
    *out = v;
    return 1;
}

/* Returns 1 for a matching parent, 0 when parents exist but none contains the
 * child, and -1 when the interface currently has no delegated parent. */
static int nc_dhcpv6_parent_prefix_for_child(const char *lan_id,
                                             const struct in6_addr *child,
                                             int child_len,
                                             struct in6_addr *parent,
                                             int *parent_len,
                                             char *canon, size_t canon_len)
{
    char cmd[256], line[16384];
    FILE *fp;
    struct json_object *root = NULL, *arr = NULL;
    int found = 0, have_parent = 0, best_len = -1;

    if (parent_len) *parent_len = 0;
    if (canon && canon_len) canon[0] = '\0';
    if (!lan_id || !nc_valid_name(lan_id) || !child || child_len < 33 ||
        child_len > 64 || !parent || !parent_len)
        return -1;
    snprintf(cmd, sizeof(cmd), "ubus -S call network.interface.%s status 2>/dev/null", lan_id);
    fp = popen(cmd, "r");
    if (!fp) return 0;
    if (fgets(line, sizeof(line), fp)) {
        root = json_tokener_parse(line);
        if (root && json_object_object_get_ex(root, "ipv6-prefix-assignment", &arr) && arr &&
            json_object_is_type(arr, json_type_array) && json_object_array_length(arr) > 0) {
            int i, n = (int)json_object_array_length(arr);
            for (i = 0; i < n; i++) {
                struct json_object *o = json_object_array_get_idx(arr, i);
                const char *addr = nc_json_str_def(o, "address", "");
                int mask = nc_json_int_def(o, "mask", 0);
                struct in6_addr candidate;
                char cidr[128], candidate_canon[128];
                int candidate_len = 0;

                if (!addr[0] || mask < 1 || mask >= child_len || mask > 64)
                    continue;
                snprintf(cidr, sizeof(cidr), "%s/%d", addr, mask);
                if (!nc_ipv6_prefix_parse(cidr, &candidate, &candidate_len,
                                          candidate_canon, sizeof(candidate_canon)))
                    continue;
                have_parent = 1;
                if (candidate_len <= best_len ||
                    !nc_ipv6_prefix_contains(&candidate, candidate_len, child, child_len))
                    continue;
                *parent = candidate;
                *parent_len = candidate_len;
                best_len = candidate_len;
                found = 1;
                if (canon && canon_len)
                    snprintf(canon, canon_len, "%s", candidate_canon);
            }
        }
    }
    pclose(fp);
    if (root) json_object_put(root);
    return found ? 1 : (have_parent ? 0 : -1);
}

static int nc_dhcpv6_derive_hostid(const struct in6_addr *prefix_addr, int prefix_len,
                                   const struct in6_addr *parent_addr, int parent_len,
                                   char *hostid, size_t hostid_len)
{
    uint64_t ph = 0, parent_high = 0;
    int slot_bits;
    uint64_t subnet;
    if (!prefix_addr || !parent_addr || !hostid || hostid_len == 0)
        return 0;
    if (parent_len <= 32 || prefix_len <= parent_len || prefix_len > 64)
        return 0;
    slot_bits = 64 - parent_len;
    if (slot_bits <= 0 || slot_bits > 31) return 0;
    if (!nc_ipv6_prefix_high64(prefix_addr, &ph) ||
        !nc_ipv6_prefix_high64(parent_addr, &parent_high)) return 0;
    subnet = (ph ^ parent_high) & ((1ULL << slot_bits) - 1ULL);
    if (subnet & ((1ULL << (64 - prefix_len)) - 1ULL)) return 0;
    if (subnet == 0) return 0;
    snprintf(hostid, hostid_len, "%llx", (unsigned long long)subnet);
    return 1;
}

static int nc_hostid_numeric_eq(const char *a, const char *b)
{
    unsigned long long av, bv;
    char *end = NULL;
    if (!a || !b || !nc_hex_string_ok(a, 0) || !nc_hex_string_ok(b, 0)) return 0;
    errno = 0; av = strtoull(a, &end, 16); if (errno || !end || *end) return 0;
    errno = 0; bv = strtoull(b, &end, 16); if (errno || !end || *end) return 0;
    return av == bv;
}

static void nc_dhcpv6_prefix_id_make(const char *scope_id, const char *duid,
                                     const char *hostid, char *out, size_t out_len)
{
    char d[17] = "";
    size_t i, j = 0;
    if (!out || out_len == 0) return;
    if (duid) for (i = 0; duid[i] && j + 1 < sizeof(d); i++)
        if (isxdigit((unsigned char)duid[i])) d[j++] = (char)tolower((unsigned char)duid[i]);
    d[j] = '\0';
    snprintf(out, out_len, "%s_pd_%s_%s", scope_id && scope_id[0] ? scope_id : "scope",
             d[0] ? d : "duid", hostid && hostid[0] ? hostid : "prefix");
}

static int nc_dhcp_validate_prefix_reservations(const char *lan_id, struct json_object *arr,
                                                char *err, size_t err_len)
{
    struct in6_addr parent_addr;
    int parent_state = -1, parent_len = 0;
    char parent_cidr[128] = "";
    int i, j, n;

    if (err && err_len) err[0] = '\0';
    if (!arr) return 0;
    if (!json_object_is_type(arr, json_type_array)) {
        snprintf(err, err_len, "prefix_reservations_must_be_array");
        return -1;
    }
    if (!lan_id || !lan_id[0] || !nc_valid_name(lan_id)) {
        snprintf(err, err_len, "invalid_prefix_lan");
        return -1;
    }
    n = (int)json_object_array_length(arr);
    if (n > 512) {
        snprintf(err, err_len, "prefix_reservations_too_large");
        return -1;
    }
    for (i = 0; i < n; i++) {
        struct json_object *entry = json_object_array_get_idx(arr, i);
        const char *id = nc_json_str_def(entry, "id", "");
        const char *raw_duid = nc_json_str_def(entry, "duid", "");
        const char *raw_prefix = nc_json_str_def(entry, "prefix", "");
        const char *raw_hostid = nc_json_str_def(entry, "hostid", "");
        char duid[300], iaid[16], canon[128], derived[32] = "";
        struct in6_addr prefix_addr;
        int prefix_len = 0, payload_prefix_len = 0;

        if (!entry || !json_object_is_type(entry, json_type_object)) {
            snprintf(err, err_len, "prefix_entry_must_be_object"); return -1;
        }
        if (id[0] && !nc_valid_name(id)) {
            snprintf(err, err_len, "invalid_prefix_id"); return -1;
        }
        if (!nc_dhcp_duid_normalize(raw_duid, duid, sizeof(duid), iaid, sizeof(iaid))) {
            snprintf(err, err_len, "invalid_prefix_duid"); return -1;
        }
        if (!nc_ipv6_prefix_parse(raw_prefix, &prefix_addr, &prefix_len, canon, sizeof(canon))) {
            snprintf(err, err_len, "invalid_prefix_cidr"); return -1;
        }
        payload_prefix_len = nc_json_int_def(entry, "prefix_len", prefix_len);
        if (payload_prefix_len != prefix_len || payload_prefix_len < 33 || payload_prefix_len > 64) {
            snprintf(err, err_len, "invalid_prefix_len"); return -1;
        }
        parent_state = nc_dhcpv6_parent_prefix_for_child(lan_id, &prefix_addr, prefix_len,
                                                         &parent_addr, &parent_len,
                                                         parent_cidr, sizeof(parent_cidr));
        if (parent_state > 0) {
            if (parent_len >= prefix_len || !nc_ipv6_prefix_contains(&parent_addr, parent_len, &prefix_addr, prefix_len)) {
                snprintf(err, err_len, "prefix_outside_lan_parent"); return -1;
            }
            if (!nc_dhcpv6_derive_hostid(&prefix_addr, prefix_len, &parent_addr, parent_len,
                                         derived, sizeof(derived))) {
                snprintf(err, err_len, "invalid_prefix_hostid_zero"); return -1;
            }
            if (raw_hostid[0] && (!nc_hex_string_ok(raw_hostid, 0) || !nc_hostid_numeric_eq(raw_hostid, derived))) {
                snprintf(err, err_len, "prefix_hostid_mismatch"); return -1;
            }
        } else if (parent_state < 0) {
            if (!raw_hostid[0] || !nc_hex_string_ok(raw_hostid, 0)) {
                snprintf(err, err_len, "prefix_hostid_required_without_parent"); return -1;
            }
            if (strtoull(raw_hostid, NULL, 16) == 0) {
                snprintf(err, err_len, "invalid_prefix_hostid_zero"); return -1;
            }
        } else { snprintf(err, err_len, "prefix_outside_lan_parent"); return -1; }
        for (j = i + 1; j < n; j++) {
            struct json_object *other = json_object_array_get_idx(arr, j);
            char duid2[300], iaid2[16], canon2[128];
            struct in6_addr tmp_addr;
            int tmp_len;
            if (!nc_dhcp_duid_normalize(nc_json_str_def(other, "duid", ""), duid2, sizeof(duid2), iaid2, sizeof(iaid2))) {
                snprintf(err, err_len, "invalid_prefix_duid"); return -1;
            }
            if (!strcasecmp(duid, duid2)) { snprintf(err, err_len, "duplicate_prefix_duid"); return -1; }
            if (!nc_ipv6_prefix_parse(nc_json_str_def(other, "prefix", ""), &tmp_addr, &tmp_len, canon2, sizeof(canon2))) {
                snprintf(err, err_len, "invalid_prefix_cidr"); return -1;
            }
            if (!strcmp(canon, canon2)) { snprintf(err, err_len, "duplicate_prefix_cidr"); return -1; }
            if (id[0] && !strcmp(id, nc_json_str_def(other, "id", ""))) { snprintf(err, err_len, "duplicate_prefix_id"); return -1; }
        }
    }
    return 0;
}

static void nc_dhcp_access_id_make(const char *scope_id, const char *action,
                                   const char *mac, char *out, size_t out_len)
{
    char m[18];
    char compact[13];
    int i, j = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!nc_mac_normalize(mac, m, sizeof(m))) {
        snprintf(out, out_len, "%s_%s", scope_id ? scope_id : "scope", action ? action : "entry");
        return;
    }
    for (i = 0; m[i] && j < (int)sizeof(compact) - 1; i++)
        if (m[i] != ':')
            compact[j++] = m[i];
    compact[j] = '\0';
    snprintf(out, out_len, "%s_%s_%s", scope_id ? scope_id : "scope",
             action ? action : "entry", compact);
}

static int nc_dhcp_validate_scope(const char *lan_id, const char *pool_start, const char *pool_end,
                                  struct json_object *reservations, char *err, size_t err_len)
{
    int ps, pe, i, j, n, prefix = 24;
    char lan_ip[64] = "";
    char full_start[64] = "";
    char full_end[64] = "";
    if (err && err_len) err[0] = '\0';
    if (!pool_start || !pool_start[0] || !pool_end || !pool_end[0]) { snprintf(err, err_len, "pool_required"); return -1; }
    if (!nc_dhcp_lan_primary(lan_id, lan_ip, sizeof(lan_ip), &prefix)) { snprintf(err, err_len, "lan_not_found"); return -1; }
    if (!lan_ip[0] || !nc_ipv4_ok(lan_ip)) { snprintf(err, err_len, "lan_primary_ipv4_required"); return -1; }
    if (nc_dhcp_expand_pool_address(pool_start, lan_ip, prefix, full_start, sizeof(full_start)) != 0) { snprintf(err, err_len, "invalid_pool_start"); return -1; }
    if (nc_dhcp_expand_pool_address(pool_end, lan_ip, prefix, full_end, sizeof(full_end)) != 0) { snprintf(err, err_len, "invalid_pool_end"); return -1; }
    ps = nc_dhcp_pool_offset(full_start, lan_ip, prefix);
    pe = nc_dhcp_pool_offset(full_end, lan_ip, prefix);
    if (ps < 1 || pe < 1 || ps > pe) { snprintf(err, err_len, "invalid_pool_range"); return -1; }
    if (!reservations || !json_object_is_type(reservations, json_type_array)) return 0;
    n = (int)json_object_array_length(reservations);
    for (i = 0; i < n; i++) {
        struct json_object *ri = json_object_array_get_idx(reservations, i);
        const char *mac_i = nc_json_str_def(ri, "mac", "");
        const char *ip_i = nc_json_str_def(ri, "ip", "");
        char macn_i[18];
        if (!nc_mac_normalize(mac_i, macn_i, sizeof(macn_i))) { snprintf(err, err_len, "invalid_reservation_mac"); return -1; }
        if (!nc_ipv4_ok(ip_i)) { snprintf(err, err_len, "invalid_reservation_ip"); return -1; }
        if (!nc_ipv4_in_prefix(ip_i, lan_ip, prefix)) { snprintf(err, err_len, "reservation_ip_outside_lan"); return -1; }
        for (j = i + 1; j < n; j++) {
            struct json_object *rj = json_object_array_get_idx(reservations, j);
            const char *mac_j = nc_json_str_def(rj, "mac", "");
            const char *ip_j = nc_json_str_def(rj, "ip", "");
            char macn_j[18];
            if (!nc_mac_normalize(mac_j, macn_j, sizeof(macn_j))) { snprintf(err, err_len, "invalid_reservation_mac"); return -1; }
            if (!strcasecmp(macn_i, macn_j)) { snprintf(err, err_len, "duplicate_reservation_mac"); return -1; }
            if (ip_i && ip_j && !strcmp(ip_i, ip_j)) { snprintf(err, err_len, "duplicate_reservation_ip"); return -1; }
        }
    }
    return 0;
}
static uint32_t nc_ipv4_to_host_u32(const char *ip)
{
    struct in_addr a;
    if (!ip || inet_pton(AF_INET, ip, &a) != 1) return 0;
    return ntohl(a.s_addr);
}

static int nc_ipv4_in_prefix(const char *ip, const char *net_ip, int prefix)
{
    uint32_t a, n, mask;
    if (prefix < 0 || prefix > 32) return 0;
    a = nc_ipv4_to_host_u32(ip); n = nc_ipv4_to_host_u32(net_ip);
    if (!a || !n) return 0;
    mask = prefix == 0 ? 0 : (0xffffffffU << (32 - prefix));
    return (a & mask) == (n & mask);
}

static void nc_dhcp_find_scope_for_ip(const char *ip, char *scope, size_t scope_len)
{
    sqlite3_stmt *st = NULL;
    int oct = nc_ipv4_last_octet_int(ip);
    if (scope && scope_len) scope[0] = '\0';
    if (!nc_ipv4_ok(ip) || oct < 0 || !scope || !scope_len) return;
    /* Prefer exact LAN CIDR + pool match; fall back to pool-only for old records with no lan_address. */
    if (nc_prepare(&st, "SELECT ds.id,ds.pool_start,ds.pool_end,la.ip,la.prefix FROM dhcp_scope ds LEFT JOIN lan_address la ON la.lan_id=ds.lan_id AND la.is_primary=1 ORDER BY ds.id") == 0) {
        const char *fallback = NULL;
        char fallback_buf[64] = {0};
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *id = (const char *)sqlite3_column_text(st, 0);
            const char *ps = (const char *)sqlite3_column_text(st, 1);
            const char *pe = (const char *)sqlite3_column_text(st, 2);
            const char *lan_ip = (const char *)sqlite3_column_text(st, 3);
            int prefix = sqlite3_column_int(st, 4);
            int s = nc_ipv4_last_octet_int(ps), e = nc_ipv4_last_octet_int(pe);
            int pool_hit = (id && s >= 0 && e >= s && oct >= s && oct <= e);
            if (!pool_hit) continue;
            if (!fallback) { snprintf(fallback_buf, sizeof(fallback_buf), "%s", id); fallback = fallback_buf; }
            if (lan_ip && lan_ip[0] && nc_ipv4_in_prefix(ip, lan_ip, prefix)) { snprintf(scope, scope_len, "%s", id); break; }
        }
        if (!scope[0] && fallback) snprintf(scope, scope_len, "%s", fallback);
        sqlite3_finalize(st);
    }
}

void nc_dhcp_refresh_leases(void)
{
    FILE *fp;
    char line[512];
    int64_t now = nc_now_s();
    if (jmx_netconfig_db_init() != 0) return;
    fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp) fp = fopen("/var/dhcp.leases", "r");
    if (!fp) return;
    /* Cache refresh: if the write lock is held, skip this pass instead of
     * writing every row in autocommit mode. The next refresh will retry. */
    if (nc_txn_begin() != 0) { fclose(fp); return; }
    while (fgets(line, sizeof(line), fp)) {
        char mac[32], ip[64], host[128], clientid[128];
        long long exp = 0;
        sqlite3_stmt *st = NULL;
        if (sscanf(line, "%lld %31s %63s %127s %127s", &exp, mac, ip, host, clientid) < 4) continue;
        if (!nc_ipv4_ok(ip)) continue;
        if (strcmp(host, "*") == 0) host[0] = '\0';
        { char scope[64] = {0}; nc_dhcp_find_scope_for_ip(ip, scope, sizeof(scope));
        if (nc_prepare(&st, "INSERT INTO dhcp_lease_cache(mac,scope_id,hostname,ip,expires_at,online,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(mac) DO UPDATE SET scope_id=excluded.scope_id,hostname=excluded.hostname,ip=excluded.ip,expires_at=excluded.expires_at,online=excluded.online,updated_at=excluded.updated_at") == 0) {
            sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, scope, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, host, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 5, exp);
            sqlite3_bind_int(st, 6, exp == 0 || exp > now);
            sqlite3_bind_int64(st, 7, now);
            nc_step_done(st); sqlite3_finalize(st);
        }}
    }
    fclose(fp);
    nc_exec("COMMIT");
}

static const char *nc_ip_last_octet(const char *ip)
{
    const char *p = ip ? strrchr(ip, '.') : NULL;
    return p ? p + 1 : (ip ? ip : "");
}

static void nc_dhcp_parse_options_to_dns(const char *opts_json, char *dns1, size_t dns1_len, char *dns2, size_t dns2_len)
{
    struct json_object *arr = opts_json ? json_tokener_parse(opts_json) : NULL;
    int i, n;
    if (dns1 && dns1_len) dns1[0] = '\0'; if (dns2 && dns2_len) dns2[0] = '\0';
    if (!arr || !json_object_is_type(arr, json_type_array)) { if (arr) json_object_put(arr); return; }
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        const char *o = json_object_get_string(json_object_array_get_idx(arr, i));
        if (o && !strncmp(o, "6,", 2)) {
            char tmp[256], *save = NULL, *tok;
            snprintf(tmp, sizeof(tmp), "%s", o + 2);
            tok = strtok_r(tmp, ",", &save); if (tok) snprintf(dns1, dns1_len, "%s", tok);
            tok = strtok_r(NULL, ",", &save); if (tok) snprintf(dns2, dns2_len, "%s", tok);
            break;
        }
    }
    json_object_put(arr);
}

/* Read the persisted rogue-DHCP-detection preference from network_global. */
static int nc_rogue_dhcp_pref(void)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (nc_prepare(&st, "SELECT rogue_dhcp_detection FROM network_global WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW)
            enabled = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return enabled ? 1 : 0;
}

/*
 * Build the passive rogue-DHCP observation report.
 *
 * The detector is a read-only LAN observer: every BOOTREPLY seen coming from
 * UDP/67 is attributed to its L2 source, and any server IP that is not one of
 * this router's own addresses is reported as unauthorized. No packet is ever
 * injected and no client is disturbed, so this stays safe on a live gateway.
 */
static struct json_object *nc_rogue_dhcp_report(int *rogue_count_out)
{
    dhcp_server_obs_t obs[32];
    struct json_object *report = json_object_new_object();
    struct json_object *servers = json_object_new_array();
    int n, i, rogue = 0, authorized = 0;
    int active = dhcp_sniff_active();

    n = active ? dhcp_sniff_servers_snapshot(obs, (int)(sizeof(obs) / sizeof(obs[0]))) : 0;
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_new_object();
        char macbuf[18], ipbuf[INET_ADDRSTRLEN] = "", offbuf[INET_ADDRSTRLEN] = "";
        struct in_addr a;

        snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 obs[i].mac[0], obs[i].mac[1], obs[i].mac[2],
                 obs[i].mac[3], obs[i].mac[4], obs[i].mac[5]);
        a.s_addr = obs[i].server_ip;
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        a.s_addr = obs[i].offered_ip;
        inet_ntop(AF_INET, &a, offbuf, sizeof(offbuf));

        json_object_object_add(item, "mac", json_object_new_string(macbuf));
        json_object_object_add(item, "server_ip", json_object_new_string(ipbuf));
        json_object_object_add(item, "offered_ip", json_object_new_string(offbuf));
        json_object_object_add(item, "first_seen", json_object_new_int64((int64_t)obs[i].first_seen));
        json_object_object_add(item, "last_seen", json_object_new_int64((int64_t)obs[i].last_seen));
        json_object_object_add(item, "hits", json_object_new_int64((int64_t)obs[i].hits));
        json_object_object_add(item, "authorized", json_object_new_boolean(obs[i].authorized));
        json_object_object_add(item, "rogue", json_object_new_boolean(!obs[i].authorized));
        json_object_object_add(item, "local_origin", json_object_new_boolean(obs[i].local_origin));
        json_object_array_add(servers, item);
        if (obs[i].authorized) authorized++; else rogue++;
    }

    json_object_object_add(report, "detector_active", json_object_new_boolean(active));
    json_object_object_add(report, "servers", servers);
    json_object_object_add(report, "server_count", json_object_new_int(n));
    json_object_object_add(report, "rogue_count", json_object_new_int(rogue));
    json_object_object_add(report, "authorized_count", json_object_new_int(authorized));
    /*
     * Scope note for the UI: the AF_PACKET/ETH_P_IP tap only receives frames
     * the bridge delivers *inbound*, so replies this router emits itself are
     * not part of the sample. An empty list therefore means "no foreign DHCP
     * server answered on the LAN", not "our own DHCP server is down".
     */
    json_object_object_add(report, "observation_scope",
                           json_object_new_string("br-lan_inbound_bootreply_udp67"));
    json_object_object_add(report, "local_server_replies_observed", json_object_new_boolean(0));
    json_object_object_add(report, "scope_note",
                           json_object_new_string("inbound_only_local_dnsmasq_offers_not_sampled"));
    if (!active)
        json_object_object_add(report, "reason",
                               json_object_new_string("dhcp_passive_observer_not_running"));
    if (rogue_count_out) *rogue_count_out = rogue;
    return report;
}

struct json_object *jmx_dhcp_service_get(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *scopes = json_object_new_array();
    struct json_object *whitelist = json_object_new_array();
    struct json_object *blacklist = json_object_new_array();
    sqlite3_stmt *st = NULL;
    char selected[128] = "";
    if (jmx_netconfig_db_init() != 0) goto done;
    nc_dhcp_refresh_leases();
    if (nc_prepare(&st, "SELECT id FROM lan ORDER BY id LIMIT 1") == 0) { if (sqlite3_step(st) == SQLITE_ROW) snprintf(selected, sizeof(selected), "%s", (const char *)sqlite3_column_text(st, 0)); sqlite3_finalize(st); }
    if (nc_prepare(&st, "SELECT l.id,l.name,l.note,l.device,COALESCE(ds.enabled,ld.enabled,1),COALESCE(ds.pool_start,ld.pool_start,''),COALESCE(ds.pool_end,ld.pool_end,''),COALESCE(ds.exclude_pool,ld.exclude_pool_json,''),COALESCE(ds.gateway,ld.gateway,''),COALESCE(ds.netmask,''),COALESCE(ds.dns1,''),COALESCE(ds.dns2,''),COALESCE(ds.lease_minutes,ld.lease_minutes,120),COALESCE(ds.domain,''),COALESCE(ds.id,l.id),COALESCE(ld.dns_json,'[]') FROM lan l LEFT JOIN lan_dhcp ld ON ld.lan_id=l.id LEFT JOIN dhcp_scope ds ON ds.lan_id=l.id ORDER BY l.id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *s = json_object_new_object(), *opts = json_object_new_array(), *res = json_object_new_array(), *leases = json_object_new_array();
            char lan_id[128] = "", scope_id[128] = "";
            const char *ps = (const char *)sqlite3_column_text(st, 5); const char *pe = (const char *)sqlite3_column_text(st, 6); char pool[160] = ""; char full_start[64] = ""; char full_end[64] = ""; char lan_ip[64] = ""; int lan_prefix = 24;
            snprintf(lan_id, sizeof(lan_id), "%s", (const char *)sqlite3_column_text(st, 0));
            snprintf(scope_id, sizeof(scope_id), "%s", (const char *)sqlite3_column_text(st, 14));
            char dns1[64], dns2[64]; snprintf(dns1,sizeof(dns1),"%s",(const char*)sqlite3_column_text(st,10)); snprintf(dns2,sizeof(dns2),"%s",(const char*)sqlite3_column_text(st,11));
            struct json_object *base = nc_dhcp_base_get(lan_id);
            if (base) {
                snprintf(dns1, sizeof(dns1), "%s", nc_json_str_def(base, "dns1", ""));
                snprintf(dns2, sizeof(dns2), "%s", nc_json_str_def(base, "dns2", ""));
                json_object_put(base);
            }
            nc_dhcp_lan_primary(lan_id, lan_ip, sizeof(lan_ip), &lan_prefix);
            if (ps && ps[0]) nc_dhcp_expand_pool_address(ps, lan_ip, lan_prefix, full_start, sizeof(full_start));
            if (pe && pe[0]) nc_dhcp_expand_pool_address(pe, lan_ip, lan_prefix, full_end, sizeof(full_end));
            if (full_start[0] && full_end[0]) snprintf(pool, sizeof(pool), "%s-%s", full_start, full_end);
            nc_add_text(s,"id",st,14); nc_add_text(s,"lan_id",st,0); nc_add_text(s,"name",st,1); nc_add_text(s,"note",st,2);
            json_object_object_add(s,"enabled",json_object_new_boolean(sqlite3_column_int(st,4))); nc_add_text(s,"interface",st,3);
            nc_add_text(s,"gateway",st,8); nc_add_text(s,"netmask",st,9); json_object_object_add(s,"pool",json_object_new_string(pool)); json_object_object_add(s,"pool_start",json_object_new_string(full_start)); json_object_object_add(s,"pool_end",json_object_new_string(full_end)); json_object_object_add(s,"exclude_pool",nc_dhcp_text_array((const char*)sqlite3_column_text(st,7)));
            json_object_object_add(s,"dns1",json_object_new_string(dns1)); json_object_object_add(s,"dns2",json_object_new_string(dns2));
            json_object_object_add(s,"lease",json_object_new_int(sqlite3_column_int(st,12))); nc_add_text(s,"domain",st,13);
            { sqlite3_stmt *st2=NULL; if(nc_prepare(&st2,"SELECT code,value FROM dhcp_option WHERE scope_id=?1 ORDER BY sort_order,id")==0){sqlite3_bind_text(st2,1,scope_id,-1,SQLITE_TRANSIENT); while(sqlite3_step(st2)==SQLITE_ROW){char o[256]; snprintf(o,sizeof(o),"%s,%s",(const char*)sqlite3_column_text(st2,0),(const char*)sqlite3_column_text(st2,1)); json_object_array_add(opts,json_object_new_string(o));} sqlite3_finalize(st2);} }
            { sqlite3_stmt *st2=NULL; if(nc_prepare(&st2,"SELECT id,name,mac,ip,remark FROM dhcp_reservation WHERE scope_id=?1 AND enabled=1 ORDER BY id")==0){sqlite3_bind_text(st2,1,scope_id,-1,SQLITE_TRANSIENT); while(sqlite3_step(st2)==SQLITE_ROW){struct json_object *r=json_object_new_object(); nc_add_text(r,"id",st2,0); nc_add_text(r,"name",st2,1); nc_add_text(r,"mac",st2,2); nc_add_text(r,"ip",st2,3); nc_add_text(r,"remark",st2,4); json_object_array_add(res,r);} sqlite3_finalize(st2);} }
            { struct json_object *access=json_object_new_array(); sqlite3_stmt *st2=NULL; if(nc_prepare(&st2,"SELECT id,action,mac,name,remark,enabled,sort_order FROM dhcp_access_entry WHERE scope_id=?1 ORDER BY sort_order,id")==0){sqlite3_bind_text(st2,1,scope_id,-1,SQLITE_TRANSIENT); while(sqlite3_step(st2)==SQLITE_ROW){struct json_object *a=json_object_new_object(); nc_add_text(a,"id",st2,0); nc_add_text(a,"action",st2,1); nc_add_text(a,"mac",st2,2); nc_add_text(a,"name",st2,3); nc_add_text(a,"remark",st2,4); json_object_object_add(a,"enabled",json_object_new_boolean(sqlite3_column_int(st2,5))); json_object_object_add(a,"sort_order",json_object_new_int(sqlite3_column_int(st2,6))); json_object_array_add(access,a);} sqlite3_finalize(st2);} json_object_object_add(s,"allow_deny_list",access); }
            { struct json_object *pfx=json_object_new_array(); sqlite3_stmt *st2=NULL; if(nc_prepare(&st2,"SELECT id,name,duid,iaid,prefix,scope_id,lan_id,hostid,prefix_len,remark,enabled,lease_minutes,sort_order,apply_state,runtime_configured,runtime_bound,runtime_prefix,runtime_duid,last_apply_at FROM dhcpv6_prefix_reservation WHERE scope_id=?1 ORDER BY sort_order,id")==0){sqlite3_bind_text(st2,1,scope_id,-1,SQLITE_TRANSIENT); while(sqlite3_step(st2)==SQLITE_ROW){struct json_object *p=json_object_new_object(); nc_add_text(p,"id",st2,0); nc_add_text(p,"name",st2,1); nc_add_text(p,"duid",st2,2); nc_add_text(p,"iaid",st2,3); nc_add_text(p,"prefix",st2,4); nc_add_text(p,"scope",st2,5); nc_add_text(p,"scope_id",st2,5); nc_add_text(p,"lan_id",st2,6); nc_add_text(p,"hostid",st2,7); json_object_object_add(p,"prefix_len",json_object_new_int(sqlite3_column_int(st2,8))); nc_add_text(p,"remark",st2,9); json_object_object_add(p,"enabled",json_object_new_boolean(sqlite3_column_int(st2,10))); json_object_object_add(p,"lease_minutes",json_object_new_int(sqlite3_column_int(st2,11))); json_object_object_add(p,"sort_order",json_object_new_int(sqlite3_column_int(st2,12))); nc_add_text(p,"apply_state",st2,13); json_object_object_add(p,"runtime_configured",json_object_new_boolean(sqlite3_column_int(st2,14))); json_object_object_add(p,"runtime_bound",json_object_new_boolean(sqlite3_column_int(st2,15))); nc_add_text(p,"runtime_prefix",st2,16); nc_add_text(p,"runtime_duid",st2,17); json_object_object_add(p,"last_apply_at",json_object_new_int64(sqlite3_column_int64(st2,18))); json_object_array_add(pfx,p);} sqlite3_finalize(st2);} json_object_object_add(s,"prefix_reservations",pfx); json_object_object_add(s,"prefixes",json_object_get(pfx)); }
            { sqlite3_stmt *st2=NULL; if(nc_prepare(&st2,"SELECT hostname,mac,ip,expires_at,online FROM dhcp_lease_cache WHERE scope_id=?1 ORDER BY updated_at DESC")==0){sqlite3_bind_text(st2,1,scope_id,-1,SQLITE_TRANSIENT); while(sqlite3_step(st2)==SQLITE_ROW){struct json_object *l=json_object_new_object(); nc_add_text(l,"hostname",st2,0); nc_add_text(l,"mac",st2,1); nc_add_text(l,"ip",st2,2); json_object_object_add(l,"expires",json_object_new_int64(sqlite3_column_int64(st2,3))); json_object_object_add(l,"online",json_object_new_boolean(sqlite3_column_int(st2,4))); json_object_array_add(leases,l);} sqlite3_finalize(st2);} }
            json_object_object_add(s,"options",opts); json_object_object_add(s,"reservations",res); json_object_object_add(s,"leases",leases); json_object_array_add(scopes,s);
        }
        sqlite3_finalize(st);
    }
done:
    if (g_netconfig_db && nc_prepare(&st,
        "SELECT ae.id,ae.action,ae.mac,ae.name,ae.remark,ae.enabled,ae.sort_order,"
        "ae.scope_id,COALESCE(ds.lan_id,'') FROM dhcp_access_entry ae "
        "LEFT JOIN dhcp_scope ds ON ds.id=ae.scope_id ORDER BY ae.sort_order,ae.id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *item = json_object_new_object();
            const char *action = (const char *)sqlite3_column_text(st, 1);
            nc_add_text(item,"id",st,0); nc_add_text(item,"action",st,1);
            nc_add_text(item,"mac",st,2); nc_add_text(item,"name",st,3);
            nc_add_text(item,"hostname",st,3); nc_add_text(item,"remark",st,4);
            nc_add_text(item,"note",st,4); json_object_object_add(item,"enabled",json_object_new_boolean(sqlite3_column_int(st,5)));
            json_object_object_add(item,"sort_order",json_object_new_int(sqlite3_column_int(st,6)));
            nc_add_text(item,"scope",st,7); nc_add_text(item,"scope_id",st,7); nc_add_text(item,"lan_id",st,8);
            json_object_array_add(action && !strcmp(action,"allow") ? whitelist : blacklist, item);
        }
        sqlite3_finalize(st); st = NULL;
    }
    { struct json_object *top_pfx=json_object_new_array(); sqlite3_stmt *stp=NULL; if(g_netconfig_db && nc_prepare(&stp,"SELECT id,name,duid,iaid,prefix,scope_id,lan_id,hostid,prefix_len,remark,enabled,lease_minutes,sort_order,apply_state,runtime_configured,runtime_bound,runtime_prefix,runtime_duid,last_apply_at FROM dhcpv6_prefix_reservation ORDER BY sort_order,id")==0){while(sqlite3_step(stp)==SQLITE_ROW){struct json_object *p=json_object_new_object(); nc_add_text(p,"id",stp,0); nc_add_text(p,"name",stp,1); nc_add_text(p,"duid",stp,2); nc_add_text(p,"iaid",stp,3); nc_add_text(p,"prefix",stp,4); nc_add_text(p,"scope",stp,5); nc_add_text(p,"scope_id",stp,5); nc_add_text(p,"lan_id",stp,6); nc_add_text(p,"hostid",stp,7); json_object_object_add(p,"prefix_len",json_object_new_int(sqlite3_column_int(stp,8))); nc_add_text(p,"remark",stp,9); json_object_object_add(p,"enabled",json_object_new_boolean(sqlite3_column_int(stp,10))); json_object_object_add(p,"lease_minutes",json_object_new_int(sqlite3_column_int(stp,11))); json_object_object_add(p,"sort_order",json_object_new_int(sqlite3_column_int(stp,12))); nc_add_text(p,"apply_state",stp,13); json_object_object_add(p,"runtime_configured",json_object_new_boolean(sqlite3_column_int(stp,14))); json_object_object_add(p,"runtime_bound",json_object_new_boolean(sqlite3_column_int(stp,15))); nc_add_text(p,"runtime_prefix",stp,16); nc_add_text(p,"runtime_duid",stp,17); json_object_object_add(p,"last_apply_at",json_object_new_int64(sqlite3_column_int64(stp,18))); json_object_array_add(top_pfx,p);} sqlite3_finalize(stp);} json_object_object_add(data,"prefix_reservations",top_pfx); json_object_object_add(data,"prefixes",json_object_get(top_pfx)); }
    json_object_object_add(data,"ts",json_object_new_int64(nc_now_s())); json_object_object_add(data,"selected",json_object_new_string(selected)); json_object_object_add(data,"scopes",scopes);
    json_object_object_add(data,"whitelist",whitelist); json_object_object_add(data,"blacklist",blacklist);
    int nc_rogue_count = 0;
    struct json_object *nc_rogue = nc_rogue_dhcp_report(&nc_rogue_count);
    { struct json_object *g=json_object_new_object(); json_object_object_add(g,"rogue_dhcp_detection",json_object_new_boolean(nc_rogue_dhcp_pref())); json_object_object_add(data,"global",g); }
    /* flat alias for the server list; refcount +1 because nc_rogue keeps its own */
    json_object_object_add(data,"rogue_dhcp_servers",json_object_get(json_object_object_get(nc_rogue,"servers")));
    json_object_object_add(data,"rogue_dhcp_count",json_object_new_int(nc_rogue_count));
    json_object_object_add(data,"rogue_dhcp",nc_rogue); /* ownership transferred */
    { struct json_object *c=json_object_new_object(); json_object_object_add(c,"service_read",json_object_new_boolean(1)); json_object_object_add(c,"service_update",json_object_new_boolean(1)); json_object_object_add(c,"apply_readback",json_object_new_boolean(1)); json_object_object_add(c,"dhcp_options",json_object_new_boolean(1)); json_object_object_add(c,"static_reservations",json_object_new_boolean(1)); json_object_object_add(c,"reservation_delete",json_object_new_boolean(1)); json_object_object_add(c,"exclude_pool",json_object_new_boolean(1)); json_object_object_add(c,"access_list_replace",json_object_new_boolean(1)); json_object_object_add(c,"access_list_apply",json_object_new_boolean(1)); json_object_object_add(c,"pool_addresses_full_ipv4",json_object_new_boolean(1)); json_object_object_add(c,"lease_read",json_object_new_boolean(1)); json_object_object_add(c,"allow_deny_list",json_object_new_boolean(1)); json_object_object_add(c,"dhcpv6_static_prefix",json_object_new_boolean(1)); json_object_object_add(c,"prefix_reservations",json_object_new_boolean(1)); json_object_object_add(c,"prefix_reservation_apply",json_object_new_boolean(1)); json_object_object_add(c,"prefix_reservation_readback",json_object_new_boolean(1)); json_object_object_add(c,"rogue_dhcp_detection",json_object_new_boolean(dhcp_sniff_active())); json_object_object_add(c,"rogue_dhcp_passive_only",json_object_new_boolean(1)); if(!dhcp_sniff_active()) json_object_object_add(c,"rogue_dhcp_detection_reason",json_object_new_string("dhcp_passive_observer_not_running")); json_object_object_add(data,"capabilities",c); }
    return jmx_gen_api_response_data(API_CODE_SUCCESS,data);
}

int jmx_dhcp_reservation_delete_resolve(const char *id, char *lan_id, size_t lan_id_len)
{
    sqlite3_stmt *st = NULL;
    char resolved_lan[128] = "";
    int changed = 0;

    if (lan_id && lan_id_len) lan_id[0] = '\0';
    if (!id || !id[0] || !nc_valid_name(id)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_exec("BEGIN IMMEDIATE") != 0) return -1;
    if (nc_prepare(&st,
        "SELECT ds.lan_id FROM dhcp_reservation dr "
        "JOIN dhcp_scope ds ON ds.id=dr.scope_id WHERE dr.id=?1") != 0) {
        nc_exec("ROLLBACK"); return -1;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        snprintf(resolved_lan, sizeof(resolved_lan), "%s",
                 (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st); st = NULL;
    if (!resolved_lan[0]) { nc_exec("ROLLBACK"); return 1; }
    if (nc_prepare(&st, "DELETE FROM dhcp_reservation WHERE id=?1") != 0) {
        nc_exec("ROLLBACK"); return -1;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) == 0) changed = sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st); st = NULL;
    if (changed != 1 || nc_exec("COMMIT") != 0) {
        nc_exec("ROLLBACK"); return -1;
    }
    if (lan_id && lan_id_len)
        snprintf(lan_id, lan_id_len, "%s", resolved_lan);
    return 0;
}

int jmx_dhcp_reservation_delete(const char *id)
{
    return jmx_dhcp_reservation_delete_resolve(id, NULL, 0);
}
static int nc_dhcp_normalize_exclude_pool(const char *raw, char *out, size_t out_len)
{
    struct json_object *a = NULL;
    char tmp[1024], *save = NULL, *tok;
    int first = 1;
    if (!out || !out_len) return -1;
    out[0] = '\0';
    if (!raw || !raw[0]) return 0;
    a = json_tokener_parse(raw);
    if (a && json_object_is_type(a, json_type_array)) {
        size_t i, n = json_object_array_length(a);
        for (i = 0; i < n; i++) {
            const char *v = json_object_get_string(json_object_array_get_idx(a, i));
            if (!v || !v[0]) continue;
            if (!first) strncat(out, ",", out_len - strlen(out) - 1);
            strncat(out, v, out_len - strlen(out) - 1); first = 0;
        }
        json_object_put(a); return 0;
    }
    if (a) json_object_put(a);
    snprintf(tmp, sizeof(tmp), "%s", raw);
    for (tok = strtok_r(tmp, ",; \t\r\n", &save); tok; tok = strtok_r(NULL, ",; \t\r\n", &save)) {
        if (!first) strncat(out, ",", out_len - strlen(out) - 1);
        strncat(out, tok, out_len - strlen(out) - 1); first = 0;
    }
    return 0;
}

static __thread char g_dhcp_set_failure_reason[128];

static int nc_dhcp_set_fail(int rc, const char *reason)
{
    snprintf(g_dhcp_set_failure_reason, sizeof(g_dhcp_set_failure_reason), "%s",
             reason && reason[0] ? reason : "dhcp_save_failed");
    return rc;
}

const char *jmx_dhcp_service_set_failure_reason(void)
{
    return g_dhcp_set_failure_reason[0] ? g_dhcp_set_failure_reason : "dhcp_save_failed";
}

static int nc_dhcp_scope_conflicts(const char *scope_id, const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    int conflicts = -1;

    if (!scope_id || !scope_id[0] || !lan_id || !lan_id[0] ||
        nc_prepare(&st, "SELECT 1 FROM dhcp_scope WHERE "
                   "(id=?1 AND lan_id<>?2) OR (lan_id=?2 AND id<>?1) LIMIT 1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, scope_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
    conflicts = sqlite3_step(st) == SQLITE_ROW ? 1 : 0;
    sqlite3_finalize(st);
    return conflicts;
}

#include "009_nc_dhcp_authority.c"

int jmx_dhcp_service_set(struct json_object *cfg)
{
    struct json_object *dhcp = NULL, *arr = NULL, *access_arr = NULL, *prefix_arr = NULL;
    sqlite3_stmt *st = NULL;
    const char *lan_id;
    char scope_id[128], ps[64], pe[64];
    int rc = -1, i, n, own_transaction;

    g_dhcp_set_failure_reason[0] = '\0';
    if (!cfg) return nc_dhcp_set_fail(-2, "dhcp_payload_required");
    lan_id = nc_json_str_def(cfg, "lan_id", "");
    if (!lan_id[0] || !nc_valid_name(lan_id)) return nc_dhcp_set_fail(-2, "invalid_dhcp_lan");
    dhcp = cfg;
    json_object_object_get_ex(cfg, "dhcp", &dhcp);
    if (!dhcp) dhcp = cfg;
    if (!json_object_is_type(dhcp, json_type_object)) return nc_dhcp_set_fail(-2, "dhcp_scope_must_be_object");
    if (jmx_netconfig_db_init() != 0) return nc_dhcp_set_fail(-1, "dhcp_database_unavailable");
    struct json_object *base = nc_dhcp_legacy_merge(lan_id, dhcp);
    if (!base) return nc_dhcp_set_fail(-2, "invalid_dhcp_scope");
    char base_error[128];
    int base_valid = nc_dhcp_base_validate(base, base_error, sizeof(base_error));
    snprintf(scope_id, sizeof(scope_id), "%s", nc_json_str_def(base, "id", lan_id));
    snprintf(ps, sizeof(ps), "%s", nc_json_str_def(base, "pool_start", ""));
    snprintf(pe, sizeof(pe), "%s", nc_json_str_def(base, "pool_end", ""));
    json_object_put(base);
    if (base_valid != 0) return nc_dhcp_set_fail(-2, base_error);
    if (!scope_id[0] || !nc_valid_name(scope_id)) return nc_dhcp_set_fail(-2, "invalid_dhcp_scope");
    { int conflicts = nc_dhcp_scope_conflicts(scope_id, lan_id); if (conflicts < 0) return nc_dhcp_set_fail(-1, "dhcp_database_read_failed"); if (conflicts) return nc_dhcp_set_fail(-2, "dhcp_scope_conflict"); }
    json_object_object_get_ex(dhcp, "reservations", &arr);
    if (arr && !json_object_is_type(arr, json_type_array)) return nc_dhcp_set_fail(-2, "reservations_must_be_array");
    access_arr = nc_dhcp_access_list_from_payload(dhcp);
    prefix_arr = nc_dhcp_prefixes_from_payload(dhcp);
    { char err[128]; if (nc_dhcp_validate_scope(lan_id, ps, pe, arr, err, sizeof(err)) != 0 || nc_dhcp_validate_access_list(access_arr, err, sizeof(err)) != 0 || nc_dhcp_validate_prefix_reservations(lan_id, prefix_arr, err, sizeof(err)) != 0) { LOG_ERROR("dhcp_service_set validation failed: %s", err); return nc_dhcp_set_fail(-2, err); } }
    own_transaction = sqlite3_get_autocommit(g_netconfig_db);
    if (own_transaction && nc_txn_begin() != 0) return nc_dhcp_set_fail(-1, "dhcp_database_write_failed");
    rc = nc_dhcp_legacy_set(lan_id, dhcp);
    if (json_object_object_get_ex(dhcp, "options", &arr)) {
        if (!json_object_is_type(arr, json_type_array)) rc = -1;
    if (rc == 0 && nc_prepare(&st,"DELETE FROM dhcp_option WHERE scope_id=?1") == 0) { sqlite3_bind_text(st,1,scope_id,-1,SQLITE_TRANSIENT); nc_step_done(st); sqlite3_finalize(st); if(json_object_object_get_ex(dhcp,"options",&arr)&&arr&&json_object_is_type(arr,json_type_array)){n=(int)json_object_array_length(arr); for(i=0;i<n;i++){const char *line=json_object_get_string(json_object_array_get_idx(arr,i)); const char *comma=line?strchr(line,','):NULL; char oid[sizeof(scope_id) + sizeof("_opt_2147483647") - 1],code[16]; if(!line||!comma)continue; snprintf(oid,sizeof(oid),"%s_opt_%d",scope_id,i); snprintf(code,sizeof(code),"%.*s",(int)(comma-line),line); if(nc_prepare(&st,"INSERT INTO dhcp_option(id,scope_id,code,value,sort_order) VALUES(?1,?2,?3,?4,?5)")==0){sqlite3_bind_text(st,1,oid,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,scope_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,code,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,comma+1,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,5,i); if(nc_step_done(st)!=0)rc=-1; sqlite3_finalize(st);}}}}
    }
    if (rc == 0 && json_object_object_get_ex(dhcp,"reservations",&arr)&&arr&&json_object_is_type(arr,json_type_array)) { if(nc_prepare(&st,"DELETE FROM dhcp_reservation WHERE scope_id=?1")==0){sqlite3_bind_text(st,1,scope_id,-1,SQLITE_TRANSIENT); nc_step_done(st); sqlite3_finalize(st);} n=(int)json_object_array_length(arr); for(i=0;i<n;i++){struct json_object *r=json_object_array_get_idx(arr,i); const char *id=nc_json_str_def(r,"id",""); const char *mac=nc_json_str_def(r,"mac",""); const char *ip=nc_json_str_def(r,"ip",""); char macn[18]; if(!id[0]||!nc_valid_name(id)||!nc_mac_normalize(mac,macn,sizeof(macn))||!ip[0]){rc=-1;break;} if(nc_prepare(&st,"INSERT INTO dhcp_reservation(id,scope_id,name,mac,ip,remark,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,scope_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,nc_json_str_def(r,"name",id),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,macn,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,5,ip,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,6,nc_json_str_def(r,"remark",""),-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,7,nc_json_bool_def(r,"enabled",1)); if(nc_step_done(st)!=0)rc=-1; sqlite3_finalize(st);} else rc=-1; }}
    if (rc == 0 && access_arr) { if (nc_prepare(&st,"DELETE FROM dhcp_access_entry WHERE scope_id=?1") == 0) { sqlite3_bind_text(st,1,scope_id,-1,SQLITE_TRANSIENT); nc_step_done(st); sqlite3_finalize(st); } else rc = -1; if (rc == 0) { n=(int)json_object_array_length(access_arr); for(i=0;i<n;i++){ struct json_object *a=json_object_array_get_idx(access_arr,i); const char *action=nc_json_str_def(a,"action",""); const char *mac=nc_json_str_def(a,"mac",""); const char *id=nc_json_str_def(a,"id",""); char macn[18], gen_id[sizeof(scope_id) + sizeof("_allow_001122334455") - 1]; int sort_order=i*10; if(!nc_mac_normalize(mac,macn,sizeof(macn))){rc=-1;break;} if(!id[0]){nc_dhcp_access_id_make(scope_id,action,macn,gen_id,sizeof(gen_id)); id=gen_id;} if(!nc_dhcp_json_int_field_ok(a,"sort_order",i*10,&sort_order)){rc=-1;break;} if(nc_prepare(&st,"INSERT INTO dhcp_access_entry(id,scope_id,action,mac,name,remark,enabled,sort_order,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,scope_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,action,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,macn,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,5,nc_json_str_def(a,"name",""),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,6,nc_json_str_def(a,"remark",""),-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,7,nc_json_bool_def(a,"enabled",1)); sqlite3_bind_int(st,8,sort_order); sqlite3_bind_int64(st,9,nc_now_s()); if(nc_step_done(st)!=0)rc=-1; sqlite3_finalize(st);} else rc=-1; } } }
    if (rc == 0 && prefix_arr) { if (nc_prepare(&st,"DELETE FROM dhcpv6_prefix_reservation WHERE scope_id=?1") == 0) { sqlite3_bind_text(st,1,scope_id,-1,SQLITE_TRANSIENT); nc_step_done(st); sqlite3_finalize(st); } else rc = -1; if (rc == 0) { n=(int)json_object_array_length(prefix_arr); for(i=0;i<n;i++){ struct json_object *p=json_object_array_get_idx(prefix_arr,i); const char *id=nc_json_str_def(p,"id",""); const char *raw_duid=nc_json_str_def(p,"duid",""); const char *raw_prefix=nc_json_str_def(p,"prefix",""); const char *raw_hostid=nc_json_str_def(p,"hostid",""); char duid[300], iaid[16], prefix_canon[128], hostid[32]="", gen_id[160]; struct in6_addr prefix_addr,parent_addr; int prefix_len=0,parent_len=0,parent_state,sort_order=i*10,lease=nc_json_int_def(p,"lease_minutes",nc_json_int_def(dhcp,"lease",120)); int64_t now=nc_now_s(); if(!nc_dhcp_duid_normalize(raw_duid,duid,sizeof(duid),iaid,sizeof(iaid))||!nc_ipv6_prefix_parse(raw_prefix,&prefix_addr,&prefix_len,prefix_canon,sizeof(prefix_canon))){rc=-1;break;} parent_state=nc_dhcpv6_parent_prefix_for_child(lan_id,&prefix_addr,prefix_len,&parent_addr,&parent_len,NULL,0); if(parent_state>0){ if(!nc_dhcpv6_derive_hostid(&prefix_addr,prefix_len,&parent_addr,parent_len,hostid,sizeof(hostid))){rc=-1;break;} } else if(parent_state<0) { snprintf(hostid,sizeof(hostid),"%s",raw_hostid); } else {rc=-1;break;} if(!nc_hex_string_ok(hostid,0)||strtoull(hostid,NULL,16)==0){rc=-1;break;} if(!id[0]){nc_dhcpv6_prefix_id_make(scope_id,duid,hostid,gen_id,sizeof(gen_id)); id=gen_id;} if(!nc_valid_name(id)||!nc_dhcp_json_int_field_ok(p,"sort_order",i*10,&sort_order)||sort_order<0||sort_order>1000000||lease<1||lease>5256000){rc=-1;break;} if(nc_prepare(&st,"INSERT INTO dhcpv6_prefix_reservation(id,scope_id,lan_id,name,duid,iaid,prefix,hostid,prefix_len,remark,enabled,lease_minutes,sort_order,apply_state,runtime_configured,runtime_bound,runtime_prefix,runtime_duid,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending',0,0,'','',?14,?15) ON CONFLICT(id) DO UPDATE SET scope_id=excluded.scope_id,lan_id=excluded.lan_id,name=excluded.name,duid=excluded.duid,iaid=excluded.iaid,prefix=excluded.prefix,hostid=excluded.hostid,prefix_len=excluded.prefix_len,remark=excluded.remark,enabled=excluded.enabled,lease_minutes=excluded.lease_minutes,sort_order=excluded.sort_order,apply_state='pending',runtime_configured=0,runtime_bound=0,runtime_prefix='',runtime_duid='',updated_at=excluded.updated_at")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,scope_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,lan_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,nc_json_str_def(p,"name",id),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,5,duid,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,6,nc_json_str_def(p,"iaid",iaid),-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,7,prefix_canon,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,8,hostid,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,9,prefix_len); sqlite3_bind_text(st,10,nc_json_str_def(p,"remark",""),-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,11,nc_json_bool_def(p,"enabled",1)); sqlite3_bind_int(st,12,lease); sqlite3_bind_int(st,13,sort_order); sqlite3_bind_int64(st,14,now); sqlite3_bind_int64(st,15,now); if(nc_step_done(st)!=0)rc=-1; sqlite3_finalize(st);} else rc=-1; } } }
    if (own_transaction) {
        if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1;
        if (rc != 0) nc_exec("ROLLBACK");
    }
    if (rc != 0)
        return nc_dhcp_set_fail(rc, "dhcp_database_write_failed");
    return 0;
}

static int nc_dhcp_rebuild_all_reservations(struct uci_context *ctx,
                                            struct uci_package *pkg)
{
    sqlite3_stmt *st = NULL;
    int rc = 0;

    if (!ctx || !pkg) return -1;
    nc_uci_delete_managed_sections(ctx, pkg, "dhcp", "host", "dw_");
    if (nc_prepare(&st,
        "SELECT dr.id,dr.name,dr.mac,dr.ip FROM dhcp_reservation dr "
        "JOIN dhcp_scope ds ON ds.id=dr.scope_id "
        "WHERE dr.enabled=1 AND ds.enabled=1 ORDER BY ds.lan_id,dr.id") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *name = (const char *)sqlite3_column_text(st, 1);
        const char *mac = (const char *)sqlite3_column_text(st, 2);
        const char *ip = (const char *)sqlite3_column_text(st, 3);
        char sec[128];

        if (!id || !nc_valid_name(id) || !mac || !ip) { rc = -1; break; }
        snprintf(sec, sizeof(sec), "dw_%s", id);
        if (nc_uci_ensure_section(ctx, pkg, "dhcp", sec, "host") != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "name", name ? name : id) != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "mac", mac) != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "ip", ip) != 0) {
            rc = -1; break;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

#define NC_DHCP_ACCESS_BEGIN "# BEGIN DREAMINGWRT DHCP ACCESS"
#define NC_DHCP_ACCESS_END   "# END DREAMINGWRT DHCP ACCESS"


static int nc_dhcpv6_rebuild_all_prefix_reservations(struct uci_context *ctx,
                                                     struct uci_package *pkg)
{
    sqlite3_stmt *st = NULL;
    int rc = 0;

    if (!ctx || !pkg) return -1;
    nc_uci_delete_managed_sections(ctx, pkg, "dhcp", "host", "dw_pd_");
    if (nc_prepare(&st,
        "SELECT id,name,duid,iaid,hostid,prefix_len,lan_id,lease_minutes "
        "FROM dhcpv6_prefix_reservation WHERE enabled=1 ORDER BY lan_id,sort_order,id") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *name = (const char *)sqlite3_column_text(st, 1);
        const char *duid = (const char *)sqlite3_column_text(st, 2);
        const char *iaid = (const char *)sqlite3_column_text(st, 3);
        const char *hostid = (const char *)sqlite3_column_text(st, 4);
        int prefix_len = sqlite3_column_int(st, 5);
        const char *lan_id = (const char *)sqlite3_column_text(st, 6);
        int lease = sqlite3_column_int(st, 7);
        char sec[180], duid_with_iaid[340], b[32];

        if (!id || !nc_valid_name(id) || !duid || !duid[0] || !hostid || !hostid[0] ||
            !lan_id || !lan_id[0] || !nc_valid_name(lan_id) || prefix_len < 33 || prefix_len > 64) {
            rc = -1; break;
        }
        snprintf(sec, sizeof(sec), "dw_pd_%s", id);
        snprintf(duid_with_iaid, sizeof(duid_with_iaid), "%s%s%s", duid,
                 iaid && iaid[0] ? "%" : "", iaid && iaid[0] ? iaid : "");
        if (nc_uci_ensure_section(ctx, pkg, "dhcp", sec, "host") != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "name", name && name[0] ? name : id) != 0 ||
            nc_uci_delete_pkg(ctx, "dhcp", sec, "duid") != 0 ||
            nc_uci_add_list_pkg(ctx, "dhcp", sec, "duid", duid_with_iaid) != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "hostid", hostid) != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "pd_interface", lan_id) != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", sec, "pd_only", "1") != 0) {
            rc = -1; break;
        }
        snprintf(b, sizeof(b), "%d", prefix_len);
        if (nc_uci_set_pkg(ctx, "dhcp", sec, "pd_prefixlen", b) != 0) { rc = -1; break; }
        if (lease > 0) {
            snprintf(b, sizeof(b), "%dm", lease);
            if (nc_uci_set_pkg(ctx, "dhcp", sec, "leasetime", b) != 0) { rc = -1; break; }
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int nc_dhcpv6_static_leases_readback_update(const char *lan_id)
{
    FILE *fp;
    char line[65536];
    struct json_object *root = NULL;
    sqlite3_stmt *st = NULL;
    int rc = 0;
    int64_t now = nc_now_s();

    if (!lan_id || !lan_id[0] || !nc_valid_name(lan_id)) return -1;
    if (access("/bin/ubus", X_OK) != 0 && access("/sbin/ubus", X_OK) != 0 && access("/usr/bin/ubus", X_OK) != 0)
        return -1;
    fp = popen("ubus -S call dhcp static_leases '{}' 2>/dev/null", "r");
    if (!fp) return -1;
    if (fgets(line, sizeof(line), fp)) root = json_tokener_parse(line);
    if (pclose(fp) != 0 || !root) {
        if (root) json_object_put(root);
        return -1;
    }

    if (nc_prepare(&st, "UPDATE dhcpv6_prefix_reservation SET apply_state='not_configured',runtime_configured=0,runtime_bound=0,runtime_prefix='',runtime_duid='',last_apply_at=?1 WHERE lan_id=?2") == 0) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, lan_id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0) rc = -1;
        sqlite3_finalize(st); st = NULL;
    } else rc = -1;

    /* Configured and bound are separate states.  Parse odhcpd's structured
     * lease/binding arrays; a configured DUID is not evidence of an active bind. */
    if (rc == 0) {
        struct json_object *leases = NULL;
        if (!json_object_object_get_ex(root, "leases", &leases) ||
            !json_object_is_type(leases, json_type_array)) {
            rc = -1;
        } else {
            int i, configured_count = 0;
            int count = (int)json_object_array_length(leases);
            for (i = 0; i < count && rc == 0; i++) {
                struct json_object *entry = json_object_array_get_idx(leases, i);
                struct json_object *duids = NULL, *bindings = NULL;
                const char *pd_if = nc_json_str_def(entry, "pd_interface", "");
                const char *duid = "", *runtime_duid = "";
                char runtime_prefix[160] = "";
                int bound = 0, j;

                if (strcmp(pd_if, lan_id) ||
                    !json_object_object_get_ex(entry, "duids", &duids) ||
                    !json_object_is_type(duids, json_type_array) ||
                    json_object_array_length(duids) == 0)
                    continue;
                duid = nc_json_str_def(json_object_array_get_idx(duids, 0), "duid", "");
                if (!duid[0]) continue;

                if (json_object_object_get_ex(entry, "bindings", &bindings) &&
                    json_object_is_type(bindings, json_type_array)) {
                    for (j = 0; j < (int)json_object_array_length(bindings); j++) {
                        struct json_object *binding = json_object_array_get_idx(bindings, j);
                        struct json_object *prefixes = NULL;
                        if (!nc_json_bool_def(binding, "bound", 0)) continue;
                        bound = 1;
                        runtime_duid = nc_json_str_def(binding, "duid", duid);
                        if (json_object_object_get_ex(binding, "prefixes", &prefixes) &&
                            json_object_is_type(prefixes, json_type_array) &&
                            json_object_array_length(prefixes) > 0) {
                            struct json_object *p = json_object_array_get_idx(prefixes, 0);
                            const char *addr = nc_json_str_def(p, "address", "");
                            int plen = nc_json_int_def(p, "prefix-length", 0);
                            if (addr[0] && plen >= 33 && plen <= 64)
                                snprintf(runtime_prefix, sizeof(runtime_prefix), "%s/%d", addr, plen);
                        }
                        break;
                    }
                }

                if (nc_prepare(&st, "UPDATE dhcpv6_prefix_reservation SET apply_state='configured',runtime_configured=1,runtime_bound=?1,runtime_prefix=?2,runtime_duid=?3,last_apply_at=?4 WHERE lan_id=?5 AND lower(duid)=lower(?6) AND enabled=1") != 0) {
                    rc = -1;
                    break;
                }
                sqlite3_bind_int(st, 1, bound);
                sqlite3_bind_text(st, 2, runtime_prefix, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, runtime_duid, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 4, now);
                sqlite3_bind_text(st, 5, lan_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 6, duid, -1, SQLITE_TRANSIENT);
                if (nc_step_done(st) != 0 || sqlite3_changes(g_netconfig_db) != 1) rc = -1;
                else configured_count++;
                sqlite3_finalize(st); st = NULL;
            }
            if (rc == 0 && nc_prepare(&st, "SELECT COUNT(*) FROM dhcpv6_prefix_reservation WHERE lan_id=?1 AND enabled=1") == 0) {
                sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(st) != SQLITE_ROW ||
                    sqlite3_column_int(st, 0) != configured_count)
                    rc = -1;
                sqlite3_finalize(st); st = NULL;
            } else if (rc == 0) {
                rc = -1;
            }
        }
    }
    json_object_put(root);
    return rc;
}

static int nc_dhcp_access_tag_ok_char(int c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '-';
}

static void nc_dhcp_access_tag_component(const char *in, char *out, size_t out_len)
{
    size_t i, j = 0;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in || !in[0]) {
        snprintf(out, out_len, "scope");
        return;
    }
    for (i = 0; in[i] && j + 1 < out_len; i++) {
        out[j++] = nc_dhcp_access_tag_ok_char((unsigned char)in[i]) ? in[i] : '_';
    }
    out[j] = '\0';
}

static int nc_dhcp_access_append(char **text, size_t *len, size_t *cap,
                                 const char *format, ...)
{
    va_list ap;
    int need;

    if (!text || !len || !cap || !format)
        return -1;
    while (1) {
        va_start(ap, format);
        need = vsnprintf(*text ? *text + *len : NULL,
                         *text && *cap > *len ? *cap - *len : 0,
                         format, ap);
        va_end(ap);
        if (need < 0)
            return -1;
        if (*text && *len + (size_t)need < *cap) {
            *len += (size_t)need;
            return 0;
        }
        {
            size_t required = *len + (size_t)need + 1;
            size_t next = *cap ? *cap : 1024;
            char *grown;

            while (next < required) {
                if (next > 1024 * 1024)
                    return -1;
                next *= 2;
            }
            grown = realloc(*text, next);
            if (!grown)
                return -1;
            *text = grown;
            *cap = next;
        }
    }
}

static int nc_dhcp_access_build_block(char **out, int *entry_count)
{
    sqlite3_stmt *st = NULL;
    char *text = NULL;
    size_t len = 0, cap = 0;
    int rc = 0, count = 0;

    if (out) *out = NULL;
    if (entry_count) *entry_count = 0;
    if (nc_dhcp_access_append(&text, &len, &cap, "%s\n", NC_DHCP_ACCESS_BEGIN) != 0)
        return -1;

    if (nc_prepare(&st,
        "SELECT ds.id,ds.lan_id,"
        "SUM(CASE WHEN ae.action='allow' AND ae.enabled=1 THEN 1 ELSE 0 END),"
        "SUM(CASE WHEN ae.action='deny' AND ae.enabled=1 THEN 1 ELSE 0 END) "
        "FROM dhcp_scope ds JOIN dhcp_access_entry ae ON ae.scope_id=ds.id "
        "WHERE ds.enabled=1 GROUP BY ds.id,ds.lan_id ORDER BY ds.id") != 0)
        goto fail;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *scope_id = (const char *)sqlite3_column_text(st, 0);
        const char *lan_id = (const char *)sqlite3_column_text(st, 1);
        int allow_count = sqlite3_column_int(st, 2);
        int deny_count = sqlite3_column_int(st, 3);
        char lan_tag[160], scope_tag[160], allow_tag[192], deny_tag[192];

        if (!scope_id || !lan_id) { rc = -1; break; }
        nc_dhcp_access_tag_component(lan_id, lan_tag, sizeof(lan_tag));
        nc_dhcp_access_tag_component(scope_id, scope_tag, sizeof(scope_tag));
        snprintf(allow_tag, sizeof(allow_tag), "dw_dhcp_%s_allow", scope_tag);
        snprintf(deny_tag, sizeof(deny_tag), "dw_dhcp_%s_deny", scope_tag);
        if (allow_count > 0 &&
            nc_dhcp_access_append(&text, &len, &cap,
                                  "dhcp-ignore=tag:%s,tag:!%s\n",
                                  lan_tag, allow_tag) != 0)
            rc = -1;
        if (deny_count > 0 &&
            nc_dhcp_access_append(&text, &len, &cap,
                                  "dhcp-ignore=tag:%s,tag:%s\n",
                                  lan_tag, deny_tag) != 0)
            rc = -1;
        count += allow_count + deny_count;
        if (rc != 0) break;
    }
    sqlite3_finalize(st); st = NULL;
    if (rc == 0 && nc_prepare(&st,
        "SELECT ds.id,ae.action,ae.mac "
        "FROM dhcp_access_entry ae JOIN dhcp_scope ds ON ds.id=ae.scope_id "
        "WHERE ae.enabled=1 AND ds.enabled=1 ORDER BY ds.id,ae.sort_order,ae.id") != 0)
        rc = -1;
    while (rc == 0 && sqlite3_step(st) == SQLITE_ROW) {
        const char *scope_id = (const char *)sqlite3_column_text(st, 0);
        const char *action = (const char *)sqlite3_column_text(st, 1);
        const char *mac = (const char *)sqlite3_column_text(st, 2);
        char scope_tag[160], action_tag[192];

        if (!scope_id || !action || !mac) { rc = -1; break; }
        nc_dhcp_access_tag_component(scope_id, scope_tag, sizeof(scope_tag));
        snprintf(action_tag, sizeof(action_tag), "dw_dhcp_%s_%s", scope_tag, action);
        if (nc_dhcp_access_append(&text, &len, &cap,
                                  "dhcp-mac=set:%s,%s\n", action_tag, mac) != 0)
            rc = -1;
    }
    if (st) sqlite3_finalize(st);
    st = NULL;
    if (rc != 0 || nc_dhcp_access_append(&text, &len, &cap, "%s\n", NC_DHCP_ACCESS_END) != 0)
        goto fail;
    if (out) *out = text;
    else free(text);
    if (entry_count) *entry_count = count;
    return 0;

fail:
    if (st) sqlite3_finalize(st);
    free(text);
    return -1;
}

static struct uci_section *nc_dhcp_dnsmasq_section(struct uci_package *pkg)
{
    struct uci_element *e;

    if (!pkg) return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (s && !strcmp(s->type, "dnsmasq"))
            return s;
    }
    return NULL;
}

static int nc_dhcp_merge_access_extraconf(struct uci_context *ctx,
                                          struct uci_package *pkg,
                                          int *entry_count)
{
    struct uci_section *section = nc_dhcp_dnsmasq_section(pkg);
    const char *current;
    const char *begin, *end, *suffix;
    char *block = NULL, *merged = NULL;
    size_t prefix_len, suffix_len, block_len, total;
    struct uci_ptr ptr = {0};
    int count = 0;

    if (entry_count) *entry_count = 0;
    if (!ctx || !pkg || !section || nc_dhcp_access_build_block(&block, &count) != 0)
        return -1;
    current = uci_lookup_option_string(ctx, section, "extraconftext");
    if (!current) current = "";
    begin = strstr(current, NC_DHCP_ACCESS_BEGIN);
    end = begin ? strstr(begin, NC_DHCP_ACCESS_END) : NULL;
    if (begin && !end) {
        free(block);
        return -1;
    }
    prefix_len = begin ? (size_t)(begin - current) : strlen(current);
    suffix = end ? end + strlen(NC_DHCP_ACCESS_END) : current + strlen(current);
    while (*suffix == '\r' || *suffix == '\n') suffix++;
    suffix_len = strlen(suffix);
    /* Keep an empty managed block so dnsmasq overwrites stale rules when the
     * final access-list entry is removed. */
    block_len = strlen(block);
    total = prefix_len + (prefix_len && current[prefix_len - 1] != '\n' && block_len ? 1 : 0) +
            block_len + suffix_len + (block_len && suffix_len ? 1 : 0) + 1;
    merged = calloc(1, total);
    if (!merged) {
        free(block);
        return -1;
    }
    if (prefix_len) memcpy(merged, current, prefix_len);
    if (block_len) {
        if (prefix_len && merged[strlen(merged) - 1] != '\n') strcat(merged, "\n");
        strcat(merged, block);
    }
    if (suffix_len) {
        if (merged[0] && merged[strlen(merged) - 1] != '\n') strcat(merged, "\n");
        strcat(merged, suffix);
    }
    ptr.p = pkg;
    ptr.s = section;
    ptr.option = "extraconftext";
    ptr.value = merged;
    if (merged[0]) {
        if (uci_set(ctx, &ptr) != UCI_OK) count = -1;
    } else {
        struct uci_option *option = uci_lookup_option(ctx, section, "extraconftext");
        if (option) {
            ptr.o = option;
            if (uci_delete(ctx, &ptr) != UCI_OK) count = -1;
        }
    }
    free(merged);
    free(block);
    if (count < 0) return -1;
    if (entry_count) *entry_count = count;
    return 0;
}

static int nc_dhcp_access_runtime_loaded(int entry_count)
{
    const char *cmd =
        "pidof dnsmasq >/dev/null 2>&1 || exit 1; found=0; "
        "for c in /tmp/etc/dnsmasq.conf.*; do [ -f \"$c\" ] || continue; "
        "d=$(sed -n 's/^conf-dir=//p' \"$c\" | head -n 1); [ -n \"$d\" ] || continue; "
        "f=$d/extraconfig.conf; [ -f \"$f\" ] || continue; "
        "grep -Fq '# BEGIN DREAMINGWRT DHCP ACCESS' \"$f\" && "
        "grep -Fq '# END DREAMINGWRT DHCP ACCESS' \"$f\" && found=1; done; "
        "[ \"$found\" -eq 1 ]";

    /* An empty access list is a valid empty set.  Do not require a marker
     * block in dnsmasq's generated config when there is nothing to load. */
    if (entry_count <= 0)
        return nc_run_quiet("pidof dnsmasq >/dev/null 2>&1");
    return nc_run_quiet(cmd);
}

enum {
    NC_DHCP_APPLY_ERR_CONFIG = -1,
    NC_DHCP_APPLY_ERR_DNSMASQ_RELOAD = -3,
    NC_DHCP_APPLY_ERR_DHCP_ACCESS_READBACK = -4,
    NC_DHCP_APPLY_ERR_ODHCPD_RELOAD = -5,
    NC_DHCP_APPLY_ERR_DHCPV6_READBACK = -6,
    NC_DHCP_APPLY_ERR_DNSMASQ_CONFIG = -7,
    NC_DHCP_APPLY_ERR_DHCPV6_CONFIG = -8,
    NC_DHCP_APPLY_ERR_DHCP_ACCESS_CONFIG = -9,
    NC_DHCP_APPLY_ERR_UCI_COMMIT = -10
};

const char *jmx_dhcp_service_apply_failure_reason(int rc)
{
    switch (rc) {
    case NC_DHCP_APPLY_ERR_DNSMASQ_RELOAD:
        return "dnsmasq_reload_failed";
    case NC_DHCP_APPLY_ERR_DHCP_ACCESS_READBACK:
        return "dhcp_access_readback_failed";
    case NC_DHCP_APPLY_ERR_ODHCPD_RELOAD:
        return "odhcpd_reload_failed";
    case NC_DHCP_APPLY_ERR_DHCPV6_READBACK:
        return "dhcpv6_readback_failed";
    case NC_DHCP_APPLY_ERR_DNSMASQ_CONFIG:
        return "dnsmasq_config_generation_failed";
    case NC_DHCP_APPLY_ERR_DHCPV6_CONFIG:
        return "dhcpv6_config_generation_failed";
    case NC_DHCP_APPLY_ERR_DHCP_ACCESS_CONFIG:
        return "dhcp_access_config_generation_failed";
    case NC_DHCP_APPLY_ERR_UCI_COMMIT:
        return "dhcp_uci_commit_failed";
    case NC_DHCP_APPLY_ERR_CONFIG:
    default:
        return "dhcp_config_apply_failed";
    }
}

const char *jmx_dhcp_service_apply_failure_stage(int rc)
{
    switch (rc) {
    case NC_DHCP_APPLY_ERR_DNSMASQ_RELOAD:
        return "dnsmasq_reload";
    case NC_DHCP_APPLY_ERR_DHCP_ACCESS_READBACK:
        return "dhcp_access_readback";
    case NC_DHCP_APPLY_ERR_ODHCPD_RELOAD:
        return "odhcpd_reload";
    case NC_DHCP_APPLY_ERR_DHCPV6_READBACK:
        return "dhcpv6_readback";
    case NC_DHCP_APPLY_ERR_DNSMASQ_CONFIG:
        return "dnsmasq_config_generation";
    case NC_DHCP_APPLY_ERR_DHCPV6_CONFIG:
        return "dhcpv6_config_generation";
    case NC_DHCP_APPLY_ERR_DHCP_ACCESS_CONFIG:
        return "dhcp_access_config_generation";
    case NC_DHCP_APPLY_ERR_UCI_COMMIT:
        return "uci_commit";
    case NC_DHCP_APPLY_ERR_CONFIG:
    default:
        return "config_generation";
    }
}

static int nc_dhcpv6_uci_reservations_present(struct uci_context *ctx,
                                               struct uci_package *pkg,
                                               const char *lan_id)
{
    struct uci_element *e;

    if (!ctx || !pkg || !lan_id || !lan_id[0])
        return 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *pd_interface;

        if (!s || strcmp(s->type, "host") || !s->e.name ||
            strncmp(s->e.name, "dw_pd_", 6))
            continue;
        pd_interface = uci_lookup_option_string(ctx, s, "pd_interface");
        if (pd_interface && !strcmp(pd_interface, lan_id))
            return 1;
    }
    return 0;
}

static int nc_dhcpv6_static_reservations_present(const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    int present = 0;

    if (!lan_id || !lan_id[0] ||
        nc_prepare(&st, "SELECT 1 FROM dhcpv6_prefix_reservation "
                   "WHERE lan_id=?1 AND enabled=1 LIMIT 1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
    present = sqlite3_step(st) == SQLITE_ROW ? 1 : 0;
    sqlite3_finalize(st);
    return present;
}

static int nc_dhcpv6_static_leases_readback_retry(const char *lan_id)
{
    int attempt;

    for (attempt = 0; attempt < 3; attempt++) {
        if (nc_dhcpv6_static_leases_readback_update(lan_id) == 0)
            return 0;
        if (attempt < 2)
            usleep(100000);
    }
    return -1;
}

int jmx_dhcp_service_apply(const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    char bak[256] = {0};
    char scope_id[128] = "";
    char lan_ip[64] = "";
    int prefix = 24;
    int rc = NC_DHCP_APPLY_ERR_CONFIG;
    int committed = 0;
    int access_entries = 0;
    int dhcpv6_static_present = 0;
    int dhcpv6_static_was_present = 0;

    if (!lan_id || !lan_id[0] || !nc_valid_name(lan_id)) return -1;
    if (jmx_netconfig_db_init() != 0 ||
        !nc_dhcp_lan_primary(lan_id, lan_ip, sizeof(lan_ip), &prefix) ||
        !lan_ip[0] || nc_backup_config("dhcp", bak, sizeof(bak)) != 0 ||
        !bak[0])
        return -1;
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "dhcp", &pkg) != UCI_OK || !pkg) goto done;
    dhcpv6_static_was_present = nc_dhcpv6_uci_reservations_present(ctx, pkg, lan_id);
    if (nc_prepare(&st,
        "SELECT id,enabled,pool_start,pool_end,gateway,dns1,dns2,lease_minutes "
        "FROM dhcp_scope WHERE lan_id=?1") != 0) goto done;
    sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        char b[64], full_start[64] = "", full_end[64] = "";
        const char *gateway = (const char *)sqlite3_column_text(st, 4);
        const char *dns1 = (const char *)sqlite3_column_text(st, 5);
        const char *dns2 = (const char *)sqlite3_column_text(st, 6);
        int start, end, limit;

        snprintf(scope_id, sizeof(scope_id), "%s", (const char *)sqlite3_column_text(st, 0));
        if (nc_dhcp_expand_pool_address((const char *)sqlite3_column_text(st, 2),
                                        lan_ip, prefix, full_start, sizeof(full_start)) != 0 ||
            nc_dhcp_expand_pool_address((const char *)sqlite3_column_text(st, 3),
                                        lan_ip, prefix, full_end, sizeof(full_end)) != 0)
            goto done;
        start = nc_dhcp_pool_offset(full_start, lan_ip, prefix);
        end = nc_dhcp_pool_offset(full_end, lan_ip, prefix);
        limit = end - start + 1;
        if (start < 1 || limit < 1 ||
            nc_uci_ensure_section(ctx, pkg, "dhcp", lan_id, "dhcp") != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", lan_id, "interface", lan_id) != 0 ||
            nc_uci_set_pkg(ctx, "dhcp", lan_id, "ignore",
                           sqlite3_column_int(st, 1) ? "0" : "1") != 0)
            goto done;
        snprintf(b, sizeof(b), "%d", start);
        if (nc_uci_set_pkg(ctx, "dhcp", lan_id, "start", b) != 0) goto done;
        snprintf(b, sizeof(b), "%d", limit);
        if (nc_uci_set_pkg(ctx, "dhcp", lan_id, "limit", b) != 0) goto done;
        snprintf(b, sizeof(b), "%dm", sqlite3_column_int(st, 7));
        if (nc_uci_set_pkg(ctx, "dhcp", lan_id, "leasetime", b) != 0 ||
            nc_uci_delete_pkg(ctx, "dhcp", lan_id, "dhcp_option") != 0)
            goto done;
        if (gateway && gateway[0]) {
            char option[128];
            snprintf(option, sizeof(option), "3,%s", gateway);
            if (nc_uci_add_list_pkg(ctx, "dhcp", lan_id, "dhcp_option", option) != 0)
                goto done;
        }
        if (dns1 && dns1[0]) {
            char option[256];
            snprintf(option, sizeof(option), "6,%s%s%s", dns1,
                     dns2 && dns2[0] ? "," : "", dns2 && dns2[0] ? dns2 : "");
            if (nc_uci_add_list_pkg(ctx, "dhcp", lan_id, "dhcp_option", option) != 0)
                goto done;
        }
    } else {
        goto done;
    }
    sqlite3_finalize(st); st = NULL;

    if (nc_prepare(&st,
        "SELECT code,value FROM dhcp_option WHERE scope_id=?1 ORDER BY sort_order,id") != 0)
        goto done;
    sqlite3_bind_text(st, 1, scope_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        char option[256];
        snprintf(option, sizeof(option), "%s,%s",
                 (const char *)sqlite3_column_text(st, 0),
                 (const char *)sqlite3_column_text(st, 1));
        if (nc_uci_add_list_pkg(ctx, "dhcp", lan_id, "dhcp_option", option) != 0)
            goto done;
    }
    sqlite3_finalize(st); st = NULL;
    if (nc_dhcp_rebuild_all_reservations(ctx, pkg) != 0) {
        rc = NC_DHCP_APPLY_ERR_DNSMASQ_CONFIG;
        goto done;
    }
    if (nc_dhcpv6_rebuild_all_prefix_reservations(ctx, pkg) != 0) {
        rc = NC_DHCP_APPLY_ERR_DHCPV6_CONFIG;
        goto done;
    }
    if (nc_dhcp_merge_access_extraconf(ctx, pkg, &access_entries) != 0) {
        rc = NC_DHCP_APPLY_ERR_DHCP_ACCESS_CONFIG;
        goto done;
    }
    if (jmx_netboot_dhcp_project(ctx, pkg) != 0) {
        rc = NC_DHCP_APPLY_ERR_DNSMASQ_CONFIG;
        goto done;
    }
    if (jmx_uci_commit(ctx, "dhcp") != UCI_OK) {
        rc = NC_DHCP_APPLY_ERR_UCI_COMMIT;
        goto done;
    }
    dhcpv6_static_present = nc_dhcpv6_static_reservations_present(lan_id);
    if (dhcpv6_static_present < 0) {
        rc = NC_DHCP_APPLY_ERR_CONFIG;
        goto done;
    }
    dhcpv6_static_present = dhcpv6_static_present || dhcpv6_static_was_present;
    committed = 1;
    if (access("/etc/init.d/dnsmasq", F_OK) != 0 ||
        nc_run_quiet("/etc/init.d/dnsmasq reload >/tmp/dw-dhcp-apply.log 2>&1 || /etc/init.d/dnsmasq restart >>/tmp/dw-dhcp-apply.log 2>&1") != 0) {
        rc = NC_DHCP_APPLY_ERR_DNSMASQ_RELOAD;
        goto done;
    }
    if (nc_dhcp_access_runtime_loaded(access_entries) != 0) {
        rc = NC_DHCP_APPLY_ERR_DHCP_ACCESS_READBACK;
        goto done;
    }
    /* odhcpd is relevant to this transaction only when an enabled static
     * DHCPv6 prefix exists.  Pure IPv4 reservations must not fail because
     * the optional DHCPv6 runtime object is absent or still settling. */
    if (dhcpv6_static_present) {
        if (access("/etc/init.d/odhcpd", F_OK) != 0 ||
            nc_run_quiet("/etc/init.d/odhcpd reload >/tmp/dw-odhcpd-apply.log 2>&1 || /etc/init.d/odhcpd restart >>/tmp/dw-odhcpd-apply.log 2>&1") != 0) {
            rc = NC_DHCP_APPLY_ERR_ODHCPD_RELOAD;
            goto done;
        }
        if (nc_dhcpv6_static_leases_readback_retry(lan_id) != 0) {
            rc = NC_DHCP_APPLY_ERR_DHCPV6_READBACK;
            goto done;
        }
    }
    rc = 0;
done:
    if (st) sqlite3_finalize(st);
    if (ctx) uci_free_context(ctx);
    if (rc != 0 && bak[0]) {
        nc_restore_config("dhcp", bak);
        if (committed && access("/etc/init.d/dnsmasq", F_OK) == 0)
            nc_run_quiet("/etc/init.d/dnsmasq reload >/tmp/dw-dhcp-rollback.log 2>&1 || /etc/init.d/dnsmasq restart >>/tmp/dw-dhcp-rollback.log 2>&1");
        if (committed && dhcpv6_static_present && access("/etc/init.d/odhcpd", F_OK) == 0)
            nc_run_quiet("/etc/init.d/odhcpd reload >/tmp/dw-odhcpd-rollback.log 2>&1 || /etc/init.d/odhcpd restart >>/tmp/dw-odhcpd-rollback.log 2>&1");
    }
    nc_cleanup_backup(bak);
    return rc;
}
